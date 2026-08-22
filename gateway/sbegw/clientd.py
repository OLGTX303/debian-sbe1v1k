"""clientd — one client database for wired and wireless (spec §29).

Identity is the MAC address. Each poll merges four independent sources so a
client is visible even when only one of them knows about it:

  * dnsmasq leases  -> IPv4/IPv6, hostname
  * ARP/NDP         -> current addresses, reachability
  * bridge FDB      -> which port/BSS the MAC is behind
  * wifid           -> radio, band, RSSI, MLO links

First/last seen, names, blocks and per-client policy persist in SQLite so
history survives a reboot.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import threading
from typing import Any

from .adapters import rtnl
from .netd import BRIDGE
from .util import monotonic, normalise_mac, now, rate

log = logging.getLogger("sbegw.clientd")

OUI_PATHS = ("/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt")


class ClientDatabase:
    def __init__(self, db_path: str, events=None):
        self.events = events
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._live: dict[str, dict[str, Any]] = {}
        self._samples: dict[str, tuple[float, int, int]] = {}
        self._oui: dict[str, str] | None = None
        self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    mac         TEXT PRIMARY KEY,
                    name        TEXT,
                    hostname    TEXT,
                    vendor      TEXT,
                    first_seen  REAL NOT NULL,
                    last_seen   REAL NOT NULL,
                    fixed_ip    TEXT,
                    blocked     INTEGER NOT NULL DEFAULT 0,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    note        TEXT,
                    tags        TEXT,
                    down_limit_kbps INTEGER,
                    up_limit_kbps   INTEGER,
                    network     TEXT,
                    rx_bytes    INTEGER NOT NULL DEFAULT 0,
                    tx_bytes    INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS client_history (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac     TEXT NOT NULL,
                    ts      REAL NOT NULL,
                    event   TEXT NOT NULL,
                    detail  TEXT
                );
                CREATE INDEX IF NOT EXISTS client_history_mac
                    ON client_history(mac, ts DESC);
                """
            )

    # ------------------------------------------------------------------ vendor

    def vendor_for(self, mac: str) -> str | None:
        """Resolve the OUI. Returns None rather than guessing when unavailable."""
        if self._oui is None:
            self._oui = {}
            for path in OUI_PATHS:
                if not os.path.exists(path):
                    continue
                try:
                    with open(path, errors="replace") as fh:
                        for line in fh:
                            if "(base 16)" in line:
                                prefix, _, name = line.partition("(base 16)")
                                self._oui[prefix.strip().lower()] = name.strip()
                except OSError:
                    pass
                break
        prefix = normalise_mac(mac).replace(":", "")[:6]
        return self._oui.get(prefix)

    # -------------------------------------------------------------- collection

    def poll(self, cfg: dict[str, Any], leases: list[dict[str, Any]],
             wireless: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Merge every source into the live client view and persist changes."""
        networks = cfg.get("networks", {})
        subnet_index: list[tuple[Any, str, Any]] = []
        for nid, net in networks.items():
            if net.get("subnet"):
                iface = ipaddress.ip_interface(net["subnet"])
                subnet_index.append((iface.network, nid, net))

        merged: dict[str, dict[str, Any]] = {}

        def entry(mac: str) -> dict[str, Any]:
            mac = normalise_mac(mac)
            return merged.setdefault(mac, {
                "mac": mac, "ipv4": None, "ipv6": [], "hostname": None,
                "network": None, "vlan": None, "port": None, "connection": "unknown",
                "wireless": None, "online": True,
            })

        # --- DHCP leases
        for lease in leases:
            item = entry(lease["mac"])
            addr = lease.get("address", "")
            if ":" in addr:
                item["ipv6"].append(addr)
            else:
                item["ipv4"] = addr
            item["hostname"] = item["hostname"] or lease.get("hostname")

        # --- ARP / NDP
        for family in (4, 6):
            for neighbour in rtnl.neighbours(family):
                mac = neighbour.get("lladdr")
                if not mac:
                    continue
                item = entry(mac)
                addr = neighbour.get("dst", "")
                if family == 4:
                    item["ipv4"] = item["ipv4"] or addr
                elif addr and addr not in item["ipv6"]:
                    item["ipv6"].append(addr)
                if neighbour.get("state") and "FAILED" in neighbour["state"]:
                    item["online"] = False

        # --- bridge FDB: which port or BSS the MAC sits behind
        for record in rtnl.fdb(BRIDGE):
            mac = record.get("mac")
            port = record.get("ifname")
            if not mac or not port or record.get("flags") == ["self"]:
                continue
            item = entry(mac)
            item["port"] = port
            item["vlan"] = record.get("vlan") or item["vlan"]
            item["connection"] = "wireless" if port.startswith("wl") else "wired"

        # --- wireless detail (authoritative for radio metrics)
        for client in wireless:
            item = entry(client["mac"])
            item["connection"] = "wireless"
            item["wireless"] = client
            item["network"] = client.get("network") or item["network"]
            item["vlan"] = client.get("vlan") or item["vlan"]
            item["port"] = client.get("interface")

        # --- resolve network membership from the address
        for item in merged.values():
            if item["network"] or not item["ipv4"]:
                continue
            try:
                address = ipaddress.ip_address(item["ipv4"])
            except ValueError:
                continue
            for network, nid, _net in subnet_index:
                if address in network:
                    item["network"] = nid
                    break

        # --- fold in persisted attributes and traffic counters
        ts = monotonic()
        out: list[dict[str, Any]] = []
        for mac, item in merged.items():
            record = self._upsert(mac, item)
            item.update({
                "name": record["name"] or item["hostname"] or mac,
                "hostname": item["hostname"] or record["hostname"],
                "vendor": record["vendor"],
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "blocked": bool(record["blocked"]),
                "quarantined": bool(record["quarantined"]),
                "fixed_ip": record["fixed_ip"],
                "note": record["note"],
                "tags": json.loads(record["tags"] or "[]"),
                "down_limit_kbps": record["down_limit_kbps"],
                "up_limit_kbps": record["up_limit_kbps"],
            })

            wifi = item.get("wireless") or {}
            rx = wifi.get("rx_bytes", 0)
            tx = wifi.get("tx_bytes", 0)
            prev = self._samples.get(mac)
            if prev and (rx or tx):
                dt = ts - prev[0]
                item["rx_rate_bps"] = round(rate(rx, prev[1], dt) * 8, 1)
                item["tx_rate_bps"] = round(rate(tx, prev[2], dt) * 8, 1)
            else:
                item["rx_rate_bps"] = 0.0
                item["tx_rate_bps"] = 0.0
            self._samples[mac] = (ts, rx, tx)
            item["rx_bytes"] = rx
            item["tx_bytes"] = tx
            out.append(item)

        # Clients that were live last poll but are gone now go offline.
        for mac in set(self._live) - set(merged):
            previous = self._live[mac]
            previous["online"] = False
            out.append(previous)
            self._history(mac, "offline", "")

        self._live = {c["mac"]: c for c in out if c.get("online", True)}
        return sorted(out, key=lambda c: (not c.get("online"), c.get("name") or ""))

    def _upsert(self, mac: str, item: dict[str, Any]) -> sqlite3.Row:
        with self._lock, self._db:
            row = self._db.execute("SELECT * FROM clients WHERE mac=?",
                                   (mac,)).fetchone()
            timestamp = now()
            if row is None:
                self._db.execute(
                    "INSERT INTO clients(mac, hostname, vendor, first_seen, "
                    "last_seen, network) VALUES(?,?,?,?,?,?)",
                    (mac, item.get("hostname"), self.vendor_for(mac), timestamp,
                     timestamp, item.get("network")))
                self._history(mac, "first-seen", item.get("network") or "")
                if self.events:
                    self.events.emit("CLIENT_ASSOCIATED", subsystem="clients",
                                     data={"client": mac,
                                           "network": item.get("network")})
                row = self._db.execute("SELECT * FROM clients WHERE mac=?",
                                       (mac,)).fetchone()
            else:
                self._db.execute(
                    "UPDATE clients SET last_seen=?, hostname=COALESCE(?, hostname), "
                    "network=COALESCE(?, network) WHERE mac=?",
                    (timestamp, item.get("hostname"), item.get("network"), mac))
            return row

    def _history(self, mac: str, event: str, detail: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO client_history(mac, ts, event, detail) VALUES(?,?,?,?)",
                (mac, now(), event, detail))
            self._db.execute(
                "DELETE FROM client_history WHERE id NOT IN "
                "(SELECT id FROM client_history ORDER BY id DESC LIMIT 20000)")

    # ------------------------------------------------------------------ actions

    def update(self, mac: str, **fields: Any) -> bool:
        allowed = {"name", "fixed_ip", "blocked", "quarantined", "note",
                   "down_limit_kbps", "up_limit_kbps"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if "tags" in fields:
            updates["tags"] = json.dumps(fields["tags"])
        if not updates:
            return False
        mac = normalise_mac(mac)
        assignments = ", ".join(f"{k}=?" for k in updates)
        with self._lock, self._db:
            cur = self._db.execute(
                f"UPDATE clients SET {assignments} WHERE mac=?",
                (*updates.values(), mac))
        self._history(mac, "updated", json.dumps(
            {k: ("***" if "limit" not in k and k == "note" else v)
             for k, v in updates.items()}))
        return cur.rowcount > 0

    def get(self, mac: str) -> dict[str, Any] | None:
        mac = normalise_mac(mac)
        live = self._live.get(mac)
        if live:
            return live
        row = self._db.execute("SELECT * FROM clients WHERE mac=?", (mac,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["online"] = False
        record["tags"] = json.loads(record.get("tags") or "[]")
        return record

    def history(self, mac: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT ts, event, detail FROM client_history WHERE mac=? "
            "ORDER BY id DESC LIMIT ?", (normalise_mac(mac), limit)).fetchall()
        return [dict(r) for r in rows]

    def known(self, limit: int = 2000) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM clients ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for row in rows:
            record = dict(row)
            record["tags"] = json.loads(record.get("tags") or "[]")
            record["online"] = record["mac"] in self._live
            out.append(record)
        return out

    def blocked_macs(self) -> list[str]:
        rows = self._db.execute(
            "SELECT mac FROM clients WHERE blocked=1").fetchall()
        return [r["mac"] for r in rows]

    def live(self) -> list[dict[str, Any]]:
        return list(self._live.values())
