"""Application-aware traffic accounting using Debian's Suricata engine.

The UCGF image uses a closed Trend Micro kernel classifier.  Its 5.4 modules
and signature database are neither ABI-compatible with this kernel nor needed
here: Suricata's open app-layer parsers emit flow records to EVE JSON, which we
aggregate per LAN client and expose both locally and to the UniFi inform agent.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import sqlite3
import threading
from typing import Any

from .configd import ApplyResult
from .util import ToolError, now, read_int, read_text, run, which, write_atomic

log = logging.getLogger("sbegw.dpi")

RUN_DIR = os.environ.get("SBEGW_RUN", "/run/sbegw")
CONF_PATH = os.path.join(RUN_DIR, "suricata-dpi.yaml")
EVE_PATH = os.path.join(RUN_DIR, "dpi-eve.json")
PID_PATH = os.path.join(RUN_DIR, "suricata-dpi.pid")

# cat/app pairs used by UniFi's legacy gateway DPI payload.  The names and IDs
# are the generic protocol entries in the UCGF bwdpi application catalogue;
# signatures and the vendor classifier itself are deliberately not copied.
APP_MAP: dict[str, tuple[int, int, str]] = {
    "http": (13, 222, "HTTP"),
    "http2": (13, 222, "HTTP"),
    "tls": (20, 185, "SSL/TLS"),
    "ssl": (20, 185, "SSL/TLS"),
    "quic": (13, 190, "QUIC"),
    "dns": (9, 61, "DNS"),
    "ssh": (10, 1, "SSH"),
    "ftp": (3, 1, "FTP"),
    "smtp": (5, 1, "SMTP"),
    "pop3": (5, 2, "POP3"),
    "imap": (5, 3, "IMAP"),
    "smb": (9, 110, "SMB"),
    "dcerpc": (9, 110, "RPC"),
    "bittorrent-dht": (1, 2, "BitTorrent"),
}


def _app(protocol: str | None) -> tuple[int, int, str]:
    key = (protocol or "unknown").lower()
    return APP_MAP.get(key, (255, 65535, key.upper() if key != "unknown" else "Unknown"))


class DpiEngine:
    def __init__(self, state_dir: str, clients=None, events=None):
        self.clients = clients
        self.events = events
        self.last_error: str | None = None
        self._offset = 0
        self._inode: int | None = None
        self._lock = threading.RLock()
        os.makedirs(state_dir, exist_ok=True)
        self._db = sqlite3.connect(os.path.join(state_dir, "dpi.db"),
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS dpi_buckets (
                    bucket      INTEGER NOT NULL,
                    client      TEXT NOT NULL,
                    client_ip   TEXT,
                    protocol    TEXT NOT NULL,
                    category    INTEGER NOT NULL,
                    application INTEGER NOT NULL,
                    display     TEXT NOT NULL,
                    rx_bytes    INTEGER NOT NULL DEFAULT 0,
                    tx_bytes    INTEGER NOT NULL DEFAULT 0,
                    rx_packets  INTEGER NOT NULL DEFAULT 0,
                    tx_packets  INTEGER NOT NULL DEFAULT 0,
                    first_seen  REAL NOT NULL,
                    last_seen   REAL NOT NULL,
                    PRIMARY KEY(bucket, client, protocol)
                );
                CREATE INDEX IF NOT EXISTS dpi_buckets_last
                    ON dpi_buckets(last_seen DESC);
                """)

    @staticmethod
    def _interfaces(cfg: dict[str, Any]) -> list[str]:
        interfaces = []
        for network in cfg.get("networks", {}).values():
            if not network.get("enabled", True) or not network.get("subnet"):
                continue
            vlan = network.get("vlan")
            interface = f"br-lan.{vlan}" if vlan else "br-lan"
            if interface not in interfaces:
                interfaces.append(interface)
        return interfaces or ["br-lan"]

    @classmethod
    def render_config(cls, cfg: dict[str, Any]) -> str:
        subnets = [str(ipaddress.ip_interface(n["subnet"]).network)
                   for n in cfg.get("networks", {}).values() if n.get("subnet")]
        home = "[" + ",".join(subnets or ["192.168.0.0/16"]) + "]"
        lines = [
            "%YAML 1.1", "---", "runmode: workers", "vars:",
            "  address-groups:", f'    HOME_NET: "{home}"',
            '    EXTERNAL_NET: "!$HOME_NET"', f"default-rule-path: {RUN_DIR}",
            "rule-files: []", "af-packet:",
        ]
        for index, interface in enumerate(cls._interfaces(cfg)):
            lines += [f"  - interface: {interface}",
                      f"    cluster-id: {90 + index}",
                      "    cluster-type: cluster_flow", "    defrag: yes",
                      "    use-mmap: yes", "    tpacket-v3: yes"]
        lines += [
            "outputs:", "  - eve-log:", "      enabled: yes",
            "      filetype: regular", f"      filename: {EVE_PATH}",
            "      rotate-interval: day", "      types:", "        - flow",
            "logging:", "  default-log-level: notice", "  outputs:",
            "    - console:", "        enabled: no",
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _ours(pid: int) -> bool:
        cmd = read_text(f"/proc/{pid}/cmdline").replace("\x00", " ")
        return "suricata" in cmd and CONF_PATH in cmd

    @classmethod
    def _running(cls) -> bool:
        pid = read_int(PID_PATH)
        return bool(pid and os.path.exists(f"/proc/{pid}") and cls._ours(pid))

    @classmethod
    def _stop(cls) -> None:
        pid = read_int(PID_PATH)
        if pid and cls._ours(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        try:
            os.unlink(PID_PATH)
        except OSError:
            pass

    def preflight(self, _old: dict[str, Any], new: dict[str, Any]) -> tuple[bool, list[str]]:
        if new.get("dpi", {}).get("enabled") and which("suricata") is None:
            return False, ["DPI requires the Debian suricata package"]
        return True, []

    def __call__(self, _old: dict[str, Any], new: dict[str, Any]) -> ApplyResult:
        dpi = new.get("dpi", {})
        self._stop()
        if not dpi.get("enabled"):
            self.last_error = None
            return ApplyResult(True, ["traffic identification disabled"])
        try:
            os.makedirs(RUN_DIR, exist_ok=True)
            write_atomic(CONF_PATH, self.render_config(new), mode=0o600)
            run(["suricata", "-T", "-c", CONF_PATH], timeout=45)
            run(["suricata", "-c", CONF_PATH, "--af-packet", "-D",
                 "--pidfile", PID_PATH], timeout=30)
            self.last_error = None
            return ApplyResult(True, ["traffic identification enabled with Suricata"])
        except (ToolError, OSError) as exc:
            self.last_error = str(exc)
            self._stop()
            if self.events:
                self.events.emit("DPI_FAILED", "error", {"detail": self.last_error},
                                 subsystem="dpi",
                                 message=f"Traffic identification failed: {exc}")
            # DPI is observational. It must not roll back a working LAN.
            return ApplyResult(True, [f"traffic identification unavailable: {exc}"])

    @staticmethod
    def _subnets(cfg: dict[str, Any]) -> list[Any]:
        out = []
        for network in cfg.get("networks", {}).values():
            try:
                out.append(ipaddress.ip_interface(network.get("subnet", "")).network)
            except ValueError:
                pass
        return out

    def _identity(self, address: str) -> str:
        if self.clients:
            for client in self.clients.live():
                if address == client.get("ipv4") or address in client.get("ipv6", []):
                    return client.get("mac") or address
        return address

    def ingest(self, event: dict[str, Any], cfg: dict[str, Any]) -> bool:
        if event.get("event_type") != "flow":
            return False
        try:
            src = ipaddress.ip_address(event["src_ip"])
            dst = ipaddress.ip_address(event["dest_ip"])
        except (KeyError, ValueError):
            return False
        if not cfg.get("dpi", {}).get("include_ipv6", True) and (
                src.version == 6 or dst.version == 6):
            return False
        subnets = self._subnets(cfg)
        src_local = any(src in subnet for subnet in subnets)
        dst_local = any(dst in subnet for subnet in subnets)
        if src_local == dst_local:
            return False

        flow = event.get("flow") or {}
        to_server = max(0, int(flow.get("bytes_toserver") or 0))
        to_client = max(0, int(flow.get("bytes_toclient") or 0))
        pkts_server = max(0, int(flow.get("pkts_toserver") or 0))
        pkts_client = max(0, int(flow.get("pkts_toclient") or 0))
        if src_local:
            client_ip, rx, tx = str(src), to_client, to_server
            rxp, txp = pkts_client, pkts_server
        else:
            client_ip, rx, tx = str(dst), to_server, to_client
            rxp, txp = pkts_server, pkts_client
        protocol = str(event.get("app_proto") or event.get("proto") or "unknown").lower()
        category, application, display = _app(protocol)
        client = self._identity(client_ip)
        timestamp = now()
        bucket = int(timestamp // 3600) * 3600
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO dpi_buckets(bucket,client,client_ip,protocol,category,application,"
                "display,rx_bytes,tx_bytes,rx_packets,tx_packets,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(bucket,client,protocol) DO UPDATE SET "
                "client_ip=excluded.client_ip, rx_bytes=rx_bytes+excluded.rx_bytes, "
                "tx_bytes=tx_bytes+excluded.tx_bytes, "
                "rx_packets=rx_packets+excluded.rx_packets, "
                "tx_packets=tx_packets+excluded.tx_packets, last_seen=excluded.last_seen",
                (bucket, client, client_ip, protocol, category, application, display,
                 rx, tx, rxp, txp, timestamp, timestamp))
        return True

    def poll(self, cfg: dict[str, Any], limit: int = 5000) -> int:
        try:
            stat = os.stat(EVE_PATH)
        except OSError:
            return 0
        if self._inode != stat.st_ino or stat.st_size < self._offset:
            self._inode, self._offset = stat.st_ino, 0
        count = 0
        try:
            with open(EVE_PATH, errors="replace") as fh:
                fh.seek(self._offset)
                for line in fh:
                    if count >= limit:
                        break
                    try:
                        count += int(self.ingest(json.loads(line), cfg))
                    except json.JSONDecodeError:
                        continue
                self._offset = fh.tell()
        except OSError as exc:
            self.last_error = str(exc)
        self.prune(int(cfg.get("dpi", {}).get("retention_hours", 24)))
        return count

    def prune(self, retention_hours: int) -> None:
        cutoff = now() - retention_hours * 3600
        with self._lock, self._db:
            self._db.execute("DELETE FROM dpi_buckets WHERE last_seen < ?", (cutoff,))

    def rows(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT client, MAX(client_ip) AS client_ip, protocol, "
                "MAX(category) AS category, MAX(application) AS application, "
                "MAX(display) AS display, SUM(rx_bytes) AS rx_bytes, "
                "SUM(tx_bytes) AS tx_bytes, SUM(rx_packets) AS rx_packets, "
                "SUM(tx_packets) AS tx_packets, MIN(first_seen) AS first_seen, "
                "MAX(last_seen) AS last_seen FROM dpi_buckets "
                "GROUP BY client,protocol ORDER BY SUM(rx_bytes)+SUM(tx_bytes) DESC "
                "LIMIT ?",
                (max(1, min(limit, 5000)),)).fetchall()
        return [dict(row) for row in rows]

    def summary(self, cfg: dict[str, Any]) -> dict[str, Any]:
        rows = self.rows()
        apps: dict[str, dict[str, Any]] = {}
        clients: dict[str, dict[str, Any]] = {}
        for row in rows:
            app = apps.setdefault(row["protocol"], {
                "protocol": row["protocol"], "name": row["display"],
                "category": row["category"], "rx_bytes": 0, "tx_bytes": 0})
            app["rx_bytes"] += row["rx_bytes"]
            app["tx_bytes"] += row["tx_bytes"]
            client = clients.setdefault(row["client"], {
                "client": row["client"], "client_ip": row["client_ip"],
                "rx_bytes": 0, "tx_bytes": 0})
            client["rx_bytes"] += row["rx_bytes"]
            client["tx_bytes"] += row["tx_bytes"]
        ordered = lambda values: sorted(values, key=lambda x: x["rx_bytes"] + x["tx_bytes"],
                                        reverse=True)
        return {
            "config": cfg.get("dpi", {}),
            "status": {"running": self._running(),
                       "tool_available": which("suricata") is not None,
                       "error": self.last_error, "flow_count": len(rows)},
            "applications": ordered(apps.values()),
            "clients": ordered(clients.values()),
        }

    def unifi_stats(self) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in self.rows(5000):
            # Inform requires a MAC. Unknown IP-only identities stay available
            # locally but are not attributed to a made-up controller client.
            if ":" not in row["client"] or len(row["client"].split(":")) != 6:
                continue
            grouped.setdefault(row["client"], []).append({
                "cat": row["category"], "app": row["application"],
                "rx_bytes": row["rx_bytes"], "tx_bytes": row["tx_bytes"],
                "rx_packets": row["rx_packets"], "tx_packets": row["tx_packets"],
            })
        return [{"mac": mac, "initialized": "0", "stats": stats}
                for mac, stats in sorted(grouped.items())]
