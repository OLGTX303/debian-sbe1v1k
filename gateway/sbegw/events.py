"""eventd — event history, severity, filtering and live fan-out.

Events are the union of the gateway list (§35) and the Wi-Fi list (§32). They are
persisted to SQLite so history survives a restart, and pushed to subscribers for
the SSE stream.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections import deque
from typing import Any, Callable, Iterable

from .util import now

log = logging.getLogger("sbegw.eventd")

SEVERITIES = ("debug", "info", "notice", "warning", "error", "critical")

# Known event kinds and their default severity. Unknown kinds are accepted at
# "info" so a new subsystem can emit without a schema change.
EVENT_SEVERITY: dict[str, str] = {
    "WAN_UP": "notice", "WAN_DOWN": "error", "WAN_DEGRADED": "warning",
    # Distinct from WAN_DOWN: the link is up, the lease or the path is not.
    "WAN_ACQUIRING": "info", "WAN_NO_INTERNET": "warning",
    "PORT_UP": "info", "PORT_DOWN": "warning",
    "VPN_UP": "notice", "VPN_DOWN": "warning",
    "BGP_UP": "notice", "BGP_DOWN": "error",
    "OSPF_UP": "notice", "OSPF_DOWN": "error",
    "CONFIG_COMMITTED": "info", "CONFIG_ROLLED_BACK": "error",
    "IDS_ALERT": "warning", "IPS_BLOCK": "warning",
    "THERMAL_WARNING": "warning", "THERMAL_CRITICAL": "critical",
    "FIRMWARE_UPDATE": "notice",
    "DHCP_LEASE": "debug", "DHCP_FAILED": "error",
    # Wi-Fi
    "RADIO_UP": "info", "RADIO_DOWN": "error", "RADIO_RECOVERED": "notice",
    "SSID_UP": "info", "SSID_DOWN": "warning",
    "CLIENT_ASSOCIATED": "info", "CLIENT_AUTHENTICATED": "debug",
    "CLIENT_DISCONNECTED": "info", "CLIENT_ROAMED": "info",
    "AUTH_FAILED": "warning", "RADIUS_FAILED": "error",
    "DFS_CAC_STARTED": "info", "DFS_CAC_COMPLETED": "info", "DFS_RADAR": "warning",
    "CHANNEL_CHANGED": "notice",
    "MLO_CLIENT_CONNECTED": "info", "MLO_LINK_ADDED": "info",
    "MLO_LINK_REMOVED": "warning", "MLO_RECOVERY": "warning",
    "RADIO_FW_CRASH": "critical", "RADIO_FW_RECOVERED": "notice",
}


class EventBus:
    def __init__(self, db_path: str, retain: int = 20000):
        self.retain = retain
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._recent: deque[dict[str, Any]] = deque(maxlen=200)
        # Suppress identical repeating events (e.g. a flapping link) so the
        # history stays readable; the count is folded into the stored row.
        self._dedup: dict[str, tuple[float, int]] = {}
        self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts       REAL NOT NULL,
                    kind     TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    subsystem TEXT,
                    message  TEXT,
                    data     TEXT,
                    count    INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS events_kind ON events(kind, ts DESC);
                """
            )

    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def emit(self, kind: str, severity: str | None = None, data: dict[str, Any] | None = None,
             *, subsystem: str = "system", message: str = "",
             dedup_key: str | None = None, dedup_window: float = 10.0) -> dict[str, Any] | None:
        severity = severity or EVENT_SEVERITY.get(kind, "info")
        if severity not in SEVERITIES:
            severity = "info"
        data = data or {}
        ts = now()

        if dedup_key:
            with self._lock:
                last = self._dedup.get(dedup_key)
                if last and ts - last[0] < dedup_window:
                    self._dedup[dedup_key] = (last[0], last[1] + 1)
                    return None
                self._dedup[dedup_key] = (ts, 1)

        event = {
            "ts": ts, "kind": kind, "severity": severity, "subsystem": subsystem,
            "message": message or self._describe(kind, data), "data": data,
        }
        with self._db:
            cur = self._db.execute(
                "INSERT INTO events(ts, kind, severity, subsystem, message, data) "
                "VALUES(?,?,?,?,?,?)",
                (ts, kind, severity, subsystem, event["message"], json.dumps(data)),
            )
            event["id"] = int(cur.lastrowid)
            if event["id"] % 500 == 0:
                self._db.execute(
                    "DELETE FROM events WHERE id NOT IN "
                    "(SELECT id FROM events ORDER BY id DESC LIMIT ?)", (self.retain,))

        with self._lock:
            self._recent.append(event)
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # noqa: BLE001
                log.debug("event subscriber failed", exc_info=True)
        if severity in ("error", "critical"):
            log.error("%s: %s", kind, event["message"])
        return event

    @staticmethod
    def _describe(kind: str, data: dict[str, Any]) -> str:
        """Human-readable default message so the UI never shows a bare kind."""
        parts = []
        for key in ("port", "radio", "wan", "ssid", "client", "mld", "link",
                    "channel", "reason", "reason_code", "status_code", "detail"):
            if key in data and data[key] is not None:
                parts.append(f"{key}={data[key]}")
        subject = kind.replace("_", " ").title()
        return f"{subject}" + (f" ({', '.join(parts)})" if parts else "")

    def query(self, *, limit: int = 200, offset: int = 0,
              severities: Iterable[str] | None = None,
              kinds: Iterable[str] | None = None,
              subsystem: str | None = None,
              since: float | None = None,
              search: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list[Any] = []
        if severities:
            sevs = [s for s in severities if s in SEVERITIES]
            if sevs:
                sql += f" AND severity IN ({','.join('?' * len(sevs))})"
                args += sevs
        if kinds:
            kinds = list(kinds)
            sql += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += kinds
        if subsystem:
            sql += " AND subsystem = ?"
            args.append(subsystem)
        if since:
            sql += " AND ts >= ?"
            args.append(since)
        if search:
            sql += " AND (message LIKE ? OR kind LIKE ? OR data LIKE ?)"
            pattern = f"%{search}%"
            args += [pattern, pattern, pattern]
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]

        rows = self._db.execute(sql, args).fetchall()
        return [
            {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "severity": r["severity"],
             "subsystem": r["subsystem"], "message": r["message"],
             "data": json.loads(r["data"] or "{}"), "count": r["count"]}
            for r in rows
        ]

    def counts(self, since: float | None = None) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) c FROM events"
        args: list[Any] = []
        if since:
            sql += " WHERE ts >= ?"
            args.append(since)
        sql += " GROUP BY severity"
        return {r["severity"]: r["c"] for r in self._db.execute(sql, args).fetchall()}

    def recent(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent)
