"""telemetryd — sampling, rate calculation and bounded retention (spec §34).

Metrics live in fixed-size ring buffers in memory (fast, bounded) and are rolled
up into SQLite at a coarser interval so the UI can draw multi-hour graphs after a
restart. Nothing here grows without bound: both tiers have a hard cap.
"""
from __future__ import annotations

import logging
import math
import os
import sqlite3
import threading
from collections import deque
from typing import Any, Callable

from .adapters import platform, rtnl
from .util import monotonic, now, rate

log = logging.getLogger("sbegw.telemetryd")

# Live tier: 1-second-ish samples for 10 minutes.
LIVE_POINTS = 600
# Rolled-up tier: one point per minute for 7 days.
ROLLUP_SECONDS = 60
ROLLUP_RETENTION = 7 * 24 * 60


class Series:
    """A bounded time series of (timestamp, value)."""

    __slots__ = ("points", "unit")

    def __init__(self, unit: str = "", maxlen: int = LIVE_POINTS):
        self.points: deque[tuple[float, float]] = deque(maxlen=maxlen)
        self.unit = unit

    def add(self, value: float, ts: float | None = None) -> None:
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return
        self.points.append((ts if ts is not None else now(), float(value)))

    def latest(self) -> float | None:
        return self.points[-1][1] if self.points else None

    def window(self, seconds: float) -> list[tuple[float, float]]:
        cutoff = now() - seconds
        return [p for p in self.points if p[0] >= cutoff]

    def average(self, seconds: float) -> float | None:
        window = self.window(seconds)
        return round(sum(v for _, v in window) / len(window), 2) if window else None

    def as_dict(self, seconds: float | None = None) -> dict[str, Any]:
        points = self.window(seconds) if seconds else list(self.points)
        return {"unit": self.unit,
                "points": [[round(t, 1), round(v, 2)] for t, v in points]}


def _state_is_volatile(path: str) -> tuple[bool, int]:
    """Is `path` on a tmpfs, and how much room is there?

    A tmpfs /data means the intended partition was not mounted. Keeping seven
    days of per-minute metrics there fills it, SQLite fails with ENOSPC, the
    supervisor crashes and Restart=always turns that into a loop that also takes
    out DHCP. Detect it and keep far less history instead.
    """
    volatile = False
    try:
        target = os.path.realpath(path)
        for line in open("/proc/mounts"):
            parts = line.split()
            if len(parts) > 2 and parts[2] == "tmpfs" and target.startswith(parts[1]):
                volatile = True
                break
    except OSError:
        pass
    try:
        st = os.statvfs(path if os.path.isdir(path) else os.path.dirname(path) or ".")
        free_mb = st.f_bavail * st.f_frsize // (1024 * 1024)
    except OSError:
        free_mb = 0
    return volatile, free_mb


class TelemetryStore:
    def __init__(self, db_path: str):
        self._series: dict[str, Series] = {}
        self._lock = threading.RLock()
        self._counters: dict[str, tuple[float, float]] = {}
        self._last_rollup = 0.0
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        volatile, free_mb = _state_is_volatile(os.path.dirname(db_path) or ".")
        self.retention_points = ROLLUP_RETENTION
        if volatile or free_mb < 256:
            # Roughly six hours instead of seven days.
            self.retention_points = 6 * 60
            log.warning(
                "state directory is %s with %d MiB free; limiting metric history "
                "to %d points per series so it cannot fill",
                "a tmpfs" if volatile else "low on space", free_mb,
                self.retention_points)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    id     INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts     REAL NOT NULL,
                    name   TEXT NOT NULL,
                    value  REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS metrics_name_ts ON metrics(name, ts DESC);
                """
            )

    def series(self, name: str, unit: str = "") -> Series:
        with self._lock:
            if name not in self._series:
                self._series[name] = Series(unit)
            return self._series[name]

    def record(self, name: str, value: float, unit: str = "") -> None:
        self.series(name, unit).add(value)

    def record_counter(self, name: str, counter: float, unit: str = "bps",
                       *, scale: float = 1.0) -> float | None:
        """Convert a monotonic counter into a per-second rate and store it."""
        ts = monotonic()
        with self._lock:
            previous = self._counters.get(name)
            self._counters[name] = (ts, counter)
        if previous is None:
            return None
        value = rate(counter, previous[1], ts - previous[0]) * scale
        self.record(name, value, unit)
        return value

    def snapshot(self, prefix: str = "", window: float | None = 300) -> dict[str, Any]:
        with self._lock:
            return {name: series.as_dict(window)
                    for name, series in self._series.items()
                    if name.startswith(prefix)}

    def latest(self, prefix: str = "") -> dict[str, float | None]:
        with self._lock:
            return {name: series.latest()
                    for name, series in self._series.items()
                    if name.startswith(prefix)}

    # ------------------------------------------------------------------ rollup

    def maybe_rollup(self) -> None:
        ts = now()
        if ts - self._last_rollup < ROLLUP_SECONDS:
            return
        self._last_rollup = ts
        with self._lock, self._db:
            for name, series in self._series.items():
                average = series.average(ROLLUP_SECONDS)
                if average is None:
                    continue
                self._db.execute(
                    "INSERT INTO metrics(ts, name, value) VALUES(?,?,?)",
                    (ts, name, average))
            self._db.execute(
                "DELETE FROM metrics WHERE ts < ?",
                (ts - self.retention_points * ROLLUP_SECONDS,))

    def history(self, name: str, *, seconds: float = 86400) -> dict[str, Any]:
        rows = self._db.execute(
            "SELECT ts, value FROM metrics WHERE name=? AND ts >= ? ORDER BY ts",
            (name, now() - seconds)).fetchall()
        return {"name": name,
                "points": [[round(r["ts"], 1), round(r["value"], 2)] for r in rows]}


class Sampler:
    """Periodically collects from every source and feeds the store."""

    def __init__(self, store: TelemetryStore, *, netd, wifid, clients,
                 config_getter: Callable[[], dict[str, Any]], events=None):
        self.store = store
        self.netd = netd
        self.wifid = wifid
        self.clients = clients
        self.config = config_getter
        self.events = events
        self._cpu_prev: dict[str, int] | None = None
        self.last_snapshot: dict[str, Any] = {}
        self._lock = threading.RLock()

    def sample(self) -> dict[str, Any]:
        cfg = self.config()
        store = self.store

        # --- system
        cpu = platform.cpu()
        cpu_percent = self._cpu_percent(cpu.get("jiffies", {}))
        if cpu_percent is not None:
            store.record("system.cpu.percent", cpu_percent, "%")
        memory = platform.memory()
        store.record("system.memory.percent", memory["used_percent"], "%")
        store.record("system.load.1m", cpu["load"][0], "")
        thermal = platform.thermal()
        if thermal.get("max_temperature_c"):
            store.record("system.temperature.c", thermal["max_temperature_c"], "°C")
            if thermal["state"] == "warning" and self.events:
                self.events.emit("THERMAL_WARNING", subsystem="hardware",
                                 data={"temperature_c": thermal["max_temperature_c"]},
                                 dedup_key="thermal-warning", dedup_window=300)
            elif thermal["state"] == "critical" and self.events:
                self.events.emit("THERMAL_CRITICAL", subsystem="hardware",
                                 data={"temperature_c": thermal["max_temperature_c"]},
                                 dedup_key="thermal-critical", dedup_window=120)

        # --- ports
        port_states = self.netd.ports.all_states(cfg)
        for port in port_states:
            counters = port["counters"]
            store.record_counter(f"port.{port['id']}.rx_bps",
                                 counters.get("rx_bytes", 0), scale=8)
            store.record_counter(f"port.{port['id']}.tx_bps",
                                 counters.get("tx_bytes", 0), scale=8)
            store.record_counter(f"port.{port['id']}.rx_pps",
                                 counters.get("rx_packets", 0), "pps")
            store.record_counter(f"port.{port['id']}.tx_pps",
                                 counters.get("tx_packets", 0), "pps")
        self.netd.ports.poll_link_changes()

        # --- WANs
        wan_health = self.netd.wans.probe(cfg)
        for wid, wan in wan_health.items():
            counters = wan.get("counters", {})
            store.record_counter(f"wan.{wid}.rx_bps", counters.get("rx_bytes", 0), scale=8)
            store.record_counter(f"wan.{wid}.tx_bps", counters.get("tx_bytes", 0), scale=8)
            if wan.get("latency_ms") is not None:
                store.record(f"wan.{wid}.latency_ms", wan["latency_ms"], "ms")
            if wan.get("loss_percent") is not None:
                store.record(f"wan.{wid}.loss_percent", wan["loss_percent"], "%")

        # --- Wi-Fi
        wifi = self.wifid.snapshot(cfg)
        for radio in wifi["radios"]:
            rid = radio["id"]
            counters = radio.get("counters", {})
            store.record_counter(f"radio.{rid}.rx_bps", counters.get("rx_bytes", 0), scale=8)
            store.record_counter(f"radio.{rid}.tx_bps", counters.get("tx_bytes", 0), scale=8)
            runtime = radio.get("runtime", {})
            if runtime.get("utilisation_percent") is not None:
                store.record(f"radio.{rid}.utilisation", runtime["utilisation_percent"], "%")
            if runtime.get("noise_dbm") is not None:
                store.record(f"radio.{rid}.noise_dbm", runtime["noise_dbm"], "dBm")
            store.record(f"radio.{rid}.clients", radio.get("client_count", 0), "")
        for mld in wifi["mlds"]:
            store.record(f"mld.{mld['id']}.links_up", mld.get("links_up", 0), "")
            store.record_counter(f"mld.{mld['id']}.rx_bps",
                                 mld.get("aggregate", {}).get("rx_bytes", 0), scale=8)
            store.record_counter(f"mld.{mld['id']}.tx_bps",
                                 mld.get("aggregate", {}).get("tx_bytes", 0), scale=8)

        # --- clients
        leases = self.netd.services.leases()
        clients = self.clients.poll(cfg, leases, wifi["clients"])
        store.record("clients.total", len([c for c in clients if c.get("online")]), "")
        store.record("clients.wireless",
                     len([c for c in clients
                          if c.get("online") and c.get("connection") == "wireless"]), "")

        # --- datapath
        accel = platform.acceleration()
        flows = platform.flow_statistics()
        if flows.get("total") is not None:
            store.record("conntrack.count", flows["total"], "")
        if flows.get("accelerated") is not None:
            store.record("flows.accelerated", flows["accelerated"], "")

        store.maybe_rollup()

        snapshot = {
            "ts": now(),
            "system": {
                "cpu_percent": cpu_percent,
                "load": cpu["load"],
                "cores": cpu["cores"],
                "frequency_mhz": cpu["frequency_mhz"],
                "memory": memory,
                "thermal": thermal,
                "storage": platform.storage(),
                "uptime": platform.uptime(),
                "board": platform.board(),
            },
            "ports": port_states,
            "wans": list(wan_health.values()),
            "primary_wan": self.netd.wans.select_primary(cfg),
            "networks": self.netd.network_states(cfg),
            "wifi": wifi,
            "clients": clients,
            "acceleration": accel | {"flows": flows,
                                     "conntrack_max": platform.conntrack_max()},
        }
        with self._lock:
            self.last_snapshot = snapshot
        return snapshot

    def _cpu_percent(self, jiffies: dict[str, int]) -> float | None:
        if not jiffies:
            return None
        previous = self._cpu_prev
        self._cpu_prev = jiffies
        if previous is None:
            return None
        total = sum(jiffies.values()) - sum(previous.values())
        idle = (jiffies.get("idle", 0) + jiffies.get("iowait", 0)) - \
               (previous.get("idle", 0) + previous.get("iowait", 0))
        if total <= 0:
            return None
        return round((total - idle) / total * 100, 1)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self.last_snapshot
