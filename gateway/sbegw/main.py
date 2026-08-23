"""sbegw entry point: wires the daemons and runs the sampler + API.

The spec's service split (platformd/netd/wifid/clientd/telemetryd/eventd/healthd/
router-api) is preserved as module boundaries, but they run in one supervised
process. On a 4-core IPQ9574 with 1 GiB of RAM, eight Python processes each
holding a config copy costs more than it buys, and a single process makes the
transactional apply genuinely atomic across subsystems.
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from typing import Any

from . import schema
from .adapters import hostapd, platform
from .api import ApiServer, ApiService
from .auth import AuthManager
from .clientd import ClientDatabase
from .configd import ConfigStore
from .dpi import DpiEngine
from .events import EventBus
from .hwd import HardwareManager
from .netd import NetDaemon
from .rf import ChannelAnalyzer
from .telemetry import Sampler, TelemetryStore
from .unifi import UniFiControllerAgent
from .util import now, read_int, read_text, run, which
from .wifid import WifiDaemon

log = logging.getLogger("sbegw")

STATE_DIR = os.environ.get("SBEGW_STATE", "/data/sbegw")
SAMPLE_INTERVAL = float(os.environ.get("SBEGW_SAMPLE_INTERVAL", "2.0"))
HEALTH_INTERVAL = 15.0


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    root.addHandler(stream)
    # systemd captures stderr; syslog is added when available for remote export.
    if os.path.exists("/dev/log"):
        try:
            syslog = logging.handlers.SysLogHandler(address="/dev/log")
            syslog.setFormatter(logging.Formatter("sbegw[%(process)d]: %(name)s "
                                                 "%(levelname)s %(message)s"))
            root.addHandler(syslog)
        except OSError:
            pass


class Gateway:
    """Owns every subsystem and the supervision loops."""

    def __init__(self, *, state_dir: str = STATE_DIR, host: str = "127.0.0.1",
                 port: int = 8081):
        os.makedirs(state_dir, exist_ok=True)
        os.makedirs("/run/sbegw", exist_ok=True)

        self.events = EventBus(os.path.join(state_dir, "events.db"))
        self.config = ConfigStore(state_dir)
        self.config.on_event = lambda kind, severity, data: self.events.emit(
            kind, severity, data, subsystem="config")

        self.netd = NetDaemon(self.events)
        self.wifid = WifiDaemon(self.events)
        self.hwd = HardwareManager(self.events)
        # RF analysis/ACS needs a way to change a channel when hostapd cannot do
        # a CSA; that path must go through configd like any other change.
        self.rf = ChannelAnalyzer(self.wifid, self.events,
                                  commit_channel=self._commit_channel)
        self.clients = ClientDatabase(os.path.join(state_dir, "clients.db"),
                                      self.events)
        self.dpi = DpiEngine(state_dir, self.clients, self.events)
        self.telemetry = TelemetryStore(os.path.join(state_dir, "metrics.db"))
        self.auth = AuthManager(os.path.join(state_dir, "auth.db"), self.config,
                                self.events)

        # Publish hardware capabilities before the first validation so the
        # schema can reject impossible configuration (e.g. MLO without hostapd).
        self.refresh_capabilities()

        # Order matters: network before wireless, since BSSes join the bridge.
        self.config.register_applier("netd", self.netd)
        self.config.register_applier("dpi", self.dpi)
        self.config.register_applier("wifid", self.wifid)
        self.config.register_health_check("connectivity", self._health_check)

        self.sampler = Sampler(self.telemetry, netd=self.netd, wifid=self.wifid,
                               clients=self.clients,
                               config_getter=self.config.get_running,
                               events=self.events)
        self.controller = UniFiControllerAgent(
            state_dir, self.config, self.netd, self.wifid, self.clients,
            dpi=self.dpi, events=self.events)
        self.api_service = ApiService(
            config_store=self.config, auth=self.auth, netd=self.netd,
            wifid=self.wifid, clients=self.clients, telemetry=self.telemetry,
            sampler=self.sampler, events=self.events, rf=self.rf,
            dpi=self.dpi, controller=self.controller)
        self.api = ApiServer(self.api_service, host, port)

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------- capability

    def refresh_capabilities(self) -> None:
        capabilities = self.wifid.capabilities()
        self.config.capabilities = capabilities
        mlo = capabilities["mlo"]
        if mlo["supported"]:
            log.info("MLO available across radios: %s",
                     ", ".join(mlo["eligible_radios"]))
        else:
            log.warning("MLO unavailable: %s", mlo["reason"] or "unknown reason")

    def _commit_channel(self, radio_id: str, channel: int) -> None:
        """Stage and commit a channel change (CSA fallback path)."""
        def mutate(cfg: dict[str, Any]) -> None:
            radios = cfg["wifi"].setdefault("radios", {})
            radios.setdefault(radio_id, {})["channel"] = channel

        self.config.stage(mutate)
        self.config.commit(user="system", source_ip="rf",
                           summary=f"channel {channel} on {radio_id}",
                           confirm_required=False)

    # ------------------------------------------------------------ health check

    def _health_check(self, cfg: dict[str, Any]) -> tuple[bool, list[str]]:
        """Post-apply check: the box must still be manageable and forwarding."""
        problems: list[str] = []

        lan_up = False
        for port in self.netd.ports.all_states(cfg):
            if port["role"] == "lan" and port["admin_up"]:
                lan_up = True
                break
        if not lan_up:
            problems.append("no LAN port is administratively up after apply")

        # At least one network must have its gateway address present, or no
        # client can reach the management UI.
        addressed = [n for n in self.netd.network_states(cfg) if n["addresses"]]
        if not addressed:
            problems.append("no network has an IP address after apply")

        if cfg.get("wifi", {}).get("networks") and not self.wifid._hostapd_running():
            # Wireless failing is serious but must not roll back a wired change;
            # report it as an event instead of failing the commit.
            self.events.emit("SSID_DOWN", subsystem="wifi",
                             data={"reason": "hostapd not running after apply"})
        return (not problems), problems

    # ----------------------------------------------------------------- startup

    def bootstrap(self) -> None:
        """Discover hardware, seed radio config, and apply the running config."""
        cfg = self.config.get_running()

        # Seed any port present in hardware but missing from config.
        discovered = self.netd.ports.discover()
        missing_ports = [p for p in discovered if p not in cfg.get("ports", {})]
        # Seed radio entries from the capability probe so the UI has something
        # to render before the operator touches anything.
        radios = self.wifid.capabilities()["radios"]
        missing_radios = [r for r in radios if r not in cfg.get("wifi", {}).get("radios", {})]

        if missing_ports or missing_radios:
            def mutate(config: dict[str, Any]) -> None:
                for port in missing_ports:
                    config["ports"][port] = {
                        "role": "lan", "name": port, "enabled": True, "mtu": 1500,
                        "speed": "auto", "duplex": "auto", "flow_control": True,
                        "network": "default"}
                for rid in missing_radios:
                    caps = radios[rid]
                    widths = caps.get("widths") or [20]
                    # Default to the widest *safe* width: 6 GHz starts at 160 so
                    # a 320 MHz claim is never made before the operator opts in.
                    default_width = 160 if caps["band"] == "6g" else (
                        80 if caps["band"] == "5g" else 20)
                    config["wifi"].setdefault("radios", {})[rid] = {
                        "enabled": True,
                        "band": caps["band"],
                        "channel": "auto",
                        "channel_width": min(default_width, max(widths)),
                        "tx_power": "auto",
                        "dfs": caps.get("dfs", True),
                    }
            self.config.stage(mutate)
            log.info("seeded %d port(s) and %d radio(s) into config",
                     len(missing_ports), len(missing_radios))

        # Apply whatever is in the running config. This must not require
        # confirmation — nobody is there to confirm at boot — and it must be
        # forced: after a reboot the kernel has no bridge and every port is
        # down, so the running config always needs (re)applying even though it
        # is byte-identical to the one already stored.
        try:
            result = self.config.commit(user="system", source_ip="boot",
                                        summary="boot apply",
                                        confirm_required=False, force=True)
            for message in result.get("messages", []):
                log.info("boot apply: %s", message)
            for warning in result.get("warnings", []):
                log.warning("boot apply: %s", warning)
        except Exception as exc:  # noqa: BLE001
            log.error("boot apply failed: %s", exc)
            self.events.emit("CONFIG_ROLLED_BACK", "error",
                             {"stage": "boot", "detail": str(exc)})

        if self.auth.needs_setup():
            log.warning("no administrator account exists; the UI will present "
                        "first-run setup")
        self.events.emit("FIRMWARE_UPDATE", "info",
                         {"detail": f"sbegw started, firmware "
                                    f"{platform.firmware_version()}"},
                         message="Gateway control plane started")

    # -------------------------------------------------------------- run loops

    def _sample_loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                snapshot = self.sampler.sample()
                self.dpi.poll(self.config.get_running())
                self.api_service.stream.publish("telemetry", {
                    "ts": snapshot["ts"],
                    "system": snapshot["system"],
                    "wans": snapshot["wans"],
                    "ports": [{k: p[k] for k in
                               ("id", "name", "link_up", "speed_mbps", "rates")}
                              for p in snapshot["ports"]],
                    "wifi": {
                        "radios": [{k: r.get(k) for k in
                                    ("id", "label", "band", "state", "runtime",
                                     "client_count")}
                                   for r in snapshot["wifi"]["radios"]],
                        "mlds": snapshot["wifi"]["mlds"],
                    },
                    "clients": {
                        "total": len([c for c in snapshot["clients"]
                                      if c.get("online")]),
                    },
                    "acceleration": snapshot["acceleration"],
                })
            except Exception:  # noqa: BLE001
                log.exception("sampler iteration failed")
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.5, SAMPLE_INTERVAL - elapsed))

    def _rf_loop(self) -> None:
        """Keep survey data fresh, and run the scheduled channel optimisation.

        The survey is a cheap read that does not disturb clients, so it can be
        polled often. A full neighbour scan and any channel change only happen in
        the configured window, because both are disruptive.
        """
        last_optimise_day = None
        while not self._stop.is_set():
            self._stop.wait(60.0)
            if self._stop.is_set():
                break
            cfg = self.config.get_running()
            try:
                self.rf.refresh_survey(cfg)
            except Exception:  # noqa: BLE001
                log.debug("survey refresh failed", exc_info=True)

            settings = cfg.get("wifi", {}).get("channel_optimisation") or {}
            if not settings.get("enabled"):
                continue
            local = time.localtime()
            hour = settings.get("schedule_hour", 4)
            today = (local.tm_year, local.tm_yday)
            if local.tm_hour != hour or last_optimise_day == today:
                continue
            last_optimise_day = today
            log.info("running scheduled channel optimisation")
            try:
                report = self.rf.optimise(cfg)
                for entry in report["radios"]:
                    log.info("channel optimisation %s: %s", entry["radio"],
                             entry["detail"])
            except Exception:  # noqa: BLE001
                log.exception("scheduled channel optimisation failed")

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(HEALTH_INTERVAL)
            if self._stop.is_set():
                break
            cfg = self.config.get_running()
            try:
                self.wifid.poll_health(cfg)
            except Exception:  # noqa: BLE001
                log.exception("wifi health poll failed")
            try:
                # DHCP/DNS dying is silent otherwise, and a router with no DHCP
                # looks identical to a router with no network at all.
                ok, detail = self.netd.services.ensure_running(cfg)
                if not ok:
                    self.events.emit(
                        "DHCP_FAILED", "error", {"detail": detail},
                        subsystem="dhcp",
                        message=f"DHCP/DNS unavailable: {detail}",
                        dedup_key="dnsmasq-down", dedup_window=300)
            except Exception:  # noqa: BLE001
                log.exception("dnsmasq health check failed")
            try:
                # Multi-WAN: reinstall the default route if the primary changed.
                primary = self.netd.wans.select_primary(cfg)
                if primary:
                    wan = cfg["wans"].get(primary, {})
                    iface = self.netd.wans.interface_for(wan, cfg)
                    gateway = self.netd.wans._default_gateway(iface)
                    if gateway:
                        from .adapters import rtnl
                        rtnl.replace_route("default", via=gateway, dev=iface,
                                           metric=10)
            except Exception:  # noqa: BLE001
                log.exception("multi-wan selection failed")
            try:
                # Fan and status LED. Driven from the health tick because both
                # are policies over the same measurements the tick already
                # gathers, and neither needs a loop of its own.
                self.hwd.poll(cfg, self._hardware_health(cfg))
            except Exception:  # noqa: BLE001
                log.exception("fan/LED policy failed")

    def _hardware_health(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Condensed health for the status LED.

        Deliberately cheap: it reuses state the daemon already tracks rather
        than probing hardware again, because it runs on every health tick.
        """
        health: dict[str, Any] = {"fault": False, "degraded": False,
                                  "wan_up": None, "applying": False}
        try:
            states = [w.get("state")
                      for w in (self.netd.wans.health() or {}).values()]
            if states:
                health["wan_up"] = any(s == "up" for s in states)
                # Several WANs where only some are up is degraded, not healthy.
                health["degraded"] = not all(s == "up" for s in states)
        except Exception:  # noqa: BLE001
            log.debug("wan health unavailable for the LED policy", exc_info=True)
        try:
            # Only radios that are actually meant to be carrying an SSID can be
            # "down". An enabled radio with no SSID assigned to it is idle, not
            # broken: on a freshly flashed unit with no Wi-Fi configured yet,
            # treating idle as degraded left the status LED blinking amber
            # forever at an operator who had done nothing wrong.
            expected = set(self.wifid._plan.get("links") or {})
            radios = [r for r in self.wifid.radio_states(cfg)
                      if r.get("id") in expected]
            # "pending" is a DFS CAC or a country update, not a fault.
            if any(r.get("health") == "failed" for r in radios):
                health["fault"] = True
            elif any(r.get("state") == "down" for r in radios):
                health["degraded"] = True
        except Exception:  # noqa: BLE001
            log.debug("radio health unavailable for the LED policy", exc_info=True)
        return health

    def run(self) -> int:
        self.bootstrap()
        # The LED shows "booting" until the first apply has been through; after
        # this point an unhealthy router is a fault, not a startup state.
        self.hwd.booted = True
        self.api.start()
        for target, name in ((self._sample_loop, "sbegw-sampler"),
                             (self._health_loop, "sbegw-health"),
                             (self._rf_loop, "sbegw-rf"),
                             (lambda: self.controller.run(self._stop),
                              "sbegw-unifi")):
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            self._threads.append(thread)

        def handle_signal(signum: int, _frame: Any) -> None:
            log.info("received signal %s; shutting down", signum)
            self._stop.set()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        while not self._stop.is_set():
            self._stop.wait(1.0)

        log.info("stopping")
        self.api.shutdown()
        return 0


def diagnose(state_dir: str) -> int:
    """Explain the state of the pieces that make a router a router.

    Written because a dead dnsmasq is invisible from the outside: the bridge is
    up, the address is right, and DHCP simply never answers. This reports the
    actual reason rather than requiring another flash-and-look cycle.
    """
    import re
    import subprocess

    from .adapters import rtnl
    from .netd import (BRIDGE, DNSMASQ_CONF, DNSMASQ_LEASES, DNSMASQ_PID,
                       ServiceManager)

    def section(title: str) -> None:
        print(f"\n=== {title} ===")

    store = ConfigStore(state_dir)
    cfg = store.get_running()
    services = ServiceManager()

    section("writable state")
    print(f"  state dir      : {state_dir}")
    writable = False
    try:
        os.makedirs(state_dir, exist_ok=True)
        probe = os.path.join(state_dir, ".probe")
        with open(probe, "w") as fh:
            fh.write("x")
        os.unlink(probe)
        writable = True
    except OSError as exc:
        print(f"  NOT WRITABLE   : {exc}")
    print(f"  writable       : {writable}")
    mounts = read_text("/proc/mounts")
    for line in mounts.splitlines():
        if " /data " in line or line.startswith("/dev/root") or " / " in line:
            print(f"  mount          : {line}")

    section("state partition selection")
    log_path = "/run/sbegw/state-mount.log"
    if os.path.exists(log_path):
        for line in read_text(log_path).splitlines():
            print(f"  {line}")
    else:
        print(f"  {log_path} not present (sbegw-state.service may not have run)")
    if "/data tmpfs" in mounts or " /data tmpfs " in mounts:
        print("  WARNING: /data is a tmpfs — configuration will NOT survive a")
        print("           reboot. The intended partition could not be mounted;")
        print("           the lines above say which candidates were rejected.")

    section("eMMC partition table")
    import glob as _glob
    for uevent in sorted(_glob.glob("/sys/block/mmcblk*/mmcblk*p*/uevent")):
        name = ""
        for line in read_text(uevent).splitlines():
            if line.startswith("PARTNAME="):
                name = line.split("=", 1)[1]
        device = "/dev/" + os.path.basename(os.path.dirname(uevent))
        sectors = read_int(os.path.join(os.path.dirname(uevent), "size")) or 0
        fstype = ""
        if which("blkid"):
            try:
                fstype = subprocess.run(
                    [which("blkid"), "-o", "value", "-s", "TYPE", device],
                    capture_output=True, text=True, timeout=5).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                pass
        mounted = " MOUNTED" if f"{device} " in mounts else ""
        print(f"  {device:16} {name:18} {sectors * 512 // 1024:>9} KiB "
              f"{fstype or '-':10}{mounted}")

    section("bridge and addresses")
    info = rtnl.link(BRIDGE)
    if info is None:
        print(f"  {BRIDGE} does not exist — netd has not applied the network")
    else:
        print(f"  {BRIDGE:8} mac={info.get('address')} "
              f"flags={','.join(info.get('flags') or [])}")
        for entry in rtnl.addresses(BRIDGE):
            for addr in entry.get("addr_info", []):
                print(f"           addr={addr.get('local')}/{addr.get('prefixlen')} "
                      f"scope={addr.get('scope')}")
    for record in rtnl.bridge_links():
        if record.get("master") == BRIDGE:
            print(f"  member   {record.get('ifname')} state={record.get('state')}")

    section("dnsmasq")
    print(f"  binary         : {which('dnsmasq')}")
    print(f"  config         : {DNSMASQ_CONF} "
          f"({'present' if os.path.exists(DNSMASQ_CONF) else 'MISSING'})")
    print(f"  pid file       : {DNSMASQ_PID} "
          f"({read_text(DNSMASQ_PID).strip() or 'empty'})")
    print(f"  lease file dir : {os.path.dirname(DNSMASQ_LEASES)} "
          f"({'present' if os.path.isdir(os.path.dirname(DNSMASQ_LEASES)) else 'MISSING'})")
    print(f"  running        : {services._running()}")

    if os.path.exists(DNSMASQ_CONF):
        try:
            run(["dnsmasq", "--test", "-C", DNSMASQ_CONF], timeout=10.0)
            print("  config test    : OK")
        except Exception as exc:  # noqa: BLE001
            print(f"  config test    : FAILED — {exc}")

    if not services._running():
        print("  attempting a start to capture the error…")
        ok, detail = services.ensure_running(cfg)
        print(f"  result         : {'started' if ok else 'FAILED'} — {detail}")

    section("control plane service state")
    # A stale dnsmasq pid usually means the supervisor is not running to revive
    # it, so report our own unit's state and recent log rather than guessing.
    if which("systemctl"):
        for unit in ("sbegw.service", "sbegw-state.service", "nginx.service"):
            try:
                active = subprocess.run(
                    [which("systemctl"), "is-active", unit],
                    capture_output=True, text=True, timeout=5).stdout.strip()
                nrestarts = subprocess.run(
                    [which("systemctl"), "show", "-p", "NRestarts", "--value", unit],
                    capture_output=True, text=True, timeout=5).stdout.strip()
                print(f"  {unit:22} {active:10} restarts={nrestarts or '?'}")
            except (OSError, subprocess.TimeoutExpired):
                print(f"  {unit:22} (could not query)")
    if which("journalctl"):
        print("  --- last 25 log lines for sbegw.service ---")
        try:
            out = subprocess.run(
                [which("journalctl"), "-u", "sbegw.service", "-n", "25",
                 "--no-pager", "--output=cat"],
                capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                print(f"  {line}")
        except (OSError, subprocess.TimeoutExpired):
            print("  (journalctl failed)")

    section("is DHCP actually serving?")
    # The single question that matters, answered explicitly rather than left to
    # be inferred from a pile of socket output.
    serving = False
    sockets = ""
    # The bridge device's own VLAN membership. Its absence forwards frames
    # between ports while never delivering them locally, which looks exactly
    # like a dead DHCP server. The vendor kernel does not add it for us.
    print()
    print("bridge VLAN membership (br-lan must appear here, not just ports):")
    try:
        out = subprocess.run(["bridge", "vlan", "show"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            if line.strip():
                print(f"  {line.rstrip()}")
        own = [l for l in out.splitlines() if l.startswith("br-lan")]
        if own:
            print(f"  -> OK: br-lan is a VLAN member ({len(own)} entry/entries)")
        else:
            print("  -> BROKEN: br-lan has NO VLAN membership of its own.")
            print("     No LAN frame can reach a local socket. Re-apply the "
                  "config, or run")
            print("     bridge vlan add dev br-lan vid 1 pvid untagged self")
    except Exception as exc:  # noqa: BLE001
        print(f"  (could not run `bridge vlan show`: {exc})")
    print()

    for argv in (["ss", "-lunp"], ["netstat", "-lunp"]):
        if which(argv[0]):
            try:
                sockets = subprocess.run(argv, capture_output=True, text=True,
                                         timeout=10).stdout
                break
            except (OSError, subprocess.TimeoutExpired):
                continue
    for line in sockets.splitlines():
        if ":67" in line and "dnsmasq" in line:
            serving = True
            print(f"  YES — {line.strip()}")
    if not serving:
        print("  NO — nothing is listening for DHCP requests on port 67")
        print("  This is the reason clients get no address.")

    leases = DNSMASQ_LEASES
    if os.path.exists(leases):
        content = read_text(leases).strip()
        entries = [l for l in content.splitlines() if l.strip()]
        print(f"  lease file {leases}: {len(entries)} lease(s)")
        for entry in entries[:10]:
            print(f"    {entry}")
    else:
        print(f"  lease file {leases} does not exist yet "
              "(normal until the first client is served)")

    # Whether this build carries the capability fix dnsmasq needs.
    unit = read_text("/etc/systemd/system/sbegw.service")
    if "CapabilityBoundingSet" in unit:
        has_setgid = "CAP_SETGID" in unit
        print(f"  unit grants CAP_SETGID: {has_setgid}"
              + ("" if has_setgid else "  <-- dnsmasq CANNOT drop privileges; "
                                       "this build predates that fix"))

    section("listening sockets")
    for argv in (["ss", "-lunp"], ["netstat", "-lunp"]):
        if which(argv[0]):
            try:
                out = subprocess.run(argv, capture_output=True, text=True,
                                     timeout=10).stdout
                for line in out.splitlines():
                    if ":53" in line or ":67" in line or ":68" in line:
                        print(f"  {line.strip()}")
                break
            except (OSError, subprocess.TimeoutExpired):
                continue
    else:
        print("  neither ss nor netstat is available")

    section("firewall")
    from .adapters import nft
    print(f"  nft available  : {nft.available()}")
    counters = nft.counters()
    print(f"  rules with counters: {len(counters)}")

    section("are DHCP requests even arriving?")
    # Distinguishes "no client is asking" from "something drops the request".
    # The accept rule's counter only moves when a DISCOVER reaches the gateway.
    dhcp_seen = 0
    if which("nft"):
        try:
            out = subprocess.run(
                [which("nft"), "-a", "list", "chain", "inet", "sbegw", "input"],
                capture_output=True, text=True, timeout=10).stdout
            # Print the entire chain with counters: filtering to the rules I
            # expected to matter meant the drop rules that actually eat traffic
            # were never shown.
            for line in out.splitlines():
                text = line.strip()
                if not text or text.startswith("table") or text.startswith("}"):
                    continue
                print(f"  {text}")
                if "zone_lan" in text and "67" in text:
                    match = re.search(r"packets (\d+)", text)
                    if match:
                        dhcp_seen = int(match.group(1))
        except (OSError, subprocess.TimeoutExpired):
            print("  (could not read nft counters)")

    print()
    for name in (BRIDGE,):
        stats = rtnl.stats(name)
        print(f"  {name}: rx_packets={stats.get('rx_packets')} "
              f"tx_packets={stats.get('tx_packets')} "
              f"rx_dropped={stats.get('rx_dropped')}")
    for record in rtnl.bridge_links():
        member = record.get("ifname")
        if record.get("master") != BRIDGE or not member:
            continue
        stats = rtnl.stats(member)
        print(f"  {member}: state={record.get('state')} "
              f"rx_packets={stats.get('rx_packets')} "
              f"tx_packets={stats.get('tx_packets')}")

    print()
    if dhcp_seen:
        print(f"  {dhcp_seen} DHCP request(s) reached the gateway and were accepted.")
        print("  If clients still get no address, the problem is between nft and")
        print("  dnsmasq — check the dnsmasq log with log-dhcp enabled.")
    else:
        print("  NO DHCP request has reached the gateway on the LAN zone.")
        print("  dnsmasq is listening, so nothing is asking it. Check that:")
        print("    - the client is plugged into a port whose state is 'forwarding'")
        print("      (a port showing 'disabled' has no carrier)")
        print("    - the client is set to DHCP rather than a static address")
        print("    - the client actually released/renewed after this box came up")

    section("rendered dnsmasq config")
    print(read_text(DNSMASQ_CONF, "(none)"))
    return 0


def diagnose_wifi(state_dir: str) -> int:
    """Explain why SSIDs are or are not on the air.

    hostapd failing to start is invisible from outside: the radios exist, the
    config validates, and simply no beacon appears. Worse, when no SSID is
    configured at all there is nothing to start and the journal is silent —
    indistinguishable from a crash. This says which of the two it is.
    """
    import glob
    import subprocess

    from .adapters import hostapd as hostapd_adapter, nl80211
    from .wifid import HOSTAPD_LOG, HOSTAPD_PID, RUN_DIR, WifiDaemon

    def section(title: str) -> None:
        print(f"\n=== {title} ===")

    store = ConfigStore(state_dir)
    cfg = store.get_running()
    wifi = cfg.get("wifi", {})
    daemon = WifiDaemon()

    section("radios discovered")
    radios = daemon.radios.capabilities()
    if not radios:
        print("  NONE. No radio was discovered, so no SSID can ever start.")
        print("  Check `ls /sys/class/ieee80211/` and `iw phy <name> info`.")
    for rid, caps in sorted(radios.items()):
        print(f"  {rid:12} band={caps.get('band')} phy={caps.get('phy')} "
              f"mac={caps.get('mac')} channels={len(caps.get('channels') or [])} "
              f"widths={caps.get('widths')} eht={caps.get('eht')} "
              f"mlo={caps.get('mlo')} max_bss={caps.get('max_ap_bss')}")

    section("configured wireless networks")
    networks = wifi.get("networks") or {}
    if not networks:
        print("  NONE — no SSID has been created yet.")
        print("  This is why hostapd is not running and the journal is silent:")
        print("  there is nothing to put on the air. Create an SSID in the UI")
        print("  (Settings -> WiFi) or with:")
        print("    curl -k -X POST https://<gw>/api/v1/wifi/networks ...")
    for wnid, wnet in sorted(networks.items()):
        bands = wnet.get("bands") or []
        present = {c.get("band") for c in radios.values()}
        missing = [b for b in bands if b not in present]
        print(f"  {wnid:12} ssid={wnet.get('ssid')!r} "
              f"enabled={wnet.get('enabled', True)} bands={bands} "
              f"security={(wnet.get('security') or {}).get('mode')}")
        if missing:
            print(f"               WARNING no radio for {', '.join(missing)}; "
                  f"it cannot come up on those bands")

    try:
        plan = daemon.build_plan(cfg)
    except Exception as exc:  # noqa: BLE001
        plan = {"links": {}, "bsses": {}, "mlds": {},
                "warnings": [f"building the plan raised: {exc}"]}

    section("MLDs")
    # From the plan, not from wifi["mlds"]: an MLD is normally derived from an
    # SSID's `mlo` flag rather than declared, so reading the stored config
    # reported "none" while two links were on the air.
    mlds = plan.get("mlds") or {}
    if not mlds:
        print("  none (MLO is optional; single-link SSIDs work without it)")
    for mid, mld in sorted(mlds.items()):
        netdevs = sorted({b["netdev"] for b in (plan.get("bsses") or {}).values()
                          if (b.get("mld") or {}).get("id") == mid
                          and b.get("netdev")})
        print(f"  {mid:12} network={mld.get('wireless_network')} "
              f"radios={','.join(mld.get('radios') or [])} "
              f"mld_addr={mld.get('mld_mac')} "
              f"{'derived' if mld.get('derived') else 'declared'}")
        # All links must share one netdev — hostapd identifies an MLD by its
        # interface name, so more than one here means the MLD will not form.
        print(f"  {'':12} netdev={','.join(netdevs) or '(none)'}"
              + ("" if len(netdevs) <= 1
                 else "   <-- WRONG: links must share one netdev"))

    section("planned BSSes")
    for warning in plan.get("warnings") or []:
        print(f"  warning: {warning}")
    if not plan.get("bsses"):
        print("  NONE. Nothing would be started even if hostapd ran.")
    for iface, bss in sorted((plan.get("bsses") or {}).items()):
        print(f"  {iface:10} ssid={bss.get('ssid')!r} band={bss.get('band')} "
              f"bssid={bss.get('bssid')} radio={bss.get('radio')} "
              f"mld={bss.get('mld')}")
    bssids = [b.get("bssid") for b in (plan.get("bsses") or {}).values()]
    if len(bssids) != len(set(bssids)):
        print("  ERROR: two BSSes share a BSSID; hostapd will refuse to start.")

    section("AP interfaces hostapd needs")
    from .adapters import rtnl as _rtnl
    if not (plan.get("bsses") or {}):
        print("  none required (no BSS planned)")
    for iface, bss in sorted((plan.get("bsses") or {}).items()):
        info = _rtnl.link(iface)
        if info is None:
            print(f"  {iface:10} MISSING — hostapd cannot start without it")
        else:
            print(f"  {iface:10} exists, address={info.get('address')} "
                  f"expected={bss.get('bssid')} "
                  f"{'OK' if (info.get('address') or '').lower() == (bss.get('bssid') or '').lower() else 'ADDRESS MISMATCH'}")

    # Whether the wiphy can run its bands on different channels at once is the
    # decisive fact for MLO on this platform: all three radios share one wiphy,
    # and if its interface combination allows only one channel then two links on
    # different channels cannot both come up ("Could not set interface flags").
    section("wiphy interface combinations")
    for phy in nl80211.all_phys():
        print(f"  {phy}:")
        text = nl80211._phy_info_text(phy)
        printing = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("valid interface combinations",
                                    "software interface modes",
                                    "Supported interface modes")):
                printing = True
                print(f"    {stripped}")
                continue
            if printing:
                if stripped.startswith("*") or stripped.startswith("#"):
                    print(f"      {stripped}")
                    if "#channels" in stripped:
                        try:
                            count = int(stripped.split("#channels <=")[1]
                                        .split(",")[0].strip())
                        except (IndexError, ValueError):
                            count = None
                        if count == 1:
                            print("      -> ONE channel only: two links on "
                                  "different channels cannot both be up, so "
                                  "MLO across bands is not possible here")
                        elif count:
                            print(f"      -> {count} simultaneous channels, "
                                  f"enough for MLO across bands")
                else:
                    printing = False

    section("hostapd")
    caps = hostapd_adapter.capabilities()
    print(f"  binary       : {caps.get('path')}")
    print(f"  resolves to  : {caps.get('real_path')}")
    print(f"  available    : {caps.get('available')}")
    print(f"  MLO / EHT    : {caps.get('mlo')} / {caps.get('eht')}")
    if caps.get("reason"):
        print(f"  reason       : {caps['reason']}")

    running = False
    try:
        with open(HOSTAPD_PID) as fh:
            pid = int(fh.read().strip())
        running = os.path.exists(f"/proc/{pid}")
        print(f"  pidfile      : {HOSTAPD_PID} -> pid {pid} "
              f"({'running' if running else 'STALE, process is gone'})")
    except (OSError, ValueError):
        print(f"  pidfile      : {HOSTAPD_PID} absent")

    section("hostapd's own log")
    print(f"  {HOSTAPD_LOG}")
    try:
        with open(HOSTAPD_LOG, errors="replace") as fh:
            body = [l.rstrip() for l in fh.read().splitlines() if l.strip()]
        if not body:
            print("  (empty — hostapd has not run, or wrote nothing)")
        for line in body[-40:]:
            print(f"  {line}")
        # The state transitions are the whole story: ENABLED means beaconing.
        states = [l for l in body if "interface state" in l or "AP-" in l]
        if states:
            print("  --- state transitions ---")
            for line in states[-12:]:
                print(f"  {line}")
    except OSError as exc:
        print(f"  (unreadable: {exc})")

    section("rendered hostapd configs")
    confs = sorted(glob.glob(os.path.join(RUN_DIR, "*.conf")))
    if not confs:
        print(f"  none in {RUN_DIR}")
    for path in confs:
        try:
            body = open(path).read()
        except OSError as exc:
            print(f"  {path}: unreadable ({exc})")
            continue
        keys = [l.split("=", 1)[0] for l in body.splitlines()
                if "=" in l and not l.startswith("#")]
        print(f"  {path} ({len(body)} bytes, {len(keys)} directives)")
        for line in body.splitlines():
            if line.startswith(("interface=", "ssid=", "channel=", "hw_mode=",
                                "mld_", "bssid=", "country_code=",
                                "ieee80211", "eht_", "he_")):
                print(f"      {line}")

    # If configs exist but nothing is running, let hostapd itself say why.
    # hostapd has no config-test flag (-t means "timestamps in debug output",
    # so passing it would have started the daemon rather than checking it);
    # _hostapd_reason does a bounded foreground run and extracts the cause.
    if confs and not running:
        section("hostapd's own verdict")
        binary = caps.get("path")
        if binary and os.path.exists(binary):
            for line in WifiDaemon._hostapd_reason(binary, confs):
                print(f"  {line}")
        else:
            print("  hostapd binary is missing; nothing can start")

    section("verdict")
    if not radios:
        print("  No radio discovered — fix that first; nothing else matters.")
    elif not networks:
        print("  No SSID is configured. hostapd is idle because there is")
        print("  nothing to broadcast. This is expected, not a fault.")
    elif not plan.get("bsses"):
        print("  SSIDs exist but none planned onto a radio. The warnings above")
        print("  say why (band with no radio, radio disabled, or BSS limit).")
    elif running:
        print("  hostapd is running with the BSSes listed above.")
    else:
        print("  SSIDs are planned but hostapd is NOT running. Its own output")
        print("  above is the reason.")
    print()
    return 0


def run_ota(args) -> int:
    """--ota-verify / --ota-apply.

    Verify is read-only and always safe. Apply writes raw flash on a
    single-bank device, so it prints the report first and says what recovery
    looks like if the second write fails.
    """
    from .otad import FirmwareUpdater, UpdateError

    updater = FirmwareUpdater()
    path = args.ota_verify or args.ota_apply
    report = updater.inspect(path)

    print(f"image   : {path}")
    print(f"size    : {report['size']} bytes")
    print(f"sha256  : {report['sha256']}")
    print(f"board   : {report['board']}")
    for payload, entry in sorted(report["payloads"].items()):
        pct = (100.0 * entry["size"] / entry["capacity"]
               if entry["capacity"] else 0.0)
        print(f"{payload:8}: {entry['size']} bytes -> {entry['partition']} "
              f"({entry['device']}, {pct:.1f}% of the partition)")
    if report["problems"]:
        print("REFUSED:")
        for problem in report["problems"]:
            print(f"  - {problem}")
        return 1
    print("verified: no problems found")

    if args.ota_verify:
        return 0

    # This board has one bank. Say so before writing, every time.
    print("writing to flash. This board has a single kernel/rootfs bank, so "
          "an interrupted write needs the U-Boot recovery page.")
    try:
        for message in updater.apply(path, reboot=args.ota_reboot,
                                    expect_sha256=args.ota_sha256):
            print(f"  {message}")
    except UpdateError as exc:
        print(f"FAILED: {exc}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sbegw",
                                     description="SBE1V1K gateway control plane")
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--check", action="store_true",
                        help="validate the stored config and exit")
    parser.add_argument("--dump-capabilities", action="store_true",
                        help="print discovered hardware capabilities and exit")
    parser.add_argument("--dhcp-trace", nargs="?", type=float, const=30.0,
                        default=None, metavar="SECONDS",
                        help="passively capture LAN frames to prove whether "
                             "client DHCP requests reach the CPU (default 30s)")
    parser.add_argument("--wifi-diagnose", action="store_true",
                        help="report why SSIDs are or are not on the air")
    parser.add_argument("--ota-verify", metavar="IMAGE",
                        help="validate a sysupgrade image without writing "
                             "anything, and report what it would do")
    parser.add_argument("--ota-apply", metavar="IMAGE",
                        help="validate and then FLASH a sysupgrade image. This "
                             "board has one bank: a failed write is "
                             "recoverable only through the U-Boot recovery page")
    parser.add_argument("--ota-reboot", action="store_true",
                        help="with --ota-apply, reboot once both payloads "
                             "verify")
    parser.add_argument("--ota-sha256", metavar="HEX",
                        help="with --ota-apply, refuse unless the image has "
                             "this sha256")
    parser.add_argument("--diagnose", action="store_true",
                        help="report why DHCP/DNS or the datapath is not working")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    if args.dump_capabilities:
        import json
        wifi = WifiDaemon()
        print(json.dumps({
            "board": platform.board(),
            "acceleration": platform.acceleration(),
            "wifi": wifi.capabilities(),
        }, indent=2, default=str))
        return 0

    if args.dhcp_trace is not None:
        from .dhcptrace import trace
        return trace(args.dhcp_trace)

    if args.ota_verify or args.ota_apply:
        return run_ota(args)

    if args.wifi_diagnose:
        return diagnose_wifi(args.state_dir)

    if args.diagnose:
        return diagnose(args.state_dir)

    if args.check:
        store = ConfigStore(args.state_dir)
        try:
            warnings = schema.validate(store.get_running())
        except schema.ValidationError as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return 1
        for warning in warnings:
            print(f"warning: {warning}")
        print("config is valid")
        return 0

    gateway = Gateway(state_dir=args.state_dir, host=args.host, port=args.port)
    return gateway.run()


if __name__ == "__main__":
    sys.exit(main())
