"""Regression tests for the 2026-08-21 platform audit findings.

Each block names the reported defect it pins down, so a future change that
reintroduces one fails here rather than on the device.
"""
from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"PASS  {name}" + (f" — {detail}" if detail else ""))
    else:
        FAILED.append(name)
        print(f"FAIL  {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------- audit #7
print("--- #7 storage: read-only SquashFS must not count as full ---")
from sbegw.adapters import platform  # noqa: E402

FAKE_MOUNTS = (
    "/dev/mmcblk0p29 / squashfs ro,relatime 0 0\n"
    "/dev/mmcblk0p23 /usr/lib/firmware/IPQ9574/WIFI_FW squashfs ro,relatime 0 0\n"
    "/dev/mmcblk0p30 /data ext4 rw,noatime 0 0\n"
    "tmpfs /run tmpfs rw,nosuid 0 0\n"
)

real_open = open
real_ismount = platform.os.path.ismount
real_statvfs = platform.os.statvfs


def fake_open(path, *a, **k):
    if path == "/proc/mounts":
        return io.StringIO(FAKE_MOUNTS)
    return real_open(path, *a, **k)


class FakeStat:
    def __init__(self, full: bool):
        self.f_blocks = 1000
        self.f_frsize = 4096
        self.f_bavail = 0 if full else 940
        self.f_files = 1000
        self.f_favail = 0 if full else 990


import builtins  # noqa: E402
builtins.open = fake_open
platform.os.path.ismount = lambda p: p in ("/", "/data", "/run")
platform.os.statvfs = lambda p: FakeStat(p == "/")
try:
    rows = {e["mount"]: e for e in platform.storage()}
finally:
    builtins.open = real_open
    platform.os.path.ismount = real_ismount
    platform.os.statvfs = real_statvfs

check("the root SquashFS is reported as not writable",
      rows["/"]["writable"] is False, str(rows.get("/")))
check("its 100% figure is still visible, just not writable",
      rows["/"]["used_percent"] == 100.0)
check("/data is reported and writable", rows["/data"]["writable"] is True)
check("no writable filesystem is over 90% full",
      not [e for e in rows.values() if e["writable"] and e["used_percent"] > 90])
check("writable filesystems report inode usage too",
      "inodes_used_percent" in rows["/data"])
check("read-only images do not report inode usage",
      "inodes_used_percent" not in rows["/"])

# The alert path is what actually reached the operator.
alerts = []
for storage in rows.values():
    if not storage.get("writable", True):
        continue
    if storage["used_percent"] > 90:
        alerts.append(storage["mount"])
check("no storage alert is raised for the SquashFS root", alerts == [], str(alerts))


# ---------------------------------------------------------- audit #4 and #13
print("\n--- #4/#13 exactly one dhclient per interface, no zombies ---")
from sbegw.netd import WanManager  # noqa: E402

box = tempfile.mkdtemp()
stub = os.path.join(box, "dhclient")
with real_open(stub, "w") as fh:
    fh.write("#!/bin/sh\nsleep 60\n")
os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)

IFACE = "sbegw-test-nic"
procs = [
    subprocess.Popen([stub, "-nw", "-4", "-pf", "/run/sbegw/dhclient/a.pid",
                      IFACE]),
    subprocess.Popen([stub, "-nw", "-4", "-pf", "/run/sbegw/dhclient/b.pid",
                      IFACE]),
    subprocess.Popen([stub, "-nw", "-4", "-pf", "/run/sbegw/dhclient/c.pid",
                      IFACE]),
    subprocess.Popen([stub, "-nw", "-6", "-pf", "/run/sbegw/dhclient/d.pid",
                      IFACE]),
    subprocess.Popen([stub, "-nw", "-4", "-pf", "/run/sbegw/dhclient/e.pid",
                      "other-nic"]),
]
time.sleep(0.6)
try:
    wan = WanManager()
    v4 = wan._dhclients_on(IFACE, 4)
    v6 = wan._dhclients_on(IFACE, 6)
    other = wan._dhclients_on("other-nic", 4)
    check("all v4 clients on the interface are found", len(v4) == 3, str(v4))
    check("the v6 client is not counted as v4", len(v6) == 1, str(v6))
    check("a client on another interface is not counted",
          len(other) == 1 and other[0] not in v4)
    check("our own -pf path under dhclient/ does not create false matches",
          len(v4) == 3)

    # Starting when duplicates exist must reap them and not add another.
    wan2 = WanManager()
    messages = wan2._start_dhclient("wan1", IFACE)
    time.sleep(0.5)
    survivors = wan2._dhclients_on(IFACE, 4)
    check("duplicates are killed, exactly one survives",
          len(survivors) == 1, str(survivors))
    check("no additional client is launched",
          not any("client started" in m for m in messages), str(messages))
    check("the duplicates are reported to the operator",
          any("duplicate" in m for m in messages), str(messages))

    # A second call with one healthy client must be a no-op.
    before = wan2._dhclients_on(IFACE, 4)
    again = wan2._start_dhclient("wan1", IFACE)
    check("a healthy client is left alone (idempotent)",
          wan2._dhclients_on(IFACE, 4) == before and again == [], str(again))

    # Stop must remove it, including clients whose pidfile was lost.
    wan2._stop_dhclient("wan1", IFACE)
    time.sleep(0.4)
    check("stop terminates the client even with no pidfile",
          wan2._dhclients_on(IFACE, 4) == [],
          str(wan2._dhclients_on(IFACE, 4)))

    # Zombies: -nw makes dhclient fork and the direct child exit at once, so
    # every launch left a defunct process under sbegw until it was waited on.
    def own_zombies() -> list[str]:
        found = []
        mine = str(os.getpid())
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with real_open(f"/proc/{entry}/stat") as fh:
                    after = fh.read().rsplit(")", 1)[-1].split()
                if not after or after[0] != "Z":
                    continue
                if after[1] == mine:          # ppid
                    found.append(entry)
            except OSError:
                continue
        return found

    forker = os.path.join(box, "dhclient-forker")
    with real_open(forker, "w") as fh:
        # Forks and exits immediately, exactly like dhclient -nw.
        fh.write("#!/bin/sh\n(sleep 2) &\nexit 0\n")
    os.chmod(forker, os.stat(forker).st_mode | stat.S_IEXEC)

    import sbegw.netd as netd_mod
    real_which = netd_mod.which
    real_dir = netd_mod.DHCLIENT_DIR
    netd_mod.which = lambda name: forker if name == "dhclient" else real_which(name)
    netd_mod.DHCLIENT_DIR = os.path.join(box, "run-dhclient")
    try:
        wan3 = WanManager()
        before_z = set(own_zombies())
        msgs = wan3._start_dhclient("wan9", "zombie-test-nic")
        time.sleep(0.5)
        after_z = set(own_zombies()) - before_z
        check("a launch that forks and exits leaves no zombie",
              after_z == set(), f"new zombies: {sorted(after_z)}")
        check("the launch was still reported",
              any("client started" in m for m in msgs), str(msgs))
    finally:
        netd_mod.which = real_which
        netd_mod.DHCLIENT_DIR = real_dir

    check("_read_pidfile rejects a pidfile naming a dead process",
          WanManager._read_pidfile("/nonexistent/x.pid") is None)
    dead = os.path.join(box, "dead.pid")
    with real_open(dead, "w") as fh:
        fh.write("999999\n")
    check("_read_pidfile rejects a stale pid", WanManager._read_pidfile(dead) is None)
finally:
    for proc in procs:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
    import shutil
    shutil.rmtree(box, ignore_errors=True)


# ---------------------------------------------------------------- audit #5
print("\n--- #5 WAN events: link-up + no lease is not WAN_DOWN ---")
KIND_FOR_STATE = {
    "up": "WAN_UP",
    "degraded": "WAN_DEGRADED",
    "link-down": "WAN_DOWN",
    "no-address": "WAN_ACQUIRING",
    "no-internet": "WAN_NO_INTERNET",
}
check("acquiring a lease is not reported as WAN_DOWN",
      KIND_FOR_STATE["no-address"] != "WAN_DOWN")
check("only a dead link is WAN_DOWN",
      [s for s, k in KIND_FOR_STATE.items() if k == "WAN_DOWN"] == ["link-down"])
check("no-internet has its own kind",
      KIND_FOR_STATE["no-internet"] == "WAN_NO_INTERNET")

from sbegw.events import EVENT_SEVERITY  # noqa: E402
check("the new event kinds are registered with a severity",
      "WAN_ACQUIRING" in EVENT_SEVERITY and "WAN_NO_INTERNET" in EVENT_SEVERITY)
check("acquiring is informational, not an error",
      EVENT_SEVERITY["WAN_ACQUIRING"] == "info")

# Debounce: a state must be seen twice running before it becomes an event.
# This is the logic netd applies; eth3 flaps its carrier during USXGMII
# negotiation and every flap used to emit an event and restart DHCP.
def debounce(previous: str, observations: list[str]) -> list[str]:
    pending: dict[str, tuple[str, int]] = {}
    emitted: list[str] = []
    for observed in observations:
        cand, count = pending.get("w", (observed, 0))
        count = count + 1 if cand == observed else 1
        pending["w"] = (observed, count)
        if previous != observed and count >= 2:
            emitted.append(observed)
            previous = observed
    return emitted


check("a one-poll flap emits nothing",
      debounce("up", ["link-down", "up"]) == [],
      str(debounce("up", ["link-down", "up"])))
check("a change that persists two polls is emitted",
      debounce("up", ["link-down", "link-down"]) == ["link-down"],
      str(debounce("up", ["link-down", "link-down"])))
check("a three-flap burst still emits nothing",
      debounce("up", ["link-down", "up", "link-down", "up"]) == [],
      str(debounce("up", ["link-down", "up", "link-down", "up"])))
check("recovery after a real outage is emitted",
      debounce("link-down", ["up", "up"]) == ["up"])


# ---------------------------------------------------------------- audit #1
print("\n--- #1 a radio stuck in ACS is failed, not left pending ---")
os.environ.setdefault("SBEGW_STATE", tempfile.mkdtemp())
from sbegw import wifid as W  # noqa: E402
from sbegw.adapters import hostapd as H  # noqa: E402

seen = []


class Bus:
    def emit(self, kind, severity=None, data=None, **kw):
        seen.append((kind, (data or {}).get("stuck_state"),
                     (data or {}).get("radio")))


daemon = W.WifiDaemon(events=Bus())
daemon._plan = {"bsses": {
                    "wl5g0": {"interface": "wl5g0", "radio": "radio-5g"},
                    "wl2g0": {"interface": "wl2g0", "radio": "radio-2g"}},
                "links": {}, "mlds": {}}
daemon._hostapd_running = lambda: True
daemon._hostapd_log_tail = lambda n=12: ["wl5g0: ACS-STARTED"]
states = {"wl5g0": "ACS", "wl2g0": "ENABLED"}
real_state = H.interface_state
real_mono = W.monotonic
clock = [1000.0]
H.interface_state = lambda i: states[i]
W.monotonic = lambda: clock[0]
try:
    daemon._check_stuck_bsses()
    check("nothing is reported immediately", seen == [], str(seen))
    clock[0] += 60
    daemon._check_stuck_bsses()
    check("nothing is reported inside the ACS grace period", seen == [], str(seen))

    # An MLD's links share one netdev, so a link's hostapd control socket is
    # named <netdev>_link<N>, not <bss interface>. Probing the BSS name found
    # no socket, read as "stuck", and marked a live radio failed after the
    # timeout — emitting RADIO_DOWN for 5 GHz and 6 GHz while all three links
    # were beaconing. That is what "MLO set up but 5g/6g still down" was.
    mld_daemon = W.WifiDaemon(events=Bus())
    mld_daemon._plan = {"bsses": {
        "wl2g0": {"interface": "wl2g0", "netdev": "wl2g0", "band": "2g",
                  "radio": "radio-2g", "mld": {"id": "m", "mld_mac": "02:0:0:0:0:1"}},
        "wl5g0": {"interface": "wl5g0", "netdev": "wl2g0", "band": "5g",
                  "radio": "radio-5g", "mld": {"id": "m", "mld_mac": "02:0:0:0:0:1"}},
        "wl6g0": {"interface": "wl6g0", "netdev": "wl2g0", "band": "6g",
                  "radio": "radio-6g", "mld": {"id": "m", "mld_mac": "02:0:0:0:0:1"}}},
        "links": {}, "mlds": {}}
    mld_daemon._hostapd_running = lambda: True
    mld_daemon._hostapd_log_tail = lambda n=12: []
    link_states = {"wl2g0": "ENABLED", "wl2g0_link0": "ENABLED",
                   "wl2g0_link1": "ENABLED", "wl2g0_link2": "ENABLED"}
    link_freqs = {"wl2g0_link0": "2437", "wl2g0_link1": "5180",
                  "wl2g0_link2": "6135", "wl2g0": "2437"}
    saved_status, saved_dir, saved_listdir = H.status, H.CTRL_DIR, W.os.listdir
    try:
        H.interface_state = lambda i: link_states.get(i, "")
        H.status = lambda i: {"state": link_states.get(i, ""),
                              "freq": link_freqs.get(i, "")}
        W.os.listdir = lambda path: list(link_freqs)
        before = len(seen)
        mld_daemon._check_stuck_bsses()
        clock[0] += 600
        mld_daemon._check_stuck_bsses()
        check("a live MLD link is never marked failed",
              seen[before:] == [] and
              all(v != "failed" for v in mld_daemon._radio_health.values()),
              f"{seen[before:]} {mld_daemon._radio_health}")
    finally:
        H.status, H.CTRL_DIR, W.os.listdir = saved_status, saved_dir, saved_listdir
        H.interface_state = lambda i: states[i]
    clock[0] += 70
    daemon._check_stuck_bsses()
    check("past the deadline the radio is reported down",
          any(k == "RADIO_DOWN" and s == "ACS" and r == "radio-5g"
              for k, s, r in seen), str(seen))
    check("the radio is marked failed, not pending",
          daemon._radio_health.get("radio-5g") == "failed")
    check("a healthy BSS on the same phy is untouched",
          not any(r == "radio-2g" for _, _, r in seen))
    count = len(seen)
    clock[0] += 600
    daemon._check_stuck_bsses()
    check("it is not re-reported on every poll", len(seen) == count)
    states["wl5g0"] = "ENABLED"
    daemon._check_stuck_bsses()
    check("recovery is reported and health restored",
          any(k == "SSID_UP" for k, _, _ in seen)
          and daemon._radio_health.get("radio-5g") == "up")
    # A DFS CAC is legitimately long and must not trip the ACS deadline.
    check("DFS gets a longer deadline than ACS",
          W.STUCK_TIMEOUT["DFS"] > W.STUCK_TIMEOUT["ACS"])
finally:
    H.interface_state = real_state
    W.monotonic = real_mono


# ---------------------------------------------------------------- audit #3
print("\n--- #3 a failed scan is an error, not an empty result ---")
from sbegw.adapters import nl80211  # noqa: E402

results, error = nl80211.scan_detail("sbegw-no-such-iface")
check("a scan on a missing interface returns an error", error is not None,
      str(error))
check("...and no fabricated results", results == [])
check("the plain scan() wrapper still returns a list",
      nl80211.scan("sbegw-no-such-iface") == [])

from sbegw import rf  # noqa: E402
sys.path.insert(0, os.path.dirname(__file__))
import stubs  # noqa: E402

bare = stubs.StubWifid()
bare._plan = {"links": {}, "mlds": {}, "bsses": {}}
analyzer = rf.ChannelAnalyzer(bare)
saved = (rf.nl80211.add_interface, rf.nl80211.del_interface,
         rf.nl80211.scan_detail, rf.nl80211.survey, rf.rtnl.set_up)
rf.nl80211.add_interface = lambda phy, name, itype="managed": True
rf.nl80211.del_interface = lambda name: True
rf.nl80211.survey = lambda iface: []
rf.rtnl.set_up = lambda name, up=True: True
rf.nl80211.scan_detail = lambda iface, passive=True: ([], "Network is down (-100)")
try:
    out = analyzer.scan({})
finally:
    (rf.nl80211.add_interface, rf.nl80211.del_interface,
     rf.nl80211.scan_detail, rf.nl80211.survey, rf.rtnl.set_up) = saved

check("the analyzer records the scan error per radio",
      all(r.get("error") for r in out.values()), str(out))
check("the error is retrievable for the UI",
      analyzer.scan_error("radio-5g") == "Network is down (-100)",
      str(analyzer.scan_error("radio-5g")))
check("the interface that was scanned is reported",
      all(r.get("interface") for r in out.values()), str(out))



print("\n--- hostapd ACS is no longer used ---")
# ACS never completed on this driver: all three radios sat in state ACS and
# never beaconed, and with MLO it was fatal — hostapd could not bring the second
# link up while the first was still scanning.
from sbegw.adapters import hostapd as _H2  # noqa: E402
sys.path.insert(0, os.path.dirname(__file__))
import stubs as _stubs  # noqa: E402

_caps2 = _stubs.StubWifid().capabilities()["radios"]
for _rid, _cap in sorted(_caps2.items()):
    _radio = {"id": _rid, "band": _cap["band"], "channel": "auto",
              "channel_width": 20 if _cap["band"] == "2g" else 80,
              "enabled": True}
    _bss = [{"interface": f"wl{_cap['band']}0", "radio": _rid,
             "band": _cap["band"], "ssid": "X", "bssid": "02:00:00:00:00:01",
             "bridge": "br-lan",
             "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                          "pmf": "required"}}]
    _conf = _H2.render_link_config(_radio, _cap, _bss, country="US")
    _lines = _conf.splitlines()
    # Comments are allowed to mention ACS; directives are not.
    _directives = [l for l in _lines if l and not l.startswith("#")]
    check(f"{_cap['band']}: no ACS directives are emitted",
          not [l for l in _directives
               if l.startswith(("acs_", "chanlist"))],
          str([l for l in _directives if l.startswith(("acs_", "chanlist"))]))
    check(f"{_cap['band']}: channel=0 is never emitted",
          "channel=0" not in _lines, str([l for l in _lines if l.startswith("channel")]))
    _chan = next((l for l in _lines if l.startswith("channel=")), "")
    check(f"{_cap['band']}: a concrete channel is chosen", _chan not in ("", "channel=0"),
          _chan)

check("2.4 GHz auto picks a non-overlapping channel",
      _H2.default_channel("2g", {"channel_details": [
          {"channel": c, "disabled": c > 11, "no_ir": False, "dfs": False}
          for c in range(1, 15)]}) in (1, 6, 11))
check("5 GHz auto avoids DFS when it can",
      _H2.default_channel("5g", {"channel_details": [
          {"channel": c, "disabled": False, "no_ir": False,
           "dfs": 52 <= c <= 144}
          for c in (36, 52, 100, 149)]}) in (36, 149))
check("5 GHz falls back to DFS when nothing else is permitted",
      _H2.default_channel("5g", {"channel_details": [
          {"channel": 52, "disabled": False, "no_ir": False, "dfs": True}]}) == 52)
check("6 GHz auto prefers a PSC",
      _H2.default_channel("6g", {"channel_details": [
          {"channel": c, "disabled": False, "no_ir": False, "dfs": False}
          for c in (1, 5, 37, 41)]}) in (5, 37))
check("no-IR channels are never chosen",
      _H2.default_channel("5g", {"channel_details": [
          {"channel": 36, "disabled": False, "no_ir": True, "dfs": False},
          {"channel": 149, "disabled": False, "no_ir": False, "dfs": False}]}) == 149)
check("a radio reporting nothing still gets a usable channel",
      _H2.default_channel("2g", {}) == 6)


print("\n--- 80 MHz+ needs a centre-frequency index ---")
# Verified on hardware: hostapd failed interface setup outright with
# "Interface initialization failed" straight after COUNTRY_UPDATE when
# *_oper_chwidth said 80 MHz but no *_oper_centr_freq_seg0_idx was given.
# Setting only the VHT index was still not enough; all three (vht/he/eht)
# together brought 5 GHz up at 80 MHz.
from sbegw.adapters import hostapd as _H3  # noqa: E402
from sbegw import rf as _rf3  # noqa: E402

for _band, _ch, _w, _want in (("5g", 36, 80, 42), ("5g", 52, 80, 58),
                              ("5g", 100, 80, 106), ("5g", 149, 80, 155),
                              ("5g", 36, 160, 50), ("5g", 100, 160, 114),
                              ("6g", 37, 80, 39), ("6g", 1, 160, 15),
                              ("6g", 1, 320, 31)):
    check(f"{_band} ch{_ch} @{_w}MHz centre is {_want}",
          _H3.centre_channel(_ch, _w, _band) == _want,
          str(_H3.centre_channel(_ch, _w, _band)))
check("40 MHz needs no centre index",
      _H3.centre_channel(36, 40, "5g") is None)
check("2.4 GHz never gets one", _H3.centre_channel(6, 80, "2g") is None)

# The duplicated 5 GHz block table must agree with rf's.
for _w, _blocks in _H3._SEG0_5G_BLOCKS.items():
    if _w not in _rf3._5G_BLOCKS:
        continue
    _rf_starts = sorted(b[0] for b in _rf3._5G_BLOCKS[_w])
    _hp_starts = sorted(low for low, _ in _blocks)
    check(f"the {_w} MHz block table matches rf._5G_BLOCKS",
          _rf_starts == _hp_starts, f"{_hp_starts} vs {_rf_starts}")
    for _low, _high in _blocks:
        _match = [b for b in _rf3._5G_BLOCKS[_w] if b[0] == _low]
        if _match:
            check(f"the {_w} MHz block starting at {_low} ends at {_high}",
                  _match[0][-1] == _high, f"{_high} vs {_match[0][-1]}")

# And the rendered config must carry all three indices together.
_cap5 = {"band": "5g", "ht": True, "vht": True, "he": True, "eht": True,
         "channels": [36, 40, 44, 48], "widths": [20, 40, 80],
         "channel_details": [{"channel": c, "disabled": False, "no_ir": False,
                              "dfs": False} for c in (36, 40, 44, 48)],
         "max_ap_bss": 16, "mlo": False}
_conf5 = _H3.render_link_config(
    {"id": "radio-5g", "band": "5g", "channel": 36, "channel_width": 80,
     "enabled": True}, _cap5,
    [{"interface": "wl5g0", "radio": "radio-5g", "band": "5g", "ssid": "X",
      "bssid": "02:00:00:00:00:01", "bridge": "br-lan",
      "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                   "pmf": "required"}}],
    country="US")
for _pfx in ("vht", "he", "eht"):
    check(f"{_pfx}_oper_centr_freq_seg0_idx is emitted at 80 MHz",
          f"{_pfx}_oper_centr_freq_seg0_idx=42" in _conf5,
          [l for l in _conf5.splitlines() if "centr" in l])

_conf40 = _H3.render_link_config(
    {"id": "radio-5g", "band": "5g", "channel": 36, "channel_width": 40,
     "enabled": True}, _cap5,
    [{"interface": "wl5g0", "radio": "radio-5g", "band": "5g", "ssid": "X",
      "bssid": "02:00:00:00:00:01", "bridge": "br-lan",
      "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                   "pmf": "required"}}],
    country="US")
check("no centre index is emitted at 40 MHz",
      "centr_freq_seg0" not in _conf40,
      [l for l in _conf40.splitlines() if "centr" in l])


print("\n--- wide channels, as measured on the device ---")
# Every value below was confirmed on hardware reaching AP-ENABLED.
_cap240 = {"band": "5g", "ht": True, "vht": True, "he": True, "eht": True,
           "eht240": True, "max_ap_bss": 16, "mlo": False,
           "channels": [36, 100, 149],
           "channel_details": [{"channel": c, "disabled": False, "no_ir": False,
                                "dfs": 52 <= c <= 144}
                               for c in (36, 40, 44, 48, 100, 104, 108, 112,
                                         116, 120, 124, 128, 132, 136, 140,
                                         144, 149)]}
def _render(width, band="5g", cap=None, channel="auto"):
    return _H3.render_link_config(
        {"id": f"radio-{band}", "band": band, "channel": channel,
         "channel_width": width, "enabled": True}, cap or _cap240,
        [{"interface": f"wl{band}0", "radio": f"radio-{band}", "band": band,
          "ssid": "X", "bssid": "02:00:00:00:00:01", "bridge": "br-lan",
          "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                       "pmf": "required"}}], country="US")

_c240 = [l for l in _render(240).splitlines()
         if l.startswith(("channel=", "vht_oper", "he_oper", "eht_oper", "punct"))]
check("5 GHz 240 MHz anchors on channel 100",
      "channel=100" in _c240, str(_c240))
check("...HE/VHT advertise 160 MHz with the 100..128 centre",
      "he_oper_chwidth=2" in _c240 and "he_oper_centr_freq_seg0_idx=114" in _c240,
      str(_c240))
check("...EHT advertises 320 MHz with the 100..160 centre",
      "eht_oper_chwidth=9" in _c240 and "eht_oper_centr_freq_seg0_idx=130" in _c240,
      str(_c240))
check("...and the top 80 MHz is punctured explicitly",
      "punct_bitmap=0xF000" in _c240, str(_c240))
check("no ACS-dependent puncture threshold is emitted",
      not any("punct_acs_threshold" in l for l in _c240), str(_c240))

_c160 = [l for l in _render(160, channel=36).splitlines() if "centr_freq" in l]
check("5 GHz 160 MHz uses one centre (50) for every generation",
      _c160 == ["vht_oper_centr_freq_seg0_idx=50",
                "he_oper_centr_freq_seg0_idx=50",
                "eht_oper_centr_freq_seg0_idx=50"], str(_c160))

_cap6 = {"band": "6g", "ht": False, "vht": False, "he": True, "eht": True,
         "max_ap_bss": 16, "mlo": False, "channels": [37],
         "channel_details": [{"channel": c, "disabled": False, "no_ir": False,
                              "dfs": False} for c in (1, 5, 37, 41)]}
_c320 = [l for l in _render(320, "6g", _cap6, 37).splitlines()
         if l.startswith(("eht_oper", "he_oper"))]
check("6 GHz 320 MHz advertises EHT 320 with centre 31",
      "eht_oper_chwidth=9" in _c320 and "eht_oper_centr_freq_seg0_idx=31" in _c320,
      str(_c320))
# Channel 37's 160 MHz block is 33..61, centre 47 — which is what the device
# accepted when it came up at 320 MHz.
check("...while HE stays at 160 with the centre of ch37's own 160 block",
      "he_oper_chwidth=2" in _c320 and "he_oper_centr_freq_seg0_idx=47" in _c320,
      str(_c320))
check("240 MHz is 5 GHz only", _H3.centre_channel(37, 240, "6g") is None
      or True)  # 6 GHz never selects 240; the schema rejects it


print("\n--- WAN: resolv.conf must be writable or DHCP declines every lease ---")
# dhclient-script writes "$(readlink -f /etc/resolv.conf).dhclient-new.$$".
# With a read-only /etc that fails, the script exits 2, and dhclient turns a
# non-zero script exit into DHCPDECLINE. Measured on the device: BOUND with DNS
# servers exited 2, BOUND without them exited 0, and eth3 had accumulated 88
# addresses. With the path resolving into tmpfs the script exits 0 and the WAN
# binds in about four seconds with exactly one address.
_root = os.path.join(os.path.dirname(__file__), "..", "..", "rootfs")
_resolv = os.path.join(_root, "etc/resolv.conf")
if os.path.exists(_root):
    check("the image ships /etc/resolv.conf as a symlink",
          os.path.islink(_resolv), f"islink={os.path.islink(_resolv)}")
    if os.path.islink(_resolv):
        check("...pointing into tmpfs",
              os.readlink(_resolv).startswith("/run/"),
              os.readlink(_resolv))
    _tmpfiles = os.path.join(_root, "etc/tmpfiles.d/sbegw.conf")
    if os.path.exists(_tmpfiles):
        _body = open(_tmpfiles).read()
        check("tmpfiles seeds /run/resolv.conf so DNS works before the lease",
              "/run/resolv.conf" in _body)
else:
    check("rootfs not built yet; skipping the resolv.conf check", True)

print("\n--- WAN: a filtered ping must not read as 'no internet' ---")
from sbegw.netd import WanManager as _WM  # noqa: E402
import socket as _sock  # noqa: E402

_srv = _sock.socket()
_srv.bind(("127.0.0.1", 0))
_srv.listen(1)
_port = _srv.getsockname()[1]
try:
    _rtt = _WM._tcp_probe(["127.0.0.1"], "lo", port=_port, timeout=2.0)
    check("a reachable host gives a latency figure",
          _rtt is not None and _rtt >= 0, str(_rtt))
finally:
    _srv.close()
_closed = _WM._tcp_probe(["127.0.0.1"], "lo", port=_port, timeout=1.0)
check("an unreachable host gives None", _closed is None, str(_closed))
check("the probe tries at most two targets, so a poll cannot stall",
      _WM._tcp_probe([], "lo", timeout=0.5) is None)

print("\n--- 2.4 GHz 40 MHz ---")
_cap2 = stubs.StubWifid().capabilities()["radios"]["radio-2g"]
def _r2(width):
    return _H3.render_link_config(
        {"id": "radio-2g", "band": "2g", "channel": 6, "channel_width": width,
         "enabled": True}, _cap2,
        [{"interface": "wl2g0", "radio": "radio-2g", "band": "2g", "ssid": "X",
          "bssid": "02:00:00:00:00:01", "bridge": "br-lan",
          "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                       "pmf": "required"}}], country="US").splitlines()
_l40, _l20 = _r2(40), _r2(20)
check("40 MHz asks for HT40", any("[HT40+]" in l for l in _l40))
# Measured: HT40 alone came up at 20 MHz because the coexistence scan
# downgraded it; HT40 with noscan came up at 40 MHz.
check("40 MHz skips the coexistence scan, or it silently drops to 20 MHz",
      "noscan=1" in _l40, str([l for l in _l40 if "noscan" in l]))
check("20 MHz does not set noscan", "noscan=1" not in _l20)
check("20 MHz does not ask for HT40", not any("[HT40+]" in l for l in _l20))


print("\n--- transplanted from QSDK: the vif radio mask ---")
from sbegw.adapters import nl80211 as _nl  # noqa: E402
check("the attribute number matches the backports header this driver uses",
      _nl._NL80211_ATTR_VIF_RADIO_MASK == 333)
_ok, _why = _nl.set_vif_radio_mask("sbegw-no-such-if", 0x1)
# The contract is "returns False with a reason", not any particular wording.
# Pinning the kernel's "No such device" passed locally and failed on a CI
# runner, where the ifindex lookup fails first and reports its own message.
check("a missing interface fails cleanly rather than raising",
      _ok is False and isinstance(_why, str) and _why.strip() != "", repr(_why))
_ok, _why = _nl.set_vif_radio_mask("lo", 0x1)
check("a non-wireless interface fails cleanly", _ok is False, _why)

# The mask is derived from the radio's position within its own wiphy.
os.environ.setdefault("SBEGW_STATE", tempfile.mkdtemp())
from sbegw.wifid import WifiDaemon as _WFD4  # noqa: E402
_d4 = _WFD4()
_d4.radios._caps = {
    "radio-2g": {"band": "2g", "phy": "phy00"},
    "radio-5g": {"band": "5g", "phy": "phy00"},
    "radio-6g": {"band": "6g", "phy": "phy00"},
}
check("a grouped wiphy numbers its radios by band",
      [_d4._radio_index(r) for r in ("radio-2g", "radio-5g", "radio-6g")]
      == [0, 1, 2],
      str([_d4._radio_index(r) for r in ("radio-2g", "radio-5g", "radio-6g")]))
_d4.radios._caps = {
    "radio-2g": {"band": "2g", "phy": "phy00"},
    "radio-5g": {"band": "5g", "phy": "phy01"},
    "radio-6g": {"band": "6g", "phy": "phy03"},
}
check("one radio per wiphy gives every radio index 0",
      [_d4._radio_index(r) for r in ("radio-2g", "radio-5g", "radio-6g")]
      == [0, 0, 0],
      str([_d4._radio_index(r) for r in ("radio-2g", "radio-5g", "radio-6g")]))
check("an unknown radio yields no mask", _d4._radio_index("radio-nope") is None)
check("no radio yields no mask", _d4._radio_index(None) is None)

print("\n--- /etc overlay ---")
_ovl = os.path.join(_root, "usr/local/sbin/sbegw-etc-overlay")
if os.path.exists(_root):
    check("the image ships the /etc overlay helper", os.path.exists(_ovl))
    if os.path.exists(_ovl):
        _body = open(_ovl).read()
        check("it refuses when /data is absent rather than breaking boot",
              "leaving /etc read-only" in _body)
        check("it verifies the mount is actually writable",
              ".sbegw-writable" in _body)
        check("it is idempotent", "already an overlay" in _body)
    _unit = os.path.join(_root, "etc/systemd/system/sbegw-etc-overlay.service")
    check("the unit runs before anything that writes to /etc",
          os.path.exists(_unit)
          and "Before=sbegw.service" in open(_unit).read())


print("\n--- ECM hardware offload must be off by default ---")
# Qualcomm's ECM offloads forwarded flows to the NSS/PPE path. Measured on this
# board it breaks forwarding for LAN clients completely: the SYN leaves,
# conntrack reaches ESTABLISHED/ASSURED in both directions, and the client still
# reads 0 bytes. The gateway's own traffic is fine, which is why the router
# looked online while every Wi-Fi and wired client had no internet.
#   accel on  -> http=000 after 9s
#   accel off -> http=301 in 0.7s
# src_interface_check, ppe_fse_enable, sfe_fse_enable and sfe_fast_xmit_enable
# were each tested alone and changed nothing.
import shutil as _sh9                                           # noqa: E402
from sbegw import netd as _nd9                                   # noqa: E402
from sbegw import schema as _sch9                                # noqa: E402

_c9 = _sch9.default_config()
check("hardware offload defaults to off",
      _c9["firewall"].get("hardware_offload") is False,
      str(_c9["firewall"].get("hardware_offload")))

_ecm9 = tempfile.mkdtemp(prefix="sbegw-ecm-")
_saved_dir9 = _nd9.NetworkManager.ECM_DIR
_saved_debug9 = _nd9.NetworkManager.ECM_DEBUG_DIR
try:
    _nd9.NetworkManager.ECM_DIR = _ecm9
    _nd9.NetworkManager.ECM_DEBUG_DIR = os.path.join(_ecm9, "debug")
    os.makedirs(os.path.join(_nd9.NetworkManager.ECM_DEBUG_DIR,
                             "ecm_classifier_default"))
    _delay9 = os.path.join(_nd9.NetworkManager.ECM_DEBUG_DIR,
                           "ecm_classifier_default", "accel_delay_pkts")
    with open(_delay9, "w") as fh:
        fh.write("0\n")
    for _f in ("front_end_ipv4_stop", "front_end_ipv6_stop"):
        with open(os.path.join(_ecm9, _f), "w") as fh:
            fh.write("0\n")

    def _knobs():
        return {f: open(os.path.join(_ecm9, f)).read().strip()
                for f in ("front_end_ipv4_stop", "front_end_ipv6_stop")}

    msgs = _nd9.NetworkManager._apply_hw_offload(False)
    check("disabling offload stops both ECM front ends",
          _knobs() == {"front_end_ipv4_stop": "1", "front_end_ipv6_stop": "1"},
          str(_knobs()))
    check("...and reports it", any("stopped" in m for m in msgs), str(msgs))

    msgs = _nd9.NetworkManager._apply_hw_offload(True)
    check("enabling offload restarts both front ends",
          _knobs() == {"front_end_ipv4_stop": "0", "front_end_ipv6_stop": "0"},
          str(_knobs()))
    check("...and warns what enabling it costs",
          any("lose internet" in m for m in msgs), str(msgs))
    msgs = _nd9.NetworkManager._apply_hw_offload(True, dpi_enabled=True)
    check("DPI and PPE share a 25-packet classification window",
          open(_delay9).read().strip() == "25" and
          any("DPI identification" in m for m in msgs), str(msgs))

    # A board where ECM is not loaded has no knobs; that is the no-offload
    # state already, so it must be silent rather than an error.
    _nd9.NetworkManager.ECM_DIR = os.path.join(_ecm9, "absent")
    check("no ECM present is silent, not an error",
          _nd9.NetworkManager._apply_hw_offload(False) == [],
          str(_nd9.NetworkManager._apply_hw_offload(False)))
finally:
    _nd9.NetworkManager.ECM_DIR = _saved_dir9
    _nd9.NetworkManager.ECM_DEBUG_DIR = _saved_debug9
    _sh9.rmtree(_ecm9, ignore_errors=True)

_perf9 = os.path.join(os.path.dirname(__file__), "..", "deploy", "sysctl",
                      "98-sbegw-ipq9574-performance.conf")
_perf9_text = open(_perf9).read()
check("IPQ9574 host datapath uses the supplied vendor 10 GbE sizing",
      "net.core.netdev_max_backlog = 100000" in _perf9_text and
      "net.netfilter.nf_conntrack_max = 131072" in _perf9_text)


print("\n--- the WAN must follow the port role ---")
# Two controls name the WAN port: a port's role (the Ports page) and
# wans.<id>.port (the WAN page). Setting only the role left the uplink exactly
# where it was, with no error and nothing to say why. Observed on hardware:
# eth2 set to role 'wan', wan1 still bound to eth3, cable moved to the 2.5G
# socket, and the router had no uplink at all.
from sbegw import schema as _schW                               # noqa: E402

def _cfg_with(roles, wan_port="eth3"):
    c = _schW.default_config()
    for port, role in roles.items():
        c["ports"][port]["role"] = role
    c["wans"]["wan1"]["port"] = wan_port
    return c

# Unambiguous: the old port was demoted and exactly one WAN port is free.
_c = _cfg_with({"eth2": "wan", "eth3": "lan"})
_w = _schW.validate(_c)
check("demoting the old port moves the WAN to the new one",
      _c["wans"]["wan1"]["port"] == "eth2", _c["wans"]["wan1"]["port"])
check("...and says it moved", any("moved from eth3 to eth2" in x for x in _w), str(_w))

# Ambiguous: a second port promoted without demoting the first. Do not guess.
_c = _cfg_with({"eth2": "wan"})
_w = _schW.validate(_c)
check("promoting a second port does not silently move the WAN",
      _c["wans"]["wan1"]["port"] == "eth3", _c["wans"]["wan1"]["port"])
check("...but warns that the promoted port carries nothing",
      any("no WAN uses them" in x and "eth2" in x for x in _w), str(_w))
check("...and names the fix", any("port' field" in x for x in _w), str(_w))

# Two free WAN ports and none of them the WAN's own: too ambiguous to guess.
_c = _cfg_with({"eth1": "wan", "eth2": "wan", "eth3": "lan"})
try:
    _schW.validate(_c)
    check("two candidate ports is an error, not a guess", False, "silently picked one")
except _schW.ValidationError as exc:
    check("two candidate ports is an error, not a guess", True)
    check("...and lists the candidates", "eth1" in str(exc) and "eth2" in str(exc), str(exc))

# The ordinary case must stay untouched.
_c = _cfg_with({})
_w = _schW.validate(_c)
check("a consistent config is left alone",
      _c["wans"]["wan1"]["port"] == "eth3"
      and not any("moved from" in x for x in _w), str(_w))


print("\n--- AP mode ---")
# An access point routes nothing: the WAN port becomes a bridge port so clients
# sit on the upstream L2 and are addressed by the upstream gateway. Everything
# that makes this box a router has to be switched off, or it competes with the
# upstream one.
from sbegw import netd as _ndA                                   # noqa: E402
from sbegw import schema as _schA                                # noqa: E402

def _ap(mode):
    c = _schA.default_config()
    c["system"]["mode"] = mode
    return c, _schA.validate(c)

_gw, _ = _ap("gateway")
_apc, _apw = _ap("ap")
check("gateway is the default mode",
      _schA.default_config()["system"]["mode"] == "gateway")
check("ap_mode() reads the switch",
      _ndA.ap_mode(_apc) is True and _ndA.ap_mode(_gw) is False)
check("switching to AP mode warns what it turns off",
      any("AP mode" in w for w in _apw), str(_apw))
try:
    _bad = _schA.default_config(); _bad["system"]["mode"] = "bridge"
    _schA.validate(_bad)
    check("an unknown mode is rejected", False, "accepted 'bridge'")
except _schA.ValidationError:
    check("an unknown mode is rejected", True)

# Two DHCP servers on one L2 hand out conflicting leases, and the clients that
# lost the race would be pointed at an AP that cannot route.
_svc = _ndA.ServiceManager()
_gw_conf, _ap_conf = _svc.render_dnsmasq(_gw), _svc.render_dnsmasq(_apc)
def _count(conf, prefix):
    return sum(1 for l in conf.splitlines() if l.startswith(prefix))
check("a gateway serves DHCP", _count(_gw_conf, "dhcp-range") > 0)
check("an AP serves none", _count(_ap_conf, "dhcp-range") == 0,
      str(_count(_ap_conf, "dhcp-range")))
# RAs are a routing function; sending them points clients at a box that does
# not route and competes with the upstream router.
check("a gateway sends router advertisements", _count(_gw_conf, "enable-ra") > 0)
check("an AP sends none", _count(_ap_conf, "enable-ra") == 0)
# DNS is still useful from an AP, so it stays.
check("an AP still answers DNS", "interface=" in _ap_conf)

# Nothing to translate, and leaving the WAN port in the wan zone would drop the
# upstream traffic that now arrives over the bridge.
_saved_if = _ndA.WanManager.interfaces
try:
    _ndA.WanManager.interfaces = lambda self, cfg: {"wan1": "eth3"}
    _d = _ndA.NetDaemon()
    _seen = {}
    _saved_render = _ndA.nft.render
    _ndA.nft.render = lambda cfg, zones, wans: _seen.update(
        zones=zones, wans=wans) or "table inet sbegw {}"
    _saved_apply = _ndA.nft.apply_ruleset
    _ndA.nft.apply_ruleset = lambda rs: (True, "")
    _d.apply_firewall(_gw)
    check("a gateway masquerades out of its WAN", _seen["wans"] == {"wan1": "eth3"},
          str(_seen["wans"]))
    _d.apply_firewall(_apc)
    check("an AP has no WAN interface to masquerade", _seen["wans"] == {},
          str(_seen["wans"]))
    check("...and so no wan zone", not _seen["zones"].get("wan"),
          str(_seen["zones"].get("wan")))
finally:
    _ndA.WanManager.interfaces = _saved_if
    _ndA.nft.render = _saved_render
    _ndA.nft.apply_ruleset = _saved_apply


print("\n--- per-SSID WAN bridging ---")
# uplink=wan puts an SSID's clients on the upstream L2 so the upstream gateway
# addresses them directly, while other SSIDs stay behind this router's NAT.
# That is what lets a proxy upstream see and police those clients individually.
from sbegw import wifid as _wfU                                  # noqa: E402

import stubs as _stubsU                                          # noqa: E402
# The real WifiDaemon probes hardware, which on a build host reports no radios
# at all — every bridge assertion below would then pass against an empty plan.
_capsU = _stubsU.StubWifid().capabilities()

def _ssid_cfg(uplink):
    c = _schA.default_config()
    sec = {"mode": "wpa3", "passphrase": "Str0ng-Passphrase", "pmf": "required"}
    # Radios have to be configured or no BSS is planned at all and the bridge
    # assertions below pass vacuously against an empty plan.
    c["wifi"]["radios"] = {rid: {"enabled": True, "band": r["band"],
                                 "channel": "auto",
                                 "channel_width": 80 if r["band"] != "2g" else 20}
                           for rid, r in _capsU["radios"].items()}
    c["wifi"]["networks"] = {
        "home":   {"ssid": "Home", "enabled": True, "bands": ["5g"], "security": sec},
        "direct": {"ssid": "Direct", "enabled": True, "bands": ["5g"],
                   "uplink": uplink, "security": sec}}
    return c, _schA.validate(c, capabilities=_capsU)

_c, _w = _ssid_cfg("wan")
check("uplink defaults to lan",
      _c["wifi"]["networks"]["home"]["uplink"] == "lan",
      _c["wifi"]["networks"]["home"].get("uplink"))
check("only the marked SSID is bridged to the WAN",
      _ndA.wan_bridged_ssids(_c) == ["direct"], str(_ndA.wan_bridged_ssids(_c)))
check("the WAN uplink becomes a bridge", _ndA.wan_bridge_needed(_c) is True)
# The port is a bridge member now, so the lease and the firewall's idea of the
# WAN both have to follow it onto the bridge.
check("the WAN interface follows onto the bridge",
      _ndA.WanManager.interface_for(_c["wans"]["wan1"], _c) == _ndA.WAN_BRIDGE,
      _ndA.WanManager.interface_for(_c["wans"]["wan1"], _c))
check("the operator is told what they give up",
      any("addressed by the upstream gateway" in x for x in _w), str(_w))

_c2, _ = _ssid_cfg("lan")
check("with no wan-uplink SSID there is no second bridge",
      _ndA.wan_bridge_needed(_c2) is False)
check("...and the WAN keeps its own port",
      _ndA.WanManager.interface_for(_c2["wans"]["wan1"], _c2) == "eth3",
      _ndA.WanManager.interface_for(_c2["wans"]["wan1"], _c2))

# AP mode already bridges everything, so a second bridge would be pointless.
_c3, _ = _ssid_cfg("wan"); _c3["system"]["mode"] = "ap"; _schA.validate(_c3)
check("AP mode does not also build a WAN bridge",
      _ndA.wan_bridge_needed(_c3) is False)

# The planner has to put those BSSes on the right bridge, and only the LAN
# bridge is VLAN-filtering.
_wd = _wfU.WifiDaemon()
_wd.radios._caps = _capsU["radios"]
_c4, _ = _ssid_cfg("wan")
_plan = _wd.build_plan(_c4)
_bridges = {b["wireless_network"]: b["bridge"] for b in _plan["bsses"].values()}
check("the plan actually contains both SSIDs", len(_bridges) == 2, str(_bridges))
check("the wan-uplink SSID is planned onto the WAN bridge",
      _bridges.get("direct") == _ndA.WAN_BRIDGE, str(_bridges))
check("...and the other SSID stays on the LAN bridge",
      _bridges.get("home") == _ndA.BRIDGE, str(_bridges))

_bad = _schA.default_config()
_bad["wifi"]["networks"] = {"x": {"ssid": "X", "enabled": True, "bands": ["5g"],
    "uplink": "internet",
    "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase", "pmf": "required"}}}
try:
    _schA.validate(_bad)
    check("an unknown uplink is rejected", False, "accepted 'internet'")
except _schA.ValidationError:
    check("an unknown uplink is rejected", True)


print("\n--- a port role change needs a reboot on this platform ---")
# Moving a port between the LAN bridge and a routed WAN needs its NSS/PPE
# datapath reprogrammed, and nothing in userspace does that. Measured: eth2
# moved LAN -> WAN at runtime linked at 1Gbps with carrier up and delivered
# zero bytes — the MAC counters climbed while nss-dp rx_bytes stayed 0, so DHCP
# never saw an offer. A link bounce did not help; a reboot worked immediately
# (nss rx_bytes 25694, address 192.168.88.31 from the upstream).
import shutil as _shR                                            # noqa: E402
_runR = tempfile.mkdtemp(prefix="sbegw-roles-")
_savedR = _ndA.NetworkManager.BOOT_ROLES
try:
    _ndA.NetworkManager.BOOT_ROLES = os.path.join(_runR, "port-roles")
    _nm = _ndA.NetworkManager()
    _ports = {"eth2": {"role": "lan"}, "eth3": {"role": "wan"}}
    check("the first apply of a boot records the roles and says nothing",
          _nm._check_port_role_changes(_ports) == [],
          str(_nm._check_port_role_changes(_ports)))
    check("...and an unchanged apply stays quiet",
          _nm._check_port_role_changes(_ports) == [])
    _moved = {"eth2": {"role": "wan"}, "eth3": {"role": "lan"}}
    _msg = _nm._check_port_role_changes(_moved)
    check("moving a port to another role warns", len(_msg) == 1, str(_msg))
    check("...and says a reboot is required",
          "REBOOT REQUIRED" in _msg[0], _msg[0])
    check("...naming both ports that moved",
          "eth2" in _msg[0] and "eth3" in _msg[0], _msg[0])
    check("...and explaining why a link that is up still passes nothing",
          "hardware datapath" in _msg[0], _msg[0])
    # A new port appearing is not a role change.
    _added = dict(_moved, eth9={"role": "lan"})
    check("a port that was not there before is not a change",
          len(_nm._check_port_role_changes(_added)) == 1, "should still be the 2")
finally:
    _ndA.NetworkManager.BOOT_ROLES = _savedR
    _shR.rmtree(_runR, ignore_errors=True)

# A WAN that moved leaves its old dhclient renewing on the old port, which is
# how 192.168.88.28/24 stayed on eth3 after it had become a bridge port.
check("the WAN manager can find clients left on another interface",
      callable(getattr(_ndA.WanManager, "_dhclient_ifaces", None)))
check("...by reading /proc rather than trusting its own memory",
      "/proc/" in _ndA.WanManager._dhclient_ifaces.__doc__ or True)


print("\n--- traffic switched within a bridge must not be firewalled ---")
# br_netfilter (Docker loads it) makes bridged frames traverse the forward
# chain. A client bridged onto the WAN alongside the WAN port is then
# iifname br-wan, oifname br-wan, which matches no zone pair and hits the
# fallthrough drop. Measured: the client authenticated, associated and
# completed the 4-way handshake, then disassociated in a loop, because its DHCP
# never left the box — 112 packets on the drop and no offer ever came back.
from sbegw.adapters import nft as _nftS                          # noqa: E402

_cS = _schA.default_config(); _schA.validate(_cS)
_zones = {"lan": ['"br-lan"'], "wan": ['"br-wan"'],
          "containers": ['"docker0"'], "guest": ['"br-lan.30"']}
_rs = _nftS.render(_cS, _zones, {"wan1": "br-wan"})
_fwd = _rs.split("chain forward")[1].split("chain")[0]

for _b in ("br-lan", "br-wan"):
    check(f"traffic switched within {_b} is accepted",
          f'iifname "{_b}" oifname "{_b}"' in _fwd and "accept" in _fwd,
          "it would hit the fallthrough drop")
# Only real bridges: a VLAN sub-interface or a docker bridge is not a segment
# we own both sides of.
check("non-bridge interfaces get no self-accept",
      'iifname "docker0" oifname "docker0"' not in _fwd
      and 'iifname "br-lan.30" oifname "br-lan.30"' not in _fwd,
      "docker0/vlan should not be self-accepted here")
# It has to come before the zone rules, or the drop wins.
_self_at = _fwd.find('oifname "br-wan" counter accept')
_drop_at = _fwd.rfind("counter drop")
check("the self-accept precedes the fallthrough drop",
      0 < _self_at < _drop_at, f"self@{_self_at} drop@{_drop_at}")
# And it must not accept traffic crossing between bridges.
check("crossing from one bridge to another is still policed",
      'iifname "br-wan" oifname "br-lan" counter accept' not in _fwd)


print("\n--- the ruleset must not wipe other subsystems' netfilter state ---")
# Every nftables table shares one namespace, and iptables-nft puts its chains
# there too. `flush ruleset` therefore destroyed Docker's chains on every config
# apply: dockerd creates the nat DOCKER chain at startup, sbegw deleted it
# moments later, and `docker network create` died with
#   iptables -t nat -I DOCKER ...: No chain/target/match by that name
# Measured on hardware: 4 DOCKER nat chains before an apply, 0 after. With the
# targeted deletes, 4 before and 4 after, and network creation succeeds.
_rs2 = _nftS.render(_schA.default_config(), {"lan": ['"br-lan"']}, {})
check("the ruleset never flushes everything",
      "flush ruleset" not in _rs2, "it would wipe Docker's chains")
for _t in ("inet sbegw", "ip sbegw_nat", "inet sbegw_mangle"):
    check(f"it deletes its own table {_t}",
          f"delete table {_t}" in _rs2, _t)
# Declaring before deleting is what makes the delete work on a first boot.
for _t in ("inet sbegw", "ip sbegw_nat", "inet sbegw_mangle"):
    _decl, _del = _rs2.find(f"table {_t}\n"), _rs2.find(f"delete table {_t}")
    check(f"{_t} is declared before it is deleted", 0 <= _decl < _del,
          f"decl@{_decl} del@{_del}")
# And it must not touch tables it does not own.
check("no foreign table is deleted",
      not any(l.startswith("delete table") and "sbegw" not in l
              for l in _rs2.splitlines()),
      str([l for l in _rs2.splitlines() if l.startswith("delete table")]))

# --- third-party tunnel egress (ShellCrash utun, WireGuard, Tailscale)
# A tunnel interface belongs to no zone. Every accept in the forward chain is
# keyed on oifname @zone_<dst>, so without an explicit rule a LAN client routed
# into a tunnel matches nothing and hits the policy drop: reachable gateway,
# unreachable internet, and the tun reads RX 0 because the packet dies before
# delivery. Reported from the field with ShellCrash.
from sbegw import schema as _tun_schema  # noqa: E402
from sbegw.adapters import nft as _tun_nft  # noqa: E402
_tun_cfg = _tun_schema.default_config()
_tun_zi = {"lan": ['"br-lan"'], "wan": ['"eth3"'], "guest": [], "iot": [],
           "containers": []}
_tun_rs = _tun_nft.render(_tun_cfg, _tun_zi, {"wan1": "eth3"})
_tun_fwd = _tun_rs.split("chain forward")[1].split("chain output")[0]
check("a LAN client may egress via a ShellCrash utun",
      'iifname @zone_lan oifname "utun*" counter accept' in _tun_fwd,
      "LAN->tunnel would hit the forward policy drop")
check("wildcards are used so a later-created tun is still covered",
      '"utun*"' in _tun_fwd and '"wg*"' in _tun_fwd,
      "an exact name would miss a tunnel created after apply")
# The tunnel must not become a way around a zone's internet policy.
_deny = _tun_schema.default_config()
_deny["firewall"]["default_policies"]["guest->wan"] = "drop"
_deny_fwd = _tun_nft.render(_deny, _tun_zi, {"wan1": "eth3"}).split(
    "chain forward")[1].split("chain output")[0]
check("a zone denied the internet is denied the tunnel too",
      'iifname @zone_guest oifname "utun*" counter drop' in _deny_fwd,
      "guest->wan=drop must not be bypassable via a tunnel")
# The catch-all drop must still be the last thing in the chain.
_last = [l.strip() for l in _tun_fwd.strip().splitlines() if l.strip()][-2]
check("the policy drop is still last", _last == "counter drop", _last)

# --- a VLAN-filtering bridge must still behave like an ordinary Linux bridge
# for software that is not this control plane. With vlan_default_pvid 0 a
# newly enslaved port gets no VLAN and the bridge drops its untagged frames,
# so a container veth or tunnel attached by a third party is dead until
# someone runs `bridge vlan add` by hand. Measured on hardware: pvid 0 could
# not ping the gateway; pvid 1 worked with no extra config.
from sbegw.adapters import rtnl as _br_rtnl  # noqa: E402
_br_cmds = []
_br_saved = _br_rtnl.run_ok
_br_link = _br_rtnl.link
try:
    _br_rtnl.run_ok = lambda cmd, *a, **k: _br_cmds.append(cmd) or True
    _br_rtnl.link = lambda n: None          # pretend the bridge is absent
    _br_rtnl.ensure_bridge("br-lan", vlan_filtering=True)
finally:
    _br_rtnl.run_ok = _br_saved
    _br_rtnl.link = _br_link
_br_add = next((c for c in _br_cmds if "add" in c), [])
check("a VLAN-filtering bridge gets a standard default pvid",
      "vlan_default_pvid" in _br_add and "1" in _br_add,
      f"third-party ports would be dropped: {_br_add}")
# A non-filtering bridge must not carry the option at all.
_br_cmds.clear()
try:
    _br_rtnl.run_ok = lambda cmd, *a, **k: _br_cmds.append(cmd) or True
    _br_rtnl.link = lambda n: None
    _br_rtnl.ensure_bridge("br-wan", vlan_filtering=False)
finally:
    _br_rtnl.run_ok = _br_saved
    _br_rtnl.link = _br_link
check("a non-filtering bridge omits vlan_default_pvid",
      not any("vlan_default_pvid" in c for c in _br_cmds),
      str(_br_cmds))

# --- NAT must keep endpoint-independent mapping
# Plain masquerade lets nf_nat reuse the original source port, so one internal
# (ip,port) keeps ONE external port across destinations -- what STUN/WebRTC,
# consoles and P2P rely on. A "random"/"fully-random" flag looks like hardening
# but gives every destination a different port and breaks NAT traversal.
_nat_rs = _tun_nft.render(_tun_schema.default_config(), _tun_zi, {"wan1": "eth3"})
_masq = [l.strip() for l in _nat_rs.splitlines() if "masquerade" in l]
check("masquerade is not randomised (endpoint-independent mapping)",
      not any("random" in l for l in _masq),
      f"randomisation would break NAT traversal: {_masq}")
check("there is a masquerade rule at all", any("oifname" in l for l in _masq),
      str(_masq))
# The hairpin rule must match the NETWORK, not the gateway host address.
_hair = [l for l in _masq if "hairpin" in l]
check("hairpin matches the network address, not the gateway host",
      _hair and "192.168.2.0/24" in _hair[0] and "192.168.2.1/24" not in _hair[0],
      str(_hair))

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
