#!/usr/bin/env python3
"""Channel analyzer and automatic channel selection tests.

Feeds the scorer synthetic scan/survey data so the decisions are checkable:
a congested channel must lose to a clean one, 2.4 GHz must stay on 1/6/11, DFS
carries a cost, and the anti-flapping rules must actually hold a switch back.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

STATE = tempfile.mkdtemp(prefix="sbegw-rf-")
os.environ["SBEGW_STATE"] = STATE

import stubs                                    # noqa: E402
from sbegw import rf, schema                    # noqa: E402

rf.STATE_DIR = STATE
rf.HISTORY_PATH = os.path.join(STATE, "channel-history.json")

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------- unit helpers

print("--- channel maths ---")
check("2.4 GHz channel 6 -> 2437 MHz", rf.channel_to_freq(6, "2g") == 2437)
check("5 GHz channel 36 -> 5180 MHz", rf.channel_to_freq(36, "5g") == 5180)
check("6 GHz channel 37 -> 6135 MHz", rf.channel_to_freq(37, "6g") == 6135)
check("5180 MHz -> channel 36", rf.freq_to_channel(5180) == 36)
check("6135 MHz -> channel 37", rf.freq_to_channel(6135) == 37)

check("80 MHz at ch 36 covers 36-48",
      rf.occupied_channels(36, 80, "5g") == [36, 40, 44, 48],
      str(rf.occupied_channels(36, 80, "5g")))
check("80 MHz at ch 44 resolves to the same block",
      rf.occupied_channels(44, 80, "5g") == [36, 40, 44, 48],
      str(rf.occupied_channels(44, 80, "5g")))
check("160 MHz covers 8 subchannels",
      len(rf.occupied_channels(36, 160, "5g")) == 8)
check("240 MHz occupies 12 subchannels",
      len(rf.occupied_channels(36, 240, "5g")) == 12,
      str(rf.occupied_channels(36, 240, "5g")))
check("320 MHz occupies 16 subchannels",
      len(rf.occupied_channels(1, 320, "6g")) == 16)
check("2.4 GHz 20 MHz splatters over neighbours",
      rf.occupied_channels(6, 20, "2g") == [4, 5, 6, 7, 8],
      str(rf.occupied_channels(6, 20, "2g")))

# ------------------------------------------------------------------- scoring

print("\n--- scoring ---")
wifid = stubs.StubWifid()
# Give the analyzer a plan so it knows which radios have BSSes.
cfg = schema.default_config()
cfg["wifi"]["radios"] = {
    rid: {"enabled": True, "band": r["band"], "channel": "auto",
          "channel_width": 80 if r["band"] == "5g" else 20}
    for rid, r in stubs.RADIOS.items()}
cfg["wifi"]["networks"]["main"] = {
    "ssid": "SBE-Net", "enabled": True, "hidden": False, "network": "default",
    "bands": ["2g", "5g", "6g"],
    "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase", "pmf": "required"},
    "client_isolation": False, "bss_transition": True, "neighbor_report": True,
    "fast_roaming": False}
schema.validate(cfg, capabilities=wifid.capabilities())

wifid._plan = {
    "links": {rid: {"radio": rid, "caps": r, "config": cfg["wifi"]["radios"][rid],
                    "bsses": [{"interface": f"wl{r['band']}0", "radio": rid,
                               "band": r["band"], "ssid": "SBE-Net",
                               "bssid": r["mac"], "mld": None}]}
              for rid, r in stubs.RADIOS.items()},
    "mlds": {},
    "bsses": {f"wl{r['band']}0": {"interface": f"wl{r['band']}0", "radio": rid,
                                  "band": r["band"], "ssid": "SBE-Net",
                                  "bssid": r["mac"], "mld": None}
              for rid, r in stubs.RADIOS.items()},
}

analyzer = rf.ChannelAnalyzer(wifid)

# Synthetic environment: 5 GHz channel 36 block is hammered, 149 is clean.
analyzer._scans["radio-5g"] = {"ts": 1.0, "neighbours": [
    {"bssid": "aa:00:00:00:00:01", "ssid": "Busy-A", "channel": 36, "width": 80,
     "rssi": -45, "band": "5g", "radio": "radio-5g"},
    {"bssid": "aa:00:00:00:00:02", "ssid": "Busy-B", "channel": 40, "width": 40,
     "rssi": -52, "band": "5g", "radio": "radio-5g"},
    {"bssid": "aa:00:00:00:00:03", "ssid": "Busy-C", "channel": 48, "width": 20,
     "rssi": -58, "band": "5g", "radio": "radio-5g"},
]}
analyzer._surveys["radio-5g"] = {"ts": 1.0, "entries": [
    {"frequency_mhz": 5180, "noise_dbm": -84, "utilisation_percent": 71.0,
     "in_use": True},
    {"frequency_mhz": 5745, "noise_dbm": -96, "utilisation_percent": 3.0},
]}

analysis = analyzer.analyse(cfg)
radios = {r["radio"]: r for r in analysis["radios"]}
five = radios["radio-5g"]

ch36 = next(c for c in five["channels"] if c["channel"] == 36)
ch149 = next(c for c in five["channels"] if c["channel"] == 149)
check("congested channel reports its neighbours",
      ch36["neighbour_count"] >= 2, f"ch36 count={ch36['neighbour_count']}")
check("clean channel reports none", ch149["neighbour_count"] == 0)
check("survey noise is surfaced", ch36["noise_dbm"] == -84, str(ch36["noise_dbm"]))
check("survey utilisation is surfaced", ch36["utilisation_percent"] == 71.0)
check("unmeasured channel reports null utilisation rather than a guess",
      next(c for c in five["channels"] if c["channel"] == 52)["utilisation_percent"] is None)

# Ask directly with channel 36 as the current one, so the comparison against
# "where we are now" is meaningful.
rec = analyzer.recommend("radio-5g", stubs.RADIOS["radio-5g"],
                         cfg["wifi"]["radios"]["radio-5g"],
                         five["channels"], 36, 80, dict(rf.DEFAULTS))
best = rec["best"]
check("scorer prefers a clean channel over the congested one",
      best and best["channel"] in (149, 132), f"picked {best and best['channel']}")
scores = {c["channel"]: c["score"] for c in rec["candidates"]}
check("every permitted 80 MHz block is scored", len(scores) >= 5, str(sorted(scores)))
check("channel 165 is not offered at 80 MHz (20 MHz-only channel)",
      165 not in scores, str(sorted(scores)))
check("congested channel scores worse than clean",
      scores.get(36, 100) < scores.get(149, 0),
      f"36={scores.get(36)} 149={scores.get(149)}")
check("DFS channel is penalised vs a non-DFS one of equal cleanliness",
      True if 100 not in scores or 149 not in scores
      else scores[100] < scores[149], f"100={scores.get(100)} 149={scores.get(149)}")

# 2.4 GHz must only ever propose non-overlapping channels.
analyzer._scans["radio-2g"] = {"ts": 1.0, "neighbours": [
    {"bssid": "bb:00:00:00:00:01", "ssid": "N1", "channel": 1, "width": 20,
     "rssi": -50, "band": "2g", "radio": "radio-2g"}]}
analysis = analyzer.analyse(cfg)
two = {r["radio"]: r for r in analysis["radios"]}["radio-2g"]
proposed = {c["channel"] for c in two["recommendation"]["candidates"]}
check("2.4 GHz only proposes 1/6/11", proposed <= {1, 6, 11}, str(sorted(proposed)))
check("2.4 GHz avoids the occupied channel 1",
      two["recommendation"]["best"]["channel"] != 1,
      f"picked {two['recommendation']['best']['channel']}")

# ------------------------------------------------------- anti-flap behaviour

print("\n--- anti-flapping ---")
gain = rec["best"]["score"] - rec["current"]["score"]
check("the gain is measured against the current channel, not zero",
      rec["current"] is not None and gain < 100.0, f"gain={gain:.1f}")

settings = dict(rf.DEFAULTS)
settings["min_improvement"] = gain + 5.0     # just above the achievable gain
rec_strict = analyzer.recommend(
    "radio-5g", stubs.RADIOS["radio-5g"], cfg["wifi"]["radios"]["radio-5g"],
    five["channels"], 36, 80, settings)
check("a small gain does not trigger a switch",
      rec_strict["should_switch"] is False,
      "; ".join(rec_strict["reasons"]))
check("the reason names the threshold",
      any("threshold" in r for r in rec_strict["reasons"]),
      "; ".join(rec_strict["reasons"]))

analyzer._last_switch["radio-5g"] = rf.now()
settings2 = dict(rf.DEFAULTS)
settings2["min_improvement"] = 0.0
rec_recent = analyzer.recommend(
    "radio-5g", stubs.RADIOS["radio-5g"], cfg["wifi"]["radios"]["radio-5g"],
    five["channels"], 36, 80, settings2)
check("a recent switch blocks another one",
      rec_recent["should_switch"] is False, "; ".join(rec_recent["reasons"]))
check("the reason mentions flapping",
      any("flapping" in r for r in rec_recent["reasons"]),
      "; ".join(rec_recent["reasons"]))

analyzer._last_switch["radio-5g"] = 0.0
rec_ok = analyzer.recommend(
    "radio-5g", stubs.RADIOS["radio-5g"], cfg["wifi"]["radios"]["radio-5g"],
    five["channels"], 36, 80, settings2)
check("with the interval elapsed and a real gain, it switches",
      rec_ok["should_switch"] is True, "; ".join(rec_ok["reasons"]))

score_of = lambda rec_, ch: next(
    c["score"] for c in rec_["candidates"] if c["channel"] == ch)
rec_on_149 = analyzer.recommend(
    "radio-5g", stubs.RADIOS["radio-5g"], cfg["wifi"]["radios"]["radio-5g"],
    five["channels"], 149, 80, settings2)
check("staying put is rewarded (hysteresis)",
      score_of(rec_ok, 36) > score_of(rec_on_149, 36),
      f"36 scores {score_of(rec_ok, 36)} when current, "
      f"{score_of(rec_on_149, 36)} when not")

# ------------------------------------------------------------ dry run + apply

print("\n--- optimise ---")
report = analyzer.optimise(cfg, radios=["radio-5g"], force=True, dry_run=True,
                           rescan=False)
entry = report["radios"][0]
check("dry run reports a target without switching",
      entry["switched"] is False and "dry run" in entry["detail"],
      entry["detail"])
check("dry run names the destination channel", entry["to_channel"] == 149,
      str(entry["to_channel"]))

committed = {}
analyzer.commit_channel = lambda rid, ch: committed.setdefault(rid, ch)
report = analyzer.optimise(cfg, radios=["radio-5g"], force=True, rescan=False)
entry = report["radios"][0]
check("apply falls back to a config commit when CSA is unavailable",
      committed.get("radio-5g") == 149, str(committed))
check("the fallback is reported honestly, not silently",
      "CSA unavailable" in entry["detail"], entry["detail"])
check("a successful switch is recorded in history",
      any(h["to_channel"] == 149 for h in analyzer.history("radio-5g")),
      str(analyzer.history("radio-5g")[:1]))

# ------------------------------------------------------------------ 240 MHz

print("\n--- 240 MHz ---")
caps240 = {rid: dict(r) for rid, r in stubs.RADIOS.items()}
caps240["radio-5g"]["eht240"] = True
caps240["radio-5g"]["widths"] = [20, 40, 80, 160, 240]

cfg240 = schema.default_config()
cfg240["wifi"]["radios"]["radio-5g"] = {
    "enabled": True, "band": "5g", "channel": "auto", "channel_width": 240}
try:
    schema.validate(cfg240, capabilities={"radios": caps240})
    check("240 MHz accepted on a capable 5 GHz radio", True)
except schema.ValidationError as exc:
    check("240 MHz accepted on a capable 5 GHz radio", False, str(exc))

cfg_bad = schema.default_config()
cfg_bad["wifi"]["radios"]["radio-6g"] = {
    "enabled": True, "band": "6g", "channel": "auto", "channel_width": 240}
try:
    schema.validate(cfg_bad, capabilities={"radios": caps240})
    check("240 MHz rejected on 6 GHz", False, "accepted")
except schema.ValidationError as exc:
    check("240 MHz rejected on 6 GHz", "5 GHz-only" in str(exc), str(exc))

# An otherwise identical 5 GHz radio whose driver does NOT report EHT240.
caps_no240 = {rid: dict(r) for rid, r in stubs.RADIOS.items()}
caps_no240["radio-5g"]["eht240"] = False
caps_no240["radio-5g"]["widths"] = [20, 40, 80, 160]

cfg_incap = schema.default_config()
cfg_incap["wifi"]["radios"]["radio-5g"] = {
    "enabled": True, "band": "5g", "channel": "auto", "channel_width": 240}
try:
    schema.validate(cfg_incap, capabilities={"radios": caps_no240})
    check("240 MHz rejected when the radio does not report EHT240", False, "accepted")
except schema.ValidationError as exc:
    check("240 MHz rejected when the radio does not report EHT240",
          "EHT240" in str(exc), str(exc))

from sbegw.adapters import hostapd as hostapd_adapter  # noqa: E402
conf = hostapd_adapter.render_link_config(
    {"id": "radio-5g", "band": "5g", "channel": 36, "channel_width": 240,
     "tx_power": "auto"},
    caps240["radio-5g"],
    [{"interface": "wl5g0", "ssid": "N", "bssid": "aa:bb:cc:dd:ee:10",
      "bridge": "br-lan", "mld": None,
      "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                   "pmf": "required"}}],
    country="US")
check("240 MHz renders as 320 MHz EHT operation",
      "eht_oper_chwidth=9" in conf, [l for l in conf.splitlines() if "chwidth" in l])
check("240 MHz keeps HE at 160 (no 320 value in that enum)",
      "he_oper_chwidth=2" in conf)
check("240 MHz emits a puncturing directive",
      "punct_acs_threshold=" in conf or "punct_bitmap=" in conf,
      [l for l in conf.splitlines() if "punct" in l])

shutil.rmtree(STATE, ignore_errors=True)

# ------------------------------------------- scanning before any SSID exists
print("\n--- scan with no AP BSS (first visit to the portal) ---")
# The analyzer used to skip any radio without an AP BSS, so on a factory-fresh
# device it returned nothing on every band — while that is precisely when the
# operator needs it, to choose a channel for their first SSID.
bare = stubs.StubWifid()
bare._plan = {
    "links": {rid: {"radio": rid, "caps": r, "config": {}, "bsses": []}
              for rid, r in stubs.RADIOS.items()},
    "mlds": {}, "bsses": {},
}
bare_analyzer = rf.ChannelAnalyzer(bare)

created, removed, scanned = [], [], []
real_add, real_del = rf.nl80211.add_interface, rf.nl80211.del_interface
real_scan, real_survey = rf.nl80211.scan_detail, rf.nl80211.survey
real_up = rf.rtnl.set_up
rf.nl80211.add_interface = lambda phy, name, itype="managed": created.append((phy, name, itype)) or True
rf.nl80211.del_interface = lambda name: removed.append(name) or True
rf.nl80211.survey = lambda iface: []
rf.rtnl.set_up = lambda name, up=True: True
# One neighbour per band, as a single-wiphy scan really returns.
FAKE_NEIGHBOURS = [
    {"bssid": "cc:00:00:00:00:01", "ssid": "N-2g", "frequency_mhz": 2437,
     "rssi": -60, "width": 20},
    {"bssid": "cc:00:00:00:00:02", "ssid": "N-5g", "frequency_mhz": 5180,
     "rssi": -60, "width": 80},
    {"bssid": "cc:00:00:00:00:03", "ssid": "N-6g", "frequency_mhz": 5955,
     "rssi": -60, "width": 160},
]
def fake_scan(iface, passive=True):
    scanned.append(iface)
    return list(FAKE_NEIGHBOURS), None
rf.nl80211.scan_detail = fake_scan
try:
    results = bare_analyzer.scan(cfg)
finally:
    rf.nl80211.add_interface, rf.nl80211.del_interface = real_add, real_del
    rf.nl80211.scan_detail, rf.nl80211.survey = real_scan, real_survey
    rf.rtnl.set_up = real_up

check("every radio is scanned without an AP BSS",
      len(results) == len(stubs.RADIOS), str(sorted(results)))
check("a temporary interface is created per radio",
      len(created) == len(stubs.RADIOS), str(created))
check("the temporary interface is a station, not an AP",
      all(c[2] == "managed" for c in created))
check("the interface name fits the kernel's 15-char limit",
      all(len(c[1]) <= 15 for c in created), str([c[1] for c in created]))
check("the scan runs on the temporary interface",
      sorted(scanned) == sorted(c[1] for c in created), str(scanned))
check("the temporary interface is always removed",
      all(c[1] in removed for c in created), str(removed))
check("each radio records only its own band's neighbours",
      all(r["neighbours"] == 1 for r in results.values()), str(results))
check("neighbour channel is derived from its frequency",
      bare_analyzer.neighbours("radio-5g")[0]["channel"] == 36)
check("the 2.4 GHz radio gets the 2.4 GHz neighbour",
      bare_analyzer.neighbours("radio-2g")[0]["ssid"] == "N-2g")
check("the 6 GHz radio gets the 6 GHz neighbour",
      bare_analyzer.neighbours("radio-6g")[0]["ssid"] == "N-6g")
check("no radio is given another band's neighbour",
      all(n["band"] == b for b in ("2g", "5g", "6g")
          for n in bare_analyzer.neighbours(f"radio-{b}")))

# All three radios behind ONE phy: the real hardware layout. A single scan must
# serve every radio, not run three times, and each must still see only its band.
single = stubs.StubWifid()
single._plan = {
    "links": {rid: {"radio": rid,
                    "caps": {**r, "phy": "phy0"},
                    "config": {}, "bsses": []}
              for rid, r in stubs.RADIOS.items()},
    "mlds": {}, "bsses": {},
}
single_analyzer = rf.ChannelAnalyzer(single)
created.clear(); scanned.clear(); removed.clear()
rf.nl80211.add_interface = lambda phy, name, itype="managed": created.append((phy, name, itype)) or True
rf.nl80211.del_interface = lambda name: removed.append(name) or True
rf.nl80211.scan_detail = fake_scan
rf.nl80211.survey = lambda iface: []
rf.rtnl.set_up = lambda name, up=True: True
try:
    single_results = single_analyzer.scan(cfg)
finally:
    rf.nl80211.add_interface, rf.nl80211.del_interface = real_add, real_del
    rf.nl80211.scan_detail, rf.nl80211.survey = real_scan, real_survey
    rf.rtnl.set_up = real_up
check("one shared phy is scanned exactly once, not once per radio",
      len(scanned) == 1, str(scanned))
check("one temporary interface is created for the shared phy",
      len(created) == 1, str(created))
check("all three radios still get results from that single scan",
      len(single_results) == 3, str(single_results))
check("each radio still sees only its own band",
      all(single_analyzer.neighbours(f"radio-{b}")[0]["band"] == b
          for b in ("2g", "5g", "6g")))

# A failure to create the interface must not raise or leak.
rf.nl80211.add_interface = lambda phy, name, itype="managed": False
rf.nl80211.del_interface = lambda name: True
try:
    empty = bare_analyzer.scan(cfg)
    check("an uncreatable scan interface yields no results, not a crash",
          empty == {}, str(empty))
except Exception as exc:
    check("an uncreatable scan interface yields no results, not a crash",
          False, f"raised {exc}")
finally:
    rf.nl80211.add_interface, rf.nl80211.del_interface = real_add, real_del


# --------------------------------------------- SSID on a band with no radio
print("\n--- SSID on a band with no radio ---")
import copy as _copy  # noqa: E402
_full = stubs.StubWifid().capabilities()
_one = _copy.deepcopy(_full)
_one["radios"] = {k: v for k, v in _full["radios"].items() if v["band"] == "5g"}
_cfg = schema.default_config()
_cfg["wifi"]["radios"] = {rid: {"enabled": True, "band": r["band"],
                                "channel": "auto", "channel_width": 80}
                          for rid, r in _one["radios"].items()}
def _with_bands(bands):
    c = _copy.deepcopy(_cfg)
    c["wifi"]["networks"] = {"main": {
        "ssid": "SBE-Net", "enabled": True, "hidden": False, "network": "default",
        "bands": bands,
        "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                     "pmf": "required"},
        "client_isolation": False, "bss_transition": True,
        "neighbor_report": True, "fast_roaming": False}}
    return c

w = schema.validate(_with_bands(["2g", "5g", "6g"]), capabilities=_one)
check("a band with no radio is accepted, not rejected", True)
check("...but it is warned about", any("no radio present" in x for x in w), str(w))
check("the warning names the missing bands",
      any("2g" in x and "6g" in x for x in w), str(w))
check("the warning names what was detected",
      any("radios detected: 5g" in x for x in w), str(w))
w = schema.validate(_with_bands(["5g"]), capabilities=_one)
check("no warning when every band has a radio", not w, str(w))
w = schema.validate(_with_bands(["2g", "5g", "6g"]), capabilities=_full)
check("no missing-radio warning on a full three-radio device",
      not any("no radio present" in x for x in w), str(w))
# A multi-band SSID with no MLD is three separate BSSes, not MLO. Saying so is
# the point: the band list alone made it look like a three-link association.
check("a multi-band SSID with no MLD is flagged as not MLO",
      any("not MLO" in x for x in w), str(w))
_mld_cfg = _copy.deepcopy(_with_bands(["2g", "5g", "6g"]))
_mld_cfg["wifi"]["mlds"] = {"mld0": {
    "name": "Main", "wireless_network": "main", "enabled": True,
    "links": ["radio-2g", "radio-5g", "radio-6g"], "link_steering": "auto"}}
w = schema.validate(_mld_cfg, capabilities=_full)
check("...and not flagged once an MLD binds it",
      not any("not MLO" in x for x in w), str(w))


print("\n--- a channel must be able to hold its width ---")
_capsB = stubs.StubWifid().capabilities()
_cB = schema.default_config()
_cB["wifi"]["radios"] = {rid: {"enabled": True, "band": r["band"],
                               "channel": "auto", "channel_width": 20}
                         for rid, r in _capsB["radios"].items()}

def _validates(rid, channel, width):
    _cB["wifi"]["radios"][rid]["channel"] = channel
    _cB["wifi"]["radios"][rid]["channel_width"] = width
    try:
        schema.validate(_cB, capabilities=_capsB)
        return True, ""
    except schema.ValidationError as exc:
        return False, str(exc)
    finally:
        _cB["wifi"]["radios"][rid]["channel"] = "auto"
        _cB["wifi"]["radios"][rid]["channel_width"] = 20

# The whole bonded block has to fit inside the permitted channel list, not just
# the primary. On the real device 6 GHz channel 197 is permitted, so the old
# primary-only check accepted it at 320 MHz — but that block is centred on
# channel 223 (7065 MHz) and runs off the top of the band. hostapd answered
# "Invalid bonded channel freq 6935, bw 320" -> "Interface initialization
# failed", and because the radio was an MLD link it tore down 2.4 GHz and
# 5 GHz with it: one bad 6 GHz channel took every band off the air.
# This stub's 6 GHz list stops at 97, so the same boundary is exercised there.
_ok, _msg = _validates("radio-6g", 69, 320)
check("a 6 GHz channel whose 320 MHz block runs past the band edge is rejected",
      not _ok, _msg or "accepted")
check("...and the message names the channels that are usable",
      "usable at 320 mhz" in _msg.lower(), _msg)
check("...and names the missing channel(s)",
      "would need channel" in _msg.lower(), _msg)
check("the lowest 6 GHz channel is fine at 320 MHz",
      _validates("radio-6g", 1, 320)[0], _validates("radio-6g", 1, 320)[1])
check("6 GHz channel 97 is rejected at 160 MHz (block runs past the edge)",
      not _validates("radio-6g", 97, 160)[0], _validates("radio-6g", 97, 160)[1])
check("6 GHz channel 65 is fine at 160 MHz",
      _validates("radio-6g", 65, 160)[0], _validates("radio-6g", 65, 160)[1])
check("the same channel is still accepted at a width that fits",
      _validates("radio-6g", 97, 20)[0], _validates("radio-6g", 97, 20)[1])
# 5 GHz channel 165 is 20 MHz-only: bonded_channels returns nothing for it, so
# it must not be offered at 80 MHz even though the primary is permitted.
check("5 GHz channel 165 is rejected at 80 MHz",
      not _validates("radio-5g", 165, 80)[0], _validates("radio-5g", 165, 80)[1])
check("5 GHz channel 165 is fine at 20 MHz",
      _validates("radio-5g", 165, 20)[0], _validates("radio-5g", 165, 20)[1])
check("5 GHz channel 36 is fine at 160 MHz",
      _validates("radio-5g", 36, 160)[0], _validates("radio-5g", 36, 160)[1])
check("2.4 GHz channel 11 is rejected at 40 MHz (needs channel 15)",
      not _validates("radio-2g", 11, 40)[0], _validates("radio-2g", 11, 40)[1])
check("2.4 GHz channel 1 is fine at 40 MHz",
      _validates("radio-2g", 1, 40)[0], _validates("radio-2g", 1, 40)[1])

print("\n--- hostapd STATUS width decoding ---")
from sbegw import wifid as _WR                                  # noqa: E402

# hostapd STATUS width decoding. Only EHT has a 320 MHz enum; 240 MHz shares it
# and is told apart by the puncturing bitmap. Enum 0 covers 20 AND 40 MHz.
_wfs = _WR._width_from_status
check("eht enum 1 is 80 MHz", _wfs({"eht_oper_chwidth": "1"}) == 80)
check("eht enum 2 is 160 MHz", _wfs({"eht_oper_chwidth": "2"}) == 160)
check("eht enum 9 is 320 MHz", _wfs({"eht_oper_chwidth": "9"}) == 320)
check("eht enum 9 with an 80 MHz puncture is 240 MHz",
      _wfs({"eht_oper_chwidth": "9", "punct_bitmap": "0xf000"}) == 240,
      str(_wfs({"eht_oper_chwidth": "9", "punct_bitmap": "0xf000"})))
check("enum 0 with no secondary channel is 20 MHz",
      _wfs({"eht_oper_chwidth": "0"}) == 20)
check("enum 0 with a secondary channel is 40 MHz",
      _wfs({"eht_oper_chwidth": "0", "secondary_channel": "-1"}) == 40)
check("an empty status yields no width", _wfs({}) is None)

print("\n--- 6 GHz width is carried by the operating class ---")
from sbegw.adapters import hostapd as _H6                       # noqa: E402

# On 6 GHz the operating class *is* the bandwidth: hostapd calls
# op_class_to_ch_width(conf->op_class) and ignores eht_oper_chwidth
# (ap_config.c, hw_features.c "In the 6 GHz band, eht_oper_chwidth is ignored").
# A hardcoded op_class=131 therefore pinned every 6 GHz radio to 20 MHz however
# wide the request was. Measured per width on hardware after the fix:
#   20->131 chw0, 40->132, 80->133 chw1, 160->134 chw2, 320->137 chw9
check("6 GHz operating classes cover 20/40/80/160/320",
      _H6.SIX_GHZ_OP_CLASS == {20: 131, 40: 132, 80: 133, 160: 134,
                               240: 137, 320: 137},
      str(_H6.SIX_GHZ_OP_CLASS))
check("160 MHz on 6 GHz uses operating class 134",
      _H6.SIX_GHZ_OP_CLASS[160] == 134)
check("240 MHz on 6 GHz reuses the 320 class (punctured, no class of its own)",
      _H6.SIX_GHZ_OP_CLASS[240] == _H6.SIX_GHZ_OP_CLASS[320] == 137)

_caps6 = {"band": "6g", "he": True, "eht": True, "ht": False, "vht": False,
          "channels": [{"channel": c, "disabled": False}
                       for c in range(1, 234, 4)]}
def _lines6(width, channel="auto"):
    return _H6._band_lines({"band": "6g", "channel_width": width,
                            "channel": channel}, _caps6)

for _w, _oc in ((20, 131), (40, 132), (80, 133), (160, 134), (320, 137)):
    check(f"{_w} MHz on 6 GHz emits op_class={_oc}",
          f"op_class={_oc}" in _lines6(_w), str(_lines6(_w)[:6]))

# secondary_channel must NOT be emitted on 6 GHz. It is not a config key in
# this hostapd at all (config_file.c has no parser for it) — it is assigned
# internally by hostapd_set_6ghz_sec_chan() for any 6 GHz op_class above
# 20 MHz. Emitting it produced "unknown configuration item 'secondary_channel'"
# and took every radio down; check_hostapd_keys.py is the general guard.
for _w in (20, 40, 80, 160, 320):
    check(f"{_w} MHz on 6 GHz emits no secondary_channel key",
          not any(l.startswith("secondary_channel=") for l in _lines6(_w)),
          str(_lines6(_w)))

print("\n--- BSSID uniqueness on a shared wiphy ---")
from sbegw.wifid import InterfacePlanner as _P  # noqa: E402
_MAC = "f4:52:46:f7:3e:f7"
_slot0 = [_P.bssid(_MAC, 0, radio_ordinal=o) for o in range(3)]
check("three radios on one MAC get three distinct slot-0 BSSIDs",
      len(set(_slot0)) == 3, str(_slot0))
_all = [_P.bssid(_MAC, s, radio_ordinal=o)
        for o in range(3) for s in range(_P.MAX_SLOTS)]
check("no BSSID collision across 3 radios x 16 slots",
      len(set(_all)) == len(_all), f"{len(set(_all))}/{len(_all)}")
# The wiphy's own MAC must never be handed out as a BSSID: the driver's default
# netdev (wlP1p1s0) already owns it, and slot 0 taking the same address put two
# netdevs on the box with one MAC, one of them bridged into br-lan.
check("the wiphy's own MAC is never used as a BSSID",
      _MAC not in set(_all), _P.bssid(_MAC, 0))
check("every derived BSSID is locally administered",
      all(int(a.split(":")[0], 16) & 0x02 for a in _all), str(_all[:3]))
check("the MLD address does not collide with any link BSSID",
      _P.mld_mac(_MAC, 0) not in set(_all))


print("\n--- wiphy enumeration ---")
_real_glob = rf.nl80211.glob.glob
rf.nl80211.glob.glob = lambda pat: [
    "/sys/class/ieee80211/phy00", "/sys/class/ieee80211/phy-scan-00"]
try:
    check("wiphy names are read from sysfs, not assumed to be phyN",
          "phy00" in rf.nl80211.all_phys(), str(rf.nl80211.all_phys()))
    check("the off-channel scan radio is not published as a radio",
          rf.nl80211.phys() == ["phy00"], str(rf.nl80211.phys()))
    check("all_phys still reports it for diagnostics",
          "phy-scan-00" in rf.nl80211.all_phys())
finally:
    rf.nl80211.glob.glob = _real_glob


print("\n--- band capability parsing (as the device reports it) ---")
# Modelled on this board's real `iw phy phy00 info`: 6 GHz advertises HE/EHT but
# no HT at all, and 2.4 GHz must never claim VHT.
_DEV_INFO = "\n".join([
    "Wiphy phy00",
    "\tBand 1:",
    "\t\tCapabilities: 0x19ef",
    "\t\t\tHT20/HT40",
    "\t\tVHT Capabilities (0x339b79b2):",
    "\t\tHE Iftypes: AP",
    "\t\tEHT Iftypes: AP",
    "\t\tFrequencies:",
    "\t\t\t* 2412 MHz [1] (30.0 dBm)",
    "\t\t\t* 2467 MHz [12] (disabled)",
    "\tBand 2:",
    "\t\t\tHT20/HT40",
    "\t\tVHT Capabilities (0x339b79b2):",
    "\t\tHE Iftypes: AP",
    "\t\tEHT Iftypes: AP",
    "\t\t160 MHz",
    "\t\tFrequencies:",
    "\t\t\t* 5180 MHz [36] (30.0 dBm)",
    "\t\t\t* 5260 MHz [52] (24.0 dBm) (radar detection)",
    "\tBand 4:",
    "\t\tHE Iftypes: AP",
    "\t\tEHT Iftypes: AP",
    "\t\t160 MHz",
    "\t\t320 MHz",
    "\t\tFrequencies:",
    "\t\t\t* 5955 MHz [1] (30.0 dBm)",
    "\t\t\t* 6135 MHz [37] (30.0 dBm)",
    "\tvalid interface combinations:",
    "\t\t * #{ AP } <= 16, #{ managed } <= 1, total <= 16, #channels <= 1",
])
_rp, _rm = rf.nl80211._phy_info_text, rf.nl80211._driver_mlo_capable
_re240 = rf.nl80211.driver_eht240_capable
rf.nl80211._phy_info_text = lambda phy: _DEV_INFO
rf.nl80211._driver_mlo_capable = lambda: True
rf.nl80211.driver_eht240_capable = lambda: True
try:
    _bands = {c["band"]: c for c in rf.nl80211.phy_band_capabilities("phy00")}
finally:
    rf.nl80211._phy_info_text, rf.nl80211._driver_mlo_capable = _rp, _rm
    rf.nl80211.driver_eht240_capable = _re240

check("all three bands are parsed from one wiphy",
      sorted(_bands) == ["2g", "5g", "6g"], str(sorted(_bands)))
check("6 GHz has no HT, as the driver reports",
      _bands["6g"]["ht"] is False)
check("6 GHz still offers 40 MHz via HE/EHT",
      40 in _bands["6g"]["widths"], str(_bands["6g"]["widths"]))
check("6 GHz offers 320 MHz", 320 in _bands["6g"]["widths"])
check("2.4 GHz never claims VHT", _bands["2g"]["vht"] is False)
check("2.4 GHz never claims 802.11ac",
      "802.11ac" not in _bands["2g"]["standards"],
      str(_bands["2g"]["standards"]))
check("2.4 GHz is capped at 40 MHz",
      _bands["2g"]["widths"] == [20, 40], str(_bands["2g"]["widths"]))
check("240 MHz is offered on 5 GHz only",
      240 in _bands["5g"]["widths"] and 240 not in _bands["6g"]["widths"]
      and 240 not in _bands["2g"]["widths"])
check("DFS is detected behind the transmit power",
      _bands["5g"]["dfs"] is True and
      [d["channel"] for d in _bands["5g"]["channel_details"] if d["dfs"]] == [52])
check("disabled channels are excluded from the usable list",
      12 not in _bands["2g"]["channels"], str(_bands["2g"]["channels"]))
check("the AP limit comes from #{ AP }, not the fallback",
      _bands["5g"]["max_ap_bss"] == 16, str(_bands["5g"]["max_ap_bss"]))


print("\n--- analyzer on a factory-fresh device (EMPTY plan) ---")
# The device as shipped: radios discovered, no SSID, so build_plan produces no
# links at all. The analyzer used to iterate plan["links"] and therefore scanned
# nothing, reporting no neighbours on every band.
fresh = stubs.StubWifid()
fresh._plan = {"links": {}, "mlds": {}, "bsses": {}}      # nothing configured
fresh_analyzer = rf.ChannelAnalyzer(fresh)
created.clear(); scanned.clear(); removed.clear()
rf.nl80211.add_interface = lambda phy, name, itype="managed": created.append((phy, name, itype)) or True
rf.nl80211.del_interface = lambda name: removed.append(name) or True
rf.nl80211.scan_detail = fake_scan
rf.nl80211.survey = lambda iface: []
rf.rtnl.set_up = lambda name, up=True: True
try:
    fresh_results = fresh_analyzer.scan(cfg)
finally:
    rf.nl80211.add_interface, rf.nl80211.del_interface = real_add, real_del
    rf.nl80211.scan_detail, rf.nl80211.survey = real_scan, real_survey
    rf.rtnl.set_up = real_up

check("an empty plan still scans every discovered radio",
      len(fresh_results) == len(stubs.RADIOS), str(fresh_results))
check("a scan actually ran", len(scanned) >= 1, str(scanned))
check("neighbours are found with no SSID configured",
      all(r["neighbours"] == 1 for r in fresh_results.values()),
      str(fresh_results))
check("each band still gets only its own neighbour",
      all(fresh_analyzer.neighbours(f"radio-{b}")[0]["band"] == b
          for b in ("2g", "5g", "6g")))
check("temporary interfaces are cleaned up",
      all(c[1] in removed for c in created), str(removed))


print("\n--- AP netdev creation (hostapd will not do it) ---")
from sbegw import wifid as _W  # noqa: E402
_calls = {"add": [], "del": [], "up": [], "mac": []}
_existing = {"wl2g0"}
_saved = (_W.rtnl.links, _W.rtnl.link, _W.rtnl.set_up, _W.rtnl.set_mac,
          _W.nl80211.add_interface, _W.nl80211.del_interface)
_W.rtnl.links = lambda: [{"ifname": n} for n in sorted(_existing | {"wl6g9", "eth0"})]
_W.rtnl.link = lambda n: ({"ifname": n, "address": "00:11:22:33:44:55"}
                          if n in _existing or n == "wl6g9" else None)
_W.rtnl.set_up = lambda n, up=True: _calls["up"].append((n, up)) or True
_W.rtnl.set_mac = lambda n, m: _calls["mac"].append((n, m)) or True
def _add(phy, name, itype="managed"):
    _calls["add"].append((phy, name, itype))
    if itype == "__ap":
        _existing.add(name)
        return True
    return False
_W.nl80211.add_interface = _add
_W.nl80211.del_interface = lambda n: _calls["del"].append(n) or True
try:
    _d = _W.WifiDaemon()
    _d.radios.phy_for = lambda rid: "phy00"
    _plan = {"bsses": {
        "wl2g0": {"radio": "radio-2g", "bssid": "f4:52:46:f7:3e:f7"},
        "wl5g0": {"radio": "radio-5g", "bssid": "f6:52:46:f7:3e:07"},
        "wl6g0": {"radio": "radio-6g", "bssid": "f6:52:46:f7:3e:17"},
    }}
    _msgs = _d._ensure_ap_interfaces(_plan)
    _made = {c[1] for c in _calls["add"]}
    check("missing AP netdevs are created", _made == {"wl5g0", "wl6g0"}, str(_made))
    check("an existing one is not recreated", "wl2g0" not in _made)
    check("they are created as __ap on the radio's phy",
          all(c[0] == "phy00" and c[2] == "__ap" for c in _calls["add"]))
    check("a stale AP netdev from an old config is removed",
          _calls["del"] == ["wl6g9"], str(_calls["del"]))
    check("non-AP interfaces are never touched", "eth0" not in _calls["del"])
    check("each gets its planned BSSID",
          sorted(_calls["mac"]) == sorted([
              ("wl2g0", "f4:52:46:f7:3e:f7"), ("wl5g0", "f6:52:46:f7:3e:07"),
              ("wl6g0", "f6:52:46:f7:3e:17")]), str(_calls["mac"]))
    check("the link is downed before its address is changed",
          all(up is False for _, up in _calls["up"]), str(_calls["up"]))

    # iw builds without the internal __ap name must fall back to "ap".
    _calls["add"].clear()
    _existing.clear()
    _W.nl80211.add_interface = lambda phy, name, itype="managed": (
        _calls["add"].append((phy, name, itype)) or itype == "ap")
    _d2 = _W.WifiDaemon()
    _d2.radios.phy_for = lambda rid: "phy00"
    _d2._ensure_ap_interfaces({"bsses": {"wl5g0": {"radio": "radio-5g",
                                                   "bssid": "02:00:00:00:00:01"}}})
    check("falls back to type 'ap' when '__ap' is unsupported",
          [c[2] for c in _calls["add"]] == ["__ap", "ap"],
          str(_calls["add"]))
finally:
    (_W.rtnl.links, _W.rtnl.link, _W.rtnl.set_up, _W.rtnl.set_mac,
     _W.nl80211.add_interface, _W.nl80211.del_interface) = _saved


print("\n--- hostapd runtime directories ---")
# The QSDK hostapd binds /var/run/hostapd/hostapd_if_eloop, a compiled-in path.
# Without that directory it aborted with "Failed to bind server socket: No such
# file or directory" before parsing any configuration.
import shutil as _shutil, tempfile as _tf  # noqa: E402
from sbegw.adapters import hostapd as _H  # noqa: E402
_orig = (_H.CONF_DIR, _H.CTRL_DIR, _H.HOSTAPD_IF_DIR)
_box = _tf.mkdtemp()
try:
    _H.CONF_DIR = os.path.join(_box, "conf")
    _H.CTRL_DIR = os.path.join(_box, "ctrl")
    _H.HOSTAPD_IF_DIR = os.path.join(_box, "varrun")
    _H.write_configs({"radio-5g": "interface=wl5g0\nssid=X\n"})
    check("the config directory is created", os.path.isdir(_H.CONF_DIR))
    check("the control-interface directory is created", os.path.isdir(_H.CTRL_DIR))
    check("hostapd's hardcoded async-socket directory is created",
          os.path.isdir(_H.HOSTAPD_IF_DIR))
    _H.HOSTAPD_IF_DIR = "/proc/cannot/create/here"
    try:
        _H.write_configs({"radio-5g": "interface=wl5g0\nssid=X\n"})
        check("an uncreatable socket directory warns instead of raising", True)
    except Exception as exc:
        check("an uncreatable socket directory warns instead of raising",
              False, f"raised {exc!r}")
finally:
    _H.CONF_DIR, _H.CTRL_DIR, _H.HOSTAPD_IF_DIR = _orig
    _shutil.rmtree(_box, ignore_errors=True)

check("the hardcoded path matches the binary's compiled-in one",
      _H.HOSTAPD_IF_DIR == "/var/run/hostapd", _H.HOSTAPD_IF_DIR)


print("\n--- hostapd supervision (foreground, captured, backed off) ---")
import stat as _stat, tempfile as _tf2, time as _time  # noqa: E402
from sbegw import wifid as _WD  # noqa: E402
from sbegw.adapters import hostapd as _HD  # noqa: E402

_box = _tf2.mkdtemp()
def _fake(name, body):
    path = os.path.join(_box, name)
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | _stat.S_IEXEC)
    return path
_fail = _fake("hostapd-fail", "#!/bin/sh\n"
              "echo 'wl5g0: interface state UNINITIALIZED->COUNTRY_UPDATE'\n"
              "echo 'Could not set channel for kernel driver'\n"
              "echo 'wl5g0: AP-DISABLED'\nexit 1\n")
_up = _fake("hostapd-ok", "#!/bin/sh\necho 'wl5g0: AP-ENABLED'\nsleep 300\n")

_saved_wd = (_WD.RUN_DIR, _WD.HOSTAPD_PID, _WD.HOSTAPD_LOG)
_saved_hd = (_HD.binary, _HD.interface_state)
try:
    _WD.RUN_DIR = _box
    _WD.HOSTAPD_PID = os.path.join(_box, "hostapd.pid")
    _WD.HOSTAPD_LOG = os.path.join(_box, "hostapd.log")
    _conf = os.path.join(_box, "radio-5g.conf")
    open(_conf, "w").write("interface=wl5g0\nssid=X\n")

    _d = _WD.WifiDaemon()
    _d._plan = {"bsses": {"wl5g0": {}}, "links": {}, "mlds": {}}

    # A hostapd that dies must report ITS OWN reason, not a generic message.
    _HD.binary = lambda: _fail
    _HD.interface_state = lambda i: None
    _ok, _msgs = _d._start_hostapd([_conf])
    _joined = " ".join(_msgs)
    check("a failing hostapd is reported as a failure", _ok is False)
    check("its exit status is reported", "status 1" in _joined, _joined)
    check("its own log lines are surfaced",
          "Could not set channel for kernel driver" in _joined, _joined)

    # A hostapd that reaches ENABLED succeeds, and returns as soon as it does.
    _HD.binary = lambda: _up
    _HD.interface_state = lambda i: "ENABLED"
    _t0 = _time.monotonic()
    _ok, _msgs = _d._start_hostapd([_conf])
    _elapsed = _time.monotonic() - _t0
    check("a healthy hostapd starts successfully", _ok is True, str(_msgs))
    check("it reports which interfaces are beaconing",
          any("AP enabled on wl5g0" in m for m in _msgs), str(_msgs))
    check("it returns as soon as the AP is up, not after the full timeout",
          _elapsed < 5.0, f"{_elapsed:.1f}s")
    check("the pid file is written", os.path.exists(_WD.HOSTAPD_PID))
    check("the process is tracked as running", _d._hostapd_running() is True)

    # DFS is a wait, not a fault.
    _d._stop_hostapd()
    _HD.interface_state = lambda i: "DFS"
    _ok, _msgs = _d._start_hostapd([_conf])
    check("a BSS in DFS/CAC is not treated as a failure", _ok is True)
    check("...but is reported as not yet beaconing",
          any("not yet beaconing" in m and "DFS" in m for m in _msgs), str(_msgs))
    _d._stop_hostapd()
    check("stopping leaves nothing running", _d._hostapd_running() is False)

    # Backoff: repeated failures must not relaunch every tick.
    _d2 = _WD.WifiDaemon()
    _d2._plan = {"bsses": {}, "links": {}, "mlds": {}}
    _attempts = []
    _d2.radios.discover = lambda force=False: {}
    _d2._hostapd_running = lambda: False
    _d2.__class__.__call__ = lambda self, o, n: (_attempts.append(1),
                                                 rf.ApplyResult(False, []))[1] \
        if hasattr(rf, "ApplyResult") else _attempts.append(1)
    _cfg2 = {"wifi": {"networks": {"main": {}}}}
    for _ in range(5):
        _d2.poll_health(_cfg2)
    check("repeated failures do not restart hostapd on every tick",
          len(_attempts) == 1, f"{len(_attempts)} attempts in 5 ticks")
    check("the backoff delay grows", _d2._hostapd_retry_after > 0)
finally:
    _WD.RUN_DIR, _WD.HOSTAPD_PID, _WD.HOSTAPD_LOG = _saved_wd
    _HD.binary, _HD.interface_state = _saved_hd
    import shutil as _sh2
    _sh2.rmtree(_box, ignore_errors=True)


print("\n--- MLO derived from the SSID's own flag ---")
# The UI has no separate MLO object any more: ticking MLO on a wireless network
# must produce one multi-link device over exactly the bands it is configured
# for, so the link list can never drift out of step with the band list.
import tempfile as _tf3  # noqa: E402
os.environ.setdefault("SBEGW_STATE", _tf3.mkdtemp())
from sbegw.wifid import WifiDaemon as _WFD  # noqa: E402

_caps_all = stubs.StubWifid().capabilities()
_d3 = _WFD()
_d3.radios._caps = _caps_all["radios"]
_c3 = schema.default_config()
_c3["wifi"]["radios"] = {rid: {"enabled": True, "band": r["band"],
                               "channel": "auto",
                               "channel_width": 20 if r["band"] == "2g" else 80}
                         for rid, r in _caps_all["radios"].items()}
_base3 = {"ssid": "SBE-Net", "network": "default", "enabled": True,
          "security": {"mode": "wpa3", "passphrase": "Str0ng-Passphrase",
                       "pmf": "required"}}

_c3["wifi"]["networks"] = {"main": {**_base3, "bands": ["2g", "5g", "6g"],
                                    "mlo": True}}
schema.validate(_c3, capabilities=_caps_all)
_p3 = _d3.build_plan(_c3)
check("an MLO SSID yields exactly one MLD",
      len(_p3["mlds"]) == 1, str(list(_p3["mlds"])))
_mld3 = list(_p3["mlds"].values())[0]
check("the MLD is marked as derived, not declared", _mld3["derived"] is True)
check("its links are exactly the SSID's bands",
      _mld3["radios"] == ["radio-2g", "radio-5g", "radio-6g"],
      str(_mld3["radios"]))
check("no MLD was written into the stored config",
      _c3["wifi"]["mlds"] == {}, str(_c3["wifi"]["mlds"]))
check("every BSS carries an mld link id",
      sorted((b.get("mld") or {}).get("link_id") for b in _p3["bsses"].values())
      == [0, 1, 2],
      str([(i, (b.get("mld") or {}).get("link_id")) for i, b in _p3["bsses"].items()]))

# --- The MLD's links must share one netdev.
#
# hostapd groups links into an AP MLD by comparing the *interface name*
# (hostapd.c hostapd_bss_setup_multi_link: os_strcmp(conf->iface, mld->name)).
# Give each link its own name and each becomes a separate single-link MLD; the
# second then tries to create its own netdev and fails with ENFILE, or, if the
# netdev is absent, fails driver init outright. Both were observed on hardware.
_netdevs3 = {b["netdev"] for b in _p3["bsses"].values() if b.get("mld")}
check("all links of an MLD share one netdev", len(_netdevs3) == 1,
      str({i: b.get("netdev") for i, b in _p3["bsses"].items()}))
check("the shared netdev is named after the lowest-band link",
      _netdevs3 == {"wl2g0"}, str(_netdevs3))
check("every MLD link still keeps its own BSS interface identity",
      len({b["interface"] for b in _p3["bsses"].values()}) == 3,
      str(sorted(b["interface"] for b in _p3["bsses"].values())))

# One netdev per MLD, carrying the MLD address and a mask spanning its radios.
_calls4 = {"add": [], "mac": [], "mask": []}
_saved4 = (_W.rtnl.links, _W.rtnl.link, _W.rtnl.set_up, _W.rtnl.set_mac,
           _W.nl80211.add_interface, _W.nl80211.del_interface,
           _W.nl80211.set_vif_radio_mask)
_W.rtnl.links = lambda: []
_W.rtnl.link = lambda n: None
_W.rtnl.set_up = lambda n, up=True: True
_W.rtnl.set_mac = lambda n, m: _calls4["mac"].append((n, m)) or True
_W.nl80211.add_interface = lambda phy, name, itype="managed": (
    _calls4["add"].append((phy, name, itype)) or itype == "__ap")
_W.nl80211.del_interface = lambda n: True
_W.nl80211.set_vif_radio_mask = lambda n, m: (
    _calls4["mask"].append((n, m)) or (True, "ok"))
try:
    _d4 = _W.WifiDaemon()
    _d4.radios.phy_for = lambda rid: "phy00"
    _d4._radio_index = lambda rid: {"radio-2g": 0, "radio-5g": 1,
                                    "radio-6g": 2}.get(rid)
    _d4._ensure_ap_interfaces(_p3)
    check("only one netdev is created for the whole MLD",
          [c[1] for c in _calls4["add"]] == ["wl2g0"], str(_calls4["add"]))
    _mldmac = list(_p3["mlds"].values())[0]["mld_mac"]
    check("the MLD netdev takes the MLD address, not a link BSSID",
          _calls4["mac"] == [("wl2g0", _mldmac)], str(_calls4["mac"]))
    # QSDK's ucode accumulates the same union in update_radio_mask()
    # ("radio_mask |= old_mask" for an MLO BSS); we have no ucode VM, so the
    # union is set in one call.
    check("its radio mask spans every radio the MLD uses",
          _calls4["mask"] == [("wl2g0", 0b111)], str(_calls4["mask"]))
finally:
    (_W.rtnl.links, _W.rtnl.link, _W.rtnl.set_up, _W.rtnl.set_mac,
     _W.nl80211.add_interface, _W.nl80211.del_interface,
     _W.nl80211.set_vif_radio_mask) = _saved4

# Dropping a band must drop the link with it, automatically.
_c3["wifi"]["networks"]["main"]["bands"] = ["5g", "6g"]
schema.validate(_c3, capabilities=_caps_all)
_p3 = _d3.build_plan(_c3)
check("removing a band removes its link",
      list(_p3["mlds"].values())[0]["radios"] == ["radio-5g", "radio-6g"],
      str(list(_p3["mlds"].values())[0]["radios"]))

# Turning MLO off must leave no MLD at all.
_c3["wifi"]["networks"]["main"]["mlo"] = False
schema.validate(_c3, capabilities=_caps_all)
_p3 = _d3.build_plan(_c3)
check("turning MLO off removes the MLD", _p3["mlds"] == {}, str(_p3["mlds"]))
check("the BSSes remain, just unlinked",
      len(_p3["bsses"]) == 2
      and all(b.get("mld") is None for b in _p3["bsses"].values()),
      str([(i, b.get("mld")) for i, b in _p3["bsses"].items()]))

# An explicitly declared MLD still wins, for configs written before the change.
_c3["wifi"]["networks"]["main"]["mlo"] = True
_c3["wifi"]["mlds"] = {"legacy": {"name": "Legacy", "wireless_network": "main",
                                   "links": ["radio-5g", "radio-6g"],
                                   "enabled": True, "link_steering": "auto"}}
schema.validate(_c3, capabilities=_caps_all)
_p3 = _d3.build_plan(_c3)
check("an explicit MLD takes precedence over derivation",
      list(_p3["mlds"]) == ["legacy"], str(list(_p3["mlds"])))
check("...and is not marked derived",
      _p3["mlds"]["legacy"]["derived"] is False)

print("\n--- an MLD's radios must not report themselves down ---")
# A 3-link MLD: all links share netdev wl2g0, so wl5g0/wl6g0 do not exist as
# netdevs. Radio state must come from each link's own hostapd control socket,
# or every band but the anchor reports "down" while it is actually on the air.
_c5 = schema.default_config()
_d5 = _WFD()
_d5.radios._caps = _caps_all["radios"]
_c5["wifi"]["radios"] = {rid: {"enabled": True, "channel": "auto",
                               "channel_width": 160 if r["band"] != "2g" else 20}
                         for rid, r in _caps_all["radios"].items()}
_c5["wifi"]["networks"] = {"main": {"ssid": "test", "network": "default",
                                    "enabled": True, "bands": ["2g", "5g", "6g"],
                                    "mlo": True,
                                    "security": {"mode": "wpa3",
                                                 "passphrase": "Str0ng-Passphrase",
                                                 "pmf": "required"}}}
schema.validate(_c5, capabilities=_caps_all)
_d5._plan = _d5.build_plan(_c5)
check("a 3-band MLO SSID plans one netdev for three links",
      len({b["netdev"] for b in _d5._plan["bsses"].values()}) == 1,
      str({i: b.get("netdev") for i, b in _d5._plan["bsses"].items()}))

# Only the shared netdev exists; the per-link control sockets carry the state.
_LINK_STATUS = {
    "wl2g0":       {"state": "ENABLED", "freq": "2437", "channel": "6",
                    "eht_oper_chwidth": "0"},
    "wl2g0_link0": {"state": "ENABLED", "freq": "2437", "channel": "6",
                    "eht_oper_chwidth": "0"},
    "wl2g0_link1": {"state": "ENABLED", "freq": "5180", "channel": "36",
                    "eht_oper_chwidth": "2"},
    "wl2g0_link2": {"state": "ENABLED", "freq": "6135", "channel": "37",
                    "eht_oper_chwidth": "2"},
}
_savedR = (_WR.hostapd.status, _WR.nl80211.interfaces, _WR.nl80211.survey,
           _WR.hostapd.CTRL_DIR, _WR.os.listdir)
try:
    _WR.hostapd.status = lambda name: dict(_LINK_STATUS.get(name, {}))
    _WR.nl80211.interfaces = lambda: [{"name": "wl2g0", "channel": 6,
                                       "width": 20, "frequency_mhz": 2437}]
    _WR.nl80211.survey = lambda iface: [
        {"frequency_mhz": 2437, "noise_dbm": -94, "in_use": True},
        {"frequency_mhz": 5180, "noise_dbm": -102},
        {"frequency_mhz": 6135, "noise_dbm": -108}]
    _WR.os.listdir = lambda path: list(_LINK_STATUS)
    _states = {r["id"]: r for r in _d5.radio_states(_c5)}
    check("every radio of the MLD reports up, not just the anchor",
          all(_states[r]["state"] == "up" for r in _states),
          str({r: _states[r]["state"] for r in _states}))
    check("each radio reports its own link's channel",
          [_states[r]["runtime"]["channel"] for r in
           ("radio-2g", "radio-5g", "radio-6g")] == [6, 36, 37],
          str({r: _states[r]["runtime"]["channel"] for r in _states}))
    check("each radio reports its own link's width",
          [_states[r]["runtime"]["channel_width"] for r in
           ("radio-2g", "radio-5g", "radio-6g")] == [20, 160, 160],
          str({r: _states[r]["runtime"]["channel_width"] for r in _states}))
    # The survey entry must be matched by frequency: "in_use" alone would give
    # all three bands the 2.4 GHz noise figure.
    check("noise is taken from the link's own frequency",
          [_states[r]["runtime"]["noise_dbm"] for r in
           ("radio-2g", "radio-5g", "radio-6g")] == [-94, -102, -108],
          str({r: _states[r]["runtime"]["noise_dbm"] for r in _states}))
    # A link mid-CAC is pending, not down — a 60s DFS wait is not a failure.
    _LINK_STATUS["wl2g0_link1"]["state"] = "DFS"
    _d5._ctrl_map_at = 0.0
    _states = {r["id"]: r for r in _d5.radio_states(_c5)}
    check("a link waiting on DFS reports pending, not down",
          _states["radio-5g"]["state"] == "pending",
          _states["radio-5g"]["state"])
    _LINK_STATUS["wl2g0_link1"]["state"] = "ENABLED"
finally:
    (_WR.hostapd.status, _WR.nl80211.interfaces, _WR.nl80211.survey,
     _WR.hostapd.CTRL_DIR, _WR.os.listdir) = _savedR


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
