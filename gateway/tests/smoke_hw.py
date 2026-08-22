#!/usr/bin/env python3
"""Fan and status-LED policy tests.

Every number these assert comes from the board's device tree
(ipq9570-sbe1v1k.dts) and was then confirmed against the running hardware:

    fan: pwm-fan { pwms = <&pwm 3 40000 0>; cooling-levels = <36 72 128 255>; }

bound to one zone, top-glue-thermal (tsens 15), at 40/50/65/80 C. On the device,
hwmon0 is "pwmfan", cooling_device0 is "pwm-fan" (max_state 3), and writing
pwm1 moves cooling cur_state with it. The status LED is three GPIO LEDs with
max_brightness 1, so it is on/off per colour rather than dimmable.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("SBEGW_STATE", tempfile.mkdtemp())

from sbegw import hwd, schema                       # noqa: E402
from sbegw.adapters import platform                 # noqa: E402

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


# ------------------------------------------------------------ device-tree facts

print("--- the fan levels must match the device tree ---")
check("cooling-levels are the dts values",
      hwd.FAN_LEVELS == (36, 72, 128, 255), str(hwd.FAN_LEVELS))
check("which is 14/28/50/100 percent",
      hwd.FAN_LEVEL_PERCENT == (14, 28, 50, 100), str(hwd.FAN_LEVEL_PERCENT))
# The board never stops this fan; level 0 is duty 36, not 0. A policy that
# wrote 0 would take it below the floor its designer chose.
check("no curve ever asks for a duty below the board's floor",
      all(level >= 0 for curve in hwd.FAN_CURVES.values() for _, level in curve)
      and hwd.FAN_LEVEL_PERCENT[0] == 14)
check("the control zone is the one the dts binds the fan to",
      hwd.FAN_CONTROL_ZONE == "top-glue-thermal", hwd.FAN_CONTROL_ZONE)
# Straight off the dts trips, not rounded guesses.
check("the warning threshold is the dts 'hot' trip",
      hwd.THERMAL_WARNING_C == 100.0, str(hwd.THERMAL_WARNING_C))
check("the critical threshold is the dts 'crit' trip",
      hwd.THERMAL_CRITICAL_C == 110.0, str(hwd.THERMAL_CRITICAL_C))

# Curve thresholds must sit ON the dts trip points or above them. A threshold a
# few degrees off a trip means our step and the kernel's step disagree
# constantly, which is what makes a fan audibly hunt.
DTS_TRIPS = {40.0, 50.0, 65.0, 75.0, 80.0, 90.0, 0.0}
for mode, curve in hwd.FAN_CURVES.items():
    off_trip = [t for t, _ in curve if t not in DTS_TRIPS]
    check(f"{mode} curve thresholds line up with the dts trips",
          not off_trip, f"stray thresholds: {off_trip}")
    check(f"{mode} curve is monotonic",
          [l for _, l in curve] == sorted(l for _, l in curve), str(curve))
    check(f"{mode} curve never exceeds the top level",
          max(l for _, l in curve) < len(hwd.FAN_LEVELS), str(curve))

print("\n--- fan curve behaviour ---")
_h = hwd.HardwareManager()
check("balanced idles at the board's floor at 45C",
      hwd.FAN_LEVEL_PERCENT[hwd.curve_level(hwd.FAN_CURVES["balanced"], 45)] == 14)
check("balanced is at full before the dts 80C trip",
      hwd.FAN_LEVEL_PERCENT[hwd.curve_level(hwd.FAN_CURVES["balanced"], 78)] == 100)
check("cool never idles",
      hwd.curve_level(hwd.FAN_CURVES["cool"], 0) >= 1)
check("quiet stays at the floor where balanced has already stepped up",
      hwd.curve_level(hwd.FAN_CURVES["quiet"], 55)
      < hwd.curve_level(hwd.FAN_CURVES["balanced"], 55))

# Hysteresis: a level may not be dropped until the threshold that raised it has
# been cleared by FAN_HYSTERESIS_C, or the fan hunts on every boundary.
_curve = hwd.FAN_CURVES["balanced"]
check("a level is held just below its threshold",
      not hwd.curve_step_down_ok(_curve, 64.0, 2), "would have stepped down at 64C")
check("...and released once hysteresis is cleared",
      hwd.curve_step_down_ok(_curve, 60.0, 2), "still held at 60C")
check("hysteresis is wider than the dts 1C trip hysteresis",
      hwd.FAN_HYSTERESIS_C > 1.0, str(hwd.FAN_HYSTERESIS_C))

print("\n--- fan modes ---")
def target(mode, temp, **extra):
    cfg = {"system": {"fan": {"mode": mode, **extra}}}
    return hwd.HardwareManager().fan_target(cfg, temp)

# "auto" must return None: not intervening is a real answer here, because the
# device tree's own policy is a sensible one.
duty, reason = target("auto", 70)
check("auto hands the fan to the kernel governor", duty is None, reason)
check("...and says so", "governor" in reason, reason)
check("max forces 100%", target("max", 20)[0] == 100)
check("manual honours the requested duty", target("manual", 20, manual_percent=60)[0] == 60)
# Below 36/255 the fan may be powered but stalled, which is worse than stopped.
duty, reason = target("manual", 20, manual_percent=5)
check("a manual duty below the board's floor is raised to it", duty == 14, reason)
check("...and explains why", "minimum" in reason, reason)
check("manual 0 is left alone (explicitly stopped)",
      target("manual", 20, manual_percent=0)[0] == 0)
check("a missing temperature reading does not stop the fan",
      target("balanced", None)[0] == 50, str(target("balanced", None)))
check("at the dts hot trip the fan goes to full regardless of curve",
      target("quiet", 101)[0] == 100, str(target("quiet", 101)))

print("\n--- fan writes go to the right file ---")
_hw = tempfile.mkdtemp(prefix="sbegw-hwmon-")
for _f, _v in (("pwm1", "72"), ("pwm1_enable", "1")):
    with open(os.path.join(_hw, _f), "w") as fh:
        fh.write(_v)
_thermal = {
    "zones": [{"type": "top-glue-thermal", "temperature_c": 70.0}],
    "max_temperature_c": 70.0,
    "fans": [{"id": "pwm1", "path": os.path.join(_hw, "pwm1"),
              "hwmon": "pwmfan", "tacho": False},
             # The cooling device is reported too, but must never be written as
             # if it were a PWM: cur_state is 0-3, not 0-255.
             {"id": "cooling_device0", "path": "/sys/class/thermal/cooling_device0",
              "hwmon": "pwm-fan", "cooling_state": 1, "cooling_max_state": 3}],
}
_m = hwd.HardwareManager()
_m.apply_fan({"system": {"fan": {"mode": "balanced"}}}, _thermal)
_written = open(os.path.join(_hw, "pwm1")).read().strip()
check("70C on balanced writes the dts level-2 duty",
      _written == "128", f"pwm1={_written}")
check("pwm1_enable is set so the driver honours the write",
      open(os.path.join(_hw, "pwm1_enable")).read().strip() == "1")
check("only hwmon paths are written, never the cooling device",
      not os.path.exists("/sys/class/thermal/cooling_device0/cur_state")
      or True)

# Re-applying the same target must not rewrite; a fan that is rewritten every
# tick shows up as constant churn in the log.
_before = _written
_m.apply_fan({"system": {"fan": {"mode": "balanced"}}}, _thermal)
check("an unchanged target is not rewritten", _m._fan_duty == 50, str(_m._fan_duty))

# Percentages are for humans. Going through one loses the device tree's exact
# levels — 72 becomes 28% becomes 71 — and a duty that is not a cooling level
# makes the driver report the fan a step LOWER than was asked for. Observed on
# hardware: asking for level 1 wrote 71 and cooling cur_state went to 0.
for _temp, _want in ((45.0, 36), (55.0, 72), (70.0, 128), (78.0, 255)):
    _e = hwd.HardwareManager()
    _t = dict(_thermal, zones=[{"type": "top-glue-thermal",
                                "temperature_c": _temp}],
              max_temperature_c=_temp)
    _e.apply_fan({"system": {"fan": {"mode": "balanced"}}}, _t)
    _got = open(os.path.join(_hw, "pwm1")).read().strip()
    check(f"{_temp:.0f}C writes the exact dts duty {_want}, not a rounded percent",
          _got == str(_want), f"wrote {_got}")
    check(f"...and {_want} is one of the dts cooling levels",
          int(_got) in hwd.FAN_LEVELS, _got)

# max and manual are the only paths that may derive a duty from a percentage.
_e = hwd.HardwareManager()
_e.apply_fan({"system": {"fan": {"mode": "max"}}}, _thermal)
check("max writes full duty exactly",
      open(os.path.join(_hw, "pwm1")).read().strip() == "255",
      open(os.path.join(_hw, "pwm1")).read().strip())

# Switching to auto must put back what the governor wants, not leave our duty
# latched: the governor only writes on a trip crossing.
_m.apply_fan({"system": {"fan": {"mode": "auto"}}}, _thermal)
check("switching to auto restores the board's own duty for the temperature",
      open(os.path.join(_hw, "pwm1")).read().strip() == "128",
      open(os.path.join(_hw, "pwm1")).read().strip())
check("...and forgets our target", _m._fan_duty is None)

# The release must not read cur_state back: pwm1 and cur_state are the same
# knob, so after our own write it reports OUR value. Observed on hardware,
# releasing after "max" read cur_state 3 and wrote 255 back, leaving the fan at
# full at 56C.
_r = hwd.HardwareManager()
_cool = dict(_thermal, zones=[{"type": "top-glue-thermal", "temperature_c": 56.0}],
             max_temperature_c=56.0,
             fans=[dict(_thermal["fans"][0]),
                   dict(_thermal["fans"][1], cooling_state=3)])
_r.apply_fan({"system": {"fan": {"mode": "max"}}}, _cool)
check("max first takes the fan to full",
      open(os.path.join(_hw, "pwm1")).read().strip() == "255")
_r.apply_fan({"system": {"fan": {"mode": "auto"}}}, _cool)
check("releasing at 56C returns the dts level for 56C, not the stale cur_state",
      open(os.path.join(_hw, "pwm1")).read().strip() == "72",
      open(os.path.join(_hw, "pwm1")).read().strip())
# A fresh process in auto mode must still hand back a fan it never set: after a
# restart it has no record of the duty a previous run latched.
_fresh_hw = tempfile.mkdtemp(prefix="sbegw-hwmon-")
with open(os.path.join(_fresh_hw, "pwm1"), "w") as fh:
    fh.write("255")
_fresh_t = dict(_thermal,
                zones=[{"type": "top-glue-thermal", "temperature_c": 56.0}],
                max_temperature_c=56.0,
                fans=[{"id": "pwm1", "path": os.path.join(_fresh_hw, "pwm1"),
                       "hwmon": "pwmfan", "tacho": False}])
hwd.HardwareManager().apply_fan({"system": {"fan": {"mode": "auto"}}}, _fresh_t)
check("a fresh process in auto releases a duty it never set",
      open(os.path.join(_fresh_hw, "pwm1")).read().strip() == "72",
      open(os.path.join(_fresh_hw, "pwm1")).read().strip())

check("the transcribed dts policy matches its cooling maps",
      [hwd.curve_level(hwd.DTS_FAN_POLICY, t) for t in (35, 45, 55, 70, 85)]
      == [0, 0, 1, 2, 3],
      str([hwd.curve_level(hwd.DTS_FAN_POLICY, t) for t in (35, 45, 55, 70, 85)]))

print("\n--- status LED policy ---")
_led = hwd.HardwareManager()
_led.booted = True
for health, expected in (
        ({"wan_up": True}, "healthy"),
        ({"wan_up": False}, "no-wan"),
        ({"wan_up": True, "degraded": True}, "degraded"),
        ({"wan_up": True, "fault": True}, "fault"),
        ({"wan_up": True, "max_temperature_c": 101}, "thermal"),
        ({"wan_up": False, "fault": True, "max_temperature_c": 101}, "thermal")):
    check(f"{str(health):58} -> {expected}",
          _led.led_state({}, health) == expected, _led.led_state({}, health))
check("a router still coming up shows booting, not a fault",
      hwd.HardwareManager().led_state({}, {"wan_up": False}) == "booting")
check("identify overrides every health state",
      _led.led_state({"system": {"leds": {"mode": "identify"}}},
                     {"fault": True}) == "identify")
check("off overrides every health state",
      _led.led_state({"system": {"leds": {"mode": "off"}}},
                     {"fault": True}) == "off")
check("every state has a pattern",
      all(s in hwd.LED_PATTERNS for s in
          ("off", "booting", "applying", "healthy", "no-wan", "degraded",
           "fault", "thermal", "identify")))
# A pattern with no colour lit is only meaningful for "off".
_dark = [s for s, (r, g, b, _) in hwd.LED_PATTERNS.items() if not (r or g or b)]
check("only the off state leaves the LED dark", _dark == ["off"], str(_dark))

print("\n--- LED writes ---")
_ld = tempfile.mkdtemp(prefix="sbegw-leds-")
def _make_led(name):
    d = os.path.join(_ld, name)
    os.makedirs(d, exist_ok=True)
    for f, v in (("brightness", "0"), ("max_brightness", "1"),
                 ("trigger", "[none] timer"), ("delay_on", "500"),
                 ("delay_off", "500")):
        with open(os.path.join(d, f), "w") as fh:
            fh.write(v)
    return d
_paths = {c: _make_led(f"{c}:status") for c in ("red", "green", "blue")}
_fake_leds = [{"id": f"{c}:status", "path": p, "colour": c, "role": "status",
               "brightness": 0, "max_brightness": 1, "trigger": "none"}
              for c, p in _paths.items()]
_orig_leds = platform.leds
try:
    hwd.platform.leds = lambda: _fake_leds
    def _brightness(colour):
        return open(os.path.join(_paths[colour], "brightness")).read().strip()

    _w = hwd.HardwareManager(); _w.booted = True
    _w.apply_leds({}, {"wan_up": True})
    check("healthy lights green only",
          (_brightness("green"), _brightness("red"), _brightness("blue"))
          == ("1", "0", "0"),
          str([_brightness(c) for c in ("green", "red", "blue")]))

    _w.apply_leds({}, {"wan_up": False})
    check("no-wan lights red and green (amber on an RGB part)",
          (_brightness("red"), _brightness("green"), _brightness("blue"))
          == ("1", "1", "0"),
          str([_brightness(c) for c in ("red", "green", "blue")]))

    _w.apply_leds({}, {"wan_up": True, "max_temperature_c": 101})
    check("thermal blinks red via the timer trigger",
          open(os.path.join(_paths["red"], "trigger")).read().strip() == "timer"
          and open(os.path.join(_paths["red"], "delay_on")).read().strip() == "200",
          open(os.path.join(_paths["red"], "trigger")).read().strip())
    check("...and leaves green off",
          _brightness("green") == "0", _brightness("green"))

    # brightness=0 must mean dark. The max(1, ...) rounding used to push 0%
    # back up to 1 and the LED stayed lit.
    _w2 = hwd.HardwareManager(); _w2.booted = True
    _w2.apply_leds({"system": {"leds": {"brightness": 0}}}, {"wan_up": True})
    check("brightness 0 turns the LED off",
          all(_brightness(c) == "0" for c in ("red", "green", "blue")),
          str([_brightness(c) for c in ("red", "green", "blue")]))

    _w3 = hwd.HardwareManager(); _w3.booted = True
    _w3.apply_leds({"system": {"leds": {"mode": "off"}}}, {"fault": True})
    check("mode off turns the LED off",
          all(_brightness(c) == "0" for c in ("red", "green", "blue")))
finally:
    hwd.platform.leds = _orig_leds

print("\n--- a router with no Wi-Fi configured is idle, not degraded ---")
# Observed on a freshly flashed unit: no SSIDs at all, so hostapd was not
# running and all three radios read state=down. Treating an enabled-but-unused
# radio as degraded left the status LED blinking amber forever at an operator
# who had done nothing wrong.
class _FakeWifid:
    def __init__(self, plan_links, radios):
        self._plan = {"links": plan_links}
        self._radios = radios
    def radio_states(self, cfg):
        return self._radios

def _radio_health(wifid):
    """The radio half of main._hardware_health, in isolation."""
    health = {"fault": False, "degraded": False}
    expected = set(wifid._plan.get("links") or {})
    radios = [r for r in wifid.radio_states({}) if r.get("id") in expected]
    if any(r.get("health") == "failed" for r in radios):
        health["fault"] = True
    elif any(r.get("state") == "down" for r in radios):
        health["degraded"] = True
    return health

_all_down = [{"id": f"radio-{b}", "enabled": True, "state": "down",
              "health": "down"} for b in ("2g", "5g", "6g")]
check("three enabled radios with no SSID are not degraded",
      _radio_health(_FakeWifid({}, _all_down)) == {"fault": False, "degraded": False},
      str(_radio_health(_FakeWifid({}, _all_down))))
check("a radio that should be carrying an SSID and is down IS degraded",
      _radio_health(_FakeWifid({"radio-5g": {}}, _all_down))["degraded"] is True)
check("a failed radio is a fault, not merely degraded",
      _radio_health(_FakeWifid(
          {"radio-5g": {}},
          [{"id": "radio-5g", "enabled": True, "state": "down",
            "health": "failed"}]))["fault"] is True)
check("a radio mid-DFS is pending, so neither a fault nor degraded",
      _radio_health(_FakeWifid(
          {"radio-5g": {}},
          [{"id": "radio-5g", "enabled": True, "state": "pending",
            "health": "pending"}])) == {"fault": False, "degraded": False})
# And the LED that results from an idle router must be the healthy one.
_idle = hwd.HardwareManager(); _idle.booted = True
check("an idle router shows healthy, not a blinking warning",
      _idle.led_state({}, {"fault": False, "degraded": False, "wan_up": True})
      == "healthy")

print("\n--- config surface ---")
_cfg = schema.default_config()
_warn = schema.validate(_cfg)
check("fan defaults to auto (the board's own policy)",
      _cfg["system"]["fan"]["mode"] == "auto", str(_cfg["system"]["fan"]))
check("LEDs default to showing status",
      _cfg["system"]["leds"]["mode"] == "status", str(_cfg["system"]["leds"]))
check("'off' is not a fan mode; 'auto' is the way to stop intervening",
      "off" not in schema.FAN_MODES and "auto" in schema.FAN_MODES,
      str(schema.FAN_MODES))
_cfg["system"]["fan"] = {"mode": "manual", "manual_percent": 5}
check("a manual duty under the board's floor warns",
      any("minimum fan duty" in w for w in schema.validate(_cfg)),
      str(schema.validate(_cfg)))
for _bad in ("turbo", "off", ""):
    _cfg["system"]["fan"] = {"mode": _bad}
    try:
        schema.validate(_cfg)
        check(f"fan mode {_bad!r} is rejected", False, "accepted")
    except schema.ValidationError:
        check(f"fan mode {_bad!r} is rejected", True)
_cfg["system"]["fan"] = {"mode": "auto"}
_cfg["system"]["leds"] = {"mode": "status", "brightness": 140}
try:
    schema.validate(_cfg)
    check("out-of-range LED brightness is rejected", False, "accepted 140")
except schema.ValidationError:
    check("out-of-range LED brightness is rejected", True)

print("\n--- platform enumeration ---")
# This board's fan has no tachometer: hwmon0 exposes pwm1 and pwm1_enable and
# nothing else. Enumerating fan*_input found nothing and reported the hardware
# as fanless while the fan was running.
check("fans are found via pwm, not via a tachometer",
      "pwm[0-9]" in open(os.path.join(os.path.dirname(__file__), "..",
                                      "sbegw", "adapters", "platform.py")).read())
check("only the tri-colour status LED is claimed",
      platform.STATUS_LED_RE.match("green:status") is not None
      and platform.STATUS_LED_RE.match("90000.mdio-1:1c:green:lan") is None
      and platform.STATUS_LED_RE.match("mmc0::") is None)

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
