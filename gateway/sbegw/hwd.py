"""hwd — fan and status-LED policy.

Fan
---
The board has a pwm-fan with no tachometer: hwmon0 exposes pwm1 (0-255) and
pwm1_enable, and nothing else. There is no way to read back an RPM, so "is the
fan spinning" is not a question this code can answer — only "what duty did we
ask for".

The kernel's own step_wise governor is already bound to this fan through
cooling_device0 and the device tree's trip points, and it is left bound
deliberately: it is the safety net, and it can raise the duty at any trip
crossing regardless of what this policy asked for. That is the desired
behaviour, so the policy here is only ever a floor.

The board's four duty levels and the temperatures that select them come from
the device tree, not from invented numbers — see FAN_LEVELS and FAN_CURVES
below. The most important thing they encode is that the minimum duty is 36/255
(14%), not zero: this board never stops its fan.

Mode "auto" means not intervening at all, which is a genuinely useful answer
here because the device tree's own policy is a sensible one.

LEDs
----
One tri-colour status LED, exposed as three independent GPIO LEDs
(red/green/blue:status). The PHY-driven LAN LEDs and the eMMC activity LED are
left alone — they already show link and disk state in hardware.

The LED answers one question: "is this router healthy, and if not, how bad?"
Blink patterns are used for the states an operator needs to notice from across a
room, solid colours for steady states.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .adapters import platform
from .util import monotonic

log = logging.getLogger("sbegw.hwd")

# Everything below comes from the board's device tree
# (ipq9570-sbe1v1k.dts), not from guesswork:
#
#   fan: pwm-fan {
#       pwms = <&pwm 3 40000 0>;          // SoC PWM channel 3, 25 kHz
#       cooling-levels = <36 72 128 255>;
#   };
#
# and the fan is bound to exactly one thermal zone, top-glue-thermal
# (tsens 15), through these cooling maps:
#
#   active-silent  40C -> level 0 (duty  36, 14%)
#   active-low     50C -> level 1 (duty  72, 28%)
#   active-med     65C -> level 2 (duty 128, 50%)
#   active-high    80C -> level 3 (duty 255, 100%)
#   hot           100C     (cpufreq throttle, not a fan map)
#   crit          110C     (shutdown)
#
# Two consequences worth being explicit about:
#
#  * The minimum duty is 36, not 0. The board never stops this fan — most
#    likely because it needs a minimum duty to start turning reliably. A policy
#    that writes 0 would stop it below the floor its designer chose.
#  * The kernel's step_wise governor is already bound to the same fan through
#    those maps and stays bound. It can raise the duty at any trip crossing
#    regardless of what we asked for, which is exactly the safety net we want.
#    So our policy is only ever a floor, and "auto" means not intervening.
FAN_LEVELS = (36, 72, 128, 255)          # dts cooling-levels, duty out of 255
FAN_LEVEL_PERCENT = tuple(round(d / 255 * 100) for d in FAN_LEVELS)  # 14/28/50/100

# (temperature °C at or above which, level index). Thresholds are kept on the
# device tree's own trip points so a mode either matches the kernel's decision
# or deliberately sits above it, never a few degrees off it — straddling a trip
# is what makes a fan hunt.
FAN_CURVES: dict[str, list[tuple[float, int]]] = {
    # The board's own policy, ramping one step early at the top so the fan is
    # already moving air before the die reaches 80C.
    "balanced": [(0, 0), (50, 1), (65, 2), (75, 3)],
    # Biased for a warm cabinet: never idle, at full well before 80C.
    "cool":     [(0, 1), (50, 2), (65, 3)],
    # Pinned at the board's floor until it genuinely needs more than the
    # kernel is already giving it.
    "quiet":    [(0, 0), (65, 1), (80, 2), (90, 3)],
}
DEFAULT_FAN_MODE = "auto"

# Drop back a level only once the temperature falls this far below the
# threshold that raised it. The device tree uses 1C of hysteresis on its trips;
# 4C here keeps our own steps from hunting on top of the kernel's.
FAN_HYSTERESIS_C = 4.0

# The device tree binds the fan to exactly one sensor, so that is the control
# input. The others are still consulted, and the hotter of the two wins: a
# single hot radio is precisely what a fan exists to deal with, and running
# faster than the board asks for is safe where running slower is not.
FAN_CONTROL_ZONE = "top-glue-thermal"

# The board's own policy, transcribed from the cooling maps above. Needed when
# handing the fan back: pwm1 and the cooling device's cur_state are the same
# knob (writing one moves the other, verified on hardware), so once we have
# written a duty there is no way to read what the governor would have chosen.
# Reproducing its table is the only honest answer; the governor then corrects
# us at its next trip crossing anyway.
DTS_FAN_POLICY: list[tuple[float, int]] = [(0, 0), (50, 1), (65, 2), (80, 3)]
FAN_ZONE_HINTS = ("cpu", "nss", "wcss", "ath12k", "top-glue")

# Straight off the device tree's trips rather than round numbers.
THERMAL_WARNING_C = 100.0   # dts "hot"
THERMAL_CRITICAL_C = 110.0  # dts "crit"

# state -> (red, green, blue, blink interval in ms or None for solid)
LED_PATTERNS: dict[str, tuple[bool, bool, bool, int | None]] = {
    "off":       (False, False, False, None),
    "booting":   (False, False, True, 500),    # blue blink: coming up
    "applying":  (False, False, True, None),   # blue solid: config in flight
    "healthy":   (False, True, False, None),   # green solid
    "no-wan":    (True, True, False, None),    # red+green solid: LAN ok, no uplink
    "degraded":  (True, True, False, 700),     # red+green blink: something is down
    "fault":     (True, False, False, None),   # red solid
    "thermal":   (True, False, False, 200),    # red fast blink: too hot
    "identify":  (False, False, True, 120),    # blue fast blink: locate me
}
DEFAULT_LED_MODE = "status"


def curve_level(curve: list[tuple[float, int]], temperature: float) -> int:
    """Fan level for a temperature: the highest point at or below it."""
    level = curve[0][1]
    for threshold, value in curve:
        if temperature >= threshold:
            level = value
        else:
            break
    return level


def curve_step_down_ok(curve: list[tuple[float, int]], temperature: float,
                       current_level: int) -> bool:
    """Whether it is safe to drop a level, honouring hysteresis.

    The threshold that justified the current level has to be cleared by
    FAN_HYSTERESIS_C before stepping down, otherwise the fan hunts.
    """
    holding = [t for t, level in curve if level >= current_level]
    if not holding:
        return True
    return temperature < min(holding) - FAN_HYSTERESIS_C


class HardwareManager:
    """Applies fan and LED policy from measured hardware state."""

    def __init__(self, events=None):
        self.events = events
        self._fan_duty: int | None = None
        self._fan_level: int | None = None
        self._pending_level: int | None = None
        # The exact 0-255 duty to write. Percentages are for humans; going
        # through one loses the device tree's levels (72 -> 28% -> 71), and a
        # duty that is not a cooling level lands the fan a step lower than
        # asked for.
        self._pending_raw: int | None = None
        # Whether the fan has been handed back at least once. A fresh process
        # in "auto" mode believes it owns nothing, so without this a duty left
        # latched by a previous run (or a previous mode) would stay latched for
        # as long as the temperature held steady.
        self._released = False
        self._led_state: str | None = None
        self._last_thermal_event = 0.0
        # Set by main once the first config apply has finished, so the LED can
        # distinguish "still coming up" from "up and unhealthy".
        self.booted = False

    # ------------------------------------------------------------------ fan

    @staticmethod
    def _control_temperature(thermal: dict[str, Any]) -> float | None:
        """The temperature the fan policy acts on.

        The device tree binds the fan to top-glue-thermal alone, so that zone is
        always included; the hottest of the other zones a fan can help with wins
        if it is higher. Running faster than the board asks for is safe, running
        slower is not, and averaging 13 sensors would hide a single hot radio.
        """
        best = None
        for zone in thermal.get("zones", []):
            kind = (zone.get("type") or "").lower()
            if not any(hint in kind for hint in FAN_ZONE_HINTS):
                continue
            temp = zone.get("temperature_c")
            if temp is None:
                continue
            best = temp if best is None else max(best, temp)
        # Fall back to the global worst case rather than declining to act.
        return best if best is not None else thermal.get("max_temperature_c")

    # Kept as an alias: _control_temperature reads better at the call sites,
    # but the old name is referenced by status().
    _relevant_temperature = _control_temperature

    def fan_target(self, cfg: dict[str, Any],
                   temperature: float | None) -> tuple[int | None, str]:
        """Target duty percent and a reason, without touching hardware.

        A target of None means "do not intervene" — hand the fan back to the
        kernel governor, which is a real and useful answer on this board
        because the device tree already encodes a sensible policy.
        """
        fan = (cfg.get("system", {}) or {}).get("fan", {}) or {}
        mode = fan.get("mode", DEFAULT_FAN_MODE)

        if mode == "auto":
            self._pending_level = self._pending_raw = None
            return None, "kernel thermal governor (device-tree policy)"

        if mode == "max":
            self._pending_level, self._pending_raw = len(FAN_LEVELS) - 1, 255
            return 100, "forced maximum"

        if mode == "manual":
            duty = int(fan.get("manual_percent", 50) or 0)
            if 0 < duty < FAN_LEVEL_PERCENT[0]:
                # Below the board's own floor the fan may not turn at all, and
                # a fan that is powered but stalled is worse than a stopped one.
                self._pending_level, self._pending_raw = 0, FAN_LEVELS[0]
                return (FAN_LEVEL_PERCENT[0],
                        f"{duty}% requested, raised to the board's minimum "
                        f"{FAN_LEVEL_PERCENT[0]}%")
            self._pending_level = None
            self._pending_raw = max(0, min(255, round(duty * 255 / 100)))
            return duty, "manual"

        if temperature is None:
            # No reading is not a reason to stop cooling.
            self._pending_level, self._pending_raw = 2, FAN_LEVELS[2]
            return FAN_LEVEL_PERCENT[2], "no temperature reading; holding 50%"

        curve = FAN_CURVES.get(mode) or FAN_CURVES["balanced"]
        level = curve_level(curve, temperature)

        if temperature >= THERMAL_WARNING_C:
            self._pending_level, self._pending_raw = len(FAN_LEVELS) - 1, 255
            return 100, f"{temperature:.0f}C at or past the dts hot trip"

        current = self._fan_level
        if (current is not None and level < current
                and not curve_step_down_ok(curve, temperature, current)):
            self._pending_level, self._pending_raw = current, FAN_LEVELS[current]
            return (FAN_LEVEL_PERCENT[current],
                    f"{temperature:.0f}C, holding level {current} (hysteresis)")

        self._pending_level, self._pending_raw = level, FAN_LEVELS[level]
        return FAN_LEVEL_PERCENT[level], f"{temperature:.0f}C, level {level}"

    def apply_fan(self, cfg: dict[str, Any],
                  thermal: dict[str, Any]) -> list[str]:
        temperature = self._control_temperature(thermal)
        duty, reason = self.fan_target(cfg, temperature)
        if duty is None:
            # Mode "auto": hand the fan back. Also done once on the first tick
            # of a fresh process, which may have inherited a latched duty it
            # has no record of setting.
            if self._fan_duty is not None or not self._released:
                self._release_fan(thermal)
            return []

        # Only real PWM entries are writable with a 0-255 duty. The cooling
        # device is reported alongside them for the kernel's view of the same
        # fan, and its cur_state is 0-3 — writing a duty there would be wrong.
        # Told apart by cooling_state rather than by path, so the distinction is
        # about what the entry *is* rather than where it happens to live.
        #
        # hwmon pwm indices are per-driver, not SoC PWM channels: this board's
        # single pwm-fan is hwmon "pwmfan" pwm1, which drives PWM channel 3.
        controllable = [f for f in thermal.get("fans", [])
                        if f.get("cooling_state") is None and f.get("path")]
        if not controllable:
            return []
        if duty == self._fan_duty:
            return []

        messages = []
        raw = self._pending_raw
        if raw is None:
            raw = max(0, min(255, round(duty * 255 / 100)))
        for fan in controllable:
            # pwm*_enable = 1 selects manual duty. Some drivers ignore writes
            # to pwm* until it is set, so set it first rather than assume.
            enable = os.path.join(os.path.dirname(fan["path"]),
                                  f"{fan['id']}_enable")
            if os.path.exists(enable):
                self._write(enable, "1")
            if not self._write(fan["path"], str(raw)):
                messages.append(f"could not set {fan['id']} duty")
        self._fan_duty = duty
        self._fan_level = self._pending_level
        self._released = False
        log.info("fan -> %d%% (%s)", duty, reason)
        return messages

    def _release_fan(self, thermal: dict[str, Any]) -> None:
        """Give the fan back to the kernel governor.

        The governor only writes the fan when a trip point is crossed, so simply
        stopping our own writes would leave the fan stuck at whatever we last
        asked for until the temperature moved.

        Reading cur_state back does not work either: it is the same knob as
        pwm1, so after our own write it reports our value rather than the
        governor's intent. Observed on hardware — releasing after "max" read
        cur_state 3 and wrote 255 straight back, leaving the fan at full at
        56C. So the board's own trip table is applied instead.
        """
        target = None
        temperature = self._control_temperature(thermal)
        if temperature is not None:
            target = FAN_LEVELS[curve_level(DTS_FAN_POLICY, temperature)]
        for fan in thermal.get("fans", []):
            if fan.get("cooling_state") is not None or not fan.get("path"):
                continue
            if target is not None:
                self._write(fan["path"], str(target))
        self._fan_duty = None
        self._fan_level = None
        self._released = True
        log.info("fan released to the kernel thermal governor%s",
                 f" at duty {target}" if target is not None else "")

    # ----------------------------------------------------------------- leds

    def led_state(self, cfg: dict[str, Any], health: dict[str, Any]) -> str:
        """The status the LED should show, worst-first."""
        leds = (cfg.get("system", {}) or {}).get("leds", {}) or {}
        mode = leds.get("mode", DEFAULT_LED_MODE)
        if mode == "off":
            return "off"
        if mode == "identify":
            return "identify"

        temperature = health.get("max_temperature_c")
        if temperature is not None and temperature >= THERMAL_WARNING_C:
            return "thermal"
        if health.get("fault"):
            return "fault"
        if not self.booted:
            return "booting"
        if health.get("applying"):
            return "applying"
        # A router with no uplink is a distinct, very common state and deserves
        # its own colour rather than being lumped in with "degraded".
        if health.get("wan_up") is False:
            return "no-wan"
        if health.get("degraded"):
            return "degraded"
        return "healthy"

    def apply_leds(self, cfg: dict[str, Any],
                   health: dict[str, Any]) -> list[str]:
        state = self.led_state(cfg, health)
        if state == self._led_state:
            return []
        pattern = LED_PATTERNS.get(state) or LED_PATTERNS["healthy"]
        red, green, blue, blink = pattern
        leds = (cfg.get("system", {}) or {}).get("leds", {}) or {}
        brightness_pct = int(leds.get("brightness", 100) or 0)

        wanted = {"red": red, "green": green, "blue": blue}
        for led in platform.leds():
            if led.get("role") != "status":
                continue
            on = wanted.get(led.get("colour"), False)
            # brightness=0 means off, whatever the state says. Without this the
            # max(1, ...) below rounded 0% back up to 1 and the LED stayed lit.
            if brightness_pct <= 0:
                on = False
            level = 0
            if on:
                # These LEDs are GPIO, so max_brightness is 1 and the scale
                # collapses to on/off. The arithmetic is kept for boards whose
                # status LED is PWM-backed.
                level = max(1, round(led["max_brightness"] * brightness_pct / 100))
            self._set_led(led, level, blink if on else None)

        self._led_state = state
        log.info("status LED -> %s", state)
        return []

    def _set_led(self, led: dict[str, Any], level: int,
                 blink_ms: int | None) -> None:
        path = led["path"]
        trigger = os.path.join(path, "trigger")
        if blink_ms and level:
            # The timer trigger owns brightness while it runs, so set the
            # trigger first and then the on/off periods.
            self._write(trigger, "timer")
            self._write(os.path.join(path, "delay_on"), str(blink_ms))
            self._write(os.path.join(path, "delay_off"), str(blink_ms))
            self._write(os.path.join(path, "brightness"), str(level))
            return
        # Back to plain on/off. Leaving the timer trigger active would keep the
        # LED blinking at whatever brightness we then wrote.
        if led.get("trigger") not in (None, "none"):
            self._write(trigger, "none")
        self._write(os.path.join(path, "brightness"), str(level))

    # ---------------------------------------------------------------- shared

    @staticmethod
    def _write(path: str, value: str) -> bool:
        try:
            with open(path, "w") as fh:
                fh.write(value + "\n")
            return True
        except OSError as exc:
            log.debug("could not write %s=%s: %s", path, value, exc)
            return False

    def poll(self, cfg: dict[str, Any], health: dict[str, Any]) -> list[str]:
        """One policy tick. Never raises: this must not take the daemon down."""
        messages: list[str] = []
        try:
            thermal = platform.thermal()
        except Exception:  # noqa: BLE001
            log.exception("reading thermal state failed")
            thermal = {}
        merged = dict(health)
        merged.setdefault("max_temperature_c", thermal.get("max_temperature_c"))
        try:
            messages += self.apply_fan(cfg, thermal)
        except Exception:  # noqa: BLE001
            log.exception("fan policy failed")
        try:
            messages += self.apply_leds(cfg, merged)
        except Exception:  # noqa: BLE001
            log.exception("LED policy failed")

        temperature = merged.get("max_temperature_c")
        if (self.events and temperature is not None
                and temperature >= THERMAL_WARNING_C
                and monotonic() - self._last_thermal_event > 300):
            self._last_thermal_event = monotonic()
            self.events.emit(
                "THERMAL_WARNING",
                "error" if temperature >= THERMAL_CRITICAL_C else "warning",
                subsystem="hardware",
                data={"temperature_c": temperature,
                      "fan_percent": self._fan_duty})
        return messages

    def status(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """What the API and UI report."""
        thermal = platform.thermal()
        temperature = self._relevant_temperature(thermal)
        fan = (cfg.get("system", {}) or {}).get("fan", {}) or {}
        target, reason = self.fan_target(cfg, temperature)
        return {
            "fan": {
                "mode": fan.get("mode", DEFAULT_FAN_MODE),
                "target_percent": target,
                "applied_percent": self._fan_duty,
                "reason": reason,
                "control_temperature_c": temperature,
                # No tacho on this board, so a duty is all that can be claimed.
                "rpm_available": any(f.get("tacho") for f in thermal.get("fans", [])),
                "devices": thermal.get("fans", []),
                "curve": FAN_CURVES.get(fan.get("mode", DEFAULT_FAN_MODE)),
            },
            "leds": {
                "mode": (cfg.get("system", {}) or {}).get("leds", {}).get(
                    "mode", DEFAULT_LED_MODE),
                "state": self._led_state,
                "devices": [l for l in platform.leds() if l.get("role") == "status"],
            },
            "thermal": thermal,
        }
