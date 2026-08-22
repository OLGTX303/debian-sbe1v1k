"""ethtool adapter: link speed/duplex, autoneg, flow control, PHY stats.

Debian's ethtool has no JSON mode for most subcommands, so output is parsed
defensively: an unparseable field becomes None rather than an exception, because
the SBE1V1K mixes three different PHYs (QCA8075, QCA8081, RTL8261) whose drivers
expose different subsets.
"""
from __future__ import annotations

import re
from typing import Any

from ..util import run, run_ok, ToolError, read_int

_SPEED_RE = re.compile(r"^\s*Speed:\s*(\d+)")
_DUPLEX_RE = re.compile(r"^\s*Duplex:\s*(\w+)")
_AUTONEG_RE = re.compile(r"^\s*Auto-negotiation:\s*(\w+)")
_LINK_RE = re.compile(r"^\s*Link detected:\s*(\w+)")
_PORT_RE = re.compile(r"^\s*Port:\s*(.+)$")
_SUPPORTED_RE = re.compile(r"([0-9]+)base\S*/(Full|Half)")


def _text(dev: str, *args: str) -> str:
    try:
        return run(["ethtool", *args, dev] if args else ["ethtool", dev])
    except (ToolError, OSError):
        return ""


def link_info(dev: str) -> dict[str, Any]:
    out = _text(dev)
    info: dict[str, Any] = {
        "speed_mbps": None, "duplex": None, "autoneg": None,
        "link_detected": None, "medium": None, "supported_speeds": [],
    }
    for line in out.splitlines():
        if m := _SPEED_RE.match(line):
            info["speed_mbps"] = int(m.group(1))
        elif m := _DUPLEX_RE.match(line):
            info["duplex"] = m.group(1).lower()
        elif m := _AUTONEG_RE.match(line):
            info["autoneg"] = m.group(1).lower() == "on"
        elif m := _LINK_RE.match(line):
            info["link_detected"] = m.group(1).lower() == "yes"
        elif m := _PORT_RE.match(line):
            info["medium"] = m.group(1).strip()

    # Supported link modes appear on continuation lines; collect the whole block.
    if "Supported link modes:" in out:
        block = out.split("Supported link modes:", 1)[1]
        block = block.split("Supported pause frame use:")[0]
        speeds = {int(m.group(1)) for m in _SUPPORTED_RE.finditer(block)}
        info["supported_speeds"] = sorted(speeds)
    return info


def pause(dev: str) -> dict[str, Any]:
    out = _text(dev, "-a")
    result: dict[str, Any] = {"autoneg": None, "rx": None, "tx": None}
    for line in out.splitlines():
        low = line.strip().lower()
        if low.startswith("autonegotiate:"):
            result["autoneg"] = low.endswith("on")
        elif low.startswith("rx:"):
            result["rx"] = low.endswith("on")
        elif low.startswith("tx:"):
            result["tx"] = low.endswith("on")
    return result


def driver_info(dev: str) -> dict[str, str]:
    out = _text(dev, "-i")
    info: dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip().replace("-", "_")] = value.strip()
    return info


def statistics(dev: str) -> dict[str, int]:
    """Driver-level counters, including CRC errors where the PHY exposes them."""
    out = _text(dev, "-S")
    stats: dict[str, int] = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value.isdigit():
            stats[key.strip()] = int(value)
    return stats


def crc_errors(dev: str) -> int | None:
    """Best-effort CRC error count across the naming variants the PHYs use."""
    stats = statistics(dev)
    for key in ("rx_crc_errors", "rx_crc_err", "rx_fcs_errors", "crc_errors",
                "rx_align_errors"):
        if key in stats:
            return stats[key]
    return None


def eee(dev: str) -> dict[str, Any]:
    out = _text(dev, "--show-eee")
    enabled = None
    for line in out.splitlines():
        low = line.strip().lower()
        if low.startswith("eee status:"):
            enabled = "enabled" in low or "active" in low
    return {"supported": bool(out), "enabled": enabled}


def cable_test(dev: str) -> dict[str, Any]:
    """Trigger a TDR cable test where the PHY driver supports it."""
    try:
        out = run(["ethtool", "--cable-test", dev], timeout=25.0)
    except (ToolError, OSError):
        return {"supported": False, "results": []}
    results = []
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("pair"):
            results.append(line)
    return {"supported": True, "results": results}


def phy_temperature(dev: str) -> float | None:
    """Some QCA PHYs export a temperature via ethtool stats or hwmon."""
    stats = statistics(dev)
    for key, value in stats.items():
        if "temp" in key.lower():
            # Drivers report either degrees or millidegrees.
            return value / 1000.0 if value > 1000 else float(value)
    return None


# ------------------------------------------------------------------ mutators

def set_speed(dev: str, speed: str, duplex: str = "full") -> bool:
    """`speed` is "auto" or an Mbps value as a string."""
    if speed == "auto":
        return run_ok(["ethtool", "-s", dev, "autoneg", "on"])
    return run_ok(["ethtool", "-s", dev, "autoneg", "off",
                   "speed", str(speed), "duplex", duplex])


def set_pause(dev: str, enabled: bool) -> bool:
    state = "on" if enabled else "off"
    return run_ok(["ethtool", "-A", dev, "rx", state, "tx", state])
