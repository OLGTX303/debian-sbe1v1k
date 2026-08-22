"""platformd hardware introspection: NSS/PPE/EDMA/PPEDS, thermal, CPU, storage.

Everything here is read-only discovery of what the IPQ9574 platform actually
offers. The spec is explicit that acceleration state must be *detected*, and that
the reason for a software fallback must be reportable — so absence of a sysfs or
debugfs node is recorded as a reason string, not hidden.
"""
from __future__ import annotations

import glob
import os
import re
from typing import Any

from ..util import read_int, read_text, run, run_json, ToolError

# QSDK exposes NSS/PPE state through these paths. They differ between QSDK
# releases, so each capability lists candidates and reports which one matched.
NSS_PATHS = ("/proc/net/nss", "/sys/kernel/debug/qca-nss-drv",
             "/sys/kernel/debug/nss")
PPE_PATHS = ("/sys/kernel/debug/ppe", "/sys/kernel/debug/qca-nss-ppe",
             "/proc/ppe")
EDMA_PATHS = ("/sys/kernel/debug/edma", "/sys/kernel/debug/qca-nss-drv/edma",
              "/proc/net/edma")
PPEDS_PATHS = ("/sys/kernel/debug/ppe_ds", "/sys/kernel/debug/qca-nss-ppe/ppe_ds",
               "/sys/kernel/debug/ath12k/ppeds")
SSDK_PATHS = ("/sys/ssdk", "/proc/qca_ssdk", "/sys/kernel/debug/ssdk")


def _first_existing(paths: tuple[str, ...]) -> str | None:
    for path in paths:
        if os.path.exists(path):
            return path
    return None


def _module_loaded(name: str) -> bool:
    return os.path.isdir(f"/sys/module/{name}")


def acceleration() -> dict[str, Any]:
    """Detect the hardware datapath and explain any missing piece."""
    nss = _first_existing(NSS_PATHS)
    ppe = _first_existing(PPE_PATHS)
    edma = _first_existing(EDMA_PATHS)
    ppeds = _first_existing(PPEDS_PATHS)
    ssdk = _first_existing(SSDK_PATHS)

    modules = {
        "qca_nss_drv": _module_loaded("qca_nss_drv"),
        "qca_nss_ppe": _module_loaded("qca_nss_ppe"),
        "qca_ssdk": _module_loaded("qca_ssdk"),
        "ecm": _module_loaded("ecm"),
        "ath12k": _module_loaded("ath12k"),
        "nf_conntrack": _module_loaded("nf_conntrack"),
    }

    reasons: list[str] = []
    if not modules["qca_nss_drv"]:
        reasons.append("qca-nss-drv not loaded: flows stay in the Linux datapath")
    if not modules["ecm"]:
        reasons.append("ECM not loaded: no connection manager to push flows to NSS")
    if nss is None:
        reasons.append("no NSS debug/proc interface found: statistics unavailable")
    if ppeds is None and modules["ath12k"]:
        reasons.append("PPEDS interface not present: Wi-Fi frames take the host path")

    # ECM front-end mode tells us whether offload is actually armed.
    ecm_state = read_text("/sys/kernel/debug/ecm/ecm_nss_ipv4/stop", "").strip()
    offload_enabled = modules["ecm"] and modules["qca_nss_drv"] and ecm_state != "1"

    return {
        "nss": {"present": nss is not None, "path": nss,
                "module": modules["qca_nss_drv"]},
        "ppe": {"present": ppe is not None, "path": ppe,
                "module": modules["qca_nss_ppe"]},
        "edma": {"present": edma is not None, "path": edma},
        "ppeds": {"present": ppeds is not None, "path": ppeds},
        "ssdk": {"present": ssdk is not None, "path": ssdk,
                 "module": modules["qca_ssdk"]},
        "modules": modules,
        "hardware_nat": offload_enabled,
        "hardware_routing": offload_enabled,
        "offload_enabled": offload_enabled,
        "fallback_reasons": reasons,
    }


def flow_statistics() -> dict[str, Any]:
    """Offloaded vs software flow counts, when the platform reports them."""
    stats: dict[str, Any] = {"accelerated": None, "software": None, "source": None}

    # ECM keeps a connection count that reflects accelerated flows.
    for path, key in (
        ("/sys/kernel/debug/ecm/ecm_db/connection_count", "accelerated"),
        ("/proc/net/nss/ipv4/connections", "accelerated"),
    ):
        value = read_int(path)
        if value is not None:
            stats[key] = value
            stats["source"] = path
            break

    total = conntrack_count()
    if total is not None:
        if stats["accelerated"] is not None:
            stats["software"] = max(0, total - stats["accelerated"])
        stats["total"] = total
    return stats


def conntrack_count() -> int | None:
    return read_int("/proc/sys/net/netfilter/nf_conntrack_count")


def conntrack_max() -> int | None:
    return read_int("/proc/sys/net/netfilter/nf_conntrack_max")


def ppeds_radios() -> list[dict[str, Any]]:
    """Per-radio PPEDS ring state (wifi spec §44)."""
    base = _first_existing(PPEDS_PATHS)
    radios: list[dict[str, Any]] = []
    if base is None:
        return radios
    for entry in sorted(glob.glob(os.path.join(base, "*"))):
        name = os.path.basename(entry)
        if not os.path.isdir(entry):
            continue
        radios.append({
            "id": name,
            "enabled": read_int(os.path.join(entry, "enabled"), 1) == 1,
            "tx_rings": read_int(os.path.join(entry, "tx_ring_count")),
            "rx_rings": read_int(os.path.join(entry, "rx_ring_count")),
            "tx_packets": read_int(os.path.join(entry, "tx_pkts")),
            "rx_packets": read_int(os.path.join(entry, "rx_pkts")),
            "errors": read_int(os.path.join(entry, "errors")),
        })
    return radios


def thermal() -> dict[str, Any]:
    """All thermal zones plus a derived worst-case state."""
    zones = []
    worst = None
    for zone_dir in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
        temp = read_int(os.path.join(zone_dir, "temp"))
        if temp is None:
            continue
        celsius = temp / 1000.0
        trips = {}
        for trip in sorted(glob.glob(os.path.join(zone_dir, "trip_point_*_temp"))):
            index = re.search(r"trip_point_(\d+)_temp", trip)
            trip_type = read_text(trip.replace("_temp", "_type")).strip()
            value = read_int(trip)
            if index and value is not None and value > 0:
                trips[trip_type or f"trip{index.group(1)}"] = value / 1000.0
        zones.append({
            "id": os.path.basename(zone_dir),
            "type": read_text(os.path.join(zone_dir, "type")).strip(),
            "temperature_c": round(celsius, 1),
            "trips": trips,
        })
        worst = celsius if worst is None else max(worst, celsius)

    state = "normal"
    if worst is not None:
        if worst >= 105:
            state = "critical"
        elif worst >= 95:
            state = "warning"
    return {"zones": zones, "max_temperature_c": round(worst, 1) if worst else None,
            "state": state, "fans": fans()}


def fans() -> list[dict[str, Any]]:
    """Every controllable fan, keyed on its PWM rather than on a tachometer.

    This board's fan is a pwm-fan with no tacho at all: hwmon0 exposes pwm1 and
    pwm1_enable and nothing else. Enumerating fan*_input therefore found no fans
    and the gateway reported the hardware as fanless while the fan was running.
    """
    out = []
    for hwmon in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        name = read_text(os.path.join(hwmon, "name")).strip()
        for pwm_path in sorted(glob.glob(os.path.join(hwmon, "pwm[0-9]"))):
            duty = read_int(pwm_path)
            # A tacho is optional; pair it up by index when it exists.
            index = os.path.basename(pwm_path)[3:]
            rpm = read_int(os.path.join(hwmon, f"fan{index}_input"))
            percent = None if duty is None else round(duty / 255 * 100)
            out.append({
                "hwmon": name,
                "id": os.path.basename(pwm_path),
                "path": pwm_path,
                "rpm": rpm,
                "duty": duty,
                "duty_percent": percent,
                "enabled": read_int(os.path.join(hwmon, f"pwm{index}_enable")),
                # Without a tacho, "stopped" can only mean zero duty; claiming a
                # fault would be inventing a reading we cannot take.
                "status": ("ok" if (rpm or 0) > 0 or (duty or 0) > 0
                           else ("stopped" if duty == 0 else "unknown")),
                "tacho": rpm is not None,
            })
    out += _cooling_fans()
    return out


def _cooling_fans() -> list[dict[str, Any]]:
    """Thermal cooling devices that are fans, for the kernel's own view.

    The kernel's step_wise governor drives cooling_device0 (pwm-fan) from the
    thermal zone trip points. That stays in place as a safety net underneath any
    policy of ours, so its state is worth reporting alongside the raw PWM.
    """
    out = []
    for dev in sorted(glob.glob("/sys/class/thermal/cooling_device*")):
        kind = read_text(os.path.join(dev, "type")).strip()
        if "fan" not in kind.lower():
            continue
        cur = read_int(os.path.join(dev, "cur_state"))
        top = read_int(os.path.join(dev, "max_state"))
        out.append({
            "hwmon": kind,
            "id": os.path.basename(dev),
            "path": dev,
            "rpm": None,
            "duty": cur,
            "duty_percent": (None if cur is None or not top
                             else round(cur / top * 100)),
            "cooling_state": cur,
            "cooling_max_state": top,
            "status": "ok" if (cur or 0) > 0 else "stopped",
            "tacho": False,
        })
    return out


# Only the tri-colour status LED is ours to drive. The PHY-driven LAN LEDs
# (90000.mdio-*) show link state in hardware and the eMMC LED shows disk
# activity; taking those over would hide information rather than add any.
STATUS_LED_RE = re.compile(r"^(red|green|blue|amber|orange|white):status$")


def leds() -> list[dict[str, Any]]:
    """The LEDs this gateway may drive, with their current state."""
    out = []
    for path in sorted(glob.glob("/sys/class/leds/*")):
        name = os.path.basename(path)
        match = STATUS_LED_RE.match(name)
        maximum = read_int(os.path.join(path, "max_brightness")) or 255
        out.append({
            "id": name,
            "path": path,
            "colour": match.group(1) if match else None,
            "role": "status" if match else "reserved",
            "brightness": read_int(os.path.join(path, "brightness")),
            "max_brightness": maximum,
            "trigger": _active_trigger(path),
        })
    return out


def _active_trigger(path: str) -> str | None:
    """The selected trigger, which sysfs marks with [brackets]."""
    for token in read_text(os.path.join(path, "trigger")).split():
        if token.startswith("[") and token.endswith("]"):
            return token[1:-1]
    return None


def cpu() -> dict[str, Any]:
    """Load, per-core frequency and utilisation derived from /proc/stat."""
    load = read_text("/proc/loadavg").split()
    freqs = []
    for path in sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")):
        khz = read_int(path)
        if khz:
            freqs.append(round(khz / 1000))
    return {
        "load": [float(x) for x in load[:3]] if len(load) >= 3 else [0.0, 0.0, 0.0],
        "cores": os.cpu_count() or 4,
        "frequency_mhz": freqs,
        "jiffies": _cpu_jiffies(),
    }


def _cpu_jiffies() -> dict[str, int]:
    """Aggregate CPU time buckets; the sampler turns these into a percentage."""
    for line in read_text("/proc/stat").splitlines():
        if line.startswith("cpu "):
            parts = [int(x) for x in line.split()[1:]]
            keys = ("user", "nice", "system", "idle", "iowait", "irq",
                    "softirq", "steal")
            return dict(zip(keys, parts))
    return {}


def memory() -> dict[str, Any]:
    info: dict[str, int] = {}
    for line in read_text("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        value = rest.strip().split(" ")[0]
        if value.isdigit():
            info[key] = int(value)
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", 0)
    return {
        "total_kb": total,
        "available_kb": available,
        "used_kb": max(0, total - available),
        "used_percent": round((total - available) / total * 100, 1) if total else 0.0,
        "swap_total_kb": info.get("SwapTotal", 0),
        "swap_free_kb": info.get("SwapFree", 0),
        # A non-zero OOM kill count is a health signal, not just a log line.
        "oom_kills": _oom_kills(),
    }


def _oom_kills() -> int:
    for line in read_text("/proc/vmstat").splitlines():
        if line.startswith("oom_kill "):
            return int(line.split()[1])
    return 0


# Filesystems that can never be written to, so their "usage" is meaningless.
READ_ONLY_FSTYPES = frozenset({"squashfs", "erofs", "cramfs", "iso9660",
                               "romfs"})


def _mount_table() -> dict[str, tuple[str, bool]]:
    """mount point -> (fstype, read_only), from /proc/mounts."""
    table: dict[str, tuple[str, bool]] = {}
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mount, fstype, opts = parts[1], parts[2], parts[3]
                mount = mount.replace("\\040", " ")
                table[mount] = (fstype,
                                "ro" in opts.split(","))
    except OSError:
        pass
    return table


def storage() -> list[dict[str, Any]]:
    """Writable filesystems only, with inode usage.

    The root filesystem here is a read-only SquashFS image, which by definition
    reports 100% used — so a health check on "/" claimed the device was out of
    storage while /data had 5.7 GB free. Read-only images are firmware, not
    user storage, and are reported separately with `writable: False` so the UI
    can show them without counting them.
    """
    table = _mount_table()
    out = []
    for mount in ("/data", "/var", "/tmp", "/run", "/"):
        if mount not in table and mount != "/":
            continue
        if not os.path.ismount(mount) and mount != "/":
            continue
        fstype, read_only = table.get(mount, ("unknown", False))
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total == 0:
            continue
        writable = not read_only and fstype not in READ_ONLY_FSTYPES
        entry = {
            "mount": mount,
            "fstype": fstype,
            "writable": writable,
            "total_bytes": total,
            "free_bytes": free,
            "used_percent": round((total - free) / total * 100, 1),
        }
        if writable and st.f_files:
            entry["inodes_total"] = st.f_files
            entry["inodes_free"] = st.f_favail
            entry["inodes_used_percent"] = round(
                (st.f_files - st.f_favail) / st.f_files * 100, 1)
        out.append(entry)
    return out


def uptime() -> float:
    return float(read_text("/proc/uptime", "0").split()[0] or 0)


def firmware_version() -> str:
    for path in ("/etc/sbegw/version", "/etc/os-release"):
        text = read_text(path)
        if not text:
            continue
        if path.endswith("version"):
            return text.strip()
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def board() -> dict[str, Any]:
    """Board identity, including everything readable from ART and the SoC."""
    from . import art as art_adapter

    identity = art_adapter.identity()
    return {
        "model": identity["model"],
        "compatible": read_text("/proc/device-tree/compatible", "")
                      .strip("\x00").replace("\x00", ","),
        "soc": "Qualcomm IPQ9574",
        "kernel": read_text("/proc/sys/kernel/osrelease").strip(),
        "firmware": firmware_version(),
        "serial": identity["serial"],
        "serial_source": identity["serial_source"],
        "identity": identity,
    }


def pcie_radios() -> list[dict[str, Any]]:
    """PCIe devices claimed by ath12k, used to correlate radios to slots."""
    radios = []
    for path in sorted(glob.glob("/sys/bus/pci/devices/*")):
        driver = os.path.join(path, "driver")
        if not os.path.islink(driver):
            continue
        if os.path.basename(os.path.realpath(driver)) != "ath12k":
            continue
        radios.append({
            "slot": os.path.basename(path),
            "vendor": read_text(os.path.join(path, "vendor")).strip(),
            "device": read_text(os.path.join(path, "device")).strip(),
            "link_speed": read_text(os.path.join(path, "current_link_speed")).strip(),
            "link_width": read_text(os.path.join(path, "current_link_width")).strip(),
        })
    return radios
