"""nl80211/cfg80211 adapter via `iw`.

Radio identity is derived from *runtime capability*, never from the phy index:
the spec is explicit that phy0/phy1/phy2 ordering must not be depended on. A phy
is classified into a logical band id by the frequencies it actually advertises,
and the mapping is only published once the capability probe succeeds.
"""
from __future__ import annotations

import glob
import logging
import os
import re
import socket
import struct
from typing import Any

from ..util import read_int, read_text, run, run_ok, ToolError, normalise_mac

log = logging.getLogger("sbegw.nl80211")

# Frequency ranges that define a band. 6 GHz starts at 5925 MHz (channel 1 is
# 5955); using 5925 avoids misclassifying 5 GHz channel 165 (5825).
BAND_RANGES = (
    ("2g", 2400, 2500),
    ("5g", 5100, 5900),
    ("6g", 5925, 7125),
)

_WIPHY_RE = re.compile(r"^Wiphy (\S+)")
_BAND_RE = re.compile(r"^\s*Band (\d+):")
# Capture everything after the channel number, not just the first
# parenthesised group: iw prints the transmit power first and the regulatory
# flags after it — "* 5260 MHz [52] (23.0 dBm) (radar detection)" — so matching
# one group only ever saw "23.0 dBm" and every DFS and no-IR flag was lost.
_FREQ_RE = re.compile(r"^\s*\* (\d+(?:\.\d+)?) MHz \[(\d+)\](.*)$")
_TXPOWER_RE = re.compile(r"\(([\d.]+) dBm\)")


def available() -> bool:
    try:
        run(["iw", "--version"], timeout=5.0)
        return True
    except (ToolError, OSError):
        return False


def all_phys() -> list[str]:
    """Every wiphy name present in the kernel, including auxiliary ones.

    Names are not necessarily "phyN": the QSDK ath12k build names each wiphy
    after the bands its pdev carries — phy00 (2.4), phy01/phy02 (5 low/high),
    phy03/phy04 (6 low/high), phy05 (2.4+5) — and an MLO hardware group adopts
    the lexicographically smallest of them. Hence the enumeration is by sysfs
    rather than by assuming a name.
    """
    return sorted(
        os.path.basename(p) for p in glob.glob("/sys/class/ieee80211/*")
    )


def phys() -> list[str]:
    """Operational wiphys, i.e. those that can host an AP.

    ath12k registers a dedicated off-channel scan radio as its own wiphy called
    "phy-scan-00" when the firmware provides one. It carries every band but
    cannot serve clients, so publishing logical radios for it would duplicate
    each band as a phantom second radio.
    """
    return [p for p in all_phys() if not p.startswith("phy-scan")]


def phy_index(phy: str) -> int | None:
    return read_int(f"/sys/class/ieee80211/{phy}/index")


def phy_mac(phy: str) -> str | None:
    mac = read_text(f"/sys/class/ieee80211/{phy}/macaddress").strip()
    return normalise_mac(mac) if mac else None


def _phy_info_text(phy: str) -> str:
    try:
        return run(["iw", "phy", phy, "info"], timeout=20.0)
    except (ToolError, OSError) as exc:
        log.warning("iw phy %s info failed: %s", phy, exc)
        return ""


_BAND_SECTION_RE = re.compile(r"^\tBand (\d+):\s*$", re.M)


def _split_bands(text: str) -> list[str]:
    """Return the text of each `Band N:` section of `iw phy info`.

    Band-scoped facts (frequencies, HT/VHT/HE/EHT capabilities, widths, spatial
    streams) live inside these sections; wiphy-scoped facts (interface modes,
    iftype combinations) live outside them.
    """
    matches = list(_BAND_SECTION_RE.finditer(text))
    sections = []
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append(text[match.start():end])
    return sections


def _classify_band(freqs: list[tuple[float, int, str]]) -> str | None:
    """Name the band from its frequencies, by majority vote.

    Deliberately not the mean of every frequency on the phy: this platform
    registers all three radios as pdevs of a SINGLE wiphy (ath12k groups an
    MLO-capable hardware group behind one wiphy), so averaging 2.4, 5 and 6 GHz
    together produced one bogus "5g" radio and lost the other two entirely.
    """
    votes: dict[str, int] = {}
    for mhz, _channel, _flags in freqs:
        for name, low, high in BAND_RANGES:
            if low <= mhz <= high:
                votes[name] = votes.get(name, 0) + 1
                break
    if not votes:
        return None
    return max(votes.items(), key=lambda kv: kv[1])[0]


def phy_band_capabilities(phy: str) -> list[dict[str, Any]]:
    """One capability set per band the phy exposes.

    On a single-wiphy MLO device this returns three entries for one phy; on a
    conventional radio-per-phy device it returns one.
    """
    text = _phy_info_text(phy)
    if not text:
        return [_parse_band(phy, "", "")]
    sections = _split_bands(text)
    if not sections:
        return [_parse_band(phy, text, text)]
    return [_parse_band(phy, section, text) for section in sections]


def phy_capabilities(phy: str) -> dict[str, Any]:
    """First band of a phy. Prefer `phy_band_capabilities` for enumeration."""
    return phy_band_capabilities(phy)[0]


def _parse_band(phy: str, text: str, whole: str) -> dict[str, Any]:
    """Parse one band section. *whole* supplies the wiphy-scoped facts.

    Returns band, channel list (with DFS/no-IR flags), supported widths, PHY
    standards, spatial streams and MLO capability. Anything the driver does not
    advertise is reported as False/None rather than assumed.
    """
    caps: dict[str, Any] = {
        "phy": phy,
        "index": phy_index(phy),
        "mac": phy_mac(phy),
        "band": None,
        "channels": [],
        "channel_details": [],
        "widths": [20],
        "standards": [],
        "ht": False, "vht": False, "he": False, "eht": False,
        "mlo": False,
        "max_nss": 1,
        "max_tx_power_dbm": None,
        "dfs": False,
        "afc": False,
        "ap_supported": False,
        "max_ap_bss": 1,
        "raw_available": bool(whole),
    }
    if not text:
        return caps

    freqs: list[tuple[float, int, str]] = []
    for line in text.splitlines():
        if m := _FREQ_RE.match(line):
            mhz = float(m.group(1))
            channel = int(m.group(2))
            flags = (m.group(3) or "").lower()
            freqs.append((mhz, channel, flags))

    caps["band"] = _classify_band(freqs)

    details = []
    for mhz, channel, flags in freqs:
        disabled = "disabled" in flags
        no_ir = "no ir" in flags
        radar = "radar detection" in flags
        # Per-channel regulatory power. iw prints it in the same parenthesised
        # run as the flags, and it varies by sub-band — on this board 5 GHz is
        # 30 dBm in UNII-1/UNII-3 but 24 dBm across the DFS channels, so a
        # single per-band figure hides a 6 dB difference that decides coverage.
        power = None
        if m_pwr := re.search(r"\(([\d.]+) dbm\)", flags):
            power = float(m_pwr.group(1))
        details.append({
            "channel": channel, "frequency_mhz": mhz,
            "disabled": disabled, "no_ir": no_ir, "dfs": radar,
            "max_tx_power_dbm": power,
            "psc": caps["band"] == "6g" and channel in _PSC_CHANNELS,
        })
        if radar:
            caps["dfs"] = True
        if not disabled:
            caps["channels"].append(channel)
    caps["channel_details"] = details

    if powers := _TXPOWER_RE.findall(text):
        caps["max_tx_power_dbm"] = max(float(p) for p in powers)

    lowered = text.lower()
    caps["ht"] = "ht20/ht40" in lowered or "ht capabilities" in lowered
    caps["vht"] = "vht capabilities" in lowered
    caps["he"] = "he iftypes" in lowered or "he mac capabilities" in lowered
    caps["eht"] = "eht iftypes" in lowered or "eht mac capabilities" in lowered
    # ath12k/QSDK advertise MLO either as an explicit iftype flag or via the
    # module parameter; require the driver to say so before offering MLO.
    caps["mlo"] = ("mlo" in whole.lower() or "multi-link" in whole.lower()
                   or _driver_mlo_capable())

    # VHT is defined for 5 GHz only. A VHT capability line inside the 2.4 GHz
    # band section is a driver/parse artefact, and reporting it there would
    # advertise 802.11ac on a band that has no such thing.
    if caps["band"] == "2g":
        caps["vht"] = False

    widths = {20}
    if caps["ht"]:
        widths.add(40)
    # 6 GHz has no HT at all — 40 MHz there comes from HE/EHT. Gating 40 MHz on
    # HT alone dropped it from the 6 GHz width list entirely, so the UI offered
    # 20/80/160/320 and no 40.
    if caps["he"] or caps["eht"]:
        widths.add(40)
    if caps["vht"] or caps["he"]:
        if "80 mhz" in lowered or caps["band"] in ("5g", "6g"):
            widths.add(80)
        if "160 mhz" in lowered or "160/8080" in lowered:
            widths.add(160)
    if caps["eht"] and caps["band"] == "6g" and "320 mhz" in lowered:
        widths.add(320)
    # 5 GHz 240 MHz: QSDK runs 320 MHz EHT with one 80 MHz block punctured.
    caps["eht240"] = bool(
        caps["eht"] and caps["band"] == "5g" and driver_eht240_capable())
    if caps["eht240"]:
        widths.add(240)
    if caps["band"] == "2g":
        widths &= {20, 40}
    caps["widths"] = sorted(widths)

    standards = []
    if caps["band"] == "2g":
        standards += ["802.11b", "802.11g"]
    else:
        standards.append("802.11a")
    if caps["ht"]:
        standards.append("802.11n")
    if caps["vht"] and caps["band"] != "2g":
        standards.append("802.11ac")
    if caps["he"]:
        standards.append("802.11ax")
    if caps["eht"]:
        standards.append("802.11be")
    caps["standards"] = standards

    # Spatial streams: count the MCS/NSS rows the driver reports.
    nss = 1
    for match in re.finditer(r"(\d+) streams?", lowered):
        nss = max(nss, int(match.group(1)))
    for match in re.finditer(r"rx mcs set.*?(\d)x(\d)", lowered):
        nss = max(nss, int(match.group(2)))
    caps["max_nss"] = nss

    # Interface modes and iftype combinations are properties of the wiphy, not
    # of a band, so they are read from the full output.
    whole_lower = whole.lower()
    caps["ap_supported"] = "* ap" in whole_lower
    # The AP limit is the "#{ AP } <= N" term. Keying on "total <= N, #{ ap"
    # assumed a field order iw does not guarantee, so the real limit was missed
    # and every radio silently fell back to 8.
    if m := re.search(r"#\{ ap[^}]*\} <= (\d+)", whole_lower):
        caps["max_ap_bss"] = int(m.group(1))
    elif m := re.search(r"total <= (\d+)", whole_lower):
        caps["max_ap_bss"] = int(m.group(1))
    elif caps["ap_supported"]:
        caps["max_ap_bss"] = 8
    caps["afc"] = "afc" in whole_lower
    return caps


# 6 GHz Preferred Scanning Channels.
_PSC_CHANNELS = {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229}


def _driver_mlo_capable() -> bool:
    """ath12k gates MLO behind a module parameter; treat 0 as no MLO."""
    value = read_text("/sys/module/ath12k/parameters/mlo_capable", "").strip()
    if not value:
        return False
    return value not in ("0", "N", "n", "off")


_EHT240_CACHE: bool | None = None


def driver_eht240_capable() -> bool:
    """Does this ath12k build support 5 GHz 240 MHz (320 MHz + 80 MHz puncture)?

    240 MHz on 5 GHz is a Qualcomm extension driven by a vendor netlink command,
    not something nl80211 advertises, so there is nothing to read from `iw`. The
    honest available signal is whether the ath12k module that is loaded was built
    with the EHT240 support present at all; an operator can force the answer with
    /etc/sbegw/eht240 when they know better than this heuristic.
    """
    global _EHT240_CACHE
    if _EHT240_CACHE is not None:
        return _EHT240_CACHE

    override = read_text("/etc/sbegw/eht240", "").strip().lower()
    if override in ("1", "yes", "true", "on"):
        _EHT240_CACHE = True
        return True
    if override in ("0", "no", "false", "off"):
        _EHT240_CACHE = False
        return False

    if not os.path.isdir("/sys/module/ath12k"):
        _EHT240_CACHE = False
        return False

    release = read_text("/proc/sys/kernel/osrelease").strip()
    found = False
    for pattern in (f"/lib/modules/{release}/ath12k.ko*",
                    f"/lib/modules/{release}*/ath12k.ko*",
                    "/lib/modules/*/ath12k.ko*"):
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, "rb") as fh:
                    if b"EHT240" in fh.read():
                        found = True
                        break
            except OSError:
                continue
        if found:
            break
    log.info("ath12k 240 MHz (EHT240) support: %s", "yes" if found else "no")
    _EHT240_CACHE = found
    return found


def interfaces() -> list[dict[str, Any]]:
    """Wireless interfaces with their phy, type, channel and MLD address."""
    try:
        text = run(["iw", "dev"], timeout=10.0)
    except (ToolError, OSError):
        return []
    out: list[dict[str, Any]] = []
    current_phy: str | None = None
    entry: dict[str, Any] | None = None
    for line in text.splitlines():
        if line.startswith("phy#"):
            current_phy = "phy" + line[4:].strip()
            continue
        stripped = line.strip()
        if stripped.startswith("Interface "):
            if entry:
                out.append(entry)
            entry = {"name": stripped.split(None, 1)[1], "phy": current_phy,
                     "type": None, "channel": None, "width": None,
                     "frequency_mhz": None, "mac": None, "ssid": None,
                     "mld_mac": None, "txpower_dbm": None}
        elif entry is not None:
            if stripped.startswith("type "):
                entry["type"] = stripped.split(None, 1)[1]
            elif stripped.startswith("addr "):
                entry["mac"] = normalise_mac(stripped.split(None, 1)[1])
            elif stripped.startswith("ssid "):
                entry["ssid"] = stripped.split(None, 1)[1]
            elif stripped.startswith("channel "):
                if m := re.match(r"channel (\d+) \((\d+) MHz\), width: (\d+)", stripped):
                    entry["channel"] = int(m.group(1))
                    entry["frequency_mhz"] = int(m.group(2))
                    entry["width"] = int(m.group(3))
            elif stripped.startswith("txpower "):
                if m := re.search(r"([\d.]+) dBm", stripped):
                    entry["txpower_dbm"] = float(m.group(1))
            elif "mld addr" in stripped.lower() or stripped.startswith("multi-link"):
                if m := re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", stripped.lower()):
                    entry["mld_mac"] = m.group(1)
    if entry:
        out.append(entry)
    return out


def station_dump(iface: str) -> list[dict[str, Any]]:
    """Per-client radio measurements, including per-link data for MLO clients.

    `iw station dump` on an MLD-capable driver emits repeated blocks with
    `Link N:` headers under one station. Those become the `links` list so the API
    can report per-link RSSI/rate as the spec requires.
    """
    try:
        text = run(["iw", "dev", iface, "station", "dump"], timeout=15.0)
    except (ToolError, OSError):
        return []

    stations: list[dict[str, Any]] = []
    station: dict[str, Any] | None = None
    link: dict[str, Any] | None = None

    def target() -> dict[str, Any] | None:
        return link if link is not None else station

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Station "):
            if station:
                stations.append(station)
            mac = normalise_mac(line.split()[1])
            station = {"mac": mac, "interface": iface, "links": [],
                       "mld_mac": None, "is_mlo": False}
            link = None
            continue
        if station is None:
            continue
        if m := re.match(r"^Link (\d+)", line):
            link = {"link_id": int(m.group(1))}
            station["links"].append(link)
            station["is_mlo"] = True
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        dest = target()
        if dest is None:
            continue

        if key == "signal":
            dest["rssi"] = _first_int(value)
        elif key == "signal avg":
            dest["rssi_avg"] = _first_int(value)
        elif key == "tx bitrate":
            dest["tx_rate_mbps"] = _first_float(value)
            dest.update(_parse_rate_flags(value))
        elif key == "rx bitrate":
            dest["rx_rate_mbps"] = _first_float(value)
        elif key == "rx bytes":
            dest["rx_bytes"] = _first_int(value) or 0
        elif key == "tx bytes":
            dest["tx_bytes"] = _first_int(value) or 0
        elif key == "rx packets":
            dest["rx_packets"] = _first_int(value) or 0
        elif key == "tx packets":
            dest["tx_packets"] = _first_int(value) or 0
        elif key == "tx retries":
            dest["tx_retries"] = _first_int(value) or 0
        elif key == "tx failed":
            dest["tx_failed"] = _first_int(value) or 0
        elif key == "connected time":
            station["connected_seconds"] = _first_int(value) or 0
        elif key == "inactive time":
            dest["inactive_ms"] = _first_int(value) or 0
        elif key == "authorized":
            station["authorized"] = value == "yes"
        elif key == "authenticated":
            station["authenticated"] = value == "yes"
        elif key == "mld address" or key == "mld addr":
            station["mld_mac"] = normalise_mac(value)
            station["is_mlo"] = True
        elif key == "beacon interval":
            dest["beacon_interval"] = _first_int(value)

    if station:
        stations.append(station)

    for sta in stations:
        _finalise_station(sta)
    return stations


def _finalise_station(sta: dict[str, Any]) -> None:
    """Aggregate per-link counters up to the MLD level for MLO clients."""
    if not sta.get("links"):
        return
    for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                  "tx_retries", "tx_failed"):
        total = sum(link.get(field, 0) or 0 for link in sta["links"])
        if total:
            sta[field] = total
    rssis = [link["rssi"] for link in sta["links"] if link.get("rssi") is not None]
    if rssis:
        # Report the strongest link as the client's effective signal; per-link
        # values stay available in `links`.
        sta["rssi"] = max(rssis)
    rates = [link.get("tx_rate_mbps") or 0 for link in sta["links"]]
    if any(rates):
        sta["tx_rate_mbps"] = round(sum(rates), 1)
    sta["link_count"] = len(sta["links"])


def _parse_rate_flags(value: str) -> dict[str, Any]:
    """Extract MCS/NSS/width/PHY generation from an `iw` bitrate line."""
    out: dict[str, Any] = {}
    low = value.lower()
    if m := re.search(r"\bmcs (\d+)", low):
        out["mcs"] = int(m.group(1))
    if m := re.search(r"\b(\d+)mhz", low):
        out["width"] = int(m.group(1))
    if m := re.search(r"\bnss (\d+)", low):
        out["nss"] = int(m.group(1))
    for token, phy in (("eht", "EHT"), ("he", "HE"), ("vht", "VHT"), ("ht", "HT")):
        if re.search(rf"\b{token}-mcs|\b{token}\b", low):
            out["phy_mode"] = phy
            break
    return out


def _first_int(value: str) -> int | None:
    m = re.search(r"-?\d+", value)
    return int(m.group()) if m else None


def _first_float(value: str) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(m.group()) if m else None


def survey(iface: str) -> list[dict[str, Any]]:
    """Channel noise and busy time — the input for utilisation metrics."""
    try:
        text = run(["iw", "dev", iface, "survey", "dump"], timeout=15.0)
    except (ToolError, OSError):
        return []
    results: list[dict[str, Any]] = []
    entry: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Survey data from"):
            if entry:
                results.append(entry)
            entry = {"interface": line.split()[-1], "in_use": False}
        elif entry is not None:
            if line == "in use":
                entry["in_use"] = True
            elif line.startswith("frequency:"):
                entry["frequency_mhz"] = _first_int(line)
                entry["in_use"] = entry["in_use"] or "in use" in line
            elif line.startswith("noise:"):
                entry["noise_dbm"] = _first_int(line)
            elif line.startswith("channel active time:"):
                entry["active_ms"] = _first_int(line)
            elif line.startswith("channel busy time:"):
                entry["busy_ms"] = _first_int(line)
            elif line.startswith("channel receive time:"):
                entry["rx_ms"] = _first_int(line)
            elif line.startswith("channel transmit time:"):
                entry["tx_ms"] = _first_int(line)
    if entry:
        results.append(entry)
    for item in results:
        active = item.get("active_ms") or 0
        busy = item.get("busy_ms") or 0
        item["utilisation_percent"] = round(busy / active * 100, 1) if active else None
    return results


def scan(iface: str, *, passive: bool = True) -> list[dict[str, Any]]:
    """Neighbour AP scan. Passive by default so client traffic is not disrupted."""
    return scan_detail(iface, passive=passive)[0]


def scan_detail(iface: str, *, passive: bool = True
                ) -> tuple[list[dict[str, Any]], str | None]:
    """Scan, returning (results, error).

    The error must reach the caller: an empty result and a failed scan are very
    different things, and reporting "no neighbours found" when the interface was
    actually down ("Network is down (-100)") sent the operator looking for an
    RF problem that did not exist.
    """
    argv = ["iw", "dev", iface, "scan"]
    if passive:
        argv.append("passive")
    try:
        text = run(argv, timeout=45.0)
    except (ToolError, OSError) as exc:
        log.info("scan on %s failed: %s", iface, exc)
        return [], f"{iface}: {exc}"

    neighbours: list[dict[str, Any]] = []
    entry: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("BSS "):
            if entry:
                neighbours.append(entry)
            bssid = line.split()[1].split("(")[0]
            entry = {"bssid": normalise_mac(bssid), "ssid": None, "channel": None,
                     "frequency_mhz": None, "rssi": None, "security": "open",
                     "phy_modes": [], "width": None, "utilisation_percent": None}
        elif entry is not None:
            if line.startswith("SSID:"):
                entry["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("freq:"):
                entry["frequency_mhz"] = _first_int(line)
                entry["channel"] = _freq_to_channel(entry["frequency_mhz"])
            elif line.startswith("signal:"):
                entry["rssi"] = _first_int(line)
            elif line.startswith("DS Parameter set: channel"):
                entry["channel"] = _first_int(line)
            elif "RSN:" in line:
                entry["security"] = "wpa2"
            elif "WPA:" in line:
                entry["security"] = "wpa"
            elif "SAE" in line:
                entry["security"] = "wpa3"
            elif "HE capabilities" in line:
                entry["phy_modes"].append("802.11ax")
            elif "EHT capabilities" in line:
                entry["phy_modes"].append("802.11be")
            elif "VHT capabilities" in line:
                entry["phy_modes"].append("802.11ac")
            elif "channel utilisation" in line.lower() or "channel utilization" in line.lower():
                raw_util = _first_int(line)
                if raw_util is not None:
                    entry["utilisation_percent"] = round(raw_util / 255 * 100, 1)
    if entry:
        neighbours.append(entry)
    return neighbours, None


def _freq_to_channel(mhz: int | None) -> int | None:
    if not mhz:
        return None
    if 2412 <= mhz <= 2484:
        return 14 if mhz == 2484 else (mhz - 2407) // 5
    if 5150 <= mhz <= 5895:
        return (mhz - 5000) // 5
    if 5925 <= mhz <= 7125:
        return (mhz - 5950) // 5
    return None


def set_country(country: str) -> bool:
    return run_ok(["iw", "reg", "set", country])


def reg_domain() -> str | None:
    try:
        text = run(["iw", "reg", "get"], timeout=5.0)
    except (ToolError, OSError):
        return None
    if m := re.search(r"country (\w{2})", text):
        return m.group(1)
    return None


# Generic-netlink pieces for the vif radio mask, transplanted from QSDK's
# ucode wifi manager. Its common.uc does
#     wdev_set_radio_mask(name, mask):
#         nl80211.request(NL80211_CMD_SET_INTERFACE, {dev, vif_radio_mask})
# and hostapd calls it through hostapd_ucode_update_radio_mask() before adding
# an MLD link. A standalone hostapd has no ucode VM, so the call is a no-op and
# the vif is left with radio_mask = 0 — on a wiphy that groups several radios
# the driver then has no idea which radio to place the vdev on.
_NETLINK_GENERIC = 16
_NLM_F_REQUEST, _NLM_F_ACK = 0x01, 0x04
_GENL_ID_CTRL = 0x10
_CTRL_CMD_GETFAMILY, _CTRL_ATTR_FAMILY_ID, _CTRL_ATTR_FAMILY_NAME = 3, 1, 2
_NL80211_CMD_SET_INTERFACE = 6
_NL80211_ATTR_IFINDEX = 3
# From the backports header this driver is built against; the mainline uapi
# header in the kernel tree does not define it.
_NL80211_ATTR_VIF_RADIO_MASK = 333


def _nl_attr(kind: int, payload: bytes) -> bytes:
    body = struct.pack("HH", 4 + len(payload), kind) + payload
    return body + b"\x00" * (-len(body) % 4)


def set_vif_radio_mask(ifname: str, mask: int) -> tuple[bool, str]:
    """Tell the driver which radios of a grouped wiphy this vif may use.

    Returns (ok, detail). The interface must be DOWN: cfg80211 rejects the
    change with EBUSY on a running interface.
    """
    try:
        ifindex = socket.if_nametoindex(ifname)
    except OSError as exc:
        return False, f"{ifname}: {exc}"

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_GENERIC)
    try:
        sock.bind((0, 0))
        sock.settimeout(5)

        def send(family: int, cmd: int, payload: bytes, flags: int) -> bytes:
            genl = struct.pack("BBH", cmd, 1, 0) + payload
            msg = struct.pack("IHHII", 16 + len(genl), family, flags, 1,
                              os.getpid()) + genl
            sock.send(msg)
            return sock.recv(8192)

        reply = send(_GENL_ID_CTRL, _CTRL_CMD_GETFAMILY,
                     _nl_attr(_CTRL_ATTR_FAMILY_NAME, b"nl80211\x00"),
                     _NLM_F_REQUEST)
        family = None
        offset = 20
        while offset + 4 <= len(reply):
            length, kind = struct.unpack_from("HH", reply, offset)
            if length < 4:
                break
            if kind == _CTRL_ATTR_FAMILY_ID:
                family = struct.unpack_from("H", reply, offset + 4)[0]
                break
            offset += (length + 3) & ~3
        if family is None:
            return False, "nl80211 generic netlink family not found"

        payload = (_nl_attr(_NL80211_ATTR_IFINDEX, struct.pack("I", ifindex))
                   + _nl_attr(_NL80211_ATTR_VIF_RADIO_MASK,
                              struct.pack("I", mask)))
        reply = send(family, _NL80211_CMD_SET_INTERFACE, payload,
                     _NLM_F_REQUEST | _NLM_F_ACK)
        if struct.unpack_from("H", reply, 4)[0] == 2:      # NLMSG_ERROR
            err = struct.unpack_from("i", reply, 16)[0]
            if err:
                return False, f"{ifname}: {os.strerror(-err)}"
        return True, "ok"
    except OSError as exc:
        return False, f"{ifname}: {exc}"
    finally:
        sock.close()


def add_interface(phy: str, name: str, itype: str = "managed") -> bool:
    """Create a virtual interface on *phy*.

    Used to obtain something scannable on a radio that has no AP BSS yet: the
    channel analyzer must work before the operator has created a single SSID,
    which is precisely when they need it to choose a channel.
    """
    return run_ok(["iw", "phy", phy, "interface", "add", name, "type", itype])


def del_interface(name: str) -> bool:
    return run_ok(["iw", "dev", name, "del"])
