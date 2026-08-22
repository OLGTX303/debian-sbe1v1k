"""RF management: channel analysis and automatic channel selection (spec §23-§25).

Two jobs:

* **Analyse** — combine what the radios can see (neighbour scan), what they
  measure (survey: noise, busy time) and what we ourselves transmit, into a
  per-channel occupancy picture the UI can draw.
* **Decide** — score every permitted channel and pick a better one, respecting
  the spec's explicit constraint: *do not change channels excessively*. A switch
  needs a minimum interval since the last one and a minimum score improvement,
  and is applied with a CSA so clients follow rather than drop.

Nothing here invents measurements. A channel with no survey data reports
`utilisation: null` instead of a plausible-looking number.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from typing import Any

from .adapters import hostapd, nl80211, rtnl
from .util import monotonic, now, read_text, write_atomic

log = logging.getLogger("sbegw.rf")

STATE_DIR = os.environ.get("SBEGW_STATE", "/data/sbegw")
HISTORY_PATH = os.path.join(STATE_DIR, "channel-history.json")

# 6 GHz Preferred Scanning Channels: clients probe these first, so an AP that
# sits on one is found faster.
PSC_CHANNELS = {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229}

# 2.4 GHz has only three non-overlapping 20 MHz channels; anything else is a
# self-inflicted wound in all but the emptiest environments.
NON_OVERLAPPING_2G = (1, 6, 11)

# How many 20 MHz subchannels a width occupies. 240 MHz is 320 with an 80 MHz
# puncture, so it *occupies* a 320 MHz span while using 12 subchannels.
WIDTH_SUBCHANNELS = {20: 1, 40: 2, 80: 4, 160: 8, 240: 12, 320: 16}
WIDTH_SPAN_MHZ = {20: 20, 40: 40, 80: 80, 160: 160, 240: 320, 320: 320}

DEFAULTS = {
    "enabled": False,
    "min_interval_seconds": 6 * 3600,
    "min_improvement": 15.0,
    "avoid_dfs": False,
    "prefer_psc": True,
    "schedule_hour": 4,
}


def channel_to_freq(channel: int, band: str) -> int | None:
    if band == "2g":
        if channel == 14:
            return 2484
        if 1 <= channel <= 13:
            return 2407 + channel * 5
        return None
    if band == "5g":
        return 5000 + channel * 5
    if band == "6g":
        return 5950 + channel * 5
    return None


def band_for_frequency(freq: float | int) -> str | None:
    """Which band a frequency belongs to. 5 GHz and 6 GHz abut at 5925 MHz."""
    if 2400 <= freq <= 2500:
        return "2g"
    if 5100 <= freq < 5925:
        return "5g"
    if 5925 <= freq <= 7125:
        return "6g"
    return None


def freq_to_channel(freq: int) -> int | None:
    if 2412 <= freq <= 2484:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if 5150 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5
    return None


# 5 GHz bonded-channel blocks are not uniformly spaced — UNII-2C ends at 144 and
# UNII-3 restarts at 149, so a block containing channel 149 cannot be derived
# arithmetically from one containing 36. These are the 802.11 tables.
_5G_BLOCKS: dict[int, tuple[tuple[int, ...], ...]] = {
    40: ((36, 40), (44, 48), (52, 56), (60, 64),
         (100, 104), (108, 112), (116, 120), (124, 128),
         (132, 136), (140, 144), (149, 153), (157, 161), (165, 169)),
    80: ((36, 40, 44, 48), (52, 56, 60, 64),
         (100, 104, 108, 112), (116, 120, 124, 128),
         (132, 136, 140, 144), (149, 153, 157, 161)),
    160: ((36, 40, 44, 48, 52, 56, 60, 64),
          (100, 104, 108, 112, 116, 120, 124, 128)),
    # 240/320 MHz on 5 GHz are the QSDK puncturing extension: a 320 MHz span
    # anchored on the 160 MHz blocks, of which 240 uses 12 subchannels.
    240: ((36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112),
          (100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144)),
    320: ((36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128),),
}


def occupied_channels(channel: int, width: int, band: str) -> list[int]:
    """The 20 MHz channel numbers a BSS of this width covers.

    2.4 GHz channels are 5 MHz apart while a 20 MHz signal is ~22 MHz wide, so
    one BSS splatters across several channel numbers — that overlap is the whole
    reason 1/6/11 exists and it has to be modelled, not idealised away.
    """
    if band == "2g":
        spread = 2 if width <= 20 else 4
        return [c for c in range(channel - spread, channel + spread + 1)
                if 1 <= c <= 14]

    if width <= 20:
        return [channel]

    if band == "5g":
        for block in _5G_BLOCKS.get(width, ()):
            if channel in block:
                return list(block)
        # An unknown channel/width pairing covers only itself rather than
        # inventing a block that does not exist in the regulatory tables.
        return [channel]

    # 6 GHz channels are 1, 5, 9 … 233: uniformly spaced, so blocks align.
    count = WIDTH_SUBCHANNELS.get(width, 1)
    index = (channel - 1) // 4
    start_index = (index // count) * count
    return [start_index * 4 + 1 + i * 4 for i in range(count)]


def bonded_channels(channel: int, width: int, band: str) -> list[int]:
    """The channels that must be regulatory-permitted to run this width.

    Distinct from `occupied_channels`, which is the *interference footprint*. On
    2.4 GHz a 20 MHz BSS on channel 1 bleeds into channels 2 and 3, but 2 and 3
    do not need to be separately permitted — only the bonded channels do. Using
    the splatter set for feasibility would make every 2.4 GHz channel look
    illegal.

    Returns an empty list when the channel cannot host the width at all — e.g.
    5 GHz channel 165, which is 20 MHz-only in most regulatory domains. Callers
    must treat that as "not a candidate" rather than falling back to the primary:
    a channel that physically cannot run 80 MHz would otherwise be proposed as an
    80 MHz candidate and, because only one subchannel's interference is counted,
    look like the cleanest option available.
    """
    if band == "2g":
        if width <= 20:
            return [channel]
        return [channel, channel + 4] if channel + 4 <= 14 else []
    if width <= 20:
        return [channel]
    if band == "5g":
        for block in _5G_BLOCKS.get(width, ()):
            if channel in block:
                return list(block)
        return []
    covered = occupied_channels(channel, width, band)
    return covered if channel in covered else []


class ChannelAnalyzer:
    """Builds the per-channel picture and scores candidates."""

    def __init__(self, wifid, events=None, commit_channel=None):
        self.wifid = wifid
        self.events = events
        # Injected by the supervisor: stages a radio's channel through configd and
        # commits it. Used only when hostapd cannot do a CSA.
        self.commit_channel = commit_channel
        self._lock = threading.RLock()
        self._scans: dict[str, dict[str, Any]] = {}   # radio -> {ts, neighbours}
        self._surveys: dict[str, dict[str, Any]] = {}  # radio -> {ts, entries}
        # Last scan error per radio, so the UI can say "the scan failed" rather
        # than showing an empty neighbour list as if the air were clear.
        self._scan_errors: dict[str, str | None] = {}
        self._history: list[dict[str, Any]] = self._load_history()
        self._last_switch: dict[str, float] = {
            entry["radio"]: entry["ts"] for entry in self._history}

    # ------------------------------------------------------------------ history

    def _load_history(self) -> list[dict[str, Any]]:
        try:
            with open(HISTORY_PATH) as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._history.append(entry)
            self._history = self._history[-200:]
            self._last_switch[entry["radio"]] = entry["ts"]
            os.makedirs(STATE_DIR, exist_ok=True)
            write_atomic(HISTORY_PATH, json.dumps(self._history, indent=2))

    def history(self, radio: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = list(reversed(self._history))
        return [i for i in items if radio is None or i["radio"] == radio]

    # -------------------------------------------------------------- collection

    def scan(self, cfg: dict[str, Any], *, radios: list[str] | None = None,
             passive: bool = True) -> dict[str, Any]:
        """Run a neighbour scan and refresh the survey. Caches per radio."""
        plan = self.wifid._plan
        own_bssids = {b.get("bssid") for b in plan["bsses"].values()}
        results: dict[str, Any] = {}

        # Group by phy. On this platform all three radios are pdevs of ONE
        # wiphy, where a single scan already covers every band — scanning per
        # radio would run the same 45-second scan three times and, worse, label
        # neighbours found on other bands with the wrong band.
        # Enumerate from the RADIO REGISTRY, not from the plan. A plan link only
        # exists for a radio that carries an SSID, so on a device with no SSID
        # yet the plan is empty and the analyzer scanned nothing at all — while
        # that is exactly when it is needed, to pick a channel for the first
        # SSID. Plan links are still used when present, for their live BSSes.
        links = dict(plan.get("links") or {})
        for rid, caps in (self.wifid.capabilities().get("radios")
                          or {}).items():
            if rid not in links:
                links[rid] = {"radio": rid, "caps": caps, "config": {},
                              "bsses": []}

        by_phy: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for rid, link in sorted(links.items()):
            if radios and rid not in radios:
                continue
            phy = (link.get("caps") or {}).get("phy") or f"\0{rid}"
            by_phy.setdefault(phy, []).append((rid, link))

        for phy, members in by_phy.items():
            with self._scannable(phy, members) as iface:
                if iface is None:
                    log.info("no scannable interface on %s (%s)", phy,
                             ", ".join(rid for rid, _ in members))
                    continue
                entries, error = nl80211.scan_detail(iface, passive=passive)
                survey = nl80211.survey(iface)
                for rid, link in members:
                    self._scan_one(rid, link, iface, entries, survey,
                                   own_bssids, results, error)
        return results

    @contextlib.contextmanager
    def _scannable(self, phy: str, members: list[tuple[str, dict[str, Any]]]):
        """Yield an interface that can run a scan on this radio.

        An AP BSS is used when one exists. Otherwise a temporary station
        interface is created on the phy and removed afterwards — without this
        the analyzer returned nothing at all until the operator had created an
        SSID, which is exactly backwards: you consult the analyzer to decide
        which channel to put the first SSID on.
        """
        # An AP interface can only scan while it is UP. A BSS stuck in ACS or
        # DFS leaves its netdev down, and scanning on it fails with
        # "Network is down (-100)" — which the analyzer previously reported as
        # simply finding no neighbours.
        for _rid, link in members:
            for bss in link.get("bsses") or []:
                iface = bss.get("interface")
                if not iface:
                    continue
                info = rtnl.link(iface)
                if info is None:
                    continue
                if "UP" in (info.get("flags") or []):
                    yield iface
                    return
                if rtnl.set_up(iface) and "UP" in (
                        (rtnl.link(iface) or {}).get("flags") or []):
                    log.info("brought %s up for scanning", iface)
                    yield iface
                    return
                log.info("%s is down and could not be brought up; using a "
                         "temporary scan interface instead", iface)

        if not phy or phy.startswith("\0"):
            yield None
            return
        # Interface names are capped at 15 characters by the kernel.
        name = f"scan-{phy}"[:15]
        nl80211.del_interface(name)     # clear a leak from an earlier crash
        if not nl80211.add_interface(phy, name, "managed"):
            log.info("could not create a scan interface on %s", phy)
            yield None
            return
        try:
            rtnl.set_up(name)
            info = rtnl.link(name)
            # Reject it only when it demonstrably failed to come up. An
            # unreadable link is inconclusive, so let the scan run and report
            # its own error rather than silently skipping the radio.
            if info is not None and "UP" not in (info.get("flags") or []):
                log.warning("scan interface %s would not come up", name)
                yield None
            else:
                yield name
        finally:
            rtnl.set_up(name, False)
            if not nl80211.del_interface(name):
                log.warning("scan interface %s could not be removed", name)

    def _scan_one(self, rid: str, link: dict[str, Any], iface: str,
                  entries: list[dict[str, Any]], survey: list[dict[str, Any]],
                  own_bssids: set, results: dict[str, Any],
                  error: str | None = None) -> None:
        band = link["caps"].get("band")
        neighbours = []
        for entry in entries:
            if entry.get("bssid") in own_bssids:
                continue
            freq = entry.get("frequency_mhz")
            # Derive each neighbour's band from its own frequency and keep only
            # those actually on this radio's band. Stamping the radio's band on
            # every result put 6 GHz neighbours in the 2.4 GHz analyzer once a
            # single scan started returning all three bands at once.
            entry_band = band_for_frequency(freq) if freq else None
            if entry_band != band:
                continue
            entry = dict(entry)
            entry["radio"] = rid
            entry["band"] = entry_band
            if entry.get("channel") is None and freq:
                entry["channel"] = freq_to_channel(freq)
            entry["width"] = entry.get("width") or 20
            neighbours.append(entry)
        with self._lock:
            self._scans[rid] = {"ts": now(), "neighbours": neighbours}
            # A temporary scan interface reports no channel-time statistics, so
            # keep whatever a real AP BSS measured earlier rather than blanking
            # utilisation figures the operator was already looking at.
            if survey:
                self._surveys[rid] = {"ts": now(), "entries": survey}
        results[rid] = {"neighbours": len(neighbours), "survey": len(survey),
                        "interface": iface, "error": error}
        with self._lock:
            self._scan_errors[rid] = error
        if error:
            log.warning("scan on %s (%s) failed: %s", rid, iface, error)
        else:
            log.info("scan on %s (%s): %d neighbour(s)", rid, iface,
                     len(neighbours))

    def refresh_survey(self, cfg: dict[str, Any]) -> None:
        """Survey is cheap and non-disruptive, unlike a scan; poll it often."""
        plan = self.wifid._plan
        for rid, link in plan["links"].items():
            if not link.get("bsses"):
                continue
            entries = nl80211.survey(link["bsses"][0]["interface"])
            if entries:
                with self._lock:
                    self._surveys[rid] = {"ts": now(), "entries": entries}

    def scan_error(self, radio: str) -> str | None:
        with self._lock:
            return self._scan_errors.get(radio)

    def neighbours(self, radio: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            out = []
            for rid, scan in self._scans.items():
                if radio and rid != radio:
                    continue
                out.extend(scan["neighbours"])
            return out

    def scan_age(self, radio: str) -> float | None:
        with self._lock:
            scan = self._scans.get(radio)
        return (now() - scan["ts"]) if scan else None

    # ---------------------------------------------------------------- analysis

    def analyse(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Per-radio channel occupancy, plus a recommendation for each."""
        caps = self.wifid.capabilities()["radios"]
        plan = self.wifid._plan
        radio_cfg = cfg.get("wifi", {}).get("radios", {})
        settings = {**DEFAULTS, **(cfg.get("wifi", {}).get("channel_optimisation") or {})}

        out: dict[str, Any] = {"radios": [], "settings": settings}

        for rid, cap in sorted(caps.items()):
            band = cap.get("band")
            configured = radio_cfg.get(rid, {})
            link = plan["links"].get(rid, {})
            bsses = link.get("bsses", [])

            runtime = {}
            if bsses:
                ifaces = {i["name"]: i for i in nl80211.interfaces()}
                runtime = ifaces.get(bsses[0]["interface"], {})
            current_channel = runtime.get("channel")
            current_width = runtime.get("width") or configured.get("channel_width") or 20

            neighbours = self.neighbours(rid)
            with self._lock:
                survey = (self._surveys.get(rid) or {}).get("entries", [])
                scan_ts = (self._scans.get(rid) or {}).get("ts")

            survey_by_channel: dict[int, dict[str, Any]] = {}
            for entry in survey:
                channel = freq_to_channel(entry.get("frequency_mhz") or 0)
                if channel is not None:
                    survey_by_channel[channel] = entry

            # Interference weight per 20 MHz channel from neighbouring APs.
            load: dict[int, dict[str, Any]] = {}
            for neighbour in neighbours:
                channel = neighbour.get("channel")
                if channel is None:
                    continue
                for covered in occupied_channels(channel, neighbour.get("width") or 20,
                                                 band):
                    slot = load.setdefault(covered, {"count": 0, "weight": 0.0,
                                                     "strongest": None})
                    slot["count"] += 1
                    rssi = neighbour.get("rssi")
                    if rssi is not None:
                        # A -50 dBm neighbour hurts far more than a -85 dBm one.
                        slot["weight"] += max(0.0, (rssi + 95) / 45.0)
                        if slot["strongest"] is None or rssi > slot["strongest"]:
                            slot["strongest"] = rssi
                    else:
                        slot["weight"] += 0.3

            channels = []
            for detail in cap.get("channel_details", []):
                channel = detail["channel"]
                if detail.get("disabled"):
                    continue
                slot = load.get(channel, {})
                survey_entry = survey_by_channel.get(channel, {})
                channels.append({
                    "channel": channel,
                    "frequency_mhz": detail.get("frequency_mhz"),
                    "dfs": detail.get("dfs", False),
                    "psc": detail.get("psc", False),
                    "no_ir": detail.get("no_ir", False),
                    "neighbour_count": slot.get("count", 0),
                    "interference": round(slot.get("weight", 0.0), 2),
                    "strongest_neighbour_rssi": slot.get("strongest"),
                    "noise_dbm": survey_entry.get("noise_dbm"),
                    "utilisation_percent": survey_entry.get("utilisation_percent"),
                    "in_use": channel in occupied_channels(
                        current_channel, current_width, band) if current_channel else False,
                    "is_current_primary": channel == current_channel,
                })

            recommendation = self.recommend(rid, cap, configured, channels,
                                            current_channel, current_width, settings)

            out["radios"].append({
                "radio": rid,
                "label": cap.get("label"),
                "band": band,
                "current_channel": current_channel,
                "current_width": current_width,
                "configured_channel": configured.get("channel", "auto"),
                "supports_240": bool(cap.get("eht240")),
                "widths": cap.get("widths", []),
                "channels": channels,
                "neighbours": neighbours,
                "own_bsses": [
                    {"ssid": b.get("ssid"), "bssid": b.get("bssid"),
                     "channel": current_channel, "width": current_width,
                     "mld": bool(b.get("mld"))}
                    for b in bsses],
                "scan_ts": scan_ts,
                "scan_age_seconds": (now() - scan_ts) if scan_ts else None,
                "recommendation": recommendation,
                "last_switch_ts": self._last_switch.get(rid),
                "history": self.history(rid)[:10],
            })
        return out

    # ------------------------------------------------------------------ scoring

    def recommend(self, rid: str, cap: dict[str, Any], configured: dict[str, Any],
                  channels: list[dict[str, Any]], current_channel: int | None,
                  current_width: int, settings: dict[str, Any]) -> dict[str, Any]:
        """Score candidate primary channels; higher is better."""
        band = cap.get("band")
        width = configured.get("channel_width") or current_width or 20

        candidates: list[dict[str, Any]] = []
        for entry in channels:
            channel = entry["channel"]
            if entry.get("no_ir"):
                continue  # passive-only channel; cannot start an AP there
            if band == "2g" and channel not in NON_OVERLAPPING_2G:
                continue
            # Feasibility uses the bonded channels; interference uses the wider
            # footprint (which on 2.4 GHz includes adjacent-channel splatter).
            required = bonded_channels(channel, width, band)
            if not required:
                continue  # this channel cannot host the requested width at all
            permitted = {c["channel"] for c in channels}
            if not set(required) <= permitted:
                continue
            covered = occupied_channels(channel, width, band)

            block = [c for c in channels if c["channel"] in covered]
            interference = sum(c["interference"] for c in block)
            neighbour_count = sum(c["neighbour_count"] for c in block)
            utilisations = [c["utilisation_percent"] for c in block
                            if c["utilisation_percent"] is not None]
            noises = [c["noise_dbm"] for c in block if c["noise_dbm"] is not None]
            utilisation = sum(utilisations) / len(utilisations) if utilisations else None
            noise = sum(noises) / len(noises) if noises else None
            has_dfs = any(c["dfs"] for c in block)

            score = 100.0
            score -= min(55.0, interference * 11.0)
            if utilisation is not None:
                score -= min(30.0, utilisation * 0.35)
            if noise is not None:
                # -95 dBm is a clean floor; every dB above it costs.
                score -= max(0.0, (noise + 95)) * 1.2
            if has_dfs:
                # A radar hit forces an evacuation and a CAC wait, so DFS is
                # worth using but never free.
                score -= 25.0 if settings.get("avoid_dfs") else 6.0
            if band == "6g" and settings.get("prefer_psc") and not entry.get("psc"):
                score -= 4.0
            if channel == current_channel:
                # Stickiness: staying put has real value (no CSA, no client
                # churn). Derived from the `current_channel` argument rather than
                # a flag baked into `channels`, so scoring a hypothetical
                # "what if we were on X" is consistent.
                score += 6.0

            candidates.append({
                "channel": channel, "score": round(max(0.0, score), 1),
                "width": width, "interference": round(interference, 2),
                "neighbour_count": neighbour_count,
                "utilisation_percent": round(utilisation, 1) if utilisation is not None else None,
                "noise_dbm": round(noise, 1) if noise is not None else None,
                "dfs": has_dfs, "psc": entry.get("psc", False),
                "covers": covered,
            })

        candidates.sort(key=lambda c: (-c["score"], c["channel"]))
        best = candidates[0] if candidates else None
        # Look the current channel up in the *full* list. Searching a truncated
        # top-N would often miss a badly-scoring current channel, and then every
        # gain would be measured against zero and look enormous.
        current = next((c for c in candidates if c["channel"] == current_channel), None)
        # The full scored list is at most a few dozen entries, so return all of
        # it: truncating here previously hid the current channel from callers and
        # made every comparison against it impossible.

        reasons: list[str] = []
        should_switch = False
        if best is None:
            reasons.append("no permitted channel could be scored")
        elif current_channel is None:
            should_switch = True
            reasons.append("radio has no current channel")
        elif best["channel"] == current_channel:
            reasons.append("already on the best-scoring channel")
        elif current is None:
            # The current channel could not be scored (e.g. it cannot host the
            # configured width), which is itself a reason to move.
            should_switch = True
            reasons.append(
                f"current channel {current_channel} cannot be scored at "
                f"{width} MHz; {best['channel']} can")
        else:
            gain = best["score"] - current["score"]
            interval = settings.get("min_interval_seconds", DEFAULTS["min_interval_seconds"])
            since = now() - self._last_switch.get(rid, 0)
            if gain < settings.get("min_improvement", DEFAULTS["min_improvement"]):
                reasons.append(
                    f"best alternative only scores {gain:+.1f}, below the "
                    f"{settings.get('min_improvement')} threshold")
            elif since < interval:
                remaining = int((interval - since) / 60)
                reasons.append(
                    f"last change was {int(since / 60)} min ago; holding for "
                    f"another {remaining} min to avoid flapping")
            else:
                should_switch = True
                reasons.append(f"channel {best['channel']} scores {gain:+.1f} better")

        return {
            "best": best,
            "current": current,
            "should_switch": should_switch,
            "reasons": reasons,
            "candidates": candidates,
        }

    # ------------------------------------------------------------------ apply

    def optimise(self, cfg: dict[str, Any], *, radios: list[str] | None = None,
                 force: bool = False, dry_run: bool = False,
                 rescan: bool = True) -> dict[str, Any]:
        """Score, then move the radios that should move.

        Returns a per-radio report. `force` bypasses the interval and improvement
        thresholds (used by the manual "optimise now" action); `dry_run` reports
        what would happen without touching anything.
        """
        if rescan:
            self.scan(cfg, radios=radios)
        else:
            self.refresh_survey(cfg)

        analysis = self.analyse(cfg)
        report: list[dict[str, Any]] = []

        for radio in analysis["radios"]:
            rid = radio["radio"]
            if radios and rid not in radios:
                continue
            rec = radio["recommendation"]
            best = rec.get("best")
            entry = {
                "radio": rid, "band": radio["band"],
                "from_channel": radio["current_channel"],
                "to_channel": best["channel"] if best else None,
                "score": best["score"] if best else None,
                "reasons": rec["reasons"], "switched": False, "detail": "",
            }

            if best is None:
                entry["detail"] = "nothing to choose from"
                report.append(entry)
                continue
            if not rec["should_switch"] and not force:
                entry["detail"] = "; ".join(rec["reasons"])
                report.append(entry)
                continue
            if best["channel"] == radio["current_channel"]:
                entry["detail"] = "already on the recommended channel"
                report.append(entry)
                continue
            if dry_run:
                entry["detail"] = "dry run; no change applied"
                report.append(entry)
                continue

            ok, detail = self.apply_channel(cfg, rid, best["channel"],
                                            radio["current_width"])
            entry["switched"] = ok
            entry["detail"] = detail
            if ok:
                self._record({
                    "ts": now(), "radio": rid, "band": radio["band"],
                    "from_channel": radio["current_channel"],
                    "to_channel": best["channel"], "width": radio["current_width"],
                    "score": best["score"], "trigger": "manual" if force else "auto",
                    "reason": "; ".join(rec["reasons"]),
                })
                if self.events:
                    self.events.emit("CHANNEL_CHANGED", subsystem="wifi", data={
                        "radio": rid, "channel": best["channel"],
                        "from": radio["current_channel"],
                        "width": radio["current_width"],
                        "reason": "; ".join(rec["reasons"])})
            report.append(entry)

        return {"radios": report, "settings": analysis["settings"]}

    def apply_channel(self, cfg: dict[str, Any], rid: str, channel: int,
                      width: int) -> tuple[bool, str]:
        """Switch one radio, preferring a CSA so clients are not dropped."""
        plan = self.wifid._plan
        link = plan["links"].get(rid)
        if not link or not link.get("bsses"):
            return False, "radio has no active BSS to switch"
        band = link["caps"].get("band")
        iface = link["bsses"][0]["interface"]

        freq = channel_to_freq(channel, band)
        if freq is None:
            return False, f"cannot map channel {channel} to a frequency on {band}"
        centre = self._centre_freq(channel, width, band)
        if centre is None:
            return False, f"cannot compute a centre frequency for {width} MHz"

        ok, detail = hostapd.channel_switch(
            iface, freq=freq, channel=channel, width=width,
            center_freq1=centre, band=band)
        if ok:
            return True, detail

        # Fall back to a configuration change, which restarts the BSS: clients
        # reconnect instead of following a CSA, so this is strictly second choice
        # and the reason is reported rather than hidden.
        log.warning("CSA unavailable on %s (%s); falling back to reconfigure",
                    rid, detail)
        if self.commit_channel is None:
            return False, (f"CSA unavailable ({detail}) and no configuration "
                           "path is wired up to fall back to")
        try:
            self.commit_channel(rid, channel)
        except Exception as exc:  # noqa: BLE001
            return False, f"CSA unavailable ({detail}); reconfigure failed: {exc}"
        return True, (f"CSA unavailable ({detail}); applied by restarting the BSS "
                      "on the new channel — clients reconnected")

    @staticmethod
    def _centre_freq(channel: int, width: int, band: str) -> int | None:
        """Centre frequency of the width-block containing `channel`."""
        if width <= 20:
            return channel_to_freq(channel, band)
        covered = occupied_channels(channel, width, band)
        if not covered:
            return None
        freqs = [channel_to_freq(c, band) for c in covered]
        freqs = [f for f in freqs if f]
        if not freqs:
            return None
        return int(sum(freqs) / len(freqs))
