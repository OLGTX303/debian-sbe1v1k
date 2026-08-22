"""wifid — owns logical Wi-Fi state: radios, SSIDs, BSSes, MLO/MLD and clients.

Radio identity
--------------
Logical ids (``radio-2g``/``radio-5g``/``radio-6g``) are assigned only after the
capability probe proves the band, and the phy↔id mapping is persisted keyed by the
phy's MAC address. A PCIe re-enumeration that swaps phy0/phy1 therefore does not
move a user's SSID to a different band.

MLO
---
An ``MLD`` is a first-class object binding one SSID to >=2 radio links. wifid
turns each MLD into a set of hostapd *link* configs sharing an ``mld_addr``, and
reports back the real per-link runtime state (channel, width, RSSI, rate,
retries) rather than what was configured — the spec is explicit that
``configured != working``.

Runtime vs desired
------------------
Every radio snapshot carries both ``configured`` and ``runtime`` blocks plus a
``downgrade_reason`` when they disagree (e.g. 320 MHz requested, 160 MHz granted
by the regulatory domain).
"""
from __future__ import annotations

import glob
import json
import logging
import os
import re
import signal
import subprocess
import threading
import time
from typing import Any

from .adapters import hostapd, nl80211, platform, rtnl
from .configd import ApplyResult
from .netd import BRIDGE, WAN_BRIDGE, NetworkManager
from .util import (derive_mac, format_mac, mac_bytes, monotonic, normalise_mac,
                   now, rate, read_text, run_ok, which, write_atomic)

log = logging.getLogger("sbegw.wifid")

STATE_DIR = os.environ.get("SBEGW_STATE", "/data/sbegw")
RADIO_MAP_PATH = os.path.join(STATE_DIR, "radio-map.json")
RUN_DIR = "/run/sbegw/hostapd"
HOSTAPD_PID = os.path.join(RUN_DIR, "hostapd.pid")
# hostapd's own output, captured because -B threw it away. Truncated on every
# start, and hostapd's default verbosity is just interface state transitions
# plus errors, so it stays small on a tmpfs.
HOSTAPD_LOG = os.path.join(RUN_DIR, "hostapd.log")

BAND_LABEL = {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}

# How long a BSS may sit in a non-beaconing state before it is called a failure.
# ACS should finish in a few seconds and a DFS CAC takes 60s (600s on weather
# radar channels), so this is generous enough not to fire on a legitimate CAC
# while still bounding "pending" — a radio stuck in ACS previously stayed
# "pending" forever and the UI never said anything was wrong.
STUCK_TIMEOUT = {"ACS": 120.0, "HT_SCAN": 120.0, "COUNTRY_UPDATE": 60.0,
                 "DFS": 900.0, "UNINITIALIZED": 60.0}
STUCK_TIMEOUT_DEFAULT = 120.0


def _width_from_status(status: dict[str, Any]) -> int | None:
    """Channel width in MHz from a hostapd STATUS block.

    hostapd reports the width as an operating-channel-width enum per PHY
    generation, and only EHT has a value for 320 MHz. 240 MHz shares the
    320 MHz enum and is told apart by the puncturing bitmap.
    """
    eht = str(status.get("eht_oper_chwidth") or "").strip()
    he = str(status.get("he_oper_chwidth") or "").strip()
    vht = str(status.get("vht_oper_chwidth") or "").strip()
    if eht == "9":
        punct = str(status.get("punct_bitmap") or "0").strip()
        try:
            punctured = bin(int(punct, 0)).count("1")
        except ValueError:
            punctured = 0
        return 320 - 20 * punctured if punctured else 320
    for value in (eht, he, vht):
        width = {"1": 80, "2": 160, "3": 80}.get(value)
        if width:
            return width
    # Enum 0 covers both 20 and 40 MHz; secondary_channel tells them apart.
    if eht == "0" or he == "0" or vht == "0":
        secondary = str(status.get("secondary_channel") or "0").strip()
        return 40 if secondary not in ("0", "") else 20
    return None


def _int_or(value: Any, fallback: Any = None) -> Any:
    """int(value) when it looks numeric, else the fallback."""
    text = str(value if value is not None else "").strip()
    return int(text) if text.isdigit() else fallback


class RadioRegistry:
    """Discovers radios and gives them stable logical identities."""

    def __init__(self, events=None):
        self.events = events
        self._caps: dict[str, dict[str, Any]] = {}
        self._map: dict[str, str] = self._load_map()   # mac -> logical id
        self._lock = threading.RLock()

    def _load_map(self) -> dict[str, str]:
        try:
            with open(RADIO_MAP_PATH) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_map(self) -> None:
        """Persist the radio identity map. Never fatal.

        Losing this only costs identity stability across a re-probe, whereas
        raising here aborted radio discovery altogether — so a full or
        read-only /data took the radios down with it.
        """
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            write_atomic(RADIO_MAP_PATH, json.dumps(self._map, indent=2))
        except OSError as exc:
            log.warning("could not persist the radio map to %s: %s",
                        RADIO_MAP_PATH, exc)

    def discover(self, *, force: bool = False) -> dict[str, dict[str, Any]]:
        """Probe every phy and return capabilities keyed by logical radio id."""
        with self._lock:
            if self._caps and not force:
                return dict(self._caps)

            found: dict[str, dict[str, Any]] = {}
            band_counts: dict[str, int] = {}
            for phy in nl80211.phys():
                # One logical radio per BAND, not per phy. ath12k puts every
                # radio of an MLO-capable hardware group behind a single wiphy
                # (see ath12k_mac_allocate: "All pdev get combined and register
                # as single wiphy"), so this box exposes one phy carrying 2.4, 5
                # and 6 GHz. Enumerating phys found one radio and lost two.
                for caps in nl80211.phy_band_capabilities(phy):
                    if not caps.get("raw_available"):
                        log.warning("phy %s did not answer the capability "
                                    "probe; not publishing a logical radio "
                                    "for it", phy)
                        continue
                    band = caps.get("band")
                    if band is None:
                        log.warning("phy %s has a band section with no "
                                    "recognisable frequencies", phy)
                        continue
                    mac = caps.get("mac") or f"phy-{phy}"
                    # The MAC belongs to the wiphy, so it is shared by every
                    # band on it; the identity key must include the band or all
                    # three radios collapse onto one id.
                    key = f"{mac}:{band}"

                    # Reuse a previously assigned id for this hardware.
                    rid = self._map.get(key)
                    if rid is None:
                        # Adopt a pre-band-aware mapping when it is unambiguous.
                        legacy = self._map.get(mac)
                        if legacy and legacy.startswith(f"radio-{band}"):
                            rid = legacy
                    if rid is None or found.get(rid) is not None:
                        index = band_counts.get(band, 0)
                        rid = (f"radio-{band}" if index == 0
                               else f"radio-{band}-{index + 1}")
                    self._map[key] = rid
                    band_counts[band] = band_counts.get(band, 0) + 1
                    self._publish(found, rid, caps, band, phy)

            self._save_map()
            self._caps = found
            return dict(found)

    def _publish(self, found: dict[str, dict[str, Any]], rid: str,
                 caps: dict[str, Any], band: str, phy: str) -> None:

        caps["id"] = rid
        caps["label"] = BAND_LABEL.get(band, band)
        caps["pcie"] = self._pcie_for(phy)
        caps["firmware"] = self._firmware_for(phy)
        found[rid] = caps

    @staticmethod
    def _pcie_for(phy: str) -> dict[str, Any] | None:
        """Correlate a phy to its PCIe slot for the hardware inventory."""
        real = os.path.realpath(f"/sys/class/ieee80211/{phy}")
        for entry in platform.pcie_radios():
            if entry["slot"] in real:
                return entry
        return None

    @staticmethod
    def _firmware_for(phy: str) -> dict[str, Any]:
        """ath12k firmware/board-data identity and crash counters."""
        info: dict[str, Any] = {"version": None, "board": None, "crashes": 0}
        real = os.path.realpath(f"/sys/class/ieee80211/{phy}/device")
        for candidate in glob.glob("/sys/kernel/debug/ath12k/*"):
            if os.path.basename(candidate) in real or real.endswith(
                    os.path.basename(candidate)):
                info["version"] = read_text(
                    os.path.join(candidate, "fw_version"), "").strip() or None
                info["board"] = read_text(
                    os.path.join(candidate, "board_name"), "").strip() or None
                crash = read_text(os.path.join(candidate, "fw_crash_count"), "").strip()
                if crash.isdigit():
                    info["crashes"] = int(crash)
                break
        if info["version"] is None:
            # dmesg carries the firmware string when debugfs is absent.
            for line in read_text("/var/log/kern.log").splitlines()[-4000:]:
                if "ath12k" in line and "fw_version" in line:
                    if m := re.search(r"fw_version\s+(\S+)", line):
                        info["version"] = m.group(1)
        return info

    def capabilities(self) -> dict[str, dict[str, Any]]:
        return self.discover()

    def phy_for(self, rid: str) -> str | None:
        caps = self.discover().get(rid)
        return caps.get("phy") if caps else None


class SlotAllocator:
    """Persistent (radio, wireless-network) -> BSS slot assignment.

    The slot decides both the netdev name and the derived BSSID, so it must not
    depend on iteration order: adding or removing an unrelated SSID would
    otherwise renumber the BSSIDs of every other SSID on that radio and force
    every client to re-associate. Slots are assigned on first sight, persisted,
    and never reused while the SSID still exists.
    """

    def __init__(self, path: str = os.path.join(STATE_DIR, "bss-slots.json")):
        self.path = path
        self._map: dict[str, dict[str, int]] = self._load()
        self._lock = threading.RLock()

    def _load(self) -> dict[str, dict[str, int]]:
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            return {r: {k: int(v) for k, v in s.items()} for r, s in data.items()}
        except (OSError, json.JSONDecodeError, ValueError, AttributeError):
            return {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        write_atomic(self.path, json.dumps(self._map, indent=2, sort_keys=True))

    def slot(self, radio_id: str, wireless_network: str, *, limit: int) -> int | None:
        """Return this SSID's slot on this radio, allocating one if needed."""
        with self._lock:
            slots = self._map.setdefault(radio_id, {})
            if wireless_network in slots:
                return slots[wireless_network] if slots[wireless_network] < limit else None
            used = set(slots.values())
            for candidate in range(limit):
                if candidate not in used:
                    slots[wireless_network] = candidate
                    self._save()
                    return candidate
            return None

    def prune(self, live: dict[str, set[str]]) -> None:
        """Drop assignments for SSIDs or radios that no longer exist."""
        with self._lock:
            changed = False
            for radio_id in list(self._map):
                if radio_id not in live:
                    del self._map[radio_id]
                    changed = True
                    continue
                for wnid in list(self._map[radio_id]):
                    if wnid not in live[radio_id]:
                        del self._map[radio_id][wnid]
                        changed = True
            if changed:
                self._save()


class InterfacePlanner:
    """Assigns netdev names, BSSIDs and MLD addresses deterministically."""

    @staticmethod
    def iface_name(radio_id: str, index: int) -> str:
        """A netdev name <=15 chars, stable for a (radio, ssid-slot) pair."""
        band = radio_id.replace("radio-", "").replace("-", "")
        return f"wl{band}{index}"

    # Upper bound on BSSes per radio, used to keep BSSID derivations from
    # different radios on the same MAC out of each other's range.
    MAX_SLOTS = 16

    @staticmethod
    def bssid(radio_mac: str, index: int, *, radio_ordinal: int = 0) -> str:
        """A stable BSSID for a (radio, slot) pair.

        `radio_ordinal` distinguishes radios that report the SAME MAC. That is
        the normal case here: ath12k registers all three radios behind one
        wiphy, so every band reports the wiphy's address and slot 0 on 2.4, 5
        and 6 GHz would otherwise claim one identical BSSID — three BSSes
        fighting over a single address on a single phy.

        Every BSSID is a derived locally-administered address — the wiphy's own
        MAC is never handed out. The driver's default netdev (wlP1p1s0 here)
        already owns it, and giving slot 0 the same address put two netdevs on
        the box with one MAC, one of them bridged into br-lan.
        """
        return derive_mac(radio_mac, local_bit=True,
                          index=radio_ordinal * InterfacePlanner.MAX_SLOTS + index)

    @staticmethod
    def mld_mac(primary_radio_mac: str, mld_index: int) -> str:
        """MLD MAC must differ from every link BSSID but stay stable."""
        octets = mac_bytes(primary_radio_mac)
        octets[0] |= 0x02
        octets[3] = (octets[3] ^ 0x80) & 0xFF
        octets[5] = (octets[5] + 0x40 + mld_index) & 0xFF
        return format_mac(octets)


class WifiDaemon:
    """Applies wireless configuration and reports real runtime state."""

    def __init__(self, events=None, clients=None):
        self.events = events
        self.clients = clients
        self.radios = RadioRegistry(events)
        self.slots = SlotAllocator()
        self._proc: subprocess.Popen | None = None
        self._logfile = None
        # Restart backoff so a hostapd that cannot start is reported once
        # instead of being relaunched every health tick forever.
        self._hostapd_failures = 0
        self._hostapd_retry_after = 0.0
        self._plan: dict[str, Any] = {"links": {}, "mlds": {}, "bsses": {}}
        self._samples: dict[str, tuple[float, dict[str, int]]] = {}
        self._radio_health: dict[str, str] = {}
        # iface -> when it was first seen in a non-beaconing state.
        self._stuck_since: dict[str, float] = {}
        self._crash_counts: dict[str, int] = {}
        # (netdev, band) -> MLD link control socket, refreshed on a short TTL.
        self._ctrl_map: dict[tuple[str, str], str] = {}
        self._ctrl_map_at = 0.0
        self._last_config_hash: str | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------ capability

    def capabilities(self) -> dict[str, Any]:
        """Published to configd so schema validation can reject impossible asks."""
        radios = self.radios.capabilities()
        hostapd_caps = hostapd.capabilities()
        mlo_hw = any(r.get("mlo") and r.get("eht") for r in radios.values())
        return {
            "radios": radios,
            "hostapd": hostapd_caps,
            "mlo": {
                "supported": bool(mlo_hw and hostapd_caps.get("mlo")),
                "driver_capable": mlo_hw,
                "hostapd_capable": hostapd_caps.get("mlo", False),
                "reason": hostapd_caps.get("reason") or (
                    "" if mlo_hw else
                    "each radio has its own wiphy (ath12k mlo_capable=0). MLO "
                    "needs all links on one wiphy, and in that mode this "
                    "hardware reports '#channels <= 1' — every band would have "
                    "to share a single channel, so concurrent 2.4/5/6 GHz is "
                    "the better trade. Verified on hardware: with the grouped "
                    "wiphy, hostapd's MLD link setup fails in the driver."),
                "eligible_radios": sorted(
                    rid for rid, r in radios.items() if r.get("mlo") and r.get("eht")),
            },
            "ppeds": platform.ppeds_radios(),
        }

    # ---------------------------------------------------------------- planning

    def build_plan(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Turn config into a concrete set of hostapd links + BSSes.

        Returns {"links": {radio_id: {...}}, "mlds": {...}, "bsses": {iface: {...}},
                 "warnings": [...]}
        """
        wifi = cfg.get("wifi", {})
        networks = cfg.get("networks", {})
        radio_caps = self.radios.capabilities()
        warnings: list[str] = []

        # Ordinal of each radio among those sharing its MAC, so BSSIDs stay
        # unique when one wiphy backs several bands. Ordered by band for
        # determinism across reboots and re-probes.
        _BAND_ORDER = {"2g": 0, "5g": 1, "6g": 2}
        radio_ordinals: dict[str, int] = {}
        _seen_macs: dict[str, int] = {}
        for _rid in sorted(radio_caps,
                           key=lambda r: (_BAND_ORDER.get(
                               radio_caps[r].get("band"), 9), r)):
            _mac = normalise_mac(radio_caps[_rid].get("mac")
                                 or "02:00:00:00:00:00")
            radio_ordinals[_rid] = _seen_macs.get(_mac, 0)
            _seen_macs[_mac] = radio_ordinals[_rid] + 1

        # Which SSIDs land on which radio, and which of those are MLD links.
        # slot index per radio keeps netdev names and BSSIDs stable.
        links: dict[str, dict[str, Any]] = {}
        bsses: dict[str, dict[str, Any]] = {}
        mlds: dict[str, dict[str, Any]] = {}

        # Assign MLD addresses first so link configs can reference them.
        mld_by_network: dict[str, dict[str, Any]] = {}

        # An SSID with `mlo` set becomes a multi-link device over exactly the
        # bands it is configured for. This is the model the UI exposes — one
        # checkbox on the wireless network — so the link list can never drift
        # out of step with the band list, which is what happened when an MLD was
        # a separate object the operator maintained by hand. Explicit MLDs in
        # the config are still honoured and take precedence.
        declared = dict(wifi.get("mlds") or {})
        for wnid, wnet in sorted((wifi.get("networks") or {}).items()):
            if not wnet.get("mlo") or not wnet.get("enabled", True):
                continue
            if any(m.get("wireless_network") == wnid for m in declared.values()):
                continue
            want = [rid for rid, caps in sorted(radio_caps.items())
                    if caps.get("band") in (wnet.get("bands") or [])]
            declared[f"mlo-{wnid}"] = {
                "name": f"{wnet.get('ssid', wnid)} MLO",
                "wireless_network": wnid,
                "links": want,
                "enabled": True,
                "link_steering": "auto",
                "derived": True,
            }

        for index, (mid, mld) in enumerate(sorted(declared.items())):
            if not mld.get("enabled", True):
                continue
            link_radios = [r for r in mld.get("links", []) if r in radio_caps]
            if len(link_radios) < 2:
                warnings.append(
                    f"MLD {mid}: fewer than two of its radios are present; "
                    "MLO will not be started")
                continue
            primary_mac = radio_caps[sorted(link_radios)[0]].get("mac")
            if not primary_mac:
                warnings.append(f"MLD {mid}: primary radio has no MAC; skipping")
                continue
            mld_mac = mld.get("mld_mac") or InterfacePlanner.mld_mac(primary_mac, index)
            entry = {
                "id": mid, "name": mld.get("name", mid), "mld_mac": mld_mac,
                "wireless_network": mld["wireless_network"],
                "radios": link_radios, "link_ids": {},
                "link_steering": mld.get("link_steering", "auto"),
                # True when this MLD came from an SSID's `mlo` flag rather than
                # an explicit entry, so the UI can label it accordingly.
                "derived": bool(mld.get("derived")),
            }
            for link_id, rid in enumerate(link_radios):
                entry["link_ids"][rid] = link_id
            mlds[mid] = entry
            mld_by_network.setdefault(mld["wireless_network"], entry)

        # Keep the persisted slot map in step with the configuration before
        # allocating, so a deleted SSID frees its slot for reuse.
        live: dict[str, set[str]] = {}
        for rid, caps in radio_caps.items():
            live[rid] = {
                wnid for wnid, wnet in wifi.get("networks", {}).items()
                if wnet.get("enabled", True)
                and caps.get("band") in wnet.get("bands", [])
            }
        self.slots.prune(live)

        # Now place every enabled SSID on every radio whose band it selects.
        for wnid, wnet in sorted(wifi.get("networks", {}).items()):
            if not wnet.get("enabled", True):
                continue
            net = networks.get(wnet.get("network", "default"), {})
            mld = mld_by_network.get(wnid)

            for rid, caps in sorted(radio_caps.items()):
                if caps.get("band") not in wnet.get("bands", []):
                    continue
                radio_cfg = wifi.get("radios", {}).get(rid, {})
                if not radio_cfg.get("enabled", True):
                    continue
                if not caps.get("ap_supported", True):
                    warnings.append(f"radio {rid} does not support AP mode")
                    continue

                limit = caps.get("max_ap_bss", 8)
                slot = self.slots.slot(rid, wnid, limit=limit)
                if slot is None:
                    warnings.append(
                        f"radio {rid} cannot host more than {limit} BSSes; "
                        f"'{wnid}' was not started")
                    continue

                iface = InterfacePlanner.iface_name(rid, slot)
                bssid = InterfacePlanner.bssid(
                    caps.get("mac") or "02:00:00:00:00:00", slot,
                    radio_ordinal=radio_ordinals.get(rid, 0))
                is_mld_link = bool(mld and rid in mld["radios"])

                security = dict(wnet.get("security", {}))
                security["fast_transition"] = wnet.get("fast_roaming", False)

                bss = {
                    "interface": iface,
                    "radio": rid,
                    "band": caps.get("band"),
                    "wireless_network": wnid,
                    "ssid": wnet["ssid"],
                    "bssid": bssid,
                    "hidden": wnet.get("hidden", False),
                    # An SSID marked uplink=wan is bridged onto the WAN L2
                    # instead of the LAN, so its clients are addressed by the
                    # upstream gateway rather than by us.
                    "bridge": (WAN_BRIDGE if wnet.get("uplink") == "wan"
                               else BRIDGE),
                    "vlan": net.get("vlan"),
                    "network": wnet.get("network", "default"),
                    "client_isolation": wnet.get("client_isolation", False),
                    "max_clients": wnet.get("max_clients"),
                    "min_rssi": wnet.get("min_rssi"),
                    "security": security,
                    "fast_roaming": wnet.get("fast_roaming", False),
                    "bss_transition": wnet.get("bss_transition", True),
                    # Advanced options from the wireless-network form. Only the
                    # ones hostapd actually implements are rendered; the rest are
                    # applied by netd/bridge or reported as unsupported.
                    "proxy_arp": wnet.get("proxy_arp", False),
                    "uapsd": wnet.get("uapsd", False),
                    "auto_dtim": wnet.get("auto_dtim", True),
                    "dtim_period": wnet.get("dtim_period", 2),
                    "group_rekey_interval": wnet.get("group_rekey_interval", False),
                    "group_rekey_seconds": wnet.get("group_rekey_seconds", 3600),
                    "mac_filter": wnet.get("mac_filter", False),
                    "mac_filter_policy": wnet.get("mac_filter_policy", "deny"),
                    "mac_filter_list": wnet.get("mac_filter_list", []),
                    "radius_mac_auth": wnet.get("radius_mac_auth", False),
                    "multicast_broadcast_blocker":
                        wnet.get("multicast_broadcast_blocker", False),
                    "multicast_to_unicast": wnet.get("multicast_to_unicast", False),
                    "minimum_data_rate": wnet.get("minimum_data_rate", False),
                    "neighbor_report": wnet.get("neighbor_report", True),
                    "slot": slot,
                    "mld": None,
                }
                if is_mld_link:
                    bss["mld"] = {
                        "id": mld["id"],
                        "mld_mac": mld["mld_mac"],
                        "link_id": mld["link_ids"][rid],
                    }
                    # Every link of this MLD shares one netdev, named after the
                    # lowest-band participating radio. hostapd identifies an MLD
                    # by its interface name, so the name has to be common; the
                    # single netdev carries the MLD address and one link per
                    # radio hangs off it.
                    bss["netdev"] = InterfacePlanner.iface_name(
                        self._mld_anchor_radio(mld, radio_caps), slot)
                bsses[iface] = bss
                links.setdefault(rid, {"radio": rid, "caps": caps,
                                       "config": radio_cfg, "bsses": []})
                links[rid]["bsses"].append(bss)

        return {"links": links, "mlds": mlds, "bsses": bsses, "warnings": warnings}

    # ----------------------------------------------------------------- apply

    def preflight(self, old: dict[str, Any],
                  new: dict[str, Any]) -> tuple[bool, list[str]]:
        problems: list[str] = []
        wifi = new.get("wifi", {})
        caps = self.capabilities()

        if wifi.get("mlds"):
            enabled = [m for m in wifi["mlds"].values() if m.get("enabled", True)]
            if enabled and not caps["mlo"]["supported"]:
                problems.append(
                    "MLO is configured but not available: "
                    + (caps["mlo"]["reason"] or "hardware or hostapd lacks MLD support"))

        radio_caps = caps["radios"]
        for rid in wifi.get("radios", {}):
            if rid not in radio_caps:
                problems.append(f"configured radio '{rid}' is not present")

        if wifi.get("networks") and not hostapd.capabilities().get("available"):
            problems.append("hostapd is not installed; wireless cannot be started")
        return (not problems), problems

    def __call__(self, old: dict[str, Any], new: dict[str, Any]) -> ApplyResult:
        with self._lock:
            messages: list[str] = []
            try:
                plan = self.build_plan(new)
                messages += plan["warnings"]

                if not plan["links"]:
                    self._stop_hostapd()
                    self._plan = plan
                    return ApplyResult(True, messages + ["no wireless networks enabled"])

                country = new.get("wifi", {}).get("country", "US")
                nl80211.set_country(country)

                configs: dict[str, str] = {}
                for rid, link in sorted(plan["links"].items()):
                    radio_cfg = dict(link["config"])
                    radio_cfg["id"] = rid
                    radio_cfg.setdefault("band", link["caps"].get("band"))
                    regulatory = new.get("wifi", {}).get("regulatory") or {}
                    radio_cfg.setdefault("six_ghz_power",
                                         regulatory.get("six_ghz_power", "lpi"))
                    configs[rid] = hostapd.render_link_config(
                        radio_cfg, link["caps"], link["bsses"], country=country,
                        radius_profiles=new.get("wifi", {}).get("radius", {}),
                        regulatory=regulatory)

                # hostapd does not create its own primary interface: the
                # nl80211 driver expects the netdev to exist already, which is
                # why OpenWrt's wifi scripts run
                #   iw phy <phy> interface add <ifname> type __ap
                # before starting it. Without this hostapd refused every
                # configuration outright.
                messages += self._ensure_ap_interfaces(plan)

                paths, changed = hostapd.write_configs(configs)
                self._plan = plan

                if changed or not self._hostapd_running():
                    ok, msgs = self._start_hostapd(paths)
                    messages += msgs
                    if not ok:
                        return ApplyResult(False, messages)
                    self._hostapd_failures = 0
                    self._hostapd_retry_after = 0.0
                else:
                    messages.append("hostapd configuration unchanged")

                messages += self._post_apply(new, plan)
            except Exception as exc:  # noqa: BLE001
                log.exception("wifid apply failed")
                return ApplyResult(False, messages + [f"wifid: {exc}"])

            mlo_active = sum(1 for b in plan["bsses"].values() if b.get("mld"))
            if mlo_active:
                messages.append(f"{mlo_active} MLO link(s) configured across "
                                f"{len(plan['mlds'])} MLD(s)")
            return ApplyResult(True, messages)

    # AP netdevs we manage: wl<band><slot>, e.g. wl5g0.
    _AP_IFACE_RE = re.compile(r"^wl(?:2g|5g|6g)\d+$")

    @staticmethod
    def _hostapd_reason(binary: str, config_paths: list[str]) -> list[str]:
        """Ask hostapd why it refused, by running it in the foreground.

        hostapd has no config-test mode, so the only way to obtain its own
        diagnosis is a short foreground run with -dd. The daemonised attempt has
        already failed at this point, so nothing is disturbed.
        """
        argv = [binary, "-dd", *config_paths]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=8)
            out = (proc.stderr or "") + (proc.stdout or "")
        except subprocess.TimeoutExpired as exc:
            def decode(value):
                if not value:
                    return ""
                return value if isinstance(value, str) else value.decode(
                    "utf-8", "replace")
            out = decode(exc.stderr) + decode(exc.stdout)
        except OSError as exc:
            return [f"could not run hostapd for diagnosis: {exc}"]

        lines = [l.strip() for l in out.splitlines() if l.strip()]
        # Prefer the lines that name a cause over hostapd's debug firehose.
        keywords = ("could not", "failed", "invalid", "unknown", "error",
                    "not support", "no such", "line ", "unsupported",
                    "refused", "rejected")
        interesting = [l for l in lines if any(k in l.lower() for k in keywords)]
        chosen = interesting[-8:] or lines[-8:]
        return chosen or ["hostapd produced no output at all"]

    @staticmethod
    def _mld_anchor_radio(mld: dict[str, Any],
                          radio_caps: dict[str, Any]) -> str:
        """The radio whose interface name the whole MLD borrows.

        Lowest band first, so the choice is stable regardless of which link
        happens to be planned first and does not move when a link is added.
        """
        order = {"2g": 0, "5g": 1, "6g": 2}
        return sorted(
            mld["radios"],
            key=lambda r: (order.get((radio_caps.get(r) or {}).get("band"), 9), r)
        )[0]

    def _radio_index(self, rid: str | None) -> int | None:
        """Index of a radio within its wiphy, for the vif radio mask.

        Radios are ordered by band, matching how ath12k numbers the pdevs of a
        hardware group. Returns None when the id is unknown.
        """
        if not rid:
            return None
        caps = self.radios.capabilities()
        entry = caps.get(rid)
        if not entry:
            return None
        phy = entry.get("phy")
        order = {"2g": 0, "5g": 1, "6g": 2}
        siblings = sorted(
            (r for r, c in caps.items() if c.get("phy") == phy),
            key=lambda r: (order.get(caps[r].get("band"), 9), r))
        try:
            return siblings.index(rid)
        except ValueError:
            return None

    def _ensure_ap_interfaces(self, plan: dict[str, Any]) -> list[str]:
        """Create/refresh the AP netdevs named in the plan, drop the rest.

        Each is created on its radio's phy and given the planned BSSID while
        down. On this platform all three bands share one phy, so the addresses
        must be distinct or the second interface cannot be brought up.
        """
        messages: list[str] = []
        # Keyed by netdev, not by BSS: the links of an MLD share one netdev, so
        # several BSSes can collapse onto a single entry here. Such a netdev
        # takes the MLD address and a radio mask covering every radio it spans.
        wanted: dict[str, dict[str, Any]] = {}
        for key, bss in (plan.get("bsses") or {}).items():
            name = bss.get("netdev") or bss.get("interface") or key
            mld = bss.get("mld") or {}
            entry = wanted.setdefault(name, {
                "phy": self.radios.phy_for(bss.get("radio")),
                "address": mld.get("mld_mac") or bss.get("bssid"),
                "radios": set(),
            })
            entry["radios"].add(bss.get("radio"))
            if mld.get("mld_mac"):
                entry["address"] = mld["mld_mac"]
            entry["phy"] = entry["phy"] or self.radios.phy_for(bss.get("radio"))

        # Remove AP interfaces we created for a previous config.
        for info in rtnl.links():
            name = info.get("ifname", "")
            if self._AP_IFACE_RE.match(name) and name not in wanted:
                if nl80211.del_interface(name):
                    messages.append(f"removed stale AP interface {name}")

        for iface, spec in sorted(wanted.items()):
            phy, bssid = spec["phy"], spec["address"]
            if not phy:
                messages.append(f"{iface}: no phy for its radio; cannot create")
                continue
            if rtnl.link(iface) is None:
                # __ap is the type OpenWrt uses; plain "ap" is the fallback for
                # iw builds that do not expose the internal name.
                if not nl80211.add_interface(phy, iface, "__ap") and \
                        not nl80211.add_interface(phy, iface, "ap"):
                    messages.append(f"{iface}: could not create on {phy}")
                    continue
                messages.append(f"created {iface} on {phy}")
            # The address can only be changed while the link is down, and
            # hostapd brings it up itself.
            rtnl.set_up(iface, False)
            # On a wiphy that groups several radios, tell the driver which one
            # this vif belongs to. QSDK's ucode manager does this before every
            # MLD link add; without it the vif carries radio_mask = 0. Harmless
            # on a one-radio-per-wiphy layout, where the mask covers the only
            # radio there is.
            # An MLD netdev needs one bit per radio it spans — QSDK's ucode
            # builds the same union incrementally in update_radio_mask()
            # ("radio_mask |= old_mask" when the BSS is an MLO link). A mask
            # with a bit for a radio the wiphy does not have is rejected with
            # EINVAL, so only set bits we resolved.
            mask = 0
            for rid in spec["radios"]:
                index = self._radio_index(rid)
                if index is not None:
                    mask |= 1 << index
            if mask:
                ok, detail = nl80211.set_vif_radio_mask(iface, mask)
                if not ok:
                    log.debug("radio mask for %s: %s", iface, detail)
            if bssid:
                current = (rtnl.link(iface) or {}).get("address", "")
                if current.lower() != bssid.lower():
                    if not rtnl.set_mac(iface, bssid):
                        messages.append(
                            f"{iface}: could not set address {bssid}")
        return messages

    def _post_apply(self, cfg: dict[str, Any], plan: dict[str, Any]) -> list[str]:
        """Work that must happen after the BSSes exist as netdevs."""
        messages: list[str] = []
        deadline = monotonic() + 12.0
        # Netdevs, not BSSes: an MLD's links share one, so waiting on every BSS
        # name would wait forever for netdevs that are never meant to exist.
        wanted = {b.get("netdev") or i for i, b in plan["bsses"].items()}
        while monotonic() < deadline:
            present = {i["name"] for i in nl80211.interfaces()}
            if wanted <= present:
                break
            time.sleep(0.5)
        else:
            missing = wanted - {i["name"] for i in nl80211.interfaces()}
            if missing:
                messages.append(f"interfaces did not appear: {', '.join(sorted(missing))}")

        for iface, bss in plan["bsses"].items():
            iface = bss.get("netdev") or iface
            if rtnl.link(iface) is None:
                continue
            # hostapd puts the BSS in the bridge; the VLAN is applied here so
            # netd stays the single owner of VLAN topology.
            bridge = bss.get("bridge") or BRIDGE
            rtnl.enslave(iface, bridge)
            # Only the LAN bridge is VLAN-filtering; the WAN bridge is a plain
            # L2 segment shared with the upstream, where a PVID of ours would
            # only get in the way.
            if bridge == BRIDGE:
                pvid = bss.get("vlan") or 1
                rtnl.bridge_vlan_add(iface, int(pvid), pvid=True, untagged=True)
            rtnl.set_up(iface)

        # TX power is an nl80211 operation, not a hostapd key.
        for rid, link in plan["links"].items():
            power = link["config"].get("tx_power", "auto")
            first = link["bsses"][0] if link["bsses"] else None
            first_iface = (first.get("netdev") or first["interface"]) if first else None
            if first_iface and power not in (None, "auto"):
                run_ok(["iw", "dev", first_iface, "set", "txpower", "fixed",
                        str(int(power) * 100)])
            elif first_iface:
                run_ok(["iw", "dev", first_iface, "set", "txpower", "auto"])
        return messages

    # -------------------------------------------------------------- hostapd

    def _hostapd_running(self) -> bool:
        if self._proc and self._proc.poll() is None:
            return True
        pid = read_text(HOSTAPD_PID).strip()
        return pid.isdigit() and os.path.exists(f"/proc/{pid}")

    def _start_hostapd(self, config_paths: list[str]) -> tuple[bool, list[str]]:
        """One hostapd process across all links — required for MLO."""
        self._stop_hostapd()
        binary = hostapd.binary()
        if not binary:
            return False, ["hostapd binary not found"]
        os.makedirs(RUN_DIR, exist_ok=True)
        # Run in the FOREGROUND as our own child, with output captured.
        #
        # -B made hostapd detach and log to syslog, so when it exited a moment
        # later there was nothing to read: the health loop just restarted it,
        # forever, and the actual reason never reached anyone. -t adds
        # timestamps; default verbosity is interface state transitions and
        # errors, which is exactly what is needed to tell "AP-ENABLED" from a
        # channel or DFS failure.
        argv = [binary, "-t", *config_paths]
        log.info("starting hostapd: %s", " ".join(argv))
        try:
            logfile = open(HOSTAPD_LOG, "wb", buffering=0)
        except OSError as exc:
            return False, [f"cannot write {HOSTAPD_LOG}: {exc}"]
        try:
            proc = subprocess.Popen(argv, stdout=logfile,
                                    stderr=subprocess.STDOUT,
                                    start_new_session=True)
        except OSError as exc:
            logfile.close()
            return False, [f"hostapd failed to start: {exc}"]
        self._proc = proc
        self._logfile = logfile
        try:
            with open(HOSTAPD_PID, "w") as fh:
                fh.write(f"{proc.pid}\n")
        except OSError:
            pass

        # Wait for it to either settle or die, rather than assuming success.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                tail = self._hostapd_log_tail()
                return False, [f"hostapd exited with status {proc.returncode} "
                               f"shortly after starting:"] + tail
            if self._interfaces_enabled(config_paths):
                break
            time.sleep(0.4)

        if proc.poll() is not None:
            return False, [f"hostapd exited with status {proc.returncode}:"] \
                + self._hostapd_log_tail()

        enabled, pending = self._ap_states()
        if self.events:
            for path in config_paths:
                self.events.emit("SSID_UP", subsystem="wifi",
                                 data={"config": os.path.basename(path)})
        messages = [f"hostapd started with {len(config_paths)} link config(s)"]
        if enabled:
            messages.append("AP enabled on " + ", ".join(sorted(enabled)))
        if pending:
            # Not a failure: DFS channels need a CAC period before beaconing.
            messages.append("not yet beaconing on " + ", ".join(sorted(pending))
                            + " (see " + HOSTAPD_LOG + ")")
        return True, messages

    def _hostapd_log_tail(self, lines: int = 12) -> list[str]:
        """Last few lines of hostapd's own log, for error reporting."""
        try:
            with open(HOSTAPD_LOG, errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            return [f"(could not read {HOSTAPD_LOG}: {exc})"]
        tail = [l.strip() for l in content.splitlines() if l.strip()]
        return tail[-lines:] or ["(hostapd wrote nothing)"]

    @staticmethod
    def _netdev(bss: dict[str, Any]) -> str:
        """The kernel netdev a BSS lives on (shared across an MLD's links)."""
        return bss.get("netdev") or bss.get("interface") or ""

    @staticmethod
    def _band_of_freq(freq: int | None) -> str | None:
        if not freq:
            return None
        if freq < 2500:
            return "2g"
        return "5g" if freq < 5925 else "6g"

    def _link_ctrl_map(self) -> dict[tuple[str, str], str]:
        """{(netdev, band): control-socket name} for MLD links.

        hostapd opens one socket per link, named `<netdev>_link<id>` with ids
        from its own allocator (hostapd_bss_alloc_link_id), so a link is
        identified by the frequency it reports rather than by an id we guessed.
        """
        now = monotonic()
        if self._ctrl_map_at and now - self._ctrl_map_at < 5.0:
            return self._ctrl_map
        out: dict[tuple[str, str], str] = {}
        try:
            names = os.listdir(hostapd.CTRL_DIR)
        except OSError:
            names = []
        for name in names:
            if "_link" not in name:
                continue
            netdev = name.split("_link", 1)[0]
            raw = str(hostapd.status(name).get("freq") or "")
            band = self._band_of_freq(int(raw) if raw.isdigit() else None)
            if band:
                out[(netdev, band)] = name
        self._ctrl_map, self._ctrl_map_at = out, now
        return out

    def _ctrl_name(self, bss: dict[str, Any]) -> str:
        """hostapd control-socket name for a BSS."""
        if not bss.get("mld"):
            return bss.get("interface") or ""
        netdev = self._netdev(bss)
        return self._link_ctrl_map().get(
            (netdev, bss.get("band") or ""), netdev)

    def _ap_states(self) -> tuple[list[str], list[str]]:
        """Interfaces hostapd reports as ENABLED, and those still not up."""
        enabled: list[str] = []
        pending: list[str] = []
        for iface, bss in sorted((self._plan.get("bsses") or {}).items()):
            state = hostapd.interface_state(self._ctrl_name(bss))
            if state == "ENABLED":
                enabled.append(iface)
            else:
                pending.append(f"{iface}({state or 'unknown'})")
        return enabled, pending

    def _interfaces_enabled(self, config_paths: list[str]) -> bool:
        bsses = self._plan.get("bsses") or {}
        if not bsses:
            return True
        return all(hostapd.interface_state(self._ctrl_name(b)) == "ENABLED"
                   for b in bsses.values())

    def _stop_hostapd(self) -> None:
        pid = read_text(HOSTAPD_PID).strip()
        if pid.isdigit() and os.path.exists(f"/proc/{pid}"):
            try:
                os.kill(int(pid), signal.SIGTERM)
                for _ in range(20):
                    if not os.path.exists(f"/proc/{pid}"):
                        break
                    time.sleep(0.2)
                else:
                    os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if getattr(self, "_logfile", None):
            try:
                self._logfile.close()
            except OSError:
                pass
            self._logfile = None

    # --------------------------------------------------------------- runtime

    def radio_states(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """Per-radio desired vs runtime state, with a downgrade reason."""
        wifi = cfg.get("wifi", {})
        radio_caps = self.radios.capabilities()
        ifaces = {i["name"]: i for i in nl80211.interfaces()}
        ppeds = {p["id"]: p for p in platform.ppeds_radios()}
        out: list[dict[str, Any]] = []

        for rid, caps in sorted(radio_caps.items()):
            configured = wifi.get("radios", {}).get(rid, {})
            link = self._plan["links"].get(rid, {})
            bsses = link.get("bsses", [])
            # Runtime state comes from the BSS's own hostapd control socket,
            # not from the netdev named in the plan. An MLD's links share one
            # netdev, so `interface` (wl5g0, wl6g0) is not a netdev at all for
            # them: ifaces.get() returned None and every band except the MLD's
            # anchor reported "down" while all three links were on the air.
            bss0 = bsses[0] if bsses else None
            netdev = self._netdev(bss0) if bss0 else None
            primary = ifaces.get(netdev) if netdev else None
            status = hostapd.status(self._ctrl_name(bss0)) if bss0 else {}

            # hostapd reports this link's own channel; the netdev's chandef is
            # whichever link happens to own it.
            runtime_channel = _int_or(status.get("channel"),
                                      primary.get("channel") if primary else None)
            runtime_freq = _int_or(status.get("freq"),
                                   primary.get("frequency_mhz") if primary else None)
            runtime_width = _width_from_status(status) or (
                primary.get("width") if primary else None)
            desired_width = configured.get("channel_width")
            desired_channel = configured.get("channel", "auto")

            reason = None
            if runtime_width and desired_width and runtime_width < desired_width:
                reason = (f"{desired_width} MHz requested, {runtime_width} MHz in use — "
                          "regulatory domain or DFS/neighbour constraints")
            if desired_channel != "auto" and runtime_channel and \
                    runtime_channel != desired_channel:
                reason = (f"channel {desired_channel} requested, {runtime_channel} "
                          "in use — likely DFS evacuation or ACS override")

            survey = nl80211.survey(netdev) if netdev else []
            # Match the survey entry to THIS link's frequency. With links
            # sharing a netdev, "in_use" alone would hand every band the same
            # figures.
            in_use = next((s for s in survey
                           if runtime_freq and s.get("frequency_mhz") == runtime_freq),
                          next((s for s in survey if s.get("in_use")), {}))

            if not configured.get("enabled", True):
                state = "disabled"
            elif status.get("state") == "ENABLED":
                state = "up"
            elif status.get("state"):
                # Beaconing has not started yet (DFS CAC, country update, ...).
                # That is not "down", and calling it down made a legitimate
                # 60-second CAC look like a failure.
                state = "pending"
            else:
                state = "down"
            health = self._radio_health.get(rid, state)

            out.append({
                "id": rid,
                "label": caps.get("label"),
                "band": caps.get("band"),
                "phy": caps.get("phy"),
                "mac": caps.get("mac"),
                "state": state,
                "health": health,
                "enabled": configured.get("enabled", True),
                "capabilities": {
                    "standards": caps.get("standards", []),
                    "widths": caps.get("widths", []),
                    "channels": caps.get("channels", []),
                    "channel_details": caps.get("channel_details", []),
                    "max_nss": caps.get("max_nss"),
                    "max_tx_power_dbm": caps.get("max_tx_power_dbm"),
                    "he": caps.get("he"), "eht": caps.get("eht"),
                    "mlo": caps.get("mlo"), "dfs": caps.get("dfs"),
                    "afc": caps.get("afc"),
                    "max_ap_bss": caps.get("max_ap_bss"),
                },
                "configured": {
                    "channel": desired_channel,
                    "channel_width": desired_width,
                    "tx_power": configured.get("tx_power", "auto"),
                },
                "runtime": {
                    "channel": runtime_channel,
                    "channel_width": runtime_width,
                    "frequency_mhz": runtime_freq,
                    "tx_power_dbm": primary.get("txpower_dbm") if primary else None,
                    "noise_dbm": in_use.get("noise_dbm"),
                    "utilisation_percent": in_use.get("utilisation_percent"),
                    "eht_active": bool(caps.get("eht")) and any(
                        b.get("mld") for b in bsses),
                },
                "downgrade_reason": reason,
                "bss_count": len(bsses),
                "client_count": self._client_count_for(bsses),
                "firmware": caps.get("firmware", {}),
                "pcie": caps.get("pcie"),
                "ppeds": ppeds.get(rid) or ppeds.get(caps.get("phy") or ""),
                "counters": self._radio_counters(bsses),
            })
        return out

    def _client_count_for(self, bsses: list[dict[str, Any]]) -> int:
        total = 0
        for bss in bsses:
            total += len(nl80211.station_dump(self._netdev(bss)))
        return total

    def _radio_counters(self, bsses: list[dict[str, Any]]) -> dict[str, Any]:
        totals = {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
                  "tx_errors": 0, "rx_dropped": 0}
        for bss in bsses:
            stats = rtnl.stats(self._netdev(bss))
            for key in totals:
                totals[key] += stats.get(key, 0)
        return totals

    def bss_states(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """Per-BSSID state, count and traffic (spec §5)."""
        out = []
        for iface, bss in sorted(self._plan["bsses"].items()):
            status = hostapd.status(self._ctrl_name(bss))
            stations = nl80211.station_dump(self._netdev(bss))
            out.append({
                "interface": iface,
                "bssid": status.get("bssid[0]") or bss.get("bssid"),
                "ssid": status.get("ssid[0]") or bss.get("ssid"),
                "wireless_network": bss.get("wireless_network"),
                "radio": bss.get("radio"),
                "band": bss.get("band"),
                "network": bss.get("network"),
                "vlan": bss.get("vlan"),
                "state": status.get("state", "UNKNOWN"),
                "channel": status.get("channel"),
                "mld": bss.get("mld"),
                "client_count": len(stations),
                "counters": rtnl.stats(self._netdev(bss)),
            })
        return out

    def mld_states(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """MLO runtime: per-link state plus aggregate throughput (spec §6)."""
        out: list[dict[str, Any]] = []
        radio_caps = self.radios.capabilities()
        ifaces = {i["name"]: i for i in nl80211.interfaces()}

        for mid, mld in sorted(self._plan["mlds"].items()):
            links = []
            aggregate = {"rx_bytes": 0, "tx_bytes": 0}
            for rid in mld["radios"]:
                bss = next((b for b in self._plan["bsses"].values()
                            if b.get("radio") == rid
                            and (b.get("mld") or {}).get("id") == mid), None)
                if bss is None:
                    links.append({"radio": rid, "state": "not-configured"})
                    continue
                iface = self._netdev(bss)
                runtime = ifaces.get(iface, {})
                status = hostapd.status(self._ctrl_name(bss))
                stats = rtnl.stats(iface)
                aggregate["rx_bytes"] += stats.get("rx_bytes", 0)
                aggregate["tx_bytes"] += stats.get("tx_bytes", 0)
                stations = nl80211.station_dump(iface)
                retries = sum(s.get("tx_retries", 0) or 0 for s in stations)
                packets = sum(s.get("tx_packets", 0) or 0 for s in stations)
                # Match the survey entry to this link's own frequency: the
                # links share a netdev, so "in_use" would give every link the
                # figures of whichever link owns the chandef.
                link_freq = _int_or(status.get("freq"))
                survey = next((s for s in nl80211.survey(iface)
                               if link_freq and s.get("frequency_mhz") == link_freq),
                              next((s for s in nl80211.survey(iface)
                                    if s.get("in_use")), {}))
                # Per-link channel and width come from the link's own control
                # socket, not from the netdev: the links of an MLD share one
                # netdev, so `iw dev` reports a single channel for all of them
                # and every link but the first read as None.
                links.append({
                    "link_id": _int_or(status.get("link_id"),
                                       bss["mld"]["link_id"]),
                    "radio": rid,
                    "band": radio_caps.get(rid, {}).get("band"),
                    "interface": iface,
                    "link_mac": (status.get("bssid[0]") or bss.get("bssid")
                                 or runtime.get("mac")),
                    "state": status.get("state", "DOWN" if not runtime else "UNKNOWN"),
                    "channel": _int_or(status.get("channel"),
                                       runtime.get("channel")),
                    "channel_width": runtime.get("width"),
                    "noise_dbm": survey.get("noise_dbm"),
                    "utilisation_percent": survey.get("utilisation_percent"),
                    "counters": stats,
                    "retry_percent": round(retries / packets * 100, 1) if packets else 0.0,
                    "client_count": len(stations),
                })

            mlo_clients = [c for c in self.wireless_clients(cfg) if c.get("is_mlo")]
            up_links = [l for l in links if l.get("state") == "ENABLED"]
            out.append({
                "id": mid,
                "name": mld["name"],
                "mld_mac": mld["mld_mac"],
                "wireless_network": mld["wireless_network"],
                "ssid": next((b["ssid"] for b in self._plan["bsses"].values()
                              if (b.get("mld") or {}).get("id") == mid), None),
                "link_steering": mld["link_steering"],
                "state": "up" if len(up_links) >= 2 else (
                    "degraded" if up_links else "down"),
                # Partial MLO must be visible, not averaged away: one failed
                # link (5 GHz stuck in ACS, say) leaves a working-looking MLD
                # that is not delivering the bands the operator asked for.
                "partial": bool(up_links) and len(up_links) < len(links),
                "links_down": [
                    f"{l.get('radio')}({l.get('state')})" for l in links
                    if l.get("state") != "ENABLED"],
                "links": links,
                "link_count": len(links),
                "links_up": len(up_links),
                "aggregate": aggregate,
                "mlo_client_count": len([c for c in mlo_clients
                                         if c.get("mld_ap") == mid]),
            })
        return out

    def wireless_clients(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """Wireless client database with per-link detail for MLO (§28)."""
        out: list[dict[str, Any]] = []
        for iface, bss in sorted(self._plan["bsses"].items()):
            netdev = self._netdev(bss)
            for sta in nl80211.station_dump(netdev):
                info = hostapd.sta_info(self._ctrl_name(bss), sta["mac"])
                band = bss.get("band")
                links = []
                for link in sta.get("links", []):
                    links.append({
                        "link_id": link.get("link_id"),
                        "rssi": link.get("rssi"),
                        "snr": self._snr(link.get("rssi"), iface),
                        "tx_rate_mbps": link.get("tx_rate_mbps"),
                        "rx_rate_mbps": link.get("rx_rate_mbps"),
                        "mcs": link.get("mcs"),
                        "nss": link.get("nss"),
                        "channel_width": link.get("width"),
                        "phy_mode": link.get("phy_mode"),
                        "tx_bytes": link.get("tx_bytes", 0),
                        "rx_bytes": link.get("rx_bytes", 0),
                        "retry_percent": self._retry_percent(link),
                    })
                entry = {
                    "mac": sta["mac"],
                    "interface": iface,
                    "bssid": bss.get("bssid"),
                    "ssid": bss.get("ssid"),
                    "wireless_network": bss.get("wireless_network"),
                    "network": bss.get("network"),
                    "vlan": info.get("vlan_id") or bss.get("vlan"),
                    "radio": bss.get("radio"),
                    "band": band,
                    "channel": None,
                    "security": bss.get("security", {}).get("mode"),
                    "authenticated": sta.get("authenticated", False),
                    "authorized": sta.get("authorized", False),
                    "rssi": sta.get("rssi"),
                    "snr": self._snr(sta.get("rssi"), iface),
                    "tx_rate_mbps": sta.get("tx_rate_mbps"),
                    "rx_rate_mbps": sta.get("rx_rate_mbps"),
                    "tx_bytes": sta.get("tx_bytes", 0),
                    "rx_bytes": sta.get("rx_bytes", 0),
                    "tx_packets": sta.get("tx_packets", 0),
                    "rx_packets": sta.get("rx_packets", 0),
                    "tx_retries": sta.get("tx_retries", 0),
                    "tx_failed": sta.get("tx_failed", 0),
                    "retry_percent": self._retry_percent(sta),
                    "connected_seconds": sta.get("connected_seconds", 0),
                    "mcs": sta.get("mcs"),
                    "nss": sta.get("nss"),
                    "phy_mode": sta.get("phy_mode"),
                    "is_mlo": sta.get("is_mlo", False),
                    "mld_mac": sta.get("mld_mac"),
                    "mld_ap": (bss.get("mld") or {}).get("id"),
                    "links": links,
                    "eht": (sta.get("phy_mode") == "EHT"),
                    "health": None,
                }
                entry["health"] = self._client_health(entry)
                out.append(entry)
        return out

    @staticmethod
    def _retry_percent(stats: dict[str, Any]) -> float:
        packets = stats.get("tx_packets") or 0
        retries = stats.get("tx_retries") or 0
        return round(retries / packets * 100, 1) if packets else 0.0

    @staticmethod
    def _snr(rssi: int | None, iface: str) -> int | None:
        if rssi is None:
            return None
        survey = next((s for s in nl80211.survey(iface) if s.get("in_use")), {})
        noise = survey.get("noise_dbm")
        return rssi - noise if noise is not None else None

    @staticmethod
    def _client_health(client: dict[str, Any]) -> dict[str, Any]:
        """Health from real measurements; the numbers stay exposed alongside."""
        rssi = client.get("rssi")
        retry = client.get("retry_percent") or 0.0
        rate_mbps = client.get("tx_rate_mbps") or 0
        score = 100
        reasons: list[str] = []

        if rssi is None:
            return {"rating": "unknown", "score": None, "reasons": ["no signal data"]}
        if rssi < -78:
            score -= 45
            reasons.append(f"weak signal ({rssi} dBm)")
        elif rssi < -70:
            score -= 25
            reasons.append(f"marginal signal ({rssi} dBm)")
        elif rssi < -64:
            score -= 10
        if retry > 30:
            score -= 30
            reasons.append(f"high retry rate ({retry}%)")
        elif retry > 15:
            score -= 15
            reasons.append(f"elevated retry rate ({retry}%)")
        if rate_mbps and rate_mbps < 50:
            score -= 15
            reasons.append(f"low PHY rate ({rate_mbps} Mbps)")

        score = max(0, score)
        rating = ("excellent" if score >= 85 else "good" if score >= 70
                  else "fair" if score >= 50 else "poor")
        return {"rating": rating, "score": score, "reasons": reasons}

    # ---------------------------------------------------------- client actions

    def disconnect_client(self, mac: str) -> bool:
        mac = normalise_mac(mac)
        for iface in self._plan["bsses"]:
            if hostapd.deauthenticate(iface, mac):
                if self.events:
                    self.events.emit("CLIENT_DISCONNECTED", subsystem="wifi",
                                     data={"client": mac, "reason": "admin action"})
                return True
        return False

    def block_client(self, mac: str) -> bool:
        mac = normalise_mac(mac)
        blocked = False
        for iface in self._plan["bsses"]:
            if hostapd.deny_mac(iface, mac):
                blocked = True
        if blocked:
            self.disconnect_client(mac)
        return blocked

    def unblock_client(self, mac: str) -> bool:
        mac = normalise_mac(mac)
        return any(hostapd.allow_mac(iface, mac) for iface in self._plan["bsses"])

    def steer_client(self, mac: str, target_bssid: str) -> bool:
        """802.11v BSS transition request — band/link steering primitive."""
        mac = normalise_mac(mac)
        for bss in self._plan["bsses"].values():
            netdev = self._netdev(bss)
            if any(s["mac"] == mac for s in nl80211.station_dump(netdev)):
                return hostapd.bss_transition(self._ctrl_name(bss), mac,
                                              normalise_mac(target_bssid))
        return False

    # -------------------------------------------------------------- neighbours

    def scan_neighbours(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        """Passive neighbour scan on one interface per radio."""
        results: list[dict[str, Any]] = []
        own_bssids = {b.get("bssid") for b in self._plan["bsses"].values()}
        own_ssids = {b.get("ssid") for b in self._plan["bsses"].values()}
        for rid, link in sorted(self._plan["links"].items()):
            if not link.get("bsses"):
                continue
            iface = link["bsses"][0]["interface"]
            for entry in nl80211.scan(iface, passive=True):
                if entry["bssid"] in own_bssids:
                    continue
                entry["radio"] = rid
                entry["band"] = link["caps"].get("band")
                # Same SSID from an unknown BSSID is worth flagging, but the spec
                # is explicit: do not call every neighbour malicious.
                entry["classification"] = (
                    "same-ssid-unknown-bssid" if entry.get("ssid") in own_ssids
                    else "neighbour")
                entry["first_seen"] = now()
                results.append(entry)
        return results

    # ------------------------------------------------------- health/recovery

    def poll_health(self, cfg: dict[str, Any]) -> None:
        """Detect firmware crashes and recover the affected radio (spec §46)."""
        caps = self.radios.discover(force=True)
        for rid, radio in caps.items():
            crashes = (radio.get("firmware") or {}).get("crashes", 0)
            previous = self._crash_counts.get(rid)
            self._crash_counts[rid] = crashes
            if previous is not None and crashes > previous:
                self._radio_health[rid] = "recovering"
                if self.events:
                    self.events.emit("RADIO_FW_CRASH", subsystem="wifi",
                                     data={"radio": rid, "crash_count": crashes})
                self.recover_radio(rid, cfg)

        self._check_stuck_bsses()

        if cfg.get("wifi", {}).get("networks") and not self._hostapd_running():
            # Exponential backoff. Restarting on every health tick turned a
            # hostapd that could not start into an endless teardown/rebuild
            # loop: the radios were reinitialised every 15s, no BSS ever
            # reached ENABLED, and the reason scrolled past unread.
            if monotonic() < self._hostapd_retry_after:
                return
            self._hostapd_failures += 1
            delay = min(15.0 * (2 ** (self._hostapd_failures - 1)), 300.0)
            self._hostapd_retry_after = monotonic() + delay
            tail = self._hostapd_log_tail(6)
            log.error("hostapd is not running but wireless is configured "
                      "(attempt %d); retrying, next attempt not before %.0fs. "
                      "Its last output was: %s",
                      self._hostapd_failures, delay, " | ".join(tail))
            if self.events:
                self.events.emit("RADIO_DOWN", subsystem="wifi",
                                 data={"reason": "hostapd not running",
                                       "attempt": self._hostapd_failures,
                                       "hostapd_log": tail},
                                 dedup_key="hostapd-down", dedup_window=60)
            result = self(cfg, cfg)
            if getattr(result, "ok", False) and self._hostapd_running():
                self._hostapd_failures = 0
                self._hostapd_retry_after = 0.0

    def _check_stuck_bsses(self) -> None:
        """Bound how long a BSS may stay non-beaconing.

        A radio whose ACS never completes used to sit in "pending" forever with
        no event and nothing in the UI to say the band was dead. Each BSS now
        gets a per-state deadline; past it, the radio is marked failed and an
        event carries the state it is stuck in.
        """
        if not self._hostapd_running():
            self._stuck_since.clear()
            return
        for iface, bss in sorted((self._plan.get("bsses") or {}).items()):
            state = hostapd.interface_state(self._ctrl_name(bss))
            rid = bss.get("radio")
            if state == "ENABLED":
                if self._stuck_since.pop(iface, None) is not None:
                    self._radio_health[rid] = "up"
                    if self.events:
                        self.events.emit("SSID_UP", subsystem="wifi",
                                         data={"radio": rid, "interface": iface})
                continue
            since = self._stuck_since.get(iface)
            if since is None:
                self._stuck_since[iface] = monotonic()
                continue
            waited = monotonic() - since
            limit = STUCK_TIMEOUT.get(state or "", STUCK_TIMEOUT_DEFAULT)
            if waited < limit:
                continue
            if self._radio_health.get(rid) == "failed":
                continue
            self._radio_health[rid] = "failed"
            log.error("%s (%s) has been stuck in state %s for %.0fs and is not "
                      "beaconing; treating it as failed. hostapd's log: %s",
                      iface, rid, state or "unknown", waited,
                      " | ".join(self._hostapd_log_tail(6)))
            if self.events:
                self.events.emit(
                    "RADIO_DOWN", "error", subsystem="wifi",
                    data={"radio": rid, "interface": iface,
                          "stuck_state": state, "waited_seconds": round(waited),
                          "detail": f"never left {state or 'unknown'}"},
                    dedup_key=f"stuck-{iface}", dedup_window=600)

    def recover_radio(self, rid: str, cfg: dict[str, Any]) -> bool:
        """Quiesce, restart and reapply configuration for one radio.

        A firmware fault on one radio must not require a full reboot. Because
        hostapd owns all links in one process (MLO requirement), recovery
        restarts hostapd and lets the MLD be rebuilt — MLO stale state is
        cleared by removing the interfaces first.
        """
        log.warning("recovering radio %s", rid)
        self._radio_health[rid] = "recovering"
        link = self._plan["links"].get(rid, {})
        for bss in link.get("bsses", []):
            rtnl.set_up(bss["interface"], False)
        self._stop_hostapd()
        # Drop stale AP netdevs so hostapd recreates them cleanly.
        for bss in link.get("bsses", []):
            rtnl.delete_link(bss["interface"])
        time.sleep(1.0)
        self.radios.discover(force=True)
        result = self(cfg, cfg)
        self._radio_health[rid] = "up" if result.ok else "failed"
        if self.events:
            self.events.emit(
                "RADIO_RECOVERED" if result.ok else "RADIO_DOWN",
                subsystem="wifi", data={"radio": rid, "messages": result.messages})
            if result.ok and self._plan["mlds"]:
                self.events.emit("MLO_RECOVERY", subsystem="wifi",
                                 data={"radio": rid})
        return result.ok

    def snapshot(self, cfg: dict[str, Any]) -> dict[str, Any]:
        return {
            "radios": self.radio_states(cfg),
            "bsses": self.bss_states(cfg),
            "mlds": self.mld_states(cfg),
            "clients": self.wireless_clients(cfg),
            "capabilities": self.capabilities(),
            "hostapd_running": self._hostapd_running(),
        }
