"""hostapd adapter: configuration rendering (including MLO) and control socket.

MLO model used here matches hostapd's own: one hostapd process is given one
config file *per link*. Links that belong to the same MLD carry identical
`ssid`/`mld_ap=1`/`mld_addr` and differ in `interface` (hence phy) and
`mld_link_id`. Non-MLO BSSes on the same radio are appended as `bss=` sections
inside their radio's config.

Debian's packaged hostapd (2.10) cannot do this — it has no MLD support at all.
`binary()` therefore prefers the QSDK build installed under /opt/sbegw and
reports MLO as unavailable when only the distro binary is present, so wifid can
refuse to promise MLO it cannot deliver.
"""
from __future__ import annotations

import glob
import logging
import os
import socket
from typing import Any, Iterable

from ..util import ToolError, run, run_ok, which, write_atomic

log = logging.getLogger("sbegw.hostapd")

RUN_DIR = "/run/sbegw/hostapd"
CONF_DIR = "/run/sbegw/hostapd/conf"
CTRL_DIR = "/run/sbegw/hostapd/ctrl"
# The QSDK hostapd binds an async-socket at a compiled-in path that cannot be
# configured; the directory must exist or startup aborts before config parsing.
# tmpfiles.d creates it at boot, but do it here too so a running system that
# lost /run (or an installer that has not rebooted) still works.
HOSTAPD_IF_DIR = "/var/run/hostapd"

# Candidate binaries, most capable first.
BINARY_CANDIDATES = (
    "/opt/sbegw/bin/hostapd",   # QSDK build wrapper (musl loader + libs)
    "/usr/local/sbin/hostapd",
    "/usr/sbin/hostapd",
)


def binary() -> str | None:
    for path in BINARY_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return which("hostapd")


def _has_symbol(path: str, needles: Iterable[bytes]) -> bool:
    """Cheap capability probe: look for config keywords in the binary."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return False
    return all(needle in blob for needle in needles)


def capabilities() -> dict[str, Any]:
    """What the installed hostapd can actually do."""
    path = binary()
    if not path:
        return {"available": False, "path": None, "mlo": False, "eht": False,
                "reason": "no hostapd binary found"}
    real = os.path.realpath(path)
    probe_target = real
    # A wrapper script points at the real ELF; probe that instead.
    if os.path.getsize(real) < 4096:
        for candidate in ("/opt/sbegw/wifi/usr/sbin/hostapd",
                          "/opt/sbegw/wifi/usr/sbin/wpad"):
            if os.path.exists(candidate):
                probe_target = candidate
                break
    mlo = _has_symbol(probe_target, (b"mld_ap", b"mld_addr"))
    eht = _has_symbol(probe_target, (b"ieee80211be",)) or _has_symbol(
        probe_target, (b"eht_oper_chwidth",))
    reason = ""
    if not mlo:
        reason = (f"{probe_target} has no MLD support; install the QSDK hostapd "
                  "(hostapd 2.11+/2025.x) to enable MLO")
    return {"available": True, "path": path, "real_path": probe_target,
            "mlo": mlo, "eht": eht, "reason": reason}


# --------------------------------------------------------------------------
# configuration rendering
# --------------------------------------------------------------------------

def _security_lines(security: dict[str, Any], *, band: str,
                    radius: dict[str, Any] | None,
                    for_mlo: bool) -> list[str]:
    """Translate a security profile into hostapd keys.

    6 GHz and MLO both mandate WPA3/SAE with PMF; those cases are already
    rejected by schema validation, so anything arriving here is legal.
    """
    mode = security.get("mode", "wpa2-wpa3")
    pmf = security.get("pmf", "optional")
    lines: list[str] = []

    if mode == "open":
        if security.get("owe") or band == "6g":
            lines += ["wpa=2", "wpa_key_mgmt=OWE", "rsn_pairwise=CCMP",
                      "ieee80211w=2"]
        else:
            lines.append("wpa=0")
        return lines

    key_mgmt: list[str] = []
    wpa = 2
    if mode == "wpa2":
        key_mgmt = ["WPA-PSK"]
    elif mode == "wpa2-wpa3":
        key_mgmt = ["WPA-PSK", "SAE"]
    elif mode == "wpa3":
        key_mgmt = ["SAE"]
    elif mode == "wpa2-enterprise":
        key_mgmt = ["WPA-EAP"]
    elif mode == "wpa3-enterprise":
        key_mgmt = ["WPA-EAP-SHA256"]

    if security.get("fast_transition"):
        # 802.11r is enabled purely by adding the FT-* AKMs; there is no
        # `ieee80211r` config key in hostapd (that name is OpenWrt's UCI option).
        # The FT names are not "FT-" + AKM: WPA-PSK becomes FT-PSK, not FT-WPA-PSK.
        FT_AKM = {"WPA-PSK": "FT-PSK", "SAE": "FT-SAE", "WPA-EAP": "FT-EAP",
                  "WPA-EAP-SHA256": "FT-EAP"}
        key_mgmt += [FT_AKM[k] for k in key_mgmt if k in FT_AKM]

    lines.append(f"wpa={wpa}")
    lines.append("wpa_key_mgmt=" + " ".join(dict.fromkeys(key_mgmt)))
    # GCMP-256 is required for WPA3 on 6 GHz/EHT paths; CCMP stays for WPA2.
    if mode in ("wpa3", "wpa3-enterprise") or for_mlo or band == "6g":
        lines.append("rsn_pairwise=CCMP GCMP-256")
        lines.append("group_cipher=CCMP")
    else:
        lines.append("rsn_pairwise=CCMP")
    lines.append("wpa_pairwise=CCMP")

    if "PSK" in " ".join(key_mgmt) or "SAE" in key_mgmt:
        passphrase = security.get("passphrase", "")
        if "SAE" in key_mgmt:
            lines.append(f"sae_password={passphrase}")
            lines.append("sae_require_mfp=1")
            # H2E is mandatory on 6 GHz and desirable everywhere else.
            lines.append("sae_pwe=2" if band != "6g" else "sae_pwe=1")
        if "WPA-PSK" in key_mgmt:
            lines.append(f"wpa_passphrase={passphrase}")

    if "EAP" in " ".join(key_mgmt) and radius:
        lines.append("ieee8021x=1")
        lines.append(f"auth_server_addr={radius.get('auth_server')}")
        lines.append(f"auth_server_port={radius.get('auth_port', 1812)}")
        lines.append(f"auth_server_shared_secret={radius.get('auth_secret', '')}")
        if radius.get("auth_server2"):
            lines.append(f"auth_server_addr={radius['auth_server2']}")
            lines.append(f"auth_server_port={radius.get('auth_port2', 1812)}")
            lines.append(f"auth_server_shared_secret={radius.get('auth_secret2', '')}")
        if radius.get("acct_server"):
            lines.append(f"acct_server_addr={radius['acct_server']}")
            lines.append(f"acct_server_port={radius.get('acct_port', 1813)}")
            lines.append(f"acct_server_shared_secret={radius.get('acct_secret', '')}")
            lines.append("radius_acct_interim_interval="
                         f"{radius.get('interim_interval', 600)}")
        if radius.get("nas_identifier"):
            lines.append(f"nas_identifier={radius['nas_identifier']}")
        if radius.get("dynamic_vlan"):
            lines += ["dynamic_vlan=1", "vlan_naming=1"]
        if radius.get("coa_secret"):
            # RADIUS CoA/Disconnect: the shared secret is the second field of
            # radius_das_client. There is no separate secret key.
            lines.append("radius_das_port=3799")
            lines.append(f"radius_das_client={radius.get('coa_client', '0.0.0.0/0')} "
                         f"{radius['coa_secret']}")
            lines.append("radius_das_require_event_timestamp=1")

    pmf_value = {"disabled": "0", "optional": "1", "required": "2"}[pmf]
    lines.append(f"ieee80211w={pmf_value}")
    # sae_require_mfp is already emitted with the SAE keys above; PMF-required
    # without SAE needs no extra key beyond ieee80211w=2.
    return lines


# Preferred starting channels per band, in order. These are the conventional
# anchors: 1/6/11 are the only non-overlapping 2.4 GHz channels, 36 and 149 are
# the non-DFS 5 GHz block starts, and 6 GHz 37 is a PSC that also anchors wide
# channels.
CHANNEL_PREFERENCE = {
    "2g": (6, 1, 11),
    "5g": (36, 149, 44, 157),
    "6g": (37, 1, 5, 53),
}


def default_channel(band: str, caps: dict[str, Any], width: int = 20) -> int:
    """A concrete, usable channel for a radio configured as "auto".

    Prefers a conventional anchor that the driver reports as enabled and not
    radar- or no-IR-restricted, so the AP can start beaconing immediately
    instead of waiting on a channel availability check.
    """
    if band == "5g" and width == 240:
        # 240 MHz only exists on one span; its primary must sit in it.
        return EHT240_5G["primary"]
    details = caps.get("channel_details") or []
    usable = {d["channel"] for d in details
              if not d.get("disabled") and not d.get("no_ir")
              and not d.get("dfs")}
    if not usable:
        # No non-DFS channel at all: fall back to any enabled one and accept the
        # CAC wait rather than refusing to start.
        usable = {d["channel"] for d in details if not d.get("disabled")}
    for candidate in CHANNEL_PREFERENCE.get(band, ()):
        if candidate in usable:
            return candidate
    if usable:
        return min(usable)
    # Nothing was reported; use the band's canonical first channel.
    return {"2g": 6, "5g": 36, "6g": 37}.get(band, 6)


# 5 GHz bonded blocks, mirroring rf._5G_BLOCKS. Duplicated deliberately:
# importing rf here would be circular (rf imports this module), and the pair is
# kept honest by a test that asserts they agree.
_SEG0_5G_BLOCKS = {
    80: ((36, 48), (52, 64), (100, 112), (116, 128), (132, 144), (149, 161)),
    160: ((36, 64), (100, 128)),
    240: ((36, 112), (100, 144)),
    320: ((36, 128),),
}


# Regulatory environment, as the third octet of the 802.11 country string.
# 0x20 "all environments", 0x49 indoor only, 0x4f outdoor only.
COUNTRY3 = {"any": 0x20, "indoor": 0x49, "outdoor": 0x4F}

# 6 GHz regulatory power type (hostapd he_6ghz_reg_pwr_type):
#   0 Low Power Indoor    indoor only, the safe default
#   1 Standard Power      outdoor-permitted; this board's own regulatory table
#                         exposes 36 dBm on 5925-6425 and 6525-6875 without the
#                         NO-OUTDOOR flag, against 30 dBm for LPI. In the US,
#                         standard power legally requires AFC coordination.
#   2 Very Low Power      portable/outdoor, lowest limit
SIX_GHZ_POWER = {"lpi": 0, "sp": 1, "vlp": 2}

# 6 GHz global operating classes (802.11 Annex E, Table E-4). On 6 GHz the
# operating class carries the channel width, so this is not cosmetic.
# 240 MHz has no class of its own: it is the 320 MHz class with one 80 MHz
# block punctured, exactly as on 5 GHz.
SIX_GHZ_OP_CLASS = {20: 131, 40: 132, 80: 133, 160: 134, 240: 137, 320: 137}


# 5 GHz 240 MHz, measured on the hardware.
#
# 240 MHz is twelve contiguous 20 MHz channels, and the only such span on 5 GHz
# is 100-144 (UNII-2C, 5490-5730). It is expressed to hostapd as a 320 MHz EHT
# operation over 100..160 with the top 80 MHz punctured — the driver reports
# "width: 320 MHz, center1: 5650" and bitmap 0xf000, i.e. 240 MHz on the air.
#
# Every other shape was rejected: anchoring at 36 makes the 320 MHz span reach
# into UNII-2B, which is not permitted here, and a centre index that is not the
# centre of a real 320 MHz block sends hostapd down its 6 GHz path ("No 6 GHz
# mode"). The whole span is DFS, so bringing it up costs a 60 s CAC.
EHT240_5G = {
    "channels": tuple(range(100, 148, 4)),   # 100 … 144
    "primary": 100,
    "eht_centre": 130,       # centre of the 320 MHz span 100..160
    "he_centre": 114,        # centre of the 160 MHz block 100..128
    "punct_bitmap": 0xF000,  # puncture 148/152/156/160
}


def centre_channel(channel: int, width: int, band: str) -> int | None:
    """The 80/160/320 MHz segment-0 centre channel for a primary channel.

    hostapd will not start an 80 MHz-or-wider BSS without this: it needs
    vht_/he_/eht_oper_centr_freq_seg0_idx, and omitting them failed interface
    setup outright ("Interface initialization failed" straight after
    COUNTRY_UPDATE) — which is why 5 GHz never came up while 20/40 MHz did.
    Returns None for widths that do not use a centre index.
    """
    if width < 80:
        return None
    if band == "2g":
        return None
    if band == "5g":
        for low, high in _SEG0_5G_BLOCKS.get(width, ()):
            if low <= channel <= high:
                return (low + high) // 2
        return None
    # 6 GHz channels are 1, 5, 9 ... spaced uniformly, so the block containing
    # the primary is found arithmetically.
    count = {80: 4, 160: 8, 320: 16}.get(width)
    if not count:
        return None
    index = (channel - 1) // 4
    start = (index // count) * count * 4 + 1
    return start + (count - 1) * 2


def _band_lines(radio: dict[str, Any], caps: dict[str, Any]) -> list[str]:
    """hw_mode / channel / width lines for one radio."""
    band = radio.get("band", "5g")
    width = int(radio.get("channel_width", 20))
    channel = radio.get("channel", "auto")
    lines: list[str] = []

    if band == "2g":
        lines.append("hw_mode=g")
    else:
        lines.append("hw_mode=a")
    if band == "6g":
        # 6 GHz operates HE/EHT only: no HT/VHT operation elements exist there,
        # and hostapd needs the operating class to pick the right 6 GHz rules.
        #
        # The operating class *is* the bandwidth on 6 GHz — hostapd derives the
        # width from it rather than from eht_oper_chwidth. A hardcoded 131 (the
        # 20 MHz class) therefore pinned every 6 GHz radio to 20 MHz no matter
        # what width was configured: the config said eht_oper_chwidth=9 and
        # STATUS came back eht_oper_chwidth=0.
        lines.append(f"op_class={SIX_GHZ_OP_CLASS.get(width, 131)}")
        power = radio.get("six_ghz_power", "lpi")
        lines.append(f"he_6ghz_reg_pwr_type={SIX_GHZ_POWER.get(power, 0)}")

    if channel in ("auto", None, 0, "0"):
        # Pick the channel ourselves rather than using hostapd ACS.
        #
        # ACS never completes on this driver: every radio sat in state ACS
        # indefinitely and never beaconed, and with MLO it was fatal — hostapd
        # could not bring the second link up while the first was still scanning
        # ("Could not set interface wl5g0 flags (UP)"), so the whole MLD was
        # torn down. A deterministic channel gets the radios on the air; the
        # channel analyzer can still move them later with a CSA, which is a
        # safer mechanism than a blocking scan at start-up.
        channel = default_channel(band, caps, width)
        lines.append(f"# channel chosen by the gateway (hostapd ACS does not "
                     f"complete on this driver)")
    lines.append(f"channel={channel}")
    # Every PHY generation that is enabled needs its own centre index, and the
    # index must describe the width THAT generation advertises — not the width
    # the operator asked for. VHT/HE have no 320 MHz enum value, so at 240 or
    # 320 MHz they advertise 160 and need the 160 MHz centre, while EHT carries
    # the real 320 MHz and needs the 320 MHz centre. Emitting one shared index
    # gave HE an impossible 160 MHz centre and EHT the wrong 320 MHz one, and
    # hostapd refused the interface.
    if band == "5g" and width == 240:
        seg0_he = EHT240_5G["he_centre"]
        seg0_eht = EHT240_5G["eht_centre"]
    else:
        seg0_he = centre_channel(int(channel), min(width, 160), band)
        seg0_eht = centre_channel(int(channel),
                                  320 if width in (240, 320) else width, band)

    if band != "6g":
        if caps.get("ht"):
            lines.append("ieee80211n=1")
            lines.append("ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]"
                         if width >= 40 else "ht_capab=[SHORT-GI-20]")
            if width >= 40:
                # Skip the 20/40 coexistence scan.
                #
                # On 2.4 GHz it downgrades to 20 MHz whenever it sees an
                # overlapping 20 MHz BSS, which is nearly always — measured on
                # hardware: HT40 alone came up at 20 MHz, HT40 with noscan came
                # up at 40 MHz. Asking for 40 MHz is an explicit choice, so
                # honour it; the operator is warned that coexistence detection
                # is skipped.
                #
                # On 5/6 GHz the scan is not even a spec requirement, and this
                # driver cannot run it: HT_SCAN ends in "Failed to request a
                # scan of neighboring BSSes ret=-22 (Invalid argument)" and the
                # interface goes straight to DISABLED. Same root cause as ACS
                # never completing here.
                lines.append("noscan=1")
        if caps.get("vht") and band != "2g":
            lines.append("ieee80211ac=1")
            lines.append(f"vht_oper_chwidth={_he_chwidth(width)}")
            if seg0_he is not None:
                lines.append(f"vht_oper_centr_freq_seg0_idx={seg0_he}")
    if caps.get("he"):
        lines.append("ieee80211ax=1")
        if band != "2g":
            # HE tops out at 160 MHz; 320 MHz is expressed by EHT alone.
            lines.append(f"he_oper_chwidth={_he_chwidth(width)}")
            if seg0_he is not None:
                lines.append(f"he_oper_centr_freq_seg0_idx={seg0_he}")
        lines.append("he_su_beamformer=1")
        lines.append("he_su_beamformee=1")
        lines.append("he_mu_beamformer=1")
        if radio.get("bss_color") is not None:
            lines.append(f"he_bss_color={radio['bss_color']}")
    if caps.get("eht"):
        lines.append("ieee80211be=1")
        if band != "2g":
            lines.append(f"eht_oper_chwidth={_eht_chwidth(width)}")
            if seg0_eht is not None:
                lines.append(f"eht_oper_centr_freq_seg0_idx={seg0_eht}")
        lines.append("eht_su_beamformer=1")
        lines.append("eht_su_beamformee=1")
        if width == 240:
            # 240 MHz is a 320 MHz EHT span with one 80 MHz block punctured.
            # The puncture must be explicit: punct_acs_threshold only works with
            # ACS, which this driver cannot complete, and leaving it out made
            # hostapd try a full 320 MHz span that the regulatory domain does
            # not permit (it aborted right after DFS-CAC-START, bitmap:0x0000).
            bitmap = radio.get("punct_bitmap", "auto")
            if bitmap in (None, "auto"):
                bitmap = EHT240_5G["punct_bitmap"]
            lines.append(f"punct_bitmap=0x{int(bitmap):04X}")
        elif radio.get("punct_bitmap") not in (None, "auto"):
            lines.append(f"punct_bitmap={int(radio['punct_bitmap'])}")

    if radio.get("tx_power") not in (None, "auto"):
        # hostapd has no direct TX power key; the value is applied via iw by
        # wifid after the BSS is up. Recorded here for traceability.
        lines.append(f"# tx_power={radio['tx_power']} dBm applied via nl80211")

    # ieee80211d is set once in the header; 802.11h (DFS/TPC) is band-specific.
    if band == "5g" and radio.get("dfs", True):
        lines.append("ieee80211h=1")
    if radio.get("beacon_interval"):
        lines.append(f"beacon_int={radio['beacon_interval']}")
    if radio.get("dtim"):
        lines.append(f"dtim_period={radio['dtim']}")
    if radio.get("rts_threshold"):
        lines.append(f"rts_threshold={radio['rts_threshold']}")
    return lines


def _he_chwidth(width: int) -> int:
    """vht_oper_chwidth / he_oper_chwidth: 0=20/40, 1=80, 2=160, 3=80+80.

    There is no 320 MHz value in this enum, so a 320 or 240 MHz radio advertises
    160 here and lets eht_oper_chwidth carry the real width.
    """
    return {20: 0, 40: 0, 80: 1, 160: 2, 240: 2, 320: 2}.get(width, 0)


def _eht_chwidth(width: int) -> int:
    """eht_oper_chwidth: same as the HE enum, plus 9 for 320 MHz.

    240 MHz has no enum value of its own — it *is* 320 MHz operation with an
    80 MHz puncture, so it reports 9 and carries a puncturing bitmap.
    """
    return {20: 0, 40: 0, 80: 1, 160: 2, 240: 9, 320: 9}.get(width, 0)


def _bss_lines(bss: dict[str, Any], radio: dict[str, Any], caps: dict[str, Any],
               *, radius: dict[str, Any] | None, is_first: bool) -> list[str]:
    """Lines describing one BSS (SSID) on a radio."""
    lines: list[str] = []
    keyword = "interface" if is_first else "bss"
    # All links of an AP MLD must name the *same* netdev. hostapd groups links
    # into an MLD by `os_strcmp(conf->iface, mld->name)` (hostapd.c
    # hostapd_bss_setup_multi_link) — the interface name *is* the MLD's
    # identity. Give the links different names and each one becomes its own
    # single-link MLD, whereupon the second tries to create its own netdev and
    # dies with ENFILE ("name already in use") or, if absent, fails driver init.
    lines.append(f"{keyword}={bss.get('netdev') or bss['interface']}")
    lines.append(f"ctrl_interface={CTRL_DIR}")
    if bss.get("bssid"):
        lines.append(f"bssid={bss['bssid']}")
    lines.append(f"ssid={bss['ssid']}")
    lines.append(f"ignore_broadcast_ssid={1 if bss.get('hidden') else 0}")
    if bss.get("bridge"):
        lines.append(f"bridge={bss['bridge']}")
    if bss.get("vlan"):
        # Tag the BSS into its network's VLAN via the bridge, not a per-BSS
        # hostapd VLAN interface, so netd remains the owner of VLAN topology.
        lines.append(f"vlan_tagged_interface={bss['vlan_parent']}") if bss.get(
            "vlan_parent") else None
    lines.append(f"ap_isolate={1 if bss.get('client_isolation') else 0}")
    if bss.get("max_clients"):
        lines.append(f"max_num_sta={bss['max_clients']}")
    if bss.get("min_rssi") is not None:
        # hostapd expects a signal threshold in dBm for association rejection.
        lines.append(f"rssi_reject_assoc_rssi={bss['min_rssi']}")
        lines.append("rssi_reject_assoc_timeout=5")

    lines += _security_lines(bss.get("security", {}), band=radio.get("band", "5g"),
                             radius=radius, for_mlo=bool(bss.get("mld")))

    # 802.11k/v/r
    if bss.get("neighbor_report", True):
        lines += ["rrm_neighbor_report=1", "rrm_beacon_report=1"]
    if bss.get("bss_transition", True):
        lines.append("bss_transition=1")
    if bss.get("fast_roaming"):
        # The FT AKMs are added in _security_lines; these are the FT parameters.
        lines.append(f"mobility_domain={bss.get('mobility_domain', '1234')}")
        lines.append("ft_over_ds=0")
        lines.append("pmk_r1_push=1")
        lines.append("ft_psk_generate_local=1")
        lines.append("r0_key_lifetime=600")
        # FT needs a NAS identifier; an enterprise RADIUS profile already set one.
        if not bss.get("security", {}).get("radius_profile"):
            lines.append("nas_identifier="
                         + (bss.get("bssid") or "sbe1v1k").replace(":", ""))
    if bss.get("wmm", True):
        lines.append("wmm_enabled=1")
    if bss.get("multicast_to_unicast"):
        lines.append("multicast_to_unicast=1")
    if bss.get("proxy_arp"):
        # proxy_arp only turns on DHCP/NDisc snooping (see hostapd.c). It does
        # NOT require ap_isolate, and appending one here emitted a second
        # ap_isolate= that overrode the operator's Client Device Isolation
        # choice — enabling Proxy ARP silently isolated every client.
        lines.append("proxy_arp=1")
    if bss.get("uapsd"):
        lines.append("uapsd_advertisement_enabled=1")
    if not bss.get("auto_dtim", True):
        lines.append(f"dtim_period={bss.get('dtim_period', 2)}")
    if bss.get("group_rekey_interval"):
        lines.append(f"wpa_group_rekey={bss.get('group_rekey_seconds', 3600)}")
    if bss.get("multicast_broadcast_blocker"):
        # DGAF is exactly "downstream group-addressed forwarding": disabling it
        # stops the AP relaying multicast/broadcast to clients.
        lines.append("disable_dgaf=1")
    if bss.get("radius_mac_auth"):
        # 2 = use RADIUS to authorise unlisted MACs.
        lines.append("macaddr_acl=2")
    elif bss.get("mac_filter") and bss.get("mac_filter_file"):
        allow = bss.get("mac_filter_policy") == "allow"
        lines.append(f"macaddr_acl={1 if allow else 0}")
        lines.append(f"{'accept' if allow else 'deny'}_mac_file="
                     f"{bss['mac_filter_file']}")

    # --- MLO: this is what makes the BSS a link of an MLD.
    mld = bss.get("mld")
    if mld:
        lines.append("mld_ap=1")
        lines.append(f"mld_addr={mld['mld_mac']}")
        # No mld_link_id: hostapd_bss_alloc_link_id() takes the next free id
        # from the MLD's own bitmap, and the vendor's config generator
        # (wifi-scripts mac80211.sh) writes only mld_ap and mld_addr. Forcing
        # an id here fights that allocator.
    return lines


def render_link_config(radio: dict[str, Any], caps: dict[str, Any],
                       bsses: list[dict[str, Any]], *,
                       country: str,
                       radius_profiles: dict[str, Any] | None = None,
                       regulatory: dict[str, Any] | None = None) -> str:
    """Render one hostapd config file covering a single radio (one MLO link)."""
    radius_profiles = radius_profiles or {}
    regulatory = regulatory or {}
    environment = regulatory.get("environment", "indoor")
    lines = [
        f"# generated by sbegw wifid for radio {radio.get('id')} "
        f"({radio.get('band')}) — do not edit",
        "driver=nl80211",
        f"country_code={country}",
        # The environment octet tells clients which rule set applies. It does
        # not itself raise power; on 6 GHz the power *type* below is what moves
        # the limit, and on 5 GHz the limit follows the sub-band.
        f"country3=0x{COUNTRY3.get(environment, 0x49):02X}",
        "ieee80211d=1",
        "logger_syslog=-1",
        "logger_syslog_level=3",
        "logger_stdout=-1",
        "logger_stdout_level=2",
    ]
    lines += _band_lines(radio, caps)

    for index, bss in enumerate(bsses):
        lines.append("")
        radius = radius_profiles.get(
            bss.get("security", {}).get("radius_profile") or "")
        lines += _bss_lines(bss, radio, caps, radius=radius, is_first=index == 0)
    return "\n".join(l for l in lines if l is not None) + "\n"


def write_configs(configs: dict[str, str]) -> tuple[list[str], bool]:
    """Write per-link config files. Returns (paths in link order, changed)."""
    os.makedirs(CONF_DIR, exist_ok=True)
    os.makedirs(CTRL_DIR, exist_ok=True)
    try:
        os.makedirs(HOSTAPD_IF_DIR, exist_ok=True)
    except OSError as exc:
        log.warning("could not create %s; hostapd's async socket will fail "
                    "to bind: %s", HOSTAPD_IF_DIR, exc)
    changed = False
    paths: list[str] = []
    for name, body in configs.items():
        path = os.path.join(CONF_DIR, f"{name}.conf")
        if write_atomic(path, body, mode=0o600):
            changed = True
        paths.append(path)
    # Remove configs for radios that no longer exist.
    for stale in glob.glob(os.path.join(CONF_DIR, "*.conf")):
        if stale not in paths:
            os.unlink(stale)
            changed = True
    return paths, changed


# --------------------------------------------------------------------------
# control interface
# --------------------------------------------------------------------------

class CtrlError(RuntimeError):
    pass


def _ctrl_request(iface: str, command: str, timeout: float = 4.0) -> str:
    """Talk to hostapd's UNIX control socket directly (no hostapd_cli needed)."""
    path = os.path.join(CTRL_DIR, iface)
    if not os.path.exists(path):
        raise CtrlError(f"no hostapd control socket for {iface}")
    local = f"/tmp/sbegw-hostapd-{os.getpid()}-{abs(hash(command)) % 10000}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.bind(local)
        sock.connect(path)
        sock.send(command.encode())
        return sock.recv(65535).decode(errors="replace")
    except OSError as exc:
        raise CtrlError(f"{iface}: {command}: {exc}") from exc
    finally:
        sock.close()
        try:
            os.unlink(local)
        except OSError:
            pass


def status(iface: str) -> dict[str, str]:
    """Parse hostapd STATUS — the authoritative runtime state of a BSS."""
    try:
        text = _ctrl_request(iface, "STATUS")
    except CtrlError as exc:
        log.debug("status failed: %s", exc)
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def interface_state(iface: str) -> str | None:
    """hostapd's own view of a BSS: ENABLED, DFS, ACS, COUNTRY_UPDATE, ...

    ENABLED is the only state in which the AP is actually beaconing. A BSS can
    sit in DFS (channel availability check) or ACS for tens of seconds while
    looking perfectly configured, so this is what distinguishes "started" from
    "on the air".
    """
    return status(iface).get("state") or None


def sta_info(iface: str, mac: str) -> dict[str, str]:
    try:
        text = _ctrl_request(iface, f"STA {mac}")
    except CtrlError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def deauthenticate(iface: str, mac: str, *, reason: int = 5) -> bool:
    try:
        return "OK" in _ctrl_request(iface, f"DEAUTHENTICATE {mac} reason={reason}")
    except CtrlError:
        return False


def disassociate(iface: str, mac: str, *, reason: int = 8) -> bool:
    try:
        return "OK" in _ctrl_request(iface, f"DISASSOCIATE {mac} reason={reason}")
    except CtrlError:
        return False


def deny_mac(iface: str, mac: str) -> bool:
    try:
        return "OK" in _ctrl_request(iface, f"DENY_ACL ADD_MAC {mac}")
    except CtrlError:
        return False


def allow_mac(iface: str, mac: str) -> bool:
    try:
        return "OK" in _ctrl_request(iface, f"DENY_ACL DEL_MAC {mac}")
    except CtrlError:
        return False


def bss_transition(iface: str, mac: str, target_bssid: str) -> bool:
    """802.11v BSS Transition Management request — the steering primitive."""
    try:
        reply = _ctrl_request(
            iface, f"BSS_TM_REQ {mac} pref=1 abridged=1 disassoc_imminent=0 "
                   f"neighbor={target_bssid},0,0,0,0")
        return "OK" in reply
    except CtrlError:
        return False


def mld_links(iface: str) -> list[dict[str, Any]]:
    """Report the links hostapd currently has attached to an MLD."""
    info = status(iface)
    links: list[dict[str, Any]] = []
    for key, value in info.items():
        # hostapd reports link state as e.g. `link_id=0`, `mld_addr=...` and
        # per-link `linkN_...` prefixed keys depending on version.
        if key.startswith("link") and "_" in key:
            prefix, _, field = key.partition("_")
            try:
                index = int(prefix[4:])
            except ValueError:
                continue
            while len(links) <= index:
                links.append({"link_id": len(links)})
            links[index][field] = value
    if not links and info.get("mld_addr"):
        links.append({"link_id": int(info.get("link_id", 0)),
                      "mld_addr": info["mld_addr"]})
    return links


def reload_config(iface: str) -> bool:
    try:
        return "OK" in _ctrl_request(iface, "RELOAD")
    except CtrlError:
        return False


# Channel widths as hostapd's CHAN_SWITCH expects them.
_CSA_BW = {20: 20, 40: 40, 80: 80, 160: 160, 240: 320, 320: 320}


def channel_switch(iface: str, *, freq: int, channel: int, width: int,
                   center_freq1: int, band: str, count: int = 10,
                   punct_bitmap: int | None = None,
                   center_freq2: int = 0) -> tuple[bool, str]:
    """Move a live BSS with a CSA so associated clients follow instead of dropping.

    Returns (ok, detail). The caller falls back to a config rewrite when this
    reports failure — not every hostapd build exposes CHAN_SWITCH.
    """
    parts = [f"CHAN_SWITCH {count} {freq}",
             f"center_freq1={center_freq1}",
             f"bandwidth={_CSA_BW.get(width, width)}"]
    if center_freq2:
        parts.append(f"center_freq2={center_freq2}")
    # The PHY flags tell hostapd which operation elements to rebuild.
    if band != "2g":
        parts.append("vht=1")
    parts.append("he=1")
    parts.append("eht=1")
    if punct_bitmap:
        parts.append(f"punct_bitmap={punct_bitmap}")
    command = " ".join(parts)

    try:
        reply = _ctrl_request(iface, command, timeout=8.0)
    except CtrlError as exc:
        return False, str(exc)
    reply = reply.strip()
    if reply.startswith("OK"):
        return True, f"CSA to channel {channel} started ({command})"
    if "UNKNOWN COMMAND" in reply:
        return False, "this hostapd build does not support CHAN_SWITCH"
    return False, f"hostapd refused the channel switch: {reply or 'FAIL'}"


def supports_channel_switch(iface: str) -> bool:
    """Probe once whether CHAN_SWITCH exists, without actually switching."""
    try:
        # A deliberately malformed request: a build with the command answers
        # FAIL, one without it answers UNKNOWN COMMAND.
        reply = _ctrl_request(iface, "CHAN_SWITCH", timeout=4.0)
    except CtrlError:
        return False
    return "UNKNOWN COMMAND" not in reply.upper()
