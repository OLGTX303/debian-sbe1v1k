#!/usr/bin/env python3
"""Verify every hostapd config key wifid can emit is one hostapd actually parses.

A typo or an OpenWrt-UCI-style name (e.g. `ieee80211r`, which is *not* a hostapd
option) makes hostapd reject the whole file, taking every radio down at once. The
check greps the real binary's string table, so it validates against the exact
build that will run on the device.

Usage: check_hostapd_keys.py [path-to-hostapd-or-wpad]
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbegw.adapters import hostapd  # noqa: E402

DEFAULT_BINARIES = (
    "/opt/sbegw/wifi/usr/sbin/wpad",
    os.path.join(os.path.dirname(__file__),
                 "../../rootfs/opt/sbegw/wifi/usr/sbin/wpad"),
)

# Keys hostapd accepts but which do not appear as standalone strings in the
# binary (they are parsed as part of a larger token). None known today; kept so
# a future exception is documented rather than silently skipped.
ALLOWED_ABSENT: set[str] = set()


def render_cases() -> list[tuple[str, str]]:
    """Render the full matrix of band x security combinations wifid supports."""
    cases: list[tuple[str, str]] = []

    caps_6g = {"band": "6g", "ht": False, "vht": False, "he": True, "eht": True,
               "mlo": True, "channels": [1, 5, 37, 69], "widths": [20, 40, 80, 160, 320]}
    caps_5g = {"band": "5g", "ht": True, "vht": True, "he": True, "eht": True,
               "mlo": True, "channels": [36, 52, 100], "widths": [20, 40, 80, 160]}
    caps_2g = {"band": "2g", "ht": True, "vht": False, "he": True, "eht": True,
               "mlo": True, "channels": [1, 6, 11], "widths": [20, 40]}

    cases.append(("6 GHz WPA3 320 MHz MLO link + FT + all extras",
                  hostapd.render_link_config(
        {"id": "radio-6g", "band": "6g", "channel": "auto", "channel_width": 320,
         "tx_power": "auto", "dfs": True, "bss_color": 5},
        caps_6g,
        [{"interface": "wl6g0", "ssid": "N", "bssid": "aa:bb:cc:dd:ee:20",
          "bridge": "br-lan",
          "security": {"mode": "wpa3", "passphrase": "strongpass123",
                       "pmf": "required", "fast_transition": True},
          "mld": {"id": "m", "mld_mac": "02:bb:cc:5d:ee:41", "link_id": 2},
          "neighbor_report": True, "bss_transition": True, "fast_roaming": True,
          "client_isolation": True, "max_clients": 64, "min_rssi": -75,
          "proxy_arp": True, "hidden": True}],
        country="US")))

    cases.append(("5 GHz WPA2/WPA3 transition, two BSSes, fixed channel",
                  hostapd.render_link_config(
        {"id": "radio-5g", "band": "5g", "channel": 36, "channel_width": 160,
         "tx_power": 20, "dfs": True, "beacon_interval": 100, "dtim": 2,
         "rts_threshold": 2347},
        caps_5g,
        [{"interface": "wl5g0", "ssid": "A", "bssid": "aa:bb:cc:dd:ee:10",
          "bridge": "br-lan", "mld": None,
          "security": {"mode": "wpa2-wpa3", "passphrase": "strongpass123",
                       "pmf": "optional"}},
         {"interface": "wl5g1", "ssid": "B", "bssid": "aa:bb:cc:dd:ee:11",
          "bridge": "br-lan", "mld": None,
          "security": {"mode": "wpa2", "passphrase": "strongpass123",
                       "pmf": "disabled"}}],
        country="US")))

    cases.append(("2.4 GHz WPA3-Enterprise with full RADIUS incl. CoA",
                  hostapd.render_link_config(
        {"id": "radio-2g", "band": "2g", "channel": 6, "channel_width": 40,
         "tx_power": "auto"},
        caps_2g,
        [{"interface": "wl2g0", "ssid": "E", "bssid": "aa:bb:cc:dd:ee:00",
          "bridge": "br-lan", "mld": None, "fast_roaming": True,
          "security": {"mode": "wpa3-enterprise", "pmf": "required",
                       "radius_profile": "r1", "fast_transition": True}}],
        country="US",
        radius_profiles={"r1": {
            "auth_server": "10.0.0.5", "auth_secret": "s",
            "auth_server2": "10.0.0.6", "auth_secret2": "s2",
            "acct_server": "10.0.0.5", "acct_secret": "s",
            "nas_identifier": "gw", "dynamic_vlan": True,
            "coa_secret": "c", "coa_client": "10.0.0.0/24"}})))

    cases.append(("2.4 GHz WPA2-Enterprise", hostapd.render_link_config(
        {"id": "radio-2g", "band": "2g", "channel": "auto", "channel_width": 20,
         "tx_power": "auto"},
        caps_2g,
        [{"interface": "wl2g0", "ssid": "E2", "bssid": "aa:bb:cc:dd:ee:02",
          "bridge": "br-lan", "mld": None,
          "security": {"mode": "wpa2-enterprise", "pmf": "optional",
                       "radius_profile": "r1"}}],
        country="US",
        radius_profiles={"r1": {"auth_server": "10.0.0.5", "auth_secret": "s"}})))

    cases.append(("6 GHz OWE (enhanced open)", hostapd.render_link_config(
        {"id": "radio-6g", "band": "6g", "channel": "auto", "channel_width": 160,
         "tx_power": "auto"},
        caps_6g,
        [{"interface": "wl6g0", "ssid": "O", "bssid": "aa:bb:cc:dd:ee:20",
          "bridge": "br-lan", "mld": None,
          "security": {"mode": "open", "owe": True, "pmf": "required"}}],
        country="US")))

    cases.append(("2.4 GHz open legacy", hostapd.render_link_config(
        {"id": "radio-2g", "band": "2g", "channel": 1, "channel_width": 20,
         "tx_power": "auto"},
        caps_2g,
        [{"interface": "wl2g0", "ssid": "Open", "bssid": "aa:bb:cc:dd:ee:00",
          "bridge": "br-lan", "mld": None,
          "security": {"mode": "open", "pmf": "disabled"}}],
        country="US")))
    return cases


CONFIG_FILE_CANDIDATES = (
    "../../../qsdk14-work-ucgf/qsdk/qca/src/network/services/hostapd/hostapd/"
    "config_file.c",
    "../../qsdk14-work-ucgf/qsdk/qca/src/network/services/hostapd/hostapd/"
    "config_file.c",
)


def _parser_keys() -> set[str]:
    """Every key hostapd's config parser compares against, from its source.

    Extracted from the `os_strcmp(buf, "key")` chain in config_file.c, which is
    exactly the set of accepted directives.
    """
    override = os.environ.get("SBEGW_HOSTAPD_CONFIG_C")
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in ((override,) if override else CONFIG_FILE_CANDIDATES):
        path = candidate if os.path.isabs(candidate) else os.path.join(here, candidate)
        if not os.path.isfile(path):
            continue
        with open(path, errors="replace") as fh:
            body = fh.read()
        return set(re.findall(r'os_strcmp\(buf,\s*"([^"]+)"\)', body))
    return set()


def main() -> int:
    binary = None
    if len(sys.argv) > 1:
        binary = sys.argv[1]
    else:
        for candidate in DEFAULT_BINARIES:
            if os.path.isfile(candidate):
                binary = candidate
                break
    if not binary or not os.path.isfile(binary):
        print("SKIP  no hostapd binary found; pass one as an argument")
        return 0

    with open(binary, "rb") as fh:
        blob = fh.read()
    print(f"checking against {os.path.realpath(binary)}\n")

    cases = render_cases()
    keys: dict[str, str] = {}
    akms: set[str] = set()
    for label, conf in cases:
        for line in conf.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            keys.setdefault(key, label)
            if key == "wpa_key_mgmt":
                akms.update(value.split())

    # The string-table test is a SUBSTRING match, which can pass a key that
    # merely occurs inside a longer one: "multicast_to_unicast" is a suffix of
    # "bridge_multicast_to_unicast", so only the longer literal is stored and a
    # bogus short key would look present. Cross-check against hostapd's own
    # parser when its source is available — that is the authority.
    parser_keys = _parser_keys()
    if parser_keys:
        print(f"cross-checking against {len(parser_keys)} keys in "
              f"hostapd's config parser")
        bad_keys = sorted(k for k in keys
                          if k not in parser_keys and k not in ALLOWED_ABSENT)
        substring_only = sorted(
            k for k in keys
            if k in parser_keys and k.encode() in blob
            and f"\x00{k}\x00".encode() not in blob)
        for key in substring_only:
            print(f"note  '{key}' is only in the string table as part of a "
                  f"longer literal, but hostapd's parser accepts it")
    else:
        print("note  hostapd source not found; falling back to the weaker "
              "string-table test")
        bad_keys = sorted(k for k in keys
                          if k.encode() not in blob and k not in ALLOWED_ABSENT)
    bad_akms = sorted(a for a in akms if a.encode() not in blob)

    print(f"{len(keys)} distinct config keys and {len(akms)} AKMs emitted "
          f"across {len(cases)} renders")

    for key in bad_keys:
        print(f"FAIL  config key '{key}' is not parsed by this hostapd "
              f"(first emitted by: {keys[key]})")
    for akm in bad_akms:
        print(f"FAIL  wpa_key_mgmt value '{akm}' is not recognised")

    if not bad_keys and not bad_akms:
        for must in ("mld_ap", "mld_addr", "mld_link_id"):
            present = must in keys
            print(f"{'PASS' if present else 'WARN'}  MLO key '{must}' is emitted "
                  f"and recognised" if present
                  else f"WARN  MLO key '{must}' was never emitted by any case")
        print("\nPASS  every emitted key and AKM is recognised by this hostapd")
        return 0

    print(f"\n{len(bad_keys) + len(bad_akms)} problem(s): hostapd rejects a config "
          "file containing an unknown option, which would take every radio down.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
