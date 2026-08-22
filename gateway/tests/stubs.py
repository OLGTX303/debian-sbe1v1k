"""Hardware stubs shared by the smoke test and the UI demo server.

These stand in for netd/wifid/clientd so tests and UI work never touch the host's
network. The shapes match what the real daemons return.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbegw.api import ApiServer, ApiService          # noqa: E402
from sbegw.auth import AuthManager                   # noqa: E402
from sbegw.configd import ApplyResult, ConfigStore   # noqa: E402
from sbegw.events import EventBus                    # noqa: E402
from sbegw.telemetry import Sampler, TelemetryStore  # noqa: E402
from sbegw.util import now                          # noqa: E402

# US-style channel lists, close enough to what `iw phy` reports on this board.
# A sparse list would make wide-channel candidates look infeasible.
_2G = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
_5G = [36, 40, 44, 48, 52, 56, 60, 64,
       100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
       149, 153, 157, 161, 165]
_5G_DFS = set(range(52, 145))
_6G = list(range(1, 98, 4))
_6G_PSC = {5, 21, 37, 53, 69, 85}


def _details(channels, band, dfs=frozenset(), psc=frozenset()):
    out = []
    for channel in channels:
        if band == "2g":
            freq = 2407 + channel * 5
        elif band == "5g":
            freq = 5000 + channel * 5
        else:
            freq = 5950 + channel * 5
        out.append({"channel": channel, "frequency_mhz": freq,
                    "disabled": False, "no_ir": False,
                    "dfs": channel in dfs, "psc": channel in psc})
    return out


RADIOS = {
    "radio-2g": {"id": "radio-2g", "phy": "phy0", "band": "2g",
                 "mac": "aa:bb:cc:dd:ee:00", "label": "2.4 GHz",
                 "widths": [20, 40], "channels": _2G,
                 "he": True, "eht": True, "mlo": True, "ht": True, "vht": False,
                 "eht240": False,
                 "max_ap_bss": 8, "ap_supported": True, "max_nss": 2, "dfs": False,
                 "afc": False, "max_tx_power_dbm": 23.0,
                 "channel_details": _details(_2G, "2g"),
                 "firmware": {"version": "WLAN.HK.2.9.0.1-01234", "crashes": 0},
                 "standards": ["802.11b", "802.11g", "802.11n", "802.11ax",
                               "802.11be"]},
    "radio-5g": {"id": "radio-5g", "phy": "phy1", "band": "5g",
                 "mac": "aa:bb:cc:dd:ee:10", "label": "5 GHz",
                 "widths": [20, 40, 80, 160, 240], "channels": _5G,
                 "he": True, "eht": True, "mlo": True, "ht": True, "vht": True,
                 "eht240": True,
                 "max_ap_bss": 8, "ap_supported": True, "max_nss": 4, "dfs": True,
                 "afc": False, "max_tx_power_dbm": 26.0,
                 "channel_details": _details(_5G, "5g", dfs=_5G_DFS),
                 "firmware": {"version": "WLAN.HK.2.9.0.1-01234", "crashes": 0},
                 "standards": ["802.11a", "802.11n", "802.11ac", "802.11ax",
                               "802.11be"]},
    "radio-6g": {"id": "radio-6g", "phy": "phy2", "band": "6g",
                 "mac": "aa:bb:cc:dd:ee:20", "label": "6 GHz",
                 "widths": [20, 40, 80, 160, 320], "channels": _6G,
                 "he": True, "eht": True, "mlo": True, "ht": False, "vht": False,
                 "eht240": False,
                 "max_ap_bss": 8, "ap_supported": True, "max_nss": 4, "dfs": False,
                 "afc": True, "max_tx_power_dbm": 24.0,
                 "channel_details": _details(_6G, "6g", psc=_6G_PSC),
                 "firmware": {"version": "WLAN.HK.2.9.0.1-01234", "crashes": 0},
                 "standards": ["802.11a", "802.11ax", "802.11be"]},
}


class StubNetd:
    """Records applies instead of touching the network."""

    def __init__(self):
        self.applies = 0
        self.services = type("S", (), {
            "leases": staticmethod(lambda: [
                {"mac": "b8:27:eb:11:22:33", "address": "192.168.2.114",
                 "hostname": "pi-hole", "expires": 0, "client_id": None},
                {"mac": "3c:22:fb:aa:bb:cc", "address": "192.168.2.131",
                 "hostname": "macbook", "expires": 0, "client_id": None}]),
            "_running": staticmethod(lambda: True)})()
        self.ports = type("P", (), {
            "all_states": staticmethod(self._port_states),
            "discover": staticmethod(lambda: ["eth0", "eth1", "eth2", "eth3"]),
            "poll_link_changes": staticmethod(lambda: None)})()
        self.wans = type("W", (), {
            "probe": staticmethod(lambda cfg: {
                "wan1": {"id": "wan1", "name": "WAN 1", "state": "up", "link_up": True,
                         "internet": True, "addresses": ["203.0.113.42/24"],
                         "gateway": "203.0.113.1", "latency_ms": 8.4,
                         "loss_percent": 0.0, "priority": 1, "weight": 1,
                         "interface": "eth3", "mode": "dhcp", "port": "eth3",
                         "since": 0,
                         "counters": {"rx_bytes": 88123456, "tx_bytes": 12345678}}}),
            "select_primary": staticmethod(lambda cfg: "wan1"),
            "health": staticmethod(lambda: {}),
            "interfaces": staticmethod(lambda cfg: {"wan1": "eth3"}),
            "interface_for": staticmethod(lambda wan: wan.get("port", "eth3")),
            "_default_gateway": staticmethod(lambda iface: "203.0.113.1")})()

    @staticmethod
    def _port_states(cfg):
        speeds = {"eth0": 1000, "eth1": 1000, "eth2": 2500, "eth3": 10000}
        out = []
        for name, port in cfg.get("ports", {}).items():
            up = name != "eth1"
            out.append({
                "id": name, "name": port.get("name") or name,
                "role": port.get("role"), "network": port.get("network"),
                "enabled": port.get("enabled", True), "admin_up": True,
                "oper_state": "UP" if up else "DOWN", "link_up": up,
                "speed_mbps": speeds.get(name) if up else None,
                "max_speed_mbps": speeds.get(name),
                "duplex": "full" if up else None, "autoneg": True,
                "supported_speeds": [100, 1000] if speeds.get(name) == 1000
                else [100, 1000, 2500] if speeds.get(name) == 2500
                else [1000, 2500, 10000],
                "medium": "Twisted Pair", "mtu": port.get("mtu", 1500),
                "mac": f"aa:bb:cc:dd:ef:0{name[-1]}",
                "flow_control": {"rx": True, "tx": True, "autoneg": True},
                "phy": {"driver": "qca8081" if name == "eth2" else "qca8075",
                        "chip": "QCA8081" if name == "eth2" else "QCA8075",
                        "firmware": None, "bus": None, "temperature_c": 48.5},
                "counters": {"rx_bytes": 5123456, "tx_bytes": 2123456,
                             "rx_packets": 41234, "tx_packets": 22111,
                             "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0,
                             "tx_dropped": 0, "crc_errors": 0, "multicast": 12},
                "rates": {"rx_bps": 24_500_000.0 if up else 0.0,
                          "tx_bps": 3_100_000.0 if up else 0.0,
                          "rx_pps": 2100.0, "tx_pps": 900.0},
                "master": "br-lan" if port.get("role") == "lan" else None})
        return out

    def network_states(self, cfg):
        return [{"id": nid, "name": n.get("name"),
                 "interface": "br-lan" if not n.get("vlan") else f"br-lan.{n['vlan']}",
                 "subnet": n.get("subnet"), "addresses": [n.get("subnet")],
                 "vlan": n.get("vlan"), "zone": n.get("zone"),
                 "purpose": n.get("purpose"),
                 "lease_count": 2 if nid == "default" else 0,
                 "dhcp_enabled": n.get("dhcp", {}).get("enabled", False),
                 "isolation": n.get("isolation", False),
                 "internet_access": n.get("internet_access", True),
                 "counters": {"rx_bytes": 91234, "tx_bytes": 41234}}
                for nid, n in cfg.get("networks", {}).items()]

    def preflight(self, old, new):
        return True, []

    def __call__(self, old, new):
        self.applies += 1
        return ApplyResult(True, ["stub netd applied"])


class StubWifid:
    def __init__(self):
        self.applies = 0
        # The RF analyzer reads wifid._plan, so keep one in step with config.
        self._plan = {"links": {}, "mlds": {}, "bsses": {}}

    def capabilities(self):
        return {"radios": RADIOS,
                "hostapd": {"available": True, "mlo": True, "eht": True,
                            "path": "/opt/sbegw/bin/hostapd",
                            "real_path": "/opt/sbegw/wifi/usr/sbin/wpad",
                            "reason": ""},
                "mlo": {"supported": True, "driver_capable": True,
                        "hostapd_capable": True, "reason": "",
                        "eligible_radios": sorted(RADIOS)},
                "ppeds": []}

    def _bsses(self, cfg):
        out = []
        slots: dict[str, int] = {}
        for wnid, wnet in sorted(cfg.get("wifi", {}).get("networks", {}).items()):
            if not wnet.get("enabled", True):
                continue
            mld_id = next((m for m, mld in cfg["wifi"].get("mlds", {}).items()
                           if mld.get("wireless_network") == wnid), None)
            mld_links = cfg["wifi"].get("mlds", {}).get(mld_id, {}).get("links", []) \
                if mld_id else []
            for rid, radio in sorted(RADIOS.items()):
                if radio["band"] not in wnet.get("bands", []):
                    continue
                slot = slots.get(rid, 0)
                slots[rid] = slot + 1
                is_link = rid in mld_links
                out.append({
                    "interface": f"wl{radio['band']}{slot}",
                    # Real wifid derives a locally-administered BSSID per slot;
                    # mirror that so overlapping SSIDs are distinguishable.
                    "bssid": radio["mac"] if slot == 0 else "%s%02x" % (
                        radio["mac"][:-2], (int(radio["mac"][-2:], 16) + slot) & 0xFF),
                    "ssid": wnet["ssid"],
                    "wireless_network": wnid, "radio": rid, "band": radio["band"],
                    "network": wnet.get("network"),
                    "vlan": cfg["networks"].get(wnet.get("network"), {}).get("vlan"),
                    "state": "ENABLED",
                    "channel": {"2g": 6, "5g": 36, "6g": 37}[radio["band"]],
                    "mld": {"id": mld_id, "mld_mac": "02:bb:cc:5d:ee:40",
                            "link_id": mld_links.index(rid)} if is_link else None,
                    "client_count": 2 if radio["band"] == "5g" else 1,
                    "counters": {"rx_bytes": 812345, "tx_bytes": 412345}})
        return out

    def _rebuild_plan(self, cfg):
        bsses = self._bsses(cfg)
        links = {}
        for bss in bsses:
            rid = bss["radio"]
            entry = links.setdefault(rid, {
                "radio": rid, "caps": RADIOS[rid],
                "config": cfg.get("wifi", {}).get("radios", {}).get(rid, {}),
                "bsses": []})
            entry["bsses"].append(bss)
        self._plan = {
            "links": links,
            "mlds": {mid: {"id": mid, "name": mld.get("name", mid),
                           "mld_mac": "02:bb:cc:5d:ee:40",
                           "wireless_network": mld.get("wireless_network"),
                           "radios": mld.get("links", []),
                           "link_ids": {r: i for i, r
                                        in enumerate(mld.get("links", []))},
                           "link_steering": mld.get("link_steering", "auto")}
                     for mid, mld in cfg.get("wifi", {}).get("mlds", {}).items()},
            "bsses": {b["interface"]: b for b in bsses},
        }
        return self._plan

    def snapshot(self, cfg):
        self._rebuild_plan(cfg)
        bsses = self._bsses(cfg)
        mlds = []
        for mid, mld in cfg.get("wifi", {}).get("mlds", {}).items():
            links = []
            for i, rid in enumerate(mld.get("links", [])):
                radio = RADIOS.get(rid, {})
                links.append({
                    "link_id": i, "radio": rid, "band": radio.get("band"),
                    "interface": f"wl{radio.get('band')}0",
                    "link_mac": radio.get("mac"), "state": "ENABLED",
                    "channel": {"2g": 6, "5g": 36, "6g": 37}.get(radio.get("band")),
                    "channel_width": {"2g": 40, "5g": 160, "6g": 320}.get(radio.get("band")),
                    "noise_dbm": -96 if radio.get("band") == "6g" else -92,
                    "utilisation_percent": 8.0 + i * 6,
                    "retry_percent": 1.1 + i, "client_count": 1,
                    "counters": {"rx_bytes": 700000 * (i + 1),
                                 "tx_bytes": 300000 * (i + 1)}})
            mlds.append({
                "id": mid, "name": mld.get("name", mid),
                "mld_mac": "02:bb:cc:5d:ee:40",
                "wireless_network": mld.get("wireless_network"),
                "ssid": cfg["wifi"]["networks"].get(
                    mld.get("wireless_network"), {}).get("ssid"),
                "link_steering": mld.get("link_steering", "auto"),
                "state": "up" if len(links) >= 2 else "down",
                "links": links, "link_count": len(links), "links_up": len(links),
                "aggregate": {"rx_bytes": sum(l["counters"]["rx_bytes"] for l in links),
                              "tx_bytes": sum(l["counters"]["tx_bytes"] for l in links)},
                "mlo_client_count": 1})

        radios = []
        for rid, radio in RADIOS.items():
            configured = cfg.get("wifi", {}).get("radios", {}).get(rid, {})
            want = configured.get("channel_width",
                                  max(radio["widths"]))
            # Show a genuine runtime downgrade on 6 GHz so the UI path is exercised.
            runtime_width = 160 if (radio["band"] == "6g" and want == 320) else want
            radios.append({
                "id": rid, "label": radio["label"], "band": radio["band"],
                "phy": radio["phy"], "mac": radio["mac"], "state": "up",
                "health": "up", "enabled": configured.get("enabled", True),
                "capabilities": radio,
                "configured": {"channel": configured.get("channel", "auto"),
                               "channel_width": want,
                               "tx_power": configured.get("tx_power", "auto")},
                "runtime": {"channel": {"2g": 6, "5g": 36, "6g": 37}[radio["band"]],
                            "channel_width": runtime_width,
                            "frequency_mhz": 5955 if radio["band"] == "6g" else 5180,
                            "tx_power_dbm": 20.0,
                            "noise_dbm": -96 if radio["band"] == "6g" else -92,
                            "utilisation_percent": {"2g": 34.0, "5g": 12.0,
                                                    "6g": 4.0}[radio["band"]],
                            "eht_active": True},
                "downgrade_reason": (
                    "320 MHz requested, 160 MHz in use — regulatory domain or "
                    "DFS/neighbour constraints"
                    if runtime_width != want else None),
                "bss_count": len([b for b in bsses if b["radio"] == rid]),
                "client_count": 2 if radio["band"] == "5g" else 1,
                "firmware": radio["firmware"], "pcie": {"slot": f"0001:0{rid[-1]}:00.0"},
                "ppeds": {"id": rid, "enabled": True, "tx_rings": 4, "rx_rings": 4,
                          "tx_packets": 91234, "rx_packets": 71234, "errors": 0},
                "counters": {"rx_bytes": 8123456, "tx_bytes": 3123456,
                             "rx_packets": 41234, "tx_packets": 21234,
                             "tx_errors": 0, "rx_dropped": 0}})

        return {"radios": radios, "bsses": bsses, "mlds": mlds,
                "clients": self.wireless_clients(cfg),
                "capabilities": self.capabilities(), "hostapd_running": True}

    def wireless_clients(self, cfg):
        mlds = cfg.get("wifi", {}).get("mlds", {})
        mld_id = next(iter(mlds), None)
        links = mlds.get(mld_id, {}).get("links", []) if mld_id else []
        clients = [{
            "mac": "3c:22:fb:aa:bb:cc", "interface": "wl5g0",
            "bssid": "aa:bb:cc:dd:ee:10", "ssid": "SBE-Net",
            "wireless_network": "main", "network": "default", "vlan": None,
            "radio": "radio-5g", "band": "5g", "channel": 36, "security": "wpa3",
            "authenticated": True, "authorized": True, "rssi": -48, "snr": 44,
            "tx_rate_mbps": 2882.0, "rx_rate_mbps": 2401.0,
            "tx_bytes": 918273645, "rx_bytes": 4182736450,
            "tx_packets": 812345, "rx_packets": 2812345,
            "tx_retries": 4123, "tx_failed": 12, "retry_percent": 0.5,
            "connected_seconds": 8412, "mcs": 13, "nss": 2, "phy_mode": "EHT",
            "is_mlo": bool(links), "mld_mac": "9a:22:fb:aa:bb:cd",
            "mld_ap": mld_id,
            "links": [{"link_id": i, "rssi": -48 - i * 6, "snr": 44 - i * 6,
                       "tx_rate_mbps": 2882.0 / (i + 1),
                       "rx_rate_mbps": 2401.0 / (i + 1),
                       "mcs": 13, "nss": 2,
                       "channel_width": {"2g": 40, "5g": 160, "6g": 320}.get(
                           RADIOS.get(r, {}).get("band")),
                       "phy_mode": "EHT", "tx_bytes": 300000000 // (i + 1),
                       "rx_bytes": 1400000000 // (i + 1),
                       "retry_percent": 0.5 + i}
                      for i, r in enumerate(links)],
            "eht": True,
            "health": {"rating": "excellent", "score": 100, "reasons": []},
        }, {
            "mac": "b8:27:eb:11:22:33", "interface": "wl2g0",
            "bssid": "aa:bb:cc:dd:ee:00", "ssid": "SBE-IoT",
            "wireless_network": "iot", "network": "default", "vlan": None,
            "radio": "radio-2g", "band": "2g", "channel": 6, "security": "wpa2",
            "authenticated": True, "authorized": True, "rssi": -74, "snr": 18,
            "tx_rate_mbps": 58.5, "rx_rate_mbps": 43.3,
            "tx_bytes": 8123456, "rx_bytes": 4123456,
            "tx_packets": 91234, "rx_packets": 41234,
            "tx_retries": 21234, "tx_failed": 412, "retry_percent": 23.3,
            "connected_seconds": 91234, "mcs": 7, "nss": 1, "phy_mode": "HT",
            "is_mlo": False, "mld_mac": None, "mld_ap": None, "links": [],
            "eht": False,
            "health": {"rating": "fair", "score": 60,
                       "reasons": ["marginal signal (-74 dBm)",
                                   "elevated retry rate (23.3%)"]},
        }]
        return clients

    def preflight(self, old, new):
        return True, []

    def __call__(self, old, new):
        self.applies += 1
        return ApplyResult(True, ["stub wifid applied"])

    def _hostapd_running(self):
        return True

    def scan_neighbours(self, cfg):
        return [
            {"bssid": "de:ad:be:ef:00:11", "ssid": "Neighbour-5G", "channel": 44,
             "frequency_mhz": 5220, "rssi": -67, "security": "wpa2",
             "phy_modes": ["802.11ac"], "width": 80, "utilisation_percent": 18.0,
             "radio": "radio-5g", "band": "5g", "classification": "neighbour",
             "first_seen": 0},
            {"bssid": "de:ad:be:ef:00:22", "ssid": "SBE-Net", "channel": 1,
             "frequency_mhz": 2412, "rssi": -81, "security": "wpa3",
             "phy_modes": ["802.11ax"], "width": 20, "utilisation_percent": 9.0,
             "radio": "radio-2g", "band": "2g",
             "classification": "same-ssid-unknown-bssid", "first_seen": 0}]

    def recover_radio(self, rid, cfg):
        return True

    # --- data the channel analyzer consumes -------------------------------
    def seed_rf(self, analyzer):
        """Populate the analyzer with a plausible RF environment."""
        recent = now() - 420
        analyzer._scans["radio-2g"] = {"ts": recent, "neighbours": [
            {"bssid": "de:ad:be:ef:01:01", "ssid": "Neighbour-Home", "channel": 1,
             "width": 20, "rssi": -52, "band": "2g", "radio": "radio-2g",
             "security": "wpa2", "phy_modes": ["802.11n"],
             "classification": "neighbour", "frequency_mhz": 2412},
            {"bssid": "de:ad:be:ef:01:02", "ssid": "TP-Link_9F20", "channel": 6,
             "width": 40, "rssi": -71, "band": "2g", "radio": "radio-2g",
             "security": "wpa2", "phy_modes": ["802.11n"],
             "classification": "neighbour", "frequency_mhz": 2437},
            {"bssid": "de:ad:be:ef:01:03", "ssid": "Guest-2G", "channel": 11,
             "width": 20, "rssi": -84, "band": "2g", "radio": "radio-2g",
             "security": "open", "phy_modes": [],
             "classification": "neighbour", "frequency_mhz": 2462}]}
        analyzer._scans["radio-5g"] = {"ts": recent, "neighbours": [
            {"bssid": "de:ad:be:ef:05:01", "ssid": "Neighbour-5G", "channel": 36,
             "width": 80, "rssi": -49, "band": "5g", "radio": "radio-5g",
             "security": "wpa2", "phy_modes": ["802.11ac"],
             "classification": "neighbour", "frequency_mhz": 5180},
            {"bssid": "de:ad:be:ef:05:02", "ssid": "Office-AP", "channel": 44,
             "width": 40, "rssi": -63, "band": "5g", "radio": "radio-5g",
             "security": "wpa3", "phy_modes": ["802.11ax"],
             "classification": "neighbour", "frequency_mhz": 5220},
            {"bssid": "de:ad:be:ef:05:03", "ssid": "SBE-Net", "channel": 100,
             "width": 20, "rssi": -88, "band": "5g", "radio": "radio-5g",
             "security": "wpa3", "phy_modes": ["802.11ax"],
             "classification": "same-ssid-unknown-bssid", "frequency_mhz": 5500}]}
        analyzer._scans["radio-6g"] = {"ts": recent, "neighbours": [
            {"bssid": "de:ad:be:ef:06:01", "ssid": "Fast-6E", "channel": 37,
             "width": 160, "rssi": -66, "band": "6g", "radio": "radio-6g",
             "security": "wpa3", "phy_modes": ["802.11be"],
             "classification": "neighbour", "frequency_mhz": 6135}]}
        analyzer._surveys["radio-2g"] = {"ts": recent, "entries": [
            {"frequency_mhz": 2412, "noise_dbm": -88, "utilisation_percent": 64.0},
            {"frequency_mhz": 2437, "noise_dbm": -90, "utilisation_percent": 38.0,
             "in_use": True},
            {"frequency_mhz": 2462, "noise_dbm": -91, "utilisation_percent": 12.0}]}
        analyzer._surveys["radio-5g"] = {"ts": recent, "entries": [
            {"frequency_mhz": 5180, "noise_dbm": -85, "utilisation_percent": 57.0,
             "in_use": True},
            {"frequency_mhz": 5220, "noise_dbm": -89, "utilisation_percent": 24.0},
            {"frequency_mhz": 5500, "noise_dbm": -95, "utilisation_percent": 4.0},
            {"frequency_mhz": 5745, "noise_dbm": -96, "utilisation_percent": 2.0}]}
        analyzer._surveys["radio-6g"] = {"ts": recent, "entries": [
            {"frequency_mhz": 6135, "noise_dbm": -97, "utilisation_percent": 6.0,
             "in_use": True}]}

    def disconnect_client(self, mac):
        return True

    def block_client(self, mac):
        return True

    def unblock_client(self, mac):
        return True

    def steer_client(self, mac, bssid):
        return True


class StubClients:
    def __init__(self):
        self._records = {}

    def poll(self, cfg, leases, wireless):
        by_mac = {c["mac"]: c for c in wireless}
        out = []
        for lease in leases:
            wifi = by_mac.get(lease["mac"])
            out.append({
                "mac": lease["mac"], "name": lease.get("hostname") or lease["mac"],
                "hostname": lease.get("hostname"), "ipv4": lease["address"],
                "ipv6": [], "network": "default", "vlan": None,
                "port": wifi["interface"] if wifi else "eth0",
                "connection": "wireless" if wifi else "wired",
                "wireless": wifi, "online": True,
                "vendor": "Raspberry Pi" if lease["mac"].startswith("b8:27")
                else "Apple",
                "first_seen": 0, "last_seen": 0,
                "blocked": self._records.get(lease["mac"], {}).get("blocked", False),
                "quarantined": False, "fixed_ip": None, "note": None, "tags": [],
                "down_limit_kbps": None, "up_limit_kbps": None,
                "rx_bytes": (wifi or {}).get("rx_bytes", 91234),
                "tx_bytes": (wifi or {}).get("tx_bytes", 41234),
                "rx_rate_bps": 12_400_000.0 if wifi else 840_000.0,
                "tx_rate_bps": 2_100_000.0 if wifi else 210_000.0})
        return out

    def get(self, mac):
        return {"mac": mac, "name": mac, "online": True, "tags": []}

    def update(self, mac, **fields):
        self._records.setdefault(mac, {}).update(fields)
        return True

    def history(self, mac, limit=100):
        return [{"ts": 0, "event": "first-seen", "detail": "default"}]


def build(state_dir: str, *, port: int = 18099):
    """Wire a full ApiService over the stubs. Returns (server, parts)."""
    os.environ["SBEGW_STATE"] = state_dir
    events = EventBus(os.path.join(state_dir, "events.db"))
    config = ConfigStore(state_dir)
    netd, wifid, clients = StubNetd(), StubWifid(), StubClients()
    config.capabilities = wifid.capabilities()
    config.on_event = lambda kind, sev, data: events.emit(kind, sev, data,
                                                          subsystem="config")
    config.register_applier("netd", netd)
    config.register_applier("wifid", wifid)
    auth = AuthManager(os.path.join(state_dir, "auth.db"), config, events)
    telemetry = TelemetryStore(os.path.join(state_dir, "metrics.db"))
    sampler = Sampler(telemetry, netd=netd, wifid=wifid, clients=clients,
                      config_getter=config.get_running, events=events)
    from sbegw.rf import ChannelAnalyzer

    def _commit_channel(radio_id, channel):
        """Mirror main.py: the CSA fallback goes through configd."""
        def mutate(cfg):
            cfg["wifi"].setdefault("radios", {}).setdefault(radio_id, {})[
                "channel"] = channel
        config.stage(mutate)
        config.commit(user="system", source_ip="rf",
                      summary=f"channel {channel} on {radio_id}",
                      confirm_required=False)

    analyzer = ChannelAnalyzer(wifid, events, commit_channel=_commit_channel)
    service = ApiService(config_store=config, auth=auth, netd=netd, wifid=wifid,
                         clients=clients, telemetry=telemetry, sampler=sampler,
                         events=events, rf=analyzer)
    server = ApiServer(service, "127.0.0.1", port)
    return server, {"config": config, "auth": auth, "events": events,
                    "netd": netd, "wifid": wifid, "clients": clients,
                    "sampler": sampler, "service": service, "rf": analyzer}
