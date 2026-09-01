#!/usr/bin/env python3
"""DPI accounting and UniFi interoperability checks without network access."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbegw import schema  # noqa: E402
from sbegw.configd import ConfigStore  # noqa: E402
from sbegw.dpi import DpiEngine  # noqa: E402
from sbegw.unifi import (UniFiControllerAgent, decode_inform, discovery_packet,
                         encode_inform)  # noqa: E402

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" +
          (f" — {detail}" if detail else ""))


class Clients:
    @staticmethod
    def live():
        return [{"mac": "02:00:5e:00:53:10", "ipv4": "192.168.2.44",
                 "ipv6": ["2001:db8:2::44"]}]


state = tempfile.mkdtemp(prefix="sbegw-dpi-")
try:
    cfg = schema.default_config()
    cfg["networks"]["guest"] = {
        "name": "Guest", "vlan": 20, "subnet": "192.168.20.1/24",
        "dhcp": {"enabled": False}, "zone": "guest", "purpose": "guest",
    }
    schema.validate(cfg)
    dpi = DpiEngine(state, Clients())

    event = {"event_type": "flow", "flow_id": 100,
             "src_ip": "192.168.2.44",
             "dest_ip": "203.0.113.8", "app_proto": "tls",
             "flow": {"bytes_toserver": 1200, "bytes_toclient": 8400,
                      "pkts_toserver": 8, "pkts_toclient": 12}}
    check("a LAN-to-WAN flow is accepted", dpi.ingest(event, cfg))
    check("an internal LAN flow is not double-counted", not dpi.ingest(
        {**event, "dest_ip": "192.168.20.9"}, cfg))
    summary = dpi.summary(cfg)
    app = summary["applications"][0]
    check("download and upload direction is preserved",
          app["rx_bytes"] == 8400 and app["tx_bytes"] == 1200, str(app))
    stats = dpi.unifi_stats()
    check("DPI is attributed to the known client MAC",
          stats and stats[0]["mac"] == "02:00:5e:00:53:10", str(stats))
    check("legacy UniFi application IDs are emitted",
          stats[0]["stats"][0]["cat"] == 20 and
          stats[0]["stats"][0]["app"] == 185, str(stats))
    rendered = dpi.render_config(cfg)
    check("Suricata listens on the LAN bridge and VLAN",
          "interface: br-lan\n" in rendered and
          "interface: br-lan.20\n" in rendered)
    check("capture config includes domain metadata and a bounded AF_PACKET ring",
          "- tls:" in rendered and "- http:" in rendered and
          "ring-size: 8192" in rendered)

    # TLS SNI arrives before the terminal flow event. It should refine generic
    # TLS into a useful service without storing a URL or packet payload.
    dpi.ingest({"event_type": "tls", "flow_id": 101,
                "tls": {"sni": "r4---sn.googlevideo.com"}}, cfg)
    service_flow = {**event, "flow_id": 101,
                    "flow": {"bytes_toserver": 50, "bytes_toclient": 950,
                             "pkts_toserver": 1, "pkts_toclient": 2}}
    check("TLS metadata classifies a service flow", dpi.ingest(service_flow, cfg))
    service_summary = dpi.summary(cfg)
    youtube = next((row for row in service_summary["applications"]
                    if row["name"] == "YouTube"), None)
    check("DPI reports service and category names",
          youtube is not None and youtube["category_name"] == "Streaming",
          str(service_summary["applications"]))
    check("DPI exposes capture health counters",
          service_summary["status"]["events_seen"] >= 3 and
          service_summary["status"]["flows_accepted"] >= 2 and
          service_summary["categories"], str(service_summary["status"]))

    payload = {"_type": "setparam", "mgmt_cfg": "authkey=001122\ncfgversion=7"}
    iv = bytes(range(16))
    for gcm in (False, True):
        packet = encode_inform(payload, "02:00:5e:00:53:10", gcm=gcm, iv=iv)
        check(f"TNBU {'GCM' if gcm else 'CBC'} round-trip",
              decode_inform(packet) == payload)
    discover = discovery_packet("02:00:5e:00:53:10", "192.168.2.1", "4.4.18")
    check("discovery frame carries a valid TLV length",
          discover[:2] == bytes((2, 6)) and
          int.from_bytes(discover[2:4], "big") == len(discover) - 4)

    network = {
        "id": "01234567-89ab-cdef-0123-456789abcdef", "name": "IoT",
        "management": "GATEWAY", "default": False, "vlanId": 30,
        "isolationEnabled": True, "internetAccessEnabled": True,
        "ipv4Configuration": {"hostIpAddress": "192.168.30.1",
                              "prefixLength": 24,
                              "dhcpConfiguration": {"mode": "SERVER",
                                "ipAddressRange": {"start": "192.168.30.50",
                                                   "stop": "192.168.30.200"}}},
    }
    translated = UniFiControllerAgent.translate_network(network)
    check("gateway network translates to local VLAN state",
          translated is not None and translated[1]["vlan"] == 30 and
          translated[1]["zone"] == "guest", str(translated))
    wifi = {
        "id": "fedcba98-7654-3210-fedc-ba9876543210", "name": "Devices",
        "type": "IOT_OPTIMIZED", "enabled": True,
        "broadcastingFrequenciesGHz": [2.4, 5],
        "network": {"networkId": network["id"]},
        "securityConfiguration": {"type": "WPA2_WPA3_PERSONAL",
                                  "passphrase": "example-passphrase"},
    }
    translated_wifi = UniFiControllerAgent.translate_wifi(
        wifi, {network["id"]: translated[0]})
    check("WiFi broadcast maps security, bands and network",
          translated_wifi is not None and
          translated_wifi[1]["security"]["mode"] == "wpa2-wpa3" and
          translated_wifi[1]["bands"] == ["2g", "5g"] and
          translated_wifi[1]["network"] == translated[0], str(translated_wifi))
    dns_cases = [
        ({"type": "A_RECORD", "enabled": True, "domain": "printer.lan",
          "ipv4Address": "192.168.2.20"}, "192.168.2.20"),
        ({"type": "CNAME_RECORD", "enabled": True, "domain": "nas.lan",
          "targetDomain": "storage.lan"}, "storage.lan"),
        ({"type": "TXT_RECORD", "enabled": True, "domain": "note.lan",
          "text": "managed"}, "managed"),
    ]
    check("current Network API DNS fields translate",
          all(UniFiControllerAgent.translate_dns(row)["record"]["value"] == expected
              for row, expected in dns_cases))
    forward = UniFiControllerAgent.translate_dns({
        "type": "FORWARD_DOMAIN", "enabled": True, "domain": "corp.example",
        "ipAddress": "10.0.0.53"})
    check("current conditional DNS field translates",
          forward == {"forwarder": {"domain": "corp.example",
                                     "server": "10.0.0.53"}}, str(forward))

    # Exercise the complete API pull and schema/transaction boundary with
    # current OpenAPI-shaped pages and detail objects.
    default = {
        "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Default",
        "management": "GATEWAY", "enabled": True, "default": True,
        "vlanId": 1, "isolationEnabled": False,
        "internetAccessEnabled": True, "mdnsForwardingEnabled": True,
        "ipv4Configuration": {"hostIpAddress": "192.168.2.1",
                              "prefixLength": 24,
                              "dhcpConfiguration": {"mode": "SERVER",
                                "leaseTimeSeconds": 86400,
                                "ipAddressRange": {"start": "192.168.2.50",
                                                   "stop": "192.168.2.200"}}},
    }
    store = ConfigStore(state)

    def controller_settings(candidate):
        candidate["controller"].update({
            "enabled": True, "inform_url": "http://192.0.2.20:8080/inform",
            "sync_enabled": True,
            "api_url": "https://192.0.2.20/proxy/network/integration/v1",
            "api_key": "test-api-key", "site_id": default["id"],
        })

    store.stage(controller_settings)
    store.commit(user="test", source_ip="local", confirm_required=False)
    agent = UniFiControllerAgent(state, store, None, None, None)
    details = {default["id"]: default, network["id"]: {**network, "enabled": True},
               wifi["id"]: wifi,
               "dddddddd-dddd-dddd-dddd-dddddddddddd": dns_cases[0][0]}

    def api_get(_cfg, path):
        if path.endswith("networks?limit=200"):
            return {"data": [{"id": default["id"]}, {"id": network["id"]}]}
        if path.endswith("wifi/broadcasts?limit=200"):
            return {"data": [{"id": wifi["id"]}]}
        if path.endswith("dns/policies?limit=200"):
            return {"data": [{"id": "dddddddd-dddd-dddd-dddd-dddddddddddd"}]}
        return details[path.rsplit("/", 1)[-1]]

    agent._api_get = api_get
    synced = agent.sync_once()
    running = store.get_running()
    check("Network API pull commits all supported domains atomically",
          synced["changed"] and len(running["networks"]) == 2 and
          len(running["wifi"]["networks"]) == 1 and
          running["dns"]["records"][0]["value"] == "192.168.2.20",
          str(synced))
finally:
    shutil.rmtree(state, ignore_errors=True)

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("Failed: " + ", ".join(FAILED))
    raise SystemExit(1)
