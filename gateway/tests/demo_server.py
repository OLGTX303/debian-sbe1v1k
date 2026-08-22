#!/usr/bin/env python3
"""Run the real API + UI against stubbed hardware, for UI work on a workstation.

    python3 tests/demo_server.py [--port 18100]
    open http://127.0.0.1:18100/   (admin / Demo-Passw0rd!)

Serves the UI from gateway/web and proxies /api to the in-process API, so the SPA
runs byte-for-byte as it will on the device. Nothing here touches the network.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import stubs  # noqa: E402  (same directory)

WEB = os.path.join(os.path.dirname(__file__), "..", "web")
API_PORT = 18099
USER, PASSWORD = "admin", "Demo-Passw0rd!"


def seed(parts):
    """Create the owner and a representative tri-band + MLO configuration."""
    auth, config = parts["auth"], parts["config"]
    if auth.needs_setup():
        auth.create_owner(USER, PASSWORD)

    def mutate(cfg):
        for rid, radio in stubs.RADIOS.items():
            cfg["wifi"].setdefault("radios", {})[rid] = {
                "enabled": True, "band": radio["band"], "channel": "auto",
                "channel_width": max(radio["widths"]), "tx_power": "auto",
                "dfs": radio["dfs"]}
        cfg["wifi"]["networks"]["main"] = {
            "ssid": "SBE-Net", "enabled": True, "hidden": False,
            "network": "default", "bands": ["2g", "5g", "6g"],
            "security": {"mode": "wpa3", "passphrase": "Demo-WiFi-Passphrase",
                         "pmf": "required"},
            "client_isolation": False, "bss_transition": True,
            "neighbor_report": True, "fast_roaming": True}
        cfg["wifi"]["networks"]["iot"] = {
            "ssid": "SBE-IoT", "enabled": True, "hidden": False,
            "network": "iot", "bands": ["2g"],
            "security": {"mode": "wpa2", "passphrase": "Demo-IoT-Passphrase",
                         "pmf": "optional"},
            "client_isolation": True, "bss_transition": False,
            "neighbor_report": False, "fast_roaming": False}
        cfg["networks"]["iot"] = {
            "name": "IoT", "purpose": "iot", "zone": "iot", "vlan": 40,
            "subnet": "192.168.40.1/24",
            "ipv6": {"mode": "disabled", "ra": False, "dhcpv6": False},
            "dhcp": {"enabled": True, "start": "192.168.40.100",
                     "end": "192.168.40.200", "lease_seconds": 86400,
                     "dns": [], "domain": "iot", "options": [], "reservations": []},
            "isolation": True, "igmp_snooping": True, "mdns": False,
            "internet_access": True, "wan": "auto"}
        cfg["wifi"]["mlds"]["mld0"] = {
            "name": "SBE-Net MLO", "enabled": True, "wireless_network": "main",
            "links": ["radio-2g", "radio-5g", "radio-6g"], "link_steering": "auto"}
        cfg["firewall"]["rules"] = [{
            "id": "block-iot-mgmt", "name": "Block IoT to management",
            "index": 1, "action": "drop", "src_zone": "iot",
            "dst_zone": "management", "protocol": "any", "family": "both",
            "enabled": True, "log": True}]
        cfg["nat"]["port_forwards"] = [{
            "id": "https", "name": "Web server", "enabled": True,
            "protocol": "tcp", "external_port": "8443",
            "internal_address": "192.168.2.20", "internal_port": "443",
            "wan": "any"}]

    config.stage(mutate)
    config.commit(user="system", summary="demo seed", confirm_required=False)
    parts["events"].emit("WAN_UP", subsystem="wan", data={"wan": "wan1"})
    parts["events"].emit("MLO_CLIENT_CONNECTED", subsystem="wifi",
                         data={"client": "3c:22:fb:aa:bb:cc", "mld": "mld0",
                               "link": 3})
    parts["events"].emit("DFS_CAC_COMPLETED", subsystem="wifi",
                         data={"radio": "radio-5g", "channel": 100})
    parts["events"].emit("AUTH_FAILED", subsystem="wifi",
                         data={"client": "aa:00:11:22:33:44", "ssid": "SBE-Net",
                               "reason": "SAE failure"})
    # A real scan needs hardware; seed a plausible RF environment instead so the
    # channel analyzer has something to draw.
    parts["wifid"]._rebuild_plan(parts["config"].get_running())
    parts["wifid"].seed_rf(parts["rf"])
    parts["rf"].scan = lambda cfg, **kw: {}      # never touch a real radio
    parts["rf"].refresh_survey = lambda cfg: None
    # `analyse` reads the live channel from nl80211; on a workstation there are
    # no radios, so report the stub's operating channels instead.
    # Point the ART reader at the real partition dumps so the Hardware page
    # shows genuine factory data instead of empty fields.
    from sbegw.adapters import art as art_module
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    art_img = os.path.join(fixtures, "art.img")
    env_img = os.path.join(fixtures, "appsblenv.img")
    if os.path.exists(art_img):
        art_module._partition_size = lambda dev: os.path.getsize(dev)
        art_module.art_device = lambda: art_img
        art_module._partition_by_name = (
            lambda names: env_img
            if names is art_module.UBOOT_ENV_PARTNAMES else art_img)

    from sbegw import rf as rf_module
    _CURRENT = {"wl2g0": (1, 20), "wl2g1": (1, 20),
                "wl5g0": (36, 160), "wl6g0": (37, 320)}
    rf_module.nl80211.interfaces = lambda: [
        {"name": name, "channel": ch, "width": w, "type": "AP",
         "frequency_mhz": rf_module.channel_to_freq(
             ch, "2g" if "2g" in name else "5g" if "5g" in name else "6g"),
         "mac": None, "ssid": None, "mld_mac": None, "txpower_dbm": 20.0}
        for name, (ch, w) in _CURRENT.items()]
    parts["sampler"].sample()


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.abspath(WEB), **kwargs)

    def log_message(self, *args):
        pass

    def end_headers(self):
        # Never cache during UI development, matching the device's nginx policy
        # for html/js/css.
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store, must-revalidate")
        super().end_headers()

    def _proxy(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(f"http://127.0.0.1:{API_PORT}{self.path}",
                                     data=body, method=method)
        for header in ("Content-Type", "Cookie", "X-CSRF-Token", "Accept",
                       "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req, timeout=60) as res:
                payload, status, headers = res.read(), res.status, res.headers
        except urllib.error.HTTPError as exc:
            payload, status, headers = exc.read(), exc.code, exc.headers
        except urllib.error.URLError as exc:
            payload = json.dumps({"error": {"code": "upstream",
                                            "message": str(exc)}}).encode()
            status, headers = 502, {}
        self.send_response(status)
        for header in ("Content-Type", "Set-Cookie"):
            value = headers.get(header) if hasattr(headers, "get") else None
            if value:
                self.send_header(header, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.startswith("/api/"):
            if self.path.rstrip("/").endswith("/stream"):
                # SSE through this simple proxy would block; the UI falls back
                # to interval polling when the stream is unavailable.
                self.send_response(501)
                self.end_headers()
                return
            return self._proxy("GET")
        return super().do_GET()

    def do_POST(self):
        self._proxy("POST")

    def do_PUT(self):
        self._proxy("PUT")

    def do_DELETE(self):
        self._proxy("DELETE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18100)
    parser.add_argument("--state", default=None)
    args = parser.parse_args()

    state = args.state or tempfile.mkdtemp(prefix="sbegw-demo-")
    ephemeral = args.state is None
    api, parts = stubs.build(state, port=API_PORT)
    api.start()
    seed(parts)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.daemon_threads = True
    print(f"UI    http://127.0.0.1:{args.port}/")
    print(f"login {USER} / {PASSWORD}")
    print(f"state {state}")
    print("ctrl-c to stop")
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        api.shutdown()
        if ephemeral:
            shutil.rmtree(state, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
