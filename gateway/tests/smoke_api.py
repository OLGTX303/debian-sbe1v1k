#!/usr/bin/env python3
"""API smoke test with stubbed hardware.

Runs the real ConfigStore, AuthManager, ChannelAnalyzer, ApiService and HTTP
server, with netd/wifid/clientd replaced by the shared stubs in stubs.py so the
test never touches the host's network. Covers auth, RBAC, CSRF, validation, the
transactional commit path, the MLO routes and the channel analyzer.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

STATE = tempfile.mkdtemp(prefix="sbegw-smoke-")
os.environ["SBEGW_STATE"] = STATE

from sbegw import rf                                        # noqa: E402
rf.STATE_DIR = STATE
rf.HISTORY_PATH = os.path.join(STATE, "channel-history.json")

import stubs                                                # noqa: E402

PASSED, FAILED = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


def msg(data):
    return str((data or {}).get("error", {}).get("message", ""))[:130]


# --------------------------------------------------------------------- wiring

server, parts = stubs.build(STATE, port=18099)
config = parts["config"]
netd, wifid, clients = parts["netd"], parts["wifid"], parts["clients"]
analyzer = parts["rf"]
# The analyzer reads wifid._plan and cached scan data; seed both so the channel
# routes have something real-shaped to work with.
wifid._rebuild_plan(config.get_running())
wifid.seed_rf(analyzer)
server.start()

BASE = "http://127.0.0.1:18099/api/v1"
COOKIE = {"value": None}
CSRF = {"value": None}


def request(method, path, body=None, *, auth_token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if COOKIE["value"]:
        req.add_header("Cookie", COOKIE["value"])
    if CSRF["value"] and method != "GET":
        req.add_header("X-CSRF-Token", CSRF["value"])
    if auth_token:
        req.add_header("Authorization", f"Bearer {auth_token}")
    try:
        with urllib.request.urlopen(req, timeout=25) as res:
            cookie = res.headers.get("Set-Cookie")
            if cookie:
                COOKIE["value"] = cookie.split(";")[0]
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def raw_request(method, path, body=None, *, csrf=None):
    """Bypass the automatic CSRF header so the check itself can be tested."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if COOKIE["value"]:
        req.add_header("Cookie", COOKIE["value"])
    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    try:
        with urllib.request.urlopen(req, timeout=25) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def msg(data):
    return str((data or {}).get("error", {}).get("message", ""))[:130]


# ------------------------------------------------------------------- the tests

print("\n--- auth ---")
status, data = request("GET", "/setup")
check("setup reports required", status == 200 and data.get("setup_required") is True)

status, data = request("GET", "/dashboard")
check("unauthenticated read is rejected", status == 401)

status, data = request("POST", "/setup", {"username": "admin", "password": "short"})
check("weak password rejected", status == 400, msg(data))

status, data = request("POST", "/setup",
                       {"username": "admin", "password": "Str0ng-Passw0rd!"})
check("owner created", status == 200 and data.get("ok"), msg(data))
CSRF["value"] = data.get("csrf")

status, data = request("GET", "/auth/self")
check("session works", status == 200 and data["user"]["role"] == "owner")

status, data = request("POST", "/setup",
                       {"username": "x", "password": "Str0ng-Passw0rd!"})
check("second setup refused", status == 409)

print("\n--- csrf ---")
status, _ = raw_request("PUT", "/ports/eth0", {"mtu": 1500})
check("mutation without CSRF is refused", status == 403)
status, _ = raw_request("PUT", "/ports/eth0", {"mtu": 1500}, csrf="wrong")
check("mutation with bad CSRF is refused", status == 403)

print("\n--- validation and commit ---")
status, data = request("GET", "/dashboard")
check("dashboard loads", status == 200 and "internet" in data, str(data)[:120])

status, data = request("PUT", "/networks/default", {"subnet": "not-an-ip"})
check("bad subnet rejected with a field path",
      status == 422 and data.get("error", {}).get("details", {})
      .get("path") == "networks.default.subnet", msg(data))

status, data = request("POST", "/networks", {
    "id": "guest", "name": "Guest", "purpose": "guest", "zone": "guest",
    "vlan": 20, "subnet": "192.168.20.1/24",
    "dhcp": {"enabled": True, "start": "192.168.20.100", "end": "192.168.20.200"}})
check("network created", status == 200, msg(data))

status, data = request("POST", "/networks", {
    "id": "overlap", "vlan": 21, "subnet": "192.168.20.5/24", "dhcp": {"enabled": False}})
check("overlapping subnet rejected", status == 422, msg(data))

status, data = request("POST", "/networks", {
    "id": "dupvlan", "vlan": 20, "subnet": "192.168.30.1/24", "dhcp": {"enabled": False}})
check("duplicate VLAN rejected", status == 422, msg(data))

status, data = request("POST", "/networks", {
    "id": "badpool", "vlan": 30, "subnet": "192.168.30.1/24",
    "dhcp": {"enabled": True, "start": "192.168.30.1", "end": "192.168.30.100"}})
check("DHCP pool containing the gateway rejected", status == 422, msg(data))

print("\n--- traffic and DNS services ---")
status, data = request("GET", "/services")
check("service settings load", status == 200 and "qos" in data and "dns" in data,
      msg(data))
check("service runtime status is explicit",
      "qos" in data.get("status", {}) and "dns" in data.get("status", {}),
      str(data.get("status")))

status, data = request("PUT", "/services", {
    "qos": {"enabled": True, "download_kbps": 0, "upload_kbps": 0}})
check("Smart Queues require a line rate",
      status == 422 and data.get("error", {}).get("details", {}).get("path") == "qos",
      msg(data))

status, data = request("PUT", "/services", {"dns": {"upstream": ["not-an-ip"]}})
check("invalid DNS resolver is rejected with its field path",
      status == 422 and data.get("error", {}).get("details", {}).get("path")
      == "dns.upstream[0]", msg(data))

status, data = request("PUT", "/services", {"dns": {"records": [
    {"name": "safe.lan", "type": "TXT", "value": "ok\nserver=203.0.113.53"}]}})
check("DNS record values cannot inject dnsmasq directives",
      status == 422 and data.get("error", {}).get("details", {}).get("path")
      == "dns.records[0].value", msg(data))

status, data = request("PUT", "/services", {
    "qos": {"enabled": True, "download_kbps": 900000, "upload_kbps": 90000},
    "dns": {"upstream": ["1.1.1.1", "2606:4700:4700::1111"],
            "dnssec": True,
            "filtering": {"enabled": True,
                          "blocklist": ["Telemetry.Example.com"],
                          "allowlist": ["allowed.example.com"]},
            "records": [{"name": "printer.lan", "type": "A",
                         "value": "192.168.2.20"}],
            "conditional_forwarders": [{"domain": "corp.example",
                                         "server": "10.0.0.53"}]}})
check("Smart Queues and DNS settings commit together", status == 200, msg(data))
status, data = request("GET", "/services")
check("service settings round-trip",
      status == 200 and data.get("qos", {}).get("download_kbps") == 900000
      and data.get("dns", {}).get("dnssec") is True,
      str(data)[:160])
check("DNS names are normalised",
      data.get("dns", {}).get("filtering", {}).get("blocklist")
      == ["telemetry.example.com"], str(data.get("dns", {}).get("filtering")))

print("\n--- DPI and controller configuration ---")
status, data = request("GET", "/dpi")
check("DPI endpoint reports unavailable stub explicitly",
      status == 200 and data.get("status", {}).get("running") is False, msg(data))
status, data = request("PUT", "/dpi", {"enabled": False,
                                        "retention_hours": 48})
check("DPI settings commit", status == 200, msg(data))
status, data = request("GET", "/controller")
check("controller endpoint exposes pairing state",
      status == 200 and "state" in data and "crypto_available" in data, msg(data))
status, data = request("PUT", "/controller", {
    "enabled": True, "inform_url": "not-a-controller"})
check("invalid inform URL is rejected",
      status == 422 and data.get("error", {}).get("details", {}).get("path")
      == "controller.inform_url", msg(data))
status, data = request("PUT", "/controller", {
    "enabled": True, "inform_url": "http://192.0.2.20:8080/inform",
    "sync_enabled": True,
    "api_url": "https://192.0.2.20/proxy/network/integration/v1",
    "api_key": "controller-secret-value",
    "site_id": "01234567-89ab-cdef-0123-456789abcdef"})
check("valid controller settings commit", status == 200, msg(data))
status, data = request("GET", "/controller")
check("controller API key is redacted",
      status == 200 and data.get("config", {}).get("api_key") == "********",
      str(data.get("config")))

print("\n--- wifi and MLO ---")
status, data = request("POST", "/wifi/networks", {
    "id": "main", "ssid": "SBE-Net", "bands": ["2g", "5g", "6g"], "network": "default",
    "security": {"mode": "wpa3", "passphrase": "Str0ng-WiFi-Pass", "pmf": "required"}})
check("tri-band WPA3 SSID created", status == 200, msg(data))

status, data = request("POST", "/wifi/networks", {
    "id": "bad6g", "ssid": "Bad6", "bands": ["6g"], "network": "default",
    "security": {"mode": "wpa2", "passphrase": "Str0ng-WiFi-Pass"}})
check("6 GHz + WPA2 rejected", status == 422, msg(data))

status, data = request("POST", "/wifi/mlo", {
    "id": "mld0", "name": "Main MLO", "wireless_network": "main",
    "links": ["radio-5g", "radio-6g"]})
check("MLD created with two links", status == 200, msg(data))

status, data = request("PUT", "/wifi/mlo/mld0", {"links": ["radio-5g"]})
check("single-link MLD rejected", status == 422, msg(data))

status, data = request("PUT", "/wifi/mlo/mld0",
                       {"links": ["radio-2g", "radio-5g", "radio-6g"]})
check("tri-link MLD accepted", status == 200, msg(data))

status, data = request("GET", "/wifi/mlo")
mld = (data.get("items") or [{}])[0]
check("MLO state reports per-link detail",
      status == 200 and len(mld.get("state", {}).get("links", [])) == 3,
      json.dumps(mld.get("state", {}).get("links", []))[:120])
check("MLO capability advertised", data.get("capability", {}).get("supported") is True)

status, data = request("POST", "/wifi/mlo", {
    "id": "mld1", "name": "Second", "wireless_network": "main",
    "links": ["radio-5g", "radio-6g"]})
check("radio cannot join two MLDs for the same SSID", status == 422, msg(data))

print("\n--- channel analyzer ---")
status, data = request("GET", "/wifi/channels")
check("channel analysis returns a radio per phy",
      status == 200 and len(data.get("radios", [])) == 3,
      f"{len(data.get('radios', []))} radios")
if status == 200 and data.get("radios"):
    five = next((r for r in data["radios"] if r["band"] == "5g"), {})
    check("channels are scored", len(five.get("channels", [])) > 10,
          f"{len(five.get('channels', []))} channels")
    check("5 GHz advertises 240 MHz capability",
          five.get("supports_240") is True, str(five.get("supports_240")))
    check("a recommendation with reasons is returned",
          bool(five.get("recommendation", {}).get("reasons")),
          str(five.get("recommendation", {}).get("reasons")))
    check("unmeasured channels report null utilisation, not a guess",
          any(c.get("utilisation_percent") is None
              for c in five.get("channels", [])))

status, data = request("POST", "/wifi/channels/optimize",
                       {"dry_run": True, "rescan": False, "force": True})
check("dry-run optimise reports without switching",
      status == 200 and all(not r["switched"] for r in data.get("radios", [])),
      str([r.get("detail") for r in data.get("radios", [])])[:120])

status, data = request("PUT", "/wifi/channels/settings",
                       {"enabled": True, "min_improvement": 25.0,
                        "min_interval_seconds": 3600, "schedule_hour": 3})
check("channel optimisation settings commit", status == 200, msg(data))
status, data = request("GET", "/wifi/channels")
check("settings are reflected back",
      data.get("settings", {}).get("min_improvement") == 25.0,
      str(data.get("settings")))

status, data = request("PUT", "/wifi/channels/settings", {"schedule_hour": 99})
check("out-of-range schedule hour rejected", status == 422, msg(data))

status, data = request("GET", "/wifi/channels/history")
check("channel history endpoint works", status == 200 and "items" in data)

print("\n--- 240 MHz over the API ---")
status, data = request("PUT", "/wifi/radios/radio-5g", {"channel_width": 240})
check("240 MHz accepted on the capable 5 GHz radio", status == 200, msg(data))
status, data = request("PUT", "/wifi/radios/radio-6g", {"channel_width": 240})
check("240 MHz rejected on 6 GHz", status == 422, msg(data))
status, data = request("PUT", "/wifi/radios/radio-2g", {"channel_width": 240})
check("240 MHz rejected on 2.4 GHz", status == 422, msg(data))

print("\n--- secrets ---")
status, data = request("GET", "/config")
blob = json.dumps(data)
check("passphrase never leaves the API", "Str0ng-WiFi-Pass" not in blob)
check("password hash never leaves the API", "scrypt$" not in blob)
check("controller API key never leaves the config API",
      "controller-secret-value" not in blob)

status, data = request("GET", "/wifi/networks")
check("SSID list redacts the passphrase", "Str0ng-WiFi-Pass" not in json.dumps(data))

print("\n--- audit and revisions ---")
status, data = request("GET", "/audit")
entries = data.get("items", [])
check("commits are audited", status == 200 and len(entries) >= 3, f"{len(entries)} entries")
check("audit redacts secrets in the diff", "Str0ng-WiFi-Pass" not in json.dumps(entries))
check("audit redacts controller API keys",
      "controller-secret-value" not in json.dumps(entries))

status, data = request("GET", "/config/revisions")
check("revision history recorded", status == 200 and len(data.get("items", [])) >= 3)

print("\n--- rbac ---")
status, _ = request("POST", "/users", {"username": "viewer",
                                       "password": "V1ewer-Passw0rd!",
                                       "role": "read-only"})
check("read-only user created", status == 200)

owner_cookie, owner_csrf = COOKIE["value"], CSRF["value"]
COOKIE["value"] = CSRF["value"] = None
status, data = request("POST", "/auth/login",
                       {"username": "viewer", "password": "V1ewer-Passw0rd!"})
check("read-only user can sign in", status == 200)
CSRF["value"] = data.get("csrf")

status, _ = request("GET", "/dashboard")
check("read-only can read the dashboard", status == 200)
status, data = request("PUT", "/ports/eth0", {"mtu": 1500})
check("read-only cannot write", status == 403, msg(data))
status, _ = request("GET", "/users")
check("read-only cannot manage users", status == 403)

status, data = request("POST", "/auth/login", {"username": "viewer", "password": "wrong"})
check("wrong password rejected", status == 401)

COOKIE["value"], CSRF["value"] = owner_cookie, owner_csrf

print("\n--- misc routes ---")
for path in ("/system", "/platform", "/ports", "/networks", "/wans", "/firewall",
             "/wifi/channels", "/wifi/channels/history",
             "/nat", "/routing", "/services", "/wifi", "/wifi/radios", "/wifi/clients",
             "/clients", "/dpi", "/controller", "/telemetry", "/events",
             "/topology", "/health",
             "/rbac", "/backups/export", "/config/pending"):
    status, _ = request("GET", path)
    check(f"GET {path}", status == 200)

status, data = request("GET", "/nope")
check("unknown route 404s with an error envelope", status == 404 and "error" in data)
status, data = request("DELETE", "/system")
check("wrong method 405s", status == 405)

status, data = request("GET", "/topology")
kinds = {n["type"] for n in data.get("nodes", [])}
check("topology is rooted at the internet",
      "internet" in kinds and "gateway" in kinds, str(sorted(kinds)))

print("\n--- wireless network form contract ---")
# The Create-New-WiFi form reads these shapes; a change here breaks the UI
# silently, so assert them.
status, radios = request("GET", "/wifi/radios")
check("GET /wifi/radios carries the MLO capability",
      isinstance(radios.get("mlo"), dict), msg(radios))
check("...with a supported flag", "supported" in (radios.get("mlo") or {}),
      str(radios.get("mlo")))
check("each radio exposes its band",
      all(r.get("band") for r in radios.get("items", [])),
      str([r.get("band") for r in radios.get("items", [])]))

# Everything the form posts must round-trip.
form_body = {
    "id": "formtest", "ssid": "Form-Test", "network": "default",
    "bands": ["5g", "6g"],
    "security": {"mode": "wpa3", "passphrase": "Str0ng-WiFi-Pass",
                 "pmf": "required", "private_preshared_keys": False,
                 "sae_anti_clogging_threshold": 7, "sae_sync": 9},
    "broadcasting_aps": "all", "application": "hotspot",
    "advanced_mode": "manual", "fast_roaming": True,
    "minimum_data_rate": True, "multicast_filtering": "auto",
    "multicast_broadcast_blocker": True, "multicast_to_unicast": True,
    "hidden": True, "client_isolation": True, "mlo": True,
    "band_steering": False, "proxy_arp": True, "bss_transition": False,
    "uapsd": True, "mac_filter": False, "radius_mac_auth": False,
    "speed_limit": True, "auto_dtim": False, "dtim_period": 3,
    "group_rekey_interval": True, "group_rekey_seconds": 1800,
    "show_ap_name_in_beacon": False,
    "blackout_schedule": {"enabled": True},
}
status, data = request("POST", "/wifi/networks", form_body)
check("the full form payload is accepted", status == 200, msg(data))

status, listing = request("GET", "/wifi/networks")
saved = next((i["config"] for i in listing.get("items", [])
              if i["id"] == "formtest"), {})
for key in ("application", "advanced_mode", "multicast_filtering",
            "multicast_broadcast_blocker", "multicast_to_unicast",
            "minimum_data_rate", "mlo", "band_steering", "proxy_arp",
            "uapsd", "speed_limit", "auto_dtim", "dtim_period",
            "group_rekey_interval", "group_rekey_seconds"):
    ok = saved.get(key) == form_body[key]
    check(f"{key} round-trips", ok,
          "" if ok else f"{saved.get(key)!r} != {form_body[key]!r}")
check("SAE tuning round-trips",
      saved.get("security", {}).get("sae_anti_clogging_threshold") == 7
      and saved.get("security", {}).get("sae_sync") == 9,
      str(saved.get("security")))
check("the blackout schedule round-trips",
      (saved.get("blackout_schedule") or {}).get("enabled") is True)

# The MLO listing must expose whether each MLD was declared or derived from an
# SSID's `mlo` flag. (Derivation itself runs in WifiDaemon.build_plan, which this
# harness stubs out — smoke_rf covers it against the real daemon.)
status, mlo = request("GET", "/wifi/mlo")
check("the MLO listing marks each entry declared or derived",
      all("derived" in m for m in mlo.get("items", [])), str(mlo.get("items"))[:200])
check("the MLO listing names each entry's wireless network",
      all("wireless_network" in m for m in mlo.get("items", [])))

# MLO with one band must be refused, not silently downgraded.
status, data = request("PUT", "/wifi/networks/formtest", {"bands": ["5g"]})
check("MLO with a single band is rejected", status == 422, msg(data))

status, data = request("DELETE", "/wifi/networks/formtest")
check("the test SSID is removed", status == 200, msg(data))

print("\n--- regulatory environment ---")
status, reg = request("GET", "/wifi/regulatory")
check("GET /wifi/regulatory works", status == 200, msg(reg))
check("it defaults to indoor / LPI",
      reg.get("environment") == "indoor" and reg.get("six_ghz_power") == "lpi",
      str(reg))

status, data = request("PUT", "/wifi/regulatory",
                       {"environment": "outdoor", "six_ghz_power": "sp"})
check("outdoor + standard power is accepted", status == 200, msg(data))
check("standard power warns about AFC",
      any("AFC" in w for w in (data.get("warnings") or [])),
      str(data.get("warnings")))

status, reg = request("GET", "/wifi/regulatory")
check("the setting round-trips",
      reg.get("environment") == "outdoor" and reg.get("six_ghz_power") == "sp",
      str(reg))

status, data = request("PUT", "/wifi/regulatory",
                       {"environment": "outdoor", "six_ghz_power": "lpi"})
check("outdoor with indoor-only power warns",
      any("indoor-only" in w for w in (data.get("warnings") or [])),
      str(data.get("warnings")))

status, data = request("PUT", "/wifi/regulatory", {"environment": "space"})
check("an unknown environment is rejected", status == 422, msg(data))

request("PUT", "/wifi/regulatory",
        {"environment": "indoor", "six_ghz_power": "lpi"})

print("\n--- applier invocation ---")
check("netd applied on each commit", netd.applies >= 4, f"{netd.applies} applies")
check("wifid applied on each commit", wifid.applies >= 4, f"{wifid.applies} applies")

server.shutdown()
shutil.rmtree(STATE, ignore_errors=True)


print("\n--- the SSID editor exposes per-SSID settings ---")
# uplink is the one per-SSID setting that changes where a client's address
# comes from, so it has to be editable in the SSID dialog rather than only in
# the config file.
_app = open(os.path.join(os.path.dirname(__file__), "..", "web", "app.js")).read()
check("the SSID dialog has a client-addressing control",
      "Client Addressing" in _app and "uplink" in _app)
check("...offering both LAN and WAN", "'lan'" in _app and "'wan'" in _app)
check("...and it is sent to the API",
      "uplink: uplink.value()" in _app, "the control would not persist")
# Choosing it gives up NAT, DHCP and management access for those clients, and
# needs a reboot for the WAN bridge, so the dialog has to say so.
check("the dialog warns what WAN bridging costs",
      "upstream gateway" in _app and "management interface" in _app)
check("...including that it needs a reboot",
      "needs a reboot" in _app)
# A WAN-bridged SSID is on no network of ours; showing one would mislead.
check("the SSID list marks WAN-bridged SSIDs instead of naming a network",
      "'WAN bridge'" in _app)

print("\n--- traffic and DNS UI contract ---")
check("navigation exposes Traffic & DNS", "Traffic & DNS" in _app)
check("the page saves both service domains",
      "body: { qos:" in _app and "body: { dns:" in _app)
check("the page exposes local records and conditional forwarding",
      "Local DNS records" in _app and "Conditional forwarding" in _app)
# The rail item was renamed from "UniFi Network" to "Controller": the page
# integrates with a controller, it is not this product's identity. The nav
# still has to expose both screens.
check("navigation exposes DPI and controller control",
      "'Traffic Identification'" in _app and "'Controller'" in _app,
      "nav labels changed without the test following")
check("DPI is a first-class primary navigation section",
      "id: 'dpi', name: 'DPI', ico: 'spectrum', featured: true" in _app)
check("the DPI page shows production traffic summaries",
      "Deep Packet Inspection" in _app and "Identified traffic" in _app
      and "Active clients" in _app and "Share" in _app
      and "Categories" in _app and "Accepted flows" in _app)
check("dashboard renders a live physical port panel",
      "function portMap(ports)" in _app and "port-jack" in _app
      and "Live link, negotiated speed and traffic" in _app)
check("the controller API key is a password field",
      "type: 'password', value: ''" in _app and "Network API key" in _app)

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
