"""Configuration schema, defaults and validation.

The gateway keeps a single JSON document as its configuration. Validation here
is the *only* gate between an API request and the candidate config, so it has to
reject regulatory- and protocol-invalid combinations (notably 6 GHz security and
MLO link composition) rather than letting hostapd fail at apply time.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

SCHEMA_VERSION = 4

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/+-]{0,62}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}$")

PORT_ROLES = ("lan", "wan", "disabled")
NETWORK_PURPOSES = ("corporate", "guest", "iot", "voice", "management", "dmz", "vpn")
# "containers" holds Docker-managed bridges. sbegw's forward chain is
# policy-drop, so without a zone of its own a container gets no network at all:
# Docker's own iptables rules and this ruleset attach to the same netfilter
# hooks, and a drop in either one wins.
ZONES = ("wan", "lan", "gateway", "vpn", "guest", "iot", "dmz", "management",
         "containers")
WAN_MODES = ("dhcp", "static", "pppoe", "disabled")
WAN_IPV6_MODES = ("disabled", "dhcpv6", "dhcpv6-pd", "slaac", "static")
FW_ACTIONS = ("allow", "reject", "drop")
BANDS = ("2g", "5g", "6g")
# 240 MHz is a Qualcomm/QSDK extension: 320 MHz EHT operation with one 80 MHz
# block preamble-punctured. It is only offered when the driver reports EHT240.
WIDTHS = (20, 40, 80, 160, 240, 320)
SECURITY_MODES = (
    "open", "wpa2", "wpa2-wpa3", "wpa3", "wpa2-enterprise", "wpa3-enterprise",
)
# 6 GHz forbids anything without SAE/PMF. Wi-Fi Alliance requires WPA3-only
# (or OWE) plus PMF on that band; TKIP and plain WPA2-PSK are illegal.
SIX_GHZ_SECURITY = ("wpa3", "wpa3-enterprise", "open-owe")
STEERING_POLICIES = ("balanced", "prefer-5g", "prefer-6g", "performance", "disabled")
# Wireless-network presets. "hotspot" and "iot" only change defaults the operator
# can still override; they do not gate any capability.
APPLICATIONS = ("standard", "hotspot", "iot")
# Which APs broadcast the SSID. This gateway is a single AP, so "all" is the only
# meaningful value today; the field exists so a saved config survives unchanged
# if AP groups are added later.
BROADCASTING_APS = ("all", "group", "specific")
ADVANCED_MODES = ("auto", "manual")
MULTICAST_FILTERING = ("off", "auto", "custom")
# Regulatory environment. Note this is not a power dial: it selects which rule
# set applies. On 6 GHz the power *type* is what changes the limit.
RF_ENVIRONMENTS = ("indoor", "outdoor", "any")
SIX_GHZ_POWER_MODES = ("lpi", "sp", "vlp")
ROLES = (
    "owner", "super-admin", "network-admin", "security-admin", "helpdesk", "read-only",
)


class ValidationError(ValueError):
    """Raised with a field path so the UI can point at the offending input."""

    def __init__(self, path: str, message: str):
        self.path = path
        super().__init__(f"{path}: {message}")


def default_config() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "system": {
            "mode": "gateway",
            # See _validate_system: duty-only fan, kernel governor underneath.
            "fan": {"mode": "auto", "manual_percent": 50},
            "leds": {"mode": "status", "brightness": 100},
            "hostname": "sbe1v1k",
            "timezone": "UTC",
            "ntp": {"enabled": True, "servers": ["pool.ntp.org", "time.cloudflare.com"]},
            "led": {"enabled": True, "brightness": 100},
            "setup_complete": False,
        },
        "ports": {
            # eth0/eth1 QCA8075 1G, eth2 QCA8081 2.5G, eth3 RTL8261 10G.
            "eth0": {"role": "lan", "name": "LAN 1", "enabled": True, "mtu": 1500,
                     "speed": "auto", "duplex": "auto", "flow_control": True, "network": "default",
                     "tagged_vlans": []},
            "eth1": {"role": "lan", "name": "LAN 2", "enabled": True, "mtu": 1500,
                     "speed": "auto", "duplex": "auto", "flow_control": True, "network": "default",
                     "tagged_vlans": []},
            "eth2": {"role": "lan", "name": "LAN 3 (2.5G)", "enabled": True, "mtu": 1500,
                     "speed": "auto", "duplex": "auto", "flow_control": True, "network": "default",
                     "tagged_vlans": []},
            "eth3": {"role": "wan", "name": "WAN (10G)", "enabled": True, "mtu": 1500,
                     "speed": "auto", "duplex": "auto", "flow_control": True, "network": None,
                     "tagged_vlans": []},
        },
        "networks": {
            "default": {
                "name": "Default",
                "purpose": "corporate",
                "vlan": None,
                "zone": "lan",
                "subnet": "192.168.2.1/24",
                "ipv6": {"mode": "dhcpv6-pd", "prefix_id": 0, "ra": True, "dhcpv6": True},
                "dhcp": {
                    "enabled": True,
                    "start": "192.168.2.100",
                    "end": "192.168.2.250",
                    "lease_seconds": 86400,
                    "dns": [],
                    "domain": "lan",
                    "options": [],
                    "reservations": [],
                },
                "isolation": False,
                "igmp_snooping": True,
                "mdns": True,
                "internet_access": True,
                "wan": "auto",
            }
        },
        "wans": {
            "wan1": {
                "name": "WAN 1",
                "port": "eth3",
                "mode": "dhcp",
                "vlan": None,
                "priority": 1,
                "weight": 1,
                "enabled": True,
                "mtu": 1500,
                "mss_clamp": True,
                "mac_clone": None,
                "static": {"address": None, "gateway": None, "dns": []},
                "pppoe": {"username": None, "password": None, "service": None, "mru": 1492},
                "ipv6": {"mode": "dhcpv6-pd", "prefix_hint": None},
                "dns": [],
                "health": {
                    "enabled": True,
                    "targets": ["1.1.1.1", "8.8.8.8"],
                    "dns_target": "one.one.one.one",
                    "interval": 5,
                    "loss_threshold": 40,
                    "latency_threshold_ms": 400,
                },
            }
        },
        "multiwan": {"mode": "failover", "sticky_sessions": True},
        "firewall": {
            # Qualcomm ECM offload breaks client forwarding on this board; see
            # _validate_firewall for the measurements.
            "hardware_offload": False,
            # Interfaces created by a third-party tunnel or proxy (ShellCrash's
            # utun, WireGuard, Tailscale) belong to no zone, so a LAN client
            # routed into one matched no zone pair and hit the forward policy
            # drop: the client could reach the gateway but not the internet, and
            # the tun showed RX 0 because packets died before delivery. These
            # patterns are treated as WAN egress. They are nft wildcards, so a
            # tunnel that appears after the ruleset is applied is still covered.
            "tunnel_interfaces": ["tun*", "utun*", "wg*", "tailscale*"],
            "default_policies": {
                "lan->wan": "allow", "lan->gateway": "allow", "lan->lan": "allow",
                "guest->wan": "allow", "guest->lan": "drop", "guest->gateway": "reject",
                "iot->wan": "allow", "iot->lan": "drop", "iot->gateway": "reject",
                "wan->lan": "drop", "wan->gateway": "drop",
                # Containers reach the internet but not the LAN, and may use
                # the gateway only for DNS/DHCP (handled in the input chain).
                "containers->wan": "allow", "containers->lan": "drop",
                "containers->gateway": "reject",
            },
            "rules": [],
            "groups": {"address": {}, "port": {}, "mac": {}, "domain": {}},
            "schedules": {},
        },
        "nat": {"masquerade": True, "hairpin": True, "port_forwards": [], "one_to_one": []},
        "routing": {"static": [], "ecmp": False, "frr": {"enabled": False, "ospf": {}, "bgp": {}}},
        "policy_routes": [],
        "qos": {"enabled": False, "engine": "cake", "download_kbps": 0, "upload_kbps": 0,
                "per_client_limits": []},
        "dns": {
            "upstream": ["1.1.1.1", "8.8.8.8"],
            "cache_size": 4096,
            "dnssec": False,
            "filtering": {"enabled": False, "block_malware": True, "block_ads": False,
                          "allowlist": [], "blocklist": []},
            "records": [],
            "conditional_forwarders": [],
            "query_log": False,
        },
        "dpi": {
            "enabled": False,
            "engine": "suricata",
            "retention_hours": 24,
            "include_ipv6": True,
        },
        "controller": {
            "enabled": False,
            "inform_url": "",
            "discovery": True,
            # Pull desired state from the controller's documented local API.
            # The key is redacted by every ordinary API/config view.
            "sync_enabled": False,
            "api_url": "",
            "api_key": "",
            "site_id": "",
            "verify_tls": True,
            "interval_seconds": 10,
        },
        "services": {
            "mdns": {"enabled": False, "networks": []},
            "upnp": {"enabled": False, "networks": []},
            "igmp_proxy": {"enabled": False, "upstream": None},
            "ssh": {"enabled": True, "port": 22},
        },
        "wifi": {
            "country": "US",
            "radios": {},          # keyed by logical radio id, populated on discovery
            "networks": {},        # SSID / WirelessNetwork objects
            "mlds": {},            # MLO multi-link devices
            "rf_profiles": {
                "default": {
                    "name": "Default",
                    "channel_width": {"2g": 20, "5g": 80, "6g": 160},
                    "tx_power": {"2g": "auto", "5g": "auto", "6g": "auto"},
                    "min_rssi": None,
                    "band_steering": "balanced",
                    "dfs": True,
                    "client_limit": None,
                }
            },
            "radius": {},
            "ppsk": {},
            "regulatory": {"environment": "indoor", "six_ghz_power": "lpi"},
            "channel_optimisation": {
                # Off by default: an unattended channel change is disruptive, so
                # the operator opts in. See rf.py for the scoring model.
                "enabled": False,
                "min_interval_seconds": 21600,
                "min_improvement": 15.0,
                "avoid_dfs": False,
                "prefer_psc": True,
                "schedule_hour": 4,
            },
        },
        "vpn": {"wireguard": {}, "ipsec": {}, "openvpn": {}},
        "users": {},
        "api_tokens": {},
    }


# --------------------------------------------------------------------------
# primitive validators
# --------------------------------------------------------------------------

def _need(obj: Any, path: str, kind: type | tuple[type, ...], what: str) -> Any:
    if not isinstance(obj, kind):
        raise ValidationError(path, f"expected {what}")
    return obj


def v_id(value: Any, path: str) -> str:
    _need(value, path, str, "an identifier string")
    if not ID_RE.match(value):
        raise ValidationError(path, "must be lowercase alphanumeric with dashes, <=39 chars")
    return value


def v_name(value: Any, path: str) -> str:
    _need(value, path, str, "a name string")
    if not NAME_RE.match(value):
        raise ValidationError(path, "1-63 chars, letters/digits/space/._- only")
    return value


def v_enum(value: Any, path: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise ValidationError(path, f"must be one of {', '.join(allowed)}")
    return value


def v_int(value: Any, path: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(path, "expected an integer")
    if not low <= value <= high:
        raise ValidationError(path, f"must be between {low} and {high}")
    return value


def v_bool(value: Any, path: str) -> bool:
    return _need(value, path, bool, "a boolean")


def v_vlan(value: Any, path: str) -> int | None:
    if value is None:
        return None
    return v_int(value, path, 1, 4094)


def v_mac(value: Any, path: str) -> str:
    _need(value, path, str, "a MAC address")
    mac = value.strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValidationError(path, "must be aa:bb:cc:dd:ee:ff")
    return mac


def v_ip(value: Any, path: str, version: int | None = None) -> str:
    _need(value, path, str, "an IP address")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(path, str(exc)) from exc
    if version and addr.version != version:
        raise ValidationError(path, f"must be IPv{version}")
    return str(addr)


def v_cidr(value: Any, path: str, version: int | None = None) -> str:
    _need(value, path, str, "an address in CIDR form")
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise ValidationError(path, str(exc)) from exc
    if version and iface.version != version:
        raise ValidationError(path, f"must be IPv{version}")
    if iface.network.prefixlen == iface.max_prefixlen:
        raise ValidationError(path, "needs a subnet prefix, e.g. 192.168.2.1/24")
    return str(iface)


def v_port_range(value: Any, path: str) -> str:
    """Accept `80`, `80-90`."""
    text = str(value).strip()
    parts = text.split("-")
    if len(parts) > 2:
        raise ValidationError(path, "expected port or port-port")
    try:
        nums = [int(p) for p in parts]
    except ValueError as exc:
        raise ValidationError(path, "ports must be numeric") from exc
    for num in nums:
        if not 1 <= num <= 65535:
            raise ValidationError(path, "ports must be 1-65535")
    if len(nums) == 2 and nums[0] > nums[1]:
        raise ValidationError(path, "range start must not exceed end")
    return text


def v_psk(value: Any, path: str) -> str:
    _need(value, path, str, "a passphrase")
    if not 8 <= len(value) <= 63:
        raise ValidationError(path, "WPA passphrase must be 8-63 characters")
    return value


def v_ssid(value: Any, path: str) -> str:
    _need(value, path, str, "an SSID")
    raw = value.encode("utf-8")
    if not 1 <= len(raw) <= 32:
        raise ValidationError(path, "SSID must be 1-32 bytes of UTF-8")
    return value


# --------------------------------------------------------------------------
# document validation
# --------------------------------------------------------------------------

def validate(cfg: dict[str, Any], *, capabilities: dict[str, Any] | None = None) -> list[str]:
    """Validate a full config document in place-ish, returning warnings.

    Raises ValidationError on anything that must not be applied. Warnings cover
    cases the hardware may silently downgrade (spec: runtime vs desired state) —
    those are surfaced in the UI instead of blocking the commit.
    """
    caps = capabilities or {}
    warnings: list[str] = []

    _need(cfg, "config", dict, "an object")
    warnings += _validate_system(cfg.setdefault("system", {}))
    _validate_ports(cfg.setdefault("ports", {}), cfg)
    _validate_networks(cfg.setdefault("networks", {}), cfg)
    warnings += _validate_wans(cfg.setdefault("wans", {}), cfg)
    _validate_firewall(cfg.setdefault("firewall", {}), cfg)
    _validate_nat(cfg.setdefault("nat", {}), cfg)
    _validate_routing(cfg.setdefault("routing", {}))
    _validate_qos(cfg.setdefault("qos", {}), cfg)
    _validate_dns(cfg.setdefault("dns", {}))
    warnings += _validate_dpi(cfg.setdefault("dpi", {}), cfg)
    _validate_controller(cfg.setdefault("controller", {}))
    warnings += _validate_wifi(cfg.setdefault("wifi", {}), cfg, caps)
    _validate_users(cfg.setdefault("users", {}))
    return warnings


# "auto" hands the fan to the kernel's step_wise governor, which the board's
# device tree already programs sensibly (levels 36/72/128/255 at 40/50/65/80C).
# That governor stays bound in every mode, so it can always raise the duty on a
# trip crossing — these modes only ever set a floor above it.
# "ap" turns the device into a plain access point: the WAN port joins the LAN
# bridge, so Wi-Fi and wired clients sit directly on the upstream L2 and take
# their addresses from the upstream gateway. No NAT, no DHCP server, no
# routing of our own — which is the point, because it lets the upstream box
# (and whatever proxy runs on it) see and police every client individually.
DEVICE_MODES = ("gateway", "ap")

# Per-SSID: which side of the router its clients live on.
SSID_UPLINKS = ("lan", "wan")

FAN_MODES = ("auto", "quiet", "balanced", "cool", "max", "manual")
# "status" shows health, "identify" blinks to locate the unit in a rack.
LED_MODES = ("status", "identify", "off")


def _validate_system(system: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    v_enum(system.setdefault("mode", "gateway"), "system.mode", DEVICE_MODES)
    if system["mode"] == "ap":
        warnings.append(
            "AP mode: the WAN port joins the LAN bridge, NAT and the DHCP "
            "server are off, and clients are addressed by the upstream "
            "gateway. This device keeps its LAN address for management and "
            "also asks upstream for one.")
    system.setdefault("hostname", "sbe1v1k")
    hostname = system["hostname"]
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$", str(hostname)):
        raise ValidationError("system.hostname", "invalid hostname")
    ntp = system.setdefault("ntp", {"enabled": True, "servers": []})
    v_bool(ntp.setdefault("enabled", True), "system.ntp.enabled")
    for i, server in enumerate(ntp.setdefault("servers", [])):
        _need(server, f"system.ntp.servers[{i}]", str, "a hostname or IP")

    # Fan. The board has a pwm-fan with no tachometer, so a duty is the only
    # thing that can be asked for or reported — there is no RPM to target.
    # The kernel's step_wise governor stays bound to the same fan through the
    # thermal trip points and remains the safety net under all of these.
    fan = system.setdefault("fan", {})
    _need(fan, "system.fan", dict, "an object")
    v_enum(fan.setdefault("mode", "auto"), "system.fan.mode", FAN_MODES)
    v_int(fan.setdefault("manual_percent", 50), "system.fan.manual_percent", 0, 100)
    # The board's cooling-levels start at 36/255. A manual duty below that may
    # leave the fan powered but stalled, so hwd raises it to the floor and this
    # warns rather than silently disagreeing with what was asked for.
    if fan["mode"] == "manual" and 0 < fan["manual_percent"] < 14:
        warnings.append(
            f"system.fan: {fan['manual_percent']}% is below this board's "
            f"minimum fan duty (36/255 = 14%); it will be raised to 14%")

    leds = system.setdefault("leds", {})
    _need(leds, "system.leds", dict, "an object")
    v_enum(leds.setdefault("mode", "status"), "system.leds.mode", LED_MODES)
    v_int(leds.setdefault("brightness", 100), "system.leds.brightness", 0, 100)
    return warnings


def _validate_ports(ports: dict[str, Any], cfg: dict[str, Any]) -> None:
    for pid, port in ports.items():
        base = f"ports.{pid}"
        _need(port, base, dict, "an object")
        v_enum(port.setdefault("role", "lan"), f"{base}.role", PORT_ROLES)
        v_bool(port.setdefault("enabled", True), f"{base}.enabled")
        v_int(port.setdefault("mtu", 1500), f"{base}.mtu", 576, 9216)
        if port.get("name"):
            v_name(port["name"], f"{base}.name")
        network = port.get("network")
        if port["role"] == "lan" and network is not None:
            if network not in cfg.get("networks", {}):
                raise ValidationError(f"{base}.network", f"unknown network '{network}'")
        tagged = port.setdefault("tagged_vlans", [])
        _need(tagged, f"{base}.tagged_vlans", list, "a list of VLAN IDs")
        for i, vid in enumerate(tagged):
            v_vlan(vid, f"{base}.tagged_vlans[{i}]")


def _validate_networks(networks: dict[str, Any], cfg: dict[str, Any]) -> None:
    if not networks:
        raise ValidationError("networks", "at least one network is required")
    seen_vlans: dict[int, str] = {}
    seen_subnets: list[tuple[ipaddress.IPv4Network, str]] = []

    for nid, net in networks.items():
        base = f"networks.{nid}"
        v_id(nid, base)
        _need(net, base, dict, "an object")
        v_name(net.setdefault("name", nid), f"{base}.name")
        v_enum(net.setdefault("purpose", "corporate"), f"{base}.purpose", NETWORK_PURPOSES)
        v_enum(net.setdefault("zone", "lan"), f"{base}.zone", ZONES)
        vlan = v_vlan(net.get("vlan"), f"{base}.vlan")
        if vlan is not None:
            if vlan in seen_vlans:
                raise ValidationError(f"{base}.vlan",
                                      f"VLAN {vlan} already used by '{seen_vlans[vlan]}'")
            seen_vlans[vlan] = nid

        subnet = v_cidr(net["subnet"], f"{base}.subnet", 4) if net.get("subnet") else None
        if subnet:
            iface = ipaddress.ip_interface(subnet)
            for other, other_id in seen_subnets:
                if iface.network.overlaps(other):
                    raise ValidationError(
                        f"{base}.subnet",
                        f"overlaps subnet of network '{other_id}' ({other})")
            seen_subnets.append((iface.network, nid))
            _validate_dhcp(net.setdefault("dhcp", {"enabled": False}), iface, f"{base}.dhcp")

        v_bool(net.setdefault("isolation", False), f"{base}.isolation")
        v_bool(net.setdefault("internet_access", True), f"{base}.internet_access")
        wan = net.setdefault("wan", "auto")
        if wan not in ("auto", None) and wan not in cfg.get("wans", {}):
            raise ValidationError(f"{base}.wan", f"unknown WAN '{wan}'")


def _validate_dhcp(dhcp: dict[str, Any], iface: Any, base: str) -> None:
    _need(dhcp, base, dict, "an object")
    if not v_bool(dhcp.setdefault("enabled", False), f"{base}.enabled"):
        return
    net = iface.network
    start = v_ip(dhcp["start"], f"{base}.start", 4) if dhcp.get("start") else None
    end = v_ip(dhcp["end"], f"{base}.end", 4) if dhcp.get("end") else None
    if not start or not end:
        raise ValidationError(base, "DHCP requires both start and end addresses")
    s_addr, e_addr = ipaddress.ip_address(start), ipaddress.ip_address(end)
    for label, addr in (("start", s_addr), ("end", e_addr)):
        if addr not in net:
            raise ValidationError(f"{base}.{label}", f"{addr} is outside {net}")
    if s_addr > e_addr:
        raise ValidationError(base, "start address must not exceed end address")
    if iface.ip in (s_addr, e_addr) or s_addr <= iface.ip <= e_addr:
        raise ValidationError(base, f"pool must not include the gateway address {iface.ip}")
    v_int(dhcp.setdefault("lease_seconds", 86400), f"{base}.lease_seconds", 120, 30 * 86400)
    for i, res in enumerate(dhcp.setdefault("reservations", [])):
        rbase = f"{base}.reservations[{i}]"
        v_mac(res["mac"], f"{rbase}.mac")
        addr = ipaddress.ip_address(v_ip(res["address"], f"{rbase}.address", 4))
        if addr not in net:
            raise ValidationError(f"{rbase}.address", f"{addr} is outside {net}")


def _validate_wans(wans: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    ports = cfg.get("ports", {})
    used_ports: dict[str, str] = {}
    for wid, wan in wans.items():
        base = f"wans.{wid}"
        v_id(wid, base)
        _need(wan, base, dict, "an object")
        v_name(wan.setdefault("name", wid), f"{base}.name")
        v_enum(wan.setdefault("mode", "dhcp"), f"{base}.mode", WAN_MODES)
        v_bool(wan.setdefault("enabled", True), f"{base}.enabled")
        v_int(wan.setdefault("priority", 1), f"{base}.priority", 1, 32)
        v_int(wan.setdefault("weight", 1), f"{base}.weight", 1, 256)
        v_int(wan.setdefault("mtu", 1500), f"{base}.mtu", 576, 9216)
        v_vlan(wan.get("vlan"), f"{base}.vlan")

        port = wan.get("port")
        if port not in ports:
            raise ValidationError(f"{base}.port", f"unknown port '{port}'")
        if port in used_ports:
            raise ValidationError(f"{base}.port",
                                  f"port {port} already used by WAN '{used_ports[port]}'")

        # Two controls name the WAN port: a port's role, and this field. Setting
        # only the role — which is the obvious thing to do, and what the Ports
        # page offers — used to leave the uplink exactly where it was, with no
        # error and nothing in the UI to say why. Observed: eth2 set to role
        # 'wan', wan1 still bound to eth3, the cable moved to the 2.5G port, and
        # the router simply had no uplink.
        #
        # So when this WAN's port is no longer a WAN port and exactly one
        # unclaimed WAN-role port exists, follow it. That is the "demote the old
        # port, promote the new one" flow, and its intent is unambiguous.
        if wan["enabled"] and ports[port].get("role") != "wan":
            claimed = set(used_ports) | {
                w.get("port") for w2, w in wans.items()
                if w2 != wid and w.get("enabled", True)}
            free = [p for p, c in sorted(ports.items())
                    if c.get("role") == "wan" and c.get("enabled", True)
                    and p not in claimed]
            if len(free) == 1:
                warnings.append(
                    f"WAN '{wid}' moved from {port} to {free[0]}: {port} is no "
                    f"longer a WAN port and {free[0]} is")
                port = wan["port"] = free[0]
            else:
                raise ValidationError(
                    f"{base}.port",
                    f"port {port} must have role 'wan' to back an enabled WAN"
                    + (f"; WAN-role ports free to use: {', '.join(free)}"
                       if free else ""))
        used_ports[port] = wid

        if wan["mode"] == "static":
            static = wan.setdefault("static", {})
            v_cidr(static.get("address"), f"{base}.static.address", 4)
            v_ip(static.get("gateway"), f"{base}.static.gateway", 4)
        if wan["mode"] == "pppoe":
            pppoe = wan.setdefault("pppoe", {})
            if not pppoe.get("username"):
                raise ValidationError(f"{base}.pppoe.username", "required for PPPoE")
            v_int(pppoe.setdefault("mru", 1492), f"{base}.pppoe.mru", 576, 1500)
        if wan.get("mac_clone"):
            v_mac(wan["mac_clone"], f"{base}.mac_clone")
        v_enum(wan.setdefault("ipv6", {}).setdefault("mode", "dhcpv6-pd"),
               f"{base}.ipv6.mode", WAN_IPV6_MODES)
        for i, dns in enumerate(wan.setdefault("dns", [])):
            v_ip(dns, f"{base}.dns[{i}]")
    warnings += _warn_unused_wan_ports(ports, wans)
    return warnings


def _warn_unused_wan_ports(ports: dict[str, Any], wans: dict[str, Any]) -> list[str]:
    """A port with role 'wan' that no WAN uses does nothing at all.

    It is taken out of the LAN bridge and carries no uplink, so it is simply a
    dead socket. This is what happens when the operator marks a second port as
    WAN without also pointing a WAN at it (or demoting the old one).
    """
    used = {w.get("port") for w in wans.values() if w.get("enabled", True)}
    orphans = [p for p, c in sorted(ports.items())
               if c.get("role") == "wan" and c.get("enabled", True)
               and p not in used]
    if not orphans:
        return []
    listed = ", ".join(orphans)
    return [f"port(s) {listed} have role 'wan' but no WAN uses them, so they "
            f"carry no traffic and are not in the LAN bridge. Point a WAN at "
            f"one (its 'port' field) or set the role back to 'lan'."]


def _validate_firewall(fw: dict[str, Any], cfg: dict[str, Any]) -> None:
    # Qualcomm's ECM (Enhanced Connection Manager) offloads forwarded flows to
    # the NSS/PPE hardware path. Measured on this board it silently breaks
    # forwarding for LAN clients: the client's SYN goes out, conntrack shows the
    # flow reaching ESTABLISHED/ASSURED in both directions, and the client still
    # receives nothing — every request times out with 0 bytes. The router's own
    # traffic is unaffected, which is why the gateway looked online while every
    # Wi-Fi and wired client had no internet.
    #
    # Stopping the ECM front ends fixes it immediately and reproducibly
    # (http=000 after 9s -> http=301 in 0.7s). None of the narrower knobs help:
    # src_interface_check, ppe_fse_enable, sfe_fse_enable and
    # sfe_fast_xmit_enable were each tested on their own and made no difference.
    # The likely culprit is ECM's handling of a VLAN-filtering bridge, which
    # this gateway always uses because it implements per-network VLANs.
    #
    # So the default is off: correct forwarding beats hardware NAT throughput on
    # a router where nothing reaches the internet. Turn it on to measure the
    # difference, and expect client traffic to stop.
    v_bool(fw.setdefault("hardware_offload", False), "firewall.hardware_offload")
    tunnels = fw.setdefault("tunnel_interfaces", ["tun*", "utun*", "wg*", "tailscale*"])
    _need(tunnels, "firewall.tunnel_interfaces", list, "a list of interface patterns")
    for i, pattern in enumerate(tunnels):
        base = f"firewall.tunnel_interfaces[{i}]"
        _need(pattern, base, str, "an interface name or nft wildcard")
        # A bare "*" would make every egress interface a tunnel and silently
        # defeat the zone policy, which is the opposite of what this is for.
        if not pattern or pattern == "*":
            raise ValidationError(base, "must name an interface or prefix, not '*'")
        if '"' in pattern:
            raise ValidationError(base, "must not contain a quote character")

    for key, action in fw.setdefault("default_policies", {}).items():
        if "->" not in key:
            raise ValidationError(f"firewall.default_policies.{key}", "expected 'src->dst'")
        src, dst = key.split("->", 1)
        v_enum(src, f"firewall.default_policies.{key}", ZONES)
        v_enum(dst, f"firewall.default_policies.{key}", ZONES)
        v_enum(action, f"firewall.default_policies.{key}", FW_ACTIONS)

    seen_ids: set[str] = set()
    for i, rule in enumerate(fw.setdefault("rules", [])):
        base = f"firewall.rules[{i}]"
        _need(rule, base, dict, "an object")
        rid = v_id(rule.setdefault("id", f"rule-{i + 1}"), f"{base}.id")
        if rid in seen_ids:
            raise ValidationError(f"{base}.id", f"duplicate rule id '{rid}'")
        seen_ids.add(rid)
        v_name(rule.setdefault("name", rid), f"{base}.name")
        v_enum(rule.setdefault("action", "drop"), f"{base}.action", FW_ACTIONS)
        v_bool(rule.setdefault("enabled", True), f"{base}.enabled")
        v_bool(rule.setdefault("log", False), f"{base}.log")
        v_int(rule.setdefault("index", i + 1), f"{base}.index", 1, 100000)
        v_enum(rule.setdefault("family", "both"), f"{base}.family", ("ipv4", "ipv6", "both"))
        v_enum(rule.setdefault("src_zone", "lan"), f"{base}.src_zone", ZONES)
        v_enum(rule.setdefault("dst_zone", "wan"), f"{base}.dst_zone", ZONES)
        proto = rule.setdefault("protocol", "any")
        v_enum(proto, f"{base}.protocol", ("any", "tcp", "udp", "tcp-udp", "icmp", "icmpv6", "esp", "gre"))
        for field in ("src_address", "dst_address"):
            if rule.get(field):
                _validate_address_spec(rule[field], f"{base}.{field}")
        for field in ("src_port", "dst_port"):
            if rule.get(field):
                if proto not in ("tcp", "udp", "tcp-udp"):
                    raise ValidationError(f"{base}.{field}",
                                          "ports require protocol tcp, udp or tcp-udp")
                v_port_range(rule[field], f"{base}.{field}")
        sched = rule.get("schedule")
        if sched and sched not in fw.get("schedules", {}):
            raise ValidationError(f"{base}.schedule", f"unknown schedule '{sched}'")


def _validate_address_spec(value: Any, path: str) -> None:
    """An address spec is a CIDR, a bare IP, or a `group:<name>` reference."""
    _need(value, path, str, "an address, CIDR or group reference")
    if value.startswith("group:"):
        return
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(path, f"not an address or CIDR: {exc}") from exc


def _validate_nat(nat: dict[str, Any], cfg: dict[str, Any]) -> None:
    v_bool(nat.setdefault("masquerade", True), "nat.masquerade")
    v_bool(nat.setdefault("hairpin", True), "nat.hairpin")
    seen: set[tuple[str, str, str]] = set()
    for i, fwd in enumerate(nat.setdefault("port_forwards", [])):
        base = f"nat.port_forwards[{i}]"
        _need(fwd, base, dict, "an object")
        v_id(fwd.setdefault("id", f"pf-{i + 1}"), f"{base}.id")
        v_name(fwd.setdefault("name", fwd["id"]), f"{base}.name")
        v_bool(fwd.setdefault("enabled", True), f"{base}.enabled")
        proto = v_enum(fwd.setdefault("protocol", "tcp"), f"{base}.protocol",
                       ("tcp", "udp", "tcp-udp"))
        ext = v_port_range(fwd["external_port"], f"{base}.external_port")
        v_ip(fwd["internal_address"], f"{base}.internal_address", 4)
        internal = v_port_range(fwd.setdefault("internal_port", ext), f"{base}.internal_port")
        if ("-" in ext) != ("-" in internal):
            raise ValidationError(base, "external and internal must both be ranges or both single")
        if "-" in ext:
            e_lo, e_hi = (int(x) for x in ext.split("-"))
            i_lo, i_hi = (int(x) for x in internal.split("-"))
            if (e_hi - e_lo) != (i_hi - i_lo):
                raise ValidationError(base, "external and internal ranges must be the same size")
        wan = fwd.setdefault("wan", "any")
        if wan != "any" and wan not in cfg.get("wans", {}):
            raise ValidationError(f"{base}.wan", f"unknown WAN '{wan}'")
        key = (proto, ext, wan)
        if key in seen:
            raise ValidationError(base, f"another forward already claims {proto} {ext} on {wan}")
        seen.add(key)


def _validate_routing(routing: dict[str, Any]) -> None:
    for i, route in enumerate(routing.setdefault("static", [])):
        base = f"routing.static[{i}]"
        _need(route, base, dict, "an object")
        dest = route.get("destination")
        try:
            network = ipaddress.ip_network(dest, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"{base}.destination", f"invalid prefix: {exc}") from exc
        kind = v_enum(route.setdefault("type", "gateway"), f"{base}.type",
                      ("gateway", "interface", "blackhole", "unreachable"))
        if kind == "gateway":
            gw = v_ip(route.get("via"), f"{base}.via")
            if ipaddress.ip_address(gw).version != network.version:
                raise ValidationError(f"{base}.via", "gateway family must match destination")
        elif kind == "interface" and not route.get("interface"):
            raise ValidationError(f"{base}.interface", "required for interface routes")
        v_int(route.setdefault("metric", 100), f"{base}.metric", 0, 4294967295)


def _validate_qos(qos: dict[str, Any], cfg: dict[str, Any]) -> None:
    """Validate the global smart-queue policy.

    UCGF keeps separate ``qos`` and ``qos-ip`` domains.  sbegw deliberately
    presents one small policy: CAKE on each enabled WAN, with optional per-host
    limits retained in the document for the client manager.
    """
    _need(qos, "qos", dict, "an object")
    enabled = v_bool(qos.setdefault("enabled", False), "qos.enabled")
    v_enum(qos.setdefault("engine", "cake"), "qos.engine", ("cake",))
    down = v_int(qos.setdefault("download_kbps", 0), "qos.download_kbps",
                 0, 10_000_000)
    up = v_int(qos.setdefault("upload_kbps", 0), "qos.upload_kbps",
               0, 10_000_000)
    if enabled and not (down or up):
        raise ValidationError(
            "qos", "set a download or upload rate before enabling Smart Queues")

    limits = qos.setdefault("per_client_limits", [])
    _need(limits, "qos.per_client_limits", list, "a list")
    seen: set[str] = set()
    network_ids = set(cfg.get("networks", {}))
    for i, limit in enumerate(limits):
        base = f"qos.per_client_limits[{i}]"
        _need(limit, base, dict, "an object")
        if limit.get("mac"):
            key = "mac:" + v_mac(limit["mac"], f"{base}.mac")
        elif limit.get("network"):
            network = limit["network"]
            if network not in network_ids:
                raise ValidationError(f"{base}.network", f"unknown network '{network}'")
            key = "network:" + network
        else:
            raise ValidationError(base, "a mac or network is required")
        if key in seen:
            raise ValidationError(base, f"duplicate limit for {key.split(':', 1)[1]}")
        seen.add(key)
        v_int(limit.setdefault("download_kbps", 0), f"{base}.download_kbps",
              0, 10_000_000)
        v_int(limit.setdefault("upload_kbps", 0), f"{base}.upload_kbps",
              0, 10_000_000)


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}"
    r"[A-Za-z0-9_])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$")


def _domain(value: Any, path: str) -> str:
    _need(value, path, str, "a DNS name")
    name = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(name):
        raise ValidationError(path, "invalid DNS name")
    return name


def _validate_dns(dns: dict[str, Any]) -> None:
    """Validate dnsmasq forwarding, local records and domain filtering."""
    _need(dns, "dns", dict, "an object")
    upstream = dns.setdefault("upstream", ["1.1.1.1", "8.8.8.8"])
    _need(upstream, "dns.upstream", list, "a list of resolver addresses")
    if not upstream:
        raise ValidationError("dns.upstream", "at least one resolver is required")
    for i, address in enumerate(upstream):
        v_ip(address, f"dns.upstream[{i}]")
    v_int(dns.setdefault("cache_size", 4096), "dns.cache_size", 0, 100_000)
    v_bool(dns.setdefault("dnssec", False), "dns.dnssec")
    v_bool(dns.setdefault("query_log", False), "dns.query_log")

    filtering = dns.setdefault("filtering", {})
    _need(filtering, "dns.filtering", dict, "an object")
    v_bool(filtering.setdefault("enabled", False), "dns.filtering.enabled")
    v_bool(filtering.setdefault("block_malware", True),
           "dns.filtering.block_malware")
    v_bool(filtering.setdefault("block_ads", False), "dns.filtering.block_ads")
    for key in ("allowlist", "blocklist"):
        names = filtering.setdefault(key, [])
        _need(names, f"dns.filtering.{key}", list, "a list of DNS names")
        normalised = [_domain(name, f"dns.filtering.{key}[{i}]")
                      for i, name in enumerate(names)]
        if len(normalised) != len(set(normalised)):
            raise ValidationError(f"dns.filtering.{key}", "contains a duplicate name")
        filtering[key] = normalised

    forwarders = dns.setdefault("conditional_forwarders", [])
    _need(forwarders, "dns.conditional_forwarders", list, "a list")
    for i, entry in enumerate(forwarders):
        base = f"dns.conditional_forwarders[{i}]"
        _need(entry, base, dict, "an object")
        entry["domain"] = _domain(entry.get("domain"), f"{base}.domain")
        entry["server"] = v_ip(entry.get("server"), f"{base}.server")

    records = dns.setdefault("records", [])
    _need(records, "dns.records", list, "a list")
    seen_records: set[tuple[str, str]] = set()
    for i, record in enumerate(records):
        base = f"dns.records[{i}]"
        _need(record, base, dict, "an object")
        kind = v_enum(record.setdefault("type", "A"), f"{base}.type",
                      ("A", "AAAA", "CNAME", "SRV", "TXT"))
        record["name"] = _domain(record.get("name"), f"{base}.name")
        value = record.get("value")
        _need(value, f"{base}.value", str, "a string")
        if "\n" in value or "\r" in value:
            raise ValidationError(f"{base}.value", "must be a single line")
        if kind == "A":
            record["value"] = v_ip(value, f"{base}.value", 4)
        elif kind == "AAAA":
            record["value"] = v_ip(value, f"{base}.value", 6)
        elif kind == "CNAME":
            record["value"] = _domain(value, f"{base}.value")
        elif not value.strip() or len(value) > 255:
            raise ValidationError(f"{base}.value", "must be 1-255 characters")
        key = (kind, record["name"])
        if key in seen_records:
            raise ValidationError(base, f"duplicate {kind} record for {record['name']}")
        seen_records.add(key)


def _validate_dpi(dpi: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    _need(dpi, "dpi", dict, "an object")
    enabled = v_bool(dpi.setdefault("enabled", False), "dpi.enabled")
    v_enum(dpi.setdefault("engine", "suricata"), "dpi.engine", ("suricata",))
    v_int(dpi.setdefault("retention_hours", 24), "dpi.retention_hours", 1, 720)
    v_bool(dpi.setdefault("include_ipv6", True), "dpi.include_ipv6")
    if enabled and cfg.get("firewall", {}).get("hardware_offload"):
        return ["dpi: hardware flow offload can bypass packet inspection; "
                "disable offload for complete traffic identification"]
    return []


def _validate_controller(controller: dict[str, Any]) -> None:
    _need(controller, "controller", dict, "an object")
    enabled = v_bool(controller.setdefault("enabled", False), "controller.enabled")
    v_bool(controller.setdefault("discovery", True), "controller.discovery")
    sync = v_bool(controller.setdefault("sync_enabled", False),
                  "controller.sync_enabled")
    v_bool(controller.setdefault("verify_tls", True), "controller.verify_tls")
    v_int(controller.setdefault("interval_seconds", 10),
          "controller.interval_seconds", 5, 300)

    for key in ("inform_url", "api_url", "api_key", "site_id"):
        value = controller.setdefault(key, "")
        _need(value, f"controller.{key}", str, "a string")
        if "\n" in value or "\r" in value or len(value) > 2048:
            raise ValidationError(f"controller.{key}", "invalid value")

    inform = controller["inform_url"].strip()
    if enabled:
        if not re.match(r"^https?://[^\s/]+(?::[0-9]{1,5})?/inform/?$", inform):
            raise ValidationError("controller.inform_url",
                                  "use http(s)://controller:8080/inform")
        controller["inform_url"] = inform.rstrip("/")
    if sync:
        api_url = controller["api_url"].strip().rstrip("/")
        if not re.match(r"^https?://[^\s]+/proxy/network/integration/v1$", api_url):
            raise ValidationError(
                "controller.api_url",
                "must end with /proxy/network/integration/v1")
        if not controller["api_key"].strip():
            raise ValidationError("controller.api_key", "an API key is required")
        if not re.match(r"^[0-9a-fA-F-]{16,64}$", controller["site_id"].strip()):
            raise ValidationError("controller.site_id", "invalid site ID")
        controller["api_url"] = api_url


def _validate_users(users: dict[str, Any]) -> None:
    for username, user in users.items():
        base = f"users.{username}"
        _need(user, base, dict, "an object")
        v_enum(user.setdefault("role", "read-only"), f"{base}.role", ROLES)
        if not user.get("password_hash"):
            raise ValidationError(f"{base}.password_hash", "user has no password set")


# --------------------------------------------------------------------------
# Wi-Fi validation, including 6 GHz security and MLO composition rules
# --------------------------------------------------------------------------

def _validate_wifi(wifi: dict[str, Any], cfg: dict[str, Any],
                   caps: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    country = wifi.setdefault("country", "US")
    if not re.match(r"^[A-Z]{2}$", str(country)):
        raise ValidationError("wifi.country", "must be a two-letter ISO country code")

    radio_caps: dict[str, Any] = caps.get("radios", {}) or {}

    for rid, radio in wifi.setdefault("radios", {}).items():
        base = f"wifi.radios.{rid}"
        _need(radio, base, dict, "an object")
        v_bool(radio.setdefault("enabled", True), f"{base}.enabled")
        band = v_enum(radio.setdefault("band", "5g"), f"{base}.band", BANDS)
        width = radio.setdefault("channel_width", 80 if band == "5g" else 20)
        if width not in WIDTHS:
            raise ValidationError(f"{base}.channel_width",
                                  f"must be one of {', '.join(map(str, WIDTHS))}")
        if width == 320 and band != "6g":
            raise ValidationError(f"{base}.channel_width", "320 MHz is 6 GHz only")
        if width == 240 and band != "5g":
            raise ValidationError(
                f"{base}.channel_width",
                "240 MHz is a 5 GHz-only extension (320 MHz EHT with an 80 MHz "
                "puncture)")
        if band == "2g" and width > 40:
            raise ValidationError(f"{base}.channel_width", "2.4 GHz supports 20 or 40 MHz")
        channel = radio.setdefault("channel", "auto")
        if channel != "auto":
            v_int(channel, f"{base}.channel", 1, 233)
        power = radio.setdefault("tx_power", "auto")
        if power != "auto":
            v_int(power, f"{base}.tx_power", 1, 30)

        if width == 240:
            probed = radio_caps.get(rid)
            if probed and not probed.get("eht240"):
                raise ValidationError(
                    f"{base}.channel_width",
                    "this radio does not report 240 MHz (EHT240) support")
        bitmap = radio.get("punct_bitmap")
        if bitmap not in (None, "auto"):
            v_int(bitmap, f"{base}.punct_bitmap", 0, 0xFFFF)

        # Runtime may downgrade these; warn rather than block (spec §53).
        cap = radio_caps.get(rid)
        if cap:
            if width > max(cap.get("widths") or [width]):
                warnings.append(
                    f"radio {rid}: {width} MHz requested but hardware reports max "
                    f"{max(cap['widths'])} MHz; runtime will be lower")
            if channel != "auto" and cap.get("channels") and channel not in cap["channels"]:
                raise ValidationError(f"{base}.channel",
                                      f"channel {channel} not permitted on {rid} in {country}")
            # The whole bonded block has to fit, not just the primary channel.
            # Channel 197 is a permitted 6 GHz channel, but a 320 MHz block
            # starting there is centred on channel 223 (7065 MHz) and runs off
            # the top of the band. hostapd rejected it with "Invalid bonded
            # channel freq 6935, bw 320" -> "Interface initialization failed",
            # and because the radio was a link of an MLD, hostapd tore down
            # every other link with it: setting one bad 6 GHz channel took
            # 2.4 GHz and 5 GHz off the air too.
            if channel != "auto" and width > 20 and cap.get("channels"):
                from .rf import bonded_channels
                bonded = bonded_channels(channel, width, band)
                missing = [c for c in bonded if c not in cap["channels"]]
                if not bonded or missing:
                    usable = [c for c in cap["channels"]
                              if bonded_channels(c, width, band)
                              and all(x in cap["channels"]
                                      for x in bonded_channels(c, width, band))]
                    raise ValidationError(
                        f"{base}.channel",
                        f"channel {channel} cannot run {width} MHz on {rid} in "
                        f"{country}: the block would need channel(s) "
                        f"{', '.join(str(c) for c in (missing or bonded)) or 'none'}"
                        + (f". Usable at {width} MHz: "
                           f"{', '.join(str(c) for c in usable)}" if usable else ""))

    net_ids = set(cfg.get("networks", {}))
    for wnid, wnet in wifi.setdefault("networks", {}).items():
        base = f"wifi.networks.{wnid}"
        v_id(wnid, base)
        _need(wnet, base, dict, "an object")
        v_ssid(wnet.get("ssid"), f"{base}.ssid")
        v_bool(wnet.setdefault("enabled", True), f"{base}.enabled")
        v_bool(wnet.setdefault("hidden", False), f"{base}.hidden")
        # Where this SSID's clients get their address from.
        #   "lan" — behind this router's NAT, on its LAN subnet (the default)
        #   "wan" — bridged onto the WAN L2, addressed by the upstream gateway,
        #           with this router doing no NAT or routing for them at all.
        # The second is what lets an upstream box (and whatever proxy runs on
        # it) see and police these clients individually, while other SSIDs stay
        # behind this router.
        v_enum(wnet.setdefault("uplink", "lan"), f"{base}.uplink", SSID_UPLINKS)
        if wnet["uplink"] == "wan":
            warnings.append(
                f"{base}: clients are bridged onto the WAN and addressed by "
                f"the upstream gateway; this router does not NAT, firewall or "
                f"serve DHCP for them, and they cannot reach its management "
                f"interface")
        v_bool(wnet.setdefault("client_isolation", False), f"{base}.client_isolation")
        network = wnet.setdefault("network", "default")
        if network not in net_ids:
            raise ValidationError(f"{base}.network", f"unknown network '{network}'")

        bands = wnet.setdefault("bands", ["2g", "5g"])
        _need(bands, f"{base}.bands", list, "a list of bands")
        if not bands:
            raise ValidationError(f"{base}.bands", "select at least one band")
        for i, band in enumerate(bands):
            v_enum(band, f"{base}.bands[{i}]", BANDS)

        # A band with no radio behind it is not an error — a radio can appear
        # later, and rejecting would make a config unrestorable on a box whose
        # third chip failed to probe. But it must be said out loud: otherwise the
        # SSID is accepted, never comes up, and nothing explains why. This is
        # what a device that registered only one of its three radios looks like.
        if caps:
            present = {r.get("band") for r in
                       (caps.get("radios") or {}).values()}
            if present:
                absent = [b for b in bands if b not in present]
                if absent:
                    warnings.append(
                        f"{wnid}: no radio present for "
                        f"{', '.join(sorted(absent))} — the SSID will not come "
                        f"up on {'that band' if len(absent) == 1 else 'those bands'}"
                        f" (radios detected: {', '.join(sorted(present)) or 'none'})")

        # A multi-band SSID is NOT MLO. Without an MLD binding it, each band
        # gets an independent BSS that merely shares a name, and clients pick
        # one instead of associating over multiple links. Capability is not
        # activation, so say so rather than letting the band list imply MLO.
        if (len(bands) >= 2 and not wnet.get("mlo")
                and (caps or {}).get("mlo", {}).get("supported")):
            bound = any(m.get("wireless_network") == wnid and m.get("enabled", True)
                        for m in (wifi.get("mlds") or {}).values())
            if not bound:
                warnings.append(
                    f"{wnid}: spans {len(bands)} bands as separate per-band "
                    f"BSSes, which is not MLO — enable MLO on this network for "
                    f"one multi-link association instead")

        security = wnet.setdefault("security", {})
        mode = v_enum(security.setdefault("mode", "wpa2-wpa3"), f"{base}.security.mode",
                      SECURITY_MODES)
        pmf = security.setdefault("pmf", "optional")
        v_enum(pmf, f"{base}.security.pmf", ("disabled", "optional", "required"))

        if mode in ("wpa2", "wpa2-wpa3", "wpa3"):
            v_psk(security.get("passphrase"), f"{base}.security.passphrase")
        if mode in ("wpa2-enterprise", "wpa3-enterprise"):
            profile = security.get("radius_profile")
            if profile not in cfg.get("wifi", {}).get("radius", {}):
                raise ValidationError(f"{base}.security.radius_profile",
                                      "enterprise security needs a RADIUS profile")

        # 6 GHz: WPA3/OWE + PMF required. Reject rather than silently drop the band.
        if "6g" in bands:
            if mode not in ("wpa3", "wpa3-enterprise", "open"):
                raise ValidationError(
                    f"{base}.security.mode",
                    f"6 GHz requires WPA3 or OWE; '{mode}' is not permitted on 6 GHz")
            if mode == "open" and not security.get("owe"):
                raise ValidationError(
                    f"{base}.security.owe",
                    "6 GHz open networks must use OWE (enhanced open)")
            if pmf != "required":
                security["pmf"] = "required"
                warnings.append(f"{wnid}: PMF forced to required because 6 GHz is enabled")
        if mode == "wpa3" and pmf == "disabled":
            raise ValidationError(f"{base}.security.pmf", "WPA3/SAE requires PMF")

        v_bool(security.setdefault("private_preshared_keys", False),
               f"{base}.security.private_preshared_keys")
        # SAE anti-clogging and sync are hostapd's own defence against SAE
        # handshake floods; both are real hostapd directives.
        v_int(security.setdefault("sae_anti_clogging_threshold", 5),
              f"{base}.security.sae_anti_clogging_threshold", 1, 100)
        v_int(security.setdefault("sae_sync", 5),
              f"{base}.security.sae_sync", 1, 100)

        for key in ("fast_roaming", "bss_transition", "neighbor_report"):
            v_bool(wnet.setdefault(key, key != "fast_roaming"), f"{base}.{key}")

        # --- presentation / scoping
        v_enum(wnet.setdefault("application", "standard"),
               f"{base}.application", APPLICATIONS)
        v_enum(wnet.setdefault("broadcasting_aps", "all"),
               f"{base}.broadcasting_aps", BROADCASTING_APS)
        # Whether the operator has taken manual control of the advanced blocks.
        # Stored so the form reopens in the mode they left it in.
        v_enum(wnet.setdefault("advanced_mode", "auto"),
               f"{base}.advanced_mode", ADVANCED_MODES)

        # --- hi-capacity tuning
        v_bool(wnet.setdefault("minimum_data_rate", False),
               f"{base}.minimum_data_rate")
        v_enum(wnet.setdefault("multicast_filtering", "off"),
               f"{base}.multicast_filtering", MULTICAST_FILTERING)
        v_bool(wnet.setdefault("multicast_broadcast_blocker", False),
               f"{base}.multicast_broadcast_blocker")
        v_bool(wnet.setdefault("multicast_to_unicast", False),
               f"{base}.multicast_to_unicast")

        # --- behaviour controls
        # MLO here replaces the separate MLO object in the UI: an SSID with this
        # set and two or more bands becomes one multi-link device, rather than
        # the operator having to build an MLD by hand and keep its link list in
        # step with the band list.
        v_bool(wnet.setdefault("mlo", False), f"{base}.mlo")
        if wnet["mlo"] and len(bands) < 2:
            raise ValidationError(
                f"{base}.mlo",
                "MLO needs at least two bands; select another band or turn it off")
        if wnet["mlo"] and not (caps or {}).get("mlo", {}).get("supported"):
            raise ValidationError(
                f"{base}.mlo",
                (caps or {}).get("mlo", {}).get("reason")
                or "this hardware does not support MLO")
        v_bool(wnet.setdefault("band_steering", True), f"{base}.band_steering")
        v_bool(wnet.setdefault("proxy_arp", False), f"{base}.proxy_arp")
        v_bool(wnet.setdefault("uapsd", False), f"{base}.uapsd")
        v_bool(wnet.setdefault("mac_filter", False), f"{base}.mac_filter")
        v_bool(wnet.setdefault("radius_mac_auth", False),
               f"{base}.radius_mac_auth")
        if wnet["radius_mac_auth"] and not security.get("radius_profile"):
            raise ValidationError(f"{base}.radius_mac_auth",
                                  "RADIUS MAC authentication needs a RADIUS profile")
        v_bool(wnet.setdefault("speed_limit", False), f"{base}.speed_limit")
        v_bool(wnet.setdefault("auto_dtim", True), f"{base}.auto_dtim")
        v_int(wnet.setdefault("dtim_period", 2), f"{base}.dtim_period", 1, 255)
        v_bool(wnet.setdefault("group_rekey_interval", False),
               f"{base}.group_rekey_interval")
        v_int(wnet.setdefault("group_rekey_seconds", 3600),
              f"{base}.group_rekey_seconds", 30, 86400)
        v_bool(wnet.setdefault("show_ap_name_in_beacon", False),
               f"{base}.show_ap_name_in_beacon")
        blackout = wnet.setdefault("blackout_schedule",
                                   {"enabled": False, "start": None, "end": None})
        _need(blackout, f"{base}.blackout_schedule", dict, "an object")
        v_bool(blackout.setdefault("enabled", False),
               f"{base}.blackout_schedule.enabled")

        mac_list = wnet.setdefault("mac_filter_list", [])
        _need(mac_list, f"{base}.mac_filter_list", list, "a list of MAC addresses")
        for i, entry in enumerate(mac_list):
            v_mac(entry, f"{base}.mac_filter_list[{i}]")
        v_enum(wnet.setdefault("mac_filter_policy", "deny"),
               f"{base}.mac_filter_policy", ("allow", "deny"))
        if wnet.get("min_rssi") is not None:
            v_int(wnet["min_rssi"], f"{base}.min_rssi", -95, -40)
        limits = wnet.setdefault("bandwidth", {"download_kbps": 0, "upload_kbps": 0})
        v_int(limits.setdefault("download_kbps", 0), f"{base}.bandwidth.download_kbps", 0, 10_000_000)
        v_int(limits.setdefault("upload_kbps", 0), f"{base}.bandwidth.upload_kbps", 0, 10_000_000)

    # --- regulatory environment
    reg = wifi.setdefault("regulatory", {})
    _need(reg, "wifi.regulatory", dict, "an object")
    v_enum(reg.setdefault("environment", "indoor"),
           "wifi.regulatory.environment", RF_ENVIRONMENTS)
    v_enum(reg.setdefault("six_ghz_power", "lpi"),
           "wifi.regulatory.six_ghz_power", SIX_GHZ_POWER_MODES)
    if reg["environment"] == "outdoor" and reg["six_ghz_power"] == "lpi":
        warnings.append(
            "wifi.regulatory: 6 GHz Low Power Indoor is indoor-only — outdoor "
            "operation needs Standard Power (which requires AFC coordination) "
            "or Very Low Power")
    if reg["six_ghz_power"] == "sp":
        warnings.append(
            "wifi.regulatory: 6 GHz Standard Power raises the limit to 36 dBm "
            "on 5925-6425 and 6525-6875 MHz, and in most domains legally "
            "requires AFC coordination before transmitting")

    for rid, radio in (wifi.get("radios") or {}).items():
        if radio.get("band") == "2g" and (radio.get("channel_width") or 20) >= 40:
            warnings.append(
                f"{rid}: 40 MHz on 2.4 GHz skips the 20/40 coexistence scan, "
                f"or it would fall back to 20 MHz whenever a neighbouring "
                f"network is present — which is most of the time")

    # Width costs power on 5 GHz. Measured on this board: 240 MHz only exists
    # in UNII-2C (channels 100-144) where the limit is 24 dBm, against 28 dBm
    # available at 80 MHz on channel 36 or 149. Say so rather than let the
    # operator lose 4 dB of coverage without knowing.
    for rid, radio in (wifi.get("radios") or {}).items():
        if radio.get("band") == "5g" and radio.get("channel_width") == 240:
            warnings.append(
                f"{rid}: 240 MHz is only available on channels 100-144, where "
                f"the regulatory limit is 4 dB below the 80 MHz channels in "
                f"UNII-1/UNII-3 — more bandwidth, less range")

    opt = wifi.setdefault("channel_optimisation", {})
    _need(opt, "wifi.channel_optimisation", dict, "an object")
    v_bool(opt.setdefault("enabled", False), "wifi.channel_optimisation.enabled")
    v_int(opt.setdefault("min_interval_seconds", 21600),
          "wifi.channel_optimisation.min_interval_seconds", 300, 7 * 86400)
    improvement = opt.setdefault("min_improvement", 15.0)
    if not isinstance(improvement, (int, float)) or not 0 <= improvement <= 100:
        raise ValidationError("wifi.channel_optimisation.min_improvement",
                              "must be a number between 0 and 100")
    v_bool(opt.setdefault("avoid_dfs", False), "wifi.channel_optimisation.avoid_dfs")
    v_bool(opt.setdefault("prefer_psc", True), "wifi.channel_optimisation.prefer_psc")
    v_int(opt.setdefault("schedule_hour", 4),
          "wifi.channel_optimisation.schedule_hour", 0, 23)

    warnings += _validate_mlds(wifi, cfg, caps)
    return warnings


def _validate_mlds(wifi: dict[str, Any], cfg: dict[str, Any],
                   caps: dict[str, Any]) -> list[str]:
    """MLO is a first-class object: an MLD binds >=2 radio links to one SSID."""
    warnings: list[str] = []
    # A radio exists if the hardware probe found it, whether or not the operator
    # has already customised it. The probe is the authority on band, so its value
    # wins where both sources have one.
    radios: dict[str, Any] = {}
    for rid, probed in (caps.get("radios") or {}).items():
        radios[rid] = {"band": probed.get("band"), "enabled": True}
    for rid, configured in (wifi.get("radios") or {}).items():
        entry = radios.setdefault(rid, {})
        entry["enabled"] = configured.get("enabled", True)
        entry.setdefault("band", configured.get("band"))
        if not (caps.get("radios") or {}).get(rid):
            entry["band"] = configured.get("band")
    networks = wifi.get("networks", {})
    claimed: dict[tuple[str, str], str] = {}

    for mid, mld in wifi.setdefault("mlds", {}).items():
        base = f"wifi.mlds.{mid}"
        v_id(mid, base)
        _need(mld, base, dict, "an object")
        v_name(mld.setdefault("name", mid), f"{base}.name")
        enabled = v_bool(mld.setdefault("enabled", True), f"{base}.enabled")

        wnid = mld.get("wireless_network")
        if wnid not in networks:
            raise ValidationError(f"{base}.wireless_network",
                                  f"unknown wireless network '{wnid}'")
        wnet = networks[wnid]

        links = mld.setdefault("links", [])
        _need(links, f"{base}.links", list, "a list of radio ids")
        if enabled and len(links) < 2:
            raise ValidationError(f"{base}.links",
                                  "MLO needs at least two radio links; disable the MLD "
                                  "or add another link")
        if len(set(links)) != len(links):
            raise ValidationError(f"{base}.links", "a radio may only appear once in an MLD")

        bands_in_mld: list[str] = []
        for i, rid in enumerate(links):
            lpath = f"{base}.links[{i}]"
            if rid not in radios:
                raise ValidationError(lpath, f"unknown radio '{rid}'")
            radio = radios[rid]
            band = radio.get("band")
            if band in bands_in_mld:
                raise ValidationError(lpath,
                                      f"two links on the same band ({band}) is not valid MLO")
            bands_in_mld.append(band)
            if band not in wnet.get("bands", []):
                raise ValidationError(
                    lpath,
                    f"radio {rid} is {band} but SSID '{wnid}' does not enable that band")
            if enabled and not radio.get("enabled", True):
                warnings.append(f"MLD {mid}: radio {rid} is disabled, link will not come up")
            key = (rid, wnid)
            if key in claimed:
                raise ValidationError(lpath,
                                      f"radio {rid} already carries '{wnid}' via MLD "
                                      f"'{claimed[key]}'")
            claimed[key] = mid

        # 802.11be is a prerequisite for MLO, and EHT mandates WPA3+PMF.
        security = wnet.get("security", {})
        if enabled and security.get("mode") not in ("wpa3", "wpa3-enterprise"):
            raise ValidationError(
                f"{base}.wireless_network",
                f"MLO requires WPA3 on '{wnid}' (802.11be forbids WPA2-only MLDs)")
        if enabled and security.get("pmf") != "required":
            security["pmf"] = "required"
            warnings.append(f"MLD {mid}: PMF forced to required for 802.11be")

        if mld.get("mld_mac"):
            v_mac(mld["mld_mac"], f"{base}.mld_mac")
        v_enum(mld.setdefault("link_steering", "auto"), f"{base}.link_steering",
               ("auto", "static", "disabled"))
    return warnings
