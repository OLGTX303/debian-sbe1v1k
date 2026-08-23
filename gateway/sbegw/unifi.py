"""UniFi Network interoperability for the SBE1V1K gateway.

There are two deliberately separate paths:

* TNBU inform/discovery makes the router adoptable as an independent gateway
  and publishes live health, interface, client and DPI data.
* The documented local Network Integration API supplies desired state.  This
  avoids executing opaque controller commands or pretending that the UCGF
  console-only UDAPI socket is a remotely supported protocol.

The binary inform framing is compatible with legacy UGW3 controllers.  The
implementation is based on public protocol descriptions and contains no UniFi
program binaries or firmware code.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any

from . import schema
from .util import now, read_int, read_text, write_atomic

log = logging.getLogger("sbegw.unifi")

MASTER_KEY = bytes.fromhex("ba86f2bbe107c7c57eb5f2690775c712")
MAGIC = b"TNBU"
STATE_FILE = "unifi-controller.json"


class ProtocolError(ValueError):
    pass


def _cipher_parts():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
    except ImportError as exc:  # pragma: no cover - depends on image packaging
        raise ProtocolError("python3-cryptography is not installed") from exc
    return Cipher, algorithms, modes, PKCS7


def encode_inform(payload: dict[str, Any], mac: str, key: bytes = MASTER_KEY,
                  *, gcm: bool = False, iv: bytes | None = None) -> bytes:
    Cipher, algorithms, modes, PKCS7 = _cipher_parts()
    iv = iv or os.urandom(16)
    raw = zlib.compress(json.dumps(payload, separators=(",", ":")).encode())
    flags = 0x01 | 0x02 | (0x08 if gcm else 0)
    mac_raw = bytes(int(part, 16) for part in mac.split(":"))
    if len(mac_raw) != 6:
        raise ProtocolError("inform identity is not a six-byte MAC")

    if gcm:
        payload_len = len(raw) + 16
        header = (MAGIC + struct.pack(">I", 1) + mac_raw + struct.pack(">H", flags)
                  + iv + struct.pack(">II", 1, payload_len))
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(header)
        encrypted = encryptor.update(raw) + encryptor.finalize() + encryptor.tag
    else:
        padder = PKCS7(128).padder()
        padded = padder.update(raw) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        header = (MAGIC + struct.pack(">I", 1) + mac_raw + struct.pack(">H", flags)
                  + iv + struct.pack(">II", 1, len(encrypted)))
    return header + encrypted


def decode_inform(packet: bytes, key: bytes = MASTER_KEY) -> dict[str, Any]:
    Cipher, algorithms, modes, PKCS7 = _cipher_parts()
    if len(packet) < 40 or packet[:4] != MAGIC:
        raise ProtocolError("invalid TNBU response")
    flags = struct.unpack(">H", packet[14:16])[0]
    iv = packet[16:32]
    length = struct.unpack(">I", packet[36:40])[0]
    if length > len(packet) - 40:
        raise ProtocolError("truncated TNBU response")
    body = packet[40:40 + length]
    if flags & 0x08:
        if len(body) < 16:
            raise ProtocolError("truncated AES-GCM tag")
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, body[-16:])).decryptor()
        decryptor.authenticate_additional_data(packet[:40])
        raw = decryptor.update(body[:-16]) + decryptor.finalize()
    else:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(body) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        raw = unpadder.update(padded) + unpadder.finalize()
    if flags & 0x02:
        raw = zlib.decompress(raw)
    elif flags & 0x04:
        raise ProtocolError("Snappy-compressed controller response is unsupported")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("controller response is not JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("controller response must be an object")
    return value


def _tlv_item(kind: int, value: bytes) -> bytes:
    return struct.pack(">HH", kind, len(value)) + value


def discovery_packet(mac: str, address: str, version: str,
                     model: str = "UGW3", index: int = 1) -> bytes:
    mac_raw = bytes(int(part, 16) for part in mac.split(":"))
    ip_raw = socket.inet_aton(address)
    items = b"".join([
        _tlv_item(1, mac_raw), _tlv_item(2, mac_raw + ip_raw),
        _tlv_item(3, f"{model}.v{version}".encode("ascii")),
        _tlv_item(10, struct.pack("!I", int(time.monotonic()))),
        _tlv_item(11, b"UNIFI-GW"), _tlv_item(12, model.encode("ascii")),
        _tlv_item(18, struct.pack("!I", index)), _tlv_item(19, mac_raw),
        _tlv_item(21, model.encode("ascii")),
        _tlv_item(22, version.encode("ascii")),
        _tlv_item(27, version.encode("ascii")),
    ])
    return struct.pack(">BBH", 2, 6, len(items)) + items


def _slug(name: str, suffix: str = "") -> str:
    value = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "network"
    value = value[:31]
    if suffix:
        value = f"{value[:32-len(suffix)]}-{suffix}"
    return value[:39].strip("-")


class UniFiControllerAgent:
    def __init__(self, state_dir: str, config, netd, wifid, clients,
                 dpi=None, events=None):
        self.state_path = os.path.join(state_dir, STATE_FILE)
        self.config = config
        self.netd = netd
        self.wifid = wifid
        self.clients = clients
        self.dpi = dpi
        self.events = events
        self._wake = threading.Event()
        self._broadcast_index = 0
        self._state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        try:
            with open(self.state_path) as fh:
                state = json.load(fh)
            if isinstance(state, dict):
                return state
        except (OSError, json.JSONDecodeError):
            pass
        return {"adopted": False, "authkey": "", "aes_gcm": False,
                "cfgversion": "", "last_inform": None, "last_sync": None,
                "last_response": None, "error": None,
                "unsupported": []}

    def _save_state(self) -> None:
        write_atomic(self.state_path, json.dumps(self._state, indent=2), mode=0o600)

    def reset(self) -> None:
        self._state.update({"adopted": False, "authkey": "", "aes_gcm": False,
                            "cfgversion": "", "last_response": None,
                            "error": None, "unsupported": []})
        self._save_state()

    def wake(self) -> None:
        self._wake.set()

    @staticmethod
    def _identity(cfg: dict[str, Any]) -> tuple[str, str]:
        address = str(ipaddress.ip_interface(
            cfg.get("networks", {}).get("default", {}).get(
                "subnet", "192.168.2.1/24")).ip)
        candidates = ["br-lan"] + [pid for pid, port in cfg.get("ports", {}).items()
                                   if port.get("role") == "lan"]
        for interface in candidates:
            mac = read_text(f"/sys/class/net/{interface}/address").strip().lower()
            if schema.MAC_RE.match(mac):
                return mac, address
        digest = hashlib.sha256(read_text("/etc/machine-id", "sbe1v1k").encode()).digest()
        raw = bytearray(digest[:6])
        raw[0] = (raw[0] | 0x02) & 0xfe
        return ":".join(f"{part:02x}" for part in raw), address

    @staticmethod
    def _interface_counters(interface: str) -> dict[str, int]:
        base = f"/sys/class/net/{interface}/statistics"
        return {key: read_int(f"{base}/{key}", 0) or 0 for key in
                ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                 "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")}

    def _inform_payload(self, cfg: dict[str, Any]) -> dict[str, Any]:
        mac, address = self._identity(cfg)
        firmware = read_text("/usr/lib/sbegw/build-epoch", "1").strip() or "1"
        if not self._state.get("adopted"):
            return {"hostname": cfg.get("system", {}).get("hostname", "sbe1v1k"),
                    "state": 0, "default": True,
                    "inform_url": cfg["controller"]["inform_url"],
                    "mac": mac, "ip": address, "model": "UGW3",
                    "model_display": "SBE1V1K UniFi Gateway",
                    "version": f"4.4.18.{firmware}",
                    "uptime": int(time.monotonic())}

        ports = []
        if_table = []
        for pid, port in sorted(cfg.get("ports", {}).items()):
            logical = "eth0" if port.get("role") == "wan" else f"eth{len(ports) + 1}"
            ports.append({"ifname": logical, "name": port.get("name", pid),
                          "type": port.get("role", "lan"), "realif": pid})
            counters = self._interface_counters(pid)
            if_table.append({"ifname": logical, "name": port.get("name", pid),
                             "mac": read_text(f"/sys/class/net/{pid}/address").strip(),
                             "up": read_text(f"/sys/class/net/{pid}/operstate").strip() == "up",
                             **counters})
        leases = []
        for client in self.clients.live():
            if client.get("ipv4"):
                item = {"mac": client["mac"], "ip": client["ipv4"]}
                if client.get("hostname"):
                    item["hostname"] = client["hostname"]
                leases.append(item)
        dpi_stats = self.dpi.unifi_stats() if self.dpi else []
        payload = {
            "bootrom_version": "sbe1v1k", "cfgversion": self._state.get("cfgversion", ""),
            "config_network_wan": {"type": "dhcp"}, "config_port_table": ports,
            "connect_request_ip": address, "connect_request_port": "22",
            "default": False, "state": 2, "discovery_response": False,
            "fw_caps": 3, "has_default_route_distance": True,
            "has_dnsmasq_hostfile_update": True, "has_dpi": bool(cfg.get("dpi", {}).get("enabled")),
            "has_eth1": True, "has_porta": True, "has_ssh_disable": True,
            "hostname": cfg.get("system", {}).get("hostname", "sbe1v1k"),
            "inform_url": cfg["controller"]["inform_url"], "ip": address,
            "ipv4_active_leases": leases, "isolated": False, "mac": mac,
            "model": "UGW3", "model_display": "SBE1V1K UniFi Gateway",
            "netmask": str(ipaddress.ip_interface(
                cfg["networks"]["default"]["subnet"]).netmask),
            "serial": mac.replace(":", ""), "selfrun_beacon": True,
            "time": int(now()), "uplink": next((p["ifname"] for p in ports
                                                   if p["type"] == "wan"), "eth0"),
            "uptime": int(time.monotonic()), "version": f"4.4.18.{firmware}",
            "system-stats": {"cpu": "0", "mem": "0",
                             "uptime": str(int(time.monotonic()))},
            "if_table": if_table, "network_table": [],
            "dpi-clients": [row["mac"] for row in dpi_stats],
            "dpi-stats": dpi_stats,
        }
        return payload

    def _send_discovery(self, cfg: dict[str, Any]) -> None:
        mac, address = self._identity(cfg)
        self._broadcast_index += 1
        packet = discovery_packet(mac, address, "4.4.18", index=self._broadcast_index)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
            sock.sendto(packet, ("233.89.188.1", 10001))
        finally:
            sock.close()

    def _key(self) -> bytes:
        raw = self._state.get("authkey") or ""
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = b""
        return key if len(key) in (16, 24, 32) else MASTER_KEY

    def inform_once(self, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = cfg or self.config.get_running()
        mac, _address = self._identity(cfg)
        body = encode_inform(self._inform_payload(cfg), mac, self._key(),
                             gcm=bool(self._state.get("aes_gcm")))
        request = urllib.request.Request(
            cfg["controller"]["inform_url"], data=body, method="POST",
            headers={"Accept": "*/*", "Content-Type": "application/x-binary",
                     "User-Agent": "AirControl Agent v1.0"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = decode_inform(response.read(), self._key())
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and not self._state.get("adopted"):
                result = {"_type": "pending-adoption"}
            else:
                raise ProtocolError(f"controller returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProtocolError(f"controller connection failed: {exc}") from exc
        self._state["last_inform"] = now()
        self._state["last_response"] = result.get("_type", "unknown")
        self._state["error"] = None
        self._handle_response(result)
        self._save_state()
        return result

    def _handle_response(self, response: dict[str, Any]) -> None:
        kind = response.get("_type")
        if kind == "setparam":
            mgmt = str(response.get("mgmt_cfg") or "")
            known = {"authkey", "cfgversion", "use_aes_gcm", "inform_url",
                     "mgmt_url", "stun_url", "report_crash", "capability",
                     "selfrun_guest_mode", "led_enabled"}
            for line in mgmt.splitlines():
                key, sep, value = line.partition("=")
                if not sep:
                    continue
                if key == "authkey" and re.fullmatch(r"[0-9a-fA-F]{32,64}", value):
                    self._state["authkey"] = value.lower()
                elif key == "cfgversion":
                    self._state["cfgversion"] = value
                elif key == "use_aes_gcm":
                    self._state["aes_gcm"] = value.lower() in ("1", "true", "yes")
                elif key not in known:
                    self._unsupported("mgmt_cfg", key)
            if self._state.get("authkey"):
                self._state["adopted"] = True
                if self.events:
                    self.events.emit("CONTROLLER_ADOPTED", "info", {},
                                     subsystem="controller",
                                     message="Gateway adopted by UniFi Network")
        elif kind == "setdefault":
            self.reset()
        elif kind == "cmd":
            # Do not acknowledge an action that was not actually performed.
            self._unsupported("command", str(response.get("cmd")))
        elif kind not in ("noop", "pending-adoption", None):
            self._unsupported("response", str(kind))

    def _unsupported(self, category: str, name: str) -> None:
        entry = f"{category}:{name}"
        items = self._state.setdefault("unsupported", [])
        if entry not in items:
            items.append(entry)
            del items[:-50]

    def _api_get(self, cfg: dict[str, Any], path: str) -> Any:
        controller = cfg["controller"]
        url = controller["api_url"].rstrip("/") + "/" + path.lstrip("/")
        request = urllib.request.Request(url, headers={
            "Accept": "application/json", "X-API-Key": controller["api_key"]})
        context = None
        if url.startswith("https://") and not controller.get("verify_tls", True):
            context = ssl._create_unverified_context()  # noqa: SLF001 - explicit UI choice
        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                return json.loads(response.read() or b"{}")
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
                TimeoutError, OSError) as exc:
            raise ProtocolError(f"Network API request failed for {path}: {exc}") from exc

    @staticmethod
    def _page(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            value = value.get("data", value.get("items", []))
        return value if isinstance(value, list) else []

    @staticmethod
    def translate_network(item: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        if item.get("management") != "GATEWAY" or not item.get("enabled", True):
            return None
        ipv4 = item.get("ipv4Configuration") or {}
        if item.get("ipv6Configuration"):
            # The local network model can apply IPv6, but this translator does
            # not yet cover every Network API IPv6 mode. Do not turn it off by
            # omission.
            return None
        host = ipv4.get("hostIpAddress")
        prefix = ipv4.get("prefixLength")
        if not host or prefix is None:
            return None
        ident = "default" if item.get("default") else _slug(
            item.get("name", "network"), str(item.get("id", ""))[:6].lower())
        dhcp_cfg = ipv4.get("dhcpConfiguration") or {}
        if dhcp_cfg and dhcp_cfg.get("mode") != "SERVER":
            # sbegw does not implement DHCP relay; treating it as disabled would
            # silently change how clients are addressed.
            return None
        pool = dhcp_cfg.get("ipAddressRange") or {}
        enabled = dhcp_cfg.get("mode") == "SERVER"
        isolated = bool(item.get("isolationEnabled"))
        return ident, {
            "name": item.get("name") or ident, "purpose": "guest" if isolated else "corporate",
            "vlan": None if item.get("default") or item.get("vlanId") == 1
                    else item.get("vlanId"),
            "zone": "guest" if isolated else "lan", "subnet": f"{host}/{prefix}",
            "dhcp": {"enabled": enabled, "start": pool.get("start"),
                     "end": pool.get("stop"),
                     "lease_seconds": dhcp_cfg.get("leaseTimeSeconds", 86400),
                     "dns": dhcp_cfg.get("dnsServerIpAddressesOverride") or [],
                     "domain": dhcp_cfg.get("domainName") or "lan",
                     "options": [], "reservations": []},
            "isolation": isolated, "igmp_snooping": True,
            "mdns": bool(item.get("mdnsForwardingEnabled", True)),
            "internet_access": bool(item.get("internetAccessEnabled", True)),
            "wan": "auto", "controller_id": item.get("id"),
        }

    @staticmethod
    def translate_wifi(item: dict[str, Any], network_ids: dict[str, str],
                       previous: dict[str, Any] | None = None
                       ) -> tuple[str, dict[str, Any]] | None:
        if item.get("type") not in ("STANDARD", "IOT_OPTIMIZED"):
            return None
        if (item.get("hotspotConfiguration") or
                item.get("broadcastingDeviceFilter") or
                item.get("clientFilteringPolicy")):
            return None
        ident = _slug(item.get("name", "wifi"), str(item.get("id", ""))[:6].lower())
        security = item.get("securityConfiguration") or {}
        modes = {"OPEN": "open", "WPA2_PERSONAL": "wpa2",
                 "WPA2_WPA3_PERSONAL": "wpa2-wpa3", "WPA3_PERSONAL": "wpa3"}
        mode = modes.get(security.get("type"))
        if not mode:
            return None
        if security.get("radiusConfiguration") or security.get("presharedKeys"):
            return None
        encryption = security.get("encryption")
        if encryption == "ENHANCED_OPEN_WITH_TRANSITION":
            return None
        owe = security.get("type") == "OPEN" and encryption == "ENHANCED_OPEN"
        passphrase = security.get("passphrase") or ""
        if passphrase == "********" and previous:
            passphrase = previous.get("security", {}).get("passphrase", "")
        elif passphrase == "********":
            # Never configure the controller's redaction marker as a real PSK.
            return None
        frequencies = item.get("broadcastingFrequenciesGHz") or (
            [2.4] if item.get("type") == "IOT_OPTIMIZED" else [2.4, 5])
        band_map = {2.4: "2g", 5: "5g", 6: "6g"}
        network_ref = item.get("network") or {}
        network = network_ids.get(network_ref.get("networkId"), "default")
        pmf = str(security.get("pmfMode") or
                  ("REQUIRED" if mode == "wpa3" else "OPTIONAL")).lower()
        return ident, {
            "ssid": item.get("name") or ident, "enabled": bool(item.get("enabled", True)),
            "hidden": bool(item.get("hideName")), "uplink": "lan",
            "network": network, "bands": [band_map[x] for x in frequencies if x in band_map],
            "client_isolation": bool(item.get("clientIsolationEnabled")),
            "security": {"mode": mode, "passphrase": passphrase, "pmf": pmf,
                         "owe": owe},
            "mlo": bool(item.get("mloEnabled")),
            "fast_roaming": bool(security.get("fastRoamingEnabled")),
            "bss_transition": bool(item.get("bssTransitionEnabled", True)),
            "band_steering": bool(item.get("bandSteeringEnabled", True)),
            "proxy_arp": bool(item.get("arpProxyEnabled")),
            "uapsd": bool(item.get("uapsdEnabled", True)),
            "multicast_to_unicast": bool(item.get("multicastToUnicastConversionEnabled")),
            "group_rekey_interval": security.get("groupRekeyIntervalSeconds") is not None,
            "group_rekey_seconds": security.get("groupRekeyIntervalSeconds") or 3600,
            "controller_id": item.get("id"),
        }

    @staticmethod
    def translate_dns(item: dict[str, Any]) -> dict[str, Any] | None:
        if not item.get("enabled", True):
            return None
        kind = item.get("type")
        names = {"A_RECORD": "A", "AAAA_RECORD": "AAAA",
                 "CNAME_RECORD": "CNAME", "SRV_RECORD": "SRV",
                 "TXT_RECORD": "TXT"}
        if kind == "FORWARD_DOMAIN":
            server = item.get("ipAddress")
            domain = item.get("domain") or item.get("name")
            return {"forwarder": {"domain": domain, "server": server}} \
                if domain and server else None
        record_kind = names.get(kind)
        name = item.get("domain") or item.get("name") or item.get("hostname")
        values = {
            "A_RECORD": item.get("ipv4Address"),
            "AAAA_RECORD": item.get("ipv6Address"),
            "CNAME_RECORD": item.get("targetDomain"),
            "TXT_RECORD": item.get("text"),
        }
        value = values.get(kind)
        if kind == "SRV_RECORD" and all(key in item for key in
                                         ("service", "protocol", "serverDomain",
                                          "port", "priority", "weight")):
            name = f"{item['service']}.{item['protocol']}.{item['domain']}"
            value = (f"{item['serverDomain']},{item['port']},"
                     f"{item['priority']},{item['weight']}")
        return {"record": {"name": name, "type": record_kind, "value": value}} \
            if record_kind and name and value is not None else None

    def sync_once(self, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = cfg or self.config.get_running()
        controller = cfg.get("controller", {})
        site = controller["site_id"]
        network_overview = self._page(self._api_get(
            cfg, f"sites/{site}/networks?limit=200"))
        wifi_overview = self._page(self._api_get(
            cfg, f"sites/{site}/wifi/broadcasts?limit=200"))
        dns_overview = self._page(self._api_get(
            cfg, f"sites/{site}/dns/policies?limit=200"))

        networks = []
        for row in network_overview:
            detail = self._api_get(cfg, f"sites/{site}/networks/{row['id']}")
            networks.append(detail.get("data", detail) if isinstance(detail, dict) else detail)
        wifi = []
        for row in wifi_overview:
            detail = self._api_get(cfg, f"sites/{site}/wifi/broadcasts/{row['id']}")
            wifi.append(detail.get("data", detail) if isinstance(detail, dict) else detail)
        dns = []
        for row in dns_overview:
            detail = self._api_get(cfg, f"sites/{site}/dns/policies/{row['id']}")
            dns.append(detail.get("data", detail) if isinstance(detail, dict) else detail)

        unsupported = []
        translated_networks: dict[str, dict[str, Any]] = {}
        controller_to_local: dict[str, str] = {}
        for row in networks:
            translated = self.translate_network(row)
            if translated:
                ident, value = translated
                translated_networks[ident] = value
                controller_to_local[str(row.get("id"))] = ident
            else:
                unsupported.append(f"network:{row.get('id', 'unknown')}")
        if "default" not in translated_networks:
            raise ProtocolError("controller did not return a managed default network")

        previous_by_controller = {str(value.get("controller_id")): value
                                  for value in cfg.get("wifi", {}).get("networks", {}).values()
                                  if value.get("controller_id")}
        translated_wifi: dict[str, dict[str, Any]] = {}
        for row in wifi:
            translated = self.translate_wifi(
                row, controller_to_local, previous_by_controller.get(str(row.get("id"))))
            if translated:
                ident, value = translated
                translated_wifi[ident] = value
            else:
                unsupported.append(f"wifi:{row.get('id', 'unknown')}")

        records, forwarders = [], []
        for row in dns:
            translated = self.translate_dns(row)
            if not translated:
                unsupported.append(f"dns:{row.get('id', 'unknown')}")
            elif "record" in translated:
                records.append(translated["record"])
            else:
                forwarders.append(translated["forwarder"])

        def mutate(candidate: dict[str, Any]) -> None:
            candidate["networks"] = translated_networks
            candidate["wifi"]["networks"] = translated_wifi
            # Explicit MLD objects are rebuilt by the operator; the Network API
            # only exposes the per-WiFi mloEnabled flag, which wifid can derive.
            candidate["wifi"]["mlds"] = {}
            candidate["dns"]["records"] = records
            candidate["dns"]["conditional_forwarders"] = forwarders
            # Keep physical port profiles valid when controller authority
            # removes or renames a network.
            for port in candidate.get("ports", {}).values():
                if (port.get("role") == "lan" and
                        port.get("network") not in translated_networks):
                    port["network"] = "default"
                valid_vlans = {network.get("vlan") for network in
                               translated_networks.values()}
                if port.get("role") == "lan":
                    port["tagged_vlans"] = [vlan for vlan in
                                              port.get("tagged_vlans", [])
                                              if vlan in valid_vlans]

        trial = copy.deepcopy(cfg)
        mutate(trial)
        schema.validate(trial, capabilities=self.config.capabilities)
        if trial != cfg:
            self.config.stage(mutate)
            result = self.config.commit(user="unifi-controller", source_ip="controller",
                                        summary="UniFi Network desired-state sync",
                                        confirm_required=False)
        else:
            result = {"changed": False, "messages": []}
        self._state["last_sync"] = now()
        combined = list(self._state.get("unsupported", []))
        for entry in unsupported:
            if entry not in combined:
                combined.append(entry)
        self._state["unsupported"] = combined[-50:]
        self._state["error"] = None
        self._save_state()
        return {"changed": trial != cfg, "unsupported": unsupported, "result": result}

    def status(self, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = cfg or self.config.get_running()
        controller = cfg.get("controller", {})
        return {"config": {key: ("********" if key == "api_key" and value else value)
                           for key, value in controller.items()},
                "state": {key: value for key, value in self._state.items()
                          if key != "authkey"},
                "crypto_available": self._crypto_available()}

    @staticmethod
    def _crypto_available() -> bool:
        try:
            _cipher_parts()
            return True
        except ProtocolError:
            return False

    def run(self, stop_event) -> None:
        while not stop_event.is_set():
            cfg = self.config.get_running()
            controller = cfg.get("controller", {})
            interval = int(controller.get("interval_seconds", 10))
            if controller.get("enabled"):
                try:
                    if controller.get("discovery") and not self._state.get("adopted"):
                        self._send_discovery(cfg)
                    self.inform_once(cfg)
                    if controller.get("sync_enabled"):
                        last = float(self._state.get("last_sync") or 0)
                        if now() - last >= max(30, interval):
                            self.sync_once(self.config.get_running())
                except Exception as exc:  # noqa: BLE001 - supervisor boundary
                    self._state["error"] = str(exc)
                    self._save_state()
                    log.warning("UniFi controller cycle failed: %s", exc)
            wait = min(max(interval, 5), 300) if controller.get("enabled") else 5
            self._wake.wait(wait)
            self._wake.clear()
