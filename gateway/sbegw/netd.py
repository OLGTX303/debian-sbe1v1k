"""netd — owns physical ports, bridges, VLANs, networks, WANs and the firewall.

Topology model
--------------
One VLAN-aware Linux bridge (``br-lan``) carries every LAN port. A network with
no VLAN is the bridge's untagged/PVID-1 domain and holds its address on ``br-lan``
itself; a VLAN-tagged network gets a ``br-lan.<vid>`` SVI. This is the layout the
IPQ9574 PPE/SSDK datapath can offload, and it lets a network move between ports
without renumbering anything.

WAN interfaces are the physical port (or a ``ethN.<vid>`` subinterface when the
WAN is tagged). DHCPv4 is delegated to ``dhclient``; DHCP/DNS/RA service for LAN
networks is delegated to ``dnsmasq``, which on this rootfs is the only daemon
present that covers DHCPv4, DHCPv6 and router advertisements together.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
from typing import Any

from .adapters import ethtool, nft, rtnl
from .configd import ApplyResult
from .util import (ToolError, monotonic, now, rate, read_text, run, run_json,
                   run_ok, which, write_atomic)

log = logging.getLogger("sbegw.netd")

BRIDGE = "br-lan"
# Carries the WAN port plus the BSSes of any SSID marked uplink=wan, so those
# clients share the upstream L2 and are addressed by the upstream gateway.
WAN_BRIDGE = "br-wan"
RUN_DIR = "/run/sbegw"
DNSMASQ_CONF = f"{RUN_DIR}/dnsmasq.conf"
DNSMASQ_PID = f"{RUN_DIR}/dnsmasq.pid"
DNSMASQ_LEASES = "/data/sbegw/dnsmasq.leases"
DHCLIENT_DIR = f"{RUN_DIR}/dhclient"

# Physical port order on the SBE1V1K. Used only for presentation defaults; the
# real port list always comes from discovery.
PORT_HINTS = {
    "eth0": {"label": "LAN 1", "phy": "QCA8075", "max_speed": 1000},
    "eth1": {"label": "LAN 2", "phy": "QCA8075", "max_speed": 1000},
    "eth2": {"label": "LAN 3", "phy": "QCA8081", "max_speed": 2500},
    "eth3": {"label": "WAN", "phy": "RTL8261N", "max_speed": 10000},
}


def is_physical_port(name: str, info: dict[str, Any]) -> bool:
    """A physical Ethernet port: has a device path, is not virtual or wireless."""
    if info.get("link_type") != "ether":
        return False
    if info.get("linkinfo", {}).get("info_kind") in ("bridge", "vlan", "veth",
                                                     "tun", "bond", "dummy"):
        return False
    if name.startswith(("br-", "wl", "lo", "vlan", "wg", "tun", "ppp", "docker")):
        return False
    # A real NIC has a driver symlink under /sys/class/net/<name>/device.
    return os.path.exists(f"/sys/class/net/{name}/device")


class PortManager:
    """Physical port discovery, state and configuration (spec §1)."""

    def __init__(self, events=None):
        self.events = events
        self._link_state: dict[str, bool] = {}
        self._samples: dict[str, tuple[float, dict[str, int]]] = {}

    def discover(self) -> list[str]:
        ports = []
        for info in rtnl.links():
            name = info.get("ifname", "")
            if is_physical_port(name, info):
                ports.append(name)
        return sorted(ports)

    def state(self, name: str, cfg_port: dict[str, Any] | None = None) -> dict[str, Any]:
        info = rtnl.link(name) or {}
        link = ethtool.link_info(name)
        pause = ethtool.pause(name)
        driver = ethtool.driver_info(name)
        stats = rtnl.stats(name)
        hint = PORT_HINTS.get(name, {})
        cfg_port = cfg_port or {}

        # Rates are computed against the previous sample of this port.
        prev = self._samples.get(name)
        ts = monotonic()
        rates: dict[str, float] = {}
        if prev:
            dt = ts - prev[0]
            for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
                rates[key.replace("bytes", "bps").replace("packets", "pps")] = round(
                    rate(stats[key], prev[1].get(key, 0), dt) * (8 if "bytes" in key else 1), 1)
        self._samples[name] = (ts, stats)

        return {
            "id": name,
            "name": cfg_port.get("name") or hint.get("label") or name,
            "role": cfg_port.get("role", "lan"),
            "network": cfg_port.get("network"),
            "enabled": cfg_port.get("enabled", True),
            "admin_up": "UP" in (info.get("flags") or []),
            "oper_state": info.get("operstate", "UNKNOWN"),
            "link_up": bool(link.get("link_detected")),
            "speed_mbps": link.get("speed_mbps"),
            "max_speed_mbps": hint.get("max_speed") or (
                max(link.get("supported_speeds") or [0]) or None),
            "duplex": link.get("duplex"),
            "autoneg": link.get("autoneg"),
            "supported_speeds": link.get("supported_speeds", []),
            "medium": link.get("medium"),
            "mtu": info.get("mtu"),
            "mac": info.get("address"),
            "flow_control": {"rx": pause.get("rx"), "tx": pause.get("tx"),
                             "autoneg": pause.get("autoneg")},
            "phy": {"driver": driver.get("driver"), "chip": hint.get("phy"),
                    "firmware": driver.get("firmware_version"),
                    "bus": driver.get("bus_info"),
                    "temperature_c": ethtool.phy_temperature(name)},
            "counters": stats | {"crc_errors": ethtool.crc_errors(name)},
            "rates": rates,
            "master": info.get("master"),
        }

    def all_states(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        ports = cfg.get("ports", {})
        return [self.state(name, ports.get(name)) for name in self.discover()]

    def poll_link_changes(self) -> None:
        """Emit PORT_UP/PORT_DOWN on transitions."""
        for name in self.discover():
            up = bool(ethtool.link_info(name).get("link_detected"))
            was = self._link_state.get(name)
            self._link_state[name] = up
            if was is None or was == up or self.events is None:
                continue
            info = ethtool.link_info(name)
            self.events.emit(
                "PORT_UP" if up else "PORT_DOWN",
                subsystem="ethernet",
                data={"port": name, "speed_mbps": info.get("speed_mbps"),
                      "duplex": info.get("duplex")},
                dedup_key=f"port-{name}-{up}", dedup_window=3.0)

    def apply(self, cfg: dict[str, Any]) -> list[str]:
        messages: list[str] = []
        present = set(self.discover())
        for name, port in cfg.get("ports", {}).items():
            if name not in present:
                messages.append(f"port {name} is configured but not present")
                continue
            enabled = port.get("enabled", True) and port.get("role") != "disabled"
            rtnl.set_up(name, enabled)
            if port.get("mtu"):
                rtnl.set_mtu(name, int(port["mtu"]))
            speed = port.get("speed", "auto")
            if speed != "auto":
                if not ethtool.set_speed(name, speed, port.get("duplex", "full")):
                    messages.append(f"{name}: could not force {speed} Mbps")
            elif ethtool.link_info(name).get("autoneg") is False:
                ethtool.set_speed(name, "auto")
            ethtool.set_pause(name, bool(port.get("flow_control", True)))
        return messages


class NetworkManager:
    """Bridge, VLAN and L3 configuration for network objects (spec §2-§4)."""

    def __init__(self, events=None):
        self.events = events

    @staticmethod
    def interface_for(nid: str, net: dict[str, Any]) -> str:
        vlan = net.get("vlan")
        return BRIDGE if vlan in (None, 1) else f"{BRIDGE}.{vlan}"

    # Overridable so tests can point at a temporary directory instead of
    # monkeypatching os.path.exists and open().
    ECM_DIR = "/proc/sys/net/ecm"

    @classmethod
    def _apply_hw_offload(cls, enabled: bool) -> list[str]:
        """Enable or stop Qualcomm ECM's accelerated forwarding front ends.

        Absent knobs mean the ECM modules are not loaded, which is itself the
        "no offload" state, so that is not an error.
        """
        stop = "0" if enabled else "1"
        applied = False
        for family in ("ipv4", "ipv6"):
            path = os.path.join(cls.ECM_DIR, f"front_end_{family}_stop")
            if not os.path.exists(path):
                continue
            try:
                with open(path, "w") as fh:
                    fh.write(stop + "\n")
                applied = True
            except OSError as exc:
                return [f"could not {'enable' if enabled else 'stop'} ECM "
                        f"{family} offload: {exc}"]
        if not applied:
            return []
        if enabled:
            return ["hardware offload (ECM) enabled — if clients lose internet "
                    "while the gateway stays online, this is why"]
        return ["hardware offload (ECM) stopped so forwarding works"]

    # Roles as they were when this boot's first apply ran. On tmpfs, so it
    # resets every boot, which is exactly the lifetime we need to compare against.
    BOOT_ROLES = "/run/sbegw/port-roles"

    def _check_port_role_changes(self, ports: dict[str, Any]) -> list[str]:
        """Warn when a port's role changed since boot.

        Changing a port between the LAN bridge and a routed WAN needs its
        NSS/PPE datapath reprogrammed, and nothing we can do from userspace
        does that. Measured on hardware: eth2 moved from LAN to WAN at runtime
        linked at 1 Gbps with carrier up, and delivered zero bytes — the MAC
        counters climbed while the nss-dp counters stayed at 0, so DHCP never
        saw an offer. A reboot with the new role in place works immediately.
        A link bounce does not.
        """
        current = {p: (c.get("role") or "lan") for p, c in sorted(ports.items())}
        try:
            os.makedirs(os.path.dirname(self.BOOT_ROLES), exist_ok=True)
            with open(self.BOOT_ROLES) as fh:
                previous = json.load(fh)
        except (OSError, ValueError):
            previous = None

        if previous is None:
            try:
                write_atomic(self.BOOT_ROLES, json.dumps(current))
            except OSError:
                pass
            return []

        changed = [f"{p}: {previous.get(p)} -> {role}"
                   for p, role in current.items()
                   if previous.get(p) not in (None, role)]
        if not changed:
            return []
        detail = "; ".join(changed)
        if self.events:
            self.events.emit(
                "PORT_ROLE_CHANGED", "warning", subsystem="network",
                data={"changes": changed},
                message=f"reboot required to move {detail}")
        return [f"port role changed ({detail}). REBOOT REQUIRED: this "
                f"platform programs a port's hardware datapath at boot, so "
                f"the port will show a link but pass no traffic until then."]

    def apply(self, cfg: dict[str, Any]) -> list[str]:
        messages: list[str] = []
        networks = cfg.get("networks", {})
        ports = cfg.get("ports", {})

        rtnl.ensure_bridge(BRIDGE, vlan_filtering=True)
        # A Linux bridge invents a random MAC unless told otherwise, so br-lan
        # changed identity on every boot. Pin it to the ART-derived LAN address
        # (nvmem cell 1, the same one the LAN ports use) so the gateway keeps a
        # stable identity for DHCP, ARP caches and upstream reservations.
        self._pin_bridge_mac()

        # IPv4/IPv6 forwarding is a prerequisite for any routing at all.
        rtnl.sysctl("net.ipv4.ip_forward", "1")
        rtnl.sysctl("net.ipv6.conf.all.forwarding", "1")
        rtnl.sysctl("net.ipv4.conf.all.rp_filter", "2")

        # Qualcomm ECM hardware offload. Off by default because it breaks
        # forwarding outright on this board: with it enabled a LAN client's
        # connections reach ESTABLISHED/ASSURED in conntrack and the client
        # still receives nothing, so every Wi-Fi and wired client had no
        # internet while the gateway itself was perfectly online. See
        # schema._validate_firewall for the measurements.
        #
        # Applied here rather than only from sysctl.d because the ECM modules
        # are not necessarily loaded when systemd-sysctl runs, and this re-runs
        # on every config apply.
        messages += self._apply_hw_offload(
            bool(cfg.get("firewall", {}).get("hardware_offload", False)))

        # --- LAN port membership and PVIDs
        lan_ports = [p for p, cfgp in ports.items()
                     if cfgp.get("role") == "lan" and cfgp.get("enabled", True)]
        for port in lan_ports:
            if rtnl.link(port) is None:
                continue
            rtnl.enslave(port, BRIDGE)
            rtnl.set_up(port)
            net = networks.get(ports[port].get("network") or "")
            pvid = (net or {}).get("vlan") or 1
            rtnl.bridge_vlan_add(port, pvid, pvid=True, untagged=True)
            for vid in ports[port].get("tagged_vlans", []):
                rtnl.bridge_vlan_add(port, int(vid))
        messages += self._check_port_role_changes(ports)

        # --- the WAN bridge, when some SSID's clients live on the upstream L2
        if wan_bridge_needed(cfg):
            rtnl.ensure_bridge(WAN_BRIDGE, vlan_filtering=False)
            rtnl.set_up(WAN_BRIDGE)
            for wid, wan in cfg.get("wans", {}).items():
                if not wan.get("enabled", True):
                    continue
                port = wan.get("port")
                vlan = wan.get("vlan")
                member = port if vlan in (None,) else f"{port}.{vlan}"
                if vlan not in (None,):
                    rtnl.ensure_vlan(port, int(vlan), member)
                if rtnl.link(member) is None:
                    continue
                rtnl.enslave(member, WAN_BRIDGE)
                rtnl.set_up(member)
                messages.append(
                    f"{member} bridged into {WAN_BRIDGE} for "
                    f"{', '.join(wan_bridged_ssids(cfg))}")
        elif rtnl.link(WAN_BRIDGE):
            # No SSID needs it any more: give the port back its own address.
            for link in rtnl.links():
                if link.get("master") == WAN_BRIDGE:
                    rtnl.release(link.get("ifname", ""))
            rtnl.del_link(WAN_BRIDGE)
            messages.append(f"removed {WAN_BRIDGE}; no SSID is bridged to the WAN")

        # In AP mode the WAN port is just another bridge port: that is what
        # puts wireless and wired clients on the upstream L2, so they are
        # addressed by the upstream gateway and visible to it individually.
        if ap_mode(cfg):
            for port, cfgp in ports.items():
                if cfgp.get("role") != "wan" or not cfgp.get("enabled", True):
                    continue
                if rtnl.link(port) is None:
                    continue
                rtnl.enslave(port, BRIDGE)
                rtnl.set_up(port)
                rtnl.bridge_vlan_add(port, 1, pvid=True, untagged=True)
                messages.append(f"AP mode: {port} bridged into {BRIDGE}")

        # Ports no longer in a LAN role must leave the bridge.
        for port, cfgp in ports.items():
            if cfgp.get("role") == "lan":
                continue
            if ap_mode(cfg) and cfgp.get("role") == "wan":
                continue          # deliberately a bridge port in AP mode
            if (rtnl.link(port) or {}).get("master") == BRIDGE:
                rtnl.release(port)

        # --- per-network SVIs and addresses
        wanted_vlan_ifaces: set[str] = set()
        for nid, net in networks.items():
            vlan = net.get("vlan")
            iface = self.interface_for(nid, net)
            if vlan in (None, 1):
                # The bridge device needs its OWN VLAN-1 membership, not just
                # the ports'. Most kernels add it automatically from
                # default_pvid, but the IPQ9574 vendor kernel does not: the
                # device came up with the three ports as VLAN-1 members and no
                # entry for br-lan at all. Frames were then forwarded between
                # ports but never delivered up the stack, so dnsmasq — bound
                # correctly to br-lan:67 — never saw a single DISCOVER while
                # eth1 happily counted 287 received packets.
                rtnl.bridge_vlan_add(BRIDGE, 1, pvid=True, untagged=True,
                                     own=True)
            else:
                # Tagged, so the 8021q SVI receives the tag it expects.
                rtnl.bridge_vlan_add(BRIDGE, int(vlan), own=True)
                if not rtnl.ensure_vlan(BRIDGE, int(vlan), iface):
                    messages.append(f"network {nid}: could not create {iface}")
                    continue
                wanted_vlan_ifaces.add(iface)
            subnet = net.get("subnet")
            if subnet:
                changed = rtnl.sync_addresses(iface, [subnet])
                if changed:
                    messages.append(f"{iface}: {' '.join(changed)}")
            rtnl.set_up(iface)
            # Per-network multicast handling.
            self._set_bridge_flag("multicast_snooping",
                                  "1" if net.get("igmp_snooping", True) else "0")

        # --- remove SVIs for deleted networks
        for info in rtnl.links():
            name = info.get("ifname", "")
            if name.startswith(f"{BRIDGE}.") and name not in wanted_vlan_ifaces:
                rtnl.delete_link(name)
                messages.append(f"removed stale SVI {name}")
        return messages

    @staticmethod
    def _pin_bridge_mac() -> None:
        """Give br-lan the ART LAN MAC instead of a random one."""
        from .adapters import art
        try:
            base = art.base_mac()
        except Exception:  # noqa: BLE001
            log.debug("could not read the ART base MAC", exc_info=True)
            return
        if not base:
            return
        wanted = art.mac_at_index(base, 1)     # dts: LAN ports use cell 1
        current = (rtnl.link(BRIDGE) or {}).get("address")
        if current and current.lower() == wanted.lower():
            return
        if rtnl.set_mac(BRIDGE, wanted):
            log.info("pinned %s MAC to %s (ART cell 1)", BRIDGE, wanted)
        else:
            log.warning("could not set %s MAC to %s", BRIDGE, wanted)

    @staticmethod
    def _set_bridge_flag(flag: str, value: str) -> None:
        path = f"/sys/class/net/{BRIDGE}/bridge/{flag}"
        try:
            with open(path, "w") as fh:
                fh.write(value)
        except OSError:
            pass

    def zone_interfaces(self, cfg: dict[str, Any],
                        wan_ifaces: dict[str, str]) -> dict[str, list[str]]:
        """Map firewall zones to the interfaces currently in them."""
        zones: dict[str, list[str]] = {z: [] for z in
                                       ("wan", "lan", "guest", "iot", "dmz",
                                        "management", "vpn", "gateway",
                                        "containers")}
        for nid, net in cfg.get("networks", {}).items():
            zone = net.get("zone", "lan")
            zones.setdefault(zone, []).append(
                f'"{self.interface_for(nid, net)}"')
        for iface in wan_ifaces.values():
            zones["wan"].append(f'"{iface}"')
        for name in ("wg0", "wg1"):
            if rtnl.link(name):
                zones["vpn"].append(f'"{name}"')
        # Docker's bridges, discovered rather than configured: the daemon
        # creates docker0 at start and a br-<id> per user-defined network, and
        # sbegw has no say in when. Without them in a zone the forward chain's
        # drop policy silently kills all container networking.
        for link in rtnl.links():
            name = link.get("ifname", "")
            if name == "docker0" or (name.startswith("br-")
                                     and name != BRIDGE
                                     and len(name) == 15):
                zones["containers"].append(f'"{name}"')
        return zones


def wan_bridged_ssids(cfg: dict[str, Any]) -> list[str]:
    """SSIDs whose clients live on the WAN L2 rather than behind us."""
    return [wnid for wnid, wnet
            in (cfg.get("wifi", {}).get("networks", {}) or {}).items()
            if wnet.get("enabled", True) and wnet.get("uplink") == "wan"]


def wan_bridge_needed(cfg: dict[str, Any]) -> bool:
    """Whether the WAN uplink has to become a bridge.

    Only when some SSID is bridged onto it. In AP mode the LAN bridge already
    carries everything, so a second bridge would be pointless.
    """
    return bool(wan_bridged_ssids(cfg)) and not ap_mode(cfg)


def ap_mode(cfg: dict[str, Any]) -> bool:
    """Whether this device is a plain access point rather than a gateway."""
    return (cfg.get("system", {}) or {}).get("mode") == "ap"


class WanManager:
    """WAN bring-up, health probing and multi-WAN selection (spec §7-§8)."""

    def __init__(self, events=None):
        self.events = events
        self._health: dict[str, dict[str, Any]] = {}
        self._state: dict[str, str] = {}
        # wid -> (candidate state, consecutive polls seen). Used to debounce.
        self._pending: dict[str, tuple[str, int]] = {}
        self._dhclients: dict[str, subprocess.Popen] = {}

    @staticmethod
    def interface_for(wan: dict[str, Any], cfg: dict[str, Any] | None = None) -> str:
        port = wan.get("port", "eth3")
        vlan = wan.get("vlan")
        iface = port if vlan in (None,) else f"{port}.{vlan}"
        # Once the uplink is bridged, the port (or its VLAN sub-interface) is a
        # bridge member with no address of its own; the lease belongs on the
        # bridge, which is also what the firewall must treat as the WAN.
        if cfg is not None and wan_bridge_needed(cfg):
            return WAN_BRIDGE
        return iface

    def interfaces(self, cfg: dict[str, Any]) -> dict[str, str]:
        return {wid: self.interface_for(wan, cfg)
                for wid, wan in cfg.get("wans", {}).items()
                if wan.get("enabled", True)}

    def apply(self, cfg: dict[str, Any]) -> list[str]:
        messages: list[str] = []
        if ap_mode(cfg):
            # The WAN port is a bridge port now, so it has no address of its
            # own; the upstream lease belongs on the bridge. The LAN address
            # configured for br-lan is deliberately left in place alongside it
            # as a secondary — if upstream DHCP fails, an AP with no address is
            # an AP nobody can reach to fix.
            for wid, wan in cfg.get("wans", {}).items():
                self._stop_dhclient(wid, self.interface_for(wan, cfg))
            messages.append(f"AP mode: requesting an upstream lease on {BRIDGE}")
            messages += self._start_dhclient("ap", BRIDGE)
            return messages
        # Leaving AP mode: the bridge must give the lease back.
        self._stop_dhclient("ap", BRIDGE)

        for wid, wan in cfg.get("wans", {}).items():
            iface_now = self.interface_for(wan, cfg)
            # A WAN that moved to another port leaves its old client running:
            # _stop_dhclient is only ever told the *new* interface, so the old
            # one kept renewing and its address stayed on the old port.
            # Observed after switching eth3 -> eth2: two v4 and two v6 clients
            # sharing one pid file, and 192.168.88.28/24 still on eth3 while it
            # had already become a LAN bridge port.
            for stale in self._dhclient_ifaces(wid):
                if stale != iface_now:
                    self._stop_dhclient(wid, stale)
                    self._flush_dynamic_v4(stale)
                    messages.append(f"WAN {wid}: released {stale} "
                                    f"(now on {iface_now})")
            if not wan.get("enabled", True):
                self._stop_dhclient(wid, iface_now)
                continue
            port = wan.get("port")
            iface = self.interface_for(wan, cfg)
            if rtnl.link(port) is None:
                messages.append(f"WAN {wid}: port {port} not present")
                continue

            if wan.get("mac_clone"):
                rtnl.set_mac(port, wan["mac_clone"])
            if wan.get("vlan"):
                rtnl.ensure_vlan(port, int(wan["vlan"]), iface)
            rtnl.set_up(port)
            rtnl.set_up(iface)
            if wan.get("mtu"):
                rtnl.set_mtu(iface, int(wan["mtu"]))

            mode = wan.get("mode", "dhcp")
            if mode == "dhcp":
                messages += self._start_dhclient(wid, iface)
            elif mode == "static":
                self._stop_dhclient(wid, iface)
                static = wan.get("static", {})
                changed = rtnl.sync_addresses(iface, [static["address"]])
                if changed:
                    messages.append(f"{iface}: {' '.join(changed)}")
                rtnl.replace_route("default", via=static["gateway"], dev=iface,
                                   metric=wan.get("priority", 1) * 10)
            elif mode == "pppoe":
                self._stop_dhclient(wid, iface)
                if which("pppd") is None:
                    messages.append(
                        f"WAN {wid}: PPPoE configured but pppd is not installed; "
                        "add the ppp and pppoe packages to the rootfs")
                else:
                    messages += self._start_pppoe(wid, wan, iface)

            # IPv6
            ipv6_mode = wan.get("ipv6", {}).get("mode", "disabled")
            if ipv6_mode in ("dhcpv6", "dhcpv6-pd"):
                rtnl.sysctl(f"net.ipv6.conf.{iface}.accept_ra", "2")
                messages += self._start_dhclient(wid, iface, family=6)
            elif ipv6_mode == "slaac":
                rtnl.sysctl(f"net.ipv6.conf.{iface}.accept_ra", "2")
        return messages

    # -------------------------------------------------------- dhcp / pppoe

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        return pid > 0 and os.path.exists(f"/proc/{pid}")

    @staticmethod
    def _dhclient_ifaces(wid: str) -> list[str]:
        """Interfaces this WAN currently has a dhclient running on.

        Read from /proc rather than remembered, so it also finds clients left
        behind by a previous service lifetime or an earlier port.
        """
        found: set[str] = set()
        for entry in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                with open(entry, "rb") as fh:
                    argv = [a.decode(errors="replace")
                            for a in fh.read().split(b"\0") if a]
            except OSError:
                continue
            if not argv or "dhclient" not in argv[0]:
                continue
            if not any(f"/{wid}-v" in a for a in argv):
                continue
            if argv[-1] and not argv[-1].startswith("-"):
                found.add(argv[-1])
        return sorted(found)

    @staticmethod
    def _dhclients_on(iface: str, family: int) -> list[int]:
        """Every running dhclient bound to *iface* for this address family.

        /proc is the only source of truth that survives our own restart. The
        previous code tracked a Popen object instead, but dhclient is started
        with -nw so it forks and the tracked child exits at once: poll() then
        reported "not running" on every apply and a *new* client was launched
        each time. Two clients then raced for the same lease, each ARP-probing
        the other's address and sending DHCPDECLINE, so eth3 accumulated a
        dozen secondary addresses and WAN took minutes to settle.
        """
        found: list[int] = []
        for entry in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                with open(entry, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            argv = [a.decode(errors="replace") for a in raw.split(b"\x00") if a]
            # Match only the program name (argv[0], or argv[1] when launched via
            # an interpreter). Scanning every argument would match our own
            # "-pf /run/sbegw/dhclient/..." path and flag unrelated processes.
            if not any(os.path.basename(a).startswith("dhclient")
                       for a in argv[:2]):
                continue
            if iface not in argv:
                continue
            # dhclient is IPv4 unless -6 is given.
            is_v6 = "-6" in argv
            if (family == 6) != is_v6:
                continue
            try:
                found.append(int(entry.split("/")[2]))
            except (IndexError, ValueError):
                continue
        return sorted(found)

    @staticmethod
    def _kill_pid(pid: int) -> None:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return
        for _ in range(25):
            if not os.path.exists(f"/proc/{pid}"):
                return
            time.sleep(0.1)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def _reap(self) -> None:
        """Reap exited dhclient/pppd children.

        -nw makes dhclient fork immediately, so every launch left a zombie
        under sbegw; repeated WAN events accumulated them.
        """
        for key, proc in list(self._dhclients.items()):
            if proc.poll() is not None:
                self._dhclients.pop(key, None)

    def _start_dhclient(self, wid: str, iface: str, family: int = 4) -> list[str]:
        key = f"{wid}-v{family}"
        messages: list[str] = []
        self._reap()

        # Exactly one client per (interface, family). Anything beyond the first
        # is a duplicate from an earlier apply or a previous service lifetime.
        running = self._dhclients_on(iface, family)
        if len(running) > 1:
            for pid in running[1:]:
                self._kill_pid(pid)
            messages.append(
                f"WAN {wid}: killed {len(running) - 1} duplicate DHCPv{family} "
                f"client(s) on {iface}")
            # Their competing leases left stale addresses behind; drop them so
            # the surviving client installs exactly one.
            if family == 4:
                messages += self._flush_dynamic_v4(iface)
        if running:
            return messages

        if which("dhclient") is None:
            return messages + [f"WAN {wid}: dhclient not installed"]
        os.makedirs(DHCLIENT_DIR, exist_ok=True)
        pidfile = f"{DHCLIENT_DIR}/{key}.pid"
        # A pidfile naming a dead process stops dhclient from starting.
        stale = self._read_pidfile(pidfile)
        if stale is None:
            try:
                os.unlink(pidfile)
            except OSError:
                pass

        argv = [which("dhclient"), "-nw", f"-{family}",
                "-pf", pidfile,
                "-lf", f"{DHCLIENT_DIR}/{key}.leases",
                iface]
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except OSError as exc:
            return messages + [f"WAN {wid}: dhclient failed: {exc}"]
        # -nw forks, so the direct child exits at once: wait for it here or it
        # becomes a zombie.
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._dhclients[key] = proc
        return messages + [f"WAN {wid}: DHCPv{family} client started on {iface}"]

    @staticmethod
    def _read_pidfile(path: str) -> int | None:
        try:
            with open(path) as fh:
                pid = int(fh.read().strip())
        except (OSError, ValueError):
            return None
        return pid if os.path.exists(f"/proc/{pid}") else None

    @staticmethod
    def _flush_dynamic_v4(iface: str) -> list[str]:
        """Remove DHCP-installed IPv4 addresses so one lease can be reinstated."""
        removed = []
        for entry in rtnl.addresses(iface):
            for info in entry.get("addr_info", []):
                if info.get("family") != "inet" or info.get("scope") != "global":
                    continue
                addr = f"{info['local']}/{info['prefixlen']}"
                if run_ok(["ip", "addr", "del", addr, "dev", iface]):
                    removed.append(addr)
        return ([f"{iface}: removed {len(removed)} stale address(es): "
                 + " ".join(removed)] if removed else [])

    def _stop_dhclient(self, wid: str, iface: str | None = None) -> None:
        self._reap()
        for family in (4, 6):
            key = f"{wid}-v{family}"
            proc = self._dhclients.pop(key, None)
            if proc and proc.poll() is None:
                proc.terminate()
            pid = self._read_pidfile(f"{DHCLIENT_DIR}/{key}.pid")
            if pid:
                self._kill_pid(pid)
            # Catch clients whose pidfile was lost across a restart.
            if iface:
                for extra in self._dhclients_on(iface, family):
                    self._kill_pid(extra)

    def _start_pppoe(self, wid: str, wan: dict[str, Any], iface: str) -> list[str]:
        pppoe = wan.get("pppoe", {})
        conf = "\n".join([
            f"plugin rp-pppoe.so {iface}",
            f"user \"{pppoe.get('username')}\"",
            "noipdefault", "defaultroute", "replacedefaultroute",
            "persist", "maxfail 0", "noauth", "usepeerdns",
            f"mru {pppoe.get('mru', 1492)}", f"mtu {wan.get('mtu', 1492)}",
            f"lcp-echo-interval 10", "lcp-echo-failure 5",
        ]) + "\n"
        write_atomic(f"/etc/ppp/peers/{wid}", conf, mode=0o600)
        secrets = (f"\"{pppoe.get('username')}\" * \"{pppoe.get('password')}\"\n")
        write_atomic("/etc/ppp/pap-secrets", secrets, mode=0o600)
        write_atomic("/etc/ppp/chap-secrets", secrets, mode=0o600)
        if run_ok(["pppd", "call", wid]):
            return [f"WAN {wid}: PPPoE session starting"]
        return [f"WAN {wid}: pppd refused to start"]

    # ---------------------------------------------------------------- health

    def probe(self, cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Per-WAN link/internet/latency/loss. Runs on the telemetry cadence."""
        results: dict[str, dict[str, Any]] = {}
        for wid, wan in cfg.get("wans", {}).items():
            if not wan.get("enabled", True):
                results[wid] = {"state": "disabled"}
                continue
            iface = self.interface_for(wan, cfg)
            link_up = bool(ethtool.link_info(wan.get("port", iface)).get("link_detected"))
            addresses = []
            for entry in rtnl.addresses(iface):
                for info in entry.get("addr_info", []):
                    if info.get("scope") == "global":
                        addresses.append(f"{info['local']}/{info['prefixlen']}")
            gateway = self._default_gateway(iface)

            health = wan.get("health", {})
            latency_ms = None
            loss_percent = None
            if link_up and health.get("enabled", True) and gateway:
                latency_ms, loss_percent = self._icmp_probe(
                    health.get("targets") or [gateway], iface)
                # Plenty of upstreams filter ICMP, and reporting "no internet"
                # on a working link because a ping was dropped is worse than
                # the extra probe. A TCP handshake to a well-known port proves
                # reachability and gives a latency figure of its own.
                if (loss_percent or 0) >= 100:
                    tcp_latency = self._tcp_probe(
                        health.get("targets") or [gateway], iface)
                    if tcp_latency is not None:
                        latency_ms, loss_percent = tcp_latency, 0.0

            internet = bool(addresses and gateway and (loss_percent or 0) < 100)
            state = "down"
            if not link_up:
                state = "link-down"
            elif not addresses:
                state = "no-address"
            elif not internet:
                state = "no-internet"
            elif (loss_percent or 0) >= health.get("loss_threshold", 40) or \
                 (latency_ms or 0) >= health.get("latency_threshold_ms", 400):
                state = "degraded"
            else:
                state = "up"

            previous = self._state.get(wid)
            self._state[wid] = state
            # Debounce: a state must hold for two consecutive polls before it
            # becomes an event. eth3 flaps its carrier during USXGMII
            # negotiation, and every flap used to emit a WAN event, restart
            # DHCP and churn routes.
            pending, count = self._pending.get(wid, (state, 0))
            count = count + 1 if pending == state else 1
            self._pending[wid] = (state, count)
            settled = count >= 2 or previous is None

            if previous and previous != state and settled and self.events:
                # One event kind per failure mode. Mapping every non-up state to
                # WAN_DOWN reported the WAN as down while DHCP was still
                # acquiring a lease — immediately after a healthy link-up.
                kind = {
                    "up": "WAN_UP",
                    "degraded": "WAN_DEGRADED",
                    "link-down": "WAN_DOWN",
                    "no-address": "WAN_ACQUIRING",
                    "no-internet": "WAN_NO_INTERNET",
                }.get(state, "WAN_DEGRADED")
                self.events.emit(kind, subsystem="wan",
                                 data={"wan": wid, "state": state,
                                       "link_up": link_up,
                                       "latency_ms": latency_ms,
                                       "loss_percent": loss_percent})

            entry = {
                "id": wid, "name": wan.get("name", wid), "interface": iface,
                "port": wan.get("port"), "mode": wan.get("mode"),
                "state": state, "link_up": link_up, "internet": internet,
                "addresses": addresses, "gateway": gateway,
                "latency_ms": latency_ms, "loss_percent": loss_percent,
                "priority": wan.get("priority", 1), "weight": wan.get("weight", 1),
                "counters": rtnl.stats(iface),
                "since": self._health.get(wid, {}).get("since") or now(),
            }
            if previous != state:
                entry["since"] = now()
            self._health[wid] = entry
            results[wid] = entry
        return results

    @staticmethod
    def _default_gateway(iface: str) -> str | None:
        for route in rtnl.routes(4):
            if route.get("dst") == "default" and route.get("dev") == iface:
                return route.get("gateway")
        return None

    @staticmethod
    @staticmethod
    def _tcp_probe(targets: list[str], iface: str, port: int = 443,
                   timeout: float = 2.0) -> float | None:
        """Round-trip time of a TCP handshake, or None if none succeeded.

        Used when ICMP reports total loss: a filtered ping is common and does
        not mean the WAN is down. The socket is bound to the WAN interface so
        the answer is about this uplink and not some other route.
        """
        for target in targets[:2]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                    iface.encode())
                except OSError:
                    pass          # not privileged enough; the route still applies
                start = monotonic()
                sock.connect((target, port))
                return round((monotonic() - start) * 1000, 1)
            except OSError:
                continue
            finally:
                sock.close()
        return None

    @staticmethod
    def _icmp_probe(targets: list[str], iface: str,
                    count: int = 3) -> tuple[float | None, float | None]:
        """ICMP latency/loss bound to the WAN interface."""
        latencies: list[float] = []
        sent = 0
        received = 0
        for target in targets[:2]:
            try:
                out = run(["ping", "-n", "-q", "-c", str(count), "-W", "1",
                           "-I", iface, target], timeout=count * 2 + 3, check=False)
            except (ToolError, OSError):
                sent += count
                continue
            sent += count
            for line in out.splitlines():
                if "packets transmitted" in line:
                    parts = line.split(",")
                    try:
                        received += int(parts[1].split()[0])
                    except (IndexError, ValueError):
                        pass
                if line.startswith("rtt ") or line.startswith("round-trip"):
                    try:
                        latencies.append(float(line.split("=")[1].split("/")[1]))
                    except (IndexError, ValueError):
                        pass
        if sent == 0:
            return None, None
        loss = round((sent - received) / sent * 100, 1)
        avg = round(sum(latencies) / len(latencies), 1) if latencies else None
        return avg, loss

    def select_primary(self, cfg: dict[str, Any]) -> str | None:
        """Pick the active WAN by health then priority; install its default route."""
        candidates = [(w["priority"], wid) for wid, w in self._health.items()
                      if w.get("state") == "up"]
        if not candidates:
            candidates = [(w["priority"], wid) for wid, w in self._health.items()
                          if w.get("state") == "degraded"]
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][1]

    def health(self) -> dict[str, dict[str, Any]]:
        return dict(self._health)


class ServiceManager:
    """dnsmasq (DHCPv4/DHCPv6/RA/DNS) rendering and lifecycle (spec §24-§25)."""

    def __init__(self, events=None):
        self.events = events
        # Why DHCP/DNS is down, if it is. Reported through /api/v1/health.
        self.last_error: str | None = None

    def render_dnsmasq(self, cfg: dict[str, Any]) -> str:
        # In AP mode the upstream gateway owns addressing. Two DHCP servers on
        # one L2 hand out conflicting leases, and the clients that lost the race
        # would be pointed at an AP that cannot route.
        serve_dhcp = ap_mode(cfg)
        dns = cfg.get("dns", {})
        lines = [
            "# generated by sbegw netd — do not edit",
            "bind-interfaces",
            "except-interface=lo",
            f"pid-file={DNSMASQ_PID}",
            f"dhcp-leasefile={DNSMASQ_LEASES}",
            "no-resolv",
            "no-hosts",
            "expand-hosts",
            "domain-needed",
            "bogus-priv",
            f"cache-size={dns.get('cache_size', 4096)}",
            "dhcp-authoritative",
            # A local DNS answer must never leak an RFC1918 address from
            # upstream (rebind protection), except for our own domains.
            "stop-dns-rebind",
            "rebind-localhost-ok",
        ]
        if dns.get("dnssec"):
            lines += ["dnssec", "trust-anchor=.,20326,8,2,"
                      "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
        if dns.get("query_log"):
            lines.append("log-queries")
        for server in dns.get("upstream", []):
            lines.append(f"server={server}")

        # Conditional / split DNS
        for entry in dns.get("conditional_forwarders", []):
            lines.append(f"server=/{entry['domain']}/{entry['server']}")
        for record in dns.get("records", []):
            if record.get("type", "A") in ("A", "AAAA"):
                lines.append(f"host-record={record['name']},{record['value']}")
            elif record["type"] == "CNAME":
                lines.append(f"cname={record['name']},{record['value']}")
            elif record["type"] == "SRV":
                lines.append(f"srv-host={record['name']},{record['value']}")
            elif record["type"] == "TXT":
                lines.append(f"txt-record={record['name']},{record['value']}")

        filtering = dns.get("filtering", {})
        if filtering.get("enabled"):
            for domain in filtering.get("blocklist", []):
                lines.append(f"address=/{domain}/")
            for domain in filtering.get("allowlist", []):
                lines.append(f"server=/{domain}/#")

        for nid, net in cfg.get("networks", {}).items():
            iface = NetworkManager.interface_for(nid, net)
            lines.append("")
            lines.append(f"# network {nid}")
            lines.append(f"interface={iface}")
            dhcp = net.get("dhcp", {})
            subnet = net.get("subnet")
            if not subnet:
                continue
            gateway = ipaddress.ip_interface(subnet)
            tag = f"net_{nid}"

            if dhcp.get("enabled") and not serve_dhcp:
                lease = dhcp.get("lease_seconds", 86400)
                lines.append(
                    f"dhcp-range=set:{tag},{dhcp['start']},{dhcp['end']},"
                    f"{gateway.network.netmask},{lease}s")
                lines.append(f"dhcp-option=tag:{tag},3,{gateway.ip}")   # router
                resolvers = dhcp.get("dns") or [str(gateway.ip)]
                lines.append(f"dhcp-option=tag:{tag},6,{','.join(resolvers)}")
                if dhcp.get("domain"):
                    lines.append(f"dhcp-option=tag:{tag},15,{dhcp['domain']}")
                lines.append(f"dhcp-option=tag:{tag},26,{net.get('mtu', 1500)}")
                for option in dhcp.get("options", []):
                    lines.append(f"dhcp-option=tag:{tag},{option['code']},{option['value']}")
                for res in dhcp.get("reservations", []):
                    name = res.get("hostname") or ""
                    parts = [res["mac"], res["address"]]
                    if name:
                        parts.insert(1, name)
                    lines.append("dhcp-host=" + ",".join(parts))
            else:
                lines.append(f"no-dhcp-interface={iface}")

            ipv6 = net.get("ipv6", {})
            # Router advertisements are a routing function. An AP that sends
            # them tells clients to route through a box that does not route,
            # and competes with the upstream router's own RAs.
            if ipv6.get("ra") and not serve_dhcp:
                mode = "ra-names,slaac"
                if ipv6.get("dhcpv6"):
                    mode = "ra-stateless,ra-names" if ipv6.get("stateless", True) \
                        else "slaac"
                # ::  == use the delegated prefix on this interface.
                lines.append(f"dhcp-range=::,constructor:{iface},{mode},64,12h")
                lines.append(f"enable-ra")
                lines.append(f"ra-param={iface},high,300,1200")
        return "\n".join(lines) + "\n"

    def apply(self, cfg: dict[str, Any]) -> list[str]:
        messages: list[str] = []
        os.makedirs(RUN_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(DNSMASQ_LEASES), exist_ok=True)
        body = self.render_dnsmasq(cfg)
        changed = write_atomic(DNSMASQ_CONF, body)
        if which("dnsmasq") is None:
            self.last_error = "dnsmasq is not installed"
            return ["dnsmasq is not installed; DHCP and DNS are unavailable"]
        # Validate before restarting: a bad config would otherwise take DNS down.
        try:
            run(["dnsmasq", "--test", "-C", DNSMASQ_CONF], timeout=10.0)
        except ToolError as exc:
            self.last_error = f"config rejected: {exc.stderr}"
            return [f"dnsmasq config rejected, keeping previous: {exc.stderr}"]
        if changed or not self._running():
            ok, detail = self._restart()
            messages.append(detail)
            if not ok and self.events:
                # Silence here is what made a dead DHCP server invisible: the
                # previous code started dnsmasq with a bool-returning helper and
                # reported "restarted" whether or not it worked.
                self.events.emit("DHCP_FAILED", "error", {"detail": detail},
                                 subsystem="dhcp",
                                 message=f"dnsmasq did not start: {detail}")
        return messages

    def ensure_running(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        """Health-loop entry point: restart dnsmasq if it has died."""
        if which("dnsmasq") is None:
            return False, "dnsmasq is not installed"
        if self._running():
            return True, "running"
        log.error("dnsmasq is not running; restarting")
        return self._restart()

    @staticmethod
    def _running() -> bool:
        pid = read_text(DNSMASQ_PID).strip()
        if not pid.isdigit():
            return False
        return os.path.exists(f"/proc/{pid}")

    def _restart(self) -> tuple[bool, str]:
        """Start dnsmasq, returning the real reason when it refuses.

        dnsmasq daemonises, so a non-zero exit or anything on stderr is the only
        signal available — and it must be surfaced, not discarded.
        """
        pid = read_text(DNSMASQ_PID).strip()
        if pid.isdigit() and os.path.exists(f"/proc/{pid}"):
            try:
                os.kill(int(pid), signal.SIGTERM)
                for _ in range(20):
                    if not os.path.exists(f"/proc/{pid}"):
                        break
                    time.sleep(0.1)
            except OSError:
                pass

        try:
            proc = subprocess.run(
                [which("dnsmasq") or "dnsmasq", "-C", DNSMASQ_CONF, "-x",
                 DNSMASQ_PID],
                capture_output=True, text=True, timeout=15.0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.last_error = str(exc)
            return False, f"dnsmasq could not be launched: {exc}"

        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            self.last_error = stderr or f"exit {proc.returncode}"
            hint = ""
            if "change group-id" in stderr or "change user-id" in stderr:
                # Distinctive enough to name the cause outright: this only
                # happens when the launching unit's CapabilityBoundingSet lacks
                # CAP_SETGID/CAP_SETUID, which children inherit.
                hint = (" — the service's CapabilityBoundingSet is missing "
                        "CAP_SETGID/CAP_SETUID, which dnsmasq needs to drop "
                        "privileges")
            return False, f"dnsmasq exited {proc.returncode}: {self.last_error}{hint}"

        # Confirm it actually stayed up rather than trusting the fork's exit.
        for _ in range(20):
            if self._running():
                self.last_error = None
                detail = "dnsmasq started"
                if stderr:
                    detail += f" (warnings: {stderr})"
                return True, detail
            time.sleep(0.1)

        self.last_error = stderr or "process vanished after starting"
        return False, f"dnsmasq did not stay running: {self.last_error}"

    def leases(self) -> list[dict[str, Any]]:
        entries = []
        for line in read_text(DNSMASQ_LEASES).splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            entries.append({
                "expires": int(parts[0]) if parts[0].isdigit() else 0,
                "mac": parts[1], "address": parts[2],
                "hostname": None if parts[3] == "*" else parts[3],
                "client_id": parts[4] if len(parts) > 4 else None,
            })
        return entries


class TrafficManager:
    """Apply UCGF-style Smart Queues with Linux CAKE.

    Egress shaping attaches directly to each WAN.  Download shaping redirects
    WAN ingress to one private IFB per WAN, because an ingress qdisc cannot pace
    packets itself.  The names and handles are owned by sbegw and are stable, so
    disabling the feature removes only qdiscs created by this manager.
    """

    IFB_PREFIX = "ifb-sbegw"
    ROOT_HANDLE = "1:"

    def __init__(self, wans: WanManager, events=None):
        self.wans = wans
        self.events = events
        self.last_error: str | None = None

    @classmethod
    def _ifb(cls, index: int) -> str:
        # Linux interface names are limited to 15 characters including NUL.
        return f"{cls.IFB_PREFIX}{index}"

    @staticmethod
    def _qdiscs(interface: str) -> list[dict[str, Any]]:
        return run_json(["tc", "-j", "qdisc", "show", "dev", interface],
                        default=[]) or []

    @classmethod
    def _has_owned_cake(cls, interface: str) -> bool:
        return any(q.get("kind") == "cake" and
                   q.get("handle") == cls.ROOT_HANDLE
                   for q in cls._qdiscs(interface))

    @classmethod
    def _cleanup(cls, interface: str, ifb: str) -> None:
        # The private IFB and explicit root handle are ownership markers.  Do
        # not disturb administrator-created CAKE or ingress policies.
        owned_ifb = os.path.exists(f"/sys/class/net/{ifb}")
        if cls._has_owned_cake(interface):
            run_ok(["tc", "qdisc", "del", "dev", interface, "root"])
        qdiscs = cls._qdiscs(interface) if owned_ifb else []
        if any(q.get("kind") == "ingress" and q.get("handle") == "ffff:"
               for q in qdiscs):
            run_ok(["tc", "qdisc", "del", "dev", interface, "ingress"])
        if owned_ifb:
            if cls._has_owned_cake(ifb):
                run_ok(["tc", "qdisc", "del", "dev", ifb, "root"])
            run_ok(["ip", "link", "del", "dev", ifb])

    def apply(self, cfg: dict[str, Any]) -> list[str]:
        qos = cfg.get("qos", {})
        requested = bool(qos.get("enabled"))
        enabled = requested and not ap_mode(cfg)
        wan_items = [(wid, wan) for wid, wan in sorted(cfg.get("wans", {}).items())
                     if wan.get("enabled", True) and wan.get("mode") != "disabled"]
        messages: list[str] = []

        if which("tc") is None:
            self.last_error = "tc is not installed" if requested else None
            return (["Smart Queues unavailable: iproute2 tc is not installed"]
                    if requested else [])

        # Always clean the interfaces in the current config first.  `replace`
        # alone cannot remove a previously configured download IFB when the new
        # policy shapes uploads only.
        for index, (_wid, wan) in enumerate(wan_items):
            self._cleanup(self.wans.interface_for(wan, cfg), self._ifb(index))

        if not enabled:
            self.last_error = None
            if requested and ap_mode(cfg):
                return ["Smart Queues are bypassed in AP mode"]
            return []

        if not wan_items:
            self.last_error = "no enabled WAN is configured"
            return [f"Smart Queues unavailable: {self.last_error}"]

        down = int(qos.get("download_kbps") or 0)
        up = int(qos.get("upload_kbps") or 0)
        failures: list[str] = []
        for index, (wid, wan) in enumerate(wan_items):
            interface = self.wans.interface_for(wan, cfg)
            ifb = self._ifb(index)
            try:
                if up:
                    run(["tc", "qdisc", "replace", "dev", interface, "root",
                         "handle", self.ROOT_HANDLE, "cake", "bandwidth",
                         f"{up}kbit", "diffserv4", "nat", "dual-srchost",
                         "ack-filter"])
                if down:
                    if not os.path.exists(f"/sys/class/net/{ifb}"):
                        run(["ip", "link", "add", ifb, "type", "ifb"])
                    run(["ip", "link", "set", "dev", ifb, "up"])
                    run(["tc", "qdisc", "replace", "dev", interface,
                         "handle", "ffff:", "ingress"])
                    run(["tc", "filter", "replace", "dev", interface,
                         "parent", "ffff:", "protocol", "all", "matchall",
                         "action", "mirred", "egress", "redirect", "dev", ifb])
                    run(["tc", "qdisc", "replace", "dev", ifb, "root",
                         "handle", self.ROOT_HANDLE, "cake", "bandwidth",
                         f"{down}kbit", "diffserv4", "nat", "wash",
                         "dual-dsthost", "ingress"])
                directions = "/".join(x for x, rate in
                                      (("download", down), ("upload", up)) if rate)
                messages.append(f"Smart Queues enabled on {wid} ({directions})")
            except (ToolError, OSError, subprocess.TimeoutExpired) as exc:
                self._cleanup(interface, ifb)
                failures.append(f"{wid}: {exc}")

        self.last_error = "; ".join(failures) or None
        if failures:
            detail = "Smart Queues failed: " + self.last_error
            messages.append(detail)
            if self.events:
                self.events.emit("QOS_FAILED", "error", {"detail": self.last_error},
                                 subsystem="qos", message=detail)
        return messages

    def status(self, cfg: dict[str, Any]) -> dict[str, Any]:
        qos = cfg.get("qos", {})
        interfaces = []
        wan_items = [(wid, wan) for wid, wan in sorted(cfg.get("wans", {}).items())
                     if wan.get("enabled", True) and wan.get("mode") != "disabled"]
        for index, (wid, wan) in enumerate(wan_items):
            interface = self.wans.interface_for(wan, cfg)
            ifb = self._ifb(index)
            interfaces.append({
                "wan": wid,
                "interface": interface,
                "upload_active": (self._has_owned_cake(interface)
                                  if which("tc") else False),
                "download_active": (os.path.exists(f"/sys/class/net/{ifb}")
                                    and self._has_owned_cake(ifb))
                                   if which("tc") else False,
            })
        return {
            "requested": bool(qos.get("enabled")),
            "effective": bool(qos.get("enabled")) and not ap_mode(cfg)
                         and any(i["upload_active"] or i["download_active"]
                                 for i in interfaces),
            "tool_available": which("tc") is not None,
            "interfaces": interfaces,
            "error": self.last_error,
        }


class NetDaemon:
    """Coordinates the managers and acts as configd's network applier."""

    def __init__(self, events=None):
        self.events = events
        self.ports = PortManager(events)
        self.networks = NetworkManager(events)
        self.wans = WanManager(events)
        self.services = ServiceManager(events)
        self.traffic = TrafficManager(self.wans, events)

    # configd calls this before anything is applied.
    def preflight(self, old: dict[str, Any],
                  new: dict[str, Any]) -> tuple[bool, list[str]]:
        problems: list[str] = []
        present = set(self.ports.discover())
        for wid, wan in new.get("wans", {}).items():
            if wan.get("enabled", True) and wan.get("port") not in present:
                problems.append(f"WAN {wid} references absent port {wan.get('port')}")
        lan = [p for p, c in new.get("ports", {}).items()
               if c.get("role") == "lan" and c.get("enabled", True)]
        if not lan:
            problems.append("no enabled LAN port would remain; refusing to lock you out")
        if nft.available() is False:
            problems.append("nft is unavailable; the firewall cannot be applied")
        return (not problems), problems

    def __call__(self, old: dict[str, Any], new: dict[str, Any]) -> ApplyResult:
        messages: list[str] = []

        # Stages are isolated: one raising must not skip the rest. Previously a
        # single exception anywhere in here aborted the whole apply, so (for
        # example) a WAN hiccup meant dnsmasq was never started and the LAN had
        # no DHCP at all — with the bridge up and addressed, which looks like a
        # working router.
        def stage(name: str, fn, *args) -> bool:
            try:
                result = fn(*args)
                if isinstance(result, list):
                    messages.extend(result)
                return True
            except Exception as exc:  # noqa: BLE001
                log.exception("netd stage %s failed", name)
                messages.append(f"{name} failed: {exc}")
                if self.events:
                    self.events.emit("CONFIG_ROLLED_BACK", "error",
                                     {"stage": name, "detail": str(exc)},
                                     subsystem="netd",
                                     message=f"netd stage {name} failed: {exc}")
                return False

        # Ports and networks are load-bearing: without them nothing else can
        # work, so a failure there fails the commit.
        if not stage("ports", self.ports.apply, new):
            return ApplyResult(False, messages)
        if not stage("networks", self.networks.apply, new):
            return ApplyResult(False, messages)

        # These are reported but must not roll back a working bridge.
        stage("wans", self.wans.apply, new)
        stage("dhcp/dns", self.services.apply, new)
        stage("smart queues", self.traffic.apply, new)
        stage("routing", self.apply_routing, new)

        try:
            ok, message = self.apply_firewall(new)
            messages.append(message)
            if not ok:
                return ApplyResult(False, messages)
        except Exception as exc:  # noqa: BLE001
            log.exception("firewall apply failed")
            return ApplyResult(False, messages + [f"firewall: {exc}"])

        # Changes that can cut the admin's own path to the box need confirming.
        risky = self._is_risky(old, new)
        return ApplyResult(True, messages, requires_confirmation=risky)

    @staticmethod
    def _is_risky(old: dict[str, Any], new: dict[str, Any]) -> bool:
        for key in ("ports", "networks", "firewall", "wans", "dns", "qos"):
            if old.get(key) != new.get(key):
                return True
        return False

    def apply_firewall(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        # An AP routes nothing, so there is no WAN zone and nothing to
        # masquerade. Leaving the WAN port in the wan zone would also drop the
        # upstream traffic that now arrives over the bridge.
        wan_ifaces = {} if ap_mode(cfg) else self.wans.interfaces(cfg)
        zones = self.networks.zone_interfaces(cfg, wan_ifaces)
        ruleset = nft.render(cfg, zones, wan_ifaces)
        return nft.apply_ruleset(ruleset)

    def apply_routing(self, cfg: dict[str, Any]) -> list[str]:
        messages: list[str] = []
        routing = cfg.get("routing", {})
        for route in routing.get("static", []):
            family = 6 if ":" in route["destination"] else 4
            ok = rtnl.replace_route(
                route["destination"], via=route.get("via"),
                dev=route.get("interface"), metric=route.get("metric", 100),
                kind=route.get("type", "gateway"), family=family)
            if not ok:
                messages.append(f"static route {route['destination']} could not be installed")

        # Policy routing: one table per WAN, plus fwmark rules from nft marks.
        for index, (wid, wan) in enumerate(sorted(cfg.get("wans", {}).items()), start=1):
            table = str(100 + index)
            iface = self.wans.interface_for(wan, cfg)
            gateway = self.wans._default_gateway(iface)
            if gateway:
                rtnl.replace_route("default", via=gateway, dev=iface, table=table)
        for index, route in enumerate(cfg.get("policy_routes", []), start=1):
            if not route.get("enabled", True):
                continue
            mark = route.get("mark") or (0x100 + index)
            target_wan = route.get("wan")
            wan_ids = sorted(cfg.get("wans", {}))
            if target_wan in wan_ids:
                table = str(100 + wan_ids.index(target_wan) + 1)
                rtnl.add_rule("fwmark", hex(mark), "lookup", table, "priority",
                              str(1000 + index))
        if routing.get("frr", {}).get("enabled") and which("vtysh") is None:
            messages.append("dynamic routing is enabled but FRR is not installed; "
                            "add the frr package to the rootfs")
        return messages

    # -------------------------------------------------------------- snapshots

    def snapshot(self, cfg: dict[str, Any]) -> dict[str, Any]:
        wan_health = self.wans.health()
        return {
            "ports": self.ports.all_states(cfg),
            "wans": list(wan_health.values()),
            "networks": self.network_states(cfg),
            "primary_wan": self.wans.select_primary(cfg),
        }

    def network_states(self, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        leases = self.services.leases()
        for nid, net in cfg.get("networks", {}).items():
            iface = self.networks.interface_for(nid, net)
            addresses = []
            for entry in rtnl.addresses(iface):
                for info in entry.get("addr_info", []):
                    if info.get("scope") in ("global", "site"):
                        addresses.append(f"{info['local']}/{info['prefixlen']}")
            subnet = net.get("subnet")
            in_scope = 0
            if subnet:
                network = ipaddress.ip_interface(subnet).network
                for lease in leases:
                    try:
                        if ipaddress.ip_address(lease["address"]) in network:
                            in_scope += 1
                    except ValueError:
                        continue
            out.append({
                "id": nid, "name": net.get("name", nid),
                "purpose": net.get("purpose"), "zone": net.get("zone"),
                "vlan": net.get("vlan"), "interface": iface,
                "subnet": subnet, "addresses": addresses,
                "dhcp_enabled": net.get("dhcp", {}).get("enabled", False),
                "lease_count": in_scope,
                "isolation": net.get("isolation", False),
                "internet_access": net.get("internet_access", True),
                "counters": rtnl.stats(iface),
            })
        return out
