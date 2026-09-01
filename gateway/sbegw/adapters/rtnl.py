"""rtnetlink adapter built on iproute2 JSON output.

`ip -j` is a stable, parseable interface and avoids a netlink binding dependency
in the rootfs. Every function returns plain data structures.
"""
from __future__ import annotations

import logging
from typing import Any

from ..util import run, run_json, run_ok

log = logging.getLogger("sbegw.rtnl")


def links() -> list[dict[str, Any]]:
    return run_json(["ip", "-j", "-d", "link", "show"], default=[]) or []


def link(name: str) -> dict[str, Any] | None:
    data = run_json(["ip", "-j", "-d", "link", "show", "dev", name], default=[]) or []
    return data[0] if data else None


def addresses(name: str | None = None) -> list[dict[str, Any]]:
    argv = ["ip", "-j", "addr", "show"]
    if name:
        argv += ["dev", name]
    return run_json(argv, default=[]) or []


def stats(name: str) -> dict[str, int]:
    """64-bit interface counters. Falls back to zeros if the link is gone.

    `-s` is required: `ip -j link show` omits stats64 entirely without it, so
    this silently returned all zeros — which zeroed every port counter and
    traffic rate in the UI and telemetry.
    """
    data = run_json(["ip", "-s", "-j", "link", "show", "dev", name],
                    default=[]) or []
    info = data[0] if data else {}
    rx = info.get("stats64", {}).get("rx", {})
    tx = info.get("stats64", {}).get("tx", {})
    return {
        "rx_bytes": rx.get("bytes", 0), "rx_packets": rx.get("packets", 0),
        "rx_errors": rx.get("errors", 0), "rx_dropped": rx.get("dropped", 0),
        "tx_bytes": tx.get("bytes", 0), "tx_packets": tx.get("packets", 0),
        "tx_errors": tx.get("errors", 0), "tx_dropped": tx.get("dropped", 0),
        "multicast": rx.get("multicast", 0),
    }


def routes(family: int = 4, table: str = "all") -> list[dict[str, Any]]:
    argv = ["ip", "-j", f"-{family}", "route", "show", "table", table]
    return run_json(argv, default=[]) or []


def neighbours(family: int = 4) -> list[dict[str, Any]]:
    return run_json(["ip", "-j", f"-{family}", "neigh", "show"], default=[]) or []


def fdb(bridge: str) -> list[dict[str, Any]]:
    return run_json(["bridge", "-j", "fdb", "show", "br", bridge], default=[]) or []


def bridge_links() -> list[dict[str, Any]]:
    return run_json(["bridge", "-j", "link", "show"], default=[]) or []


def bridge_vlans() -> list[dict[str, Any]]:
    return run_json(["bridge", "-j", "vlan", "show"], default=[]) or []


# ------------------------------------------------------------------ mutators

def set_up(name: str, up: bool = True) -> bool:
    return run_ok(["ip", "link", "set", "dev", name, "up" if up else "down"])


def set_mtu(name: str, mtu: int) -> bool:
    return run_ok(["ip", "link", "set", "dev", name, "mtu", str(mtu)])


def set_mac(name: str, mac: str) -> bool:
    return run_ok(["ip", "link", "set", "dev", name, "address", mac])


def ensure_bridge(name: str, *, vlan_filtering: bool = True,
                  stp: bool = False, default_pvid: int = 1) -> bool:
    """Create or reconcile a bridge.

    default_pvid is what makes this behave like an ordinary Linux bridge for
    software that is not this control plane. A VLAN-filtering bridge created
    with default_pvid 0 gives a newly enslaved port NO VLAN membership, so the
    bridge silently discards its untagged frames -- anything a third party
    attaches (a container veth, a tunnel, a test interface) is dead on arrival
    and needs a manual `bridge vlan add` to work at all. Measured on hardware:
    with pvid 0 a freshly added port could not even ping the gateway; with
    pvid 1 it got "1 PVID Egress Untagged" automatically and worked.

    Ports this control plane manages are given their VLANs explicitly
    afterwards, so this only decides the fallback for ports it does not know
    about. 1 is the kernel's own default.
    """
    args = ["vlan_filtering", "1" if vlan_filtering else "0",
            "stp_state", "1" if stp else "0"]
    # vlan_default_pvid is only meaningful on a VLAN-filtering bridge, and
    # older kernels reject it on one that is not.
    if vlan_filtering:
        args += ["vlan_default_pvid", str(default_pvid)]
    if link(name) is None:
        if not run_ok(["ip", "link", "add", "name", name, "type", "bridge"] + args):
            return False
    else:
        run_ok(["ip", "link", "set", "dev", name, "type", "bridge"] + args)
    return set_up(name)


def del_link(name: str) -> bool:
    """Delete a link. Absent is success: the caller wanted it gone."""
    if link(name) is None:
        return True
    return run_ok(["ip", "link", "delete", "dev", name])


def ensure_vlan(parent: str, vid: int, name: str) -> bool:
    if link(name) is None:
        if not run_ok(["ip", "link", "add", "link", parent, "name", name,
                       "type", "vlan", "id", str(vid)]):
            return False
    return set_up(name)


def enslave(port: str, bridge: str) -> bool:
    info = link(port) or {}
    if info.get("master") == bridge:
        return True
    return run_ok(["ip", "link", "set", "dev", port, "master", bridge])


def release(port: str) -> bool:
    return run_ok(["ip", "link", "set", "dev", port, "nomaster"])


def delete_link(name: str) -> bool:
    if link(name) is None:
        return True
    return run_ok(["ip", "link", "del", "dev", name])


def bridge_vlan_add(port: str, vid: int, *, pvid: bool = False,
                    untagged: bool = False, own: bool = False) -> bool:
    """Add a VLAN to a bridge port, or to the bridge device itself.

    `own` maps to iproute2's `self`, which is mandatory when *port* is the
    bridge device: without it the request is sent as `master` and the kernel
    rejects it with EOPNOTSUPP. That silently broke every tagged network, and
    the bridge's own VLAN-1 membership, whose absence stops frames from ever
    being delivered locally (they are still forwarded port to port, so the
    interface counters look healthy while nothing reaches a socket).
    """
    argv = ["bridge", "vlan", "add", "dev", port, "vid", str(vid)]
    if pvid:
        argv.append("pvid")
    if untagged:
        argv.append("untagged")
    if own:
        argv.append("self")
    return run_ok(argv)


def bridge_vlan_del(port: str, vid: int, *, own: bool = False) -> bool:
    argv = ["bridge", "vlan", "del", "dev", port, "vid", str(vid)]
    if own:
        argv.append("self")
    return run_ok(argv)


def sync_addresses(name: str, wanted: list[str]) -> list[str]:
    """Make *name* hold exactly *wanted* (CIDR strings). Returns changes made."""
    changes: list[str] = []
    current: set[str] = set()
    for entry in addresses(name):
        for info in entry.get("addr_info", []):
            if info.get("family") in ("inet", "inet6") and not info.get("temporary"):
                # Skip link-local IPv6, which the kernel owns.
                if info.get("scope") == "link":
                    continue
                current.add(f"{info['local']}/{info['prefixlen']}")
    for addr in current - set(wanted):
        if run_ok(["ip", "addr", "del", addr, "dev", name]):
            changes.append(f"-{addr}")
    for addr in set(wanted) - current:
        if run_ok(["ip", "addr", "add", addr, "dev", name]):
            changes.append(f"+{addr}")
    return changes


def flush_addresses(name: str) -> bool:
    return run_ok(["ip", "addr", "flush", "dev", name])


def replace_route(destination: str, *, via: str | None = None,
                  dev: str | None = None, metric: int = 100,
                  table: str = "main", kind: str = "gateway",
                  family: int = 4) -> bool:
    argv = ["ip", f"-{family}", "route", "replace"]
    if kind in ("blackhole", "unreachable"):
        argv += [kind, destination]
    else:
        argv.append(destination)
        if via:
            argv += ["via", via]
        if dev:
            argv += ["dev", dev]
    argv += ["metric", str(metric), "table", table]
    return run_ok(argv)


def del_route(destination: str, *, table: str = "main", family: int = 4) -> bool:
    return run_ok(["ip", f"-{family}", "route", "del", destination, "table", table])


def rules(family: int = 4) -> list[dict[str, Any]]:
    return run_json(["ip", "-j", f"-{family}", "rule", "show"], default=[]) or []


def add_rule(*args: str, family: int = 4) -> bool:
    return run_ok(["ip", f"-{family}", "rule", "add", *args])


def del_rule(*args: str, family: int = 4) -> bool:
    return run_ok(["ip", f"-{family}", "rule", "del", *args])


def sysctl(key: str, value: str) -> bool:
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(path, "r+") as fh:
            if fh.read().strip() == value:
                return True
            fh.seek(0)
            fh.write(value)
        return True
    except OSError as exc:
        log.debug("sysctl %s=%s failed: %s", key, value, exc)
        return False
