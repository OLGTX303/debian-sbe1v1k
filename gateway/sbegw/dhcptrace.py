"""dhcptrace — settle whether LAN frames physically reach the CPU.

Server-side DHCP has been proven working on this platform (dnsmasq binds
0.0.0.0%br-lan:67, and an injected DISCOVER gets a lease), yet clients get no
address and the nftables LAN counters stay at zero. That leaves exactly two
possibilities, and they need different fixes:

  * frames never arrive — cabling, port role, the NSS/PPE datapath not
    delivering to the host, or the bridge dropping them; or
  * frames arrive but the ruleset does not match them — a zone-set or VLAN
    mismatch.

Interface byte counters cannot distinguish those on this box: an offloaded
datapath may not increment them, and until now `rtnl.stats()` was reading
`ip -j link` without `-s` and so reported zero unconditionally. So this module
does not trust counters. It opens an AF_PACKET socket per interface and reports
what the kernel actually delivers, which is the same thing tcpdump would show —
tcpdump is not in the rootfs, hence doing it here.

Nothing is transmitted; this is purely passive.
"""
from __future__ import annotations

import select
import socket
import struct
import subprocess
import time
from collections import Counter
from shutil import which
from typing import Any

from .adapters import rtnl

ETH_P_ALL = 0x0003

# sockaddr_ll.sll_pkttype
PKTTYPE = {0: "to-us", 1: "broadcast", 2: "multicast", 3: "other-host",
           4: "outgoing", 5: "loopback", 6: "fastroute"}

ETHERTYPE = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q",
             0x88A8: "802.1ad", 0x8863: "PPPoE-disc", 0x8864: "PPPoE-ses",
             0x88CC: "LLDP", 0x8809: "LACP"}

DHCP_MSG = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
            6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _decode(frame: bytes) -> tuple[str, str]:
    """Return (category, human description) for one Ethernet frame."""
    if len(frame) < 14:
        return "short", f"runt frame, {len(frame)} bytes"
    dst, src = _mac(frame[0:6]), _mac(frame[6:12])
    etype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    tag = ""
    # A VLAN tag is normally stripped by the kernel before it reaches us, but
    # handle it when present so a double-tagged or unstripped frame is readable.
    while etype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        vid = struct.unpack("!H", frame[offset:offset + 2])[0] & 0x0FFF
        etype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        tag += f" vlan{vid}"
        offset += 4

    name = ETHERTYPE.get(etype, f"0x{etype:04x}")
    base = f"{src} > {dst}{tag} {name}"

    if etype == 0x0806 and len(frame) >= offset + 28:
        op = struct.unpack("!H", frame[offset + 6:offset + 8])[0]
        spa = ".".join(str(b) for b in frame[offset + 14:offset + 18])
        tpa = ".".join(str(b) for b in frame[offset + 24:offset + 28])
        kind = "request" if op == 1 else "reply" if op == 2 else f"op{op}"
        return "arp", f"{base} {kind} who-has {tpa} tell {spa}"

    if etype != 0x0800 or len(frame) < offset + 20:
        return "other", base

    ihl = (frame[offset] & 0x0F) * 4
    proto = frame[offset + 9]
    src_ip = ".".join(str(b) for b in frame[offset + 12:offset + 16])
    dst_ip = ".".join(str(b) for b in frame[offset + 16:offset + 20])
    base = f"{base} {src_ip} > {dst_ip}"
    if proto != 17:
        return "other", f"{base} proto {proto}"

    udp = offset + ihl
    if len(frame) < udp + 8:
        return "other", f"{base} UDP (truncated)"
    sport, dport = struct.unpack("!HH", frame[udp:udp + 4])
    base = f"{base} UDP {sport}->{dport}"
    if {sport, dport} & {67, 68}:
        payload = frame[udp + 8:]
        detail = ""
        # BOOTP: op(1) .. xid at 4, chaddr at 28, magic cookie at 236.
        if len(payload) >= 240 and payload[236:240] == b"\x63\x82\x53\x63":
            xid = struct.unpack("!I", payload[4:8])[0]
            chaddr = _mac(payload[28:34])
            msgtype = None
            i = 240
            while i + 1 < len(payload):
                opt = payload[i]
                if opt == 255:
                    break
                if opt == 0:
                    i += 1
                    continue
                length = payload[i + 1]
                if opt == 53 and length >= 1:
                    msgtype = payload[i + 2]
                    break
                i += 2 + length
            detail = (f" {DHCP_MSG.get(msgtype, f'type{msgtype}')}"
                      f" xid=0x{xid:08x} client={chaddr}")
        return "dhcp", f"{base} DHCP{detail}"
    return "other", base


def _lan_interfaces() -> list[str]:
    """br-lan, its enslaved ports and its SVIs."""
    names: list[str] = []
    for info in rtnl.links():
        name = info.get("ifname", "")
        if not name:
            continue
        if name == "br-lan" or name.startswith("br-lan.") or \
                info.get("master") == "br-lan":
            names.append(name)
    return names


def _counters(names: list[str]) -> dict[str, dict[str, int]]:
    return {n: rtnl.stats(n) for n in names}


def _run(argv: list[str]) -> str:
    if not which(argv[0]):
        return f"({argv[0]} is not installed)"
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return (done.stdout + done.stderr).strip() or "(no output)"
    except Exception as exc:  # noqa: BLE001
        return f"({argv[0]} failed: {exc})"


def _section(title: str) -> None:
    print(f"\n--- {title} " + "-" * max(0, 62 - len(title)))


def trace(seconds: float = 30.0) -> int:
    names = _lan_interfaces()
    if not names:
        print("br-lan does not exist, so there is no LAN datapath to trace.")
        return 1

    print("=" * 72)
    print("sbegw DHCP datapath trace")
    print("=" * 72)
    print(f"listening passively on: {', '.join(names)}")
    print(f"duration: {seconds:g}s — plug a client in now, or renew its lease")

    _section("bridge state")
    print(_run(["bridge", "-s", "link", "show"]))
    _section("bridge VLANs")
    print(_run(["bridge", "vlan", "show"]))
    _section("nftables LAN zone set")
    print(_run(["nft", "list", "set", "inet", "sbegw", "zone_lan"]))

    before = _counters(names)

    sockets: dict[int, tuple[socket.socket, str]] = {}
    for name in names:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
            sock.bind((name, 0))
            sock.setblocking(False)
            sockets[sock.fileno()] = (sock, name)
        except OSError as exc:
            print(f"  cannot capture on {name}: {exc}")
    if not sockets:
        print("no capture socket could be opened; CAP_NET_RAW is required.")
        return 1

    seen: Counter[tuple[str, str]] = Counter()
    pkttypes: Counter[tuple[str, str]] = Counter()
    dhcp_lines: list[str] = []
    dhcp_ifaces: set[str] = set()
    total = 0

    _section("live capture")
    deadline = time.monotonic() + seconds
    poller = select.poll()
    for fd in sockets:
        poller.register(fd, select.POLLIN)

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        for fd, _ in poller.poll(min(remaining, 1.0) * 1000):
            sock, name = sockets[fd]
            while True:
                try:
                    frame, addr = sock.recvfrom(2048)
                except BlockingIOError:
                    break
                except OSError:
                    break
                total += 1
                pkttype = PKTTYPE.get(addr[2], str(addr[2]))
                category, text = _decode(frame)
                seen[(name, category)] += 1
                pkttypes[(name, pkttype)] += 1
                if category == "dhcp":
                    dhcp_ifaces.add(name)
                    line = f"  [{name} {pkttype}] {text}"
                    print(line, flush=True)
                    dhcp_lines.append(line)
                elif category == "arp" and seen[(name, "arp")] <= 5:
                    print(f"  [{name} {pkttype}] {text}", flush=True)

    for sock, _ in sockets.values():
        sock.close()

    after = _counters(names)

    _section("frames captured")
    if not total:
        print("  none at all")
    for name in names:
        cats = {c: n for (i, c), n in seen.items() if i == name}
        types = {t: n for (i, t), n in pkttypes.items() if i == name}
        total_iface = sum(cats.values())
        print(f"  {name:<12} {total_iface:>6} frames  "
              f"{cats or '{}'}  {types or '{}'}")

    _section("interface counter deltas over the window")
    for name in names:
        b, a = before[name], after[name]
        print(f"  {name:<12} rx_packets +{a['rx_packets'] - b['rx_packets']:<8} "
              f"tx_packets +{a['tx_packets'] - b['tx_packets']:<8} "
              f"rx_dropped +{a['rx_dropped'] - b['rx_dropped']:<6} "
              f"(absolute rx={a['rx_packets']} tx={a['tx_packets']})")

    ports = [n for n in names if n != "br-lan" and not n.startswith("br-lan.")]
    for name in ports:
        _section(f"ethtool -S {name} (driver counters)")
        out = _run(["ethtool", "-S", name])
        interesting = [l for l in out.splitlines()
                       if any(k in l.lower() for k in
                              ("rx", "drop", "err", "discard"))
                       and not l.strip().endswith(": 0")]
        print("\n".join(f"  {l.strip()}" for l in interesting[:25])
              or "  (all driver counters are zero)")

    _section("nftables LAN counters now")
    out = _run(["nft", "list", "chain", "inet", "sbegw", "input"])
    for line in out.splitlines():
        if "zone_lan" in line or "counter" in line:
            print(f"  {line.strip()}")

    _section("verdict")
    dhcp_total = sum(n for (_, c), n in seen.items() if c == "dhcp")
    port_frames = sum(n for (i, _), n in seen.items() if i in ports)
    bridge_frames = sum(n for (i, _), n in seen.items() if i == "br-lan")

    if dhcp_total:
        print(f"  {dhcp_total} DHCP frame(s) reached the CPU.")
        if "br-lan" in dhcp_ifaces:
            print("  They arrive on br-lan, so the datapath and the bridge are "
                  "fine.\n  If the nftables zone_lan counter above is still 0, "
                  "the ruleset is\n  not matching them — that is the bug.")
        else:
            print("  They arrive on a port but NOT on br-lan, so the bridge "
                  "is not\n  delivering them locally. Check `bridge vlan show` "
                  "above: if there is\n  no row for br-lan itself, the bridge "
                  "device is missing its own VLAN\n  membership and no frame "
                  "can ever reach a socket. That is fixed by\n  `bridge vlan "
                  "add dev br-lan vid 1 pvid untagged self`.")
    elif port_frames or bridge_frames:
        print(f"  Traffic is flowing ({port_frames} on ports, {bridge_frames} "
              "on br-lan) but no\n  DHCP among it. The client is not sending "
              "DISCOVERs — it may have a\n  static address or a cached lease. "
              "Force a renew on the client.")
    else:
        print("  NOTHING was delivered to the CPU on any LAN interface.")
        print("  The client's frames are not reaching Linux at all. Check, in "
              "order:\n"
              "    1. link/cable — is the port LED on, is the peer up?\n"
              "    2. the port's role — a port set 'disabled' never forwards.\n"
              "    3. which socket the client is actually plugged into.\n"
              "  This is below the control plane; dnsmasq and nftables are not "
              "involved.")
    print()
    return 0
