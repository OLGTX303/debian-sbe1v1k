# UCGF `/usr/share` gateway analysis

This note records which ideas were taken from the extracted UCGF filesystem and
how they map to the SBE1V1K Debian control plane. It is an implementation map,
not a claim that `sbegw` contains or reproduces UniFi OS.

## Useful sources in the extracted image

- `usr/share/ubios-udapi-server/config-board/ucg-fiber-a6a8.json` describes the
  UCGF capability model: mutable interfaces, two WAN roles, VLAN-aware switch
  ports, hardware-offload mode, thermal/storage descriptors and SFP state.
- `usr/share/ubios-udapi-server/config-migrate-v2/` exposes the durable gateway
  domains through its migration names. The relevant families are interfaces,
  VLANs, firewall filter/NAT/PBR/sets, static and dynamic routing, QoS, DNS/DHCP,
  multicast, WAN failover, VPN, DPI and IDS/IPS.
- `usr/share/unifi-core/app` is the console/application supervisor. It is a
  large Node application with local PostgreSQL state, cloud/identity hooks and
  bundled setup/portal applications; it is not the packet-routing data plane.
- `usr/share/dpi/tdts` and the matching kernel extensions implement the closed
  Trend Micro classifier. The extracted 5.4 modules cannot load into this
  project's QSDK 6.6 kernel, and neither those modules nor their signatures are
  copied into sbegw.
- `usr/bin/udapi-bridge` connects the local Network application to
  `ubios-udapi-server` over a Unix peer socket and loopback port 1080. It is an
  internal console RPC bridge, not the remote device-adoption protocol.
- The management palette and density were measured from the shipped web assets.
  No vendor JavaScript or branded component bundle is included in this project.

The UCGF board JSON must not be treated as SBE1V1K hardware truth. UCGF declares
an RTL8372 switch, SFP+ outlets and one PoE port; SBE1V1K has a different
Ethernet/PHY layout plus three QCN9274 radios. `sbegw` therefore adopts the
capability-oriented pattern while keeping discovery and board data specific to
the SBE1V1K device tree, ART and live kernel state.

## Domain mapping

| UCGF domain family | sbegw owner | State |
| --- | --- | --- |
| interfaces, vlans, dhcpServers | `netd`, `schema` | Integrated |
| firewall-filter, firewall-nat, firewall-pbr, firewall-sets | `netd`, nft adapter | Integrated |
| routes-static, WAN failover | `netd` | Integrated |
| dnsForwarder | `ServiceManager` / dnsmasq | Integrated, now exposed in API/UI |
| qos, qos-ip | `TrafficManager` / CAKE + IFB | Integrated, now exposed in API/UI |
| mdns, IGMP, UPnP | network/service config | Partially integrated; no dedicated page yet |
| WireGuard, IPsec, OpenVPN | reserved config model | Not yet applied |
| DPI | `DpiEngine` / Debian Suricata | Integrated as passive app-layer accounting; no vendor signatures |
| IDS/IPS, geo-IP, UTM | none | Deliberately not copied; no false capability is advertised |
| BGP/OSPF | routing model / optional FRR | Model present; full UI and renderer pending |
| UniFi adoption and telemetry | `UniFiControllerAgent` | TNBU inform + UDP discovery compatibility |
| UniFi desired state | `UniFiControllerAgent` | Networks, WiFi and DNS via documented local Network API |
| UniFi identity/cloud/notifications | none | Not copied; these are console services, not gateway control |

## Traffic and DNS integration

`GET/PUT /api/v1/services` now returns and transactionally updates the two
service domains. The same schema gate used by ports, firewall and Wi-Fi rejects
empty Smart Queue rates, malformed resolver addresses, invalid domain names and
bad local records before dnsmasq or `tc` is touched.

Smart Queues use CAKE directly on WAN egress. WAN ingress is redirected through
one private IFB per WAN and shaped there; disabling the policy removes only
CAKE/IFB objects owned by sbegw. AP mode bypasses shaping because it has no routed
WAN. Runtime status distinguishes configured from active and reports a missing
tool or rejected qdisc instead of showing a false success state.

The reference 5.4 image contains `sch_cake`, `ifb`, `act_mirred` and
`cls_matchall`, but those modules are not ABI-compatible with the QSDK 6.6
kernel. `scripts/build-qsdk-gateway-modules.sh` enables and builds the matching
QSDK packages; the existing Debian rootfs assembly then copies them with the
other 6.6 modules.

DNS configuration is rendered through the existing private dnsmasq instance:
upstream resolvers, DNSSEC, query logging, cache sizing, local A/AAAA/CNAME/SRV/
TXT records, conditional forwarders, and explicit allow/block domain lists.
dnsmasq validates the generated file before the live process is restarted.

## DPI integration

When enabled, `DpiEngine` renders a private, bounded-ring Suricata AF_PACKET
configuration for `br-lan` and its VLAN interfaces. EVE flow, TLS, HTTP and DNS
metadata refine generic encrypted flows into common services. The gateway
aggregates application/category, byte and packet totals per LAN client in a
bounded SQLite database; it does not retain packet payloads, URLs or DNS
answers. Local API/UI reads return the same totals used to build the legacy
`dpi-stats` inform field, plus capture-health counters.

This is application-aware accounting, not IDS/IPS. Hardware flow offload may
bypass passive inspection, so validation raises a visible warning if both are
requested. If both are explicitly enabled, ECM's vendor-derived 25-packet delay
gives Suricata an identification window before PPE acceleration; the UI still
marks byte accounting as partial. Failure to start Suricata raises `DPI_FAILED`,
but cannot roll back a working LAN because DPI is observational rather than
forwarding-critical.

## UniFi Network interoperability

The gateway has two separate controller paths:

1. UDP 10001 discovery and encrypted TNBU `/inform` messages implement the
   independent-gateway adoption/telemetry handshake, including CBC/GCM key
   transition, interface counters, leases and DPI totals.
2. An operator-provided local Network Integration API key pulls supported
   desired state. Networks, Standard/IoT WiFi broadcasts and DNS policies are
   translated, validated and committed through the same transaction layer as
   local changes.

Controller state and the adopted auth key live in a mode-0600 state file. The
Network API key is redacted from normal configuration reads and audit diffs.
Unsupported controller responses and objects are retained in controller status
instead of being reported as applied. See `unifi_network_interoperability.md`
for configuration and exact limits.

## UI decisions

Traffic & DNS is one navigation entry and two dense primary cards, followed by
plain record/forwarder tables. It reuses the console's existing typography,
4 px controls, shared pills, banners, tables and modal behavior. There are no
gradients, oversized marketing headings, decorative illustrations, invented
metrics or a second design system. This keeps it visually consistent with the
rest of the gateway and with the reference appliance's information density.

Traffic Identification and UniFi Network follow those same cards, fields,
tables, pills, button sizes and spacing. No visual generator, bitmap decoration
or parallel component library was introduced.
