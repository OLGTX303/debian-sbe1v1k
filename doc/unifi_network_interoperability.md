# UniFi Network interoperability

`sbegw` can present the SBE1V1K to a UniFi Network application as an independent
gateway and can pull a defined subset of controller configuration. This is a
community compatibility layer, not Ubiquiti firmware, UniFi OS, or a supported
Ubiquiti product identity.

## Architecture

The extracted UCG-Fiber image has three different layers that should not be
confused:

- `unifi-core` supervises applications on a UniFi console.
- The Network application talks to the co-resident gateway through the private
  loopback `udapi-bridge` and `ubios-udapi-server` peer socket.
- Independent gateways use UDP discovery and encrypted TNBU messages at the
  Network application's `/inform` endpoint.

The private UDAPI path assumes the vendor database, object factories, binaries
and local socket. `sbegw` does not copy or emulate that console-internal stack.
It implements the independent-gateway inform path for adoption and telemetry,
then uses the documented local Network Integration API for desired state.

## Configure it

Open **System → UniFi Network** in the local gateway UI.

1. Enter the application inform URL, normally
   `http://controller.example:8080/inform`, enable controller control, and
   apply. Layer-2 discovery can stay enabled when gateway and application share
   a broadcast domain.
2. In UniFi Network, adopt the pending gateway. TCP 8080 and UDP 10001 must be
   reachable in the relevant direction. The pairing key is stored only in
   `/data/sbegw/unifi-controller.json`, mode 0600.
3. To let controller configuration change this gateway, create a local Network
   Integration API key and enable synchronization. Enter the API base ending in
   `/proxy/network/integration/v1`, the site UUID, and the key. Keep TLS
   verification enabled unless the controller uses a private certificate that
   this gateway cannot validate.

Inform and API synchronization are separate switches. This lets an operator
use UniFi only for visibility without giving it desired-state authority.

## What is synchronized

The current implementation translates:

- gateway-managed IPv4 networks, VLANs, isolation, DHCP ranges and DNS options;
- Standard and IoT-optimized WiFi broadcasts with open/WPA2/WPA3 personal
  security, band selection, client isolation and related broadcast options;
- local DNS records and conditional forwarding policies.

Each pull builds a complete candidate for those three domains, validates it
against SBE1V1K capabilities, and only then applies it transactionally. Physical
port references are kept valid when a controller network disappears. A bad
subnet, unsupported security mode, incomplete DHCP range, or impossible MLO
combination rejects the whole pull instead of partly reconfiguring the router.

Firewall policy, VPN, routing protocols, IDS/IPS, RADIUS/enterprise WiFi,
hotspot, PPSK and vendor-only domains are not currently fetched. Unsupported
objects inside the synchronized domains, and unsupported inform commands, are
listed in **Controller status → Not applied by this gateway**. Local
configuration remains authoritative for every other domain.

## DPI telemetry

Debian Suricata passively parses flows on the LAN bridge and VLAN interfaces.
`sbegw` stores per-client application byte/packet totals and publishes them in
the legacy gateway `dpi-stats` inform shape. No UCG-Fiber Trend Micro module or
signature database is used: those assets are closed and tied to its 5.4 kernel.

This feature provides traffic identification only. It is not an IDS/IPS engine,
does not block flows, and cannot see packets bypassed by hardware offload.

## Operational limits

- The compatibility identity is the legacy `UGW3` independent-gateway model.
  Controller releases can change undocumented adoption behavior.
- Adoption does not make the SBE1V1K a UniFi Cloud Gateway and does not install
  UniFi OS applications on it.
- The local gateway UI stays available and is the recovery/control surface if
  the controller or API is offline.
- Controller errors, last inform/sync times, crypto availability and unsupported
  objects are visible in the local UI and `GET /api/v1/controller`.

## References

- [UniFi device adoption](https://help.ui.com/hc/en-us/articles/360012622613-UniFi-Device-Adoption)
- [Self-hosting UniFi](https://help.ui.com/hc/en-us/articles/34210126298775-Self-Hosting-UniFi)
- [Official UniFi API getting started](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- [UniFi Network Integration API schema](https://developer.ui.com/network/v10.4.57/openapi.json)
- [Required ports](https://help.ui.com/hc/en-us/articles/218506997-Required-Ports-Reference)
