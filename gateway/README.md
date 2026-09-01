# sbegw — gateway control plane for the Askey SBE1V1K (IPQ9574)

A DIY enterprise-style router control plane for the SBE1V1K running Debian
bookworm arm64. It implements the data model, transactional configuration, REST
API and management UI described in `../doc/gateway_sepicafication.txt` and
`../doc/wifi_subsystem.txt`, with **Multi-Link Operation as a first-class object**
rather than a checkbox.

This is a do-it-yourself project. It is not a commercial product and is not
affiliated with Ubiquiti.

## Layout

```
sbegw/
  configd.py      candidate/running config, transactional commit, rollback, audit
  schema.py       config schema + validation (the only gate before a commit)
  netd.py         ports, bridge/VLANs, networks, WANs, firewall, NAT, DHCP/DNS
                  and CAKE/IFB Smart Queues
  wifid.py        radios, SSIDs, BSSes, MLO/MLD, wireless clients, RF, recovery
  clientd.py      unified wired + wireless client database
  dpi.py          passive Suricata app identification + bounded flow accounting
  unifi.py        UniFi discovery/inform and documented API desired-state sync
  telemetry.py    sampling, rate calculation, bounded retention
  events.py       event history, severity, filtering, live fan-out
  auth.py         local accounts, sessions, RBAC, API tokens, TOTP
  api.py          /api/v1 REST + SSE
  main.py         supervisor
  adapters/       the ONLY code allowed to touch iproute2/nft/iw/hostapd/QSDK
web/              management UI (vanilla JS, no build step, no CDN)
deploy/           systemd unit, nginx vhost, launcher + hostapd shim
tests/            smoke tests and a workstation demo server
```

The spec's service split (platformd/netd/wifid/clientd/telemetryd/eventd/healthd/
router-api) is preserved as module boundaries but runs in **one** supervised
process: on a 4-core IPQ9574 eight Python processes each holding a config copy
cost more than they buy, and a single process makes the transactional apply
genuinely atomic across subsystems.

## Multi-Link Operation

MLO is the reason this project cannot use Debian's hostapd.

* `rootfs/usr/sbin/hostapd` is Debian's **hostapd 2.10** — it contains **zero**
  MLD support (`mld_ap`, `mld_addr`, `mld_link_id` are all absent). It cannot
  bring up an 802.11be MLD at all.
* The QSDK build (`hostapd 2.12-devel`, the `wpad` multi-call binary) does. It is
  installed side-by-side under `/opt/sbegw/wifi` with its own musl loader and
  libraries; glibc and musl coexist because their dynamic loaders have different
  paths. `/opt/sbegw/bin/hostapd` is the shim that selects it.
* `ath12k.ko` on this build exposes the `mlo_capable` module parameter, so the
  driver side is present too.

`wifid` refuses to promise MLO it cannot deliver: `capabilities()["mlo"]`
reports `supported` only when *both* a radio advertises EHT+MLO and the installed
hostapd parses MLD keys, and the reason is surfaced in the API and UI when it
does not.

### Model

```
MLD (wifi.mlds.<id>)
 ├── link 0 -> radio-2g   (BSS wl2g0, mld_link_id=0)
 ├── link 1 -> radio-5g   (BSS wl5g0, mld_link_id=1)
 └── link 2 -> radio-6g   (BSS wl6g0, mld_link_id=2)
```

One hostapd process is given one config file *per link*; links of the same MLD
share `mld_addr` and differ in `interface` and `mld_link_id`. Validation enforces
what the protocol requires, before anything is applied:

* at least two links, at most one per band, no radio in two MLDs for one SSID
* WPA3 with PMF required (802.11be forbids WPA2-only MLDs)
* every linked band must be enabled on the SSID

Per-link runtime state (channel, width, noise, retry rate, client count) and
per-link client metrics (RSSI, SNR, MCS/NSS, bytes) are reported separately from
the aggregate, because the spec is explicit that `configured != working`.

### Stable identities

* **Radios** get logical ids (`radio-2g`/`radio-5g`/`radio-6g`) only after the
  capability probe proves the band. The phy↔id map is persisted keyed by the
  phy's MAC, so a PCIe re-enumeration that swaps `phy0`/`phy1` does not move an
  SSID to another band.
* **BSS slots** (hence netdev names and derived BSSIDs) are persisted per
  (radio, SSID) in `bss-slots.json`. Adding an unrelated SSID must not renumber
  existing BSSIDs and force every client to re-associate.

## Channel analysis and automatic channel selection

`rf.py` combines three independent sources into one per-channel picture:
neighbour APs from a passive scan, measured noise and airtime-busy from the
driver survey, and our own BSSes.

The UI draws it in the familiar WiFi-analyzer form: one trapezoid per BSS on a
real dBm axis, plotted in the **frequency** domain rather than by channel number
— on 2.4 GHz channels sit 5 MHz apart while a signal is 20 MHz wide, so only a
frequency axis shows the overlap truthfully. Each AP gets a stable pastel hue
derived from its BSSID so the chart does not reshuffle between refreshes.
Captions are laid out with collision avoidance, since two APs on one channel
would otherwise print on top of each other exactly where both need reading. Band
tabs carry AP counts, and an AP list under the chart repeats the colour key with
signal, security and channel.

Our own AP has no RSSI — we are the transmitter, not a receiver — so it is drawn
dashed near the top rather than given a fabricated signal level, and the list
shows no dBm figure for it.

The chart measures its container and builds geometry in real pixels: scaling a
fixed viewBox to the card width either shrinks the axis labels to unreadable or
letterboxes the plot with dead space. The x domain spans the full extent of every
block drawn, not just channel centres — a 160 MHz BSS on channel 36 reaches
80 MHz below its centre frequency, and deriving the domain from centres drew it
off the left edge over the axis labels. On 5 GHz the real UNII-2C/UNII-3 gap is
therefore visible, because it is really there.

Scoring penalises weighted neighbour interference (a -50 dBm neighbour costs far
more than a -85 dBm one), measured utilisation, and noise above the -95 dBm
floor; DFS carries a cost because a radar hit forces an evacuation and a CAC
wait, and 6 GHz non-PSC channels a small one. Staying put earns a bonus.

Two guards implement the spec's *do not change channels excessively*: a switch
needs a minimum score improvement over the **current** channel and a minimum
interval since the last change. `Optimise now` bypasses both; the scheduled run
does not. Changes are applied with a CSA (`CHAN_SWITCH`) so clients follow
instead of dropping, falling back to a config commit that restarts the BSS — and
saying so — when hostapd has no CSA support.

Two distinctions the code keeps separate, because conflating them produced real
bugs:

* `occupied_channels()` is the **interference footprint** — on 2.4 GHz a 20 MHz
  BSS on channel 1 splatters over channels 2-3.
* `bonded_channels()` is the set that must be **regulatory-permitted**, and is
  empty when a channel cannot host the width at all. 5 GHz channel 165 is
  20 MHz-only; treating it as an 80 MHz candidate made it look like the cleanest
  option available, because only one subchannel's interference was counted.

5 GHz bonded blocks come from the 802.11 tables, not arithmetic: UNII-2C ends at
144 and UNII-3 restarts at 149, so the block containing 149 cannot be derived
from the one containing 36.

## 240 MHz on 5 GHz

Not a standard channel width — it is 320 MHz EHT operation with one 80 MHz block
preamble-punctured, which this QSDK stack does support:

* `ath12k` carries `EHT240`, `ath12k_add_sta_240mhz_info_extn` and
  `WMI_PDEV_PARAM_SET_PREAM_PUNCT_BW`
* hostapd has a `5G 240MHz config identified` path and a "240 MHz Vendor NL
  command", alongside `5G 320MHz: ... punct_bitmap=`

So it renders as `eht_oper_chwidth=9` (320) with `he_oper_chwidth=2` (HE has no
320 value) plus a puncturing directive. By default `punct_acs_threshold` lets ACS
choose *which* 80 MHz to drop from measured interference; `punct_bitmap` pins it.

Availability is gated on a probe, not assumed: `driver_eht240_capable()` checks
the loaded ath12k module, overridable via `/etc/sbegw/eht240`. The width picker
only offers it on 5 GHz radios that report it, and labels it "240 MHz
(punctured)" so the operator knows what they are choosing. Because the runtime
may still grant less, the radio card shows configured vs actual with a reason.

## Device identity from ART

The Hardware page shows what the factory actually programmed, read from the
device rather than inferred from the model name. `adapters/art.py` reads:

* **Askey factory block** — 64-byte NUL-terminated ASCII slots at `0xf4000` of
  the `0:ART` partition: manufacturer, label OUI, model, hardware revision,
  hardware variant, serial number, per-band factory SSID/key, WPS PIN, and an
  ISO 3166-1 numeric region code (840 = US)
* **base MAC** at ART offset 0, plus the DTS nvmem derivation (WAN = cell 0,
  LAN = cell 1, radios = -1/-2/-3) and the five slots the vendor programmed
* **per-radio calibration** at `0x58800`/`0x8a800`/`0xbc800`, each validated for
  the ath12k header and reported with a digest and a programmed-byte count
* **U-Boot environment** from `0:APPSBLENV`, CRC32-checked, for `machid`,
  `bootcmd`/`bootargs`, `ethaddr` and the SoC version
* **Qualcomm socinfo**, **eMMC CID** and the **device tree**

Cross-checks that fall out of reading real hardware: the factory SSID suffix
matches the low octets of the base MAC, and U-Boot's `ethaddr` matches ART offset
0. On the reference unit the label OUI (`B4EEB4`) does *not* match the programmed
base MAC (`F45246…`) — both are Askey allocations, so both are shown with the
disagreement stated rather than one silently preferred.

The factory Wi-Fi passphrase and WPS PIN are deliberately **not** part of the
normal identity read: they are reported as programmed/absent only. The values
come from a separate route gated on `system.write`, and reading them raises an
audit event — they are printed on the device label, but a passphrase in a
screenshot or a shared API response is still an exposure.

### Calibration extraction was broken

The rootfs builder's `sbe1v1k-art-init` read `0x800000` bytes from offset
`0x1100000` of a partition that is `0x100000` bytes long, so it silently
extracted nothing and the radios came up on firmware defaults — wrong TX power
and EVM. `sbegw-caldata.service` now extracts the three per-radio blobs at the
offsets the board's own vendor OpenWrt hotplug script uses, into
`/run/firmware/ath12k/QCN9274/hw2.0/cal-pci-000N:01:00.0.bin`, before the driver
probes. Every ART read is bounds-checked against the partition size, so a wrong
offset is a logged error instead of empty calibration data.

## Transactional configuration

```
change -> candidate -> validate -> preflight -> checkpoint -> apply
       -> health check -> commit            (any failure -> rollback)
```

A commit that is service-affecting requires confirmation; if it is not confirmed
within the rollback window the previous configuration is re-applied
automatically, so a bad firewall or WAN change cannot lock the administrator out.
Every transition is recorded in the audit log with a redacted diff, and the last
60 revisions can be rolled back to individually.

## Install

```bash
sudo ./scripts/install-gateway.sh            # from debian-sbe1v1k/
```

Then on the device:

```bash
systemctl daemon-reload
systemctl enable --now sbegw-tls sbegw nginx
```

Browse to `https://192.168.2.1/` and complete first-run setup. The certificate is
self-signed and generated on first boot — a DIY gateway has no public DNS name,
so that is the honest option.

Inspect what the hardware actually offers, without applying anything:

```bash
/opt/sbegw/bin/sbegw --dump-capabilities
```

## Tests

Run from `gateway/`:

```bash
python3 tests/smoke_configd.py        # transactional commit, rollback, audit
python3 tests/smoke_api.py            # auth, RBAC, CSRF, validation, MLO, channels
python3 tests/smoke_rf.py             # channel scoring, anti-flap, 240 MHz
python3 tests/smoke_art.py            # ART parsing, bounds checks, secret gating
python3 tests/smoke_dpi_unifi.py      # DPI totals, TNBU crypto, object mapping
python3 tests/check_hostapd_keys.py   # every emitted hostapd key really exists
```

`check_hostapd_keys.py` matters more than it looks: hostapd rejects a config file
containing a single unknown option, which would take every radio down at once. It
greps the actual binary that will run on the device, and it caught three real
bugs (`ieee80211r` and `radius_das_shared_secret` are OpenWrt UCI names, not
hostapd options, and the FT AKMs are `FT-PSK`/`FT-EAP`, not `FT-WPA-PSK`).

To work on the UI from a workstation, with stubbed hardware:

```bash
python3 tests/demo_server.py          # http://127.0.0.1:18100/
```

## Status

Implemented and exercised by the tests above:

* ports (discovery, roles, speed/duplex/flow control, counters, PHY, rates)
* VLAN-aware bridge, networks with VLAN/zone/subnet/DHCP, per-network SVIs
* WAN: DHCP/static/PPPoE scaffolding, IPv6 modes, health probing, multi-WAN
  selection by health then priority
* zone-based nftables firewall, NAT/port forwarding/hairpin, policy-route marks
* dnsmasq rendering for DHCPv4, DHCPv6, RA and DNS (incl. filtering, records)
* Wi-Fi: radio discovery and capabilities, SSIDs, multi-BSSID, WPA2/WPA3/OWE,
  WPA2/WPA3-Enterprise with RADIUS, 802.11k/v/r, MLO, per-link telemetry,
  wireless client database with a measured health model, passive neighbour scan,
  firmware-crash detection and per-radio recovery
* channel analyzer (spectrum view per band) and automatic channel selection with
  CSA, hysteresis and scheduling
* 240 MHz on 5 GHz via EHT preamble puncturing, capability-gated
* clients: merged DHCP/ARP/NDP/FDB/wireless view, naming, blocking, fixed IP
* telemetry with bounded retention, events, SSE stream
* Suricata application/service identification from protocol, TLS SNI and HTTP
  Host metadata, with per-client/category totals, engine health and UniFi DPI stats
* UniFi gateway discovery/inform plus transactional Network API synchronization
* auth: scrypt passwords, sessions, CSRF, rate limiting, TOTP, API tokens, RBAC
* transactional config, revisions, rollback, audit; config backup/restore
* UI covering the spec's navigation tree, in light and dark themes, using the
  UniFi Network palette and metrics taken from the shipped UCG-Fiber bundle;
  the overview includes a live physical port face driven by netd PHY state

Not implemented yet — the API and UI do not pretend otherwise:

* **FRR** (OSPF/BGP/BFD/VRF/VRRP): `frr` is not in the rootfs; `netd` reports
  this instead of silently ignoring the config
* **VPN** (WireGuard/IPsec/OpenVPN): schema slots exist, no apply path
* **IDS/IPS**: DPI is integrated, but blocking/signature enforcement is not
* **PPSK, AFC, SD-WAN, mDNS reflector and UPnP**
* **PPPoE** needs the `ppp`/`pppoe` packages added to the rootfs
* QSDK 6.6 NSS/PPE/ECM modules and vendor IPQ9574 10 GbE host tuning are staged.
  Hardware offload remains off by default because it broke client forwarding on
  the measured VLAN-filtering topology. When explicitly enabled with DPI, ECM
  holds the first 25 packets in the host path for application classification.
