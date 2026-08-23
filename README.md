# Debian Bookworm on the Askey SBE1V1K (IPQ9574, Wi-Fi 7)

A Debian arm64 userspace and control plane for the Askey SBE1V1K — a Qualcomm
IPQ9574 board with three ath12k radios (2.4 / 5 / 6 GHz), a 2.5 G port and a
10 G port. It keeps the board's existing U-Boot and 6.6 kernel and replaces the
userspace with Debian plus `sbegw`, a gateway control plane.

Built for a personal, non-commercial project. There is no warranty of any kind;
flashing router firmware can leave a device recoverable only through its U-Boot
recovery page.

## What works

Verified on hardware, not just in tests:

- **Wi-Fi 7 tri-band concurrent** — 2.4 GHz 40 MHz, 5 GHz up to 240 MHz (a
  320 MHz EHT span with one 80 MHz block punctured), 6 GHz up to 320 MHz.
- **MLO** — a real multi-link AP MLD. MLDs are identified by interface name, so
  every link of an MLD shares one netdev carrying the MLD address, with a radio
  mask spanning the radios it uses.
- **Routing** — VLAN-aware bridge, multi-WAN with DHCP/static/PPPoE, nftables
  firewall with zones, NAT, port forwards, dnsmasq for DHCP/DNS.
- **DPI and controller visibility** — passive Suricata traffic identification,
  UniFi gateway discovery/inform telemetry, and opt-in desired-state sync from
  the documented local Network Integration API.
- **AP mode** and **per-SSID WAN bridging** — an SSID's clients can be bridged
  onto the upstream L2 and addressed by the upstream gateway instead of sitting
  behind this router's NAT.
- **Writable root** — the SquashFS root is turned into an overlay whose upper
  layer lives on the data partition, so `apt install` works and persists.
- **Fan and status-LED policy** — driven by the board's own device-tree cooling
  levels and trip points rather than invented numbers.
- **OTA** — `sbegw --ota-verify` / `--ota-apply`, which validate a sysupgrade
  image completely before writing anything.

## Dashboard

Connect a computer to the SBE1V1K LAN and open the local management dashboard:

- [Open dashboard over HTTPS](https://192.168.2.1/)
- [Open dashboard over HTTP](http://192.168.2.1/)

The first connection shows the protected first-run setup screen. Create the
local administrator there, then sign in to view the live Overview dashboard,
radio status, clients, ports, WAN state, firewall, telemetry and OTA controls.
The dashboard is served locally by the router and does not require cloud access.

The live device at `192.168.2.1` currently reports `setup_required: true`; an
authenticated dashboard screenshot will be added after first-run setup is
completed on the device.

## Layout

```
gateway/sbegw/     the Python control plane (cryptography + optional services)
gateway/web/       the management UI (vanilla JS, no build step)
gateway/deploy/    systemd units, sysctl drop-ins, the overlay-root init
gateway/tests/     ~775 assertions, runnable on any Linux host
scripts/           build the rootfs, install the gateway, pack an image
doc/               the specification the control plane was written against
```

## Quick start

```bash
git clone https://github.com/OLGTX303/debian-sbe1v1k
cd debian-sbe1v1k
bash scripts/fetch-sources.sh          # checks host tools, fetches public
                                       # sources, applies the board patch
bash scripts/build-qsdk-gateway-modules.sh # CAKE/IFB for Smart Queues
```

`fetch-sources.sh` tells you exactly what it still needs and where to put it,
then re-run it to have it verify and patch. Nothing it does needs root.

Every script takes its QSDK inputs from one variable, `QSDK`, pointing at the
top of a QSDK tree — the directory holding `qca/`, `build_dir/` and
`staging_dir/`. It is auto-detected from `../qsdk` or `../qsdk14-work-ucgf/qsdk`
if you leave it unset, and everything else is derived:

```bash
QSDK=/path/to/qsdk bash scripts/fetch-sources.sh
```

When no QSDK tree is present, `fetch-sources.sh` automatically clones the
Qualcomm QSDK source from CodeLinaro (`QSDK_REPO`), using `QSDK_REF` when set.
If the repository requires access, configure Git credentials first. Cloning
the source is only the first step: QSDK must still be configured and built to
produce the kernel, firmware, `wpad`, `build_dir/` and `staging_dir/` outputs
used by the Debian image.

For a private QSDK archive, the same script can download and verify it before
checking the tree. The archive must extract to a directory containing `qca/`:

```bash
QSDK=/srv/qsdk \
QSDK_ARCHIVE='https://private.example/qsdk.tar' \
QSDK_SHA256='<sha256>' \
QSDK_STRIP_COMPONENTS=1 \
MIRROR='https://deb.debian.org/debian' \
bash scripts/fetch-sources.sh
```

Credentials for a private URL are supplied through the machine's `curl`
configuration or environment; they are not stored in this repository. Debian
Bookworm is downloaded by `build-debian-rootfs.sh` via
`MIRROR` and is verified by the normal debootstrap package checks.

## Building

Needs `debootstrap`, `qemu-user-static`, `squashfs-tools` and root:

```bash
sudo ROOT_PASSWORD='choose-one' bash scripts/build-debian-rootfs.sh
sudo bash scripts/install-gateway.sh
sudo bash scripts/pack-debian-squashfs.sh
sudo bash scripts/make-sysupgrade.sh
```

The result is a sysupgrade tar the board's recovery page accepts.

Pushing a version tag such as `v0.2.0`, or starting the `release` workflow
manually with a tag, builds the image on the configured private QSDK runner and
publishes it as the GitHub release asset `sysupgrade.bin`. The release image
includes the locally supplied Qualcomm/QSDK ath12k, NSS/PPE and hostapd driver
components; those vendor binaries are intentionally not stored in this repo.

Two inputs are **not** in this repository and must be supplied locally:

- **A QSDK build tree** for the matching 6.6 kernel, its modules, the ath12k
  firmware, and the MLO-capable hostapd (`wpad`). Debian's hostapd 2.10 has no
  MLD support, so MLO needs the vendor build.
- **Board firmware** for the radios.

Both are vendor-licensed and are not redistributed here. `scripts/` reads them
from paths you point at; the build warns and degrades if they are absent.

`patches/` carries the board support that is ours to distribute — the device
tree diff adding the pwm-fan and its cooling levels, the thermal zones and trip
points, and the port wiring. `fetch-sources.sh` applies it, and it is
idempotent: a second run reports "already applied" rather than failing.

## Tests

```bash
cd gateway && for t in tests/smoke_*.py; do python3 "$t"; done
```

They run without hardware and without root. Where a test asserts a specific
number — a fan duty, a channel width, an operating class — that number was
taken from the device tree or measured on the board, and the comment says
which.

## Licence

Not yet chosen. Until a `LICENSE` file is added, no permission is granted
beyond reading the code. Open an issue if you want it under something specific.
