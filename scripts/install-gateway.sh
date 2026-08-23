#!/usr/bin/env bash
# Install the sbegw control plane, UI and MLO-capable hostapd into the Debian
# rootfs. Safe to re-run; it only writes under the rootfs, never to a device.
set -euo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="${ROOTFS:-$WS/rootfs}"
GATEWAY="$WS/gateway"

# OpenWrt/QSDK staging root holding the MLO-capable hostapd (wpad) and musl.
# QSDK is the top level of a QSDK tree — the directory holding qca/, build_dir/
# and staging_dir/. Everything else is derived from it, because three scripts
# used to define QSDK_ROOT as three different things (the top level here, a
# build_dir staging root there, a staging_dir one elsewhere), so setting it once
# and running them all broke two of the three.
#
# Both the plain layout and a checkout named after its branch are probed, so an
# unset QSDK usually resolves on its own.
QSDK="${QSDK:-}"
if [[ -z "$QSDK" ]]; then
    for _candidate in "$WS/../qsdk" "$WS/../qsdk14-work-ucgf/qsdk"; do
        [[ -d "$_candidate/qca" ]] && QSDK="$(cd "$_candidate" && pwd)" && break
    done
fi
QSDK="${QSDK:-$WS/../qsdk}"
# The build_dir root: this is where the MLO-capable wpad is built.
QSDK_ROOT="${QSDK_ROOT:-$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx}"
# Reuse the UI assets from the supplied UniFi Core portal.  This is the actual
# Inter/Lato set used by that console, rather than a browser-dependent system
# font approximation.  Callers can still override either path explicitly.
PORTAL_UI="${PORTAL_UI:-$WS/../ucgf_controller_port/rootfs_ucgf/usr/share/unifi-core/app/node_modules/@ubnt/unifi-portal/dist/local}"
BRAND_FONTS="${BRAND_FONTS:-$PORTAL_UI/fonts}"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }

[[ -d "$ROOTFS" ]] || die "rootfs not found: $ROOTFS (run build-debian-rootfs.sh first)"
[[ -d "$GATEWAY/sbegw" ]] || die "gateway source not found: $GATEWAY/sbegw"

# --------------------------------------------------------------- control plane

note "installing control plane to /opt/sbegw/lib"
install -d "$ROOTFS/opt/sbegw/lib" "$ROOTFS/opt/sbegw/bin" "$ROOTFS/opt/sbegw/web"
rm -rf "$ROOTFS/opt/sbegw/lib/sbegw"
cp -a --no-preserve=ownership "$GATEWAY/sbegw" "$ROOTFS/opt/sbegw/lib/sbegw"
chmod -R go-w "$ROOTFS/opt/sbegw/lib/sbegw"
find "$ROOTFS/opt/sbegw/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
install -m 0644 "$GATEWAY/README.md" "$ROOTFS/opt/sbegw/README.md" 2>/dev/null || true

install -m 0755 "$GATEWAY/deploy/bin/sbegw" "$ROOTFS/opt/sbegw/bin/sbegw"
install -m 0755 "$GATEWAY/deploy/bin/hostapd" "$ROOTFS/opt/sbegw/bin/hostapd"
install -m 0755 "$GATEWAY/deploy/bin/sbegw-art-caldata" \
    "$ROOTFS/opt/sbegw/bin/sbegw-art-caldata"
install -m 0755 "$GATEWAY/deploy/bin/sbegw-mount-state" \
    "$ROOTFS/opt/sbegw/bin/sbegw-mount-state"
install -m 0755 "$GATEWAY/deploy/bin/sbegw-clock-floor" \
    "$ROOTFS/opt/sbegw/bin/sbegw-clock-floor"

# --------------------------------------------------------------------- web UI

note "installing UI to /opt/sbegw/web"
install -m 0644 "$GATEWAY/web/app.css" "$GATEWAY/web/app.js" \
    "$ROOTFS/opt/sbegw/web/"
# Stamp the asset URLs with a content hash. Without this a browser can keep
# running the previous release's JavaScript against the new API after an upgrade.
UI_VERSION="$(cat "$GATEWAY/web/app.js" "$GATEWAY/web/app.css" \
    | sha256sum | cut -c1-12)"
sed -e "s/app\.css?v=[A-Za-z0-9]*/app.css?v=$UI_VERSION/" \
    -e "s/app\.js?v=[A-Za-z0-9]*/app.js?v=$UI_VERSION/" \
    "$GATEWAY/web/index.html" > "$ROOTFS/opt/sbegw/web/index.html"
chmod 0644 "$ROOTFS/opt/sbegw/web/index.html"
note "UI asset version $UI_VERSION"

if [[ -d "$PORTAL_UI" ]]; then
    for asset in favicon.svg favicon.ico apple-touch-icon.png; do
        [[ -f "$PORTAL_UI/$asset" ]] &&
            install -m 0644 "$PORTAL_UI/$asset" "$ROOTFS/opt/sbegw/web/$asset"
    done
fi

if [[ -d "$BRAND_FONTS" ]]; then
    note "copying Inter/Lato webfonts from $BRAND_FONTS"
    install -d "$ROOTFS/opt/sbegw/web/fonts"
    # The stylesheet references unhashed names; the bundle uses content hashes.
    for face in Inter-Regular Inter-SemiBold Inter-Bold Lato-Regular; do
        src="$(find "$BRAND_FONTS" -maxdepth 1 -name "${face}.*.woff2" | head -1)"
        if [[ -n "$src" ]]; then
            install -m 0644 "$src" "$ROOTFS/opt/sbegw/web/fonts/${face}.woff2"
        else
            warn "font $face not found; the UI falls back to the system UI font"
        fi
    done
else
    warn "no webfont directory at $BRAND_FONTS"
    warn "the UI will fall back to the platform UI font (still fully usable)"
fi

# ------------------------------------------------- MLO-capable hostapd bundle

note "staging MLO-capable hostapd (QSDK wpad) to /opt/sbegw/wifi"
if [[ ! -x "$QSDK_ROOT/usr/sbin/wpad" ]]; then
    warn "QSDK wpad not found at $QSDK_ROOT/usr/sbin/wpad"
    warn "MLO will be UNAVAILABLE: Debian's hostapd 2.10 has no MLD support."
    warn "Build the QSDK wlan-hostapd package, then re-run this script."
else
    install -d "$ROOTFS/opt/sbegw/wifi/usr/sbin" \
               "$ROOTFS/opt/sbegw/wifi/lib" "$ROOTFS/opt/sbegw/wifi/usr/lib"
    install -m 0755 "$QSDK_ROOT/usr/sbin/wpad" \
        "$ROOTFS/opt/sbegw/wifi/usr/sbin/wpad"
    # wpad is a multi-call binary dispatching on argv[0].
    ln -sf wpad "$ROOTFS/opt/sbegw/wifi/usr/sbin/hostapd"
    ln -sf wpad "$ROOTFS/opt/sbegw/wifi/usr/sbin/wpa_supplicant"
    if [[ -x "$QSDK_ROOT/usr/sbin/hostapd_cli" ]]; then
        install -m 0755 "$QSDK_ROOT/usr/sbin/hostapd_cli" \
            "$ROOTFS/opt/sbegw/wifi/usr/sbin/hostapd_cli"
    fi

    # Resolve the shared libraries wpad actually asks for, rather than guessing.
    missing=()
    mapfile -t needed < <(
        readelf -d "$QSDK_ROOT/usr/sbin/wpad" 2>/dev/null \
        | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p')
    needed+=("ld-musl-aarch64.so.1" "libjson-c.so.5")
    for lib in "${needed[@]}"; do
        src="$(find "$QSDK_ROOT/lib" "$QSDK_ROOT/usr/lib" -maxdepth 1 \
                -name "$lib" 2>/dev/null | head -1)"
        if [[ -z "$src" ]]; then
            missing+=("$lib")
            continue
        fi
        case "$src" in
            "$QSDK_ROOT/lib/"*) dest="$ROOTFS/opt/sbegw/wifi/lib/$lib" ;;
            *)                  dest="$ROOTFS/opt/sbegw/wifi/usr/lib/$lib" ;;
        esac
        install -m 0755 "$src" "$dest"
    done
    # libc.so is musl's own soname for the loader; satisfy it with a link.
    ln -sf ld-musl-aarch64.so.1 "$ROOTFS/opt/sbegw/wifi/lib/libc.so"

    # The ELF hardcodes its interpreter path, so the musl loader must exist
    # there. It cannot clash with glibc's ld-linux-aarch64.so.1.
    install -d "$ROOTFS/lib"
    install -m 0755 "$QSDK_ROOT/lib/ld-musl-aarch64.so.1" \
        "$ROOTFS/lib/ld-musl-aarch64.so.1"

    if (( ${#missing[@]} )); then
        warn "could not find these libraries: ${missing[*]}"
        warn "hostapd may fail to start; check the QSDK staging root"
    else
        note "hostapd bundle complete ($(printf '%s ' "${needed[@]}"))"
    fi

    if grep -qa mld_ap "$QSDK_ROOT/usr/sbin/wpad"; then
        note "verified: staged hostapd advertises MLD (mld_ap) support"
    else
        warn "staged hostapd does NOT contain mld_ap; MLO will be unavailable"
    fi
fi

# ------------------------------------------------------------- writable root

# Own /sbin/init so the kernel runs our overlay pivot. The kernel command line
# on this board carries no `init=`, so /sbin/init is the entry point, and that
# makes an overlay root possible without an initramfs and without touching
# U-Boot or the DTB.
#
# systemd-sysv ships /sbin/init, so the swap goes through dpkg-divert. Without
# the diversion an `apt upgrade` on the now-writable system would quietly
# restore the symlink, the next boot would come up read-only, and every package
# the user had installed would appear to have vanished — the changes would still
# be sitting unmounted in the overlay upper layer.
note "installing the writable-root overlay init"
install -d "$ROOTFS/usr/lib/sbegw"
install -m 0755 "$GATEWAY/deploy/bin/sbegw-overlay-init" \
    "$ROOTFS/usr/lib/sbegw/overlay-init"
sh -n "$ROOTFS/usr/lib/sbegw/overlay-init" ||
    die "overlay-init has a syntax error; refusing to make it PID 1"

# The rootfs builder deletes its qemu shim when it finishes, so borrow one from
# the host for the duration of this step. Without it the diversion is silently
# skipped, and the only thing left protecting the writable root is the apt hook
# below.
QEMU_TMP=""
if [[ ! -x "$ROOTFS/usr/bin/qemu-aarch64-static" ]]; then
    host_qemu="$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)"
    if [[ -n "$host_qemu" ]]; then
        install -m 0755 "$host_qemu" "$ROOTFS/usr/bin/qemu-aarch64-static"
        QEMU_TMP="$ROOTFS/usr/bin/qemu-aarch64-static"
    fi
fi

if [[ -x "$ROOTFS/usr/bin/qemu-aarch64-static" ]]; then
    chroot "$ROOTFS" /usr/bin/qemu-aarch64-static /bin/sh -e <<'DIVERT'
if ! dpkg-divert --list /sbin/init | grep -q sbegw; then
    # --rename refuses to act once /sbin/init is already our symlink, so put the
    # packaged one back first if an earlier run moved it by hand.
    if [ -e /sbin/init.systemd-sysv ] && [ -L /sbin/init ]; then
        rm -f /sbin/init
        mv /sbin/init.systemd-sysv /sbin/init
    fi
    dpkg-divert --divert /sbin/init.systemd-sysv --rename --package sbegw --add /sbin/init >/dev/null
fi
ln -sf /usr/lib/sbegw/overlay-init /sbin/init
DIVERT
    [[ -z "$QEMU_TMP" ]] || rm -f "$QEMU_TMP"
    grep -q '/sbin/init.systemd-sysv' "$ROOTFS/var/lib/dpkg/diversions" 2>/dev/null ||
        warn "dpkg has no record of the /sbin/init diversion"
else
    # No emulator anywhere: do the same thing by hand. The image still boots
    # writable, but dpkg does not know, so the apt hook below is what keeps an
    # `apt upgrade` from quietly reverting it.
    warn "no qemu-aarch64 available; swapping /sbin/init without a dpkg"
    warn "diversion (the apt hook still protects it)"
    [[ -e "$ROOTFS/sbin/init.systemd-sysv" ]] ||
        mv "$ROOTFS/sbin/init" "$ROOTFS/sbin/init.systemd-sysv"
    ln -sf /usr/lib/sbegw/overlay-init "$ROOTFS/sbin/init"
fi

# Self-healing, and the only protection if the diversion could not be recorded:
# re-assert /sbin/init after any dpkg run. A restored systemd symlink boots
# read-only, and every package the user installed then looks like it vanished —
# the files are still in the overlay upper layer, just not mounted.
install -d "$ROOTFS/etc/apt/apt.conf.d"
cat > "$ROOTFS/etc/apt/apt.conf.d/99-sbegw-overlay-init" <<'EOF'
// The writable root depends on /sbin/init being sbegw's overlay pivot; see
// /usr/lib/sbegw/overlay-init. systemd-sysv owns that path, so reinstalling or
// upgrading it restores the plain systemd symlink and the next boot comes up
// read-only. Re-assert the symlink after every dpkg run.
//
// Keep this command free of embedded double quotes: apt.conf has no \" escape,
// so a quoted sub-expression is truncated at the first inner quote and every
// apt operation then fails with "Problem executing scripts DPkg::Post-Invoke".
// ln -sf is idempotent, so there is nothing to compare first.
DPkg::Post-Invoke {
    "test -e /usr/lib/sbegw/overlay-init && ln -sf /usr/lib/sbegw/overlay-init /sbin/init || true";
};
EOF
chmod 0644 "$ROOTFS/etc/apt/apt.conf.d/99-sbegw-overlay-init"

# The pivot execs this directly, so it has to exist independently of /sbin/init.
[[ -e "$ROOTFS/lib/systemd/systemd" || -e "$ROOTFS/usr/lib/systemd/systemd" ]] ||
    die "no systemd binary in the rootfs; the overlay pivot would have nothing to exec"

# ----------------------------------------------------------------- docker

# data-root is deliberately NOT the default /var/lib/docker. With the writable
# root, /var/lib/docker would sit in the overlay's upper layer — and Docker's
# overlay2 storage driver refuses to run on an overlayfs backing store. It
# would either fail outright or silently fall back to the vfs driver, which
# copies whole image layers instead of sharing them. /data is the rootfs_data
# ext4 mounted directly, so pointing at it keeps overlay2 usable and keeps
# images off the read-only SquashFS.
#
# Log rotation matters more than usual here: the same partition holds the
# gateway's own state, and an unbounded json-file log on a container that
# chatters would fill it.
note "configuring docker (data-root on the ext4, not the overlay)"
install -d "$ROOTFS/etc/docker"
cat > "$ROOTFS/etc/docker/daemon.json" <<'EOF'
{
  "data-root": "/data/docker",
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "iptables": true
}
EOF
chmod 0644 "$ROOTFS/etc/docker/daemon.json"

# -------------------------------------------------------- hardware offload

# See the file's own comment: ECM offload breaks client forwarding on this
# board. netd re-applies this on every config apply, driven by
# firewall.hardware_offload; this drop-in covers the window before that.
note "installing the ECM offload sysctl drop-in"
install -d "$ROOTFS/etc/sysctl.d"
install -m 0644 "$GATEWAY/deploy/sysctl/99-sbegw-offload.conf" \
    "$ROOTFS/etc/sysctl.d/99-sbegw-offload.conf"

# ----------------------------------------------------------------- clock / NTP

# This board has no RTC (/dev/rtc* does not exist), so every boot starts with a
# clock in the past. apt then rejects every Debian Release file as "not valid
# yet" and TLS certificate checks fail, which makes the writable rootfs useless
# for installing anything. Two parts to the fix: a floor at the image build
# time, and real NTP once the WAN is up.
note "stamping the build time and enabling NTP"
install -d "$ROOTFS/usr/lib/sbegw"
: > "$ROOTFS/usr/lib/sbegw/build-epoch"
chmod 0644 "$ROOTFS/usr/lib/sbegw/build-epoch"
# The stamp carries no content; only its mtime matters, and it is now.
touch "$ROOTFS/usr/lib/sbegw/build-epoch"

# Debian's postinst enables this, but it runs under qemu in a chroot with no
# running systemd, so link it explicitly rather than trust that it happened.
if [[ -f "$ROOTFS/lib/systemd/system/systemd-timesyncd.service" ]]; then
    install -d "$ROOTFS/etc/systemd/system/sysinit.target.wants"
    ln -sf /lib/systemd/system/systemd-timesyncd.service \
        "$ROOTFS/etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service"
else
    warn "systemd-timesyncd is not in the rootfs; the clock will only ever be"
    warn "as accurate as the build stamp, and apt will start failing once the"
    warn "repository Release files age past their validity window"
fi

# ------------------------------------------------------------------- services

note "installing systemd units"
install -d "$ROOTFS/etc/systemd/system/multi-user.target.wants"
for unit in sbegw.service sbegw-state.service; do
    install -m 0644 "$GATEWAY/deploy/systemd/$unit" \
        "$ROOTFS/etc/systemd/system/$unit"
    ln -sf "../$unit" \
        "$ROOTFS/etc/systemd/system/multi-user.target.wants/$unit"
done

# sysinit, not multi-user: the clock has to be sane before anything validates a
# date. Pulled in by multi-user.target it would run long after its own
# Before=sysinit.target ordering had already been passed, which is no use to
# apt or to TLS certificate checks.
install -d "$ROOTFS/etc/systemd/system/sysinit.target.wants"
install -m 0644 "$GATEWAY/deploy/systemd/sbegw-clock-floor.service" \
    "$ROOTFS/etc/systemd/system/sbegw-clock-floor.service"
ln -sf ../sbegw-clock-floor.service \
    "$ROOTFS/etc/systemd/system/sysinit.target.wants/sbegw-clock-floor.service"
rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbegw-clock-floor.service"

# The rootfs builder's ART init reads calibration data from an offset past the
# end of the 1 MiB ART partition, so it silently extracts nothing. Remove that
# block entirely; sbegw-caldata.service does it correctly with the vendor
# offsets. Editing shell with sed risks leaving a syntax error that would abort
# ART init altogether, so the block is excised with a real parser and the result
# is syntax-checked before it is kept.
ART_INIT="$ROOTFS/usr/local/sbin/sbe1v1k-art-init"
# Detect the actual command, not just the offset literal: the replacement
# comment mentions 0x1100000, so grepping for that made this non-idempotent and
# a second install aborted the whole script under `set -e`.
if [[ -f "$ART_INIT" ]] && grep -q 'of=/run/firmware/caldata\.bin' "$ART_INIT"; then
    python3 - "$ART_INIT" <<'PYEOF'
import re
import sys

path = sys.argv[1]
with open(path) as fh:
    text = fh.read()

# Drop the whole `if dd ... caldata.bin ...; then ... fi` block, however many
# lines it spans, plus the comment that introduces it.
pattern = re.compile(
    r"\n# caldb_offset/caldb_size.*?\nif dd if=\"\$ART\" of=/run/firmware/caldata\.bin"
    r".*?\nfi\n",
    re.S)
replacement = (
    "\n# Calibration extraction is handled by sbegw-art-caldata, which uses the\n"
    "# correct per-radio ART offsets (0x58800/0x8a800/0xbc800). The block that\n"
    "# used to be here read 0x800000 bytes from 0x1100000 of a 0x100000-byte\n"
    "# partition and therefore extracted nothing.\n")
new_text, count = pattern.subn(replacement, text)
if count != 1:
    print(f"expected exactly one caldata block, found {count}; leaving it alone",
          file=sys.stderr)
    raise SystemExit(1)

# Also drop the now-misleading log line.
new_text = new_text.replace(
    'echo "using ART=$ART; extracted caldata.bin" > /run/sbe1v1k/art-init.log',
    'echo "using ART=$ART" > /run/sbe1v1k/art-init.log')

with open(path, "w") as fh:
    fh.write(new_text)
PYEOF
    if sh -n "$ART_INIT"; then
        note "removed the out-of-range caldata read from sbe1v1k-art-init"
    else
        die "editing sbe1v1k-art-init produced invalid shell; aborting"
    fi
fi

# --- calibration extraction rides on sbe1v1k-art-init -----------------------
# See the drop-in for why this is not a unit of its own.
if [[ -f "$ROOTFS/etc/systemd/system/sbe1v1k-art-init.service" ]]; then
    install -d "$ROOTFS/etc/systemd/system/sbe1v1k-art-init.service.d"
    install -m 0644 \
        "$GATEWAY/deploy/systemd/sbe1v1k-art-init.service.d-sbegw-caldata.conf" \
        "$ROOTFS/etc/systemd/system/sbe1v1k-art-init.service.d/sbegw-caldata.conf"
    note "hooked caldata extraction onto sbe1v1k-art-init"
else
    warn "sbe1v1k-art-init.service missing; calibration data will not be extracted"
fi
# Remove the standalone unit from any earlier install of this tree: it created an
# ordering cycle that made systemd delete the systemd-modules-load job.
rm -f "$ROOTFS/etc/systemd/system/sbegw-caldata.service" \
      "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbegw-caldata.service"

# --- bound the vendor firmware mount so it cannot stall boot forever
if [[ -f "$ROOTFS/etc/systemd/system/wififw.service" ]]; then
    install -d "$ROOTFS/etc/systemd/system/wififw.service.d"
    install -m 0644 "$GATEWAY/deploy/systemd/wififw.service.d-timeout.conf" \
        "$ROOTFS/etc/systemd/system/wififw.service.d/timeout.conf"
    note "bounded wififw.service start timeout (it hung on a previous boot)"
fi

# --- one wiphy per radio, or only one band can ever be on the air
install -d "$ROOTFS/etc/modprobe.d"
install -m 0644 "$GATEWAY/deploy/modprobe/sbe1v1k-ath12k.conf" \
    "$ROOTFS/etc/modprobe.d/sbe1v1k-ath12k.conf"
note "ath12k mlo_capable=0: one wiphy per radio (concurrent tri-band)"

# --- /etc writable, backed by the data partition
install -m 0755 "$GATEWAY/deploy/bin/sbegw-etc-overlay" \
    "$ROOTFS/usr/local/sbin/sbegw-etc-overlay"
install -m 0644 "$GATEWAY/deploy/systemd/sbegw-etc-overlay.service" \
    "$ROOTFS/etc/systemd/system/sbegw-etc-overlay.service"
ln -sf ../sbegw-etc-overlay.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbegw-etc-overlay.service"
note "/etc is made writable at boot by an overlay on /data"

# --- resolv.conf must live on tmpfs, or DHCP declines every lease
# dhclient-script writes "$(readlink -f /etc/resolv.conf).dhclient-new.$$".
# On a read-only /etc that fails, the script exits 2, and dhclient turns that
# into a DHCPDECLINE: the WAN never gets a usable address.
if [[ ! -L "$ROOTFS/etc/resolv.conf" ]]; then
    cp -f "$ROOTFS/etc/resolv.conf" "$ROOTFS/etc/resolv.conf.seed" 2>/dev/null || true
    ln -sf /run/resolv.conf "$ROOTFS/etc/resolv.conf"
    note "/etc/resolv.conf -> /run/resolv.conf (writable; stops the DHCP decline loop)"
fi

# --- SSH for on-device debugging
# sshd could never start on this image: /etc/ssh is on the read-only SquashFS
# root, so it had no host keys and exited with "no hostkeys available".
install -d "$ROOTFS/etc/ssh/sshd_config.d"
install -m 0644 "$GATEWAY/deploy/ssh/10-sbegw.conf" \
    "$ROOTFS/etc/ssh/sshd_config.d/10-sbegw.conf"
install -m 0755 "$GATEWAY/deploy/bin/sbegw-gen-hostkeys" \
    "$ROOTFS/usr/local/sbin/sbegw-gen-hostkeys"
install -m 0644 "$GATEWAY/deploy/systemd/sbegw-hostkeys.service" \
    "$ROOTFS/etc/systemd/system/sbegw-hostkeys.service"
ln -sf ../sbegw-hostkeys.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbegw-hostkeys.service"
note "SSH enabled: host keys on /data, root login with a password (LAN only)"

# --- logind cannot create a StateDirectory on a read-only root
# It failed at step STATE_DIRECTORY on every boot, leaving a permanently failed
# unit in the health report.
install -d "$ROOTFS/etc/systemd/system/systemd-logind.service.d"
install -m 0644 \
    "$GATEWAY/deploy/systemd/systemd-logind.service.d-sbegw-state.conf" \
    "$ROOTFS/etc/systemd/system/systemd-logind.service.d/sbegw-state.conf"
note "cleared logind's StateDirectory (read-only root; lingering is unused)"

# --- the EDMA queue-mapping file the NSS driver looks for at probe time
install -d "$ROOTFS/etc/config"
install -m 0644 "$GATEWAY/deploy/etc/config/nss_cfg.ini" \
    "$ROOTFS/etc/config/nss_cfg.ini"
note "installed /etc/config/nss_cfg.ini (silences the EDMA fallback error)"

# --- netd owns dnsmasq; the packaged service is a second, conflicting instance
# It failed on every boot because our dnsmasq already holds port 53.
if [[ -e "$ROOTFS/lib/systemd/system/dnsmasq.service" ]]; then
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/dnsmasq.service"
    rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/dnsmasq.service"
    rm -f "$ROOTFS"/etc/rc?.d/[SK]??dnsmasq
    note "masked the packaged dnsmasq.service (netd manages dnsmasq directly)"
fi

# The DPI engine renders a per-site configuration and starts its own Suricata
# process.  Debian enables the stock service during package installation; if it
# is left enabled, two AF_PACKET consumers compete for traffic and the stock
# daemon also writes to paths that are unsuitable for the read-only image.
if [[ -e "$ROOTFS/lib/systemd/system/suricata.service" ]]; then
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/suricata.service"
    rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/suricata.service"
    rm -f "$ROOTFS"/etc/rc?.d/[SK]??suricata
    note "masked the packaged suricata.service (sbegw manages DPI directly)"
fi

# --- the previous build's portal UI fights this one for the network and ports
for unit in sbe1v1k-config-ui.service sbe1v1k-port-config.service; do
    if [[ -e "$ROOTFS/etc/systemd/system/$unit" ]]; then
        rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/$unit"
        ln -sf /dev/null "$ROOTFS/etc/systemd/system/$unit"
        note "disabled $unit (superseded by the control plane)"
    fi
done

# The control plane owns the network; networkd must not fight it.
for unit in systemd-networkd.service systemd-networkd.socket; do
    rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/$unit" \
          "$ROOTFS/etc/systemd/system/sockets.target.wants/$unit"
done
install -d "$ROOTFS/etc/systemd/system"
ln -sf /dev/null "$ROOTFS/etc/systemd/system/systemd-networkd.service"

# Masking networkd orphans anything that was WantedBy it. sbe1v1k-apply-macs
# writes the ART-derived MAC addresses onto the Ethernet ports; losing it leaves
# them with driver-generated MACs, so re-parent it onto sbegw instead.
if [[ -f "$ROOTFS/etc/systemd/system/sbe1v1k-apply-macs.service" ]]; then
    install -d "$ROOTFS/etc/systemd/system/sbegw.service.wants"
    ln -sf ../sbe1v1k-apply-macs.service \
        "$ROOTFS/etc/systemd/system/sbegw.service.wants/sbe1v1k-apply-macs.service"
    install -d "$ROOTFS/etc/systemd/system/sbe1v1k-apply-macs.service.d"
    cat > "$ROOTFS/etc/systemd/system/sbe1v1k-apply-macs.service.d/sbegw.conf" <<'EOF'
# Re-parented from systemd-networkd (masked by sbegw) onto the control plane.
[Unit]
Before=sbegw.service
EOF
    note "re-parented sbe1v1k-apply-macs onto sbegw.service"
else
    warn "sbe1v1k-apply-macs.service not present; Ethernet ports will use"
    warn "driver-generated MACs rather than the ART base address"
fi
# Port roles are netd's job now; leaving the old static config enabled would
# fight it for the same interfaces.
rm -f "$ROOTFS/etc/systemd/system/systemd-networkd.service.wants/sbe1v1k-port-config.service" \
      "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbe1v1k-port-config.service" \
      "$ROOTFS/etc/systemd/system/systemd-networkd.service.wants/sbe1v1k-apply-macs.service"
rmdir "$ROOTFS/etc/systemd/system/systemd-networkd.service.wants" 2>/dev/null || true

# Runtime directories. nginx.conf in this rootfs logs to /run/nginx, which
# nothing created — nginx failed at ExecStartPre on every boot as a result.
install -d "$ROOTFS/etc/tmpfiles.d"
install -m 0644 "$GATEWAY/deploy/tmpfiles/sbegw.conf" \
    "$ROOTFS/etc/tmpfiles.d/sbegw.conf"
note "installed tmpfiles entries for /run/nginx and /run/sbegw"

note "installing nginx site"
install -d "$ROOTFS/etc/nginx/sites-available" "$ROOTFS/etc/nginx/sites-enabled"
install -m 0644 "$GATEWAY/deploy/nginx/sbegw.conf" \
    "$ROOTFS/etc/nginx/sites-available/sbegw"
ln -sf ../sites-available/sbegw "$ROOTFS/etc/nginx/sites-enabled/sbegw"
# Remove the older hand-rolled portal vhosts so they cannot claim :443 first.
rm -f "$ROOTFS/etc/nginx/sites-enabled/default" \
      "$ROOTFS/etc/nginx/sites-enabled/sbe1v1k-portal" \
      "$ROOTFS/etc/nginx/sites-enabled/ucgf-console" \
      "$ROOTFS/etc/nginx/conf.d/00-sbe1v1k-temp.conf"

# --------------------------------------------------- first-boot TLS + state

note "installing first-boot TLS generator"
install -d "$ROOTFS/usr/local/sbin"
cat > "$ROOTFS/usr/local/sbin/sbegw-gen-tls" <<'EOF'
#!/bin/sh
# Generate a self-signed certificate for local management on first boot.
# A DIY gateway has no public DNS name, so a local self-signed cert is the
# honest option: it encrypts the session without pretending to be CA-verified.
set -eu
DIR=/data/sbegw/tls
[ -s "$DIR/server.crt" ] && [ -s "$DIR/server.key" ] && exit 0
mkdir -p "$DIR"
HOSTNAME_FQDN="$(hostname 2>/dev/null || echo sbe1v1k)"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$DIR/server.key" -out "$DIR/server.crt" \
    -subj "/CN=$HOSTNAME_FQDN" \
    -addext "subjectAltName=DNS:$HOSTNAME_FQDN,DNS:sbe1v1k.lan,IP:192.168.2.1" \
    >/dev/null 2>&1
chmod 600 "$DIR/server.key"
chmod 644 "$DIR/server.crt"
echo "generated self-signed management certificate in $DIR"
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbegw-gen-tls"

cat > "$ROOTFS/etc/systemd/system/sbegw-tls.service" <<'EOF'
[Unit]
Description=Generate the local management TLS certificate
Before=nginx.service
# /data is a separate writable partition; the root filesystem is read-only
# SquashFS, so without this the certificate cannot be written and nginx never
# starts — which leaves the device with no management access at all.
Requires=sbegw-state.service
After=sbegw-state.service
ConditionPathExists=!/data/sbegw/tls/server.crt

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/sbegw-gen-tls

[Install]
WantedBy=multi-user.target
EOF
ln -sf ../sbegw-tls.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/sbegw-tls.service"

install -d "$ROOTFS/data/sbegw" "$ROOTFS/run/sbegw"

# The image boots as read-only SquashFS, so an "ext4 /" fstab entry makes
# systemd-remount-fs fail on every boot. Describe reality instead, and give
# /data a noauto entry documenting where state lives.
cat > "$ROOTFS/etc/fstab" <<'EOF'
# The root filesystem is SquashFS and read-only; nothing to remount.
# Writable state is mounted at /data by sbegw-state.service, which picks the
# first usable partition (rootfs_data_1, then edata/econfig) and falls back to
# tmpfs. rootfs_data is left alone: it holds the vendor OpenWrt overlay.
tmpfs /tmp tmpfs defaults,nosuid,nodev,size=128m 0 0
EOF

# nginx must not start before its certificate exists.
install -d "$ROOTFS/etc/systemd/system/nginx.service.d"
cat > "$ROOTFS/etc/systemd/system/nginx.service.d/sbegw.conf" <<'EOF'
[Unit]
After=sbegw-tls.service sbegw.service
Requires=sbegw-tls.service
EOF

# ---------------------------------------------------------------- validation

note "byte-compiling the control plane"
if command -v python3 >/dev/null; then
    python3 -m compileall -q "$GATEWAY/sbegw" >/dev/null \
        || die "control plane does not compile"
fi

note "checking for tools the control plane needs at runtime"
for tool in ip bridge ethtool nft iw dnsmasq dhclient nginx openssl python3; do
    if ! find "$ROOTFS/usr/sbin" "$ROOTFS/usr/bin" "$ROOTFS/sbin" "$ROOTFS/bin" \
            -maxdepth 1 -name "$tool" 2>/dev/null | grep -q .; then
        warn "missing in rootfs: $tool"
    fi
done
for tool in tc pppd wg vtysh suricata; do
    if ! find "$ROOTFS/usr/sbin" "$ROOTFS/usr/bin" -maxdepth 1 -name "$tool" \
            2>/dev/null | grep -q .; then
        echo "    optional (feature disabled until installed): $tool"
    fi
done
if [[ ! -d "$ROOTFS/usr/lib/python3/dist-packages/cryptography" ]]; then
    warn "missing in rootfs: python3-cryptography (UniFi inform disabled)"
fi

for module in sch_cake ifb act_mirred cls_matchall; do
    if ! find "$ROOTFS/lib/modules" -type f -name "$module.ko*" -print -quit \
            2>/dev/null | grep -q .; then
        echo "    optional (Smart Queues disabled until QSDK module is built): $module"
    fi
done

cat <<EOF

Installed:
  /opt/sbegw/lib/sbegw     control plane (netd, wifid, DPI, UniFi, configd, api)
  /opt/sbegw/bin/sbegw     launcher
  /opt/sbegw/bin/hostapd   MLO-capable hostapd shim
  /opt/sbegw/wifi          QSDK hostapd + musl runtime
  /opt/sbegw/web           management UI
  /etc/systemd/system/sbegw.service
  /etc/nginx/sites-enabled/sbegw

On the device:
  systemctl daemon-reload && systemctl enable --now sbegw-tls sbegw nginx
  then browse to https://192.168.2.1/ and complete first-run setup.

Verify the hardware view without applying anything:
  /opt/sbegw/bin/sbegw --dump-capabilities
EOF
