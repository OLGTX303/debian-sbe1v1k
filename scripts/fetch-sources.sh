#!/usr/bin/env bash
# Get a fresh clone to the point where the build scripts will run.
#
# Three kinds of input are needed, and they are not equal:
#
#   1. Debian itself — fetched by debootstrap during the build. Nothing to do
#      here; set MIRROR when a local Debian mirror is required.
#   2. Things with a public canonical source — hostapd, linux-firmware. Fetched
#      here.
#   3. Qualcomm's QSDK — the 6.6 kernel and its modules, the ath12k firmware
#      and board data, and the MLO-capable hostapd build. NOT publicly
#      downloadable and not redistributed by this project. You supply a tree;
#      this script tells you exactly what it needs from it and checks it.
#
# Nothing here writes outside the workspace, and it is safe to re-run.
set -euo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="${VENDOR:-$WS/../vendor}"
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
# fetch-sources works on the tree itself, so QSDK is what it needs.
QSDK_ROOT="$QSDK"
DEBIAN_MIRROR="${MIRROR:-http://deb.debian.org/debian}"
QSDK_REPO="${QSDK_REPO:-https://git.codelinaro.org/clo/qsdk.git}"

download_qsdk() {
    local archive="$1" destination="$2" tmp expected actual
    mkdir -p "$destination"
    if [[ "$archive" == http://* || "$archive" == https://* ]]; then
        command -v curl >/dev/null || die "curl is required to download QSDK_ARCHIVE"
        tmp="$(mktemp "${TMPDIR:-/tmp}/sbe1v1k-qsdk.XXXXXX.tar")"
        trap 'rm -f "$tmp"' RETURN
        note "downloading private QSDK archive"
        curl --fail --location --retry 3 --continue-at - "$archive" -o "$tmp"
        [[ -n "${QSDK_SHA256:-}" ]] || die "set QSDK_SHA256 when downloading QSDK_ARCHIVE"
        expected="${QSDK_SHA256}  $tmp"
        actual="$(sha256sum "$tmp")"
        [[ "$actual" == "$expected" ]] || die "QSDK_SHA256 does not match downloaded archive"
    else
        tmp="$archive"
        [[ -f "$tmp" ]] || die "QSDK archive not found: $tmp"
        if [[ -n "${QSDK_SHA256:-}" ]]; then
            expected="${QSDK_SHA256}  $tmp"
            actual="$(sha256sum "$tmp")"
            [[ "$actual" == "$expected" ]] || die "QSDK_SHA256 does not match archive"
        fi
    fi
    note "extracting QSDK into $destination"
    if [[ -n "${QSDK_STRIP_COMPONENTS:-}" ]]; then
        tar -xf "$tmp" -C "$destination" --strip-components="$QSDK_STRIP_COMPONENTS"
    else
        tar -xf "$tmp" -C "$destination"
    fi
    [[ -d "$destination/qca" ]] || die "archive extracted, but $destination/qca is missing; set QSDK_STRIP_COMPONENTS correctly"
}

note() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

mkdir -p "$VENDOR"

# --------------------------------------------------------------- host packages

note "checking host build dependencies"
missing=()
for tool in debootstrap qemu-aarch64-static mksquashfs mkfs.ext4 dtc git curl \
            tar patch python3; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
if (( ${#missing[@]} )); then
    warn "missing: ${missing[*]}"
    warn "on Debian/Ubuntu:"
    warn "  sudo apt install debootstrap qemu-user-static squashfs-tools \\"
    warn "                   device-tree-compiler e2fsprogs git curl python3"
else
    note "all host tools present"
fi

# ------------------------------------------------------------- public sources

# hostapd upstream. Useful for reading and for building a non-MLO hostapd; the
# MLD support this project relies on lives in Qualcomm's tree, not here.
if [[ ! -d "$VENDOR/hostap" ]]; then
    note "cloning hostapd (upstream, for reference and non-MLO builds)"
    git clone --depth 1 https://w1.fi/hostap.git "$VENDOR/hostap" \
        || warn "hostapd clone failed; not fatal"
else
    note "hostapd already present at $VENDOR/hostap"
fi

# linux-firmware carries ath12k firmware for some parts. Whether it has the
# blobs for THIS board's QCN9274 radios depends on the release, so this is a
# convenience, not a guarantee — the QSDK tree is the reliable source.
if [[ ! -d "$VENDOR/linux-firmware" ]]; then
    note "cloning linux-firmware (shallow; ath12k blobs may or may not cover"
    note "  this board's radios — the QSDK tree is authoritative)"
    git clone --depth 1 \
        https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git \
        "$VENDOR/linux-firmware" || warn "linux-firmware clone failed; not fatal"
else
    note "linux-firmware already present"
fi

# ---------------------------------------------------------------- QSDK inputs

# Qualcomm does not publish QSDK through this repository. A private build can
# provide a local archive or an authenticated URL. URL downloads require
# QSDK_SHA256 so a changed vendor archive cannot silently change the driver ABI.
if [[ ! -d "$QSDK/qca" && -n "${QSDK_ARCHIVE:-}" ]]; then
    download_qsdk "$QSDK_ARCHIVE" "$QSDK"
fi

if [[ ! -d "$QSDK/qca" && "${QSDK_AUTO_CLONE:-1}" == "1" ]]; then
    command -v git >/dev/null || die "git is required to clone QSDK"
    [[ ! -e "$QSDK" || -d "$QSDK" ]] || die "QSDK path exists but is not a directory: $QSDK"
    mkdir -p "$(dirname "$QSDK")"
    note "cloning QSDK from $QSDK_REPO"
    if [[ -n "${QSDK_REF:-}" ]]; then
        git clone --depth 1 --recurse-submodules --branch "$QSDK_REF" \
            "$QSDK_REPO" "$QSDK"
    else
        git clone --depth 1 --recurse-submodules "$QSDK_REPO" "$QSDK"
    fi
fi

note "checking the QSDK tree at $QSDK_ROOT"
if [[ ! -d "$QSDK_ROOT" ]]; then
    cat >&2 <<EOF

[!] No QSDK tree found at $QSDK_ROOT

    QSDK source is cloned from:
      $QSDK_REPO
    Authentication, if required, comes from your normal Git credential helper.
    The clone supplies source; you still need to configure/build QSDK so its
    build_dir/, staging_dir/, firmware and kernel-module outputs exist.

    The build reads exactly these four things from it:

      kernel modules   build_dir/target-*/root-ipq95xx/lib/modules/6.6.116+/
      ath12k firmware  staging_dir/target-*/root-ipq95xx/lib/firmware/
      ath12k INI       qca/feeds/wlan-open/mac80211/files/ini/
      MLO hostapd      build_dir/target-*/root-ipq95xx/usr/sbin/wpad
                       (Debian's hostapd 2.10 has no MLD support, so MLO
                        needs this one; without it everything else still
                        works and the build warns.)

    Then re-run this script to have it check them and apply the board patch.

EOF
    exit 1
fi

found=0
for probe in \
    "kernel modules:$QSDK_ROOT/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/lib/modules" \
    "ath12k firmware:$QSDK_ROOT/staging_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/lib/firmware" \
    "ath12k INI:$QSDK_ROOT/qca/feeds/wlan-open/mac80211/files/ini" \
    "kernel source:$QSDK_ROOT/qca/src/linux-6.6"
do
    label="${probe%%:*}"; path="${probe#*:}"
    if [[ -d "$path" ]]; then
        note "  found $label"
        found=$((found + 1))
    else
        warn "  missing $label ($path)"
    fi
done
[[ "$found" -gt 0 ]] || die "nothing recognisable in $QSDK_ROOT; is that a QSDK tree?"

if command -v curl >/dev/null && ! curl --fail --silent --show-error --head "$DEBIAN_MIRROR/" >/dev/null; then
    warn "Debian mirror is not reachable: $DEBIAN_MIRROR"
else
    note "Debian mirror: $DEBIAN_MIRROR (used by build-debian-rootfs.sh)"
fi

if [[ -x "$QSDK_ROOT/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/usr/sbin/wpad" ]]; then
    note "  found MLO-capable hostapd (wpad)"
else
    warn "  no wpad built yet: MLO will be unavailable until you build the"
    warr= ; warn "  QSDK wlan-hostapd package"
fi

qos_modules="$QSDK_ROOT/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/lib/modules"
if find "$qos_modules" -type f -name 'sch_cake.ko*' -print -quit 2>/dev/null | grep -q . &&
   find "$qos_modules" -type f -name 'ifb.ko*' -print -quit 2>/dev/null | grep -q .; then
    note "  found Smart Queue kernel modules (CAKE + IFB)"
else
    warn "  Smart Queue kernel modules are not built yet"
    warn "  run: QSDK=\"$QSDK_ROOT\" bash scripts/build-qsdk-gateway-modules.sh"
fi

# ------------------------------------------------------------- board patches

KSRC="$QSDK_ROOT/qca/src/linux-6.6"
if [[ -d "$KSRC" ]]; then
    for patch in "$WS"/patches/*.patch; do
        [[ -e "$patch" ]] || continue
        name="$(basename "$patch")"
        # --dry-run first: a patch that is already applied is a normal state
        # for a re-run, not a failure.
        if patch -p1 --dry-run --silent -d "$KSRC" < "$patch" >/dev/null 2>&1; then
            note "applying $name"
            patch -p1 -d "$KSRC" < "$patch"
        elif patch -p1 -R --dry-run --silent -d "$KSRC" < "$patch" >/dev/null 2>&1; then
            note "$name already applied"
        else
            warn "$name does not apply cleanly to $KSRC — apply it by hand"
        fi
    done
fi

cat <<EOF

[*] Ready. Next:

      QSDK="$QSDK_ROOT" bash scripts/build-qsdk-gateway-modules.sh
      sudo QSDK="$QSDK_ROOT" MIRROR="$DEBIAN_MIRROR" ROOT_PASSWORD='choose-one' bash scripts/build-debian-rootfs.sh
      sudo QSDK="$QSDK_ROOT" bash scripts/install-gateway.sh
      sudo bash scripts/pack-debian-squashfs.sh
      sudo bash scripts/make-sysupgrade.sh

    The result is a sysupgrade tar the board's recovery page accepts. Run the
    tests first if you like — they need neither hardware nor root:

      cd gateway && for t in tests/smoke_*.py; do python3 "\$t"; done

EOF
