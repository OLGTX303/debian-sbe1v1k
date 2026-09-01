#!/usr/bin/env bash
set -euo pipefail

# Package a vendor-compatible CONTROL/kernel/root sysupgrade tar.
# This does not flash anything. The vendor U-Boot requires root=SquashFS v4.

WS="$(cd "$(dirname "$0")/.." && pwd)"
# This FIT contains the matching QSDK 6.6.116 kernel and SBE1V1K DTB.
# The old 6.18 FIT cannot load the QSDK 6.6 modules.
KERNEL_FIT="${KERNEL_FIT:-$WS/../qsdk14-work-ucgf/qsdk/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/linux-ipq95xx_generic/askey_sbe1v1k-fit-uImage.itb}"
ROOTFS="${ROOTFS:-$WS/build/debian-bookworm-sbe1v1k.squashfs}"
# Accept the old location so a half-finished build tree still works.
[ -f "$ROOTFS" ] || ROOTFS="$WS/debian-bookworm-sbe1v1k.squashfs"
OUT="${OUT:-$WS/debian-bookworm-sbe1v1k-sysupgrade.bin}"
# The rootfs partition is PARTLABEL=rootfs, /dev/mmcblk0p29 on this board:
# 1048576 KiB as reported by /proc/partitions. The old 127926272 came from
# p27 in the supplied eMMC backup, which is not the partition the vendor
# U-Boot actually boots — it capped the image at 122 MB and left ~900 MB of
# the real partition unused.
ROOTFS_LIMIT="${ROOTFS_LIMIT:-1073741824}" # PARTLABEL=rootfs (mmcblk0p29), 1 GiB
TOTAL_LIMIT="${TOTAL_LIMIT:-1073741824}"  # requested 1 GiB package limit
ROOT_KIND="${ROOT_KIND:-debian}"
BOARD="askey_sbe1v1k"
STAGE="$(mktemp -d /tmp/sbe1v1k-sysupgrade.XXXXXX)"
trap 'rmdir "$STAGE/sysupgrade-'"$BOARD"'" 2>/dev/null || true; rmdir "$STAGE" 2>/dev/null || true' EXIT

[[ -f "$KERNEL_FIT" ]] || { echo "ERROR: kernel FIT missing: $KERNEL_FIT" >&2; exit 1; }
[[ -f "$ROOTFS" ]] || { echo "ERROR: root SquashFS missing: $ROOTFS" >&2; exit 1; }
command -v dumpimage >/dev/null || { echo "ERROR: dumpimage is required" >&2; exit 1; }
command -v unsquashfs >/dev/null || { echo "ERROR: unsquashfs is required" >&2; exit 1; }
# Refuse a payload older than the tree it is supposed to contain. pack-debian-
# squashfs.sh failing leaves the previous SquashFS in place, and this script
# happily packaged it — producing an image with a fresh filename and content
# hash that did not contain any of the changes just made to the rootfs. Silent
# staleness in a flashable artifact is the worst kind.
SRC_TREE="${SRC_TREE:-$WS/rootfs}"
if [[ -d "$SRC_TREE" && -f "$ROOTFS" ]]; then
    newer=$(find "$SRC_TREE" -newer "$ROOTFS" -print -quit 2>/dev/null || true)
    if [[ -n "$newer" ]]; then
        echo "ERROR: $ROOTFS is older than $SRC_TREE" >&2
        echo "       (e.g. $newer)" >&2
        echo "       re-run scripts/pack-debian-squashfs.sh first" >&2
        exit 1
    fi
fi

root_magic=$(od -An -tx4 -N4 "$ROOTFS" | tr -d ' ')
[[ "$root_magic" == "73717368" ]] || { echo "ERROR: root payload is not SquashFS v4" >&2; exit 1; }
if [[ "$ROOT_KIND" == debian ]]; then
    for required in '/etc/debian_version' '/etc/passwd' '/usr/bin/apt'; do
        unsquashfs -ll "$ROOTFS" | grep "squashfs-root${required}$" >/dev/null || {
            echo "ERROR: root payload is not a complete Debian filesystem; missing $required" >&2
            exit 1
        }
    done
    if ! unsquashfs -ll "$ROOTFS" | grep -E 'squashfs-root/(sbin/init|usr/lib/systemd/systemd)$' >/dev/null; then
        echo "ERROR: root payload is not a complete Debian filesystem; missing systemd init" >&2
        exit 1
    fi
elif [[ "$ROOT_KIND" == ucgf ]]; then
    for required in \
        '/sbin/init' \
        '/usr/share/unifi-core/app/node_modules/@ubnt/unifi-portal/dist/local/index.html' \
        '/lib/systemd/system/unifi-core.service' \
        '/lib/systemd/system/udapi-server.service' \
        '/usr/lib/ulp-go'; do
        unsquashfs -ll "$ROOTFS" | grep "squashfs-root${required}" >/dev/null || {
            echo "ERROR: UCG root payload is incomplete; missing $required" >&2
            exit 1
        }
    done
else
    echo "ERROR: ROOT_KIND must be debian or ucgf" >&2
    exit 1
fi
# Hand the artefact back to the user who invoked the build.
#
# These scripts run under sudo, so everything they create is owned by root. The
# desktop browser here is a snap, and snapd's AppArmor profile for the home
# interface grants access only through "owner @{HOME}/**" rules — a snap running
# as the user is denied a root-owned file even at mode 644. The recovery page
# then fails to read it and reports "Image must be a FIT-based raw image or an
# OpenWrt sysupgrade tar", which looks exactly like a malformed image and is
# not. The one image that ever flashed was the one owned by the user.
give_back() {
    [ -n "${SUDO_UID:-}" ] || return 0
    for f in "$@"; do
        [ -e "$f" ] || continue
        chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$f" || true
        chmod 0644 "$f" || true
    done
}

root_bytes=$(stat -c %s "$ROOTFS")
(( root_bytes <= ROOTFS_LIMIT )) || { echo "ERROR: root payload exceeds configured rootfs partition limit ($ROOTFS_LIMIT bytes)" >&2; exit 1; }
dumpimage -l "$KERNEL_FIT" >/dev/null 2>&1 || { echo "ERROR: kernel payload is not a valid FIT image" >&2; exit 1; }

DIR="$STAGE/sysupgrade-$BOARD"
mkdir -p "$DIR"
printf 'BOARD=%s\n' "$BOARD" > "$DIR/CONTROL"
cp -f "$KERNEL_FIT" "$DIR/kernel"

# Follow the reference recipe for this board exactly. From
# yintaomu-SBE1V1K-OpenWrt target/linux/qualcommbe/image/Makefile:
#
#   IMAGE/sysupgrade.bin/squashfs := append-rootfs | pad-to 64k \
#                                  | sysupgrade-tar rootfs=$@ | append-metadata
#
# Two steps were missing here and both matter:
#
#   pad-to 64k       the rootfs member must end on a 64 KiB boundary. Ours was
#                    8192 bytes short of one, and the eMMC writer works in
#                    erase-block units.
#   append-metadata  fwtool's JSON trailer. The target's platform.sh sets
#                    REQUIRE_IMAGE_METADATA=1, so an image without it is
#                    refused outright by sysupgrade.
#
# The tar also archives the DIRECTORY (as scripts/sysupgrade-tar.sh does), so a
# directory member precedes the files, and uses --sort=name for a stable order.
pad_to() {
    local file="$1" align="$2" size rem
    size=$(stat -c %s "$file")
    rem=$(( size % align ))
    if (( rem )); then
        dd if=/dev/zero bs=1 count=$(( align - rem )) status=none >> "$file"
        echo "padded $(basename "$file") by $(( align - rem )) bytes to a ${align}-byte boundary"
    fi
}

dd if="$ROOTFS" of="$DIR/root" bs=1024 conv=sync status=none
pad_to "$DIR/root" 65536

tar -C "$STAGE" --sort=name --owner=0 --group=0 --numeric-owner \
    -cf "$OUT" "sysupgrade-$BOARD"

# --- append-metadata
# fwtool -I embeds the JSON so sysupgrade can check the image is for this board.
FWTOOL="${FWTOOL:-$(command -v fwtool || true)}"
for candidate in \
    "$WS/../qsdk14-work-ucgf/qsdk/staging_dir/host/bin/fwtool" \
    "$WS/../qsdk/staging_dir/host/bin/fwtool" \
    "$WS/../openwrt-sbe1v1k/staging_dir/host/bin/fwtool" \
    "$WS/../yintaomu-SBE1V1K-OpenWrt/staging_dir/host/bin/fwtool"; do
    [ -n "$FWTOOL" ] && break
    [ -x "$candidate" ] && FWTOOL="$candidate"
done
if [ -n "$FWTOOL" ] && [ -x "$FWTOOL" ]; then
    metadata=$(printf '{ "metadata_version": "1.1", "compat_version": "1.0", "supported_devices": ["askey,sbe1v1k","askey,rtq7300t","spectrum,sbe1v1k"], "version": { "dist": "Debian", "version": "bookworm", "revision": "sbegw", "target": "qualcommbe/ipq95xx", "board": "%s" } }' "$BOARD")
    printf '%s' "$metadata" | "$FWTOOL" -I - "$OUT"
    echo "appended fwtool metadata for $BOARD"
else
    echo "WARNING: fwtool not found; image has no metadata trailer and" >&2
    echo "         OpenWrt sysupgrade (REQUIRE_IMAGE_METADATA=1) will refuse it." >&2
fi
total_bytes=$(stat -c %s "$OUT")
(( total_bytes <= TOTAL_LIMIT )) || { echo "ERROR: sysupgrade exceeds 1 GiB package limit" >&2; exit 1; }
# Assert the result is what the U-Boot recovery page will actually accept: it
# sniffs the first 512 bytes for the FIT magic or "ustar" at offset 257. The
# intermediate .squashfs in this directory is neither, and its name differs from
# the real image by one word — uploading it produces exactly
#   "Image must be a FIT-based raw image or an OpenWrt sysupgrade tar."
python3 - "$OUT" <<'VALIDATE'
import sys
path = sys.argv[1]
with open(path, "rb") as fh:
    head = fh.read(512)
fit = head[:4] == bytes((0xD0, 0x0D, 0xFE, 0xED))
tar = len(head) >= 262 and head[257:262] == b"ustar"
if not (fit or tar):
    sys.exit(f"ERROR: {path} is neither a FIT image nor a sysupgrade tar; "
             "the recovery page would reject it")
print(f"format check: {'FIT raw image' if fit else 'OpenWrt sysupgrade tar'} — "
      "the recovery page will accept this")
VALIDATE

echo "$OUT"
tar tf "$OUT"
echo "root payload: $root_bytes bytes; package: $total_bytes bytes"
# Also emit a content-addressed copy. A browser refuses to read a file that
# changed on disk after it was selected (NotReadableError), and the recovery
# page reports that as "Image must be a FIT-based raw image or an OpenWrt
# sysupgrade tar" — indistinguishable from a bad image. A unique name per build
# means a rebuild can never invalidate a selection that is already in progress.
stamp=$(sha256sum "$OUT" | cut -c1-12)
stable="${OUT%.bin}-$stamp.bin"
cp -f "$OUT" "$stable"
echo
echo "FLASH THIS FILE: $stable"
echo "  Stable name: a later build will not overwrite it, so a file already"
echo "  selected in the browser stays readable."
give_back "$OUT" "$stable"
echo "  owner: $(stat -c '%U:%G' "$stable") (readable by a sandboxed browser)"
echo "  ($(stat -c %s "$stable") bytes, sha256 $(sha256sum "$stable" | cut -c1-64))"
