#!/usr/bin/env bash
set -euo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-$WS/rootfs}"
# The intermediate rootfs image lives under build/, not beside the flashable
# sysupgrade tar: a .squashfs is neither a FIT image nor a tar, so uploading it
# to the recovery page fails with "Image must be a FIT-based raw image or an
# OpenWrt sysupgrade tar" — and its name differed from the real image by one
# word, which is an easy mistake to make at 1am.
OUT="${OUT:-$WS/build/debian-bookworm-sbe1v1k.squashfs}"
mkdir -p "$(dirname "$OUT")"
# The rootfs partition is PARTLABEL=rootfs, /dev/mmcblk0p29 on this board:
# 1048576 KiB as reported by /proc/partitions. The old 127926272 came from
# p27 in the supplied eMMC backup, which is not the partition the vendor
# U-Boot actually boots — it capped the image at 122 MB and left ~900 MB of
# the real partition unused.
LIMIT="${LIMIT:-1073741824}" # PARTLABEL=rootfs (mmcblk0p29), 1 GiB

[[ -d "$SRC" ]] || { echo "ERROR: Debian rootfs missing: $SRC" >&2; exit 1; }
# -e follows symlinks, and these are absolute symlinks *inside the image*, so it
# resolves them against the build host's filesystem. /sbin/init -> /lib/systemd/
# systemd happened to exist on the host and passed by luck; once it pointed at
# /usr/lib/sbegw/overlay-init the check failed on a perfectly good rootfs — and
# make-sysupgrade.sh then packaged the previous, stale SquashFS without
# complaining. Accept a dangling symlink: the target lives in the image, and the
# SquashFS content checks in make-sysupgrade.sh verify it for real.
for required in "$SRC/etc/debian_version" "$SRC/etc/passwd" "$SRC/sbin/init" "$SRC/usr/bin/apt"; do
    [[ -e "$required" || -L "$required" ]] ||
        { echo "ERROR: incomplete Debian rootfs; missing $required" >&2; exit 1; }
done
command -v mksquashfs >/dev/null || { echo "ERROR: mksquashfs is required" >&2; exit 1; }

rm -f "$OUT"
mksquashfs "$SRC" "$OUT" -comp xz -b 262144 -noappend -no-xattrs
if [ -n "${SUDO_UID:-}" ]; then
    # Built under sudo; give it back so later steps and the user can read it.
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" || true
fi
bytes=$(stat -c %s "$OUT")
if (( bytes > LIMIT )); then
    echo "ERROR: Debian SquashFS is $bytes bytes; rootfs partition is only $LIMIT bytes." >&2
    echo "Use a larger partition/layout before creating a sysupgrade image." >&2
    exit 1
fi
echo "$OUT ($bytes bytes; limit $LIMIT)"
