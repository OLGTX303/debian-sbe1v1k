#!/usr/bin/env bash
set -euo pipefail

# Build a Debian Bookworm arm64 userspace for the SBE1V1K. This deliberately does
# not touch flash or the existing OpenWrt build.

WS="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="${ROOTFS:-$WS/rootfs}"
OUT="${OUT:-$WS/debian-bookworm-sbe1v1k.ext4}"
SIZE="${SIZE:-6144M}"
MIRROR="${MIRROR:-http://deb.debian.org/debian}"
BOARD_FW="${BOARD_FW:-$WS/../uinif_u7pro_serious_fw/re/rootfs_full/lib/firmware}"
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
# The staging_dir root: firmware, INI files, the musl userland.
QSDK_ROOT="${QSDK_ROOT:-$QSDK/staging_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx}"
QSDK_MODULES="${QSDK_MODULES:-$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/lib/modules/6.6.116+}"
KERNEL_RELEASE="${KERNEL_RELEASE:-6.6.116}"
QSDK_FIRMWARE="${QSDK_FIRMWARE:-$QSDK_ROOT/lib/firmware}"
QSDK_INI="${QSDK_INI:-$QSDK/qca/feeds/wlan-open/mac80211/files/ini}"
PORTAL_ASSETS="${PORTAL_ASSETS:-$WS/../ucgf_controller_port/rootfs_ucgf/usr/share/unifi-core/app/node_modules/@ubnt/unifi-portal/dist/local}"
PORTAL_INDEX="${PORTAL_INDEX:-$WS/portal/index.html}"
QEMU="${QEMU:-$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)}"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root (needed for debootstrap/chroot and the ext4 image)"
command -v debootstrap >/dev/null || die "install debootstrap"
[[ -n "$QEMU" && -x "$QEMU" ]] || die "install qemu-user (qemu-aarch64)"
[[ -d "$BOARD_FW" ]] || die "board firmware directory not found: $BOARD_FW"
[[ -d "$QSDK_MODULES" ]] || die "QSDK modules directory not found: $QSDK_MODULES"
[[ -d "$QSDK_FIRMWARE" ]] || die "QSDK firmware directory not found: $QSDK_FIRMWARE"
[[ -d "$QSDK_INI" ]] || die "QSDK ath12k INI directory not found: $QSDK_INI"
[[ -d "$PORTAL_ASSETS" ]] || die "UCG portal frontend assets not found: $PORTAL_ASSETS"
[[ -r "$PORTAL_INDEX" ]] || die "SBE1V1K portal index not found: $PORTAL_INDEX"

mkdir -p "$WS" "$ROOTFS"
if [[ -d "$ROOTFS/debootstrap" && ! -e "$ROOTFS/usr/bin/apt" ]]; then
    PARTIAL="${ROOTFS}.partial.$$.backup"
    echo "[*] moving incomplete bootstrap to $PARTIAL"
    mv "$ROOTFS" "$PARTIAL"
    mkdir -p "$ROOTFS"
fi
if [[ ! -e "$ROOTFS/usr/bin/apt" ]]; then
    debootstrap --arch=arm64 --foreign bookworm "$ROOTFS" "$MIRROR"
    chroot "$ROOTFS" /debootstrap/debootstrap --second-stage
fi
install -m 0755 "$QEMU" "$ROOTFS/usr/bin/qemu-aarch64-static"

# install-gateway.sh masks packaged units by replacing them with symlinks to
# /dev/null, because sbegw owns networking, DNS and DHCP. Rebuilding over an
# already-installed rootfs then goes wrong twice over: `cat > unit` writes
# *through* the symlink into /dev/null, so the unit ends up empty rather than
# rewritten, and `systemctl enable` later fails with "does not exist" or
# "is masked" and aborts the build under `set -e`. Neither is recoverable by
# re-running, so the script only ever worked on a first, clean rootfs.
#
# Clear the masks here, before anything is written. install-gateway re-applies
# them at the end of the pipeline; this stage's job is a working bare rootfs.
if [[ -d "$ROOTFS/etc/systemd/system" ]]; then
    find "$ROOTFS/etc/systemd/system" -maxdepth 1 -type l -lname /dev/null \
        -print -delete 2>/dev/null || true
fi

install -d "$ROOTFS/etc/apt/sources.list.d" "$ROOTFS/etc/systemd/network" \
    "$ROOTFS/lib/firmware/IPQ9574/WIFI_FW" "$ROOTFS/lib/firmware/qcn9224" \
    "$ROOTFS/vendor/firmware/qcn9224" "$ROOTFS/lib/modules" "$ROOTFS/usr/local/sbin" \
    "$ROOTFS/etc/modules-load.d" "$ROOTFS/etc/systemd/system" \
    "$ROOTFS/etc/systemd/system/systemd-modules-load.service.d"
cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb $MIRROR bookworm main contrib non-free-firmware
deb $MIRROR bookworm-updates main contrib non-free-firmware
deb $MIRROR bookworm-backports main contrib non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free-firmware
EOF
cat > "$ROOTFS/etc/hostname" <<'EOF'
sbe1v1k
EOF
cat > "$ROOTFS/etc/fstab" <<'EOF'
LABEL=debian-rootfs / ext4 defaults,noatime,errors=remount-ro 0 1
EOF
cat > "$ROOTFS/etc/systemd/network/10-br-lan.netdev" <<'EOF'
[NetDev]
Name=br-lan
Kind=bridge
EOF
install -d "$ROOTFS/etc/sbe1v1k"
cat > "$ROOTFS/etc/sbe1v1k/ports.conf" <<'EOF'
# eth0/eth1 = QCA8075 1G, eth2 = QCA8081 2.5G, eth3 = RTL8261 10G.
eth0=lan
eth1=lan
eth2=lan
eth3=wan
EOF
cat > "$ROOTFS/usr/local/sbin/sbe1v1k-port-config" <<'EOF'
#!/bin/sh
set -eu
STATE=/run/sbe1v1k
CONF=$STATE/ports.conf
NET=/run/systemd/network
mkdir -p "$STATE" "$NET"
if [ ! -e "$CONF" ]; then cp /etc/sbe1v1k/ports.conf "$CONF"; fi
lan=""
rm -f "$NET/20-lan-ports.network" "$NET/30-br-lan.network" "$NET"/40-wan-*.network
while IFS='=' read -r ifname role; do
    case "$ifname" in ''|'#'*) continue ;; esac
    case "$ifname:$role" in
        eth[0-9]:lan) lan="${lan:+$lan }$ifname" ;;
        eth[0-9]:wan) cat > "$NET/40-wan-$ifname.network" <<EON
[Match]
Name=$ifname

[Network]
DHCP=yes
IPv6AcceptRA=yes
EON
            ;;
    esac
done < "$CONF"
if [ -n "$lan" ]; then
    cat > "$NET/20-lan-ports.network" <<EON
[Match]
Name=$lan

[Network]
Bridge=br-lan
LinkLocalAddressing=no
IPv6AcceptRA=no
EON
fi
cat > "$NET/30-br-lan.network" <<'EON'
[Match]
Name=br-lan

[Network]
Address=192.168.2.1/24
ConfigureWithoutCarrier=yes
IPv6AcceptRA=no
EON
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-port-config"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-port-config.service" <<'EOF'
[Unit]
Description=Configure SBE1V1K LAN/WAN ports from DTS profile
After=sbe1v1k-drivers.service
Before=systemd-networkd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-port-config
RemainAfterExit=yes

[Install]
WantedBy=systemd-networkd.service
EOF
# Remove network files from older image builds; the port-role service owns them.
rm -f "$ROOTFS/etc/systemd/network/20-lan.network" \
      "$ROOTFS/etc/systemd/network/20-lan-ports.network" \
      "$ROOTFS/etc/systemd/network/30-br-lan.network" \
      "$ROOTFS/etc/systemd/network/40-wan-"*.network
install -d "$ROOTFS/etc/dnsmasq.d"
cat > "$ROOTFS/etc/dnsmasq.d/sbe1v1k-lan.conf" <<'EOF'
interface=br-lan
bind-interfaces
listen-address=192.168.2.1
dhcp-leasefile=/run/dnsmasq.leases
dhcp-authoritative
dhcp-range=192.168.2.100,192.168.2.200,255.255.255.0,12h
dhcp-option=option:router,192.168.2.1
dhcp-option=option:dns-server,192.168.2.1
domain-needed
bogus-priv
EOF
# Debian ships the dnsmasq.d include commented out by default. Enable it so
# the board LAN DHCP range is actually read by the daemon.
grep -qxF 'conf-dir=/etc/dnsmasq.d/,*.conf' "$ROOTFS/etc/dnsmasq.conf" || \
    printf '%s\n' 'conf-dir=/etc/dnsmasq.d/,*.conf' >> "$ROOTFS/etc/dnsmasq.conf"

# The SBE1V1K board firmware is not part of a generic Debian install.
find "$ROOTFS/lib/firmware" -xtype l -delete 2>/dev/null || true
cp -a --no-preserve=ownership "$BOARD_FW"/. "$ROOTFS/lib/firmware/"
# The Debian userspace must use modules built for the selected QSDK 6.6.116
# kernel. Do not copy QSDK's musl userland over Debian's glibc userland.
find "$ROOTFS/lib/firmware" -xtype l -delete 2>/dev/null || true
MODULE_SOURCE_VERSION="$(basename "$QSDK_MODULES")"
install -d "$ROOTFS/lib/modules/$KERNEL_RELEASE"
find "$ROOTFS/lib/modules" -maxdepth 1 -type f -name '*.ko' -delete 2>/dev/null || true
cp -a --no-preserve=ownership "$QSDK_MODULES"/. "$ROOTFS/lib/modules/$KERNEL_RELEASE/"
cp -a --no-preserve=ownership "$QSDK_FIRMWARE"/. "$ROOTFS/lib/firmware/"
# The QSDK ath12k extension requests these by firmware-relative names
# (global.ini, internal/global_i.ini, QCN9274.ini, ...), not from the WIFIFW
# partition. Without them ath12k dereferences an uninitialized INI store and
# panics during module insertion.
install -d "$ROOTFS/lib/firmware/internal"
cp -a --no-preserve=ownership "$QSDK_INI"/. "$ROOTFS/lib/firmware/"
find "$ROOTFS/lib/modules/$KERNEL_RELEASE" -type f -name '*.ko' -exec strip --strip-debug {} + 2>/dev/null || true

# OpenWrt's installed module tree ships a FLATTENED modules.builtin: every line
# is a bare filename ("8021q.ko") instead of a path ("kernel/net/8021q/8021q.ko").
# kmod rejects those lines, so depmod aborts, no modules.dep is produced, and
# modprobe then fails for EVERY module by name -- silently, since anything using
# modprobe just does nothing. Take the well-formed file from the kernel build and
# generate the dep data here, so modprobe works in the image.
_kbuild="$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/linux-ipq95xx_generic/linux-6.6.116"
if [[ -f "$_kbuild/modules.builtin" ]]; then
    cp -a --no-preserve=ownership "$_kbuild/modules.builtin" \
        "$ROOTFS/lib/modules/$KERNEL_RELEASE/modules.builtin"
    [[ -f "$_kbuild/modules.order" ]] && cp -a --no-preserve=ownership \
        "$_kbuild/modules.order" "$ROOTFS/lib/modules/$KERNEL_RELEASE/modules.order"
else
    # Without the kernel build tree, drop the malformed lines rather than leave a
    # file that makes depmod abort outright.
    sed -i -n '/\//p' "$ROOTFS/lib/modules/$KERNEL_RELEASE/modules.builtin" 2>/dev/null || true
fi
if depmod -b "$ROOTFS" "$KERNEL_RELEASE" 2>&1 | grep -q "ERROR"; then
    die "depmod failed for $KERNEL_RELEASE; modprobe would be broken in the image"
fi
[[ -s "$ROOTFS/lib/modules/$KERNEL_RELEASE/modules.dep" ]] \
    || die "depmod produced no modules.dep; modprobe would be broken in the image"
grep -q "qca-nss-ppe-bridge-mgr" "$ROOTFS/lib/modules/$KERNEL_RELEASE/modules.dep" \
    || echo "[!] PPE bridge-mgr not in the module tree; hardware offload unavailable" >&2

cat > "$ROOTFS/etc/modules-load.d/sbe1v1k-qca.conf" <<'EOF'
cfg80211
mac80211
mdio-ipq4019
mdio-ahb
ath12k
ath12k_wifi6
ath12k_wifi7
ath12k_wifi8
qca-nss-dp
qca-nss-ppe
qca-nss-ppe-rule
qca-nss-ppe-netlink
qca-nss-ppe-vp
qca-nss-sfe
qca-nss-phy
qca-ssdk
qca-nss-ppe-vlan
qca-nss-ppe-bridge-mgr
ecm
EOF

# Match the OpenWrt vendor flow: use the Wi-Fi firmware already stored in the
# eMMC GPT partitions 0:WIFIFW (primary, normally mmcblk0p23) or 0:WIFIFW_1
# (backup, normally mmcblk0p24). Do not hard-code p23: enumerate PARTNAME so
# this also works if the bootloader exposes a different mmc device number.
cat > "$ROOTFS/usr/local/sbin/sbe1v1k-wififw" <<'EOF'
#!/bin/sh
set -u

# This is the layout used by the previous QSDK/OpenWrt image. The ath12k
# driver requests the vendor QCN9224 files from /lib/firmware/qcn9224.
MNT=/lib/firmware/IPQ9574/WIFI_FW
QCN=/lib/firmware/qcn9224
VENDOR=/vendor/firmware/qcn9224

part=""
for uevent in /sys/block/mmcblk*/mmcblk*p*/uevent; do
    [ -r "$uevent" ] || continue
    name=$(sed -n 's/^PARTNAME=//p' "$uevent")
    case "$name" in
        0:WIFIFW|WIFIFW|0:WIFIFW_1|WIFIFW_1)
            part=/dev/$(basename "$(dirname "$uevent")")
            [ -b "$part" ] && break
            part=""
            ;;
    esac
done

if [ -z "$part" ]; then
    echo "WIFIFW eMMC partition not found; retaining packaged firmware" >&2
    exit 0
fi

mkdir -p "$MNT" "$QCN" "$VENDOR" /lib/firmware/IPQ9574
if ! mountpoint -q "$MNT"; then
    mount -t squashfs -o ro "$part" "$MNT" || {
        echo "failed to mount $part as WIFIFW" >&2
        exit 0
    }
fi

[ -d "$MNT/qcn9224" ] || {
    echo "$part has no qcn9224 firmware directory" >&2
    exit 0
}

# Reproduce the OpenWrt links, including files added by newer firmware
# partitions. Do not remove the packaged ath12k/QCN9274 firmware: it contains
# board-2.bin and firmware-2.bin, which are separate from WIFIFW.
for src in "$MNT/qcn9224"/*; do
    [ -f "$src" ] || continue
    name=$(basename "$src")
    ln -sfn "$src" "$QCN/$name"
    case "$name" in
        Data.msc) ln -sfn "$src" "$VENDOR/$name" ;;
        qdss_*) ln -sfn "$src" "$VENDOR/$name" ;;
    esac
done
for src in "$MNT"/*; do
    [ -f "$src" ] || continue
    name=$(basename "$src")
    ln -sfn "$src" "/lib/firmware/IPQ9574/$name"
done
echo "using $part for ath12k firmware at $MNT"
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-wififw"

# The vendor image reads the ART eMMC partition before NSS-DP/ath12k starts.
# Keep that behavior explicit: firmware is requested from writable /run, while
# the immutable SquashFS continues to provide the packaged QCN9274 files.
cat > "$ROOTFS/usr/local/sbin/sbe1v1k-art-init" <<'EOF'
#!/bin/sh
set -u
ART=""
for attempt in $(seq 1 20); do
    for uevent in /sys/block/mmcblk*/mmcblk*p*/uevent; do
        [ -r "$uevent" ] || continue
        name=$(sed -n 's/^PARTNAME=//p' "$uevent")
        case "$name" in
            0:ART|ART) ART=/dev/$(basename "$(dirname "$uevent")"); break 2 ;;
        esac
    done
    sleep 1
done
[ -b "$ART" ] || { echo "ART partition not found" >&2; exit 0; }
mkdir -p /run/firmware /run/sbe1v1k
if [ -e /sys/module/firmware_class/parameters/path ]; then
    echo '/run/firmware:/lib/firmware' > /sys/module/firmware_class/parameters/path
fi

# caldb_offset/caldb_size are the values used by the SBE1V1K DTS and stock
# QSDK flow. The ath12k firmware requests this blob as caldata.bin.
if dd if="$ART" of=/run/firmware/caldata.bin bs=1 skip=$((0x1100000)) \
        count=$((0x800000)) status=none 2>/dev/null; then
    chmod 0644 /run/firmware/caldata.bin
    cp -f /run/firmware/caldata.bin /run/sbe1v1k/caldata.bin
fi
echo "using ART=$ART; extracted caldata.bin" > /run/sbe1v1k/art-init.log
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-art-init"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-art-init.service" <<'EOF'
[Unit]
Description=Load SBE1V1K ART calibration database
DefaultDependencies=no
After=systemd-udev-trigger.service
Before=wififw.service systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-art-init
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF

cat > "$ROOTFS/usr/local/sbin/sbe1v1k-apply-macs" <<'EOF'
#!/bin/sh
set -u
ART=""
for uevent in /sys/block/mmcblk*/mmcblk*p*/uevent; do
    [ -r "$uevent" ] || continue
    name=$(sed -n 's/^PARTNAME=//p' "$uevent")
    case "$name" in
        0:ART|ART) ART=/dev/$(basename "$(dirname "$uevent")"); break ;;
    esac
done
[ -b "$ART" ] || exit 0
base_mac() {
    hex=$(dd if="$ART" bs=1 skip=0 count=6 status=none 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
    [ "${#hex}" = 12 ] || return 1
    case "$hex" in 000000000000|ffffffffffff) return 1 ;; esac
    BASEHEX="$hex"
}
mac_at() {
    index="$1"
    hex=$(printf '%012x' "$((0x$BASEHEX + index))")
    printf '%s\n' "$hex" | sed 's/../&:/g;s/:$//' 
}
set_mac() {
    dev="$1"; index="$2"; mac=$(mac_at "$index") || return 0
    ip link set dev "$dev" address "$mac" 2>/dev/null || true
    echo "$dev $mac" >> /run/sbe1v1k/art-macs.log
}
: > /run/sbe1v1k/art-macs.log
# The DTS uses a mac-base NVMEM provider: cell 0 is the ART base MAC and
# cells 1..3 are generated by incrementing it, not by reading raw slots.
base_mac || exit 0
set_mac eth3 0
set_mac eth0 1
set_mac eth1 2
set_mac eth2 3
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-apply-macs"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-apply-macs.service" <<'EOF'
[Unit]
Description=Apply SBE1V1K ART MAC addresses to Ethernet ports
After=sbe1v1k-drivers.service sbe1v1k-art-init.service
Before=systemd-networkd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-apply-macs
RemainAfterExit=yes

[Install]
WantedBy=systemd-networkd.service
EOF

cat > "$ROOTFS/etc/systemd/system/wififw.service" <<'EOF'
[Unit]
Description=Mount vendor eMMC Wi-Fi firmware
DefaultDependencies=no
Requires=dev-mmcblk0.device
Requires=sbe1v1k-art-init.service
After=dev-mmcblk0.device systemd-udev-trigger.service
Before=systemd-modules-load.service
ConditionPathExists=/sys/block/mmcblk0

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-wififw
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF

cat > "$ROOTFS/etc/systemd/system/systemd-modules-load.service.d/wififw.conf" <<'EOF'
[Unit]
Requires=wififw.service
After=wififw.service
EOF

# Load the vendor modules explicitly and retain errors in the journal. Debian
# otherwise reports systemd-modules-load as successful even when a module is
# absent or rejected for a kernel vermagic mismatch.
cat > "$ROOTFS/usr/local/sbin/sbe1v1k-load-drivers" <<'EOF'
#!/bin/sh
set -u
LOG=/run/sbe1v1k-driver-load.log
: > "$LOG"
for mod in cfg80211 mac80211 ath ath_debug mdio-ipq4019 mdio-ahb ath12k ath12k_wifi6 ath12k_wifi7 \
    ath12k_wifi8 qca8084-phy qca8k-cc qca-ssdk qca-nss-ppe qca-nss-ppe-rule \
    qca-nss-ppe-netlink qca-nss-ppe-vp qca-nss-dp qca-nss-sfe qca-nss-phy \
    qca-nss-ppe-vlan qca-nss-ppe-bridge-mgr ecm; do
    if modprobe "$mod" >>"$LOG" 2>&1; then
        echo "loaded $mod" >>"$LOG"
    else
        rc=$?
        echo "FAILED $mod (rc=$rc)" >>"$LOG"
    fi
done
cat "$LOG" >&2
exit 0
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-load-drivers"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-drivers.service" <<'EOF'
[Unit]
Description=Load SBE1V1K QCA Wi-Fi and Ethernet drivers
Requires=wififw.service
After=wififw.service systemd-modules-load.service
Before=systemd-networkd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-load-drivers
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Copy the shell/XML part of the reversed U7 Pro RF workflow. These scripts
# are architecture-independent; QSDK kernel modules remain the hardware ABI.
if [[ -d "$QSDK_ROOT/usr/etc/unifi-wifi" ]]; then
    install -d "$ROOTFS/usr/etc/unifi-wifi"
    cp -a --no-preserve=ownership "$QSDK_ROOT/usr/etc/unifi-wifi"/. "$ROOTFS/usr/etc/unifi-wifi/"
fi
if [[ -f "$QSDK_ROOT/usr/sbin/unifi-wifi-apply" ]]; then
    install -m 0755 "$QSDK_ROOT/usr/sbin/unifi-wifi-apply" "$ROOTFS/usr/local/sbin/unifi-wifi-apply"
fi

# Copy only the static UCG portal frontend. Its native UCG runtime is not
# included; API calls are handled by the Debian SBE1V1K control service.
install -d "$ROOTFS/usr/share/sbe1v1k-portal"
cp -a --no-preserve=ownership "$PORTAL_ASSETS"/. "$ROOTFS/usr/share/sbe1v1k-portal/"
install -m 0644 "$PORTAL_INDEX" "$ROOTFS/usr/share/sbe1v1k-portal/index.html"

cat > "$ROOTFS/etc/fstab" <<'EOF'
LABEL=debian-rootfs / ext4 defaults,noatime,errors=remount-ro 0 1
EOF

# Remove any previously staged native UCG runtime. The Debian portal below is
# intentionally independent of udapi, unifi-core, UCG nginx, nspawn, and Docker.
rm -f "$ROOTFS/usr/local/sbin/start-ucgf-console" \
      "$ROOTFS/usr/local/sbin/start-controller.sh" \
      "$ROOTFS/usr/local/sbin/install-debian-console.sh" \
      "$ROOTFS/etc/systemd/system/ucgf-console.service"
rm -rf "$ROOTFS/usr/lib/ucgf"

# Debian nginx exposes the Debian-native gateway portal on port 80.
# The portal backend is the local SBE1V1K control API on 127.0.0.1:8090.
install -d "$ROOTFS/etc/nginx/sites-available" "$ROOTFS/etc/nginx/sites-enabled"
rm -f "$ROOTFS/etc/nginx/sites-enabled/default"
cat > "$ROOTFS/etc/nginx/sites-available/sbe1v1k-portal" <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /usr/share/sbe1v1k-portal;
    location /device/ {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
    }
    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
ln -sfn ../sites-available/sbe1v1k-portal "$ROOTFS/etc/nginx/sites-enabled/sbe1v1k-portal"

# Small device-management UI for port roles, VLANs, and a basic ath12k AP profile.
cat > "$ROOTFS/usr/local/sbin/sbe1v1k-config-ui.py" <<'PY'
#!/usr/bin/python3
import json, os, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = '/etc/sbe1v1k-network.json'

def run(*args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=False).stdout

PAGE = '''<!doctype html><meta name="viewport" content="width=device-width"><title>SBE1V1K Gateway Control</title>
<style>body{font:16px sans-serif;max-width:760px;margin:2em auto}input,select,button{padding:.55em;margin:.25em}section{border:1px solid #ccc;padding:1em;margin:1em 0}</style>
<h1>SBE1V1K Gateway Control</h1><p>LAN gateway management</p>
<section><h2>Port roles</h2><p>eth0/eth1: 1G; eth2: 2.5G; eth3: 10G.</p><form method="post" action="/device/api/ports">
eth0 <select name="eth0"><option value="lan">LAN</option><option value="wan">WAN</option></select>
eth1 <select name="eth1"><option value="lan">LAN</option><option value="wan">WAN</option></select>
eth2 (2.5G) <select name="eth2"><option value="lan">LAN</option><option value="wan">WAN</option></select>
eth3 (10G) <select name="eth3"><option value="wan">WAN</option><option value="lan">LAN</option></select>
<button>Apply port roles</button></form></section>
<section><h2>VLAN</h2><form method="post" action="/device/api/vlan">
Parent <input name="parent" value="eth0"> VLAN ID <input name="id" type="number" min="1" max="4094" value="10">
Name <input name="name" value="lan10"> Address <input name="address" value="192.168.10.1/24"><button>Apply VLAN</button></form></section>
<section><h2>Wi-Fi AP</h2><form method="post" action="/device/api/wifi">
Interface <input name="interface" value="wlP1p1s0"> SSID <input name="ssid" value="SBE1V1K">
Password <input name="password" type="password" minlength="8" value="password123"> Channel <input name="channel" value="36">
Country <input name="country" value="US"><button>Apply Wi-Fi</button></form></section>
<pre id="status">Loading status...</pre><script>fetch('/device/api/status').then(r=>r.text()).then(x=>status.textContent=x)</script>'''

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, content='text/html'):
        b = body.encode(); self.send_response(code); self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path in ('/', '/device/', '/device'): self.send(200, PAGE); return
        if self.path == '/device/api/status':
            self.send(200, json.dumps({'links': run('ip','-br','link'), 'wifi': run('iw','dev')}), 'application/json'); return
        self.send(404, 'not found')
    def form(self):
        n = int(self.headers.get('Content-Length','0')); from urllib.parse import parse_qs
        return {k:v[0] for k,v in parse_qs(self.rfile.read(n).decode()).items()}
    def do_POST(self):
        f = self.form()
        if self.path == '/device/api/ports':
            roles = {p:f.get(p,'lan') for p in ('eth0','eth1','eth2','eth3')}
            if any(v not in ('lan','wan') for v in roles.values()):
                self.send(400, 'invalid port role'); return
            os.makedirs('/run/sbe1v1k', exist_ok=True)
            with open('/run/sbe1v1k/ports.conf','w') as out:
                for p in roles: out.write(p+'='+roles[p]+'\n')
            run('/usr/local/sbin/sbe1v1k-port-config')
            run('systemctl','restart','systemd-networkd.service')
            run('systemctl','restart','dnsmasq.service')
            self.send(200, 'Port roles applied. Return to /device/'); return
        if self.path == '/device/api/vlan':
            parent, name, vid = f.get('parent','eth0'), f.get('name','lan10'), f.get('id','10')
            if not name.replace('_','').isalnum() or not vid.isdigit() or not 1 <= int(vid) <= 4094:
                self.send(400, 'invalid VLAN'); return
            run('ip','link','add','link',parent,'name',name,'type','vlan','id',vid)
            if f.get('address'): run('ip','addr','replace',f['address'],'dev',name)
            run('ip','link','set',name,'up')
            os.makedirs('/run/systemd/network', exist_ok=True)
            open('/run/systemd/network/50-'+name+'.netdev','w').write('[NetDev]\nName='+name+'\nKind=vlan\n[VLAN]\nId='+vid+'\n')
            open('/run/systemd/network/50-'+name+'.network','w').write('[Match]\nName='+name+'\n[Network]\nAddress='+f.get('address','')+'\n')
            self.send(200, 'VLAN applied: '+name); return
        if self.path == '/device/api/wifi':
            iface, ssid, pw = f.get('interface','wlP1p1s0'), f.get('ssid','SBE1V1K'), f.get('password','')
            if len(pw) < 8 or not ssid or any(x in iface for x in '/ '): self.send(400, 'invalid Wi-Fi settings'); return
            os.makedirs('/run/hostapd', exist_ok=True)
            open('/run/hostapd/hostapd.conf','w').write('interface='+iface+'\ndriver=nl80211\nssid='+ssid+'\ncountry_code='+f.get('country','US')+'\nhw_mode=a\nchannel='+f.get('channel','36')+'\nwpa=2\nwpa_passphrase='+pw+'\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n')
            run('systemctl','restart','hostapd'); self.send(200, 'Wi-Fi AP applied'); return
        self.send(404, 'not found')
    def log_message(self, *_): pass

HTTPServer(('127.0.0.1', 8090), Handler).serve_forever()
PY
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-config-ui.py"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-config-ui.service" <<'EOF'
[Unit]
Description=SBE1V1K VLAN and Wi-Fi configuration UI
After=network.target

[Service]
ExecStart=/usr/local/sbin/sbe1v1k-config-ui.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

install -d "$ROOTFS/etc/systemd/system/nginx.service.d"
cat > "$ROOTFS/etc/systemd/system/nginx.service.d/sbe1v1k-runtime.conf" <<'EOF'
[Unit]
After=network-online.target sbe1v1k-config-ui.service
Wants=network-online.target sbe1v1k-config-ui.service

[Service]
ExecStartPre=
ExecStartPre=/bin/mkdir -p /run/nginx/body /run/nginx/proxy /run/nginx/fastcgi /run/nginx/uwsgi /run/nginx/scgi
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
Restart=on-failure
RestartSec=3
EOF

install -d "$ROOTFS/etc/systemd/system/hostapd.service.d"
cat > "$ROOTFS/etc/systemd/system/hostapd.service.d/sbe1v1k-runtime.conf" <<'EOF'
[Unit]
ConditionFileNotEmpty=
ConditionFileNotEmpty=/run/hostapd/hostapd.conf

[Service]
Environment=DAEMON_CONF=/run/hostapd/hostapd.conf
EOF

cat > "$ROOTFS/usr/local/sbin/sbe1v1k-hardware" <<'EOF'
#!/bin/sh
set -u

# GPIO LEDs are declared by the board DTS. Do not match the PHY LEDs here:
# the QCA8081 green/yellow LEDs must remain owned by the netdev trigger.
is_board_led() {
    node=$(readlink -f "$1/device/of_node" 2>/dev/null || true)
    case "$node" in
        */leds/led-blue|*/leds/led-red|*/leds/led-green) return 0 ;;
    esac
    return 1
}
for led in /sys/class/leds/*blue*; do
    [ -e "$led/brightness" ] || continue
    is_board_led "$led" || continue
    echo none > "$led/trigger" 2>/dev/null || true
    max=$(cat "$led/max_brightness" 2>/dev/null || echo 1)
    echo "$max" > "$led/brightness" 2>/dev/null || true
done
for led in /sys/class/leds/*red* /sys/class/leds/*green*; do
    [ -e "$led/brightness" ] || continue
    is_board_led "$led" || continue
    echo none > "$led/trigger" 2>/dev/null || true
    echo 0 > "$led/brightness" 2>/dev/null || true
done

# The two LEDs inside the QCA8081 PHY are wired to the 2.5G eth2 port. Use
# the kernel netdev trigger, which the QCA808x driver translates to hardware
# link/activity patterns. Match the PHY node rather than a generated LED name.
for led in /sys/class/leds/*; do
    [ -e "$led/trigger" ] || continue
    node=$(readlink -f "$led/device/of_node" 2>/dev/null || true)
    dev=$(basename "$(readlink -f "$led/device" 2>/dev/null || true)")
    case "$node $dev" in
        *ethernet-phy@28*|*90000.mdio-1:1c*)
            grep -qw netdev "$led/trigger" || continue
            echo netdev > "$led/trigger" 2>/dev/null || continue
            echo eth2 > "$led/device_name" 2>/dev/null || true
            echo 1 > "$led/link" 2>/dev/null || true
            echo 1 > "$led/tx" 2>/dev/null || true
            echo 1 > "$led/rx" 2>/dev/null || true
            ;;
    esac
done

# pwm-fan and the thermal cooling maps are in the DTS; fan speed is automatic.
for mod in mdio-ipq4019 mdio-ahb ath12k ath12k_wifi7 qca-nss-dp qca-nss-ppe qca-nss-ppe-rule \
    qca-nss-ppe-netlink qca-nss-ppe-vp qca-nss-sfe qca-nss-phy qca-ssdk \
    qca-nss-ppe-vlan qca-nss-ppe-bridge-mgr ecm; do
    modprobe "$mod" 2>/dev/null || true
done
exit 0
EOF
chmod 0755 "$ROOTFS/usr/local/sbin/sbe1v1k-hardware"
cat > "$ROOTFS/etc/systemd/system/sbe1v1k-hardware.service" <<'EOF'
[Unit]
Description=SBE1V1K Wi-Fi, LED and hardware initialization
After=systemd-udev-trigger.service systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbe1v1k-hardware
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

chroot "$ROOTFS" /usr/bin/qemu-aarch64-static /bin/bash -euxo pipefail <<'CHROOT'
export DEBIAN_FRONTEND=noninteractive
# A previous run of this script leaves /etc/resolv.conf as a symlink to
# /run/resolv.conf, which is where the *device* gets its nameservers at boot.
# Inside the chroot that path does not exist, so apt could not resolve anything
# and a rebuild failed with "Temporary failure resolving 'deb.debian.org'" —
# the script was only ever correct on a first, clean run. Plant a real file for
# the duration of the build; the final resolv.conf is set up further down.
rm -f /etc/resolv.conf
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
apt-get update
apt-get install -y --no-install-recommends \
    systemd systemd-sysv systemd-timesyncd udev dbus \
    openssh-server sudo ca-certificates curl wget nginx \
    iproute2 iputils-ping ethtool net-tools \
    kmod pciutils usbutils \
    nftables bridge-utils vlan iw wpasupplicant hostapd python3 \
    python3-cryptography dnsmasq \
    locales tzdata less vim-tiny \
    docker.io docker-compose iptables
# Suricata moved to Bookworm Backports.  Select that suite explicitly so its
# matching libhtp2 is installed too; otherwise apt prefers Bookworm's older
# library and rejects the DPI engine as an unsatisfied dependency.
apt-get install -y -t bookworm-backports --no-install-recommends suricata

# Pin iptables to the nftables backend, explicitly and in manual mode.
#
# This gateway programs netfilter through nftables. Third-party software does
# not: ShellCrash, and most transparent proxies, drive iptables. If iptables is
# wired to the LEGACY ip_tables engine, those rules land in a second, separate
# netfilter backend running alongside the nft one -- two engines filtering the
# same packets with no defined interaction. Measured on hardware in exactly
# that state: `iptables v1.8.9 (legacy)` with ip_tables mangle/nat/filter live,
# while sbegw's rules sat in nftables, and a transparent proxy that works on
# ordinary routers did not work here.
#
# Every normal router has one namespace -- OpenWrt is nft-only, and Debian's
# own alternatives system rates iptables-nft as "Best". Something on the device
# had nonetheless selected legacy in manual mode, so relying on the default is
# not enough; set it, and fail the build if the tools disagree afterwards.
for _alt in iptables ip6tables arptables ebtables; do
    if update-alternatives --list "$_alt" >/dev/null 2>&1; then
        update-alternatives --set "$_alt" "/usr/sbin/${_alt}-nft" || true
    fi
done
# Verify by reading the alternative link, NOT by running iptables. On the nft
# backend `iptables --version` opens a netfilter netlink socket, which is not
# available inside this qemu chroot -- it fails with "Failed to initialize nft:
# Protocol not supported" even when the alternative is set correctly, and an
# earlier version of this check aborted the build on that false negative.
for _alt in iptables ip6tables; do
    _tgt="$(readlink -f "/etc/alternatives/$_alt" 2>/dev/null || true)"
    # readlink -f resolves the whole alternatives chain to the implementation
    # binary, which for the nft backend is xtables-nft-multi -- NOT a name
    # ending in "-nft". Match on the backend token and reject legacy explicitly;
    # an earlier "*-nft" glob failed a build whose alternative was already right.
    case "$_tgt" in
        *legacy*) echo "ERROR: $_alt uses the legacy backend ($_tgt)" >&2; exit 1 ;;
        *nft*)    : ;;
        *) echo "ERROR: $_alt resolves to '$_tgt', which is neither nft nor legacy" >&2
           exit 1 ;;
    esac
done

# Pointing the CLI at nft is not sufficient on its own. Measured on hardware:
# after switching the alternatives, /proc/net/ip_tables_names still listed
# mangle, nat and filter, because the legacy kernel modules stay loaded with
# their tables registered and their hooks live. That leaves two netfilter
# engines filtering the same packets, which is the state a standard router is
# never in. Keep the legacy modules out so there is exactly one backend.
#
# Nothing here needs them: Docker and every other consumer go through
# /usr/sbin/iptables, which is now iptables-nft.
install -d /etc/modprobe.d
cat > /etc/modprobe.d/sbe1v1k-single-netfilter.conf <<'MODBLK'
# One netfilter backend only: nftables. The legacy ip_tables engine would
# otherwise register a second set of hooks alongside it.
blacklist ip_tables
blacklist ip6_tables
blacklist iptable_nat
blacklist iptable_mangle
blacklist iptable_filter
blacklist iptable_raw
blacklist ip6table_nat
blacklist ip6table_mangle
blacklist ip6table_filter
MODBLK
# Docker's prerequisites were checked against this kernel before adding it:
# cgroups v2 (the board mounts cgroup2fs), MEMCG, CGROUP_PIDS, NAMESPACES,
# NET_NS, PID_NS, VETH, BRIDGE, OVERLAY_FS, NF_NAT and BRIDGE_NETFILTER are all
# built in, and br_netfilter/overlay/veth/xt_conntrack/nf_nat/iptable_nat are
# all available as modules. iptables is named explicitly because Docker
# programs its NAT and port publishing through it and the image did not
# otherwise have it.
#
# The daemon keeps its images and containers under /var/lib/docker, which lands
# in the writable overlay's upper layer on rootfs_data (5.7 GB free), not in
# the read-only SquashFS.
# The package may recreate its stock default site. Keep only the SBE1V1K
# gateway console server on port 80 to avoid duplicate default_server entries.
rm -f /etc/nginx/sites-enabled/default
sed -i \
    -e 's#^error_log /var/log/nginx/error.log;#error_log /run/nginx/error.log;#' \
    -e 's#^[[:space:]]*access_log /var/log/nginx/access.log;#\taccess_log /run/nginx/access.log;#' \
    /etc/nginx/nginx.conf
cat > /etc/nginx/conf.d/00-sbe1v1k-temp.conf <<'EOF'
# The image root is read-only; keep nginx request/proxy scratch space in /run.
error_log /run/nginx/error.log;
access_log /run/nginx/access.log;
client_body_temp_path /run/nginx/body;
proxy_temp_path /run/nginx/proxy;
fastcgi_temp_path /run/nginx/fastcgi;
uwsgi_temp_path /run/nginx/uwsgi;
scgi_temp_path /run/nginx/scgi;
EOF
echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen
locale-gen
systemctl enable systemd-networkd ssh serial-getty@ttyMSM0.service
systemctl enable dnsmasq.service
systemctl enable sbe1v1k-port-config.service
systemctl enable sbe1v1k-art-init.service sbe1v1k-apply-macs.service
systemctl disable hostapd.service 2>/dev/null || true
systemctl disable ucgf-console.service 2>/dev/null || true
# Debian nginx fronts the local SBE1V1K portal on port 80.
systemctl enable nginx.service sbe1v1k-config-ui.service \
    wififw.service sbe1v1k-drivers.service sbe1v1k-hardware.service || true
if [[ -e /lib/systemd/system/systemd-resolved.service ]]; then
    systemctl enable systemd-resolved
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
else
    # Debian Bookworm may provide systemd-resolved as a separate package.
    # Keep the image buildable without it; DHCP can supply /etc/resolv.conf.
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi
passwd -l root
rm -f /usr/bin/qemu-aarch64-static
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/*
CHROOT

chroot "$ROOTFS" depmod -a "$KERNEL_RELEASE" 2>/dev/null || true

# -e follows symlinks, and /sbin/init is an absolute symlink *into the image*
# (install-gateway.sh points it at /usr/lib/sbegw/overlay-init for the writable
# root). Resolved against the build host that target does not exist, so a
# perfectly good rootfs failed this check. Accept a dangling symlink; what
# matters is that the entry exists inside the image.
for required in /etc/debian_version /etc/passwd /sbin/init /usr/bin/apt; do
    [[ -e "$ROOTFS$required" || -L "$ROOTFS$required" ]] ||
        die "Debian bootstrap incomplete: missing $required"
done

# The chroot above runs `passwd -l root`, which leaves "!" in front of the hash.
# This step used to be conditional on ROOT_PASSWORD being set, so a build without
# it shipped a LOCKED root account: sshd rejects every password and the serial
# console rejects the login, leaving no way into the device at all. Always set a
# password, and default it rather than produce an unreachable image.
ROOT_PASSWORD="${ROOT_PASSWORD:-password}"
printf 'root:%s\n' "$ROOT_PASSWORD" | chroot "$ROOTFS" chpasswd
chroot "$ROOTFS" passwd -u root >/dev/null
if [[ "$ROOT_PASSWORD" == "password" ]]; then
    echo "[!] root password is the default 'password'." >&2
    echo "[!] Rebuild with ROOT_PASSWORD=... to change it, or run passwd on the device." >&2
fi

# Prove it took. A locked ("!") or disabled ("*") hash means no console and no
# SSH; an empty field means a passwordless root, which sshd refuses too.
root_hash="$(chroot "$ROOTFS" getent shadow root | cut -d: -f2)"
case "$root_hash" in
    "")   die "root has an empty password field; the image would be unreachable" ;;
    '!'*) die "root is still locked ($root_hash); the image would be unreachable" ;;
    '*'*) die "root login is disabled ($root_hash); the image would be unreachable" ;;
esac

rm -f "$OUT"
truncate -s "$SIZE" "$OUT"
mkfs.ext4 -L debian-rootfs "$OUT" >/dev/null
MNT="$(mktemp -d /tmp/sbe1v1k-debian.XXXXXX)"
cleanup() { mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true; rmdir "$MNT"; }
trap cleanup EXIT
mount -o loop "$OUT" "$MNT"
tar -C "$ROOTFS" -cf - . | tar -C "$MNT" -xf -
sync
umount "$MNT"
echo "rootfs: $ROOTFS"
echo "image : $OUT ($(du -h "$OUT" | cut -f1))"
echo "The image is an ext4 filesystem; do not flash it until its target GPT partition is confirmed."
