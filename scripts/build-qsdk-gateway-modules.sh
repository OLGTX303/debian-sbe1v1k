#!/usr/bin/env bash
# Enable and build the QSDK kernel modules used by sbegw Smart Queues.
#
# The UCGF 5.4 image ships sch_cake, ifb, act_mirred and cls_matchall.  Those
# binaries cannot be copied into the Debian firmware because this project uses
# QSDK kernel 6.6.  Build matching modules from the supplied QSDK tree instead.
set -euo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
QSDK="${QSDK:-}"
if [[ -z "$QSDK" ]]; then
    for candidate in "$WS/../qsdk" "$WS/../qsdk14-work-ucgf/qsdk"; do
        [[ -f "$candidate/Makefile" && -f "$candidate/.config" ]] &&
            QSDK="$(cd "$candidate" && pwd)" && break
    done
fi
QSDK="${QSDK:-$WS/../qsdk}"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[*] $*"; }

[[ -f "$QSDK/Makefile" ]] || die "not a QSDK build tree: $QSDK"
[[ -f "$QSDK/.config" ]] || die "QSDK has no .config: configure the ipq95xx target first"

build_target="$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl"
kernel_target="$build_target/linux-ipq95xx_generic"
toolchain_target="$build_target/toolchain"
for output in "$build_target" "$kernel_target" "$toolchain_target"; do
    if [[ "${CONFIGURE_ONLY:-0}" != "1" && -d "$output" && ! -w "$output" ]]; then
        die "QSDK build output is not writable: $output (fix ownership from an earlier sudo build, then retry)"
    fi
done

note "enabling QSDK 6.6 Smart Queue modules"
(
    cd "$QSDK"
    # This QSDK keeps its kconfig utility in scripts/config/ (a directory), not
    # at scripts/config like newer OpenWrt.  Replace the three package symbols
    # directly, then let `make defconfig` resolve every dependency.
    # kmod-qca-nss-ppe-vlan-mgr / -bridge-mgr teach PPE about Linux bridges and
    # their VLANs. Without them ECM accelerates a flow that PPE cannot forward:
    # measured on hardware, a LAN client's traffic reached ESTABLISHED in
    # conntrack, nftables dropped nothing (drop counter 0), and the client read
    # 0 bytes. The vendor image loads both (51-qca-nss-ppe-vlan-mgr,
    # 52-qca-nss-ppe-bridge-mgr) and its acceleration works; our build had
    # neither compiled at all. bridge-mgr depends on vlan-mgr, and this gateway
    # always uses a VLAN-filtering bridge, so both are required.
    for symbol in PACKAGE_kmod-sched-core PACKAGE_kmod-sched-cake PACKAGE_kmod-ifb \
                  PACKAGE_kmod-qca-nss-ppe-vlan-mgr \
                  PACKAGE_kmod-qca-nss-ppe-bridge-mgr; do
        sed -i -e "/^CONFIG_${symbol}=/d" -e "/^# CONFIG_${symbol} is not set$/d" .config
        printf 'CONFIG_%s=y\n' "$symbol" >> .config
    done
    # Vendor makefiles dump their generated make database to stderr.  Keep the
    # normal path quiet; `set -e` still stops here if dependency resolution
    # returns a failure.
    make defconfig >/dev/null 2>&1

    if [[ "${CONFIGURE_ONLY:-0}" == "1" ]]; then
        exit 0
    fi

    jobs="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"
    # Package selection changes the generated kernel configuration.  Refresh
    # the kernel first so package/kernel/linux does not try to package modules
    # from a stale build (and then report sch_hfsc/sch_cake as missing).
    make -j"$jobs" target/linux/compile
    make -j"$jobs" package/kernel/linux/compile
    # The PPE managers live in a feed package, so kernel/linux does not build
    # them. Non-fatal: a tree without the nss feed still gets Smart Queues.
    if [[ -d "$QSDK/qca/feeds/nss/clients/qca-nss-ae-clients" ]]; then
        make -j"$jobs" package/qca/feeds/nss/clients/qca-nss-ae-clients/compile \
            || make -j"$jobs" package/feeds/nss/qca-nss-ae-clients/compile \
            || echo "[!] qca-nss-ae-clients failed to build; PPE offload stays unusable" >&2
    else
        echo "[!] qca-nss-ae-clients not in this tree; PPE offload stays unusable" >&2
    fi
)

if [[ "${CONFIGURE_ONLY:-0}" == "1" ]]; then
    note "configuration updated; build package/kernel/linux before assembling the rootfs"
    exit 0
fi

module_root="$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl/root-ipq95xx/lib/modules"
kernel_release_dir="$module_root/6.6.116+"
package_root="$kernel_target/packages/ipkg-aarch64_cortex-a73_neon-vfpv4"
mkdir -p "$kernel_release_dir"
for package in kmod-sched-core kmod-sched-cake kmod-ifb \
               kmod-qca-nss-ppe-vlan-mgr kmod-qca-nss-ppe-bridge-mgr; do
    # The PPE managers are optional: a tree without the nss feed still yields a
    # working image, just without hardware offload. Skip rather than die.
    case "$package" in
        kmod-qca-nss-ppe-*)
            # These come from a feed package, whose ipkg payload lands under its
            # own build dir rather than the kernel target's packages/ tree. Its
            # `install` target also fails on this QSDK at the ipkg-packaging
            # step, so take the .ko straight from the payload dir.
            _ae="$(echo "$QSDK/build_dir/target-aarch64_cortex-a73+neon-vfpv4_musl"/linux-ipq95xx_generic/qca-nss-ae-clients-*/ipkg-aarch64_cortex-a73_neon-vfpv4)"
            if [[ -d "$_ae/$package/lib/modules" ]]; then
                package_modules="$_ae/$package/lib/modules"
                find "$package_modules" -name '*.ko' -exec \
                    cp -a {} "$kernel_release_dir/" \; 
                note "installed $package from the feed payload dir"
                continue
            fi
            echo "[!] $package not built; hardware offload unavailable" >&2
            continue
            ;;
    esac
    package_modules="$package_root/$package/lib/modules"
    [[ -d "$package_modules" ]] || die "$package was built but its module payload is missing: $package_modules"
    while IFS= read -r -d '' source_module; do
        install -m 0644 "$source_module" "$kernel_release_dir/$(basename "$source_module")"
    done < <(find "$package_modules" -type f -name '*.ko*' -print0)
done
for module in sch_cake ifb act_mirred cls_matchall; do
    find "$module_root" -type f -name "$module.ko*" -print -quit 2>/dev/null |
        grep -q . || die "$module was not installed under $module_root"
done
note "Smart Queue modules are ready for scripts/build-debian-rootfs.sh"
