#!/usr/bin/env bash
set -euo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_TREE="${KERNEL_TREE:-$WS/../qsdk14-work-ucgf/qsdk/qca/src/linux-6.6}"
DTS="${DTS:-$WS/../uinif_u7pro_serious_fw/ipq9574-sbe1v1k.dts}"
OUT="${OUT:-$WS/ipq9574-sbe1v1k.dtb}"
TMP="$(mktemp --suffix=.dts /tmp/sbe1v1k.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

[[ -f "$DTS" ]] || { echo "ERROR: missing DTS: $DTS" >&2; exit 1; }
[[ -d "$KERNEL_TREE/arch/arm64/boot/dts/qcom" ]] || {
    echo "ERROR: kernel DTS include tree not found: $KERNEL_TREE" >&2; exit 1;
}

cpp -nostdinc -undef -x assembler-with-cpp \
    -I "$KERNEL_TREE/arch/arm64/boot/dts/qcom" \
    -I "$KERNEL_TREE/include" -I "$KERNEL_TREE/include/uapi" \
    "$DTS" "$TMP"
dtc -I dts -O dtb -o "$OUT" "$TMP"
echo "$OUT"
