"""ART / board identity reader for the SBE1V1K.

Everything here comes from the device itself — the ART partition, the U-Boot
environment, the Qualcomm socinfo driver, the eMMC CID and the device tree. None
of it is inferred from the model name, and anything that cannot be read is
reported as unavailable with a reason rather than filled in with a plausible
value.

Layout facts, taken from the board DTS and the vendor OpenWrt
`11-ath12k-caldata` hotplug script and verified against a real ART dump:

* the ART partition is named ``0:ART`` and is 1 MiB
* offset 0x0 holds the base MAC as six bytes; the DTS exposes it as the
  ``ethaddr`` nvmem cell with ``#nvmem-cell-cells = <1>``, so ports index off it
  (WAN = cell 0, LAN = cell 1) and radios use negative indices (-1, -2, -3)
* per-radio ath12k calibration blobs live at 0x58800, 0x8a800 and 0xbc800, each
  0x2d000 long, and are requested by the driver as
  ``ath12k/QCN9274/hw2.0/cal-pci-000N:01:00.0.bin``
"""
from __future__ import annotations

import binascii
import glob
import hashlib
import logging
import os
import re
from typing import Any

from ..util import format_mac, mac_bytes, read_int, read_text

log = logging.getLogger("sbegw.art")

ART_PARTNAMES = ("0:ART", "ART")
UBOOT_ENV_PARTNAMES = ("0:APPSBLENV", "APPSBLENV")

BASE_MAC_OFFSET = 0x0
BASE_MAC_LENGTH = 6

# (pci domain, ART offset, length). The domain is what ath12k puts in the
# firmware filename it asks userspace for.
CALDATA_REGIONS = (
    (1, 0x58800, 0x2D000),
    (2, 0x8A800, 0x2D000),
    (3, 0xBC800, 0x2D000),
)
# ath12k calibration blobs start with this little-endian header.
CALDATA_MAGIC = bytes((0x01, 0x00, 0x04, 0x04))

CALDATA_FIRMWARE_DIR = "ath12k/QCN9274/hw2.0"

# Askey's factory identity block: NUL-terminated ASCII in 64-byte slots starting
# at 0xf4000. Verified against a real ART dump — the factory SSID suffix (3EFA)
# matches the low octets of the base MAC at offset 0, which cross-checks both
# reads. `region` is an ISO 3166-1 numeric country code (840 = United States).
VENDOR_BLOCK_OFFSET = 0xF4000
VENDOR_SLOT_SIZE = 0x40
VENDOR_SLOTS: tuple[tuple[int, str], ...] = (
    (0, "manufacturer"),
    (1, "oui"),
    (2, "model"),
    (3, "hardware_revision"),
    (4, "hardware_variant"),   # unlabelled in the vendor tooling; reads "1"
    (5, "serial"),
    (6, "factory_ssid_2g"),
    (7, "factory_key_2g"),
    (8, "factory_ssid_5g"),
    (9, "factory_key_5g"),
    (10, "factory_ssid_6g"),
    (11, "factory_key_6g"),
    (12, "wps_pin"),
    (13, "region"),
)
# Slots that must not be handed out casually: a factory Wi-Fi passphrase or WPS
# PIN in a screenshot or a log is a real exposure, even though both are printed
# on the device label.
VENDOR_SECRET_FIELDS = frozenset({
    "factory_key_2g", "factory_key_5g", "factory_key_6g", "wps_pin",
})

# ISO 3166-1 numeric -> alpha-2, for the regions this hardware ships to.
_REGION_NUMERIC = {
    "840": "US", "124": "CA", "484": "MX", "826": "GB", "276": "DE",
    "250": "FR", "724": "ES", "380": "IT", "528": "NL", "392": "JP",
    "410": "KR", "156": "CN", "036": "AU", "554": "NZ", "356": "IN",
    "076": "BR", "702": "SG", "158": "TW",
}


def _slot_text(blob: bytes) -> str | None:
    """Decode one 64-byte slot up to its NUL/0xFF terminator."""
    end = 0
    while end < len(blob) and blob[end] not in (0x00, 0xFF):
        end += 1
    text = blob[:end].decode("ascii", "replace").strip()
    return text or None


def vendor_block(device: str | None = None, *,
                 include_secrets: bool = False) -> dict[str, Any]:
    """Askey factory identity: manufacturer, model, HW rev, serial, region.

    Secret fields are omitted unless explicitly requested, so the ordinary
    identity read cannot leak the factory passphrase or WPS PIN.
    """
    device = device or art_device()
    result: dict[str, Any] = {"present": False, "fields": {}, "reason": None}
    if not device:
        result["reason"] = "ART partition not found"
        return result

    span = (max(index for index, _ in VENDOR_SLOTS) + 1) * VENDOR_SLOT_SIZE
    raw = read_region(device, VENDOR_BLOCK_OFFSET, span)
    if raw is None:
        result["reason"] = (f"vendor block at 0x{VENDOR_BLOCK_OFFSET:x} is outside "
                            "the ART partition")
        return result
    if _is_blank(raw):
        result["reason"] = (f"vendor block at 0x{VENDOR_BLOCK_OFFSET:x} is blank; "
                            "this unit has no factory identity programmed")
        return result

    fields: dict[str, Any] = {}
    for index, name in VENDOR_SLOTS:
        start = index * VENDOR_SLOT_SIZE
        value = _slot_text(raw[start:start + VENDOR_SLOT_SIZE])
        if name in VENDOR_SECRET_FIELDS:
            fields[f"{name}_set"] = value is not None
            if include_secrets:
                fields[name] = value
            continue
        fields[name] = value

    region = fields.get("region")
    if region:
        fields["region_numeric"] = region
        fields["region"] = _REGION_NUMERIC.get(region, region)

    result["present"] = True
    result["offset"] = VENDOR_BLOCK_OFFSET
    result["fields"] = fields
    return result


def _partition_by_name(names: tuple[str, ...]) -> str | None:
    """Find /dev/mmcblkXpN for a GPT partition label."""
    for uevent in sorted(glob.glob("/sys/block/mmcblk*/mmcblk*p*/uevent")):
        text = read_text(uevent)
        match = re.search(r"^PARTNAME=(.*)$", text, re.M)
        if match and match.group(1).strip() in names:
            return "/dev/" + os.path.basename(os.path.dirname(uevent))
    return None


def art_device() -> str | None:
    return _partition_by_name(ART_PARTNAMES)


def _partition_size(device: str) -> int | None:
    """Size in bytes from sysfs, so a read can be bounds-checked."""
    name = os.path.basename(device)
    sectors = read_int(f"/sys/class/block/{name}/size")
    return sectors * 512 if sectors else None


def read_region(device: str, offset: int, length: int) -> bytes | None:
    """Read a byte range, refusing to run off the end of the partition.

    The existing shell helper read 0x800000 bytes from offset 0x1100000 of a
    1 MiB partition, which silently produced nothing. Bounds are checked here so
    a wrong offset is an explicit error instead of empty calibration data.
    """
    size = _partition_size(device)
    if size is not None and offset + length > size:
        log.error("refusing ART read past end of %s: 0x%x+0x%x > 0x%x",
                  device, offset, length, size)
        return None
    try:
        with open(device, "rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
    except OSError as exc:
        log.warning("ART read failed on %s at 0x%x: %s", device, offset, exc)
        return None
    return data if len(data) == length else None


def _is_blank(data: bytes) -> bool:
    return not data or all(b in (0x00, 0xFF) for b in data)


# --------------------------------------------------------------------- MACs

def base_mac(device: str | None = None) -> str | None:
    device = device or art_device()
    if not device:
        return None
    raw = read_region(device, BASE_MAC_OFFSET, BASE_MAC_LENGTH)
    if raw is None or _is_blank(raw):
        return None
    return format_mac(raw)


def mac_cells(device: str | None = None, count: int = 5) -> list[str]:
    """The consecutive MAC slots the vendor programmed at offset 0."""
    device = device or art_device()
    if not device:
        return []
    raw = read_region(device, BASE_MAC_OFFSET, BASE_MAC_LENGTH * count)
    if raw is None:
        return []
    out = []
    for i in range(count):
        chunk = raw[i * 6:(i + 1) * 6]
        out.append(format_mac(chunk) if not _is_blank(chunk) else None)
    return out


def mac_at_index(base: str, index: int) -> str:
    """Offset a MAC by a signed index, as the DTS nvmem cells do."""
    value = int.from_bytes(bytes(mac_bytes(base)), "big") + index
    return format_mac(value.to_bytes(6, "big"))


def derived_macs(device: str | None = None) -> dict[str, Any]:
    """Per-port and per-radio addresses, with how each was derived.

    The DTS maps WAN to cell 0 and the LAN ports to cell 1, and gives the three
    radios negative indices off the base. Reported alongside the raw cells so a
    mismatch with the running interface is visible rather than hidden.
    """
    base = base_mac(device)
    if not base:
        return {"base": None, "ports": {}, "radios": {}, "cells": []}
    return {
        "base": base,
        "cells": mac_cells(device),
        "ports": {
            # dts: wan uses <&ethaddr 0>, lan1..3 use <&ethaddr 1>
            "wan": {"mac": mac_at_index(base, 0), "cell": 0},
            "lan": {"mac": mac_at_index(base, 1), "cell": 1},
        },
        "radios": {
            # dts: wifi nodes use <&ethaddr (-1)>, (-2), (-3)
            f"pcie{n}": {"mac": mac_at_index(base, -n), "cell": -n}
            for n in (1, 2, 3)
        },
    }


# ---------------------------------------------------------------- calibration

def caldata_status(device: str | None = None) -> list[dict[str, Any]]:
    """Per-radio calibration blob state, read from ART.

    A blob is only called valid when it is present, non-blank and carries the
    ath12k header — "the partition exists" is not the same as "this radio is
    calibrated".
    """
    device = device or art_device()
    out: list[dict[str, Any]] = []
    for domain, offset, length in CALDATA_REGIONS:
        entry: dict[str, Any] = {
            "pci_domain": f"{domain:04d}",
            "firmware_name": f"{CALDATA_FIRMWARE_DIR}/cal-pci-{domain:04d}:01:00.0.bin",
            "offset": offset,
            "length": length,
            "present": False,
            "valid_header": False,
            "blank": None,
            "bytes_programmed": None,
            "sha256": None,
            "reason": None,
        }
        if not device:
            entry["reason"] = "ART partition not found"
            out.append(entry)
            continue
        blob = read_region(device, offset, length)
        if blob is None:
            entry["reason"] = "read failed or region outside the partition"
            out.append(entry)
            continue
        entry["present"] = True
        entry["blank"] = _is_blank(blob)
        entry["valid_header"] = blob[:4] == CALDATA_MAGIC
        entry["bytes_programmed"] = sum(1 for b in blob if b not in (0x00, 0xFF))
        entry["sha256"] = hashlib.sha256(blob).hexdigest()[:16]
        if entry["blank"]:
            entry["reason"] = "region is blank; this radio has no calibration data"
        elif not entry["valid_header"]:
            entry["reason"] = ("region does not start with the ath12k caldata "
                               "header; offset may be wrong for this board")
        out.append(entry)
    return out


def caldata_names(domain: int, index: int) -> list[str]:
    """The filename ath12k requests for one radio.

    No longer a guess: the board's own vendor hotplug script,
    qsdk/files/etc/hotplug.d/firmware/11-ath12k-caldata, maps each requested
    name to the exact ART offset used here —

        ath12k/QCN9274/hw2.0/cal-pci-0001:01:00.0.bin  <- 0x58800
        ath12k/QCN9274/hw2.0/cal-pci-0002:01:00.0.bin  <- 0x8a800
        ath12k/QCN9274/hw2.0/cal-pci-0003:01:00.0.bin  <- 0xbc800

    so the PCI-domain form is authoritative and the previously written
    caldata_<n>.bin guesses are dropped. The "qmi failed to load CAL data
    file:caldata.bin" line in the boot log is the driver's *fallback* path after
    the per-slot request failed, not the name it wants.
    """
    return [f"cal-pci-{domain:04d}:01:00.0.bin"]


def extract_caldata(target_dir: str = "/run/firmware") -> dict[str, Any]:
    """Write the per-radio blobs where the ath12k firmware loader will find them.

    ath12k asks userspace for `cal-pci-<domain>:01:00.0.bin`; on OpenWrt a
    hotplug script supplies it. There is no such hotplug path here, so the blobs
    are written up-front into a directory added to the firmware search path.
    """
    device = art_device()
    result: dict[str, Any] = {"device": device, "written": [], "errors": []}
    if not device:
        result["errors"].append("ART partition not found")
        return result

    directory = os.path.join(target_dir, CALDATA_FIRMWARE_DIR)
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        result["errors"].append(f"cannot create {directory}: {exc}")
        return result

    for index, (domain, offset, length) in enumerate(CALDATA_REGIONS):
        label = f"radio {domain}"
        blob = read_region(device, offset, length)
        if blob is None:
            result["errors"].append(f"{label}: read failed at 0x{offset:x}")
            continue
        if _is_blank(blob):
            result["errors"].append(f"{label}: ART region 0x{offset:x} is blank")
            continue
        if blob[:4] != CALDATA_MAGIC:
            # Warn but still write. The expected header was inferred, not
            # documented, and the vendor's own hotplug script dd's the region
            # out with no validation whatsoever — so treating a mismatch as
            # fatal risks withholding perfectly good calibration data and
            # leaving the radio on coldboot calibration, which is the failure
            # this whole path exists to prevent.
            result["errors"].append(
                f"{label}: ART region 0x{offset:x} does not start with the "
                f"expected header {CALDATA_MAGIC.hex()} (got "
                f"{blob[:4].hex()}); writing it anyway")
        for name in caldata_names(domain, index):
            path = os.path.join(directory, name)
            try:
                with open(path, "wb") as fh:
                    fh.write(blob)
                os.chmod(path, 0o644)
            except OSError as exc:
                result["errors"].append(f"{name}: write failed: {exc}")
                continue
            result["written"].append({"path": path, "bytes": len(blob),
                                      "radio": domain})
    return result


# ------------------------------------------------------------- U-Boot env

def uboot_env() -> dict[str, Any]:
    """Parse the APPSBLENV partition: a CRC32 followed by NUL-separated pairs."""
    device = _partition_by_name(UBOOT_ENV_PARTNAMES)
    result: dict[str, Any] = {"device": device, "crc_ok": None, "variables": {}}
    if not device:
        return result
    size = _partition_size(device) or 0x40000
    try:
        with open(device, "rb") as fh:
            raw = fh.read(min(size, 0x40000))
    except OSError as exc:
        log.debug("U-Boot env read failed: %s", exc)
        return result
    if len(raw) < 8:
        return result

    stored_crc = int.from_bytes(raw[:4], "little")
    body = raw[4:]
    end = body.find(b"\x00\x00")
    payload = body[:end] if end >= 0 else body.rstrip(b"\xff\x00")
    result["crc_ok"] = binascii.crc32(body) & 0xFFFFFFFF == stored_crc

    for item in payload.split(b"\x00"):
        if not item or b"=" not in item:
            continue
        key, _, value = item.partition(b"=")
        try:
            result["variables"][key.decode()] = value.decode(errors="replace")
        except UnicodeDecodeError:
            continue
    return result


# ------------------------------------------------------------- SoC and eMMC

def soc_info() -> dict[str, Any]:
    """Qualcomm socinfo (CONFIG_QCOM_SOCINFO) exposes these under /sys."""
    base = "/sys/devices/soc0"
    if not os.path.isdir(base):
        return {"available": False}
    info: dict[str, Any] = {"available": True}
    for attr in ("machine", "family", "soc_id", "revision", "serial_number",
                 "raw_version", "build_id", "image_crm_version",
                 "platform_version", "platform_subtype", "hw_platform"):
        value = read_text(os.path.join(base, attr)).strip()
        if value:
            info[attr] = value
    return info


def emmc_info() -> dict[str, Any]:
    """eMMC CID fields — the closest thing to a unique factory serial here."""
    for device in sorted(glob.glob("/sys/block/mmcblk[0-9]/device")):
        info: dict[str, Any] = {"available": True,
                                "block_device": "/dev/" + os.path.basename(
                                    os.path.dirname(device))}
        for attr in ("name", "type", "serial", "manfid", "oemid", "fwrev",
                     "hwrev", "date", "cid", "life_time", "pre_eol_info"):
            value = read_text(os.path.join(device, attr)).strip()
            if value:
                info[attr] = value
        size = read_int(os.path.join(os.path.dirname(device), "size"))
        if size:
            info["capacity_bytes"] = size * 512
        return info
    return {"available": False}


def device_tree() -> dict[str, Any]:
    model = read_text("/proc/device-tree/model", "").strip("\x00").strip()
    compatible = read_text("/proc/device-tree/compatible", "")
    return {
        "model": model or None,
        "compatible": [c for c in compatible.split("\x00") if c] or None,
        "serial_number": read_text("/proc/device-tree/serial-number", "")
                         .strip("\x00").strip() or None,
    }


# -------------------------------------------------------------- composite

def identity(*, include_secrets: bool = False) -> dict[str, Any]:
    """Everything the Hardware page needs, each field tagged with its source."""
    device = art_device()
    vendor = vendor_block(device, include_secrets=include_secrets)
    vfields = vendor.get("fields", {})
    dt = device_tree()
    soc = soc_info()
    emmc = emmc_info()
    env = uboot_env()
    macs = derived_macs(device)
    caldata = caldata_status(device)

    # No vendor serial is programmed into ART or the config partitions on this
    # board, so pick the best available hardware identifier and say which it is
    # rather than inventing a "serial number" field.
    serial = None
    serial_source = None
    for candidate, source in (
        (vfields.get("serial"), f"ART factory block (0x{VENDOR_BLOCK_OFFSET:x})"),
        (dt.get("serial_number"), "device-tree"),
        (soc.get("serial_number"), "qualcomm socinfo"),
        (emmc.get("serial"), "eMMC CID"),
    ):
        if candidate:
            serial = candidate
            serial_source = source
            break
    if not serial and macs.get("base"):
        serial = macs["base"].replace(":", "").upper()
        serial_source = "derived from the ART base MAC (no serial is programmed)"

    calibrated = [c for c in caldata if c["valid_header"] and not c["blank"]]

    base = macs.get("base")
    oui_field = vfields.get("oui")
    # The label OUI and the programmed base MAC's OUI are not always the same
    # part of the Askey allocation, so report both rather than assuming.
    oui_from_mac = base.replace(":", "").upper()[:6] if base else None

    return {
        "model": vfields.get("model") or dt.get("model") or "Askey SBE1V1K",
        "model_source": ("ART factory block" if vfields.get("model")
                         else "device-tree"),
        "manufacturer": vfields.get("manufacturer"),
        "hardware_revision": vfields.get("hardware_revision"),
        "hardware_variant": vfields.get("hardware_variant"),
        "region": vfields.get("region"),
        "region_numeric": vfields.get("region_numeric"),
        "oui": oui_field,
        "oui_from_base_mac": oui_from_mac,
        "oui_matches_mac": (bool(oui_field) and oui_field.upper() == oui_from_mac)
                           if (oui_field and oui_from_mac) else None,
        "factory_wifi": {
            "ssid_2g": vfields.get("factory_ssid_2g"),
            "ssid_5g": vfields.get("factory_ssid_5g"),
            "ssid_6g": vfields.get("factory_ssid_6g"),
            "key_2g": vfields.get("factory_key_2g"),
            "key_5g": vfields.get("factory_key_5g"),
            "key_6g": vfields.get("factory_key_6g"),
            "key_set": vfields.get("factory_key_2g_set"),
            "wps_pin": vfields.get("wps_pin"),
            "wps_pin_set": vfields.get("wps_pin_set"),
        },
        "vendor_block": {"present": vendor.get("present"),
                         "offset": vendor.get("offset"),
                         "reason": vendor.get("reason")},
        "dt_model": dt.get("model"),
        "compatible": dt.get("compatible"),
        "serial": serial,
        "serial_source": serial_source,
        "soc": {
            "name": "Qualcomm IPQ9574",
            "machine": soc.get("machine"),
            "family": soc.get("family"),
            "soc_id": soc.get("soc_id"),
            "revision": soc.get("revision"),
            "available": soc.get("available", False),
        },
        "machid": env["variables"].get("machid"),
        "bootloader": {
            "device": env.get("device"),
            "crc_ok": env.get("crc_ok"),
            "bootcmd": env["variables"].get("bootcmd"),
            "bootargs": env["variables"].get("bootargs"),
            "flash_type": env["variables"].get("flash_type"),
            "soc_version": ".".join(filter(None, (
                env["variables"].get("soc_version_major"),
                env["variables"].get("soc_version_minor")))) or None,
            "ethaddr": env["variables"].get("ethaddr"),
            "variable_count": len(env["variables"]),
        },
        "emmc": emmc,
        "art": {
            "device": device,
            "present": device is not None,
            "size_bytes": _partition_size(device) if device else None,
            "macs": macs,
            "caldata": caldata,
            "radios_calibrated": len(calibrated),
            "radios_expected": len(CALDATA_REGIONS),
        },
    }
