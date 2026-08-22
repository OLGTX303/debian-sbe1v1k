#!/usr/bin/env python3
"""Generate synthetic ART / U-Boot-env images matching the SBE1V1K layout.

Deliberately synthetic: a real dump carries the unit's serial, factory Wi-Fi
passphrase and WPS PIN, and none of that belongs in a source tree. The structure
(offsets, slot size, ath12k caldata header, env CRC) is identical to the real
partitions, so the parser is exercised exactly the same way.

To check the parser against a genuine dump instead, point the tests at one:
    SBEGW_ART_IMAGE=/path/to/p20-0_ART.img python3 tests/smoke_art.py
"""
from __future__ import annotations

import binascii
import os
import sys

ART_SIZE = 0x100000
VENDOR_OFFSET = 0xF4000
SLOT = 0x40
BASE_MAC = bytes((0x02, 0x00, 0x5E, 0x00, 0x53, 0x10))   # documentation range
CALDATA = ((0x58800, 0x2D000), (0x8A800, 0x2D000), (0xBC800, 0x2D000))
CALDATA_MAGIC = bytes((0x01, 0x00, 0x04, 0x04))

VENDOR_VALUES = [
    "Demo Manufacturing Ltd.",   # 0 manufacturer
    "02005E",                    # 1 label OUI
    "SBE1V1K",                   # 2 model
    "REV:4",                     # 3 hardware revision
    "1",                         # 4 hardware variant
    "DEMOSN12AB34CD56",          # 5 serial (no digit runs that could
                                 # collide with the PIN below)
    "DemoSetup-5310",            # 6 factory SSID 2.4 GHz
    "demo-factory-key",          # 7 factory key 2.4 GHz
    "DemoSetup-5310",            # 8 factory SSID 5 GHz
    "demo-factory-key",          # 9 factory key 5 GHz
    "DemoSetup-5310",            # 10 factory SSID 6 GHz
    "demo-factory-key",          # 11 factory key 6 GHz
    "13571357",                  # 12 WPS PIN (distinct substring)
    "840",                       # 13 region (ISO 3166-1 numeric)
]

ENV_VARS = {
    "baudrate": "115200",
    "bootargs": "console=ttyMSM0,115200n8",
    "bootcmd": "aq_load_fw 0x0 && bootipq",
    "bootdelay": "2",
    "ethaddr": ":".join(f"{b:02x}" for b in BASE_MAC),
    "flash_type": "5",
    "machid": "8773001",
    "soc_version_major": "1",
    "soc_version_minor": "1",
}


def build_art() -> bytes:
    art = bytearray(b"\xff" * ART_SIZE)
    # Five consecutive MAC slots at offset 0, as the vendor programs them.
    art[0:6] = BASE_MAC
    for i in range(1, 5):
        art[i * 6:(i + 1) * 6] = BASE_MAC[:5] + bytes((BASE_MAC[5] + 1,))
    # Per-radio calibration blobs with the real header and varying content.
    for index, (offset, length) in enumerate(CALDATA, start=1):
        blob = bytearray(b"\x00" * length)
        blob[0:4] = CALDATA_MAGIC
        for j in range(0x40, 0x40 + 512 * index):
            blob[j] = (j * index) & 0xFF
        art[offset:offset + length] = blob
    # Factory identity block: NUL-terminated ASCII in 64-byte slots.
    for index, value in enumerate(VENDOR_VALUES):
        start = VENDOR_OFFSET + index * SLOT
        art[start:start + SLOT] = value.encode().ljust(SLOT, b"\x00")
    return bytes(art)


def build_env() -> bytes:
    payload = b"".join(f"{k}={v}".encode() + b"\x00"
                       for k, v in sorted(ENV_VARS.items()))
    body = payload + b"\x00"
    body = body.ljust(0x40000 - 4, b"\xff")
    crc = binascii.crc32(body) & 0xFFFFFFFF
    return crc.to_bytes(4, "little") + body


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "fixtures")
    os.makedirs(out, exist_ok=True)
    art_path = os.path.join(out, "art.img")
    env_path = os.path.join(out, "appsblenv.img")
    with open(art_path, "wb") as fh:
        fh.write(build_art())
    with open(env_path, "wb") as fh:
        fh.write(build_env())
    print(f"wrote {art_path} ({os.path.getsize(art_path)} bytes)")
    print(f"wrote {env_path} ({os.path.getsize(env_path)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
