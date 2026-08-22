#!/usr/bin/env python3
"""ART / board identity reader tests.

Runs against the synthetic fixtures by default. To check the parser against a
genuine dump (which must never be committed — it holds the serial, factory Wi-Fi
passphrase and WPS PIN):

    SBEGW_ART_IMAGE=/path/to/p20-0_ART.img \
    SBEGW_ENV_IMAGE=/path/to/p17-0_APPSBLENV.img python3 tests/smoke_art.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbegw.adapters import art  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
ART_IMAGE = os.environ.get("SBEGW_ART_IMAGE") or os.path.join(FIXTURES, "art.img")
ENV_IMAGE = os.environ.get("SBEGW_ENV_IMAGE") or os.path.join(FIXTURES, "appsblenv.img")
REAL = bool(os.environ.get("SBEGW_ART_IMAGE"))

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


if not os.path.exists(ART_IMAGE):
    print("generating fixtures…")
    subprocess.run([sys.executable, os.path.join(HERE, "make_fixtures.py")],
                   check=True, capture_output=True)

# Redirect the reader at the images instead of live partitions.
art._partition_size = lambda dev: os.path.getsize(dev)
art.art_device = lambda: ART_IMAGE
art._partition_by_name = (
    lambda names: ENV_IMAGE if names is art.UBOOT_ENV_PARTNAMES else ART_IMAGE)

print(f"--- source: {'REAL DUMP' if REAL else 'synthetic fixtures'} ---\n")

# ------------------------------------------------------------------- bounds

print("--- bounds checking ---")
size = os.path.getsize(ART_IMAGE)
check("a read inside the partition succeeds",
      art.read_region(ART_IMAGE, 0, 6) is not None)
check("a read past the end is refused, not truncated",
      art.read_region(ART_IMAGE, size - 4, 64) is None)
check("the old out-of-range caldata read is refused",
      art.read_region(ART_IMAGE, 0x1100000, 0x800000) is None,
      "0x1100000+0x800000 in a 0x100000 partition")

# ---------------------------------------------------------------------- MACs

print("\n--- MAC addresses ---")
base = art.base_mac(ART_IMAGE)
check("base MAC reads from offset 0", base is not None and base.count(":") == 5, str(base))
cells = art.mac_cells(ART_IMAGE)
check("five MAC slots are read", len(cells) == 5, str(cells))
macs = art.derived_macs(ART_IMAGE)
check("WAN uses nvmem cell 0 (the base itself)",
      macs["ports"]["wan"]["mac"] == base, str(macs["ports"]["wan"]))
check("LAN uses nvmem cell 1", macs["ports"]["lan"]["cell"] == 1)
check("radios use negative cells -1/-2/-3",
      [macs["radios"][f"pcie{n}"]["cell"] for n in (1, 2, 3)] == [-1, -2, -3])
check("radio MACs step down from the base",
      art.mac_at_index(base, -1) == macs["radios"]["pcie1"]["mac"])

# --------------------------------------------------------------- calibration

print("\n--- calibration regions ---")
cal = art.caldata_status(ART_IMAGE)
check("three calibration regions are described", len(cal) == 3)
check("all three sit inside the partition", all(c["present"] for c in cal),
      str([c["reason"] for c in cal if not c["present"]]))
check("all three carry the ath12k header", all(c["valid_header"] for c in cal),
      str([c["reason"] for c in cal if not c["valid_header"]]))
check("none is blank", all(c["blank"] is False for c in cal))
check("each region has a distinct digest",
      len({c["sha256"] for c in cal}) == 3, str([c["sha256"] for c in cal]))
check("firmware names match what ath12k requests",
      [c["firmware_name"] for c in cal] == [
          f"ath12k/QCN9274/hw2.0/cal-pci-{n:04d}:01:00.0.bin" for n in (1, 2, 3)],
      str([c["firmware_name"] for c in cal]))

# ---------------------------------------------------------- extraction

print("\n--- extraction ---")
import tempfile  # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    result = art.extract_caldata(tmp)
    radios = {e["radio"] for e in result["written"]}
    check("all three radios are extracted", radios == {1, 2, 3}, str(radios))
    check("no extraction errors", not result["errors"], str(result["errors"]))
    names = sorted(os.path.basename(e["path"]) for e in result["written"])
    # The vendor hotplug script (11-ath12k-caldata) is authoritative: ath12k
    # requests cal-pci-<domain>:01:00.0.bin under ath12k/QCN9274/hw2.0. The
    # earlier caldata_<n>.bin guesses are gone.
    check("the exact names ath12k requests are written",
          names == ["cal-pci-0001:01:00.0.bin", "cal-pci-0002:01:00.0.bin",
                    "cal-pci-0003:01:00.0.bin"], str(names))
    check("they land in the directory ath12k searches",
          all(e["path"].endswith(
              f"ath12k/QCN9274/hw2.0/{os.path.basename(e['path'])}")
              for e in result["written"]))
    check("every blob is the full region size",
          all(e["bytes"] == 0x2D000 for e in result["written"]))
    check("everything lands in the ath12k search path",
          all("ath12k/QCN9274/hw2.0" in e["path"] for e in result["written"]))

# -------------------------------------------------------------- vendor block

print("\n--- vendor identity block ---")
block = art.vendor_block(ART_IMAGE)
check("vendor block is found at 0xf4000",
      block["present"] and block["offset"] == 0xF4000, str(block.get("reason")))
fields = block["fields"]
check("manufacturer is read", bool(fields.get("manufacturer")),
      str(fields.get("manufacturer")))
check("model is read", fields.get("model") == "SBE1V1K", str(fields.get("model")))
check("hardware revision is read", bool(fields.get("hardware_revision")),
      str(fields.get("hardware_revision")))
check("serial is read", bool(fields.get("serial")),
      fields.get("serial") if not REAL else "(withheld from output)")
check("region maps ISO numeric to alpha-2",
      fields.get("region") == "US" and fields.get("region_numeric") == "840",
      f"{fields.get('region')} / {fields.get('region_numeric')}")
check("factory SSIDs are read for all three bands",
      all(fields.get(f"factory_ssid_{b}") for b in ("2g", "5g", "6g")))

print("\n--- secret handling ---")
check("the plain vendor read omits the factory key",
      "factory_key_2g" not in fields and fields.get("factory_key_2g_set") is True)
check("the plain vendor read omits the WPS PIN",
      "wps_pin" not in fields and fields.get("wps_pin_set") is True)

identity = art.identity()
blob = json.dumps(identity)
secret = art.vendor_block(ART_IMAGE, include_secrets=True)["fields"]
check("identity() never contains the factory passphrase",
      secret["factory_key_2g"] not in blob)
check("identity() never contains the WPS PIN", secret["wps_pin"] not in blob)
check("identity() still reports that they are programmed",
      identity["factory_wifi"]["key_set"] is True
      and identity["factory_wifi"]["wps_pin_set"] is True)
check("the explicit reveal does return them",
      bool(secret.get("factory_key_2g")) and bool(secret.get("wps_pin")))

# ------------------------------------------------------------------- U-Boot

print("\n--- U-Boot environment ---")
env = art.uboot_env()
check("environment CRC32 validates", env["crc_ok"] is True, str(env["crc_ok"]))
check("variables are parsed", len(env["variables"]) >= 8,
      f"{len(env['variables'])} variables")
check("machid is present", bool(env["variables"].get("machid")),
      env["variables"].get("machid"))
check("U-Boot ethaddr matches the ART base MAC",
      env["variables"].get("ethaddr") == base,
      f"{env['variables'].get('ethaddr')} vs {base}")

# ----------------------------------------------------------------- identity

print("\n--- composite identity ---")
check("model prefers the ART factory block",
      identity["model"] == "SBE1V1K"
      and identity["model_source"] == "ART factory block", identity["model_source"])
check("serial is sourced from the ART factory block",
      "ART factory block" in (identity["serial_source"] or ""),
      identity["serial_source"])
check("label OUI and MAC-derived OUI are both reported",
      identity["oui"] is not None and identity["oui_from_base_mac"] is not None,
      f"{identity['oui']} / {identity['oui_from_base_mac']}")
check("OUI agreement is stated rather than assumed",
      identity["oui_matches_mac"] in (True, False),
      str(identity["oui_matches_mac"]))
check("ART calibration summary is reported",
      identity["art"]["radios_calibrated"] == 3
      and identity["art"]["radios_expected"] == 3)


print("\n--- caldata is written even with an unexpected header ---")
# The expected header was inferred, not documented, and the vendor's hotplug
# script validates nothing. A mismatch must not withhold the blob, or the radio
# silently falls back to coldboot calibration - the exact failure this prevents.
with tempfile.TemporaryDirectory() as tmp:
    real_magic = art.CALDATA_MAGIC
    art.CALDATA_MAGIC = b"\xde\xad\xbe\xef"
    try:
        result = art.extract_caldata(tmp)
    finally:
        art.CALDATA_MAGIC = real_magic
    check("all three blobs are still written on a header mismatch",
          {e["radio"] for e in result["written"]} == {1, 2, 3},
          str(result["written"]))
    check("the mismatch is reported as a warning",
          len(result["errors"]) == 3 and
          all("writing it anyway" in e for e in result["errors"]),
          str(result["errors"]))

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
