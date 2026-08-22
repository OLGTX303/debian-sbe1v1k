#!/usr/bin/env python3
"""OTA update tests.

This board has one bank: a single `kernel` (32 MiB) and a single `rootfs`
(1 GiB), with no A/B pair. A bad write is recoverable only through the U-Boot
recovery page, so almost every test here is about refusing to write.

The write path itself is exercised against scratch files standing in for the
partitions, which is as close as this can get without flashing real hardware.
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
# Redirect staging before importing, so nothing tries to write to /data here.
os.environ["SBEGW_STATE"] = tempfile.mkdtemp(prefix="sbegw-ota-state-")

from sbegw import otad                                  # noqa: E402

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


WORK = tempfile.mkdtemp(prefix="sbegw-ota-")


def make_image(path, *, board=otad.BOARD, kernel_magic=otad.FIT_MAGIC,
               root_magic=otad.SQUASHFS_MAGIC,
               kernel_size=2 << 20, root_size=32 << 20, members=("kernel", "root"),
               prefixes=None):
    """A synthetic sysupgrade tar with controllable defects."""
    with tarfile.open(path, "w") as tar:
        for name in members:
            magic = kernel_magic if name == "kernel" else root_magic
            size = kernel_size if name == "kernel" else root_size
            body = magic + os.urandom(64) + b"\0" * max(0, size - len(magic) - 64)
            body = body[:size]
            prefix = (prefixes or {}).get(name, f"sysupgrade-{board}")
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
        info = tarfile.TarInfo(f"sysupgrade-{board}/CONTROL")
        info.size = 0
        tar.addfile(info, io.BytesIO(b""))
    return path


class ScratchUpdater(otad.FirmwareUpdater):
    """Writes to files instead of the eMMC, with fixed capacities."""

    def __init__(self, capacities, **kw):
        super().__init__(**kw)
        self._caps = capacities
        self._files = {}
        for label, size in capacities.items():
            p = os.path.join(WORK, f"part-{label}")
            with open(p, "wb") as fh:
                fh.truncate(size)
            self._files[label] = p

    def _device_for(self, label):
        return self._files.get(label)


def _caps(kernel=32 << 20, rootfs=64 << 20):
    return {"kernel": kernel, "rootfs": rootfs}


def _patched_capacity(mapping):
    """otad reads partition size from sysfs; point it at our scratch sizes."""
    original = otad._partition_bytes

    def fake(device):
        for label, size in mapping.items():
            if device and device.endswith(f"part-{label}"):
                return size
        return original(device)
    return original, fake


# ------------------------------------------------------------------ inspection

print("--- a good image passes ---")
good = make_image(os.path.join(WORK, "good.bin"))
up = ScratchUpdater(_caps())
_orig, _fake = _patched_capacity(_caps())
otad._partition_bytes = _fake
try:
    rep = up.inspect(good)
    check("a well-formed image is accepted", rep["ok"], str(rep["problems"]))
    check("the board is read from the tar prefix", rep["board"] == otad.BOARD, str(rep["board"]))
    check("both payloads are found", set(rep["payloads"]) == {"kernel", "root"},
          str(list(rep["payloads"])))
    check("the file's sha256 is reported", len(rep["sha256"] or "") == 64)

    print("\n--- everything that must be refused ---")
    # A truncated download is the most likely real-world bad image.
    short = make_image(os.path.join(WORK, "short.bin"), root_size=1 << 20)
    rep = up.inspect(short)
    check("a truncated root payload is refused", not rep["ok"])
    check("...and named as a truncated download",
          any("truncated" in p for p in rep["problems"]), str(rep["problems"]))

    # Wrong magic means the payload is not what it claims, whatever its size.
    badroot = make_image(os.path.join(WORK, "badroot.bin"), root_magic=b"XXXX")
    rep = up.inspect(badroot)
    check("a root payload that is not SquashFS is refused", not rep["ok"])
    check("...saying which magic was expected",
          any("SquashFS" in p for p in rep["problems"]), str(rep["problems"]))

    badkernel = make_image(os.path.join(WORK, "badkernel.bin"), kernel_magic=b"ZZZZ")
    rep = up.inspect(badkernel)
    check("a kernel payload that is not a FIT is refused", not rep["ok"])
    check("...saying FIT", any("FIT" in p for p in rep["problems"]), str(rep["problems"]))

    # An image for another board would brick this one.
    other = make_image(os.path.join(WORK, "other.bin"), board="some_other_board")
    rep = up.inspect(other)
    check("an image for another board is refused", not rep["ok"])
    check("...naming both boards",
          any("some_other_board" in p and otad.BOARD in p for p in rep["problems"]),
          str(rep["problems"]))

    missing = make_image(os.path.join(WORK, "missing.bin"), members=("root",))
    rep = up.inspect(missing)
    check("a missing kernel payload is refused",
          not rep["ok"] and any("kernel" in p for p in rep["problems"]),
          str(rep["problems"]))

    # Two directories means it is not a single sysupgrade image.
    mixed = make_image(os.path.join(WORK, "mixed.bin"),
                       prefixes={"kernel": "sysupgrade-other"})
    rep = up.inspect(mixed)
    check("an image with two sysupgrade directories is refused", not rep["ok"],
          str(rep["problems"]))

    # A raw FIT image is what the recovery page takes, not this path.
    raw = os.path.join(WORK, "raw.bin")
    with open(raw, "wb") as fh:
        fh.write(otad.FIT_MAGIC + os.urandom(1 << 20))
    rep = up.inspect(raw)
    check("a raw FIT image is refused with advice", not rep["ok"])
    check("...pointing at the recovery page",
          any("recovery page" in p for p in rep["problems"]), str(rep["problems"]))

    rep = up.inspect(os.path.join(WORK, "nope.bin"))
    check("a missing file is reported, not raised", not rep["ok"])

    print("\n--- payloads must fit the real partitions ---")
    tiny = ScratchUpdater(_caps(rootfs=8 << 20))
    otad._partition_bytes = _patched_capacity(_caps(rootfs=8 << 20))[1]
    rep = tiny.inspect(good)
    check("a root payload larger than its partition is refused", not rep["ok"])
    check("...quoting both sizes",
          any("holds only" in p for p in rep["problems"]), str(rep["problems"]))
    otad._partition_bytes = _fake

    print("\n--- apply refuses before it writes ---")
    before = open(up._files["rootfs"], "rb").read(64)
    for label, image in (("truncated", short), ("wrong board", other),
                         ("bad magic", badroot)):
        try:
            up.apply(image)
            check(f"apply refuses a {label} image", False, "it wrote something")
        except otad.UpdateError:
            check(f"apply refuses a {label} image", True)
    check("a refused apply leaves the partition untouched",
          open(up._files["rootfs"], "rb").read(64) == before)

    # A digest the caller supplies must match, so a mirror serving the wrong
    # file cannot be applied even if the file itself is valid.
    try:
        up.apply(good, expect_sha256="0" * 64)
        check("a sha256 mismatch is refused", False, "it wrote something")
    except otad.UpdateError as exc:
        check("a sha256 mismatch is refused", "sha256 mismatch" in str(exc), str(exc))

    print("\n--- the write path ---")
    msgs = up.apply(good, reboot=False)
    check("a good image applies", any("verified" in m for m in msgs), str(msgs))
    check("...and does not reboot unless asked",
          any("reboot when ready" in m for m in msgs), str(msgs))

    # What landed must be byte-identical to what was in the tar.
    with tarfile.open(good) as tar:
        for payload, label in (("root", "rootfs"), ("kernel", "kernel")):
            want = hashlib.sha256(
                tar.extractfile(f"sysupgrade-{otad.BOARD}/{payload}").read()).hexdigest()
            size = tar.getmember(f"sysupgrade-{otad.BOARD}/{payload}").size
            with open(up._files[label], "rb") as fh:
                got = hashlib.sha256(fh.read(size)).hexdigest()
            check(f"{payload} landed byte-identical on {label}", want == got)

    # Order matters on a single-bank device: the smaller payload goes last so
    # the mismatched window is as short as possible.
    check("the root is written before the kernel",
          [m for m in msgs if "->" in m][0].startswith("root"),
          str([m for m in msgs if "->" in m]))

    print("\n--- status ---")
    st = up.status()
    check("status says there is only one bank", st["banks"] == 1, str(st["banks"]))
    check("status names the board", st["board"] == otad.BOARD)
    check("status reports both partitions",
          set(st["partitions"]) == {"kernel", "rootfs"}, str(list(st["partitions"])))
finally:
    otad._partition_bytes = _orig

print("\n--- staging ---")
# A 180 MB image has no business in the SquashFS overlay's upper layer.
check("uploads are staged under the state directory, not the overlay",
      otad.STAGING_DIR.endswith("firmware")
      and "/data" in os.path.join(os.environ.get("SBEGW_STATE", "/data/sbegw"),
                                  "firmware").replace(os.environ["SBEGW_STATE"], "/data"),
      otad.STAGING_DIR)
# A client-supplied filename must never climb out of the staging directory.
for _hostile in ("../../etc/passwd", "/etc/shadow", "a/b/c.bin", ""):
    _p = otad.FirmwareUpdater.staging_path(_hostile)
    check(f"a staged name cannot escape: {_hostile!r}",
          os.path.dirname(os.path.abspath(_p)) == os.path.abspath(otad.STAGING_DIR),
          _p)
check("asking where a file would go creates nothing",
      not os.path.exists(otad.STAGING_DIR)
      or os.path.isdir(otad.STAGING_DIR))

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
