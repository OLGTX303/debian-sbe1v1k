"""otad — over-the-air firmware update.

This board has ONE bank: a single `kernel` partition (32 MiB) and a single
`rootfs` (1 GiB). There is no A/B pair to fall back to, so a bad or truncated
write leaves the device recoverable only through the U-Boot recovery page. That
single fact shapes everything here:

  * Nothing is written until the whole image has been validated — tar layout,
    both payload magics, both payload sizes against the real partitions, and
    the board name in the sysupgrade metadata.
  * Every write is read back and hashed before the next one starts. If the
    read-back disagrees, the update stops and says so rather than rebooting
    into a half-written system.
  * The root filesystem is written first and the kernel second. Both orders
    leave a mismatched pair if the second write fails, but the kernel is 32 MiB
    against the root's ~170 MiB, so writing it last makes the window as short
    as it can be.
  * A reboot is never automatic. The caller asks for it, after being told the
    verification passed.

Layout of a sysupgrade image, which is what the vendor recovery page also
takes:

    sysupgrade-askey_sbe1v1k/CONTROL
    sysupgrade-askey_sbe1v1k/kernel      FIT image  -> PARTLABEL=kernel
    sysupgrade-askey_sbe1v1k/root        SquashFS   -> PARTLABEL=rootfs
"""
from __future__ import annotations

import glob
import hashlib
import logging
import os
import subprocess
import tarfile
from typing import Any

log = logging.getLogger("sbegw.otad")

# u-boot FIT ("device tree blob") and SquashFS v4, little endian.
FIT_MAGIC = b"\xd0\x0d\xfe\xed"
SQUASHFS_MAGIC = b"hsqs"

# A payload smaller than this is a truncated download, not a firmware image.
MIN_KERNEL_BYTES = 1 << 20          # 1 MiB
MIN_ROOTFS_BYTES = 16 << 20         # 16 MiB

BOARD = "askey_sbe1v1k"
# Uploads land on the rootfs_data ext4, not in the SquashFS overlay's upper
# layer: a ~180 MB image has no business there. SBEGW_STATE is honoured so the
# tests do not have to write to /data on a build host.
STAGING_DIR = os.path.join(
    os.environ.get("SBEGW_STATE", "/data/sbegw"), "firmware")

# 1 MiB blocks: large enough that the copy is bound by the eMMC rather than by
# syscall overhead, small enough to report progress usefully.
BLOCK = 1 << 20


class UpdateError(Exception):
    """Refused or failed. The message is meant to be shown to the operator."""


def _partition(label: str) -> str | None:
    """Resolve a GPT partition name to its device, without udev."""
    for uevent in glob.glob("/sys/block/mmcblk*/mmcblk*p*/uevent"):
        try:
            with open(uevent) as fh:
                names = [l[len("PARTNAME="):].strip()
                         for l in fh if l.startswith("PARTNAME=")]
        except OSError:
            continue
        if any(n == label or n == f"0:{label}" for n in names):
            return "/dev/" + os.path.basename(os.path.dirname(uevent))
    return None


def _partition_bytes(device: str) -> int:
    name = os.path.basename(device)
    for path in glob.glob(f"/sys/block/mmcblk*/{name}/size"):
        try:
            with open(path) as fh:
                return int(fh.read().strip()) * 512
        except (OSError, ValueError):
            pass
    return 0


class FirmwareUpdater:
    """Validates and applies a sysupgrade image."""

    # Overridable so tests can point at scratch files instead of the eMMC.
    TARGETS = {"root": "rootfs", "kernel": "kernel"}

    def __init__(self, events=None):
        self.events = events
        self._devices: dict[str, str] = {}

    # ------------------------------------------------------------- inspection

    def inspect(self, path: str) -> dict[str, Any]:
        """Everything checkable without writing anything.

        Returns a report with `ok` and `problems`; the caller decides. Never
        raises for a bad image — an unreadable file is a normal outcome here.
        """
        report: dict[str, Any] = {
            "path": path, "ok": False, "problems": [], "payloads": {},
            "sha256": None, "board": None, "size": None,
        }
        if not os.path.isfile(path):
            report["problems"].append(f"{path} is not a file")
            return report

        report["size"] = os.path.getsize(path)
        report["sha256"] = self._sha256_file(path)

        try:
            with tarfile.open(path) as tar:
                members = {m.name: m for m in tar.getmembers()}
        except (tarfile.TarError, OSError) as exc:
            report["problems"].append(
                f"not a readable sysupgrade tar: {exc}. A FIT-based raw image "
                f"cannot be applied this way; use the recovery page.")
            return report

        prefixes = {n.split("/", 1)[0] for n in members if "/" in n}
        if len(prefixes) != 1:
            report["problems"].append(
                f"expected exactly one sysupgrade-* directory, found {sorted(prefixes)}")
            return report
        prefix = prefixes.pop()
        report["board"] = prefix.replace("sysupgrade-", "")
        if report["board"] != BOARD:
            report["problems"].append(
                f"image is for '{report['board']}', this device is '{BOARD}'")

        for payload, label in self.TARGETS.items():
            member = members.get(f"{prefix}/{payload}")
            if member is None:
                report["problems"].append(f"missing {prefix}/{payload}")
                continue
            device = self._device_for(label)
            capacity = _partition_bytes(device) if device else 0
            entry = {
                "size": member.size,
                "partition": label,
                "device": device,
                "capacity": capacity,
            }
            report["payloads"][payload] = entry

            if device is None:
                report["problems"].append(f"no partition named '{label}' on this device")
            elif capacity and member.size > capacity:
                report["problems"].append(
                    f"{payload} is {member.size} bytes but {label} holds only "
                    f"{capacity}")

            floor = MIN_ROOTFS_BYTES if payload == "root" else MIN_KERNEL_BYTES
            if member.size < floor:
                report["problems"].append(
                    f"{payload} is only {member.size} bytes; that is a "
                    f"truncated download, not firmware")
                continue

            magic = self._read_member(path, member.name, len(SQUASHFS_MAGIC))
            expected = SQUASHFS_MAGIC if payload == "root" else FIT_MAGIC
            if not magic.startswith(expected):
                report["problems"].append(
                    f"{payload} does not start with the expected "
                    f"{'SquashFS' if payload == 'root' else 'FIT'} magic "
                    f"(saw {magic[:4].hex()})")

        report["ok"] = not report["problems"]
        return report

    # ------------------------------------------------------------------ apply

    def apply(self, path: str, *, reboot: bool = False,
              expect_sha256: str | None = None) -> list[str]:
        """Validate, then write. Raises UpdateError without writing anything
        if any check fails."""
        report = self.inspect(path)
        if expect_sha256 and report["sha256"] != expect_sha256:
            raise UpdateError(
                f"sha256 mismatch: expected {expect_sha256}, got {report['sha256']}")
        if not report["ok"]:
            raise UpdateError("; ".join(report["problems"]))

        messages = [f"image verified: {report['board']}, "
                    f"sha256 {report['sha256'][:12]}"]
        if self.events:
            self.events.emit("FIRMWARE_UPDATE_STARTED", subsystem="system",
                             data={"sha256": report["sha256"]})

        # Root first, kernel last: a failed second write leaves a mismatched
        # pair either way, and the kernel is by far the smaller window.
        for payload in ("root", "kernel"):
            entry = report["payloads"][payload]
            written = self._write_member(path, report["board"], payload,
                                         entry["device"], entry["size"])
            expected = self._member_sha256(path, report["board"], payload)
            if written != expected:
                raise UpdateError(
                    f"{payload} read back differently from what was written "
                    f"({written[:12]} != {expected[:12]}). DO NOT REBOOT: the "
                    f"flash is now inconsistent. Re-run the update, or recover "
                    f"through the U-Boot recovery page.")
            messages.append(f"{payload} -> {entry['partition']} "
                            f"({entry['size']} bytes, verified)")

        os.sync()
        if self.events:
            self.events.emit("FIRMWARE_UPDATE_APPLIED", subsystem="system",
                             data={"sha256": report["sha256"]})
        if reboot:
            messages.append("rebooting into the new firmware")
            subprocess.Popen(["systemctl", "reboot"])
        else:
            messages.append("reboot when ready to run the new firmware")
        return messages

    # --------------------------------------------------------------- plumbing

    def _device_for(self, label: str) -> str | None:
        if label not in self._devices:
            device = _partition(label)
            if device:
                self._devices[label] = device
        return self._devices.get(label)

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(BLOCK), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _read_member(path: str, name: str, count: int) -> bytes:
        try:
            with tarfile.open(path) as tar:
                handle = tar.extractfile(name)
                return handle.read(count) if handle else b""
        except (tarfile.TarError, OSError):
            return b""

    def _member_sha256(self, path: str, board: str, payload: str) -> str:
        digest = hashlib.sha256()
        with tarfile.open(path) as tar:
            handle = tar.extractfile(f"sysupgrade-{board}/{payload}")
            if handle is None:
                return ""
            for chunk in iter(lambda: handle.read(BLOCK), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _write_member(self, path: str, board: str, payload: str,
                      device: str, size: int) -> str:
        """Stream a payload onto its partition and hash what lands there."""
        with tarfile.open(path) as tar:
            source = tar.extractfile(f"sysupgrade-{board}/{payload}")
            if source is None:
                raise UpdateError(f"{payload} vanished from the image")
            try:
                target = open(device, "r+b")
            except OSError as exc:
                raise UpdateError(f"cannot open {device}: {exc}") from exc
            with target:
                copied = 0
                while True:
                    chunk = source.read(BLOCK)
                    if not chunk:
                        break
                    target.write(chunk)
                    copied += len(chunk)
                target.flush()
                os.fsync(target.fileno())
            if copied != size:
                raise UpdateError(
                    f"{payload}: wrote {copied} of {size} bytes")

        # Read back from the device, not from the page cache we just filled.
        digest = hashlib.sha256()
        with open(device, "rb") as fh:
            try:
                os.posix_fadvise(fh.fileno(), 0, size, os.POSIX_FADV_DONTNEED)
            except (AttributeError, OSError):
                pass
            remaining = size
            while remaining > 0:
                chunk = fh.read(min(BLOCK, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()

    # ---------------------------------------------------------------- staging

    @staticmethod
    def staging_path(name: str = "upload.bin", *, create: bool = False) -> str:
        """Where an uploaded image lands.

        basename() is the traversal guard: a client-supplied name can never
        climb out of the staging directory. Creating the directory is opt-in so
        that asking where a file *would* go has no side effects.
        """
        if create:
            os.makedirs(STAGING_DIR, exist_ok=True)
        return os.path.join(STAGING_DIR, os.path.basename(name) or "upload.bin")

    @staticmethod
    def free_bytes() -> int:
        try:
            st = os.statvfs(STAGING_DIR if os.path.isdir(STAGING_DIR) else "/data")
        except OSError:
            return 0
        return st.f_bavail * st.f_frsize

    def status(self) -> dict[str, Any]:
        """What the API and UI report."""
        partitions = {}
        for payload, label in self.TARGETS.items():
            device = self._device_for(label)
            partitions[label] = {
                "device": device,
                "capacity": _partition_bytes(device) if device else 0,
            }
        staged = None
        if os.path.isdir(STAGING_DIR):
            images = sorted(glob.glob(os.path.join(STAGING_DIR, "*.bin")))
            if images:
                staged = self.inspect(images[-1])
        return {
            "board": BOARD,
            "partitions": partitions,
            # One bank. Worth saying out loud wherever this is displayed.
            "banks": 1,
            "staging_free_bytes": self.free_bytes(),
            "staged": staged,
        }
