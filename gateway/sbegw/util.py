"""Shared helpers: process execution, atomic writes, rate math, logging."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Iterable, Sequence

log = logging.getLogger("sbegw")

# Binaries are resolved once at import so a missing tool degrades to a clear
# "unavailable" capability rather than an exception deep inside an adapter.
_TOOLS = (
    "ip", "bridge", "ethtool", "nft", "iw", "tc", "hostapd_cli",
    "wpa_cli", "conntrack", "dnsmasq", "systemctl", "wg", "vtysh",
)


class ToolError(RuntimeError):
    """A subprocess exited non-zero."""

    def __init__(self, argv: Sequence[str], rc: int, stderr: str):
        self.argv = list(argv)
        self.rc = rc
        self.stderr = stderr.strip()
        super().__init__(f"{argv[0]} exited {rc}: {self.stderr}")


def which(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path="/usr/sbin:/sbin:/usr/bin:/bin:/opt/sbegw/bin")


def tools() -> dict[str, str | None]:
    return {t: which(t) for t in _TOOLS}


def run(argv: Sequence[str], *, check: bool = True, timeout: float = 15.0,
        input_text: str | None = None) -> str:
    """Run a command and return stdout. Never invokes a shell."""
    argv = [str(a) for a in argv]
    exe = which(argv[0])
    if exe is None:
        raise ToolError(argv, 127, f"{argv[0]} not found")
    proc = subprocess.run(
        [exe, *argv[1:]],
        capture_output=True, text=True, timeout=timeout, input=input_text,
    )
    if check and proc.returncode != 0:
        raise ToolError(argv, proc.returncode, proc.stderr)
    return proc.stdout


def run_ok(argv: Sequence[str], **kw) -> bool:
    """Run a command, returning success. Used where failure is informational."""
    try:
        run(argv, **kw)
        return True
    except (ToolError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("command failed: %s", exc)
        return False


def run_json(argv: Sequence[str], *, default: Any = None, **kw) -> Any:
    """Run a command expected to emit JSON. Returns *default* on any failure."""
    try:
        out = run(argv, **kw)
    except (ToolError, OSError, subprocess.TimeoutExpired) as exc:
        log.debug("json command failed: %s", exc)
        return default
    if not out.strip():
        return default
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        log.debug("non-JSON output from %s", argv)
        return default


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def read_int(path: str, default: int | None = None) -> int | None:
    raw = read_text(path).strip()
    try:
        return int(raw, 0)
    except ValueError:
        return default


def write_atomic(path: str, data: str, mode: int = 0o644) -> bool:
    """Write *data* to *path* atomically. Returns True if content changed."""
    if read_text(path, default="\x00") == data:
        return False
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".sbegw.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def now() -> float:
    return time.time()


def monotonic() -> float:
    return time.monotonic()


def rate(cur: float, prev: float, dt: float) -> float:
    """Per-second rate from two counter samples, tolerating counter resets."""
    if dt <= 0 or prev is None or cur < prev:
        return 0.0
    return (cur - prev) / dt


def first(iterable: Iterable[Any], default: Any = None) -> Any:
    for item in iterable:
        return item
    return default


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def normalise_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def mac_bytes(mac: str) -> list[int]:
    return [int(part, 16) for part in normalise_mac(mac).split(":")]


def format_mac(octets: Sequence[int]) -> str:
    return ":".join(f"{o & 0xff:02x}" for o in octets)


def derive_mac(base: str, *, local_bit: bool, index: int) -> str:
    """Derive a stable secondary MAC from a base address.

    Sets the locally-administered bit and mixes *index* into the low octet so
    BSSIDs and MLD addresses stay stable across reboots for a given slot.
    """
    octets = mac_bytes(base)
    if local_bit:
        octets[0] |= 0x02
    octets[5] = (octets[5] + index) & 0xFF
    return format_mac(octets)
