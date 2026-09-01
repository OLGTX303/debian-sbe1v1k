#!/usr/bin/env python3
"""Image and boot-plumbing checks: writable root, clock, apt prerequisites.

These assert properties of the shipped scripts rather than of the Python control
plane, because the failures they guard against are boot-level and only show up
on hardware:

* the root was a read-only SquashFS, so nothing could be installed;
* the board has no RTC, so every boot started in the past and `apt update`
  rejected every Debian Release file as "not valid yet";
* the build scripts capped the root payload at 122 MB from a partition the
  vendor U-Boot does not actually boot, wasting ~900 MB of the real one.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
DEPLOY = os.path.join(REPO, "gateway", "deploy")
SCRIPTS = os.path.join(REPO, "scripts")

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


def read(*parts):
    path = os.path.join(*parts)
    try:
        with open(path) as fh:
            return fh.read()
    except OSError as exc:
        return f"<<unreadable: {exc}>>"


def shell_syntax_ok(path):
    """`sh -n`, so a typo cannot ship as PID 1 or as an early-boot unit."""
    if not os.path.exists(path):
        return False, "missing"
    proc = subprocess.run(["sh", "-n", path], capture_output=True, text=True)
    return proc.returncode == 0, proc.stderr.strip()


# ------------------------------------------------------------- writable root

print("--- writable root: the overlay pivot ---")
OVERLAY = os.path.join(DEPLOY, "bin", "sbegw-overlay-init")
overlay = read(OVERLAY)

check("the overlay init exists", os.path.exists(OVERLAY))
ok, err = shell_syntax_ok(OVERLAY)
check("it is syntactically valid shell", ok, err)
check("it is executable", os.access(OVERLAY, os.X_OK))
check("it is a /bin/sh script (dash is what the image has)",
      overlay.startswith("#!/bin/sh"), overlay.splitlines()[0] if overlay else "")

# The kernel command line carries no init=, so /sbin/init is the entry point.
# Everything below is what makes owning it safe.
check("it hands over with switch_root", "exec switch_root" in overlay)
check("it execs systemd, not /sbin/init (which is this script — a boot loop)",
      'exec "$REAL"' in overlay and 'REAL=/lib/systemd/systemd' in overlay)
check("the fallback path boots the read-only root",
      "fallback()" in overlay and 'exec "$REAL"' in overlay)

# A failure must never cost a boot, so every error exit goes through fallback.
bad_exits = [l.strip() for l in overlay.splitlines()
             if re.match(r"^\s*exit\s+[1-9]", l) and "fallback" not in l]
check("no error path exits without falling back", not bad_exits, str(bad_exits))

# udev is not running at PID 1, so /dev/disk/by-partlabel does not exist yet.
code_lines = [l for l in overlay.splitlines()
              if l.strip() and not l.lstrip().startswith("#")]
check("the data partition is found via sysfs PARTNAME, not /dev/disk/by-partlabel",
      "PARTNAME=" in overlay
      and not any("by-partlabel" in l for l in code_lines),
      str([l.strip() for l in code_lines if "by-partlabel" in l]))
check("it targets the rootfs_data partition", "LABEL=rootfs_data" in overlay)

# The root it starts on is read-only, so a tmpfs has to come first or every
# mkdir for a mountpoint fails.
run_at = overlay.find("tmpfs /run")
mkdir_at = overlay.find('mkdir -p "$MNT"')
check("a tmpfs is mounted on /run before any mountpoint is created",
      0 < run_at < mkdir_at, f"tmpfs@{run_at} mkdir@{mkdir_at}")

check("overlayfs support is checked before it is relied on",
      "grep -qw overlay /proc/filesystems" in overlay)
check("the merged root is checked for an init before switching into it",
      '[ -x "$NEWROOT$REAL" ]' in overlay)
check("the merged root is proved writable before switching into it",
      ".sbegw-writable" in overlay)
check("the state partition is carried into the new root at /data",
      'mount --move "$MNT" "$NEWROOT/data"' in overlay)

# Two escape hatches, because the overlay is exactly the thing that might break.
check("a kernel command line flag can force a read-only boot",
      "sbegw.readonly" in overlay and "/proc/cmdline" in overlay)
check("a marker file on the data partition can force a read-only boot",
      "overlay/root.disabled" in overlay)

print("\n--- the first boot after a flash ---")
# Flashing wipes rootfs_data, so on the first boot after a sysupgrade the
# partition has no filesystem at all and the pivot cannot mount it. The whole
# boot then stays read-only and the operator sees "/ is 100% full again", while
# sbegw-mount-state formats the partition ~20s later — long after the only
# moment a root overlay could have been built:
#     [ 2.20] mmcblk0: p1 ... p30
#     [ 4.24] EXT4-fs (mmcblk0p30): VFS: Can't find ext4 filesystem
#     [25.40] EXT4-fs (mmcblk0p30): mounted filesystem r/w
check("a blank data partition is formatted during the pivot",
      "mkfs.ext4" in overlay, "the first boot after a flash stays read-only")
check("...guarded by the same blank check sbegw-mount-state uses",
      "looks_blank" in overlay and "0\\000\\377" in overlay.replace("\\\\", "\\")
      or "tr -d" in overlay)
# What matters is not how many times the string appears, but that the only
# invocation is inside the blank-guarded branch.
_lines = overlay.splitlines()
_calls = [i for i, l in enumerate(_lines)
          if "mkfs.ext4" in l and not l.lstrip().startswith(("#", "log"))]
_guarded = all(
    any("looks_blank" in _lines[j] for j in range(max(0, i - 4), i))
    for i in _calls)
check("...so a partition holding unrecognised data is never reformatted",
      len(_calls) == 1 and _guarded,
      f"{len(_calls)} mkfs call(s), guarded={_guarded}")
# Not blank and it will not mount: replay the journal rather than give up.
check("a dirty filesystem gets its journal replayed",
      "e2fsck -p" in overlay)
check("the mount is retried rather than attempted once",
      "attempt" in overlay and "while" in overlay)
mkfs_at = overlay.find("mkfs.ext4")
fsck_at = overlay.find("e2fsck -p")
check("blank is checked before falling back to a journal replay",
      0 < mkfs_at < fsck_at, f"mkfs@{mkfs_at} fsck@{fsck_at}")

print("\n--- writable root: how it becomes /sbin/init ---")
installer = read(SCRIPTS, "install-gateway.sh")
check("the installer ships the overlay init",
      "deploy/bin/sbegw-overlay-init" in installer)
check("it syntax-checks it before making it PID 1",
      'sh -n "$ROOTFS/usr/lib/sbegw/overlay-init"' in installer)
check("/sbin/init points at it", "ln -sf /usr/lib/sbegw/overlay-init /sbin/init" in installer)
# systemd-sysv owns /sbin/init. Without a diversion an `apt upgrade` on the
# now-writable system restores the symlink, the next boot is read-only, and
# every package the user installed appears to vanish — the changes are still
# in the overlay upper layer, just not mounted.
check("the swap is recorded with dpkg-divert so an upgrade cannot undo it",
      "dpkg-divert" in installer and "/sbin/init" in installer)
check("the installer verifies a systemd binary exists to exec",
      "the overlay pivot would have nothing to exec" in installer)

# --------------------------------------------------------------- clock / apt

print("\n--- clock: this board has no RTC ---")
CLOCK = os.path.join(DEPLOY, "bin", "sbegw-clock-floor")
clock = read(CLOCK)
check("the clock-floor helper exists", os.path.exists(CLOCK))
ok, err = shell_syntax_ok(CLOCK)
check("it is syntactically valid shell", ok, err)
check("it is executable", os.access(CLOCK, os.X_OK))

# Only ever forward: moving a correct clock backwards would reintroduce the
# very failure this exists to prevent.
check("it compares against the current time before setting it",
      'now=$(date +%s)' in clock and '[ "$now" -ge "$floor" ]' in clock)
check("it takes the build stamp as a floor", "build-epoch" in clock)
check("it also honours systemd-timesyncd's saved clock",
      "/var/lib/systemd/timesync/clock" in clock)
check("it exits cleanly when there is nothing to do",
      clock.count("exit 0") >= 3, str(clock.count("exit 0")))

unit = read(DEPLOY, "systemd", "sbegw-clock-floor.service")
check("the unit runs before anything that validates a date",
      "Before=sysinit.target time-set.target systemd-timesyncd.service" in unit)
check("the unit does not wait on the default dependency graph",
      "DefaultDependencies=no" in unit)
check("the unit is a oneshot that stays applied",
      "Type=oneshot" in unit and "RemainAfterExit=yes" in unit)
check("the installer enables the unit",
      "sbegw-clock-floor.service" in installer)
check("the installer stamps the build time",
      "usr/lib/sbegw/build-epoch" in installer)

print("\n--- apt can actually run ---")
rootfs_build = read(SCRIPTS, "build-debian-rootfs.sh")
# Without NTP the build stamp only holds until the repository Release files age
# past their validity window, and then apt breaks again.
check("systemd-timesyncd is installed for real time sync",
      "systemd-timesyncd" in rootfs_build)
check("the installer enables timesyncd explicitly (its postinst runs under qemu)",
      "sysinit.target.wants/systemd-timesyncd.service" in installer)
check("wget is installed", re.search(r"\bwget\b", rootfs_build) is not None)
check("ca-certificates is installed, so https works",
      "ca-certificates" in rootfs_build)
check("sources.list covers main, updates and security",
      all(s in rootfs_build for s in ("bookworm main", "bookworm-updates",
                                      "bookworm-security")))
check("Suricata DPI is installed from Bookworm Backports",
      "bookworm-backports" in rootfs_build
      and re.search(r"apt-get install .*bookworm-backports.*suricata", rootfs_build)
      is not None)
check("the stock Suricata unit is masked because sbegw owns DPI",
      'etc/systemd/system/suricata.service' in installer
      and 'multi-user.target.wants/suricata.service' in installer)
check("the supplied UniFi portal fonts are transplanted into the gateway UI",
      "unifi-portal/dist/local" in installer and "PORTAL_UI/fonts" in installer
      and "Inter-Regular" in installer)
check("the supplied UniFi favicon assets are transplanted too",
      all(asset in installer for asset in ("favicon.svg", "favicon.ico",
                                            "apple-touch-icon.png")))

print("\n--- root must be able to log in ---")
# The chroot runs `passwd -l root`, which leaves "!" in front of the hash. The
# password step used to be conditional on ROOT_PASSWORD being set, so a build
# without it shipped a LOCKED root: sshd rejects every password and the serial
# console rejects the login, leaving no way into the device at all.
check("the password step is unconditional",
      'ROOT_PASSWORD="${ROOT_PASSWORD:-password}"' in rootfs_build,
      "still gated on ROOT_PASSWORD being set"
      if 'if [[ -n "${ROOT_PASSWORD:-}" ]]' in rootfs_build else "")
check("the account is explicitly unlocked",
      "passwd -u root" in rootfs_build)
check("using the default password is called out",
      "root password is the default" in rootfs_build)
# The build must refuse to produce an image nobody can log into.
for state, needle in (("locked", "root is still locked"),
                      ("disabled", "root login is disabled"),
                      ("empty", "empty password field")):
    check(f"the build fails if the root hash is {state}",
          needle in rootfs_build, needle)

# -e follows symlinks, so a host-side check on /sbin/init resolves the image's
# absolute symlink against the build host. It passed by luck while the target
# was /lib/systemd/systemd and broke the moment it became the overlay init.
# Three scripts had this bug; each must now accept a dangling symlink.
print("\n--- host-side checks must not resolve in-image symlinks ---")
for name in ("build-debian-rootfs.sh", "pack-debian-squashfs.sh"):
    body = read(SCRIPTS, name)
    lines = body.splitlines()
    # The list of required paths and the test that checks them sit on adjacent
    # lines, so look at the loop as a whole rather than a single line.
    guarded = False
    for i, line in enumerate(lines):
        if "/sbin/init" in line and "for required in" in line:
            window = "\n".join(lines[i:i + 4])
            guarded = "-L " in window
            break
    check(f"{name} tolerates a dangling /sbin/init symlink", guarded,
          "the required-paths check has no -L guard")

# apt.conf has no \" escape. A quoted sub-expression inside the hook command is
# truncated at the first inner quote, and then EVERY apt operation fails with
# "Problem executing scripts DPkg::Post-Invoke" — including the ones the
# operator runs on the device. Caught when it aborted the rootfs build.
_hook = re.search(r"DPkg::Post-Invoke \{(.*?)\};", installer, re.S)
check("the apt hook is present", _hook is not None)
if _hook:
    _cmd = _hook.group(1)
    _inner = _cmd.strip().strip(";").strip()
    check("the hook command contains no escaped double quotes",
          "\\\"" not in _cmd, _inner[:80])
    check("...and exactly one quoted command",
          _inner.count('"') == 2, f"{_inner.count(chr(34))} quote chars")
    check("the hook cannot fail an apt run",
          "|| true" in _cmd, _inner[:80])

print("\n--- docker ---")
check("docker is installed", "docker.io" in rootfs_build)
# Docker programs its NAT and published ports through iptables, and the image
# did not otherwise carry it.
check("iptables is installed for docker's NAT",
      re.search(r"\biptables\b", rootfs_build) is not None)
# overlay2 refuses to run on an overlayfs backing store, and with the writable
# root /var/lib/docker would land in the overlay's upper layer. It would fail
# outright, or silently drop to the vfs driver and copy whole layers.
check("docker's data-root is moved off the overlay onto the ext4",
      '"data-root": "/data/docker"' in installer,
      "overlay2 cannot run on overlayfs")
check("...and overlay2 is requested explicitly",
      '"storage-driver": "overlay2"' in installer)
# The same partition holds the gateway's own state.
check("container logs are size-capped",
      '"max-size"' in installer and '"max-file"' in installer)

print("\n--- docker's traffic must survive the firewall ---")
_schema = read(REPO, "gateway", "sbegw", "schema.py")
_netd = read(REPO, "gateway", "sbegw", "netd.py")
# sbegw's forward chain is policy-drop and Docker's own iptables rules attach to
# the same netfilter hooks, so a drop in either wins. Without a zone, a
# container gets no network at all.
check("there is a firewall zone for container bridges",
      '"containers"' in _schema and "containers" in _netd)
check("containers may reach the internet",
      '"containers->wan": "allow"' in _schema)
check("...but not the LAN", '"containers->lan": "drop"' in _schema)
check("docker0 is discovered rather than configured",
      'docker0' in _netd, "the daemon creates it, not us")
check("user-defined docker networks (br-<id>) are picked up too",
      'br-' in _netd and 'startswith("br-")' in _netd)

print("\n--- root payload size limit ---")
# The live root is PARTLABEL=rootfs = /dev/mmcblk0p29, 1048576 KiB per
# /proc/partitions. The old 127926272 came from p27 in an eMMC backup, which is
# not the partition U-Boot boots.
P29 = str(1024 * 1024 * 1024)
for name in ("pack-debian-squashfs.sh", "make-sysupgrade.sh"):
    body = read(SCRIPTS, name)
    assigns = [l.strip() for l in body.splitlines()
               if re.match(r"^\s*(ROOTFS_)?LIMIT=", l)]
    check(f"{name} sizes the payload against the real rootfs partition",
          P29 in body and not any("127926272" in l for l in assigns),
          "; ".join(assigns))

# --- exactly one netfilter backend
# This gateway programs nftables; third-party proxies drive iptables. If
# iptables is wired to the legacy ip_tables engine, both run at once on the
# same packets. Measured on hardware in that state, and a transparent proxy
# that works on ordinary routers did not work here.
import pathlib as _pl  # noqa: E402
_bs = _pl.Path(__file__).resolve().parents[2] / "scripts" / "build-debian-rootfs.sh"
_bt = _bs.read_text() if _bs.exists() else ""
check("the image pins iptables to the nft backend",
      "update-alternatives --set \"$_alt\"" in _bt and "-nft" in _bt,
      "third-party iptables rules would land in a second backend")
check("the build fails if iptables is not on nft",
      'iptables --version | grep -q "nf_tables"' in _bt,
      "a silent legacy fallback would ship")
check("the legacy netfilter modules are blacklisted",
      "blacklist ip_tables" in _bt and "sbe1v1k-single-netfilter.conf" in _bt,
      "legacy hooks would register alongside nft")

print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
import pathlib  # noqa: E402\nsys.exit(1 if FAILED else 0)
