#!/usr/bin/env python3
"""Focused DNS renderer and Smart Queue command tests without root/network."""
from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbegw import netd, schema  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" +
          (f" — {detail}" if detail else ""))


print("\n--- dnsmasq service rendering ---")
cfg = schema.default_config()
cfg["dns"].update({
    "dnssec": True,
    "query_log": True,
    "conditional_forwarders": [{"domain": "corp.example", "server": "10.0.0.53"}],
    "records": [
        {"name": "printer.lan", "type": "A", "value": "192.168.2.20"},
        {"name": "alias.lan", "type": "CNAME", "value": "printer.lan"},
    ],
    "filtering": {"enabled": True, "block_malware": False, "block_ads": False,
                  "blocklist": ["telemetry.example"],
                  "allowlist": ["allowed.example"]},
})
schema.validate(cfg)
rendered = netd.ServiceManager().render_dnsmasq(cfg)
for label, line in (
    ("DNSSEC is rendered", "dnssec"),
    ("query logging is rendered", "log-queries"),
    ("conditional forwarding is rendered", "server=/corp.example/10.0.0.53"),
    ("local A records are rendered", "host-record=printer.lan,192.168.2.20"),
    ("local CNAME records are rendered", "cname=alias.lan,printer.lan"),
    ("blocked domains are rendered", "address=/telemetry.example/"),
    ("allowed domains bypass filtering", "server=/allowed.example/#"),
):
    check(label, line in rendered, line)


print("\n--- Smart Queue tc plan ---")
commands: list[list[str]] = []
links = {"eth3"}
real_run = netd.run
real_run_ok = netd.run_ok
real_run_json = netd.run_json
real_which = netd.which
real_exists = netd.os.path.exists


def fake_run(argv, **_kwargs):
    argv = [str(part) for part in argv]
    commands.append(argv)
    if argv[:3] == ["ip", "link", "add"]:
        links.add(argv[3])
    elif argv[:4] == ["ip", "link", "del", "dev"]:
        links.discard(argv[4])
    return ""


def fake_run_ok(argv, **kwargs):
    fake_run(argv, **kwargs)
    return True


def fake_exists(path):
    prefix = "/sys/class/net/"
    return path[len(prefix):] in links if path.startswith(prefix) else real_exists(path)


class Wans:
    @staticmethod
    def interface_for(_wan, _cfg=None):
        return "eth3"


try:
    netd.run = fake_run
    netd.run_ok = fake_run_ok
    netd.run_json = lambda *_args, **_kwargs: []
    netd.which = lambda name: f"/sbin/{name}"
    netd.os.path.exists = fake_exists

    manager = netd.TrafficManager(Wans())
    shaped = copy.deepcopy(cfg)
    shaped["qos"] = {"enabled": True, "engine": "cake",
                     "download_kbps": 900000, "upload_kbps": 90000,
                     "per_client_limits": []}
    messages = manager.apply(shaped)
    joined = [" ".join(command) for command in commands]
    check("upload CAKE is attached to the WAN",
          any("tc qdisc replace dev eth3 root handle 1: cake bandwidth 90000kbit" in c
              for c in joined))
    check("download traffic is redirected to IFB",
          any("tc filter replace dev eth3 parent ffff: protocol all matchall action "
              "mirred egress redirect dev ifb-sbegw0" in c for c in joined))
    check("download CAKE is attached to IFB",
          any("tc qdisc replace dev ifb-sbegw0 root handle 1: cake bandwidth 900000kbit" in c
              for c in joined))
    check("successful shaping is reported", manager.last_error is None and
          any("enabled on wan1" in message for message in messages), str(messages))

    commands.clear()
    ap_cfg = copy.deepcopy(shaped)
    ap_cfg["system"]["mode"] = "ap"
    messages = manager.apply(ap_cfg)
    check("Smart Queues are bypassed in AP mode",
          not any(" cake " in f" {command} " for command in
                  (" ".join(c) for c in commands))
          and any("bypassed" in message for message in messages),
          str(messages))
finally:
    netd.run = real_run
    netd.run_ok = real_run_ok
    netd.run_json = real_run_json
    netd.which = real_which
    netd.os.path.exists = real_exists


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
