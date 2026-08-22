#!/usr/bin/env python3
"""configd transactional-commit tests: preflight, apply failure, health-check
failure, rollback timer, revision rollback and audit redaction."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

STATE = tempfile.mkdtemp(prefix="sbegw-cfg-")
os.environ["SBEGW_STATE"] = STATE

from sbegw.configd import ApplyResult, CommitError, ConfigStore, diff_config  # noqa: E402

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


class Applier:
    """Configurable applier so each failure mode can be exercised."""

    def __init__(self):
        self.calls = []
        self.fail = False
        self.preflight_problems = []
        self.requires_confirmation = False

    def preflight(self, old, new):
        return (not self.preflight_problems), list(self.preflight_problems)

    def __call__(self, old, new):
        self.calls.append(new.get("system", {}).get("hostname"))
        if self.fail:
            return ApplyResult(False, ["deliberate apply failure"])
        return ApplyResult(True, ["applied"],
                           requires_confirmation=self.requires_confirmation)


def fresh():
    store = ConfigStore(STATE)
    applier = Applier()
    store.register_applier("test", applier)
    return store, applier


print("--- diff ---")
changes = diff_config({"a": 1, "b": {"c": 2}}, {"a": 1, "b": {"c": 3}, "d": 4})
paths = {c["path"] for c in changes}
check("diff finds nested change and addition", paths == {"b.c", "d"}, str(sorted(paths)))

print("\n--- happy path ---")
store, applier = fresh()
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-one"}))
check("candidate diverges from running", len(store.pending_changes()) == 1)
result = store.commit(user="tester", confirm_required=False)
check("commit succeeded", result["committed"] and not result["confirm_pending"])
check("applier saw the new value", applier.calls[-1] == "gw-one", str(applier.calls))
check("running config updated", store.get_running()["system"]["hostname"] == "gw-one")
check("candidate matches running", store.pending_changes() == [])

print("\n--- no-op commit ---")
result = store.commit(user="tester", confirm_required=False)
check("empty commit is a no-op", result["changes"] == [])

print("\n--- preflight rejection ---")
store, applier = fresh()
applier.preflight_problems = ["would strand the administrator"]
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-bad"}))
try:
    store.commit(user="tester", confirm_required=False)
    check("preflight blocks the commit", False, "no error raised")
except CommitError as exc:
    check("preflight blocks the commit", exc.stage == "preflight", exc.stage)
    check("preflight reason is reported",
          "strand" in " ".join(exc.details), str(exc.details))
check("nothing was applied on preflight failure", applier.calls == [], str(applier.calls))
check("running config untouched",
      store.get_running()["system"]["hostname"] == "gw-one")

print("\n--- apply failure rolls back ---")
store, applier = fresh()
store.discard_candidate()
applier.fail = True
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-fails"}))
try:
    store.commit(user="tester", confirm_required=False)
    check("apply failure raises", False, "no error raised")
except CommitError as exc:
    check("apply failure raises", exc.stage == "apply", exc.stage)
check("running config restored after apply failure",
      store.get_running()["system"]["hostname"] == "gw-one",
      store.get_running()["system"]["hostname"])
check("rollback re-invoked the applier with the old config",
      applier.calls[-1] == "gw-one", str(applier.calls))

print("\n--- health-check failure rolls back ---")
store, applier = fresh()
store.discard_candidate()
store.register_health_check("always-fails", lambda cfg: (False, ["link never came up"]))
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-unhealthy"}))
try:
    store.commit(user="tester", confirm_required=False)
    check("health failure raises", False, "no error raised")
except CommitError as exc:
    check("health failure raises", exc.stage == "health", exc.stage)
    check("health reason reported", "link never came up" in " ".join(exc.details))
check("running config restored after health failure",
      store.get_running()["system"]["hostname"] == "gw-one")

print("\n--- rollback timer ---")
store, applier = fresh()
store.discard_candidate()
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-risky"}))
result = store.commit(user="tester", confirm_required=True, rollback_seconds=2)
check("commit is pending confirmation", result["confirm_pending"] is True)
check("new value is live while pending",
      store.get_running()["system"]["hostname"] == "gw-risky")
check("pending commit is reported", store.pending_commit is not None)
time.sleep(3.0)
check("unconfirmed commit rolled back automatically",
      store.get_running()["system"]["hostname"] == "gw-one",
      store.get_running()["system"]["hostname"])
check("pending commit cleared", store.pending_commit is None)

print("\n--- confirmation cancels the timer ---")
store, applier = fresh()
store.discard_candidate()
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-confirmed"}))
result = store.commit(user="tester", confirm_required=True, rollback_seconds=2)
check("confirm accepts the right txid", store.confirm(result["txid"]) is True)
check("confirm rejects an unknown txid", store.confirm("deadbeef") is False)
time.sleep(3.0)
check("confirmed commit survives the deadline",
      store.get_running()["system"]["hostname"] == "gw-confirmed",
      store.get_running()["system"]["hostname"])

print("\n--- concurrent commit guard ---")
store, applier = fresh()
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-a"}))
first = store.commit(user="tester", confirm_required=True, rollback_seconds=30)
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-b"}))
try:
    store.commit(user="tester", confirm_required=False)
    check("second commit blocked while one awaits confirmation", False)
except CommitError as exc:
    check("second commit blocked while one awaits confirmation",
          exc.stage == "lock", exc.stage)
store.confirm(first["txid"])

print("\n--- revision rollback ---")
revisions = store.revisions()
check("revisions recorded", len(revisions) >= 4, f"{len(revisions)} revisions")
target = next(r for r in revisions if "gw-confirmed" in str(
    store._db.execute("SELECT config FROM revisions WHERE id=?",
                      (r["id"],)).fetchone()["config"]))
store.rollback_to_revision(target["id"], user="tester")
check("rollback to a revision restores its hostname",
      store.get_running()["system"]["hostname"] == "gw-confirmed",
      store.get_running()["system"]["hostname"])

print("\n--- audit redaction ---")
store, applier = fresh()
store.discard_candidate()
store.stage(lambda cfg: cfg["wifi"]["networks"].__setitem__("s1", {
    "ssid": "Secret-SSID", "enabled": True, "bands": ["5g"], "network": "default",
    "security": {"mode": "wpa3", "passphrase": "TOP-SECRET-VALUE",
                 "pmf": "required"}}))
store.commit(user="tester", confirm_required=False)
audit = store.audit_log(limit=5)
serialised = str(audit)
check("secret is absent from the audit diff", "TOP-SECRET-VALUE" not in serialised)
check("the change itself is still recorded", "Secret-SSID" in serialised)
check("audit records the user", audit[0]["user"] == "tester")

print("\n--- boot re-apply (reboot with an unchanged config) ---")
# The device came up correctly on its first boot and lost every LAN port on
# each boot after it: seeding ports/radios made the first boot's commit see a
# diff, while later boots had none, so the diff-gated commit no-oped and netd
# never recreated the bridge or brought the ports up. Boot must force an apply.
store, applier = fresh()
store.stage(lambda cfg: cfg["system"].update({"hostname": "gw-reboot"}))
store.commit(user="system", confirm_required=False)
applied_before = len(applier.calls)

result = store.commit(user="system", source_ip="boot", summary="boot apply",
                      confirm_required=False)
check("an unchanged commit still reports no changes",
      result["messages"] == ["no changes to commit"])
check("...and does NOT reach the appliers (the reboot bug)",
      len(applier.calls) == applied_before)

result = store.commit(user="system", source_ip="boot", summary="boot apply",
                      confirm_required=False, force=True)
check("force=True applies an identical config",
      len(applier.calls) == applied_before + 1)
check("forced apply is committed", result.get("committed") is not False)
check("forced apply needs no confirmation",
      not result.get("confirm_pending"))
check("forced apply reports an empty change set", result.get("changes") == [])
check("forced apply keeps the config intact",
      store.get_running()["system"]["hostname"] == "gw-reboot")
revs_before = len(store.revisions(limit=100))
store.commit(user="system", source_ip="boot", summary="boot apply",
             confirm_required=False, force=True)
check("a forced no-change apply adds no revision history",
      len(store.revisions(limit=100)) == revs_before,
      f"{revs_before} -> {len(store.revisions(limit=100))}")
check("but it is still recorded in the audit log",
      any(a["detail"] == "boot apply" for a in store.audit_log(limit=10)))

shutil.rmtree(STATE, ignore_errors=True)
print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    print("failed: " + ", ".join(FAILED))
sys.exit(1 if FAILED else 0)
