"""configd — candidate/running configuration with atomic commit and rollback.

Implements the flow required by the gateway spec (§40):

    change -> candidate -> validate -> preflight -> checkpoint -> apply
           -> health check -> commit          (failure -> rollback)

A commit that does not receive an explicit confirmation within the rollback
window is reverted automatically, so a bad firewall or WAN change cannot lock the
administrator out of the box. Every transition is recorded in the audit log with
a diff (§39).
"""
from __future__ import annotations

import copy
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from . import schema
from .util import now, write_atomic

log = logging.getLogger("sbegw.configd")

STATE_DIR = os.environ.get("SBEGW_STATE", "/data/sbegw")
RUNNING_PATH = os.path.join(STATE_DIR, "running.json")
CANDIDATE_PATH = os.path.join(STATE_DIR, "candidate.json")
DB_PATH = os.path.join(STATE_DIR, "sbegw.db")

DEFAULT_ROLLBACK_SECONDS = 120


class CommitError(RuntimeError):
    def __init__(self, message: str, *, stage: str, txid: str,
                 details: list[str] | None = None):
        self.stage = stage
        self.txid = txid
        self.details = details or []
        super().__init__(message)


@dataclass
class ApplyResult:
    """What an applier reports back to configd."""
    ok: bool
    messages: list[str] = field(default_factory=list)
    # Set when the applier knows the change is service-affecting for the admin's
    # own path to the box, which forces confirmation before commit.
    requires_confirmation: bool = False


# An applier takes (old_config, new_config) and makes the system match new.
Applier = Callable[[dict[str, Any], dict[str, Any]], ApplyResult]
HealthCheck = Callable[[dict[str, Any]], tuple[bool, list[str]]]


def diff_config(old: Any, new: Any, path: str = "") -> list[dict[str, Any]]:
    """Produce a flat list of {path, old, new} entries. Used for audit + UI."""
    changes: list[dict[str, Any]] = []
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            sub = f"{path}.{key}" if path else str(key)
            if key not in old:
                changes.append({"path": sub, "old": None, "new": new[key]})
            elif key not in new:
                changes.append({"path": sub, "old": old[key], "new": None})
            else:
                changes.extend(diff_config(old[key], new[key], sub))
    elif isinstance(old, list) and isinstance(new, list):
        if old != new:
            changes.append({"path": path, "old": old, "new": new})
    elif old != new:
        changes.append({"path": path, "old": old, "new": new})
    return changes


class ConfigStore:
    """Holds running + candidate config, revisions, and the audit trail."""

    def __init__(self, state_dir: str = STATE_DIR):
        self.state_dir = state_dir
        self.running_path = os.path.join(state_dir, "running.json")
        self.candidate_path = os.path.join(state_dir, "candidate.json")
        self._lock = threading.RLock()
        self._appliers: list[tuple[str, Applier]] = []
        self._health_checks: list[tuple[str, HealthCheck]] = []
        self._pending: dict[str, Any] | None = None
        self._rollback_timer: threading.Timer | None = None
        self.capabilities: dict[str, Any] = {}
        self.on_event: Callable[[str, str, dict[str, Any]], None] | None = None

        os.makedirs(state_dir, exist_ok=True)
        self._db = sqlite3.connect(os.path.join(state_dir, "sbegw.db"),
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._init_db()
        self.running = self._load_running()
        self.candidate = copy.deepcopy(self.running)

    # ---------------------------------------------------------------- storage

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS revisions (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid     TEXT NOT NULL,
                    ts       REAL NOT NULL,
                    user     TEXT,
                    source   TEXT,
                    summary  TEXT,
                    config   TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid     TEXT NOT NULL,
                    ts       REAL NOT NULL,
                    user     TEXT,
                    source_ip TEXT,
                    action   TEXT NOT NULL,
                    resource TEXT,
                    success  INTEGER NOT NULL,
                    detail   TEXT,
                    diff     TEXT
                );
                CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts DESC);
                CREATE INDEX IF NOT EXISTS revisions_ts ON revisions(ts DESC);
                """
            )

    def _load_running(self) -> dict[str, Any]:
        try:
            with open(self.running_path) as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError):
            log.warning("no usable running config; starting from defaults")
            cfg = schema.default_config()
            write_atomic(self.running_path, json.dumps(cfg, indent=2), mode=0o600)
            return cfg
        return self._migrate(cfg)

    def _migrate(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Fill in keys added by newer schema versions without losing user data."""
        version = cfg.get("schema_version", 0)
        defaults = schema.default_config()

        def merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
            for key, value in src.items():
                if key not in dst:
                    dst[key] = copy.deepcopy(value)
                elif isinstance(value, dict) and isinstance(dst[key], dict):
                    merge(dst[key], value)

        merge(cfg, defaults)
        if version != schema.SCHEMA_VERSION:
            log.info("migrated config from schema %s to %s", version, schema.SCHEMA_VERSION)
            cfg["schema_version"] = schema.SCHEMA_VERSION
        return cfg

    # ------------------------------------------------------------- appliers

    def register_applier(self, name: str, applier: Applier) -> None:
        self._appliers.append((name, applier))

    def register_health_check(self, name: str, check: HealthCheck) -> None:
        self._health_checks.append((name, check))

    def _emit(self, kind: str, severity: str, data: dict[str, Any]) -> None:
        if self.on_event:
            try:
                self.on_event(kind, severity, data)
            except Exception:  # an event sink must never break a commit
                log.exception("event sink raised")

    # ------------------------------------------------------------- candidate

    def get_running(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.running)

    def get_candidate(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.candidate)

    def discard_candidate(self) -> None:
        with self._lock:
            self.candidate = copy.deepcopy(self.running)
            try:
                os.unlink(self.candidate_path)
            except OSError:
                pass

    def stage(self, mutate: Callable[[dict[str, Any]], None]) -> list[str]:
        """Apply *mutate* to the candidate and validate it. Returns warnings."""
        with self._lock:
            trial = copy.deepcopy(self.candidate)
            mutate(trial)
            warnings = schema.validate(trial, capabilities=self.capabilities)
            self.candidate = trial
            write_atomic(self.candidate_path, json.dumps(trial, indent=2), mode=0o600)
            return warnings

    def pending_changes(self) -> list[dict[str, Any]]:
        with self._lock:
            return diff_config(self.running, self.candidate)

    # ---------------------------------------------------------------- commit

    def commit(self, *, user: str = "system", source_ip: str = "local",
               summary: str = "", rollback_seconds: int = DEFAULT_ROLLBACK_SECONDS,
               confirm_required: bool | None = None,
               force: bool = False) -> dict[str, Any]:
        """Validate, checkpoint, apply and health-check the candidate config.

        Returns a dict describing the transaction. If the change needs
        confirmation, `confirm_pending` is True and the caller must call
        `confirm(txid)` before the rollback timer fires.

        `force` applies the candidate even when it is identical to the running
        config. That is required at boot: the kernel starts with no bridge and
        every port down, so "nothing changed since last time" does not mean
        "nothing needs doing". Without it the first boot worked (seeding ports
        and radios produced a diff) and every boot after it left the device with
        no br-lan and all LAN ports down.
        """
        txid = uuid.uuid4().hex[:12]
        with self._lock:
            if self._pending:
                raise CommitError("another commit is awaiting confirmation",
                                  stage="lock", txid=self._pending["txid"])

            old = copy.deepcopy(self.running)
            new = copy.deepcopy(self.candidate)
            changes = diff_config(old, new)
            if not changes and not force:
                return {"txid": txid, "changes": [], "committed": True,
                        "confirm_pending": False, "warnings": [],
                        "messages": ["no changes to commit"]}

            # --- validate
            try:
                warnings = schema.validate(new, capabilities=self.capabilities)
            except schema.ValidationError as exc:
                self._audit(txid, user, source_ip, "commit", "config", False,
                            f"validation failed: {exc}", changes)
                raise CommitError(str(exc), stage="validate", txid=txid) from exc

            # --- preflight: appliers get a chance to reject before anything moves
            problems: list[str] = []
            for name, applier in self._appliers:
                check = getattr(applier, "preflight", None)
                if check is None:
                    continue
                try:
                    ok, msgs = check(old, new)
                except Exception as exc:  # noqa: BLE001 - report, do not apply
                    ok, msgs = False, [f"{name} preflight raised: {exc}"]
                if not ok:
                    problems.extend(msgs)
            if problems:
                self._audit(txid, user, source_ip, "commit", "config", False,
                            "; ".join(problems), changes)
                raise CommitError("preflight failed", stage="preflight", txid=txid,
                                  details=problems)

            # --- checkpoint
            # A forced re-apply of an identical config has nothing to roll back
            # to that is not already the running config, and recording a
            # checkpoint/commit pair for every boot would evict the operator's
            # real history (60 revisions kept, two per boot) after a month of
            # reboots. The audit log still records each boot apply.
            record_revisions = bool(changes)
            checkpoint_id = self._save_revision(
                txid, user, "checkpoint", summary or "pre-apply checkpoint",
                old) if record_revisions else self._latest_revision()

            # --- apply
            messages: list[str] = []
            needs_confirm = False
            failed: str | None = None
            for name, applier in self._appliers:
                try:
                    result = applier(old, new)
                except Exception as exc:  # noqa: BLE001
                    log.exception("applier %s raised", name)
                    result = ApplyResult(False, [f"{name}: {exc}"])
                messages.extend(result.messages)
                needs_confirm = needs_confirm or result.requires_confirmation
                if not result.ok:
                    failed = name
                    break

            if failed:
                log.error("apply failed in %s; rolling back to revision %s",
                          failed, checkpoint_id)
                self._rollback_to(old, reason=f"apply failed in {failed}")
                self._audit(txid, user, source_ip, "commit", "config", False,
                            f"apply failed in {failed}", changes)
                self._emit("CONFIG_ROLLED_BACK", "error",
                           {"txid": txid, "stage": "apply", "failed": failed})
                raise CommitError(f"apply failed in {failed}", stage="apply",
                                  txid=txid, details=messages)

            # --- health check
            unhealthy: list[str] = []
            for name, check in self._health_checks:
                try:
                    ok, msgs = check(new)
                except Exception as exc:  # noqa: BLE001
                    ok, msgs = False, [f"{name} health check raised: {exc}"]
                if not ok:
                    unhealthy.extend(msgs)
            if unhealthy:
                log.error("health check failed after apply: %s", unhealthy)
                self._rollback_to(old, reason="health check failed")
                self._audit(txid, user, source_ip, "commit", "config", False,
                            "; ".join(unhealthy), changes)
                self._emit("CONFIG_ROLLED_BACK", "error",
                           {"txid": txid, "stage": "health", "details": unhealthy})
                raise CommitError("health check failed after apply", stage="health",
                                  txid=txid, details=unhealthy)

            # --- commit (or arm the rollback timer and wait for confirmation)
            self.running = new
            write_atomic(self.running_path, json.dumps(new, indent=2), mode=0o600)
            self.candidate = copy.deepcopy(new)
            revision = self._save_revision(
                txid, user, "commit", summary or self._summarise(changes),
                new) if record_revisions else checkpoint_id

            confirm = needs_confirm if confirm_required is None else confirm_required
            if confirm and rollback_seconds > 0:
                self._pending = {"txid": txid, "previous": old, "revision": revision,
                                 "deadline": now() + rollback_seconds, "user": user}
                self._rollback_timer = threading.Timer(
                    rollback_seconds, self._rollback_timeout, args=(txid,))
                self._rollback_timer.daemon = True
                self._rollback_timer.start()
                log.warning("commit %s applied, awaiting confirmation within %ss",
                            txid, rollback_seconds)

            self._audit(txid, user, source_ip, "commit", "config", True,
                        summary or self._summarise(changes), changes)
            self._emit("CONFIG_COMMITTED", "info",
                       {"txid": txid, "revision": revision, "changes": len(changes),
                        "confirm_pending": bool(self._pending)})
            return {
                "txid": txid,
                "revision": revision,
                "changes": changes,
                "warnings": warnings,
                "messages": messages,
                "committed": True,
                "confirm_pending": bool(self._pending),
                "rollback_deadline": self._pending["deadline"] if self._pending else None,
            }

    def confirm(self, txid: str, *, user: str = "system") -> bool:
        """Cancel the rollback timer for a pending commit."""
        with self._lock:
            if not self._pending or self._pending["txid"] != txid:
                return False
            if self._rollback_timer:
                self._rollback_timer.cancel()
                self._rollback_timer = None
            self._pending = None
            self._audit(txid, user, "local", "confirm", "config", True,
                        "commit confirmed", [])
            log.info("commit %s confirmed", txid)
            return True

    def _rollback_timeout(self, txid: str) -> None:
        with self._lock:
            if not self._pending or self._pending["txid"] != txid:
                return
            previous = self._pending["previous"]
            log.error("commit %s not confirmed in time; rolling back", txid)
            self._pending = None
            self._rollback_timer = None
        self._rollback_to(previous, reason="not confirmed before rollback deadline")
        self._audit(txid, "system", "local", "rollback", "config", True,
                    "rollback timer expired", [])
        self._emit("CONFIG_ROLLED_BACK", "warning",
                   {"txid": txid, "stage": "confirm-timeout"})

    def _rollback_to(self, config: dict[str, Any], *, reason: str) -> None:
        """Re-apply *config*. Best effort: a failing applier must not stop others."""
        with self._lock:
            current = copy.deepcopy(self.running)
            self.running = copy.deepcopy(config)
            self.candidate = copy.deepcopy(config)
            write_atomic(self.running_path, json.dumps(config, indent=2), mode=0o600)
        for name, applier in self._appliers:
            try:
                applier(current, config)
            except Exception:  # noqa: BLE001
                log.exception("rollback applier %s failed (%s)", name, reason)

    def rollback_to_revision(self, revision_id: int, *, user: str = "system",
                             source_ip: str = "local") -> dict[str, Any]:
        row = self._db.execute("SELECT config FROM revisions WHERE id=?",
                               (revision_id,)).fetchone()
        if row is None:
            raise CommitError(f"revision {revision_id} not found", stage="revision",
                              txid="-")
        target = self._migrate(json.loads(row["config"]))
        with self._lock:
            self.candidate = target
        return self.commit(user=user, source_ip=source_ip,
                           summary=f"rollback to revision {revision_id}")

    @property
    def pending_commit(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._pending:
                return None
            return {"txid": self._pending["txid"], "deadline": self._pending["deadline"]}

    # ------------------------------------------------------- history / audit

    @staticmethod
    def _summarise(changes: list[dict[str, Any]]) -> str:
        if not changes:
            return "no changes"
        heads = sorted({c["path"].split(".")[0] for c in changes})
        return f"{len(changes)} change(s) in {', '.join(heads[:5])}"

    def _latest_revision(self) -> int:
        """Newest stored revision id, or 0 when none has been saved yet."""
        row = self._db.execute("SELECT MAX(id) FROM revisions").fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _save_revision(self, txid: str, user: str, source: str, summary: str,
                       config: dict[str, Any]) -> int:
        with self._db:
            cur = self._db.execute(
                "INSERT INTO revisions(txid, ts, user, source, summary, config) "
                "VALUES(?,?,?,?,?,?)",
                (txid, now(), user, source, summary, json.dumps(config)),
            )
            self._db.execute(
                "DELETE FROM revisions WHERE id NOT IN "
                "(SELECT id FROM revisions ORDER BY id DESC LIMIT 60)")
        return int(cur.lastrowid)

    def _audit(self, txid: str, user: str, source_ip: str, action: str,
               resource: str, success: bool, detail: str,
               changes: list[dict[str, Any]]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO audit(txid, ts, user, source_ip, action, resource, "
                "success, detail, diff) VALUES(?,?,?,?,?,?,?,?,?)",
                (txid, now(), user, source_ip, action, resource, int(success), detail,
                 json.dumps(self._redact(changes))),
            )
            self._db.execute(
                "DELETE FROM audit WHERE id NOT IN "
                "(SELECT id FROM audit ORDER BY id DESC LIMIT 5000)")

    # Substrings that mark a key as secret, wherever it appears.
    SECRET_KEYS = ("passphrase", "password", "psk", "secret", "private_key",
                   "preshared", "token", "totp", "hash")

    @classmethod
    def _is_secret_key(cls, key: str) -> bool:
        return any(s in key.lower() for s in cls.SECRET_KEYS)

    @classmethod
    def _redact_value(cls, value: Any) -> Any:
        """Recursively mask secret-looking keys inside a diff value.

        Creating an object produces a single diff entry whose *value* is the whole
        new subtree, so masking on the entry path alone would leak the secret.
        """
        if isinstance(value, dict):
            return {k: ("***" if cls._is_secret_key(k) else cls._redact_value(v))
                    for k, v in value.items()}
        if isinstance(value, list):
            return [cls._redact_value(v) for v in value]
        return value

    @classmethod
    def _redact(cls, changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Keep secrets out of the audit diff while still recording the change."""
        out = []
        for change in changes:
            path = change["path"]
            leaf = path.rsplit(".", 1)[-1]
            if cls._is_secret_key(leaf) or cls._is_secret_key(path):
                out.append({"path": path, "old": "***", "new": "***"})
            else:
                out.append({"path": path,
                            "old": cls._redact_value(change.get("old")),
                            "new": cls._redact_value(change.get("new"))})
        return out

    def audit_log(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)).fetchall()
        return [
            {"id": r["id"], "txid": r["txid"], "ts": r["ts"], "user": r["user"],
             "source_ip": r["source_ip"], "action": r["action"],
             "resource": r["resource"], "success": bool(r["success"]),
             "detail": r["detail"], "diff": json.loads(r["diff"] or "[]")}
            for r in rows
        ]

    def revisions(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT id, txid, ts, user, source, summary FROM revisions "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def revision_diff(self, revision_id: int) -> list[dict[str, Any]]:
        row = self._db.execute("SELECT config FROM revisions WHERE id=?",
                               (revision_id,)).fetchone()
        if row is None:
            return []
        return self._redact(diff_config(json.loads(row["config"]), self.get_running()))
