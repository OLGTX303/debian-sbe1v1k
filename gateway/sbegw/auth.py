"""authd — local accounts, sessions, RBAC, API tokens, MFA (spec §37-§38).

Local-first by design (§51): authentication never depends on a controller, cloud
service or upstream DNS. Passwords use scrypt via hashlib, which is in the Debian
stdlib build, so no external crypto dependency is needed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import struct
import threading
import time
from typing import Any

from .util import now

log = logging.getLogger("sbegw.authd")

SESSION_TTL = 8 * 3600
SESSION_IDLE_TTL = 60 * 60
LOGIN_WINDOW = 300
LOGIN_MAX_FAILURES = 8
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

# Permission is "<area>.<read|write>". A role maps to a permission set; the
# wildcard "*" is only held by owner/super-admin.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {"*"},
    "super-admin": {"*"},
    "network-admin": {
        "network.read", "network.write", "routing.read", "routing.write",
        "system.read", "audit.read", "vpn.read",
    },
    "security-admin": {
        "security.read", "security.write", "network.read", "vpn.read", "vpn.write",
        "system.read", "audit.read",
    },
    "helpdesk": {"network.read", "security.read", "system.read", "clients.write"},
    "read-only": {"network.read", "security.read", "routing.read", "vpn.read",
                  "system.read", "audit.read"},
}

ALL_PERMISSIONS = sorted({
    "network.read", "network.write", "security.read", "security.write",
    "routing.read", "routing.write", "vpn.read", "vpn.write",
    "system.read", "system.write", "firmware.update", "backup.manage",
    "users.manage", "audit.read", "clients.write",
})


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                            p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def totp_now(secret_b32: str, *, at: float | None = None, step: int = 30,
             digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(secret_b32: str, code: str, *, skew: int = 1) -> bool:
    code = code.strip()
    for drift in range(-skew, skew + 1):
        if hmac.compare_digest(totp_now(secret_b32, at=time.time() + drift * 30), code):
            return True
    return False


class Principal:
    """Who a request is acting as."""

    def __init__(self, name: str, role: str, *, permissions: set[str] | None = None,
                 kind: str = "session"):
        self.name = name
        self.role = role
        self.kind = kind
        self.permissions = permissions if permissions is not None else \
            set(ROLE_PERMISSIONS.get(role, set()))

    def can(self, permission: str) -> bool:
        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        # A write permission implies the matching read permission.
        area, _, action = permission.partition(".")
        if action == "read" and f"{area}.write" in self.permissions:
            return True
        return False

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "kind": self.kind,
                "permissions": sorted(self.permissions)}


class AuthManager:
    def __init__(self, db_path: str, config_store, events=None):
        self.config = config_store
        self.events = events
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._failures: dict[str, list[float]] = {}
        self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS logins (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL NOT NULL,
                    username  TEXT,
                    source_ip TEXT,
                    success   INTEGER NOT NULL,
                    reason    TEXT,
                    agent     TEXT
                );
                CREATE INDEX IF NOT EXISTS logins_ts ON logins(ts DESC);
                """
            )

    # ------------------------------------------------------------------- setup

    def needs_setup(self) -> bool:
        cfg = self.config.get_running()
        return not cfg.get("users")

    def create_owner(self, username: str, password: str) -> None:
        """First-run owner creation. Refuses once any user exists."""
        if not self.needs_setup():
            raise PermissionError("initial setup has already been completed")
        self._validate_password(password)

        def mutate(cfg: dict[str, Any]) -> None:
            cfg["users"][username] = {
                "role": "owner",
                "password_hash": hash_password(password),
                "created": now(),
                "totp_secret": None,
            }
            cfg["system"]["setup_complete"] = True

        self.config.stage(mutate)
        self.config.commit(user=username, summary="initial setup",
                           confirm_required=False)

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        classes = sum([
            any(c.islower() for c in password), any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ])
        if classes < 3:
            raise ValueError("password needs at least three of: lowercase, "
                             "uppercase, digits, symbols")

    # ---------------------------------------------------------------- accounts

    def create_user(self, username: str, password: str, role: str, *,
                    actor: str = "system") -> None:
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role '{role}'")
        self._validate_password(password)
        cfg = self.config.get_running()
        if username in cfg.get("users", {}):
            raise ValueError(f"user '{username}' already exists")

        def mutate(config: dict[str, Any]) -> None:
            config["users"][username] = {
                "role": role, "password_hash": hash_password(password),
                "created": now(), "totp_secret": None,
            }

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"create user {username}",
                           confirm_required=False)

    def set_password(self, username: str, password: str, *,
                     actor: str = "system") -> None:
        self._validate_password(password)

        def mutate(config: dict[str, Any]) -> None:
            if username not in config.get("users", {}):
                raise ValueError(f"unknown user '{username}'")
            config["users"][username]["password_hash"] = hash_password(password)

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"password change for {username}",
                           confirm_required=False)
        self.revoke_user_sessions(username)

    def delete_user(self, username: str, *, actor: str = "system") -> None:
        cfg = self.config.get_running()
        users = cfg.get("users", {})
        if username not in users:
            raise ValueError(f"unknown user '{username}'")
        owners = [u for u, d in users.items() if d.get("role") == "owner"]
        if users[username].get("role") == "owner" and len(owners) <= 1:
            raise PermissionError("cannot delete the only owner account")

        def mutate(config: dict[str, Any]) -> None:
            config["users"].pop(username, None)

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"delete user {username}",
                           confirm_required=False)
        self.revoke_user_sessions(username)

    def enable_totp(self, username: str, *, actor: str = "system") -> str:
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

        def mutate(config: dict[str, Any]) -> None:
            config["users"][username]["totp_secret"] = secret

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"enable MFA for {username}",
                           confirm_required=False)
        return secret

    # ----------------------------------------------------------------- sessions

    def _rate_limited(self, key: str) -> bool:
        cutoff = now() - LOGIN_WINDOW
        with self._lock:
            attempts = [t for t in self._failures.get(key, []) if t > cutoff]
            self._failures[key] = attempts
            return len(attempts) >= LOGIN_MAX_FAILURES

    def _record_failure(self, key: str) -> None:
        with self._lock:
            self._failures.setdefault(key, []).append(now())

    def login(self, username: str, password: str, *, source_ip: str = "",
              agent: str = "", totp: str | None = None) -> dict[str, Any]:
        # Rate limit per source IP *and* per username so neither dimension can
        # be brute-forced by varying the other.
        for key in (f"ip:{source_ip}", f"user:{username}"):
            if self._rate_limited(key):
                self._log_login(username, source_ip, False, "rate limited", agent)
                raise PermissionError("too many failed attempts; try again later")

        user = self.config.get_running().get("users", {}).get(username)
        # Always run a hash comparison so a missing user and a wrong password
        # take the same time.
        stored = (user or {}).get("password_hash") or hash_password(secrets.token_hex(8))
        if not verify_password(password, stored) or user is None:
            self._record_failure(f"ip:{source_ip}")
            self._record_failure(f"user:{username}")
            self._log_login(username, source_ip, False, "invalid credentials", agent)
            if self.events:
                self.events.emit("AUTH_FAILED", subsystem="auth",
                                 data={"username": username, "source_ip": source_ip})
            raise PermissionError("invalid username or password")

        if user.get("totp_secret"):
            if not totp or not totp_verify(user["totp_secret"], totp):
                self._record_failure(f"user:{username}")
                self._log_login(username, source_ip, False, "MFA failed", agent)
                raise PermissionError("MFA code required or incorrect")

        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        session = {
            "token": token, "csrf": csrf, "username": username,
            "role": user.get("role", "read-only"), "created": now(),
            "last_seen": now(), "source_ip": source_ip, "agent": agent,
        }
        with self._lock:
            self._sessions[token] = session
        self._log_login(username, source_ip, True, "", agent)
        return session

    def logout(self, token: str) -> bool:
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def revoke_user_sessions(self, username: str) -> int:
        with self._lock:
            tokens = [t for t, s in self._sessions.items() if s["username"] == username]
            for token in tokens:
                del self._sessions[token]
        return len(tokens)

    def sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{k: v for k, v in s.items() if k not in ("token", "csrf")}
                    | {"id": t[:8]} for t, s in self._sessions.items()]

    def revoke_session(self, session_id: str) -> bool:
        with self._lock:
            for token in list(self._sessions):
                if token.startswith(session_id):
                    del self._sessions[token]
                    return True
        return False

    def principal_for_session(self, token: str) -> Principal | None:
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            timestamp = now()
            if timestamp - session["created"] > SESSION_TTL or \
                    timestamp - session["last_seen"] > SESSION_IDLE_TTL:
                del self._sessions[token]
                return None
            session["last_seen"] = timestamp
            return Principal(session["username"], session["role"])

    def csrf_for_session(self, token: str) -> str | None:
        with self._lock:
            session = self._sessions.get(token)
            return session["csrf"] if session else None

    # -------------------------------------------------------------- api tokens

    def create_token(self, name: str, role: str, *, actor: str = "system",
                     permissions: list[str] | None = None) -> str:
        secret = secrets.token_urlsafe(32)
        digest = hashlib.sha256(secret.encode()).hexdigest()

        def mutate(config: dict[str, Any]) -> None:
            config.setdefault("api_tokens", {})[name] = {
                "hash": digest, "role": role, "created": now(),
                "permissions": permissions or sorted(ROLE_PERMISSIONS.get(role, [])),
            }

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"create API token {name}",
                           confirm_required=False)
        return secret

    def delete_token(self, name: str, *, actor: str = "system") -> None:
        def mutate(config: dict[str, Any]) -> None:
            config.get("api_tokens", {}).pop(name, None)

        self.config.stage(mutate)
        self.config.commit(user=actor, summary=f"delete API token {name}",
                           confirm_required=False)

    def principal_for_token(self, secret: str) -> Principal | None:
        digest = hashlib.sha256(secret.encode()).hexdigest()
        for name, token in self.config.get_running().get("api_tokens", {}).items():
            if hmac.compare_digest(token.get("hash", ""), digest):
                return Principal(name, token.get("role", "read-only"),
                                 permissions=set(token.get("permissions") or []),
                                 kind="token")
        return None

    # ------------------------------------------------------------------ history

    def _log_login(self, username: str, source_ip: str, success: bool,
                   reason: str, agent: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO logins(ts, username, source_ip, success, reason, agent) "
                "VALUES(?,?,?,?,?,?)",
                (now(), username, source_ip, int(success), reason, agent[:200]))
            self._db.execute(
                "DELETE FROM logins WHERE id NOT IN "
                "(SELECT id FROM logins ORDER BY id DESC LIMIT 2000)")

    def login_history(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT ts, username, source_ip, success, reason, agent FROM logins "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) | {"success": bool(r["success"])} for r in rows]
