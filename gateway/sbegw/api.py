"""router-api — versioned REST API and SSE stream (spec §49, wifi §50).

Implemented on the stdlib ThreadingHTTPServer so the gateway has no third-party
web framework to keep alive across Debian upgrades. nginx terminates TLS in front
of it and proxies /api plus the static UI; the API itself binds to localhost.

Every mutating route is CSRF-protected, RBAC-checked and audited. Reads are
served from the last telemetry snapshot so a burst of UI polling cannot turn into
a burst of subprocess calls.
"""
from __future__ import annotations

import json
import logging
import queue
import re
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from . import schema
from .adapters import nft, platform
from .auth import ALL_PERMISSIONS, ROLE_PERMISSIONS, AuthManager, Principal
from .configd import CommitError
from .util import now

log = logging.getLogger("sbegw.api")

API_PREFIX = "/api/v1"
MAX_BODY = 4 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str,
                 details: Any = None):
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


class Route:
    __slots__ = ("method", "pattern", "handler", "permission", "regex")

    def __init__(self, method: str, pattern: str, handler: Callable,
                 permission: str | None):
        self.method = method
        self.pattern = pattern
        self.handler = handler
        self.permission = permission
        # `{name}` becomes a named group; everything else is literal.
        regex = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern)
        self.regex = re.compile(f"^{regex}$")


class Router:
    def __init__(self):
        self.routes: list[Route] = []

    def add(self, method: str, pattern: str, handler: Callable,
            permission: str | None = None) -> None:
        self.routes.append(Route(method, API_PREFIX + pattern, handler, permission))

    def match(self, method: str, path: str) -> tuple[Route, dict[str, str]] | None:
        allowed: set[str] = set()
        for route in self.routes:
            match = route.regex.match(path)
            if not match:
                continue
            if route.method != method:
                allowed.add(route.method)
                continue
            return route, match.groupdict()
        if allowed:
            raise ApiError(405, "method_not_allowed",
                           f"{method} not allowed here", {"allow": sorted(allowed)})
        return None


class EventStream:
    """Fan-out of events and telemetry frames to SSE subscribers."""

    def __init__(self, maxsize: int = 200):
        self.maxsize = maxsize
        self._queues: list[queue.Queue] = []
        self._lock = threading.Lock()

    def register(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self.maxsize)
        with self._lock:
            self._queues.append(q)
        return q

    def unregister(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._queues:
                self._queues.remove(q)

    def publish(self, kind: str, payload: Any) -> None:
        frame = (kind, payload)
        with self._lock:
            targets = list(self._queues)
        for q in targets:
            try:
                q.put_nowait(frame)
            except queue.Full:
                # A stalled client must not slow the sampler; drop its oldest.
                try:
                    q.get_nowait()
                    q.put_nowait(frame)
                except queue.Empty:
                    pass

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._queues)


class ApiService:
    """Holds the wiring and registers every route."""

    def __init__(self, *, config_store, auth: AuthManager, netd, wifid, clients,
                 telemetry, sampler, events, rf=None, dpi=None, controller=None):
        self.config = config_store
        self.auth = auth
        self.netd = netd
        self.wifid = wifid
        self.clients = clients
        self.telemetry = telemetry
        self.sampler = sampler
        self.events = events
        self.rf = rf
        self.dpi = dpi
        self.controller = controller
        self.stream = EventStream()
        self.router = Router()
        self._register()
        self.events.subscribe(lambda event: self.stream.publish("event", event))

    # ------------------------------------------------------------------ helpers

    def _snapshot(self) -> dict[str, Any]:
        snapshot = self.sampler.snapshot()
        if not snapshot:
            snapshot = self.sampler.sample()
        return snapshot

    def _commit(self, principal: Principal, source_ip: str, summary: str,
                mutate: Callable[[dict[str, Any]], None], *,
                confirm: bool | None = None) -> dict[str, Any]:
        try:
            warnings = self.config.stage(mutate)
        except schema.ValidationError as exc:
            raise ApiError(422, "validation_failed", str(exc),
                           {"path": exc.path}) from exc
        except (ValueError, KeyError) as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        try:
            result = self.config.commit(user=principal.name, source_ip=source_ip,
                                        summary=summary, confirm_required=confirm)
        except CommitError as exc:
            self.config.discard_candidate()
            raise ApiError(409, f"commit_{exc.stage}", str(exc),
                           {"txid": exc.txid, "details": exc.details}) from exc
        result["warnings"] = list(result.get("warnings", [])) + warnings
        # Reads are served from the cached telemetry snapshot, so refresh it now:
        # otherwise the response to "create X" is followed by a read that still
        # does not know X exists. A sampling failure must not fail the commit.
        try:
            self.sampler.sample()
        except Exception:  # noqa: BLE001
            log.warning("post-commit resample failed", exc_info=True)
        return result

    @staticmethod
    def _paginate(items: list[Any], query: dict[str, list[str]]) -> dict[str, Any]:
        limit = min(int(query.get("limit", ["200"])[0] or 200), 2000)
        offset = max(int(query.get("offset", ["0"])[0] or 0), 0)
        sort = query.get("sort", [None])[0]
        if sort:
            reverse = sort.startswith("-")
            key = sort.lstrip("-")
            items = sorted(items, key=lambda i: (i.get(key) is None, i.get(key)),
                           reverse=reverse)
        return {"total": len(items), "limit": limit, "offset": offset,
                "items": items[offset:offset + limit]}

    # ------------------------------------------------------------------- routes

    def _register(self) -> None:
        add = self.router.add

        # --- auth / setup (unauthenticated)
        add("GET", "/setup", self.get_setup, None)
        add("POST", "/setup", self.post_setup, None)
        add("POST", "/auth/login", self.post_login, None)
        add("POST", "/auth/logout", self.post_logout, None)
        add("GET", "/auth/self", self.get_self, "system.read")
        add("GET", "/auth/sessions", self.get_sessions, "users.manage")
        add("DELETE", "/auth/sessions/{id}", self.delete_session, "users.manage")
        add("GET", "/auth/history", self.get_login_history, "audit.read")

        # --- system / platform
        add("GET", "/system", self.get_system, "system.read")
        add("GET", "/platform", self.get_platform, "system.read")
        add("GET", "/platform/identity", self.get_identity, "system.read")
        add("GET", "/platform/identity/factory-credentials",
            self.get_factory_credentials, "system.write")
        add("PUT", "/system", self.put_system, "system.write")
        add("GET", "/dashboard", self.get_dashboard, "system.read")
        add("GET", "/health", self.get_health, "system.read")
        add("GET", "/controller", self.get_controller, "system.read")
        add("PUT", "/controller", self.put_controller, "system.write")
        add("POST", "/controller/inform", self.post_controller_inform,
            "system.write")
        add("POST", "/controller/sync", self.post_controller_sync,
            "system.write")
        add("POST", "/controller/reset", self.post_controller_reset,
            "system.write")

        # --- ports
        add("GET", "/ports", self.get_ports, "network.read")
        add("PUT", "/ports/{id}", self.put_port, "network.write")

        # --- networks
        add("GET", "/networks", self.get_networks, "network.read")
        add("POST", "/networks", self.post_network, "network.write")
        add("PUT", "/networks/{id}", self.put_network, "network.write")
        add("DELETE", "/networks/{id}", self.delete_network, "network.write")

        # --- wans
        add("GET", "/wans", self.get_wans, "network.read")
        add("PUT", "/wans/{id}", self.put_wan, "network.write")

        # --- firewall / nat
        add("GET", "/firewall", self.get_firewall, "security.read")
        add("PUT", "/firewall", self.put_firewall, "security.write")
        add("GET", "/firewall/counters", self.get_firewall_counters, "security.read")
        add("GET", "/nat", self.get_nat, "security.read")
        add("PUT", "/nat", self.put_nat, "security.write")

        # --- routing
        add("GET", "/routing", self.get_routing, "routing.read")
        add("PUT", "/routing", self.put_routing, "routing.write")

        # --- traffic management / DNS services
        add("GET", "/services", self.get_services, "network.read")
        add("PUT", "/services", self.put_services, "network.write")

        # --- application-aware traffic accounting
        add("GET", "/dpi", self.get_dpi, "security.read")
        add("PUT", "/dpi", self.put_dpi, "security.write")

        # --- wifi
        add("GET", "/wifi", self.get_wifi, "network.read")
        add("GET", "/wifi/radios", self.get_radios, "network.read")
        add("PUT", "/wifi/radios/{id}", self.put_radio, "network.write")
        add("GET", "/wifi/networks", self.get_wifi_networks, "network.read")
        add("POST", "/wifi/networks", self.post_wifi_network, "network.write")
        add("PUT", "/wifi/networks/{id}", self.put_wifi_network, "network.write")
        add("DELETE", "/wifi/networks/{id}", self.delete_wifi_network, "network.write")
        add("GET", "/wifi/mlo", self.get_mlo, "network.read")
        add("POST", "/wifi/mlo", self.post_mld, "network.write")
        add("PUT", "/wifi/mlo/{id}", self.put_mld, "network.write")
        add("DELETE", "/wifi/mlo/{id}", self.delete_mld, "network.write")
        add("GET", "/wifi/regulatory", self.get_regulatory, "network.read")
        add("PUT", "/wifi/regulatory", self.put_regulatory, "network.write")
        add("GET", "/wifi/clients", self.get_wifi_clients, "network.read")
        add("GET", "/wifi/neighbors", self.get_neighbours, "security.read")
        add("POST", "/wifi/radios/{id}/recover", self.post_radio_recover, "network.write")
        add("GET", "/wifi/capabilities", self.get_wifi_capabilities, "network.read")
        add("GET", "/wifi/channels", self.get_channels, "network.read")
        add("POST", "/wifi/channels/scan", self.post_channel_scan, "network.write")
        add("POST", "/wifi/channels/optimize", self.post_channel_optimize,
            "network.write")
        add("PUT", "/wifi/channels/settings", self.put_channel_settings,
            "network.write")
        add("GET", "/wifi/channels/history", self.get_channel_history, "network.read")

        # --- clients
        add("GET", "/clients", self.get_clients, "network.read")
        add("GET", "/clients/{mac}", self.get_client, "network.read")
        add("PUT", "/clients/{mac}", self.put_client, "clients.write")
        add("POST", "/clients/{mac}/actions/{action}", self.post_client_action,
            "clients.write")

        # --- telemetry / events / logs
        add("GET", "/telemetry", self.get_telemetry, "system.read")
        add("GET", "/telemetry/series", self.get_series, "system.read")
        add("GET", "/telemetry/history", self.get_series_history, "system.read")
        add("GET", "/events", self.get_events, "system.read")
        add("GET", "/topology", self.get_topology, "network.read")

        # --- config transactions
        add("GET", "/config", self.get_config, "system.read")
        add("GET", "/config/pending", self.get_pending, "system.read")
        add("POST", "/config/commit", self.post_commit, "system.write")
        add("POST", "/config/confirm", self.post_confirm, "system.write")
        add("POST", "/config/discard", self.post_discard, "system.write")
        add("GET", "/config/revisions", self.get_revisions, "system.read")
        add("POST", "/config/revisions/{id}/rollback", self.post_rollback,
            "system.write")
        add("GET", "/audit", self.get_audit, "audit.read")

        # --- users / rbac
        add("GET", "/users", self.get_users, "users.manage")
        add("POST", "/users", self.post_user, "users.manage")
        add("PUT", "/users/{name}", self.put_user, "users.manage")
        add("DELETE", "/users/{name}", self.delete_user, "users.manage")
        add("GET", "/rbac", self.get_rbac, "users.manage")

        # --- backups
        add("GET", "/backups/export", self.get_backup, "backup.manage")
        add("POST", "/backups/import", self.post_backup, "backup.manage")

    # ============================================================ handlers

    def get_dpi(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        if self.dpi is None:
            return {"config": cfg.get("dpi", {}),
                    "status": {"running": False, "tool_available": False,
                               "error": "DPI service is unavailable", "flow_count": 0},
                    "applications": [], "clients": []}
        self.dpi.poll(cfg)
        return self.dpi.summary(cfg)

    def put_dpi(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        allowed = {"enabled", "engine", "retention_hours", "include_ipv6"}
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise ApiError(400, "bad_request",
                           f"unknown DPI settings: {', '.join(unknown)}")

        def mutate(cfg: dict[str, Any]) -> None:
            cfg["dpi"].update(body)

        return self._commit(ctx.principal, ctx.source_ip,
                            "traffic identification settings", mutate,
                            confirm=False)

    def get_controller(self, ctx) -> dict[str, Any]:
        if self.controller is not None:
            return self.controller.status()
        cfg = self.config.get_running().get("controller", {})
        return {"config": _redact_secrets(cfg),
                "state": {"adopted": False,
                          "error": "controller agent unavailable"},
                "crypto_available": False}

    def put_controller(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        allowed = {"enabled", "inform_url", "discovery", "sync_enabled",
                   "api_url", "api_key", "site_id", "verify_tls",
                   "interval_seconds"}
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise ApiError(400, "bad_request",
                           f"unknown controller settings: {', '.join(unknown)}")
        updates = {k: v for k, v in body.items()
                   if not (k == "api_key" and v == "********")}

        def mutate(cfg: dict[str, Any]) -> None:
            cfg["controller"].update(updates)

        result = self._commit(ctx.principal, ctx.source_ip,
                              "UniFi Network controller settings", mutate,
                              confirm=False)
        if self.controller is not None:
            self.controller.wake()
        return result

    def post_controller_inform(self, ctx) -> dict[str, Any]:
        if self.controller is None:
            raise ApiError(503, "unavailable", "controller agent is unavailable")
        try:
            return {"ok": True, "response": self.controller.inform_once()}
        except Exception as exc:  # protocol boundary; return a useful UI error
            raise ApiError(502, "controller_failed", str(exc)) from exc

    def post_controller_sync(self, ctx) -> dict[str, Any]:
        if self.controller is None:
            raise ApiError(503, "unavailable", "controller agent is unavailable")
        cfg = self.config.get_running()
        if not cfg.get("controller", {}).get("sync_enabled"):
            raise ApiError(409, "sync_disabled", "controller API sync is disabled")
        try:
            return self.controller.sync_once(cfg)
        except schema.ValidationError as exc:
            raise ApiError(422, "validation_failed", str(exc),
                           {"path": exc.path}) from exc
        except Exception as exc:  # protocol boundary; return a useful UI error
            raise ApiError(502, "controller_failed", str(exc)) from exc

    def post_controller_reset(self, ctx) -> dict[str, Any]:
        if self.controller is None:
            raise ApiError(503, "unavailable", "controller agent is unavailable")
        self.controller.reset()
        return {"ok": True}

    def get_setup(self, ctx) -> dict[str, Any]:
        return {"setup_required": self.auth.needs_setup(),
                "board": platform.board()}

    def post_setup(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        try:
            self.auth.create_owner(body["username"], body["password"])
        except (KeyError, ValueError) as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        except PermissionError as exc:
            raise ApiError(409, "already_configured", str(exc)) from exc
        session = self.auth.login(body["username"], body["password"],
                                  source_ip=ctx.source_ip, agent=ctx.agent)
        ctx.set_session_cookie(session["token"])
        return {"ok": True, "csrf": session["csrf"],
                "user": {"name": body["username"], "role": "owner"}}

    def post_login(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        try:
            session = self.auth.login(
                body.get("username", ""), body.get("password", ""),
                source_ip=ctx.source_ip, agent=ctx.agent, totp=body.get("totp"))
        except PermissionError as exc:
            raise ApiError(401, "unauthorized", str(exc)) from exc
        ctx.set_session_cookie(session["token"])
        return {"ok": True, "csrf": session["csrf"],
                "user": {"name": session["username"], "role": session["role"],
                         "permissions": sorted(
                             ROLE_PERMISSIONS.get(session["role"], set()))}}

    def post_logout(self, ctx) -> dict[str, Any]:
        if ctx.session_token:
            self.auth.logout(ctx.session_token)
        ctx.clear_session_cookie()
        return {"ok": True}

    def get_self(self, ctx) -> dict[str, Any]:
        return {"user": ctx.principal.as_dict(),
                "csrf": self.auth.csrf_for_session(ctx.session_token or "")}

    def get_sessions(self, ctx) -> dict[str, Any]:
        return {"sessions": self.auth.sessions()}

    def delete_session(self, ctx) -> dict[str, Any]:
        return {"ok": self.auth.revoke_session(ctx.params["id"])}

    def get_login_history(self, ctx) -> dict[str, Any]:
        return {"logins": self.auth.login_history()}

    # ------------------------------------------------------------------ system

    def get_system(self, ctx) -> dict[str, Any]:
        snapshot = self._snapshot()
        cfg = self.config.get_running()
        return {"config": cfg.get("system", {}),
                "state": snapshot.get("system", {}),
                "pending_commit": self.config.pending_commit}

    def get_identity(self, ctx) -> dict[str, Any]:
        """Factory identity read from ART, U-Boot, socinfo, eMMC and the DT.

        The factory Wi-Fi passphrase and WPS PIN are reported as present/absent
        only — see get_factory_credentials for the values.
        """
        from .adapters import art
        return art.identity()

    def get_factory_credentials(self, ctx) -> dict[str, Any]:
        """The factory Wi-Fi key and WPS PIN from the ART vendor block.

        Separated from the identity read and gated on system.write: these are
        printed on the device label, but a passphrase in a screenshot, a log or a
        casually shared API response is still a real exposure. Reading them is
        audited.
        """
        from .adapters import art
        block = art.vendor_block(include_secrets=True)
        fields = block.get("fields", {})
        self.events.emit(
            "CONFIG_COMMITTED", "notice",
            {"detail": "factory credentials read from ART",
             "user": ctx.principal.name, "source_ip": ctx.source_ip},
            subsystem="audit",
            message=f"{ctx.principal.name} revealed the factory Wi-Fi credentials")
        return {
            "present": block.get("present"),
            "reason": block.get("reason"),
            "wps_pin": fields.get("wps_pin"),
            "keys": {
                "2g": fields.get("factory_key_2g"),
                "5g": fields.get("factory_key_5g"),
                "6g": fields.get("factory_key_6g"),
            },
            "ssids": {
                "2g": fields.get("factory_ssid_2g"),
                "5g": fields.get("factory_ssid_5g"),
                "6g": fields.get("factory_ssid_6g"),
            },
        }

    def get_platform(self, ctx) -> dict[str, Any]:
        return {
            "board": platform.board(),
            "acceleration": platform.acceleration(),
            "flows": platform.flow_statistics(),
            "ppeds": platform.ppeds_radios(),
            "thermal": platform.thermal(),
            "storage": platform.storage(),
            "radios": self.wifid.capabilities()["radios"],
            "hostapd": self.wifid.capabilities()["hostapd"],
        }

    def put_system(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        return self._commit(ctx.principal, ctx.source_ip, "system settings",
                            lambda cfg: cfg["system"].update(body))

    def get_dashboard(self, ctx) -> dict[str, Any]:
        snapshot = self._snapshot()
        cfg = self.config.get_running()
        wifi = snapshot.get("wifi", {})
        clients = snapshot.get("clients", [])
        wans = snapshot.get("wans", [])
        primary = next((w for w in wans if w["id"] == snapshot.get("primary_wan")), None)
        return {
            "ts": snapshot.get("ts"),
            "system": snapshot.get("system", {}),
            "internet": {
                "state": primary["state"] if primary else "down",
                "wan": primary["id"] if primary else None,
                "public_ip": (primary or {}).get("addresses", [None])[0],
                "latency_ms": (primary or {}).get("latency_ms"),
                "loss_percent": (primary or {}).get("loss_percent"),
            },
            "wans": wans,
            "ports": [{k: p[k] for k in ("id", "name", "role", "link_up",
                                         "speed_mbps", "duplex", "rates")}
                      for p in snapshot.get("ports", [])],
            "clients": {
                "total": len([c for c in clients if c.get("online")]),
                "wired": len([c for c in clients if c.get("online")
                              and c.get("connection") == "wired"]),
                "wireless": len([c for c in clients if c.get("online")
                                 and c.get("connection") == "wireless"]),
                "mlo": len([c for c in clients if c.get("online")
                            and (c.get("wireless") or {}).get("is_mlo")]),
            },
            "wifi": {
                "radios": [{k: r.get(k) for k in
                            ("id", "label", "band", "state", "health", "runtime",
                             "configured", "client_count", "downgrade_reason",
                             "bss_count")}
                           for r in wifi.get("radios", [])],
                "mlds": wifi.get("mlds", []),
                "hostapd_running": wifi.get("hostapd_running"),
            },
            "acceleration": snapshot.get("acceleration", {}),
            "events": self.events.query(limit=15),
            "alerts": self._alerts(snapshot),
            "networks": snapshot.get("networks", []),
        }

    def _alerts(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        """Things the operator should act on right now."""
        alerts: list[dict[str, Any]] = []
        system = snapshot.get("system", {})
        if system.get("thermal", {}).get("state") in ("warning", "critical"):
            alerts.append({"severity": "warning", "area": "thermal",
                           "message": f"Temperature {system['thermal']['max_temperature_c']}°C"})
        if system.get("memory", {}).get("used_percent", 0) > 90:
            alerts.append({"severity": "warning", "area": "memory",
                           "message": "Memory pressure above 90%"})
        for storage in system.get("storage", []):
            # Only writable filesystems can fill up. The root SquashFS is
            # permanently 100% used by construction, and alerting on it told
            # the operator the device was out of space while /data was at 1%.
            if not storage.get("writable", True):
                continue
            if storage["used_percent"] > 90:
                alerts.append({"severity": "warning", "area": "storage",
                               "message": f"{storage['mount']} is "
                                          f"{storage['used_percent']}% full"})
            if storage.get("inodes_used_percent", 0) > 90:
                alerts.append({"severity": "warning", "area": "storage",
                               "message": f"{storage['mount']} has used "
                                          f"{storage['inodes_used_percent']}% "
                                          f"of its inodes"})
        for wan in snapshot.get("wans", []):
            if wan.get("state") not in ("up", "disabled"):
                alerts.append({"severity": "error", "area": "wan",
                               "message": f"{wan.get('name')} is {wan.get('state')}"})
        for radio in snapshot.get("wifi", {}).get("radios", []):
            if radio.get("downgrade_reason"):
                alerts.append({"severity": "info", "area": "wifi",
                               "message": f"{radio['label']}: {radio['downgrade_reason']}"})
            if radio.get("health") == "failed":
                alerts.append({"severity": "error", "area": "wifi",
                               "message": f"{radio['label']} radio failed"})
        for mld in snapshot.get("wifi", {}).get("mlds", []):
            if mld.get("state") == "degraded":
                alerts.append({"severity": "warning", "area": "mlo",
                               "message": f"MLD {mld['name']} has only "
                                          f"{mld['links_up']} link(s) up"})
        accel = snapshot.get("acceleration", {})
        for reason in accel.get("fallback_reasons", [])[:2]:
            alerts.append({"severity": "info", "area": "acceleration",
                           "message": reason})
        if self.config.pending_commit:
            alerts.append({"severity": "warning", "area": "config",
                           "message": "A configuration change is awaiting "
                                      "confirmation and will roll back"})
        return alerts

    def get_health(self, ctx) -> dict[str, Any]:
        snapshot = self._snapshot()
        wifi = snapshot.get("wifi", {})
        return {
            "services": {
                "hostapd": "up" if wifi.get("hostapd_running") else "down",
                "dnsmasq": "up" if self.netd.services._running() else "down",
                "dnsmasq_error": getattr(self.netd.services, "last_error", None),
                "nftables": "up" if nft.available() else "down",
            },
            "radios": {r["id"]: r.get("health") for r in wifi.get("radios", [])},
            "wans": {w["id"]: w.get("state") for w in snapshot.get("wans", [])},
            "thermal": snapshot.get("system", {}).get("thermal", {}).get("state"),
            "memory": snapshot.get("system", {}).get("memory", {}),
            "acceleration": snapshot.get("acceleration", {}),
            "event_counts": self.events.counts(since=now() - 86400),
        }

    # ------------------------------------------------------------------- ports

    def get_ports(self, ctx) -> dict[str, Any]:
        return self._paginate(self._snapshot().get("ports", []), ctx.query)

    def put_port(self, ctx) -> dict[str, Any]:
        pid = ctx.params["id"]
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            if pid not in cfg["ports"]:
                raise KeyError(f"unknown port '{pid}'")
            cfg["ports"][pid].update(body)

        return self._commit(ctx.principal, ctx.source_ip, f"port {pid}", mutate)

    # ---------------------------------------------------------------- networks

    def get_networks(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        states = {n["id"]: n for n in self._snapshot().get("networks", [])}
        items = [{"id": nid, "config": net, "state": states.get(nid, {})}
                 for nid, net in cfg.get("networks", {}).items()]
        return self._paginate(items, ctx.query)

    def post_network(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        nid = body.pop("id", None)
        if not nid:
            raise ApiError(400, "bad_request", "id is required")

        def mutate(cfg: dict[str, Any]) -> None:
            if nid in cfg["networks"]:
                raise ValueError(f"network '{nid}' already exists")
            base = schema.default_config()["networks"]["default"]
            cfg["networks"][nid] = {**base, **body}

        return self._commit(ctx.principal, ctx.source_ip, f"create network {nid}", mutate)

    def put_network(self, ctx) -> dict[str, Any]:
        nid = ctx.params["id"]
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            if nid not in cfg["networks"]:
                raise KeyError(f"unknown network '{nid}'")
            _deep_update(cfg["networks"][nid], body)

        return self._commit(ctx.principal, ctx.source_ip, f"network {nid}", mutate)

    def delete_network(self, ctx) -> dict[str, Any]:
        nid = ctx.params["id"]

        def mutate(cfg: dict[str, Any]) -> None:
            if nid not in cfg["networks"]:
                raise KeyError(f"unknown network '{nid}'")
            if len(cfg["networks"]) == 1:
                raise ValueError("cannot delete the last network")
            users = [w for w, wn in cfg.get("wifi", {}).get("networks", {}).items()
                     if wn.get("network") == nid]
            if users:
                raise ValueError(f"network is used by SSID(s): {', '.join(users)}")
            cfg["networks"].pop(nid)
            for port in cfg["ports"].values():
                if port.get("network") == nid:
                    port["network"] = None

        return self._commit(ctx.principal, ctx.source_ip, f"delete network {nid}", mutate)

    # -------------------------------------------------------------------- wans

    def get_wans(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        states = {w["id"]: w for w in self._snapshot().get("wans", [])}
        items = [{"id": wid, "config": wan, "state": states.get(wid, {})}
                 for wid, wan in cfg.get("wans", {}).items()]
        return {"items": items, "primary": self._snapshot().get("primary_wan"),
                "multiwan": cfg.get("multiwan", {})}

    def put_wan(self, ctx) -> dict[str, Any]:
        wid = ctx.params["id"]
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            if wid not in cfg["wans"]:
                base = schema.default_config()["wans"]["wan1"]
                cfg["wans"][wid] = {**base, **body}
            else:
                _deep_update(cfg["wans"][wid], body)

        return self._commit(ctx.principal, ctx.source_ip, f"WAN {wid}", mutate)

    # ---------------------------------------------------------------- firewall

    def get_firewall(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        return {"firewall": cfg.get("firewall", {}), "zones": list(schema.ZONES),
                "counters": nft.counters()}

    def put_firewall(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        return self._commit(ctx.principal, ctx.source_ip, "firewall",
                            lambda cfg: _deep_update(cfg["firewall"], body))

    def get_firewall_counters(self, ctx) -> dict[str, Any]:
        return {"counters": nft.counters()}

    def get_nat(self, ctx) -> dict[str, Any]:
        return {"nat": self.config.get_running().get("nat", {})}

    def put_nat(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        return self._commit(ctx.principal, ctx.source_ip, "NAT",
                            lambda cfg: _deep_update(cfg["nat"], body))

    # ----------------------------------------------------------------- routing

    def get_routing(self, ctx) -> dict[str, Any]:
        from .adapters import rtnl
        return {"routing": self.config.get_running().get("routing", {}),
                "policy_routes": self.config.get_running().get("policy_routes", []),
                "table_v4": rtnl.routes(4, table="main"),
                "table_v6": rtnl.routes(6, table="main")}

    def put_routing(self, ctx) -> dict[str, Any]:
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            if "policy_routes" in body:
                cfg["policy_routes"] = body.pop("policy_routes")
            _deep_update(cfg["routing"], body)

        return self._commit(ctx.principal, ctx.source_ip, "routing", mutate)

    # ------------------------------------------------------ traffic / DNS

    def get_services(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        traffic = getattr(self.netd, "traffic", None)
        traffic_status = traffic.status(cfg) if traffic else {
            "requested": bool(cfg.get("qos", {}).get("enabled")),
            "effective": False, "tool_available": None,
            "interfaces": [], "error": None,
        }
        dns_service = getattr(self.netd, "services", None)
        dns_running = bool(dns_service and dns_service._running())
        return {
            "qos": cfg.get("qos", {}),
            "dns": cfg.get("dns", {}),
            "status": {
                "qos": traffic_status,
                "dns": {
                    "running": dns_running,
                    "error": getattr(dns_service, "last_error", None),
                },
            },
        }

    def put_services(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        if not isinstance(body, dict):
            raise ApiError(400, "bad_request", "request body must be an object")
        unknown = sorted(set(body) - {"qos", "dns"})
        if unknown:
            raise ApiError(400, "bad_request",
                           f"unknown service setting(s): {', '.join(unknown)}")
        if not body:
            raise ApiError(400, "bad_request", "qos or dns settings are required")

        def mutate(cfg: dict[str, Any]) -> None:
            for key in ("qos", "dns"):
                if key in body:
                    if not isinstance(body[key], dict):
                        raise ValueError(f"{key} must be an object")
                    _deep_update(cfg.setdefault(key, {}), body[key])

        return self._commit(ctx.principal, ctx.source_ip,
                            "traffic and DNS services", mutate)

    # -------------------------------------------------------------------- wifi

    def get_wifi(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        wifi = self._snapshot().get("wifi", {})
        return {"config": cfg.get("wifi", {}), "state": wifi}

    def get_radios(self, ctx) -> dict[str, Any]:
        # The MLO capability travels with the radio list because the wireless
        # network form needs it to enable or explain its MLO control, and there
        # is no separate MLO page to fetch it from any more.
        return {"items": self._snapshot().get("wifi", {}).get("radios", []),
                "mlo": self.wifid.capabilities().get("mlo", {})}

    def put_radio(self, ctx) -> dict[str, Any]:
        rid = ctx.params["id"]
        body = ctx.json()
        capabilities = self.wifid.capabilities()
        if rid not in capabilities["radios"]:
            raise ApiError(404, "not_found", f"radio '{rid}' is not present")

        def mutate(cfg: dict[str, Any]) -> None:
            radios = cfg["wifi"].setdefault("radios", {})
            current = radios.setdefault(rid, {
                "enabled": True, "band": capabilities["radios"][rid]["band"],
                "channel": "auto",
                "channel_width": max(capabilities["radios"][rid]["widths"]),
                "tx_power": "auto"})
            current.update(body)
            # The band is hardware truth, not a user setting.
            current["band"] = capabilities["radios"][rid]["band"]

        return self._commit(ctx.principal, ctx.source_ip, f"radio {rid}", mutate)

    def get_wifi_networks(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        bsses = self._snapshot().get("wifi", {}).get("bsses", [])
        items = []
        for wnid, wnet in cfg.get("wifi", {}).get("networks", {}).items():
            own = [b for b in bsses if b.get("wireless_network") == wnid]
            items.append({
                "id": wnid,
                "config": _redact_secrets(wnet),
                "bsses": own,
                "client_count": sum(b.get("client_count", 0) for b in own),
                "mld": next((m["id"] for m in
                             self._snapshot().get("wifi", {}).get("mlds", [])
                             if m.get("wireless_network") == wnid), None),
            })
        return {"items": items}

    def post_wifi_network(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        wnid = body.pop("id", None)
        if not wnid:
            raise ApiError(400, "bad_request", "id is required")

        def mutate(cfg: dict[str, Any]) -> None:
            networks = cfg["wifi"].setdefault("networks", {})
            if wnid in networks:
                raise ValueError(f"wireless network '{wnid}' already exists")
            networks[wnid] = {
                "ssid": body.get("ssid", wnid), "enabled": True, "hidden": False,
                "network": "default", "bands": ["2g", "5g"],
                "security": {"mode": "wpa2-wpa3", "pmf": "optional"},
                "client_isolation": False, "bss_transition": True,
                "neighbor_report": True, "fast_roaming": False,
            } | body

        return self._commit(ctx.principal, ctx.source_ip, f"create SSID {wnid}", mutate)

    def put_wifi_network(self, ctx) -> dict[str, Any]:
        wnid = ctx.params["id"]
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            networks = cfg["wifi"].get("networks", {})
            if wnid not in networks:
                raise KeyError(f"unknown wireless network '{wnid}'")
            _deep_update(networks[wnid], body)

        return self._commit(ctx.principal, ctx.source_ip, f"SSID {wnid}", mutate)

    def delete_wifi_network(self, ctx) -> dict[str, Any]:
        wnid = ctx.params["id"]

        def mutate(cfg: dict[str, Any]) -> None:
            networks = cfg["wifi"].get("networks", {})
            if wnid not in networks:
                raise KeyError(f"unknown wireless network '{wnid}'")
            mlds = [m for m, mld in cfg["wifi"].get("mlds", {}).items()
                    if mld.get("wireless_network") == wnid]
            if mlds:
                raise ValueError(f"SSID is used by MLD(s): {', '.join(mlds)}")
            networks.pop(wnid)

        return self._commit(ctx.principal, ctx.source_ip, f"delete SSID {wnid}", mutate)

    # --------------------------------------------------------------------- MLO

    def get_mlo(self, ctx) -> dict[str, Any]:
        cfg = self.config.get_running()
        capabilities = self.wifid.capabilities()
        states = {m["id"]: m for m in self._snapshot().get("wifi", {}).get("mlds", [])}
        declared = cfg.get("wifi", {}).get("mlds", {})
        items = [{"id": mid, "config": mld, "state": states.get(mid, {}),
                  "wireless_network": mld.get("wireless_network"),
                  "link_count": states.get(mid, {}).get("link_count"),
                  "derived": False}
                 for mid, mld in declared.items()]
        # MLDs derived from a wireless network's `mlo` flag exist only in the
        # plan, not in the stored config. They are the normal case now that the
        # UI has no separate MLO object, so the listing has to include them or
        # an SSID's MLO would be invisible over the API.
        for mid, state in sorted(states.items()):
            if mid in declared:
                continue
            items.append({"id": mid, "config": None, "state": state,
                          "wireless_network": state.get("wireless_network"),
                          "link_count": state.get("link_count"),
                          "derived": True})
        return {"items": items, "capability": capabilities["mlo"]}

    def post_mld(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        mid = body.pop("id", None)
        if not mid:
            raise ApiError(400, "bad_request", "id is required")
        capability = self.wifid.capabilities()["mlo"]
        if not capability["supported"]:
            raise ApiError(412, "mlo_unavailable",
                           capability["reason"] or "MLO is not available on this device",
                           capability)

        def mutate(cfg: dict[str, Any]) -> None:
            mlds = cfg["wifi"].setdefault("mlds", {})
            if mid in mlds:
                raise ValueError(f"MLD '{mid}' already exists")
            mlds[mid] = {"name": body.get("name", mid), "enabled": True,
                         "links": [], "link_steering": "auto"} | body

        return self._commit(ctx.principal, ctx.source_ip, f"create MLD {mid}", mutate)

    def put_mld(self, ctx) -> dict[str, Any]:
        mid = ctx.params["id"]
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            mlds = cfg["wifi"].get("mlds", {})
            if mid not in mlds:
                raise KeyError(f"unknown MLD '{mid}'")
            _deep_update(mlds[mid], body)

        return self._commit(ctx.principal, ctx.source_ip, f"MLD {mid}", mutate)

    def delete_mld(self, ctx) -> dict[str, Any]:
        mid = ctx.params["id"]

        def mutate(cfg: dict[str, Any]) -> None:
            if mid not in cfg["wifi"].get("mlds", {}):
                raise KeyError(f"unknown MLD '{mid}'")
            cfg["wifi"]["mlds"].pop(mid)

        return self._commit(ctx.principal, ctx.source_ip, f"delete MLD {mid}", mutate)

    def get_regulatory(self, ctx) -> dict[str, Any]:
        reg = self.config.get_running().get("wifi", {}).get("regulatory") or {}
        return {"environment": reg.get("environment", "indoor"),
                "six_ghz_power": reg.get("six_ghz_power", "lpi")}

    def put_regulatory(self, ctx) -> dict[str, Any]:
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            reg = cfg["wifi"].setdefault("regulatory", {})
            for key in ("environment", "six_ghz_power"):
                if key in body:
                    reg[key] = body[key]

        return self._commit(ctx.principal, ctx.source_ip,
                            "regulatory environment", mutate)

    def get_wifi_clients(self, ctx) -> dict[str, Any]:
        clients = self._snapshot().get("wifi", {}).get("clients", [])
        if ctx.query.get("mlo_only", ["0"])[0] in ("1", "true"):
            clients = [c for c in clients if c.get("is_mlo")]
        return self._paginate(clients, ctx.query)

    def get_neighbours(self, ctx) -> dict[str, Any]:
        # A scan is expensive; only run it when explicitly requested.
        if ctx.query.get("scan", ["0"])[0] in ("1", "true"):
            return {"items": self.wifid.scan_neighbours(self.config.get_running())}
        return {"items": [], "hint": "pass ?scan=1 to trigger a passive scan"}

    def post_radio_recover(self, ctx) -> dict[str, Any]:
        rid = ctx.params["id"]
        ok = self.wifid.recover_radio(rid, self.config.get_running())
        return {"ok": ok, "radio": rid}

    def get_wifi_capabilities(self, ctx) -> dict[str, Any]:
        return self.wifid.capabilities()

    # -------------------------------------------------- channel analysis / ACS

    def _require_rf(self):
        if self.rf is None:
            raise ApiError(501, "not_available",
                           "RF analysis is not wired up in this build")
        return self.rf

    def get_channels(self, ctx) -> dict[str, Any]:
        """Per-channel occupancy for every radio, plus a recommendation.

        Reads cached scan data; pass ?scan=1 (or POST /wifi/channels/scan) to
        refresh it, since a scan briefly takes the radio off-channel.
        """
        rf = self._require_rf()
        cfg = self.config.get_running()
        if ctx.query.get("scan", ["0"])[0] in ("1", "true"):
            rf.scan(cfg)
        else:
            rf.refresh_survey(cfg)
        return rf.analyse(cfg)

    def post_channel_scan(self, ctx) -> dict[str, Any]:
        rf = self._require_rf()
        body = ctx.json() if ctx.has_body else {}
        radios = body.get("radios")
        result = rf.scan(self.config.get_running(), radios=radios,
                         passive=body.get("passive", True))
        return {"scanned": result}

    def post_channel_optimize(self, ctx) -> dict[str, Any]:
        rf = self._require_rf()
        body = ctx.json() if ctx.has_body else {}
        report = rf.optimise(
            self.config.get_running(),
            radios=body.get("radios"),
            force=bool(body.get("force")),
            dry_run=bool(body.get("dry_run")),
            rescan=body.get("rescan", True))
        # A channel change alters runtime state, so refresh the read cache.
        try:
            self.sampler.sample()
        except Exception:  # noqa: BLE001
            log.debug("post-optimise resample failed", exc_info=True)
        return report

    def put_channel_settings(self, ctx) -> dict[str, Any]:
        body = ctx.json()

        def mutate(cfg: dict[str, Any]) -> None:
            _deep_update(cfg["wifi"].setdefault("channel_optimisation", {}), body)

        return self._commit(ctx.principal, ctx.source_ip,
                            "channel optimisation settings", mutate, confirm=False)

    def get_channel_history(self, ctx) -> dict[str, Any]:
        rf = self._require_rf()
        radio = ctx.query.get("radio", [None])[0]
        return {"items": rf.history(radio)}

    # ----------------------------------------------------------------- clients

    def get_clients(self, ctx) -> dict[str, Any]:
        clients = self._snapshot().get("clients", [])
        search = (ctx.query.get("search", [""])[0] or "").lower()
        if search:
            clients = [c for c in clients
                       if search in (c.get("name") or "").lower()
                       or search in c["mac"]
                       or search in (c.get("ipv4") or "")]
        if ctx.query.get("online", [""])[0] in ("1", "true"):
            clients = [c for c in clients if c.get("online")]
        return self._paginate(clients, ctx.query)

    def get_client(self, ctx) -> dict[str, Any]:
        mac = ctx.params["mac"]
        client = self.clients.get(mac)
        if client is None:
            raise ApiError(404, "not_found", f"no client {mac}")
        return {"client": client, "history": self.clients.history(mac)}

    def put_client(self, ctx) -> dict[str, Any]:
        mac = ctx.params["mac"]
        body = ctx.json()
        ok = self.clients.update(mac, **body)
        if not ok:
            raise ApiError(404, "not_found", f"no client {mac} or nothing to update")
        # A fixed IP is configuration, so it goes through configd.
        if "fixed_ip" in body and body["fixed_ip"]:
            client = self.clients.get(mac) or {}
            network_id = client.get("network") or "default"

            def mutate(cfg: dict[str, Any]) -> None:
                dhcp = cfg["networks"][network_id].setdefault("dhcp", {})
                reservations = dhcp.setdefault("reservations", [])
                reservations = [r for r in reservations if r["mac"] != mac.lower()]
                reservations.append({"mac": mac.lower(), "address": body["fixed_ip"],
                                     "hostname": client.get("hostname")})
                dhcp["reservations"] = reservations

            self._commit(ctx.principal, ctx.source_ip, f"fixed IP for {mac}", mutate,
                         confirm=False)
        return {"ok": True}

    def post_client_action(self, ctx) -> dict[str, Any]:
        mac = ctx.params["mac"]
        action = ctx.params["action"]
        if action == "disconnect":
            return {"ok": self.wifid.disconnect_client(mac)}
        if action == "block":
            self.clients.update(mac, blocked=True)
            return {"ok": self.wifid.block_client(mac)}
        if action == "unblock":
            self.clients.update(mac, blocked=False)
            return {"ok": self.wifid.unblock_client(mac)}
        if action == "steer":
            target = ctx.json().get("bssid")
            if not target:
                raise ApiError(400, "bad_request", "bssid is required")
            return {"ok": self.wifid.steer_client(mac, target)}
        raise ApiError(400, "bad_request", f"unknown action '{action}'")

    # --------------------------------------------------------------- telemetry

    def get_telemetry(self, ctx) -> dict[str, Any]:
        return self._snapshot()

    def get_series(self, ctx) -> dict[str, Any]:
        prefix = ctx.query.get("prefix", [""])[0]
        window = float(ctx.query.get("window", ["300"])[0])
        return {"series": self.telemetry.snapshot(prefix, window)}

    def get_series_history(self, ctx) -> dict[str, Any]:
        name = ctx.query.get("name", [None])[0]
        if not name:
            raise ApiError(400, "bad_request", "name is required")
        seconds = float(ctx.query.get("seconds", ["86400"])[0])
        return self.telemetry.history(name, seconds=seconds)

    def get_events(self, ctx) -> dict[str, Any]:
        query = ctx.query
        return {"items": self.events.query(
            limit=min(int(query.get("limit", ["200"])[0]), 1000),
            offset=int(query.get("offset", ["0"])[0]),
            severities=query.get("severity"),
            kinds=query.get("kind"),
            subsystem=query.get("subsystem", [None])[0],
            search=query.get("search", [None])[0],
        ), "counts": self.events.counts(since=now() - 86400)}

    def get_topology(self, ctx) -> dict[str, Any]:
        """Gateway-rooted tree: internet -> gateway -> ports/VLANs/Wi-Fi -> clients."""
        snapshot = self._snapshot()
        clients = [c for c in snapshot.get("clients", []) if c.get("online")]
        nodes: list[dict[str, Any]] = []

        primary = snapshot.get("primary_wan")
        nodes.append({"id": "internet", "type": "internet", "parent": None,
                      "label": "Internet",
                      "state": next((w["state"] for w in snapshot.get("wans", [])
                                     if w["id"] == primary), "down")})
        nodes.append({"id": "gateway", "type": "gateway", "parent": "internet",
                      "label": snapshot.get("system", {}).get("board", {})
                      .get("model", "Gateway")})

        for port in snapshot.get("ports", []):
            if port["role"] != "lan":
                continue
            nodes.append({"id": f"port:{port['id']}", "type": "port",
                          "parent": "gateway", "label": port["name"],
                          "state": "up" if port["link_up"] else "down",
                          "speed_mbps": port.get("speed_mbps")})

        for network in snapshot.get("networks", []):
            nodes.append({"id": f"net:{network['id']}", "type": "network",
                          "parent": "gateway", "label": network["name"],
                          "vlan": network.get("vlan"), "subnet": network.get("subnet")})

        for bss in snapshot.get("wifi", {}).get("bsses", []):
            parent = f"net:{bss.get('network')}"
            nodes.append({"id": f"bss:{bss['interface']}", "type": "wifi",
                          "parent": parent,
                          "label": f"{bss.get('ssid')} · {bss.get('band')}",
                          "state": bss.get("state"), "mld": bss.get("mld")})

        for client in clients:
            wifi = client.get("wireless") or {}
            if wifi:
                parent = f"bss:{wifi.get('interface')}"
            elif client.get("port"):
                parent = f"port:{client['port']}"
            else:
                parent = f"net:{client.get('network') or 'default'}"
            nodes.append({
                "id": f"client:{client['mac']}", "type": "client", "parent": parent,
                "label": client.get("name") or client["mac"],
                "ipv4": client.get("ipv4"),
                "connection": client.get("connection"),
                "rssi": wifi.get("rssi"), "is_mlo": wifi.get("is_mlo", False),
            })
        return {"nodes": nodes}

    # ------------------------------------------------------------------ config

    def get_config(self, ctx) -> dict[str, Any]:
        return {"running": _redact_secrets(self.config.get_running()),
                "candidate": _redact_secrets(self.config.get_candidate())}

    def get_pending(self, ctx) -> dict[str, Any]:
        return {"changes": self.config.pending_changes(),
                "pending_commit": self.config.pending_commit}

    def post_commit(self, ctx) -> dict[str, Any]:
        body = ctx.json() if ctx.has_body else {}
        try:
            return self.config.commit(
                user=ctx.principal.name, source_ip=ctx.source_ip,
                summary=body.get("summary", "manual commit"),
                rollback_seconds=int(body.get("rollback_seconds", 120)))
        except CommitError as exc:
            raise ApiError(409, f"commit_{exc.stage}", str(exc),
                           {"txid": exc.txid, "details": exc.details}) from exc

    def post_confirm(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        txid = body.get("txid")
        if not txid:
            raise ApiError(400, "bad_request", "txid is required")
        return {"ok": self.config.confirm(txid, user=ctx.principal.name)}

    def post_discard(self, ctx) -> dict[str, Any]:
        self.config.discard_candidate()
        return {"ok": True}

    def get_revisions(self, ctx) -> dict[str, Any]:
        return {"items": self.config.revisions()}

    def post_rollback(self, ctx) -> dict[str, Any]:
        try:
            return self.config.rollback_to_revision(
                int(ctx.params["id"]), user=ctx.principal.name,
                source_ip=ctx.source_ip)
        except CommitError as exc:
            raise ApiError(409, "rollback_failed", str(exc),
                           {"details": exc.details}) from exc

    def get_audit(self, ctx) -> dict[str, Any]:
        limit = min(int(ctx.query.get("limit", ["200"])[0]), 1000)
        offset = int(ctx.query.get("offset", ["0"])[0])
        return {"items": self.config.audit_log(limit, offset)}

    # ------------------------------------------------------------------- users

    def get_users(self, ctx) -> dict[str, Any]:
        users = self.config.get_running().get("users", {})
        return {"items": [{"username": name, "role": data.get("role"),
                           "created": data.get("created"),
                           "mfa_enabled": bool(data.get("totp_secret"))}
                          for name, data in users.items()]}

    def post_user(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        try:
            self.auth.create_user(body["username"], body["password"],
                                  body.get("role", "read-only"),
                                  actor=ctx.principal.name)
        except (KeyError, ValueError) as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        return {"ok": True}

    def put_user(self, ctx) -> dict[str, Any]:
        name = ctx.params["name"]
        body = ctx.json()
        if "password" in body:
            try:
                self.auth.set_password(name, body["password"], actor=ctx.principal.name)
            except ValueError as exc:
                raise ApiError(400, "bad_request", str(exc)) from exc
        if body.get("enable_mfa"):
            secret = self.auth.enable_totp(name, actor=ctx.principal.name)
            return {"ok": True, "totp_secret": secret}
        if "role" in body:
            def mutate(cfg: dict[str, Any]) -> None:
                if name not in cfg["users"]:
                    raise KeyError(f"unknown user '{name}'")
                cfg["users"][name]["role"] = body["role"]
            self._commit(ctx.principal, ctx.source_ip, f"role for {name}", mutate,
                         confirm=False)
        return {"ok": True}

    def delete_user(self, ctx) -> dict[str, Any]:
        name = ctx.params["name"]
        if name == ctx.principal.name:
            raise ApiError(400, "bad_request", "you cannot delete your own account")
        try:
            self.auth.delete_user(name, actor=ctx.principal.name)
        except (ValueError, PermissionError) as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        return {"ok": True}

    def get_rbac(self, ctx) -> dict[str, Any]:
        return {"roles": {r: sorted(p) for r, p in ROLE_PERMISSIONS.items()},
                "permissions": ALL_PERMISSIONS}

    # ----------------------------------------------------------------- backups

    def get_backup(self, ctx) -> dict[str, Any]:
        """Config-only backup. ART/calibration is never user configuration."""
        cfg = self.config.get_running()
        return {"version": schema.SCHEMA_VERSION, "created": now(),
                "board": platform.board(), "config": cfg,
                "note": "contains secrets; store securely. ART/calibration excluded."}

    def post_backup(self, ctx) -> dict[str, Any]:
        body = ctx.json()
        incoming = body.get("config")
        if not isinstance(incoming, dict):
            raise ApiError(400, "bad_request", "config object is required")

        def mutate(cfg: dict[str, Any]) -> None:
            cfg.clear()
            cfg.update(incoming)

        return self._commit(ctx.principal, ctx.source_ip, "restore backup", mutate,
                            confirm=True)


def _deep_update(target: dict[str, Any], updates: dict[str, Any]) -> None:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


SECRET_KEYS = ("passphrase", "password", "password_hash", "secret", "psk", "api_key",
               "private_key", "totp_secret", "hash", "auth_secret", "acct_secret")


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("********" if any(s in k.lower() for s in SECRET_KEYS)
                    else _redact_secrets(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_secrets(v) for v in value]
    return value


# ==========================================================================
# HTTP plumbing
# ==========================================================================

class RequestContext:
    def __init__(self, handler: "ApiHandler", params: dict[str, str]):
        self.handler = handler
        self.params = params
        self.query = handler.query
        self.principal: Principal = handler.principal  # type: ignore[assignment]
        self.source_ip = handler.source_ip
        self.agent = handler.headers.get("User-Agent", "")
        self.session_token = handler.session_token
        self._body = handler.body

    @property
    def has_body(self) -> bool:
        return bool(self._body)

    def json(self) -> dict[str, Any]:
        if not self._body:
            return {}
        try:
            data = json.loads(self._body)
        except json.JSONDecodeError as exc:
            raise ApiError(400, "invalid_json", f"body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ApiError(400, "invalid_json", "body must be a JSON object")
        return data

    def set_session_cookie(self, token: str) -> None:
        self.handler.extra_headers.append(
            ("Set-Cookie",
             f"sbegw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"))

    def clear_session_cookie(self) -> None:
        self.handler.extra_headers.append(
            ("Set-Cookie", "sbegw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"))


class ApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "sbegw"
    sys_version = ""
    service: ApiService = None  # type: ignore[assignment]

    # -- logging goes to our logger, not stderr
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---------------------------------------------------------------- helpers

    @property
    def source_ip(self) -> str:
        # nginx sits in front; trust its header only from loopback.
        if self.client_address[0] in ("127.0.0.1", "::1"):
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in self.extra_headers:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, exc: ApiError) -> None:
        self._send_json(exc.status, {"error": {"code": exc.code,
                                               "message": exc.message,
                                               "details": exc.details}})

    def _cookies(self) -> dict[str, str]:
        raw = self.headers.get("Cookie", "")
        out: dict[str, str] = {}
        for part in raw.split(";"):
            if "=" in part:
                key, _, value = part.partition("=")
                out[key.strip()] = value.strip()
        return out

    # ------------------------------------------------------------------ verbs

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        self.extra_headers: list[tuple[str, str]] = []
        self.body = b""
        self.principal = None
        self.session_token = None
        service = self.service

        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or parsed.path
        self.query = urllib.parse.parse_qs(parsed.query)

        try:
            if path == f"{API_PREFIX}/stream":
                self._handle_stream()
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError(413, "too_large", "request body too large")
            if length:
                self.body = self.rfile.read(length)

            matched = service.router.match(method, path)
            if matched is None:
                raise ApiError(404, "not_found", f"no route for {method} {path}")
            route, params = matched

            if route.permission is not None:
                self._authenticate()
                if method != "GET":
                    self._check_csrf()
                if not self.principal.can(route.permission):
                    raise ApiError(403, "forbidden",
                                   f"{self.principal.role} lacks {route.permission}")

            ctx = RequestContext(self, params)
            result = route.handler(ctx)
            self._send_json(200, result)

        except ApiError as exc:
            self._error(exc)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            log.error("unhandled error on %s %s: %s\n%s", method, path, exc,
                      traceback.format_exc())
            self._error(ApiError(500, "internal_error", str(exc)))

    def _authenticate(self) -> None:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            principal = self.service.auth.principal_for_token(header[7:].strip())
            if principal is None:
                raise ApiError(401, "unauthorized", "invalid API token")
            self.principal = principal
            return
        token = self._cookies().get("sbegw_session")
        if not token:
            raise ApiError(401, "unauthorized", "authentication required")
        principal = self.service.auth.principal_for_session(token)
        if principal is None:
            raise ApiError(401, "session_expired", "session expired; sign in again")
        self.session_token = token
        self.principal = principal

    def _check_csrf(self) -> None:
        # Token-authenticated callers are not browser sessions and are exempt.
        if self.principal and self.principal.kind == "token":
            return
        expected = self.service.auth.csrf_for_session(self.session_token or "")
        provided = self.headers.get("X-CSRF-Token", "")
        if not expected or provided != expected:
            raise ApiError(403, "csrf_failed", "missing or invalid CSRF token")

    def _handle_stream(self) -> None:
        """Server-sent events: telemetry frames plus live events."""
        try:
            self._authenticate()
        except ApiError as exc:
            self._error(exc)
            return
        if not self.principal.can("system.read"):
            self._error(ApiError(403, "forbidden", "system.read required"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q = self.service.stream.register()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    kind, payload = q.get(timeout=15)
                    frame = (f"event: {kind}\n"
                             f"data: {json.dumps(payload, default=str)}\n\n")
                except queue.Empty:
                    frame = ": keepalive\n\n"
                self.wfile.write(frame.encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.service.stream.unregister(q)


class ApiServer:
    def __init__(self, service: ApiService, host: str = "127.0.0.1",
                 port: int = 8081):
        handler = type("BoundApiHandler", (ApiHandler,), {"service": service})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.service = service
        self.host = host
        self.port = port

    def serve_forever(self) -> None:
        log.info("API listening on http://%s:%s%s", self.host, self.port, API_PREFIX)
        self.httpd.serve_forever(poll_interval=0.5)

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, daemon=True,
                                  name="sbegw-api")
        thread.start()
        return thread

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
