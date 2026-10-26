from __future__ import annotations

import time
from collections import defaultdict, deque
from http.cookies import CookieError, SimpleCookie
import re
from threading import Lock
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import (
    SESSION_COOKIE,
    AuthContext,
    validate_browser_session,
    validate_csrf,
    validate_ide_capability,
    validate_pending_ide_capability,
)
from .db import Runtime


_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MAX_SOURCE_SNAPSHOT_REQUEST_BYTES = 112 * 1024 * 1024
_CREDENTIAL_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "bootstrap",
    "capability",
    "passphrase",
    "private_key",
    "secret_key",
    "session_key",
    "signature",
    "token",
    "x_amz_signature",
}
_CREDENTIAL_QUERY_SUFFIXES = ("password", "passwd", "secret", "token", "credential", "credentials")
_SECURITY_HEADERS = {
    b"content-security-policy": b"default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    b"referrer-policy": b"no-referrer",
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
}

_ADVISOR_TRIAGE_REQUEST = re.compile(r"/v1/findings/([1-9][0-9]*)/triage\Z")


class AdvisorRequestAudit:
    """Process-authoritative bounded ledger of admitted finding-triage POSTs."""

    def __init__(
        self,
        *,
        maximum_entries: int = 8192,
        instance_id: str | None = None,
    ) -> None:
        if not 1 <= maximum_entries <= 65_536:
            raise ValueError("Advisor request audit bound is invalid")
        identity = instance_id or uuid4().hex
        if re.fullmatch(r"[0-9a-f]{32}", identity) is None:
            raise ValueError("Advisor request audit instance identity is invalid")
        self._instance_id = identity
        self._entries: deque[tuple[int, int]] = deque(maxlen=maximum_entries)
        self._latest_sequence = 0
        self._lock = Lock()

    def observe(self, method: str, path: str) -> None:
        if method != "POST":
            return
        match = _ADVISOR_TRIAGE_REQUEST.fullmatch(path)
        if match is None:
            return
        identity = match.group(1)
        if len(identity) > 10:
            return
        finding_id = int(identity)
        if finding_id > 2_147_483_647:
            return
        with self._lock:
            self._latest_sequence += 1
            self._entries.append((self._latest_sequence, finding_id))

    def snapshot(self, finding_id: int, after_sequence: int) -> dict[str, str | int | bool]:
        if finding_id < 1 or after_sequence < 0:
            raise ValueError("Advisor request audit query is invalid")
        with self._lock:
            latest_sequence = self._latest_sequence
            retained_from_sequence = (
                self._entries[0][0] if self._entries else latest_sequence + 1
            )
            cursor_retained = bool(
                after_sequence <= latest_sequence
                and after_sequence >= retained_from_sequence - 1
            )
            matching_request_count = sum(
                1
                for sequence, observed_finding_id in self._entries
                if sequence > after_sequence and observed_finding_id == finding_id
            ) if cursor_retained else 0
            return {
                "schema": "lomo-advisor-request-audit/v1",
                "instance_id": self._instance_id,
                "finding_id": finding_id,
                "latest_sequence": latest_sequence,
                "retained_from_sequence": retained_from_sequence,
                "requested_after_sequence": after_sequence,
                "matching_request_count": matching_request_count,
                "cursor_retained": cursor_retained,
            }


_IDE_ROUTE_SCOPES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # The existing capability admits only the request. Mutating/reading Git
    # evidence additionally requires exact repository/member owner approval in
    # the route; no retained IDE capability is silently expanded or replaced.
    ("GET", re.compile(r"/v1/git/push-protection(?:/[0-9a-f]{64})?\Z"), "project:resolve"),
    ("POST", re.compile(r"/v1/git/push-protection\Z"), "project:create"),
    ("PATCH", re.compile(r"/v1/git/push-protection/[0-9a-f]{64}\Z"), "project:resolve"),
    ("POST", re.compile(r"/v1/git/push-protection/[0-9a-f]{64}/(?:observation|check|trees|remove)\Z"), "project:resolve"),
    (
        "POST",
        re.compile(r"/v1/auth/ide/browser-invitations\Z"),
        "browser:invite",
    ),
    (
        "GET",
        re.compile(
            r"/v1/auth/ide/browser-invitations/[A-Za-z0-9_-]{24}/membership\Z"
        ),
        "browser:invite",
    ),
    ("GET", re.compile(r"/v1/events\Z"), "event:read"),
    (
        "POST",
        re.compile(r"/v1/ide/source-open-commands/[0-9a-f]{32}/ack\Z"),
        "source:open-ack",
    ),
    (
        "GET",
        re.compile(r"/v1/ide/source-open-commands/[0-9a-f]{32}/context\Z"),
        "source:open-context",
    ),
    ("GET", re.compile(r"/v1/advisor/providers\Z"), "finding:advisor"),
    ("GET", re.compile(r"/v1/advisor/triage-request-audit\Z"), "finding:advisor"),
    ("POST", re.compile(r"/v1/projects/resolve\Z"), "project:resolve"),
    ("POST", re.compile(r"/v1/sources/preview\Z"), "project:resolve"),
    ("POST", re.compile(r"/v1/projects\Z"), "project:create"),
    ("POST", re.compile(r"/v1/source-snapshots\Z"), "source:snapshot"),
    ("GET", re.compile(r"/v1/projects/[1-9][0-9]*/scans/latest\Z"), "scan:read"),
    ("POST", re.compile(r"/v1/scans\Z"), "scan:create"),
    ("GET", re.compile(r"/v1/scans/[1-9][0-9]*\Z"), "scan:read"),
    ("GET", re.compile(r"/v1/scans/[1-9][0-9]*/summary\Z"), "scan:read"),
    ("GET", re.compile(r"/v1/scans/[1-9][0-9]*/finding-files\Z"), "finding:read"),
    ("GET", re.compile(r"/v1/scans/[1-9][0-9]*/finding-diagnostics\Z"), "finding:read"),
    ("GET", re.compile(r"/v1/scans/[1-9][0-9]*/findings\Z"), "finding:read"),
    (
        "GET",
        re.compile(r"/v1/scans/[1-9][0-9]*/findings/[1-9][0-9]*\Z"),
        "finding:read",
    ),
    ("POST", re.compile(r"/v1/findings/[1-9][0-9]*/triage\Z"), "finding:advisor"),
    (
        "PATCH",
        re.compile(r"/v1/findings/[1-9][0-9]*/lifecycle\Z"),
        "finding:lifecycle",
    ),
    ("DELETE", re.compile(r"/v1/findings/[1-9][0-9]*\Z"), "finding:delete"),
    ("GET", re.compile(r"/v1/jobs/[1-9][0-9]*\Z"), "job:read"),
    ("POST", re.compile(r"/v1/jobs/[1-9][0-9]*/cancel\Z"), "job:cancel"),
)


def ide_scope_for_request(method: str, path: str) -> str | None:
    """Return the one explicit IDE action scope for an exact route."""

    normalized_method = method.upper()
    for allowed_method, pattern, scope in _IDE_ROUTE_SCOPES:
        if normalized_method == allowed_method and pattern.fullmatch(path):
            return scope
    return None


class SecurityBoundaryMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        runtime: Runtime,
        advisor_request_audit: AdvisorRequestAudit | None = None,
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.settings = runtime.settings
        self.advisor_request_audit = advisor_request_audit or AdvisorRequestAudit()
        self.allowed_origins = frozenset(self.settings.control_origin_list)
        self.control_hosts = frozenset(
            urlsplit(origin).netloc.lower()
            for origin in self.allowed_origins
        )
        self.allowed_hosts = frozenset(
            [urlsplit(origin).netloc.lower() for origin in self.allowed_origins]
            + self.settings.internal_host_list
        )
        self.attempts: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        path = str(scope.get("path", ""))
        method = str(scope.get("method", "GET")).upper()
        host = headers.get("host", "").lower()
        origin = (headers.get("origin") or "").rstrip("/")

        if host not in self.allowed_hosts:
            await self._reject(scope, receive, send, 400, "invalid host")
            return
        if origin and origin not in self.allowed_origins:
            await self._reject(scope, receive, send, 403, "invalid origin")
            return
        if method == "POST" and (path == "/v1/source-snapshots" or re.fullmatch(r"/v1/git/push-protection/[0-9a-f]{64}/trees", path)):
            declared_lengths = [
                value
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ]
            if len(declared_lengths) != 1 or not declared_lengths[0].isdigit():
                await self._reject(
                    scope,
                    receive,
                    send,
                    411,
                    "native source snapshots require one exact Content-Length",
                )
                return
            if int(declared_lengths[0]) > _MAX_SOURCE_SNAPSHOT_REQUEST_BYTES:
                await self._reject(
                    scope,
                    receive,
                    send,
                    413,
                    "native source snapshot request exceeds its encoded body limit",
                )
                return
        if self._has_query_credential(scope):
            # Uvicorn renders its access-log path from this mutable ASGI scope at
            # response start. Remove the submitted query before rejecting it so
            # a mistaken credential can never be copied into container logs.
            scope["query_string"] = b"redacted=1"
            await self._reject(scope, receive, send, 400, "credentials are forbidden in URLs")
            return
        if path == "/v1/auth/bootstrap" and origin not in self.allowed_origins:
            await self._reject(scope, receive, send, 403, "bootstrap requires the control origin")
            return
        retained_bootstrap_member = None
        if path == "/v1/auth/bootstrap":
            retained_bootstrap_member = await run_in_threadpool(
                self._validate_browser_session,
                self._cookie(headers, SESSION_COOKIE),
            )
        public_ide_enrollment = (
            method == "POST" and path == "/v1/auth/ide/enrollments"
        )
        if public_ide_enrollment and host not in self.control_hosts:
            await self._reject(
                scope,
                receive,
                send,
                403,
                "IDE enrollment requires the exact loopback control host",
            )
            return
        rate_limited_auth_attempt = (
            public_ide_enrollment
            or path == "/v1/auth/ide/enrollments/current/claim-first-owner"
            or (path == "/v1/auth/bootstrap" and retained_bootstrap_member is None)
        )
        if rate_limited_auth_attempt and self._rate_limited(path):
            await self._reject(scope, receive, send, 429, "too many authentication attempts")
            return

        context: AuthContext | None = None
        pending_self_route = (
            (method == "POST" and path == "/v1/auth/ide/activate")
            or (
                method == "POST"
                and path == "/v1/auth/ide/enrollments/current/claim-first-owner"
            )
            or (method == "DELETE" and path == "/v1/auth/ide/pending")
            or (
                method == "GET"
                and path == "/v1/auth/ide/enrollments/current/wait"
            )
        )
        protected = (
            path.startswith("/v1/")
            and path != "/v1/auth/bootstrap"
            and not public_ide_enrollment
        )
        protected = protected or path in {"/docs", "/redoc", "/openapi.json"}
        if protected:
            authorization = headers.get("authorization", "")
            if authorization:
                if not authorization.startswith("Bearer "):
                    await self._reject(scope, receive, send, 401, "invalid authorization")
                    return
                if pending_self_route:
                    context = await run_in_threadpool(
                        self._validate_pending_capability,
                        authorization[7:],
                        method == "POST" or path == "/v1/auth/ide/enrollments/current/wait",
                    )
                else:
                    context = await run_in_threadpool(
                        self._validate_capability,
                        authorization[7:],
                    )
                if context is not None:
                    required_scope = None if pending_self_route else ide_scope_for_request(method, path)
                    if not pending_self_route and (
                        required_scope is None or required_scope not in context.scopes
                    ):
                        await self._reject(
                            scope,
                            receive,
                            send,
                            403,
                            "IDE capability does not permit this endpoint",
                        )
                        return
            elif pending_self_route:
                context = None
            else:
                context = await run_in_threadpool(
                    self._validate_browser_session,
                    self._cookie(headers, SESSION_COOKIE),
                )
            if context is None:
                status = 429 if self._rate_limited("protected-auth-failure") else 401
                detail = "too many authentication attempts" if status == 429 else "authentication required"
                await self._reject(scope, receive, send, status, detail)
                return
            if context.kind == "browser" and method in _UNSAFE_METHODS:
                if origin not in self.allowed_origins:
                    await self._reject(scope, receive, send, 403, "state changes require the control origin")
                    return
                if not validate_csrf(headers.get("x-csrf-token", ""), context, self.settings):
                    await self._reject(scope, receive, send, 403, "invalid csrf token")
                    return

        scope.setdefault("state", {})["auth"] = context
        self.advisor_request_audit.observe(method, path)
        await self.app(
            scope,
            receive,
            self._secure_send(
                send,
                no_store=(
                    path != "/v1/events"
                    and (path.startswith("/v1/") or path in {"/docs", "/redoc", "/openapi.json"})
                ),
            ),
        )

    def _validate_capability(self, token: str) -> AuthContext | None:
        with self.runtime.session_factory() as db:
            return validate_ide_capability(token, db, self.settings)

    def _validate_pending_capability(
        self,
        token: str,
        allow_active: bool,
    ) -> AuthContext | None:
        with self.runtime.session_factory() as db:
            return validate_pending_ide_capability(
                token,
                db,
                self.settings,
                allow_active=allow_active,
            )

    def _validate_browser_session(self, token: str) -> AuthContext | None:
        with self.runtime.session_factory() as db:
            return validate_browser_session(token, db, self.settings)

    @staticmethod
    def _cookie(headers: Headers, key: str) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("cookie", ""))
            return cookie[key].value if key in cookie else ""
        except CookieError:
            return ""

    @staticmethod
    def _has_query_credential(scope: Scope) -> bool:
        raw = bytes(scope.get("query_string", b""))
        try:
            for key, _ in parse_qsl(raw.decode("utf-8"), keep_blank_values=True):
                normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
                compact = normalized.replace("_", "")
                if (
                    normalized in _CREDENTIAL_QUERY_KEYS
                    or compact in {"apikey", "accesstoken", "clientsecret"}
                    or normalized.endswith(_CREDENTIAL_QUERY_SUFFIXES)
                ):
                    return True
            return False
        except UnicodeDecodeError:
            return True

    def _rate_limited(self, key: str) -> bool:
        now = time.monotonic()
        attempts = self.attempts[key]
        while attempts and attempts[0] < now - 60:
            attempts.popleft()
        if len(attempts) >= 10:
            return True
        attempts.append(now)
        return False

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, status: int, detail: str) -> None:
        secure_send = SecurityBoundaryMiddleware._secure_send(send, no_store=True)
        await JSONResponse({"detail": detail}, status_code=status, headers={"Cache-Control": "no-store"})(scope, receive, secure_send)

    @staticmethod
    def _secure_send(send: Send, *, no_store: bool = False):
        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", []))
                if no_store:
                    raw_headers = [
                        (key, value)
                        for key, value in raw_headers
                        if key.lower() != b"cache-control"
                    ]
                existing = {key.lower() for key, _ in raw_headers}
                raw_headers.extend((key, value) for key, value in _SECURITY_HEADERS.items() if key not in existing)
                if no_store:
                    raw_headers.append((b"cache-control", b"no-store"))
                message["headers"] = raw_headers
            await send(message)

        return wrapped
