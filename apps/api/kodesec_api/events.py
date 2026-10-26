from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import select as io_select
import socket
from threading import Event as ThreadEvent, Lock, Thread, current_thread
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, event, func, inspect as sa_inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.attributes import flag_modified, set_committed_value

from .auth import (
    AuthContext,
    IdeStreamAuthorization,
    validate_ide_stream_authorization,
)
from .db import Runtime, SchemaSingletonStateError, get_runtime
from .models import EventDispatchState, EventOutbox, Finding, Job, Project, Scan


EVENT_SCHEMA_VERSION = 1
MAX_EVENT_BYTES = 4096
DISPATCH_BATCH_SIZE = 128
MAX_DISPATCH_BATCHES_PER_WAKE = 8
REPLAY_LIMIT = 256
RETENTION_EVENTS = 50_000
RETENTION_AGE = timedelta(hours=24)
KEEPALIVE_SECONDS = 15.0
MAX_INSTALLATION_CONNECTIONS = 32
MAX_SUBJECT_CONNECTIONS = 4
OUTBOX_PENDING_CHANNEL = "kodesec_outbox_pending"
EVENT_READY_CHANNEL = "kodesec_event_ready"

DOMAIN_EVENT_KINDS = frozenset(
    {"project.changed", "scan.changed", "job.changed", "findings.changed"}
)
TARGET_EVENT_KINDS = frozenset({"ide.source.open"})
AGGREGATE_TYPES = frozenset({"project", "scan", "job", "findings"})
CHANGES = frozenset({"created", "updated", "deleted"})
SCOPE_KEYS = frozenset({"project_id", "scan_id", "job_id"})
HINT_KEYS = frozenset({"status", "stage", "progress", "decision", "count"})
_MACHINE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DECIMAL_ID = re.compile(r"[1-9][0-9]*\Z")
_CURSOR = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_CURSOR = 2**63 - 1
_SESSION_EVENTS = "kodesec_event_outbox_intents"
_SESSION_NOTIFY_STAGED = "kodesec_event_outbox_notify_staged"
_listeners_lock = Lock()
_listeners_installed = False

router = APIRouter(tags=["events"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _authorization_wait_timeout(
    _authorization: IdeStreamAuthorization | None,
) -> float:
    return KEEPALIVE_SECONDS


async def _guard_stream_authorization(
    subscription: EventWakeSubscription,
    authorization: IdeStreamAuthorization | None,
    session_factory: sessionmaker[Session],
) -> None:
    subscription.check()
    if authorization is not None and not await asyncio.to_thread(
        _durable_stream_authorization_is_active,
        session_factory,
        authorization,
    ):
        raise EventAuthorizationRevoked("event stream authorization is not active")


def _durable_stream_authorization_is_active(
    session_factory: sessionmaker[Session],
    authorization: IdeStreamAuthorization,
) -> bool:
    with session_factory() as db:
        return validate_ide_stream_authorization(authorization, db)


class EventConnectionLimiter:
    """Small process-local safety bound; durable delivery remains in PostgreSQL."""

    def __init__(
        self,
        *,
        installation_limit: int = MAX_INSTALLATION_CONNECTIONS,
        subject_limit: int = MAX_SUBJECT_CONNECTIONS,
    ) -> None:
        self._installation_limit = installation_limit
        self._subject_limit = subject_limit
        self._lock = Lock()
        self._total = 0
        self._subjects: dict[str, int] = {}

    def acquire(self, subject: str) -> bool:
        with self._lock:
            subject_count = self._subjects.get(subject, 0)
            if self._total >= self._installation_limit or subject_count >= self._subject_limit:
                return False
            self._total += 1
            self._subjects[subject] = subject_count + 1
            return True

    def release(self, subject: str) -> None:
        with self._lock:
            subject_count = self._subjects.get(subject, 0)
            if subject_count <= 0:
                return
            self._total = max(0, self._total - 1)
            if subject_count == 1:
                self._subjects.pop(subject, None)
            else:
                self._subjects[subject] = subject_count - 1


class EventWakeSubscription:
    def __init__(
        self,
        broker: EventWakeBroker,
        token: object,
        wake: asyncio.Event,
    ) -> None:
        self._broker = broker
        self._token = token
        self._wake = wake
        self._closed = False

    async def wait(self, timeout: float = KEEPALIVE_SECONDS) -> bool:
        """Return true for a durable DB hint and false for a heartbeat deadline."""

        try:
            await asyncio.wait_for(self._wake.wait(), timeout=timeout)
        except TimeoutError:
            self._broker.raise_subscription_error(self._token)
            return False
        self._wake.clear()
        self._broker.raise_subscription_error(self._token)
        return True

    def check(self) -> None:
        self._broker.raise_subscription_error(self._token)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._broker.unsubscribe(self._token)


class EventWakeBroker:
    """One blocking PostgreSQL LISTEN connection shared by this API process."""

    def __init__(
        self,
        engine: Engine,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._engine = engine
        self._session_factory = session_factory
        self._lock = Lock()
        self._subscribers: dict[
            object,
            tuple[asyncio.AbstractEventLoop, asyncio.Event, str],
        ] = {}
        self._thread: Thread | None = None
        self._ready = ThreadEvent()
        self._startup_error: BaseException | None = None
        self._failed_subscriptions: dict[object, BaseException] = {}
        self._backend_pid: int | None = None
        self._dispatched_since_prune = 0
        self._closed = False
        self._stop_read: socket.socket | None = None
        self._stop_write: socket.socket | None = None

    async def start(self) -> None:
        """Commit LISTEN and perform one durable catch-up without a timer."""

        if self._engine.dialect.name != "postgresql":
            return
        await asyncio.to_thread(self._ensure_started)

    async def subscribe(self, subject: str) -> EventWakeSubscription:
        if self._engine.dialect.name != "postgresql":
            # Isolated SQLite API tests do not have a cross-process wake
            # primitive. Production fails closed to PostgreSQL at startup.
            raise RuntimeError("event wake listener requires PostgreSQL")
        loop = asyncio.get_running_loop()
        wake = asyncio.Event()
        token = object()
        with self._lock:
            if self._closed:
                raise RuntimeError("event wake listener is closed")
            self._subscribers[token] = (loop, wake, subject)
        try:
            for attempt in range(6):
                self._clear_subscription_error(token)
                try:
                    await asyncio.to_thread(self._ensure_started)
                    break
                except RuntimeError:
                    if attempt == 5:
                        raise
                    await asyncio.sleep(min(0.5, 0.05 * (2**attempt)))
        except BaseException:
            self.unsubscribe(token)
            raise
        return EventWakeSubscription(self, token, wake)

    def unsubscribe(self, token: object) -> None:
        with self._lock:
            self._subscribers.pop(token, None)
            self._failed_subscriptions.pop(token, None)

    def _clear_subscription_error(self, token: object) -> None:
        with self._lock:
            self._failed_subscriptions.pop(token, None)

    def raise_subscription_error(self, token: object) -> None:
        with self._lock:
            failure = self._failed_subscriptions.get(token)
        if failure is not None:
            if isinstance(failure, EventAuthorizationRevoked):
                raise failure
            raise RuntimeError("event wake listener disconnected") from failure

    def revoke_subject(self, subject: str) -> int:
        """Fail established streams for one committed revoked capability."""

        failure = EventAuthorizationRevoked("event stream authorization revoked")
        with self._lock:
            subscribers = tuple(
                (token, loop, wake)
                for token, (loop, wake, active_subject) in self._subscribers.items()
                if active_subject == subject
            )
            for token, _, _ in subscribers:
                self._failed_subscriptions[token] = failure
        for _, loop, wake in subscribers:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                continue
        return len(subscribers)

    def revoke_ide_slot(self, client_slot: str) -> int:
        """Fail every established generation for one committed IDE slot change."""

        prefix = f"ide:{client_slot}:"
        failure = EventAuthorizationRevoked("event stream authorization revoked")
        with self._lock:
            subscribers = tuple(
                (token, loop, wake)
                for token, (loop, wake, active_subject) in self._subscribers.items()
                if active_subject.startswith(prefix)
            )
            for token, _, _ in subscribers:
                self._failed_subscriptions[token] = failure
        for _, loop, wake in subscribers:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                continue
        return len(subscribers)

    def subject_connection_count(self, subject: str) -> int:
        with self._lock:
            return sum(
                1
                for _, _, active_subject in self._subscribers.values()
                if active_subject == subject
            )

    def wake_subject(self, subject: str) -> int:
        """Wake only streams authenticated as the exact persisted subject."""

        with self._lock:
            subscribers = tuple(
                (loop, wake)
                for loop, wake, active_subject in self._subscribers.values()
                if active_subject == subject
            )
        for loop, wake in subscribers:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                continue
        return len(subscribers)

    def _ensure_started(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("event wake listener is closed")
            if self._thread is None or not self._thread.is_alive():
                if self._stop_read is None or self._stop_write is None:
                    self._stop_read, self._stop_write = socket.socketpair()
                self._ready = ThreadEvent()
                self._startup_error = None
                self._thread = Thread(
                    target=self._listen,
                    name="kodesec-event-listener",
                    daemon=True,
                )
                self._thread.start()
            thread = self._thread
        if not self._ready.wait(timeout=5.0):
            raise RuntimeError("event wake listener did not become ready")
        failure = self._startup_error
        if failure is None and thread is not None and thread.is_alive():
            return
        deadline = 5.0
        elapsed = 0.0
        delay = 0.05
        while elapsed < deadline:
            with self._lock:
                active_thread = self._thread
                active_failure = self._startup_error
            if active_failure is None and active_thread is not None and active_thread.is_alive():
                return
            wait_for = min(delay, deadline - elapsed)
            if wait_for <= 0:
                break
            ThreadEvent().wait(wait_for)
            elapsed += wait_for
            delay = min(0.5, delay * 2)
            failure = active_failure or failure
        raise RuntimeError("event wake listener failed to start") from failure

    def _listen(self) -> None:
        reconnect_attempt = 0
        stop_read = self._stop_read
        if stop_read is None:
            raise RuntimeError("event wake listener stop channel is unavailable")
        try:
            while True:
                proxy: Any = None
                try:
                    proxy = self._engine.raw_connection()
                    driver = proxy.driver_connection
                    driver.autocommit = True
                    self._backend_pid = int(driver.get_backend_pid())
                    with driver.cursor() as cursor:
                        cursor.execute(f"LISTEN {OUTBOX_PENDING_CHANNEL}")
                        cursor.execute(f"LISTEN {EVENT_READY_CHANNEL}")
                    self._dispatch_pending(prune=True)
                    self._startup_error = None
                    reconnect_attempt = 0
                    self._ready.set()
                    while True:
                        readable, _, _ = io_select.select(
                            [driver, stop_read],
                            [],
                            [],
                        )
                        if stop_read in readable:
                            stop_read.recv(1)
                            return
                        if driver not in readable:
                            continue
                        driver.poll()
                        pending = False
                        ready = False
                        while driver.notifies:
                            notification = driver.notifies.pop(0)
                            pending = pending or notification.channel == OUTBOX_PENDING_CHANNEL
                            ready = ready or notification.channel == EVENT_READY_CHANNEL
                        if pending:
                            self._dispatch_pending(prune=False)
                        if pending or ready:
                            self._wake_subscribers()
                except BaseException as exc:
                    with self._lock:
                        closed = self._closed
                    if closed:
                        return
                    self._startup_error = exc
                    self._ready.set()
                    self._fail_subscribers(exc)
                    reconnect_attempt = min(reconnect_attempt + 1, 8)
                finally:
                    self._backend_pid = None
                    if proxy is not None:
                        try:
                            driver = proxy.driver_connection
                            if not getattr(driver, "closed", True):
                                with driver.cursor() as cursor:
                                    cursor.execute("UNLISTEN *")
                            # A dedicated LISTEN connection must never re-enter
                            # the application pool with session state attached.
                            proxy.detach()
                        except BaseException:
                            try:
                                proxy.invalidate()
                            except BaseException:
                                pass
                        finally:
                            proxy.close()

                delay = min(30.0, 0.25 * (2 ** min(reconnect_attempt - 1, 7)))
                readable, _, _ = io_select.select([stop_read], [], [], delay)
                if stop_read in readable:
                    stop_read.recv(1)
                    return
        finally:
            with self._lock:
                if self._thread is current_thread():
                    self._thread = None

    def _dispatch_pending(self, *, prune: bool) -> None:
        dispatched = 0
        for _ in range(MAX_DISPATCH_BATCHES_PER_WAKE):
            batch_count = dispatch_pending_events(self._session_factory)
            dispatched += batch_count
            if batch_count < DISPATCH_BATCH_SIZE:
                break
        with self._session_factory() as db:
            pending = db.scalar(
                select(EventOutbox.row_id)
                .where(
                    EventOutbox.event_id.is_(None),
                    EventOutbox.quarantined_at.is_(None),
                )
                .limit(1)
            )
        if pending is not None:
            # Continue a pre-existing backlog or bounded poison-row retries
            # without depending on a second domain write.
            with self._session_factory.begin() as db:
                db.execute(text(f"SELECT pg_notify('{OUTBOX_PENDING_CHANNEL}', '1')"))
        self._dispatched_since_prune += dispatched
        if prune or self._dispatched_since_prune >= 1024:
            prune_dispatched_events(self._session_factory)
            self._dispatched_since_prune = 0

    def _wake_subscribers(self) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers.values())
        for loop, wake, _ in subscribers:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                continue

    def _fail_subscribers(self, failure: BaseException) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers.items())
            for token, _ in subscribers:
                self._failed_subscriptions[token] = failure
        for _, (loop, wake, _) in subscribers:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                continue
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            thread = self._thread
            self._subscribers.clear()
            stop_read = self._stop_read
            stop_write = self._stop_write
        try:
            if stop_write is not None:
                stop_write.send(b"x")
        except OSError:
            pass
        if thread is not None:
            thread.join(timeout=5.0)
        if stop_read is not None:
            stop_read.close()
        if stop_write is not None:
            stop_write.close()


class EventAuthorizationRevoked(RuntimeError):
    """An established stream's persisted capability was revoked."""


def ide_stream_subject(client_slot: str, generation: int) -> str:
    """Return the exact process-local wake subject for one IDE authority."""

    return f"ide:{client_slot}:{generation}"


def _field_changed(model: object, *names: str) -> bool:
    state = sa_inspect(model)
    return any(state.attrs[name].history.has_changes() for name in names)


def _before_flush(session: Session, _flush_context: object, _instances: object) -> None:
    """Advance the one project revision that predates explicit revision writers."""

    for model in tuple(session.dirty):
        if not isinstance(model, Project):
            continue
        if not _field_changed(model, "name", "repo_path", "remote_url", "default_branch"):
            continue
        if not _field_changed(model, "revision"):
            model.revision = max(1, int(model.revision or 1)) + 1


def _machine_hint(value: object) -> str | None:
    if not isinstance(value, str) or _MACHINE_TEXT.fullmatch(value) is None:
        return None
    return value


def _positive_id(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _scan_from_session(session: Session, scan_id: int | None, relationship: object = None) -> Scan | None:
    if isinstance(relationship, Scan):
        return relationship
    if scan_id is None:
        return None
    identity = session.identity_key(Scan, scan_id)
    loaded = session.identity_map.get(identity)
    if isinstance(loaded, Scan):
        return loaded
    # The flush has completed, so this bounded lookup cannot recursively flush.
    with session.no_autoflush:
        return session.get(Scan, scan_id)


def _scope(**values: int | None) -> dict[str, int]:
    return {
        key: value
        for key, value in values.items()
        if key in SCOPE_KEYS and _positive_id(value) is not None
    }


def _event_size(document: Mapping[str, Any]) -> int:
    return len(
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _validate_maps(scope: object, hint: object) -> tuple[dict[str, int], dict[str, str | int | bool]]:
    if not isinstance(scope, dict) or not set(scope).issubset(SCOPE_KEYS):
        raise ValueError("invalid event scope")
    clean_scope: dict[str, int] = {}
    for key, value in scope.items():
        normalized = _positive_id(value)
        if normalized is None:
            raise ValueError("invalid event scope identifier")
        clean_scope[key] = normalized

    if not isinstance(hint, dict) or not set(hint).issubset(HINT_KEYS):
        raise ValueError("invalid event hint")
    clean_hint: dict[str, str | int | bool] = {}
    for key, value in hint.items():
        if isinstance(value, str):
            normalized_text = _machine_hint(value)
            if normalized_text is None:
                raise ValueError("invalid event hint text")
            clean_hint[key] = normalized_text
        elif isinstance(value, bool):
            clean_hint[key] = value
        elif isinstance(value, int) and -(2**31) <= value <= 2**31 - 1:
            clean_hint[key] = value
        else:
            raise ValueError("invalid event hint scalar")
    return clean_scope, clean_hint


def _intent_document(
    *,
    kind: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_revision: int,
    scope: object,
    change: str,
    hint: object,
    event_id: int,
    occurred_at: str,
) -> dict[str, Any]:
    if kind not in DOMAIN_EVENT_KINDS or aggregate_type not in AGGREGATE_TYPES:
        raise ValueError("invalid event taxonomy")
    if kind != f"{aggregate_type}.changed":
        raise ValueError("event kind does not match aggregate")
    if _DECIMAL_ID.fullmatch(aggregate_id) is None:
        raise ValueError("invalid aggregate identifier")
    if isinstance(aggregate_revision, bool) or aggregate_revision < 1:
        raise ValueError("invalid aggregate revision")
    if change not in CHANGES:
        raise ValueError("invalid event change")
    if event_id < 1:
        raise ValueError("invalid event identifier")
    clean_scope, clean_hint = _validate_maps(scope, hint)
    document = {
        "v": EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "kind": kind,
        "aggregate": {
            "type": aggregate_type,
            "id": aggregate_id,
            "revision": aggregate_revision,
        },
        "scope": clean_scope,
        "change": change,
        "hint": clean_hint,
        "occurred_at": occurred_at,
    }
    if _event_size(document) > MAX_EVENT_BYTES:
        raise ValueError("event envelope exceeds the 4 KiB limit")
    return document


def _coalesce_intent(
    session: Session,
    *,
    kind: str,
    aggregate_type: str,
    aggregate_id: int,
    aggregate_revision: int,
    scope: dict[str, int],
    change: str,
    hint: dict[str, str | int | bool],
) -> None:
    rendered_id = str(aggregate_id)
    # Validate the exact persisted shape before it can participate in the
    # domain transaction. The real event ID/timestamp have the same bounds.
    _intent_document(
        kind=kind,
        aggregate_type=aggregate_type,
        aggregate_id=rendered_id,
        aggregate_revision=max(1, aggregate_revision),
        scope=scope,
        change=change,
        hint=hint,
        event_id=_MAX_CURSOR,
        occurred_at="9999-12-31T23:59:59.999999Z",
    )
    intents: dict[tuple[str, str, str], EventOutbox] = session.info.setdefault(
        _SESSION_EVENTS,
        {},
    )
    key = (kind, aggregate_type, rendered_id)
    existing = intents.get(key)
    if existing is None:
        existing = EventOutbox(
            schema_version=EVENT_SCHEMA_VERSION,
            kind=kind,
            aggregate_type=aggregate_type,
            aggregate_id=rendered_id,
            aggregate_revision=max(1, aggregate_revision),
            scope=scope,
            change=change,
            hint=hint,
            dispatch_attempts=0,
        )
        intents[key] = existing
        session.add(existing)
        return
    # An explicit flush can persist this intent before the domain transaction
    # reaches its final revision. Updates made from ``after_flush`` to an
    # already-inserted ORM object are discarded by SQLAlchemy's history
    # cleanup, so update the compact row directly inside the same transaction.
    # ``row_id`` is assigned as soon as the INSERT executes, including while
    # SQLAlchemy is still completing the flush that transitions this object
    # from pending to persistent.  The identity is therefore the reliable
    # signal that a direct in-transaction UPDATE is required; checking only
    # ``InstanceState.persistent`` misses that after-flush window and the ORM
    # then discards the coalesced revision as inner-flush history.
    if existing.row_id is not None:
        clean_scope, clean_hint = _validate_maps(
            {**existing.scope, **scope},
            {**existing.hint, **hint},
        )
        final_change = (
            change
            if change == "deleted" or existing.change != "created"
            else "created"
        )
        final_revision = max(existing.aggregate_revision, aggregate_revision, 1)
        session.execute(
            EventOutbox.__table__.update()
            .where(EventOutbox.row_id == existing.row_id)
            .values(
                aggregate_revision=final_revision,
                scope=clean_scope,
                change=final_change,
                hint=clean_hint,
            )
        )
        set_committed_value(existing, "aggregate_revision", final_revision)
        set_committed_value(existing, "scope", clean_scope)
        set_committed_value(existing, "change", final_change)
        set_committed_value(existing, "hint", clean_hint)
        return
    existing.aggregate_revision = max(existing.aggregate_revision, aggregate_revision, 1)
    existing.scope = {**existing.scope, **scope}
    existing.hint = {**existing.hint, **hint}
    # An intent can already have been flushed earlier in the same transaction.
    # Mark JSON fields explicitly so coalesced revisions survive the next flush.
    flag_modified(existing, "scope")
    flag_modified(existing, "hint")
    if change == "deleted" or existing.change != "created":
        existing.change = change


def _after_flush(session: Session, _flush_context: object) -> None:
    deleted_projects = {
        model.id for model in session.deleted if isinstance(model, Project) and model.id is not None
    }
    deleted_scans = {
        model.id for model in session.deleted if isinstance(model, Scan) and model.id is not None
    }

    candidates = tuple(session.new) + tuple(session.dirty) + tuple(session.deleted)
    seen: set[int] = set()
    for model in candidates:
        identity = id(model)
        if identity in seen or isinstance(model, (EventOutbox, EventDispatchState)):
            continue
        seen.add(identity)
        is_new = model in session.new
        is_deleted = model in session.deleted
        change = "deleted" if is_deleted else "created" if is_new else "updated"

        if isinstance(model, Project):
            if not (is_new or is_deleted or _field_changed(
                model,
                "name",
                "repo_path",
                "remote_url",
                "default_branch",
                "revision",
            )):
                continue
            revision = int(model.revision or 1) + (1 if is_deleted else 0)
            _coalesce_intent(
                session,
                kind="project.changed",
                aggregate_type="project",
                aggregate_id=model.id,
                aggregate_revision=revision,
                scope=_scope(project_id=model.id),
                change=change,
                hint={},
            )
            continue

        if isinstance(model, Scan):
            if model.project_id in deleted_projects:
                continue
            if not (is_new or is_deleted or _field_changed(
                model,
                "status",
                "gate_decision",
                "revision",
                "findings_revision",
            )):
                continue
            revision = int(model.revision or 1) + (1 if is_deleted else 0)
            hint: dict[str, str | int | bool] = {}
            status = _machine_hint(model.status)
            decision = _machine_hint(model.gate_decision)
            if status is not None:
                hint["status"] = status
            if decision is not None:
                hint["decision"] = decision
            _coalesce_intent(
                session,
                kind="scan.changed",
                aggregate_type="scan",
                aggregate_id=model.id,
                aggregate_revision=revision,
                scope=_scope(project_id=model.project_id, scan_id=model.id),
                change=change,
                hint=hint,
            )
            if not is_new and not is_deleted and _field_changed(model, "findings_revision"):
                _coalesce_intent(
                    session,
                    kind="findings.changed",
                    aggregate_type="findings",
                    aggregate_id=model.id,
                    aggregate_revision=int(model.findings_revision or 1),
                    scope=_scope(project_id=model.project_id, scan_id=model.id),
                    change="updated",
                    hint={},
                )
            continue

        if isinstance(model, Job):
            if model.scan_id in deleted_scans:
                continue
            if not (is_new or is_deleted or _field_changed(
                model,
                "status",
                "stage",
                "progress",
                "revision",
                "scan_id",
            )):
                continue
            scan = _scan_from_session(session, model.scan_id, model.__dict__.get("scan"))
            if scan is not None and scan.project_id in deleted_projects:
                continue
            revision = int(model.revision or 1) + (1 if is_deleted else 0)
            hint = {}
            status = _machine_hint(model.status)
            stage = _machine_hint(model.stage)
            if status is not None:
                hint["status"] = status
            if stage is not None:
                hint["stage"] = stage
            if isinstance(model.progress, int) and not isinstance(model.progress, bool):
                hint["progress"] = model.progress
            _coalesce_intent(
                session,
                kind="job.changed",
                aggregate_type="job",
                aggregate_id=model.id,
                aggregate_revision=revision,
                scope=_scope(
                    project_id=scan.project_id if scan is not None else None,
                    scan_id=model.scan_id,
                    job_id=model.id,
                ),
                change=change,
                hint=hint,
            )
            continue

        if isinstance(model, Finding):
            if model.scan_id in deleted_scans:
                continue
            if not (is_new or is_deleted or _field_changed(
                model,
                "revision",
                "lifecycle_status",
                "gate_exempt",
                "ai_verdict",
            )):
                continue
            scan = _scan_from_session(session, model.scan_id, model.__dict__.get("scan"))
            if scan is not None and scan.project_id in deleted_projects:
                continue
            _coalesce_intent(
                session,
                kind="findings.changed",
                aggregate_type="findings",
                aggregate_id=model.scan_id,
                aggregate_revision=int(scan.findings_revision if scan is not None else model.revision or 1),
                scope=_scope(
                    project_id=scan.project_id if scan is not None else None,
                    scan_id=model.scan_id,
                ),
                change="updated",
                hint={},
            )

    if (
        session.info.get(_SESSION_EVENTS)
        and not session.info.get(_SESSION_NOTIFY_STAGED)
        and session.get_bind().dialect.name == "postgresql"
    ):
        # PostgreSQL delivers this only if the surrounding source transaction
        # commits. It contains no resource data and is merely a wake-up hint.
        session.execute(text(f"SELECT pg_notify('{OUTBOX_PENDING_CHANNEL}', '1')"))
        session.info[_SESSION_NOTIFY_STAGED] = True


def _after_transaction_end(session: Session, transaction: object) -> None:
    if getattr(transaction, "parent", None) is None:
        session.info.pop(_SESSION_EVENTS, None)
        session.info.pop(_SESSION_NOTIFY_STAGED, None)


def install_outbox_listeners() -> None:
    """Install process-wide ORM hooks once for both API and worker sessions."""

    global _listeners_installed
    with _listeners_lock:
        if _listeners_installed:
            return
        event.listen(Session, "before_flush", _before_flush)
        event.listen(Session, "after_flush", _after_flush)
        event.listen(Session, "after_transaction_end", _after_transaction_end)
        _listeners_installed = True


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _occurred_at(value: datetime | None) -> str:
    moment = value or _utcnow()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def event_document(row: EventOutbox) -> dict[str, Any]:
    if row.event_id is None:
        raise ValueError("undispatched event has no replay identifier")
    return _intent_document(
        kind=row.kind,
        aggregate_type=row.aggregate_type,
        aggregate_id=row.aggregate_id,
        aggregate_revision=row.aggregate_revision,
        scope=row.scope,
        change=row.change,
        hint=row.hint,
        event_id=row.event_id,
        occurred_at=_occurred_at(row.created_at),
    )


def dispatch_pending_events(
    session_factory: sessionmaker[Session],
    *,
    batch_size: int = DISPATCH_BATCH_SIZE,
) -> int:
    """Assign replay IDs after source commits under one durable allocator lock."""

    bounded_batch = max(1, min(batch_size, DISPATCH_BATCH_SIZE))
    dispatched = 0
    with session_factory.begin() as db:
        state = db.scalar(
            select(EventDispatchState)
            .where(EventDispatchState.id == 1)
            .with_for_update()
        )
        if state is None:
            raise SchemaSingletonStateError(
                "event dispatch allocator singleton is missing from the initialized schema"
            )
        rows = list(
            db.scalars(
                select(EventOutbox)
                .where(
                    EventOutbox.event_id.is_(None),
                    EventOutbox.quarantined_at.is_(None),
                )
                .order_by(EventOutbox.row_id)
                .limit(bounded_batch)
                .with_for_update()
            )
        )
        next_event_id = int(state.next_event_id)
        now = _utcnow()
        for row in rows:
            try:
                _intent_document(
                    kind=row.kind,
                    aggregate_type=row.aggregate_type,
                    aggregate_id=row.aggregate_id,
                    aggregate_revision=row.aggregate_revision,
                    scope=row.scope,
                    change=row.change,
                    hint=row.hint,
                    event_id=next_event_id,
                    occurred_at=_occurred_at(row.created_at),
                )
            except (TypeError, ValueError):
                row.dispatch_attempts += 1
                row.dispatch_error_code = "invalid_event_envelope"
                if row.dispatch_attempts >= 3:
                    row.quarantined_at = now
                continue
            row.event_id = next_event_id
            row.dispatched_at = now
            row.dispatch_error_code = None
            next_event_id += 1
            dispatched += 1
        if dispatched:
            state.next_event_id = next_event_id
            state.updated_at = now
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    text(
                        f"SELECT pg_notify('{EVENT_READY_CHANNEL}', CAST(:event_id AS TEXT))"
                    ),
                    {"event_id": next_event_id - 1},
                )
    return dispatched


def prune_dispatched_events(session_factory: sessionmaker[Session]) -> int:
    """Keep at least the newer of 24 hours or the latest 50,000 events."""

    with session_factory.begin() as db:
        highwater = db.scalar(select(func.max(EventOutbox.event_id))) or 0
        event_threshold = int(highwater) - RETENTION_EVENTS
        if event_threshold < 1:
            return 0
        result = db.execute(
            delete(EventOutbox).where(
                EventOutbox.event_id.is_not(None),
                EventOutbox.event_id <= event_threshold,
                EventOutbox.created_at < _utcnow() - RETENTION_AGE,
            )
        )
        return max(0, int(result.rowcount or 0))


@dataclass(frozen=True, slots=True)
class StreamBatch:
    highwater_event_id: int
    earliest_event_id: int
    events: tuple[dict[str, Any], ...]
    reset_reason: str | None = None


def _read_stream_batch(
    session_factory: sessionmaker[Session],
    cursor: int | None,
    *,
    prune: bool,
) -> StreamBatch:
    # One bounded dispatch transaction per connected-stream read. Additional
    # committed intent remains durable and is assigned on the next read.
    dispatch_pending_events(session_factory)
    if prune:
        prune_dispatched_events(session_factory)
    with session_factory() as db:
        earliest = db.scalar(select(func.min(EventOutbox.event_id)))
        highwater = db.scalar(select(func.max(EventOutbox.event_id)))
        highwater_id = int(highwater or 0)
        earliest_id = int(earliest) if earliest is not None else highwater_id + 1
        if cursor is None:
            return StreamBatch(highwater_id, earliest_id, ())
        if cursor > highwater_id:
            return StreamBatch(highwater_id, earliest_id, (), "cursor_ahead")
        if highwater_id > 0 and cursor < earliest_id - 1:
            return StreamBatch(highwater_id, earliest_id, (), "cursor_expired")
        rows = list(
            db.scalars(
                select(EventOutbox)
                .where(
                    EventOutbox.event_id > cursor,
                    EventOutbox.event_id <= highwater_id,
                )
                .order_by(EventOutbox.event_id)
                .limit(REPLAY_LIMIT + 1)
            )
        )
        if len(rows) > REPLAY_LIMIT:
            return StreamBatch(highwater_id, earliest_id, (), "backlog_too_large")
        return StreamBatch(
            highwater_id,
            earliest_id,
            tuple(event_document(row) for row in rows),
        )


def prepare_stream(
    session_factory: sessionmaker[Session],
    cursor: int | None,
) -> StreamBatch:
    return _read_stream_batch(session_factory, cursor, prune=True)


def _protocol_document(batch: StreamBatch, *, reason: str | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "v": EVENT_SCHEMA_VERSION,
        "highwater_event_id": batch.highwater_event_id,
        "earliest_event_id": batch.earliest_event_id,
    }
    if reason is not None:
        document["reason"] = reason
    return document


def encode_sse(event_name: str, document: Mapping[str, Any], event_id: int | None = None) -> bytes:
    if event_name not in DOMAIN_EVENT_KINDS | TARGET_EVENT_KINDS | {"stream.ready", "stream.reset"}:
        raise ValueError("invalid SSE event name")
    data = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if "\n" in data or "\r" in data or len(data.encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValueError("invalid SSE event data")
    lines = []
    if event_id is not None:
        if event_id < 1:
            raise ValueError("invalid SSE event ID")
        lines.append(f"id: {event_id}")
    lines.extend((f"event: {event_name}", f"data: {data}", "", ""))
    return "\n".join(lines).encode("utf-8")


async def _event_stream(
    request: Request,
    runtime: Runtime,
    cursor: int | None,
    limiter: EventConnectionLimiter,
    wake_broker: EventWakeBroker,
    subject: str,
    authorization: IdeStreamAuthorization | None = None,
) -> AsyncIterator[bytes]:
    subscription: EventWakeSubscription | None = None
    sent_target_commands: set[str] = set()

    async def target_commands() -> tuple[dict[str, object], ...]:
        if authorization is None:
            return ()
        # A capability can be shared by several VS Code windows through one
        # profile authority store. Never deliver a source command while that
        # capability has an ambiguous recipient set.
        if wake_broker.subject_connection_count(subject) != 1:
            return ()
        from .ide_source import pending_source_open_commands

        documents = await asyncio.to_thread(
            pending_source_open_commands,
            runtime.session_factory,
            authorization.client_slot,
            authorization.generation,
        )
        return tuple(
            document
            for document in documents
            if str(document.get("command_id", "")) not in sent_target_commands
        )

    try:
        # LISTEN is committed before the initial durable read, closing the
        # listen/query race without an idle sweep. IDE authorization is then
        # revalidated from the durable slot so a revoke/replace immediately
        # before subscription cannot survive a missed process-local wake. The
        # same durable fence runs again immediately before every emitted frame.
        subscription = await wake_broker.subscribe(subject)
        if (
            authorization is None
            and subject.startswith("ide:")
        ) or (
            authorization is not None
            and subject != ide_stream_subject(
                authorization.client_slot,
                authorization.generation,
            )
        ):
            raise EventAuthorizationRevoked("event stream authorization subject mismatch")
        await _guard_stream_authorization(
            subscription,
            authorization,
            runtime.session_factory,
        )
        batch = await asyncio.to_thread(prepare_stream, runtime.session_factory, cursor)
        ready_frame = encode_sse("stream.ready", _protocol_document(batch))
        await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
        yield ready_frame
        if batch.reset_reason is not None:
            reset_frame = encode_sse(
                "stream.reset",
                _protocol_document(batch, reason=batch.reset_reason),
            )
            await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
            yield reset_frame
            return
        for document in batch.events:
            event_id = int(document["event_id"])
            frame = encode_sse(str(document["kind"]), document, event_id)
            await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
            yield frame
        for document in await target_commands():
            frame = encode_sse("ide.source.open", document)
            await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
            sent_target_commands.add(str(document["command_id"]))
            yield frame

        active_cursor = batch.highwater_event_id
        while True:
            assert subscription is not None
            timeout = _authorization_wait_timeout(authorization)
            if timeout <= 0:
                return
            notified = await subscription.wait(timeout=timeout)
            if not notified:
                # Heartbeats keep intermediaries honest and do not mutate
                # replay state. IDE streams still revalidate their exact
                # durable slot, generation, and revocation before yield.
                await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
                yield b": keepalive\n\n"
                continue
            batch = await asyncio.to_thread(
                _read_stream_batch,
                runtime.session_factory,
                active_cursor,
                prune=False,
            )
            if batch.reset_reason is not None:
                reset_frame = encode_sse(
                    "stream.reset",
                    _protocol_document(batch, reason=batch.reset_reason),
                )
                await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
                yield reset_frame
                return
            if batch.events:
                for document in batch.events:
                    event_id = int(document["event_id"])
                    frame = encode_sse(str(document["kind"]), document, event_id)
                    await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
                    yield frame
                active_cursor = batch.highwater_event_id
            for document in await target_commands():
                frame = encode_sse("ide.source.open", document)
                await _guard_stream_authorization(subscription, authorization, runtime.session_factory)
                sent_target_commands.add(str(document["command_id"]))
                yield frame
    except EventAuthorizationRevoked:
        # Authorization revocation is a clean EOF, never a protocol event that
        # could reveal credential state. A reconnect is rejected with 401.
        return
    except asyncio.CancelledError:
        raise
    finally:
        if subscription is not None:
            subscription.close()
        limiter.release(subject)


def _parse_cursor(request: Request) -> int | None:
    raw = request.headers.get("last-event-id")
    if raw is None:
        return None
    if _CURSOR.fullmatch(raw) is None:
        raise HTTPException(400, "Last-Event-ID must be a non-negative decimal integer")
    cursor = int(raw)
    if cursor > _MAX_CURSOR:
        raise HTTPException(400, "Last-Event-ID is outside the supported range")
    return cursor


@router.get("/v1/events")
def stream_events(
    request: Request,
    runtime: Runtime = Depends(get_runtime),
) -> StreamingResponse:
    if request.url.query:
        raise HTTPException(400, "event stream parameters are forbidden in the URL")
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext):
        raise HTTPException(401, "authentication required")
    cursor = _parse_cursor(request)
    limiter = getattr(request.app.state, "event_connection_limiter", None)
    if not isinstance(limiter, EventConnectionLimiter):
        raise HTTPException(503, "event stream is unavailable")
    subject = f"{context.kind}:{context.subject}"
    authorization: IdeStreamAuthorization | None = None
    if context.kind == "ide":
        if context.capability_generation is None:
            raise HTTPException(401, "invalid IDE event-stream authorization")
        authorization = IdeStreamAuthorization(
            client_slot=context.subject,
            generation=context.capability_generation,
        )
        subject = ide_stream_subject(
            authorization.client_slot,
            authorization.generation,
        )
    if not limiter.acquire(subject):
        raise HTTPException(429, "event stream connection limit reached")
    wake_broker = getattr(request.app.state, "event_wake_broker", None)
    if not isinstance(wake_broker, EventWakeBroker):
        limiter.release(subject)
        raise HTTPException(503, "event stream listener is unavailable")
    return StreamingResponse(
        _event_stream(
            request,
            runtime,
            cursor,
            limiter,
            wake_broker,
            subject,
            authorization,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )
