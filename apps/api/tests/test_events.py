from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import kodesec_api.events as events_module
import kodesec_api.ide_source as ide_source_module
from kodesec_api.auth import (
    CAPABILITY_PREFIX,
    IDE_CAPABILITY_SCOPES,
    IdeStreamAuthorization,
)
from kodesec_api.db import Base, SchemaSingletonStateError, initialize_database
from kodesec_api.events import (
    EventAuthorizationRevoked,
    EventConnectionLimiter,
    EventWakeBroker,
    MAX_EVENT_BYTES,
    dispatch_pending_events,
    encode_sse,
    event_document,
    ide_stream_subject,
    install_outbox_listeners,
    prepare_stream,
    prune_dispatched_events,
    StreamBatch,
    _event_stream,
)
from kodesec_api.models import (
    EventDispatchState,
    EventOutbox,
    Finding,
    Job,
    Project,
    RuntimeConfig,
    Scan,
)


@pytest.fixture()
def sqlite_sessions():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    try:
        yield factory
    finally:
        engine.dispose()


def _project(name: str) -> Project:
    return Project(
        name=name,
        repo_path=f"/workspaces/{name}",
        remote_url=None,
        default_branch="main",
    )


def test_domain_event_intent_commits_and_rolls_back_atomically(sqlite_sessions) -> None:
    with sqlite_sessions() as db:
        committed = _project("committed")
        db.add(committed)
        db.commit()
        committed_id = committed.id

    with sqlite_sessions() as db:
        rows = list(db.scalars(select(EventOutbox).order_by(EventOutbox.row_id)))
        assert len(rows) == 1
        assert rows[0].event_id is None
        assert rows[0].kind == "project.changed"
        assert rows[0].aggregate_id == str(committed_id)
        assert rows[0].aggregate_revision == 1
        assert rows[0].scope == {"project_id": committed_id}

    with sqlite_sessions() as db:
        db.add(_project("rolled-back"))
        db.flush()
        db.rollback()

    with sqlite_sessions() as db:
        assert db.scalar(select(Project).where(Project.name == "rolled-back")) is None
        assert db.scalar(select(EventOutbox).where(EventOutbox.aggregate_id != str(committed_id))) is None


def test_dispatcher_rejects_missing_allocator_without_recreating_it(sqlite_sessions) -> None:
    with sqlite_sessions.begin() as db:
        db.execute(delete(EventDispatchState))

    with pytest.raises(SchemaSingletonStateError, match="allocator singleton is missing"):
        dispatch_pending_events(sqlite_sessions)

    with sqlite_sessions() as db:
        assert db.get(EventDispatchState, 1) is None


def test_project_event_coalesces_revision_across_two_explicit_flushes(
    sqlite_sessions,
) -> None:
    with sqlite_sessions() as db:
        project = _project("two-flush-revision")
        db.add(project)
        db.flush()
        project_id = project.id

        project.default_branch = "release"
        db.flush()
        db.commit()

    with sqlite_sessions() as db:
        rows = list(
            db.scalars(
                select(EventOutbox).where(
                    EventOutbox.kind == "project.changed",
                    EventOutbox.aggregate_id == str(project_id),
                )
            )
        )
        assert len(rows) == 1
        assert rows[0].aggregate_revision == 2
        assert rows[0].change == "created"


def test_finding_batch_is_one_scan_scoped_sanitized_invalidation(sqlite_sessions) -> None:
    with sqlite_sessions() as db:
        project = _project("findings")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, status="running", revision=1, findings_revision=1)
        db.add(scan)
        db.flush()
        for number in (1, 2):
            db.add(
                Finding(
                    scan_id=scan.id,
                    scan_finding_number=number,
                    scanner="secret-scanner",
                    rule_id=f"secret-rule-{number}",
                    severity="high",
                    file_path=f"/private/source/secret-{number}.py",
                    start_line=1,
                    end_line=1,
                    message="password=do-not-stream",
                    code_snippet="AWS_SECRET_ACCESS_KEY=do-not-stream",
                    fingerprint=f"fingerprint-{number}",
                    metadata_json={"prompt": "do-not-stream"},
                    ai_reasoning="private model reasoning",
                    revision=1,
                )
            )
        scan.findings_revision = 2
        scan.revision = 2
        db.commit()
        scan_id = scan.id
        project_id = project.id

    with sqlite_sessions() as db:
        rows = list(
            db.scalars(
                select(EventOutbox).where(EventOutbox.kind == "findings.changed")
            )
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.aggregate_id == str(scan_id)
        assert row.aggregate_revision == 2
        assert row.scope == {"project_id": project_id, "scan_id": scan_id}
        assert row.hint == {}
        rendered = json.dumps(
            {
                "scope": row.scope,
                "hint": row.hint,
                "kind": row.kind,
                "aggregate_id": row.aggregate_id,
            },
            sort_keys=True,
        )
        for forbidden in (
            "/private/source",
            "password",
            "AWS_SECRET",
            "secret-rule",
            "model reasoning",
            "prompt",
        ):
            assert forbidden not in rendered


def test_lease_only_heartbeat_does_not_emit_client_event(sqlite_sessions) -> None:
    with sqlite_sessions() as db:
        job = Job(kind="scan", title="Scan", status="running", stage="scan", revision=1)
        db.add(job)
        db.commit()
        job_id = job.id

    with sqlite_sessions.begin() as db:
        job = db.get(Job, job_id)
        assert job is not None
        job.heartbeat_at = datetime.now(timezone.utc)

    with sqlite_sessions() as db:
        rows = list(
            db.scalars(
                select(EventOutbox).where(
                    EventOutbox.kind == "job.changed",
                    EventOutbox.aggregate_id == str(job_id),
                )
            )
        )
        assert len(rows) == 1


def test_dispatch_assigns_monotonic_ids_only_after_domain_commit(sqlite_sessions) -> None:
    with sqlite_sessions.begin() as db:
        db.add(_project("committed-before-dispatch"))

    assert dispatch_pending_events(sqlite_sessions) == 1
    assert dispatch_pending_events(sqlite_sessions) == 0
    with sqlite_sessions() as db:
        row = db.scalar(select(EventOutbox))
        assert row is not None
        assert row.event_id == 1
        document = event_document(row)
        assert document["event_id"] == 1
        assert document["kind"] == "project.changed"
        assert len(json.dumps(document, separators=(",", ":")).encode()) <= MAX_EVENT_BYTES


def test_invalid_event_is_retried_boundedly_then_quarantined(sqlite_sessions) -> None:
    with sqlite_sessions.begin() as db:
        db.add(
            EventOutbox(
                schema_version=1,
                kind="project.changed",
                aggregate_type="project",
                aggregate_id="1",
                aggregate_revision=1,
                scope={"project_id": 1},
                change="created",
                hint={"status": "source text is forbidden"},
                dispatch_attempts=0,
            )
        )

    assert dispatch_pending_events(sqlite_sessions) == 0
    assert dispatch_pending_events(sqlite_sessions) == 0
    assert dispatch_pending_events(sqlite_sessions) == 0
    with sqlite_sessions() as db:
        row = db.scalar(select(EventOutbox))
        assert row is not None
        assert row.event_id is None
        assert row.dispatch_attempts == 3
        assert row.dispatch_error_code == "invalid_event_envelope"
        assert row.quarantined_at is not None


def test_replay_cursor_reset_and_protocol_encoding(sqlite_sessions) -> None:
    empty = prepare_stream(sqlite_sessions, 0)
    assert empty.reset_reason is None
    assert empty.highwater_event_id == 0
    assert empty.earliest_event_id == 1

    with sqlite_sessions.begin() as db:
        db.add_all([_project("replay-a"), _project("replay-b")])
    assert dispatch_pending_events(sqlite_sessions) == 2

    replay = prepare_stream(sqlite_sessions, 0)
    assert replay.reset_reason is None
    assert replay.highwater_event_id == 2
    assert replay.earliest_event_id == 1
    assert [item["event_id"] for item in replay.events] == [1, 2]

    fresh = prepare_stream(sqlite_sessions, None)
    assert fresh.events == ()
    assert fresh.highwater_event_id == 2

    future = prepare_stream(sqlite_sessions, 3)
    assert future.reset_reason == "cursor_ahead"

    with sqlite_sessions.begin() as db:
        first = db.scalar(select(EventOutbox).where(EventOutbox.event_id == 1))
        assert first is not None
        db.delete(first)
    expired = prepare_stream(sqlite_sessions, 0)
    assert expired.reset_reason == "cursor_expired"
    assert expired.earliest_event_id == 2

    ready = encode_sse(
        "stream.ready",
        {"v": 1, "highwater_event_id": 2, "earliest_event_id": 2},
    )
    assert ready.startswith(b"event: stream.ready\ndata: ")
    assert b"id:" not in ready

    domain = encode_sse("project.changed", replay.events[0], 1)
    assert domain.startswith(b"id: 1\nevent: project.changed\ndata: ")
    assert domain.endswith(b"\n\n")


def test_replay_backlog_and_retention_are_bounded(sqlite_sessions, monkeypatch) -> None:
    with sqlite_sessions.begin() as db:
        for number in range(events_module.REPLAY_LIMIT + 1):
            db.add(
                EventOutbox(
                    schema_version=1,
                    kind="project.changed",
                    aggregate_type="project",
                    aggregate_id=str(number + 1),
                    aggregate_revision=1,
                    scope={"project_id": number + 1},
                    change="created",
                    hint={},
                    dispatch_attempts=0,
                )
            )
    while dispatch_pending_events(sqlite_sessions):
        pass
    assert prepare_stream(sqlite_sessions, 0).reset_reason == "backlog_too_large"

    monkeypatch.setattr(events_module, "RETENTION_EVENTS", 2)
    monkeypatch.setattr(events_module, "RETENTION_AGE", timedelta(seconds=0))
    assert prune_dispatched_events(sqlite_sessions) == events_module.REPLAY_LIMIT - 1
    with sqlite_sessions() as db:
        retained = list(db.scalars(select(EventOutbox).order_by(EventOutbox.event_id)))
        assert [row.event_id for row in retained] == [events_module.REPLAY_LIMIT, events_module.REPLAY_LIMIT + 1]


def test_idle_heartbeat_does_not_requery_the_database(monkeypatch) -> None:
    calls = 0

    def prepare(_factory, _cursor):
        nonlocal calls
        calls += 1
        return StreamBatch(0, 1, ())

    class Subscription:
        closed = False

        async def wait(self, timeout=15.0):
            return False

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 0

    monkeypatch.setattr(events_module, "prepare_stream", prepare)
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire("browser:test") is True
    runtime = SimpleNamespace(session_factory=object())
    request = SimpleNamespace()

    async def exercise() -> tuple[bytes, bytes]:
        stream = _event_stream(
            request,
            runtime,
            0,
            limiter,
            broker,
            "browser:test",
        )
        ready = await anext(stream)
        heartbeat = await anext(stream)
        await stream.aclose()
        return ready, heartbeat

    ready, heartbeat = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert heartbeat == b": keepalive\n\n"
    assert calls == 1
    assert broker.subscription.closed is True
    assert limiter.acquire("browser:test") is True
    limiter.release("browser:test")


def test_active_ide_stream_keeps_durable_authority_across_keepalive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_at = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
    clock = {"now": started_at}

    class Subscription:
        closed = False
        wait_timeout: float | None = None

        async def wait(self, timeout=15.0):
            self.wait_timeout = timeout
            clock["now"] = started_at + timedelta(days=365)
            return False

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 0

    monkeypatch.setattr(events_module, "_utcnow", lambda: clock["now"])
    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda _factory, _cursor: StreamBatch(0, 1, ()),
    )
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    client_slot = "ks1_" + "e" * 43
    subject = ide_stream_subject(client_slot, 1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    monkeypatch.setattr(
        events_module,
        "_durable_stream_authorization_is_active",
        lambda _factory, candidate: candidate == authorization,
    )
    assert limiter.acquire(subject) is True

    async def exercise() -> bytes:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=object()),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        ready = await anext(stream)
        keepalive = await anext(stream)
        await stream.aclose()
        return ready, keepalive

    ready, keepalive = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert keepalive == b": keepalive\n\n"
    assert broker.subscription.wait_timeout == pytest.approx(15.0)
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


def test_active_ide_stream_does_not_emit_reset_after_revoke_during_live_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_at = datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc)
    clock = {"now": started_at}
    revoked = {"value": False}

    class Subscription:
        closed = False

        async def wait(self, timeout=15.0):
            return True

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 0

    client_slot = "ks1_" + "r" * 43
    subject = ide_stream_subject(client_slot, 1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    monkeypatch.setattr(events_module, "_utcnow", lambda: clock["now"])
    monkeypatch.setattr(
        events_module,
        "_durable_stream_authorization_is_active",
        lambda _factory, candidate: candidate == authorization and not revoked["value"],
    )
    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda _factory, _cursor: StreamBatch(0, 1, ()),
    )

    def revoke_during_live_read(_factory, _cursor, *, prune):
        assert prune is False
        revoked["value"] = True
        return StreamBatch(0, 1, (), reset_reason="cursor_ahead")

    monkeypatch.setattr(events_module, "_read_stream_batch", revoke_during_live_read)
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire(subject) is True

    async def exercise() -> bytes:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=object()),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        ready = await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        return ready

    ready = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


def test_active_ide_stream_does_not_emit_source_command_after_fetch_crosses_revoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_at = datetime(2026, 8, 29, 14, 0, tzinfo=timezone.utc)
    clock = {"now": started_at}
    revoked = {"value": False}

    class Subscription:
        closed = False

        async def wait(self, timeout=15.0):
            raise AssertionError("source command should be checked before waiting")

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 1

    client_slot = "ks1_" + "s" * 43
    subject = ide_stream_subject(client_slot, 1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    monkeypatch.setattr(events_module, "_utcnow", lambda: clock["now"])
    monkeypatch.setattr(
        events_module,
        "_durable_stream_authorization_is_active",
        lambda _factory, candidate: candidate == authorization and not revoked["value"],
    )
    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda _factory, _cursor: StreamBatch(0, 1, ()),
    )

    def revoke_during_source_fetch(_factory, capability_id, capability_generation):
        assert capability_id == client_slot
        assert capability_generation == 1
        revoked["value"] = True
        return ({"command_id": "a" * 32},)

    monkeypatch.setattr(
        ide_source_module,
        "pending_source_open_commands",
        revoke_during_source_fetch,
    )
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire(subject) is True

    async def exercise() -> bytes:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=object()),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        ready = await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        return ready

    ready = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


@pytest.mark.parametrize("durable_change", ("revoke", "replace"))
def test_active_ide_stream_revalidates_after_subscribe_before_first_frame(
    sqlite_sessions,
    durable_change: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_slot = "ks1_" + "v" * 43
    subject = ide_stream_subject(client_slot, 1)
    activated_at = datetime.now(timezone.utc) - timedelta(days=1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    slot_key = f"{CAPABILITY_PREFIX}{client_slot}"
    with sqlite_sessions.begin() as db:
        db.add(
            RuntimeConfig(
                key=slot_key,
                value=json.dumps(
                    {
                        "v": 1,
                        "generation": 1,
                        "client_name": "durable stream authority",
                        "active": {
                            "generation": 1,
                            "digest": "a" * 64,
                            "client_name": "durable stream authority",
                            "scopes": list(IDE_CAPABILITY_SCOPES),
                            "activated_at": activated_at.isoformat(),
                            "revoked_at": None,
                        },
                        "pending": None,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        )

    class Subscription:
        closed = False

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            with sqlite_sessions.begin() as db:
                row = db.get(RuntimeConfig, slot_key)
                record = json.loads(row.value)
                if durable_change == "revoke":
                    record["active"]["revoked_at"] = datetime.now(timezone.utc).isoformat()
                else:
                    successor_activated_at = datetime.now(timezone.utc)
                    record["generation"] = 2
                    record["active"] = {
                        "generation": 2,
                        "digest": "b" * 64,
                        "client_name": "replacement stream authority",
                        "scopes": list(IDE_CAPABILITY_SCOPES),
                        "activated_at": successor_activated_at.isoformat(),
                        "revoked_at": None,
                    }
                row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
            return self.subscription

        def subject_connection_count(self, _subject):
            return 1

    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda *_args, **_kwargs: pytest.fail(
            "durably inactive authorization reached the initial event read"
        ),
    )
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire(subject) is True

    async def exercise() -> None:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=sqlite_sessions),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        with pytest.raises(StopAsyncIteration):
            await anext(stream)

    asyncio.run(exercise())
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


def test_active_ide_stream_revalidates_durable_authority_at_each_yield_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_slot = "ks1_" + "y" * 43
    subject = ide_stream_subject(client_slot, 1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    durable_checks = 0

    def durable_authority(_factory, candidate):
        nonlocal durable_checks
        assert candidate == authorization
        durable_checks += 1
        # The first check fences the subscribe/read boundary and the second
        # fences stream.ready. Simulate a cross-process committed revoke before
        # the next frame without relying on scheduler timing or sleeps.
        return durable_checks < 3

    class Subscription:
        closed = False

        def check(self):
            return None

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 0

    monkeypatch.setattr(
        events_module,
        "_durable_stream_authorization_is_active",
        durable_authority,
    )
    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda _factory, _cursor: StreamBatch(0, 1, (), reset_reason="cursor_ahead"),
    )
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire(subject) is True

    async def exercise() -> bytes:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=object()),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        ready = await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        return ready

    ready = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert durable_checks == 3
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


def test_capability_revocation_closes_only_matching_subject(sqlite_sessions) -> None:
    broker = EventWakeBroker(sqlite_sessions.kw["bind"], sqlite_sessions)

    async def exercise() -> None:
        loop = asyncio.get_running_loop()

        def register(subject: str):
            token = object()
            wake = asyncio.Event()
            with broker._lock:
                broker._subscribers[token] = (loop, wake, subject)
            return events_module.EventWakeSubscription(broker, token, wake)

        revoked = register("ide:revoked")
        unaffected = register("ide:other")

        assert broker.revoke_subject("ide:missing") == 0
        assert broker.revoke_subject("ide:revoked") == 1
        with pytest.raises(EventAuthorizationRevoked, match="authorization revoked"):
            await revoked.wait(timeout=0.1)
        assert await unaffected.wait(timeout=0.01) is False

        revoked.close()
        unaffected.close()

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_revoked_event_stream_closes_without_an_sse_error_frame(monkeypatch) -> None:
    class Subscription:
        closed = False

        def check(self):
            return None

        async def wait(self, timeout=15.0):
            raise EventAuthorizationRevoked("event stream authorization revoked")

        def close(self):
            self.closed = True

    class Broker:
        def __init__(self):
            self.subscription = Subscription()

        async def subscribe(self, _subject):
            return self.subscription

        def subject_connection_count(self, _subject):
            return 0

    monkeypatch.setattr(
        events_module,
        "prepare_stream",
        lambda _factory, _cursor: StreamBatch(0, 1, ()),
    )
    client_slot = "ks1_" + "w" * 43
    subject = ide_stream_subject(client_slot, 1)
    authorization = IdeStreamAuthorization(client_slot, 1)
    monkeypatch.setattr(
        events_module,
        "_durable_stream_authorization_is_active",
        lambda _factory, candidate: candidate == authorization,
    )
    broker = Broker()
    limiter = EventConnectionLimiter(installation_limit=1, subject_limit=1)
    assert limiter.acquire(subject) is True

    async def exercise() -> bytes:
        stream = _event_stream(
            SimpleNamespace(),
            SimpleNamespace(session_factory=object()),
            0,
            limiter,
            broker,
            subject,
            authorization,
        )
        ready = await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        return ready

    ready = asyncio.run(exercise())
    assert ready.startswith(b"event: stream.ready")
    assert broker.subscription.closed is True
    assert limiter.acquire(subject) is True
    limiter.release(subject)


def test_postgresql_dispatch_order_follows_commit_visibility(postgres_engine) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    earlier_row = factory()
    try:
        delayed = _project("delayed-commit")
        earlier_row.add(delayed)
        earlier_row.flush()

        with factory.begin() as committed_first:
            visible = _project("visible-first")
            committed_first.add(visible)
            committed_first.flush()
            visible_id = visible.id

        assert dispatch_pending_events(factory) == 1
        earlier_row.commit()
        delayed_id = delayed.id
        assert dispatch_pending_events(factory) == 1
    finally:
        earlier_row.close()

    with factory() as db:
        replay = list(
            db.scalars(
                select(EventOutbox)
                .where(EventOutbox.kind == "project.changed")
                .order_by(EventOutbox.event_id)
            )
        )
    assert [(row.aggregate_id, row.event_id) for row in replay] == [
        (str(visible_id), 1),
        (str(delayed_id), 2),
    ]


def test_postgresql_domain_notify_is_transactional_and_coalesced_across_flushes(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)

    async def exercise() -> None:
        subscription = await broker.subscribe("ide:notify-test")

        rolled_back = factory()
        try:
            rolled_back.add(_project("notify-rollback"))
            rolled_back.flush()
            rolled_back.rollback()
        finally:
            rolled_back.close()
        assert await subscription.wait(timeout=0.15) is False
        with factory() as db:
            assert db.scalar(
                select(EventOutbox).where(EventOutbox.aggregate_id == "1")
            ) is None

        committed = factory()
        try:
            project = _project("notify-multi-flush")
            committed.add(project)
            committed.flush()
            project_id = project.id
            project.default_branch = "release"
            committed.flush()
            committed.commit()
        finally:
            committed.close()
        assert await subscription.wait(timeout=5.0) is True
        with factory() as db:
            rows = list(
                db.scalars(
                    select(EventOutbox).where(
                        EventOutbox.kind == "project.changed",
                        EventOutbox.aggregate_id == str(project_id),
                    )
                )
            )
        assert len(rows) == 1
        assert rows[0].aggregate_revision == 2
        # Reconnect/replay is authoritative even if PostgreSQL coalesces wake
        # hints or the process observes both source-pending and event-ready.
        replay = prepare_stream(factory, 0)
        assert [event["event_id"] for event in replay.events] == [rows[0].event_id]
        subscription.close()

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_postgresql_listener_failure_closes_subscription_and_lazily_restarts(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)

    async def exercise() -> None:
        failed = await broker.subscribe("ide:listener-failure")
        backend_pid = broker._backend_pid
        assert backend_pid is not None
        with postgres_engine.begin() as connection:
            assert connection.scalar(
                select(func.pg_terminate_backend(backend_pid))
            ) is True
        with pytest.raises(RuntimeError, match="listener disconnected"):
            await failed.wait(timeout=5.0)
        failed.close()

        recovered = await broker.subscribe("ide:listener-recovered")
        with factory.begin() as db:
            db.add(_project("listener-recovered"))
        assert await recovered.wait(timeout=5.0) is True
        recovered.close()

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_postgresql_dispatches_committed_intent_without_sse_subscribers(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)

    async def exercise() -> int:
        await broker.start()
        with factory.begin() as db:
            project = _project("zero-subscribers")
            db.add(project)
            db.flush()
            project_id = project.id
        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline:
            with factory() as db:
                event_id = db.scalar(
                    select(EventOutbox.event_id).where(
                        EventOutbox.kind == "project.changed",
                        EventOutbox.aggregate_id == str(project_id),
                    )
                )
            if event_id is not None:
                return int(event_id)
            await asyncio.sleep(0.01)
        raise AssertionError("outbox dispatcher did not wake without an SSE subscriber")

    try:
        assert asyncio.run(exercise()) == 1
    finally:
        broker.close()


def test_postgresql_dispatch_continuation_drains_more_than_one_wake_budget(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)
    total = (
        events_module.MAX_DISPATCH_BATCHES_PER_WAKE
        * events_module.DISPATCH_BATCH_SIZE
        + 7
    )

    async def exercise() -> None:
        await broker.start()
        with factory.begin() as db:
            db.add_all([_project(f"backlog-{number}") for number in range(total)])
        deadline = asyncio.get_running_loop().time() + 10.0
        while asyncio.get_running_loop().time() < deadline:
            with factory() as db:
                dispatched = db.scalar(
                    select(func.count(EventOutbox.row_id)).where(
                        EventOutbox.event_id.is_not(None)
                    )
                )
            if dispatched == total:
                return
            await asyncio.sleep(0.01)
        raise AssertionError("self-notified dispatch continuation left a durable tail")

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_postgresql_poison_row_quarantines_without_stranding_valid_tail(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)
    total_valid = events_module.DISPATCH_BATCH_SIZE + 5

    async def exercise() -> None:
        await broker.start()
        with factory.begin() as db:
            db.add(
                EventOutbox(
                    schema_version=1,
                    kind="project.changed",
                    aggregate_type="project",
                    aggregate_id="1",
                    aggregate_revision=1,
                    scope={"project_id": 1},
                    change="created",
                    hint={"status": "source text is forbidden"},
                    dispatch_attempts=0,
                )
            )
            db.add_all(
                [
                    EventOutbox(
                        schema_version=1,
                        kind="project.changed",
                        aggregate_type="project",
                        aggregate_id=str(number + 2),
                        aggregate_revision=1,
                        scope={"project_id": number + 2},
                        change="created",
                        hint={},
                        dispatch_attempts=0,
                    )
                    for number in range(total_valid)
                ]
            )
            db.execute(text(f"SELECT pg_notify('{events_module.OUTBOX_PENDING_CHANNEL}', '1')"))

        deadline = asyncio.get_running_loop().time() + 10.0
        while asyncio.get_running_loop().time() < deadline:
            with factory() as db:
                poison = db.scalar(
                    select(EventOutbox).where(EventOutbox.aggregate_id == "1")
                )
                dispatched = db.scalar(
                    select(func.count(EventOutbox.row_id)).where(
                        EventOutbox.event_id.is_not(None)
                    )
                )
            if (
                poison is not None
                and poison.quarantined_at is not None
                and poison.dispatch_attempts == 3
                and dispatched == total_valid
            ):
                return
            await asyncio.sleep(0.01)
        raise AssertionError("poison row stranded the valid outbox tail")

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_postgresql_zero_subscriber_listener_reconnects_after_backend_loss(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    install_outbox_listeners()
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)

    async def exercise() -> None:
        await broker.start()
        original_pid = broker._backend_pid
        assert original_pid is not None
        with postgres_engine.begin() as connection:
            assert connection.scalar(select(func.pg_terminate_backend(original_pid))) is True

        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline:
            recovered_pid = broker._backend_pid
            if recovered_pid is not None and recovered_pid != original_pid:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("zero-subscriber listener did not reconnect")

        with factory.begin() as db:
            project = _project("after-listener-reconnect")
            db.add(project)
            db.flush()
            project_id = project.id
        dispatch_deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < dispatch_deadline:
            with factory() as db:
                event_id = db.scalar(
                    select(EventOutbox.event_id).where(
                        EventOutbox.kind == "project.changed",
                        EventOutbox.aggregate_id == str(project_id),
                    )
                )
            if event_id is not None:
                return
            await asyncio.sleep(0.01)
        raise AssertionError("reconnected listener did not dispatch a later domain write")

    try:
        asyncio.run(exercise())
    finally:
        broker.close()


def test_postgresql_broker_close_removes_dedicated_listener_backend(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, autoflush=False, future=True)
    broker = EventWakeBroker(postgres_engine, factory)
    asyncio.run(broker.start())
    backend_pid = broker._backend_pid
    assert backend_pid is not None
    broker.close()

    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"),
            {"pid": backend_pid},
        ) == 0
