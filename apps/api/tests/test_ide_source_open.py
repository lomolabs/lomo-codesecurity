from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from kodesec_api.auth import (
    CAPABILITY_PREFIX,
    AuthContext,
    IDE_CAPABILITY_SCOPES,
    list_ide_capabilities,
)
from kodesec_api.db import Base
from kodesec_api.events import EventWakeBroker, encode_sse, ide_stream_subject
from kodesec_api.ide_source import (
    SourceOpenAck,
    SourceOpenCreate,
    acknowledge_source_open_command,
    create_source_open_command,
    get_source_open_project_context,
    pending_source_open_commands,
)
from kodesec_api.models import Finding, IdeSourceOpenCommand, Project, RuntimeConfig, Scan
from kodesec_api.settings import Settings


@pytest.fixture()
def source_open_fixture():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    broker = EventWakeBroker(engine, factory)
    capability_id = "ks1_" + "s" * 43
    activated_at = datetime.now(timezone.utc)
    with factory.begin() as db:
        db.add(
            RuntimeConfig(
                key=f"{CAPABILITY_PREFIX}{capability_id}",
                value=json.dumps(
                    {
                        "v": 1,
                        "generation": 1,
                        "client_name": "VS Code target",
                        "active": {
                            "generation": 1,
                            "digest": "a" * 64,
                            "client_name": "VS Code target",
                            "scopes": list(IDE_CAPABILITY_SCOPES),
                            "activated_at": activated_at.isoformat(),
                            "revoked_at": None,
                        },
                        "pending": None,
                    }
                ),
            )
        )
        project = Project(name="source-open", repo_path="/workspaces/source-open")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, status="completed", revision=1, findings_revision=3)
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            scan_finding_number=7,
            scanner="checkov",
            rule_id="CKV_TEST",
            severity="high",
            file_path="private/exact.tf",
            start_line=4,
            end_line=4,
            message="must never enter the targeted SSE envelope",
            code_snippet="secret body must not be broadcast",
            fingerprint="f" * 64,
            revision=2,
        )
        db.add(finding)
        db.flush()
        identities = (project.id, scan.id, finding.id)
    try:
        yield factory, broker, capability_id, identities
    finally:
        broker.close()
        engine.dispose()


def _request(broker: EventWakeBroker, key: str = "web-source-open-1234"):
    return SimpleNamespace(
        headers={"Idempotency-Key": key},
        app=SimpleNamespace(state=SimpleNamespace(event_wake_broker=broker)),
    )


def _browser() -> AuthContext:
    return AuthContext(kind="browser", subject="local-browser", scopes=frozenset({"api:read", "api:write"}))


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        KODESEC_INSTALLATION_SECRET="installation-" * 4,
        KODESEC_BOOTSTRAP_TOKEN="bootstrap-token-" * 4,
        KODESEC_CONTROL_ORIGINS="http://127.0.0.1:8080",
        KODESEC_ALLOWED_ROOTS="/workspaces",
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )


def _ide(capability_id: str, generation: int = 1) -> AuthContext:
    return AuthContext(
        kind="ide",
        subject=capability_id,
        scopes=frozenset(IDE_CAPABILITY_SCOPES),
        capability_generation=generation,
    )


def test_immutable_git_snapshot_never_queues_current_file_navigation(source_open_fixture, monkeypatch):
    factory, broker, capability_id, (project_id, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: 1)
    with factory.begin() as db:
        db.get(Project, project_id).repo_path = "/source-snapshots/git-commit/" + "a" * 64
    payload = SourceOpenCreate(finding_id=finding_id, expected_finding_revision=2,
        expected_findings_revision=3, target_capability_id=capability_id, expected_target_generation=1)
    with factory() as db, pytest.raises(HTTPException) as blocked:
        create_source_open_command(payload, _request(broker), _browser(), db)
    assert blocked.value.status_code == 409
    assert blocked.value.detail["code"] == "ide_source_immutable_git"
    with factory() as db:
        assert db.scalar(select(func.count(IdeSourceOpenCommand.id))) == 0


def test_exact_recipient_command_is_durable_body_free_and_acknowledged(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, (project_id, scan_id, finding_id) = source_open_fixture
    target_subject = ide_stream_subject(capability_id, 1)
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: int(subject == target_subject))
    wakes: list[str] = []
    monkeypatch.setattr(broker, "wake_subject", lambda subject: wakes.append(subject) or 1)
    payload = SourceOpenCreate(
        finding_id=finding_id,
        expected_finding_revision=2,
        expected_findings_revision=3,
        target_capability_id=capability_id,
        expected_target_generation=1,
    )
    with factory() as db:
        created = create_source_open_command(payload, _request(broker), _browser(), db)
    assert created["status"] == "queued"
    assert created["project_id"] == project_id
    assert wakes == [target_subject]

    with factory.begin() as db:
        command = db.get(IdeSourceOpenCommand, str(created["id"]))
        project = db.get(Project, project_id)
        assert command is not None
        assert project is not None
        assert command.project_repo_path == "/workspaces/source-open"
        project.repo_path = "/workspaces/renamed-after-queue"
    with factory() as db:
        assert get_source_open_project_context(
            str(created["id"]),
            _ide(capability_id),
            db,
        ) == {
            "v": 1,
            "command_id": created["id"],
            "project_id": project_id,
            "project_repo_path": "/workspaces/source-open",
        }

    documents = pending_source_open_commands(factory, capability_id, 1)
    assert len(documents) == 1
    assert documents[0] == {
        "v": 1,
        "command_id": created["id"],
        "project_id": project_id,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "scan_finding_number": 7,
        "expected_finding_revision": 2,
        "expected_findings_revision": 3,
        "expires_at": created["expires_at"],
    }
    frame = encode_sse("ide.source.open", documents[0]).decode()
    assert "private/exact.tf" not in frame
    assert "secret body" not in frame
    assert "must never" not in frame

    with factory() as db:
        acknowledgement = acknowledge_source_open_command(
            str(created["id"]),
            SourceOpenAck(status="opened", error_code=None),
            _request(broker, "unused-ack-key"),
            _ide(capability_id),
            db,
        )
    assert acknowledgement["status"] == "opened"
    assert acknowledgement["revision"] == 2
    assert pending_source_open_commands(factory, capability_id, 1) == ()
    assert wakes[-1] == "browser:local-browser"


def test_two_connected_streams_reject_ambiguous_target_without_queueing(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, (_, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: 2)
    payload = SourceOpenCreate(
        finding_id=finding_id,
        expected_finding_revision=2,
        expected_findings_revision=3,
        target_capability_id=capability_id,
        expected_target_generation=1,
    )
    with factory() as db, pytest.raises(HTTPException) as rejected:
        create_source_open_command(payload, _request(broker), _browser(), db)
    assert rejected.value.status_code == 409
    assert rejected.value.detail["code"] == "ide_source_target_ambiguous"
    with factory() as db:
        assert db.scalar(select(func.count(IdeSourceOpenCommand.id))) == 0


@pytest.mark.parametrize("unsafe_path", [
    "/workspaces/source-open/../outside",
    "/workspaces/source-open/\ud800",
])
def test_noncanonical_registered_project_is_rejected_before_source_open_queueing(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_path: str,
) -> None:
    factory, broker, capability_id, (project_id, _, finding_id) = source_open_fixture
    target_subject = ide_stream_subject(capability_id, 1)
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: int(subject == target_subject))
    with factory() as db:
        project = db.get(Project, project_id)
        assert project is not None
        project.repo_path = unsafe_path
        payload = SourceOpenCreate(
            finding_id=finding_id,
            expected_finding_revision=2,
            expected_findings_revision=3,
            target_capability_id=capability_id,
            expected_target_generation=1,
        )
        with pytest.raises(HTTPException) as rejected:
            create_source_open_command(payload, _request(broker), _browser(), db)
        assert rejected.value.status_code == 409
        assert rejected.value.detail["code"] == "ide_source_project_noncanonical"
        db.rollback()
    with factory() as db:
        assert db.scalar(select(func.count(IdeSourceOpenCommand.id))) == 0


def test_capability_listing_distinguishes_disconnected_exact_and_ambiguous_targets(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, _ = source_open_fixture
    request = _request(broker)
    for connection_count, available, reason in (
        (0, False, "not currently connected"),
        (1, True, None),
        (2, False, "multiple connected windows"),
    ):
        monkeypatch.setattr(broker, "subject_connection_count", lambda subject, count=connection_count: count)
        with factory() as db:
            [listed] = list_ide_capabilities(request, _browser(), db, _settings())
        assert listed.id == capability_id
        assert listed.source_open_available is available
        if reason is None:
            assert listed.source_open_disabled_reason is None
        else:
            assert reason in str(listed.source_open_disabled_reason)


def test_create_is_revision_fenced_idempotent_and_ack_is_recipient_bound(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, (_, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: 1)
    monkeypatch.setattr(broker, "wake_subject", lambda subject: 1)
    stale = SourceOpenCreate(
        finding_id=finding_id,
        expected_finding_revision=1,
        expected_findings_revision=3,
        target_capability_id=capability_id,
        expected_target_generation=1,
    )
    with factory() as db, pytest.raises(HTTPException) as rejected:
        create_source_open_command(stale, _request(broker), _browser(), db)
    assert rejected.value.status_code == 409
    assert rejected.value.detail["code"] == "revision_conflict"

    exact = stale.model_copy(update={"expected_finding_revision": 2})
    with factory() as db:
        first = create_source_open_command(exact, _request(broker), _browser(), db)
    with factory() as db:
        replay = create_source_open_command(exact, _request(broker), _browser(), db)
    assert replay["id"] == first["id"]
    with factory() as db:
        assert db.scalar(select(func.count(IdeSourceOpenCommand.id))) == 1

    with factory() as db, pytest.raises(HTTPException) as wrong_target:
        acknowledge_source_open_command(
            str(first["id"]),
            SourceOpenAck(status="failed", error_code="workspace_not_open"),
            _request(broker),
            _ide("ks1_" + "o" * 43),
            db,
        )
    assert wrong_target.value.status_code == 404
    with factory() as db:
        opened = acknowledge_source_open_command(
            str(first["id"]),
            SourceOpenAck(status="opened", error_code=None),
            _request(broker),
            _ide(capability_id),
            db,
        )
    with factory() as db:
        duplicate = acknowledge_source_open_command(
            str(first["id"]),
            SourceOpenAck(status="opened", error_code=None),
            _request(broker),
            _ide(capability_id),
            db,
        )
    assert duplicate == opened
    with factory() as db, pytest.raises(HTTPException) as conflicting:
        acknowledge_source_open_command(
            str(first["id"]),
            SourceOpenAck(status="failed", error_code="workspace_not_open"),
            _request(broker),
            _ide(capability_id),
            db,
        )
    assert conflicting.value.status_code == 409


def test_source_open_is_generation_fenced_from_create_through_delivery_and_ack(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, (_, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda _subject: 1)
    monkeypatch.setattr(broker, "wake_subject", lambda _subject: 1)
    stale_target = SourceOpenCreate(
        finding_id=finding_id,
        expected_finding_revision=2,
        expected_findings_revision=3,
        target_capability_id=capability_id,
        expected_target_generation=2,
    )
    with factory() as db, pytest.raises(HTTPException) as rejected:
        create_source_open_command(stale_target, _request(broker), _browser(), db)
    assert rejected.value.status_code == 409
    assert rejected.value.detail == {
        "code": "ide_source_target_generation_conflict",
        "message": "The selected IDE authority changed before source navigation was queued.",
        "action": "refresh_ide_clients",
        "context": {
            "target_capability_id": capability_id,
            "expected_target_generation": 2,
            "current_target_generation": 1,
        },
    }

    exact_target = stale_target.model_copy(update={"expected_target_generation": 1})
    with factory() as db:
        created = create_source_open_command(
            exact_target,
            _request(broker, "web-source-open-generation"),
            _browser(),
            db,
        )
    assert created["expected_target_generation"] == 1
    assert len(pending_source_open_commands(factory, capability_id, 1)) == 1
    assert pending_source_open_commands(factory, capability_id, 2) == ()

    with factory() as db, pytest.raises(HTTPException) as wrong_context_generation:
        get_source_open_project_context(str(created["id"]), _ide(capability_id, 2), db)
    assert wrong_context_generation.value.status_code == 404
    with factory() as db, pytest.raises(HTTPException) as wrong_ack_generation:
        acknowledge_source_open_command(
            str(created["id"]),
            SourceOpenAck(status="opened", error_code=None),
            _request(broker),
            _ide(capability_id, 2),
            db,
        )
    assert wrong_ack_generation.value.status_code == 404


@pytest.mark.parametrize("authority_change", ["replacement", "revocation"])
@pytest.mark.parametrize("operation", ["context", "ack"])
def test_stale_admitted_ide_context_cannot_disclose_or_ack_after_authority_change(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
    authority_change: str,
    operation: str,
) -> None:
    factory, broker, capability_id, (_, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda _subject: 1)
    monkeypatch.setattr(broker, "wake_subject", lambda _subject: 1)
    with factory() as db:
        created = create_source_open_command(
            SourceOpenCreate(
                finding_id=finding_id,
                expected_finding_revision=2,
                expected_findings_revision=3,
                target_capability_id=capability_id,
                expected_target_generation=1,
            ),
            _request(broker, f"stale-authority-{authority_change}-{operation}"),
            _browser(),
            db,
        )

    admitted_context = _ide(capability_id, 1)
    with factory.begin() as db:
        row = db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{capability_id}")
        assert row is not None
        record = json.loads(row.value)
        active = record["active"]
        assert active is not None
        if authority_change == "replacement":
            record["generation"] = 2
            active["generation"] = 2
            active["digest"] = "b" * 64
        else:
            active["revoked_at"] = datetime.now(timezone.utc).isoformat()
        row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)

    with factory() as db, pytest.raises(HTTPException) as rejected:
        if operation == "context":
            get_source_open_project_context(
                str(created["id"]),
                admitted_context,
                db,
            )
        else:
            acknowledge_source_open_command(
                str(created["id"]),
                SourceOpenAck(status="opened", error_code=None),
                _request(broker, "unused-stale-ack-key"),
                admitted_context,
                db,
            )
    assert rejected.value.status_code == 404
    assert rejected.value.detail == "source-open command not found"
    assert "project_repo_path" not in json.dumps(rejected.value.detail)

    with factory() as db:
        command = db.get(IdeSourceOpenCommand, str(created["id"]))
        assert command is not None
        assert command.status == "queued"
        assert command.revision == 1
        assert command.error_code is None
        assert command.acknowledged_at is None


def test_expired_command_cannot_be_opened(
    source_open_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, broker, capability_id, (_, _, finding_id) = source_open_fixture
    monkeypatch.setattr(broker, "subject_connection_count", lambda subject: 1)
    monkeypatch.setattr(broker, "wake_subject", lambda subject: 1)
    payload = SourceOpenCreate(
        finding_id=finding_id,
        expected_finding_revision=2,
        expected_findings_revision=3,
        target_capability_id=capability_id,
        expected_target_generation=1,
    )
    with factory() as db:
        created = create_source_open_command(payload, _request(broker), _browser(), db)
    with factory.begin() as db:
        command = db.get(IdeSourceOpenCommand, created["id"])
        assert command is not None
        command.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with factory() as db, pytest.raises(HTTPException) as expired:
        acknowledge_source_open_command(
            str(created["id"]),
            SourceOpenAck(status="opened", error_code=None),
            _request(broker),
            _ide(capability_id),
            db,
        )
    assert expired.value.status_code == 409
    assert expired.value.detail["code"] == "ide_source_command_expired"
    with factory() as db:
        command = db.get(IdeSourceOpenCommand, created["id"])
        assert command is not None
        assert command.status == "expired"
        assert command.revision == 2


def test_broker_exact_subject_wake_does_not_wake_other_capabilities(
    source_open_fixture,
) -> None:
    _, broker, capability_id, _ = source_open_fixture

    async def exercise() -> None:
        loop = asyncio.get_running_loop()
        target = asyncio.Event()
        other = asyncio.Event()
        with broker._lock:
            broker._subscribers = {
                object(): (loop, target, ide_stream_subject(capability_id, 1)),
                object(): (loop, other, ide_stream_subject("ks1_" + "o" * 43, 1)),
            }
        assert broker.subject_connection_count(ide_stream_subject(capability_id, 1)) == 1
        assert broker.wake_subject(ide_stream_subject(capability_id, 1)) == 1
        await asyncio.sleep(0)
        assert target.is_set()
        assert not other.is_set()

    asyncio.run(exercise())
