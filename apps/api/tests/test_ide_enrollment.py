from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

import kodesec_api.auth as auth_module
from kodesec_api.app import create_app
from kodesec_api.auth import (
    IDE_CAPABILITY_SCOPES,
    SESSION_COOKIE,
    AuthContext,
    wait_for_ide_enrollment_decision,
)
from kodesec_api.db import Base, Runtime, SchemaVerification
from kodesec_api.events import EventWakeBroker
from kodesec_api.models import IdeEnrollment, RuntimeConfig
from kodesec_api.settings import Settings


ORIGIN = "http://127.0.0.1:18089"
INSTALLATION_SECRET = "enrollment-installation-secret-" * 2
BOOTSTRAP_TOKEN = "enrollment-bootstrap-token-" * 2


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_SOURCE_SNAPSHOT_DIR=str(tmp_path / "source-snapshots"),
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )


def _engine():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


@contextmanager
def _auth_only_startup():
    with (
        patch(
            "kodesec_api.main.init_db",
            return_value=SchemaVerification(
                identity="enrollment-test",
                fingerprint="a" * 64,
                initialized_at=datetime(2026, 8, 30, tzinfo=timezone.utc),
            ),
        ),
        patch("kodesec_api.main.enforce_runtime_publication_boundaries"),
    ):
        yield


def _bootstrap(client: TestClient) -> str:
    response = client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": BOOTSTRAP_TOKEN},
    )
    assert response.status_code == 200, response.text
    assert client.cookies.get(SESSION_COOKIE)
    return str(response.json()["csrf_token"])


def _enroll(client: TestClient, slot_character: str, name: str = "Local VS Code"):
    response = client.post(
        "/v1/auth/ide/enrollments",
        json={
            "client_name": name,
            "client_slot": "ks1_" + slot_character * 43,
            "expected_active_generation": 0,
        },
    )
    assert response.status_code == 201, response.text
    return response


def test_installer_bootstrap_atomically_claims_only_pristine_first_ide(
    tmp_path: Path,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as client:
                first = _enroll(client, "f", "First Mac profile").json()
                first_bearer = {"Authorization": f"Bearer {first['capability']}"}
                claimed = client.post(
                    "/v1/auth/ide/enrollments/current/claim-first-owner",
                    headers=first_bearer,
                    json={
                        "bootstrap_token": BOOTSTRAP_TOKEN,
                        "expected_request_id": first["request_id"],
                        "expected_revision": first["revision"],
                        "expected_generation": first["generation"],
                    },
                )
                assert claimed.status_code == 200, claimed.text
                assert claimed.json()["state"] == "approved"
                assert claimed.json()["revision"] == 2

                activated = client.post("/v1/auth/ide/activate", headers=first_bearer)
                assert activated.status_code == 200, activated.text
                invitation = client.post(
                    "/v1/auth/ide/browser-invitations",
                    headers=first_bearer,
                    json={"purpose": "integrated_dashboard"},
                )
                assert invitation.status_code == 200, invitation.text
                assert invitation.json()["bootstrap_token"].startswith("kbi1.")

                later = _enroll(client, "l", "Later Mac profile").json()
                later_bearer = {"Authorization": f"Bearer {later['capability']}"}
                refused = client.post(
                    "/v1/auth/ide/enrollments/current/claim-first-owner",
                    headers=later_bearer,
                    json={
                        "bootstrap_token": BOOTSTRAP_TOKEN,
                        "expected_request_id": later["request_id"],
                        "expected_revision": later["revision"],
                        "expected_generation": later["generation"],
                    },
                )
                assert refused.status_code == 409, refused.text
                assert refused.json()["detail"]["code"] == "first_owner_claim_not_pristine"
                premature = client.post("/v1/auth/ide/activate", headers=later_bearer)
                assert premature.status_code == 409
                assert premature.json()["detail"]["code"] == "ide_enrollment_approval_required"
    finally:
        engine.dispose()


def test_first_owner_claim_selects_oldest_live_pending_even_when_newer_calls_first(
    tmp_path: Path,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as client:
                requested_at = datetime.now(timezone.utc)
                with patch(
                    "kodesec_api.auth._utcnow",
                    side_effect=[requested_at, requested_at + timedelta(seconds=1)],
                ):
                    older = _enroll(client, "o", "Older profile").json()
                    newer = _enroll(client, "n", "Newer profile").json()

                def claim(enrollment: dict[str, object]):
                    return client.post(
                        "/v1/auth/ide/enrollments/current/claim-first-owner",
                        headers={"Authorization": f"Bearer {enrollment['capability']}"},
                        json={
                            "bootstrap_token": BOOTSTRAP_TOKEN,
                            "expected_request_id": enrollment["request_id"],
                            "expected_revision": enrollment["revision"],
                            "expected_generation": enrollment["generation"],
                        },
                    )

                refused_newer = claim(newer)
                assert refused_newer.status_code == 409, refused_newer.text
                assert refused_newer.json()["detail"]["code"] == "first_owner_claim_not_winner"

                winner = claim(older)
                assert winner.status_code == 200, winner.text
                assert winner.json()["state"] == "approved"

                newer_status = client.get(
                    "/v1/auth/ide/enrollments/current/wait?after_revision=0",
                    headers={"Authorization": f"Bearer {newer['capability']}"},
                )
                assert newer_status.status_code == 200, newer_status.text
                assert newer_status.json()["state"] == "awaiting_approval"

            with Runtime.create(settings, engine=engine).session_factory() as db:
                marker = db.get(RuntimeConfig, auth_module.BOOTSTRAP_MARKER)
                assert marker is not None
                enrollments = list(db.scalars(
                    select(IdeEnrollment).order_by(
                        IdeEnrollment.requested_at.asc(),
                        IdeEnrollment.request_id.asc(),
                    )
                ))
                assert [(row.request_id, row.state) for row in enrollments] == [
                    (older["request_id"], "approved"),
                    (newer["request_id"], "awaiting_approval"),
                ]
    finally:
        engine.dispose()


def test_postgresql_simultaneous_first_owner_claims_approve_exactly_oldest_pending(
    postgres_engine,
    tmp_path: Path,
) -> None:
    Base.metadata.create_all(postgres_engine)
    settings = _settings(tmp_path)
    barrier = Barrier(2)

    with _auth_only_startup():
        app = create_app(runtime_override=Runtime.create(settings, engine=postgres_engine))
        with TestClient(app, base_url=ORIGIN) as client:
            requested_at = datetime.now(timezone.utc)
            with patch(
                "kodesec_api.auth._utcnow",
                side_effect=[requested_at, requested_at + timedelta(seconds=1)],
            ):
                older = _enroll(client, "o", "Concurrent older profile").json()
                newer = _enroll(client, "n", "Concurrent newer profile").json()

            def claim(enrollment: dict[str, object]):
                barrier.wait(timeout=5)
                return client.post(
                    "/v1/auth/ide/enrollments/current/claim-first-owner",
                    headers={"Authorization": f"Bearer {enrollment['capability']}"},
                    json={
                        "bootstrap_token": BOOTSTRAP_TOKEN,
                        "expected_request_id": enrollment["request_id"],
                        "expected_revision": enrollment["revision"],
                        "expected_generation": enrollment["generation"],
                    },
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                older_future = executor.submit(claim, older)
                newer_future = executor.submit(claim, newer)
                older_claim = older_future.result(timeout=10)
                newer_claim = newer_future.result(timeout=10)

            assert older_claim.status_code == 200, older_claim.text
            assert older_claim.json()["state"] == "approved"
            assert newer_claim.status_code == 409, newer_claim.text
            assert newer_claim.json()["detail"]["code"] in {
                "first_owner_claim_not_winner",
                "first_owner_bootstrap_consumed",
            }

    with Runtime.create(settings, engine=postgres_engine).session_factory() as db:
        marker = db.get(RuntimeConfig, auth_module.BOOTSTRAP_MARKER)
        assert marker is not None
        enrollments = list(db.scalars(
            select(IdeEnrollment).order_by(
                IdeEnrollment.requested_at.asc(),
                IdeEnrollment.request_id.asc(),
            )
        ))
        assert [(row.request_id, row.state) for row in enrollments] == [
            (older["request_id"], "approved"),
            (newer["request_id"], "awaiting_approval"),
        ]


def test_no_paste_enrollment_requires_exact_browser_approval_and_survives_restart(
    tmp_path: Path,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            first_app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(first_app, base_url=ORIGIN) as first:
                csrf = _bootstrap(first)
                issued = _enroll(first, "a")
                body = issued.json()
                assert set(body) == {
                    "request_id",
                    "state",
                    "revision",
                    "verification_code",
                    "capability",
                    "scopes",
                    "client_slot",
                    "generation",
                    "requested_at",
                    "activation_expires_at",
                }
                assert body["state"] == "awaiting_approval"
                assert body["revision"] == 1
                assert body["scopes"] == list(IDE_CAPABILITY_SCOPES)
                assert body["capability"].startswith("kc1.")
                assert issued.headers["cache-control"] == "no-store"
                bearer = {"Authorization": f"Bearer {body['capability']}"}

                premature = first.post("/v1/auth/ide/activate", headers=bearer)
                assert premature.status_code == 409
                assert premature.json()["detail"] == {
                    "code": "ide_enrollment_approval_required",
                    "message": "Approve this IDE enrollment in CodeSecurity Settings before activation.",
                    "action": "review_pending_enrollments",
                }
                status = first.get(
                    "/v1/auth/ide/enrollments/current/wait?after_revision=0",
                    headers=bearer,
                )
                assert status.status_code == 200, status.text
                assert status.json()["state"] == "awaiting_approval"

                pending = first.get("/v1/auth/ide/enrollments")
                assert pending.status_code == 200, pending.text
                assert pending.json() == [{
                    "request_id": body["request_id"],
                    "state": "awaiting_approval",
                    "revision": 1,
                    "verification_code": body["verification_code"],
                    "scopes": list(IDE_CAPABILITY_SCOPES),
                    "client_slot": body["client_slot"],
                    "client_name": "Local VS Code",
                    "generation": 1,
                    "requested_at": body["requested_at"],
                    "activation_expires_at": body["activation_expires_at"],
                }]
                assert body["capability"] not in json.dumps(pending.json())

                no_csrf = first.post(
                    f"/v1/auth/ide/enrollments/{body['request_id']}/decision",
                    headers={"Origin": ORIGIN},
                    json={
                        "decision": "approved",
                        "expected_revision": 1,
                        "expected_generation": 1,
                    },
                )
                assert no_csrf.status_code == 403
                approved = first.post(
                    f"/v1/auth/ide/enrollments/{body['request_id']}/decision",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "decision": "approved",
                        "expected_revision": 1,
                        "expected_generation": 1,
                    },
                )
                assert approved.status_code == 200, approved.text
                assert approved.json()["state"] == "approved"
                assert approved.json()["revision"] == 2

                stale = first.post(
                    f"/v1/auth/ide/enrollments/{body['request_id']}/decision",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "decision": "rejected",
                        "expected_revision": 1,
                        "expected_generation": 1,
                    },
                )
                assert stale.status_code == 409
                assert stale.json()["detail"]["code"] == "ide_enrollment_revision_conflict"

                activated = first.post("/v1/auth/ide/activate", headers=bearer)
                assert activated.status_code == 200, activated.text
                assert activated.json()["generation"] == 1

            with first_app.state.runtime.session_factory() as db:
                runtime_values = list(db.scalars(select(RuntimeConfig.value)))
                enrollment = db.scalar(select(IdeEnrollment))
                assert enrollment is not None
                enrollment_document = {
                    column.name: getattr(enrollment, column.name)
                    for column in IdeEnrollment.__table__.columns
                }
                activated_at = enrollment.activated_at
            assert body["capability"] not in json.dumps(runtime_values)
            assert body["capability"] not in json.dumps(enrollment_document, default=str)
            assert activated_at is not None

            second_app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(second_app, base_url=ORIGIN) as second:
                long_after_activation_deadline = (
                    datetime.fromisoformat(body["activation_expires_at"])
                    + timedelta(days=1)
                )
                with patch(
                    "kodesec_api.auth._utcnow",
                    return_value=long_after_activation_deadline,
                ):
                    retained = second.get(
                        "/v1/auth/ide/enrollments/current/wait?after_revision=0",
                        headers=bearer,
                    )
                assert retained.status_code == 200, retained.text
                assert retained.json()["state"] == "approved"
                assert retained.json()["revision"] == 3
                replay = second.post("/v1/auth/ide/activate", headers=bearer)
                assert replay.status_code == 200, replay.text
    finally:
        engine.dispose()


def test_wait_rereads_committed_decision_when_event_listener_disconnects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as client:
                issued = _enroll(client, "w", "Listener recovery VS Code").json()

                broker = EventWakeBroker(
                    engine,
                    app.state.runtime.session_factory,
                )
                closed = False

                class DisconnectAfterCommit:
                    async def wait(self, timeout: float) -> bool:
                        assert timeout == auth_module.IDE_ENROLLMENT_WAIT_SECONDS
                        with app.state.runtime.session_factory() as db, db.begin():
                            sidecar = db.get(IdeEnrollment, issued["request_id"])
                            assert sidecar is not None
                            sidecar.state = "approved"
                            sidecar.decision_at = datetime.now(timezone.utc)
                            sidecar.revision = 2
                        raise RuntimeError("fixture listener disconnected")

                    def close(self) -> None:
                        nonlocal closed
                        closed = True

                async def subscribe(subject: str):
                    assert subject == f"ide-enrollment:{issued['request_id']}"
                    return DisconnectAfterCommit()

                monkeypatch.setattr(broker, "subscribe", subscribe)
                request = Request({
                    "type": "http",
                    "method": "GET",
                    "path": "/v1/auth/ide/enrollments/current/wait",
                    "headers": [],
                    "app": SimpleNamespace(
                        state=SimpleNamespace(event_wake_broker=broker),
                    ),
                })
                context = AuthContext(
                    kind="ide-pending",
                    subject=issued["client_slot"],
                    scopes=frozenset({
                        "capability:activate-self",
                        "capability:cancel-pending",
                    }),
                    capability_generation=issued["generation"],
                )
                runtime = SimpleNamespace(
                    session_factory=app.state.runtime.session_factory,
                    engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
                )
                result = asyncio.run(wait_for_ide_enrollment_decision(
                    request,
                    after_revision=1,
                    context=context,
                    runtime=runtime,
                ))
                assert result.state == "approved"
                assert result.revision == 2
                assert closed is True
    finally:
        engine.dispose()


def test_rejection_expiry_and_live_request_cap_are_typed_and_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        monkeypatch.setattr(auth_module, "_MAX_LIVE_IDE_ENROLLMENTS", 1)
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as client:
                internal_attempt = client.post(
                    "/v1/auth/ide/enrollments",
                    headers={"Host": "api:8080"},
                    json={
                        "client_name": "Internal service",
                        "client_slot": "ks1_" + "i" * 43,
                        "expected_active_generation": 0,
                    },
                )
                assert internal_attempt.status_code == 403
                assert internal_attempt.json()["detail"] == (
                    "IDE enrollment requires the exact loopback control host"
                )
                csrf = _bootstrap(client)
                issued = _enroll(client, "b", "Rejected VS Code").json()
                capped = client.post(
                    "/v1/auth/ide/enrollments",
                    json={
                        "client_name": "Another VS Code",
                        "client_slot": "ks1_" + "c" * 43,
                        "expected_active_generation": 0,
                    },
                )
                assert capped.status_code == 429
                assert capped.json()["detail"]["code"] == "ide_enrollment_limit_reached"

                rejected = client.post(
                    f"/v1/auth/ide/enrollments/{issued['request_id']}/decision",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "decision": "rejected",
                        "expected_revision": 1,
                        "expected_generation": 1,
                    },
                )
                assert rejected.status_code == 200, rejected.text
                bearer = {"Authorization": f"Bearer {issued['capability']}"}
                status = client.get(
                    "/v1/auth/ide/enrollments/current/wait?after_revision=1",
                    headers=bearer,
                )
                assert status.status_code == 200, status.text
                assert status.json()["state"] == "rejected"
                activation = client.post("/v1/auth/ide/activate", headers=bearer)
                assert activation.status_code == 403
                assert activation.json()["detail"]["code"] == "ide_enrollment_rejected"

                next_issue = _enroll(client, "c", "Expiring VS Code").json()
                with app.state.runtime.session_factory() as db, db.begin():
                    sidecar = db.scalar(select(IdeEnrollment).where(
                        IdeEnrollment.request_id == next_issue["request_id"]
                    ))
                    assert sidecar is not None
                    expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                    requested_at = expired_at - timedelta(seconds=600)
                    sidecar.requested_at = requested_at
                    sidecar.activation_expires_at = expired_at
                    slot = db.get(RuntimeConfig, f"auth.ide_slot.{next_issue['client_slot']}")
                    assert slot is not None
                    record = json.loads(slot.value)
                    record["pending"]["issued_at"] = requested_at.isoformat()
                    record["pending"]["activation_expires_at"] = expired_at.isoformat()
                    slot.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
                expired_bearer = {"Authorization": f"Bearer {next_issue['capability']}"}
                expired = client.get(
                    "/v1/auth/ide/enrollments/current/wait?after_revision=0",
                    headers=expired_bearer,
                )
                assert expired.status_code == 200, expired.text
                assert expired.json()["state"] == "expired"
                expired_activation = client.post("/v1/auth/ide/activate", headers=expired_bearer)
                assert expired_activation.status_code == 410
                assert expired_activation.json()["detail"]["code"] == "ide_enrollment_expired"
                cancelled = client.delete("/v1/auth/ide/pending", headers=expired_bearer)
                assert cancelled.status_code == 200, cancelled.text
                with app.state.runtime.session_factory() as db:
                    expired_sidecar = db.get(IdeEnrollment, next_issue["request_id"])
                    expired_slot = db.get(
                        RuntimeConfig,
                        f"auth.ide_slot.{next_issue['client_slot']}",
                    )
                    assert expired_sidecar is not None
                    assert expired_sidecar.state == "awaiting_approval"
                    assert expired_sidecar.decision_at is None
                    assert expired_slot is not None
                    assert json.loads(expired_slot.value)["pending"] is None
    finally:
        engine.dispose()
