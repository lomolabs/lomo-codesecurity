from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from kodesec_api.auth import (
    AuthContext,
    BOOTSTRAP_MARKER,
    BROWSER_SESSION_PREFIX,
    CAPABILITY_PREFIX,
    CapabilityRevocationRequest,
    DYNAMIC_BROWSER_PAIRING_KEY,
    IDE_CAPABILITY_SCOPES,
    IdeEnrollmentDecisionRequest,
    IdeEnrollmentRequest,
    InvalidCapabilityRecoveryRequest,
    PendingCancellationRequest,
    BootstrapRequest,
    _commit_one_time_transaction,
    _stage_one_time_token,
    activate_ide_capability,
    bootstrap,
    create_ide_enrollment,
    decide_ide_enrollment,
    enforce_installation_secret_binding,
    issue_dynamic_browser_pairing_token,
    list_ide_capabilities,
    recover_invalid_ide_capability,
    revoke_ide_capability,
    validate_ide_capability,
    validate_pending_ide_capability,
)
from kodesec_api.db import initialize_database
from kodesec_api.models import IdeEnrollment, RuntimeConfig
from kodesec_api.settings import Settings


CLIENT_SLOT = "ks1_" + "a" * 43


def _settings(*, bootstrap_token: str = "bootstrap-token-" * 4) -> Settings:
    return Settings(
        _env_file=None,
        KODESEC_INSTALLATION_SECRET="installation-" * 4,
        KODESEC_BOOTSTRAP_TOKEN=bootstrap_token,
        KODESEC_CONTROL_ORIGINS="http://127.0.0.1:8080",
        KODESEC_ALLOWED_ROOTS="/workspace/source",
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )


def _consume_bootstrap_once(factory, settings: Settings) -> int:
    with factory() as db:
        try:
            _stage_one_time_token(
                db,
                BOOTSTRAP_MARKER,
                settings.bootstrap_token,
                settings.bootstrap_token,
                settings,
            )
            _commit_one_time_transaction(db)
            return 200
        except HTTPException as exc:
            db.rollback()
            return exc.status_code


def _pair_browser_once(factory, settings: Settings, pairing_token: str) -> tuple[int, str | None]:
    with factory() as db:
        try:
            bootstrap(
                BootstrapRequest(bootstrap_token=pairing_token),
                request=Request({
                    "type": "http", "method": "POST", "path": "/v1/auth/bootstrap",
                    "headers": [],
                    "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
                }),
                response=Response(),
                db=db,
                settings=settings,
            )
            return 200, None
        except HTTPException as exc:
            db.rollback()
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            code = detail.get("code")
            return exc.status_code, str(code) if isinstance(code, str) else None


def _enroll_once(
    factory,
    settings: Settings,
    *,
    expected_active_generation: int = 0,
) -> tuple[int, str | None, str | None]:
    with factory() as db:
        try:
            result = create_ide_enrollment(
                IdeEnrollmentRequest(
                    client_name="concurrent VS Code",
                    client_slot=CLIENT_SLOT,
                    expected_active_generation=expected_active_generation,
                ),
                Response(),
                db,
                settings,
            )
            return 201, result.request_id, result.capability
        except HTTPException as exc:
            db.rollback()
            return exc.status_code, None, None


def _approve_once(factory, request_id: str, generation: int) -> int:
    with factory() as db:
        request = Request({
            "type": "http",
            "method": "POST",
            "path": f"/v1/auth/ide/enrollments/{request_id}/decision",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
        })
        browser = AuthContext(
            kind="browser",
            subject="local-browser",
            scopes=frozenset({"api:read", "api:write"}),
            session_nonce="browser-session",
        )
        try:
            decide_ide_enrollment(
                request_id,
                IdeEnrollmentDecisionRequest(
                    decision="approved",
                    expected_revision=1,
                    expected_generation=generation,
                ),
                request,
                browser,
                db,
            )
            return 200
        except HTTPException as exc:
            db.rollback()
            return exc.status_code


def _revoke_once(factory) -> int:
    with factory() as db:
        request = Request({
            "type": "http",
            "method": "DELETE",
            "path": f"/v1/auth/ide/capabilities/{CLIENT_SLOT}",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
        })
        browser = AuthContext(
            kind="browser",
            subject="local-browser",
            scopes=frozenset({"api:read", "api:write"}),
            session_nonce="browser-session",
        )
        try:
            revoke_ide_capability(
                CLIENT_SLOT,
                CapabilityRevocationRequest(
                    expected_latest_generation=2,
                    expected_active_generation=1,
                    expected_pending_generation=2,
                ),
                request,
                browser,
                db,
            )
            return 200
        except HTTPException as exc:
            db.rollback()
            return exc.status_code


def _activate_once(factory, settings: Settings, capability: str) -> int:
    with factory() as db:
        context = validate_pending_ide_capability(
            capability,
            db,
            settings,
            allow_active=True,
        )
        if context is None:
            return 401
        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/v1/auth/ide/activate",
            "headers": [(b"authorization", f"Bearer {capability}".encode("ascii"))],
            "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
        })
        try:
            return activate_ide_capability(
                request,
                Response(),
                context,
                db,
                settings,
            ).generation
        except HTTPException as exc:
            db.rollback()
            return exc.status_code


def test_enrollment_client_name_is_trimmed_and_rejects_unrecognizable_labels() -> None:
    request = IdeEnrollmentRequest(
        client_name="  Ubuntu QA · vulnerable-demo  ",
        client_slot=CLIENT_SLOT,
        expected_active_generation=0,
    )
    assert request.client_name == "Ubuntu QA · vulnerable-demo"

    for client_name in ("   ", "trusted\u0000client", "trusted\u202eclient"):
        with pytest.raises(ValidationError):
            IdeEnrollmentRequest(
                client_name=client_name,
                client_slot=CLIENT_SLOT,
                expected_active_generation=0,
            )

    for invalid in (
        {"client_name": "VS Code", "client_slot": "not-a-slot", "expected_active_generation": 0},
        {"client_name": "VS Code", "client_slot": CLIENT_SLOT, "expected_active_generation": True},
        {"client_name": "VS Code", "client_slot": CLIENT_SLOT},
        {"client_name": "VS Code", "client_slot": CLIENT_SLOT, "expected_active_generation": 0, "unexpected": "forbidden"},
    ):
        with pytest.raises(ValidationError):
            IdeEnrollmentRequest.model_validate(invalid)

    assert PendingCancellationRequest(expected_pending_generation=1).expected_pending_generation == 1
    for invalid in (
        {},
        {"expected_pending_generation": True},
        {"expected_pending_generation": 0},
        {"expected_pending_generation": 1, "unexpected": "forbidden"},
    ):
        with pytest.raises(ValidationError):
            PendingCancellationRequest.model_validate(invalid)

    revocation = CapabilityRevocationRequest(
        expected_latest_generation=3,
        expected_active_generation=2,
        expected_pending_generation=3,
    )
    assert revocation.expected_latest_generation == 3
    for invalid in (
        {},
        {
            "expected_latest_generation": True,
            "expected_active_generation": None,
            "expected_pending_generation": None,
        },
        {
            "expected_latest_generation": 1,
            "expected_active_generation": 0,
            "expected_pending_generation": None,
        },
        {
            "expected_latest_generation": 1,
            "expected_active_generation": None,
            "expected_pending_generation": None,
            "unexpected": "forbidden",
        },
    ):
        with pytest.raises(ValidationError):
            CapabilityRevocationRequest.model_validate(invalid)

    recovery_token = "kir1_" + "a" * 64
    assert InvalidCapabilityRecoveryRequest(
        recovery_token=recovery_token
    ).recovery_token == recovery_token
    for invalid in (
        {},
        {"recovery_token": "kc1.not-a-recovery-token"},
        {"recovery_token": recovery_token, "unexpected": "forbidden"},
    ):
        with pytest.raises(ValidationError):
            InvalidCapabilityRecoveryRequest.model_validate(invalid)


def test_enrollment_and_approved_activation_are_concurrent_single_authority_cas(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, future=True)
    settings = _settings()
    with factory() as db:
        enforce_installation_secret_binding(db, settings)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: _enroll_once(factory, settings), range(2)))
    assert sorted(status for status, _, _ in results) == [201, 409]
    _, request_id, capability = next(result for result in results if result[0] == 201)
    assert request_id is not None
    assert capability is not None

    with factory() as db:
        assert db.scalar(select(func.count()).select_from(IdeEnrollment)) == 1
        slot = json.loads(db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{CLIENT_SLOT}").value)
        assert slot["active"] is None
        assert slot["pending"]["generation"] == 1
        assert slot["pending"]["scopes"] == list(IDE_CAPABILITY_SCOPES)
        assert capability not in json.dumps(slot)
        assert validate_ide_capability(capability, db, settings) is None

        request = Request({
            "type": "http",
            "method": "POST",
            "path": f"/v1/auth/ide/enrollments/{request_id}/decision",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
        })
        browser = AuthContext(
            kind="browser",
            subject="local-browser",
            scopes=frozenset({"api:read", "api:write"}),
            session_nonce="browser-session",
        )
        approved = decide_ide_enrollment(
            request_id,
            IdeEnrollmentDecisionRequest(
                decision="approved",
                expected_revision=1,
                expected_generation=1,
            ),
            request,
            browser,
            db,
        )
        assert approved.state == "approved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        generations = list(executor.map(
            lambda _: _activate_once(factory, settings, capability),
            range(2),
        ))
    assert generations == [1, 1]
    with factory() as db:
        assert validate_ide_capability(capability, db, settings) is not None


def test_same_slot_enrollment_and_revoke_share_one_postgres_lock_order(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, future=True)
    settings = _settings()
    with factory() as db:
        enforce_installation_secret_binding(db, settings)

    first_status, first_request_id, first_capability = _enroll_once(factory, settings)
    assert first_status == 201
    assert first_request_id is not None
    assert first_capability is not None
    assert _approve_once(factory, first_request_id, 1) == 200
    assert _activate_once(factory, settings, first_capability) == 1
    successor_status, _, _ = _enroll_once(
        factory,
        settings,
        expected_active_generation=1,
    )
    assert successor_status == 201

    with ThreadPoolExecutor(max_workers=2) as executor:
        create_future = executor.submit(
            _enroll_once,
            factory,
            settings,
            expected_active_generation=1,
        )
        revoke_future = executor.submit(_revoke_once, factory)
        create_status, _, _ = create_future.result(timeout=30)
        revoke_status = revoke_future.result(timeout=30)
    assert create_status in {201, 409}
    assert revoke_status == 200

    with factory() as db:
        live_unactivated = db.scalar(
            select(func.count())
            .select_from(IdeEnrollment)
            .where(
                IdeEnrollment.state.in_(("awaiting_approval", "approved")),
                IdeEnrollment.activated_at.is_(None),
            )
        )
        assert live_unactivated in {0, 1}


def test_dynamic_browser_pairing_issues_exactly_one_session_concurrently(postgres_engine) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, future=True)
    settings = _settings(bootstrap_token="kb1." + "z" * 43)
    assert _pair_browser_once(factory, settings, settings.bootstrap_token) == (200, None)

    with factory() as db:
        expired_token, issued_at, _ = issue_dynamic_browser_pairing_token(db, settings)
        row = db.get(RuntimeConfig, DYNAMIC_BROWSER_PAIRING_KEY)
        record = json.loads(row.value)
        record["issued_at"] = (issued_at - timedelta(seconds=601)).isoformat()
        record["expires_at"] = (issued_at - timedelta(seconds=1)).isoformat()
        row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
        db.commit()
    assert _pair_browser_once(factory, settings, expired_token) == (
        410,
        "browser_pairing_token_expired",
    )

    with factory() as db:
        dynamic_token, _, _ = issue_dynamic_browser_pairing_token(db, settings)
        db.commit()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(
            lambda _: _pair_browser_once(factory, settings, dynamic_token),
            range(2),
        ))
    assert sorted(status for status, _ in results) == [200, 409]
    assert [code for status, code in results if status == 409] == ["browser_pairing_token_consumed"]

    with factory() as db:
        sessions = db.scalar(
            select(func.count(RuntimeConfig.key)).where(
                RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%")
            )
        )
        record = json.loads(db.get(RuntimeConfig, DYNAMIC_BROWSER_PAIRING_KEY).value)
    assert sessions == 2
    assert record["used_at"] is not None
    assert dynamic_token not in json.dumps(record)


def test_rotated_bootstrap_token_is_consumed_exactly_once_concurrently(postgres_engine) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, future=True)
    original = _settings(bootstrap_token="original-bootstrap-token-" * 3)
    assert _consume_bootstrap_once(factory, original) == 200

    rotated = _settings(bootstrap_token="rotated-bootstrap-token-" * 3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = sorted(executor.map(lambda _: _consume_bootstrap_once(factory, rotated), range(2)))
    assert statuses == [200, 409]


def test_invalid_slot_is_redacted_and_exact_recovery_is_state_fenced(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    factory = sessionmaker(bind=postgres_engine, future=True)
    settings = _settings()
    slot_key = f"{CAPABILITY_PREFIX}{CLIENT_SLOT}"
    first_raw_state = json.dumps(
        {
            "unexpected": "plain-capability-must-not-be-listed",
            "digest": "f" * 64,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    second_raw_state = json.dumps(
        {"unexpected": "concurrently-changed-invalid-state"},
        separators=(",", ":"),
        sort_keys=True,
    )
    request = Request(
        {
            "type": "http",
            "method": "DELETE",
            "path": f"/v1/auth/ide/capabilities/{CLIENT_SLOT}/invalid",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(event_wake_broker=None)),
        }
    )
    browser = AuthContext(
        kind="browser",
        subject="local-browser",
        scopes=frozenset({"api:read", "api:write"}),
        session_nonce="browser-session",
    )

    with factory() as db:
        db.add(RuntimeConfig(key=slot_key, value=first_raw_state))
        db.commit()

    with factory() as db:
        [first_listing] = list_ide_capabilities(request, browser, db, settings)
        [repeated_listing] = list_ide_capabilities(request, browser, db, settings)
    assert first_listing.state == "invalid"
    assert first_listing.id == CLIENT_SLOT
    assert first_listing.active is False
    assert first_listing.source_open_available is False
    assert first_listing.invalid_recovery_token == repeated_listing.invalid_recovery_token
    redacted = first_listing.model_dump_json()
    assert "plain-capability-must-not-be-listed" not in redacted
    assert "f" * 64 not in redacted
    assert "digest" not in redacted

    with factory() as db:
        row = db.get(RuntimeConfig, slot_key)
        row.value = second_raw_state
        db.commit()

    with factory() as db, pytest.raises(HTTPException) as stale:
        recover_invalid_ide_capability(
            CLIENT_SLOT,
            InvalidCapabilityRecoveryRequest(
                recovery_token=first_listing.invalid_recovery_token,
            ),
            request,
            browser,
            db,
            settings,
        )
    assert stale.value.status_code == 409
    assert stale.value.detail["code"] == "ide_pairing_invalid_recovery_conflict"

    with factory() as db:
        assert db.get(RuntimeConfig, slot_key).value == second_raw_state
        [current_listing] = list_ide_capabilities(request, browser, db, settings)
    assert current_listing.invalid_recovery_token != first_listing.invalid_recovery_token

    with factory() as db:
        recovered = recover_invalid_ide_capability(
            CLIENT_SLOT,
            InvalidCapabilityRecoveryRequest(
                recovery_token=current_listing.invalid_recovery_token,
            ),
            request,
            browser,
            db,
            settings,
        )
        assert recovered.recovered is True
    with factory() as db:
        assert db.get(RuntimeConfig, slot_key) is None
