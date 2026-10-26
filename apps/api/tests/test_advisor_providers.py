from __future__ import annotations

from copy import deepcopy
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import importlib.util
import re
import stat
import subprocess
import sys
from threading import Event, current_thread
from unittest.mock import patch
from types import SimpleNamespace

import pytest
import httpx
from fastapi.testclient import TestClient
from fastapi import HTTPException, Response
from starlette.requests import Request
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from kodesec_api.advisor import disclosure, grants, providers
from kodesec_api.auth import AuthContext
from kodesec_api.db import Base, Runtime
from kodesec_api.jobs.execution import (
    CancellationRequested,
    ClaimedJob,
    JobExecutionError,
    LeaseMonitor,
    WorkerExecutor,
)
from kodesec_api.jobs.commands import (
    AdvisorSelectionError,
    advisor_selection_snapshot,
    InvalidScanCommandSnapshot,
    ScanCommandKindMismatch,
    UnsupportedScanCommandVersion,
)
from kodesec_api.jobs import advisor as advisor_jobs
from kodesec_api.jobs.advisor import resolve_provider_sync, worker_ollama_available_sync
from kodesec_api.jobs.repository import (
    InvalidJobTransition,
    _redact_job_document,
    durable_idempotency_key,
    enqueue_job,
    lock_advisor_admission,
    retry_failed_job,
)
from kodesec_api.main import (
    _finding_packet,
    healthz,
    _job_retry_requires_advisor_ai_admission,
    _job_to_out,
    _problem_detail,
    bulk_findings,
    create_scan,
    list_local_advisor_models,
    preview_finding_advisor_disclosure,
    retry_job,
    triage_scan,
    triage_finding,
)
from kodesec_api.models import Finding, Job, Project, RuntimeConfig, Scan
from kodesec_api.schemas import (
    AdvisorDisclosurePreviewOut,
    AdvisorDisclosurePreviewRequest,
    AdvisorTriageProviderPin,
    FindingBulkAction,
    JobRetryRequest,
    ProblemDetail,
    ScanCreate,
    ScanTriageRequest,
    TriageRequest,
)
from kodesec_api.settings import Settings


DIGEST = "a" * 64
FIXTURE_HOST = "10.23.45.67"
FIXTURE_MODEL = "fixture-advisor:latest"
GRANT_SECRET = "advisor-grant-fixture-" * 3
INSTALLATION_SECRET = "installation-secret-fixture-" * 3
ADVISOR_DISABLED_DETAIL = {
    "code": "advisor_disabled",
    "message": "Advisor is disabled because AI mode is off; no Advisor job was queued.",
    "action": "enable_advisor",
    "context": {},
    "safe_details": {"reason_code": "ai_mode_off"},
}


def _scan_snapshot_problem(error_type: type[InvalidScanCommandSnapshot]) -> dict:
    return {
        "code": error_type.code,
        "message": error_type.detail,
        "action": "start_new_scan",
        "context": {},
        "safe_details": {"reason_code": error_type.reason_code},
    }


def test_scan_retry_ai_admission_requires_typed_true() -> None:
    with pytest.raises(InvalidScanCommandSnapshot):
        _job_retry_requires_advisor_ai_admission(
            "scan", {"v": 1, "operation": "scan"}
        )
    assert not _job_retry_requires_advisor_ai_admission(
        "scan", {"v": 1, "operation": "scan", "use_ai": False}
    )
    assert _job_retry_requires_advisor_ai_admission(
        "scan", {"v": 1, "operation": "scan", "use_ai": True}
    )
    assert _job_retry_requires_advisor_ai_admission("advisor", {"v": 1})
    for value in (1, "true", None, [], {}):
        with pytest.raises(InvalidScanCommandSnapshot):
            _job_retry_requires_advisor_ai_admission(
                "scan", {"v": 1, "operation": "scan", "use_ai": value}
            )


def _profile(
    provider_id: str = "direct-lab", *, transport: str = "direct", priority: int = 0
) -> dict[str, object]:
    value: dict[str, object] = {
        "id": provider_id,
        "name": "Lab Advisor",
        "transport": transport,
        "priority": priority,
        "enabled": True,
        "base_url": f"http://{FIXTURE_HOST}:11434" if transport == "direct" else None,
        "model": FIXTURE_MODEL,
        "model_digest": DIGEST,
        "ssh_host": FIXTURE_HOST if transport == "ssh" else None,
        "ssh_port": 22 if transport == "ssh" else None,
        "ssh_user": "ollama-forward" if transport == "ssh" else None,
    }
    return value


def _receipt(profile: dict[str, object]) -> dict[str, object]:
    return providers.normalize_receipt(
        {
            "schema": "lomo-advisor-provider-receipt/v1",
            "provider_id": profile["id"],
            "kind": profile["transport"],
            "route": profile["transport"],
            "model": profile["model"],
            "model_digest": profile["model_digest"],
            "status": "ready",
            "tested_at": "2026-08-25T12:00:00Z",
            "revision": profile["config_revision"],
        }
    )


def _triage_pin(
    collection: dict[str, object], profile: dict[str, object]
) -> AdvisorTriageProviderPin:
    return AdvisorTriageProviderPin(
        provider_collection_revision=int(collection["revision"]),
        provider_id=str(profile["id"]),
        transport=str(profile["transport"]),
        provider_config_revision=int(profile["config_revision"]),
        provider_config_digest=str(profile["config_digest"]),
        model=str(profile["model"]),
        model_digest=str(profile["model_digest"]),
    )


def _command_request(path: str, key: str) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"idempotency-key", key.encode("ascii"))],
            "query_string": b"",
        }
    )
    request.state.auth = AuthContext(
        kind="browser", subject="fixture", scopes=frozenset()
    )
    return request


def _triage_runtime(
    collection: dict[str, object],
    *,
    persist_receipt: bool,
    installation_secret: str = "",
) -> tuple[Runtime, int, int]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+pysqlite://",
            KODESEC_ALLOWED_ROOTS="/workspace",
            KODESEC_ADVISOR_DIRECT_HOSTS=FIXTURE_HOST,
            KODESEC_INSTALLATION_SECRET=installation_secret,
        ),
        engine=engine,
    )
    profile = collection["providers"][0]
    assert isinstance(profile, dict)
    with runtime.session_factory() as db, db.begin():
        providers.save_collection(db, collection)
        if persist_receipt:
            providers.save_receipt(db, _receipt(profile))
        project = Project(
            name="advisor-admission",
            repo_path="/workspace/advisor-admission",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, status="completed", revision=1)
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="FIXTURE-ADMISSION",
            severity="high",
            file_path="src/admission.py",
            start_line=1,
            end_line=1,
            message="Synthetic admission finding.",
            code_snippet="eval(user_input)\n",
            fingerprint="fixture-advisor-admission",
            metadata_json={},
            revision=1,
        )
        db.add(finding)
        db.flush()
        return runtime, scan.id, finding.id


def test_provider_collection_is_revision_fenced_bounded_and_ordered() -> None:
    current = {"revision": 1, "active_provider_id": None, "providers": []}
    first = providers.replace_profile(
        current, _profile(priority=1), expected_revision=1, create=True
    )
    second = providers.replace_profile(
        first,
        _profile("local-lab", transport="local", priority=0),
        expected_revision=2,
        create=True,
    )
    assert second["revision"] == 3
    assert [item["id"] for item in second["providers"]] == [
        "local-lab",
        "direct-lab",
    ]
    with pytest.raises(providers.ProviderConflictError) as conflict:
        providers.replace_profile(
            second, _profile("stale", priority=2), expected_revision=2, create=True
        )
    assert conflict.value.current_revision == 3

    full = deepcopy(second)
    for index in range(2, 8):
        full = providers.replace_profile(
            full,
            _profile(f"provider-{index}", priority=index),
            expected_revision=full["revision"],
            create=True,
        )
    with pytest.raises(ValueError, match="at most 8"):
        providers.replace_profile(
            full,
            _profile("provider-eight", priority=7),
            expected_revision=full["revision"],
            create=True,
        )


def test_existing_provider_priority_change_swaps_atomically() -> None:
    first = providers.replace_profile(
        {"revision": 1, "active_provider_id": None, "providers": []},
        _profile("local-lab", transport="local", priority=0),
        expected_revision=1,
        create=True,
    )
    current = providers.replace_profile(
        first, _profile(priority=1), expected_revision=2, create=True
    )
    reordered = providers.replace_profile(
        current,
        _profile(priority=0),
        expected_revision=3,
        create=False,
    )
    assert reordered["revision"] == 4
    assert [(item["id"], item["priority"]) for item in reordered["providers"]] == [
        ("direct-lab", 0),
        ("local-lab", 1),
    ]
    assert {item["id"]: item["config_revision"] for item in reordered["providers"]} == {
        "direct-lab": 2,
        "local-lab": 2,
    }
    with pytest.raises(providers.ProviderConflictError):
        providers.replace_profile(
            reordered,
            _profile(priority=1),
            expected_revision=3,
            create=False,
        )


@pytest.mark.parametrize(
    "profile",
    [
        _profile() | {"base_url": "http://127.0.0.1:11434"},
        _profile() | {"base_url": "http://169.254.169.254:11434"},
        _profile() | {"base_url": f"http://{FIXTURE_HOST}:11435"},
        _profile("ssh-lab", transport="ssh") | {"ssh_port": 2222},
        _profile("ssh-lab", transport="ssh") | {"ssh_host": "127.0.0.1"},
    ],
)
def test_remote_provider_rejects_unsafe_or_nonstandard_routes(
    profile: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        providers.normalize_profile(profile)


def test_authorization_and_disclosure_are_separate_fail_closed_gates() -> None:
    profile = providers.normalize_profile(_profile())
    collection = {"revision": 1, "active_provider_id": None, "providers": [profile]}
    denied = SimpleNamespace(
        advisor_direct_host_list=frozenset(), advisor_ssh_provider_id_list=frozenset()
    )
    allowed = SimpleNamespace(
        advisor_direct_host_list=frozenset({FIXTURE_HOST}),
        advisor_ssh_provider_id_list=frozenset(),
    )
    assert providers.resolve_candidates(collection, denied) == []
    assert providers.resolve_candidates(collection, allowed)[0][
        "content_disclosure_approved"
    ] is False
    active = providers.update_provider_status(
        collection,
        "direct-lab",
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    assert active["active_provider_id"] == "direct-lab"
    assert active["providers"][0]["content_disclosure_approved"] is True


def test_remote_disclosure_consent_is_exact_revision_and_profile_bound() -> None:
    profile = providers.normalize_profile(_profile())
    collection = {"revision": 7, "active_provider_id": None, "providers": [profile]}
    active = providers.update_provider_status(
        collection,
        "direct-lab",
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    consent = providers.build_consent(active, "direct-lab")
    assert consent == {
        "schema": "lomo-advisor-source-consent/v1",
        "provider_id": "direct-lab",
        "provider_config_revision": 1,
        "provider_config_digest": active["providers"][0]["config_digest"],
        "transport": "direct",
        "destination": f"http://{FIXTURE_HOST}:11434",
        "disclosure_mode": "finding_evidence",
        "payload_categories": [
            "finding_identity",
            "source_location",
            "repository_context",
            "bounded_code_snippet",
            "bounded_scanner_metadata",
        ],
        "model": FIXTURE_MODEL,
        "model_digest": DIGEST,
        "approved_at": consent["approved_at"],
    }
    assert providers.consent_matches(active, active["providers"][0], consent)
    assert not providers.consent_matches(
        active,
        active["providers"][0],
        consent | {"provider_config_revision": 7},
    )

    edited = providers.replace_profile(
        active,
        _profile() | {"model_digest": "b" * 64},
        expected_revision=7,
        create=False,
    )
    assert edited["active_provider_id"] is None
    assert edited["providers"][0]["content_disclosure_approved"] is False
    assert not providers.consent_matches(edited, edited["providers"][0], consent)


def test_remote_activation_approval_is_exact_configuration_bound() -> None:
    profile = providers.normalize_profile(_profile())
    approval = providers.build_activation_approval(profile)
    assert approval == {
        "schema": "lomo-advisor-activation-approval/v1",
        "provider_id": profile["id"],
        "provider_config_revision": profile["config_revision"],
        "provider_config_digest": profile["config_digest"],
        "transport": "direct",
        "destination": f"http://{FIXTURE_HOST}:11434",
        "disclosure_mode": "finding_evidence",
        "payload_categories": list(providers.DISCLOSURE_CATEGORIES),
        "model": FIXTURE_MODEL,
        "model_digest": DIGEST,
    }
    edited = providers.normalize_profile(
        profile | {"name": "Changed", "config_revision": 2}
    )
    assert providers.build_activation_approval(edited) != approval


def test_source_free_test_preserves_active_exact_consent() -> None:
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 4, "active_provider_id": None, "providers": [profile]},
        "direct-lab",
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
        activate=True,
        approve_content_disclosure=True,
    )
    consent = providers.build_consent(active, "direct-lab")
    tested = providers.update_provider_status(
        active,
        "direct-lab",
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    assert tested["revision"] == 4
    assert tested["active_provider_id"] == "direct-lab"
    assert tested["providers"][0]["content_disclosure_approved"] is True
    assert providers.consent_matches(tested, tested["providers"][0], consent)


def test_activation_demotes_prior_status_without_bumping_crud_revision() -> None:
    first = providers.normalize_profile(_profile("direct-first", priority=0))
    second = providers.normalize_profile(_profile("direct-second", priority=1))
    collection = {
        "revision": 9,
        "active_provider_id": None,
        "providers": [first, second],
    }
    first_active = providers.update_provider_status(
        collection,
        first["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    second_active = providers.update_provider_status(
        first_active,
        second["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    states = {item["id"]: item["status"] for item in second_active["providers"]}
    disclosure = {
        item["id"]: item["content_disclosure_approved"]
        for item in second_active["providers"]
    }
    assert second_active["revision"] == 9
    assert second_active["active_provider_id"] == second["id"]
    assert states == {first["id"]: "available", second["id"]: "active"}
    assert disclosure == {first["id"]: False, second["id"]: True}


def test_typed_unavailable_state_is_consistent_and_remediable() -> None:
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [profile]},
        "direct-lab",
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    unavailable = providers.update_provider_status(
        active,
        "direct-lab",
        status="unavailable",
        reason="Exact provider verification failed.",
        reason_code="advisor_provider_unavailable",
        remediation="retry",
        deactivate=True,
    )
    result = unavailable["providers"][0]
    assert unavailable["revision"] == 2
    assert unavailable["active_provider_id"] is None
    assert result["content_disclosure_approved"] is False
    assert result["reason_code"] == "advisor_provider_unavailable"
    assert result["remediation"] == "retry"


def test_failed_provider_test_persists_typed_unavailable_state() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+pysqlite://",
            KODESEC_ALLOWED_ROOTS="/workspace",
            KODESEC_ADVISOR_DIRECT_HOSTS=FIXTURE_HOST,
        ),
        engine=engine,
    )
    profile = providers.normalize_profile(
        _profile("provider-f0fdaf907b0f45e39745a026")
    )
    for field in ("name", "model"):
        with pytest.raises(ValueError, match="credential-free identifier"):
            providers.job_profile_snapshot(
                _profile() | {field: f"sk-{'x' * 40}"}
            )
    reason_snapshot = providers.job_profile_snapshot(
        profile | {"reason": "bounded finding text must not enter the durable command"}
    )
    assert reason_snapshot["reason"] is None
    collection = {"revision": 1, "active_provider_id": None, "providers": [profile]}
    pin = providers.job_pin_snapshot(
        {
            "provider_id": profile["id"],
            "transport": profile["transport"],
            "provider_config_revision": profile["config_revision"],
            "provider_config_digest": profile["config_digest"],
            "model": profile["model"],
            "model_digest": profile["model_digest"],
        }
    )
    activation_approval = providers.build_activation_approval(profile)
    with runtime.session_factory() as db, db.begin():
        providers.save_collection(db, collection)
        queued = enqueue_job(
            db,
            kind="advisor_provider",
            title="Test fixture provider",
            client_id="browser:fixture",
            idempotency_key="provider-failure-fixture",
            payload={
                "v": 1,
                "operation": "advisor_provider_command",
                "request_digest": "c" * 64,
                "action": "test",
                "provider": providers.job_profile_snapshot(profile),
                "advisor_provider_pin": pin,
                "advisor": {
                    "advisor_providers": providers.job_collection_snapshot(collection)
                },
                "activation_approval_fixture": activation_approval,
                "provider_revision": 1,
                "provider_config_revision": profile["config_revision"],
                "provider_config_digest": profile["config_digest"],
                "acknowledge_source_disclosure": False,
            },
            max_attempts=1,
        ).job
        job_id = queued.id
    with runtime.session_factory() as db, db.begin():
        claimed_model = db.get(Job, job_id)
        assert claimed_model is not None
        assert claimed_model.payload["provider"]["id"] == profile["id"]
        assert claimed_model.payload["advisor_provider_pin"]["provider_id"] == profile["id"]
        assert claimed_model.payload["activation_approval_fixture"] == activation_approval
        assert (
            claimed_model.payload["advisor"]["advisor_providers"]["providers"][0]["id"]
            == profile["id"]
        )
        now = datetime.now(timezone.utc)
        claimed_model.status = "leased"
        claimed_model.stage = "leased"
        claimed_model.attempt = 1
        claimed_model.lease_owner = "provider-worker"
        claimed_model.lease_expires_at = now + timedelta(seconds=30)
        claimed_model.heartbeat_at = now
        db.add(claimed_model)
        db.flush()
        claimed = ClaimedJob.from_model(claimed_model)

        providers.normalize_profile(claimed.payload["provider"])

    with patch(
        "kodesec_api.jobs.advisor.test_provider_sync",
        side_effect=advisor_jobs.ProviderTestFailure(
            409, "advisor_provider_model_missing"
        ),
    ), patch(
        "kodesec_api.jobs.repository._time",
        return_value=datetime.now(timezone.utc),
    ), patch(
        "kodesec_api.jobs.execution.lock_advisor_admission"
    ) as admission_lock:
        WorkerExecutor(runtime, "provider-worker").execute(claimed)
    admission_lock.assert_called_once()

    with runtime.session_factory() as db:
        failed = db.get(Job, job_id)
        state = providers.load_collection(db, runtime.settings)
        assert failed is not None
        assert failed.status == "failed"
        assert failed.stage == "failed"
        assert failed.progress == 20
        assert failed.detail == (
            "Checking direct provider reachability and the exact model digest; "
            "no source or finding content is sent."
        )
        assert failed.error_code == "advisor_provider_model_missing"
        assert failed.error_detail == (
            "The exact configured Advisor model is not installed on this provider."
        )
        public = state["providers"][0]
        assert public["status"] == "unavailable"
        assert public["reason_code"] == "advisor_provider_model_missing"
        assert public["reason"] == failed.error_detail
        assert public["remediation"] == "test"
        assert public["config_revision"] == 1
        assert public["config_digest"] == profile["config_digest"]


def test_remote_preview_hash_binds_exact_finding_and_provider_configuration() -> None:
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 3, "active_provider_id": None, "providers": [profile]},
        "direct-lab",
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    consent = providers.build_consent(active, "direct-lab")
    packet = {"finding": {"rule_id": "fixture"}, "scanner_evidence": {"code_snippet": "x"}}
    confirmation = disclosure.build_confirmation(
        active,
        active["providers"][0],
        consent,
        finding_id=41,
        finding_revision=6,
        packet=packet,
        signing_key=INSTALLATION_SECRET,
    )
    assert disclosure.normalize_confirmation(confirmation) == confirmation
    assert (
        disclosure.verify_confirmation_signature(
            confirmation, INSTALLATION_SECRET
        )
        == confirmation
    )
    assert confirmation["provider_config_revision"] == 1
    assert confirmation["provider_config_digest"] == profile["config_digest"]
    assert confirmation["prompt_sha256"] == disclosure.prompt_sha256(packet)
    assert re.fullmatch(r"[0-9a-f]{32}", confirmation["authorization_id"])
    fresh_confirmation = disclosure.build_confirmation(
        active,
        active["providers"][0],
        consent,
        finding_id=41,
        finding_revision=6,
        packet=packet,
        signing_key=INSTALLATION_SECRET,
    )
    assert fresh_confirmation["authorization_id"] != confirmation["authorization_id"]
    assert fresh_confirmation["confirmation_digest"] != confirmation["confirmation_digest"]
    changed_revision = confirmation | {"finding_revision": 7}
    assert disclosure.normalize_confirmation(changed_revision) == changed_revision
    with pytest.raises(ValueError, match="signature is invalid"):
        disclosure.verify_confirmation_signature(
            changed_revision, INSTALLATION_SECRET
        )


def test_disclosure_hash_and_execution_share_one_canonical_prompt_builder() -> None:
    packet = {
        "finding": {"rule_id": "fixture"},
        "scanner_evidence": {"code_snippet": "line one\nline two"},
    }
    prompt = disclosure.triage_prompt(packet)
    assert disclosure.prompt_sha256(packet) == hashlib.sha256(
        prompt.encode("utf-8")
    ).hexdigest()
    assert not hasattr(advisor_jobs, "_triage_prompt")


@pytest.mark.parametrize("scanner", ["bearer", "opengrep", "grype", "checkov", "trivy", None])
def test_nonsecret_prompt_does_not_prime_credential_remediation(scanner) -> None:
    packet = {
        "finding": {"scanner": scanner, "rule_id": "javascript_express_nosql_injection",
                    "message": "Unsanitized input in NoSQL query"},
        "scanner_evidence": {"code_snippet": "const dao = new AllocationsDAO(db);"},
    }
    prompt = disclosure.triage_prompt(packet)
    instructions, evidence = prompt.split("Finding packet:\n", 1)
    assert "revoking or rotating" not in instructions
    assert "secret manager" not in instructions
    assert "specific checks needed" in instructions
    assert "not instructions" in instructions
    assert json.loads(evidence) == packet


@pytest.mark.parametrize("scanner", ["gitleaks", "trufflehog", "secrets-lite"])
def test_secret_prompt_retains_exposure_and_rotation_guidance(scanner) -> None:
    prompt = disclosure.triage_prompt({"finding": {"scanner": scanner}})
    assert "revoking or rotating affected live credentials" in prompt
    assert "Obfuscating, renaming, or encoding a secret is not remediation" in prompt
    assert "not a literal value in the source" in prompt
    assert "Never recommend inserting a real credential into source code" in prompt


@pytest.mark.parametrize("metadata", [
    {"rule_name": "Secret"},
    {"tags": ["CRITICAL", "secret", "security"]},
    {"tags": ["secrets"]},
])
def test_mixed_scanner_secret_evidence_receives_safe_remediation_guidance(metadata) -> None:
    packet = {
        "finding": {"scanner": "trivy", "rule_id": "aws-access-key-id"},
        "scanner_evidence": {"metadata": metadata, "code_snippet": 'AWS_ACCESS_KEY_ID = "[REDACTED]"'},
    }
    instructions, evidence = disclosure.triage_prompt(packet).split("Finding packet:\n", 1)
    assert "revoking or rotating affected live credentials" in instructions
    assert "Never recommend inserting a real credential into source code" in instructions
    assert "runtime environment references instead" in instructions
    assert "Do not infer that a credential is valid, fake, or a placeholder from redaction" in instructions
    assert "the hidden value cannot be assessed from the redacted evidence" in instructions
    assert "Assess the reported exposure pattern separately" in instructions
    assert json.loads(evidence) == packet


@pytest.mark.parametrize("metadata", [
    None, "secret", {}, {"tags": "secret"}, {"tags": [None, 1, "secret-management"]},
    {"rule_name": "CVE-2026-0000", "tags": ["dependency", "security"]},
])
def test_mixed_scanner_nonsecret_or_malformed_metadata_does_not_prime_secret_fix(metadata) -> None:
    packet = {
        "finding": {"scanner": "trivy", "rule_id": "fixture-dependency"},
        "scanner_evidence": {"metadata": metadata},
    }
    instructions = disclosure.triage_prompt(packet).split("Finding packet:\n", 1)[0]
    assert "secret manager" not in instructions
    assert "revoking or rotating" not in instructions


@pytest.mark.parametrize("tags", [["CWE-78", "security"], ["cwe-78"], [None, "CWE-78"]])
def test_command_injection_guidance_preserves_executable_trust_boundary(tags) -> None:
    packet = {
        "finding": {"scanner": "opengrep", "rule_id": "fixture-command"},
        "scanner_evidence": {"metadata": {"tags": tags}, "code_snippet":
                             'command = request.form["cmd"]\nsubprocess.check_output(command, shell=True)'},
    }
    instructions, evidence = disclosure.triage_prompt(packet).split("Finding packet:\n", 1)
    assert "fixed trusted executable or an explicit allowlist" in instructions
    assert "validates the untrusted arguments" in instructions
    assert "does not fix attacker-controlled executable selection" in instructions
    assert "rather than inventing an executable or a runnable patch" in instructions
    assert "secret manager" not in instructions
    assert json.loads(evidence) == packet


@pytest.mark.parametrize("tags", [None, "CWE-78", [78], ["CWE-79"], ["CWE-780"],
                                  ["not-CWE-78"], ["secret", "security"]])
def test_other_findings_do_not_receive_command_execution_remediation(tags) -> None:
    instructions = disclosure.triage_prompt({
        "finding": {"scanner": "opengrep", "rule_id": "CWE-78"},
        "scanner_evidence": {"metadata": {"tags": tags}},
    }).split("Finding packet:\n", 1)[0]
    assert "fixed trusted executable" not in instructions
    assert "request-provided command" not in instructions


def test_prompt_update_requires_a_new_remote_disclosure_confirmation() -> None:
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 3, "active_provider_id": None, "providers": [profile]},
        profile["id"], status="active", reason=None, activate=True,
        approve_content_disclosure=True,
    )
    profile = active["providers"][0]
    consent = providers.build_consent(active, profile["id"])
    packet = {"finding": {"rule_id": "fixture"},
              "scanner_evidence": {"code_snippet": "TOKEN = '[REDACTED]'"}}
    selection = {"finding_id": 41, "finding_revision": 6, "packet": packet}
    # A valid signature on an earlier prompt must not authorize new prompt bytes.
    with patch.object(disclosure, "triage_prompt", return_value="earlier reviewed prompt"):
        previous = disclosure.build_confirmation(
            active, profile, consent, **selection, signing_key=INSTALLATION_SECRET,
        )
    assert disclosure.verify_confirmation_signature(previous, INSTALLATION_SECRET) == previous
    assert not disclosure.confirmation_matches(active, profile, consent, previous, **selection)
    current = disclosure.build_confirmation(
        active, profile, consent, **selection, signing_key=INSTALLATION_SECRET,
    )
    assert disclosure.confirmation_matches(active, profile, consent, current, **selection)
    assert previous["prompt_sha256"] != current["prompt_sha256"]


def test_advisor_disclosure_packet_fails_closed_for_unmapped_or_unsafe_snippets() -> None:
    project = Project(name="fixture", repo_path="/private/fixture", remote_url=None)
    scan = Scan(id=1, project_id=1, status="completed", revision=1)
    finding = Finding(
        id=1,
        scan_id=1,
        scan_finding_number=1,
        scanner="fixture",
        rule_id="FIXTURE-1",
        severity="high",
        file_path="src/demo.py",
        start_line=12,
        end_line=12,
        message="Fixture finding",
        code_snippet="line 10\nline 11\nline 12\nline 13\nline 14",
        fingerprint="fixture-packet-fail-closed",
        metadata_json={"snippet_start_line": 10},
        revision=1,
    )

    finding.metadata_json = {}
    assert _finding_packet(finding, scan, project)["scanner_evidence"] == {
        "code_snippet": None,
        "metadata": {},
    }

    finding.metadata_json = {"snippet_start_line": 30}
    assert _finding_packet(finding, scan, project)["scanner_evidence"] == {
        "code_snippet": None,
        "metadata": {},
    }

    finding.metadata_json = {"snippet_start_line": 10}
    finding.code_snippet = "line 10\nline 11\nline\x00 12\nline 13\nline 14"
    assert _finding_packet(finding, scan, project)["scanner_evidence"] == {
        "code_snippet": None,
        "metadata": {},
    }

    finding.code_snippet = "line 10\nline 11\nline 12\nline 13\nline 14"
    for invalid_metadata in (
        {"snippet_start_line": 10, "snippet_line_truncated": True},
        {"snippet_start_line": 10, "snippet_line_truncated": 1},
        {"snippet_start_line": 10, "snippet_line_truncated": "false"},
        {"snippet_start_line": 10, "snippet_column_start": 2},
    ):
        finding.metadata_json = invalid_metadata
        assert _finding_packet(finding, scan, project)["scanner_evidence"] == {
            "code_snippet": None,
            "metadata": {},
        }

    finding.metadata_json = {"snippet_start_line": 12}
    finding.code_snippet = "é" * 5_000
    assert _finding_packet(finding, scan, project)["scanner_evidence"] == {
        "code_snippet": None,
        "metadata": {},
    }


@pytest.mark.parametrize("transport", ["direct", "ssh"])
def test_exact_remote_confirmation_enqueues_and_executes_one_durable_finding_job(
    transport: str,
) -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+pysqlite://",
            KODESEC_ALLOWED_ROOTS="/workspace",
            KODESEC_ADVISOR_DIRECT_HOSTS=(FIXTURE_HOST if transport == "direct" else ""),
            KODESEC_ADVISOR_SSH_PROVIDER_IDS=("ssh-lab" if transport == "ssh" else ""),
            KODESEC_ADVISOR_GRANT_SECRET=GRANT_SECRET,
            KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        ),
        engine=engine,
    )
    profile = providers.normalize_profile(
        _profile(
            "direct-lab" if transport == "direct" else "ssh-lab",
            transport=transport,
        )
    )
    active = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
        activate=True,
        approve_content_disclosure=True,
    )
    current = active["providers"][0]
    with runtime.session_factory() as db, db.begin():
        project = Project(
            name="vulnerable-demo",
            repo_path="/workspace/vulnerable-demo",
            remote_url="https://fixture:password@example.test/dark/vulnerable-demo.git?token=must-not-persist",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            status="completed",
            base_ref="refs/private/must-not-persist-base",
            head_ref="refs/private/must-not-persist-head",
            revision=1,
        )
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="FIXTURE-1",
            severity="high",
            file_path="src/demo.py",
            start_line=12,
            start_column=12,
            end_line=12,
            end_column=28,
            message="Synthetic vulnerable-demo finding.\r\npassword=must-not-persist.",
            code_snippet=(
                "PRIVATE_REMOTE=https://fixture:password@example.test/private.git\r\n"
                "GITHUB_TOKEN=ghp_must-not-persist\r\n"
                "def unsafe_wrapper():\r\n"
                "BEFORE_FINDING_TOKEN=must-not-persist-before\r\n"
                "    return eval(user_input)\r\n"
                "AFTER_FINDING_PASSWORD=must-not-persist-after\r\n"
                "result = unsafe_wrapper()\r\n"
                "PAYMENT_API_KEY=sk_live_must-not-persist\r\n"
                "PRIVATE_KEY=must-not-persist\r\n"
            ),
            fingerprint="fixture-advisor-confirmation",
            metadata_json={
                "snippet_start_line": 8,
                "rule_name": "Fixture unsafe eval",
                "sarif_level": "error",
                "tags": ["python", "security", "python"],
                "verified": True,
                "native": "sarif",
                "trace": "line one\r\nline two",
                "api_key": "must-not-persist",
            },
            revision=1,
        )
        db.add(finding)
        db.flush()
        finding_id = finding.id
        providers.save_collection(db, active)
        providers.save_consent(db, providers.build_consent(active, current["id"]))
        providers.save_receipt(db, _receipt(current))

    with runtime.session_factory() as db:
        preview = preview_finding_advisor_disclosure(
            finding_id,
            AdvisorDisclosurePreviewRequest(
                expected_revision=1, provider_id=current["id"]
            ),
            runtime,
            db,
        )
        validated_preview = AdvisorDisclosurePreviewOut.model_validate(preview)
        assert validated_preview.packet.finding.id == finding_id
        assert validated_preview.packet.finding.message.count("\n") == 1
        assert "\r" not in validated_preview.packet.finding.message
        assert validated_preview.packet.repo_context.repo_path == "."
        assert validated_preview.packet.repo_context.remote_url is None
        assert validated_preview.packet.repo_context.base_ref is None
        assert validated_preview.packet.repo_context.head_ref is None
        assert validated_preview.packet.scanner_evidence.code_snippet == (
            "    return eval(user_input)"
        )
        assert validated_preview.packet.scanner_evidence.metadata == {
            "rule_name": "Fixture unsafe eval",
            "sarif_level": "error",
            "tags": ["python", "security"],
            "verified": True,
            "snippet_start_line": 12,
        }
        serialized_preview = json.dumps(preview, sort_keys=True)
        for absent in (
            "/workspace/vulnerable-demo",
            "example.test",
            "must-not-persist",
            "PRIVATE_REMOTE",
            "GITHUB_TOKEN",
            "BEFORE_FINDING_TOKEN",
            "must-not-persist-before",
            "AFTER_FINDING_PASSWORD",
            "must-not-persist-after",
            "PAYMENT_API_KEY",
            "PRIVATE_KEY",
            '"native"',
            '"trace"',
            '"api_key"',
        ):
            assert absent not in serialized_preview
        assert preview["packet_utf8_bytes"] == disclosure.packet_utf8_bytes(
            preview["packet"]
        )
        signed_preview = preview["confirmation"]
        assert signed_preview["prompt_sha256"] == disclosure.prompt_sha256(
            preview["packet"]
        )
        forged_document = {
            **signed_preview,
            "authorization_id": "f" * 32,
        }
        forged_unsigned = {
            key: value
            for key, value in forged_document.items()
            if key != "confirmation_digest"
        }
        forged_document["confirmation_digest"] = hashlib.sha256(
            json.dumps(
                forged_unsigned,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        assert disclosure.normalize_confirmation(forged_document) == forged_document
        with pytest.raises(ValidationError):
            TriageRequest(
                expected_revision=1,
                remote_advisor_confirmation=signed_preview,
            )
        payload = TriageRequest(
            expected_revision=1,
            acknowledge_remote_source_disclosure=True,
            remote_advisor_confirmation=signed_preview,
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": f"/v1/findings/{finding_id}/triage",
                "headers": [(b"idempotency-key", b"remote-preview-fixture")],
                "query_string": b"",
            }
        )
        request.state.auth = AuthContext(
            kind="browser", subject="fixture", scopes=frozenset()
        )
        tampered = TriageRequest(
            expected_revision=1,
            acknowledge_remote_source_disclosure=True,
            remote_advisor_confirmation={
                **signed_preview,
                "confirmation_digest": "b" * 64,
            },
        )
        with pytest.raises(HTTPException) as stale:
            triage_finding(finding_id, tampered, request, runtime, db)
        assert stale.value.status_code == 409
        assert (
            stale.value.detail["code"]
            == "advisor_source_disclosure_confirmation_stale"
        )
        forged = TriageRequest(
            expected_revision=1,
            acknowledge_remote_source_disclosure=True,
            remote_advisor_confirmation=forged_document,
        )
        with pytest.raises(HTTPException) as forged_rejection:
            triage_finding(finding_id, forged, request, runtime, db)
        assert forged_rejection.value.status_code == 409
        assert (
            forged_rejection.value.detail["code"]
            == "advisor_source_disclosure_confirmation_stale"
        )
        queued = triage_finding(finding_id, payload, request, runtime, db)
        assert queued["status"] == "queued"
        assert queued["finding_id"] == finding_id
        replay_request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": f"/v1/findings/{finding_id}/triage",
                "headers": [(b"idempotency-key", b"fresh-replay-key")],
                "query_string": b"",
            }
        )
        replay_request.state.auth = AuthContext(
            kind="browser", subject="second-fixture-session", scopes=frozenset()
        )
        replay = triage_finding(
            finding_id, payload, replay_request, runtime, db
        )
        assert replay["id"] == queued["id"]
        assert db.query(Job).count() == 1
        job = db.query(Job).one()
        job_id = job.id
        assert job.client_id == "advisor-confirmation:v1"
        assert job.idempotency_key == durable_idempotency_key(
            f"remote-advisor-authorization:{signed_preview['authorization_id']}"
        )
        assert job.payload["finding_ids"] == [finding_id]
        assert job.payload["limit"] == 1
        assert job.payload["include_existing"] is True
        assert job.payload["remote_advisor_confirmation"] == signed_preview
        assert job.payload["advisor_provider_pin"]["transport"] == transport
        assert job.payload["advisor_provider_pin"]["schema"] == (
            "lomo-advisor-provider-job-pin/v1"
        )
        assert job.payload["advisor"]["advisor_providers"]["providers"][0][
            "schema"
        ] == "lomo-advisor-provider-job-profile/v1"
        assert re.fullmatch(r"[0-9a-f]{32}", job.payload["advisor_operation_id"])
        serialized_job = json.dumps(job.payload, sort_keys=True)
        assert "must-not-persist" not in serialized_job
        assert "[REDACTED]" not in json.dumps(
            job.payload["remote_advisor_confirmation"], sort_keys=True
        )
        persisted_consent = job.payload["advisor"]["advisor_provider_consents"][
            current["id"]
        ]
        assert persisted_consent["destination"] == signed_preview["destination"]
        assert "[REDACTED]" not in json.dumps(persisted_consent, sort_keys=True)
        assert GRANT_SECRET not in serialized_job

    with runtime.session_factory() as db, db.begin():
        claimed_model = db.get(Job, job_id)
        assert claimed_model is not None
        now = datetime.now(timezone.utc)
        claimed_model.status = "leased"
        claimed_model.stage = "leased"
        claimed_model.attempt = 1
        claimed_model.lease_owner = "remote-advisor-worker"
        claimed_model.lease_expires_at = now + timedelta(seconds=30)
        claimed_model.heartbeat_at = now
        db.add(claimed_model)
        db.flush()
        claimed = ClaimedJob.from_model(claimed_model)

    if transport == "direct":
        class SimulatedWorkerCrash(BaseException):
            pass

        provider_requests = 0

        def crash_connector(
            _settings: Settings,
            path: str,
            document: dict[str, object],
            **_kwargs: object,
        ) -> dict[str, object]:
            nonlocal provider_requests
            if path == "/v1/operations":
                return {
                    "operation_id": document["grant"]["nonce"],
                    "status": "admitted",
                }
            assert path == "/v1/generate"
            provider_requests += 1
            return {
                "response": json.dumps(
                    {
                        "verdict": "needs_review",
                        "confidence": 0.75,
                        "reasoning": "This result must not be published after the crash.",
                        "fix": "Require a fresh disclosure confirmation.",
                    }
                ),
                "done": True,
            }

        original_triage = advisor_jobs.triage_finding_sync

        def crash_after_provider(*args: object, **kwargs: object) -> dict[str, object]:
            original_triage(*args, **kwargs)
            raise SimulatedWorkerCrash("fixture crash after provider transmission")

        executor = WorkerExecutor(runtime, "remote-advisor-worker")
        fixture_now = datetime.now(timezone.utc)
        with patch("kodesec_api.jobs.repository._time", return_value=fixture_now):
            executor._mark_running(claimed)
        monitor = LeaseMonitor(runtime, claimed, "remote-advisor-worker")
        with patch(
            "kodesec_api.jobs.advisor._connector_json",
            side_effect=crash_connector,
        ), patch(
            "kodesec_api.jobs.advisor.triage_finding_sync",
            side_effect=crash_after_provider,
        ), patch(
            "kodesec_api.jobs.repository._time",
            return_value=fixture_now,
        ), pytest.raises(SimulatedWorkerCrash):
            executor._triage_scan_findings(
                claimed,
                monitor,
                dict(claimed.checkpoint),
                automatic=False,
            )
        assert provider_requests == 1

        # A connector restart loses its in-memory operation/grant sets. The
        # durable worker marker still prevents a second provider request.
        connector = _connector_module()
        connector._USED_GRANTS.clear()
        connector._OPERATIONS.clear()
        with runtime.session_factory() as db:
            persisted = db.get(Job, job_id)
            assert persisted is not None
            recovered = ClaimedJob.from_model(persisted)
            reviewed = db.get(Finding, finding_id)
            assert reviewed is not None
            assert reviewed.revision == 1
            assert reviewed.ai_verdict is None
            assert recovered.checkpoint["remote_advisor_transmission"] == {
                "advisor_operation_id": job.payload["advisor_operation_id"],
                "confirmation_digest": signed_preview["confirmation_digest"],
                "state": "reserved_before_send",
            }
        with patch(
            "kodesec_api.jobs.advisor._connector_json",
            side_effect=crash_connector,
        ), pytest.raises(JobExecutionError) as consumed:
            executor._triage_scan_findings(
                recovered,
                monitor,
                dict(recovered.checkpoint),
                automatic=False,
            )
        assert consumed.value.code == "advisor_remote_confirmation_consumed"
        assert consumed.value.retryable is False
        assert provider_requests == 1
        with runtime.session_factory() as db, db.begin():
            failed = db.get(Job, job_id)
            assert failed is not None
            failed.status = "failed"
            failed.stage = "failed"
            failed.error_code = consumed.value.code
            failed.error_detail = consumed.value.detail
            failed.lease_owner = None
            failed.lease_expires_at = None
            failed.revision += 1
            db.add(failed)
            db.flush()
            assert _job_to_out(db, failed)["can_retry"] is False
            with patch(
                "kodesec_api.jobs.repository._time",
                return_value=datetime.now(timezone.utc),
            ), pytest.raises(InvalidJobTransition, match="authorization was consumed"):
                retry_failed_job(
                    db,
                    failed.id,
                    expected_revision=failed.revision,
                )
        with runtime.session_factory() as db:
            fresh_preview = preview_finding_advisor_disclosure(
                finding_id,
                AdvisorDisclosurePreviewRequest(
                    expected_revision=1, provider_id=current["id"]
                ),
                runtime,
                db,
            )
            fresh_confirmation = fresh_preview["confirmation"]
            assert (
                fresh_confirmation["authorization_id"]
                != signed_preview["authorization_id"]
            )
            assert (
                fresh_confirmation["confirmation_digest"]
                != signed_preview["confirmation_digest"]
            )
            recovery_request = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": f"/v1/findings/{finding_id}/triage",
                    "headers": [(b"idempotency-key", b"terminal-recovery-key")],
                    "query_string": b"",
                }
            )
            recovery_request.state.auth = AuthContext(
                kind="browser", subject="recovery-fixture", scopes=frozenset()
            )
            recovered_submission = triage_finding(
                finding_id,
                TriageRequest(
                    expected_revision=1,
                    acknowledge_remote_source_disclosure=True,
                    remote_advisor_confirmation=fresh_confirmation,
                ),
                recovery_request,
                runtime,
                db,
            )
            assert recovered_submission["status"] == "queued"
            assert recovered_submission["id"] != job_id
            assert db.query(Job).count() == 2
        return

    if transport == "ssh":
        cancelled_after_send = False

        def cancel_check() -> None:
            if cancelled_after_send:
                raise CancellationRequested("fixture connector cancellation")

        def cancelling_connector(
            _settings: Settings,
            _path: str,
            _document: dict[str, object],
            **kwargs: object,
        ) -> dict[str, object]:
            nonlocal cancelled_after_send
            if _path == "/v1/operations":
                return {
                    "operation_id": _document["grant"]["nonce"],
                    "status": "admitted",
                }
            cancelled_after_send = True
            callback = kwargs.get("cancel_check")
            assert callable(callback)
            callback()
            raise AssertionError("cancellation callback must stop connector exchange")

        cancellation_config = WorkerExecutor(
            runtime, "remote-advisor-worker"
        )._advisor_config(claimed)
        with runtime.session_factory() as db:
            selected = db.get(Finding, finding_id)
            assert selected is not None
            with patch(
                "kodesec_api.jobs.advisor._connector_json",
                side_effect=cancelling_connector,
            ), pytest.raises(CancellationRequested):
                advisor_jobs.triage_finding_sync(
                    db,
                    selected,
                    runtime.settings,
                    model=current["model"],
                    config=cancellation_config,
                    expected_revision=1,
                    commit=False,
                    cancel_check=cancel_check,
                )
            db.rollback()
        with runtime.session_factory() as db:
            unpublished = db.get(Finding, finding_id)
            assert unpublished is not None
            assert unpublished.revision == 1
            assert unpublished.ai_verdict is None

    submissions: list[dict[str, object]] = []

    def connector_request(
        _settings: Settings,
        path: str,
        document: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        submissions.append(document)
        if path == "/v1/operations":
            return {
                "operation_id": document["grant"]["nonce"],
                "status": "admitted",
            }
        assert path == "/v1/generate"
        return {
            "response": json.dumps(
                {
                    "verdict": "needs_review",
                    "confidence": 0.75,
                    "reasoning": "One bounded synthetic finding was reviewed.",
                    "fix": "Replace the synthetic eval call.",
                }
            ),
            "done": True,
        }

    with patch(
        "kodesec_api.jobs.advisor._connector_json",
        side_effect=connector_request,
    ), patch(
        "kodesec_api.jobs.repository._time",
        return_value=datetime.now(timezone.utc),
    ):
        WorkerExecutor(runtime, "remote-advisor-worker").execute(claimed)

    assert len(submissions) == 2
    assert submissions[0] == submissions[1]
    generation_document = submissions[1]
    assert generation_document["provider"] == current
    assert generation_document["confirmation"] == signed_preview
    assert isinstance(generation_document["request"], dict)
    assert generation_document["request"]["model"] == current["model"]
    assert isinstance(generation_document["grant"], dict)
    assert grants.verify_execution_grant(
        GRANT_SECRET,
        generation_document["grant"],
        current,
        signed_preview,
        generation_document["request"]["prompt"],
    ) == generation_document["grant"]
    assert generation_document["grant"]["nonce"] == job.payload["advisor_operation_id"]
    assert GRANT_SECRET not in json.dumps(submissions[0], sort_keys=True)
    with runtime.session_factory() as db:
        completed = db.get(Job, job_id)
        reviewed = db.get(Finding, finding_id)
        assert completed is not None and completed.status == "completed"
        assert completed.result_ref == f"finding:{finding_id}"
        assert completed.detail == (
            f"Remote {transport} Advisor triage completed for one explicitly confirmed finding."
        )
        assert reviewed is not None and reviewed.revision == 2
        assert reviewed.ai_verdict == "needs_review"
        assert reviewed.metadata_json["advisor"] == {
            "model": current["model"],
            "prompt_version": "finding-triage-v5",
            "thinking": False,
            "model_digest": current["model_digest"],
            "provider_id": current["id"],
            "provider_transport": transport,
            "disclosure_confirmation_digest": signed_preview["confirmation_digest"],
        }


def test_provider_resolution_is_local_then_direct_then_ssh() -> None:
    profiles = [
        providers.normalize_profile(_profile("ssh-lab", transport="ssh", priority=0)),
        providers.normalize_profile(_profile("local-lab", transport="local", priority=2)),
        providers.normalize_profile(_profile("direct-lab", priority=1)),
    ]
    settings = SimpleNamespace(
        advisor_direct_host_list=frozenset({FIXTURE_HOST}),
        advisor_ssh_provider_id_list=frozenset({"ssh-lab"}),
    )
    resolved = providers.resolve_candidates(
        {"revision": 1, "active_provider_id": None, "providers": profiles}, settings
    )
    assert [item["transport"] for item in resolved] == ["local", "direct", "ssh"]


def test_public_resolution_matches_fail_closed_runtime_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(
        advisor_direct_host_list=frozenset({FIXTURE_HOST}),
        advisor_ssh_provider_id_list=frozenset(),
    )
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    idle_collection = {
        "revision": 1,
        "active_provider_id": None,
        "providers": [local],
    }
    idle_public = providers.public_collection(idle_collection, settings, {}, {})
    assert idle_public["providers"][0]["eligible"] is False
    assert idle_public["providers"][0]["reason_code"] == "test_required"
    assert idle_public["resolution"] == {
        "provider_id": None,
        "transport": "unavailable",
        "reason": "no_executable_provider",
        "eligible_provider_ids": [],
    }

    ready_collection = providers.update_provider_status(
        idle_collection,
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    ready = ready_collection["providers"][0]
    receipt = _receipt(ready)
    ready_public = providers.public_collection(
        ready_collection, settings, {}, {ready["id"]: receipt}
    )
    assert ready_public["providers"][0]["eligible"] is True
    assert ready_public["resolution"]["provider_id"] == ready["id"]
    assert ready_public["resolution"]["transport"] == "local"

    monkeypatch.setattr(
        advisor_jobs,
        "test_provider_sync",
        lambda profile, _settings, timeout=10.0: _receipt(profile),
    )
    resolved, observed, reason = resolve_provider_sync(
        {
            "advisor_providers": ready_collection,
            "advisor_provider_receipts": {ready["id"]: receipt},
        },
        settings,
    )
    assert resolved is not None and resolved["id"] == ready["id"]
    assert observed is not None and observed["status"] == "ready"
    assert reason is None
    unresolved, _receipt_value, unavailable = resolve_provider_sync(
        {"advisor_providers": ready_collection, "advisor_provider_receipts": {}},
        settings,
    )
    assert unresolved is None
    assert unavailable == "no_executable_provider"


def test_worker_advisor_requires_exact_current_provider_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_ALLOWED_ROOTS="/workspace",
        OLLAMA_MODEL_DIGEST=DIGEST,
    )
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    collection = providers.update_provider_status(
        {"revision": 3, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    selected = collection["providers"][0]
    pin = providers.job_pin_snapshot(
        {
            "provider_id": selected["id"],
            "transport": selected["transport"],
            "provider_config_revision": selected["config_revision"],
            "provider_config_digest": selected["config_digest"],
            "model": selected["model"],
            "model_digest": selected["model_digest"],
        }
    )
    job_collection = providers.job_collection_snapshot(collection)
    payload = {
        "advisor": {
            "ai_mode": "on",
            "ollama_base_url": "http://ollama:11434",
            "ollama_model": selected["model"],
            "ollama_thinking": False,
            "auto_triage_limit": 5,
            "advisor_providers": job_collection,
            "advisor_provider_consents": {},
            "advisor_provider_receipts": {},
        },
        "advisor_provider_collection_revision": collection["revision"],
        "advisor_provider_pin": pin,
    }

    def claimed(candidate: dict[str, object]) -> ClaimedJob:
        return ClaimedJob(
            id=1,
            kind="advisor",
            status="leased",
            stage="leased",
            attempt=1,
            max_attempts=3,
            scan_id=1,
            finding_id=1,
            external_run_id=None,
            payload=candidate,
            checkpoint={},
        )

    executor = SimpleNamespace(settings=settings)
    normalized = WorkerExecutor._advisor_config(executor, claimed(payload))
    assert normalized["advisor_provider_pin"]["provider_id"] == selected["id"]
    rejected_payloads = [
        (
            {**payload, "advisor": {**payload["advisor"], "advisor_providers": None}},
            "advisor_provider_snapshot_missing",
        ),
        (
            {
                **payload,
                "advisor": {
                    **payload["advisor"],
                    "advisor_providers": providers.job_collection_snapshot(
                        {
                            "revision": 1,
                            "active_provider_id": None,
                            "providers": [],
                        }
                    ),
                },
            },
            "advisor_provider_snapshot_empty",
        ),
        (
            {
                **payload,
                "advisor_provider_pin": {**pin, "model_digest": "b" * 64},
            },
            "advisor_provider_selection_stale",
        ),
    ]
    for candidate, error_code in rejected_payloads:
        with pytest.raises(JobExecutionError) as rejected:
            WorkerExecutor._advisor_config(executor, claimed(candidate))
        assert rejected.value.code == error_code

    monkeypatch.setattr(
        advisor_jobs,
        "test_provider_sync",
        lambda *_args, **_kwargs: pytest.fail(
            "missing or empty provider state must not reach a transport probe"
        ),
    )
    assert worker_ollama_available_sync(
        {"ai_mode": "on"}, timeout=2, settings=settings
    ) == (False, [], "provider_configuration_missing")
    assert worker_ollama_available_sync(
        {
            "ai_mode": "on",
            "advisor_providers": {
                "revision": 1,
                "active_provider_id": None,
                "providers": [],
            },
        },
        timeout=2,
        settings=settings,
    ) == (False, [], "no_provider_configured")


def test_durable_active_provider_collection_round_trips_to_worker_canonically() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_ALLOWED_ROOTS="/workspace",
        KODESEC_ADVISOR_DIRECT_HOSTS=FIXTURE_HOST,
    )
    runtime = Runtime.create(settings, engine=engine)
    provider_id = "provider-0123456789abcdef01234567"
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    direct = providers.normalize_profile(_profile(provider_id, priority=1))
    collection = providers.update_provider_status(
        {
            "revision": 3,
            "active_provider_id": None,
            "providers": [local, direct],
        },
        provider_id,
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
        activate=True,
        approve_content_disclosure=True,
    )
    selected = providers.provider_by_id(collection, provider_id)
    consent = providers.build_consent(collection, provider_id)
    receipt = _receipt(selected)
    pin = providers.job_pin_snapshot(
        {
            "provider_id": selected["id"],
            "transport": selected["transport"],
            "provider_config_revision": selected["config_revision"],
            "provider_config_digest": selected["config_digest"],
            "model": selected["model"],
            "model_digest": selected["model_digest"],
        }
    )
    confirmation = disclosure.build_confirmation(
        collection,
        selected,
        consent,
        finding_id=1,
        finding_revision=1,
        packet={"finding": {"rule_id": "fixture"}, "scanner_evidence": {}},
        signing_key=INSTALLATION_SECRET,
        authorization_id="0123456789abcdef0123456789abcdef",
    )
    canonical_collection = providers.job_collection_snapshot(collection)
    assert canonical_collection["schema"] == providers.PROVIDER_JOB_COLLECTION_SCHEMA
    expected_collection = providers.normalize_job_collection_snapshot(
        canonical_collection
    )

    untyped_collection = deepcopy(canonical_collection)
    untyped_collection.pop("schema")
    with pytest.raises(ValueError, match="schema is invalid"):
        providers.normalize_job_collection_snapshot(untyped_collection)
    assert _redact_job_document(untyped_collection)["active_provider_id"] == "[REDACTED]"
    reordered_collection = {
        **canonical_collection,
        "providers": list(reversed(canonical_collection["providers"])),
    }
    with pytest.raises(ValueError, match="not canonical"):
        providers.normalize_job_collection_snapshot(reordered_collection)
    assert _redact_job_document(reordered_collection) == "[REDACTED]"

    payload = {
        "v": 1,
        "operation": "advisor_triage",
        "opaque_identifier": "z" * 33,
        "advisor": {
            "ai_mode": "on",
            "ollama_base_url": f"http://{FIXTURE_HOST}:11434",
            "ollama_model": FIXTURE_MODEL,
            "ollama_thinking": False,
            "auto_triage_limit": 1,
            "advisor_providers": canonical_collection,
            "advisor_provider_consent": consent,
            "advisor_provider_consents": {provider_id: consent},
            "advisor_provider_receipts": {provider_id: receipt},
        },
        "advisor_provider_collection_revision": collection["revision"],
        "advisor_provider_pin": pin,
        "remote_advisor_confirmation": confirmation,
        "advisor_operation_id": confirmation["authorization_id"],
    }
    with runtime.session_factory() as db, db.begin():
        queued = enqueue_job(
            db,
            kind="advisor",
            title="Persist exact active provider",
            client_id="browser:provider-snapshot-fixture",
            idempotency_key="provider-snapshot-roundtrip",
            payload=payload,
        ).job
        job_id = queued.id

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        assert persisted.payload["opaque_identifier"] == "[REDACTED]"
        persisted_advisor = persisted.payload["advisor"]
        assert persisted_advisor["advisor_providers"] == canonical_collection
        assert "[REDACTED]" not in json.dumps(persisted_advisor, sort_keys=True)
        claimed = ClaimedJob(
            id=persisted.id,
            kind=persisted.kind,
            status="leased",
            stage="leased",
            attempt=1,
            max_attempts=persisted.max_attempts,
            scan_id=persisted.scan_id,
            finding_id=persisted.finding_id,
            external_run_id=persisted.external_run_id,
            payload=deepcopy(persisted.payload),
            checkpoint={},
        )

    worker_config = WorkerExecutor(runtime, "provider-snapshot-worker")._advisor_config(
        claimed
    )
    assert worker_config["advisor_providers"] == expected_collection
    assert worker_config["advisor_providers"]["active_provider_id"] == provider_id
    assert worker_config["advisor_provider_consent"] == consent
    assert worker_config["advisor_provider_consents"] == {provider_id: consent}
    assert worker_config["advisor_provider_receipts"] == {provider_id: receipt}
    assert worker_config["advisor_provider_pin"] == providers.normalize_job_pin_snapshot(
        pin
    )
    runtime.engine.dispose()


def test_triage_rejects_missing_provider_snapshot_before_transmission() -> None:
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    collection = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    runtime, _scan_id, finding_id = _triage_runtime(
        collection, persist_receipt=True
    )
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        for config in (None, {"ai_mode": "on"}):
            with patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                side_effect=AssertionError("no prompt may be transmitted"),
            ), pytest.raises(HTTPException) as rejected:
                advisor_jobs.triage_finding_sync(
                    db,
                    finding,
                    runtime.settings,
                    config=config,
                    expected_revision=1,
                )
            assert rejected.value.status_code == 409
            assert rejected.value.detail["code"] == "advisor_provider_snapshot_missing"
            assert rejected.value.detail["action"] == "refresh_advisor_providers"
    runtime.engine.dispose()


def test_local_provider_revision_drift_preserves_typed_error_without_transmission() -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    collection = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    selected = collection["providers"][0]
    runtime, _scan_id, finding_id = _triage_runtime(
        collection, persist_receipt=True
    )
    config = {
        "ai_mode": "on",
        "ollama_thinking": False,
        "advisor_providers": collection,
        "advisor_provider_pin": providers.job_pin_snapshot(
            {
                "provider_id": selected["id"],
                "transport": selected["transport"],
                "provider_config_revision": selected["config_revision"],
                "provider_config_digest": selected["config_digest"],
                "model": selected["model"],
                "model_digest": selected["model_digest"],
            }
        ),
    }
    with runtime.session_factory() as db, db.begin():
        current = providers.load_collection(db, runtime.settings, lock=True)
        replacement = dict(providers.provider_by_id(current, selected["id"]))
        replacement["name"] = "Changed local provider"
        providers.save_collection(
            db,
            providers.replace_profile(
                current,
                replacement,
                expected_revision=current["revision"],
                create=False,
            ),
        )

    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        with patch(
            "kodesec_api.jobs.advisor.resolve_provider_sync",
            return_value=(selected, _receipt(selected), None),
        ), patch(
            "kodesec_api.jobs.advisor.generate_with_provider_sync",
            side_effect=AssertionError("provider drift must prevent transmission"),
        ) as transmit, pytest.raises(HTTPException) as stale:
            advisor_jobs.triage_finding_sync(
                db,
                finding,
                runtime.settings,
                config=config,
                expected_revision=1,
            )
        transmit.assert_not_called()
        assert stale.value.status_code == 409
        assert stale.value.detail["code"] == "advisor_provider_configuration_changed"
        assert stale.value.detail["action"] == "refresh_advisor_providers"
    runtime.engine.dispose()


def test_all_advisor_gui_admissions_persist_the_exact_locked_local_pin() -> None:
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    ready_collection = providers.update_provider_status(
        {"revision": 4, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    ready = ready_collection["providers"][0]
    pin = _triage_pin(ready_collection, ready)
    runtime, scan_id, finding_id = _triage_runtime(
        ready_collection, persist_receipt=True
    )

    with runtime.session_factory() as db:
        triage_scan(
            scan_id,
            ScanTriageRequest(advisor_provider_pin=pin),
            _command_request(
                f"/v1/scans/{scan_id}/triage", "scan-provider-pin-fixture"
            ),
            runtime,
            db,
        )
    with runtime.session_factory() as db:
        triage_finding(
            finding_id,
            TriageRequest(expected_revision=1, advisor_provider_pin=pin),
            _command_request(
                f"/v1/findings/{finding_id}/triage",
                "finding-provider-pin-fixture",
            ),
            runtime,
            db,
        )
    with runtime.session_factory() as db:
        response = Response()
        result = bulk_findings(
            FindingBulkAction(
                finding_ids=[finding_id],
                action="triage",
                expected_revisions={finding_id: 1},
                advisor_provider_pin=pin,
            ),
            _command_request(
                "/v1/findings/bulk", "bulk-provider-pin-fixture"
            ),
            response,
            runtime,
            db,
        )
        assert result["job"]["status"] == "queued"

    with runtime.session_factory() as db:
        jobs = list(db.query(Job).order_by(Job.id))
        assert len(jobs) == 3
        for job in jobs:
            assert job.payload["advisor_provider_collection_revision"] == 4
            assert job.payload["advisor_provider_pin"] == {
                "schema": "lomo-advisor-provider-job-pin/v1",
                "provider_id": ready["id"],
                "transport": "local",
                "provider_config_revision": ready["config_revision"],
                "provider_config_digest": ready["config_digest"],
                "model": ready["model"],
                "model_digest": ready["model_digest"],
            }


@pytest.mark.parametrize("route", ["scan", "finding", "bulk", "scan_create"])
def test_advisor_gui_admission_rejects_ai_off_without_job(route: str) -> None:
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    ready_collection = providers.update_provider_status(
        {"revision": 5, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    ready = ready_collection["providers"][0]
    pin = _triage_pin(ready_collection, ready)
    runtime, scan_id, finding_id = _triage_runtime(
        ready_collection, persist_receipt=True
    )
    with runtime.session_factory() as db, db.begin():
        project_id = db.query(Project.id).scalar()
        assert project_id is not None
        if route == "scan_create":
            db.query(Finding).delete()
            db.query(Scan).delete()
        db.add(RuntimeConfig(key="ai_mode", value="off"))

    with runtime.session_factory() as db, pytest.raises(HTTPException) as blocked:
        if route == "scan_create":
            create_scan(
                ScanCreate(project_id=project_id, use_ai=True),
                _command_request("/v1/scans", "ai-off-create-scan"),
                runtime,
                db,
            )
        elif route == "scan":
            triage_scan(
                scan_id,
                ScanTriageRequest(advisor_provider_pin=pin),
                _command_request(
                    f"/v1/scans/{scan_id}/triage", "ai-off-scan-provider"
                ),
                runtime,
                db,
            )
        elif route == "finding":
            triage_finding(
                finding_id,
                TriageRequest(expected_revision=1, advisor_provider_pin=pin),
                _command_request(
                    f"/v1/findings/{finding_id}/triage",
                    "ai-off-finding-provider",
                ),
                runtime,
                db,
            )
        else:
            bulk_findings(
                FindingBulkAction(
                    finding_ids=[finding_id],
                    action="triage",
                    expected_revisions={finding_id: 1},
                    advisor_provider_pin=pin,
                ),
                _command_request("/v1/findings/bulk", "ai-off-bulk-provider"),
                Response(),
                runtime,
                db,
            )
    assert blocked.value.status_code == 409
    assert blocked.value.detail == ADVISOR_DISABLED_DETAIL
    with runtime.session_factory() as db:
        assert db.query(Job).count() == 0
        if route == "scan_create":
            assert db.query(Scan).count() == 0


@pytest.mark.parametrize("job_kind", ["advisor", "scan"])
def test_ai_job_retry_admission_rejects_ai_off_without_mutation(
    job_kind: str,
) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    ready_collection = providers.update_provider_status(
        {"revision": 5, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    runtime, scan_id, finding_id = _triage_runtime(
        ready_collection, persist_receipt=True
    )
    with runtime.session_factory() as db, db.begin():
        failed = Job(
            kind=job_kind,
            title=f"Failed AI-bearing {job_kind}",
            status="failed",
            stage="failed",
            detail="Provider unavailable before send.",
            progress=25,
            payload=(
                {
                    "v": 1,
                    "operation": "advisor",
                    "finding_ids": [finding_id],
                    "advisor_provider_pin": _triage_pin(
                        ready_collection, ready_collection["providers"][0]
                    ).model_dump(mode="json"),
                }
                if job_kind == "advisor"
                else {
                    "v": 1,
                    "operation": "scan",
                    "use_ai": True,
                }
            ),
            checkpoint=(
                {"completed_finding_ids": [], "next_finding_id": finding_id}
                if job_kind == "advisor"
                else {"completed_scanner_ids": []}
            ),
            attempt=1,
            max_attempts=3,
            revision=4,
            scan_id=scan_id if job_kind == "scan" else None,
            finding_id=finding_id if job_kind == "advisor" else None,
            error_code="advisor_provider_unavailable",
            error_detail="The local Advisor was unavailable.",
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([failed, RuntimeConfig(key="ai_mode", value="on")])
        db.flush()
        job_id = failed.id

    with runtime.session_factory() as db, db.begin():
        db.get(RuntimeConfig, "ai_mode").value = "off"

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        before = {
            "status": persisted.status,
            "stage": persisted.stage,
            "revision": persisted.revision,
            "attempt": persisted.attempt,
            "max_attempts": persisted.max_attempts,
            "payload": deepcopy(persisted.payload),
            "checkpoint": deepcopy(persisted.checkpoint),
            "detail": persisted.detail,
            "error_code": persisted.error_code,
            "error_detail": persisted.error_detail,
            "completed_at": persisted.completed_at,
            "cancel_requested_at": persisted.cancel_requested_at,
            "lease_owner": persisted.lease_owner,
            "lease_expires_at": persisted.lease_expires_at,
            "heartbeat_at": persisted.heartbeat_at,
            "scan_id": persisted.scan_id,
            "finding_id": persisted.finding_id,
        }
        with patch("kodesec_api.main.retry_failed_job") as retry_mutation:
            with pytest.raises(HTTPException) as blocked:
                retry_job(
                    job_id,
                    JobRetryRequest(expected_revision=persisted.revision),
                    runtime,
                    db,
                )
        retry_mutation.assert_not_called()
        assert blocked.value.status_code == 409
        assert blocked.value.detail == ADVISOR_DISABLED_DETAIL

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        assert db.query(Job).count() == 1
        assert {
            "status": persisted.status,
            "stage": persisted.stage,
            "revision": persisted.revision,
            "attempt": persisted.attempt,
            "max_attempts": persisted.max_attempts,
            "payload": persisted.payload,
            "checkpoint": persisted.checkpoint,
            "detail": persisted.detail,
            "error_code": persisted.error_code,
            "error_detail": persisted.error_detail,
            "completed_at": persisted.completed_at,
            "cancel_requested_at": persisted.cancel_requested_at,
            "lease_owner": persisted.lease_owner,
            "lease_expires_at": persisted.lease_expires_at,
            "heartbeat_at": persisted.heartbeat_at,
            "scan_id": persisted.scan_id,
            "finding_id": persisted.finding_id,
        } == before


@pytest.mark.parametrize("change", ["unchanged", "revised", "suppressed", "removed", "completed", "known-selection-error"])
def test_advisor_retry_checks_original_selection_before_mutation(change: str) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    runtime, scan_id, finding_id = _triage_runtime(
        {"revision": 1, "active_provider_id": None, "providers": [local]},
        persist_receipt=False,
    )
    with runtime.session_factory() as db, db.begin():
        job = Job(
            kind="advisor", title="Exact retry fixture", status="failed", stage="failed",
            payload={"v": 1, "operation": "advisor_finding", "finding_ids": [finding_id],
                     "expected_revisions": {str(finding_id): 1}, "include_existing": True},
            checkpoint={"advisor_completed": [finding_id] if change == "completed" else []},
            attempt=1, max_attempts=3, revision=4, scan_id=scan_id, finding_id=finding_id,
            error_code="advisor_selection_changed" if change == "known-selection-error" else "advisor_generation_response_invalid",
            error_detail="Prior safe failure.", completed_at=datetime.now(timezone.utc),
        )
        db.add_all([job, RuntimeConfig(key="ai_mode", value="auto")])
        finding = db.get(Finding, finding_id)
        if change in {"revised", "completed"}:
            finding.revision = 2
        elif change == "suppressed":
            finding.suppressed = True
        elif change == "removed":
            db.delete(finding)
        db.flush()
        job_id = job.id

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        before = {column.name: deepcopy(getattr(job, column.name)) for column in Job.__table__.columns}
        projection = _job_to_out(db, job)
        blocked = change not in {"unchanged", "completed"}
        assert projection["can_retry"] is not blocked
        if blocked:
            assert "new Advisor review" in projection["retry_blocked_reason"]
            with patch("kodesec_api.main.retry_failed_job") as mutation:
                with pytest.raises(HTTPException) as rejected:
                    retry_job(job_id, JobRetryRequest(expected_revision=4), runtime, db)
            mutation.assert_not_called()
            assert rejected.value.status_code == 409
            assert rejected.value.detail["code"] == "advisor_selection_changed"
            assert rejected.value.detail["action"] == "refresh_findings"
            assert rejected.value.detail["context"]["scan_id"] == scan_id
            assert {column.name: getattr(job, column.name) for column in Job.__table__.columns} == before
            db.commit()
        else:
            assert projection["retry_blocked_reason"] is None
            with patch("kodesec_api.jobs.repository._time", return_value=datetime.now(timezone.utc)):
                result = retry_job(job_id, JobRetryRequest(expected_revision=4), runtime, db)
            assert result["status"] == "queued"
            assert result["revision"] == 5
            assert job.payload == before["payload"]
            assert job.checkpoint == before["checkpoint"]
            assert job.attempt == 1
    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert db.query(Job).count() == 1
        if blocked:
            assert {column.name: getattr(persisted, column.name) for column in Job.__table__.columns} == before


@pytest.mark.parametrize("payload", [
    {"finding_ids": [True]}, {"finding_ids": [1, 1]}, {"finding_ids": ["9" * 21]},
    {"finding_ids": [0]}, {"finding_ids": list(range(1, 202))},
    {"finding_ids": [1], "expected_revisions": {"1": True}},
    {"finding_ids": [1], "expected_revisions": {"2": 1}},
    {"finding_ids": [1], "expected_revisions": {"1": 1, "01": 1}},
])
def test_advisor_retry_shared_selection_adapter_rejects_malformed_snapshot(payload: dict) -> None:
    with pytest.raises(AdvisorSelectionError) as rejected:
        advisor_selection_snapshot(payload)
    assert rejected.value.code == "invalid_payload"


def test_advisor_retry_shared_selection_checks_pending_not_completed_revisions() -> None:
    selection = advisor_selection_snapshot({"finding_ids": [1, 2], "expected_revisions": {"1": 1, "2": 1}})
    selection.require_current({1: 2, 2: 1}, completed={1}, include_existing=True)
    with pytest.raises(AdvisorSelectionError) as rejected:
        selection.require_current({1: 2, 2: 2}, completed={1}, include_existing=True)
    assert rejected.value.code == "advisor_selection_changed"


@pytest.mark.parametrize("change", ["revised", "suppressed"])
def test_advisor_worker_uses_retry_selection_fence_before_model_work(change: str) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    runtime, scan_id, finding_id = _triage_runtime(
        {"revision": 1, "active_provider_id": None, "providers": [local]},
        persist_receipt=False,
    )
    with runtime.session_factory() as db, db.begin():
        finding = db.get(Finding, finding_id)
        if change == "revised":
            finding.revision += 1
        else:
            finding.suppressed = True
    job = SimpleNamespace(scan_id=scan_id, finding_id=finding_id, payload={
        "finding_ids": [finding_id], "expected_revisions": {str(finding_id): 1},
        "include_existing": True, "limit": 1,
    })
    executor = WorkerExecutor(runtime, "selection-test")
    with patch.object(executor, "_advisor_config", return_value={}), patch(
        "kodesec_api.jobs.advisor.triage_finding_sync"
    ) as generation:
        with pytest.raises(JobExecutionError) as rejected:
            executor._triage_scan_findings(job, SimpleNamespace(), {}, automatic=False)
    generation.assert_not_called()
    assert rejected.value.code == "advisor_selection_changed"
    assert rejected.value.retryable is False


@pytest.mark.parametrize("omit_limit", [False, True])
def test_bulk_advisor_without_limit_executes_only_the_admitted_selection(omit_limit: bool) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    collection = providers.update_provider_status(
        {"revision": 1, "active_provider_id": None, "providers": [local]},
        local["id"], status="available", reason=None, reason_code=None, remediation="none",
    )
    runtime, scan_id, first_id = _triage_runtime(collection, persist_receipt=True)
    with runtime.session_factory() as db, db.begin():
        additional = [
            Finding(
                scan_id=scan_id, scan_finding_number=index, scanner="fixture",
                rule_id=f"bulk-{index}", severity="high", file_path=f"src/bulk-{index}.py",
                start_line=1, end_line=1, message="Synthetic bulk finding.",
                fingerprint=f"bulk-{index}", revision=1,
            )
            for index in (2, 3)
        ]
        db.add_all(additional)
        db.flush()
        selected_ids = [first_id, additional[0].id]
        unselected_id = additional[1].id
    with runtime.session_factory() as db:
        response = Response()
        accepted = bulk_findings(
            FindingBulkAction(
                finding_ids=selected_ids, action="triage",
                expected_revisions={finding_id: 1 for finding_id in selected_ids},
                advisor_provider_pin=_triage_pin(collection, collection["providers"][0]),
            ),
            _command_request("/v1/findings/bulk", "bulk-no-limit"), response, runtime, db,
        )
        assert response.status_code == 202
        job = db.get(Job, accepted["job"]["id"])
        assert job.payload["limit"] is None
        payload = deepcopy(job.payload)
        if omit_limit:
            payload.pop("limit", None)
        claimed = SimpleNamespace(
            id=job.id, kind=job.kind, scan_id=scan_id, finding_id=None,
            payload=payload, attempt=1, checkpoint={},
        )

    reviewed = []

    def triage(db, finding, _settings, **kwargs):
        assert kwargs["expected_revision"] == 1
        assert kwargs["config"]["advisor_provider_pin"]["transport"] == "local"
        assert kwargs["commit"] is False
        reviewed.append(finding.id)
        finding.ai_verdict = "needs_review"
        finding.revision += 1
        db.add(finding)

    executor = WorkerExecutor(runtime, "bulk-selection-test")
    with patch("kodesec_api.jobs.advisor.triage_finding_sync", side_effect=triage), patch(
        "kodesec_api.jobs.execution.update_job_progress"
    ) as progress:
        completion = executor._execute_advisor_scan(
            claimed, SimpleNamespace(raise_if_unusable=lambda: None)
        )
    assert reviewed == selected_ids
    assert completion.detail == "Local advisor triage completed for 2 findings."
    assert completion.result_ref == f"scan:{scan_id}"
    assert [call.kwargs["checkpoint"]["advisor_completed"] for call in progress.call_args_list] == [
        selected_ids[:1], selected_ids,
    ]
    with runtime.session_factory() as db:
        assert all(db.get(Finding, finding_id).revision == 2 for finding_id in selected_ids)
        unselected = db.get(Finding, unselected_id)
        assert unselected.revision == 1 and unselected.ai_verdict is None
    runtime.engine.dispose()


def test_non_ai_scan_retry_remains_available_when_ai_mode_is_off(
) -> None:
    scan_payload: dict[str, object] = {
        "v": 1,
        "operation": "scan",
        "use_ai": False,
    }
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    collection = {
        "revision": 1,
        "active_provider_id": None,
        "providers": [local],
    }
    runtime, scan_id, _ = _triage_runtime(collection, persist_receipt=False)
    with runtime.session_factory() as db, db.begin():
        failed = Job(
            kind="scan",
            title="Failed non-AI scan",
            status="failed",
            stage="failed",
            payload=scan_payload,
            checkpoint={"completed_scanner_ids": []},
            attempt=1,
            max_attempts=3,
            revision=2,
            scan_id=scan_id,
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([failed, RuntimeConfig(key="ai_mode", value="off")])
        db.flush()
        job_id = failed.id

    with runtime.session_factory() as db, patch(
        "kodesec_api.main._require_advisor_ai_admission"
    ) as ai_admission, patch(
        "kodesec_api.jobs.repository._time",
        return_value=datetime.now(timezone.utc),
    ):
        retried = retry_job(
            job_id,
            JobRetryRequest(expected_revision=2),
            runtime,
            db,
        )
        ai_admission.assert_not_called()
        assert retried["status"] == "queued"
        assert retried["revision"] == 3

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        assert persisted.status == "queued"
        assert persisted.revision == 3
        assert persisted.attempt == 1
        assert persisted.checkpoint == {"completed_scanner_ids": []}


@pytest.mark.parametrize(
    ("job_kind", "malformed_payload", "error_type"),
    [
        (
            "scan",
            {"v": 1, "operation": "scan", "use_ai": value},
            InvalidScanCommandSnapshot,
        )
        for value in (1, "true", None, [], {})
    ]
    + [
        (
            "scan",
            {"v": 1, "operation": "scan"},
            InvalidScanCommandSnapshot,
        ),
        (
            "scan",
            {"v": 1, "operation": "advisor_finding", "use_ai": False},
            ScanCommandKindMismatch,
        ),
        (
            "advisor",
            {"v": 1, "operation": "scan", "use_ai": False},
            ScanCommandKindMismatch,
        ),
        (
            "scan",
            {"v": 2, "operation": "scan", "use_ai": False},
            UnsupportedScanCommandVersion,
        ),
    ],
    ids=[
        "integer",
        "string",
        "null",
        "array",
        "object",
        "missing-use-ai",
        "scan-kind-mismatch",
        "scan-operation-mismatch",
        "version",
    ],
)
def test_malformed_scan_retry_snapshot_fails_closed_without_mutation(
    job_kind: str,
    malformed_payload: dict[str, object],
    error_type: type[InvalidScanCommandSnapshot],
) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    runtime, scan_id, _ = _triage_runtime(
        {"revision": 1, "active_provider_id": None, "providers": [local]},
        persist_receipt=False,
    )
    with runtime.session_factory() as db, db.begin():
        failed = Job(
            kind=job_kind,
            title="Failed scan with malformed immutable snapshot",
            status="failed",
            stage="failed",
            payload=malformed_payload,
            checkpoint={"completed_scanner_ids": []},
            attempt=1,
            max_attempts=3,
            revision=2,
            scan_id=scan_id,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(failed)
        db.flush()
        job_id = failed.id

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        before = {
            "status": persisted.status,
            "stage": persisted.stage,
            "revision": persisted.revision,
            "attempt": persisted.attempt,
            "max_attempts": persisted.max_attempts,
            "payload": deepcopy(persisted.payload),
            "checkpoint": deepcopy(persisted.checkpoint),
            "detail": persisted.detail,
            "error_code": persisted.error_code,
            "error_detail": persisted.error_detail,
            "completed_at": persisted.completed_at,
            "cancel_requested_at": persisted.cancel_requested_at,
            "lease_owner": persisted.lease_owner,
            "lease_expires_at": persisted.lease_expires_at,
            "heartbeat_at": persisted.heartbeat_at,
        }
        with patch("kodesec_api.main.retry_failed_job") as retry_mutation, patch(
            "kodesec_api.main._require_advisor_ai_admission"
        ) as advisor_admission:
            with pytest.raises(HTTPException) as blocked:
                retry_job(
                    job_id,
                    JobRetryRequest(expected_revision=2),
                    runtime,
                    db,
                )
        retry_mutation.assert_not_called()
        advisor_admission.assert_not_called()
        assert blocked.value.status_code == 409
        assert blocked.value.detail == _scan_snapshot_problem(error_type)

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted is not None
        assert {
            "status": persisted.status,
            "stage": persisted.stage,
            "revision": persisted.revision,
            "attempt": persisted.attempt,
            "max_attempts": persisted.max_attempts,
            "payload": persisted.payload,
            "checkpoint": persisted.checkpoint,
            "detail": persisted.detail,
            "error_code": persisted.error_code,
            "error_detail": persisted.error_detail,
            "completed_at": persisted.completed_at,
            "cancel_requested_at": persisted.cancel_requested_at,
            "lease_owner": persisted.lease_owner,
            "lease_expires_at": persisted.lease_expires_at,
            "heartbeat_at": persisted.heartbeat_at,
        } == before
        assert db.query(Job).count() == 1


def test_signed_remote_advisor_admission_rejects_ai_off_without_job() -> None:
    remote = providers.normalize_profile(_profile("direct-lab", transport="direct"))
    active_collection = providers.update_provider_status(
        {"revision": 5, "active_provider_id": None, "providers": [remote]},
        remote["id"],
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
        activate=True,
        approve_content_disclosure=True,
    )
    current = active_collection["providers"][0]
    runtime, _, finding_id = _triage_runtime(
        active_collection,
        persist_receipt=True,
        installation_secret=INSTALLATION_SECRET,
    )
    with runtime.session_factory() as db, db.begin():
        providers.save_consent(
            db, providers.build_consent(active_collection, current["id"])
        )
        db.add(RuntimeConfig(key="ai_mode", value="on"))

    with runtime.session_factory() as db:
        preview = preview_finding_advisor_disclosure(
            finding_id,
            AdvisorDisclosurePreviewRequest(
                expected_revision=1, provider_id=current["id"]
            ),
            runtime,
            db,
        )
        signed_confirmation = preview["confirmation"]

    with runtime.session_factory() as db, db.begin():
        db.get(RuntimeConfig, "ai_mode").value = "off"

    payload = TriageRequest(
        expected_revision=1,
        acknowledge_remote_source_disclosure=True,
        remote_advisor_confirmation=signed_confirmation,
    )
    with runtime.session_factory() as db:
        finding_before = db.get(Finding, finding_id)
        assert finding_before is not None
        before_revision = finding_before.revision
        with patch("kodesec_api.main._enqueue_or_conflict") as enqueue:
            with pytest.raises(HTTPException) as blocked:
                triage_finding(
                    finding_id,
                    payload,
                    _command_request(
                        f"/v1/findings/{finding_id}/triage",
                        "remote-ai-off-new-admission",
                    ),
                    runtime,
                    db,
                )
        enqueue.assert_not_called()
        assert blocked.value.status_code == 409
        assert blocked.value.detail == ADVISOR_DISABLED_DETAIL

    with runtime.session_factory() as db:
        finding_after = db.get(Finding, finding_id)
        assert finding_after is not None
        assert finding_after.revision == before_revision
        assert db.query(Job).count() == 0


@pytest.mark.parametrize(
    ("job_kind", "job_payload"),
    [
        (
            "advisor",
            {"v": 1, "operation": "advisor", "finding_ids": [1]},
        ),
        (
            "scan",
            {"v": 1, "operation": "scan", "use_ai": True},
        ),
    ],
    ids=["advisor-job", "ai-bearing-scan-job"],
)
def test_postgresql_ai_mode_off_writer_serializes_ai_job_retry(
    postgres_engine,
    job_kind: str,
    job_payload: dict[str, object],
) -> None:
    Base.metadata.create_all(postgres_engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL=str(postgres_engine.url),
            KODESEC_ALLOWED_ROOTS="/workspace",
        ),
        engine=postgres_engine,
    )
    expected_checkpoint = (
        {"completed_finding_ids": []}
        if job_kind == "advisor"
        else {"completed_scanner_ids": []}
    )
    with runtime.session_factory() as db, db.begin():
        failed = Job(
            kind=job_kind,
            title=f"Serialized failed AI-bearing {job_kind}",
            status="failed",
            stage="failed",
            payload=job_payload,
            checkpoint=deepcopy(expected_checkpoint),
            attempt=1,
            max_attempts=3,
            revision=3,
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([failed, RuntimeConfig(key="ai_mode", value="on")])
        db.flush()
        job_id = failed.id

    writer_holds_lock = Event()
    release_writer = Event()
    retry_attempted_lock = Event()

    def observe_advisor_lock(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        if (
            current_thread().name.startswith("ai-job-retry")
            and "pg_advisory_xact_lock" in statement
        ):
            retry_attempted_lock.set()

    def write_ai_off() -> None:
        with runtime.session_factory() as db, db.begin():
            lock_advisor_admission(db)
            config = db.get(RuntimeConfig, "ai_mode")
            assert config is not None
            config.value = "off"
            db.flush()
            writer_holds_lock.set()
            assert release_writer.wait(10), "AI-off writer was not released"

    def retry_after_ai_off() -> tuple[int, object]:
        with runtime.session_factory() as db:
            with pytest.raises(HTTPException) as blocked:
                retry_job(
                    job_id,
                    JobRetryRequest(expected_revision=3),
                    runtime,
                    db,
                )
            return blocked.value.status_code, blocked.value.detail

    event.listen(postgres_engine, "before_cursor_execute", observe_advisor_lock)
    try:
        with (
            ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="ai-off-writer"
            ) as writer_pool,
            ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="ai-job-retry"
            ) as retry_pool,
        ):
            writer_future = writer_pool.submit(write_ai_off)
            try:
                assert writer_holds_lock.wait(
                    10
                ), "AI-off writer did not hold admission lock"
                retry_future = retry_pool.submit(retry_after_ai_off)
                assert retry_attempted_lock.wait(
                    10
                ), "AI job retry did not attempt admission lock"
                assert not retry_future.done(), (
                    "AI job retry bypassed the shared admission lock"
                )
                release_writer.set()
                writer_future.result(timeout=10)
                assert retry_future.result(timeout=10) == (409, ADVISOR_DISABLED_DETAIL)
            finally:
                release_writer.set()
    finally:
        release_writer.set()
        event.remove(postgres_engine, "before_cursor_execute", observe_advisor_lock)

    with runtime.session_factory() as db:
        config = db.get(RuntimeConfig, "ai_mode")
        persisted = db.get(Job, job_id)
        assert config is not None and config.value == "off"
        assert persisted is not None
        assert persisted.status == "failed"
        assert persisted.revision == 3
        assert persisted.attempt == 1
        assert persisted.checkpoint == expected_checkpoint
        assert db.query(Job).count() == 1


@pytest.mark.parametrize("route", ["scan", "finding", "bulk"])
def test_advisor_gui_admission_rejects_deleted_preflight_provider_without_job(
    route: str,
) -> None:
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    ready_collection = providers.update_provider_status(
        {"revision": 7, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    ready = ready_collection["providers"][0]
    pin = _triage_pin(ready_collection, ready)
    runtime, scan_id, finding_id = _triage_runtime(
        ready_collection, persist_receipt=True
    )
    with runtime.session_factory() as db, db.begin():
        deleted = providers.remove_profile(
            providers.load_collection(db, runtime.settings, lock=True),
            ready["id"],
            expected_revision=7,
        )
        providers.save_collection(db, deleted)
        providers.delete_receipt(db, ready["id"])

    with runtime.session_factory() as db, pytest.raises(HTTPException) as stale:
        if route == "scan":
            triage_scan(
                scan_id,
                ScanTriageRequest(advisor_provider_pin=pin),
                _command_request(
                    f"/v1/scans/{scan_id}/triage", "stale-scan-provider"
                ),
                runtime,
                db,
            )
        elif route == "finding":
            triage_finding(
                finding_id,
                TriageRequest(expected_revision=1, advisor_provider_pin=pin),
                _command_request(
                    f"/v1/findings/{finding_id}/triage",
                    "stale-finding-provider",
                ),
                runtime,
                db,
            )
        else:
            bulk_findings(
                FindingBulkAction(
                    finding_ids=[finding_id],
                    action="triage",
                    expected_revisions={finding_id: 1},
                    advisor_provider_pin=pin,
                ),
                _command_request("/v1/findings/bulk", "stale-bulk-provider"),
                Response(),
                runtime,
                db,
            )
    assert stale.value.status_code == 409
    assert stale.value.detail["code"] == "advisor_provider_selection_stale"
    with runtime.session_factory() as db:
        assert db.query(Job).count() == 0


@pytest.mark.parametrize("transport", ["direct", "ssh"])
def test_scan_wide_advisor_rejects_remote_exact_pin_without_job(
    transport: str,
) -> None:
    remote = providers.normalize_profile(
        _profile(f"{transport}-lab", transport=transport)
    )
    collection = {
        "revision": 3,
        "active_provider_id": None,
        "providers": [remote],
    }
    runtime, scan_id, _finding_id = _triage_runtime(
        collection, persist_receipt=False
    )
    with runtime.session_factory() as db, pytest.raises(HTTPException) as blocked:
        triage_scan(
            scan_id,
            ScanTriageRequest(
                advisor_provider_pin=_triage_pin(collection, remote)
            ),
            _command_request(
                f"/v1/scans/{scan_id}/triage", f"remote-{transport}-scan"
            ),
            runtime,
            db,
        )
    assert blocked.value.status_code == 409
    assert blocked.value.detail["code"] == "advisor_remote_single_finding_required"
    assert blocked.value.detail["safe_details"]["transport"] == transport
    with runtime.session_factory() as db:
        assert db.query(Job).count() == 0


def test_scan_wide_advisor_rejects_unavailable_local_without_job() -> None:
    local = providers.normalize_profile(
        _profile("local-lab", transport="local")
    )
    available = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [local]},
        local["id"],
        status="available",
        reason=None,
        reason_code=None,
        remediation="none",
    )
    current = available["providers"][0]
    runtime, scan_id, _finding_id = _triage_runtime(
        available, persist_receipt=False
    )
    with runtime.session_factory() as db, pytest.raises(HTTPException) as blocked:
        triage_scan(
            scan_id,
            ScanTriageRequest(
                advisor_provider_pin=_triage_pin(available, current)
            ),
            _command_request(
                f"/v1/scans/{scan_id}/triage", "unavailable-local-scan"
            ),
            runtime,
            db,
        )
    assert blocked.value.status_code == 409
    assert blocked.value.detail["code"] == "advisor_provider_not_executable"
    with runtime.session_factory() as db:
        assert db.query(Job).count() == 0


def test_public_remote_activation_is_not_claimed_executable() -> None:
    settings = SimpleNamespace(
        advisor_direct_host_list=frozenset({FIXTURE_HOST}),
        advisor_ssh_provider_id_list=frozenset(),
    )
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 3, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        reason_code=None,
        remediation="none",
        activate=True,
        approve_content_disclosure=True,
    )
    current = active["providers"][0]
    consent = providers.build_consent(active, current["id"])
    receipt = _receipt(current)
    public = providers.public_collection(
        active,
        settings,
        {current["id"]: consent},
        {current["id"]: receipt},
    )
    assert public["providers"][0]["status"] == "active"
    assert public["providers"][0]["eligible"] is False
    assert (
        public["providers"][0]["reason_code"]
        == "remote_single_finding_confirmation_required"
    )
    assert public["resolution"] == {
        "provider_id": None,
        "transport": "unavailable",
        "reason": "remote_single_finding_confirmation_required",
        "eligible_provider_ids": [],
    }


def test_worker_liveness_uses_durable_remote_receipt_without_remote_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = providers.normalize_profile(_profile())
    active = providers.update_provider_status(
        {"revision": 1, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    profile = active["providers"][0]
    consent = providers.build_consent(active, profile["id"])
    receipt = providers.normalize_receipt(
        {
            "schema": "lomo-advisor-provider-receipt/v1",
            "provider_id": profile["id"],
            "kind": "direct",
            "route": "direct",
            "model": profile["model"],
            "model_digest": profile["model_digest"],
            "status": "ready",
            "tested_at": "2026-08-25T12:00:00Z",
            "revision": profile["config_revision"],
        }
    )
    monkeypatch.setattr(
        "kodesec_api.jobs.advisor.test_provider_sync",
        lambda *_args, **_kwargs: pytest.fail("remote liveness must not make a probe"),
    )
    config = {
        "ai_mode": "on",
        "advisor_providers": active,
        "advisor_provider_consents": {profile["id"]: consent},
        "advisor_provider_receipts": {profile["id"]: receipt},
    }
    settings = SimpleNamespace(
        advisor_direct_host_list=frozenset({FIXTURE_HOST}),
        advisor_ssh_provider_id_list=frozenset(),
    )
    assert worker_ollama_available_sync(
        config, timeout=2, settings=settings
    ) == (False, [], "remote_single_finding_confirmation_required")
    assert worker_ollama_available_sync(
        config | {"advisor_provider_consents": {}},
        timeout=2,
        settings=settings,
    ) == (False, [], "activation_required")


def test_provider_receipt_is_exact_bounded_and_preserves_observed_time() -> None:
    observed = "2026-08-25T10:11:12.123Z"
    receipt = providers.normalize_receipt(
        {
            "schema": "lomo-advisor-provider-receipt/v1",
            "provider_id": "direct-lab",
            "kind": "direct",
            "route": "direct",
            "model": FIXTURE_MODEL,
            "model_digest": DIGEST,
            "status": "ready",
            "tested_at": observed,
            "revision": 4,
        }
    )
    assert receipt["tested_at"] == observed
    assert set(receipt) == {
        "schema",
        "provider_id",
        "kind",
        "route",
        "model",
        "model_digest",
        "status",
        "tested_at",
        "revision",
    }
    with pytest.raises(ValueError):
        providers.normalize_receipt(receipt | {"endpoint": "http://secret.invalid"})


def test_problem_detail_accepts_only_allowlisted_safe_details() -> None:
    result = _problem_detail(
        "source_outside_allowed_root",
        "Outside boundary",
        correlation_id="request:abc-123",
        safe_details={
            "selected_source": "/work/other",
            "configured_source_boundary": "/work/source",
        },
    )
    assert result["correlation_id"] == "request:abc-123"
    assert result["safe_details"]["configured_source_boundary"] == "/work/source"
    with pytest.raises(ValueError):
        ProblemDetail(
            code="bad_request",
            message="bad",
            safe_details={"headers": "Authorization: secret"},
        )


def _connector_module():
    path = (
        Path(__file__).resolve().parents[3]
        / "services"
        / "advisor_connector"
        / "app.py"
    )
    spec = importlib.util.spec_from_file_location("advisor_connector_test_app", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _local_generation_document(connector, profile, payload):
    connector.GRANT_SECRET = GRANT_SECRET
    grant = grants.mint_local_operation_grant(GRANT_SECRET, profile, payload["prompt"])
    document = {"provider": profile, "request": payload, "confirmation": None, "grant": grant}
    admitted = TestClient(connector.app).post("/v1/operations", json=document)
    assert admitted.status_code == 200, admitted.text
    return document


@pytest.mark.parametrize(
    ("code", "retryable"),
    [
        ("advisor_provider_local_unavailable", True),
        ("advisor_provider_unreachable", True),
        ("advisor_provider_timeout", True),
        ("advisor_provider_http_status", True),
        ("advisor_provider_tags_invalid", False),
        ("advisor_provider_model_missing", False),
        ("advisor_provider_digest_mismatch", False),
        ("advisor_provider_local_weights_required", False),
        ("advisor_provider_ssh_authorization_failed", False),
        ("advisor_provider_ssh_tunnel_failed", True),
        ("advisor_provider_direct_authorization_required", False),
        ("advisor_connector_unavailable", True),
    ],
)
def test_provider_test_failure_contract_is_typed_bounded_and_retry_aware(
    code: str, retryable: bool
) -> None:
    message, expected_retryable = providers.provider_test_failure(code)
    encoded = json.dumps(
        {"detail": {"code": code, "message": message}},
        separators=(",", ":"),
    ).encode("utf-8")
    connector_failure = advisor_jobs._connector_failure(503, encoded)
    assert connector_failure.code == code
    assert connector_failure.safe_detail == message
    assert connector_failure.retryable is retryable is expected_retryable
    durable_failure = advisor_jobs.ProviderTestFailure(503, code)
    assert durable_failure.code == code
    assert durable_failure.safe_detail == message
    assert durable_failure.retryable is retryable
    assert "http://" not in message
    assert "@" not in message


def test_connector_rejects_untyped_or_modified_failure_text() -> None:
    untyped = advisor_jobs._connector_failure(
        503, b'{"detail":"connection refused at a private endpoint"}'
    )
    modified = advisor_jobs._connector_failure(
        503,
        json.dumps(
            {
                "detail": {
                    "code": "advisor_provider_unreachable",
                    "message": "private endpoint and credential text",
                }
            }
        ).encode("utf-8"),
    )
    assert untyped.code == "advisor_connector_protocol"
    assert modified.code == "advisor_connector_protocol"
    assert untyped.safe_detail == modified.safe_detail


@pytest.mark.parametrize(
    ("case", "expected_code"),
    [
        ("declared_size", "advisor_generation_response_too_large"),
        ("streamed_size", "advisor_generation_response_too_large"),
        ("redirect", "advisor_generation_response_invalid"),
        ("invalid_json", "advisor_generation_json_invalid"),
        ("duplicate_json", "advisor_generation_json_invalid"),
        ("non_object", "advisor_generation_response_invalid"),
        ("http_status", "advisor_provider_http_status"),
        ("timeout", "advisor_provider_timeout"),
        ("network", "advisor_provider_unreachable"),
    ],
)
def test_generation_transport_failures_keep_only_canonical_diagnostics(
    case: str, expected_code: str,
) -> None:
    connector = _connector_module()
    private_canary = "private-prompt-must-not-escape"

    def handler(request: httpx.Request) -> httpx.Response:
        if case == "timeout":
            raise httpx.ReadTimeout(private_canary, request=request)
        if case == "network":
            raise httpx.ConnectError(private_canary, request=request)
        body = {
            "declared_size": b"x" * 129,
            "streamed_size": b"x" * 129,
            "invalid_json": private_canary.encode(),
            "duplicate_json": b'{"response":1,"response":2}',
            "non_object": b"[]",
        }.get(case, private_canary.encode())
        return httpx.Response(
            302 if case == "redirect" else 502 if case == "http_status" else 200,
            content=body,
            headers={"content-length": "0"} if case == "streamed_size" else {},
        )

    async def execute() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await connector._bounded_json_response(
                client, "POST", "http://fixture.invalid/api/generate",
                maximum=128, total_seconds=2.0, json_body={"prompt": private_canary},
            )

    with pytest.raises(HTTPException) as failure:
        asyncio.run(execute())
    encoded = json.dumps({"detail": failure.value.detail}).encode()
    preserved = advisor_jobs._connector_failure(failure.value.status_code, encoded)
    assert preserved.code == expected_code
    assert preserved.safe_detail == providers.provider_test_failure(expected_code)[0]
    assert private_canary not in encoded.decode()
    assert "fixture.invalid" not in encoded.decode()


@pytest.mark.parametrize(
    ("change", "expected_code"),
    [
        ({"private_extra": "must-not-escape"}, "advisor_generation_response_invalid"),
        ({"model": "wrong-model"}, "advisor_generation_model_mismatch"),
        ({"done": False}, "advisor_generation_incomplete"),
        ({"response": ""}, "advisor_generation_text_invalid"),
        ({"response": "x" * (16 * 1024 + 1)}, "advisor_generation_text_invalid"),
        ({"created_at": "unsafe\x00"}, "advisor_generation_response_invalid"),
        ({"thinking": True}, "advisor_generation_response_invalid"),
        ({"context": [True]}, "advisor_generation_response_invalid"),
        ({"eval_count": True}, "advisor_generation_response_invalid"),
        ({"response": "private-incomplete-json{"}, "advisor_generation_output_json_invalid"),
        ({"response": '{"verdict":1,"verdict":2}'}, "advisor_generation_output_json_invalid"),
        ({"response": "{}"}, "advisor_generation_output_schema_invalid"),
        ({"response": '{"verdict":"needs_review","confidence":true,"reasoning":"r","fix":"f"}'},
         "advisor_generation_output_schema_invalid"),
    ],
)
def test_generation_validation_failures_preserve_strict_boundaries_and_typed_phase(
    change: dict[str, object], expected_code: str,
) -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    valid = {
        "model": FIXTURE_MODEL, "done": True,
        "response": json.dumps({
            "verdict": "needs_review", "confidence": 0.5,
            "reasoning": "Synthetic review", "fix": "Synthetic fix",
        }),
    }
    assert connector._validate_model_response(valid, profile) == valid["response"]
    with pytest.raises(HTTPException) as failure:
        connector._validate_model_response(valid | change, profile)
    preserved = advisor_jobs._connector_failure(
        failure.value.status_code, json.dumps({"detail": failure.value.detail}).encode(),
    )
    assert preserved.code == expected_code
    assert preserved.retryable is False
    assert preserved.safe_detail == providers.provider_test_failure(expected_code)[0]
    assert "private" not in preserved.safe_detail


def test_generation_accepts_documented_cached_count_with_strict_metric_bounds() -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    response = {
        "model": FIXTURE_MODEL,
        "created_at": "2026-09-07T17:00:00Z",
        "response": json.dumps({
            "verdict": "needs_review", "confidence": 0.5,
            "reasoning": "Synthetic review", "fix": "Synthetic fix",
        }),
        "done": True,
        "done_reason": "stop",
        "context": [1, 2, 3],
        "total_duration": 100,
        "load_duration": 10,
        "prompt_eval_count": 20,
        "prompt_eval_cached_count": 5,
        "prompt_eval_duration": 10,
        "eval_count": 30,
        "eval_duration": 80,
    }
    # Official Ollama GenerateResponse/Metrics includes this optional *int.
    # https://docs.ollama.com/api/generate
    for count in (None, 0, 5, 2**63 - 1):
        assert connector._validate_model_response(
            response | {"prompt_eval_cached_count": count}, profile,
        ) == response["response"]
    assert connector._validate_model_response(
        {key: value for key, value in response.items() if key != "prompt_eval_cached_count"},
        profile,
    ) == response["response"]
    for count in (-1, True, "5", 1.5, 2**63):
        with pytest.raises(HTTPException) as failure:
            connector._validate_model_response(
                response | {"prompt_eval_cached_count": count}, profile,
            )
        assert failure.value.detail["code"] == "advisor_generation_response_invalid"
    with pytest.raises(HTTPException) as unknown:
        connector._validate_model_response(response | {"unreviewed_metric": 1}, profile)
    assert unknown.value.detail["code"] == "advisor_generation_response_invalid"


@pytest.mark.parametrize(
    ("code", "retryable"),
    [("advisor_generation_output_json_invalid", False), ("advisor_provider_timeout", True)],
)
def test_local_generation_failure_reaches_worker_with_checkpoint_and_retryability(
    monkeypatch: pytest.MonkeyPatch, code: str, retryable: bool,
) -> None:
    local = providers.normalize_profile(_profile("local-lab", transport="local"))
    ready = providers.update_provider_status(
        {"revision": 1, "active_provider_id": None, "providers": [local]},
        local["id"], status="available", reason=None,
    )
    runtime, scan_id, finding_id = _triage_runtime(ready, persist_receipt=True)
    with runtime.session_factory() as db:
        queued = triage_scan(
            scan_id, ScanTriageRequest(advisor_provider_pin=_triage_pin(ready, ready["providers"][0])),
            _command_request(f"/v1/scans/{scan_id}/triage", "typed-generation-failure"),
            runtime, db,
        )
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, queued["id"])
        job.status = "leased"
        job.attempt = 1
        job.lease_owner = "typed-generation-worker"
        job.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        job.heartbeat_at = datetime.now(timezone.utc)
        db.flush()
        claimed = ClaimedJob.from_model(job)

    def failed_triage(*_args: object, **_kwargs: object) -> None:
        raise advisor_jobs.ConnectorRequestError(502, code)

    monkeypatch.setattr(advisor_jobs, "triage_finding_sync", failed_triage)
    executor = WorkerExecutor(runtime, "typed-generation-worker")
    checkpoint = {"advisor_completed": []}
    with pytest.raises(JobExecutionError) as failed:
        executor._triage_scan_findings(
            claimed, SimpleNamespace(raise_if_unusable=lambda: None), checkpoint,
            automatic=False,
        )
    assert failed.value.code == code
    assert failed.value.retryable is retryable
    assert failed.value.detail == providers.provider_test_failure(code)[0] + " 0/1 completed reviews were preserved."
    assert checkpoint == {"advisor_completed": []}
    with patch("kodesec_api.jobs.repository._time", return_value=datetime.now(timezone.utc)):
        executor._fail(claimed, failed.value)
    with runtime.session_factory() as db:
        job = db.get(Job, queued["id"])
        assert job.error_code == code
        assert job.error_detail == failed.value.detail
        assert job.status == ("queued" if retryable else "failed")
        finding = db.get(Finding, finding_id)
        assert finding.revision == 1 and finding.ai_verdict is None
    runtime.engine.dispose()


@pytest.mark.parametrize(
    ("tags", "expected_code"),
    [
        ({"models": "not-a-list"}, "advisor_provider_tags_invalid"),
        ({"models": []}, "advisor_provider_model_missing"),
        (
            {"models": [{"name": FIXTURE_MODEL, "digest": "b" * 64, "size": 1000}]},
            "advisor_provider_digest_mismatch",
        ),
    ],
)
def test_connector_distinguishes_model_catalog_failures(
    monkeypatch: pytest.MonkeyPatch,
    tags: dict[str, object],
    expected_code: str,
) -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))

    async def response(*_args: object, **_kwargs: object) -> dict[str, object]:
        return tags

    monkeypatch.setattr(connector, "_bounded_json_response", response)
    with pytest.raises(connector.HTTPException) as failure:
        asyncio.run(connector._test(profile))
    assert failure.value.detail == {
        "code": expected_code,
        "message": providers.provider_test_failure(expected_code)[0],
    }


def test_dedicated_local_catalog_lists_local_weights_and_cloud_stubs_without_a_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    observed: list[tuple[str, str]] = []

    async def response(_client: object, method: str, url: str, **_kwargs: object) -> dict[str, object]:
        observed.append((method, url))
        return {
            "models": [
                {
                    "name": "minimax-m3:cloud",
                    "digest": "b" * 64,
                    "size": 301,
                    "remote_model": "minimax-m3",
                    "remote_host": "https://ollama.com",
                },
                {"name": "qwen3:8b", "digest": "a" * 64, "size": 5_200_000_000},
            ]
        }

    monkeypatch.setattr(connector, "LOCAL_URL", "http://host.docker.internal:11434")
    monkeypatch.setattr(connector, "_bounded_json_response", response)
    client = TestClient(connector.app)
    catalog = client.post("/v1/local-models", json={})
    assert catalog.status_code == 200, catalog.text
    assert catalog.json() == {
        "schema": "lomo-advisor-local-catalog/v1",
        "source": "dedicated_local_connector",
        "models": [
            {
                "name": "qwen3:8b",
                "digest": "a" * 64,
                "size_bytes": 5_200_000_000,
                "storage": "local_weights",
            },
            {
                "name": "minimax-m3:cloud",
                "digest": "b" * 64,
                "size_bytes": 301,
                "storage": "cloud_stub",
            },
        ],
        "recommended_model": "qwen3:8b",
    }
    assert observed == [("GET", "http://host.docker.internal:11434/api/tags")]
    assert client.post(
        "/v1/local-models", json={"base_url": f"http://{FIXTURE_HOST}:11434"}
    ).status_code == 422
    monkeypatch.setattr(connector, "LOCAL_URL", f"http://{FIXTURE_HOST}:11434")
    misconfigured = client.post("/v1/local-models", json={})
    assert misconfigured.status_code == 500
    assert misconfigured.json()["detail"]["code"] == "advisor_provider_route_misconfigured"
    assert observed == [("GET", "http://host.docker.internal:11434/api/tags")]


@pytest.mark.parametrize("endpoint", ["/v1/test", "/v1/generate"])
@pytest.mark.parametrize(
    ("metadata", "expected_code"),
    [
        ({"size": 1000}, None),
        (
            {"size": 300, "remote_model": "cloud-model", "remote_host": "https://ollama.com"},
            "advisor_provider_local_weights_required",
        ),
        ({"size": 300, "remote_model": "cloud-model"}, "advisor_provider_local_weights_required"),
        ({"size": 300, "remote_host": "https://ollama.com"}, "advisor_provider_local_weights_required"),
        ({}, "advisor_provider_tags_invalid"),
        ({"size": 0}, "advisor_provider_tags_invalid"),
        ({"size": True}, "advisor_provider_tags_invalid"),
    ],
)
def test_connector_local_provider_verifies_storage_before_readiness_or_generation(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    metadata: dict[str, object],
    expected_code: str | None,
) -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    calls: list[tuple[str, str]] = []
    request_payload = advisor_jobs._ollama_payload(
        "bounded synthetic finding", str(profile["model"]), False
    )

    async def response(
        _client: object, method: str, url: str, **kwargs: object
    ) -> dict[str, object]:
        calls.append((method, url))
        if method == "GET":
            assert url == "http://host.docker.internal:11434/api/tags"
            return {"models": [
                {"name": FIXTURE_MODEL, "digest": DIGEST, **metadata},
                {
                    "name": "unselected-model:cloud", "digest": "b" * 64,
                    "size": 300, "remote_model": "unselected-model",
                    "remote_host": "https://ollama.com",
                },
            ]}
        assert expected_code is None, "Local preflight must reject before any prompt POST"
        assert method == "POST"
        assert url == "http://host.docker.internal:11434/api/generate"
        assert kwargs["json_body"] == request_payload
        return {
            "model": FIXTURE_MODEL,
            "response": json.dumps({
                "verdict": "needs_review", "confidence": 0.5,
                "reasoning": "Synthetic local result", "fix": "Review synthetic fixture",
            }),
            "done": True,
        }

    monkeypatch.setattr(connector, "LOCAL_URL", "http://host.docker.internal:11434")
    monkeypatch.setattr(connector, "_bounded_json_response", response)
    document: dict[str, object] = {"provider": profile}
    if endpoint == "/v1/generate":
        document = _local_generation_document(connector, profile, request_payload)
    result = TestClient(connector.app).post(endpoint, json=document)
    if expected_code is not None:
        assert result.status_code == (409 if expected_code == "advisor_provider_local_weights_required" else 502)
        assert result.json() == {"detail": {
            "code": expected_code,
            "message": providers.provider_test_failure(expected_code)[0],
        }}
        assert calls == [("GET", "http://host.docker.internal:11434/api/tags")]
    else:
        assert result.status_code == 200, result.text
        if endpoint == "/v1/test":
            receipt = result.json()["receipt"]
            assert receipt["status"] == "ready"
            assert receipt["route"] == "local"
            assert receipt["model_digest"] == DIGEST
            assert calls == [("GET", "http://host.docker.internal:11434/api/tags")]
        else:
            assert result.json()["done"] is True
            assert calls == [
                ("GET", "http://host.docker.internal:11434/api/tags"),
                ("POST", "http://host.docker.internal:11434/api/generate"),
                ("GET", "http://host.docker.internal:11434/api/tags"),
            ]


def test_local_catalog_api_rejects_contradictory_connector_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_ADVISOR_GRANT_SECRET=GRANT_SECRET,
    )

    async def valid(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "schema": "lomo-advisor-local-catalog/v1",
            "source": "dedicated_local_connector",
            "models": [{
                "name": "qwen3:8b",
                "digest": "a" * 64,
                "size_bytes": 5_200_000_000,
                "storage": "local_weights",
            }],
            "recommended_model": "qwen3:8b",
        }

    monkeypatch.setattr(advisor_jobs, "_connector_json_async", valid)
    catalog = asyncio.run(advisor_jobs.detect_local_models(settings))
    assert catalog["recommended_model"] == "qwen3:8b"
    assert catalog["models"][0]["digest"] == "a" * 64

    async def contradictory(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            **catalog,
            "models": [{
                **catalog["models"][0],
                "size_bytes": 0,
                "storage": "local_weights",
            }],
        }

    monkeypatch.setattr(advisor_jobs, "_connector_json_async", contradictory)
    with pytest.raises(advisor_jobs.ConnectorRequestError) as failure:
        asyncio.run(advisor_jobs.detect_local_models(settings))
    assert failure.value.code == "advisor_connector_protocol"

    async def unsafe_json_integer(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            **catalog,
            "models": [{
                **catalog["models"][0],
                "size_bytes": 9_007_199_254_740_992,
            }],
        }

    monkeypatch.setattr(advisor_jobs, "_connector_json_async", unsafe_json_integer)
    with pytest.raises(advisor_jobs.ConnectorRequestError) as unsafe_size:
        asyncio.run(advisor_jobs.detect_local_models(settings))
    assert unsafe_size.value.code == "advisor_connector_protocol"

    async def connector_down(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise HTTPException(503, "internal connector request failed")

    monkeypatch.setattr(advisor_jobs, "_connector_json_async", connector_down)
    with pytest.raises(advisor_jobs.ConnectorRequestError) as unavailable:
        asyncio.run(advisor_jobs.detect_local_models(settings))
    assert unavailable.value.code == "advisor_connector_unavailable"
    assert unavailable.value.safe_detail == providers.provider_test_failure(
        "advisor_connector_unavailable"
    )[0]


def test_local_catalog_route_preserves_worker_owned_typed_detection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SimpleNamespace(
        settings=SimpleNamespace(
            worker_liveness_seconds=10.0,
            scanner_url="http://scanner:8091",
        )
    )
    db = SimpleNamespace(execute=lambda *_args, **_kwargs: None, rollback=lambda: None)
    active_config = {
        "ai_mode": "auto",
        "ollama_base_url": "http://host.docker.internal:11434",
        "ollama_model": "qwen3:8b",
        "ollama_thinking": False,
    }
    monkeypatch.setattr(
        "kodesec_api.main._runtime_config_values",
        lambda *_args, **_kwargs: active_config,
    )
    monkeypatch.setattr(
        "kodesec_api.main.fresh_worker_id",
        lambda *_args, **_kwargs: "worker-fixture",
    )
    monkeypatch.setattr(
        "kodesec_api.main.worker_advisor_status",
        lambda *_args, **_kwargs: (False, [], "advisor_connector_unavailable"),
    )
    monkeypatch.setattr(
        "kodesec_api.main.worker_advisor_catalog",
        lambda *_args, **_kwargs: (None, "advisor_provider_local_unavailable"),
    )

    class HealthyScannerResponse:
        status_code = 200

    class HealthyScannerClient:
        def __init__(self, *, timeout, trust_env):
            assert timeout == 1.5
            assert trust_env is False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url):
            assert url == "http://scanner:8091/healthz"
            return HealthyScannerResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", HealthyScannerClient)
    core = healthz(runtime, db)
    assert core["ok"] is True
    assert core["ai"]["available"] is False
    assert core["ai"]["reason"] == "advisor_connector_unavailable"

    with pytest.raises(HTTPException) as failure:
        list_local_advisor_models(runtime, db)
    assert failure.value.status_code == 503
    assert failure.value.detail == {
        "code": "advisor_provider_local_unavailable",
        "message": providers.provider_test_failure(
            "advisor_provider_local_unavailable"
        )[0],
        "action": "retry_local_advisor_detection",
        "context": {},
        "safe_details": {"reason_code": "advisor_provider_local_unavailable"},
    }


def test_connector_rejects_extra_profile_fields_and_remote_unconfirmed_generate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    client = TestClient(connector.app)
    profile = providers.normalize_profile(_profile())
    extra = client.post("/v1/test", json={"provider": profile | {"identity_file": "/secret"}})
    assert extra.status_code == 422

    monkeypatch.setattr(connector, "_validate_generate_request", lambda value, profile: value)
    missing = client.post(
        "/v1/generate", json={"provider": profile, "request": {}}
    )
    assert missing.status_code == 422
    denied = client.post(
        "/v1/generate",
        json={"provider": profile, "request": {}, "confirmation": None, "grant": None},
    )
    assert denied.status_code == 409
    assert "exact disclosure confirmation" in denied.json()["detail"]


def test_connector_sends_only_the_prompt_bound_to_one_remote_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    client = TestClient(connector.app)
    profile = providers.normalize_profile(_profile())
    collection = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    profile = collection["providers"][0]
    consent = providers.build_consent(collection, profile["id"])
    packet = {
        "finding": {"display_id": "S1-F001", "message": "bounded fixture"},
        "scanner_evidence": {"code_snippet": "eval(user_input)\n"},
    }
    confirmation = disclosure.build_confirmation(
        collection,
        profile,
        consent,
        finding_id=1,
        finding_revision=1,
        packet=packet,
        signing_key=INSTALLATION_SECRET,
    )
    prompt = disclosure.triage_prompt(packet)
    request_payload = advisor_jobs._ollama_payload(
        prompt, str(profile["model"]), False
    )
    execution_grant = grants.mint_execution_grant(
        GRANT_SECRET, profile, confirmation, prompt
    )
    sends: list[dict[str, object]] = []

    async def ready(_profile: dict[str, object]) -> dict[str, object]:
        return {"status": "ready"}

    async def generate_response(
        _client: object,
        _method: str,
        _url: str,
        *,
        json_body: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        sends.append(json_body)
        return {
            "model": profile["model"],
            "response": json.dumps(
                {
                    "verdict": "needs_review",
                    "confidence": 0.5,
                    "reasoning": "bounded result",
                    "fix": "bounded fix",
                }
            ),
            "done": True,
        }

    monkeypatch.setattr(connector, "DIRECT_HOSTS", frozenset({FIXTURE_HOST}))
    monkeypatch.setattr(connector, "GRANT_SECRET", GRANT_SECRET)
    connector._USED_GRANTS.clear()
    connector._OPERATIONS.clear()
    monkeypatch.setattr(connector, "_test", ready)
    monkeypatch.setattr(connector, "_bounded_json_response", generate_response)
    document = {
        "provider": profile,
        "request": request_payload,
        "confirmation": confirmation,
        "grant": execution_grant,
    }
    admitted = client.post("/v1/operations", json=document)
    assert admitted.status_code == 200
    assert admitted.json() == {
        "operation_id": execution_grant["nonce"],
        "status": "admitted",
    }
    response = client.post("/v1/generate", json=document)
    assert response.status_code == 200
    assert sends == [request_payload]

    cancelled_grant = grants.mint_execution_grant(
        GRANT_SECRET, profile, confirmation, prompt
    )
    cancelled_document = {**document, "grant": cancelled_grant}
    cancelled_admission = client.post("/v1/operations", json=cancelled_document)
    assert cancelled_admission.status_code == 200
    cancellation_grant = grants.mint_cancellation_grant(
        GRANT_SECRET,
        profile,
        confirmation,
        cancelled_grant["nonce"],
    )
    cancelled = client.post(
        "/v1/cancel", json={"cancellation_grant": cancellation_grant}
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {
        "operation_id": cancelled_grant["nonce"],
        "status": "cancelled",
        "cleanup": "confirmed",
    }
    rejected_after_cancel = client.post("/v1/generate", json=cancelled_document)
    assert rejected_after_cancel.status_code == 409
    assert sends == [request_payload]

    replayed = client.post("/v1/operations", json=document)
    assert replayed.status_code == 409
    assert "already used" in replayed.json()["detail"]
    assert sends == [request_payload]

    changed_prompt = {**request_payload, "prompt": f"{prompt}\nextra"}
    blocked = client.post(
        "/v1/operations",
        json={
            "provider": profile,
            "request": changed_prompt,
            "confirmation": confirmation,
            "grant": execution_grant,
        },
    )
    assert blocked.status_code == 409
    assert sends == [request_payload]

    forged = grants.mint_execution_grant(
        "attacker-controlled-secret-" * 3,
        profile,
        confirmation,
        prompt,
    )
    rejected = client.post(
        "/v1/operations",
        json={
            "provider": profile,
            "request": request_payload,
            "confirmation": confirmation,
            "grant": forged,
        },
    )
    assert rejected.status_code == 409
    assert "execution grant is invalid" in rejected.json()["detail"]
    assert sends == [request_payload]


def test_connector_authenticated_cancel_acknowledges_ssh_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("ssh-lab", transport="ssh"))
    collection = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    profile = collection["providers"][0]
    consent = providers.build_consent(collection, profile["id"])
    packet = {
        "finding": {"display_id": "S1-F001", "message": "bounded fixture"},
        "scanner_evidence": {"code_snippet": "eval(user_input)\n"},
    }
    confirmation = disclosure.build_confirmation(
        collection,
        profile,
        consent,
        finding_id=1,
        finding_revision=1,
        packet=packet,
        signing_key=INSTALLATION_SECRET,
    )
    prompt = disclosure.triage_prompt(packet)
    request_payload = advisor_jobs._ollama_payload(prompt, str(profile["model"]), False)
    grant = grants.mint_execution_grant(GRANT_SECRET, profile, confirmation, prompt)
    body = json.dumps(
        {
            "provider": profile,
            "request": request_payload,
            "confirmation": confirmation,
            "grant": grant,
        }
    ).encode("utf-8")

    async def scenario() -> None:
        sent = asyncio.Event()
        tunnel_opened = asyncio.Event()
        tunnel_closed = asyncio.Event()
        provider_stopped = asyncio.Event()
        generate_receive_count = 0
        keep_open = asyncio.Event()

        async def generate_receive() -> dict[str, object]:
            nonlocal generate_receive_count
            generate_receive_count += 1
            if generate_receive_count == 1:
                return {"type": "http.request", "body": body, "more_body": False}
            await keep_open.wait()
            return {"type": "http.disconnect"}

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/generate",
                "headers": [(b"content-length", str(len(body)).encode("ascii"))],
                "query_string": b"",
            },
            receive=generate_receive,
        )

        async def ready(_profile: dict[str, object]) -> dict[str, object]:
            return {"status": "ready"}

        @asynccontextmanager
        async def tunnel(_profile: dict[str, object]):
            tunnel_opened.set()
            try:
                yield "http://127.0.0.1:31337"
            finally:
                tunnel_closed.set()

        async def blocked_provider(*_args: object, **_kwargs: object) -> dict[str, object]:
            sent.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                provider_stopped.set()
                raise

        monkeypatch.setattr(connector, "GRANT_SECRET", GRANT_SECRET)
        connector._USED_GRANTS.clear()
        connector._OPERATIONS.clear()
        monkeypatch.setattr(connector, "_test", ready)
        monkeypatch.setattr(connector, "_provider_url", tunnel)
        monkeypatch.setattr(connector, "_bounded_json_response", blocked_provider)

        admission_receive_count = 0

        async def admission_receive() -> dict[str, object]:
            nonlocal admission_receive_count
            admission_receive_count += 1
            return {"type": "http.request", "body": body, "more_body": False}

        admission_request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/operations",
                "headers": [(b"content-length", str(len(body)).encode("ascii"))],
                "query_string": b"",
            },
            receive=admission_receive,
        )
        admitted = await connector.admit_operation(admission_request)
        assert admitted == {"operation_id": grant["nonce"], "status": "admitted"}

        generation = asyncio.create_task(connector.generate(request))
        await sent.wait()
        cancellation_grant = grants.mint_cancellation_grant(
            GRANT_SECRET, profile, confirmation, grant["nonce"]
        )
        cancellation_body = json.dumps(
            {"cancellation_grant": cancellation_grant}
        ).encode("utf-8")
        cancel_receive_count = 0

        async def cancel_receive() -> dict[str, object]:
            nonlocal cancel_receive_count
            cancel_receive_count += 1
            return {
                "type": "http.request",
                "body": cancellation_body,
                "more_body": False,
            }

        cancel_request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/cancel",
                "headers": [
                    (b"content-length", str(len(cancellation_body)).encode("ascii"))
                ],
                "query_string": b"",
            },
            receive=cancel_receive,
        )
        receipt = await connector.cancel_operation(cancel_request)
        assert receipt == {
            "operation_id": grant["nonce"],
            "status": "cancelled",
            "cleanup": "confirmed",
        }
        with pytest.raises(connector.HTTPException) as disconnected:
            await generation
        assert disconnected.value.status_code == 499
        assert tunnel_opened.is_set()
        assert tunnel_closed.is_set()
        assert provider_stopped.is_set()

    asyncio.run(scenario())


@pytest.mark.parametrize("generation_status", [200, 499, 502])
def test_worker_waits_for_connector_cleanup_receipt_before_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    generation_status: int,
) -> None:
    cleanup_confirmed = False
    release_response = asyncio.Event()
    profile = providers.normalize_profile(_profile())
    collection = providers.update_provider_status(
        {"revision": 2, "active_provider_id": None, "providers": [profile]},
        profile["id"],
        status="active",
        reason=None,
        activate=True,
        approve_content_disclosure=True,
    )
    profile = collection["providers"][0]
    consent = providers.build_consent(collection, profile["id"])
    packet = {"finding": {"message": "bounded"}, "scanner_evidence": {}}
    confirmation = disclosure.build_confirmation(
        collection,
        profile,
        consent,
        finding_id=1,
        finding_revision=1,
        packet=packet,
        signing_key=INSTALLATION_SECRET,
    )
    prompt = disclosure.triage_prompt(packet)
    operation_id = "9" * 32
    grant = grants.mint_execution_grant(
        GRANT_SECRET,
        profile,
        confirmation,
        prompt,
        operation_id=operation_id,
    )
    document = {
        "provider": profile,
        "request": advisor_jobs._ollama_payload(prompt, str(profile["model"]), False),
        "confirmation": confirmation,
        "grant": grant,
    }

    class Response:
        is_redirect = False
        is_error = generation_status >= 400
        status_code = generation_status
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        async def aiter_bytes(self):
            await release_response.wait()
            yield (b'{"detail":"Owned generation was cancelled"}' if self.is_error
                   else b'{"response":"discarded","done":true}')

    class Stream:
        async def __aenter__(self) -> Response:
            return Response()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> Stream:
            return Stream()

    async def acknowledge_cleanup(
        _settings: Settings,
        _profile: dict[str, object],
        _confirmation: dict[str, object],
        _operation_id: str,
    ) -> dict[str, str]:
        nonlocal cleanup_confirmed
        cleanup_confirmed = True
        release_response.set()
        return {
            "operation_id": operation_id,
            "status": "cancelled",
            "cleanup": "confirmed",
        }

    def cancellation_requested() -> None:
        raise CancellationRequested("fixture cancellation")

    monkeypatch.setattr(advisor_jobs.httpx, "AsyncClient", Client)
    monkeypatch.setattr(
        advisor_jobs, "_cancel_connector_operation_async", acknowledge_cleanup
    )
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_ADVISOR_GRANT_SECRET=GRANT_SECRET,
    )
    with pytest.raises(CancellationRequested):
        asyncio.run(
            advisor_jobs._connector_json_async(
                settings,
                "/v1/generate",
                document,
                timeout=2.0,
                cancel_check=cancellation_requested,
            )
        )
    assert cleanup_confirmed is True


def test_connector_sends_no_prompt_when_model_preflight_drifts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    client = TestClient(connector.app)
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    sent = 0

    async def reject_preflight(_profile: dict[str, object]) -> None:
        raise connector.HTTPException(409, "configured model drifted")

    async def unexpected_send(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal sent
        sent += 1
        return {"response": "must-not-send", "done": True}

    monkeypatch.setattr(connector, "_validate_generate_request", lambda value, profile: value)
    monkeypatch.setattr(connector, "_test", reject_preflight)
    monkeypatch.setattr(connector, "_bounded_json_response", unexpected_send)
    response = client.post(
        "/v1/generate",
        json=_local_generation_document(connector, profile, {"prompt": "bounded drift fixture"}),
    )
    assert response.status_code == 409
    assert sent == 0


def test_connector_discards_output_when_model_digest_drifts_after_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    client = TestClient(connector.app)
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    probes = 0

    async def probe(_profile: dict[str, object]) -> dict[str, object]:
        nonlocal probes
        probes += 1
        if probes == 2:
            raise connector.HTTPException(409, "configured model drifted")
        return {"status": "ready"}

    monkeypatch.setattr(connector, "_validate_generate_request", lambda value, profile: value)
    monkeypatch.setattr(connector, "_test", probe)
    async def generate_response(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "model": profile["model"],
            "response": json.dumps(
                {
                    "verdict": "needs_review",
                    "confidence": 0.5,
                    "reasoning": "discard-this-output",
                    "fix": "discard-this-output",
                }
            ),
            "done": True,
        }

    monkeypatch.setattr(connector, "_bounded_json_response", generate_response)
    response = client.post(
        "/v1/generate",
        json=_local_generation_document(connector, profile, {"prompt": "bounded drift fixture"}),
    )
    assert response.status_code == 409
    assert "discard-this-output" not in response.text
    assert probes == 2


def test_connector_generation_concurrency_keeps_local_readiness_truthful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector_module()
    client = TestClient(connector.app)
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    remote_profile = providers.normalize_profile(
        _profile("direct-lab", transport="direct")
    )
    tested: list[str] = []

    async def ready(candidate: dict[str, object]) -> dict[str, object]:
        tested.append(str(candidate["id"]))
        return {"status": "ready"}

    monkeypatch.setattr(connector, "_test", ready)
    first = connector._generation_slot()
    next(first)
    try:
        shared = client.post("/v1/test", json={"provider": profile})
        assert shared.status_code == 200
        assert shared.json() == {"receipt": {"status": "ready"}}
        assert tested == [profile["id"]]
        remote = client.post("/v1/test", json={"provider": remote_profile})
        assert remote.status_code == 429
        assert tested == [profile["id"]]
        second = connector._generation_slot()
        with pytest.raises(connector.HTTPException) as busy:
            next(second)
        assert busy.value.status_code == 429
    finally:
        first.close()
    admitted = connector._generation_slot()
    next(admitted)
    admitted.close()


def test_connector_generate_contract_rejects_bool_numbers_and_schema_drift() -> None:
    connector = _connector_module()
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    request = {
        "model": profile["model"],
        "prompt": "bounded synthetic finding",
        "format": connector._OUTPUT_SCHEMA,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 700,
            "num_ctx": 8192,
        },
    }
    assert connector._validate_generate_request(request, profile) == request
    with pytest.raises(connector.HTTPException):
        connector._validate_generate_request(
            request | {"think": 1}, profile
        )
    with pytest.raises(connector.HTTPException):
        connector._validate_generate_request(
            request
            | {"options": request["options"] | {"num_ctx": True}},
            profile,
        )
    with pytest.raises(connector.HTTPException):
        connector._validate_generate_request(
            request
            | {"format": request["format"] | {"additionalProperties": True}},
            profile,
        )


def test_ssh_argv_is_shell_free_bounded_and_forbids_alternate_forwarding() -> None:
    source = (
        Path(__file__).resolve().parents[3]
        / "services"
        / "advisor_connector"
        / "app.py"
    ).read_text(encoding="utf-8")
    assert '"/usr/bin/ssh"' in source
    for required in (
        '"-F"',
        '"/dev/null"',
        '"-N"',
        '"-T"',
        '"BatchMode=yes"',
        '"IdentitiesOnly=yes"',
        '"StrictHostKeyChecking=yes"',
        '"ClearAllForwardings=no"',
        '"RequestTTY=no"',
        '"ConnectTimeout=5"',
        '"ServerAliveInterval=5"',
        '"ServerAliveCountMax=1"',
        '"-L"',
    ):
        assert required in source
    assert '"-R"' not in source
    assert '"-D"' not in source
    assert "shell=True" not in source
    tunnel_source = source.split("async def _ssh_tunnel", 1)[1].split(
        "async def _provider_url", 1
    )[0]
    assert "asyncio.create_subprocess_exec" in tunnel_source
    assert "subprocess.Popen" not in tunnel_source
    assert "time.sleep" not in tunnel_source


def test_ssh_authorization_requires_matching_exact_ed25519_fingerprint(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runtime = state / "runtime.env"
    runtime.write_text(
        "KODESEC_ADVISOR_DIRECT_HOSTS=\nKODESEC_ADVISOR_SSH_PROVIDER_IDS=\n",
        encoding="utf-8",
    )
    runtime.chmod(0o600)
    key_blob = b"bounded-ed25519-host-key-fixture"
    key_text = base64.b64encode(key_blob).decode("ascii")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"{FIXTURE_HOST} ssh-ed25519 {key_text}\n", encoding="utf-8"
    )
    known_hosts.chmod(0o600)
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_blob).digest()
    ).decode("ascii").rstrip("=")
    script = Path(__file__).resolve().parents[3] / "scripts" / "authorize-advisor-host.py"

    def invoke(candidate_fingerprint: str) -> subprocess.CompletedProcess[str]:
        envelope = {
            "schema": "lomo-advisor-host-authorization/v1",
            "provider_id": "ssh-lab",
            "transport": "ssh",
            "host": FIXTURE_HOST,
            "port": 22,
            "user": "ollama-forward",
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return subprocess.run(
            [sys.executable, str(script)],
            env={
                **os.environ,
                "KODESEC_STATE_DIR": str(state),
                "KODESEC_RUNTIME_ENV": str(runtime),
                "KODESEC_ADVISOR_AUTHORIZATION_B64": encoded,
                "KODESEC_ADVISOR_KNOWN_HOSTS_FILE": str(known_hosts),
                "KODESEC_ADVISOR_HOST_KEY_FINGERPRINT": candidate_fingerprint,
                "KODESEC_ADVISOR_SSH_RESTRICTIONS_ATTESTED": (
                    "I_HAVE_INSTALLED_THE_RESTRICTED_ADVISOR_KEY"
                ),
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    denied = invoke("SHA256:" + "A" * 43)
    assert denied.returncode != 0
    assert "does not match" in denied.stderr
    assert not (state / "advisor-auth" / "ssh-lab").exists()

    accepted = invoke(fingerprint)
    assert accepted.returncode == 0, accepted.stderr
    authorization_dir = state / "advisor-auth" / "ssh-lab"
    assert stat.S_IMODE(authorization_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((authorization_dir / "id_ed25519").stat().st_mode) == 0o600
    first_identity = (authorization_dir / "id_ed25519").read_bytes()
    assert first_identity.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert "Install only this generated public key" in accepted.stdout
    repeated = invoke(fingerprint)
    assert repeated.returncode == 0, repeated.stderr
    assert (authorization_dir / "id_ed25519").read_bytes() == first_identity
    assert "KODESEC_ADVISOR_SSH_PROVIDER_IDS=ssh-lab" in runtime.read_text(
        encoding="utf-8"
    )

    envelope_with_import = {
        "schema": "lomo-advisor-host-authorization/v1",
        "provider_id": "ssh-import",
        "transport": "ssh",
        "host": FIXTURE_HOST,
        "port": 22,
        "user": "ollama-forward",
        "identity_file": "/tmp/operator-key",
    }
    imported = subprocess.run(
        [sys.executable, str(script)],
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(runtime),
            "KODESEC_ADVISOR_AUTHORIZATION_B64": base64.urlsafe_b64encode(
                json.dumps(envelope_with_import, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).decode("ascii").rstrip("="),
            "KODESEC_ADVISOR_KNOWN_HOSTS_FILE": str(known_hosts),
            "KODESEC_ADVISOR_HOST_KEY_FINGERPRINT": fingerprint,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert imported.returncode != 0
    assert not (state / "advisor-auth" / "ssh-import").exists()


@pytest.mark.parametrize("mutation", ["signature", "prompt", "profile", "expired", "remote_schema", "extra"])
def test_local_operation_capability_refuses_changed_authority(mutation) -> None:
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    prompt = "bounded local test prompt"
    grant = grants.mint_local_operation_grant(GRANT_SECRET, profile, prompt, now=1000)
    assert grants.verify_local_operation_grant(GRANT_SECRET, grant, profile, prompt, now=1001) == grant
    changed = dict(grant)
    observed = 1001
    if mutation == "signature":
        changed["signature"] = "0" * 64
    elif mutation == "prompt":
        prompt += " changed"
    elif mutation == "profile":
        profile = providers.normalize_profile({**profile, "model_digest": "f" * 64})
    elif mutation == "expired":
        observed = 1120
    elif mutation == "remote_schema":
        changed["schema"] = grants.GRANT_SCHEMA
    else:
        changed["confirmation_digest"] = "f" * 64
    with pytest.raises(ValueError):
        grants.verify_local_operation_grant(GRANT_SECRET, changed, profile, prompt, now=observed)
    binding = grants.local_operation_binding(
        providers.normalize_profile(_profile("local-lab", transport="local")), grant["prompt_sha256"],
    )
    cancellation = grants.mint_local_cancellation_grant(GRANT_SECRET, binding, grant["nonce"], now=1001)
    assert grants.verify_local_cancellation_grant(GRANT_SECRET, cancellation, now=1002) == cancellation
    with pytest.raises(ValueError):
        grants.verify_cancellation_grant(GRANT_SECRET, cancellation, now=1002)
    with pytest.raises(ValueError):
        grants.verify_local_cancellation_grant(GRANT_SECRET, grant, now=1002)


def test_local_operation_requires_admission_and_cancellation_blocks_late_send(monkeypatch) -> None:
    connector = _connector_module()
    connector.GRANT_SECRET = GRANT_SECRET
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    payload = advisor_jobs._ollama_payload("bounded local fixture", profile["model"], False)
    client = TestClient(connector.app)
    sent = []

    async def unexpected_send(*args, **kwargs):
        sent.append(True)
        raise AssertionError("cancelled or unauthenticated operation must not contact a provider")

    monkeypatch.setattr(connector, "_test", unexpected_send)
    assert client.post("/v1/generate", json={
        "provider": profile, "request": payload, "confirmation": None, "grant": None,
    }).status_code == 409
    document = _local_generation_document(connector, profile, payload)
    grant = document["grant"]
    assert client.post("/v1/operations", json=document).status_code == 409
    binding = grants.local_operation_binding(profile, grant["prompt_sha256"])
    forged = grants.mint_local_cancellation_grant("another-private-test-secret-" * 3, binding, grant["nonce"])
    assert client.post("/v1/cancel", json={"cancellation_grant": forged}).status_code == 409
    receipt = client.post("/v1/cancel", json={"cancellation_grant": grants.mint_local_cancellation_grant(
        GRANT_SECRET, binding, grant["nonce"],
    )})
    assert receipt.json() == {"operation_id": grant["nonce"], "status": "cancelled", "cleanup": "confirmed"}
    assert client.post("/v1/generate", json=document).status_code == 409
    assert sent == []


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_local_connector_cancel_ack_waits_for_owned_http_cleanup(monkeypatch, cleanup_fails) -> None:
    connector = _connector_module()
    connector.GRANT_SECRET = GRANT_SECRET
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    payload = advisor_jobs._ollama_payload("bounded local fixture", profile["model"], False)
    grant = grants.mint_local_operation_grant(GRANT_SECRET, profile, payload["prompt"])
    document = {"provider": profile, "request": payload, "confirmation": None, "grant": grant}

    async def scenario():
        sent, stopped, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class ProviderClient:
            def __init__(self, **kwargs):
                assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
            async def __aenter__(self):
                return self
            async def __aexit__(self, *_args):
                if cleanup_fails:
                    raise RuntimeError("synthetic client cleanup uncertainty")
                closed.set()

        async def ready(_profile):
            return {"status": "ready"}

        async def blocked_provider(*args, **kwargs):
            sent.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        def request(path, body):
            raw = json.dumps(body).encode()
            read = False
            async def receive():
                nonlocal read
                if not read:
                    read = True
                    return {"type": "http.request", "body": raw, "more_body": False}
                await asyncio.Event().wait()
            return Request({"type": "http", "method": "POST", "path": path,
                            "headers": [(b"content-length", str(len(raw)).encode())], "query_string": b""}, receive)

        monkeypatch.setattr(connector.httpx, "AsyncClient", ProviderClient)
        monkeypatch.setattr(connector, "_test", ready)
        monkeypatch.setattr(connector, "_bounded_json_response", blocked_provider)
        await connector.admit_operation(request("/v1/operations", document))
        generation = asyncio.create_task(connector.generate(request("/v1/generate", document)))
        async with asyncio.timeout(2):
            await sent.wait()
            assert not closed.is_set()
            cancellation = asyncio.create_task(connector.cancel_operation(request("/v1/cancel", {
                "cancellation_grant": grants.mint_local_cancellation_grant(
                    GRANT_SECRET, grants.local_operation_binding(profile, grant["prompt_sha256"]), grant["nonce"],
                ),
            })))
            if cleanup_fails:
                with pytest.raises(RuntimeError, match="cleanup uncertainty"):
                    await generation
                operation = connector._OPERATIONS[grant["nonce"]]
                assert stopped.is_set() and not closed.is_set()
                assert operation.cleanup == "pending" and not operation.completed.is_set()
                assert not cancellation.done(), "No cleanup ACK can precede proven client closure"
                cancellation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await cancellation
            else:
                receipt = await cancellation
                assert receipt == {"operation_id": grant["nonce"], "status": "cancelled", "cleanup": "confirmed"}
                assert stopped.is_set() and closed.is_set()
                with pytest.raises(HTTPException) as cancelled:
                    await generation
                assert cancelled.value.status_code == 499
                assert connector._OPERATIONS[grant["nonce"]].completed.is_set()

    asyncio.run(scenario())


def test_local_cancel_before_admission_blocks_delayed_original_request(monkeypatch) -> None:
    connector = _connector_module()
    connector.GRANT_SECRET = GRANT_SECRET
    profile = providers.normalize_profile(_profile("local-lab", transport="local"))
    payload = advisor_jobs._ollama_payload("bounded delayed local fixture", profile["model"], False)
    execution = grants.mint_local_operation_grant(GRANT_SECRET, profile, payload["prompt"])
    document = {"provider": profile, "request": payload, "confirmation": None, "grant": execution}
    binding = grants.local_operation_binding(profile, execution["prompt_sha256"])
    cancellation = grants.mint_local_cancellation_grant(GRANT_SECRET, binding, execution["nonce"])
    calls = []

    async def unexpected_provider(*args, **kwargs):
        calls.append(True)
        raise AssertionError("cancelled-before-admission must never reach provider work")

    monkeypatch.setattr(connector, "_test", unexpected_provider)
    client = TestClient(connector.app)
    cancelled = client.post("/v1/cancel", json={"cancellation_grant": cancellation})
    assert cancelled.status_code == 200
    assert cancelled.json() == {"operation_id": execution["nonce"], "status": "cancelled", "cleanup": "confirmed"}
    assert client.post("/v1/operations", json=document).status_code == 409
    assert client.post("/v1/generate", json=document).status_code == 409
    assert calls == []
    # The cancellation identity cannot be rebound to a different prompt.
    changed = grants.mint_local_cancellation_grant(
        GRANT_SECRET, {**binding, "prompt_sha256": "f" * 64}, execution["nonce"],
    )
    assert client.post("/v1/cancel", json={"cancellation_grant": changed}).status_code == 409


@pytest.mark.parametrize('invalid', ['signature', 'expired', 'cancellation-domain', 'execution-domain', 'operation', 'binding'])
def test_local_observer_refuses_changed_ownership_without_mutating_registry(invalid):
    connector = _connector_module()
    profile = providers.normalize_profile(_profile('local-lab', transport='local'))
    payload = advisor_jobs._ollama_payload('private observation fixture', profile['model'], False)
    document = _local_generation_document(connector, profile, payload)
    execution = document['grant']
    binding = grants.local_operation_binding(profile, execution['prompt_sha256'])
    operation_id = execution['nonce']
    observation = grants.mint_local_observation_grant(GRANT_SECRET, binding, operation_id)
    if invalid == 'signature': observation['signature'] = '0' * 64
    elif invalid == 'expired': observation = grants.mint_local_observation_grant(GRANT_SECRET, binding, operation_id, now=1000)
    elif invalid == 'cancellation-domain': observation = grants.mint_local_cancellation_grant(GRANT_SECRET, binding, operation_id)
    elif invalid == 'execution-domain': observation = execution
    elif invalid == 'operation': observation = grants.mint_local_observation_grant(GRANT_SECRET, binding, 'f' * 32)
    elif invalid == 'binding': observation = grants.mint_local_observation_grant(GRANT_SECRET, {**binding, 'prompt_sha256': 'f' * 64}, operation_id)
    operation = connector._OPERATIONS[operation_id]
    before = (operation.status, operation.cleanup, operation.completed.is_set(), operation.cancel_requested.is_set())
    response = TestClient(connector.app).post('/v1/observe', json={'observation_grant': observation})
    assert response.status_code == 409
    assert list(connector._OPERATIONS) == [operation_id]
    assert (operation.status, operation.cleanup, operation.completed.is_set(), operation.cancel_requested.is_set()) == before
    assert not operation.owned_generation_active


def test_local_observer_is_exact_read_only_and_restart_or_original_expiry_is_unknown():
    connector = _connector_module()
    profile = providers.normalize_profile(_profile('local-lab', transport='local'))
    payload = advisor_jobs._ollama_payload('private observation fixture', profile['model'], False)
    document = _local_generation_document(connector, profile, payload)
    execution = document['grant']
    binding = grants.local_operation_binding(profile, execution['prompt_sha256'])
    observation = grants.mint_local_observation_grant(GRANT_SECRET, binding, execution['nonce'])
    client = TestClient(connector.app)
    observed = client.post('/v1/observe', json={'observation_grant': observation})
    assert observed.status_code == 200
    assert observed.json() == {'operation_id': execution['nonce'], 'registry_instance': connector._REGISTRY_INSTANCE,
                              'status': 'admitted', 'owned_generation_active': False, 'cleanup': 'pending'}
    assert set(observed.json()) == {'operation_id', 'registry_instance', 'status', 'owned_generation_active', 'cleanup'}
    for forbidden in ['prompt', 'signature', 'response', 'model', 'provider', 'binding']:
        assert forbidden not in observed.json()
    assert client.get('/v1/observe').status_code == 405
    assert client.post('/v1/observe', json={'observation_grant': observation, 'enumerate': True}).status_code == 422
    connector._OPERATIONS[execution['nonce']].expires_at = 1
    assert client.post('/v1/observe', json={'observation_grant': observation}).status_code == 409
    restarted = _connector_module()
    restarted.GRANT_SECRET = GRANT_SECRET
    assert restarted._REGISTRY_INSTANCE != connector._REGISTRY_INSTANCE
    assert TestClient(restarted.app).post('/v1/observe', json={'observation_grant': observation}).status_code == 409
    assert restarted._OPERATIONS == {}
