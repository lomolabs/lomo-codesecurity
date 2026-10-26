from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from kodesec_api.auth import AuthContext
from kodesec_api.db import Base, Runtime, initialize_database
from kodesec_api.jobs.execution import _validated_scan_coverage_snapshot
from kodesec_api.main import (
    SCANNER_TOOL_REGISTRY,
    _ScannerRuntimeSnapshot,
    _ensure_tool_state,
    _scanner_preflight,
    _scanner_tool_rows,
    create_scan,
    patch_scanner_tool,
    update_scanner_tool,
)
from kodesec_api.models import Job, Project, RuntimeConfig, Scan, ScannerToolState
from kodesec_api.schemas import ScanCreate, ScannerToolPatch
from kodesec_api.settings import Settings


EXPECTED_VERSIONS = {
    "trivy": "0.73.0",
    "gitleaks": "8.30.1",
    "opengrep": "1.27.0",
    "bearer": "2.1.0",
    "grype": "0.117.0",
    "checkov": "3.3.10",
    "trufflehog": "3.96.0",
    "syft": "1.51.0",
}


def _ready_runtime_inventory() -> dict[str, dict[str, object]]:
    readiness = {
        "binary": {"state": "ready", "reason": None, "component_ids": []},
        "data": {"state": "not_required", "reason": None, "component_ids": []},
        "rules": {"state": "not_required", "reason": None, "component_ids": []},
        "execution": {"state": "ready", "reason": None, "component_ids": []},
    }
    return {
        tool_id: {
            "id": tool_id,
            "available": True,
            "status": "ready",
            "installed_version": version,
            "readiness": readiness,
            "runtime_ready": True,
        }
        for tool_id, version in EXPECTED_VERSIONS.items()
    }


def _runtime_snapshot(
    tools: dict[str, dict[str, object]],
) -> _ScannerRuntimeSnapshot:
    return _ScannerRuntimeSnapshot(tools=tools, active_generation=None)


def _runtime() -> Runtime:
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
        SCANNER_URL="http://scanner:8091",
        KODESEC_ALLOWED_ROOTS="/workspace",
    )
    return Runtime.create(settings, engine=engine)


def test_api_registry_matches_the_curated_eight_tool_candidate() -> None:
    observed = {
        tool_id: str(metadata["current_version"])
        for tool_id, metadata in SCANNER_TOOL_REGISTRY.items()
        if metadata["source"] == "external"
    }
    assert observed == EXPECTED_VERSIONS
    tool_lock = json.loads(
        (Path(__file__).resolve().parents[3] / "scanner-tools.lock.json").read_text()
    )
    assert {
        tool_id: metadata["output_format"]
        for tool_id, metadata in SCANNER_TOOL_REGISTRY.items()
        if metadata["source"] == "external"
    } == {
        item["id"]: item["adapter"]["output_format"]
        for item in tool_lock["tools"]
    }


def test_concurrent_tool_state_initialization_creates_one_row(
    postgres_engine, monkeypatch
) -> None:
    initialize_database(postgres_engine)
    barrier = Barrier(2)
    original_get = Session.get

    def synchronized_get(session, entity, ident, **kwargs):
        state = original_get(session, entity, ident, **kwargs)
        if entity is ScannerToolState and ident == "secrets-lite" and state is None:
            barrier.wait(timeout=5)
        return state

    monkeypatch.setattr(Session, "get", synchronized_get)

    def initialize(_: int) -> str:
        with Session(postgres_engine) as db:
            return _ensure_tool_state(db, "secrets-lite").id

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(initialize, range(2))) == [
            "secrets-lite",
            "secrets-lite",
        ]

    with Session(postgres_engine) as db:
        assert db.scalar(
            select(func.count()).select_from(ScannerToolState).where(
                ScannerToolState.id == "secrets-lite"
            )
        ) == 1


def test_apply_latest_records_desired_version_without_claiming_installation() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        state = _ensure_tool_state(db, "trivy")
        state.current_version = "0.72.0"
        state.latest_version = EXPECTED_VERSIONS["trivy"]
        state.candidate_release_id = "scanner-release-v1"
        state.candidate_manifest_sha256 = "a" * 64
        db.add(state)
        db.commit()
        runtime_inventory = {
            "trivy": {
                "id": "trivy",
                "available": True,
                "status": "ready",
                "installed_version": "0.72.0",
            }
        }
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(runtime_inventory),
        ):
            output = update_scanner_tool("trivy", runtime=runtime, db=db)
        db.expire_all()
        persisted = _ensure_tool_state(db, "trivy")
        assert persisted.current_version == "0.72.0"
        assert persisted.pinned_version == EXPECTED_VERSIONS["trivy"]
        assert persisted.status == "host_confirmation_required"
        assert output["current_version"] == "0.72.0"
        assert output["installed_version"] == "0.72.0"
        assert output["pinned_version"] == EXPECTED_VERSIONS["trivy"]
        assert output["status"] == "host_confirmation_required"
        assert output["update_available"] is True
    runtime.engine.dispose()


def test_verified_rebuild_commits_runtime_version_and_clears_desired_pin() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        state = _ensure_tool_state(db, "trivy")
        state.current_version = "0.72.0"
        state.latest_version = EXPECTED_VERSIONS["trivy"]
        state.pinned_version = EXPECTED_VERSIONS["trivy"]
        state.status = "host_confirmation_required"
        db.add(state)
        db.commit()
        runtime_inventory = {
            "trivy": {
                "id": "trivy",
                "available": True,
                "status": "ready",
                "installed_version": EXPECTED_VERSIONS["trivy"],
            }
        }
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(runtime_inventory),
        ):
            output = next(
                item
                for item in _scanner_tool_rows(db, runtime.settings)
                if item["id"] == "trivy"
            )
        assert output["current_version"] == EXPECTED_VERSIONS["trivy"]
        assert output["installed_version"] == EXPECTED_VERSIONS["trivy"]
        assert output["status"] == "ready"
        assert output["update_available"] is False
        assert output["pinned_version"] is None
    with runtime.session_factory() as db:
        persisted = _ensure_tool_state(db, "trivy")
        assert persisted.current_version == EXPECTED_VERSIONS["trivy"]
        assert persisted.pinned_version is None
        assert persisted.status == "ready"
    runtime.engine.dispose()


def test_runtime_inventory_synchronizes_a_verified_installed_version() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        state = _ensure_tool_state(db, "syft")
        state.current_version = "1.45.1"
        db.add(state)
        db.commit()
        runtime_inventory = {
            "syft": {
                "id": "syft",
                "available": True,
                "status": "ready",
                "installed_version": EXPECTED_VERSIONS["syft"],
            }
        }
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(runtime_inventory),
        ):
            output = next(
                item
                for item in _scanner_tool_rows(db, runtime.settings)
                if item["id"] == "syft"
            )
        assert output["current_version"] == EXPECTED_VERSIONS["syft"]
    with runtime.session_factory() as db:
        assert _ensure_tool_state(db, "syft").current_version == EXPECTED_VERSIONS["syft"]
    runtime.engine.dispose()


def test_enable_disable_does_not_hide_missing_runtime_or_install_a_pin() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot({}),
        ):
            disabled = patch_scanner_tool(
                "bearer",
                ScannerToolPatch(enabled=False),
                runtime=runtime,
                db=db,
            )
            assert disabled["enabled"] is False
            assert disabled["status"] == "disabled"

            enabled = patch_scanner_tool(
                "bearer",
                ScannerToolPatch(enabled=True),
                runtime=runtime,
                db=db,
            )
            assert enabled["enabled"] is True
            assert enabled["available"] is False
            assert enabled["status"] == "missing"
            assert enabled["pinned_version"] is None
            assert enabled["installed_version"] is None
            assert enabled["current_version"] == EXPECTED_VERSIONS["bearer"]
    runtime.engine.dispose()


def test_scan_admission_fails_closed_when_every_scanner_tool_is_disabled() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        project = Project(
            name="no-scanner-tools",
            repo_path="/workspace/no-scanner-tools",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        for tool_id in SCANNER_TOOL_REGISTRY:
            state = _ensure_tool_state(db, tool_id)
            state.enabled = False
            db.add(state)
        db.commit()
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/scans",
                "headers": [(b"idempotency-key", b"no-tools-fixture")],
            }
        )
        request.state.auth = AuthContext(
            kind="browser",
            subject="test-session",
            scopes=frozenset(),
        )
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot({}),
        ):
            with pytest.raises(HTTPException) as rejected:
                create_scan(
                    ScanCreate(project_id=project.id, use_ai=False),
                    request=request,
                    runtime=runtime,
                    db=db,
                )
        assert rejected.value.status_code == 409
        assert rejected.value.detail["code"] == "no_scanner_tools_enabled"
        assert rejected.value.detail["action"] == "enable_scanner"
        assert len(rejected.value.detail["context"]["preflight_revision"]) == 64
        assert db.query(Scan).count() == 0
        assert db.query(Job).count() == 0
    runtime.engine.dispose()


@pytest.mark.parametrize(
    ("target_path", "target_kind"),
    [("k8s/deployment.yaml", "file"), ("k8s", "directory")],
)
def test_scan_admission_persists_one_typed_canonical_source_target(
    target_path: str,
    target_kind: str,
) -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        project = Project(
            name="exact-file",
            repo_path="/workspace/exact-file",
            default_branch="main",
        )
        db.add(project)
        db.commit()
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/scans",
                "headers": [(b"idempotency-key", b"exact-file-fixture")],
            }
        )
        request.state.auth = AuthContext(
            kind="browser", subject="test-session", scopes=frozenset()
        )
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(_ready_runtime_inventory()),
        ):
            created = create_scan(
                ScanCreate(
                    project_id=project.id,
                    target_path=target_path,
                    target_kind=target_kind,
                ),
                request=request,
                runtime=runtime,
                db=db,
            )
        assert created["status"] == "pending"
        job = db.query(Job).one()
        assert job.payload["target_path"] == target_path
        assert job.payload["target_kind"] == target_kind

    for invalid in ("/absolute.py", "../outside.py", "src//app.py", "src\\app.py"):
        with pytest.raises(ValueError, match="target_path"):
            ScanCreate(project_id=1, target_path=invalid, target_kind="file")
    with pytest.raises(ValueError, match="both target_path and target_kind"):
        ScanCreate(project_id=1, target_path="app.py")
    with pytest.raises(ValueError, match="both target_path and target_kind"):
        ScanCreate(project_id=1, target_kind="file")
    with pytest.raises(ValueError, match="mode=full"):
        ScanCreate(
            project_id=1,
            mode="incremental_diff",
            target_path="app.py",
            target_kind="file",
        )
    runtime.engine.dispose()


@pytest.mark.parametrize(
    ("advisor_mode", "request_value", "expected_use_ai"),
    [
        ("on", "omitted", False),
        ("on", "false", False),
        ("on", "true", True),
    ],
)
def test_scan_advisor_requires_explicit_enabled_opt_in(
    advisor_mode: str,
    request_value: str,
    expected_use_ai: bool,
) -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        project = Project(
            name=f"advisor-{advisor_mode}-{request_value}",
            repo_path=f"/workspace/advisor-{advisor_mode}-{request_value}",
            default_branch="main",
        )
        db.add(project)
        db.add(RuntimeConfig(key="ai_mode", value=advisor_mode))
        db.commit()
        payload = (
            ScanCreate(project_id=project.id)
            if request_value == "omitted"
            else ScanCreate(project_id=project.id, use_ai=request_value == "true")
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/scans",
                "headers": [
                    (
                        b"idempotency-key",
                        f"advisor-{advisor_mode}-{request_value}".encode("ascii"),
                    )
                ],
            }
        )
        request.state.auth = AuthContext(
            kind="browser",
            subject="test-session",
            scopes=frozenset(),
        )

        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(_ready_runtime_inventory()),
        ):
            create_scan(payload, request=request, runtime=runtime, db=db)

        job = db.query(Job).one()
        assert job.payload["use_ai"] is expected_use_ai
    runtime.engine.dispose()


def test_scan_admission_defaults_complete_and_limited_is_explicit() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        project = Project(
            name="coverage-admission",
            repo_path="/workspace/coverage-admission",
            default_branch="main",
        )
        db.add(project)
        for tool_id in SCANNER_TOOL_REGISTRY:
            state = _ensure_tool_state(db, tool_id)
            state.enabled = tool_id in {"gitleaks", "trivy"}
            db.add(state)
        db.commit()
        inventory = _ready_runtime_inventory()
        inventory["gitleaks"] = {
            **inventory["gitleaks"],
            "runtime_ready": False,
            "readiness": {
                **inventory["gitleaks"]["readiness"],
                "execution": {
                    "state": "unattested",
                    "reason": "offline execution contract is not attested",
                    "component_ids": [],
                },
            },
        }

        def request(key: bytes) -> Request:
            value = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/v1/scans",
                    "headers": [(b"idempotency-key", key)],
                }
            )
            value.state.auth = AuthContext(
                kind="browser", subject="test-session", scopes=frozenset()
            )
            return value

        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(inventory),
        ):
            reviewed_preflight = _scanner_preflight(db, runtime.settings)
            with pytest.raises(HTTPException) as rejected:
                create_scan(
                    ScanCreate(project_id=project.id),
                    request=request(b"complete-coverage-fixture"),
                    runtime=runtime,
                    db=db,
                )
            assert rejected.value.status_code == 409
            assert rejected.value.detail["code"] == "scanner_runtime_prerequisite_missing"
            assert rejected.value.detail["action"] == "repair_scanner_runtime"
            assert rejected.value.detail["context"]["blocked_tool_ids"] == [
                "gitleaks"
            ]
            assert rejected.value.detail["context"]["preparation_available"] is False
            assert rejected.value.detail["context"]["preparation_blocking_reasons"] == [
                "offline execution contract is not attested"
            ]
            assert db.query(Scan).count() == 0
            assert db.query(Job).count() == 0

            with pytest.raises(HTTPException) as stale:
                create_scan(
                    ScanCreate(
                        project_id=project.id,
                        coverage="limited",
                        acknowledge_limited_coverage=True,
                        preflight_revision="0" * 64,
                    ),
                    request=request(b"stale-limited-coverage-fixture"),
                    runtime=runtime,
                    db=db,
                )
            assert stale.value.status_code == 409
            assert stale.value.detail["code"] == "scanner_preflight_changed"
            assert db.query(Scan).count() == 0
            assert db.query(Job).count() == 0

            created = create_scan(
                ScanCreate(
                    project_id=project.id,
                    coverage="limited",
                    acknowledge_limited_coverage=True,
                    preflight_revision=reviewed_preflight["revision"],
                ),
                request=request(b"limited-coverage-fixture"),
                runtime=runtime,
                db=db,
            )
        assert created["status"] == "pending"
        job = db.query(Job).one()
        assert job.payload["coverage"] == "limited"
        assert job.payload["requested_tools"] == ["gitleaks", "trivy"]
        assert job.payload["enabled_tools"] == ["trivy"]
        assert [item["id"] for item in job.payload["omitted_tools"]] == [
            "gitleaks"
        ]
        assert _validated_scan_coverage_snapshot(job.payload)["omitted_tools"] == [
            {
                "id": "gitleaks",
                "name": "Gitleaks",
                "blocking_reasons": [
                    "offline execution contract is not attested"
                ],
                "required_component_ids": [],
                "preparation_blocking_reasons": [
                    "offline execution contract is not attested"
                ],
            }
        ]
        assert len(job.payload["preflight_revision"]) == 64
    runtime.engine.dispose()


def test_arbitrary_or_unattested_image_selection_is_rejected() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        state = _ensure_tool_state(db, "trivy")
        state.latest_version = EXPECTED_VERSIONS["trivy"]
        db.add(state)
        db.commit()
        with pytest.raises(HTTPException, match="attested curated candidate"):
            patch_scanner_tool(
                "trivy",
                ScannerToolPatch(pinned_version="9.9.9"),
                runtime=runtime,
                db=db,
            )
        with pytest.raises(HTTPException, match="manifest attestation"):
            update_scanner_tool("trivy", runtime=runtime, db=db)
    runtime.engine.dispose()
