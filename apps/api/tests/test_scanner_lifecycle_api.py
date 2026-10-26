from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

from fastapi import HTTPException
import httpx
import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from kodesec_api.auth import AuthContext
from kodesec_api.db import Base, Runtime
from kodesec_api.main import (
    _job_to_out,
    _ScannerRuntimeSnapshot,
    _scanner_cache_rollback_eligibility,
    check_scanner_tools,
    cancel_job,
    prepare_scanners,
    rollback_scanner_cache,
    scanner_lifecycle,
    update_scanner_cache,
)
from kodesec_api.models import EventOutbox, Job, ScannerLifecycleState
from kodesec_api.events import install_outbox_listeners
from kodesec_api.jobs.execution import (
    _UPDATER_STAGES,
    _enqueue_scanner_preparation_cache_continuation,
    _scanner_preparation_component_rejection,
    ClaimedJob,
    ExecutionCompletion,
    JobExecutionError,
    LeaseMonitor,
    WorkerExecutor,
)
from kodesec_api.jobs.repository import CacheCommitInProgressError, request_cancellation
from kodesec_api.redaction import redact_json, redact_text
from kodesec_api.schemas import (
    SCANNER_CATALOG_COMPONENT_STATES,
    SCANNER_CATALOG_TOOL_STATES,
    SCANNER_SOURCE_INTRINSIC_CACHE_COMPONENT_IDS,
    ScannerCacheUpdateRequest,
    ScannerPreparationCommandOut,
)
from kodesec_api.settings import Settings


def _runtime() -> Runtime:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+pysqlite://",
            SCANNER_URL="http://scanner:8091",
            SCANNER_UPDATER_URL="http://scanner-updater:8092",
            KODESEC_ALLOWED_ROOTS="/workspace",
        ),
        engine=engine,
    )


def _request(key: str) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/fixture",
            "headers": [(b"idempotency-key", key.encode("ascii"))],
        }
    )
    request.state.auth = AuthContext(
        kind="browser",
        subject="fixture",
        scopes=frozenset({"api:write"}),
    )
    return request


def test_updater_protocol_admits_the_non_cancellable_commit_stage() -> None:
    assert "committing" in _UPDATER_STAGES


def _persist_cache_cancellation_job(runtime, *, kind="scanner_cache_update", stage="staging", status="running"):
    from kodesec_api.main import _scanner_lifecycle_digest

    install_outbox_listeners()
    claimed = _claimed_cache_job()
    operation = "cache_rollback" if kind == "scanner_cache_rollback" else "cache_update"
    components = [] if operation == "cache_rollback" else ["grype-db"]
    now = datetime.now(timezone.utc)
    with runtime.session_factory() as db:
        job = Job(
            id=claimed.id, kind=kind, title="Cache cancellation fixture",
            status=status, stage=stage, attempt=1, max_attempts=3,
            external_run_id=claimed.external_run_id,
            payload={"v": 1, "operation": operation, "component_ids": components,
                     "request_digest": _scanner_lifecycle_digest(operation, components)},
            checkpoint={}, revision=1, lease_owner="worker-test",
            lease_expires_at=now + timedelta(seconds=30), heartbeat_at=now,
            started_at=now,
            cancel_requested_at=now if status == "cancelling" else None,
        )
        db.add(job)
        db.flush()
        state = db.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.job_id = job.id
        state.status = status
        db.commit()
        return ClaimedJob.from_model(job), now


def _cancellation_rows(db):
    return tuple(
        db.execute(select(model.__table__)).all()
        for model in (Job, ScannerLifecycleState, EventOutbox)
    )


@pytest.mark.parametrize("kind", ["scanner_cache_update", "scanner_cache_rollback"])
@pytest.mark.parametrize("stage", ["committing", "activating"])
def test_cache_commit_cancellation_is_unavailable_and_refused_without_mutation(kind, stage) -> None:
    runtime = _runtime()
    claimed, now = _persist_cache_cancellation_job(runtime, kind=kind, stage=stage)
    with runtime.session_factory() as db, patch("kodesec_api.jobs.repository._time", return_value=now):
        job = db.get(Job, claimed.id)
        assert job is not None
        assert _job_to_out(db, job)["can_cancel"] is False
        before = _cancellation_rows(db)
        assert before[2], "the mutation check must include a real seeded outbox row"
        with pytest.raises(CacheCommitInProgressError):
            request_cancellation(db, job.id)
        with pytest.raises(HTTPException) as raised:
            cancel_job(job.id, _request("late-cache-cancel"), db=db)
        assert raised.value.status_code == 409
        assert raised.value.detail["code"] == "cache_commit_in_progress"
        assert raised.value.detail["action"] == "refresh_job"
        assert redact_json(raised.value.detail) == raised.value.detail
        assert redact_text("cache_commit_in_progress") == "cache_commit_in_progress"
        assert redact_text("scanner: cache_commit_in_progress") == "scanner: cache_commit_in_progress"
        db.commit()
        assert _cancellation_rows(db) == before
    runtime.engine.dispose()


def test_cache_cancellation_refreshes_preloaded_job_under_lock() -> None:
    runtime = _runtime()
    claimed, now = _persist_cache_cancellation_job(runtime)
    with runtime.session_factory() as db, patch("kodesec_api.jobs.repository._time", return_value=now):
        cached = db.get(Job, claimed.id)
        assert cached is not None and _job_to_out(db, cached)["can_cancel"] is True
        # Advance persisted state without updating the identity map, as a worker
        # can between the route's authorization read and its cancellation lock.
        db.execute(update(Job).where(Job.id == claimed.id).values(
            stage="committing", revision=2,
        ).execution_options(synchronize_session=False))
        assert cached.stage == "staging"
        before = _cancellation_rows(db)
        with pytest.raises(HTTPException) as raised:
            cancel_job(claimed.id, _request("cached-stage-cancel"), db=db)
        assert raised.value.status_code == 409
        assert cached.stage == "committing"
        assert cached.cancel_requested_at is None
        db.commit()
        assert _cancellation_rows(db) == before
    runtime.engine.dispose()


@pytest.mark.parametrize("kind,stage,status", [
    ("scanner_cache_update", "validating_generation", "running"),
    ("scanner_cache_rollback", "rolling_back", "running"),
    ("scanner_cache_update", "queued", "queued"),
    ("scanner_cache_rollback", "starting", "leased"),
])
def test_cache_precommit_cancellation_remains_available_and_idempotent(kind, stage, status) -> None:
    runtime = _runtime()
    claimed, now = _persist_cache_cancellation_job(runtime, kind=kind, stage=stage, status=status)
    with runtime.session_factory() as db, patch("kodesec_api.jobs.repository._time", return_value=now):
        assert _job_to_out(db, db.get(Job, claimed.id))["can_cancel"] is True
        first = cancel_job(claimed.id, _request("precommit-cancel"), db=db)
        assert first["status"] == "cancelling" and first["cancel_requested_at"] is not None
        assert first["can_cancel"] is False
        before = _cancellation_rows(db)
        repeated = cancel_job(claimed.id, _request("repeated-cancel"), db=db)
        assert repeated["revision"] == first["revision"]
        assert _cancellation_rows(db) == before
    runtime.engine.dispose()


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled", "cancelling"])
def test_cache_terminal_or_pending_cancellation_stays_idempotent(status) -> None:
    runtime = _runtime()
    claimed, now = _persist_cache_cancellation_job(runtime, stage="committing", status=status)
    with runtime.session_factory() as db, patch("kodesec_api.jobs.repository._time", return_value=now):
        before = _cancellation_rows(db)
        result = cancel_job(claimed.id, _request("terminal-cancel"), db=db)
        assert result["status"] == status and result["can_cancel"] is False
        assert _cancellation_rows(db) == before
    runtime.engine.dispose()


@pytest.mark.parametrize("kind", ["scan", "advisor", "scanner_catalog_check"])
def test_cache_commit_stage_names_do_not_disable_other_job_kinds(kind) -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        job = Job(kind=kind, status="running", stage="committing")
        assert _job_to_out(db, job)["can_cancel"] is True
    runtime.engine.dispose()


def test_scanner_preparation_component_rejection_names_required_lock_refresh() -> None:
    rejection = _scanner_preparation_component_rejection(
        {
            "grype-db": "requires_lock_refresh",
            "trivy-db": "candidate_available",
        },
        ["grype-db", "trivy-db"],
    )
    assert rejection is not None
    assert rejection.code == "scanner_preparation_lock_refresh_required"
    assert rejection.detail == (
        "Reviewed scanner database lock refresh required for: grype-db. "
        "Get refreshed reviewed CodeSecurity source, then rerun normal startup "
        "with your existing state and editor options to rebuild changed inputs. "
        "Choose Prepare all scanners afterward."
    )
    assert _scanner_preparation_component_rejection(
        {"grype-db": "candidate_available"},
        ["grype-db"],
    ) is None


def _catalog_result_with_lock_refresh() -> dict:
    tool_ids = sorted(
        [
            "trivy",
            "gitleaks",
            "opengrep",
            "bearer",
            "grype",
            "checkov",
            "trufflehog",
            "syft",
        ]
    )
    component_ids = sorted(
        [
            "trivy-db",
            "trivy-java-db",
            "trivy-checks",
            "opengrep-reviewed-rules",
            "bearer-rules",
            "grype-db",
        ]
    )
    return {
        "kind": "catalog",
        "checked_at": "2026-08-12T12:00:00Z",
        "tools": [
            {
                "tool_id": tool_id,
                "state": "current",
                "installed_version": "1.0.0",
                "candidate_version": None,
                "candidate_release_id": None,
                "candidate_manifest_digest": None,
            }
            for tool_id in tool_ids
        ],
        "components": [
            {
                "component_id": component_id,
                "state": (
                    "requires_lock_refresh"
                    if component_id == "grype-db"
                    else "unattested"
                ),
                "current_immutable_ref": None,
                "candidate_immutable_ref": None,
                "candidate_manifest_digest": None,
            }
            for component_id in component_ids
        ],
    }


def test_api_catalog_contract_carries_only_component_lock_refresh_state() -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "worker-test")

    assert "requires_lock_refresh" in SCANNER_CATALOG_COMPONENT_STATES
    assert "requires_lock_refresh" not in SCANNER_CATALOG_TOOL_STATES
    assert "trivy-checks" not in SCANNER_SOURCE_INTRINSIC_CACHE_COMPONENT_IDS

    accepted = executor._admit_catalog_result(_catalog_result_with_lock_refresh())
    grype = next(
        item for item in accepted["components"] if item["component_id"] == "grype-db"
    )
    assert grype == {
        "component_id": "grype-db",
        "state": "requires_lock_refresh",
        "current_immutable_ref": None,
        "candidate_immutable_ref": None,
        "candidate_manifest_digest": None,
    }

    with runtime.session_factory() as db:
        scanner_lifecycle(db=db)
        lifecycle = db.get(ScannerLifecycleState, "catalog")
        assert lifecycle is not None
        lifecycle.status = "completed"
        lifecycle.receipt = {"schema_version": 1, "result": accepted}
        db.commit()
        output = scanner_lifecycle(db=db)
        exposed_grype = next(
            item
            for item in output["catalog"]["receipt"]["result"]["components"]
            if item["component_id"] == "grype-db"
        )
        assert exposed_grype["state"] == "requires_lock_refresh"

    actionable = _catalog_result_with_lock_refresh()
    grype_raw = next(
        item
        for item in actionable["components"]
        if item["component_id"] == "grype-db"
    )
    grype_raw["candidate_immutable_ref"] = "sha256:" + "a" * 64
    grype_raw["candidate_manifest_digest"] = "a" * 64
    with pytest.raises(JobExecutionError, match="Non-actionable"):
        executor._admit_catalog_result(actionable)

    tool_state = _catalog_result_with_lock_refresh()
    tool_state["tools"][0]["state"] = "requires_lock_refresh"
    with pytest.raises(JobExecutionError, match="tool state is invalid"):
        executor._admit_catalog_result(tool_state)

    hostile_state = _catalog_result_with_lock_refresh()
    hostile_state["components"][0]["state"] = ["requires_lock_refresh"]
    with pytest.raises(JobExecutionError, match="component state is invalid"):
        executor._admit_catalog_result(hostile_state)

    acquisition_relative = _catalog_result_with_lock_refresh()
    grype_state = next(
        item
        for item in acquisition_relative["components"]
        if item["component_id"] == "grype-db"
    )
    grype_state["state"] = "unattested"
    checks_state = next(
        item
        for item in acquisition_relative["components"]
        if item["component_id"] == "trivy-checks"
    )
    checks_state["state"] = "requires_lock_refresh"
    with pytest.raises(JobExecutionError, match="source-intrinsic"):
        executor._admit_catalog_result(acquisition_relative)

    runtime.engine.dispose()


@pytest.mark.parametrize(
    ("state", "current_ref", "candidate_ref", "manifest"),
    [
        ("current", "sha256:" + "a" * 64, None, None),
        ("candidate_available", None, "sha256:" + "b" * 64, "b" * 64),
        ("unavailable", None, None, None),
        ("unattested", None, None, None),
    ],
)
def test_api_catalog_contract_preserves_supported_component_states(
    state: str,
    current_ref: str | None,
    candidate_ref: str | None,
    manifest: str | None,
) -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "worker-test")
    result = _catalog_result_with_lock_refresh()
    grype = next(
        item for item in result["components"] if item["component_id"] == "grype-db"
    )
    grype.update(
        {
            "state": state,
            "current_immutable_ref": current_ref,
            "candidate_immutable_ref": candidate_ref,
            "candidate_manifest_digest": manifest,
        }
    )

    accepted = executor._admit_catalog_result(result)
    accepted_grype = next(
        item for item in accepted["components"] if item["component_id"] == "grype-db"
    )
    assert accepted_grype == {
        "component_id": "grype-db",
        "state": state,
        "current_immutable_ref": current_ref,
        "candidate_immutable_ref": candidate_ref,
        "candidate_manifest_digest": manifest,
    }
    with runtime.session_factory() as db:
        scanner_lifecycle(db=db)
        lifecycle = db.get(ScannerLifecycleState, "catalog")
        assert lifecycle is not None
        lifecycle.status = "completed"
        lifecycle.receipt = {"schema_version": 1, "result": accepted}
        db.commit()
        persisted = next(
            item
            for item in lifecycle.receipt["result"]["components"]
            if item["component_id"] == "grype-db"
        )
        assert persisted == accepted_grype
        output = scanner_lifecycle(db=db)

    exposed = next(
        item
        for item in output["catalog"]["receipt"]["result"]["components"]
        if item["component_id"] == "grype-db"
    )
    assert exposed["state"] == state
    assert set(exposed) == set(accepted_grype)
    runtime.engine.dispose()


def test_catalog_check_is_an_immediate_durable_command_without_api_egress() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        with patch("kodesec_api.main.httpx.Client", side_effect=AssertionError("API egress")):
            output = check_scanner_tools(_request("catalog-command-0001"), runtime=runtime, db=db)

        job = db.scalar(select(Job))
        state = db.get(ScannerLifecycleState, "catalog")
        assert job is not None and state is not None
        assert output["job"]["id"] == job.id
        assert output["job"]["status"] == "queued"
        assert output["lifecycle"]["job_url"] == f"/v1/jobs/{job.id}"
        assert job.kind == "scanner_catalog_check"
        assert job.payload == {
            "v": 1,
            "operation": "catalog_check",
            "request_digest": job.payload["request_digest"],
            "component_ids": [],
            "preparation_budget": job.payload["preparation_budget"],
        }
        assert len(job.payload["request_digest"]) == 64
        assert state.status == "queued" and state.job_id == job.id

        replay = check_scanner_tools(_request("catalog-command-0001"), runtime=runtime, db=db)
        assert replay["job"]["id"] == job.id
        assert len(list(db.scalars(select(Job)))) == 1
    runtime.engine.dispose()


def test_prepare_scanners_queues_catalog_with_one_conditional_cache_continuation() -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db", "trivy-db"],
        "blocked_tools": [{
            "id": "grype",
            "name": "Grype",
            "preparation_blocking_reasons": [],
        }],
    }
    with runtime.session_factory() as db:
        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            output = prepare_scanners(_request("prepare-command-0001"), runtime=runtime, db=db)

        jobs = list(db.scalars(select(Job).order_by(Job.id)))
        assert [job.kind for job in jobs] == ["scanner_catalog_check"]
        assert jobs[0].payload["component_ids"] == []
        continuation = jobs[0].payload["preparation"]
        assert continuation == {
            "schema_version": 2,
            "component_ids": ["grype-db", "trivy-db"],
            "request_digest": continuation["request_digest"],
            "preparation_budget": jobs[0].payload["preparation_budget"],
        }
        assert len(continuation["request_digest"]) == 64
        assert output["required_component_ids"] == ["grype-db", "trivy-db"]
        assert output["catalog"]["job"]["id"] == jobs[0].id
        assert output["cache"] is None
        ScannerPreparationCommandOut.model_validate(output, strict=True)
        assert db.get(ScannerLifecycleState, "catalog").job_id == jobs[0].id
        assert db.get(ScannerLifecycleState, "cache").job_id is None
        lifecycle = scanner_lifecycle(db=db)
        assert lifecycle["catalog"]["job_id"] == jobs[0].id
        assert lifecycle["cache"]["job_id"] is None

        with pytest.raises(HTTPException) as conflict:
            update_scanner_cache(
                ScannerCacheUpdateRequest(component_ids=["grype-db"]),
                _request("manual-cache-during-preparation"),
                db=db,
            )
        assert conflict.value.status_code == 409
        assert conflict.value.detail["code"] == "scanner_preparation_catalog_active"

        with patch(
            "kodesec_api.main._scanner_preflight",
            side_effect=AssertionError("idempotent replay must not rerun preflight"),
        ):
            replay = prepare_scanners(_request("prepare-command-0001"), runtime=runtime, db=db)
        assert replay["catalog"]["job"]["id"] == jobs[0].id
        assert replay["cache"] is None
        assert len(list(db.scalars(select(Job)))) == 1
    runtime.engine.dispose()


@pytest.mark.parametrize("catalog_digest", [None, "a" * 64])
def test_catalog_completion_creates_exactly_one_admissible_cache_continuation(catalog_digest: str | None) -> None:
    from kodesec_api.main import _scanner_lifecycle_digest
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db", "trivy-db"],
        "blocked_tools": [],
    }
    with runtime.session_factory() as db:
        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            output = prepare_scanners(
                _request("prepare-continuation-safe"),
                runtime=runtime,
                db=db,
            )
        catalog = db.get(Job, output["catalog"]["job"]["id"])
        assert catalog is not None
        result = {
            **({"catalog_digest": catalog_digest, "catalog_mode": "signed"} if catalog_digest else {}),
            "components": [
                {"component_id": "grype-db", "state": "candidate_available"},
                {"component_id": "trivy-db", "state": "current"},
            ],
        }
        first = _enqueue_scanner_preparation_cache_continuation(db, catalog, result)
        second = _enqueue_scanner_preparation_cache_continuation(db, catalog, result)
        db.commit()

        assert first is not None and second is not None and first.id == second.id
        jobs = list(db.scalars(select(Job).order_by(Job.id)))
        assert [job.kind for job in jobs] == [
            "scanner_catalog_check",
            "scanner_cache_update",
        ]
        assert jobs[1].payload == {
            "v": 1,
            "operation": "cache_update",
            "request_digest": _scanner_lifecycle_digest("cache_update", ["grype-db", "trivy-db"], catalog_digest, catalog.payload["preparation_budget"]),
            "component_ids": ["grype-db", "trivy-db"],
            "prerequisite_job_id": catalog.id,
            "preparation_budget": catalog.payload["preparation_budget"],
            **({"catalog_digest": catalog_digest} if catalog_digest else {}),
        }
        continuation_id = UUID(str(jobs[1].external_run_id))
        assert continuation_id.version == 5
        assert continuation_id.variant == "specified in RFC 4122"
        assert db.get(ScannerLifecycleState, "cache").job_id == jobs[1].id

        with patch(
            "kodesec_api.main._scanner_preflight",
            side_effect=AssertionError("idempotent replay must not rerun preflight"),
        ):
            replay = prepare_scanners(
                _request("prepare-continuation-safe"),
                runtime=runtime,
                db=db,
            )
        assert replay["cache"]["job"]["id"] == jobs[1].id
        ScannerPreparationCommandOut.model_validate(replay, strict=True)
    runtime.engine.dispose()


def test_worker_catalog_completion_atomically_publishes_the_cache_continuation() -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db", "trivy-db"],
        "blocked_tools": [],
    }
    with runtime.session_factory() as db:
        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            output = prepare_scanners(
                _request("prepare-worker-continuation"),
                runtime=runtime,
                db=db,
            )
        catalog = db.get(Job, output["catalog"]["job"]["id"])
        catalog_state = db.get(ScannerLifecycleState, "catalog")
        assert catalog is not None and catalog_state is not None
        catalog.status = "running"
        catalog.stage = "source_blind_updater"
        catalog.attempt = 1
        catalog.lease_owner = "worker-continuation-test"
        catalog.lease_expires_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        catalog.started_at = datetime.now(timezone.utc)
        catalog_state.status = "running"
        db.commit()
        db.refresh(catalog)
        claimed = ClaimedJob.from_model(catalog)
        result = _catalog_result_with_lock_refresh()
        for component in result["components"]:
            if component["component_id"] in {"grype-db", "trivy-db"}:
                component["state"] = "candidate_available"
        record = {
            "schema_version": 1,
            "operation_id": catalog.external_run_id,
            "request_digest": catalog.payload["request_digest"],
            "kind": "catalog_check",
            "requested_components": [],
            "attempt": 1,
            "max_attempts": 3,
            "updated_at": "2026-08-12T12:00:00Z",
            "result": result,
        }

    executor = WorkerExecutor(runtime, "worker-continuation-test")
    with patch(
        "kodesec_api.jobs.repository._time",
        return_value=datetime.now(timezone.utc),
    ):
        executor._complete(
            claimed,
            ExecutionCompletion(
                detail="Catalog completed.",
                result_ref="scanner-lifecycle:catalog",
                lifecycle_scope="catalog",
                lifecycle_receipt=record,
            ),
        )

    with runtime.session_factory() as db:
        catalog = db.get(Job, claimed.id)
        jobs = list(db.scalars(select(Job).order_by(Job.id)))
        assert catalog is not None and catalog.status == "completed"
        assert [job.kind for job in jobs] == [
            "scanner_catalog_check",
            "scanner_cache_update",
        ]
        assert jobs[1].payload["prerequisite_job_id"] == catalog.id
        assert db.get(ScannerLifecycleState, "catalog").status == "completed"
        assert db.get(ScannerLifecycleState, "cache").job_id == jobs[1].id
    runtime.engine.dispose()


def test_catalog_lock_refresh_completes_without_queuing_a_doomed_cache_job() -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db", "trivy-db"],
        "blocked_tools": [],
    }
    with runtime.session_factory() as db:
        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            output = prepare_scanners(
                _request("prepare-continuation-lock-refresh"),
                runtime=runtime,
                db=db,
            )
        catalog = db.get(Job, output["catalog"]["job"]["id"])
        assert catalog is not None
        created = _enqueue_scanner_preparation_cache_continuation(
            db,
            catalog,
            {
                "components": [
                    {"component_id": "grype-db", "state": "requires_lock_refresh"},
                    {"component_id": "trivy-db", "state": "candidate_available"},
                ],
            },
        )
        db.commit()

        assert created is None
        assert [job.kind for job in db.scalars(select(Job))] == [
            "scanner_catalog_check",
        ]
        assert db.get(ScannerLifecycleState, "cache").job_id is None
    runtime.engine.dispose()


def test_prepare_scanners_rejects_an_unrepairable_runtime_prerequisite() -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": False,
        "required_component_ids": ["grype-db"],
        "blocked_tools": [{
            "id": "grype",
            "name": "Grype",
            "preparation_blocking_reasons": [
                "Grype binary is missing from the scanner image.",
            ],
        }],
    }
    try:
        with runtime.session_factory() as db:
            with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
                with pytest.raises(HTTPException) as blocked:
                    prepare_scanners(_request("prepare-command-unrepairable"), runtime=runtime, db=db)
            assert blocked.value.status_code == 409
            assert blocked.value.detail["code"] == "scanner_runtime_prerequisite_missing"
            assert blocked.value.detail["action"] == "repair_scanner_runtime"
            assert blocked.value.detail["context"] == {
                "tool_ids": ["grype"],
                "blocking_reasons": [
                    "Grype binary is missing from the scanner image.",
                ],
            }
            assert blocked.value.detail["safe_details"] == {
                "reason_code": "runtime_prerequisite_missing",
            }
            assert list(db.scalars(select(Job))) == []
    finally:
        runtime.engine.dispose()


def test_cache_update_accepts_only_sorted_curated_ids_and_rejects_rebinding() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db, patch(
        "kodesec_api.main._scanner_runtime_snapshot",
        return_value=_ScannerRuntimeSnapshot(tools={}, active_generation=None),
    ):
        output = update_scanner_cache(
            ScannerCacheUpdateRequest(component_ids=["grype-db", "trivy-db"]),
            _request("cache-command-0001"),
            runtime=runtime,
            db=db,
        )
        job = db.get(Job, output["job"]["id"])
        assert job is not None
        assert job.kind == "scanner_cache_update"
        assert job.payload["component_ids"] == ["grype-db", "trivy-db"]
        assert output["lifecycle"]["scope"] == "cache"
        assert output["lifecycle"]["status"] == "queued"
        with patch("kodesec_api.main._scanner_runtime_snapshot",
            side_effect=AssertionError("accepted cache command replay must not recheck or enqueue verification")):
            replay = update_scanner_cache(
                ScannerCacheUpdateRequest(component_ids=["grype-db", "trivy-db"]),
                _request("cache-command-0001"), runtime=runtime, db=db,
            )
        assert replay["job"]["id"] == job.id
        assert len(list(db.scalars(select(Job)))) == 1

        try:
            update_scanner_cache(
                ScannerCacheUpdateRequest(component_ids=["bearer-rules"]),
                _request("cache-command-0001"),
                runtime=runtime,
                db=db,
            )
        except HTTPException as exc:
            assert exc.status_code == 409
        else:  # pragma: no cover - explicit failure keeps the assertion clear
            raise AssertionError("idempotency-key rebinding was accepted")
    runtime.engine.dispose()


def test_signed_catalog_selection_is_fenced_at_admission_forwarding_and_replay() -> None:
    from kodesec_api.main import _scanner_lifecycle_digest, _lock_scanner_lifecycle_state

    runtime = _runtime()
    executor = WorkerExecutor(runtime, "catalog-selection-test")
    digest = "a" * 64
    with runtime.session_factory() as db, patch(
        "kodesec_api.main._scanner_runtime_snapshot",
        return_value=_ScannerRuntimeSnapshot(tools={}, active_generation=None),
    ):
        catalog = db.get(ScannerLifecycleState, "catalog")
        catalog.status = "completed"
        catalog.receipt = {"result": {"catalog_mode": "signed", "catalog_digest": digest}}
        db.commit()
        for selection in [None, "b" * 64]:
            with pytest.raises(HTTPException) as failure:
                update_scanner_cache(
                    ScannerCacheUpdateRequest(component_ids=["grype-db"], catalog_digest=selection),
                    _request("signed-refused"), runtime=runtime, db=db,
                )
            assert failure.value.detail["code"] == "scanner_catalog_selection_changed"
            assert len(list(db.scalars(select(Job)))) == 0
        with patch("kodesec_api.main._lock_scanner_lifecycle_state", wraps=_lock_scanner_lifecycle_state) as locks:
            accepted = update_scanner_cache(
                ScannerCacheUpdateRequest(component_ids=["grype-db"], catalog_digest=digest),
                _request("signed-selected"), runtime=runtime, db=db,
            )
        assert [call.args[1] for call in locks.call_args_list][-2:] == ["catalog", "cache"]
        job = db.get(Job, accepted["job"]["id"])
        job.attempt = 1
        db.commit()
        forwarded = executor._updater_request_for_job(ClaimedJob.from_model(job))
        assert forwarded["catalog_digest"] == digest
        assert forwarded["request_digest"] == _scanner_lifecycle_digest("cache_update", ["grype-db"], digest, job.payload["preparation_budget"])
        assert forwarded["request_digest"] != _scanner_lifecycle_digest("cache_update", ["grype-db"])
        catalog.receipt = {"result": {"catalog_mode": "signed", "catalog_digest": "b" * 64}}
        db.commit()
        replay = update_scanner_cache(
            ScannerCacheUpdateRequest(component_ids=["grype-db"], catalog_digest=digest),
            _request("signed-selected"), runtime=runtime, db=db,
        )
        assert replay["job"]["id"] == job.id
        assert job.payload["catalog_digest"] == digest
        with pytest.raises(HTTPException):
            update_scanner_cache(
                ScannerCacheUpdateRequest(component_ids=["grype-db"], catalog_digest="b" * 64),
                _request("signed-selected"), runtime=runtime, db=db,
            )
    runtime.engine.dispose()


def test_catalog_signature_mode_is_explicit_and_invalid_signatures_do_not_auto_retry() -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "catalog-mode-test")
    result = _catalog_result_with_lock_refresh()
    result.update(catalog_mode="signed", catalog_digest="a" * 64)
    assert executor._admit_catalog_result(result)["catalog_digest"] == "a" * 64
    for mode, digest in [("signed", None), ("source-reviewed/bundled", "a" * 64), ([], None), ("signed", "invalid")]:
        with pytest.raises(JobExecutionError):
            executor._admit_catalog_result({**result, "catalog_mode": mode, "catalog_digest": digest})
    job = _claimed_cache_job()
    record = {**_cache_record(job), "status": "failed", "result": None,
              "error_code": "scanner_data_catalog_invalid", "error_detail": "Signed scanner catalog verification failed."}
    with patch.object(executor, "_mark_updater_lifecycle_running"), patch.object(executor, "_set_progress"), \
         patch.object(executor, "_get_updater_operation", return_value=record), patch.object(executor, "_persist_updater_terminal_state"):
        with pytest.raises(JobExecutionError) as failure:
            executor._execute_updater(job, None)
    assert failure.value.code == "scanner_data_catalog_invalid"
    assert not failure.value.retryable
    runtime.engine.dispose()


@pytest.mark.parametrize("current_state", ["requires_lock_refresh", "candidate_available"])
def test_prepare_scanners_rechecks_retained_expiry_and_only_current_catalog_admits_cache(
    current_state: str,
) -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db", "trivy-db"],
        "blocked_tools": [],
    }
    with runtime.session_factory() as db:
        catalog_command = check_scanner_tools(_request("known-catalog-0001"), runtime=runtime, db=db)
        catalog = db.get(ScannerLifecycleState, "catalog")
        assert catalog is not None
        catalog_job = db.get(Job, catalog_command["job"]["id"])
        assert catalog_job is not None
        catalog_job.status = "completed"
        catalog_job.stage = "completed"
        catalog_job.progress = 100
        catalog.status = "completed"
        catalog.receipt = {
            "result": {
                "components": [
                    {"component_id": "trivy-db", "state": "candidate_available"},
                    {"component_id": "grype-db", "state": "requires_lock_refresh"},
                ],
            },
        }
        db.commit()

        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            admitted = prepare_scanners(
                _request("prepare-lock-refresh-0001"), runtime=runtime, db=db
            )
        assert admitted["required_component_ids"] == ["grype-db", "trivy-db"]
        assert admitted["cache"] is None
        fresh = db.get(Job, admitted["catalog"]["job"]["id"])
        assert fresh is not None and fresh.id != catalog_job.id
        assert catalog_job.status == "completed"
        assert [job.kind for job in db.scalars(select(Job).order_by(Job.id))] == [
            "scanner_catalog_check", "scanner_catalog_check",
        ]
        assert db.get(ScannerLifecycleState, "cache").job_id is None
        with patch("kodesec_api.main._scanner_preflight", side_effect=AssertionError("replay")):
            replay = prepare_scanners(_request("prepare-lock-refresh-0001"), runtime=runtime, db=db)
        assert replay["catalog"]["job"]["id"] == fresh.id

        # A source update can make the fresh check admissible. Rechecking an
        # unchanged expired lock still creates no cache work or download.
        created = _enqueue_scanner_preparation_cache_continuation(db, fresh, {
            "components": [
                {"component_id": "trivy-db", "state": "candidate_available"},
                {"component_id": "grype-db", "state": current_state},
            ],
        })
        db.commit()
        if current_state == "requires_lock_refresh":
            assert created is None
            assert db.get(ScannerLifecycleState, "cache").job_id is None
            assert len(list(db.scalars(select(Job)))) == 2
        else:
            assert created is not None and created.kind == "scanner_cache_update"
            assert created.payload["prerequisite_job_id"] == fresh.id
            assert created.payload["component_ids"] == ["grype-db", "trivy-db"]
            assert len(list(db.scalars(select(Job)))) == 3
    runtime.engine.dispose()


@pytest.mark.parametrize(
    ("catalog_job_status", "refresh_component"),
    [
        ("completed", "trivy-java-db"),
        ("cancelled", "grype-db"),
    ],
)
def test_prepare_scanners_ignores_unrelated_or_noncurrent_lock_refresh_evidence(
    catalog_job_status: str,
    refresh_component: str,
) -> None:
    runtime = _runtime()
    preflight = {
        "ready": False,
        "preparation_available": True,
        "required_component_ids": ["grype-db"],
        "blocked_tools": [],
    }
    with runtime.session_factory() as db:
        command = check_scanner_tools(_request("known-catalog-0002"), runtime=runtime, db=db)
        catalog = db.get(ScannerLifecycleState, "catalog")
        catalog_job = db.get(Job, command["job"]["id"])
        assert catalog is not None and catalog_job is not None
        catalog.status = "completed"
        catalog.receipt = {
            "result": {
                "components": [
                    {"component_id": refresh_component, "state": "requires_lock_refresh"},
                ],
            },
        }
        catalog_job.status = catalog_job_status
        catalog_job.stage = catalog_job_status
        catalog_job.progress = 100 if catalog_job_status == "completed" else 0
        db.commit()
        with patch("kodesec_api.main._scanner_preflight", return_value=preflight):
            output = prepare_scanners(
                _request(f"prepare-{catalog_job_status}-{refresh_component}"),
                runtime=runtime,
                db=db,
            )
        assert output["required_component_ids"] == ["grype-db"]
        assert output["cache"] is None
        assert len(list(db.scalars(select(Job)))) == 2
    runtime.engine.dispose()


def test_cache_rollback_requires_previous_good_and_queues_one_durable_command() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        with pytest.raises(HTTPException, match="previous-good") as missing:
            rollback_scanner_cache(
                _request("rollback-command-missing"),
                runtime=runtime,
                db=db,
            )
        assert missing.value.status_code == 409

        scanner_lifecycle(db=db)
        state = db.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.active_generation = "a" * 64
        state.previous_generation = "b" * 64
        db.commit()

        eligible = {
            "eligible": True,
            "reason_code": "eligible",
            "reason": "The previous verified cache generation is compatible and can be restored atomically.",
            "target_generation": "b" * 64,
        }
        with patch(
            "kodesec_api.main._scanner_cache_rollback_eligibility",
            return_value=eligible,
        ):
            output = rollback_scanner_cache(
                _request("rollback-command-0001"),
                runtime=runtime,
                db=db,
            )
        job = db.get(Job, output["job"]["id"])
        assert job is not None
        assert job.kind == "scanner_cache_rollback"
        assert job.payload["operation"] == "cache_rollback"
        assert job.payload["component_ids"] == []
        assert len(job.payload["request_digest"]) == 64
        assert output["lifecycle"]["status"] == "queued"

        job.status = "completed"
        state.active_generation = "b" * 64
        state.previous_generation = "a" * 64
        state.status = "completed"
        db.commit()

        currently_ineligible = {
            "eligible": False,
            "reason_code": "different_reviewed_locks",
            "reason": "The current previous generation uses different reviewed locks.",
            "target_generation": "a" * 64,
        }
        with patch(
            "kodesec_api.main._scanner_cache_rollback_eligibility",
            return_value=currently_ineligible,
        ):
            replay = rollback_scanner_cache(
                _request("rollback-command-0001"),
                runtime=runtime,
                db=db,
            )
        assert replay["job"]["id"] == job.id
        assert replay["job"]["status"] == "completed"
        assert replay["lifecycle"]["previous_generation"] == "a" * 64
        assert len(list(db.scalars(select(Job)))) == 1
    runtime.engine.dispose()


def test_cache_rollback_rejects_incompatible_target_without_a_job() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        scanner_lifecycle(db=db)
        state = db.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.active_generation = "a" * 64
        state.previous_generation = "b" * 64
        db.commit()

        blocked = {
            "eligible": False,
            "reason_code": "different_reviewed_locks",
            "reason": "The previous cache generation was built from different reviewed scanner locks. Prepare a verified cache for the current scanner catalog instead.",
            "target_generation": "b" * 64,
        }
        with patch(
            "kodesec_api.main._scanner_cache_rollback_eligibility",
            return_value=blocked,
        ):
            with pytest.raises(HTTPException) as rejected:
                rollback_scanner_cache(
                    _request("rollback-command-incompatible"),
                    runtime=runtime,
                    db=db,
                )

        assert rejected.value.status_code == 409
        assert rejected.value.detail["code"] == "scanner_cache_rollback_unavailable"
        assert rejected.value.detail["action"] == "prepare_scanners"
        assert rejected.value.detail["context"] == {
            "reason_code": "different_reviewed_locks",
            "target_generation": "b" * 64,
        }
        assert list(db.scalars(select(Job))) == []
        db.refresh(state)
        assert state.status == "idle"
        assert state.job_id is None
    runtime.engine.dispose()


def test_cache_rollback_preflight_classifies_malformed_scanner_evidence() -> None:
    runtime = _runtime()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={
                    "eligible": True,
                    "reason_code": "eligible",
                    "reason": "Generated malformed target.",
                    "target_generation": "not-a-digest",
                },
            )
        )
    )
    with runtime.session_factory() as db:
        scanner_lifecycle(db=db)
        state = db.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.previous_generation = "b" * 64
        db.commit()

        with patch("kodesec_api.main.httpx.Client", return_value=client):
            eligibility = _scanner_cache_rollback_eligibility(
                db,
                runtime.settings,
            )

        assert eligibility == {
            "eligible": False,
            "reason_code": "scanner_eligibility_invalid",
            "reason": "The scanner runtime did not return valid rollback eligibility. Refresh scanner status before retrying.",
            "target_generation": "b" * 64,
        }
        assert list(db.scalars(select(Job))) == []
    runtime.engine.dispose()


def test_cache_rollback_timeout_survives_api_and_offers_verification_retry_without_job() -> None:
    runtime = _runtime()
    timeout = {
        "eligible": False,
        "reason_code": "previous_generation_verification_timeout",
        "reason": "Verification of the previous scanner cache generation timed out. Retry verification; no cache state was changed.",
        "target_generation": "b" * 64,
        "verification": {
            "state": "timed_out", "target": "previous_good", "generation_id": "b" * 64,
            "phase": "validating", "component_id": "grype-db",
            "started_at": "2026-09-07T12:00:00+00:00", "last_activity_at": "2026-09-07T12:15:00+00:00",
            "bytes_verified": None, "bytes_total": None,
        },
    }
    client = httpx.Client(transport=httpx.MockTransport(
        lambda _request: httpx.Response(200, json=timeout),
    ))
    with runtime.session_factory() as db:
        scanner_lifecycle(db=db)
        state = db.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.previous_generation = timeout["target_generation"]
        db.commit()

        with patch("kodesec_api.main.httpx.Client", return_value=client):
            eligibility = _scanner_cache_rollback_eligibility(db, runtime.settings)
        assert eligibility == timeout

        with patch("kodesec_api.main._scanner_cache_rollback_eligibility", return_value=eligibility):
            with pytest.raises(HTTPException) as failure:
                rollback_scanner_cache(
                    _request("rollback-timeout-0001"), runtime=runtime, db=db,
                )
        assert failure.value.status_code == 409
        assert failure.value.detail["code"] == "scanner_cache_rollback_unavailable"
        assert failure.value.detail["message"] == timeout["reason"]
        assert failure.value.detail["action"] == "retry_scanner_verification"
        assert failure.value.detail["context"] == {
            "reason_code": timeout["reason_code"],
            "target_generation": timeout["target_generation"],
        }
        assert list(db.scalars(select(Job))) == []
        db.refresh(state)
        assert state.status == "idle"
        assert state.job_id is None
        assert state.previous_generation == timeout["target_generation"]
    runtime.engine.dispose()


def test_lifecycle_read_exposes_bounded_job_links_not_command_payloads() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        check_scanner_tools(_request("catalog-command-0002"), runtime=runtime, db=db)
        output = scanner_lifecycle(db=db)
        assert output["catalog"]["status"] == "queued"
        assert output["catalog"]["job_url"].startswith("/v1/jobs/")
        assert output["catalog"]["receipt"] == {}
        assert output["cache"]["status"] == "idle"
        assert output["cache"]["job_id"] is None
    runtime.engine.dispose()


def test_completed_catalog_receipt_does_not_override_cancelled_job_truth() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        command = check_scanner_tools(_request("catalog-cancellation-race"), runtime=runtime, db=db)
        job = db.get(Job, command["job"]["id"])
        state = db.get(ScannerLifecycleState, "catalog")
        assert job is not None and state is not None
        now = datetime.now(timezone.utc)
        job.status = "leased"
        job.stage = "source_blind_updater"
        job.attempt = 1
        job.lease_owner = "worker-test"
        job.lease_expires_at = now + timedelta(seconds=30)
        job.heartbeat_at = now
        job.revision += 1
        claimed = ClaimedJob.from_model(job)
        receipt = {
            "schema_version": 1,
            "operation_id": claimed.external_run_id,
            "request_digest": claimed.payload["request_digest"],
            "kind": "catalog_check",
            "requested_components": [],
            "attempt": claimed.attempt,
            "max_attempts": claimed.max_attempts,
            "updated_at": "2026-08-12T12:00:00Z",
            "result": _catalog_result_with_lock_refresh(),
        }
        state.status = "completed"
        state.receipt = receipt
        state.revision += 1
        db.add_all((job, state))
        db.flush()
        request_cancellation(db, job.id, now=now)
        db.commit()

        cancelling = scanner_lifecycle(db=db)["catalog"]
        assert cancelling["status"] == "cancelling"
        assert cancelling["receipt"] == receipt

    with patch("kodesec_api.jobs.repository._time", return_value=now):
        WorkerExecutor(runtime, "worker-test")._finalize_cancelled(claimed)

    with runtime.session_factory() as db:
        job = db.get(Job, claimed.id)
        state = db.get(ScannerLifecycleState, "catalog")
        assert job is not None and job.status == "cancelled"
        assert job.detail == (
            "Cancellation won the durable job race after the source-blind updater completed; "
            "the verified lifecycle receipt remains authoritative."
        )
        assert state is not None and state.status == "cancelled"
        assert state.receipt == receipt
        output = scanner_lifecycle(db=db)["catalog"]
        assert output["status"] == "cancelled"
        assert output["receipt"] == receipt
    runtime.engine.dispose()


def _claimed_cache_job() -> ClaimedJob:
    from kodesec_api.main import _scanner_lifecycle_digest

    return ClaimedJob(
        id=1,
        kind="scanner_cache_update",
        status="running",
        stage="source_blind_updater",
        attempt=1,
        max_attempts=3,
        scan_id=None,
        finding_id=None,
        external_run_id="10000000-0000-4000-8000-000000000001",
        payload={
            "v": 1,
            "operation": "cache_update",
            "request_digest": _scanner_lifecycle_digest("cache_update", ["grype-db"]),
            "component_ids": ["grype-db"],
        },
        checkpoint={},
    )


def _cache_record(job: ClaimedJob) -> dict:
    timestamp = "2026-08-12T12:00:00Z"
    return {
        "schema_version": 1,
        "operation_id": job.external_run_id,
        "request_digest": job.payload["request_digest"],
        "kind": "cache_update",
        "requested_components": ["grype-db"],
        "status": "completed",
        "stage": "completed",
        "attempt": 1,
        "max_attempts": 3,
        "cancel_requested_at": None,
        "created_at": timestamp,
        "started_at": timestamp,
        "finished_at": timestamp,
        "updated_at": timestamp,
        "last_activity_at": timestamp,
        "activity": None,
        "result": {
            "kind": "cache",
            "active": {"generation_id": "a" * 64, "manifest_sha256": "b" * 64},
            "previous_good": None,
            "updated_components": ["grype-db"],
        },
        "error_code": None,
        "error_detail": None,
    }


@pytest.mark.parametrize("kind", ["scanner_cache_update", "scanner_cache_rollback"])
def test_cache_cancellation_racing_unobserved_commit_retains_completed_receipt(kind) -> None:
    runtime = _runtime()
    claimed, now = _persist_cache_cancellation_job(runtime, kind=kind)
    completed = _cache_record(claimed)
    completed["kind"] = claimed.payload["operation"]
    completed["requested_components"] = claimed.payload["component_ids"]
    completed["result"]["updated_components"] = claimed.payload["component_ids"]
    completed["result"]["previous_good"] = {
        "generation_id": "c" * 64, "manifest_sha256": "d" * 64,
    }
    committing = {
        **completed, "status": "running", "stage": "committing",
        "finished_at": None, "result": None,
    }
    requests = []

    def updater_response(request):
        requests.append(request.method)
        assert request.url.path == f"/operations/{claimed.external_run_id}"
        assert request.headers["X-KodeSec-Request-Digest"] == claimed.payload["request_digest"]
        return httpx.Response(200, json=committing if request.method == "DELETE" else completed)

    executor = WorkerExecutor(
        runtime, "worker-test",
        updater_client_factory=lambda: httpx.Client(
            base_url="http://updater.fixture", transport=httpx.MockTransport(updater_response),
        ),
    )
    # The API still observes the earlier cancellable stage. Publication has
    # crossed the updater's independent commit boundary before DELETE arrives.
    with runtime.session_factory() as db, patch("kodesec_api.jobs.repository._time", return_value=now):
        assert cancel_job(claimed.id, _request("cache-commit-race"), db=db)["status"] == "cancelling"
    with patch("kodesec_api.jobs.execution.time.sleep"):
        record = executor._cancel_updater_if_present(claimed, LeaseMonitor(runtime, claimed, "worker-test"))
    assert requests == ["DELETE", "GET"]
    assert record["status"] == "completed"
    with patch("kodesec_api.jobs.repository._time", return_value=now):
        executor._finalize_cancelled(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, claimed.id)
        state = db.get(ScannerLifecycleState, "cache")
        assert job.status == "cancelled" and job.cancel_requested_at is not None
        assert "after the source-blind updater completed" in job.detail
        assert state.status == "cancelled"
        assert state.receipt["result"] == completed["result"]
        assert state.active_generation == "a" * 64
        assert state.previous_generation == "c" * 64
        public = scanner_lifecycle(db=db)["cache"]
        assert public["status"] == "cancelled"
        assert public["active_generation"] == state.active_generation
        assert public["previous_generation"] == state.previous_generation
        assert public["receipt"]["result"]["active"]["generation_id"] == state.active_generation
    runtime.engine.dispose()


def test_worker_admits_exact_empty_component_rollback_receipt() -> None:
    runtime = _runtime()
    from kodesec_api.main import _scanner_lifecycle_digest

    claimed = ClaimedJob(
        id=2,
        kind="scanner_cache_rollback",
        status="running",
        stage="source_blind_updater",
        attempt=1,
        max_attempts=3,
        scan_id=None,
        finding_id=None,
        external_run_id="20000000-0000-4000-8000-000000000002",
        payload={
            "v": 1,
            "operation": "cache_rollback",
            "request_digest": _scanner_lifecycle_digest("cache_rollback", []),
            "component_ids": [],
        },
        checkpoint={},
    )
    record = _cache_record(claimed)
    record["kind"] = "cache_rollback"
    record["requested_components"] = []
    record["result"]["updated_components"] = []
    accepted = WorkerExecutor(runtime, "worker-test")._admit_updater_record(
        claimed,
        httpx.Response(200, json=record),
        allowed_attempts={1},
    )
    assert accepted["kind"] == "cache_rollback"
    assert accepted["result"]["updated_components"] == []
    runtime.engine.dispose()


def test_worker_admits_bounded_cache_activity_and_maps_honest_progress() -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "worker-test")
    claimed = _claimed_cache_job()
    record = _cache_record(claimed)
    record.update(
        {
            "status": "running",
            "stage": "downloading",
            "finished_at": None,
            "result": None,
            "activity": {
                "component_id": "grype-db",
                "component_index": 1,
                "component_total": 1,
                "bytes_completed": 50,
                "bytes_total": 100,
            },
        }
    )

    accepted = executor._admit_updater_record(
        claimed,
        httpx.Response(200, json=record),
        allowed_attempts={1},
    )
    assert accepted["activity"]["bytes_completed"] == 50
    assert 25 < executor._updater_progress(accepted) < 71
    assert "grype-db (1 of 1)" in executor._updater_detail(accepted)

    record["activity"]["bytes_completed"] = 101
    with pytest.raises(JobExecutionError, match="outside its bound"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, json=record),
            allowed_attempts={1},
        )
    record["activity"].update(
        {
            "component_id": "trivy-db",
            "bytes_completed": 50,
        }
    )
    with pytest.raises(JobExecutionError, match="requested cache operation"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, json=record),
            allowed_attempts={1},
        )
    runtime.engine.dispose()


def test_worker_admits_exact_active_generation_validation_activity() -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "worker-test")
    claimed = _claimed_cache_job()
    record = _cache_record(claimed)
    record.update(
        {
            "status": "running",
            "stage": "validating_active",
            "finished_at": None,
            "result": None,
            "activity": {
                "component_id": "bearer-rules",
                "component_index": 1,
                "component_total": 6,
                "bytes_completed": 4096,
                "bytes_total": 8192,
            },
        }
    )

    accepted = executor._admit_updater_record(
        claimed,
        httpx.Response(200, json=record),
        allowed_attempts={1},
    )

    assert accepted["stage"] == "validating_active"
    assert accepted["activity"] == record["activity"]
    assert executor._updater_progress(accepted) == 18
    assert "bearer-rules (1 of 6)" in executor._updater_detail(accepted)
    runtime.engine.dispose()


def test_updater_receipt_admission_rejects_unknown_fields_paths_and_oversize() -> None:
    runtime = _runtime()
    executor = WorkerExecutor(runtime, "worker-test")
    claimed = _claimed_cache_job()
    accepted = executor._admit_updater_record(
        claimed,
        httpx.Response(200, json=_cache_record(claimed)),
        allowed_attempts={1},
    )
    assert accepted["result"]["active"]["generation_id"] == "a" * 64

    missing_activity = _cache_record(claimed)
    missing_activity.pop("last_activity_at")
    missing_activity.pop("activity")
    with pytest.raises(JobExecutionError, match="strict local schema"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, json=missing_activity),
            allowed_attempts={1},
        )

    unknown = _cache_record(claimed)
    unknown["command"] = ["sh", "-c", "unsafe"]
    with pytest.raises(JobExecutionError, match="strict local schema"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, json=unknown),
            allowed_attempts={1},
        )

    path_value = _cache_record(claimed)
    path_value["result"]["active"]["generation_id"] = "/private/source"
    with pytest.raises(JobExecutionError, match="SHA-256"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, json=path_value),
            allowed_attempts={1},
        )

    with pytest.raises(JobExecutionError, match="16 KiB"):
        executor._admit_updater_record(
            claimed,
            httpx.Response(200, content=b"{" + b" " * (16 * 1024) + b"}"),
            allowed_attempts={1},
        )
    runtime.engine.dispose()
