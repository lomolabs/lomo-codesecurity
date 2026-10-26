from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event, current_thread
from unittest.mock import Mock, patch
from types import SimpleNamespace
import asyncio
import hashlib
import json

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import StaticPool

from kodesec_api.db import Base, Runtime, initialize_database
from kodesec_api.advisor import providers
from kodesec_api.jobs.execution import (
    ClaimedJob,
    ExecutionCompletion,
    JobExecutionError,
    LeaseMonitor,
    WorkerExecutor,
    _canonical_json_bytes,
    _scanner_manifest_digest,
    _scanner_poll_interval_seconds,
    _updater_poll_interval_seconds,
    _scanner_request_digest,
    _strict_scanner_finding,
    _validated_scan_coverage_snapshot,
    _validated_scan_source_snapshot_digest,
    _validated_scan_target,
)


def test_updater_poll_backs_off_only_for_unchanged_meaningful_activity() -> None:
    previous = {
        "status": "running",
        "stage": "downloading",
        "updated_at": "2026-08-31T14:15:20Z",
        "last_activity_at": "2026-08-31T14:15:15Z",
        "activity": {"component_id": "trivy-java-db", "component_index": 6},
    }
    heartbeat_only = {**previous, "updated_at": "2026-08-31T14:15:25Z"}
    real_activity = {**heartbeat_only, "last_activity_at": "2026-08-31T14:15:25Z"}

    assert _updater_poll_interval_seconds(previous, heartbeat_only) == 10.0
    assert _updater_poll_interval_seconds(heartbeat_only, real_activity) == 2.0


from kodesec_api.jobs.commands import (
    InvalidScanCommandSnapshot,
    ScanCommandKindMismatch,
    UnsupportedScanCommandVersion,
    scan_command_snapshot,
)
from kodesec_api.jobs.advisor import triage_finding_sync
from kodesec_api.jobs.liveness import record_worker_heartbeat, worker_heartbeat_is_fresh
from kodesec_api.jobs.repository import claim_next_job, enqueue_job, mark_job_running, request_cancellation
from kodesec_api.models import Finding, GatePolicy, Job, Project, Scan, ScannerLifecycleState, ScannerToolState
from kodesec_api.models import RuntimeConfig
from kodesec_api.main import (
    INCOMPLETE_GATE_REASON,
    _advisor_snapshot,
    update_finding_lifecycle,
)
from kodesec_api.schemas import FindingLifecycleUpdate
from kodesec_api.artifact_boundary import ARTIFACT_BOUNDARY_MARKER
from kodesec_api.artifact_boundary import ArtifactBoundaryError
from kodesec_api.settings import Settings
from kodesec_api.worker import run_worker


def _runtime(postgres_engine, tmp_path) -> Runtime:
    initialize_database(postgres_engine)
    return Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL=str(postgres_engine.url),
            SCANNER_URL="http://scanner:8091",
            OLLAMA_BASE_URL="http://127.0.0.1:11434",
            KODESEC_ALLOWED_ROOTS="/workspaces",
            KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
            KODESEC_WORKER_POLL_SECONDS=0.05,
            KODESEC_ADVISOR_GRANT_SECRET="fixture-worker-connector-grant-" * 2,
        ),
        engine=postgres_engine,
    )


def test_worker_imports_and_requires_current_artifact_boundary_readiness(tmp_path) -> None:
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
            KODESEC_ALLOWED_ROOTS="/workspaces",
            KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        ),
        engine=engine,
    )
    try:
        with patch(
            "kodesec_api.settings.Settings.validate_worker_configuration"
        ), patch("kodesec_api.worker.install_outbox_listeners"), patch(
            "kodesec_api.worker.init_db", return_value="fixture-current"
        ):
            with pytest.raises(
                RuntimeError,
                match="durable worker publication boundaries are not initialized",
            ):
                run_worker(runtime, once=True, worker_id="worker-readiness-fixture")
    finally:
        runtime.engine.dispose()


def test_unchanged_scanner_polling_backs_off_and_resets_on_status_change() -> None:
    intervals = [
        _scanner_poll_interval_seconds(
            base_seconds=0.5,
            heartbeat_seconds=10.0,
            unchanged_polls=count,
        )
        for count in range(10)
    ]

    assert intervals == [0.5, 1.0, 2.0, 4.0, 8.0, 10.0, 10.0, 10.0, 10.0, 10.0]
    assert sum(intervals) == 65.5
    elapsed = 0.0
    poll_count = 0
    while elapsed < 446.0:
        elapsed += _scanner_poll_interval_seconds(
            base_seconds=0.5,
            heartbeat_seconds=10.0,
            unchanged_polls=poll_count,
        )
        poll_count += 1
    assert poll_count < 50

    publish = Mock()
    request_payload = {
        "run_id": _FIXTURE_RUN_ID,
        "scan_id": 1,
        "repo_path": "/workspaces/project",
        "mode": "full",
        "base_ref": None,
        "head_ref": None,
        "enabled_tools": ["trivy"],
    }
    states = iter(
        [
            _run_state("queued"),
            _run_state("running"),
            _run_state("running"),
            _run_state("completed"),
        ]
    )
    wait = Mock(return_value=False)
    monitor = SimpleNamespace(
        cancel_requested=SimpleNamespace(wait=wait),
        raise_if_unusable=Mock(),
    )

    executor = SimpleNamespace(
        settings=SimpleNamespace(
            worker_poll_seconds=0.5,
            worker_heartbeat_seconds=10.0,
        ),
        _get_scanner_run=Mock(side_effect=states),
        _set_progress=publish,
    )
    terminal = WorkerExecutor._wait_for_scanner(
        executor,
        SimpleNamespace(id=1, external_run_id=_FIXTURE_RUN_ID),
        _run_state("queued"),
        monitor,
        request_payload,
        Mock(),
    )

    assert terminal["status"] == "completed"
    assert [call.args[0] for call in wait.call_args_list] == [0.5, 1.0, 0.5, 1.0]
    assert [call.kwargs["detail"] for call in publish.call_args_list] == [
        "Scanner run was admitted and is waiting for the local scanner executor.",
        (
            "Scanner runtime is executing the enabled tools. "
            "Tool-level progress is unavailable; elapsed time and scanner state freshness remain visible."
        ),
    ]


def _scan_payload(
    *,
    use_ai: bool = False,
    target_path: str | None = None,
    target_kind: str | None = None,
) -> dict:
    return {
        "v": 1,
        "operation": "scan",
        "request_digest": "a" * 64,
        "use_ai": use_ai,
        "enabled_tools": ["trivy"],
        **({"target_path": target_path} if target_path is not None else {}),
        **({"target_kind": target_kind} if target_kind is not None else {}),
        "advisor": {
            "ai_mode": "on" if use_ai else "off",
            "ollama_base_url": "http://127.0.0.1:11434",
            "ollama_model": "fixture-model",
            "ollama_thinking": False,
            "auto_triage_limit": 5,
        },
    }


def _seed_scan_job(
    runtime: Runtime,
    *,
    use_ai: bool = False,
    max_attempts: int = 1,
    target_path: str | None = None,
    target_kind: str | None = None,
) -> int:
    with runtime.session_factory() as db, db.begin():
        project = Project(name=f"project-{use_ai}", repo_path="/workspaces/project", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="pending", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        result = enqueue_job(
            db,
            kind="scan",
            title=f"Scan #{scan.id}",
            client_id="browser:test",
            idempotency_key=f"scan-{scan.id}-fixture",
            payload=_scan_payload(
                use_ai=use_ai,
                target_path=target_path,
                target_kind=target_kind,
            ),
            scan_id=scan.id,
            external_run_id="00000000-0000-4000-8000-000000000001",
            max_attempts=max_attempts,
        )
        return result.job.id


def _claim(runtime: Runtime, worker_id: str = "worker-test") -> ClaimedJob:
    with runtime.session_factory() as db, db.begin():
        model = claim_next_job(db, worker_id=worker_id, lease_seconds=30)
        assert model is not None
        return ClaimedJob.from_model(model)


def _claim_exhausted(runtime: Runtime) -> ClaimedJob:
    expired_start = datetime.now(timezone.utc) - timedelta(seconds=20)
    with runtime.session_factory() as db, db.begin():
        first = claim_next_job(db, worker_id="worker-crashed", lease_seconds=10, now=expired_start)
        assert first is not None
        mark_job_running(
            db,
            first.id,
            worker_id="worker-crashed",
            attempt=first.attempt,
            stage="scanner",
            now=expired_start,
        )
    return _reclaim_exhausted(runtime)


def _reclaim_exhausted(runtime: Runtime) -> ClaimedJob:
    with runtime.session_factory() as db, db.begin():
        recovered = claim_next_job(db, worker_id="worker-recovery", lease_seconds=30)
        assert recovered is not None and recovered.stage == "recovery_exhausted"
        return ClaimedJob.from_model(recovered)


def _malformed_scan_runtime(
    tmp_path,
    *,
    use_ai: object,
    stage: str,
    job_kind: str = "scan",
    operation: str = "scan",
    version: object = 1,
) -> tuple[Runtime, ClaimedJob]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+pysqlite:///:memory:",
            KODESEC_ALLOWED_ROOTS="/workspaces",
            KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        ),
        engine=engine,
    )
    with runtime.session_factory() as db, db.begin():
        project = Project(
            name=f"malformed-{stage}",
            repo_path=f"/workspaces/{stage}",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            mode="full",
            status="pending",
            scanner_summary={},
            gate_reasons=[],
        )
        db.add(scan)
        db.flush()
        job = Job(
            kind=job_kind,
            title="Malformed immutable scan snapshot",
            status="leased",
            stage=stage,
            payload={"v": version, "operation": operation, "use_ai": use_ai},
            checkpoint={"scanner_persisted": True} if stage == "recovery_exhausted" else {},
            attempt=1,
            max_attempts=1,
            revision=2,
            lease_owner="worker-recovery" if stage == "recovery_exhausted" else "worker-test",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
            heartbeat_at=datetime.now(timezone.utc),
            scan_id=scan.id,
            external_run_id=(
                "00000000-0000-4000-8000-000000000002"
                if stage == "recovery_exhausted"
                else "00000000-0000-4000-8000-000000000001"
            ),
        )
        db.add(job)
        db.flush()
        claimed = ClaimedJob.from_model(job)
    return runtime, claimed


def _malformed_scan_durable_state(runtime: Runtime, claimed: ClaimedJob) -> dict:
    with runtime.session_factory() as db:
        job = db.get(Job, claimed.id)
        scan = db.get(Scan, claimed.scan_id)
        assert job is not None and scan is not None
        return {
            "job": {
                "status": job.status,
                "stage": job.stage,
                "revision": job.revision,
                "attempt": job.attempt,
                "heartbeat_at": job.heartbeat_at,
                "started_at": job.started_at,
                "lease_owner": job.lease_owner,
                "lease_expires_at": job.lease_expires_at,
                "completed_at": job.completed_at,
                "error_code": job.error_code,
                "error_detail": job.error_detail,
                "payload": dict(job.payload),
                "checkpoint": dict(job.checkpoint),
            },
            "scan": {
                "status": scan.status,
                "revision": scan.revision,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error": scan.error,
                "scanner_summary": dict(scan.scanner_summary),
            },
        }


def test_scan_command_snapshot_uses_only_exact_json_booleans() -> None:
    with pytest.raises(InvalidScanCommandSnapshot):
        scan_command_snapshot("scan", {"v": 1, "operation": "scan"})
    assert (
        scan_command_snapshot(
            "scan",
            {"v": 1, "operation": "scan", "use_ai": False}
        ).use_ai
        is False
    )
    assert (
        scan_command_snapshot(
            "scan",
            {"v": 1, "operation": "scan", "use_ai": True}
        ).use_ai
        is True
    )
    for payload in (None, [], "scan", True):
        with pytest.raises(InvalidScanCommandSnapshot):
            scan_command_snapshot("scan", payload)
    assert scan_command_snapshot(
        "advisor", {"v": 1, "operation": "advisor_finding"}
    ) is None
    assert scan_command_snapshot(
        "scanner_catalog_check", {"v": 1, "operation": "catalog_check"}
    ) is None
    with pytest.raises(ScanCommandKindMismatch):
        scan_command_snapshot(
            "scan", {"v": 1, "operation": "advisor_finding", "use_ai": False}
        )
    with pytest.raises(ScanCommandKindMismatch):
        scan_command_snapshot(
            "advisor", {"v": 1, "operation": "scan", "use_ai": False}
        )
    with pytest.raises(UnsupportedScanCommandVersion):
        scan_command_snapshot(
            "scan", {"v": True, "operation": "scan", "use_ai": False}
        )


@pytest.mark.parametrize(
    ("job_kind", "operation", "version", "use_ai", "expected_code"),
    [
        ("scan", "scan", 1, 1, InvalidScanCommandSnapshot.code),
        ("scan", "scan", 1, "true", InvalidScanCommandSnapshot.code),
        ("scan", "scan", 1, None, InvalidScanCommandSnapshot.code),
        ("scan", "scan", 1, [], InvalidScanCommandSnapshot.code),
        ("scan", "scan", 1, {}, InvalidScanCommandSnapshot.code),
        ("maintenance", "scan", 1, False, ScanCommandKindMismatch.code),
        ("scan", "advisor_finding", 1, False, ScanCommandKindMismatch.code),
        ("scan", "scan", 2, False, UnsupportedScanCommandVersion.code),
    ],
    ids=[
        "integer",
        "string",
        "null",
        "array",
        "object",
        "operation-scan-kind-mismatch",
        "kind-scan-operation-mismatch",
        "version",
    ],
)
def test_worker_rejects_malformed_scan_ai_snapshot_before_work(
    tmp_path,
    job_kind: str,
    operation: str,
    version: object,
    use_ai: object,
    expected_code: str,
) -> None:
    scanner_factory = Mock()
    runtime, job = _malformed_scan_runtime(
        tmp_path,
        use_ai=use_ai,
        stage="starting",
        job_kind=job_kind,
        operation=operation,
        version=version,
    )
    executor = WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=scanner_factory,
    )
    durable_snapshot = _malformed_scan_durable_state(runtime, job)
    fixture_now = datetime.now(timezone.utc)
    with patch(
        "kodesec_api.jobs.repository._time", return_value=fixture_now
    ), patch("kodesec_api.jobs.execution.LeaseMonitor") as lease_monitor, patch.object(
        executor, "_mark_running"
    ) as mark_running, patch.object(
        executor, "_triage_scan_findings"
    ) as advisor_work, patch.object(
        runtime, "session_factory", wraps=runtime.session_factory
    ) as session_factory:
        executor.execute(job)
    lease_monitor.assert_not_called()
    mark_running.assert_not_called()
    scanner_factory.assert_not_called()
    advisor_work.assert_not_called()
    session_factory.assert_called_once()
    terminal = _malformed_scan_durable_state(runtime, job)
    assert terminal["scan"] == durable_snapshot["scan"]
    assert terminal["job"] == {
        **durable_snapshot["job"],
        "status": "failed",
        "stage": "failed",
        "revision": durable_snapshot["job"]["revision"] + 1,
        "lease_owner": None,
        "lease_expires_at": None,
        "completed_at": terminal["job"]["completed_at"],
        "error_code": expected_code,
        "error_detail": terminal["job"]["error_detail"],
    }
    assert terminal["job"]["completed_at"] is not None
    assert terminal["job"]["error_detail"]


def test_cancelling_scan_does_not_reinterpret_immutable_ai_snapshot() -> None:
    executor = WorkerExecutor(
        SimpleNamespace(settings=SimpleNamespace()),
        "worker-test",
    )
    job = ClaimedJob(
        id=3,
        kind="scan",
        status="cancelling",
        stage="cancelling",
        attempt=1,
        max_attempts=1,
        scan_id=1,
        finding_id=None,
        external_run_id="00000000-0000-4000-8000-000000000003",
        payload={"v": 1, "operation": "scan", "use_ai": "true"},
        checkpoint={},
    )
    monitor = Mock()
    with patch("kodesec_api.jobs.execution.LeaseMonitor", return_value=monitor), patch(
        "kodesec_api.jobs.execution.scan_command_snapshot"
    ) as interpret_snapshot, patch.object(
        executor, "_cancel_external_if_present"
    ) as cancel_external, patch.object(
        executor, "_finalize_cancelled_safely", return_value=True
    ) as finalize_cancelled:
        executor.execute(job)
    interpret_snapshot.assert_not_called()
    monitor.start.assert_called_once_with()
    cancel_external.assert_called_once_with(job, monitor)
    monitor.stop.assert_called_once_with()
    finalize_cancelled.assert_called_once_with(job)


def test_exhausted_recovery_rejects_malformed_scan_snapshot_before_work(tmp_path) -> None:
    scanner_factory = Mock()
    runtime, job = _malformed_scan_runtime(
        tmp_path,
        use_ai="true",
        stage="recovery_exhausted",
    )
    executor = WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=scanner_factory,
    )
    durable_snapshot = _malformed_scan_durable_state(runtime, job)
    fixture_now = datetime.now(timezone.utc)
    with patch(
        "kodesec_api.jobs.repository._time", return_value=fixture_now
    ), patch("kodesec_api.jobs.execution.LeaseMonitor") as lease_monitor, patch.object(
        executor, "_mark_running"
    ) as mark_running, patch.object(
        executor, "_load_checkpoint"
    ) as load_checkpoint, patch.object(
        executor, "_triage_scan_findings"
    ) as advisor_work, patch.object(
        executor, "fail_exhausted"
    ) as fail_exhausted, patch.object(
        runtime, "session_factory", wraps=runtime.session_factory
    ) as session_factory:
        executor.recover_exhausted(job)
    lease_monitor.assert_not_called()
    mark_running.assert_not_called()
    load_checkpoint.assert_not_called()
    scanner_factory.assert_not_called()
    advisor_work.assert_not_called()
    fail_exhausted.assert_not_called()
    session_factory.assert_called_once()
    terminal = _malformed_scan_durable_state(runtime, job)
    assert terminal["scan"] == durable_snapshot["scan"]
    assert terminal["job"]["status"] == "failed"
    assert terminal["job"]["stage"] == "failed"
    assert terminal["job"]["revision"] == durable_snapshot["job"]["revision"] + 1
    assert terminal["job"]["error_code"] == InvalidScanCommandSnapshot.code
    assert terminal["job"]["lease_owner"] is None
    assert terminal["job"]["lease_expires_at"] is None


@pytest.mark.parametrize(
    ("job_kind", "operation", "route_name"),
    [
        ("advisor", "advisor_finding", "_execute_advisor_finding"),
        ("scanner_catalog_check", "catalog_check", "_execute_updater"),
    ],
    ids=["advisor", "updater"],
)
def test_scan_snapshot_preflight_preserves_legitimate_durable_routing(
    tmp_path,
    job_kind: str,
    operation: str,
    route_name: str,
) -> None:
    runtime, job = _malformed_scan_runtime(
        tmp_path,
        use_ai=False,
        stage="starting",
        job_kind=job_kind,
        operation=operation,
    )
    executor = WorkerExecutor(runtime, "worker-test")
    monitor = Mock()
    fixture_now = datetime.now(timezone.utc)
    with patch(
        "kodesec_api.jobs.repository._time", return_value=fixture_now
    ), patch(
        "kodesec_api.jobs.execution.LeaseMonitor", return_value=monitor
    ), patch.object(
        executor,
        route_name,
        return_value=ExecutionCompletion(detail="Legitimate durable route completed."),
    ) as routed:
        executor.execute(job)
    routed.assert_called_once_with(job, monitor)
    monitor.start.assert_called_once_with()
    monitor.raise_if_unusable.assert_called_once_with()
    with runtime.session_factory() as db:
        persisted = db.get(Job, job.id)
        assert persisted is not None
        assert persisted.status == "completed"
        assert persisted.error_code is None


def test_malformed_scan_is_terminally_contained_and_worker_claims_next_job(tmp_path) -> None:
    runtime, malformed = _malformed_scan_runtime(
        tmp_path,
        use_ai=False,
        stage="queued",
        job_kind="advisor",
        operation="scan",
    )
    with runtime.session_factory() as db, db.begin():
        malformed_row = db.get(Job, malformed.id)
        assert malformed_row is not None
        malformed_row.stage = "queued"
        malformed_row.lease_owner = "worker-contained"
        continuation = enqueue_job(
            db,
            kind="maintenance",
            title="Worker continuation after malformed scan",
            client_id="browser:test",
            idempotency_key="malformed-scan-continuation",
            payload={"v": 1, "operation": "unsupported_fixture"},
            max_attempts=1,
        ).job
        continuation.status = "leased"
        continuation.stage = "queued"
        continuation.attempt = 1
        continuation.lease_owner = "worker-contained"
        continuation.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        continuation.heartbeat_at = datetime.now(timezone.utc)
        continuation_job_id = continuation.id
        db.add(RuntimeConfig(key=ARTIFACT_BOUNDARY_MARKER, value="completed"))

    stop = Event()

    class ContinuingExecutor(WorkerExecutor):
        def execute(self, job: ClaimedJob) -> None:
            super().execute(job)
            if job.id == continuation_job_id:
                stop.set()

    pending_job_ids = [malformed.id, continuation_job_id]

    def claim_fixture(db, **_kwargs):
        return db.get(Job, pending_job_ids.pop(0))

    fixture_now = datetime.now(timezone.utc)
    with patch(
        "kodesec_api.jobs.repository._time", return_value=fixture_now
    ), patch(
        "kodesec_api.settings.Settings.validate_worker_configuration"
    ), patch("kodesec_api.worker.WorkerExecutor", ContinuingExecutor), patch(
        "kodesec_api.worker.worker_ollama_available_sync",
        return_value=(False, [], "disabled"),
    ), patch(
        "kodesec_api.worker.install_outbox_listeners"
    ), patch(
        "kodesec_api.worker.init_db", return_value="fixture-current"
    ), patch(
        "kodesec_api.worker.claim_next_job", side_effect=claim_fixture
    ), patch(
        # This fixture deliberately shares one SQLite connection. An unrelated
        # publisher's read-session close can roll back the worker transaction.
        # PostgreSQL worker-loop tests retain the actual background publisher.
        "kodesec_api.worker._AdvisorReceiptPublisher"
    ) as publisher:
        assert run_worker(runtime, stop_event=stop, worker_id="worker-contained") == 2
    publisher.assert_called_once_with(runtime, "worker-contained")
    publisher.return_value.start.assert_called_once_with()
    publisher.return_value.stop.assert_called_once_with()

    with runtime.session_factory() as db:
        malformed_row = db.get(Job, malformed.id)
        continuation_row = db.get(Job, continuation_job_id)
        scan = db.get(Scan, malformed.scan_id)
        assert malformed_row is not None and malformed_row.status == "failed"
        assert malformed_row.error_code == ScanCommandKindMismatch.code
        assert continuation_row is not None and continuation_row.status == "failed"
        assert continuation_row.error_code == "unsupported_operation"
        assert scan is not None and scan.status == "pending" and scan.revision == 1


def _client_factory(handler) -> callable:
    def factory() -> httpx.Client:
        return httpx.Client(
            base_url="http://scanner:8091",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        )

    return factory


def _updater_client_factory(handler) -> callable:
    def factory() -> httpx.Client:
        return httpx.Client(
            base_url="http://scanner-updater:8092",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        )

    return factory


def _seed_updater_job(
    runtime: Runtime,
    *,
    kind: str = "scanner_cache_update",
    component_ids: list[str] | None = None,
    max_attempts: int = 3,
) -> int:
    operation = {
        "scanner_catalog_check": "catalog_check",
        "scanner_cache_update": "cache_update",
        "scanner_cache_rollback": "cache_rollback",
    }[kind]
    selected = (
        []
        if operation in {"catalog_check", "cache_rollback"}
        else sorted(component_ids or ["grype-db"])
    )
    from kodesec_api.main import _scanner_lifecycle_digest
    from kodesec_api.preparation_budget import issue_budget
    budget = issue_budget() if operation != "cache_rollback" else None

    with runtime.session_factory() as db, db.begin():
        result = enqueue_job(
            db,
            kind=kind,
            title=f"Updater {operation}",
            client_id="browser:test",
            idempotency_key=f"updater-{operation}-fixture",
            payload={
                "v": 1,
                "operation": operation,
                "request_digest": _scanner_lifecycle_digest(operation, selected, preparation_budget=budget),
                **({"preparation_budget": budget.model_dump()} if budget is not None else {}),
                "component_ids": selected,
            },
            external_run_id="10000000-0000-4000-8000-000000000001",
            max_attempts=max_attempts,
        )
        scope = "catalog" if operation == "catalog_check" else "cache"
        state = db.get(ScannerLifecycleState, scope)
        assert state is not None
        state.status = "queued"
        state.job_id = result.job.id
        state.revision += 1
        state.receipt = {}
        state.error_code = None
        state.error_detail = None
        state.started_at = None
        state.completed_at = None
        db.add(state)
        return result.job.id


def _operation_record(
    claimed: ClaimedJob,
    *,
    status: str,
    result: dict | None = None,
    error_code: str | None = None,
    error_detail: str | None = None,
) -> dict:
    timestamp = (claimed.payload["preparation_budget"]["issued_at"]
                 if claimed.payload.get("preparation_budget") is not None else "2026-08-12T12:00:00Z")
    return {
        "schema_version": 2 if claimed.payload.get("preparation_budget") is not None else 1,
        **({"preparation_budget": claimed.payload["preparation_budget"], "workflow_deadline_exceeded": False} if claimed.payload.get("preparation_budget") is not None else {}),
        "operation_id": claimed.external_run_id,
        "request_digest": claimed.payload["request_digest"],
        "kind": claimed.payload["operation"],
        "requested_components": claimed.payload["component_ids"],
        "status": status,
        "stage": status if status in {"completed", "failed", "cancelled"} else "discovering",
        "attempt": claimed.attempt,
        "max_attempts": claimed.max_attempts,
        "cancel_requested_at": timestamp if status in {"cancelling", "cancelled"} else None,
        "created_at": timestamp,
        "started_at": None if status == "queued" else timestamp,
        "finished_at": timestamp if status in {"completed", "failed", "cancelled"} else None,
        "updated_at": timestamp,
        "last_activity_at": timestamp,
        "activity": None,
        "result": result,
        "error_code": error_code,
        "error_detail": error_detail,
    }


@pytest.mark.parametrize(
    ("error_code", "attempt", "retryable"),
    [
        ("installed_content_mismatch", 1, False),
        ("cache_grype_validation_invalid", 1, False),
        ("cache_grype_validation_timeout", 1, True),
        ("cache_grype_validation_timeout", 3, False),
        ("operation_failed", 1, True),
        ("operation_failed", 3, False),
    ],
)
def test_updater_integrity_failure_is_terminal_without_redownload(
    error_code: str, attempt: int, retryable: bool,
) -> None:
    executor = WorkerExecutor(SimpleNamespace(settings=Settings(_env_file=None)), "worker-test")
    job = SimpleNamespace(attempt=attempt, max_attempts=3)
    record = {
        "attempt": attempt,
        "status": "failed",
        "error_code": error_code,
        "error_detail": "Scanner installed data differs from its reviewed lock.",
    }
    with patch.object(executor, "_mark_updater_lifecycle_running"), patch.object(
        executor, "_set_progress"
    ), patch.object(executor, "_get_updater_operation", return_value=record), patch.object(
        executor, "_persist_updater_terminal_state"
    ) as persist, patch.object(executor, "_start_updater") as start, patch.object(
        executor, "_wait_for_updater"
    ) as wait:
        with pytest.raises(JobExecutionError) as failure:
            executor._execute_updater(job, Mock())

    persist.assert_called_once_with(job, record)
    start.assert_not_called()
    wait.assert_not_called()
    assert failure.value.code == error_code
    assert failure.value.detail == record["error_detail"]
    assert failure.value.retryable is retryable


_FIXTURE_RUN_ID = "00000000-0000-4000-8000-000000000001"


def _fixture_finding(index: int) -> dict:
    return {
        "scanner": "fixture",
        "rule_id": f"fixture.rule.{index:05d}",
        "severity": "high",
        "file_path": f"src/{index:05d}.py",
        "start_line": 3,
        "start_column": None,
        "end_line": 3,
        "end_column": None,
        "message": "password=not-a-real-secret",
        "code_snippet": "password=not-a-real-secret",
        "fingerprint": hashlib.sha256(f"fixture:{index}".encode()).hexdigest(),
        "metadata": {},
    }


@pytest.mark.parametrize(
    ("path", "accepted"),
    [
        ("src/password=canonical-filename-secret.py", True),
        ("C:/src/app.py", False),
        ("https:src/app.py", False),
        ("src//app.py", False),
        ("src/\u202eapp.py", False),
    ],
)
def test_scanner_ingress_uses_the_native_canonical_finding_path_contract(
    path: str, accepted: bool
) -> None:
    finding = _fixture_finding(1)
    finding["file_path"] = path
    if not accepted:
        with pytest.raises(JobExecutionError, match="invalid project-relative path"):
            _strict_scanner_finding(finding)
        return
    normalized, _ = _strict_scanner_finding(finding)
    assert normalized["file_path"] == path


def test_scanner_ingress_preserves_a_sarif_insertion_point() -> None:
    finding = _fixture_finding(1)
    finding.update(
        start_line=9,
        start_column=1,
        end_line=9,
        end_column=1,
    )

    normalized, _ = _strict_scanner_finding(finding)

    assert normalized["start_line"] == normalized["end_line"] == 9
    assert normalized["start_column"] == normalized["end_column"] == 1


def _run_state(
    status: str, *, scan_id: int = 1, enabled_tools: list[str] | None = None
) -> dict:
    effective_enabled_tools = ["trivy"] if enabled_tools is None else enabled_tools
    request_payload = {
        "run_id": _FIXTURE_RUN_ID,
        "scan_id": scan_id,
        "repo_path": "/workspaces/project",
        "mode": "full",
        "base_ref": None,
        "head_ref": None,
        "enabled_tools": effective_enabled_tools,
    }
    return {
        "run_id": _FIXTURE_RUN_ID,
        "request_digest": _scanner_request_digest(request_payload),
        "status": status,
        "created_at": "2026-08-13T12:00:00Z",
        "started_at": None if status == "queued" else "2026-08-13T12:00:00Z",
        "finished_at": (
            "2026-08-13T12:00:01Z"
            if status in {"completed", "failed", "cancelled"}
            else None
        ),
        "deadline_at": "2026-08-13T12:10:00Z",
        "expires_at": "2026-08-13T12:20:00Z" if status in {"completed", "failed", "cancelled"} else None,
        "error_code": "fixture_failed" if status == "failed" else None,
        "error_detail": "Fixture scanner failed." if status == "failed" else None,
        "result_manifest": None,
        "result_available": False,
    }


def _scanner_transport(
    *,
    count: int = 1,
    status: str = "completed",
    scan_id: int = 1,
    page_size: int = 128,
    enabled_tools: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    effective_enabled_tools = ["trivy"] if enabled_tools is None else enabled_tools
    findings = [_fixture_finding(index) for index in range(count)]
    encoded = [_canonical_json_bytes(item) + b"\n" for item in findings]
    pages: list[dict] = []
    request_digest = _run_state(
        "running", scan_id=scan_id, enabled_tools=effective_enabled_tools
    )["request_digest"]
    findings_digest = hashlib.sha256(b"".join(encoded)).hexdigest()
    summary = {
        "findings_total": count,
        "severity_counts": ({"high": count} if count else {}),
        "scanner_counts": ({"fixture": count} if count else {}),
        "artifacts": [],
    }
    page_count = (count + page_size - 1) // page_size if count else 0
    manifest = {
        "schema_version": 1,
        "status": status,
        "result_digest": "0" * 64,
        "findings_digest": findings_digest,
        "findings_total": count,
        "findings_bytes": sum(map(len, encoded)),
        "page_count": page_count,
        "page_limit": 128,
        "summary": summary,
        "artifacts": [],
    }
    manifest["result_digest"] = _scanner_manifest_digest(manifest)
    for offset in range(0, count, page_size):
        page_items = findings[offset : offset + page_size]
        page_body = b"".join(encoded[offset : offset + page_size])
        end = offset + len(page_items)
        pages.append(
            {
                "schema_version": 1,
                "run_id": _FIXTURE_RUN_ID,
                "request_digest": request_digest,
                "result_digest": manifest["result_digest"],
                "findings_total": count,
                "start_ordinal": offset + 1,
                "items": page_items,
                "items_bytes": len(page_body),
                "page_digest": hashlib.sha256(page_body).hexdigest(),
                "truncated": end < count,
                "next_cursor": f"cursor-{end}" if end < count else None,
            }
        )
    terminal = {
        **_run_state("completed", scan_id=scan_id, enabled_tools=effective_enabled_tools),
        "result_manifest": manifest,
        "result_available": True,
    }
    return terminal, pages


def _terminal_result(status: str = "completed", *, scan_id: int = 1) -> dict:
    return _scanner_transport(status=status, scan_id=scan_id)[0]


class _ScannerRouter:
    def __init__(
        self,
        *,
        count: int = 1,
        status: str = "completed",
        scan_id: int = 1,
        enabled_tools: list[str] | None = None,
    ) -> None:
        self.terminal, self.pages = _scanner_transport(
            count=count,
            status=status,
            scan_id=scan_id,
            enabled_tools=enabled_tools,
        )
        self.calls: list[tuple[str, str]] = []
        self.ack_status = 200

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        if request.method == "POST" and request.url.path.endswith("/result/ack"):
            if self.ack_status != 200:
                return httpx.Response(self.ack_status)
            manifest = self.terminal["result_manifest"]
            return httpx.Response(
                200,
                json={
                    "schema_version": 1,
                    "run_id": _FIXTURE_RUN_ID,
                    "request_digest": self.terminal["request_digest"],
                    "result_digest": manifest["result_digest"],
                    "acknowledged": True,
                    "result_available": False,
                },
            )
        if request.method == "GET" and request.url.path.endswith("/findings"):
            cursor = request.url.params.get("cursor")
            index = 0 if cursor is None else int(cursor.removeprefix("cursor-")) // 128
            return httpx.Response(200, json=self.pages[index])
        if request.method == "DELETE":
            tombstone = {**self.terminal, "result_available": False}
            return httpx.Response(202, json=tombstone)
        return httpx.Response(202, json=self.terminal)


def _rebind_scanner_transport(router: _ScannerRouter) -> None:
    """Recompute immutable fixture bindings after a test mutates evidence."""

    manifest = router.terminal["result_manifest"]
    encoded_findings: list[bytes] = []
    for page in router.pages:
        encoded = [_canonical_json_bytes(item) + b"\n" for item in page["items"]]
        page_body = b"".join(encoded)
        page["items_bytes"] = len(page_body)
        page["page_digest"] = hashlib.sha256(page_body).hexdigest()
        encoded_findings.extend(encoded)
    manifest["findings_bytes"] = sum(map(len, encoded_findings))
    manifest["findings_digest"] = hashlib.sha256(b"".join(encoded_findings)).hexdigest()
    manifest["result_digest"] = _scanner_manifest_digest(manifest)
    for page in router.pages:
        page["result_digest"] = manifest["result_digest"]


@pytest.mark.parametrize("result_status", ["completed", "partial"])
def test_worker_persists_terminal_scanner_evidence(postgres_engine, tmp_path, result_status: str) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    router = _ScannerRouter(status=result_status)

    claimed = _claim(runtime)
    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(router)).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        findings = list(db.query(Finding).filter(Finding.scan_id == scan.id)) if scan else []
        assert job and job.status == "completed" and job.progress == 100
        assert scan and scan.status == result_status
        if result_status == "partial":
            assert scan.gate_decision == "incomplete"
        else:
            assert scan.gate_decision == "not_configured"
        assert len(findings) == 1
        assert "not-a-real-secret" not in (findings[0].message + (findings[0].code_snippet or ""))
        assert job.checkpoint["scanner_acknowledged"] is True
    assert router.calls == [
        ("POST", "/runs"),
        ("GET", f"/runs/{_FIXTURE_RUN_ID}/findings"),
        ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack"),
    ]


def test_postgresql_lifecycle_commit_serializes_before_worker_terminal_gate(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job is not None and job.scan_id is not None
        scan = db.get(Scan, job.scan_id)
        assert scan is not None
        db.add(
            GatePolicy(
                project_id=scan.project_id,
                active=True,
                max_critical=0,
                max_high=0,
                block_secrets=True,
            )
        )
        scan_id = scan.id

    worker_at_ack = Event()
    release_worker_ack = Event()
    lifecycle_scan_locked = Event()
    lifecycle_finding_locked = Event()
    lifecycle_holds_both = Event()
    release_lifecycle_update = Event()
    worker_attempted_terminal_lock = Event()

    class CoordinatedScannerRouter(_ScannerRouter):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path.endswith("/result/ack"):
                worker_at_ack.set()
                assert release_worker_ack.wait(10), "worker ACK coordination timed out"
            return super().__call__(request)

    router = CoordinatedScannerRouter(scan_id=scan_id)
    claimed = _claim(runtime)

    def normalized_statement(statement: object) -> str:
        return " ".join(str(statement).lower().split())

    def after_cursor_execute(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if not current_thread().name.startswith("lifecycle-writer"):
            return
        normalized = normalized_statement(statement)
        if " for update" not in normalized:
            return
        if " from scans " in f" {normalized} ":
            lifecycle_scan_locked.set()
        if " from findings " in f" {normalized} ":
            lifecycle_finding_locked.set()

    def before_cursor_execute(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = normalized_statement(statement)
        if (
            current_thread().name.startswith("lifecycle-writer")
            and normalized.startswith("update findings set ")
        ):
            assert lifecycle_scan_locked.is_set(), "lifecycle changed a finding before locking its scan"
            assert lifecycle_finding_locked.is_set(), "lifecycle changed an unlocked finding"
            lifecycle_holds_both.set()
            assert release_lifecycle_update.wait(10), "lifecycle coordination timed out"
            return
        if (
            current_thread().name.startswith("terminal-worker")
            and lifecycle_holds_both.is_set()
            and " from scans " in f" {normalized} "
            and " for update" in normalized
        ):
            worker_attempted_terminal_lock.set()

    event.listen(runtime.engine, "before_cursor_execute", before_cursor_execute)
    event.listen(runtime.engine, "after_cursor_execute", after_cursor_execute)
    try:
        with (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="terminal-worker") as worker_pool,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="lifecycle-writer") as lifecycle_pool,
        ):
            worker_future = worker_pool.submit(
                WorkerExecutor(
                    runtime,
                    "worker-test",
                    scanner_client_factory=_client_factory(router),
                ).execute,
                claimed,
            )
            assert worker_at_ack.wait(10), "worker did not persist scanner evidence before ACK"
            with runtime.session_factory() as db:
                scan = db.get(Scan, scan_id)
                finding = db.scalar(select(Finding).where(Finding.scan_id == scan_id))
                assert scan is not None and scan.revision == 3 and scan.findings_revision == 2
                assert finding is not None and finding.revision == 1
                finding_id = finding.id

            def apply_lifecycle() -> dict:
                with runtime.session_factory() as db:
                    return update_finding_lifecycle(
                        finding_id,
                        FindingLifecycleUpdate(
                            action="accepted_risk",
                            reason="concurrent terminal publication receipt",
                            expected_revision=1,
                        ),
                        db,
                    )

            lifecycle_future = lifecycle_pool.submit(apply_lifecycle)
            assert lifecycle_holds_both.wait(10), "lifecycle writer did not hold Scan then Finding"
            release_worker_ack.set()
            assert worker_attempted_terminal_lock.wait(10), "worker did not attempt terminal Scan lock"
            assert not worker_future.done(), "worker crossed the lifecycle Scan lock"
            assert not lifecycle_future.done(), "lifecycle transaction did not remain open"
            release_lifecycle_update.set()
            lifecycle_result = lifecycle_future.result(timeout=10)
            worker_future.result(timeout=10)
    finally:
        release_worker_ack.set()
        release_lifecycle_update.set()
        event.remove(runtime.engine, "before_cursor_execute", before_cursor_execute)
        event.remove(runtime.engine, "after_cursor_execute", after_cursor_execute)

    assert lifecycle_result["revision"] == 2
    assert lifecycle_result["lifecycle_status"] == "accepted_risk"
    assert lifecycle_result["gate_effect"] == "non_blocking"
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, scan_id)
        finding = db.get(Finding, finding_id)
        assert job is not None and job.status == "completed" and job.progress == 100
        assert scan is not None and scan.status == "completed"
        # Initial, running, evidence, lifecycle, and terminal revisions all survive.
        assert scan.revision == 5
        assert scan.findings_revision == 3
        assert scan.gate_decision == "pass"
        assert scan.gate_reasons == []
        assert scan.scanner_summary == {
            "findings_total": 1,
            "severity_counts": {"high": 1},
            "scanner_counts": {"fixture": 1},
            "artifacts": [],
            "ignored_count": 0,
            "gate_exempt_count": 1,
        }
        assert finding is not None and finding.revision == 2
        assert finding.lifecycle_status == "accepted_risk"
        assert finding.gate_exempt is True


def test_explicit_limited_coverage_is_persisted_partial_with_exact_omissions(
    postgres_engine, tmp_path
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    preflight_revision = "f" * 64
    omitted = {
        "id": "opengrep",
        "name": "OpenGrep",
        "blocking_reasons": [
            "no validated active or previous-good cache generation"
        ],
        "required_component_ids": ["opengrep-reviewed-rules"],
        "preparation_blocking_reasons": [],
    }
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job is not None
        job.payload = {
            **job.payload,
            "coverage": "limited",
            "preflight_revision": preflight_revision,
            "requested_tools": ["opengrep", "sast-lite"],
            "enabled_tools": ["sast-lite"],
            "omitted_tools": [omitted],
        }

    router = _ScannerRouter(status="completed", enabled_tools=["sast-lite"])
    WorkerExecutor(
        runtime, "worker-test", scanner_client_factory=_client_factory(router)
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job is not None else None
        assert job is not None and job.status == "completed"
        assert scan is not None and scan.status == "partial"
        assert scan.gate_decision == "incomplete"
        assert scan.gate_reasons == [INCOMPLETE_GATE_REASON]
        assert scan.scanner_summary["coverage"] == {
            "mode": "limited",
            "complete": False,
            "requested_tool_ids": ["opengrep", "sast-lite"],
            "ready_tool_ids": ["sast-lite"],
            "omitted_tool_ids": ["opengrep"],
            "omitted_tools": [omitted],
            "preflight_revision": preflight_revision,
        }


def test_scan_coverage_snapshot_rejects_unreviewed_or_malformed_tool_evidence() -> None:
    omitted = {
        "id": "gitleaks",
        "name": "Gitleaks",
        "blocking_reasons": ["offline execution contract is not attested"],
        "required_component_ids": [],
        "preparation_blocking_reasons": [
            "offline execution contract is not attested"
        ],
    }
    valid = {
        "coverage": "limited",
        "preflight_revision": "f" * 64,
        "requested_tools": ["gitleaks", "trivy"],
        "enabled_tools": ["trivy"],
        "omitted_tools": [omitted],
    }
    assert _validated_scan_coverage_snapshot(valid) == valid

    invalid_payloads = [
        {**valid, "preflight_revision": "not-a-digest"},
        {**valid, "requested_tools": ["trivy"]},
        {**valid, "requested_tools": ["gitleaks", "gitleaks", "trivy"]},
        {**valid, "enabled_tools": ["unknown-scanner"]},
        {**valid, "enabled_tools": ["gitleaks", "trivy"]},
        {**valid, "omitted_tools": [{**omitted, "unexpected": True}]},
        {
            **valid,
            "omitted_tools": [
                {
                    **omitted,
                    "preparation_blocking_reasons": ["forged distinct reason"],
                }
            ],
        },
        {
            **valid,
            "omitted_tools": [
                {**omitted, "name": "Gitleaks\nforged activity"}
            ],
        },
        {**valid, "omitted_tools": [omitted, omitted]},
        {"coverage": "complete", "enabled_tools": []},
    ]
    for payload in invalid_payloads:
        with pytest.raises(JobExecutionError) as rejected:
            _validated_scan_coverage_snapshot(payload)
        assert rejected.value.code == "invalid_payload"


def test_worker_binds_only_a_typed_canonical_source_target_into_scanner_identity() -> None:
    assert _validated_scan_target({}) == (None, None)
    assert _validated_scan_target(
        {"target_path": "k8s/deployment.yaml", "target_kind": "file"}
    ) == ("k8s/deployment.yaml", "file")
    assert _validated_scan_target(
        {"target_path": "k8s", "target_kind": "directory"}
    ) == ("k8s", "directory")
    base = {
        "scan_id": 1,
        "repo_path": "/workspaces/project",
        "target_path": "k8s/deployment.yaml",
        "target_kind": "file",
        "mode": "full",
        "base_ref": None,
        "head_ref": None,
        "enabled_tools": ["trivy"],
    }
    assert _scanner_request_digest(base) != _scanner_request_digest(
        {**base, "target_path": "app.py"}
    )
    assert _scanner_request_digest(base) != _scanner_request_digest(
        {**base, "target_path": "k8s", "target_kind": "directory"}
    )
    assert _validated_scan_source_snapshot_digest({}) is None
    assert _validated_scan_source_snapshot_digest(
        {"source_snapshot_digest": "a" * 64}
    ) == "a" * 64
    assert _scanner_request_digest(base) != _scanner_request_digest(
        {**base, "source_snapshot_digest": "a" * 64}
    )
    for invalid in (42, "/absolute.py", "../outside.py", "src//app.py"):
        with pytest.raises(JobExecutionError) as rejected:
            _validated_scan_target({"target_path": invalid, "target_kind": "file"})
        assert rejected.value.code == "invalid_payload"
    for invalid in (
        {"target_path": "app.py"},
        {"target_kind": "file"},
        {"target_path": "app.py", "target_kind": "workspace"},
        {"target_path": "app.py", "target_kind": ["file"]},
        {"target_path": "app.py", "target_kind": {"kind": "file"}},
    ):
        with pytest.raises(JobExecutionError) as rejected:
            _validated_scan_target(invalid)
        assert rejected.value.code == "invalid_payload"
    with pytest.raises(JobExecutionError) as rejected:
        _validated_scan_source_snapshot_digest({"source_snapshot_digest": "invalid"})
    assert rejected.value.code == "invalid_payload"


@pytest.mark.parametrize("count", [0, 257, 10_000])
def test_worker_streams_bounded_scanner_result_pages(postgres_engine, tmp_path, count: int) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    router = _ScannerRouter(count=count)
    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"
        assert job.checkpoint["scanner_findings_total"] == count
        assert job.checkpoint["scanner_acknowledged"] is True
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == count
    expected_pages = (count + 127) // 128
    assert sum(path.endswith("/findings") for _method, path in router.calls) == expected_pages
    assert router.calls[-1] == ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack")


def test_worker_accepts_scanner_global_order_before_cross_tool_identity(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    router = _ScannerRouter(count=2)
    first, second = router.pages[0]["items"]
    first.update(
        scanner="z-scanner",
        rule_id="z.rule",
        file_path="src/shared.py",
        start_line=7,
        start_column=1,
        end_line=7,
        end_column=2,
    )
    second.update(
        scanner="a-scanner",
        rule_id="a.rule",
        file_path="src/shared.py",
        start_line=7,
        start_column=2,
        end_line=7,
        end_column=3,
    )
    router.terminal["result_manifest"]["summary"]["scanner_counts"] = {
        "a-scanner": 1,
        "z-scanner": 1,
    }
    _rebind_scanner_transport(router)

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == job.scan_id)
            .order_by(Finding.scan_finding_number)
            .all()
            if job
            else []
        )
        assert job and job.status == "completed"
        assert [(finding.scanner, finding.start_column) for finding in findings] == [
            ("z-scanner", 1),
            ("a-scanner", 2),
        ]


def test_worker_rejects_scanner_global_order_with_descending_columns(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter(count=2)
    first, second = router.pages[0]["items"]
    first.update(
        file_path="src/shared.py",
        start_line=7,
        start_column=2,
        end_line=7,
        end_column=3,
    )
    second.update(
        file_path="src/shared.py",
        start_line=7,
        start_column=1,
        end_line=7,
        end_column=2,
    )
    _rebind_scanner_transport(router)

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_protocol"
        assert scan and scan.status == "failed"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0


def test_scanner_persistence_never_replaces_existing_operator_finding_state(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job is not None and job.scan_id is not None
        existing = Finding(
            scan_id=job.scan_id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="operator-state",
            severity="high",
            file_path="operator.py",
            start_line=1,
            end_line=1,
            message="Operator-reviewed evidence",
            fingerprint="operator-state-fingerprint",
            lifecycle_status="accepted_risk",
            lifecycle_reason="Reviewed before a recovered persistence attempt.",
            gate_exempt=True,
            revision=7,
        )
        db.add(existing)
        db.flush()
        existing_id = existing.id

    router = _ScannerRouter()
    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        existing = db.get(Finding, existing_id)
        assert job is not None and job.status == "failed"
        assert job.error_code == "scan_evidence_conflict"
        assert existing is not None
        assert existing.lifecycle_status == "accepted_risk"
        assert existing.lifecycle_reason == "Reviewed before a recovered persistence attempt."
        assert existing.revision == 7
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 1


def test_worker_reloads_committed_scanner_persistence_after_db_return_uncertainty(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()

    class CommitThenRaiseExecutor(WorkerExecutor):
        raised = False

        def _persist_scanner_manifest(self, *args, **kwargs):
            checkpoint = super()._persist_scanner_manifest(*args, **kwargs)
            if not self.raised:
                self.raised = True
                raise OperationalError(
                    "fixture post-commit return",
                    {},
                    RuntimeError("fixture connection lost after commit"),
                )
            return checkpoint

    CommitThenRaiseExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed" and job.attempt == 1
        assert job.checkpoint["scanner_persisted"] is True
        assert job.checkpoint["scanner_acknowledged"] is True
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 1
    assert router.calls == [
        ("POST", "/runs"),
        ("GET", f"/runs/{_FIXTURE_RUN_ID}/findings"),
        ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack"),
    ]


def test_worker_recovers_precommit_scanner_persistence_uncertainty_without_reexecution(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()

    class RaiseBeforePersistenceExecutor(WorkerExecutor):
        def _persist_scanner_manifest(self, *args, **kwargs):
            raise OperationalError(
                "fixture pre-commit failure",
                {},
                RuntimeError("fixture connection lost before persistence"),
            )

    RaiseBeforePersistenceExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.attempt == 1
        assert job.checkpoint.get("scanner_persisted") is not True
        assert job.checkpoint.get("scanner_acknowledged") is not True
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 0
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert router.calls == [("POST", "/runs")]

    router.calls.clear()
    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(router),
    ).recover_exhausted(_reclaim_exhausted(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed" and job.attempt == 1
        assert job.checkpoint["scanner_persisted"] is True
        assert job.checkpoint["scanner_acknowledged"] is True
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 1
    assert router.calls == [
        ("GET", f"/runs/{_FIXTURE_RUN_ID}"),
        ("GET", f"/runs/{_FIXTURE_RUN_ID}/findings"),
        ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack"),
    ]


def test_worker_recovers_completion_transaction_uncertainty_without_repaging(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()

    class RaiseBeforeCompletionExecutor(WorkerExecutor):
        def _complete(self, *args, **kwargs):
            raise OperationalError(
                "fixture completion transaction failure",
                {},
                RuntimeError("fixture connection lost before completion commit"),
            )

    RaiseBeforeCompletionExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.attempt == 1
        assert job.checkpoint["scanner_persisted"] is True
        assert job.checkpoint["scanner_acknowledged"] is True
        finding_id = db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar()
        assert finding_id is not None
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert router.calls == [
        ("POST", "/runs"),
        ("GET", f"/runs/{_FIXTURE_RUN_ID}/findings"),
        ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack"),
    ]

    router.calls.clear()
    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(router),
    ).recover_exhausted(_reclaim_exhausted(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed" and job.attempt == 1
        assert db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar() == finding_id
    assert router.calls == [("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack")]


@pytest.mark.parametrize("final_ack_status", [200, 404])
def test_persisted_result_ack_outage_recovers_without_repaging(
    postgres_engine,
    tmp_path,
    final_ack_status: int,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    router.ack_status = 503

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.attempt == 1
        assert job.checkpoint["scanner_persisted"] is True
        assert job.checkpoint.get("scanner_acknowledged") is not True
        finding_id = db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar()
        assert finding_id is not None
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    recovered = _reclaim_exhausted(runtime)
    router.ack_status = final_ack_status
    router.calls.clear()
    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(router),
    ).recover_exhausted(recovered)

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"
        assert job.checkpoint["scanner_acknowledged"] is True
        assert db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar() == finding_id
    assert router.calls == [("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack")]


def test_repeated_final_attempt_ack_outage_never_terminalizes_persisted_evidence(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    router.ack_status = 503
    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))

    for _receipt in range(3):
        with runtime.session_factory() as db, db.begin():
            job = db.get(Job, job_id)
            assert job and job.status == "running"
            assert job.checkpoint["scanner_persisted"] is True
            job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        WorkerExecutor(
            runtime,
            "worker-recovery",
            scanner_client_factory=_client_factory(router),
        ).recover_exhausted(_reclaim_exhausted(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.error_code is None
        assert job.checkpoint["scanner_persisted"] is True
        assert job.checkpoint.get("scanner_acknowledged") is not True


def test_worker_rejects_mismatched_scanner_run_evidence(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    mismatched = _terminal_result()
    mismatched["request_digest"] = "0" * 64

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(202, json=mismatched)

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(handler)).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_run_conflict"
        assert scan and scan.status == "failed" and scan.gate_decision == "incomplete"
        assert scan.gate_reasons == [INCOMPLETE_GATE_REASON]
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0


def test_worker_digest_cleans_malformed_terminal_manifest_before_protocol_failure(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    valid_terminal = json.loads(json.dumps(router.terminal))
    manifest = router.terminal["result_manifest"]
    request_digest = router.terminal["request_digest"]
    result_digest = manifest["result_digest"]
    manifest["summary"]["findings_total"] = 2
    calls: list[tuple[str, str, dict[str, str]]] = []
    factory_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, dict(request.url.params)))
        if request.method == "POST" and request.url.path == "/runs":
            return httpx.Response(202, json=router.terminal)
        if request.method == "DELETE" and request.url.path == f"/runs/{_FIXTURE_RUN_ID}":
            return httpx.Response(
                202,
                json={**valid_terminal, "result_available": False},
            )
        raise AssertionError("malformed terminal state must be cleaned without paging or acknowledgement")

    def client_factory() -> httpx.Client:
        nonlocal factory_calls
        factory_calls += 1
        return httpx.Client(
            base_url="http://scanner:8091",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        )

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=client_factory,
    ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_protocol"
        assert job.checkpoint.get("scanner_persisted") is not True
        assert job.checkpoint["scanner_evidence"] == {
            "request_digest": request_digest,
            "sha256": result_digest,
        }
        assert job.checkpoint["scanner_cleanup"] == {
            "action": "discard",
            "error_code": "scanner_protocol",
        }
        assert scan and scan.status == "failed"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0
    assert factory_calls == 1
    assert calls == [
        ("POST", "/runs", {}),
        (
            "DELETE",
            f"/runs/{_FIXTURE_RUN_ID}",
            {
                "request_digest": request_digest,
                "result_digest": result_digest,
            },
        ),
    ]


def test_worker_rejects_noncanonical_scanner_finding_path(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    router.pages[0]["items"][0]["file_path"] = "../outside.py"
    _rebind_scanner_transport(router)

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    ).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_protocol"
        assert scan and scan.status == "failed"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0


def test_protocol_rejection_cleanup_outage_recovers_by_delete_without_repaging(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    router.pages[0]["items"][0]["file_path"] = "../outside.py"
    _rebind_scanner_transport(router)
    calls: list[tuple[str, str]] = []
    factory_calls = 0
    delete_status = 503

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "DELETE":
            return httpx.Response(delete_status)
        return router(request)

    def factory() -> httpx.Client:
        nonlocal factory_calls
        factory_calls += 1
        return httpx.Client(
            base_url="http://scanner:8091",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        )

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=factory).execute(_claim(runtime))
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.attempt == 1
        assert job.checkpoint.get("scanner_persisted") is not True
        assert job.checkpoint["scanner_cleanup"] == {
            "action": "discard",
            "error_code": "scanner_protocol",
        }
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 0
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert factory_calls == 1
    assert calls[-1] == ("DELETE", f"/runs/{_FIXTURE_RUN_ID}")

    delete_status = 404
    calls.clear()
    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=factory,
    ).recover_exhausted(_reclaim_exhausted(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_protocol"
        assert scan and scan.status == "failed" and scan.gate_decision == "incomplete"
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 0
    assert factory_calls == 2
    assert calls == [("DELETE", f"/runs/{_FIXTURE_RUN_ID}")]


def test_worker_rejects_scanner_run_identity_conflict(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(
            409,
            json={"detail": {"code": "run_id_conflict", "message": "bounded fixture conflict"}},
        )

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(handler)).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_run_conflict"
        assert scan and scan.status == "failed"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0


def test_worker_contains_failure_transaction_uncertainty(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(
            409,
            json={"detail": {"code": "run_id_conflict", "message": "bounded fixture conflict"}},
        )

    failure = OperationalError(
        "fixture failure transaction",
        {},
        RuntimeError("fixture database unavailable"),
    )
    with patch("kodesec_api.jobs.execution.fail_job", side_effect=failure):
        WorkerExecutor(
            runtime,
            "worker-test",
            scanner_client_factory=_client_factory(handler),
        ).execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "running" and job.error_code is None


def test_exhausted_recovery_contains_receipt_transaction_uncertainty(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    claimed = _claim_exhausted(runtime)

    class RetryableStatusExecutor(WorkerExecutor):
        def _get_scanner_run(self, client, run_id: str, request_digest: str) -> dict:
            raise JobExecutionError(
                "scanner_unreachable",
                "Fixture scanner status is unavailable.",
                retryable=True,
            )

    receipt_failure = OperationalError(
        "fixture recovery receipt transaction",
        {},
        RuntimeError("fixture database unavailable"),
    )
    with patch("kodesec_api.jobs.execution.update_job_progress", side_effect=receipt_failure):
        RetryableStatusExecutor(
            runtime,
            "worker-recovery",
            scanner_client_factory=_client_factory(lambda _request: httpx.Response(503)),
        ).recover_exhausted(claimed)

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "leased" and job.error_code is None


def test_worker_waits_for_scanner_capacity_without_burning_attempt(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()
    start_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal start_calls
        if request.method == "POST" and request.url.path == "/runs":
            start_calls += 1
            if start_calls <= 2:
                return httpx.Response(
                    409,
                    json={
                        "detail": {
                            "code": "scanner_capacity",
                            "message": "bounded fixture capacity",
                        }
                    },
                )
        return router(request)

    WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(handler),
    ).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed" and job.attempt == 1
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 1
    assert start_calls == 3


def test_declared_missing_artifact_fails_closed_without_publication(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    router = _ScannerRouter()
    artifacts = [
        {
            "scanner": "syft",
            "artifact_type": "sbom",
            "format": "cyclonedx-json",
            "path": str(tmp_path / "artifacts" / "scans" / "1" / "syft" / "missing.json"),
            "size_bytes": 10,
            "sha256": "a" * 64,
        }
    ]
    router.terminal["result_manifest"]["artifacts"] = artifacts
    router.terminal["result_manifest"]["summary"]["artifacts"] = artifacts
    _rebind_scanner_transport(router)

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(router)).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "scanner_protocol"
        assert scan and scan.status == "failed" and scan.gate_decision == "incomplete"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 0


def test_artifact_operational_failure_cannot_complete_job(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()

    with patch(
        "kodesec_api.jobs.execution.admit_scan_artifacts",
        side_effect=ArtifactBoundaryError("fixture ENOSPC"),
    ):
        WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(router)).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "failed" and job.error_code == "artifact_publication_failed"
        assert scan and scan.status == "failed"


def test_worker_reposts_stable_run_after_scanner_restart(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    calls = {"post": 0, "get": 0}
    router = _ScannerRouter()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/runs":
            calls["post"] += 1
            if calls["post"] == 1:
                return httpx.Response(202, json=_run_state("running"))
            return router(request)
        if request.method == "GET" and request.url.path == f"/runs/{_FIXTURE_RUN_ID}":
            calls["get"] += 1
            return httpx.Response(404, json={"detail": "unknown run"})
        return router(request)

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(handler)).execute(_claim(runtime))
    assert calls == {"post": 2, "get": 1}
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"


def test_worker_bounds_repeated_scanner_registry_resets(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=2)
    calls = {"post": 0, "get": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls[request.method.casefold()] += 1
        if request.method == "POST":
            return httpx.Response(202, json=_run_state("running"))
        return httpx.Response(404, json={"detail": "registry reset"})

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(handler)).execute(_claim(runtime))
    assert calls == {"post": 4, "get": 4}
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "queued" and job.error_code == "scanner_registry_unstable"


def test_worker_cancellation_confirms_scanner_cleanup(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.scan_id
        scan_id = job.scan_id
    unindexed = tmp_path / "artifacts" / "scans" / str(scan_id) / "syft" / "unindexed.json"
    unindexed.parent.mkdir(parents=True)
    unindexed.write_text("temporary", encoding="utf-8")
    with runtime.session_factory() as db, db.begin():
        request_cancellation(db, job_id)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.params["request_digest"] == _run_state("running")["request_digest"]
        return httpx.Response(202, json=_run_state("cancelled"))

    WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(handler)).execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "cancelled"
        assert scan and scan.status == "cancelled" and scan.gate_decision == "incomplete"
        assert scan.gate_reasons == [INCOMPLETE_GATE_REASON]
    assert not (tmp_path / "artifacts" / "scans" / str(scan_id)).exists()


def test_lease_monitor_refreshes_process_health_during_long_work(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    runtime.settings.worker_heartbeat_seconds = 1.0
    job_id = _seed_scan_job(runtime)
    claimed = _claim(runtime)
    marker = tmp_path / "worker-process-heartbeat"
    refreshed = Event()

    def record_health() -> None:
        from kodesec_api.worker_health import record_process_heartbeat

        record_process_heartbeat(marker)
        refreshed.set()

    monitor = LeaseMonitor(runtime, claimed, "worker-test")
    with patch(
        "kodesec_api.jobs.execution.record_process_heartbeat",
        side_effect=record_health,
    ):
        monitor.start()
        assert refreshed.wait(3), "lease heartbeat did not refresh process health"
        monitor.stop()

    assert marker.is_file()
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job is not None and job.lease_owner == "worker-test"


@pytest.mark.parametrize("terminal_status", ["failed", "cancelled"])
def test_terminal_scan_after_persisted_partial_evidence_keeps_incomplete_gate(
    postgres_engine,
    tmp_path,
    terminal_status: str,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime)
    claimed = _claim(runtime)
    router = _ScannerRouter(status="partial")
    executor = WorkerExecutor(
        runtime,
        "worker-test",
        scanner_client_factory=_client_factory(router),
    )
    monitor = LeaseMonitor(runtime, claimed, "worker-test")
    monitor.start()
    executor._mark_running(claimed)
    try:
        manifest = router.terminal["result_manifest"]
        request_digest = router.terminal["request_digest"]
        checkpoint = executor._prepare_scanner_artifact_provenance(
            claimed,
            monitor,
            request_digest=request_digest,
            manifest=manifest,
        )
        with _client_factory(router)() as client:
            checkpoint = executor._persist_scanner_manifest(
                claimed,
                manifest,
                client,
                monitor,
                request_digest=request_digest,
                checkpoint=checkpoint,
                use_ai=False,
            )
    finally:
        monitor.stop()
    assert checkpoint["scanner_persisted"] is True
    assert checkpoint["scan_status"] == "partial"

    if terminal_status == "cancelled":
        with runtime.session_factory() as db, db.begin():
            request_cancellation(db, job_id)
        executor._finalize_cancelled(claimed)
    else:
        executor._fail(
            claimed,
            JobExecutionError(
                "fixture_terminal_failure",
                "Scanner evidence was persisted before a bounded terminal failure.",
                retryable=False,
            ),
        )

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == terminal_status
        assert scan and scan.status == terminal_status
        assert scan.gate_decision == "incomplete"
        assert scan.gate_reasons == [INCOMPLETE_GATE_REASON]
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 1


def test_queued_updater_cancellation_needs_no_network_operation(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_updater_job(runtime)
    with runtime.session_factory() as db, db.begin():
        request_cancellation(db, job_id)
    claimed = _claim(runtime)
    assert claimed.status == "cancelling" and claimed.attempt == 0

    def forbidden_client():
        raise AssertionError("a never-started updater operation must not be contacted")

    WorkerExecutor(
        runtime,
        "worker-test",
        updater_client_factory=forbidden_client,
    ).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        lifecycle = db.get(ScannerLifecycleState, "cache")
        assert job and job.status == "cancelled"
        assert lifecycle and lifecycle.status == "cancelled" and lifecycle.receipt == {}


def test_exhausted_recovery_persists_completed_scanner_result(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    router = _ScannerRouter()

    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(router),
    ).recover_exhausted(_claim_exhausted(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "completed"
        assert scan and scan.status == "completed"
        assert db.query(Finding).filter(Finding.scan_id == scan.id).count() == 1
    assert router.calls == [
        ("GET", f"/runs/{_FIXTURE_RUN_ID}"),
        ("GET", f"/runs/{_FIXTURE_RUN_ID}/findings"),
        ("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack"),
    ]


def test_exhausted_recovery_observes_active_run_to_completion(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    claimed = _claim_exhausted(runtime)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.scan_id
        scan_id = job.scan_id
        started_at = job.started_at
    calls = {"state_get": 0}
    router = _ScannerRouter()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == f"/runs/{_FIXTURE_RUN_ID}":
            calls["state_get"] += 1
            if calls["state_get"] == 1:
                return httpx.Response(200, json=_run_state("running"))
            with runtime.session_factory() as db:
                job = db.get(Job, job_id)
                assert job and (job.status, job.stage) == ("running", "scanner")
                assert job.attempt == job.max_attempts == 1
                assert job.external_run_id == claimed.external_run_id == _FIXTURE_RUN_ID
                assert job.started_at == started_at
        return router(request)

    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(handler),
    ).recover_exhausted(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"
        assert job.attempt == job.max_attempts == 1
        assert job.external_run_id == _FIXTURE_RUN_ID
        assert job.started_at == started_at
        assert db.query(Finding).filter(Finding.scan_id == scan_id).count() == 1
    assert calls == {"state_get": 2}
    assert router.calls.count(("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack")) == 1
    assert ("POST", "/runs") not in router.calls


@pytest.mark.parametrize("interruption", ["cancellation", "replacement-worker"])
def test_exhausted_recovery_fences_first_observation_before_polling_or_publication(
    postgres_engine, tmp_path, interruption: str,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    claimed = _claim_exhausted(runtime)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "DELETE":
            # Cancellation retains the exact worker lease: clean up now rather
            # than waiting for that lease to expire. A replacement owner must
            # still prevent every request after the initial observation.
            assert interruption == "cancellation"
            assert calls == [("GET", f"/runs/{_FIXTURE_RUN_ID}"),
                             ("DELETE", f"/runs/{_FIXTURE_RUN_ID}")]
            assert request.url.params["request_digest"] == _run_state("running")["request_digest"]
            return httpx.Response(202, json=_run_state("cancelled"))
        assert calls == [("GET", f"/runs/{_FIXTURE_RUN_ID}")]
        with runtime.session_factory() as db, db.begin():
            if interruption == "cancellation":
                request_cancellation(db, job_id)
            else:
                job = db.get(Job, job_id)
                assert job is not None
                job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                db.flush()
                replacement = claim_next_job(db, worker_id="replacement-worker", lease_seconds=30)
                assert replacement and replacement.id == job_id and replacement.attempt == 1
        return httpx.Response(200, json=_run_state("running"))

    WorkerExecutor(
        runtime, "worker-recovery", scanner_client_factory=_client_factory(handler),
    ).recover_exhausted(claimed)

    assert calls == [("GET", f"/runs/{_FIXTURE_RUN_ID}")] + (
        [("DELETE", f"/runs/{_FIXTURE_RUN_ID}")] if interruption == "cancellation" else [])
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.attempt == job.max_attempts == 1
        assert job.external_run_id == _FIXTURE_RUN_ID and job.error_code is None
        assert not job.checkpoint.get("scanner_persisted")
        assert db.query(Finding).filter(Finding.scan_id == job.scan_id).count() == 0
        if interruption == "cancellation":
            assert job.status == "cancelled" and job.cancel_requested_at is not None
            assert job.lease_owner is None
            scan = db.get(Scan, job.scan_id)
            assert scan.status == "cancelled" and scan.gate_decision == "incomplete"
        else:
            assert job.status == "leased" and job.cancel_requested_at is None
            assert job.lease_owner == "replacement-worker"


def test_exhausted_recovery_bounds_permanent_scanner_outage(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fixture scanner unavailable", request=request)

    executor = WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(unavailable),
    )
    claimed = _claim_exhausted(runtime)
    for receipt in range(1, 4):
        executor.recover_exhausted(claimed)
        with runtime.session_factory() as db, db.begin():
            job = db.get(Job, job_id)
            assert job
            assert job.checkpoint["recovery_reconciliations"] == receipt
            if receipt < 3:
                assert job.status == "running"
                assert job.stage == "recovery_wait"
                job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            else:
                assert job.status == "failed"
                assert job.error_code == "attempts_exhausted"
                assert "three bounded reconciliation leases" in (job.error_detail or "")
        if receipt < 3:
            claimed = _reclaim_exhausted(runtime)


def test_unexpected_exhausted_recovery_failure_is_contained_and_worker_continues(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    recovery_job_id = _seed_scan_job(runtime, max_attempts=1)
    _claim_exhausted(runtime)
    stop = Event()
    fixture_secret = "fixture-recovery-secret-value"
    private_path = "/Users/private-owner/recovery-source"

    with runtime.session_factory() as db, db.begin():
        recovery_job = db.get(Job, recovery_job_id)
        assert recovery_job
        recovery_job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        queued = enqueue_job(
            db,
            kind="maintenance",
            title="Worker-loop continuation fixture",
            client_id="browser:test",
            idempotency_key="worker-loop-continuation",
            payload={"v": 1, "operation": "unsupported_fixture"},
            max_attempts=1,
        ).job
        continuation_job_id = queued.id
        db.add(RuntimeConfig(key=ARTIFACT_BOUNDARY_MARKER, value="completed"))

    class ContainedRecoveryExecutor(WorkerExecutor):
        def _get_scanner_run(self, client, run_id: str, request_digest: str) -> dict:
            raise RuntimeError(
                f"unexpected recovery failure at {private_path}; password={fixture_secret}"
            )

        def execute(self, job: ClaimedJob) -> None:
            super().execute(job)
            if job.id == continuation_job_id:
                stop.set()

    with (
        patch("kodesec_api.worker.WorkerExecutor", ContainedRecoveryExecutor),
        patch("kodesec_api.worker.worker_ollama_available_sync", return_value=(False, [], "disabled")),
    ):
        assert run_worker(runtime, stop_event=stop, worker_id="worker-contained") == 2

    with runtime.session_factory() as db:
        recovery_job = db.get(Job, recovery_job_id)
        continuation_job = db.get(Job, continuation_job_id)
        assert recovery_job and recovery_job.status == "failed"
        assert recovery_job.error_code == "worker_internal_error"
        assert recovery_job.error_detail == (
            "Unexpected worker failure was contained during final-attempt reconciliation."
        )
        assert fixture_secret not in str(recovery_job.error_detail)
        assert private_path not in str(recovery_job.error_detail)
        assert continuation_job and continuation_job.status == "failed"
        assert continuation_job.error_code == "unsupported_operation"


def test_unexpected_execution_failure_is_contained_without_private_detail(
    postgres_engine,
    tmp_path,
    caplog,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    fixture_secret = "fixture-execution-secret-value"
    private_path = "/Users/private-owner/execution-source"

    class UnexpectedExecutor(WorkerExecutor):
        def _execute_scan(self, job, monitor, *, use_ai):
            raise RuntimeError(
                f"unexpected execution failure at {private_path}; password={fixture_secret}"
            )

    UnexpectedExecutor(runtime, "worker-test").execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "failed"
        assert job.error_code == "worker_internal_error"
        assert job.error_detail == (
            "Unexpected worker failure was contained during durable execution."
        )
        assert fixture_secret not in str(job.error_detail)
        assert private_path not in str(job.error_detail)
    assert fixture_secret not in caplog.text
    assert private_path not in caplog.text


def test_exhausted_recovery_uses_persisted_checkpoint_without_rewriting_ids(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, max_attempts=1)
    claimed = _claim(runtime, worker_id="worker-crashed")

    router = _ScannerRouter()
    executor = WorkerExecutor(
        runtime,
        "worker-crashed",
        scanner_client_factory=_client_factory(router),
    )
    monitor = LeaseMonitor(runtime, claimed, "worker-crashed")
    monitor.start()
    executor._mark_running(claimed)
    manifest = router.terminal["result_manifest"]
    request_digest = router.terminal["request_digest"]
    checkpoint = executor._prepare_scanner_artifact_provenance(
        claimed,
        monitor,
        request_digest=request_digest,
        manifest=manifest,
    )
    with _client_factory(router)() as client:
        checkpoint = executor._persist_scanner_manifest(
            claimed,
            manifest,
            client,
            monitor,
            request_digest=request_digest,
            checkpoint=checkpoint,
            use_ai=False,
        )
    monitor.stop()
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        assert job
        job.checkpoint = checkpoint
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        finding_id = db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar()
    recovered = _reclaim_exhausted(runtime)

    router.calls.clear()

    WorkerExecutor(
        runtime,
        "worker-recovery",
        scanner_client_factory=_client_factory(router),
    ).recover_exhausted(recovered)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"
        assert db.query(Finding.id).filter(Finding.scan_id == job.scan_id).scalar() == finding_id
    assert router.calls == [("POST", f"/runs/{_FIXTURE_RUN_ID}/result/ack")]


def test_optional_advisor_failure_preserves_scan_and_gate(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_scan_job(runtime, use_ai=True)
    router = _ScannerRouter()
    executor = WorkerExecutor(runtime, "worker-test", scanner_client_factory=_client_factory(router))
    with patch.object(
        executor,
        "_triage_scan_findings",
        side_effect=JobExecutionError("advisor_unavailable", "password=hidden", retryable=True),
    ):
        executor.execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        scan = db.get(Scan, job.scan_id) if job else None
        assert job and job.status == "completed"
        assert scan and scan.status == "completed" and scan.gate_decision == "not_configured"
        assert scan.scanner_summary["advisor"]["error_code"] == "advisor_unavailable"
        assert "hidden" not in str(scan.scanner_summary)


def test_worker_activates_only_an_exact_bounded_cache_receipt(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_updater_job(runtime, component_ids=["grype-db"])
    claimed = _claim(runtime)
    active = {"generation_id": "a" * 64, "manifest_sha256": "b" * 64}
    previous = {"generation_id": "c" * 64, "manifest_sha256": "d" * 64}
    terminal = _operation_record(
        claimed,
        status="completed",
        result={
            "kind": "cache",
            "active": active,
            "previous_good": previous,
            "updated_components": ["grype-db"],
        },
    )

    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            assert request.headers["X-KodeSec-Request-Digest"] == claimed.payload["request_digest"]
            return httpx.Response(404, json={"detail": {"code": "not_found"}})
        assert request.method == "POST"
        payload = __import__("json").loads(request.content)
        assert payload == {
            "schema_version": 2,
            "preparation_budget": claimed.payload["preparation_budget"],
            "operation_id": claimed.external_run_id,
            "request_digest": claimed.payload["request_digest"],
            "kind": "cache_update",
            "requested_components": ["grype-db"],
            "attempt": 1,
            "max_attempts": 3,
        }
        return httpx.Response(200, json=terminal)

    WorkerExecutor(
        runtime,
        "worker-test",
        updater_client_factory=_updater_client_factory(handler),
    ).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        lifecycle = db.get(ScannerLifecycleState, "cache")
        assert job and job.status == "completed"
        assert lifecycle and lifecycle.status == "completed"
        assert lifecycle.active_generation == "a" * 64
        assert lifecycle.previous_generation == "c" * 64
        assert lifecycle.receipt["result"]["updated_components"] == ["grype-db"]
        assert lifecycle.receipt["schema_version"] == 2
        assert lifecycle.receipt["preparation_budget"] == claimed.payload["preparation_budget"]
        assert lifecycle.receipt["workflow_deadline_exceeded"] is False
        assert set(lifecycle.receipt) == {
            "schema_version",
            "preparation_budget",
            "workflow_deadline_exceeded",
            "operation_id",
            "request_digest",
            "kind",
            "requested_components",
            "attempt",
            "max_attempts",
            "updated_at",
            "result",
        }
    assert calls == [("GET", f"/operations/{claimed.external_run_id}"), ("POST", "/operations")]


def test_scanner_preparation_cache_fails_closed_when_catalog_cannot_supply_component(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    with runtime.session_factory() as db, db.begin():
        catalog = enqueue_job(
            db,
            kind="scanner_catalog_check",
            title="Preparation catalog",
            client_id="browser:test",
            idempotency_key="preparation-catalog-prerequisite",
            payload={"v": 1, "operation": "catalog_check"},
            max_attempts=3,
        ).job
        catalog.status = "completed"
        catalog.stage = "completed"
        catalog.progress = 100
        catalog.completed_at = datetime.now(timezone.utc)
        catalog_state = db.get(ScannerLifecycleState, "catalog")
        assert catalog_state is not None
        catalog_state.job_id = catalog.id
        catalog_state.status = "completed"
        catalog_state.receipt = {
            "result": {
                "components": [
                    {"component_id": "grype-db", "state": "requires_lock_refresh"},
                ],
            },
        }
        catalog_id = catalog.id

    cache_id = _seed_updater_job(runtime, component_ids=["grype-db"], max_attempts=1)
    with runtime.session_factory() as db, db.begin():
        cache = db.get(Job, cache_id)
        assert cache is not None
        cache.payload = {**cache.payload, "prerequisite_job_id": catalog_id}

    updater = Mock(side_effect=AssertionError("cache updater must not start"))
    executor = WorkerExecutor(runtime, "worker-test", updater_client_factory=updater)
    executor.execute(_claim(runtime))

    updater.assert_not_called()
    with runtime.session_factory() as db:
        cache = db.get(Job, cache_id)
        lifecycle = db.get(ScannerLifecycleState, "cache")
        assert cache is not None and cache.status == "failed"
        assert cache.error_code == "scanner_preparation_lock_refresh_required"
        assert cache.error_detail == (
            "Reviewed scanner database lock refresh required for: grype-db. "
            "Get refreshed reviewed CodeSecurity source, then rerun normal startup "
            "with your existing state and editor options to rebuild changed inputs. "
            "Choose Prepare all scanners afterward."
        )
        assert lifecycle is not None and lifecycle.status == "failed"


def test_worker_dispatches_and_persists_verified_cache_rollback(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_updater_job(runtime, kind="scanner_cache_rollback")
    claimed = _claim(runtime)
    restored = {"generation_id": "c" * 64, "manifest_sha256": "d" * 64}
    replaced = {"generation_id": "a" * 64, "manifest_sha256": "b" * 64}
    terminal = _operation_record(
        claimed,
        status="completed",
        result={
            "kind": "cache",
            "active": restored,
            "previous_good": replaced,
            "updated_components": [],
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"detail": {"code": "not_found"}})
        payload = __import__("json").loads(request.content)
        assert payload["kind"] == "cache_rollback"
        assert payload["requested_components"] == []
        return httpx.Response(200, json=terminal)

    WorkerExecutor(
        runtime,
        "worker-test",
        updater_client_factory=_updater_client_factory(handler),
    ).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        lifecycle = db.get(ScannerLifecycleState, "cache")
        assert job and job.status == "completed"
        assert job.detail == "Verified offline scanner cache rolled back atomically."
        assert lifecycle and lifecycle.status == "completed"
        assert lifecycle.active_generation == restored["generation_id"]
        assert lifecycle.previous_generation == replaced["generation_id"]
        assert lifecycle.receipt["kind"] == "cache_rollback"
        assert lifecycle.receipt["result"]["updated_components"] == []


def test_worker_rejects_cache_receipt_with_extra_component_without_activation(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_updater_job(runtime, component_ids=["grype-db"], max_attempts=1)
    claimed = _claim(runtime)
    terminal = _operation_record(
        claimed,
        status="completed",
        result={
            "kind": "cache",
            "active": {"generation_id": "a" * 64, "manifest_sha256": "b" * 64},
            "previous_good": None,
            "updated_components": ["grype-db", "trivy-db"],
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"detail": {"code": "not_found"}})
        return httpx.Response(200, json=terminal)

    WorkerExecutor(
        runtime,
        "worker-test",
        updater_client_factory=_updater_client_factory(handler),
    ).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        lifecycle = db.get(ScannerLifecycleState, "cache")
        assert job and job.status == "failed" and job.error_code == "updater_protocol"
        assert job.error_detail == "Updater cache receipt does not match the exact requested component set."
        assert lifecycle and lifecycle.status == "failed"
        assert lifecycle.active_generation is None and lifecycle.receipt == {}


def test_catalog_receipt_requires_exact_eight_and_only_admits_attested_candidate(
    postgres_engine,
    tmp_path,
) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    job_id = _seed_updater_job(runtime, kind="scanner_catalog_check")
    claimed = _claim(runtime)
    tool_ids = sorted(
        ["trivy", "gitleaks", "opengrep", "bearer", "grype", "checkov", "trufflehog", "syft"]
    )
    tools = [
        {
            "tool_id": tool_id,
            "state": "candidate_available" if tool_id == "trivy" else "current",
            "installed_version": "0.73.0" if tool_id == "trivy" else "1.0.0",
            "candidate_version": "0.74.0" if tool_id == "trivy" else None,
            "candidate_release_id": "trivy-v0.74.0-linux" if tool_id == "trivy" else None,
            "candidate_manifest_digest": "e" * 64 if tool_id == "trivy" else None,
        }
        for tool_id in tool_ids
    ]
    components = [
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
        for component_id in sorted(
            ["trivy-db", "trivy-java-db", "trivy-checks", "opengrep-reviewed-rules", "bearer-rules", "grype-db"]
        )
    ]
    terminal = _operation_record(
        claimed,
        status="completed",
        result={
            "kind": "catalog",
            "checked_at": "2026-08-12T12:00:00Z",
            "tools": tools,
            "components": components,
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"detail": {"code": "not_found"}})
        return httpx.Response(200, json=terminal)

    WorkerExecutor(
        runtime,
        "worker-test",
        updater_client_factory=_updater_client_factory(handler),
    ).execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        trivy = db.get(ScannerToolState, "trivy")
        current = db.get(ScannerToolState, "gitleaks")
        lifecycle = db.get(ScannerLifecycleState, "catalog")
        assert job and job.status == "completed"
        assert trivy and trivy.current_version == "0.73.0"
        assert trivy.latest_version == "0.74.0" and trivy.update_available is True
        assert trivy.candidate_release_id == "trivy-v0.74.0-linux"
        assert trivy.candidate_manifest_sha256 == "e" * 64
        assert current and current.candidate_manifest_sha256 is None
        assert lifecycle is not None
        persisted_components = lifecycle.receipt["result"]["components"]
        grype = next(
            item for item in persisted_components if item["component_id"] == "grype-db"
        )
        assert grype["state"] == "requires_lock_refresh"


def _advisor_fixture_admission(db, settings, *, model: str, default_model: str | None = None) -> dict:
    """Bind synthetic worker jobs to the same typed provider admission as the API."""

    profile = providers.normalize_profile({
        "id": "local-fixture", "name": "Local worker fixture", "transport": "local",
        "priority": 0, "enabled": True, "model": model, "model_digest": "a" * 64,
    })
    collection = providers.update_provider_status(
        {"revision": 1, "active_provider_id": None, "providers": [profile]},
        profile["id"], status="available", reason=None, reason_code=None, remediation="none",
    )
    profile = collection["providers"][0]
    providers.save_collection(db, collection)
    providers.save_receipt(db, {
        "schema": "lomo-advisor-provider-receipt/v1", "provider_id": profile["id"],
        "kind": "local", "route": "local", "model": model, "model_digest": profile["model_digest"],
        "status": "ready", "tested_at": "2026-08-25T12:00:00Z", "revision": profile["config_revision"],
    })
    return {
        "advisor_provider_collection_revision": collection["revision"],
        "advisor_provider_pin": providers.job_pin_snapshot({
            "provider_id": profile["id"], "transport": "local",
            "provider_config_revision": profile["config_revision"],
            "provider_config_digest": profile["config_digest"],
            "model": model, "model_digest": profile["model_digest"],
        }),
        "advisor": _advisor_snapshot(settings, {
            "ai_mode": "on", "ollama_base_url": "http://127.0.0.1:11434",
            "ollama_model": default_model or model, "ollama_thinking": False, "auto_triage_limit": 5,
            "advisor_providers": collection,
        }, db=db),
    }


def test_advisor_override_and_checkpoint_are_durable(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    with runtime.session_factory() as db, db.begin():
        project = Project(name="advisor", repo_path="/workspaces/advisor", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id, scan_finding_number=1, scanner="fixture", rule_id="rule", severity="high",
            file_path="app.py", start_line=1, end_line=1, message="finding", fingerprint="fingerprint",
        )
        db.add(finding)
        db.flush()
        result = enqueue_job(
            db, kind="advisor", title="Advisor", client_id="browser:test", idempotency_key="advisor-fixture",
            payload={
                "v": 1, "operation": "advisor_finding", "request_digest": "b" * 64,
                "scan_id": scan.id, "finding_id": finding.id, "model": "override-model",
                "include_existing": True, "finding_ids": [finding.id], "limit": 1,
                "expected_revisions": {str(finding.id): finding.revision},
                **_advisor_fixture_admission(
                    db, runtime.settings, model="override-model", default_model="default-model",
                ),
            },
            scan_id=scan.id, finding_id=finding.id, max_attempts=1,
        )
        job_id = result.job.id
    observed = {}

    def triage(
        _db,
        finding,
        _settings,
        *,
        model,
        config,
        expected_revision,
        commit,
        cancel_check,
        reserve_local_operation,
    ):
        observed.update(
            model=model,
            url=config["ollama_base_url"],
            expected_revision=expected_revision,
            commit=commit,
        )
        cancel_check()
        finding.ai_verdict = "needs_review"
        _db.add(finding)
        _db.flush()
        return {"finding_id": finding.id}

    with patch("kodesec_api.jobs.advisor.triage_finding_sync", side_effect=triage):
        WorkerExecutor(runtime, "worker-test").execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "completed"
        assert job.checkpoint["advisor_completed"] == [job.finding_id]
    assert observed == {
        "model": "override-model",
        "url": "http://127.0.0.1:11434",
        "expected_revision": 1,
        "commit": False,
    }


def test_bulk_advisor_failure_preserves_completed_checkpoint_and_safe_error(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    with runtime.session_factory() as db, db.begin():
        project = Project(name="advisor-bulk", repo_path="/workspaces/advisor-bulk", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        findings = [
            Finding(
                scan_id=scan.id,
                scan_finding_number=index,
                scanner="fixture",
                rule_id=f"rule-{index}",
                severity="high",
                file_path=f"app-{index}.py",
                start_line=index,
                end_line=index,
                message=f"finding {index}",
                fingerprint=f"advisor-bulk-{index}",
            )
            for index in (1, 2)
        ]
        db.add_all(findings)
        db.flush()
        finding_ids = [finding.id for finding in findings]
        result = enqueue_job(
            db,
            kind="advisor",
            title="Bulk advisor",
            client_id="browser:test",
            idempotency_key="advisor-bulk-fixture",
            payload={
                "v": 1,
                "operation": "advisor_scan",
                "request_digest": "c" * 64,
                "scan_id": scan.id,
                "model": "fixture-model",
                "include_existing": True,
                "finding_ids": finding_ids,
                "limit": None,
                **_advisor_fixture_admission(db, runtime.settings, model="fixture-model"),
            },
            scan_id=scan.id,
            max_attempts=1,
        )
        job_id = result.job.id

    calls = {"count": 0}

    def triage(_db, finding, _settings, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise HTTPException(503, "Ollama advisor unavailable: password=fixture-secret")
        finding.ai_verdict = "true_positive"
        finding.ai_confidence = 0.9
        finding.ai_reasoning = "Completed before the local advisor became unavailable."
        finding.ai_fix = "Review the validated evidence."
        _db.add(finding)

    with patch("kodesec_api.jobs.advisor.triage_finding_sync", side_effect=triage):
        WorkerExecutor(runtime, "worker-test").execute(_claim(runtime))

    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        persisted = list(db.query(Finding).filter(Finding.scan_id == job.scan_id).order_by(Finding.id)) if job else []
        assert job and job.status == "failed"
        assert job.error_code == "advisor_unavailable"
        assert job.error_detail == "Local Advisor is unavailable; 1/2 completed reviews were preserved."
        assert "fixture-secret" not in str(job.error_detail)
        assert job.checkpoint["advisor_completed"] == [finding_ids[0]]
        assert persisted[0].ai_verdict == "true_positive"
        assert persisted[1].ai_verdict is None


def test_advisor_revision_change_after_admission_fails_without_false_completion(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    with runtime.session_factory() as db, db.begin():
        project = Project(name="advisor-race", repo_path="/workspaces/advisor-race", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="race.rule",
            severity="high",
            file_path="app.py",
            start_line=1,
            end_line=1,
            message="finding",
            fingerprint="advisor-race",
        )
        db.add(finding)
        db.flush()
        result = enqueue_job(
            db,
            kind="advisor",
            title="Advisor race",
            client_id="browser:test",
            idempotency_key="advisor-race-fixture",
            payload={
                "v": 1,
                "operation": "advisor_finding",
                "request_digest": "d" * 64,
                "scan_id": scan.id,
                "finding_id": finding.id,
                "model": "fixture-model",
                "include_existing": True,
                "finding_ids": [finding.id],
                "expected_revisions": {str(finding.id): finding.revision},
                "limit": 1,
                **_advisor_fixture_admission(db, runtime.settings, model="fixture-model"),
            },
            scan_id=scan.id,
            finding_id=finding.id,
            max_attempts=3,
        )
        finding.message = "finding changed after command admission"
        finding.revision += 1
        scan.revision += 1
        scan.findings_revision += 1
        job_id = result.job.id

    WorkerExecutor(runtime, "worker-test").execute(_claim(runtime))
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        assert job and job.status == "failed"
        assert job.error_code == "advisor_selection_changed"
        assert job.checkpoint.get("advisor_completed", []) == []


@pytest.mark.parametrize("cancel_stage", ["before-call", "during-call"])
@pytest.mark.parametrize("existing_review", [False, True])
def test_advisor_prefill_is_cancellable_without_short_read_timeout(
    tmp_path, seed_ready_local_advisor, cancel_stage: str, existing_review: bool,
) -> None:
    from copy import deepcopy

    from kodesec_api.advisor import providers
    from kodesec_api.jobs.execution import CancellationRequested
    from kodesec_api.main import _advisor_snapshot

    # This is the connector/cancellation boundary, not a PostgreSQL lock-race
    # test. Keep all state disposable and all provider responses synthetic.
    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    runtime = Runtime.create(
        Settings(
            _env_file=None, DATABASE_URL="sqlite+pysqlite://",
            KODESEC_ALLOWED_ROOTS="/workspaces",
            KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
            KODESEC_ADVISOR_GRANT_SECRET="local-prefill-grant-fixture-" * 3,
        ),
        engine=engine,
    )
    pin = seed_ready_local_advisor(runtime)
    with runtime.session_factory() as db, db.begin():
        project = Project(name="slow-advisor", repo_path="/workspaces/slow", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id, scan_finding_number=1, scanner="fixture", rule_id="rule", severity="high",
            file_path="app.py", start_line=1, end_line=1, message="finding", fingerprint="slow",
            ai_verdict="needs_review" if existing_review else None,
            ai_confidence=0.5 if existing_review else None,
            ai_reasoning="Previously saved review." if existing_review else None,
            ai_fix="Previously saved fix." if existing_review else None,
        )
        db.add(finding)
        db.flush()
        finding_id = finding.id
        scan_id = scan.id
    with runtime.session_factory() as db:
        collection = providers.load_collection(db, runtime.settings)
        receipt = providers.load_receipt(db, str(pin["provider_id"]))
        snapshot = _advisor_snapshot(runtime.settings, {
            "ai_mode": "auto", "ollama_base_url": "http://127.0.0.1:11434",
            "ollama_model": pin["model"], "ollama_thinking": False,
            "advisor_providers": collection,
        }, db=db)
    config = WorkerExecutor(runtime, "prefill-fixture")._advisor_config(SimpleNamespace(
        kind="advisor", payload={
            "advisor": snapshot, "model": pin["model"],
            "advisor_provider_collection_revision": pin["provider_collection_revision"],
            "advisor_provider_pin": providers.job_pin_snapshot(pin),
        },
    ))
    started = asyncio.Event()
    release = asyncio.Event()
    returned = asyncio.Event()
    requests = []
    closed = []
    cancellation = CancellationRequested("synthetic prefill cancellation")

    class ConnectorResponse:
        is_redirect = False
        is_error = False
        headers = {}

        def __init__(self, path):
            self.path = path

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            closed.append(self.path)

        async def aiter_bytes(self):
            if self.path == "/v1/test":
                yield json.dumps({"receipt": receipt}).encode()
                return
            if self.path == "/v1/operations":
                yield json.dumps({"operation_id": requests[-1][1]["grant"]["nonce"], "status": "admitted"}).encode()
                return
            assert self.path == "/v1/generate"
            started.set()
            await release.wait()
            yield json.dumps({"response": json.dumps({
                "verdict": "true_positive", "confidence": 0.9,
                "reasoning": "Synthetic result must be discarded.", "fix": "Discarded fix.",
            }), "done": True}).encode()
            returned.set()

    class ConnectorClient:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False
            assert kwargs["trust_env"] is False
            self.timeout = kwargs["timeout"]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, *, json):
            base = runtime.settings.advisor_connector_url.rstrip("/")
            assert method == "POST" and url.startswith(f"{base}/v1/")
            path = url.removeprefix(base)
            requests.append((path, json, self.timeout.read))
            return ConnectorResponse(path)

    def cancel_check():
        if cancel_stage == "before-call" or started.is_set():
            raise cancellation

    def persisted_state(db):
        return [
            {column.name: deepcopy(getattr(row, column.name)) for column in row.__table__.columns}
            for row in (db.get(Finding, finding_id), db.get(Scan, scan_id))
        ]

    async def confirmed_cancel(_settings, _profile, confirmation, operation_id, *, local_binding=None):
        from kodesec_api.advisor import grants
        assert confirmation is None
        assert local_binding["transport"] == "local"
        assert requests[-1][1]["grant"]["nonce"] == operation_id
        grants.normalize_local_operation_binding(local_binding)
        release.set()
        return {"operation_id": operation_id, "status": "cancelled", "cleanup": "confirmed"}

    try:
        with runtime.session_factory() as db:
            before = persisted_state(db)
            finding = db.get(Finding, finding_id)
            with patch("kodesec_api.jobs.advisor.httpx.AsyncClient", ConnectorClient), patch(
                "kodesec_api.jobs.advisor._cancel_connector_operation_async", side_effect=confirmed_cancel,
            ), pytest.raises(
                CancellationRequested,
            ) as caught:
                triage_finding_sync(
                    db, finding, runtime.settings, model=pin["model"], config=config,
                    expected_revision=finding.revision, commit=False, cancel_check=cancel_check,
                )
            assert caught.value is cancellation
            # Committing here also proves cancellation left no staged review.
            db.commit()
        with runtime.session_factory() as db:
            assert persisted_state(db) == before
        if cancel_stage == "before-call":
            assert requests == [] and closed == []
            assert not started.is_set() and not returned.is_set()
        else:
            assert [path for path, _body, _timeout in requests] == ["/v1/test", "/v1/operations", "/v1/generate"]
            assert closed == ["/v1/test", "/v1/operations", "/v1/generate"] and returned.is_set()
            assert set(requests[0][1]) == {"provider"}
            _path, document, read_timeout = requests[2]
            assert read_timeout == 95.0
            assert providers.job_profile_snapshot(document["provider"]) == providers.job_profile_snapshot(
                requests[0][1]["provider"],
            )
            assert document["provider"]["transport"] == "local"
            assert document["provider"]["model_digest"] == pin["model_digest"]
            assert document["request"]["model"] == pin["model"]
            assert document["confirmation"] is None
            from kodesec_api.advisor import grants
            assert grants.verify_local_operation_grant(
                runtime.settings.advisor_grant_secret, document["grant"], document["provider"],
                document["request"]["prompt"],
            ) == document["grant"]
    finally:
        runtime.engine.dispose()


def test_worker_liveness_is_low_write_and_run_once_claims(postgres_engine, tmp_path) -> None:
    runtime = _runtime(postgres_engine, tmp_path)
    _seed_scan_job(runtime)
    now = datetime.now(timezone.utc)
    with runtime.session_factory() as db, db.begin():
        record_worker_heartbeat(db, "worker-test", now=now)
        db.add(RuntimeConfig(key=ARTIFACT_BOUNDARY_MARKER, value="completed"))
    with runtime.session_factory() as db:
        assert worker_heartbeat_is_fresh(db, stale_after_seconds=15, now=now)
    executed: list[int] = []

    class FakeExecutor:
        def __init__(self, _runtime, _owner):
            pass

        def execute(self, job):
            executed.append(job.id)

        def recover_exhausted(self, job):
            executed.append(job.id)

    with (
        patch("kodesec_api.worker.WorkerExecutor", FakeExecutor),
        patch("kodesec_api.worker.worker_ollama_available_sync", return_value=(True, ["fixture-model"], None)),
    ):
        assert run_worker(runtime, once=True, worker_id="worker-once") == 1
    assert len(executed) == 1


def _local_operation_runtime(tmp_path, *, count=1):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    runtime = Runtime.create(Settings(
        _env_file=None, DATABASE_URL="sqlite+pysqlite://", KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_ADVISOR_GRANT_SECRET="fixture-worker-connector-grant-" * 2,
    ), engine=engine)
    with runtime.session_factory() as db, db.begin():
        project = Project(name="local-operation", repo_path="/workspaces/local-operation", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={},
                    gate_decision="block", gate_reasons=["scanner high severity"])
        db.add(scan)
        db.flush()
        findings = [Finding(scan_id=scan.id, scan_finding_number=index, scanner="fixture", rule_id="local-rule",
                            severity="high", file_path=f"app-{index}.py", message="bounded finding",
                            fingerprint=f"local-operation-{index}") for index in range(1, count + 1)]
        db.add_all(findings)
        db.flush()
        ids = [finding.id for finding in findings]
        admission = _advisor_fixture_admission(db, runtime.settings, model="fixture-model")
        result = enqueue_job(db, kind="advisor", title="Local Advisor", client_id="browser:test",
                             idempotency_key="local-operation", scan_id=scan.id,
                             finding_id=ids[0] if count == 1 else None, max_attempts=1, payload={
            "v": 1, "operation": "advisor_finding" if count == 1 else "advisor_scan",
            "request_digest": "b" * 64, "scan_id": scan.id,
            "finding_id": ids[0] if count == 1 else None, "finding_ids": ids,
            "expected_revisions": {str(finding.id): finding.revision for finding in findings},
            "model": "fixture-model", "include_existing": True, "limit": count, **admission,
        })
        job_id = result.job.id
    # Claim concurrency is PostgreSQL-only; these tests isolate the already
    # claimed worker's checkpoint/cancellation boundary with disposable state.
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, job_id)
        job.status = "leased"
        job.attempt = 1
        job.lease_owner = "worker-test"
        job.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        db.flush()
        claimed = ClaimedJob.from_model(job)
    return runtime, claimed, ids


def test_local_operations_are_persisted_before_admission_and_distinct_per_finding(tmp_path, monkeypatch):
    from kodesec_api.advisor import grants
    from kodesec_api.jobs import advisor

    # SQLite supplies no timezone; this unit fixture owns its explicit UTC clock.
    monkeypatch.setattr("kodesec_api.jobs.repository._time", lambda value, session: value or datetime.now(timezone.utc))
    runtime, claimed, ids = _local_operation_runtime(tmp_path, count=2)
    executor = WorkerExecutor(runtime, "worker-test")
    executor._mark_running(claimed)
    admitted = []
    monkeypatch.setattr(advisor, "revalidate_local_provider_sync", lambda db, profile, settings: profile)

    def connector(settings, path, document, **kwargs):
        if path == "/v1/test":
            with runtime.session_factory() as db:
                return {"receipt": providers.load_receipt(db, document["provider"]["id"])}
        grant = document["grant"]
        grants.verify_local_operation_grant(settings.advisor_grant_secret, grant,
                                           document["provider"], document["request"]["prompt"])
        if path == "/v1/operations":
            with runtime.session_factory() as db:
                job = db.get(Job, claimed.id)
                record = job.checkpoint["local_advisor_operation"]
                assert record["advisor_operation_id"] == grant["nonce"]
                assert record["finding_id"] == ids[len(admitted)]
                assert record["finding_revision"] == 1 and record["attempt"] == claimed.attempt
                assert record["binding"] == grants.local_operation_binding(document["provider"], grant["prompt_sha256"])
                serialized = json.dumps(job.checkpoint)
                assert document["request"]["prompt"] not in serialized
                assert "signature" not in serialized and settings.advisor_grant_secret not in serialized
            admitted.append(grant["nonce"])
            return {"operation_id": grant["nonce"], "status": "admitted"}
        assert path == "/v1/generate"
        return {"response": json.dumps({"verdict": "needs_review", "confidence": .5,
                                        "reasoning": "Bounded synthetic review.", "fix": "Review evidence."}), "done": True}

    monkeypatch.setattr(advisor, "_connector_json", connector)
    monitor = SimpleNamespace(raise_if_unusable=lambda: None)
    try:
        checkpoint = executor._triage_scan_findings(claimed, monitor, {}, automatic=False)
        assert len(set(admitted)) == 2
        assert checkpoint["advisor_completed"] == ids
        assert "local_advisor_operation" not in checkpoint
        with runtime.session_factory() as db:
            job = db.get(Job, claimed.id)
            scan = db.get(Scan, claimed.scan_id)
            assert job.checkpoint == checkpoint
            assert scan.gate_decision == "block" and scan.gate_reasons == ["scanner high severity"]
            assert all(db.get(Finding, finding_id).ai_verdict == "needs_review" for finding_id in ids)
    finally:
        engine = runtime.engine
        engine.dispose()


@pytest.mark.parametrize("acknowledged", [True, False])
def test_recovered_local_cancellation_requires_exact_cleanup_ack(tmp_path, monkeypatch, acknowledged):
    from kodesec_api.advisor import grants
    from kodesec_api.jobs import advisor

    monkeypatch.setattr("kodesec_api.jobs.repository._time", lambda value, session: value or datetime.now(timezone.utc))
    runtime, claimed, ids = _local_operation_runtime(tmp_path)
    executor = WorkerExecutor(runtime, "worker-test")
    config = executor._advisor_config(claimed)
    profile = providers.provider_by_id(config["advisor_providers"], config["advisor_provider_pin"]["provider_id"])
    grant = grants.mint_local_operation_grant(runtime.settings.advisor_grant_secret, profile, "bounded fixture")
    record = {"advisor_operation_id": grant["nonce"], "finding_id": ids[0], "finding_revision": 1,
              "attempt": claimed.attempt, "binding": grants.local_operation_binding(profile, grant["prompt_sha256"])}
    with runtime.session_factory() as db, db.begin():
        job = db.get(Job, claimed.id)
        job.checkpoint = {"local_advisor_operation": record}
        db.flush()
        request_cancellation(db, claimed.id)
        db.flush()
        # Deliberately leave claimed.checkpoint stale: recovery must reload DB.
        from dataclasses import replace
        claimed = replace(claimed, status="cancelling")

    calls = []
    def cancel(binding, operation_id, settings):
        with runtime.session_factory() as db:
            assert db.get(Job, claimed.id).status == "cancelling"
            assert db.get(Finding, ids[0]).ai_verdict is None
        assert binding == record["binding"] and operation_id == record["advisor_operation_id"]
        calls.append(operation_id)
        if not acknowledged:
            raise advisor.ConnectorCleanupUnconfirmed("synthetic pending cleanup")
        return {"operation_id": operation_id, "status": "cancelled", "cleanup": "confirmed"}

    monkeypatch.setattr(advisor, "cancel_local_operation_sync", cancel)
    try:
        executor.execute(claimed)
        assert calls == [record["advisor_operation_id"]]
        with runtime.session_factory() as db:
            job = db.get(Job, claimed.id)
            assert job.status == ("cancelled" if acknowledged else "cancelling")
            assert job.checkpoint["local_advisor_operation"] == record
            assert db.get(Finding, ids[0]).ai_verdict is None
            scan = db.get(Scan, claimed.scan_id)
            assert scan.gate_decision == "block" and scan.gate_reasons == ["scanner high severity"]
    finally:
        runtime.engine.dispose()
