from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event
import time

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from kodesec_api.db import initialize_database
from kodesec_api.events import install_outbox_listeners
from kodesec_api.jobs.repository import (
    CacheCommitInProgressError,
    IdempotencyConflictError,
    InvalidJobTransition,
    LeaseLostError,
    claim_next_job,
    complete_job,
    durable_idempotency_key,
    enqueue_job,
    fail_job,
    finalize_cancelled,
    heartbeat_job,
    mark_job_running,
    request_cancellation,
    retry_failed_job,
    update_job_progress,
)
from kodesec_api.models import EventOutbox, Job, ScannerLifecycleState
from kodesec_api.preparation_budget import issue_budget


def _initialize(engine) -> None:
    initialize_database(engine)


def _payload(operation: str = "scan", marker: str = "fixture") -> dict:
    return {"v": 1, "operation": operation, "marker": marker}


def _enqueue(
    session: Session,
    key: str,
    *,
    kind: str = "scan",
    marker: str = "fixture",
    priority: int = 0,
    max_attempts: int = 3,
):
    return enqueue_job(
        session,
        kind=kind,
        title=f"{kind} {key}",
        client_id="browser:test",
        idempotency_key=key,
        payload={**_payload(kind, marker), **({"preparation_budget": issue_budget().model_dump()} if kind in {"scanner_catalog_check", "scanner_cache_update"} else {})},
        priority=priority,
        max_attempts=max_attempts,
    )


def test_enqueue_is_idempotent_and_rejects_payload_rebinding(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        first = _enqueue(session, "command-1")
        session.commit()
        first_id = first.job.id
        assert first.created is True

    with Session(postgres_engine) as session:
        replay = _enqueue(session, "command-1")
        assert replay.created is False
        assert replay.job.id == first_id
        with pytest.raises(IdempotencyConflictError, match="different command"):
            _enqueue(session, "command-1", marker="different")


def test_job_documents_enforce_utf8_bytes_redact_secrets_and_preserve_digest(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        result = enqueue_job(
            session,
            kind="maintenance",
            title="Unicode boundary",
            client_id="browser:test",
            idempotency_key="unicode-boundary",
            payload={
                "v": 1,
                "operation": "maintenance",
                "request_digest": "a" * 64,
                "source_snapshot_digest": "b" * 64,
                "untyped_digest": "c" * 64,
                "note": "password=fixture-secret",
            },
        )
        session.commit()
        assert result.job.payload["request_digest"] == "a" * 64
        assert result.job.payload["source_snapshot_digest"] == "b" * 64
        assert result.job.payload["untyped_digest"] == "[REDACTED]"
        assert "fixture-secret" not in str(result.job.payload)

    with Session(postgres_engine) as session, pytest.raises(ValueError, match="UTF-8 bytes"):
        enqueue_job(
            session,
            kind="maintenance",
            title="Too large",
            client_id="browser:test",
            idempotency_key="unicode-too-large",
            payload={"v": 1, "operation": "maintenance", "note": "é" * 9000},
        )


def test_operator_retry_is_revision_fenced_and_preserves_run_identity(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        job = enqueue_job(
            session,
            kind="scan",
            title="Retry scan",
            client_id="browser:test",
            idempotency_key="retry-command",
            payload=_payload(),
            external_run_id="00000000-0000-4000-8000-000000000001",
            max_attempts=1,
        ).job
        session.commit()
        job_id = job.id
    with Session(postgres_engine) as session:
        claimed = claim_next_job(session, worker_id="worker", lease_seconds=30)
        assert claimed
        fail_job(
            session,
            claimed.id,
            worker_id="worker",
            attempt=claimed.attempt,
            error_code="fixture",
            error_detail="fixture",
            retryable=False,
        )
        session.commit()
        revision = claimed.revision
    with Session(postgres_engine) as session:
        retried = retry_failed_job(session, job_id, expected_revision=revision)
        assert retried.status == "queued"
        assert retried.max_attempts == 2
        assert retried.external_run_id == "00000000-0000-4000-8000-000000000001"
        with pytest.raises(InvalidJobTransition, match="revision changed"):
            retry_failed_job(session, job_id, expected_revision=revision)


def test_scanner_lifecycle_retry_never_expands_beyond_three_updater_attempts(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        job = _enqueue(
            session,
            "updater-retry-bound",
            kind="scanner_cache_update",
            max_attempts=3,
        ).job
        job.status = "failed"
        job.attempt = 3
        job.completed_at = datetime.now(timezone.utc)
        session.commit()
        job_id = job.id
        revision = job.revision

    with Session(postgres_engine) as session:
        with pytest.raises(InvalidJobTransition, match="maximum retry limit"):
            retry_failed_job(session, job_id, expected_revision=revision)


def test_concurrent_enqueue_creates_one_logical_job(postgres_engine) -> None:
    _initialize(postgres_engine)
    barrier = Barrier(2)

    def submit(_: int) -> tuple[int, bool]:
        with Session(postgres_engine) as session:
            barrier.wait(timeout=5)
            result = _enqueue(session, "concurrent-command")
            session.commit()
            return result.job.id, result.created

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, range(2)))

    assert len({job_id for job_id, _ in results}) == 1
    assert sorted(created for _, created in results) == [False, True]
    with Session(postgres_engine) as session:
        assert session.scalar(
            select(Job).where(Job.idempotency_key == durable_idempotency_key("concurrent-command"))
        ) is not None
        assert len(list(session.scalars(select(Job)))) == 1


def test_claim_uses_priority_fifo_and_skip_locked(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        low = _enqueue(session, "low", kind="maintenance", priority=-1).job
        high = _enqueue(session, "high", kind="maintenance", priority=5).job
        session.commit()
        low_id, high_id = low.id, high.id

    first_session = Session(postgres_engine)
    second_session = Session(postgres_engine)
    try:
        first = claim_next_job(first_session, worker_id="worker-a", kinds={"maintenance"})
        assert first and first.id == high_id
        second = claim_next_job(second_session, worker_id="worker-b", kinds={"maintenance"})
        assert second and second.id == low_id
        second_session.commit()
        first_session.commit()
    finally:
        first_session.close()
        second_session.close()


def test_concurrent_workers_admit_only_one_scan(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        _enqueue(session, "scan-a", kind="scan")
        _enqueue(session, "scan-b", kind="scan")
        session.commit()
    barrier = Barrier(2)

    def claim(worker_number: int) -> int | None:
        with Session(postgres_engine) as session:
            barrier.wait(timeout=5)
            job = claim_next_job(session, worker_id=f"worker-{worker_number}", kinds={"scan"})
            session.commit()
            return job.id if job else None

    with ThreadPoolExecutor(max_workers=2) as executor:
        claimed = list(executor.map(claim, range(2)))

    assert len([job_id for job_id in claimed if job_id is not None]) == 1
    with Session(postgres_engine) as session:
        jobs = list(session.scalars(select(Job).order_by(Job.id)))
        assert [job.status for job in jobs].count("leased") == 1
        assert [job.status for job in jobs].count("queued") == 1


def test_cache_mutation_and_scan_share_one_cross_kind_admission_lease(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        _enqueue(session, "scan-cache-boundary", kind="scan")
        _enqueue(session, "cache-scan-boundary", kind="scanner_cache_update")
        _enqueue(session, "catalog-coexists", kind="scanner_catalog_check")
        session.commit()

    with Session(postgres_engine) as first, Session(postgres_engine) as second:
        scan = claim_next_job(first, worker_id="scan-worker", kinds={"scan"})
        assert scan is not None and scan.kind == "scan"
        first.commit()

        assert claim_next_job(
            second,
            worker_id="cache-worker",
            kinds={"scanner_cache_update"},
        ) is None
        catalog = claim_next_job(
            second,
            worker_id="catalog-worker",
            kinds={"scanner_catalog_check"},
        )
        assert catalog is not None and catalog.kind == "scanner_catalog_check"
        second.commit()

    with Session(postgres_engine) as session:
        active = list(
            session.scalars(
                select(Job).where(Job.status.in_(("leased", "running", "cancelling")))
            )
        )
        assert {job.kind for job in active} == {"scan", "scanner_catalog_check"}
        cache = session.scalar(select(Job).where(Job.kind == "scanner_cache_update"))
        assert cache is not None and cache.status == "queued"


def test_scanner_preparation_cache_waits_for_catalog_and_inherits_cancellation(postgres_engine) -> None:
    _initialize(postgres_engine)
    with Session(postgres_engine) as session:
        catalog = enqueue_job(
            session,
            kind="scanner_catalog_check",
            title="Preparation catalog",
            client_id="browser:test",
            idempotency_key="preparation-catalog",
            payload={"v": 1, "operation": "catalog_check", "preparation_budget": issue_budget().model_dump()},
        ).job
        cache = enqueue_job(
            session,
            kind="scanner_cache_update",
            title="Preparation cache",
            client_id="browser:test",
            idempotency_key="preparation-cache",
            payload={
                "v": 1,
                "operation": "cache_update",
                "prerequisite_job_id": catalog.id,
                "preparation_budget": catalog.payload["preparation_budget"],
            },
        ).job
        cache_id = cache.id
        catalog_id = catalog.id
        session.commit()

    with Session(postgres_engine) as session:
        assert claim_next_job(
            session,
            worker_id="cache-worker",
            kinds={"scanner_cache_update"},
        ) is None
        catalog = session.get(Job, catalog_id)
        assert catalog is not None
        catalog.status = "cancelled"
        catalog.stage = "cancelled"
        catalog.completed_at = datetime.now(timezone.utc)
        session.commit()

    with Session(postgres_engine) as session:
        claimed = claim_next_job(
            session,
            worker_id="cache-worker",
            kinds={"scanner_cache_update"},
        )
        assert claimed is not None and claimed.id == cache_id
        assert claimed.status == "cancelling"
        assert claimed.attempt == 0
        assert claimed.cancel_requested_at is not None


def test_expired_lease_is_reclaimed_and_stale_attempt_is_fenced(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job_id = _enqueue(session, "recover", kind="maintenance").job.id
        first = claim_next_job(
            session,
            worker_id="lost-worker",
            lease_seconds=30,
            now=initial,
            kinds={"maintenance"},
        )
        assert first and first.attempt == 1
        session.commit()

    with Session(postgres_engine) as session:
        assert claim_next_job(
            session,
            worker_id="early-worker",
            now=initial + timedelta(seconds=29),
            kinds={"maintenance"},
        ) is None
        session.rollback()

    reclaimed_at = initial + timedelta(seconds=31)
    with Session(postgres_engine) as session:
        reclaimed = claim_next_job(
            session,
            worker_id="replacement",
            now=reclaimed_at,
            kinds={"maintenance"},
        )
        assert reclaimed and reclaimed.id == job_id
        assert reclaimed.attempt == 2
        assert reclaimed.lease_owner == "replacement"
        session.commit()

    with Session(postgres_engine) as session:
        with pytest.raises(LeaseLostError):
            heartbeat_job(
                session,
                job_id,
                worker_id="lost-worker",
                attempt=1,
                now=reclaimed_at,
            )


def test_heartbeat_renews_without_revision_noise(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job = _enqueue(session, "heartbeat", kind="maintenance").job
        claimed = claim_next_job(session, worker_id="worker", now=initial, kinds={"maintenance"})
        assert claimed and claimed.id == job.id
        revision = claimed.revision
        renewed = heartbeat_job(
            session,
            job.id,
            worker_id="worker",
            attempt=claimed.attempt,
            now=initial + timedelta(seconds=10),
        )
        assert renewed.revision == revision
        assert renewed.heartbeat_at == initial + timedelta(seconds=10)
        assert renewed.lease_expires_at == initial + timedelta(seconds=40)


def test_progress_completion_and_cancellation_race_are_fenced(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job_id = _enqueue(session, "lifecycle", kind="maintenance").job.id
        claimed = claim_next_job(session, worker_id="worker", now=initial, kinds={"maintenance"})
        assert claimed
        running = mark_job_running(
            session,
            job_id,
            worker_id="worker",
            attempt=claimed.attempt,
            stage="executing",
            progress=5,
            now=initial + timedelta(seconds=1),
        )
        revision = running.revision
        progressed = update_job_progress(
            session,
            job_id,
            worker_id="worker",
            attempt=claimed.attempt,
            progress=40,
            checkpoint={"stable_run_id": "fixture-run"},
            now=initial + timedelta(seconds=2),
        )
        assert progressed.revision == revision + 1
        assert progressed.checkpoint == {"stable_run_id": "fixture-run"}
        cancellation = request_cancellation(
            session,
            job_id,
            now=initial + timedelta(seconds=3),
        )
        assert cancellation.changed is True
        with pytest.raises(InvalidJobTransition):
            complete_job(
                session,
                job_id,
                worker_id="worker",
                attempt=claimed.attempt,
                now=initial + timedelta(seconds=4),
            )
        cancelled = finalize_cancelled(
            session,
            job_id,
            worker_id="worker",
            attempt=claimed.attempt,
            now=initial + timedelta(seconds=4),
        )
        assert cancelled.status == "cancelled"
        assert cancelled.progress == 40
        assert cancelled.lease_owner is None


def test_cache_cancellation_refreshes_stale_preload_after_waiting_for_worker_commit(postgres_engine) -> None:
    _initialize(postgres_engine)
    install_outbox_listeners()
    with Session(postgres_engine) as session:
        job = _enqueue(session, "cache-commit-lock", kind="scanner_cache_update").job
        job.status = "running"
        job.stage = "staging"
        state = session.get(ScannerLifecycleState, "cache")
        assert state is not None
        state.job_id = job.id
        state.status = "running"
        session.commit()
        job_id = job.id

    def persisted_rows(session):
        # The worker's after_flush hook stages outbox rows; Core selects below
        # do not trigger ORM autoflush, so include those rows before comparison.
        session.flush()
        return tuple(
            session.execute(select(model.__table__).order_by(*model.__table__.primary_key.columns)).all()
            for model in (Job, ScannerLifecycleState, EventOutbox)
        )

    preloaded, start_cancellation, for_update_attempted = Event(), Event(), Event()
    cancellation_pid = {}

    def cancel_in_own_session():
        with Session(postgres_engine) as session:
            connection = session.connection()
            connection.execute(text("SET LOCAL lock_timeout = '5s'"))
            cancellation_pid["value"] = connection.scalar(text("SELECT pg_backend_pid()"))
            cached = session.get(Job, job_id)
            assert cached is not None and cached.stage == "staging"

            def observe_lock(_conn, _cursor, statement, _parameters, _context, _executemany):
                if "FOR UPDATE" in statement:
                    for_update_attempted.set()

            event.listen(connection, "before_cursor_execute", observe_lock)
            try:
                preloaded.set()
                assert start_cancellation.wait(timeout=5), "worker did not release cancellation attempt"
                with pytest.raises(CacheCommitInProgressError):
                    request_cancellation(session, job_id)
                assert cached.stage == "committing" and cached.status == "running"
                assert cached.cancel_requested_at is None
                session.commit()
            finally:
                event.remove(connection, "before_cursor_execute", observe_lock)

    worker = Session(postgres_engine)
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(cancel_in_own_session)
    try:
        assert preloaded.wait(timeout=5), "cancellation session did not preload staging"
        worker_pid = worker.scalar(text("SELECT pg_backend_pid()"))
        job = worker.scalar(select(Job).where(Job.id == job_id).with_for_update())
        assert job is not None
        job.stage = "committing"
        job.revision += 1
        worker.flush()
        baseline = persisted_rows(worker)
        assert baseline[2], "mutation comparison must include actual outbox rows"
        start_cancellation.set()
        assert for_update_attempted.wait(timeout=5), "cancellation did not request its row lock"
        deadline = time.monotonic() + 3
        while worker_pid not in worker.scalar(
            text("SELECT pg_blocking_pids(:pid)"), {"pid": cancellation_pid["value"]},
        ):
            assert time.monotonic() < deadline, "PostgreSQL did not observe cancellation blocked by this worker"
            time.sleep(0.01)
        worker.commit()
        future.result(timeout=5)
        with Session(postgres_engine) as session:
            assert persisted_rows(session) == baseline
    finally:
        # Release the lock before joining, including on failed synchronization.
        worker.rollback()
        worker.close()
        start_cancellation.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_cancellation_is_reclaimable_after_attempt_budget_exhaustion(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job = _enqueue(session, "cancel-exhausted", kind="maintenance", max_attempts=1).job
        claimed = claim_next_job(session, worker_id="lost-worker", now=initial, kinds={"maintenance"})
        assert claimed and claimed.attempt == 1
        request_cancellation(session, job.id, now=initial + timedelta(seconds=1))
        session.commit()
        job_id = job.id

    with Session(postgres_engine) as session:
        reclaimed = claim_next_job(
            session,
            worker_id="replacement",
            now=initial + timedelta(seconds=31),
            kinds={"maintenance"},
        )
        assert reclaimed and reclaimed.id == job_id
        assert reclaimed.status == "cancelling"
        assert reclaimed.attempt == 1
        finalized = finalize_cancelled(
            session,
            job_id,
            worker_id="replacement",
            attempt=1,
            now=initial + timedelta(seconds=32),
        )
        assert finalized.status == "cancelled"


def test_cancelled_retryable_job_does_not_expose_stale_failure(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job = _enqueue(session, "retry-then-cancel", kind="maintenance", max_attempts=2).job
        claimed = claim_next_job(session, worker_id="first", now=initial, kinds={"maintenance"})
        assert claimed
        queued = fail_job(
            session,
            job.id,
            worker_id="first",
            attempt=1,
            error_code="temporary",
            error_detail="temporary failure",
            retryable=True,
            now=initial + timedelta(seconds=1),
        )
        assert queued.status == "queued" and queued.error_code == "temporary"
        request_cancellation(session, job.id, now=initial + timedelta(seconds=2))
        cancelled_claim = claim_next_job(
            session,
            worker_id="cleanup",
            now=initial + timedelta(seconds=3),
            kinds={"maintenance"},
        )
        assert cancelled_claim and cancelled_claim.status == "cancelling"
        terminal = finalize_cancelled(
            session,
            job.id,
            worker_id="cleanup",
            attempt=1,
            now=initial + timedelta(seconds=4),
        )
        assert terminal.status == "cancelled"
        assert terminal.error is None
        assert terminal.error_code is None
        assert terminal.error_detail is None


def test_scan_cancellation_recovery_serializes_with_new_scan_claim(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        first = _enqueue(session, "cancel-first", kind="scan").job
        _enqueue(session, "queued-second", kind="scan")
        claimed = claim_next_job(session, worker_id="crashed", now=initial, kinds={"scan"})
        assert claimed and claimed.id == first.id
        request_cancellation(session, first.id, now=initial + timedelta(seconds=1))
        session.commit()

    recovery_session = Session(postgres_engine)
    contender_started = Event()

    def claim_contender() -> int | None:
        with Session(postgres_engine) as contender_session:
            contender_started.set()
            contender = claim_next_job(
                contender_session,
                worker_id="contender",
                now=initial + timedelta(seconds=31),
                kinds={"scan"},
            )
            contender_session.commit()
            return contender.id if contender is not None else None

    try:
        recovery = claim_next_job(
            recovery_session,
            worker_id="cleanup",
            now=initial + timedelta(seconds=31),
            kinds={"scan"},
        )
        assert recovery and recovery.status == "cancelling"
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(claim_contender)
            assert contender_started.wait(timeout=5)
            time.sleep(0.05)
            assert not future.done(), "the contender bypassed cancellation admission serialization"
            recovery_session.commit()
            assert future.result(timeout=5) is None
    finally:
        recovery_session.rollback()
        recovery_session.close()


def test_expired_final_attempt_is_leased_only_for_terminal_recovery(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job = _enqueue(session, "exhausted-recovery", kind="maintenance", max_attempts=1).job
        first = claim_next_job(session, worker_id="lost-worker", now=initial, kinds={"maintenance"})
        assert first and first.attempt == 1
        session.commit()
        job_id = job.id

    with Session(postgres_engine) as session:
        recovery = claim_next_job(
            session,
            worker_id="recovery-worker",
            now=initial + timedelta(seconds=31),
            kinds={"maintenance"},
        )
        assert recovery and recovery.id == job_id
        assert recovery.status == "leased"
        assert recovery.stage == "recovery_exhausted"
        assert recovery.attempt == recovery.max_attempts == 1
        terminal = fail_job(
            session,
            job_id,
            worker_id="recovery-worker",
            attempt=1,
            error_code="attempts_exhausted",
            error_detail="Worker lease expired after the final allowed attempt.",
            retryable=False,
            now=initial + timedelta(seconds=32),
        )
        assert terminal.status == "failed"
        assert terminal.attempt == 1
        assert terminal.error_code == "attempts_exhausted"


def test_retry_respects_attempt_budget_and_completion_is_terminal(postgres_engine) -> None:
    _initialize(postgres_engine)
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session:
        job = _enqueue(session, "retry", kind="maintenance", max_attempts=2).job
        first = claim_next_job(session, worker_id="worker", now=initial, kinds={"maintenance"})
        assert first
        retry = fail_job(
            session,
            job.id,
            worker_id="worker",
            attempt=1,
            error_code="temporary",
            error_detail="safe retryable failure",
            retryable=True,
            now=initial + timedelta(seconds=1),
        )
        assert retry.status == "queued"
        second = claim_next_job(
            session,
            worker_id="worker",
            now=initial + timedelta(seconds=2),
            kinds={"maintenance"},
        )
        assert second and second.attempt == 2
        mark_job_running(
            session,
            job.id,
            worker_id="worker",
            attempt=2,
            stage="executing",
            now=initial + timedelta(seconds=3),
        )
        completed = complete_job(
            session,
            job.id,
            worker_id="worker",
            attempt=2,
            result_ref="scan:fixture",
            now=initial + timedelta(seconds=4),
        )
        assert completed.status == "completed"
        assert completed.progress == 100
        assert completed.result_ref == "scan:fixture"
        assert request_cancellation(session, job.id).changed is False


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"status": "pending"}, "ck_jobs_status"),
        ({"progress": 101}, "ck_jobs_progress"),
        ({"priority": 11}, "ck_jobs_priority"),
        ({"attempt": 4, "max_attempts": 3}, "ck_jobs_attempt"),
        ({"client_id": "only-client", "idempotency_key": None}, "ck_jobs_idempotency_pair"),
    ],
)
def test_database_constraints_reject_invalid_job_state(postgres_engine, overrides, constraint) -> None:
    _initialize(postgres_engine)
    values = {
        "kind": "maintenance",
        "title": "constraint fixture",
        "status": "queued",
        "payload": {"v": 1},
        "checkpoint": {},
        "priority": 0,
        "attempt": 0,
        "max_attempts": 3,
        "revision": 1,
    }
    values.update(overrides)
    with Session(postgres_engine) as session:
        session.add(Job(**values))
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
    assert constraint in str(exc_info.value.orig)


@pytest.mark.parametrize('cancelled', [False, True])
def test_readonly_recovery_queue_expiry_preserves_cancellation_and_max1(postgres_engine, cancelled):
    from kodesec_api.recovery_contract import issue_recovery_budget
    _initialize(postgres_engine)
    now = datetime.now(timezone.utc)
    with Session(postgres_engine) as session:
        record = enqueue_job(session, kind='scanner_cache_reconcile', title='Reconcile cache outcome',
            client_id='browser:test', idempotency_key='explicit-readonly-expired', max_attempts=1,
            payload={'v': 1, 'operation': 'cache_reconcile',
                     'reconciliation_budget': issue_recovery_budget(now=now-timedelta(seconds=901)).model_dump()},
        ).job
        record.created_at = now-timedelta(seconds=901)
        record.updated_at = record.created_at
        record.cancel_requested_at = now if cancelled else None
        session.commit()
        job_id = record.id
    with Session(postgres_engine) as session:
        claimed = claim_next_job(session, worker_id='readonly-fixture', now=now)
        session.commit()
        original = session.get(Job, job_id)
        if cancelled:
            assert claimed is not None and claimed.status == 'cancelling'
        else:
            assert claimed is None and original.status == 'failed'
            assert original.error_code == 'scanner_reconciliation_deadline'
        assert original.max_attempts == 1
        original.status = 'failed'
        session.commit()
        with pytest.raises(InvalidJobTransition, match='single-attempt'):
            retry_failed_job(session, job_id, expected_revision=original.revision, now=now)


@pytest.mark.parametrize('action', ['start', 'progress', 'complete'])
@pytest.mark.parametrize('fence', ['current', 'wrong_owner', 'wrong_attempt', 'expired'])
def test_cancellation_preserves_cleanup_ownership(postgres_engine, action, fence) -> None:
    """A Cancel/progress race must enter cleanup, not wait for lease expiry."""
    _initialize(postgres_engine)
    initial = datetime(2026, 10, 3, 5, 0, tzinfo=timezone.utc)
    with Session(postgres_engine) as session, session.begin():
        job_id = _enqueue(session, 'cancel-cleanup-owner', kind='maintenance').job.id
        claimed = claim_next_job(session, worker_id='owner', now=initial, kinds={'maintenance'})
        attempt = claimed.attempt
        if action != 'start':
            mark_job_running(session, job_id, worker_id='owner', attempt=attempt,
                             stage='executing', now=initial + timedelta(seconds=1))
    # A separate transaction models the real browser cancellation endpoint.
    with Session(postgres_engine) as session, session.begin():
        request_cancellation(session, job_id, now=initial + timedelta(seconds=2))
    kwargs = dict(worker_id='other' if fence == 'wrong_owner' else 'owner',
                  attempt=attempt + 1 if fence == 'wrong_attempt' else attempt,
                  now=initial + timedelta(seconds=31 if fence == 'expired' else 3))
    with Session(postgres_engine) as session:
        error = InvalidJobTransition if fence == 'current' else LeaseLostError
        with pytest.raises(error):
            if action == 'start':
                mark_job_running(session, job_id, stage='executing', **kwargs)
            elif action == 'progress':
                update_job_progress(session, job_id, progress=50, **kwargs)
            else:
                complete_job(session, job_id, **kwargs)
        session.rollback()
        current = session.get(Job, job_id)
        assert current.status == 'cancelling'
        assert current.lease_owner == 'owner' and current.attempt == attempt
        assert current.progress == 0 and current.completed_at is None
        assert current.cancel_requested_at == initial + timedelta(seconds=2)
