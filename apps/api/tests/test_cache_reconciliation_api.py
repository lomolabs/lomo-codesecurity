"""Explicit browser recovery, immutable original outcome and strict private wire."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from kodesec_api import main
from kodesec_api.jobs.execution import ClaimedJob, WorkerExecutor, JobExecutionError
from kodesec_api.jobs.repository import InvalidJobTransition, retry_failed_job
from kodesec_api.models import Job, ScannerLifecycleState
from kodesec_api.preparation_budget import issue_budget, timestamp
from kodesec_api.recovery_contract import RecoveryBudget, RecoveryTarget, recovery_digest
from kodesec_api.schemas import JobReconcileRequest
from test_scanner_lifecycle_api import _runtime, _request


def original_job(runtime):
    with runtime.session_factory() as db:
        budget = issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=901))
        operation_id = str(uuid4())
        job = main._enqueue_or_conflict(db, kind='scanner_cache_update', title='Prepare scanner data',
            client_id='browser:fixture', idempotency_key='original-uncertain', external_run_id=operation_id,
            max_attempts=3, payload={'v': 1, 'operation': 'cache_update', 'component_ids': ['grype-db'],
                'preparation_budget': budget.model_dump(),
                'request_digest': main._scanner_lifecycle_digest('cache_update', ['grype-db'], preparation_budget=budget)})
        job.status, job.stage, job.attempt = 'failed', 'failed', 1
        job.error_code = 'scanner_preparation_commit_uncertain'
        job.completed_at = datetime.now(timezone.utc)
        state = main._require_scanner_lifecycle_state(db, 'cache')
        state.status, state.job_id = 'failed', job.id
        db.commit()
        return job.id, job.revision


def preview(original):
    return {'operation_id': original.external_run_id, 'request_digest': original.payload['request_digest'],
            'attempt': original.attempt, 'record_sha256': 'a'*64, 'pointer_sha256': 'b'*64,
            'active': {'generation_id': 'c'*64, 'manifest_sha256': 'd'*64}}


def admit(runtime, job_id, revision, key='reconcile-command'):
    def response(settings, original, clock):
        assert 0 < clock.remaining(900) <= 900
        return preview(original)
    with runtime.session_factory() as db, patch.object(main, '_updater_reconciliation_preview', side_effect=response):
        return main.reconcile_scanner_cache_job(job_id, JobReconcileRequest(expected_revision=revision),
                                               _request(key), runtime=runtime, db=db)


def test_explicit_admission_shares_no_original_clock_and_replay_never_renews():
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    result = admit(runtime, job_id, revision)
    assert result['original_job_id'] == job_id
    assert result['job']['original_job_id'] == job_id
    with runtime.session_factory() as db:
        original = db.get(Job, job_id)
        recovery = db.get(Job, result['job']['id'])
        assert original.status == 'failed' and original.revision == revision
        assert recovery.kind == 'scanner_cache_reconcile' and recovery.max_attempts == 1
        assert 'preparation_budget' not in recovery.payload
        budget = RecoveryBudget.model_validate(recovery.payload['reconciliation_budget'])
        target = RecoveryTarget.model_validate(recovery.payload['reconciliation_target'])
        assert recovery.payload['request_digest'] == recovery_digest(budget, target)
        assert target.original_job_id == original.id and target.original_job_revision == original.revision
        with patch.object(main, 'issue_recovery_budget', side_effect=AssertionError('replay renewed clock')):
            replay = main.reconcile_scanner_cache_job(job_id, JobReconcileRequest(expected_revision=revision),
                _request('reconcile-command'), runtime=runtime, db=db)
        assert replay['job']['id'] == recovery.id
        assert len(list(db.scalars(select(Job)))) == 2


@pytest.mark.parametrize('worker_attempt,updater_attempt', [(2, 1), (3, 1), (3, 2)])
def test_worker_reclaim_can_reconcile_earlier_published_updater_attempt(worker_attempt, updater_attempt):
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    with runtime.session_factory() as db:
        original = db.get(Job, job_id)
        original.attempt = worker_attempt
        db.commit()
    def response(settings, original, clock):
        return {**preview(original), 'attempt': updater_attempt}
    with runtime.session_factory() as db, patch.object(main, '_updater_reconciliation_preview', side_effect=response):
        result = main.reconcile_scanner_cache_job(job_id, JobReconcileRequest(expected_revision=revision),
            _request('reclaimed-worker'), runtime=runtime, db=db)
        recovery = db.get(Job, result['job']['id'])
        assert recovery.payload['reconciliation_target']['attempt'] == updater_attempt
        original = db.get(Job, job_id)
        assert original.attempt == worker_attempt and original.status == 'failed'
        assert original.revision == revision


def test_reconciliation_rejects_updater_attempt_ahead_of_original_worker():
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    with runtime.session_factory() as db, patch.object(main, '_updater_reconciliation_preview',
            side_effect=lambda settings, original, clock: {**preview(original), 'attempt': 2}):
        with pytest.raises(HTTPException) as caught:
            main.reconcile_scanner_cache_job(job_id, JobReconcileRequest(expected_revision=revision),
                _request('future-updater'), runtime=runtime, db=db)
        assert caught.value.status_code == 409
        assert caught.value.detail['code'] == 'scanner_reconciliation_target_changed'
        assert len(list(db.scalars(select(Job)))) == 1


@pytest.mark.parametrize('change,code', [('revision', 'job_revision_changed'),
                                        ('error', 'scanner_reconciliation_not_available'),
                                        ('status', 'scanner_reconciliation_not_available')])
def test_original_admission_is_exact(change, code):
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        if change == 'revision': revision += 1
        elif change == 'error': job.error_code = 'cache_grype_validation_timeout'
        else: job.status = 'completed'
        db.commit()
    with pytest.raises(HTTPException) as caught:
        admit(runtime, job_id, revision)
    assert caught.value.status_code == 409 and caught.value.detail['code'] == code


@pytest.mark.parametrize('malformed', [None, {'v': 1}, {'reconciliation_target': []}])
def test_malformed_idempotent_replay_is_bounded_conflict(malformed):
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    result = admit(runtime, job_id, revision)
    with runtime.session_factory() as db:
        recovery = db.get(Job, result['job']['id'])
        recovery.payload = malformed
        db.commit()
        with pytest.raises(HTTPException) as caught:
            main.reconcile_scanner_cache_job(job_id, JobReconcileRequest(expected_revision=revision),
                _request('reconcile-command'), runtime=runtime, db=db)
        assert caught.value.status_code == 409


def test_generic_retry_never_extends_recovery_attempts():
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    result = admit(runtime, job_id, revision)
    with runtime.session_factory() as db:
        recovery = db.get(Job, result['job']['id'])
        recovery.status, recovery.attempt = 'failed', 1
        db.commit()
        assert main._job_to_out(db, recovery)['can_retry'] is False
        with pytest.raises(InvalidJobTransition, match='single-attempt'):
            retry_failed_job(db, recovery.id, expected_revision=recovery.revision, now=datetime.now(timezone.utc))
        assert recovery.max_attempts == 1


def test_private_recovery_receipt_echo_and_original_failure_remain_exact():
    from kodesec_scanner.updater import OperationRecord, ReconciliationOperationResult, ReconciliationIntent, CacheOperationResult
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    result = admit(runtime, job_id, revision)
    with runtime.session_factory() as db:
        recovery = db.get(Job, result['job']['id'])
        recovery.attempt = 1
        claimed = ClaimedJob.from_model(recovery)
        worker = WorkerExecutor(runtime, worker_id="readonly-recovery-fixture")
        request = worker._updater_request_for_job(claimed)
        target = request['reconciliation_target']
        now = timestamp(datetime.now(timezone.utc))
        receipt = ReconciliationOperationResult(kind='reconciliation', active=target['active'], previous_good=None,
            original_operation_id=target['operation_id'], original_request_digest=target['request_digest'],
            original_record_sha256='e'*64, original_workflow_deadline_exceeded=True, verified_at=now)
        record = OperationRecord(schema_version=3, reconciliation_budget=request['reconciliation_budget'],
            reconciliation_target=target, operation_id=request['operation_id'], request_digest=request['request_digest'],
            kind='cache_reconcile', requested_components=[], status='completed', stage='completed',
            attempt=1, max_attempts=1, created_at=now, started_at=now, finished_at=now, updated_at=now,
            last_activity_at=now, result=receipt,
            reconciliation_intent=ReconciliationIntent(original_completed_sha256='e'*64, original_finished_at=now,
                cache_result=CacheOperationResult(kind='cache', active=target['active'], previous_good=None,
                                                 updated_components=['grype-db']), result=receipt))
        raw = record.model_dump(mode='json')
        admitted = worker._admit_updater_record(claimed, httpx.Response(200, json=raw), allowed_attempts={1})
        state = worker._apply_completed_updater_state(db, recovery, admitted)
        assert state.receipt['result']['kind'] == 'reconciliation'
        assert state.receipt['result']['original_workflow_deadline_exceeded'] is True
        assert state.status == 'completed' and db.get(Job, job_id).status == 'failed'
        raw['reconciliation_budget']['deadline_at'] = timestamp(datetime.now(timezone.utc)+timedelta(seconds=901))
        with pytest.raises(JobExecutionError):
            worker._admit_updater_record(claimed, httpx.Response(200, json=raw), allowed_attempts={1})


def test_admitted_reconciliation_runs_through_worker_dispatch_and_persists_outcome():
    """Exercise execute(), not just receipt helpers, with a complete private reply."""
    import json
    from kodesec_api.jobs.execution import LeaseMonitor
    from kodesec_scanner.updater import (
        OperationRecord, ReconciliationOperationResult, ReconciliationIntent, CacheOperationResult,
    )
    runtime = _runtime()
    original_id, revision = original_job(runtime)
    admitted = admit(runtime, original_id, revision)
    worker_id = 'reconciliation-dispatch-fixture'
    with runtime.session_factory() as db:
        original = db.get(Job, original_id)
        original_state = {column.name: getattr(original, column.name) for column in Job.__table__.columns}
        job = db.get(Job, admitted['job']['id'])
        now = datetime.now(timezone.utc)
        job.status, job.stage, job.attempt = 'leased', 'starting', 1
        job.lease_owner, job.lease_expires_at = worker_id, now + timedelta(seconds=30)
        job.heartbeat_at, job.started_at = now, now
        db.commit()
        claimed = ClaimedJob.from_model(job)
    requests = []

    def updater(request):
        requests.append((request.method, request.url.path))
        if request.method == 'GET':
            assert request.url.path == '/operations/' + claimed.external_run_id
            return httpx.Response(404)
        assert request.method == 'POST' and request.url.path == '/operations'
        payload = json.loads(request.content)
        assert payload['kind'] == 'cache_reconcile' and payload['schema_version'] == 3
        target = payload['reconciliation_target']
        now = timestamp(datetime.now(timezone.utc))
        result = ReconciliationOperationResult(kind='reconciliation', active=target['active'], previous_good=None,
            original_operation_id=target['operation_id'], original_request_digest=target['request_digest'],
            original_record_sha256='e'*64, original_workflow_deadline_exceeded=True, verified_at=now)
        record = OperationRecord(schema_version=3, reconciliation_budget=payload['reconciliation_budget'],
            reconciliation_target=target, operation_id=payload['operation_id'], request_digest=payload['request_digest'],
            kind='cache_reconcile', requested_components=[], status='completed', stage='completed',
            attempt=1, max_attempts=1, created_at=now, started_at=now, finished_at=now, updated_at=now,
            last_activity_at=now, result=result,
            reconciliation_intent=ReconciliationIntent(original_completed_sha256='e'*64, original_finished_at=now,
                cache_result=CacheOperationResult(kind='cache', active=target['active'], previous_good=None,
                                                 updated_components=['grype-db']), result=result))
        return httpx.Response(202, json=record.model_dump(mode='json'))

    worker = WorkerExecutor(runtime, worker_id, updater_client_factory=lambda: httpx.Client(
        base_url='http://scanner-updater:8092', transport=httpx.MockTransport(updater)))
    # No concurrent SQLite heartbeat thread; real dispatch, fencing, transport
    # admission and terminal persistence still execute against the leased row.
    with patch.object(LeaseMonitor, 'start'), patch.object(LeaseMonitor, 'stop'), patch(
        'kodesec_api.jobs.repository._time', side_effect=lambda value, db: datetime.now(timezone.utc)
    ):
        worker.execute(claimed)
    with runtime.session_factory() as db:
        job = db.get(Job, claimed.id)
        assert job.status == 'completed', job.error_code
        assert job.attempt == job.max_attempts == 1 and job.lease_owner is None
        state = db.get(ScannerLifecycleState, 'cache')
        assert state.status == 'completed' and state.job_id == claimed.id
        assert state.receipt['result']['original_operation_id'] == original_state['external_run_id']
        original = db.get(Job, original_id)
        assert {column.name: getattr(original, column.name) for column in Job.__table__.columns} == original_state
        assert len(list(db.scalars(select(Job)))) == 2
    assert requests == [('GET', '/operations/' + claimed.external_run_id), ('POST', '/operations')]


@pytest.mark.parametrize('mode', ['slow_chunks', 'overflow'])
def test_preview_absolute_clock_and_byte_bound_close_owned_stream(monkeypatch, mode):
    import asyncio
    from types import SimpleNamespace
    from kodesec_api.preparation_budget import PreparationClock
    from kodesec_api.recovery_contract import issue_recovery_budget
    runtime = _runtime()
    closed = []
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            if mode == 'slow_chunks':
                for _ in range(100):
                    await asyncio.sleep(0.005)
                    yield b' '
            else:
                yield b' '*4097
        async def aclose(self):
            closed.append(True)
    client_class = httpx.AsyncClient
    def client(**kwargs):
        return client_class(**kwargs, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Stream())))
    monkeypatch.setattr(main.httpx, 'AsyncClient', client)
    monkeypatch.setattr(main, '_RECONCILIATION_PREVIEW_SECONDS', 0.02)
    original = SimpleNamespace(external_run_id=str(uuid4()), payload={'request_digest': 'a'*64})
    with pytest.raises(HTTPException) as caught:
        main._updater_reconciliation_preview(runtime.settings, original, PreparationClock(issue_recovery_budget()))
    assert caught.value.status_code == 503 and closed == [True]


def publication_activity():
    return {'status': 'running', 'stage': 'committing', 'updated_at': '2026-10-03T08:28:55Z',
        'component_id': None, 'component_index': None, 'component_total': None,
        'bytes_completed': None, 'bytes_total': None}


def test_historical_deadline_can_check_proven_publication_without_rewriting_failure():
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        job.error_code = 'scanner_preparation_deadline'
        job.checkpoint = {'updater_activity': publication_activity()}
        db.commit()
        assert main._job_to_out(db, job)['can_reconcile_cache'] is True
        assert main._job_to_out(db, job)['can_retry'] is False
    result = admit(runtime, job_id, revision)
    with runtime.session_factory() as db:
        original = db.get(Job, job_id)
        assert original.error_code == 'scanner_preparation_deadline'
        assert original.status == 'failed' and original.revision == revision
        assert result['original_job_id'] == job_id


@pytest.mark.parametrize('activity', [None, {}, {'stage': 'committing'},
    {**publication_activity(), 'stage': 'downloading'},
    {**publication_activity(), 'status': 'completed'},
    {**publication_activity(), 'updated_at': 'invalid'}])
def test_historical_deadline_without_admitted_commit_activity_cannot_reconcile(activity):
    runtime = _runtime()
    job_id, revision = original_job(runtime)
    with runtime.session_factory() as db:
        job = db.get(Job, job_id)
        job.error_code = 'scanner_preparation_deadline'
        job.checkpoint = {'updater_activity': activity}
        db.commit()
        assert main._job_to_out(db, job)['can_reconcile_cache'] is False
    with pytest.raises(HTTPException) as caught:
        admit(runtime, job_id, revision)
    assert caught.value.status_code == 409
