from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from kodesec_api import main
from kodesec_api.jobs.execution import (
    ClaimedJob, WorkerExecutor, JobExecutionError,
    _enqueue_scanner_preparation_cache_continuation,
)
from kodesec_api.jobs.repository import InvalidJobTransition, retry_failed_job, fail_job
from kodesec_api.models import Job, ScannerLifecycleState
from kodesec_api.preparation_budget import PreparationBudget, issue_budget
from test_scanner_lifecycle_api import _runtime, _request


def preflight():
    return {'ready': False, 'required_component_ids': ['grype-db'],
            'preparation_available': True, 'blocked_tools': [], 'cache_verification': None}


@pytest.mark.parametrize("platform,seconds", [("mac", 1200), ("linux", 3120), ("windows", 4680)])
def test_server_budget_is_shared_by_catalog_cache_and_idempotent_replay(platform, seconds):
    runtime = _runtime()
    runtime.settings.preparation_platform = platform
    with runtime.session_factory() as db:
        with patch.object(main, '_scanner_preflight', return_value=preflight()):
            first = main.prepare_scanners(_request('whole-budget-prepare'), runtime=runtime, db=db)
        catalog = db.get(Job, first['catalog']['job']['id'])
        budget = catalog.payload['preparation_budget']
        assert (datetime.fromisoformat(budget['deadline_at']) - datetime.fromisoformat(budget['issued_at'])).total_seconds() == seconds
        assert catalog.payload['preparation']['preparation_budget'] == budget
        assert catalog.payload['preparation']['schema_version'] == 2
        cache = _enqueue_scanner_preparation_cache_continuation(db, catalog, {'components': [{'component_id': 'grype-db', 'state': 'current'}]})
        db.commit()
        assert cache.payload['preparation_budget'] == budget
        runtime.settings.preparation_platform = 'windows' if platform != 'windows' else 'mac'
        with patch.object(main, 'issue_budget', side_effect=AssertionError('replay must not issue a budget')):
            replay = main.prepare_scanners(_request('whole-budget-prepare'), runtime=runtime, db=db)
        assert replay['catalog']['job']['id'] == catalog.id
        assert replay['cache']['job']['id'] == cache.id
        assert len(list(db.scalars(select(Job)))) == 2


def test_expired_continuation_never_enqueues_a_cache_job():
    runtime = _runtime()
    with runtime.session_factory() as db:
        with patch.object(main, '_scanner_preflight', return_value=preflight()):
            first = main.prepare_scanners(_request('expired-continuation'), runtime=runtime, db=db)
        catalog = db.get(Job, first['catalog']['job']['id'])
        expired = issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1201)).model_dump()
        continuation = {**catalog.payload['preparation'], 'preparation_budget': expired,
                        'request_digest': main._scanner_lifecycle_digest('cache_update', ['grype-db'], preparation_budget=expired)}
        catalog.payload = {**catalog.payload, 'preparation_budget': expired, 'preparation': continuation}
        with pytest.raises(JobExecutionError) as failure:
            _enqueue_scanner_preparation_cache_continuation(db, catalog, {'components': [{'component_id': 'grype-db', 'state': 'current'}]})
        assert failure.value.code == 'scanner_preparation_deadline'
        assert not list(db.scalars(select(Job).where(Job.kind == 'scanner_cache_update')))


def claimed(budget=None):
    components = ['grype-db']
    payload = {'v': 1, 'operation': 'cache_update', 'component_ids': components,
               'request_digest': main._scanner_lifecycle_digest('cache_update', components, preparation_budget=budget)}
    if budget is not None:
        payload['preparation_budget'] = budget.model_dump()
    return ClaimedJob(id=1, kind='scanner_cache_update', status='running', stage='staging',
                      attempt=1, max_attempts=3, scan_id=None, finding_id=None,
                      external_run_id=str(uuid4()), payload=payload, checkpoint={})


def test_worker_transport_bounds_are_positive_decreasing_and_legacy_start_is_closed():
    runtime = _runtime()
    worker = WorkerExecutor(runtime, worker_id='budget-test')
    budget = issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1199))
    job = claimed(budget)
    remaining = worker._preparation_bound(job, 30)
    assert 0 < remaining <= 1
    assert worker._preparation_bound(job, 30) <= remaining
    request = worker._updater_request_for_job(job)
    assert request['schema_version'] == 2 and request['preparation_budget'] == budget.model_dump()
    legacy = claimed()
    assert worker._updater_request_for_job(legacy)['schema_version'] == 1
    assert worker._preparation_bound(legacy, 30, cleanup=True) == 5
    with pytest.raises(JobExecutionError) as failure:
        worker._preparation_bound(legacy, 30)
    assert failure.value.code == 'scanner_preparation_budget_required'
    expired = claimed(issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1201)))
    with pytest.raises(JobExecutionError) as failure:
        worker._preparation_bound(expired, 30)
    assert failure.value.code == 'scanner_preparation_deadline'
    assert worker._preparation_bound(expired, 30, cleanup=True) == 5


def test_late_committed_receipt_preserves_actual_active_cache_with_failed_workflow():
    runtime = _runtime()
    worker = WorkerExecutor(runtime, worker_id='budget-test')
    budget = issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1201))
    active = {'generation_id': 'a' * 64, 'manifest_sha256': 'b' * 64}
    with runtime.session_factory() as db:
        job = Job(kind='scanner_cache_update', title='late atomic fixture', status='running',
                  stage='committing', attempt=1, max_attempts=3, payload={}, checkpoint={}, revision=1)
        db.add(job)
        db.flush()
        state = main._lock_scanner_lifecycle_state(db, 'cache')
        state.job_id = job.id
        record = {'schema_version': 2, 'preparation_budget': budget.model_dump(),
                  'workflow_deadline_exceeded': True, 'operation_id': str(uuid4()),
                  'request_digest': 'c' * 64, 'kind': 'cache_update',
                  'requested_components': ['grype-db'], 'attempt': 1, 'max_attempts': 3,
                  'updated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                  'result': {'kind': 'cache', 'active': active, 'previous_good': None,
                             'updated_components': ['grype-db']}}
        actual = worker._apply_completed_updater_state(db, job, record)
        assert actual.status == 'failed' and actual.error_code == 'scanner_preparation_deadline'
        assert actual.active_generation == active['generation_id']
        assert actual.receipt['result']['active'] == active
        assert actual.receipt['workflow_deadline_exceeded'] is True


def test_manual_retry_cannot_renew_an_expired_group():
    runtime = _runtime()
    with runtime.session_factory() as db:
        budget = issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1201))
        job = Job(kind='scanner_cache_update', title='expired retry fixture', status='failed',
                  stage='failed', attempt=1, max_attempts=3,
                  payload={'preparation_budget': budget.model_dump()}, checkpoint={}, revision=1)
        db.add(job)
        db.flush()
        with pytest.raises(InvalidJobTransition, match='scanner_preparation_deadline'):
            retry_failed_job(db, job.id, expected_revision=job.revision, now=datetime.now(timezone.utc))
        assert job.attempt == 1 and job.status == 'failed'


def test_budget_is_internal_and_caller_timestamp_cannot_authorize_a_new_group():
    from kodesec_api.schemas import ScannerCacheUpdateRequest
    with pytest.raises(ValueError):
        ScannerCacheUpdateRequest.model_validate({'component_ids': ['grype-db'], 'preparation_budget': issue_budget().model_dump()})


def test_replay_refuses_individually_valid_cache_budget_from_another_group():
    runtime = _runtime()
    with runtime.session_factory() as db:
        with patch.object(main, '_scanner_preflight', return_value=preflight()):
            first = main.prepare_scanners(_request('different-group-replay'), runtime=runtime, db=db)
        catalog = db.get(Job, first['catalog']['job']['id'])
        cache = _enqueue_scanner_preparation_cache_continuation(db, catalog, {'components': [{'component_id': 'grype-db', 'state': 'current'}]})
        different = issue_budget().model_dump()
        cache.payload = {**cache.payload, 'preparation_budget': different,
                         'request_digest': main._scanner_lifecycle_digest('cache_update', ['grype-db'], preparation_budget=different)}
        db.commit()
        with pytest.raises(HTTPException) as failure:
            main.prepare_scanners(_request('different-group-replay'), runtime=runtime, db=db)
        assert failure.value.detail['code'] == 'scanner_preparation_invalid'


@pytest.mark.parametrize('budget', [None, issue_budget(now=datetime.now(timezone.utc) - timedelta(seconds=1201)).model_dump()])
def test_queued_attempt_zero_cancellation_wins_over_budget_rejection(budget):
    # Pure repository branch proof; no claim about PostgreSQL lock/concurrency.
    from types import SimpleNamespace
    from kodesec_api.jobs.repository import claim_next_job
    current = datetime.now(timezone.utc)
    job = Job(id=10, kind='scanner_catalog_check', title='cancelled before dispatch',
              status='queued', stage='queued', attempt=0, max_attempts=3,
              cancel_requested_at=current, payload={} if budget is None else {'preparation_budget': budget},
              checkpoint={}, revision=1, created_at=current)
    class Session:
        bind = SimpleNamespace(dialect=SimpleNamespace(name='postgresql'))
        def scalar(self, statement): return job
        def flush(self): pass
    assert claim_next_job(Session(), worker_id='cancellation-test', now=current) is job
    assert job.status == 'cancelling' and job.attempt == 0
    assert job.error_code is None and job.completed_at is None


@pytest.mark.parametrize("platform", ["mac", "linux", "windows"])
def test_api_and_updater_bind_exactly_the_same_version_two_digest(platform):
    from kodesec_scanner.updater import operation_request_digest
    budget = issue_budget(platform=platform)
    for operation, components, selected in [('catalog_check', [], None), ('cache_update', ['grype-db', 'trivy-db'], 'a' * 64)]:
        assert main._scanner_lifecycle_digest(operation, components, selected, budget) == operation_request_digest(schema_version=2, kind=operation, requested_components=components, catalog_digest=selected, preparation_budget=budget)


def test_recovery_and_stage_continuation_refuse_backwards_persisted_clock():
    from dataclasses import replace
    from kodesec_api.jobs.repository import _preparation_rejection
    current = datetime.now(timezone.utc)
    budget = issue_budget(now=current - timedelta(seconds=600))
    job = Job(kind='scanner_catalog_check', payload={'preparation_budget': budget.model_dump()}, updated_at=current + timedelta(seconds=10), created_at=current)
    assert _preparation_rejection(job, current) == 'scanner_preparation_deadline'
    runtime = _runtime()
    worker = WorkerExecutor(runtime, 'high-water-test')
    with pytest.raises(JobExecutionError) as failure:
        worker._preparation_bound(replace(claimed(budget), updated_at=current + timedelta(seconds=10)), 30)
    assert failure.value.code == 'scanner_preparation_deadline'


def test_worker_refuses_a_late_finish_labelled_with_an_on_time_flag():
    import httpx
    from test_durable_worker import _operation_record
    from kodesec_api.preparation_budget import moment, timestamp
    budget = issue_budget()
    job = claimed(budget)
    record = _operation_record(job, status='completed', result={'kind': 'cache', 'active': {'generation_id': 'a' * 64, 'manifest_sha256': 'b' * 64}, 'previous_good': None, 'updated_components': ['grype-db']})
    record['finished_at'] = timestamp(moment(budget.deadline_at) + timedelta(microseconds=1))
    record['updated_at'] = record['finished_at']
    worker = WorkerExecutor(_runtime(), 'precise-receipt-test')
    with pytest.raises(JobExecutionError) as failure:
        worker._admit_updater_record(job, httpx.Response(200, json=record), allowed_attempts={1})
    assert failure.value.code == 'updater_protocol'
    assert 'precise finish timestamp' in failure.value.detail


@pytest.mark.parametrize('kind,error,retryable,expected', [
    ('scanner_cache_update', 'scanner_preparation_commit_uncertain', False, 'scanner_preparation_commit_uncertain'),
    ('scanner_cache_update', 'updater_unreachable', True, 'scanner_preparation_deadline'),
    ('scanner_cache_update', 'scanner_preparation_commit_uncertain', True, 'scanner_preparation_deadline'),
    ('scanner_catalog_check', 'scanner_preparation_commit_uncertain', False, 'scanner_preparation_deadline'),
])
def test_expiry_preserves_only_nonretryable_uncertain_publication(kind, error, retryable, expected):
    runtime = _runtime()
    current = datetime.now(timezone.utc)
    budget = issue_budget(now=current - timedelta(seconds=1201))
    with runtime.session_factory() as db:
        job = Job(kind=kind, title='publication deadline', status='running', stage='committing',
            attempt=2, max_attempts=3, payload={'preparation_budget': budget.model_dump()},
            checkpoint={}, revision=1, lease_owner='deadline-owner',
            lease_expires_at=current+timedelta(seconds=30))
        db.add(job)
        db.flush()
        result = fail_job(db, job.id, worker_id='deadline-owner', attempt=2,
            error_code=error, error_detail='Observed terminal outcome.', retryable=retryable, now=current)
        assert result.status == 'failed' and result.error_code == expected
        assert result.attempt == 2 and result.completed_at == current
        assert result.payload['preparation_budget'] == budget.model_dump()
        assert result.lease_owner is None


@pytest.mark.parametrize('payload,expected', [
    ({}, 'scanner_preparation_budget_required'),
    ({'preparation_budget': {}}, 'scanner_preparation_budget_invalid'),
])
def test_uncertain_publication_never_bypasses_missing_or_invalid_budget(payload, expected):
    runtime = _runtime()
    current = datetime.now(timezone.utc)
    with runtime.session_factory() as db:
        job = Job(kind='scanner_cache_update', title='invalid publication budget', status='running',
            stage='committing', attempt=1, max_attempts=3, payload=payload, checkpoint={}, revision=1,
            lease_owner='deadline-owner', lease_expires_at=current+timedelta(seconds=30))
        db.add(job)
        db.flush()
        result = fail_job(db, job.id, worker_id='deadline-owner', attempt=1,
            error_code='scanner_preparation_commit_uncertain', error_detail='Uncertain publication.',
            retryable=False, now=current)
        assert result.status == 'failed' and result.error_code == expected


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_manual_catalog_uses_host_budget_without_api_egress(platform):
    runtime = _runtime()
    runtime.settings.preparation_platform = platform
    with runtime.session_factory() as db:
        with patch.object(main.httpx, "Client", side_effect=AssertionError("API egress")):
            result = main.check_scanner_tools(_request("platform-manual-catalog"), runtime=runtime, db=db)
        job = db.get(Job, result["job"]["id"])
        budget = PreparationBudget.model_validate(job.payload["preparation_budget"])
        assert budget.schema_version == 4
        expected = 3120 if platform == "linux" else 4680
        assert (datetime.fromisoformat(budget.deadline_at) - datetime.fromisoformat(budget.issued_at)).total_seconds() == expected
