from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from kodesec_scanner import updater
from kodesec_scanner.preparation_budget import (
    PreparationBudget, PreparationClock, PreparationDeadlineExceeded,
    issue_budget, timestamp,
)

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)

def legacy_budget(*, now=NOW):
    """Explicit schema1 receipts keep testing their original 900-second clock."""
    return PreparationBudget(schema_version=1, preparation_id=str(uuid4()),
                             issued_at=timestamp(now),
                             deadline_at=timestamp(now + timedelta(seconds=900)))



def request(budget, attempt=1):
    return updater.OperationRequest(
        schema_version=2, operation_id=uuid4(), preparation_budget=budget,
        request_digest=updater.operation_request_digest(schema_version=2,
            kind='catalog_check', requested_components=[], preparation_budget=budget),
        kind='catalog_check', requested_components=[], attempt=attempt, max_attempts=3,
    )


def test_catalog_cache_and_retry_do_not_renew_the_clock():
    wall, mono = [NOW], [10.0]
    budget = legacy_budget(now=NOW)
    clock = PreparationClock(budget, now=lambda: wall[0], monotonic=lambda: mono[0])
    wall[0] += timedelta(seconds=600)
    mono[0] += 600
    assert clock.remaining(900) == 300
    recovered = PreparationClock(budget, now=lambda: wall[0], monotonic=lambda: mono[0])
    assert recovered.remaining(900) == 300
    wall[0] += timedelta(seconds=301)
    mono[0] += 301
    for candidate in (clock, recovered):
        with pytest.raises(PreparationDeadlineExceeded):
            candidate.remaining(900)


@pytest.mark.parametrize('elapsed', [899.9995, 900, 901])
def test_no_zero_or_submillisecond_dispatch(elapsed):
    with pytest.raises(PreparationDeadlineExceeded):
        PreparationClock(legacy_budget(now=NOW), now=lambda: NOW + timedelta(seconds=elapsed))


def test_monotonic_and_persisted_high_water_fail_closed():
    wall, mono = [NOW], [0.0]
    clock = PreparationClock(legacy_budget(now=NOW), now=lambda: wall[0], monotonic=lambda: mono[0])
    mono[0] = 901
    with pytest.raises(PreparationDeadlineExceeded):
        clock.remaining(30)
    with pytest.raises(PreparationDeadlineExceeded):
        PreparationClock(legacy_budget(now=NOW), now=lambda: NOW, high_water=NOW + timedelta(seconds=1))
    wall[0] = NOW - timedelta(microseconds=1)
    with pytest.raises(PreparationDeadlineExceeded):
        clock.remaining(30)


@pytest.mark.parametrize('change', [
    {'schema_version': True}, {'extra': 'untrusted'},
    {'deadline_at': timestamp(NOW + timedelta(seconds=901))},
    {'issued_at': '2026-09-30T00:00:00+00:00'},
    {'preparation_id': str(uuid4()).upper()},
])
def test_strict_budget_shape(change):
    with pytest.raises((ValidationError, ValueError)):
        PreparationBudget.model_validate({**legacy_budget(now=NOW).model_dump(), **change})


@pytest.mark.parametrize("platform,seconds", [("mac", 1200), ("linux", 3120), ("windows", 4680)])
def test_retry_persists_original_budget_and_expired_retry_allocates_nothing(tmp_path, platform, seconds):
    budget = issue_budget(now=NOW, platform=platform)
    initial = request(budget)
    store = updater.OperationStore(tmp_path / 'cache')
    queued, accepted = store.create_or_get(initial, now=timestamp(NOW))
    assert accepted and queued.preparation_budget == budget
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW))
    failed = store.transition(initial.operation_id, status='failed', stage='failed', error_code='operation_failed', error_detail='bounded failure', now=timestamp(NOW + timedelta(seconds=600)))
    retry = initial.model_copy(update={'attempt': 2})
    restarted, accepted = store.create_or_get(retry, now=timestamp(NOW + timedelta(seconds=601)))
    assert accepted and restarted.preparation_budget == budget and restarted.created_at == queued.created_at
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW + timedelta(seconds=601)))
    failed = store.transition(initial.operation_id, status='failed', stage='failed', error_code='operation_failed', error_detail='bounded failure', now=timestamp(NOW + timedelta(seconds=seconds - 1)))
    with pytest.raises(PreparationDeadlineExceeded):
        store.create_or_get(initial.model_copy(update={'attempt': 3}), now=timestamp(NOW + timedelta(seconds=seconds + 1)))
    assert store.load(initial.operation_id) == failed
    altered = retry.model_copy(update={'preparation_budget': legacy_budget(now=NOW)})
    with pytest.raises(updater.OperationConflictError):
        store.create_or_get(altered, now=timestamp(NOW + timedelta(seconds=601)))


def test_fresh_unbudgeted_work_rejected_but_legacy_record_read_and_replay_survive(tmp_path):
    old = updater.OperationRequest(schema_version=1, operation_id=uuid4(),
        request_digest=updater.operation_request_digest(schema_version=1, kind='catalog_check', requested_components=[]),
        kind='catalog_check', requested_components=[], attempt=1, max_attempts=3)
    store = updater.OperationStore(tmp_path / 'cache')
    with pytest.raises(updater.OperationStateError, match='budget required'):
        store.create_or_get(old)
    legacy = updater.OperationRecord(schema_version=1, operation_id=old.operation_id,
        request_digest=old.request_digest, kind=old.kind, requested_components=[],
        status='queued', stage='queued', attempt=1, max_attempts=3,
        created_at=timestamp(NOW), updated_at=timestamp(NOW))
    with store._ledger_lock():
        store._write_unlocked(legacy)
    assert store.create_or_get(old) == (legacy, False)
    wire = store.load(old.operation_id).model_dump(mode='json')
    assert 'preparation_budget' not in wire and 'workflow_deadline_exceeded' not in wire
    cancelled = store.request_cancel(old.operation_id, request_digest=old.request_digest)
    assert cancelled.cancel_requested_at is not None


def test_atomic_published_late_outcome_retains_exact_cache_and_marks_workflow_late(tmp_path, monkeypatch):
    initial = request(legacy_budget(now=NOW))
    initial = initial.model_copy(update={'kind': 'cache_update', 'requested_components': ['bearer-rules'],
        'request_digest': updater.operation_request_digest(schema_version=2, kind='cache_update', requested_components=['bearer-rules'], preparation_budget=initial.preparation_budget)})
    store = updater.OperationStore(tmp_path / 'cache')
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='committing', now=timestamp(NOW + timedelta(seconds=899)))
    ref = {'generation_id': 'a' * 64, 'manifest_sha256': 'b' * 64}
    pointer = SimpleNamespace(operation_id=str(initial.operation_id), active=SimpleNamespace(**ref), previous_good=None)
    monkeypatch.setattr(updater, 'load_active_pointer', lambda root: pointer)
    monkeypatch.setattr(updater, 'validate_generation', lambda *args, **kwargs: None)
    monkeypatch.setattr(updater, '_pointer_result', lambda pointer, components: updater.CacheOperationResult(kind='cache', active=ref, previous_good=None, updated_components=components))
    completed = store.reconcile_published(initial.operation_id, now=timestamp(NOW + timedelta(seconds=901)))
    assert completed.status == 'completed' and completed.workflow_deadline_exceeded is True
    assert completed.result.active.model_dump() == ref
    assert completed.preparation_budget == initial.preparation_budget


def test_context_expiry_stops_before_heartbeat_or_progress(tmp_path):
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(tmp_path / 'cache')
    record, _ = store.create_or_get(initial, now=timestamp(NOW))
    context = updater.OperationContext(request=initial, store=store,
        wall_now=lambda: timestamp(NOW + timedelta(seconds=901)))
    with pytest.raises(PreparationDeadlineExceeded):
        context.checkpoint()
    assert store.load(initial.operation_id) == record


def test_context_initializes_one_clock_and_retains_fractional_precision(tmp_path, monkeypatch):
    initial = request(legacy_budget(now=NOW + timedelta(microseconds=400000)))
    store = updater.OperationStore(tmp_path / 'cache')
    record, _ = store.create_or_get(initial, now=timestamp(NOW + timedelta(microseconds=400000)))
    context = updater.OperationContext(request=initial, store=store,
        wall_now=lambda: timestamp(NOW + timedelta(microseconds=500000)))
    assert 899 < context.remaining_seconds(900) < 900
    clock = context._budget_clock
    assert context.remaining_seconds(900) <= 899.9
    assert context._budget_clock is clock
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW + timedelta(microseconds=500000)))
    late = NOW + timedelta(seconds=900, microseconds=400001)
    monkeypatch.setattr(updater, '_utc_now', lambda: late)
    from test_updater import _catalog
    completed = store.transition(initial.operation_id, status='completed', stage='completed', result=_catalog())
    assert completed.workflow_deadline_exceeded is True
    assert completed.finished_at == timestamp(late)
    assert completed.updated_at == timestamp(late)


@pytest.mark.parametrize('kind', ['ledger', 'generation'])
def test_contended_execution_locks_obey_the_owned_clock(tmp_path, monkeypatch, kind):
    import fcntl
    import os
    wall = [NOW]
    clock = PreparationClock(legacy_budget(now=NOW), now=lambda: wall[0])
    store = updater.OperationStore(tmp_path / 'cache')
    updater.prepare_cache_layout(store.cache_root)
    lock_path = (store._root(create=True) / '.ledger.lock') if kind == 'ledger' else store.cache_root / '.generation.lock'
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    token = updater._PREPARATION_LOCK_CHECK.set(lambda: clock.remaining(900))
    monkeypatch.setattr(updater.time, 'sleep', lambda seconds: wall.__setitem__(0, NOW + timedelta(seconds=901)))
    try:
        with pytest.raises(PreparationDeadlineExceeded):
            with (store._ledger_lock() if kind == 'ledger' else updater.generation_lock(store.cache_root)):
                pytest.fail('contended work acquired the lock after its budget')
    finally:
        updater._PREPARATION_LOCK_CHECK.reset(token)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    with (store._ledger_lock() if kind == 'ledger' else updater.generation_lock(store.cache_root)):
        pass  # Independent cancellation/reconciliation remains available.


@pytest.mark.parametrize('local', [0, -1, True, float('nan'), float('inf')])
def test_invalid_local_bounds_never_become_unbounded(local):
    clock = PreparationClock(legacy_budget(now=NOW), now=lambda: NOW)
    with pytest.raises(ValueError):
        clock.remaining(local)


def test_actual_catalog_then_cache_handlers_share_one_budget_and_stop_before_activation(tmp_path, monkeypatch):
    from test_updater import TOOLS, RULES, _catalog
    wall = [NOW]
    budget = legacy_budget(now=NOW)
    store = updater.OperationStore(tmp_path / 'cache')
    monkeypatch.setattr(updater, '_utc_now', lambda: wall[0])
    def catalog(context):
        wall[0] += timedelta(seconds=600)
        context.checkpoint()
        return _catalog()
    completed = updater.execute_operation(request(budget), TOOLS, RULES, store,
        catalog_check=catalog, now=lambda: timestamp(wall[0]))
    assert completed.status == 'completed' and not completed.workflow_deadline_exceeded
    cache_request = updater.OperationRequest(schema_version=2, preparation_budget=budget,
        operation_id=uuid4(), kind='cache_update', requested_components=['grype-db'],
        request_digest=updater.operation_request_digest(schema_version=2, kind='cache_update', requested_components=['grype-db'], preparation_budget=budget),
        attempt=1, max_attempts=3)
    def cache(context):
        assert context.remaining_seconds(900) <= 300
        wall[0] += timedelta(seconds=301)
        context.checkpoint()
        pytest.fail('expired cache handler continued')
    monkeypatch.setattr(updater, 'activate_generation', lambda *args, **kwargs: pytest.fail('expired cache activated'))
    failed = updater.execute_operation(cache_request, TOOLS, RULES, store,
        cache_update=cache, now=lambda: timestamp(wall[0]))
    assert failed.status == 'failed' and failed.error_code == 'scanner_preparation_deadline'
    assert failed.attempt == 1 and failed.preparation_budget == completed.preparation_budget
    assert not (store.cache_root / 'active.json').exists()


def test_deadline_failure_preserves_already_acknowledged_cancellation(tmp_path):
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(tmp_path / 'cache')
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW))
    store.request_cancel(initial.operation_id, request_digest=initial.request_digest, now=timestamp(NOW + timedelta(seconds=899)))
    terminal = updater._fail_operation(store, initial.operation_id, 'operation_failed', timestamp(NOW + timedelta(seconds=901)), exc=PreparationDeadlineExceeded())
    assert terminal.status == 'cancelled' and terminal.error_code is None


@pytest.mark.parametrize('wrapped', [False, True])
def test_real_sealed_generation_sql_validation_receives_shared_remaining_bound(tmp_path, monkeypatch, wrapped):
    from functools import wraps
    from test_grype_cache_contract import _sealed_generation
    from kodesec_scanner import cache_manifest, grype_identity
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    wall = [NOW]
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(cache_root)
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(wall[0]))
    monkeypatch.setattr(updater, '_utc_now', lambda: wall[0])
    context = updater.OperationContext(request=initial, store=store, wall_now=lambda: timestamp(wall[0]))
    assert context.remaining_seconds(900) > 899
    wall[0] += timedelta(seconds=899)  # Forward step after initial monotonic admission.
    checkpoint = context.refresh_activity
    if wrapped:
        @wraps(checkpoint)
        def decorated(): return checkpoint()
        callback = decorated
    else:
        callback = checkpoint
    cache_manifest.clear_grype_logical_proof_cache()
    original = grype_identity.compute_grype_logical_identity
    bounds = []
    def observe(*args, **kwargs):
        bounds.append(kwargs['timeout_seconds'])
        return original(*args, **kwargs)
    monkeypatch.setattr(grype_identity, 'compute_grype_logical_identity', observe)
    assert cache_manifest.validate_generation(cache_root, manifest.generation_id, checkpoint=callback).manifest == manifest
    assert bounds and all(0 < bound <= 1 for bound in bounds)


def test_contended_generation_lock_acknowledges_cancellation_before_acquisition(tmp_path):
    import fcntl
    import os
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(tmp_path / 'cache')
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW))
    store.request_cancel(initial.operation_id, request_digest=initial.request_digest, now=timestamp(NOW))
    context = updater.OperationContext(request=initial, store=store, wall_now=lambda: timestamp(NOW))
    updater.prepare_cache_layout(store.cache_root)
    descriptor = os.open(store.cache_root / '.generation.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    try:
        with pytest.raises(updater.OperationStateError, match='cancellation requested'):
            with updater.generation_lock(store.cache_root, checkpoint=context.checkpoint):
                pytest.fail('cancelled owner acquired the contended generation lock')
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def test_precise_completion_flag_cannot_be_forged_in_a_persisted_receipt(tmp_path):
    from test_updater import _catalog
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(tmp_path / 'cache')
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW))
    late = store.transition(initial.operation_id, status='completed', stage='completed', result=_catalog(), now=timestamp(NOW + timedelta(seconds=900, microseconds=1)))
    with pytest.raises(ValueError, match='precise finish timestamp'):
        updater.OperationRecord.model_validate({**late.model_dump(mode='json'), 'workflow_deadline_exceeded': False})


@pytest.mark.parametrize('proof', ['complete', 'sql_deadline', 'invalid_pointer'])
def test_expired_reconciliation_has_five_second_sql_bound_and_preserves_unknown_source(tmp_path, monkeypatch, proof):
    from test_grype_cache_contract import _sealed_generation
    from kodesec_scanner import cache_manifest, grype_identity
    import hashlib
    cache_root, manifest, generation = _sealed_generation(tmp_path)
    budget = legacy_budget(now=NOW)
    initial = updater.OperationRequest(schema_version=2, preparation_budget=budget,
        operation_id=uuid4(), kind='cache_update', requested_components=['grype-db'],
        request_digest=updater.operation_request_digest(schema_version=2, kind='cache_update', requested_components=['grype-db'], preparation_budget=budget),
        attempt=1, max_attempts=3)
    store = updater.OperationStore(cache_root)
    store.create_or_get(initial, now=timestamp(NOW))
    store.transition(initial.operation_id, status='running', stage='discovering', now=timestamp(NOW))
    committing = store.transition(initial.operation_id, status='running', stage='committing', now=timestamp(NOW + timedelta(seconds=899)))
    reference = cache_manifest.GenerationReference(generation_id=manifest.generation_id,
        manifest_sha256=hashlib.sha256((generation / 'manifest.json').read_bytes()).hexdigest())
    pointer = cache_manifest.ActiveGenerationPointer(schema_version=1, revision=1,
        active=reference, previous_good=None, activated_at=timestamp(NOW), operation_id=str(initial.operation_id))
    pointer_path = cache_root / 'active.json'
    pointer_path.write_bytes(cache_manifest.canonical_json_bytes(pointer.model_dump(mode='json')) if proof != 'invalid_pointer' else b'{invalid')
    pointer_path.chmod(0o600)
    pointer_before = pointer_path.read_bytes()
    source = cache_root / 'staging' / str(initial.operation_id) / 'preserve'
    source.parent.mkdir(parents=True)
    source.write_bytes(b'unknown publication source')
    monkeypatch.setattr(updater, '_utc_now', lambda: NOW + timedelta(seconds=901))
    original = grype_identity.compute_grype_logical_identity
    bounds = []
    def observe(*args, **kwargs):
        bounds.append(kwargs['timeout_seconds'])
        if proof == 'sql_deadline':
            raise grype_identity.GrypeIdentityError('deadline')
        return original(*args, **kwargs)
    monkeypatch.setattr(grype_identity, 'compute_grype_logical_identity', observe)
    cache_manifest.clear_grype_logical_proof_cache()
    result = store.reconcile_published(initial.operation_id, preparation_budget=budget)
    assert pointer_path.read_bytes() == pointer_before and source.exists()
    if proof == 'complete':
        assert result.status == 'completed' and result.workflow_deadline_exceeded
        assert result.result.active == reference
        assert bounds and all(0 < bound <= 5 for bound in bounds)
    else:
        assert result == committing and result.status == 'running' and result.stage == 'committing'
        if proof == 'sql_deadline':
            assert bounds and all(0 < bound <= 5 for bound in bounds)
        monkeypatch.setattr(updater, '_prune_unreferenced_generations', lambda *args, **kwargs: pytest.fail('uncertain source pruned'))
        assert store.recover_interrupted() == [committing]
        assert store.load(initial.operation_id) == committing
        assert pointer_path.read_bytes() == pointer_before and source.exists()


def test_expired_curl_is_refused_immediately_before_process_dispatch(tmp_path, monkeypatch):
    initial = request(legacy_budget(now=NOW))
    store = updater.OperationStore(tmp_path / 'cache')
    store.create_or_get(initial, now=timestamp(NOW))
    context = updater.OperationContext(request=initial, store=store,
        wall_now=lambda: timestamp(NOW + timedelta(seconds=901)))
    monkeypatch.setattr(updater.subprocess, 'Popen', lambda *args, **kwargs: pytest.fail('expired curl dispatched'))
    with pytest.raises(PreparationDeadlineExceeded):
        updater._run_bounded_curl(['curl', '--max-time', '900'], context=context, timeout_seconds=900)
    assert store.load(initial.operation_id).status == 'queued'


@pytest.mark.parametrize("platform,seconds", [("mac", 1200), ("linux", 3120), ("windows", 4680)])
def test_platform_budget_preserves_wire_identity_and_recovery_deadline(platform, seconds):
    budget = issue_budget(now=NOW, platform=platform)
    assert budget.schema_version == (3 if platform == "mac" else 4)
    restored = PreparationBudget.model_validate_json(budget.model_dump_json())
    assert restored == budget
    wall, mono = [NOW + timedelta(seconds=seconds - 5)], [50.0]
    clock = PreparationClock(restored, now=lambda: wall[0], monotonic=lambda: mono[0])
    assert clock.remaining() == 5
    mono[0] += 6
    with pytest.raises(PreparationDeadlineExceeded):
        clock.remaining()
    with pytest.raises(PreparationDeadlineExceeded):
        PreparationClock(restored, now=lambda: NOW + timedelta(seconds=seconds))


@pytest.mark.parametrize("version,seconds", [(1, 1800), (1, 2700), (2, 900), (2, 1801), (2, 5400)])
def test_platform_budget_cannot_reinterpret_or_stack_intervals(version, seconds):
    wire = legacy_budget(now=NOW).model_dump()
    with pytest.raises(ValidationError):
        PreparationBudget.model_validate({**wire, "schema_version": version,
            "deadline_at": timestamp(NOW + timedelta(seconds=seconds))})


def test_unknown_platform_never_issues_work():
    with pytest.raises(ValueError, match="unsupported preparation platform"):
        issue_budget(now=NOW, platform="request-header")


@pytest.mark.parametrize('version,seconds', [(1, 900), (2, 1800), (2, 2700), (3, 1200), (3, 2400), (3, 3600)])
def test_legacy_receipts_keep_their_exact_issued_deadline(version, seconds):
    budget = PreparationBudget(schema_version=version, preparation_id=str(uuid4()),
                               issued_at=timestamp(NOW),
                               deadline_at=timestamp(NOW + timedelta(seconds=seconds)))
    assert PreparationClock(budget, now=lambda: NOW, monotonic=lambda: 1).remaining() == seconds


@pytest.mark.parametrize('version,seconds', [(1, 1200), (2, 2400), (2, 3600), (3, 900), (3, 4800), (3, 3601), (3, 3120), (3, 4680), (4, 1200), (4, 2400), (4, 3600), (4, 6084)])
def test_new_policy_cannot_reinterpret_legacy_or_stack_budgets(version, seconds):
    with pytest.raises(ValidationError):
        PreparationBudget(schema_version=version, preparation_id=str(uuid4()),
                          issued_at=timestamp(NOW),
                          deadline_at=timestamp(NOW + timedelta(seconds=seconds)))


def test_default_preparation_issues_new_mac_budget():
    budget = issue_budget(now=NOW)
    assert budget.schema_version == 3
    assert PreparationClock(budget, now=lambda: NOW, monotonic=lambda: 1).remaining() == 1200


@pytest.mark.parametrize("platform,seconds", [("mac", 1800), ("linux", 4680), ("windows", 7020)])
def test_new_default_run_budget_never_scales_an_explicit_operation(platform, seconds):
    from kodesec_scanner.settings import Settings
    default = Settings(KODESEC_SCAN_PLATFORM=platform, _env_file=None)
    assert default.run_deadline_seconds == seconds
    explicit = Settings(KODESEC_SCAN_PLATFORM=platform, KODESEC_RUN_DEADLINE_SECONDS=90, _env_file=None)
    assert explicit.run_deadline_seconds == 90
    assert explicit.model_copy().run_deadline_seconds == 90
