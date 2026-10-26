"""Synthetic clock/crash proofs using real bounded sealed generation fixtures."""
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from kodesec_scanner import updater, readonly_recovery as recovery
from kodesec_scanner.preparation_budget import timestamp
from kodesec_scanner.recovery_contract import (
    RecoveryTarget, issue_recovery_budget, recovery_digest,
)
from test_updater import MOMENT, TOOLS, RULES, _request, _prepare_generation


@pytest.fixture
def bound(tmp_path, monkeypatch):
    moment = [MOMENT + timedelta(seconds=1201)]
    monkeypatch.setattr(updater, '_utc_now', lambda: moment[0])
    store = updater.OperationStore(tmp_path / 'cache')
    original = _request()
    store.create_or_get(original, now=timestamp(MOMENT))
    store.transition(original.operation_id, status='running', stage='committing', now=timestamp(MOMENT))
    manifest = _prepare_generation(store.cache_root, original.operation_id)
    updater.activate_generation(store.cache_root, manifest.generation_id, str(original.operation_id),
                                activated_at=timestamp(MOMENT))
    target = RecoveryTarget.model_validate({
        **recovery.preview(store, original.operation_id, original.request_digest),
        'original_job_id': 17, 'original_job_revision': 9,
    })
    budget = issue_recovery_budget(now=moment[0])
    request = updater.OperationRequest(schema_version=3, operation_id=uuid4(),
        request_digest=recovery_digest(budget, target), reconciliation_budget=budget,
        reconciliation_target=target, kind='cache_reconcile', requested_components=[], attempt=1, max_attempts=1)
    # This fixture only includes one reviewed component; no transport/tool call.
    monkeypatch.setattr(recovery, '_validate_candidate_components', lambda *a, **kw: None)
    return store, original, request, moment


def run(bound):
    store, original, request, moment = bound
    return updater.execute_operation(request, TOOLS, RULES, store, now=lambda: timestamp(moment[0]))


def test_expired_original_gets_separate_readonly_proof_without_pointer_or_data_change(bound, monkeypatch):
    store, original, request, moment = bound
    before = (store.cache_root / 'active.json').read_bytes()
    validator = recovery.validate_generation
    deadlines = []
    def slow_proof(*a, **kw):
        deadlines.append(kw['checkpoint'].__self__.verification_deadline_monotonic())
        moment[0] += timedelta(seconds=6)  # Cold proof exceeds automatic5s; separate clock decreases.
        return validator(*a, **kw)
    monkeypatch.setattr(recovery, 'validate_generation', slow_proof)
    monkeypatch.setattr(updater, '_prune_unreferenced_generations', lambda *a, **kw: pytest.fail('readonly cannot prune'))
    result = run(bound)
    assert result.status == 'completed' and result.result.kind == 'reconciliation'
    assert result.result.original_workflow_deadline_exceeded is True
    completed = store.load(original.operation_id)
    assert completed.status == 'completed' and completed.workflow_deadline_exceeded
    assert completed.preparation_budget == original.preparation_budget
    assert completed.result.updated_components == original.requested_components
    assert (store.cache_root / 'active.json').read_bytes() == before
    assert result.reconciliation_budget == request.reconciliation_budget and len(deadlines) == 1


class Crash(BaseException):
    pass


@pytest.mark.parametrize('point', ['intent_before_original', 'original_before_recovery'])
def test_crash_replays_only_exact_historical_writes(bound, monkeypatch, point):
    store, original, request, moment = bound
    write_method = updater.OperationStore._write_unlocked
    write = lambda record: write_method(store, record)
    def injected(self, record):
        if point == 'intent_before_original' and record.operation_id == original.operation_id and record.status == 'completed':
            raise Crash()
        if point == 'original_before_recovery' and record.operation_id == request.operation_id and record.status == 'completed':
            raise Crash()
        return write(record)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', injected)
    with pytest.raises(Crash):
        run(bound)
    assert store.load(request.operation_id).stage == 'committing'
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', write_method)
    monkeypatch.setattr(recovery, 'validate_generation', lambda *a, **kw: pytest.fail('restart may not rerun SQL'))
    monkeypatch.setattr(updater, 'validate_generation', lambda *a, **kw: pytest.fail('restart may not rerun SQL'))
    moment[0] += timedelta(seconds=1000)
    recovered = store.recover_interrupted(now=timestamp(moment[0]))
    assert any(item.operation_id == request.operation_id and item.status == 'completed' for item in recovered)
    assert store.load(original.operation_id).status == 'completed'
    assert store.load(original.operation_id).workflow_deadline_exceeded


@pytest.mark.parametrize('change', ['pointer', 'record', 'intent'])
def test_changed_or_tampered_binding_cannot_finish_uncertain_original(bound, monkeypatch, change):
    store, original, request, moment = bound
    write_method = updater.OperationStore._write_unlocked
    write = lambda record: write_method(store, record)
    def injected(self, record):
        if record.operation_id == original.operation_id and record.status == 'completed':
            raise Crash()
        return write(record)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', injected)
    with pytest.raises(Crash):
        run(bound)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', write_method)
    if change == 'pointer':
        path = store.cache_root / 'active.json'
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b'\n')
    elif change == 'record':
        current = store.load(original.operation_id)
        write(current.model_copy(update={'updated_at': timestamp(moment[0] + timedelta(microseconds=1))}))
    else:
        current = store.load(request.operation_id)
        intent = current.reconciliation_intent.model_copy(update={'original_completed_sha256': '0'*64})
        write(current.model_copy(update={'reconciliation_intent': intent}))
    with store._ledger_lock(), pytest.raises(updater.OperationConflictError):
        recovery.replay_intent_unlocked(store, store._load_unlocked(request.operation_id))
    assert store.load(original.operation_id).status == 'running'


def test_cancellation_during_proof_leaves_original_uncertain(bound, monkeypatch):
    store, original, request, moment = bound
    validator = recovery.validate_generation
    def cancel(*a, **kw):
        store.request_cancel(request.operation_id, request_digest=request.request_digest, now=timestamp(moment[0]))
        return validator(*a, **kw)
    monkeypatch.setattr(recovery, 'validate_generation', cancel)
    assert run(bound).status == 'cancelled'
    assert store.load(original.operation_id).stage == 'committing'


def test_expired_recovery_never_dispatches_or_renews_clock(bound, monkeypatch):
    store, original, request, moment = bound
    moment[0] += timedelta(seconds=901)
    monkeypatch.setattr(recovery, 'validate_generation', lambda *a, **kw: pytest.fail('expired proof dispatched'))
    with pytest.raises(updater.PreparationDeadlineExceeded):
        run(bound)
    assert store.load(original.operation_id).stage == 'committing'


@pytest.mark.parametrize('field,value', [('max_attempts', 2), ('attempt', 2), ('kind', 'cache_update'), ('schema_version', 2)])
def test_recovery_version_and_single_attempt_are_closed(bound, field, value):
    request = bound[2]
    with pytest.raises((ValueError, ValidationError)):
        updater.OperationRequest.model_validate({**request.model_dump(mode='json'), field: value})


def test_ledger_contention_uses_remaining_recovery_without_heartbeat(bound, monkeypatch):
    import fcntl
    import os
    from kodesec_scanner.preparation_budget import PreparationClock
    store, original, request, moment = bound
    record, accepted = store.create_or_get(request, now=timestamp(moment[0]))
    assert accepted
    moment[0] += timedelta(seconds=899.9)
    context = updater.OperationContext(request=request, store=store,
        wall_now=lambda: timestamp(moment[0]),
        _budget_clock=PreparationClock(request.reconciliation_budget, now=lambda: moment[0]))
    descriptor = os.open(store.operations_path / '.ledger.lock', os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        monkeypatch.setattr(updater.time, 'sleep', lambda seconds: moment.__setitem__(0, moment[0] + timedelta(seconds=seconds)))
        with pytest.raises(updater.PreparationDeadlineExceeded):
            with store._ledger_lock(checkpoint=lambda: context.remaining_seconds(900)):
                pytest.fail('expired ledger contention was admitted')
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert store.load(original.operation_id).stage == 'committing'
    assert store.load(request.operation_id) == record


def test_completion_write_exception_replays_intent_without_fresh_sql(bound, monkeypatch):
    store, original, request, moment = bound
    write = updater.OperationStore._write_unlocked
    failed = []
    def injected(self, record):
        if record.operation_id == request.operation_id and record.status == 'completed' and not failed:
            failed.append(True)
            raise OSError('owned receipt write interrupted')
        return write(self, record)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', injected)
    result = run(bound)
    assert failed and result.status == 'completed'
    assert store.load(original.operation_id).workflow_deadline_exceeded


@pytest.mark.parametrize('change', ['pointer', 'intent'])
def test_restart_rejects_changed_intent_without_automatic_original_sql(bound, monkeypatch, change):
    store, original, request, moment = bound
    write = updater.OperationStore._write_unlocked
    def injected(self, record):
        if record.operation_id == original.operation_id and record.status == 'completed':
            raise Crash()
        return write(self, record)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', injected)
    with pytest.raises(Crash):
        run(bound)
    monkeypatch.setattr(updater.OperationStore, '_write_unlocked', write)
    if change == 'pointer':
        path = store.cache_root / 'active.json'
        path.chmod(0o600)
        path.write_bytes(path.read_bytes()+b'\n')
    else:
        own = store.load(request.operation_id)
        write(store, own.model_copy(update={'reconciliation_intent': own.reconciliation_intent.model_copy(
            update={'original_completed_sha256': '0'*64})}))
    monkeypatch.setattr(updater, 'validate_generation', lambda *a, **kw: pytest.fail('restart performed SQL'))
    monkeypatch.setattr(recovery, 'validate_generation', lambda *a, **kw: pytest.fail('restart performed SQL'))
    store.recover_interrupted(now=timestamp(moment[0]+timedelta(seconds=901)))
    assert store.load(request.operation_id).status == 'failed'
    assert store.load(original.operation_id).stage == 'committing'


def test_startup_metadata_exhaustion_defers_source_and_all_maintenance(bound, monkeypatch):
    store, original, request, moment = bound
    queued, accepted = store.create_or_get(request, now=timestamp(moment[0]))
    assert accepted
    class ExhaustedMetadata:
        calls = 0
        def checkpoint(self):
            self.calls += 1
            if self.calls > 4:
                raise updater.PreparationDeadlineExceeded('synthetic bounded metadata exhaustion')
    monkeypatch.setattr(updater, '_ReadOnlyReconciliationClock', ExhaustedMetadata)
    monkeypatch.setattr(updater, '_prune_unreferenced_generations', lambda *a, **kw: pytest.fail('uncertain startup pruned'))
    before = (store.cache_root / 'active.json').read_bytes()
    store.recover_interrupted(now=timestamp(moment[0]))
    assert store.load(original.operation_id).stage == 'committing'
    assert store.load(request.operation_id) == queued
    assert (store.cache_root / 'active.json').read_bytes() == before


def test_startup_rejects_corrupt_record1025_before_loading_or_sorting(bound, monkeypatch):
    store, original, request, moment = bound
    # Existing admission contract is1024 records, independent of terminal16KiB.
    for _ in range(updater.MAX_OPERATION_RECORDS):
        (store.operations_path / (str(uuid4())+'.json')).write_bytes(b'')
    monkeypatch.setattr(updater.OperationStore, '_load_unlocked',
                        lambda *a, **kw: pytest.fail('oversized ledger reached record loading'))
    with pytest.raises(updater.OperationCapacityError, match='record bound'):
        store.recover_interrupted(now=timestamp(moment[0]))


def test_startup_inventory_expiry_closes_iterator_and_preserves_uncertainty(bound, monkeypatch):
    store, original, request, moment = bound
    scandir = updater.os.scandir
    closed = []
    class Inventory:
        def __enter__(self):
            self.entries = scandir(store.operations_path)
            return self.entries
        def __exit__(self, *args):
            self.entries.close()
            closed.append(True)
    class InventoryDeadline:
        calls = 0
        def checkpoint(self):
            self.calls += 1
            if self.calls >= 3:
                raise updater.PreparationDeadlineExceeded('synthetic inventory expiry')
    monkeypatch.setattr(updater.os, 'scandir', lambda path: Inventory())
    monkeypatch.setattr(updater, '_ReadOnlyReconciliationClock', InventoryDeadline)
    monkeypatch.setattr(updater, '_prune_unreferenced_generations', lambda *a, **kw: pytest.fail('inventory timeout pruned'))
    store.recover_interrupted(now=timestamp(moment[0]))
    assert closed == [True]
    assert store.load(original.operation_id).stage == 'committing'
