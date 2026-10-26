"""Explicit source-blind recovery; writes receipts, never cache content/pointers."""
from __future__ import annotations

import hashlib
from uuid import UUID

from .cache_manifest import (
    MAX_ACTIVE_POINTER_BYTES, ActiveGenerationPointer, canonical_json_bytes,
    _decode_json_object, _read_bounded_regular_file, validate_generation,
)
from .preparation_budget import moment
from .updater import (
    OperationConflictError, OperationRecord, OperationStateError, ReconciliationIntent,
    ReconciliationOperationResult, _ReadOnlyReconciliationClock, _pointer_result, _validate_candidate_components, generation_lock,
)


def record_sha(record: OperationRecord) -> str:
    return hashlib.sha256(canonical_json_bytes(record.model_dump(mode='json'))).hexdigest()


def pointer_snapshot(store):
    raw = _read_bounded_regular_file(store.cache_root / 'active.json',
                                     MAX_ACTIVE_POINTER_BYTES, 'active generation pointer')
    pointer = ActiveGenerationPointer.model_validate(_decode_json_object(raw, 'active generation pointer'))
    return pointer, hashlib.sha256(raw).hexdigest()


def preview(store, operation_id: UUID, request_digest: str):
    # Bounded metadata only. No database verification, proof cache or work admission.
    clock = _ReadOnlyReconciliationClock()
    with generation_lock(store.cache_root, checkpoint=clock.checkpoint), store._ledger_lock(contention_check=clock.checkpoint):
        current = store._load_unlocked(operation_id)
        if current.request_digest != request_digest:
            raise OperationConflictError('original operation binding changed')
        if (current.kind != 'cache_update' or current.preparation_budget is None
                or current.status != 'running' or current.stage not in {'committing', 'activating'}):
            raise OperationStateError('original operation has no uncertain publication')
        pointer, digest = pointer_snapshot(store)
        if pointer.operation_id != str(operation_id):
            raise OperationConflictError('published pointer does not belong to original operation')
        clock.checkpoint()
        return {'operation_id': str(current.operation_id), 'request_digest': current.request_digest,
                'attempt': current.attempt, 'record_sha256': record_sha(current),
                'pointer_sha256': digest, 'active': pointer.active.model_dump(mode='json')}


def _bound_pointer(store, target):
    pointer, digest = pointer_snapshot(store)
    if (digest != target.pointer_sha256 or pointer.operation_id != target.operation_id
            or pointer.active.model_dump(mode='json') != target.active.model_dump(mode='json')):
        raise OperationConflictError('reconciliation pointer changed')
    return pointer


def _completed(original, pointer, proven_at):
    return OperationRecord.model_validate(original.model_copy(update={
        'status': 'completed', 'stage': 'completed', 'finished_at': proven_at,
        'started_at': original.started_at or proven_at, 'updated_at': proven_at,
        'last_activity_at': proven_at, 'activity': None,
        'result': _pointer_result(pointer, original.requested_components),
        'workflow_deadline_exceeded': moment(proven_at) >= moment(original.preparation_budget.deadline_at),
        'error_code': None, 'error_detail': None,
    }).model_dump(mode='json'))


def replay_intent_unlocked(store, current, *, checkpoint=None):
    """Caller holds generation+ledger locks. Replay historical writes only."""
    if checkpoint is not None:
        checkpoint()
    target, intent = current.reconciliation_target, current.reconciliation_intent
    if intent is None:
        return None
    pointer = _bound_pointer(store, target)
    original = store._load_unlocked(UUID(target.operation_id))
    if (original.operation_id != intent.result.original_operation_id
            or original.request_digest != target.request_digest or original.attempt != target.attempt
            or original.preparation_budget is None
            or intent.result.original_request_digest != target.request_digest
            or intent.result.verified_at != intent.original_finished_at
            or intent.result.original_record_sha256 != intent.original_completed_sha256
            or intent.result.active != pointer.active or intent.result.previous_good != pointer.previous_good
            or intent.cache_result != _pointer_result(pointer, original.requested_components)
            or not moment(current.reconciliation_budget.issued_at) <= moment(intent.original_finished_at)
                < moment(current.reconciliation_budget.deadline_at)):
        raise OperationConflictError('historical reconciliation intent differs from its binding')
    if original.status == 'completed':
        completed = original
    else:
        if (record_sha(original) != target.record_sha256 or original.status != 'running'
                or original.stage not in {'committing', 'activating'}):
            raise OperationConflictError('original operation revision changed')
        completed = _completed(original, pointer, intent.original_finished_at)
    if (record_sha(completed) != intent.original_completed_sha256
            or completed.workflow_deadline_exceeded != intent.result.original_workflow_deadline_exceeded):
        raise OperationConflictError('historical completed outcome differs from intent')
    if checkpoint is not None:
        checkpoint()
    if original.status != 'completed':
        store._write_unlocked(completed)
    return store._transition_unlocked(current, status='completed', stage='completed',
                                      result=intent.result, now=intent.original_finished_at)


def execute_reconciliation(context, tools, rules, *, now):
    store, target = context.store, context.request.reconciliation_target
    with generation_lock(store.cache_root, checkpoint=context.checkpoint):
        context.progress('validating_generation', now=now())
        with store._ledger_lock(checkpoint=lambda: context.remaining_seconds(900)):
            original = store._load_unlocked(UUID(target.operation_id))
            if (record_sha(original) != target.record_sha256 or original.request_digest != target.request_digest
                    or original.attempt != target.attempt or original.kind != 'cache_update'
                    or original.status != 'running' or original.stage not in {'committing', 'activating'}
                    or original.preparation_budget is None):
                raise OperationConflictError('original operation revision changed')
            pointer = _bound_pointer(store, target)
        validated = validate_generation(store.cache_root, pointer.active.generation_id,
                                        expected_manifest_sha256=pointer.active.manifest_sha256,
                                        checkpoint=context.refresh_activity)
        context.checkpoint()
        _validate_candidate_components(validated, original.requested_components, tools, rules,
                                       evaluated_at=moment(now()))
        context.checkpoint()
        with store._ledger_lock(checkpoint=lambda: context.remaining_seconds(900)):
            # No nested heartbeat lock. Clock and cancellation checked under the same CAS lock.
            context.remaining_seconds(900)
            own = store._load_unlocked(context.request.operation_id)
            if own.cancel_requested_at is not None or own.status != 'running':
                raise OperationStateError('reconciliation cancellation requested')
            original = store._load_unlocked(UUID(target.operation_id))
            if record_sha(original) != target.record_sha256:
                raise OperationConflictError('original operation changed during proof')
            pointer = _bound_pointer(store, target)
            proven_at = now()
            completed = _completed(original, pointer, proven_at)
            result = ReconciliationOperationResult(
                kind='reconciliation', active=pointer.active, previous_good=pointer.previous_good,
                original_operation_id=original.operation_id, original_request_digest=original.request_digest,
                original_record_sha256=record_sha(completed),
                original_workflow_deadline_exceeded=completed.workflow_deadline_exceeded,
                verified_at=proven_at,
            )
            intent = ReconciliationIntent(original_completed_sha256=record_sha(completed),
                                           original_finished_at=proven_at,
                                           cache_result=completed.result, result=result)
            committing = OperationRecord.model_validate(own.model_copy(update={
                'stage': 'committing', 'reconciliation_intent': intent,
                'updated_at': proven_at, 'last_activity_at': proven_at,
            }).model_dump(mode='json'))
            # Fence: durable intent precedes both outcome writes; no source mutations.
            store._write_unlocked(committing)
            return replay_intent_unlocked(store, committing, checkpoint=lambda: context.remaining_seconds(900))


def reconcile_intent(store, operation_id, *, clock=None):
    """Five-second owned cleanup only; never performs SQL or renews recovery."""
    clock = clock or _ReadOnlyReconciliationClock()
    with generation_lock(store.cache_root, checkpoint=clock.checkpoint), store._ledger_lock(checkpoint=clock.checkpoint):
        current = store._load_unlocked(operation_id)
        if current.reconciliation_intent is None:
            return None
        try:
            return replay_intent_unlocked(store, current, checkpoint=clock.checkpoint)
        except (OperationConflictError, ValueError):
            return current  # Preserve durable historical intent for explicit inspection.
