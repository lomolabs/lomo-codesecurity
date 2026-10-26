from kodesec_scanner.preparation_budget import issue_budget
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from kodesec_scanner import updater_service
from kodesec_scanner.cache_manifest import load_rules_lock, load_tool_lock
from kodesec_scanner.updater import (
    OperationCapacityError,
    OperationConflictError,
    OperationNotFoundError,
    OperationRequest,
    OperationStore,
    operation_request_digest,
)

ROOT = Path(__file__).resolve().parents[3]
TOOLS = load_tool_lock(ROOT / "scanner-tools.lock.json")
RULES = load_rules_lock(ROOT / "scanner-rules.lock.json")


def request():
    budget = issue_budget() if True else None
    version = 2 if budget is not None else 1
    return OperationRequest(
        schema_version=version,
        preparation_budget=budget,
        operation_id=uuid4(),
        request_digest=operation_request_digest(
            schema_version=version,
        preparation_budget=budget, kind="catalog_check", requested_components=[]
        ),
        kind="catalog_check",
        requested_components=[],
        attempt=1,
        max_attempts=3,
    )


class ControlledPool:
    def __init__(self, **kwargs):
        self.futures = []
        self.closed = False

    def submit(self, function, value):
        future = Future()
        self.futures.append(future)
        return future

    def shutdown(self, **kwargs):
        self.closed = True


@pytest.fixture
def executor(tmp_path, monkeypatch):
    monkeypatch.setattr(updater_service, "ThreadPoolExecutor", ControlledPool)
    value = updater_service.UpdaterExecutor(
        TOOLS,
        RULES,
        OperationStore(tmp_path / "cache"),
        SimpleNamespace(),
        max_active=1,
        max_pending=1,
    )
    yield value
    for future in value._executor.futures:
        if not future.done():
            future.set_result(None)
    assert value.shutdown()


def fail_first(executor, first):
    executor.store.transition(first.operation_id, status="running", stage="discovering")
    return executor.store.transition(
        first.operation_id,
        status="failed",
        stage="failed",
        error_code="operation_failed",
        error_detail="bounded test failure",
    )


def test_retry_admitted_while_previous_future_is_finishing(executor):
    first = request()
    executor.submit(first)
    failed = fail_first(executor, first)
    retry = first.model_copy(update={"attempt": 2})
    queued, accepted = executor.submit(retry)
    assert accepted and queued.attempt == 2 and queued.status == "queued"
    assert len(executor._futures) == 2
    old, new = executor._executor.futures
    old.set_result(failed)
    assert list(executor._futures) == [new]
    assert executor.store.load(first.operation_id) == queued
    # Finishing attempt 1 cannot unregister attempt 2 or double-release capacity.
    executor._finished(old)
    other = request()
    assert executor.submit(other)[1]
    with pytest.raises(OperationCapacityError):
        executor.submit(request())


def test_capacity_preserves_failed_attempt_and_replay(executor):
    first, other = request(), request()
    executor.submit(first)
    executor.submit(other)
    failed = fail_first(executor, first)
    assert executor.submit(first) == (failed, False)
    with pytest.raises(OperationCapacityError):
        executor.submit(first.model_copy(update={"attempt": 2}))
    assert executor.store.load(first.operation_id) == failed
    missing = request()
    with pytest.raises(OperationCapacityError):
        executor.submit(missing)
    with pytest.raises(OperationNotFoundError):
        executor.store.load(missing.operation_id)
    with pytest.raises(OperationConflictError):
        executor.submit(first.model_copy(update={"max_attempts": 2}))
    assert executor.store.load(first.operation_id) == failed
    executor._executor.futures[0].set_result(failed)
    assert executor.submit(first.model_copy(update={"attempt": 2}))[1]


def test_completed_future_registers_callback_outside_guard(executor, monkeypatch):
    class ImmediateFuture(Future):
        def add_done_callback(self, callback):
            assert not executor._guard.locked()
            super().add_done_callback(callback)

    def finish_immediately(function, value):
        future = ImmediateFuture()
        future.set_result(None)
        return future

    monkeypatch.setattr(executor._executor, "submit", finish_immediately)
    assert executor.submit(request())[1]
    assert not executor._futures
    assert executor._slots.acquire(blocking=False)
    assert executor._slots.acquire(blocking=False)
    assert not executor._slots.acquire(blocking=False)
    executor._slots.release()
    executor._slots.release()


def test_shutdown_tracks_both_attempts_and_snapshots_operations(executor, monkeypatch):
    first = request()
    executor.submit(first)
    fail_first(executor, first)
    executor.submit(first.model_copy(update={"attempt": 2}))
    expected = set(executor._executor.futures)
    cancelled = []

    def cancel(self, operation_id, **kwargs):
        cancelled.append(operation_id)
        # Completion during cancellation must not mutate the iteration.
        next(iter(expected)).set_result(None)

    monkeypatch.setattr(OperationStore, "request_cancel", cancel)

    def wait(futures, *, timeout):
        assert set(futures) == expected
        return set(), expected

    monkeypatch.setattr(updater_service, "wait", wait)
    assert executor.shutdown() is False
    assert cancelled == [first.operation_id]
    monkeypatch.undo()
    with pytest.raises(OperationCapacityError):
        executor.submit(request())


@pytest.mark.parametrize("max_active", [1, 2])
def test_real_worker_retry_after_terminal_record_before_future_return(
    tmp_path,
    monkeypatch,
    max_active,
):
    from threading import Event
    from kodesec_scanner.updater import LockedLifecycleHandlers, OperationError

    terminal_published, allow_return = Event(), Event()
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
    )

    def catalog(context):
        if context.request.attempt == 1:
            raise OperationError("bounded first-attempt test failure")
        return handlers.catalog_check(context)

    original = updater_service.UpdaterExecutor._execute_created

    def pause_first_return(self, value):
        result = original(self, value)
        if value.attempt == 1:
            terminal_published.set()
            assert allow_return.wait(5)
        return result

    monkeypatch.setattr(
        updater_service.UpdaterExecutor, "_execute_created", pause_first_return
    )
    executor = updater_service.UpdaterExecutor(
        TOOLS,
        RULES,
        OperationStore(tmp_path / "cache"),
        SimpleNamespace(cache_update=handlers.cache_update, catalog_check=catalog),
        max_active=max_active,
        max_pending=1,
    )
    try:
        first = request()
        executor.submit(first)
        assert terminal_published.wait(5)
        assert executor.store.load(first.operation_id).status == "failed"
        old = next(iter(executor._futures))
        record, accepted = executor.submit(first.model_copy(update={"attempt": 2}))
        assert accepted and record.attempt == 2 and record.status == "queued"
        assert not old.done()
        allow_return.set()
        assert old.result(timeout=5).status == "failed"
        # Shutdown must wait for the next attempt, including max_active=1 queueing.
        # Wait for its actual result first so shutdown does not cancel it.
        with executor._guard:
            pending = list(executor._futures)
        for future in pending:
            future.result(timeout=5)
        final = executor.store.load(first.operation_id)
        assert final.status == "completed" and final.attempt == 2
    finally:
        allow_return.set()
        assert executor.shutdown()


def test_grype_telemetry_exposes_only_the_validated_reason():
    from kodesec_scanner import updater
    from kodesec_scanner.cache_manifest import GrypeContentValidationError

    for code in ("deadline", "integrity", "cancelled"):
        error = GrypeContentValidationError(code)
        error.args = ("private https://example.invalid/cache",)
        assert (
            updater._safe_operation_telemetry_detail(error)
            == "grype_validation_" + code
        )
    error.code = "/private/host/path"
    assert (
        updater._safe_operation_telemetry_detail(error)
        == "non-operation exception redacted"
    )
