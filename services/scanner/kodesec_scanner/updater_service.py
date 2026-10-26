"""Bounded background execution for source-blind lifecycle operations."""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from uuid import UUID

from .cache_manifest import LoadedDocument, RulesLockFile, ToolLockFile
from .updater import (
    LockedLifecycleHandlers,
    OperationCapacityError,
    OperationRecord,
    OperationRequest,
    OperationStore,
    execute_operation,
    validate_operation_request,
)


@dataclass
class UpdaterExecutor:
    """Persist first, then execute from a small fixed worker/queue budget."""

    tools: LoadedDocument[ToolLockFile]
    rules: LoadedDocument[RulesLockFile]
    store: OperationStore
    handlers: LockedLifecycleHandlers
    max_active: int = 1
    max_pending: int = 8
    shutdown_wait_seconds: float = 10.0
    _executor: ThreadPoolExecutor = field(init=False, repr=False)
    _slots: threading.BoundedSemaphore = field(init=False, repr=False)
    _futures: dict[Future[OperationRecord], UUID] = field(init=False, default_factory=dict, repr=False)
    _guard: threading.Lock = field(init=False, default_factory=threading.Lock, repr=False)
    _closed: bool = field(init=False, default=False, repr=False)

    def __post_init__(self) -> None:
        if not 1 <= self.max_active <= 2 or not 1 <= self.max_pending <= 32:
            raise ValueError("updater execution bounds are invalid")
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_active,
            thread_name_prefix="kodesec-updater",
        )
        self._slots = threading.BoundedSemaphore(self.max_active + self.max_pending)

    def recover(self) -> list[OperationRecord]:
        return self.store.recover_interrupted()

    def submit(self, request: OperationRequest) -> tuple[OperationRecord, bool]:
        validate_operation_request(request, self.tools.value)
        with self._guard:
            if self._closed:
                raise OperationCapacityError("updater executor is shutting down")
            acquired = self._slots.acquire(blocking=False)
            try:
                # Replays remain available at capacity. A new attempt may only
                # change the ledger after reserving its own execution slot.
                record, should_execute = self.store.create_or_get(
                    request, admit_new_attempt=acquired,
                )
                if not should_execute:
                    if acquired:
                        self._slots.release()
                    return record, False
                future = self._executor.submit(self._execute_created, request)
                self._futures[future] = request.operation_id
            except Exception:
                if acquired:
                    self._slots.release()
                raise
        # A completed Future invokes its callback synchronously. Register outside
        # the guard so a fast operation cannot deadlock its own completion.
        future.add_done_callback(self._finished)
        return record, True

    def _execute_created(self, request: OperationRequest) -> OperationRecord:
        return execute_operation(
            request,
            self.tools,
            self.rules,
            self.store,
            cache_update=self.handlers.cache_update,
            catalog_check=self.handlers.catalog_check,
            admitted=True,
        )

    def _finished(self, future: Future[OperationRecord]) -> None:
        with self._guard:
            if self._futures.pop(future, None) is not None:
                self._slots.release()

    def shutdown(self) -> bool:
        with self._guard:
            self._closed = True
            futures = list(self._futures)
            operation_ids = set(self._futures.values())
        for operation_id in operation_ids:
            try:
                record = self.store.load(operation_id)
                self.store.request_cancel(
                    operation_id,
                    request_digest=record.request_digest,
                )
            except Exception:
                continue
        _done, pending = wait(futures, timeout=self.shutdown_wait_seconds)
        self._executor.shutdown(wait=False, cancel_futures=True)
        return not pending
