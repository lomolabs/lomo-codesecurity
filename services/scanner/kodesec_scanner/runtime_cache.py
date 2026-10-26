"""Lifecycle-owned, nonblocking verification of read-only scanner cache inputs.

This is not an updater or a durable job queue. At most the current active and
previous-good references are retained, with one verification running at a time.
The updater still owns synchronous validation, publication and pointer changes.
"""
from __future__ import annotations

import math
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from .cache_manifest import (
    ActiveGenerationPointer, CacheValidationError, CacheVerification,
    CACHE_COMPONENT_IDS,
    GenerationReference, GrypeContentValidationError, LockValidationError,
    ResolvedGeneration, ValidatedGeneration, load_active_pointer,
    load_rules_lock, load_tool_lock, runtime_reference_identity, validate_generation,
)
from .data_catalog import generation_locks

VerificationTarget = Literal["active", "previous_good"]
IDENTITY_CHECK_INTERVAL_SECONDS = 1.0
logger = logging.getLogger(__name__)


class VerificationConflict(ValueError):
    def __init__(self, code: Literal["cache_verification_changed", "cache_verification_not_retryable"]):
        self.code = code
        super().__init__(code)


class _VerificationCancelled(RuntimeError):
    pass


class _VerificationDeadline(RuntimeError):
    pass


@dataclass
class _Task:
    target: VerificationTarget
    reference: GenerationReference
    identity: tuple[Any, ...]
    state: Literal["verifying", "timed_out", "failed", "ready", "invalid", "cancelled"] = "verifying"
    phase: Literal["queued", "validating", "hashing"] = "queued"
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    component_id: str | None = None
    bytes_verified: int | None = None
    bytes_total: int | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    generation: ValidatedGeneration | None = None

    def observation(self) -> CacheVerification:
        if self.state not in {"verifying", "timed_out", "failed"}:
            raise RuntimeError("terminal cache proof has no pending observation")
        return CacheVerification(
            state=self.state, target=self.target,
            generation_id=self.reference.generation_id, phase=self.phase,
            started_at=self.started_at, last_activity_at=self.last_activity_at,
            component_id=self.component_id, bytes_verified=self.bytes_verified,
            bytes_total=self.bytes_total,
        )


class RuntimeCacheVerifier:
    def __init__(
        self, cache_root: Path, tool_lock_path: Path, rules_lock_path: Path,
        *, deadline_seconds: float = 900, shutdown_wait_seconds: float = 10,
    ):
        if any(isinstance(value, bool) or not math.isfinite(value) or value <= 0
               for value in (deadline_seconds, shutdown_wait_seconds)):
            raise ValueError("verification deadlines must be finite and positive")
        self.cache_root = cache_root
        self.tool_lock_path = tool_lock_path
        self.rules_lock_path = rules_lock_path
        self._deadline_seconds = deadline_seconds
        self._shutdown_wait_seconds = shutdown_wait_seconds
        self._condition = threading.Condition()
        self._tasks: dict[VerificationTarget, _Task] = {}
        self._running: _Task | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def start(self) -> None:
        with self._condition:
            if self._thread is not None or self._closed:
                raise RuntimeError("cache verifier lifecycle has already started")
            self._thread = threading.Thread(target=self._run, name="scanner-cache-verification", daemon=True)
            self._thread.start()

    def _capture(self, target: VerificationTarget) -> tuple[ActiveGenerationPointer, GenerationReference | None, tuple[Any, ...] | None]:
        tools = load_tool_lock(self.tool_lock_path)
        rules = load_rules_lock(self.rules_lock_path)
        pointer = load_active_pointer(self.cache_root)
        reference = pointer.active if target == "active" else pointer.previous_good
        identity = None if reference is None else runtime_reference_identity(
            self.cache_root, reference, tool_lock_sha256=tools.sha256, rules_lock_sha256=rules.sha256,
        )
        return pointer, reference, identity

    def _task(self, target: VerificationTarget, reference: GenerationReference, identity: tuple[Any, ...]) -> _Task:
        # The caller holds the condition, never a filesystem/SQL operation.
        existing = self._tasks.get(target)
        if existing is not None and existing.identity == identity:
            return existing
        if existing is not None:
            existing.cancel.set()
        task = _Task(target, reference, identity)
        self._tasks[target] = task
        self._condition.notify_all()
        return task

    def _resolve(
        self, target: VerificationTarget, expected_locks: tuple[str, str] | None = None,
    ) -> ResolvedGeneration:
        # Never let a slow, older filesystem observation cancel a task that a
        # concurrent reader has already selected. I/O stays outside the lock;
        # one recapture handles an intervening target update without a spin loop.
        for _attempt in range(2):
            with self._condition:
                observed_task = self._tasks.get(target)
            try:
                pointer, reference, identity = self._capture(target)
            except (CacheValidationError, LockValidationError, OSError):
                with self._condition:
                    if self._tasks.get(target) is not observed_task:
                        continue
                    self._tasks.pop(target, None)
                    if observed_task is not None:
                        observed_task.cancel.set()
                return ResolvedGeneration("unavailable", None, None, "cache_pointer_unavailable")
            with self._condition:
                if self._tasks.get(target) is not observed_task:
                    continue
                if self._closed or self._thread is None:
                    raise RuntimeError("cache verifier is outside its application lifecycle")
                if reference is None:
                    self._tasks.pop(target, None)
                    if observed_task is not None:
                        observed_task.cancel.set()
                    return ResolvedGeneration("unavailable", None, pointer, "no_previous_generation")
                if expected_locks is not None and identity[1:3] != expected_locks:
                    raise CacheValidationError("scanner locks changed during readiness")
                task = self._task(target, reference, identity)
                if not self._thread.is_alive() and task.state == "verifying":
                    task.state = "failed"
                if task.state == "ready":
                    return ResolvedGeneration("ready", task.generation, pointer)
                if task.state == "invalid":
                    return ResolvedGeneration("invalid", None, pointer, "cache_generation_invalid")
                if task.state == "cancelled":
                    # This identity was removed and then selected again. Never
                    # revive its interrupted proof or requeue from a status GET.
                    task.state = "failed"
                observation = task.observation()
                state = {"verifying": "verifying", "timed_out": "verification_timeout", "failed": "verification_failed"}[task.state]
                return ResolvedGeneration(state, None, pointer, verification=observation)
        raise CacheValidationError("scanner cache changed during concurrent readiness observations")

    def resolve(
        self, cache_root: Path, *, tool_lock_sha256: str, rules_lock_sha256: str,
        checkpoint: Callable[[], object] | None = None,
    ) -> ResolvedGeneration:
        if checkpoint is not None:
            checkpoint()
        if cache_root.resolve(strict=False) != self.cache_root.resolve(strict=False):
            raise CacheValidationError("cache verifier root does not match the runtime")
        return self._resolve("active", (tool_lock_sha256, rules_lock_sha256))

    def resolve_previous(self, reference: GenerationReference) -> ResolvedGeneration:
        result = self._resolve("previous_good")
        if result.pointer is None or result.pointer.previous_good != reference:
            raise CacheValidationError("rollback pointer changed during verification")
        return result

    def retry(self, target: VerificationTarget, expected_generation: str) -> CacheVerification:
        if target not in {"active", "previous_good"}:
            raise VerificationConflict("cache_verification_changed")
        with self._condition:
            observed_task = self._tasks.get(target)
        try:
            _pointer, reference, identity = self._capture(target)
        except (CacheValidationError, LockValidationError, OSError) as exc:
            raise VerificationConflict("cache_verification_changed") from exc
        if reference is None or reference.generation_id != expected_generation:
            raise VerificationConflict("cache_verification_changed")
        with self._condition:
            old = self._tasks.get(target)
            if old is None or old is not observed_task or old.identity != identity:
                raise VerificationConflict("cache_verification_changed")
            if self._closed or self._thread is None or not self._thread.is_alive():
                raise VerificationConflict("cache_verification_not_retryable")
            if old.state == "verifying":
                return old.observation()
            if old.state not in {"timed_out", "failed"}:
                raise VerificationConflict("cache_verification_not_retryable")
            self._tasks.pop(target)
            return self._task(target, reference, identity).observation()

    def _verify(self, task: _Task) -> None:
        deadline = time.monotonic() + self._deadline_seconds
        next_identity_check = 0.0

        def checkpoint(*, final: bool = False) -> None:
            nonlocal next_identity_check
            if task.cancel.is_set():
                raise _VerificationCancelled()
            moment = time.monotonic()
            if moment >= deadline:
                raise _VerificationDeadline()
            if final or moment >= next_identity_check:
                try:
                    _pointer, _reference, current = self._capture(task.target)
                except (CacheValidationError, LockValidationError, OSError) as exc:
                    raise _VerificationCancelled() from exc
                if current != task.identity:
                    raise _VerificationCancelled()
                next_identity_check = moment + IDENTITY_CHECK_INTERVAL_SECONDS
            with self._condition:
                task.last_activity_at = max(task.last_activity_at, datetime.now(UTC))

        def progress(component: str, _index: int, _total: int, verified: int, total: int) -> None:
            if component not in CACHE_COMPONENT_IDS:
                raise CacheValidationError("cache contains an unreviewed verification component")
            with self._condition:
                task.component_id, task.bytes_verified, task.bytes_total = component, verified, total
                task.phase = "hashing" if verified else "validating"
                task.last_activity_at = max(task.last_activity_at, datetime.now(UTC))

        candidate = validate_generation(
            self.cache_root, task.reference.generation_id,
            expected_manifest_sha256=task.reference.manifest_sha256,
            checkpoint=checkpoint, progress=progress,
        )
        if task.target == "active":
            generation_locks(candidate, load_tool_lock(self.tool_lock_path),
                load_rules_lock(self.rules_lock_path), checkpoint=checkpoint)
        # Rollback admission resolves the previous generation's authority after
        # this content proof. Doing it here would misreport an unavailable older
        # catalog as corrupt bytes and hide the existing lock-mismatch guidance.
        checkpoint(final=True)
        with self._condition:
            if task.cancel.is_set() or self._tasks.get(task.target) is not task:
                raise _VerificationCancelled()
            task.generation = candidate
            task.state = "ready"

    def _run(self) -> None:
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._closed or any(
                    task.state == "verifying" and task.phase == "queued" for task in self._tasks.values()))
                if self._closed:
                    return
                task = next(self._tasks[target] for target in ("active", "previous_good")
                    if target in self._tasks and self._tasks[target].state == "verifying"
                    and self._tasks[target].phase == "queued")
                self._running = task
                task.phase = "validating"
                task.started_at = task.last_activity_at = datetime.now(UTC)
                started_monotonic = time.monotonic()
            try:
                self._verify(task)
            except _VerificationCancelled:
                with self._condition:
                    task.state = "cancelled"
            except _VerificationDeadline:
                with self._condition:
                    task.state = "timed_out"
            except GrypeContentValidationError as exc:
                with self._condition:
                    task.state = "timed_out" if exc.retryable else "invalid"
            except (CacheValidationError, LockValidationError):
                with self._condition:
                    task.state = "invalid"
            except OSError:
                with self._condition:
                    task.state = "failed"
            except Exception:
                # Keep the verifier available for an explicit retry without
                # retaining a proof or exposing private exception details.
                with self._condition:
                    task.generation = None
                    task.state = "failed"
            finally:
                with self._condition:
                    # Interrupted verification must never remain pending.
                    if task.state == "verifying":
                        task.state = "failed"
                    if task.state in {"timed_out", "failed", "invalid"}:
                        elapsed_ms = min(900_000, max(0, math.ceil(
                            (time.monotonic() - started_monotonic) * 1000)))
                        logger.warning(
                            "scanner runtime cache verification failed target=%s component_id=%s "
                            "state=%s phase=%s elapsed_ms=%s",
                            task.target, task.component_id if task.component_id in CACHE_COMPONENT_IDS else "none",
                            task.state, task.phase, elapsed_ms,
                        )
                    self._running = None
                    self._condition.notify_all()

    def shutdown(self) -> bool:
        with self._condition:
            self._closed = True
            for task in self._tasks.values():
                task.cancel.set()
            if self._running is not None:
                self._running.cancel.set()
            self._condition.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=self._shutdown_wait_seconds)
        return thread is None or not thread.is_alive()
