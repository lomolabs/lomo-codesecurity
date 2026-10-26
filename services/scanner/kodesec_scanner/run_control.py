from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from .external import ExecutionControl, RunCancelled, RunDeadlineExceeded
from .models import (
    RUN_RESULT_MAX_FINDINGS,
    RUN_RESULT_MAX_ITEM_BYTES,
    RUN_RESULT_MAX_PAGE_BYTES,
    RUN_RESULT_PAGE_ENVELOPE_BYTES,
    RUN_RESULT_PAGE_LIMIT,
    Finding,
    RunFindingPageRequest,
    RunFindingPageResponse,
    RunResultAckRequest,
    RunResultAckResponse,
    RunResultManifest,
    RunStartRequest,
    RunStateResponse,
    ScanArtifact,
    ScanRequest,
    ScanResponse,
    canonical_json_bytes,
)


TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RESULT_DIRECTORY_MODE = 0o700
_RESULT_FILE_MODE = 0o600
_RESULT_LOCK_FILE = ".registry.lock"
_RESULT_TEMP_FILE = re.compile(r"^\.[0-9a-f]{32}\.[0-9a-f]{16}\.tmp$")
_RESULT_SEALED_FILE = re.compile(r"^[0-9a-f]{32}-[0-9a-f]{64}\.jsonl$")


class RunNotFoundError(KeyError):
    pass


class RunConflictError(ValueError):
    pass


class RunCapacityError(RuntimeError):
    pass


class RunResultTooLargeError(RuntimeError):
    pass


class RunResultInvalidError(RuntimeError):
    pass


class RunResultUnavailableError(RuntimeError):
    pass


class RunCursorError(ValueError):
    pass


class RunResultStorageError(RuntimeError):
    pass


class SourceBoundaryError(ValueError):
    """A requested source cannot be proven to remain inside its authorized boundary."""


class CaptureStorageError(RuntimeError):
    """The private selected-source capture could not be written safely."""


RunExecutor = Callable[[ScanRequest, ExecutionControl], ScanResponse]


@dataclass
class _RunRecord:
    request: RunStartRequest
    fingerprint: str
    status: str
    created_at: datetime
    deadline_at: datetime
    control: ExecutionControl
    started_at: datetime | None = None
    finished_at: datetime | None = None
    expires_at: datetime | None = None
    expires_monotonic: float | None = None
    error_code: str | None = None
    error_detail: str | None = None
    result_manifest: RunResultManifest | None = None
    result_file: str | None = None
    result_file_bytes: int = 0
    result_cleanup_sync_pending: bool = False
    result_manifest_bytes: int = 0
    thread: threading.Thread | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _request_fingerprint(request: RunStartRequest) -> str:
    payload = request.model_dump(mode="json", exclude={"run_id"})
    payload["enabled_tools"] = sorted(set(payload["enabled_tools"]))
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def result_manifest_digest(
    *,
    status: str,
    findings_digest: str,
    findings_total: int,
    findings_bytes: int,
    page_count: int,
    summary: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": 1,
                "status": status,
                "findings_digest": findings_digest,
                "findings_total": findings_total,
                "findings_bytes": findings_bytes,
                "page_count": page_count,
                "page_limit": RUN_RESULT_PAGE_LIMIT,
                "summary": summary,
                "artifacts": artifacts,
            }
        )
    ).hexdigest()


def _finding_sort_key(
    pair: tuple[int, Finding],
) -> tuple[int, str, int, int, int, int, str, str, str]:
    _, finding = pair
    return (
        _SEVERITY_RANK[finding.severity],
        finding.file_path,
        finding.start_line or 0,
        finding.start_column or 0,
        finding.end_line or 0,
        finding.end_column or 0,
        finding.scanner,
        finding.rule_id,
        finding.fingerprint,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


class RunRegistry:
    """Bounded process-local execution and immutable result recovery.

    Findings are sealed as canonical JSONL in the scanner's private tmpfs and
    exposed only through digest-bound pages. PostgreSQL remains the durable
    source of truth; a scanner restart accepts the worker's same stable run ID.
    """

    def __init__(
        self,
        executor: RunExecutor,
        *,
        deadline_seconds: float,
        retention_seconds: float,
        max_terminal_records: int,
        result_dir: Path,
        max_findings: int,
        max_item_bytes: int,
        max_page_bytes: int,
        max_run_bytes: int,
        max_total_bytes: int,
        max_active_runs: int = 1,
        termination_grace_seconds: float = 5.0,
        shutdown_wait_seconds: float = 10.0,
    ) -> None:
        if min(deadline_seconds, retention_seconds, termination_grace_seconds, shutdown_wait_seconds) <= 0:
            raise ValueError("run-control time bounds must be positive")
        if min(
            max_terminal_records,
            max_active_runs,
            max_findings,
            max_item_bytes,
            max_page_bytes,
            max_run_bytes,
            max_total_bytes,
        ) <= 0:
            raise ValueError("run-control capacity bounds must be positive")
        if max_page_bytes > max_run_bytes or max_run_bytes > max_total_bytes:
            raise ValueError("run-control byte bounds must be nested")
        if max_findings > RUN_RESULT_MAX_FINDINGS:
            raise ValueError("max_findings exceeds the wire contract")
        if max_item_bytes != RUN_RESULT_MAX_ITEM_BYTES or max_page_bytes != RUN_RESULT_MAX_PAGE_BYTES:
            raise ValueError("item and page limits must match the immutable wire contract")
        if max_item_bytes >= max_page_bytes - RUN_RESULT_PAGE_ENVELOPE_BYTES:
            raise ValueError("a result page must contain one bounded item plus its envelope")
        if (
            not result_dir.is_absolute()
            or result_dir.name != "run-results"
            or result_dir.parent == result_dir
            or result_dir != result_dir.parent / "run-results"
            or any(part in {".", ".."} for part in result_dir.parts)
        ):
            raise ValueError("result_dir must be the fixed absolute scratch child")

        self._executor = executor
        self._deadline_seconds = deadline_seconds
        self._retention_seconds = retention_seconds
        self._max_terminal_records = max_terminal_records
        self._result_dir = result_dir
        self._max_findings = max_findings
        self._max_item_bytes = max_item_bytes
        self._max_page_bytes = max_page_bytes
        self._max_run_bytes = max_run_bytes
        self._max_total_bytes = max_total_bytes
        self._max_active_runs = max_active_runs
        self._termination_grace_seconds = termination_grace_seconds
        self._shutdown_wait_seconds = shutdown_wait_seconds
        self._records: dict[UUID, _RunRecord] = {}
        self._active: set[UUID] = set()
        self._retained_result_bytes = 0
        self._cursor_secret = secrets.token_bytes(32)
        self._publication_lock = threading.Lock()
        self._condition = threading.Condition(threading.RLock())
        self._result_lock_fd: int | None = None
        self._closed = False
        self._acquire_result_directory()

    def __del__(self) -> None:
        # CPython normally releases descriptors during process teardown. This
        # also keeps short-lived test/application registries from retaining an
        # advisory lock after their last reference disappears.
        try:
            self._release_result_directory()
        except BaseException:
            pass

    def start(self, request: RunStartRequest) -> RunStateResponse:
        fingerprint = _request_fingerprint(request)
        with self._condition:
            if self._closed:
                raise RunCapacityError("scanner run registry is shut down")
            self._prune_locked(time.monotonic())
            existing = self._records.get(request.run_id)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise RunConflictError("run_id is already bound to a different request")
                return self._snapshot_locked(existing)
            if len(self._active) >= self._max_active_runs:
                raise RunCapacityError("scanner active-run capacity is exhausted")
            self._reserve_terminal_slot_locked(include_active=True)
            if (
                self._retained_result_bytes
                + (len(self._active) + 1) * self._max_run_bytes
                > self._max_total_bytes
            ):
                raise RunCapacityError("scanner result retention capacity is exhausted")

            created_at = _utc_now()
            control = ExecutionControl.with_timeout(
                self._deadline_seconds,
                self._termination_grace_seconds,
            )
            record = _RunRecord(
                request=request.model_copy(deep=True),
                fingerprint=fingerprint,
                status="queued",
                created_at=created_at,
                deadline_at=created_at + timedelta(seconds=self._deadline_seconds),
                control=control,
            )
            thread = threading.Thread(
                target=self._execute,
                args=(request.run_id,),
                name=f"kodesec-run-{str(request.run_id)[:8]}",
                daemon=True,
            )
            record.thread = thread
            self._records[request.run_id] = record
            self._active.add(request.run_id)
            try:
                thread.start()
            except BaseException:
                self._active.discard(request.run_id)
                self._records.pop(request.run_id, None)
                raise
            return self._snapshot_locked(record)

    def get(self, run_id: UUID) -> RunStateResponse:
        with self._condition:
            self._prune_locked(time.monotonic())
            record = self._records.get(run_id)
            if record is None:
                raise RunNotFoundError(str(run_id))
            state = self._snapshot_locked(record)
            if state.status == "completed" and state.result_manifest is None:
                raise RunResultStorageError("completed scanner run omitted its immutable manifest")
            return state

    def list(self, *, active_only: bool = False) -> list[RunStateResponse]:
        with self._condition:
            self._prune_locked(time.monotonic())
            records = sorted(
                self._records.values(),
                key=lambda item: (item.created_at, str(item.request.run_id)),
            )
            return [
                self._snapshot_locked(record, include_manifest=False)
                for record in records
                if not active_only or record.request.run_id in self._active
            ]

    def page(self, run_id: UUID, request: RunFindingPageRequest) -> RunFindingPageResponse:
        with self._condition:
            self._prune_locked(time.monotonic())
            record = self._records.get(run_id)
            if record is None:
                raise RunNotFoundError(str(run_id))
            self._validate_result_binding_locked(record, request.request_digest, None)
            manifest = record.result_manifest
            if manifest is None or record.result_file is None:
                raise RunResultUnavailableError("scanner result was acknowledged or is unavailable")
            if manifest.findings_total == 0:
                raise RunResultUnavailableError("scanner result contains no finding pages")

            if request.cursor is None:
                start_ordinal, byte_offset = 1, 0
            else:
                start_ordinal, byte_offset = self._decode_cursor(record, request.cursor)
            if start_ordinal > manifest.findings_total or byte_offset >= manifest.findings_bytes:
                raise RunCursorError("finding cursor is outside the immutable result")

            with self._open_result_directory() as directory_fd:
                descriptor = self._open_result_file_locked(directory_fd, record)
                try:
                    if byte_offset:
                        os.lseek(descriptor, byte_offset - 1, os.SEEK_SET)
                        if os.read(descriptor, 1) != b"\n":
                            raise RunCursorError("finding cursor is not aligned to a sealed item")
                    os.lseek(descriptor, byte_offset, os.SEEK_SET)
                    with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
                        items: list[Finding] = []
                        encoded_items: list[bytes] = []
                        items_bytes = 0
                        max_items_bytes = self._max_page_bytes - RUN_RESULT_PAGE_ENVELOPE_BYTES
                        while len(items) < request.limit:
                            line_offset = handle.tell()
                            line = handle.readline(self._max_item_bytes + 1)
                            if not line:
                                break
                            if not line.endswith(b"\n") or len(line) > self._max_item_bytes:
                                raise RunResultStorageError("scanner result page failed its sealed bounds")
                            if items and items_bytes + len(line) > max_items_bytes:
                                handle.seek(line_offset)
                                break
                            try:
                                finding = Finding.model_validate_json(line[:-1])
                            except ValidationError as exc:
                                raise RunResultStorageError(
                                    "scanner result page failed strict validation"
                                ) from exc
                            if canonical_json_bytes(finding.model_dump(mode="json")) + b"\n" != line:
                                raise RunResultStorageError("scanner result page is not canonical")
                            items.append(finding)
                            encoded_items.append(line)
                            items_bytes += len(line)
                        next_offset = handle.tell()
                finally:
                    os.close(descriptor)

            if not items:
                raise RunResultStorageError("scanner result cursor produced an empty page")
            end_ordinal = start_ordinal + len(items) - 1
            truncated = end_ordinal < manifest.findings_total
            if not truncated and next_offset != manifest.findings_bytes:
                raise RunResultStorageError("scanner result length does not match its manifest")
            next_cursor = (
                self._encode_cursor(record, end_ordinal + 1, next_offset)
                if truncated
                else None
            )
            page_body = b"".join(encoded_items)
            return RunFindingPageResponse(
                run_id=record.request.run_id,
                request_digest=record.fingerprint,
                result_digest=manifest.result_digest,
                findings_total=manifest.findings_total,
                start_ordinal=start_ordinal,
                items=items,
                items_bytes=items_bytes,
                page_digest=hashlib.sha256(page_body).hexdigest(),
                truncated=truncated,
                next_cursor=next_cursor,
            )

    def acknowledge(self, run_id: UUID, request: RunResultAckRequest) -> RunResultAckResponse:
        with self._condition:
            self._prune_locked(time.monotonic())
            record = self._records.get(run_id)
            if record is None:
                raise RunNotFoundError(str(run_id))
            self._validate_result_binding_locked(
                record,
                request.request_digest,
                request.result_digest,
            )
            manifest = record.result_manifest
            if manifest is None:
                raise RunResultUnavailableError("scanner run has no result to acknowledge")
            if record.result_file is not None or record.result_cleanup_sync_pending:
                self._unlink_record_file_locked(record)
            return RunResultAckResponse(
                run_id=record.request.run_id,
                request_digest=record.fingerprint,
                result_digest=manifest.result_digest,
            )

    def cancel(
        self,
        run_id: UUID,
        *,
        request_digest: str | None = None,
        result_digest: str | None = None,
    ) -> RunStateResponse:
        with self._condition:
            if result_digest is not None and request_digest is None:
                raise RunConflictError("result digest cleanup requires the bound request digest")
            self._prune_locked(time.monotonic())
            record = self._records.get(run_id)
            if record is None:
                raise RunNotFoundError(str(run_id))
            if request_digest is not None and record.fingerprint != request_digest:
                raise RunConflictError("run_id is already bound to a different request")
            if result_digest is not None and record.status != "completed":
                raise RunConflictError("result digest cleanup requires completed immutable evidence")
            if result_digest is not None:
                self._validate_result_binding_locked(record, record.fingerprint, result_digest)
                if record.result_file is not None or record.result_cleanup_sync_pending:
                    self._unlink_record_file_locked(record)
            if record.status not in TERMINAL_RUN_STATUSES:
                record.control.cancel_event.set()
                record.status = "cancelling"
                self._condition.notify_all()
            elif (
                request_digest is not None
                and result_digest is None
                and record.status in {"failed", "cancelled"}
            ):
                # A durable worker can safely clear a non-publishable terminal
                # identity before re-posting the same immutable request.  The
                # exact request digest prevents a stale worker from deleting a
                # rebound identity.  Completed runs are deliberately excluded:
                # their evidence requires the stronger result-digest binding.
                terminal = self._snapshot_locked(record)
                self._drop_record_locked(run_id)
                self._condition.notify_all()
                return terminal
            return self._snapshot_locked(record)

    def wait_for_terminal(self, run_id: UUID, timeout: float) -> RunStateResponse:
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                record = self._records.get(run_id)
                if record is None:
                    raise RunNotFoundError(str(run_id))
                if record.status in TERMINAL_RUN_STATUSES:
                    return self._snapshot_locked(record)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"scanner run {run_id} did not become terminal")
                self._condition.wait(timeout=remaining)

    def shutdown(self) -> bool:
        with self._condition:
            threads: list[threading.Thread] = []
            for run_id in tuple(self._active):
                record = self._records.get(run_id)
                if record is None:
                    continue
                record.control.cancel_event.set()
                record.status = "cancelling"
                if record.thread is not None:
                    threads.append(record.thread)
            self._condition.notify_all()
        deadline = time.monotonic() + self._shutdown_wait_seconds
        for thread in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)
        with self._condition:
            while self._active and time.monotonic() < deadline:
                self._condition.wait(timeout=deadline - time.monotonic())
            stopped = not self._active
            if stopped:
                for record in tuple(self._records.values()):
                    if record.result_file is not None:
                        self._unlink_record_file_locked(record)
                self._closed = True
                self._release_result_directory()
            return stopped

    def _execute(self, run_id: UUID) -> None:
        with self._condition:
            record = self._records.get(run_id)
            if record is None:
                return
            if record.control.cancel_event.is_set():
                self._finalize_locked(record, status="cancelled", error_code="cancelled")
                return
            record.status = "running"
            record.started_at = _utc_now()
            request = ScanRequest.model_validate(record.request.model_dump(exclude={"run_id"}))
            control = record.control
            self._condition.notify_all()

        terminal_status = "failed"
        error_code: str | None = None
        error_detail: str | None = None
        try:
            control.checkpoint()
            produced = self._executor(request, control)
            control.checkpoint()
            if type(produced) is not ScanResponse:
                raise RunResultInvalidError("scanner executor returned an invalid result type")
            if produced.status == "failed":
                terminal_status = "failed"
                error_code = "scanner_result_failed"
                error_detail = "scanner execution reported failed evidence"
            else:
                self._seal_and_finalize(run_id, produced, control)
                return
        except RunCancelled:
            terminal_status = "cancelled"
            error_code = "cancelled"
        except RunDeadlineExceeded:
            terminal_status = "failed"
            error_code = "deadline_exceeded"
            error_detail = "scanner run exceeded its independent deadline"
        except RunResultTooLargeError:
            terminal_status = "failed"
            error_code = "result_too_large"
            error_detail = "scanner result exceeds the bounded recovery size limit"
        except RunCapacityError:
            terminal_status = "failed"
            error_code = "result_capacity"
            error_detail = "scanner result retention capacity is exhausted"
        except RunResultInvalidError:
            terminal_status = "failed"
            error_code = "result_invalid"
            error_detail = "scanner result failed strict recovery validation"
        except RunResultStorageError:
            terminal_status = "failed"
            error_code = "result_storage_failed"
            error_detail = "scanner result could not be sealed in private recovery storage"
        except SourceBoundaryError:
            terminal_status = "failed"
            error_code = "source_boundary_invalid"
            error_detail = "scanner source boundary validation failed"
        except CaptureStorageError:
            terminal_status = "failed"
            error_code = "capture_storage_unavailable"
            error_detail = "scanner could not write the private selected-source capture"
        except (ValidationError, ValueError):
            terminal_status = "failed"
            error_code = "result_invalid"
            error_detail = "scanner result failed strict recovery validation"
        except BaseException:
            terminal_status = "failed"
            error_code = "execution_failed"
            error_detail = "scanner execution failed"

        with self._condition:
            current = self._records.get(run_id)
            if current is None or current.status in TERMINAL_RUN_STATUSES:
                return
            if current.control.cancel_event.is_set():
                terminal_status = "cancelled"
                error_code = "cancelled"
                error_detail = None
            self._finalize_locked(
                current,
                status=terminal_status,
                error_code=error_code,
                error_detail=error_detail,
            )

    def _seal_and_finalize(
        self,
        run_id: UUID,
        produced: ScanResponse,
        control: ExecutionControl,
    ) -> None:
        try:
            control.checkpoint()
            if type(produced) is not ScanResponse or produced.status not in {"completed", "partial"}:
                raise ValueError("scanner result status is not publishable")
            if type(produced.findings) is not list or len(produced.findings) > self._max_findings:
                raise RunResultTooLargeError("scanner result exceeds the finding limit")
            findings: list[Finding] = []
            for ordinal, item in enumerate(produced.findings, start=1):
                if ordinal == 1 or ordinal % 32 == 0:
                    control.checkpoint()
                findings.append(Finding.model_validate(item.model_dump(mode="json")))
            artifacts: list[ScanArtifact] = []
            for ordinal, artifact in enumerate(produced.artifacts, start=1):
                if ordinal == 1 or ordinal % 32 == 0:
                    control.checkpoint()
                artifacts.append(ScanArtifact.model_validate(artifact.model_dump(mode="json")))
            minimum_pages = (
                (len(findings) + RUN_RESULT_PAGE_LIMIT - 1) // RUN_RESULT_PAGE_LIMIT
                if findings
                else 0
            )
            validated_shape = RunResultManifest(
                status=produced.status,
                result_digest="0" * 64,
                findings_digest="0" * 64,
                findings_total=len(findings),
                findings_bytes=0,
                page_count=minimum_pages,
                summary=produced.summary,
                artifacts=artifacts,
            )
            summary = validated_shape.summary
            artifacts = sorted(
                validated_shape.artifacts,
                key=lambda artifact: canonical_json_bytes(
                    artifact.model_dump(mode="json")
                ),
            )
            control.checkpoint()
        except RunResultTooLargeError:
            raise
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise RunResultInvalidError("scanner result failed strict validation") from exc

        control.checkpoint()
        ordered = sorted(enumerate(findings), key=_finding_sort_key)
        control.checkpoint()
        fingerprints: set[str] = set()
        severity_counts: dict[str, int] = {}
        scanner_counts: dict[str, int] = {}
        for ordinal, (_, finding) in enumerate(ordered, start=1):
            if ordinal == 1 or ordinal % 32 == 0:
                control.checkpoint()
            if finding.fingerprint in fingerprints:
                raise RunResultInvalidError("scanner result contains duplicate fingerprints")
            fingerprints.add(finding.fingerprint)
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            scanner_counts[finding.scanner] = scanner_counts.get(finding.scanner, 0) + 1
        artifact_payload = [artifact.model_dump(mode="json") for artifact in artifacts]
        summary_artifacts = summary.get("artifacts")
        canonical_summary_artifacts = (
            sorted(summary_artifacts, key=canonical_json_bytes)
            if type(summary_artifacts) is list
            else None
        )
        if (
            summary.get("findings_total") != len(ordered)
            or summary.get("severity_counts") != severity_counts
            or summary.get("scanner_counts") != scanner_counts
            or canonical_summary_artifacts != artifact_payload
        ):
            raise RunResultInvalidError("scanner result summary does not reconcile")
        summary = {**summary, "artifacts": artifact_payload}
        control.checkpoint()

        with self._publication_slot(control):
            with self._condition:
                self._prune_locked(time.monotonic())
                self._reserve_terminal_slot_locked()
                if self._retained_result_bytes + self._max_run_bytes > self._max_total_bytes:
                    raise RunCapacityError("scanner result retention capacity is exhausted")

            temporary_name = f".{run_id.hex}.{secrets.token_hex(8)}.tmp"
            final_name: str | None = None
            descriptor: int | None = None
            with self._open_result_directory() as directory_fd:
                try:
                    descriptor = os.open(
                        temporary_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        _RESULT_FILE_MODE,
                        dir_fd=directory_fd,
                    )
                    findings_hash = hashlib.sha256()
                    findings_bytes = 0
                    page_count = 0
                    page_items = 0
                    page_bytes = 0
                    page_budget = self._max_page_bytes - RUN_RESULT_PAGE_ENVELOPE_BYTES
                    for ordinal, (_, finding) in enumerate(ordered, start=1):
                        if ordinal == 1 or ordinal % 32 == 0:
                            control.checkpoint()
                        strict_finding = Finding.model_validate(finding.model_dump(mode="json"))
                        encoded = canonical_json_bytes(strict_finding.model_dump(mode="json")) + b"\n"
                        if len(encoded) > self._max_item_bytes:
                            raise RunResultTooLargeError("scanner finding exceeds the item byte limit")
                        if findings_bytes + len(encoded) > self._max_run_bytes:
                            raise RunResultTooLargeError("scanner result exceeds the run byte limit")
                        if page_items and (
                            page_items >= RUN_RESULT_PAGE_LIMIT
                            or page_bytes + len(encoded) > page_budget
                        ):
                            page_count += 1
                            page_items = 0
                            page_bytes = 0
                        _write_all(descriptor, encoded)
                        findings_hash.update(encoded)
                        findings_bytes += len(encoded)
                        page_items += 1
                        page_bytes += len(encoded)
                    if page_items:
                        page_count += 1
                    control.checkpoint()
                    os.fsync(descriptor)
                    control.checkpoint()
                    observed = os.fstat(descriptor)
                    if not stat.S_ISREG(observed.st_mode) or observed.st_size != findings_bytes:
                        raise RunResultStorageError("sealed scanner result size changed")
                    os.close(descriptor)
                    descriptor = None
                    control.checkpoint()

                    findings_digest = findings_hash.hexdigest()
                    digest = result_manifest_digest(
                        status=produced.status,
                        findings_digest=findings_digest,
                        findings_total=len(ordered),
                        findings_bytes=findings_bytes,
                        page_count=page_count,
                        summary=summary,
                        artifacts=artifact_payload,
                    )
                    manifest = RunResultManifest(
                        status=produced.status,
                        result_digest=digest,
                        findings_digest=findings_digest,
                        findings_total=len(ordered),
                        findings_bytes=findings_bytes,
                        page_count=page_count,
                        summary=summary,
                        artifacts=artifacts,
                    )
                    manifest_bytes = len(canonical_json_bytes(manifest.model_dump(mode="json")))
                    retained_bytes = findings_bytes + manifest_bytes
                    if retained_bytes > self._max_run_bytes:
                        raise RunResultTooLargeError(
                            "scanner result and manifest exceed the run byte limit"
                        )
                    control.checkpoint()
                    final_name = f"{run_id.hex}-{digest}.jsonl"
                    os.replace(
                        temporary_name,
                        final_name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    os.fsync(directory_fd)
                    control.checkpoint()

                    with self._condition:
                        current = self._records.get(run_id)
                        try:
                            control.checkpoint()
                        except (RunCancelled, RunDeadlineExceeded):
                            os.unlink(final_name, dir_fd=directory_fd)
                            os.fsync(directory_fd)
                            final_name = None
                            raise
                        if current is None:
                            os.unlink(final_name, dir_fd=directory_fd)
                            os.fsync(directory_fd)
                            final_name = None
                            return
                        current.result_manifest = manifest
                        current.result_file = final_name
                        current.result_file_bytes = findings_bytes
                        current.result_manifest_bytes = manifest_bytes
                        self._retained_result_bytes += retained_bytes
                        final_name = None
                        self._finalize_locked(current, status="completed")
                except (RunCancelled, RunDeadlineExceeded):
                    raise
                except (RunResultTooLargeError, RunResultInvalidError, RunCapacityError):
                    raise
                except OSError as exc:
                    raise RunResultStorageError("private scanner result storage failed") from exc
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    if final_name is not None:
                        try:
                            os.unlink(final_name, dir_fd=directory_fd)
                        except FileNotFoundError:
                            pass
                    try:
                        os.unlink(temporary_name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass

    def _finalize_locked(
        self,
        record: _RunRecord,
        *,
        status: str,
        error_code: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        now = _utc_now()
        record.status = status
        record.finished_at = now
        record.expires_at = now + timedelta(seconds=self._retention_seconds)
        record.expires_monotonic = time.monotonic() + self._retention_seconds
        record.error_code = error_code
        record.error_detail = error_detail
        if status != "completed":
            record.result_manifest = None
            if record.result_file is not None:
                self._unlink_record_file_locked(record)
        self._active.discard(record.request.run_id)
        self._prune_locked(time.monotonic())
        self._condition.notify_all()

    def _prune_locked(self, now_monotonic: float) -> None:
        expired = [
            run_id
            for run_id, record in self._records.items()
            if record.expires_monotonic is not None and record.expires_monotonic <= now_monotonic
        ]
        for run_id in expired:
            self._drop_record_locked(run_id)

        terminal = sorted(
            (record for record in self._records.values() if record.status in TERMINAL_RUN_STATUSES),
            key=lambda item: item.finished_at or item.created_at,
        )
        excess = max(len(terminal) - self._max_terminal_records, 0)
        # Unacknowledged evidence is never evicted. Acknowledged tombstones may
        # be removed by the registry's normal record-count retention bound.
        for record in (item for item in terminal if item.result_file is None):
            if excess <= 0:
                break
            self._drop_record_locked(record.request.run_id)
            excess -= 1

    def _reserve_terminal_slot_locked(self, *, include_active: bool = False) -> None:
        terminal = sorted(
            (record for record in self._records.values() if record.status in TERMINAL_RUN_STATUSES),
            key=lambda item: item.finished_at or item.created_at,
        )
        reserved = len(self._active) if include_active else 0
        while len(terminal) + reserved >= self._max_terminal_records:
            acknowledged = next((record for record in terminal if record.result_file is None), None)
            if acknowledged is None:
                raise RunCapacityError("scanner terminal-result capacity is exhausted")
            self._drop_record_locked(acknowledged.request.run_id)
            terminal.remove(acknowledged)

    def _drop_record_locked(self, run_id: UUID) -> None:
        record = self._records.get(run_id)
        if record is None:
            return
        if record.result_file is not None:
            self._unlink_record_file_locked(record)
        if record.result_manifest_bytes:
            self._retained_result_bytes = max(
                0,
                self._retained_result_bytes - record.result_manifest_bytes,
            )
            record.result_manifest_bytes = 0
        self._records.pop(run_id, None)
        self._active.discard(run_id)

    def _unlink_record_file_locked(self, record: _RunRecord) -> None:
        filename = record.result_file
        if filename is None and not record.result_cleanup_sync_pending:
            return
        result_file_bytes = record.result_file_bytes
        with self._open_result_directory() as directory_fd:
            if filename is not None:
                try:
                    os.unlink(filename, dir_fd=directory_fd)
                except FileNotFoundError as exc:
                    raise RunResultStorageError(
                        "scanner result evidence is missing before durable cleanup"
                    ) from exc
                except OSError as exc:
                    raise RunResultStorageError(
                        "scanner result evidence could not be removed"
                    ) from exc

                # unlink(2) has removed the name from this process's namespace,
                # so retaining the old pointer would make every retry fail with
                # FileNotFoundError.  Track the remaining directory-durability
                # obligation explicitly; startup reconciliation removes any
                # sealed name that could reappear after a crash.
                self._retained_result_bytes = max(
                    0,
                    self._retained_result_bytes - result_file_bytes,
                )
                record.result_file = None
                record.result_file_bytes = 0
                record.result_cleanup_sync_pending = True
            try:
                os.fsync(directory_fd)
            except OSError as exc:
                raise RunResultStorageError(
                    "scanner result cleanup could not be made durable"
                ) from exc
        record.result_cleanup_sync_pending = False

    def _validate_result_binding_locked(
        self,
        record: _RunRecord,
        request_digest: str,
        result_digest: str | None,
    ) -> None:
        if record.fingerprint != request_digest:
            raise RunConflictError("run_id is already bound to a different request")
        if record.status != "completed" or record.result_manifest is None:
            raise RunResultUnavailableError("scanner run has no completed result")
        if result_digest is not None and record.result_manifest.result_digest != result_digest:
            raise RunConflictError("result digest is bound to different immutable evidence")

    def _encode_cursor(self, record: _RunRecord, ordinal: int, byte_offset: int) -> str:
        manifest = record.result_manifest
        if manifest is None:
            raise RunResultUnavailableError("scanner run has no result manifest")
        payload = canonical_json_bytes(
            {
                "v": 1,
                "run_id": str(record.request.run_id),
                "request_digest": record.fingerprint,
                "result_digest": manifest.result_digest,
                "ordinal": ordinal,
                "byte_offset": byte_offset,
            }
        )
        signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
        return f"{self._b64(payload)}.{self._b64(signature)}"

    def _decode_cursor(self, record: _RunRecord, cursor: str) -> tuple[int, int]:
        try:
            payload_token, signature_token = cursor.split(".", 1)
            payload = self._unb64(payload_token)
            signature = self._unb64(signature_token)
            expected = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("signature")
            value = json.loads(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RunCursorError("finding cursor is invalid") from exc
        manifest = record.result_manifest
        expected_keys = {
            "v",
            "run_id",
            "request_digest",
            "result_digest",
            "ordinal",
            "byte_offset",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected_keys
            or value.get("v") != 1
            or value.get("run_id") != str(record.request.run_id)
            or value.get("request_digest") != record.fingerprint
            or manifest is None
            or value.get("result_digest") != manifest.result_digest
            or not isinstance(value.get("ordinal"), int)
            or isinstance(value.get("ordinal"), bool)
            or not isinstance(value.get("byte_offset"), int)
            or isinstance(value.get("byte_offset"), bool)
            or value["ordinal"] < 1
            or value["byte_offset"] < 0
        ):
            raise RunCursorError("finding cursor is not bound to this immutable result")
        return value["ordinal"], value["byte_offset"]

    @contextmanager
    def _publication_slot(self, control: ExecutionControl) -> Iterator[None]:
        acquired = False
        try:
            while not acquired:
                control.checkpoint()
                acquired = self._publication_lock.acquire(timeout=0.05)
            control.checkpoint()
            yield
        finally:
            if acquired:
                self._publication_lock.release()

    def _acquire_result_directory(self) -> None:
        lock_descriptor: int | None = None
        try:
            with self._open_result_directory() as directory_fd:
                try:
                    lock_descriptor = os.open(
                        _RESULT_LOCK_FILE,
                        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                        _RESULT_FILE_MODE,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise RunResultStorageError(
                        "scanner result registry lock could not be opened safely"
                    ) from exc
                observed = os.fstat(lock_descriptor)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1
                    or stat.S_IMODE(observed.st_mode) != _RESULT_FILE_MODE
                ):
                    raise RunResultStorageError("scanner result registry lock is unsafe")
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    if exc.errno in {errno.EACCES, errno.EAGAIN}:
                        raise RunCapacityError(
                            "scanner result directory is already owned by a live registry"
                        ) from exc
                    raise RunResultStorageError(
                        "scanner result registry lock could not be acquired safely"
                    ) from exc
                self._reconcile_result_directory(directory_fd)
                self._result_lock_fd = lock_descriptor
                lock_descriptor = None
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)

    @staticmethod
    def _reconcile_result_directory(directory_fd: int) -> None:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise RunResultStorageError("scanner result storage could not be reconciled") from exc
        removable: list[str] = []
        for name in names:
            if name == _RESULT_LOCK_FILE:
                continue
            if _RESULT_TEMP_FILE.fullmatch(name) is None and _RESULT_SEALED_FILE.fullmatch(name) is None:
                raise RunResultStorageError("scanner result storage contains an unknown entry")
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise RunResultStorageError("scanner result storage entry could not be inspected") from exc
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != _RESULT_FILE_MODE
            ):
                raise RunResultStorageError("scanner result storage contains an unsafe entry")
            removable.append(name)
        try:
            for name in removable:
                os.unlink(name, dir_fd=directory_fd)
            if removable:
                os.fsync(directory_fd)
        except OSError as exc:
            raise RunResultStorageError("scanner result storage could not be reconciled") from exc

    def _release_result_directory(self) -> None:
        descriptor = self._result_lock_fd
        if descriptor is None:
            return
        self._result_lock_fd = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _unb64(value: str) -> bytes:
        if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
            raise ValueError("invalid base64url")
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    @contextmanager
    def _open_result_directory(self) -> Iterator[int]:
        scratch = self._result_dir.parent
        try:
            os.mkdir(scratch.parent, _RESULT_DIRECTORY_MODE)
        except FileExistsError:
            pass
        try:
            parent_stat = os.lstat(scratch.parent)
        except OSError as exc:
            raise RunResultStorageError("scanner scratch parent is unavailable") from exc
        if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
            raise RunResultStorageError("scanner scratch parent is not a safe directory")
        try:
            parent_fd = os.open(
                scratch.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            raise RunResultStorageError("scanner scratch parent could not be opened safely") from exc
        try:
            try:
                os.mkdir(scratch.name, _RESULT_DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError:
                pass
        finally:
            os.close(parent_fd)
        try:
            scratch_stat = os.lstat(scratch)
        except OSError as exc:
            raise RunResultStorageError("scanner scratch storage is unavailable") from exc
        if (
            not stat.S_ISDIR(scratch_stat.st_mode)
            or stat.S_ISLNK(scratch_stat.st_mode)
            or scratch_stat.st_uid != os.geteuid()
        ):
            raise RunResultStorageError("scanner scratch storage is not a private owned directory")
        try:
            os.chmod(scratch, _RESULT_DIRECTORY_MODE, follow_symlinks=False)
            scratch_fd = os.open(
                scratch,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            raise RunResultStorageError("scanner scratch storage could not be opened safely") from exc
        directory_fd: int | None = None
        try:
            try:
                os.mkdir(
                    self._result_dir.name,
                    _RESULT_DIRECTORY_MODE,
                    dir_fd=scratch_fd,
                )
            except FileExistsError:
                pass
            result_stat = os.stat(
                self._result_dir.name,
                dir_fd=scratch_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(result_stat.st_mode)
                or stat.S_ISLNK(result_stat.st_mode)
                or result_stat.st_uid != os.geteuid()
            ):
                raise RunResultStorageError("scanner result storage is not a private owned directory")
            os.chmod(
                self._result_dir.name,
                _RESULT_DIRECTORY_MODE,
                dir_fd=scratch_fd,
                follow_symlinks=False,
            )
            directory_fd = os.open(
                self._result_dir.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=scratch_fd,
            )
            opened = os.fstat(directory_fd)
            if opened.st_ino != result_stat.st_ino or opened.st_dev != result_stat.st_dev:
                raise RunResultStorageError("scanner result storage changed during secure open")
            yield directory_fd
        except RunResultStorageError:
            raise
        except OSError as exc:
            raise RunResultStorageError("scanner result storage could not be opened safely") from exc
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(scratch_fd)

    @staticmethod
    def _open_result_file_locked(directory_fd: int, record: _RunRecord) -> int:
        filename = record.result_file
        if filename is None:
            raise RunResultUnavailableError("scanner result is unavailable")
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
        except FileNotFoundError as exc:
            raise RunResultUnavailableError("scanner result is unavailable") from exc
        except OSError as exc:
            raise RunResultStorageError("scanner result could not be opened safely") from exc
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != _RESULT_FILE_MODE
            or observed.st_size != record.result_file_bytes
        ):
            os.close(descriptor)
            raise RunResultStorageError("scanner result file failed its sealed identity check")
        return descriptor

    @staticmethod
    def _snapshot_locked(
        record: _RunRecord,
        *,
        include_manifest: bool = True,
    ) -> RunStateResponse:
        return RunStateResponse(
            run_id=record.request.run_id,
            request_digest=record.fingerprint,
            status=record.status,  # type: ignore[arg-type]
            created_at=record.created_at,
            started_at=record.started_at,
            finished_at=record.finished_at,
            deadline_at=record.deadline_at,
            expires_at=record.expires_at,
            error_code=record.error_code,
            error_detail=record.error_detail,
            result_manifest=record.result_manifest if include_manifest else None,
            result_available=bool(
                include_manifest
                and record.result_manifest is not None
                and record.result_file is not None
            ),
        )
