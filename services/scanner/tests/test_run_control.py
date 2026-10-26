from __future__ import annotations

import errno
import os
from pathlib import Path
import tempfile

os.environ.setdefault(
    "KODESEC_SCRATCH_DIR",
    str(Path(tempfile.mkdtemp(prefix="kodesec-scanner-module-")) / "scratch"),
)

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from kodesec_scanner import main as scanner
from kodesec_scanner import external
from kodesec_scanner.external import ExecutionControl, request_scratch_directory
from kodesec_scanner.models import (
    RUN_RESULT_MAX_ITEM_BYTES,
    Finding,
    RunFindingPageResponse,
    RunFindingPageRequest,
    RunResultAckRequest,
    RunResultManifest,
    RunStartRequest,
    RunStateResponse,
    ScanArtifact,
    ScanRequest,
    ScanResponse,
    canonical_json_bytes,
)
from kodesec_scanner.run_control import (
    RunCapacityError,
    RunConflictError,
    RunCursorError,
    RunNotFoundError,
    RunRegistry,
    RunResultStorageError,
    RunResultUnavailableError,
    result_manifest_digest,
)


def _request(run_id: UUID | None = None, *, scan_id: int = 1, repo_path: str = "/fixture") -> RunStartRequest:
    return RunStartRequest(
        run_id=run_id or uuid4(),
        scan_id=scan_id,
        repo_path=repo_path,
        enabled_tools=["sast-lite"],
    )


def _result(message: str = "fixture") -> ScanResponse:
    return ScanResponse(
        status="completed",
        findings=[
            Finding(
                scanner="sast-lite",
                rule_id="fixture-rule",
                severity="high",
                file_path="source.py",
                start_line=1,
                end_line=1,
                message=message,
                fingerprint="f" * 64,
            )
        ],
        summary={
            "findings_total": 1,
            "severity_counts": {"high": 1},
            "scanner_counts": {"sast-lite": 1},
            "artifacts": [],
        },
    )


def _many_findings_result(count: int, *, message_size: int = 1000) -> ScanResponse:
    findings = [
        Finding(
            scanner="opengrep",
            rule_id=f"fixture.rule.{index % 17}",
            severity="high",
            file_path=f"src/module-{index % 101}/file-{index:05d}.py",
            start_line=(index % 500) + 1,
            end_line=(index % 500) + 1,
            message=f"finding-{index:05d}:" + "m" * message_size,
            code_snippet=f"dangerous_call({index})",
            fingerprint=hashlib.sha256(f"fixture-{index}".encode()).hexdigest(),
            metadata={"source": "production-shaped-fixture", "index": index},
        )
        for index in range(count)
    ]
    return ScanResponse(
        status="completed",
        findings=findings,
        artifacts=[],
        summary={
            "findings_total": count,
            "severity_counts": {"high": count} if count else {},
            "scanner_counts": {"opengrep": count} if count else {},
            "artifacts": [],
        },
    )


def _registry(
    executor,
    *,
    deadline_seconds: float = 5,
    retention_seconds: float = 5,
    max_terminal_records: int = 4,
    max_findings: int = 50_000,
    max_run_bytes: int = 336 * 1024 * 1024,
    max_total_bytes: int = 384 * 1024 * 1024,
    max_active_runs: int = 1,
    result_dir: Path | None = None,
) -> RunRegistry:
    if result_dir is None:
        result_dir = Path(tempfile.mkdtemp(prefix="kodesec-run-control-")) / "scratch" / "run-results"
    return RunRegistry(
        executor,
        deadline_seconds=deadline_seconds,
        retention_seconds=retention_seconds,
        max_terminal_records=max_terminal_records,
        result_dir=result_dir,
        max_findings=max_findings,
        max_item_bytes=32 * 1024,
        max_page_bytes=4 * 1024 * 1024,
        max_run_bytes=max_run_bytes,
        max_total_bytes=max_total_bytes,
        max_active_runs=max_active_runs,
        termination_grace_seconds=0.1,
        shutdown_wait_seconds=1,
    )


def _abandon_registry_lock(registry: RunRegistry) -> None:
    """Simulate process death without calling the cleanup-oriented shutdown."""

    registry._release_result_directory()


def test_enabled_tools_is_required_and_nonempty() -> None:
    with pytest.raises(ValidationError, match="Field required"):
        ScanRequest(scan_id=1, repo_path="/fixture")
    with pytest.raises(ValidationError, match="at least 1 item"):
        ScanRequest(scan_id=1, repo_path="/fixture", enabled_tools=[])

    parsed = RunStartRequest.model_validate(
        {
            "run_id": str(uuid4()),
            "scan_id": 1,
            "repo_path": "/fixture",
            "enabled_tools": ["sast-lite"],
        }
    )
    assert isinstance(parsed.run_id, UUID)


def test_finding_wire_model_is_strict_bounded_and_records_evidence_truncation() -> None:
    finding = Finding(
        scanner="opengrep",
        rule_id="fixture.rule",
        severity="high",
        file_path="src/app.py",
        start_line=3,
        end_line=3,
        message="m" * 10_000,
        code_snippet="ž" * 20_000,
        fingerprint="f" * 64,
        metadata={},
    )
    assert finding.metadata == {"message_truncated": True, "snippet_truncated": True}
    assert len(canonical_json_bytes(finding.model_dump(mode="json"))) + 1 <= RUN_RESULT_MAX_ITEM_BYTES

    payload = finding.model_dump(mode="json")
    with pytest.raises(ValidationError, match="Input should be a valid integer"):
        Finding.model_validate({**payload, "start_line": True})
    with pytest.raises(ValidationError, match="lowercase SHA-256"):
        Finding.model_validate({**payload, "fingerprint": "F" * 64})
    with pytest.raises(ValidationError, match="project-relative"):
        Finding.model_validate({**payload, "file_path": "../escape.py"})
    with pytest.raises(ValidationError, match="valid UTF-8"):
        Finding.model_validate({**payload, "rule_id": "bad\ud800"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        Finding.model_validate({**payload, "unexpected": True})


def test_manifest_page_artifact_and_ack_tombstone_shapes_are_exact() -> None:
    finding = _result().findings[0]
    encoded = canonical_json_bytes(finding.model_dump(mode="json")) + b"\n"
    import hashlib

    digest = hashlib.sha256(encoded).hexdigest()
    manifest = RunResultManifest(
        status="completed",
        result_digest="a" * 64,
        findings_digest=digest,
        findings_total=1,
        findings_bytes=len(encoded),
        page_count=1,
        summary={"findings_total": 1},
        artifacts=[],
    )
    page = RunFindingPageResponse(
        run_id=uuid4(),
        request_digest="b" * 64,
        result_digest=manifest.result_digest,
        findings_total=1,
        start_ordinal=1,
        items=[finding],
        items_bytes=len(encoded),
        page_digest=digest,
        truncated=False,
    )
    assert page.next_cursor is None
    completed = RunStateResponse(
        run_id=page.run_id,
        request_digest=page.request_digest,
        status="completed",
        created_at=datetime.now(timezone.utc),
        deadline_at=datetime.now(timezone.utc),
        result_manifest=manifest,
        result_available=False,
    )
    assert completed.result_manifest == manifest

    with pytest.raises(ValidationError, match="only completed"):
        RunStateResponse.model_validate({**completed.model_dump(), "status": "failed"})
    with pytest.raises(ValidationError, match="canonical absolute POSIX path"):
        ScanArtifact(
            scanner="syft",
            artifact_type="sbom",
            format="cyclonedx-json",
            path="/data//artifact.json",
            size_bytes=1,
            sha256="c" * 64,
        )


def test_run_id_is_idempotent_but_cannot_be_rebound_and_capacity_is_one() -> None:
    entered = threading.Event()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        entered.set()
        while True:
            control.checkpoint()
            control.cancel_event.wait(0.01)

    registry = _registry(execute)
    request = _request()
    first = registry.start(request)
    assert first.run_id == request.run_id
    assert len(first.request_digest) == 64
    assert entered.wait(1)
    assert registry.start(request).run_id == request.run_id

    rebound = request.model_copy(update={"scan_id": 2})
    with pytest.raises(RunConflictError, match="different request"):
        registry.start(rebound)
    with pytest.raises(RunCapacityError, match="capacity"):
        registry.start(_request())
    with pytest.raises(RunConflictError, match="different request"):
        registry.cancel(request.run_id, request_digest="0" * 64)
    assert registry.get(request.run_id).status == "running"

    acknowledged = registry.cancel(request.run_id, request_digest=first.request_digest)
    assert acknowledged.status in {"cancelling", "cancelled"}
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "cancelled"
    assert terminal.error_code == "cancelled"
    assert terminal.result_manifest is None
    assert registry.cancel(request.run_id).status == "cancelled"


def test_hostile_concurrent_starts_admit_exactly_one_execution() -> None:
    release = threading.Event()
    executor_calls = 0
    executor_lock = threading.Lock()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        nonlocal executor_calls
        with executor_lock:
            executor_calls += 1
        while not release.wait(0.01):
            control.checkpoint()
        return _result()

    registry = _registry(execute)
    barrier = threading.Barrier(8)

    def start_one() -> UUID | None:
        barrier.wait()
        request = _request()
        try:
            return registry.start(request).run_id
        except RunCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(lambda _index: start_one(), range(8)))
    accepted = [run_id for run_id in admitted if run_id is not None]
    assert len(accepted) == 1
    assert executor_calls == 1
    release.set()
    assert registry.wait_for_terminal(accepted[0], 2).status == "completed"


def test_concurrent_retries_of_one_run_id_execute_only_once() -> None:
    release = threading.Event()
    calls = 0
    calls_lock = threading.Lock()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        nonlocal calls
        with calls_lock:
            calls += 1
        while not release.wait(0.01):
            control.checkpoint()
        return _result()

    registry = _registry(execute)
    request = _request()
    barrier = threading.Barrier(8)

    def retry() -> UUID:
        barrier.wait()
        return registry.start(request).run_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        returned = list(pool.map(lambda _index: retry(), range(8)))
    assert returned == [request.run_id] * 8
    assert calls == 1
    release.set()
    completed = registry.wait_for_terminal(request.run_id, 2)
    assert completed.result_manifest is not None and completed.result_available


def test_replacement_registry_accepts_the_same_stable_run_id_after_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executions: list[int] = []

    def execute(request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        executions.append(request.scan_id)
        return _result()

    request = _request(scan_id=73)
    first_process = _registry(execute)
    monkeypatch.setattr(scanner, "run_registry", first_process)
    assert scanner.start_run(request).run_id == request.run_id
    assert first_process.wait_for_terminal(request.run_id, 2).status == "completed"
    assert first_process.shutdown()

    replacement_process = _registry(execute)
    monkeypatch.setattr(scanner, "run_registry", replacement_process)
    with pytest.raises(HTTPException) as missing_after_restart:
        scanner.get_run(request.run_id)
    assert missing_after_restart.value.status_code == 404

    # This is the worker reconciliation contract: a 404 from the replacement
    # scanner permits POSTing the same durable run ID and immutable payload.
    assert scanner.start_run(request).run_id == request.run_id
    assert replacement_process.wait_for_terminal(request.run_id, 2).status == "completed"
    assert executions == [73, 73]


def test_reexecution_canonicalizes_arbitrary_finding_and_artifact_order(
    tmp_path: Path,
) -> None:
    first_finding = Finding(
        scanner="opengrep",
        rule_id="fixture-rule",
        severity="high",
        file_path="source.py",
        start_line=7,
        start_column=3,
        end_line=7,
        end_column=9,
        message="first",
        fingerprint="a" * 64,
    )
    second_finding = first_finding.model_copy(
        update={"message": "second", "fingerprint": "b" * 64}
    )
    first_artifact = ScanArtifact(
        scanner="syft",
        artifact_type="sbom",
        format="cyclonedx-json",
        path="/data/artifacts/a.cyclonedx.json",
        size_bytes=101,
        sha256="a" * 64,
    )
    second_artifact = first_artifact.model_copy(
        update={
            "path": "/data/artifacts/b.cyclonedx.json",
            "size_bytes": 202,
            "sha256": "b" * 64,
        }
    )
    executions = 0

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        nonlocal executions
        executions += 1
        findings = (
            [second_finding, first_finding]
            if executions == 1
            else [first_finding, second_finding]
        )
        artifacts = (
            [second_artifact, first_artifact]
            if executions == 1
            else [first_artifact, second_artifact]
        )
        return ScanResponse(
            status="completed",
            findings=findings,
            artifacts=artifacts,
            summary={
                "findings_total": 2,
                "severity_counts": {"high": 2},
                "scanner_counts": {"opengrep": 2},
                "artifacts": [
                    artifact.model_dump(mode="json") for artifact in artifacts
                ],
            },
        )

    request = _request(scan_id=731)
    result_dir = tmp_path / "scratch" / "run-results"
    first_process = _registry(execute, result_dir=result_dir)
    try:
        first_process.start(request)
        first_state = first_process.wait_for_terminal(request.run_id, 2)
        assert first_state.result_manifest is not None
        first_manifest = first_state.result_manifest.model_dump(mode="json")
        first_page = first_process.page(
            request.run_id,
            RunFindingPageRequest(request_digest=first_state.request_digest),
        ).model_dump(mode="json")
        assert first_process.shutdown()

        replacement = _registry(execute, result_dir=result_dir)
        try:
            replacement.start(request)
            second_state = replacement.wait_for_terminal(request.run_id, 2)
            assert second_state.result_manifest is not None
            second_manifest = second_state.result_manifest.model_dump(mode="json")
            second_page = replacement.page(
                request.run_id,
                RunFindingPageRequest(request_digest=second_state.request_digest),
            ).model_dump(mode="json")

            assert first_manifest == second_manifest
            assert first_page == second_page
            assert [item["fingerprint"] for item in second_page["items"]] == [
                "a" * 64,
                "b" * 64,
            ]
            assert [
                artifact["sha256"] for artifact in second_manifest["artifacts"]
            ] == ["a" * 64, "b" * 64]
            assert second_manifest["summary"]["artifacts"] == second_manifest["artifacts"]
        finally:
            replacement.shutdown()
    finally:
        first_process.shutdown()


def test_startup_reconciliation_removes_abandoned_temp_and_sealed_results(
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    first = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    request = _request(scan_id=74)
    first.start(request)
    completed = first.wait_for_terminal(request.run_id, 2)
    assert completed.result_manifest is not None
    sealed = result_dir / f"{request.run_id.hex}-{completed.result_manifest.result_digest}.jsonl"
    assert sealed.is_file()
    abandoned_temp = result_dir / f".{uuid4().hex}.{'a' * 16}.tmp"
    abandoned_temp.touch(mode=0o600)
    os.chmod(abandoned_temp, 0o600)
    _abandon_registry_lock(first)

    replacement = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    assert not sealed.exists()
    assert not abandoned_temp.exists()
    assert sorted(path.name for path in result_dir.iterdir()) == [".registry.lock"]
    replacement.start(request)
    reposted = replacement.wait_for_terminal(request.run_id, 2)
    assert reposted.status == "completed" and reposted.result_available


def test_startup_reconciliation_removes_abandoned_max_shape_placeholder(
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    first = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    abandoned = result_dir / f"{uuid4().hex}-{'b' * 64}.jsonl"
    with abandoned.open("wb") as handle:
        handle.truncate(312 * 1024 * 1024)
    os.chmod(abandoned, 0o600)
    assert abandoned.stat().st_size == 312 * 1024 * 1024
    _abandon_registry_lock(first)

    replacement = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    assert not abandoned.exists()
    request = _request(scan_id=75)
    replacement.start(request)
    assert replacement.wait_for_terminal(request.run_id, 2).status == "completed"


@pytest.mark.parametrize(
    "unsafe_kind",
    ["unknown", "symlink", "directory", "hardlink", "wrong_mode"],
)
def test_startup_reconciliation_rejects_unknown_or_unsafe_entries(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    first = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    candidate = result_dir / f"{uuid4().hex}-{'c' * 64}.jsonl"
    if unsafe_kind == "unknown":
        candidate = result_dir / "unexpected.txt"
        candidate.touch(mode=0o600)
    elif unsafe_kind == "symlink":
        target = tmp_path / "outside"
        target.touch()
        candidate.symlink_to(target)
    elif unsafe_kind == "directory":
        candidate.mkdir(mode=0o600)
    elif unsafe_kind == "hardlink":
        target = tmp_path / "outside"
        target.touch(mode=0o600)
        os.chmod(target, 0o600)
        os.link(target, candidate)
    else:
        candidate.touch(mode=0o644)
        os.chmod(candidate, 0o644)
    _abandon_registry_lock(first)

    with pytest.raises(RunResultStorageError, match="unknown|unsafe"):
        _registry(lambda _request, _control: _result(), result_dir=result_dir)
    assert candidate.exists() or candidate.is_symlink()


def test_concurrent_registry_is_refused_without_purging_live_result(tmp_path: Path) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    live = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    request = _request(scan_id=76)
    live.start(request)
    completed = live.wait_for_terminal(request.run_id, 2)
    assert completed.result_manifest is not None
    sealed = result_dir / f"{request.run_id.hex}-{completed.result_manifest.result_digest}.jsonl"
    assert sealed.is_file()

    with pytest.raises(RunCapacityError, match="already owned"):
        _registry(lambda _request, _control: _result(), result_dir=result_dir)
    assert sealed.is_file()
    assert live.get(request.run_id).result_available

    assert live.shutdown()
    replacement = _registry(lambda _request, _control: _result(), result_dir=result_dir)
    with pytest.raises(RunCapacityError, match="shut down"):
        live.start(_request(scan_id=77))
    replacement_request = _request(scan_id=78)
    replacement.start(replacement_request)
    assert replacement.wait_for_terminal(replacement_request.run_id, 2).status == "completed"


def test_cancel_wins_a_completion_race() -> None:
    entered = threading.Event()
    release = threading.Event()

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        entered.set()
        assert release.wait(2)
        return _result()

    registry = _registry(execute)
    request = _request()
    registry.start(request)
    assert entered.wait(1)
    assert registry.cancel(request.run_id).status == "cancelling"
    release.set()
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "cancelled"
    assert terminal.result_manifest is None


def test_digest_bound_discard_rejects_noncompleted_run_without_cancelling() -> None:
    entered = threading.Event()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        entered.set()
        while True:
            control.cancel_event.wait(0.01)
            control.checkpoint()

    registry = _registry(execute)
    request = _request()
    started = registry.start(request)
    assert entered.wait(1)
    with pytest.raises(RunConflictError, match="completed immutable evidence"):
        registry.cancel(
            request.run_id,
            request_digest=started.request_digest,
            result_digest="0" * 64,
        )
    assert registry.get(request.run_id).status == "running"
    registry.cancel(request.run_id, request_digest=started.request_digest)
    assert registry.wait_for_terminal(request.run_id, 2).status == "cancelled"


def test_request_bound_terminal_cleanup_releases_stable_run_id_for_reexecution(
    tmp_path: Path,
) -> None:
    calls = 0

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RunCapacityError("fixture result capacity")
        return _result()

    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(execute, result_dir=result_dir)
    request = _request(scan_id=79)
    started = registry.start(request)
    failed = registry.wait_for_terminal(request.run_id, 2)
    assert failed.status == "failed" and failed.error_code == "result_capacity"
    assert failed.result_manifest is None and not failed.result_available

    with pytest.raises(RunConflictError, match="different request"):
        registry.cancel(request.run_id, request_digest="0" * 64)
    assert registry.get(request.run_id) == failed

    removed = registry.cancel(request.run_id, request_digest=started.request_digest)
    assert removed == failed
    with pytest.raises(RunNotFoundError):
        registry.cancel(request.run_id, request_digest=started.request_digest)
    assert sorted(path.name for path in result_dir.iterdir()) == [".registry.lock"]

    restarted = registry.start(request)
    assert restarted.request_digest == started.request_digest
    completed = registry.wait_for_terminal(request.run_id, 2)
    assert completed.status == "completed" and completed.result_available
    assert calls == 2


def test_request_bound_cancelled_cleanup_is_atomic_under_concurrent_retries() -> None:
    entered = threading.Event()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        entered.set()
        while True:
            control.cancel_event.wait(0.01)
            control.checkpoint()

    registry = _registry(execute)
    request = _request(scan_id=80)
    started = registry.start(request)
    assert entered.wait(1)
    registry.cancel(request.run_id)
    assert registry.wait_for_terminal(request.run_id, 2).status == "cancelled"
    request_digest = started.request_digest

    barrier = threading.Barrier(8)

    def discard() -> str:
        barrier.wait()
        try:
            return registry.cancel(request.run_id, request_digest=request_digest).status
        except RunNotFoundError:
            return "missing"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: discard(), range(8)))
    assert outcomes.count("cancelled") == 1
    assert outcomes.count("missing") == 7


def test_cancel_while_waiting_for_publication_lock_never_seals_result() -> None:
    registry = _registry(lambda _request, _control: _result())
    request = _request()
    registry._publication_lock.acquire()
    try:
        registry.start(request)
        deadline = time.monotonic() + 1
        while registry.get(request.run_id).status == "queued" and time.monotonic() < deadline:
            time.sleep(0.005)
        registry.cancel(request.run_id)
    finally:
        registry._publication_lock.release()
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "cancelled"
    assert terminal.result_manifest is None and not terminal.result_available


def test_overall_deadline_is_independent_and_terminal() -> None:
    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        while True:
            control.cancel_event.wait(0.005)
            control.checkpoint()

    registry = _registry(execute, deadline_seconds=0.03)
    request = _request()
    registry.start(request)
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "failed"
    assert terminal.error_code == "deadline_exceeded"
    assert terminal.result_manifest is None


@pytest.mark.parametrize("interrupt", ["cancel", "deadline"])
@pytest.mark.parametrize("interrupt_after", [1, 3])
def test_scan_redaction_stops_at_interruption_without_publishing_or_leaking_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: str,
    interrupt_after: int,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scratch = tmp_path / "scratch"
    monkeypatch.setattr(scanner, "settings", SimpleNamespace(
        allowed_root_list=[str(repo)], max_files=100, max_file_bytes=1024 * 1024,
        artifact_dir=str(tmp_path / "artifacts"), scratch_dir=str(scratch),
        source_snapshot_dir=str(tmp_path / "snapshots"), tool_cache_dir=str(tmp_path / "cache"),
        tool_lock_path=str(tmp_path / "tools.lock"), rules_lock_path=str(tmp_path / "rules.lock"),
        validate_storage_boundaries=lambda: None,
    ))
    findings = _many_findings_result(3).findings
    monkeypatch.setattr(scanner, "_scan_files", lambda *_args: findings)
    monkeypatch.setattr(scanner, "scanner_runtime_context", lambda **_kwargs: SimpleNamespace(
        readiness_by_id={}, runtime_by_id={}, tools=None,
    ))
    # Advance only ExecutionControl's clock at a known redaction boundary;
    # registry scheduling and the test's wait retain their real monotonic clock.
    offset = [0.0]
    monkeypatch.setattr(external, "time", SimpleNamespace(
        monotonic=lambda: time.monotonic() + offset[0], time=time.time, sleep=time.sleep,
    ))
    control_seen: list[ExecutionControl] = []
    redacted: list[str] = []
    executor_returned = threading.Event()
    original_redactor = scanner.redact_finding

    def redact_then_interrupt(finding: Finding) -> Finding:
        result = original_redactor(finding)
        redacted.append(finding.fingerprint)
        if len(redacted) == interrupt_after:
            if interrupt == "cancel":
                control_seen[0].cancel_event.set()
            else:
                offset[0] = 60.0
        return result

    def execute(request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        control_seen.append(control)
        result = scanner._execute_scan(request, control)
        executor_returned.set()
        return result

    monkeypatch.setattr(scanner, "redact_finding", redact_then_interrupt)
    registry = _registry(execute, result_dir=tmp_path / "recovery" / "run-results")
    request = _request(repo_path=str(repo))
    try:
        registry.start(request)
        terminal = registry.wait_for_terminal(request.run_id, 2)
        assert terminal.status == ("cancelled" if interrupt == "cancel" else "failed")
        assert terminal.error_code == ("cancelled" if interrupt == "cancel" else "deadline_exceeded")
        assert not terminal.result_available and terminal.result_manifest is None
        assert len(redacted) == interrupt_after
        assert not executor_returned.is_set()
        assert list(scratch.iterdir()) == []
        with pytest.raises(RunResultUnavailableError):
            registry.page(request.run_id, RunFindingPageRequest(
                request_digest=terminal.request_digest,
            ))
    finally:
        assert registry.shutdown()


def test_execution_failure_is_fixed_and_safe_in_recovery_state() -> None:
    fixture_credential = "fixture-run-control-secret-value"
    private_source = "/Users/private-owner/projects/credential-bearing-source"

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        raise RuntimeError(
            f"source entry escapes {private_source}; "
            f"Authorization: Bearer {fixture_credential}; password={fixture_credential}"
        )

    registry = _registry(execute)
    request = _request(repo_path="/fixture/source-must-not-be-reflected")
    registry.start(request)
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "failed"
    assert terminal.error_code == "execution_failed"
    assert terminal.error_detail == "scanner execution failed"
    assert fixture_credential not in (terminal.error_detail or "")
    assert private_source not in (terminal.error_detail or "")
    listed_json = registry.list()[0].model_dump_json()
    assert fixture_credential not in listed_json
    assert private_source not in listed_json
    assert request.repo_path not in listed_json
    assert '"result_manifest":null' in listed_json


@pytest.mark.parametrize(
    ("target_kind", "target_path"),
    (("directory", "infra"), ("file", "infra/main.tf")),
)
def test_capture_storage_failure_is_typed_safe_and_cleans_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
    target_path: str,
) -> None:
    repo = tmp_path / "repo"
    selected = repo / "infra" / "main.tf"
    selected.parent.mkdir(parents=True)
    selected.write_text('resource "fixture" "selected" {}\n', encoding="utf-8")
    scratch_root = tmp_path / "scratch"
    private_destination = scratch_root / "must-not-appear-in-terminal-state"
    attempted_destinations: list[Path] = []
    original_open = Path.open

    def fail_selected_source_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
        if mode == "xb" and "selected-source" in path.parts and path.name == "main.tf":
            attempted_destinations.append(path)
            raise OSError(errno.ENOSPC, "fixture storage full", private_destination)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_selected_source_open)
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            max_files=100,
            max_file_bytes=1024 * 1024,
            artifact_dir=str(tmp_path / "artifacts"),
            tool_lock_path=str(tmp_path / "tools.lock"),
            rules_lock_path=str(tmp_path / "rules.lock"),
            tool_cache_dir=str(tmp_path / "cache"),
            external_tool_timeout=30,
        ),
    )
    monkeypatch.setattr(
        scanner,
        "scanner_runtime_context",
        lambda **_kwargs: SimpleNamespace(
            readiness_by_id={},
            tools=None,
            runtime_by_id={},
        ),
    )

    def execute(request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        with request_scratch_directory(str(scratch_root), request.scan_id) as request_scratch:
            return scanner._execute_scan_in_scratch(
                request,
                control,
                time.monotonic(),
                repo,
                request_scratch,
            )

    registry = _registry(execute)
    request = RunStartRequest(
        run_id=uuid4(),
        scan_id=81,
        repo_path=str(repo),
        target_kind=target_kind,
        target_path=target_path,
        enabled_tools=["opengrep"],
    )
    registry.start(request)
    terminal = registry.wait_for_terminal(request.run_id, 2)

    assert attempted_destinations
    assert terminal.status == "failed"
    assert terminal.error_code == "capture_storage_unavailable"
    assert terminal.error_detail == "scanner could not write the private selected-source capture"
    assert str(private_destination) not in terminal.model_dump_json()
    assert terminal.result_manifest is None and not terminal.result_available
    assert list(scratch_root.iterdir()) == []


@pytest.mark.parametrize(
    "failure",
    (
        "unauthorized_root",
        "deleted_nested_target",
        "snapshot_digest_unavailable",
        "snapshot_digest_mismatch",
    ),
)
def test_source_boundary_failure_is_typed_safe_and_cleans_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    repo = (tmp_path / "outside") if failure == "unauthorized_root" else (allowed / "repo")
    selected = repo / "infra" / "main.tf"
    selected.parent.mkdir(parents=True)
    selected.write_text('resource "fixture" "selected" {}\n', encoding="utf-8")
    scratch_root = tmp_path / "scratch"
    source_snapshot_root = tmp_path / "source-snapshots"
    snapshot_digest = "a" * 64 if failure.startswith("snapshot_digest_") else None
    if failure == "snapshot_digest_mismatch":
        (source_snapshot_root / "generations" / snapshot_digest / "source").mkdir(parents=True)
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(allowed)],
            max_files=100,
            max_file_bytes=1024 * 1024,
            artifact_dir=str(tmp_path / "artifacts"),
            source_snapshot_dir=str(source_snapshot_root),
            scratch_dir=str(scratch_root),
            tool_cache_dir=str(tmp_path / "cache"),
            tool_lock_path=str(tmp_path / "tools.lock"),
            rules_lock_path=str(tmp_path / "rules.lock"),
            external_tool_timeout=30,
            validate_storage_boundaries=lambda: None,
        ),
    )

    if failure == "deleted_nested_target":
        original_open_repository = scanner._open_authorized_repository
        target_deleted = False

        def open_then_delete_target(source_repo: Path, subject: str) -> int:
            nonlocal target_deleted
            descriptor = original_open_repository(source_repo, subject)
            if subject == "selected directory" and not target_deleted:
                selected.unlink()
                selected.parent.rmdir()
                target_deleted = True
            return descriptor

        monkeypatch.setattr(scanner, "_open_authorized_repository", open_then_delete_target)

    registry = _registry(scanner._execute_scan)
    request = RunStartRequest(
        run_id=uuid4(),
        scan_id=82,
        repo_path=str(repo),
        target_kind="directory",
        target_path="infra",
        enabled_tools=["sast-lite"],
        source_snapshot_digest=snapshot_digest,
    )
    registry.start(request)
    terminal = registry.wait_for_terminal(request.run_id, 2)
    terminal_json = terminal.model_dump_json()

    assert terminal.status == "failed"
    assert terminal.error_code == "source_boundary_invalid"
    assert terminal.error_detail == "scanner source boundary validation failed"
    assert str(repo) not in terminal_json
    assert str(selected) not in terminal_json
    assert str(source_snapshot_root) not in terminal_json
    assert terminal.result_manifest is None and not terminal.result_available
    assert not scratch_root.exists() or list(scratch_root.iterdir()) == []


def test_terminal_results_are_byte_and_record_bounded() -> None:
    oversized_result = _result()
    oversized_result.findings.append(
        oversized_result.findings[0].model_copy(update={"fingerprint": "e" * 64})
    )
    oversized_result.summary = {
        "findings_total": 2,
        "severity_counts": {"high": 2},
        "scanner_counts": {"sast-lite": 2},
        "artifacts": [],
    }
    oversized = _registry(lambda _request, _control: oversized_result, max_findings=1)
    oversized_request = _request()
    oversized.start(oversized_request)
    rejected = oversized.wait_for_terminal(oversized_request.run_id, 2)
    assert rejected.status == "failed"
    assert rejected.error_code == "result_too_large"
    assert rejected.result_manifest is None

    bounded = _registry(lambda _request, _control: _result(), max_terminal_records=2)
    requests = [_request(scan_id=index) for index in range(1, 4)]
    for request in requests:
        bounded.start(request)
        state = bounded.wait_for_terminal(request.run_id, 2)
        assert state.status == "completed" and state.result_manifest is not None
        bounded.acknowledge(
            request.run_id,
            RunResultAckRequest(
                request_digest=state.request_digest,
                result_digest=state.result_manifest.result_digest,
            ),
        )
    with pytest.raises(RunNotFoundError):
        bounded.get(requests[0].run_id)
    assert [state.run_id for state in bounded.list()] == [requests[1].run_id, requests[2].run_id]
    assert all(state.result_manifest is None for state in bounded.list())
    assert bounded.get(requests[2].run_id).result_manifest is not None

    expiring = _registry(lambda _request, _control: _result(), retention_seconds=0.03)
    expiring_request = _request()
    expiring.start(expiring_request)
    assert expiring.wait_for_terminal(expiring_request.run_id, 2).status == "completed"
    time.sleep(0.04)
    with pytest.raises(RunNotFoundError):
        expiring.get(expiring_request.run_id)


def test_paged_result_is_digest_bound_and_acknowledgement_is_idempotent() -> None:
    registry = _registry(lambda _request, _control: _many_findings_result(257, message_size=128))
    request = _request()
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 5)
    assert state.status == "completed" and state.result_manifest is not None, state.model_dump()
    assert state.result_available
    assert state.result_manifest.findings_total == 257
    assert registry.list()[0].result_manifest is None

    cursor = None
    observed: list[Finding] = []
    reconstructed = hashlib.sha256()
    while True:
        page = registry.page(
            request.run_id,
            RunFindingPageRequest(
                request_digest=state.request_digest,
                cursor=cursor,
                limit=128,
            ),
        )
        body = b"".join(
            canonical_json_bytes(item.model_dump(mode="json")) + b"\n"
            for item in page.items
        )
        assert page.page_digest == hashlib.sha256(body).hexdigest()
        assert page.items_bytes == len(body)
        reconstructed.update(body)
        observed.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert len(observed) == 257
    assert reconstructed.hexdigest() == state.result_manifest.findings_digest

    first = registry.page(
        request.run_id,
        RunFindingPageRequest(request_digest=state.request_digest, limit=1),
    )
    assert first.next_cursor is not None
    payload_token, signature_token = first.next_cursor.split(".", 1)
    hostile_cursor = f"{payload_token}.{'A' if signature_token[0] != 'A' else 'B'}{signature_token[1:]}"
    with pytest.raises(RunCursorError):
        registry.page(
            request.run_id,
            RunFindingPageRequest(
                request_digest=state.request_digest,
                cursor=hostile_cursor,
                limit=1,
            ),
        )

    ack = RunResultAckRequest(
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    assert registry.acknowledge(request.run_id, ack).acknowledged
    assert registry.acknowledge(request.run_id, ack).acknowledged
    tombstone = registry.get(request.run_id)
    assert tombstone.result_manifest == state.result_manifest
    assert tombstone.result_available is False
    with pytest.raises(RunResultUnavailableError):
        registry.page(
            request.run_id,
            RunFindingPageRequest(request_digest=state.request_digest),
        )


def test_ack_unlink_failure_preserves_evidence_and_capacity_until_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    max_run_bytes = 4 * 1024 * 1024
    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(
        lambda _request, _control: _many_findings_result(100),
        result_dir=result_dir,
        max_run_bytes=max_run_bytes,
        max_total_bytes=max_run_bytes + 64 * 1024,
    )
    request = _request(scan_id=86)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    ack = RunResultAckRequest(
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    with registry._condition:
        record = registry._records[request.run_id]
        filename = record.result_file
        result_file_bytes = record.result_file_bytes
        retained_before = registry._retained_result_bytes
    assert filename is not None
    assert result_file_bytes > 64 * 1024

    original_unlink = os.unlink

    def reject_sealed_unlink(path, *args, **kwargs):
        if path == filename:
            raise OSError("fixture unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", reject_sealed_unlink)
    with pytest.raises(RunResultStorageError, match="could not be removed"):
        registry.acknowledge(request.run_id, ack)

    assert (result_dir / filename).is_file()
    assert registry.get(request.run_id).result_available
    with registry._condition:
        record = registry._records[request.run_id]
        assert record.result_file == filename
        assert record.result_file_bytes == result_file_bytes
        assert registry._retained_result_bytes == retained_before

    blocked = _request(scan_id=87)
    with pytest.raises(RunCapacityError, match="result retention capacity"):
        registry.start(blocked)

    monkeypatch.setattr(os, "unlink", original_unlink)
    assert registry.acknowledge(request.run_id, ack).acknowledged
    with registry._condition:
        record = registry._records[request.run_id]
        assert record.result_file is None
        assert record.result_file_bytes == 0
        assert registry._retained_result_bytes == retained_before - result_file_bytes
        retained_after = registry._retained_result_bytes
    assert not (result_dir / filename).exists()
    assert registry.acknowledge(request.run_id, ack).acknowledged
    assert registry._retained_result_bytes == retained_after

    registry.start(blocked)
    assert registry.wait_for_terminal(blocked.run_id, 2).status == "completed"


def test_ack_fsync_failure_retries_pending_sync_and_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    max_run_bytes = 4 * 1024 * 1024
    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(
        lambda _request, _control: _many_findings_result(100),
        result_dir=result_dir,
        max_run_bytes=max_run_bytes,
        max_total_bytes=max_run_bytes + 64 * 1024,
    )
    request = _request(scan_id=88)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    ack = RunResultAckRequest(
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    with registry._condition:
        record = registry._records[request.run_id]
        filename = record.result_file
        result_file_bytes = record.result_file_bytes
        retained_before = registry._retained_result_bytes
    assert filename is not None
    assert result_file_bytes > 64 * 1024

    original_fsync = os.fsync
    fsync_calls = 0

    def reject_first_directory_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("fixture directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", reject_first_directory_fsync)
    with pytest.raises(RunResultStorageError, match="could not be made durable"):
        registry.acknowledge(request.run_id, ack)

    assert not (result_dir / filename).exists()
    assert not registry.get(request.run_id).result_available
    with registry._condition:
        record = registry._records[request.run_id]
        assert record.result_file is None
        assert record.result_file_bytes == 0
        assert record.result_cleanup_sync_pending
        assert registry._retained_result_bytes == retained_before - result_file_bytes
        retained_after_unlink = registry._retained_result_bytes

    admitted = _request(scan_id=90)
    registry.start(admitted)
    assert registry.acknowledge(request.run_id, ack).acknowledged
    with registry._condition:
        record = registry._records[request.run_id]
        assert not record.result_cleanup_sync_pending
        assert registry._retained_result_bytes >= retained_after_unlink
    fsync_calls_after_retry = fsync_calls
    assert registry.acknowledge(request.run_id, ack).acknowledged
    assert fsync_calls == fsync_calls_after_retry
    assert registry.wait_for_terminal(admitted.run_id, 2).status == "completed"


def test_pending_cleanup_sync_does_not_wedge_retention_or_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(
        lambda _request, _control: _result(),
        result_dir=result_dir,
        retention_seconds=0.03,
    )
    request = _request(scan_id=91)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    ack = RunResultAckRequest(
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    with registry._condition:
        record = registry._records[request.run_id]
        result_file_bytes = record.result_file_bytes
        manifest_bytes = record.result_manifest_bytes
        retained_before = registry._retained_result_bytes

    original_fsync = os.fsync

    def reject_directory_fsync(_descriptor: int) -> None:
        raise OSError("fixture persistent directory fsync failure")

    monkeypatch.setattr(os, "fsync", reject_directory_fsync)
    with pytest.raises(RunResultStorageError, match="could not be made durable"):
        registry.acknowledge(request.run_id, ack)
    with pytest.raises(RunResultStorageError, match="could not be made durable"):
        registry.acknowledge(request.run_id, ack)
    with registry._condition:
        record = registry._records[request.run_id]
        assert record.result_cleanup_sync_pending
        assert registry._retained_result_bytes == retained_before - result_file_bytes
        assert registry._retained_result_bytes == manifest_bytes

    time.sleep(0.04)
    with pytest.raises(RunNotFoundError):
        registry.get(request.run_id)
    assert registry.list() == []
    assert registry._retained_result_bytes == 0

    monkeypatch.setattr(os, "fsync", original_fsync)
    replacement = _request(scan_id=92)
    registry.start(replacement)
    assert registry.wait_for_terminal(replacement.run_id, 2).status == "completed"


def test_signed_cursor_must_be_aligned_to_a_sealed_item_boundary() -> None:
    registry = _registry(lambda _request, _control: _many_findings_result(2, message_size=128))
    request = _request()
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    with registry._condition:
        record = registry._records[request.run_id]
        misaligned = registry._encode_cursor(record, 2, 1)
    with pytest.raises(RunCursorError, match="aligned"):
        registry.page(
            request.run_id,
            RunFindingPageRequest(
                request_digest=state.request_digest,
                cursor=misaligned,
                limit=1,
            ),
        )


def test_terminal_cancel_discards_only_digest_bound_evidence_and_keeps_tombstone() -> None:
    registry = _registry(lambda _request, _control: _result())
    request = _request()
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.status == "completed" and state.result_manifest is not None
    assert state.result_available

    # A terminal DELETE without an immutable result binding is a status
    # reconciliation only; it must not discard recoverable evidence.
    assert registry.cancel(request.run_id).result_available
    assert registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
    ).result_available
    with pytest.raises(RunConflictError):
        registry.cancel(
            request.run_id,
            request_digest=state.request_digest,
            result_digest="0" * 64,
        )
    with pytest.raises(RunConflictError, match="requires"):
        registry.cancel(
            request.run_id,
            result_digest=state.result_manifest.result_digest,
        )
    assert registry.get(request.run_id).result_available

    discarded = registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    assert discarded.status == "completed"
    assert discarded.result_manifest == state.result_manifest
    assert discarded.result_available is False
    # Retrying the same discard after an uncertain response is safe.
    assert not registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    ).result_available
    with pytest.raises(RunResultUnavailableError):
        registry.page(
            request.run_id,
            RunFindingPageRequest(request_digest=state.request_digest),
        )


def test_digest_bound_discard_failure_is_retryable_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(
        lambda _request, _control: _result(),
        result_dir=result_dir,
    )
    request = _request(scan_id=89)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    with registry._condition:
        record = registry._records[request.run_id]
        filename = record.result_file
        result_file_bytes = record.result_file_bytes
        retained_before = registry._retained_result_bytes
    assert filename is not None

    original_unlink = os.unlink

    def reject_sealed_unlink(path, *args, **kwargs):
        if path == filename:
            raise OSError("fixture discard unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", reject_sealed_unlink)
    with pytest.raises(RunResultStorageError, match="could not be removed"):
        registry.cancel(
            request.run_id,
            request_digest=state.request_digest,
            result_digest=state.result_manifest.result_digest,
        )
    assert (result_dir / filename).is_file()
    assert registry.get(request.run_id).result_available
    assert registry._retained_result_bytes == retained_before

    monkeypatch.setattr(os, "unlink", original_unlink)
    discarded = registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    assert discarded.status == "completed"
    assert discarded.result_available is False
    assert registry._retained_result_bytes == retained_before - result_file_bytes
    retained_after = registry._retained_result_bytes
    assert not (result_dir / filename).exists()

    retried = registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    assert retried.result_available is False
    assert registry._retained_result_bytes == retained_after


def test_digest_bound_discard_retries_pending_directory_sync(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(
        lambda _request, _control: _result(),
        result_dir=result_dir,
    )
    request = _request(scan_id=93)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None
    with registry._condition:
        record = registry._records[request.run_id]
        filename = record.result_file
        result_file_bytes = record.result_file_bytes
        retained_before = registry._retained_result_bytes
    assert filename is not None

    original_fsync = os.fsync
    fsync_calls = 0

    def reject_first_directory_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("fixture discard directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", reject_first_directory_fsync)
    with pytest.raises(RunResultStorageError, match="could not be made durable"):
        registry.cancel(
            request.run_id,
            request_digest=state.request_digest,
            result_digest=state.result_manifest.result_digest,
        )
    assert not (result_dir / filename).exists()
    with registry._condition:
        record = registry._records[request.run_id]
        assert record.result_file is None
        assert record.result_cleanup_sync_pending
        assert registry._retained_result_bytes == retained_before - result_file_bytes

    discarded = registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    )
    assert discarded.result_available is False
    with registry._condition:
        assert not registry._records[request.run_id].result_cleanup_sync_pending
        retained_after = registry._retained_result_bytes
    fsync_calls_after_retry = fsync_calls

    assert not registry.cancel(
        request.run_id,
        request_digest=state.request_digest,
        result_digest=state.result_manifest.result_digest,
    ).result_available
    assert fsync_calls == fsync_calls_after_retry
    assert registry._retained_result_bytes == retained_after


def test_unacknowledged_terminal_record_reserves_slot_until_acknowledged() -> None:
    registry = _registry(
        lambda _request, _control: _result(),
        max_terminal_records=1,
    )
    first = _request(scan_id=1)
    registry.start(first)
    first_state = registry.wait_for_terminal(first.run_id, 2)
    assert first_state.status == "completed" and first_state.result_manifest is not None
    assert first_state.result_available

    second = _request(scan_id=2)
    with pytest.raises(RunCapacityError, match="terminal-result capacity"):
        registry.start(second)
    assert registry.get(first.run_id).result_available

    registry.acknowledge(
        first.run_id,
        RunResultAckRequest(
            request_digest=first_state.request_digest,
            result_digest=first_state.result_manifest.result_digest,
        ),
    )
    registry.start(second)
    assert registry.wait_for_terminal(second.run_id, 2).status == "completed"
    with pytest.raises(RunNotFoundError):
        registry.get(first.run_id)


def test_result_manifest_digest_recipe_is_canonical_and_excludes_itself() -> None:
    summary = {
        "findings_total": 1,
        "severity_counts": {"high": 1},
        "scanner_counts": {"sast-lite": 1},
        "artifacts": [],
    }
    fields = {
        "schema_version": 1,
        "status": "completed",
        "findings_digest": "a" * 64,
        "findings_total": 1,
        "findings_bytes": 123,
        "page_count": 1,
        "page_limit": 128,
        "summary": summary,
        "artifacts": [],
    }
    expected = hashlib.sha256(canonical_json_bytes(fields)).hexdigest()
    assert result_manifest_digest(
        status="completed",
        findings_digest="a" * 64,
        findings_total=1,
        findings_bytes=123,
        page_count=1,
        summary=summary,
        artifacts=[],
    ) == expected


def test_result_transport_guarantees_10000_production_shaped_findings() -> None:
    registry = _registry(
        lambda _request, _control: _many_findings_result(10_000),
        deadline_seconds=60,
        retention_seconds=60,
    )
    request = _request()
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 30)
    assert state.status == "completed" and state.result_manifest is not None, state.model_dump()
    manifest = state.result_manifest
    assert manifest.findings_total == 10_000
    assert manifest.findings_bytes < 336 * 1024 * 1024
    assert len(state.model_dump_json().encode("utf-8")) < 1024 * 1024

    cursor = None
    count = 0
    pages = 0
    digest = hashlib.sha256()
    while True:
        page = registry.page(
            request.run_id,
            RunFindingPageRequest(
                request_digest=state.request_digest,
                cursor=cursor,
            ),
        )
        encoded = b"".join(
            canonical_json_bytes(item.model_dump(mode="json")) + b"\n"
            for item in page.items
        )
        assert len(page.model_dump_json().encode("utf-8")) <= 4 * 1024 * 1024
        digest.update(encoded)
        count += len(page.items)
        pages += 1
        cursor = page.next_cursor
        if cursor is None:
            break
    assert count == 10_000
    assert pages == manifest.page_count
    assert digest.hexdigest() == manifest.findings_digest


def test_failed_scan_response_never_becomes_a_completed_manifest() -> None:
    result = ScanResponse(
        status="failed",
        findings=[],
        artifacts=[],
        summary={
            "findings_total": 0,
            "severity_counts": {},
            "scanner_counts": {},
            "artifacts": [],
        },
    )
    registry = _registry(lambda _request, _control: result)
    request = _request()
    registry.start(request)
    terminal = registry.wait_for_terminal(request.run_id, 2)
    assert terminal.status == "failed"
    assert terminal.error_code == "scanner_result_failed"
    assert terminal.result_manifest is None and not terminal.result_available


def test_unacknowledged_result_is_preserved_when_global_capacity_is_full() -> None:
    max_run = 4 * 1024 * 1024
    registry = _registry(
        lambda _request, _control: _result(),
        max_run_bytes=max_run,
        max_total_bytes=max_run,
    )
    first = _request(scan_id=1)
    registry.start(first)
    first_state = registry.wait_for_terminal(first.run_id, 2)
    assert first_state.status == "completed" and first_state.result_available

    second = _request(scan_id=2)
    with pytest.raises(RunCapacityError, match="result retention capacity"):
        registry.start(second)
    with pytest.raises(RunNotFoundError):
        registry.get(second.run_id)
    assert registry.get(first.run_id).result_available


def test_result_capacity_rejects_new_execution_until_retained_result_is_acknowledged() -> None:
    calls = 0

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        nonlocal calls
        calls += 1
        return _many_findings_result(100) if calls == 1 else _result()

    max_run = 4 * 1024 * 1024
    registry = _registry(
        execute,
        max_run_bytes=max_run,
        max_total_bytes=max_run + 64 * 1024,
    )
    first = _request(scan_id=82)
    registry.start(first)
    first_state = registry.wait_for_terminal(first.run_id, 2)
    assert first_state.status == "completed" and first_state.result_manifest is not None
    assert first_state.result_available
    assert first_state.result_manifest.findings_bytes > 64 * 1024
    assert calls == 1

    # Reconciliation of the already-bound identity precedes capacity checks.
    assert registry.start(first) == first_state
    second = _request(scan_id=83)
    with pytest.raises(RunCapacityError, match="result retention capacity"):
        registry.start(second)
    assert calls == 1
    with pytest.raises(RunNotFoundError):
        registry.get(second.run_id)

    registry.acknowledge(
        first.run_id,
        RunResultAckRequest(
            request_digest=first_state.request_digest,
            result_digest=first_state.result_manifest.result_digest,
        ),
    )
    registry.start(second)
    assert registry.wait_for_terminal(second.run_id, 2).status == "completed"
    assert calls == 2


def test_active_durable_run_reserves_result_bytes_before_second_execution() -> None:
    entered = threading.Event()
    calls = 0

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            while True:
                control.cancel_event.wait(0.01)
                control.checkpoint()
        return _result()

    max_run = 4 * 1024 * 1024
    registry = _registry(
        execute,
        max_run_bytes=max_run,
        max_total_bytes=6 * 1024 * 1024,
        max_active_runs=2,
    )
    first = _request(scan_id=84)
    started = registry.start(first)
    assert entered.wait(1)

    second = _request(scan_id=85)
    with pytest.raises(RunCapacityError, match="result retention capacity"):
        registry.start(second)
    assert calls == 1
    with pytest.raises(RunNotFoundError):
        registry.get(second.run_id)

    registry.cancel(first.run_id, request_digest=started.request_digest)
    assert registry.wait_for_terminal(first.run_id, 2).status == "cancelled"
    registry.start(second)
    assert registry.wait_for_terminal(second.run_id, 2).status == "completed"
    assert calls == 2


def test_result_directory_symlink_fails_closed_without_path_detail(tmp_path: Path) -> None:
    scratch_target = tmp_path / "real-scratch"
    scratch_target.mkdir()
    scratch_link = tmp_path / "scratch-link"
    scratch_link.symlink_to(scratch_target, target_is_directory=True)
    with pytest.raises(RunResultStorageError) as rejected:
        _registry(
            lambda _request, _control: _result(),
            result_dir=scratch_link / "run-results",
        )
    assert str(tmp_path) not in str(rejected.value)


def test_shutdown_reports_an_execution_that_ignores_cancellation() -> None:
    entered = threading.Event()
    release = threading.Event()

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        entered.set()
        assert release.wait(2)
        return _result()

    registry = RunRegistry(
        execute,
        deadline_seconds=5,
        retention_seconds=5,
        max_terminal_records=1,
        result_dir=Path(tempfile.mkdtemp(prefix="kodesec-run-control-")) / "scratch" / "run-results",
        max_findings=50_000,
        max_item_bytes=32 * 1024,
        max_page_bytes=4 * 1024 * 1024,
        max_run_bytes=336 * 1024 * 1024,
        max_total_bytes=384 * 1024 * 1024,
        max_active_runs=1,
        termination_grace_seconds=0.05,
        shutdown_wait_seconds=0.05,
    )
    request = _request()
    registry.start(request)
    assert entered.wait(1)
    assert not registry.shutdown()
    release.set()
    assert registry.wait_for_terminal(request.run_id, 2).status == "cancelled"


def test_http_run_contract_validates_reconciles_and_cancels(monkeypatch: pytest.MonkeyPatch) -> None:
    entered = threading.Event()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        entered.set()
        while True:
            control.cancel_event.wait(0.01)
            control.checkpoint()

    registry = _registry(execute)
    monkeypatch.setattr(scanner, "run_registry", registry)
    run_id = uuid4()
    request = _request(run_id, scan_id=41)
    started = scanner.start_run(request)
    assert started.run_id == run_id
    assert entered.wait(1)
    assert scanner.start_run(request).run_id == run_id

    with pytest.raises(HTTPException) as conflict:
        scanner.start_run(request.model_copy(update={"scan_id": 42}))
    assert conflict.value.status_code == 409
    assert conflict.value.detail["code"] == "run_id_conflict"
    with pytest.raises(HTTPException) as capacity:
        scanner.start_run(_request())
    assert capacity.value.status_code == 409
    assert capacity.value.detail["code"] == "scanner_capacity"
    with pytest.raises(ValidationError):
        RunStartRequest.model_validate(
            {
                "run_id": "not-a-uuid",
                "scan_id": 41,
                "repo_path": "/fixture",
                "enabled_tools": ["sast-lite"],
            }
        )
    with pytest.raises(HTTPException) as missing:
        scanner.get_run(uuid4())
    assert missing.value.status_code == 404

    listed = scanner.list_runs(active_only=True)
    assert [item.run_id for item in listed.runs] == [run_id]
    assert listed.runs[0].result_manifest is None

    assert scanner.cancel_run(run_id).status in {"cancelling", "cancelled"}
    terminal = registry.wait_for_terminal(run_id, 2)
    assert terminal.status == "cancelled"
    assert scanner.get_run(run_id).status == "cancelled"
    assert scanner.cancel_run(run_id).status == "cancelled"

    routes = {(route.path, frozenset(route.methods or [])): route for route in scanner.app.routes}
    assert not any(path == "/scan" for path, _methods in routes)
    assert routes[("/runs", frozenset({"POST"}))].status_code == 202
    assert routes[("/runs/{run_id}", frozenset({"DELETE"}))].status_code == 202


def test_asgi_run_contract_serializes_status_conflicts_and_idempotent_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()

    def execute(_request: ScanRequest, control: ExecutionControl) -> ScanResponse:
        entered.set()
        while True:
            control.cancel_event.wait(0.01)
            control.checkpoint()

    registry = _registry(execute)
    monkeypatch.setattr(scanner, "run_registry", registry)
    run_id = uuid4()
    body = {
        "run_id": str(run_id),
        "scan_id": 51,
        "repo_path": "/fixture",
        "enabled_tools": ["sast-lite"],
    }
    with TestClient(scanner.app) as client:
        omitted_tools = client.post(
            "/runs",
            json={key: value for key, value in body.items() if key != "enabled_tools"},
        )
        assert omitted_tools.status_code == 422
        explicit_none = client.post("/runs", json={**body, "enabled_tools": []})
        assert explicit_none.status_code == 422
        started = client.post("/runs", json=body)
        assert started.status_code == 202
        assert started.json()["run_id"] == str(run_id)
        request_digest = started.json()["request_digest"]
        assert len(request_digest) == 64
        assert entered.wait(1)
        assert client.post("/runs", json=body).status_code == 202
        conflict = client.post("/runs", json={**body, "scan_id": 52})
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "run_id_conflict"
        capacity = client.post("/runs", json={**body, "run_id": str(uuid4())})
        assert capacity.status_code == 409
        assert capacity.json()["detail"]["code"] == "scanner_capacity"
        assert client.get("/runs/not-a-uuid").status_code == 422
        listed = client.get("/runs", params={"active_only": "true"})
        assert listed.status_code == 200
        assert listed.json()["runs"][0]["result_manifest"] is None
        mismatched = client.delete(
            f"/runs/{run_id}",
            params={"request_digest": "0" * 64},
        )
        assert mismatched.status_code == 409
        assert mismatched.json()["detail"]["code"] == "run_id_conflict"
        assert client.delete(
            f"/runs/{run_id}",
            params={"request_digest": request_digest},
        ).status_code == 202
        assert registry.wait_for_terminal(run_id, 2).status == "cancelled"
        assert client.delete(f"/runs/{run_id}").status_code == 202
        reconciled = client.get(f"/runs/{run_id}")
        assert reconciled.status_code == 200
        assert reconciled.json()["status"] == "cancelled"


def test_asgi_paged_result_ack_and_digest_bound_discard_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry(lambda _request, _control: _many_findings_result(3, message_size=128))
    monkeypatch.setattr(scanner, "run_registry", registry)
    request = _request(scan_id=61)
    registry.start(request)
    state = registry.wait_for_terminal(request.run_id, 2)
    assert state.result_manifest is not None

    with TestClient(scanner.app) as client:
        oversized_limit = client.get(
            f"/runs/{request.run_id}/findings",
            params={"request_digest": state.request_digest, "limit": 129},
        )
        assert oversized_limit.status_code == 422
        mismatched = client.get(
            f"/runs/{request.run_id}/findings",
            params={"request_digest": "0" * 64, "limit": 1},
        )
        assert mismatched.status_code == 409

        first = client.get(
            f"/runs/{request.run_id}/findings",
            params={"request_digest": state.request_digest, "limit": 1},
        )
        assert first.status_code == 200
        first_body = first.json()
        assert first_body["start_ordinal"] == 1
        assert len(first_body["items"]) == 1
        assert first_body["truncated"] is True
        cursor = first_body["next_cursor"]
        payload_token, signature_token = cursor.split(".", 1)
        hostile_cursor = f"{payload_token}.{'A' if signature_token[0] != 'A' else 'B'}{signature_token[1:]}"
        hostile = client.get(
            f"/runs/{request.run_id}/findings",
            params={
                "request_digest": state.request_digest,
                "cursor": hostile_cursor,
                "limit": 1,
            },
        )
        assert hostile.status_code == 422

        protected = client.delete(
            f"/runs/{request.run_id}",
            params={"request_digest": state.request_digest},
        )
        assert protected.status_code == 202
        assert protected.json()["status"] == "completed"
        assert protected.json()["result_available"] is True
        assert client.get(
            f"/runs/{request.run_id}/findings",
            params={"request_digest": state.request_digest, "limit": 1},
        ).status_code == 200

        bad_discard = client.delete(
            f"/runs/{request.run_id}",
            params={
                "request_digest": state.request_digest,
                "result_digest": "0" * 64,
            },
        )
        assert bad_discard.status_code == 409
        unbound_discard = client.delete(
            f"/runs/{request.run_id}",
            params={"result_digest": state.result_manifest.result_digest},
        )
        assert unbound_discard.status_code == 422
        acknowledged = client.post(
            f"/runs/{request.run_id}/result/ack",
            json={
                "request_digest": state.request_digest,
                "result_digest": state.result_manifest.result_digest,
            },
        )
        assert acknowledged.status_code == 200
        assert acknowledged.json()["result_available"] is False
        assert client.post(
            f"/runs/{request.run_id}/result/ack",
            json={
                "request_digest": state.request_digest,
                "result_digest": state.result_manifest.result_digest,
            },
        ).status_code == 200
        unavailable = client.get(
            f"/runs/{request.run_id}/findings",
            params={"request_digest": state.request_digest},
        )
        assert unavailable.status_code == 410
        tombstone = client.get(f"/runs/{request.run_id}")
        assert tombstone.status_code == 200
        assert tombstone.json()["result_manifest"]["result_digest"] == state.result_manifest.result_digest
        assert tombstone.json()["result_available"] is False


def test_asgi_request_bound_failed_cleanup_allows_stable_post_reexecution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = 0

    def execute(_request: ScanRequest, _control: ExecutionControl) -> ScanResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RunCapacityError("fixture result capacity")
        return _result()

    result_dir = tmp_path / "scratch" / "run-results"
    registry = _registry(execute, result_dir=result_dir)
    monkeypatch.setattr(scanner, "run_registry", registry)
    run_id = uuid4()
    body = {
        "run_id": str(run_id),
        "scan_id": 81,
        "repo_path": "/fixture",
        "enabled_tools": ["sast-lite"],
    }

    with TestClient(scanner.app) as client:
        started = client.post("/runs", json=body)
        assert started.status_code == 202
        request_digest = started.json()["request_digest"]
        failed = registry.wait_for_terminal(run_id, 2)
        assert failed.status == "failed" and failed.error_code == "result_capacity"

        conflict = client.delete(
            f"/runs/{run_id}",
            params={"request_digest": "0" * 64},
        )
        assert conflict.status_code == 409
        assert client.get(f"/runs/{run_id}").json()["error_code"] == "result_capacity"

        removed = client.delete(
            f"/runs/{run_id}",
            params={"request_digest": request_digest},
        )
        assert removed.status_code == 202
        assert removed.json()["status"] == "failed"
        assert removed.json()["error_code"] == "result_capacity"
        assert client.delete(
            f"/runs/{run_id}",
            params={"request_digest": request_digest},
        ).status_code == 404
        assert sorted(path.name for path in result_dir.iterdir()) == [".registry.lock"]

        reposted = client.post("/runs", json=body)
        assert reposted.status_code == 202
        assert reposted.json()["request_digest"] == request_digest
        assert registry.wait_for_terminal(run_id, 2).status == "completed"
        assert calls == 2
