from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from kodesec_scanner import cache_manifest, updater
from kodesec_scanner.external import _process_group_exists
from kodesec_scanner.cache_manifest import (
    CacheComponentReceipt,
    CacheFileRecord,
    CanaryReceipt,
    CanonicalTree,
    CANONICAL_TREE_HASH_ALGORITHM,
    GenerationManifest,
    GrypeDatabaseDataContract,
    LoadedDocument,
    ResolvedGeneration,
    ValidatedGeneration,
    activate_generation,
    canonical_tree_sha256,
    load_rules_lock,
    load_tool_lock,
    validate_generation,
    write_generation_manifest,
)
from kodesec_scanner.updater import (
    CACHE_COMPONENT_IDS,
    CATALOG_TOOL_IDS,
    CatalogComponentResult,
    CatalogOperationResult,
    CatalogToolResult,
    LockedLifecycleHandlers,
    OperationConflictError,
    OperationRequest,
    OperationStore,
    execute_operation,
    operation_request_digest,
)


ROOT = Path(__file__).resolve().parents[3]
TOOLS = load_tool_lock(ROOT / "scanner-tools.lock.json")
RULES = load_rules_lock(ROOT / "scanner-rules.lock.json")
NOW = "2026-08-12T21:00:00Z"
MOMENT = datetime(2026, 8, 12, 21, 0, 0, tzinfo=UTC)
BEFORE_MOMENT = MOMENT - timedelta(microseconds=1)

from kodesec_scanner.preparation_budget import issue_budget

@pytest.fixture(autouse=True)
def _owned_preparation_test_clock(monkeypatch):
    monkeypatch.setattr(updater, "_utc_now", lambda: MOMENT)


@pytest.mark.parametrize(("errors", "expected_error"), [
    ([], None),
    ([{"type": "file_error", "filename": "PRIVATE_PATH_MARKER",
       "error": "file processing time exceeded"}], "bearer_analysis_incomplete:file_timeout"),
    ([
        {"type": "file_error", "filename": "PRIVATE_PATH_MARKER", "error": "PRIVATE_NATIVE_MARKER"},
        {"type": "file_error", "filename": "PRIVATE_PATH_MARKER", "error": "exceeded memory limit"},
        {"type": "file_error", "filename": "PRIVATE_PATH_MARKER", "error": "file processing time exceeded"},
        {"type": "file_error", "filename": "PRIVATE_PATH_MARKER", "error": "exceeded memory limit"},
    ], "bearer_analysis_incomplete:file_timeout,memory_limit,unknown"),
])
def test_bearer_canary_requires_jsonv2_completeness_before_semantic_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, errors: list[dict[str, str]],
    expected_error: str | None,
) -> None:
    rule_set = RULES.value.rule_set("bearer-rules")
    canary = rule_set.canaries[0]
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    monkeypatch.setattr(updater, "_baked_canary_path", lambda item: fixture)
    monkeypatch.setattr(updater, "_verify_canary_fixture", lambda *args: None)
    commands: list[list[str]] = []
    def fake_popen(command, **kwargs):
        commands.append(command)
        assert command[command.index("--format") + 1] == "jsonv2"
        assert "--parallel" not in command
        assert kwargs["stdout"] == subprocess.DEVNULL and kwargs["stderr"] == subprocess.DEVNULL
        ids = canary.expected_rule_ids
        Path(command[command.index("--output") + 1]).write_text(json.dumps({
            "source": "Bearer", "version": "2.1.0+lomo.1", "errors": errors,
            "findings": [{"id": ids[index % len(ids)]} for index in range(canary.expected_result_count)],
        }))
        return SimpleNamespace(returncode=canary.expected_exit_code, poll=lambda: canary.expected_exit_code)
    monkeypatch.setattr(updater.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(updater, "_terminate_canary", lambda process: None)
    context = SimpleNamespace(checkpoint=lambda: None)
    if expected_error is not None:
        with pytest.raises(updater.OperationError, match=f"^{expected_error}$") as failure:
            updater.run_rule_canaries(context, rule_set, tmp_path / "rules", tmp_path / "scratch")
        assert "PRIVATE_" not in str(failure.value)
    else:
        receipts = updater.run_rule_canaries(context, rule_set, tmp_path / "rules", tmp_path / "scratch")
        assert receipts[0].passed is True
        assert receipts[0].output_sha256 == canary.output_sha256
        assert receipts[0].result_count == canary.expected_result_count
    assert len(commands) == 1
    assert list((tmp_path / "scratch").iterdir()) == []


@pytest.mark.parametrize("payload", [
    {"source": "Bearer", "version": "2.1.0+lomo.1", "findings": [{"id": "expected"}]},
    {"source": "Bearer", "version": "2.1.0+lomo.1", "findings": [], "errors": {}},
    {"source": "Bearer", "version": "dev", "findings": [], "errors": []},
    pytest.param({"source": "Bearer", "version": "2.1.0", "findings": [], "errors": []},
                 id="stock-version-rejected"),
])
def test_bearer_canary_rejects_missing_or_malformed_completeness(tmp_path: Path, payload: dict) -> None:
    path = tmp_path / "result.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(updater.OperationError, match="^bearer_native_report_invalid$"):
        updater._parse_bearer_semantics(path)


def test_bearer_canary_rejects_unsafe_or_oversize_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "result.json"
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"source": "Bearer", "version": "2.1.0+lomo.1", "findings": [], "errors": []}))
    path.symlink_to(target)
    with pytest.raises(updater.OperationError, match="^bearer_native_report_invalid$"):
        updater._parse_bearer_semantics(path)
    monkeypatch.setattr(updater, "MAX_CANARY_OUTPUT_BYTES", 16)
    with pytest.raises(updater.OperationError, match="^bearer_native_report_invalid$"):
        updater._parse_bearer_semantics(target)


class _CheckpointContext:
    def checkpoint(self) -> None:
        return None

    def refresh_activity(self) -> None:
        self.checkpoint()


class _ProgressContext(_CheckpointContext):
    def __init__(self) -> None:
        self.events: list[str] = []

    def progress(self, stage: str, **_context: object) -> None:
        self.events.append(stage)


def _empty_observed_tree() -> CanonicalTree:
    return CanonicalTree(
        algorithm=CANONICAL_TREE_HASH_ALGORITHM,
        sha256=canonical_tree_sha256(()),
        file_count=0,
        size_bytes=0,
        files=(),
    )


@pytest.mark.parametrize("returncode", [7, -signal.SIGTERM])
def test_data_command_failure_keeps_typed_private_evidence(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, returncode: int,
) -> None:
    stderr = "download denied https://example.invalid/db?token=private-token\n"
    script = (
        "import os, signal, sys; os.write(2, sys.argv[1].encode()); "
        "code=int(sys.argv[2]); "
        "os.kill(os.getpid(), -code) if code < 0 else sys.exit(code)"
    )
    with pytest.raises(updater.DataCommandFailureError) as raised:
        updater._run_data_command(
            _CheckpointContext(),  # type: ignore[arg-type]
            [sys.executable, "-c", script, stderr, str(returncode)],
            command_id="trivy-promotion", cwd=tmp_path, environment={},
        )
    failure = raised.value
    assert failure.command_id == "trivy-promotion"
    assert failure.returncode == returncode
    assert failure.signal == (-returncode if returncode < 0 else None)
    assert failure.stderr_bytes == len(stderr.encode())
    assert failure.stderr_sha256 == hashlib.sha256(stderr.encode()).hexdigest()
    assert "private-token" not in failure.private_stderr
    assert "[REDACTED]" in failure.private_stderr
    assert failure.timing is not None and failure.timing.elapsed_ms >= 0
    assert failure.timing.effective_timeout_ms == updater.MAX_DATA_COMMAND_SECONDS * 1000
    assert failure.timing.local_limit_ms == updater.MAX_DATA_COMMAND_SECONDS * 1000
    assert failure.timing.preparation_budget_ms is None
    assert failure.timing.capped is False

    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-db"])
    store.create_or_get(request, now=NOW)
    updater._log_operation_failure(store, request.operation_id, failure)
    terminal = updater._fail_operation(
        store, request.operation_id, "operation_failed", NOW, exc=failure,
    )
    assert terminal.error_code == "data_command_failed"
    assert f"exit status {returncode}" in terminal.error_detail
    assert "command_id=trivy-promotion" in caplog.text
    assert f"returncode={returncode}" in caplog.text
    assert failure.stderr_sha256 in caplog.text
    published = caplog.text + terminal.model_dump_json() + str(failure)
    for private in ("example.invalid", "private-token", stderr, script):
        assert private not in published


@pytest.mark.parametrize("expected_exit_code", [0, 2])
def test_data_command_preserves_stdout_file_and_expected_canary_exit(
    tmp_path: Path, expected_exit_code: int,
) -> None:
    output = tmp_path / "status.json"
    content = b'{"valid":true,"schemaVersion":"v6.1.9"}\n'
    result = updater._run_data_command(
        _CheckpointContext(),  # type: ignore[arg-type]
        [sys.executable, "-c", f"import os, sys; os.write(1, {content!r}); sys.exit({expected_exit_code})"],
        command_id="grype-status", cwd=tmp_path, environment={},
        stdout_path=output, expected_exit_code=expected_exit_code,
    )
    assert type(result) is int and result == expected_exit_code
    assert output.read_bytes() == content
    with pytest.raises(updater.OperationError, match="output already exists"):
        updater._run_data_command(
            _CheckpointContext(),  # type: ignore[arg-type]
            [sys.executable, "-c", "raise AssertionError('must not run')"],
            command_id="grype-status", cwd=tmp_path, environment={}, stdout_path=output,
        )
    assert output.read_bytes() == content


@pytest.mark.parametrize(("text", "markers"), [
    ("context deadline exceeded", ("context_deadline",)),
    ("TLS handshake TIMEOUT", ("timeout", "tls_handshake")),
    ("no such host; connection reset", ("dns_lookup", "connection_reset")),
    ("unexpected EOF; connection refused", ("connection_refused", "unexpected_eof")),
    ("no space left on device", ("disk_capacity",)),
    ("permission denied", ("permission_denied",)),
    ("UNAUTHORIZED; too many requests", ("unauthorized", "rate_limit")),
    ("manifest unknown; blob unknown", ("manifest_unknown", "blob_unknown")),
    ("x509: certificate has expired", ("certificate",)),
    ("download error: OCI artifact: failed to copy", ("download_error", "oci_artifact", "copy_failed")),
    ("OCI artifact error: oci download error: copy error: stream error: received from peer",
     ("download_error", "oci_artifact", "oci_layer_copy_error", "stream_error", "peer_error")),
    ("OCI artifact error: oci download error: download error: gzip: invalid checksum",
     ("download_error", "oci_artifact", "oci_local_unpack_error", "gzip_invalid", "checksum_invalid")),
    ("OCI repository error: OCI manifest error:", ("oci_repository_error", "oci_manifest_error")),
    ("failed to fetch the layer:", ("oci_layer_fetch_error",)),
    ("failed to create a temp dir: failed to create a temp file: file too large",
     ("temporary_directory_error", "temporary_file_error", "file_size_limit")),
    ("failed to extract: failed to write", ("extract_failed", "write_failed")),
    ("failed to open: failed to decode: failed to parse", ("open_failed", "decode_failed", "parse_failed")),
    ("invalid checksum: digest mismatch", ("checksum_invalid", "digest_mismatch")),
    ("no such file or directory; read-only file system", ("path_missing", "read_only_filesystem")),
    ("file exists; database is locked", ("path_exists", "database_locked")),
    ("unrecognized private diagnostic", ()),
])
def test_data_command_logs_only_fixed_diagnostic_markers(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, text: str, markers: tuple[str, ...],
) -> None:
    private = "https://private.invalid/download?token=private-token"
    error = updater.DataCommandFailureError("trivy-promotion", 1, text + " " + private)
    assert error.stderr_markers == markers
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-db"])
    store.create_or_get(request, now=NOW)
    updater._log_operation_failure(store, request.operation_id, error)
    terminal = updater._fail_operation(
        store, request.operation_id, "operation_failed", NOW, exc=error,
    )
    assert "stderr_markers=" + (",".join(markers) or "none") in caplog.text
    assert terminal.error_code == "data_command_failed"
    for secret in (private, "private.invalid", "private-token", "unrecognized private diagnostic"):
        assert secret not in caplog.text + terminal.model_dump_json() + str(error)


@pytest.mark.parametrize(("text", "statuses"), [
    ("unexpected status code 403 Forbidden", ("403",)),
    ("unexpected status: 429; HTTP status: 503; status code 429", ("429", "503")),
    ("offset 403; status code 200; status code 999; status code 4030", ()),
])
def test_data_command_http_markers_never_export_process_text(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, text: str, statuses: tuple[str, ...],
) -> None:
    private = "https://private.invalid/signed?X-Amz-Signature=unusual-secret /private/download.db"
    error = updater.DataCommandFailureError("trivy-promotion", 1, text + " " + private)
    assert error.http_status_markers == statuses
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-java-db"])
    store.create_or_get(request, now=NOW)
    updater._log_operation_failure(store, request.operation_id, error)
    assert "http_status_markers=" + (",".join(statuses) or "none") in caplog.text
    assert "elapsed_ms=None" in caplog.text  # No fabricated timing for a legacy error.
    for secret in ("private.invalid", "unusual-secret", "/private/download.db", "X-Amz"):
        assert secret not in caplog.text + str(error)


@pytest.mark.parametrize('prefix', [
    'https://private.invalid/layer?token=private-token',
    'https://private.invalid/layer?X-Amz-Signature=private-signature',
    'authorization=private-credential',
])
def test_data_command_fixed_markers_survive_redacted_error_tail(tmp_path, caplog, prefix):
    text = prefix + ' stream error: received from peer; status code 503'
    error = updater.DataCommandFailureError('trivy-promotion', 1, text)
    assert 'stream error:' not in error.private_stderr
    assert error.stderr_markers == ('stream_error', 'peer_error')
    assert error.http_status_markers == ('503',)
    store = OperationStore(tmp_path / 'cache')
    request = _request(components=['trivy-java-db'])
    store.create_or_get(request, now=NOW)
    updater._log_operation_failure(store, request.operation_id, error)
    terminal = updater._fail_operation(store, request.operation_id, 'operation_failed', NOW, exc=error)
    output = caplog.text + terminal.model_dump_json() + str(error)
    assert 'stderr_markers=stream_error,peer_error' in output
    assert 'http_status_markers=503' in output
    for forbidden in (prefix, 'private.invalid', 'private-token', 'private-signature', 'private-credential'):
        assert forbidden not in output


@pytest.mark.parametrize(("elapsed", "milliseconds", "capped"), [(3.25, 3250, False), (86401, 86400000, True)])
def test_data_command_failure_preserves_original_budget_and_nonzero_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    elapsed: float, milliseconds: int, capped: bool,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-java-db"])
    store.create_or_get(request, now=NOW)
    context = updater.OperationContext(request, store)
    clock = [100.0]
    bounds = []

    def remaining(self, local_bound):
        assert self is context
        bounds.append(local_bound)
        if len(bounds) != 1:
            raise updater.PreparationDeadlineExceeded("must not replace the child failure")
        return 2.5

    def command(_command, **kwargs):
        assert kwargs["timeout"] == 2.5
        assert kwargs["control"].deadline_monotonic == 102.5
        assert kwargs["control"].context is context
        assert kwargs["stdin"] == subprocess.DEVNULL
        clock[0] = 100 + elapsed  # Exit observed after the admitted budget, without a new clock.
        return subprocess.CompletedProcess(_command, 1, "", "unknown private failure")

    monkeypatch.setattr(updater.OperationContext, "remaining_seconds", remaining)
    monkeypatch.setattr(updater.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(updater, "run_captured_command", command)
    with pytest.raises(updater.DataCommandFailureError) as raised:
        updater._run_data_command(context, ["private-command"], command_id="trivy-promotion",
                                  cwd=tmp_path, environment={}, timeout_seconds=900)
    error = raised.value
    assert bounds == [900]
    assert error.timing == updater.DataCommandTiming(milliseconds, 2500, 900000, 1200000, capped)
    assert error.stderr_markers == error.http_status_markers == ()
    updater._log_operation_failure(store, request.operation_id, error)
    assert f"elapsed_ms={milliseconds} effective_timeout_ms=2500 local_limit_ms=900000 preparation_budget_ms=1200000 timing_capped={capped}" in caplog.text
    assert "private-command" not in caplog.text and "unknown private failure" not in caplog.text
    terminal = updater._fail_operation(store, request.operation_id, "operation_failed", NOW, exc=error)
    assert terminal.error_code == "data_command_failed"
    assert "exit status 1" in terminal.error_detail
    assert terminal.preparation_budget == request.preparation_budget
    assert "elapsed_ms" not in terminal.model_dump_json()


@pytest.mark.parametrize("failure", [
    updater.PreparationDeadlineExceeded("scanner preparation deadline exceeded"),
    updater.OperationStateError("updater operation cancellation requested"),
])
def test_data_command_diagnostics_do_not_replace_budget_or_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception,
) -> None:
    def command(*args, **kwargs):
        raise failure
    monkeypatch.setattr(updater, "run_captured_command", command)
    with pytest.raises(type(failure)) as raised:
        updater._run_data_command(_CheckpointContext(), ["private-command"],
                                  command_id="trivy-promotion", cwd=tmp_path, environment={})
    assert raised.value is failure


@pytest.mark.parametrize("cancel", [False, True])
def test_data_command_bound_and_cancellation_clean_up_exact_process_group(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, cancel: bool,
) -> None:
    pid_file = tmp_path / "command.pid"
    script = """
import os, signal, subprocess, sys
child = subprocess.Popen([sys.executable, '-c', 'import signal; signal.pause()'])
def stop(_signum, _frame):
    child.wait()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
with open(sys.argv[1], 'w') as output:
    output.write(str(os.getpid()))
if sys.argv[2] == 'overflow':
    os.write(2, b'x' * (64 * 1024 + 1))
signal.pause()
"""

    class Context(_CheckpointContext):
        def checkpoint(self) -> None:
            if cancel and pid_file.exists():
                raise updater.OperationStateError("updater operation cancellation requested")

    expected_error = updater.OperationStateError if cancel else updater.DataCommandOutputLimitError
    expected_message = "cancellation requested" if cancel else "exceeded its captured output limit"
    try:
        with pytest.raises(expected_error, match=expected_message) as raised:
            updater._run_data_command(
                Context(),  # type: ignore[arg-type]
                [sys.executable, "-c", script, str(pid_file), "cancel" if cancel else "overflow"],
                command_id="trivy-promotion", cwd=tmp_path, environment={},
                timeout_seconds=10,
            )
        assert not _process_group_exists(int(pid_file.read_text()))
        if not cancel:
            failure = raised.value
            assert failure.command_id == "trivy-promotion"
            assert failure.limit_bytes == updater.MAX_DATA_COMMAND_OUTPUT_BYTES
            assert isinstance(failure.__cause__, updater.CapturedCommandOutputLimitError)
            store = OperationStore(tmp_path / "cache")
            request = _request(components=["trivy-db"])
            store.create_or_get(request, now=NOW)
            updater._log_operation_failure(store, request.operation_id, failure)
            terminal = updater._fail_operation(
                store, request.operation_id, "operation_failed", NOW, exc=failure,
            )
            assert terminal.error_code == "data_command_output_limit"
            assert "65536 bytes" in terminal.error_detail
            assert "command_id=trivy-promotion" in caplog.text
            assert "output_limit_bytes=65536" in caplog.text
            published = caplog.text + terminal.model_dump_json() + str(failure)
            assert script not in published
            assert str(pid_file) not in published
            assert "x" * 100 not in published
    finally:
        if pid_file.exists():
            try:
                os.killpg(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_data_command_rejects_unrecognized_identity_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("unrecognized command identity must not launch")

    monkeypatch.setattr(updater, "run_captured_command", forbidden)
    with pytest.raises(updater.OperationError, match="invalid scanner data command identity"):
        updater._run_data_command(
            _CheckpointContext(),  # type: ignore[arg-type]
            ["unrecognized"], command_id="unrecognized",  # type: ignore[arg-type]
            cwd=tmp_path, environment={},
        )


def test_data_command_closes_stdin_without_changing_shared_runner_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_stdin: list[int | None] = []
    launch = subprocess.Popen

    def record_launch(*args: object, **kwargs: object) -> subprocess.Popen:
        observed_stdin.append(kwargs.get("stdin"))  # type: ignore[arg-type]
        return launch(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess, "Popen", record_launch)
    output = tmp_path / "stdin.json"
    assert updater._run_data_command(
        _CheckpointContext(),  # type: ignore[arg-type]
        [sys.executable, "-c", "import sys; assert sys.stdin.buffer.read() == b''; print('{}')"],
        command_id="grype-status", cwd=tmp_path, environment={}, stdout_path=output,
    ) == 0
    assert output.read_bytes() == b"{}\n"
    inherited = updater.run_captured_command(
        [sys.executable, "-c", "print('default unchanged')"], tmp_path, 10, {},
    )
    assert inherited.returncode == 0
    assert inherited.stdout == "default unchanged\n"
    assert observed_stdin == [subprocess.DEVNULL, None]


@pytest.mark.parametrize("component_id", ["trivy-db", "trivy-java-db"])
def test_trivy_download_stage_precedes_validation_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component_id: str,
) -> None:
    requirement = next(
        item
        for item in TOOLS.value.tool("trivy").requirements
        if item.id == component_id
    )
    contract = requirement.data_contract
    assert contract is not None
    payload = tmp_path / "payload"
    stage = tmp_path / "stage"
    payload.mkdir()
    stage.mkdir()
    context = _ProgressContext()

    def run_command(
        _context: object,
        _command: list[str],
        **_kwargs: object,
    ) -> int:
        assert context.events == []
        assert _command.count("--no-progress") == 1
        assert "--quiet" not in _command
        assert ("--download-db-only" if component_id == "trivy-db" else "--download-java-db-only") in _command
        context.events.append("transport_complete")
        component_root = payload / str(requirement.cache_subpath)
        component_root.mkdir(parents=True, exist_ok=True)
        (component_root / "metadata.json").write_text(
            json.dumps(
                {
                    "Version": contract.schema_version,
                    "UpdatedAt": contract.publisher_updated_at,
                    "NextUpdate": contract.publisher_refresh_due_at,
                }
            )
        )
        return 0

    monkeypatch.setattr(updater, "_run_data_command", run_command)
    monkeypatch.setattr(
        updater,
        "collect_canonical_tree",
        lambda *_args, **_kwargs: _empty_observed_tree(),
    )
    monkeypatch.setattr(updater, "_validate_installed_content", lambda *_args: None)

    staged = updater._stage_trivy_component(
        context,  # type: ignore[arg-type]
        requirement,
        payload=payload,
        operation_stage=stage,
        progress_context={
            "component_id": component_id,
            "component_index": 1,
            "component_total": 1,
        },
    )

    assert context.events == ["transport_complete", "validating_source"]
    assert staged.updated_at == contract.publisher_updated_at
    assert updater._parse_utc(staged.expires_at, "expiry") == updater._parse_utc(
        contract.publisher_updated_at,
        "publisher update",
    ) + timedelta(days=14)


@pytest.mark.parametrize(
    ("component_id", "metadata_field", "hostile_value"),
    [
        ("trivy-db", "Version", True),
        ("trivy-db", "Version", 2.0),
        ("trivy-java-db", "Version", True),
        ("trivy-java-db", "Version", 1.0),
        ("trivy-checks", "MajorVersion", True),
        ("trivy-checks", "MajorVersion", 2.0),
    ],
)
def test_trivy_metadata_schema_requires_an_exact_integer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component_id: str,
    metadata_field: str,
    hostile_value: object,
) -> None:
    requirement = next(
        requirement
        for requirement in TOOLS.value.tool("trivy").requirements
        if requirement.id == component_id
    )
    payload = tmp_path / "payload"
    stage = tmp_path / "stage"
    payload.mkdir()
    stage.mkdir()

    def run_command(
        _context: object,
        _command: list[str],
        **_kwargs: object,
    ) -> int:
        assert ("--no-progress" in _command) is (component_id != "trivy-checks")
        component_root = payload / str(requirement.cache_subpath)
        component_root.mkdir(parents=True, exist_ok=True)
        metadata = {
            metadata_field: hostile_value,
            "UpdatedAt": "2026-08-12T20:00:00Z",
            "NextUpdate": "2026-08-13T20:00:00Z",
            "DownloadedAt": "2026-08-12T20:00:00Z",
            "Digest": f"sha256:{requirement.source.sha256}",
        }
        (component_root / "metadata.json").write_text(json.dumps(metadata))
        return 0

    monkeypatch.setattr(updater, "_run_data_command", run_command)

    with pytest.raises(updater.OperationError, match="differs from its lock"):
        updater._stage_trivy_component(
            _CheckpointContext(),  # type: ignore[arg-type]
            requirement,
            payload=payload,
            operation_stage=stage,
        )


def test_grype_stage_uses_the_exact_typed_lock_status_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = TOOLS.value.tool("grype").requirements[0].model_copy(
        update={
            "data_contract": GrypeDatabaseDataContract(
                kind="grype-db-status/v1",
                schema_version="v7.2.1",
                built_at="2026-08-13T06:38:08Z",
                timestamp_kind="intrinsic",
            ),
            # This test isolates the status schema/build contract; logical
            # database content is exercised by the dedicated identity tests.
            "installed_content": TOOLS.value.tool("grype").requirements[0].installed_content.model_copy(
                update={"hash_algorithm": CANONICAL_TREE_HASH_ALGORITHM}
            ),
        }
    )
    payload = tmp_path / "payload"
    stage = tmp_path / "stage"
    payload.mkdir()
    stage.mkdir()
    context = _ProgressContext()

    def download(**_kwargs: object) -> None:
        assert context.events == []
        context.events.append("transport_complete")

    monkeypatch.setattr(updater, "_download_direct_locked_asset", download)
    monkeypatch.setattr(
        updater,
        "collect_canonical_tree",
        lambda *_args, **_kwargs: _empty_observed_tree(),
    )
    monkeypatch.setattr(updater, "_validate_installed_content", lambda *_args, **_kwargs: None)

    def run_command(
        _context: object,
        command: list[str],
        **kwargs: object,
    ) -> int:
        assert context.events == ["transport_complete", "validating_source"]
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        assert environment["GRYPE_DB_VALIDATE_AGE"] == "true"
        assert environment["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == "1209600s"
        if command[1:3] == ["db", "status"]:
            output = kwargs["stdout_path"]
            assert isinstance(output, Path)
            output.write_text(
                '{"valid":true,"schemaVersion":"v7.2.1",'
                '"built":"2026-08-13T06:38:08Z"}'
            )
        return 0

    monkeypatch.setattr(updater, "_run_data_command", run_command)

    staged = updater._stage_grype_component(
        context,  # type: ignore[arg-type]
        requirement,
        payload=payload,
        operation_stage=stage,
        timeout_seconds=30,
        progress_context={
            "component_id": "grype-db",
            "component_index": 1,
            "component_total": 1,
        },
    )

    assert staged.updated_at == "2026-08-13T06:38:08Z"
    assert context.events == ["transport_complete", "validating_source"]


def test_grype_stage_rejects_status_that_differs_from_the_typed_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = TOOLS.value.tool("grype").requirements[0]
    payload = tmp_path / "payload"
    stage = tmp_path / "stage"
    payload.mkdir()
    stage.mkdir()
    monkeypatch.setattr(updater, "_download_direct_locked_asset", lambda **_kwargs: None)

    def run_command(
        _context: object,
        command: list[str],
        **kwargs: object,
    ) -> int:
        if command[1:3] == ["db", "status"]:
            output = kwargs["stdout_path"]
            assert isinstance(output, Path)
            output.write_text(
                '{"valid":true,"schemaVersion":"v6.1.9",'
                '"built":"2026-08-13T06:38:08Z"}'
            )
        return 0

    monkeypatch.setattr(updater, "_run_data_command", run_command)

    with pytest.raises(updater.OperationError, match="identity differs from its lock"):
        updater._stage_grype_component(
            _CheckpointContext(),  # type: ignore[arg-type]
            requirement,
            payload=payload,
            operation_stage=stage,
            timeout_seconds=30,
        )


def test_trivy_installed_content_allows_only_bounded_volatile_metadata() -> None:
    requirement = TOOLS.value.tool("trivy").requirements[0]
    expected = requirement.installed_content
    assert expected is not None
    assert expected.file_count == 1
    assert expected.volatile_paths == ["metadata.json"]

    # Synthetic stable content isolates the volatile-file policy from regular
    # database lock renewals, which have their own real candidate receipts.
    stable = CacheFileRecord(
        path="trivy.db",
        size_bytes=32,
        sha256="a" * 64,
    )
    requirement = requirement.model_copy(update={
        "installed_size_bytes": 33,
        "installed_content": expected.model_copy(update={
            "sha256": canonical_tree_sha256((stable,)), "size_bytes": 32,
        }),
    })

    def observed_tree(*records: CacheFileRecord) -> CanonicalTree:
        return CanonicalTree(
            algorithm=CANONICAL_TREE_HASH_ALGORITHM,
            sha256=canonical_tree_sha256(records),
            file_count=len(records),
            size_bytes=sum(record.size_bytes for record in records),
            files=records,
        )

    metadata = CacheFileRecord(path="metadata.json", size_bytes=1, sha256="e" * 64)
    changed_metadata = CacheFileRecord(
        path="metadata.json", size_bytes=4096, sha256="f" * 64
    )

    updater._validate_installed_content(observed_tree(metadata, stable), requirement)
    updater._validate_installed_content(
        observed_tree(changed_metadata, stable), requirement
    )

    oversized_metadata = changed_metadata.model_copy(update={"size_bytes": 4097})
    with pytest.raises(updater.OperationError, match="volatile metadata"):
        updater._validate_installed_content(
            observed_tree(oversized_metadata, stable), requirement
        )

    with pytest.raises(updater.OperationError, match="volatile metadata"):
        updater._validate_installed_content(observed_tree(stable), requirement)

    changed_stable = stable.model_copy(update={"sha256": "1" * 64})
    with pytest.raises(updater.OperationError, match="identity differs"):
        updater._validate_installed_content(
            observed_tree(metadata, changed_stable), requirement
        )


def test_installed_content_mismatch_carries_bounded_platform_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = TOOLS.value.tool("trivy").requirements[0]
    expected = requirement.installed_content
    assert expected is not None
    changed = CacheFileRecord(
        path="trivy.db",
        size_bytes=expected.size_bytes,
        sha256="1" * 64,
    )
    metadata = CacheFileRecord(path="metadata.json", size_bytes=1, sha256="2" * 64)
    observed = CanonicalTree(
        algorithm=CANONICAL_TREE_HASH_ALGORITHM,
        sha256=canonical_tree_sha256((metadata, changed)),
        file_count=2,
        size_bytes=metadata.size_bytes + changed.size_bytes,
        files=(metadata, changed),
    )
    monkeypatch.setattr(updater, "_runtime_linux_platform", lambda: "linux/amd64")

    with pytest.raises(updater.InstalledContentMismatchError) as captured:
        updater._validate_installed_content(observed, requirement)

    assert captured.value.evidence.model_dump(mode="json") == {
        "kind": "installed_content_mismatch",
        "component_id": "trivy-db",
        "runtime_platform": "linux/amd64",
        "hash_algorithm": "kodesec-canonical-tree-v1",
        "expected_sha256": expected.sha256,
        "observed_sha256": canonical_tree_sha256((changed,)),
        "expected_file_count": expected.file_count,
        "observed_file_count": 1,
        "expected_size_bytes": expected.size_bytes,
        "observed_size_bytes": changed.size_bytes,
    }


def test_grype_physical_mismatch_reports_only_fixed_source_blind_file_hashes() -> None:
    requirement = TOOLS.value.tool("grype").requirements[0]
    requirement = requirement.model_copy(update={
        "installed_content": requirement.installed_content.model_copy(update={
            "hash_algorithm": CANONICAL_TREE_HASH_ALGORITHM,
        }),
    })
    files = (
        CacheFileRecord(path="6/vulnerability.db", size_bytes=20, sha256="a" * 64),
        CacheFileRecord(path="6/import.json", size_bytes=10, sha256="b" * 64),
        CacheFileRecord(path="unreviewed-name", size_bytes=5, sha256="c" * 64),
    )
    observed = CanonicalTree(
        algorithm=CANONICAL_TREE_HASH_ALGORITHM,
        sha256=canonical_tree_sha256(files),
        file_count=3,
        size_bytes=35,
        files=files,
    )
    with pytest.raises(updater.InstalledContentMismatchError) as failure:
        updater._validate_installed_content(observed, requirement)
    assert failure.value.database_sha256 == "a" * 64
    assert failure.value.import_metadata_sha256 == "b" * 64
    assert "unreviewed-name" not in str(vars(failure.value))
    assert "c" * 64 not in str(vars(failure.value))

    other_component = failure.value.evidence.model_copy(update={"component_id": "trivy-db"})
    other_failure = updater.InstalledContentMismatchError(other_component, files=files)
    assert other_failure.database_sha256 is None
    assert other_failure.import_metadata_sha256 is None


def test_locked_archive_extracts_nested_files_then_seals_the_tree(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "nested.tar.gz"
    payload = b"rules:\n  - id: exact-rule\n"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ("python", "python/lang"):
            item = tarfile.TarInfo(name)
            item.type = tarfile.DIRTYPE
            item.mode = 0o755
            bundle.addfile(item)
        item = tarfile.TarInfo("python/lang/exact.yml")
        item.size = len(payload)
        item.mode = 0o644
        bundle.addfile(item, io.BytesIO(payload))

    destination = tmp_path / "rules"
    updater.extract_locked_tar_gz(archive, destination, _CheckpointContext())  # type: ignore[arg-type]

    extracted = destination / "python" / "lang" / "exact.yml"
    assert extracted.read_bytes() == payload
    assert destination.stat().st_mode & 0o222 == 0
    assert extracted.stat().st_mode & 0o222 == 0


def test_private_staging_cleanup_reopens_sealed_directories_without_following_links(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    root = tmp_path / "operation-stage"
    nested = root / "sealed"
    nested.mkdir(parents=True, mode=0o700)
    payload = nested / "rules.yml"
    payload.write_text("rules: []\n", encoding="utf-8")
    payload.chmod(0o400)
    (root / "outside-alias").symlink_to(outside)
    nested.chmod(0o500)
    root.chmod(0o500)

    updater._remove_private_staging_tree(root)

    assert not root.exists()
    assert outside.read_text(encoding="utf-8") == "preserve"


def test_component_copy_observes_bounded_cancellation_checkpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quantum = 2 * 1024 * 1024
    monkeypatch.setattr(updater, "GENERATION_HASH_CHECKPOINT_BYTES", quantum)
    source = tmp_path / "source"
    source.mkdir()
    content = b"x" * (quantum * 2)
    payload = source / "large.db"
    payload.write_bytes(content)
    record = CacheFileRecord(
        path="large.db",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    calls = 0

    class CancelCopy(RuntimeError):
        pass

    def checkpoint() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CancelCopy("cancelled during component copy")

    with pytest.raises(CancelCopy, match="cancelled during component copy"):
        updater._copy_exact_tree(
            source,
            tmp_path / "destination",
            [record],
            checkpoint,
        )

    assert calls == 2
    assert (tmp_path / "destination" / "large.db").stat().st_size <= quantum


def test_component_copy_reports_exact_bytes_without_invented_progress(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    content = b"x" * (1024 * 1024 + 7)
    payload = source / "component.db"
    payload.write_bytes(content)
    record = CacheFileRecord(
        path="component.db",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    observations: list[tuple[int, int]] = []

    updater._copy_exact_tree(
        source,
        tmp_path / "destination",
        [record],
        byte_progress=lambda completed, total: observations.append((completed, total)),
    )

    assert observations[0] == (0, len(content))
    assert observations[-1] == (len(content), len(content))
    assert [completed for completed, _total in observations] == sorted(
        completed for completed, _total in observations
    )


def test_lock_change_carries_only_current_byte_identical_component(
    tmp_path: Path,
) -> None:
    content = b"id: reviewed-rule\n"
    receipt = _bearer_generation_manifest(content).components[0]
    source = tmp_path / "old-generation"
    source_file = source / receipt.files[0].path
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(content)
    old_manifest = GenerationManifest.create(
        tool_lock_sha256="0" * 64,
        rules_lock_sha256=RULES.sha256,
        created_at=NOW,
        components=[receipt],
    )
    generation = ValidatedGeneration(
        path=source,
        manifest=old_manifest,
        manifest_sha256="1" * 64,
    )
    current_tools = LoadedDocument(
        value=TOOLS.value,
        sha256=TOOLS.sha256,
        path=TOOLS.path,
    )

    updater._validate_component_receipts(
        [receipt],
        [],
        current_tools,
        RULES,
        evaluated_at=MOMENT,
    )
    destination = tmp_path / "new-generation"
    carried = updater._copy_validated_component(
        generation,
        receipt,
        destination,
    )

    assert carried == receipt
    assert (destination / receipt.files[0].path).read_bytes() == content
    mismatched = receipt.model_copy(update={"immutable_ref": "different-ref"})
    with pytest.raises(updater.OperationError, match="identity differs"):
        updater._validate_component_receipts(
            [mismatched],
            [],
            current_tools,
            RULES,
            evaluated_at=MOMENT,
        )


def test_operation_telemetry_detail_is_bounded_and_path_blind() -> None:
    assert (
        updater._safe_operation_telemetry_detail(
            updater.OperationError("locked asset transport failed")
        )
        == "locked asset transport failed"
    )
    assert updater._safe_operation_telemetry_detail(
        updater.OperationError("failed https://example.invalid/private")
    ) == "operation exception detail redacted"
    assert updater._safe_operation_telemetry_detail(
        RuntimeError("internal detail")
    ) == "non-operation exception redacted"


def test_default_open_disables_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []
    response = object()

    class _Opener:
        def open(self, request: object, *, timeout: float) -> object:
            assert request is sentinel_request
            assert timeout == 7.5
            return response

    def _build_opener(*handlers: object) -> _Opener:
        captured.extend(handlers)
        return _Opener()

    sentinel_request = object()
    monkeypatch.setattr(updater.urllib.request, "build_opener", _build_opener)

    assert updater._default_open(sentinel_request, 7.5) is response  # type: ignore[arg-type]
    assert len(captured) == 2
    assert isinstance(captured[0], updater.urllib.request.ProxyHandler)
    assert captured[0].proxies == {}
    assert isinstance(captured[1], updater._StrictRedirectHandler)


def test_download_redirects_are_limited_to_github_release_assets() -> None:
    source = "https://github.com/Bearer/bearer-rules/releases/download/v0.48.4/go.tar.gz"
    release = "https://release-assets.githubusercontent.com/github-production-release-asset/exact?sig=short-lived"

    assert updater._admitted_download_transition(source, release)
    assert updater._admitted_download_transition(release, release)
    assert not updater._admitted_download_transition(source, "https://example.com/go.tar.gz")
    assert not updater._admitted_download_transition(source, "http://release-assets.githubusercontent.com/go.tar.gz")
    assert not updater._admitted_download_transition(source, "https://user@release-assets.githubusercontent.com/go.tar.gz")


def test_release_location_parser_requires_one_exact_302_handoff() -> None:
    source = "https://github.com/Bearer/bearer-rules/releases/download/v0.48.4/go.tar.gz"
    release = "https://release-assets.githubusercontent.com/github-production-release-asset/exact?sig=short-lived"
    headers = f"HTTP/2 302\r\nlocation: {release}\r\ncontent-length: 0\r\n\r\n".encode()

    assert updater._parse_release_location(source, headers) == release
    with pytest.raises(Exception, match="unapproved redirect"):
        updater._parse_release_location(
            source,
            b"HTTP/2 302\r\nlocation: https://example.invalid/asset\r\n\r\n",
        )
    with pytest.raises(Exception, match="one exact release redirect"):
        updater._parse_release_location(source, b"HTTP/2 200\r\n\r\n")


def _request(
    *,
    operation_id: UUID | None = None,
    kind: str = "cache_update",
    components: list[str] | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    issued_at: datetime = MOMENT,
) -> OperationRequest:
    requested = ["bearer-rules"] if components is None else components
    operation_id = operation_id or uuid4()
    budget = issue_budget(now=issued_at).model_copy(update={"preparation_id": str(operation_id)}) if kind != "cache_rollback" else None
    version = 2 if budget is not None else 1
    digest = operation_request_digest(
        schema_version=version,
        preparation_budget=budget,
        kind=kind,  # type: ignore[arg-type]
        requested_components=requested,
    )
    return OperationRequest.model_validate(
        {
            "schema_version": version,
            **({"preparation_budget": budget.model_dump()} if budget is not None else {}),
            "operation_id": str(operation_id),
            "request_digest": digest,
            "kind": kind,
            "requested_components": requested,
            "attempt": attempt,
            "max_attempts": max_attempts,
        }
    )


def _catalog() -> CatalogOperationResult:
    versions = {tool.id: tool.version for tool in TOOLS.value.tools}
    return CatalogOperationResult(
        kind="catalog",
        checked_at=NOW,
        tools=[
            CatalogToolResult(
                tool_id=tool_id,
                state="current",
                installed_version=versions[tool_id],
            )
            for tool_id in CATALOG_TOOL_IDS
        ],
        components=[
            CatalogComponentResult(component_id=component_id, state="unavailable")
            for component_id in CACHE_COMPONENT_IDS
        ],
    )


def _completed_catalog_record(
    operation_id: UUID,
    *,
    finished_at: str = NOW,
    updated_at: str | None = None,
) -> updater.OperationRecord:
    request = _request(
        operation_id=operation_id,
        kind="catalog_check",
        components=[],
    )
    return updater.OperationRecord(
        schema_version=request.schema_version,
        preparation_budget=request.preparation_budget,
        operation_id=operation_id,
        request_digest=request.request_digest,
        kind="catalog_check",
        requested_components=[],
        status="completed",
        stage="completed",
        attempt=1,
        max_attempts=3,
        cancel_requested_at=None,
        created_at=finished_at,
        started_at=finished_at,
        finished_at=finished_at,
        updated_at=updated_at or finished_at,
        result=_catalog(),
        error_code=None,
        error_detail=None,
    )


def _ledger_operation_names(store: OperationStore) -> set[str]:
    return {
        entry.name
        for entry in store.operations_path.iterdir()
        if updater._OPERATION_FILE.fullmatch(entry.name)
    }


def _bearer_generation_manifest(content: bytes) -> GenerationManifest:
    expected = RULES.value.rule_set("bearer-rules").canaries[0]
    receipt = CacheComponentReceipt(
        component_id="bearer-rules",
        tool_id="bearer",
        kind="rules",
        root="bearer/rules",
        immutable_ref="30a6919acec715bf915ff4704d1b4ffeac998eab",
        source_sha256="1e58ac09b18435ed53e57fc67f1d31af6c13e17776469a8f1fe8995f40f1a0e1",
        updated_at=NOW,
        expires_at=None,
        files=[
            CacheFileRecord(
                path="bearer/rules/python.yml",
                size_bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        ],
        canaries=[
            CanaryReceipt(
                canary_id=expected.id,
                fixture_sha256=expected.fixture_sha256,
                output_sha256=expected.output_sha256,
                exit_code=expected.expected_exit_code,
                result_count=expected.expected_result_count,
                expected_ids=sorted(expected.expected_rule_ids),
                observed_ids=sorted(expected.expected_rule_ids),
                passed=True,
            )
        ],
    )
    manifest = GenerationManifest.create(
        tool_lock_sha256=TOOLS.sha256,
        rules_lock_sha256=RULES.sha256,
        created_at=NOW,
        components=[receipt],
    )
    return manifest


def _data_candidate(
    *,
    updated_at: str,
    expires_at: str,
    component_id: str = "trivy-db",
) -> SimpleNamespace:
    tool, requirement = next(
        (tool, requirement)
        for tool in TOOLS.value.tools
        for requirement in tool.requirements
        if requirement.id == component_id
    )
    receipt = SimpleNamespace(
        component_id=requirement.id,
        tool_id=tool.id,
        kind=requirement.kind,
        root=requirement.cache_subpath,
        immutable_ref=requirement.source.immutable_ref,
        source_sha256=requirement.source.sha256,
        updated_at=updated_at,
        expires_at=expires_at,
        canaries=[
            SimpleNamespace(
                canary_id=expected.id,
                fixture_sha256=expected.fixture_sha256,
                output_sha256=expected.output_sha256,
                exit_code=expected.expected_exit_code,
                result_count=expected.expected_result_count,
                expected_ids=expected.expected_ids,
                observed_ids=expected.expected_ids,
            )
            for expected in requirement.canaries
        ],
    )
    return SimpleNamespace(
        manifest=SimpleNamespace(
            tool_lock_sha256=TOOLS.sha256,
            rules_lock_sha256=RULES.sha256,
            components=[receipt],
        )
    )


def _timestamp_tools(candidate):
    """Synthetic publisher dates for isolated admission-boundary controls."""
    receipts = {r.component_id: r for r in candidate.manifest.components}
    payload = TOOLS.value.model_dump(mode="json")
    for tool in payload["tools"]:
        for requirement in tool["requirements"]:
            receipt = receipts.get(requirement["id"])
            contract = requirement.get("data_contract")
            if receipt is None or contract is None:
                continue
            if contract["kind"] in {"trivy-db-metadata/v2", "trivy-java-db-metadata/v1"}:
                interval = updater._parse_utc(contract["publisher_refresh_due_at"], "due") - updater._parse_utc(contract["publisher_updated_at"], "updated")
                contract["publisher_updated_at"] = receipt.updated_at
                contract["publisher_refresh_due_at"] = updater._timestamp_plus(receipt.updated_at, interval.total_seconds())
            elif contract["kind"] == "grype-db-metadata/v1":
                contract["built_at"] = receipt.updated_at
    return SimpleNamespace(value=cache_manifest.ToolLockFile.model_validate(payload), sha256=TOOLS.sha256)


@pytest.mark.parametrize(
    ("updated_at", "expires_at", "error"),
    [
        ("2026-07-29T21:00:00Z", NOW, "residual freshness window is insufficient"),
        (
            "2026-07-29T21:05:00Z",
            "2026-08-12T21:05:00Z",
            "residual freshness window is insufficient",
        ),
        (
            "2026-08-12T21:05:00.000001Z",
            "2026-08-26T21:05:00.000001Z",
            "timestamp is in the future",
        ),
        (
            "2026-08-12T20:00:00Z",
            "2026-08-26T20:00:00.000001Z",
            "freshness differs from its lock",
        ),
    ],
)
def test_candidate_validation_rejects_runtime_unready_timestamps(
    monkeypatch: pytest.MonkeyPatch,
    updated_at: str,
    expires_at: str,
    error: str,
) -> None:
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )

    candidate = _data_candidate(updated_at=updated_at, expires_at=expires_at)
    with pytest.raises(updater.OperationError, match=error):
        updater._validate_candidate_components(
            candidate,
            ["trivy-db"],
            _timestamp_tools(candidate),
            RULES,
            evaluated_at=MOMENT,
        )


def test_candidate_validation_accepts_exact_admission_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )

    candidate = _data_candidate(updated_at="2026-08-12T21:05:00Z",
                                expires_at="2026-08-26T21:05:00Z")
    updater._validate_candidate_components(
        candidate,
        ["trivy-db"],
        _timestamp_tools(candidate),
        RULES,
        evaluated_at=MOMENT,
    )


@pytest.mark.parametrize(
    ("updated", "expires", "expected"),
    [
        pytest.param(
            MOMENT + timedelta(minutes=5),
            MOMENT + timedelta(days=1),
            False,
            id="future-exact-skew-boundary",
        ),
        pytest.param(
            MOMENT + timedelta(minutes=5, microseconds=1),
            MOMENT + timedelta(days=1),
            True,
            id="future-beyond-skew-boundary",
        ),
        pytest.param(
            MOMENT - timedelta(days=1),
            MOMENT,
            True,
            id="expired",
        ),
        pytest.param(
            MOMENT - timedelta(days=1),
            MOMENT + timedelta(minutes=5),
            True,
            id="exact-activation-margin",
        ),
        pytest.param(
            MOMENT - timedelta(days=1),
            MOMENT + timedelta(minutes=5, microseconds=1),
            False,
            id="above-activation-margin",
        ),
        pytest.param(
            MOMENT - timedelta(days=1),
            MOMENT + timedelta(days=1),
            False,
            id="exact-reviewed-window",
        ),
        pytest.param(
            MOMENT - timedelta(days=1),
            MOMENT + timedelta(days=1, microseconds=1),
            True,
            id="overlong-reviewed-window",
        ),
    ],
)
def test_intrinsic_catalog_lock_refresh_boundaries(
    updated: datetime,
    expires: datetime,
    expected: bool,
) -> None:
    assert updater._intrinsic_freshness_window_is_temporally_unusable(
        updated,
        expires,
        2 * 24 * 60 * 60,
        MOMENT,
    ) is expected


def test_candidate_validation_rejects_stale_carried_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )
    requested = _data_candidate(
        component_id="trivy-java-db",
        updated_at="2026-08-12T20:00:00Z",
        expires_at="2026-08-26T20:00:00Z",
    ).manifest.components[0]
    carried = _data_candidate(
        updated_at="2026-07-29T21:00:00Z",
        expires_at=NOW,
    ).manifest.components[0]
    candidate = SimpleNamespace(
        manifest=SimpleNamespace(
            tool_lock_sha256=TOOLS.sha256,
            rules_lock_sha256=RULES.sha256,
            components=[carried, requested],
        )
    )

    with pytest.raises(updater.OperationError, match="residual freshness window"):
        updater._validate_candidate_components(
            candidate,
            ["trivy-java-db"],
            _timestamp_tools(candidate),
            RULES,
            evaluated_at=MOMENT,
        )


def test_rollback_eligibility_reports_different_reviewed_locks_before_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_generation = "b" * 64
    monkeypatch.setattr(
        updater,
        "load_active_pointer",
        lambda _cache_root: SimpleNamespace(
            previous_good=SimpleNamespace(
                generation_id=target_generation,
                manifest_sha256="c" * 64,
            )
        ),
    )
    monkeypatch.setattr(
        updater,
        "validate_generation",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=tmp_path / "cache" / "generations" / target_generation,
            manifest=SimpleNamespace(
                tool_lock_sha256="0" * 64,
                rules_lock_sha256=RULES.sha256,
                components=[],
            )
        ),
    )
    monkeypatch.setattr(
        updater,
        "_validate_component_receipts",
        lambda *_args, **_kwargs: pytest.fail(
            "lock-incompatible rollback reached component validation"
        ),
    )

    eligibility = updater.evaluate_cache_rollback_eligibility(
        tmp_path / "cache",
        TOOLS,
        RULES,
        evaluated_at=MOMENT,
    )

    assert eligibility.model_dump(mode="json") == {
        "eligible": False,
        "reason_code": "different_reviewed_locks",
        "reason": "The previous cache generation's signed scanner data authority is unavailable or invalid.",
        "target_generation": target_generation,
    }


@pytest.mark.parametrize("failure_code", ["deadline", "integrity"])
def test_rollback_eligibility_distinguishes_timeout_from_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_code: str,
) -> None:
    target = "b" * 64
    monkeypatch.setattr(
        updater, "load_active_pointer",
        lambda _root: SimpleNamespace(previous_good=SimpleNamespace(
            generation_id=target, manifest_sha256="c" * 64,
        )),
    )

    def rejected_validation(*_args: object, **_kwargs: object) -> None:
        raise updater.GrypeContentValidationError(failure_code)

    monkeypatch.setattr(updater, "validate_generation", rejected_validation)
    eligibility = updater.evaluate_cache_rollback_eligibility(
        tmp_path / "cache", TOOLS, RULES, evaluated_at=MOMENT,
    )

    assert eligibility.eligible is False
    assert eligibility.target_generation == target
    if failure_code == "deadline":
        assert eligibility.reason_code == "previous_generation_verification_timeout"
        assert eligibility.reason == (
            "Verification of the previous scanner cache generation timed out. "
            "Refresh scanner status to retry; no cache state was changed."
        )
    else:
        assert eligibility.reason_code == "previous_generation_invalid"
        assert "failed integrity validation" in eligibility.reason
    assert list(tmp_path.iterdir()) == []


def test_candidate_validation_rejects_future_rule_timestamp() -> None:
    manifest = _bearer_generation_manifest(b"id: reviewed-rule\n")
    future_receipt = manifest.components[0].model_copy(
        update={"updated_at": "2026-08-12T21:05:00.000001Z"}
    )
    candidate = SimpleNamespace(
        manifest=SimpleNamespace(
            tool_lock_sha256=TOOLS.sha256,
            rules_lock_sha256=RULES.sha256,
            components=[future_receipt],
        )
    )

    with pytest.raises(updater.OperationError, match="timestamp is in the future"):
        updater._validate_candidate_components(
            candidate,
            ["bearer-rules"],
            TOOLS,
            RULES,
            evaluated_at=MOMENT,
        )


def test_candidate_expiring_during_final_validation_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-db"])
    active_manifest = _prepare_generation(store.cache_root, uuid4())
    activate_generation(
        store.cache_root,
        active_manifest.generation_id,
        str(uuid4()),
        activated_at="2026-08-12T20:30:00Z",
    )
    active_before = (store.cache_root / "active.json").read_bytes()
    candidate = _data_candidate(
        updated_at="2026-07-29T21:00:00Z",
        expires_at=NOW,
    )
    publication_started = False
    # The sole semantic check now runs after activation's final structural
    # walk. An expired candidate must fail at that publication fence.
    evaluation_times = iter((MOMENT,))

    monkeypatch.setattr(updater, "validate_generation", lambda *_args, **_kwargs: candidate)
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )

    def delayed_activation(
        *_args: object,
        prepare_publication: object,
        **_kwargs: object,
    ) -> object:
        nonlocal publication_started
        guard = prepare_publication
        guard(candidate)  # type: ignore[operator]
        publication_started = True
        raise AssertionError("an expired candidate reached pointer publication")

    monkeypatch.setattr(updater, "activate_generation", delayed_activation)

    failed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        cache_update=lambda _context: "f" * 64,
        now=lambda: NOW,
        evaluation_now=lambda: next(evaluation_times),
    )

    assert failed.status == "failed"
    assert failed.error_code == "operation_failed"
    assert publication_started is False
    assert (store.cache_root / "active.json").read_bytes() == active_before


def test_fresh_boundary_candidate_passes_final_publication_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-db"])
    active_manifest = _prepare_generation(store.cache_root, uuid4())
    active_pointer = activate_generation(
        store.cache_root,
        active_manifest.generation_id,
        str(uuid4()),
        activated_at="2026-08-12T20:30:00Z",
    )
    candidate = _data_candidate(
        updated_at="2026-08-12T21:05:00Z",
        expires_at="2026-08-26T21:05:00Z",
    )
    activated = False

    monkeypatch.setattr(updater, "validate_generation", lambda *_args, **_kwargs: candidate)
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )

    def observe_activation(
        *_args: object,
        prepare_publication: object,
        **_kwargs: object,
    ) -> object:
        nonlocal activated
        guard = prepare_publication
        guard(candidate)  # type: ignore[operator]
        activated = True
        return active_pointer

    monkeypatch.setattr(updater, "activate_generation", observe_activation)

    completed = execute_operation(
        request,
        _timestamp_tools(candidate),
        RULES,
        store,
        cache_update=lambda _context: "f" * 64,
        now=lambda: NOW,
        evaluation_now=lambda: MOMENT,
    )

    assert completed.status == "completed"
    assert activated is True


def test_cache_update_uses_one_final_target_walk_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    outer_walks: list[str] = []
    final_walks: list[str] = []
    original_outer = updater.validate_generation
    original_final = cache_manifest.validate_generation

    def observe_outer(root: Path, generation_id: str, **kwargs: object):
        outer_walks.append(generation_id)
        return original_outer(root, generation_id, **kwargs)

    def observe_final(root: Path, generation_id: str, **kwargs: object):
        final_walks.append(generation_id)
        return original_final(root, generation_id, **kwargs)

    monkeypatch.setattr(updater, "validate_generation", observe_outer)
    monkeypatch.setattr(cache_manifest, "validate_generation", observe_final)
    completed = execute_operation(
        request, TOOLS, RULES, store,
        cache_update=lambda _context: manifest.generation_id,
        now=lambda: NOW, evaluation_now=lambda: MOMENT,
    )
    assert completed.status == "completed"
    assert outer_walks == []
    assert final_walks == [manifest.generation_id]
    pointer = cache_manifest.load_active_pointer(store.cache_root)
    assert pointer.active.generation_id == manifest.generation_id
    assert pointer.previous_good is None


def test_cache_update_rejects_custom_missing_target_without_pointer(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    failed = execute_operation(
        request, TOOLS, RULES, store,
        cache_update=lambda _context: "f" * 64,
        now=lambda: NOW, evaluation_now=lambda: MOMENT,
    )
    assert failed.status == "failed"
    assert failed.result is None
    assert not (store.cache_root / "active.json").exists()


def test_cache_update_same_operation_replay_checks_semantics_without_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    activate_generation(
        store.cache_root, manifest.generation_id, str(request.operation_id),
        activated_at=NOW,
    )
    pointer_before = (store.cache_root / "active.json").read_bytes()
    semantic_calls = 0
    transitions: list[str] = []
    original_transition = OperationStore.transition

    def refuse_semantics(*_args: object, **_kwargs: object) -> None:
        nonlocal semantic_calls
        semantic_calls += 1
        raise updater.OperationError("replay candidate no longer matches reviewed locks")

    def record_transition(self: OperationStore, *args: object, **kwargs: object):
        if isinstance(kwargs.get("stage"), str):
            transitions.append(kwargs["stage"])  # type: ignore[arg-type]
        return original_transition(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(updater, "_validate_candidate_components", refuse_semantics)
    monkeypatch.setattr(OperationStore, "transition", record_transition)
    failed = execute_operation(
        request, TOOLS, RULES, store,
        cache_update=lambda _context: manifest.generation_id,
        now=lambda: NOW, evaluation_now=lambda: MOMENT,
    )
    assert failed.status == "failed"
    assert semantic_calls == 1
    assert "committing" not in transitions
    assert (store.cache_root / "active.json").read_bytes() == pointer_before


@pytest.mark.parametrize("target", ["manifest", "content"])
def test_cache_update_rejects_target_tampering_before_final_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    target_root = store.cache_root / "generations" / manifest.generation_id
    original_activation = updater.activate_generation

    def mutate_before_activation(*args: object, **kwargs: object):
        path = (target_root / "manifest.json" if target == "manifest"
                else target_root / "bearer/rules/python.yml")
        path.chmod(0o600)
        path.write_bytes(b"changed-after-publication")
        path.chmod(0o400)
        return original_activation(*args, **kwargs)

    monkeypatch.setattr(updater, "activate_generation", mutate_before_activation)
    failed = execute_operation(
        request, TOOLS, RULES, store,
        cache_update=lambda _context: manifest.generation_id,
        now=lambda: NOW, evaluation_now=lambda: MOMENT,
    )
    assert failed.status == "failed"
    assert failed.result is None
    assert not (store.cache_root / "active.json").exists()


def test_cancellation_between_final_checkpoint_and_commit_prevents_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    original_validation = updater._validate_candidate_components
    validation_calls = 0
    publication_started = False

    def request_cancellation_during_final_validation(
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal validation_calls
        validation_calls += 1
        original_validation(*args, **kwargs)  # type: ignore[arg-type]
        if validation_calls == 1:
            store.request_cancel(
                request.operation_id,
                request_digest=request.request_digest,
                now=NOW,
            )

    def guarded_activation(
        *_args: object,
        prepare_publication: object,
        **_kwargs: object,
    ) -> object:
        nonlocal publication_started
        candidate = validate_generation(store.cache_root, manifest.generation_id)
        guard = prepare_publication
        guard(candidate)  # type: ignore[operator]
        publication_started = True
        raise AssertionError("cancelled operation reached pointer publication")

    monkeypatch.setattr(
        updater,
        "_validate_candidate_components",
        request_cancellation_during_final_validation,
    )
    monkeypatch.setattr(updater, "activate_generation", guarded_activation)

    cancelled = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        cache_update=lambda _context: manifest.generation_id,
        now=lambda: NOW,
        evaluation_now=lambda: MOMENT,
    )

    assert cancelled.status == "cancelled"
    assert validation_calls == 1
    assert publication_started is False
    assert not (store.cache_root / "active.json").exists()


def test_previous_good_expiring_during_final_validation_never_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(kind="cache_rollback", components=[])
    first = _prepare_generation(store.cache_root, uuid4())
    activate_generation(
        store.cache_root,
        first.generation_id,
        str(uuid4()),
        activated_at="2026-08-12T20:15:00Z",
    )
    second = _prepare_generation(
        store.cache_root,
        uuid4(),
        content=b"id: reviewed-rule-v2\n",
    )
    activate_generation(
        store.cache_root,
        second.generation_id,
        str(uuid4()),
        activated_at="2026-08-12T20:30:00Z",
    )
    active_before = (store.cache_root / "active.json").read_bytes()
    candidate = _data_candidate(
        updated_at="2026-07-29T21:00:00Z",
        expires_at=NOW,
    )
    publication_started = False
    evaluation_times = iter((BEFORE_MOMENT, MOMENT))
    monkeypatch.setattr(updater, "validate_generation", lambda *_args, **_kwargs: candidate)
    monkeypatch.setattr(
        updater,
        "receipt_matches_installed_content",
        lambda *_args: True,
    )

    def delayed_rollback(
        *_args: object,
        prepare_publication: object,
        **_kwargs: object,
    ) -> object:
        nonlocal publication_started
        guard = prepare_publication
        guard(candidate)  # type: ignore[operator]
        publication_started = True
        raise AssertionError("an expired previous-good generation reached publication")

    monkeypatch.setattr(updater, "rollback_to_previous_good", delayed_rollback)

    failed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        now=lambda: NOW,
        evaluation_now=lambda: next(evaluation_times),
    )

    assert failed.status == "failed"
    assert failed.error_code == "operation_failed"
    assert publication_started is False
    assert (store.cache_root / "active.json").read_bytes() == active_before


def _prepare_generation(
    cache_root: Path,
    operation_id: UUID,
    *,
    content: bytes = b"id: reviewed-rule\n",
) -> GenerationManifest:
    cache_root.mkdir(mode=0o700, exist_ok=True)
    generations = cache_root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    stage = generations / f"stage-{operation_id}"
    payload = stage / "bearer" / "rules" / "python.yml"
    payload.parent.mkdir(parents=True, mode=0o700)
    payload.write_bytes(content)
    payload.chmod(0o600)
    manifest = _bearer_generation_manifest(content)
    destination = generations / manifest.generation_id
    stage.rename(destination)
    write_generation_manifest(destination, manifest)
    return manifest


def _prepare_active_and_orphan_generations(
    cache_root: Path,
) -> tuple[GenerationManifest, GenerationManifest]:
    active = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: active-generation\n",
    )
    activate_generation(
        cache_root,
        active.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: unreferenced-generation\n",
    )
    return active, orphan


@pytest.mark.parametrize("target_kind", ["active", "orphan"])
def test_grype_verification_timeout_aborts_pruning_without_deleting_generations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_kind: str,
) -> None:
    root = tmp_path / "cache"
    active, orphan = _prepare_active_and_orphan_generations(root)
    target = active if target_kind == "active" else orphan
    pointer_before = (root / "active.json").read_bytes()
    manifests_before = {
        item.generation_id: (root / "generations" / item.generation_id / "manifest.json").read_bytes()
        for item in (active, orphan)
    }
    original_validate = updater.validate_generation
    failure = updater.GrypeContentValidationError("deadline")

    def timed_out_validation(cache_root: Path, generation_id: str, **kwargs: object):
        if generation_id == target.generation_id:
            raise failure
        return original_validate(cache_root, generation_id, **kwargs)

    monkeypatch.setattr(updater, "validate_generation", timed_out_validation)
    with updater.generation_lock(root):
        with pytest.raises(updater.GrypeContentValidationError) as raised:
            updater._prune_unreferenced_generations(root)

    assert raised.value is failure
    assert (root / "active.json").read_bytes() == pointer_before
    assert {item.name for item in (root / "generations").iterdir()} == set(manifests_before)
    for generation_id, content in manifests_before.items():
        assert (root / "generations" / generation_id / "manifest.json").read_bytes() == content
        assert (root / "generations" / generation_id / "bearer/rules/python.yml").is_file()
    assert list((root / "tombstones").iterdir()) == []


def test_generation_pruning_bounds_repeated_updates_and_preserves_rollback(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    first = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: reviewed-rule-v1\n",
    )
    activate_generation(
        cache_root,
        first.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    second = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: reviewed-rule-v2\n",
    )
    activate_generation(
        cache_root,
        second.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    third = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: reviewed-rule-v3\n",
    )
    activate_generation(
        cache_root,
        third.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )

    with updater.generation_lock(cache_root):
        removed = updater._prune_unreferenced_generations(cache_root)

    assert removed == [first.generation_id]
    generations = cache_root / "generations"
    assert {path.name for path in generations.iterdir()} == {
        second.generation_id,
        third.generation_id,
    }

    with updater.generation_lock(cache_root):
        pointer = updater.rollback_to_previous_good(
            cache_root,
            str(uuid4()),
            activated_at=NOW,
        )
        assert updater._prune_unreferenced_generations(cache_root) == []

    assert pointer.active.generation_id == second.generation_id
    assert pointer.previous_good is not None
    assert pointer.previous_good.generation_id == third.generation_id
    assert {path.name for path in generations.iterdir()} == {
        second.generation_id,
        third.generation_id,
    }


def test_retained_only_startup_skips_payload_validation_but_never_skips_delete_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cache"
    previous = _prepare_generation(root, uuid4(), content=b"id: previous\n")
    activate_generation(root, previous.generation_id, str(uuid4()), activated_at=NOW)
    active = _prepare_generation(root, uuid4(), content=b"id: active\n")
    activate_generation(root, active.generation_id, str(uuid4()), activated_at=NOW)
    pointer_before = (root / "active.json").read_bytes()
    validated: list[str] = []
    original_validate = updater.validate_generation

    def observed_validation(cache_root: Path, generation_id: str, **kwargs: object):
        validated.append(generation_id)
        return original_validate(cache_root, generation_id, **kwargs)

    monkeypatch.setattr(updater, "validate_generation", observed_validation)
    assert OperationStore(root).recover_interrupted(now=NOW) == []
    assert validated == []
    assert (root / "active.json").read_bytes() == pointer_before
    assert {entry.name for entry in (root / "generations").iterdir()} == {
        previous.generation_id, active.generation_id,
    }
    # The no-deletion shortcut does not skip sealed ownership/type/link checks.
    payload = root / "generations" / previous.generation_id / "bearer/rules/python.yml"
    payload.chmod(0o600)
    with pytest.raises(updater.OperationError, match="referenced generation is invalid"):
        OperationStore(root).recover_interrupted(now=NOW)
    assert validated == []
    payload.write_bytes(b"id: corrupt previous\n")
    payload.chmod(0o400)
    orphan = _prepare_generation(root, uuid4(), content=b"id: preserved orphan\n")
    with pytest.raises(updater.OperationError, match="referenced generation is invalid"):
        OperationStore(root).recover_interrupted(now=NOW)
    assert previous.generation_id in validated
    assert orphan.generation_id not in validated
    assert (root / "generations" / orphan.generation_id).is_dir()
    assert (root / "active.json").read_bytes() == pointer_before
    assert list((root / "tombstones").iterdir()) == []


def test_generation_pruning_retains_in_progress_staging_and_never_follows_aliases(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    _active, orphan = _prepare_active_and_orphan_generations(cache_root)
    operation_stage = cache_root / "staging" / str(uuid4())
    operation_stage.mkdir(mode=0o700, parents=True)
    (operation_stage / "partial").write_bytes(b"in progress")

    with updater.generation_lock(cache_root):
        assert updater._prune_unreferenced_generations(cache_root) == [
            orphan.generation_id
        ]

    assert operation_stage.is_dir()
    assert (operation_stage / "partial").read_bytes() == b"in progress"

    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_bytes(b"preserved")
    generations = cache_root / "generations"
    blocked_orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: retained-when-any-entry-is-unsafe\n",
    )
    alias = generations / ("f" * 64)
    alias.symlink_to(outside, target_is_directory=True)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="unsafe entry"):
            updater._prune_unreferenced_generations(cache_root)

    assert alias.is_symlink()
    assert marker.read_bytes() == b"preserved"
    assert (generations / blocked_orphan.generation_id).is_dir()


def test_cache_update_prunes_then_preflights_capacity_before_staging_or_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    active = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: carried-active-generation\n",
    )
    activate_generation(
        cache_root,
        active.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=cache_root,
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: datetime.fromisoformat(
            TOOLS.value.tool("trivy").requirements[0].data_contract.publisher_updated_at
        ),
    )
    request = _request(components=["trivy-db"])
    events: list[str] = []
    original_resolve = updater.resolve_active_generation

    def observe_resolve(*args: object, **kwargs: object) -> ResolvedGeneration:
        events.append("resolve")
        return original_resolve(*args, **kwargs)  # type: ignore[arg-type]

    def observe_prune(*_args: object, **_kwargs: object) -> list[str]:
        events.append("prune")
        return []

    def reject_capacity(*_args: object, **_kwargs: object) -> None:
        events.append("capacity")
        assert list((cache_root / "staging").iterdir()) == []
        raise updater.OperationCapacityError("simulated constrained capacity")

    def forbidden_work(*_args: object, **_kwargs: object) -> None:
        events.append("forbidden-work")

    monkeypatch.setattr(updater, "resolve_active_generation", observe_resolve)
    monkeypatch.setattr(updater, "_prune_unreferenced_generations", observe_prune)
    monkeypatch.setattr(updater, "_data_update_capacity_preflight", reject_capacity)
    monkeypatch.setattr(updater, "_copy_validated_component", forbidden_work)
    monkeypatch.setattr(updater, "_run_data_command", forbidden_work)
    context = SimpleNamespace(
        request=request,
        checkpoint=lambda: None,
        progress=lambda *_args, **_kwargs: events.append("progress"),
        byte_progress=lambda *_args, **_kwargs: None,
    )

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationCapacityError, match="constrained capacity"):
            handlers.cache_update(context)  # type: ignore[arg-type]

    assert [event for event in events if event != "progress"] == ["resolve", "prune", "capacity"]
    assert list((cache_root / "staging").iterdir()) == []


def test_grype_capacity_preflight_reserves_its_transient_import_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = TOOLS.value.tool("grype").requirements[0]
    requirements = {"grype-db": ("grype", requirement)}
    resolved = ResolvedGeneration(
        state="unavailable",
        generation=None,
        pointer=None,
    )
    installed = int(requirement.installed_size_bytes or 0)
    download = int(requirement.source.size_bytes or 0)
    required = (
        installed
        + download
        + installed
        + updater.MIN_DATA_UPDATE_MARGIN_BYTES
    )

    monkeypatch.setattr(
        updater.os,
        "statvfs",
        lambda _root: SimpleNamespace(f_bavail=required - 1, f_frsize=1),
    )
    with pytest.raises(updater.OperationCapacityError, match="safe staging capacity"):
        updater._data_update_capacity_preflight(
            tmp_path,
            resolved,
            ["grype-db"],
            requirements,
        )

    monkeypatch.setattr(
        updater.os,
        "statvfs",
        lambda _root: SimpleNamespace(f_bavail=required, f_frsize=1),
    )
    updater._data_update_capacity_preflight(
        tmp_path,
        resolved,
        ["grype-db"],
        requirements,
    )


def test_partial_cache_update_reports_retained_and_requested_component_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    active = _prepare_generation(cache_root, uuid4())
    activate_generation(
        cache_root,
        active.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=cache_root,
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: MOMENT,
    )
    request = _request(components=["opengrep-reviewed-rules"])
    events: list[tuple[str, dict[str, object]]] = []
    current_activity: dict[str, object] = {}

    class StopAfterRetention(RuntimeError):
        pass

    class Context:
        def __init__(self) -> None:
            self.request = request

        def checkpoint(self) -> None:
            return None

        def progress(self, stage: str, **details: object) -> None:
            current_activity.clear()
            current_activity.update(details)
            events.append((stage, dict(details)))
            if (
                stage == "downloading"
                and details.get("component_id") == "opengrep-reviewed-rules"
            ):
                raise StopAfterRetention()

        def byte_progress(
            self,
            completed: int,
            total: int,
            *,
            force: bool = False,
        ) -> None:
            events.append(
                (
                    "bytes",
                    {
                        **current_activity,
                        "completed": completed,
                        "total": total,
                        "force": force,
                    },
                )
            )

    monkeypatch.setattr(updater, "_data_update_capacity_preflight", lambda *_args: None)

    with updater.generation_lock(cache_root):
        with pytest.raises(StopAfterRetention):
            handlers.cache_update(Context())  # type: ignore[arg-type]

    retained = [details for stage, details in events if stage == "retaining"]
    assert retained == [
        {
            "component_id": "bearer-rules",
            "component_index": 1,
            "component_total": 1,
        }
    ]
    retained_bytes = [
        details
        for stage, details in events
        if stage == "bytes" and details.get("component_id") == "bearer-rules"
    ]
    assert retained_bytes[0]["completed"] == 0
    assert retained_bytes[-1]["completed"] == retained_bytes[-1]["total"]
    assert any(
        stage == "downloading"
        and details.get("component_id") == "opengrep-reviewed-rules"
        for stage, details in events
    )


def test_no_pointer_crash_orphan_is_pruned_before_startup_and_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    store = OperationStore(cache_root)
    startup_orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: crash-before-first-pointer-startup\n",
    )
    assert not (cache_root / "active.json").exists()

    assert store.recover_interrupted() == []
    assert not (cache_root / "generations" / startup_orphan.generation_id).exists()

    capacity_orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: crash-before-first-pointer-capacity\n",
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=cache_root,
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: datetime.fromisoformat(
            TOOLS.value.tool("trivy").requirements[0].data_contract.publisher_updated_at
        ),
    )
    events: list[str] = []

    def reject_capacity(*_args: object, **_kwargs: object) -> None:
        assert not (
            cache_root / "generations" / capacity_orphan.generation_id
        ).exists()
        events.append("capacity")
        raise updater.OperationCapacityError("simulated constrained first install")

    def forbidden_work(*_args: object, **_kwargs: object) -> None:
        events.append("forbidden-work")

    monkeypatch.setattr(updater, "_data_update_capacity_preflight", reject_capacity)
    monkeypatch.setattr(updater, "_run_data_command", forbidden_work)
    monkeypatch.setattr(updater, "_download_direct_locked_asset", forbidden_work)
    request = _request(components=["trivy-db"])
    context = SimpleNamespace(
        request=request,
        checkpoint=lambda: None,
        progress=lambda *_args, **_kwargs: events.append("progress"),
    )

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationCapacityError, match="constrained first install"):
            handlers.cache_update(context)  # type: ignore[arg-type]

    assert events == ["capacity"]
    assert not (cache_root / "active.json").exists()
    assert list((cache_root / "generations").iterdir()) == []
    assert list((cache_root / "staging").iterdir()) == []


def test_restart_recovery_retires_only_a_missing_previous_good(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    previous_good = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: previous-good\n",
    )
    activate_generation(
        cache_root,
        previous_good.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    active = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: current-active\n",
    )
    pointer = activate_generation(
        cache_root,
        active.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    assert pointer.previous_good is not None
    dangling = pointer.model_copy(
        update={
            "previous_good": updater.GenerationReference(
                generation_id="f" * 64,
                manifest_sha256="e" * 64,
            )
        }
    )
    updater._atomic_write_json(
        cache_root,
        "active.json",
        dangling.model_dump(mode="json"),
        updater.MAX_ACTIVE_POINTER_BYTES,
    )

    assert OperationStore(cache_root).recover_interrupted(now=NOW) == []

    repaired = updater.load_active_pointer(cache_root)
    assert repaired.revision == pointer.revision + 1
    assert repaired.active == pointer.active
    assert repaired.previous_good is None
    assert validate_generation(
        cache_root,
        repaired.active.generation_id,
        expected_manifest_sha256=repaired.active.manifest_sha256,
    ).manifest.generation_id == active.generation_id


def test_no_pointer_pruning_stops_if_a_pointer_appears_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: pointer-race-orphan\n",
    )
    pointer_path = cache_root / "active.json"
    appeared = tmp_path / "appeared-pointer-metadata"
    appeared.write_bytes(b"appeared")
    appeared.chmod(0o600)
    original_lstat = updater._prune_lstat
    pointer_checks = 0

    def pointer_appears(path: Path):
        nonlocal pointer_checks
        if path != pointer_path:
            return original_lstat(path)
        pointer_checks += 1
        # Tombstone recovery and the prune snapshot both prove the pointer is
        # absent before candidates are validated. Make it appear only at the
        # final pre-delete fence.
        if pointer_checks <= 2:
            raise FileNotFoundError(pointer_path)
        return appeared.lstat()

    monkeypatch.setattr(updater, "_prune_lstat", pointer_appears)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="pointer appeared"):
            updater._prune_unreferenced_generations(
                cache_root,
                allow_missing_pointer=True,
            )

    assert pointer_checks == 3
    assert (cache_root / "generations" / orphan.generation_id).is_dir()


def test_mid_tombstone_delete_interruption_is_recovered_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    active, orphan = _prepare_active_and_orphan_generations(cache_root)
    original_delete = updater._delete_validated_generation_tree

    class SimulatedInterruption(RuntimeError):
        pass

    def interrupt_delete(
        parent: Path,
        generation_id: str,
        _identities: dict[str, tuple[int, ...]],
    ) -> None:
        assert parent == cache_root / "tombstones"
        assert generation_id == orphan.generation_id
        partial = parent / generation_id
        rules = partial / "bearer" / "rules"
        rules.chmod(0o700)
        (rules / "python.yml").unlink()
        raise SimulatedInterruption("simulated crash during recursive tombstone delete")

    monkeypatch.setattr(updater, "_delete_validated_generation_tree", interrupt_delete)

    with updater.generation_lock(cache_root):
        with pytest.raises(SimulatedInterruption, match="simulated crash"):
            updater._prune_unreferenced_generations(cache_root)

    generations = cache_root / "generations"
    tombstones = cache_root / "tombstones"
    assert not (generations / orphan.generation_id).exists()
    assert (tombstones / orphan.generation_id).is_dir()
    assert (tombstones / f"{orphan.generation_id}.json").is_file()
    assert (generations / active.generation_id).is_dir()

    monkeypatch.setattr(
        updater,
        "_delete_validated_generation_tree",
        original_delete,
    )
    store = OperationStore(cache_root)
    assert store.recover_interrupted() == []

    assert list(tombstones.iterdir()) == []
    validated = validate_generation(
        cache_root,
        active.generation_id,
    )
    assert validated.manifest.generation_id == active.generation_id


def test_receipt_only_tombstone_phase_is_recovered_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    active, orphan = _prepare_active_and_orphan_generations(cache_root)
    original_rename = updater.cache_repair.rename_exclusive

    def interrupt_before_rename(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated interruption before generation rename")

    monkeypatch.setattr(updater.cache_repair, "rename_exclusive", interrupt_before_rename)
    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="atomically tombstoned"):
            updater._prune_unreferenced_generations(cache_root)

    generations = cache_root / "generations"
    tombstones = cache_root / "tombstones"
    assert (generations / orphan.generation_id).is_dir()
    assert not (tombstones / orphan.generation_id).exists()
    assert (tombstones / f"{orphan.generation_id}.json").is_file()

    monkeypatch.setattr(updater.cache_repair, "rename_exclusive", original_rename)
    assert OperationStore(cache_root).recover_interrupted() == []

    assert list(tombstones.iterdir()) == []
    assert not (generations / orphan.generation_id).exists()
    assert (generations / active.generation_id).is_dir()


def test_renamed_unfsynced_tombstone_phase_is_recovered_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    active, orphan = _prepare_active_and_orphan_generations(cache_root)
    original_persist = updater._persist_tombstone_rename

    def interrupt_before_namespace_fsync(*_args: object) -> None:
        raise OSError("simulated interruption before tombstone namespace fsync")

    monkeypatch.setattr(
        updater,
        "_persist_tombstone_rename",
        interrupt_before_namespace_fsync,
    )
    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="atomically tombstoned"):
            updater._prune_unreferenced_generations(cache_root)

    generations = cache_root / "generations"
    tombstones = cache_root / "tombstones"
    assert not (generations / orphan.generation_id).exists()
    assert (tombstones / orphan.generation_id).is_dir()
    assert (tombstones / f"{orphan.generation_id}.json").is_file()

    monkeypatch.setattr(updater, "_persist_tombstone_rename", original_persist)
    assert OperationStore(cache_root).recover_interrupted() == []

    assert list(tombstones.iterdir()) == []
    assert not (generations / orphan.generation_id).exists()
    assert (generations / active.generation_id).is_dir()


def test_generation_pruning_refuses_a_corrupt_pointer_without_removing_orphan(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    _active, orphan = _prepare_active_and_orphan_generations(cache_root)
    pointer = cache_root / "active.json"
    pointer.write_text("{not-json", encoding="utf-8")
    pointer.chmod(0o600)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="pointer is invalid"):
            updater._prune_unreferenced_generations(
                cache_root,
                allow_missing_pointer=True,
            )

    assert (cache_root / "generations" / orphan.generation_id).is_dir()


def test_generation_pruning_validates_previous_good_before_removing_orphan(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    previous_good = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: previous-good\n",
    )
    activate_generation(
        cache_root,
        previous_good.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    active = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: current-active\n",
    )
    activate_generation(
        cache_root,
        active.generation_id,
        str(uuid4()),
        activated_at=NOW,
    )
    orphan = _prepare_generation(
        cache_root,
        uuid4(),
        content=b"id: removable-only-after-validation\n",
    )
    previous_payload = (
        cache_root
        / "generations"
        / previous_good.generation_id
        / "bearer"
        / "rules"
        / "python.yml"
    )
    previous_payload.chmod(0o600)
    previous_payload.write_bytes(b"id: corrupted-previous-good\n")
    previous_payload.chmod(0o400)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="referenced generation is invalid"):
            updater._prune_unreferenced_generations(cache_root)

    assert (cache_root / "generations" / orphan.generation_id).is_dir()


@pytest.mark.parametrize("unsafe_mode", [0o600, 0o440], ids=["mutable", "wrong-mode"])
def test_generation_pruning_refuses_mutable_or_wrong_mode_orphan(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    cache_root = tmp_path / "cache"
    _active, orphan = _prepare_active_and_orphan_generations(cache_root)
    orphan_payload = (
        cache_root
        / "generations"
        / orphan.generation_id
        / "bearer"
        / "rules"
        / "python.yml"
    )
    orphan_payload.chmod(unsafe_mode)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="not a sealed updater generation"):
            updater._prune_unreferenced_generations(cache_root)

    assert (cache_root / "generations" / orphan.generation_id).is_dir()


@pytest.mark.parametrize(
    "unsafe_metadata",
    ["wrong-owner", "nested-device-boundary", "special-entry"],
)
def test_generation_pruning_rejects_ambiguous_orphan_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_metadata: str,
) -> None:
    cache_root = tmp_path / "cache"
    _active, orphan = _prepare_active_and_orphan_generations(cache_root)
    orphan_payload = (
        cache_root
        / "generations"
        / orphan.generation_id
        / "bearer"
        / "rules"
        / "python.yml"
    )
    original_lstat = updater._prune_lstat

    def altered_lstat(path: Path) -> object:
        metadata = original_lstat(path)
        if path != orphan_payload:
            return metadata
        values = {
            "st_dev": metadata.st_dev,
            "st_ino": metadata.st_ino,
            "st_mode": metadata.st_mode,
            "st_nlink": metadata.st_nlink,
            "st_uid": metadata.st_uid,
            "st_gid": metadata.st_gid,
            "st_size": metadata.st_size,
            "st_mtime_ns": metadata.st_mtime_ns,
            "st_ctime_ns": metadata.st_ctime_ns,
        }
        if unsafe_metadata == "wrong-owner":
            values["st_uid"] = metadata.st_uid + 1
        elif unsafe_metadata == "nested-device-boundary":
            values["st_dev"] = metadata.st_dev + 1
        else:
            values["st_mode"] = stat.S_IFIFO | 0o400
        return SimpleNamespace(**values)

    monkeypatch.setattr(updater, "_prune_lstat", altered_lstat)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="not a sealed updater generation"):
            updater._prune_unreferenced_generations(cache_root)

    assert (cache_root / "generations" / orphan.generation_id).is_dir()


def test_generation_pruning_never_follows_a_nested_symlink(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    _active, orphan = _prepare_active_and_orphan_generations(cache_root)
    orphan_root = cache_root / "generations" / orphan.generation_id
    rules_root = orphan_root / "bearer" / "rules"
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_bytes(b"preserved")
    orphan_root.chmod(0o700)
    rules_root.chmod(0o700)
    alias = rules_root / "outside-alias"
    alias.symlink_to(outside, target_is_directory=True)
    rules_root.chmod(0o500)
    orphan_root.chmod(0o500)

    with updater.generation_lock(cache_root):
        with pytest.raises(updater.OperationError, match="not a sealed updater generation"):
            updater._prune_unreferenced_generations(cache_root)

    assert alias.is_symlink()
    assert marker.read_bytes() == b"preserved"


def _unpublished_generation(
    cache_root: Path,
    operation_id: UUID,
    *,
    content: bytes = b"id: reviewed-rule\n",
) -> tuple[Path, Path, GenerationManifest]:
    cache_root.mkdir(mode=0o700, exist_ok=True)
    operation_stage = cache_root / "staging" / str(operation_id)
    payload_file = operation_stage / "payload" / "bearer" / "rules" / "python.yml"
    payload_file.parent.mkdir(parents=True, mode=0o700)
    payload_file.write_bytes(content)
    payload_file.chmod(0o600)
    return operation_stage, operation_stage / "payload", _bearer_generation_manifest(content)


def _damaged_repair_fixture(tmp_path):
    from kodesec_scanner import cache_repair
    root = tmp_path / "cache"
    original = _prepare_generation(root, uuid4())
    for name in ("staging", "tombstones"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    pointer = activate_generation(root, original.generation_id, str(uuid4()))
    damaged = root / "generations" / original.generation_id / "manifest.json"
    damaged.chmod(0o600)
    damaged.write_text('{"corrupt":true}\n')
    damaged.chmod(0o400)
    source = cache_repair.admit_repair(root, cache_manifest.resolve_active_generation(root))
    operation = uuid4()
    request = _request(operation_id=operation, components=list(CACHE_COMPONENT_IDS))
    store = OperationStore(root)
    store.create_or_get(request, now=NOW)
    store.transition(operation, status="running", stage="staging", now=NOW)
    stage, payload, candidate = _unpublished_generation(root, operation, content=b"id: replacement-rule\n")
    return root, pointer, source, operation, stage, payload, candidate


def _publish_repair_fixture(fixture):
    from kodesec_scanner import cache_repair
    root, _pointer, source, operation, stage, payload, candidate = fixture
    return updater._publish_sealed_generation(root, stage, payload, candidate,
        before_publish=lambda sealed: cache_repair.record_candidate(root, source, sealed, str(operation), OperationStore(root).load(operation).request_digest))



def _activate_repair_fixture(fixture, *, prepare_publication=None):
    from kodesec_scanner import cache_repair
    root, _old, _source, operation, _stage, _payload, candidate = fixture
    store = OperationStore(root)
    def commit(_candidate):
        store.transition(operation, status="running", stage="committing", now=NOW)
        return NOW
    return cache_repair.activate_repair(root, candidate.generation_id, str(operation),
        store.load(operation).request_digest, prepare_publication=prepare_publication or commit)


def test_corrupt_single_generation_repair_replaces_pointer_and_reclaims_damaged_bytes(tmp_path):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    generation = _publish_repair_fixture(fixture)
    new = _activate_repair_fixture(fixture)
    assert new.revision == old.revision + 1
    assert new.previous_good is None
    assert new.operation_id == str(operation)
    assert new.active.generation_id == candidate.generation_id
    assert cache_repair.recover_repair(root)
    assert (root / cache_repair.INTENT_NAME).exists()
    record = OperationStore(root).reconcile_published(operation, now=NOW)
    assert record.status == "completed"
    assert cache_repair.recover_repair(root)
    assert not (root / "generations" / old.active.generation_id).exists()
    assert not (root / cache_repair.INTENT_NAME).exists()
    assert list((root / "tombstones").iterdir()) == []
    assert cache_manifest.resolve_active_generation(root).state == "ready"
    assert updater._prune_unreferenced_generations(root) == []
    assert not cache_repair.recover_repair(root)


@pytest.mark.parametrize("published", [False, True])
def test_interrupted_unactivated_repair_preserves_old_selection_and_retires_only_candidate(tmp_path, published):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, source, operation, stage, payload, candidate = fixture
    if published:
        _publish_repair_fixture(fixture)
    else:
        # Crash after the intent is durable but before the final namespace move.
        def interrupt(sealed):
            cache_repair.record_candidate(root, source, sealed, str(operation), OperationStore(root).load(operation).request_digest)
            raise RuntimeError("power loss before candidate publication")
        with pytest.raises(RuntimeError, match="power loss"):
            updater._publish_sealed_generation(root, stage, payload, candidate, before_publish=interrupt)
    assert cache_repair.recover_repair(root)
    assert cache_manifest.load_active_pointer(root) == old
    assert (root / "generations" / old.active.generation_id).is_dir()
    assert not (root / "generations" / candidate.generation_id).exists()
    assert not (root / cache_repair.INTENT_NAME).exists()
    assert cache_manifest.resolve_active_generation(root).state == "invalid"


@pytest.mark.parametrize("change", ["source-file", "candidate-file", "pointer", "symlink"])
def test_repair_refuses_changed_or_unsafe_inputs_without_switch_or_retirement(tmp_path, change):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    if change in {"source-file", "candidate-file"}:
        generation = old.active.generation_id if change == "source-file" else candidate.generation_id
        path = root / "generations" / generation / "manifest.json"
        path.chmod(0o600); path.write_text('{}\n'); path.chmod(0o400)
    elif change == "pointer":
        value = old.model_copy(update={"revision": old.revision + 10})
        cache_manifest._atomic_write_json(root, "active.json", value.model_dump(mode="json"), 65536)
    else:
        path = root / "generations" / old.active.generation_id
        path.chmod(0o700); (path / "escape").symlink_to(tmp_path); path.chmod(0o500)
    with pytest.raises(cache_manifest.CacheValidationError):
        _activate_repair_fixture(fixture)
    assert (root / "generations" / old.active.generation_id).exists()
    assert (root / "generations" / candidate.generation_id).exists()
    assert cache_manifest.load_active_pointer(root).active == old.active
    if change == "symlink":
        path.chmod(0o700)
        (path / "escape").unlink()
        path.chmod(0o500)


def test_repair_freshness_or_cancellation_refusal_preserves_old_pointer(tmp_path):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    def semantic_refusal(_):
        raise updater.OperationError("expired or cancelled before publication")
    with pytest.raises(updater.OperationError, match="expired or cancelled"):
        _activate_repair_fixture(fixture, prepare_publication=semantic_refusal)
    assert cache_manifest.load_active_pointer(root) == old
    assert cache_repair.recover_repair(root)



@pytest.mark.parametrize("change", ["missing-operation", "request-digest", "duplicate-key", "partial-request"])
def test_repair_refuses_unbound_or_ambiguous_intent(tmp_path, change):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    path = root / cache_repair.INTENT_NAME
    if change == "missing-operation":
        OperationStore(root)._path(operation).unlink()
    elif change == "duplicate-key":
        raw = path.read_text()
        path.write_text('{"schema_version":1,' + raw.lstrip()[1:])
    elif change == "request-digest":
        raw = json.loads(path.read_text())
        raw["request_digest"] = "f" * 64
        path.write_text(json.dumps(raw))
    else:
        store = OperationStore(root)
        record = store.load(operation)
        request = _request(operation_id=operation, components=["bearer-rules"])
        store._write_unlocked(record.model_copy(update={
            "requested_components": request.requested_components,
            "request_digest": request.request_digest,
        }))
    with pytest.raises((cache_manifest.CacheValidationError, updater.OperationError)):
        cache_repair.recover_repair(root)
    assert cache_manifest.load_active_pointer(root) == old
    assert (root / "generations" / old.active.generation_id).is_dir()
    assert (root / "generations" / candidate.generation_id).is_dir()
    assert path.is_file()


def test_repair_publication_refuses_an_existing_destination_before_intent(tmp_path):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, _operation, _stage, _payload, candidate = fixture
    destination = root / "generations" / candidate.generation_id
    destination.mkdir(mode=0o500)
    identity = destination.stat().st_ino
    with pytest.raises(updater.OperationError, match="repair candidate destination already exists"):
        _publish_repair_fixture(fixture)
    assert destination.stat().st_ino == identity
    assert list(destination.iterdir()) == []
    assert not (root / cache_repair.INTENT_NAME).exists()
    assert cache_manifest.load_active_pointer(root) == old


@pytest.mark.parametrize("expired", [False, True])
def test_repair_restart_reconciles_exact_commit_without_rehash_or_new_work(tmp_path, monkeypatch, expired):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    pointer = _activate_repair_fixture(fixture)
    def forbidden(*_args, **_kwargs):
        pytest.fail("repair metadata reconciliation must not renew generation validation")
    monkeypatch.setattr(updater, "validate_generation", forbidden)
    monkeypatch.setattr(cache_repair, "validate_generation", forbidden)
    moment = MOMENT + timedelta(hours=1) if expired else MOMENT
    monkeypatch.setattr(updater, "_utc_now", lambda: moment)
    recovered = OperationStore(root).recover_interrupted(now=updater.utc_timestamp(moment))
    assert len(recovered) == 1
    record = recovered[0]
    assert record.operation_id == operation and record.status == "completed"
    assert record.result.active == pointer.active
    assert record.workflow_deadline_exceeded is expired
    assert not (root / cache_repair.INTENT_NAME).exists()
    assert not (root / "generations" / old.active.generation_id).exists()
    assert (root / "generations" / candidate.generation_id).is_dir()
    assert cache_manifest.load_active_pointer(root) == pointer


@pytest.mark.parametrize("target", ["file", "manifest", "pointer"])
def test_published_repair_change_preserves_original_data_and_uncertain_record(tmp_path, target):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    pointer = _activate_repair_fixture(fixture)
    if target == "pointer":
        replacement = pointer.model_copy(update={"revision": pointer.revision + 1})
        cache_manifest._atomic_write_json(root, "active.json", replacement.model_dump(mode="json"), 65536)
    else:
        path = root / "generations" / candidate.generation_id
        path = path / "manifest.json" if target == "manifest" else next(path.rglob("*.yml"))
        original = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(original)  # Even identical bytes with changed identity need fresh proof.
        path.chmod(0o400)
    with pytest.raises(cache_manifest.CacheValidationError):
        cache_repair.recover_repair(root)
    record = OperationStore(root).reconcile_published(operation, now=NOW,
        preparation_budget=OperationStore(root).load(operation).preparation_budget)
    assert record.status == "running" and record.stage == "committing"
    assert (root / "generations" / old.active.generation_id).exists()
    assert (root / cache_repair.INTENT_NAME).exists()


@pytest.mark.parametrize("phase", ["receipt", "rename", "delete"])
def test_repair_retirement_resumes_exact_receipt_after_interruption(tmp_path, monkeypatch, phase):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, _candidate = fixture
    _publish_repair_fixture(fixture)
    pointer = _activate_repair_fixture(fixture)
    seams = {"receipt": "_rename_receipted_generation", "rename": "_persist_tombstone_rename",
             "delete": "_remove_tombstone_receipt"}
    seam = seams[phase]
    original = getattr(updater, seam)
    def interrupt(*args, **kwargs):
        if phase == "rename":
            original(*args, **kwargs)
        raise updater.PreparationDeadlineExceeded("owned cleanup interrupted")
    monkeypatch.setattr(updater, seam, interrupt)
    with pytest.raises(updater.PreparationDeadlineExceeded, match="owned cleanup"):
        cache_repair.recover_repair(root)
    assert (root / cache_repair.INTENT_NAME).exists()
    assert cache_manifest.load_active_pointer(root) == pointer
    monkeypatch.setattr(updater, seam, original)
    recovered = OperationStore(root).recover_interrupted(now=NOW)
    assert recovered[0].status == "completed"
    assert not (root / "generations" / old.active.generation_id).exists()
    assert not (root / cache_repair.INTENT_NAME).exists()
    assert list((root / "tombstones").iterdir()) == []


def test_startup_repair_metadata_deadline_defers_with_intent_and_data_retained(tmp_path, monkeypatch):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, _stage, _payload, candidate = fixture
    _publish_repair_fixture(fixture)
    _activate_repair_fixture(fixture)
    def exhausted(*_args, **_kwargs):
        raise updater.PreparationDeadlineExceeded("original metadata clock exhausted")
    monkeypatch.setattr(cache_repair, "_inventory", exhausted)
    assert OperationStore(root).recover_interrupted(now=NOW) == []
    assert (root / cache_repair.INTENT_NAME).exists()
    assert (root / "generations" / old.active.generation_id).exists()
    assert (root / "generations" / candidate.generation_id).exists()
    assert OperationStore(root).load(operation).stage == "committing"



@pytest.mark.parametrize("components", [list(CACHE_COMPONENT_IDS), ["bearer-rules"]])
def test_damaged_cache_requires_complete_request_and_capacity_before_acquisition(tmp_path, monkeypatch, components):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, _operation, stage, _payload, _candidate = fixture
    updater._remove_private_staging_tree(stage)
    request = _request(components=components)
    store = OperationStore(root)
    store.create_or_get(request, now=NOW)
    context = updater.OperationContext(request=request, store=store, wall_now=lambda: NOW)
    handlers = LockedLifecycleHandlers(tools=TOOLS, rules=RULES, cache_root=root,
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: datetime.fromisoformat(
            TOOLS.value.tool("trivy").requirements[0].data_contract.publisher_updated_at))
    events = []
    def capacity(*_args):
        events.append("capacity")
        assert not (root / "staging" / str(request.operation_id)).exists()
        raise updater.OperationCapacityError("safe repair capacity unavailable")
    def forbidden(*_args, **_kwargs):
        pytest.fail("damaged bytes must not be carried, pruned, or acquired before admission")
    monkeypatch.setattr(updater, "_data_update_capacity_preflight", capacity)
    monkeypatch.setattr(updater, "_prune_unreferenced_generations", forbidden)
    monkeypatch.setattr(updater, "_copy_validated_component", forbidden)
    monkeypatch.setattr(updater, "_run_data_command", forbidden)
    match = "safe repair capacity" if len(components) == len(CACHE_COMPONENT_IDS) else "complete repair"
    with pytest.raises(updater.OperationError, match=match):
        handlers.cache_update(context)
    assert events == (["capacity"] if len(components) == len(CACHE_COMPONENT_IDS) else [])
    assert cache_manifest.load_active_pointer(root) == old
    assert not (root / cache_repair.INTENT_NAME).exists()


def test_repair_executor_preserves_original_deadline_after_valid_pointer_publication(tmp_path, monkeypatch):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, source, operation, _stage, _payload, _candidate = fixture
    store = OperationStore(root)
    store._path(operation).unlink()
    request = _request(operation_id=operation, components=list(CACHE_COMPONENT_IDS))
    current_time = [MOMENT]
    monkeypatch.setattr(updater, "_utc_now", lambda: current_time[0])
    def prepare(context):
        context.progress("staging", now=NOW)
        object.__setattr__(context, "_repair_source", source)
        return _publish_repair_fixture(fixture)
    def semantic_check(candidate, requested, *_args, **_kwargs):
        # Small structural fixture: semantic engines are exercised by separate
        # qualification, not represented as passing by this unit test.
        assert candidate.reference.generation_id == fixture[-1].generation_id
        assert requested == list(CACHE_COMPONENT_IDS)
    monkeypatch.setattr(updater, "_validate_candidate_components", semantic_check)
    original_activate = cache_repair.activate_repair
    def activate_then_expire(*args, **kwargs):
        pointer = original_activate(*args, **kwargs)
        current_time[0] += timedelta(hours=1)
        return pointer
    monkeypatch.setattr(cache_repair, "activate_repair", activate_then_expire)
    record = execute_operation(request, TOOLS, RULES, store, cache_update=prepare,
        now=lambda: updater.utc_timestamp(current_time[0]), evaluation_now=lambda: current_time[0])
    assert record.status == "completed" and record.workflow_deadline_exceeded
    assert record.preparation_budget == request.preparation_budget
    assert record.result.previous_good is None
    assert cache_manifest.load_active_pointer(root).active == record.result.active
    assert (root / "generations" / old.active.generation_id).exists()
    assert (root / cache_repair.INTENT_NAME).exists()
    # Only metadata recovery is admitted after expiry; it cannot rewrite failure
    # into a passing preparation or replace the original clock.
    store.recover_interrupted(now=updater.utc_timestamp(current_time[0]))
    assert store.load(operation).workflow_deadline_exceeded
    assert not (root / "generations" / old.active.generation_id).exists()
    assert not (root / cache_repair.INTENT_NAME).exists()



def test_completed_repair_operation_is_retained_until_intent_cleanup(tmp_path, monkeypatch):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, _old, _source, operation, _stage, _payload, _candidate = fixture
    _publish_repair_fixture(fixture)
    _activate_repair_fixture(fixture)
    assert cache_repair.recover_repair(root)
    store = OperationStore(root)
    assert store.reconcile_published(operation, now=NOW).status == "completed"
    monkeypatch.setattr(updater, "MAX_OPERATION_RECORDS", 2)
    later = _request(kind="catalog_check", components=[])
    later_now = updater.utc_timestamp(MOMENT + timedelta(seconds=1))
    store.create_or_get(later, now=later_now)
    store.transition(later.operation_id, status="running", stage="discovering", now=later_now)
    store.transition(later.operation_id, status="completed", stage="completed", result=_catalog(), now=later_now)
    incoming = _request(kind="catalog_check", components=[])
    store.create_or_get(incoming, now=later_now)
    assert store.load(operation).status == "completed"
    with pytest.raises(updater.OperationNotFoundError):
        store.load(later.operation_id)
    assert cache_repair.recover_repair(root)
    assert not (root / cache_repair.INTENT_NAME).exists()
    store.create_or_get(_request(kind="catalog_check", components=[]), now=later_now)
    with pytest.raises(updater.OperationNotFoundError):
        store.load(operation)



@pytest.mark.parametrize("reappears", [False, True])
def test_missing_selected_generation_repair_records_exact_absence(tmp_path, reappears):
    from kodesec_scanner import cache_repair
    fixture = _damaged_repair_fixture(tmp_path)
    root, old, _source, operation, stage, payload, candidate = fixture
    missing = root / "generations" / old.active.generation_id
    updater._remove_private_staging_tree(missing)  # Exact disposable unit-test fault.
    source = cache_repair.admit_repair(root, cache_manifest.resolve_active_generation(root))
    assert source.entries == {}
    fixture = root, old, source, operation, stage, payload, candidate
    _publish_repair_fixture(fixture)
    if reappears:
        missing.mkdir(mode=0o500)
        inode = missing.stat().st_ino
        with pytest.raises(cache_manifest.CacheValidationError, match="appeared"):
            _activate_repair_fixture(fixture)
        assert missing.stat().st_ino == inode
        assert cache_manifest.load_active_pointer(root) == old
    else:
        pointer = _activate_repair_fixture(fixture)
        record = OperationStore(root).recover_interrupted(now=NOW)[0]
        assert record.status == "completed" and record.result.active == pointer.active
        assert not missing.exists()
        assert not (root / cache_repair.INTENT_NAME).exists()


def test_exclusive_generation_rename_cannot_replace_an_empty_destination(tmp_path):
    from kodesec_scanner.cache_repair import rename_exclusive
    source = tmp_path / "source"; destination = tmp_path / "destination"
    source.mkdir(); destination.mkdir()
    identities = (source.stat().st_ino, destination.stat().st_ino)
    with pytest.raises(FileExistsError):
        rename_exclusive(source, destination)
    assert (source.stat().st_ino, destination.stat().st_ino) == identities


def test_generation_publication_exposes_only_a_sealed_valid_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    operation_stage, payload, manifest = _unpublished_generation(cache_root, uuid4())
    destination = cache_root / "generations" / manifest.generation_id
    original = updater.write_generation_manifest
    sealed_paths: list[Path] = []

    def observe_seal(path: Path, candidate: GenerationManifest) -> str:
        assert not destination.exists()
        assert path.name == candidate.generation_id
        assert path.parent.parent == operation_stage / "candidate"
        sealed_paths.append(path)
        return original(path, candidate)

    monkeypatch.setattr(updater, "write_generation_manifest", observe_seal)

    generation_id = updater._publish_sealed_generation(
        cache_root,
        operation_stage,
        payload,
        manifest,
    )

    assert generation_id == manifest.generation_id
    assert len(sealed_paths) == 1
    assert not sealed_paths[0].exists()
    assert validate_generation(cache_root, generation_id).manifest == manifest


def test_generation_sealing_failure_never_exposes_a_final_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    operation_stage, payload, manifest = _unpublished_generation(cache_root, uuid4())
    destination = cache_root / "generations" / manifest.generation_id

    def fail_seal(_path: Path, _candidate: GenerationManifest) -> str:
        raise RuntimeError("simulated seal interruption")

    monkeypatch.setattr(updater, "write_generation_manifest", fail_seal)
    with pytest.raises(updater.OperationError, match="sealed and validated"):
        updater._publish_sealed_generation(
            cache_root,
            operation_stage,
            payload,
            manifest,
        )

    assert not destination.exists()


def test_generation_publication_preserves_cancellation_semantics(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    operation_stage, payload, manifest = _unpublished_generation(cache_root, uuid4())
    destination = cache_root / "generations" / manifest.generation_id

    def cancel() -> None:
        raise updater.OperationStateError("updater operation cancellation requested")

    with pytest.raises(updater.OperationStateError, match="cancellation requested"):
        updater._publish_sealed_generation(
            cache_root,
            operation_stage,
            payload,
            manifest,
            cancel,
        )

    assert not destination.exists()


def test_request_digest_is_retry_stable_but_strictly_verified() -> None:
    operation_id = uuid4()
    first = _request(operation_id=operation_id, attempt=1)
    second = _request(operation_id=operation_id, attempt=2)
    assert first.request_digest == second.request_digest

    payload = first.model_dump(mode="json")
    payload["request_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="canonical operation request"):
        OperationRequest.model_validate(payload)

    payload = first.model_dump(mode="json")
    payload["requested_components"] = ["trivy-db", "bearer-rules"]
    with pytest.raises(ValidationError, match="sorted and unique"):
        OperationRequest.model_validate(payload)


def test_store_replay_conflict_and_exact_next_retry(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    operation_id = uuid4()
    first = _request(operation_id=operation_id)
    created, should_execute = store.create_or_get(first, now=NOW)
    assert should_execute is True
    assert created.attempt == 1
    assert created.status == "queued"

    replay, should_execute = store.create_or_get(first, now=NOW)
    assert should_execute is False
    assert replay == created

    different = _request(operation_id=operation_id, components=["grype-db"])
    with pytest.raises(OperationConflictError, match="different request"):
        store.create_or_get(different, now=NOW)

    store.transition(operation_id, status="running", stage="staging", now=NOW)
    failed = store.transition(
        operation_id,
        status="failed",
        stage="failed",
        error_code="operation_failed",
        error_detail="bounded failure",
        now=NOW,
    )
    assert failed.attempt == 1

    skipped = _request(operation_id=operation_id, attempt=3)
    with pytest.raises(OperationConflictError, match="exactly the next"):
        store.create_or_get(skipped, now=NOW)

    retry = _request(operation_id=operation_id, attempt=2)
    restarted, should_execute = store.create_or_get(retry, now=NOW)
    assert should_execute is True
    assert restarted.status == "queued"
    assert restarted.started_at is None
    assert restarted.error_detail is None
    assert restarted.attempt == 2

    changed_max = _request(operation_id=operation_id, attempt=2, max_attempts=2)
    with pytest.raises(OperationConflictError, match="immutable"):
        store.create_or_get(changed_max, now=NOW)


def test_operation_heartbeat_does_not_claim_updater_activity(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    created, _ = store.create_or_get(request, now=NOW)
    running = store.transition(
        request.operation_id,
        status="running",
        stage="downloading",
        now="2026-08-12T21:00:01Z",
    )

    too_soon = store.heartbeat(
        request.operation_id,
        request_digest=request.request_digest,
        now="2026-08-12T21:00:05Z",
    )
    heartbeat = store.heartbeat(
        request.operation_id,
        request_digest=request.request_digest,
        now="2026-08-12T21:00:06Z",
    )

    assert created.last_activity_at == NOW
    assert too_soon == running
    assert heartbeat.updated_at == "2026-08-12T21:00:06Z"
    assert heartbeat.last_activity_at == "2026-08-12T21:00:01Z"


def test_opaque_command_refreshes_component_activity_without_inventing_bytes(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["trivy-java-db"])
    store.create_or_get(request, now=NOW)
    activity = updater.OperationActivity(
        component_id="trivy-java-db", component_index=1, component_total=1
    )
    running = store.transition(
        request.operation_id,
        status="running",
        stage="downloading",
        activity=activity,
        now="2026-08-12T21:00:01Z",
    )

    too_soon = store.refresh_activity(
        request.operation_id,
        request_digest=request.request_digest,
        now="2026-08-12T21:00:10Z",
    )
    refreshed = store.refresh_activity(
        request.operation_id,
        request_digest=request.request_digest,
        now="2026-08-12T21:00:11Z",
    )

    assert too_soon == running
    assert refreshed.last_activity_at == "2026-08-12T21:00:11Z"
    assert refreshed.activity == activity
    assert refreshed.activity.bytes_completed is None
    assert refreshed.activity.bytes_total is None


def test_full_ledger_prunes_oldest_completed_receipt_and_survives_restart(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    operation_ids = [
        UUID(int=index + 1, version=4)
        for index in range(updater.MAX_OPERATION_RECORDS)
    ]
    oldest_at = "2026-08-12T20:00:00Z"
    for index, operation_id in enumerate(operation_ids):
        store._write_unlocked(
            _completed_catalog_record(
                operation_id,
                finished_at=oldest_at if index == 0 else NOW,
            )
        )

    request = _request(kind="catalog_check", components=[], issued_at=MOMENT + timedelta(hours=1))
    created, should_execute = store.create_or_get(
        request,
        now="2026-08-12T22:00:00Z",
    )

    assert should_execute is True
    assert created.status == "queued"
    assert len(_ledger_operation_names(store)) == updater.MAX_OPERATION_RECORDS
    with pytest.raises(updater.OperationNotFoundError):
        store.load(operation_ids[0])

    restarted = OperationStore(store.cache_root)
    assert restarted.load(request.operation_id) == created
    retained = restarted.load(operation_ids[-1])
    assert retained.status == "completed"
    assert len(_ledger_operation_names(restarted)) == updater.MAX_OPERATION_RECORDS


def test_full_ledger_replay_does_not_prune_any_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updater, "MAX_OPERATION_RECORDS", 3)
    store = OperationStore(tmp_path / "cache")
    operation_ids = [UUID(int=index + 1, version=4) for index in range(3)]
    for operation_id in operation_ids:
        store._write_unlocked(_completed_catalog_record(operation_id))
    before = _ledger_operation_names(store)
    request = _request(
        operation_id=operation_ids[1],
        kind="catalog_check",
        components=[],
    )

    replay, should_execute = store.create_or_get(request, now=NOW)

    assert should_execute is False
    assert replay.operation_id == request.operation_id
    assert _ledger_operation_names(store) == before


def test_full_ledger_pruning_uses_timestamp_then_uuid_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updater, "MAX_OPERATION_RECORDS", 2)
    store = OperationStore(tmp_path / "cache")
    lower = UUID(int=1, version=4)
    higher = UUID(int=2, version=4)
    store._write_unlocked(_completed_catalog_record(higher))
    store._write_unlocked(_completed_catalog_record(lower))

    request = _request(kind="catalog_check", components=[], issued_at=MOMENT + timedelta(hours=1))
    store.create_or_get(request, now="2026-08-12T22:00:00Z")

    with pytest.raises(updater.OperationNotFoundError):
        store.load(lower)
    assert store.load(higher).status == "completed"
    assert store.load(request.operation_id).status == "queued"


def test_full_ledger_with_only_unresolved_receipts_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updater, "MAX_OPERATION_RECORDS", 5)
    store = OperationStore(tmp_path / "cache")
    requests = [_request() for _ in range(5)]
    for request in requests:
        store.create_or_get(request, now=NOW)
    store.transition(requests[1].operation_id, status="running", stage="committing", now=NOW)
    store.transition(requests[2].operation_id, status="running", stage="downloading", now=NOW)
    store.request_cancel(
        requests[2].operation_id,
        request_digest=requests[2].request_digest,
        now=NOW,
    )
    store.transition(requests[3].operation_id, status="running", stage="staging", now=NOW)
    store.transition(
        requests[3].operation_id,
        status="failed",
        stage="failed",
        error_code="operation_failed",
        error_detail="bounded failure",
        now=NOW,
    )
    store.request_cancel(
        requests[4].operation_id,
        request_digest=requests[4].request_digest,
        now=NOW,
    )
    before = _ledger_operation_names(store)

    with pytest.raises(updater.OperationCapacityError, match="no completed receipt"):
        store.create_or_get(_request(), now=NOW)

    assert _ledger_operation_names(store) == before
    assert {
        store.load(request.operation_id).status for request in requests
    } == {"queued", "running", "cancelling", "failed", "cancelled"}


def test_full_ledger_with_unsafe_entry_fails_before_pruning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updater, "MAX_OPERATION_RECORDS", 3)
    store = OperationStore(tmp_path / "cache")
    retained_ids = [UUID(int=index + 1, version=4) for index in range(2)]
    for operation_id in retained_ids:
        store._write_unlocked(_completed_catalog_record(operation_id))
    unsafe_id = UUID(int=3, version=4)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (store.operations_path / updater._operation_filename(unsafe_id)).symlink_to(outside)
    before = _ledger_operation_names(store)

    with pytest.raises(updater.OperationError, match="unsafe or unexpected"):
        store.create_or_get(_request(kind="catalog_check", components=[]), now=NOW)

    assert _ledger_operation_names(store) == before
    assert all(store.load(operation_id).status == "completed" for operation_id in retained_ids)


def test_restart_recovery_terminalizes_component_activity_and_removes_staging(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["grype-db"])
    store.create_or_get(request, now=NOW)
    store.transition(request.operation_id, status="running", stage="downloading", now=NOW)
    active = store.update_activity(
        request.operation_id,
        request_digest=request.request_digest,
        activity=updater.OperationActivity(
            component_id="grype-db",
            component_index=1,
            component_total=len(request.requested_components),
        ),
        force=True,
        now=NOW,
    )
    assert active.activity is not None
    stage = store.cache_root / "staging" / str(request.operation_id)
    payload = stage / "sealed" / "rules.yml"
    payload.parent.mkdir(parents=True, mode=0o700)
    payload.write_text("rules: []\n", encoding="utf-8")
    payload.chmod(0o400)
    payload.parent.chmod(0o500)
    stage.chmod(0o500)

    recovered = store.recover_interrupted(now=NOW)

    assert len(recovered) == 1
    assert recovered[0].status == "failed"
    assert recovered[0].stage == "failed"
    assert recovered[0].error_code == "updater_restarted"
    assert recovered[0].activity is None
    assert not stage.exists()


def test_restart_recovery_rejects_unknown_staging_entries(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    store.create_or_get(_request(), now=NOW)
    staging = store.cache_root / "staging"
    staging.mkdir(mode=0o700)
    (staging / "not-an-operation").mkdir(mode=0o700)

    with pytest.raises(Exception, match="unknown entry"):
        store.recover_interrupted(now=NOW)


def test_restart_recovery_removes_uuid_orphan_without_a_ledger_record(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    orphan = store.cache_root / "staging" / str(uuid4())
    orphan.mkdir(parents=True, mode=0o700)
    payload = orphan / "payload"
    payload.write_text("temporary", encoding="utf-8")
    payload.chmod(0o400)
    orphan.chmod(0o500)

    assert store.recover_interrupted(now=NOW) == []
    assert not orphan.exists()


def test_cancel_requires_matching_digest_and_can_retry(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    operation_id = uuid4()
    request = _request(operation_id=operation_id)
    store.create_or_get(request, now=NOW)

    with pytest.raises(OperationConflictError, match="does not match"):
        store.request_cancel(operation_id, request_digest="0" * 64, now=NOW)

    cancelled = store.request_cancel(
        operation_id,
        request_digest=request.request_digest,
        now=NOW,
    )
    assert cancelled.status == "cancelled"
    assert cancelled.cancel_requested_at == NOW
    assert cancelled.started_at is None

    retry = _request(operation_id=operation_id, attempt=2)
    restarted, should_execute = store.create_or_get(retry, now=NOW)
    assert should_execute is True
    assert restarted.status == "queued"
    assert restarted.cancel_requested_at is None


def test_committing_operation_is_non_cancellable_and_reconciles_published_pointer(
    tmp_path: Path,
) -> None:
    store = OperationStore(tmp_path / "cache")
    operation_id = uuid4()
    request = _request(operation_id=operation_id)
    store.create_or_get(request, now=NOW)
    store.transition(operation_id, status="running", stage="staging", now=NOW)
    committing = store.transition(
        operation_id,
        status="running",
        stage="committing",
        now=NOW,
    )

    observed = store.request_cancel(
        operation_id,
        request_digest=request.request_digest,
        now=NOW,
    )
    assert observed == committing
    assert observed.cancel_requested_at is None

    manifest = _prepare_generation(store.cache_root, operation_id)
    activate_generation(
        store.cache_root,
        manifest.generation_id,
        str(operation_id),
        activated_at=NOW,
    )
    completed = store.reconcile_published(operation_id, now=NOW)
    assert completed is not None
    assert completed.status == "completed"
    assert completed.result is not None
    assert completed.result.active.generation_id == manifest.generation_id


@pytest.mark.parametrize("budgeted", [True, False])
@pytest.mark.parametrize("recovery", ["reconcile", "startup"])
def test_grype_verification_timeout_preserves_published_operation_for_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recovery: str, budgeted: bool,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request() if budgeted else _request(kind="cache_rollback", components=[])
    store.create_or_get(request, now=NOW)
    store.transition(request.operation_id, status="running", stage="staging", now=NOW)
    committing = store.transition(
        request.operation_id, status="running", stage="committing", now=NOW,
    )
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    activate_generation(
        store.cache_root, manifest.generation_id, str(request.operation_id),
        activated_at=NOW,
    )
    pointer_before = (store.cache_root / "active.json").read_bytes()
    original_validate = updater.validate_generation
    failure = updater.GrypeContentValidationError("deadline")

    def timed_out_validation(*_args: object, **_kwargs: object):
        raise failure

    monkeypatch.setattr(updater, "validate_generation", timed_out_validation)
    if budgeted:
        observed = (store.reconcile_published(request.operation_id, now=NOW)
                    if recovery == "reconcile" else store.recover_interrupted(now=NOW))
        assert observed == (committing if recovery == "reconcile" else [committing])
    else:
        with pytest.raises(updater.GrypeContentValidationError) as raised:
            if recovery == "reconcile":
                store.reconcile_published(request.operation_id, now=NOW)
            else:
                store.recover_interrupted(now=NOW)
        assert raised.value is failure
    assert store.load(request.operation_id) == committing
    assert (store.cache_root / "active.json").read_bytes() == pointer_before
    assert (store.cache_root / "generations" / manifest.generation_id).is_dir()
    monkeypatch.setattr(updater, "validate_generation", original_validate)
    completed = store.reconcile_published(request.operation_id, now=NOW)
    assert completed is not None
    assert completed.status == "completed"
    assert completed.result is not None
    assert completed.result.active.generation_id == manifest.generation_id


def test_completion_write_failure_reconciles_already_published_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request()
    manifest = _prepare_generation(store.cache_root, request.operation_id)
    original_transition = OperationStore.transition
    terminal_write_failed = False

    def fail_first_terminal_write(
        self: OperationStore,
        operation_id: UUID,
        **kwargs: object,
    ):
        nonlocal terminal_write_failed
        if kwargs.get("status") == "completed" and not terminal_write_failed:
            terminal_write_failed = True
            raise OSError("simulated terminal receipt interruption")
        return original_transition(self, operation_id, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(OperationStore, "transition", fail_first_terminal_write)
    monkeypatch.setattr(
        updater,
        "_validate_candidate_components",
        lambda *_args, **_kwargs: None,
    )

    completed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        cache_update=lambda _context: manifest.generation_id,
        now=lambda: NOW,
        evaluation_now=lambda: MOMENT,
    )

    assert terminal_write_failed is True
    assert completed.status == "completed"
    assert completed.result is not None
    assert completed.result.active.generation_id == manifest.generation_id
    assert store.load(request.operation_id) == completed


def test_cache_rollback_is_durable_non_injectable_and_swaps_last_good(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "cache")
    first_operation = uuid4()
    first = _prepare_generation(store.cache_root, first_operation)
    activate_generation(
        store.cache_root,
        first.generation_id,
        str(first_operation),
        activated_at=NOW,
    )
    second_operation = uuid4()
    second = _prepare_generation(
        store.cache_root,
        second_operation,
        content=b"id: reviewed-rule-v2\n",
    )
    activate_generation(
        store.cache_root,
        second.generation_id,
        str(second_operation),
        activated_at=NOW,
    )

    transitions: list[updater.OperationRecord] = []
    original_transition = OperationStore.transition

    def record_transition(self: OperationStore, *args: object, **kwargs: object):
        record = original_transition(self, *args, **kwargs)
        transitions.append(record)
        return record

    monkeypatch.setattr(OperationStore, "transition", record_transition)
    request = _request(kind="cache_rollback", components=[])
    completed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        now=lambda: NOW,
        evaluation_now=lambda: MOMENT,
    )

    assert completed.status == "completed"
    assert completed.kind == "cache_rollback"
    assert completed.result is not None
    assert completed.result.updated_components == []
    assert completed.result.active.generation_id == first.generation_id
    assert completed.result.previous_good is not None
    assert completed.result.previous_good.generation_id == second.generation_id
    assert all(record.activity is None for record in transitions)
    assert {"rolling_back", "committing", "completed"} <= {
        record.stage for record in transitions
    }

    payload = request.model_dump(mode="json")
    payload["requested_components"] = ["grype-db"]
    payload["request_digest"] = operation_request_digest(
        schema_version=1,
        kind="cache_rollback",
        requested_components=["grype-db"],
    )
    with pytest.raises(ValidationError, match="does not accept component ids"):
        OperationRequest.model_validate(payload)


def test_catalog_receipt_requires_exact_sorted_sets_and_no_urls() -> None:
    catalog = _catalog()
    assert [item.tool_id for item in catalog.tools] == list(CATALOG_TOOL_IDS)
    assert [item.component_id for item in catalog.components] == list(CACHE_COMPONENT_IDS)

    payload = catalog.model_dump(mode="json")
    payload["tools"] = payload["tools"][:-1]
    with pytest.raises(ValidationError):
        CatalogOperationResult.model_validate(payload)

    with pytest.raises(ValidationError, match="paths or URLs"):
        CatalogToolResult(
            tool_id="trivy",
            state="candidate_available",
            installed_version="0.73.0",
            candidate_version="0.74.0",
            candidate_release_id="https://example.invalid/release",
            candidate_manifest_digest="1" * 64,
        )

    lock_refresh = CatalogComponentResult(
        component_id="grype-db",
        state="requires_lock_refresh",
    )
    assert lock_refresh.state == "requires_lock_refresh"

    with pytest.raises(ValidationError, match="non-candidate"):
        CatalogComponentResult(
            component_id="grype-db",
            state="requires_lock_refresh",
            candidate_immutable_ref="sha256:" + "1" * 64,
            candidate_manifest_digest="1" * 64,
        )

    with pytest.raises(ValidationError, match="source-intrinsic"):
        CatalogComponentResult(
            component_id="trivy-checks",
            state="requires_lock_refresh",
        )

    with pytest.raises(ValidationError):
        CatalogToolResult(
            tool_id="grype",
            state="requires_lock_refresh",
        )


def test_locked_catalog_reports_runtime_binary_and_component_truth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intrinsic = [requirement for tool in TOOLS.value.tools for requirement in tool.requirements
        if requirement.id in updater.SOURCE_INTRINSIC_DATA_COMPONENT_IDS]
    evaluated_at = max(updater._parse_utc(
        updater.locked_intrinsic_updated_at(requirement), "locked intrinsic timestamp"
    ) for requirement in intrinsic)
    assert all(evaluated_at < updater._parse_utc(
        updater.locked_intrinsic_updated_at(requirement), "locked intrinsic timestamp"
    ) + timedelta(seconds=requirement.max_age_seconds - updater.MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS)
        for requirement in intrinsic), "reviewed catalog needs a common usable freshness window"
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: evaluated_at,
    )
    monkeypatch.setattr(
        updater,
        "tool_runtime_state",
        lambda tool_id: (
            {
                "id": tool_id,
                "available": True,
                "status": "ready",
                "installed_version": TOOLS.value.tool(tool_id).version,
            }
            if tool_id == "gitleaks"
            else {
                "id": tool_id,
                "available": False,
                "status": "missing",
                "installed_version": None,
            }
        ),
    )

    result = handlers.catalog_check(SimpleNamespace(checkpoint=lambda: None))
    tools_by_id = {item.tool_id: item for item in result.tools}
    components_by_id = {item.component_id: item for item in result.components}

    assert tools_by_id["gitleaks"].state == "current"
    assert tools_by_id["gitleaks"].installed_version == "8.30.1"
    assert tools_by_id["trivy"].state == "unavailable"
    assert tools_by_id["trivy"].installed_version is None
    assert components_by_id["bearer-rules"].state == "candidate_available"
    assert components_by_id["opengrep-reviewed-rules"].state == "candidate_available"
    assert components_by_id["trivy-db"].state == "candidate_available"
    assert components_by_id["grype-db"].state == "candidate_available"


@pytest.mark.parametrize(
    ("evaluated_delta", "expected_state"),
    [
        pytest.param(
            timedelta(seconds=-300, microseconds=-1),
            "requires_lock_refresh",
            id="future-before-five-minute-boundary",
        ),
        pytest.param(
            timedelta(seconds=-300),
            "candidate_available",
            id="future-exact-five-minute-boundary",
        ),
        pytest.param(
            timedelta(seconds=-300, microseconds=1),
            "candidate_available",
            id="future-after-five-minute-boundary",
        ),
        pytest.param(
            timedelta(days=14, seconds=-300, microseconds=-1),
            "candidate_available",
            id="expiry-before-activation-margin",
        ),
        pytest.param(
            timedelta(days=14, seconds=-300),
            "requires_lock_refresh",
            id="expiry-exact-activation-margin",
        ),
        pytest.param(
            timedelta(days=14, seconds=-300, microseconds=1),
            "requires_lock_refresh",
            id="expiry-after-activation-margin",
        ),
    ],
)
def test_catalog_requires_lock_refresh_for_unusable_locked_grype_without_a_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evaluated_delta: timedelta,
    expected_state: str,
) -> None:
    requirement = next(
        item for item in TOOLS.value.tool("grype").requirements if item.id == "grype-db"
    )
    assert isinstance(requirement.data_contract, GrypeDatabaseDataContract)
    evaluated_at = datetime.fromisoformat(requirement.data_contract.built_at) + evaluated_delta
    resolved = ResolvedGeneration(
        state="unavailable",
        generation=None,
        pointer=None,
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: evaluated_at,
    )
    monkeypatch.setattr(
        updater,
        "resolve_active_generation",
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        updater,
        "tool_runtime_state",
        lambda tool_id: {
            "id": tool_id,
            "available": False,
            "status": "missing",
            "installed_version": None,
        },
    )

    result = handlers.catalog_check(SimpleNamespace(checkpoint=lambda: None))
    components = {item.component_id: item for item in result.components}

    assert components["grype-db"].state == expected_state
    assert components["trivy-checks"].state == "candidate_available"
    if expected_state == "requires_lock_refresh":
        assert components["grype-db"].candidate_immutable_ref is None
        assert components["grype-db"].candidate_manifest_digest is None


@pytest.mark.parametrize(
    ("component_id", "window", "mismatched_field", "expected_state"),
    [
        ("grype-db", "expired", "source_sha256", "requires_lock_refresh"),
        ("trivy-db", "activation-margin", "source_sha256", "requires_lock_refresh"),
        ("trivy-java-db", "future", "immutable_ref", "requires_lock_refresh"),
        ("grype-db", "fresh", "source_sha256", "candidate_available"),
        ("trivy-db", "fresh", "immutable_ref", "candidate_available"),
        ("trivy-checks", "acquisition-relative", "source_sha256", "candidate_available"),
    ],
)
def test_catalog_replacement_checks_selected_lock_freshness_despite_old_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component_id: str,
    window: str,
    mismatched_field: str,
    expected_state: str,
) -> None:
    requirement = next(
        item for tool in TOOLS.value.tools for item in tool.requirements
        if item.id == component_id
    )
    if window == "acquisition-relative":
        evaluated_at = MOMENT
    else:
        updated_at = updater.locked_intrinsic_updated_at(requirement)
        assert updated_at is not None
        assert requirement.max_age_seconds is not None
        offsets = {
            "expired": timedelta(seconds=requirement.max_age_seconds),
            "activation-margin": timedelta(seconds=(
                requirement.max_age_seconds - updater.MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS
            )),
            "future": -timedelta(minutes=5, microseconds=1),
            "fresh": timedelta(hours=1),
        }
        evaluated_at = updater._parse_utc(updated_at, "selected locked timestamp") + offsets[window]
    candidate = _data_candidate(
        component_id=component_id,
        updated_at=(evaluated_at - timedelta(hours=1)).isoformat(),
        expires_at=(evaluated_at + timedelta(days=6)).isoformat(),
    )
    receipt = candidate.manifest.components[0]
    setattr(receipt, mismatched_field, "0" * 64 if mismatched_field == "source_sha256" else "old-reviewed-ref")
    candidate.manifest.tool_lock_sha256 = "1" * 64
    resolved = ResolvedGeneration(
        state="ready",
        generation=ValidatedGeneration(
            path=tmp_path / "generation",
            manifest=candidate.manifest,
            manifest_sha256="f" * 64,
        ),
        pointer=None,
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: evaluated_at,
    )
    monkeypatch.setattr(updater, "resolve_active_generation", lambda *_args, **_kwargs: resolved)
    monkeypatch.setattr(updater, "tool_runtime_state", lambda tool_id: {
        "id": tool_id, "available": False, "status": "missing", "installed_version": None,
    })

    result = handlers.catalog_check(_CheckpointContext())
    component = next(item for item in result.components if item.component_id == component_id)

    assert result.catalog_mode == "source-reviewed/bundled"
    assert result.catalog_digest is None
    assert component.state == expected_state
    if expected_state == "requires_lock_refresh":
        assert component.candidate_immutable_ref is None
        assert component.candidate_manifest_digest is None
    else:
        assert component.candidate_immutable_ref == f"sha256:{requirement.source.sha256}"
        assert component.candidate_manifest_digest == requirement.source.sha256
    assert not handlers.cache_root.exists()
    assert not handlers.scratch_root.exists()


def test_catalog_uses_locked_trivy_hard_expiry_before_any_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = next(
        item
        for item in TOOLS.value.tool("trivy").requirements
        if item.id == "trivy-db"
    )
    contract = requirement.data_contract
    assert contract is not None
    refresh_due = updater._parse_utc(
        contract.publisher_refresh_due_at,
        "publisher refresh due",
    )
    assert updater._locked_intrinsic_candidate_is_temporally_unusable(
        requirement,
        refresh_due + timedelta(days=1),
    ) is False
    hard_expiry_boundary = updater._parse_utc(
        contract.publisher_updated_at,
        "publisher updated",
    ) + timedelta(days=14, minutes=-5)
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: hard_expiry_boundary,
    )
    monkeypatch.setattr(
        updater,
        "resolve_active_generation",
        lambda *_args, **_kwargs: ResolvedGeneration(
            state="unavailable",
            generation=None,
            pointer=None,
        ),
    )
    monkeypatch.setattr(
        updater,
        "tool_runtime_state",
        lambda tool_id: {
            "id": tool_id,
            "available": False,
            "status": "missing",
            "installed_version": None,
        },
    )

    result = handlers.catalog_check(SimpleNamespace(checkpoint=lambda: None))
    components = {item.component_id: item for item in result.components}

    assert components["trivy-db"].state == "requires_lock_refresh"
    assert components["trivy-db"].candidate_manifest_digest is None


def test_direct_cache_update_cannot_download_an_expired_locked_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = next(
        item
        for item in TOOLS.value.tool("trivy").requirements
        if item.id == "trivy-db"
    )
    contract = requirement.data_contract
    assert contract is not None
    assert requirement.max_age_seconds is not None
    expired_at = updater._parse_utc(
        contract.publisher_updated_at,
        "publisher updated",
    ) + timedelta(seconds=requirement.max_age_seconds)
    store = OperationStore(tmp_path / "cache")
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=store.cache_root,
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: expired_at,
    )
    calls: list[str] = []

    def forbidden(label: str):
        def observe(*_args: object, **_kwargs: object) -> None:
            calls.append(label)

        return observe

    monkeypatch.setattr(updater, "_run_data_command", forbidden("command"))
    monkeypatch.setattr(
        updater,
        "_download_direct_locked_asset",
        forbidden("direct-download"),
    )
    monkeypatch.setattr(updater, "download_locked_asset", forbidden("download"))
    monkeypatch.setattr(
        updater,
        "_data_update_capacity_preflight",
        forbidden("capacity-preflight"),
    )

    failed = execute_operation(
        _request(components=["trivy-db"]),
        TOOLS,
        RULES,
        store,
        cache_update=handlers.cache_update,
        now=lambda: NOW,
        evaluation_now=lambda: expired_at,
    )

    assert failed.status == "failed"
    assert failed.error_code == "operation_failed"
    assert calls == []
    assert list((store.cache_root / "staging").iterdir()) == []


def test_runtime_resolution_rejects_freshness_beyond_the_reviewed_lock(
    tmp_path: Path,
) -> None:
    candidate = _data_candidate(
        updated_at="2026-08-12T20:00:00Z",
        expires_at="2026-08-26T20:00:00.000001Z",
    )
    generation = ValidatedGeneration(
        path=tmp_path / "generation",
        manifest=candidate.manifest,  # type: ignore[arg-type]
        manifest_sha256="f" * 64,
    )
    resolved = ResolvedGeneration(
        state="ready",
        generation=generation,
        pointer=None,
    )

    with pytest.raises(updater.CacheValidationError, match="differs from its reviewed lock"):
        updater.runtime_components_from_resolved(
            resolved,
            TOOLS,
            RULES,
            ["trivy-db"],
            now=MOMENT,
        )


@pytest.mark.parametrize(
    ("resolved_state", "component_id", "updated_at", "expires_at", "expected_state"),
    [
        (
            "ready",
            "trivy-db",
            "2026-08-12T20:00:00Z",
            NOW,
            "requires_lock_refresh",
        ),
        (
            "fallback",
            "trivy-db",
            "2026-08-12T20:00:00Z",
            NOW,
            "requires_lock_refresh",
        ),
        (
            "fallback",
            "trivy-db",
            "2026-08-12T20:00:00Z",
            "2026-08-12T21:05:00Z",
            "requires_lock_refresh",
        ),
        (
            "ready",
            "trivy-db",
            "2026-08-12T21:05:00.000001Z",
            "2026-08-13T21:05:00.000001Z",
            "requires_lock_refresh",
        ),
        (
            "ready",
            "trivy-db",
            "2026-08-12T20:00:00Z",
            "2026-08-26T20:00:00.000001Z",
            "requires_lock_refresh",
        ),
        (
            "ready",
            "trivy-checks",
            "2026-08-12T20:00:00Z",
            NOW,
            "candidate_available",
        ),
    ],
)
def test_locked_catalog_requires_refresh_only_for_unusable_intrinsic_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolved_state: str,
    component_id: str,
    updated_at: str,
    expires_at: str,
    expected_state: str,
) -> None:
    # These cases isolate temporal admission; installed-content mismatches are
    # covered separately with actual canonical file records.
    monkeypatch.setattr(updater, "receipt_matches_installed_content", lambda *_args: True)
    candidate = _data_candidate(
        component_id=component_id,
        updated_at=updated_at,
        expires_at=expires_at,
    )
    generation = ValidatedGeneration(
        path=tmp_path / "generation",
        manifest=candidate.manifest,  # type: ignore[arg-type]
        manifest_sha256="f" * 64,
    )
    resolved = ResolvedGeneration(
        state=resolved_state,  # type: ignore[arg-type]
        generation=generation,
        pointer=None,
    )
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=RULES,
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
        evaluation_now=lambda: MOMENT,
    )
    monkeypatch.setattr(updater, "resolve_active_generation", lambda *_args, **_kwargs: resolved)
    monkeypatch.setattr(
        updater,
        "tool_runtime_state",
        lambda tool_id: {
            "id": tool_id,
            "available": False,
            "status": "missing",
            "installed_version": None,
        },
    )

    result = handlers.catalog_check(SimpleNamespace(checkpoint=lambda: None))
    components_by_id = {item.component_id: item for item in result.components}

    assert result.checked_at == "2026-08-12T21:00:00.000000Z"
    assert components_by_id[component_id].state == expected_state
    if expected_state == "requires_lock_refresh":
        assert components_by_id[component_id].candidate_immutable_ref is None


def test_catalog_lock_refresh_uses_the_lock_timestamp_contract() -> None:
    requirements = {
        requirement.id: requirement
        for tool in TOOLS.value.tools
        for requirement in tool.requirements
    }

    for component_id in (
        "grype-db",
        "trivy-checks",
        "trivy-db",
        "trivy-java-db",
    ):
        requirement = requirements[component_id]
        receipt = _data_candidate(
            component_id=component_id,
            updated_at="2026-08-12T20:00:00Z",
            expires_at=NOW,
        ).manifest.components[0]

        assert requirement.data_contract is not None
        assert updater._source_intrinsic_candidate_is_temporally_unusable(
            receipt,
            requirement,
            MOMENT,
        ) is (requirement.data_contract.timestamp_kind == "intrinsic")

    intrinsic = requirements["trivy-db"]
    unavailable = intrinsic.model_copy(
        update={"provenance": "unavailable", "data_contract": None}
    )
    receipt = _data_candidate(
        updated_at="2026-08-12T20:00:00Z",
        expires_at=NOW,
    ).manifest.components[0]
    receipt.source_sha256 = "0" * 64
    assert not updater._source_intrinsic_candidate_is_temporally_unusable(
        receipt,
        intrinsic,
        MOMENT,
    )

    receipt.source_sha256 = intrinsic.source.sha256
    receipt.immutable_ref = "mismatched-lock-ref"
    assert not updater._source_intrinsic_candidate_is_temporally_unusable(
        receipt,
        intrinsic,
        MOMENT,
    )

    receipt.immutable_ref = intrinsic.source.immutable_ref
    assert not updater._source_intrinsic_candidate_is_temporally_unusable(
        receipt,
        unavailable,
        MOMENT,
    )


def test_catalog_execution_is_idempotent_and_bounded(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(kind="catalog_check", components=[])
    calls = 0

    def catalog_handler(_context: object) -> CatalogOperationResult:
        nonlocal calls
        calls += 1
        return _catalog()

    completed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        catalog_check=catalog_handler,
        now=lambda: NOW,
    )
    assert completed.status == "completed"
    assert completed.result is not None
    assert completed.result.kind == "catalog"

    replay = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        catalog_check=catalog_handler,
        now=lambda: NOW,
    )
    assert replay == completed
    assert calls == 1


def test_unexpected_handler_failure_does_not_persist_process_output(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(kind="catalog_check", components=[])

    def leaking_handler(_context: object) -> CatalogOperationResult:
        raise RuntimeError("token=hunter2 /private/source https://example.invalid stderr dump")

    failed = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        catalog_check=leaking_handler,
        now=lambda: NOW,
    )
    assert failed.status == "failed"
    assert failed.error_code == "operation_failed"
    rendered = failed.model_dump_json()
    assert "hunter2" not in rendered
    assert "/private/source" not in rendered
    assert "example.invalid" not in rendered


def test_installed_content_failure_terminalizes_activity_and_retry_is_clean(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["grype-db"])
    evidence = updater.InstalledContentFailureEvidence(
        kind="installed_content_mismatch",
        component_id="grype-db",
        runtime_platform="linux/amd64",
        hash_algorithm="kodesec-canonical-tree-v1",
        expected_sha256="a" * 64,
        observed_sha256="b" * 64,
        expected_file_count=2,
        observed_file_count=3,
        expected_size_bytes=100,
        observed_size_bytes=101,
    )

    def mismatched_handler(context: object) -> str:
        context.progress(  # type: ignore[attr-defined]
            "validating_source",
            component_id="grype-db",
            component_index=1,
            component_total=1,
            now=NOW,
        )
        raise updater.InstalledContentMismatchError(evidence)

    with caplog.at_level("ERROR", logger=updater.LOGGER.name):
        failed = execute_operation(
            request,
            TOOLS,
            RULES,
            store,
            cache_update=mismatched_handler,
            now=lambda: NOW,
        )

    assert failed.status == "failed"
    assert failed.error_code == "installed_content_mismatch"
    assert failed.error_detail == (
        "scanner installed data differs from its reviewed lock on linux amd64"
    )
    assert failed.activity is None
    persisted = store.load(request.operation_id)
    assert persisted == failed
    assert "component_id=grype-db" in caplog.text
    assert "runtime_platform=linux/amd64" in caplog.text
    assert f"expected_sha256={evidence.expected_sha256}" in caplog.text
    assert f"observed_sha256={evidence.observed_sha256}" in caplog.text

    retry = _request(
        operation_id=request.operation_id,
        components=["grype-db"],
        attempt=2,
    )
    restarted, should_execute = store.create_or_get(retry, now=NOW)
    assert should_execute is True
    assert restarted.status == "queued"
    assert restarted.activity is None
    assert restarted.error_code is None
    assert restarted.error_detail is None


@pytest.mark.parametrize("failure_code", [
    "files", "import_metadata", "import_checksum", "file", "changed", "size",
    "deadline", "cancelled", "schema", "integrity", "data", "database",
])
def test_grype_validation_failure_preserves_typed_terminal_reason(
    tmp_path: Path, failure_code: str,
) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(components=["grype-db"])

    def invalid_database(context: object) -> str:
        context.progress(  # type: ignore[attr-defined]
            "validating_source", component_id="grype-db",
            component_index=1, component_total=1, now=NOW,
        )
        raise updater.GrypeContentValidationError(failure_code)

    failed = execute_operation(
        request, TOOLS, RULES, store, cache_update=invalid_database,
        now=lambda: NOW,
    )

    assert failed.status == "failed"
    assert failed.activity is None
    assert failed.result is None
    assert store.load(request.operation_id) == failed
    assert not (store.cache_root / "active.json").exists()
    if failure_code == "deadline":
        assert failed.error_code == "cache_grype_validation_timeout"
        assert failed.error_detail == (
            "Grype database validation timed out; the candidate was not "
            "activated and preparation may be retried."
        )
    else:
        assert failed.error_code == "cache_grype_validation_invalid"
        assert failed.error_detail == (
            f"Grype database validation failed ({failure_code}); the candidate "
            "was not activated. Review scanner preparation details before retrying."
        )


@pytest.mark.parametrize("valid_timing", [False, True])
def test_grype_phase_telemetry_is_bounded_and_does_not_change_public_failure(tmp_path, caplog, valid_timing):
    from kodesec_scanner.grype_identity import GrypeValidationTiming

    store = OperationStore(tmp_path / "cache")
    request = _request(components=["grype-db"])

    def fail(context):
        context.progress("validating_source", component_id="grype-db",
                         component_index=1, component_total=1, now=NOW)
        raise updater.GrypeContentValidationError("deadline", validation_timing=(
            GrypeValidationTiming("sqlite_integrity", 800, 900, False) if valid_timing
            else {"phase": "private/path/secret", "elapsed": "untrusted"}
        ))

    with caplog.at_level("ERROR", logger=updater.LOGGER.name):
        failed = execute_operation(request, TOOLS, RULES, store, cache_update=fail, now=lambda: NOW)
    assert failed.status == "failed"
    assert failed.error_code == "cache_grype_validation_timeout"
    assert failed.result is None
    assert not (store.cache_root / "active.json").exists()
    assert "grype_validation_deadline" in caplog.text
    assert "private/path/secret" not in caplog.text
    assert ("validation_phase=sqlite_integrity" in caplog.text) == valid_timing
    assert ("phase_elapsed_ms=800 validation_elapsed_ms=900 timing_capped=False" in caplog.text) == valid_timing


def test_running_operation_honors_durable_cancellation(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request(kind="catalog_check", components=[])

    def cancelling_handler(context: object) -> CatalogOperationResult:
        typed = context  # keep the handler signature narrow at the public boundary
        typed.store.request_cancel(  # type: ignore[attr-defined]
            request.operation_id,
            request_digest=request.request_digest,
            now=NOW,
        )
        typed.checkpoint()  # type: ignore[attr-defined]
        raise AssertionError("checkpoint must cancel")

    cancelled = execute_operation(
        request,
        TOOLS,
        RULES,
        store,
        catalog_check=cancelling_handler,
        now=lambda: NOW,
    )
    assert cancelled.status == "cancelled"
    assert cancelled.stage == "cancelled"
    assert cancelled.result is None
