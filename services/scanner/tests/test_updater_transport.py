"""Locked transport grammar and redacted failure evidence; no network calls."""

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from kodesec_scanner import updater
from kodesec_scanner.preparation_budget import issue_budget, timestamp

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)


def context(tmp_path, elapsed=0):
    budget = issue_budget(now=NOW)
    request = updater.OperationRequest(
        schema_version=2, operation_id=uuid4(), kind="catalog_check",
        preparation_budget=budget, requested_components=[], attempt=1, max_attempts=1,
        request_digest=updater.operation_request_digest(
            schema_version=2, kind="catalog_check", requested_components=[],
            preparation_budget=budget,
        ),
    )
    store = updater.OperationStore(tmp_path / "cache")
    store.create_or_get(request, now=timestamp(NOW))
    return updater.OperationContext(
        request=request, store=store,
        wall_now=lambda: timestamp(NOW + timedelta(seconds=elapsed)),
    )


def capture_process(monkeypatch, returncode=0, stderr=b""):
    calls = []

    class Process:
        def __init__(self, command, **kwargs):
            self.returncode = returncode
            calls.append(list(command))

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            return b"", stderr

    monkeypatch.setattr(updater.subprocess, "Popen", Process)
    return calls


@pytest.mark.parametrize("elapsed, retry", [(0, "300"), (1198.25, "1"), (1199.75, None)])
def test_curl_retry_integer_grammar_preserves_decreasing_budget(tmp_path, monkeypatch, elapsed, retry):
    calls = capture_process(monkeypatch)
    command = ["curl", "--max-time", "300", "--connect-timeout", "20",
               "--retry-max-time", "300", "--retry", "3", "--version"]
    updater._run_bounded_curl(command, context=context(tmp_path, elapsed), timeout_seconds=300)
    actual = calls[0]
    remaining = min(300, 1200 - elapsed)
    for flag in ("--max-time", "--connect-timeout"):
        assert 0 < float(actual[actual.index(flag) + 1]) <= remaining
    if retry is None:
        assert "--retry-max-time" not in actual
        assert actual[actual.index("--retry") + 1] == "0"
    else:
        assert actual[actual.index("--retry-max-time") + 1] == retry
        assert 0 < int(retry) <= remaining
    assert command[command.index("--retry-max-time") + 1] == "300"


def test_actual_local_curl_option_parser_without_transfer(
    tmp_path, monkeypatch, record_testsuite_property,
):
    curl = Path("/usr/bin/curl")
    if not curl.is_file():
        pytest.skip("local curl parser is unavailable")
    environment = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "NO_COLOR": "1"}
    version = subprocess.run(
        [str(curl), "-q", "--version"], capture_output=True, timeout=3,
        check=True, env=environment,
    )
    decimal = subprocess.run(
        [str(curl), "-q", "--retry-max-time", "1.500000", "--version"],
        capture_output=True, timeout=3, env=environment,
    )
    # Capture the actual production argument rewrite, then test that parser.
    with monkeypatch.context() as patch:
        calls = capture_process(patch)
        updater._run_bounded_curl(
            [str(curl), "-q", "--retry-max-time", "1.5", "--retry", "3", "--version"],
            context=context(tmp_path), timeout_seconds=1.5,
        )
    integer = subprocess.run(calls[0], capture_output=True, timeout=3, env=environment)
    assert all(len(result.stdout) + len(result.stderr) <= 16 * 1024
               for result in (version, decimal, integer))
    assert integer.returncode == 0
    version_token = version.stdout.splitlines()[0].split()[1].decode("ascii")
    numeric_version = tuple(int(part) for part in version_token.split(".")[:3])
    if numeric_version < (8, 16, 0):
        assert decimal.returncode == 2
        assert b"numerical parameter" in decimal.stderr
    else:
        assert decimal.returncode == 0
    record_testsuite_property("local_curl_compatibility", json.dumps({
        "scope": "local_option_parser_not_installed_image", "url_provided": False,
        "path": str(curl), "sha256": hashlib.sha256(curl.read_bytes()).hexdigest(),
        "version": version_token, "decimal_exit": decimal.returncode,
        "integer_exit": integer.returncode,
    }, sort_keys=True))


def test_transport_failure_keeps_only_typed_redacted_evidence(tmp_path, monkeypatch, caplog):
    secret = b"https://example.invalid/private?token=synthetic-secret /private/source.py"
    capture_process(monkeypatch, returncode=2, stderr=secret)
    current = context(tmp_path)
    with pytest.raises(updater.AssetTransportError) as caught:
        updater._run_bounded_curl(
            ["curl", "--head", "--version"], context=current, timeout_seconds=10,
        )
    failure = caught.value
    assert failure.reason == "curl_exit" and failure.transport_stage == "release_headers"
    assert failure.returncode == 2 and failure.signal is None
    updater._log_operation_failure(current.store, current.request.operation_id, failure)
    record = updater._fail_operation(
        current.store, current.request.operation_id, "operation_failed", timestamp(NOW),
        exc=failure,
    )
    rendered = caplog.text + record.model_dump_json() + repr(vars(failure))
    assert "returncode=2" in caplog.text and "transport_stage=release_headers" in caplog.text
    assert record.error_code == "locked_asset_transport_failed"
    for private in ("synthetic-secret", "example.invalid", "/private/source.py"):
        assert private not in rendered


@pytest.mark.parametrize("reason, stage, code", [
    ("https://private.invalid", "asset_body", 2),
    ("curl_exit", "/private/source", 2),
    ("curl_exit", "asset_body", 0),
    ("curl_exit", "asset_body", True),
    ("curl_exit", "asset_body", 256),
])
def test_transport_classification_rejects_unbounded_or_untyped_values(reason, stage, code):
    with pytest.raises(ValueError):
        updater.AssetTransportError(reason, stage, code)
