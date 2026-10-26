from __future__ import annotations

import importlib.util
import json
import math
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from itertools import combinations
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from kodesec_scanner import external
from kodesec_scanner.redaction import REDACTED, redact_json, redact_text
from kodesec_scanner.settings import Settings
from kodesec_scanner.tools import SCANNER_TOOLS


def _fake_result(
    command: list[str],
    returncode: int = 0,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(command, returncode)


def _sarif_document(*results: object) -> dict[str, object]:
    return {
        "runs": [
            {
                "columnKind": "utf16CodeUnits",
                "tool": {"driver": {"rules": []}},
                "results": list(results),
            }
        ]
    }


def _valid_sarif_result(uri: str = "source.py") -> dict[str, object]:
    return {
        "ruleId": "fixture-rule",
        "level": "error",
        "message": {"text": "fixture finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _bearer_document(*findings: object, errors: object = None) -> dict[str, object]:
    return {"source": "Bearer", "version": "2.1.0+lomo.1", "findings": list(findings),
            "errors": [] if errors is None else errors}


def _valid_bearer_finding(uri: str = "source.py") -> dict[str, object]:
    return {"id": "fixture-rule", "title": "fixture finding", "filename": uri, "severity": "high",
            "sink": {"start": 1, "end": 1, "column": {"start": 1, "end": 2}}}


@pytest.fixture(scope="module")
def api_redaction() -> ModuleType:
    path = Path(__file__).resolve().parents[3] / "apps/api/kodesec_api/redaction.py"
    spec = importlib.util.spec_from_file_location("api_redaction_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("code", [
    "bearer_native_report_invalid",
    "bearer_analysis_incomplete:multiple",  # Retained historical receipts.
    "bearer_analysis_incomplete:aerr_defpstu,file_timeout,memory_limit,unknown,worker_failure",
    "bearer_analysis_incomplete:aerr_s,file_timeout",
    *[
        f"bearer_analysis_incomplete:{','.join(categories)}"
        for count in range(1, 6)
        for categories in combinations(
            ("analysis_error", "file_timeout", "memory_limit", "unknown", "worker_failure"), count,
        )
    ],
])
def test_bearer_fixed_diagnostics_survive_public_redaction(code: str, api_redaction: ModuleType) -> None:
    assert len(code.encode("ascii")) <= 90
    for text_redactor in (redact_text, api_redaction.redact_text):
        assert text_redactor(code) == code
        assert text_redactor(f"bearer: {code}") == f"bearer: {code}"
    summary = {"tools": [{"id": "bearer", "error": code}], "errors": [f"bearer: {code}"]}
    assert redact_json(summary) == summary
    assert api_redaction.redact_json(summary) == summary


def _sarif_result_with_multiple_locations() -> dict[str, object]:
    result = _valid_sarif_result()
    locations = result["locations"]
    assert isinstance(locations, list)
    result["locations"] = [locations[0], json.loads(json.dumps(locations[0]))]
    return result


def _sarif_result_with_security_severity(value: object) -> dict[str, object]:
    result = _valid_sarif_result()
    result["properties"] = {"security-severity": value}
    return result


def test_trivy_repeated_package_locations_preserve_all_occurrences_atomically(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "package-lock.json").write_text("{\n  \"first\": 1,\n  \"second\": 2\n}\n", encoding="utf-8")
    result = _valid_sarif_result("package-lock.json")
    result["ruleId"] = "CVE-2026-13149"
    locations = [
        {"physicalLocation": {
            "artifactLocation": {"uri": "package-lock.json", "uriBaseId": "ROOTPATH"},
            "region": {"startLine": line, "startColumn": 1,
                       "endLine": line + 1, "endColumn": 1},
        }, "message": {"text": "package-lock.json: bounded-fixture@1.0.0"}}
        for line in (2, 3)
    ]
    result["locations"] = locations
    native = tmp_path / "trivy.sarif"
    native.write_text(json.dumps(_sarif_document(result)), encoding="utf-8")
    parsed = external._parse_sarif(native, "trivy", root)
    assert parsed.integrity.as_dict() == {
        "complete": True, "total_records": 1, "accepted_records": 1,
        "intentionally_filtered_records": 0, "dropped_records": 0,
        "dropped_reason_counts": {}, "filter_reason_counts": {},
    }
    findings = external._validated_native_findings(parsed)
    assert [(item.file_path, item.start_line, item.start_column,
             item.end_line, item.end_column) for item in findings] == [
        ("package-lock.json", 2, 1, 3, 1), ("package-lock.json", 3, 1, 4, 1),
    ]
    assert len({item.fingerprint for item in findings}) == 2

    # No broadened permission for other producers, and no partial acceptance of
    # a Trivy result with one unsafe, unreadable or malformed occurrence.
    other = external._parse_sarif(native, "opengrep", root)
    assert other.integrity.dropped_reason_counts == {"multiple_locations": 1}
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (root / "linked.json").symlink_to(outside)
    for invalid in (
        {"physicalLocation": {"artifactLocation": {"uri": "../outside.json"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "linked.json"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "missing.json"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"},
                              "region": {"startLine": 999}}},
        "not-a-location",
    ):
        result["locations"] = [locations[0], invalid]
        native.write_text(json.dumps(_sarif_document(result)), encoding="utf-8")
        parsed = external._parse_sarif(native, "trivy", root)
        assert parsed.findings == []
        assert parsed.integrity.total_records == 1
        assert parsed.integrity.accepted_records == 0
        assert parsed.integrity.dropped_reason_counts == {"invalid_trivy_occurrence_locations": 1}
        with pytest.raises(external.NativeParseIntegrityError):
            external._validated_native_findings(parsed)


def _runtime_components(tmp_path: Path) -> dict[str, Path]:
    cache = tmp_path / "generation"
    components = {
        "trivy-db": cache / "trivy" / "db",
        "trivy-java-db": cache / "trivy" / "java-db",
        "trivy-checks": cache / "trivy" / "checks",
        "grype-db": cache / "grype",
        "opengrep-reviewed-rules": cache / "opengrep" / "pack",
        "bearer-rules": cache / "bearer" / "rules",
    }
    for path in components.values():
        path.mkdir(parents=True, exist_ok=True)
    return components


def _wait_for_pids_to_exit(process_ids: list[int], timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    remaining = set(process_ids)
    while remaining and time.monotonic() < deadline:
        for process_id in tuple(remaining):
            try:
                os.kill(process_id, 0)
            except (ProcessLookupError, PermissionError):
                remaining.discard(process_id)
        if remaining:
            time.sleep(0.02)
    return not remaining


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ("source.py", "source.py"),
        ("./nested/source.py", "nested/source.py"),
        ("../outside.py", ""),
        ("/tmp/outside.py", ""),
        ("file:///tmp/outside.py", ""),
    ],
)
def test_native_finding_paths_are_canonical_and_confined(
    tmp_path: Path,
    reported: str,
    expected: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    assert external._normalize_path(root, reported) == expected


def test_request_scratch_is_private_and_removed_on_success_and_failure(tmp_path: Path) -> None:
    scratch_root = tmp_path / "scratch"
    successful: Path
    with external.request_scratch_directory(str(scratch_root), 7) as request_dir:
        successful = request_dir
        assert stat.S_IMODE(request_dir.stat().st_mode) == 0o700
        (request_dir / "raw.sarif").write_text("raw fixture", encoding="utf-8")
    assert not successful.exists()
    assert list(scratch_root.iterdir()) == []

    class SimulatedRequestCrash(BaseException):
        pass

    failed: Path
    with pytest.raises(SimulatedRequestCrash):
        with external.request_scratch_directory(str(scratch_root), 8) as request_dir:
            failed = request_dir
            (request_dir / "raw.stderr").write_text("failure fixture", encoding="utf-8")
            raise SimulatedRequestCrash
    assert not failed.exists()
    assert list(scratch_root.iterdir()) == []


def test_command_streams_raw_output_only_to_scratch_and_timeout_cleans_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(external, "get_settings", lambda: SimpleNamespace(external_tool_nice=0))
    scratch_root = tmp_path / "scratch"
    request_path: Path
    with external.request_scratch_directory(str(scratch_root), 9) as request_dir:
        request_path = request_dir
        raw_dir = request_dir / "fixture"
        result = external._run_command(
            "fixture",
            [
                sys.executable,
                "-c",
                "import sys; print('raw stdout fixture'); print('raw stderr fixture', file=sys.stderr)",
            ],
            tmp_path,
            5,
            raw_dir,
        )
        assert result.returncode == 0
        assert (raw_dir / "fixture.stdout.txt").read_text(encoding="utf-8").strip() == "raw stdout fixture"
        assert (raw_dir / "fixture.stderr.txt").read_text(encoding="utf-8").strip() == "raw stderr fixture"
    assert not request_path.exists()

    with external.request_scratch_directory(str(scratch_root), 10) as request_dir:
        request_path = request_dir
        with pytest.raises(subprocess.TimeoutExpired):
            external._run_command(
                "fixture",
                [sys.executable, "-c", "import time; print('raw timeout fixture'); time.sleep(10)"],
                tmp_path,
                0.05,
                request_dir / "fixture",
            )
    assert not request_path.exists()
    assert list(scratch_root.iterdir()) == []


def test_cancellation_kills_the_exact_external_process_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        external,
        "get_settings",
        lambda: SimpleNamespace(external_tool_nice=0, process_termination_grace_seconds=0.1),
    )
    pid_file = tmp_path / "processes.txt"
    raw_dir = tmp_path / "raw"
    control = external.ExecutionControl.with_timeout(10, termination_grace_seconds=0.1)
    errors: list[BaseException] = []
    script = """
import os, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
])
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()} {child.pid}")
    handle.flush()
    os.fsync(handle.fileno())
while True:
    time.sleep(1)
"""

    def invoke() -> None:
        try:
            external._run_command(
                "fixture",
                [sys.executable, "-c", script, str(pid_file)],
                tmp_path,
                30,
                raw_dir,
                control=control,
            )
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pid_file.exists()
    process_ids = [int(value) for value in pid_file.read_text(encoding="utf-8").split()]
    process_group_id = process_ids[0]
    try:
        control.cancel_event.set()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], external.RunCancelled)
        assert not external._process_group_exists(process_group_id)
        assert _wait_for_pids_to_exit(process_ids)
    finally:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def test_successful_leader_cannot_leave_a_descendant_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "successful-processes.txt"
    script = """
import os, signal, subprocess, sys
child = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
])
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(f"{os.getpid()} {child.pid}")
    handle.flush()
    os.fsync(handle.fileno())
"""
    result = external._run_command(
        "fixture",
        [sys.executable, "-c", script, str(pid_file)],
        tmp_path,
        5,
        tmp_path / "successful-raw",
    )
    process_ids = [int(value) for value in pid_file.read_text(encoding="utf-8").split()]
    process_group_id = process_ids[0]
    try:
        assert result.returncode == 0
        assert not external._process_group_exists(process_group_id)
        assert _wait_for_pids_to_exit(process_ids)
    finally:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def test_captured_control_output_is_killed_at_the_byte_limit(tmp_path: Path) -> None:
    pid_file = tmp_path / "capture-process.txt"
    script = """
import os, sys, time
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
    handle.flush()
    os.fsync(handle.fileno())
os.write(1, b"x" * 65536)
time.sleep(60)
"""
    started = time.monotonic()
    with pytest.raises(external.CapturedCommandOutputLimitError) as raised:
        external.run_captured_command(
            [sys.executable, "-c", script, str(pid_file)],
            tmp_path,
            10,
            os.environ.copy(),
            max_output_bytes=128,
        )
    assert raised.value.limit_bytes == 128
    assert time.monotonic() - started < 3
    process_group_id = int(pid_file.read_text(encoding="utf-8"))
    try:
        assert not external._process_group_exists(process_group_id)
    finally:
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def test_native_findings_and_logs_never_enter_persistent_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.py").write_text("password = 'fixture phrase only'\n", encoding="utf-8")
    scratch_root = tmp_path / "scratch"
    publish_root = tmp_path / "persistent" / "scans" / "11"
    cache_root = tmp_path / "cache"
    raw_paths: list[Path] = []

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, timeout, stdout_path
        assert scanner == "gitleaks"
        assert env is not None
        assert Path(env["TMPDIR"]) == raw_dir
        assert Path(env["XDG_CACHE_HOME"]).is_relative_to(raw_dir)
        out = Path(command[command.index("--report-path") + 1])
        out.write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "columnKind": "utf16CodeUnits",
                            "tool": {"driver": {"rules": []}},
                            "results": [
                                {
                                    "ruleId": "fixture-rule",
                                    "level": "error",
                                    "message": {"text": "password = 'fixture phrase only'"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "source.py"},
                                                "region": {"startLine": 1},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (raw_dir / "gitleaks.stdout.txt").write_text("raw stdout", encoding="utf-8")
        (raw_dir / "gitleaks.stderr.txt").write_text("raw stderr", encoding="utf-8")
        raw_paths.extend([out, raw_dir / "gitleaks.stdout.txt", raw_dir / "gitleaks.stderr.txt"])
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(scratch_root), 11) as request_dir:
        request_path = request_dir
        result = external.run_external_tool(
            "gitleaks",
            repo,
            request_dir,
            publish_root,
            cache_root,
            30,
        )
        assert result.status == "completed"
        assert len(result.findings) == 1
        assert result.artifacts == []
        assert all(path.is_relative_to(request_dir) and not path.exists() for path in raw_paths)
        assert not publish_root.exists()
    assert not request_path.exists()
    assert all(not path.exists() for path in raw_paths)


def test_only_sanitized_sbom_is_published_and_cache_is_separate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scratch_root = tmp_path / "scratch"
    publish_root = tmp_path / "persistent" / "scans" / "12"
    cache_root = tmp_path / "cache"
    fixture_credential = "fixture-publication-boundary-secret-value"
    component_digest = "A1" * 32
    hash_lookalike = "B2" * 32
    wrong_length_digest = "C3" * 20
    unrecognized_digest = "D4" * 32
    raw_sbom: Path | None = None

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal raw_sbom
        del cwd, timeout, stdout_path
        assert scanner == "syft"
        assert env is not None
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
        raw_sbom = Path(next(value.split("=", 1)[1] for value in command if value.startswith("cyclonedx-json=")))
        raw_sbom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "metadata": {
                        "component": {
                            "type": "file",
                            "name": str(repo),
                            "bom-ref": f"root:{repo}",
                        },
                        "token": fixture_credential,
                    },
                    "components": [{
                        "name": "fixture-component",
                        "purl": "pkg:pypi/fixture-component@1.2.3",
                        "password": "fixture phrase only",
                        "hashes": [
                            {"alg": "SHA-256", "content": component_digest},
                            {"alg": "SHA-256", "content": wrong_length_digest},
                            {"alg": "SHA-999", "content": unrecognized_digest},
                            {"alg": "SHA-256", "content": hash_lookalike, "note": "not a hash record"},
                        ],
                        "evidence": {"alg": "SHA-256", "content": hash_lookalike},
                        "hash": hash_lookalike,
                        "digest": hash_lookalike,
                        "sha256": hash_lookalike,
                        "credentials": {"alg": "SHA-256", "content": hash_lookalike},
                    }],
                    "dependencies": [{"ref": f"root:{repo}", "dependsOn": []}],
                }
            ),
            encoding="utf-8",
        )
        (raw_dir / "syft.stdout.txt").write_text(fixture_credential, encoding="utf-8")
        (raw_dir / "syft.stderr.txt").write_text("raw stderr", encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(scratch_root), 12) as request_dir:
        request_path = request_dir
        result = external.run_external_tool(
            "syft",
            repo,
            request_dir,
            publish_root,
            cache_root,
            30,
        )
        assert raw_sbom is not None and raw_sbom.is_relative_to(request_dir)
        assert not raw_sbom.exists()
        assert result.status == "completed"
        assert len(result.artifacts) == 1

    assert not request_path.exists()
    assert raw_sbom is not None and not raw_sbom.exists()
    artifact = result.artifacts[0]
    published = Path(artifact.path)
    assert published == publish_root / "syft" / "syft.cyclonedx.json"
    assert published.exists()
    assert stat.S_IMODE(published.stat().st_mode) == 0o640
    content = published.read_text(encoding="utf-8")
    assert fixture_credential not in content
    payload = json.loads(content)
    assert str(repo) not in content
    assert payload["metadata"]["component"]["name"] == "source"
    assert payload["metadata"]["component"]["bom-ref"] == "urn:kodesec:source"
    assert payload["dependencies"][0]["ref"] == "urn:kodesec:source"
    component = payload["components"][0]
    assert component["name"] == "fixture-component"
    assert component["purl"] == "pkg:pypi/fixture-component@1.2.3"
    assert component["password"] == REDACTED
    hash_contents = [item["content"] for item in component["hashes"]]
    assert hash_contents.count(component_digest.lower()) == 1
    assert hash_contents.count(REDACTED) == 3
    assert component["evidence"]["content"] == REDACTED
    assert component["hash"] == REDACTED
    assert component["digest"] == REDACTED
    assert component["sha256"] == REDACTED
    assert component["credentials"] == REDACTED
    assert payload["metadata"]["token"] == REDACTED
    assert not cache_root.exists()
    assert not (publish_root / "syft" / "syft.stdout.txt").exists()
    assert not (publish_root / "syft" / "syft.stderr.txt").exists()


def test_failed_sbom_parse_publishes_nothing_and_raw_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scratch_root = tmp_path / "scratch"
    publish_root = tmp_path / "persistent" / "scans" / "13"

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        out = Path(next(value.split("=", 1)[1] for value in command if value.startswith("cyclonedx-json=")))
        out.write_text("{not-valid-json", encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(scratch_root), 13) as request_dir:
        request_path = request_dir
        result = external.run_external_tool(
            "syft",
            repo,
            request_dir,
            publish_root,
            tmp_path / "cache",
            30,
        )
        assert result.status == "failed"
        assert result.artifacts == []
    assert not request_path.exists()
    assert not publish_root.exists()


def test_sbom_publication_canonicalizes_syft_run_volatility(
    tmp_path: Path,
) -> None:
    publish_root = tmp_path / "persistent" / "scans" / "stable"

    def publish_variant(
        label: str,
        *,
        timestamp: str,
        serial: str,
        alpha_ref: str,
        beta_ref: str,
        reverse: bool,
    ) -> tuple[external.ScanArtifact, bytes]:
        scratch = tmp_path / f"scratch-{label}"
        scratch.mkdir()
        raw = scratch / "syft.cyclonedx.json"
        source_name = str(tmp_path / f"volatile-source-{label}")
        source_ref = f"root:{source_name}"
        alpha = {
            "type": "library",
            "name": "alpha",
            "version": "1.0",
            "purl": "pkg:pypi/alpha@1.0",
            "bom-ref": alpha_ref,
            "hashes": [
                {"alg": "SHA-256", "content": "a1" * 32},
                {"alg": "SHA-1", "content": "b2" * 20},
            ],
        }
        beta = {
            "type": "library",
            "name": "beta",
            "version": "2.0",
            "purl": "pkg:pypi/beta@2.0",
            "bom-ref": beta_ref,
        }
        dependencies = [
            {"ref": source_ref, "dependsOn": [beta_ref, alpha_ref]},
            {"ref": alpha_ref, "dependsOn": [beta_ref]},
            {"ref": beta_ref, "dependsOn": []},
        ]
        components = [alpha, beta]
        tools = [
            {"type": "application", "name": "syft", "version": "1.2.3"},
            {"type": "application", "name": "fixture", "version": "4.5.6"},
        ]
        if reverse:
            components.reverse()
            dependencies.reverse()
            tools.reverse()
            alpha["hashes"].reverse()
        raw.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "serialNumber": serial,
                    "metadata": {
                        "timestamp": timestamp,
                        "component": {
                            "type": "file",
                            "name": source_name,
                            "bom-ref": source_ref,
                        },
                        "tools": {"components": tools},
                    },
                    "components": components,
                    "dependencies": dependencies,
                }
            ),
            encoding="utf-8",
        )
        artifact = external._publish_sanitized_sbom(raw, scratch, publish_root)
        return artifact, Path(artifact.path).read_bytes()

    first_artifact, first_content = publish_variant(
        "one",
        timestamp="2026-08-13T08:00:00Z",
        serial="urn:uuid:00000000-0000-4000-8000-000000000099",
        alpha_ref="urn:uuid:00000000-0000-4000-8000-000000000011",
        beta_ref="urn:uuid:00000000-0000-4000-8000-000000000012",
        reverse=False,
    )
    second_artifact, second_content = publish_variant(
        "two",
        timestamp="2026-08-13T08:00:17Z",
        serial="urn:uuid:00000000-0000-4000-8000-000000000199",
        alpha_ref="urn:uuid:00000000-0000-4000-8000-000000000021",
        beta_ref="urn:uuid:00000000-0000-4000-8000-000000000022",
        reverse=True,
    )

    assert first_content == second_content
    assert first_artifact.sha256 == second_artifact.sha256
    assert first_artifact.size_bytes == second_artifact.size_bytes
    published = json.loads(second_content)
    assert "serialNumber" not in published
    assert "timestamp" not in published["metadata"]
    assert {component["name"] for component in published["components"]} == {
        "alpha",
        "beta",
    }
    component_refs = {
        component["bom-ref"] for component in published["components"]
    }
    assert len(component_refs) == 2
    assert all(
        ref.startswith(external._STABLE_GENERATED_BOM_REF_PREFIX)
        for ref in component_refs
    )
    dependency_refs = {item["ref"] for item in published["dependencies"]}
    assert dependency_refs == {external._STABLE_SOURCE_BOM_REF, *component_refs}


def test_native_finding_order_and_tags_are_canonical(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("alpha.py", "beta.py"):
        (root / name).write_text("fixture()\n", encoding="utf-8")

    def document(reverse: bool) -> dict[str, object]:
        rules = [
            {
                "id": "fixture.alpha",
                "name": "alpha",
                "properties": {"tags": ["zeta", "alpha"]},
            },
            {
                "id": "fixture.beta",
                "name": "beta",
                "properties": {"tags": ["stable", "native"]},
            },
        ]
        results = [
            {
                **_valid_sarif_result("alpha.py"),
                "ruleId": "fixture.alpha",
                "message": {"text": "alpha finding"},
            },
            {
                **_valid_sarif_result("beta.py"),
                "ruleId": "fixture.beta",
                "message": {"text": "beta finding"},
            },
        ]
        if reverse:
            rules.reverse()
            results.reverse()
            for rule in rules:
                rule["properties"]["tags"].reverse()  # type: ignore[index]
        return {
            "runs": [
                {
                    "columnKind": "utf16CodeUnits",
                    "tool": {"driver": {"rules": rules}},
                    "results": [*results, results[0]],
                }
            ]
        }

    first = tmp_path / "first.sarif"
    second = tmp_path / "second.sarif"
    first.write_text(json.dumps(document(False)), encoding="utf-8")
    second.write_text(json.dumps(document(True)), encoding="utf-8")

    first_findings = external.parse_sarif(first, "opengrep", root)
    second_findings = external.parse_sarif(second, "opengrep", root)

    assert [finding.model_dump(mode="json") for finding in first_findings] == [
        finding.model_dump(mode="json") for finding in second_findings
    ]
    assert len(first_findings) == 2
    assert all(finding.metadata["tags"] == sorted(finding.metadata["tags"]) for finding in first_findings)


def test_native_finding_identity_includes_full_normalized_location(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.py").write_text("fixture(first, second)\n", encoding="utf-8")

    def result_at(start_column: int, end_column: int) -> dict[str, object]:
        result = _valid_sarif_result()
        locations = result["locations"]
        assert isinstance(locations, list)
        physical = locations[0]["physicalLocation"]
        assert isinstance(physical, dict)
        region = physical["region"]
        assert isinstance(region, dict)
        region.update(
            {
                "startLine": 1,
                "startColumn": start_column,
                "endLine": 1,
                "endColumn": end_column,
            }
        )
        return result

    first = result_at(1, 8)
    second = result_at(10, 16)
    native = tmp_path / "columns.sarif"
    native.write_text(
        json.dumps(_sarif_document(first, second, first)),
        encoding="utf-8",
    )

    findings = external.parse_sarif(native, "opengrep", root)

    assert len(findings) == 2
    assert len({finding.fingerprint for finding in findings}) == 2
    assert {
        (finding.start_line, finding.start_column, finding.end_line, finding.end_column)
        for finding in findings
    } == {(1, 1, 1, 8), (1, 10, 1, 16)}


def test_same_fingerprint_with_divergent_native_evidence_fails_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    first = _valid_sarif_result()
    second = json.loads(json.dumps(first))
    second["level"] = "warning"
    native = tmp_path / "collision.sarif"
    native.write_text(
        json.dumps(_sarif_document(first, second)),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="finding_fingerprint_collision"):
        external.parse_sarif(native, "opengrep", root)


@pytest.mark.parametrize(
    "security_severity",
    [
        "NaN",
        "Infinity",
        "-Infinity",
        -0.01,
        10.01,
        "not-a-score",
        "",
        True,
        None,
    ],
)
def test_sarif_invalid_security_severity_fails_native_parse_integrity(
    tmp_path: Path,
    security_severity: object,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    native = tmp_path / "invalid-security-severity.sarif"
    native.write_text(
        json.dumps(
            _sarif_document(
                _sarif_result_with_security_severity(security_severity)
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(native, "opengrep", root)

    assert exc_info.value.integrity.as_dict() == {
        "complete": False,
        "total_records": 1,
        "accepted_records": 0,
        "intentionally_filtered_records": 0,
        "dropped_records": 1,
        "dropped_reason_counts": {"invalid_security_severity": 1},
        "filter_reason_counts": {},
    }


@pytest.mark.parametrize(
    ("security_severity", "expected"),
    [
        (0, "low"),
        ("0", "low"),
        (10, "critical"),
        ("10.0", "critical"),
    ],
)
def test_sarif_security_severity_accepts_inclusive_boundaries(
    tmp_path: Path,
    security_severity: object,
    expected: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    native = tmp_path / "valid-security-severity.sarif"
    native.write_text(
        json.dumps(
            _sarif_document(
                _sarif_result_with_security_severity(security_severity)
            )
        ),
        encoding="utf-8",
    )

    findings = external.parse_sarif(native, "opengrep", root)

    assert len(findings) == 1
    assert findings[0].severity == expected


@pytest.mark.parametrize(
    ("level", "expected"),
    [("error", "high"), ("warning", "medium"), ("note", "info"), ("none", "info")],
)
def test_sarif_inherits_rule_default_level_without_changing_finding_identity(
    tmp_path: Path, level: str, expected: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    del result["level"]
    document = _sarif_document(result)
    # Pinned OpenGrep 1.27.0 puts the level on its rule descriptor, not the
    # result. Its result properties carry no separate severity override.
    document["runs"][0]["tool"]["driver"]["rules"] = [{
        "id": "fixture-rule",
        "defaultConfiguration": {"level": level},
        "properties": {"precision": "very-high", "tags": ["security"]},
    }]
    native = tmp_path / "opengrep.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    inherited = external.parse_sarif(native, "opengrep", root)
    assert len(inherited) == 1
    assert inherited[0].severity == expected
    assert inherited[0].metadata["sarif_level"] == level

    result["level"] = level
    native.write_text(json.dumps(document), encoding="utf-8")
    explicit = external.parse_sarif(native, "opengrep", root)
    assert [item.model_dump(mode="json") for item in inherited] == [
        item.model_dump(mode="json") for item in explicit
    ]


@pytest.mark.parametrize("default_configuration", [{"level": "error"}, None, []])
def test_sarif_explicit_result_level_overrides_unconsumed_rule_default(
    tmp_path: Path, default_configuration: object,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    result["level"] = "note"
    document = _sarif_document(result)
    document["runs"][0]["tool"]["driver"]["rules"] = [{
        "id": "fixture-rule", "defaultConfiguration": default_configuration,
    }]
    native = tmp_path / "explicit.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    finding = external.parse_sarif(native, "opengrep", root)[0]
    assert finding.severity == "info"
    assert finding.metadata["sarif_level"] == "note"


@pytest.mark.parametrize("rule", [
    None, {"id": "fixture-rule"},
    {"id": "fixture-rule", "defaultConfiguration": {}},
])
def test_sarif_omitted_result_and_rule_levels_default_to_warning(
    tmp_path: Path, rule: dict[str, object] | None,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    del result["level"]
    document = _sarif_document(result)
    document["runs"][0]["tool"]["driver"]["rules"] = [] if rule is None else [rule]
    native = tmp_path / "default.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    finding = external.parse_sarif(native, "opengrep", root)[0]
    assert finding.severity == "medium"
    assert finding.metadata["sarif_level"] == "warning"


@pytest.mark.parametrize("origin", ["result", "rule"])
@pytest.mark.parametrize("level", [None, "", "ERROR", "unexpected", 1, False, [], {}])
def test_sarif_malformed_consumed_level_fails_native_parse_integrity(
    tmp_path: Path, origin: str, level: object,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    document = _sarif_document(result)
    if origin == "result":
        result["level"] = level
    else:
        del result["level"]
        document["runs"][0]["tool"]["driver"]["rules"] = [{
            "id": "fixture-rule", "defaultConfiguration": {"level": level},
        }]
    native = tmp_path / "invalid-level.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(native, "opengrep", root)
    assert exc_info.value.integrity.total_records == 1
    assert exc_info.value.integrity.accepted_records == 0
    assert exc_info.value.integrity.dropped_reason_counts == {"invalid_sarif_level": 1}


@pytest.mark.parametrize("configuration", [None, [], "error", False, 1])
def test_sarif_malformed_consumed_default_configuration_fails_closed(
    tmp_path: Path, configuration: object,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    del result["level"]
    document = _sarif_document(result)
    document["runs"][0]["tool"]["driver"]["rules"] = [{
        "id": "fixture-rule", "defaultConfiguration": configuration,
    }]
    native = tmp_path / "invalid-configuration.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(native, "opengrep", root)
    assert exc_info.value.integrity.dropped_reason_counts == {"invalid_sarif_level": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("configurations", [
    [{"level": "error"}, {"level": "warning"}],
    ["warning", {}],
    [None, {"level": None}],
])
def test_sarif_conflicting_duplicate_rule_default_levels_fail_closed(
    tmp_path: Path, reverse: bool, configurations: list[object],
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    del result["level"]
    document = _sarif_document(result)
    rules = [{"id": "fixture-rule", "defaultConfiguration": configuration}
             for configuration in configurations]
    document["runs"][0]["tool"]["driver"]["rules"] = rules[::-1] if reverse else rules
    native = tmp_path / "conflicting-defaults.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RuntimeError, match="conflicting duplicate SARIF rules"):
        external.parse_sarif(native, "opengrep", root)


@pytest.mark.parametrize(("result_properties", "rule_properties", "expected"), [
    ({"severity": "critical", "security-severity": 4}, {"severity": "low"}, "critical"),
    ({"security-severity": 9}, {"severity": "low"}, "low"),
    ({"security-severity": 9}, {}, "critical"),
])
def test_sarif_inherited_level_preserves_severity_property_precedence(
    tmp_path: Path, result_properties: dict[str, object],
    rule_properties: dict[str, object], expected: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("fixture()\n", encoding="utf-8")
    result = _valid_sarif_result()
    del result["level"]
    result["properties"] = result_properties
    document = _sarif_document(result)
    document["runs"][0]["tool"]["driver"]["rules"] = [{
        "id": "fixture-rule", "defaultConfiguration": {"level": "error"},
        "properties": rule_properties,
    }]
    native = tmp_path / "precedence.sarif"
    native.write_text(json.dumps(document), encoding="utf-8")
    finding = external.parse_sarif(native, "opengrep", root)[0]
    assert finding.severity == expected
    assert finding.metadata["sarif_level"] == "error"


def test_trivy_sarif_uses_exact_message_severity_when_level_is_lossy(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("fixture = True\n", encoding="utf-8")
    result = _valid_sarif_result("app.py")
    result["ruleId"] = "aws-access-key-id"
    result["message"] = {
        "text": (
            "Artifact: app.py Type:  Secret AWS Access Key ID "
            "Severity: CRITICAL Match: synthetic-fixture-match"
        )
    }
    native = tmp_path / "trivy.sarif"
    native.write_text(
        json.dumps(_sarif_document(result)),
        encoding="utf-8",
    )

    findings = external.parse_sarif(native, "trivy", root)

    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_failed_sbom_publication_preserves_previous_sanitized_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    raw = scratch / "syft.cyclonedx.json"
    raw.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}', encoding="utf-8")
    publish_root = tmp_path / "persistent" / "scans" / "existing"
    destination = publish_root / "syft" / "syft.cyclonedx.json"
    destination.parent.mkdir(parents=True)
    destination.write_text('{"previous":"sanitized"}\n', encoding="utf-8")

    def fail_dump(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("simulated persistent write failure")

    monkeypatch.setattr(external.json, "dump", fail_dump)
    with pytest.raises(OSError, match="simulated persistent write failure"):
        external._publish_sanitized_sbom(raw, scratch, publish_root)

    assert destination.read_text(encoding="utf-8") == '{"previous":"sanitized"}\n'
    assert list(destination.parent.glob(".syft.*.json")) == []


@pytest.mark.parametrize(("platform", "factor"), [("mac", 1), ("linux", 2.6), ("windows", 3.9)])
@pytest.mark.parametrize("reference", [1, 30, 300, 900])
def test_update_capable_tools_are_constructed_for_offline_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str, factor: int, reference: int,
) -> None:
    settings = Settings(KODESEC_SCAN_PLATFORM=platform, _env_file=None)
    monkeypatch.setattr(external, "get_settings", lambda: settings)
    # Ambient native overrides are not forwarded; only the validated lane is.
    monkeypatch.setenv("KODESEC_SCAN_PLATFORM", "unbounded")
    repo = tmp_path / "repo"
    repo.mkdir()
    cache_root = tmp_path / "cache"
    captured: dict[str, list[tuple[list[str], dict[str, str], Path | None]]] = {}

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd
        floor = 600 if (scanner.startswith("trivy-") or scanner == "grype"
                        or scanner == "bearer" and platform != "mac") else 0
        assert type(timeout) is int and timeout == math.ceil(max(reference, floor) * factor)
        if scanner == "bearer":
            assert env["KODESEC_SCAN_PLATFORM"] == platform
        else:
            assert "KODESEC_SCAN_PLATFORM" not in env
        assert env is not None
        captured.setdefault(scanner, []).append((command, env, stdout_path))
        if scanner.startswith("trivy-"):
            Path(command[command.index("--output") + 1]).write_text('{"runs":[]}', encoding="utf-8")
        elif scanner == "grype":
            Path(command[command.index("--file") + 1]).write_text('{"runs":[]}', encoding="utf-8")
        elif scanner == "bearer":
            Path(command[command.index("--output") + 1]).write_text(json.dumps(_bearer_document()), encoding="utf-8")
        elif scanner == "trufflehog":
            assert stdout_path is not None
            stdout_path.write_text("", encoding="utf-8")
        else:  # pragma: no cover - protects the fixture if the production list changes
            pytest.fail(f"unexpected scanner: {scanner}")
        assert Path(env["TMPDIR"]) == raw_dir
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 14) as request_dir:
        dependency_root = tmp_path / "persistent" / "scans" / "14"
        sbom = dependency_root / "syft" / "syft.cyclonedx.json"
        sbom.parent.mkdir(parents=True)
        sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
        runtime_inputs = {**_runtime_components(tmp_path), "syft_sbom": sbom}
        for scanner in ("trivy", "grype", "bearer", "trufflehog"):
            result = external.run_external_tool(
                scanner,
                repo,
                request_dir,
                dependency_root,
                cache_root,
                reference,
                inputs=runtime_inputs,
            )
            assert result.status == "completed"
            assert result.artifacts == []

    assert set(captured) >= {"trivy-source", "trivy-artifacts"}
    source_call = captured["trivy-source"][0]
    artifact_call = captured["trivy-artifacts"][0]
    assert source_call[0][1] == "fs"
    assert artifact_call[0][1] == "rootfs"
    assert artifact_call[0][artifact_call[0].index("--pkg-types") + 1] == "library"
    assert artifact_call[0][artifact_call[0].index("--parallel") + 1] == "1"
    for trivy_command, trivy_environment, _ in (source_call, artifact_call):
        assert "--offline-scan" in trivy_command
        assert "--skip-db-update" in trivy_command
        assert "--skip-java-db-update" in trivy_command
        assert "--skip-check-update" in trivy_command
        assert "--disable-telemetry" in trivy_command
        assert "--skip-version-check" in trivy_command
        assert trivy_command[trivy_command.index("--cache-dir") + 1] == str(
            runtime_inputs["trivy-db"].parent
        )
        assert Path(trivy_environment["XDG_CACHE_HOME"]).is_relative_to(request_dir)

    grype_command, grype_environment, _ = captured["grype"][0]
    assert grype_command[:2] == ["grype", f"sbom:{sbom}"]
    assert grype_environment["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert grype_environment["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert grype_environment["GRYPE_DB_CACHE_DIR"] == str(runtime_inputs["grype-db"])
    assert grype_environment["GRYPE_DB_VALIDATE_AGE"] == "false"

    bearer_command, bearer_environment, _ = captured["bearer"][0]
    assert bearer_command[bearer_command.index("--format") + 1] == "jsonv2"
    assert "--parallel" not in bearer_command
    assert "--disable-version-check" in bearer_command
    assert "--disable-default-rules" in bearer_command
    assert bearer_command[bearer_command.index("--external-rule-dir") + 1] == str(
        runtime_inputs["bearer-rules"]
    )
    assert bearer_environment["BEARER_TELEMETRY_ENABLED"] == "false"

    trufflehog_command, _, trufflehog_stdout = captured["trufflehog"][0]
    assert "--no-update" in trufflehog_command
    assert "--no-verification" in trufflehog_command
    assert trufflehog_stdout is not None


@pytest.mark.parametrize("source_kind", ["regular", "file_symlink", "directory_symlink", "outside_absolute"])
@pytest.mark.parametrize("relative_directory", [
    "manifests café",
    "tests/scanner-runtime/fixtures/dependencies/positive",
    "bearer",
])
def test_syft_source_locations_reach_grype_without_weakening_source_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_kind: str,
    relative_directory: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source_directory = repo / relative_directory
    source_directory.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("fixture-package==1.0\n", encoding="utf-8")
    if source_kind == "directory_symlink":
        source_directory.symlink_to(outside, target_is_directory=True)
    else:
        source_directory.mkdir()
        source = source_directory / "requirements.txt"
        if source_kind == "file_symlink":
            source.symlink_to(outside / "requirements.txt")
        else:
            source.write_text("fixture-package==1.0\n", encoding="utf-8")
    native_path = str(outside / "requirements.txt") if source_kind == "outside_absolute" else f"/{relative_directory}/requirements.txt"
    relative_path = native_path.removeprefix("/")
    publish_root = tmp_path / "artifacts" / "scans" / "42"

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, timeout, raw_dir, env
        if scanner == "syft":
            output = Path(command[command.index("-o") + 1].split("=", 1)[1])
            output.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"name": str(repo), "type": "file"}},
                "components": [{"name": "fixture-package", "properties": [
                    {"name": "syft:location:0:path", "value": native_path},
                ]}],
            }), encoding="utf-8")
        else:
            assert scanner == "grype"
            sbom = json.loads(Path(command[1].removeprefix("sbom:")).read_text())
            location = sbom["components"][0]["properties"][0]["value"]
            if source_kind == "outside_absolute":
                assert location != native_path
            else:
                assert location == relative_path
            Path(command[command.index("--file") + 1]).write_text(
                json.dumps(_sarif_document(_valid_sarif_result(location))), encoding="utf-8"
            )
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 42) as scratch:
        syft = external.run_external_tool("syft", repo, scratch, publish_root, tmp_path / "cache", 30)
        assert syft.status == "completed"
        grype = external.run_external_tool(
            "grype", repo, scratch, publish_root, tmp_path / "cache", 30,
            inputs={**_runtime_components(tmp_path), "syft_sbom": Path(syft.artifacts[0].path)},
        )
    assert grype.exit_code == 0
    assert grype.parse_integrity is not None
    if source_kind == "regular":
        assert grype.status == "completed"
        assert grype.error is None
        assert len(grype.findings) == 1
        assert grype.findings[0].file_path == relative_path
        assert grype.findings[0].code_snippet == "fixture-package==1.0"
        assert grype.parse_integrity["accepted_records"] == 1
        assert grype.parse_integrity["dropped_records"] == 0
    else:
        assert grype.status == "failed"
        assert grype.error == "native_output_integrity_failed"
        assert grype.findings == []
        assert grype.parse_integrity["dropped_reason_counts"] == {"unsafe_or_unreadable_source_path": 1}


@pytest.mark.parametrize("invalid_path", [
    "../requirements.txt", "/requirements.txt", "C:/requirements.txt",
    "file:///requirements.txt", "a\\requirements.txt", "./requirements.txt",
    "a//requirements.txt", "a/../requirements.txt", "requirements.txt\x00",
    "requirements\u202e.txt", "requirements\ud800.txt", " requirements.txt",
    "a" * 4097, "ghp_fixture_not_a_valid_secret_123456789", "[REDACTED]", 1,
    "prefix/[REDACTED]/requirements.txt",
    "prefix/" + "a" * 32 + "/requirements.txt",
    "prefix/ghp_fixture_not_a_valid_secret_123456789/requirements.txt",
    "prefix/eyJfixture.fixture.fixture/requirements.txt",
    "prefix/password=fixture/requirements.txt",
    "prefix/password=/fixture",
    "prefix/requirements.txt?api_key=fixture/child",
    "Bearer /foo", "prefix/Bearer /foo/requirements.txt",
    "prefix/Bearer fixture/requirements.txt",
    "prefix/-----BEGIN PRIVATE KEY-----/fixture",
    "prefix/-----BEGIN SECRET-----/fixture",
    "/".join(["a"] * 2049),
    "é/" * 1365 + "ab",
])
def test_syft_source_locations_reject_unsafe_or_secret_values(invalid_path: object) -> None:
    valid = {"name": "syft:location:0:path", "value": "requirements.txt"}
    invalid = {**valid, "value": invalid_path}
    payload = {
        "properties": [valid, invalid, {**valid, "name": "password"}, {**valid, "note": "lookalike"}],
        "untyped": valid,
        "value": "fixture private value",
    }
    redacted = external._redact_cyclonedx(payload)
    assert redacted["properties"][0]["value"] == "requirements.txt"
    assert [item["value"] for item in redacted["properties"][1:]] == [REDACTED] * 3
    assert redacted["untyped"]["value"] == REDACTED
    assert redacted["value"] == REDACTED


@pytest.mark.parametrize("relative_path", [
    "tests/scanner-runtime/fixtures/dependencies/positive/requirements.txt",
    "tests/scanner-runtime/fixtures/dependencies/positive/package-lock.json",
    "tests/scanner-runtime/fixtures/dependencies/positive/package.json",
    "bearer/requirements.txt",
    "Bearer/requirements.txt",
    "a" * 31 + "/requirements.txt",
    "/".join(["a"] * 2048) + "a",
])
def test_typed_syft_paths_preserve_separators_without_changing_generic_redaction(
    relative_path: str,
) -> None:
    value = {"name": "syft:location:0:path", "value": relative_path}
    assert external._cyclonedx_source_location(value) == relative_path
    redacted = external._redact_cyclonedx({"properties": [value], "untyped": value})
    assert redacted["properties"][0]["value"] == relative_path
    assert redacted["untyped"]["value"] == REDACTED
    if relative_path.startswith("tests/"):
        assert redact_json(relative_path, "path") == f"{REDACTED}.{relative_path.rsplit('.', 1)[1]}"


@pytest.mark.parametrize(("text", "expected"), [
    ("prefix/Bearer /foo/file.txt", f"prefix/Bearer {REDACTED}"),
    ("prefix/password=/foo", f"prefix/password={REDACTED}"),
    ("prefix/ghp_fixture_not_a_valid_secret_123456789/file.txt", f"prefix/{REDACTED}/file.txt"),
    ("-----BEGIN PRIVATE KEY-----/fixture", f"-----BEGIN PRIVATE KEY-----{REDACTED}"),
    ("a" * 32, REDACTED),
])
def test_source_path_exception_preserves_generic_credential_redaction(
    text: str, expected: str,
) -> None:
    assert redact_text(text) == expected


@pytest.mark.parametrize(("source_root", "source_name"), [
    (None, "/exact-source"), (Path("/different-source"), "/exact-source"),
    (Path("/exact-source"), "/exact-source"),
    pytest.param(Path("/exact-source"), None, id="missing_metadata"),
])
def test_syft_virtual_source_locations_require_the_exact_producer_root(
    source_root: Path | None, source_name: str | None,
) -> None:
    paths = ["/requirements.txt", "/../outside.txt", "//outside.txt", "/file:///outside.txt"]
    payload = {
        "metadata": {"component": {"name": source_name, "type": "file"}} if source_name else {},
        "components": [{"properties": [
            {"name": "syft:location:0:path", "value": path} for path in paths
        ]}],
    }
    sanitized = external._redact_cyclonedx(external._normalize_cyclonedx_source(payload, source_root))
    actual = [item["value"] for item in sanitized["components"][0]["properties"]]
    assert actual == [
        "requirements.txt" if source_root == Path("/exact-source") and source_name == "/exact-source" else REDACTED,
        REDACTED, REDACTED, REDACTED,
    ]


def test_grype_requires_syft_sbom_and_refuses_cross_scan_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    publish_root = tmp_path / "persistent" / "scans" / "31"
    outside = tmp_path / "persistent" / "scans" / "32" / "syft" / "syft.cyclonedx.json"
    outside.parent.mkdir(parents=True)
    outside.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        pytest.fail("Grype must not execute without one same-scan Syft SBOM")

    monkeypatch.setattr(external, "_run_command", fail_if_called)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 31) as request_dir:
        missing = external.run_external_tool(
            "grype", repo, request_dir, publish_root, tmp_path / "cache", 30
        )
    assert missing.status == "failed"
    assert missing.error == "syft_sbom_unavailable"

    with external.request_scratch_directory(str(tmp_path / "scratch"), 32) as request_dir:
        escaped = external.run_external_tool(
            "grype",
            repo,
            request_dir,
            publish_root,
            tmp_path / "cache",
            30,
            inputs={"syft_sbom": outside},
        )
    assert escaped.status == "failed"
    assert "escapes this scan publication root" in (escaped.error or "")


def test_native_exit_policy_has_only_the_documented_bearer_exception() -> None:
    external_ids = {
        str(tool["id"])
        for tool in SCANNER_TOOLS
        if tool.get("source") == "external"
    }

    for scanner in external_ids:
        external._validate_native_exit_code(scanner, 0)
        if scanner == "bearer":
            external._validate_native_exit_code(scanner, 1)
        else:
            with pytest.raises(external.NativeExitError):
                external._validate_native_exit_code(scanner, 1)
        with pytest.raises(external.NativeExitError):
            external._validate_native_exit_code(scanner, 2)


def test_syft_nonzero_exit_never_publishes_a_leftover_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    publish_root = tmp_path / "persistent" / "scans" / "37"

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        out = Path(
            next(
                value.split("=", 1)[1]
                for value in command
                if value.startswith("cyclonedx-json=")
            )
        )
        out.write_text(
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}',
            encoding="utf-8",
        )
        return _fake_result(command, 2)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 37
    ) as request_dir:
        result = external.run_external_tool(
            "syft",
            repo,
            request_dir,
            publish_root,
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.error == "unexpected_native_exit_code"
    assert result.exit_code == 2
    assert result.artifacts == []
    assert not publish_root.exists()


@pytest.mark.parametrize(
    ("exit_code", "results", "expected_status", "expected_error", "expected_count"),
    [
        (1, [_valid_bearer_finding()], "completed_with_exit_code", None, 1),
        (1, [], "failed", "bearer_findings_exit_without_findings", 0),
        (2, [_valid_bearer_finding()], "failed", "unexpected_native_exit_code", 0),
        (
            1,
            [{"ruleId": "missing-location"}],
            "failed",
            "native_output_integrity_failed",
            0,
        ),
    ],
)
def test_bearer_exit_one_requires_valid_normalized_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    results: list[object],
    expected_status: str,
    expected_error: str | None,
    expected_count: int,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.py").write_text("print('fixture')\n", encoding="utf-8")
    runtime_inputs = _runtime_components(tmp_path)

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        Path(command[command.index("--output") + 1]).write_text(
            json.dumps(_bearer_document(*results)),
            encoding="utf-8",
        )
        return _fake_result(command, exit_code)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 38
    ) as request_dir:
        result = external.run_external_tool(
            "bearer",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "38",
            tmp_path / "cache",
            30,
            inputs=runtime_inputs,
        )

    assert result.status == expected_status
    assert result.error == expected_error
    assert result.exit_code == exit_code
    assert len(result.findings) == expected_count
    if exit_code == 2:
        assert result.parse_integrity is None
    elif results:
        assert result.parse_integrity is not None
        assert result.parse_integrity["total_records"] == 1


@pytest.mark.parametrize(
    ("line_ending", "suffix", "exit_code", "expected_status"),
    [
        ("\n", "", 1, "completed"),
        ("\r\n", "", 1, "completed"),
        ("\n", " ", 1, "failed"),
        ("\n", "", 0, "failed"),
    ],
)
def test_bearer_unsupported_source_report_is_exact_and_exit_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    line_ending: str,
    suffix: str,
    exit_code: int,
    expected_status: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "fixture" {}\n',
        encoding="utf-8",
    )
    runtime_inputs = _runtime_components(tmp_path)

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        message = line_ending.join(
            (
                "The security report is not yet available for your application.",
                "Learn more about language support at "
                "https://docs.bearer.com/reference/supported-languages/",
            )
        )
        Path(command[command.index("--output") + 1]).write_text(
            f"{line_ending}{message}{line_ending}{suffix}",
            encoding="utf-8",
            newline="",
        )
        return _fake_result(command, exit_code)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 40
    ) as request_dir:
        result = external.run_external_tool(
            "bearer",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "40",
            tmp_path / "cache",
            30,
            inputs=runtime_inputs,
        )

    assert result.status == expected_status
    assert result.exit_code == exit_code
    assert result.findings == []
    if expected_status == "completed":
        assert result.error is None
        assert result.parse_integrity == {
            "complete": True,
            "total_records": 1,
            "accepted_records": 0,
            "intentionally_filtered_records": 1,
            "dropped_records": 0,
            "dropped_reason_counts": {},
            "filter_reason_counts": {"source_language_not_supported": 1},
        }
    else:
        assert result.error is not None
        assert result.error == "bearer_native_report_invalid"
        assert result.parse_integrity is None


def test_bearer_jsonv2_matches_existing_finding_identity_and_source_boundary(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.py").write_text("print('fixture')\n", encoding="utf-8")
    finding = _valid_bearer_finding()
    finding.update({"full_filename": "/outside/private.py", "snippet": "NATIVE_PRIVATE_MARKER",
                    "code_extract": "NATIVE_PRIVATE_MARKER", "severity": "critical"})
    parsed = external._parse_bearer_jsonv2(json.dumps(_bearer_document(finding)).encode(), repo)
    sarif = _valid_sarif_result()
    sarif.pop("level")
    sarif["locations"][0]["physicalLocation"]["region"] = {  # type: ignore[index]
        "startLine": 1, "endLine": 1, "startColumn": 1, "endColumn": 2,
    }
    native = tmp_path / "old.sarif"
    native.write_text(json.dumps(_sarif_document(sarif)))
    old = external._parse_sarif(native, "bearer", repo)
    assert parsed.integrity.as_dict() == old.integrity.as_dict()
    left, right = parsed.findings[0].model_dump(), old.findings[0].model_dump()
    left.pop("metadata"); right.pop("metadata")
    assert left.pop("severity") == "critical"
    # This fixture omits both result and rule levels, so SARIF defaults to warning.
    assert right.pop("severity") == "medium"
    assert left == right
    assert parsed.findings[0].metadata["native"] == "bearer-jsonv2"
    assert "sarif_level" not in parsed.findings[0].metadata
    assert "NATIVE_PRIVATE_MARKER" not in parsed.findings[0].model_dump_json()


@pytest.mark.parametrize(("severity", "expected"), [
    ("critical", "critical"), ("high", "high"), ("medium", "medium"),
    ("low", "low"), ("warning", "info"),
])
def test_bearer_jsonv2_preserves_native_severity(tmp_path: Path, severity: str, expected: str) -> None:
    (tmp_path / "source.py").write_text("print('fixture')\n")
    finding = {**_valid_bearer_finding(), "severity": severity}
    parsed = external._parse_bearer_jsonv2(json.dumps(_bearer_document(finding)).encode(), tmp_path)
    assert parsed.findings[0].severity == expected
    assert parsed.integrity.accepted_records == 1 and parsed.integrity.dropped_records == 0


@pytest.mark.parametrize("severity", [None, "", "info", "HIGH", "future", 1, True, []])
def test_bearer_jsonv2_invalid_severity_is_an_atomic_record_failure(tmp_path: Path, severity: object) -> None:
    (tmp_path / "source.py").write_text("print('fixture')\n")
    finding = _valid_bearer_finding()
    if severity is None:
        finding.pop("severity")
    else:
        finding["severity"] = severity
    parsed = external._parse_bearer_jsonv2(json.dumps(_bearer_document(
        _valid_bearer_finding(), finding,
    )).encode(), tmp_path)
    assert parsed.integrity.total_records == 2 and parsed.integrity.accepted_records == 1
    assert parsed.integrity.dropped_reason_counts == {"invalid_bearer_result": 1}
    with pytest.raises(external.NativeParseIntegrityError):
        external._validated_native_findings(parsed)


@pytest.mark.parametrize(("diagnostics", "category"), [
    ([("file_error", "file processing time exceeded")], "file_timeout"),
    ([("file_error", "exceeded memory limit")], "memory_limit"),
    ([("file_error", "exited unexpectedly")], "worker_failure"),
    ([("file_error", "didn't start within expected time")], "worker_failure"),
    ([("file_error", "PRIVATE_NATIVE_MARKER")], "unknown"),
    ([("error", "PRIVATE_NATIVE_MARKER")], "analysis_error"),
    *[
        ([("error", prefix + (
            "PRIVATE_NATIVE_MARKER /private/PRIVATE_PATH_MARKER token=PRIVATE_SECRET_MARKER\n"
            "failed to scan file: PRIVATE_INJECTED_MARKER\x00"
        ))], category)
        for prefix, category in (
            ("accept dir failed for detector ", "aerr_d"),
            ("classification dependencies error: ", "aerr_e"),
            ("classification frameworks error: ", "aerr_f"),
            ("skipping file: due to panic ", "aerr_p"),
            ("failed to scan file: ", "aerr_s"),
            ("failed to process file for detector ", "aerr_t"),
        )
    ],
    *[
        ([("error", message)], "analysis_error")
        for message in (
            " failed to scan file: PRIVATE_NATIVE_MARKER",
            "failed to scan file:PRIVATE_NATIVE_MARKER",
            "Failed to scan file: PRIVATE_NATIVE_MARKER",
            "PRIVATE_NATIVE_MARKER failed to scan file: PRIVATE_NATIVE_MARKER",
        )
    ],
    ([("file_error", "failed to scan file: PRIVATE_NATIVE_MARKER")], "unknown"),
    ([
        ("error", "failed to scan file: PRIVATE_NATIVE_MARKER"),
        ("error", "failed to scan file: PRIVATE_DUPLICATE_MARKER"),
        ("error", "PRIVATE_NATIVE_MARKER"),
        ("file_error", "file processing time exceeded"),
    ], "aerr_su,file_timeout"),
    ([
        ("error", "failed to process file for detector PRIVATE_NATIVE_MARKER"),
        ("error", "PRIVATE_NATIVE_MARKER"),
        ("error", "failed to scan file: PRIVATE_NATIVE_MARKER"),
        ("error", "skipping file: due to panic PRIVATE_NATIVE_MARKER"),
        ("error", "classification frameworks error: PRIVATE_NATIVE_MARKER"),
        ("error", "classification dependencies error: PRIVATE_NATIVE_MARKER"),
        ("error", "accept dir failed for detector PRIVATE_NATIVE_MARKER"),
        ("error", "failed to scan file: PRIVATE_DUPLICATE_MARKER"),
        ("file_error", "file processing time exceeded"),
        ("file_error", "exceeded memory limit"),
        ("file_error", "exited unexpectedly"),
        ("future_native_failure", "failed to scan file: PRIVATE_NATIVE_MARKER"),
    ], "aerr_defpstu,file_timeout,memory_limit,unknown,worker_failure"),
    ([("future_native_failure", "PRIVATE_NATIVE_MARKER")], "unknown"),
    ([
        ("file_error", "file processing time exceeded"),
        ("file_error", "exceeded memory limit"),
        ("file_error", "file processing time exceeded"),
    ], "file_timeout,memory_limit"),
    ([
        ("error", "PRIVATE_NATIVE_MARKER"),
        ("file_error", "file processing time exceeded"),
        ("file_error", "exceeded memory limit"),
        ("future_native_failure", "PRIVATE_NATIVE_MARKER"),
        ("file_error", "exited unexpectedly"),
    ], "analysis_error,file_timeout,memory_limit,unknown,worker_failure"),
    ([
        ("file_error", "didn't start within expected time"),
        ("file_error", "PRIVATE_NATIVE_MARKER"),
        ("file_error", "exceeded memory limit"),
        ("file_error", "file processing time exceeded"),
        ("error", "PRIVATE_NATIVE_MARKER"),
        ("file_error", "exited unexpectedly"),
        ("future_native_failure", "PRIVATE_NATIVE_MARKER"),
    ], "analysis_error,file_timeout,memory_limit,unknown,worker_failure"),
])
@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("with_findings", [False, True])
def test_bearer_native_file_errors_withhold_findings_and_remove_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    diagnostics: list[tuple[str, str]], category: str, exit_code: int, with_findings: bool,
    api_redaction: ModuleType,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    runtime_inputs = _runtime_components(tmp_path)
    raw_roots: list[Path] = []
    def fake_run(scanner, command, cwd, timeout, raw_dir, env=None, **kwargs):
        raw_roots.append(raw_dir)
        Path(command[command.index("--output") + 1]).write_text(json.dumps(_bearer_document(
            *([_valid_bearer_finding()] if with_findings else []), errors=[
                {"type": diagnostic_type, "filename": "PRIVATE_PATH_MARKER", "error": diagnostic}
                for diagnostic_type, diagnostic in diagnostics
            ],
        )))
        return _fake_result(command, exit_code)
    monkeypatch.setattr(external, "_run_command", fake_run)
    # No source file exists: diagnostics must be rejected before source reads.
    with external.request_scratch_directory(str(tmp_path / "scratch"), 401) as request_dir:
        result = external.run_external_tool("bearer", repo, request_dir, tmp_path / "publish",
                                           tmp_path / "cache", 30, inputs=runtime_inputs)
        assert all(not path.exists() for path in raw_roots)
    assert result.status == "failed"
    assert result.error == f"bearer_analysis_incomplete:{category}"
    assert len(result.error.encode("ascii")) <= 90
    assert result.findings == [] and result.artifacts == [] and result.parse_integrity is None
    assert "PRIVATE_" not in repr(result)
    summary = {"tools": [{"id": "bearer", "error": result.error}],
               "errors": [f"bearer: {result.error}"]}
    assert redact_json(summary) == summary
    assert api_redaction.redact_json(summary) == summary
    assert not (tmp_path / "publish").exists()


@pytest.mark.parametrize("changes", [
    {"source": "bearer"}, {"version": "dev"}, {"version": "v2.1.0"},
    {"version": "2.1.1"}, {"errors": {}}, {"errors": False}, {"errors": None},
    {"findings": {}}, {"expected_findings": None}, {"unexpected": []},
    {"errors": ["PRIVATE_NATIVE_MARKER"]},
    {"errors": [{"type": "file_error", "error": "PRIVATE_NATIVE_MARKER"}]},
    {"errors": [{"type": "file_error", "filename": 7, "error": "PRIVATE_NATIVE_MARKER"}]},
    pytest.param({"version": "2.1.0"}, id="stock-version-rejected"),
])
def test_bearer_jsonv2_envelope_is_strict(tmp_path: Path, changes: dict[str, object]) -> None:
    payload = _bearer_document(_valid_bearer_finding())
    payload.update(changes)
    with pytest.raises(external.BearerReportError) as failure:
        external._parse_bearer_jsonv2(json.dumps(payload).encode(), tmp_path)
    assert failure.value.code == "bearer_native_report_invalid"
    assert "PRIVATE_" not in str(failure.value)


@pytest.mark.parametrize("key", ["source", "version", "findings", "errors"])
def test_bearer_jsonv2_requires_every_completeness_field(tmp_path: Path, key: str) -> None:
    payload = _bearer_document()
    payload.pop(key)
    with pytest.raises(external.BearerReportError, match="^bearer_native_report_invalid$"):
        external._parse_bearer_jsonv2(json.dumps(payload).encode(), tmp_path)


@pytest.mark.parametrize("raw", [
    b'{}', b'{"errors":[],"errors":[]}', b'{"errors":NaN}', b'\xff',
    b'PRIVATE_NATIVE_MARKER\n{"source":"Bearer"}', b'[' * 2000,
])
def test_bearer_jsonv2_rejects_ambiguous_or_malformed_json(tmp_path: Path, raw: bytes) -> None:
    with pytest.raises(external.BearerReportError, match="^bearer_native_report_invalid$"):
        external._parse_bearer_jsonv2(raw, tmp_path)


def test_bearer_jsonv2_bounds_and_empty_upstream_slices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for findings, errors in [(None, None), (None, []), ([], [])]:
        payload = _bearer_document()
        payload.update(findings=findings, errors=errors)
        parsed = external._parse_bearer_jsonv2(json.dumps(payload).encode(), tmp_path)
        assert parsed.findings == [] and parsed.integrity.total_records == 0
    monkeypatch.setattr(external, "MAX_NATIVE_FINDINGS_BYTES", 32)
    with pytest.raises(external.BearerReportError, match="^bearer_native_report_invalid$"):
        external._parse_bearer_jsonv2(b" " * 33, tmp_path)


@pytest.mark.parametrize("uri", ["../outside.py", "linked.py", "missing.py"])
def test_bearer_jsonv2_keeps_atomic_source_path_rejection(tmp_path: Path, uri: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.py").write_text("print('fixture')\n")
    (tmp_path / "outside.py").write_text("PRIVATE_NATIVE_MARKER")
    (repo / "linked.py").symlink_to(tmp_path / "outside.py")
    parsed = external._parse_bearer_jsonv2(json.dumps(_bearer_document(
        _valid_bearer_finding(), _valid_bearer_finding(uri),
    )).encode(), repo)
    assert parsed.integrity.total_records == 2
    assert parsed.integrity.accepted_records == 1 and parsed.integrity.dropped_records == 1
    with pytest.raises(external.NativeParseIntegrityError):
        external._validated_native_findings(parsed)


@pytest.mark.parametrize("sink", [
    None, {}, {"start": 1, "end": 1, "column": None},
    {"start": 0, "end": 1, "column": {"start": 1, "end": 2}},
    {"start": True, "end": 1, "column": {"start": 1, "end": 2}},
    {"start": 1, "end": 1, "column": {"start": 9999, "end": 10000}},
])
def test_bearer_jsonv2_rejects_malformed_source_coordinates(tmp_path: Path, sink: object) -> None:
    (tmp_path / "source.py").write_text("print('fixture')\n")
    finding = {**_valid_bearer_finding(), "sink": sink}
    parsed = external._parse_bearer_jsonv2(json.dumps(_bearer_document(finding)).encode(), tmp_path)
    assert parsed.findings == []
    assert parsed.integrity.total_records == 1 and parsed.integrity.dropped_records == 1
    with pytest.raises(external.NativeParseIntegrityError):
        external._validated_native_findings(parsed)


def test_bearer_cancel_after_native_exit_prevents_jsonv2_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    runtime_inputs = _runtime_components(tmp_path)
    control = external.ExecutionControl.with_timeout(30)
    def fake_run(scanner, command, cwd, timeout, raw_dir, env=None, **kwargs):
        Path(command[command.index("--output") + 1]).write_text(json.dumps(_bearer_document()))
        control.cancel_event.set()
        return _fake_result(command)
    monkeypatch.setattr(external, "_run_command", fake_run)
    monkeypatch.setattr(external, "_parse_bearer_jsonv2", lambda *args: pytest.fail("cancelled native output reached parser"))
    with external.request_scratch_directory(str(tmp_path / "scratch"), 402) as request_dir:
        with pytest.raises(external.RunCancelled):
            external.run_external_tool("bearer", repo, request_dir, tmp_path / "publish",
                                       tmp_path / "cache", 30, inputs=runtime_inputs, control=control)


@pytest.mark.parametrize(
    ("native_result", "reason"),
    [
        ("not-an-object", "non_object_result"),
        ({"ruleId": "missing-location"}, "missing_location"),
        (_valid_sarif_result("../outside.py"), "unsupported_path"),
        (_sarif_result_with_multiple_locations(), "multiple_locations"),
    ],
)
def test_sarif_dropped_result_records_fail_native_run_with_bounded_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_result: object,
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        Path(command[command.index("--report-path") + 1]).write_text(
            json.dumps(_sarif_document(native_result)),
            encoding="utf-8",
        )
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 39
    ) as request_dir:
        result = external.run_external_tool(
            "gitleaks",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "39",
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.error == "native_output_integrity_failed"
    assert result.findings == []
    assert result.parse_integrity == {
        "complete": False,
        "total_records": 1,
        "accepted_records": 0,
        "intentionally_filtered_records": 0,
        "dropped_records": 1,
        "dropped_reason_counts": {reason: 1},
        "filter_reason_counts": {},
    }


@pytest.mark.parametrize(
    ("scanner", "output_name"),
    [
        ("gitleaks", "gitleaks.sarif"),
        ("trivy", "trivy.sarif"),
        ("bearer", "bearer.json"),
        ("checkov", "results_sarif.sarif"),
        ("trufflehog", "trufflehog.jsonl"),
    ],
)
def test_success_without_required_native_output_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner: str,
    output_name: str,
) -> None:
    del output_name
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(external, "_run_command", lambda *args, **kwargs: _fake_result(args[1]))
    inputs = _runtime_components(tmp_path)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 33) as request_dir:
        result = external.run_external_tool(
            scanner,
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "33",
            tmp_path / "cache",
            30,
            inputs=inputs,
        )
    assert result.status == "failed"
    assert result.error == "required_output_missing" or "required JSONL output" in (result.error or "")


def test_trufflehog_malformed_jsonl_is_a_failed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[1]
        stdout_path = kwargs.get("stdout_path")
        assert isinstance(stdout_path, Path)
        stdout_path.write_text('{"valid":true}\nnot-json\n', encoding="utf-8")
        return _fake_result(command)  # type: ignore[arg-type]

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 34) as request_dir:
        result = external.run_external_tool(
            "trufflehog",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "34",
            tmp_path / "cache",
            30,
        )
    assert result.status == "failed"
    assert result.error == "native_output_integrity_failed"
    assert result.parse_integrity is not None
    assert result.parse_integrity["dropped_reason_counts"] == {
        "malformed_json_result": 1,
        "missing_path": 1,
    }


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (
            b'{"DetectorName":"first","DetectorName":"second",'
            b'"SourceMetadata":{"Data":{"Filesystem":{"file":"source.py"}}}}\n',
            "duplicate_json_key",
        ),
        (
            b'{"DetectorName":"fixture","Score":NaN,'
            b'"SourceMetadata":{"Data":{"Filesystem":{"file":"source.py"}}}}\n',
            "non_finite_json_number",
        ),
        (
            b'{"DetectorName":"fixture",'
            b'"SourceMetadata":{"Data":{"Filesystem":{"file":"source.py"}}}}\xff\n',
            "invalid_utf8_result",
        ),
    ],
)
def test_trufflehog_jsonl_uses_strict_json_decoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.py").write_text("fixture\n", encoding="utf-8")

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[1]
        stdout_path = kwargs.get("stdout_path")
        assert isinstance(stdout_path, Path)
        stdout_path.write_bytes(payload)
        return _fake_result(command)  # type: ignore[arg-type]

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 45
    ) as request_dir:
        result = external.run_external_tool(
            "trufflehog",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "45",
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.error == "native_output_integrity_failed"
    assert result.findings == []
    assert result.parse_integrity is not None
    assert result.parse_integrity["complete"] is False
    assert result.parse_integrity["dropped_reason_counts"] == {reason: 1}


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        ([], "non_object_result"),
        (
            {
                "DetectorName": "fixture",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "../outside.py"}}
                },
            },
            "unsupported_path",
        ),
    ],
)
def test_trufflehog_dropped_records_fail_with_bounded_integrity_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record: object,
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[1]
        stdout_path = kwargs.get("stdout_path")
        assert isinstance(stdout_path, Path)
        stdout_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        return _fake_result(command)  # type: ignore[arg-type]

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 40
    ) as request_dir:
        result = external.run_external_tool(
            "trufflehog",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "40",
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.error == "native_output_integrity_failed"
    assert result.parse_integrity == {
        "complete": False,
        "total_records": 1,
        "accepted_records": 0,
        "intentionally_filtered_records": 0,
        "dropped_records": 1,
        "dropped_reason_counts": {reason: 1},
        "filter_reason_counts": {},
    }


def test_trufflehog_git_metadata_filter_is_explicit_and_not_a_parse_drop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[1]
        stdout_path = kwargs.get("stdout_path")
        assert isinstance(stdout_path, Path)
        stdout_path.write_text(
            json.dumps(
                {
                    "DetectorName": "fixture",
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": ".git/config"}}
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return _fake_result(command)  # type: ignore[arg-type]

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 41
    ) as request_dir:
        result = external.run_external_tool(
            "trufflehog",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "41",
            tmp_path / "cache",
            30,
        )

    assert result.status == "completed"
    assert result.findings == []
    assert result.parse_integrity == {
        "complete": True,
        "total_records": 1,
        "accepted_records": 0,
        "intentionally_filtered_records": 1,
        "dropped_records": 0,
        "dropped_reason_counts": {},
        "filter_reason_counts": {"git_metadata_path": 1},
    }


def test_valid_zero_native_results_remain_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[1]
        stdout_path = kwargs.get("stdout_path")
        assert isinstance(stdout_path, Path)
        stdout_path.write_text("", encoding="utf-8")
        return _fake_result(command)  # type: ignore[arg-type]

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 42
    ) as request_dir:
        result = external.run_external_tool(
            "trufflehog",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "42",
            tmp_path / "cache",
            30,
        )

    assert result.status == "completed"
    assert result.findings == []
    assert result.parse_integrity is not None
    assert result.parse_integrity["complete"] is True
    assert result.parse_integrity["total_records"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        "{}",
        '{"runs":"not-a-list"}',
        '{"runs":[{"results":"not-a-list"}]}',
    ],
)
def test_malformed_sarif_is_a_failed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        Path(command[command.index("--report-path") + 1]).write_text(payload, encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 35) as request_dir:
        result = external.run_external_tool(
            "gitleaks",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "35",
            tmp_path / "cache",
            30,
        )
    assert result.status == "failed"
    assert "malformed SARIF" in (result.error or "")


@pytest.mark.parametrize(
    "payload",
    [
        b'{"runs":[],"runs":[]}',
        b'{"runs":[],"score":NaN}',
        b'{"runs":[]}\xff',
    ],
)
def test_sarif_uses_strict_json_decoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        Path(command[command.index("--report-path") + 1]).write_bytes(payload)
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 46
    ) as request_dir:
        result = external.run_external_tool(
            "gitleaks",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "46",
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.findings == []
    assert "malformed SARIF" in (result.error or "")


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        '{"bomFormat":"not-cyclonedx","specVersion":"1.6"}',
        '{"bomFormat":"CycloneDX","components":{}}',
    ],
)
def test_malformed_syft_document_is_not_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    publish_root = tmp_path / "persistent" / "scans" / "36"

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        out = Path(next(value.split("=", 1)[1] for value in command if value.startswith("cyclonedx-json=")))
        out.write_text(payload, encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 36) as request_dir:
        result = external.run_external_tool(
            "syft",
            repo,
            request_dir,
            publish_root,
            tmp_path / "cache",
            30,
        )
    assert result.status == "failed"
    assert "malformed CycloneDX" in (result.error or "")
    assert not publish_root.exists()


@pytest.mark.parametrize(
    "payload",
    [
        b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6"}',
        b'{"bomFormat":"CycloneDX","specVersion":"1.6","score":Infinity}',
        b'{"bomFormat":"CycloneDX","specVersion":"1.6"}\xff',
    ],
)
def test_syft_cyclonedx_uses_strict_json_decoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    publish_root = tmp_path / "persistent" / "scans" / "47"

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, raw_dir, env, stdout_path
        out = Path(
            next(
                value.split("=", 1)[1]
                for value in command
                if value.startswith("cyclonedx-json=")
            )
        )
        out.write_bytes(payload)
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(
        str(tmp_path / "scratch"), 47
    ) as request_dir:
        result = external.run_external_tool(
            "syft",
            repo,
            request_dir,
            publish_root,
            tmp_path / "cache",
            30,
        )

    assert result.status == "failed"
    assert result.findings == []
    assert result.artifacts == []
    assert "malformed CycloneDX" in (result.error or "")
    assert not publish_root.exists()


def test_opengrep_requires_validated_generation_rules_and_never_uses_remote_auto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    calls: list[list[str]] = []

    def fail_if_called(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        pytest.fail("OpenGrep must not execute without pinned local rules")

    monkeypatch.setattr(external, "_run_command", fail_if_called)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 15) as request_dir:
        missing = external.run_external_tool(
            "opengrep",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "15",
            tmp_path / "cache",
            30,
        )
    assert missing.status == "failed"
    assert "offline_component_unavailable:opengrep-reviewed-rules" in (missing.error or "")

    cache_root = tmp_path / "cache"
    rules = cache_root / "opengrep" / "rules.yml"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text("rules: []\n", encoding="utf-8")

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, timeout, raw_dir, env, stdout_path
        assert cwd == rules.parent
        calls.append(command)
        Path(command[command.index("--output") + 1]).write_text('{"runs":[]}', encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 16) as request_dir:
        configured = external.run_external_tool(
            "opengrep",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "16",
            cache_root,
            30,
            inputs={"opengrep-reviewed-rules": rules.parent},
        )
    assert configured.status == "completed"
    assert len(calls) == 1
    assert calls[0][calls[0].index("--config") + 1] == "rules.yml"
    assert "auto" not in calls[0]
    metadata = next(tool for tool in SCANNER_TOOLS if tool["id"] == "opengrep")
    assert "pinned local rules" in metadata["description"]
    assert "offline-ready" in metadata["description"]


def test_opengrep_refuses_rules_outside_its_cache_or_through_a_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    cache_root = tmp_path / "cache"
    outside = tmp_path / "outside-rules.yml"
    outside.write_text("rules: []\n", encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        pytest.fail("OpenGrep must not execute with rules outside its isolated cache")

    monkeypatch.setattr(external, "_run_command", fail_if_called)
    for scan_id, configured in ((17, outside), (18, cache_root / "opengrep" / "linked.yml")):
        if scan_id == 18:
            configured.parent.mkdir(parents=True, exist_ok=True)
            configured.symlink_to(outside)
        with external.request_scratch_directory(str(tmp_path / "scratch"), scan_id) as request_dir:
            result = external.run_external_tool(
                "opengrep",
                repo,
                request_dir,
                tmp_path / "persistent" / "scans" / str(scan_id),
                cache_root,
                30,
                inputs={"opengrep-reviewed-rules": configured},
            )
        assert result.status == "failed"
        assert "offline_component_invalid:opengrep-reviewed-rules" in (result.error or "")

    rules_directory = cache_root / "opengrep" / "rules"
    rules_directory.mkdir()
    (rules_directory / "linked.yml").symlink_to(outside)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 20) as request_dir:
        nested = external.run_external_tool(
            "opengrep",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "20",
            cache_root,
            30,
            inputs={"opengrep-reviewed-rules": rules_directory},
        )
    assert nested.status == "failed"
    assert nested.error == "offline_rules_unavailable: active OpenGrep rule generation is invalid"


def test_tool_environment_disables_supported_update_and_telemetry_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    cache_root = tmp_path / "cache"
    monkeypatch.setenv("HOME", "/ambient-home-must-not-be-used")

    opengrep_environment, _ = external._tool_environment("opengrep", scratch, cache_root)
    private_home = scratch / "home"
    assert opengrep_environment["HOME"] == str(private_home)
    assert private_home.is_dir()
    assert stat.S_IMODE(private_home.stat().st_mode) == 0o700
    assert opengrep_environment["PATH"].split(os.pathsep)[0] == str(
        external.OPENGREP_EXECUTABLE_PATH.parent
    )
    assert opengrep_environment["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert opengrep_environment["SEMGREP_SEND_METRICS"] == "off"

    bearer_environment, _ = external._tool_environment("bearer", scratch, cache_root)
    assert bearer_environment["HOME"] == str(private_home)
    assert private_home.is_dir()
    assert stat.S_IMODE(private_home.stat().st_mode) == 0o700
    assert bearer_environment["BEARER_TELEMETRY_ENABLED"] == "false"

    checkov_environment, _ = external._tool_environment("checkov", scratch, cache_root)
    assert checkov_environment["HOME"] == str(private_home)
    assert checkov_environment["CHECKOV_SKIP_FRAMEWORK_DOWNLOADS"] == "true"


def test_checkov_scan_disables_runtime_downloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    observed: list[str] = []

    def fake_run(
        scanner: str,
        command: list[str],
        cwd: Path,
        timeout: int,
        raw_dir: Path,
        env: dict[str, str] | None = None,
        *,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del scanner, cwd, timeout, env, stdout_path
        observed.extend(command)
        (raw_dir / "results_sarif.sarif").write_text('{"runs":[]}', encoding="utf-8")
        return _fake_result(command)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 19) as request_dir:
        result = external.run_external_tool(
            "checkov",
            repo,
            request_dir,
            tmp_path / "persistent" / "scans" / "19",
            tmp_path / "cache",
            30,
        )
    assert result.status == "completed"
    assert "--skip-download" in observed


def test_native_output_size_limit_fails_before_unbounded_json_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    oversized = scratch / "oversized.sarif"
    oversized.write_bytes(b"12345")
    monkeypatch.setattr(external, "MAX_NATIVE_FINDINGS_BYTES", 4)

    with pytest.raises(RuntimeError, match="processing size limit"):
        external._maybe_sarif(oversized, "fixture", tmp_path, scratch)


@pytest.mark.parametrize("interrupt", ["cancel", "deadline"])
@pytest.mark.parametrize("recursive", [False, True])
def test_sarif_interrupt_stops_before_reading_the_next_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: str,
    recursive: bool,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    for name in ("first.py", "second.py"):
        (root / name).write_text("value = 1\n", encoding="utf-8")
    native = tmp_path / "report.sarif"
    document = _sarif_document(
        _valid_sarif_result("first.py"), _valid_sarif_result("second.py"),
    )
    if recursive:
        results = document["runs"][0]["results"]
        results[0]["locations"].extend(results[1]["locations"])
        results.pop()
    native.write_text(json.dumps(document), encoding="utf-8")
    clock = [0.0]
    monkeypatch.setattr(external.time, "monotonic", lambda: clock[0])
    control = external.ExecutionControl.with_timeout(10)
    reads: list[str] = []
    original = external.SourceTextReader.read_document

    def read_document(reader: external.SourceTextReader, relative_path: str) -> external.SourceDocument:
        document = original(reader, relative_path)
        reads.append(relative_path)
        if interrupt == "cancel":
            control.cancel_event.set()
        else:
            clock[0] = 11.0
        return document

    monkeypatch.setattr(external.SourceTextReader, "read_document", read_document)
    expected = external.RunCancelled if interrupt == "cancel" else external.RunDeadlineExceeded
    with pytest.raises(expected):
        external._maybe_sarif(native, "trivy" if recursive else "checkov", root, tmp_path, control)
    assert reads == ["first.py"]


@pytest.mark.parametrize("interrupt", ["cancel", "deadline"])
def test_sarif_interrupt_stops_during_strict_json_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    native = tmp_path / "report.sarif"
    native.write_text(json.dumps(_sarif_document(_valid_sarif_result())), encoding="utf-8")
    clock = [0.0]
    monkeypatch.setattr(external.time, "monotonic", lambda: clock[0])
    control = external.ExecutionControl.with_timeout(10)
    objects: list[int] = []
    original = external._strict_json_object

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = original(pairs)
        objects.append(len(pairs))
        if interrupt == "cancel":
            control.cancel_event.set()
        else:
            clock[0] = 11.0
        return result

    monkeypatch.setattr(external, "_strict_json_object", object_pairs)
    expected = external.RunCancelled if interrupt == "cancel" else external.RunDeadlineExceeded
    with pytest.raises(expected):
        external._maybe_sarif(native, "checkov", root, tmp_path, control)
    assert len(objects) == 1


@pytest.mark.parametrize("interrupt", ["cancel", "deadline"])
@pytest.mark.parametrize("boundary", ["run", "rule", "invalid_column"])
def test_sarif_interrupt_checks_non_finding_loops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: str,
    boundary: str,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(external.time, "monotonic", lambda: clock[0])
    control = external.ExecutionControl.with_timeout(10)

    class InterruptingList(list):
        def __iter__(self):
            for index, item in enumerate(super().__iter__()):
                if index == 1:
                    if interrupt == "cancel":
                        control.cancel_event.set()
                    else:
                        clock[0] = 11.0
                yield item

    document = _sarif_document()
    if boundary == "run":
        document["runs"] = InterruptingList([document["runs"][0], "must not inspect"])
    elif boundary == "rule":
        document["runs"][0]["tool"]["driver"]["rules"] = InterruptingList([
            {"id": "first"}, {"id": "second", "properties": {"tags": "must not inspect"}},
        ])
    else:
        document["runs"][0]["columnKind"] = "unsupported"
        document["runs"][0]["results"] = InterruptingList([{}, {}])
    expected = external.RunCancelled if interrupt == "cancel" else external.RunDeadlineExceeded
    with external.SourceTextReader(tmp_path, 1024) as reader, pytest.raises(expected):
        external._parse_sarif_document_with_reader(document, "checkov", tmp_path, reader, control)


@pytest.mark.parametrize("payload", [
    b'{"nested":{"value":1},"items":[true,null,1.5]}',
    b'{"duplicate":1,"duplicate":2}', b'{"value":NaN}',
    b'{"value":1e999}', b'{"value":"\xff"}', b'{"unterminated":',
])
def test_controlled_strict_json_retains_uncontrolled_semantics(payload: bytes) -> None:
    try:
        expected = external._strict_json_bytes(payload)
    except external.NativeJSONDecodeError as error:
        with pytest.raises(external.NativeJSONDecodeError) as controlled:
            external._strict_json_bytes(payload, external.ExecutionControl.with_timeout(10))
        assert controlled.value.reason == error.reason
    else:
        assert external._strict_json_bytes(payload, external.ExecutionControl.with_timeout(10)) == expected


def test_native_parser_checks_the_scanner_wide_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    sarif = scratch / "fixture.sarif"
    sarif.write_text('{"runs":[]}', encoding="utf-8")
    control = external.ExecutionControl.with_timeout(10)
    entered = threading.Event()

    def slow_parse(
        path: Path,
        scanner: str,
        root: Path,
        supplied_control: external.ExecutionControl | None = None,
    ) -> external.NativeParseResult:
        del path, scanner, root
        assert supplied_control is control
        entered.set()
        control.cancel_event.set()
        return external.NativeParseResult(
            findings=[],
            integrity=external.NativeParseIntegrity(),
        )

    monkeypatch.setattr(external, "_parse_sarif", slow_parse)
    with pytest.raises(external.RunCancelled):
        external._maybe_sarif(sarif, "fixture", tmp_path, scratch, control)
    assert entered.is_set()


def test_tool_scratch_is_removed_when_execution_crashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedToolCrash(BaseException):
        pass

    def crash(
        scanner: str,
        repo: Path,
        tool_dir: Path,
        publish_root: Path,
        cache_root: Path,
        timeout: int,
        started: float,
        control: external.ExecutionControl | None = None,
        inputs: dict[str, Path] | None = None,
    ) -> external.ToolRunResult:
        del scanner, repo, publish_root, cache_root, timeout, started, control, inputs
        (tool_dir / "raw.stderr.txt").write_text("raw crash fixture", encoding="utf-8")
        raise SimulatedToolCrash

    monkeypatch.setattr(external, "_run_external_tool", crash)
    request_dir = tmp_path / "request"
    request_dir.mkdir()
    with pytest.raises(SimulatedToolCrash):
        external.run_external_tool(
            "gitleaks",
            tmp_path,
            request_dir,
            tmp_path / "persistent",
            tmp_path / "cache",
            30,
        )
    assert not (request_dir / "gitleaks").exists()


def test_tool_environment_ignores_persistent_cache_symlinks_and_stays_in_scratch(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (cache_root / "gitleaks").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    environment, disposable_cache = external._tool_environment(
        "gitleaks", scratch, cache_root
    )
    assert disposable_cache == scratch / "cache"
    assert Path(environment["XDG_CACHE_HOME"]) == disposable_cache
    assert (cache_root / "gitleaks").is_symlink()


def test_storage_boundaries_require_three_separate_absolute_roots(tmp_path: Path) -> None:
    valid = Settings(
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_SCRATCH_DIR=str(tmp_path / "scratch"),
        KODESEC_TOOL_CACHE_DIR=str(tmp_path / "cache"),
    )
    valid.validate_storage_boundaries()

    overlapping = Settings(
        KODESEC_ARTIFACT_DIR=str(tmp_path / "data"),
        KODESEC_SCRATCH_DIR=str(tmp_path / "data" / "scratch"),
        KODESEC_TOOL_CACHE_DIR=str(tmp_path / "cache"),
    )
    with pytest.raises(RuntimeError, match="must be separate"):
        overlapping.validate_storage_boundaries()

    relative = Settings(
        KODESEC_ARTIFACT_DIR="relative/artifacts",
        KODESEC_SCRATCH_DIR=str(tmp_path / "scratch"),
        KODESEC_TOOL_CACHE_DIR=str(tmp_path / "cache"),
    )
    with pytest.raises(RuntimeError, match="must be absolute"):
        relative.validate_storage_boundaries()


@pytest.mark.parametrize(
    "environment",
    [
        {"KODESEC_MAX_FILES": 0},
        {"KODESEC_MAX_FILE_BYTES": 0},
    ],
)
def test_source_coverage_limits_must_be_positive(
    environment: dict[str, int],
) -> None:
    with pytest.raises(ValueError):
        Settings(**environment)


@pytest.mark.parametrize("outcome", ["completed", "failed", "cancelled"])
def test_adapter_measurement_uses_monotonic_elapsed_and_includes_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str,
) -> None:
    from prometheus_client import CollectorRegistry, Histogram

    registry = CollectorRegistry()
    metric = Histogram("adapter_test_seconds", "fixture", ["scanner"], registry=registry)
    from kodesec_scanner import execution_metrics

    monkeypatch.setattr(execution_metrics, "adapter_duration", metric)
    clock = [100.0]
    monkeypatch.setattr(external.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(external.time, "time", lambda: -1_000_000.0)

    def adapter(*_args, **_kwargs):
        clock[0] += 0.25
        if outcome == "cancelled":
            raise external.RunCancelled("fixture")
        return external.ToolRunResult(scanner="gitleaks", status=outcome)

    def cleanup(*_args, **_kwargs):
        clock[0] += 0.125

    monkeypatch.setattr(external, "_run_external_tool", adapter)
    monkeypatch.setattr(external.shutil, "rmtree", cleanup)
    args = ("gitleaks", tmp_path, tmp_path, tmp_path, tmp_path, 30)
    if outcome == "cancelled":
        with pytest.raises(external.RunCancelled):
            external.run_external_tool(*args)
    else:
        assert external.run_external_tool(*args).status == outcome
    assert registry.get_sample_value("adapter_test_seconds_count", {"scanner": "gitleaks"}) == 1
    assert registry.get_sample_value("adapter_test_seconds_sum", {"scanner": "gitleaks"}) == 0.375
    # An unexecuted unknown tool cannot create a user-derived metric label.
    skipped = external.run_external_tool("user-provided-tool", *args[1:])
    assert skipped.status == "skipped"
    assert registry.get_sample_value("adapter_test_seconds_count", {"scanner": "user-provided-tool"}) is None


@pytest.mark.parametrize("platform", ["linux", "windows"])
@pytest.mark.parametrize("cancelled", [False, True])
def test_platform_allowance_cannot_renew_original_run_control(tmp_path, monkeypatch, platform, cancelled):
    settings = Settings(KODESEC_SCAN_PLATFORM=platform, _env_file=None,
                        KODESEC_EXTERNAL_TOOL_NICE=0)
    monkeypatch.setattr(external, "get_settings", lambda: settings)
    control = external.ExecutionControl.with_timeout(0.05, termination_grace_seconds=0.1)
    original_deadline = control.deadline_monotonic
    calls = []
    def invoke(scanner, command, cwd, timeout, raw_dir, env, *, control):
        calls.append(timeout)
        assert control.deadline_monotonic == original_deadline
        return external._run_command(scanner, [sys.executable, "-c", "import time; time.sleep(5)"],
                                     cwd, timeout, raw_dir, env, control=control)
    monkeypatch.setattr(external, "_invoke_run_command", invoke)
    if cancelled:
        control.cancel_event.set()
    with pytest.raises(external.RunCancelled if cancelled else external.RunDeadlineExceeded):
        external.run_external_tool("bearer", tmp_path, tmp_path / "scratch", tmp_path / "publish",
                                   tmp_path / "cache", 300, control, _runtime_components(tmp_path))
    assert control.deadline_monotonic == original_deadline
    assert calls == ([] if cancelled else [1560 if platform == "linux" else 2340])
    assert not (tmp_path / "scratch" / "bearer").exists()


@pytest.mark.parametrize("platform", ["", "Linux", "wsl", "2", " linux", "unbounded"])
def test_scan_platform_requires_exact_installation_lane(platform):
    with pytest.raises(ValueError):
        Settings(KODESEC_SCAN_PLATFORM=platform, _env_file=None)
