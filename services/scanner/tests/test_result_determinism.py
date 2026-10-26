from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

os.environ.setdefault(
    "KODESEC_SCRATCH_DIR",
    str(Path(tempfile.mkdtemp(prefix="kodesec-determinism-module-")) / "scratch"),
)

from kodesec_scanner import external
from kodesec_scanner import main as scanner
from kodesec_scanner.models import (
    RUN_RESULT_MAX_FINDINGS,
    RUN_RESULT_MAX_ITEM_BYTES,
    RUN_RESULT_MAX_PAGE_BYTES,
    Finding,
    RunFindingPageRequest,
    RunStartRequest,
)
from kodesec_scanner.run_control import RunRegistry


def _registry(result_dir: Path) -> RunRegistry:
    return RunRegistry(
        scanner._execute_scan,
        deadline_seconds=5,
        retention_seconds=5,
        max_terminal_records=2,
        result_dir=result_dir,
        max_findings=RUN_RESULT_MAX_FINDINGS,
        max_item_bytes=RUN_RESULT_MAX_ITEM_BYTES,
        max_page_bytes=RUN_RESULT_MAX_PAGE_BYTES,
        max_run_bytes=336 * 1024 * 1024,
        max_total_bytes=384 * 1024 * 1024,
        termination_grace_seconds=0.1,
        shutdown_wait_seconds=2,
    )


def test_same_run_reexecution_has_identical_manifest_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    artifact_root = tmp_path / "artifacts"
    scratch_root = tmp_path / "request-scratch"
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            max_files=100,
            max_file_bytes=1024 * 1024,
            artifact_dir=str(artifact_root),
            source_snapshot_dir=str(tmp_path / "source-snapshots"),
            scratch_dir=str(scratch_root),
            tool_cache_dir=str(tmp_path / "tool-cache"),
            tool_lock_path=str(tmp_path / "scanner-tools.lock.json"),
            rules_lock_path=str(tmp_path / "scanner-rules.lock.json"),
            external_tool_timeout=30,
            validate_storage_boundaries=lambda: None,
        ),
    )

    ready_dimension = SimpleNamespace(
        model_dump=lambda **_kwargs: {
            "state": "ready",
            "reason": None,
            "component_ids": [],
        }
    )
    readiness = SimpleNamespace(
        ready=True,
        binary=ready_dimension,
        data=ready_dimension,
        rules=ready_dimension,
        execution=ready_dimension,
    )
    runtime_by_id = {
        tool_id: {
            "id": tool_id,
            "available": True,
            "status": "verified",
            "installed_version": "fixture-1",
        }
        for tool_id in ("opengrep", "syft")
    }
    monkeypatch.setattr(
        scanner,
        "scanner_runtime_context",
        lambda **_kwargs: SimpleNamespace(
            runtime_by_id=runtime_by_id,
            readiness_by_id={"opengrep": readiness, "syft": readiness},
            tools=None,
        ),
    )
    monkeypatch.setattr(
        scanner,
        "tool_runtime_state",
        lambda tool_id: {
            "id": tool_id,
            "available": True,
            "status": "builtin",
            "installed_version": "fixture-1",
        },
    )

    alpha = Finding(
        scanner="opengrep",
        rule_id="fixture.alpha",
        severity="high",
        file_path="src/alpha.py",
        start_line=4,
        end_line=4,
        message="alpha finding",
        fingerprint="a" * 64,
        metadata={"tags": ["alpha", "stable"]},
    )
    beta = Finding(
        scanner="opengrep",
        rule_id="fixture.beta",
        severity="medium",
        file_path="src/beta.py",
        start_line=9,
        end_line=9,
        message="beta finding",
        fingerprint="b" * 64,
        metadata={"tags": ["beta", "stable"]},
    )
    executions = {"opengrep": 0, "syft": 0}

    def fake_external_tool(
        tool_id: str,
        _repo: Path,
        request_scratch: Path,
        publish_root: Path,
        _cache_root: Path,
        _timeout: int,
        _control: external.ExecutionControl,
        _inputs: dict[str, Path],
    ) -> external.ToolRunResult:
        executions[tool_id] += 1
        execution = executions[tool_id]
        if tool_id == "opengrep":
            findings = [beta, alpha, alpha] if execution == 1 else [alpha, beta, beta]
            return external.ToolRunResult(
                scanner=tool_id,
                status="completed",
                findings=findings,
                duration_ms=7 if execution == 1 else 9_999,
                exit_code=0,
                parse_integrity={
                    "complete": True,
                    "total_records": 3,
                    "accepted_records": 3,
                    "intentionally_filtered_records": 0,
                    "dropped_records": 0,
                    "dropped_reason_counts": {},
                    "filter_reason_counts": {},
                },
            )

        alpha_ref = (
            "urn:uuid:00000000-0000-4000-8000-000000000011"
            if execution == 1
            else "urn:uuid:00000000-0000-4000-8000-000000000021"
        )
        beta_ref = (
            "urn:uuid:00000000-0000-4000-8000-000000000012"
            if execution == 1
            else "urn:uuid:00000000-0000-4000-8000-000000000022"
        )
        components = [
            {
                "type": "library",
                "name": "alpha",
                "version": "1",
                "purl": "pkg:pypi/alpha@1",
                "bom-ref": alpha_ref,
            },
            {
                "type": "library",
                "name": "beta",
                "version": "2",
                "purl": "pkg:pypi/beta@2",
                "bom-ref": beta_ref,
            },
        ]
        dependencies = [
            {"ref": alpha_ref, "dependsOn": [beta_ref]},
            {"ref": beta_ref, "dependsOn": []},
        ]
        if execution == 2:
            components.reverse()
            dependencies.reverse()
        raw = request_scratch / "mocked-syft.cyclonedx.json"
        raw.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "serialNumber": (
                        "urn:uuid:00000000-0000-4000-8000-000000000099"
                        if execution == 1
                        else "urn:uuid:00000000-0000-4000-8000-000000000199"
                    ),
                    "metadata": {
                        "timestamp": (
                            "2026-08-13T08:00:00Z"
                            if execution == 1
                            else "2026-08-13T08:00:42Z"
                        ),
                        "component": {
                            "type": "file",
                            "name": str(repo),
                            "bom-ref": f"root:{repo}",
                        },
                    },
                    "components": components,
                    "dependencies": dependencies,
                }
            ),
            encoding="utf-8",
        )
        artifact = external._publish_sanitized_sbom(
            raw,
            request_scratch,
            publish_root,
        )
        return external.ToolRunResult(
            scanner=tool_id,
            status="completed",
            artifacts=[artifact],
            duration_ms=11 if execution == 1 else 8_888,
            exit_code=0,
        )

    monkeypatch.setattr(scanner, "run_external_tool", fake_external_tool)

    request = RunStartRequest(
        run_id=UUID("12345678-1234-5678-9234-567812345678"),
        scan_id=73,
        repo_path=str(repo),
        enabled_tools=["opengrep", "syft"],
    )
    result_dir = tmp_path / "registry-scratch" / "run-results"

    first = _registry(result_dir)
    try:
        first.start(request)
        first_state = first.wait_for_terminal(request.run_id, 2)
        assert first_state.status == "completed"
        assert first_state.result_manifest is not None
        first_manifest = first_state.result_manifest.model_dump(mode="json")
        first_page = first.page(
            request.run_id,
            RunFindingPageRequest(request_digest=first_state.request_digest),
        ).model_dump(mode="json")
        assert "duration_ms" not in json.dumps(first_manifest["summary"])
        assert first.shutdown()

        second = _registry(result_dir)
        try:
            second.start(request)
            second_state = second.wait_for_terminal(request.run_id, 2)
            assert second_state.status == "completed"
            assert second_state.result_manifest is not None
            second_manifest = second_state.result_manifest.model_dump(mode="json")
            second_page = second.page(
                request.run_id,
                RunFindingPageRequest(request_digest=second_state.request_digest),
            ).model_dump(mode="json")

            assert first_manifest == second_manifest
            assert first_page == second_page
            assert first_manifest["result_digest"] == second_manifest["result_digest"]
            assert first_manifest["findings_digest"] == second_manifest["findings_digest"]
            assert first_manifest["artifacts"][0]["sha256"] == second_manifest["artifacts"][0]["sha256"]
            published = Path(second_manifest["artifacts"][0]["path"]).read_bytes()
            assert hashlib.sha256(published).hexdigest() == second_manifest["artifacts"][0]["sha256"]
            assert [item["fingerprint"] for item in second_page["items"]] == [
                "a" * 64,
                "b" * 64,
            ]
        finally:
            second.shutdown()
    finally:
        first.shutdown()
