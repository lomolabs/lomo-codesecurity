from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).parents[3] / "scripts" / "demo-scan.sh"
REQUIRED_EXTERNAL = (
    "trivy",
    "gitleaks",
    "opengrep",
    "bearer",
    "grype",
    "checkov",
    "trufflehog",
    "syft",
)


def _validator_source() -> str:
    script = SCRIPT.read_text(encoding="utf-8")
    marker = '    SCAN_JSON="$scan_json" python3 - <<\'PY\'\n'
    source = script.split(marker, 1)[1].split("\nPY\n    FINDINGS_JSON=", 1)[0]
    assert "required_external" in source
    return source


def _findings_printer_source() -> str:
    script = SCRIPT.read_text(encoding="utf-8")
    marker = '    FINDINGS_JSON="$findings" python3 - <<\'PY\'\n'
    source = script.split(marker, 1)[1].split("\nPY\n    echo", 1)[0]
    assert "paginated envelope" in source
    return source


def _valid_scan() -> dict[str, object]:
    order = (*REQUIRED_EXTERNAL[:-1], "syft")
    # The dependency invariant requires Syft before Grype.
    order = tuple(tool_id for tool_id in order if tool_id not in {"syft", "grype"}) + (
        "syft",
        "grype",
    )
    tools = [
        {
            "id": tool_id,
            "source": "external",
            "enabled": True,
            "available": True,
            "status": "completed",
            "error": None,
            "findings_count": 0,
            "artifacts_count": 1 if tool_id == "syft" else 0,
        }
        for tool_id in REQUIRED_EXTERNAL
    ]
    return {
        "status": "completed",
        "error": None,
        "gate_decision": "fail",
        "scanner_summary": {
            "requested_mode": "full",
            "effective_mode": "full",
            "findings_total": 1,
            "severity_counts": {"high": 1},
            "errors": [],
            "tools": tools,
            "external_runs": [{"id": tool_id} for tool_id in order],
            "artifacts": [
                {
                    "scanner": "syft",
                    "artifact_type": "sbom",
                    "format": "cyclonedx-json",
                }
            ],
        },
    }


def _validate(scan: dict[str, object]) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "SCAN_JSON": json.dumps(scan)}
    return subprocess.run(
        [sys.executable, "-c", _validator_source()],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _print_findings(payload: object) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "FINDINGS_JSON": json.dumps(payload)}
    return subprocess.run(
        [sys.executable, "-c", _findings_printer_source()],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_demo_scan_accepts_only_complete_eight_scanner_evidence() -> None:
    result = _validate(_valid_scan())
    assert result.returncode == 0, result.stderr


def test_demo_scan_rejects_partial_missing_scanner_and_missing_syft_evidence() -> None:
    scan = deepcopy(_valid_scan())
    scan["status"] = "partial"
    summary = scan["scanner_summary"]
    assert isinstance(summary, dict)
    summary["errors"] = ["bearer: timeout"]
    tools = summary["tools"]
    assert isinstance(tools, list)
    tools[:] = [item for item in tools if item["id"] != "bearer"]
    summary["artifacts"] = []

    result = _validate(scan)

    assert result.returncode == 1
    assert "terminal status" in result.stderr
    assert "scanner_summary.errors" in result.stderr
    assert "missing=['bearer']" in result.stderr
    assert "no Syft CycloneDX SBOM evidence" in result.stderr


def test_demo_scan_rejects_grype_before_syft() -> None:
    scan = _valid_scan()
    summary = scan["scanner_summary"]
    assert isinstance(summary, dict)
    summary["external_runs"] = [
        {"id": tool_id}
        for tool_id in (*REQUIRED_EXTERNAL[:-1], "syft")
    ]

    result = _validate(scan)

    assert result.returncode == 1
    assert "Grype ran before" in result.stderr


def test_demo_scan_reads_the_bounded_findings_page_contract() -> None:
    result = _print_findings(
        {
            "items": [
                {
                    "severity": "high",
                    "rule_id": "fixture.rule",
                    "file_path": "src/app.py",
                    "start_line": 7,
                }
            ],
            "total": 13,
            "truncated": True,
            "next_cursor": "opaque-cursor",
            "revision": 2,
        }
    )

    assert result.returncode == 0, result.stderr
    assert "fixture.rule" in result.stdout
    assert "src/app.py:7" in result.stdout


def test_demo_scan_rejects_non_envelope_or_inconsistent_findings_payloads() -> None:
    non_envelope = _print_findings([])
    assert non_envelope.returncode != 0
    assert "paginated envelope" in non_envelope.stderr

    inconsistent = _print_findings(
        {
            "items": [],
            "total": 0,
            "truncated": False,
            "next_cursor": "unexpected",
            "revision": 1,
        }
    )
    assert inconsistent.returncode != 0
    assert "truncation and cursor state disagree" in inconsistent.stderr


def test_demo_scan_resolves_conflicts_by_exact_repo_path() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'POST "$API_URL/v1/projects/resolve"' in source
    assert '"repo_path": os.environ["DEMO_PATH"]' in source
    assert "limit=500" not in source
