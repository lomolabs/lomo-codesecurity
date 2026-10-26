from pathlib import Path

import pytest

from kodesec_scanner.lite_iac import docker_user_state
from kodesec_scanner.rules import scan_text_file
from kodesec_scanner.main import _eligible_source_name


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.dev", "service.Dockerfile", "Containerfile"])
@pytest.mark.parametrize("text,state", [
    ("FROM scratch\n", "unresolved"),
    ("FROM scratch\nUSER root\n", "root"),
    ("FROM scratch\nUSER 0:10001\n", "root"),
    ("FROM scratch\nUSER 00\n", "root"),
    ("FROM scratch\nUSER 10001:0\n", "declared"),
    ("FROM scratch\nUSER app\n", "declared"),
    ("FROM scratch\nUSER 10001\nUSER root\n", "root"),
    ("FROM scratch\nUSER root\nUSER 10001\n", "declared"),
    ("FROM scratch AS builder\nUSER 10001\nFROM scratch\n", "unresolved"),
    ("FROM scratch AS builder\nUSER 10001\nFROM builder\n", "declared"),
    ("FROM scratch\nUSER 10001\nFROM 0\n", "declared"),
    ("FROM scratch\nUSER 10001\nFROM alpine\n", "unresolved"),
    ("FROM scratch\nUSER $APP_USER\n", "unresolved"),
    ("FROM scratch\nUSER 10001:$GROUP\n", "unresolved"),
    ("FROM scratch\nUSER\n", "unresolved"),
    ("USER 10001\n", "unresolved"),
    ("  from\tscratch\r\n  user\t10001:10001\r\n", "declared"),
    ("FROM scratch\n# USER 10001\n", "unresolved"),
    ("FROM scratch\nUSER \\\n 10001\n", "declared"),
    ("# escape=`\nFROM scratch\nUSER `\n10001\n", "declared"),
    ("FROM scratch\nRUN <<EOF\nUSER 10001\nEOF\n", "unresolved"),
    ("# syntax=example/custom:1\nFROM scratch\nUSER 10001\n", "unresolved"),
    ("# syntax=docker/dockerfile:1\nFROM scratch\nUSER 10001\n", "declared"),
    ("# ordinary comment\n# escape=`\nFROM scratch\nUSER `\n10001\n", "unresolved"),
])
def test_docker_final_stage_policy_is_consistent_for_all_supported_names(
    tmp_path: Path, name: str, text: str, state: str,
) -> None:
    assert _eligible_source_name(Path(name))
    assert docker_user_state(text.splitlines(keepends=True), lambda: None) == state
    findings = scan_text_file(tmp_path, tmp_path / name, text, enabled_tools={"iac-lite"})
    assert [finding.rule_id for finding in findings] == ([] if state == "declared" else ["iac.docker_no_user"])
    for finding in findings:
        assert finding.start_line is finding.end_line is finding.code_snippet is None
        assert finding.metadata == {"container_hardening": True}
        assert finding.severity == "medium"
        assert "explicitly declares root" in finding.message if state == "root" else "no established" in finding.message


def test_docker_parent_directory_name_does_not_enable_iac_checks(tmp_path: Path) -> None:
    path = tmp_path / "dockerfile-examples/main.js"
    assert scan_text_file(tmp_path, path, "const hostPath = true;", enabled_tools={"iac-lite"}) == []
