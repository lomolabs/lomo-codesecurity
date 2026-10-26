from __future__ import annotations

from pathlib import Path
import random
import re
import time

import pytest

from kodesec_scanner import rules
from kodesec_scanner.external import ExecutionControl, RunCancelled, RunDeadlineExceeded
from kodesec_scanner.redaction import redact_text


TOKEN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


@pytest.mark.parametrize("name,line,expected", [
    ("main.py", "subprocess.run(command, shell=True)", ["sast.python_shell_true"]),
    ("main.js", "const settings = eval(serialized);", ["sast.javascript_eval"]),
    ("main.ts", "const settings = Function(serialized);", ["sast.javascript_eval"]),
    ("main.py", "eval(serialized)", []),
    ("main.js", "// subprocess.run(command, shell=True)", []),
    ("main.py", "# subprocess.run(command, shell=True)", []),
    ("main.js", "// eval(serialized)", []),
    ("README.md", "subprocess.run(command, shell=True); eval(serialized)", []),
    ("deployment.yaml", "description: eval(serialized)", []),
    ("main.py", "token = random.random()", ["sast.insecure_random"]),
    ("main.js", "const token = Math.random();", ["sast.insecure_random"]),
])
def test_sast_lite_respects_named_language_and_comment_scope(
    tmp_path: Path, name: str, line: str, expected: list[str],
) -> None:
    findings = rules.scan_text_file(tmp_path, tmp_path / name, line + "\n", enabled_tools={"sast-lite"})
    assert [finding.rule_id for finding in findings] == expected


def test_comment_scope_keeps_secret_checks_enabled(tmp_path: Path) -> None:
    text = '# password = "demo-demo-demo-demo"\n'
    findings = rules.scan_text_file(tmp_path, tmp_path / "main.py", text)
    assert [finding.rule_id for finding in findings] == ["secret.generic_assignment"]


@pytest.mark.parametrize("name,line", [
    ("main.py", f"# fixture identifier: {TOKEN}\n"),
    ("package-lock.json", f'{{"token": "{TOKEN}"}}\n'),
    ("main.py", f'# token sha256-{TOKEN}\n'),
    ("main.py", f'# token sha512-{TOKEN}\n'),
    ("main.py", f'# token "integrity": {TOKEN}\n'),
])
def test_entropy_exclusions_skip_calculation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, line: str,
) -> None:
    def unexpected_entropy(_value: str) -> float:
        raise AssertionError("excluded entropy input must not be evaluated")

    monkeypatch.setattr(rules, "_entropy", unexpected_entropy)
    findings = rules.scan_text_file(tmp_path, tmp_path / name, line, enabled_tools={"secrets-lite"})
    assert not [finding for finding in findings if finding.rule_id == "secret.high_entropy"]


def test_entropy_positive_retains_metadata_and_stable_fingerprint(tmp_path: Path) -> None:
    text = f"# token: {TOKEN}\n"
    findings = rules.scan_text_file(tmp_path, tmp_path / "main.py", text, enabled_tools={"secrets-lite"})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.scanner, finding.rule_id, finding.severity) == ("secrets-lite", "secret.high_entropy", "medium")
    assert finding.metadata["entropy"] == 5.95
    assert finding.code_snippet == redact_text(text.rstrip("\n"))
    assert finding.start_line == finding.end_line == 1
    repeated = rules.scan_text_file(tmp_path, tmp_path / "main.py", text, enabled_tools={"secrets-lite"})
    assert finding.model_dump() == repeated[0].model_dump()


def test_entropy_identity_keeps_distinct_tails_and_repeated_occurrences(tmp_path: Path) -> None:
    from kodesec_scanner.main import _canonicalize_findings

    first, second = TOKEN * 3 + "abc", TOKEN * 3 + "bac"
    assert first[:160] == second[:160]
    text = f"# token: {first} {second} {first}\n"
    findings = rules.scan_text_file(tmp_path, tmp_path / "source.py", text, enabled_tools={"secrets-lite"})
    assert len(findings) == 3 and len({finding.fingerprint for finding in findings}) == 3
    assert len({finding.metadata["entropy"] for finding in findings}) == 1
    assert len(_canonicalize_findings(findings)) == 3
    assert all(finding.start_line == finding.end_line == 1 for finding in findings)
    assert all(first not in finding.code_snippet and second not in finding.code_snippet for finding in findings)
    repeated = rules.scan_text_file(tmp_path, tmp_path / "source.py", text, enabled_tools={"secrets-lite"})
    assert [finding.model_dump() for finding in findings] == [finding.model_dump() for finding in repeated]


def test_entropy_identity_version_does_not_change_other_rule_fingerprints(tmp_path: Path) -> None:
    text = "subprocess.run(command, shell=True)\n"
    finding = rules.scan_text_file(tmp_path, tmp_path / "source.py", text, enabled_tools={"sast-lite"})[0]
    assert finding.fingerprint == rules._fingerprint("sast.python_shell_true", "source.py", 1, text)


@pytest.mark.parametrize("kind", ["cancelled", "expired"])
def test_lite_control_stops_before_document_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    control = ExecutionControl.with_timeout(0 if kind == "expired" else 10)
    if kind == "cancelled":
        control.cancel_event.set()

    def unexpected_document(_text: str) -> None:
        raise AssertionError("terminal control must stop before indexing source")

    monkeypatch.setattr(rules.SourceDocument, "from_text", unexpected_document)
    with pytest.raises(RunCancelled if kind == "cancelled" else RunDeadlineExceeded):
        rules.scan_text_file(tmp_path, tmp_path / "main.py", "x" * 1_048_576, checkpoint=control.checkpoint)


def test_empty_family_selection_does_not_index_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_document(_text: str) -> None:
        raise AssertionError("disabled lite rules must not index source")

    monkeypatch.setattr(rules.SourceDocument, "from_text", unexpected_document)
    assert rules.scan_text_file(tmp_path, tmp_path / "main.py", "x" * 1_048_576, enabled_tools=set()) == []


@pytest.mark.parametrize("line,expected", [
    ("subprocess.run(command, shell = True)", True),
    ("subprocess.check_output(command, shell\t=\tTrue)", True),
    ("subprocess.run(command, shell=False)", False),
    ("subprocess.run(command); shell=True", False),
    ("subprocess.run(command); subprocess.Popen(command, shell=True)", True),
    ("subprocess.run(nested()); shell=True", False),
    ("subprocess.run(subprocess.run(command, shell=True))", True),
    ("subprocess.run(command, shell=True", True),
])
def test_shell_check_preserves_first_closing_parenthesis_behavior(line: str, expected: bool) -> None:
    assert rules._has_python_shell_true(line, lambda: None) is expected


def test_shell_disjoint_scan_matches_prior_bounded_heuristic() -> None:
    original = re.compile(r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True")
    fragments = ["subprocess.run(", "subprocess.check_output(", "subprocess._(",
                 "subprocess.run2(", "shell=True", "shell = False", ")", "x", ", ", "\t", "shell\t=\tTrue"]
    generator = random.Random(0)
    for _ in range(2000):
        line = "".join(generator.choices(fragments, k=12))
        assert rules._has_python_shell_true(line, lambda: None) == bool(original.search(line))


def test_repeated_unclosed_shell_calls_have_bounded_work_and_owner_cancellation(tmp_path: Path) -> None:
    text = "subprocess.run(" * 65536 + "\n"
    assert len(text.encode()) == 983041 and len(text.encode()) < 1048576
    started = time.monotonic()
    assert rules.scan_text_file(tmp_path, tmp_path / "source.py", text, enabled_tools={"sast-lite"}) == []
    assert time.monotonic() - started < 3
    control = ExecutionControl.with_timeout(10)
    calls = 0

    def cancel_during_scan():
        nonlocal calls
        calls += 1
        if calls == 3:
            control.cancel_event.set()
        control.checkpoint()

    with pytest.raises(RunCancelled):
        rules._has_python_shell_true(text, cancel_during_scan)


@pytest.mark.parametrize("rule_id,severity,name,positive,negative", [
    ("secret.aws_access_key", "critical", "source.py", "# AKIAABCDEFGHIJKLMNOP", "# AKIAABCDEFGHIJKLMNO"),
    ("secret.github_token", "critical", "source.py", "# ghp_" + "a" * 30, "# ghp_" + "a" * 29),
    ("secret.slack_token", "critical", "source.py", "# xoxb-" + "a" * 20, "# xoxb-" + "a" * 19),
    ("secret.private_key", "critical", "source.py", "-----BEGIN TEST PRIVATE KEY-----\nQUJD\n-----END TEST PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----"),
    ("secret.high_entropy", "medium", "source.py", "# token: " + TOKEN, "# token: " + "a" * 62),
    ("sast.insecure_random", "low", "source.py", "token = random.random()", "token = secrets.token_urlsafe(32)"),
    ("iac.terraform_public_ingress", "high", "network.tf", 'cidr_blocks = ["0.0.0.0/0", "::/0"]', 'cidr_blocks = ["10.0.0.0/8", "2001:db8::/32"]'),
])
def test_non_demo_rules_have_exact_synthetic_controls(
    tmp_path: Path, rule_id: str, severity: str, name: str, positive: str, negative: str,
) -> None:
    family = {"secret": "secrets-lite", "sast": "sast-lite", "iac": "iac-lite"}[rule_id.split(".")[0]]
    for text, expected in [(positive, [rule_id]), (negative, [])]:
        findings = rules.scan_text_file(tmp_path, tmp_path / name, text, enabled_tools={family})
        assert [finding.rule_id for finding in findings] == expected
        assert all(finding.scanner == family and finding.severity == severity for finding in findings)
        assert all(redact_text(finding.code_snippet) == finding.code_snippet for finding in findings)
        repeated = rules.scan_text_file(tmp_path, tmp_path / name, text, enabled_tools={family})
        assert [finding.model_dump() for finding in findings] == [finding.model_dump() for finding in repeated]
