from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

import pytest

from kodesec_scanner.rules import scan_text_file
from kodesec_scanner.redaction import redact_finding


REVIEW_ROOT = Path(__file__).resolve().parents[3] / "examples" / "first-party-review"
MANIFEST = json.loads((REVIEW_ROOT / "expectations.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["file"])
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
@pytest.mark.parametrize("family", [None, "secrets-lite", "sast-lite", "iac-lite"])
def test_review_examples_have_exact_lite_outcomes(case: dict, variant: str, family: str | None) -> None:
    path = REVIEW_ROOT / variant / case["file"]
    text = path.read_text(encoding="utf-8")
    enabled = None if family is None else {family}
    findings = scan_text_file(REVIEW_ROOT, path, text, enabled_tools=enabled)
    actual = Counter((finding.scanner, finding.rule_id, finding.severity) for finding in findings)
    expected = Counter({(case["scanner"], rule["id"], rule["severity"]): rule[variant]
                        for rule in case["rules"] if rule[variant] and family in {None, case["scanner"]}})
    assert actual == expected
    assert all(finding.file_path == f"{variant}/{case['file']}" for finding in findings)
    repeated = scan_text_file(REVIEW_ROOT, path, text, enabled_tools=enabled)
    assert [finding.model_dump() for finding in findings] == [finding.model_dump() for finding in repeated]
    for finding in findings:
        assert redact_finding(finding).model_dump() == finding.model_dump()
        if finding.start_line is not None:
            assert finding.code_snippet is not None
            assert finding.metadata["snippet_start_line"] <= finding.start_line
            line = text.splitlines()[finding.start_line - 1]
            assert finding.start_column == 1
            assert finding.end_column == len(line.encode("utf-16-le")) // 2 + 1


def test_review_examples_remain_small_and_do_not_call_python_functions() -> None:
    paths = [REVIEW_ROOT / variant / case["file"]
             for variant in ["vulnerable", "fixed"] for case in MANIFEST["cases"]]
    assert sum(len(path.read_text(encoding="utf-8").splitlines()) for path in paths) <= 240
    for path in paths:
        if path.suffix == ".py":
            tree = ast.parse(path.read_text(encoding="utf-8"))
            assert all(isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
                       for node in tree.body)
