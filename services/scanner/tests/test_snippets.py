from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kodesec_scanner import external
from kodesec_scanner.models import Finding
from kodesec_scanner.rules import scan_text_file
from kodesec_scanner.source_io import SourceDocument, SourceTextReader, SourceEvidenceError
from kodesec_scanner.redaction import redact_finding, redact_text


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_source_snippet_redacts_private_key_body_when_begin_is_outside_context(
    tmp_path: Path, ending: str,
) -> None:
    # Synthetic, non-key bytes. The short final line evades generic token masking.
    tail = "QUJDREVGR0hJSktMTQ=="
    source = ending.join([
        "-----BEGIN PRIVATE KEY-----", *(["A" * 64] * 60), tail,
        "-----END PRIVATE KEY-----", "const result = eval(payload);", "",
    ])
    finding = next(item for item in scan_text_file(tmp_path, tmp_path / "source.js", source,
        enabled_tools={"sast-lite"}) if item.rule_id == "sast.javascript_eval")
    assert finding.start_line == finding.end_line == 64
    assert finding.start_column == 1
    assert finding.end_column == 30
    assert finding.metadata["snippet_start_line"] > 1
    assert "-----BEGIN PRIVATE KEY-----" not in finding.code_snippet
    assert tail not in redact_finding(finding).code_snippet
    assert "const result = eval(payload);" in finding.code_snippet
    snippet, start = external._snippet_from_source_document(SourceDocument.from_text(source), 64)
    assert start > 1
    assert tail not in redact_text(snippet)
    assert "const result = eval(payload);" in snippet


def test_source_private_key_index_is_cached_and_unbound_fallback_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kodesec_scanner import source_io

    original = source_io.private_key_body_boundaries
    calls = []

    def record(text: str):
        calls.append(len(text))
        return original(text)

    monkeypatch.setattr(source_io, "private_key_body_boundaries", record)
    source = SourceDocument.from_text("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n😀safe();\n")
    for _ in range(20):
        snippet, start = external._snippet_from_source_document(source, 4)
        assert start == 1
        assert "QUJD" not in snippet
        assert "😀safe();" in snippet
    assert calls == [len(source.text)]
    assert external._snippet_from_source_document(source, None, "QUJD") == (None, None)
    snippet, start = external._snippet_from_source_document(source, 5, "QUJD")
    assert start == 1 and "QUJD" not in snippet
    clean = SourceDocument.from_text("safe();\n")
    assert external._snippet_from_source_document(clean, None, "safe();") == ("safe();", None)


def test_source_private_key_context_handles_multiple_and_unclosed_blocks() -> None:
    text = ("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"
            "safe();\n-----BEGIN EC PRIVATE KEY-----\nREVGRw==\nmore material")
    source = SourceDocument.from_text(text)
    assert source.redact_snippet("QUJD\n-----END PRIVATE KEY-----\nsafe();", 2) == (
        "[REDACTED]\n-----END PRIVATE KEY-----\nsafe();")
    assert source.redact_snippet("safe();", 4) == "safe();"
    assert source.redact_snippet("REVGRw==\nmore material", 6) == "[REDACTED]\n[REDACTED]"
    with pytest.raises(SourceEvidenceError):
        source.redact_snippet("bad", 0)


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_source_snippet_masks_all_inline_key_bodies_without_changing_ranges(tmp_path: Path, ending: str) -> None:
    begin, end = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
    text = f"{begin}QUJD{end}; {begin}REVG{end}{ending}const result = eval(payload);{ending}"
    source = SourceDocument.from_text(text)
    assert list(source.private_key_boundaries) == [len(begin), len(begin) + 4,
        len(begin) + 4 + len(end) + 2 + len(begin), len(begin) + 4 + len(end) + 2 + len(begin) + 4]
    finding = scan_text_file(tmp_path, tmp_path / "source.js", text, enabled_tools={"sast-lite"})[0]
    assert finding.start_line == finding.end_line == 2
    assert finding.start_column == 1 and finding.end_column == 30
    assert "QUJD" not in finding.code_snippet and "REVG" not in finding.code_snippet
    assert finding.code_snippet.count("[REDACTED]") == 2
    assert "const result = eval(payload);" in finding.code_snippet
    assert redact_finding(finding).model_dump() == finding.model_dump()


def test_private_key_is_sanitized_before_encoded_model_context_trimming(tmp_path: Path) -> None:
    tail = "QUJDREVGR0hJSktMTQ=="
    text = "\n".join([*(["😀" * 70] * 40), "-----BEGIN PRIVATE KEY-----", tail,
        "-----END PRIVATE KEY-----", "const result = eval(payload);", *(["😀" * 70] * 40)])
    finding = next(item for item in scan_text_file(tmp_path, tmp_path / "source.js", text,
        enabled_tools={"sast-lite"}) if item.rule_id == "sast.javascript_eval")
    assert finding.start_line == 44
    assert finding.start_column == 1 and finding.end_column == 30
    assert finding.metadata["snippet_truncated"] is True
    assert tail not in redact_finding(finding).code_snippet
    assert "const result = eval(payload);" in finding.code_snippet
    assert "😀" in finding.code_snippet


def _write_sarif(
    path: Path,
    *,
    source_path: str,
    start_line: int | None,
    fallback: str = "",
    region_values: dict[str, object] | None = None,
    column_kind: str | None = "utf16CodeUnits",
    tool_name: str = "Fixture",
    rule_id: str = "fixture.eval",
) -> None:
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        **(
                            {"columnKind": column_kind}
                            if column_kind is not None
                            else {}
                        ),
                        "tool": {"driver": {"name": tool_name, "rules": []}},
                        "results": [
                            {
                                "ruleId": rule_id,
                                "level": "error",
                                "message": {"text": "fixture offender"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": source_path},
                                            "region": {
                                                "snippet": {"text": fallback},
                                                **(
                                                    {"startLine": start_line}
                                                    if start_line is not None
                                                    else {}
                                                ),
                                                **(region_values or {}),
                                            },
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


def test_builtin_snippet_preserves_leading_blank_lines_and_indentation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    path = root / "source.js"
    source = "\n\n    const result = eval(payload);\n    return result;\n"

    finding = next(item for item in scan_text_file(root, path, source) if item.rule_id == "sast.javascript_eval")

    assert finding.start_line == 3
    assert finding.start_column == 1
    assert finding.end_line == 3
    assert finding.end_column == len("    const result = eval(payload);".encode("utf-16-le")) // 2 + 1
    assert finding.metadata["snippet_start_line"] == 1
    assert finding.code_snippet == "\n\n    const result = eval(payload);\n    return result;"
    snippet_lines = finding.code_snippet.splitlines()
    offender_index = finding.start_line - finding.metadata["snippet_start_line"]
    assert snippet_lines[offender_index] == "    const result = eval(payload);"


def test_many_short_lines_use_compact_indexes_and_a_single_document_cache(
    tmp_path: Path,
) -> None:
    text = "x\n" * (1_048_576 // 2)
    source = SourceDocument.from_text(text)

    assert source.line_count == 524_289
    retained_index_bytes = sum(
        values.buffer_info()[1] * values.itemsize
        for values in (source.line_starts, source.utf16_endpoints)
    )
    assert retained_index_bytes < 5 * 1024 * 1024
    assert source.line(0, keepend=True) == "x\n"
    assert source.line(source.line_count - 1) == ""

    root = tmp_path / "repo-cache"
    root.mkdir()
    (root / "first.js").write_text("first();\n", encoding="utf-8")
    (root / "second.js").write_text("second();\n", encoding="utf-8")
    with SourceTextReader(root, 1_048_576) as reader:
        first = reader.read_document("first.js")
        assert reader.read_document("first.js") is first
        reader.read_document("second.js")
        assert reader.read_document("first.js") is not first


def test_sarif_snippet_keeps_offender_when_long_prefix_exceeds_limit(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    path = root / "source.js"
    prefix = [f"// prefix {number:02d} " + ("x" * 1200) + "\n" for number in range(40)]
    offender = "    eval(payload);\n"
    suffix = [f"// suffix {number:02d}\n" for number in range(40)]
    source_lines = [*prefix, offender, *suffix]
    path.write_text("".join(source_lines), encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(sarif_path, source_path="source.js", start_line=41)

    finding = external.parse_sarif(sarif_path, "fixture", root)[0]

    assert finding.code_snippet is not None
    assert len(finding.code_snippet) <= external.SNIPPET_MAX_CHARS
    snippet_start = finding.metadata["snippet_start_line"]
    assert isinstance(snippet_start, int)
    assert snippet_start > 1
    snippet_lines = finding.code_snippet.splitlines()
    assert snippet_lines[0] == redact_text(source_lines[snippet_start - 1].removesuffix("\n"))
    assert snippet_lines[finding.start_line - snippet_start] == offender.removesuffix("\n")
    assert finding.metadata["snippet_truncated"] is True


def test_finding_transport_bounds_single_long_offending_line_around_column() -> None:
    line = ("x" * 18_000) + "eval(payload)" + ("y" * 18_000)
    finding = Finding(
        scanner="fixture",
        rule_id="fixture.long-line",
        severity="high",
        file_path="source.js",
        start_line=41,
        start_column=18_001,
        end_line=41,
        end_column=18_014,
        message="fixture offender",
        code_snippet=line,
        fingerprint="f" * 64,
        metadata={"snippet_start_line": 41},
    )

    assert finding.code_snippet is not None
    assert finding.code_snippet.startswith("eval(payload)")
    assert finding.metadata["snippet_start_line"] == 41
    assert finding.metadata["snippet_truncated"] is True
    assert finding.metadata["snippet_line_truncated"] is True
    assert finding.metadata["snippet_column_start"] == 18_001


def test_sarif_rejects_a_reported_location_without_exact_source(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    sarif_path = tmp_path / "findings.sarif"
    fallback = "    eval(payload);\n    return payload;\n"
    _write_sarif(sarif_path, source_path="missing.js", start_line=44, fallback=fallback)

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "unsafe_or_unreadable_source_path": 1,
    }


def test_sarif_preserves_precise_multiline_columns(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "source.js"
    source.write_text("const first = input;\nunsafe(\n  first,\n);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=2,
        region_values={"startColumn": 1, "endLine": 3, "endColumn": 8},
    )

    finding = external.parse_sarif(sarif_path, "fixture", root)[0]

    assert (finding.start_line, finding.start_column) == (2, 1)
    assert (finding.end_line, finding.end_column) == (3, 8)


def test_sarif_preserves_a_zero_width_insertion_point(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    sarif_path = tmp_path / "trivy.sarif"
    _write_sarif(
        sarif_path,
        source_path="Dockerfile",
        start_line=1,
        region_values={"startColumn": 1, "endLine": 1, "endColumn": 1},
        tool_name="Trivy",
        rule_id="fixture.trivy.insertion-point",
    )

    finding = external.parse_sarif(sarif_path, "trivy", root)[0]

    assert (
        finding.start_line,
        finding.start_column,
        finding.end_line,
        finding.end_column,
    ) == (1, 1, 1, 1)


def test_sarif_completes_a_start_only_column_to_the_exact_line_end(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("const value = unsafe(input);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        region_values={"startColumn": 15},
    )

    finding = external.parse_sarif(sarif_path, "fixture", root)[0]

    assert (finding.start_line, finding.end_line) == (1, 1)
    assert finding.start_column == 15
    assert finding.end_column == 29


def test_sarif_completes_a_missing_start_column_from_the_line_start(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("unsafe(input);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        region_values={"endColumn": 8},
    )

    finding = external.parse_sarif(sarif_path, "fixture", root)[0]

    assert (finding.start_line, finding.end_line) == (1, 1)
    assert finding.start_column == 1
    assert finding.end_column == 8


def test_sarif_invalid_columns_fail_native_parse_integrity(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("unsafe(input);\n", encoding="utf-8")
    for index, values in enumerate(
        (
            {"startColumn": 0, "endColumn": 8},
            {"startColumn": True, "endColumn": 8},
            {"startColumn": 2, "endColumn": 0},
            {"startColumn": 9, "endColumn": 2},
        )
    ):
        sarif_path = tmp_path / f"findings-{index}.sarif"
        _write_sarif(sarif_path, source_path="source.js", start_line=1, region_values=values)
        with pytest.raises(external.NativeParseIntegrityError) as exc_info:
            external.parse_sarif(sarif_path, "fixture", root)
        assert exc_info.value.integrity.dropped_reason_counts == {
            "invalid_source_location": 1,
        }


def test_sarif_reversed_lines_fail_native_parse_integrity(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("unsafe(input);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=3,
        region_values={"startColumn": 2, "endLine": 1, "endColumn": 4},
    )

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "invalid_source_location": 1,
    }


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("prefix", ["", "// header\n\t😀 "])
def test_gitleaks_zero_end_column_uses_exact_multiline_source(
    tmp_path: Path, newline: str, prefix: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    secret = newline.join(["BEGIN fixture", "inert test material", "END fixture"])
    (root / "key.pem").write_bytes((prefix + secret).encode())
    start_line = prefix.count("\n") + 1
    start_column = len(prefix.rsplit("\n", 1)[-1].encode()) + 1 + (start_line > 1)
    sarif = tmp_path / "finding.sarif"
    _write_sarif(sarif, source_path="key.pem", start_line=start_line,
                 column_kind=None, fallback=secret,
                 region_values={"startColumn": start_column,
                                "endLine": start_line, "endColumn": 0})
    finding, = external.parse_sarif(sarif, "gitleaks", root)
    assert (finding.start_line, finding.start_column, finding.end_line, finding.end_column) == (
        start_line, 1 if not prefix else 5, start_line + 2, 12,
    )


@pytest.mark.parametrize("change", ["absent", "duplicate", "wrong-line", "wrong-column",
                                    "boolean-column", "boolean-end", "nonzero-end-line",
                                    "declared-kind", "other-scanner", "later-newline"])
def test_gitleaks_zero_end_column_refuses_unproven_recovery(tmp_path: Path, change: str) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    text = "BEGIN fixture\ninert test material\nEND fixture"
    source = text
    values = {"startColumn": 1, "endLine": 1, "endColumn": 0}
    start_line = 1
    if change == "absent": source = source.replace("inert", "other")
    if change == "duplicate": source += "\n" + text
    if change == "wrong-line": start_line = 2
    if change == "wrong-column": values["startColumn"] = 2
    if change == "boolean-column": values["startColumn"] = True
    if change == "boolean-end": values["endColumn"] = False
    if change == "nonzero-end-line": values["endLine"] = 3
    if change == "later-newline": source += "\n"
    (root / "key.pem").write_text(source)
    sarif = tmp_path / "finding.sarif"
    _write_sarif(sarif, source_path="key.pem", start_line=start_line, fallback=text,
                 column_kind="utf16CodeUnits" if change == "declared-kind" else None,
                 region_values=values)
    with pytest.raises(external.NativeParseIntegrityError) as error:
        external.parse_sarif(sarif, "fixture" if change == "other-scanner" else "gitleaks", root)
    assert error.value.integrity.dropped_records == 1


def test_sarif_line_only_location_uses_crlf_safe_utf16_columns(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_bytes("safe\r\n😀unsafe();\r\n".encode("utf-8"))
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(sarif_path, source_path="source.js", start_line=2)

    finding = external.parse_sarif(sarif_path, "fixture", root)[0]

    assert (
        finding.start_line,
        finding.start_column,
        finding.end_line,
        finding.end_column,
    ) == (2, 1, 2, 12)
    assert finding.code_snippet == "safe\r\n😀unsafe();"
    assert finding.metadata["snippet_start_line"] == 1


def test_sarif_explicit_column_kinds_normalize_to_one_utf16_fingerprint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_bytes("x😀yz\r\n".encode("utf-8"))
    findings = []
    runs = []
    for column_kind, start_column, end_column in (
        ("unicodeCodePoints", 2, 4),
        ("utf16CodeUnits", 2, 5),
    ):
        sarif_path = tmp_path / f"{column_kind}.sarif"
        _write_sarif(
            sarif_path,
            source_path="source.js",
            start_line=1,
            region_values={
                "startColumn": start_column,
                "endColumn": end_column,
            },
            column_kind=column_kind,
        )
        findings.append(external.parse_sarif(sarif_path, "fixture", root)[0])
        runs.extend(json.loads(sarif_path.read_text(encoding="utf-8"))["runs"])

    assert {
        (
            finding.start_line,
            finding.start_column,
            finding.end_line,
            finding.end_column,
        )
        for finding in findings
    } == {(1, 2, 1, 5)}
    assert len({finding.fingerprint for finding in findings}) == 1

    combined = tmp_path / "combined.sarif"
    combined.write_text(json.dumps({"runs": runs}), encoding="utf-8")
    deduplicated = external.parse_sarif(combined, "fixture", root)
    assert len(deduplicated) == 1
    assert deduplicated[0].fingerprint == findings[0].fingerprint


def test_sarif_nonempty_results_reject_an_invalid_column_kind(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("unsafe(input);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        column_kind="bytes",
    )

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "invalid_column_kind": 1,
    }


def test_sarif_nonempty_results_reject_an_explicit_null_column_kind(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text("unsafe(input);\n", encoding="utf-8")
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        column_kind=None,
    )
    document = json.loads(sarif_path.read_text(encoding="utf-8"))
    document["runs"][0]["columnKind"] = None
    sarif_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "invalid_column_kind": 1,
    }


@pytest.mark.parametrize(
    ("scanner", "tool_name", "rule_id", "region_values", "expected_columns"),
    [
        ("bearer", "Bearer", "javascript_lang_eval", {}, (1, 28)),
        (
            "checkov",
            "Checkov",
            "CKV_SECRET_6",
            {"startColumn": 16, "endColumn": 20},
            (16, 20),
        ),
        (
            "opengrep",
            "Semgrep OSS",
            "javascript.lang.security.detect-eval-with-expression",
            {"startColumn": 16, "endColumn": 20},
            (16, 20),
        ),
    ],
)
def test_sarif_missing_column_kind_accepts_only_unambiguous_source_ranges(
    tmp_path: Path,
    scanner: str,
    tool_name: str,
    rule_id: str,
    region_values: dict[str, object],
    expected_columns: tuple[int, int],
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text(
        "const unsafe = eval(input);\n",
        encoding="utf-8",
    )
    sarif_path = tmp_path / f"{scanner}.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        region_values=region_values,
        column_kind=None,
        tool_name=tool_name,
        rule_id=rule_id,
    )

    finding = external.parse_sarif(sarif_path, scanner, root)[0]

    explicit_path = tmp_path / f"{scanner}-utf16.sarif"
    _write_sarif(
        explicit_path,
        source_path="source.js",
        start_line=1,
        region_values=region_values,
        column_kind="utf16CodeUnits",
        tool_name=tool_name,
        rule_id=rule_id,
    )
    explicit_finding = external.parse_sarif(explicit_path, scanner, root)[0]

    assert finding.scanner == scanner
    assert finding.rule_id == rule_id
    assert (finding.start_column, finding.end_column) == expected_columns
    assert finding.fingerprint == explicit_finding.fingerprint


def test_sarif_missing_column_kind_rejects_emoji_ambiguous_columns(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.js").write_text(
        "const 😀 = eval(input);\n",
        encoding="utf-8",
    )
    sarif_path = tmp_path / "opengrep.sarif"
    _write_sarif(
        sarif_path,
        source_path="source.js",
        start_line=1,
        region_values={"startColumn": 11, "endColumn": 15},
        column_kind=None,
        tool_name="Semgrep OSS",
        rule_id="javascript.lang.security.detect-eval-with-expression",
    )

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "opengrep", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "ambiguous_missing_column_kind": 1,
    }


def test_sarif_source_symlink_outside_root_fails_without_fallback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("unsafe(input);\n", encoding="utf-8")
    (root / "source.js").symlink_to(outside)
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(sarif_path, source_path="source.js", start_line=1)

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "unsafe_or_unreadable_source_path": 1,
    }


@pytest.mark.parametrize("source_kind", ["missing", "outside_symlink"])
def test_sarif_locationless_record_still_requires_a_safe_existing_source(
    tmp_path: Path,
    source_kind: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    if source_kind == "outside_symlink":
        outside = tmp_path / "outside.js"
        outside.write_text("unsafe(input);\n", encoding="utf-8")
        (root / "source.js").symlink_to(outside)
    sarif_path = tmp_path / "findings.sarif"
    _write_sarif(sarif_path, source_path="source.js", start_line=None)

    with pytest.raises(external.NativeParseIntegrityError) as exc_info:
        external.parse_sarif(sarif_path, "fixture", root)

    assert exc_info.value.integrity.dropped_reason_counts == {
        "unsafe_or_unreadable_source_path": 1,
    }


@pytest.mark.parametrize(
    "location",
    [
        {"end_line": 2},
        {"start_line": 2},
        {"start_line": 2, "end_line": 1},
        {"start_line": 2, "end_line": 2, "end_column": 4},
    ],
)
def test_finding_dto_rejects_non_normalized_locations(
    location: dict[str, int],
) -> None:
    with pytest.raises(ValidationError):
        Finding(
            scanner="fixture",
            rule_id="fixture.rule",
            severity="high",
            file_path="src/app.py",
            message="fixture",
            fingerprint="f" * 64,
            **location,
        )


def test_finding_dto_accepts_a_zero_width_insertion_point() -> None:
    finding = Finding(
        scanner="fixture",
        rule_id="fixture.rule",
        severity="high",
        file_path="src/app.py",
        message="fixture",
        fingerprint="f" * 64,
        start_line=2,
        end_line=2,
        start_column=4,
        end_column=4,
    )

    assert finding.start_column == finding.end_column == 4
