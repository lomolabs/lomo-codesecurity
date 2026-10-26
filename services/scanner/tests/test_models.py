from __future__ import annotations

import pytest
from pydantic import ValidationError

from kodesec_scanner.models import (
    FINDING_SNIPPET_MAX_JSON_BYTES,
    Finding,
    _bound_snippet,
    canonical_json_bytes,
)
from kodesec_scanner.source_io import SourceDocument, complete_source_location


@pytest.mark.parametrize("control", ["\n", "\r", "\t", "\x1f", "\x7f"])
def test_finding_rejects_all_control_characters_in_file_path(control: str) -> None:
    with pytest.raises(ValidationError, match="project-relative"):
        Finding(
            scanner="opengrep",
            rule_id="fixture.rule",
            severity="high",
            file_path=f"src/{control}escape.py",
            message="fixture",
            fingerprint="f" * 64,
        )


@pytest.mark.parametrize("prefix", ["\t" + "😀" * 50, "é" * 100 + "😀" * 30, "x" * 200])
def test_long_line_window_retains_utf16_offender_and_exact_origin(prefix: str) -> None:
    source_line = prefix + "eval(value)" + " tail" * 200
    # Exercise the real producer normalization, including code-point to UTF-16.
    _, start_column, _, end_column = complete_source_location(
        SourceDocument.from_text(source_line), 1, len(prefix) + 1,
        1, len(prefix) + 5, "unicodeCodePoints",
    )
    bounded, metadata, truncated = _bound_snippet(
        source_line, max_bytes=64, finding_start_line=1, finding_end_line=1,
        start_column=start_column, metadata={"snippet_start_line": 1},
    )
    assert truncated is True
    assert bounded.startswith("eval(value)")
    assert metadata["snippet_column_start"] == start_column
    assert metadata["snippet_line_truncated"] is True
    assert len(canonical_json_bytes(bounded)) <= 64
    assert source_line.encode("utf-16-le")[(start_column - 1) * 2:(end_column - 1) * 2].decode("utf-16-le") == "eval"


def test_rebounded_window_preserves_an_existing_nonzero_utf16_origin() -> None:
    prefix = "😀" * 30 + "\t"
    origin = 900
    start_column = origin + len(prefix.encode("utf-16-le")) // 2
    bounded, metadata, truncated = _bound_snippet(
        prefix + "eval(value)" + " tail" * 200, max_bytes=64,
        finding_start_line=20, finding_end_line=20, start_column=start_column,
        metadata={"snippet_start_line": 20, "snippet_line_truncated": True, "snippet_column_start": origin},
    )
    assert truncated is True
    assert bounded.startswith("eval(value)")
    assert metadata["snippet_start_line"] == 20
    assert metadata["snippet_column_start"] == start_column
    assert len(canonical_json_bytes(bounded)) <= 64


def test_long_line_with_small_unicode_prefix_retains_context_and_column_one() -> None:
    source = "\t😀eval(value)" + " tail" * 200
    bounded, metadata, truncated = _bound_snippet(
        source, max_bytes=64, finding_start_line=7, finding_end_line=7,
        start_column=4, metadata={"snippet_start_line": 7},
    )
    assert truncated is True
    assert bounded.startswith("\t😀eval(value)")
    assert metadata["snippet_column_start"] == 1
    assert len(canonical_json_bytes(bounded)) <= 64


def test_wire_bounded_finding_keeps_unicode_offender_after_serialization() -> None:
    prefix = "\t" + "😀" * 5000
    source = prefix + "eval(value)" + " tail" * 5000
    _, start_column, _, end_column = complete_source_location(
        SourceDocument.from_text(source), 1, len(prefix) + 1,
        1, len(prefix) + 5, "unicodeCodePoints",
    )
    finding = Finding(
        scanner="opengrep", rule_id="fixture.eval", severity="high",
        file_path="src/emoji.ts", start_line=1, end_line=1,
        start_column=start_column, end_column=end_column, message="fixture",
        code_snippet=source, fingerprint="f" * 64,
        metadata={"snippet_start_line": 1},
    )
    retained = Finding.model_validate_json(finding.model_dump_json())
    assert retained.code_snippet.startswith("eval(value)")
    assert retained.start_column == 10_002
    assert retained.end_column == 10_006
    assert retained.metadata["snippet_column_start"] == 10_002
    assert retained.metadata["snippet_truncated"] is True
    assert len(canonical_json_bytes(retained.code_snippet)) <= FINDING_SNIPPET_MAX_JSON_BYTES
