from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from kodesec_scanner import external
from kodesec_scanner.gitleaks_locations import GitleaksSourceRanges, _source_range
from kodesec_scanner.source_io import SourceDocument, SourceEvidenceError


def record(text: str, coordinates: tuple[int, int, int, int], *, path: str = "source.txt",
           rule: str = "fixture", tags: list[str] | None = None) -> dict:
    return {"ruleId": rule, "message": {"text": "inert test finding"},
            "properties": {"tags": tags}, "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path}, "region": {
                    **dict(zip(("startLine", "startColumn", "endLine", "endColumn"), coordinates)),
                    "snippet": {"text": text},
                }}}]}


def region(item: dict) -> dict:
    return item["locations"][0]["physicalLocation"]["region"]


def resolve(items: list[dict], item: dict, source: SourceDocument):
    ranges = GitleaksSourceRanges(items, lambda path: str(path), lambda: None)
    return ranges.resolve(item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                          item["ruleId"], region(item), item["properties"], source)


@pytest.mark.parametrize(("source", "secret", "raw", "expected"), [
    ("abc token\n", "token", (1, 5, 1, 9), (1, 5, 1, 10)),
    ("x😀secret\n", "secret", (1, 6, 1, 11), (1, 4, 1, 10)),
    ("header\n\t😀 token\n", "token", (2, 8, 2, 12), (2, 5, 2, 10)),
    ("header\r\n\t😀 token\r\n", "token", (2, 8, 2, 12), (2, 5, 2, 10)),
    ("header\r\t😀 token\n", "token", (1, 14, 1, 18), (2, 5, 2, 10)),
    ("header\n\t😀 token", "token", (2, 8, 2, 12), (2, 5, 2, 10)),
    ("token", "token", (1, 1, 1, 5), (1, 1, 1, 6)),
    ("x😀BEGIN\nbody😀\nEND\n", "BEGIN\nbody😀\nEND", (1, 6, 3, 4), (1, 4, 3, 4)),
    # The first line of a later native fragment can have absolute line > 1.
    ("a" * 100_000 + "\n😀token\n", "token", (2, 5, 2, 9), (2, 3, 2, 8)),
])
def test_exact_unique_source_span_normalizes_native_bytes(source, secret, raw, expected):
    assert _source_range(SourceDocument.from_text(source), secret, raw) == expected


@pytest.mark.parametrize(("source", "secret", "raw"), [
    ("token token\n", "token", (1, 1, 1, 5)),
    ("x😀secret\n", "absent", (1, 6, 1, 11)),
    ("x😀secret\n", "secret", (1, 5, 1, 11)),
    ("x😀secret\n", "secret", (1, 6, 1, 12)),
    ("x😀secret\n", "secret", (2, 6, 2, 11)),
    ("x😀secret\n", "secret", (1, 2, 1, 7)),
    # Mid-line fragment offsets cannot be inferred from a whole-source line.
    ("a" * 125_000 + "😀secret\n", "secret", (1, 5, 1, 10)),
    # Secret is a capture group; native Match includes the assignment prefix.
    ("key=token\n", "token", (1, 1, 1, 9)),
])
def test_missing_or_mismatched_whole_match_is_not_a_witness(source, secret, raw):
    assert _source_range(SourceDocument.from_text(source), secret, raw) is None


def test_decoded_sibling_uses_only_same_run_file_rule_and_raw_range():
    source = SourceDocument.from_text("x😀encoded\n")
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded-value-absent-from-source", (1, 6, 1, 12),
                     tags=["decoded:base64", "decode-depth:1"])
    assert resolve([decoded, plain], decoded, source) == (1, 4, 1, 11)
    assert resolve([plain, decoded], decoded, source) == (1, 4, 1, 11)
    assert resolve([decoded], decoded, source) is None
    for key, value in (("path", "other.txt"), ("rule", "other")):
        other = record("encoded", (1, 6, 1, 12), **{key: value})
        assert resolve([other, decoded], decoded, source) is None
    shifted = record("encoded", (1, 7, 1, 12))
    assert resolve([shifted, decoded], decoded, source) is None


def test_plain_record_cannot_borrow_another_plain_records_snippet():
    plain = record("encoded", (1, 6, 1, 12))
    absent = record("absent", (1, 6, 1, 12))
    source = SourceDocument.from_text("x😀encoded\n")
    assert resolve([plain, absent], absent, source) is None
    assert resolve([absent, plain], absent, source) is None
    assert resolve([plain, absent], plain, source) == (1, 4, 1, 11)


@pytest.mark.parametrize("tags", [["decoded:hex", "decode-depth:1"],
                                 ["decoded:base64", "decode-depth:2"],
                                 ["decoded:base64"], ["decode-depth:1"], [False], 0])
def test_unknown_or_malformed_decoder_never_borrows_a_witness(tags):
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded", (1, 6, 1, 12), tags=tags)
    assert resolve([plain, decoded], decoded, SourceDocument.from_text("x😀encoded\n")) is None


@pytest.mark.parametrize("field", ["startLine", "startColumn", "endLine", "endColumn"])
@pytest.mark.parametrize("value", [True, False, 0, -1, None, "1", 1.5])
def test_invalid_native_coordinate_cannot_create_a_witness(field, value):
    item = record("encoded", (1, 6, 1, 12))
    region(item)[field] = value
    assert resolve([item], item, SourceDocument.from_text("x😀encoded\n")) is None


@pytest.mark.parametrize("snippet", [None, {}, {"text": None}, {"text": ""}, {"text": 1}])
def test_missing_or_malformed_snippet_cannot_borrow_a_witness(snippet):
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded", (1, 6, 1, 12), tags=["decoded:base64", "decode-depth:1"])
    region(decoded)["snippet"] = snippet
    assert resolve([plain, decoded], decoded, SourceDocument.from_text("x😀encoded\n")) is None


def test_conflicting_witnesses_do_not_choose_a_range():
    source = SourceDocument.from_text("header\nabc\n")
    items = [record("ab", (2, 2, 2, 3)), record("bc", (2, 2, 2, 3))]
    with pytest.raises(SourceEvidenceError, match="ambiguous_gitleaks_source_range"):
        resolve(items, items[0], source)


def test_cached_witness_is_revalidated_when_source_reader_changes_document():
    item = record("encoded", (1, 6, 1, 12))
    ranges = GitleaksSourceRanges([item], str, lambda: None)
    assert ranges.resolve("source.txt", "fixture", region(item), item["properties"],
                          SourceDocument.from_text("x😀encoded\n")) == (1, 4, 1, 11)
    assert ranges.resolve("source.txt", "fixture", region(item), item["properties"],
                          SourceDocument.from_text("x😀changed\n")) is None


@pytest.mark.parametrize("reverse", [False, True])
def test_parser_preserves_decoded_identity_through_publication(tmp_path: Path, reverse: bool):
    source = tmp_path / "source.txt"
    source.write_text("x😀encoded\n", encoding="utf-8")
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded", (1, 6, 1, 12), tags=["decoded:base64", "decode-depth:1"])
    other_decoded = record("another decoded value", (1, 6, 1, 12), tags=["decoded:base64", "decode-depth:1"])
    records = [decoded, plain, other_decoded, copy.deepcopy(decoded), copy.deepcopy(plain)]
    if reverse:
        records.reverse()
    run = {"tool": {"driver": {"name": "gitleaks", "semanticVersion": "v8.0.0"}},
           "results": records}
    path = tmp_path / "output.sarif"
    path.write_text(json.dumps({"runs": [run]}))
    with external.SourceTextReader(tmp_path, 1_048_576) as reader:
        parsed = external._parse_sarif_document_with_reader({"runs": [run]}, "gitleaks", tmp_path, reader)
    assert (parsed.integrity.total_records, parsed.integrity.accepted_records,
            parsed.integrity.dropped_records) == (5, 5, 0)
    assert len(parsed.findings) == 5
    assert {item.metadata["source_location_basis"] for item in parsed.findings} == {"gitleaks-exact-source"}
    published = external.parse_sarif(path, "gitleaks", tmp_path)
    assert len(published) == len({item.fingerprint for item in published}) == 3
    ordinary, = [item for item in published if "native_decode_tags" not in item.metadata]
    transformed = [item for item in published if "native_decode_tags" in item.metadata]
    assert len(transformed) == 2
    for item in transformed:
        assert item.metadata["native_decode_tags"] == ["decoded:base64", "decode-depth:1"]
        assert item.code_snippet == ordinary.code_snippet
        assert "decoded_match_identity" not in item.metadata
    from kodesec_scanner.main import _canonicalize_findings
    assert _canonicalize_findings(published) == _canonicalize_findings(list(reversed(published)))
    assert len(_canonicalize_findings(published)) == 3
    explicit = copy.deepcopy(plain)
    region(explicit).update(startColumn=4, endColumn=11)
    run.update(columnKind="utf16CodeUnits", results=[explicit])
    path.write_text(json.dumps({"runs": [run]}))
    expected, = external.parse_sarif(path, "gitleaks", tmp_path)
    assert ordinary.fingerprint == expected.fingerprint
    assert all(item.fingerprint != expected.fingerprint for item in transformed)


def test_decoded_identity_does_not_hide_conflicting_evidence(tmp_path: Path):
    (tmp_path / "source.txt").write_text("x😀encoded\n", encoding="utf-8")
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded", (1, 6, 1, 12), tags=["decoded:base64", "decode-depth:1"])
    conflict = copy.deepcopy(decoded)
    conflict["level"] = "error"
    path = tmp_path / "output.sarif"
    path.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "gitleaks"}},
                                        "results": [plain, decoded, conflict]}]}))
    with pytest.raises(RuntimeError, match="finding_fingerprint_collision"):
        external.parse_sarif(path, "gitleaks", tmp_path)


@pytest.mark.parametrize("change", ["other-scanner", "explicit-null", "explicit-invalid", "other-run"])
def test_source_witness_does_not_relax_other_sarif_or_cross_run_evidence(tmp_path: Path, change: str):
    (tmp_path / "source.txt").write_text("x😀encoded\n", encoding="utf-8")
    plain = record("encoded", (1, 6, 1, 12))
    decoded = record("decoded", (1, 6, 1, 12), tags=["decoded:base64", "decode-depth:1"])
    run = {"tool": {"driver": {"name": "gitleaks"}}, "results": [decoded, plain]}
    runs = [run]
    if change == "explicit-null": run["columnKind"] = None
    if change == "explicit-invalid": run["columnKind"] = "bytes"
    if change == "other-run":
        runs = [{**run, "results": [decoded]}, {**run, "results": [plain]}]
    path = tmp_path / "output.sarif"
    path.write_text(json.dumps({"runs": runs}))
    with pytest.raises(external.NativeParseIntegrityError):
        external.parse_sarif(path, "fixture" if change == "other-scanner" else "gitleaks", tmp_path)
