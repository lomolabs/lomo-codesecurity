"""Source witnesses for the pinned Gitleaks producer's undeclared columns."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable
from typing import Any

from .source_io import SourceDocument, SourceEvidenceError, complete_source_location


SourceRange = tuple[int, int, int, int]
WitnessKey = tuple[str, str, int, int, int, int]


def _coordinates(region: dict[str, Any]) -> SourceRange | None:
    values = tuple(region.get(name) for name in
                   ("startLine", "startColumn", "endLine", "endColumn"))
    if any(type(value) is not int or value < 1 for value in values):
        return None
    return values  # type: ignore[return-value]


def _encoding(properties: object) -> str | None:
    if not isinstance(properties, dict):
        return None
    tags = properties.get("tags")
    if tags is None:
        tags = []
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        return None
    decoder_tags = {tag for tag in tags if tag.startswith(("decoded:", "decode-depth:"))}
    if not decoder_tags:
        return "plain"
    if decoder_tags == {"decoded:base64", "decode-depth:1"}:
        return "base64"
    return None


def _source_range(source: SourceDocument, text: str, raw: SourceRange) -> SourceRange | None:
    """Prove a whole-match span, without guessing a fragment's column origin.

    The SARIF snippet is Secret, which can be shorter than Match. Such a capture
    group is not a whole-match witness. Native fragments reset columns, so a
    fragment's first line uses a different byte origin from subsequent LF lines.
    Exact unique text must agree with both endpoints under one convention.
    """
    if not text:
        return None
    start = source.text.find(text)
    if start < 0 or source.text.find(text, start + 1) >= 0:
        return None
    end = start + len(text)
    native_first = source.text.count("\n", 0, start) + 1
    native_last = source.text.count("\n", 0, end) + 1
    if (raw[0], raw[2]) != (native_first, native_last):
        return None
    start_prefix = source.text[source.text.rfind("\n", 0, start) + 1:start]
    end_prefix = source.text[source.text.rfind("\n", 0, end) + 1:end]
    start_bytes, end_bytes = len(start_prefix.encode()), len(end_prefix.encode())
    # A mid-line fragment boundary is deliberately not inferred. Its offsets
    # cannot establish this whole-source span; ordinary admission still applies.
    origins = (0,) if native_first == 1 else (0, 1)
    if not any((raw[1], raw[3]) == (
        start_bytes + 1 + origin,
        end_bytes + (origin if native_first == native_last else 1),
    ) for origin in origins):
        return None
    first = bisect_right(source.line_starts, start) - 1
    last = bisect_right(source.line_starts, end) - 1
    result = (
        first + 1,
        len(source.text[source.line_starts[first]:start].encode("utf-16-le")) // 2 + 1,
        last + 1,
        len(source.text[source.line_starts[last]:end].encode("utf-16-le")) // 2 + 1,
    )
    complete_source_location(source, *result, "utf16CodeUnits")
    return result


class GitleaksSourceRanges:
    """Run-local witnesses; no source documents or secrets are copied per result.

    A decoded result may share its exact file/rule/native-range witness with an
    unencoded result in the same run. The decoded secret itself is never treated
    as literal source. Only the current reader document is retained; switching
    documents invalidates cached proofs, including a reread of a changed file.
    """

    def __init__(self, results: list[Any], normalize: Callable[[object], str],
                 checkpoint: Callable[[], None]) -> None:
        self._checkpoint = checkpoint
        self._witnesses: dict[WitnessKey, set[str]] = {}
        self._source: SourceDocument | None = None
        self._ranges: dict[WitnessKey, set[SourceRange]] = {}
        for result in results:
            checkpoint()
            if not isinstance(result, dict) or _encoding(result.get("properties") or {}) != "plain":
                continue
            locations = result.get("locations")
            if not isinstance(locations, list) or len(locations) != 1 or not isinstance(locations[0], dict):
                continue
            physical = locations[0].get("physicalLocation")
            if not isinstance(physical, dict):
                continue
            artifact, region = physical.get("artifactLocation"), physical.get("region")
            if not isinstance(artifact, dict) or not isinstance(region, dict):
                continue
            path, raw = normalize(artifact.get("uri")), _coordinates(region)
            snippet = region.get("snippet")
            text = snippet.get("text") if isinstance(snippet, dict) else None
            rule = result.get("ruleId")
            if path and raw and isinstance(rule, str) and rule and isinstance(text, str) and text:
                self._witnesses.setdefault((path, rule, *raw), set()).add(text)

    def resolve(self, path: str, rule: str, region: dict[str, Any], properties: dict[str, Any],
                source: SourceDocument) -> SourceRange | None:
        raw, encoding = _coordinates(region), _encoding(properties)
        snippet = region.get("snippet")
        text = snippet.get("text") if isinstance(snippet, dict) else None
        if raw is None or encoding is None or not isinstance(text, str) or not text:
            return None
        if self._source is not source:
            self._source, self._ranges = source, {}
        key = (path, rule, *raw)
        if key not in self._ranges:
            ranges = set()
            for witness_text in self._witnesses.get(key, ()):
                self._checkpoint()
                candidate = _source_range(source, witness_text, raw)
                if candidate is not None:
                    ranges.add(candidate)
            self._ranges[key] = ranges
        ranges = self._ranges[key]
        if len(ranges) > 1:
            raise SourceEvidenceError("ambiguous_gitleaks_source_range")
        if len(ranges) != 1:
            return None
        result = next(iter(ranges))
        if encoding == "plain":
            self._checkpoint()
            if _source_range(source, text, raw) != result:
                return None
        return result
