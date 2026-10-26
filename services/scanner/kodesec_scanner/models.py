from datetime import datetime
import json
import math
import posixpath
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ToolId = Annotated[str, Field(min_length=1, max_length=64)]
SHA256_PATTERN = r"^[0-9a-f]{64}$"
RUN_RESULT_MAX_FINDINGS = 50_000
RUN_RESULT_MAX_ITEM_BYTES = 32 * 1024
RUN_RESULT_MAX_PAGE_BYTES = 4 * 1024 * 1024
RUN_RESULT_PAGE_ENVELOPE_BYTES = 16 * 1024
RUN_RESULT_PAGE_LIMIT = 128
RUN_RESULT_MAX_SUMMARY_BYTES = 256 * 1024
MAX_DATABASE_INTEGER = 2_147_483_647
FINDING_SCANNER_MAX_BYTES = 80
FINDING_RULE_MAX_BYTES = 160
FINDING_PATH_MAX_BYTES = 4096
FINDING_MESSAGE_MAX_JSON_BYTES = 4 * 1024
FINDING_SNIPPET_MAX_JSON_BYTES = 16 * 1024
FINDING_METADATA_MAX_BYTES = 4 * 1024


class StrictWireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise ValueError("value is not canonical UTF-8 JSON") from exc


def _validate_bounded_text(value: str, *, name: str, max_bytes: int) -> str:
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{name} must be non-empty canonical text")
    try:
        encoded_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} is not valid UTF-8 text") from exc
    if encoded_size > max_bytes:
        raise ValueError(f"{name} exceeds its encoded byte limit")
    return value


def _validate_scan_target_path(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
            for character in value
        )
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or posixpath.normpath(value) != value
    ):
        raise ValueError("target_path must be a canonical project-relative POSIX path")
    try:
        encoded_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("target_path is not valid UTF-8 text") from exc
    if encoded_size > FINDING_PATH_MAX_BYTES:
        raise ValueError("target_path exceeds its encoded byte limit")
    return value


def _truncate_json_string(value: str, max_bytes: int) -> tuple[str, bool]:
    if len(canonical_json_bytes(value)) <= max_bytes:
        return value, False
    low = 0
    high = len(value)
    while low < high:
        midpoint = (low + high + 1) // 2
        if len(canonical_json_bytes(value[:midpoint])) <= max_bytes:
            low = midpoint
        else:
            high = midpoint - 1
    return value[:low], True


def _without_final_line_ending(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith(("\n", "\r")):
        return value[:-1]
    return value


def _utf16_window_index(value: str, column_offset: int) -> tuple[int, int]:
    """Map a UTF-16 offset to a whole Python character and its exact offset.

    A coordinate inside a surrogate pair retains that character rather than
    slicing it away. Tabs are one source code unit, not expanded screen cells.
    """
    if value.isascii():
        offset = min(column_offset, len(value))
        return offset, offset
    units = 0
    index = 0
    for character in value:
        width = 2 if ord(character) > 0xFFFF else 1
        if units + width > column_offset:
            break
        units += width
        index += 1
    return index, units


def _bound_snippet(
    value: str,
    *,
    max_bytes: int,
    finding_start_line: int | None,
    finding_end_line: int | None,
    start_column: int | None,
    metadata: dict[str, Any],
) -> tuple[str, dict[str, Any], bool]:
    if len(canonical_json_bytes(value)) <= max_bytes:
        return value, metadata, False

    lines = value.splitlines(keepends=True)
    snippet_start = metadata.get("snippet_start_line")
    if (
        not lines
        or not isinstance(snippet_start, int)
        or isinstance(snippet_start, bool)
        or snippet_start < 1
        or finding_start_line is None
    ):
        bounded, _ = _truncate_json_string(value, max_bytes)
        return bounded, metadata, True

    offender_start = finding_start_line - snippet_start
    offender_end = (finding_end_line or finding_start_line) - snippet_start
    if not 0 <= offender_start < len(lines):
        bounded, _ = _truncate_json_string(value, max_bytes)
        return bounded, metadata, True
    offender_end = min(max(offender_end, offender_start), len(lines) - 1)
    selected_start = 0
    selected_end = len(lines) - 1

    def render(start: int, end: int) -> str:
        return _without_final_line_ending("".join(lines[start : end + 1]))

    while len(canonical_json_bytes(render(selected_start, selected_end))) > max_bytes and (
        selected_start < offender_start or selected_end > offender_end
    ):
        before = offender_start - selected_start
        after = selected_end - offender_end
        if before > after:
            selected_start += 1
        elif after > before:
            selected_end -= 1
        elif len(lines[selected_start]) >= len(lines[selected_end]):
            selected_start += 1
        else:
            selected_end -= 1

    bounded = render(selected_start, selected_end)
    bounded_metadata = dict(metadata)
    bounded_metadata["snippet_start_line"] = snippet_start + selected_start
    if len(canonical_json_bytes(bounded)) <= max_bytes:
        return bounded, bounded_metadata, True

    # The offending line/span itself exceeds the wire budget. Preserve the
    # offending start line and a column-centered window when precise columns
    # exist. The receipt keeps its source-column origin explicit.
    source_line = _without_final_line_ending(lines[offender_start])
    # Source locations have already been normalized to UTF-16. Python string
    # indices count code points, so using the source column as an index skips
    # characters after astral Unicode. Preserve any earlier captured origin.
    recorded_origin = metadata.get("snippet_column_start")
    source_origin = (
        recorded_origin
        if offender_start == 0
        and metadata.get("snippet_line_truncated") is True
        and isinstance(recorded_origin, int)
        and not isinstance(recorded_origin, bool)
        and recorded_origin > 0
        else 1
    )
    column_offset = max((start_column or source_origin) - source_origin, 0)
    offender_index, offender_units = _utf16_window_index(source_line, column_offset)
    prefix = source_line[:offender_index]
    if len(canonical_json_bytes(prefix)) >= max_bytes:
        selected_index = offender_index
        selected_units = offender_units
    else:
        selected_index = 0
        selected_units = 0
    bounded, _ = _truncate_json_string(source_line[selected_index:], max_bytes)
    bounded_metadata["snippet_start_line"] = finding_start_line
    bounded_metadata["snippet_line_truncated"] = True
    bounded_metadata["snippet_column_start"] = source_origin + selected_units
    return bounded, bounded_metadata, True


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise ValueError("metadata exceeds its nesting limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("metadata contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise ValueError("metadata keys must be non-empty strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("metadata contains a non-JSON value")


class ScanRequest(StrictWireModel):
    scan_id: int = Field(gt=0, le=MAX_DATABASE_INTEGER)
    repo_path: str = Field(min_length=1, max_length=4096)
    target_path: str | None = Field(default=None, min_length=1, max_length=4096)
    target_kind: Literal["file", "directory"] | None = None
    source_snapshot_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    mode: Literal["full", "incremental_diff"] = "full"
    base_ref: str | None = Field(default=None, max_length=255)
    head_ref: str | None = Field(default=None, max_length=255)
    enabled_tools: list[ToolId] = Field(min_length=1, max_length=32)

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str | None) -> str | None:
        return _validate_scan_target_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_target_mode(self) -> "ScanRequest":
        if (self.target_path is None) != (self.target_kind is None):
            raise ValueError("a selected source target requires both target_path and target_kind")
        if self.target_path is not None and self.mode != "full":
            raise ValueError("a selected source target requires mode=full")
        return self


class RunStartRequest(ScanRequest):
    # FastAPI supplies JSON bodies as decoded Python values before validation;
    # allow the standard UUID string representation at this one wire field.
    run_id: UUID = Field(strict=False)


class Finding(StrictWireModel):
    scanner: str = "unknown"
    rule_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    file_path: str
    start_line: int | None = Field(default=None, ge=1, le=MAX_DATABASE_INTEGER)
    start_column: int | None = Field(default=None, ge=1, le=MAX_DATABASE_INTEGER)
    end_line: int | None = Field(default=None, ge=1, le=MAX_DATABASE_INTEGER)
    end_column: int | None = Field(default=None, ge=1, le=MAX_DATABASE_INTEGER)
    message: str
    code_snippet: str | None = None
    fingerprint: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scanner")
    @classmethod
    def validate_scanner(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            name="scanner",
            max_bytes=FINDING_SCANNER_MAX_BYTES,
        )

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            name="rule_id",
            max_bytes=FINDING_RULE_MAX_BYTES,
        )

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, value: str) -> str:
        if (
            not value
            or value.startswith("/")
            or "\\" in value
            or "\x00" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or ".." in value.split("/")
            or posixpath.normpath(value) != value
            or value == "."
        ):
            raise ValueError("file_path must be a canonical project-relative POSIX path")
        try:
            encoded_size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("file_path is not valid UTF-8 text") from exc
        if encoded_size > FINDING_PATH_MAX_BYTES:
            raise ValueError("file_path exceeds its encoded byte limit")
        return value

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("fingerprint must be a lowercase SHA-256 digest")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value)
        if len(canonical_json_bytes(value)) > FINDING_METADATA_MAX_BYTES:
            raise ValueError("metadata exceeds its canonical byte limit")
        return value

    @model_validator(mode="after")
    def validate_normalized_location(self) -> "Finding":
        if self.start_line is None:
            if any(
                value is not None
                for value in (self.end_line, self.start_column, self.end_column)
            ):
                raise ValueError("location coordinates require a start line")
            return self._bound_evidence()
        if self.end_line is None:
            raise ValueError("a location start line requires an end line")
        if self.end_line < self.start_line:
            raise ValueError("location end line must not precede its start line")
        if self.start_column is None and self.end_column is not None:
            raise ValueError("an end column requires a start column")
        if (
            self.start_column is not None
            and self.end_column is not None
            and self.start_line == self.end_line
            and self.end_column < self.start_column
        ):
            raise ValueError("same-line end column must not precede start")
        return self._bound_evidence()

    def _bound_evidence(self) -> "Finding":
        if not self.message:
            raise ValueError("message must be non-empty")
        message, message_truncated = _truncate_json_string(
            self.message,
            FINDING_MESSAGE_MAX_JSON_BYTES,
        )
        snippet = self.code_snippet
        snippet_truncated = False
        metadata = dict(self.metadata)
        if snippet is not None:
            snippet, metadata, snippet_truncated = _bound_snippet(
                snippet,
                max_bytes=FINDING_SNIPPET_MAX_JSON_BYTES,
                finding_start_line=self.start_line,
                finding_end_line=self.end_line,
                start_column=self.start_column,
                metadata=metadata,
            )
        if message_truncated:
            metadata["message_truncated"] = True
        if snippet_truncated:
            metadata["snippet_truncated"] = True
        _validate_json_value(metadata)
        if len(canonical_json_bytes(metadata)) > FINDING_METADATA_MAX_BYTES:
            raise ValueError("metadata cannot record required evidence truncation within its byte limit")
        self.message = message
        self.code_snippet = snippet
        self.metadata = metadata
        if len(canonical_json_bytes(self.model_dump(mode="json"))) + 1 > RUN_RESULT_MAX_ITEM_BYTES:
            raise ValueError("finding exceeds its canonical transport byte limit")
        return self


class ScanArtifact(StrictWireModel):
    scanner: Literal["syft"]
    artifact_type: Literal["sbom"]
    format: Literal["cyclonedx-json"]
    path: str
    size_bytes: int = Field(ge=0, le=8 * 1024 * 1024)
    sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("path")
    @classmethod
    def validate_artifact_path(cls, value: str) -> str:
        try:
            encoded_size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("artifact path is not valid UTF-8 text") from exc
        path_parts = value.split("/")
        if (
            not value.startswith("/")
            or value == "/"
            or "\\" in value
            or "\x00" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(part in {"", ".", ".."} for part in path_parts[1:])
            or posixpath.normpath(value) != value
            or encoded_size > 4096
        ):
            raise ValueError("artifact path must be a canonical absolute POSIX path")
        return value


class ScanResponse(StrictWireModel):
    status: Literal["completed", "partial", "failed"]
    findings: list[Finding] = Field(max_length=RUN_RESULT_MAX_FINDINGS)
    artifacts: list[ScanArtifact] = Field(default_factory=list, max_length=128)
    summary: dict[str, Any]

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value)
        if len(canonical_json_bytes(value)) > RUN_RESULT_MAX_SUMMARY_BYTES:
            raise ValueError("summary exceeds its canonical byte limit")
        return value

    @model_validator(mode="after")
    def validate_summary_total(self) -> "ScanResponse":
        if self.summary.get("findings_total") != len(self.findings):
            raise ValueError("summary findings_total does not match the finding collection")
        return self


class RunResultManifest(StrictWireModel):
    schema_version: Literal[1] = 1
    status: Literal["completed", "partial"]
    result_digest: str = Field(pattern=SHA256_PATTERN)
    findings_digest: str = Field(pattern=SHA256_PATTERN)
    findings_total: int = Field(ge=0, le=RUN_RESULT_MAX_FINDINGS)
    findings_bytes: int = Field(ge=0, le=336 * 1024 * 1024)
    page_count: int = Field(ge=0, le=RUN_RESULT_MAX_FINDINGS)
    page_limit: Literal[RUN_RESULT_PAGE_LIMIT] = RUN_RESULT_PAGE_LIMIT
    summary: dict[str, Any]
    artifacts: list[ScanArtifact] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def validate_manifest_counts(self) -> "RunResultManifest":
        _validate_json_value(self.summary)
        if len(canonical_json_bytes(self.summary)) > RUN_RESULT_MAX_SUMMARY_BYTES:
            raise ValueError("summary exceeds its canonical byte limit")
        if self.summary.get("findings_total") != self.findings_total:
            raise ValueError("summary findings_total does not match the manifest")
        minimum_pages = (
            (self.findings_total + self.page_limit - 1) // self.page_limit
            if self.findings_total
            else 0
        )
        if not minimum_pages <= self.page_count <= self.findings_total:
            raise ValueError("page_count is inconsistent with findings_total and page_limit")
        return self


class RunStateResponse(StrictWireModel):
    run_id: UUID
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["queued", "running", "cancelling", "completed", "failed", "cancelled"]
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    deadline_at: datetime
    expires_at: datetime | None = None
    error_code: str | None = None
    error_detail: str | None = None
    result_manifest: RunResultManifest | None = None
    result_available: bool = False

    @model_validator(mode="after")
    def validate_result_state(self) -> "RunStateResponse":
        if self.status != "completed" and (self.result_manifest is not None or self.result_available):
            raise ValueError("only completed runs can expose a result manifest")
        if self.result_available and self.result_manifest is None:
            raise ValueError("available results require an immutable manifest")
        return self


class RunListResponse(StrictWireModel):
    runs: list[RunStateResponse]


class RunFindingPageRequest(StrictWireModel):
    request_digest: str = Field(pattern=SHA256_PATTERN)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    limit: int = Field(default=RUN_RESULT_PAGE_LIMIT, ge=1, le=RUN_RESULT_PAGE_LIMIT)


class RunFindingPageResponse(StrictWireModel):
    schema_version: Literal[1] = 1
    run_id: UUID
    request_digest: str = Field(pattern=SHA256_PATTERN)
    result_digest: str = Field(pattern=SHA256_PATTERN)
    findings_total: int = Field(ge=0, le=RUN_RESULT_MAX_FINDINGS)
    start_ordinal: int = Field(ge=1)
    items: list[Finding] = Field(min_length=1, max_length=RUN_RESULT_PAGE_LIMIT)
    items_bytes: int = Field(ge=1, le=RUN_RESULT_MAX_PAGE_BYTES - RUN_RESULT_PAGE_ENVELOPE_BYTES)
    page_digest: str = Field(pattern=SHA256_PATTERN)
    truncated: bool
    next_cursor: str | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def validate_page_shape(self) -> "RunFindingPageResponse":
        if self.start_ordinal + len(self.items) - 1 > self.findings_total:
            raise ValueError("finding page exceeds the manifest total")
        if self.truncated != (self.next_cursor is not None):
            raise ValueError("truncated and next_cursor must describe the same page state")
        if self.truncated != (self.start_ordinal + len(self.items) - 1 < self.findings_total):
            raise ValueError("page continuation does not match its ordinal range")
        encoded_items = b"".join(
            canonical_json_bytes(item.model_dump(mode="json")) + b"\n"
            for item in self.items
        )
        if len(encoded_items) != self.items_bytes:
            raise ValueError("items_bytes does not match the canonical page body")
        import hashlib

        if hashlib.sha256(encoded_items).hexdigest() != self.page_digest:
            raise ValueError("page_digest does not match the canonical page body")
        if len(canonical_json_bytes(self.model_dump(mode="json"))) > RUN_RESULT_MAX_PAGE_BYTES:
            raise ValueError("finding page exceeds the encoded response limit")
        return self


class RunResultAckRequest(StrictWireModel):
    request_digest: str = Field(pattern=SHA256_PATTERN)
    result_digest: str = Field(pattern=SHA256_PATTERN)


class RunResultAckResponse(StrictWireModel):
    schema_version: Literal[1] = 1
    run_id: UUID
    request_digest: str = Field(pattern=SHA256_PATTERN)
    result_digest: str = Field(pattern=SHA256_PATTERN)
    acknowledged: bool = True
    result_available: Literal[False] = False
