from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unicodedata
from bisect import bisect_right
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from .models import Finding, ScanArtifact, canonical_json_bytes
from .gitleaks_locations import GitleaksSourceRanges
from .redaction import has_source_path_credentials, redact_json, redact_text
from .settings import get_settings
from .snippets import bounded_line_snippet
from .source_io import (
    SourceEvidenceError,
    SourceDocument,
    SourceTextReader,
    complete_source_location,
)
from .tools import (
    EXTERNAL_TOOL_VERSIONS,
    OPENGREP_EXECUTABLE_PATH,
    OPENGREP_RULE_ENTRYPOINT,
    external_tool_ids,
)


SEVERITY_MAP = {"error": "high", "warning": "medium", "note": "info", "none": "info"}
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
_TRIVY_MESSAGE_SEVERITY_LINE = re.compile(
    r"(?:\A|\r?\n)Severity: (CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)(?=\r?\n|\Z)"
)
_TRIVY_SECRET_MESSAGE_SEVERITY = re.compile(
    r"\AArtifact: [^\r\n]+ Type:  Secret [^\r\n]+ "
    r"Severity: (CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN) Match: [^\r\n]*\Z"
)
_TRIVY_MESSAGE_SEVERITIES: dict[str, FindingSeverity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}
SNIPPET_CONTEXT_LINES = 40
SNIPPET_MAX_CHARS = 20000
MAX_NATIVE_FINDINGS_BYTES = 64 * 1024 * 1024
MAX_PUBLISHABLE_SBOM_BYTES = 8 * 1024 * 1024
MAX_CAPTURED_COMMAND_BYTES = 8 * 1024 * 1024
MAX_OPENGREP_RULE_ENTRIES = 10_000
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]+\Z")
_CYCLONEDX_HASH_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}
_STABLE_SOURCE_NAME = "source"
_STABLE_SOURCE_BOM_REF = "urn:kodesec:source"
_STABLE_GENERATED_BOM_REF_PREFIX = "urn:kodesec:bom-ref:sha256:"
_BEARER_UNSUPPORTED_SOURCE_MESSAGE = (
    "The security report is not yet available for your application.\n"
    "Learn more about language support at "
    "https://docs.bearer.com/reference/supported-languages/"
)
_BEARER_UNSUPPORTED_SOURCE_REPORTS = frozenset(
    {
        f"\n{_BEARER_UNSUPPORTED_SOURCE_MESSAGE}\n",
        f"\r\n{_BEARER_UNSUPPORTED_SOURCE_MESSAGE.replace(chr(10), chr(13) + chr(10))}\r\n",
    }
)


def _trivy_message_severity(message: object) -> FindingSeverity | None:
    """Read Trivy's SARIF-only severity field from its structured message text."""
    if not isinstance(message, dict):
        return None
    text = message.get("text")
    if not isinstance(text, str):
        return None
    matched = _TRIVY_MESSAGE_SEVERITY_LINE.search(text)
    if matched is None:
        matched = _TRIVY_SECRET_MESSAGE_SEVERITY.fullmatch(text)
    if matched is None:
        return None
    return _TRIVY_MESSAGE_SEVERITIES[matched.group(1)]


_CYCLONEDX_UUID_BOM_REF = re.compile(
    r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_CYCLONEDX_UNORDERED_ARRAY_KEYS = frozenset(
    {
        "annotations",
        "authors",
        "components",
        "compositions",
        "copyright",
        "dependencies",
        "dependsOn",
        "externalReferences",
        "hashes",
        "licenses",
        "occurrences",
        "properties",
        "provides",
        "services",
        "tools",
        "vulnerabilities",
    }
)
_CYCLONEDX_REFERENCE_KEYS = frozenset({"bom-ref", "ref", "dependsOn", "provides"})


class RunCancelled(RuntimeError):
    """The owning scanner run requested cancellation."""


class RunDeadlineExceeded(TimeoutError):
    """The scanner-wide deadline expired independently of a tool timeout."""


class CapturedCommandOutputLimitError(RuntimeError):
    """A command exceeded its combined stdout/stderr capture bound."""

    def __init__(self, limit_bytes: int) -> None:
        super().__init__("command output exceeds the processing size limit")
        self.limit_bytes = limit_bytes


@dataclass(frozen=True)
class ExecutionControl:
    cancel_event: threading.Event
    deadline_monotonic: float
    termination_grace_seconds: float = 5.0

    @classmethod
    def with_timeout(cls, timeout_seconds: float, termination_grace_seconds: float = 5.0) -> "ExecutionControl":
        return cls(
            cancel_event=threading.Event(),
            deadline_monotonic=time.monotonic() + timeout_seconds,
            termination_grace_seconds=termination_grace_seconds,
        )

    def checkpoint(self) -> None:
        if self.cancel_event.is_set():
            raise RunCancelled("scanner run cancellation requested")
        if time.monotonic() >= self.deadline_monotonic:
            raise RunDeadlineExceeded("scanner run deadline exceeded")

    def remaining_seconds(self) -> float:
        return max(self.deadline_monotonic - time.monotonic(), 0.0)


@dataclass
class ToolRunResult:
    scanner: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[ScanArtifact] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    parse_integrity: dict[str, Any] | None = None


@dataclass
class NativeParseIntegrity:
    """Bounded, evidence-free accounting for one native result stream."""

    total_records: int = 0
    accepted_records: int = 0
    intentionally_filtered_records: int = 0
    dropped_records: int = 0
    dropped_reason_counts: dict[str, int] = field(default_factory=dict)
    filter_reason_counts: dict[str, int] = field(default_factory=dict)

    def accept(self) -> None:
        self.total_records += 1
        self.accepted_records += 1

    def drop(self, reason: str) -> None:
        self.total_records += 1
        self.dropped_records += 1
        self.dropped_reason_counts[reason] = self.dropped_reason_counts.get(reason, 0) + 1

    def filter(self, reason: str) -> None:
        self.total_records += 1
        self.intentionally_filtered_records += 1
        self.filter_reason_counts[reason] = self.filter_reason_counts.get(reason, 0) + 1

    def merge(self, other: "NativeParseIntegrity") -> None:
        self.total_records += other.total_records
        self.accepted_records += other.accepted_records
        self.intentionally_filtered_records += other.intentionally_filtered_records
        self.dropped_records += other.dropped_records
        for reason, count in other.dropped_reason_counts.items():
            self.dropped_reason_counts[reason] = self.dropped_reason_counts.get(reason, 0) + count
        for reason, count in other.filter_reason_counts.items():
            self.filter_reason_counts[reason] = self.filter_reason_counts.get(reason, 0) + count

    def as_dict(self) -> dict[str, Any]:
        return {
            "complete": self.dropped_records == 0,
            "total_records": self.total_records,
            "accepted_records": self.accepted_records,
            "intentionally_filtered_records": self.intentionally_filtered_records,
            "dropped_records": self.dropped_records,
            "dropped_reason_counts": dict(sorted(self.dropped_reason_counts.items())),
            "filter_reason_counts": dict(sorted(self.filter_reason_counts.items())),
        }


@dataclass
class NativeParseResult:
    findings: list[Finding]
    integrity: NativeParseIntegrity


class NativeParseIntegrityError(RuntimeError):
    def __init__(self, integrity: NativeParseIntegrity) -> None:
        super().__init__("native_output_integrity_failed")
        self.integrity = integrity


class NativeExitError(RuntimeError):
    """A native process returned an exit outside its documented scan contract."""


class BearerReportError(RuntimeError):
    """A fixed, source-free JSONV2 envelope or analysis failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# Bearer 2.1.0 ErrorDetection producers; only these constant prefixes are
# classified. Compact letters keep every category combination within 90 bytes:
# directory, dependency, framework, panic, SAST scan, legacy detector; u is
# an unmatched analysis error. No native suffix, path or count is retained.
_BEARER_ANALYSIS_ERROR_PREFIXES = (
    ("accept dir failed for detector ", "d"),
    ("classification dependencies error: ", "e"),
    ("classification frameworks error: ", "f"),
    ("skipping file: due to panic ", "p"),
    ("failed to scan file: ", "s"),
    ("failed to process file for detector ", "t"),
)


def _bearer_jsonv2_findings(payload: bytes) -> list[object]:
    """Admit the pinned same-scan completeness envelope before its findings.

    Bearer 2.1.0 SARIF omits FileFailedDetection and ErrorDetection. JSONV2
    carries them in ``errors`` alongside the same post-filtered findings.
    Native filenames, messages and extracts never become failure text.
    """
    invalid = "bearer_native_report_invalid"
    if len(payload) > MAX_NATIVE_FINDINGS_BYTES:
        raise BearerReportError(invalid)
    try:
        report = _strict_json_bytes(payload)
    except (NativeJSONDecodeError, RecursionError, ValueError):
        raise BearerReportError(invalid) from None
    if (
        not isinstance(report, dict)
        or set(report) - {"source", "version", "findings", "errors", "expected_findings"}
        or not {"source", "version", "findings", "errors"} <= set(report)
        or report["source"] != "Bearer"
        or report["version"] != EXTERNAL_TOOL_VERSIONS["bearer"]
        or ("expected_findings" in report and not isinstance(report["expected_findings"], list))
    ):
        raise BearerReportError(invalid)
    findings, errors = report["findings"], report["errors"]
    # Go's nil RawFindings slice encodes as null. A nil errors slice occurs
    # only on the no-files branch; ordinary supported scans initialize [].
    if errors is None and findings is None:
        errors = []
    if findings is None:
        findings = []
    if (
        not isinstance(findings, list) or len(findings) > 100_000
        or not isinstance(errors, list) or len(errors) > 100_000
    ):
        raise BearerReportError(invalid)
    if errors:
        categories: set[str] = set()
        analysis_categories: set[str] = set()
        for error in errors:
            if (
                not isinstance(error, dict)
                or set(error) != {"type", "filename", "error"}
                or any(not isinstance(error[key], str) for key in error)
            ):
                raise BearerReportError(invalid)
            if error["type"] == "file_error":
                categories.add({
                    "file processing time exceeded": "file_timeout",
                    "exceeded memory limit": "memory_limit",
                    "exited unexpectedly": "worker_failure",
                    "didn't start within expected time": "worker_failure",
                }.get(error["error"], "unknown"))
            elif error["type"] == "error":
                analysis_categories.add(next((
                    category for prefix, category in _BEARER_ANALYSIS_ERROR_PREFIXES
                    if error["error"].startswith(prefix)
                ), "u"))
            else:
                categories.add("unknown")
        if analysis_categories:
            categories.add(
                "analysis_error" if analysis_categories == {"u"}
                else f"aerr_{''.join(sorted(analysis_categories))}"
            )
        category = ",".join(sorted(categories))
        raise BearerReportError(f"bearer_analysis_incomplete:{category}")
    return findings


def _parse_bearer_jsonv2(payload: bytes, root: Path, control: ExecutionControl | None = None) -> NativeParseResult:
    """Normalize admitted JSONV2 through the shared source-evidence boundary."""
    check = control.checkpoint if control else (lambda: None)
    check()
    records = _bearer_jsonv2_findings(payload)
    check()
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    integrity = NativeParseIntegrity()
    for record in records:
        check()
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("id"), str) or not record["id"]
            or not isinstance(record.get("title"), str)
            or not isinstance(record.get("filename"), str)
            or not isinstance(record.get("severity"), str)
            or record["severity"] not in {"critical", "high", "medium", "low", "warning"}
            or not isinstance(record.get("sink"), dict)
            or not isinstance(record["sink"].get("column"), dict)
        ):
            integrity.drop("invalid_bearer_result")
            continue
        sink = record["sink"]
        # These are the exact locations used by upstream's SARIF formatter.
        # JSONV2 also preserves severity, which its SARIF formatter omits.
        # Keep source-derived snippets;
        # never consume full_filename, sink.content, snippet or code_extract.
        region = {
            "startLine": sink.get("start"), "endLine": sink.get("end"),
            "startColumn": sink["column"].get("start"),
            "endColumn": sink["column"].get("end"),
        }
        results.append({
            "ruleId": record["id"], "message": {"text": record["title"]},
            "properties": {"severity": "info" if record["severity"] == "warning" else record["severity"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": record["filename"]}, "region": region,
            }}],
        })
        rules[record["id"]] = {"id": record["id"], "name": record["id"]}
    with SourceTextReader(root, get_settings().max_file_bytes, checkpoint=check) as reader:
        parsed = _parse_sarif_document_with_reader({"runs": [{
            "tool": {"driver": {"rules": list(rules.values())}}, "results": results,
        }]}, "bearer", root, reader, control)
    integrity.merge(parsed.integrity)
    for finding in parsed.findings:
        check()
        finding.metadata["native"] = "bearer-jsonv2"
        finding.metadata.pop("sarif_level", None)
    return NativeParseResult(findings=parsed.findings, integrity=integrity)


class NativeJSONDecodeError(ValueError):
    """A native JSON document violated the strict, evidence-free decode policy."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NativeJSONDecodeError("duplicate_json_key")
        value[key] = item
    return value


def _reject_nonfinite_json_number(_value: str) -> Any:
    raise NativeJSONDecodeError("non_finite_json_number")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise NativeJSONDecodeError("non_finite_json_number")
    return parsed


def _strict_json_bytes(payload: bytes, control: ExecutionControl | None = None) -> Any:
    """Decode native JSON as strict UTF-8 with unambiguous object semantics."""

    if control is not None:
        control.checkpoint()
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NativeJSONDecodeError("invalid_utf8") from exc
    if control is not None:
        control.checkpoint()

    def controlled_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        assert control is not None
        control.checkpoint()
        result = _strict_json_object(pairs)
        control.checkpoint()
        return result

    try:
        result = json.loads(
            text,
            object_pairs_hook=_strict_json_object if control is None else controlled_object,
            parse_constant=_reject_nonfinite_json_number,
            parse_float=_strict_json_float,
        )
    except NativeJSONDecodeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NativeJSONDecodeError("malformed_json") from exc
    if control is not None:
        control.checkpoint()
    return result


def _validate_native_exit_code(scanner: str, exit_code: int) -> None:
    """Accept only exits whose meaning is part of our explicit tool contract.

    Bearer documents exit 1 as "findings present".  That exception is further
    constrained at the end of the run: it is successful only when at least one
    native result was parsed and normalized.  Every other non-zero exit is an
    execution failure, irrespective of any output the process happened to
    leave behind.
    """

    if exit_code == 0 or (scanner == "bearer" and exit_code == 1):
        return
    raise NativeExitError("unexpected_native_exit_code")


def _cyclonedx_hash_content(value: dict[Any, Any]) -> str | None:
    """Return one canonical standard hash value, never a hash-shaped lookalike."""

    if set(value) != {"alg", "content"}:
        return None
    algorithm = value.get("alg")
    content = value.get("content")
    expected_length = (
        _CYCLONEDX_HASH_LENGTHS.get(algorithm)
        if isinstance(algorithm, str)
        else None
    )
    if (
        expected_length is None
        or not isinstance(content, str)
        or len(content) != expected_length
        or _HEX_DIGEST.fullmatch(content) is None
    ):
        return None
    return content.lower()


def _cyclonedx_source_location(value: dict[Any, Any]) -> str | None:
    """Preserve only Syft's bounded, typed relative source location."""

    if set(value) != {"name", "value"}:
        return None
    name, path = value.get("name"), value.get("value")
    if (
        not isinstance(name, str)
        or re.fullmatch(r"syft:location:(?:0|[1-9][0-9]*):path", name) is None
        or not isinstance(path, str)
        or not path
        or path != path.strip()
        or path.startswith("/")
        or ":" in path
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in path)
    ):
        return None
    if len(path.encode("utf-8")) > 4096:
        return None
    if has_source_path_credentials(path):
        return None
    return path


def _redact_cyclonedx(
    value: Any,
    key: str = "",
    *,
    depth: int = 0,
    hash_record: bool = False,
    property_record: bool = False,
) -> Any:
    """Redact raw Syft output while preserving validated SBOM hash identity."""

    if depth >= 64 and isinstance(value, (dict, list)):
        return "[REDACTED]"
    if key and redact_json(None, key) == "[REDACTED]":
        return "[REDACTED]"
    if isinstance(value, dict):
        hash_content = _cyclonedx_hash_content(value) if hash_record else None
        source_location = _cyclonedx_source_location(value) if property_record else None
        return {
            str(item_key): (
                hash_content
                if hash_content is not None and item_key == "content"
                else source_location
                if source_location is not None and item_key == "value"
                else _redact_cyclonedx(item, str(item_key), depth=depth + 1)
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_cyclonedx(
                item,
                key,
                depth=depth + 1,
                hash_record=key == "hashes",
                property_record=key == "properties",
            )
            for item in value
        ]
    if (
        isinstance(value, str)
        and key in _CYCLONEDX_REFERENCE_KEYS
        and _CYCLONEDX_UUID_BOM_REF.fullmatch(value)
    ):
        return value.lower()
    return redact_json(value, key, _depth=depth)


def _normalize_cyclonedx_source(payload: Any, source_root: Path | None = None) -> Any:
    """Remove the staged repository path from Syft's root source component."""

    if not isinstance(payload, dict):
        return payload
    metadata = payload.get("metadata")
    source_component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(source_component, dict):
        return payload
    source_name = source_component.get("name")
    if not isinstance(source_name, str):
        return payload
    without_scheme = source_name.removeprefix("file://")
    if not (
        without_scheme.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", without_scheme)
    ):
        return payload
    old_bom_ref = source_component.get("bom-ref")
    path_tokens = {
        source_name,
        without_scheme,
        without_scheme.replace("\\", "/"),
        without_scheme.replace("/", "\\"),
    }
    path_tokens = {token for token in path_tokens if token not in {"", "/", "\\"}}
    # Syft directory catalogs use paths relative to a virtual '/' rather than
    # the host filesystem. Only the producer holding the exact scanned root
    # may translate those paths; API readmission accepts relative paths only.
    virtual_source_paths = source_root is not None and source_name == str(source_root)

    def clean_string(value: str) -> str:
        if isinstance(old_bom_ref, str) and value == old_bom_ref:
            return _STABLE_SOURCE_BOM_REF
        for token in sorted(path_tokens, key=len, reverse=True):
            value = value.replace(token, _STABLE_SOURCE_NAME)
        return value

    def clean(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            if (
                virtual_source_paths
                and key == "properties"
                and set(value) == {"name", "value"}
                and isinstance(value["value"], str)
                and value["value"].startswith("/")
            ):
                relative_property = {**value, "value": value["value"][1:]}
                if _cyclonedx_source_location(relative_property) is not None:
                    value = relative_property
            result: dict[str, Any] = {}
            for key, item in value.items():
                normalized_key = clean_string(str(key))
                if normalized_key in result:
                    raise RuntimeError("CycloneDX source normalization produced a key collision")
                result[normalized_key] = clean(item, normalized_key)
            return result
        if isinstance(value, list):
            return [clean(item, key) for item in value]
        return clean_string(value) if isinstance(value, str) else value

    normalized = clean(payload)
    normalized_source = normalized["metadata"]["component"]
    normalized_source["name"] = _STABLE_SOURCE_NAME
    normalized_source["bom-ref"] = _STABLE_SOURCE_BOM_REF
    return normalized


def _canonicalize_cyclonedx_collections(value: Any, key: str = "") -> Any:
    """Canonicalize CycloneDX collections whose order has no evidence meaning."""

    if isinstance(value, dict):
        return {
            str(item_key): _canonicalize_cyclonedx_collections(item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        normalized = [_canonicalize_cyclonedx_collections(item) for item in value]
        if key in _CYCLONEDX_UNORDERED_ARRAY_KEYS:
            normalized.sort(key=canonical_json_bytes)
        return normalized
    return value


def _generated_cyclonedx_bom_refs(value: Any) -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}

    def collect(item: Any) -> None:
        if isinstance(item, dict):
            bom_ref = item.get("bom-ref")
            if isinstance(bom_ref, str) and _CYCLONEDX_UUID_BOM_REF.fullmatch(bom_ref):
                if bom_ref in definitions:
                    raise RuntimeError("CycloneDX contains a duplicate generated bom-ref")
                definitions[bom_ref] = item
            for nested in item.values():
                collect(nested)
        elif isinstance(item, list):
            for nested in item:
                collect(nested)

    collect(value)
    return definitions


def _cyclonedx_reference_identity(value: Any, generated_refs: frozenset[str]) -> Any:
    """Remove producer-generated reference tokens from stable node identity."""

    if isinstance(value, dict):
        return {
            str(key): _cyclonedx_reference_identity(item, generated_refs)
            for key, item in value.items()
            if key != "bom-ref"
        }
    if isinstance(value, list):
        normalized = [
            _cyclonedx_reference_identity(item, generated_refs)
            for item in value
        ]
        normalized.sort(key=canonical_json_bytes)
        return normalized
    if isinstance(value, str) and value in generated_refs:
        return "[GENERATED-BOM-REF]"
    return value


def _replace_cyclonedx_references(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = replacements.get(str(key), str(key))
            if normalized_key in normalized:
                raise RuntimeError("CycloneDX reference normalization produced a key collision")
            normalized[normalized_key] = _replace_cyclonedx_references(item, replacements)
        return normalized
    if isinstance(value, list):
        return [_replace_cyclonedx_references(item, replacements) for item in value]
    if isinstance(value, str):
        return replacements.get(value, value)
    return value


def _canonicalize_cyclonedx(payload: Any) -> Any:
    """Remove Syft run volatility without discarding durable SBOM evidence."""

    if not isinstance(payload, dict):
        return payload
    normalized = dict(payload)
    normalized.pop("serialNumber", None)
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        normalized_metadata = dict(metadata)
        normalized_metadata.pop("timestamp", None)
        normalized["metadata"] = normalized_metadata

    definitions = _generated_cyclonedx_bom_refs(normalized)
    generated_refs = frozenset(definitions)
    replacements: dict[str, str] = {}
    stable_refs: set[str] = set()
    for original, definition in definitions.items():
        identity = _cyclonedx_reference_identity(definition, generated_refs)
        digest = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        stable_ref = f"{_STABLE_GENERATED_BOM_REF_PREFIX}{digest}"
        if stable_ref in stable_refs:
            raise RuntimeError("CycloneDX generated bom-refs have ambiguous stable identity")
        stable_refs.add(stable_ref)
        replacements[original] = stable_ref

    normalized = _replace_cyclonedx_references(normalized, replacements)
    return _canonicalize_cyclonedx_collections(normalized)


@contextmanager
def request_scratch_directory(base_dir: str, scan_id: int) -> Iterator[Path]:
    """Provide one private request directory and remove it on every unwind path."""

    root = Path(base_dir)
    if root.is_symlink():
        raise RuntimeError("scanner scratch root must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir():
        raise RuntimeError("scanner scratch root is not a directory")
    root.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=f"scan-{scan_id}-", dir=root) as temporary:
        request_dir = Path(temporary)
        request_dir.chmod(0o700)
        yield request_dir


def artifact_record(path: Path, scanner: str, artifact_type: str, fmt: str) -> ScanArtifact | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return ScanArtifact(
        scanner=scanner,
        artifact_type=artifact_type,
        format=fmt,
        path=str(path),
        size_bytes=size,
        sha256=digest.hexdigest(),
    )


def _raw_file(path: Path, scratch_dir: Path) -> Path:
    if path.is_symlink():
        raise RuntimeError("scanner raw output must not be a symlink")
    resolved = path.resolve(strict=True)
    resolved.relative_to(scratch_dir.resolve(strict=True))
    if not resolved.is_file():
        raise RuntimeError("scanner raw output is not a regular file")
    return resolved


def _publish_directory(publish_root: Path, scanner: str) -> Path:
    publish_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    if publish_root.is_symlink():
        raise RuntimeError("artifact publication root must not be a symlink")
    root = publish_root.resolve(strict=True)
    tool_dir = root / scanner
    tool_dir.mkdir(mode=0o750, exist_ok=True)
    if tool_dir.is_symlink() or tool_dir.resolve(strict=True).parent != root:
        raise RuntimeError("artifact publication directory escapes its root")
    return tool_dir


def _publish_sanitized_sbom(
    raw_path: Path,
    scratch_dir: Path,
    publish_root: Path,
    source_root: Path | None = None,
) -> ScanArtifact:
    source = _raw_file(raw_path, scratch_dir)
    if source.stat().st_size > MAX_PUBLISHABLE_SBOM_BYTES:
        raise RuntimeError("SBOM exceeds the publishable size limit")
    try:
        payload = _strict_json_bytes(source.read_bytes())
    except NativeJSONDecodeError as exc:
        raise RuntimeError("Syft returned malformed CycloneDX JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("bomFormat") != "CycloneDX"
        or not isinstance(payload.get("specVersion"), str)
        or not payload["specVersion"].strip()
        or ("components" in payload and not isinstance(payload["components"], list))
    ):
        raise RuntimeError("Syft returned malformed CycloneDX JSON")
    sanitized = _canonicalize_cyclonedx(
        _redact_cyclonedx(_normalize_cyclonedx_source(payload, source_root))
    )
    destination_dir = _publish_directory(publish_root, "syft")
    destination = destination_dir / "syft.cyclonedx.json"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".syft.", suffix=".json", dir=destination_dir)
    temporary = Path(temporary_name)
    try:
        handle = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with handle:
            os.fchmod(handle.fileno(), 0o640)
            json.dump(sanitized, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        record = artifact_record(temporary, "syft", "sbom", "cyclonedx-json")
        if record is None:
            raise RuntimeError("sanitized SBOM publication failed")
        published_record = record.model_copy(update={"path": str(destination)})
        os.replace(temporary, destination)
        return published_record
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _fingerprint(
    scanner: str,
    rule_id: str,
    rel_path: str,
    start_line: int | None,
    start_column: int | None,
    end_line: int | None,
    end_column: int | None,
    message: str,
    *,
    decoded_match_identity: str | None = None,
) -> str:
    payload = canonical_json_bytes(
        {
            "scanner": scanner,
            "rule_id": rule_id,
            "location": {
                "file_path": rel_path,
                "start_line": start_line,
                "start_column": start_column,
                "end_line": end_line,
                "end_column": end_column,
            },
            "message_prefix": message[:240],
            **({"decoded_match_identity": decoded_match_identity} if decoded_match_identity else {}),
        }
    )
    return hashlib.sha256(payload).hexdigest()


def _normalize_path_with_reason(root: Path, value: Any) -> tuple[str, str | None]:
    if not isinstance(value, str):
        return "", "missing_path"
    raw = value.replace("\\", "/").strip()
    if not raw:
        return "", "missing_path"
    raw = raw.removeprefix("file://")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", raw):
        return "", "unsupported_path"
    while raw.startswith("./"):
        raw = raw[2:]
    try:
        root_path = root.resolve(strict=True)
        path = Path(raw)
        candidate = path if path.is_absolute() else root_path / path
        relative = candidate.relative_to(root_path)
    except ValueError:
        return "", "out_of_root_path"
    except (OSError, RuntimeError):
        return "", "unsupported_path"
    if (
        relative == Path(".")
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return "", "unsupported_path"
    return relative.as_posix(), None


def _normalize_path(root: Path, value: str | None) -> str:
    normalized, _reason = _normalize_path_with_reason(root, value)
    return normalized


def _fallback_snippet(fallback: str | None, start_line: int | None) -> tuple[str | None, int | None]:
    lines = (redact_text(fallback) or "").splitlines(keepends=True)
    if not lines:
        return None, None
    snippet, _ = bounded_line_snippet(
        lines,
        0,
        context_lines=len(lines) - 1,
        max_chars=SNIPPET_MAX_CHARS,
    )
    if not snippet:
        return None, None
    return snippet, start_line if start_line and start_line > 0 else None


def _snippet_from_source_document(
    source: SourceDocument,
    start_line: int | None,
    fallback: str | None = None,
) -> tuple[str | None, int | None]:
    fallback_result = _fallback_snippet(fallback, start_line)
    if source.private_key_boundaries:
        # Producer text without a proven source offset can start inside a key.
        fallback_result = (None, None)
    if not start_line or start_line < 1:
        return fallback_result
    lines = source.line_view(keepends=True)
    idx = start_line - 1
    if idx >= len(lines):
        raise SourceEvidenceError("source_location_out_of_range")
    snippet, actual_start_line = bounded_line_snippet(
        lines,
        idx,
        context_lines=SNIPPET_CONTEXT_LINES,
        max_chars=SNIPPET_MAX_CHARS,
    )
    if not snippet:
        return fallback_result
    return source.redact_snippet(snippet, actual_start_line), actual_start_line


def _signal_process_group(process_group_id: int, requested_signal: signal.Signals) -> bool:
    try:
        os.killpg(process_group_id, requested_signal)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin can report EPERM while a just-reaped session disappears.
        # Never broaden the target in response to an ambiguous group lookup.
        return False


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return False


def _terminate_process_group(process: subprocess.Popen[Any], grace_seconds: float) -> None:
    """Terminate only the new session owned by ``process``, then enforce KILL."""

    process_group_id = process.pid
    _signal_process_group(process_group_id, signal.SIGTERM)
    deadline = time.monotonic() + max(grace_seconds, 0.0)
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group_id):
            break
        time.sleep(min(0.02, max(deadline - time.monotonic(), 0.0)))
    # Enforce KILL against the same group even when a platform reports an
    # ambiguous post-TERM existence check. Never fall back to a broader target.
    _signal_process_group(process_group_id, signal.SIGKILL)
    try:
        process.wait(timeout=max(min(grace_seconds, 1.0), 0.1))
    except subprocess.TimeoutExpired:
        _signal_process_group(process_group_id, signal.SIGKILL)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            # The caller cannot safely target anything broader than this exact
            # process group. Container shutdown remains the final boundary.
            pass
    # Reaping the group leader and reaping its descendants are separate kernel
    # events.  Fedora can expose the killed descendant group briefly after
    # ``wait()`` returns, so give the exact group a bounded disappearance
    # window before returning to the caller.
    disappearance_deadline = time.monotonic() + max(min(grace_seconds, 1.0), 0.1)
    while _process_group_exists(process_group_id) and time.monotonic() < disappearance_deadline:
        time.sleep(min(0.02, max(disappearance_deadline - time.monotonic(), 0.0)))


def _wait_for_process(
    process: subprocess.Popen[Any],
    command: list[str],
    timeout: float,
    control: ExecutionControl | None,
) -> int:
    tool_deadline = time.monotonic() + timeout
    while True:
        if control is not None:
            control.checkpoint()
        remaining = tool_deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        wait_for = min(0.05, remaining)
        if control is not None:
            wait_for = min(wait_for, max(control.remaining_seconds(), 0.001))
        try:
            return process.wait(timeout=wait_for)
        except subprocess.TimeoutExpired:
            continue


def run_captured_command(
    command: list[str],
    cwd: Path,
    timeout: float,
    env: dict[str, str],
    control: ExecutionControl | None = None,
    max_output_bytes: int = MAX_CAPTURED_COMMAND_BYTES,
    *,
    stdin: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a small control command with cancellation and bounded captured output."""

    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract guard
        _terminate_process_group(process, 0.05)
        raise RuntimeError("command capture pipes were not created")
    streams = (process.stdout, process.stderr)
    stdout_descriptor = process.stdout.fileno()
    stderr_descriptor = process.stderr.fileno()
    buffers: dict[int, bytearray] = {stream.fileno(): bytearray() for stream in streams}
    total_bytes = 0
    leader_finished = False
    tool_deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                if control is not None:
                    control.checkpoint()
                remaining = tool_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                select_for = min(0.05, remaining)
                if control is not None:
                    select_for = min(select_for, max(control.remaining_seconds(), 0.001))
                for key, _ in selector.select(timeout=select_for):
                    descriptor = key.fileobj.fileno()
                    try:
                        chunk = os.read(descriptor, min(65536, max_output_bytes - total_bytes + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[descriptor].extend(chunk)
                    total_bytes += len(chunk)
                    if total_bytes > max_output_bytes:
                        raise CapturedCommandOutputLimitError(max_output_bytes)
                if not leader_finished and process.poll() is not None:
                    leader_finished = True
                    # A successful leader is not allowed to leave pipe-owning
                    # descendants behind in its exact start_new_session group.
                    _terminate_process_group(process, 0.05)
            if not leader_finished:
                _wait_for_process(process, command, max(tool_deadline - time.monotonic(), 0.001), control)
                _terminate_process_group(process, 0.05)
    except BaseException:
        grace = control.termination_grace_seconds if control is not None else 5.0
        _terminate_process_group(process, grace)
        raise
    finally:
        for stream in streams:
            stream.close()
    stdout = bytes(buffers[stdout_descriptor]).decode("utf-8", errors="surrogateescape")
    stderr = bytes(buffers[stderr_descriptor]).decode("utf-8", errors="surrogateescape")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _run_command(
    scanner: str,
    command: list[str],
    cwd: Path,
    timeout: float,
    raw_dir: Path,
    env: dict[str, str] | None = None,
    *,
    stdout_path: Path | None = None,
    control: ExecutionControl | None = None,
) -> subprocess.CompletedProcess[bytes]:
    started = time.monotonic()
    settings = get_settings()
    actual_command = command
    if settings.external_tool_nice > 0 and shutil.which("nice"):
        actual_command = ["nice", "-n", str(settings.external_tool_nice), *command]
    raw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw_root = raw_dir.resolve(strict=True)
    stdout_file = stdout_path or raw_root / f"{scanner}.stdout.txt"
    stderr_file = raw_root / f"{scanner}.stderr.txt"
    if stdout_file.parent.resolve(strict=True) != raw_root or stderr_file.parent.resolve(strict=True) != raw_root:
        raise RuntimeError("scanner output path escapes request scratch")
    with stdout_file.open("xb") as stdout_handle, stderr_file.open("xb") as stderr_handle:
        process = subprocess.Popen(
            actual_command,
            cwd=str(cwd),
            stdout=stdout_handle,
            stderr=stderr_handle,
            env=env,
            start_new_session=True,
        )
        try:
            _wait_for_process(process, command, timeout, control)
        except BaseException:
            grace = (
                control.termination_grace_seconds
                if control is not None
                else float(getattr(settings, "process_termination_grace_seconds", 5.0))
            )
            _terminate_process_group(process, grace)
            raise
        else:
            # Remove any descendant that outlived a successful command leader.
            _terminate_process_group(process, 0.05)
    result = subprocess.CompletedProcess(command, process.returncode)
    result.duration_ms = int((time.monotonic() - started) * 1000)  # type: ignore[attr-defined]
    return result


def _invoke_run_command(
    scanner: str,
    command: list[str],
    cwd: Path,
    timeout: float,
    raw_dir: Path,
    env: dict[str, str] | None,
    *,
    stdout_path: Path | None = None,
    control: ExecutionControl | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if control is None:
        return _run_command(
            scanner,
            command,
            cwd,
            timeout,
            raw_dir,
            env,
            stdout_path=stdout_path,
        )
    return _run_command(
        scanner,
        command,
        cwd,
        timeout,
        raw_dir,
        env,
        stdout_path=stdout_path,
        control=control,
    )


def _parse_sarif_with_reader(
    path: Path,
    scanner: str,
    root: Path,
    source_reader: SourceTextReader,
    control: ExecutionControl | None = None,
    *, checkov_cwd: Path | None = None,
) -> NativeParseResult:
    if control is not None:
        control.checkpoint()
    payload = path.read_bytes()
    if control is not None:
        control.checkpoint()
    try:
        sarif = _strict_json_bytes(payload, control)
    except NativeJSONDecodeError as exc:
        raise RuntimeError(f"{scanner} returned malformed SARIF") from exc
    del payload
    path_lookup = None
    if scanner == "checkov" and checkov_cwd is not None:
        path_lookup = _checkov_source_path_lookup(sarif, root, checkov_cwd, source_reader, control)
    return _parse_sarif_document_with_reader(sarif, scanner, root, source_reader, control,
                                           checkov_path_lookup=path_lookup)


def _checkov_source_path_lookup(
    sarif: object, root: Path, cwd: Path, reader: SourceTextReader,
    control: ExecutionControl | None,
) -> dict[str, str | None]:
    """Invert only the pinned Checkov projection of exact contained source paths."""
    requested: set[str] = set()
    if isinstance(sarif, dict) and isinstance(sarif.get("runs"), list):
        for run in sarif["runs"]:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list):
                continue
            for result in run["results"]:
                if control is not None:
                    control.checkpoint()
                if not isinstance(result, dict) or not isinstance(result.get("locations"), list):
                    continue
                for location in result["locations"]:
                    if control is not None:
                        control.checkpoint()
                    if not isinstance(location, dict):
                        continue
                    physical = location.get("physicalLocation")
                    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
                    uri = artifact.get("uri") if isinstance(artifact, dict) else None
                    if isinstance(uri, str) and 0 < len(uri) <= 4096:
                        requested.add(uri)
    maximum_files = get_settings().max_files
    if len(requested) > maximum_files:
        raise SourceEvidenceError("producer_path_lookup_limit")
    target = root.resolve(strict=True)
    owned_cwd = cwd.resolve(strict=True)

    def project(relative: str) -> str:
        # Checkov 3.3.10 record.py:102-108 and sarif.py:225 erase every '/..'
        # from cwd-relative paths before URI quoting, including name prefixes.
        # Derive keys from safe local source entries, never strip a native URI.
        # Ambiguous keys are refused; upgrades require the native path canary.
        return quote(("/" + os.path.relpath(target / relative, owned_cwd))
                     .replace("/..", "").lstrip("/"))

    return reader.projected_path_lookup(requested, project, maximum_files * 4,
        control.checkpoint if control is not None else lambda: None)


def _gitleaks_unterminated_range(
    source: SourceDocument, region: dict[str, Any],
) -> tuple[int, int, int, int]:
    """Recover the pinned producer's zero end-column from exact source bytes.

    Gitleaks 8.30.1 leaves the end position unset for a multiline match extending
    past the last newline. Its SARIF snippet is the secret, not surrounding
    context. Require one exact occurrence and the producer's byte-based start;
    never invent an endpoint or accept a snippet absent from captured source.
    """
    snippet = region.get("snippet")
    text = snippet.get("text") if isinstance(snippet, dict) else None
    if not isinstance(text, str) or not text or "\n" not in text:
        raise SourceEvidenceError("invalid_source_location")
    start = source.text.find(text)
    if start < 0 or source.text.find(text, start + 1) >= 0:
        raise SourceEvidenceError("invalid_source_location")
    end = start + len(text)
    first = bisect_right(source.line_starts, start) - 1
    last = bisect_right(source.line_starts, end) - 1
    prefix = source.text[source.line_starts[first]:start]
    # The producer measures subsequent columns from the preceding LF itself.
    native_column = len(prefix.encode("utf-8")) + 1 + (first > 0)
    if (
        region.get("startLine") != first + 1
        or region.get("endLine") != first + 1
        or region.get("startColumn") != native_column
        or first == last
        or "\n" in source.text[end:]
    ):
        raise SourceEvidenceError("invalid_source_location")
    return (
        first + 1, len(prefix.encode("utf-16-le")) // 2 + 1,
        last + 1,
        len(source.text[source.line_starts[last]:end].encode("utf-16-le")) // 2 + 1,
    )


def _parse_sarif_document_with_reader(
    sarif: object,
    scanner: str,
    root: Path,
    source_reader: SourceTextReader,
    control: ExecutionControl | None = None,
    *, checkov_path_lookup: dict[str, str | None] | None = None,
) -> NativeParseResult:
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise RuntimeError(f"{scanner} returned malformed SARIF")
    findings: list[Finding] = []
    integrity = NativeParseIntegrity()
    for run in sarif["runs"]:
        if control is not None:
            control.checkpoint()
        if not isinstance(run, dict):
            raise RuntimeError(f"{scanner} returned malformed SARIF")
        rules: dict[str, tuple[dict[str, Any], bytes]] = {}
        tool = run.get("tool") or {}
        if not isinstance(tool, dict):
            raise RuntimeError(f"{scanner} returned malformed SARIF")
        driver = tool.get("driver") or {}
        if not isinstance(driver, dict):
            raise RuntimeError(f"{scanner} returned malformed SARIF")
        for rule in driver.get("rules") or []:
            if control is not None:
                control.checkpoint()
            if isinstance(rule, dict) and rule.get("id"):
                rule_props = rule.get("properties") or {}
                short_description = rule.get("shortDescription") or {}
                if not isinstance(rule_props, dict) or not isinstance(short_description, dict):
                    raise RuntimeError(f"{scanner} returned malformed SARIF")
                raw_tags = rule_props.get("tags") or []
                if not isinstance(raw_tags, list) or any(
                    not isinstance(tag, str) for tag in raw_tags
                ):
                    raise RuntimeError(f"{scanner} returned malformed SARIF rule tags")
                default_configuration = rule.get("defaultConfiguration", {})
                evidence = canonical_json_bytes(
                    {
                        "name": rule.get("name"),
                        "help_uri": rule.get("helpUri"),
                        "short_description": short_description.get("text"),
                        "severity": rule_props.get("severity"),
                        "default_configuration_is_object": isinstance(default_configuration, dict),
                        "default_level": (
                            default_configuration.get("level", "warning")
                            if isinstance(default_configuration, dict)
                            else default_configuration
                        ),
                        "tags": sorted(set(raw_tags)),
                    }
                )
                rule_id = str(rule["id"])
                existing = rules.get(rule_id)
                if existing is not None and existing[1] != evidence:
                    raise RuntimeError(
                        f"{scanner} returned conflicting duplicate SARIF rules"
                    )
                rules[rule_id] = (rule, evidence)
        results = run.get("results") or []
        if not isinstance(results, list):
            raise RuntimeError(f"{scanner} returned malformed SARIF")
        column_kind_present = "columnKind" in run
        column_kind = run.get("columnKind")
        if results and column_kind_present and column_kind not in {
            "unicodeCodePoints",
            "utf16CodeUnits",
        }:
            for _result in results:
                if control is not None:
                    control.checkpoint()
                integrity.drop("invalid_column_kind")
            continue
        gitleaks_ranges = GitleaksSourceRanges(
            results, lambda uri: _normalize_path_with_reason(root, uri)[0],
            control.checkpoint if control is not None else lambda: None,
        ) if scanner == "gitleaks" and not column_kind_present else None
        for result in results:
            if control is not None:
                control.checkpoint()
            if not isinstance(result, dict):
                integrity.drop("non_object_result")
                continue
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
            rule_entry = rules.get(rule_id)
            rule = rule_entry[0] if rule_entry is not None else {}
            props = result.get("properties") or {}
            if not isinstance(props, dict):
                integrity.drop("invalid_properties")
                continue
            rule_props = rule.get("properties") or {}
            # OpenGrep emits severity on the rule descriptor and omits the
            # result level. SARIF 2.1.0 inherits that default, then warning.
            # A present malformed value is not an omitted default.
            if "level" in result:
                level = result["level"]
            else:
                default_configuration = rule.get("defaultConfiguration", {})
                if not isinstance(default_configuration, dict):
                    integrity.drop("invalid_sarif_level")
                    continue
                level = default_configuration.get("level", "warning")
            if not isinstance(level, str) or level not in SEVERITY_MAP:
                integrity.drop("invalid_sarif_level")
                continue
            severity = SEVERITY_MAP[level]
            security_score: float | None = None
            if "security-severity" in props:
                raw_security_score = props["security-severity"]
                if (
                    isinstance(raw_security_score, bool)
                    or not isinstance(raw_security_score, (str, int, float))
                    or (isinstance(raw_security_score, str) and not raw_security_score.strip())
                ):
                    integrity.drop("invalid_security_severity")
                    continue
                try:
                    security_score = float(raw_security_score)
                except (OverflowError, TypeError, ValueError):
                    integrity.drop("invalid_security_severity")
                    continue
                if not math.isfinite(security_score) or not 0 <= security_score <= 10:
                    integrity.drop("invalid_security_severity")
                    continue
            sarif_severity = str(props.get("severity") or rule_props.get("severity") or "").lower()
            if sarif_severity in {"critical", "high", "medium", "low", "info"}:
                severity = sarif_severity
            elif security_score is not None:
                severity = (
                    "critical"
                    if security_score >= 9
                    else "high"
                    if security_score >= 7
                    else "medium"
                    if security_score >= 4
                    else "low"
                )
            elif scanner == "trivy":
                severity = _trivy_message_severity(result.get("message")) or severity

            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                integrity.drop("missing_location")
                continue
            if len(locations) != 1:
                if scanner == "trivy":
                    # Trivy groups repeated vulnerable package occurrences in
                    # one result's primary locations (for example several npm
                    # lockfile entries). Preserve every exact occurrence, not
                    # an arbitrary first location or one enlarged source range.
                    # Each occurrence uses the unchanged strict single-location
                    # parser and the same opened source boundary. Admission is
                    # atomic for the original native result: any invalid location
                    # rejects all of its occurrences; native counts remain per
                    # original result, not per normalized finding.
                    occurrences = _parse_sarif_document_with_reader(
                        {"runs": [{**run, "results": [
                            {**result, "locations": [location]}
                            for location in locations
                        ]}]},
                        scanner, root, source_reader, control,
                    )
                    if occurrences.integrity.dropped_records:
                        integrity.drop("invalid_trivy_occurrence_locations")
                    else:
                        findings.extend(occurrences.findings)
                        integrity.accept()
                    continue
                integrity.drop("multiple_locations")
                continue
            loc = locations[0]
            if not isinstance(loc, dict):
                integrity.drop("invalid_location")
                continue
            phys = loc.get("physicalLocation") or {}
            if not isinstance(phys, dict):
                integrity.drop("invalid_location")
                continue
            artifact = phys.get("artifactLocation") or {}
            if not isinstance(artifact, dict):
                integrity.drop("invalid_location")
                continue
            region = phys.get("region") or {}
            if not isinstance(region, dict):
                integrity.drop("invalid_location")
                continue
            uri = artifact.get("uri")
            if scanner == "checkov" and checkov_path_lookup is not None:
                if isinstance(uri, str) and uri in checkov_path_lookup:
                    rel_path = checkov_path_lookup[uri] or ""
                    path_reason = None if rel_path else "ambiguous_checkov_source_path"
                else:
                    rel_path, path_reason = "", "unresolved_checkov_source_path"
            else:
                rel_path, path_reason = _normalize_path_with_reason(root, uri)
            if not rel_path:
                integrity.drop(path_reason or "unsupported_path")
                continue
            def coordinate(name: str) -> int | None:
                if name not in region:
                    return None
                value = region.get(name)
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 1
                ):
                    raise SourceEvidenceError("invalid_source_location")
                return value

            try:
                start_line = coordinate("startLine")
                end_line = coordinate("endLine")
                start_column = coordinate("startColumn")
                recover_gitleaks_end = (
                    scanner == "gitleaks" and not column_kind_present
                    and type(region.get("endColumn")) is int
                    and region["endColumn"] == 0
                )
                end_column = None if recover_gitleaks_end else coordinate("endColumn")
                source_document = source_reader.read_document(rel_path)
                location_kind = column_kind
                source_witness = None
                if recover_gitleaks_end:
                    start_line, start_column, end_line, end_column = _gitleaks_unterminated_range(
                        source_document, region,
                    )
                    location_kind = "utf16CodeUnits"
                elif gitleaks_ranges is not None:
                    source_witness = gitleaks_ranges.resolve(
                        rel_path, rule_id, region, props, source_document,
                    )
                    if source_witness is not None:
                        start_line, start_column, end_line, end_column = source_witness
                        location_kind = "utf16CodeUnits"
                (
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                ) = complete_source_location(
                    source_document,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                    location_kind,
                )
            except SourceEvidenceError as exc:
                integrity.drop(exc.reason)
                continue
            message = str((result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id)
            raw_snippet = str((region.get("snippet") or {}).get("text") or props.get("match") or "")
            try:
                snippet, snippet_start = _snippet_from_source_document(
                    source_document,
                    start_line,
                    raw_snippet,
                )
            except SourceEvidenceError as exc:
                integrity.drop(exc.reason)
                continue
            raw_tags = rule_props.get("tags") or []
            if not isinstance(raw_tags, list) or any(
                not isinstance(tag, str) for tag in raw_tags
            ):
                raise RuntimeError(f"{scanner} returned malformed SARIF rule tags")
            metadata = {
                "native": "sarif",
                "sarif_level": level,
                "rule_name": rule.get("name"),
                "help_uri": rule.get("helpUri"),
                "tags": sorted(set(raw_tags)),
                "snippet_start_line": snippet_start,
                **({"source_location_basis": "gitleaks-exact-source"} if source_witness else {}),
                **({"native_decode_tags": ["decoded:base64", "decode-depth:1"]}
                   if source_witness and "decoded:base64" in (props.get("tags") or []) else {}),
                **({"snippet_truncated": True} if start_line and source_document.context_exceeds_chars(
                    start_line, SNIPPET_CONTEXT_LINES, SNIPPET_MAX_CHARS) else {}),
            }
            # Decoding can produce a distinct native detection at the same
            # proven source range. Keep both reports without changing the
            # identity of ordinary findings or relaxing collision checks.
            # Only the fingerprint preimage receives this identity; neither the
            # decoded secret nor its standalone digest becomes finding metadata.
            decoded_match_identity = (
                hashlib.sha256(canonical_json_bytes({
                    "transform": "base64-depth-1", "match": raw_snippet,
                })).hexdigest() if "native_decode_tags" in metadata else None
            )
            findings.append(
                Finding(
                    scanner=scanner,
                    rule_id=rule_id[:160],
                    severity=severity,  # type: ignore[arg-type]
                    file_path=rel_path,
                    start_line=start_line,
                    start_column=start_column,
                    end_line=end_line,
                    end_column=end_column,
                    message=message[:4000],
                    code_snippet=snippet,
                    fingerprint=_fingerprint(
                        scanner,
                        rule_id,
                        rel_path,
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                        message,
                        decoded_match_identity=decoded_match_identity,
                    ),
                    metadata=metadata,
                )
            )
            integrity.accept()
    return NativeParseResult(findings=findings, integrity=integrity)


def _parse_sarif(
    path: Path, scanner: str, root: Path, control: ExecutionControl | None = None,
    *, checkov_cwd: Path | None = None,
) -> NativeParseResult:
    try:
        with SourceTextReader(root, get_settings().max_file_bytes,
                              checkpoint=control.checkpoint if control else None) as source_reader:
            return _parse_sarif_with_reader(path, scanner, root, source_reader, control,
                                           checkov_cwd=checkov_cwd)
    except SourceEvidenceError as exc:
        raise RuntimeError(f"{scanner} source evidence unavailable: {exc.reason}") from exc


def _validated_native_findings(parsed: NativeParseResult) -> list[Finding]:
    if parsed.integrity.dropped_records:
        raise NativeParseIntegrityError(parsed.integrity)
    return _deduplicate_findings(parsed.findings)


def parse_sarif(path: Path, scanner: str, root: Path) -> list[Finding]:
    """Parse SARIF and reject a stream whose result records were not normalized."""

    return _validated_native_findings(_parse_sarif(path, scanner, root))


def _parse_sarif_controlled(
    path: Path,
    scanner: str,
    root: Path,
    control: ExecutionControl | None,
    *, checkov_cwd: Path | None = None,
) -> NativeParseResult:
    if control is not None:
        control.checkpoint()
    parsed = (_parse_sarif(path, scanner, root, control)
              if checkov_cwd is None else
              _parse_sarif(path, scanner, root, control, checkov_cwd=checkov_cwd))
    if control is not None:
        control.checkpoint()
    return parsed


def _parse_trufflehog_with_reader(
    path: Path,
    root: Path,
    source_reader: SourceTextReader,
    control: ExecutionControl | None = None,
) -> NativeParseResult:
    findings: list[Finding] = []
    integrity = NativeParseIntegrity()
    with path.open("rb") as handle:
        for line in handle:
            if control is not None:
                control.checkpoint()
            if not line.strip():
                continue
            try:
                item = _strict_json_bytes(line)
            except NativeJSONDecodeError as exc:
                reason = {
                    "invalid_utf8": "invalid_utf8_result",
                    "malformed_json": "malformed_json_result",
                }.get(exc.reason, exc.reason)
                integrity.drop(reason)
                continue
            if not isinstance(item, dict):
                integrity.drop("non_object_result")
                continue
            detector = str(item.get("DetectorName") or item.get("DetectorType") or item.get("SourceType") or "secret")
            source_metadata = item.get("SourceMetadata") or {}
            data = source_metadata.get("Data") if isinstance(source_metadata, dict) else None
            source = data.get("Filesystem") if isinstance(data, dict) else None
            source = source if isinstance(source, dict) else {}
            reported_path = source.get("file") or source.get("path") or source.get("filename")
            rel_path, path_reason = _normalize_path_with_reason(root, reported_path)
            if not rel_path:
                integrity.drop(path_reason or "unsupported_path")
                continue
            if rel_path.startswith(".git/"):
                integrity.filter("git_metadata_path")
                continue
            line_num = (
                source.get("line")
                if source.get("line") is not None
                else source.get("line_number")
            )
            if line_num is not None and (
                not isinstance(line_num, int)
                or isinstance(line_num, bool)
                or line_num < 1
            ):
                integrity.drop("invalid_source_location")
                continue
            start_line = line_num
            verified = bool(item.get("Verified") or item.get("verified"))
            message = str(item.get("Reason") or item.get("reason") or f"Potential secret detected by TruffleHog ({detector})")
            raw = str(item.get("Redacted") or item.get("Raw") or item.get("raw") or "")
            try:
                source_document = source_reader.read_document(rel_path)
                (
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                ) = complete_source_location(
                    source_document,
                    start_line,
                    None,
                    start_line,
                    None,
                    "utf16CodeUnits",
                )
                snippet, snippet_start = _snippet_from_source_document(
                    source_document,
                    start_line,
                    raw,
                )
            except SourceEvidenceError as exc:
                integrity.drop(exc.reason)
                continue
            findings.append(
                Finding(
                    scanner="trufflehog",
                    rule_id=detector[:160],
                    severity="critical" if verified else "high",
                    file_path=rel_path,
                    start_line=start_line,
                    start_column=start_column,
                    end_line=end_line,
                    end_column=end_column,
                    message=message[:4000],
                    code_snippet=snippet,
                    fingerprint=_fingerprint(
                        "trufflehog",
                        detector,
                        rel_path,
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                        message,
                    ),
                    metadata={"native": "jsonl", "verified": verified, "snippet_start_line": snippet_start,
                        **({"snippet_truncated": True} if start_line and source_document.context_exceeds_chars(
                            start_line, SNIPPET_CONTEXT_LINES, SNIPPET_MAX_CHARS) else {})},
                )
            )
            integrity.accept()
    if integrity.total_records == 0 and path.stat().st_size > 0:
        raise RuntimeError("TruffleHog returned no JSONL records")
    return NativeParseResult(findings=findings, integrity=integrity)


def _parse_trufflehog(
    path: Path,
    root: Path,
    control: ExecutionControl | None = None,
) -> NativeParseResult:
    try:
        with SourceTextReader(root, get_settings().max_file_bytes,
                              checkpoint=control.checkpoint if control else None) as source_reader:
            return _parse_trufflehog_with_reader(
                path,
                root,
                source_reader,
                control,
            )
    except SourceEvidenceError as exc:
        raise RuntimeError(
            f"TruffleHog source evidence unavailable: {exc.reason}"
        ) from exc


def parse_trufflehog(
    path: Path,
    root: Path,
    control: ExecutionControl | None = None,
) -> list[Finding]:
    """Parse JSONL and reject a stream whose result records were not normalized."""

    return _validated_native_findings(_parse_trufflehog(path, root, control))


def _maybe_sarif(
    path: Path,
    scanner: str,
    root: Path,
    scratch_dir: Path,
    control: ExecutionControl | None = None,
    *, checkov_cwd: Path | None = None,
) -> NativeParseResult:
    if not path.exists() or path.stat().st_size == 0:
        return NativeParseResult(findings=[], integrity=NativeParseIntegrity())
    source = _raw_file(path, scratch_dir)
    if source.stat().st_size > MAX_NATIVE_FINDINGS_BYTES:
        raise RuntimeError("native scanner findings exceed the processing size limit")
    return _parse_sarif_controlled(source, scanner, root, control, checkov_cwd=checkov_cwd)


def _required_sarif(
    path: Path,
    scanner: str,
    root: Path,
    scratch_dir: Path,
    control: ExecutionControl | None = None,
) -> NativeParseResult:
    """Parse one mandatory native SARIF output or fail the tool run closed."""

    if not path.exists() or path.stat().st_size == 0:
        raise RuntimeError("required_output_missing")
    return _maybe_sarif(path, scanner, root, scratch_dir, control)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate identical evidence and reject ambiguous fingerprint collisions."""

    unique: dict[str, tuple[bytes, Finding]] = {}
    for finding in findings:
        encoded = canonical_json_bytes(finding.model_dump(mode="json"))
        existing = unique.get(finding.fingerprint)
        if existing is None:
            unique[finding.fingerprint] = (encoded, finding)
        elif existing[0] != encoded:
            raise RuntimeError("finding_fingerprint_collision")
    return [
        item[1]
        for item in sorted(unique.values(), key=lambda item: (item[1].fingerprint, item[0]))
    ]


def _tool_environment(scanner: str, scratch_dir: Path, cache_root: Path) -> tuple[dict[str, str], Path]:
    """Create only disposable per-request state for an external tool.

    ``cache_root`` is the authoritative generation store. Runtime tools must
    never create, chmod, or otherwise mutate it; exact data/rule component
    roots are passed separately after active-generation validation. Keeping the
    argument for now avoids a broad internal API change while making that
    ownership boundary explicit.
    """

    del cache_root
    scratch = scratch_dir.resolve(strict=True)
    cache_dir = scratch / "cache"
    if cache_dir.is_symlink():
        raise RuntimeError("scanner disposable cache must not be a symlink")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if cache_dir.resolve(strict=True).parent != scratch:
        raise RuntimeError("scanner disposable cache escapes request scratch")
    cache_dir.chmod(0o700)
    home_dir = scratch / "home"
    if home_dir.is_symlink():
        raise RuntimeError("scanner private home must not be a symlink")
    home_dir.mkdir(mode=0o700, exist_ok=True)
    if home_dir.resolve(strict=True).parent != scratch:
        raise RuntimeError("scanner private home escapes request scratch")
    home_dir.chmod(0o700)
    # Native scans must not inherit credentials, Python import hooks, or tool
    # configuration overrides from the service process. These are the only
    # ambient values needed to render text; executables use owned runtime paths.
    environment = {
        key: value for key in ("LANG", "LC_ALL", "LC_CTYPE")
        if (value := os.environ.get(key)) and re.fullmatch(r"[A-Za-z0-9_.@-]+", value)
    }
    environment.update({
        "PATH": os.pathsep.join(("/usr/local/bin", os.defpath)),
        "HOME": str(home_dir),
        "NO_COLOR": "1",
        "TEMP": str(scratch_dir),
        "TMP": str(scratch_dir),
        "TMPDIR": str(scratch_dir),
        "XDG_CACHE_HOME": str(cache_dir),
    })
    if scanner == "opengrep":
        environment.update(
            {
                "PATH": os.pathsep.join(
                    part
                    for part in (
                        str(OPENGREP_EXECUTABLE_PATH.parent),
                        environment.get("PATH", ""),
                    )
                    if part
                ),
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SEND_METRICS": "off",
            }
        )
    elif scanner == "bearer":
        environment["BEARER_TELEMETRY_ENABLED"] = "false"
    elif scanner == "checkov":
        environment["CHECKOV_SKIP_FRAMEWORK_DOWNLOADS"] = "true"
        environment["PYTHONSAFEPATH"] = "1"
    return environment, cache_dir


class SourceConfigurationError(RuntimeError):
    """A native producer cannot safely disable a source-owned control file."""


def _refuse_source_controls(repo: Path, scanner: str, names: tuple[str, ...]) -> None:
    # Checkov discovers target-root configuration even with --config-file;
    # Gitleaks always reads target-root .gitleaksignore in addition to its flag.
    # Do not read, remove, rename or rewrite any of those source bytes.
    for name in names:
        try:
            (repo / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SourceConfigurationError("source_control_inspection_failed") from exc
        raise SourceConfigurationError(f"source_control_unsupported:{scanner}")


def _trusted_tool_config(tool_dir: Path, name: str, content: str) -> Path:
    """Create one fixed configuration only in the owned request directory."""
    path = tool_dir / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
    return path


def _required_runtime_component(
    inputs: dict[str, Path] | None,
    component_id: str,
) -> Path:
    candidate = (inputs or {}).get(component_id)
    if candidate is None:
        raise RuntimeError(f"offline_component_unavailable:{component_id}")
    try:
        if candidate.is_symlink():
            raise RuntimeError(f"offline_component_invalid:{component_id}")
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"offline_component_invalid:{component_id}") from exc
    if not resolved.is_dir():
        raise RuntimeError(f"offline_component_invalid:{component_id}")
    return resolved


def _trivy_runtime_cache(inputs: dict[str, Path] | None) -> Path:
    database = _required_runtime_component(inputs, "trivy-db")
    java_database = _required_runtime_component(inputs, "trivy-java-db")
    checks = _required_runtime_component(inputs, "trivy-checks")
    cache = database.parent
    try:
        java_database.relative_to(cache)
        checks.relative_to(cache)
    except ValueError as exc:
        raise RuntimeError("offline_component_invalid:trivy-cache-layout") from exc
    return cache


def _opengrep_rules_path(configured_path: str, cache_dir: Path) -> Path | None:
    """Accept only a real, non-symlinked rule file/tree in OpenGrep's cache."""

    path = Path(configured_path)
    if not configured_path or not path.is_absolute():
        return None
    try:
        cache = cache_dir.resolve(strict=True)
        relative = path.relative_to(cache)
        current = cache
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None
        resolved = path.resolve(strict=True)
        resolved.relative_to(cache)
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved.is_file():
        return resolved
    if not resolved.is_dir():
        return None
    entry_count = 0
    for root, directories, filenames in os.walk(resolved, followlinks=False):
        for name in (*directories, *filenames):
            entry_count += 1
            if entry_count > MAX_OPENGREP_RULE_ENTRIES:
                return None
            entry = Path(root) / name
            if entry.is_symlink():
                return None
            try:
                entry.resolve(strict=True).relative_to(cache)
            except (OSError, RuntimeError, ValueError):
                return None
            if name in directories and not entry.is_dir():
                return None
            if name in filenames and not entry.is_file():
                return None
    return resolved


def run_external_tool(
    scanner: str,
    repo: Path,
    scratch_dir: Path,
    publish_root: Path,
    cache_root: Path,
    timeout: int,
    control: ExecutionControl | None = None,
    inputs: dict[str, Path] | None = None,
) -> ToolRunResult:
    if scanner not in external_tool_ids():
        return ToolRunResult(scanner=scanner, status="skipped", error="not_external_tool")

    # Maintainer-only parsers import this module without runtime telemetry deps.
    # Python's module import lock also serializes first use by concurrent runs.
    from .execution_metrics import adapter_duration

    started = time.monotonic()
    tool_dir = scratch_dir / scanner
    tool_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        if control is None:
            return _run_external_tool(
                scanner,
                repo,
                tool_dir,
                publish_root,
                cache_root,
                timeout,
                started,
                inputs=inputs,
            )
        return _run_external_tool(
            scanner,
            repo,
            tool_dir,
            publish_root,
            cache_root,
            timeout,
            started,
            control,
            inputs,
        )
    finally:
        # Parsed output has no further value and can otherwise accumulate across
        # a multi-tool request until its outer TemporaryDirectory is removed.
        shutil.rmtree(tool_dir, ignore_errors=True)
        adapter_duration.labels(scanner=scanner).observe(time.monotonic() - started)


def _run_external_tool(
    scanner: str,
    repo: Path,
    tool_dir: Path,
    publish_root: Path,
    cache_root: Path,
    timeout: int,
    started: float,
    control: ExecutionControl | None = None,
    inputs: dict[str, Path] | None = None,
) -> ToolRunResult:
    # `timeout` is a Mac-reference duration, not an already adjusted value.
    # Read the validated installation lane once per invocation. The run's original
    # ExecutionControl remains authoritative across all native stages.
    platform = get_settings().scan_platform
    factor = {"mac": 1, "linux": 2.6, "windows": 3.9}[platform]
    extended_timeout = math.ceil(max(timeout, 600) * factor)
    timeout = math.ceil(timeout * factor)
    environment, cache_dir = _tool_environment(scanner, tool_dir, cache_root)
    if scanner == "bearer":
        environment["KODESEC_SCAN_PLATFORM"] = platform
        # D-021 gives VM analysis its finite native whole-scan budget. The
        # original run control still wins; Mac and other tool budgets retain
        # their reference policy, without multiplying an absolute run interval.
        if platform != "mac":
            timeout = extended_timeout
    artifacts: list[ScanArtifact] = []
    findings: list[Finding] = []
    error: str | None = None
    exit_code: int | None = None
    parse_integrity = NativeParseIntegrity()
    parsed_native_output = False
    bearer_unsupported_source = False

    def accept_native_parse(parsed: NativeParseResult) -> list[Finding]:
        nonlocal parsed_native_output
        parse_integrity.merge(parsed.integrity)
        parsed_native_output = True
        if parsed.integrity.dropped_records:
            raise NativeParseIntegrityError(parse_integrity)
        return _deduplicate_findings(parsed.findings)

    def parse_receipt() -> dict[str, Any] | None:
        return parse_integrity.as_dict() if parsed_native_output else None

    try:
        if control is not None:
            control.checkpoint()
        if scanner == "gitleaks":
            _refuse_source_controls(repo, scanner, (".gitleaksignore",))
            config = _trusted_tool_config(
                tool_dir, "gitleaks-owned.toml", "[extend]\nuseDefault = true\n",
            )
            out = tool_dir / "gitleaks.sarif"
            command = [
                "gitleaks", "dir", str(repo), "--config", str(config),
                "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(tool_dir),
                "--report-format", "sarif", "--report-path", str(out),
                "--exit-code", "0", "--no-banner",
            ]
            result = _invoke_run_command(scanner, command, tool_dir, timeout, tool_dir, environment, control=control)
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            findings = accept_native_parse(
                _maybe_sarif(out, scanner, repo, tool_dir, control)
            )
        elif scanner == "trivy":
            runtime_cache = _trivy_runtime_cache(inputs)
            config = _trusted_tool_config(tool_dir, "trivy-owned.yaml", "{}\n")
            ignore = _trusted_tool_config(tool_dir, "trivy-owned-ignore.txt", "")
            secret_config = _trusted_tool_config(tool_dir, "trivy-owned-secret.yaml", "{}\n")
            owned_controls = [
                "--config", str(config), "--ignorefile", str(ignore),
                "--secret-config", str(secret_config),
            ]
            source_out = tool_dir / "trivy-source.sarif"
            source_command = [
                "trivy",
                "fs",
                *owned_controls,
                "--format",
                "sarif",
                "--output",
                str(source_out),
                "--scanners",
                "vuln,secret,misconfig",
                "--cache-dir",
                str(runtime_cache),
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--disable-telemetry",
                "--skip-version-check",
                str(repo),
            ]
            source_result = _invoke_run_command(
                "trivy-source",
                source_command,
                tool_dir,
                extended_timeout,
                tool_dir,
                environment,
                control=control,
            )
            exit_code = source_result.returncode
            _validate_native_exit_code(scanner, exit_code)
            source_findings = accept_native_parse(
                _required_sarif(source_out, scanner, repo, tool_dir, control)
            )

            # Trivy 0.73.0's source-oriented ``fs`` target deliberately scans
            # lockfiles and IaC but does not analyze standalone JAR/WAR/EAR
            # artifacts. A second bounded library-only ``rootfs`` pass is
            # therefore required to exercise the immutable Java DB and avoid
            # silently omitting packaged Java dependencies.
            out = tool_dir / "trivy-artifacts.sarif"
            artifact_command = [
                "trivy",
                "rootfs",
                *owned_controls,
                "--format",
                "sarif",
                "--output",
                str(out),
                "--scanners",
                "vuln",
                "--pkg-types",
                "library",
                "--parallel",
                "1",
                "--cache-dir",
                str(runtime_cache),
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--disable-telemetry",
                "--skip-version-check",
                str(repo),
            ]
            result = _invoke_run_command(
                "trivy-artifacts",
                artifact_command,
                tool_dir,
                extended_timeout,
                tool_dir,
                environment,
                control=control,
            )
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            artifact_findings = accept_native_parse(
                _required_sarif(out, scanner, repo, tool_dir, control)
            )
            findings = _deduplicate_findings(
                [*source_findings, *artifact_findings]
            )
        elif scanner == "opengrep":
            resolved_rules = _required_runtime_component(
                inputs,
                "opengrep-reviewed-rules",
            )
            rules_path = _opengrep_rules_path(
                str(resolved_rules / OPENGREP_RULE_ENTRYPOINT),
                resolved_rules,
            )
            if rules_path is None:
                return ToolRunResult(
                    scanner=scanner,
                    status="failed",
                    error="offline_rules_unavailable: active OpenGrep rule generation is invalid",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            out = tool_dir / "opengrep.sarif"
            command = [
                "opengrep",
                "scan",
                "--config",
                rules_path.name,
                "--sarif",
                "--output",
                str(out),
                str(repo),
            ]
            result = _invoke_run_command(
                scanner,
                command,
                rules_path.parent,
                timeout,
                tool_dir,
                environment,
                control=control,
            )
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            findings = accept_native_parse(
                _maybe_sarif(out, scanner, repo, tool_dir, control)
            )
        elif scanner == "bearer":
            resolved_rules = _required_runtime_component(inputs, "bearer-rules")
            rules_path = _opengrep_rules_path(str(resolved_rules), resolved_rules)
            if rules_path is None:
                return ToolRunResult(
                    scanner=scanner,
                    status="failed",
                    error="offline_rules_unavailable: active Bearer rule generation is invalid",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            out = tool_dir / "bearer.json"
            config = _trusted_tool_config(tool_dir, "bearer-owned.yaml", "{}\n")
            command = [
                "bearer",
                "scan",
                str(repo),
                "--config-file",
                str(config),
                "--format",
                "jsonv2",
                "--output",
                str(out),
                "--disable-version-check",
                "--disable-default-rules",
                "--external-rule-dir",
                str(rules_path),
            ]
            result = _invoke_run_command(scanner, command, tool_dir, timeout, tool_dir, environment, control=control)
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            if not out.exists():
                raise RuntimeError("required_output_missing")
            if out.exists():
                raw_path = _raw_file(out, tool_dir)
                if raw_path.stat().st_size > MAX_NATIVE_FINDINGS_BYTES:
                    raise BearerReportError("bearer_native_report_invalid")
                with raw_path.open("rb") as stream:
                    raw = stream.read(MAX_NATIVE_FINDINGS_BYTES + 1)
                if exit_code == 1 and raw in {
                    text.encode("utf-8") for text in _BEARER_UNSUPPORTED_SOURCE_REPORTS
                }:
                    parse_integrity.filter("source_language_not_supported")
                    parsed_native_output = True
                    bearer_unsupported_source = True
            if not bearer_unsupported_source:
                if control is not None:
                    control.checkpoint()
                findings = accept_native_parse(
                    _parse_bearer_jsonv2(raw, repo, control)
                )
                if control is not None:
                    control.checkpoint()
        elif scanner == "grype":
            out = tool_dir / "grype.sarif"
            sbom = (inputs or {}).get("syft_sbom")
            if sbom is None:
                return ToolRunResult(
                    scanner=scanner,
                    status="failed",
                    error="syft_sbom_unavailable",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            if sbom.is_symlink():
                raise RuntimeError("Syft dependency artifact must not be a symlink")
            try:
                sbom = sbom.resolve(strict=True)
                sbom.relative_to(publish_root.resolve(strict=True))
            except (OSError, RuntimeError, ValueError) as exc:
                raise RuntimeError("Syft dependency artifact escapes this scan publication root") from exc
            if not sbom.is_file():
                raise RuntimeError("Syft dependency artifact is not a regular file")
            database = _required_runtime_component(inputs, "grype-db")
            environment.update(
                {
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                    "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_DB_CACHE_DIR": str(database),
                    # One immutable generation is already fail-closed against
                    # its reviewed receipt window before its roots are resolved.
                    # Do not let Grype's separate wall-clock check invalidate
                    # that admitted snapshot while the same scan is running.
                    "GRYPE_DB_VALIDATE_AGE": "false",
                }
            )
            result = _invoke_run_command(
                scanner,
                ["grype", f"sbom:{sbom}", "-o", "sarif", "--file", str(out)],
                tool_dir,
                extended_timeout,
                tool_dir,
                environment,
                control=control,
            )
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            findings = accept_native_parse(
                _maybe_sarif(out, scanner, repo, tool_dir, control)
            )
        elif scanner == "checkov":
            _refuse_source_controls(repo, scanner, (".checkov.yaml", ".checkov.yml"))
            config = _trusted_tool_config(tool_dir, "checkov-owned.yaml", "{}\n")
            # Checkov 3.3.10 config_utils discovers target configs only for a
            # standalone -d/--directory token. The supported joined argparse
            # spelling preserves directory scan context without that read,
            # including controls created after our conservative root check.
            # A pinned native discovery canary must pass before a tool upgrade.
            command = [
                "checkov", f"--directory={repo}", "--config-file", str(config),
                "--framework", "kubernetes,dockerfile,terraform", "--output", "sarif",
                "--output-file-path", str(tool_dir) + "/", "--skip-download", "--soft-fail",
            ]
            result = _invoke_run_command(scanner, command, tool_dir, timeout, tool_dir, environment, control=control)
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            out = tool_dir / "results_sarif.sarif"
            findings = accept_native_parse(
                _maybe_sarif(out, scanner, repo, tool_dir, control, checkov_cwd=tool_dir)
            )
        elif scanner == "trufflehog":
            out = tool_dir / "trufflehog.jsonl"
            result = _invoke_run_command(
                scanner,
                ["trufflehog", "filesystem", str(repo), "--json", "--no-update", "--no-verification"],
                tool_dir,
                timeout,
                tool_dir,
                environment,
                stdout_path=out,
                control=control,
            )
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            if not out.exists():
                raise RuntimeError("TruffleHog did not produce its required JSONL output")
            raw_path = _raw_file(out, tool_dir)
            if raw_path.stat().st_size > MAX_NATIVE_FINDINGS_BYTES:
                raise RuntimeError("native scanner findings exceed the processing size limit")
            findings = accept_native_parse(
                _parse_trufflehog(raw_path, repo, control)
            )
        elif scanner == "syft":
            out = tool_dir / "syft.cyclonedx.json"
            environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
            result = _invoke_run_command(
                scanner,
                ["syft", f"dir:{repo}", "-o", f"cyclonedx-json={out}"],
                tool_dir,
                timeout,
                tool_dir,
                environment,
                control=control,
            )
            exit_code = result.returncode
            _validate_native_exit_code(scanner, exit_code)
            if not out.exists() or out.stat().st_size == 0:
                raise RuntimeError("Syft did not produce its required CycloneDX output")
            artifacts.append(_publish_sanitized_sbom(out, tool_dir, publish_root, repo))
        else:
            error = "unsupported_external_tool"
        if control is not None:
            control.checkpoint()
    except (RunCancelled, RunDeadlineExceeded):
        raise
    except FileNotFoundError:
        return ToolRunResult(scanner=scanner, status="unavailable", error="binary_not_found", duration_ms=int((time.monotonic() - started) * 1000))
    except subprocess.TimeoutExpired:
        return ToolRunResult(scanner=scanner, status="failed", error="timeout", duration_ms=int((time.monotonic() - started) * 1000))
    except NativeExitError:
        return ToolRunResult(
            scanner=scanner,
            status="failed",
            error="unexpected_native_exit_code",
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=exit_code,
            parse_integrity=parse_receipt(),
        )
    except NativeParseIntegrityError as exc:
        return ToolRunResult(
            scanner=scanner,
            status="failed",
            error="native_output_integrity_failed",
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=exit_code,
            parse_integrity=exc.integrity.as_dict(),
        )
    except SourceConfigurationError as exc:
        return ToolRunResult(
            scanner=scanner,
            status="failed",
            error=str(exc),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except BearerReportError as exc:
        return ToolRunResult(
            scanner=scanner,
            status="failed",
            error=exc.code,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=exit_code,
        )
    except Exception as exc:
        if str(exc) == "required_output_missing":
            return ToolRunResult(
                scanner=scanner,
                status="failed",
                error="required_output_missing",
                duration_ms=int((time.monotonic() - started) * 1000),
                exit_code=exit_code,
                parse_integrity=parse_receipt(),
            )
        detail = redact_text(str(exc)) or "tool execution failed"
        return ToolRunResult(
            scanner=scanner,
            status="failed",
            error=f"{type(exc).__name__}: {detail}"[:400],
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=exit_code,
            parse_integrity=parse_receipt(),
        )

    if scanner not in {"syft", "trufflehog"} and error is None:
        expected_output = locals().get("out")
        if not isinstance(expected_output, Path) or not expected_output.exists() or expected_output.stat().st_size == 0:
            return ToolRunResult(
                scanner=scanner,
                status="failed",
                error="required_output_missing",
                duration_ms=int((time.monotonic() - started) * 1000),
                exit_code=exit_code,
                parse_integrity=parse_receipt(),
            )

    status = "completed" if error is None else "failed"
    if scanner == "bearer" and exit_code == 1:
        if findings:
            status = "completed_with_exit_code"
        elif bearer_unsupported_source:
            status = "completed"
        else:
            status = "failed"
            error = "bearer_findings_exit_without_findings"
    return ToolRunResult(
        scanner=scanner,
        status=status,
        findings=findings,
        artifacts=artifacts,
        error=error,
        duration_ms=int((time.monotonic() - started) * 1000),
        exit_code=exit_code,
        parse_integrity=parse_receipt(),
    )
