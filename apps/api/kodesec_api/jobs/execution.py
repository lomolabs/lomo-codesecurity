from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import nullcontext
import hashlib
import hmac
import json
import logging
import math
import posixpath
import re
from threading import Event, Lock, Thread
import time
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid5

import httpx
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import case, func, insert, select
from sqlalchemy.exc import SQLAlchemyError

from ..recovery_contract import RecoveryBudget, RecoveryTarget, RecoveryResult, RecoveryIntent, recovery_digest
from ..preparation_budget import (
    PreparationBudget,
    PreparationClock,
    PreparationDeadlineExceeded,
    budget_remaining,
    moment as budget_moment,
)
from .. import main as domain
from . import advisor
from .commands import (
    AdvisorSelectionError,
    InvalidScanCommandSnapshot,
    advisor_selection_snapshot,
    scan_command_snapshot,
)
from ..advisor import disclosure as advisor_disclosure
from ..advisor import grants as advisor_grants
from ..advisor import providers as advisor_providers
from ..artifact_boundary import (
    ArtifactAttestationError,
    ArtifactBoundaryError,
    admit_scan_artifacts,
    prepare_scan_artifact_provenance,
)
from ..db import Runtime
from ..models import Finding, Job, Project, Scan, ScanArtifact, ScannerLifecycleState, ScannerToolState
from ..redaction import redact_finding_payload
from ..source_snapshots import (
    SourceSnapshotError,
    is_source_snapshot_project,
    source_snapshot_project_source_id,
    validate_source_snapshot,
)
from ..schemas import (
    SCANNER_CATALOG_COMPONENT_STATES,
    SCANNER_CATALOG_TOOL_STATES,
    SCANNER_SOURCE_INTRINSIC_CACHE_COMPONENT_IDS,
    ScannerPreparationContinuation,
    normalize_scan_target_path,
)
from .liveness import record_worker_heartbeat
from ..worker_health import record_process_heartbeat
from .repository import (
    IdempotencyConflictError,
    InvalidJobTransition,
    LeaseLostError,
    complete_job,
    enqueue_job,
    fail_job,
    finalize_cancelled,
    heartbeat_job,
    lock_advisor_admission,
    mark_job_running,
    request_cancellation,
    update_job_progress,
)


LOGGER = logging.getLogger(__name__)
_SCANNER_TERMINAL = frozenset({"completed", "failed", "cancelled"})
_UPDATER_JOB_KINDS = frozenset(
    {"scanner_catalog_check", "scanner_cache_update", "scanner_cache_rollback", "scanner_cache_reconcile"}
)
_UPDATER_TERMINAL = frozenset({"completed", "failed", "cancelled"})
_SAFE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_CACHE_COMPONENT_IDS = frozenset(
    {
        "trivy-db",
        "trivy-java-db",
        "trivy-checks",
        "opengrep-reviewed-rules",
        "bearer-rules",
        "grype-db",
    }
)
_EXTERNAL_TOOL_IDS = tuple(
    sorted(
        {
            "trivy",
            "gitleaks",
            "opengrep",
            "bearer",
            "grype",
            "checkov",
            "trufflehog",
            "syft",
        }
    )
)
_UPDATER_STAGES = frozenset(
    {
        "queued",
        "resolving_lock",
        "discovering",
        "validating_active",
        "downloading",
        "validating_source",
        "retaining",
        "staging",
        "validating_generation",
        "committing",
        "activating",
        "rolling_back",
        "completed",
        "failed",
        "cancelled",
    }
)
_UPDATER_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "operation_id",
        "request_digest",
        "kind",
        "requested_components",
        "status",
        "stage",
        "attempt",
        "max_attempts",
        "cancel_requested_at",
        "created_at",
        "started_at",
        "finished_at",
        "updated_at",
        "last_activity_at",
        "activity",
        "result",
        "error_code",
        "error_detail",
    }
)
_UPDATER_ACTIVITY_KEYS = frozenset(
    {
        "component_id",
        "component_index",
        "component_total",
        "bytes_completed",
        "bytes_total",
    }
)
_MAX_UPDATER_ACTIVITY_BYTES = 4 * 1024 * 1024 * 1024
_SAFE_UPDATER_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,511}\Z")
_SAFE_UPDATER_VERSION = re.compile(r"v?[0-9][0-9A-Za-z._+\-]{0,79}\Z")
_SAFE_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_UPDATER_RECEIPT_BYTES = 16 * 1024
_UPDATER_STATUS_POLL_SECONDS = 2.0
_UPDATER_UNCHANGED_POLL_SECONDS = 10.0


def _updater_poll_interval_seconds(
    previous: dict[str, Any], current: dict[str, Any]
) -> float:
    """Back off when only the updater's storage heartbeat changed."""

    meaningful_fields = ("status", "stage", "last_activity_at", "activity")
    if all(previous.get(field) == current.get(field) for field in meaningful_fields):
        return _UPDATER_UNCHANGED_POLL_SECONDS
    return _UPDATER_STATUS_POLL_SECONDS

_SCANNER_MAX_FINDINGS = 50_000
_SCANNER_MAX_ITEM_BYTES = 32 * 1024
_SCANNER_MAX_PAGE_BYTES = 4 * 1024 * 1024
_SCANNER_PAGE_ENVELOPE_BYTES = 16 * 1024
_SCANNER_PAGE_LIMIT = 128
_SCANNER_MAX_RUN_BYTES = 336 * 1024 * 1024
_SCANNER_MAX_SUMMARY_BYTES = 256 * 1024
_SCANNER_MAX_MANIFEST_BYTES = 1024 * 1024
_SCANNER_MAX_STATE_BYTES = _SCANNER_MAX_MANIFEST_BYTES + 16 * 1024
_SCANNER_MAX_ACK_BYTES = 16 * 1024
_SCANNER_MAX_ARTIFACTS = 128
_SCANNER_MAX_METADATA_BYTES = 4 * 1024
_SCANNER_MAX_MESSAGE_JSON_BYTES = 4 * 1024
_SCANNER_MAX_SNIPPET_JSON_BYTES = 16 * 1024
_SCANNER_MAX_PATH_BYTES = 4096
_SCANNER_MAX_INTEGER = 2_147_483_647
_SCANNER_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_SCANNER_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SCANNER_STATE_KEYS = frozenset(
    {
        "run_id",
        "request_digest",
        "status",
        "created_at",
        "started_at",
        "finished_at",
        "deadline_at",
        "expires_at",
        "error_code",
        "error_detail",
        "result_manifest",
        "result_available",
    }
)


def _scanner_state_identity(state: dict[str, Any]) -> tuple[Any, ...]:
    """Return only scanner fields whose change is meaningful operator activity."""

    return tuple(
        state.get(name)
        for name in (
            "status",
            "started_at",
            "finished_at",
            "expires_at",
            "error_code",
            "error_detail",
            "result_available",
        )
    )


def _scanner_poll_interval_seconds(
    *,
    base_seconds: float,
    heartbeat_seconds: float,
    unchanged_polls: int,
) -> float:
    """Back off unchanged scanner states without exceeding lease liveness cadence."""

    bounded_unchanged = min(max(unchanged_polls, 0), 16)
    return min(
        max(base_seconds, heartbeat_seconds),
        base_seconds * (2**bounded_unchanged),
    )


_SCANNER_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "result_digest",
        "findings_digest",
        "findings_total",
        "findings_bytes",
        "page_count",
        "page_limit",
        "summary",
        "artifacts",
    }
)
_SCANNER_PAGE_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "request_digest",
        "result_digest",
        "findings_total",
        "start_ordinal",
        "items",
        "items_bytes",
        "page_digest",
        "truncated",
        "next_cursor",
    }
)
_SCANNER_FINDING_KEYS = frozenset(
    {
        "scanner",
        "rule_id",
        "severity",
        "file_path",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "message",
        "code_snippet",
        "fingerprint",
        "metadata",
    }
)
_SCANNER_ARTIFACT_KEYS = frozenset(
    {"scanner", "artifact_type", "format", "path", "size_bytes", "sha256"}
)
_SCANNER_ACK_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "request_digest",
        "result_digest",
        "acknowledged",
        "result_available",
    }
)


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise JobExecutionError("scanner_protocol", "Scanner returned non-canonical JSON evidence.") from exc


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value}")


def _strict_int(value: Any, *, minimum: int = 0, maximum: int = _SCANNER_MAX_INTEGER) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid bounded integer.")
    return value


def _strict_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SAFE_SHA256.fullmatch(value) is None:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid evidence digest.")
    return value


def _strict_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise JobExecutionError("scanner_protocol", "Scanner JSON evidence exceeds its nesting limit.")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise JobExecutionError("scanner_protocol", "Scanner JSON evidence contains a non-finite number.")
        return
    if isinstance(value, list):
        for item in value:
            _strict_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise JobExecutionError("scanner_protocol", "Scanner JSON evidence contains an invalid key.")
            _strict_json_value(item, depth=depth + 1)
        return
    raise JobExecutionError("scanner_protocol", "Scanner returned a non-JSON evidence value.")


def _strict_bounded_text(value: Any, *, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value or (not allow_empty and not value):
        raise JobExecutionError("scanner_protocol", "Scanner returned invalid bounded text evidence.")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise JobExecutionError("scanner_protocol", "Scanner returned invalid UTF-8 evidence.") from exc
    if size > maximum:
        raise JobExecutionError("scanner_protocol", "Scanner text evidence exceeds its byte limit.")
    return value


def _strict_job_snapshot_text(value: Any, *, maximum: int) -> str:
    """Admit one safe, canonical single-line value from a durable job payload."""

    if not isinstance(value, str):
        raise JobExecutionError(
            "invalid_payload", "Scan readiness evidence contains invalid text."
        )
    try:
        encoded_size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise JobExecutionError(
            "invalid_payload", "Scan readiness evidence contains invalid text."
        ) from exc
    if (
        not value
        or value != value.strip()
        or encoded_size > maximum
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
            for character in value
        )
    ):
        raise JobExecutionError(
            "invalid_payload", "Scan readiness evidence contains invalid text."
        )
    return value


def _strict_scan_tool_ids(value: Any, *, field: str, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) for item in value)
        or value != sorted(set(value))
        or set(value) - set(domain.SCANNER_TOOL_REGISTRY)
    ):
        raise JobExecutionError(
            "invalid_payload", f"Scan job has an invalid {field} snapshot."
        )
    return list(value)


def _validated_scan_target(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    raw_target_path = payload.get("target_path")
    raw_target_kind = payload.get("target_kind")
    try:
        target_path = (
            normalize_scan_target_path(raw_target_path)
            if isinstance(raw_target_path, str)
            else None
        )
    except ValueError as exc:
        raise JobExecutionError(
            "invalid_payload",
            "Scan job has an invalid selected source target.",
        ) from exc
    if (
        (raw_target_path is None) != (raw_target_kind is None)
        or raw_target_path is not None and target_path is None
        or raw_target_kind is not None
        and (
            not isinstance(raw_target_kind, str)
            or raw_target_kind not in {"file", "directory"}
        )
    ):
        raise JobExecutionError(
            "invalid_payload",
            "Scan job has an invalid selected source target.",
        )
    return target_path, raw_target_kind


def _validated_scan_source_snapshot_digest(payload: dict[str, Any]) -> str | None:
    value = payload.get("source_snapshot_digest")
    if value is None:
        return None
    if not isinstance(value, str) or _SAFE_SHA256.fullmatch(value) is None:
        raise JobExecutionError(
            "invalid_payload",
            "Scan job has an invalid native source snapshot binding.",
        )
    return value


def _validated_scan_coverage_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the immutable complete/limited scanner selection before source work."""

    coverage = payload.get("coverage", "complete")
    if coverage not in {"complete", "limited"}:
        raise JobExecutionError("invalid_payload", "Scan job has an invalid coverage mode.")
    enabled_tools = _strict_scan_tool_ids(
        payload.get("enabled_tools"), field="enabled-tools"
    )
    requested_tools = _strict_scan_tool_ids(
        payload.get("requested_tools", enabled_tools), field="requested-tools"
    )
    preflight_revision = payload.get("preflight_revision")
    if preflight_revision is not None and (
        not isinstance(preflight_revision, str)
        or _SAFE_SHA256.fullmatch(preflight_revision) is None
    ):
        raise JobExecutionError(
            "invalid_payload", "Scan job has an invalid preflight revision."
        )

    omitted_raw = payload.get("omitted_tools", [])
    if coverage == "complete":
        if requested_tools != enabled_tools or omitted_raw != []:
            raise JobExecutionError(
                "invalid_payload",
                "Complete scan tool evidence is internally inconsistent.",
            )
        return {
            "coverage": coverage,
            "preflight_revision": preflight_revision,
            "requested_tools": requested_tools,
            "enabled_tools": enabled_tools,
            "omitted_tools": [],
        }

    if preflight_revision is None or not isinstance(omitted_raw, list) or not omitted_raw:
        raise JobExecutionError(
            "invalid_payload", "Limited scan omitted-tool evidence is incomplete."
        )
    omitted_tools: list[dict[str, Any]] = []
    omitted_ids: list[str] = []
    expected_keys = {
        "id",
        "name",
        "blocking_reasons",
        "required_component_ids",
        "preparation_blocking_reasons",
    }
    for item in omitted_raw:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise JobExecutionError(
                "invalid_payload", "Limited scan omitted-tool evidence is invalid."
            )
        tool_id = item.get("id")
        if not isinstance(tool_id, str) or tool_id not in _EXTERNAL_TOOL_IDS:
            raise JobExecutionError(
                "invalid_payload", "Limited scan omitted-tool identity is invalid."
            )
        name = _strict_job_snapshot_text(item.get("name"), maximum=120)
        reasons_raw = item.get("blocking_reasons")
        if (
            not isinstance(reasons_raw, list)
            or not 1 <= len(reasons_raw) <= 4
            or len(set(reasons_raw)) != len(reasons_raw)
        ):
            raise JobExecutionError(
                "invalid_payload", "Limited scan blocking reasons are invalid."
            )
        reasons = [
            _strict_job_snapshot_text(reason, maximum=512) for reason in reasons_raw
        ]
        preparation_reasons_raw = item.get("preparation_blocking_reasons")
        if (
            not isinstance(preparation_reasons_raw, list)
            or len(preparation_reasons_raw) > 4
            or len(set(preparation_reasons_raw)) != len(preparation_reasons_raw)
        ):
            raise JobExecutionError(
                "invalid_payload",
                "Limited scan preparation-blocking reasons are invalid.",
            )
        preparation_reasons = [
            _strict_job_snapshot_text(reason, maximum=512)
            for reason in preparation_reasons_raw
        ]
        if set(preparation_reasons) - set(reasons):
            raise JobExecutionError(
                "invalid_payload",
                "Limited scan preparation-blocking reasons are inconsistent.",
            )
        components_raw = item.get("required_component_ids")
        if (
            not isinstance(components_raw, list)
            or len(components_raw) > len(_CACHE_COMPONENT_IDS)
            or any(not isinstance(component, str) for component in components_raw)
            or components_raw != sorted(set(components_raw))
            or set(components_raw) - _CACHE_COMPONENT_IDS
        ):
            raise JobExecutionError(
                "invalid_payload", "Limited scan required-component evidence is invalid."
            )
        omitted_ids.append(tool_id)
        omitted_tools.append(
            {
                "id": tool_id,
                "name": name,
                "blocking_reasons": reasons,
                "required_component_ids": list(components_raw),
                "preparation_blocking_reasons": preparation_reasons,
            }
        )
    if omitted_ids != sorted(set(omitted_ids)):
        raise JobExecutionError(
            "invalid_payload", "Limited scan omitted tools are not canonical."
        )
    if set(enabled_tools) & set(omitted_ids) or set(requested_tools) != (
        set(enabled_tools) | set(omitted_ids)
    ):
        raise JobExecutionError(
            "invalid_payload", "Limited scan tool evidence is internally inconsistent."
        )
    return {
        "coverage": coverage,
        "preflight_revision": preflight_revision,
        "requested_tools": requested_tools,
        "enabled_tools": enabled_tools,
        "omitted_tools": omitted_tools,
    }


def _strict_evidence_text(value: Any, *, maximum_json_bytes: int, allow_empty: bool) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise JobExecutionError("scanner_protocol", "Scanner returned invalid text evidence.")
    if len(_canonical_json_bytes(value)) > maximum_json_bytes:
        raise JobExecutionError("scanner_protocol", "Scanner text evidence exceeds its JSON byte limit.")
    return value


def _scanner_manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "schema_version": manifest["schema_version"],
                "status": manifest["status"],
                "findings_digest": manifest["findings_digest"],
                "findings_total": manifest["findings_total"],
                "findings_bytes": manifest["findings_bytes"],
                "page_count": manifest["page_count"],
                "page_limit": manifest["page_limit"],
                "summary": manifest["summary"],
                "artifacts": manifest["artifacts"],
            }
        )
    ).hexdigest()


def _strict_scanner_artifact(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SCANNER_ARTIFACT_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid artifact declaration.")
    if (
        value.get("scanner") != "syft"
        or value.get("artifact_type") != "sbom"
        or value.get("format") != "cyclonedx-json"
    ):
        raise JobExecutionError("scanner_protocol", "Scanner returned an unsupported artifact declaration.")
    path = _strict_bounded_text(value.get("path"), maximum=_SCANNER_MAX_PATH_BYTES)
    parts = path.split("/")
    if (
        not path.startswith("/")
        or path == "/"
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or any(part in {"", ".", ".."} for part in parts[1:])
        or posixpath.normpath(path) != path
    ):
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid artifact path.")
    return {
        "scanner": "syft",
        "artifact_type": "sbom",
        "format": "cyclonedx-json",
        "path": path,
        "size_bytes": _strict_int(value.get("size_bytes"), maximum=8 * 1024 * 1024),
        "sha256": _strict_sha256(value.get("sha256")),
    }


def _strict_scanner_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid result summary.")
    _strict_json_value(value)
    if len(_canonical_json_bytes(value)) > _SCANNER_MAX_SUMMARY_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner result summary exceeds its byte limit.")
    return value


def _strict_scanner_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SCANNER_MANIFEST_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid immutable manifest.")
    if len(_canonical_json_bytes(value)) > _SCANNER_MAX_MANIFEST_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner result manifest exceeds its byte limit.")
    if value.get("schema_version") != 1 or isinstance(value.get("schema_version"), bool):
        raise JobExecutionError("scanner_protocol", "Scanner returned an unsupported manifest schema.")
    status = value.get("status")
    if status not in {"completed", "partial"}:
        raise JobExecutionError("scanner_protocol", "Scanner manifest has an unusable status.")
    total = _strict_int(value.get("findings_total"), maximum=_SCANNER_MAX_FINDINGS)
    findings_bytes = _strict_int(value.get("findings_bytes"), maximum=_SCANNER_MAX_RUN_BYTES)
    page_count = _strict_int(value.get("page_count"), maximum=_SCANNER_MAX_FINDINGS)
    if value.get("page_limit") != _SCANNER_PAGE_LIMIT or isinstance(value.get("page_limit"), bool):
        raise JobExecutionError("scanner_protocol", "Scanner manifest page limit is invalid.")
    minimum_pages = (total + _SCANNER_PAGE_LIMIT - 1) // _SCANNER_PAGE_LIMIT if total else 0
    if not minimum_pages <= page_count <= total:
        raise JobExecutionError("scanner_protocol", "Scanner manifest page count is inconsistent.")
    if (total == 0) != (findings_bytes == 0 and page_count == 0):
        raise JobExecutionError("scanner_protocol", "Scanner manifest empty-result bounds are inconsistent.")
    summary = _strict_scanner_summary(value.get("summary"))
    if summary.get("findings_total") != total:
        raise JobExecutionError("scanner_protocol", "Scanner summary total does not match the manifest.")
    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > _SCANNER_MAX_ARTIFACTS:
        raise JobExecutionError("scanner_protocol", "Scanner artifact collection exceeds its bound.")
    artifacts = [_strict_scanner_artifact(item) for item in raw_artifacts]
    normalized = {
        "schema_version": 1,
        "status": status,
        "result_digest": _strict_sha256(value.get("result_digest")),
        "findings_digest": _strict_sha256(value.get("findings_digest")),
        "findings_total": total,
        "findings_bytes": findings_bytes,
        "page_count": page_count,
        "page_limit": _SCANNER_PAGE_LIMIT,
        "summary": summary,
        "artifacts": artifacts,
    }
    if findings_bytes + len(_canonical_json_bytes(normalized)) > _SCANNER_MAX_RUN_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner result exceeds its combined byte limit.")
    if not hmac.compare_digest(normalized["result_digest"], _scanner_manifest_digest(normalized)):
        raise JobExecutionError("scanner_protocol", "Scanner result manifest digest does not reconcile.")
    return normalized


def _strict_scanner_finding(value: Any) -> tuple[dict[str, Any], bytes]:
    if not isinstance(value, dict) or set(value) != _SCANNER_FINDING_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid finding shape.")
    scanner = _strict_bounded_text(value.get("scanner"), maximum=80)
    rule_id = _strict_bounded_text(value.get("rule_id"), maximum=160)
    if scanner != scanner.strip() or rule_id != rule_id.strip():
        raise JobExecutionError("scanner_protocol", "Scanner returned non-canonical identity text.")
    severity = value.get("severity")
    if not isinstance(severity, str) or severity not in _SCANNER_SEVERITIES:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid finding severity.")
    file_path = _strict_bounded_text(value.get("file_path"), maximum=_SCANNER_MAX_PATH_BYTES)
    if domain._normalized_finding_path(file_path) != file_path:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid project-relative path.")

    coordinates: dict[str, int | None] = {}
    for name in ("start_line", "start_column", "end_line", "end_column"):
        coordinate = value.get(name)
        coordinates[name] = (
            None
            if coordinate is None
            else _strict_int(coordinate, minimum=1, maximum=_SCANNER_MAX_INTEGER)
        )
    start_line = coordinates["start_line"]
    end_line = coordinates["end_line"]
    start_column = coordinates["start_column"]
    end_column = coordinates["end_column"]
    if start_line is None:
        if any(item is not None for item in (end_line, start_column, end_column)):
            raise JobExecutionError("scanner_protocol", "Scanner finding location is inconsistent.")
    elif (
        end_line is None
        or end_line < start_line
        or (start_column is None and end_column is not None)
        or (
            start_column is not None
            and end_column is not None
            and start_line == end_line
            and end_column < start_column
        )
    ):
        raise JobExecutionError("scanner_protocol", "Scanner finding location is inconsistent.")

    message = _strict_evidence_text(
        value.get("message"),
        maximum_json_bytes=_SCANNER_MAX_MESSAGE_JSON_BYTES,
        allow_empty=False,
    )
    raw_snippet = value.get("code_snippet")
    snippet = None
    if raw_snippet is not None:
        snippet = _strict_evidence_text(
            raw_snippet,
            maximum_json_bytes=_SCANNER_MAX_SNIPPET_JSON_BYTES,
            allow_empty=True,
        )
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise JobExecutionError("scanner_protocol", "Scanner finding metadata is invalid.")
    _strict_json_value(metadata)
    if len(_canonical_json_bytes(metadata)) > _SCANNER_MAX_METADATA_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner finding metadata exceeds its byte limit.")
    normalized = {
        "scanner": scanner,
        "rule_id": rule_id,
        "severity": severity,
        "file_path": file_path,
        **coordinates,
        "message": message,
        "code_snippet": snippet,
        "fingerprint": _strict_sha256(value.get("fingerprint")),
        "metadata": metadata,
    }
    encoded = _canonical_json_bytes(normalized) + b"\n"
    if len(encoded) > _SCANNER_MAX_ITEM_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner finding exceeds its transport byte limit.")
    return normalized, encoded


def _strict_scanner_state(value: Any, *, run_id: str, request_digest: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SCANNER_STATE_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid run state.")
    if value.get("run_id") != run_id or value.get("request_digest") != request_digest:
        raise JobExecutionError(
            "scanner_run_conflict",
            "Scanner run identity is bound to a different immutable request.",
        )
    status = value.get("status")
    if status not in {"queued", "running", "cancelling", "completed", "failed", "cancelled"}:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid run status.")
    available = value.get("result_available")
    if not isinstance(available, bool):
        raise JobExecutionError("scanner_protocol", "Scanner run availability is invalid.")
    for name in ("created_at", "deadline_at"):
        timestamp = value.get(name)
        if not isinstance(timestamp, str):
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps are invalid.")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps are invalid.") from exc
        if parsed.tzinfo is None:
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps lack a timezone.")
    for name in ("started_at", "finished_at", "expires_at"):
        timestamp = value.get(name)
        if timestamp is None:
            continue
        if not isinstance(timestamp, str):
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps are invalid.")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps are invalid.") from exc
        if parsed.tzinfo is None:
            raise JobExecutionError("scanner_protocol", "Scanner run timestamps lack a timezone.")
    error_code = value.get("error_code")
    error_detail = value.get("error_detail")
    if error_code is not None and (
        not isinstance(error_code, str) or _SAFE_ERROR_CODE.fullmatch(error_code) is None
    ):
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid run error code.")
    if error_detail is not None:
        _strict_bounded_text(error_detail, maximum=4000, allow_empty=False)
    raw_manifest = value.get("result_manifest")
    manifest = _strict_scanner_manifest(raw_manifest) if raw_manifest is not None else None
    if status == "completed":
        if manifest is None:
            raise JobExecutionError("scanner_protocol", "Completed scanner run omitted its manifest.")
    elif manifest is not None or available:
        raise JobExecutionError("scanner_protocol", "Noncompleted scanner run exposed result evidence.")
    if available and manifest is None:
        raise JobExecutionError("scanner_protocol", "Available scanner result omitted its manifest.")
    return {**value, "result_manifest": manifest}


def _raw_scanner_result_binding(
    value: Any,
    *,
    run_id: str,
    request_digest: str,
) -> tuple[str, str, str] | None:
    """Recover only the immutable cleanup capability from a hostile state body."""

    if (
        not isinstance(value, dict)
        or value.get("run_id") != run_id
        or value.get("request_digest") != request_digest
        or value.get("status") != "completed"
    ):
        return None
    manifest = value.get("result_manifest")
    result_digest = manifest.get("result_digest") if isinstance(manifest, dict) else None
    if not isinstance(result_digest, str) or _SAFE_SHA256.fullmatch(result_digest) is None:
        return None
    return run_id, request_digest, result_digest


def _strict_scanner_page(
    value: Any,
    *,
    run_id: str,
    request_digest: str,
    manifest: dict[str, Any],
    expected_ordinal: int,
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], bytes]]]:
    if not isinstance(value, dict) or set(value) != _SCANNER_PAGE_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid finding page.")
    if len(_canonical_json_bytes(value)) > _SCANNER_MAX_PAGE_BYTES:
        raise JobExecutionError("scanner_protocol", "Scanner finding page exceeds its byte limit.")
    if value.get("schema_version") != 1 or isinstance(value.get("schema_version"), bool):
        raise JobExecutionError("scanner_protocol", "Scanner returned an unsupported finding-page schema.")
    if (
        value.get("run_id") != run_id
        or value.get("request_digest") != request_digest
        or value.get("result_digest") != manifest["result_digest"]
    ):
        raise JobExecutionError("scanner_run_conflict", "Scanner finding page has the wrong immutable binding.")
    if value.get("findings_total") != manifest["findings_total"] or isinstance(
        value.get("findings_total"), bool
    ):
        raise JobExecutionError("scanner_protocol", "Scanner finding page total does not reconcile.")
    if value.get("start_ordinal") != expected_ordinal or isinstance(value.get("start_ordinal"), bool):
        raise JobExecutionError("scanner_protocol", "Scanner finding page ordinal is discontinuous.")
    raw_items = value.get("items")
    if not isinstance(raw_items, list) or not 1 <= len(raw_items) <= _SCANNER_PAGE_LIMIT:
        raise JobExecutionError("scanner_protocol", "Scanner finding page has an invalid item count.")
    items = [_strict_scanner_finding(item) for item in raw_items]
    encoded = b"".join(item[1] for item in items)
    items_bytes = _strict_int(
        value.get("items_bytes"),
        minimum=1,
        maximum=_SCANNER_MAX_PAGE_BYTES - _SCANNER_PAGE_ENVELOPE_BYTES,
    )
    if items_bytes != len(encoded):
        raise JobExecutionError("scanner_protocol", "Scanner finding-page byte count does not reconcile.")
    if not hmac.compare_digest(_strict_sha256(value.get("page_digest")), hashlib.sha256(encoded).hexdigest()):
        raise JobExecutionError("scanner_protocol", "Scanner finding-page digest does not reconcile.")
    truncated = value.get("truncated")
    cursor = value.get("next_cursor")
    if not isinstance(truncated, bool):
        raise JobExecutionError("scanner_protocol", "Scanner finding-page continuation is invalid.")
    if cursor is not None:
        _strict_bounded_text(cursor, maximum=2048)
    end_ordinal = expected_ordinal + len(items) - 1
    if end_ordinal > manifest["findings_total"]:
        raise JobExecutionError("scanner_protocol", "Scanner finding page exceeds the manifest total.")
    expected_truncated = end_ordinal < manifest["findings_total"]
    if truncated != expected_truncated or truncated != (cursor is not None):
        raise JobExecutionError("scanner_protocol", "Scanner finding-page continuation does not reconcile.")
    return value, items


def _strict_scanner_ack(
    value: Any,
    *,
    run_id: str,
    request_digest: str,
    result_digest: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SCANNER_ACK_KEYS:
        raise JobExecutionError("scanner_protocol", "Scanner returned an invalid acknowledgement.")
    if (
        value.get("schema_version") != 1
        or isinstance(value.get("schema_version"), bool)
        or value.get("run_id") != run_id
        or value.get("request_digest") != request_digest
        or value.get("result_digest") != result_digest
        or value.get("acknowledged") is not True
        or value.get("result_available") is not False
    ):
        raise JobExecutionError("scanner_protocol", "Scanner acknowledgement binding is invalid.")
    return value


def _scanner_request_digest(payload: dict[str, Any]) -> str:
    """Match the scanner's immutable run binding without publishing source data."""

    document = {
        key: payload.get(key)
        for key in (
            "scan_id",
            "repo_path",
            "target_path",
            "target_kind",
            "source_snapshot_digest",
            "mode",
            "base_ref",
            "head_ref",
            "enabled_tools",
        )
    }
    enabled_tools = document.get("enabled_tools")
    if enabled_tools is not None:
        document["enabled_tools"] = sorted(set(enabled_tools))
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _checkpoint_scanner_binding(
    checkpoint: dict[str, Any],
) -> tuple[str | None, str | None]:
    forbidden_keys = {"scanner_request_digest", "scanner_result_digest"}
    record = checkpoint.get("scanner_evidence")
    if record is None:
        if forbidden_keys.intersection(checkpoint):
            raise JobExecutionError(
                "scanner_protocol",
                "Durable scanner evidence used an unsupported binding representation.",
            )
        return None, None
    if (
        not isinstance(record, dict)
        or set(record) != {"request_digest", "sha256"}
        or not isinstance(record.get("request_digest"), str)
        or _SAFE_SHA256.fullmatch(record["request_digest"]) is None
        or not isinstance(record.get("sha256"), str)
        or _SAFE_SHA256.fullmatch(record["sha256"]) is None
        or forbidden_keys.intersection(checkpoint)
    ):
        raise JobExecutionError(
            "scanner_protocol",
            "Durable scanner evidence has an invalid immutable binding.",
        )
    return record["request_digest"], record["sha256"]


def _checkpoint_artifact_digest(checkpoint: dict[str, Any], name: str) -> str | None:
    forbidden_name = {
        "artifact_manifest": "artifact_manifest_digest",
        "artifact_provenance": "artifact_provenance_digest",
    }[name]
    record = checkpoint.get(name)
    if record is None:
        if forbidden_name in checkpoint:
            raise JobExecutionError(
                "scanner_protocol",
                "Durable artifact evidence used an unsupported digest representation.",
            )
        return None
    if (
        not isinstance(record, dict)
        or set(record) != {"sha256"}
        or not isinstance(record.get("sha256"), str)
        or _SAFE_SHA256.fullmatch(record["sha256"]) is None
        or forbidden_name in checkpoint
    ):
        raise JobExecutionError(
            "scanner_protocol",
            "Durable artifact evidence has an invalid immutable digest.",
        )
    return record["sha256"]


def _checkpoint_scanner_cleanup(checkpoint: dict[str, Any]) -> str | None:
    record = checkpoint.get("scanner_cleanup")
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or set(record) != {"action", "error_code"}
        or record.get("action") != "discard"
        or not isinstance(record.get("error_code"), str)
        or _SAFE_ERROR_CODE.fullmatch(record["error_code"]) is None
    ):
        raise JobExecutionError(
            "scanner_protocol",
            "Durable scanner cleanup receipt is invalid.",
        )
    return record["error_code"]


class JobExecutionError(RuntimeError):
    def __init__(
        self,
        code: str,
        detail: str,
        *,
        retryable: bool = False,
        scanner_binding: tuple[str, str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = domain._redacted_text(detail, 4000)
        self.retryable = retryable
        self.scanner_binding = scanner_binding


def _scanner_preparation_component_rejection(
    component_states: dict[str, str],
    requested: object,
) -> JobExecutionError | None:
    unavailable = (
        []
        if not isinstance(requested, list)
        else [
            component_id
            for component_id in requested
            if not isinstance(component_id, str)
            or component_states.get(component_id) not in {"current", "candidate_available"}
        ]
    )
    if unavailable and all(
        isinstance(component_id, str)
        and component_states.get(component_id) == "requires_lock_refresh"
        for component_id in unavailable
    ):
        return JobExecutionError(
            "scanner_preparation_lock_refresh_required",
            "Reviewed scanner database lock refresh required for: "
            + ", ".join(sorted(unavailable))
            + ". Get refreshed reviewed CodeSecurity source, then rerun normal startup "
            "with your existing state and editor options to rebuild changed inputs. "
            "Choose Prepare all scanners afterward.",
        )
    if not isinstance(requested, list) or unavailable:
        return JobExecutionError(
            "scanner_preparation_component_unavailable",
            "The checked catalog cannot safely prepare every required scanner item. Review scanner readiness before retrying.",
        )
    return None


def _scanner_preparation_continuation(
    catalog_job: Job,
) -> ScannerPreparationContinuation | None:
    raw = (
        catalog_job.payload.get("preparation")
        if isinstance(catalog_job.payload, dict)
        else None
    )
    if raw is None:
        return None
    if catalog_job.kind != "scanner_catalog_check":
        raise JobExecutionError(
            "invalid_payload",
            "Only a scanner catalog command may carry a preparation continuation.",
        )
    try:
        continuation = ScannerPreparationContinuation.model_validate(raw, strict=True)
    except ValidationError as exc:
        raise JobExecutionError(
            "invalid_payload",
            "Scanner preparation continuation is invalid.",
        ) from exc
    expected_digest = domain._scanner_lifecycle_digest(
        "cache_update",
        list(continuation.component_ids),
        preparation_budget=continuation.preparation_budget,
    )
    if continuation.request_digest != expected_digest:
        raise JobExecutionError(
            "invalid_payload",
            "Scanner preparation continuation does not match its required components.",
        )
    return continuation


def _enqueue_scanner_preparation_cache_continuation(
    db: Any,
    catalog_job: Job,
    catalog_result: dict[str, Any],
) -> Job | None:
    continuation = _scanner_preparation_continuation(catalog_job)
    if continuation is None:
        return None
    if (
        continuation.preparation_budget is None
        or catalog_job.payload.get("preparation_budget")
        != continuation.preparation_budget.model_dump(mode="json")
    ):
        raise JobExecutionError(
            "scanner_preparation_budget_required",
            "The legacy preparation command cannot admit new work.",
        )
    try:
        budget_remaining(
            continuation.preparation_budget,
            high_water=catalog_job.updated_at or catalog_job.created_at,
        )
    except PreparationDeadlineExceeded as exc:
        raise JobExecutionError(
            "scanner_preparation_deadline",
            "Scanner preparation exceeded its shared preparation deadline.",
        ) from exc
    components = catalog_result.get("components")
    if not isinstance(components, list):
        raise JobExecutionError(
            "scanner_preparation_catalog_invalid",
            "Scanner catalog evidence is incomplete. Run scanner preparation again.",
        )
    component_states = {
        item.get("component_id"): item.get("state")
        for item in components
        if isinstance(item, dict)
        and isinstance(item.get("component_id"), str)
        and isinstance(item.get("state"), str)
    }
    rejection = _scanner_preparation_component_rejection(
        component_states,
        list(continuation.component_ids),
    )
    if rejection is not None:
        return None
    if not catalog_job.client_id or not catalog_job.external_run_id:
        raise JobExecutionError(
            "invalid_payload",
            "Scanner preparation catalog command has no durable command identity.",
        )

    catalog_digest = catalog_result.get("catalog_digest")
    try:
        cache_digest = domain._scanner_lifecycle_digest(
            "cache_update", list(continuation.component_ids), catalog_digest, continuation.preparation_budget,
        )
    except (TypeError, ValueError) as exc:
        raise JobExecutionError("scanner_preparation_catalog_invalid", "Scanner catalog identity is invalid.") from exc

    cache_state = db.scalar(
        select(ScannerLifecycleState)
        .where(ScannerLifecycleState.id == "cache")
        .with_for_update(of=ScannerLifecycleState)
        .execution_options(populate_existing=True)
    )
    if cache_state is None:
        raise JobExecutionError(
            "lifecycle_state_conflict",
            "Scanner cache lifecycle state is unavailable.",
        )
    cache_key = f"prepare-cache:v1:{catalog_job.id}"
    external_run_id = str(
        uuid5(
            NAMESPACE_URL,
            "lomo-code-security:scanner-preparation-cache:v1:"
            f"{catalog_job.id}:{catalog_job.external_run_id}",
        )
    )
    try:
        cache_job = enqueue_job(
            db,
            kind="scanner_cache_update",
            title="Prepare verified offline scanner cache",
            client_id=catalog_job.client_id,
            idempotency_key=cache_key,
            payload={
                "v": 1,
                "operation": "cache_update",
                "request_digest": cache_digest,
                "component_ids": list(continuation.component_ids),
                "preparation_budget": continuation.preparation_budget.model_dump(mode="json"),
                "prerequisite_job_id": catalog_job.id,
                **({"catalog_digest": catalog_digest} if catalog_digest is not None else {}),
            },
            external_run_id=external_run_id,
            max_attempts=3,
        ).job
    except (IdempotencyConflictError, ValueError) as exc:
        raise JobExecutionError(
            "scanner_preparation_invalid",
            "Scanner preparation cache continuation conflicts with its durable command identity.",
        ) from exc

    if cache_state.job_id == cache_job.id:
        return cache_job
    active_cache = (
        db.get(Job, cache_state.job_id)
        if cache_state.job_id is not None
        else None
    )
    if active_cache is not None and active_cache.status in {
        "queued",
        "leased",
        "running",
        "cancelling",
    }:
        raise JobExecutionError(
            "scanner_preparation_cache_conflict",
            "Another scanner cache command became active before catalog validation completed.",
            retryable=True,
        )
    cache_state.status = "queued"
    cache_state.job_id = cache_job.id
    cache_state.receipt = {}
    cache_state.error_code = None
    cache_state.error_detail = None
    cache_state.started_at = None
    cache_state.completed_at = None
    cache_state.updated_at = datetime.now(timezone.utc)
    cache_state.revision += 1
    db.add(cache_state)
    return cache_job


class CancellationRequested(RuntimeError):
    pass


class ScannerRecoveryPending(RuntimeError):
    """Leave a proven external/durable reconciliation under its current lease."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    id: int
    kind: str
    status: str
    stage: str | None
    attempt: int
    max_attempts: int
    scan_id: int | None
    finding_id: int | None
    external_run_id: str | None
    payload: dict[str, Any]
    checkpoint: dict[str, Any]
    updated_at: datetime | None = None

    @classmethod
    def from_model(cls, job: Job) -> ClaimedJob:
        return cls(
            id=job.id,
            kind=job.kind,
            status=job.status,
            stage=job.stage,
            attempt=job.attempt,
            max_attempts=job.max_attempts,
            scan_id=job.scan_id,
            finding_id=job.finding_id,
            external_run_id=job.external_run_id,
            payload=dict(job.payload or {}),
            checkpoint=dict(job.checkpoint or {}),
            updated_at=job.updated_at,
        )


@dataclass(frozen=True, slots=True)
class ExecutionCompletion:
    detail: str
    result_ref: str | None = None
    scan_id: int | None = None
    scan_status: str | None = None
    lifecycle_scope: str | None = None
    lifecycle_receipt: dict[str, Any] | None = None
    active_generation: str | None = None
    previous_generation: str | None = None
    advisor_provider_id: str | None = None
    advisor_provider_action: str | None = None
    advisor_provider_snapshot: dict[str, Any] | None = None
    advisor_provider_receipt: dict[str, Any] | None = None
    advisor_content_disclosure_approved: bool = False


@dataclass(frozen=True, slots=True)
class _ScannerReply:
    status_code: int
    value: Any | None


class LeaseMonitor:
    """Renew one lease on a dedicated short-lived session.

    Scanner and Ollama calls may block longer than one lease. Keeping this
    narrow monitor separate avoids holding a database transaction open during
    local HTTP work while preserving fencing by worker ID and attempt.
    """

    def __init__(self, runtime: Runtime, job: ClaimedJob, worker_id: str) -> None:
        self.runtime = runtime
        self.job = job
        self.worker_id = worker_id
        self.cancel_requested = Event()
        self._stop = Event()
        self._guard = Lock()
        self._failure: BaseException | None = None
        self._thread = Thread(
            target=self._run,
            name=f"kodesec-lease-{job.id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.runtime.settings.worker_heartbeat_seconds + 1.0))
        if self._thread.is_alive():
            raise RuntimeError("job lease monitor did not stop within its bounded interval")

    def raise_if_unusable(self) -> None:
        self.raise_if_lease_lost()
        if self.cancel_requested.is_set():
            raise CancellationRequested("durable cancellation requested")

    def raise_if_lease_lost(self) -> None:
        with self._guard:
            failure = self._failure
        if failure is not None:
            raise LeaseLostError("job lease monitor lost ownership") from failure

    def _record_failure(self, exc: BaseException) -> None:
        with self._guard:
            self._failure = exc
        self._stop.set()

    def _run(self) -> None:
        interval = self.runtime.settings.worker_heartbeat_seconds
        while not self._stop.wait(interval):
            try:
                with self.runtime.session_factory() as db, db.begin():
                    job = heartbeat_job(
                        db,
                        self.job.id,
                        worker_id=self.worker_id,
                        attempt=self.job.attempt,
                        lease_seconds=self.runtime.settings.worker_lease_seconds,
                    )
                    record_worker_heartbeat(db, self.worker_id)
                    if job.cancel_requested_at is not None or job.status == "cancelling":
                        self.cancel_requested.set()
                # The lightweight container health marker represents the same
                # committed durable heartbeat. Refresh it from the lease
                # monitor as well as the idle claim loop so long-running work
                # cannot make a healthy worker look dead.
                record_process_heartbeat()
            except BaseException as exc:
                self._record_failure(exc)
                return


class WorkerExecutor:
    """Execute one already-claimed job and commit one fenced terminal state."""

    def __init__(
        self,
        runtime: Runtime,
        worker_id: str,
        *,
        scanner_client_factory: Callable[[], httpx.Client] | None = None,
        updater_client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        self.runtime = runtime
        self.settings = runtime.settings
        self.worker_id = worker_id
        self._scanner_client_factory = scanner_client_factory or self._new_scanner_client
        self._updater_client_factory = updater_client_factory or self._new_updater_client

    def execute(self, job: ClaimedJob) -> None:
        # Immutable scan command interpretation must fail before a monitor can
        # write a heartbeat or the worker can mutate the claimed job/scan.
        scan_use_ai = False
        if job.status != "cancelling":
            try:
                scan_snapshot = scan_command_snapshot(job.kind, job.payload)
            except InvalidScanCommandSnapshot as exc:
                self._reject_invalid_scan_command(job, exc)
                return
            scan_use_ai = scan_snapshot.use_ai if scan_snapshot is not None else False
        monitor = LeaseMonitor(self.runtime, job, self.worker_id)
        monitor.start()
        try:
            if job.status == "cancelling":
                if not (job.kind in _UPDATER_JOB_KINDS and job.attempt == 0):
                    self._cancel_external_if_present(job, monitor)
                monitor.stop()
                self._finalize_cancelled_safely(job)
                return

            self._mark_running(job)
            operation = str(job.payload.get("operation") or "")
            if job.payload.get("v") != 1:
                raise JobExecutionError("unsupported_payload", "Job payload schema is not supported.")
            if operation == "scan":
                completion = self._execute_scan(
                    job,
                    monitor,
                    use_ai=scan_use_ai,
                )
            elif operation == "advisor_finding":
                completion = self._execute_advisor_finding(job, monitor)
            elif operation == "advisor_scan":
                completion = self._execute_advisor_scan(job, monitor)
            elif operation == "advisor_provider_command":
                completion = self._execute_advisor_provider(job, monitor)
            elif operation in {"catalog_check", "cache_update", "cache_rollback", "cache_reconcile"}:
                completion = self._execute_updater(job, monitor)
            else:
                raise JobExecutionError("unsupported_operation", "Job operation is not supported.")

            monitor.raise_if_unusable()
            self._complete(job, completion)
            self._stop_after_terminal(monitor)
        except ScannerRecoveryPending as exc:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning(
                "scanner reconciliation remains pending under the durable lease",
                extra={"job_id": job.id, "error_code": exc.code},
            )
        except CancellationRequested:
            cleanup_failure: BaseException | None = None
            try:
                self._cancel_external_if_present(job, monitor)
            except (
                JobExecutionError,
                SQLAlchemyError,
                ArtifactBoundaryError,
                OSError,
                RuntimeError,
            ) as exc:
                cleanup_failure = exc
            if cleanup_failure is not None:
                try:
                    monitor.stop()
                except RuntimeError:
                    pass
                LOGGER.warning(
                    "job cancellation cleanup remains pending",
                    extra={
                        "job_id": job.id,
                        "error_code": getattr(cleanup_failure, "code", "cleanup_failed"),
                    },
                )
                return
            if not self._finalize_cancelled_safely(job):
                try:
                    monitor.stop()
                except RuntimeError:
                    pass
                return
            self._stop_after_terminal(monitor)
        except LeaseLostError:
            try:
                self._stop_after_terminal(monitor)
            except Exception:
                pass
            LOGGER.warning("job lease lost", extra={"job_id": job.id})
        except JobExecutionError as exc:
            try:
                self._stop_after_terminal(monitor)
            except Exception:
                pass
            if exc.code in {"scanner_cleanup_unconfirmed", "advisor_cancel_unconfirmed"}:
                LOGGER.warning(
                    "owned operation cleanup remains pending",
                    extra={"job_id": job.id, "error_code": exc.code},
                )
                return
            self._fail(job, exc)
        except SQLAlchemyError:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning(
                "durable job database outcome remains uncertain under the current lease",
                extra={"job_id": job.id, "error_code": "scanner_db_uncertain"},
            )
        except BaseException as exc:
            try:
                self._stop_after_terminal(monitor)
            except Exception:
                pass
            LOGGER.error(
                "unexpected worker execution failure contained",
                extra={"job_id": job.id, "exception_type": type(exc).__name__},
            )
            self._fail(
                job,
                JobExecutionError(
                    "worker_internal_error",
                    "Unexpected worker failure was contained during durable execution.",
                    retryable=False,
                ),
            )

    def _reject_invalid_scan_command(
        self,
        job: ClaimedJob,
        rejection: InvalidScanCommandSnapshot,
    ) -> None:
        """Terminalize one malformed claimed command without touching its scan."""

        try:
            with self.runtime.session_factory() as db, db.begin():
                fail_job(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    error_code=rejection.code,
                    error_detail=rejection.detail,
                    retryable=False,
                )
        except (LeaseLostError, InvalidJobTransition):
            LOGGER.warning(
                "invalid scan command rejection was fenced by newer state",
                extra={"job_id": job.id, "error_code": rejection.code},
            )
        except SQLAlchemyError:
            LOGGER.warning(
                "invalid scan command rejection database outcome is uncertain",
                extra={"job_id": job.id, "error_code": rejection.code},
            )

    @staticmethod
    def _stop_after_terminal(monitor: LeaseMonitor) -> None:
        """Stop heartbeats after a committed terminal mutation.

        The final heartbeat can race the terminal commit and observe the now
        intentionally absent lease. That is not a loss of terminal ownership.
        """

        try:
            monitor.stop()
        except RuntimeError:
            LOGGER.warning("terminal lease monitor stopped late")

    def _new_scanner_client(self) -> httpx.Client:
        timeout = self.settings.worker_scanner_request_seconds
        return httpx.Client(
            base_url=self.settings.scanner_url.rstrip("/"),
            timeout=httpx.Timeout(
                timeout,
                read=self.settings.worker_scanner_page_read_seconds,
            ),
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    def _bounded_scanner_json(
        client: httpx.Client,
        method: str,
        path: str,
        *,
        max_bytes: int,
        **kwargs: Any,
    ) -> _ScannerReply:
        try:
            with client.stream(method, path, **kwargs) as response:
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError as exc:
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Scanner returned an invalid response length.",
                        ) from exc
                    if declared_size < 0 or declared_size > max_bytes:
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Scanner response exceeds its encoded byte limit.",
                        )
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    if len(chunk) > max_bytes - len(body):
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Scanner response exceeds its encoded byte limit.",
                        )
                    body.extend(chunk)
                status_code = response.status_code
        except JobExecutionError:
            raise
        try:
            value = json.loads(
                bytes(body).decode("utf-8", errors="strict"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            # Error responses such as a cleaned 404 or a sealed-integrity 500
            # are classified by status and do not need to carry a JSON body.
            # Successful responses and binding conflicts are part of the
            # authenticated transport contract and must remain strict JSON.
            if status_code < 400 or status_code == 409:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner returned invalid JSON.",
                ) from exc
            value = None
        return _ScannerReply(status_code=status_code, value=value)

    def _new_updater_client(self) -> httpx.Client:
        timeout = self.settings.worker_updater_request_seconds
        return httpx.Client(
            base_url=self.settings.scanner_updater_url.rstrip("/"),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
        )

    def _preparation_bound(self, job: ClaimedJob, local_bound: float, *, cleanup: bool = False) -> float:
        if job.kind == "scanner_cache_rollback":
            return local_bound
        recovery = job.kind == "scanner_cache_reconcile"
        raw = job.payload.get("reconciliation_budget" if recovery else "preparation_budget")
        if raw is None:
            if cleanup:
                return min(local_bound, 5.0)
            raise JobExecutionError(
                "scanner_preparation_budget_required",
                "Start a new preparation command with the current source.",
            )
        budget = (RecoveryBudget if recovery else PreparationBudget).model_validate(raw)
        identity = (job.external_run_id, budget.model_dump_json())
        try:
            if getattr(self, "_owned_preparation_identity", None) != identity:
                self._owned_preparation_clock = PreparationClock(budget, high_water=job.updated_at)
                self._owned_preparation_identity = identity
            return self._owned_preparation_clock.remaining(local_bound)
        except PreparationDeadlineExceeded as exc:
            if cleanup:
                return min(local_bound, 5.0)
            raise JobExecutionError(
                "scanner_reconciliation_deadline" if recovery else "scanner_preparation_deadline",
                "Scanner operation exceeded its immutable preparation deadline.",
            ) from exc

    @staticmethod
    def _preparation_record_late(record: dict[str, Any]) -> bool:
        raw = record.get("preparation_budget")
        if raw is None:
            return False
        budget = PreparationBudget.model_validate(raw)
        return bool(
            record.get("workflow_deadline_exceeded")
            or datetime.now(timezone.utc) >= budget_moment(budget.deadline_at)
        )

    def _validate_updater_prerequisite(self, job: ClaimedJob) -> None:
        prerequisite_job_id = job.payload.get("prerequisite_job_id")
        if prerequisite_job_id is None:
            return
        if (
            job.kind != "scanner_cache_update"
            or isinstance(prerequisite_job_id, bool)
            or not isinstance(prerequisite_job_id, int)
            or prerequisite_job_id < 1
            or prerequisite_job_id == job.id
        ):
            raise JobExecutionError(
                "invalid_payload",
                "Scanner cache preparation has an invalid catalog prerequisite.",
            )
        with self.runtime.session_factory() as db:
            prerequisite = db.get(Job, prerequisite_job_id)
            if prerequisite is None or prerequisite.kind != "scanner_catalog_check":
                raise JobExecutionError(
                    "scanner_preparation_catalog_missing",
                    "Scanner preparation cannot verify its required catalog check.",
                )
            if prerequisite.status == "cancelled":
                raise JobExecutionError(
                    "scanner_preparation_catalog_cancelled",
                    "Scanner preparation stopped because its catalog check was cancelled.",
                )
            if prerequisite.status == "failed":
                raise JobExecutionError(
                    "scanner_preparation_catalog_failed",
                    "Scanner preparation stopped because its catalog check failed. Retry the catalog stage before retrying scanner data preparation.",
                )
            if prerequisite.status != "completed":
                raise JobExecutionError(
                    "scanner_preparation_catalog_pending",
                    "Scanner data preparation is waiting for its catalog check to complete.",
                    retryable=True,
                )
            lifecycle = db.get(ScannerLifecycleState, "catalog")
            if lifecycle is None or lifecycle.job_id != prerequisite.id or lifecycle.status != "completed":
                raise JobExecutionError(
                    "scanner_preparation_catalog_changed",
                    "Scanner catalog state changed before data preparation started. Start scanner preparation again from the current catalog.",
                )
            receipt = lifecycle.receipt if isinstance(lifecycle.receipt, dict) else {}
            result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
            if job.payload.get("catalog_digest") != result.get("catalog_digest"):
                raise JobExecutionError(
                    "scanner_preparation_catalog_changed",
                    "Scanner preparation no longer matches the exact verified catalog selection.",
                )
            components = result.get("components")
            if not isinstance(components, list):
                raise JobExecutionError(
                    "scanner_preparation_catalog_invalid",
                    "Scanner catalog evidence is incomplete. Run scanner preparation again.",
                )
            component_states = {
                item.get("component_id"): item.get("state")
                for item in components
                if isinstance(item, dict)
                and isinstance(item.get("component_id"), str)
                and isinstance(item.get("state"), str)
            }
            requested = job.payload.get("component_ids")
            rejection = _scanner_preparation_component_rejection(
                component_states,
                requested,
            )
            if rejection is not None:
                raise rejection

    def _updater_request_for_job(self, job: ClaimedJob) -> dict[str, Any]:
        if job.kind == "scanner_cache_reconcile":
            try:
                budget = RecoveryBudget.model_validate(job.payload.get("reconciliation_budget"))
                target = RecoveryTarget.model_validate(job.payload.get("reconciliation_target"))
                digest = recovery_digest(budget, target)
                if (job.attempt != 1 or job.max_attempts != 1 or not job.external_run_id
                        or job.payload.get("operation") != "cache_reconcile"
                        or job.payload.get("component_ids") != [] or job.payload.get("request_digest") != digest):
                    raise ValueError("recovery immutable command differs")
            except (ValidationError, ValueError) as exc:
                raise JobExecutionError("invalid_payload", "Read-only recovery command is invalid.") from exc
            return {"schema_version": 3, "kind": "cache_reconcile", "requested_components": [],
                    "reconciliation_budget": budget.model_dump(mode="json"),
                    "reconciliation_target": target.model_dump(mode="json"),
                    "operation_id": job.external_run_id, "request_digest": digest,
                    "attempt": 1, "max_attempts": 1}
        self._validate_updater_prerequisite(job)
        if not job.external_run_id:
            raise JobExecutionError(
                "missing_updater_operation",
                "Scanner lifecycle job has no stable updater operation identifier.",
            )
        expected_operation = {
            "scanner_catalog_check": "catalog_check",
            "scanner_cache_update": "cache_update",
            "scanner_cache_rollback": "cache_rollback",
        }.get(job.kind)
        operation = job.payload.get("operation")
        components = job.payload.get("component_ids")
        if operation != expected_operation or not isinstance(components, list):
            raise JobExecutionError(
                "invalid_payload",
                "Scanner lifecycle job payload does not match its durable command kind.",
            )
        if (
            any(not isinstance(item, str) for item in components)
            or components != sorted(set(components))
            or set(components) - _CACHE_COMPONENT_IDS
            or (operation in {"catalog_check", "cache_rollback"} and components)
            or (operation == "cache_update" and not components)
        ):
            raise JobExecutionError(
                "invalid_payload",
                "Scanner lifecycle job contains an invalid reviewed component selection.",
            )
        catalog_digest = self._optional_sha256(job.payload.get("catalog_digest"), "catalog digest")
        if catalog_digest is not None and operation != "cache_update":
            raise JobExecutionError("invalid_payload", "Only scanner cache updates can select a data catalog.")
        raw_budget = job.payload.get("preparation_budget")
        try:
            budget = PreparationBudget.model_validate(raw_budget) if raw_budget is not None else None
        except (ValidationError, ValueError) as exc:
            raise JobExecutionError("invalid_payload", "Scanner preparation budget is invalid.") from exc
        expected_digest = domain._scanner_lifecycle_digest(operation, components, catalog_digest, budget)
        if job.payload.get("request_digest") != expected_digest:
            raise JobExecutionError(
                "invalid_payload",
                "Scanner lifecycle job request digest does not match its immutable command.",
            )
        if not 1 <= job.attempt <= job.max_attempts <= 3:
            raise JobExecutionError(
                "attempts_exhausted",
                "Scanner lifecycle operation exceeded its bounded three-attempt contract.",
            )
        return {
            "schema_version": 2 if budget is not None else 1,
            **({"preparation_budget": budget.model_dump(mode="json")} if budget is not None else {}),
            "operation_id": job.external_run_id,
            "request_digest": expected_digest,
            "kind": operation,
            "requested_components": components,
            "attempt": job.attempt,
            "max_attempts": job.max_attempts,
            **({"catalog_digest": catalog_digest} if catalog_digest is not None else {}),
        }

    @staticmethod
    def _updater_error_code(response: httpx.Response) -> str | None:
        try:
            value = response.json()
        except Exception:
            return None
        detail = value.get("detail") if isinstance(value, dict) else None
        code = detail.get("code") if isinstance(detail, dict) else None
        if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
            return code
        return None

    @staticmethod
    def _exact_object(value: Any, keys: set[str] | frozenset[str], label: str) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != set(keys):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} does not match the strict local schema.",
            )
        return value

    @staticmethod
    def _optional_safe_identity(value: Any, label: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_UPDATER_IDENTITY.fullmatch(value):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} is not a bounded opaque identity.",
            )
        return value

    @staticmethod
    def _optional_version(value: Any, label: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_UPDATER_VERSION.fullmatch(value):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} is not a bounded scanner version.",
            )
        return value

    @staticmethod
    def _optional_sha256(value: Any, label: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_SHA256.fullmatch(value):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} is not a SHA-256 identity.",
            )
        return value

    @staticmethod
    def _utc_receipt_timestamp(value: Any, label: str, *, optional: bool = False) -> str | None:
        if value is None and optional:
            return None
        if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} is not a bounded RFC3339 UTC timestamp.",
            )
        try:
            parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        except ValueError as exc:
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} is not a bounded RFC3339 UTC timestamp.",
            ) from exc
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise JobExecutionError(
                "updater_protocol",
                f"Updater {label} must use UTC.",
            )
        return value

    def _admit_catalog_result(self, value: Any) -> dict[str, Any]:
        optional = {"catalog_digest", "catalog_mode"}.intersection(value) if isinstance(value, dict) else set()
        result = self._exact_object(
            value,
            {"kind", "checked_at", "tools", "components"} | optional,
            "catalog result",
        )
        if result["kind"] != "catalog":
            raise JobExecutionError("updater_protocol", "Updater returned the wrong result kind.")
        catalog_digest = self._optional_sha256(result.get("catalog_digest"), "catalog digest")
        catalog_mode = result.get("catalog_mode", "source-reviewed/bundled")
        if (not isinstance(catalog_mode, str) or catalog_mode not in {"signed", "source-reviewed/bundled"}
            or (catalog_mode == "signed") != (catalog_digest is not None)):
            raise JobExecutionError("updater_protocol", "Updater catalog mode and signature identity are inconsistent.")
        checked_at = self._utc_receipt_timestamp(result["checked_at"], "catalog checked_at")
        raw_tools = result["tools"]
        if not isinstance(raw_tools, list) or len(raw_tools) != len(_EXTERNAL_TOOL_IDS):
            raise JobExecutionError(
                "updater_protocol",
                "Updater catalog must report the curated eight tools exactly once.",
            )
        tools: list[dict[str, Any]] = []
        for raw in raw_tools:
            item = self._exact_object(
                raw,
                {
                    "tool_id",
                    "state",
                    "installed_version",
                    "candidate_version",
                    "candidate_release_id",
                    "candidate_manifest_digest",
                },
                "catalog tool item",
            )
            tool_id = item["tool_id"]
            state = item["state"]
            if (
                not isinstance(tool_id, str)
                or not isinstance(state, str)
                or state not in SCANNER_CATALOG_TOOL_STATES
            ):
                raise JobExecutionError("updater_protocol", "Updater catalog tool state is invalid.")
            installed = self._optional_version(item["installed_version"], "installed version")
            candidate = self._optional_version(item["candidate_version"], "candidate version")
            release_id = self._optional_safe_identity(
                item["candidate_release_id"], "candidate release id"
            )
            manifest = self._optional_sha256(
                item["candidate_manifest_digest"], "candidate manifest digest"
            )
            if state == "candidate_available" and not (candidate and release_id and manifest):
                raise JobExecutionError(
                    "updater_protocol",
                    "Available scanner candidates require version, release, and manifest identities.",
                )
            if state == "current" and any(
                candidate_value is not None
                for candidate_value in (candidate, release_id, manifest)
            ):
                raise JobExecutionError(
                    "updater_protocol",
                    "Current scanner catalog entries may not advertise a candidate.",
                )
            tools.append(
                {
                    "tool_id": tool_id,
                    "state": state,
                    "installed_version": installed,
                    "candidate_version": candidate,
                    "candidate_release_id": release_id,
                    "candidate_manifest_digest": manifest,
                }
            )
        if [item["tool_id"] for item in tools] != list(_EXTERNAL_TOOL_IDS):
            raise JobExecutionError(
                "updater_protocol",
                "Updater catalog tools are not the exact sorted curated tool set.",
            )

        raw_components = result["components"]
        expected_components = sorted(_CACHE_COMPONENT_IDS)
        if not isinstance(raw_components, list) or len(raw_components) != len(expected_components):
            raise JobExecutionError(
                "updater_protocol",
                "Updater catalog must report the reviewed cache components exactly once.",
            )
        components: list[dict[str, Any]] = []
        for raw in raw_components:
            item = self._exact_object(
                raw,
                {
                    "component_id",
                    "state",
                    "current_immutable_ref",
                    "candidate_immutable_ref",
                    "candidate_manifest_digest",
                },
                "catalog component item",
            )
            component_id = item["component_id"]
            state = item["state"]
            if (
                not isinstance(component_id, str)
                or not isinstance(state, str)
                or state not in SCANNER_CATALOG_COMPONENT_STATES
            ):
                raise JobExecutionError(
                    "updater_protocol", "Updater catalog component state is invalid."
                )
            current_ref = self._optional_safe_identity(
                item["current_immutable_ref"], "current component reference"
            )
            candidate_ref = self._optional_safe_identity(
                item["candidate_immutable_ref"], "candidate component reference"
            )
            manifest = self._optional_sha256(
                item["candidate_manifest_digest"], "component manifest digest"
            )
            if state == "candidate_available" and not (candidate_ref and manifest):
                raise JobExecutionError(
                    "updater_protocol",
                    "Available cache candidates require immutable and manifest identities.",
                )
            if (
                state == "requires_lock_refresh"
                and component_id not in SCANNER_SOURCE_INTRINSIC_CACHE_COMPONENT_IDS
            ):
                raise JobExecutionError(
                    "updater_protocol",
                    "Lock refresh is valid only for source-intrinsic data components.",
                )
            if state != "candidate_available" and any(
                candidate_value is not None
                for candidate_value in (candidate_ref, manifest)
            ):
                raise JobExecutionError(
                    "updater_protocol",
                    "Non-actionable cache catalog states may not advertise a candidate.",
                )
            if state == "current" and current_ref is None:
                raise JobExecutionError(
                    "updater_protocol",
                    "Current cache catalog entries require an immutable identity.",
                )
            components.append(
                {
                    "component_id": component_id,
                    "state": state,
                    "current_immutable_ref": current_ref,
                    "candidate_immutable_ref": candidate_ref,
                    "candidate_manifest_digest": manifest,
                }
            )
        if [item["component_id"] for item in components] != expected_components:
            raise JobExecutionError(
                "updater_protocol",
                "Updater catalog components are not the exact sorted reviewed set.",
            )
        return {
            "kind": "catalog",
            "checked_at": checked_at,
            "tools": tools,
            "components": components,
            **({"catalog_digest": catalog_digest} if "catalog_digest" in optional else {}),
            **({"catalog_mode": catalog_mode} if "catalog_mode" in optional else {}),
        }

    def _admit_cache_result(self, job: ClaimedJob, value: Any) -> dict[str, Any]:
        result = self._exact_object(
            value,
            {"kind", "active", "previous_good", "updated_components"},
            "cache result",
        )
        if result["kind"] != "cache":
            raise JobExecutionError("updater_protocol", "Updater returned the wrong result kind.")

        def reference(raw: Any, label: str, *, optional: bool = False) -> dict[str, str] | None:
            if raw is None and optional:
                return None
            item = self._exact_object(raw, {"generation_id", "manifest_sha256"}, label)
            generation = self._optional_sha256(item["generation_id"], f"{label} generation")
            manifest = self._optional_sha256(item["manifest_sha256"], f"{label} manifest")
            if generation is None or manifest is None:
                raise JobExecutionError(
                    "updater_protocol", f"Updater {label} is incomplete."
                )
            return {"generation_id": generation, "manifest_sha256": manifest}

        active = reference(result["active"], "active generation")
        previous = reference(result["previous_good"], "previous-good generation", optional=True)
        updated = result["updated_components"]
        expected = list(job.payload.get("component_ids") or [])
        if (
            not isinstance(updated, list)
            or any(not isinstance(item, str) for item in updated)
            or updated != sorted(set(updated))
            or updated != expected
        ):
            raise JobExecutionError(
                "updater_protocol",
                "Updater cache receipt does not match the exact requested component set.",
            )
        return {
            "kind": "cache",
            "active": active,
            "previous_good": previous,
            "updated_components": updated,
        }

    def _admit_updater_record(
        self,
        job: ClaimedJob,
        response: httpx.Response,
        *,
        allowed_attempts: set[int],
    ) -> dict[str, Any]:
        if len(response.content) > _MAX_UPDATER_RECEIPT_BYTES:
            raise JobExecutionError(
                "updater_protocol", "Updater operation record exceeds the 16 KiB admission limit."
            )
        try:
            raw = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise JobExecutionError("updater_protocol", "Updater returned invalid JSON.") from exc
        request = self._updater_request_for_job(job)
        expected_keys = _UPDATER_RECORD_KEYS | (
            {"preparation_budget", "workflow_deadline_exceeded"}
            if request["schema_version"] == 2 else (
                {"reconciliation_budget", "reconciliation_target", "reconciliation_intent"}
                if request["schema_version"] == 3 else set())
        )
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise JobExecutionError(
                "updater_protocol",
                "Updater operation record does not match the strict local schema.",
            )
        record = raw
        if (
            isinstance(record["schema_version"], bool)
            or record["schema_version"] != request["schema_version"]
            or record["operation_id"] != request["operation_id"]
            or record["request_digest"] != request["request_digest"]
            or record["kind"] != request["kind"]
            or record["requested_components"] != request["requested_components"]
            or isinstance(record["attempt"], bool)
            or not isinstance(record["attempt"], int)
            or record["attempt"] not in allowed_attempts
            or isinstance(record["max_attempts"], bool)
            or not isinstance(record["max_attempts"], int)
            or record["max_attempts"] != request["max_attempts"]
        ):
            raise JobExecutionError(
                "updater_operation_conflict",
                "Updater operation record does not match its immutable durable command.",
            )
        if request["schema_version"] == 2 and (
            record["preparation_budget"] != request["preparation_budget"]
            or type(record["workflow_deadline_exceeded"]) is not bool
            or (record["workflow_deadline_exceeded"] and record["status"] != "completed")
        ):
            raise JobExecutionError(
                "updater_operation_conflict",
                "Updater preparation budget does not match its immutable command.",
            )
        if request["schema_version"] == 3:
            try:
                if (record["reconciliation_budget"] != request["reconciliation_budget"]
                        or record["reconciliation_target"] != request["reconciliation_target"]):
                    raise ValueError("recovery binding differs")
                if record["reconciliation_intent"] is not None:
                    RecoveryIntent.model_validate(record["reconciliation_intent"])
            except (ValueError, ValidationError) as exc:
                raise JobExecutionError("updater_operation_conflict", "Recovery binding differs from its command.") from exc
        status = record["status"]
        stage = record["stage"]
        if status not in {"queued", "running", "cancelling", "completed", "failed", "cancelled"}:
            raise JobExecutionError("updater_protocol", "Updater operation status is invalid.")
        if stage not in _UPDATER_STAGES:
            raise JobExecutionError("updater_protocol", "Updater operation stage is invalid.")
        expected_stage = {"completed": "completed", "failed": "failed", "cancelled": "cancelled"}
        if status in expected_stage and stage != expected_stage[status]:
            raise JobExecutionError(
                "updater_protocol", "Updater terminal status and stage are inconsistent."
            )
        created_at = self._utc_receipt_timestamp(record["created_at"], "created_at")
        started_at = self._utc_receipt_timestamp(
            record["started_at"], "started_at", optional=True
        )
        finished_at = self._utc_receipt_timestamp(
            record["finished_at"], "finished_at", optional=True
        )
        updated_at = self._utc_receipt_timestamp(record["updated_at"], "updated_at")
        last_activity_at = self._utc_receipt_timestamp(
            record["last_activity_at"], "last_activity_at", optional=True
        )
        activity_contract_available = record["last_activity_at"] is not None
        last_activity_at = last_activity_at or updated_at
        cancelled_at = self._utc_receipt_timestamp(
            record["cancel_requested_at"], "cancel_requested_at", optional=True
        )
        terminal = status in _UPDATER_TERMINAL
        if terminal != (finished_at is not None):
            raise JobExecutionError(
                "updater_protocol", "Updater finish timestamp does not match terminal state."
            )
        if request["schema_version"] == 2 and status == "completed":
            late_finish = (
                datetime.fromisoformat(finished_at.removesuffix("Z") + "+00:00")
                >= budget_moment(request["preparation_budget"]["deadline_at"])
            )
            if record["workflow_deadline_exceeded"] != late_finish:
                raise JobExecutionError(
                    "updater_protocol",
                    "Updater workflow deadline flag differs from its precise finish timestamp.",
                )
        if status != "queued" and started_at is None:
            raise JobExecutionError(
                "updater_protocol", "Updater started state omitted its start timestamp."
            )
        if status == "cancelling" and cancelled_at is None:
            raise JobExecutionError(
                "updater_protocol", "Updater cancelling state omitted its request timestamp."
            )
        error_code = record["error_code"]
        error_detail = record["error_detail"]
        if status == "failed":
            if (
                not isinstance(error_code, str)
                or not _SAFE_ERROR_CODE.fullmatch(error_code)
                or not isinstance(error_detail, str)
                or not error_detail.strip()
                or len(error_detail) > 512
            ):
                raise JobExecutionError(
                    "updater_protocol", "Updater failure omitted its bounded safe diagnostic."
                )
            error_detail = domain._redacted_text(error_detail, 512)
        elif error_code is not None or error_detail is not None:
            raise JobExecutionError(
                "updater_protocol", "Only failed updater operations may include errors."
            )
        result: dict[str, Any] | None = None
        if status == "completed":
            if job.kind == "scanner_cache_reconcile":
                try:
                    result = RecoveryResult.model_validate(record["result"]).model_dump(mode="json")
                    target = request["reconciliation_target"]
                    if (result["original_operation_id"] != target["operation_id"]
                            or result["original_request_digest"] != target["request_digest"]
                            or result["active"] != target["active"]
                            or not budget_moment(request["reconciliation_budget"]["issued_at"])
                                <= budget_moment(result["verified_at"])
                                < budget_moment(request["reconciliation_budget"]["deadline_at"])
                            or record["reconciliation_intent"] is None
                            or record["reconciliation_intent"]["result"] != result):
                        raise ValueError("recovery result differs from immutable binding")
                except (ValidationError, ValueError) as exc:
                    raise JobExecutionError("updater_protocol", "Recovery outcome binding is invalid.") from exc
            else:
                result = (
                    self._admit_catalog_result(record["result"])
                    if job.kind == "scanner_catalog_check"
                    else self._admit_cache_result(job, record["result"])
                )
        elif record["result"] is not None:
            raise JobExecutionError(
                "updater_protocol", "Non-completed updater operation exposed a result."
            )
        activity: dict[str, Any] | None = None
        raw_activity = record["activity"]
        if raw_activity is not None:
            item = self._exact_object(raw_activity, _UPDATER_ACTIVITY_KEYS, "activity")
            component_id = item["component_id"]
            component_index = item["component_index"]
            component_total = item["component_total"]
            bytes_completed = item["bytes_completed"]
            bytes_total = item["bytes_total"]
            requested_activity = stage in {"downloading", "validating_source"}
            generation_activity = stage in {
                "validating_active",
                "retaining",
                "validating_generation",
            }
            if (
                request["kind"] != "cache_update"
                or not isinstance(component_id, str)
                or component_id not in _CACHE_COMPONENT_IDS
                or isinstance(component_index, bool)
                or not isinstance(component_index, int)
                or isinstance(component_total, bool)
                or not isinstance(component_total, int)
                or not 1 <= component_index <= component_total <= len(_CACHE_COMPONENT_IDS)
                or not (requested_activity or generation_activity)
                or (
                    requested_activity
                    and (
                        component_id not in request["requested_components"]
                        or component_total != len(request["requested_components"])
                    )
                )
            ):
                raise JobExecutionError(
                    "updater_protocol", "Updater activity does not match the requested cache operation."
                )
            if (bytes_completed is None) != (bytes_total is None):
                raise JobExecutionError(
                    "updater_protocol", "Updater activity byte progress is incomplete."
                )
            if bytes_completed is not None:
                if (
                    isinstance(bytes_completed, bool)
                    or not isinstance(bytes_completed, int)
                    or isinstance(bytes_total, bool)
                    or not isinstance(bytes_total, int)
                    or not 0 <= bytes_completed <= bytes_total <= _MAX_UPDATER_ACTIVITY_BYTES
                    or bytes_total < 1
                ):
                    raise JobExecutionError(
                        "updater_protocol", "Updater activity byte progress is outside its bound."
                    )
            activity = {
                "component_id": component_id,
                "component_index": component_index,
                "component_total": component_total,
                "bytes_completed": bytes_completed,
                "bytes_total": bytes_total,
            }
        elif (
            activity_contract_available
            and request["kind"] == "cache_update"
            and status == "running"
            and stage in {"downloading", "validating_source"}
        ):
            raise JobExecutionError(
                "updater_protocol", "Updater component stage omitted its bounded activity."
            )
        return {
            "schema_version": request["schema_version"],
            **({
                "preparation_budget": record["preparation_budget"],
                "workflow_deadline_exceeded": record["workflow_deadline_exceeded"],
            } if request["schema_version"] == 2 else ({
                "reconciliation_budget": record["reconciliation_budget"],
                "reconciliation_target": record["reconciliation_target"],
                "reconciliation_intent": record["reconciliation_intent"],
            } if request["schema_version"] == 3 else {})),
            "operation_id": request["operation_id"],
            "request_digest": request["request_digest"],
            "kind": request["kind"],
            "requested_components": request["requested_components"],
            "status": status,
            "stage": stage,
            "attempt": record["attempt"],
            "max_attempts": request["max_attempts"],
            "cancel_requested_at": cancelled_at,
            "created_at": created_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "updated_at": updated_at,
            "last_activity_at": last_activity_at,
            "activity": activity,
            "result": result,
            "error_code": error_code,
            "error_detail": error_detail,
        }

    def _start_updater(self, job: ClaimedJob) -> dict[str, Any]:
        payload = self._updater_request_for_job(job)
        timeout = self._preparation_bound(job, self.settings.worker_updater_request_seconds)
        try:
            with self._updater_client_factory() as client:
                response = client.post("/operations", json=payload, timeout=timeout)
                if response.status_code in {200, 202}:
                    return self._admit_updater_record(
                        job,
                        response,
                        allowed_attempts={job.attempt},
                    )
                if response.status_code == 409:
                    code = self._updater_error_code(response)
                    raise JobExecutionError(
                        "updater_operation_conflict"
                        if code == "operation_conflict"
                        else "updater_rejected",
                        "Source-blind updater rejected the stable operation identity.",
                    )
                response.raise_for_status()
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "updater_unreachable",
                "Source-blind updater could not be reached while starting the operation.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError(
                "updater_start_failed",
                "Source-blind updater rejected the lifecycle operation.",
            ) from exc
        raise JobExecutionError("updater_protocol", "Updater did not return an operation record.")

    def _get_updater_operation(self, job: ClaimedJob, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        payload = self._updater_request_for_job(job)
        try:
            with self._updater_client_factory() as client:
                response = client.get(
                    f"/operations/{job.external_run_id}",
                    headers={"X-KodeSec-Request-Digest": str(payload["request_digest"])},
                    timeout=min(
                        timeout_seconds if timeout_seconds is not None
                        else self.settings.worker_updater_request_seconds,
                        self._preparation_bound(job, self.settings.worker_updater_request_seconds, cleanup=True),
                    ),
                )
                if response.status_code == 404:
                    raise JobExecutionError(
                        "updater_operation_missing",
                        "Stable updater operation is not present in its durable ledger.",
                        retryable=True,
                    )
                response.raise_for_status()
                return self._admit_updater_record(
                    job,
                    response,
                    allowed_attempts={job.attempt, max(1, job.attempt - 1)},
                )
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "updater_unreachable",
                "Source-blind updater could not be reached while reconciling the operation.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError(
                "updater_status_failed",
                "Source-blind updater operation status could not be read.",
                retryable=True,
            ) from exc

    @staticmethod
    def _updater_progress(record: dict[str, Any]) -> int:
        stage = str(record["stage"])
        progress = {
            "queued": 10,
            "resolving_lock": 15,
            "discovering": 22,
            "validating_active": 18,
            "downloading": 30,
            "validating_source": 68,
            "retaining": 23,
            "staging": 76,
            "validating_generation": 84,
            "activating": 91,
            "committing": 96,
            "rolling_back": 80,
        }.get(stage, 10)
        activity = record.get("activity")
        if isinstance(activity, dict) and stage in {"downloading", "validating_source"}:
            index = int(activity["component_index"])
            total = int(activity["component_total"])
            slot = 46.0 / total
            progress = 25 + int((index - 1) * slot)
            if stage == "downloading":
                completed = activity.get("bytes_completed")
                byte_total = activity.get("bytes_total")
                if isinstance(completed, int) and isinstance(byte_total, int) and byte_total > 0:
                    fraction = float(completed) / float(byte_total)
                    progress += int(slot * min(max(fraction, 0.0), 1.0) * 0.75)
            # Without an exact byte denominator, component/stage identity is
            # the only honest progress signal. Clients render it as
            # indeterminate activity instead of inventing a percentage.
        return min(max(progress, 10), 96)

    @staticmethod
    def _updater_detail(record: dict[str, Any]) -> str:
        stage = str(record["stage"])
        descriptions = {
            "queued": "Waiting for the source-blind updater.",
            "resolving_lock": "Verifying the pinned scanner catalog and cache lock.",
            "discovering": "Checking the curated scanner catalog for reviewed candidates.",
            "validating_active": "Revalidating the current immutable cache before preparing its successor.",
            "downloading": "Downloading checksum-pinned scanner data.",
            "validating_source": "Validating downloaded scanner data and rules.",
            "retaining": "Copying an unchanged validated component into the private successor generation.",
            "staging": "Building a private candidate cache generation.",
            "validating_generation": "Revalidating every file in the private candidate cache.",
            "activating": "Activating the validated cache generation atomically.",
            "committing": "Committing the validated cache receipt.",
            "rolling_back": "Restoring the previous validated cache generation.",
        }
        detail = descriptions.get(stage, "Scanner lifecycle operation is running.")
        activity = record.get("activity")
        if isinstance(activity, dict):
            component = str(activity["component_id"])
            index = int(activity["component_index"])
            total = int(activity["component_total"])
            detail = (
                f"{detail.removesuffix('.')} Current component: "
                f"{component} ({index} of {total})."
            )
        return detail

    def _publish_updater_activity(self, job: ClaimedJob, record: dict[str, Any]) -> None:
        activity = record.get("activity") if isinstance(record.get("activity"), dict) else None
        update = {
            "status": str(record["status"]),
            "stage": str(record["stage"]),
            "updated_at": str(record["last_activity_at"]),
            "component_id": activity.get("component_id") if activity else None,
            "component_index": activity.get("component_index") if activity else None,
            "component_total": activity.get("component_total") if activity else None,
            "bytes_completed": activity.get("bytes_completed") if activity else None,
            "bytes_total": activity.get("bytes_total") if activity else None,
        }
        checkpoint, current_progress = self._load_checkpoint(job)
        progress = max(current_progress, self._updater_progress(record))
        if checkpoint.get("updater_activity") == update and current_progress >= progress:
            return
        checkpoint["updater_activity"] = update
        self._set_progress(
            job,
            progress=progress,
            stage=str(record["stage"]),
            detail=self._updater_detail(record),
            checkpoint=checkpoint,
        )

    def _wait_for_updater(
        self,
        job: ClaimedJob,
        record: dict[str, Any],
        monitor: LeaseMonitor,
    ) -> dict[str, Any]:
        transient_failures = 0
        poll_seconds = _UPDATER_STATUS_POLL_SECONDS
        self._publish_updater_activity(job, record)
        while str(record.get("status")) not in _UPDATER_TERMINAL:
            try:
                remaining = self._preparation_bound(job, max(self.settings.worker_poll_seconds, poll_seconds))
            except JobExecutionError as expired:
                if expired.code not in {"scanner_preparation_deadline", "scanner_reconciliation_deadline"}:
                    raise
                # Read-only bounded reconciliation; never dispatch or retry.
                final = self._get_updater_operation(job)
                if str(final.get("status")) in _UPDATER_TERMINAL:
                    return final
                if job.kind != "scanner_cache_reconcile" and str(final.get("stage")) in {"committing", "activating"}:
                    raise JobExecutionError(
                        "scanner_preparation_commit_uncertain",
                        "Preparation exceeded its deadline during atomic publication; "
                        "active cache outcome needs reconciliation.",
                    ) from expired
                # Updater's persisted budget terminates owned work independently of this observer.
                raise expired
            monitor.raise_if_unusable()
            if monitor.cancel_requested.wait(
                remaining
            ):
                self._cancel_updater_if_present(job, monitor)
                raise CancellationRequested("durable updater cancellation requested")
            try:
                previous = record
                record = self._get_updater_operation(job)
                transient_failures = 0
                poll_seconds = _updater_poll_interval_seconds(previous, record)
                if str(record.get("status")) not in _UPDATER_TERMINAL:
                    self._publish_updater_activity(job, record)
            except JobExecutionError as exc:
                if not exc.retryable:
                    raise
                transient_failures += 1
                poll_seconds = _UPDATER_STATUS_POLL_SECONDS
                if transient_failures >= 3:
                    raise
        monitor.raise_if_unusable()
        return record

    @staticmethod
    def _updater_lifecycle_scope(job: ClaimedJob | Job) -> str:
        if job.kind == "scanner_catalog_check":
            return "catalog"
        if job.kind == "scanner_cache_update":
            return "cache"
        if job.kind in {"scanner_cache_rollback", "scanner_cache_reconcile"}:
            return "cache"
        raise JobExecutionError(
            "invalid_payload", "Job kind is not a scanner lifecycle operation."
        )

    def _mark_updater_lifecycle_running(self, job: ClaimedJob) -> None:
        with self.runtime.session_factory() as db, db.begin():
            state = db.get(ScannerLifecycleState, self._updater_lifecycle_scope(job))
            if state is None or state.job_id != job.id:
                raise JobExecutionError(
                    "lifecycle_state_conflict",
                    "Scanner lifecycle command is no longer linked to its durable state.",
                )
            state.status = "running"
            state.error_code = None
            state.error_detail = None
            state.started_at = state.started_at or datetime.now(timezone.utc)
            state.completed_at = None
            state.updated_at = datetime.now(timezone.utc)
            state.revision += 1
            db.add(state)

    @staticmethod
    def _bounded_updater_receipt(record: dict[str, Any]) -> dict[str, Any]:
        receipt = {
            "schema_version": record["schema_version"],
            **({
                "preparation_budget": record["preparation_budget"],
                "workflow_deadline_exceeded": record["workflow_deadline_exceeded"],
            } if record["schema_version"] == 2 else ({
                "reconciliation_budget": record["reconciliation_budget"],
                "reconciliation_target": record["reconciliation_target"],
            } if record["schema_version"] == 3 else {})),
            "operation_id": record["operation_id"],
            "request_digest": record["request_digest"],
            "kind": record["kind"],
            "requested_components": record["requested_components"],
            "attempt": record["attempt"],
            "max_attempts": record["max_attempts"],
            "updated_at": record["updated_at"],
            "result": record["result"],
        }
        encoded = json.dumps(
            receipt,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > _MAX_UPDATER_RECEIPT_BYTES:
            raise JobExecutionError(
                "updater_protocol", "Admitted updater receipt exceeds its persistence bound."
            )
        return json.loads(encoded)

    def _apply_catalog_receipt(
        self,
        db: Any,
        result: dict[str, Any],
    ) -> None:
        checked_at_text = str(result["checked_at"])
        checked_at = datetime.fromisoformat(checked_at_text.removesuffix("Z") + "+00:00")
        for item in result["tools"]:
            tool_id = str(item["tool_id"])
            state = db.get(ScannerToolState, tool_id)
            if state is None:
                defaults = domain.SCANNER_TOOL_REGISTRY[tool_id]
                state = ScannerToolState(
                    id=tool_id,
                    enabled=True,
                    current_version=str(defaults["current_version"]),
                    latest_version=str(defaults["latest_version"]),
                    status="ready",
                    update_available=False,
                )
            catalog_state = str(item["state"])
            state.last_checked_at = checked_at
            state.updated_at = datetime.now(timezone.utc)
            state.published_at = checked_at_text
            if catalog_state == "candidate_available":
                state.latest_version = str(item["candidate_version"])
                state.candidate_release_id = str(item["candidate_release_id"])
                state.candidate_manifest_sha256 = str(item["candidate_manifest_digest"])
                state.update_available = (
                    domain._normalize_version(state.current_version)
                    != domain._normalize_version(state.latest_version)
                )
                state.last_error = None
            elif catalog_state == "current":
                if item["installed_version"] is not None:
                    state.latest_version = str(item["installed_version"])
                state.candidate_release_id = None
                state.candidate_manifest_sha256 = None
                state.update_available = False
                state.last_error = None
            else:
                state.candidate_release_id = None
                state.candidate_manifest_sha256 = None
                state.update_available = False
                state.last_error = (
                    "Curated catalog candidate is unavailable."
                    if catalog_state == "unavailable"
                    else "Curated catalog candidate lacks a verified manifest attestation."
                )
            db.add(state)

    def _apply_completed_updater_state(
        self,
        db: Any,
        job: Job,
        record: dict[str, Any],
    ) -> ScannerLifecycleState:
        scope = self._updater_lifecycle_scope(job)
        state = db.get(ScannerLifecycleState, scope)
        if state is None or state.job_id != job.id:
            raise JobExecutionError(
                "lifecycle_state_conflict",
                "Scanner lifecycle receipt is no longer linked to its durable command.",
            )
        result = record["result"]
        if not isinstance(result, dict):
            raise JobExecutionError(
                "updater_protocol", "Completed updater record omitted its admitted result."
            )
        if scope == "catalog":
            self._apply_catalog_receipt(db, result)
        else:
            active = result["active"]
            previous = result["previous_good"]
            state.active_generation = str(active["generation_id"])
            state.previous_generation = (
                str(previous["generation_id"]) if previous is not None else None
            )
        late = self._preparation_record_late(record)
        state.status = "failed" if late else "completed"
        state.receipt = self._bounded_updater_receipt(record)
        state.error_code = "scanner_preparation_deadline" if late else None
        state.error_detail = (
            "Scanner cache outcome was recorded, but preparation exceeded its shared deadline."
            if late else None
        )
        state.started_at = state.started_at or job.started_at or datetime.now(timezone.utc)
        state.completed_at = datetime.now(timezone.utc)
        state.updated_at = datetime.now(timezone.utc)
        state.revision += 1
        db.add(state)
        return state

    def _persist_completed_updater_receipt(
        self,
        claimed: ClaimedJob,
        record: dict[str, Any],
        *,
        cancellation_race: bool = False,
    ) -> None:
        with self.runtime.session_factory() as db, db.begin():
            job = db.get(Job, claimed.id)
            if job is None:
                return
            self._apply_completed_updater_state(db, job, record)

    def _persist_updater_terminal_state(
        self,
        claimed: ClaimedJob,
        record: dict[str, Any],
    ) -> None:
        with self.runtime.session_factory() as db, db.begin():
            job = db.get(Job, claimed.id)
            if job is None:
                return
            state = db.get(ScannerLifecycleState, self._updater_lifecycle_scope(job))
            if state is None or state.job_id != job.id:
                return
            state.status = str(record["status"])
            state.receipt = {}
            state.error_code = record.get("error_code")
            state.error_detail = record.get("error_detail")
            state.started_at = state.started_at or job.started_at
            state.completed_at = datetime.now(timezone.utc)
            state.updated_at = datetime.now(timezone.utc)
            state.revision += 1
            db.add(state)

    def _execute_updater(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
    ) -> ExecutionCompletion:
        self._mark_updater_lifecycle_running(job)
        self._set_progress(
            job,
            progress=10,
            stage="source_blind_updater",
            detail="Source-blind scanner lifecycle operation is starting.",
        )
        try:
            record = self._get_updater_operation(job)
        except JobExecutionError as exc:
            if exc.code != "updater_operation_missing":
                raise
            record = self._start_updater(job)
        if (
            int(record["attempt"]) < job.attempt
            and str(record["status"]) in {"failed", "cancelled"}
        ):
            record = self._start_updater(job)
        if str(record["status"]) not in _UPDATER_TERMINAL:
            record = self._wait_for_updater(job, record, monitor)
        status = str(record["status"])
        if status == "cancelled":
            self._persist_updater_terminal_state(job, record)
            raise CancellationRequested("source-blind updater operation was cancelled")
        if status == "failed":
            self._persist_updater_terminal_state(job, record)
            error_code = str(record["error_code"] or "updater_failed")
            raise JobExecutionError(
                error_code,
                str(record["error_detail"] or "Source-blind updater operation failed."),
                # Re-fetching the same immutable input cannot repair a failed
                # installed-content contract. Preserve its terminal explanation
                # instead of hiding it behind another automatic download.
                retryable=(
                    error_code not in {
                        "scanner_preparation_deadline",
                        "scanner_preparation_budget_required",
                        "installed_content_mismatch",
                        "cache_grype_validation_invalid",
                        "scanner_data_catalog_invalid",
                    }
                    and job.attempt < job.max_attempts
                ),
            )
        if status != "completed":
            raise JobExecutionError(
                "updater_protocol", "Updater operation did not reach a supported terminal state."
            )
        if self._preparation_record_late(record):
            self._persist_completed_updater_receipt(job, record)
            raise JobExecutionError(
                "scanner_preparation_deadline",
                "Actual scanner cache outcome was preserved, but preparation exceeded its shared deadline.",
            )
        result = record["result"]
        active = result.get("active") if isinstance(result, dict) else None
        previous = result.get("previous_good") if isinstance(result, dict) else None
        return ExecutionCompletion(
            detail=(
                "Curated scanner catalog check completed with a bounded receipt."
                if job.kind == "scanner_catalog_check"
                else (
                    "Verified offline scanner cache rolled back atomically."
                    if job.kind == "scanner_cache_rollback"
                    else ("Published cache outcome reconciled; original preparation remains failed."
                          if job.kind == "scanner_cache_reconcile"
                          else "Verified offline scanner cache generation was activated atomically.")
                )
            ),
            result_ref=f"scanner-lifecycle:{self._updater_lifecycle_scope(job)}",
            lifecycle_scope=self._updater_lifecycle_scope(job),
            lifecycle_receipt=record,
            active_generation=(
                str(active["generation_id"]) if isinstance(active, dict) else None
            ),
            previous_generation=(
                str(previous["generation_id"]) if isinstance(previous, dict) else None
            ),
        )

    def _cancel_updater_if_present(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
    ) -> dict[str, Any] | None:
        if job.kind not in _UPDATER_JOB_KINDS or not job.external_run_id:
            return None
        payload = self._updater_request_for_job(job)
        deadline = time.monotonic() + self.settings.worker_cancel_wait_seconds
        def remaining_cancel() -> float:
            remaining = min(
                deadline - time.monotonic(),
                self._preparation_bound(job, self.settings.worker_updater_request_seconds, cleanup=True),
            )
            if remaining <= 0.001:
                raise JobExecutionError(
                    "updater_cancel_timeout",
                    "Updater cancellation did not reach a terminal state before the safety deadline.",
                    retryable=True,
                )
            return remaining

        try:
            with self._updater_client_factory() as client:
                response = client.delete(
                    f"/operations/{job.external_run_id}",
                    headers={"X-KodeSec-Request-Digest": str(payload["request_digest"])},
                    timeout=remaining_cancel(),
                )
                if response.status_code == 404:
                    return None
                if response.status_code == 409:
                    raise JobExecutionError(
                        "updater_operation_conflict",
                        "Updater cancellation found a different immutable operation binding.",
                    )
                response.raise_for_status()
                record = self._admit_updater_record(
                    job,
                    response,
                    allowed_attempts={job.attempt, max(1, job.attempt - 1)},
                )
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
            raise JobExecutionError(
                "updater_cancel_unavailable",
                "Updater cancellation could not be confirmed; the durable job remains cancelling.",
                retryable=True,
            ) from exc

        while str(record.get("status")) not in _UPDATER_TERMINAL:
            if time.monotonic() >= deadline:
                raise JobExecutionError(
                    "updater_cancel_timeout",
                    "Updater cancellation did not reach a terminal state before the safety deadline.",
                    retryable=True,
                )
            with monitor._guard:
                failure = monitor._failure
            if failure is not None:
                raise LeaseLostError("job lease was lost during updater cancellation") from failure
            time.sleep(min(remaining_cancel(), max(self.settings.worker_poll_seconds, _UPDATER_STATUS_POLL_SECONDS)))
            record = self._get_updater_operation(job, timeout_seconds=remaining_cancel())
        if record.get("status") == "completed":
            self._persist_completed_updater_receipt(job, record, cancellation_race=True)
        else:
            self._persist_updater_terminal_state(job, record)
        return record

    def _mark_running(self, job: ClaimedJob) -> None:
        try:
            with self.runtime.session_factory() as db, db.begin():
                mark_job_running(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    stage="starting",
                    detail="Worker claimed durable job.",
                    progress=max(1, int(job.checkpoint.get("progress") or 0)),
                )
        except InvalidJobTransition as exc:
            raise CancellationRequested("cancellation won the start race") from exc

    def _set_progress(
        self,
        job: ClaimedJob,
        *,
        progress: int,
        stage: str,
        detail: str,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        try:
            with self.runtime.session_factory() as db, db.begin():
                update_job_progress(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    progress=progress,
                    stage=stage,
                    detail=detail,
                    checkpoint=checkpoint,
                )
        except InvalidJobTransition as exc:
            raise CancellationRequested("cancellation won the progress race") from exc

    def _scanner_request_payload(self, job: ClaimedJob, scan: Scan, project: Project) -> dict[str, Any]:
        if not job.external_run_id:
            raise JobExecutionError("missing_scanner_run", "Scan job has no stable scanner run identifier.")
        coverage_snapshot = _validated_scan_coverage_snapshot(job.payload)
        target_path, target_kind = _validated_scan_target(job.payload)
        source_snapshot_digest = _validated_scan_source_snapshot_digest(job.payload)
        repo_path = project.repo_path
        if is_source_snapshot_project(repo_path):
            if source_snapshot_digest is None:
                raise JobExecutionError(
                    "invalid_payload",
                    "Native Windows scan job lost its immutable source snapshot binding.",
                )
            try:
                repo_path = str(
                    validate_source_snapshot(
                        self.settings,
                        source_snapshot_digest,
                        source_id=source_snapshot_project_source_id(project.repo_path),
                        scan_target=(target_path, target_kind),
                    )
                )
            except SourceSnapshotError as exc:
                raise JobExecutionError(
                    "source_snapshot_invalid",
                    "Native Windows source snapshot is unavailable or no longer matches its sealed manifest.",
                ) from exc
        elif source_snapshot_digest is not None:
            raise JobExecutionError(
                "invalid_payload",
                "Mounted scan job unexpectedly carried a native source snapshot binding.",
            )
        return {
            "run_id": job.external_run_id,
            "scan_id": scan.id,
            "repo_path": repo_path,
            "target_path": target_path,
            "target_kind": target_kind,
            "source_snapshot_digest": source_snapshot_digest,
            "mode": scan.mode,
            "base_ref": scan.base_ref,
            "head_ref": scan.head_ref,
            "enabled_tools": coverage_snapshot["enabled_tools"],
        }

    @staticmethod
    def _scanner_state(
        value: Any,
        *,
        run_id: str,
        request_digest: str,
    ) -> dict[str, Any]:
        try:
            return _strict_scanner_state(value, run_id=run_id, request_digest=request_digest)
        except JobExecutionError as exc:
            binding = _raw_scanner_result_binding(
                value,
                run_id=run_id,
                request_digest=request_digest,
            )
            if exc.code == "scanner_protocol" and binding is not None:
                raise JobExecutionError(
                    exc.code,
                    exc.detail,
                    retryable=exc.retryable,
                    scanner_binding=binding,
                ) from exc
            raise

    @staticmethod
    def _scanner_error_code(response: httpx.Response) -> str | None:
        try:
            value = response.json()
        except Exception:
            return None
        detail = value.get("detail") if isinstance(value, dict) else None
        code = detail.get("code") if isinstance(detail, dict) else None
        return code if isinstance(code, str) else None

    @staticmethod
    def _scanner_error_code_value(value: Any) -> str | None:
        detail = value.get("detail") if isinstance(value, dict) else None
        code = detail.get("code") if isinstance(detail, dict) else None
        return code if isinstance(code, str) else None

    def _start_scanner(self, client: httpx.Client, payload: dict[str, Any]) -> dict[str, Any]:
        run_id = str(payload["run_id"])
        request_digest = _scanner_request_digest(payload)
        try:
            response = self._bounded_scanner_json(
                client,
                "POST",
                "/runs",
                max_bytes=_SCANNER_MAX_STATE_BYTES,
                json=payload,
            )
            if response.status_code in {200, 202}:
                return self._scanner_state(
                    response.value,
                    run_id=run_id,
                    request_digest=request_digest,
                )
            if response.status_code == 409:
                error_code = self._scanner_error_code_value(response.value)
                if error_code == "scanner_capacity":
                    raise JobExecutionError(
                        "scanner_busy",
                        "Scanner admission is busy with another run.",
                        retryable=True,
                    )
                if error_code == "run_id_conflict":
                    raise JobExecutionError(
                        "scanner_run_conflict",
                        "Scanner run identity is bound to a different immutable request.",
                    )
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner returned an unrecognized admission conflict.",
                )
            if response.status_code >= 400:
                raise JobExecutionError("scanner_start_failed", "Scanner rejected the stable run.")
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "scanner_unreachable",
                "Scanner could not be reached while starting the stable run.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError("scanner_start_failed", "Scanner rejected the stable run.") from exc
        raise JobExecutionError("scanner_protocol", "Scanner did not return a run state.")

    def _get_scanner_run(
        self,
        client: httpx.Client,
        run_id: str,
        request_digest: str,
    ) -> dict[str, Any]:
        try:
            response = self._bounded_scanner_json(
                client,
                "GET",
                f"/runs/{run_id}",
                max_bytes=_SCANNER_MAX_STATE_BYTES,
            )
            if response.status_code == 404:
                raise JobExecutionError(
                    "scanner_run_missing",
                    "Stable scanner run registry was reset; restarting the same run identity.",
                    retryable=True,
                )
            if response.status_code >= 400:
                raise JobExecutionError("scanner_status_failed", "Scanner run status could not be read.")
            return self._scanner_state(
                response.value,
                run_id=run_id,
                request_digest=request_digest,
            )
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "scanner_unreachable",
                "Scanner could not be reached while reconciling the stable run.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError("scanner_status_failed", "Scanner run status could not be read.") from exc

    def _get_scanner_page(
        self,
        client: httpx.Client,
        *,
        run_id: str,
        request_digest: str,
        manifest: dict[str, Any],
        expected_ordinal: int,
        cursor: str | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], bytes]]]:
        try:
            params: dict[str, Any] = {
                "request_digest": request_digest,
                "limit": _SCANNER_PAGE_LIMIT,
            }
            if cursor is not None:
                params["cursor"] = cursor
            response = self._bounded_scanner_json(
                client,
                "GET",
                f"/runs/{run_id}/findings",
                max_bytes=_SCANNER_MAX_PAGE_BYTES,
                params=params,
            )
            if response.status_code in {404, 410}:
                raise JobExecutionError(
                    "scanner_run_missing",
                    "Scanner result recovery window reset during bounded ingestion.",
                    retryable=True,
                )
            if response.status_code == 409:
                raise JobExecutionError(
                    "scanner_run_conflict",
                    "Scanner finding page is bound to different immutable evidence.",
                )
            if response.status_code == 500:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner sealed result failed its integrity check.",
                )
            if response.status_code >= 400:
                raise JobExecutionError(
                    "scanner_page_failed",
                    "Scanner finding page could not be read.",
                    retryable=response.status_code >= 500,
                )
            return _strict_scanner_page(
                response.value,
                run_id=run_id,
                request_digest=request_digest,
                manifest=manifest,
                expected_ordinal=expected_ordinal,
            )
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "scanner_unreachable",
                "Scanner became unreachable during bounded result ingestion.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError(
                "scanner_page_failed",
                "Scanner finding page could not be read.",
                retryable=True,
            ) from exc

    def _ack_scanner_result(
        self,
        client: httpx.Client,
        *,
        run_id: str,
        request_digest: str,
        result_digest: str,
    ) -> None:
        try:
            response = self._bounded_scanner_json(
                client,
                "POST",
                f"/runs/{run_id}/result/ack",
                max_bytes=_SCANNER_MAX_ACK_BYTES,
                json={
                    "request_digest": request_digest,
                    "result_digest": result_digest,
                },
            )
            if response.status_code == 404:
                # The exact immutable result was already acknowledged and its
                # retained tombstone subsequently expired. Durable database
                # persistence makes this a successful cleanup outcome.
                return
            if response.status_code == 409:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner acknowledgement rejected its immutable binding.",
                )
            if response.status_code >= 500:
                raise JobExecutionError(
                    "scanner_ack_unavailable",
                    "Scanner result acknowledgement is temporarily unavailable.",
                    retryable=True,
                )
            if response.status_code >= 400:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner rejected the result acknowledgement contract.",
                )
            _strict_scanner_ack(
                response.value,
                run_id=run_id,
                request_digest=request_digest,
                result_digest=result_digest,
            )
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise JobExecutionError(
                "scanner_ack_unavailable",
                "Scanner could not be reached while acknowledging durable evidence.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise JobExecutionError(
                "scanner_ack_unavailable",
                "Scanner result acknowledgement transport failed.",
                retryable=True,
            ) from exc

    def _load_checkpoint(self, job: ClaimedJob) -> tuple[dict[str, Any], int]:
        """Reload durable recovery state instead of trusting a claimed snapshot."""

        with self.runtime.session_factory() as db:
            current = db.get(Job, job.id)
            if current is None:
                raise JobExecutionError("missing_job", "Scan job no longer exists.")
            return dict(current.checkpoint or {}), int(current.progress or 0)

    def _reload_persisted_scanner_outcome(
        self,
        job: ClaimedJob,
        *,
        request_digest: str,
        result_digest: str,
    ) -> dict[str, Any]:
        """Resolve an uncertain DB return without guessing commit outcome."""

        try:
            checkpoint, _progress = self._load_checkpoint(job)
        except SQLAlchemyError as exc:
            raise ScannerRecoveryPending("scanner_db_uncertain") from exc
        current_request, current_result = _checkpoint_scanner_binding(checkpoint)
        if (
            checkpoint.get("scanner_persisted") is True
            and current_request == request_digest
            and current_result == result_digest
        ):
            return checkpoint
        # Retain the immutable scanner spool. A later lease can safely page it
        # again; no finding or artifact is visible unless the one transaction
        # and its exact checkpoint both committed.
        raise ScannerRecoveryPending("scanner_db_uncertain")

    def _record_scanner_cleanup_pending(
        self,
        job: ClaimedJob,
        *,
        request_digest: str,
        result_digest: str,
        error_code: str,
    ) -> dict[str, Any]:
        """Durably bind a rejected immutable result before deleting its spool."""

        if (
            _SAFE_SHA256.fullmatch(request_digest) is None
            or _SAFE_SHA256.fullmatch(result_digest) is None
            or _SAFE_ERROR_CODE.fullmatch(error_code) is None
        ):
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner cleanup receipt has an invalid immutable binding.",
            )
        try:
            checkpoint, current_progress = self._load_checkpoint(job)
        except SQLAlchemyError as exc:
            raise ScannerRecoveryPending("scanner_cleanup_checkpoint_pending") from exc
        if checkpoint.get("scanner_persisted") is True:
            raise JobExecutionError(
                "scanner_protocol",
                "Persisted scanner evidence cannot be discarded as rejected transport.",
            )
        existing_request, existing_result = _checkpoint_scanner_binding(checkpoint)
        if (existing_request, existing_result) not in {
            (None, None),
            (request_digest, result_digest),
        }:
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner cleanup is bound to different immutable evidence.",
            )
        existing_cleanup = _checkpoint_scanner_cleanup(checkpoint)
        if existing_cleanup is not None and existing_cleanup != error_code:
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner cleanup receipt changed its terminal cause.",
            )
        checkpoint.update(
            {
                "scanner_evidence": {
                    "request_digest": request_digest,
                    "sha256": result_digest,
                },
                "scanner_cleanup": {
                    "action": "discard",
                    "error_code": error_code,
                },
            }
        )
        try:
            self._set_progress(
                job,
                progress=max(1, current_progress),
                stage="scanner_cleanup_wait",
                detail="Rejected immutable scanner evidence is awaiting confirmed cleanup.",
                checkpoint=checkpoint,
            )
        except SQLAlchemyError as exc:
            raise ScannerRecoveryPending("scanner_cleanup_checkpoint_pending") from exc
        return checkpoint

    def _acknowledge_persisted_scanner_result(
        self,
        job: ClaimedJob,
        client: httpx.Client,
        checkpoint: dict[str, Any],
        monitor: LeaseMonitor,
        *,
        use_ai: bool,
    ) -> dict[str, Any]:
        """Require scanner cleanup and checkpoint it before later stages."""

        request_digest, result_digest = _checkpoint_scanner_binding(checkpoint)
        if (
            not checkpoint.get("scanner_persisted")
            or not job.external_run_id
            or not isinstance(request_digest, str)
            or _SAFE_SHA256.fullmatch(request_digest) is None
            or not isinstance(result_digest, str)
            or _SAFE_SHA256.fullmatch(result_digest) is None
        ):
            raise JobExecutionError(
                "scanner_protocol",
                "Persisted scanner evidence omitted its immutable acknowledgement binding.",
            )
        # Always repeat the idempotent ACK on recovery. This closes a worker
        # crash between scanner cleanup and its database checkpoint.
        monitor.raise_if_unusable()
        try:
            self._ack_scanner_result(
                client,
                run_id=job.external_run_id,
                request_digest=request_digest,
                result_digest=result_digest,
            )
        except JobExecutionError as exc:
            # The findings/artifact transaction is already authoritative.
            # Keep the running lease recoverable until the idempotent ACK can
            # be confirmed; never turn durable evidence into a failed scan
            # merely because temporary scanner storage could not be cleaned.
            raise ScannerRecoveryPending("scanner_ack_pending") from exc
        try:
            current_checkpoint, current_progress = self._load_checkpoint(job)
        except SQLAlchemyError as exc:
            raise ScannerRecoveryPending("scanner_ack_checkpoint_pending") from exc
        current_request_digest, current_result_digest = _checkpoint_scanner_binding(
            current_checkpoint
        )
        if (
            current_request_digest != request_digest
            or current_result_digest != result_digest
            or current_checkpoint.get("scanner_persisted") is not True
        ):
            raise JobExecutionError(
                "scanner_protocol",
                "Durable scanner evidence changed before acknowledgement checkpointing.",
            )
        if current_checkpoint.get("scanner_acknowledged") is True:
            return current_checkpoint
        checkpoint = {**current_checkpoint, "scanner_acknowledged": True}
        try:
            self._set_progress(
                job,
                progress=max(83, current_progress),
                stage="advisor" if use_ai else "gate",
                detail="Durable scanner evidence was acknowledged and temporary result storage was cleaned.",
                checkpoint=checkpoint,
            )
        except SQLAlchemyError as exc:
            # ACK is idempotent and its tombstone may already exist. Recovery
            # repeats it, reloads the exact typed binding, and checkpoints it.
            raise ScannerRecoveryPending("scanner_ack_checkpoint_pending") from exc
        return checkpoint

    def _discard_scanner_result(
        self,
        client: httpx.Client,
        monitor: LeaseMonitor,
        *,
        run_id: str,
        request_digest: str,
        result_digest: str,
    ) -> None:
        binding = (run_id, request_digest, result_digest)
        monitor.raise_if_lease_lost()
        try:
            self._delete_scanner_run(
                client,
                run_id=run_id,
                request_digest=request_digest,
                result_digest=result_digest,
            )
        except JobExecutionError as exc:
            raise JobExecutionError(
                "scanner_cleanup_unconfirmed",
                "Scanner protocol rejection cleanup could not be confirmed; durable recovery remains pending.",
                retryable=True,
                scanner_binding=binding,
            ) from exc
        monitor.raise_if_lease_lost()

    def _cleanup_bound_scanner_protocol_error(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        client: httpx.Client,
        failure: JobExecutionError,
    ) -> None:
        binding = failure.scanner_binding
        if binding is None:
            return
        run_id, request_digest, result_digest = binding
        if run_id != str(job.external_run_id):
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner cleanup capability did not match the durable run identity.",
            )
        self._record_scanner_cleanup_pending(
            job,
            request_digest=request_digest,
            result_digest=result_digest,
            error_code=failure.code,
        )
        self._discard_scanner_result(
            client,
            monitor,
            run_id=run_id,
            request_digest=request_digest,
            result_digest=result_digest,
        )

    def _resume_rejected_scanner_cleanup(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        checkpoint: dict[str, Any],
    ) -> None:
        error_code = _checkpoint_scanner_cleanup(checkpoint)
        if error_code is None:
            return
        request_digest, result_digest = _checkpoint_scanner_binding(checkpoint)
        if (
            not job.external_run_id
            or not isinstance(request_digest, str)
            or not isinstance(result_digest, str)
        ):
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner cleanup receipt omitted its immutable evidence binding.",
            )
        with self._scanner_client_factory() as client:
            self._discard_scanner_result(
                client,
                monitor,
                run_id=job.external_run_id,
                request_digest=request_digest,
                result_digest=result_digest,
            )
        raise JobExecutionError(
            error_code,
            "Rejected immutable scanner evidence was cleaned without publication.",
            retryable=False,
        )

    def _delete_scanner_run(
        self,
        client: httpx.Client,
        *,
        run_id: str,
        request_digest: str,
        result_digest: str | None,
    ) -> dict[str, Any] | None:
        try:
            params = {"request_digest": request_digest}
            if result_digest is not None:
                params["result_digest"] = result_digest
            response = self._bounded_scanner_json(
                client,
                "DELETE",
                f"/runs/{run_id}",
                max_bytes=_SCANNER_MAX_STATE_BYTES,
                params=params,
            )
            if response.status_code == 404:
                return None
            if response.status_code == 409:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner rejected the immutable cleanup binding.",
                )
            if response.status_code >= 500:
                raise JobExecutionError(
                    "scanner_cancel_unavailable",
                    "Scanner result cleanup is temporarily unavailable.",
                    retryable=True,
                )
            if response.status_code not in {200, 202}:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner rejected the bounded cleanup contract.",
                )
            state = self._scanner_state(
                response.value,
                run_id=run_id,
                request_digest=request_digest,
            )
            if result_digest is not None:
                manifest = state.get("result_manifest")
                if (
                    state.get("status") != "completed"
                    or state.get("result_available") is not False
                    or not isinstance(manifest, dict)
                    or manifest.get("result_digest") != result_digest
                ):
                    raise JobExecutionError(
                        "scanner_protocol",
                        "Scanner did not confirm immutable result cleanup.",
                    )
            return state
        except JobExecutionError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
            raise JobExecutionError(
                "scanner_cancel_unavailable",
                "Scanner cleanup could not be confirmed; cancellation remains pending.",
                retryable=True,
            ) from exc

    def _wait_for_scanner(
        self,
        job: ClaimedJob,
        state: dict[str, Any],
        monitor: LeaseMonitor,
        request_payload: dict[str, Any],
        client: httpx.Client,
        *,
        allow_registry_restart: bool = True,
    ) -> dict[str, Any]:
        transient_failures = 0
        registry_resets = 0
        request_digest = _scanner_request_digest(request_payload)
        published_status: str | None = None
        previous_identity = _scanner_state_identity(state)
        unchanged_polls = 0
        while str(state.get("status")) not in _SCANNER_TERMINAL:
            scanner_status = str(state.get("status"))
            if scanner_status != published_status:
                detail = {
                    "queued": "Scanner run was admitted and is waiting for the local scanner executor.",
                    "running": (
                        "Scanner runtime is executing the enabled tools. "
                        "Tool-level progress is unavailable; elapsed time and scanner state freshness remain visible."
                    ),
                    "cancelling": "Scanner runtime acknowledged cancellation and is cleaning temporary output.",
                }.get(scanner_status, "Scanner runtime reported a new bounded state.")
                self._set_progress(
                    job,
                    progress=15,
                    stage="scanner",
                    detail=detail,
                )
                published_status = scanner_status
            monitor.raise_if_unusable()
            poll_seconds = _scanner_poll_interval_seconds(
                base_seconds=self.settings.worker_poll_seconds,
                heartbeat_seconds=self.settings.worker_heartbeat_seconds,
                unchanged_polls=unchanged_polls,
            )
            if monitor.cancel_requested.wait(poll_seconds):
                self._cancel_scanner_if_present(job, monitor, client)
                raise CancellationRequested("durable cancellation requested")
            try:
                next_state = self._get_scanner_run(
                    client,
                    str(job.external_run_id),
                    request_digest,
                )
                transient_failures = 0
                next_identity = _scanner_state_identity(next_state)
                if next_identity == previous_identity:
                    unchanged_polls += 1
                else:
                    unchanged_polls = 0
                state = next_state
                previous_identity = next_identity
            except JobExecutionError as exc:
                if not exc.retryable:
                    raise
                if exc.code == "scanner_run_missing":
                    if not allow_registry_restart:
                        raise
                    registry_resets += 1
                    if registry_resets > 3:
                        raise JobExecutionError(
                            "scanner_registry_unstable",
                            "Scanner run registry repeatedly reset during one worker attempt.",
                            retryable=True,
                        ) from exc
                    state = self._start_scanner(client, request_payload)
                    transient_failures = 0
                    previous_identity = _scanner_state_identity(state)
                    unchanged_polls = 0
                    continue
                transient_failures += 1
                unchanged_polls += 1
                if transient_failures >= 3:
                    raise
        monitor.raise_if_unusable()
        return state

    def _cancel_scanner_if_present(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        client: httpx.Client | None = None,
    ) -> dict[str, Any] | None:
        if job.kind != "scan" or not job.external_run_id:
            return None
        request_payload = self._scanner_request_for_job(job)
        request_digest = _scanner_request_digest(request_payload)
        checkpoint, _current_progress = self._load_checkpoint(job)
        deadline = time.monotonic() + self.settings.worker_cancel_wait_seconds
        try:
            with (
                nullcontext(client)
                if client is not None
                else self._scanner_client_factory()
            ) as scanner_client:
                persisted = checkpoint.get("scanner_persisted") is True
                checkpoint_request_digest, result_digest = _checkpoint_scanner_binding(
                    checkpoint
                )
                if (
                    checkpoint_request_digest is not None
                    and checkpoint_request_digest != request_digest
                ):
                    raise JobExecutionError(
                        "scanner_protocol",
                        "Durable scanner cleanup evidence does not match the job request.",
                    )
                if persisted:
                    monitor.raise_if_lease_lost()
                    if (
                        not isinstance(result_digest, str)
                        or _SAFE_SHA256.fullmatch(result_digest) is None
                    ):
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Persisted cancellation evidence omitted its immutable cleanup binding.",
                        )
                    self._ack_scanner_result(
                        scanner_client,
                        run_id=job.external_run_id,
                        request_digest=request_digest,
                        result_digest=result_digest,
                    )
                    return None
                bound_digest = (
                    str(result_digest)
                    if isinstance(result_digest, str)
                    and _SAFE_SHA256.fullmatch(result_digest) is not None
                    else None
                )
                monitor.raise_if_lease_lost()
                state = self._delete_scanner_run(
                    scanner_client,
                    run_id=job.external_run_id,
                    request_digest=request_digest,
                    result_digest=bound_digest,
                )
                if state is None:
                    return None
                # A result may complete between the cancellation request and
                # the ordinary DELETE. Bind and discard that exact manifest
                # rather than finalizing while retained evidence remains.
                manifest = state.get("result_manifest")
                if (
                    bound_digest is None
                    and state.get("status") == "completed"
                    and isinstance(manifest, dict)
                ):
                    monitor.raise_if_lease_lost()
                    state = self._delete_scanner_run(
                        scanner_client,
                        run_id=job.external_run_id,
                        request_digest=request_digest,
                        result_digest=str(manifest["result_digest"]),
                    )
                    return state
                while str(state.get("status")) not in _SCANNER_TERMINAL:
                    if time.monotonic() >= deadline:
                        raise JobExecutionError(
                            "scanner_cancel_timeout",
                            "Scanner cancellation did not reach a terminal state before the safety deadline.",
                            retryable=True,
                        )
                    with monitor._guard:
                        failure = monitor._failure
                    if failure is not None:
                        raise LeaseLostError(
                            "job lease was lost during scanner cancellation"
                        ) from failure
                    time.sleep(self.settings.worker_poll_seconds)
                    try:
                        state = self._get_scanner_run(
                            scanner_client,
                            job.external_run_id,
                            request_digest,
                        )
                    except JobExecutionError as exc:
                        if exc.code == "scanner_run_missing":
                            return None
                        raise
                manifest = state.get("result_manifest")
                if state.get("status") == "completed" and isinstance(manifest, dict):
                    monitor.raise_if_lease_lost()
                    state = self._delete_scanner_run(
                        scanner_client,
                        run_id=job.external_run_id,
                        request_digest=request_digest,
                        result_digest=str(manifest["result_digest"]),
                    )
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
            raise JobExecutionError(
                "scanner_cancel_unavailable",
                "Scanner cancellation could not be confirmed; the durable job remains cancelling.",
                retryable=True,
            ) from exc

        return state

    def _cancel_local_advisor_if_present(
        self, job: ClaimedJob, monitor: LeaseMonitor,
    ) -> dict[str, str] | None:
        checkpoint, _progress = self._load_checkpoint(job)
        record = checkpoint.get("local_advisor_operation")
        if record is None:
            return None
        try:
            if not isinstance(record, dict) or set(record) != {
                "advisor_operation_id", "binding", "finding_id", "finding_revision", "attempt",
            }:
                raise ValueError("invalid local operation checkpoint")
            operation_id = record["advisor_operation_id"]
            if not isinstance(operation_id, str) or _SAFE_OPERATION_ID.fullmatch(operation_id) is None:
                raise ValueError("invalid local operation identity")
            if any(
                isinstance(record[key], bool) or not isinstance(record[key], int) or record[key] < 1
                for key in ("finding_id", "finding_revision", "attempt")
            ) or record["attempt"] > job.attempt:
                raise ValueError("invalid local operation ownership")
            binding = advisor_grants.normalize_local_operation_binding(record["binding"])
            config = self._advisor_config(job)
            profile = advisor_providers.provider_by_id(config["advisor_providers"], binding["provider_id"])
            if binding != advisor_grants.local_operation_binding(profile, binding["prompt_sha256"]):
                raise ValueError("local operation provider binding changed")
            with self.runtime.session_factory() as db:
                finding = db.get(Finding, record["finding_id"])
                if finding is None or finding.scan_id != job.scan_id:
                    raise ValueError("local operation finding ownership changed")
            monitor.raise_if_lease_lost()
            return advisor.cancel_local_operation_sync(binding, operation_id, self.settings)
        except (KeyError, TypeError, ValueError, HTTPException, advisor.ConnectorCleanupUnconfirmed) as exc:
            raise JobExecutionError(
                "advisor_cancel_unconfirmed",
                "Local Advisor connector cleanup is not yet confirmed; cancellation remains pending.",
                retryable=True,
            ) from exc

    def _cancel_external_if_present(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
    ) -> dict[str, Any] | None:
        if job.kind in _UPDATER_JOB_KINDS:
            return self._cancel_updater_if_present(job, monitor)
        local_receipt = self._cancel_local_advisor_if_present(job, monitor)
        if job.kind == "advisor":
            config = self._advisor_config(job)
            confirmation = config.get("remote_advisor_confirmation")
            operation_id = config.get("advisor_operation_id")
            if confirmation is None:
                return local_receipt
            try:
                profile = advisor_providers.provider_by_id(
                    config["advisor_providers"], confirmation["provider_id"]
                )
                monitor.raise_if_lease_lost()
                return advisor.cancel_remote_operation_sync(
                    profile,
                    confirmation,
                    str(operation_id),
                    self.settings,
                )
            except (KeyError, ValueError, HTTPException, advisor.ConnectorCleanupUnconfirmed) as exc:
                raise JobExecutionError(
                    "advisor_cancel_unconfirmed",
                    "Remote Advisor connector cleanup is not yet confirmed; cancellation remains pending.",
                    retryable=True,
                ) from exc
        return self._cancel_scanner_if_present(job, monitor)

    def _scanner_request_for_job(self, job: ClaimedJob) -> dict[str, Any]:
        if job.scan_id is None:
            raise JobExecutionError("missing_scan", "Scan job has no scan reference.")
        with self.runtime.session_factory() as db:
            scan = db.get(Scan, job.scan_id)
            project = db.get(Project, scan.project_id) if scan else None
            if scan is None or project is None:
                raise JobExecutionError("missing_scan", "Scan or source project no longer exists.")
            return self._scanner_request_payload(job, scan, project)

    def _prepare_scanner_artifact_provenance(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        *,
        request_digest: str,
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        monitor.raise_if_unusable()
        artifacts_digest = hashlib.sha256(
            _canonical_json_bytes(manifest["artifacts"])
        ).hexdigest()
        try:
            with self.runtime.session_factory() as db:
                current = db.get(Job, job.id)
                if current is None:
                    raise JobExecutionError("missing_job", "Scan job no longer exists.")
                checkpoint = dict(current.checkpoint or {})
        except SQLAlchemyError as exc:
            raise ScannerRecoveryPending("scanner_db_uncertain") from exc
        existing_provenance = _checkpoint_artifact_digest(
            checkpoint,
            "artifact_provenance",
        )
        existing_request_digest, existing_result_digest = _checkpoint_scanner_binding(
            checkpoint
        )
        existing_binding = (
            existing_request_digest,
            existing_result_digest,
            _checkpoint_artifact_digest(checkpoint, "artifact_manifest"),
        )
        expected_binding = (
            request_digest,
            manifest["result_digest"],
            artifacts_digest,
        )
        if existing_provenance is not None:
            if (
                not isinstance(existing_provenance, str)
                or _SAFE_SHA256.fullmatch(existing_provenance) is None
                or existing_binding != expected_binding
            ):
                raise JobExecutionError(
                    "scanner_protocol",
                    "Durable artifact provenance is bound to different scanner evidence.",
                    scanner_binding=(
                        str(job.external_run_id),
                        request_digest,
                        manifest["result_digest"],
                    ),
                )
        elif any(value is not None for value in existing_binding):
            raise JobExecutionError(
                "scanner_protocol",
                "Durable artifact provenance checkpoint is incomplete.",
                scanner_binding=(
                    str(job.external_run_id),
                    request_digest,
                    manifest["result_digest"],
                ),
            )
        try:
            provenance = prepare_scan_artifact_provenance(
                self.settings,
                int(job.scan_id or 0),
                manifest["artifacts"],
                expected_digest=(
                    str(existing_provenance)
                    if existing_provenance is not None
                    else None
                ),
            )
        except ArtifactAttestationError as exc:
            raise JobExecutionError(
                "scanner_protocol",
                "Scanner artifact evidence failed its durable provenance boundary.",
                scanner_binding=(
                    str(job.external_run_id),
                    request_digest,
                    manifest["result_digest"],
                ),
            ) from exc
        monitor.raise_if_unusable()
        if existing_provenance is not None:
            return checkpoint
        checkpoint.update(
            {
                "scanner_evidence": {
                    "request_digest": request_digest,
                    "sha256": manifest["result_digest"],
                },
                "artifact_manifest": {"sha256": artifacts_digest},
                "artifact_provenance": {"sha256": provenance},
            }
        )
        try:
            self._set_progress(
                job,
                progress=30,
                stage="scanner_evidence",
                detail="Scanner artifact provenance is durably bound before publication.",
                checkpoint=checkpoint,
            )
        except SQLAlchemyError as exc:
            # Whether this short provenance transaction committed is resolved
            # by reloading the typed binding on the next durable lease.
            raise ScannerRecoveryPending("scanner_db_uncertain") from exc
        monitor.raise_if_unusable()
        return checkpoint

    def _execute_scan(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        *,
        use_ai: bool,
    ) -> ExecutionCompletion:
        if job.scan_id is None:
            raise JobExecutionError("missing_scan", "Scan job has no scan reference.")
        checkpoint, _current_progress = self._load_checkpoint(job)
        self._resume_rejected_scanner_cleanup(job, monitor, checkpoint)
        if not checkpoint.get("scanner_persisted"):
            with self.runtime.session_factory() as db:
                scan = db.get(Scan, job.scan_id)
                project = db.get(Project, scan.project_id) if scan else None
                if scan is None or project is None:
                    raise JobExecutionError("missing_scan", "Scan or source project no longer exists.")
                request_payload = self._scanner_request_payload(job, scan, project)
                scan.status = "running"
                scan.started_at = scan.started_at or datetime.now(timezone.utc)
                scan.error = None
                scan.revision += 1
                db.add(scan)
                db.commit()

            self._set_progress(
                job,
                progress=15,
                stage="scanner",
                detail="Stable scanner run is starting.",
            )
            request_digest = _scanner_request_digest(request_payload)
            registry_resets = 0
            with self._scanner_client_factory() as scanner_client:
                while True:
                    admission_deadline = (
                        time.monotonic() + self.settings.worker_scanner_admission_wait_seconds
                    )
                    while True:
                        monitor.raise_if_unusable()
                        try:
                            state = self._start_scanner(scanner_client, request_payload)
                            break
                        except JobExecutionError as exc:
                            if exc.scanner_binding is not None:
                                self._cleanup_bound_scanner_protocol_error(
                                    job,
                                    monitor,
                                    scanner_client,
                                    exc,
                                )
                                raise
                            if exc.code != "scanner_busy":
                                raise
                            if time.monotonic() >= admission_deadline:
                                raise JobExecutionError(
                                    "scanner_busy",
                                    "Scanner admission stayed busy for the bounded local wait.",
                                    retryable=True,
                                ) from exc
                            if monitor.cancel_requested.wait(self.settings.worker_poll_seconds):
                                raise CancellationRequested("durable cancellation requested")
                    try:
                        state = self._wait_for_scanner(
                            job,
                            state,
                            monitor,
                            request_payload,
                            scanner_client,
                        )
                    except JobExecutionError as exc:
                        if exc.scanner_binding is not None:
                            self._cleanup_bound_scanner_protocol_error(
                                job,
                                monitor,
                                scanner_client,
                                exc,
                            )
                        raise
                    scanner_status = str(state.get("status"))
                    if scanner_status == "cancelled":
                        raise CancellationRequested("scanner run was cancelled")
                    if scanner_status != "completed":
                        code = str(state.get("error_code") or "scanner_run_failed")
                        raise JobExecutionError(
                            code,
                            "Scanner run failed before it produced admissible evidence.",
                            retryable=False,
                        )
                    manifest = state.get("result_manifest")
                    if not isinstance(manifest, dict) or state.get("result_available") is not True:
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Completed scanner run has no available immutable result.",
                        )
                    try:
                        checkpoint = self._prepare_scanner_artifact_provenance(
                            job,
                            monitor,
                            request_digest=request_digest,
                            manifest=manifest,
                        )
                        try:
                            checkpoint = self._persist_scanner_manifest(
                                job,
                                manifest,
                                scanner_client,
                                monitor,
                                request_digest=request_digest,
                                checkpoint=checkpoint,
                                use_ai=use_ai,
                            )
                        except SQLAlchemyError:
                            checkpoint = self._reload_persisted_scanner_outcome(
                                job,
                                request_digest=request_digest,
                                result_digest=str(manifest["result_digest"]),
                            )
                    except JobExecutionError as exc:
                        if exc.code == "scanner_run_missing" and registry_resets < 3:
                            registry_resets += 1
                            continue
                        if not exc.retryable:
                            self._record_scanner_cleanup_pending(
                                job,
                                request_digest=request_digest,
                                result_digest=str(manifest["result_digest"]),
                                error_code=exc.code,
                            )
                            self._discard_scanner_result(
                                scanner_client,
                                monitor,
                                run_id=str(job.external_run_id),
                                request_digest=request_digest,
                                result_digest=manifest["result_digest"],
                            )
                        raise
                    checkpoint = self._acknowledge_persisted_scanner_result(
                        job,
                        scanner_client,
                        checkpoint,
                        monitor,
                        use_ai=use_ai,
                    )
                    break
        else:
            with self._scanner_client_factory() as scanner_client:
                checkpoint = self._acknowledge_persisted_scanner_result(
                    job,
                    scanner_client,
                    checkpoint,
                    monitor,
                    use_ai=use_ai,
                )

        advisor_warning = False
        if use_ai:
            try:
                checkpoint = self._triage_scan_findings(job, monitor, checkpoint, automatic=True)
            except JobExecutionError as exc:
                advisor_warning = True
                checkpoint = {**checkpoint, "advisor_error": exc.code}
                with self.runtime.session_factory() as db, db.begin():
                    scan = db.scalar(
                        select(Scan)
                        .where(Scan.id == job.scan_id)
                        .with_for_update()
                    )
                    if scan is not None:
                        summary = dict(scan.scanner_summary or {})
                        summary["advisor"] = {
                            "status": "failed",
                            "error_code": exc.code,
                            "detail": "Optional local advisor failed; scanner evidence and deterministic gate remain available.",
                        }
                        scan.scanner_summary = domain._redacted_json_object(summary)
                        scan.revision += 1
                        db.add(scan)
                    try:
                        update_job_progress(
                            db,
                            job.id,
                            worker_id=self.worker_id,
                            attempt=job.attempt,
                            progress=93,
                            stage="gate",
                            detail="Scanner evidence persisted; optional advisor did not complete.",
                            checkpoint=checkpoint,
                        )
                    except InvalidJobTransition as transition:
                        raise CancellationRequested("cancellation won the advisor failure race") from transition
        scan_status = str(checkpoint.get("scan_status") or "completed")
        return ExecutionCompletion(
            detail=(
                f"Scan #{job.scan_id} finished with durable evidence; optional advisor failed."
                if advisor_warning
                else f"Scan #{job.scan_id} finished with durable scanner evidence."
            ),
            result_ref=f"scan:{job.scan_id}",
            scan_id=job.scan_id,
            scan_status=scan_status,
        )

    def _persist_scanner_manifest(
        self,
        job: ClaimedJob,
        manifest: dict[str, Any],
        client: httpx.Client,
        monitor: LeaseMonitor,
        *,
        request_digest: str,
        checkpoint: dict[str, Any],
        use_ai: bool,
    ) -> dict[str, Any]:
        monitor.raise_if_unusable()
        total = int(manifest["findings_total"])
        raw_artifacts = manifest["artifacts"]
        if total > self.settings.worker_max_findings:
            raise JobExecutionError("scanner_result_too_large", "Scanner result exceeds the finding limit.")
        if len(raw_artifacts) > self.settings.worker_max_artifacts:
            raise JobExecutionError("scanner_result_too_large", "Scanner result exceeds the artifact limit.")
        final_status = str(manifest["status"])
        summary = dict(manifest["summary"])
        coverage_snapshot = _validated_scan_coverage_snapshot(job.payload)
        if coverage_snapshot["coverage"] == "limited":
            requested_tool_ids = coverage_snapshot["requested_tools"]
            ready_tool_ids = coverage_snapshot["enabled_tools"]
            omitted_tools = coverage_snapshot["omitted_tools"]
            summary["coverage"] = {
                "mode": "limited",
                "complete": False,
                "requested_tool_ids": requested_tool_ids,
                "ready_tool_ids": ready_tool_ids,
                "omitted_tool_ids": sorted(
                    item["id"] for item in omitted_tools
                ),
                "omitted_tools": omitted_tools,
                "preflight_revision": coverage_snapshot["preflight_revision"],
            }
            # A user may explicitly choose available-tools execution, but its
            # evidence can never satisfy the complete deterministic gate.
            final_status = "partial"
        severity_counts: dict[str, int] = {}
        scanner_counts: dict[str, int] = {}
        fingerprints: set[str] = set()
        findings_hash = hashlib.sha256()
        findings_bytes = 0
        finding_count = 0
        page_count = 0
        next_cursor: str | None = None
        previous_sort_key: tuple[int, str, int, int, int, int, str, str, str] | None = None
        with self.runtime.session_factory() as db, db.begin():
            # All finding writers lock the parent scan first. Persistence also
            # refuses to replace existing evidence: a durable retry must
            # recover the committed checkpoint, never erase operator state.
            scan = db.scalar(
                select(Scan).where(Scan.id == job.scan_id).with_for_update()
            )
            if scan is None:
                raise JobExecutionError("missing_scan", "Scan no longer exists.")
            existing_findings = db.scalar(
                select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
            )
            existing_artifacts = db.scalar(
                select(func.count(ScanArtifact.id)).where(ScanArtifact.scan_id == scan.id)
            )
            if int(existing_findings or 0) or int(existing_artifacts or 0):
                raise JobExecutionError(
                    "scan_evidence_conflict",
                    "Scan already has persisted evidence; refusing to replace operator state.",
                )
            while finding_count < total:
                monitor.raise_if_unusable()
                page, items = self._get_scanner_page(
                    client,
                    run_id=str(job.external_run_id),
                    request_digest=request_digest,
                    manifest=manifest,
                    expected_ordinal=finding_count + 1,
                    cursor=next_cursor,
                )
                monitor.raise_if_unusable()
                prospective_count = finding_count + len(items)
                prospective_bytes = findings_bytes + int(page["items_bytes"])
                prospective_pages = page_count + 1
                if (
                    prospective_count > total
                    or prospective_bytes > int(manifest["findings_bytes"])
                    or prospective_bytes > _SCANNER_MAX_RUN_BYTES
                    or prospective_pages > int(manifest["page_count"])
                ):
                    raise JobExecutionError(
                        "scanner_protocol",
                        "Scanner finding page prospectively exceeds its immutable manifest.",
                    )
                rows: list[dict[str, Any]] = []
                for item, encoded in items:
                    fingerprint = item["fingerprint"]
                    if fingerprint in fingerprints:
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Scanner result contains a duplicate finding fingerprint.",
                        )
                    fingerprints.add(fingerprint)
                    sort_key = (
                        _SCANNER_SEVERITY_RANK[item["severity"]],
                        item["file_path"],
                        item["start_line"] or 0,
                        item["start_column"] or 0,
                        item["end_line"] or 0,
                        item["end_column"] or 0,
                        item["scanner"],
                        item["rule_id"],
                        fingerprint,
                    )
                    if previous_sort_key is not None and sort_key < previous_sort_key:
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Scanner findings are not in their canonical global order.",
                        )
                    previous_sort_key = sort_key
                    findings_hash.update(encoded)
                    findings_bytes += len(encoded)
                    finding_count += 1
                    severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
                    scanner_counts[item["scanner"]] = scanner_counts.get(item["scanner"], 0) + 1
                    redacted = redact_finding_payload(item)
                    raw_redacted_message = str(redacted["message"])
                    raw_redacted_snippet = (
                        str(redacted["code_snippet"])
                        if redacted.get("code_snippet") is not None
                        else None
                    )
                    redacted_message = raw_redacted_message.replace("\x00", "")
                    redacted_snippet = (
                        raw_redacted_snippet.replace("\x00", "")
                        if raw_redacted_snippet is not None
                        else None
                    )
                    redacted_metadata = dict(redacted.get("metadata") or {})
                    nul_removed: list[str] = []
                    if redacted_message != raw_redacted_message:
                        nul_removed.append("message")
                    if redacted_snippet != raw_redacted_snippet:
                        nul_removed.append("code_snippet")
                    if nul_removed:
                        redacted_metadata["transport_nul_removed"] = nul_removed
                    if (
                        len(_canonical_json_bytes(redacted_message))
                        > _SCANNER_MAX_MESSAGE_JSON_BYTES
                        or (
                            redacted_snippet is not None
                            and len(_canonical_json_bytes(redacted_snippet))
                            > _SCANNER_MAX_SNIPPET_JSON_BYTES
                        )
                    ):
                        raise JobExecutionError(
                            "scanner_protocol",
                            "Redacted scanner evidence exceeds its persistence wire bound.",
                        )
                    rows.append(
                        {
                            "scan_id": scan.id,
                            "scan_finding_number": finding_count,
                            "scanner": item["scanner"],
                            "rule_id": item["rule_id"],
                            "severity": item["severity"],
                            "file_path": item["file_path"],
                            "start_line": item["start_line"],
                            "start_column": item["start_column"],
                            "end_line": item["end_line"],
                            "end_column": item["end_column"],
                            "message": redacted_message,
                            "code_snippet": redacted_snippet,
                            "fingerprint": fingerprint,
                            "metadata_json": domain._bounded_redacted_finding_metadata(
                                redacted_metadata
                            ),
                            "lifecycle_status": "open",
                            "gate_exempt": False,
                            "revision": 1,
                        }
                    )
                page_count += 1
                next_cursor = page["next_cursor"]
                monitor.raise_if_unusable()
                db.execute(insert(Finding), rows)
                if next_cursor is None:
                    break
            if total == 0:
                if manifest["findings_digest"] != hashlib.sha256(b"").hexdigest():
                    raise JobExecutionError(
                        "scanner_protocol",
                        "Empty scanner result has the wrong findings digest.",
                    )
            if (
                finding_count != total
                or findings_bytes != manifest["findings_bytes"]
                or page_count != manifest["page_count"]
                or next_cursor is not None
                or not hmac.compare_digest(findings_hash.hexdigest(), manifest["findings_digest"])
            ):
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner result pages do not reconcile with their immutable manifest.",
                )
            for count_map, expected, label in (
                (summary.get("severity_counts"), severity_counts, "severity"),
                (summary.get("scanner_counts"), scanner_counts, "scanner"),
            ):
                if (
                    not isinstance(count_map, dict)
                    or any(
                        not isinstance(key, str)
                        or not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                        for key, value in count_map.items()
                    )
                    or count_map != expected
                ):
                    raise JobExecutionError(
                        "scanner_protocol",
                        f"Scanner summary {label} counts do not reconcile.",
                    )
            if summary.get("artifacts") != raw_artifacts:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner summary artifacts do not reconcile with the manifest.",
                )
            try:
                admitted_artifacts = admit_scan_artifacts(
                    db,
                    self.settings,
                    scan.id,
                    raw_artifacts,
                    provenance_digest=str(
                        _checkpoint_artifact_digest(checkpoint, "artifact_provenance")
                    ),
                )
            except ArtifactAttestationError as exc:
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner artifact provenance changed during result persistence.",
                ) from exc
            except ArtifactBoundaryError as exc:
                raise JobExecutionError(
                    "artifact_publication_failed",
                    "A validated scanner artifact could not be published atomically.",
                    retryable=True,
                ) from exc
            if len(admitted_artifacts) != len(raw_artifacts):
                raise JobExecutionError(
                    "scanner_protocol",
                    "Scanner artifact declarations were not admitted exactly.",
                )
            checkpoint.update(
                {
                    "scanner_persisted": True,
                    "scan_status": final_status,
                    "scanner_findings_total": finding_count,
                    "scanner_findings_bytes": findings_bytes,
                    "advisor_completed": [],
                }
            )
            scan.scanner_summary = domain._redacted_json_object(summary)
            scan.status = "analyzing" if use_ai else "running"
            scan.error = None
            scan.completed_at = None
            scan.duration_ms = None
            scan.revision += 1
            scan.findings_revision += 1
            db.add(scan)
            update_job_progress(
                db,
                job.id,
                worker_id=self.worker_id,
                attempt=job.attempt,
                progress=82,
                stage="advisor" if use_ai else "gate",
                detail=f"Persisted {finding_count} redacted findings and attested artifacts.",
                checkpoint=checkpoint,
            )
        return checkpoint

    def _advisor_config(self, job: ClaimedJob) -> dict[str, Any]:
        snapshot = job.payload.get("advisor")
        if not isinstance(snapshot, dict):
            raise JobExecutionError("invalid_payload", "Advisor settings snapshot is missing.")
        raw_consent = snapshot.get("advisor_provider_consent")
        try:
            consent = (
                advisor_providers.normalize_consent(raw_consent)
                if isinstance(raw_consent, dict)
                else None
            )
            raw_consents = snapshot.get("advisor_provider_consents", {})
            if not isinstance(raw_consents, dict) or len(raw_consents) > 8:
                raise ValueError("consent map is invalid")
            consents = {
                str(provider_id): advisor_providers.normalize_consent(value)
                for provider_id, value in raw_consents.items()
                if isinstance(provider_id, str) and isinstance(value, dict)
            }
            if len(consents) != len(raw_consents):
                raise ValueError("consent map is invalid")
            raw_receipts = snapshot.get("advisor_provider_receipts", {})
            if not isinstance(raw_receipts, dict) or len(raw_receipts) > 8:
                raise ValueError("receipt map is invalid")
            receipts = {
                str(provider_id): advisor_providers.normalize_receipt(value)
                for provider_id, value in raw_receipts.items()
                if isinstance(provider_id, str) and isinstance(value, dict)
            }
            if len(receipts) != len(raw_receipts):
                raise ValueError("receipt map is invalid")
        except ValueError as exc:
            raise JobExecutionError(
                "invalid_payload", "Advisor disclosure-consent snapshot is invalid."
            ) from exc
        raw_collection = snapshot.get("advisor_providers")
        if not isinstance(raw_collection, dict):
            raise JobExecutionError(
                "advisor_provider_snapshot_missing",
                "Advisor provider snapshot is missing; refresh Advisor providers and submit a new command.",
            )
        try:
            collection = advisor_providers.normalize_job_collection_snapshot(
                raw_collection
            )
        except ValueError as exc:
            raise JobExecutionError(
                "advisor_provider_snapshot_invalid",
                "Advisor provider snapshot is invalid; refresh Advisor providers and submit a new command.",
            ) from exc
        if (
            collection.get("state_error")
            == advisor_providers.PROVIDER_STATE_CORRUPT
        ):
            raise JobExecutionError(
                "advisor_provider_snapshot_corrupt",
                "Advisor provider configuration is corrupt; repair it before submitting a new command.",
            )
        if not collection["providers"]:
            raise JobExecutionError(
                "advisor_provider_snapshot_empty",
                "No Advisor provider is configured; configure the local transport before submitting a new command.",
            )
        raw_pin = job.payload.get("advisor_provider_pin")
        pin: dict[str, Any] | None = None
        if raw_pin is not None:
            if not isinstance(raw_pin, dict):
                raise JobExecutionError(
                    "advisor_provider_pin_invalid",
                    "Advisor provider pin is invalid; refresh Advisor providers and submit a new command.",
                )
            try:
                normalized_pin = advisor_providers.normalize_job_pin_snapshot(raw_pin)
                if raw_pin != advisor_providers.job_pin_snapshot(normalized_pin):
                    raise ValueError("provider pin snapshot is not canonical")
                pinned_profile = advisor_providers.provider_by_id(
                    collection, normalized_pin["provider_id"]
                )
            except ValueError as exc:
                raise JobExecutionError(
                    "advisor_provider_pin_invalid",
                    "Advisor provider pin is invalid; refresh Advisor providers and submit a new command.",
                ) from exc
            except KeyError as exc:
                raise JobExecutionError(
                    "advisor_provider_selection_stale",
                    "Advisor provider pin is missing from its snapshot; refresh providers and submit a new command.",
                ) from exc
            expected_pin = {
                "provider_id": pinned_profile["id"],
                "transport": pinned_profile["transport"],
                "provider_config_revision": pinned_profile["config_revision"],
                "provider_config_digest": pinned_profile["config_digest"],
                "model": pinned_profile["model"],
                "model_digest": pinned_profile["model_digest"],
            }
            if (
                normalized_pin != expected_pin
                or job.payload.get("advisor_provider_collection_revision")
                != collection["revision"]
            ):
                raise JobExecutionError(
                    "advisor_provider_selection_stale",
                    "Advisor provider pin does not match its exact collection snapshot; refresh providers and submit a new command.",
                )
            pin = expected_pin
        elif job.kind == "advisor":
            raise JobExecutionError(
                "advisor_provider_pin_missing",
                "Advisor job has no exact provider pin; refresh providers and submit a new command.",
            )
        raw_confirmation = job.payload.get("remote_advisor_confirmation")
        raw_operation_id = job.payload.get("advisor_operation_id")
        confirmation: dict[str, Any] | None = None
        if raw_confirmation is not None:
            if not isinstance(raw_confirmation, dict):
                raise JobExecutionError(
                    "invalid_payload", "Remote Advisor confirmation is invalid."
                )
            try:
                confirmation = advisor_disclosure.normalize_confirmation(
                    raw_confirmation
                )
            except ValueError as exc:
                raise JobExecutionError(
                    "invalid_payload", "Remote Advisor confirmation is invalid."
                ) from exc
            if (
                pin is None
                or not isinstance(raw_operation_id, str)
                or _SAFE_OPERATION_ID.fullmatch(raw_operation_id) is None
                or pin["transport"] not in {"direct", "ssh"}
                or any(
                    confirmation[confirmation_key] != pin[pin_key]
                    for confirmation_key, pin_key in (
                        ("provider_id", "provider_id"),
                        ("transport", "transport"),
                        ("provider_config_revision", "provider_config_revision"),
                        ("provider_config_digest", "provider_config_digest"),
                        ("model", "model"),
                        ("model_digest", "model_digest"),
                    )
                )
                or job.payload.get("advisor_provider_collection_revision")
                != collection["revision"]
            ):
                raise JobExecutionError(
                    "invalid_payload",
                    "Remote Advisor confirmation does not match its exact provider snapshot.",
                )
        elif pin is not None and pin["transport"] in {"direct", "ssh"}:
            raise JobExecutionError(
                "invalid_payload",
                "A remote Advisor provider pin requires one exact disclosure confirmation.",
            )
        elif raw_operation_id is not None:
            raise JobExecutionError(
                "invalid_payload",
                "A local Advisor provider must not declare a remote operation id.",
            )
        return {
            "ai_mode": str(snapshot.get("ai_mode") or "off"),
            "ollama_base_url": domain._normalize_ollama_base_url(
                str(snapshot.get("ollama_base_url") or ""),
                self.settings,
            ),
            "ollama_model": domain._normalize_ollama_model(
                str(job.payload.get("model") or snapshot.get("ollama_model") or ""),
                self.settings,
            ),
            "ollama_thinking": bool(snapshot.get("ollama_thinking")),
            "auto_triage_limit": domain._normalize_auto_triage_limit(
                snapshot.get("auto_triage_limit"),
                self.settings,
            ),
            "advisor_providers": collection,
            "advisor_provider_consent": consent,
            "advisor_provider_consents": consents,
            "advisor_provider_receipts": receipts,
            "advisor_provider_pin": pin,
            "remote_advisor_confirmation": confirmation,
            "advisor_operation_id": raw_operation_id,
        }

    def _triage_scan_findings(
        self,
        job: ClaimedJob,
        monitor: LeaseMonitor,
        checkpoint: dict[str, Any],
        *,
        automatic: bool,
    ) -> dict[str, Any]:
        if job.scan_id is None:
            raise JobExecutionError("missing_scan", "Advisor job has no scan reference.")
        config = self._advisor_config(job)
        if checkpoint.get("local_advisor_operation") is not None:
            # A recovered attempt cannot overlap an earlier local request. The
            # exact connector cleanup acknowledgement precedes a new identity.
            self._cancel_local_advisor_if_present(job, monitor)
            checkpoint = {key: value for key, value in checkpoint.items() if key != "local_advisor_operation"}
            self._set_progress(
                job, progress=max(5, self._load_checkpoint(job)[1]),
                stage="advisor", detail="Confirmed prior local Advisor transport cleanup.",
                checkpoint=checkpoint,
            )
            monitor.raise_if_unusable()
        completed = {
            int(value)
            for value in checkpoint.get("advisor_completed", [])
            if isinstance(value, int)
            or (isinstance(value, str) and value.isdigit())
        }
        try:
            selection = advisor_selection_snapshot(job.payload)
        except AdvisorSelectionError as exc:
            raise JobExecutionError(exc.code, exc.detail, retryable=False) from exc
        selected_ids = selection.finding_ids
        expected_revisions = selection.expected_revisions
        include_existing = bool(job.payload.get("include_existing")) if not automatic else False
        limit_value = job.payload.get("limit")
        if automatic:
            limit_value = config["auto_triage_limit"]
        if limit_value is None and selected_ids is not None:
            bounded_limit = len(selected_ids)
        elif limit_value is None:
            bounded_limit = 100
        else:
            bounded_limit = max(0, min(int(limit_value), 200))
        remote_confirmation = config.get("remote_advisor_confirmation")
        if remote_confirmation is not None and (
            automatic
            or job.payload.get("operation") != "advisor_finding"
            or job.finding_id is None
            or selected_ids != [job.finding_id]
            or expected_revisions is None
            or set(expected_revisions) != {job.finding_id}
            or not include_existing
            or bounded_limit != 1
        ):
            raise JobExecutionError(
                "invalid_payload",
                "Remote Advisor execution is restricted to one exact finding revision.",
            )
        if bounded_limit == 0:
            return checkpoint
        with self.runtime.session_factory() as db:
            query = select(Finding.id, Finding.revision).where(
                Finding.scan_id == job.scan_id,
                Finding.suppressed.is_(False),
            )
            if selected_ids is not None:
                query = query.where(Finding.id.in_(selected_ids))
            if not include_existing:
                query = query.where(Finding.ai_verdict.is_(None))
            severity_order = case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                (Finding.severity == "info", 4),
                else_=5,
            )
            query = query.order_by(
                severity_order,
                Finding.file_path,
                func.coalesce(Finding.start_line, 0),
                Finding.scanner,
                Finding.rule_id,
                Finding.id,
            ).limit(bounded_limit)
            candidate_rows = [
                (int(finding_id), int(revision))
                for finding_id, revision in db.execute(query).all()
            ]
            candidate_ids = [finding_id for finding_id, _revision in candidate_rows]
            candidate_revisions = dict(candidate_rows)
            try:
                selection.require_current(
                    candidate_revisions, completed=completed, include_existing=include_existing
                )
            except AdvisorSelectionError as exc:
                raise JobExecutionError(exc.code, exc.detail, retryable=False) from exc
            if not automatic and not candidate_ids:
                raise JobExecutionError(
                    "advisor_no_eligible_findings",
                    "No eligible active findings remain for this advisor command; refresh Findings before submitting another review.",
                    retryable=False,
                )
        total = len(candidate_ids)
        remote_attempt_reserved = False
        if remote_confirmation is not None and candidate_ids:
            operation_id = config.get("advisor_operation_id")
            expected_transmission = {
                "advisor_operation_id": operation_id,
                "confirmation_digest": remote_confirmation["confirmation_digest"],
                "state": "reserved_before_send",
            }
            prior_transmission = checkpoint.get("remote_advisor_transmission")
            if prior_transmission is not None:
                if prior_transmission != expected_transmission:
                    raise JobExecutionError(
                        "invalid_payload",
                        "Remote Advisor transmission checkpoint does not match its exact confirmation.",
                        retryable=False,
                    )
                raise JobExecutionError(
                    "advisor_remote_confirmation_consumed",
                    "This one-finding remote Advisor authorization may already have transmitted its prompt. It will not be sent again; refresh the finding, review a fresh disclosure preview, and explicitly confirm a new request.",
                    retryable=False,
                )
            checkpoint = {
                **checkpoint,
                "remote_advisor_transmission": expected_transmission,
            }
            # Commit the one-use marker before connector admission. If either
            # process crashes after this point, lease recovery fails closed
            # instead of silently reusing the operator's disclosure consent.
            self._set_progress(
                job,
                progress=5,
                stage="advisor_disclosure_reserved",
                detail="Reserved this exact one-finding remote disclosure once; it will not be resent after an uncertain outcome.",
                checkpoint=checkpoint,
            )
            remote_attempt_reserved = True
            monitor.raise_if_unusable()
        for index, finding_id in enumerate(candidate_ids, start=1):
            if finding_id in completed:
                continue
            monitor.raise_if_unusable()
            with self.runtime.session_factory() as db:
                finding = db.get(Finding, finding_id)
                if finding is None or finding.scan_id != job.scan_id:
                    raise JobExecutionError(
                        "advisor_selection_changed",
                        "A selected finding disappeared before Advisor publication.",
                        retryable=False,
                    )
                def reserve_local_operation(record: dict[str, Any]) -> None:
                    nonlocal checkpoint
                    monitor.raise_if_unusable()
                    checkpoint = {
                        **checkpoint,
                        "local_advisor_operation": {
                            **record, "finding_id": finding_id,
                            "finding_revision": int(finding.revision), "attempt": job.attempt,
                        },
                    }
                    self._set_progress(
                        job, progress=max(5 if not automatic else 82, self._load_checkpoint(job)[1]),
                        stage="advisor", detail="Reserved exact local Advisor request ownership before sending.",
                        checkpoint=checkpoint,
                    )
                    monitor.raise_if_unusable()

                try:
                    advisor.triage_finding_sync(
                        db,
                        finding,
                        self.settings,
                        model=config["ollama_model"],
                        config=config,
                        expected_revision=(
                            expected_revisions[finding_id]
                            if expected_revisions is not None
                            else candidate_revisions[finding_id]
                        ),
                        commit=False,
                        cancel_check=monitor.raise_if_unusable,
                        reserve_local_operation=reserve_local_operation,
                    )
                    monitor.raise_if_unusable()
                    completed.add(finding_id)
                    checkpoint = {
                        **{key: value for key, value in checkpoint.items() if key != "local_advisor_operation"},
                        "advisor_completed": sorted(completed),
                    }
                    progress = 82 + int(index / max(total, 1) * 11) if automatic else 5 + int(index / max(total, 1) * 90)
                    update_job_progress(
                        db,
                        job.id,
                        worker_id=self.worker_id,
                        attempt=job.attempt,
                        progress=min(progress, 93 if automatic else 95),
                        stage="advisor",
                        detail=(
                            f"Remote {config['advisor_provider_pin']['transport']} Advisor "
                            f"analyzed {index}/{total} explicitly confirmed finding."
                            if remote_confirmation is not None
                            else f"Local Advisor analyzed {index}/{total} selected findings."
                        ),
                        checkpoint=checkpoint,
                    )
                    db.commit()
                except (CancellationRequested, LeaseLostError):
                    db.rollback()
                    raise
                except InvalidJobTransition as exc:
                    db.rollback()
                    raise CancellationRequested("cancellation won the advisor checkpoint race") from exc
                except Exception as exc:
                    db.rollback()
                    if isinstance(exc, advisor.ConnectorCleanupUnconfirmed):
                        raise JobExecutionError(
                            "advisor_cancel_unconfirmed",
                            "Advisor connector cleanup is not yet confirmed; cancellation remains pending.",
                            retryable=True,
                        ) from exc
                    if remote_attempt_reserved:
                        raise JobExecutionError(
                            "advisor_remote_confirmation_consumed",
                            "The exact remote Advisor prompt may have been transmitted, but publication was not confirmed. This job will not resend it; refresh the finding, review a fresh disclosure preview, and explicitly confirm a new request.",
                            retryable=False,
                        ) from exc
                    if isinstance(exc, advisor.ConnectorRequestError):
                        raise JobExecutionError(
                            exc.code,
                            f"{exc.safe_detail} {len(completed)}/{total} completed reviews were preserved.",
                            retryable=exc.retryable,
                        ) from exc
                    unavailable = isinstance(exc, HTTPException) and exc.status_code == 503
                    selection_changed = (
                        isinstance(exc, HTTPException) and exc.status_code == 409
                    )
                    preserved = len(completed)
                    route_label = (
                        f"Remote {config['advisor_provider_pin']['transport']} Advisor"
                        if remote_confirmation is not None
                        else "Local Advisor"
                    )
                    detail = (
                        f"{route_label} is unavailable; {preserved}/{total} completed reviews were preserved."
                        if unavailable
                        else (
                            "Selected finding state changed while Advisor was running; reopen Findings and submit a new review."
                            if selection_changed
                            else f"{route_label} output failed; {preserved}/{total} completed reviews were preserved."
                        )
                    )
                    raise JobExecutionError(
                        (
                            "advisor_unavailable"
                            if unavailable
                            else "advisor_selection_changed"
                            if selection_changed
                            else "advisor_failed"
                        ),
                        detail,
                        retryable=not selection_changed,
                    ) from exc
        return checkpoint

    def _execute_advisor_finding(self, job: ClaimedJob, monitor: LeaseMonitor) -> ExecutionCompletion:
        if job.finding_id is None or job.scan_id is None:
            raise JobExecutionError("missing_finding", "Advisor job has no finding reference.")
        checkpoint = dict(job.checkpoint)
        if job.finding_id not in checkpoint.get("advisor_completed", []):
            checkpoint = self._triage_scan_findings(job, monitor, checkpoint, automatic=False)
        raw_pin = job.payload.get("advisor_provider_pin")
        transport = raw_pin.get("transport") if isinstance(raw_pin, dict) else None
        return ExecutionCompletion(
            detail=(
                f"Remote {transport} Advisor triage completed for one explicitly confirmed finding."
                if job.payload.get("remote_advisor_confirmation") is not None
                else "Local Advisor triage completed."
            ),
            result_ref=f"finding:{job.finding_id}",
        )

    def _execute_advisor_scan(self, job: ClaimedJob, monitor: LeaseMonitor) -> ExecutionCompletion:
        checkpoint = self._triage_scan_findings(
            job,
            monitor,
            dict(job.checkpoint),
            automatic=False,
        )
        completed = len(checkpoint.get("advisor_completed", []))
        return ExecutionCompletion(
            detail=f"Local advisor triage completed for {completed} findings.",
            result_ref=f"scan:{job.scan_id}" if job.scan_id is not None else None,
        )

    def _execute_advisor_provider(
        self, job: ClaimedJob, monitor: LeaseMonitor
    ) -> ExecutionCompletion:
        raw_profile = job.payload.get("provider")
        action = job.payload.get("action")
        if not isinstance(raw_profile, dict) or action not in {
            "test",
            "activate",
            "disconnect",
        }:
            raise JobExecutionError(
                "invalid_payload", "Advisor provider command is invalid."
            )
        try:
            profile = advisor_providers.normalize_profile(raw_profile)
        except ValueError as exc:
            raise JobExecutionError(
                "invalid_payload", "Advisor provider snapshot is invalid."
            ) from exc
        approved = bool(job.payload.get("acknowledge_source_disclosure"))
        approval = job.payload.get("source_disclosure_approval")
        if action == "activate" and profile["transport"] in {"direct", "ssh"}:
            if (
                not approved
                or approval != advisor_providers.build_activation_approval(profile)
            ):
                raise JobExecutionError(
                    "source_disclosure_not_approved",
                    "Remote Advisor activation approval does not match the exact provider configuration.",
                    retryable=False,
                )
        elif approved or approval is not None:
            raise JobExecutionError(
                "invalid_payload",
                "Source disclosure approval is valid only for remote activation.",
                retryable=False,
            )
        monitor.raise_if_unusable()
        receipt = None
        if action in {"test", "activate"}:
            self._set_progress(
                job,
                progress=20,
                stage="provider_readiness",
                detail=(
                    f"Checking {profile['transport']} provider reachability and the exact model digest; no source or finding content is sent."
                ),
            )
            monitor.raise_if_unusable()
            try:
                receipt = advisor.test_provider_sync(
                    profile, self.settings, timeout=10.0
                )
            except advisor.ProviderTestFailure as exc:
                raise JobExecutionError(
                    exc.code,
                    exc.safe_detail,
                    retryable=exc.retryable,
                ) from exc
            except HTTPException as exc:
                raise JobExecutionError(
                    "advisor_provider_unavailable",
                    "Advisor provider readiness failed without a typed connector result.",
                    retryable=True,
                ) from exc
            monitor.raise_if_unusable()
        return ExecutionCompletion(
            detail=(
                f"Advisor provider {action} completed with an exact model receipt."
                if receipt is not None
                else "Advisor provider disconnected."
            ),
            result_ref=f"advisor-provider:{profile['id']}",
            advisor_provider_id=profile["id"],
            advisor_provider_action=action,
            advisor_provider_snapshot=profile,
            advisor_provider_receipt=receipt,
            advisor_content_disclosure_approved=approved,
        )

    def _complete(self, job: ClaimedJob, completion: ExecutionCompletion) -> None:
        if (
            completion.lifecycle_receipt is not None
            and self._preparation_record_late(completion.lifecycle_receipt)
        ):
            self._persist_completed_updater_receipt(job, completion.lifecycle_receipt)
            self._fail(job, JobExecutionError(
                "scanner_preparation_deadline",
                "Actual cache outcome was preserved, but preparation completed after its shared deadline.",
            ))
            return
        try:
            with self.runtime.session_factory() as db, db.begin():
                if completion.scan_id is not None:
                    scan = db.scalar(
                        select(Scan)
                        .where(Scan.id == completion.scan_id)
                        .with_for_update()
                    )
                    if scan is None:
                        raise JobExecutionError("missing_scan", "Scan disappeared before completion.")
                    if completion.scan_status == "partial":
                        decision = "incomplete"
                        reasons = [domain.INCOMPLETE_GATE_REASON]
                    else:
                        decision, reasons = domain._evaluate_gate(db, scan)
                    now = datetime.now(timezone.utc)
                    scan.status = completion.scan_status or "completed"
                    scan.gate_decision = decision
                    scan.gate_reasons = domain._redacted_reason_list(reasons)
                    scan.completed_at = now
                    scan.duration_ms = domain._duration_ms_since(scan.started_at, now)
                    scan.revision += 1
                    db.add(scan)
                if completion.lifecycle_scope is not None:
                    current_job = db.get(Job, job.id)
                    if current_job is None or completion.lifecycle_receipt is None:
                        raise JobExecutionError(
                            "lifecycle_state_conflict",
                            "Scanner lifecycle command disappeared before receipt persistence.",
                        )
                    lifecycle = self._apply_completed_updater_state(
                        db,
                        current_job,
                        completion.lifecycle_receipt,
                    )
                    if lifecycle.status == "failed":
                        fail_job(
                            db, job.id, worker_id=self.worker_id, attempt=job.attempt,
                            error_code="scanner_preparation_deadline",
                            error_detail=(
                                "Actual cache outcome was preserved, "
                                "but preparation exceeded its shared deadline."
                            ),
                            retryable=False,
                        )
                        return
                    if current_job.kind == "scanner_catalog_check":
                        catalog_result = completion.lifecycle_receipt.get("result")
                        if not isinstance(catalog_result, dict):
                            raise JobExecutionError(
                                "scanner_preparation_catalog_invalid",
                                "Scanner catalog completion omitted its admitted result.",
                            )
                        _enqueue_scanner_preparation_cache_continuation(
                            db,
                            current_job,
                            catalog_result,
                        )
                if completion.advisor_provider_id is not None:
                    lock_advisor_admission(db)
                    current = advisor_providers.load_collection(
                        db, self.settings, lock=True
                    )
                    try:
                        current_profile = advisor_providers.provider_by_id(
                            current, completion.advisor_provider_id
                        )
                    except KeyError as exc:
                        raise JobExecutionError(
                            "provider_configuration_changed",
                            "Advisor provider was removed while its command was running.",
                        ) from exc
                    if any(
                        current_profile[key]
                        != completion.advisor_provider_snapshot.get(key)
                        for key in ("id", "config_revision", "config_digest")
                    ):
                        raise JobExecutionError(
                            "provider_configuration_changed",
                            "Advisor provider changed while its command was running; the stale result was discarded.",
                        )
                    action = completion.advisor_provider_action
                    if action == "disconnect":
                        updated = advisor_providers.disconnect_provider(
                            current, completion.advisor_provider_id
                        )
                    else:
                        remains_active = (
                            action == "test"
                            and current["active_provider_id"]
                            == completion.advisor_provider_id
                            and current_profile["content_disclosure_approved"]
                        )
                        updated = advisor_providers.update_provider_status(
                            current,
                            completion.advisor_provider_id,
                            status=(
                                "active"
                                if action == "activate" or remains_active
                                else "available"
                            ),
                            reason=None,
                            reason_code=None,
                            remediation="none",
                            activate=action == "activate",
                            approve_content_disclosure=(
                                completion.advisor_content_disclosure_approved
                            ),
                        )
                    advisor_providers.save_collection(db, updated)
                    if completion.advisor_provider_receipt is not None:
                        receipt = {
                            **completion.advisor_provider_receipt,
                            "revision": current_profile["config_revision"],
                        }
                        advisor_providers.save_receipt(
                            db, receipt
                        )
                    if (
                        action == "activate"
                        and current_profile["transport"] in {"direct", "ssh"}
                    ):
                        for other_profile in updated["providers"]:
                            if other_profile["id"] != completion.advisor_provider_id:
                                advisor_providers.delete_consent(
                                    db, other_profile["id"]
                                )
                        advisor_providers.save_consent(
                            db,
                            advisor_providers.build_consent(
                                updated, completion.advisor_provider_id
                            ),
                        )
                    elif action == "disconnect":
                        advisor_providers.delete_consent(
                            db, completion.advisor_provider_id
                        )
                        advisor_providers.delete_receipt(
                            db, completion.advisor_provider_id
                        )
                complete_job(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    detail=completion.detail,
                    result_ref=completion.result_ref,
                )
        except InvalidJobTransition as exc:
            raise CancellationRequested("cancellation won the completion race") from exc

    def _finalize_cancelled(self, job: ClaimedJob) -> None:
        with self.runtime.session_factory() as db, db.begin():
            scan = None
            if job.kind == "scan" and job.scan_id is not None:
                scan = db.scalar(
                    select(Scan)
                    .where(Scan.id == job.scan_id)
                    .with_for_update()
                )
            current = db.scalar(
                select(Job).where(Job.id == job.id).with_for_update(of=Job)
            )
            if current is None:
                return
            if current.status == "cancelled":
                return
            if current.status != "cancelling":
                raise LeaseLostError("job is no longer cancelling under this worker lease")
            if current.kind == "scan" and current.scan_id is not None:
                if current.scan_id != job.scan_id:
                    raise LeaseLostError("job scan identity changed before cancellation finalization")
                if scan is not None and scan.status not in domain.TERMINAL_SCAN_STATUSES:
                    now = datetime.now(timezone.utc)
                    scan.status = "cancelled"
                    scan.error = "Cancelled by local user request."
                    decision, reasons = domain._evaluate_scan_gate(db, scan)
                    scan.gate_decision = decision
                    scan.gate_reasons = domain._redacted_reason_list(reasons)
                    scan.completed_at = now
                    scan.duration_ms = domain._duration_ms_since(scan.started_at, now)
                    scan.revision += 1
                    db.add(scan)
                if not bool((current.checkpoint or {}).get("scanner_persisted")):
                    domain.delete_scan_artifact_tree(self.settings, current.scan_id)
            if current.kind in _UPDATER_JOB_KINDS:
                lifecycle = db.get(
                    ScannerLifecycleState,
                    self._updater_lifecycle_scope(current),
                )
                updater_completed_after_cancel = bool(
                    lifecycle is not None
                    and lifecycle.job_id == current.id
                    and lifecycle.status == "completed"
                    and isinstance(lifecycle.receipt, dict)
                    and lifecycle.receipt
                )
                if lifecycle is not None and lifecycle.job_id == current.id:
                    lifecycle.status = "cancelled"
                    if not updater_completed_after_cancel:
                        lifecycle.receipt = {}
                    lifecycle.error_code = None
                    lifecycle.error_detail = None
                    lifecycle.started_at = lifecycle.started_at or current.started_at
                    lifecycle.completed_at = datetime.now(timezone.utc)
                    lifecycle.updated_at = datetime.now(timezone.utc)
                    lifecycle.revision += 1
                    db.add(lifecycle)
            else:
                updater_completed_after_cancel = False
            finalize_cancelled(
                db,
                job.id,
                worker_id=self.worker_id,
                attempt=job.attempt,
                detail=(
                    "Cancellation won the durable job race after the source-blind updater completed; the verified lifecycle receipt remains authoritative."
                    if updater_completed_after_cancel
                    else "Cancellation confirmed by the source-blind updater."
                    if current.kind in _UPDATER_JOB_KINDS
                    else "Cancellation confirmed; temporary scanner output was cleaned."
                ),
            )

    def _finalize_cancelled_safely(self, job: ClaimedJob) -> bool:
        try:
            self._finalize_cancelled(job)
            return True
        except (SQLAlchemyError, ArtifactBoundaryError, OSError, RuntimeError):
            LOGGER.warning(
                "job cancellation finalization remains pending",
                extra={"job_id": job.id, "error_code": "cancellation_state_uncertain"},
            )
            return False

    def _fail(self, job: ClaimedJob, failure: JobExecutionError) -> None:
        try:
            with self.runtime.session_factory() as db, db.begin():
                current = db.get(Job, job.id)
                if current is None or current.status in {"completed", "failed", "cancelled"}:
                    return
                if current.status == "cancelling" or current.cancel_requested_at is not None:
                    # Leave the durable cancellation eligible for another worker
                    # when scanner cleanup could not be confirmed safely.
                    return
                if (
                    current.kind == "advisor_provider"
                    and current.payload.get("operation") == "advisor_provider_command"
                    and current.payload.get("action") in {"test", "activate"}
                ):
                    lock_advisor_admission(db)
                    raw_profile = current.payload.get("provider")
                    if isinstance(raw_profile, dict):
                        try:
                            snapshot_profile = advisor_providers.normalize_profile(
                                raw_profile
                            )
                            collection = advisor_providers.load_collection(
                                db, self.settings, lock=True
                            )
                            live_profile = advisor_providers.provider_by_id(
                                collection, snapshot_profile["id"]
                            )
                        except (KeyError, ValueError):
                            live_profile = None
                        if live_profile is not None and all(
                            live_profile[key] == snapshot_profile[key]
                            for key in ("config_revision", "config_digest")
                        ):
                            unavailable = advisor_providers.update_provider_status(
                                collection,
                                live_profile["id"],
                                status="unavailable",
                                reason=failure.detail,
                                reason_code=(
                                    failure.code
                                    if advisor_providers.REASON_CODE.fullmatch(failure.code)
                                    else "advisor_provider_unavailable"
                                ),
                                remediation="test",
                                deactivate=True,
                            )
                            advisor_providers.save_collection(db, unavailable)
                            advisor_providers.delete_consent(db, live_profile["id"])
                            advisor_providers.delete_receipt(db, live_profile["id"])
                scan = None
                if current.kind == "scan" and current.scan_id is not None:
                    if current.scan_id != job.scan_id:
                        raise LeaseLostError("job scan identity changed before failure finalization")
                    scan = db.scalar(
                        select(Scan)
                        .where(Scan.id == current.scan_id)
                        .with_for_update()
                    )
                updated = fail_job(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    error_code=failure.code,
                    error_detail=failure.detail,
                    retryable=failure.retryable,
                )
                if updated.kind in _UPDATER_JOB_KINDS:
                    lifecycle = db.get(
                        ScannerLifecycleState,
                        self._updater_lifecycle_scope(updated),
                    )
                    if lifecycle is not None and lifecycle.job_id == updated.id:
                        lifecycle.status = updated.status
                        if failure.code not in {
                            "scanner_preparation_deadline", "scanner_preparation_commit_uncertain",
                        }:
                            lifecycle.receipt = {}
                        lifecycle.error_code = (
                            None if updated.status == "queued" else failure.code
                        )
                        lifecycle.error_detail = (
                            None if updated.status == "queued" else failure.detail
                        )
                        lifecycle.started_at = lifecycle.started_at or updated.started_at
                        lifecycle.completed_at = (
                            None
                            if updated.status == "queued"
                            else datetime.now(timezone.utc)
                        )
                        lifecycle.updated_at = datetime.now(timezone.utc)
                        lifecycle.revision += 1
                        db.add(lifecycle)
                if updated.kind == "scan" and updated.scan_id is not None:
                    if scan is not None:
                        if updated.status == "failed":
                            now = datetime.now(timezone.utc)
                            scan.status = "failed"
                            scan.error = failure.detail
                            decision, reasons = domain._evaluate_scan_gate(db, scan)
                            scan.gate_decision = decision
                            scan.gate_reasons = domain._redacted_reason_list(reasons)
                            scan.completed_at = now
                            scan.duration_ms = domain._duration_ms_since(scan.started_at, now)
                        else:
                            scan.status = "pending"
                            scan.error = None
                            scan.completed_at = None
                            scan.duration_ms = None
                        scan.revision += 1
                        db.add(scan)
                    if updated.status == "failed" and not bool(
                        (updated.checkpoint or {}).get("scanner_persisted")
                    ):
                        domain.delete_scan_artifact_tree(self.settings, updated.scan_id)
        except (LeaseLostError, InvalidJobTransition):
            LOGGER.warning("job failure was fenced by newer state", extra={"job_id": job.id})
        except SQLAlchemyError:
            LOGGER.warning(
                "job failure transaction outcome remains uncertain",
                extra={"job_id": job.id, "error_code": "scanner_db_uncertain"},
            )
        except (ArtifactBoundaryError, OSError, RuntimeError):
            # Filesystem cleanup is part of fail-closed publication. A cleanup
            # failure must not escape the executor or be converted into a
            # misleading success; the durable terminal failure remains the
            # authoritative result and the maintenance sweep can retry it.
            LOGGER.warning(
                "failed scan artifact cleanup remains pending",
                extra={"job_id": job.id, "error_code": "cleanup_failed"},
            )

    def fail_exhausted(self, job: ClaimedJob) -> None:
        self._fail(
            job,
            JobExecutionError(
                "attempts_exhausted",
                "Worker recovery attempts were exhausted after an expired lease.",
                retryable=False,
            ),
        )

    def _defer_exhausted_recovery(self, job: ClaimedJob, *, error_code: str) -> None:
        try:
            self._defer_exhausted_recovery_unchecked(job, error_code=error_code)
        except SQLAlchemyError:
            LOGGER.warning(
                "final-attempt recovery receipt outcome remains uncertain",
                extra={"job_id": job.id, "error_code": "scanner_db_uncertain"},
            )

    def _defer_exhausted_recovery_unchecked(
        self,
        job: ClaimedJob,
        *,
        error_code: str,
    ) -> None:
        """Persist one bounded reconciliation receipt or terminalize it.

        Recovery observation does not consume another execution attempt, but
        an unavailable dependency must not leave a final-attempt job cycling
        forever. Two renewed leases are allowed before the third receipt
        becomes an explicit ``attempts_exhausted`` terminal failure.
        """

        with self.runtime.session_factory() as db, db.begin():
            current = db.get(Job, job.id)
            if current is None:
                return
            checkpoint = dict(current.checkpoint or {})
            reconciliations = int(checkpoint.get("recovery_reconciliations") or 0) + 1
            checkpoint.update(
                {
                    "recovery_reconciliations": reconciliations,
                    "recovery_last_error": error_code,
                }
            )
            if current.status == "leased":
                mark_job_running(
                    db,
                    job.id,
                    worker_id=self.worker_id,
                    attempt=job.attempt,
                    stage="recovery",
                    detail="Reconciling the final durable attempt with its stable external operation.",
                    progress=max(1, int(current.progress or 0)),
                )
            update_job_progress(
                db,
                job.id,
                worker_id=self.worker_id,
                attempt=job.attempt,
                progress=max(1, int(current.progress or 0)),
                stage="recovery_wait",
                detail=(
                    f"Stable operation recovery receipt {reconciliations}/3 could not be completed; "
                    "the existing identity and any already-published evidence remain unchanged."
                ),
                checkpoint=checkpoint,
            )
        if reconciliations >= 3:
            self._fail(
                job,
                JobExecutionError(
                    "attempts_exhausted",
                    "Final-attempt recovery was unavailable after three bounded reconciliation leases; "
                    "no unproven external result was published.",
                    retryable=False,
                ),
            )

    def recover_exhausted(self, job: ClaimedJob) -> None:
        """Reconcile a final crashed attempt without re-running its command."""

        try:
            scan_snapshot = scan_command_snapshot(job.kind, job.payload)
        except InvalidScanCommandSnapshot as exc:
            self._reject_invalid_scan_command(job, exc)
            return
        if job.kind in _UPDATER_JOB_KINDS:
            self._recover_exhausted_updater(job)
            return
        if job.kind != "scan" or not job.external_run_id or job.scan_id is None:
            self.fail_exhausted(job)
            return
        if scan_snapshot is None:
            self.fail_exhausted(job)
            return
        use_ai = scan_snapshot.use_ai
        monitor = LeaseMonitor(self.runtime, job, self.worker_id)
        monitor.start()
        try:
            checkpoint, _current_progress = self._load_checkpoint(job)
            if _checkpoint_scanner_cleanup(checkpoint) is not None:
                self._mark_running(job)
                self._resume_rejected_scanner_cleanup(job, monitor, checkpoint)
            if bool(checkpoint.get("scanner_persisted")):
                self._mark_running(job)
                with self._scanner_client_factory() as scanner_client:
                    checkpoint = self._acknowledge_persisted_scanner_result(
                        job,
                        scanner_client,
                        checkpoint,
                        monitor,
                        use_ai=use_ai,
                    )
                monitor.raise_if_unusable()
                self._complete(
                    job,
                    ExecutionCompletion(
                        detail=f"Recovered already-persisted scanner evidence for scan #{job.scan_id}.",
                        result_ref=f"scan:{job.scan_id}",
                        scan_id=job.scan_id,
                        scan_status=str(checkpoint.get("scan_status") or "completed"),
                    ),
                )
                self._stop_after_terminal(monitor)
                return
            request_payload = self._scanner_request_for_job(job)
            request_digest = _scanner_request_digest(request_payload)
            with self._scanner_client_factory() as scanner_client:
                try:
                    state = self._get_scanner_run(
                        scanner_client,
                        job.external_run_id,
                        request_digest,
                    )
                except JobExecutionError as exc:
                    if exc.scanner_binding is not None:
                        self._cleanup_bound_scanner_protocol_error(
                            job,
                            monitor,
                            scanner_client,
                            exc,
                        )
                        raise
                    if exc.code == "scanner_run_missing":
                        monitor.stop()
                        self.fail_exhausted(job)
                        return
                    if exc.retryable:
                        monitor.stop()
                        self._defer_exhausted_recovery(job, error_code=exc.code)
                        return
                    raise

                self._mark_running(job)
                if str(state.get("status")) not in _SCANNER_TERMINAL:
                    try:
                        state = self._wait_for_scanner(
                            job,
                            state,
                            monitor,
                            request_payload,
                            scanner_client,
                            allow_registry_restart=False,
                        )
                    except JobExecutionError as exc:
                        if exc.scanner_binding is not None:
                            self._cleanup_bound_scanner_protocol_error(
                                job,
                                monitor,
                                scanner_client,
                                exc,
                            )
                        raise

                manifest = state.get("result_manifest")
                if (
                    str(state.get("status")) == "completed"
                    and state.get("result_available") is True
                    and isinstance(manifest, dict)
                ):
                    try:
                        checkpoint = self._prepare_scanner_artifact_provenance(
                            job,
                            monitor,
                            request_digest=request_digest,
                            manifest=manifest,
                        )
                        try:
                            checkpoint = self._persist_scanner_manifest(
                                job,
                                manifest,
                                scanner_client,
                                monitor,
                                request_digest=request_digest,
                                checkpoint=checkpoint,
                                use_ai=use_ai,
                            )
                        except SQLAlchemyError:
                            checkpoint = self._reload_persisted_scanner_outcome(
                                job,
                                request_digest=request_digest,
                                result_digest=str(manifest["result_digest"]),
                            )
                    except JobExecutionError as exc:
                        if not exc.retryable:
                            self._record_scanner_cleanup_pending(
                                job,
                                request_digest=request_digest,
                                result_digest=str(manifest["result_digest"]),
                                error_code=exc.code,
                            )
                            self._discard_scanner_result(
                                scanner_client,
                                monitor,
                                run_id=str(job.external_run_id),
                                request_digest=request_digest,
                                result_digest=manifest["result_digest"],
                            )
                        raise
                    checkpoint = self._acknowledge_persisted_scanner_result(
                        job,
                        scanner_client,
                        checkpoint,
                        monitor,
                        use_ai=use_ai,
                    )
                    monitor.raise_if_unusable()
                    self._complete(
                        job,
                        ExecutionCompletion(
                            detail=f"Recovered completed scanner evidence for scan #{job.scan_id} after final-attempt crash.",
                            result_ref=f"scan:{job.scan_id}",
                            scan_id=job.scan_id,
                            scan_status=str(checkpoint.get("scan_status") or "completed"),
                        ),
                    )
                    self._stop_after_terminal(monitor)
                    return

            monitor.stop()
            self.fail_exhausted(job)
        except ScannerRecoveryPending as exc:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning(
                "final-attempt scanner reconciliation remains pending",
                extra={"job_id": job.id, "error_code": exc.code},
            )
        except CancellationRequested:
            cleanup_failure: BaseException | None = None
            try:
                self._cancel_scanner_if_present(job, monitor)
            except (
                JobExecutionError,
                SQLAlchemyError,
                ArtifactBoundaryError,
                OSError,
                RuntimeError,
            ) as exc:
                cleanup_failure = exc
            try:
                monitor.stop()
            except RuntimeError:
                pass
            if cleanup_failure is not None:
                LOGGER.warning(
                    "exhausted recovery cancellation cleanup remains pending",
                    extra={
                        "job_id": job.id,
                        "error_code": getattr(cleanup_failure, "code", "cleanup_failed"),
                    },
                )
                return
            self._finalize_cancelled_safely(job)
        except LeaseLostError:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning("exhausted recovery lease lost", extra={"job_id": job.id})
        except JobExecutionError as exc:
            try:
                monitor.stop()
            except Exception:
                pass
            if exc.code in {"scanner_cleanup_unconfirmed", "advisor_cancel_unconfirmed"}:
                LOGGER.warning(
                    "final-attempt scanner protocol cleanup remains pending",
                    extra={"job_id": job.id, "error_code": exc.code},
                )
                return
            if exc.retryable:
                self._defer_exhausted_recovery(job, error_code=exc.code)
                return
            self._fail(job, exc)
        except SQLAlchemyError:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning(
                "final-attempt database outcome remains uncertain under the current lease",
                extra={"job_id": job.id, "error_code": "scanner_db_uncertain"},
            )
        except BaseException:
            try:
                monitor.stop()
            except Exception:
                pass
            self._fail(
                job,
                JobExecutionError(
                    "worker_internal_error",
                    "Unexpected worker failure was contained during final-attempt reconciliation.",
                    retryable=False,
                ),
            )

    def _recover_exhausted_updater(self, job: ClaimedJob) -> None:
        if not job.external_run_id:
            self.fail_exhausted(job)
            return
        monitor = LeaseMonitor(self.runtime, job, self.worker_id)
        monitor.start()
        try:
            try:
                record = self._get_updater_operation(job)
            except JobExecutionError as exc:
                monitor.stop()
                if exc.code == "updater_operation_missing":
                    try:
                        self._preparation_bound(job, 1.0)
                    except JobExecutionError as deadline:
                        self._fail(job, deadline)
                    else:
                        self.fail_exhausted(job)
                elif exc.retryable:
                    self._defer_exhausted_recovery(job, error_code=exc.code)
                else:
                    self._fail(job, exc)
                return

            self._mark_running(job)
            self._mark_updater_lifecycle_running(job)
            if str(record["status"]) not in _UPDATER_TERMINAL:
                record = self._wait_for_updater(job, record, monitor)
            status = str(record["status"])
            if status == "completed":
                result = record["result"]
                active = result.get("active") if isinstance(result, dict) else None
                previous = result.get("previous_good") if isinstance(result, dict) else None
                self._complete(
                    job,
                    ExecutionCompletion(
                        detail="Recovered a completed source-blind updater receipt after worker loss.",
                        result_ref=f"scanner-lifecycle:{self._updater_lifecycle_scope(job)}",
                        lifecycle_scope=self._updater_lifecycle_scope(job),
                        lifecycle_receipt=record,
                        active_generation=(
                            str(active["generation_id"])
                            if isinstance(active, dict)
                            else None
                        ),
                        previous_generation=(
                            str(previous["generation_id"])
                            if isinstance(previous, dict)
                            else None
                        ),
                    ),
                )
                self._stop_after_terminal(monitor)
                return
            if status == "cancelled":
                self._persist_updater_terminal_state(job, record)
                with self.runtime.session_factory() as db, db.begin():
                    request_cancellation(
                        db,
                        job.id,
                        detail="Recovered cancellation from the source-blind updater ledger.",
                    )
                self._finalize_cancelled(job)
                self._stop_after_terminal(monitor)
                return
            monitor.stop()
            self._persist_updater_terminal_state(job, record)
            self._fail(
                job,
                JobExecutionError(
                    str(record.get("error_code") or "updater_failed"),
                    str(record.get("error_detail") or "Source-blind updater operation failed."),
                    retryable=False,
                ),
            )
        except CancellationRequested:
            try:
                self._cancel_updater_if_present(job, monitor)
            finally:
                monitor.stop()
            self._finalize_cancelled(job)
        except LeaseLostError:
            try:
                monitor.stop()
            except Exception:
                pass
            LOGGER.warning("exhausted updater recovery lease lost", extra={"job_id": job.id})
        except JobExecutionError as exc:
            try:
                monitor.stop()
            except Exception:
                pass
            self._fail(job, exc)
        except BaseException:
            try:
                monitor.stop()
            except Exception:
                pass
            self._fail(
                job,
                JobExecutionError(
                    "worker_internal_error",
                    "Unexpected worker failure was contained during updater reconciliation.",
                ),
            )
