from __future__ import annotations

import asyncio
import base64
import binascii
import json
import hashlib
import posixpath
import re
import unicodedata
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Literal, get_args
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import Select, case, exists, func, select, tuple_
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from .recovery_contract import RecoveryBudget, RecoveryTarget, issue_recovery_budget, recovery_digest
from .preparation_budget import (
    PreparationBudget,
    PreparationClock,
    PreparationDeadlineExceeded,
    budget_remaining,
    issue_budget,
)
from . import __version__
from .artifact_boundary import (
    ArtifactBoundaryError,
    delete_scan_artifact_tree,
    enforce_artifact_publication_boundary,
    prepare_artifact_download,
)
from .auth import AuthContext, enforce_installation_secret_binding
from .db import Runtime, SchemaSingletonStateError, get_db, get_runtime, init_db
from .jobs.repository import (
    CacheCommitInProgressError,
    IdempotencyConflictError,
    InvalidJobTransition,
    JobNotFoundError,
    can_cancel_job,
    enqueue_job,
    durable_idempotency_key,
    lock_advisor_admission,
    preparation_retry_blocked_reason,
    request_cancellation,
    retry_failed_job,
)
from .jobs.commands import (
    AdvisorSelectionError,
    InvalidScanCommandSnapshot,
    advisor_selection_snapshot,
    scan_command_snapshot,
)
from .jobs.liveness import fresh_worker_id, worker_advisor_catalog, worker_advisor_status
from .local_url import normalize_local_ollama_url
from .advisor import disclosure as advisor_disclosure
from .advisor import providers as advisor_providers
from .models import (
    Finding,
    GatePolicy,
    Job,
    Project,
    RuntimeConfig,
    Scan,
    ScanArtifact,
    SchemaIdentity,
    ScannerLifecycleState,
    ScannerToolState,
)
from .redaction import REDACTED, redact_json, redact_text
from .security import AdvisorRequestAudit
from .source_snapshots import (
    SourceSnapshotError,
    inspect_source_snapshot,
    delete_source_snapshots,
    is_source_snapshot_project,
    source_snapshot_project_path,
    source_snapshot_project_source_id,
    source_snapshot_project_kind,
    store_source_snapshot,
    validate_source_snapshot,
)
from .schemas import (
    MAX_PUBLIC_SAFE_DETAIL_TEXT_LENGTH,
    FindingBulkAction,
    AdvisorDisclosurePreviewOut,
    AdvisorDisclosurePreviewRequest,
    AdvisorLocalCatalogOut,
    AdvisorProviderCollectionOut,
    AdvisorProviderCommandRequest,
    AdvisorProviderDeleteRequest,
    AdvisorProviderReceiptOut,
    AdvisorProviderWriteRequest,
    AdvisorTriageProviderPin,
    FindingDiagnosticPageOut,
    FindingDetailOut,
    FindingFileManifestPageOut,
    FindingLifecycleUpdate,
    FindingPageOut,
    FindingOut,
    GatePolicyUpdate,
    JobOut,
    JobRetryRequest,
    JobReconcileRequest,
    ScannerReconciliationCommandOut,
    ProblemDetail,
    ProjectCreate,
    ProjectOut,
    ProjectResolve,
    SourcePreviewRequest,
    SourcePreviewOut,
    SourceSnapshotCreate,
    SourceSnapshotOut,
    SourceSnapshotLimitsOut,
    ScanSourceSnapshotOut,
    RuntimeAdvisorConfigUpdate,
    RuntimeComponentsConfigUpdate,
    RuntimeConfigOut,
    RuntimeConfigUpdate,
    RuntimeGateConfigUpdate,
    ScanArtifactOut,
    ScanCreate,
    ScanOut,
    ScanSummaryOut,
    ScanTriageRequest,
    ScannerToolOut,
    ScannerToolPatch,
    ScannerCacheUpdateRequest,
    ScannerCacheComponentId,
    ScannerLifecycleCommandOut,
    ScannerLifecycleOut,
    ScannerPreparationCommandOut,
    ScannerPreparationContinuation,
    ScannerCacheRollbackEligibilityOut,
    ScannerCacheVerificationOut,
    ScannerCacheVerificationRetryRequest,
    ScannerPreflightOut,
    TriageRequest,
    ScannerToolReadinessOut,
    normalize_project_repo_path,
)
from .settings import Settings

router = APIRouter()

SCANNER_TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "secrets-lite": {
        "id": "secrets-lite",
        "name": "Internal Secrets Lite",
        "category": "secrets",
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for common token patterns, private keys, high-entropy material, and sensitive assignments.",
        "current_version": __version__,
        "latest_version": __version__,
    },
    "sast-lite": {
        "id": "sast-lite",
        "name": "Internal SAST Lite",
        "category": "sast",
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for a small set of risky code patterns such as shell execution, eval, formatted SQL, and weak token randomness.",
        "current_version": __version__,
        "latest_version": __version__,
    },
    "iac-lite": {
        "id": "iac-lite",
        "name": "Internal IaC Lite",
        "category": "iac",
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for a small set of Kubernetes, Terraform, and Docker hardening risks.",
        "current_version": __version__,
        "latest_version": __version__,
    },
    "trivy": {
        "id": "trivy",
        "name": "Trivy",
        "category": "dependency/iac",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Aqua Security Trivy filesystem scanner for vulnerabilities, IaC misconfigurations, secrets, and license signals.",
        "current_version": "0.73.0",
        "latest_version": "0.73.0",
    },
    "gitleaks": {
        "id": "gitleaks",
        "name": "Gitleaks",
        "category": "secrets",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Gitleaks secret scanner using its native detector rules and SARIF output.",
        "current_version": "8.30.1",
        "latest_version": "8.30.1",
    },
    "opengrep": {
        "id": "opengrep",
        "name": "OpenGrep",
        "category": "sast",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "OpenGrep semantic/static-analysis scanner using pinned local rules and SARIF output.",
        "current_version": "1.27.0",
        "latest_version": "1.27.0",
    },
    "bearer": {
        "id": "bearer",
        "name": "Bearer",
        "category": "sast/privacy",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "jsonv2",
        "description": "Bearer code scanner for security, privacy, and data-flow risks in supported languages.",
        "current_version": "2.1.0",
        "latest_version": "2.1.0",
    },
    "grype": {
        "id": "grype",
        "name": "Grype",
        "category": "dependency",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Anchore Grype vulnerability scanner for packages and container/dependency metadata.",
        "current_version": "0.117.0",
        "latest_version": "0.117.0",
    },
    "checkov": {
        "id": "checkov",
        "name": "Checkov",
        "category": "iac",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Checkov IaC scanner for Terraform, Kubernetes, Dockerfile, GitHub Actions, and cloud configuration risks.",
        "current_version": "3.3.10",
        "latest_version": "3.3.10",
    },
    "trufflehog": {
        "id": "trufflehog",
        "name": "TruffleHog",
        "category": "secrets",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "jsonl",
        "description": "TruffleHog verified/structured secret scanner with JSONL output.",
        "current_version": "3.96.0",
        "latest_version": "3.96.0",
    },
    "syft": {
        "id": "syft",
        "name": "Syft",
        "category": "sbom",
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "cyclonedx-json",
        "description": "Anchore Syft SBOM generator. It stores CycloneDX artifacts and does not emit security findings directly.",
        "current_version": "1.51.0",
        "latest_version": "1.51.0",
    },
}

def _startup(runtime: Runtime) -> None:
    verification = init_db(runtime.engine)
    runtime.schema_identity = verification.identity
    runtime.schema_fingerprint = verification.fingerprint
    runtime.schema_initialized_at = verification.initialized_at
    with runtime.session_factory() as db:
        enforce_installation_secret_binding(db, runtime.settings)
    enforce_runtime_publication_boundaries(runtime)


_PUBLICATION_BOUNDARY_LOCK_ID = 21297445770945863


def enforce_runtime_publication_boundaries(runtime: Runtime) -> None:
    """Serialize current artifact publication checks before admission."""

    with runtime.engine.connect() as connection:
        postgresql = connection.dialect.name == "postgresql"
        if postgresql:
            connection.exec_driver_sql(
                f"SELECT pg_advisory_lock({_PUBLICATION_BOUNDARY_LOCK_ID})"
            )
        try:
            enforce_artifact_publication_boundary(runtime)
        finally:
            if postgresql:
                connection.exec_driver_sql(
                    f"SELECT pg_advisory_unlock({_PUBLICATION_BOUNDARY_LOCK_ID})"
                )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _problem_detail(
    code: str,
    message: str,
    *,
    action: str | None = None,
    context: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    safe_details: dict[str, str | int | bool | None] | None = None,
) -> dict[str, Any]:
    """Build a bounded stable error body without leaking exception text."""

    result = ProblemDetail(
        code=code,
        message=message,
        action=action,
        context=context or {},
        correlation_id=correlation_id,
        safe_details=safe_details,
    ).model_dump(mode="json")
    if correlation_id is None:
        result.pop("correlation_id", None)
    if safe_details is None:
        result.pop("safe_details", None)
    return result


TERMINAL_SCAN_STATUSES = {"completed", "partial", "failed", "cancelled"}
INCOMPLETE_GATE_REASON = (
    "Required scanner evidence is incomplete; the deterministic policy gate was not passed."
)
ACTIVE_JOB_STATUSES = frozenset({"queued", "leased", "running", "cancelling"})
ADVISOR_SCAN_STATUSES = frozenset({"completed", "partial", "failed"})


def _duration_ms_since(started_at: datetime | None, now: datetime) -> int | None:
    if not started_at:
        return None
    try:
        return max(0, int((now - started_at).total_seconds() * 1000))
    except TypeError:
        if started_at.tzinfo is None:
            return max(0, int((now.replace(tzinfo=None) - started_at).total_seconds() * 1000))
        return None


def _reject_active_job_deletion(db: Session, scan_ids: list[int]) -> None:
    if not scan_ids:
        return
    active_job_id = db.scalar(
        select(Job.id).where(
            Job.scan_id.in_(scan_ids),
            Job.status.in_(ACTIVE_JOB_STATUSES),
        ).limit(1)
    )
    if active_job_id is not None:
        raise HTTPException(
            409,
            f"resource has active durable job #{active_job_id}; cancel and wait for terminal cleanup first",
        )


def _statement_limit(stmt: Select[Any], limit: int = 100) -> Select[Any]:
    return stmt.limit(max(1, min(limit, 500)))


def _severity_rank(value: str | None) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get((value or "info").lower(), 5)


def _normalized_finding_location(item: dict[str, Any]) -> dict[str, int | None]:
    def coordinate(name: str) -> int | None:
        value = item.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None

    start_line = coordinate("start_line")
    end_line = coordinate("end_line") or start_line
    if start_line is None or end_line is None or end_line < start_line:
        return {
            "start_line": None,
            "start_column": None,
            "end_line": None,
            "end_column": None,
        }
    start_column = coordinate("start_column")
    end_column = coordinate("end_column")
    if start_column is None:
        end_column = None
    elif end_column is not None and start_line == end_line and end_column < start_column:
        start_column = None
        end_column = None
    return {
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
    }


def _normalized_finding_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    try:
        if len(value.encode("utf-8")) > 4096:
            return None
    except UnicodeError:
        return None
    segments = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in value
        )
        or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", value) is not None
        or any(not segment or segment in {".", ".."} for segment in segments)
        or posixpath.normpath(value) != value
    ):
        return None
    return value


def _finding_path_to_out(value: Any) -> str:
    normalized = _normalized_finding_path(value)
    return normalized if normalized is not None else REDACTED


def _finding_sort_key(item: Finding) -> tuple[int, str, int, str, str, int]:
    return (
        _severity_rank(item.severity),
        item.file_path or "",
        item.start_line or 0,
        item.scanner or "",
        item.rule_id or "",
        item.id,
    )


def _display_finding_id(scan_id: int, ordinal: int | None) -> str | None:
    if not ordinal:
        return None
    return f"S{scan_id}-F{ordinal:03d}"


def _scan_finding_ordinals(db: Session, scan_id: int) -> dict[int, int]:
    return {
        int(finding_id): int(scan_finding_number)
        for finding_id, scan_finding_number in db.execute(
            select(Finding.id, Finding.scan_finding_number).where(Finding.scan_id == scan_id)
        )
    }


def _scan_finding_ordinal(db: Session, finding: Finding | None) -> int | None:
    del db
    if not finding:
        return None
    return finding.scan_finding_number


def _finding_display_label(db: Session, finding: Finding | None) -> str | None:
    if not finding:
        return None
    return _display_finding_id(finding.scan_id, _scan_finding_ordinal(db, finding))


def _finding_occurrence_metadata(db: Session, items: list[Finding], ordinals: dict[int, int]) -> dict[int, dict[str, Any]]:
    identities = {(item.scanner, item.fingerprint) for item in items if item.fingerprint}
    empty = {
        item.id: {
            "occurrence_count": 1,
            "is_repeat": False,
            "first_seen_scan_id": None,
            "first_seen_display_id": None,
        }
        for item in items
    }
    if not identities or not items:
        return empty
    project_id = db.scalar(
        select(Scan.project_id).where(Scan.id == items[0].scan_id)
    )
    if project_id is None:
        return empty

    identity_predicate = tuple_(Finding.scanner, Finding.fingerprint).in_(
        sorted(identities)
    )
    counts = {
        (str(scanner), str(fingerprint)): int(count or 0)
        for scanner, fingerprint, count in db.execute(
            select(Finding.scanner, Finding.fingerprint, func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Scan.project_id == project_id, identity_predicate)
            .group_by(Finding.scanner, Finding.fingerprint)
        ).all()
    }
    ranked = (
        select(
            Finding.id.label("finding_id"),
            Finding.scan_id,
            Finding.scan_finding_number,
            Finding.scanner,
            Finding.fingerprint,
            func.row_number()
            .over(
                partition_by=(Finding.scanner, Finding.fingerprint),
                order_by=(Finding.scan_id.asc(), Finding.id.asc()),
            )
            .label("position"),
        )
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.project_id == project_id, identity_predicate)
        .subquery()
    )
    first_seen = {
        (str(scanner), str(fingerprint)): (
            int(finding_id),
            int(scan_id),
            int(scan_finding_number),
        )
        for finding_id, scan_id, scan_finding_number, scanner, fingerprint in db.execute(
            select(
                ranked.c.finding_id,
                ranked.c.scan_id,
                ranked.c.scan_finding_number,
                ranked.c.scanner,
                ranked.c.fingerprint,
            ).where(ranked.c.position == 1)
        ).all()
    }

    metadata: dict[int, dict[str, Any]] = {}
    for item in items:
        identity = (item.scanner, item.fingerprint)
        first = first_seen.get(identity)
        first_id, first_scan_id, first_ordinal = first if first else (item.id, item.scan_id, ordinals.get(item.id, item.scan_finding_number))
        first_label = _display_finding_id(first_scan_id, first_ordinal)
        count = counts.get(identity, 1)
        metadata[item.id] = {
            "occurrence_count": count,
            "is_repeat": first_id != item.id,
            "first_seen_scan_id": first_scan_id,
            "first_seen_display_id": first_label,
        }
    return metadata


def _finding_lifecycle(item: Finding) -> dict[str, Any]:
    status = item.lifecycle_status or ("ignore" if item.suppressed else "open")
    gate_exempt = bool(item.gate_exempt)
    return {
        "status": status,
        "gate_exempt": gate_exempt,
        "gate_exempt_reason": item.lifecycle_reason if gate_exempt else None,
        "reason": item.lifecycle_reason,
        "updated_at": item.lifecycle_updated_at,
    }


def _finding_gate_exempt(item: Finding) -> bool:
    lifecycle = _finding_lifecycle(item)
    return bool(lifecycle["gate_exempt"])


def _apply_finding_lifecycle(finding: Finding, action: str, reason: str | None = None) -> None:
    normalized_reason = _redacted_optional_text(reason, 500)
    if action in {"gate_exempt", "accepted_risk", "ignore", "false_positive", "fixed"} and not (
        normalized_reason and normalized_reason.strip()
    ):
        raise HTTPException(422, f"reason is required for finding lifecycle action: {action}")
    metadata = dict(finding.metadata_json or {})
    lifecycle = dict(metadata.get("lifecycle") or {})
    lifecycle["status"] = action
    lifecycle["reason"] = normalized_reason
    updated_at = _utcnow()
    lifecycle["updated_at"] = updated_at.isoformat()

    if action in {"open", "needs_review"}:
        finding.suppressed = False
        finding.suppression_reason = None
        lifecycle["gate_exempt"] = False
        lifecycle["gate_exempt_reason"] = None
    elif action == "gate_exempt":
        finding.suppressed = False
        finding.suppression_reason = None
        lifecycle["gate_exempt"] = True
        lifecycle["gate_exempt_reason"] = normalized_reason or "Marked non-blocking for gate."
    elif action == "accepted_risk":
        finding.suppressed = False
        finding.suppression_reason = None
        lifecycle["gate_exempt"] = True
        lifecycle["gate_exempt_reason"] = normalized_reason or "Accepted risk."
    elif action == "ignore":
        finding.suppressed = True
        finding.suppression_reason = normalized_reason or "Ignored by user."
        lifecycle["gate_exempt"] = False
        lifecycle["gate_exempt_reason"] = None
    elif action == "false_positive":
        finding.suppressed = True
        finding.suppression_reason = normalized_reason or "Marked false positive."
        lifecycle["gate_exempt"] = False
        lifecycle["gate_exempt_reason"] = None
    elif action == "fixed":
        finding.suppressed = True
        finding.suppression_reason = normalized_reason or "Marked fixed."
        lifecycle["gate_exempt"] = False
        lifecycle["gate_exempt_reason"] = None
    else:
        raise HTTPException(422, f"unsupported finding lifecycle action: {action}")

    metadata["lifecycle"] = lifecycle
    finding.metadata_json = _redacted_json_object(metadata)
    finding.lifecycle_status = action
    finding.gate_exempt = bool(lifecycle["gate_exempt"])
    finding.lifecycle_reason = normalized_reason
    finding.lifecycle_updated_at = updated_at
    finding.revision += 1


def _finding_to_out(item: Finding, ordinal: int, occurrence: dict[str, Any]) -> dict[str, Any]:
    lifecycle = _finding_lifecycle(item)
    gate_effect = "excluded" if item.suppressed else "non_blocking" if lifecycle["gate_exempt"] else "blocking"
    return {
        "id": item.id,
        "scan_id": item.scan_id,
        "scan_finding_number": ordinal,
        "display_id": _display_finding_id(item.scan_id, ordinal),
        "scanner": _redacted_identity_text(item.scanner, 80),
        "rule_id": _redacted_identity_text(item.rule_id, 160),
        "severity": _redacted_identity_text(item.severity, 30),
        "file_path": _finding_path_to_out(item.file_path),
        "start_line": item.start_line,
        "start_column": item.start_column,
        "end_line": item.end_line,
        "end_column": item.end_column,
        "message": _redacted_display_text(item.message, 4000),
        "code_snippet": _redacted_optional_text(
            item.code_snippet, _FINDING_SNIPPET_MAX_CHARS
        ),
        "fingerprint": _redacted_identity_text(item.fingerprint, 128),
        "metadata_json": _bounded_redacted_finding_metadata(item.metadata_json),
        "ai_verdict": _redacted_optional_text(item.ai_verdict, 40),
        "ai_confidence": item.ai_confidence,
        "ai_reasoning": _redacted_optional_text(item.ai_reasoning, 4000),
        "ai_fix": _redacted_optional_text(item.ai_fix, 4000),
        "suppressed": item.suppressed,
        "suppression_reason": _redacted_optional_text(item.suppression_reason, 500),
        "lifecycle_status": _redacted_text(lifecycle["status"]),
        "gate_exempt": lifecycle["gate_exempt"],
        "gate_exempt_reason": _redacted_optional_text(lifecycle["gate_exempt_reason"], 500),
        "lifecycle_reason": _redacted_optional_text(lifecycle["reason"], 500),
        "lifecycle_updated_at": lifecycle["updated_at"],
        "occurrence_count": occurrence.get("occurrence_count", 1),
        "is_repeat": occurrence.get("is_repeat", False),
        "first_seen_scan_id": occurrence.get("first_seen_scan_id"),
        "first_seen_display_id": occurrence.get("first_seen_display_id"),
        "revision": item.revision,
        "gate_effect": gate_effect,
        "created_at": item.created_at,
    }


def _finding_list_to_out(item: Finding, occurrence: dict[str, Any]) -> dict[str, Any]:
    lifecycle = _finding_lifecycle(item)
    gate_effect = "excluded" if item.suppressed else "non_blocking" if lifecycle["gate_exempt"] else "blocking"
    return {
        "id": item.id,
        "scan_id": item.scan_id,
        "scan_finding_number": item.scan_finding_number,
        "display_id": _display_finding_id(item.scan_id, item.scan_finding_number),
        "scanner": _redacted_identity_text(item.scanner, 80),
        "rule_id": _redacted_identity_text(item.rule_id, 160),
        "severity": _redacted_identity_text(item.severity, 30),
        "file_path": _finding_path_to_out(item.file_path),
        "start_line": item.start_line,
        "start_column": item.start_column,
        "end_line": item.end_line,
        "end_column": item.end_column,
        "message": _redacted_display_text(item.message, 4000),
        "fingerprint": _redacted_identity_text(item.fingerprint, 128),
        "suppressed": item.suppressed,
        "lifecycle_status": _redacted_identity_text(lifecycle["status"], 40),
        "gate_exempt": lifecycle["gate_exempt"],
        "occurrence_count": occurrence.get("occurrence_count", 1),
        "is_repeat": occurrence.get("is_repeat", False),
        "first_seen_scan_id": occurrence.get("first_seen_scan_id"),
        "first_seen_display_id": occurrence.get("first_seen_display_id"),
        "advisor_verdict": _redacted_optional_text(item.ai_verdict, 40),
        "advisor_confidence": item.ai_confidence,
        "gate_effect": gate_effect,
        "revision": item.revision,
        "created_at": item.created_at,
    }


_FINDING_CURSOR_VERSION = 1
_FINDING_CURSOR_MAX_CHARS = 512
_FINDING_CURSOR_MAX_AFTER = 50_000
_SQL_INTEGER_MAX = 2_147_483_647
_FINDING_CURSOR_KEYS = frozenset({"v", "s", "r", "a", "f"})
_FINDING_FILE_CURSOR_VERSION = 1
_FINDING_FILE_CURSOR_KIND = "finding_files"
_FINDING_FILE_CURSOR_KEYS = frozenset({"v", "k", "s", "r", "a"})
_FINDING_DIAGNOSTIC_CURSOR_VERSION = 1
_FINDING_DIAGNOSTIC_CURSOR_KIND = "finding_diagnostics"
_FINDING_DIAGNOSTIC_CURSOR_KEYS = frozenset({"v", "k", "s", "r", "a", "f"})
_FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")
_FINDING_LIFECYCLES = (
    "open",
    "needs_review",
    "gate_exempt",
    "accepted_risk",
    "ignore",
    "false_positive",
    "fixed",
)


def _strict_cursor_document(raw: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("cursor contains a duplicate key")
            document[key] = value
        return document

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"cursor contains a non-finite number: {value}")

    decoded = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(decoded, dict):
        raise ValueError("cursor payload must be an object")
    return decoded


def _finding_cursor_numbers_are_bounded(document: dict[str, Any]) -> bool:
    def bounded(key: str, maximum: int) -> bool:
        value = document.get(key)
        return type(value) is int and 1 <= value <= maximum

    return (
        bounded("s", _SQL_INTEGER_MAX)
        and bounded("r", _SQL_INTEGER_MAX)
        and bounded("a", _FINDING_CURSOR_MAX_AFTER)
    )


def _finding_filter_digest(
    *,
    file_path: str | None,
    severity: str | None,
    scanner: str | None,
    lifecycle_status: str | None,
) -> str:
    document = {
        "file_path": file_path,
        "lifecycle_status": lifecycle_status,
        "scanner": scanner,
        "severity": severity,
    }
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _encode_finding_cursor(
    *, scan_id: int, findings_revision: int, after: int, filter_digest: str
) -> str:
    document = {
        "a": after,
        "f": filter_digest,
        "r": findings_revision,
        "s": scan_id,
        "v": _FINDING_CURSOR_VERSION,
    }
    if not _finding_cursor_numbers_are_bounded(document):
        raise ValueError("finding cursor values exceed persisted bounds")
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _invalid_finding_cursor(message: str = "finding cursor is invalid") -> HTTPException:
    return HTTPException(400, {"code": "cursor_invalid", "message": message})


def _decode_finding_cursor(cursor: str) -> dict[str, Any]:
    if not cursor or len(cursor) > _FINDING_CURSOR_MAX_CHARS or not cursor.isascii():
        raise _invalid_finding_cursor()
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(
            f"{cursor}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if len(raw) > 256:
            raise ValueError("cursor payload is too large")
        document = _strict_cursor_document(raw)
    except (UnicodeError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise _invalid_finding_cursor() from exc
    if not isinstance(document, dict) or set(document) != _FINDING_CURSOR_KEYS:
        raise _invalid_finding_cursor()
    if (
        type(document.get("v")) is not int
        or document["v"] != _FINDING_CURSOR_VERSION
        or not _finding_cursor_numbers_are_bounded(document)
        or not isinstance(document.get("f"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", document["f"])
    ):
        raise _invalid_finding_cursor()
    return document


def _encode_finding_file_cursor(
    *, scan_id: int, findings_revision: int, after: int
) -> str:
    document = {
        "a": after,
        "k": _FINDING_FILE_CURSOR_KIND,
        "r": findings_revision,
        "s": scan_id,
        "v": _FINDING_FILE_CURSOR_VERSION,
    }
    if not _finding_cursor_numbers_are_bounded(document):
        raise ValueError("finding file cursor values exceed persisted bounds")
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _invalid_finding_file_cursor(
    message: str = "finding file cursor is invalid",
) -> HTTPException:
    return HTTPException(400, {"code": "cursor_invalid", "message": message})


def _decode_finding_file_cursor(cursor: str) -> dict[str, Any]:
    if not cursor or len(cursor) > _FINDING_CURSOR_MAX_CHARS or not cursor.isascii():
        raise _invalid_finding_file_cursor()
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(
            f"{cursor}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if len(raw) > 256:
            raise ValueError("cursor payload is too large")
        document = _strict_cursor_document(raw)
    except (UnicodeError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise _invalid_finding_file_cursor() from exc
    if set(document) != _FINDING_FILE_CURSOR_KEYS:
        raise _invalid_finding_file_cursor()
    if (
        type(document.get("v")) is not int
        or document["v"] != _FINDING_FILE_CURSOR_VERSION
        or document["k"] != _FINDING_FILE_CURSOR_KIND
        or not _finding_cursor_numbers_are_bounded(document)
    ):
        raise _invalid_finding_file_cursor()
    return document


def _encode_finding_diagnostic_cursor(
    *, scan_id: int, findings_revision: int, after: int, filter_digest: str
) -> str:
    document = {
        "a": after,
        "f": filter_digest,
        "k": _FINDING_DIAGNOSTIC_CURSOR_KIND,
        "r": findings_revision,
        "s": scan_id,
        "v": _FINDING_DIAGNOSTIC_CURSOR_VERSION,
    }
    if not _finding_cursor_numbers_are_bounded(document):
        raise ValueError("finding diagnostic cursor values exceed persisted bounds")
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _invalid_finding_diagnostic_cursor(
    message: str = "finding diagnostic cursor is invalid",
) -> HTTPException:
    return HTTPException(400, {"code": "cursor_invalid", "message": message})


def _decode_finding_diagnostic_cursor(cursor: str) -> dict[str, Any]:
    if not cursor or len(cursor) > _FINDING_CURSOR_MAX_CHARS or not cursor.isascii():
        raise _invalid_finding_diagnostic_cursor()
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(
            f"{cursor}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if len(raw) > 256:
            raise ValueError("cursor payload is too large")
        document = _strict_cursor_document(raw)
    except (UnicodeError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise _invalid_finding_diagnostic_cursor() from exc
    if set(document) != _FINDING_DIAGNOSTIC_CURSOR_KEYS:
        raise _invalid_finding_diagnostic_cursor()
    if (
        type(document.get("v")) is not int
        or document["v"] != _FINDING_DIAGNOSTIC_CURSOR_VERSION
        or document["k"] != _FINDING_DIAGNOSTIC_CURSOR_KIND
        or not _finding_cursor_numbers_are_bounded(document)
        or not isinstance(document.get("f"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", document["f"])
    ):
        raise _invalid_finding_diagnostic_cursor()
    return document


def _job_activity_to_out(job: Job) -> dict[str, Any] | None:
    raw = (job.checkpoint or {}).get("updater_activity")
    expected = {
        "status",
        "stage",
        "updated_at",
        "component_id",
        "component_index",
        "component_total",
        "bytes_completed",
        "bytes_total",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        return None
    component_id = raw.get("component_id")
    component_index = raw.get("component_index")
    component_total = raw.get("component_total")
    bytes_completed = raw.get("bytes_completed")
    bytes_total = raw.get("bytes_total")
    if component_id is None:
        if any(value is not None for value in (component_index, component_total, bytes_completed, bytes_total)):
            return None
    elif (
        not isinstance(component_id, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", component_id) is None
        or isinstance(component_index, bool)
        or not isinstance(component_index, int)
        or isinstance(component_total, bool)
        or not isinstance(component_total, int)
        or not 1 <= component_index <= component_total <= 32
        or (bytes_completed is None) != (bytes_total is None)
    ):
        return None
    if bytes_completed is not None and (
        isinstance(bytes_completed, bool)
        or not isinstance(bytes_completed, int)
        or isinstance(bytes_total, bool)
        or not isinstance(bytes_total, int)
        or not 0 <= bytes_completed <= bytes_total <= 4 * 1024 * 1024 * 1024
        or bytes_total < 1
    ):
        return None
    updated_at = raw.get("updated_at")
    if not isinstance(updated_at, str) or len(updated_at) > 40:
        return None
    try:
        parsed_updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed_updated_at.tzinfo is None:
        return None
    return {
        "component_id": component_id,
        "component_index": component_index,
        "component_total": component_total,
        "bytes_completed": bytes_completed,
        "bytes_total": bytes_total,
        "updated_at": parsed_updated_at,
    }


def _advisor_retry_selection_problem(
    db: Session, job: Job, *, lock: bool = False
) -> AdvisorSelectionError | None:
    if job.kind != "advisor" or job.status != "failed":
        return None
    if job.error_code in {"advisor_selection_changed", "advisor_no_eligible_findings"}:
        return AdvisorSelectionError(
            "This Advisor selection is no longer current. Open the findings and "
            "submit a new Advisor review; the original job will stay unchanged."
        )
    try:
        selection = advisor_selection_snapshot(job.payload)
        if selection.finding_ids is None:
            # Scan-wide commands retain their existing eligible-set semantics.
            return None
        if selection.expected_revisions is None:
            raise AdvisorSelectionError("Advisor revision snapshot is missing.", invalid=True)
        # Match the normal writer order: Advisor admission, parent scan,
        # findings in ID order, then the retry's revision-fenced job row.
        scan_query = select(Scan).where(Scan.id == job.scan_id)
        if lock:
            scan_query = scan_query.with_for_update()
        scan = db.scalar(scan_query)
        if scan is None or scan.status not in ADVISOR_SCAN_STATUSES:
            raise AdvisorSelectionError(
                "The original scan is no longer available for Advisor. Open the "
                "findings and submit a new Advisor review."
            )
        query = select(Finding.id, Finding.revision).where(
            Finding.scan_id == job.scan_id,
            Finding.id.in_(selection.finding_ids),
            Finding.suppressed.is_(False),
        ).order_by(Finding.id.asc())
        if lock:
            query = query.with_for_update()
        completed = {
            value for value in job.checkpoint.get("advisor_completed", [])
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
        }
        selection.require_current(
            dict(db.execute(query).all()), completed=completed,
            include_existing=True,
        )
    except AdvisorSelectionError as exc:
        return exc
    return None


def _can_reconcile_cache_job(job: Job) -> bool:
    if job.kind != "scanner_cache_update" or job.status != "failed":
        return False
    if job.error_code == "scanner_preparation_commit_uncertain":
        return True
    # Older failure finalization replaced the publication-specific error with
    # the budget rejection. Preserve that history and use its admitted activity
    # only to offer a check; the command still proves the current exact pointer.
    activity = (job.checkpoint or {}).get("updater_activity")
    return bool(job.error_code == "scanner_preparation_deadline"
        and isinstance(activity, dict) and _job_activity_to_out(job) is not None
        and activity.get("status") == "running"
        and activity.get("stage") in {"committing", "activating"})


def _job_to_out(db: Session, job: Job) -> dict[str, Any]:
    retry_problem = _advisor_retry_selection_problem(db, job)
    retry_reason = retry_problem.detail if retry_problem else (
        None if _can_reconcile_cache_job(job)
        else preparation_retry_blocked_reason(job, now=_utcnow())
    )
    original_job_id = None
    if job.kind == "scanner_cache_reconcile":
        try:
            target = RecoveryTarget.model_validate(job.payload.get("reconciliation_target"))
            budget = RecoveryBudget.model_validate(job.payload.get("reconciliation_budget"))
            if job.payload.get("request_digest") == recovery_digest(budget, target):
                original_job_id = target.original_job_id
        except (AttributeError, ValueError, TypeError):
            pass  # Unknown binding stays unknown in the public projection.
    finding = db.get(Finding, job.finding_id) if job.finding_id else None
    ordinal = _scan_finding_ordinal(db, finding) if finding else None
    display_id = _display_finding_id(finding.scan_id, ordinal) if finding and ordinal else None
    title = f"Advisor triage for {display_id}" if job.kind == "advisor" and display_id else job.title
    return {
        "id": job.id,
        "original_job_id": original_job_id,
        "can_reconcile_cache": _can_reconcile_cache_job(job),
        "kind": _redacted_identity_text(job.kind, 40),
        "title": _redacted_text(title, 240),
        "status": _redacted_identity_text(job.status, 40),
        "stage": _redacted_optional_text(job.stage, 120),
        "detail": _redacted_optional_text(job.detail),
        "progress": job.progress,
        "scan_id": job.scan_id,
        "finding_id": job.finding_id,
        "finding_display_id": display_id,
        "finding_scan_number": ordinal,
        "finding_rule_id": _redacted_identity_text(finding.rule_id, 160) if finding else None,
        "error": _redacted_optional_text(job.error),
        "error_code": _redacted_identity_text(job.error_code, 80) if job.error_code else None,
        "error_detail": _redacted_optional_text(job.error_detail),
        "attempt": job.attempt,
        "max_attempts": job.max_attempts,
        "revision": job.revision,
        "cancel_requested_at": job.cancel_requested_at,
        "heartbeat_at": job.heartbeat_at,
        "activity": _job_activity_to_out(job),
        "can_cancel": can_cancel_job(job),
        "retry_blocked_reason": retry_reason,
        "can_retry": job.status == "failed" and job.kind != "scanner_cache_reconcile"
        and not _can_reconcile_cache_job(job) and retry_reason is None and not (
            job.kind == "advisor"
            and isinstance(job.payload, dict)
            and job.payload.get("remote_advisor_confirmation") is not None
            and isinstance(job.checkpoint, dict)
            and job.checkpoint.get("remote_advisor_transmission") is not None
        ) and (
            job.attempt < job.max_attempts
            or job.max_attempts
            < (
                3
                if job.kind
                in {"scanner_catalog_check", "scanner_cache_update", "scanner_cache_rollback"}
                else 10
            )
        ),
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "updated_at": job.updated_at,
    }


_SCAN_HISTORY_FIELDS = frozenset({
    "findings_total", "advisor", "requested_mode", "effective_mode", "warnings",
    "scope", "source_coverage", "coverage", "tools",
})
_SCAN_HISTORY_TOOL_FIELDS = frozenset({"id", "name", "enabled", "status", "error"})


def _scan_history_summary(value: Any) -> Any:
    """History keeps UI evidence; exact scan reads retain full engine receipts.

    This is a projection, never a cached observation or a gate calculation.
    Normalize keys in source order before selecting, matching persisted-row
    redaction's collision semantics. All retained values still pass redaction.
    """
    if not isinstance(value, dict):
        return value
    summary = {_clean_text(key): item for key, item in value.items()}
    history = {key: item for key, item in summary.items() if key in _SCAN_HISTORY_FIELDS}
    if isinstance(history.get("tools"), list):
        history["tools"] = [
            {key: item for key, item in {_clean_text(k): v for k, v in tool.items()}.items()
             if key in _SCAN_HISTORY_TOOL_FIELDS}
            if isinstance(tool, dict) else tool
            for tool in history["tools"]
        ]
    return history


def _scan_to_out(scan: Scan, job: Job | None = None, *, redaction_memo: _RedactionMemo | None = None, history: bool = False) -> dict[str, Any]:
    """Serialize persisted scan state without trusting untrusted persisted row contents."""

    source_snapshot = None
    if job is not None and job.kind == "scan" and job.scan_id == scan.id:
        payload = job.payload if isinstance(job.payload, dict) else {}
        raw_source = payload.get("source_snapshot")
        if raw_source is not None:
            try:
                source = ScanSourceSnapshotOut.model_validate(raw_source)
            except ValidationError:
                source = None
            if (
                source is not None
                and type(payload.get("scan_id")) is int
                and payload["scan_id"] > 0
                and payload.get("scan_id") == scan.id
                and type(payload.get("project_id")) is int
                and payload["project_id"] > 0
                and payload.get("project_id") == scan.project_id
                and payload.get("source_snapshot_digest") == source.snapshot_digest
                and payload.get("target_path") == source.target_path
                and payload.get("target_kind") == source.target_kind
                and all(
                    path is None or redact_text(path) == path
                    for path in (source.directory_scope, source.target_path)
                )
            ):
                source_snapshot = source.model_dump(mode="json")
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "mode": _redacted_identity_text(scan.mode, 40),
        "base_ref": _redacted_identity_text(scan.base_ref, 160) if scan.base_ref is not None else None,
        "head_ref": _redacted_identity_text(scan.head_ref, 160) if scan.head_ref is not None else None,
        "status": _redacted_identity_text(scan.status, 40),
        "gate_decision": _redacted_identity_text(scan.gate_decision, 40) if scan.gate_decision is not None else None,
        "gate_reasons": _redacted_reason_list(scan.gate_reasons),
        "scanner_summary": _redacted_json_object(
            _scan_history_summary(scan.scanner_summary) if history else scan.scanner_summary,
            memo=redaction_memo,
        ),
        "error": _redacted_optional_text(scan.error),
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_ms": scan.duration_ms,
        "revision": scan.revision,
        "findings_revision": scan.findings_revision,
        "job_id": job.id if job is not None else None,
        "job_revision": job.revision if job is not None else None,
        "source_snapshot": source_snapshot,
    }


def _project_to_out(project: Project) -> dict[str, Any]:
    """Serialize project identity while filtering stored remote credentials."""

    return {
        "id": project.id,
        "name": project.name,
        "repo_path": project.repo_path,
        "remote_url": _redacted_remote_url(project.remote_url),
        "default_branch": project.default_branch,
        "revision": project.revision,
        "created_at": project.created_at,
    }


def _normalize_ai_mode(value: str | None, settings: Settings) -> str:
    normalized = (value or settings.ai_mode or "auto").strip().lower()
    return normalized if normalized in {"auto", "on", "off"} else "auto"


def _normalize_ollama_base_url(value: str | None, settings: Settings) -> str:
    allowed_hosts = settings.ollama_allowed_host_list
    default = normalize_local_ollama_url(
        settings.ollama_base_url or "http://localhost:11434",
        allowed_hosts,
    )
    try:
        return normalize_local_ollama_url(value or default, allowed_hosts)
    except ValueError:
        return default


def _normalize_ollama_model(value: str | None, settings: Settings) -> str:
    normalized = (value or settings.ollama_model or "qwen3:8b").strip()
    return normalized[:120] or "qwen3:8b"


def _normalize_auto_triage_limit(value: str | int | None, settings: Settings) -> int:
    try:
        normalized = int(value if value is not None else settings.auto_triage_limit)
    except (TypeError, ValueError):
        normalized = settings.auto_triage_limit
    return max(0, min(normalized, 50))


GATE_PRESETS: dict[str, dict[str, int | bool]] = {
    "observe": {"active": False, "max_critical": -1, "max_high": -1, "block_secrets": False},
    "baseline": {"active": True, "max_critical": 0, "max_high": -1, "block_secrets": True},
    "strict": {"active": True, "max_critical": 0, "max_high": 0, "block_secrets": True},
}


def _normalize_gate_preset(value: str | None) -> str:
    normalized = (value or "baseline").strip().lower()
    return normalized if normalized in {*GATE_PRESETS.keys(), "custom"} else "baseline"


def _normalize_gate_limit(value: str | int | None, default: int) -> int:
    try:
        normalized = int(value if value is not None else default)
    except (TypeError, ValueError):
        normalized = default
    return max(-1, min(normalized, 999))


def _normalize_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean_text(value: Any, limit: int | None = None) -> str:
    cleaned = str(value if value is not None else "").replace("\x00", "")
    return cleaned[:limit] if limit else cleaned


def _clean_optional_text(value: Any, limit: int | None = None) -> str | None:
    if value is None:
        return None
    return _clean_text(value, limit)


def _clean_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {_clean_text(key): _clean_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean_json(item) for item in value]
    if isinstance(value, str):
        return _clean_text(value)
    return value


_FINDING_SNIPPET_MAX_CHARS = 20_000
_FINDING_METADATA_MAX_BYTES = 16_384


def _redacted_text(value: Any, limit: int | None = None) -> str:
    cleaned = _clean_text(value)
    redacted = redact_text(cleaned) or ""
    return redacted[:limit] if limit else redacted


def _redacted_display_text(value: Any, limit: int | None = None) -> str:
    redacted = _redacted_text(value)
    rendered = "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in redacted
    )
    return rendered[:limit] if limit else rendered


def _redacted_optional_text(value: Any, limit: int | None = None) -> str | None:
    if value is None:
        return None
    return _redacted_text(value, limit)


_IDENTITY_CONTEXT_KEYS = {
    "artifact_type",
    "base_ref",
    "engine",
    "file_path",
    "fingerprint",
    "format",
    "head_ref",
    "id",
    "mode",
    "name",
    "path",
    "project",
    "repo_path",
    "request_digest",
    "rule_id",
    "scanner",
    "sha256",
    "status",
    "version",
}
_SAFE_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_EXPLICIT_CREDENTIAL_MARKERS = (
    "authorization",
    "bearer ",
    "password",
    "passwd",
    "passphrase",
    "private_key",
    "private-key",
    "private key",
    "api_key",
    "api-key",
    "apikey",
    "secret=",
    "token=",
    "ghp_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "sk-live_",
    "sk_test_",
    "sk-test_",
    "-----begin ",
)


def _clearly_credential_bearing(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _EXPLICIT_CREDENTIAL_MARKERS):
        return True
    if "://" in value:
        try:
            # A username alone is normal for SSH (ssh://git@host) and does not
            # establish that a credential is embedded. A URL password does.
            return urlsplit(value).password is not None
        except ValueError:
            return False
    return False


def _redacted_identity_text(value: Any, limit: int | None = None) -> str:
    cleaned = _clean_text(value)
    rendered = _redacted_text(cleaned) if _clearly_credential_bearing(cleaned) else cleaned
    return rendered[:limit] if limit else rendered


def _redacted_remote_url(value: str | None) -> str | None:
    if value is None:
        return None
    return _redacted_identity_text(value)


class _RedactionMemo:
    """Bounded scalar reuse for one serialization call, never a process cache.

    Only immutable scalar results are shared. No document, revision, response or
    authorization is cached; each current database row is still traversed.
    """

    def __init__(self) -> None:
        self.keys: dict[str, bool] = {}
        self.strings: dict[tuple[str, str], str] = {}

    def sensitive_key(self, key: str) -> bool:
        if key in self.keys:
            return self.keys[key]
        result = bool(key and redact_json(None, key) == REDACTED)
        if len(self.keys) < 512 and len(key) <= 256:
            self.keys[key] = result
        return result

    def text(self, value: str, key: str) -> str:
        identity = (key, value)
        if identity in self.strings:
            return self.strings[identity]
        result = _redacted_json_text(value, key)
        if len(self.strings) < 512 and len(key) <= 256 and len(value) <= 256:
            self.strings[identity] = result
        return result


def _redacted_json_text(value: str, key: str) -> str:
    cleaned = _clean_text(value)
    normalized_key = key.lower().replace("-", "_")
    if (
        normalized_key
        in {
            "catalog_digest",
            "config_digest",
            "confirmation_digest",
            "disclosure_confirmation_digest",
            "model_digest",
            "preflight_revision",
            "provider_config_digest",
            "request_digest",
            "runtime_identity",
            "sha256",
        }
        or normalized_key.endswith("_sha256")
    ):
        return cleaned.lower() if _SAFE_SHA256.fullmatch(cleaned) else _redacted_text(cleaned)
    is_identity = normalized_key in _IDENTITY_CONTEXT_KEYS or normalized_key.endswith("_id")
    if is_identity and not _clearly_credential_bearing(cleaned):
        return cleaned
    return redact_text(cleaned)


def _redacted_json(value: Any, key: str = "", *, _depth: int = 0, _memo: _RedactionMemo | None = None) -> Any:
    # Sensitive keys and the depth boundary precede scalar reuse. Context is
    # exact: an allowed digest under one key never exempts a credential key.
    sensitive = _memo.sensitive_key(key) if _memo is not None else bool(key and redact_json(None, key) == REDACTED)
    if sensitive:
        return REDACTED
    if _depth >= 64 and isinstance(value, (dict, list)):
        return REDACTED
    if isinstance(value, dict):
        result = {}
        for item_key, item in value.items():
            cleaned_key = _clean_text(item_key)
            result[cleaned_key] = _redacted_json(item, cleaned_key, _depth=_depth + 1, _memo=_memo)
        return result
    if isinstance(value, list):
        return [_redacted_json(item, _depth=_depth + 1, _memo=_memo) for item in value]
    if isinstance(value, str):
        return _memo.text(value, key) if _memo is not None else _redacted_json_text(value, key)
    return value


def _redacted_json_object(value: Any, *, memo: _RedactionMemo | None = None) -> dict[str, Any]:
    if value is None:
        return {}
    candidate = value if isinstance(value, dict) else {"unstructured_value": value}
    redacted = _redacted_json(candidate, _memo=memo if memo is not None else _RedactionMemo())
    return redacted if isinstance(redacted, dict) else {}


def _bounded_redacted_finding_metadata(value: Any) -> dict[str, Any]:
    metadata = _redacted_json_object(value)
    try:
        encoded = json.dumps(
            metadata,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return {"_kodesec_truncated": True}
    if len(encoded) <= _FINDING_METADATA_MAX_BYTES:
        return metadata
    # Never cut serialized JSON or return a partial credential-bearing value.
    return {"_kodesec_truncated": True}


def _redacted_reason_list(value: Any) -> list[str]:
    if value is None:
        return []
    candidates = value if isinstance(value, list) else [value]
    reasons: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, str):
            reasons.append(_redacted_text(candidate))
        else:
            reasons.append(json.dumps(_redacted_json(candidate), sort_keys=True, separators=(",", ":")))
    return reasons


def _default_runtime_config(settings: Settings) -> dict[str, Any]:
    return {
        "ai_mode": _normalize_ai_mode(settings.ai_mode, settings),
        "ollama_base_url": _normalize_ollama_base_url(settings.ollama_base_url, settings),
        "ollama_model": _normalize_ollama_model(settings.ollama_model, settings),
        "ollama_thinking": _normalize_bool(settings.ollama_thinking),
        "auto_triage_limit": _normalize_auto_triage_limit(settings.auto_triage_limit, settings),
        "component_monitoring_enabled": False,
        "component_git_proxy_enabled": False,
        "component_db_admin_enabled": False,
        "gate_preset": "baseline",
        "gate_active": True,
        "gate_max_critical": 0,
        "gate_max_high": -1,
        "gate_block_secrets": True,
    }


def _runtime_config_values(settings: Settings, db: Session) -> dict[str, Any]:
    values = _default_runtime_config(settings)
    try:
        rows = list(db.scalars(select(RuntimeConfig)))
    except SQLAlchemyError as exc:
        raise HTTPException(
            503,
            _problem_detail(
                "runtime_configuration_unavailable",
                "Runtime configuration could not be read; retry after database recovery.",
                action="refresh_settings",
                safe_details={"reason_code": "database_read_failed"},
            ),
        ) from exc

    persisted = {row.key: row.value for row in rows}
    values["ai_mode"] = _normalize_ai_mode(persisted.get("ai_mode"), settings)
    values["ollama_base_url"] = _normalize_ollama_base_url(persisted.get("ollama_base_url"), settings)
    values["ollama_model"] = _normalize_ollama_model(persisted.get("ollama_model"), settings)
    values["ollama_thinking"] = _normalize_bool(persisted.get("ollama_thinking"), bool(values["ollama_thinking"]))
    values["auto_triage_limit"] = _normalize_auto_triage_limit(persisted.get("auto_triage_limit"), settings)
    values["component_monitoring_enabled"] = _normalize_bool(persisted.get("component_monitoring_enabled"), False)
    values["component_git_proxy_enabled"] = _normalize_bool(persisted.get("component_git_proxy_enabled"), False)
    values["component_db_admin_enabled"] = _normalize_bool(persisted.get("component_db_admin_enabled"), False)
    values["gate_preset"] = _normalize_gate_preset(persisted.get("gate_preset"))
    values["gate_active"] = _normalize_bool(persisted.get("gate_active"), True)
    values["gate_max_critical"] = _normalize_gate_limit(persisted.get("gate_max_critical"), 0)
    values["gate_max_high"] = _normalize_gate_limit(persisted.get("gate_max_high"), -1)
    values["gate_block_secrets"] = _normalize_bool(persisted.get("gate_block_secrets"), True)
    try:
        values["advisor_providers"] = advisor_providers.load_collection(db, settings)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(
            503,
            _problem_detail(
                "runtime_configuration_unavailable",
                "Runtime configuration is unavailable or invalid; repair it before retrying.",
                action="refresh_settings",
                safe_details={"reason_code": "configuration_read_failed"},
            ),
        ) from exc
    return values


def _gate_policy_values(values: dict[str, Any]) -> dict[str, int | bool]:
    return {
        "active": bool(values["gate_active"]),
        "max_critical": int(values["gate_max_critical"]),
        "max_high": int(values["gate_max_high"]),
        "block_secrets": bool(values["gate_block_secrets"]),
    }


def _gate_policy_values_from_payload(
    payload: RuntimeConfigUpdate | RuntimeGateConfigUpdate | GatePolicyUpdate,
) -> dict[str, int | bool]:
    if isinstance(payload, (RuntimeConfigUpdate, RuntimeGateConfigUpdate)):
        return {
            "active": payload.gate_active,
            "max_critical": payload.gate_max_critical,
            "max_high": payload.gate_max_high,
            "block_secrets": payload.gate_block_secrets,
        }
    return {
        "active": payload.active,
        "max_critical": payload.max_critical,
        "max_high": payload.max_high,
        "block_secrets": payload.block_secrets,
    }


def _upsert_gate_policy(db: Session, project_id: int, values: dict[str, int | bool]) -> GatePolicy:
    policy = db.scalar(select(GatePolicy).where(GatePolicy.project_id == project_id).with_for_update())
    if not policy:
        policy = GatePolicy(project_id=project_id)
    policy.active = bool(values["active"])
    policy.max_critical = int(values["max_critical"])
    policy.max_high = int(values["max_high"])
    policy.block_secrets = bool(values["block_secrets"])
    db.add(policy)
    return policy


def _recalculate_project_scan_gates(db: Session, project_id: int) -> None:
    db.flush()
    scans = list(
        db.scalars(
            select(Scan)
            .where(
                Scan.project_id == project_id,
                Scan.status.in_(TERMINAL_SCAN_STATUSES),
            )
            .order_by(Scan.id.asc())
            .with_for_update()
        )
    )
    for scan in scans:
        decision, reasons = _evaluate_scan_gate(db, scan)
        scan.gate_decision = decision
        scan.gate_reasons = _redacted_reason_list(reasons)
        scan.revision += 1
        db.add(scan)


def _upsert_runtime_config_values(db: Session, updates: dict[str, str]) -> None:
    for key, value in updates.items():
        item = db.get(RuntimeConfig, key)
        if item is None:
            item = RuntimeConfig(key=key, value=str(value))
        else:
            item.value = str(value)
        item.updated_at = _utcnow()
        db.add(item)


def _apply_runtime_gate_to_existing(
    db: Session,
    payload: RuntimeConfigUpdate | RuntimeGateConfigUpdate,
) -> None:
    if not payload.gate_apply_to_existing:
        return
    gate_values = _gate_policy_values_from_payload(payload)
    project_ids = list(db.scalars(select(Project.id).order_by(Project.id)))
    for project_id in project_ids:
        _upsert_gate_policy(db, project_id, gate_values)
        _recalculate_project_scan_gates(db, project_id)


def _save_runtime_config(db: Session, payload: RuntimeConfigUpdate) -> None:
    _upsert_runtime_config_values(db, {
        "ai_mode": payload.ai_mode,
        "ollama_base_url": payload.ollama_base_url,
        "ollama_model": payload.ollama_model,
        "ollama_thinking": str(payload.ollama_thinking).lower(),
        "auto_triage_limit": str(payload.auto_triage_limit),
        "component_monitoring_enabled": str(payload.component_monitoring_enabled).lower(),
        "component_git_proxy_enabled": str(payload.component_git_proxy_enabled).lower(),
        "component_db_admin_enabled": str(payload.component_db_admin_enabled).lower(),
        "gate_preset": payload.gate_preset,
        "gate_active": str(payload.gate_active).lower(),
        "gate_max_critical": str(payload.gate_max_critical),
        "gate_max_high": str(payload.gate_max_high),
        "gate_block_secrets": str(payload.gate_block_secrets).lower(),
    })
    _apply_runtime_gate_to_existing(db, payload)
    db.commit()


def _ensure_tool_state(db: Session, tool_id: str) -> ScannerToolState:
    if tool_id not in SCANNER_TOOL_REGISTRY:
        raise HTTPException(404, "scanner tool not found")
    defaults = SCANNER_TOOL_REGISTRY[tool_id]
    state = db.get(ScannerToolState, tool_id)
    if state is None:
        values = {
            "id": tool_id,
            "enabled": defaults["source"] == "external",
            "current_version": str(defaults["current_version"]),
            "latest_version": str(defaults["latest_version"]),
            "status": "ready" if defaults["source"] == "external" else "disabled",
            "update_available": False,
        }
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(
                postgresql_insert(ScannerToolState)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[ScannerToolState.id])
            )
        else:
            db.add(ScannerToolState(**values))
        db.commit()
        state = db.get(ScannerToolState, tool_id)
        if state is None:  # pragma: no cover - guarded by the primary-key upsert
            raise RuntimeError("scanner tool state disappeared during initialization")
    return state


def _scanner_runtime_failure(
    status_code: int,
    code: str,
    message: str,
    reason_code: str,
) -> HTTPException:
    return HTTPException(
        status_code,
        _problem_detail(
            code,
            message,
            action="repair_scanner_runtime",
            safe_details={"reason_code": reason_code},
        ),
    )


@dataclass(frozen=True)
class _ScannerRuntimeSnapshot:
    tools: dict[str, dict[str, Any]]
    active_generation: str | None
    cache_verification: dict[str, Any] | None = None


def _scanner_runtime_snapshot(settings: Settings) -> _ScannerRuntimeSnapshot:
    try:
        with httpx.Client(timeout=settings.scanner_tools_timeout, trust_env=False) as client:
            response = client.get(f"{settings.scanner_url.rstrip('/')}/tools")
            response.raise_for_status()
            payload = response.json()
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        raise _scanner_runtime_failure(
            503,
            "scanner_runtime_unavailable",
            "Scanner readiness could not reach the scanner runtime.",
            "scanner_unavailable",
        ) from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise _scanner_runtime_failure(
            502,
            "scanner_runtime_protocol_invalid",
            "Scanner readiness returned invalid data.",
            "scanner_protocol_invalid",
        ) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
        raise _scanner_runtime_failure(
            502,
            "scanner_runtime_protocol_invalid",
            "Scanner readiness returned invalid data.",
            "scanner_protocol_invalid",
        )
    if "active_generation" not in payload:
        raise _scanner_runtime_failure(
            502,
            "scanner_runtime_protocol_invalid",
            "Scanner readiness returned invalid data.",
            "scanner_protocol_invalid",
        )
    active_generation = payload["active_generation"]
    if active_generation is not None and (
        not isinstance(active_generation, str)
        or re.fullmatch(r"[0-9a-f]{64}", active_generation) is None
    ):
        raise _scanner_runtime_failure(
            502,
            "scanner_runtime_protocol_invalid",
            "Scanner readiness returned invalid data.",
            "scanner_protocol_invalid",
        )
    cache_verification = None
    if payload.get("cache_verification") is not None:
        try:
            verification = ScannerCacheVerificationOut.model_validate(payload["cache_verification"], strict=True)
            if (verification.target != "active" or (
                active_generation is not None and verification.generation_id != active_generation
            )):
                raise ValueError("scanner verification target mismatch")
            cache_verification = verification.model_dump(mode="json")
        except (ValidationError, ValueError) as exc:
            raise _scanner_runtime_failure(502, "scanner_runtime_protocol_invalid",
                "Scanner readiness returned invalid data.", "scanner_protocol_invalid") from exc
    runtime_tools: dict[str, dict[str, Any]] = {}
    for item in payload["tools"]:
        if not isinstance(item, dict):
            raise _scanner_runtime_failure(
                502,
                "scanner_runtime_protocol_invalid",
                "Scanner readiness returned invalid data.",
                "scanner_protocol_invalid",
            )
        tool_id = item.get("id")
        if (
            not isinstance(tool_id, str)
            or tool_id not in SCANNER_TOOL_REGISTRY
            or tool_id in runtime_tools
        ):
            raise _scanner_runtime_failure(
                502,
                "scanner_runtime_protocol_invalid",
                "Scanner readiness returned invalid data.",
                "scanner_protocol_invalid",
            )
        runtime_identity = item.get("runtime_identity")
        if runtime_identity is not None and (not isinstance(runtime_identity, str) or re.fullmatch(r"[0-9a-f]{64}", runtime_identity) is None):
            raise _scanner_runtime_failure(502, "scanner_runtime_protocol_invalid",
                "Scanner runtime identity is invalid.", "scanner_protocol_invalid")
        runtime_tools[tool_id] = item
    for item in runtime_tools.values():
        readiness, _ = _scanner_runtime_readiness(item)
        verification_states = {facet["state"] for facet in readiness.values()
            if facet["state"] in _SCANNER_VERIFICATION_FACET_REASONS}
        if verification_states and (
            cache_verification is None or verification_states != {
                _SCANNER_VERIFICATION_FACET_STATES[cache_verification["state"]]
            }
        ):
            raise _scanner_runtime_failure(502, "scanner_runtime_protocol_invalid",
                "Scanner readiness returned invalid data.", "scanner_protocol_invalid")
    return _ScannerRuntimeSnapshot(
        tools=runtime_tools,
        active_generation=active_generation,
        cache_verification=cache_verification,
    )


_SCANNER_VERIFICATION_FACET_STATES = {
    "verifying": "verifying",
    "timed_out": "verification_timeout",
    "failed": "verification_failed",
}
_SCANNER_VERIFICATION_FACET_REASONS = {
    "verifying": "scanner cache verification is in progress",
    "verification_timeout": "scanner cache verification timed out",
    "verification_failed": "scanner cache verification could not complete",
}


def _scanner_verification_action(verification: Mapping[str, Any]) -> str:
    return "wait_for_scanner_verification" if verification["state"] == "verifying" else "retry_scanner_verification"


def _require_scanner_verification_ready(verification: dict[str, Any] | None) -> None:
    if verification is None:
        return
    state = verification["state"]
    reason = _SCANNER_VERIFICATION_FACET_REASONS[_SCANNER_VERIFICATION_FACET_STATES[state]]
    raise HTTPException(409, _problem_detail(
        "scanner_cache_verification_required",
        reason.capitalize() + ". Wait and refresh scanner status." if state == "verifying"
        else reason.capitalize() + ". Retry verification of this exact cache; no download is required.",
        action=_scanner_verification_action(verification),
        context={"target": verification["target"], "generation_id": verification["generation_id"]},
        safe_details={"reason_code": state},
    ))


_SCANNER_READINESS_FACETS = ("binary", "data", "rules", "execution")
_SCANNER_READINESS_DATA_COMPONENTS = frozenset(
    {"trivy-db", "trivy-java-db", "trivy-checks", "grype-db"}
)
_SCANNER_READINESS_RULE_COMPONENTS = frozenset(
    {"opengrep-reviewed-rules", "bearer-rules"}
)
_SCANNER_TOOL_CACHE_COMPONENTS: dict[str, frozenset[str]] = {
    "trivy": frozenset({"trivy-db", "trivy-java-db", "trivy-checks"}),
    "opengrep": frozenset({"opengrep-reviewed-rules"}),
    "bearer": frozenset({"bearer-rules"}),
    "grype": frozenset({"grype-db"}),
}
_SCANNER_READINESS_SAFE_REASONS = frozenset(
    {
        "immutable component provenance is unavailable",
        "component provenance is not attested",
        "no validated active or previous-good cache generation exists",
        "no validated cache generation is selected for scanner execution",
        "active cache generation is invalid; previous-good is not execution-ready",
        "cache generation was built from different scanner locks",
        "required components are absent from the cache generation",
        "cache component identity differs from its lock",
        "cache component freshness window expired",
        "binary provenance is not verified",
        "binary license evidence is unavailable",
        "binary license evidence is not attested",
        "binary runtime status is missing",
        "binary runtime status is unverified",
        "binary runtime status is version_mismatch",
        "binary runtime status is binary_changed",
        "rules provenance is unavailable in the rules lock",
        "rules provenance is not attested in the rules lock",
        "rules requirement is absent from the rules lock",
        "rules canary evidence is not attested",
        "cache rule canary receipts differ from the rules lock",
        "offline execution contract is not attested",
    }
)
_SCANNER_READINESS_INVALID_REASON = "Scanner runtime readiness data failed validation."
_SCANNER_DATA_REFRESH_WARNING = (
    "Refresh due: reviewed data is at least 7 days old; newer vulnerabilities may be missing. "
    "Update reviewed source before the 14-day expiry."
)


def _invalid_scanner_runtime_readiness() -> tuple[dict[str, Any], bool]:
    return (
        {
            facet: {
                "state": "invalid",
                "reason": _SCANNER_READINESS_INVALID_REASON,
                "component_ids": [],
            }
            for facet in _SCANNER_READINESS_FACETS
        },
        False,
    )


def _scanner_runtime_readiness(
    runtime: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    has_readiness = "readiness" in runtime
    has_runtime_ready = "runtime_ready" in runtime
    if not has_readiness and not has_runtime_ready:
        return _invalid_scanner_runtime_readiness()
    if not has_readiness or not has_runtime_ready or type(runtime["runtime_ready"]) is not bool:
        return _invalid_scanner_runtime_readiness()
    try:
        readiness = ScannerToolReadinessOut.model_validate(
            runtime["readiness"], strict=True
        ).model_dump(mode="json")
    except ValidationError:
        return _invalid_scanner_runtime_readiness()

    for facet_name in _SCANNER_READINESS_FACETS:
        facet = readiness[facet_name]
        state = facet["state"]
        reason = facet["reason"]
        component_ids = facet["component_ids"]
        if state in {"ready", "not_required"}:
            # The scanner's seven-day advisory does not invalidate data that
            # still satisfies its integrity and fourteen-day freshness checks.
            # Admit only that exact data warning, never arbitrary runtime text.
            refresh_warning = (
                state == "ready"
                and facet_name == "data"
                and bool(component_ids)
                and reason == _SCANNER_DATA_REFRESH_WARNING
            )
            if reason is not None and not refresh_warning:
                return _invalid_scanner_runtime_readiness()
        elif state in _SCANNER_VERIFICATION_FACET_REASONS:
            if reason != _SCANNER_VERIFICATION_FACET_REASONS[state]:
                return _invalid_scanner_runtime_readiness()
        elif reason not in _SCANNER_READINESS_SAFE_REASONS:
            return _invalid_scanner_runtime_readiness()
        if state == "not_required" and component_ids:
            return _invalid_scanner_runtime_readiness()
        if facet_name in {"binary", "execution"} and component_ids:
            return _invalid_scanner_runtime_readiness()
        if facet_name == "data" and not set(component_ids).issubset(
            _SCANNER_READINESS_DATA_COMPONENTS
        ):
            return _invalid_scanner_runtime_readiness()
        if facet_name == "rules" and not set(component_ids).issubset(
            _SCANNER_READINESS_RULE_COMPONENTS
        ):
            return _invalid_scanner_runtime_readiness()
        facet["component_ids"] = sorted(component_ids)

    calculated_ready = all(
        readiness[facet]["state"] in {"ready", "not_required"}
        for facet in _SCANNER_READINESS_FACETS
    )
    if runtime["runtime_ready"] is not calculated_ready:
        return _invalid_scanner_runtime_readiness()
    return readiness, calculated_ready


def _scanner_tool_rows(
    db: Session,
    settings: Settings,
    *,
    runtime_snapshot: _ScannerRuntimeSnapshot | None = None,
) -> list[dict[str, Any]]:
    counts = {
        str(scanner): int(count or 0)
        for scanner, count in db.execute(select(Finding.scanner, func.count(func.distinct(Finding.fingerprint))).group_by(Finding.scanner)).all()
    }
    artifact_counts = {
        str(scanner): int(count or 0)
        for scanner, count in db.execute(select(ScanArtifact.scanner, func.count(ScanArtifact.id)).group_by(ScanArtifact.scanner)).all()
    }
    runtime_tools = (runtime_snapshot or _scanner_runtime_snapshot(settings)).tools
    rows: list[dict[str, Any]] = []
    synchronized_runtime_state = False
    for tool_id, defaults in SCANNER_TOOL_REGISTRY.items():
        state = _ensure_tool_state(db, tool_id)
        runtime = runtime_tools.get(tool_id, {})
        readiness, runtime_ready = _scanner_runtime_readiness(runtime)
        latest_version = state.latest_version or str(defaults["latest_version"])
        installed_version = (
            str(runtime["installed_version"])
            if runtime.get("installed_version") is not None
            else None
        )
        current_version = installed_version or state.current_version or str(defaults["current_version"])
        desired_version = state.pinned_version
        available = bool(runtime.get("available", defaults["source"] == "internal"))
        runtime_status = str(runtime.get("status") or ("ready" if available else "missing"))
        if (
            defaults["source"] == "external"
            and available
            and runtime_status == "ready"
            and installed_version
            and _normalize_version(state.current_version) != _normalize_version(installed_version)
        ):
            state.current_version = installed_version
            state.updated_at = _utcnow()
            db.add(state)
            synchronized_runtime_state = True
        status = "disabled" if not state.enabled else state.status
        if state.enabled and defaults["source"] == "external" and not available:
            status = runtime_status
        elif state.enabled and runtime_status != "ready":
            status = runtime_status
        elif (
            state.enabled
            and defaults["source"] == "external"
            and desired_version
            and _normalize_version(installed_version) != _normalize_version(desired_version)
        ):
            status = "host_confirmation_required"
        elif state.enabled and status in {"update_pending_rebuild", "host_confirmation_required"}:
            status = "ready"
            state.current_version = installed_version or state.current_version
            state.pinned_version = None
            state.update_available = False
            state.status = "ready"
            state.updated_at = _utcnow()
            db.add(state)
            synchronized_runtime_state = True
            desired_version = None
        elif state.enabled and status in {"missing", "check_failed", "version_error"}:
            status = "ready"
        update_available = (
            defaults["source"] == "external"
            and _normalize_version(installed_version) != _normalize_version(latest_version)
        )
        rows.append(
            {
                **defaults,
                "enabled": bool(state.enabled),
                "current_version": current_version,
                "latest_version": latest_version,
                "installed_version": installed_version,
                "available": available,
                "pinned_version": desired_version,
                "status": status,
                "update_available": bool(update_available),
                "findings_count": counts.get(tool_id, 0),
                "artifacts_count": artifact_counts.get(tool_id, 0),
                "candidate_release_id": state.candidate_release_id,
                "candidate_manifest_sha256": state.candidate_manifest_sha256,
                "published_at": state.published_at,
                "last_error": _redacted_optional_text(state.last_error),
                "last_checked_at": state.last_checked_at,
                "updated_at": state.updated_at,
                "readiness": readiness,
                "runtime_ready": runtime_ready,
            }
        )
    if synchronized_runtime_state:
        db.commit()
    return rows


def _scanner_cache_rollback_eligibility(
    db: Session,
    settings: Settings,
) -> dict[str, Any]:
    """Reconcile persisted lifecycle state with the scanner's exact cache view."""

    state = db.get(ScannerLifecycleState, "cache")
    expected_target = state.previous_generation if state is not None else None
    if expected_target is None:
        return ScannerCacheRollbackEligibilityOut(
            eligible=False,
            reason_code="no_previous_generation",
            reason="No previous-good scanner cache generation is available.",
            target_generation=None,
        ).model_dump(mode="json", exclude_unset=True)
    try:
        with httpx.Client(
            timeout=settings.scanner_tools_timeout,
            trust_env=False,
        ) as client:
            response = client.get(
                f"{settings.scanner_url.rstrip('/')}/cache/rollback-eligibility"
            )
            response.raise_for_status()
            eligibility = ScannerCacheRollbackEligibilityOut.model_validate(
                response.json(),
                strict=True,
            )
    except httpx.RequestError:
        return ScannerCacheRollbackEligibilityOut(
            eligible=False,
            reason_code="scanner_unavailable",
            reason="Rollback eligibility could not reach the scanner runtime. Refresh scanner status before retrying.",
            target_generation=expected_target,
        ).model_dump(mode="json", exclude_unset=True)
    except (httpx.HTTPStatusError, json.JSONDecodeError, UnicodeError, ValidationError):
        return ScannerCacheRollbackEligibilityOut(
            eligible=False,
            reason_code="scanner_eligibility_invalid",
            reason="The scanner runtime did not return valid rollback eligibility. Refresh scanner status before retrying.",
            target_generation=expected_target,
        ).model_dump(mode="json", exclude_unset=True)
    if eligibility.target_generation != expected_target:
        return ScannerCacheRollbackEligibilityOut(
            eligible=False,
            reason_code="state_mismatch",
            reason="Scanner cache state changed while rollback eligibility was checked. Refresh scanner status before retrying.",
            target_generation=expected_target,
        ).model_dump(mode="json", exclude_unset=True)
    return eligibility.model_dump(mode="json", exclude_unset=True)


def _scanner_preflight(db: Session, settings: Settings, *, include_runtime_identity: bool = False) -> dict[str, Any]:
    """Return one deterministic, fail-closed scanner-readiness snapshot."""

    runtime_snapshot = _scanner_runtime_snapshot(settings)
    rows = _scanner_tool_rows(db, settings, runtime_snapshot=runtime_snapshot)
    enabled_rows = sorted(
        (row for row in rows if row["enabled"]), key=lambda row: str(row["id"])
    )
    ready_tool_ids = sorted(
        str(row["id"])
        for row in enabled_rows
        if row.get("runtime_ready") is True
    )
    blocked_tools: list[dict[str, Any]] = []
    required_component_ids: set[str] = set()
    preparation_available = True
    for row in enabled_rows:
        if row.get("runtime_ready") is True:
            continue
        reasons: list[str] = []
        components: set[str] = set()
        preparation_blocking_reasons: list[str] = []
        readiness = row.get("readiness")
        if isinstance(readiness, dict):
            for facet_name in _SCANNER_READINESS_FACETS:
                facet = readiness.get(facet_name)
                if not isinstance(facet, dict) or facet.get("state") in {
                    "ready",
                    "not_required",
                }:
                    continue
                reason = facet.get("reason")
                safe_reason = (
                    str(reason)
                    if isinstance(reason, str) and reason
                    else f"Scanner {facet_name} readiness is unavailable."
                )
                if safe_reason not in reasons:
                    reasons.append(safe_reason)
                if facet.get("state") in _SCANNER_VERIFICATION_FACET_REASONS:
                    if safe_reason not in preparation_blocking_reasons:
                        preparation_blocking_reasons.append(safe_reason)
                    continue
                component_ids = facet.get("component_ids")
                if (
                    facet_name in {"data", "rules"}
                    and isinstance(component_ids, list)
                    and component_ids
                ):
                    components.update(
                        str(component_id) for component_id in component_ids
                    )
                elif safe_reason not in preparation_blocking_reasons:
                    preparation_blocking_reasons.append(safe_reason)
        if not reasons:
            fallback_reason = "Scanner runtime did not report verified readiness."
            reasons.append(fallback_reason)
            preparation_blocking_reasons.append(fallback_reason)
            components.update(
                _SCANNER_TOOL_CACHE_COMPONENTS.get(str(row["id"]), frozenset())
            )
        if preparation_blocking_reasons:
            preparation_available = False
        required_component_ids.update(components)
        blocked_tools.append(
            {
                "id": str(row["id"]),
                "name": str(row["name"]),
                "blocking_reasons": reasons[:4],
                "required_component_ids": sorted(components),
                "preparation_blocking_reasons": preparation_blocking_reasons[:4],
            }
        )

    catalog = db.get(ScannerLifecycleState, "catalog")
    cache = db.get(ScannerLifecycleState, "cache")
    enabled_tool_ids = [str(row["id"]) for row in enabled_rows]
    body: dict[str, Any] = {
        "schema_version": 1,
        "ready": bool(enabled_tool_ids) and not blocked_tools,
        "enabled_tool_ids": enabled_tool_ids,
        "ready_tool_ids": ready_tool_ids,
        "blocked_tools": blocked_tools,
        "required_component_ids": sorted(required_component_ids),
        "preparation_available": bool(blocked_tools)
        and bool(required_component_ids)
        and preparation_available,
        "active_generation": runtime_snapshot.active_generation,
        "catalog_revision": catalog.revision if catalog is not None else None,
        "cache_revision": cache.revision if cache is not None else None,
        "cache_rollback": _scanner_cache_rollback_eligibility(db, settings),
        "recommended_action": (
            "enable_scanner"
            if not enabled_tool_ids
            else "repair_scanner_runtime"
            if blocked_tools and not (
                required_component_ids and preparation_available
            )
            else "prepare_scanners"
            if blocked_tools
            else "scan"
        ),
    }
    if runtime_snapshot.cache_verification is not None:
        body.update({
            "ready": False,
            "preparation_available": False,
            "cache_verification": runtime_snapshot.cache_verification,
            "recommended_action": _scanner_verification_action(runtime_snapshot.cache_verification),
        })
    # Activity paints independently of the admission revision. Only a changed
    # verification target/generation/state can change this security snapshot.
    revision_body = dict(body)
    # Catalog checks discover available releases; they do not change executing
    # scanners or active data. Keep their progress counter out of scan identity.
    revision_body.pop("catalog_revision")
    runtime_identities = {tool_id: runtime_snapshot.tools.get(tool_id, {}).get("runtime_identity")
        for tool_id in enabled_tool_ids}
    # Bind verified executing binaries and adapter code, not just version names
    # or cache readiness. Missing identities never authorize protected pushes.
    revision_body["runtime_identities"] = runtime_identities
    if body.get("cache_verification") is not None:
        revision_body["cache_verification"] = {key: body["cache_verification"][key]
            for key in ("state", "target", "generation_id")}
    if body["cache_rollback"].get("verification") is not None:
        revision_body["cache_rollback"] = {**body["cache_rollback"], "verification": {
            key: body["cache_rollback"]["verification"][key]
            for key in ("state", "target", "generation_id")}}
    encoded = json.dumps(
        revision_body,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    body["revision"] = hashlib.sha256(encoded).hexdigest()
    response = ScannerPreflightOut.model_validate(body).model_dump(mode="json", exclude_unset=True)
    if include_runtime_identity:
        response["runtime_identities"] = runtime_identities
    return response


def _normalize_version(value: str | None) -> str:
    return (value or "").strip().removeprefix("v")


def _is_secret_finding(finding: Finding) -> bool:
    text = f"{finding.scanner} {finding.rule_id} {finding.message}".lower()
    return "secret" in text or "token" in text or "private-key" in text


def _scan_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id, Finding.suppressed.is_(False))
        .group_by(Finding.severity)
    ).all()
    return {str(sev or "info"): int(count or 0) for sev, count in rows}


def _scan_scanner_counts(db: Session, scan_id: int) -> dict[str, int]:
    return {
        str(scanner or "unknown"): int(count or 0)
        for scanner, count in db.execute(
            select(Finding.scanner, func.count(Finding.id))
            .where(Finding.scan_id == scan_id, Finding.suppressed.is_(False))
            .group_by(Finding.scanner)
        ).all()
    }


def _refresh_scan_finding_summary(db: Session, scan: Scan) -> None:
    counts = _scan_counts(db, scan.id)
    scanner_counts = _scan_scanner_counts(db, scan.id)
    findings_total = int(
        db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        or 0
    )
    ignored_count = int(db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id, Finding.suppressed.is_(True))) or 0)
    gate_exempt_count = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.scan_id == scan.id,
                Finding.suppressed.is_(False),
                Finding.gate_exempt.is_(True),
            )
        )
        or 0
    )
    summary = dict(scan.scanner_summary or {})
    # Lifecycle suppression changes the active/gate projection, not the
    # historical scanner evidence persisted for this scan.
    summary["findings_total"] = findings_total
    summary["severity_counts"] = counts
    summary["scanner_counts"] = scanner_counts
    summary["ignored_count"] = ignored_count
    summary["gate_exempt_count"] = gate_exempt_count
    scan.scanner_summary = _redacted_json_object(summary)
    decision, reasons = _evaluate_scan_gate(db, scan)
    scan.gate_decision = decision
    scan.gate_reasons = _redacted_reason_list(reasons)
    scan.revision += 1
    scan.findings_revision += 1
    db.add(scan)


def _distinct_findings_count(db: Session, where: Any | None = None) -> int:
    stmt = select(func.count(func.distinct(Finding.fingerprint)))
    if where is not None:
        stmt = stmt.where(where)
    return int(db.scalar(stmt) or 0)


def _evaluate_gate(db: Session, scan: Scan, *, policy_project_id: int | None = None) -> tuple[str, list[str]]:
    policy = db.scalar(select(GatePolicy).where(GatePolicy.project_id == (policy_project_id if policy_project_id is not None else scan.project_id), GatePolicy.active.is_(True)))
    if not policy:
        return "not_configured", []

    gate_conditions = (
        Finding.scan_id == scan.id,
        Finding.suppressed.is_(False),
        Finding.gate_exempt.is_(False),
    )
    critical = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                *gate_conditions, Finding.severity == "critical"
            )
        )
        or 0
    )
    high = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                *gate_conditions, Finding.severity == "high"
            )
        )
        or 0
    )
    searchable = func.lower(
        Finding.scanner + " " + Finding.rule_id + " " + Finding.message
    )
    secrets = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                *gate_conditions,
                searchable.contains("secret")
                | searchable.contains("token")
                | searchable.contains("private-key"),
            )
        )
        or 0
    )
    reasons: list[str] = []

    if policy.max_critical >= 0 and critical > policy.max_critical:
        reasons.append(f"critical findings: {critical} > max {policy.max_critical}")
    if policy.max_high >= 0 and high > policy.max_high:
        reasons.append(f"high findings: {high} > max {policy.max_high}")
    if policy.block_secrets and secrets:
        reasons.append(f"secret findings: {secrets}")

    return ("pass" if not reasons else "fail"), reasons


def _evaluate_scan_gate(db: Session, scan: Scan, *, policy_project_id: int | None = None) -> tuple[str, list[str]]:
    """Evaluate only complete scanner evidence as an authoritative gate.

    Finding lifecycle changes may legitimately make a completed scan pass, but
    they cannot repair missing scanner evidence. Preserve an existing fail or
    incomplete decision for every non-complete state and otherwise fail closed
    to the explicit incomplete decision.
    """

    if scan.status == "completed":
        return _evaluate_gate(db, scan, policy_project_id=policy_project_id)
    existing_reasons = _redacted_reason_list(scan.gate_reasons)
    if scan.gate_decision in {"fail", "incomplete"}:
        return scan.gate_decision, existing_reasons or [INCOMPLETE_GATE_REASON]
    return "incomplete", [INCOMPLETE_GATE_REASON]


def _normalize_advisor_packet_value(value: Any) -> Any:
    """Make the exact preview/transmission packet safe to render as multiline text."""

    if isinstance(value, dict):
        return {
            key: _normalize_advisor_packet_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_advisor_packet_value(item) for item in value]
    if not isinstance(value, str):
        return value
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        character
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf"}
        else "\ufffd"
        for character in normalized
    )


_ADVISOR_PACKET_SNIPPET_MAX_LINES = 16
_ADVISOR_PACKET_SNIPPET_MAX_CHARS = 8_000
_ADVISOR_PACKET_SNIPPET_MAX_UTF8_BYTES = 8_000
_ADVISOR_PACKET_METADATA_TEXT_FIELDS = {
    "rule_name": 160,
    "sarif_level": 30,
}
_ADVISOR_PACKET_METADATA_MAX_TAGS = 32
_ADVISOR_PACKET_METADATA_TAG_MAX_CHARS = 80


def _advisor_packet_safe_single_line(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in value
    ):
        return None
    redacted = _redacted_text(value, limit)
    return redacted or None


def _advisor_packet_snippet(finding: Finding) -> tuple[str | None, int | None]:
    """Return only safely mapped, bounded source lines for remote Advisor use."""

    value = finding.code_snippet
    metadata = finding.metadata_json
    if not isinstance(value, str) or not value or not isinstance(metadata, dict):
        return None, None
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if any(
        character not in {"\n", "\t"}
        and unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in normalized
    ):
        return None, None
    snippet_start_line = metadata.get("snippet_start_line")
    start_line = finding.start_line
    end_line = finding.end_line if finding.end_line is not None else start_line
    if (
        not isinstance(snippet_start_line, int)
        or isinstance(snippet_start_line, bool)
        or snippet_start_line < 1
        or not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or start_line < 1
        or not isinstance(end_line, int)
        or isinstance(end_line, bool)
        or end_line < start_line
    ):
        return None, None
    if "snippet_line_truncated" in metadata:
        snippet_line_truncated = metadata["snippet_line_truncated"]
        if not isinstance(snippet_line_truncated, bool) or snippet_line_truncated:
            return None, None
    snippet_column_start = metadata.get("snippet_column_start")
    if snippet_column_start is not None and (
        not isinstance(snippet_column_start, int)
        or isinstance(snippet_column_start, bool)
        or snippet_column_start != 1
    ):
        return None, None

    lines = normalized.splitlines()
    finding_start_index = start_line - snippet_start_line
    finding_end_index = end_line - snippet_start_line
    finding_line_count = finding_end_index - finding_start_index + 1
    if (
        not lines
        or finding_line_count > _ADVISOR_PACKET_SNIPPET_MAX_LINES
        or finding_start_index < 0
        or finding_end_index >= len(lines)
    ):
        return None, None

    candidate = "\n".join(lines[finding_start_index : finding_end_index + 1])
    rendered = _redacted_text(candidate)
    if (
        not rendered
        or rendered.count("\n") != candidate.count("\n")
        or len(rendered) > _ADVISOR_PACKET_SNIPPET_MAX_CHARS
        or len(rendered.encode("utf-8")) > _ADVISOR_PACKET_SNIPPET_MAX_UTF8_BYTES
    ):
        return None, None
    return rendered, start_line


def _advisor_packet_metadata(
    value: Any, *, snippet_start_line: int | None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    metadata: dict[str, Any] = {}
    for key, limit in _ADVISOR_PACKET_METADATA_TEXT_FIELDS.items():
        candidate = _advisor_packet_safe_single_line(value.get(key), limit)
        if candidate is not None:
            metadata[key] = candidate
    tags = value.get("tags")
    if isinstance(tags, list):
        bounded_tags: list[str] = []
        for item in tags[:_ADVISOR_PACKET_METADATA_MAX_TAGS]:
            candidate = _advisor_packet_safe_single_line(
                item, _ADVISOR_PACKET_METADATA_TAG_MAX_CHARS
            )
            if candidate is not None and candidate not in bounded_tags:
                bounded_tags.append(candidate)
        if bounded_tags:
            metadata["tags"] = bounded_tags
    if isinstance(value.get("verified"), bool):
        metadata["verified"] = value["verified"]
    if snippet_start_line is not None:
        metadata["snippet_start_line"] = snippet_start_line
    return metadata


def _finding_packet(finding: Finding, scan: Scan, project: Project, display_id: str | None = None) -> dict[str, Any]:
    code_snippet, snippet_start_line = _advisor_packet_snippet(finding)
    return _normalize_advisor_packet_value({
        "schema_version": 1,
        "finding": {
            "id": finding.id,
            "display_id": display_id or f"S{finding.scan_id}-DB{finding.id}",
            "scanner": _redacted_identity_text(finding.scanner, 80),
            "rule_id": _redacted_identity_text(finding.rule_id, 160),
            "severity": _redacted_identity_text(finding.severity, 30),
            "message": _redacted_text(finding.message, 4000),
            "fingerprint": _redacted_identity_text(finding.fingerprint, 128),
        },
        "location": {
            "file_path": _finding_path_to_out(finding.file_path),
            "start_line": finding.start_line,
            "start_column": finding.start_column,
            "end_line": finding.end_line,
            "end_column": finding.end_column,
        },
        "repo_context": {
            "project": _redacted_identity_text(project.name, 120),
            "repo_path": ".",
            "remote_url": None,
            "scan_id": scan.id,
            "mode": _redacted_identity_text(scan.mode, 40),
            "base_ref": None,
            "head_ref": None,
        },
        "scanner_evidence": {
            "code_snippet": code_snippet,
            "metadata": _advisor_packet_metadata(
                finding.metadata_json, snippet_start_line=snippet_start_line
            ),
        },
    })


_COMPONENT_HEALTH_BODY_MAX_BYTES = 4096
_COMPONENT_HEALTH_CONTRACTS = frozenset(
    {"status", "control", "scanner", "grafana", "gitea"}
)


def _component_health_body_matches(response: httpx.Response, contract: str) -> bool:
    if contract == "status":
        return True
    body_bytes = response.content
    if len(body_bytes) > _COMPONENT_HEALTH_BODY_MAX_BYTES:
        return False
    try:
        health_body = response.json()
    except ValueError:
        return False
    if not isinstance(health_body, dict) or len(health_body) > 32:
        return False
    if contract == "control":
        return health_body.get("ok") is True
    if contract == "scanner":
        return (
            health_body.get("ok") is True
            and health_body.get("engine") == "kodesec-worker"
        )
    if contract == "grafana":
        return health_body.get("database") == "ok"
    if contract == "gitea":
        return health_body.get("status") == "pass"
    raise ValueError("unsupported component health contract")


def _http_component(
    name: str,
    url: str,
    desired: bool,
    profile: str,
    command: str,
    check_url: str | None = None,
    accepted_status_codes: tuple[int, ...] = (200,),
    health_contract: str = "status",
) -> dict[str, Any]:
    if health_contract not in _COMPONENT_HEALTH_CONTRACTS:
        raise ValueError("unsupported component health contract")
    required = profile == "core"
    reachable = False
    healthy = False
    observed_state = "unknown"
    reason_code = "probe_failed"
    message = "Current service state could not be determined."
    try:
        with httpx.Client(timeout=1.0, follow_redirects=False, trust_env=False) as client:
            response = client.get(check_url or url)
            reachable = True
            # A response proves reachability, not health. Each component
            # opts into exact statuses from its semantic health endpoint;
            # login, authorization, redirect, and not-found pages must not
            # be promoted to a healthy component.
            healthy = response.status_code in accepted_status_codes
            if healthy:
                healthy = _component_health_body_matches(response, health_contract)
            if desired:
                observed_state = "running" if healthy else "unhealthy"
                reason_code = (
                    "health_response_accepted"
                    if healthy
                    else "health_response_rejected"
                )
                message = (
                    "Running and healthy."
                    if healthy
                    else "Running, but its health endpoint did not return the accepted healthy response."
                )
            else:
                observed_state = "running_undesired"
                reason_code = (
                    "running_undesired"
                    if healthy
                    else "running_undesired_unhealthy"
                )
                message = (
                    "Running although desired off; apply the component selection to stop it without deleting data."
                    if healthy
                    else "Reachable although desired off, and its health response is unhealthy; apply the component selection to stop it without deleting data."
                )
    except httpx.ConnectError:
        if desired:
            observed_state = "not_running"
            reason_code = "not_reachable"
            message = (
                "Required core service is not reachable."
                if required
                else "Not running; optional; scanning is unaffected."
            )
        else:
            observed_state = "not_observed"
            reason_code = "not_observed"
            message = "Not observed; optional component is desired off."
    except httpx.TimeoutException:
        observed_state = "unknown"
        reason_code = "probe_timeout"
        message = (
            "Required core service state could not be determined because its health check timed out."
            if required
            else (
                "Desired optional service state could not be determined because its health check timed out."
                if desired
                else "Optional service is desired off, but its current state could not be determined because its health check timed out."
            )
        )
    except httpx.HTTPError:
        observed_state = "unknown"
        reason_code = "probe_failed"
        message = (
            "Required core service state could not be determined."
            if required
            else (
                "Desired optional service state could not be determined."
                if desired
                else "Optional service is desired off, but its current state could not be determined."
            )
        )
    return {
        "id": name,
        "required": required,
        "desired_enabled": desired,
        "desired_state": "enabled" if desired else "disabled",
        "observed_state": observed_state,
        "reachable": reachable,
        "healthy": healthy,
        "url": url,
        "profile": profile,
        "apply_command": command,
        "reason_code": reason_code,
        "message": message,
    }


def _component_rows(values: dict[str, Any], settings: Settings) -> list[dict[str, Any]]:
    control_origin = settings.control_origin_list[0]
    apply_command = _component_apply_command(values)
    specs = [
        ("control", control_origin, True, "core", apply_command, "http://127.0.0.1:8080/healthz", (200,), "control"),
        ("scanner", control_origin, True, "core", apply_command, "http://scanner:8091/healthz", (200,), "scanner"),
        ("grafana", "http://127.0.0.1:3001", bool(values["component_monitoring_enabled"]), "monitoring", apply_command, "http://grafana:3000/api/health", (200,), "grafana"),
        ("prometheus", "http://127.0.0.1:9090", bool(values["component_monitoring_enabled"]), "monitoring", apply_command, "http://prometheus:9090/-/ready", (200,)),
        ("gitea", "http://127.0.0.1:3000", bool(values["component_git_proxy_enabled"]), "git-proxy", apply_command, "http://gitea:3000/api/healthz", (200,), "gitea"),
        ("adminer", "http://127.0.0.1:8082", bool(values["component_db_admin_enabled"]), "db-admin", apply_command, "http://adminer:8080", (200,)),
    ]
    # Probe desired-off services too: an HTTP response is the socket-free proof
    # that a previously enabled optional container still needs reconciliation.
    with ThreadPoolExecutor(max_workers=len(specs), thread_name_prefix="component-health") as executor:
        return list(executor.map(lambda spec: _http_component(*spec), specs))


def _component_apply_command(values: dict[str, Any]) -> str:
    selection = (
        bool(values["component_monitoring_enabled"]),
        bool(values["component_git_proxy_enabled"]),
        bool(values["component_db_admin_enabled"]),
    )
    commands = {
        (False, False, False): "make apply-components COMPONENTS=core",
        (True, False, False): "make apply-components COMPONENTS=monitoring",
        (False, True, False): "make apply-components COMPONENTS=git-proxy",
        (False, False, True): "make apply-components COMPONENTS=db-admin",
        (True, True, False): "make apply-components COMPONENTS=monitoring-git-proxy",
        (True, False, True): "make apply-components COMPONENTS=monitoring-db-admin",
        (False, True, True): "make apply-components COMPONENTS=git-proxy-db-admin",
        (True, True, True): "make apply-components COMPONENTS=all",
    }
    return commands[selection]


@router.get("/healthz")
def healthz(
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    settings = runtime.settings
    db_ok = True
    try:
        db.execute(select(func.now()))
    except Exception:
        db_ok = False
        try:
            db.rollback()
        except Exception:
            pass

    scanner_ok = False
    try:
        with httpx.Client(timeout=1.5, trust_env=False) as client:
            scanner_ok = client.get(f"{settings.scanner_url.rstrip('/')}/healthz").status_code == 200
    except Exception:
        scanner_ok = False

    active_config = _runtime_config_values(settings, db) if db_ok else None
    worker_id = None
    if db_ok:
        worker_id = fresh_worker_id(
            db,
            stale_after_seconds=max(15.0, settings.worker_liveness_seconds * 3),
        )
    if db_ok:
        ollama_ok, models, ollama_reason = worker_advisor_status(
            db,
            active_config,
            worker_id=worker_id,
            stale_after_seconds=max(90.0, settings.worker_liveness_seconds * 9),
        )
    else:
        ollama_ok, models, ollama_reason = False, [], "database_unavailable"
    return {
        "ok": db_ok and scanner_ok and worker_id is not None,
        "version": __version__,
        "db": db_ok,
        "source_snapshot_limits": SourceSnapshotLimitsOut().model_dump(),
        "scanner": scanner_ok,
        "worker": worker_id is not None,
        "ai": {
            "mode": active_config["ai_mode"] if active_config is not None else None,
            "available": ollama_ok,
            "base_url": active_config["ollama_base_url"] if active_config is not None else None,
            "model": active_config["ollama_model"] if active_config is not None else None,
            "thinking": active_config["ollama_thinking"] if active_config is not None else None,
            "models": models[:20],
            "reason": ollama_reason,
        },
    }


@router.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _schema_init_status(db: Session, runtime: Runtime) -> dict[str, Any]:
    current_identity = runtime.schema_identity
    current_fingerprint = runtime.schema_fingerprint
    current_initialized_at = runtime.schema_initialized_at
    identity_row = db.get(SchemaIdentity, 1)
    completed = (
        current_identity is not None
        and current_fingerprint is not None
        and current_initialized_at is not None
        and identity_row is not None
        and identity_row.schema_id == current_identity
        and identity_row.schema_fingerprint == current_fingerprint
        and identity_row.initialized_at == current_initialized_at
    )
    return {
        "id": "schema-init",
        "lifecycle": "one-shot",
        "startable": False,
        "state": "completed" if completed else "unverified",
        "message": (
            "Completed successfully; expected to stop."
            if completed
            else (
                "Initial schema identity no longer matches the API startup verification."
                if current_identity is not None
                else "Database schema has not been verified by API startup."
            )
        ),
        "schema_id": current_identity if completed else None,
        "schema_fingerprint": current_fingerprint if completed else None,
        "initialized_at": current_initialized_at if completed else None,
        "evidence": "schema-identity-and-api-startup-verification" if completed else None,
    }


def _config_response(db: Session, runtime: Runtime) -> dict[str, Any]:
    settings = runtime.settings
    active_config = _runtime_config_values(settings, db)
    worker_id = fresh_worker_id(
        db,
        stale_after_seconds=max(15.0, settings.worker_liveness_seconds * 3),
    )
    ollama_ok, models, reason = worker_advisor_status(
        db,
        active_config,
        worker_id=worker_id,
        stale_after_seconds=max(90.0, settings.worker_liveness_seconds * 9),
    )
    components = _component_rows(active_config, settings)
    return {
        "installation_id": settings.installation_id,
        "allowed_roots": settings.allowed_root_list,
        "scanner_url": settings.scanner_url,
        "ai_mode": active_config["ai_mode"],
        "ollama_base_url": active_config["ollama_base_url"],
        "ollama_available": ollama_ok,
        "ollama_model": active_config["ollama_model"],
        "ollama_thinking": active_config["ollama_thinking"],
        "ollama_models": models,
        "ollama_reason": reason,
        "auto_triage_limit": active_config["auto_triage_limit"],
        "component_monitoring_enabled": active_config["component_monitoring_enabled"],
        "component_git_proxy_enabled": active_config["component_git_proxy_enabled"],
        "component_db_admin_enabled": active_config["component_db_admin_enabled"],
        "gate_preset": active_config["gate_preset"],
        "gate_active": active_config["gate_active"],
        "gate_max_critical": active_config["gate_max_critical"],
        "gate_max_high": active_config["gate_max_high"],
        "gate_block_secrets": active_config["gate_block_secrets"],
        "component_apply_command": _component_apply_command(active_config),
        "components": components,
        "schema_init": _schema_init_status(db, runtime),
    }


@router.get("/v1/config", response_model=RuntimeConfigOut)
def config(runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    return _config_response(db, runtime)


@router.put("/v1/config", response_model=RuntimeConfigOut)
def update_config(payload: RuntimeConfigUpdate, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        ollama_base_url = normalize_local_ollama_url(
            payload.ollama_base_url,
            runtime.settings.ollama_allowed_host_list,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    lock_advisor_admission(db)
    _save_runtime_config(db, payload.model_copy(update={"ollama_base_url": ollama_base_url}))
    return _config_response(db, runtime)


@router.patch("/v1/config/advisor", response_model=RuntimeConfigOut)
def update_advisor_config(
    payload: RuntimeAdvisorConfigUpdate,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        ollama_base_url = normalize_local_ollama_url(
            payload.ollama_base_url,
            runtime.settings.ollama_allowed_host_list,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    lock_advisor_admission(db)
    _upsert_runtime_config_values(db, {
        "ai_mode": payload.ai_mode,
        "ollama_base_url": ollama_base_url,
        "ollama_model": payload.ollama_model,
        "ollama_thinking": str(payload.ollama_thinking).lower(),
        "auto_triage_limit": str(payload.auto_triage_limit),
    })
    db.commit()
    return _config_response(db, runtime)


def _provider_revision_conflict(error: advisor_providers.ProviderConflictError) -> HTTPException:
    return HTTPException(
        409,
        _problem_detail(
            "revision_conflict",
            "Advisor provider configuration changed after it was loaded.",
            action="refresh_advisor_providers",
            context={"current_revision": error.current_revision},
            safe_details={"current_revision": error.current_revision},
        ),
    )


def _provider_collection_response(
    db: Session, settings: Settings
) -> dict[str, Any]:
    collection = advisor_providers.load_collection(db, settings)
    return advisor_providers.public_collection(
        collection,
        settings,
        advisor_providers.load_valid_consents(db, collection),
        advisor_providers.load_valid_receipts(db, collection),
    )


@router.get(
    "/v1/advisor/providers", response_model=AdvisorProviderCollectionOut
)
def list_advisor_providers(
    runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)
) -> dict[str, Any]:
    return _provider_collection_response(db, runtime.settings)


@router.get(
    "/v1/advisor/local-models", response_model=AdvisorLocalCatalogOut
)
def list_local_advisor_models(
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    worker_id = fresh_worker_id(
        db,
        stale_after_seconds=max(15.0, runtime.settings.worker_liveness_seconds * 3),
    )
    catalog, reason = worker_advisor_catalog(
        db,
        worker_id=worker_id,
        stale_after_seconds=max(90.0, runtime.settings.worker_liveness_seconds * 9),
    )
    if catalog is not None:
        return catalog
    reason_code = reason or "advisor_local_catalog_unavailable"
    try:
        message, _retryable = advisor_providers.provider_test_failure(reason_code)
    except ValueError:
        message = {
            "work_processing_unavailable": "Local Ollama detection is waiting for the durable worker.",
            "not_checked_by_worker": "Local Ollama detection has not completed yet.",
            "worker_advisor_catalog_stale": "The last local Ollama detection receipt is stale.",
            "worker_advisor_catalog_owner_mismatch": "Local Ollama detection is waiting for the current durable worker.",
            "invalid_worker_advisor_catalog": "The local Ollama detection receipt is invalid.",
        }.get(reason_code, "Local Ollama detection is temporarily unavailable.")
    raise HTTPException(
        503,
        _problem_detail(
            reason_code,
            message,
            action="retry_local_advisor_detection",
            context={},
            safe_details={"reason_code": reason_code},
        ),
    )


@router.get("/v1/advisor/triage-request-audit")
def advisor_triage_request_audit(
    request: Request,
    finding_id: int = Query(ge=1),
    after_sequence: int = Query(ge=0, le=9_007_199_254_740_991),
) -> dict[str, str | int | bool]:
    """Return a body-free bounded audit window for one finding-triage route."""

    audit = getattr(request.app.state, "advisor_request_audit", None)
    if not isinstance(audit, AdvisorRequestAudit):
        raise RuntimeError("Advisor request audit is unavailable")
    return audit.snapshot(finding_id, after_sequence)


@router.get(
    "/v1/advisor/providers/{provider_id}/receipt",
    response_model=AdvisorProviderReceiptOut,
)
def get_advisor_provider_receipt(
    provider_id: str,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    current = advisor_providers.load_collection(db, runtime.settings)
    try:
        profile = advisor_providers.provider_by_id(current, provider_id)
    except KeyError as exc:
        raise HTTPException(404, "advisor provider not found") from exc
    receipt = advisor_providers.load_receipt(db, provider_id)
    if receipt is None or receipt["revision"] != profile["config_revision"] or any(
        receipt[key] != profile[profile_key]
        for key, profile_key in (
            ("kind", "transport"),
            ("route", "transport"),
            ("model", "model"),
            ("model_digest", "model_digest"),
        )
    ):
        raise HTTPException(404, "no current verified receipt exists for this provider")
    return receipt


@router.post(
    "/v1/advisor/providers",
    response_model=AdvisorProviderCollectionOut,
    status_code=201,
)
def create_advisor_provider(
    payload: AdvisorProviderWriteRequest,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    lock_advisor_admission(db)
    current = advisor_providers.load_collection(db, runtime.settings, lock=True)
    try:
        updated = advisor_providers.replace_profile(
            current,
            payload.provider.model_dump(mode="json"),
            expected_revision=payload.expected_revision,
            create=True,
        )
        advisor_providers.save_collection(db, updated)
        db.commit()
    except advisor_providers.ProviderConflictError as exc:
        db.rollback()
        raise _provider_revision_conflict(exc) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    return _provider_collection_response(db, runtime.settings)


@router.put(
    "/v1/advisor/providers/{provider_id}",
    response_model=AdvisorProviderCollectionOut,
)
def replace_advisor_provider(
    provider_id: str,
    payload: AdvisorProviderWriteRequest,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if payload.provider.id != provider_id:
        raise HTTPException(422, "route and provider ids must match")
    lock_advisor_admission(db)
    current = advisor_providers.load_collection(db, runtime.settings, lock=True)
    try:
        updated = advisor_providers.replace_profile(
            current,
            payload.provider.model_dump(mode="json"),
            expected_revision=payload.expected_revision,
            create=False,
        )
        advisor_providers.save_collection(db, updated)
        previous_revisions = {
            item["id"]: item["config_revision"] for item in current["providers"]
        }
        changed_ids = {
            item["id"]
            for item in updated["providers"]
            if previous_revisions.get(item["id"]) != item["config_revision"]
        }
        # Editing or swapping priority invalidates every changed profile's
        # exact receipt and disclosure consent, including the displaced row.
        for changed_id in changed_ids:
            advisor_providers.delete_consent(db, changed_id)
            advisor_providers.delete_receipt(db, changed_id)
        db.commit()
    except advisor_providers.ProviderConflictError as exc:
        db.rollback()
        raise _provider_revision_conflict(exc) from exc
    except KeyError as exc:
        db.rollback()
        raise HTTPException(404, "advisor provider not found") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    return _provider_collection_response(db, runtime.settings)


@router.delete(
    "/v1/advisor/providers/{provider_id}",
    response_model=AdvisorProviderCollectionOut,
)
def delete_advisor_provider(
    provider_id: str,
    payload: AdvisorProviderDeleteRequest,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    lock_advisor_admission(db)
    current = advisor_providers.load_collection(db, runtime.settings, lock=True)
    try:
        updated = advisor_providers.remove_profile(
            current, provider_id, expected_revision=payload.expected_revision
        )
        advisor_providers.save_collection(db, updated)
        advisor_providers.delete_consent(db, provider_id)
        advisor_providers.delete_receipt(db, provider_id)
        db.commit()
    except advisor_providers.ProviderConflictError as exc:
        db.rollback()
        raise _provider_revision_conflict(exc) from exc
    except KeyError as exc:
        db.rollback()
        raise HTTPException(404, "advisor provider not found") from exc
    return _provider_collection_response(db, runtime.settings)


@router.post(
    "/v1/advisor/providers/{provider_id}/commands",
    response_model=JobOut,
    status_code=202,
)
def command_advisor_provider(
    provider_id: str,
    payload: AdvisorProviderCommandRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    client_id, idempotency_key = _command_identity(request)
    request_digest = _request_digest(payload, provider_id=provider_id)
    existing = _existing_command(
        db,
        kind="advisor_provider",
        client_id=client_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )
    if existing is not None:
        return _job_to_out(db, existing)
    lock_advisor_admission(db)
    current = advisor_providers.load_collection(db, runtime.settings, lock=True)
    try:
        advisor_providers.require_revision(current, payload.expected_revision)
        profile = advisor_providers.provider_by_id(current, provider_id)
    except advisor_providers.ProviderConflictError as exc:
        db.rollback()
        raise _provider_revision_conflict(exc) from exc
    except KeyError as exc:
        db.rollback()
        raise HTTPException(404, "advisor provider not found") from exc
    if payload.action != "disconnect":
        if not profile["enabled"]:
            raise HTTPException(409, "disabled advisor provider cannot be tested or activated")
        authorized = advisor_providers.authorized_provider_ids(runtime.settings, current)
        if provider_id not in authorized:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_provider_authorization_required",
                    "This provider requires explicit host authorization before use.",
                    action="authorize_advisor_provider",
                    context={"provider_id": provider_id, "transport": profile["transport"]},
                    safe_details={"provider_id": provider_id, "transport": profile["transport"]},
                ),
            )
    approval = (
        payload.source_disclosure_approval.model_dump(mode="json", by_alias=True)
        if payload.source_disclosure_approval is not None
        else None
    )
    if payload.action == "activate" and profile["transport"] in {"direct", "ssh"}:
        expected_approval = advisor_providers.build_activation_approval(profile)
        if (
            not payload.acknowledge_source_disclosure
            or approval != expected_approval
        ):
            raise HTTPException(
                422,
                _problem_detail(
                    "advisor_source_disclosure_confirmation_required",
                    "Activation requires explicit approval bound to this exact provider revision, destination, model digest, and disclosure categories.",
                    action="confirm_advisor_source_disclosure",
                    context={"provider_id": provider_id, "transport": profile["transport"]},
                    safe_details={
                        "provider_id": provider_id,
                        "transport": profile["transport"],
                        "current_revision": profile["config_revision"],
                    },
                ),
            )
    elif payload.acknowledge_source_disclosure or approval is not None:
        raise HTTPException(422, "source disclosure approval is accepted only for remote activation")
    active = db.scalar(
        select(Job).where(
            Job.kind == "advisor_provider",
            Job.status.in_(ACTIVE_JOB_STATUSES),
        )
    )
    if active is not None:
        raise HTTPException(409, f"advisor provider command already active as job {active.id}")
    job = _enqueue_or_conflict(
        db,
        kind="advisor_provider",
        title=f"{payload.action.title()} Advisor provider {profile['name']}",
        client_id=client_id,
        idempotency_key=idempotency_key,
        payload={
            "v": 1,
            "operation": "advisor_provider_command",
            "request_digest": request_digest,
            "action": payload.action,
            "provider": advisor_providers.job_profile_snapshot(profile),
            "provider_revision": current["revision"],
            "provider_config_revision": profile["config_revision"],
            "provider_config_digest": profile["config_digest"],
            "acknowledge_source_disclosure": payload.acknowledge_source_disclosure,
            "source_disclosure_approval": approval,
        },
        max_attempts=3,
    )
    job.detail = _redacted_text(
        f"Queued {payload.action} for Advisor provider {profile['name']}"
    )
    db.commit()
    db.refresh(job)
    return _job_to_out(db, job)


@router.patch("/v1/config/gate", response_model=RuntimeConfigOut)
def update_gate_config(
    payload: RuntimeGateConfigUpdate,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _upsert_runtime_config_values(db, {
        "gate_preset": payload.gate_preset,
        "gate_active": str(payload.gate_active).lower(),
        "gate_max_critical": str(payload.gate_max_critical),
        "gate_max_high": str(payload.gate_max_high),
        "gate_block_secrets": str(payload.gate_block_secrets).lower(),
    })
    # Global defaults, per-project policy rows, and terminal scan revisions are
    # committed together so apply-to-existing can never expose a split state.
    _apply_runtime_gate_to_existing(db, payload)
    db.commit()
    return _config_response(db, runtime)


@router.patch("/v1/config/components", response_model=RuntimeConfigOut)
def update_components_config(
    payload: RuntimeComponentsConfigUpdate,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _upsert_runtime_config_values(db, {
        "component_monitoring_enabled": str(payload.component_monitoring_enabled).lower(),
        "component_git_proxy_enabled": str(payload.component_git_proxy_enabled).lower(),
        "component_db_admin_enabled": str(payload.component_db_admin_enabled).lower(),
    })
    db.commit()
    return _config_response(db, runtime)


@router.get("/v1/scanner/tools", response_model=list[ScannerToolOut])
def scanner_tools(runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return _scanner_tool_rows(db, runtime.settings)


@router.get("/v1/scanner/preflight", response_model=ScannerPreflightOut, response_model_exclude_unset=True)
def scanner_preflight(
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _scanner_preflight(db, runtime.settings)


def _require_scanner_lifecycle_state(db: Session, scope: str) -> ScannerLifecycleState:
    if scope not in {"catalog", "cache"}:
        raise ValueError("scanner lifecycle scope is invalid")
    state = db.get(ScannerLifecycleState, scope)
    if state is None:
        raise SchemaSingletonStateError(
            f"scanner lifecycle singleton {scope!r} is missing from the initialized schema"
        )
    return state


def _lock_scanner_lifecycle_state(db: Session, scope: str) -> ScannerLifecycleState:
    if scope not in {"catalog", "cache"}:
        raise ValueError("scanner lifecycle scope is invalid")
    state = db.scalar(
        select(ScannerLifecycleState)
        .where(ScannerLifecycleState.id == scope)
        .with_for_update(of=ScannerLifecycleState)
        .execution_options(populate_existing=True)
    )
    if state is None:
        raise SchemaSingletonStateError(
            f"scanner lifecycle singleton {scope!r} is missing from the initialized schema"
        )
    return state


def _scanner_lifecycle_scope_out(
    db: Session,
    state: ScannerLifecycleState,
) -> dict[str, Any]:
    job = db.get(Job, state.job_id) if state.job_id is not None else None
    status = job.status if job is not None else state.status
    error_code = job.error_code if job is not None and job.status == "failed" else state.error_code
    error_detail = (
        job.error_detail if job is not None and job.status == "failed" else state.error_detail
    )
    started_at = job.started_at if job is not None else state.started_at
    completed_at = job.completed_at if job is not None else state.completed_at
    updated_at = job.updated_at if job is not None else state.updated_at
    return {
        "scope": state.id,
        "status": status,
        "revision": state.revision,
        "job_id": job.id if job is not None else None,
        "job_url": f"/v1/jobs/{job.id}" if job is not None else None,
        "active_generation": state.active_generation,
        "previous_generation": state.previous_generation,
        "receipt": _redacted_json_object(state.receipt or {}),
        "error_code": _redacted_identity_text(error_code, 80) if error_code else None,
        "error_detail": _redacted_optional_text(error_detail),
        "started_at": started_at,
        "completed_at": completed_at,
        "updated_at": updated_at,
    }


def _scanner_lifecycle_digest(
    operation: str,
    component_ids: list[str],
    catalog_digest: str | None = None,
    preparation_budget: PreparationBudget | dict[str, Any] | None = None,
) -> str:
    document = {
        "schema_version": 2 if preparation_budget is not None else 1,
        "kind": operation,
        "requested_components": sorted(component_ids),
    }
    if catalog_digest is not None:
        if operation != "cache_update" or re.fullmatch(r"[0-9a-f]{64}", catalog_digest) is None:
            raise ValueError("invalid scanner data catalog selection")
        document["catalog_digest"] = catalog_digest
    if preparation_budget is not None:
        document["preparation_budget"] = PreparationBudget.model_validate(preparation_budget).model_dump(mode="json")
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _enqueue_scanner_lifecycle_job(
    db: Session,
    request: Request,
    *,
    kind: str,
    operation: str,
    scope: str,
    component_ids: list[str],
    title: str,
    catalog_digest: str | None = None,
    require_previous_generation: bool = False,
    rollback_eligibility: dict[str, Any] | None = None,
    prerequisite_job_id: int | None = None,
    preparation_continuation: ScannerPreparationContinuation | None = None,
    command_identity: tuple[str, str] | None = None,
    scanner_settings: Settings | None = None,
    preparation_platform: str = "mac",
    commit: bool = True,
) -> dict[str, Any]:
    client_id, idempotency_key = command_identity or _command_identity(request)
    # Catalog completion takes these locks in this same order before admitting
    # its cache continuation. Manual admission and replay must not invert it.
    catalog_state = _lock_scanner_lifecycle_state(db, "catalog") if operation == "cache_update" else None
    state = _lock_scanner_lifecycle_state(db, scope)
    prior = db.scalar(select(Job).where(Job.client_id == client_id, Job.kind == kind,
                                       Job.idempotency_key == durable_idempotency_key(idempotency_key)))
    preparation_budget = None
    if operation in {"catalog_check", "cache_update"}:
        if prior is not None:
            raw_budget = prior.payload.get("preparation_budget") if isinstance(prior.payload, dict) else None
            preparation_budget = PreparationBudget.model_validate(raw_budget) if raw_budget is not None else None
        elif preparation_continuation is not None:
            preparation_budget = preparation_continuation.preparation_budget
        else:
            preparation_budget = issue_budget(platform=preparation_platform)
    request_digest = _scanner_lifecycle_digest(operation, component_ids, catalog_digest, preparation_budget)
    existing = _existing_command(
        db,
        kind=kind,
        client_id=client_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )
    if existing is not None:
        return {
            "job": _job_to_out(db, existing),
            "lifecycle": _scanner_lifecycle_scope_out(db, state),
        }
    if operation in {"catalog_check", "cache_update"}:
        if preparation_budget is None:
            raise HTTPException(409, _problem_detail(
                "scanner_preparation_budget_required",
                "Start a new preparation command with the current source.",
                action="prepare_scanners",
            ))
        try:
            budget_remaining(preparation_budget)
        except PreparationDeadlineExceeded as exc:
            raise HTTPException(409, _problem_detail(
                "scanner_preparation_deadline",
                "The preparation deadline has elapsed. Start a new command.",
                action="prepare_scanners",
            )) from exc
    if operation == "cache_update":
        assert catalog_state is not None
        receipt = catalog_state.receipt if isinstance(catalog_state.receipt, dict) else {}
        result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
        if catalog_digest != result.get("catalog_digest"):
            raise HTTPException(409, _problem_detail(
                "scanner_catalog_selection_changed",
                "The scanner data catalog changed. Refresh the catalog and review the exact candidates again.",
                action="prepare_scanners",
            ))
    if scanner_settings is not None:
        # Inspect new cache commands only; replay preserves the accepted job.
        _require_scanner_verification_ready(
            _scanner_runtime_snapshot(scanner_settings).cache_verification
        )
    if require_previous_generation and not state.previous_generation:
        raise HTTPException(409, "no previous-good scanner cache generation is available")
    if require_previous_generation:
        eligibility = ScannerCacheRollbackEligibilityOut.model_validate(
            rollback_eligibility,
            strict=True,
        )
        if (
            not eligibility.eligible
            or eligibility.target_generation != state.previous_generation
        ):
            raise HTTPException(
                409,
                _problem_detail(
                    "scanner_cache_rollback_unavailable",
                    eligibility.reason,
                    action=(
                        _scanner_verification_action(eligibility.verification.model_dump())
                        if eligibility.verification is not None
                        else "prepare_scanners"
                    ),
                    context={
                        "reason_code": eligibility.reason_code,
                        "target_generation": eligibility.target_generation,
                    },
                ),
            )
    active = db.get(Job, state.job_id) if state.job_id is not None else None
    if active is not None and active.status in ACTIVE_JOB_STATUSES:
        raise HTTPException(
            409,
            f"scanner {scope} lifecycle already has active job {active.id}",
        )

    payload: dict[str, Any] = {
        "v": 1,
        "operation": operation,
        "request_digest": request_digest,
        "component_ids": sorted(component_ids),
    }
    if preparation_budget is not None:
        payload["preparation_budget"] = preparation_budget.model_dump(mode="json")
    if catalog_digest is not None:
        payload["catalog_digest"] = catalog_digest
    if prerequisite_job_id is not None:
        payload["prerequisite_job_id"] = prerequisite_job_id
    if preparation_continuation is not None:
        if kind != "scanner_catalog_check" or operation != "catalog_check" or scope != "catalog":
            raise ValueError("scanner preparation continuation requires a catalog command")
        expected_continuation_digest = _scanner_lifecycle_digest(
            "cache_update",
            list(preparation_continuation.component_ids),
            preparation_budget=preparation_continuation.preparation_budget,
        )
        if preparation_continuation.request_digest != expected_continuation_digest:
            raise ValueError("scanner preparation continuation digest does not match its components")
        payload["preparation"] = preparation_continuation.model_dump(mode="json")

    try:
        job = _enqueue_or_conflict(
            db,
            kind=kind,
            title=title,
            client_id=client_id,
            idempotency_key=idempotency_key,
            payload=payload,
            external_run_id=str(uuid4()),
            max_attempts=3,
        )
        state.status = "queued"
        state.job_id = job.id
        state.receipt = {}
        state.error_code = None
        state.error_detail = None
        state.started_at = None
        state.completed_at = None
        state.updated_at = _utcnow()
        state.revision += 1
        db.add(state)
        if commit:
            db.commit()
        else:
            db.flush()
    except HTTPException as exc:
        if not commit:
            raise
        db.rollback()
        existing = _existing_command(
            db,
            kind=kind,
            client_id=client_id,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        if existing is None:
            raise exc
        state = _require_scanner_lifecycle_state(db, scope)
        return {
            "job": _job_to_out(db, existing),
            "lifecycle": _scanner_lifecycle_scope_out(db, state),
        }
    if commit:
        db.refresh(job)
        db.refresh(state)
    return {
        "job": _job_to_out(db, job),
        "lifecycle": _scanner_lifecycle_scope_out(db, state),
    }


@router.get("/v1/scanner/lifecycle", response_model=ScannerLifecycleOut)
def scanner_lifecycle(db: Session = Depends(get_db)) -> dict[str, Any]:
    states = {
        scope: _require_scanner_lifecycle_state(db, scope)
        for scope in ("catalog", "cache")
    }
    return {
        scope: _scanner_lifecycle_scope_out(db, state)
        for scope, state in states.items()
    }


def _scanner_preparation_continuation_from_job(
    job: Job,
) -> ScannerPreparationContinuation | None:
    raw = job.payload.get("preparation") if isinstance(job.payload, dict) else None
    if raw is None:
        return None
    try:
        continuation = ScannerPreparationContinuation.model_validate(raw, strict=True)
    except ValidationError as exc:
        raise HTTPException(
            409,
            _problem_detail(
                "scanner_preparation_invalid",
                "The scanner preparation continuation is invalid and cannot be used safely.",
                action="review_scanner_jobs",
            ),
        ) from exc
    expected_digest = _scanner_lifecycle_digest(
        "cache_update",
        list(continuation.component_ids),
        preparation_budget=continuation.preparation_budget,
    )
    continuation_budget = (
        continuation.preparation_budget.model_dump(mode="json")
        if continuation.preparation_budget is not None else None
    )
    if (
        continuation.request_digest != expected_digest
        or job.payload.get("preparation_budget") != continuation_budget
    ):
        raise HTTPException(
            409,
            _problem_detail(
                "scanner_preparation_invalid",
                "The scanner preparation continuation does not match its required components.",
                action="review_scanner_jobs",
            ),
        )
    return continuation


def _scanner_preparation_cache_key(catalog_job_id: int) -> str:
    if catalog_job_id < 1:
        raise ValueError("scanner preparation catalog job id must be positive")
    return f"prepare-cache:v1:{catalog_job_id}"


def _reject_active_scanner_preparation_catalog(db: Session) -> None:
    catalog_state = _lock_scanner_lifecycle_state(db, "catalog")
    catalog_job = (
        db.get(Job, catalog_state.job_id)
        if catalog_state.job_id is not None
        else None
    )
    if (
        catalog_job is None
        or catalog_job.kind != "scanner_catalog_check"
        or catalog_job.status not in ACTIVE_JOB_STATUSES
    ):
        return
    continuation = _scanner_preparation_continuation_from_job(catalog_job)
    if continuation is None:
        return
    raise HTTPException(
        409,
        _problem_detail(
            "scanner_preparation_catalog_active",
            "Scanner preparation is still validating the reviewed catalog before cache work can be admitted.",
            action="review_scanner_jobs",
            context={"catalog_job_id": catalog_job.id},
        ),
    )


@router.post(
    "/v1/scanner/prepare",
    response_model=ScannerPreparationCommandOut,
    status_code=202,
)
def prepare_scanners(
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue catalog validation with one durable conditional cache continuation."""

    client_id, parent_key = _command_identity(request)
    parent_digest = hashlib.sha256(parent_key.encode("ascii")).hexdigest()
    catalog_key = f"prepare-catalog:{parent_digest}"
    existing_catalog = db.scalar(
        select(Job).where(
            Job.client_id == client_id,
            Job.kind == "scanner_catalog_check",
            Job.idempotency_key == durable_idempotency_key(catalog_key),
        )
    )
    if existing_catalog is not None:
        continuation = _scanner_preparation_continuation_from_job(existing_catalog)
        if continuation is None:
            raise HTTPException(
                409,
                _problem_detail(
                    "scanner_preparation_invalid",
                    "The prior scanner preparation command has no conditional cache continuation.",
                    action="review_scanner_jobs",
                ),
            )
        component_ids = list(continuation.component_ids)
        cache_key = _scanner_preparation_cache_key(existing_catalog.id)
        existing_cache = db.scalar(
            select(Job).where(
                Job.client_id == client_id,
                Job.kind == "scanner_cache_update",
                Job.idempotency_key == durable_idempotency_key(cache_key),
            )
        )
        if existing_cache is not None:
            try:
                cache_request = ScannerCacheUpdateRequest.model_validate(
                    {"component_ids": existing_cache.payload.get("component_ids"),
                     "catalog_digest": existing_cache.payload.get("catalog_digest")},
                    strict=True,
                )
            except ValidationError as exc:
                raise HTTPException(
                    409,
                    _problem_detail(
                        "scanner_preparation_invalid",
                        "The prior scanner preparation cache command is invalid and cannot be replayed safely.",
                        action="review_scanner_jobs",
                    ),
                ) from exc
            if (
                existing_cache.payload.get("prerequisite_job_id") != existing_catalog.id
                or existing_cache.payload.get("preparation_budget")
                != existing_catalog.payload.get("preparation_budget")
                or existing_cache.payload.get("preparation_budget") != (
                    continuation.preparation_budget.model_dump(mode="json")
                    if continuation.preparation_budget is not None else None
                )
                or existing_cache.payload.get("request_digest") != _scanner_lifecycle_digest(
                    "cache_update", component_ids, existing_cache.payload.get("catalog_digest"),
                    existing_cache.payload.get("preparation_budget"),
                )
                or cache_request.component_ids != component_ids
            ):
                raise HTTPException(
                    409,
                    _problem_detail(
                        "scanner_preparation_invalid",
                        "The prior scanner preparation stages are not linked safely and cannot be replayed.",
                        action="review_scanner_jobs",
                    ),
                )
        return {
            "catalog": {
                "job": _job_to_out(db, existing_catalog),
                "lifecycle": _scanner_lifecycle_scope_out(
                    db, _require_scanner_lifecycle_state(db, "catalog")
                ),
            },
            "cache": (
                {
                    "job": _job_to_out(db, existing_cache),
                    "lifecycle": _scanner_lifecycle_scope_out(
                        db, _require_scanner_lifecycle_state(db, "cache")
                    ),
                }
                if existing_cache is not None
                else None
            ),
            "required_component_ids": component_ids,
        }

    preparation_budget = issue_budget(platform=runtime.settings.preparation_platform)
    preflight = _scanner_preflight(db, runtime.settings)
    _require_scanner_verification_ready(preflight.get("cache_verification"))
    if preflight["ready"]:
        raise HTTPException(
            409,
            _problem_detail(
                "scanners_already_ready",
                "All enabled scanners already have verified binaries, data, rules, and offline execution.",
                action="scan",
            ),
        )
    component_ids = list(preflight["required_component_ids"])
    # A retained catalog can describe locks from before a source update. Every
    # new explicit attempt checks the current source; only that fresh catalog's
    # validated completion may admit its conditional cache continuation.
    if not preflight.get("preparation_available", False):
        blocked = [
            tool
            for tool in preflight["blocked_tools"]
            if tool.get("preparation_blocking_reasons")
        ]
        raise HTTPException(
            409,
            _problem_detail(
                "scanner_runtime_prerequisite_missing",
                "Scanner preparation cannot repair a missing scanner binary or offline execution prerequisite.",
                action="repair_scanner_runtime",
                context={
                    "tool_ids": [str(tool["id"]) for tool in blocked],
                    "blocking_reasons": [
                        str(reason)
                        for tool in blocked
                        for reason in tool["preparation_blocking_reasons"]
                    ][:8],
                },
                safe_details={"reason_code": "runtime_prerequisite_missing"},
            ),
        )
    if not component_ids:
        raise HTTPException(
            409,
            _problem_detail(
                "scanner_preparation_unavailable",
                "Scanner preparation cannot repair the reported runtime state from the verified cache catalog.",
                action="review_scanner_readiness",
                safe_details={"reason_code": "no_required_cache_components"},
            ),
        )

    continuation = ScannerPreparationContinuation(
        schema_version=2,
        preparation_budget=preparation_budget,
        component_ids=component_ids,
        request_digest=_scanner_lifecycle_digest("cache_update", component_ids, preparation_budget=preparation_budget),
    )
    catalog = _enqueue_scanner_lifecycle_job(
        db,
        request,
        kind="scanner_catalog_check",
        operation="catalog_check",
        scope="catalog",
        component_ids=[],
        title="Check curated scanner catalog for scanner preparation",
        preparation_continuation=continuation,
        command_identity=(client_id, catalog_key),
    )
    return {
        "catalog": catalog,
        "cache": None,
        "required_component_ids": component_ids,
    }


@router.post(
    "/v1/scanner/tools/check-latest",
    response_model=ScannerLifecycleCommandOut,
    status_code=202,
)
def check_scanner_tools(
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue an explicit source-blind catalog check; never contact upstream here."""

    return _enqueue_scanner_lifecycle_job(
        db,
        request,
        kind="scanner_catalog_check",
        operation="catalog_check",
        scope="catalog",
        component_ids=[],
        title="Check curated scanner catalog",
        preparation_platform=runtime.settings.preparation_platform,
    )


@router.post(
    "/v1/scanner/cache/update",
    response_model=ScannerLifecycleCommandOut,
    status_code=202,
)
def update_scanner_cache(
    payload: ScannerCacheUpdateRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _reject_active_scanner_preparation_catalog(db)
    return _enqueue_scanner_lifecycle_job(
        db,
        request,
        kind="scanner_cache_update",
        operation="cache_update",
        scope="cache",
        component_ids=list(payload.component_ids),
        title="Update verified offline scanner cache",
        catalog_digest=payload.catalog_digest,
        scanner_settings=runtime.settings,
        preparation_platform=runtime.settings.preparation_platform,
    )


@router.post(
    "/v1/scanner/cache/verification/retry",
    response_model=ScannerCacheVerificationOut,
    status_code=202,
)
def retry_scanner_cache_verification(
    payload: ScannerCacheVerificationRetryRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
) -> dict[str, Any]:
    """Retry one exact failed runtime observation, never a cache update job."""

    _command_identity(request)
    try:
        with httpx.Client(timeout=runtime.settings.scanner_tools_timeout, trust_env=False) as client:
            response = client.post(
                f"{runtime.settings.scanner_url.rstrip('/')}/cache/verification/retry",
                json=payload.model_dump(mode="json"),
            )
    except httpx.RequestError as exc:
        raise HTTPException(503, _problem_detail(
            "scanner_verification_retry_unavailable",
            "Scanner verification retry could not reach the runtime. Refresh scanner status before trying again.",
            action="refresh_scanner_preflight",
        )) from exc
    try:
        if len(response.content) > 4096:
            raise ValueError("verification response exceeds its bound")
        value = response.json()
        if response.status_code == 409:
            conflicts = {
                "cache_verification_changed": "Scanner cache state changed. Refresh scanner status before retrying verification.",
                "cache_verification_not_retryable": "This scanner cache verification is not waiting for a retry. Refresh scanner status.",
            }
            detail = value.get("detail") if isinstance(value, dict) else None
            code = detail.get("code") if isinstance(detail, dict) else None
            if isinstance(code, str) and code in conflicts:
                raise HTTPException(409, _problem_detail(code, conflicts[code], action="refresh_scanner_preflight"))
            raise ValueError("unrecognized verification conflict")
        if response.status_code != 202:
            raise ValueError("unexpected verification response status")
        verification = ScannerCacheVerificationOut.model_validate(value, strict=True)
        if (verification.state != "verifying" or verification.target != payload.target
                or verification.generation_id != payload.expected_generation):
            raise ValueError("verification response target changed")
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(502, _problem_detail(
            "scanner_verification_retry_protocol_invalid",
            "Scanner verification retry returned invalid data. Refresh scanner status before trying again.",
            action="refresh_scanner_preflight",
        )) from exc
    return verification.model_dump(mode="json")


@router.post(
    "/v1/scanner/cache/rollback",
    response_model=ScannerLifecycleCommandOut,
    status_code=202,
)
def rollback_scanner_cache(
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    eligibility = _scanner_cache_rollback_eligibility(db, runtime.settings)
    return _enqueue_scanner_lifecycle_job(
        db,
        request,
        kind="scanner_cache_rollback",
        operation="cache_rollback",
        scope="cache",
        component_ids=[],
        title="Roll back verified offline scanner cache",
        require_previous_generation=True,
        rollback_eligibility=eligibility,
    )


@router.patch("/v1/scanner/tools/{tool_id}", response_model=ScannerToolOut)
def patch_scanner_tool(tool_id: str, payload: ScannerToolPatch, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    state = _ensure_tool_state(db, tool_id)
    if payload.enabled is not None:
        state.enabled = payload.enabled
        state.status = "ready" if payload.enabled else "disabled"
    if payload.pinned_version is not None:
        desired = payload.pinned_version.strip() or None
        if desired is not None and SCANNER_TOOL_REGISTRY[tool_id]["source"] != "external":
            raise HTTPException(409, "internal fallback scanners do not select image releases")
        if desired is not None and _normalize_version(desired) != _normalize_version(state.latest_version):
            raise HTTPException(422, "pinned_version must be the attested curated candidate")
        if desired is not None and not state.candidate_manifest_sha256:
            raise HTTPException(409, "scanner candidate has no admitted manifest attestation")
        state.pinned_version = desired
        if desired is not None:
            state.status = "host_confirmation_required"
    state.update_available = (
        SCANNER_TOOL_REGISTRY[tool_id]["source"] == "external"
        and (
            bool(state.pinned_version)
            or _normalize_version(state.current_version) != _normalize_version(state.latest_version)
        )
    )
    state.updated_at = _utcnow()
    db.add(state)
    db.commit()
    return next(item for item in _scanner_tool_rows(db, runtime.settings) if item["id"] == tool_id)


@router.post("/v1/scanner/tools/{tool_id}/update", response_model=ScannerToolOut)
def update_scanner_tool(tool_id: str, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    state = _ensure_tool_state(db, tool_id)
    defaults = SCANNER_TOOL_REGISTRY[tool_id]
    if defaults["source"] == "external":
        # The control plane is intentionally unable to mutate the immutable
        # scanner container. Record the desired image pin and keep the actual
        # installed version authoritative until a verified rebuild is running.
        state.pinned_version = state.latest_version or str(defaults["latest_version"])
        state.update_available = True
        if not state.candidate_manifest_sha256:
            raise HTTPException(409, "scanner candidate has no admitted manifest attestation")
        state.status = "host_confirmation_required"
    else:
        state.current_version = state.latest_version or str(defaults["latest_version"])
        state.pinned_version = None
        state.update_available = False
        state.status = "ready"
    state.updated_at = _utcnow()
    db.add(state)
    db.commit()
    return next(item for item in _scanner_tool_rows(db, runtime.settings) if item["id"] == tool_id)


def _configured_source_access(repo_path: str, settings: Settings) -> SourcePreviewOut:
    """Share the configured boundary between preview and project admission.

    This is deliberately lexical: the API has no source mount. The scanner
    checks real paths, symlinks and file safety again at execution admission.
    """
    source_roots = [
        PurePosixPath(normalize_project_repo_path(value))
        for value in settings.allowed_root_list
    ]
    canonical_repo_path = normalize_project_repo_path(repo_path)
    project_path = PurePosixPath(canonical_repo_path)
    authorized = any(project_path.is_relative_to(root) for root in source_roots)
    return SourcePreviewOut(
        installation_id=settings.installation_id,
        repo_path=canonical_repo_path,
        authorized=authorized,
        configured_roots=[str(root) for root in source_roots],
        reason_code=None if authorized else "source_outside_allowed_root",
    )


@router.post("/v1/sources/preview", response_model=SourcePreviewOut)
def preview_source(payload: SourcePreviewRequest, runtime: Runtime = Depends(get_runtime)) -> SourcePreviewOut:
    # No database dependency: preview/cancel must never register a project or job.
    return _configured_source_access(payload.repo_path, runtime.settings)


@router.post("/v1/projects", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    access = _configured_source_access(payload.repo_path, runtime.settings)
    canonical_repo_path = access.repo_path
    source_roots = access.configured_roots
    if not access.authorized:
        selected_display = _redacted_identity_text(canonical_repo_path, 4096)
        boundary_displays = [
            _redacted_identity_text(str(source_root), 4096)
            for source_root in source_roots
        ]
        selected_public = _redacted_identity_text(
            canonical_repo_path,
            MAX_PUBLIC_SAFE_DETAIL_TEXT_LENGTH,
        )
        boundary_public = _redacted_identity_text(
            ", ".join(str(source_root) for source_root in source_roots),
            MAX_PUBLIC_SAFE_DETAIL_TEXT_LENGTH,
        )
        raise HTTPException(
            422,
            _problem_detail(
                "source_outside_allowed_root",
                "The selected directory is outside the authorized source root.",
                action="authorize_source",
                context={
                    "source_target": {
                        "kind": "mounted_directory",
                        "display_path": selected_display,
                    },
                    "authorization_boundary": {
                        "kind": "allowed_roots",
                        "display_paths": boundary_displays,
                    },
                    "selected_path": selected_display,
                    "allowed_roots": boundary_displays,
                },
                safe_details={
                    "selected_source": selected_public,
                    "configured_source_boundary": boundary_public,
                },
            ),
        )
    existing = db.scalar(select(Project).where(Project.repo_path == canonical_repo_path))
    if existing:
        raise HTTPException(409, "this canonical source path is already bound to a project")
    project = Project(
        name=payload.name,
        repo_path=canonical_repo_path,
        remote_url=payload.remote_url,
        default_branch=payload.default_branch,
    )
    try:
        db.add(project)
        db.flush()
        db.add(GatePolicy(project_id=project.id, **_gate_policy_values(_runtime_config_values(runtime.settings, db))))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if db.scalar(select(Project.id).where(Project.repo_path == canonical_repo_path)) is not None:
            raise HTTPException(
                409,
                "this canonical source path is already bound to a project",
            ) from exc
        raise
    db.refresh(project)
    return _project_to_out(project)


@router.post("/v1/source-snapshots", response_model=SourceSnapshotOut, status_code=201)
def create_source_snapshot(
    payload: SourceSnapshotCreate,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Admit one explicit native-Windows source snapshot without widening mounts."""

    try:
        snapshot_digest, _, file_count, total_bytes = store_source_snapshot(
            runtime.settings,
            payload,
        )
        canonical_repo_path = source_snapshot_project_path(payload.source_id)
    except SourceSnapshotError as exc:
        storage_status = {"snapshot_storage_full": 507, "snapshot_storage_busy": 409, "snapshot_storage_unavailable": 503}.get(exc.code)
        if storage_status is not None:
            raise HTTPException(storage_status, _problem_detail(exc.code, str(exc),
                action="retry" if exc.code == "snapshot_storage_busy" else "review_storage",
                safe_details={"reason_code": exc.code})) from exc
        raise HTTPException(
            422,
            _problem_detail(
                "source_snapshot_invalid",
                str(exc),
                action="choose_approved_source",
                safe_details={"reason_code": "snapshot_boundary_rejected"},
            ),
        ) from exc

    project = db.scalar(select(Project).where(Project.repo_path == canonical_repo_path))
    if project is None:
        project = Project(
            name=payload.name,
            repo_path=canonical_repo_path,
            remote_url=None,
            default_branch="main",
        )
        try:
            db.add(project)
            db.flush()
            db.add(
                GatePolicy(
                    project_id=project.id,
                    **_gate_policy_values(_runtime_config_values(runtime.settings, db)),
                )
            )
            db.commit()
        except IntegrityError:
            db.rollback()
            project = db.scalar(
                select(Project).where(Project.repo_path == canonical_repo_path)
            )
            if project is None:
                raise
    db.refresh(project)
    return {
        "project": _project_to_out(project),
        "snapshot_digest": snapshot_digest,
        "directory_scope": payload.directory_scope,
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,159}\Z")
_REMOTE_ADVISOR_CONFIRMATION_CLIENT_ID = "advisor-confirmation:v1"


def _command_identity(request: Request) -> tuple[str, str]:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext):
        raise HTTPException(401, "authentication required")
    key = (request.headers.get("Idempotency-Key") or "").strip()
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise HTTPException(
            422,
            "Idempotency-Key must contain 8-160 ASCII letters, digits, '.', '_', ':', or '-'",
        )
    return f"{context.kind}:{context.subject}"[:160], key


def _remote_advisor_confirmation_identity(
    confirmation: Mapping[str, Any],
) -> tuple[str, str]:
    """Bind one signed disclosure confirmation to one durable command.

    A caller-supplied idempotency key scopes ordinary commands to that caller.
    Remote disclosure authorization is stricter: the server-issued identity in
    its digest-bound confirmation is a global, single-use capability. Putting
    that identity in the existing durable jobs uniqueness namespace closes both
    fresh-key replay and concurrent admission without process-local state.
    """

    authorization_id = str(confirmation["authorization_id"])
    return (
        _REMOTE_ADVISOR_CONFIRMATION_CLIENT_ID,
        f"remote-advisor-authorization:{authorization_id}",
    )


def _request_digest(payload: Any, **route_values: Any) -> str:
    rendered = payload.model_dump(mode="json", exclude_none=False)
    if not isinstance(rendered, dict):
        raise HTTPException(422, "command payload must be an object")
    document = {**route_values, **rendered}
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _existing_command(
    db: Session,
    *,
    kind: str,
    client_id: str,
    idempotency_key: str,
    request_digest: str,
) -> Job | None:
    job = db.scalar(
        select(Job).where(
            Job.client_id == client_id,
            Job.kind == kind,
            Job.idempotency_key == durable_idempotency_key(idempotency_key),
        )
    )
    if job is not None and job.payload.get("request_digest") != request_digest:
        raise HTTPException(409, "Idempotency-Key is already bound to a different command")
    return job


def _advisor_snapshot(
    settings: Settings,
    values: dict[str, Any],
    *,
    db: Session | None = None,
    require_disclosure_consent: bool = False,
    required_provider_id: str | None = None,
    allow_remote_generation: bool = False,
) -> dict[str, Any]:
    collection = advisor_providers.normalize_collection(
        values.get("advisor_providers")
        if isinstance(values.get("advisor_providers"), dict)
        else advisor_providers.default_collection(settings)
    )
    consent_map = (
        advisor_providers.load_valid_consents(db, collection)
        if db is not None
        else {}
    )
    receipt_map = (
        advisor_providers.load_valid_receipts(db, collection)
        if db is not None
        else {}
    )
    consent: dict[str, Any] | None = None
    selected_id = required_provider_id
    if selected_id is None:
        public = advisor_providers.public_collection(
            collection, settings, consent_map, receipt_map
        )
        selected_id = public["resolution"]["provider_id"]
    if selected_id is not None:
        try:
            profile = advisor_providers.provider_by_id(collection, selected_id)
        except KeyError as exc:
            raise HTTPException(409, "the selected Advisor provider no longer exists") from exc
        if profile["transport"] in {"direct", "ssh"}:
            stored = consent_map.get(selected_id)
            if stored is not None:
                consent = stored
            elif require_disclosure_consent:
                raise HTTPException(
                    409,
                    _problem_detail(
                        "advisor_source_disclosure_consent_required",
                        "The active remote Advisor consent is missing or stale. Test and activate the exact provider again before running Advisor.",
                        action="activate_advisor_provider",
                        context={
                            "provider_id": selected_id,
                            "provider_config_revision": profile["config_revision"],
                        },
                        safe_details={
                            "provider_id": selected_id,
                            "current_revision": profile["config_revision"],
                            "transport": profile["transport"],
                        },
                    ),
                )
            if require_disclosure_consent and not allow_remote_generation:
                raise HTTPException(
                    409,
                    _problem_detail(
                        "advisor_remote_single_finding_required",
                        "Remote Advisor disclosure is available only for one explicitly confirmed finding at a time.",
                        action="preview_advisor_source_disclosure",
                        context={"provider_id": selected_id},
                        safe_details={
                            "provider_id": selected_id,
                            "transport": profile["transport"],
                            "reason_code": "single_finding_confirmation_required",
                        },
                    ),
                )
    return {
        "ai_mode": _normalize_ai_mode(str(values.get("ai_mode") or "off"), settings),
        "ollama_base_url": _normalize_ollama_base_url(values.get("ollama_base_url"), settings),
        "ollama_model": _normalize_ollama_model(str(values.get("ollama_model") or ""), settings),
        "ollama_thinking": bool(values.get("ollama_thinking")),
        "auto_triage_limit": _normalize_auto_triage_limit(values.get("auto_triage_limit"), settings),
        "advisor_providers": advisor_providers.job_collection_snapshot(collection),
        "advisor_provider_consent": consent,
        "advisor_provider_consents": consent_map,
        "advisor_provider_receipts": receipt_map,
    }


def _provider_job_pin(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider_id": profile["id"],
        "transport": profile["transport"],
        "provider_config_revision": profile["config_revision"],
        "provider_config_digest": profile["config_digest"],
        "model": profile["model"],
        "model_digest": profile["model_digest"],
    }


def _require_advisor_ai_admission(
    db: Session, settings: Settings
) -> dict[str, Any]:
    """Fence Advisor admission against the current durable AI mode."""

    lock_advisor_admission(db)
    persisted_mode = db.get(RuntimeConfig, "ai_mode")
    ai_mode = _normalize_ai_mode(
        persisted_mode.value if persisted_mode is not None else None,
        settings,
    )
    if ai_mode == "off":
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_disabled",
                "Advisor is disabled because AI mode is off; no Advisor job was queued.",
                action="enable_advisor",
                safe_details={"reason_code": "ai_mode_off"},
            ),
        )
    values = _runtime_config_values(settings, db)
    values["ai_mode"] = ai_mode
    return values


def _job_retry_requires_advisor_ai_admission(
    job_kind: str, job_payload: object
) -> bool:
    """Identify immutable job snapshots that can resume Advisor work."""

    scan_snapshot = scan_command_snapshot(job_kind, job_payload)
    return job_kind == "advisor" or (
        scan_snapshot is not None and scan_snapshot.use_ai
    )


def _resolve_pinned_local_advisor_for_enqueue(
    db: Session,
    settings: Settings,
    requested: AdvisorTriageProviderPin,
    *,
    scan_wide: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Resolve and fence the exact local provider in the enqueue transaction."""

    values = _require_advisor_ai_admission(db, settings)
    collection = advisor_providers.load_collection(db, settings, lock=True)
    requested_pin = requested.model_dump(mode="json")
    if collection.get("state_error") == advisor_providers.PROVIDER_STATE_CORRUPT:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_configuration_corrupt",
                "Advisor provider configuration is corrupt; no Advisor job was queued.",
                action="repair_advisor_provider_configuration",
                safe_details={
                    "reason_code": advisor_providers.PROVIDER_STATE_CORRUPT,
                },
            ),
        )
    if collection["revision"] != requested_pin["provider_collection_revision"]:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_selection_stale",
                "Advisor provider configuration changed after selection; no Advisor job was queued.",
                action="refresh_advisor_providers",
                safe_details={
                    "expected_revision": requested_pin["provider_collection_revision"],
                    "current_revision": collection["revision"],
                },
            ),
        )
    try:
        requested_profile = advisor_providers.provider_by_id(
            collection, requested_pin["provider_id"]
        )
    except KeyError as exc:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_selection_stale",
                "The selected Advisor provider no longer exists; no Advisor job was queued.",
                action="refresh_advisor_providers",
                safe_details={"provider_id": requested_pin["provider_id"]},
            ),
        ) from exc
    live_pin = {
        "provider_collection_revision": collection["revision"],
        **_provider_job_pin(requested_profile),
    }
    if requested_pin != live_pin:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_selection_stale",
                "The selected Advisor provider no longer matches its exact configuration; no Advisor job was queued.",
                action="refresh_advisor_providers",
                safe_details={
                    "provider_id": requested_profile["id"],
                    "current_revision": requested_profile["config_revision"],
                },
            ),
        )
    if requested_profile["transport"] in {"direct", "ssh"}:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_remote_single_finding_required",
                (
                    "Scan-wide remote Advisor disclosure is forbidden; choose one finding "
                    "and confirm its exact disclosure preview."
                    if scan_wide
                    else "Remote Advisor review requires one exact disclosure preview and confirmation."
                ),
                action="preview_advisor_source_disclosure",
                safe_details={
                    "provider_id": requested_profile["id"],
                    "transport": requested_profile["transport"],
                    "reason_code": "single_finding_confirmation_required",
                },
            ),
        )
    receipts = advisor_providers.load_valid_receipts(db, collection)
    public = advisor_providers.public_collection(collection, settings, {}, receipts)
    if (
        public["resolution"]["provider_id"] != requested_profile["id"]
        or public["resolution"]["transport"] != "local"
        or not requested_profile["enabled"]
    ):
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_not_executable",
                "No tested and currently executable local Advisor provider matches the exact selection.",
                action="test_advisor_provider",
                safe_details={
                    "provider_id": requested_profile["id"],
                    "reason_code": public["resolution"]["reason"]
                    or "no_executable_provider",
                },
            ),
        )
    values["advisor_providers"] = collection
    snapshot = _advisor_snapshot(
        settings,
        values,
        db=db,
        required_provider_id=requested_profile["id"],
    )
    return requested_profile, snapshot, live_pin


def _enqueue_or_conflict(db: Session, **values: Any) -> Job:
    try:
        return enqueue_job(db, **values).job
    except IdempotencyConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/v1/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), limit: int = 100) -> list[dict[str, Any]]:
    return [
        _project_to_out(project)
        for project in db.scalars(_statement_limit(select(Project).order_by(Project.id.desc()), limit))
    ]


@router.post("/v1/projects/resolve", response_model=ProjectOut)
def resolve_project(payload: ProjectResolve, db: Session = Depends(get_db)) -> dict[str, Any]:
    project = db.scalar(select(Project).where(Project.repo_path == payload.repo_path))
    if project is None:
        raise HTTPException(404, "project not found")
    return _project_to_out(project)


@router.get("/v1/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    return _project_to_out(project)


@router.get("/v1/projects/{project_id}/scans/latest", response_model=ScanOut)
def get_latest_project_scan(project_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    scan = db.scalar(
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.id.desc()).limit(1)
    )
    if scan is None:
        raise HTTPException(404, "project has no scans")
    return _scan_to_out(scan)


@router.delete("/v1/projects/{project_id}")
def delete_project(project_id: int, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    from .git_push_policy import guard_push_project_deletion
    guard_push_project_deletion(db, project)
    scan_ids = [scan.id for scan in db.scalars(select(Scan).where(Scan.project_id == project_id))]
    _reject_active_job_deletion(db, scan_ids)
    for scan_id in scan_ids:
        _delete_artifact_files(db, scan_id, runtime.settings)
    snapshot_source_id = (
        source_snapshot_project_source_id(project.repo_path)
        if is_source_snapshot_project(project.repo_path)
        else None
    )
    db.delete(project)
    db.commit()
    source_snapshots_deleted = 0
    if snapshot_source_id is not None:
        try:
            source_snapshots_deleted = delete_source_snapshots(
                runtime.settings,
                snapshot_source_id,
            )
        except SourceSnapshotError as exc:
            raise HTTPException(
                500,
                _problem_detail(
                    "source_snapshot_cleanup_failed",
                    "The project was deleted, but its local source snapshot cleanup needs recovery.",
                    action="review_recovery",
                    safe_details={"reason_code": "snapshot_cleanup_failed"},
                ),
            ) from exc
    return {
        "deleted": True,
        "project_id": project_id,
        "scans_deleted": len(scan_ids),
        "source_snapshots_deleted": source_snapshots_deleted,
    }


@router.post("/v1/scans", response_model=ScanOut, status_code=202)
def create_scan(
    payload: ScanCreate,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    client_id, idempotency_key = _command_identity(request)
    request_digest = _request_digest(payload)
    existing = _existing_command(
        db,
        kind="scan",
        client_id=client_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )
    if existing is not None:
        scan = db.get(Scan, existing.scan_id) if existing.scan_id else None
        if scan is None:
            raise HTTPException(409, "idempotent scan command no longer has its scan resource")
        return _scan_to_out(scan, existing)

    project = db.get(Project, payload.project_id)
    if not project:
        raise HTTPException(404, "project not found")
    source_snapshot = None
    if is_source_snapshot_project(project.repo_path):
        if payload.source_snapshot_digest is None:
            raise HTTPException(
                409,
                _problem_detail(
                    "source_snapshot_required",
                    "Choose Check Outgoing Commits in VS Code to capture an exact Git tree before scanning."
                    if source_snapshot_project_kind(project.repo_path) == "git-commit"
                    else "Refresh the selected native Windows source snapshot before scanning.",
                    action="choose_approved_source",
                    safe_details={"reason_code": "snapshot_digest_required"},
                ),
            )
        try:
            snapshot = inspect_source_snapshot(
                runtime.settings,
                payload.source_snapshot_digest,
                source_id=source_snapshot_project_source_id(project.repo_path),
                scan_target=(payload.target_path, payload.target_kind),
            )
            source_snapshot = ScanSourceSnapshotOut(
                kind=source_snapshot_project_kind(project.repo_path),
                source_id=snapshot.source_id,
                snapshot_digest=snapshot.snapshot_digest,
                directory_scope=snapshot.directory_scope,
                target_path=payload.target_path,
                target_kind=payload.target_kind,
                file_count=snapshot.file_count,
                total_bytes=snapshot.total_bytes,
            ).model_dump(mode="json")
            if any(
                path is not None and redact_text(path) != path
                for path in (snapshot.directory_scope, payload.target_path)
            ):
                raise SourceSnapshotError(
                    "The selected source path contains credential-shaped text; rename that path before scanning.",
                    code="unsafe_source_path",
                )
        except SourceSnapshotError as exc:
            raise HTTPException(
                422,
                _problem_detail(
                    "source_snapshot_invalid",
                    str(exc),
                    action="choose_approved_source",
                    safe_details={"reason_code": "snapshot_boundary_rejected"},
                ),
            ) from exc
    elif payload.source_snapshot_digest is not None:
        raise HTTPException(
            422,
            _problem_detail(
                "source_snapshot_not_allowed",
                "A mounted source cannot be replaced by a native Windows snapshot.",
                action="choose_approved_source",
                safe_details={"reason_code": "mounted_source_snapshot_forbidden"},
            ),
        )
    advisor_config = (
        _require_advisor_ai_admission(db, runtime.settings)
        if payload.use_ai is True
        else None
    )
    preflight = _scanner_preflight(db, runtime.settings)
    if payload.coverage == "complete":
        _require_scanner_verification_ready(preflight.get("cache_verification"))
    if (
        payload.preflight_revision is not None
        and payload.preflight_revision != preflight["revision"]
    ):
        raise HTTPException(
            409,
            _problem_detail(
                "scanner_preflight_changed",
                "Scanner readiness changed after it was reviewed.",
                action="refresh_scanner_preflight",
                context={
                    "expected_preflight_revision": payload.preflight_revision,
                    "current_preflight_revision": preflight["revision"],
                },
            ),
        )
    requested_tools = list(preflight["enabled_tool_ids"])
    ready_tools = list(preflight["ready_tool_ids"])
    blocked_tools = list(preflight["blocked_tools"])
    scanner_recovery_action = str(preflight["recommended_action"])
    runtime_repair_required = scanner_recovery_action == "repair_scanner_runtime"
    scanner_blocking_context = {
        "preflight_revision": preflight["revision"],
        "blocked_tool_ids": [tool["id"] for tool in blocked_tools],
        "required_component_ids": preflight["required_component_ids"],
        "preparation_available": preflight["preparation_available"],
        "preparation_blocking_reasons": [
            str(reason)
            for tool in blocked_tools
            for reason in tool.get("preparation_blocking_reasons", [])
        ][:8],
    }
    if not requested_tools:
        raise HTTPException(
            409,
            _problem_detail(
                "no_scanner_tools_enabled",
                "Enable at least one scanner tool before starting a scan.",
                action="enable_scanner",
                context={"preflight_revision": preflight["revision"]},
            ),
        )
    if payload.coverage == "complete" and blocked_tools:
        raise HTTPException(
            409,
            _problem_detail(
                (
                    "scanner_runtime_prerequisite_missing"
                    if runtime_repair_required
                    else "scanner_preparation_required"
                ),
                (
                    "Enabled scanners need a complete shipped runtime before a complete scan."
                    if runtime_repair_required
                    else "Enabled scanners are not ready for a complete scan."
                ),
                action=scanner_recovery_action,
                context=scanner_blocking_context,
            ),
        )
    if payload.coverage == "limited" and not ready_tools:
        raise HTTPException(
            409,
            _problem_detail(
                (
                    "scanner_runtime_prerequisite_missing"
                    if runtime_repair_required
                    else "scanner_preparation_required"
                ),
                (
                    "No enabled scanner has a complete shipped runtime for a limited scan."
                    if runtime_repair_required
                    else "No enabled scanner is ready for a limited scan."
                ),
                action=scanner_recovery_action,
                context=scanner_blocking_context,
            ),
        )
    enabled_tools = requested_tools if payload.coverage == "complete" else ready_tools
    scan = Scan(
        project_id=payload.project_id,
        mode=payload.mode,
        base_ref=payload.base_ref,
        head_ref=payload.head_ref,
        status="pending",
        gate_reasons=[],
        scanner_summary={},
    )
    db.add(scan)
    db.flush()
    active_config = advisor_config or _runtime_config_values(runtime.settings, db)
    # Advisor work is explicit per scan. Runtime configuration controls whether
    # the local Advisor is available, but must never opt an ordinary scan in.
    use_ai = payload.use_ai is True
    job_payload = {
        "v": 1,
        "operation": "scan",
        "request_digest": request_digest,
        "scan_id": scan.id,
        "target_path": payload.target_path,
        "target_kind": payload.target_kind,
        "source_snapshot_digest": payload.source_snapshot_digest,
        "use_ai": use_ai,
        "coverage": payload.coverage,
        "preflight_revision": preflight["revision"],
        "requested_tools": requested_tools,
        "enabled_tools": enabled_tools,
        "omitted_tools": blocked_tools if payload.coverage == "limited" else [],
        "advisor": _advisor_snapshot(
            runtime.settings,
            active_config,
            db=db,
            require_disclosure_consent=use_ai,
        ),
    }
    if source_snapshot is not None:
        job_payload["source_snapshot"] = source_snapshot
        job_payload["project_id"] = scan.project_id
    try:
        job = _enqueue_or_conflict(
            db,
            kind="scan",
            title=f"Scan #{scan.id}",
            client_id=client_id,
            idempotency_key=idempotency_key,
            payload=job_payload,
            scan_id=scan.id,
            external_run_id=str(uuid4()),
            max_attempts=3,
        )
        db.commit()
    except HTTPException as exc:
        db.rollback()
        # Concurrent exact submissions may both stage a scan before the unique
        # job insert arbitrates. Roll back the losing scan and return the
        # already-committed command when its client request is identical.
        existing = _existing_command(
            db,
            kind="scan",
            client_id=client_id,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        if existing is None:
            raise exc
        scan = db.get(Scan, existing.scan_id) if existing.scan_id else None
        if scan is None:
            raise HTTPException(409, "idempotent scan command no longer has its scan resource") from exc
        return _scan_to_out(scan, existing)
    db.refresh(scan)
    return _scan_to_out(scan, job)


@router.get("/v1/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), project_id: int | None = None, limit: int = 100,
               view: Literal["full", "history"] = "full") -> list[dict[str, Any]]:
    stmt = select(Scan).order_by(Scan.id.desc())
    if project_id:
        stmt = stmt.where(Scan.project_id == project_id)
    memo = _RedactionMemo()
    return [_scan_to_out(scan, redaction_memo=memo, history=view == "history")
            for scan in db.scalars(_statement_limit(stmt, limit))]


@router.delete("/v1/scans/{scan_id}")
def delete_scan(scan_id: int, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    _reject_active_job_deletion(db, [scan_id])
    _delete_artifact_files(db, scan_id, runtime.settings)
    findings_deleted = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0
    db.delete(scan)
    db.commit()
    return {"deleted": True, "scan_id": scan_id, "findings_deleted": int(findings_deleted)}


@router.get("/v1/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    jobs = list(db.scalars(select(Job).where(Job.scan_id == scan.id, Job.kind == "scan").limit(2)))
    if len(jobs) == 1:
        observed = _scan_to_out(scan, jobs[0])
        if observed["source_snapshot"] is not None:
            return observed
    return _scan_to_out(scan)


@router.get("/v1/scans/{scan_id}/summary", response_model=ScanSummaryOut)
def get_scan_summary(scan_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    # Hold a shared row lock while assembling the multi-query resource. Every
    # finding mutation also advances this scan row, so counts, gate state, and
    # both revisions belong to one committed snapshot rather than a mixture of
    # READ COMMITTED statements.
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update(read=True))
    if scan is None:
        raise HTTPException(404, "scan not found")
    total = int(db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0)
    suppressed = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.scan_id == scan_id, Finding.suppressed.is_(True)
            )
        )
        or 0
    )
    gate_exempt = int(
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.scan_id == scan_id,
                Finding.suppressed.is_(False),
                Finding.gate_exempt.is_(True),
            )
        )
        or 0
    )
    severity_counts = {
        str(severity or "info"): int(count or 0)
        for severity, count in db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id, Finding.suppressed.is_(False))
            .group_by(Finding.severity)
        ).all()
    }
    scanner_counts = {
        str(scanner or "unknown"): int(count or 0)
        for scanner, count in db.execute(
            select(Finding.scanner, func.count(Finding.id))
            .where(Finding.scan_id == scan_id, Finding.suppressed.is_(False))
            .group_by(Finding.scanner)
        ).all()
    }
    return {
        "scan": {
            "id": scan.id,
            "project_id": scan.project_id,
            "mode": _redacted_identity_text(scan.mode, 40),
            "status": _redacted_identity_text(scan.status, 40),
            "gate_decision": _redacted_optional_text(scan.gate_decision, 40),
            "gate_reasons": _redacted_reason_list(scan.gate_reasons),
            "error": _redacted_optional_text(scan.error),
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "duration_ms": scan.duration_ms,
        },
        "findings": {
            "total": total,
            "active": total - suppressed,
            "suppressed": suppressed,
            "gate_exempt": gate_exempt,
            "severity_counts": severity_counts,
            "scanner_counts": scanner_counts,
        },
        "revision": scan.revision,
        "findings_revision": scan.findings_revision,
    }


def _finding_filter_conditions(
    scan_id: int,
    *,
    file_path: str | None,
    severity: str | None,
    scanner: str | None,
    lifecycle_status: str | None,
) -> list[Any]:
    conditions: list[Any] = [Finding.scan_id == scan_id]
    if file_path is not None:
        if _normalized_finding_path(file_path) != file_path:
            raise HTTPException(422, "file_path must be an exact canonical project-relative POSIX path")
        conditions.append(Finding.file_path == file_path)
    if severity is not None:
        normalized = severity.lower()
        if normalized not in {"critical", "high", "medium", "low", "info"}:
            raise HTTPException(422, "severity filter is invalid")
        conditions.append(Finding.severity == normalized)
    if scanner is not None:
        if not scanner or scanner != scanner.strip():
            raise HTTPException(422, "scanner filter is invalid")
        conditions.append(Finding.scanner == scanner)
    if lifecycle_status is not None:
        if lifecycle_status not in {
            "open",
            "needs_review",
            "gate_exempt",
            "accepted_risk",
            "ignore",
            "false_positive",
            "fixed",
        }:
            raise HTTPException(422, "lifecycle_status filter is invalid")
        conditions.append(Finding.lifecycle_status == lifecycle_status)
    return conditions


def _finding_revision_conflict(scan: Scan) -> HTTPException:
    return HTTPException(
        409,
        {
            "code": "revision_conflict",
            "message": "findings changed after the selected manifest snapshot",
            "revision": scan.findings_revision,
        },
    )


def _invalid_finding_file_manifest() -> HTTPException:
    return HTTPException(
        500,
        {
            "code": "finding_file_manifest_invalid",
            "message": "persisted finding file aggregates are inconsistent",
        },
    )


def _invalid_finding_diagnostics() -> HTTPException:
    return HTTPException(
        500,
        {
            "code": "finding_diagnostics_invalid",
            "message": "persisted finding diagnostics are inconsistent",
        },
    )


@router.get(
    "/v1/scans/{scan_id}/finding-files",
    response_model=FindingFileManifestPageOut,
)
def list_finding_files(
    scan_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=_FINDING_CURSOR_MAX_CHARS),
) -> dict[str, Any]:
    # The scan row is the collection revision fence. Finding writers take its
    # update lock and advance findings_revision in the same transaction, so the
    # header, page identities, and aggregates below belong to one committed
    # snapshot even under PostgreSQL READ COMMITTED.
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update(read=True))
    if scan is None:
        raise HTTPException(404, "scan not found")

    after = 0
    if cursor is not None:
        decoded = _decode_finding_file_cursor(cursor)
        if decoded["s"] != scan_id:
            raise _invalid_finding_file_cursor(
                "finding file cursor does not match this scan"
            )
        if decoded["r"] != scan.findings_revision:
            raise HTTPException(
                409,
                {
                    "code": "cursor_stale",
                    "message": "findings changed after this cursor was issued; restart pagination",
                    "revision": scan.findings_revision,
                },
            )
        after = int(decoded["a"])

    total_findings, total_files = db.execute(
        select(
            func.count(Finding.id),
            func.count(func.distinct(Finding.file_path)),
        ).where(Finding.scan_id == scan_id)
    ).one()
    total_findings = int(total_findings or 0)
    total_files = int(total_files or 0)
    if (total_findings == 0) != (total_files == 0):
        raise _invalid_finding_file_manifest()

    first = aliased(Finding, name="finding_file_first")
    previous = aliased(Finding, name="finding_file_previous")
    first_rows = list(
        db.execute(
            select(first.file_path, first.scan_finding_number)
            .where(
                first.scan_id == scan_id,
                first.scan_finding_number > after,
                ~exists().where(
                    previous.scan_id == first.scan_id,
                    previous.file_path == first.file_path,
                    previous.scan_finding_number < first.scan_finding_number,
                ),
            )
            .order_by(first.scan_finding_number.asc())
            .limit(limit + 1)
        ).all()
    )
    has_more = len(first_rows) > limit
    page_rows = first_rows[:limit]
    page_paths = [str(row.file_path) for row in page_rows]
    first_numbers = [int(row.scan_finding_number) for row in page_rows]
    if (
        len(page_paths) != len(set(page_paths))
        or len(first_numbers) != len(set(first_numbers))
        or any(
            number < 1 or number > _FINDING_CURSOR_MAX_AFTER
            for number in first_numbers
        )
        or any(_normalized_finding_path(path) != path for path in page_paths)
        or len(page_paths) > total_files
    ):
        raise _invalid_finding_file_manifest()

    aggregate_by_path: dict[str, dict[str, Any]] = {}
    if page_paths:
        severity_columns = [
            func.sum(case((Finding.severity == severity, 1), else_=0)).label(
                f"severity_{severity}"
            )
            for severity in _FINDING_SEVERITIES
        ]
        lifecycle_columns = [
            func.sum(
                case((Finding.lifecycle_status == lifecycle, 1), else_=0)
            ).label(f"lifecycle_{lifecycle}")
            for lifecycle in _FINDING_LIFECYCLES
        ]
        aggregate_rows = db.execute(
            select(
                Finding.file_path.label("file_path"),
                func.count(Finding.id).label("total"),
                func.sum(case((Finding.suppressed.is_(False), 1), else_=0)).label(
                    "active"
                ),
                func.sum(case((Finding.suppressed.is_(True), 1), else_=0)).label(
                    "suppressed"
                ),
                func.sum(
                    case(
                        (
                            Finding.suppressed.is_(False)
                            & Finding.gate_exempt.is_(True),
                            1,
                        ),
                        else_=0,
                    )
                ).label("gate_exempt"),
                func.sum(
                    case(
                        (
                            Finding.suppressed.is_(False)
                            & Finding.gate_exempt.is_(False),
                            1,
                        ),
                        else_=0,
                    )
                ).label("blocking"),
                *severity_columns,
                *lifecycle_columns,
            )
            .where(Finding.scan_id == scan_id, Finding.file_path.in_(page_paths))
            .group_by(Finding.file_path)
        ).mappings()
        for row in aggregate_rows:
            path = str(row["file_path"])
            if path in aggregate_by_path:
                raise _invalid_finding_file_manifest()
            total = int(row["total"] or 0)
            active = int(row["active"] or 0)
            suppressed = int(row["suppressed"] or 0)
            gate_exempt = int(row["gate_exempt"] or 0)
            blocking = int(row["blocking"] or 0)
            severity_counts = {
                severity: int(row[f"severity_{severity}"] or 0)
                for severity in _FINDING_SEVERITIES
            }
            lifecycle_counts = {
                lifecycle: int(row[f"lifecycle_{lifecycle}"] or 0)
                for lifecycle in _FINDING_LIFECYCLES
            }
            if (
                total < 1
                or active + suppressed != total
                or gate_exempt + blocking != active
                or sum(severity_counts.values()) != total
                or sum(lifecycle_counts.values()) != total
                or suppressed
                != lifecycle_counts["ignore"]
                + lifecycle_counts["false_positive"]
                + lifecycle_counts["fixed"]
                or gate_exempt
                != lifecycle_counts["gate_exempt"]
                + lifecycle_counts["accepted_risk"]
                or blocking
                != lifecycle_counts["open"] + lifecycle_counts["needs_review"]
            ):
                raise _invalid_finding_file_manifest()
            aggregate_by_path[path] = {
                "file_path": path,
                "total": total,
                "active": active,
                "suppressed": suppressed,
                "gate_exempt": gate_exempt,
                "blocking": blocking,
                "severity_counts": severity_counts,
                "lifecycle_counts": lifecycle_counts,
            }
    if set(aggregate_by_path) != set(page_paths):
        raise _invalid_finding_file_manifest()

    items = []
    for path, first_number in zip(page_paths, first_numbers, strict=True):
        items.append(
            {
                **aggregate_by_path[path],
                "first_scan_finding_number": first_number,
            }
        )
    next_cursor = None
    if has_more and items:
        next_cursor = _encode_finding_file_cursor(
            scan_id=scan_id,
            findings_revision=scan.findings_revision,
            after=items[-1]["first_scan_finding_number"],
        )
    return {
        "scan": {
            "id": scan.id,
            "project_id": scan.project_id,
            "status": _redacted_identity_text(scan.status, 40),
            "gate_decision": _redacted_optional_text(scan.gate_decision, 40),
            "gate_reasons": _redacted_reason_list(scan.gate_reasons),
            "error": _redacted_optional_text(scan.error),
            "revision": scan.revision,
            "findings_revision": scan.findings_revision,
        },
        "total_findings": total_findings,
        "total_files": total_files,
        "items": items,
        "truncated": has_more,
        "next_cursor": next_cursor,
    }


@router.get(
    "/v1/scans/{scan_id}/finding-diagnostics",
    response_model=FindingDiagnosticPageOut,
)
def list_finding_diagnostics(
    scan_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=_FINDING_CURSOR_MAX_CHARS),
    file_path: str | None = Query(default=None, max_length=4096),
    severity: str | None = Query(default=None, max_length=30),
    scanner: str | None = Query(default=None, max_length=80),
    lifecycle_status: str | None = Query(default=None, max_length=40),
    expected_revision: int | None = Query(
        default=None, ge=1, le=_SQL_INTEGER_MAX
    ),
) -> dict[str, Any]:
    # Problems needs only immutable diagnostic coordinates and presentation
    # text. The shared scan lock fences those rows to the returned collection
    # revision without loading ORM findings or occurrence history.
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update(read=True))
    if scan is None:
        raise HTTPException(404, "scan not found")
    if expected_revision is not None and expected_revision != scan.findings_revision:
        raise _finding_revision_conflict(scan)
    conditions = _finding_filter_conditions(
        scan_id,
        file_path=file_path,
        severity=severity,
        scanner=scanner,
        lifecycle_status=lifecycle_status,
    )
    normalized_severity = severity.lower() if severity is not None else None
    filter_digest = _finding_filter_digest(
        file_path=file_path,
        severity=normalized_severity,
        scanner=scanner,
        lifecycle_status=lifecycle_status,
    )
    after = 0
    if cursor is not None:
        decoded = _decode_finding_diagnostic_cursor(cursor)
        if (
            decoded["s"] != scan_id
            or decoded["f"] != filter_digest
        ):
            raise _invalid_finding_diagnostic_cursor(
                "finding diagnostic cursor does not match this scan and filter set"
            )
        if decoded["r"] != scan.findings_revision:
            raise HTTPException(
                409,
                {
                    "code": "cursor_stale",
                    "message": "findings changed after this cursor was issued; restart pagination",
                    "revision": scan.findings_revision,
                },
            )
        after = int(decoded["a"])

    total = int(db.scalar(select(func.count(Finding.id)).where(*conditions)) or 0)
    if (
        total > _FINDING_CURSOR_MAX_AFTER
        or type(scan.id) is not int
        or not 1 <= scan.id <= _SQL_INTEGER_MAX
        or type(scan.findings_revision) is not int
        or not 1 <= scan.findings_revision <= _SQL_INTEGER_MAX
    ):
        raise _invalid_finding_diagnostics()
    fetched = list(
        db.execute(
            select(
                Finding.id,
                Finding.scan_finding_number,
                Finding.scanner,
                Finding.severity,
                Finding.file_path,
                Finding.start_line,
                Finding.start_column,
                Finding.end_line,
                Finding.end_column,
                Finding.message,
                Finding.revision,
            )
            .where(*conditions, Finding.scan_finding_number > after)
            .order_by(Finding.scan_finding_number.asc())
            .limit(limit + 1)
        ).mappings()
    )
    has_more = len(fetched) > limit
    page_rows = fetched[:limit]
    items: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    prior_ordinal = after
    for row in page_rows:
        finding_id = row["id"]
        ordinal = row["scan_finding_number"]
        finding_revision = row["revision"]
        path = row["file_path"]
        scanner_name = row["scanner"]
        severity_name = row["severity"]
        if (
            type(finding_id) is not int
            or not 1 <= finding_id <= _SQL_INTEGER_MAX
            or finding_id in seen_ids
            or type(ordinal) is not int
            or not prior_ordinal < ordinal <= _FINDING_CURSOR_MAX_AFTER
            or type(finding_revision) is not int
            or not 1 <= finding_revision <= _SQL_INTEGER_MAX
            or _normalized_finding_path(path) != path
            or not isinstance(scanner_name, str)
            or not scanner_name
            or severity_name not in _FINDING_SEVERITIES
            or not isinstance(row["message"], str)
        ):
            raise _invalid_finding_diagnostics()
        location = _normalized_finding_location(dict(row))
        items.append(
            {
                "id": finding_id,
                "scan_finding_number": ordinal,
                "display_id": _display_finding_id(scan_id, ordinal),
                "scanner": _redacted_identity_text(scanner_name, 80),
                "severity": severity_name,
                "file_path": path,
                **location,
                "message": _redacted_display_text(row["message"], 4000),
                "revision": finding_revision,
            }
        )
        seen_ids.add(finding_id)
        prior_ordinal = ordinal
    if len(items) > total:
        raise _invalid_finding_diagnostics()

    next_cursor = None
    if has_more and items:
        next_cursor = _encode_finding_diagnostic_cursor(
            scan_id=scan_id,
            findings_revision=scan.findings_revision,
            after=items[-1]["scan_finding_number"],
            filter_digest=filter_digest,
        )
    return {
        "scan_id": scan.id,
        "items": items,
        "total": total,
        "truncated": has_more,
        "next_cursor": next_cursor,
        "revision": scan.findings_revision,
    }


@router.get("/v1/scans/{scan_id}/findings", response_model=FindingPageOut)
def list_findings(
    scan_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=_FINDING_CURSOR_MAX_CHARS),
    anchor_scan_finding_number: int | None = Query(
        default=None, ge=1, le=_FINDING_CURSOR_MAX_AFTER
    ),
    file_path: str | None = Query(default=None, max_length=4096),
    severity: str | None = Query(default=None, max_length=30),
    scanner: str | None = Query(default=None, max_length=80),
    lifecycle_status: str | None = Query(default=None, max_length=40),
    expected_revision: int | None = Query(
        default=None, ge=1, le=_SQL_INTEGER_MAX
    ),
) -> dict[str, Any]:
    # Cursor identity and every emitted row must be bound to the same committed
    # findings revision. Writers advance the parent scan row transactionally.
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update(read=True))
    if scan is None:
        raise HTTPException(404, "scan not found")
    if expected_revision is not None and expected_revision != scan.findings_revision:
        raise _finding_revision_conflict(scan)
    if cursor is not None and anchor_scan_finding_number is not None:
        raise HTTPException(422, "cursor and anchor_scan_finding_number are mutually exclusive")
    conditions = _finding_filter_conditions(
        scan_id,
        file_path=file_path,
        severity=severity,
        scanner=scanner,
        lifecycle_status=lifecycle_status,
    )
    normalized_severity = severity.lower() if severity is not None else None
    filter_digest = _finding_filter_digest(
        file_path=file_path,
        severity=normalized_severity,
        scanner=scanner,
        lifecycle_status=lifecycle_status,
    )
    after = 0
    if cursor is not None:
        decoded = _decode_finding_cursor(cursor)
        if decoded["s"] != scan_id or decoded["f"] != filter_digest:
            raise _invalid_finding_cursor("finding cursor does not match this scan and filter set")
        if decoded["r"] != scan.findings_revision:
            raise HTTPException(
                409,
                {
                    "code": "cursor_stale",
                    "message": "findings changed after this cursor was issued; restart pagination",
                    "revision": scan.findings_revision,
                },
            )
        after = int(decoded["a"])
    elif anchor_scan_finding_number is not None:
        anchor_exists = db.scalar(
            select(func.count(Finding.id)).where(
                *conditions,
                Finding.scan_finding_number == anchor_scan_finding_number,
            )
        )
        if not anchor_exists:
            raise HTTPException(404, "anchor finding is not present under the active filters")
        position = int(
            db.scalar(
                select(func.count(Finding.id)).where(
                    *conditions,
                    Finding.scan_finding_number <= anchor_scan_finding_number,
                )
            )
            or 0
        )
        page_member_count = ((position - 1) % limit) + 1
        reverse_numbers = list(
            db.scalars(
                select(Finding.scan_finding_number)
                .where(
                    *conditions,
                    Finding.scan_finding_number <= anchor_scan_finding_number,
                )
                .order_by(Finding.scan_finding_number.desc())
                .limit(page_member_count)
            )
        )
        after = int(reverse_numbers[-1]) - 1

    total = int(db.scalar(select(func.count(Finding.id)).where(*conditions)) or 0)
    fetched = list(
        db.scalars(
            select(Finding)
            .where(*conditions, Finding.scan_finding_number > after)
            .order_by(Finding.scan_finding_number.asc())
            .limit(limit + 1)
        )
    )
    has_more = len(fetched) > limit
    items = fetched[:limit]
    ordinals = {item.id: item.scan_finding_number for item in items}
    occurrences = _finding_occurrence_metadata(db, items, ordinals)
    next_cursor = None
    if has_more and items:
        next_cursor = _encode_finding_cursor(
            scan_id=scan_id,
            findings_revision=scan.findings_revision,
            after=items[-1].scan_finding_number,
            filter_digest=filter_digest,
        )
    return {
        "items": [
            _finding_list_to_out(item, occurrences.get(item.id, {})) for item in items
        ],
        "total": total,
        "truncated": has_more,
        "next_cursor": next_cursor,
        "revision": scan.findings_revision,
    }


@router.get(
    "/v1/scans/{scan_id}/findings/{scan_finding_number}",
    response_model=FindingDetailOut,
)
def get_scan_local_finding(
    scan_id: int,
    scan_finding_number: int,
    expected_revision: int = Query(ge=1),
    expected_findings_revision: int = Query(ge=1),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    # Finding writers take an exclusive parent-scan lock before publication.
    # Holding its shared lock makes the collection revision and exact finding
    # read one coherent snapshot without reversing the writer lock order.
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .with_for_update(read=True, of=Scan)
    )
    if scan is None:
        raise HTTPException(
            404,
            _problem_detail(
                "scan_removed",
                "The scan no longer exists.",
                action="refresh_findings",
                context={"scan_id": scan_id},
            ),
        )
    if scan.findings_revision != expected_findings_revision:
        raise HTTPException(
            409,
            _problem_detail(
                "revision_conflict",
                "Findings changed after the selected collection snapshot.",
                action="refresh_findings",
                context={
                    "scan_id": scan_id,
                    "scan_finding_number": scan_finding_number,
                    "expected_findings_revision": expected_findings_revision,
                    "current_findings_revision": scan.findings_revision,
                },
            ),
        )
    finding = db.scalar(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.scan_finding_number == scan_finding_number,
        )
    )
    if finding is None:
        raise HTTPException(
            409,
            _problem_detail(
                "finding_removed",
                "The selected finding no longer exists in this scan.",
                action="refresh_findings",
                context={
                    "scan_id": scan_id,
                    "scan_finding_number": scan_finding_number,
                    "current_findings_revision": scan.findings_revision,
                },
            ),
        )
    if finding.revision != expected_revision:
        raise HTTPException(
            409,
            _problem_detail(
                "revision_conflict",
                "The selected finding changed after it was loaded.",
                action="refresh_findings",
                context={
                    "scan_id": scan_id,
                    "scan_finding_number": scan_finding_number,
                    "finding_id": finding.id,
                    "expected_revision": expected_revision,
                    "current_revision": finding.revision,
                    "current_findings_revision": scan.findings_revision,
                },
            ),
        )
    occurrence = _finding_occurrence_metadata(
        db, [finding], {finding.id: finding.scan_finding_number}
    ).get(finding.id, {})
    detail = _finding_to_out(finding, finding.scan_finding_number, occurrence)
    detail["findings_revision"] = scan.findings_revision
    return detail


@router.get("/v1/scans/{scan_id}/artifacts", response_model=list[ScanArtifactOut])
def list_scan_artifacts(scan_id: int, db: Session = Depends(get_db)) -> list[ScanArtifact]:
    return list(db.scalars(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id).order_by(ScanArtifact.scanner, ScanArtifact.artifact_type, ScanArtifact.id)))


@router.post("/v1/scans/{scan_id}/triage", response_model=JobOut, status_code=202)
def triage_scan(
    scan_id: int,
    payload: ScanTriageRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    client_id, idempotency_key = _command_identity(request)
    request_digest = _request_digest(payload, scan_id=scan_id)
    existing = _existing_command(
        db,
        kind="advisor",
        client_id=client_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )
    if existing is not None:
        return _job_to_out(db, existing)
    selected_profile, advisor_snapshot, live_pin = (
        _resolve_pinned_local_advisor_for_enqueue(
            db,
            runtime.settings,
            payload.advisor_provider_pin,
            scan_wide=True,
        )
    )
    if payload.model not in {None, "", selected_profile["model"]}:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_selection_stale",
                "Advisor command model does not match the exact selected provider.",
                action="refresh_advisor_providers",
                safe_details={"provider_id": selected_profile["id"]},
            ),
        )
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status not in ADVISOR_SCAN_STATUSES:
        raise HTTPException(409, "advisor triage requires a terminal scan with persisted findings")
    eligible_query = select(func.count(Finding.id)).where(
        Finding.scan_id == scan_id,
        Finding.suppressed.is_(False),
    )
    if not payload.include_existing:
        eligible_query = eligible_query.where(Finding.ai_verdict.is_(None))
    eligible_count = int(db.scalar(eligible_query) or 0)
    if eligible_count == 0:
        raise HTTPException(409, "advisor triage requires at least one eligible active finding")
    job = _enqueue_or_conflict(
        db,
        kind="advisor",
        title=f"Advisor triage for scan #{scan_id}",
        client_id=client_id,
        idempotency_key=idempotency_key,
        payload={
            "v": 1,
            "operation": "advisor_scan",
            "request_digest": request_digest,
            "scan_id": scan_id,
            "model": selected_profile["model"],
            "advisor_provider_collection_revision": live_pin[
                "provider_collection_revision"
            ],
            "advisor_provider_pin": advisor_providers.job_pin_snapshot(
                _provider_job_pin(selected_profile)
            ),
            "include_existing": payload.include_existing,
            "finding_ids": None,
            "limit": payload.limit,
            "advisor": advisor_snapshot,
        },
        scan_id=scan_id,
        max_attempts=3,
    )
    job.detail = _redacted_text(f"Queued advisor triage for {eligible_count} eligible active findings")
    db.commit()
    db.refresh(job)
    return _job_to_out(db, job)


def _delete_artifact_files(db: Session, scan_id: int, settings: Settings) -> None:
    del db  # Database rows are removed by the owning scan's cascade.
    delete_scan_artifact_tree(settings, scan_id)


def _download_chunks(content) -> Iterator[bytes]:
    try:
        while chunk := content.read(1024 * 1024):
            yield chunk
    finally:
        content.close()


def _artifact_content_response(
    artifact_id: int,
    *,
    disposition: str,
    runtime: Runtime,
    db: Session,
) -> StreamingResponse:
    artifact = db.get(ScanArtifact, artifact_id)
    if not artifact:
        raise HTTPException(404, "artifact not found")
    try:
        verified = prepare_artifact_download(artifact, runtime.settings)
    except ArtifactBoundaryError as exc:
        raise HTTPException(404, "artifact file is unavailable or no longer verified") from exc
    # The scanner-owned path is never exposed as a browser filename. A stable
    # ASCII product name works in managed Chrome/Safari profiles that do not
    # honor filename* alone, while the UTF-8 form preserves RFC 5987 behavior.
    browser_filename = f"lomo-codesecurity-scan-{artifact.scan_id}-syft.cyclonedx.json"
    return StreamingResponse(
        _download_chunks(verified.content),
        media_type="application/vnd.cyclonedx+json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f'{disposition}; filename="{browser_filename}"; '
                f"filename*=UTF-8''{quote(browser_filename, safe='')}"
            ),
            "Content-Length": str(verified.size_bytes),
        },
    )


@router.get("/v1/artifacts/{artifact_id}/open")
def open_artifact(artifact_id: int, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> StreamingResponse:
    return _artifact_content_response(
        artifact_id,
        disposition="inline",
        runtime=runtime,
        db=db,
    )


@router.get("/v1/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: int, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> StreamingResponse:
    return _artifact_content_response(
        artifact_id,
        disposition="attachment",
        runtime=runtime,
        db=db,
    )


@router.post("/v1/findings/bulk")
def bulk_findings(
    payload: FindingBulkAction,
    request: Request,
    response: Response,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding_ids = sorted(set(payload.finding_ids))
    if payload.action == "triage":
        response.status_code = 202
        client_id, idempotency_key = _command_identity(request)
        request_digest = _request_digest(payload, finding_ids=finding_ids)
        existing = _existing_command(
            db,
            kind="advisor",
            client_id=client_id,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        if existing is not None:
            return {
                "updated": 0,
                "deleted": 0,
                "job": _job_to_out(db, existing),
                "scan_ids": [existing.scan_id] if existing.scan_id is not None else [],
            }
        assert payload.advisor_provider_pin is not None
        selected_profile, advisor_snapshot, live_pin = (
            _resolve_pinned_local_advisor_for_enqueue(
                db,
                runtime.settings,
                payload.advisor_provider_pin,
                scan_wide=True,
            )
        )
        if payload.model not in {None, "", selected_profile["model"]}:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_provider_selection_stale",
                    "Advisor command model does not match the exact selected provider.",
                    action="refresh_advisor_providers",
                    safe_details={"provider_id": selected_profile["id"]},
                ),
            )
    finding_owners = list(
        db.execute(
            select(Finding.id, Finding.scan_id)
            .where(Finding.id.in_(finding_ids))
            .order_by(Finding.id.asc())
        )
    )
    if len(finding_owners) != len(finding_ids):
        found = {finding_id for finding_id, _scan_id in finding_owners}
        missing = [finding_id for finding_id in finding_ids if finding_id not in found]
        raise HTTPException(404, f"findings not found: {missing[:10]}")
    scan_ids = sorted({scan_id for _finding_id, scan_id in finding_owners})
    # Every writer locks parent scans in stable order before their findings.
    # This preserves atomic summary revisions without a Scan<->Finding deadlock.
    locked_scans = {
        scan.id: scan
        for scan in db.scalars(
            select(Scan)
            .where(Scan.id.in_(scan_ids))
            .order_by(Scan.id.asc())
            .with_for_update()
        )
    }
    if set(locked_scans) != set(scan_ids):
        raise HTTPException(404, "one or more finding scans no longer exist")
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.id.in_(finding_ids))
            .order_by(Finding.id.asc())
            .with_for_update()
        )
    )
    if len(findings) != len(finding_ids):
        found = {finding.id for finding in findings}
        missing = [finding_id for finding_id in finding_ids if finding_id not in found]
        raise HTTPException(404, f"findings not found: {missing[:10]}")
    expected_revisions = payload.expected_revisions
    if expected_revisions is None or set(expected_revisions) != set(finding_ids):
        raise HTTPException(
            422,
            "expected_revisions must contain exactly one revision for every selected finding",
        )
    stale = {
        finding.id: finding.revision
        for finding in findings
        if expected_revisions[finding.id] != finding.revision
    }
    if stale:
        raise HTTPException(
            409,
            {
                "code": "revision_conflict",
                "message": "one or more findings changed after they were loaded; refresh before retrying",
                "revisions": stale,
            },
        )
    if payload.action == "triage":
        if len(scan_ids) != 1:
            raise HTTPException(422, "bulk advisor triage requires findings from one scan")
        inactive_count = sum(1 for finding in findings if finding.suppressed)
        if inactive_count:
            raise HTTPException(409, "bulk advisor triage accepts active findings only")
        scan_id = scan_ids[0]
        scan = locked_scans.get(scan_id)
        if scan is None or scan.status not in ADVISOR_SCAN_STATUSES:
            raise HTTPException(409, "advisor triage requires a terminal scan with persisted findings")
        job = _enqueue_or_conflict(
            db,
            kind="advisor",
            title=f"Advisor triage for {len(findings)} selected findings",
            client_id=client_id,
            idempotency_key=idempotency_key,
            payload={
                "v": 1,
                "operation": "advisor_scan",
                "request_digest": request_digest,
                "scan_id": scan_id,
                "model": selected_profile["model"],
                "advisor_provider_collection_revision": live_pin[
                    "provider_collection_revision"
                ],
                "advisor_provider_pin": advisor_providers.job_pin_snapshot(
                    _provider_job_pin(selected_profile)
                ),
                "include_existing": True,
                "finding_ids": finding_ids,
                "expected_revisions": {
                    str(finding.id): expected_revisions[finding.id]
                    for finding in findings
                },
                "limit": None,
                "advisor": advisor_snapshot,
            },
            scan_id=scan_id,
            max_attempts=3,
        )
        job.detail = _redacted_text(f"Queued advisor triage for {len(findings)} selected findings")
        db.commit()
        db.refresh(job)
        return {"updated": 0, "deleted": 0, "job": _job_to_out(db, job), "scan_ids": scan_ids}

    if payload.action == "delete":
        _reject_active_job_deletion(db, scan_ids)
        for finding in findings:
            db.delete(finding)
        db.flush()
        for scan_id in scan_ids:
            scan = locked_scans.get(scan_id)
            if scan:
                _refresh_scan_finding_summary(db, scan)
        db.commit()
        return {"updated": 0, "deleted": len(findings), "scan_ids": scan_ids}

    for finding in findings:
        _apply_finding_lifecycle(finding, payload.action, payload.reason)
        db.add(finding)
    db.flush()
    for scan_id in scan_ids:
        scan = locked_scans.get(scan_id)
        if scan:
            _refresh_scan_finding_summary(db, scan)
    db.commit()
    return {"updated": len(findings), "deleted": 0, "scan_ids": scan_ids}


@router.get("/v1/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "finding not found")
    ordinals = {finding.id: finding.scan_finding_number}
    occurrences = _finding_occurrence_metadata(db, [finding], ordinals)
    return _finding_to_out(
        finding, finding.scan_finding_number, occurrences.get(finding.id, {})
    )


@router.get("/v1/findings/{finding_id}/packet")
def get_packet(finding_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "finding not found")
    scan = db.get(Scan, finding.scan_id)
    project = db.get(Project, scan.project_id) if scan else None
    if not scan or not project:
        raise HTTPException(404, "finding context not found")
    return _finding_packet(finding, scan, project, _finding_display_label(db, finding))


@router.post(
    "/v1/findings/{finding_id}/advisor-disclosure-preview",
    response_model=AdvisorDisclosurePreviewOut,
)
def preview_finding_advisor_disclosure(
    finding_id: int,
    payload: AdvisorDisclosurePreviewRequest,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Describe and hash the exact remote payload without transmitting it."""

    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    scan = db.get(Scan, finding.scan_id)
    project = db.get(Project, scan.project_id) if scan is not None else None
    if scan is None or project is None:
        raise HTTPException(404, "finding context not found")
    if finding.revision != payload.expected_revision:
        raise HTTPException(
            409,
            _problem_detail(
                "revision_conflict",
                "The selected finding changed before disclosure preview.",
                action="refresh_findings",
                context={
                    "finding_id": finding.id,
                    "expected_revision": payload.expected_revision,
                    "current_revision": finding.revision,
                },
                safe_details={
                    "expected_revision": payload.expected_revision,
                    "current_revision": finding.revision,
                },
            ),
        )
    if finding.suppressed or scan.status not in ADVISOR_SCAN_STATUSES:
        raise HTTPException(409, "Advisor disclosure preview requires one active terminal finding")
    collection = advisor_providers.load_collection(db, runtime.settings)
    provider_id = payload.provider_id or collection["active_provider_id"]
    if provider_id is None:
        raise HTTPException(409, "no remote Advisor provider is active")
    try:
        profile = advisor_providers.provider_by_id(collection, provider_id)
    except KeyError as exc:
        raise HTTPException(404, "advisor provider not found") from exc
    if profile["transport"] == "local":
        raise HTTPException(409, "the active Advisor route is local and needs no remote disclosure")
    if collection["active_provider_id"] != provider_id or profile["status"] != "active":
        raise HTTPException(409, "the remote Advisor provider is not currently active")
    if provider_id not in advisor_providers.authorized_provider_ids(
        runtime.settings, collection
    ):
        raise HTTPException(409, "the remote Advisor provider is not authorized")
    consent = advisor_providers.load_consent(db, provider_id)
    receipt = advisor_providers.load_receipt(db, provider_id)
    if not advisor_providers.receipt_matches(profile, receipt):
        raise HTTPException(409, "the remote Advisor provider has no current exact test receipt")
    packet = _finding_packet(
        finding, scan, project, _finding_display_label(db, finding)
    )
    try:
        confirmation = advisor_disclosure.build_confirmation(
            collection,
            profile,
            consent or {},
            finding_id=finding.id,
            finding_revision=finding.revision,
            packet=packet,
            signing_key=runtime.settings.installation_secret,
        )
        return {
            "confirmation": confirmation,
            "packet": packet,
            "packet_utf8_bytes": advisor_disclosure.packet_utf8_bytes(packet),
        }
    except ValueError as exc:
        raise HTTPException(409, "remote Advisor consent is missing or stale") from exc


@router.post("/v1/findings/{finding_id}/triage", response_model=JobOut, status_code=202)
def triage_finding(
    finding_id: int,
    payload: TriageRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    client_id, idempotency_key = _command_identity(request)
    request_digest = _request_digest(payload, finding_id=finding_id)
    selected_profile: dict[str, Any] | None = None
    advisor_snapshot: dict[str, Any] | None = None
    live_pin: dict[str, Any] | None = None
    remote_confirmation_document: dict[str, Any] | None = None
    submitted_confirmation = payload.remote_advisor_confirmation
    if submitted_confirmation is not None:
        try:
            remote_confirmation_document = (
                advisor_disclosure.verify_confirmation_signature(
                    submitted_confirmation.model_dump(mode="json", by_alias=True),
                    runtime.settings.installation_secret,
                )
            )
        except ValueError as exc:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_source_disclosure_confirmation_stale",
                    "The remote Advisor preview is malformed or no longer current.",
                    action="preview_advisor_source_disclosure",
                    context={"finding_id": finding_id},
                ),
            ) from exc
        client_id, idempotency_key = _remote_advisor_confirmation_identity(
            remote_confirmation_document
        )
        # Provider mutations take this same transaction-scoped lock. Acquire it
        # before scan/finding row locks so admission has one global lock order.
        lock_advisor_admission(db)
    existing = _existing_command(
        db,
        kind="advisor",
        client_id=client_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )
    if existing is not None:
        return _job_to_out(db, existing)
    if submitted_confirmation is not None:
        _require_advisor_ai_admission(db, runtime.settings)
    if payload.remote_advisor_confirmation is None:
        assert payload.advisor_provider_pin is not None
        selected_profile, advisor_snapshot, live_pin = (
            _resolve_pinned_local_advisor_for_enqueue(
                db,
                runtime.settings,
                payload.advisor_provider_pin,
                scan_wide=False,
            )
        )
        if payload.model not in {None, "", selected_profile["model"]}:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_provider_selection_stale",
                    "Advisor command model does not match the exact selected provider.",
                    action="refresh_advisor_providers",
                    safe_details={"provider_id": selected_profile["id"]},
                ),
            )
    finding_scan_id = db.scalar(
        select(Finding.scan_id).where(Finding.id == finding_id)
    )
    if finding_scan_id is None:
        raise HTTPException(
            404,
            _problem_detail(
                "finding_removed",
                "The selected finding no longer exists.",
                action="refresh_findings",
                context={"finding_id": finding_id},
            ),
        )
    # Writers lock the parent scan before its findings so concurrent summary,
    # lifecycle, and Advisor operations cannot deadlock on opposite lock order.
    scan = db.scalar(
        select(Scan).where(Scan.id == finding_scan_id).with_for_update()
    )
    finding = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id, Finding.scan_id == finding_scan_id)
        .with_for_update()
    )
    if finding is None:
        raise HTTPException(
            404,
            _problem_detail(
                "finding_removed",
                "The selected finding no longer exists.",
                action="refresh_findings",
                context={"finding_id": finding_id},
            ),
        )
    if finding.revision != payload.expected_revision:
        raise HTTPException(
            409,
            _problem_detail(
                "revision_conflict",
                "The selected finding changed after it was loaded.",
                action="refresh_findings",
                context={
                    "finding_id": finding.id,
                    "expected_revision": payload.expected_revision,
                    "current_revision": finding.revision,
                },
            ),
        )
    if finding.suppressed:
        raise HTTPException(
            409,
            _problem_detail(
                "finding_changed",
                "Advisor review accepts active findings only.",
                action="refresh_findings",
                context={"finding_id": finding.id, "current_revision": finding.revision},
            ),
        )
    if scan is None or scan.status not in ADVISOR_SCAN_STATUSES:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_scan_not_terminal",
                "Advisor review requires a terminal scan with persisted findings.",
                action="refresh_scan",
                context={"scan_id": finding.scan_id},
            ),
        )
    collection = advisor_providers.load_collection(
        db, runtime.settings, lock=submitted_confirmation is not None
    )
    if collection.get("state_error") == advisor_providers.PROVIDER_STATE_CORRUPT:
        raise HTTPException(
            409,
            _problem_detail(
                "advisor_provider_configuration_corrupt",
                "Advisor provider configuration is corrupt; no Advisor job was queued.",
                action="repair_advisor_provider_configuration",
                context={"finding_id": finding.id},
                safe_details={
                    "reason_code": advisor_providers.PROVIDER_STATE_CORRUPT,
                    "current_revision": finding.revision,
                },
            ),
        )
    consents = advisor_providers.load_valid_consents(db, collection)
    receipts = advisor_providers.load_valid_receipts(db, collection)
    if submitted_confirmation is not None:
        assert remote_confirmation_document is not None
        document = remote_confirmation_document
        provider_id = document["provider_id"]
        try:
            profile = advisor_providers.provider_by_id(collection, provider_id)
        except KeyError as exc:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_source_disclosure_confirmation_stale",
                    "The confirmed remote Advisor provider no longer exists.",
                    action="preview_advisor_source_disclosure",
                    context={"finding_id": finding.id, "provider_id": provider_id},
                    safe_details={"provider_id": provider_id, "current_revision": finding.revision},
                ),
            ) from exc
        project = db.get(Project, scan.project_id)
        if project is None:
            raise HTTPException(404, "finding context not found")
        packet = _finding_packet(
            finding, scan, project, _finding_display_label(db, finding)
        )
        consent = consents.get(provider_id)
        current = bool(
            profile["transport"] in {"direct", "ssh"}
            and profile["status"] == "active"
            and collection["active_provider_id"] == provider_id
            and provider_id
            in advisor_providers.authorized_provider_ids(
                runtime.settings, collection
            )
            and advisor_providers.receipt_matches(
                profile, receipts.get(provider_id)
            )
            and consent is not None
            and advisor_disclosure.confirmation_matches(
                collection,
                profile,
                consent,
                document,
                finding_id=finding.id,
                finding_revision=finding.revision,
                packet=packet,
            )
        )
        if not current:
            raise HTTPException(
                409,
                _problem_detail(
                    "advisor_source_disclosure_confirmation_stale",
                    "The remote Advisor preview no longer matches the exact provider, receipt, consent, or finding revision.",
                    action="preview_advisor_source_disclosure",
                    context={"finding_id": finding.id, "provider_id": provider_id},
                    safe_details={"provider_id": provider_id, "current_revision": finding.revision},
                ),
            )
        if payload.model not in {None, "", profile["model"]}:
            raise HTTPException(409, "Advisor command model does not match the confirmed provider pin")
        selected_profile = profile
        values = _runtime_config_values(runtime.settings, db)
        values["advisor_providers"] = collection
        advisor_snapshot = _advisor_snapshot(
            runtime.settings,
            values,
            db=db,
            require_disclosure_consent=True,
            required_provider_id=provider_id,
            allow_remote_generation=True,
        )
        live_pin = {
            "provider_collection_revision": collection["revision"],
            **_provider_job_pin(profile),
        }
    label = _finding_display_label(db, finding) or f"DB finding #{finding.id}"
    assert selected_profile is not None
    assert advisor_snapshot is not None
    assert live_pin is not None
    job = _enqueue_or_conflict(
        db,
        kind="advisor",
        title=(
            f"Remote Advisor triage for {label}"
            if remote_confirmation_document is not None
            else f"Advisor triage for {label}"
        ),
        client_id=client_id,
        idempotency_key=idempotency_key,
        payload={
            "v": 1,
            "operation": "advisor_finding",
            "request_digest": request_digest,
            "scan_id": finding.scan_id,
            "finding_id": finding.id,
            "model": _normalize_ollama_model(
                payload.model
                or (
                    selected_profile["model"]
                    if selected_profile is not None
                    else runtime.settings.ollama_model
                ),
                runtime.settings,
            ),
            "advisor_provider_collection_revision": live_pin[
                "provider_collection_revision"
            ],
            "advisor_provider_pin": advisor_providers.job_pin_snapshot(
                _provider_job_pin(selected_profile)
            ),
            "remote_advisor_confirmation": remote_confirmation_document,
            "advisor_operation_id": (
                uuid4().hex if remote_confirmation_document is not None else None
            ),
            "include_existing": True,
            "finding_ids": [finding.id],
            "expected_revisions": {str(finding.id): finding.revision},
            "limit": 1,
            "advisor": advisor_snapshot,
        },
        scan_id=finding.scan_id,
        finding_id=finding.id,
        max_attempts=3,
    )
    db.commit()
    db.refresh(job)
    return _job_to_out(db, job)


@router.patch("/v1/findings/{finding_id}/lifecycle", response_model=FindingOut)
def update_finding_lifecycle(finding_id: int, payload: FindingLifecycleUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding_scan_id = db.scalar(
        select(Finding.scan_id).where(Finding.id == finding_id)
    )
    if finding_scan_id is None:
        raise HTTPException(404, "finding not found")
    scan = db.scalar(
        select(Scan).where(Scan.id == finding_scan_id).with_for_update()
    )
    if scan is None:
        raise HTTPException(404, "finding context not found")
    finding = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id, Finding.scan_id == finding_scan_id)
        .with_for_update()
    )
    if not finding:
        raise HTTPException(404, "finding not found")
    if finding.revision != payload.expected_revision:
        raise HTTPException(
            409,
            {
                "code": "revision_conflict",
                "message": "finding changed after it was loaded; refresh before retrying",
                "revision": finding.revision,
            },
        )
    _apply_finding_lifecycle(finding, payload.action, payload.reason)
    db.add(finding)
    db.flush()
    _refresh_scan_finding_summary(db, scan)
    db.commit()
    db.refresh(finding)
    ordinals = {finding.id: finding.scan_finding_number}
    occurrences = _finding_occurrence_metadata(db, [finding], ordinals)
    return _finding_to_out(
        finding, finding.scan_finding_number, occurrences.get(finding.id, {})
    )


@router.delete("/v1/findings/{finding_id}")
def delete_finding(
    finding_id: int,
    expected_revision: int = Query(ge=1),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding_scan_id = db.scalar(
        select(Finding.scan_id).where(Finding.id == finding_id)
    )
    if finding_scan_id is None:
        raise HTTPException(404, "finding not found")
    scan = db.scalar(
        select(Scan).where(Scan.id == finding_scan_id).with_for_update()
    )
    if scan is None:
        raise HTTPException(404, "finding context not found")
    finding = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id, Finding.scan_id == finding_scan_id)
        .with_for_update()
    )
    if not finding:
        raise HTTPException(404, "finding not found")
    if finding.revision != expected_revision:
        raise HTTPException(
            409,
            {
                "code": "revision_conflict",
                "message": "finding changed after it was loaded; refresh before retrying",
                "revision": finding.revision,
            },
        )
    scan_id = finding_scan_id
    _reject_active_job_deletion(db, [scan_id])
    db.delete(finding)
    db.flush()
    _refresh_scan_finding_summary(db, scan)
    db.commit()
    return {"deleted": True, "finding_id": finding_id, "scan_id": scan_id}


@router.get("/v1/jobs", response_model=list[JobOut])
def list_jobs(db: Session = Depends(get_db), status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    stmt = select(Job).order_by(Job.id.desc())
    if status == "active":
        stmt = stmt.where(Job.status.in_(ACTIVE_JOB_STATUSES))
    elif status:
        stmt = stmt.where(Job.status == status)
    return [_job_to_out(db, job) for job in db.scalars(_statement_limit(stmt, limit))]


@router.get("/v1/jobs/{job_id}", response_model=JobOut)
def get_job(
    job_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "job not found")
    _authorize_ide_job_access(request, job)
    return _job_to_out(db, job)


@router.post("/v1/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(
    job_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    existing_job = db.get(Job, job_id)
    if existing_job is None:
        raise HTTPException(404, "job not found")
    _authorize_ide_job_access(request, existing_job)
    try:
        result = request_cancellation(
            db,
            job_id,
            detail="Cancellation requested; waiting for worker cleanup confirmation.",
        )
    except JobNotFoundError as exc:
        raise HTTPException(404, "job not found") from exc
    except CacheCommitInProgressError as exc:
        raise HTTPException(409, _problem_detail(
            "cache_commit_in_progress",
            "Scanner data activation is being committed and can no longer be cancelled. Refresh the job to see its result.",
            action="refresh_job",
        )) from exc
    lifecycle_scope = {
        "scanner_catalog_check": "catalog",
        "scanner_cache_update": "cache",
        "scanner_cache_rollback": "cache",
        "scanner_cache_reconcile": "cache",
    }.get(result.job.kind)
    if lifecycle_scope is not None and result.changed:
        state = _require_scanner_lifecycle_state(db, lifecycle_scope)
        if state.job_id == result.job.id:
            state.status = "cancelling"
            state.updated_at = _utcnow()
            state.revision += 1
            db.add(state)
    db.commit()
    db.refresh(result.job)
    return _job_to_out(db, result.job)


def _authorize_ide_job_access(request: Request, job: Job) -> None:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "ide":
        return
    if job.kind not in {"scan", "advisor"} or job.client_id != f"ide:{context.subject}":
        raise HTTPException(403, "IDE capability cannot access this job")


_RECONCILIATION_PREVIEW_SECONDS = 5.0


async def _updater_reconciliation_preview_async(settings: Settings, original: Job, clock: PreparationClock) -> dict[str, Any]:
    """One absolute response clock; timeout cancels and closes owned async I/O."""
    bound = clock.remaining(min(settings.worker_updater_request_seconds, _RECONCILIATION_PREVIEW_SECONDS))
    async with asyncio.timeout(bound):
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
            async with client.stream(
                "GET", f"{settings.scanner_updater_url.rstrip('/')}/operations/{original.external_run_id}/reconciliation-preview",
                headers={"X-KodeSec-Request-Digest": original.payload["request_digest"], "Accept-Encoding": "identity"},
                timeout=bound,
            ) as response:
                if response.status_code == 409:
                    raise HTTPException(409, _problem_detail(
                        "scanner_reconciliation_target_changed", "The published outcome changed; refresh before reconciling."))
                if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("updater preview unavailable")
                declared = response.headers.get("content-length")
                if declared is not None and not 0 <= int(declared) <= 4096:
                    raise ValueError("updater preview exceeds bound")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    clock.remaining(5.0)
                    if len(chunk) > 4096 - len(body):
                        raise ValueError("updater preview exceeds bound")
                    body.extend(chunk)
        clock.remaining(5.0)
        value = json.loads(body)
        if not isinstance(value, dict) or set(value) != {
            "operation_id", "request_digest", "attempt", "record_sha256", "pointer_sha256", "active"
        }:
            raise ValueError("updater preview differs from schema")
        return value


def _updater_reconciliation_preview(settings: Settings, original: Job, clock: PreparationClock) -> dict[str, Any]:
    try:
        return asyncio.run(_updater_reconciliation_preview_async(settings, original, clock))
    except HTTPException:
        raise
    except (httpx.RequestError, ValueError, TimeoutError, PreparationDeadlineExceeded) as exc:
        raise HTTPException(503, _problem_detail(
            "scanner_updater_unavailable", "The updater could not provide a bounded recovery target.")) from exc


@router.post("/v1/jobs/{job_id}/reconcile", response_model=ScannerReconciliationCommandOut, status_code=202)
def reconcile_scanner_cache_job(
    job_id: int,
    payload: JobReconcileRequest,
    request: Request,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "browser":
        raise HTTPException(403, "cache outcome reconciliation requires browser authorization")
    client_id, key = _command_identity(request)
    state = _lock_scanner_lifecycle_state(db, "cache")
    prior = db.scalar(select(Job).where(
        Job.client_id == client_id, Job.kind == "scanner_cache_reconcile",
        Job.idempotency_key == durable_idempotency_key(key),
    ))
    if prior is not None:
        try:
            if not isinstance(prior.payload, dict):
                raise ValueError("recovery payload is not an object")
            target = RecoveryTarget.model_validate(prior.payload.get("reconciliation_target"))
            budget = RecoveryBudget.model_validate(prior.payload.get("reconciliation_budget"))
            if (prior.payload.get("request_digest") != recovery_digest(budget, target)
                    or prior.payload.get("operation") != "cache_reconcile"
                    or prior.payload.get("component_ids") != [] or prior.max_attempts != 1):
                raise ValueError("recovery replay digest differs")
        except (ValueError, TypeError) as exc:
            raise HTTPException(409, _problem_detail(
                "scanner_reconciliation_target_changed", "Stored recovery binding is invalid.")) from exc
        if target.original_job_id != job_id or target.original_job_revision != payload.expected_revision:
            raise HTTPException(409, _problem_detail("job_revision_changed", "Recovery command identity changed."))
        return {"job": _job_to_out(db, prior), "lifecycle": _scanner_lifecycle_scope_out(db, state),
                "original_job_id": job_id}
    original = db.scalar(select(Job).where(Job.id == job_id).with_for_update(of=Job))
    if original is None:
        raise HTTPException(404, "job not found")
    if original.revision != payload.expected_revision:
        raise HTTPException(409, _problem_detail("job_revision_changed", "Reload the original job before reconciling."))
    if (not _can_reconcile_cache_job(original)
            or not original.external_run_id or not isinstance(original.payload, dict)
            or original.attempt < 1 or original.payload.get("preparation_budget") is None):
        raise HTTPException(409, _problem_detail(
            "scanner_reconciliation_not_available", "This job has no uncertain published cache outcome."))
    try:
        original_budget = PreparationBudget.model_validate(original.payload["preparation_budget"])
        components = original.payload.get("component_ids")
        if (str(UUID(original.external_run_id)) != original.external_run_id
                or not isinstance(components, list) or not components
                or any(not isinstance(item, str) for item in components)
                or components != sorted(set(components))
                or set(components) - set(get_args(ScannerCacheComponentId))
                or original.payload.get("request_digest") != _scanner_lifecycle_digest(
                    "cache_update", components, original.payload.get("catalog_digest"), original_budget)):
            raise ValueError("original operation command differs")
    except (ValueError, TypeError) as exc:
        raise HTTPException(409, _problem_detail(
            "scanner_reconciliation_not_available", "The original immutable command is invalid.")) from exc
    active = db.get(Job, state.job_id) if state.job_id is not None else None
    if active is not None and active.status in ACTIVE_JOB_STATUSES:
        raise HTTPException(409, _problem_detail(
            "scanner_reconciliation_active", "A cache lifecycle command is already active."))
    budget = issue_recovery_budget()
    clock = PreparationClock(budget)
    preview = _updater_reconciliation_preview(runtime.settings, original, clock)
    try:
        target = RecoveryTarget.model_validate({**preview, "original_job_id": original.id,
                                               "original_job_revision": original.revision})
        # Reclaiming an expired worker lease advances the job attempt without
        # restarting an updater already at the non-cancellable commit point.
        # Bind the exact observed updater attempt; it may precede the worker's
        # attempt, but cannot come from a future execution of this command.
        if (target.operation_id != original.external_run_id
                or target.request_digest != original.payload.get("request_digest")
                or target.attempt > original.attempt):
            raise ValueError("original identity differs")
        clock.remaining(5.0)
    except (ValueError, PreparationDeadlineExceeded) as exc:
        raise HTTPException(409, _problem_detail(
            "scanner_reconciliation_target_changed", "The original operation binding changed.")) from exc
    job = _enqueue_or_conflict(
        db, kind="scanner_cache_reconcile", title="Reconcile cache outcome",
        client_id=client_id, idempotency_key=key, external_run_id=str(uuid4()), max_attempts=1,
        payload={"v": 1, "operation": "cache_reconcile", "component_ids": [],
                 "request_digest": recovery_digest(budget, target),
                 "reconciliation_budget": budget.model_dump(mode="json"),
                 "reconciliation_target": target.model_dump(mode="json")},
    )
    state.status, state.job_id = "queued", job.id
    state.receipt, state.error_code, state.error_detail = {}, None, None
    state.started_at, state.completed_at = None, None
    state.updated_at = _utcnow()
    state.revision += 1
    db.add(state)
    db.commit()
    db.refresh(job)
    return {"job": _job_to_out(db, job), "lifecycle": _scanner_lifecycle_scope_out(db, state),
            "original_job_id": original.id}


@router.post("/v1/jobs/{job_id}/retry", response_model=JobOut)
def retry_job(
    job_id: int,
    payload: JobRetryRequest,
    runtime: Runtime = Depends(get_runtime),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    # Job kind and payload are immutable. Read their command snapshot without a
    # row lock so every retry that can resume Advisor work follows the shared
    # admission-lock-before-job-row order used by new admissions.
    job_snapshot = db.execute(
        select(Job.kind, Job.payload).where(Job.id == job_id)
    ).one_or_none()
    if job_snapshot is not None:
        if job_snapshot.kind == "scanner_cache_update" or (
            job_snapshot.kind == "scanner_catalog_check"
            and isinstance(job_snapshot.payload, dict)
            and "preparation" in job_snapshot.payload
        ):
            _require_scanner_verification_ready(
                _scanner_runtime_snapshot(runtime.settings).cache_verification
            )
        try:
            requires_advisor = _job_retry_requires_advisor_ai_admission(
                job_snapshot.kind, job_snapshot.payload
            )
        except InvalidScanCommandSnapshot as exc:
            raise HTTPException(
                409,
                _problem_detail(
                    exc.code,
                    exc.detail,
                    action="start_new_scan",
                    safe_details={"reason_code": exc.reason_code},
                ),
            ) from exc
        if requires_advisor:
            _require_advisor_ai_admission(db, runtime.settings)
        if job_snapshot.kind == "advisor":
            existing_job = db.get(Job, job_id, populate_existing=True)
            if existing_job is not None:
                problem = _advisor_retry_selection_problem(db, existing_job, lock=True)
                if problem is not None:
                    raise HTTPException(
                        409,
                        _problem_detail(
                            problem.code,
                            problem.detail,
                            action="refresh_findings",
                            context={"scan_id": existing_job.scan_id, "finding_id": existing_job.finding_id},
                        ),
                    )
    try:
        job = retry_failed_job(
            db,
            job_id,
            expected_revision=payload.expected_revision,
            detail="Operator retry queued with the original command snapshot.",
        )
    except JobNotFoundError as exc:
        raise HTTPException(404, "job not found") from exc
    except InvalidJobTransition as exc:
        raise HTTPException(409, str(exc)) from exc
    lifecycle_scope = {
        "scanner_catalog_check": "catalog",
        "scanner_cache_update": "cache",
        "scanner_cache_rollback": "cache",
        "scanner_cache_reconcile": "cache",
    }.get(job.kind)
    if lifecycle_scope is not None:
        state = _require_scanner_lifecycle_state(db, lifecycle_scope)
        if state.job_id == job.id:
            state.status = "queued"
            state.receipt = {}
            state.error_code = None
            state.error_detail = None
            state.started_at = None
            state.completed_at = None
            state.updated_at = _utcnow()
            state.revision += 1
            db.add(state)
    db.commit()
    db.refresh(job)
    return _job_to_out(db, job)


@router.get("/v1/gate-policies/{project_id}")
def get_gate_policy(project_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    policy = db.scalar(select(GatePolicy).where(GatePolicy.project_id == project_id))
    if not policy:
        raise HTTPException(404, "gate policy not found")
    return {
        "project_id": project_id,
        "active": policy.active,
        "max_critical": policy.max_critical,
        "max_high": policy.max_high,
        "block_secrets": policy.block_secrets,
    }


@router.put("/v1/gate-policies/{project_id}")
def update_gate_policy(project_id: int, payload: GatePolicyUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    current = db.scalar(select(GatePolicy).where(GatePolicy.project_id == project_id).with_for_update())
    if not current:
        raise HTTPException(404, "gate policy not found")
    observed = {key: getattr(current, key) for key in ("active", "max_critical", "max_high", "block_secrets")}
    if observed != payload.expected_policy.model_dump():
        raise HTTPException(409, "This project's gate policy changed. Reload the policy and review your draft before saving.")
    policy = _upsert_gate_policy(db, project_id, _gate_policy_values_from_payload(payload))
    _recalculate_project_scan_gates(db, project_id)
    db.commit()
    return {
        "project_id": project_id,
        "active": policy.active,
        "max_critical": policy.max_critical,
        "max_high": policy.max_high,
        "block_secrets": policy.block_secrets,
    }


@router.get("/v1/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    projects = db.scalar(select(func.count(Project.id))) or 0
    scans = db.scalar(select(func.count(Scan.id))) or 0
    active_where = Finding.suppressed.is_(False)
    findings = _distinct_findings_count(db, active_where)
    artifacts = db.scalar(select(func.count(ScanArtifact.id))) or 0
    recent = list(db.scalars(select(Scan).order_by(Scan.id.desc()).limit(8)))
    severities = db.execute(
        select(Finding.severity, func.count(func.distinct(Finding.fingerprint))).where(active_where).group_by(Finding.severity)
    ).all()
    scanners = db.execute(
        select(Finding.scanner, func.count(func.distinct(Finding.fingerprint))).where(active_where).group_by(Finding.scanner)
    ).all()
    scanner_severities = db.execute(
        select(Finding.scanner, Finding.severity, func.count(func.distinct(Finding.fingerprint))).where(active_where).group_by(Finding.scanner, Finding.severity)
    ).all()
    rules = db.execute(
        select(Finding.scanner, Finding.rule_id, Finding.severity, func.count(func.distinct(Finding.fingerprint)))
        .where(active_where)
        .group_by(Finding.scanner, Finding.rule_id, Finding.severity)
        .order_by(func.count(func.distinct(Finding.fingerprint)).desc())
        .limit(12)
    ).all()
    scanner_severity_counts: dict[str, dict[str, int]] = {}
    for scanner, severity, count in scanner_severities:
        scanner_key = str(scanner or "unknown")
        scanner_severity_counts.setdefault(scanner_key, {})[str(severity or "info")] = int(count or 0)
    return {
        "projects": projects,
        "scans": scans,
        "findings": findings,
        "finding_occurrences": int(db.scalar(select(func.count(Finding.id)).where(active_where)) or 0),
        "artifacts": artifacts,
        "severity_counts": {str(sev or "info"): int(count or 0) for sev, count in severities},
        "scanner_counts": {str(scanner or "unknown"): int(count or 0) for scanner, count in scanners},
        "scanner_severity_counts": scanner_severity_counts,
        "top_rules": [
            {"scanner": str(scanner or "unknown"), "rule_id": str(rule_id or "unknown"), "severity": str(severity or "info"), "count": int(count or 0)}
            for scanner, rule_id, severity, count in rules
        ],
        "recent_scans": [ScanOut.model_validate(item).model_dump(mode="json") for item in recent],
    }
