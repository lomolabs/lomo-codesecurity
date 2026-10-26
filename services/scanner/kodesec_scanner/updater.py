"""Durable, source-blind operation boundary for scanner lifecycle work.

Requests contain only reviewed component identifiers.  They cannot inject a
URL, filesystem path, command, or environment variable. Implemented transports
resolve every source from validated immutable locks, admit only GitHub's fixed
release-asset HTTPS handoff, reject host proxy state, and return only the
bounded receipts defined here. Components
without a complete reviewed transport remain explicitly unavailable.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import math
import os
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, BinaryIO, Callable, Iterator, Literal, Protocol, get_args
from uuid import UUID

from pydantic import Field, ValidationError, field_validator, model_validator, model_serializer

from .preparation_budget import (
    PreparationBudget,
    PreparationClock,
    PreparationDeadlineExceeded,
    budget_remaining,
    moment as budget_moment,
)
from .recovery_contract import RecoveryBudget, RecoveryTarget, recovery_digest
from . import cache_repair
from .data_catalog import DataCatalogError, DataCatalogStore, generation_locks

from .cache_manifest import (
    EXTERNAL_TOOL_IDS,
    MAX_ACTIVE_POINTER_BYTES,
    REVIEWED_DATA_HARD_VALIDITY_SECONDS,
    ActiveGenerationPointer,
    CacheComponentReceipt,
    CacheFileRecord,
    CanonicalTree,
    CanaryReceipt,
    CacheValidationError,
    CacheVerification,
    CACHE_COMPONENT_IDS,
    ComponentCanaryLock,
    ComponentRequirementLock,
    GenerationManifest,
    GenerationReference,
    GENERATION_HASH_CHECKPOINT_BYTES,
    GrypeDatabaseDataContract,
    GrypeContentErrorCode,
    GrypeContentValidationError,
    GrypeLogicalContentReceipt,
    GRYPE_LOGICAL_TREE_HASH_ALGORITHM,
    LoadedDocument,
    LockValidationError,
    MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS,
    RuleCanaryLock,
    RuleSetLock,
    RulesLockFile,
    ResolvedGeneration,
    ToolLockFile,
    TrivyChecksDataContract,
    TrivyDatabaseDataContract,
    TrivyJavaDatabaseDataContract,
    ValidatedGeneration,
    _StrictModel,
    _atomic_write_json,
    _decode_json_object,
    _parse_utc,
    _read_bounded_regular_file,
    _require_bounded_text,
    _require_identifier,
    _require_relative_path,
    _secure_directory,
    activate_generation,
    canonical_json_bytes,
    canonical_tree_sha256,
    collect_canonical_tree,
    grype_logical_tree_records,
    verify_grype_logical_content,
    load_active_pointer,
    locked_intrinsic_updated_at,
    receipt_matches_installed_content,
    receipt_matches_freshness_contract,
    resolve_active_generation,
    rollback_to_previous_good,
    runtime_components_from_resolved,
    utc_timestamp,
    validate_lock_alignment,
    validate_generation,
    write_generation_manifest,
)
from .external import (
    BearerReportError,
    CapturedCommandOutputLimitError,
    ExecutionControl,
    RunDeadlineExceeded,
    run_captured_command,
    _bearer_jsonv2_findings,
)
from .redaction import redact_text
from .tools import OPENGREP_CORE_PATH, OPENGREP_RULE_ENTRYPOINT, tool_runtime_state


MAX_OPERATION_BYTES = 256 * 1024
MAX_TERMINAL_RESULT_BYTES = 16 * 1024
MAX_OPERATION_RECORDS = 1_024
MAX_OPERATION_ATTEMPTS = 3
MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_STAGING_ENTRIES = MAX_ARCHIVE_ENTRIES * 8
MAX_ARCHIVE_DEPTH = 16
MAX_CANARY_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_DOWNLOAD_CONTROL_BYTES = 64 * 1024
MIN_DATA_UPDATE_MARGIN_BYTES = 512 * 1024 * 1024
MAX_DATA_COMMAND_SECONDS = 900
MAX_DATA_COMMAND_OUTPUT_BYTES = 64 * 1024
OPERATION_ACTIVITY_WRITE_INTERVAL_SECONDS = 2.0
OPERATION_HEARTBEAT_INTERVAL_SECONDS = 5.0
OPERATION_OPAQUE_ACTIVITY_WRITE_INTERVAL_SECONDS = 10.0
MAX_GENERATION_TOMBSTONES = 32
MAX_TOMBSTONE_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_TOMBSTONE_ENTRIES = 20_000
CANARY_OUTPUT_HASH_ALGORITHM = "kodesec-canary-result-v1"
CURL_PATH = Path("/usr/bin/curl")
LOGGER = logging.getLogger("kodesec_scanner.updater")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _evaluation_moment(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationError("lifecycle evaluation clock must be timezone-aware")
    return value.astimezone(UTC)


def _precise_utc_timestamp(value: datetime) -> str:
    return _evaluation_moment(value).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )


def _source_intrinsic_candidate_is_temporally_unusable(
    receipt: CacheComponentReceipt,
    requirement: ComponentRequirementLock,
    evaluated_at: datetime,
) -> bool:
    contract = requirement.data_contract
    if (
        requirement.provenance != "verified"
        or contract is None
        or contract.timestamp_kind != "intrinsic"
        or receipt.immutable_ref != requirement.source.immutable_ref
        or receipt.source_sha256 != requirement.source.sha256
        or receipt.expires_at is None
    ):
        return False
    updated = _parse_utc(receipt.updated_at, "catalog component updated_at")
    expires = _parse_utc(receipt.expires_at, "catalog component expires_at")
    return _intrinsic_freshness_window_is_temporally_unusable(
        updated,
        expires,
        requirement.max_age_seconds,
        evaluated_at,
    )


def _intrinsic_freshness_window_is_temporally_unusable(
    updated: datetime,
    expires: datetime,
    max_age_seconds: int | None,
    evaluated_at: datetime,
) -> bool:
    return (
        updated > evaluated_at + timedelta(minutes=5)
        or expires
        <= evaluated_at + timedelta(seconds=MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS)
        or max_age_seconds is None
        or expires > updated + timedelta(seconds=max_age_seconds)
    )


def _locked_intrinsic_candidate_is_temporally_unusable(
    requirement: ComponentRequirementLock,
    evaluated_at: datetime,
) -> bool:
    contract = requirement.data_contract
    if (
        requirement.provenance != "verified"
        or contract is None
        or contract.timestamp_kind != "intrinsic"
        or requirement.max_age_seconds is None
    ):
        return False
    updated_at = locked_intrinsic_updated_at(requirement)
    if updated_at is None:
        return False
    updated = _parse_utc(updated_at, "catalog locked intrinsic updated_at")
    expires = updated + timedelta(seconds=requirement.max_age_seconds)
    return _intrinsic_freshness_window_is_temporally_unusable(
        updated,
        expires,
        requirement.max_age_seconds,
        evaluated_at,
    )


@dataclass(frozen=True)
class StagedDataComponent:
    tool_id: str
    requirement: ComponentRequirementLock
    updated_at: str
    expires_at: str
    files: list[CacheFileRecord]
    grype_logical_content: GrypeLogicalContentReceipt | None = None

CATALOG_TOOL_IDS = tuple(sorted(EXTERNAL_TOOL_IDS))
SOURCE_INTRINSIC_DATA_COMPONENT_IDS = frozenset(
    {"grype-db", "trivy-db", "trivy-java-db"}
)
OperationKind = Literal["catalog_check", "cache_update", "cache_rollback", "cache_reconcile"]
OperationStatus = Literal[
    "queued",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
]
CatalogToolState = Literal["current", "candidate_available", "unavailable", "unattested"]
CatalogState = CatalogToolState
CatalogComponentState = Literal[
    "current",
    "candidate_available",
    "requires_lock_refresh",
    "unavailable",
    "unattested",
]
CacheRollbackEligibilityCode = Literal[
    "eligible",
    "no_previous_generation",
    "cache_pointer_invalid",
    "previous_generation_invalid",
    "previous_generation_verification_timeout",
    "previous_generation_verifying",
    "previous_generation_verification_failed",
    "different_reviewed_locks",
    "previous_generation_incompatible",
]

OPERATION_STAGES = (
    "queued",
    "resolving_lock",
    "discovering",
    "validating_active",
    "downloading",
    "validating_source",
    "retaining",
    "staging",
    "validating_generation",
    "activating",
    "committing",
    "rolling_back",
    "completed",
    "failed",
    "cancelled",
)
TERMINAL_STATUSES = ("completed", "failed", "cancelled")
_OPERATION_STAGE_SET = frozenset(OPERATION_STAGES)
_TERMINAL_STATUS_SET = frozenset(TERMINAL_STATUSES)
_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"running", "cancelled", "failed"}),
    "running": frozenset({"running", "cancelling", "completed", "failed", "cancelled"}),
    "cancelling": frozenset({"cancelling", "cancelled", "failed"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_OPERATION_FILE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json\Z"
)
_GENERATION_ID = re.compile(r"[0-9a-f]{64}\Z")
_TOMBSTONE_RECEIPT = re.compile(r"([0-9a-f]{64})\.json\Z")


class OperationError(RuntimeError):
    """Base class for updater-operation failures."""


class OperationConflictError(OperationError):
    """A stable operation id was reused with incompatible request state."""


class OperationNotFoundError(OperationError):
    """An updater operation does not exist."""


class OperationStateError(OperationError):
    """An updater operation transition is invalid."""


class OperationCapacityError(OperationError):
    """The bounded operation ledger has no safe capacity."""


AssetTransportReason = Literal["unavailable", "deadline", "output_bound", "curl_exit"]
AssetTransportStage = Literal["release_headers", "asset_body"]


class AssetTransportError(OperationError):
    """Allowlisted transport evidence; never retain command or process text."""

    def __init__(
        self,
        reason: AssetTransportReason,
        stage: AssetTransportStage,
        returncode: int | None = None,
    ) -> None:
        if (
            reason not in get_args(AssetTransportReason)
            or stage not in get_args(AssetTransportStage)
        ):
            raise ValueError("invalid locked asset transport classification")
        if returncode is not None and (
            type(returncode) is not int or not -255 <= returncode <= 255
        ):
            raise ValueError("invalid locked asset transport return code")
        if reason == "curl_exit" and (returncode is None or returncode == 0):
            raise ValueError("locked asset transport failure requires a nonzero exit")
        super().__init__("locked asset transport failed")
        self.reason = reason
        self.transport_stage = stage
        self.returncode = returncode
        self.signal = -returncode if returncode is not None and returncode < 0 else None


DataCommandId = Literal[
    "trivy-promotion", "grype-import", "grype-status",
    "trivy-canary", "syft-canary", "grype-canary",
]
_DATA_COMMAND_IDS = frozenset(get_args(DataCommandId))
# Observed fixed phrases, not inferred causes. Never publish arbitrary command
# text: even database-only commands can print signed URLs or credentials.
_DATA_COMMAND_MARKERS = (
    ("context deadline exceeded", "context_deadline"),
    ("timeout", "timeout"),
    ("no such host", "dns_lookup"),
    ("connection reset", "connection_reset"),
    ("connection refused", "connection_refused"),
    ("unexpected eof", "unexpected_eof"),
    ("no space left", "disk_capacity"),
    ("permission denied", "permission_denied"),
    ("unauthorized", "unauthorized"),
    ("too many requests", "rate_limit"),
    ("manifest unknown", "manifest_unknown"),
    ("blob unknown", "blob_unknown"),
    ("x509", "certificate"),
    ("tls handshake", "tls_handshake"),
    ("download error", "download_error"),
    ("oci artifact", "oci_artifact"),
    # Pinned Trivy wraps network copying and local decompression differently.
    # The outer "oci download error" alone cannot identify either phase.
    ("oci download error: copy error:", "oci_layer_copy_error"),
    ("oci download error: download error:", "oci_local_unpack_error"),
    ("oci repository error:", "oci_repository_error"),
    ("oci manifest error:", "oci_manifest_error"),
    ("failed to fetch the layer:", "oci_layer_fetch_error"),
    ("failed to create a temp dir:", "temporary_directory_error"),
    ("failed to create a temp file:", "temporary_file_error"),
    ("stream error:", "stream_error"),
    ("received from peer", "peer_error"),
    ("gzip: invalid", "gzip_invalid"),
    ("file too large", "file_size_limit"),
    ("failed to copy", "copy_failed"),
    ("failed to extract", "extract_failed"),
    ("failed to write", "write_failed"),
    ("failed to open", "open_failed"),
    ("failed to decode", "decode_failed"),
    ("failed to parse", "parse_failed"),
    ("invalid checksum", "checksum_invalid"),
    ("digest mismatch", "digest_mismatch"),
    ("no such file or directory", "path_missing"),
    ("read-only file system", "read_only_filesystem"),
    ("file exists", "path_exists"),
    ("database is locked", "database_locked"),
)
_DATA_HTTP_STATUS = re.compile(
    r"\b(?:unexpected status(?: code)?|status code|http status)[ :]+"
    r"(400|401|403|404|408|409|413|429|500|502|503|504)\b"
)


@dataclass(frozen=True)
class DataCommandTiming:
    """Failure-only attribution; these observations never control execution."""

    elapsed_ms: int
    effective_timeout_ms: int
    local_limit_ms: int
    preparation_budget_ms: int | None
    capped: bool

    def __post_init__(self) -> None:
        for value in (self.elapsed_ms, self.effective_timeout_ms, self.local_limit_ms):
            if type(value) is not int or not 0 <= value <= 86_400_000:
                raise ValueError("invalid scanner data command timing")
        if self.preparation_budget_ms is not None and (
            type(self.preparation_budget_ms) is not int
            or not 0 < self.preparation_budget_ms <= 86_400_000
        ):
            raise ValueError("invalid original scanner preparation interval")
        if type(self.capped) is not bool:
            raise ValueError("invalid scanner data command timing cap")


class DataCommandFailureError(OperationError):
    """A fixed lifecycle command failed; process text stays private and redacted."""

    def __init__(self, command_id: DataCommandId, returncode: int, stderr: str,
                 *, timing: DataCommandTiming | None = None) -> None:
        if command_id not in _DATA_COMMAND_IDS:
            raise ValueError("invalid scanner data command identity")
        if type(returncode) is not int or not -255 <= returncode <= 255:
            raise ValueError("invalid scanner data command return code")
        raw = stderr.encode("utf-8", errors="surrogateescape")
        if len(raw) > MAX_DATA_COMMAND_OUTPUT_BYTES:
            raise ValueError("scanner data command diagnostic exceeds its bound")
        super().__init__("scanner data command returned an unexpected exit status")
        self.command_id = command_id
        self.returncode = returncode
        self.signal = -returncode if returncode < 0 else None
        self.stderr_bytes = len(raw)
        self.stderr_sha256 = hashlib.sha256(raw).hexdigest()
        # Never persist or log this field. Source-blind fixed commands can still
        # include signed transport URLs or credentials in their error output.
        self.private_stderr = (redact_text(stderr) or "")[:MAX_DATA_COMMAND_OUTPUT_BYTES]
        # Classify only allowlisted literals before redaction: an assignment or
        # signed URL can cause the redactor to consume the trailing error cause.
        # The original text is never attached to this exception or emitted.
        lowered = stderr.lower()
        self.stderr_markers = tuple(
            label for phrase, label in _DATA_COMMAND_MARKERS if phrase in lowered
        )
        self.http_status_markers = tuple(sorted(set(_DATA_HTTP_STATUS.findall(lowered))))
        self.timing = timing


class DataCommandOutputLimitError(OperationError):
    """A fixed lifecycle command exceeded its output bound; no output is retained."""

    def __init__(self, command_id: DataCommandId, limit_bytes: int) -> None:
        if command_id not in _DATA_COMMAND_IDS:
            raise ValueError("invalid scanner data command identity")
        if type(limit_bytes) is not int or limit_bytes <= 0:
            raise ValueError("invalid scanner data command output bound")
        super().__init__("scanner data command exceeded its captured output limit")
        self.command_id = command_id
        self.limit_bytes = limit_bytes


def _validate_timestamp(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not value.endswith("Z"):
        raise ValueError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be RFC3339 UTC") from exc
    if parsed.utcoffset() is None:
        raise ValueError(f"{label} must be RFC3339 UTC")
    return value


def operation_request_digest(
    *,
    schema_version: int,
    kind: OperationKind,
    requested_components: list[str],
    catalog_digest: str | None = None,
    preparation_budget: PreparationBudget | None = None,
) -> str:
    """Return the retry-stable digest; operation id and attempt are excluded."""

    # This is a wire-protocol digest shared with the API worker.  It is
    # deliberately compact JSON *without* the newline used by lock documents.
    payload = {
            "kind": kind,
            "requested_components": requested_components,
            "schema_version": schema_version,
        }
    if catalog_digest is not None:
        payload["catalog_digest"] = catalog_digest
    if preparation_budget is not None:
        payload["preparation_budget"] = preparation_budget.model_dump(mode="json")
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class OperationRequest(_StrictModel):
    schema_version: Literal[1, 2, 3]
    preparation_budget: PreparationBudget | None = None
    reconciliation_budget: RecoveryBudget | None = None
    reconciliation_target: RecoveryTarget | None = None
    operation_id: UUID = Field(strict=False)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: OperationKind
    requested_components: list[str] = Field(max_length=32)
    attempt: int = Field(ge=1, le=MAX_OPERATION_ATTEMPTS)
    max_attempts: int = Field(ge=1, le=MAX_OPERATION_ATTEMPTS)
    catalog_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("schema_version", mode="before")
    @classmethod
    def strict_schema_version(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("operation schema version must be an integer")
        return value

    @field_validator("operation_id")
    @classmethod
    def validate_operation_id(cls, value: UUID) -> UUID:
        if value.version not in {1, 2, 3, 4, 5} or value.variant != "specified in RFC 4122":
            raise ValueError("operation id must be an RFC 4122 UUID")
        return value

    @field_validator("requested_components")
    @classmethod
    def validate_requested_components(cls, value: list[str]) -> list[str]:
        if value != sorted(value) or len(value) != len(set(value)):
            raise ValueError("requested component ids must be sorted and unique")
        for item in value:
            _require_identifier(item, "operation component id")
        return value

    @model_validator(mode="after")
    def validate_request(self) -> "OperationRequest":
        if (self.schema_version == 2) != (self.preparation_budget is not None):
            raise ValueError("preparation budget version mismatch")
        if self.kind == "cache_rollback" and self.preparation_budget is not None:
            raise ValueError("rollback uses its separate safety contract")
        if self.attempt > self.max_attempts:
            raise ValueError("operation attempt exceeds max_attempts")
        if self.kind == "cache_update" and not self.requested_components:
            raise ValueError("cache_update requires at least one reviewed component id")
        if self.kind != "cache_update" and self.requested_components:
            raise ValueError(f"{self.kind} does not accept component ids")
        if self.kind != "cache_update" and self.catalog_digest is not None:
            raise ValueError("only cache updates accept a selected catalog digest")
        if self.schema_version == 3:
            if (self.kind != "cache_reconcile" or self.reconciliation_budget is None
                    or self.reconciliation_target is None or self.attempt != 1 or self.max_attempts != 1):
                raise ValueError("read-only recovery requires its exact single-attempt binding")
            expected = recovery_digest(self.reconciliation_budget, self.reconciliation_target)
            if self.request_digest != expected:
                raise ValueError("recovery digest does not match its immutable target")
            return self
        if self.kind == "cache_reconcile" or self.reconciliation_budget is not None or self.reconciliation_target is not None:
            raise ValueError("recovery fields require schema version 3")
        expected = operation_request_digest(
            schema_version=self.schema_version,
            kind=self.kind,
            requested_components=self.requested_components,
            catalog_digest=self.catalog_digest,
            preparation_budget=self.preparation_budget,
        )
        if self.request_digest != expected:
            raise ValueError("request_digest does not match the canonical operation request")
        return self


class CatalogToolResult(_StrictModel):
    tool_id: str
    state: CatalogToolState
    installed_version: str | None = Field(default=None, max_length=128)
    candidate_version: str | None = Field(default=None, max_length=128)
    candidate_release_id: str | None = Field(default=None, max_length=256)
    candidate_manifest_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator("tool_id")
    @classmethod
    def validate_tool_id(cls, value: str) -> str:
        if value not in EXTERNAL_TOOL_IDS:
            raise ValueError("catalog tool id is not curated")
        return value

    @field_validator("installed_version", "candidate_version", "candidate_release_id")
    @classmethod
    def validate_release_text(cls, value: str | None) -> str | None:
        if value is not None:
            _require_bounded_text(value, "catalog release value", 256)
            if "://" in value or "/" in value or "\\" in value:
                raise ValueError("catalog receipts may not expose paths or URLs")
        return value

    @model_validator(mode="after")
    def validate_candidate(self) -> "CatalogToolResult":
        candidate_values = (
            self.candidate_version,
            self.candidate_release_id,
            self.candidate_manifest_digest,
        )
        if self.state == "candidate_available":
            if self.installed_version is None or not all(candidate_values):
                raise ValueError("candidate tools require installed, release, version, and digest evidence")
        elif any(value is not None for value in candidate_values):
            raise ValueError("non-candidate tool results may not expose candidate metadata")
        if self.state == "current" and self.installed_version is None:
            raise ValueError("current tool results require the installed version")
        return self


class CatalogComponentResult(_StrictModel):
    component_id: str
    state: CatalogComponentState
    current_immutable_ref: str | None = Field(default=None, max_length=256)
    candidate_immutable_ref: str | None = Field(default=None, max_length=256)
    candidate_manifest_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator("component_id")
    @classmethod
    def validate_component_id(cls, value: str) -> str:
        if value not in CACHE_COMPONENT_IDS:
            raise ValueError("catalog cache component id is not curated")
        return value

    @field_validator("current_immutable_ref", "candidate_immutable_ref")
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        if value is not None:
            _require_bounded_text(value, "catalog immutable reference", 256)
            if "://" in value or "/" in value or "\\" in value:
                raise ValueError("catalog receipts may not expose paths or URLs")
        return value

    @model_validator(mode="after")
    def validate_candidate(self) -> "CatalogComponentResult":
        candidate_values = (self.candidate_immutable_ref, self.candidate_manifest_digest)
        if (
            self.state == "requires_lock_refresh"
            and self.component_id not in SOURCE_INTRINSIC_DATA_COMPONENT_IDS
        ):
            raise ValueError(
                "requires_lock_refresh is limited to source-intrinsic data components"
            )
        if self.state == "candidate_available":
            if not all(candidate_values):
                raise ValueError("candidate components require immutable reference and digest")
        elif any(value is not None for value in candidate_values):
            raise ValueError("non-candidate component results may not expose candidate metadata")
        if self.state == "current" and self.current_immutable_ref is None:
            raise ValueError("current component results require the active immutable reference")
        return self


class CatalogOperationResult(_StrictModel):
    kind: Literal["catalog"]
    checked_at: str
    tools: list[CatalogToolResult] = Field(min_length=8, max_length=8)
    components: list[CatalogComponentResult] = Field(min_length=6, max_length=6)
    catalog_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    catalog_mode: Literal["source-reviewed/bundled", "signed"] = "source-reviewed/bundled"

    @field_validator("checked_at")
    @classmethod
    def validate_checked_at(cls, value: str) -> str:
        return _validate_timestamp(value, "catalog checked_at") or value

    @model_validator(mode="after")
    def validate_complete_catalog(self) -> "CatalogOperationResult":
        if (self.catalog_mode == "signed") != (self.catalog_digest is not None):
            raise ValueError("signed catalog mode requires its exact selected digest")
        tool_ids = [item.tool_id for item in self.tools]
        component_ids = [item.component_id for item in self.components]
        if tool_ids != list(CATALOG_TOOL_IDS):
            raise ValueError("catalog result must contain each curated tool once in sorted order")
        if component_ids != list(CACHE_COMPONENT_IDS):
            raise ValueError("catalog result must contain each cache component once in sorted order")
        if len(canonical_json_bytes(self.model_dump(mode="json"))) > MAX_TERMINAL_RESULT_BYTES:
            raise ValueError("catalog result exceeds its receipt size limit")
        return self


class CacheOperationResult(_StrictModel):
    kind: Literal["cache"]
    active: GenerationReference
    previous_good: GenerationReference | None
    updated_components: list[str] = Field(max_length=32)

    @field_validator("updated_components")
    @classmethod
    def validate_components(cls, value: list[str]) -> list[str]:
        if value != sorted(value) or len(value) != len(set(value)):
            raise ValueError("updated component ids must be sorted and unique")
        if set(value) - set(CACHE_COMPONENT_IDS):
            raise ValueError("cache receipt contains an unreviewed component id")
        return value


class CacheRollbackEligibility(_StrictModel):
    """Source-blind proof that the current previous-good pointer is usable."""

    eligible: bool
    reason_code: CacheRollbackEligibilityCode
    reason: str = Field(min_length=1, max_length=256)
    target_generation: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    verification: CacheVerification | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def validate_eligibility(self) -> "CacheRollbackEligibility":
        if self.eligible != (self.reason_code == "eligible"):
            raise ValueError("rollback eligibility and reason code disagree")
        if self.eligible and self.target_generation is None:
            raise ValueError("eligible rollback requires an exact target generation")
        if self.verification is not None:
            expected = {
                "verifying": "previous_generation_verifying",
                "timed_out": "previous_generation_verification_timeout",
                "failed": "previous_generation_verification_failed",
            }[self.verification.state]
            if (self.eligible or self.reason_code != expected
                    or self.verification.target != "previous_good"
                    or self.verification.generation_id != self.target_generation):
                raise ValueError("rollback verification does not match its target/state")
        return self


class ReconciliationOperationResult(_StrictModel):
    kind: Literal["reconciliation"]
    active: GenerationReference
    previous_good: GenerationReference | None
    original_operation_id: UUID = Field(strict=False)
    original_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_workflow_deadline_exceeded: bool
    verified_at: str

    @field_validator("verified_at")
    @classmethod
    def verified_timestamp(cls, value: str) -> str:
        budget_moment(value)
        return value


class ReconciliationIntent(_StrictModel):
    # Historical outcome only: never imported into a physical verification cache.
    original_completed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_finished_at: str
    cache_result: CacheOperationResult
    result: ReconciliationOperationResult

    @field_validator("original_finished_at")
    @classmethod
    def finish_timestamp(cls, value: str) -> str:
        budget_moment(value)
        return value


OperationResult = Annotated[
    CatalogOperationResult | CacheOperationResult | ReconciliationOperationResult,
    Field(discriminator="kind"),
]


class OperationActivity(_StrictModel):
    component_id: str
    component_index: int = Field(ge=1, le=32)
    component_total: int = Field(ge=1, le=32)
    bytes_completed: int | None = Field(default=None, ge=0, le=MAX_DOWNLOAD_BYTES)
    bytes_total: int | None = Field(default=None, ge=1, le=MAX_DOWNLOAD_BYTES)

    @field_validator("component_id")
    @classmethod
    def validate_component_id(cls, value: str) -> str:
        _require_identifier(value, "operation activity component id")
        if value not in CACHE_COMPONENT_IDS:
            raise ValueError("operation activity component is not reviewed")
        return value

    @model_validator(mode="after")
    def validate_progress(self) -> "OperationActivity":
        if self.component_index > self.component_total:
            raise ValueError("operation activity component index exceeds its total")
        if (self.bytes_completed is None) != (self.bytes_total is None):
            raise ValueError("operation byte progress requires completed and total together")
        if (
            self.bytes_completed is not None
            and self.bytes_total is not None
            and self.bytes_completed > self.bytes_total
        ):
            raise ValueError("operation byte progress exceeds its total")
        return self


class InstalledContentFailureEvidence(_StrictModel):
    """Bounded, source-blind evidence for an immutable payload mismatch."""

    kind: Literal["installed_content_mismatch"]
    component_id: str
    runtime_platform: Literal["linux/amd64", "linux/arm64", "unsupported"]
    hash_algorithm: Literal[
        "kodesec-canonical-tree-v1", "kodesec-grype-v6-logical-tree-v1"
    ]
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_file_count: int = Field(gt=0, le=MAX_STAGING_ENTRIES)
    observed_file_count: int = Field(ge=0, le=MAX_STAGING_ENTRIES)
    expected_size_bytes: int = Field(gt=0, le=MAX_DOWNLOAD_BYTES)
    observed_size_bytes: int = Field(ge=0, le=MAX_DOWNLOAD_BYTES)

    @field_validator("component_id")
    @classmethod
    def validate_component_id(cls, value: str) -> str:
        _require_identifier(value, "installed-content failure component")
        if value not in CACHE_COMPONENT_IDS:
            raise ValueError("installed-content failure component is not reviewed")
        return value


class InstalledContentMismatchError(OperationError):
    """An installed data tree differs from its exact reviewed lock identity."""

    def __init__(
        self,
        evidence: InstalledContentFailureEvidence,
        *,
        files: tuple[CacheFileRecord, ...] = (),
    ) -> None:
        super().__init__("scanner installed data identity differs from its lock")
        self.evidence = evidence
        # Only these two fixed, source-blind Grype members are useful to
        # distinguish hydration drift from import-record drift. Never log
        # arbitrary downloaded paths, file bodies, or another tool's members.
        grype_files = {
            item.path: item.sha256 for item in files
            if evidence.component_id == "grype-db"
            and item.path in {"6/vulnerability.db", "6/import.json"}
        }
        self.database_sha256 = grype_files.get("6/vulnerability.db")
        self.import_metadata_sha256 = grype_files.get("6/import.json")


class OperationRecord(_StrictModel):
    schema_version: Literal[1, 2, 3]
    preparation_budget: PreparationBudget | None = None
    reconciliation_budget: RecoveryBudget | None = None
    reconciliation_target: RecoveryTarget | None = None
    workflow_deadline_exceeded: bool = False
    reconciliation_intent: ReconciliationIntent | None = None
    operation_id: UUID = Field(strict=False)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: OperationKind
    requested_components: list[str] = Field(max_length=32)
    status: OperationStatus
    stage: str
    attempt: int = Field(ge=1, le=MAX_OPERATION_ATTEMPTS)
    max_attempts: int = Field(ge=1, le=MAX_OPERATION_ATTEMPTS)
    cancel_requested_at: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str
    last_activity_at: str | None = None
    activity: OperationActivity | None = None
    result: OperationResult | None = None
    error_code: str | None = None
    error_detail: str | None = Field(default=None, max_length=256)

    @field_validator("schema_version", mode="before")
    @classmethod
    def strict_schema_version(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("operation schema version must be an integer")
        return value

    @model_serializer(mode="wrap")
    def versioned_wire(self, handler):
        value = handler(self)
        if self.schema_version != 3:
            for key in ("reconciliation_budget", "reconciliation_target", "reconciliation_intent"):
                value.pop(key, None)
        if self.schema_version == 3:
            value.pop("preparation_budget", None)
            value.pop("workflow_deadline_exceeded", None)
        if self.schema_version == 1:
            value.pop("preparation_budget", None)
            value.pop("workflow_deadline_exceeded", None)
        return value

    @field_validator("requested_components")
    @classmethod
    def validate_requested_components(cls, value: list[str]) -> list[str]:
        if value != sorted(value) or len(value) != len(set(value)):
            raise ValueError("operation record component ids must be sorted and unique")
        for item in value:
            _require_identifier(item, "operation record component id")
        return value

    @field_validator("stage")
    @classmethod
    def validate_stage(cls, value: str) -> str:
        if value not in _OPERATION_STAGE_SET:
            raise ValueError("operation stage is not supported")
        return value

    @field_validator(
        "cancel_requested_at",
        "created_at",
        "started_at",
        "finished_at",
        "updated_at",
        "last_activity_at",
    )
    @classmethod
    def validate_timestamps(cls, value: str | None) -> str | None:
        return _validate_timestamp(value, "operation timestamp")

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        if value is not None and not _ERROR_CODE.fullmatch(value):
            raise ValueError("operation error code is not bounded and stable")
        return value

    @field_validator("error_detail")
    @classmethod
    def validate_error_detail(cls, value: str | None) -> str | None:
        if value is not None:
            _require_bounded_text(value, "operation error detail", 256)
            if "://" in value or "/" in value or "\\" in value:
                raise ValueError("operation errors may not expose paths or URLs")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> "OperationRecord":
        if (self.schema_version == 2) != (self.preparation_budget is not None):
            raise ValueError("operation budget version mismatch")
        if self.workflow_deadline_exceeded and (self.schema_version != 2 or self.status != "completed"):
            raise ValueError("late workflow flag requires an actual completed budgeted outcome")
        if self.schema_version == 3:
            if (self.kind != "cache_reconcile" or self.reconciliation_budget is None
                    or self.reconciliation_target is None or self.attempt != 1 or self.max_attempts != 1):
                raise ValueError("recovery record requires its exact single-attempt binding")
            if self.reconciliation_intent is not None and self.stage not in {"committing", "completed", "failed"}:
                raise ValueError("recovery intent requires a durable outcome stage")
        elif (self.kind == "cache_reconcile" or self.reconciliation_budget is not None
              or self.reconciliation_target is not None or self.reconciliation_intent is not None):
            raise ValueError("recovery fields require schema version 3")
        terminal = self.status in _TERMINAL_STATUS_SET
        if terminal != (self.finished_at is not None):
            raise ValueError("terminal operations require exactly one finish timestamp")
        if self.preparation_budget is not None and self.status == "completed":
            late_finish = (
                _parse_utc(self.finished_at, "operation finish")
                >= budget_moment(self.preparation_budget.deadline_at)
            )
            if self.workflow_deadline_exceeded != late_finish:
                raise ValueError("workflow deadline flag differs from the precise finish timestamp")
        if self.status in {"running", "cancelling", "completed", "failed"} and not self.started_at:
            raise ValueError("started operations require a start timestamp")
        if self.activity is not None:
            if self.kind != "cache_update":
                raise ValueError("only cache updates may expose component activity")
            if self.stage in {"downloading", "validating_source"}:
                if (
                    self.activity.component_id not in self.requested_components
                    or self.activity.component_total != len(self.requested_components)
                ):
                    raise ValueError(
                        "download activity is outside the requested component set"
                    )
            elif self.stage in {"validating_active", "retaining", "validating_generation"}:
                if self.activity.component_id not in CACHE_COMPONENT_IDS:
                    raise ValueError("cache validation activity has an unknown component")
            else:
                raise ValueError("operation stage may not expose component activity")
        if self.status == "completed":
            if self.result is None or self.error_code is not None or self.error_detail is not None:
                raise ValueError("completed operations require one bounded result and no error")
            if self.stage != "completed":
                raise ValueError("completed operation must use the completed stage")
            if len(canonical_json_bytes(self.result.model_dump(mode="json"))) > MAX_TERMINAL_RESULT_BYTES:
                raise ValueError("terminal operation result exceeds its receipt size limit")
            if self.kind == "cache_reconcile" and not isinstance(self.result, ReconciliationOperationResult):
                raise ValueError("recovery requires its separate outcome result")
            if self.kind == "catalog_check" and not isinstance(self.result, CatalogOperationResult):
                raise ValueError("catalog operations require a catalog result")
            if self.kind in {"cache_update", "cache_rollback"} and not isinstance(
                self.result, CacheOperationResult
            ):
                raise ValueError("cache operations require a cache result")
            if self.kind == "cache_update" and self.result.updated_components != self.requested_components:
                raise ValueError("cache update receipt must exactly match the requested component set")
            if self.kind == "cache_rollback" and self.result.updated_components:
                raise ValueError("cache rollback receipts may not claim updated components")
        elif self.result is not None:
            raise ValueError("non-completed operations may not expose a result")
        if self.status == "failed":
            if self.stage != "failed" or not self.error_code or not self.error_detail:
                raise ValueError("failed operations require bounded error code and generic detail")
        elif self.error_code is not None or self.error_detail is not None:
            raise ValueError("only failed operations may expose errors")
        if self.status == "cancelled" and self.stage != "cancelled":
            raise ValueError("cancelled operations must use the cancelled stage")
        if self.status in {"cancelling", "cancelled"} and self.cancel_requested_at is None:
            raise ValueError("cancelled operations require a durable cancellation request")
        if self.attempt > self.max_attempts:
            raise ValueError("operation attempt exceeds max_attempts")
        return self


def validate_operation_request(request: OperationRequest, tools: ToolLockFile) -> None:
    lock_components = {
        requirement.id
        for tool in tools.tools
        for requirement in tool.requirements
    }
    if lock_components != set(CACHE_COMPONENT_IDS):
        raise OperationError("reviewed tool lock does not define the exact cache component catalog")
    unknown = sorted(set(request.requested_components) - lock_components)
    if unknown:
        raise OperationError("operation requested a component absent from the reviewed tool lock")


def _operation_filename(operation_id: UUID) -> str:
    return f"{str(operation_id).lower()}.json"


# Thread-local pure deadline check: it never opens the ledger recursively.  The
# atomic publication fence clears this before committing; reconciliation and
# cancellation remain possible after expiry.
_PREPARATION_LOCK_CHECK: ContextVar[Callable[[], object] | None] = ContextVar("preparation_lock_check", default=None)


def _acquire_owned_lock(
    descriptor: int,
    checkpoint: Callable[[], object] | None = None,
    *,
    contention_check: Callable[[], object] | None = None,
) -> None:
    check = checkpoint or _PREPARATION_LOCK_CHECK.get()
    if check is None and contention_check is not None:
        # Completed/legacy replay reads remain available after expiry when the
        # ledger is free. Contention cannot grant an unbounded admission wait.
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            check = contention_check
    if check is None:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return
    while True:
        check()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(0.05)


class _ReadOnlyReconciliationClock:
    """At most five seconds to establish pointer truth; never starts new work."""
    def __init__(self) -> None:
        self.deadline_monotonic = time.monotonic() + 5.0

    def shorten(self, remaining: float) -> None:
        self.deadline_monotonic = min(self.deadline_monotonic, time.monotonic() + remaining)

    def checkpoint(self) -> None:
        if self.deadline_monotonic - time.monotonic() <= 0.001:
            raise PreparationDeadlineExceeded("read-only cache reconciliation remains uncertain")

    def verification_deadline_monotonic(self) -> float:
        self.checkpoint()
        return self.deadline_monotonic


@dataclass(frozen=True)
class OperationStore:
    cache_root: Path

    @property
    def operations_path(self) -> Path:
        return self.cache_root / "operations"

    def _root(self, *, create: bool = False) -> Path:
        root = _secure_directory(self.cache_root, "tool cache root", create=create)
        return _secure_directory(root / "operations", "operation root", create=create)

    def _path(self, operation_id: UUID, *, create_root: bool = False) -> Path:
        return self._root(create=create_root) / _operation_filename(operation_id)

    @contextmanager
    def _ledger_lock(
        self,
        checkpoint: Callable[[], object] | None = None,
        *,
        contention_check: Callable[[], object] | None = None,
    ) -> Iterator[None]:
        root = self._root(create=True)
        path = root / ".ledger.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise OperationError("operation ledger lock cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OperationError("operation ledger lock is not a private regular file")
            os.fchmod(descriptor, 0o600)
            _acquire_owned_lock(descriptor, checkpoint, contention_check=contention_check)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _operation_ids_unlocked(self) -> list[UUID]:
        root = self._root(create=True)
        operation_ids: list[UUID] = []
        try:
            entries = os.scandir(root)
        except OSError as exc:
            raise OperationError("operation ledger cannot be enumerated") from exc
        with entries:
            for entry in entries:
                if entry.name == ".ledger.lock":
                    metadata = entry.stat(follow_symlinks=False)
                    if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                        raise OperationError("operation ledger lock is unsafe")
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise OperationError("operation ledger entry cannot be inspected") from exc
                if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not _OPERATION_FILE.fullmatch(
                    entry.name
                ):
                    raise OperationError("operation ledger contains an unsafe or unexpected entry")
                if metadata.st_nlink != 1:
                    raise OperationError("operation ledger entry has an unsafe link count")
                operation_ids.append(UUID(entry.name.removesuffix(".json")))
        if len(operation_ids) > MAX_OPERATION_RECORDS:
            raise OperationCapacityError("operation ledger exceeds its record bound")
        return sorted(operation_ids, key=lambda item: item.hex)

    @staticmethod
    def _completed_prune_order(record: OperationRecord) -> tuple[datetime, datetime, str]:
        if record.status != "completed" or record.finished_at is None:
            raise OperationStateError("only completed operation receipts may be pruned")

        def parsed(value: str) -> datetime:
            try:
                return datetime.fromisoformat(
                    value.removesuffix("Z") + "+00:00"
                ).astimezone(UTC)
            except ValueError as exc:  # pragma: no cover - strict record validation owns this
                raise OperationError(
                    "completed operation receipt has an invalid timestamp"
                ) from exc

        return (
            parsed(record.finished_at),
            parsed(record.updated_at),
            record.operation_id.hex,
        )

    def _prune_completed_for_admission_unlocked(
        self,
        operation_ids: list[UUID],
        *,
        requested_operation_id: UUID,
    ) -> None:
        """Free exactly one bounded slot without discarding unresolved receipts."""

        # Admission reaches this helper only after checking the requested
        # operation's stable identity. Strictly load every ledger entry before
        # deleting anything so malformed durable state can never be repaired by
        # accidentally pruning around it.
        records = [self._load_unlocked(operation_id) for operation_id in operation_ids]
        repair_operation_id = cache_repair.retained_operation_id(self.cache_root)
        candidates = sorted(
            (
                record
                for record in records
                if record.operation_id != requested_operation_id
                and record.operation_id != repair_operation_id
                and record.status == "completed"
            ),
            key=self._completed_prune_order,
        )
        if not candidates:
            raise OperationCapacityError(
                "operation ledger is full and has no completed receipt eligible for pruning"
            )

        root = self._root()
        directory_fd = -1
        try:
            directory_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            candidate = candidates[0]
            filename = _operation_filename(candidate.operation_id)
            # Re-read through the strict bounded loader under the ledger lock,
            # then verify the exact direct child immediately before unlinking.
            # Legitimate writers share this lock, so a changed receipt is an
            # unsafe ledger condition rather than permission to prune it.
            if self._load_unlocked(candidate.operation_id) != candidate:
                raise OperationError("completed operation receipt changed before pruning")
            metadata = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OperationError("completed operation receipt is unsafe to prune")
            os.unlink(filename, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OperationError:
            raise
        except OSError as exc:
            raise OperationError("completed operation receipt could not be pruned safely") from exc
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def _load_unlocked(self, operation_id: UUID) -> OperationRecord:
        path = self._path(operation_id)
        try:
            raw = _read_bounded_regular_file(path, MAX_OPERATION_BYTES, "updater operation")
        except CacheValidationError as exc:
            if "missing" in str(exc):
                raise OperationNotFoundError("updater operation does not exist") from exc
            raise OperationError("updater operation is unsafe") from exc
        try:
            record = OperationRecord.model_validate(_decode_json_object(raw, "updater operation"))
        except (ValidationError, ValueError) as exc:
            raise OperationError("updater operation failed strict validation") from exc
        if record.operation_id != operation_id:
            raise OperationError("updater operation filename and identity differ")
        return record

    def load(self, operation_id: UUID, *, request_digest: str | None = None) -> OperationRecord:
        # Readers must participate in the ledger lock. `_read_bounded_regular_file`
        # deliberately rejects a path replaced while it is being read; without
        # serialization, an ordinary GET racing an atomic state transition can
        # therefore surface a transient ledger-invalid 500 even though both the
        # pre-transition and post-transition records are valid.
        with self._ledger_lock():
            record = self._load_unlocked(operation_id)
        if request_digest is not None:
            if not re.fullmatch(r"[0-9a-f]{64}", request_digest):
                raise OperationConflictError("request digest header is malformed")
            if record.request_digest != request_digest:
                raise OperationConflictError("request digest does not match updater operation")
        return record

    def _write_unlocked(self, record: OperationRecord) -> OperationRecord:
        root = self._root(create=True)
        _atomic_write_json(
            root,
            _operation_filename(record.operation_id),
            record.model_dump(mode="json"),
            MAX_OPERATION_BYTES,
        )
        return record

    @staticmethod
    def _timestamp(current: OperationRecord, now: str | None = None) -> str:
        if now is not None:
            return now
        if current.preparation_budget is not None or current.reconciliation_budget is not None:
            return _precise_utc_timestamp(_utc_now())
        return utc_timestamp()

    def _transition_unlocked(
        self,
        current: OperationRecord,
        *,
        status: OperationStatus,
        stage: str,
        result: OperationResult | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
        activity: OperationActivity | None = None,
        now: str | None = None,
    ) -> OperationRecord:
        if (
            current.status == status
            and current.stage == stage
            and current.activity == activity
        ):
            return current
        if status not in _TRANSITIONS[current.status]:
            raise OperationStateError(
                f"cannot transition updater operation from {current.status} to {status}"
            )
        timestamp = self._timestamp(current, now)
        started_at = current.started_at
        if current.status == "queued" and status in {"running", "failed"}:
            started_at = timestamp
        finished_at = timestamp if status in _TERMINAL_STATUS_SET else None
        cancel_requested_at = current.cancel_requested_at
        if status in {"cancelling", "cancelled"} and cancel_requested_at is None:
            cancel_requested_at = timestamp
        updated = current.model_copy(
            update={
                "status": status,
                "stage": stage,
                "started_at": started_at,
                "finished_at": finished_at,
                "updated_at": timestamp,
                "last_activity_at": timestamp,
                "activity": activity,
                "cancel_requested_at": cancel_requested_at,
                "result": result,
                "workflow_deadline_exceeded": bool(
                    current.preparation_budget is not None
                    and status == "completed"
                    and _parse_utc(timestamp, "operation finish")
                    >= budget_moment(current.preparation_budget.deadline_at)
                ),
                "error_code": error_code,
                "error_detail": error_detail,
            }
        )
        try:
            validated = OperationRecord.model_validate(updated.model_dump(mode="json"))
        except ValidationError as exc:
            raise OperationStateError(
                "updater operation transition violates its state contract"
            ) from exc
        return self._write_unlocked(validated)

    def _reconcile_published_unlocked(
        self,
        current: OperationRecord,
        *,
        now: str,
        reconciliation_clock: _ReadOnlyReconciliationClock | None = None,
    ) -> OperationRecord | None:
        if current.kind not in {"cache_update", "cache_rollback"} or current.stage not in {
            "committing",
            "activating",
        }:
            return None
        if current.preparation_budget is not None:
            reconciliation_clock = reconciliation_clock or _ReadOnlyReconciliationClock()
            try:
                remaining = budget_remaining(current.preparation_budget,
                    now=_parse_utc(now, "reconciliation"),
                    high_water=_parse_utc(current.updated_at, "reconciliation high water"))
            except PreparationDeadlineExceeded:
                # Expiry permits only this five-second read-only safety proof.
                # It cannot qualify preparation or renew its execution budget.
                pass
            else:
                reconciliation_clock.shorten(remaining)
        checkpoint = reconciliation_clock.checkpoint if reconciliation_clock is not None else None
        try:
            if checkpoint is not None:
                checkpoint()
            pointer = load_active_pointer(self.cache_root)
            if pointer.operation_id != str(current.operation_id):
                return None
            repaired = cache_repair.publication_proof(
                self.cache_root, str(current.operation_id), current.request_digest,
                current.requested_components, pointer, checkpoint,
            ) if current.kind == "cache_update" else False
            if not repaired:
                validate_generation(
                    self.cache_root,
                    pointer.active.generation_id,
                    expected_manifest_sha256=pointer.active.manifest_sha256,
                    checkpoint=checkpoint,
                )
            if checkpoint is not None:
                checkpoint()
        except PreparationDeadlineExceeded:
            return current  # Preserve committing intent; outcome is unknown.
        except CacheValidationError as exc:
            if reconciliation_clock is not None:
                return current  # No verified publication outcome; retain source.
            if isinstance(exc, GrypeContentValidationError) and exc.retryable:
                raise
            return None
        if current.preparation_budget is not None:
            now = _precise_utc_timestamp(max(_parse_utc(now, "reconciliation"), _utc_now()))
        result = _pointer_result(pointer, current.requested_components)
        completed = OperationRecord.model_validate(
            current.model_copy(
                update={
                    "status": "completed",
                    "stage": "completed",
                    "started_at": current.started_at or now,
                    "finished_at": now,
                    "updated_at": now,
                    "activity": None,
                    "result": result,
                    "workflow_deadline_exceeded": bool(
                        current.preparation_budget is not None
                        and _parse_utc(now, "operation reconcile")
                        >= budget_moment(current.preparation_budget.deadline_at)
                    ),
                    "error_code": None,
                    "error_detail": None,
                }
            ).model_dump(mode="json")
        )
        return self._write_unlocked(completed)

    def reconcile_published(
        self,
        operation_id: UUID,
        *,
        now: str | None = None,
        preparation_budget: PreparationBudget | None = None,
    ) -> OperationRecord | None:
        """Establish actual pointer truth without renewing preparation work."""

        reconciliation_clock = _ReadOnlyReconciliationClock() if preparation_budget is not None else None
        checkpoint = reconciliation_clock.checkpoint if reconciliation_clock is not None else None
        with self._ledger_lock(checkpoint):
            current = self._load_unlocked(operation_id)
            return self._reconcile_published_unlocked(
                current,
                now=self._timestamp(current, now),
                reconciliation_clock=reconciliation_clock,
            )

    def create_or_get(
        self,
        request: OperationRequest,
        *,
        now: str | None = None,
        admit_new_attempt: bool = True,
    ) -> tuple[OperationRecord, bool]:
        """Create, replay, or restart exactly the next bounded attempt."""

        admission_clock = None
        def admission_wait() -> None:
            nonlocal admission_clock
            budget = request.reconciliation_budget or request.preparation_budget
            if budget is None:
                raise PreparationDeadlineExceeded("unbudgeted preparation cannot wait for fresh admission")
            if admission_clock is None:
                admission_clock = PreparationClock(budget,
                    now=lambda: _parse_utc(now, "admission clock") if now is not None else _utc_now())
            admission_clock.remaining(900)
        with self._ledger_lock(contention_check=admission_wait if request.kind != "cache_rollback" else None):
            try:
                existing = self._load_unlocked(request.operation_id)
            except OperationNotFoundError:
                existing = None
            if existing is None:
                if request.kind != "cache_rollback":
                    budget = request.reconciliation_budget or request.preparation_budget
                    if budget is None:
                        raise OperationStateError("scanner preparation budget required")
                    budget_remaining(
                        budget,
                        now=_parse_utc(now, "operation admission") if now is not None else _utc_now(),
                    )
                if request.attempt != 1:
                    raise OperationConflictError("a new operation must begin at attempt 1")
                if not admit_new_attempt:
                    raise OperationCapacityError("updater execution queue is full")
                operation_ids = self._operation_ids_unlocked()
                if len(operation_ids) >= MAX_OPERATION_RECORDS:
                    self._prune_completed_for_admission_unlocked(
                        operation_ids,
                        requested_operation_id=request.operation_id,
                    )
                timestamp = now or _precise_utc_timestamp(_utc_now())
                record = OperationRecord(
                    schema_version=request.schema_version,
                    preparation_budget=request.preparation_budget,
                    reconciliation_budget=request.reconciliation_budget,
                    reconciliation_target=request.reconciliation_target,
                    operation_id=request.operation_id,
                    request_digest=request.request_digest,
                    kind=request.kind,
                    requested_components=request.requested_components,
                    status="queued",
                    stage="queued",
                    attempt=request.attempt,
                    max_attempts=request.max_attempts,
                    cancel_requested_at=None,
                    created_at=timestamp,
                    started_at=None,
                    finished_at=None,
                    updated_at=timestamp,
                    last_activity_at=timestamp,
                    activity=None,
                    result=None,
                    error_code=None,
                    error_detail=None,
                )
                return self._write_unlocked(record), True

            if (
                existing.preparation_budget != request.preparation_budget
                or existing.reconciliation_budget != request.reconciliation_budget
                or existing.reconciliation_target != request.reconciliation_target
                or existing.schema_version != request.schema_version
            ):
                raise OperationConflictError("preparation budget is immutable")
            if existing.request_digest != request.request_digest:
                raise OperationConflictError("operation id was reused with a different request")
            if existing.max_attempts != request.max_attempts:
                raise OperationConflictError("max_attempts is immutable for an operation id")
            if request.attempt == existing.attempt or existing.status == "completed":
                return existing, False
            if request.attempt != existing.attempt + 1:
                raise OperationConflictError("retry must request exactly the next attempt")
            if existing.status not in {"failed", "cancelled"}:
                raise OperationConflictError("only terminal failed or cancelled operations may restart")
            if request.attempt > existing.max_attempts:
                raise OperationConflictError("operation retry exceeds max_attempts")
            if request.kind != "cache_rollback":
                if request.preparation_budget is None:
                    raise OperationStateError("legacy preparation may only be read cancelled or reconciled")
                budget_remaining(
                    request.preparation_budget,
                    now=_parse_utc(now, "operation retry") if now is not None else _utc_now(),
                    high_water=_parse_utc(existing.updated_at, "operation high water"),
                )
            if not admit_new_attempt:
                raise OperationCapacityError("updater execution queue is full")
            timestamp = now or _precise_utc_timestamp(_utc_now())
            restarted = OperationRecord.model_validate(
                existing.model_copy(
                    update={
                        "status": "queued",
                        "stage": "queued",
                        "attempt": request.attempt,
                        "cancel_requested_at": None,
                        "started_at": None,
                        "finished_at": None,
                        "updated_at": timestamp,
                        "last_activity_at": timestamp,
                        "activity": None,
                        "result": None,
                        "error_code": None,
                        "error_detail": None,
                    }
                ).model_dump(mode="json")
            )
            return self._write_unlocked(restarted), True

    def transition(
        self,
        operation_id: UUID,
        *,
        status: OperationStatus,
        stage: str,
        result: OperationResult | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
        activity: OperationActivity | None = None,
        now: str | None = None,
    ) -> OperationRecord:
        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            return self._transition_unlocked(
                current,
                status=status,
                stage=stage,
                result=result,
                error_code=error_code,
                error_detail=error_detail,
                activity=activity,
                now=now,
            )

    def heartbeat(
        self,
        operation_id: UUID,
        *,
        request_digest: str,
        now: str | None = None,
    ) -> OperationRecord:
        """Persist bounded liveness without turning every poll into an event."""

        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            if current.request_digest != request_digest:
                raise OperationConflictError("request digest does not match updater operation")
            if current.status in _TERMINAL_STATUS_SET:
                return current
            timestamp = self._timestamp(current, now)
            previous = current.updated_at
            if (
                _parse_utc(timestamp, "operation heartbeat")
                - _parse_utc(previous, "operation last activity")
            ).total_seconds() < OPERATION_HEARTBEAT_INTERVAL_SECONDS:
                return current
            updated = OperationRecord.model_validate(
                current.model_copy(
                    update={"updated_at": timestamp}
                ).model_dump(mode="json")
            )
            return self._write_unlocked(updated)

    def update_activity(
        self,
        operation_id: UUID,
        *,
        request_digest: str,
        activity: OperationActivity,
        force: bool = False,
        now: str | None = None,
    ) -> OperationRecord:
        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            if current.request_digest != request_digest:
                raise OperationConflictError("request digest does not match updater operation")
            if current.status in {"cancelling", "cancelled"} or current.cancel_requested_at:
                raise OperationStateError("updater operation cancellation requested")
            if current.status != "running":
                raise OperationStateError("operation activity requires a running operation")
            timestamp = self._timestamp(current, now)
            previous = current.last_activity_at or current.updated_at
            elapsed = (
                _parse_utc(timestamp, "operation activity")
                - _parse_utc(previous, "operation last activity")
            ).total_seconds()
            if not force and elapsed < OPERATION_ACTIVITY_WRITE_INTERVAL_SECONDS:
                return current
            return self._transition_unlocked(
                current,
                status="running",
                stage=current.stage,
                activity=activity,
                now=timestamp,
            )

    def update_byte_progress(
        self,
        operation_id: UUID,
        *,
        request_digest: str,
        completed: int,
        total: int,
        force: bool = False,
        now: str | None = None,
    ) -> OperationRecord:
        """Check cancellation and derive byte activity from one locked ledger read."""

        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            if not re.fullmatch(r"[0-9a-f]{64}", request_digest):
                raise OperationConflictError("request digest header is malformed")
            if current.request_digest != request_digest:
                raise OperationConflictError("request digest does not match updater operation")
            if current.status in {"cancelling", "cancelled"} or current.cancel_requested_at:
                raise OperationStateError("updater operation cancellation requested")
            if current.activity is None:
                return current
            if current.status != "running":
                raise OperationStateError("operation activity requires a running operation")
            timestamp = self._timestamp(current, now)
            previous = current.last_activity_at or current.updated_at
            elapsed = (
                _parse_utc(timestamp, "operation activity")
                - _parse_utc(previous, "operation last activity")
            ).total_seconds()
            if not force and elapsed < OPERATION_ACTIVITY_WRITE_INTERVAL_SECONDS:
                return current
            activity = current.activity.model_copy(
                update={"bytes_completed": completed, "bytes_total": total}
            )
            return self._transition_unlocked(
                current,
                status="running",
                stage=current.stage,
                activity=activity,
                now=timestamp,
            )

    def refresh_activity(
        self,
        operation_id: UUID,
        *,
        request_digest: str,
        now: str | None = None,
    ) -> OperationRecord:
        """Refresh truthful component activity while an opaque command is running."""

        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            if current.request_digest != request_digest:
                raise OperationConflictError("request digest does not match updater operation")
            if current.status in {"cancelling", "cancelled"} or current.cancel_requested_at:
                raise OperationStateError("updater operation cancellation requested")
            if current.status != "running":
                raise OperationStateError("operation activity requires a running operation")
            if current.activity is None:
                return current
            timestamp = self._timestamp(current, now)
            previous = current.last_activity_at or current.updated_at
            elapsed = (
                _parse_utc(timestamp, "operation activity")
                - _parse_utc(previous, "operation last activity")
            ).total_seconds()
            if elapsed < OPERATION_OPAQUE_ACTIVITY_WRITE_INTERVAL_SECONDS:
                return current
            updated = OperationRecord.model_validate(
                current.model_copy(
                    update={"updated_at": timestamp, "last_activity_at": timestamp}
                ).model_dump(mode="json")
            )
            return self._write_unlocked(updated)

    def request_cancel(
        self,
        operation_id: UUID,
        *,
        request_digest: str,
        now: str | None = None,
    ) -> OperationRecord:
        with self._ledger_lock():
            current = self._load_unlocked(operation_id)
            if current.request_digest != request_digest:
                raise OperationConflictError(
                    "request digest does not match updater operation"
                )
            if current.status in _TERMINAL_STATUS_SET or current.status == "cancelling":
                return current
            if current.stage in {"committing", "activating"}:
                # The check and every state transition share the ledger lock,
                # so cancellation cannot cross the non-cancellable marker.
                return current
            if current.status == "queued":
                return self._transition_unlocked(
                    current,
                    status="cancelled",
                    stage="cancelled",
                    now=now,
                )
            return self._transition_unlocked(
                current,
                status="cancelling",
                stage=current.stage,
                now=now,
            )

    def recover_interrupted(self, *, now: str | None = None) -> list[OperationRecord]:
        """Fail active records left behind by a terminated updater process.

        A replay of the same attempt then observes a terminal record and the
        durable API worker may submit exactly the next bounded attempt. Queued
        records are not silently restarted after process replacement because
        their in-memory work item no longer exists.
        """

        recovered: list[OperationRecord] = []
        recovery_moment = _utc_now()
        # All two-ledger recovery writes use generation-before-ledger lock order.
        recovery_lock_clock = _ReadOnlyReconciliationClock()
        def metadata_checkpoint() -> bool:
            try:
                recovery_lock_clock.checkpoint()
                return True
            except PreparationDeadlineExceeded:
                LOGGER.warning("startup recovery metadata deadline reached; records and maintenance retained")
                return False

        with generation_lock(self.cache_root, checkpoint=recovery_lock_clock.checkpoint):
            try:
                cache_repair.recover_repair(self.cache_root, recovery_lock_clock.checkpoint)
            except PreparationDeadlineExceeded:
                LOGGER.warning("startup repair cleanup deadline reached; exact intent and receipts retained")
                return recovered
            with self._ledger_lock(checkpoint=recovery_lock_clock.checkpoint):
                root = self._root(create=True)
                operation_ids: list[UUID] = []
                with os.scandir(root) as entries:
                    for entry in entries:
                        if not metadata_checkpoint():
                            return recovered
                        if entry.name == ".ledger.lock":
                            continue
                        if not _OPERATION_FILE.fullmatch(entry.name):
                            raise OperationError("operation ledger contains an unsafe or unexpected entry")
                        if len(operation_ids) >= MAX_OPERATION_RECORDS:
                            raise OperationCapacityError("operation ledger exceeds its existing record bound")
                        operation_ids.append(UUID(entry.name.removesuffix(".json")))
                operation_ids.sort(key=str)
                records = {}
                for operation_id in operation_ids:
                    if not metadata_checkpoint():
                        return recovered
                    records[operation_id] = self._load_unlocked(operation_id)
                protected_originals = {
                    UUID(record.reconciliation_target.operation_id)
                    for record in records.values() if record.kind == "cache_reconcile"
                }
                # Replay proven recovery writes before attempting legacy safety proof.
                operation_ids.sort(key=lambda item: records[item].kind != "cache_reconcile")
                for operation_id in operation_ids:
                    if not metadata_checkpoint():
                        return recovered
                    current = self._load_unlocked(operation_id)
                    timestamp = now or (
                        _precise_utc_timestamp(recovery_moment)
                        if current.preparation_budget is not None or current.reconciliation_budget is not None
                        else utc_timestamp(recovery_moment)
                    )
                    if current.status in _TERMINAL_STATUS_SET:
                        continue
                    if operation_id in protected_originals:
                        # Explicit recovery owns this uncertainty. Restart cannot
                        # sneak in another SQL proof through the legacy safety path.
                        recovered.append(current)
                        continue
                    if current.kind == "cache_reconcile" and current.reconciliation_intent is not None:
                        from .readonly_recovery import replay_intent_unlocked
                        try:
                            outcome = replay_intent_unlocked(self, current, checkpoint=recovery_lock_clock.checkpoint)
                        except (OperationError, CacheValidationError, ValueError):
                            outcome = None
                        if outcome is not None:
                            recovered.append(outcome)
                            continue
                    if not metadata_checkpoint():
                        return recovered
                    published = self._reconcile_published_unlocked(
                        current,
                        now=timestamp,
                    )
                    if published is not None:
                        recovered.append(published)
                        continue
                    status: OperationStatus = (
                        "cancelled"
                        if current.status in {"cancelling", "cancelled"}
                        or current.cancel_requested_at is not None
                        else "failed"
                    )
                    update = {
                        "status": status,
                        "stage": status,
                        "started_at": current.started_at or timestamp,
                        "finished_at": timestamp,
                        "updated_at": timestamp,
                        "activity": None,
                        "cancel_requested_at": (
                            current.cancel_requested_at or timestamp
                            if status == "cancelled"
                            else current.cancel_requested_at
                        ),
                        "result": None,
                        "error_code": "updater_restarted" if status == "failed" else None,
                        "error_detail": (
                            "scanner lifecycle operation was interrupted by updater restart"
                            if status == "failed"
                            else None
                        ),
                    }
                    record = OperationRecord.model_validate(
                        current.model_copy(update=update).model_dump(mode="json")
                    )
                    recovered.append(self._write_unlocked(record))
        if any(record.kind == "cache_reconcile" for record in recovered):
            # Historical read-only outcome proof cannot authorize startup pruning.
            return recovered
        if any(record.status not in _TERMINAL_STATUS_SET for record in recovered):
            # An exhausted read-only proof does not authorize source cleanup.
            LOGGER.warning("cache publication remains uncertain; startup pruning deferred")
            return recovered
        with generation_lock(self.cache_root):
            try:
                cache_repair.recover_repair(self.cache_root, recovery_lock_clock.checkpoint)
            except PreparationDeadlineExceeded:
                LOGGER.warning("startup repair cleanup deadline reached; exact intent and receipts retained")
                return recovered
            _recover_generation_tombstones(self.cache_root)
            self._recover_staging()
            _prune_unreferenced_generations(
                self.cache_root,
                allow_missing_pointer=True,
                retire_missing_previous_good=True,
            )
        return recovered

    def _recover_staging(self) -> None:
        """Remove only staging trees owned by durable terminal operations."""

        cache_root = _secure_directory(self.cache_root, "tool cache root", create=True)
        staging_root = _secure_directory(
            cache_root / "staging",
            "updater staging root",
            create=True,
        )
        try:
            with os.scandir(staging_root) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise OperationError("updater staging root cannot be enumerated") from exc
        for entry in entries:
            if not _OPERATION_FILE.fullmatch(f"{entry.name}.json"):
                raise OperationError("updater staging root contains an unknown entry")
            operation_id = UUID(entry.name)
            try:
                record = self.load(operation_id)
            except OperationNotFoundError:
                LOGGER.warning(
                    "removing orphan updater staging operation_id=%s",
                    operation_id,
                )
                _remove_private_staging_tree(staging_root / entry.name)
                continue
            if record.status not in _TERMINAL_STATUS_SET:
                raise OperationError("active operation retained staging after recovery")
            _remove_private_staging_tree(staging_root / entry.name)


@dataclass(frozen=True)
class OperationContext:
    request: OperationRequest
    store: OperationStore
    wall_now: Callable[[], str] = field(default_factory=lambda: lambda: _precise_utc_timestamp(_utc_now()))
    _budget_clock: PreparationClock | None = None
    _repair_source: cache_repair.RepairSource | None = None

    def remaining_seconds(self, local_bound: float) -> float:
        budget = self.request.reconciliation_budget or self.request.preparation_budget
        if budget is None:
            return local_bound  # Existing isolated read/cancel contexts; fresh legacy work is rejected.
        if self._budget_clock is None:
            record = self.store.load(self.request.operation_id)
            clock = PreparationClock(
                budget,
                now=lambda: _parse_utc(self.wall_now(), "preparation clock"),
                high_water=_parse_utc(record.updated_at, "preparation high water"),
            )
            object.__setattr__(self, "_budget_clock", clock)
        return self._budget_clock.remaining(local_bound)


    def verification_deadline_monotonic(self) -> float | None:
        self.remaining_seconds(900)
        return self._budget_clock.deadline_monotonic if self._budget_clock is not None else None

    def checkpoint(self) -> OperationRecord:
        self.remaining_seconds(900)
        record = self.store.heartbeat(
            self.request.operation_id,
            request_digest=self.request.request_digest,
        )
        if record.status in {"cancelling", "cancelled"} or record.cancel_requested_at is not None:
            raise OperationStateError("updater operation cancellation requested")
        return record

    def refresh_activity(self) -> OperationRecord:
        self.remaining_seconds(900)
        record = self.store.refresh_activity(
            self.request.operation_id,
            request_digest=self.request.request_digest,
        )
        if record.activity is None:
            return self.checkpoint()
        if record.status in {"cancelling", "cancelled"} or record.cancel_requested_at is not None:
            raise OperationStateError("updater operation cancellation requested")
        return record

    def progress(
        self,
        stage: str,
        *,
        component_id: str | None = None,
        component_index: int | None = None,
        component_total: int | None = None,
        now: str | None = None,
    ) -> OperationRecord:
        self.checkpoint()
        activity = None
        if component_id is not None:
            if component_index is None or component_total is None:
                raise OperationError("component progress requires an index and total")
            activity = OperationActivity(
                component_id=component_id,
                component_index=component_index,
                component_total=component_total,
            )
        return self.store.transition(
            self.request.operation_id,
            status="running",
            stage=stage,
            activity=activity,
            now=now,
        )

    def byte_progress(
        self,
        completed: int,
        total: int,
        *,
        force: bool = False,
        now: str | None = None,
    ) -> OperationRecord:
        self.remaining_seconds(900)
        return self.store.update_byte_progress(
            self.request.operation_id,
            request_digest=self.request.request_digest,
            completed=completed,
            total=total,
            force=force,
            now=now,
        )


def _generation_progress(
    context: OperationContext,
    stage: Literal["validating_active", "validating_generation", "retaining"],
) -> Callable[[str, int, int, int, int], object]:
    """Adapt exact generation hashing evidence to durable updater activity."""

    if context.request.kind == "cache_rollback":
        # Rollback keeps its own rolling_back/committing stages. Component
        # activity belongs to cache-update requests and would invalidate the
        # durable rollback record before the pointer could be restored.
        return lambda *_evidence: context.checkpoint()

    current_component: tuple[str, int, int] | None = None

    def publish(
        component_id: str,
        component_index: int,
        component_total: int,
        bytes_completed: int,
        bytes_total: int,
    ) -> object:
        nonlocal current_component
        identity = (component_id, component_index, component_total)
        if identity != current_component:
            context.progress(
                stage,
                component_id=component_id,
                component_index=component_index,
                component_total=component_total,
            )
            current_component = identity
        if bytes_total > 0:
            return context.byte_progress(
                bytes_completed,
                bytes_total,
                force=bytes_completed in {0, bytes_total},
            )
        return context.checkpoint()

    return publish


CacheUpdateHandler = Callable[[OperationContext], str]
CatalogCheckHandler = Callable[[OperationContext], CatalogOperationResult]


class DownloadResponse(Protocol):
    headers: object

    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> "DownloadResponse": ...

    def __exit__(self, *args: object) -> object: ...


DownloadOpener = Callable[[urllib.request.Request, float], DownloadResponse]


def _admitted_download_transition(source_url: str, target_url: str) -> bool:
    """Admit only GitHub's fixed release-asset HTTPS handoff.

    Release download URLs are stable and human-reviewable, but GitHub serves
    their bytes from a short-lived signed URL on one dedicated host. The exact
    size and SHA-256 remain the authority; no other redirect target is allowed.
    """

    try:
        _require_bounded_text(source_url, "download source URL")
        _require_bounded_text(target_url, "download redirect URL", 4096)
        source = urlsplit(source_url)
        target = urlsplit(target_url)
        source_port = source.port
        target_port = target.port
    except ValueError:
        return False
    if (
        source.scheme != "https"
        or target.scheme != "https"
        or source.username is not None
        or source.password is not None
        or target.username is not None
        or target.password is not None
        or source.fragment
        or target.fragment
        or source_port not in (None, 443)
        or target_port not in (None, 443)
    ):
        return False
    source_host = (source.hostname or "").lower()
    target_host = (target.hostname or "").lower()
    return (source_host, target_host) in {
        ("github.com", "release-assets.githubusercontent.com"),
        ("release-assets.githubusercontent.com", "release-assets.githubusercontent.com"),
    }


def _parse_release_location(source_url: str, raw_headers: bytes) -> str:
    if not raw_headers or len(raw_headers) > MAX_DOWNLOAD_CONTROL_BYTES:
        raise OperationError("locked asset response headers are empty or oversized")
    try:
        rendered = raw_headers.decode("iso-8859-1")
    except UnicodeError as exc:  # pragma: no cover - ISO-8859-1 is total
        raise OperationError("locked asset response headers are malformed") from exc
    lines = rendered.replace("\r\n", "\n").split("\n")
    status = [line for line in lines if line.startswith("HTTP/")]
    locations = [line.partition(":")[2].strip() for line in lines if line.lower().startswith("location:")]
    if len(status) != 1 or not re.fullmatch(r"HTTP/(?:1\.[01]|2) 302(?: .*)?", status[0]):
        raise OperationError("locked asset source did not return one exact release redirect")
    if len(locations) != 1 or not _admitted_download_transition(source_url, locations[0]):
        raise OperationError("locked asset source returned an unapproved redirect")
    return locations[0]


def _terminate_download_process(process: subprocess.Popen[bytes]) -> None:
    _terminate_canary(process)


def _run_bounded_curl(
    command: list[str],
    *,
    context: OperationContext,
    timeout_seconds: float,
    progress_path: Path | None = None,
    progress_total: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": "/tmp",
        "NO_COLOR": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    stage: AssetTransportStage = (
        "release_headers" if "--head" in command else "asset_body"
    )
    # Header/file preparation may have consumed time since the wrapper bound.
    # Refuse expired work immediately before allocating an owned process.
    context.checkpoint()
    if isinstance(context, OperationContext):
        timeout_seconds = context.remaining_seconds(timeout_seconds)
        command = list(command)
        for flag in ("--max-time", "--connect-timeout"):
            if flag in command:
                index = command.index(flag) + 1
                command[index] = f"{min(float(command[index]), timeout_seconds):.6f}"
        if "--retry-max-time" in command:
            index = command.index("--retry-max-time") + 1
            # curl before 8.16 accepts only integer retry windows. Zero disables
            # its retry deadline, so subsecond work must instead disable retries.
            retry_seconds = math.floor(min(float(command[index]), timeout_seconds))
            if retry_seconds > 0:
                command[index] = str(retry_seconds)
            else:
                del command[index - 1:index + 1]
                if "--retry" in command:
                    command[command.index("--retry") + 1] = "0"
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        raise AssetTransportError("unavailable", stage) from exc
    started = time.monotonic()
    try:
        while process.poll() is None:
            context.checkpoint()
            if progress_path is not None and progress_total is not None:
                try:
                    observed = min(progress_path.stat().st_size, progress_total)
                except FileNotFoundError:
                    observed = 0
                context.byte_progress(observed, progress_total)
            if time.monotonic() - started > timeout_seconds + 2:
                raise AssetTransportError("deadline", stage)
            time.sleep(0.05)
        stdout, stderr = process.communicate(timeout=1)
    except BaseException:
        _terminate_download_process(process)
        raise
    if len(stdout) + len(stderr) > MAX_DOWNLOAD_CONTROL_BYTES:
        raise AssetTransportError("output_bound", stage, process.returncode)
    if process.returncode != 0:
        raise AssetTransportError("curl_exit", stage, process.returncode)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _download_locked_asset_curl(
    *,
    url: str,
    expected_size: int,
    destination: Path,
    context: OperationContext,
    timeout_seconds: float,
) -> None:
    timeout = (
        context.remaining_seconds(min(timeout_seconds, 300))
        if isinstance(context, OperationContext) else min(timeout_seconds, 300)
    )
    try:
        curl_metadata = CURL_PATH.lstat()
    except OSError as exc:
        raise AssetTransportError("unavailable", "release_headers") from exc
    if (
        not stat.S_ISREG(curl_metadata.st_mode)
        or curl_metadata.st_mode & 0o022
        or not os.access(CURL_PATH, os.X_OK)
    ):
        raise AssetTransportError("unavailable", "release_headers")
    curl = str(CURL_PATH)
    headers = _run_bounded_curl(
        [
            curl,
            "--silent",
            "--show-error",
            "--head",
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--connect-timeout",
            str(min(timeout, 20)),
            "--max-time",
            str(timeout),
            "--retry",
            "3",
            "--retry-all-errors",
            "--retry-delay",
            "1",
            "--retry-max-time",
            str(timeout),
            "--url",
            url,
        ],
        context=context,
        timeout_seconds=float(timeout),
    )
    target = _parse_release_location(url, headers.stdout)
    context.checkpoint()
    if isinstance(context, OperationContext):
        timeout = context.remaining_seconds(timeout)
    _run_bounded_curl(
        [
            curl,
            "--fail",
            "--silent",
            "--show-error",
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--connect-timeout",
            str(min(timeout, 20)),
            "--max-time",
            str(timeout),
            "--retry",
            "3",
            "--retry-all-errors",
            "--retry-delay",
            "1",
            "--retry-max-time",
            str(timeout),
            "--max-filesize",
            str(expected_size),
            "--create-file-mode",
            "0600",
            "--output",
            str(destination),
            "--url",
            target,
        ],
        context=context,
        timeout_seconds=float(timeout),
        progress_path=destination,
        progress_total=expected_size,
    )
    context.byte_progress(expected_size, expected_size, force=True)


def _download_exact_https_asset_curl(
    *,
    url: str,
    expected_size: int,
    destination: Path,
    context: OperationContext,
    timeout_seconds: float,
    allowed_host: str,
) -> None:
    """Download one exact non-redirecting HTTPS asset from a fixed host."""

    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != allowed_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise OperationError("locked data asset URL is outside its admitted host")
    timeout = (
        context.remaining_seconds(min(timeout_seconds, MAX_DATA_COMMAND_SECONDS))
        if isinstance(context, OperationContext) else min(timeout_seconds, MAX_DATA_COMMAND_SECONDS)
    )
    _run_bounded_curl(
        [
            str(CURL_PATH),
            "--fail",
            "--silent",
            "--show-error",
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--connect-timeout",
            str(min(timeout, 20)),
            "--max-time",
            str(timeout),
            "--retry",
            "3",
            "--retry-all-errors",
            "--retry-delay",
            "1",
            "--retry-max-time",
            str(timeout),
            "--max-filesize",
            str(expected_size),
            "--create-file-mode",
            "0600",
            "--output",
            str(destination),
            "--url",
            url,
        ],
        context=context,
        timeout_seconds=float(timeout),
        progress_path=destination,
        progress_total=expected_size,
    )
    context.byte_progress(expected_size, expected_size, force=True)


@dataclass(frozen=True, kw_only=True)
class _DataCommandControl(ExecutionControl):
    context: OperationContext

    def checkpoint(self) -> None:
        self.context.refresh_activity()
        super().checkpoint()


def _run_data_command(
    context: OperationContext,
    command: list[str],
    *,
    command_id: DataCommandId,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float = MAX_DATA_COMMAND_SECONDS,
    stdout_path: Path | None = None,
    expected_exit_code: int = 0,
) -> int:
    """Run a fixed lifecycle command with cancellation and descendant cleanup."""

    if command_id not in _DATA_COMMAND_IDS:
        raise OperationError("invalid scanner data command identity")
    if type(expected_exit_code) is not int or not 0 <= expected_exit_code <= 255:
        raise OperationError("invalid scanner data command expected exit code")
    local_limit_seconds = timeout_seconds
    preparation_budget = None
    if isinstance(context, OperationContext):
        timeout_seconds = context.remaining_seconds(timeout_seconds)
        preparation_budget = context.request.preparation_budget
    output_handle: BinaryIO | None = None
    try:
        if stdout_path is not None:
            if stdout_path.exists() or stdout_path.is_symlink():
                raise OperationError("scanner data command output already exists")
            output_handle = stdout_path.open("xb")
        started = time.monotonic()
        try:
            completed = run_captured_command(
                command,
                cwd=cwd,
                env=environment,
                timeout=timeout_seconds,
                control=_DataCommandControl(
                    cancel_event=threading.Event(),
                    deadline_monotonic=time.monotonic() + timeout_seconds,
                    context=context,
                ),
                max_output_bytes=MAX_DATA_COMMAND_OUTPUT_BYTES,
                stdin=subprocess.DEVNULL,
            )
        except CapturedCommandOutputLimitError as exc:
            raise DataCommandOutputLimitError(command_id, exc.limit_bytes) from exc
        except (subprocess.TimeoutExpired, RunDeadlineExceeded) as exc:
            raise OperationError("scanner data command exceeded its time bound") from exc
        except OSError as exc:
            raise OperationError("scanner data command is unavailable") from exc
        finished = time.monotonic()
        if output_handle is not None:
            output_handle.write(completed.stdout.encode("utf-8", errors="surrogateescape"))
        if completed.returncode != expected_exit_code:
            # Use the already-admitted bound. A second budget read could mask the
            # actual child failure with expiry and must never renew this command.
            def bounded_ms(seconds: float) -> int:
                return int(min(86_400_000, max(0, seconds * 1000)))

            elapsed_seconds = finished - started
            timing = DataCommandTiming(
                elapsed_ms=bounded_ms(elapsed_seconds),
                effective_timeout_ms=bounded_ms(timeout_seconds),
                local_limit_ms=bounded_ms(local_limit_seconds),
                preparation_budget_ms=(int((
                    budget_moment(preparation_budget.deadline_at)
                    - budget_moment(preparation_budget.issued_at)
                ).total_seconds() * 1000) if preparation_budget is not None else None),
                capped=any(value < 0 or value > 86_400 for value in
                           (elapsed_seconds, timeout_seconds, local_limit_seconds)),
            )
            raise DataCommandFailureError(command_id, completed.returncode, completed.stderr,
                                          timing=timing)
        return int(completed.returncode)
    finally:
        if output_handle is not None:
            output_handle.close()


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _admitted_download_transition(req.full_url, newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_open(request: urllib.request.Request, timeout: float) -> DownloadResponse:
    # Updater egress is defined entirely by immutable lock URLs.  Never inherit
    # HTTP(S) proxy variables from the host/container environment: a proxy is
    # another mutable network authority and could observe or redirect catalog
    # and artifact requests despite the redirect handler below.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _StrictRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)  # type: ignore[return-value]


def _safe_direct_child(root: Path, name: str, label: str) -> Path:
    _require_relative_path(name, label)
    if "/" in name:
        raise OperationError(f"{label} must be one direct child")
    candidate = root / name
    if candidate.parent != root:
        raise OperationError(f"{label} escapes its root")
    return candidate


def download_locked_asset(
    *,
    url: str,
    expected_sha256: str,
    expected_size: int,
    destination: Path,
    context: OperationContext,
    timeout_seconds: float,
    opener: DownloadOpener = _default_open,
) -> None:
    """Download one exact lock-owned asset without proxy or open redirects."""

    if expected_size <= 0 or expected_size > MAX_DOWNLOAD_BYTES:
        raise OperationError("locked asset size is outside the updater bound")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise OperationError("locked asset digest is malformed")
    if not url.startswith("https://"):
        raise OperationError("locked asset URL is not HTTPS")
    if isinstance(context, OperationContext):
        timeout_seconds = context.remaining_seconds(timeout_seconds)
    if destination.exists() or destination.is_symlink():
        raise OperationError("locked asset destination already exists")
    if opener is _default_open:
        try:
            _download_locked_asset_curl(
                url=url,
                expected_size=expected_size,
                destination=destination,
                context=context,
                timeout_seconds=timeout_seconds,
            )
            metadata = destination.lstat()
            if destination.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise OperationError("locked asset transport produced an unsafe file")
            observed = metadata.st_size
            digest = hashlib.sha256()
            with destination.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    context.checkpoint()
                    digest.update(chunk)
            if observed != expected_size or digest.hexdigest() != expected_sha256:
                raise OperationError("locked asset checksum or size does not match its lock")
            destination.chmod(0o400)
            return
        except Exception:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "*/*",
            "User-Agent": "kodesec-updater/1 curl/8.10.1",
        },
    )
    digest = hashlib.sha256()
    observed = 0
    descriptor = -1
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with opener(request, timeout_seconds) as response:
            final_url = getattr(response, "geturl", lambda: url)()
            if final_url != url and not _admitted_download_transition(url, final_url):
                raise OperationError("locked asset request used an unapproved redirect")
            while True:
                context.checkpoint()
                chunk = response.read(min(1024 * 1024, expected_size + 1 - observed))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > expected_size:
                    raise OperationError("locked asset exceeds its exact size")
                context.byte_progress(observed, expected_size)
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    count = os.write(descriptor, chunk[offset:])
                    if count <= 0:
                        raise OperationError("locked asset write made no progress")
                    offset += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        if observed != expected_size or digest.hexdigest() != expected_sha256:
            raise OperationError("locked asset checksum or size does not match its lock")
        context.byte_progress(expected_size, expected_size, force=True)
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def extract_locked_tar_gz(
    archive: Path,
    destination: Path,
    context: OperationContext,
    *,
    maximum_files: int = MAX_ARCHIVE_ENTRIES,
    maximum_bytes: int = MAX_DOWNLOAD_BYTES,
) -> None:
    """Extract a digest-verified tarball with strict path and type admission."""

    if destination.exists() or destination.is_symlink():
        raise OperationError("archive destination already exists")
    destination.mkdir(mode=0o700, parents=False)
    total = 0
    files = 0
    seen: set[str] = set()
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            for member in bundle:
                context.checkpoint()
                name = member.name.removeprefix("./")
                if name.endswith("/"):
                    name = name.rstrip("/")
                if not name:
                    continue
                try:
                    _require_relative_path(name, "archive member")
                except ValueError as exc:
                    raise OperationError("archive contains an unsafe path") from exc
                if len(name.split("/")) > MAX_ARCHIVE_DEPTH or name in seen:
                    raise OperationError("archive member depth or identity is unsafe")
                seen.add(name)
                target = destination / name
                try:
                    target.resolve(strict=False).relative_to(destination.resolve(strict=True))
                except (OSError, RuntimeError, ValueError) as exc:
                    raise OperationError("archive member escapes its destination") from exc
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise OperationError("archive contains a link or special entry")
                files += 1
                total += member.size
                if files > maximum_files or total > maximum_bytes:
                    raise OperationError("archive exceeds its extraction bound")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                extracted = bundle.extractfile(member)
                if extracted is None:
                    raise OperationError("archive regular file cannot be read")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                )
                observed = 0
                try:
                    while True:
                        chunk = extracted.read(min(1024 * 1024, member.size + 1 - observed))
                        if not chunk:
                            break
                        observed += len(chunk)
                        if observed > member.size:
                            raise OperationError("archive member exceeds its header size")
                        offset = 0
                        while offset < len(chunk):
                            count = os.write(descriptor, chunk[offset:])
                            if count <= 0:
                                raise OperationError("archive extraction made no progress")
                            offset += count
                    os.fsync(descriptor)
                    os.fchmod(descriptor, 0o400)
                finally:
                    os.close(descriptor)
                    extracted.close()
                if observed != member.size:
                    raise OperationError("archive member size differs from its header")
        if not files:
            raise OperationError("archive contains no regular files")
        for current, directories, _files in os.walk(destination, topdown=False):
            for directory in directories:
                (Path(current) / directory).chmod(0o500)
        destination.chmod(0o500)
    except Exception:
        _remove_private_staging_tree(destination)
        raise


def _remove_private_staging_tree(root: Path) -> None:
    """Remove one updater-owned staging tree without following aliases."""

    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationError("operation staging tree cannot be inspected") from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise OperationError("operation staging tree is unsafe")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise OperationError("operation staging tree cannot be resolved") from exc
    observed = 0
    try:
        for directory, child_directories, child_files in os.walk(
            root,
            topdown=False,
            followlinks=False,
        ):
            current = Path(directory)
            current.resolve(strict=True).relative_to(resolved_root)
            current.chmod(0o700)
            for name in child_files:
                observed += 1
                if observed > MAX_STAGING_ENTRIES:
                    raise OperationError("operation staging cleanup exceeds its bound")
                child = current / name
                child_metadata = child.lstat()
                if not (stat.S_ISREG(child_metadata.st_mode) or child.is_symlink()):
                    raise OperationError("operation staging tree contains a special file")
                child.unlink()
            for name in child_directories:
                observed += 1
                if observed > MAX_STAGING_ENTRIES:
                    raise OperationError("operation staging cleanup exceeds its bound")
                child = current / name
                child_metadata = child.lstat()
                if child.is_symlink():
                    child.unlink()
                elif stat.S_ISDIR(child_metadata.st_mode):
                    child.chmod(0o700)
                    child.rmdir()
                else:
                    raise OperationError("operation staging tree contains a special entry")
        root.rmdir()
    except (OSError, RuntimeError, ValueError) as exc:
        raise OperationError("operation staging tree could not be removed safely") from exc


def canonical_canary_output_sha256(
    *,
    canary_id: str,
    fixture_sha256: str,
    exit_code: int,
    result_count: int,
    rule_ids: list[str],
) -> str:
    """Hash the scanner-independent semantic canary result contract."""

    _require_identifier(canary_id, "canary id")
    if not re.fullmatch(r"[0-9a-f]{64}", fixture_sha256):
        raise OperationError("canary fixture digest is malformed")
    normalized_ids = sorted(set(rule_ids))
    if normalized_ids != rule_ids:
        raise OperationError("canary rule ids must be sorted and unique")
    payload = {
        "algorithm": CANARY_OUTPUT_HASH_ALGORITHM,
        "canary_id": canary_id,
        "exit_code": exit_code,
        "fixture_sha256": fixture_sha256,
        "result_count": result_count,
        "rule_ids": normalized_ids,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _verify_exact_file(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    context: OperationContext,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OperationError("locked data asset is missing") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise OperationError("locked data asset is unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            context.checkpoint()
            digest.update(chunk)
    if metadata.st_size != expected_size or digest.hexdigest() != expected_sha256:
        raise OperationError("locked data asset checksum or size differs from its lock")
    path.chmod(0o400)


def _download_direct_locked_asset(
    *,
    requirement: ComponentRequirementLock,
    destination: Path,
    context: OperationContext,
    timeout_seconds: float,
    allowed_host: str,
) -> None:
    source = requirement.source
    if not source.immutable_ref or not source.sha256 or not source.size_bytes:
        raise OperationError("locked data asset identity is incomplete")
    if destination.exists() or destination.is_symlink():
        raise OperationError("locked data asset destination already exists")
    try:
        _download_exact_https_asset_curl(
            url=source.immutable_ref,
            expected_size=source.size_bytes,
            destination=destination,
            context=context,
            timeout_seconds=timeout_seconds,
            allowed_host=allowed_host,
        )
        _verify_exact_file(
            destination,
            expected_size=source.size_bytes,
            expected_sha256=source.sha256,
            context=context,
        )
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _component_fixture_path(canary: ComponentCanaryLock) -> Path:
    root = Path("/usr/local/share/kodesec/canaries")
    candidate = root / canary.fixture_path
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise OperationError("data canary fixture is unavailable") from exc
    return candidate


def _verify_component_fixture(canary: ComponentCanaryLock, path: Path) -> None:
    if canary.fixture_kind == "tree":
        observed = collect_canonical_tree(path, require_immutable=True)
        if (
            observed.algorithm != canary.fixture_hash_algorithm
            or observed.sha256 != canary.fixture_sha256
        ):
            raise OperationError("data canary fixture tree differs from its lock")
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OperationError("data canary fixture file is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o222
        or metadata.st_nlink != 1
    ):
        raise OperationError("data canary fixture file is unsafe")
    if hashlib.sha256(path.read_bytes()).hexdigest() != canary.fixture_sha256:
        raise OperationError("data canary fixture file differs from its lock")


def _load_command_json(path: Path, label: str) -> dict[str, object]:
    try:
        raw = _read_bounded_regular_file(path, MAX_CANARY_OUTPUT_BYTES, label)
        return _decode_json_object(raw, label)
    except (CacheValidationError, LockValidationError) as exc:
        raise OperationError(f"{label} is invalid") from exc


def _trivy_result_semantics(path: Path, category: str) -> tuple[int, list[str]]:
    payload = _load_command_json(path, "Trivy canary output")
    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise OperationError("Trivy canary output is invalid")
    ids: list[str] = []
    count = 0
    key = "Misconfigurations" if category == "misconfiguration" else "Vulnerabilities"
    id_key = "ID" if category == "misconfiguration" else "VulnerabilityID"
    for result in results:
        if not isinstance(result, dict):
            raise OperationError("Trivy canary result is invalid")
        entries = result.get(key, []) or []
        if not isinstance(entries, list):
            raise OperationError("Trivy canary result is invalid")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get(id_key), str):
                raise OperationError("Trivy canary result lacks an exact id")
            ids.append(entry[id_key])
            count += 1
            if count > 10_000:
                raise OperationError("Trivy canary result count exceeds its bound")
    return count, sorted(set(ids))


def _grype_result_semantics(path: Path) -> tuple[int, list[str]]:
    payload = _load_command_json(path, "Grype canary output")
    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        raise OperationError("Grype canary output is invalid")
    ids: list[str] = []
    for match in matches:
        vulnerability = match.get("vulnerability") if isinstance(match, dict) else None
        identifier = vulnerability.get("id") if isinstance(vulnerability, dict) else None
        if not isinstance(identifier, str):
            raise OperationError("Grype canary result lacks an exact id")
        ids.append(identifier)
        if len(ids) > 10_000:
            raise OperationError("Grype canary result count exceeds its bound")
    return len(ids), sorted(set(ids))


def _data_environment(scratch: Path) -> dict[str, str]:
    home = scratch / "home"
    cache = scratch / "xdg-cache"
    config = scratch / "xdg-config"
    for directory in (home, cache, config):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "HOME": str(home),
        "NO_COLOR": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": str(scratch),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_VALIDATE_AGE": "true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": (
            f"{REVIEWED_DATA_HARD_VALIDITY_SECONDS}s"
        ),
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }


def _copy_exact_tree(
    source: Path,
    destination: Path,
    records: list[CacheFileRecord],
    checkpoint: Callable[[], object] | None = None,
    byte_progress: Callable[[int, int], object] | None = None,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise OperationError("component destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    source_root = source.resolve(strict=True)
    bytes_since_checkpoint = 0
    copied_bytes = 0
    total_bytes = sum(record.size_bytes for record in records)
    if checkpoint is not None:
        checkpoint()
    if byte_progress is not None and total_bytes > 0:
        byte_progress(0, total_bytes)
    for record in records:
        origin = source_root / record.path
        target = destination / record.path
        try:
            origin.resolve(strict=True).relative_to(source_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise OperationError("component source file escapes its immutable root") from exc
        metadata = origin.lstat()
        if origin.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OperationError("component source contains an unsafe file")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with origin.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    digest.update(chunk)
                    offset = 0
                    while offset < len(chunk):
                        count = os.write(descriptor, chunk[offset:])
                        if count <= 0:
                            raise OperationError("component copy made no progress")
                        offset += count
                    bytes_since_checkpoint += len(chunk)
                    copied_bytes += len(chunk)
                    if byte_progress is not None and total_bytes > 0:
                        byte_progress(copied_bytes, total_bytes)
                    if (
                        checkpoint is not None
                        and bytes_since_checkpoint >= GENERATION_HASH_CHECKPOINT_BYTES
                    ):
                        checkpoint()
                        bytes_since_checkpoint = 0
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        if total != record.size_bytes or digest.hexdigest() != record.sha256:
            raise OperationError("component source changed while it was promoted")
    for current, directories, _files in os.walk(destination, topdown=False):
        for directory in directories:
            (Path(current) / directory).chmod(0o500)
    destination.chmod(0o500)
    if copied_bytes != total_bytes:
        raise OperationError("component copy size differs from its reviewed receipt")
    if checkpoint is not None:
        checkpoint()


def _prefixed_records(root: str, records: list[CacheFileRecord] | tuple[CacheFileRecord, ...]) -> list[CacheFileRecord]:
    return [
        CacheFileRecord(
            path=f"{root}/{record.path}",
            size_bytes=record.size_bytes,
            sha256=record.sha256,
        )
        for record in records
    ]


def _copy_validated_component(
    source_generation: ValidatedGeneration,
    receipt: CacheComponentReceipt,
    stage: Path,
    checkpoint: Callable[[], object] | None = None,
    byte_progress: Callable[[int, int], object] | None = None,
) -> CacheComponentReceipt:
    source = source_generation.path / receipt.root
    relative_records = [
        CacheFileRecord(
            path=record.path.removeprefix(receipt.root + "/"),
            size_bytes=record.size_bytes,
            sha256=record.sha256,
        )
        for record in receipt.files
    ]
    _copy_exact_tree(
        source,
        stage / receipt.root,
        relative_records,
        checkpoint,
        byte_progress,
    )
    return receipt


def _timestamp_plus(value: str, seconds: int) -> str:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OperationError("scanner data timestamp is invalid") from exc
    return (parsed.astimezone(UTC) + timedelta(seconds=seconds)).isoformat().replace(
        "+00:00", "Z"
    )


def _runtime_linux_platform() -> Literal[
    "linux/amd64", "linux/arm64", "unsupported"
]:
    """Return the updater's normalized producer platform without host input."""

    if platform.system() != "Linux":
        return "unsupported"
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "linux/amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux/arm64"
    return "unsupported"


def _validate_installed_content(
    observed: CanonicalTree,
    requirement: ComponentRequirementLock,
    *,
    grype_logical_content: GrypeLogicalContentReceipt | None = None,
) -> None:
    expected = requirement.installed_content
    if expected is None or requirement.installed_size_bytes is None:
        raise OperationError("scanner data installed-content lock is incomplete")
    volatile = set(expected.volatile_paths)
    records = {item.path: item for item in observed.files}
    if not volatile.issubset(records):
        raise OperationError("scanner data volatile metadata is missing")
    if any(records[path].size_bytes <= 0 or records[path].size_bytes > 4096 for path in volatile):
        raise OperationError("scanner data volatile metadata exceeds its strict bound")
    stable = [item for item in observed.files if item.path not in volatile]
    hash_algorithm = observed.algorithm
    if expected.hash_algorithm == GRYPE_LOGICAL_TREE_HASH_ALGORITHM:
        if grype_logical_content is None:
            raise OperationError("Grype logical installed-content evidence is missing")
        stable = grype_logical_tree_records(stable, grype_logical_content)
        hash_algorithm = GRYPE_LOGICAL_TREE_HASH_ALGORITHM
    elif grype_logical_content is not None:
        raise OperationError("unexpected logical installed-content evidence")
    stable_size = sum(item.size_bytes for item in stable)
    stable_sha256 = canonical_tree_sha256(stable)
    if (
        expected.hash_algorithm != hash_algorithm
        or stable_sha256 != expected.sha256
        or len(stable) != expected.file_count
        or stable_size != expected.size_bytes
    ):
        raise InstalledContentMismatchError(
            InstalledContentFailureEvidence(
                kind="installed_content_mismatch",
                component_id=requirement.id,
                runtime_platform=_runtime_linux_platform(),
                hash_algorithm=hash_algorithm,
                expected_sha256=expected.sha256,
                observed_sha256=stable_sha256,
                expected_file_count=expected.file_count,
                observed_file_count=len(stable),
                expected_size_bytes=expected.size_bytes,
                observed_size_bytes=stable_size,
            ),
            files=tuple(item for item in observed.files if item.path not in volatile),
        )
    # `installed_size_bytes` is a capacity estimate captured from qualification.
    # Only the explicitly allowlisted metadata may vary, and by at most one
    # bounded file each; immutable payload bytes remain exact above.
    if (
        observed.size_bytes < stable_size + len(volatile)
        or observed.size_bytes
        > requirement.installed_size_bytes + 4096 * len(volatile)
    ):
        raise OperationError("scanner installed data size exceeds its reviewed bound")


def _data_update_capacity_preflight(
    root: Path,
    resolved: object,
    requested: list[str],
    requirements: dict[str, tuple[str, ComponentRequirementLock]],
) -> None:
    requested_set = set(requested)
    carried = 0
    generation = getattr(resolved, "generation", None)
    if generation is not None:
        carried = sum(
            record.size_bytes
            for receipt in generation.manifest.components
            if receipt.component_id not in requested_set
            for record in receipt.files
        )
    installed = sum(
        int(requirements[item][1].installed_size_bytes or 0) for item in requested
    )
    downloads = sum(int(requirements[item][1].source.size_bytes or 0) for item in requested)
    grype_import_workspace = max(
        (
            int(requirements[item][1].installed_size_bytes or 0)
            for item in requested
            if item == "grype-db"
        ),
        default=0,
    )
    # Grype imports its compressed archive through a temporary database tree
    # before the verified tree is sealed in the candidate generation. Reserve
    # one additional installed-size bound for that day-one staging workspace.
    required = (
        carried
        + installed
        + downloads
        + grype_import_workspace
        + MIN_DATA_UPDATE_MARGIN_BYTES
    )
    filesystem = os.statvfs(root)
    available = filesystem.f_bavail * filesystem.f_frsize
    if available < required:
        raise OperationCapacityError("scanner data update lacks safe staging capacity")


def _previous_data_for_missing_components(
    root: Path,
    resolved: ResolvedGeneration,
    requested: list[str],
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    context: OperationContext,
    *,
    evaluated_at: datetime,
) -> tuple[ValidatedGeneration | None, dict[str, CacheComponentReceipt]]:
    """Reuse only missing data from the pinned, independently verified rollback tree.

    The caller holds the generation lock. This does not refresh an installed
    component or change a database's age; requested canaries run again after
    the rehashed copy joins the other staged components.
    """
    if (resolved.state != "ready" or resolved.generation is None
            or resolved.pointer is None or resolved.pointer.previous_good is None):
        return None, {}
    present = {item.component_id for item in resolved.generation.manifest.components}
    data_ids = {
        item.id for tool in tools.value.tools for item in tool.requirements
        if item.kind != "rules"
    }
    missing = set(requested).intersection(data_ids) - present
    if not missing:
        return None, {}
    reference = resolved.pointer.previous_good
    previous = validate_generation(
        root,
        reference.generation_id,
        expected_manifest_sha256=reference.manifest_sha256,
        checkpoint=context.checkpoint,
        progress=_generation_progress(context, "retaining"),
    )
    reusable: dict[str, CacheComponentReceipt] = {}
    for receipt in previous.manifest.components:
        if receipt.component_id not in missing:
            continue
        context.checkpoint()
        try:
            _validate_component_receipts(
                [receipt], [receipt.component_id], tools, rules,
                evaluated_at=evaluated_at,
            )
        except OperationError:
            # A valid old generation can contain a different or expired data
            # identity. Acquire the currently reviewed source in that case.
            continue
        reusable[receipt.component_id] = receipt
    return previous, reusable


def _stage_trivy_component(
    context: OperationContext,
    requirement: ComponentRequirementLock,
    *,
    payload: Path,
    operation_stage: Path,
    progress_context: dict[str, object] | None = None,
) -> StagedDataComponent:
    if not requirement.cache_subpath or not requirement.source.immutable_ref:
        raise OperationError("Trivy component lock is incomplete")
    cache = payload / "trivy"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch = operation_stage / "trivy-runtime"
    scratch.mkdir(mode=0o700, exist_ok=True)
    environment = _data_environment(scratch)
    common = [
        "trivy",
        "image",
        "--cache-dir",
        str(cache),
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
    ]
    if requirement.id == "trivy-db":
        command = [
            *common,
            "--db-repository",
            requirement.source.immutable_ref,
            "--download-db-only",
        ]
    elif requirement.id == "trivy-java-db":
        command = [
            *common,
            "--java-db-repository",
            requirement.source.immutable_ref,
            "--download-java-db-only",
        ]
    elif requirement.id == "trivy-checks":
        fixture = Path("/usr/local/share/kodesec/canaries/iac/positive")
        output = operation_stage / "trivy-checks-download.json"
        command = [
            "trivy",
            "fs",
            "--cache-dir",
            str(cache),
            "--checks-bundle-repository",
            requirement.source.immutable_ref,
            "--format",
            "json",
            "--output",
            str(output),
            "--scanners",
            "misconfig",
            "--skip-db-update",
            "--skip-java-db-update",
            "--disable-telemetry",
            "--skip-version-check",
            str(fixture),
        ]
    else:  # pragma: no cover - strict component catalog guard
        raise OperationError("unsupported Trivy data component")
    _run_data_command(
        context,
        command,
        command_id="trivy-promotion",
        cwd=payload,
        environment=environment,
    )
    if progress_context is not None:
        context.progress("validating_source", **progress_context)
    component_root = payload / requirement.cache_subpath
    metadata_path = component_root / "metadata.json"
    metadata = _load_command_json(metadata_path, "Trivy component metadata")
    if requirement.id == "trivy-db":
        contract = requirement.data_contract
        if not isinstance(contract, TrivyDatabaseDataContract):
            raise OperationError("Trivy vulnerability DB contract is invalid")
        observed_version = metadata.get("Version")
        if (
            type(observed_version) is not int
            or observed_version != contract.schema_version
        ):
            raise OperationError("Trivy vulnerability DB schema differs from its lock")
        updated_at = str(metadata.get("UpdatedAt", ""))
        refresh_due_at = str(metadata.get("NextUpdate", ""))
        if (
            updated_at != contract.publisher_updated_at
            or refresh_due_at != contract.publisher_refresh_due_at
        ):
            raise OperationError("Trivy vulnerability DB metadata differs from its lock")
        expires_at = _timestamp_plus(
            updated_at,
            int(requirement.max_age_seconds or 0),
        )
    elif requirement.id == "trivy-java-db":
        contract = requirement.data_contract
        if not isinstance(contract, TrivyJavaDatabaseDataContract):
            raise OperationError("Trivy Java DB contract is invalid")
        observed_version = metadata.get("Version")
        if (
            type(observed_version) is not int
            or observed_version != contract.schema_version
        ):
            raise OperationError("Trivy Java DB schema differs from its lock")
        updated_at = str(metadata.get("UpdatedAt", ""))
        refresh_due_at = str(metadata.get("NextUpdate", ""))
        if (
            updated_at != contract.publisher_updated_at
            or refresh_due_at != contract.publisher_refresh_due_at
        ):
            raise OperationError("Trivy Java DB metadata differs from its lock")
        expires_at = _timestamp_plus(
            updated_at,
            int(requirement.max_age_seconds or 0),
        )
    else:
        contract = requirement.data_contract
        if not isinstance(contract, TrivyChecksDataContract):
            raise OperationError("Trivy checks contract is invalid")
        observed_major_version = metadata.get("MajorVersion")
        if (
            type(observed_major_version) is not int
            or observed_major_version != contract.major_version
            or metadata.get("Digest") != f"sha256:{requirement.source.sha256}"
        ):
            raise OperationError("Trivy checks identity differs from its lock")
        updated_at = str(metadata.get("DownloadedAt", ""))
        expires_at = _timestamp_plus(updated_at, int(requirement.max_age_seconds or 0))
    observed = collect_canonical_tree(component_root)
    _validate_installed_content(observed, requirement)
    # Model construction performs strict timestamp and max-age validation later.
    return StagedDataComponent(
        tool_id="trivy",
        requirement=requirement,
        updated_at=updated_at,
        expires_at=expires_at,
        files=list(observed.files),
    )


def _stage_grype_component(
    context: OperationContext,
    requirement: ComponentRequirementLock,
    *,
    payload: Path,
    operation_stage: Path,
    timeout_seconds: float,
    progress_context: dict[str, object] | None = None,
) -> StagedDataComponent:
    if not requirement.cache_subpath:
        raise OperationError("Grype component lock is incomplete")
    archive = operation_stage / "grype-vulnerability-db.tar.zst"
    _download_direct_locked_asset(
        requirement=requirement,
        destination=archive,
        context=context,
        timeout_seconds=max(timeout_seconds, MAX_DATA_COMMAND_SECONDS),
        allowed_host="grype.anchore.io",
    )
    if progress_context is not None:
        context.progress("validating_source", **progress_context)
    database = payload / requirement.cache_subpath
    database.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch = operation_stage / "grype-runtime"
    scratch.mkdir(mode=0o700, exist_ok=True)
    environment = _data_environment(scratch)
    environment["GRYPE_DB_CACHE_DIR"] = str(database)
    _run_data_command(
        context,
        ["grype", "db", "import", str(archive)],
        command_id="grype-import",
        cwd=payload,
        environment=environment,
    )
    if any(database.glob("tmp-*")):
        raise OperationError("Grype database import left transient state")
    status_path = operation_stage / "grype-status.json"
    _run_data_command(
        context,
        ["grype", "db", "status", "-o", "json"],
        command_id="grype-status",
        cwd=payload,
        environment=environment,
        stdout_path=status_path,
    )
    status_payload = _load_command_json(status_path, "Grype database status")
    contract = requirement.data_contract
    if not isinstance(contract, GrypeDatabaseDataContract):
        raise OperationError("Grype database contract is invalid")
    if (
        status_payload.get("valid") is not True
        or status_payload.get("schemaVersion") != contract.schema_version
        or status_payload.get("built") != contract.built_at
    ):
        raise OperationError("Grype database identity differs from its lock")
    observed = collect_canonical_tree(database)
    logical_content = None
    if (
        requirement.installed_content is not None
        and requirement.installed_content.hash_algorithm == GRYPE_LOGICAL_TREE_HASH_ALGORITHM
    ):
        logical_content = verify_grype_logical_content(
            database, observed.files, checkpoint=context.refresh_activity
        )
    _validate_installed_content(
        observed, requirement, grype_logical_content=logical_content
    )
    updated_at = contract.built_at
    return StagedDataComponent(
        tool_id="grype",
        requirement=requirement,
        updated_at=updated_at,
        expires_at=_timestamp_plus(updated_at, int(requirement.max_age_seconds or 0)),
        files=list(observed.files),
        grype_logical_content=logical_content,
    )


def _run_data_canaries(
    context: OperationContext,
    staged: StagedDataComponent,
    *,
    payload: Path,
    scratch_root: Path,
) -> list[CanaryReceipt]:
    receipts: list[CanaryReceipt] = []
    scratch_root = _secure_directory(scratch_root, "updater scratch root", create=True)
    requirement = staged.requirement
    for canary in requirement.canaries:
        fixture = _component_fixture_path(canary)
        _verify_component_fixture(canary, fixture)
        context.checkpoint()
        with tempfile.TemporaryDirectory(prefix="data-canary-", dir=scratch_root) as temporary:
            scratch = Path(temporary)
            scratch.chmod(0o700)
            environment = _data_environment(scratch)
            output = scratch / "result.json"
            if staged.tool_id == "trivy":
                cache = payload / "trivy"
                if requirement.id == "trivy-db":
                    command = [
                        "trivy",
                        "fs",
                        "--quiet",
                        "--cache-dir",
                        str(cache),
                        "--format",
                        "json",
                        "--output",
                        str(output),
                        "--scanners",
                        "vuln",
                        "--offline-scan",
                        "--skip-db-update",
                        "--skip-java-db-update",
                        "--skip-check-update",
                        "--disable-telemetry",
                        "--skip-version-check",
                        str(fixture),
                    ]
                    category = "vulnerability"
                elif requirement.id == "trivy-java-db":
                    command = [
                        "trivy",
                        "rootfs",
                        "--quiet",
                        "--cache-dir",
                        str(cache),
                        "--format",
                        "json",
                        "--output",
                        str(output),
                        "--scanners",
                        "vuln",
                        "--pkg-types",
                        "library",
                        "--parallel",
                        "1",
                        "--offline-scan",
                        "--skip-db-update",
                        "--skip-java-db-update",
                        "--skip-check-update",
                        "--disable-telemetry",
                        "--skip-version-check",
                        str(fixture),
                    ]
                    category = "vulnerability"
                elif requirement.id == "trivy-checks":
                    command = [
                        "trivy",
                        "fs",
                        "--quiet",
                        "--cache-dir",
                        str(cache),
                        "--format",
                        "json",
                        "--output",
                        str(output),
                        "--scanners",
                        "misconfig",
                        "--offline-scan",
                        "--skip-db-update",
                        "--skip-java-db-update",
                        "--skip-check-update",
                        "--disable-telemetry",
                        "--skip-version-check",
                        str(fixture),
                    ]
                    category = "misconfiguration"
                else:  # pragma: no cover - strict component catalog guard
                    raise OperationError("unsupported Trivy canary component")
                exit_code = _run_data_command(
                    context,
                    command,
                    command_id="trivy-canary",
                    cwd=payload,
                    environment=environment,
                    expected_exit_code=canary.expected_exit_code,
                )
                result_count, observed_ids = _trivy_result_semantics(output, category)
            elif staged.tool_id == "grype":
                sbom = scratch / "fixture.cyclonedx.json"
                _run_data_command(
                    context,
                    ["syft", f"dir:{fixture}", "-o", f"cyclonedx-json={sbom}"],
                    command_id="syft-canary",
                    cwd=payload,
                    environment=environment,
                )
                environment["GRYPE_DB_CACHE_DIR"] = str(payload / requirement.cache_subpath)
                exit_code = _run_data_command(
                    context,
                    ["grype", f"sbom:{sbom}", "-o", "json", "--file", str(output)],
                    command_id="grype-canary",
                    cwd=payload,
                    environment=environment,
                    expected_exit_code=canary.expected_exit_code,
                )
                result_count, observed_ids = _grype_result_semantics(output)
            else:  # pragma: no cover - strict staging type guard
                raise OperationError("unsupported data canary tool")
            digest = canonical_canary_output_sha256(
                canary_id=canary.id,
                fixture_sha256=canary.fixture_sha256,
                exit_code=exit_code,
                result_count=result_count,
                rule_ids=observed_ids,
            )
            if (
                exit_code != canary.expected_exit_code
                or result_count != canary.expected_result_count
                or observed_ids != canary.expected_ids
                or digest != canary.output_sha256
            ):
                raise OperationError("data canary semantic output differs from its lock")
            receipts.append(
                CanaryReceipt(
                    canary_id=canary.id,
                    fixture_sha256=canary.fixture_sha256,
                    output_sha256=digest,
                    exit_code=exit_code,
                    result_count=result_count,
                    expected_ids=canary.expected_ids,
                    observed_ids=observed_ids,
                    passed=True,
                )
            )
    return receipts


def _baked_canary_path(canary: RuleCanaryLock) -> Path:
    prefix = "tests/scanner-runtime/fixtures/"
    if not canary.fixture_path.startswith(prefix):
        raise OperationError("rules canary fixture is outside the immutable fixture catalog")
    relative = canary.fixture_path.removeprefix(prefix)
    try:
        _require_relative_path(relative, "baked canary path")
    except ValueError as exc:
        raise OperationError("rules canary fixture path is unsafe") from exc
    root = Path("/usr/local/share/kodesec/canaries")
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OperationError("immutable rules canary fixture is unavailable") from exc
    return resolved


def _verify_canary_fixture(canary: RuleCanaryLock, path: Path) -> None:
    if canary.fixture_kind == "tree":
        observed = collect_canonical_tree(path, require_immutable=True)
        if (
            observed.algorithm != canary.fixture_hash_algorithm
            or observed.sha256 != canary.fixture_sha256
        ):
            raise OperationError("rules canary fixture tree differs from its lock")
        return
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222:
        raise OperationError("rules canary fixture file is unsafe or writable")
    if metadata.st_nlink != 1:
        raise OperationError("rules canary fixture file is hard-linked")
    if hashlib.sha256(path.read_bytes()).hexdigest() != canary.fixture_sha256:
        raise OperationError("rules canary fixture file differs from its lock")


def _terminate_canary(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, 15)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        raise OperationError("rules canary process could not be cleaned up") from exc


def _parse_sarif_semantics(path: Path) -> tuple[int, list[str]]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise OperationError("rules canary omitted its required SARIF output")
    if metadata.st_size <= 0 or metadata.st_size > MAX_CANARY_OUTPUT_BYTES:
        raise OperationError("rules canary SARIF output is empty or oversized")
    raw = path.read_bytes()
    first = raw.find(b"{")
    if first < 0:
        raise OperationError("rules canary SARIF output is malformed")
    try:
        payload = json.loads(raw[first:])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationError("rules canary SARIF output is malformed") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise OperationError("rules canary SARIF output is malformed")
    ids: list[str] = []
    count = 0
    for run in payload["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise OperationError("rules canary SARIF output is malformed")
        for result in run.get("results", []):
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise OperationError("rules canary SARIF result lacks an exact rule id")
            rule_id = result["ruleId"]
            _require_bounded_text(rule_id, "rules canary result id", 256)
            ids.append(rule_id)
            count += 1
            if count > 10_000:
                raise OperationError("rules canary result count exceeds its bound")
    return count, sorted(set(ids))


def _parse_bearer_semantics(path: Path) -> tuple[int, list[str]]:
    """Require the same complete JSONV2 envelope as ordinary source scans."""
    try:
        raw = _read_bounded_regular_file(path, MAX_CANARY_OUTPUT_BYTES, "Bearer canary output")
        findings = _bearer_jsonv2_findings(raw)
    except (OSError, CacheValidationError, BearerReportError) as exc:
        code = exc.code if isinstance(exc, BearerReportError) else "bearer_native_report_invalid"
        raise OperationError(code) from None
    if len(findings) > 10_000:
        raise OperationError("Bearer canary result count exceeds its bound")
    ids: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
            raise OperationError("Bearer canary result lacks an exact rule id")
        _require_bounded_text(finding["id"], "Bearer canary result id", 256)
        ids.append(finding["id"])
    return len(findings), sorted(set(ids))


def run_rule_canaries(
    context: OperationContext,
    rule_set: RuleSetLock,
    component_root: Path,
    scratch_root: Path,
) -> list[CanaryReceipt]:
    """Reproduce every reviewed canary and attach semantic receipts."""

    receipts: list[CanaryReceipt] = []
    scratch_root = _secure_directory(scratch_root, "updater scratch root", create=True)
    for canary in sorted(rule_set.canaries, key=lambda item: item.id):
        if canary.state != "verified" or not canary.output_sha256:
            raise OperationError("rules canary evidence is not verified")
        fixture = _baked_canary_path(canary)
        _verify_canary_fixture(canary, fixture)
        context.checkpoint()
        with tempfile.TemporaryDirectory(prefix="canary-", dir=scratch_root) as temporary:
            scratch = Path(temporary)
            scratch.chmod(0o700)
            output = scratch / "result.sarif"
            home = scratch / "home"
            home.mkdir(mode=0o700)
            working_directory = scratch
            if rule_set.tool_id == "opengrep":
                entrypoint = component_root / OPENGREP_RULE_ENTRYPOINT
                try:
                    entrypoint.resolve(strict=True).relative_to(
                        component_root.resolve(strict=True)
                    )
                    metadata = entrypoint.lstat()
                except (OSError, RuntimeError, ValueError) as exc:
                    raise OperationError(
                        "reviewed OpenGrep rule entrypoint is unavailable"
                    ) from exc
                if (
                    entrypoint.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_mode & 0o222
                ):
                    raise OperationError(
                        "reviewed OpenGrep rule entrypoint is unsafe"
                    )
                command = [
                    str(OPENGREP_CORE_PATH),
                    "scan",
                    "--config",
                    entrypoint.name,
                    "--sarif",
                    "--output",
                    str(output),
                    str(fixture),
                ]
                working_directory = component_root
            elif rule_set.tool_id == "bearer":
                output = scratch / "result.json"
                command = [
                    "/usr/local/bin/bearer",
                    "scan",
                    str(fixture),
                    "--format",
                    "jsonv2",
                    "--output",
                    str(output),
                    "--disable-version-check",
                    "--disable-default-rules",
                    "--external-rule-dir",
                    str(component_root),
                ]
            else:  # pragma: no cover - the strict model limits this union
                raise OperationError("rules canary tool is not supported")
            environment = {
                "HOME": str(home),
                "NO_COLOR": "1",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SEND_METRICS": "off",
                "BEARER_TELEMETRY_ENABLED": "false",
                "TMPDIR": str(scratch),
            }
            local_bound = context.remaining_seconds(300) if isinstance(context, OperationContext) else 300
            started = time.monotonic()
            try:
                process = subprocess.Popen(
                    command,
                    cwd=working_directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError as exc:
                raise OperationError("rules canary executable is unavailable") from exc
            try:
                while process.poll() is None:
                    context.checkpoint()
                    if time.monotonic() - started > local_bound:
                        raise OperationError("rules canary exceeded its time bound")
                    time.sleep(0.05)
            except BaseException:
                _terminate_canary(process)
                raise
            finally:
                _terminate_canary(process)
            exit_code = int(process.returncode)
            result_count, observed_ids = (
                _parse_bearer_semantics(output) if rule_set.tool_id == "bearer"
                else _parse_sarif_semantics(output)
            )
            expected_ids = sorted(canary.expected_rule_ids)
            digest = canonical_canary_output_sha256(
                canary_id=canary.id,
                fixture_sha256=canary.fixture_sha256,
                exit_code=exit_code,
                result_count=result_count,
                rule_ids=observed_ids,
            )
            if (
                exit_code != canary.expected_exit_code
                or result_count != canary.expected_result_count
                or observed_ids != expected_ids
                or digest != canary.output_sha256
            ):
                raise OperationError("rules canary semantic output differs from its lock")
            receipts.append(
                CanaryReceipt(
                    canary_id=canary.id,
                    fixture_sha256=canary.fixture_sha256,
                    output_sha256=digest,
                    exit_code=exit_code,
                    result_count=result_count,
                    expected_ids=expected_ids,
                    observed_ids=observed_ids,
                    passed=True,
                )
            )
    return receipts


@contextmanager
def generation_lock(
    cache_root: Path, *, checkpoint: Callable[[], object] | None = None,
) -> Iterator[None]:
    prepare_cache_layout(cache_root)
    root = _secure_directory(cache_root, "tool cache root", create=True)
    lock_path = root / ".generation.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OperationError("cache generation lock is unsafe")
        os.fchmod(descriptor, 0o600)
        _acquire_owned_lock(descriptor, checkpoint)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _cache_layout_is_mount(path: Path) -> bool:
    """Narrow mount-point seam for runtime boundary tests."""

    return path.is_mount()


def _cache_layout_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def prepare_cache_layout(cache_root: Path) -> None:
    """Create or safely normalize the updater-owned private cache layout.

    A configured mount is accepted only when it already has the exact private
    mode installed by the image boundary. Runtime normalization uses no-follow
    directory descriptors and never chmods a symlink, foreign owner, or mount.
    Nested cache directories must remain on the cache root's device.
    """

    owner = os.getuid()
    group = os.getgid()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        cache_root.mkdir(mode=0o700, exist_ok=True)
        root_metadata = cache_root.lstat()
    except OSError as exc:
        raise OperationError("updater cache root cannot be created safely") from exc
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != owner
        or root_metadata.st_gid != group
    ):
        raise OperationError("updater cache root is not an owner-owned real directory")
    root_is_mount = _cache_layout_is_mount(cache_root)
    root_fd = -1
    try:
        root_fd = os.open(cache_root, flags)
        if _cache_layout_identity(os.fstat(root_fd)) != _cache_layout_identity(
            root_metadata
        ):
            raise OperationError("updater cache root changed during layout validation")
        if stat.S_IMODE(root_metadata.st_mode) != 0o700:
            if root_is_mount:
                raise OperationError(
                    "updater cache mount does not have the required private mode"
                )
            os.fchmod(root_fd, 0o700)
            if stat.S_IMODE(os.fstat(root_fd).st_mode) != 0o700:
                raise OperationError("updater cache root mode could not be normalized")

        root_device = os.fstat(root_fd).st_dev
        for name in ("generations", "staging", "tombstones"):
            try:
                os.mkdir(name, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            child_metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != owner
                or child_metadata.st_gid != group
                or child_metadata.st_dev != root_device
            ):
                raise OperationError(
                    "updater cache layout contains an unsafe owned directory"
                )
            child = cache_root / name
            child_is_mount = _cache_layout_is_mount(child)
            child_fd = os.open(name, flags, dir_fd=root_fd)
            try:
                if _cache_layout_identity(os.fstat(child_fd)) != _cache_layout_identity(
                    child_metadata
                ):
                    raise OperationError(
                        "updater cache directory changed during layout validation"
                    )
                if stat.S_IMODE(child_metadata.st_mode) != 0o700:
                    if child_is_mount:
                        raise OperationError(
                            "updater cache child mount does not have the required private mode"
                        )
                    os.fchmod(child_fd, 0o700)
                    if stat.S_IMODE(os.fstat(child_fd).st_mode) != 0o700:
                        raise OperationError(
                            "updater cache directory mode could not be normalized"
                        )
            finally:
                os.close(child_fd)
    except OperationError:
        raise
    except OSError as exc:
        raise OperationError("updater cache layout cannot be prepared safely") from exc
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def _prune_unreferenced_generations(
    cache_root: Path,
    checkpoint: Callable[[], object] | None = None,
    *,
    allow_missing_pointer: bool = False,
    retire_missing_previous_good: bool = False,
) -> list[str]:
    """Remove sealed generations outside the atomic active/rollback pair.

    The caller must hold ``.generation.lock``. A candidate being built remains
    below ``staging/<operation-id>`` and is therefore retained until its atomic
    publication/activation sequence finishes. Unknown names, aliases, and
    special entries fail closed instead of being followed or removed.
    """

    root = _secure_directory(cache_root, "tool cache root")
    generations = _secure_directory(root / "generations", "generation root")
    owner = os.getuid()
    group = os.getgid()
    root_metadata = _prune_lstat(root)
    generations_metadata = _prune_lstat(generations)
    if (
        root_metadata.st_uid != owner
        or root_metadata.st_gid != group
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or generations_metadata.st_uid != owner
        or generations_metadata.st_gid != group
        or stat.S_IMODE(generations_metadata.st_mode) != 0o700
        or root_metadata.st_dev != generations_metadata.st_dev
    ):
        raise OperationError("cache generation roots are not private owner directories")
    _recover_generation_tombstones(root, checkpoint)
    pointer_path = root / "active.json"
    pointer_metadata: os.stat_result | None
    try:
        pointer_metadata = _prune_lstat(pointer_path)
    except FileNotFoundError as exc:
        if not allow_missing_pointer:
            raise OperationError("active generation pointer is required for pruning") from exc
        pointer_metadata = None
    retained: set[str] = set()
    references: list[GenerationReference] = []
    if pointer_metadata is not None:
        if (
            not stat.S_ISREG(pointer_metadata.st_mode)
            or pointer_metadata.st_nlink != 1
            or pointer_metadata.st_uid != owner
            or pointer_metadata.st_gid != group
            or stat.S_IMODE(pointer_metadata.st_mode) != 0o600
            or pointer_metadata.st_dev != generations_metadata.st_dev
        ):
            raise OperationError("active generation pointer is unsafe for pruning")
        try:
            pointer = load_active_pointer(root)
        except CacheValidationError as exc:
            raise OperationError("active generation pointer is invalid for pruning") from exc
        retained.add(pointer.active.generation_id)
        references.append(pointer.active)
        if pointer.previous_good is not None:
            previous_path = generations / pointer.previous_good.generation_id
            try:
                _prune_lstat(previous_path)
            except FileNotFoundError:
                if not retire_missing_previous_good:
                    references.append(pointer.previous_good)
                else:
                    # A valid active generation remains independently usable.
                    # Startup recovery may retire only an absent rollback
                    # target; an existing but invalid target still fails closed
                    # below so no ambiguous cache tree is pruned.
                    validate_generation(
                        root,
                        pointer.active.generation_id,
                        expected_manifest_sha256=pointer.active.manifest_sha256,
                        checkpoint=checkpoint,
                    )
                    pointer = ActiveGenerationPointer(
                        schema_version=pointer.schema_version,
                        revision=pointer.revision + 1,
                        active=pointer.active,
                        previous_good=None,
                        activated_at=pointer.activated_at,
                        operation_id=pointer.operation_id,
                    )
                    _atomic_write_json(
                        root,
                        "active.json",
                        pointer.model_dump(mode="json"),
                        MAX_ACTIVE_POINTER_BYTES,
                    )
                    pointer_metadata = _prune_lstat(pointer_path)
                    LOGGER.warning(
                        "retired missing previous-good cache generation during startup recovery"
                    )
            else:
                retained.add(pointer.previous_good.generation_id)
                references.append(pointer.previous_good)
    try:
        for reference in references:
            _validate_prunable_generation_tree(
                generations / reference.generation_id,
                expected_device=generations_metadata.st_dev,
                owner=owner,
                group=group,
            )
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            raise
        raise OperationError("referenced generation is invalid for pruning") from exc
    try:
        with os.scandir(generations) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
    except OSError as exc:
        raise OperationError("generation root cannot be enumerated safely") from exc
    unreferenced: list[str] = []
    for entry in entries:
        if checkpoint is not None:
            checkpoint()
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise OperationError("generation entry cannot be inspected safely") from exc
        if (
            not _GENERATION_ID.fullmatch(entry.name)
            or entry.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise OperationError("generation root contains an unsafe entry")
        if entry.name in retained:
            continue
        unreferenced.append(entry.name)

    # Retention is not scanner readiness. If only the sealed active/rollback
    # pair remains, there is nothing to delete: do not hash and SQL-check their
    # multi-GiB contents merely to return an empty cleanup result. The runtime
    # scanner still independently verifies data before admitting any scan.
    # Any actual deletion below requires full retained-content validation first.
    if not unreferenced:
        return []
    try:
        for reference in references:
            validate_generation(
                root,
                reference.generation_id,
                expected_manifest_sha256=reference.manifest_sha256,
                checkpoint=checkpoint,
            )
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            raise
        raise OperationError("referenced generation is invalid for pruning") from exc

    candidates: list[tuple[str, dict[str, tuple[int, ...]]]] = []
    for generation_id in unreferenced:
        if checkpoint is not None:
            checkpoint()
        candidate = generations / generation_id
        try:
            validate_generation(root, generation_id, checkpoint=checkpoint)
            identities = _validate_prunable_generation_tree(
                candidate,
                expected_device=generations_metadata.st_dev,
                owner=owner,
                group=group,
            )
        except CacheValidationError as exc:
            if isinstance(exc, GrypeContentValidationError) and exc.retryable:
                raise
            raise OperationError("unreferenced generation is not a sealed updater generation") from exc
        candidates.append((generation_id, identities))

    removed: list[str] = []
    for generation_id, identities in candidates:
        if checkpoint is not None:
            checkpoint()
        if pointer_metadata is None:
            try:
                _prune_lstat(pointer_path)
            except FileNotFoundError:
                pass
            else:
                raise OperationError("active generation pointer appeared during pruning")
        elif _prune_identity(_prune_lstat(pointer_path)) != _prune_identity(
            pointer_metadata
        ):
            raise OperationError("active generation pointer changed during pruning")
        _tombstone_validated_generation(
            root,
            generation_id,
            identities,
        )
        removed.append(generation_id)
    if removed:
        _fsync_directory(generations, "generation root")
    return removed


def _prune_lstat(path: Path) -> os.stat_result:
    """Narrow seam for no-follow pruning metadata and mount-boundary tests."""

    return path.lstat()


def _prune_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_prunable_generation_tree(
    generation: Path,
    *,
    expected_device: int,
    owner: int,
    group: int,
) -> dict[str, tuple[int, ...]]:
    """Validate exact sealed ownership/modes without crossing aliases/mounts."""

    identities: dict[str, tuple[int, ...]] = {}
    pending: list[tuple[Path, str]] = [(generation, ".")]
    while pending:
        current, relative = pending.pop()
        try:
            metadata = _prune_lstat(current)
        except OSError as exc:
            raise CacheValidationError("prunable generation entry cannot be inspected") from exc
        is_directory = stat.S_ISDIR(metadata.st_mode)
        is_regular = stat.S_ISREG(metadata.st_mode)
        expected_mode = 0o500 if is_directory else 0o400
        if (
            metadata.st_dev != expected_device
            or metadata.st_uid != owner
            or metadata.st_gid != group
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or (not is_directory and not is_regular)
            or (is_regular and metadata.st_nlink != 1)
        ):
            raise CacheValidationError(
                "prunable generation ownership, mode, type, or device is unsafe"
            )
        identities[relative] = _prune_identity(metadata)
        if not is_directory:
            continue
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise CacheValidationError("prunable generation cannot be enumerated") from exc
        for entry in reversed(entries):
            child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
            try:
                _require_relative_path(child_relative, "prunable generation entry")
            except ValueError as exc:
                raise CacheValidationError("prunable generation path is unsafe") from exc
            pending.append((current / entry.name, child_relative))
    return identities


def _tombstone_receipt_payload(
    generation_id: str,
    identities: dict[str, tuple[int, ...]],
) -> dict[str, object]:
    if not _GENERATION_ID.fullmatch(generation_id):
        raise OperationError("generation tombstone identity is invalid")
    if not 1 <= len(identities) <= MAX_TOMBSTONE_ENTRIES or "." not in identities:
        raise OperationError("generation tombstone entry count is invalid")
    return {
        "schema_version": 1,
        "generation_id": generation_id,
        "entries": [
            {"path": path, "identity": list(identities[path])}
            for path in sorted(identities)
        ],
    }


def _load_tombstone_receipt(
    tombstones: Path,
    generation_id: str,
    *,
    expected_device: int,
    owner: int,
    group: int,
) -> tuple[dict[str, tuple[int, ...]], tuple[int, ...]]:
    receipt_path = tombstones / f"{generation_id}.json"
    try:
        receipt_metadata = _prune_lstat(receipt_path)
    except OSError as exc:
        raise OperationError("generation tombstone receipt is missing or unsafe") from exc
    if (
        not stat.S_ISREG(receipt_metadata.st_mode)
        or receipt_metadata.st_nlink != 1
        or receipt_metadata.st_uid != owner
        or receipt_metadata.st_gid != group
        or receipt_metadata.st_dev != expected_device
        or stat.S_IMODE(receipt_metadata.st_mode) != 0o600
    ):
        raise OperationError("generation tombstone receipt is unsafe")
    try:
        raw = _read_bounded_regular_file(
            receipt_path,
            MAX_TOMBSTONE_RECEIPT_BYTES,
            "generation tombstone receipt",
        )
        payload = _decode_json_object(raw, "generation tombstone receipt")
    except (CacheValidationError, ValueError) as exc:
        raise OperationError("generation tombstone receipt is invalid") from exc
    if set(payload) != {"schema_version", "generation_id", "entries"}:
        raise OperationError("generation tombstone receipt shape is invalid")
    if payload["schema_version"] != 1 or payload["generation_id"] != generation_id:
        raise OperationError("generation tombstone receipt identity is invalid")
    entries = payload["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TOMBSTONE_ENTRIES:
        raise OperationError("generation tombstone receipt entries are invalid")
    identities: dict[str, tuple[int, ...]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "identity"}:
            raise OperationError("generation tombstone receipt entry is invalid")
        path = entry["path"]
        raw_identity = entry["identity"]
        if not isinstance(path, str) or path in identities:
            raise OperationError("generation tombstone receipt path is invalid")
        if path != ".":
            try:
                _require_relative_path(path, "generation tombstone receipt path")
            except ValueError as exc:
                raise OperationError("generation tombstone receipt path is invalid") from exc
        if (
            not isinstance(raw_identity, list)
            or len(raw_identity) != 9
            or any(type(value) is not int or value < 0 for value in raw_identity)
        ):
            raise OperationError("generation tombstone receipt metadata is invalid")
        identity = tuple(raw_identity)
        mode = identity[2]
        is_directory = stat.S_ISDIR(mode)
        is_regular = stat.S_ISREG(mode)
        if (
            identity[0] != expected_device
            or identity[4] != owner
            or identity[5] != group
            or (is_directory and stat.S_IMODE(mode) != 0o500)
            or (is_regular and (stat.S_IMODE(mode) != 0o400 or identity[3] != 1))
            or (not is_directory and not is_regular)
            or (path == "." and not is_directory)
        ):
            raise OperationError("generation tombstone receipt metadata is unsafe")
        identities[path] = identity
    if "." not in identities:
        raise OperationError("generation tombstone receipt omits its root")
    return identities, _prune_identity(receipt_metadata)


def _validate_partial_tombstone_tree(
    tombstone: Path,
    original: dict[str, tuple[int, ...]],
    *,
    expected_device: int,
    owner: int,
    group: int,
    checkpoint: Callable[[], object] | None = None,
) -> dict[str, tuple[int, ...]]:
    """Validate a crash-partial deletion as a strict subset of its receipt."""

    current_identities: dict[str, tuple[int, ...]] = {}
    pending: list[tuple[Path, str]] = [(tombstone, ".")]
    while pending:
        if checkpoint is not None:
            checkpoint()
        current, relative = pending.pop()
        expected = original.get(relative)
        if expected is None:
            raise OperationError("generation tombstone contains an unreceipted entry")
        try:
            metadata = _prune_lstat(current)
        except OSError as exc:
            raise OperationError("generation tombstone entry cannot be inspected") from exc
        observed = _prune_identity(metadata)
        expected_directory = stat.S_ISDIR(expected[2])
        observed_directory = stat.S_ISDIR(metadata.st_mode)
        observed_regular = stat.S_ISREG(metadata.st_mode)
        if (
            metadata.st_dev != expected_device
            or metadata.st_dev != expected[0]
            or metadata.st_ino != expected[1]
            or metadata.st_uid != owner
            or metadata.st_uid != expected[4]
            or metadata.st_gid != group
            or metadata.st_gid != expected[5]
            or observed_directory != expected_directory
            or (not observed_directory and not observed_regular)
            or (
                observed_directory
                and stat.S_IMODE(metadata.st_mode) not in {0o500, 0o700}
            )
            or (observed_regular and observed != expected)
        ):
            raise OperationError("generation tombstone entry differs from its receipt")
        current_identities[relative] = observed
        if not observed_directory:
            continue
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    if checkpoint is not None:
                        checkpoint()
                    if len(current_identities) + len(pending) + len(entries) >= len(original):
                        raise OperationError("generation tombstone exceeds its receipt")
                    entries.append(entry)
                entries.sort(key=lambda item: item.name)
        except OSError as exc:
            raise OperationError("generation tombstone cannot be enumerated") from exc
        if len(current_identities) + len(entries) > len(original):
            raise OperationError("generation tombstone exceeds its receipt")
        for entry in reversed(entries):
            child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
            try:
                _require_relative_path(child_relative, "generation tombstone entry")
            except ValueError as exc:
                raise OperationError("generation tombstone path is unsafe") from exc
            pending.append((current / entry.name, child_relative))
    return current_identities


def _remove_tombstone_receipt(
    tombstones: Path,
    generation_id: str,
    receipt_identity: tuple[int, ...],
) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(tombstones, flags)
    try:
        name = f"{generation_id}.json"
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _prune_identity(metadata) != receipt_identity:
            raise OperationError("generation tombstone receipt changed before removal")
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OperationError:
        raise
    except OSError as exc:
        raise OperationError("generation tombstone receipt could not be removed") from exc
    finally:
        os.close(directory_fd)


def _persist_tombstone_rename(generations_fd: int, tombstones_fd: int) -> None:
    """Narrow phase boundary for rename-durability fault injection."""

    os.fsync(generations_fd)
    os.fsync(tombstones_fd)


def _validate_receipted_generation_source(
    generation: Path,
    original: dict[str, tuple[int, ...]],
    *,
    expected_device: int,
    owner: int,
    group: int,
    checkpoint: Callable[[], object] | None = None,
) -> dict[str, tuple[int, ...]]:
    """Bind a receipt to its complete source, allowing only our root chmod."""

    current = _validate_partial_tombstone_tree(
        generation,
        original,
        expected_device=expected_device,
        owner=owner,
        group=group,
        checkpoint=checkpoint,
    )
    if set(current) != set(original):
        raise OperationError("receipted generation source is incomplete")
    for path, observed in current.items():
        expected = original[path]
        if path != "." or stat.S_IMODE(observed[2]) == 0o500:
            if observed != expected:
                raise OperationError("receipted generation source changed")
            continue
        # Darwin requires write permission on the directory being renamed.
        # A durable receipt precedes this root-only 0500 -> 0700 transition.
        if stat.S_IMODE(observed[2]) != 0o700:
            raise OperationError("receipted generation source mode is unsafe")
        comparable = tuple(
            value for index, value in enumerate(observed) if index not in {2, 8}
        )
        expected_comparable = tuple(
            value for index, value in enumerate(expected) if index not in {2, 8}
        )
        if comparable != expected_comparable:
            raise OperationError("receipted generation source changed")
    return current


def _rename_receipted_generation(
    generations: Path,
    tombstones: Path,
    generation_id: str,
    original: dict[str, tuple[int, ...]],
    *,
    expected_device: int,
    owner: int,
    group: int,
    checkpoint: Callable[[], object] | None = None,
) -> None:
    """Finish the receipt-backed atomic namespace transition portably."""

    current = _validate_receipted_generation_source(
        generations / generation_id,
        original,
        expected_device=expected_device,
        owner=owner,
        group=group,
        checkpoint=checkpoint,
    )
    if checkpoint is not None:
        checkpoint()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    generations_fd = os.open(generations, flags)
    tombstones_fd = os.open(tombstones, flags)
    source_fd = -1
    try:
        source_fd = os.open(generation_id, flags, dir_fd=generations_fd)
        source = os.fstat(source_fd)
        if _prune_identity(source) != current["."]:
            raise OperationError("generation changed before atomic tombstoning")
        if stat.S_IMODE(source.st_mode) == 0o500:
            os.fchmod(source_fd, 0o700)
            os.fsync(source_fd)
            transitioned = os.fstat(source_fd)
            if (
                transitioned.st_dev != source.st_dev
                or transitioned.st_ino != source.st_ino
                or transitioned.st_uid != source.st_uid
                or transitioned.st_gid != source.st_gid
                or transitioned.st_nlink != source.st_nlink
                or transitioned.st_size != source.st_size
                or transitioned.st_mtime_ns != source.st_mtime_ns
                or stat.S_IMODE(transitioned.st_mode) != 0o700
            ):
                raise OperationError("generation changed during tombstone preparation")
        os.close(source_fd)
        source_fd = -1
        cache_repair.rename_exclusive(
            Path(generation_id), Path(generation_id),
            src_dir_fd=generations_fd, dst_dir_fd=tombstones_fd,
        )
        _persist_tombstone_rename(generations_fd, tombstones_fd)
    except OperationError:
        raise
    except OSError as exc:
        raise OperationError("generation could not be atomically tombstoned") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        os.close(tombstones_fd)
        os.close(generations_fd)


def _tombstone_validated_generation(
    cache_root: Path,
    generation_id: str,
    identities: dict[str, tuple[int, ...]],
) -> None:
    """Retire content-validated, unreferenced generations during normal pruning."""
    return _retire_owned_generation(cache_root, generation_id, identities)


def _retire_owned_generation(
    cache_root: Path,
    generation_id: str,
    identities: dict[str, tuple[int, ...]],
    *,
    checkpoint: Callable[[], object] | None = None,
) -> None:
    """Retire an exact owned tree after normal validation or a durable repair proof."""
    root = _secure_directory(cache_root, "tool cache root")
    generations = _secure_directory(root / "generations", "generation root")
    tombstones = _secure_directory(root / "tombstones", "generation tombstone root")
    owner = os.getuid()
    group = os.getgid()
    generation_metadata = _prune_lstat(generations)
    tombstone_metadata = _prune_lstat(tombstones)
    if (
        generation_metadata.st_dev != tombstone_metadata.st_dev
        or tombstone_metadata.st_uid != owner
        or tombstone_metadata.st_gid != group
        or stat.S_IMODE(tombstone_metadata.st_mode) != 0o700
    ):
        raise OperationError("generation tombstone root is not private or same-filesystem")
    receipt_path = tombstones / f"{generation_id}.json"
    tombstone_path = tombstones / generation_id
    for path in (receipt_path, tombstone_path):
        try:
            _prune_lstat(path)
        except FileNotFoundError:
            continue
        raise OperationError("generation tombstone destination already exists")
    if checkpoint is not None:
        checkpoint()
    _atomic_write_json(
        tombstones,
        f"{generation_id}.json",
        _tombstone_receipt_payload(generation_id, identities),
        MAX_TOMBSTONE_RECEIPT_BYTES,
    )
    receipt_identities, receipt_identity = _load_tombstone_receipt(
        tombstones,
        generation_id,
        expected_device=tombstone_metadata.st_dev,
        owner=owner,
        group=group,
    )
    if receipt_identities != identities:
        raise OperationError("generation tombstone receipt differs from validation")
    if checkpoint is not None:
        checkpoint()
    _rename_receipted_generation(
        generations,
        tombstones,
        generation_id,
        receipt_identities,
        expected_device=tombstone_metadata.st_dev,
        owner=owner,
        group=group,
        checkpoint=checkpoint,
    )
    current = _validate_partial_tombstone_tree(
        tombstone_path,
        receipt_identities,
        expected_device=tombstone_metadata.st_dev,
        owner=owner,
        group=group,
        checkpoint=checkpoint,
    )
    if checkpoint is None:
        _delete_validated_generation_tree(tombstones, generation_id, current)
    else:
        _delete_validated_generation_tree(tombstones, generation_id, current, checkpoint=checkpoint)
        checkpoint()
    _remove_tombstone_receipt(tombstones, generation_id, receipt_identity)


def _delete_validated_generation_tree(
    generations: Path,
    generation_id: str,
    identities: dict[str, tuple[int, ...]],
    *,
    checkpoint: Callable[[], object] | None = None,
) -> None:
    """Delete one prevalidated tree through dirfds without following aliases."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.open(generations, flags)
    generation_fd = -1
    try:
        generation_fd = os.open(generation_id, flags, dir_fd=parent_fd)
        if _prune_identity(os.fstat(generation_fd)) != identities["."]:
            raise OperationError("generation changed before safe deletion")

        def remove_children(directory_fd: int, relative: str) -> None:
            if checkpoint is not None:
                checkpoint()
            expected_prefix = "" if relative == "." else relative + "/"
            expected_names = {
                path.removeprefix(expected_prefix).split("/", 1)[0]
                for path in identities
                if path != relative and path.startswith(expected_prefix)
            }
            with os.scandir(directory_fd) as iterator:
                observed_names = {entry.name for entry in iterator}
            if observed_names != expected_names:
                raise OperationError("generation changed before safe deletion")
            os.fchmod(directory_fd, 0o700)
            for name in sorted(observed_names):
                if checkpoint is not None:
                    checkpoint()
                child_relative = name if relative == "." else f"{relative}/{name}"
                expected = identities.get(child_relative)
                if expected is None:
                    raise OperationError("generation changed before safe deletion")
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _prune_identity(metadata) != expected:
                    raise OperationError("generation changed before safe deletion")
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        if _prune_identity(os.fstat(child_fd)) != expected:
                            raise OperationError("generation changed before safe deletion")
                        remove_children(child_fd, child_relative)
                    finally:
                        os.close(child_fd)
                    os.rmdir(name, dir_fd=directory_fd)
                elif stat.S_ISREG(metadata.st_mode):
                    os.unlink(name, dir_fd=directory_fd)
                else:  # pragma: no cover - prevalidation and identity fence
                    raise OperationError("generation contains an unsafe deletion entry")

        remove_children(generation_fd, ".")
        os.close(generation_fd)
        generation_fd = -1
        os.rmdir(generation_id, dir_fd=parent_fd)
    except OperationError:
        raise
    except OSError as exc:
        raise OperationError("sealed generation could not be removed safely") from exc
    finally:
        if generation_fd >= 0:
            os.close(generation_fd)
        os.close(parent_fd)


def _recover_generation_tombstones(
    cache_root: Path,
    checkpoint: Callable[[], object] | None = None,
) -> list[str]:
    """Validate and finish bounded crash-interrupted tombstone deletions."""

    root = _secure_directory(cache_root, "tool cache root")
    generations = _secure_directory(root / "generations", "generation root")
    tombstones = _secure_directory(root / "tombstones", "generation tombstone root")
    owner = os.getuid()
    group = os.getgid()
    generations_metadata = _prune_lstat(generations)
    tombstones_metadata = _prune_lstat(tombstones)
    if (
        generations_metadata.st_dev != tombstones_metadata.st_dev
        or tombstones_metadata.st_uid != owner
        or tombstones_metadata.st_gid != group
        or stat.S_IMODE(tombstones_metadata.st_mode) != 0o700
    ):
        raise OperationError("generation tombstone root is not private or same-filesystem")

    pointer_path = root / "active.json"
    try:
        pointer_metadata: os.stat_result | None = _prune_lstat(pointer_path)
    except FileNotFoundError:
        pointer_metadata = None
    retained: set[str] = set()
    if pointer_metadata is not None:
        if (
            not stat.S_ISREG(pointer_metadata.st_mode)
            or pointer_metadata.st_nlink != 1
            or pointer_metadata.st_uid != owner
            or pointer_metadata.st_gid != group
            or pointer_metadata.st_dev != generations_metadata.st_dev
            or stat.S_IMODE(pointer_metadata.st_mode) != 0o600
        ):
            raise OperationError("active generation pointer is unsafe during tombstone recovery")
        try:
            pointer = load_active_pointer(root)
        except CacheValidationError as exc:
            raise OperationError("active generation pointer is invalid during tombstone recovery") from exc
        retained.add(pointer.active.generation_id)
        if pointer.previous_good is not None:
            retained.add(pointer.previous_good.generation_id)

    try:
        with os.scandir(tombstones) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
    except OSError as exc:
        raise OperationError("generation tombstone root cannot be enumerated") from exc
    pairs: dict[str, set[str]] = {}
    for entry in entries:
        if checkpoint is not None:
            checkpoint()
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise OperationError("generation tombstone entry cannot be inspected") from exc
        if entry.is_symlink():
            raise OperationError("generation tombstone root contains an unsafe entry")
        receipt_match = _TOMBSTONE_RECEIPT.fullmatch(entry.name)
        if receipt_match is not None and stat.S_ISREG(metadata.st_mode):
            generation_id = receipt_match.group(1)
            kind = "receipt"
        elif _GENERATION_ID.fullmatch(entry.name) and stat.S_ISDIR(metadata.st_mode):
            generation_id = entry.name
            kind = "payload"
        else:
            raise OperationError("generation tombstone root contains an unsafe entry")
        pairs.setdefault(generation_id, set()).add(kind)
    if len(pairs) > MAX_GENERATION_TOMBSTONES:
        raise OperationCapacityError("generation tombstone recovery exceeds its bound")

    recoverable: list[
        tuple[
            str,
            tuple[int, ...],
            dict[str, tuple[int, ...]],
            dict[str, tuple[int, ...]] | None,
            bool,
        ]
    ] = []
    for generation_id in sorted(pairs):
        kinds = pairs[generation_id]
        if "receipt" not in kinds:
            raise OperationError("generation tombstone payload has no recovery receipt")
        original, receipt_identity = _load_tombstone_receipt(
            tombstones,
            generation_id,
            expected_device=tombstones_metadata.st_dev,
            owner=owner,
            group=group,
        )
        source_present = False
        try:
            _prune_lstat(generations / generation_id)
        except FileNotFoundError:
            pass
        else:
            if "payload" in kinds:
                raise OperationError(
                    "generation exists in authoritative and tombstone namespaces"
                )
            if generation_id in retained:
                raise OperationError("active pointer references a receipted generation")
            _validate_receipted_generation_source(
                generations / generation_id,
                original,
                expected_device=generations_metadata.st_dev,
                owner=owner,
                group=group,
                checkpoint=checkpoint,
            )
            source_present = True
        current = None
        if "payload" in kinds:
            if generation_id in retained:
                raise OperationError("active pointer references a generation tombstone")
            current = _validate_partial_tombstone_tree(
                tombstones / generation_id,
                original,
                expected_device=tombstones_metadata.st_dev,
                owner=owner,
                group=group,
                checkpoint=checkpoint,
            )
        recoverable.append(
            (generation_id, receipt_identity, original, current, source_present)
        )

    recovered: list[str] = []
    for generation_id, receipt_identity, original, current, source_present in recoverable:
        if checkpoint is not None:
            checkpoint()

        def require_stable_pointer() -> None:
            if pointer_metadata is None:
                try:
                    _prune_lstat(pointer_path)
                except FileNotFoundError:
                    pass
                else:
                    raise OperationError(
                        "active generation pointer appeared during tombstone recovery"
                    )
            elif _prune_identity(_prune_lstat(pointer_path)) != _prune_identity(
                pointer_metadata
            ):
                raise OperationError(
                    "active generation pointer changed during tombstone recovery"
                )

        if source_present:
            require_stable_pointer()
            _rename_receipted_generation(
                generations,
                tombstones,
                generation_id,
                original,
                expected_device=tombstones_metadata.st_dev,
                owner=owner,
                group=group,
                checkpoint=checkpoint,
            )
            current = _validate_partial_tombstone_tree(
                tombstones / generation_id,
                original,
                expected_device=tombstones_metadata.st_dev,
                owner=owner,
                group=group,
                checkpoint=checkpoint,
            )
        if current is not None:
            require_stable_pointer()
            if checkpoint is None:
                _delete_validated_generation_tree(tombstones, generation_id, current)
            else:
                _delete_validated_generation_tree(tombstones, generation_id, current, checkpoint=checkpoint)
                checkpoint()
        _remove_tombstone_receipt(tombstones, generation_id, receipt_identity)
        recovered.append(generation_id)
    return recovered


def _fsync_directory(path: Path, label: str) -> None:
    """Persist one already-validated directory entry boundary."""

    directory = _secure_directory(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except (CacheValidationError, OSError) as exc:
        raise OperationError(f"{label} could not be persisted") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _publish_sealed_generation(
    cache_root: Path,
    operation_stage: Path,
    payload: Path,
    manifest: GenerationManifest,
    checkpoint: Callable[[], object] | None = None,
    progress: Callable[[str, int, int, int, int], object] | None = None,
    before_publish: Callable[[ValidatedGeneration], object] | None = None,
) -> str:
    """Validate and atomically publish a complete immutable generation.

    The final ``generations/<id>`` name must never expose a directory before
    its manifest has been written, its descendants have been sealed, and
    strict generation validation has passed. Keeping the validation root below
    the operation's private staging directory permits the final rename to
    remain atomic on the cache volume.
    """

    root = _secure_directory(cache_root, "tool cache root")
    stage = _secure_directory(operation_stage, "operation staging directory")
    try:
        payload_metadata = payload.lstat()
    except OSError as exc:
        raise OperationError("generation payload is missing or unsafe") from exc
    if payload.is_symlink() or not stat.S_ISDIR(payload_metadata.st_mode):
        raise OperationError("generation payload is missing or unsafe")
    if payload.parent.resolve(strict=True) != stage:
        raise OperationError("generation payload is outside its operation staging directory")
    candidate_root = stage / "candidate"
    candidate_generations = candidate_root / "generations"
    try:
        candidate_generations.mkdir(mode=0o700, parents=True)
    except OSError as exc:
        raise OperationError("candidate generation staging could not be created") from exc
    staged_generation = candidate_generations / manifest.generation_id
    if staged_generation.exists() or staged_generation.is_symlink():
        raise OperationError("candidate generation destination already exists")
    try:
        payload.rename(staged_generation)
        write_generation_manifest(staged_generation, manifest)
        candidate = validate_generation(
            candidate_root,
            manifest.generation_id,
            checkpoint=checkpoint,
            progress=progress,
        )
    except (OperationStateError, GrypeContentValidationError):
        raise
    except (CacheValidationError, OSError, RuntimeError, ValueError) as exc:
        raise OperationError("candidate generation could not be sealed and validated") from exc
    if candidate.manifest != manifest:
        raise OperationError("candidate generation manifest changed while it was sealed")

    generations = _secure_directory(root / "generations", "generation root", create=True)
    destination = generations / manifest.generation_id
    if destination.exists() or destination.is_symlink():
        if before_publish is not None:
            raise OperationError("repair candidate destination already exists")
        existing = validate_generation(
            root,
            manifest.generation_id,
            checkpoint=checkpoint,
            progress=progress,
        )
        if existing.manifest != manifest:
            raise OperationError("generation identity collision")
        return manifest.generation_id
    if before_publish is not None:
        before_publish(candidate)
    # Darwin refuses to rename a directory whose owner-write bit is clear.
    # Temporarily reopen only the candidate root through an already-open,
    # no-follow descriptor; all descendant files/directories remain sealed and
    # the generation is not active. Restore 0500 on that same inode before the
    # operation can proceed to pointer publication.
    generation_descriptor = -1
    published = False
    publication_error: OSError | None = None
    try:
        generation_descriptor = os.open(
            staged_generation,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fchmod(generation_descriptor, 0o700)
        if before_publish is not None:
            cache_repair.rename_exclusive(staged_generation, destination)
        else:
            staged_generation.rename(destination)
        published = True
        os.fchmod(generation_descriptor, 0o500)
        os.fsync(generation_descriptor)
    except OSError as exc:
        publication_error = exc
    finally:
        if generation_descriptor >= 0:
            try:
                os.fchmod(generation_descriptor, 0o500)
            except OSError as exc:
                publication_error = publication_error or exc
            os.close(generation_descriptor)
    if publication_error is not None:
        location = destination if published else staged_generation
        try:
            mode = location.lstat().st_mode
        except OSError:
            mode = 0
        if mode & 0o222:
            raise OperationError(
                "sealed generation permissions could not be restored"
            ) from publication_error
        raise OperationError("sealed generation publication failed") from publication_error
    # Persist both sides of the cross-directory rename before the active
    # pointer may reference the candidate.  A failure leaves at most a sealed,
    # inactive generation which is safe to reconcile or garbage-collect.
    _fsync_directory(generations, "generation root")
    _fsync_directory(candidate_generations, "candidate generation staging")
    return manifest.generation_id


@dataclass(frozen=True)
class LockedLifecycleHandlers:
    """Real handlers whose inputs are limited to validated immutable locks."""

    tools: LoadedDocument[ToolLockFile]
    rules: LoadedDocument[RulesLockFile]
    cache_root: Path
    scratch_root: Path
    timeout_seconds: float = 30.0
    opener: DownloadOpener = _default_open
    evaluation_now: Callable[[], datetime] = _utc_now
    catalog_store: DataCatalogStore | None = None

    def __post_init__(self) -> None:
        validate_lock_alignment(self.tools.value, self.rules.value)

    def catalog_check(self, context: OperationContext) -> CatalogOperationResult:
        """Return the reviewed lock catalog without mutable upstream discovery."""

        context.checkpoint()
        if self.catalog_store is not None:
            # The existing generation lock also fences selected-catalog
            # retention against an update currently consuming that authority.
            with generation_lock(self.cache_root, checkpoint=context.checkpoint):
                selected = self.catalog_store.check(checkpoint=context.checkpoint, now=self.evaluation_now())
                result = replace(self, tools=selected.tools, rules=selected.rules, catalog_store=None).catalog_check(context)
                return result.model_copy(update={"catalog_digest": selected.digest, "catalog_mode": "signed"})
        resolved = resolve_active_generation(
            self.cache_root,
            checkpoint=context.checkpoint,
        )
        current_receipts = (
            {item.component_id: item for item in resolved.generation.manifest.components}
            if resolved.generation is not None
            else {}
        )
        tools: list[CatalogToolResult] = []
        for tool in sorted(self.tools.value.tools, key=lambda item: item.id):
            context.checkpoint()
            runtime = tool_runtime_state(tool.id)
            context.checkpoint()
            installed = runtime.get("installed_version")
            current = (
                runtime.get("available") is True
                and runtime.get("status") == "ready"
                and installed == tool.version
            )
            tools.append(
                CatalogToolResult(
                    tool_id=tool.id,
                    state="current" if current else "unavailable",
                    installed_version=str(installed) if current else None,
                )
            )
        requirements = {
            requirement.id: requirement
            for tool in self.tools.value.tools
            for requirement in tool.requirements
        }
        # Structural generation validation and runtime binary probes can be
        # slow. Sample the authoritative wall clock only after those steps so
        # the catalog's checked_at instant is the freshness decision boundary.
        evaluated_at = _evaluation_moment(self.evaluation_now())
        checked_at = _precise_utc_timestamp(evaluated_at)
        components: list[CatalogComponentResult] = []
        for component_id in CACHE_COMPONENT_IDS:
            requirement = requirements[component_id]
            receipt = current_receipts.get(component_id)
            current = False
            if receipt is not None and resolved.state == "ready":
                try:
                    # A catalog can change one component without making all
                    # unchanged components downloads. Full generation bytes
                    # were validated above; compare this receipt's exact data
                    # and canary identity against the selected candidate.
                    _validate_component_receipts(
                        [receipt],
                        [component_id],
                        self.tools,
                        self.rules,
                        evaluated_at=evaluated_at,
                    )
                    current = True
                except OperationError:
                    current = False
            if current:
                components.append(
                    CatalogComponentResult(
                        component_id=component_id,
                        state="current",
                        current_immutable_ref=f"sha256:{receipt.source_sha256}",
                    )
                )
            else:
                if (
                    requirement.provenance == "verified"
                    and requirement.source.immutable_ref
                    and requirement.source.sha256
                ):
                    requires_lock_refresh = (
                        _locked_intrinsic_candidate_is_temporally_unusable(
                            requirement,
                            evaluated_at,
                        )
                        or (
                            receipt is not None
                            and _source_intrinsic_candidate_is_temporally_unusable(
                                receipt,
                                requirement,
                                evaluated_at,
                            )
                        )
                    )
                    if requires_lock_refresh:
                        # Fetching the same immutable object cannot extend the
                        # source-intrinsic freshness window. Acquisition-timed
                        # components such as trivy-checks remain refreshable.
                        # Do not offer a lifecycle action already known to fail the
                        # activation-time readiness fence; a reviewed lock
                        # replacement is required first.
                        components.append(
                            CatalogComponentResult(
                                component_id=component_id,
                                state="requires_lock_refresh",
                            )
                        )
                        continue
                    components.append(
                        CatalogComponentResult(
                            component_id=component_id,
                            state="candidate_available",
                            current_immutable_ref=(
                                f"sha256:{receipt.source_sha256}"
                                if receipt is not None
                                else None
                            ),
                            candidate_immutable_ref=f"sha256:{requirement.source.sha256}",
                            candidate_manifest_digest=requirement.source.sha256,
                        )
                    )
                    continue
                components.append(
                    CatalogComponentResult(
                        component_id=component_id,
                        state=(
                            "unavailable"
                            if requirement.provenance == "unavailable"
                            else "unattested"
                        ),
                    )
                )
        return CatalogOperationResult(
            kind="catalog",
            checked_at=checked_at,
            tools=tools,
            components=components,
        )

    def cache_update(self, context: OperationContext) -> str:
        if self.catalog_store is not None:
            if context.request.catalog_digest is None:
                raise DataCatalogError("selection")
            selected = self.catalog_store.selected(context.request.catalog_digest,
                checkpoint=context.checkpoint, now=self.evaluation_now())
            return replace(self, tools=selected.tools, rules=selected.rules, catalog_store=None)._cache_update_locked(context)
        if context.request.catalog_digest is not None:
            raise DataCatalogError("trust")
        validate_lock_alignment(self.tools.value, self.rules.value)
        return self._cache_update_locked(context)

    def _cache_update_locked(self, context: OperationContext) -> str:
        request = context.request
        evaluated_at = _evaluation_moment(self.evaluation_now())
        requirements = {
            requirement.id: (tool.id, requirement)
            for tool in self.tools.value.tools
            for requirement in tool.requirements
        }
        for component_id in request.requested_components:
            _tool_id, requirement = requirements[component_id]
            if (
                requirement.provenance != "verified"
                or not requirement.cache_subpath
                or not requirement.source.immutable_ref
                or not requirement.source.sha256
            ):
                raise OperationError("requested component lacks immutable catalog inputs")
            if _locked_intrinsic_candidate_is_temporally_unusable(
                requirement,
                evaluated_at,
            ):
                raise OperationError(
                    "requested source-intrinsic component requires a reviewed lock refresh"
                )
            if requirement.kind == "rules":
                rule_set = self.rules.value.rule_set(component_id)
                if any(
                    canary.state != "verified" or not canary.output_sha256
                    for canary in rule_set.canaries
                ):
                    raise OperationError("rules canary evidence is not verified")

        root = _secure_directory(self.cache_root, "tool cache root", create=True)
        cache_repair.recover_repair(root, context.checkpoint)
        resolved = resolve_active_generation(
            root,
            checkpoint=context.checkpoint,
            progress=_generation_progress(context, "validating_active"),
        )
        if resolved.state == "invalid" and set(request.requested_components) == set(CACHE_COMPONENT_IDS):
            # No data from the damaged generation is carried. This admission
            # accepts only a structurally owned sole selection, not a malformed
            # pointer, fallback or a partially selected repair.
            source = cache_repair.admit_repair(root, resolved, context.checkpoint)
            object.__setattr__(context, "_repair_source", source)
        elif resolved.state in {"fallback", "invalid"}:
            raise OperationError("cache update requires a valid active generation or complete repair")
        else:
            _prune_unreferenced_generations(
                root,
                context.checkpoint,
                allow_missing_pointer=True,
            )
        _data_update_capacity_preflight(
            root,
            resolved,
            request.requested_components,
            requirements,
        )
        previous, reusable_data = _previous_data_for_missing_components(
            root, resolved, request.requested_components, self.tools, self.rules,
            context, evaluated_at=_evaluation_moment(self.evaluation_now()),
        )

        staging_root = _secure_directory(
            root / "staging",
            "updater staging root",
            create=True,
        )
        operation_stage = staging_root / str(request.operation_id)
        if operation_stage.exists() or operation_stage.is_symlink():
            _remove_private_staging_tree(operation_stage)
        if operation_stage.exists() or operation_stage.is_symlink():
            raise OperationError("operation staging directory could not be reset")
        operation_stage.mkdir(mode=0o700)
        payload = operation_stage / "payload"
        payload.mkdir(mode=0o700)
        receipts: dict[str, CacheComponentReceipt] = {}
        staged_data: dict[str, StagedDataComponent] = {}
        try:
            if resolved.state == "ready" and resolved.generation is not None:
                active = resolved.generation
                carried_receipts = [
                    receipt
                    for receipt in active.manifest.components
                    if receipt.component_id not in request.requested_components
                ]
                # A refreshed immutable component necessarily changes the tool
                # lock hash. Admit unchanged components by their exact current
                # lock identity, canary evidence, installed-content receipt,
                # and freshness instead of trusting or rejecting a different
                # lock document wholesale. The structurally validated generation
                # and copy helper independently rehash every carried file.
                _validate_component_receipts(
                    carried_receipts,
                    [],
                    self.tools,
                    self.rules,
                    evaluated_at=evaluated_at,
                )
                carried_total = len(carried_receipts)
                for carried_index, receipt in enumerate(carried_receipts, start=1):
                    context.progress(
                        "retaining",
                        component_id=receipt.component_id,
                        component_index=carried_index,
                        component_total=carried_total,
                    )
                    receipts[receipt.component_id] = _copy_validated_component(
                        active,
                        receipt,
                        payload,
                        context.checkpoint,
                        lambda completed, total: context.byte_progress(
                            completed,
                            total,
                            force=completed in {0, total},
                        ),
                    )

            component_total = len(request.requested_components)
            for component_index, component_id in enumerate(
                request.requested_components, start=1
            ):
                progress_context = {
                    "component_id": component_id,
                    "component_index": component_index,
                    "component_total": component_total,
                }
                tool_id, requirement = requirements[component_id]
                if component_id in reusable_data:
                    receipt = reusable_data[component_id]
                    assert previous is not None and receipt.expires_at is not None
                    context.progress("retaining", **progress_context)
                    _copy_validated_component(
                        previous, receipt, payload, context.checkpoint,
                        lambda completed, total: context.byte_progress(
                            completed, total, force=completed in {0, total},
                        ),
                    )
                    staged_data[component_id] = StagedDataComponent(
                        tool_id=tool_id,
                        requirement=requirement,
                        updated_at=receipt.updated_at,
                        expires_at=receipt.expires_at,
                        files=[CacheFileRecord(
                            path=item.path.removeprefix(receipt.root + "/"),
                            size_bytes=item.size_bytes, sha256=item.sha256,
                        ) for item in receipt.files],
                        grype_logical_content=receipt.grype_logical_content,
                    )
                    continue
                context.progress("downloading", **progress_context)
                if requirement.kind != "rules":
                    if component_id.startswith("trivy-"):
                        staged_data[component_id] = _stage_trivy_component(
                            context,
                            requirement,
                            payload=payload,
                            operation_stage=operation_stage,
                            progress_context=progress_context,
                        )
                    elif component_id == "grype-db":
                        staged_data[component_id] = _stage_grype_component(
                            context,
                            requirement,
                            payload=payload,
                            operation_stage=operation_stage,
                            timeout_seconds=context.remaining_seconds(self.timeout_seconds),
                            progress_context=progress_context,
                        )
                    else:  # pragma: no cover - strict cache component catalog guard
                        raise OperationError("data component has no admitted promotion handler")
                    continue
                rule_set = self.rules.value.rule_set(component_id)
                component_root = payload / str(requirement.cache_subpath)
                if rule_set.distribution_mode == "embedded":
                    context.progress("validating_source", **progress_context)
                    source = Path(str(requirement.source.discovery_ref))
                    observed = collect_canonical_tree(source, require_immutable=True)
                    if (
                        observed.algorithm != rule_set.tree_hash_algorithm
                        or observed.sha256 != rule_set.tree_sha256
                        or observed.file_count != rule_set.tree_file_count
                        or observed.size_bytes != rule_set.tree_size_bytes
                    ):
                        raise OperationError("embedded rules tree differs from its reviewed lock")
                    locked_files = [
                        CacheFileRecord(
                            path=item.path,
                            size_bytes=item.size_bytes,
                            sha256=item.sha256,
                        )
                        for item in rule_set.files
                    ]
                    if tuple(locked_files) != observed.files:
                        raise OperationError("embedded rules files differ from their allowlist")
                    _copy_exact_tree(
                        source,
                        component_root,
                        locked_files,
                        context.checkpoint,
                    )
                    relative_records = locked_files
                elif rule_set.distribution_mode == "external" and component_id == "bearer-rules":
                    archives = operation_stage / "archives"
                    archives.mkdir(mode=0o700)
                    unpacked = operation_stage / "unpacked"
                    unpacked.mkdir(mode=0o700)
                    for asset in rule_set.assets:
                        context.progress("downloading", **progress_context)
                        archive = _safe_direct_child(archives, asset.name, "rule asset name")
                        download_locked_asset(
                            url=asset.url,
                            expected_sha256=asset.sha256,
                            expected_size=asset.size_bytes,
                            destination=archive,
                            context=context,
                            timeout_seconds=context.remaining_seconds(self.timeout_seconds),
                            opener=self.opener,
                        )
                        context.progress("validating_source", **progress_context)
                        language = asset.name.removesuffix(".tar.gz")
                        destination = _safe_direct_child(
                            operation_stage, f"extract-{language}", "rule extraction root"
                        )
                        extract_locked_tar_gz(archive, destination, context)
                        extracted_tree = collect_canonical_tree(destination)
                        if any(
                            not item.path.startswith(language + "/")
                            for item in extracted_tree.files
                        ):
                            raise OperationError("rule asset archive has an unexpected root")
                        language_root = destination / language
                        target = _safe_direct_child(unpacked, language, "rule language root")
                        if target.exists() or target.is_symlink() or not language_root.is_dir():
                            raise OperationError("rule asset language root is unsafe or duplicated")
                        destination.chmod(0o700)
                        # The extractor seals every directory after validation.
                        # Re-open only this private staging root long enough to
                        # move it into the combined tree; the promoted copy is
                        # independently hashed and sealed below.
                        language_root.chmod(0o700)
                        language_root.rename(target)
                        destination.rmdir()
                    observed = collect_canonical_tree(unpacked)
                    if (
                        observed.algorithm != rule_set.tree_hash_algorithm
                        or observed.sha256 != rule_set.tree_sha256
                        or observed.file_count != rule_set.tree_file_count
                        or observed.size_bytes != rule_set.tree_size_bytes
                    ):
                        raise OperationError("extracted rules tree differs from its reviewed lock")
                    _copy_exact_tree(
                        unpacked,
                        component_root,
                        list(observed.files),
                        context.checkpoint,
                    )
                    relative_records = list(observed.files)
                else:
                    raise OperationError("rules distribution has no admitted promotion handler")

                canaries = run_rule_canaries(
                    context,
                    rule_set,
                    component_root,
                    self.scratch_root,
                )

                receipts[component_id] = CacheComponentReceipt(
                    component_id=component_id,
                    tool_id=tool_id,
                    kind=requirement.kind,
                    root=str(requirement.cache_subpath),
                    immutable_ref=str(requirement.source.immutable_ref),
                    source_sha256=str(requirement.source.sha256),
                    updated_at=utc_timestamp(),
                    expires_at=None,
                    files=_prefixed_records(str(requirement.cache_subpath), relative_records),
                    canaries=canaries,
                )

            # Reproduce data canaries only after every requested component has
            # been staged. Trivy's source, Java, and checks facets deliberately
            # share one cache root, so validating an individual partial tree
            # before its siblings exist would not prove the runtime contract.
            for component_id in sorted(staged_data):
                component_index = request.requested_components.index(component_id) + 1
                context.progress(
                    "validating_source",
                    component_id=component_id,
                    component_index=component_index,
                    component_total=component_total,
                )
                staged = staged_data[component_id]
                canaries = _run_data_canaries(
                    context,
                    staged,
                    payload=payload,
                    scratch_root=self.scratch_root,
                )
                requirement = staged.requirement
                receipts[component_id] = CacheComponentReceipt(
                    component_id=component_id,
                    tool_id=staged.tool_id,
                    kind=requirement.kind,
                    root=str(requirement.cache_subpath),
                    immutable_ref=str(requirement.source.immutable_ref),
                    source_sha256=str(requirement.source.sha256),
                    updated_at=staged.updated_at,
                    expires_at=staged.expires_at,
                    grype_logical_content=staged.grype_logical_content,
                    files=_prefixed_records(
                        str(requirement.cache_subpath), staged.files
                    ),
                    canaries=canaries,
                )

            context.progress("staging")
            manifest = GenerationManifest.create(
                tool_lock_sha256=self.tools.sha256,
                rules_lock_sha256=self.rules.sha256,
                created_at=utc_timestamp(),
                components=sorted(receipts.values(), key=lambda item: item.component_id),
            )
            return _publish_sealed_generation(
                root,
                operation_stage,
                payload,
                manifest,
                context.refresh_activity,
                _generation_progress(context, "validating_generation"),
                before_publish=(lambda candidate: cache_repair.record_candidate(
                    root, context._repair_source, candidate, str(request.operation_id),
                    request.request_digest, context.checkpoint,
                )) if context._repair_source is not None else None,
            )
        finally:
            _remove_private_staging_tree(operation_stage)


def _validate_candidate_components(
    candidate: ValidatedGeneration,
    requested_components: list[str],
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    *,
    evaluated_at: datetime,
) -> None:
    evaluated = _evaluation_moment(evaluated_at)
    manifest = candidate.manifest
    tools, rules = generation_locks(candidate, tools, rules)
    if manifest.tool_lock_sha256 != tools.sha256 or manifest.rules_lock_sha256 != rules.sha256:
        raise OperationError("candidate generation was produced from different reviewed locks")
    _validate_component_receipts(
        manifest.components,
        requested_components,
        tools,
        rules,
        evaluated_at=evaluated,
    )


def _validate_component_receipts(
    component_receipts: list[CacheComponentReceipt],
    requested_components: list[str],
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    *,
    evaluated_at: datetime,
) -> None:
    """Bind receipts directly to current locks, independent of another lock hash."""

    evaluated = _evaluation_moment(evaluated_at)
    requirements = {
        requirement.id: (tool.id, requirement)
        for tool in tools.value.tools
        for requirement in tool.requirements
    }
    receipts = {item.component_id: item for item in component_receipts}
    if len(receipts) != len(component_receipts):
        raise OperationError("candidate generation contains duplicate cache components")
    if set(receipts) - set(requirements):
        raise OperationError("candidate generation contains an unreviewed cache component")
    missing = set(requested_components) - set(receipts)
    if missing:
        raise OperationError("candidate generation omits a requested cache component")
    for component_id, receipt in receipts.items():
        tool_id, requirement = requirements[component_id]
        try:
            updated = _parse_utc(receipt.updated_at, "candidate component updated_at")
        except ValueError as exc:  # pragma: no cover - strict manifest model guard
            raise OperationError("candidate component timestamp is invalid") from exc
        if updated > evaluated + timedelta(minutes=5):
            raise OperationError("candidate component timestamp is in the future")
        if requirement.provenance != "verified":
            raise OperationError("candidate generation uses a cache component without verified provenance")
        if (
            receipt.tool_id != tool_id
            or receipt.kind != requirement.kind
            or receipt.root != requirement.cache_subpath
            or receipt.immutable_ref != requirement.source.immutable_ref
            or receipt.source_sha256 != requirement.source.sha256
        ):
            raise OperationError("candidate generation identity differs from the reviewed tool lock")
        if requirement.kind == "rules":
            try:
                rule_set = rules.value.rule_set(component_id)
            except KeyError as exc:
                raise OperationError("candidate rules component is absent from its rule lock") from exc
            expected_canaries = sorted(rule_set.canaries, key=lambda item: item.id)
            observed_canaries = sorted(receipt.canaries, key=lambda item: item.canary_id)
            if any(item.state != "verified" or not item.output_sha256 for item in expected_canaries):
                raise OperationError("candidate rules component has unattested canary evidence")
            if [item.id for item in expected_canaries] != [item.canary_id for item in observed_canaries]:
                raise OperationError("candidate rules canaries differ from the reviewed rule lock")
            for expected, observed in zip(expected_canaries, observed_canaries, strict=True):
                if (
                    observed.fixture_sha256 != expected.fixture_sha256
                    or observed.output_sha256 != expected.output_sha256
                    or observed.exit_code != expected.expected_exit_code
                    or observed.result_count != expected.expected_result_count
                    or observed.expected_ids != sorted(expected.expected_rule_ids)
                    or observed.observed_ids != sorted(expected.expected_rule_ids)
                ):
                    raise OperationError("candidate rules canary receipt differs from its rule lock")
        else:
            if not receipt_matches_installed_content(receipt, requirement):
                raise OperationError(
                    "candidate installed data differs from the reviewed tool lock"
                )
            expected_canaries = sorted(
                requirement.canaries, key=lambda item: item.id
            )
            observed_canaries = sorted(
                receipt.canaries, key=lambda item: item.canary_id
            )
            if [item.id for item in expected_canaries] != [
                item.canary_id for item in observed_canaries
            ]:
                raise OperationError(
                    "candidate data canaries differ from the reviewed tool lock"
                )
            for expected, observed in zip(
                expected_canaries, observed_canaries, strict=True
            ):
                if (
                    observed.fixture_sha256 != expected.fixture_sha256
                    or observed.output_sha256 != expected.output_sha256
                    or observed.exit_code != expected.expected_exit_code
                    or observed.result_count != expected.expected_result_count
                    or observed.expected_ids != expected.expected_ids
                    or observed.observed_ids != expected.expected_ids
                ):
                    raise OperationError(
                        "candidate data canary receipt differs from the tool lock"
                    )
            if receipt.expires_at is None or requirement.max_age_seconds is None:
                raise OperationError("candidate data freshness evidence is incomplete")
            try:
                expires = _parse_utc(
                    receipt.expires_at,
                    "candidate component expires_at",
                )
            except ValueError as exc:  # pragma: no cover - strict manifest model guard
                raise OperationError("candidate component expiry is invalid") from exc
            if not receipt_matches_freshness_contract(receipt, requirement):
                raise OperationError("candidate data freshness differs from its lock")
            if expires <= evaluated + timedelta(
                seconds=MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS
            ):
                raise OperationError(
                    "candidate data residual freshness window is insufficient"
                )


def evaluate_cache_rollback_eligibility(
    cache_root: Path,
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    *,
    evaluated_at: datetime | None = None,
    resolver: Callable[[GenerationReference], ResolvedGeneration] | None = None,
) -> CacheRollbackEligibility:
    """Validate the exact current rollback target without admitting work.

    The scanner and updater use the same immutable generation and semantic
    validation code.  This keeps the UI/admission preflight from guessing from
    the mere presence of a ``previous_good`` pointer.
    """

    validate_lock_alignment(tools.value, rules.value)
    try:
        pointer = load_active_pointer(cache_root)
    except CacheValidationError:
        return CacheRollbackEligibility(
            eligible=False,
            reason_code="cache_pointer_invalid",
            reason="Scanner cache state is unavailable or invalid; prepare scanners before rollback.",
            target_generation=None,
        )
    previous = pointer.previous_good
    if previous is None:
        return CacheRollbackEligibility(
            eligible=False,
            reason_code="no_previous_generation",
            reason="No previous-good scanner cache generation is available.",
            target_generation=None,
        )
    try:
        if resolver is None:
            candidate = validate_generation(
                cache_root,
                previous.generation_id,
                expected_manifest_sha256=previous.manifest_sha256,
            )
        else:
            resolved = resolver(previous)
            if resolved.verification is not None:
                observation = resolved.verification
                code, reason = {
                    "verifying": ("previous_generation_verifying", "The previous scanner cache generation is being verified. Rollback stays unavailable until verification finishes."),
                    "timed_out": ("previous_generation_verification_timeout", "Verification of the previous scanner cache generation timed out. Retry verification; no cache state was changed."),
                    "failed": ("previous_generation_verification_failed", "Verification of the previous scanner cache generation could not complete. Retry verification; no cache state was changed."),
                }[observation.state]
                return CacheRollbackEligibility(
                    eligible=False, reason_code=code, reason=reason,
                    target_generation=previous.generation_id, verification=observation,
                )
            candidate = resolved.generation
            if resolved.state != "ready" or candidate is None or candidate.reference != previous:
                raise CacheValidationError("previous generation proof is unavailable")
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            return CacheRollbackEligibility(
                eligible=False,
                reason_code="previous_generation_verification_timeout",
                reason="Verification of the previous scanner cache generation timed out. Refresh scanner status to retry; no cache state was changed.",
                target_generation=previous.generation_id,
            )
        return CacheRollbackEligibility(
            eligible=False,
            reason_code="previous_generation_invalid",
            reason="The previous scanner cache generation failed integrity validation and cannot be restored.",
            target_generation=previous.generation_id,
        )
    try:
        tools, rules = generation_locks(candidate, tools, rules)
    except DataCatalogError:
        return CacheRollbackEligibility(
            eligible=False, reason_code="different_reviewed_locks",
            reason="The previous cache generation's signed scanner data authority is unavailable or invalid.",
            target_generation=previous.generation_id,
        )
    if (
        candidate.manifest.tool_lock_sha256 != tools.sha256
        or candidate.manifest.rules_lock_sha256 != rules.sha256
    ):
        return CacheRollbackEligibility(
            eligible=False,
            reason_code="different_reviewed_locks",
            reason="The previous cache generation was built from different reviewed scanner locks. Prepare a verified cache for the current scanner catalog instead.",
            target_generation=previous.generation_id,
        )
    try:
        _validate_component_receipts(
            candidate.manifest.components,
            [],
            tools,
            rules,
            evaluated_at=_evaluation_moment(evaluated_at or _utc_now()),
        )
    except OperationError:
        return CacheRollbackEligibility(
            eligible=False,
            reason_code="previous_generation_incompatible",
            reason="The previous cache generation no longer satisfies the current scanner component and freshness requirements.",
            target_generation=previous.generation_id,
        )
    return CacheRollbackEligibility(
        eligible=True,
        reason_code="eligible",
        reason="The previous verified cache generation is compatible and can be restored atomically.",
        target_generation=previous.generation_id,
    )


def _safe_operation_telemetry_detail(exc: Exception) -> str:
    """Return a bounded diagnostic without paths, URLs, or untrusted output."""

    if (
        isinstance(exc, GrypeContentValidationError)
        and type(exc.code) is str
        and exc.code in get_args(GrypeContentErrorCode)
    ):
        return f"grype_validation_{exc.code}"
    if not isinstance(exc, OperationError):
        return "non-operation exception redacted"
    detail = str(exc)
    try:
        _require_bounded_text(detail, "operation telemetry detail", 256)
    except ValueError:
        return "operation exception detail redacted"
    if "://" in detail or "/" in detail or "\\" in detail:
        return "operation exception detail redacted"
    return detail


def _log_operation_failure(
    store: OperationStore,
    operation_id: UUID,
    exc: Exception,
) -> None:
    try:
        record = store.load(operation_id)
        stage = record.stage
        component_id = (
            record.activity.component_id if record.activity is not None else None
        )
    except Exception:
        stage = "unavailable"
        component_id = None
    if isinstance(exc, AssetTransportError):
        LOGGER.error(
            "scanner asset transport failed operation_id=%s stage=%s component_id=%s "
            "transport_stage=%s reason=%s returncode=%s signal=%s",
            operation_id, stage, component_id, exc.transport_stage,
            exc.reason, exc.returncode, exc.signal,
        )
        return
    if isinstance(exc, DataCommandOutputLimitError):
        LOGGER.error(
            "scanner lifecycle command failed operation_id=%s stage=%s "
            "component_id=%s command_id=%s error_type=%s output_limit_bytes=%s",
            operation_id, stage, component_id, exc.command_id,
            type(exc).__name__, exc.limit_bytes,
        )
        return
    if isinstance(exc, DataCommandFailureError):
        timing = exc.timing
        LOGGER.error(
            "scanner lifecycle command failed operation_id=%s stage=%s "
            "component_id=%s command_id=%s returncode=%s signal=%s "
            "stderr_bytes=%s stderr_sha256=%s stderr_markers=%s http_status_markers=%s "
            "elapsed_ms=%s effective_timeout_ms=%s local_limit_ms=%s preparation_budget_ms=%s "
            "timing_capped=%s",
            operation_id, stage, component_id, exc.command_id, exc.returncode,
            exc.signal, exc.stderr_bytes, exc.stderr_sha256,
            ",".join(exc.stderr_markers) or "none",
            ",".join(exc.http_status_markers) or "none",
            timing.elapsed_ms if timing else None,
            timing.effective_timeout_ms if timing else None,
            timing.local_limit_ms if timing else None,
            timing.preparation_budget_ms if timing else None,
            timing.capped if timing else None,
        )
        return
    if isinstance(exc, InstalledContentMismatchError):
        evidence = exc.evidence
        LOGGER.error(
            "scanner lifecycle operation failed operation_id=%s stage=%s "
            "component_id=%s error_type=%s detail=%s runtime_platform=%s "
            "expected_sha256=%s observed_sha256=%s expected_file_count=%s "
            "observed_file_count=%s expected_size_bytes=%s observed_size_bytes=%s "
            "grype_database_sha256=%s grype_import_metadata_sha256=%s",
            operation_id,
            stage,
            component_id,
            type(exc).__name__,
            _safe_operation_telemetry_detail(exc),
            evidence.runtime_platform,
            evidence.expected_sha256,
            evidence.observed_sha256,
            evidence.expected_file_count,
            evidence.observed_file_count,
            evidence.expected_size_bytes,
            evidence.observed_size_bytes,
            exc.database_sha256,
            exc.import_metadata_sha256,
        )
        return
    if isinstance(exc, GrypeContentValidationError):
        from .grype_identity import bounded_validation_timing

        timing = bounded_validation_timing(exc.validation_timing)
        if timing is not None:
            LOGGER.error(
                "scanner lifecycle operation failed operation_id=%s stage=%s component_id=%s "
                "error_type=%s detail=%s validation_phase=%s phase_elapsed_ms=%s "
                "validation_elapsed_ms=%s timing_capped=%s",
                operation_id, stage, component_id, type(exc).__name__,
                _safe_operation_telemetry_detail(exc), timing["phase"], timing["phase_elapsed_ms"],
                timing["validation_elapsed_ms"], timing["capped"],
            )
            return
    LOGGER.error(
        "scanner lifecycle operation failed operation_id=%s stage=%s component_id=%s "
        "error_type=%s detail=%s",
        operation_id,
        stage,
        component_id,
        type(exc).__name__,
        _safe_operation_telemetry_detail(exc),
    )


def execute_operation(
    request: OperationRequest,
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    store: OperationStore,
    *,
    cache_update: CacheUpdateHandler | None = None,
    catalog_check: CatalogCheckHandler | None = None,
    admitted: bool = False,
    now: Callable[[], str] = utc_timestamp,
    evaluation_now: Callable[[], datetime] = _utc_now,
) -> OperationRecord:
    """Run one reviewed operation and publish only an admitted terminal receipt."""

    if now is utc_timestamp:
        now = lambda: _precise_utc_timestamp(_utc_now())
    validate_lock_alignment(tools.value, rules.value)
    validate_operation_request(request, tools.value)
    if admitted:
        record = store.load(
            request.operation_id,
            request_digest=request.request_digest,
        )
        if record.status != "queued" or record.attempt != request.attempt:
            raise OperationConflictError(
                "admitted operation is no longer queued for this attempt"
            )
        should_execute = True
    else:
        record, should_execute = store.create_or_get(request, now=now())
    if not should_execute:
        return record
    context = OperationContext(request=request, store=store, wall_now=now)
    lock_token = _PREPARATION_LOCK_CHECK.set(None)
    try:
        budget = request.reconciliation_budget or request.preparation_budget
        if budget is not None:
            clock = PreparationClock(
                budget,
                now=lambda: _parse_utc(now(), "preparation clock"),
                high_water=_parse_utc(record.updated_at, "preparation high water"),
            )
            object.__setattr__(context, "_budget_clock", clock)
            _PREPARATION_LOCK_CHECK.set(lambda: clock.remaining(900))
        context.progress("resolving_lock", now=now())
        if request.kind == "cache_reconcile":
            from .readonly_recovery import execute_reconciliation
            return execute_reconciliation(context, tools, rules, now=now)
        if request.kind in {"cache_update", "cache_rollback"}:
            if request.kind == "cache_rollback":
                with generation_lock(store.cache_root, checkpoint=context.checkpoint):
                    context.progress("rolling_back", now=now())
                    context.checkpoint()
                    current_pointer = load_active_pointer(store.cache_root)
                    if current_pointer.previous_good is None:
                        raise OperationError(
                            "no previous-good generation is available"
                        )
                    previous_good = validate_generation(
                        store.cache_root,
                        current_pointer.previous_good.generation_id,
                        expected_manifest_sha256=(
                            current_pointer.previous_good.manifest_sha256
                        ),
                        checkpoint=context.refresh_activity,
                        progress=_generation_progress(context, "validating_generation"),
                    )
                    context.checkpoint()
                    _validate_candidate_components(
                        previous_good,
                        [],
                        tools,
                        rules,
                        evaluated_at=_evaluation_moment(evaluation_now()),
                    )

                    def prepare_rollback_publication(
                        inner_previous_good: ValidatedGeneration,
                    ) -> str:
                        context.checkpoint()
                        rollback_moment = _evaluation_moment(evaluation_now())
                        _validate_candidate_components(
                            inner_previous_good,
                            [],
                            tools,
                            rules,
                            evaluated_at=rollback_moment,
                        )
                        rollback_at = _precise_utc_timestamp(rollback_moment)
                        store.transition(
                            request.operation_id,
                            status="running",
                            stage="committing",
                            now=rollback_at,
                        )
                        return rollback_at

                    pointer = rollback_to_previous_good(
                        store.cache_root,
                        str(request.operation_id),
                        checkpoint=context.refresh_activity,
                        progress=_generation_progress(context, "validating_generation"),
                        prepare_publication=prepare_rollback_publication,
                    )
                    _prune_unreferenced_generations(
                        store.cache_root,
                        context.checkpoint,
                    )
                    return store.transition(
                        request.operation_id,
                        status="completed",
                        stage="completed",
                        result=_pointer_result(pointer, []),
                        now=now(),
                    )
            if cache_update is None:
                raise OperationError("cache update handler is unavailable")
            with generation_lock(store.cache_root, checkpoint=context.checkpoint):
                context.progress("validating_active", now=now())
                generation_id = cache_update(context)
                context.progress("validating_generation", now=now())

                def validate_activation_replay(
                    inner_candidate: ValidatedGeneration,
                ) -> None:
                    context.checkpoint()
                    _validate_candidate_components(
                        inner_candidate,
                        request.requested_components,
                        tools,
                        rules,
                        evaluated_at=_evaluation_moment(evaluation_now()),
                    )

                def prepare_activation_publication(
                    inner_candidate: ValidatedGeneration,
                ) -> str:
                    context.checkpoint()
                    activation_moment = _evaluation_moment(evaluation_now())
                    _validate_candidate_components(
                        inner_candidate,
                        request.requested_components,
                        tools,
                        rules,
                        evaluated_at=activation_moment,
                    )
                    context.checkpoint()
                    activation_at = _precise_utc_timestamp(activation_moment)
                    # Persist the non-cancellable commit point only after the
                    # helper's final structural walk and semantic freshness
                    # fence. No cancellation checkpoint occurs between this
                    # transition and the atomic active-pointer publication.
                    store.transition(
                        request.operation_id,
                        status="running",
                        stage="committing",
                        now=activation_at,
                    )
                    _PREPARATION_LOCK_CHECK.set(None)
                    return activation_at

                if context._repair_source is not None:
                    pointer = cache_repair.activate_repair(
                        store.cache_root, generation_id, str(request.operation_id),
                        request.request_digest,
                        checkpoint=context.refresh_activity,
                        progress=_generation_progress(context, "validating_generation"),
                        prepare_publication=prepare_activation_publication,
                    )
                else:
                    pointer = activate_generation(
                        store.cache_root,
                        generation_id,
                        str(request.operation_id),
                        checkpoint=context.refresh_activity,
                        progress=_generation_progress(context, "validating_generation"),
                        prepare_publication=prepare_activation_publication,
                        validate_replay=validate_activation_replay,
                    )
                try:
                    if context._repair_source is not None:
                        cache_repair.recover_repair(store.cache_root, context.refresh_activity)
                    _prune_unreferenced_generations(
                        store.cache_root,
                        context.checkpoint,
                    )
                except PreparationDeadlineExceeded:
                    # Publication already returned its validated atomic pointer.
                    # Defer maintenance without inventing a second validation
                    # window or erasing the actual activated cache outcome.
                    LOGGER.info("post-publication maintenance deferred at preparation deadline")
                result: CatalogOperationResult | CacheOperationResult = _pointer_result(
                    pointer,
                    request.requested_components,
                )
                return store.transition(
                    request.operation_id,
                    status="completed",
                    stage="completed",
                    result=result,
                    now=now(),
                )
        else:
            if catalog_check is None:
                raise OperationError("catalog check handler is unavailable")
            context.progress("discovering", now=now())
            result = catalog_check(context)
            # Revalidation here prevents a handler from returning a constructed
            # model that was later mutated outside Pydantic.
            result = CatalogOperationResult.model_validate(result.model_dump(mode="json"))
        context.checkpoint()
        return store.transition(
            request.operation_id,
            status="completed",
            stage="completed",
            result=result,
            now=now(),
        )
    except OperationStateError:
        cleanup_clock = _ReadOnlyReconciliationClock() if request.kind == "cache_reconcile" else None
        _PREPARATION_LOCK_CHECK.set(cleanup_clock.checkpoint if cleanup_clock is not None else None)
        if request.kind == "cache_reconcile":
            from .readonly_recovery import reconcile_intent
            published = reconcile_intent(store, request.operation_id, clock=cleanup_clock)
        else:
            published = store.reconcile_published(
                request.operation_id,
                now=now(),
                preparation_budget=request.preparation_budget,
            )
        if published is not None:
            return published
        current = store.load(request.operation_id)
        if current.status == "cancelling":
            return store.transition(
                request.operation_id,
                status="cancelled",
                stage="cancelled",
                now=now(),
            )
        if current.status == "cancelled":
            return current
        return _fail_operation(store, request.operation_id, "operation_state_invalid", now())
    except Exception as exc:
        cleanup_clock = _ReadOnlyReconciliationClock() if request.kind == "cache_reconcile" else None
        _PREPARATION_LOCK_CHECK.set(cleanup_clock.checkpoint if cleanup_clock is not None else None)
        _log_operation_failure(store, request.operation_id, exc)
        if request.kind == "cache_reconcile":
            from .readonly_recovery import reconcile_intent
            published = reconcile_intent(store, request.operation_id, clock=cleanup_clock)
        else:
            published = store.reconcile_published(
                request.operation_id,
                now=now(),
                preparation_budget=request.preparation_budget,
            )
        if published is not None:
            return published
        return _fail_operation(
            store,
            request.operation_id,
            "operation_failed",
            now(),
            exc=exc,
        )
    finally:
        _PREPARATION_LOCK_CHECK.reset(lock_token)


def _pointer_result(pointer: ActiveGenerationPointer, updated: list[str]) -> CacheOperationResult:
    return CacheOperationResult(
        kind="cache",
        active=pointer.active,
        previous_good=pointer.previous_good,
        updated_components=sorted(updated),
    )


def _fail_operation(
    store: OperationStore,
    operation_id: UUID,
    error_code: str,
    timestamp: str,
    *,
    exc: Exception | None = None,
) -> OperationRecord:
    """Persist bounded failure evidence without paths, URLs, or process output."""

    current = store.load(operation_id)
    if current.status in _TERMINAL_STATUS_SET:
        return current
    error_detail = (
        "scanner lifecycle operation failed; inspect bounded service telemetry"
    )
    if isinstance(exc, PreparationDeadlineExceeded):
        if current.status == "cancelling" or current.cancel_requested_at is not None:
            return store.transition(operation_id, status="cancelled", stage="cancelled", now=timestamp)
        error_code = ("scanner_reconciliation_deadline" if current.kind == "cache_reconcile"
                      else "scanner_preparation_deadline")
        error_detail = "scanner operation exceeded its immutable preparation deadline"
    elif current.kind == "cache_reconcile":
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            error_code = "scanner_reconciliation_deadline"
        else:
            error_code = ("scanner_reconciliation_target_changed" if isinstance(exc, OperationConflictError)
                          else "scanner_reconciliation_invalid")
        error_detail = "read-only cache outcome reconciliation failed; original outcome is preserved"
    elif isinstance(exc, AssetTransportError):
        error_code = "locked_asset_transport_failed"
        error_detail = (
            f"locked asset transport failed ({exc.transport_stage}, {exc.reason}, "
            f"exit {exc.returncode})"
        )
    elif isinstance(exc, InstalledContentMismatchError):
        error_code = "installed_content_mismatch"
        runtime_platform = exc.evidence.runtime_platform.replace("/", " ")
        error_detail = (
            "scanner installed data differs from its reviewed lock on "
            f"{runtime_platform}"
        )
    elif isinstance(exc, GrypeContentValidationError):
        if exc.retryable:
            error_code = "cache_grype_validation_timeout"
            error_detail = (
                "Grype database validation timed out; the candidate was not "
                "activated and preparation may be retried."
            )
        else:
            error_code = "cache_grype_validation_invalid"
            error_detail = (
                f"Grype database validation failed ({exc.code}); the candidate "
                "was not activated. Review scanner preparation details before retrying."
            )
    elif isinstance(exc, DataCatalogError):
        error_code = "scanner_data_catalog_invalid"
        error_detail = (
            f"Signed scanner data catalog admission failed ({exc.code}); "
            "the active cache was not changed. Check the reviewed catalog and release trust configuration."
        )
    elif isinstance(exc, DataCommandOutputLimitError):
        error_code = "data_command_output_limit"
        error_detail = (
            f"scanner preparation command {exc.command_id} exceeded its captured "
            f"output limit of {exc.limit_bytes} bytes; inspect bounded service telemetry"
        )
    elif isinstance(exc, DataCommandFailureError):
        error_code = "data_command_failed"
        error_detail = (
            f"scanner preparation command {exc.command_id} failed "
            f"with exit status {exc.returncode}; inspect bounded service telemetry"
        )
    return store.transition(
        operation_id,
        status="failed",
        stage="failed",
        error_code=error_code,
        error_detail=error_detail,
        activity=None,
        now=timestamp,
    )
