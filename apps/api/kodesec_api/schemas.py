from datetime import datetime, timedelta
import posixpath
import re
import unicodedata
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .remote_url import normalize_remote_url
from .preparation_budget import PreparationBudget


MAX_PUBLIC_SAFE_DETAIL_TEXT_LENGTH = 500


class ProblemDetail(BaseModel):
    """Bounded, machine-readable error detail for interactive API workflows."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1, max_length=500)
    action: str | None = Field(
        default=None,
        min_length=1,
        max_length=80,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    context: dict[str, Any] = Field(default_factory=dict, max_length=16)
    correlation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$",
    )
    safe_details: dict[str, str | int | bool | None] | None = Field(
        default=None,
        max_length=8,
    )

    @field_validator("safe_details")
    @classmethod
    def validate_safe_details(
        cls, value: dict[str, str | int | bool | None] | None
    ) -> dict[str, str | int | bool | None] | None:
        if value is None:
            return None
        allowed = {
            "configured_source_boundary",
            "current_revision",
            "expected_revision",
            "provider_id",
            "reason_code",
            "resource",
            "selected_source",
            "transport",
        }
        if any(key not in allowed for key in value):
            raise ValueError("safe_details contains a non-public field")
        for item in value.values():
            if isinstance(item, str) and (
                len(item) > MAX_PUBLIC_SAFE_DETAIL_TEXT_LENGTH
                or any(unicodedata.category(character) in {"Cc", "Cf"} for character in item)
            ):
                raise ValueError("safe_details text must be bounded visible text")
            if isinstance(item, int) and not isinstance(item, bool) and not -(2**31) <= item < 2**31:
                raise ValueError("safe_details integer is outside the public bound")
        return value


def normalize_project_repo_path(value: str) -> str:
    candidate = value.strip()
    if not candidate.startswith("/") or "\\" in candidate or "\x00" in candidate:
        raise ValueError("repo_path must be an absolute POSIX path")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in candidate):
        raise ValueError("repo_path must contain only safe Unicode scalar values")
    try:
        candidate.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("repo_path must contain only UTF-8 Unicode scalar values") from exc
    if ".." in candidate.split("/"):
        raise ValueError("repo_path must not contain parent traversal")
    normalized = posixpath.normpath(candidate)
    return f"/{normalized.lstrip('/')}" if normalized.startswith("//") else normalized


def normalize_scan_target_path(value: str) -> str:
    """Validate one selected canonical path below a project's source root."""

    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or posixpath.normpath(value) != value
    ):
        raise ValueError("target_path must be a canonical project-relative POSIX path")
    return value


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    repo_path: str = Field(min_length=1, max_length=4096)
    remote_url: str | None = Field(default=None, max_length=4096)
    default_branch: str = "main"

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in candidate
        ):
            raise ValueError("project name must contain visible text")
        return candidate

    @field_validator("repo_path")
    @classmethod
    def validate_repo_path(cls, value: str) -> str:
        return normalize_project_repo_path(value)

    @field_validator("remote_url")
    @classmethod
    def validate_remote_url(cls, value: str | None) -> str | None:
        return normalize_remote_url(value)


class ProjectResolve(BaseModel):
    repo_path: str = Field(min_length=1, max_length=4096)

    @field_validator("repo_path")
    @classmethod
    def validate_repo_path(cls, value: str) -> str:
        return normalize_project_repo_path(value)


class SourcePreviewRequest(ProjectResolve):
    model_config = ConfigDict(extra="forbid")


class SourcePreviewOut(BaseModel):
    """Configured mount authorization only; scan admission rechecks source safety."""

    model_config = ConfigDict(extra="forbid")

    installation_id: str = Field(pattern=r"^[0-9a-f]{12}$")
    repo_path: str
    authorization_mode: Literal["mounted"] = "mounted"
    authorized: bool
    configured_roots: list[str] = Field(min_length=1, max_length=32)
    reason_code: Literal["source_outside_allowed_root"] | None


class ProjectOut(BaseModel):
    id: int
    name: str
    repo_path: str
    remote_url: str | None
    default_branch: str
    revision: int = 1
    created_at: datetime

    model_config = {"from_attributes": True}


MAX_SOURCE_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_SNAPSHOT_BASE64_BYTES = 4 * ((MAX_SOURCE_SNAPSHOT_FILE_BYTES + 2) // 3)


class SourceSnapshotLimitsOut(BaseModel):
    """Transfer admission is separate from the scanner's eligible-code bound."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1] = 1
    max_file_bytes: Literal[8_388_608] = 8_388_608
    max_total_bytes: Literal[67_108_864] = 67_108_864
    max_files: Literal[5000] = 5000
    max_encoded_request_bytes: Literal[117_440_512] = 117_440_512
    eligible_source_max_file_bytes: Literal[1_048_576] = 1_048_576


class SourceSnapshotFile(BaseModel):
    """One bounded regular file in a native-Windows local source snapshot."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)
    content_base64: str = Field(min_length=0, max_length=MAX_SOURCE_SNAPSHOT_BASE64_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=MAX_SOURCE_SNAPSHOT_FILE_BYTES)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_scan_target_path(value)


MAX_SOURCE_SNAPSHOT_FILES = 5000
MAX_SOURCE_SNAPSHOT_BYTES = 64 * 1024 * 1024


class SourceSnapshotCreate(BaseModel):
    """Explicit bounded source material admitted only by the snapshot route."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str = Field(min_length=1, max_length=120)
    directory_scope: str | None = Field(default=None, min_length=1, max_length=4096)
    files: list[SourceSnapshotFile] = Field(max_length=MAX_SOURCE_SNAPSHOT_FILES)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in candidate
        ):
            raise ValueError("snapshot name must contain visible text")
        return candidate

    @field_validator("directory_scope")
    @classmethod
    def validate_directory_scope(cls, value: str | None) -> str | None:
        return normalize_scan_target_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_manifest_order(self) -> "SourceSnapshotCreate":
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("snapshot file paths must be unique and sorted")
        if sum(item.size_bytes for item in self.files) > MAX_SOURCE_SNAPSHOT_BYTES:
            raise ValueError("snapshot exceeds the 64 MiB total limit")
        if self.directory_scope is not None:
            prefix = f"{self.directory_scope}/"
            if any(not path.startswith(prefix) for path in paths):
                raise ValueError("snapshot files must remain inside directory_scope")
        return self


class SourceSnapshotOut(BaseModel):
    project: ProjectOut
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_scope: str | None
    file_count: int = Field(ge=0, le=MAX_SOURCE_SNAPSHOT_FILES)
    total_bytes: int = Field(ge=0, le=MAX_SOURCE_SNAPSHOT_BYTES)


class ScanCreate(BaseModel):
    project_id: int
    mode: Literal["full", "incremental_diff"] = "full"
    target_path: str | None = Field(default=None, min_length=1, max_length=4096)
    target_kind: Literal["file", "directory"] | None = None
    source_snapshot_digest: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    base_ref: str | None = Field(default=None, max_length=160)
    head_ref: str | None = Field(default=None, max_length=160)
    use_ai: bool = False
    coverage: Literal["complete", "limited"] = "complete"
    acknowledge_limited_coverage: bool = False
    preflight_revision: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def validate_coverage_acknowledgement(self) -> "ScanCreate":
        if (self.target_path is None) != (self.target_kind is None):
            raise ValueError("a selected source target requires both target_path and target_kind")
        if self.target_path is not None and self.mode != "full":
            raise ValueError("a selected source target requires mode=full")
        if self.coverage == "limited" and not self.acknowledge_limited_coverage:
            raise ValueError(
                "limited coverage requires acknowledge_limited_coverage=true"
            )
        if self.coverage == "limited" and self.preflight_revision is None:
            raise ValueError(
                "limited coverage requires the reviewed preflight_revision"
            )
        return self

    @field_validator("base_ref", "head_ref")
    @classmethod
    def validate_git_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or value != value.strip() or value.startswith("-"):
            raise ValueError("git ref must be non-empty, unpadded, and must not be option-shaped")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("git ref must not contain control characters")
        lowered = value.casefold()
        sensitive_markers = ("password=", "passwd=", "secret=", "token=", "authorization:", "bearer ")
        if any(marker in lowered for marker in sensitive_markers):
            raise ValueError("git ref contains credential-shaped material")
        return value

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str | None) -> str | None:
        return normalize_scan_target_path(value) if value is not None else None


class ScanSourceSnapshotOut(BaseModel):
    """Body-free original admission, not a claim about current disk contents."""

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["native-windows", "git-commit"] = "native-windows"
    source_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_scope: str | None
    target_path: str | None
    target_kind: Literal["file", "directory"] | None
    file_count: int = Field(ge=0, le=MAX_SOURCE_SNAPSHOT_FILES)
    total_bytes: int = Field(ge=0, le=MAX_SOURCE_SNAPSHOT_BYTES)

    @model_validator(mode="after")
    def validate_scope(self) -> "ScanSourceSnapshotOut":
        if (self.target_path is None) != (self.target_kind is None):
            raise ValueError("snapshot target requires both path and kind")
        for path in (self.directory_scope, self.target_path):
            if path is not None and normalize_scan_target_path(path) != path:
                raise ValueError("snapshot provenance path is not canonical")
        expected_scope = self.target_path if self.target_kind == "directory" else None
        if self.directory_scope != expected_scope:
            raise ValueError("snapshot provenance directory scope does not match target")
        return self


class ScanOut(BaseModel):
    id: int
    project_id: int
    mode: str
    base_ref: str | None
    head_ref: str | None
    status: str
    gate_decision: str | None
    gate_reasons: list[str]
    scanner_summary: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None
    revision: int = 1
    findings_revision: int = 1
    job_id: int | None = None
    job_revision: int | None = None
    source_snapshot: ScanSourceSnapshotOut | None = None

    model_config = {"from_attributes": True}


class JobActivityOut(BaseModel):
    component_id: str | None = Field(default=None, max_length=80)
    component_index: int | None = Field(default=None, ge=1, le=32)
    component_total: int | None = Field(default=None, ge=1, le=32)
    bytes_completed: int | None = Field(default=None, ge=0, le=4 * 1024 * 1024 * 1024)
    bytes_total: int | None = Field(default=None, ge=1, le=4 * 1024 * 1024 * 1024)
    updated_at: datetime


class JobOut(BaseModel):
    id: int
    original_job_id: int | None = None
    kind: str
    title: str
    status: str
    stage: str | None
    detail: str | None
    progress: int | None
    scan_id: int | None
    finding_id: int | None
    finding_display_id: str | None = None
    finding_scan_number: int | None = None
    finding_rule_id: str | None = None
    error: str | None
    error_code: str | None = None
    error_detail: str | None = None
    attempt: int = 0
    max_attempts: int = 1
    revision: int = 1
    cancel_requested_at: datetime | None = None
    heartbeat_at: datetime | None = None
    activity: JobActivityOut | None = None
    can_cancel: bool = False
    can_retry: bool = False
    can_reconcile_cache: bool = False
    retry_blocked_reason: str | None = None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    updated_at: datetime

    model_config = {"from_attributes": True}


class JobReconcileRequest(BaseModel):
    expected_revision: int = Field(ge=1, strict=True)
    model_config = {"extra": "forbid"}


class JobRetryRequest(BaseModel):
    expected_revision: int = Field(ge=1)


class FindingOut(BaseModel):
    id: int
    scan_id: int
    scan_finding_number: int
    display_id: str
    scanner: str
    rule_id: str
    severity: str
    file_path: str = Field(max_length=4096)
    start_line: int | None
    start_column: int | None
    end_line: int | None
    end_column: int | None
    message: str = Field(max_length=4000)
    code_snippet: str | None = Field(max_length=20_000)
    fingerprint: str
    metadata_json: dict[str, Any]
    ai_verdict: str | None
    ai_confidence: float | None
    ai_reasoning: str | None
    ai_fix: str | None
    suppressed: bool
    suppression_reason: str | None
    lifecycle_status: str = "open"
    gate_exempt: bool = False
    gate_exempt_reason: str | None = None
    lifecycle_reason: str | None = None
    lifecycle_updated_at: datetime | None = None
    occurrence_count: int = 1
    is_repeat: bool = False
    first_seen_display_id: str | None = None
    first_seen_scan_id: int | None = None
    revision: int = 1
    gate_effect: Literal["blocking", "non_blocking", "excluded"]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingDetailOut(FindingOut):
    """Exact finding evidence bound to its authoritative collection revision."""

    findings_revision: int = Field(ge=1)


class ScanArtifactOut(BaseModel):
    id: int
    scan_id: int
    scanner: str
    artifact_type: str
    format: str
    path: str
    size_bytes: int
    sha256: str
    created_at: datetime

    model_config = {"from_attributes": True}


class GatePolicyValues(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool = True
    max_critical: int = Field(default=0, ge=-1, le=999)
    max_high: int = Field(default=-1, ge=-1, le=999)
    block_secrets: bool = True


class GatePolicyUpdate(GatePolicyValues):
    expected_policy: GatePolicyValues


class AdvisorDisclosurePreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    provider_id: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9-]{0,39}$"
    )


class AdvisorDisclosureConfirmationOut(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["lomo-advisor-run-confirmation/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    authorization_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    provider_config_revision: int = Field(ge=1)
    provider_config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transport: Literal["direct", "ssh"]
    destination: str = Field(min_length=1, max_length=500)
    disclosure_mode: Literal["finding_evidence"]
    payload_categories: list[str] = Field(min_length=5, max_length=5)
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consent_approved_at: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
    )
    finding_id: int = Field(ge=1)
    finding_revision: int = Field(ge=1)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirmation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class AdvisorDisclosurePacketFindingOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = Field(ge=1)
    display_id: str = Field(min_length=1, max_length=80)
    scanner: str = Field(max_length=80)
    rule_id: str = Field(max_length=160)
    severity: str = Field(max_length=30)
    message: str = Field(max_length=4_000)
    fingerprint: str = Field(max_length=128)


class AdvisorDisclosurePacketLocationOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(min_length=1, max_length=4_096)
    start_line: int | None = Field(default=None, ge=1, le=2_147_483_647)
    start_column: int | None = Field(default=None, ge=1, le=2_147_483_647)
    end_line: int | None = Field(default=None, ge=1, le=2_147_483_647)
    end_column: int | None = Field(default=None, ge=1, le=2_147_483_647)


class AdvisorDisclosurePacketRepoContextOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str = Field(max_length=120)
    repo_path: str = Field(max_length=4_096)
    remote_url: str | None = Field(default=None, max_length=4_096)
    scan_id: int = Field(ge=1)
    mode: str = Field(max_length=40)
    base_ref: str | None = Field(default=None, max_length=160)
    head_ref: str | None = Field(default=None, max_length=160)


class AdvisorDisclosurePacketEvidenceOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code_snippet: str | None = Field(default=None, max_length=20_000)
    metadata: dict[str, Any]


class AdvisorDisclosurePacketOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    finding: AdvisorDisclosurePacketFindingOut
    location: AdvisorDisclosurePacketLocationOut
    repo_context: AdvisorDisclosurePacketRepoContextOut
    scanner_evidence: AdvisorDisclosurePacketEvidenceOut


class AdvisorDisclosurePreviewOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: AdvisorDisclosureConfirmationOut
    packet: AdvisorDisclosurePacketOut
    packet_utf8_bytes: int = Field(ge=2, le=256 * 1024)


class AdvisorTriageProviderPin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_collection_revision: int = Field(ge=1)
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    transport: Literal["local", "direct", "ssh"]
    provider_config_revision: int = Field(ge=1)
    provider_config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str | None = Field(default=None, max_length=120)
    expected_revision: int = Field(ge=1)
    advisor_provider_pin: AdvisorTriageProviderPin | None = None
    acknowledge_remote_source_disclosure: bool = False
    remote_advisor_confirmation: AdvisorDisclosureConfirmationOut | None = None

    @model_validator(mode="after")
    def validate_remote_confirmation_pair(self) -> "TriageRequest":
        if self.remote_advisor_confirmation is not None and not self.acknowledge_remote_source_disclosure:
            raise ValueError("remote Advisor confirmation requires explicit acknowledgement")
        if self.acknowledge_remote_source_disclosure and self.remote_advisor_confirmation is None:
            raise ValueError("remote Advisor acknowledgement requires one exact preview confirmation")
        if self.remote_advisor_confirmation is not None and self.advisor_provider_pin is not None:
            raise ValueError("remote Advisor confirmation and local provider pin are mutually exclusive")
        if self.remote_advisor_confirmation is None and self.advisor_provider_pin is None:
            raise ValueError("local Advisor triage requires one exact provider pin")
        return self


class ScanTriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str | None = Field(default=None, max_length=120)
    include_existing: bool = False
    limit: int = Field(default=100, ge=1, le=200)
    advisor_provider_pin: AdvisorTriageProviderPin


class FindingLifecycleUpdate(BaseModel):
    action: Literal["open", "needs_review", "gate_exempt", "accepted_risk", "ignore", "false_positive", "fixed"]
    reason: str | None = Field(default=None, max_length=500)
    expected_revision: int = Field(ge=1)


class FindingListItemOut(BaseModel):
    id: int
    scan_id: int
    scan_finding_number: int
    display_id: str
    scanner: str
    rule_id: str
    severity: str
    file_path: str = Field(max_length=4096)
    start_line: int | None
    start_column: int | None
    end_line: int | None
    end_column: int | None
    message: str = Field(max_length=4000)
    fingerprint: str
    suppressed: bool
    lifecycle_status: str
    gate_exempt: bool
    occurrence_count: int
    is_repeat: bool
    first_seen_scan_id: int | None = None
    first_seen_display_id: str | None = None
    advisor_verdict: str | None = None
    advisor_confidence: float | None = None
    gate_effect: Literal["blocking", "non_blocking", "excluded"]
    revision: int
    created_at: datetime


class FindingPageOut(BaseModel):
    items: list[FindingListItemOut]
    total: int = Field(ge=0)
    truncated: bool
    next_cursor: str | None
    revision: int = Field(ge=1)


class FindingDiagnosticOut(BaseModel):
    id: int = Field(ge=1, le=2_147_483_647)
    scan_finding_number: int = Field(ge=1, le=50_000)
    display_id: str = Field(min_length=1, max_length=64)
    scanner: str = Field(min_length=1, max_length=80)
    severity: Literal["critical", "high", "medium", "low", "info"]
    file_path: str = Field(min_length=1, max_length=4096)
    start_line: int | None = Field(ge=1, le=2_147_483_647)
    start_column: int | None = Field(ge=1, le=2_147_483_647)
    end_line: int | None = Field(ge=1, le=2_147_483_647)
    end_column: int | None = Field(ge=1, le=2_147_483_647)
    message: str = Field(max_length=4000)
    revision: int = Field(ge=1, le=2_147_483_647)

    model_config = ConfigDict(extra="forbid")


class FindingDiagnosticPageOut(BaseModel):
    scan_id: int = Field(ge=1, le=2_147_483_647)
    items: list[FindingDiagnosticOut] = Field(max_length=200)
    total: int = Field(ge=0, le=50_000)
    truncated: bool
    next_cursor: str | None = Field(max_length=512)
    revision: int = Field(ge=1, le=2_147_483_647)

    model_config = ConfigDict(extra="forbid")


class FindingSeverityCountsOut(BaseModel):
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    info: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class FindingLifecycleCountsOut(BaseModel):
    open: int = Field(ge=0)
    needs_review: int = Field(ge=0)
    gate_exempt: int = Field(ge=0)
    accepted_risk: int = Field(ge=0)
    ignore: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    fixed: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class FindingFileAggregateOut(BaseModel):
    file_path: str = Field(min_length=1, max_length=4096)
    first_scan_finding_number: int = Field(ge=1, le=50_000)
    total: int = Field(ge=1)
    active: int = Field(ge=0)
    suppressed: int = Field(ge=0)
    gate_exempt: int = Field(ge=0)
    blocking: int = Field(ge=0)
    severity_counts: FindingSeverityCountsOut
    lifecycle_counts: FindingLifecycleCountsOut

    model_config = ConfigDict(extra="forbid")


class FindingFileManifestScanOut(BaseModel):
    id: int = Field(ge=1)
    project_id: int = Field(ge=1)
    status: str = Field(min_length=1, max_length=40)
    gate_decision: str | None = Field(default=None, max_length=40)
    gate_reasons: list[str]
    error: str | None
    revision: int = Field(ge=1)
    findings_revision: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class FindingFileManifestPageOut(BaseModel):
    scan: FindingFileManifestScanOut
    total_findings: int = Field(ge=0)
    total_files: int = Field(ge=0)
    items: list[FindingFileAggregateOut] = Field(max_length=200)
    truncated: bool
    next_cursor: str | None

    model_config = ConfigDict(extra="forbid")


class ScanSummaryResourceOut(BaseModel):
    id: int
    project_id: int
    mode: str
    status: str
    gate_decision: str | None
    gate_reasons: list[str]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None


class ScanFindingCountsOut(BaseModel):
    total: int = Field(ge=0)
    active: int = Field(ge=0)
    suppressed: int = Field(ge=0)
    gate_exempt: int = Field(ge=0)
    severity_counts: dict[str, int]
    scanner_counts: dict[str, int]


class ScanSummaryOut(BaseModel):
    scan: ScanSummaryResourceOut
    findings: ScanFindingCountsOut
    revision: int = Field(ge=1)
    findings_revision: int = Field(ge=1)


class FindingBulkAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_ids: list[int] = Field(min_length=1, max_length=200)
    action: Literal["triage", "delete", "open", "needs_review", "gate_exempt", "accepted_risk", "ignore", "false_positive", "fixed"]
    reason: str | None = Field(default=None, max_length=500)
    model: str | None = Field(default=None, max_length=120)
    expected_revisions: dict[int, int] | None = Field(default=None, max_length=200)
    advisor_provider_pin: AdvisorTriageProviderPin | None = None

    @field_validator("expected_revisions")
    @classmethod
    def validate_expected_revisions(
        cls, value: dict[int, int] | None
    ) -> dict[int, int] | None:
        if value is None:
            return None
        if any(
            isinstance(finding_id, bool)
            or finding_id < 1
            or isinstance(revision, bool)
            or revision < 1
            for finding_id, revision in value.items()
        ):
            raise ValueError("expected_revisions must map positive finding IDs to positive revisions")
        return value

    @model_validator(mode="after")
    def validate_advisor_provider_pin(self) -> "FindingBulkAction":
        if self.action == "triage" and self.advisor_provider_pin is None:
            raise ValueError("bulk Advisor triage requires one exact provider pin")
        if self.action != "triage" and self.advisor_provider_pin is not None:
            raise ValueError("advisor provider pin is accepted only for bulk triage")
        return self


class RuntimeConfigUpdate(BaseModel):
    ai_mode: Literal["auto", "on", "off"] = "auto"
    ollama_base_url: str = Field(min_length=1, max_length=500)
    ollama_model: str = Field(min_length=1, max_length=120)
    ollama_thinking: bool = False
    auto_triage_limit: int = Field(default=5, ge=0, le=50)
    component_monitoring_enabled: bool = False
    component_git_proxy_enabled: bool = False
    component_db_admin_enabled: bool = False
    gate_preset: Literal["observe", "baseline", "strict", "custom"] = "baseline"
    gate_active: bool = True
    gate_max_critical: int = Field(default=0, ge=-1, le=999)
    gate_max_high: int = Field(default=-1, ge=-1, le=999)
    gate_block_secrets: bool = True
    gate_apply_to_existing: bool = False

    @field_validator("ollama_model")
    @classmethod
    def validate_ollama_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("ollama_model is required")
        return normalized


class RuntimeAdvisorConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_mode: Literal["auto", "on", "off"]
    ollama_base_url: str = Field(min_length=1, max_length=500)
    ollama_model: str = Field(min_length=1, max_length=120)
    ollama_thinking: bool
    auto_triage_limit: int = Field(ge=0, le=50)

    @field_validator("ollama_model")
    @classmethod
    def validate_ollama_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("ollama_model is required")
        return normalized


class AdvisorProviderInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=40, pattern=r"^[a-z][a-z0-9-]{0,39}$")
    name: str = Field(min_length=1, max_length=80)
    transport: Literal["local", "direct", "ssh"]
    priority: int = Field(ge=0, le=7)
    enabled: bool
    base_url: str | None = Field(default=None, max_length=500)
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    ssh_host: str | None = Field(default=None, max_length=253)
    ssh_port: Literal[22] | None = None
    ssh_user: str | None = Field(default=None, max_length=64)


class AdvisorProviderOut(AdvisorProviderInput):
    authorization: Literal["not_required", "required", "authorized"]
    status: Literal[
        "idle", "testing", "available", "unavailable", "active", "disconnected"
    ]
    reason: str | None = Field(default=None, max_length=240)
    reason_code: str | None = Field(
        default=None, max_length=80, pattern=r"^[a-z][a-z0-9_]{0,79}$"
    )
    remediation: Literal["none", "authorize", "test", "activate", "retry", "refresh"]
    last_activity_at: datetime | None = None
    content_disclosure_approved: bool
    config_revision: int = Field(ge=1)
    config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    eligible: bool


class AdvisorProviderResolutionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str | None = Field(default=None, max_length=40)
    transport: Literal["local", "direct", "ssh", "unavailable"]
    reason: str | None = Field(default=None, max_length=240)
    eligible_provider_ids: list[str] = Field(max_length=8)


class AdvisorProviderCollectionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(ge=1)
    active_provider_id: str | None = Field(default=None, max_length=40)
    providers: list[AdvisorProviderOut] = Field(max_length=8)
    resolution: AdvisorProviderResolutionOut


class AdvisorLocalModelOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=120)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=9_007_199_254_740_991)
    storage: Literal["local_weights", "cloud_stub"]

    @field_validator("name")
    @classmethod
    def validate_safe_name(cls, value: str) -> str:
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"}
            for character in value
        ):
            raise ValueError("local model name contains unsafe characters")
        return value

    @model_validator(mode="after")
    def validate_local_weight_size(self) -> "AdvisorLocalModelOut":
        if self.storage == "local_weights" and self.size_bytes == 0:
            raise ValueError("a model with local weights requires a nonzero size")
        return self


class AdvisorLocalCatalogOut(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    schema_version: Literal["lomo-advisor-local-catalog/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    source: Literal["dedicated_local_connector"]
    models: list[AdvisorLocalModelOut] = Field(max_length=200)
    recommended_model: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_catalog_identity(self) -> "AdvisorLocalCatalogOut":
        names = [model.name for model in self.models]
        if len(names) != len(set(names)):
            raise ValueError("local model names must be unique")
        if self.recommended_model is not None and not any(
            model.name == self.recommended_model and model.storage == "local_weights"
            for model in self.models
        ):
            raise ValueError("the recommended model must have local weights")
        return self


class AdvisorProviderReceiptOut(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["lomo-advisor-provider-receipt/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    kind: Literal["local", "direct", "ssh"]
    route: Literal["local", "direct", "ssh"]
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["ready"]
    tested_at: datetime
    revision: int = Field(ge=1)


class AdvisorProviderWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    provider: AdvisorProviderInput


class AdvisorProviderDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)


class AdvisorProviderActivationApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["lomo-advisor-activation-approval/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    provider_config_revision: int = Field(ge=1)
    provider_config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transport: Literal["direct", "ssh"]
    destination: str = Field(min_length=1, max_length=500)
    disclosure_mode: Literal["finding_evidence"]
    payload_categories: list[str] = Field(min_length=5, max_length=5)
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class AdvisorProviderCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    action: Literal["test", "activate", "disconnect"]
    acknowledge_source_disclosure: bool = False
    source_disclosure_approval: AdvisorProviderActivationApproval | None = None


class RuntimeGateConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gate_preset: Literal["observe", "baseline", "strict", "custom"]
    gate_active: bool
    gate_max_critical: int = Field(ge=-1, le=999)
    gate_max_high: int = Field(ge=-1, le=999)
    gate_block_secrets: bool
    gate_apply_to_existing: bool


class RuntimeComponentsConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component_monitoring_enabled: bool
    component_git_proxy_enabled: bool
    component_db_admin_enabled: bool


class RuntimeComponentOut(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    required: bool
    desired_enabled: bool
    desired_state: Literal["enabled", "disabled"]
    observed_state: Literal[
        "running",
        "running_undesired",
        "not_running",
        "not_observed",
        "disabled",
        "unhealthy",
        "unknown",
    ]
    reachable: bool
    healthy: bool
    url: str = Field(min_length=1, max_length=500)
    profile: str = Field(min_length=1, max_length=80)
    apply_command: str = Field(min_length=1, max_length=160)
    reason_code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=240)


class SchemaInitStatusOut(BaseModel):
    id: Literal["schema-init"]
    lifecycle: Literal["one-shot"]
    startable: Literal[False]
    state: Literal["completed", "unverified"]
    message: str = Field(min_length=1, max_length=240)
    schema_id: str | None = Field(default=None, max_length=120)
    schema_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    initialized_at: datetime | None
    evidence: Literal["schema-identity-and-api-startup-verification"] | None


class RuntimeConfigOut(BaseModel):
    installation_id: str = Field(pattern=r"^[a-f0-9]{12}$")
    allowed_roots: list[str]
    scanner_url: str
    ai_mode: Literal["auto", "on", "off"]
    ollama_base_url: str
    ollama_available: bool
    ollama_model: str
    ollama_thinking: bool
    ollama_models: list[str]
    ollama_reason: str | None
    auto_triage_limit: int
    component_monitoring_enabled: bool
    component_git_proxy_enabled: bool
    component_db_admin_enabled: bool
    gate_preset: Literal["observe", "baseline", "strict", "custom"]
    gate_active: bool
    gate_max_critical: int
    gate_max_high: int
    gate_block_secrets: bool
    component_apply_command: str
    components: list[RuntimeComponentOut]
    schema_init: SchemaInitStatusOut


class ScannerToolPatch(BaseModel):
    enabled: bool | None = None
    pinned_version: str | None = Field(default=None, max_length=80)


ScannerCacheComponentId = Literal[
    "trivy-db",
    "trivy-java-db",
    "trivy-checks",
    "opengrep-reviewed-rules",
    "bearer-rules",
    "grype-db",
]

ScannerCatalogToolState = Literal[
    "current",
    "candidate_available",
    "unavailable",
    "unattested",
]
ScannerCatalogComponentState = Literal[
    "current",
    "candidate_available",
    "requires_lock_refresh",
    "unavailable",
    "unattested",
]
ScannerSourceIntrinsicCacheComponentId = Literal[
    "trivy-db",
    "trivy-java-db",
    "grype-db",
]
SCANNER_CATALOG_TOOL_STATES: frozenset[str] = frozenset(
    get_args(ScannerCatalogToolState)
)
SCANNER_CATALOG_COMPONENT_STATES: frozenset[str] = frozenset(
    get_args(ScannerCatalogComponentState)
)
SCANNER_SOURCE_INTRINSIC_CACHE_COMPONENT_IDS: frozenset[str] = frozenset(
    get_args(ScannerSourceIntrinsicCacheComponentId)
)


ScannerReadinessState = Literal[
    "ready",
    "not_required",
    "unattested",
    "unavailable",
    "stale",
    "invalid",
    "verifying",
    "verification_timeout",
    "verification_failed",
]


class ScannerCacheVerificationOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["verifying", "timed_out", "failed"]
    target: Literal["active", "previous_good"]
    generation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    phase: Literal["queued", "validating", "hashing"]
    component_id: ScannerCacheComponentId | None
    started_at: str = Field(max_length=32)
    last_activity_at: str = Field(max_length=32)
    bytes_verified: int | None = Field(ge=0, le=8 * 1024**3)
    bytes_total: int | None = Field(ge=0, le=8 * 1024**3)

    @field_validator("started_at", "last_activity_at")
    @classmethod
    def validate_utc_timestamp(cls, value: str) -> str:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
            raise ValueError("verification timestamps must be UTC ISO timestamps")
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError("verification timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def validate_activity(self) -> "ScannerCacheVerificationOut":
        if datetime.fromisoformat(self.last_activity_at) < datetime.fromisoformat(self.started_at):
            raise ValueError("verification activity precedes its start")
        if (self.bytes_verified is None) != (self.bytes_total is None):
            raise ValueError("verification byte counts must be a pair")
        if (self.bytes_verified is not None and self.bytes_total is not None
                and self.bytes_verified > self.bytes_total):
            raise ValueError("verified bytes exceed the total")
        return self


class ScannerCacheVerificationRetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: Literal["active", "previous_good"]
    expected_generation: str = Field(pattern=r"^[0-9a-f]{64}$")


class ScannerReadinessFacetOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    state: ScannerReadinessState
    reason: str | None = Field(default=None, max_length=512)
    component_ids: list[ScannerCacheComponentId] = Field(max_length=6)

    @field_validator("component_ids")
    @classmethod
    def validate_component_ids(
        cls, value: list[ScannerCacheComponentId]
    ) -> list[ScannerCacheComponentId]:
        if len(value) != len(set(value)):
            raise ValueError("component_ids must not contain duplicates")
        return value


class ScannerToolReadinessOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    binary: ScannerReadinessFacetOut
    data: ScannerReadinessFacetOut
    rules: ScannerReadinessFacetOut
    execution: ScannerReadinessFacetOut


class ScannerCacheUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component_ids: list[ScannerCacheComponentId] = Field(min_length=1, max_length=6)
    catalog_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("component_ids")
    @classmethod
    def validate_component_ids(
        cls, value: list[ScannerCacheComponentId]
    ) -> list[ScannerCacheComponentId]:
        if len(value) != len(set(value)):
            raise ValueError("component_ids must not contain duplicates")
        return sorted(value)


class ScannerPreparationContinuation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1, 2]
    preparation_budget: PreparationBudget | None = None
    component_ids: list[ScannerCacheComponentId] = Field(min_length=1, max_length=6)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_budget_version(self) -> "ScannerPreparationContinuation":
        if (self.schema_version == 2) != (self.preparation_budget is not None):
            raise ValueError("preparation continuation budget version mismatch")
        return self

    @field_validator("component_ids")
    @classmethod
    def validate_component_ids(
        cls, value: list[ScannerCacheComponentId]
    ) -> list[ScannerCacheComponentId]:
        if value != sorted(set(value)):
            raise ValueError("component_ids must be sorted and unique")
        return value


class ScannerLifecycleScopeOut(BaseModel):
    scope: Literal["catalog", "cache"]
    status: Literal[
        "idle",
        "queued",
        "leased",
        "running",
        "cancelling",
        "completed",
        "failed",
        "cancelled",
    ]
    revision: int
    job_id: int | None
    job_url: str | None
    active_generation: str | None
    previous_generation: str | None
    receipt: dict[str, Any]
    error_code: str | None
    error_detail: str | None
    started_at: datetime | None
    completed_at: datetime | None
    updated_at: datetime


class ScannerLifecycleOut(BaseModel):
    catalog: ScannerLifecycleScopeOut
    cache: ScannerLifecycleScopeOut


class ScannerLifecycleCommandOut(BaseModel):
    job: JobOut
    lifecycle: ScannerLifecycleScopeOut


class ScannerReconciliationCommandOut(ScannerLifecycleCommandOut):
    original_job_id: int


class ScannerPreparationCommandOut(BaseModel):
    catalog: ScannerLifecycleCommandOut
    cache: ScannerLifecycleCommandOut | None
    required_component_ids: list[ScannerCacheComponentId]


class ScannerToolOut(BaseModel):
    id: str
    name: str
    category: str
    lifecycle: str
    source: str
    output_format: str
    description: str
    enabled: bool
    current_version: str
    latest_version: str
    installed_version: str | None = None
    available: bool = False
    pinned_version: str | None
    status: str
    update_available: bool
    findings_count: int
    artifacts_count: int = 0
    candidate_release_id: str | None = None
    candidate_manifest_sha256: str | None = None
    published_at: str | None = None
    last_error: str | None = None
    last_checked_at: datetime | None
    updated_at: datetime | None
    readiness: ScannerToolReadinessOut | None = None
    runtime_ready: bool | None = None


class ScannerPreflightBlockedToolOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    blocking_reasons: list[str] = Field(min_length=1, max_length=4)
    required_component_ids: list[ScannerCacheComponentId] = Field(max_length=6)
    preparation_blocking_reasons: list[str] = Field(max_length=4)


ScannerCacheRollbackEligibilityCode = Literal[
    "eligible",
    "no_previous_generation",
    "cache_pointer_invalid",
    "previous_generation_invalid",
    "previous_generation_verifying",
    "previous_generation_verification_timeout",
    "previous_generation_verification_failed",
    "different_reviewed_locks",
    "previous_generation_incompatible",
    "scanner_unavailable",
    "scanner_eligibility_invalid",
    "state_mismatch",
]


class ScannerCacheRollbackEligibilityOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    eligible: bool
    reason_code: ScannerCacheRollbackEligibilityCode
    reason: str = Field(min_length=1, max_length=256)
    target_generation: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    verification: ScannerCacheVerificationOut | None = None

    @model_validator(mode="after")
    def validate_eligibility(self) -> "ScannerCacheRollbackEligibilityOut":
        if self.eligible != (self.reason_code == "eligible"):
            raise ValueError("rollback eligibility and reason code disagree")
        if self.eligible and self.target_generation is None:
            raise ValueError("eligible rollback requires an exact target generation")
        verification_states = {
            "previous_generation_verifying": "verifying",
            "previous_generation_verification_timeout": "timed_out",
            "previous_generation_verification_failed": "failed",
        }
        expected_state = verification_states.get(self.reason_code)
        if expected_state is not None:
            if (self.verification is None or self.verification.target != "previous_good"
                    or self.verification.generation_id != self.target_generation
                    or self.verification.state != expected_state):
                raise ValueError("rollback verification differs from its exact target and state")
        elif self.verification is not None:
            raise ValueError("rollback verification requires its matching reason code")
        return self


class ScannerPreflightOut(BaseModel):
    """One safe readiness snapshot shared by UI, IDE, CLI, and future CI."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    revision: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    ready: bool
    enabled_tool_ids: list[str] = Field(max_length=32)
    ready_tool_ids: list[str] = Field(max_length=32)
    blocked_tools: list[ScannerPreflightBlockedToolOut] = Field(max_length=32)
    required_component_ids: list[ScannerCacheComponentId] = Field(max_length=6)
    preparation_available: bool
    active_generation: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    catalog_revision: int | None = Field(default=None, ge=1)
    cache_revision: int | None = Field(default=None, ge=1)
    cache_rollback: ScannerCacheRollbackEligibilityOut
    cache_verification: ScannerCacheVerificationOut | None = None
    recommended_action: Literal[
        "scan",
        "prepare_scanners",
        "enable_scanner",
        "repair_scanner_runtime",
        "wait_for_scanner_verification",
        "retry_scanner_verification",
    ]

    @model_validator(mode="after")
    def validate_verification_admission(self) -> "ScannerPreflightOut":
        if self.cache_verification is not None:
            action = ("wait_for_scanner_verification" if self.cache_verification.state == "verifying"
                else "retry_scanner_verification")
            if (self.cache_verification.target != "active" or self.ready or self.preparation_available
                    or self.recommended_action != action):
                raise ValueError("active cache verification cannot admit scanning or preparation")
        elif self.recommended_action in {"wait_for_scanner_verification", "retry_scanner_verification"}:
            raise ValueError("verification guidance requires an exact verification target")
        return self
