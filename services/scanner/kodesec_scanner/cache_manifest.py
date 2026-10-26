"""Strict, fail-closed scanner locks and offline-cache generation manifests.

This module deliberately contains no downloader and accepts no caller-provided
URLs.  It is shared by the source-blind updater and the scanner readiness
surface so binary integrity, offline data, and rule provenance cannot collapse
into one misleading ``ready`` flag.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Callable, Generic, Iterable, Literal, Mapping, TypeVar, get_args

if TYPE_CHECKING:
    from .grype_identity import GrypeFileObservation, GrypeValidationTiming

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


SCHEMA_VERSION = 1
CANONICAL_TREE_HASH_ALGORITHM = "kodesec-canonical-tree-v1"
GRYPE_LOGICAL_TREE_HASH_ALGORITHM = "kodesec-grype-v6-logical-tree-v1"
GRYPE_DATABASE_PATH = "6/vulnerability.db"
GRYPE_IMPORT_METADATA_PATH = "6/import.json"
GRYPE_IDENTITY_TIMEOUT_SECONDS = 900
MAX_LOCK_BYTES = 1024 * 1024
MAX_ACTIVE_POINTER_BYTES = 64 * 1024
MAX_GENERATION_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_GENERATION_FILES = 20_000
MAX_GENERATION_DEPTH = 16
MAX_GENERATION_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_GENERATION_BYTES = 8 * 1024 * 1024 * 1024
GENERATION_HASH_CHECKPOINT_BYTES = 16 * 1024 * 1024
GENERATION_WALK_CHECKPOINT_ENTRIES = 64
MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS = 5 * 60
REVIEWED_DATA_REFRESH_WARNING_SECONDS = 7 * 24 * 60 * 60
REVIEWED_DATA_HARD_VALIDITY_SECONDS = 14 * 24 * 60 * 60
MAX_PUBLISHER_REFRESH_INTERVAL_SECONDS = 7 * 24 * 60 * 60

EXTERNAL_TOOL_IDS = frozenset(
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
RULE_SET_IDS = frozenset({"opengrep-reviewed-rules", "bearer-rules"})
CACHE_COMPONENT_IDS = (
    "bearer-rules", "grype-db", "opengrep-reviewed-rules",
    "trivy-checks", "trivy-db", "trivy-java-db",
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\Z")
_VERSION = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

ProvenanceState = Literal["verified", "unattested", "unavailable"]
RequirementKind = Literal["database", "checks", "rules"]
ReadinessState = Literal[
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


class LockValidationError(ValueError):
    """A scanner lock is malformed, ambiguous, or not safely readable."""


class CacheValidationError(ValueError):
    """A cache pointer or generation cannot be trusted."""


GrypeContentErrorCode = Literal[
    "files", "import_metadata", "import_checksum", "file", "changed", "size",
    "deadline", "cancelled", "schema", "integrity", "data", "database",
]


class GrypeContentValidationError(CacheValidationError):
    """A source-blind Grype failure with an explicit retry policy."""

    def __init__(self, code: GrypeContentErrorCode, *, validation_timing: GrypeValidationTiming | None = None) -> None:
        if code not in get_args(GrypeContentErrorCode):
            raise ValueError("unsupported Grype validation reason")
        self.code = code
        self.retryable = code == "deadline"
        self.validation_timing = validation_timing
        super().__init__(f"Grype cache validation failed: {code}")


class CacheActivationError(RuntimeError):
    """A validated cache generation could not be activated atomically."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _require_identifier(value: str, label: str = "identifier") -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} is not a bounded lowercase identifier")
    return value


def _require_bounded_text(value: str, label: str, maximum: int = 2048) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise ValueError(
            f"{label} is empty, padded, too long, or contains control characters"
        )
    return value


def _require_https(value: str, label: str) -> str:
    _require_bounded_text(value, label)
    if not value.startswith("https://") or "@" in value.split("/", 3)[2]:
        raise ValueError(f"{label} must be an HTTPS reference without userinfo")
    return value


def _require_repo_reference(value: str, label: str) -> str:
    _require_bounded_text(value, label)
    if not value.startswith("repo:"):
        raise ValueError(f"{label} must be a repository-relative reference")
    _require_relative_path(value.removeprefix("repo:"), label)
    return value


def _require_relative_path(value: str, label: str = "path") -> str:
    if (
        not value
        or len(value) > 1024
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "//" in value
        or _CONTROL.search(value)
    ):
        raise ValueError(f"{label} must be one bounded relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{label} contains an unsafe path segment")
    return value


def _parse_utc(value: str, label: str) -> datetime:
    if not _RFC3339_UTC.fullmatch(value):
        raise ValueError(f"{label} must be an RFC3339 UTC timestamp")
    # OCI/Trivy metadata uses RFC3339Nano while Python datetimes retain
    # microsecond precision. Keep the lossless timestamp in the signed receipt,
    # but normalize only the comparison value to Python's supported precision.
    normalized = value
    if "." in value:
        whole, fraction = value[:-1].split(".", 1)
        normalized = f"{whole}.{fraction[:6].ljust(6, '0')}Z"
    try:
        return datetime.fromisoformat(normalized.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not a real timestamp") from exc


def utc_timestamp(value: datetime | None = None) -> str:
    moment = (value or datetime.now(UTC)).astimezone(UTC)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value cannot be encoded as canonical JSON") from exc
    return (rendered + "\n").encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _read_bounded_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise CacheValidationError(f"{label} must be a regular non-symlink file")
        if before_path.st_size <= 0 or before_path.st_size > maximum:
            raise CacheValidationError(f"{label} is empty or exceeds its size limit")
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except CacheValidationError:
        raise
    except FileNotFoundError as exc:
        raise CacheValidationError(f"{label} is missing") from exc
    except OSError as exc:
        raise CacheValidationError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != before_path.st_size:
            raise CacheValidationError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise CacheValidationError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != after.st_size:
            raise CacheValidationError(f"{label} changed while it was being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_without_duplicate_keys,
            parse_constant=_reject_non_json_number,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise LockValidationError(
            f"{label} is not strict, unambiguous UTF-8 JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise LockValidationError(f"{label} must contain one JSON object")
    return parsed


class LicenseLock(_StrictModel):
    state: ProvenanceState
    spdx: str | None = Field(default=None, max_length=128)
    source_ref: str | None = Field(default=None, max_length=2048)
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def validate_evidence(self) -> "LicenseLock":
        if self.state == "verified":
            if not self.spdx or not self.source_ref or not self.source_sha256:
                raise ValueError(
                    "verified license locks require SPDX, source, and digest evidence"
                )
            if self.source_ref.startswith("repo:"):
                _require_repo_reference(self.source_ref, "license source_ref")
            else:
                _require_https(self.source_ref, "license source_ref")
        elif not self.reason:
            raise ValueError("unattested or unavailable license locks require a reason")
        return self


class BinaryArtifactLock(_StrictModel):
    platform: Literal["linux/amd64", "linux/arm64", "any"]
    kind: Literal["tar.gz", "executable", "wheel"]
    url: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _require_https(value, "binary artifact URL")


class BinarySourceBuildLock(_StrictModel):
    """Reviewed source inputs; the native build records its actual output hash."""

    kind: Literal["bearer-source-build"]
    recipe_ref: Literal["repo:services/scanner/bearer/source.lock.json"]
    recipe_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_version: str = Field(min_length=1, max_length=64)
    platforms: list[Literal["linux/amd64", "linux/arm64"]] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_recipe(self) -> "BinarySourceBuildLock":
        if not _VERSION.fullmatch(self.output_version) or "+lomo." not in self.output_version:
            raise ValueError("modified Bearer requires an exact distinct Lomo version")
        if self.platforms != ["linux/amd64", "linux/arm64"]:
            raise ValueError("source builds require both native Linux architectures")
        return self


class BinaryLock(_StrictModel):
    provenance: ProvenanceState
    source_repository: str = Field(min_length=1, max_length=2048)
    version_command: list[str] = Field(min_length=1, max_length=8)
    artifacts: list[BinaryArtifactLock] = Field(max_length=4)
    source_build: BinarySourceBuildLock | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    license: LicenseLock
    reason: str | None = Field(default=None, max_length=512)

    @field_validator("source_repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        return _require_https(value, "binary source_repository")

    @field_validator("version_command")
    @classmethod
    def validate_version_command(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_bounded_text(item, "version command token", 256)
        return value

    @model_validator(mode="after")
    def validate_artifacts(self) -> "BinaryLock":
        if self.source_build is not None and self.artifacts:
            raise ValueError("source builds and prebuilt artifacts are mutually exclusive")
        platforms = [artifact.platform for artifact in self.artifacts]
        if len(platforms) != len(set(platforms)):
            raise ValueError("binary artifact platforms must be unique")
        if self.provenance == "verified" and not self.artifacts and self.source_build is None:
            raise ValueError("verified binary locks require immutable artifacts")
        if self.provenance == "verified" and self.source_build is None and set(platforms) not in (
            {"any"},
            {"linux/amd64", "linux/arm64"},
        ):
            raise ValueError(
                "verified binaries require one portable artifact or both Linux architectures"
            )
        if self.provenance != "verified" and not self.reason:
            raise ValueError("unattested or unavailable binary locks require a reason")
        return self


class AdapterLock(_StrictModel):
    output_format: Literal["sarif", "jsonv2", "jsonl", "cyclonedx-json"]
    offline_contract: ProvenanceState
    arguments: list[str] = Field(min_length=1, max_length=64)
    supplemental_arguments: list[list[str]] = Field(default_factory=list, max_length=8)
    environment: dict[str, str] = Field(max_length=32)
    reason: str | None = Field(default=None, max_length=512)

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_bounded_text(item, "adapter argument", 1024)
        return value

    @field_validator("supplemental_arguments")
    @classmethod
    def validate_supplemental_arguments(
        cls, value: list[list[str]]
    ) -> list[list[str]]:
        for command in value:
            if not command or len(command) > 64:
                raise ValueError("supplemental adapter commands must be bounded")
            for item in command:
                _require_bounded_text(item, "supplemental adapter argument", 1024)
        return value

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key):
                raise ValueError("adapter environment key is not allowlist-shaped")
            _require_bounded_text(item, "adapter environment value", 1024)
        return value

    @model_validator(mode="after")
    def validate_contract_evidence(self) -> "AdapterLock":
        if self.offline_contract != "verified" and not self.reason:
            raise ValueError("unverified offline contracts require a reason")
        return self


class ComponentSourceLock(_StrictModel):
    kind: Literal["oci", "https", "git", "embedded", "rules-lock"]
    discovery_ref: str = Field(min_length=1, max_length=2048)
    immutable_ref: str | None = Field(default=None, max_length=2048)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: int | None = Field(
        default=None, gt=0, le=MAX_GENERATION_FILE_BYTES
    )

    @field_validator("discovery_ref", "immutable_ref")
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is not None:
            _require_bounded_text(value, "component source reference")
        return value

    @model_validator(mode="after")
    def validate_source_kind(self) -> "ComponentSourceLock":
        if self.kind == "embedded":
            prefix = "/usr/local/share/kodesec/rules/"
            if (
                not self.discovery_ref.startswith(prefix)
                or ".." in Path(self.discovery_ref).parts
                or not self.immutable_ref
                or not self.sha256
            ):
                raise ValueError(
                    "embedded components require an immutable baked rule path"
                )
        return self


class ComponentCanaryLock(_StrictModel):
    id: str
    fixture_path: str
    fixture_kind: Literal["file", "tree"]
    fixture_hash_algorithm: Literal["sha256-file-v1", "kodesec-canonical-tree-v1"]
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_exit_code: int = Field(ge=0, le=255)
    expected_result_count: int = Field(ge=0, le=10_000)
    expected_ids: list[str] = Field(max_length=512)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _require_identifier(value, "component canary id")

    @field_validator("fixture_path")
    @classmethod
    def validate_fixture_path(cls, value: str) -> str:
        return _require_relative_path(value, "component canary fixture_path")

    @field_validator("expected_ids")
    @classmethod
    def validate_expected_ids(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("component canary expected ids must be sorted and unique")
        for item in value:
            _require_bounded_text(item, "component canary expected id", 256)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> "ComponentCanaryLock":
        if (self.fixture_kind == "file") != (
            self.fixture_hash_algorithm == "sha256-file-v1"
        ):
            raise ValueError("component canary fixture kind and hash algorithm disagree")
        if self.expected_result_count < len(self.expected_ids):
            raise ValueError(
                "component canary count cannot be smaller than its unique id set"
            )
        return self


class InstalledContentLock(_StrictModel):
    """Exact immutable payload identity below one cache component root.

    Some tools generate a small local metadata file containing download time.
    Those paths are explicitly allowlisted and semantically validated by the
    updater; every other file remains bound to this canonical tree identity.
    """

    hash_algorithm: Literal[
        "kodesec-canonical-tree-v1", "kodesec-grype-v6-logical-tree-v1"
    ]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_count: int = Field(gt=0, le=MAX_GENERATION_FILES)
    size_bytes: int = Field(gt=0, le=MAX_GENERATION_BYTES)
    volatile_paths: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("volatile_paths")
    @classmethod
    def validate_volatile_paths(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("installed content volatile paths must be sorted and unique")
        return [
            _require_relative_path(item, "installed content volatile path")
            for item in value
        ]


class TrivyDatabaseDataContract(_StrictModel):
    """Intrinsic metadata contract for the Trivy operating-system database."""

    kind: Literal["trivy-db-metadata/v2"]
    schema_version: Literal[2]
    timestamp_kind: Literal["intrinsic"]
    publisher_updated_at: str
    publisher_refresh_due_at: str

    @field_validator("publisher_updated_at", "publisher_refresh_due_at")
    @classmethod
    def validate_publisher_timestamp(cls, value: str) -> str:
        _parse_utc(value, "Trivy publisher timestamp")
        return value

    @model_validator(mode="after")
    def validate_publisher_window(self) -> "TrivyDatabaseDataContract":
        updated = _parse_utc(self.publisher_updated_at, "Trivy publisher updated_at")
        refresh_due = _parse_utc(
            self.publisher_refresh_due_at,
            "Trivy publisher refresh_due_at",
        )
        if not updated < refresh_due <= updated + timedelta(
            seconds=MAX_PUBLISHER_REFRESH_INTERVAL_SECONDS
        ):
            raise ValueError("Trivy publisher refresh interval is invalid")
        return self


class TrivyJavaDatabaseDataContract(_StrictModel):
    """Intrinsic metadata contract for the Trivy Java vulnerability database."""

    kind: Literal["trivy-java-db-metadata/v2"]
    schema_version: Literal[1]
    timestamp_kind: Literal["intrinsic"]
    publisher_updated_at: str
    publisher_refresh_due_at: str

    @field_validator("publisher_updated_at", "publisher_refresh_due_at")
    @classmethod
    def validate_publisher_timestamp(cls, value: str) -> str:
        _parse_utc(value, "Trivy Java publisher timestamp")
        return value

    @model_validator(mode="after")
    def validate_publisher_window(self) -> "TrivyJavaDatabaseDataContract":
        updated = _parse_utc(
            self.publisher_updated_at,
            "Trivy Java publisher updated_at",
        )
        refresh_due = _parse_utc(
            self.publisher_refresh_due_at,
            "Trivy Java publisher refresh_due_at",
        )
        if not updated < refresh_due <= updated + timedelta(
            seconds=MAX_PUBLISHER_REFRESH_INTERVAL_SECONDS
        ):
            raise ValueError("Trivy Java publisher refresh interval is invalid")
        return self


class TrivyChecksDataContract(_StrictModel):
    """Acquisition-relative metadata contract for the Trivy checks bundle."""

    kind: Literal["trivy-checks-metadata/v1"]
    major_version: Literal[2]
    timestamp_kind: Literal["acquisition-relative"]


class GrypeDatabaseDataContract(_StrictModel):
    """Exact intrinsic identity reported by ``grype db status``."""

    kind: Literal["grype-db-status/v1"]
    schema_version: str = Field(pattern=r"^v\d+\.\d+\.\d+$", max_length=32)
    built_at: str
    timestamp_kind: Literal["intrinsic"]

    @field_validator("built_at")
    @classmethod
    def validate_built_at(cls, value: str) -> str:
        _parse_utc(value, "Grype database built_at")
        return value


ComponentDataContract = Annotated[
    TrivyDatabaseDataContract
    | TrivyJavaDatabaseDataContract
    | TrivyChecksDataContract
    | GrypeDatabaseDataContract,
    Field(discriminator="kind"),
]


@dataclass(frozen=True)
class _DataComponentStructuralProfile:
    owner_tool_id: str
    requirement_kind: Literal["database", "checks"]
    required: bool
    cache_subpath: str
    source_kind: Literal["oci", "https"]
    discovery_ref: str
    contract_type: type[_StrictModel]
    timestamp_kind: Literal["intrinsic", "acquisition-relative"]


_DATA_COMPONENT_STRUCTURAL_PROFILES: Mapping[
    str, _DataComponentStructuralProfile
] = {
    "trivy-db": _DataComponentStructuralProfile(
        owner_tool_id="trivy",
        requirement_kind="database",
        required=True,
        cache_subpath="trivy/db",
        source_kind="oci",
        discovery_ref="ghcr.io/aquasecurity/trivy-db:2",
        contract_type=TrivyDatabaseDataContract,
        timestamp_kind="intrinsic",
    ),
    "trivy-java-db": _DataComponentStructuralProfile(
        owner_tool_id="trivy",
        requirement_kind="database",
        required=True,
        cache_subpath="trivy/java-db",
        source_kind="oci",
        discovery_ref="ghcr.io/aquasecurity/trivy-java-db:1",
        contract_type=TrivyJavaDatabaseDataContract,
        timestamp_kind="intrinsic",
    ),
    "trivy-checks": _DataComponentStructuralProfile(
        owner_tool_id="trivy",
        requirement_kind="checks",
        required=True,
        cache_subpath="trivy/policy",
        source_kind="oci",
        discovery_ref="ghcr.io/aquasecurity/trivy-checks:1",
        contract_type=TrivyChecksDataContract,
        timestamp_kind="acquisition-relative",
    ),
    "grype-db": _DataComponentStructuralProfile(
        owner_tool_id="grype",
        requirement_kind="database",
        required=True,
        cache_subpath="grype",
        source_kind="https",
        discovery_ref="https://grype.anchore.io/databases/v6/latest.json",
        contract_type=GrypeDatabaseDataContract,
        timestamp_kind="intrinsic",
    ),
}


class ComponentRequirementLock(_StrictModel):
    id: str
    kind: RequirementKind
    required: bool
    provenance: ProvenanceState
    cache_subpath: str | None = None
    source: ComponentSourceLock
    installed_size_bytes: int | None = Field(
        default=None, gt=0, le=MAX_GENERATION_BYTES
    )
    installed_content: InstalledContentLock | None = None
    data_contract: ComponentDataContract | None = None
    max_age_seconds: int | None = Field(
        default=None, ge=60, le=31 * 24 * 60 * 60
    )
    canaries: list[ComponentCanaryLock] = Field(default_factory=list, max_length=32)
    reason: str | None = Field(default=None, max_length=512)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _require_identifier(value, "component id")

    @field_validator("cache_subpath")
    @classmethod
    def validate_cache_path(cls, value: str | None) -> str | None:
        return (
            _require_relative_path(value, "cache_subpath")
            if value is not None
            else None
        )

    @model_validator(mode="after")
    def validate_provenance(self) -> "ComponentRequirementLock":
        if (
            self.installed_content is not None
            and self.installed_content.hash_algorithm == GRYPE_LOGICAL_TREE_HASH_ALGORITHM
            and (
                self.id != "grype-db"
                or self.kind != "database"
                or self.cache_subpath != "grype"
                or not isinstance(self.data_contract, GrypeDatabaseDataContract)
                or not self.data_contract.schema_version.startswith("v6.")
                or self.installed_content.volatile_paths
                or self.installed_content.file_count != 2
            )
        ):
            raise ValueError("logical installed content requires the exact Grype v6 profile")
        canary_ids = [item.id for item in self.canaries]
        if canary_ids != sorted(set(canary_ids)):
            raise ValueError("component canaries must be sorted and unique")
        if self.provenance == "verified":
            if (
                not self.cache_subpath
                or not self.source.immutable_ref
                or not self.source.sha256
                or (self.kind != "rules" and not self.source.size_bytes)
            ):
                raise ValueError(
                    "verified cache requirements need a cache path, immutable source "
                    "identity, size, and SHA-256"
                )
            if self.kind in {"database", "checks"} and (
                self.max_age_seconds is None
                or self.max_age_seconds <= MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS
                or self.installed_size_bytes is None
                or self.installed_content is None
                or self.data_contract is None
                or not self.canaries
            ):
                raise ValueError(
                    "verified data/check requirements need a typed data contract, usable "
                    "freshness window, immutable installed content, and semantic canaries"
                )
            if self.kind == "rules" and (
                self.max_age_seconds is not None
                or self.installed_content is not None
                or self.data_contract is not None
                or self.canaries
            ):
                raise ValueError(
                    "rules freshness and canaries are governed by the reviewed rules lock"
                )
        elif not self.reason:
            raise ValueError(
                "unattested or unavailable cache requirements require a reason"
            )
        elif (
            self.max_age_seconds is not None
            or self.installed_size_bytes is not None
            or self.installed_content is not None
            or self.data_contract is not None
            or self.canaries
        ):
            raise ValueError("unverified cache requirements cannot carry qualified evidence")
        if (
            self.id not in _DATA_COMPONENT_STRUCTURAL_PROFILES
            and self.data_contract is not None
        ):
            raise ValueError("component has no admitted typed data contract")
        return self


class ToolLockEntry(_StrictModel):
    id: str
    version: str = Field(min_length=1, max_length=64)
    binary: BinaryLock
    adapter: AdapterLock
    requirements: list[ComponentRequirementLock] = Field(max_length=16)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _require_identifier(value, "tool id")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("tool version must be exact")
        return value

    @model_validator(mode="after")
    def validate_requirements(self) -> "ToolLockEntry":
        source_build = self.binary.source_build
        if source_build is not None and (
            self.id != "bearer" or self.version != source_build.output_version
            or self.binary.source_repository != "https://github.com/Bearer/bearer"
        ):
            raise ValueError("source build must match its exact Bearer tool identity")
        identifiers = [item.id for item in self.requirements]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("tool requirement ids must be unique")
        return self


class ToolLockFile(_StrictModel):
    schema_version: Literal[2]
    toolset_id: str
    tools: list[ToolLockEntry] = Field(min_length=8, max_length=8)

    @field_validator("toolset_id")
    @classmethod
    def validate_toolset_id(cls, value: str) -> str:
        return _require_identifier(value, "toolset id")

    @model_validator(mode="after")
    def validate_complete_toolset(self) -> "ToolLockFile":
        identifiers = [tool.id for tool in self.tools]
        if (
            len(identifiers) != len(set(identifiers))
            or set(identifiers) != EXTERNAL_TOOL_IDS
        ):
            raise ValueError(
                "tool lock must contain each curated external tool exactly once"
            )
        requirement_ids = [
            requirement.id for tool in self.tools for requirement in tool.requirements
        ]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("cache component ids must be globally unique")
        requirements = {
            requirement.id: (tool.id, requirement)
            for tool in self.tools
            for requirement in tool.requirements
        }
        for component_id, profile in _DATA_COMPONENT_STRUCTURAL_PROFILES.items():
            observed = requirements.get(component_id)
            if observed is None:
                raise ValueError("tool lock lacks an exact data component profile")
            owner_tool_id, requirement = observed
            if (
                owner_tool_id != profile.owner_tool_id
                or requirement.kind != profile.requirement_kind
                or requirement.required is not profile.required
                or requirement.cache_subpath != profile.cache_subpath
                or requirement.source.kind != profile.source_kind
                or requirement.source.discovery_ref != profile.discovery_ref
            ):
                raise ValueError(
                    "data component structure differs from its exact profile"
                )
            contract = requirement.data_contract
            if requirement.provenance == "verified" and (
                type(contract) is not profile.contract_type
                or contract.timestamp_kind != profile.timestamp_kind
                or requirement.max_age_seconds
                != REVIEWED_DATA_HARD_VALIDITY_SECONDS
            ):
                raise ValueError(
                    "verified data component contract differs from its exact profile"
                )
        return self

    def tool(self, tool_id: str) -> ToolLockEntry:
        for tool in self.tools:
            if tool.id == tool_id:
                return tool
        raise KeyError(tool_id)


class RuleFileLock(_StrictModel):
    path: str
    kind: Literal["rule", "license", "notice"]
    size_bytes: int = Field(gt=0, le=MAX_GENERATION_FILE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_ids: list[str] = Field(max_length=512)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _require_relative_path(value, "rule path")

    @field_validator("rule_ids")
    @classmethod
    def validate_rule_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("rule ids must be unique")
        for item in value:
            _require_bounded_text(item, "rule id", 256)
        return value

    @model_validator(mode="after")
    def validate_file_role(self) -> "RuleFileLock":
        if self.kind == "rule" and not self.rule_ids:
            raise ValueError("rule files require at least one exact rule id")
        if self.kind != "rule" and self.rule_ids:
            raise ValueError("license and notice files cannot claim scanner rule ids")
        return self


class RuleAssetLock(_StrictModel):
    name: str
    url: str = Field(min_length=1, max_length=2048)
    size_bytes: int = Field(gt=0, le=MAX_GENERATION_FILE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _require_relative_path(value, "rule asset name")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _require_https(value, "rule asset URL")


class RuleCanaryLock(_StrictModel):
    id: str
    state: ProvenanceState
    fixture_path: str
    fixture_kind: Literal["file", "tree"]
    fixture_hash_algorithm: Literal["sha256-file-v1", "kodesec-canonical-tree-v1"]
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    expected_exit_code: int = Field(ge=0, le=255)
    expected_result_count: int = Field(ge=0, le=10_000)
    expected_rule_ids: list[str] = Field(max_length=128)
    reason: str | None = Field(default=None, max_length=512)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _require_identifier(value, "rule canary id")

    @field_validator("fixture_path")
    @classmethod
    def validate_fixture_path(cls, value: str) -> str:
        return _require_relative_path(value, "rule canary fixture_path")

    @field_validator("expected_rule_ids")
    @classmethod
    def validate_expected_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("expected canary rule ids must be unique")
        for item in value:
            _require_bounded_text(item, "expected canary rule id", 256)
        return value

    @model_validator(mode="after")
    def validate_expected_count(self) -> "RuleCanaryLock":
        if (self.fixture_kind == "file") != (
            self.fixture_hash_algorithm == "sha256-file-v1"
        ):
            raise ValueError("canary fixture kind and hash algorithm disagree")
        if self.expected_result_count < len(self.expected_rule_ids):
            raise ValueError(
                "canary result count cannot be smaller than its unique rule-id set"
            )
        if self.state == "verified":
            if not self.output_sha256:
                raise ValueError(
                    "verified canaries require an exact sanitized output digest"
                )
            if self.reason is not None:
                raise ValueError("verified canaries cannot retain an unresolved reason")
        else:
            if self.output_sha256 is not None:
                raise ValueError(
                    "unverified canaries cannot carry an unproven output digest"
                )
            if not self.reason:
                raise ValueError("unverified canaries require an explicit reason")
        return self


class RuleSetLock(_StrictModel):
    id: str
    tool_id: Literal["opengrep", "bearer"]
    engine_version: str = Field(min_length=1, max_length=64)
    requested_version: str | None = Field(default=None, max_length=64)
    state: ProvenanceState
    distribution_mode: Literal["external", "embedded", "unresolved"]
    source_repository: str | None = Field(default=None, max_length=2048)
    source_path: str | None = Field(default=None, max_length=1024)
    requested_ref: str | None = Field(default=None, max_length=256)
    source_commit: str | None = None
    archive_url: str | None = Field(default=None, max_length=2048)
    archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assets: list[RuleAssetLock] = Field(max_length=32)
    tree_hash_algorithm: Literal["kodesec-canonical-tree-v1"] | None = None
    tree_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    tree_file_count: int | None = Field(default=None, gt=0, le=MAX_GENERATION_FILES)
    tree_size_bytes: int | None = Field(default=None, gt=0, le=MAX_GENERATION_BYTES)
    files: list[RuleFileLock] = Field(max_length=10_000)
    canaries: list[RuleCanaryLock] = Field(max_length=128)
    license: LicenseLock
    reason: str | None = Field(default=None, max_length=512)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _require_identifier(value, "rule set id")

    @field_validator("engine_version")
    @classmethod
    def validate_engine_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("rule engine version must be exact")
        return value

    @field_validator("source_repository")
    @classmethod
    def validate_repository(cls, value: str | None) -> str | None:
        return (
            _require_https(value, "rule source_repository")
            if value is not None
            else None
        )

    @field_validator("source_path")
    @classmethod
    def validate_source_path(cls, value: str | None) -> str | None:
        return (
            _require_relative_path(value, "rule source_path")
            if value is not None
            else None
        )

    @field_validator("requested_ref")
    @classmethod
    def validate_requested_ref(cls, value: str | None) -> str | None:
        if value is not None:
            _require_bounded_text(value, "rule requested_ref", 256)
        return value

    @field_validator("source_commit")
    @classmethod
    def validate_commit(cls, value: str | None) -> str | None:
        if value is not None and not _COMMIT.fullmatch(value):
            raise ValueError("rule source_commit must be a full hexadecimal object id")
        return value

    @field_validator("archive_url")
    @classmethod
    def validate_archive_url(cls, value: str | None) -> str | None:
        return _require_https(value, "rule archive_url") if value is not None else None

    @model_validator(mode="after")
    def validate_release_evidence(self) -> "RuleSetLock":
        paths = [item.path for item in self.files]
        all_rule_ids = [rule_id for item in self.files for rule_id in item.rule_ids]
        asset_names = [item.name for item in self.assets]
        asset_urls = [item.url for item in self.assets]
        canary_ids = [item.id for item in self.canaries]
        if (
            len(paths) != len(set(paths))
            or len(all_rule_ids) != len(set(all_rule_ids))
            or len(asset_names) != len(set(asset_names))
            or len(asset_urls) != len(set(asset_urls))
            or len(canary_ids) != len(set(canary_ids))
        ):
            raise ValueError(
                "rule files, assets, and canaries must have unique identities"
            )
        if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
            raise ValueError("rule files must use canonical UTF-8 path order")
        for item in self.files:
            if item.rule_ids != sorted(item.rule_ids):
                raise ValueError("rule ids must use canonical lexical order")
        if (self.archive_url is None) != (self.archive_sha256 is None):
            raise ValueError("single rule archives require both URL and SHA-256")
        if self.state == "verified":
            if self.distribution_mode == "unresolved":
                raise ValueError(
                    "verified rule sets require a resolved distribution mode"
                )
            if (
                not self.tree_hash_algorithm
                or not self.tree_sha256
                or not self.tree_file_count
                or not self.tree_size_bytes
                or not self.canaries
            ):
                raise ValueError(
                    "verified rule sets require canonical tree and canary evidence"
                )
            if not self.files and not self.assets and self.archive_url is None:
                raise ValueError(
                    "verified rule sets require a file allowlist or digest-pinned assets"
                )
            if self.distribution_mode == "embedded":
                if (
                    not self.source_path
                    or self.source_repository is not None
                    or self.source_commit is not None
                    or self.archive_url is not None
                    or self.assets
                    or not self.files
                ):
                    raise ValueError(
                        "embedded rule sets require only a repository source path and exact file allowlist"
                    )
                if self.tree_file_count != len(self.files):
                    raise ValueError(
                        "embedded rule tree count differs from its file allowlist"
                    )
                if self.tree_size_bytes != sum(item.size_bytes for item in self.files):
                    raise ValueError(
                        "embedded rule tree size differs from its file allowlist"
                    )
                if self.tree_sha256 != canonical_tree_sha256(
                    {
                        "path": item.path,
                        "size_bytes": item.size_bytes,
                        "sha256": item.sha256,
                    }
                    for item in self.files
                ):
                    raise ValueError(
                        "embedded rule tree digest differs from its file allowlist"
                    )
                licenses = [item for item in self.files if item.kind == "license"]
                if len(licenses) != 1:
                    raise ValueError(
                        "embedded rule sets require exactly one allowlisted license"
                    )
                license_file = licenses[0]
                if (
                    self.license.state != "verified"
                    or self.license.source_ref
                    != f"repo:{self.source_path}/{license_file.path}"
                    or self.license.source_sha256 != license_file.sha256
                ):
                    raise ValueError(
                        "embedded rule license evidence differs from its allowlisted file"
                    )
                positive = [
                    item for item in self.canaries if item.expected_result_count > 0
                ]
                zero = [
                    item for item in self.canaries if item.expected_result_count == 0
                ]
                expected_ids = {
                    item.removeprefix("rules.")
                    for canary in positive
                    for item in canary.expected_rule_ids
                }
                if not positive or not zero or expected_ids != set(all_rule_ids):
                    raise ValueError(
                        "embedded rules require positive and zero canaries covering every exact rule id"
                    )
            elif self.distribution_mode == "external":
                if (
                    not self.source_repository
                    or not self.source_commit
                    or self.source_path is not None
                ):
                    raise ValueError(
                        "external rule sets require an HTTPS repository and immutable commit"
                    )
        else:
            if not self.reason:
                raise ValueError("unattested or unavailable rule sets require a reason")
            if any(
                (
                    self.source_commit,
                    self.archive_url,
                    self.archive_sha256,
                    self.assets,
                    self.tree_hash_algorithm,
                    self.tree_sha256,
                    self.tree_file_count,
                    self.tree_size_bytes,
                    self.files,
                    self.canaries,
                )
            ):
                raise ValueError(
                    "partial rule evidence may not masquerade as a non-verified lock"
                )
            if self.source_path is not None:
                raise ValueError(
                    "unverified rule sets cannot claim an embedded source path"
                )
        return self


class RulesLockFile(_StrictModel):
    schema_version: Literal[1]
    ruleset_id: str
    rule_sets: list[RuleSetLock] = Field(min_length=2, max_length=2)

    @field_validator("ruleset_id")
    @classmethod
    def validate_ruleset_id(cls, value: str) -> str:
        return _require_identifier(value, "ruleset id")

    @model_validator(mode="after")
    def validate_complete_rule_set(self) -> "RulesLockFile":
        identifiers = [item.id for item in self.rule_sets]
        tool_ids = [item.tool_id for item in self.rule_sets]
        if set(identifiers) != RULE_SET_IDS or len(identifiers) != len(
            set(identifiers)
        ):
            raise ValueError(
                "rules lock must contain the curated rule sets exactly once"
            )
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("rules lock may contain only one rule set per tool")
        return self

    def rule_set(self, rule_set_id: str) -> RuleSetLock:
        for item in self.rule_sets:
            if item.id == rule_set_id:
                return item
        raise KeyError(rule_set_id)


def validate_lock_alignment(tools: ToolLockFile, rules: RulesLockFile) -> None:
    """Fail when a tool requirement and its rule provenance disagree."""

    requirements = {
        requirement.id: (tool.id, requirement)
        for tool in tools.tools
        for requirement in tool.requirements
        if requirement.kind == "rules"
    }
    if set(requirements) != RULE_SET_IDS:
        raise LockValidationError(
            "tool lock rule requirements differ from the curated rule sets"
        )
    for rule_set in rules.rule_sets:
        tool_id, requirement = requirements[rule_set.id]
        if tool_id != rule_set.tool_id or not requirement.required:
            raise LockValidationError(
                "rule requirement ownership or required state differs from its lock"
            )
        if requirement.provenance != rule_set.state:
            raise LockValidationError(
                "rule requirement provenance differs from its rule lock"
            )
        if rule_set.state != "verified":
            continue
        expected_kind = (
            "embedded" if rule_set.distribution_mode == "embedded" else "rules-lock"
        )
        expected_ref = (
            rule_set.requested_ref
            if rule_set.distribution_mode == "embedded"
            else rule_set.source_commit
        )
        if (
            requirement.source.kind != expected_kind
            or requirement.source.immutable_ref != expected_ref
            or requirement.source.sha256 != rule_set.tree_sha256
        ):
            raise LockValidationError(
                "rule requirement immutable identity differs from its rule lock"
            )


DocumentT = TypeVar("DocumentT", bound=BaseModel)


@dataclass(frozen=True)
class LoadedDocument(Generic[DocumentT]):
    value: DocumentT
    sha256: str
    path: Path


def _load_document(
    path: Path, model: type[DocumentT], label: str
) -> LoadedDocument[DocumentT]:
    try:
        raw = _read_bounded_regular_file(path, MAX_LOCK_BYTES, label)
        payload = _decode_json_object(raw, label)
        value = model.model_validate(payload)
    except (CacheValidationError, LockValidationError, ValidationError) as exc:
        if isinstance(exc, LockValidationError):
            raise
        raise LockValidationError(f"{label} failed strict schema validation") from exc
    return LoadedDocument(
        value=value,
        sha256=hashlib.sha256(raw).hexdigest(),
        path=path.resolve(strict=True),
    )


def load_tool_lock(path: Path) -> LoadedDocument[ToolLockFile]:
    return _load_document(path, ToolLockFile, "scanner tools lock")


def load_rules_lock(path: Path) -> LoadedDocument[RulesLockFile]:
    return _load_document(path, RulesLockFile, "scanner rules lock")


class CacheFileRecord(_StrictModel):
    path: str
    size_bytes: int = Field(ge=0, le=MAX_GENERATION_FILE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _require_relative_path(value, "cache file path")


@dataclass(frozen=True)
class CanonicalTree:
    """A bounded identity for every regular file below one real directory."""

    algorithm: str
    sha256: str
    file_count: int
    size_bytes: int
    files: tuple[CacheFileRecord, ...]


def _canonical_tree_records(
    records: Iterable[CacheFileRecord | Mapping[str, Any]],
) -> tuple[CacheFileRecord, ...]:
    normalized: list[CacheFileRecord] = []
    for item in records:
        if isinstance(item, CacheFileRecord):
            record = item
        else:
            record = CacheFileRecord.model_validate(dict(item))
        if unicodedata.normalize("NFC", record.path) != record.path:
            raise CacheValidationError("canonical tree paths must use Unicode NFC")
        normalized.append(record)
    normalized.sort(key=lambda item: item.path.encode("utf-8"))
    paths = [item.path for item in normalized]
    if len(paths) != len(set(paths)):
        raise CacheValidationError("canonical tree file paths must be unique")
    if len(normalized) > MAX_GENERATION_FILES:
        raise CacheValidationError("canonical tree exceeds its file-count limit")
    if sum(item.size_bytes for item in normalized) > MAX_GENERATION_BYTES:
        raise CacheValidationError("canonical tree exceeds its byte limit")
    return tuple(normalized)


def canonical_tree_sha256(
    records: Iterable[CacheFileRecord | Mapping[str, Any]],
) -> str:
    """Hash canonical v1 records: UTF-8 path, byte size, and file SHA-256.

    The records are sorted by their UTF-8 encoded POSIX path and serialized by
    :func:`canonical_json_bytes`. Directory metadata is intentionally omitted;
    collectors reject empty directories so an unrecorded tree entry cannot be
    added without invalidating the identity.
    """

    normalized = _canonical_tree_records(records)
    payload = [item.model_dump(mode="json") for item in normalized]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def collect_canonical_tree(
    root: Path,
    *,
    require_immutable: bool = False,
    maximum_files: int = MAX_GENERATION_FILES,
    maximum_bytes: int = MAX_GENERATION_BYTES,
) -> CanonicalTree:
    """Read and hash a tree without following aliases or accepting races.

    Symlinks, hardlinks, special files, empty directories, path normalization
    ambiguity, and metadata changes during collection are rejected. When
    ``require_immutable`` is true every directory and file must have all write
    permission bits cleared, as expected for the image-baked rule source.
    """

    if maximum_files <= 0 or maximum_files > MAX_GENERATION_FILES:
        raise ValueError("maximum_files is outside the canonical tree bound")
    if maximum_bytes <= 0 or maximum_bytes > MAX_GENERATION_BYTES:
        raise ValueError("maximum_bytes is outside the canonical tree bound")
    try:
        root_before = root.lstat()
    except OSError as exc:
        raise CacheValidationError("canonical tree root is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_before.st_mode):
        raise CacheValidationError("canonical tree root must be a real directory")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise CacheValidationError("canonical tree root cannot be resolved") from exc
    if require_immutable and root_before.st_mode & 0o222:
        raise CacheValidationError("canonical tree root is writable")

    def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    directory_identities: dict[Path, tuple[int, int, int, int, int, int]] = {
        resolved_root: identity(root_before)
    }
    directories: set[str] = set()
    records: list[CacheFileRecord] = []
    total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise CacheValidationError(
            "canonical tree cannot be traversed safely"
        ) from error

    for current_name, child_directories, child_files in os.walk(
        resolved_root,
        topdown=True,
        followlinks=False,
        onerror=walk_error,
    ):
        current = Path(current_name)
        try:
            current_metadata = current.lstat()
        except OSError as exc:
            raise CacheValidationError("canonical tree directory disappeared") from exc
        if current.is_symlink() or not stat.S_ISDIR(current_metadata.st_mode):
            raise CacheValidationError(
                "canonical tree contains a non-directory traversal entry"
            )
        if require_immutable and current_metadata.st_mode & 0o222:
            raise CacheValidationError("canonical tree contains a writable directory")
        known_identity = directory_identities.get(current)
        if known_identity is not None and known_identity != identity(current_metadata):
            raise CacheValidationError(
                "canonical tree directory changed during traversal"
            )
        directory_identities[current] = identity(current_metadata)

        child_directories.sort(key=lambda item: item.encode("utf-8"))
        child_files.sort(key=lambda item: item.encode("utf-8"))
        for name in child_directories:
            candidate = current / name
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise CacheValidationError(
                    "canonical tree directory cannot be inspected"
                ) from exc
            relative = candidate.relative_to(resolved_root).as_posix()
            _require_relative_path(relative, "canonical tree directory")
            if unicodedata.normalize("NFC", relative) != relative:
                raise CacheValidationError("canonical tree paths must use Unicode NFC")
            if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise CacheValidationError(
                    "canonical tree contains a symlink or special directory"
                )
            if require_immutable and metadata.st_mode & 0o222:
                raise CacheValidationError(
                    "canonical tree contains a writable directory"
                )
            directories.add(relative)
            directory_identities[candidate] = identity(metadata)

        for name in child_files:
            candidate = current / name
            relative = candidate.relative_to(resolved_root).as_posix()
            _require_relative_path(relative, "canonical tree file")
            if unicodedata.normalize("NFC", relative) != relative:
                raise CacheValidationError("canonical tree paths must use Unicode NFC")
            try:
                path_before = candidate.lstat()
            except OSError as exc:
                raise CacheValidationError(
                    "canonical tree file cannot be inspected"
                ) from exc
            if candidate.is_symlink() or not stat.S_ISREG(path_before.st_mode):
                raise CacheValidationError(
                    "canonical tree contains a symlink or special file"
                )
            if path_before.st_nlink != 1:
                raise CacheValidationError("canonical tree contains a hard-linked file")
            if require_immutable and path_before.st_mode & 0o222:
                raise CacheValidationError("canonical tree contains a writable file")
            if path_before.st_size > MAX_GENERATION_FILE_BYTES:
                raise CacheValidationError("canonical tree file exceeds its size limit")
            try:
                descriptor = os.open(candidate, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
            except OSError as exc:
                raise CacheValidationError(
                    "canonical tree file cannot be opened safely"
                ) from exc
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or identity(before) != identity(path_before)
                ):
                    raise CacheValidationError(
                        "canonical tree file changed before reading"
                    )
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = os.read(
                        descriptor,
                        min(1024 * 1024, MAX_GENERATION_FILE_BYTES + 1 - observed),
                    )
                    if not chunk:
                        break
                    digest.update(chunk)
                    observed += len(chunk)
                    if observed > MAX_GENERATION_FILE_BYTES:
                        raise CacheValidationError(
                            "canonical tree file exceeds its size limit"
                        )
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            try:
                path_after = candidate.lstat()
            except OSError as exc:
                raise CacheValidationError(
                    "canonical tree file disappeared while reading"
                ) from exc
            if (
                identity(before) != identity(after)
                or identity(after) != identity(path_after)
                or observed != after.st_size
                or path_after.st_nlink != 1
            ):
                raise CacheValidationError("canonical tree file changed while reading")
            records.append(
                CacheFileRecord(
                    path=relative, size_bytes=observed, sha256=digest.hexdigest()
                )
            )
            total_bytes += observed
            if len(records) > maximum_files or total_bytes > maximum_bytes:
                raise CacheValidationError(
                    "canonical tree exceeds its configured bound"
                )

    required_directories: set[str] = set()
    for record in records:
        parts = record.path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            required_directories.add("/".join(parts[:index]))
    if directories != required_directories:
        raise CacheValidationError(
            "canonical tree contains an empty or unrecorded directory"
        )
    for directory, before in directory_identities.items():
        try:
            after = directory.lstat()
        except OSError as exc:
            raise CacheValidationError(
                "canonical tree directory disappeared after traversal"
            ) from exc
        if directory.is_symlink() or identity(after) != before:
            raise CacheValidationError(
                "canonical tree directory changed during traversal"
            )

    normalized = _canonical_tree_records(records)
    if not normalized:
        raise CacheValidationError("canonical tree contains no files")
    return CanonicalTree(
        algorithm=CANONICAL_TREE_HASH_ALGORITHM,
        sha256=canonical_tree_sha256(normalized),
        file_count=len(normalized),
        size_bytes=sum(item.size_bytes for item in normalized),
        files=normalized,
    )


class CanaryReceipt(_StrictModel):
    canary_id: str
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exit_code: int = Field(ge=0, le=255)
    result_count: int = Field(ge=0, le=10_000)
    expected_ids: list[str] = Field(max_length=128)
    observed_ids: list[str] = Field(max_length=512)
    passed: Literal[True]

    @field_validator("canary_id")
    @classmethod
    def validate_canary_id(cls, value: str) -> str:
        return _require_identifier(value, "canary receipt id")

    @model_validator(mode="after")
    def validate_result(self) -> "CanaryReceipt":
        if self.expected_ids != sorted(set(self.expected_ids)):
            raise ValueError("canary expected ids must be sorted and unique")
        if self.observed_ids != sorted(set(self.observed_ids)):
            raise ValueError("canary observed ids must be sorted and unique")
        for item in [*self.expected_ids, *self.observed_ids]:
            _require_bounded_text(item, "canary result id", 256)
        if self.expected_ids != self.observed_ids:
            raise ValueError("cache canary result ids differ from the exact expectation")
        if self.result_count < len(self.observed_ids):
            raise ValueError("cache canary result count is smaller than its rule-id set")
        return self


class GrypeLogicalContentReceipt(_StrictModel):
    """Recomputed logical digests; actual byte hashes remain in ``files``."""

    database_logical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    import_metadata_logical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CacheComponentReceipt(_StrictModel):
    component_id: str
    tool_id: str
    kind: RequirementKind
    root: str
    immutable_ref: str = Field(min_length=1, max_length=2048)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    updated_at: str
    expires_at: str | None = None
    files: list[CacheFileRecord] = Field(min_length=1, max_length=MAX_GENERATION_FILES)
    canaries: list[CanaryReceipt] = Field(min_length=1, max_length=128)
    grype_logical_content: GrypeLogicalContentReceipt | None = None

    @field_validator("component_id", "tool_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _require_identifier(value, "cache component identifier")

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str) -> str:
        return _require_relative_path(value, "cache component root")

    @field_validator("immutable_ref")
    @classmethod
    def validate_immutable_ref(cls, value: str) -> str:
        return _require_bounded_text(value, "cache immutable_ref")

    @field_validator("updated_at")
    @classmethod
    def validate_updated_at(cls, value: str) -> str:
        _parse_utc(value, "updated_at")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: str | None) -> str | None:
        if value is not None:
            _parse_utc(value, "expires_at")
        return value

    @model_validator(mode="after")
    def validate_files(self) -> "CacheComponentReceipt":
        if self.grype_logical_content is not None and (
            self.component_id != "grype-db"
            or self.tool_id != "grype"
            or self.kind != "database"
            or self.root != "grype"
        ):
            raise ValueError("logical Grype evidence requires the exact Grype component")
        if self.tool_id not in EXTERNAL_TOOL_IDS:
            raise ValueError("cache component names an unknown external tool")
        paths = [item.path for item in self.files]
        canary_ids = [item.canary_id for item in self.canaries]
        if len(paths) != len(set(paths)):
            raise ValueError("cache component file paths must be unique")
        if canary_ids != sorted(set(canary_ids)):
            raise ValueError("cache component canaries must be sorted and unique")
        prefix = self.root + "/"
        if any(not path.startswith(prefix) for path in paths):
            raise ValueError("cache component files must be below the declared root")
        updated = _parse_utc(self.updated_at, "updated_at")
        if self.kind in {"database", "checks"} and self.expires_at is None:
            raise ValueError("database and checks cache components require an expiry")
        if self.kind == "rules" and self.expires_at is not None:
            raise ValueError("rules cache components may not declare an expiry")
        if self.expires_at is not None and _parse_utc(
            self.expires_at, "expires_at"
        ) <= updated:
            raise ValueError("cache component expiry must follow its update time")
        return self


def locked_intrinsic_updated_at(
    requirement: ComponentRequirementLock,
) -> str | None:
    """Return the reviewed publisher timestamp for one intrinsic component.

    Publisher refresh hints (for example Trivy ``NextUpdate``) deliberately do
    not participate in the hard-validity calculation. They remain attested in
    the lock so promotion can verify the exact immutable object, while the
    local hard expiry is always anchored to the publisher's update/build time.
    """

    contract = requirement.data_contract
    if isinstance(
        contract,
        (TrivyDatabaseDataContract, TrivyJavaDatabaseDataContract),
    ):
        return contract.publisher_updated_at
    if isinstance(contract, GrypeDatabaseDataContract):
        return contract.built_at
    return None


def receipt_matches_freshness_contract(
    receipt: CacheComponentReceipt,
    requirement: ComponentRequirementLock,
) -> bool:
    """Bind a data receipt to the exact reviewed fourteen-day hard window."""

    if requirement.kind not in {"database", "checks"}:
        return receipt.expires_at is None
    if (
        requirement.max_age_seconds != REVIEWED_DATA_HARD_VALIDITY_SECONDS
        or receipt.expires_at is None
    ):
        return False
    try:
        updated = _parse_utc(receipt.updated_at, "updated_at")
        expires = _parse_utc(receipt.expires_at, "expires_at")
        intrinsic = locked_intrinsic_updated_at(requirement)
        if intrinsic is not None and updated != _parse_utc(intrinsic, "locked intrinsic timestamp"):
            return False
    except ValueError:
        return False
    return expires == updated + timedelta(
        seconds=REVIEWED_DATA_HARD_VALIDITY_SECONDS
    )


def grype_logical_tree_records(
    records: Iterable[CacheFileRecord],
    logical: GrypeLogicalContentReceipt,
) -> list[CacheFileRecord]:
    """Replace only verified derived digests, retaining exact paths and sizes."""

    files = list(records)
    by_path = {record.path: record for record in files}
    if len(files) != 2 or set(by_path) != {
        GRYPE_DATABASE_PATH, GRYPE_IMPORT_METADATA_PATH
    }:
        raise GrypeContentValidationError("files")
    replacements = {
        GRYPE_DATABASE_PATH: logical.database_logical_sha256,
        GRYPE_IMPORT_METADATA_PATH: logical.import_metadata_logical_sha256,
    }
    return [
        record.model_copy(update={"sha256": replacements[record.path]})
        for record in files
    ]


_GRYPE_LOGICAL_PROOF_CACHE_LOCK = threading.Lock()
_GRYPE_LOGICAL_PROOF_CACHE: OrderedDict[
    tuple[str, str, str, int, str, int], GrypeLogicalContentReceipt
] = OrderedDict()
_GRYPE_LOGICAL_PROOF_CACHE_LIMIT = 2


def clear_grype_logical_proof_cache() -> None:
    """Discard process-local proofs; no persisted receipt can populate them."""
    with _GRYPE_LOGICAL_PROOF_CACHE_LOCK:
        _GRYPE_LOGICAL_PROOF_CACHE.clear()


def verify_grype_logical_content(
    root: Path,
    records: Iterable[CacheFileRecord],
    *,
    checkpoint: Callable[[], object] | None = None,
    _observation_sink: list[GrypeFileObservation] | None = None,
    deadline_monotonic: float | None = None,
) -> GrypeLogicalContentReceipt:
    """Verify actual DB/schema integrity and its checksum-derived metadata.

    Always re-read both physical files. A successful in-process SQL proof may
    be reused only for those exact bytes and algorithms, including after a
    private staging tree is copied. Manifests, paths and stat data cannot seed
    or select a proof. Structural and physical generation checks remain owned
    by the caller. No failure or incomplete observation is retained.
    The non-cryptographic xxh64 only validates Grype's own import record; both
    the reviewed logical identity and sealed physical files remain SHA-256.
    """
    from .grype_identity import (
        GRYPE_LOGICAL_DB_ALGORITHM, GrypeFileObservation, GrypeIdentityError,
        compute_grype_logical_identity, observe_grype_file,
    )

    if _observation_sink is not None and (type(_observation_sink) is not list or _observation_sink):
        raise ValueError("Grype observation sink must be an empty list")

    deadline = time.monotonic() + GRYPE_IDENTITY_TIMEOUT_SECONDS
    # Maintained callbacks are bound context methods. Decorators must preserve
    # __wrapped__, or callers must supply deadline_monotonic explicitly.
    callback = checkpoint
    seen_callbacks: set[int] = set()
    while deadline_monotonic is None and callback is not None:
        if id(callback) in seen_callbacks:
            raise ValueError("verification checkpoint wrapper is cyclic")
        seen_callbacks.add(id(callback))
        owner = getattr(callback, "__self__", None)
        owned_deadline = getattr(owner, "verification_deadline_monotonic", None)
        if callable(owned_deadline):
            deadline_monotonic = owned_deadline()
            break
        callback = getattr(callback, "__wrapped__", None)
    if deadline_monotonic is not None:
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(deadline_monotonic)
        ):
            raise ValueError("verification deadline must be an owned finite monotonic value")
        deadline = min(deadline, deadline_monotonic)

    def remaining_seconds() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0.001:
            raise GrypeContentValidationError("deadline")
        return remaining

    remaining_seconds()
    files = list(records)
    by_path = {record.path: record for record in files}
    if len(files) != 2 or set(by_path) != {
        GRYPE_DATABASE_PATH, GRYPE_IMPORT_METADATA_PATH
    }:
        raise GrypeContentValidationError("files")
    database = by_path[GRYPE_DATABASE_PATH]
    metadata_record = by_path[GRYPE_IMPORT_METADATA_PATH]
    if not 0 < database.size_bytes <= MAX_GENERATION_FILE_BYTES:
        raise GrypeContentValidationError("size")
    if not 0 < metadata_record.size_bytes <= 4096:
        raise GrypeContentValidationError("import_metadata")
    try:
        raw = _read_bounded_regular_file(root / GRYPE_IMPORT_METADATA_PATH, 4096, "Grype import metadata")
    except CacheValidationError as exc:
        raise GrypeContentValidationError("import_metadata") from exc
    if len(raw) != metadata_record.size_bytes or hashlib.sha256(raw).hexdigest() != metadata_record.sha256:
        raise GrypeContentValidationError("import_metadata")
    try:
        metadata = _decode_json_object(raw, "Grype import metadata")
    except LockValidationError as exc:
        raise GrypeContentValidationError("import_metadata") from exc
    if (
        set(metadata) != {"digest", "source", "client_version"}
        or metadata["source"] != "manual import"
        or not isinstance(metadata["client_version"], str)
        or not re.fullmatch(r"v6\.[0-9]+\.[0-9]+", metadata["client_version"])
        or not isinstance(metadata["digest"], str)
        or not re.fullmatch(r"xxh64:[0-9a-f]{16}", metadata["digest"])
    ):
        raise GrypeContentValidationError("import_metadata")
    try:
        observed_metadata = observe_grype_file(
            root / GRYPE_IMPORT_METADATA_PATH,
            maximum_bytes=metadata_record.size_bytes,
            timeout_seconds=remaining_seconds(),
            checkpoint=checkpoint,
        )
        if (observed_metadata.sha256 != metadata_record.sha256
                or observed_metadata.size_bytes != metadata_record.size_bytes):
            raise GrypeContentValidationError("import_metadata")
        # Only the internal cache's empty state selects this cold path. No
        # manifest, pathname, or stat value selects a cached SQL proof. The
        # compute function hashes the real DB itself and outputs its own fresh
        # observation only after successful SQL/integrity validation.
        with _GRYPE_LOGICAL_PROOF_CACHE_LOCK:
            cold_cache = not _GRYPE_LOGICAL_PROOF_CACHE
        identity = None
        if cold_cache:
            fresh_observations: list[GrypeFileObservation] = []
            identity = compute_grype_logical_identity(
                root / GRYPE_DATABASE_PATH,
                maximum_bytes=database.size_bytes,
                timeout_seconds=remaining_seconds(),
                checkpoint=checkpoint,
                _observation_sink=fresh_observations,
            )
            if (len(fresh_observations) != 1
                    or type(fresh_observations[0]) is not GrypeFileObservation
                    or fresh_observations[0]._path != root / GRYPE_DATABASE_PATH):
                raise GrypeContentValidationError("changed")
            observed_database = fresh_observations[0]
        else:
            observed_database = observe_grype_file(
                root / GRYPE_DATABASE_PATH,
                maximum_bytes=database.size_bytes,
                timeout_seconds=remaining_seconds(),
                checkpoint=checkpoint,
            )
        if (observed_database.sha256 != database.sha256
                or observed_database.size_bytes != database.size_bytes):
            raise GrypeContentValidationError("changed")
        if metadata["digest"] != observed_database.xxh64:
            raise GrypeContentValidationError("import_checksum")
        key = (
            GRYPE_LOGICAL_TREE_HASH_ALGORITHM, GRYPE_LOGICAL_DB_ALGORITHM,
            observed_database.sha256, observed_database.size_bytes,
            observed_metadata.sha256, observed_metadata.size_bytes,
        )
        result = None
        if not cold_cache:
            with _GRYPE_LOGICAL_PROOF_CACHE_LOCK:
                result = _GRYPE_LOGICAL_PROOF_CACHE.get(key)
        if result is None:
            if identity is None:
                identity = compute_grype_logical_identity(
                    root / GRYPE_DATABASE_PATH,
                    maximum_bytes=database.size_bytes,
                    timeout_seconds=remaining_seconds(),
                    checkpoint=checkpoint,
                )
            if (identity.algorithm != GRYPE_LOGICAL_DB_ALGORITHM
                    or identity.physical_sha256 != observed_database.sha256
                    or identity.physical_xxh64 != observed_database.xxh64):
                raise GrypeContentValidationError("changed")
            normalized_metadata = {
                **metadata,
                "digest": "logical-sha256:" + identity.sha256,
            }
            result = GrypeLogicalContentReceipt(
                database_logical_sha256=identity.sha256,
                import_metadata_logical_sha256=hashlib.sha256(
                    canonical_json_bytes(normalized_metadata)
                ).hexdigest(),
            )
        if checkpoint is not None:
            checkpoint()
        remaining_seconds()
        # Check both after the final caller callback: it may itself cancel or
        # detect/mutate operation state. These fences never replace byte hashes.
        observed_database.require_unchanged()
        observed_metadata.require_unchanged()
    except GrypeIdentityError as exc:
        raise GrypeContentValidationError(exc.code, validation_timing=exc.validation_timing) from exc
    with _GRYPE_LOGICAL_PROOF_CACHE_LOCK:
        _GRYPE_LOGICAL_PROOF_CACHE[key] = result
        _GRYPE_LOGICAL_PROOF_CACHE.move_to_end(key)
        while len(_GRYPE_LOGICAL_PROOF_CACHE) > _GRYPE_LOGICAL_PROOF_CACHE_LIMIT:
            _GRYPE_LOGICAL_PROOF_CACHE.popitem(last=False)
    if _observation_sink is not None:
        _observation_sink.append(observed_database)
    return result


def receipt_matches_installed_content(
    receipt: CacheComponentReceipt,
    requirement: ComponentRequirementLock,
) -> bool:
    """Independently bind a promoted receipt to immutable installed payloads."""

    expected = requirement.installed_content
    if expected is None or requirement.installed_size_bytes is None:
        return False
    prefix = receipt.root + "/"
    relative = [
        item.model_copy(update={"path": item.path.removeprefix(prefix)})
        for item in receipt.files
    ]
    records = {item.path: item for item in relative}
    volatile = set(expected.volatile_paths)
    if not volatile.issubset(records):
        return False
    if any(records[path].size_bytes <= 0 or records[path].size_bytes > 4096 for path in volatile):
        return False
    stable = [item for item in relative if item.path not in volatile]
    if expected.hash_algorithm == GRYPE_LOGICAL_TREE_HASH_ALGORITHM:
        if receipt.grype_logical_content is None:
            return False
        try:
            stable = grype_logical_tree_records(stable, receipt.grype_logical_content)
        except CacheValidationError:
            return False
    elif receipt.grype_logical_content is not None:
        return False
    stable_size = sum(item.size_bytes for item in stable)
    observed_size = sum(item.size_bytes for item in relative)
    return (
        canonical_tree_sha256(stable) == expected.sha256
        and len(stable) == expected.file_count
        and stable_size == expected.size_bytes
        and observed_size >= stable_size + len(volatile)
        and observed_size
        <= requirement.installed_size_bytes + 4096 * len(volatile)
    )


def _generation_identity_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "generation_id"}


class GenerationManifest(_StrictModel):
    schema_version: Literal[1]
    generation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rules_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str
    total_size_bytes: int = Field(ge=0, le=MAX_GENERATION_BYTES)
    components: list[CacheComponentReceipt] = Field(min_length=1, max_length=64)

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: str) -> str:
        _parse_utc(value, "generation created_at")
        return value

    @model_validator(mode="after")
    def validate_identity_and_contents(self) -> "GenerationManifest":
        component_ids = [item.component_id for item in self.components]
        paths = [record.path for item in self.components for record in item.files]
        if len(component_ids) != len(set(component_ids)):
            raise ValueError("generation component ids must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("generation file paths must be globally unique")
        if len(paths) > MAX_GENERATION_FILES:
            raise ValueError("generation contains too many files")
        total = sum(
            record.size_bytes for item in self.components for record in item.files
        )
        if total != self.total_size_bytes:
            raise ValueError("generation total size does not match its file records")
        payload = self.model_dump(mode="json")
        expected = canonical_sha256(_generation_identity_payload(payload))
        if self.generation_id != expected:
            raise ValueError("generation id does not match canonical manifest content")
        return self

    @classmethod
    def create(
        cls,
        *,
        tool_lock_sha256: str,
        rules_lock_sha256: str,
        created_at: str,
        components: list[CacheComponentReceipt],
    ) -> "GenerationManifest":
        total = sum(record.size_bytes for item in components for record in item.files)
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool_lock_sha256": tool_lock_sha256,
            "rules_lock_sha256": rules_lock_sha256,
            "created_at": created_at,
            "total_size_bytes": total,
            "components": [item.model_dump(mode="json") for item in components],
        }
        return cls.model_validate(
            {"generation_id": canonical_sha256(payload), **payload}
        )


class GenerationReference(_StrictModel):
    generation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActiveGenerationPointer(_StrictModel):
    schema_version: Literal[1]
    revision: int = Field(ge=1)
    active: GenerationReference
    previous_good: GenerationReference | None
    activated_at: str
    operation_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )

    @field_validator("activated_at")
    @classmethod
    def validate_activated_at(cls, value: str) -> str:
        _parse_utc(value, "pointer activated_at")
        return value

    @model_validator(mode="after")
    def validate_references(self) -> "ActiveGenerationPointer":
        if (
            self.previous_good
            and self.previous_good.generation_id == self.active.generation_id
        ):
            raise ValueError("active and previous-good generations must differ")
        return self


@dataclass(frozen=True)
class ValidatedGeneration:
    path: Path
    manifest: GenerationManifest
    manifest_sha256: str

    @property
    def reference(self) -> GenerationReference:
        return GenerationReference(
            generation_id=self.manifest.generation_id,
            manifest_sha256=self.manifest_sha256,
        )


class CacheVerification(_StrictModel):
    state: Literal["verifying", "timed_out", "failed"]
    target: Literal["active", "previous_good"]
    generation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    phase: Literal["queued", "validating", "hashing"]
    component_id: str | None = None
    started_at: datetime
    last_activity_at: datetime
    bytes_verified: int | None = Field(default=None, ge=0, le=MAX_GENERATION_BYTES)
    bytes_total: int | None = Field(default=None, ge=0, le=MAX_GENERATION_BYTES)

    @model_validator(mode="after")
    def validate_observation(self) -> "CacheVerification":
        if self.component_id is not None and self.component_id not in CACHE_COMPONENT_IDS:
            raise ValueError("unreviewed verification component")
        if (self.started_at.utcoffset() != timedelta(0)
                or self.last_activity_at.utcoffset() != timedelta(0)
                or self.last_activity_at < self.started_at):
            raise ValueError("verification activity requires ordered UTC timestamps")
        if (self.bytes_verified is None) != (self.bytes_total is None):
            raise ValueError("verification byte counts must be paired")
        if self.bytes_verified is not None and self.bytes_verified > self.bytes_total:
            raise ValueError("verification bytes exceed the component total")
        return self


@dataclass(frozen=True)
class ResolvedGeneration:
    state: Literal["ready", "fallback", "unavailable", "invalid", "verifying", "verification_timeout", "verification_failed"]
    generation: ValidatedGeneration | None
    pointer: ActiveGenerationPointer | None
    error_code: str | None = None
    verification: CacheVerification | None = None


@dataclass(frozen=True)
class RuntimeComponentSnapshot:
    generation_id: str
    manifest_sha256: str
    roots: Mapping[str, Path]


@dataclass(frozen=True)
class _RuntimeGenerationCacheEntry:
    identity: tuple[Any, ...]
    resolved: ResolvedGeneration


_RUNTIME_GENERATION_CACHE_LOCK = threading.Lock()
_RUNTIME_GENERATION_CACHE: dict[str, _RuntimeGenerationCacheEntry] = {}


def _secure_directory(path: Path, label: str, *, create: bool = False) -> Path:
    try:
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise CacheValidationError(f"{label} must be a real directory")
        return path.resolve(strict=True)
    except CacheValidationError:
        raise
    except OSError as exc:
        raise CacheValidationError(f"{label} is missing or unsafe") from exc


@dataclass
class _GenerationHashCheckpoint:
    callback: Callable[[], object] | None
    observe_bytes: Callable[[int], object] | None = None
    bytes_since_checkpoint: int = 0

    def observe(self, amount: int) -> None:
        if self.observe_bytes is not None:
            self.observe_bytes(amount)
        if self.callback is not None:
            self.bytes_since_checkpoint += amount
            if self.bytes_since_checkpoint >= GENERATION_HASH_CHECKPOINT_BYTES:
                self.callback()
                self.bytes_since_checkpoint %= GENERATION_HASH_CHECKPOINT_BYTES


def _hash_generation_file(
    path: Path,
    expected_size: int,
    checkpoint: _GenerationHashCheckpoint,
) -> str:
    maximum = min(MAX_GENERATION_FILE_BYTES, expected_size)
    if expected_size < 0:
        raise CacheValidationError("generation file has a negative expected size")
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise CacheValidationError(
                "generation entry is not a regular non-symlink file"
            )
        if (
            before_path.st_nlink != 1
            or before_path.st_size != expected_size
            or expected_size > maximum
        ):
            raise CacheValidationError("generation file identity or size is unsafe")
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except CacheValidationError:
        raise
    except OSError as exc:
        raise CacheValidationError("generation file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise CacheValidationError("generation file grew while hashing")
            digest.update(chunk)
            checkpoint.observe(len(chunk))
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != expected_size:
            raise CacheValidationError("generation file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _require_grype_observation_unchanged(observation: GrypeFileObservation) -> None:
    from .grype_identity import GrypeIdentityError

    try:
        observation.require_unchanged()
    except GrypeIdentityError as exc:
        raise GrypeContentValidationError(exc.code) from exc


def _walk_generation(
    root: Path,
    checkpoint: Callable[[], object] | None = None,
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    pending: list[tuple[Path, int]] = [(root, 0)]
    entries = 0
    if checkpoint is not None:
        checkpoint()
    while pending:
        current, depth = pending.pop()
        if depth > MAX_GENERATION_DEPTH:
            raise CacheValidationError("generation directory depth exceeds its limit")
        try:
            current_entries = list(os.scandir(current))
        except OSError as exc:
            raise CacheValidationError(
                "generation directory cannot be enumerated"
            ) from exc
        for entry in current_entries:
            entries += 1
            if (
                checkpoint is not None
                and entries % GENERATION_WALK_CHECKPOINT_ENTRIES == 0
            ):
                checkpoint()
            if entries > MAX_GENERATION_FILES + MAX_GENERATION_DEPTH * 64:
                raise CacheValidationError("generation contains too many entries")
            relative = Path(entry.path).relative_to(root).as_posix()
            try:
                _require_relative_path(relative, "generation entry")
            except ValueError as exc:
                raise CacheValidationError(
                    "generation contains an unsafe relative path"
                ) from exc
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise CacheValidationError(
                    "generation entry cannot be inspected"
                ) from exc
            if entry.is_symlink():
                raise CacheValidationError("generation may not contain symlinks")
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_mode & 0o222:
                    raise CacheValidationError("generation directories must be immutable")
                directories.add(relative)
                pending.append((Path(entry.path), depth + 1))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1 or metadata.st_mode & 0o222:
                    raise CacheValidationError("generation files must be immutable and unlinked")
                files.add(relative)
            else:
                raise CacheValidationError(
                    "generation contains a non-file filesystem entry"
                )
    if checkpoint is not None:
        checkpoint()
    return files, directories


def _model_from_raw(raw: bytes, model: type[DocumentT], label: str) -> DocumentT:
    try:
        return model.model_validate(_decode_json_object(raw, label))
    except (LockValidationError, ValidationError) as exc:
        raise CacheValidationError(f"{label} failed strict schema validation") from exc


def validate_generation(
    cache_root: Path,
    generation_id: str,
    *,
    expected_manifest_sha256: str | None = None,
    checkpoint: Callable[[], object] | None = None,
    progress: Callable[[str, int, int, int, int], object] | None = None,
) -> ValidatedGeneration:
    if checkpoint is not None:
        checkpoint()
    if not _DIGEST.fullmatch(generation_id):
        raise CacheValidationError("generation id must be a lowercase SHA-256 digest")
    root = _secure_directory(cache_root, "tool cache root")
    generations = _secure_directory(root / "generations", "generation root")
    generation = _secure_directory(generations / generation_id, "generation")
    if generation.parent != generations or generation.name != generation_id:
        raise CacheValidationError("generation escapes the generation root")
    if generation.lstat().st_mode & 0o222:
        raise CacheValidationError("generation root must be immutable")
    manifest_path = generation / "manifest.json"
    raw = _read_bounded_regular_file(
        manifest_path,
        MAX_GENERATION_MANIFEST_BYTES,
        "generation manifest",
    )
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if (
        expected_manifest_sha256 is not None
        and manifest_sha256 != expected_manifest_sha256
    ):
        raise CacheValidationError(
            "generation manifest digest does not match the active pointer"
        )
    manifest = _model_from_raw(raw, GenerationManifest, "generation manifest")
    if manifest.generation_id != generation_id:
        raise CacheValidationError(
            "generation directory and manifest identities differ"
        )

    actual_files, actual_directories = _walk_generation(generation, checkpoint)
    records = {
        record.path: record
        for component in manifest.components
        for record in component.files
    }
    expected_files = set(records) | {"manifest.json"}
    if actual_files != expected_files:
        raise CacheValidationError("generation contains missing or undeclared files")
    expected_directories: set[str] = set()
    for path in records:
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    if actual_directories != expected_directories:
        raise CacheValidationError(
            "generation contains missing or undeclared directories"
        )

    observed_total = 0
    hash_checkpoint = _GenerationHashCheckpoint(checkpoint)
    file_index = 0
    component_total = len(manifest.components)
    reused_grype_observations: list[GrypeFileObservation] = []
    for component_index, component in enumerate(manifest.components, start=1):
        component_bytes = 0
        component_size = sum(record.size_bytes for record in component.files)
        if progress is not None:
            progress(
                component.component_id,
                component_index,
                component_total,
                component_bytes,
                component_size,
            )

        # SQL integrity/row verification precedes byte progress. A complete
        # byte counter must not imply this additional validation has finished.
        grype_observations: list[GrypeFileObservation] = []
        if component.grype_logical_content is not None:
            prefix = component.root + "/"
            relative_files = [
                record.model_copy(update={"path": record.path.removeprefix(prefix)})
                for record in component.files
            ]
            observed_logical = verify_grype_logical_content(
                generation / component.root, relative_files, checkpoint=checkpoint,
                _observation_sink=grype_observations,
            )
            if observed_logical != component.grype_logical_content:
                raise GrypeContentValidationError("data")

        def observe_component_bytes(amount: int) -> None:
            nonlocal component_bytes
            component_bytes += amount
            if progress is not None:
                progress(
                    component.component_id,
                    component_index,
                    component_total,
                    component_bytes,
                    component_size,
                )

        hash_checkpoint.observe_bytes = observe_component_bytes
        for record in component.files:
            file_index += 1
            database_path = generation / record.path
            is_grype_database = (
                component.grype_logical_content is not None
                and record.path == component.root + "/" + GRYPE_DATABASE_PATH
            )
            if is_grype_database and grype_observations:
                if len(grype_observations) != 1:
                    raise CacheValidationError("Grype observation count is invalid")
                observation = grype_observations[0]
                if (
                    observation._path != database_path
                    or observation.size_bytes != record.size_bytes
                    or observation.sha256 != record.sha256
                ):
                    raise CacheValidationError("Grype observation does not match the manifest")
                # The verifier already read and SHA-256-hashed these exact
                # bytes. Keep its post-callback identity/sidecar fence after
                # reporting progress, and retain it until the final callback.
                _require_grype_observation_unchanged(observation)
                hash_checkpoint.observe(record.size_bytes)
                _require_grype_observation_unchanged(observation)
                reused_grype_observations.append(observation)
                observed = observation.sha256
            else:
                observed = _hash_generation_file(
                    database_path,
                    record.size_bytes,
                    hash_checkpoint,
                )
            if observed != record.sha256:
                raise CacheValidationError(
                    "generation file digest does not match its manifest"
                )
            observed_total += record.size_bytes
            if observed_total > MAX_GENERATION_BYTES:
                raise CacheValidationError("generation exceeds its aggregate size limit")
            if (
                checkpoint is not None
                and file_index % GENERATION_WALK_CHECKPOINT_ENTRIES == 0
            ):
                checkpoint()
        if component_bytes != component_size:
            raise CacheValidationError("generation component size does not match its manifest")
    hash_checkpoint.observe_bytes = None
    if observed_total != manifest.total_size_bytes:
        raise CacheValidationError(
            "generation aggregate size does not match its manifest"
        )
    if checkpoint is not None:
        checkpoint()
    for observation in reused_grype_observations:
        _require_grype_observation_unchanged(observation)
    return ValidatedGeneration(
        path=generation,
        manifest=manifest,
        manifest_sha256=manifest_sha256,
    )


def _atomic_write_json(parent: Path, filename: str, payload: Any, maximum: int) -> str:
    if "/" in filename or "\\" in filename or filename in {"", ".", ".."}:
        raise CacheActivationError("atomic JSON destination must be one direct child")
    rendered = canonical_json_bytes(payload)
    if len(rendered) > maximum:
        raise CacheActivationError("atomic JSON payload exceeds its size limit")
    directory = _secure_directory(parent, "atomic JSON parent")
    flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
    directory_fd = os.open(directory, flags)
    temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        try:
            target = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise CacheActivationError("atomic JSON target is not a regular file")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        written = 0
        while written < len(rendered):
            count = os.write(descriptor, rendered[written:])
            if count <= 0:
                raise CacheActivationError("atomic JSON write made no progress")
            written += count
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
        )
        os.fsync(directory_fd)
    except CacheActivationError:
        raise
    except OSError as exc:
        raise CacheActivationError("atomic JSON publication failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except (FileNotFoundError, OSError):
            pass
        os.close(directory_fd)
    return hashlib.sha256(rendered).hexdigest()


def write_generation_manifest(generation: Path, manifest: GenerationManifest) -> str:
    directory = _secure_directory(generation, "generation")
    if directory.name != manifest.generation_id:
        raise CacheActivationError(
            "manifest generation id does not match its destination"
        )
    digest = _atomic_write_json(
        directory,
        "manifest.json",
        manifest.model_dump(mode="json"),
        MAX_GENERATION_MANIFEST_BYTES,
    )
    for current_name, directories, files in os.walk(directory, topdown=False):
        current = Path(current_name)
        for name in files:
            path = current / name
            if path.is_symlink() or not path.is_file():
                raise CacheActivationError("generation contains an unsafe entry while sealing")
            path.chmod(0o400)
        for name in directories:
            path = current / name
            if path.is_symlink() or not path.is_dir():
                raise CacheActivationError("generation contains an unsafe entry while sealing")
            path.chmod(0o500)
    directory.chmod(0o500)
    return digest


def load_active_pointer(cache_root: Path) -> ActiveGenerationPointer:
    root = _secure_directory(cache_root, "tool cache root")
    path = root / "active.json"
    try:
        raw = _read_bounded_regular_file(
            path, MAX_ACTIVE_POINTER_BYTES, "active generation pointer"
        )
        return _model_from_raw(
            raw, ActiveGenerationPointer, "active generation pointer"
        )
    except FileNotFoundError as exc:
        raise CacheValidationError("active generation pointer is missing") from exc


def _path_stat_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    """Return the metadata identity used to cache an immutable cache snapshot."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CacheValidationError("runtime cache identity cannot be inspected") from exc
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _runtime_generation_identity(
    cache_root: Path,
    *,
    tool_lock_sha256: str,
    rules_lock_sha256: str,
) -> tuple[Any, ...]:
    """Bind a cached validation to exact pointer, lock, and generation identities."""

    root = _secure_directory(cache_root, "tool cache root")
    pointer_path = root / "active.json"
    raw = _read_bounded_regular_file(
        pointer_path,
        MAX_ACTIVE_POINTER_BYTES,
        "active generation pointer",
    )
    pointer = _model_from_raw(
        raw,
        ActiveGenerationPointer,
        "active generation pointer",
    )
    generations = root / "generations"
    identities: list[Any] = [
        str(root),
        tool_lock_sha256,
        rules_lock_sha256,
        hashlib.sha256(raw).hexdigest(),
        _path_stat_identity(pointer_path),
        _path_stat_identity(generations),
    ]
    for reference in (pointer.active, pointer.previous_good):
        if reference is None:
            identities.append(None)
            continue
        generation = generations / reference.generation_id
        identities.append(
            (
                reference.generation_id,
                reference.manifest_sha256,
                _path_stat_identity(generation),
                _path_stat_identity(generation / "manifest.json"),
            )
        )
    return tuple(identities)


def runtime_reference_identity(
    cache_root: Path,
    reference: GenerationReference,
    *,
    tool_lock_sha256: str,
    rules_lock_sha256: str,
) -> tuple[Any, ...]:
    """Invalidate a read-only proof for one exact immutable generation.

    Active and previous-good references are intentionally independent. A change
    to the rollback pointer must not invalidate an unchanged active generation.
    The caller also checks that this reference is still selected by the pointer.
    """
    root = _secure_directory(cache_root, "tool cache root")
    generations = _secure_directory(root / "generations", "cache generations")
    generation = generations / reference.generation_id
    return (
        str(root), tool_lock_sha256, rules_lock_sha256,
        reference.generation_id, reference.manifest_sha256,
        # Adding an unrelated generation changes the parent's timestamps, not
        # this proof. Replacement or permission/type changes still invalidate.
        _path_stat_identity(generations)[:3],
        _path_stat_identity(generation),
        _path_stat_identity(generation / "manifest.json"),
    )


def clear_runtime_generation_cache() -> None:
    """Clear the process-local scanner validation cache (primarily for tests)."""

    with _RUNTIME_GENERATION_CACHE_LOCK:
        _RUNTIME_GENERATION_CACHE.clear()


def resolve_active_generation_cached(
    cache_root: Path,
    *,
    tool_lock_sha256: str,
    rules_lock_sha256: str,
    checkpoint: Callable[[], object] | None = None,
) -> ResolvedGeneration:
    """Resolve once per immutable pointer identity for scanner read paths.

    The updater and qualification paths continue to call
    :func:`resolve_active_generation` directly and therefore always perform a
    full tree validation. Scanner cache mounts are read-only and published
    generation trees are immutable; pointer content/metadata, lock digests,
    and referenced generation/manifest identities invalidate this cache.
    """

    root_key = str(cache_root.resolve(strict=False))
    for _attempt in range(2):
        try:
            before = _runtime_generation_identity(
                cache_root,
                tool_lock_sha256=tool_lock_sha256,
                rules_lock_sha256=rules_lock_sha256,
            )
        except CacheValidationError:
            # Missing/unsafe pointer states are cheap and must be re-evaluated
            # on each request so a fresh installation becomes visible.
            return resolve_active_generation(cache_root, checkpoint=checkpoint)
        with _RUNTIME_GENERATION_CACHE_LOCK:
            cached = _RUNTIME_GENERATION_CACHE.get(root_key)
            if cached is not None and cached.identity == before:
                return cached.resolved
            resolved = resolve_active_generation(cache_root, checkpoint=checkpoint)
            try:
                after = _runtime_generation_identity(
                    cache_root,
                    tool_lock_sha256=tool_lock_sha256,
                    rules_lock_sha256=rules_lock_sha256,
                )
            except CacheValidationError:
                continue
            if before != after:
                continue
            _RUNTIME_GENERATION_CACHE[root_key] = _RuntimeGenerationCacheEntry(
                identity=after,
                resolved=resolved,
            )
            return resolved
    return ResolvedGeneration(
        state="invalid",
        generation=None,
        pointer=None,
        error_code="cache_pointer_changed_during_validation",
    )


def resolve_active_generation(
    cache_root: Path,
    *,
    checkpoint: Callable[[], object] | None = None,
    progress: Callable[[str, int, int, int, int], object] | None = None,
) -> ResolvedGeneration:
    if checkpoint is not None:
        checkpoint()
    try:
        pointer = load_active_pointer(cache_root)
    except CacheValidationError as exc:
        missing = "missing" in str(exc)
        return ResolvedGeneration(
            state="unavailable" if missing else "invalid",
            generation=None,
            pointer=None,
            error_code="cache_pointer_missing" if missing else "cache_pointer_invalid",
        )
    try:
        generation = validate_generation(
            cache_root,
            pointer.active.generation_id,
            expected_manifest_sha256=pointer.active.manifest_sha256,
            checkpoint=checkpoint,
            progress=progress,
        )
        return ResolvedGeneration(state="ready", generation=generation, pointer=pointer)
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            raise
    if pointer.previous_good is not None:
        try:
            generation = validate_generation(
                cache_root,
                pointer.previous_good.generation_id,
                expected_manifest_sha256=pointer.previous_good.manifest_sha256,
                checkpoint=checkpoint,
                progress=progress,
            )
            return ResolvedGeneration(
                state="fallback",
                generation=generation,
                pointer=pointer,
                error_code="active_generation_invalid_using_previous_good",
            )
        except CacheValidationError as exc:
            if isinstance(exc, GrypeContentValidationError) and exc.retryable:
                raise
    return ResolvedGeneration(
        state="invalid",
        generation=None,
        pointer=pointer,
        error_code="active_and_previous_good_invalid",
    )


def resolve_runtime_components(
    cache_root: Path,
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    component_ids: Iterable[str],
) -> RuntimeComponentSnapshot:
    """Resolve an exact component set from one immutable active snapshot.

    Runtime adapters use this helper instead of mutable top-level cache paths.
    Every returned root is bound to both lock digests and its exact component
    receipt. One validated generation object is used for the entire mapping so
    activation racing this call cannot mix generations within a scan.
    """

    resolved = resolve_active_generation(cache_root)
    return runtime_components_from_resolved(
        resolved,
        tools,
        rules,
        component_ids,
    )


def runtime_components_from_resolved(
    resolved: ResolvedGeneration,
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    component_ids: Iterable[str],
    *,
    now: datetime | None = None,
) -> RuntimeComponentSnapshot:
    """Resolve component roots from the exact already-validated snapshot.

    Callers that evaluate readiness and start a scan use this helper so both
    decisions are derived from one immutable generation. It independently
    enforces freshness and rule-canary receipts instead of relying on a prior
    readiness calculation.
    """

    validate_lock_alignment(tools.value, rules.value)
    if resolved.state != "ready" or resolved.generation is None:
        raise CacheValidationError("active cache generation is unavailable or invalid")
    generation = resolved.generation
    if (
        generation.manifest.tool_lock_sha256 != tools.sha256
        or generation.manifest.rules_lock_sha256 != rules.sha256
    ):
        raise CacheValidationError("active cache generation was built from different locks")
    requirements = {
        requirement.id: (tool.id, requirement)
        for tool in tools.value.tools
        for requirement in tool.requirements
    }
    requested = list(component_ids)
    if requested != sorted(set(requested)):
        raise CacheValidationError("runtime component ids must be sorted and unique")
    receipts = {
        receipt.component_id: receipt for receipt in generation.manifest.components
    }
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    roots: dict[str, Path] = {}
    for component_id in requested:
        if component_id not in requirements:
            raise CacheValidationError("cache component is absent from the reviewed tool lock")
        tool_id, requirement = requirements[component_id]
        if requirement.provenance != "verified" or not requirement.cache_subpath:
            raise CacheValidationError("cache component provenance is not verified")
        receipt = receipts.get(component_id)
        if receipt is None:
            raise CacheValidationError("cache component is absent from the active generation")
        if (
            receipt.tool_id != tool_id
            or receipt.kind != requirement.kind
            or receipt.root != requirement.cache_subpath
            or receipt.immutable_ref != requirement.source.immutable_ref
            or receipt.source_sha256 != requirement.source.sha256
        ):
            raise CacheValidationError("cache component identity differs from its lock")
        updated_at = _parse_utc(receipt.updated_at, "updated_at")
        if updated_at > moment + timedelta(minutes=5):
            raise CacheValidationError("cache component timestamp is in the future")
        if requirement.max_age_seconds is not None and not receipt_matches_freshness_contract(
            receipt,
            requirement,
        ):
            raise CacheValidationError(
                "cache component freshness differs from its reviewed lock"
            )
        if (
            receipt.expires_at is not None
            and _parse_utc(receipt.expires_at, "expires_at") <= moment
        ):
            raise CacheValidationError("cache component freshness window expired")
        if requirement.kind == "rules":
            canary_failure = _rules_canary_readiness(
                [requirement],
                rules.value,
                generation,
            )
            if canary_failure is not None:
                raise CacheValidationError(
                    "cache rule canary receipts are not execution-ready"
                )
        root = generation.path / receipt.root
        try:
            resolved_root = root.resolve(strict=True)
            resolved_root.relative_to(generation.path)
        except (OSError, RuntimeError, ValueError) as exc:
            raise CacheValidationError("cache component root escapes its generation") from exc
        if root.is_symlink() or not resolved_root.is_dir():
            raise CacheValidationError("cache component root is not a real directory")
        roots[component_id] = resolved_root
    return RuntimeComponentSnapshot(
        generation_id=generation.manifest.generation_id,
        manifest_sha256=generation.manifest_sha256,
        roots=roots,
    )


def activate_generation(
    cache_root: Path,
    generation_id: str,
    operation_id: str,
    *,
    activated_at: str | None = None,
    checkpoint: Callable[[], object] | None = None,
    progress: Callable[[str, int, int, int, int], object] | None = None,
    prepare_publication: Callable[[ValidatedGeneration], str] | None = None,
    validate_replay: Callable[[ValidatedGeneration], object] | None = None,
) -> ActiveGenerationPointer:
    root = _secure_directory(cache_root, "tool cache root", create=True)
    previous_pointer: ActiveGenerationPointer | None = None
    pointer_path = root / "active.json"
    if pointer_path.exists() or pointer_path.is_symlink():
        previous_pointer = load_active_pointer(root)
        resolved = resolve_active_generation(root, checkpoint=checkpoint, progress=progress)
        if resolved.generation is None:
            raise CacheActivationError(
                "existing active state has no valid last-good generation"
            )
        previous_good = resolved.generation.reference
        revision = previous_pointer.revision + 1
    else:
        previous_good = None
        revision = 1

    # Validate the target only after any potentially long current-generation
    # walk. The resulting immutable reference is therefore the final
    # structural observation before the semantic publication guard and the
    # atomic active-pointer write.
    candidate = validate_generation(root, generation_id, checkpoint=checkpoint, progress=progress)
    if previous_pointer is not None:
        if (
            previous_pointer.active.generation_id == candidate.manifest.generation_id
            and previous_pointer.active.manifest_sha256 == candidate.manifest_sha256
        ):
            if previous_pointer.operation_id == operation_id:
                # No publication callback runs for a no-write replay. Its
                # caller can still require a fresh semantic check of the
                # generation just structurally validated above.
                if validate_replay is not None:
                    validate_replay(candidate)
                return previous_pointer
            # A distinct durable operation still needs a pointer receipt bound
            # to its own identity. Preserve last-good rather than pointing it
            # at the same active generation, which the pointer schema forbids.
            publication_timestamp = (
                prepare_publication(candidate)
                if prepare_publication is not None
                else activated_at or utc_timestamp()
            )
            payload = ActiveGenerationPointer(
                schema_version=SCHEMA_VERSION,
                revision=previous_pointer.revision + 1,
                active=candidate.reference,
                previous_good=previous_pointer.previous_good,
                activated_at=publication_timestamp,
                operation_id=operation_id,
            )
            _atomic_write_json(
                root,
                "active.json",
                payload.model_dump(mode="json"),
                MAX_ACTIVE_POINTER_BYTES,
            )
            return payload
    publication_timestamp = (
        prepare_publication(candidate)
        if prepare_publication is not None
        else activated_at or utc_timestamp()
    )
    payload = ActiveGenerationPointer(
        schema_version=SCHEMA_VERSION,
        revision=revision,
        active=candidate.reference,
        previous_good=previous_good,
        activated_at=publication_timestamp,
        operation_id=operation_id,
    )
    _atomic_write_json(
        root,
        "active.json",
        payload.model_dump(mode="json"),
        MAX_ACTIVE_POINTER_BYTES,
    )
    return payload


def rollback_to_previous_good(
    cache_root: Path,
    operation_id: str,
    *,
    activated_at: str | None = None,
    checkpoint: Callable[[], object] | None = None,
    progress: Callable[[str, int, int, int, int], object] | None = None,
    prepare_publication: Callable[[ValidatedGeneration], str] | None = None,
) -> ActiveGenerationPointer:
    root = _secure_directory(cache_root, "tool cache root")
    pointer = load_active_pointer(root)
    if pointer.previous_good is None:
        raise CacheActivationError("no previous-good generation is available")
    current: GenerationReference | None = None
    try:
        current = validate_generation(
            root,
            pointer.active.generation_id,
            expected_manifest_sha256=pointer.active.manifest_sha256,
            checkpoint=checkpoint,
            progress=progress,
        ).reference
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            raise
    # The rollback target must be the last full structural observation before
    # the semantic guard and pointer swap; validating it before the current
    # generation would leave an unbounded mutation window.
    previous = validate_generation(
        root,
        pointer.previous_good.generation_id,
        expected_manifest_sha256=pointer.previous_good.manifest_sha256,
        checkpoint=checkpoint,
        progress=progress,
    )
    publication_timestamp = (
        prepare_publication(previous)
        if prepare_publication is not None
        else activated_at or utc_timestamp()
    )
    payload = ActiveGenerationPointer(
        schema_version=SCHEMA_VERSION,
        revision=pointer.revision + 1,
        active=previous.reference,
        previous_good=current,
        activated_at=publication_timestamp,
        operation_id=operation_id,
    )
    _atomic_write_json(
        root,
        "active.json",
        payload.model_dump(mode="json"),
        MAX_ACTIVE_POINTER_BYTES,
    )
    return payload


class ReadinessFacet(_StrictModel):
    state: ReadinessState
    reason: str | None = Field(default=None, max_length=512)
    component_ids: list[str] = Field(max_length=32)

    @property
    def ready(self) -> bool:
        return self.state in {"ready", "not_required"}


class ToolReadiness(_StrictModel):
    tool_id: str
    binary: ReadinessFacet
    data: ReadinessFacet
    rules: ReadinessFacet
    execution: ReadinessFacet
    ready: bool


def _not_required() -> ReadinessFacet:
    return ReadinessFacet(state="not_required", reason=None, component_ids=[])


def _requirement_failure(
    requirements: list[ComponentRequirementLock],
) -> ReadinessFacet | None:
    unavailable = [item.id for item in requirements if item.provenance == "unavailable"]
    if unavailable:
        return ReadinessFacet(
            state="unavailable",
            reason="immutable component provenance is unavailable",
            component_ids=unavailable,
        )
    unattested = [item.id for item in requirements if item.provenance == "unattested"]
    if unattested:
        return ReadinessFacet(
            state="unattested",
            reason="component provenance is not attested",
            component_ids=unattested,
        )
    return None


def _component_readiness(
    requirements: list[ComponentRequirementLock],
    generation: ValidatedGeneration | None,
    *,
    expected_tool_id: str,
    expected_tool_lock_sha256: str,
    expected_rules_lock_sha256: str,
    now: datetime,
    verification: CacheVerification | None = None,
) -> ReadinessFacet:
    required = [item for item in requirements if item.required]
    if not required:
        return _not_required()
    provenance_failure = _requirement_failure(required)
    if provenance_failure is not None:
        return provenance_failure
    if generation is None:
        if verification is not None:
            state, reason = {
                "verifying": ("verifying", "scanner cache verification is in progress"),
                "timed_out": ("verification_timeout", "scanner cache verification timed out"),
                "failed": ("verification_failed", "scanner cache verification could not complete"),
            }[verification.state]
            return ReadinessFacet(state=state, reason=reason, component_ids=[item.id for item in required])
        return ReadinessFacet(
            state="unavailable",
            reason="no validated cache generation is selected for scanner execution",
            component_ids=[item.id for item in required],
        )
    manifest = generation.manifest
    if (
        manifest.tool_lock_sha256 != expected_tool_lock_sha256
        or manifest.rules_lock_sha256 != expected_rules_lock_sha256
    ):
        return ReadinessFacet(
            state="invalid",
            reason="cache generation was built from different scanner locks",
            component_ids=[item.id for item in required],
        )
    receipts = {item.component_id: item for item in manifest.components}
    missing = [item.id for item in required if item.id not in receipts]
    if missing:
        return ReadinessFacet(
            state="unavailable",
            reason="required components are absent from the cache generation",
            component_ids=missing,
        )
    stale: list[str] = []
    refresh_due = False
    invalid: list[str] = []
    for requirement in required:
        receipt = receipts[requirement.id]
        updated_at = _parse_utc(receipt.updated_at, "updated_at")
        if updated_at > now + timedelta(minutes=5):
            invalid.append(requirement.id)
            continue
        if (
            receipt.tool_id != expected_tool_id
            or receipt.kind != requirement.kind
            or receipt.root != requirement.cache_subpath
        ):
            invalid.append(requirement.id)
            continue
        if (
            receipt.immutable_ref != requirement.source.immutable_ref
            or receipt.source_sha256 != requirement.source.sha256
        ):
            invalid.append(requirement.id)
            continue
        if requirement.kind != "rules" and not receipt_matches_installed_content(
            receipt, requirement
        ):
            invalid.append(requirement.id)
            continue
        # Data/check canaries are authoritative in the tool lock. Rule canaries
        # are authoritative in the separately reviewed rules lock and are
        # validated by `_rules_canary_readiness` below. Comparing a rule receipt
        # to the tool lock's intentionally empty data-canary list rejects every
        # otherwise valid promoted rule generation.
        if requirement.kind != "rules":
            expected_canaries = sorted(requirement.canaries, key=lambda item: item.id)
            observed_canaries = sorted(
                receipt.canaries, key=lambda item: item.canary_id
            )
            if [item.id for item in expected_canaries] != [
                item.canary_id for item in observed_canaries
            ]:
                invalid.append(requirement.id)
                continue
            if any(
                observed.fixture_sha256 != expected.fixture_sha256
                or observed.output_sha256 != expected.output_sha256
                or observed.exit_code != expected.expected_exit_code
                or observed.result_count != expected.expected_result_count
                or observed.expected_ids != expected.expected_ids
                or observed.observed_ids != expected.expected_ids
                for expected, observed in zip(
                    expected_canaries, observed_canaries, strict=True
                )
            ):
                invalid.append(requirement.id)
                continue
        if requirement.max_age_seconds is not None and not receipt_matches_freshness_contract(
            receipt,
            requirement,
        ):
            invalid.append(requirement.id)
            continue
        if (
            receipt.expires_at is not None
            and _parse_utc(receipt.expires_at, "expires_at") <= now
        ):
            stale.append(requirement.id)
        if requirement.max_age_seconds is not None and now >= _parse_utc(
            receipt.updated_at, "updated_at"
        ) + timedelta(seconds=REVIEWED_DATA_REFRESH_WARNING_SECONDS):
            refresh_due = True
    if invalid:
        return ReadinessFacet(
            state="invalid",
            reason="cache component identity differs from its lock",
            component_ids=invalid,
        )
    if stale:
        return ReadinessFacet(
            state="stale",
            reason="cache component freshness window expired",
            component_ids=stale,
        )
    return ReadinessFacet(
        state="ready",
        reason=("Refresh due: reviewed data is at least 7 days old; newer vulnerabilities may be missing. "
                "Update reviewed source before the 14-day expiry." if refresh_due else None),
        component_ids=[item.id for item in required],
    )


def _rules_canary_readiness(
    rule_requirements: list[ComponentRequirementLock],
    rules: RulesLockFile,
    generation: ValidatedGeneration | None,
) -> ReadinessFacet | None:
    if not rule_requirements:
        return None
    receipts = (
        {item.component_id: item for item in generation.manifest.components}
        if generation is not None
        else {}
    )
    unattested: list[str] = []
    invalid: list[str] = []
    for requirement in rule_requirements:
        try:
            rule_set = rules.rule_set(requirement.id)
        except KeyError:
            invalid.append(requirement.id)
            continue
        expected = sorted(rule_set.canaries, key=lambda item: item.id)
        if not expected or any(item.state != "verified" or not item.output_sha256 for item in expected):
            unattested.append(requirement.id)
            continue
        receipt = receipts.get(requirement.id)
        if receipt is None:
            continue
        observed = sorted(receipt.canaries, key=lambda item: item.canary_id)
        if [item.id for item in expected] != [item.canary_id for item in observed]:
            invalid.append(requirement.id)
            continue
        for locked, actual in zip(expected, observed, strict=True):
            if (
                actual.fixture_sha256 != locked.fixture_sha256
                or actual.output_sha256 != locked.output_sha256
                or actual.exit_code != locked.expected_exit_code
                or actual.result_count != locked.expected_result_count
                or actual.expected_ids != sorted(locked.expected_rule_ids)
                or actual.observed_ids != sorted(locked.expected_rule_ids)
            ):
                invalid.append(requirement.id)
                break
    if invalid:
        return ReadinessFacet(
            state="invalid",
            reason="cache rule canary receipts differ from the rules lock",
            component_ids=sorted(set(invalid)),
        )
    if unattested:
        return ReadinessFacet(
            state="unattested",
            reason="rules canary evidence is not attested",
            component_ids=sorted(set(unattested)),
        )
    return None


def evaluate_tool_readiness(
    tools: LoadedDocument[ToolLockFile],
    rules: LoadedDocument[RulesLockFile],
    resolved: ResolvedGeneration,
    binary_statuses: Mapping[str, str],
    *,
    now: datetime | None = None,
) -> list[ToolReadiness]:
    validate_lock_alignment(tools.value, rules.value)
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    generation = resolved.generation
    result: list[ToolReadiness] = []
    rule_states = {item.id: item.state for item in rules.value.rule_sets}
    for tool in tools.value.tools:
        observed_binary = binary_statuses.get(tool.id, "missing")
        if tool.binary.provenance != "verified":
            binary = ReadinessFacet(
                state=tool.binary.provenance,
                reason="binary provenance is not verified",
                component_ids=[],
            )
        elif tool.binary.license.state != "verified":
            binary = ReadinessFacet(
                state=tool.binary.license.state,
                reason=(
                    "binary license evidence is unavailable"
                    if tool.binary.license.state == "unavailable"
                    else "binary license evidence is not attested"
                ),
                component_ids=[],
            )
        elif observed_binary == "ready":
            binary = ReadinessFacet(state="ready", reason=None, component_ids=[])
        else:
            binary = ReadinessFacet(
                state="unavailable" if observed_binary == "missing" else "invalid",
                reason=f"binary runtime status is {observed_binary}",
                component_ids=[],
            )

        data_requirements = [item for item in tool.requirements if item.kind != "rules"]
        rule_requirements = [item for item in tool.requirements if item.kind == "rules"]
        data = _component_readiness(
            data_requirements,
            generation,
            expected_tool_id=tool.id,
            expected_tool_lock_sha256=tools.sha256,
            expected_rules_lock_sha256=rules.sha256,
            now=moment,
            verification=resolved.verification,
        )
        rules_facet = _component_readiness(
            rule_requirements,
            generation,
            expected_tool_id=tool.id,
            expected_tool_lock_sha256=tools.sha256,
            expected_rules_lock_sha256=rules.sha256,
            now=moment,
            verification=resolved.verification,
        )
        if rule_requirements:
            unavailable_rules = [
                item.id
                for item in rule_requirements
                if rule_states.get(item.id) == "unavailable"
            ]
            unattested_rules = [
                item.id
                for item in rule_requirements
                if rule_states.get(item.id) == "unattested"
            ]
            unknown_rules = [
                item.id for item in rule_requirements if item.id not in rule_states
            ]
            if unavailable_rules:
                rules_facet = ReadinessFacet(
                    state="unavailable",
                    reason="rules provenance is unavailable in the rules lock",
                    component_ids=unavailable_rules,
                )
            elif unattested_rules:
                rules_facet = ReadinessFacet(
                    state="unattested",
                    reason="rules provenance is not attested in the rules lock",
                    component_ids=unattested_rules,
                )
            elif unknown_rules:
                rules_facet = ReadinessFacet(
                    state="invalid",
                    reason="rules requirement is absent from the rules lock",
                    component_ids=unknown_rules,
                )
            else:
                canary_failure = _rules_canary_readiness(
                    rule_requirements,
                    rules.value,
                    generation,
                )
                if canary_failure is not None:
                    rules_facet = canary_failure

        execution = ReadinessFacet(
            state=(
                "ready"
                if tool.adapter.offline_contract == "verified"
                else tool.adapter.offline_contract
            ),
            reason=(
                None
                if tool.adapter.offline_contract == "verified"
                else "offline execution contract is not attested"
            ),
            component_ids=[],
        )
        ready = all(facet.ready for facet in (binary, data, rules_facet, execution))
        result.append(
            ToolReadiness(
                tool_id=tool.id,
                binary=binary,
                data=data,
                rules=rules_facet,
                execution=execution,
                ready=ready,
            )
        )
    return result
