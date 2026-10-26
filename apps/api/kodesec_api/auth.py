from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import Runtime, get_db, get_runtime, get_runtime_settings
from .models import IdeEnrollment, RuntimeConfig
from .settings import Settings


SESSION_COOKIE = "kodesec_session"
BROWSER_SESSION_PREFIX = "auth.browser_session."
INSTALLATION_SECRET_BINDING_KEY = "auth.installation_secret_binding"
CAPABILITY_PREFIX = "auth.ide_slot."
BOOTSTRAP_MARKER = "auth.bootstrap_consumed"
IDE_CAPABILITY_ACTIVATION_TTL_SECONDS = 600
IDE_ENROLLMENT_WAIT_SECONDS = 20
_MAX_LIVE_IDE_ENROLLMENTS = 32
_IDE_ENROLLMENT_RETENTION_SECONDS = 24 * 60 * 60
DYNAMIC_BROWSER_PAIRING_KEY = "auth.browser_pairing_dynamic"
DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS = 600
_BROWSER_SESSION_TOKEN = re.compile(r"([A-Za-z0-9_-]{32})\.([0-9a-f]{64})\Z")
_BROWSER_MEMBER_ID = re.compile(r"kbm1_([A-Za-z0-9_-]{32})\Z")
_BROWSER_SESSION_RECORD_FIELDS = frozenset({
    "digest",
    "member_name",
    "member_kind",
    "created_at",
    "last_seen_at",
})
_BROWSER_SESSION_PRUNE_LIMIT = 64
IDE_BROWSER_INVITATION_PREFIX = "auth.browser_invitation.ide."
IDE_BROWSER_MEMBERSHIP_PREFIX = "auth.browser_membership.ide."
_IDE_BROWSER_INVITATION_TOKEN = re.compile(
    r"kbi1\.([A-Za-z0-9_-]{24})\.([A-Za-z0-9_-]{43})\Z"
)
_IDE_BROWSER_INVITATION_FIELDS = frozenset({
    "v",
    "verifier",
    "issuer_slot",
    "issuer_generation",
    "member_name",
    "purpose",
    "issued_at",
    "expires_at",
})
_IDE_BROWSER_MEMBERSHIP_FIELDS = frozenset({
    "v",
    "issuer_slot",
    "issuer_generation",
    "purpose",
    "member_id",
    "member_created_at",
})
_MAX_LIVE_IDE_BROWSER_INVITATIONS = 64
IDE_BROWSER_MEMBERSHIP_WAIT_SECONDS = 20
BROWSER_COOKIE_RETENTION_SECONDS = 400 * 24 * 60 * 60
_IDE_CLIENT_SLOT = re.compile(r"ks1_[A-Za-z0-9_-]{43}\Z")
_IDE_CAPABILITY_TOKEN = re.compile(
    r"kc1\.(ks1_[A-Za-z0-9_-]{43})\.([1-9][0-9]{0,9})\.([A-Za-z0-9_-]{43})\Z"
)
_IDE_INVALID_RECOVERY_TOKEN = re.compile(r"kir1_[0-9a-f]{64}\Z")
_IDE_ENROLLMENT_REQUEST_ID = re.compile(r"ker1_[A-Za-z0-9_-]{24}\Z")
_IDE_ENROLLMENT_VERIFICATION_CODE = re.compile(r"[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}\Z")
_IDE_ENROLLMENT_STATES = frozenset({"awaiting_approval", "approved", "rejected"})
_IDE_ENROLLMENT_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_IDE_SLOT_RECORD_FIELDS = frozenset({
    "v",
    "generation",
    "client_name",
    "active",
    "pending",
})
_IDE_ACTIVE_RECORD_FIELDS = frozenset({
    "generation",
    "digest",
    "client_name",
    "scopes",
    "activated_at",
    "revoked_at",
})
_IDE_PENDING_RECORD_FIELDS = frozenset({
    "generation",
    "digest",
    "client_name",
    "scopes",
    "issued_at",
    "activation_expires_at",
})
router = APIRouter(prefix="/v1/auth", tags=["authentication"])

# IDE capabilities are intentionally narrower than browser operator sessions.
# Keep these values action-oriented and map each one to an exact HTTP route in
# ``security.py``; adding a scope here alone must never grant an endpoint.
IDE_CAPABILITY_SCOPES: tuple[str, ...] = (
    "event:read",
    "finding:advisor",
    "finding:delete",
    "finding:lifecycle",
    "finding:read",
    "job:cancel",
    "job:read",
    "project:create",
    "project:resolve",
    "scan:create",
    "scan:read",
    "source:open-ack",
    "source:open-context",
    "source:snapshot",
    "browser:invite",
)


@dataclass(frozen=True)
class AuthContext:
    kind: str
    subject: str
    scopes: frozenset[str]
    session_nonce: str | None = None
    capability_generation: int | None = None


@dataclass(frozen=True)
class IdeStreamAuthorization:
    client_slot: str
    generation: int


class InstallationSecretBindingError(RuntimeError):
    """The configured installation secret does not own this database."""

    code = "installation_secret_binding_mismatch"
    action = "restore_original_installation_secret_or_matching_database"

    def __init__(self) -> None:
        super().__init__(
            "KODESEC_INSTALLATION_SECRET does not match this database. "
            "Restore the installation's original secret or restore the database "
            "that belongs to this generated runtime configuration; do not rotate "
            "the installation secret in place."
        )


class BootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bootstrap_token: str = Field(min_length=1, max_length=256)


class IdeEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_name: str = Field(min_length=1, max_length=120)
    client_slot: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    expected_active_generation: int = Field(strict=True, ge=0, le=2_147_483_647)

    @field_validator("client_name")
    @classmethod
    def validate_client_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("client_name must contain a recognizable name")
        if any(unicodedata.category(character) in {"Cc", "Cf"} for character in candidate):
            raise ValueError("client_name must not contain control or formatting characters")
        return candidate

    @field_validator("client_slot")
    @classmethod
    def validate_client_slot(cls, value: str) -> str:
        if _IDE_CLIENT_SLOT.fullmatch(value) is None:
            raise ValueError("client_slot must be one exact stable profile slot")
        return value


class IdeEnrollmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    request_id: str = Field(pattern=r"^ker1_[A-Za-z0-9_-]{24}$")
    state: Literal["awaiting_approval"] = "awaiting_approval"
    revision: Literal[1] = 1
    verification_code: str = Field(pattern=r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
    capability: str
    scopes: list[str]
    client_slot: str
    generation: int
    requested_at: datetime
    activation_expires_at: datetime


class IdeEnrollmentStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    request_id: str = Field(pattern=r"^ker1_[A-Za-z0-9_-]{24}$")
    state: Literal["awaiting_approval", "approved", "rejected", "expired"]
    revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    decision_at: datetime | None
    activation_expires_at: datetime


class IdeEnrollmentBrowserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    request_id: str = Field(pattern=r"^ker1_[A-Za-z0-9_-]{24}$")
    state: Literal["awaiting_approval"] = "awaiting_approval"
    revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    verification_code: str = Field(pattern=r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
    scopes: list[str]
    client_slot: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    client_name: str = Field(min_length=1, max_length=120)
    generation: int = Field(strict=True, ge=1, le=2_147_483_647)
    requested_at: datetime
    activation_expires_at: datetime


class IdeEnrollmentDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: Literal["approved", "rejected"]
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_generation: int = Field(strict=True, ge=1, le=2_147_483_647)


class IdeFirstOwnerClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    bootstrap_token: str = Field(min_length=1, max_length=256)
    expected_request_id: str = Field(pattern=r"^ker1_[A-Za-z0-9_-]{24}$")
    expected_revision: Literal[1] = 1
    expected_generation: int = Field(strict=True, ge=1, le=2_147_483_647)


class CapabilityActivationResponse(BaseModel):
    client_slot: str
    generation: int
    scopes: list[str]


class IdeBrowserInvitationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bootstrap_token: str = Field(pattern=r"^kbi1\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$")
    invitation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{24}$")
    purpose: Literal["integrated_dashboard", "extra_browser"]
    issued_at: datetime
    expires_at: datetime
    expires_in: Literal[600] = 600


class IdeBrowserInvitationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    purpose: Literal["integrated_dashboard", "extra_browser"]


class IdeBrowserInvitationPendingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    invitation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{24}$")
    status: Literal["pending"] = "pending"
    purpose: Literal["integrated_dashboard", "extra_browser"]
    expires_at: datetime


class IdeBrowserInvitationActiveResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    invitation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{24}$")
    status: Literal["active"] = "active"
    purpose: Literal["integrated_dashboard", "extra_browser"]
    member_id: str = Field(pattern=r"^kbm1_[A-Za-z0-9_-]{32}$")
    created_at: datetime


class IdeBrowserInvitationMissingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    invitation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{24}$")
    status: Literal["missing_or_revoked"] = "missing_or_revoked"


IdeBrowserInvitationMembershipResponse = (
    IdeBrowserInvitationPendingResponse
    | IdeBrowserInvitationActiveResponse
    | IdeBrowserInvitationMissingResponse
)


class BrowserMemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=r"^kbm1_[A-Za-z0-9_-]{32}$")
    member_name: str = Field(min_length=1, max_length=120)
    member_kind: Literal["owner", "browser", "ide_dashboard"]
    created_at: datetime
    last_seen_at: datetime
    current: bool


class BrowserMemberRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_created_at: datetime


class PendingCancellationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_pending_generation: int = Field(strict=True, ge=1, le=2_147_483_647)


class CapabilityRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_latest_generation: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_active_generation: int | None = Field(
        strict=True,
        ge=1,
        le=2_147_483_647,
    )
    expected_pending_generation: int | None = Field(
        strict=True,
        ge=1,
        le=2_147_483_647,
    )


class InvalidCapabilityRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    recovery_token: str = Field(strict=True, pattern=r"^kir1_[0-9a-f]{64}$")

    @field_validator("recovery_token")
    @classmethod
    def validate_recovery_token(cls, value: str) -> str:
        if _IDE_INVALID_RECOVERY_TOKEN.fullmatch(value) is None:
            raise ValueError("recovery_token must identify one exact invalid IDE slot state")
        return value


class IdeCapabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["valid"] = "valid"
    id: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    client_name: str = Field(min_length=1, max_length=120)
    scopes: list[str]
    created_at: datetime | None
    revoked: bool
    active: bool
    connected: bool
    active_generation: int | None = Field(strict=True, ge=1, le=2_147_483_647)
    latest_generation: int = Field(strict=True, ge=0, le=2_147_483_647)
    pending_activation: bool
    pending_generation: int | None = Field(strict=True, ge=1, le=2_147_483_647)
    pending_client_name: str | None = Field(default=None, max_length=120)
    pending_activation_expires_at: datetime | None
    source_open_available: bool
    source_open_disabled_reason: str | None
    invalid_recovery_token: None = None

    @model_validator(mode="after")
    def validate_state_relations(self) -> IdeCapabilityResponse:
        if self.active_generation is not None and self.active_generation > self.latest_generation:
            raise ValueError("active_generation cannot exceed latest_generation")
        if self.active and (
            self.active_generation is None
            or self.revoked
        ):
            raise ValueError("active state requires one unrevoked retained authority")
        if self.active_generation is None and (
            self.revoked
            or self.scopes
        ):
            raise ValueError("retained authority fields require active_generation")
        if self.connected and not self.active:
            raise ValueError("connected state requires active authority")
        if self.source_open_available and not (self.active and self.connected):
            raise ValueError("source opening requires one connected active authority")
        pending_values = (
            self.pending_generation,
            self.pending_client_name,
            self.pending_activation_expires_at,
        )
        if any(value is None for value in pending_values) != all(
            value is None for value in pending_values
        ):
            raise ValueError("pending authority fields must be present or absent together")
        if self.pending_generation is not None and self.pending_generation > self.latest_generation:
            raise ValueError("pending_generation cannot exceed latest_generation")
        if self.pending_activation and self.pending_generation is None:
            raise ValueError("pending activation requires a pending authority")
        return self


class InvalidIdeCapabilityResponse(BaseModel):
    """Redacted invalid slot state with only its stable ID and exact CAS token."""

    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["invalid"] = "invalid"
    id: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    client_name: Literal["Invalid IDE client record"] = "Invalid IDE client record"
    scopes: list[str] = Field(default_factory=list, max_length=0)
    created_at: None = None
    revoked: Literal[False] = False
    active: Literal[False] = False
    connected: Literal[False] = False
    active_generation: None = None
    latest_generation: None = None
    pending_activation: Literal[False] = False
    pending_generation: None = None
    pending_client_name: None = None
    pending_activation_expires_at: None = None
    source_open_available: Literal[False] = False
    source_open_disabled_reason: Literal[
        "This IDE client record is invalid or not active."
    ] = "This IDE client record is invalid or not active."
    invalid_recovery_token: str = Field(pattern=r"^kir1_[0-9a-f]{64}$")


class InvalidCapabilityRecoveryResponse(BaseModel):
    recovered: Literal[True] = True


class BrowserPairingTokenIssueResponse(BaseModel):
    bootstrap_token: str
    issued_at: datetime
    expires_at: datetime
    expires_in: int


@dataclass(frozen=True)
class _DynamicOneTimeCredentialSpec:
    state_key: str
    prefix: str
    mac_purpose: str
    code_prefix: str
    state_invalid_code: str
    action: str
    label: str
    ttl_seconds: int = 600


_BROWSER_PAIRING_SPEC = _DynamicOneTimeCredentialSpec(
    state_key=DYNAMIC_BROWSER_PAIRING_KEY,
    prefix="kb1",
    mac_purpose="browser-dynamic-pairing",
    code_prefix="browser_pairing_token",
    state_invalid_code="browser_pairing_state_invalid",
    action="obtain_new_browser_pairing_token",
    label="browser pairing key",
    ttl_seconds=DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _mac(settings: Settings, purpose: str, value: str) -> str:
    message = f"{purpose}\0{value}".encode("utf-8")
    return hmac.new(settings.installation_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _token_matches(presented: str, expected: str) -> bool:
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _installation_secret_fingerprint(settings: Settings) -> str:
    return _mac(
        settings,
        "installation-secret-binding",
        "lomo-kodesec-runtime-config-v1",
    )


def enforce_installation_secret_binding(db: Session, settings: Settings) -> None:
    """Bind durable HMAC-backed authority to one generated installation secret."""

    expected = _installation_secret_fingerprint(settings)
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == INSTALLATION_SECRET_BINDING_KEY)
        .with_for_update()
    )
    if row is None:
        db.add(RuntimeConfig(key=INSTALLATION_SECRET_BINDING_KEY, value=expected))
        db.commit()
        return
    if not hmac.compare_digest(row.value, expected):
        db.rollback()
        raise InstallationSecretBindingError()
    db.rollback()


def _stage_one_time_token(db: Session, marker_key: str, presented: str, expected: str, settings: Settings) -> None:
    if not _token_matches(presented, expected):
        raise HTTPException(401, "invalid one-time credential")
    digest = _mac(settings, marker_key, expected)
    marker = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == marker_key)
        .with_for_update()
    )
    if marker is not None and hmac.compare_digest(marker.value, digest):
        raise HTTPException(409, "one-time credential already consumed")
    if marker is None:
        marker = RuntimeConfig(key=marker_key, value=digest)
    else:
        marker.value = digest
        marker.updated_at = _utcnow()
    db.add(marker)


def _commit_one_time_transaction(
    db: Session,
    *,
    conflict: Callable[[], HTTPException] | None = None,
) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if conflict is not None:
            raise conflict() from exc
        raise HTTPException(409, "one-time credential already consumed") from exc


def _dynamic_credential_problem(
    spec: _DynamicOneTimeCredentialSpec,
    status_code: int,
    problem: str,
    message: str,
) -> HTTPException:
    return HTTPException(
        status_code,
        {
            "code": spec.state_invalid_code if problem == "state_invalid" else f"{spec.code_prefix}_{problem}",
            "message": message,
            "action": spec.action,
        },
    )


def _browser_pairing_token_consumed() -> HTTPException:
    return _dynamic_credential_problem(
        _BROWSER_PAIRING_SPEC,
        409,
        "consumed",
        "The one-time browser pairing key was already used.",
    )


def _issue_dynamic_one_time_credential(
    db: Session,
    settings: Settings,
    spec: _DynamicOneTimeCredentialSpec,
    *,
    now: datetime | None = None,
) -> tuple[str, datetime, datetime]:
    issued_at = now or _utcnow()
    expires_at = issued_at + timedelta(seconds=spec.ttl_seconds)
    token = f"{spec.prefix}.{secrets.token_urlsafe(32)}"
    record = {
        "v": 1,
        "verifier": _mac(settings, spec.mac_purpose, token),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "used_at": None,
    }
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == spec.state_key)
        .with_for_update()
    )
    serialized = json.dumps(record, separators=(",", ":"), sort_keys=True)
    if row is None:
        row = RuntimeConfig(key=spec.state_key, value=serialized)
    else:
        # Replacing the sole verifier invalidates any prior unused dynamic
        # pairing value without retaining that value or its plaintext history.
        row.value = serialized
        row.updated_at = issued_at
    db.add(row)
    return token, issued_at, expires_at


def _stage_dynamic_one_time_credential(
    db: Session,
    presented: str,
    settings: Settings,
    spec: _DynamicOneTimeCredentialSpec,
    *,
    now: datetime | None = None,
) -> None:
    if re.fullmatch(rf"{re.escape(spec.prefix)}\.[A-Za-z0-9_-]{{43}}\Z", presented) is None:
        raise _dynamic_credential_problem(
            spec,
            422,
            "invalid",
            f"The {spec.label} format is invalid.",
        )
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == spec.state_key)
        .with_for_update()
    )
    if row is None:
        raise _dynamic_credential_problem(
            spec,
            409,
            "unavailable",
            f"No current {spec.label} exists for this installation.",
        )
    try:
        record: dict[str, Any] = json.loads(row.value)
        if set(record) != {"v", "verifier", "issued_at", "expires_at", "used_at"}:
            raise ValueError("unexpected pairing state fields")
        issued_at = _record_time(record, "issued_at")
        expires_at = _record_time(record, "expires_at")
        if (
            type(record["v"]) is not int
            or record["v"] != 1
            or re.fullmatch(r"[0-9a-f]{64}", str(record["verifier"])) is None
            or expires_at <= issued_at
            or (
                record["used_at"] is not None
                and _record_time(record, "used_at") < issued_at
            )
        ):
            raise ValueError("invalid pairing state")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise _dynamic_credential_problem(
            spec,
            409,
            "state_invalid",
            f"The stored {spec.label} state is invalid and cannot create authority.",
        ) from None
    if not hmac.compare_digest(
        str(record.get("verifier", "")),
        _mac(settings, spec.mac_purpose, presented),
    ):
        raise _dynamic_credential_problem(
            spec,
            409,
            "superseded",
            f"This {spec.label} is no longer current because a newer key was generated.",
        )
    if record.get("used_at") is not None:
        raise _dynamic_credential_problem(
            spec,
            409,
            "consumed",
            f"The one-time {spec.label} was already used.",
        )
    consumed_at = now or _utcnow()
    if expires_at <= consumed_at:
        raise _dynamic_credential_problem(
            spec,
            410,
            "expired",
            f"The one-time {spec.label} expired before it was used.",
        )
    record["used_at"] = consumed_at.isoformat()
    row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
    row.updated_at = consumed_at
    db.add(row)


def issue_dynamic_browser_pairing_token(
    db: Session,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> tuple[str, datetime, datetime]:
    return _issue_dynamic_one_time_credential(db, settings, _BROWSER_PAIRING_SPEC, now=now)


def _ide_browser_invitation_problem(
    status_code: int,
    code: str,
    message: str,
    action: str,
) -> HTTPException:
    return HTTPException(
        status_code,
        {"code": code, "message": message, "action": action},
    )


def _ide_browser_invitation_key(invitation_id: str) -> str:
    return f"{IDE_BROWSER_INVITATION_PREFIX}{invitation_id}"


def _ide_browser_membership_key(invitation_id: str) -> str:
    return f"{IDE_BROWSER_MEMBERSHIP_PREFIX}{invitation_id}"


def _ide_browser_invitation_subject(invitation_id: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]{24}", invitation_id) is None:
        raise ValueError("invalid IDE browser invitation identity")
    return f"ide-browser-invitation:{invitation_id}"


def _valid_browser_member_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 120
        and value == value.strip()
        and not any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    )


def _parse_ide_browser_invitation_record(row: RuntimeConfig) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(row.value)
    issued_at = _record_time(record, "issued_at")
    expires_at = _record_time(record, "expires_at")
    if (
        set(record) != _IDE_BROWSER_INVITATION_FIELDS
        or type(record["v"]) is not int
        or record["v"] != 1
        or re.fullmatch(r"[0-9a-f]{64}", str(record["verifier"])) is None
        or _IDE_CLIENT_SLOT.fullmatch(str(record["issuer_slot"])) is None
        or type(record["issuer_generation"]) is not int
        or not 1 <= record["issuer_generation"] <= 2_147_483_647
        or not _valid_browser_member_name(record["member_name"])
        or record["purpose"] not in {"integrated_dashboard", "extra_browser"}
        or expires_at - issued_at
        != timedelta(seconds=DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS)
    ):
        raise ValueError("invalid IDE browser invitation state")
    return record


def _parse_ide_browser_membership_record(row: RuntimeConfig) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(row.value)
    member_created_at = _record_time(record, "member_created_at")
    if (
        set(record) != _IDE_BROWSER_MEMBERSHIP_FIELDS
        or type(record["v"]) is not int
        or record["v"] != 1
        or _IDE_CLIENT_SLOT.fullmatch(str(record["issuer_slot"])) is None
        or type(record["issuer_generation"]) is not int
        or not 1 <= record["issuer_generation"] <= 2_147_483_647
        or record["purpose"] not in {"integrated_dashboard", "extra_browser"}
        or _BROWSER_MEMBER_ID.fullmatch(str(record["member_id"])) is None
        or member_created_at.tzinfo is None
    ):
        raise ValueError("invalid IDE browser membership state")
    return record


def issue_ide_browser_invitation(
    db: Session,
    settings: Settings,
    context: AuthContext,
    purpose: Literal["integrated_dashboard", "extra_browser"],
    *,
    now: datetime | None = None,
) -> tuple[str, str, datetime, datetime]:
    if (
        context.kind != "ide"
        or _IDE_CLIENT_SLOT.fullmatch(context.subject) is None
        or context.capability_generation is None
    ):
        raise HTTPException(403, "active IDE capability required")
    issued_at = (now or _utcnow()).astimezone(timezone.utc)
    expires_at = issued_at + timedelta(seconds=DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS)
    issuer = active_ide_capability_record(db, context.subject, for_update=True)
    if issuer is None or issuer["generation"] != context.capability_generation:
        db.rollback()
        raise HTTPException(401, "active IDE capability required")
    db.execute(
        delete(RuntimeConfig).where(
            RuntimeConfig.key.like(f"{IDE_BROWSER_INVITATION_PREFIX}%"),
            RuntimeConfig.updated_at <= issued_at - timedelta(
                seconds=DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS
            ),
        )
    )
    live_count = db.scalar(
        select(func.count()).select_from(RuntimeConfig).where(
            RuntimeConfig.key.like(f"{IDE_BROWSER_INVITATION_PREFIX}%")
        )
    ) or 0
    if live_count >= _MAX_LIVE_IDE_BROWSER_INVITATIONS:
        db.rollback()
        raise _ide_browser_invitation_problem(
            429,
            "ide_browser_invitation_limit_reached",
            "Too many unconsumed browser invitations are active for this installation.",
            "wait_for_browser_invitation_expiry",
        )
    invitation_id = secrets.token_urlsafe(18)
    secret = secrets.token_urlsafe(32)
    token = f"kbi1.{invitation_id}.{secret}"
    member_name = (
        f"{issuer['client_name']} integrated dashboard"
        if purpose == "integrated_dashboard"
        else f"Additional browser from {issuer['client_name']}"
    )
    if len(member_name) > 120:
        member_name = member_name[:120].rstrip()
    record = {
        "v": 1,
        "verifier": _mac(settings, "ide-browser-invitation", token),
        "issuer_slot": context.subject,
        "issuer_generation": context.capability_generation,
        "member_name": member_name,
        "purpose": purpose,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    db.add(RuntimeConfig(
        key=_ide_browser_invitation_key(invitation_id),
        value=json.dumps(record, separators=(",", ":"), sort_keys=True),
    ))
    return invitation_id, token, issued_at, expires_at


def _stage_ide_browser_invitation(
    db: Session,
    presented: str,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> tuple[str, str, Literal["integrated_dashboard", "extra_browser"]]:
    match = _IDE_BROWSER_INVITATION_TOKEN.fullmatch(presented)
    if match is None:
        raise _ide_browser_invitation_problem(
            422,
            "ide_browser_invitation_invalid",
            "The one-time IDE browser invitation format is invalid.",
            "add_browser_from_paired_ide",
        )
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _ide_browser_invitation_key(match.group(1)))
        .with_for_update()
    )
    if row is None:
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_unavailable",
            "This one-time IDE browser invitation is not available.",
            "add_browser_from_paired_ide",
        )
    consumed_at = (now or _utcnow()).astimezone(timezone.utc)
    try:
        record = _parse_ide_browser_invitation_record(row)
        issued_at = _record_time(record, "issued_at")
        expires_at = _record_time(record, "expires_at")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_state_invalid",
            "The stored IDE browser invitation is invalid and cannot create browser authority.",
            "review_paired_ide_clients",
        ) from None
    if not hmac.compare_digest(
        str(record["verifier"]),
        _mac(settings, "ide-browser-invitation", presented),
    ):
        raise _ide_browser_invitation_problem(
            401,
            "ide_browser_invitation_invalid",
            "The one-time IDE browser invitation is invalid.",
            "add_browser_from_paired_ide",
        )
    if expires_at <= consumed_at:
        raise _ide_browser_invitation_problem(
            410,
            "ide_browser_invitation_expired",
            "The one-time IDE browser invitation expired before it was used.",
            "add_browser_from_paired_ide",
        )
    issuer = active_ide_capability_record(db, str(record["issuer_slot"]), for_update=True)
    if issuer is None or issuer["generation"] != record["issuer_generation"]:
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_issuer_revoked",
            "The VS Code profile that created this browser invitation is no longer authorized.",
            "pair_extension",
        )
    return match.group(1), str(record["member_name"]), record["purpose"]


def _stage_browser_bootstrap_credential(
    db: Session,
    presented: str,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> tuple[
    Callable[[], HTTPException] | None,
    str,
    Literal["owner", "browser", "ide_dashboard"],
    str | None,
    Literal["integrated_dashboard", "extra_browser"] | None,
]:
    if _token_matches(presented, settings.bootstrap_token):
        _stage_one_time_token(db, BOOTSTRAP_MARKER, presented, settings.bootstrap_token, settings)
        return None, "Installation owner browser", "owner", None, None
    if presented.startswith(f"{_BROWSER_PAIRING_SPEC.prefix}."):
        _stage_dynamic_one_time_credential(db, presented, settings, _BROWSER_PAIRING_SPEC, now=now)
        return _browser_pairing_token_consumed, "Local browser", "browser", None, None
    if presented.startswith("kbi1."):
        invitation_id, member_name, purpose = _stage_ide_browser_invitation(
            db,
            presented,
            settings,
            now=now,
        )
        member_kind: Literal["browser", "ide_dashboard"] = (
            "ide_dashboard" if purpose == "integrated_dashboard" else "browser"
        )
        return None, member_name, member_kind, invitation_id, purpose
    _stage_one_time_token(db, BOOTSTRAP_MARKER, presented, settings.bootstrap_token, settings)
    return None, "Installation owner browser", "owner", None, None


def _browser_session_key(session_id: str) -> str:
    return f"{BROWSER_SESSION_PREFIX}{session_id}"


def _browser_session_id(token: str) -> str | None:
    match = _BROWSER_SESSION_TOKEN.fullmatch(token)
    return match.group(1) if match is not None else None


def _browser_member_id(session_id: str) -> str:
    return f"kbm1_{session_id}"


def _browser_member_session_id(member_id: str) -> str | None:
    match = _BROWSER_MEMBER_ID.fullmatch(member_id)
    return match.group(1) if match is not None else None


def _record_time(record: dict[str, Any], field: str) -> datetime:
    value = datetime.fromisoformat(str(record[field]))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _browser_member_metadata(
    row: RuntimeConfig,
    now: datetime,
) -> dict[str, Any] | None:
    try:
        record: dict[str, Any] = json.loads(row.value)
        if set(record) != _BROWSER_SESSION_RECORD_FIELDS:
            return None
        created_at = _record_time(record, "created_at")
        last_seen_at = _record_time(record, "last_seen_at")
        if (
            not _valid_browser_member_name(record["member_name"])
            or record["member_kind"] not in {"owner", "browser", "ide_dashboard"}
            or re.fullmatch(r"[0-9a-f]{64}", str(record["digest"])) is None
            or created_at > now + timedelta(seconds=30)
            or last_seen_at < created_at
            or last_seen_at > now + timedelta(seconds=30)
        ):
            return None
        return record
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def _browser_session_record(
    row: RuntimeConfig,
    token: str,
    settings: Settings,
    now: datetime,
) -> dict[str, Any] | None:
    record = _browser_member_metadata(row, now)
    if record is None or not hmac.compare_digest(
        str(record["digest"]),
        _mac(settings, "browser-session-verifier", token),
    ):
        return None
    return record


def _prune_browser_sessions(
    db: Session,
    now: datetime,
    *,
    limit: int = _BROWSER_SESSION_PRUNE_LIMIT,
) -> None:
    rows = list(db.scalars(
        select(RuntimeConfig)
        .where(RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%"))
        .order_by(RuntimeConfig.updated_at.asc(), RuntimeConfig.key.asc())
        .limit(limit)
    ))
    for row in rows:
        if _browser_member_metadata(row, now) is None:
            session_id = row.key.removeprefix(BROWSER_SESSION_PREFIX)
            if re.fullmatch(r"[A-Za-z0-9_-]{32}", session_id) is not None:
                _delete_browser_membership_receipts(db, _browser_member_id(session_id))
            db.delete(row)


def issue_browser_session(
    db: Session,
    settings: Settings,
    *,
    member_name: str = "Local browser",
    member_kind: Literal["owner", "browser", "ide_dashboard"] = "browser",
    now: datetime | None = None,
) -> tuple[str, str, int]:
    issued_at = (now or _utcnow()).astimezone(timezone.utc)
    if not _valid_browser_member_name(member_name):
        raise ValueError("browser member name is invalid")
    session_id = secrets.token_urlsafe(24)
    token = f"{session_id}.{secrets.token_hex(32)}"
    recognizable_name = f"{member_name[:108].rstrip()} · {session_id[-8:]}"
    record = {
        "digest": _mac(settings, "browser-session-verifier", token),
        "member_name": recognizable_name,
        "member_kind": member_kind,
        "created_at": issued_at.isoformat(),
        "last_seen_at": issued_at.isoformat(),
    }
    _prune_browser_sessions(db, issued_at)
    db.add(RuntimeConfig(
        key=_browser_session_key(session_id),
        value=json.dumps(record, separators=(",", ":"), sort_keys=True),
    ))
    return token, csrf_token(settings, session_id), BROWSER_COOKIE_RETENTION_SECONDS


def _finalize_ide_browser_invitation(
    db: Session,
    invitation_id: str,
    session_id: str,
) -> None:
    invitation = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _ide_browser_invitation_key(invitation_id))
        .with_for_update()
    )
    if invitation is None:
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_unavailable",
            "This one-time IDE browser invitation is not available.",
            "add_browser_from_paired_ide",
        )
    try:
        invitation_record = _parse_ide_browser_invitation_record(invitation)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_state_invalid",
            "The stored IDE browser invitation is invalid and cannot acknowledge browser authority.",
            "review_paired_ide_clients",
        ) from None
    db.flush()
    member = db.get(RuntimeConfig, _browser_session_key(session_id))
    checked_at = _utcnow()
    member_record = _browser_member_metadata(member, checked_at) if member is not None else None
    if member_record is None:
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_membership_unavailable",
            "The browser authority created from this invitation is not available.",
            "pair_integrated_browser_again",
        )
    membership_key = _ide_browser_membership_key(invitation_id)
    if db.get(RuntimeConfig, membership_key) is not None:
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_membership_conflict",
            "This browser invitation already owns a membership acknowledgement.",
            "review_browser_members",
        )
    db.add(RuntimeConfig(
        key=membership_key,
        value=json.dumps({
            "v": 1,
            "issuer_slot": invitation_record["issuer_slot"],
            "issuer_generation": invitation_record["issuer_generation"],
            "purpose": invitation_record["purpose"],
            "member_id": _browser_member_id(session_id),
            "member_created_at": _record_time(member_record, "created_at").isoformat(),
        }, separators=(",", ":"), sort_keys=True),
    ))
    db.delete(invitation)


def _delete_browser_membership_receipts(db: Session, member_id: str) -> None:
    """Delete only valid acknowledgements bound to one revoked browser member."""
    if _BROWSER_MEMBER_ID.fullmatch(member_id) is None:
        raise ValueError("invalid browser member identity")
    rows = list(db.scalars(
        select(RuntimeConfig)
        .where(RuntimeConfig.key.like(f"{IDE_BROWSER_MEMBERSHIP_PREFIX}%"))
        .with_for_update()
    ))
    for row in rows:
        try:
            record = _parse_ide_browser_membership_record(row)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
        if record["member_id"] == member_id:
            db.delete(row)


def _browser_invitation_membership_response(
    db: Session,
    context: AuthContext,
    invitation_id: str,
    *,
    now: datetime | None = None,
) -> IdeBrowserInvitationMembershipResponse:
    if re.fullmatch(r"[A-Za-z0-9_-]{24}", invitation_id) is None:
        raise HTTPException(404, "browser invitation not found")
    checked_at = (now or _utcnow()).astimezone(timezone.utc)
    membership = db.get(RuntimeConfig, _ide_browser_membership_key(invitation_id))
    if membership is not None:
        try:
            record = _parse_ide_browser_membership_record(membership)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise _ide_browser_invitation_problem(
                409,
                "ide_browser_membership_state_invalid",
                "The stored browser membership acknowledgement is invalid.",
                "review_browser_members",
            ) from None
        # A completed dashboard member outlives IDE revocation independently.
        # A newly approved generation of the same profile may reconcile that
        # acknowledgement, but cannot consume an older pending invitation.
        retained_dashboard = (
            record["purpose"] == "integrated_dashboard"
            and context.capability_generation is not None
            and record["issuer_generation"] < context.capability_generation
        )
        if record["issuer_slot"] != context.subject or not (
            record["issuer_generation"] == context.capability_generation
            or retained_dashboard
        ):
            raise HTTPException(404, "browser invitation not found")
        session_id = _browser_member_session_id(str(record["member_id"]))
        member = db.get(RuntimeConfig, _browser_session_key(session_id)) if session_id else None
        member_record = _browser_member_metadata(member, checked_at) if member is not None else None
        if (
            member_record is None
            or _record_time(member_record, "created_at")
            != _record_time(record, "member_created_at")
        ):
            return IdeBrowserInvitationMissingResponse(invitation_id=invitation_id)
        return IdeBrowserInvitationActiveResponse(
            invitation_id=invitation_id,
            purpose=record["purpose"],
            member_id=record["member_id"],
            created_at=_record_time(record, "member_created_at"),
        )
    invitation = db.get(RuntimeConfig, _ide_browser_invitation_key(invitation_id))
    if invitation is None:
        return IdeBrowserInvitationMissingResponse(invitation_id=invitation_id)
    try:
        record = _parse_ide_browser_invitation_record(invitation)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise _ide_browser_invitation_problem(
            409,
            "ide_browser_invitation_state_invalid",
            "The stored IDE browser invitation is invalid.",
            "review_paired_ide_clients",
        ) from None
    if (
        record["issuer_slot"] != context.subject
        or record["issuer_generation"] != context.capability_generation
    ):
        raise HTTPException(404, "browser invitation not found")
    expires_at = _record_time(record, "expires_at")
    if expires_at <= checked_at:
        return IdeBrowserInvitationMissingResponse(invitation_id=invitation_id)
    return IdeBrowserInvitationPendingResponse(
        invitation_id=invitation_id,
        purpose=record["purpose"],
        expires_at=expires_at,
    )


def validate_browser_session(
    token: str,
    db: Session,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> AuthContext | None:
    session_id = _browser_session_id(token)
    if session_id is None:
        return None
    checked_at = (now or _utcnow()).astimezone(timezone.utc)
    row = db.get(RuntimeConfig, _browser_session_key(session_id))
    if row is None or _browser_session_record(row, token, settings, checked_at) is None:
        return None
    return AuthContext(
        kind="browser",
        subject="local-browser",
        scopes=frozenset({"api:read", "api:write"}),
        session_nonce=session_id,
    )


def renew_browser_session(
    db: Session,
    token: str,
    context: AuthContext,
    settings: Settings,
    *,
    now: datetime | None = None,
    commit: bool = True,
) -> int:
    session_id = _browser_session_id(token)
    if session_id is None or session_id != context.session_nonce:
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed")
    renewed_at = (now or _utcnow()).astimezone(timezone.utc)
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _browser_session_key(session_id))
        .with_for_update()
    )
    record = _browser_session_record(row, token, settings, renewed_at) if row is not None else None
    if row is None or record is None:
        db.rollback()
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed")
    record["last_seen_at"] = renewed_at.isoformat()
    row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
    row.updated_at = renewed_at
    db.add(row)
    if commit:
        db.commit()
    return BROWSER_COOKIE_RETENTION_SECONDS


def revoke_browser_session(
    db: Session,
    token: str,
    context: AuthContext,
) -> None:
    session_id = _browser_session_id(token)
    if session_id is None or session_id != context.session_nonce:
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed")
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _browser_session_key(session_id))
        .with_for_update()
    )
    if row is None:
        db.rollback()
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed")
    try:
        record: dict[str, Any] = json.loads(row.value)
    except (TypeError, json.JSONDecodeError) as exc:
        db.rollback()
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed") from exc
    if set(record) != _BROWSER_SESSION_RECORD_FIELDS:
        db.rollback()
        raise HTTPException(401, "browser member is missing or revoked, or its local cookie was removed")
    _delete_browser_membership_receipts(db, _browser_member_id(session_id))
    db.delete(row)
    db.commit()


def csrf_token(settings: Settings, session_nonce: str) -> str:
    return _mac(settings, "csrf", session_nonce)


def validate_csrf(presented: str, context: AuthContext, settings: Settings) -> bool:
    if context.kind != "browser" or not context.session_nonce:
        return False
    return hmac.compare_digest(presented, csrf_token(settings, context.session_nonce))


def _capability_key(client_slot: str) -> str:
    return f"{CAPABILITY_PREFIX}{client_slot}"


def _invalid_ide_slot_recovery_token(
    settings: Settings,
    client_slot: str,
    raw_value: str,
) -> str:
    """Return a non-secret CAS token for one exact invalid slot value."""

    return "kir1_" + _mac(
        settings,
        "ide-invalid-slot-recovery",
        f"{client_slot}\0{raw_value}",
    )


def _ide_capability_problem(
    status_code: int,
    code: str,
    message: str,
    action: str,
) -> HTTPException:
    return HTTPException(
        status_code,
        {"code": code, "message": message, "action": action},
    )


def _ide_enrollment_problem(
    status_code: int,
    code: str,
    message: str,
    action: str,
) -> HTTPException:
    return HTTPException(
        status_code,
        {"code": code, "message": message, "action": action},
    )


def _database_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _ide_enrollment_subject(request_id: str) -> str:
    if _IDE_ENROLLMENT_REQUEST_ID.fullmatch(request_id) is None:
        raise ValueError("invalid IDE enrollment request identity")
    return f"ide-enrollment:{request_id}"


def _validate_ide_enrollment(row: IdeEnrollment) -> None:
    if (
        _IDE_ENROLLMENT_REQUEST_ID.fullmatch(row.request_id) is None
        or _IDE_CLIENT_SLOT.fullmatch(row.client_slot) is None
        or type(row.generation) is not int
        or not 1 <= row.generation <= 2_147_483_647
        or not _valid_stored_client_name(row.client_name)
        or _IDE_ENROLLMENT_VERIFICATION_CODE.fullmatch(row.verification_code) is None
        or row.scopes != list(IDE_CAPABILITY_SCOPES)
        or row.state not in _IDE_ENROLLMENT_STATES
        or type(row.revision) is not int
        or not 1 <= row.revision <= 2_147_483_647
    ):
        raise ValueError("invalid IDE enrollment state")
    requested_at = _database_utc(row.requested_at)
    expires_at = _database_utc(row.activation_expires_at)
    decision_at = _database_utc(row.decision_at) if row.decision_at is not None else None
    activated_at = _database_utc(row.activated_at) if row.activated_at is not None else None
    if (
        expires_at - requested_at != timedelta(seconds=IDE_CAPABILITY_ACTIVATION_TTL_SECONDS)
        or (row.state == "awaiting_approval") != (decision_at is None)
        or (decision_at is not None and not requested_at <= decision_at < expires_at)
        or (
            activated_at is not None
            and (
                row.state != "approved"
                or activated_at < (decision_at or requested_at)
                or activated_at >= expires_at
            )
        )
    ):
        raise ValueError("invalid IDE enrollment lifecycle")


def _ide_enrollment_effective_state(
    row: IdeEnrollment,
    *,
    now: datetime | None = None,
) -> Literal["awaiting_approval", "approved", "rejected", "expired"]:
    _validate_ide_enrollment(row)
    checked_at = (now or _utcnow()).astimezone(timezone.utc)
    if (
        row.activated_at is None
        and row.state != "rejected"
        and _database_utc(row.activation_expires_at) <= checked_at
    ):
        return "expired"
    if row.state == "awaiting_approval":
        return "awaiting_approval"
    if row.state == "approved":
        return "approved"
    return "rejected"


def _ide_enrollment_status_response(
    row: IdeEnrollment,
    *,
    now: datetime | None = None,
) -> IdeEnrollmentStatusResponse:
    return IdeEnrollmentStatusResponse(
        request_id=row.request_id,
        state=_ide_enrollment_effective_state(row, now=now),
        revision=row.revision,
        decision_at=_database_utc(row.decision_at) if row.decision_at is not None else None,
        activation_expires_at=_database_utc(row.activation_expires_at),
    )


def _locked_ide_enrollment(
    db: Session,
    *,
    client_slot: str,
    generation: int,
) -> IdeEnrollment | None:
    return db.scalar(
        select(IdeEnrollment)
        .where(
            IdeEnrollment.client_slot == client_slot,
            IdeEnrollment.generation == generation,
        )
        .with_for_update()
    )


def _reject_enrollment_sidecar(
    db: Session,
    *,
    client_slot: str,
    generation: int,
    changed_at: datetime,
) -> IdeEnrollment | None:
    enrollment = _locked_ide_enrollment(
        db,
        client_slot=client_slot,
        generation=generation,
    )
    if enrollment is None:
        return None
    try:
        _validate_ide_enrollment(enrollment)
    except ValueError:
        return enrollment
    if (
        enrollment.activated_at is None
        and enrollment.state != "rejected"
        and changed_at < _database_utc(enrollment.activation_expires_at)
    ):
        enrollment.state = "rejected"
        enrollment.decision_at = changed_at
        enrollment.revision += 1
        db.add(enrollment)
    return enrollment


def _parse_ide_capability_token(token: str) -> tuple[str, int] | None:
    match = _IDE_CAPABILITY_TOKEN.fullmatch(token)
    if match is None:
        return None
    generation = int(match.group(2))
    if generation > 2_147_483_647:
        return None
    return match.group(1), generation


def _parse_ide_slot_record(row: RuntimeConfig) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(row.value)
    if set(record) != _IDE_SLOT_RECORD_FIELDS:
        raise ValueError("unexpected IDE slot fields")
    if type(record["v"]) is not int or record["v"] != 1:
        raise ValueError("invalid IDE slot version")
    generation = record["generation"]
    if type(generation) is not int or not 0 <= generation <= 2_147_483_647:
        raise ValueError("invalid IDE slot generation")
    client_name = record["client_name"]
    if not _valid_stored_client_name(client_name):
        raise ValueError("invalid IDE slot client name")

    active = record["active"]
    if active is not None:
        if not isinstance(active, dict) or set(active) != _IDE_ACTIVE_RECORD_FIELDS:
            raise ValueError("invalid active IDE authority")
        active_generation = active["generation"]
        activated_at = _exact_record_time(active, "activated_at")
        revoked_at = (
            _exact_record_time(active, "revoked_at")
            if active["revoked_at"] is not None
            else None
        )
        if (
            type(active_generation) is not int
            or not 1 <= active_generation <= generation
            or not _valid_ide_digest(active["digest"])
            or active["scopes"] != list(IDE_CAPABILITY_SCOPES)
            or not _valid_stored_client_name(active["client_name"])
            or (revoked_at is not None and revoked_at < activated_at)
        ):
            raise ValueError("invalid active IDE authority")

    pending = record["pending"]
    if pending is not None:
        if not isinstance(pending, dict) or set(pending) != _IDE_PENDING_RECORD_FIELDS:
            raise ValueError("invalid pending IDE authority")
        pending_generation = pending["generation"]
        issued_at = _exact_record_time(pending, "issued_at")
        activation_expires_at = _exact_record_time(pending, "activation_expires_at")
        if (
            type(pending_generation) is not int
            or pending_generation != generation
            or not _valid_ide_digest(pending["digest"])
            or pending["scopes"] != list(IDE_CAPABILITY_SCOPES)
            or not _valid_stored_client_name(pending["client_name"])
            or activation_expires_at - issued_at != timedelta(seconds=IDE_CAPABILITY_ACTIVATION_TTL_SECONDS)
            or (active is not None and pending_generation <= active["generation"])
        ):
            raise ValueError("invalid pending IDE authority")

    if generation == 0 and (active is not None or pending is not None):
        raise ValueError("generation zero cannot own IDE authority")
    return record


def _valid_stored_client_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 120
        and value == value.strip()
        and not any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    )


def _valid_ide_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _exact_record_time(record: dict[str, Any], field: str) -> datetime:
    if not isinstance(record[field], str):
        raise ValueError(f"{field} must be one exact timestamp string")
    return _record_time(record, field)


def _serialize_ide_slot_record(record: dict[str, Any]) -> str:
    return json.dumps(record, separators=(",", ":"), sort_keys=True)


def _active_ide_record(
    record: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    active = record["active"]
    if (
        active is None
        or active["revoked_at"] is not None
    ):
        return None
    return active


def active_ide_capability_record(
    db: Session,
    capability_id: str,
    *,
    for_update: bool = False,
) -> dict[str, Any] | None:
    if _IDE_CLIENT_SLOT.fullmatch(capability_id) is None:
        return None
    statement = select(RuntimeConfig).where(
        RuntimeConfig.key == _capability_key(capability_id)
    )
    if for_update:
        statement = statement.with_for_update()
    row = db.scalar(statement)
    if row is None:
        return None
    try:
        return _active_ide_record(_parse_ide_slot_record(row))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def validate_ide_stream_authorization(
    authorization: IdeStreamAuthorization,
    db: Session,
    *,
    now: datetime | None = None,
) -> bool:
    """Revalidate an established bearer context without retaining its bearer."""

    if (
        _IDE_CLIENT_SLOT.fullmatch(authorization.client_slot) is None
        or type(authorization.generation) is not int
        or not 1 <= authorization.generation <= 2_147_483_647
    ):
        return False
    row = db.get(RuntimeConfig, _capability_key(authorization.client_slot))
    if row is None:
        return False
    try:
        record = _parse_ide_slot_record(row)
        active = record["active"]
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False
    return bool(
        active is not None
        and active["generation"] == authorization.generation
        and active["revoked_at"] is None
    )


def _capability_context(
    token: str,
    db: Session,
    settings: Settings,
    *,
    pending: bool,
    allow_active: bool = False,
) -> AuthContext | None:
    identity = _parse_ide_capability_token(token)
    if identity is None:
        return None
    client_slot, generation = identity
    row = db.get(RuntimeConfig, _capability_key(client_slot))
    if row is None:
        return None
    try:
        record = _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None
    expected_digest = _mac(settings, "ide-capability", token)
    if pending:
        candidate = record["pending"]
        if (
            candidate is not None
            and candidate["generation"] == generation
            and hmac.compare_digest(candidate["digest"], expected_digest)
        ):
            return AuthContext(
                kind="ide-pending",
                subject=client_slot,
                scopes=frozenset({"capability:activate-self", "capability:cancel-pending"}),
                capability_generation=generation,
            )
        if not allow_active:
            return None
    active = _active_ide_record(record)
    if (
        active is None
        or active["generation"] != generation
        or not hmac.compare_digest(active["digest"], expected_digest)
    ):
        return None
    return AuthContext(
        kind="ide",
        subject=client_slot,
        scopes=frozenset(IDE_CAPABILITY_SCOPES),
        capability_generation=generation,
    )


def validate_ide_capability(token: str, db: Session, settings: Settings) -> AuthContext | None:
    return _capability_context(token, db, settings, pending=False)


def validate_pending_ide_capability(
    token: str,
    db: Session,
    settings: Settings,
    *,
    allow_active: bool = False,
) -> AuthContext | None:
    return _capability_context(
        token,
        db,
        settings,
        pending=True,
        allow_active=allow_active,
    )


def _browser_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "browser":
        raise HTTPException(403, "browser session required")
    return context


def _ide_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "ide":
        raise HTTPException(403, "IDE capability required")
    return context


def _activating_ide_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind not in {"ide", "ide-pending"}:
        raise HTTPException(403, "pending IDE capability required")
    return context


def _pending_ide_context(request: Request) -> AuthContext:
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "ide-pending":
        raise HTTPException(403, "pending IDE capability required")
    return context


def _request_bearer(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "IDE capability required")
    return authorization[7:]


def _locked_ide_slot(db: Session, client_slot: str) -> RuntimeConfig | None:
    return db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _capability_key(client_slot))
        .with_for_update()
    )


def _notify_capability_revoked(request: Request, capability_id: str) -> None:
    # Notify matching established streams only after durable revocation.
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        broker.revoke_ide_slot(capability_id)


@router.post("/bootstrap")
def bootstrap(payload: BootstrapRequest, request: Request, response: Response, db: Session = Depends(get_db), settings: Settings = Depends(get_runtime_settings)) -> dict[str, Any]:
    conflict, member_name, member_kind, invitation_id, invitation_purpose = _stage_browser_bootstrap_credential(
        db,
        payload.bootstrap_token,
        settings,
    )
    retained_session = request.cookies.get(SESSION_COOKIE, "")
    retained_context = validate_browser_session(retained_session, db, settings)
    if invitation_purpose == "extra_browser" and retained_context is not None:
        db.rollback()
        raise _ide_browser_invitation_problem(
            409,
            "browser_already_paired",
            "This browser is already paired. Open the one-time pairing code in another browser or an unpaired browser profile.",
            "use_unpaired_browser_profile",
        )
    if retained_context is not None:
        ttl = renew_browser_session(
            db,
            retained_session,
            retained_context,
            settings,
            commit=False,
        )
        session = retained_session
        csrf = csrf_token(settings, retained_context.session_nonce or "")
        session_id = retained_context.session_nonce
    else:
        session, csrf, ttl = issue_browser_session(
            db,
            settings,
            member_name=member_name,
            member_kind=member_kind,
        )
        session_id = _browser_session_id(session)
    if session_id is None:
        db.rollback()
        raise HTTPException(409, "browser membership identity is unavailable")
    if invitation_id is not None:
        _finalize_ide_browser_invitation(db, invitation_id, session_id)
    _commit_one_time_transaction(db, conflict=conflict)
    if invitation_id is not None:
        from .events import EventWakeBroker

        broker = getattr(request.app.state, "event_wake_broker", None)
        if isinstance(broker, EventWakeBroker):
            broker.wake_subject(_ide_browser_invitation_subject(invitation_id))
    response.set_cookie(
        SESSION_COOKIE,
        session,
        max_age=ttl,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "csrf_token": csrf, "expires_in": ttl}


@router.get("/session")
def session(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_runtime_settings),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    context = _browser_context(request)
    token = request.cookies.get(SESSION_COOKIE, "")
    ttl = renew_browser_session(db, token, context, settings)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=ttl,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {
        "authenticated": True,
        "csrf_token": csrf_token(settings, context.session_nonce or ""),
        "expires_in": ttl,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    context: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    revoke_browser_session(
        db,
        request.cookies.get(SESSION_COOKIE, ""),
        context,
    )
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": False}


@router.post(
    "/ide/enrollments",
    response_model=IdeEnrollmentResponse,
    status_code=201,
)
def create_ide_enrollment(
    payload: IdeEnrollmentRequest,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> IdeEnrollmentResponse:
    """Create one browser-reviewed pending authority without a pasted secret."""

    now = _utcnow()
    # The installation binding is a mandatory singleton and provides one exact
    # cross-process lock for the bounded unauthenticated enrollment allocator.
    allocation_lock = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == INSTALLATION_SECRET_BINDING_KEY)
        .with_for_update()
    )
    if allocation_lock is None:
        db.rollback()
        raise _ide_enrollment_problem(
            503,
            "ide_enrollment_authority_unavailable",
            "The installation authority is not ready to enroll an IDE.",
            "retry_after_control_plane_ready",
        )
    row = _locked_ide_slot(db, payload.client_slot)
    if row is None:
        record: dict[str, Any] = {
            "v": 1,
            "generation": 0,
            "client_name": payload.client_name,
            "active": None,
            "pending": None,
        }
        row = RuntimeConfig(key=_capability_key(payload.client_slot), value="")
    else:
        try:
            record = _parse_ide_slot_record(row)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            db.rollback()
            raise _ide_enrollment_problem(
                409,
                "ide_enrollment_slot_state_invalid",
                "The stored IDE client slot is invalid and cannot create authority.",
                "review_paired_ide_clients",
            ) from None

    # Keep the shared lock order exact: installation allocator, target slot,
    # then enrollment sidecars. Decision, activation, cancellation, and revoke
    # also acquire the target slot before an enrollment row.
    db.execute(
        delete(IdeEnrollment).where(
            IdeEnrollment.activation_expires_at
            <= now - timedelta(seconds=_IDE_ENROLLMENT_RETENTION_SECONDS)
        )
    )
    live_count = db.scalar(
        select(func.count())
        .select_from(IdeEnrollment)
        .where(
            IdeEnrollment.state.in_(("awaiting_approval", "approved")),
            IdeEnrollment.activation_expires_at > now,
            IdeEnrollment.activated_at.is_(None),
        )
    ) or 0
    if live_count >= _MAX_LIVE_IDE_ENROLLMENTS:
        db.rollback()
        raise _ide_enrollment_problem(
            429,
            "ide_enrollment_limit_reached",
            "Too many IDE enrollment requests are waiting for review or activation.",
            "review_or_wait_for_pending_enrollments",
        )

    active = record["active"]
    active_generation = active["generation"] if active is not None else 0
    initial_or_pending_only_slot = active is None and payload.expected_active_generation == 0
    exact_retained_generation = (
        active is not None
        and payload.expected_active_generation == active_generation
    )
    explicitly_revoked_recovery = (
        active is not None
        and active["revoked_at"] is not None
        and payload.expected_active_generation == 0
    )
    if not (
        initial_or_pending_only_slot
        or exact_retained_generation
        or explicitly_revoked_recovery
    ):
        reset_required = (
            active is not None
            and active["revoked_at"] is None
            and payload.expected_active_generation == 0
        )
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_generation_conflict",
            (
                "This VS Code profile lost its local authority while the server still retains an IDE authority."
                if reset_required
                else "This VS Code profile no longer matches the active IDE authority generation."
            ),
            (
                "revoke_or_restore_profile_authority"
                if reset_required
                else "reload_profile_authority"
            ),
        )

    pending = record["pending"]
    if pending is not None:
        if _record_time(pending, "activation_expires_at") > now:
            enrollment = _locked_ide_enrollment(
                db,
                client_slot=payload.client_slot,
                generation=pending["generation"],
            )
            db.rollback()
            if enrollment is None:
                raise _ide_enrollment_problem(
                    409,
                    "ide_enrollment_sidecar_missing",
                    "The pending IDE authority has no review record and cannot be resumed safely.",
                    "review_paired_ide_clients",
                )
            raise _ide_enrollment_problem(
                409,
                "ide_enrollment_already_pending",
                "This VS Code profile already has an IDE enrollment waiting for review or activation.",
                "resume_pending_enrollment",
            )
        record["pending"] = None

    generation = record["generation"] + 1
    if generation > 2_147_483_647:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_generation_exhausted",
            "This IDE client slot cannot issue another authority generation.",
            "create_new_profile_slot",
        )
    secret = secrets.token_urlsafe(32)
    token = f"kc1.{payload.client_slot}.{generation}.{secret}"
    scopes = list(IDE_CAPABILITY_SCOPES)
    activation_expires_at = now + timedelta(seconds=IDE_CAPABILITY_ACTIVATION_TTL_SECONDS)
    record["generation"] = generation
    record["pending"] = {
        "generation": generation,
        "digest": _mac(settings, "ide-capability", token),
        "client_name": payload.client_name,
        "scopes": scopes,
        "issued_at": now.isoformat(),
        "activation_expires_at": activation_expires_at.isoformat(),
    }
    live_codes = set(db.scalars(
        select(IdeEnrollment.verification_code).where(
            IdeEnrollment.state == "awaiting_approval",
            IdeEnrollment.activation_expires_at > now,
        )
    ))
    verification_code = ""
    for _ in range(8):
        candidate = "".join(secrets.choice(_IDE_ENROLLMENT_CODE_ALPHABET) for _ in range(8))
        candidate = f"{candidate[:4]}-{candidate[4:]}"
        if candidate not in live_codes:
            verification_code = candidate
            break
    if not verification_code:
        db.rollback()
        raise _ide_enrollment_problem(
            503,
            "ide_enrollment_code_unavailable",
            "A distinct IDE verification code could not be allocated.",
            "retry_enrollment",
        )
    request_id = f"ker1_{secrets.token_urlsafe(18)}"
    enrollment = IdeEnrollment(
        request_id=request_id,
        client_slot=payload.client_slot,
        generation=generation,
        client_name=payload.client_name,
        verification_code=verification_code,
        scopes=scopes,
        state="awaiting_approval",
        revision=1,
        requested_at=now,
        activation_expires_at=activation_expires_at,
        decision_at=None,
        activated_at=None,
    )
    row.value = _serialize_ide_slot_record(record)
    row.updated_at = now
    db.add(row)
    db.add(enrollment)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_generation_conflict",
            "Another VS Code window changed this IDE client slot while enrollment was created.",
            "reload_profile_authority",
        ) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return IdeEnrollmentResponse(
        request_id=request_id,
        verification_code=verification_code,
        capability=token,
        scopes=scopes,
        client_slot=payload.client_slot,
        generation=generation,
        requested_at=now,
        activation_expires_at=activation_expires_at,
    )


def _current_ide_enrollment(
    db: Session,
    context: AuthContext,
) -> IdeEnrollment:
    if (
        context.kind not in {"ide", "ide-pending"}
        or _IDE_CLIENT_SLOT.fullmatch(context.subject) is None
        or context.capability_generation is None
    ):
        raise HTTPException(403, "IDE enrollment authority required")
    row = db.scalar(
        select(IdeEnrollment).where(
            IdeEnrollment.client_slot == context.subject,
            IdeEnrollment.generation == context.capability_generation,
        )
    )
    if row is None:
        raise _ide_enrollment_problem(
            404,
            "ide_enrollment_not_found",
            "The IDE enrollment review record is no longer available.",
            "start_new_enrollment",
        )
    try:
        _validate_ide_enrollment(row)
    except ValueError:
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_state_invalid",
            "The stored IDE enrollment review state is invalid.",
            "review_paired_ide_clients",
        ) from None
    return row


@router.get(
    "/ide/enrollments/current/wait",
    response_model=IdeEnrollmentStatusResponse,
)
async def wait_for_ide_enrollment_decision(
    request: Request,
    after_revision: int = Query(ge=0, le=2_147_483_647),
    context: AuthContext = Depends(_activating_ide_context),
    runtime: Runtime = Depends(get_runtime),
) -> IdeEnrollmentStatusResponse:
    """Long-wait on a durable enrollment revision, then re-read its DB state."""

    def read_status() -> IdeEnrollmentStatusResponse:
        with runtime.session_factory() as session:
            return _ide_enrollment_status_response(
                _current_ide_enrollment(session, context)
            )

    current = read_status()
    if current.revision > after_revision or current.state != "awaiting_approval":
        return current
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if not isinstance(broker, EventWakeBroker):
        raise _ide_enrollment_problem(
            503,
            "ide_enrollment_wake_unavailable",
            "IDE enrollment status notifications are not available.",
            "retry_enrollment_status",
        )
    # SQLite is used only by isolated API tests and has no cross-process wake;
    # its immediate durable read still validates the response contract.
    if runtime.engine.dialect.name != "postgresql":
        return read_status()
    try:
        subscription = await broker.subscribe(_ide_enrollment_subject(current.request_id))
    except RuntimeError as exc:
        reconciled = read_status()
        if reconciled.revision > after_revision or reconciled.state != "awaiting_approval":
            return reconciled
        raise _ide_enrollment_problem(
            503,
            "ide_enrollment_wake_unavailable",
            "IDE enrollment status notifications are not available.",
            "retry_enrollment_status",
        ) from exc
    try:
        reconciled = read_status()
        if reconciled.revision > after_revision or reconciled.state != "awaiting_approval":
            return reconciled
        try:
            await subscription.wait(timeout=IDE_ENROLLMENT_WAIT_SECONDS)
        except RuntimeError as exc:
            reconciled = read_status()
            if reconciled.revision > after_revision or reconciled.state != "awaiting_approval":
                return reconciled
            raise _ide_enrollment_problem(
                503,
                "ide_enrollment_wake_unavailable",
                "IDE enrollment status notifications are not available.",
                "retry_enrollment_status",
            ) from exc
        return read_status()
    finally:
        subscription.close()


@router.get(
    "/ide/enrollments",
    response_model=list[IdeEnrollmentBrowserResponse],
)
def list_pending_ide_enrollments(
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> list[IdeEnrollmentBrowserResponse]:
    now = _utcnow()
    rows = list(db.scalars(
        select(IdeEnrollment)
        .where(
            IdeEnrollment.state == "awaiting_approval",
            IdeEnrollment.activation_expires_at > now,
            IdeEnrollment.activated_at.is_(None),
        )
        .order_by(IdeEnrollment.requested_at.asc(), IdeEnrollment.request_id.asc())
    ))
    result: list[IdeEnrollmentBrowserResponse] = []
    for row in rows:
        try:
            _validate_ide_enrollment(row)
        except ValueError:
            raise _ide_enrollment_problem(
                409,
                "ide_enrollment_state_invalid",
                "A pending IDE enrollment review record is invalid.",
                "review_paired_ide_clients",
            ) from None
        result.append(IdeEnrollmentBrowserResponse(
            request_id=row.request_id,
            revision=row.revision,
            verification_code=row.verification_code,
            scopes=list(row.scopes),
            client_slot=row.client_slot,
            client_name=row.client_name,
            generation=row.generation,
            requested_at=_database_utc(row.requested_at),
            activation_expires_at=_database_utc(row.activation_expires_at),
        ))
    return result


@router.post(
    "/ide/enrollments/current/claim-first-owner",
    response_model=IdeEnrollmentStatusResponse,
)
def claim_first_ide_owner(
    payload: IdeFirstOwnerClaimRequest,
    request: Request,
    response: Response,
    context: AuthContext = Depends(_pending_ide_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> IdeEnrollmentStatusResponse:
    """Consume the installer bootstrap to approve only a pristine first IDE."""

    token = _request_bearer(request)
    identity = _parse_ide_capability_token(token)
    if identity is None or identity != (context.subject, context.capability_generation):
        raise HTTPException(401, "invalid pending IDE capability")
    client_slot, generation = identity
    if generation != payload.expected_generation:
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_mismatch",
            "The first-owner installer claim no longer matches this pending IDE generation.",
            "review_pending_enrollments",
        )

    # Use the same global-before-slot lock order as enrollment allocation. The
    # installer bootstrap is allowed to decide exactly one pristine profile;
    # all later profiles remain browser-reviewed.
    installation = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == INSTALLATION_SECRET_BINDING_KEY)
        .with_for_update()
    )
    if installation is None:
        db.rollback()
        raise _ide_enrollment_problem(
            503,
            "first_owner_claim_authority_unavailable",
            "The installation authority is not ready for first-owner setup.",
            "retry_after_control_plane_ready",
        )
    slot_row = _locked_ide_slot(db, client_slot)
    if slot_row is None:
        db.rollback()
        raise HTTPException(401, "invalid pending IDE capability")
    enrollment = db.scalar(
        select(IdeEnrollment)
        .where(IdeEnrollment.request_id == payload.expected_request_id)
        .with_for_update()
    )
    if enrollment is None:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_mismatch",
            "The first-owner installer claim no longer matches this IDE enrollment.",
            "review_pending_enrollments",
        )
    try:
        slot_record = _parse_ide_slot_record(slot_row)
        _validate_ide_enrollment(enrollment)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_state_invalid",
            "The first-owner IDE enrollment state is invalid.",
            "review_paired_ide_clients",
        ) from None
    pending = slot_record["pending"]
    if (
        pending is None
        or slot_record["active"] is not None
        or pending["generation"] != generation
        or not hmac.compare_digest(pending["digest"], _mac(settings, "ide-capability", token))
        or enrollment.client_slot != client_slot
        or enrollment.generation != generation
        or enrollment.request_id != payload.expected_request_id
        or enrollment.revision != payload.expected_revision
        or enrollment.state != "awaiting_approval"
        or enrollment.activated_at is not None
    ):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_mismatch",
            "The first-owner installer claim no longer matches this pending IDE authority.",
            "review_pending_enrollments",
        )
    now = _utcnow()
    if _ide_enrollment_effective_state(enrollment, now=now) == "expired":
        db.rollback()
        raise _ide_enrollment_problem(
            410,
            "ide_enrollment_expired",
            "This IDE enrollment expired before first-owner setup completed.",
            "start_new_enrollment",
        )

    slot_rows = list(db.scalars(
        select(RuntimeConfig)
        .where(RuntimeConfig.key.like(f"{CAPABILITY_PREFIX}%"))
        .with_for_update()
    ))
    try:
        slot_records = [_parse_ide_slot_record(row) for row in slot_rows]
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_state_invalid",
            "An IDE client slot is invalid, so first-owner setup cannot select an authority safely.",
            "review_paired_ide_clients",
        ) from None
    browser_members = db.scalar(
        select(func.count())
        .select_from(RuntimeConfig)
        .where(RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%"))
    ) or 0
    live_enrollments = list(db.scalars(
        select(IdeEnrollment)
        .where(
            IdeEnrollment.state == "awaiting_approval",
            IdeEnrollment.activation_expires_at > now,
            IdeEnrollment.activated_at.is_(None),
        )
        .order_by(IdeEnrollment.requested_at.asc(), IdeEnrollment.request_id.asc())
        .with_for_update()
    ))
    try:
        for candidate in live_enrollments:
            _validate_ide_enrollment(candidate)
    except ValueError:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_state_invalid",
            "A live IDE enrollment is invalid, so first-owner setup cannot choose a winner safely.",
            "review_paired_ide_clients",
        ) from None
    if (
        browser_members != 0
        or any(record["active"] is not None for record in slot_records)
    ):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_not_pristine",
            "Automatic first-owner setup is unavailable because this installation already has another browser or IDE identity.",
            "review_pending_enrollments",
        )
    winner = live_enrollments[0] if live_enrollments else None
    if winner is None or winner.request_id != enrollment.request_id:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_not_winner",
            "Another earlier live IDE enrollment is the deterministic first-owner candidate. This request remains available for owner approval.",
            "review_pending_enrollments",
        )
    if not _token_matches(payload.bootstrap_token, settings.bootstrap_token):
        db.rollback()
        raise _ide_enrollment_problem(
            401,
            "first_owner_bootstrap_invalid",
            "The owner-only installer bootstrap does not match this installation.",
            "restore_first_owner_bootstrap",
        )
    try:
        _stage_one_time_token(
            db,
            BOOTSTRAP_MARKER,
            payload.bootstrap_token,
            settings.bootstrap_token,
            settings,
        )
    except HTTPException as error:
        db.rollback()
        if error.status_code == 409:
            raise _ide_enrollment_problem(
                409,
                "first_owner_bootstrap_consumed",
                "The one-use installer bootstrap was already consumed.",
                "review_pending_enrollments",
            ) from error
        raise

    enrollment.state = "approved"
    enrollment.decision_at = now
    enrollment.revision += 1
    db.add(enrollment)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "first_owner_claim_conflict",
            "Another local process claimed first-owner setup first.",
            "review_pending_enrollments",
        ) from exc
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return _ide_enrollment_status_response(enrollment, now=now)


@router.post(
    "/ide/enrollments/{request_id}/decision",
    response_model=IdeEnrollmentStatusResponse,
)
def decide_ide_enrollment(
    request_id: str,
    payload: IdeEnrollmentDecisionRequest,
    request: Request,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> IdeEnrollmentStatusResponse:
    if _IDE_ENROLLMENT_REQUEST_ID.fullmatch(request_id) is None:
        raise HTTPException(404, "IDE enrollment request not found")
    candidate = db.get(IdeEnrollment, request_id)
    if candidate is None:
        db.rollback()
        raise HTTPException(404, "IDE enrollment request not found")
    slot_row = _locked_ide_slot(db, candidate.client_slot)
    if slot_row is None:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_authority_missing",
            "The pending IDE authority no longer exists.",
            "refresh_pending_enrollments",
        )
    row = db.scalar(
        select(IdeEnrollment)
        .where(IdeEnrollment.request_id == request_id)
        .with_for_update()
    )
    if row is None:
        db.rollback()
        raise HTTPException(404, "IDE enrollment request not found")
    try:
        _validate_ide_enrollment(row)
    except ValueError:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_state_invalid",
            "The IDE enrollment review record is invalid and cannot be decided.",
            "review_paired_ide_clients",
        ) from None
    try:
        slot_record = _parse_ide_slot_record(slot_row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_authority_invalid",
            "The pending IDE authority is invalid and cannot be approved.",
            "review_paired_ide_clients",
        ) from None
    pending = slot_record["pending"]
    if (
        pending is None
        or pending["generation"] != row.generation
        or pending["client_name"] != row.client_name
        or pending["scopes"] != row.scopes
        or _record_time(pending, "activation_expires_at")
        != _database_utc(row.activation_expires_at)
    ):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_authority_mismatch",
            "The pending IDE authority no longer matches this review request.",
            "refresh_pending_enrollments",
        )
    now = _utcnow()
    if _ide_enrollment_effective_state(row, now=now) == "expired":
        db.rollback()
        raise _ide_enrollment_problem(
            410,
            "ide_enrollment_expired",
            "This IDE enrollment expired before it was reviewed.",
            "start_new_enrollment",
        )
    if (
        row.state != "awaiting_approval"
        or row.revision != payload.expected_revision
        or row.generation != payload.expected_generation
    ):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_revision_conflict",
            "The IDE enrollment changed before this decision was applied.",
            "refresh_pending_enrollments",
        )
    row.state = payload.decision
    row.decision_at = now
    row.revision += 1
    db.add(row)
    db.commit()
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        broker.wake_subject(_ide_enrollment_subject(request_id))
    return _ide_enrollment_status_response(row, now=now)


@router.post("/ide/activate", response_model=CapabilityActivationResponse)
def activate_ide_capability(
    request: Request,
    response: Response,
    context: AuthContext = Depends(_activating_ide_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> CapabilityActivationResponse:
    token = _request_bearer(request)
    identity = _parse_ide_capability_token(token)
    if identity is None or identity != (context.subject, context.capability_generation):
        raise HTTPException(401, "invalid IDE capability")
    client_slot, generation = identity
    row = _locked_ide_slot(db, client_slot)
    if row is None:
        db.rollback()
        raise HTTPException(401, "invalid IDE capability")
    try:
        record = _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_enrollment_slot_state_invalid",
            "The stored IDE client slot is invalid and cannot activate authority.",
            "review_paired_ide_clients",
        ) from None
    expected_digest = _mac(settings, "ide-capability", token)
    active = record["active"]
    if (
        active is not None
        and active["generation"] == generation
        and hmac.compare_digest(active["digest"], expected_digest)
        and active["revoked_at"] is None
    ):
        db.rollback()
        # A prior activation may have committed but failed while notifying the
        # stable slot event subject. Repeating the wake is safe and closes any
        # stream that still carries the replaced generation.
        _notify_capability_revoked(request, client_slot)
        response.headers["Cache-Control"] = "no-store"
        return CapabilityActivationResponse(
            client_slot=client_slot,
            generation=generation,
            scopes=list(IDE_CAPABILITY_SCOPES),
        )

    pending = record["pending"]
    if (
        pending is None
        or pending["generation"] != generation
        or not hmac.compare_digest(pending["digest"], expected_digest)
    ):
        db.rollback()
        raise HTTPException(401, "invalid or superseded pending IDE capability")
    activated_at = _utcnow()
    enrollment = _locked_ide_enrollment(
        db,
        client_slot=client_slot,
        generation=generation,
    )
    if enrollment is None:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_sidecar_missing",
            "The pending IDE authority has no matching browser review record.",
            "start_new_enrollment",
        )
    try:
        _validate_ide_enrollment(enrollment)
    except ValueError:
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_state_invalid",
            "The stored IDE enrollment review state is invalid.",
            "review_paired_ide_clients",
        ) from None
    if (
        enrollment.client_name != pending["client_name"]
        or enrollment.scopes != pending["scopes"]
        or _database_utc(enrollment.activation_expires_at)
        != _record_time(pending, "activation_expires_at")
    ):
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_authority_mismatch",
            "The pending IDE authority no longer matches its browser review record.",
            "review_paired_ide_clients",
        )
    effective_state = _ide_enrollment_effective_state(enrollment, now=activated_at)
    if effective_state == "expired":
        db.rollback()
        raise _ide_enrollment_problem(
            410,
            "ide_enrollment_expired",
            "The approved IDE enrollment expired before durable local activation.",
            "start_new_enrollment",
        )
    if effective_state == "awaiting_approval":
        db.rollback()
        raise _ide_enrollment_problem(
            409,
            "ide_enrollment_approval_required",
            "Approve this IDE enrollment in CodeSecurity Settings before activation.",
            "review_pending_enrollments",
        )
    if effective_state == "rejected":
        db.rollback()
        raise _ide_enrollment_problem(
            403,
            "ide_enrollment_rejected",
            "This IDE enrollment was rejected in CodeSecurity Settings.",
            "start_new_enrollment",
        )
    had_prior_active = active is not None and active["generation"] != generation
    record["active"] = {
        "generation": generation,
        "digest": pending["digest"],
        "client_name": pending["client_name"],
        "scopes": pending["scopes"],
        "activated_at": activated_at.isoformat(),
        "revoked_at": None,
    }
    record["client_name"] = pending["client_name"]
    record["pending"] = None
    row.value = _serialize_ide_slot_record(record)
    row.updated_at = activated_at
    enrollment.activated_at = activated_at
    enrollment.revision += 1
    db.add(row)
    db.add(enrollment)
    db.commit()
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    if had_prior_active:
        _notify_capability_revoked(request, client_slot)
    response.headers["Cache-Control"] = "no-store"
    return CapabilityActivationResponse(
        client_slot=client_slot,
        generation=generation,
        scopes=list(IDE_CAPABILITY_SCOPES),
    )


@router.delete("/ide/pending")
def cancel_pending_ide_capability(
    request: Request,
    context: AuthContext = Depends(_pending_ide_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> dict[str, bool]:
    token = _request_bearer(request)
    identity = _parse_ide_capability_token(token)
    if identity is None or identity != (context.subject, context.capability_generation):
        raise HTTPException(401, "invalid pending IDE capability")
    client_slot, generation = identity
    row = _locked_ide_slot(db, client_slot)
    if row is None:
        db.rollback()
        raise HTTPException(401, "invalid pending IDE capability")
    try:
        record = _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise HTTPException(401, "invalid pending IDE capability") from None
    pending = record["pending"]
    if (
        pending is None
        or pending["generation"] != generation
        or not hmac.compare_digest(
            pending["digest"],
            _mac(settings, "ide-capability", token),
        )
    ):
        db.rollback()
        raise HTTPException(401, "invalid or superseded pending IDE capability")
    changed_at = _utcnow()
    enrollment = _reject_enrollment_sidecar(
        db,
        client_slot=client_slot,
        generation=generation,
        changed_at=changed_at,
    )
    record["pending"] = None
    row.value = _serialize_ide_slot_record(record)
    row.updated_at = changed_at
    db.add(row)
    db.commit()
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker) and enrollment is not None:
        broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    return {"cancelled": True}


@router.post(
    "/ide/browser-invitations",
    response_model=IdeBrowserInvitationResponse,
)
def create_ide_browser_invitation(
    payload: IdeBrowserInvitationRequest,
    response: Response,
    context: AuthContext = Depends(_ide_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> IdeBrowserInvitationResponse:
    invitation_id, token, issued_at, expires_at = issue_ide_browser_invitation(
        db,
        settings,
        context,
        payload.purpose,
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return IdeBrowserInvitationResponse(
        bootstrap_token=token,
        invitation_id=invitation_id,
        purpose=payload.purpose,
        issued_at=issued_at,
        expires_at=expires_at,
    )


@router.get(
    "/ide/browser-invitations/{invitation_id}/membership",
    response_model=IdeBrowserInvitationMembershipResponse,
)
async def wait_for_ide_browser_membership(
    invitation_id: str,
    request: Request,
    response: Response,
    context: AuthContext = Depends(_ide_context),
    runtime: Runtime = Depends(get_runtime),
) -> IdeBrowserInvitationMembershipResponse:
    """Wait once for one IDE-issued browser invitation to become durable."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    def read_status() -> IdeBrowserInvitationMembershipResponse:
        with runtime.session_factory() as session:
            return _browser_invitation_membership_response(
                session,
                context,
                invitation_id,
            )

    current = read_status()
    if current.status != "pending":
        return current
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if not isinstance(broker, EventWakeBroker):
        raise _ide_browser_invitation_problem(
            503,
            "ide_browser_membership_wake_unavailable",
            "Browser membership acknowledgement is not available.",
            "retry_browser_membership_status",
        )
    if runtime.engine.dialect.name != "postgresql":
        return read_status()
    try:
        subscription = await broker.subscribe(_ide_browser_invitation_subject(invitation_id))
    except RuntimeError as exc:
        reconciled = read_status()
        if reconciled.status != "pending":
            return reconciled
        raise _ide_browser_invitation_problem(
            503,
            "ide_browser_membership_wake_unavailable",
            "Browser membership acknowledgement is not available.",
            "retry_browser_membership_status",
        ) from exc
    try:
        reconciled = read_status()
        if reconciled.status != "pending":
            return reconciled
        try:
            await subscription.wait(timeout=IDE_BROWSER_MEMBERSHIP_WAIT_SECONDS)
        except RuntimeError as exc:
            reconciled = read_status()
            if reconciled.status != "pending":
                return reconciled
            raise _ide_browser_invitation_problem(
                503,
                "ide_browser_membership_wake_unavailable",
                "Browser membership acknowledgement is not available.",
                "retry_browser_membership_status",
            ) from exc
        return read_status()
    finally:
        subscription.close()


@router.post("/browser/pairing-token", response_model=BrowserPairingTokenIssueResponse)
def rotate_browser_pairing_token(
    response: Response,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> BrowserPairingTokenIssueResponse:
    token, issued_at, expires_at = issue_dynamic_browser_pairing_token(db, settings)
    _commit_one_time_transaction(db)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return BrowserPairingTokenIssueResponse(
        bootstrap_token=token,
        issued_at=issued_at,
        expires_at=expires_at,
        expires_in=DYNAMIC_BROWSER_PAIRING_TOKEN_TTL_SECONDS,
    )


@router.get("/browser/sessions", response_model=list[BrowserMemberResponse])
def list_browser_members(
    context: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> list[BrowserMemberResponse]:
    current_session_id = context.session_nonce
    checked_at = _utcnow()
    rows = db.query(RuntimeConfig).filter(
        RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%")
    ).order_by(RuntimeConfig.updated_at.desc(), RuntimeConfig.key.asc()).all()
    result: list[BrowserMemberResponse] = []
    for row in rows:
        session_id = row.key.removeprefix(BROWSER_SESSION_PREFIX)
        if re.fullmatch(r"[A-Za-z0-9_-]{32}", session_id) is None:
            continue
        record = _browser_member_metadata(row, checked_at)
        if record is None:
            continue
        created_at = _record_time(record, "created_at")
        last_seen_at = _record_time(record, "last_seen_at")
        result.append(BrowserMemberResponse(
            id=_browser_member_id(session_id),
            member_name=record["member_name"],
            member_kind=record["member_kind"],
            created_at=created_at,
            last_seen_at=last_seen_at,
            current=session_id == current_session_id,
        ))
    return result


@router.delete("/browser/sessions/{member_id}")
def revoke_browser_member(
    member_id: str,
    payload: BrowserMemberRevocationRequest,
    request: Request,
    response: Response,
    context: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    session_id = _browser_member_session_id(member_id)
    if session_id is None:
        raise HTTPException(404, "browser member not found")
    row = db.scalar(
        select(RuntimeConfig)
        .where(RuntimeConfig.key == _browser_session_key(session_id))
        .with_for_update()
    )
    if row is None:
        db.rollback()
        raise HTTPException(404, "browser member not found")
    try:
        record: dict[str, Any] = json.loads(row.value)
        created_at = _record_time(record, "created_at")
        if set(record) != _BROWSER_SESSION_RECORD_FIELDS:
            raise ValueError("invalid browser member state")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise HTTPException(409, {
            "code": "browser_member_state_invalid",
            "message": "The stored browser member is invalid and cannot be revoked safely.",
            "action": "review_browser_members",
        }) from None
    if created_at != payload.expected_created_at.astimezone(timezone.utc):
        db.rollback()
        raise HTTPException(409, {
            "code": "browser_member_revision_conflict",
            "message": "The browser member changed before this revocation was applied.",
            "action": "refresh_browser_members",
        })
    _delete_browser_membership_receipts(db, member_id)
    db.delete(row)
    db.commit()
    current = session_id == context.session_nonce
    if current:
        response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return {"revoked": True, "current": current}


@router.get(
    "/ide/capabilities",
    response_model=list[IdeCapabilityResponse | InvalidIdeCapabilityResponse],
)
def list_ide_capabilities(
    request: Request,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> list[IdeCapabilityResponse | InvalidIdeCapabilityResponse]:
    rows = db.query(RuntimeConfig).filter(RuntimeConfig.key.like(f"{CAPABILITY_PREFIX}%")).all()
    result: list[IdeCapabilityResponse | InvalidIdeCapabilityResponse] = []
    for row in rows:
        capability_id = row.key.removeprefix(CAPABILITY_PREFIX)
        if _IDE_CLIENT_SLOT.fullmatch(capability_id) is None:
            continue
        try:
            record = _parse_ide_slot_record(row)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            result.append(
                InvalidIdeCapabilityResponse(
                    id=capability_id,
                    invalid_recovery_token=_invalid_ide_slot_recovery_token(
                        settings,
                        capability_id,
                        row.value,
                    ),
                )
            )
            continue
        broker = getattr(request.app.state, "event_wake_broker", None)
        from .events import EventWakeBroker

        active_record = _active_ide_record(record)
        retained_active_record = record["active"]
        pending_record = record["pending"]
        active = active_record is not None
        if isinstance(broker, EventWakeBroker) and active_record is not None:
            from .events import ide_stream_subject

            connection_count = broker.subject_connection_count(
                ide_stream_subject(capability_id, active_record["generation"])
            )
        else:
            connection_count = 0
        connected = connection_count > 0
        pending_activation = (
            pending_record is not None
            and _record_time(pending_record, "activation_expires_at") > _utcnow()
        )
        source_open_available = active and connection_count == 1
        client_name = (
            retained_active_record["client_name"]
            if retained_active_record is not None
            else pending_record["client_name"]
            if pending_record is not None
            else record["client_name"]
        )
        result.append(
            IdeCapabilityResponse(
                id=capability_id,
                client_name=client_name,
                scopes=retained_active_record["scopes"] if retained_active_record is not None else [],
                created_at=(
                    _record_time(retained_active_record, "activated_at")
                    if retained_active_record is not None
                    else _record_time(pending_record, "issued_at")
                    if pending_record is not None
                    else None
                ),
                revoked=(
                    retained_active_record is not None
                    and retained_active_record["revoked_at"] is not None
                ),
                active=active,
                connected=active and connected,
                active_generation=(
                    retained_active_record["generation"] if retained_active_record is not None else None
                ),
                latest_generation=record["generation"],
                pending_activation=pending_activation,
                pending_generation=pending_record["generation"] if pending_record is not None else None,
                pending_client_name=pending_record["client_name"] if pending_record is not None else None,
                pending_activation_expires_at=(
                    _record_time(pending_record, "activation_expires_at")
                    if pending_record is not None
                    else None
                ),
                source_open_available=source_open_available,
                source_open_disabled_reason=None if source_open_available else (
                    "This IDE capability has multiple connected windows. Close or re-pair until exactly one target window is connected."
                    if active and connection_count > 1
                    else "This IDE client is not currently connected to the CodeSecurity event stream."
                    if active
                    else "This IDE client is waiting for durable activation in VS Code."
                    if pending_activation
                    else "This IDE client is invalid or not active."
                ),
            )
        )
    return result


@router.delete("/ide/capabilities/{capability_id}")
def revoke_ide_capability(
    capability_id: str,
    payload: CapabilityRevocationRequest,
    request: Request,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    if _IDE_CLIENT_SLOT.fullmatch(capability_id) is None:
        raise HTTPException(404, "IDE client slot not found")
    row = _locked_ide_slot(db, capability_id)
    if row is None:
        db.rollback()
        raise HTTPException(404, "IDE client slot not found")
    try:
        record = _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_slot_state_invalid",
            "The stored IDE client slot is invalid and cannot be revoked safely.",
            "review_paired_ide_clients",
        ) from None
    retained_active = record["active"]
    pending = record["pending"]
    actual_tuple = (
        record["generation"],
        retained_active["generation"] if retained_active is not None else None,
        pending["generation"] if pending is not None else None,
    )
    expected_tuple = (
        payload.expected_latest_generation,
        payload.expected_active_generation,
        payload.expected_pending_generation,
    )
    if expected_tuple != actual_tuple:
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_reset_generation_conflict",
            "The IDE client slot changed before this reset request was applied.",
            "refresh_paired_ide_clients",
        )
    had_active = retained_active is not None
    changed_at = _utcnow()
    changed = record["pending"] is not None
    enrollment = None
    if pending is not None:
        enrollment = _reject_enrollment_sidecar(
            db,
            client_slot=capability_id,
            generation=pending["generation"],
            changed_at=changed_at,
        )
    if retained_active is not None and retained_active["revoked_at"] is None:
        changed = True
        retained_active["revoked_at"] = changed_at.isoformat()
    if changed:
        record["pending"] = None
        row.value = _serialize_ide_slot_record(record)
        row.updated_at = changed_at
        db.add(row)
        db.commit()
    else:
        db.rollback()
    if had_active:
        _notify_capability_revoked(request, capability_id)
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker) and enrollment is not None:
        broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    return {"revoked": True}


@router.delete(
    "/ide/capabilities/{capability_id}/invalid",
    response_model=InvalidCapabilityRecoveryResponse,
)
def recover_invalid_ide_capability(
    capability_id: str,
    payload: InvalidCapabilityRecoveryRequest,
    request: Request,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_runtime_settings),
) -> InvalidCapabilityRecoveryResponse:
    """Delete only the exact redacted invalid slot state the browser reviewed."""

    if _IDE_CLIENT_SLOT.fullmatch(capability_id) is None:
        raise HTTPException(404, "IDE client slot not found")
    row = _locked_ide_slot(db, capability_id)
    if row is None:
        db.rollback()
        raise HTTPException(404, "IDE client slot not found")
    try:
        _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        pass
    else:
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_invalid_recovery_not_required",
            "This IDE client slot is valid and cannot be removed by invalid-state recovery.",
            "refresh_paired_ide_clients",
        )
    actual_token = _invalid_ide_slot_recovery_token(
        settings,
        capability_id,
        row.value,
    )
    if not hmac.compare_digest(payload.recovery_token, actual_token):
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_invalid_recovery_conflict",
            "The invalid IDE client slot changed before this recovery request was applied.",
            "refresh_paired_ide_clients",
        )
    enrollments = list(db.scalars(
        select(IdeEnrollment).where(IdeEnrollment.client_slot == capability_id)
    ))
    db.delete(row)
    for enrollment in enrollments:
        db.delete(enrollment)
    db.commit()
    _notify_capability_revoked(request, capability_id)
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        for enrollment in enrollments:
            broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    return InvalidCapabilityRecoveryResponse()


@router.delete("/ide/capabilities/{capability_id}/pending")
def cancel_pending_ide_capability_from_browser(
    capability_id: str,
    payload: PendingCancellationRequest,
    request: Request,
    _: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    if _IDE_CLIENT_SLOT.fullmatch(capability_id) is None:
        raise HTTPException(404, "IDE client slot not found")
    row = _locked_ide_slot(db, capability_id)
    if row is None:
        db.rollback()
        raise HTTPException(404, "IDE client slot not found")
    try:
        record = _parse_ide_slot_record(row)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_slot_state_invalid",
            "The stored IDE client slot is invalid and cannot cancel pending activation safely.",
            "review_paired_ide_clients",
        ) from None
    pending = record["pending"]
    if pending is None or pending["generation"] != payload.expected_pending_generation:
        db.rollback()
        raise _ide_capability_problem(
            409,
            "ide_pairing_pending_generation_conflict",
            "The pending IDE authority changed before this cancellation request was applied.",
            "refresh_paired_ide_clients",
        )
    changed_at = _utcnow()
    enrollment = _reject_enrollment_sidecar(
        db,
        client_slot=capability_id,
        generation=pending["generation"],
        changed_at=changed_at,
    )
    record["pending"] = None
    row.value = _serialize_ide_slot_record(record)
    row.updated_at = changed_at
    db.add(row)
    db.commit()
    from .events import EventWakeBroker

    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker) and enrollment is not None:
        broker.wake_subject(_ide_enrollment_subject(enrollment.request_id))
    return {"cancelled": True}
