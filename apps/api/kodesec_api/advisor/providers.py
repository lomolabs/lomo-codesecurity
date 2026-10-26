from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import unicodedata
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from ..models import RuntimeConfig
from ..redaction import redact_text


PROVIDERS_KEY = "advisor.providers.v1"
PROVIDER_RECEIPT_PREFIX = "advisor.provider.receipt.v1."
PROVIDER_CONSENT_PREFIX = "advisor.provider.consent.v1."
PROVIDER_JOB_PROFILE_SCHEMA = "lomo-advisor-provider-job-profile/v1"
PROVIDER_JOB_PIN_SCHEMA = "lomo-advisor-provider-job-pin/v1"
PROVIDER_JOB_COLLECTION_SCHEMA = "lomo-advisor-provider-job-collection/v1"
MAX_PROVIDERS = 8
PROVIDER_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
PROVIDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()/+-]{0,79}\Z")
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}(?::[A-Za-z0-9][A-Za-z0-9._-]{0,18})?\Z")
MODEL_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CONFIG_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
PROVIDER_STATE_CORRUPT = "provider_configuration_corrupt"
TRANSPORTS = frozenset({"local", "direct", "ssh"})
DISCLOSURE_CATEGORIES = (
    "finding_identity",
    "source_location",
    "repository_context",
    "bounded_code_snippet",
    "bounded_scanner_metadata",
)
STATUSES = frozenset(
    {"idle", "testing", "available", "unavailable", "active", "disconnected"}
)
REMEDIATIONS = frozenset(
    {"none", "authorize", "test", "activate", "retry", "refresh"}
)

# Connector failures cross a process boundary before they become durable job
# fields. Keep the vocabulary and user-safe text here so the connector, worker,
# and UI-facing provider state cannot drift or relay arbitrary upstream text.
PROVIDER_TEST_FAILURES: dict[str, tuple[str, bool]] = {
    "advisor_provider_local_unavailable": (
        "Local Ollama is not reachable at the configured same-device endpoint.",
        True,
    ),
    "advisor_provider_unreachable": (
        "The configured Advisor provider could not be reached.",
        True,
    ),
    "advisor_provider_timeout": (
        "The Advisor provider did not respond before the bounded deadline.",
        True,
    ),
    "advisor_provider_http_status": (
        "The Advisor provider returned an unsuccessful HTTP status.",
        True,
    ),
    "advisor_provider_tags_invalid": (
        "The Advisor provider returned a malformed model catalog.",
        False,
    ),
    "advisor_provider_model_missing": (
        "The exact configured Advisor model is not installed on this provider.",
        False,
    ),
    "advisor_provider_digest_mismatch": (
        "The configured Advisor model is present, but its digest does not match the exact pin.",
        False,
    ),
    "advisor_provider_local_weights_required": (
        "The selected Ollama model is cloud-backed, not local. Choose a model with local weights in Settings > Advisor Providers.",
        False,
    ),
    "advisor_provider_ssh_authorization_failed": (
        "SSH authorization is missing, invalid, or does not match this exact provider profile.",
        False,
    ),
    "advisor_provider_ssh_tunnel_failed": (
        "The authorized SSH forward could not reach a ready state.",
        True,
    ),
    "advisor_provider_direct_authorization_required": (
        "The direct Advisor host is outside the authorized provider boundary.",
        False,
    ),
    "advisor_provider_route_misconfigured": (
        "The local Advisor route is misconfigured.",
        False,
    ),
    "advisor_provider_receipt_invalid": (
        "The Advisor connector returned an invalid exact-model receipt.",
        False,
    ),
    "advisor_generation_response_too_large": (
        "The Advisor generation response exceeded the bounded size; no review was published.",
        False,
    ),
    "advisor_generation_response_invalid": (
        "The Advisor generation response envelope was invalid; no review was published.",
        False,
    ),
    "advisor_generation_json_invalid": (
        "The Advisor generation endpoint returned invalid JSON; no review was published.",
        False,
    ),
    "advisor_generation_model_mismatch": (
        "The Advisor generation response named a different model; no review was published.",
        False,
    ),
    "advisor_generation_incomplete": (
        "The Advisor generation response was not complete; no review was published.",
        False,
    ),
    "advisor_generation_text_invalid": (
        "The Advisor review text was missing, empty, or oversized; no review was published.",
        False,
    ),
    "advisor_generation_output_json_invalid": (
        "The Advisor model did not return a complete strict-JSON review; no review was published.",
        False,
    ),
    "advisor_generation_output_schema_invalid": (
        "The Advisor model's review did not match the required result schema; no review was published.",
        False,
    ),
    "advisor_connector_protocol": (
        "The Advisor connector returned an invalid typed failure response.",
        True,
    ),
    "advisor_connector_unavailable": (
        "The dedicated local Advisor connector is unavailable.",
        True,
    ),
}


def provider_test_failure(code: str) -> tuple[str, bool]:
    """Return canonical safe detail and retryability for a connector failure."""

    try:
        return PROVIDER_TEST_FAILURES[code]
    except KeyError as exc:
        raise ValueError("advisor provider test failure code is not supported") from exc


class ProviderConflictError(ValueError):
    def __init__(self, current_revision: int) -> None:
        super().__init__("advisor provider configuration changed; reload before retrying")
        self.current_revision = current_revision


def _visible_text(value: object, *, name: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(
        unicodedata.category(character) in {"Cc", "Cf"} for character in text
    ):
        raise ValueError(f"{name} must contain bounded visible text")
    return text


def normalize_host(value: object, *, name: str = "host") -> str:
    host = _visible_text(value, name=name, maximum=15).lower().rstrip(".")
    if any(character in host for character in {"/", "\\", "@", ":", "%", "[", "]"}):
        raise ValueError(f"{name} must be one exact IPv4 address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{name} must be one exact IPv4 address") from exc
    if address.version != 4 or any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    ):
        raise ValueError(f"{name} targets an unsafe special-purpose address")
    return address.compressed


def normalize_direct_url(value: object) -> str:
    candidate = _visible_text(value, name="base_url", maximum=500).rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port != 11434
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("direct base_url must be an exact explicit-port HTTP origin")
    host = normalize_host(parsed.hostname, name="direct host")
    if host in {"localhost", "host.docker.internal"}:
        raise ValueError("direct base_url must not target the local provider route")
    return f"http://{host}:{parsed.port}"


def _normalize_nullable_timestamp(value: object) -> str | None:
    if value in {None, ""}:
        return None
    text = str(value)
    try:
        observed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if observed.tzinfo is None or observed.utcoffset() is None:
        return None
    return observed.astimezone(timezone.utc).isoformat()


def _credential_free_identifier(
    value: object,
    *,
    name: str,
    maximum: int,
    pattern: re.Pattern[str],
) -> str:
    normalized = _visible_text(value, name=name, maximum=maximum)
    if pattern.fullmatch(normalized) is None or redact_text(normalized) != normalized:
        raise ValueError(f"{name} must be a credential-free identifier")
    return normalized


def _profile_config_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value.get(key)
        for key in (
            "id",
            "name",
            "transport",
            "priority",
            "enabled",
            "base_url",
            "model",
            "model_digest",
            "ssh_host",
            "ssh_port",
            "ssh_user",
        )
    }


def profile_config_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        _profile_config_projection(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_profile(value: Mapping[str, Any]) -> dict[str, Any]:
    provider_id = _visible_text(value.get("id"), name="provider id", maximum=40)
    if not PROVIDER_ID.fullmatch(provider_id):
        raise ValueError("provider id must match [a-z][a-z0-9-]{0,39}")
    name = _credential_free_identifier(
        value.get("name"),
        name="provider name",
        maximum=80,
        pattern=PROVIDER_NAME,
    )
    transport = str(value.get("transport") or "").strip().lower()
    if transport not in TRANSPORTS:
        raise ValueError("provider transport must be local, direct, or ssh")
    priority = value.get("priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 7:
        raise ValueError("provider priority must be an integer from 0 through 7")
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise ValueError("provider enabled must be boolean")
    model = _credential_free_identifier(
        value.get("model"),
        name="model",
        maximum=120,
        pattern=MODEL_NAME,
    )
    model_digest = str(value.get("model_digest") or "").strip().lower()
    if not MODEL_DIGEST.fullmatch(model_digest):
        raise ValueError("model_digest must be an exact lowercase SHA-256 digest")

    base_url: str | None = None
    ssh_host: str | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    if transport == "direct":
        base_url = normalize_direct_url(value.get("base_url"))
    elif value.get("base_url") not in {None, ""}:
        raise ValueError("base_url is backend-owned for local and ssh providers")

    if transport == "ssh":
        ssh_host = normalize_host(value.get("ssh_host"), name="ssh_host")
        raw_port = value.get("ssh_port", 22)
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) or raw_port != 22:
            raise ValueError("ssh_port must be exactly 22")
        ssh_port = raw_port
        ssh_user = _visible_text(value.get("ssh_user"), name="ssh_user", maximum=64)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", ssh_user):
            raise ValueError("ssh_user is not a safe OpenSSH user name")
    elif any(value.get(key) not in {None, ""} for key in ("ssh_host", "ssh_user")) or value.get(
        "ssh_port"
    ) not in {None, 22}:
        raise ValueError("SSH fields are accepted only for ssh providers")

    disclosure = value.get("content_disclosure_approved", False)
    if not isinstance(disclosure, bool):
        raise ValueError("content_disclosure_approved must be boolean")
    config_revision = value.get("config_revision", 1)
    if (
        isinstance(config_revision, bool)
        or not isinstance(config_revision, int)
        or config_revision < 1
    ):
        raise ValueError("provider config_revision must be a positive integer")
    reason_code = value.get("reason_code")
    if reason_code is not None and (
        not isinstance(reason_code, str) or REASON_CODE.fullmatch(reason_code) is None
    ):
        raise ValueError("provider reason_code must be a safe typed token")
    remediation = str(value.get("remediation") or "test")
    if remediation not in REMEDIATIONS:
        raise ValueError("provider remediation is not supported")
    profile = {
        "id": provider_id,
        "name": name,
        "transport": transport,
        "priority": priority,
        "enabled": enabled,
        "base_url": base_url,
        "model": model,
        "model_digest": model_digest,
        "ssh_host": ssh_host,
        "ssh_port": ssh_port,
        "ssh_user": ssh_user,
        "status": str(value.get("status") or "idle")
        if str(value.get("status") or "idle") in STATUSES
        else "idle",
        "reason": _visible_text(value.get("reason"), name="reason", maximum=240)
        if value.get("reason")
        else None,
        "last_activity_at": _normalize_nullable_timestamp(value.get("last_activity_at")),
        "content_disclosure_approved": disclosure,
        "config_revision": config_revision,
        "reason_code": reason_code,
        "remediation": remediation,
    }
    profile["config_digest"] = profile_config_digest(profile)
    return profile


def job_profile_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return one canonical, credential-free profile for durable execution."""

    profile = normalize_profile(value)
    return {
        "schema": PROVIDER_JOB_PROFILE_SCHEMA,
        **profile,
        "reason": None,
        "last_activity_at": None,
        "reason_code": None,
        "remediation": "none",
    }


def normalize_job_profile_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != PROVIDER_JOB_PROFILE_SCHEMA:
        raise ValueError("advisor provider job profile schema is invalid")
    normalized = job_profile_snapshot(value)
    normalized.pop("schema")
    return normalized


def job_pin_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    """Type the exact provider pin so durable redaction cannot corrupt it."""

    provider_id = _visible_text(value.get("provider_id"), name="provider id", maximum=40)
    if not PROVIDER_ID.fullmatch(provider_id):
        raise ValueError("provider id must match [a-z][a-z0-9-]{0,39}")
    transport = str(value.get("transport") or "").strip().lower()
    if transport not in TRANSPORTS:
        raise ValueError("provider transport must be local, direct, or ssh")
    revision = value.get("provider_config_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("provider config revision must be a positive integer")
    config_digest = str(value.get("provider_config_digest") or "").strip().lower()
    if not CONFIG_DIGEST.fullmatch(config_digest):
        raise ValueError("provider config digest must be an exact SHA-256 digest")
    model = _credential_free_identifier(
        value.get("model"),
        name="model",
        maximum=120,
        pattern=MODEL_NAME,
    )
    model_digest = str(value.get("model_digest") or "").strip().lower()
    if not MODEL_DIGEST.fullmatch(model_digest):
        raise ValueError("model digest must be an exact SHA-256 digest")
    return {
        "schema": PROVIDER_JOB_PIN_SCHEMA,
        "provider_id": provider_id,
        "transport": transport,
        "provider_config_revision": revision,
        "provider_config_digest": config_digest,
        "model": model,
        "model_digest": model_digest,
    }


def normalize_job_pin_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != PROVIDER_JOB_PIN_SCHEMA:
        raise ValueError("advisor provider job pin schema is invalid")
    normalized = job_pin_snapshot(value)
    normalized.pop("schema")
    return normalized


def _job_collection_snapshot(normalized: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PROVIDER_JOB_COLLECTION_SCHEMA,
        **normalized,
        "providers": [job_profile_snapshot(profile) for profile in normalized["providers"]],
    }


def job_collection_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return _job_collection_snapshot(normalize_collection(value))


def normalize_job_collection_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != PROVIDER_JOB_COLLECTION_SCHEMA:
        raise ValueError("advisor provider job collection schema is invalid")
    raw_profiles = value.get("providers")
    if not isinstance(raw_profiles, list):
        raise ValueError("advisor provider job collection profiles are invalid")
    profiles = [
        normalize_job_profile_snapshot(profile)
        for profile in raw_profiles
        if isinstance(profile, Mapping)
    ]
    if len(profiles) != len(raw_profiles):
        raise ValueError("advisor provider job collection profiles are invalid")
    collection = normalize_collection({**value, "providers": profiles})
    if value != _job_collection_snapshot(collection):
        raise ValueError("advisor provider job collection snapshot is not canonical")
    return collection


def normalize_collection(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("state_error") == PROVIDER_STATE_CORRUPT:
        return {
            "revision": 1,
            "active_provider_id": None,
            "providers": [],
            "state_error": PROVIDER_STATE_CORRUPT,
        }
    revision = value.get("revision", 1)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("provider collection revision must be positive")
    raw_profiles = value.get("providers", [])
    if not isinstance(raw_profiles, list) or len(raw_profiles) > MAX_PROVIDERS:
        raise ValueError(f"at most {MAX_PROVIDERS} advisor providers are allowed")
    profiles = [normalize_profile(item) for item in raw_profiles if isinstance(item, Mapping)]
    if len(profiles) != len(raw_profiles):
        raise ValueError("every advisor provider must be an object")
    identities = [item["id"] for item in profiles]
    priorities = [item["priority"] for item in profiles]
    if len(set(identities)) != len(identities):
        raise ValueError("advisor provider ids must be unique")
    if len(set(priorities)) != len(priorities):
        raise ValueError("advisor provider priorities must be unique")
    profiles.sort(key=lambda item: (item["priority"], item["id"]))
    active = value.get("active_provider_id")
    if active is not None and active not in identities:
        active = None
    if active is not None:
        selected = next(item for item in profiles if item["id"] == active)
        if not selected["enabled"]:
            active = None
    return {
        "revision": revision,
        "active_provider_id": active,
        "providers": profiles,
    }


def default_collection(settings: Any) -> dict[str, Any]:
    digest = str(getattr(settings, "ollama_model_digest", "") or "").strip().lower()
    if not MODEL_DIGEST.fullmatch(digest):
        return {"revision": 1, "active_provider_id": None, "providers": []}
    profile = normalize_profile(
        {
            "id": "local-default",
            "name": "This device",
            "transport": "local",
            "priority": 0,
            "enabled": True,
            "base_url": None,
            "model": getattr(settings, "ollama_model", "qwen3:8b"),
            "model_digest": digest,
        }
    )
    return {"revision": 1, "active_provider_id": None, "providers": [profile]}


def load_collection(db: Session, settings: Any, *, lock: bool = False) -> dict[str, Any]:
    item = db.get(RuntimeConfig, PROVIDERS_KEY, with_for_update=lock)
    if item is None:
        return default_collection(settings)
    try:
        parsed = json.loads(item.value)
        if not isinstance(parsed, dict):
            raise ValueError
        return normalize_collection(parsed)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {
            "revision": 1,
            "active_provider_id": None,
            "providers": [],
            "state_error": PROVIDER_STATE_CORRUPT,
        }


def save_collection(db: Session, collection: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_collection(collection)
    if normalized.get("state_error") == PROVIDER_STATE_CORRUPT:
        raise ValueError("corrupt advisor provider state cannot be persisted")
    encoded = json.dumps(normalized, allow_nan=False, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > 16 * 1024:
        raise ValueError("advisor provider configuration exceeds the bounded size limit")
    item = db.get(RuntimeConfig, PROVIDERS_KEY)
    if item is None:
        item = RuntimeConfig(key=PROVIDERS_KEY, value=encoded)
    else:
        item.value = encoded
        item.updated_at = datetime.now(timezone.utc)
    db.add(item)
    db.flush()
    return normalized


def require_revision(collection: Mapping[str, Any], expected_revision: int) -> None:
    if isinstance(expected_revision, bool) or expected_revision < 1:
        raise ValueError("expected_revision must be a positive integer")
    current = int(collection["revision"])
    if current != expected_revision:
        raise ProviderConflictError(current)


def replace_profile(
    collection: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    expected_revision: int,
    create: bool,
) -> dict[str, Any]:
    current = normalize_collection(collection)
    require_revision(current, expected_revision)
    candidate = normalize_profile(profile)
    profiles = deepcopy(current["providers"])
    index = next((i for i, item in enumerate(profiles) if item["id"] == candidate["id"]), None)
    if create and index is not None:
        raise ValueError("advisor provider id already exists")
    if not create and index is None:
        raise KeyError(candidate["id"])
    if create:
        if len(profiles) >= MAX_PROVIDERS:
            raise ValueError(f"at most {MAX_PROVIDERS} advisor providers are allowed")
        if any(item["priority"] == candidate["priority"] for item in profiles):
            raise ValueError("advisor provider priority is already in use")
        profiles.append(candidate)
    else:
        previous = profiles[index]
        changed_provider_ids = {candidate["id"]}
        if candidate["priority"] != previous["priority"]:
            displaced_index = next(
                (
                    item_index
                    for item_index, item in enumerate(profiles)
                    if item_index != index and item["priority"] == candidate["priority"]
                ),
                None,
            )
            if displaced_index is not None:
                displaced = deepcopy(profiles[displaced_index])
                changed_provider_ids.add(displaced["id"])
                displaced["priority"] = previous["priority"]
                displaced["config_revision"] += 1
                displaced["content_disclosure_approved"] = False
                displaced["status"] = "available"
                displaced["reason"] = "Provider order changed; test and activate this exact configuration again."
                displaced["reason_code"] = "provider_configuration_changed"
                displaced["remediation"] = "activate"
                profiles[displaced_index] = normalize_profile(displaced)
        candidate["config_revision"] = previous["config_revision"] + 1
        candidate = normalize_profile(candidate)
        profiles[index] = candidate
    active = current["active_provider_id"]
    if active == candidate["id"] or (
        not create and active in changed_provider_ids
    ):
        active = None
    return normalize_collection(
        {
            "revision": current["revision"] + 1,
            "active_provider_id": active,
            "providers": profiles,
        }
    )


def remove_profile(
    collection: Mapping[str, Any], provider_id: str, *, expected_revision: int
) -> dict[str, Any]:
    current = normalize_collection(collection)
    require_revision(current, expected_revision)
    profiles = [item for item in current["providers"] if item["id"] != provider_id]
    if len(profiles) == len(current["providers"]):
        raise KeyError(provider_id)
    return normalize_collection(
        {
            "revision": current["revision"] + 1,
            "active_provider_id": None
            if current["active_provider_id"] == provider_id
            else current["active_provider_id"],
            "providers": profiles,
        }
    )


def disclosure_destination(profile: Mapping[str, Any]) -> str:
    normalized = normalize_profile(profile)
    if normalized["transport"] == "direct":
        return str(normalized["base_url"])
    if normalized["transport"] == "ssh":
        return (
            f"ssh://{normalized['ssh_user']}@{normalized['ssh_host']}:22/"
            "ollama/127.0.0.1:11434"
        )
    return "local://ollama"


def normalize_disclosure_destination(value: object, *, transport: str) -> str:
    """Accept only the canonical credential-free destination shown to operators."""

    candidate = _visible_text(value, name="disclosure destination", maximum=500)
    if transport == "direct":
        normalized = normalize_direct_url(candidate)
    elif transport == "ssh":
        parsed = urlsplit(candidate)
        username = parsed.username
        if (
            parsed.scheme != "ssh"
            or username is None
            or parsed.password is not None
            or parsed.port != 22
            or parsed.path != "/ollama/127.0.0.1:11434"
            or parsed.query
            or parsed.fragment
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username) is None
        ):
            raise ValueError("SSH disclosure destination is not canonical")
        host = normalize_host(parsed.hostname, name="SSH disclosure host")
        normalized = f"ssh://{username}@{host}:22/ollama/127.0.0.1:11434"
    else:
        raise ValueError("disclosure destination requires a remote transport")
    if candidate != normalized:
        raise ValueError("disclosure destination is not canonical")
    return normalized


def build_activation_approval(profile: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_profile(profile)
    if normalized["transport"] not in {"direct", "ssh"}:
        raise ValueError("only remote providers require a disclosure approval")
    return normalize_activation_approval({
        "schema": "lomo-advisor-activation-approval/v1",
        "provider_id": normalized["id"],
        "provider_config_revision": normalized["config_revision"],
        "provider_config_digest": normalized["config_digest"],
        "transport": normalized["transport"],
        "destination": disclosure_destination(normalized),
        "disclosure_mode": "finding_evidence",
        "payload_categories": list(DISCLOSURE_CATEGORIES),
        "model": normalized["model"],
        "model_digest": normalized["model_digest"],
    })


def normalize_activation_approval(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "provider_id",
        "provider_config_revision",
        "provider_config_digest",
        "transport",
        "destination",
        "disclosure_mode",
        "payload_categories",
        "model",
        "model_digest",
    }
    if set(value) != required or value.get("schema") != "lomo-advisor-activation-approval/v1":
        raise ValueError("Advisor activation approval does not match schema v1")
    provider_id = str(value.get("provider_id") or "")
    revision = value.get("provider_config_revision")
    config_digest = str(value.get("provider_config_digest") or "").lower()
    transport = str(value.get("transport") or "")
    destination = normalize_disclosure_destination(
        value.get("destination"), transport=transport
    )
    model = _credential_free_identifier(
        value.get("model"),
        name="model",
        maximum=120,
        pattern=MODEL_NAME,
    )
    model_digest = str(value.get("model_digest") or "").lower()
    if (
        PROVIDER_ID.fullmatch(provider_id) is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or CONFIG_DIGEST.fullmatch(config_digest) is None
        or transport not in {"direct", "ssh"}
        or value.get("disclosure_mode") != "finding_evidence"
        or value.get("payload_categories") != list(DISCLOSURE_CATEGORIES)
        or MODEL_DIGEST.fullmatch(model_digest) is None
    ):
        raise ValueError("Advisor activation approval fields are invalid")
    return {
        "schema": "lomo-advisor-activation-approval/v1",
        "provider_id": provider_id,
        "provider_config_revision": revision,
        "provider_config_digest": config_digest,
        "transport": transport,
        "destination": destination,
        "disclosure_mode": "finding_evidence",
        "payload_categories": list(DISCLOSURE_CATEGORIES),
        "model": model,
        "model_digest": model_digest,
    }


def normalize_consent(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "provider_id",
        "provider_config_revision",
        "provider_config_digest",
        "transport",
        "destination",
        "disclosure_mode",
        "payload_categories",
        "model",
        "model_digest",
        "approved_at",
    }
    if set(value) != required or value.get("schema") != "lomo-advisor-source-consent/v1":
        raise ValueError("Advisor source-disclosure consent does not match schema v1")
    provider_id = str(value.get("provider_id") or "")
    revision = value.get("provider_config_revision")
    config_digest = str(value.get("provider_config_digest") or "")
    transport = str(value.get("transport") or "")
    destination = normalize_disclosure_destination(
        value.get("destination"), transport=transport
    )
    model = _visible_text(value.get("model"), name="model", maximum=120)
    digest = str(value.get("model_digest") or "").lower()
    approved_at = str(value.get("approved_at") or "")
    try:
        observed = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Advisor source-disclosure consent timestamp is invalid") from exc
    if (
        PROVIDER_ID.fullmatch(provider_id) is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or CONFIG_DIGEST.fullmatch(config_digest) is None
        or transport not in {"direct", "ssh"}
        or value.get("disclosure_mode") != "finding_evidence"
        or value.get("payload_categories") != list(DISCLOSURE_CATEGORIES)
        or MODEL_DIGEST.fullmatch(digest) is None
        or not approved_at.endswith("Z")
        or observed.tzinfo is None
    ):
        raise ValueError("Advisor source-disclosure consent fields are invalid")
    return {
        "schema": "lomo-advisor-source-consent/v1",
        "provider_id": provider_id,
        "provider_config_revision": revision,
        "provider_config_digest": config_digest,
        "transport": transport,
        "destination": destination,
        "disclosure_mode": "finding_evidence",
        "payload_categories": list(DISCLOSURE_CATEGORIES),
        "model": model,
        "model_digest": digest,
        "approved_at": approved_at,
    }


def build_consent(
    collection: Mapping[str, Any], provider_id: str
) -> dict[str, Any]:
    current = normalize_collection(collection)
    profile = provider_by_id(current, provider_id)
    if (
        profile["transport"] not in {"direct", "ssh"}
        or not profile["enabled"]
        or not profile["content_disclosure_approved"]
    ):
        raise ValueError("remote Advisor provider is not active with disclosure approval")
    return normalize_consent(
        {
            "schema": "lomo-advisor-source-consent/v1",
            "provider_id": provider_id,
            "provider_config_revision": profile["config_revision"],
            "provider_config_digest": profile["config_digest"],
            "transport": profile["transport"],
            "destination": disclosure_destination(profile),
            "disclosure_mode": "finding_evidence",
            "payload_categories": list(DISCLOSURE_CATEGORIES),
            "model": profile["model"],
            "model_digest": profile["model_digest"],
            "approved_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )


def consent_matches(
    collection: Mapping[str, Any],
    profile: Mapping[str, Any],
    consent: Mapping[str, Any] | None,
) -> bool:
    if consent is None:
        return False
    try:
        normalize_collection(collection)
        normalized_profile = normalize_profile(profile)
        normalized_consent = normalize_consent(consent)
    except (TypeError, ValueError):
        return False
    expected = {
        "provider_id": normalized_profile["id"],
        "provider_config_revision": normalized_profile["config_revision"],
        "provider_config_digest": normalized_profile["config_digest"],
        "transport": normalized_profile["transport"],
        "destination": disclosure_destination(normalized_profile),
        "disclosure_mode": "finding_evidence",
        "payload_categories": list(DISCLOSURE_CATEGORIES),
        "model": normalized_profile["model"],
        "model_digest": normalized_profile["model_digest"],
    }
    return (
        normalized_profile["transport"] in {"direct", "ssh"}
        and normalized_profile["enabled"]
        and normalized_profile["content_disclosure_approved"]
        and all(normalized_consent.get(key) == value for key, value in expected.items())
    )


def save_consent(db: Session, value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_consent(value)
    key = f"{PROVIDER_CONSENT_PREFIX}{normalized['provider_id']}"
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
    item = db.get(RuntimeConfig, key)
    if item is None:
        item = RuntimeConfig(key=key, value=encoded)
    else:
        item.value = encoded
        item.updated_at = datetime.now(timezone.utc)
    db.add(item)
    db.flush()
    return normalized


def load_consent(db: Session, provider_id: str) -> dict[str, Any] | None:
    if PROVIDER_ID.fullmatch(provider_id) is None:
        return None
    item = db.get(RuntimeConfig, f"{PROVIDER_CONSENT_PREFIX}{provider_id}")
    if item is None:
        return None
    try:
        value = json.loads(item.value)
        if not isinstance(value, dict):
            return None
        return normalize_consent(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def delete_consent(db: Session, provider_id: str) -> None:
    if PROVIDER_ID.fullmatch(provider_id) is None:
        return
    item = db.get(RuntimeConfig, f"{PROVIDER_CONSENT_PREFIX}{provider_id}")
    if item is not None:
        db.delete(item)
        db.flush()


def authorized_provider_ids(settings: Any, collection: Mapping[str, Any]) -> set[str]:
    direct_hosts = set(getattr(settings, "advisor_direct_host_list", frozenset()))
    ssh_ids = set(getattr(settings, "advisor_ssh_provider_id_list", frozenset()))
    allowed: set[str] = set()
    for profile in collection["providers"]:
        if profile["transport"] == "local":
            allowed.add(profile["id"])
        elif profile["transport"] == "direct":
            host = urlsplit(str(profile["base_url"])).hostname or ""
            if host.lower() in direct_hosts:
                allowed.add(profile["id"])
        elif profile["id"] in ssh_ids:
            allowed.add(profile["id"])
    return allowed


def public_collection(
    collection: Mapping[str, Any],
    settings: Any,
    consents: Mapping[str, Mapping[str, Any]] | None = None,
    receipts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized = normalize_collection(collection)
    if normalized.get("state_error") == PROVIDER_STATE_CORRUPT:
        return {
            "revision": 1,
            "active_provider_id": None,
            "providers": [],
            "resolution": {
                "provider_id": None,
                "transport": "unavailable",
                "reason": PROVIDER_STATE_CORRUPT,
                "eligible_provider_ids": [],
            },
        }
    authorized = authorized_provider_ids(settings, normalized)
    consent_map = dict(consents or {})
    receipt_map = dict(receipts or {})
    providers: list[dict[str, Any]] = []
    for profile in normalized["providers"]:
        item = deepcopy(profile)
        receipt_ready = receipt_matches(item, receipt_map.get(item["id"]))
        status_ready = item["status"] in {"available", "active"}
        item["authorization"] = (
            "not_required"
            if item["transport"] == "local"
            else "authorized"
            if item["id"] in authorized
            else "required"
        )
        consent_ready = consent_matches(
            normalized, item, consent_map.get(item["id"])
        )
        item["eligible"] = bool(
            item["enabled"]
            and item["id"] in authorized
            and status_ready
            and receipt_ready
            and item["transport"] == "local"
        )
        if item["transport"] != "local" and item["id"] not in authorized:
            item["reason_code"] = "authorization_required"
            item["reason"] = "Exact host authorization is required before testing this provider."
            item["remediation"] = "authorize"
        elif item["transport"] != "local" and item["reason_code"] is None:
            if (
                item["id"] == normalized["active_provider_id"]
                and item["status"] == "active"
                and receipt_ready
                and consent_ready
            ):
                item["reason_code"] = "remote_single_finding_confirmation_required"
                item["reason"] = (
                    "Ready for an explicit one-finding Advisor review after its exact "
                    "disclosure preview is confirmed. Automatic, scan-wide, and bulk "
                    "remote routing remain disabled."
                )
                item["remediation"] = "none"
            else:
                item["reason_code"] = "activation_required"
                item["reason"] = "Test and activate this exact provider before remote Advisor use."
                item["remediation"] = "activate"
        elif (
            item["transport"] == "local"
            and not item["eligible"]
            and item["reason_code"] is None
        ):
            item["reason_code"] = "test_required"
            item["reason"] = "Test this exact local provider before Advisor use."
            item["remediation"] = "test"
        providers.append(item)
    enabled = [
        item
        for item in providers
        if item["eligible"]
    ]
    active_id = normalized["active_provider_id"]
    # Local-first remains the route policy. Within each route tier, an
    # explicitly activated profile is the authoritative preference.
    route_order = {"local": 0, "direct": 1, "ssh": 2}
    enabled.sort(
        key=lambda item: (
            route_order[item["transport"]],
            0 if item["id"] == active_id else 1,
            item["priority"],
            item["id"],
        )
    )
    selected = enabled[0] if enabled else None
    active = next(
        (
            item
            for item in providers
            if item["id"] == normalized["active_provider_id"]
        ),
        None,
    )
    unavailable_reason = (
        str(active["reason_code"])
        if active is not None and active.get("reason_code")
        else "no_executable_provider"
        if providers
        else "no_configured_provider"
    )
    return {
        "revision": normalized["revision"],
        "active_provider_id": normalized["active_provider_id"],
        "providers": providers,
        "resolution": {
            "provider_id": selected["id"] if selected else None,
            "transport": selected["transport"] if selected else "unavailable",
            "reason": None if selected else unavailable_reason,
            "eligible_provider_ids": [item["id"] for item in enabled],
        },
    }


def load_valid_consents(
    db: Session, collection: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    current = normalize_collection(collection)
    result: dict[str, dict[str, Any]] = {}
    for profile in current["providers"]:
        if profile["transport"] == "local":
            continue
        consent = load_consent(db, profile["id"])
        if consent_matches(current, profile, consent):
            result[profile["id"]] = consent
    return result


def receipt_matches(
    profile: Mapping[str, Any], receipt: Mapping[str, Any] | None
) -> bool:
    if receipt is None:
        return False
    try:
        normalized_profile = normalize_profile(profile)
        normalized_receipt = normalize_receipt(receipt)
    except (TypeError, ValueError):
        return False
    return normalized_receipt == {
        "schema": "lomo-advisor-provider-receipt/v1",
        "provider_id": normalized_profile["id"],
        "kind": normalized_profile["transport"],
        "route": normalized_profile["transport"],
        "model": normalized_profile["model"],
        "model_digest": normalized_profile["model_digest"],
        "status": "ready",
        "tested_at": normalized_receipt["tested_at"],
        "revision": normalized_profile["config_revision"],
    }


def load_valid_receipts(
    db: Session, collection: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    current = normalize_collection(collection)
    result: dict[str, dict[str, Any]] = {}
    for profile in current["providers"]:
        receipt = load_receipt(db, profile["id"])
        if receipt_matches(profile, receipt):
            result[profile["id"]] = receipt
    return result


def resolve_candidates(collection: Mapping[str, Any], settings: Any) -> list[dict[str, Any]]:
    normalized = normalize_collection(collection)
    if normalized.get("state_error") == PROVIDER_STATE_CORRUPT:
        return []
    allowed = authorized_provider_ids(settings, normalized)
    candidates = [
        deepcopy(item)
        for item in normalized["providers"]
        if item["enabled"] and item["id"] in allowed
    ]
    route_order = {"local": 0, "direct": 1, "ssh": 2}
    active_id = normalized["active_provider_id"]
    candidates.sort(
        key=lambda item: (
            route_order[item["transport"]],
            0 if item["id"] == active_id else 1,
            item["priority"],
            item["id"],
        )
    )
    return candidates


def provider_by_id(collection: Mapping[str, Any], provider_id: str) -> dict[str, Any]:
    normalized_id = _visible_text(provider_id, name="provider id", maximum=40)
    if not PROVIDER_ID.fullmatch(normalized_id):
        raise KeyError(provider_id)
    for profile in collection["providers"]:
        if profile["id"] == normalized_id:
            return deepcopy(profile)
    raise KeyError(provider_id)


def update_provider_status(
    collection: Mapping[str, Any],
    provider_id: str,
    *,
    status: str,
    reason: str | None,
    reason_code: str | None = None,
    remediation: str = "none",
    activate: bool = False,
    approve_content_disclosure: bool = False,
    deactivate: bool = False,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError("provider status is not supported")
    current = normalize_collection(collection)
    profile = provider_by_id(current, provider_id)
    profiles = deepcopy(current["providers"])
    index = next(i for i, item in enumerate(profiles) if item["id"] == provider_id)
    profile["status"] = status
    profile["reason"] = _visible_text(reason, name="reason", maximum=240) if reason else None
    if reason_code is not None and REASON_CODE.fullmatch(reason_code) is None:
        raise ValueError("provider reason_code must be a safe typed token")
    if remediation not in REMEDIATIONS:
        raise ValueError("provider remediation is not supported")
    profile["reason_code"] = reason_code
    profile["remediation"] = remediation
    profile["last_activity_at"] = datetime.now(timezone.utc).isoformat()
    if activate:
        for other_index, other in enumerate(profiles):
            if other["id"] != provider_id and other["status"] == "active":
                demoted = deepcopy(other)
                demoted["status"] = "available"
                demoted["reason"] = "Another eligible Advisor provider was selected."
                demoted["reason_code"] = "provider_not_selected"
                demoted["remediation"] = "activate"
                demoted["last_activity_at"] = datetime.now(timezone.utc).isoformat()
                demoted["content_disclosure_approved"] = False
                profiles[other_index] = demoted
        profile["content_disclosure_approved"] = (
            profile["transport"] == "local" or approve_content_disclosure
        )
    if deactivate:
        profile["content_disclosure_approved"] = False
    profiles[index] = profile
    return normalize_collection(
        {
            "revision": current["revision"],
            "active_provider_id": (
                provider_id
                if activate
                else None
                if deactivate and current["active_provider_id"] == provider_id
                else current["active_provider_id"]
            ),
            "providers": profiles,
        }
    )


def disconnect_provider(collection: Mapping[str, Any], provider_id: str) -> dict[str, Any]:
    current = update_provider_status(
        collection,
        provider_id,
        status="disconnected",
        reason="Disconnected by the operator.",
        reason_code="operator_disconnected",
        remediation="activate",
        deactivate=True,
    )
    return current


def normalize_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "provider_id",
        "kind",
        "route",
        "model",
        "model_digest",
        "status",
        "tested_at",
        "revision",
    }
    if set(value) != required or value.get("schema") != "lomo-advisor-provider-receipt/v1":
        raise ValueError("advisor provider receipt does not match schema v1")
    provider_id = str(value.get("provider_id") or "")
    kind = str(value.get("kind") or "")
    route = str(value.get("route") or "")
    model = _visible_text(value.get("model"), name="model", maximum=120)
    digest = str(value.get("model_digest") or "").lower()
    tested_at = str(value.get("tested_at") or "")
    revision = value.get("revision")
    try:
        observed = datetime.fromisoformat(tested_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("advisor provider receipt timestamp is invalid") from exc
    if (
        PROVIDER_ID.fullmatch(provider_id) is None
        or kind not in TRANSPORTS
        or route != kind
        or MODEL_DIGEST.fullmatch(digest) is None
        or value.get("status") != "ready"
        or not tested_at.endswith("Z")
        or observed.tzinfo is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
    ):
        raise ValueError("advisor provider receipt fields are invalid")
    return {
        "schema": "lomo-advisor-provider-receipt/v1",
        "provider_id": provider_id,
        "kind": kind,
        "route": route,
        "model": model,
        "model_digest": digest,
        "status": "ready",
        "tested_at": tested_at,
        "revision": revision,
    }


def save_receipt(db: Session, value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_receipt(value)
    key = f"{PROVIDER_RECEIPT_PREFIX}{normalized['provider_id']}"
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
    item = db.get(RuntimeConfig, key)
    if item is None:
        item = RuntimeConfig(key=key, value=encoded)
    else:
        item.value = encoded
        item.updated_at = datetime.now(timezone.utc)
    db.add(item)
    db.flush()
    return normalized


def load_receipt(db: Session, provider_id: str) -> dict[str, Any] | None:
    if PROVIDER_ID.fullmatch(provider_id) is None:
        return None
    item = db.get(RuntimeConfig, f"{PROVIDER_RECEIPT_PREFIX}{provider_id}")
    if item is None:
        return None
    try:
        value = json.loads(item.value)
        if not isinstance(value, dict):
            return None
        return normalize_receipt(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def delete_receipt(db: Session, provider_id: str) -> None:
    if PROVIDER_ID.fullmatch(provider_id) is None:
        return
    item = db.get(RuntimeConfig, f"{PROVIDER_RECEIPT_PREFIX}{provider_id}")
    if item is not None:
        db.delete(item)
        db.flush()


def exact_host_set(values: Iterable[str]) -> frozenset[str]:
    result = {normalize_host(item) for item in values if str(item).strip()}
    if len(result) > MAX_PROVIDERS:
        raise ValueError(f"at most {MAX_PROVIDERS} exact advisor hosts are allowed")
    return frozenset(result)
