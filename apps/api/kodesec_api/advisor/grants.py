from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Mapping

from . import disclosure, providers


GRANT_SCHEMA = "lomo-advisor-execution-grant/v1"
GRANT_LIFETIME_SECONDS = 120
GRANT_CLOCK_SKEW_SECONDS = 5
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")


def _secret(value: object) -> bytes:
    rendered = str(value or "")
    if len(rendered) < 43 or len(rendered) > 256:
        raise ValueError("Advisor execution-grant secret is missing or weak")
    return rendered.encode("utf-8")


def _signature(secret: object, document: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(document),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(_secret(secret), encoded, hashlib.sha256).hexdigest()


def mint_execution_grant(
    secret: object,
    profile: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    prompt: str,
    *,
    operation_id: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Mint one short-lived, non-durable capability for an exact remote prompt."""

    normalized_profile = providers.normalize_profile(profile)
    normalized_confirmation = disclosure.normalize_confirmation(confirmation)
    if normalized_profile["transport"] not in {"direct", "ssh"}:
        raise ValueError("execution grants are accepted only for remote providers")
    if not isinstance(prompt, str) or not prompt:
        raise ValueError("execution grant prompt is empty")
    prompt_digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    expected = {
        "provider_id": normalized_profile["id"],
        "provider_config_revision": normalized_profile["config_revision"],
        "provider_config_digest": normalized_profile["config_digest"],
        "transport": normalized_profile["transport"],
        "model": normalized_profile["model"],
        "model_digest": normalized_profile["model_digest"],
        "prompt_sha256": prompt_digest,
    }
    if any(
        normalized_confirmation.get(key) != expected_value
        for key, expected_value in expected.items()
    ):
        raise ValueError("execution grant does not match the provider confirmation")
    issued_at = int(time.time()) if now is None else now
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 1:
        raise ValueError("execution grant time is invalid")
    nonce = operation_id or secrets.token_hex(16)
    if _OPERATION_ID.fullmatch(nonce) is None:
        raise ValueError("execution grant operation id is invalid")
    document = {
        "schema": GRANT_SCHEMA,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": issued_at + GRANT_LIFETIME_SECONDS,
        "provider_id": normalized_profile["id"],
        "provider_config_revision": normalized_profile["config_revision"],
        "provider_config_digest": normalized_profile["config_digest"],
        "transport": normalized_profile["transport"],
        "model": normalized_profile["model"],
        "model_digest": normalized_profile["model_digest"],
        "confirmation_digest": normalized_confirmation["confirmation_digest"],
        "prompt_sha256": prompt_digest,
    }
    return {**document, "signature": _signature(secret, document)}


def normalize_execution_grant(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "nonce",
        "issued_at",
        "expires_at",
        "provider_id",
        "provider_config_revision",
        "provider_config_digest",
        "transport",
        "model",
        "model_digest",
        "confirmation_digest",
        "prompt_sha256",
        "signature",
    }
    if set(value) != required or value.get("schema") != GRANT_SCHEMA:
        raise ValueError("Advisor execution grant does not match schema v1")
    nonce = str(value.get("nonce") or "")
    issued_at = value.get("issued_at")
    expires_at = value.get("expires_at")
    provider_id = str(value.get("provider_id") or "")
    provider_revision = value.get("provider_config_revision")
    provider_digest = str(value.get("provider_config_digest") or "")
    transport = str(value.get("transport") or "")
    model = str(value.get("model") or "")
    model_digest = str(value.get("model_digest") or "")
    confirmation_digest = str(value.get("confirmation_digest") or "")
    prompt_digest = str(value.get("prompt_sha256") or "")
    signature = str(value.get("signature") or "")
    if (
        _NONCE.fullmatch(nonce) is None
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at < 1
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at - issued_at != GRANT_LIFETIME_SECONDS
        or providers.PROVIDER_ID.fullmatch(provider_id) is None
        or isinstance(provider_revision, bool)
        or not isinstance(provider_revision, int)
        or provider_revision < 1
        or providers.CONFIG_DIGEST.fullmatch(provider_digest) is None
        or transport not in {"direct", "ssh"}
        or not model
        or len(model) > 120
        or providers.MODEL_DIGEST.fullmatch(model_digest) is None
        or _SHA256.fullmatch(confirmation_digest) is None
        or _SHA256.fullmatch(prompt_digest) is None
        or _SHA256.fullmatch(signature) is None
    ):
        raise ValueError("Advisor execution grant fields are invalid")
    return dict(value)


def verify_execution_grant(
    secret: object,
    value: Mapping[str, Any],
    profile: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    prompt: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify the worker-only capability and all prompt/provider bindings."""

    grant = normalize_execution_grant(value)
    signature = str(grant["signature"])
    document = {key: item for key, item in grant.items() if key != "signature"}
    if not hmac.compare_digest(signature, _signature(secret, document)):
        raise ValueError("Advisor execution grant signature is invalid")
    observed_at = int(time.time()) if now is None else now
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or grant["issued_at"] > observed_at + GRANT_CLOCK_SKEW_SECONDS
        or grant["expires_at"] <= observed_at
    ):
        raise ValueError("Advisor execution grant is expired or not yet valid")
    normalized_profile = providers.normalize_profile(profile)
    normalized_confirmation = disclosure.normalize_confirmation(confirmation)
    prompt_digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    expected = {
        "provider_id": normalized_profile["id"],
        "provider_config_revision": normalized_profile["config_revision"],
        "provider_config_digest": normalized_profile["config_digest"],
        "transport": normalized_profile["transport"],
        "model": normalized_profile["model"],
        "model_digest": normalized_profile["model_digest"],
        "confirmation_digest": normalized_confirmation["confirmation_digest"],
        "prompt_sha256": prompt_digest,
    }
    if any(grant.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("Advisor execution grant binding is invalid")
    return grant


CANCELLATION_GRANT_SCHEMA = "lomo-advisor-cancellation-grant/v1"


def mint_cancellation_grant(
    secret: object,
    profile: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    operation_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Mint a fresh recovery-safe capability for one connector operation."""

    normalized_profile = providers.normalize_profile(profile)
    normalized_confirmation = disclosure.normalize_confirmation(confirmation)
    if _OPERATION_ID.fullmatch(operation_id) is None:
        raise ValueError("cancellation grant operation id is invalid")
    issued_at = int(time.time()) if now is None else now
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 1:
        raise ValueError("cancellation grant time is invalid")
    document = {
        "schema": CANCELLATION_GRANT_SCHEMA,
        "operation_id": operation_id,
        "issued_at": issued_at,
        "expires_at": issued_at + GRANT_LIFETIME_SECONDS,
        "provider_id": normalized_profile["id"],
        "provider_config_revision": normalized_profile["config_revision"],
        "provider_config_digest": normalized_profile["config_digest"],
        "transport": normalized_profile["transport"],
        "model_digest": normalized_profile["model_digest"],
        "confirmation_digest": normalized_confirmation["confirmation_digest"],
    }
    return {**document, "signature": _signature(secret, document)}


def verify_cancellation_grant(
    secret: object,
    value: Mapping[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    required = {
        "schema",
        "operation_id",
        "issued_at",
        "expires_at",
        "provider_id",
        "provider_config_revision",
        "provider_config_digest",
        "transport",
        "model_digest",
        "confirmation_digest",
        "signature",
    }
    if set(value) != required or value.get("schema") != CANCELLATION_GRANT_SCHEMA:
        raise ValueError("Advisor cancellation grant does not match schema v1")
    operation_id = str(value.get("operation_id") or "")
    issued_at = value.get("issued_at")
    expires_at = value.get("expires_at")
    provider_id = str(value.get("provider_id") or "")
    revision = value.get("provider_config_revision")
    provider_digest = str(value.get("provider_config_digest") or "")
    transport = str(value.get("transport") or "")
    model_digest = str(value.get("model_digest") or "")
    confirmation_digest = str(value.get("confirmation_digest") or "")
    signature = str(value.get("signature") or "")
    if (
        _OPERATION_ID.fullmatch(operation_id) is None
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at - issued_at != GRANT_LIFETIME_SECONDS
        or providers.PROVIDER_ID.fullmatch(provider_id) is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or providers.CONFIG_DIGEST.fullmatch(provider_digest) is None
        or transport not in {"direct", "ssh"}
        or providers.MODEL_DIGEST.fullmatch(model_digest) is None
        or _SHA256.fullmatch(confirmation_digest) is None
        or _SHA256.fullmatch(signature) is None
    ):
        raise ValueError("Advisor cancellation grant fields are invalid")
    document = {key: item for key, item in value.items() if key != "signature"}
    if not hmac.compare_digest(signature, _signature(secret, document)):
        raise ValueError("Advisor cancellation grant signature is invalid")
    observed_at = int(time.time()) if now is None else now
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or issued_at > observed_at + GRANT_CLOCK_SKEW_SECONDS
        or expires_at <= observed_at
    ):
        raise ValueError("Advisor cancellation grant is expired or not yet valid")
    return dict(value)


LOCAL_OPERATION_SCHEMA = "lomo-advisor-local-operation/v1"
LOCAL_CANCELLATION_SCHEMA = "lomo-advisor-local-cancellation/v1"
LOCAL_OBSERVATION_SCHEMA = "lomo-advisor-local-observation/v1"
_LOCAL_BINDING_KEYS = frozenset({
    "provider_id", "provider_config_revision", "provider_config_digest",
    "transport", "model", "model_digest", "prompt_sha256",
})


def normalize_local_operation_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate credential-free local ownership; this is not disclosure consent."""
    if set(value) != _LOCAL_BINDING_KEYS:
        raise ValueError("Local Advisor operation binding fields are invalid")
    revision = value["provider_config_revision"]
    model = value["model"]
    if (
        value["transport"] != "local"
        or not isinstance(value["provider_id"], str)
        or providers.PROVIDER_ID.fullmatch(value["provider_id"]) is None
        or isinstance(revision, bool) or not isinstance(revision, int) or revision < 1
        or not isinstance(model, str) or not model or len(model) > 120
        or any(
            not isinstance(value[key], str) or _SHA256.fullmatch(value[key]) is None
            for key in ("provider_config_digest", "model_digest", "prompt_sha256")
        )
    ):
        raise ValueError("Local Advisor operation binding is invalid")
    return dict(value)


def local_operation_binding(profile: Mapping[str, Any], prompt_sha256: str) -> dict[str, Any]:
    normalized = providers.normalize_profile(profile)
    return normalize_local_operation_binding({
        "provider_id": normalized["id"],
        "provider_config_revision": normalized["config_revision"],
        "provider_config_digest": normalized["config_digest"],
        "transport": normalized["transport"],
        "model": normalized["model"],
        "model_digest": normalized["model_digest"],
        "prompt_sha256": prompt_sha256,
    })


def _mint_local_capability(
    secret: object, binding: Mapping[str, Any], operation_id: str,
    *, schema: str, now: int | None,
) -> dict[str, Any]:
    binding = normalize_local_operation_binding(binding)
    if not isinstance(operation_id, str) or _OPERATION_ID.fullmatch(operation_id) is None:
        raise ValueError("Local Advisor operation identity is invalid")
    issued_at = int(time.time()) if now is None else now
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 1:
        raise ValueError("Local Advisor capability time is invalid")
    identity_key = "nonce" if schema == LOCAL_OPERATION_SCHEMA else "operation_id"
    document = {
        "schema": schema, identity_key: operation_id,
        "issued_at": issued_at, "expires_at": issued_at + GRANT_LIFETIME_SECONDS,
        **binding,
    }
    return {**document, "signature": _signature(secret, document)}


def _verify_local_capability(
    secret: object, value: Mapping[str, Any], *, schema: str, now: int | None,
) -> dict[str, Any]:
    identity_key = "nonce" if schema == LOCAL_OPERATION_SCHEMA else "operation_id"
    required = _LOCAL_BINDING_KEYS | {
        "schema", identity_key, "issued_at", "expires_at", "signature",
    }
    if set(value) != required or value.get("schema") != schema:
        raise ValueError("Local Advisor capability schema is invalid")
    normalize_local_operation_binding({key: value[key] for key in _LOCAL_BINDING_KEYS})
    identity = value[identity_key]
    issued_at, expires_at = value["issued_at"], value["expires_at"]
    signature = value["signature"]
    observed_at = int(time.time()) if now is None else now
    if (
        not isinstance(identity, str) or _OPERATION_ID.fullmatch(identity) is None
        or isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 1
        or isinstance(expires_at, bool) or not isinstance(expires_at, int)
        or expires_at - issued_at != GRANT_LIFETIME_SECONDS
        or not isinstance(signature, str) or _SHA256.fullmatch(signature) is None
        or isinstance(observed_at, bool) or not isinstance(observed_at, int)
        or issued_at > observed_at + GRANT_CLOCK_SKEW_SECONDS or expires_at <= observed_at
    ):
        raise ValueError("Local Advisor capability fields or lifetime are invalid")
    document = {key: item for key, item in value.items() if key != "signature"}
    if not hmac.compare_digest(signature, _signature(secret, document)):
        raise ValueError("Local Advisor capability signature is invalid")
    return dict(value)


def mint_local_operation_grant(
    secret: object, profile: Mapping[str, Any], prompt: str,
    *, operation_id: str | None = None, now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(prompt, str) or not prompt:
        raise ValueError("Local Advisor operation prompt is empty")
    binding = local_operation_binding(profile, hashlib.sha256(prompt.encode("utf-8")).hexdigest())
    return _mint_local_capability(
        secret, binding, operation_id or secrets.token_hex(16),
        schema=LOCAL_OPERATION_SCHEMA, now=now,
    )


def verify_local_operation_grant(
    secret: object, value: Mapping[str, Any], profile: Mapping[str, Any], prompt: str,
    *, now: int | None = None,
) -> dict[str, Any]:
    grant = _verify_local_capability(secret, value, schema=LOCAL_OPERATION_SCHEMA, now=now)
    expected = local_operation_binding(profile, hashlib.sha256(prompt.encode("utf-8")).hexdigest())
    if any(grant[key] != item for key, item in expected.items()):
        raise ValueError("Local Advisor operation binding changed")
    return grant


def mint_local_cancellation_grant(
    secret: object, binding: Mapping[str, Any], operation_id: str,
    *, now: int | None = None,
) -> dict[str, Any]:
    return _mint_local_capability(
        secret, binding, operation_id, schema=LOCAL_CANCELLATION_SCHEMA, now=now,
    )


def verify_local_cancellation_grant(
    secret: object, value: Mapping[str, Any], *, now: int | None = None,
) -> dict[str, Any]:
    return _verify_local_capability(secret, value, schema=LOCAL_CANCELLATION_SCHEMA, now=now)


def mint_local_observation_grant(
    secret: object, binding: Mapping[str, Any], operation_id: str,
    *, now: int | None = None,
) -> dict[str, Any]:
    """Authorize only a read of one already-owned local operation."""
    return _mint_local_capability(
        secret, binding, operation_id, schema=LOCAL_OBSERVATION_SCHEMA, now=now,
    )


def verify_local_observation_grant(
    secret: object, value: Mapping[str, Any], *, now: int | None = None,
) -> dict[str, Any]:
    return _verify_local_capability(secret, value, schema=LOCAL_OBSERVATION_SCHEMA, now=now)
