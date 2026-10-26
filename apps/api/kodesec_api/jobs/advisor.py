from __future__ import annotations

import asyncio
import json
import math
import re
import time
from typing import Any, Callable
import unicodedata

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import main as domain
from ..advisor import disclosure as advisor_disclosure
from ..advisor import grants as advisor_grants
from ..advisor import providers as advisor_providers
from ..metrics import advisor_duration
from ..models import Finding, Project, Scan
from ..settings import Settings
from .repository import lock_advisor_admission


_ADVISOR_RESPONSE_MAX_BYTES = 16 * 1024
_CONNECTOR_RESPONSE_MAX_BYTES = 64 * 1024
_ADVISOR_RESULT_KEYS = frozenset({"verdict", "confidence", "reasoning", "fix"})
_ADVISOR_VERDICTS = frozenset({"true_positive", "false_positive", "needs_review"})
_ADVISOR_MULTILINE_MAX_CHARS = 4000
_ADVISOR_UNSAFE_MULTILINE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_ADVISOR_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_ADVISOR_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_review"],
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {"type": "string", "maxLength": 4000},
        "fix": {"type": "string", "maxLength": 4000},
    },
    "required": ["verdict", "confidence", "reasoning", "fix"],
    "additionalProperties": False,
}


class ConnectorCleanupUnconfirmed(RuntimeError):
    """Keep a durable cancellation non-terminal until connector cleanup is proven."""


class ConnectorRequestError(HTTPException):
    """One bounded, typed connector failure safe to cross into durable state."""

    def __init__(self, status_code: int, code: str) -> None:
        detail, retryable = advisor_providers.provider_test_failure(code)
        super().__init__(status_code, detail)
        self.code = code
        self.safe_detail = detail
        self.retryable = retryable


class ProviderTestFailure(HTTPException):
    """Canonical provider-test failure consumed by worker execution."""

    def __init__(self, status_code: int, code: str) -> None:
        detail, retryable = advisor_providers.provider_test_failure(code)
        super().__init__(status_code, detail)
        self.code = code
        self.safe_detail = detail
        self.retryable = retryable


class AdvisorResultValidationError(ValueError):
    """Reject one untrusted model result before any review state is changed."""


def _connector_failure(status_code: int, raw_body: bytes) -> ConnectorRequestError:
    try:
        document = json.loads(
            raw_body,
            object_pairs_hook=_json_object_without_duplicate_keys,
            parse_constant=_reject_non_json_numeric_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ConnectorRequestError(502, "advisor_connector_protocol")
    detail = document.get("detail") if isinstance(document, dict) else None
    if not isinstance(detail, dict) or set(detail) != {"code", "message"}:
        return ConnectorRequestError(502, "advisor_connector_protocol")
    code = detail.get("code")
    message = detail.get("message")
    if not isinstance(code, str) or not isinstance(message, str):
        return ConnectorRequestError(502, "advisor_connector_protocol")
    try:
        expected, _retryable = advisor_providers.provider_test_failure(code)
    except ValueError:
        return ConnectorRequestError(502, "advisor_connector_protocol")
    if message != expected:
        return ConnectorRequestError(502, "advisor_connector_protocol")
    return ConnectorRequestError(status_code, code)


def _json_object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("advisor response contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_non_json_numeric_constant(_value: str) -> None:
    raise ValueError("advisor response contains a non-JSON numeric constant")


def _ollama_payload(prompt: str, model: str, thinking: bool) -> dict[str, Any]:
    return {
        "model": model,
        "prompt": prompt,
        # Ollama accepts a JSON Schema object here. Keep the strict parser below
        # as the publication boundary: a model or older runtime can still fail
        # to honor generation constraints, but it can never weaken admission.
        "format": _ADVISOR_OUTPUT_SCHEMA,
        "stream": False,
        "think": thinking,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 700,
            "num_ctx": 8192,
        },
    }


def _parse_json_response(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if not raw or len(raw.encode("utf-8")) > _ADVISOR_RESPONSE_MAX_BYTES:
        raise ValueError("advisor response is empty or exceeds the bounded response size")
    parsed = json.loads(
        raw,
        object_pairs_hook=_json_object_without_duplicate_keys,
        parse_constant=_reject_non_json_numeric_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError("advisor response must be a JSON object")
    return parsed


def _normalize_advisor_multiline(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AdvisorResultValidationError(f"advisor {field} must be text")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized) > _ADVISOR_MULTILINE_MAX_CHARS:
        raise AdvisorResultValidationError(
            f"advisor {field} exceeds {_ADVISOR_MULTILINE_MAX_CHARS} characters"
        )
    if any(
        character not in {"\n", "\t"}
        and unicodedata.category(character) in _ADVISOR_UNSAFE_MULTILINE_CATEGORIES
        for character in normalized
    ):
        raise AdvisorResultValidationError(
            f"advisor {field} contains unsafe control or formatting characters"
        )
    return normalized


def _validate_advisor_result(parsed: dict[str, Any]) -> tuple[str, float, str, str]:
    if set(parsed) != _ADVISOR_RESULT_KEYS:
        raise AdvisorResultValidationError(
            "advisor response must contain exactly verdict, confidence, reasoning, and fix"
        )

    verdict = parsed["verdict"]
    if not isinstance(verdict, str) or verdict not in _ADVISOR_VERDICTS:
        raise AdvisorResultValidationError("advisor verdict is not supported")

    raw_confidence = parsed["confidence"]
    if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
        raise AdvisorResultValidationError("advisor confidence must be a number")
    confidence = float(raw_confidence)
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise AdvisorResultValidationError(
            "advisor confidence must be finite and between zero and one"
        )

    reasoning = _normalize_advisor_multiline(parsed["reasoning"], "reasoning")
    fix = _normalize_advisor_multiline(parsed["fix"], "fix")
    return verdict, confidence, reasoning, fix


def worker_ollama_available_sync(
    config: dict[str, Any],
    timeout: float = 1.5,
    settings: Settings | None = None,
) -> tuple[bool, list[str], str | None]:
    """Probe the same-device advisor from the worker process only."""

    if config["ai_mode"] == "off":
        return False, [], "disabled"
    if settings is None:
        return False, [], "provider_settings_missing"
    raw_collection = config.get("advisor_providers")
    if not isinstance(raw_collection, dict):
        return False, [], "provider_configuration_missing"
    if (
        raw_collection.get("state_error")
        == advisor_providers.PROVIDER_STATE_CORRUPT
    ):
        return False, [], advisor_providers.PROVIDER_STATE_CORRUPT
    try:
        collection = advisor_providers.normalize_collection(raw_collection)
        candidates = advisor_providers.resolve_candidates(collection, settings)
    except ValueError:
        return False, [], "provider_configuration_invalid"
    if not collection["providers"]:
        return False, [], "no_provider_configured"
    if not candidates:
        return False, [], "no_authorized_provider"
    for profile in candidates:
        if profile["transport"] != "local":
            continue
        try:
            test_provider_sync(profile, settings, timeout=max(timeout, 3.0))
            return True, [str(profile["model"])], None
        except ProviderTestFailure:
            continue
    if any(profile["transport"] in {"direct", "ssh"} for profile in candidates):
        public = advisor_providers.public_collection(
            collection,
            settings,
            config.get("advisor_provider_consents", {}),
            config.get("advisor_provider_receipts", {}),
        )
        return False, [], str(
            public["resolution"]["reason"]
            or "remote_single_finding_confirmation_required"
        )
    return False, [], "provider_unavailable"


async def _connector_json_async(
    settings: Settings,
    path: str,
    document: dict[str, Any],
    *,
    timeout: float,
    cancel_check: Any | None = None,
) -> dict[str, Any]:
    base = settings.advisor_connector_url.rstrip("/")
    request_timeout = httpx.Timeout(
        timeout,
        connect=min(timeout, 3.0),
        read=timeout,
        write=min(timeout, 5.0),
        pool=min(timeout, 3.0),
    )
    async def exchange() -> bytes:
        body = bytearray()
        async with httpx.AsyncClient(
            timeout=request_timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client, client.stream(
            "POST", f"{base}{path}", json=document
        ) as response:
            if response.is_redirect:
                raise ValueError("redirects are forbidden")
            declared = response.headers.get("content-length")
            if declared is not None and int(declared) > _CONNECTOR_RESPONSE_MAX_BYTES:
                raise ValueError("connector response exceeds the bounded size")
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _CONNECTOR_RESPONSE_MAX_BYTES:
                    raise ValueError("connector response exceeds the bounded size")
            if response.is_error:
                raise _connector_failure(response.status_code, bytes(body))
        return bytes(body)

    task = asyncio.create_task(exchange())
    cancellation_failure: Exception | None = None
    try:
        async with asyncio.timeout(timeout):
            while not task.done():
                await asyncio.sleep(0.1)
                if cancel_check is not None:
                    try:
                        cancel_check()
                    except Exception as exc:
                        cancellation_failure = exc
                        break
            if cancellation_failure is not None:
                grant = document.get("grant")
                confirmation = document.get("confirmation")
                profile = document.get("provider")
                if (
                    path == "/v1/generate"
                    and isinstance(grant, dict)
                    and (confirmation is None or isinstance(confirmation, dict))
                    and isinstance(profile, dict)
                ):
                    await _cancel_connector_operation_async(
                        settings,
                        profile,
                        confirmation,
                        str(grant.get("nonce") or ""),
                        **({"local_binding": advisor_grants.local_operation_binding(
                            profile, grant["prompt_sha256"],
                        )} if profile.get("transport") == "local" else {}),
                    )
                    try:
                        await task
                    except (httpx.HTTPStatusError, ConnectorRequestError):
                        # The authenticated cleanup receipt above is the
                        # authoritative terminal boundary. The original
                        # generation exchange may end as cancelled or failed
                        # depending on which terminal event won the race.
                        # exchange() normalizes HTTP failures into our typed
                        # error, including the connector's expected HTTP499.
                        pass
                else:
                    # Non-generation calls have no owned provider generation.
                    await task
                raise cancellation_failure
            raw_body = await task
    except TimeoutError as exc:
        raise HTTPException(504, "Advisor connector exceeded the absolute deadline") from exc
    except ConnectorRequestError:
        raise
    except (httpx.HTTPError, OSError, ValueError) as exc:
        raise HTTPException(
            503,
            domain._redacted_text(
                f"Advisor connector request failed: {type(exc).__name__}"
            ),
        ) from exc
    finally:
        if not task.done():
            task.cancel()
        try:
            await task
        except BaseException:
            pass
    try:
        result = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(502, "Advisor connector returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise HTTPException(502, "Advisor connector returned a non-object response")
    return result


async def _cancel_connector_operation_async(
    settings: Settings,
    profile: dict[str, Any],
    confirmation: dict[str, Any] | None,
    operation_id: str,
    *, local_binding: dict[str, Any] | None = None,
) -> dict[str, str]:
    if _ADVISOR_OPERATION_ID.fullmatch(operation_id) is None:
        raise ConnectorCleanupUnconfirmed("Advisor connector operation identity is invalid")
    cancellation_grant = (
        advisor_grants.mint_local_cancellation_grant(
            settings.advisor_grant_secret, local_binding, operation_id,
        ) if local_binding is not None else advisor_grants.mint_cancellation_grant(
            settings.advisor_grant_secret, profile, confirmation, operation_id,
        )
    )
    base = settings.advisor_connector_url.rstrip("/")
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=3.0, read=20.0, write=5.0, pool=3.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"{base}/v1/cancel",
                json={"cancellation_grant": cancellation_grant},
            )
            if response.is_redirect:
                raise ValueError("redirects are forbidden")
            response.raise_for_status()
            if len(response.content) > _CONNECTOR_RESPONSE_MAX_BYTES:
                raise ValueError("connector cancellation response exceeds the bounded size")
            receipt = response.json()
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise ConnectorCleanupUnconfirmed(
            "Advisor connector cleanup could not be confirmed"
        ) from exc
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"operation_id", "status", "cleanup"}
        or receipt.get("operation_id") != operation_id
        or receipt.get("status") not in {"cancelled", "completed", "failed", "not_active"}
        or receipt.get("cleanup") != "confirmed"
    ):
        raise ConnectorCleanupUnconfirmed(
            "Advisor connector returned an invalid cleanup receipt"
        )
    return {
        "operation_id": operation_id,
        "status": str(receipt["status"]),
        "cleanup": "confirmed",
    }


def cancel_remote_operation_sync(
    profile: dict[str, Any],
    confirmation: dict[str, Any],
    operation_id: str,
    settings: Settings,
) -> dict[str, str]:
    return asyncio.run(
        _cancel_connector_operation_async(
            settings, profile, confirmation, operation_id
        )
    )


def cancel_local_operation_sync(
    binding: dict[str, Any], operation_id: str, settings: Settings,
) -> dict[str, str]:
    return asyncio.run(_cancel_connector_operation_async(
        settings, {}, None, operation_id, local_binding=binding,
    ))


def _connector_json(
    settings: Settings,
    path: str,
    document: dict[str, Any],
    *,
    timeout: float,
    cancel_check: Any | None = None,
) -> dict[str, Any]:
    """Run one connector request under an absolute wall-clock deadline."""

    return asyncio.run(
        _connector_json_async(
            settings,
            path,
            document,
            timeout=timeout,
            cancel_check=cancel_check,
        )
    )


def test_provider_sync(
    profile: dict[str, Any], settings: Settings, *, timeout: float = 10.0
) -> dict[str, Any]:
    """Test route/model identity without sending source or finding content."""

    normalized = advisor_providers.normalize_profile(profile)
    try:
        response = _connector_json(
            settings, "/v1/test", {"provider": normalized}, timeout=timeout
        )
    except ConnectorRequestError as exc:
        raise ProviderTestFailure(exc.status_code, exc.code) from exc
    receipt = response.get("receipt")
    expected = {
        "schema": "lomo-advisor-provider-receipt/v1",
        "provider_id": normalized["id"],
        "kind": normalized["transport"],
        "route": normalized["transport"],
        "model": normalized["model"],
        "model_digest": normalized["model_digest"],
        "status": "ready",
    }
    if not isinstance(receipt, dict) or set(receipt) != {
        *expected.keys(),
        "tested_at",
        "revision",
    } or any(receipt.get(key) != value for key, value in expected.items()):
        raise ProviderTestFailure(502, "advisor_provider_receipt_invalid")
    tested_at = receipt.get("tested_at")
    revision = receipt.get("revision")
    if (
        not isinstance(tested_at, str)
        or not tested_at.endswith("Z")
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
    ):
        raise ProviderTestFailure(502, "advisor_provider_receipt_invalid")
    return {**expected, "tested_at": tested_at, "revision": revision}


async def detect_local_models(
    settings: Settings, *, timeout: float = 10.0
) -> dict[str, Any]:
    """Read only the dedicated connector's same-device Ollama catalog."""

    try:
        catalog = await _connector_json_async(
            settings,
            "/v1/local-models",
            {},
            timeout=timeout,
        )
    except ConnectorRequestError:
        raise
    except HTTPException as exc:
        raise ConnectorRequestError(
            exc.status_code, "advisor_connector_unavailable"
        ) from exc
    if (
        set(catalog) != {"schema", "source", "models", "recommended_model"}
        or catalog.get("schema") != "lomo-advisor-local-catalog/v1"
        or catalog.get("source") != "dedicated_local_connector"
        or not isinstance(catalog.get("models"), list)
        or len(catalog["models"]) > 200
    ):
        raise ConnectorRequestError(502, "advisor_connector_protocol")
    normalized_models: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for item in catalog["models"]:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "digest",
            "size_bytes",
            "storage",
        }:
            raise ConnectorRequestError(502, "advisor_connector_protocol")
        name = item.get("name")
        digest = item.get("digest")
        size = item.get("size_bytes")
        storage = item.get("storage")
        if (
            not isinstance(name, str)
            or not 0 < len(name) <= 120
            or any(
                unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"}
                for character in name
            )
            or name in seen_names
            or not isinstance(digest, str)
            or advisor_providers.MODEL_DIGEST.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            # The catalog crosses a JSON/TypeScript boundary. Keep numeric
            # evidence exactly representable by every supported client.
            or not 0 <= size <= 9_007_199_254_740_991
            or storage not in {"local_weights", "cloud_stub"}
            or storage == "local_weights" and size == 0
        ):
            raise ConnectorRequestError(502, "advisor_connector_protocol")
        seen_names.add(name)
        normalized_models.append(dict(item))
    recommended = catalog.get("recommended_model")
    if recommended is not None and not any(
        item["name"] == recommended and item["storage"] == "local_weights"
        for item in normalized_models
    ):
        raise ConnectorRequestError(502, "advisor_connector_protocol")
    return {
        "schema": "lomo-advisor-local-catalog/v1",
        "source": "dedicated_local_connector",
        "models": normalized_models,
        "recommended_model": recommended,
    }


def detect_local_models_sync(
    settings: Settings, *, timeout: float = 10.0
) -> dict[str, Any]:
    """Run local discovery from the worker's independent receipt publisher."""

    return asyncio.run(detect_local_models(settings, timeout=timeout))


def resolve_provider_sync(
    config: dict[str, Any], settings: Settings, *, timeout: float = 10.0
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    collection = config.get("advisor_providers")
    if not isinstance(collection, dict):
        return None, None, "provider_configuration_missing"
    if collection.get("state_error") == advisor_providers.PROVIDER_STATE_CORRUPT:
        return None, None, advisor_providers.PROVIDER_STATE_CORRUPT
    try:
        advisor_providers.normalize_collection(collection)
    except ValueError:
        return None, None, "provider_configuration_invalid"
    raw_receipts = config.get("advisor_provider_receipts", {})
    receipts = raw_receipts if isinstance(raw_receipts, dict) else {}
    raw_consents = config.get("advisor_provider_consents", {})
    consents = raw_consents if isinstance(raw_consents, dict) else {}
    public = advisor_providers.public_collection(
        collection, settings, consents, receipts
    )
    selected_id = public["resolution"]["provider_id"]
    if selected_id is None:
        return None, None, str(public["resolution"]["reason"])
    try:
        profile = advisor_providers.provider_by_id(collection, selected_id)
    except KeyError:
        return None, None, "provider_configuration_invalid"
    # Automatic and scan-wide resolution remains local-only. Remote execution
    # enters through the separately confirmed one-finding path below.
    if profile["transport"] != "local":
        return None, None, "remote_single_finding_confirmation_required"
    try:
        return profile, test_provider_sync(profile, settings, timeout=timeout), None
    except ProviderTestFailure:
        return None, None, "provider_unavailable"


def revalidate_local_provider_sync(
    db: Session,
    profile: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    """Fence one queued local selection against live durable state.

    The provider configuration row remains locked through prompt transmission
    and publication in the caller's transaction, so an edit, disconnect, or
    receipt invalidation cannot race after this check.
    """

    snapshot = advisor_providers.normalize_profile(profile)
    current = advisor_providers.load_collection(db, settings, lock=True)
    if current.get("state_error") == advisor_providers.PROVIDER_STATE_CORRUPT:
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_configuration_corrupt",
                "Advisor provider configuration is corrupt; no prompt was sent.",
                action="repair_advisor_provider_configuration",
                context={"provider_id": snapshot["id"]},
                safe_details={
                    "provider_id": snapshot["id"],
                    "reason_code": advisor_providers.PROVIDER_STATE_CORRUPT,
                },
            ),
        )
    try:
        live = advisor_providers.provider_by_id(current, snapshot["id"])
    except KeyError as exc:
        raise HTTPException(409, "Advisor provider was removed before execution") from exc
    receipt = advisor_providers.load_receipt(db, live["id"])
    public = advisor_providers.public_collection(
        current,
        settings,
        {},
        {live["id"]: receipt} if receipt is not None else {},
    )
    if (
        live["transport"] != "local"
        or any(
            live[key] != snapshot[key]
            for key in ("id", "config_revision", "config_digest", "model", "model_digest")
        )
        or public["resolution"]["provider_id"] != live["id"]
        or not advisor_providers.receipt_matches(live, receipt)
    ):
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_configuration_changed",
                "Advisor provider changed or became unavailable before execution; no prompt was sent.",
                action="refresh_advisor_providers",
                context={"provider_id": snapshot["id"]},
                safe_details={
                    "provider_id": snapshot["id"],
                    "current_revision": live["config_revision"],
                },
            ),
        )
    return live


def revalidate_remote_provider_sync(
    db: Session,
    profile: dict[str, Any],
    settings: Settings,
    confirmation: dict[str, Any],
    *,
    finding_id: int,
    finding_revision: int,
    packet: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Fence one explicit remote disclosure against live durable provider state."""

    snapshot = advisor_providers.normalize_profile(profile)
    lock_advisor_admission(db)
    current = advisor_providers.load_collection(db, settings, lock=True)
    try:
        live = advisor_providers.provider_by_id(current, snapshot["id"])
    except KeyError as exc:
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_source_disclosure_confirmation_stale",
                "The confirmed remote Advisor provider was removed; no prompt was sent.",
                action="preview_advisor_source_disclosure",
                context={"finding_id": finding_id, "provider_id": snapshot["id"]},
                safe_details={
                    "provider_id": snapshot["id"],
                    "current_revision": finding_revision,
                },
            ),
        ) from exc
    consent = advisor_providers.load_consent(db, live["id"])
    receipt = advisor_providers.load_receipt(db, live["id"])
    exact_profile = all(
        live[key] == snapshot[key]
        for key in (
            "id",
            "transport",
            "config_revision",
            "config_digest",
            "model",
            "model_digest",
        )
    )
    current_confirmation = bool(
        exact_profile
        and live["transport"] in {"direct", "ssh"}
        and live["enabled"]
        and live["status"] == "active"
        and current["active_provider_id"] == live["id"]
        and live["id"] in advisor_providers.authorized_provider_ids(settings, current)
        and advisor_providers.receipt_matches(live, receipt)
        and consent is not None
        and advisor_disclosure.confirmation_matches(
            current,
            live,
            consent,
            confirmation,
            finding_id=finding_id,
            finding_revision=finding_revision,
            packet=packet,
        )
    )
    if not current_confirmation:
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_source_disclosure_confirmation_stale",
                "The remote Advisor confirmation no longer matches the exact provider, consent, receipt, or finding; no prompt was sent.",
                action="preview_advisor_source_disclosure",
                context={"finding_id": finding_id, "provider_id": snapshot["id"]},
                safe_details={
                    "provider_id": snapshot["id"],
                    "current_revision": finding_revision,
                },
            ),
        )
    return live, current, consent


def generate_with_provider_sync(
    profile: dict[str, Any],
    request_payload: dict[str, Any],
    settings: Settings,
    *,
    remote_confirmation: dict[str, Any] | None = None,
    operation_id: str | None = None,
    cancel_check: Any | None = None,
    reserve_local_operation: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Send one prompt only through its exact locally fenced provider route."""

    normalized = advisor_providers.normalize_profile(profile)
    if normalized["transport"] == "local" and remote_confirmation is not None:
        raise HTTPException(409, "Local Advisor generation does not accept remote confirmation.")
    if normalized["transport"] in {"direct", "ssh"} and remote_confirmation is None:
        raise HTTPException(
            409,
            "Remote Advisor source disclosure is not authorized for this request.",
        )
    if remote_confirmation is not None and (
        not isinstance(operation_id, str)
        or _ADVISOR_OPERATION_ID.fullmatch(operation_id) is None
    ):
        raise HTTPException(409, "Remote Advisor operation identity is invalid.")
    if remote_confirmation is None and operation_id is not None:
        raise HTTPException(409, "Local Advisor generation does not accept a remote operation id.")
    execution_grant = (
        advisor_grants.mint_execution_grant(
            settings.advisor_grant_secret,
            normalized,
            remote_confirmation,
            str(request_payload.get("prompt") or ""),
            operation_id=operation_id,
        )
        if remote_confirmation is not None
        else advisor_grants.mint_local_operation_grant(
            settings.advisor_grant_secret, normalized, str(request_payload.get("prompt") or ""),
        )
    )
    if remote_confirmation is None:
        operation_id = execution_grant["nonce"]
        if reserve_local_operation is not None:
            reserve_local_operation({
                "advisor_operation_id": operation_id,
                "binding": advisor_grants.local_operation_binding(
                    normalized, execution_grant["prompt_sha256"],
                ),
            })
    document = {
        "provider": normalized,
        "request": request_payload,
        "confirmation": remote_confirmation,
        "grant": execution_grant,
    }
    if execution_grant is not None:
        admission = _connector_json(
            settings,
            "/v1/operations",
            document,
            timeout=8.0,
        )
        if admission != {"operation_id": operation_id, "status": "admitted"}:
            raise HTTPException(502, "Advisor connector operation admission is invalid")
        if cancel_check is not None:
            try:
                cancel_check()
            except Exception:
                if remote_confirmation is None:
                    cancel_local_operation_sync(
                        advisor_grants.local_operation_binding(normalized, execution_grant["prompt_sha256"]),
                        str(operation_id), settings,
                    )
                else:
                    cancel_remote_operation_sync(
                        normalized, remote_confirmation, str(operation_id), settings,
                    )
                raise
    response = _connector_json(
        settings,
        "/v1/generate",
        document,
        timeout=95.0,
        cancel_check=cancel_check,
    )
    if not isinstance(response.get("response"), str):
        raise HTTPException(502, "Advisor connector response does not contain text")
    return response


def triage_finding_sync(
    db: Session,
    finding: Finding,
    settings: Settings,
    model: str | None = None,
    config: dict[str, Any] | None = None,
    *,
    expected_revision: int | None = None,
    commit: bool = True,
    cancel_check: Any | None = None,
    reserve_local_operation: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute one bounded advisor request from a leased worker."""

    input_revision = int(finding.revision)
    if expected_revision is not None and input_revision != expected_revision:
        raise HTTPException(
            409,
            domain._problem_detail(
                "revision_conflict",
                "The selected finding changed before Advisor review started.",
                action="refresh_findings",
                context={
                    "finding_id": finding.id,
                    "expected_revision": expected_revision,
                    "current_revision": input_revision,
                },
            ),
        )

    scan = db.get(Scan, finding.scan_id)
    project = db.get(Project, scan.project_id) if scan else None
    if not scan or not project:
        raise HTTPException(404, "finding context not found")
    if finding.suppressed:
        raise HTTPException(409, "advisor triage accepts active findings only")

    if not isinstance(config, dict):
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_snapshot_missing",
                "Advisor job configuration is missing; no prompt was sent.",
                action="refresh_advisor_providers",
                context={"finding_id": finding.id},
                safe_details={"current_revision": input_revision},
            ),
        )
    active_config = dict(config)
    if cancel_check is not None:
        cancel_check()
    resolved_profile: dict[str, Any] | None = None
    remote_confirmation: dict[str, Any] | None = None
    raw_remote_confirmation = active_config.get("remote_advisor_confirmation")
    if raw_remote_confirmation is not None:
        if not isinstance(raw_remote_confirmation, dict):
            raise HTTPException(409, "Remote Advisor confirmation is invalid; no prompt was sent.")
        try:
            remote_confirmation = advisor_disclosure.normalize_confirmation(
                raw_remote_confirmation
            )
        except ValueError as exc:
            raise HTTPException(
                409, "Remote Advisor confirmation is invalid; no prompt was sent."
            ) from exc
    raw_provider_collection = active_config.get("advisor_providers")
    if not isinstance(raw_provider_collection, dict):
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_snapshot_missing",
                "Advisor provider snapshot is missing; no prompt was sent.",
                action="refresh_advisor_providers",
                context={"finding_id": finding.id},
                safe_details={"current_revision": input_revision},
            ),
        )
    if (
        raw_provider_collection.get("state_error")
        == advisor_providers.PROVIDER_STATE_CORRUPT
    ):
        raise HTTPException(
            503,
            domain._problem_detail(
                "advisor_provider_configuration_corrupt",
                "Advisor provider configuration is corrupt; no prompt was sent.",
                action="repair_advisor_provider_configuration",
                context={"finding_id": finding.id},
                safe_details={
                    "reason_code": advisor_providers.PROVIDER_STATE_CORRUPT,
                    "current_revision": input_revision,
                },
            ),
        )
    try:
        provider_collection = advisor_providers.normalize_collection(
            raw_provider_collection
        )
    except ValueError as exc:
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_snapshot_invalid",
                "Advisor provider snapshot is invalid; no prompt was sent.",
                action="refresh_advisor_providers",
                context={"finding_id": finding.id},
                safe_details={"current_revision": input_revision},
            ),
        ) from exc
    if not provider_collection["providers"]:
        raise HTTPException(
            409,
            domain._problem_detail(
                "advisor_provider_snapshot_empty",
                "No Advisor provider is configured; no prompt was sent.",
                action="configure_advisor_provider",
                context={"finding_id": finding.id},
                safe_details={"current_revision": input_revision},
            ),
        )
    active_config["advisor_providers"] = provider_collection
    raw_pin = active_config.get("advisor_provider_pin")
    if remote_confirmation is not None:
        try:
            resolved_profile = advisor_providers.provider_by_id(
                provider_collection, remote_confirmation["provider_id"]
            )
        except KeyError as exc:
            raise HTTPException(
                409,
                domain._problem_detail(
                    "advisor_provider_selection_stale",
                    "Remote Advisor provider is absent from its admitted snapshot; no prompt was sent.",
                    action="preview_advisor_source_disclosure",
                    context={"finding_id": finding.id},
                ),
            ) from exc
        raw_consents = active_config.get("advisor_provider_consents")
        snapshot_consent = (
            raw_consents.get(resolved_profile["id"])
            if isinstance(raw_consents, dict)
            else None
        )
        packet = domain._finding_packet(
            finding,
            scan,
            project,
            domain._finding_display_label(db, finding),
        )
        if (
            not isinstance(raw_pin, dict)
            or resolved_profile["transport"] not in {"direct", "ssh"}
            or not isinstance(snapshot_consent, dict)
            or any(
                raw_pin.get(pin_key) != resolved_profile.get(profile_key)
                for pin_key, profile_key in (
                    ("provider_id", "id"),
                    ("transport", "transport"),
                    ("provider_config_revision", "config_revision"),
                    ("provider_config_digest", "config_digest"),
                    ("model", "model"),
                    ("model_digest", "model_digest"),
                )
            )
            or not advisor_disclosure.confirmation_matches(
                provider_collection,
                resolved_profile,
                snapshot_consent,
                remote_confirmation,
                finding_id=finding.id,
                finding_revision=input_revision,
                packet=packet,
            )
        ):
            raise HTTPException(
                409,
                domain._problem_detail(
                    "advisor_provider_selection_stale",
                    "Remote Advisor job snapshot does not match its exact disclosure confirmation; no prompt was sent.",
                    action="preview_advisor_source_disclosure",
                    context={
                        "finding_id": finding.id,
                        "provider_id": resolved_profile["id"],
                    },
                ),
            )
        resolved_profile, live_collection, live_consent = (
            revalidate_remote_provider_sync(
                db,
                resolved_profile,
                settings,
                remote_confirmation,
                finding_id=finding.id,
                finding_revision=input_revision,
                packet=packet,
            )
        )
        # Keep the provider admission lock and the scan/finding row locks
        # through the one bounded transmission and publication. This makes
        # the preview's provider and finding revisions exact at send time.
        db.refresh(scan, with_for_update=True)
        db.refresh(finding, with_for_update=True)
        if finding.revision != input_revision or finding.suppressed:
            raise HTTPException(
                409,
                domain._problem_detail(
                    "finding_changed",
                    "The finding changed after remote disclosure confirmation; no prompt was sent.",
                    action="refresh_findings",
                    context={
                        "finding_id": finding.id,
                        "expected_revision": input_revision,
                        "current_revision": finding.revision,
                    },
                ),
            )
        packet = domain._finding_packet(
            finding,
            scan,
            project,
            domain._finding_display_label(db, finding),
        )
        if not advisor_disclosure.confirmation_matches(
            live_collection,
            resolved_profile,
            live_consent,
            remote_confirmation,
            finding_id=finding.id,
            finding_revision=finding.revision,
            packet=packet,
        ):
            raise HTTPException(
                409,
                "The finding disclosure changed before remote transmission; no prompt was sent.",
            )
        ok, reason = True, None
    else:
        resolved_profile, _receipt, reason = resolve_provider_sync(
            active_config, settings, timeout=10.0
        )
        if raw_pin is not None and not isinstance(raw_pin, dict):
            raise HTTPException(
                409,
                domain._problem_detail(
                    "advisor_provider_pin_invalid",
                    "Advisor provider pin is invalid; no prompt was sent.",
                    action="refresh_advisor_providers",
                    context={"finding_id": finding.id},
                ),
            )
        if resolved_profile is not None and isinstance(raw_pin, dict) and any(
            raw_pin.get(pin_key) != resolved_profile.get(profile_key)
            for pin_key, profile_key in (
                ("provider_id", "id"),
                ("transport", "transport"),
                ("provider_config_revision", "config_revision"),
                ("provider_config_digest", "config_digest"),
                ("model", "model"),
                ("model_digest", "model_digest"),
            )
        ):
            raise HTTPException(
                409,
                domain._problem_detail(
                    "advisor_provider_selection_stale",
                    "Advisor provider resolution no longer matches the admitted exact pin; no prompt was sent.",
                    action="refresh_advisor_providers",
                    context={"finding_id": finding.id},
                ),
            )
        ok = resolved_profile is not None
    if cancel_check is not None:
        cancel_check()
    if not ok or resolved_profile is None:
        raise HTTPException(
            503,
            domain._problem_detail(
                "advisor_provider_unavailable",
                "The selected Advisor provider is unavailable; no prompt was sent.",
                action="test_advisor_provider",
                context={"finding_id": finding.id},
                safe_details={"reason_code": str(reason or "provider_unavailable")},
            ),
        )

    packet = domain._finding_packet(
        finding, scan, project, domain._finding_display_label(db, finding)
    )
    prompt = advisor_disclosure.triage_prompt(packet)
    started = time.time()
    active_model = str(resolved_profile["model"])
    if model not in {None, "", active_model}:
        raise HTTPException(409, "Advisor command model does not match the resolved provider pin")
    try:
        request_payload = _ollama_payload(
            prompt,
            model=active_model,
            thinking=bool(active_config["ollama_thinking"]),
        )
        if remote_confirmation is None:
            resolved_profile = revalidate_local_provider_sync(
                db, resolved_profile, settings
            )
        payload = generate_with_provider_sync(
            resolved_profile,
            request_payload,
            settings,
            remote_confirmation=remote_confirmation,
            operation_id=active_config.get("advisor_operation_id"),
            cancel_check=cancel_check,
            reserve_local_operation=reserve_local_operation,
        )
        if cancel_check is not None:
            cancel_check()
        if not isinstance(payload, dict) or not isinstance(payload.get("response"), str):
            raise ValueError("Ollama response does not contain advisor text")
        parsed = _parse_json_response(payload["response"])
        verdict, confidence, reasoning, fix = _validate_advisor_result(parsed)
    except ConnectorCleanupUnconfirmed:
        raise
    except HTTPException:
        raise
    except AdvisorResultValidationError as exc:
        raise HTTPException(
            502,
            domain._problem_detail(
                "advisor_output_invalid",
                "Advisor returned invalid bounded text; the existing review was preserved.",
                action="retry_advisor",
            ),
        ) from exc
    except (TypeError, ValueError) as exc:
        if cancel_check is not None:
            cancel_check()
        raise HTTPException(502, domain._redacted_text(f"Ollama advisor failed: {exc}")) from exc
    finally:
        advisor_duration.observe(max(time.time() - started, 0))

    # Local generation is made without a row lock, while an explicitly remote
    # call already holds its exact disclosure locks. In both cases, re-read the
    # authoritative rows before publication so stale output cannot overwrite a
    # concurrent lifecycle action or duplicate a revision.
    db.refresh(scan, with_for_update=True)
    db.refresh(finding, with_for_update=True)
    if finding.revision != input_revision or finding.suppressed:
        raise HTTPException(
            409,
            domain._problem_detail(
                "finding_changed",
                "The finding changed while Advisor was running; stale output was discarded.",
                action="refresh_findings",
                context={
                    "finding_id": finding.id,
                    "expected_revision": input_revision,
                    "current_revision": finding.revision,
                },
            ),
        )
    finding.ai_verdict = verdict
    finding.ai_confidence = confidence
    finding.ai_reasoning = domain._redacted_text(reasoning, 4000) or None
    finding.ai_fix = domain._redacted_text(fix, 4000) or None
    metadata = dict(finding.metadata_json or {})
    advisor_metadata = {
        "model": active_model,
        "prompt_version": advisor_disclosure.PROMPT_VERSION,
        "thinking": bool(active_config["ollama_thinking"]),
    }
    if resolved_profile is not None:
        advisor_metadata.update(
            {
                "model_digest": resolved_profile["model_digest"],
                "provider_id": resolved_profile["id"],
                "provider_transport": resolved_profile["transport"],
            }
        )
    if remote_confirmation is not None:
        advisor_metadata.update(
            {
                "disclosure_confirmation_digest": remote_confirmation[
                    "confirmation_digest"
                ],
            }
        )
    metadata["advisor"] = advisor_metadata
    finding.metadata_json = domain._redacted_json_object(metadata)
    finding.revision += 1
    scan.revision += 1
    scan.findings_revision += 1
    db.add(finding)
    db.add(scan)
    if commit:
        db.commit()
        db.refresh(finding)
    else:
        db.flush()
    return {
        "finding_id": finding.id,
        "verdict": finding.ai_verdict,
        "confidence": finding.ai_confidence,
        "reasoning": finding.ai_reasoning,
        "fix": finding.ai_fix,
    }
