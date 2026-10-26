from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from sqlalchemy.orm import Session

from ..models import RuntimeConfig
from ..redaction import redact_text
from ..schemas import AdvisorLocalCatalogOut


WORKER_HEARTBEAT_KEY = "worker.heartbeat.v1"
WORKER_ADVISOR_KEY = "worker.advisor.v1"
WORKER_ADVISOR_CATALOG_KEY = "worker.advisor.catalog.v1"
WORKER_ADVISOR_CATALOG_SCHEMA = "lomo-worker-advisor-catalog/v1"
_WORKER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z")
WORKER_ADVISOR_CATALOG_FAILURE_CODES = frozenset(
    {
        "advisor_connector_protocol",
        "advisor_connector_unavailable",
        "advisor_provider_local_unavailable",
        "advisor_provider_tags_invalid",
    }
)


def _advisor_config_digest(config: Mapping[str, Any]) -> str:
    selected = {
        "ai_mode": str(config.get("ai_mode") or "off"),
        "ollama_base_url": str(config.get("ollama_base_url") or ""),
        "ollama_model": str(config.get("ollama_model") or ""),
        "ollama_thinking": bool(config.get("ollama_thinking")),
        "advisor_providers": config.get("advisor_providers")
        if isinstance(config.get("advisor_providers"), dict)
        else None,
    }
    encoded = json.dumps(selected, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return sha256(encoded).hexdigest()


def _safe_status_text(value: object, limit: int) -> str:
    return (redact_text(str(value)) or "")[:limit]


def _validated_worker_id(worker_id: str) -> str:
    if _WORKER_ID.fullmatch(worker_id) is None:
        raise ValueError("worker identity is invalid")
    return worker_id


def worker_advisor_catalog_failure_reason(reason: str) -> str:
    """Map connector output to the catalog receipt's closed vocabulary."""

    if reason in WORKER_ADVISOR_CATALOG_FAILURE_CODES:
        return reason
    return "advisor_connector_protocol"


def record_worker_heartbeat(
    db: Session, worker_id: str, *, now: datetime | None = None
) -> None:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    value = json.dumps(
        {"at": current.isoformat(), "worker_id": _validated_worker_id(worker_id)},
        separators=(",", ":"),
        sort_keys=True,
    )
    marker = db.get(RuntimeConfig, WORKER_HEARTBEAT_KEY)
    if marker is None:
        marker = RuntimeConfig(key=WORKER_HEARTBEAT_KEY, value=value)
    else:
        marker.value = value
        marker.updated_at = current
    db.add(marker)
    db.flush()


def fresh_worker_id(
    db: Session,
    *,
    stale_after_seconds: float,
    now: datetime | None = None,
) -> str | None:
    marker = db.get(RuntimeConfig, WORKER_HEARTBEAT_KEY)
    if marker is None:
        return None
    try:
        payload = json.loads(marker.value)
        if not isinstance(payload, dict) or set(payload) != {"at", "worker_id"}:
            return None
        observed = datetime.fromisoformat(str(payload["at"]))
        if observed.tzinfo is None or observed.utcoffset() is None:
            return None
        worker_id = payload.get("worker_id")
        if not isinstance(worker_id, str) or _WORKER_ID.fullmatch(worker_id) is None:
            return None
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age = (current - observed.astimezone(timezone.utc)).total_seconds()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return worker_id if -1.0 <= age <= stale_after_seconds else None


def worker_heartbeat_is_fresh(
    db: Session,
    *,
    stale_after_seconds: float,
    now: datetime | None = None,
) -> bool:
    return (
        fresh_worker_id(db, stale_after_seconds=stale_after_seconds, now=now)
        is not None
    )


def record_worker_advisor_status(
    db: Session,
    worker_id: str,
    config: Mapping[str, Any],
    *,
    available: bool,
    models: list[str],
    reason: str | None,
    now: datetime | None = None,
) -> None:
    """Publish a bounded worker-owned Ollama receipt without credential material."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    safe_models = [
        safe for item in models[:20] if (safe := _safe_status_text(item, 160))
    ]
    value = json.dumps(
        {
            "at": current.isoformat(),
            "worker_id": _validated_worker_id(worker_id),
            "config_digest": _advisor_config_digest(config),
            "available": bool(available),
            "models": safe_models,
            "reason": _safe_status_text(reason, 240) if reason else None,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    marker = db.get(RuntimeConfig, WORKER_ADVISOR_KEY)
    if marker is None:
        marker = RuntimeConfig(key=WORKER_ADVISOR_KEY, value=value)
    else:
        marker.value = value
        marker.updated_at = current
    db.add(marker)
    db.flush()


def worker_advisor_status(
    db: Session,
    config: Mapping[str, Any],
    *,
    worker_id: str | None,
    stale_after_seconds: float,
    now: datetime | None = None,
) -> tuple[bool, list[str], str | None]:
    """Read the matching worker receipt; never probe Ollama from the API."""

    if str(config.get("ai_mode") or "off") == "off":
        return False, [], "disabled"
    if worker_id is None:
        return False, [], "work_processing_unavailable"
    marker = db.get(RuntimeConfig, WORKER_ADVISOR_KEY)
    if marker is None:
        return False, [], "not_checked_by_worker"
    try:
        payload = json.loads(marker.value)
        if not isinstance(payload, dict) or set(payload) != {
            "at",
            "worker_id",
            "config_digest",
            "available",
            "models",
            "reason",
        }:
            raise ValueError("advisor status receipt shape is invalid")
        receipt_worker_id = payload.get("worker_id")
        if (
            not isinstance(receipt_worker_id, str)
            or _WORKER_ID.fullmatch(receipt_worker_id) is None
        ):
            raise ValueError("advisor status worker identity is invalid")
        if receipt_worker_id != worker_id:
            return False, [], "worker_advisor_status_owner_mismatch"
        observed = datetime.fromisoformat(str(payload["at"]))
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("advisor timestamp must include a timezone")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age = (current - observed.astimezone(timezone.utc)).total_seconds()
        if not -1.0 <= age <= stale_after_seconds:
            return False, [], "worker_advisor_status_stale"
        if payload.get("config_digest") != _advisor_config_digest(config):
            return False, [], "worker_configuration_pending"
        if not isinstance(payload.get("available"), bool):
            raise ValueError("advisor availability must be boolean")
        raw_models = payload.get("models")
        if not isinstance(raw_models, list) or any(
            not isinstance(item, str) for item in raw_models
        ):
            raise ValueError("advisor models must be strings")
        raw_reason = payload.get("reason")
        if raw_reason is not None and not isinstance(raw_reason, str):
            raise ValueError("advisor reason must be text")
        return bool(payload["available"]), raw_models[:20], raw_reason
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False, [], "invalid_worker_advisor_status"


def record_worker_advisor_catalog(
    db: Session,
    worker_id: str,
    *,
    catalog: Mapping[str, Any] | None,
    reason: str | None,
    now: datetime | None = None,
) -> None:
    """Publish connector-owned discovery through the worker/database boundary."""

    if (catalog is None) == (reason is None):
        raise ValueError(
            "advisor catalog receipt requires exactly one catalog or failure reason"
        )
    if reason is not None and reason not in WORKER_ADVISOR_CATALOG_FAILURE_CODES:
        raise ValueError("advisor catalog failure reason is invalid")
    normalized_catalog = (
        AdvisorLocalCatalogOut.model_validate(catalog).model_dump(
            mode="json", by_alias=True
        )
        if catalog is not None
        else None
    )
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    value = json.dumps(
        {
            "schema": WORKER_ADVISOR_CATALOG_SCHEMA,
            "at": current.isoformat(),
            "worker_id": _validated_worker_id(worker_id),
            "catalog": normalized_catalog,
            # The closed failure vocabulary is already safe; free-text redaction
            # can corrupt a valid code and make the durable receipt unreadable.
            "reason": reason,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    marker = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
    if marker is None:
        marker = RuntimeConfig(key=WORKER_ADVISOR_CATALOG_KEY, value=value)
    else:
        marker.value = value
        marker.updated_at = current
    db.add(marker)
    db.flush()


def worker_advisor_catalog(
    db: Session,
    *,
    worker_id: str | None,
    stale_after_seconds: float,
    now: datetime | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read a fresh worker receipt without giving the API connector access."""

    if worker_id is None:
        return None, "work_processing_unavailable"
    marker = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
    if marker is None:
        return None, "not_checked_by_worker"
    try:
        payload = json.loads(marker.value)
        if not isinstance(payload, dict):
            raise ValueError("advisor catalog receipt must be an object")
        if set(payload) != {"schema", "at", "worker_id", "catalog", "reason"}:
            raise ValueError("advisor catalog receipt shape is invalid")
        if payload.get("schema") != WORKER_ADVISOR_CATALOG_SCHEMA:
            raise ValueError("advisor catalog receipt schema is invalid")
        receipt_worker_id = payload.get("worker_id")
        if (
            not isinstance(receipt_worker_id, str)
            or _WORKER_ID.fullmatch(receipt_worker_id) is None
        ):
            raise ValueError("advisor catalog worker identity is invalid")
        if receipt_worker_id != worker_id:
            return None, "worker_advisor_catalog_owner_mismatch"
        observed = datetime.fromisoformat(str(payload["at"]))
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("advisor catalog timestamp must include a timezone")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age = (current - observed.astimezone(timezone.utc)).total_seconds()
        if not -1.0 <= age <= stale_after_seconds:
            return None, "worker_advisor_catalog_stale"
        catalog = payload.get("catalog")
        reason = payload.get("reason")
        if (catalog is None) == (reason is None):
            raise ValueError("advisor catalog receipt state is contradictory")
        if catalog is None:
            if (
                not isinstance(reason, str)
                or reason not in WORKER_ADVISOR_CATALOG_FAILURE_CODES
            ):
                raise ValueError("advisor catalog failure reason is invalid")
            return None, reason
        normalized = AdvisorLocalCatalogOut.model_validate(catalog).model_dump(
            mode="json", by_alias=True
        )
        return normalized, None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None, "invalid_worker_advisor_catalog"
