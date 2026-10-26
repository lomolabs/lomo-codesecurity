from __future__ import annotations

from copy import deepcopy
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from kodesec_api.db import Base, Runtime
from kodesec_api.auth import AuthContext, csrf_token
from kodesec_api.main import (
    SCANNER_TOOL_REGISTRY,
    _ScannerRuntimeSnapshot,
    _runtime_config_values,
    _scanner_preflight,
    _scanner_cache_rollback_eligibility,
    _scanner_runtime_readiness,
    _scanner_runtime_snapshot,
    _scanner_tool_rows,
    create_scan,
    prepare_scanners,
    retry_scanner_cache_verification,
    retry_job,
    update_scanner_cache,
    router,
)
from kodesec_api.models import Job, Project, Scan, ScannerLifecycleState
from kodesec_api.schemas import JobRetryRequest, ScanCreate, ScannerCacheUpdateRequest, ScannerCacheVerificationRetryRequest, ScannerToolOut
from kodesec_api.security import SecurityBoundaryMiddleware
from kodesec_api.settings import Settings


def _runtime() -> Runtime:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        SCANNER_URL="http://scanner:8091",
        KODESEC_ALLOWED_ROOTS="/workspace",
    )
    return Runtime.create(settings, engine=engine)


def _ready_readiness() -> dict[str, object]:
    return {
        "binary": {"state": "ready", "reason": None, "component_ids": []},
        "data": {
            "state": "ready",
            "reason": None,
            "component_ids": ["trivy-java-db", "trivy-db"],
        },
        "rules": {"state": "not_required", "reason": None, "component_ids": []},
        "execution": {"state": "ready", "reason": None, "component_ids": []},
    }


def _runtime_snapshot(
    tools: dict[str, dict[str, object]],
    *,
    active_generation: str | None = None,
) -> _ScannerRuntimeSnapshot:
    return _ScannerRuntimeSnapshot(
        tools=tools,
        active_generation=active_generation,
    )


def test_runtime_configuration_database_failure_is_typed_and_never_defaults() -> None:
    class BrokenSession:
        def scalars(self, _statement: object) -> object:
            raise SQLAlchemyError("fixture database failure")

    with pytest.raises(HTTPException) as unavailable:
        _runtime_config_values(
            Settings(_env_file=None, KODESEC_ALLOWED_ROOTS="/workspace"),
            BrokenSession(),  # type: ignore[arg-type]
        )
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail["code"] == "runtime_configuration_unavailable"
    assert unavailable.value.detail["action"] == "refresh_settings"
    assert unavailable.value.detail["safe_details"] == {
        "reason_code": "database_read_failed"
    }


@pytest.mark.parametrize(
    ("scanner_result", "status_code", "code", "reason_code"),
    [
        (
            httpx.ConnectError("fixture scanner unavailable"),
            503,
            "scanner_runtime_unavailable",
            "scanner_unavailable",
        ),
        (
            httpx.Response(
                200,
                json={"tools": "not-a-list"},
                request=httpx.Request("GET", "http://scanner:8091/tools"),
            ),
            502,
            "scanner_runtime_protocol_invalid",
            "scanner_protocol_invalid",
        ),
        (
            httpx.Response(
                200,
                json={"tools": [], "active_generation": "not-a-generation"},
                request=httpx.Request("GET", "http://scanner:8091/tools"),
            ),
            502,
            "scanner_runtime_protocol_invalid",
            "scanner_protocol_invalid",
        ),
    ],
    ids=["unavailable", "invalid-protocol", "invalid-generation"],
)
def test_scanner_preflight_propagates_typed_runtime_failure(
    scanner_result: object,
    status_code: int,
    code: str,
    reason_code: str,
) -> None:
    runtime = _runtime()
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    get_effect = (
        {"side_effect": scanner_result}
        if isinstance(scanner_result, Exception)
        else {"return_value": scanner_result}
    )
    try:
        with patch("kodesec_api.main.httpx.Client.get", **get_effect):
            with pytest.raises(HTTPException) as typed_failure:
                _scanner_runtime_snapshot(runtime.settings)
        assert typed_failure.value.status_code == status_code
        assert typed_failure.value.detail["code"] == code
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            side_effect=typed_failure.value,
        ):
            with TestClient(app) as client:
                response = client.get("/v1/scanner/preflight")
        assert response.status_code == status_code
        detail = response.json()["detail"]
        assert detail["code"] == code
        assert detail["action"] == "repair_scanner_runtime"
        assert detail["safe_details"] == {"reason_code": reason_code}
    finally:
        runtime.engine.dispose()


def test_tool_rows_pass_strict_readiness_through_to_the_response_model() -> None:
    runtime = _runtime()
    runtime_inventory = {
        "trivy": {
            "id": "trivy",
            "available": True,
            "status": "ready",
            "installed_version": "0.73.0",
            "readiness": _ready_readiness(),
            "runtime_ready": True,
        }
    }
    try:
        with runtime.session_factory() as db:
            with patch(
                "kodesec_api.main._scanner_runtime_snapshot",
                return_value=_runtime_snapshot(runtime_inventory),
            ):
                row = next(
                    item
                    for item in _scanner_tool_rows(db, runtime.settings)
                    if item["id"] == "trivy"
                )
        response = ScannerToolOut.model_validate(row).model_dump(mode="json")
        assert response["available"] is True
        assert response["status"] == "ready"
        assert response["runtime_ready"] is True
        assert response["readiness"] == {
            "binary": {"state": "ready", "reason": None, "component_ids": []},
            "data": {
                "state": "ready",
                "reason": None,
                "component_ids": ["trivy-db", "trivy-java-db"],
            },
            "rules": {
                "state": "not_required",
                "reason": None,
                "component_ids": [],
            },
            "execution": {"state": "ready", "reason": None, "component_ids": []},
        }
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("refresh_due", [False, True])
def test_scanner_tools_endpoint_serializes_runtime_readiness(refresh_due) -> None:
    runtime = _runtime()
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    runtime_inventory = {
        "trivy": {
            "id": "trivy",
            "available": True,
            "status": "ready",
            "installed_version": "0.73.0",
            "readiness": _ready_readiness(),
            "runtime_ready": True,
        }
    }
    reason = _REFRESH_WARNING if refresh_due else None
    runtime_inventory["trivy"]["readiness"]["data"]["reason"] = reason
    try:
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(runtime_inventory),
        ):
            with TestClient(app) as client:
                response = client.get("/v1/scanner/tools")
        assert response.status_code == 200, response.text
        trivy = next(item for item in response.json() if item["id"] == "trivy")
        assert trivy["runtime_ready"] is True
        assert trivy["readiness"]["data"] == {
            "state": "ready",
            "reason": reason,
            "component_ids": ["trivy-db", "trivy-java-db"],
        }
        assert set(trivy["readiness"]) == {"binary", "data", "rules", "execution"}
    finally:
        runtime.engine.dispose()


def test_scanner_preflight_is_deterministic_and_blocks_missing_readiness() -> None:
    runtime = _runtime()
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    runtime_inventory = {
        "trivy": {
            "id": "trivy",
            "available": True,
            "status": "ready",
            "installed_version": "0.73.0",
            "readiness": _ready_readiness(),
            "runtime_ready": True,
        }
    }
    try:
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(runtime_inventory),
        ):
            with TestClient(app) as client:
                first = client.get("/v1/scanner/preflight")
                second = client.get("/v1/scanner/preflight")
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        body = first.json()
        assert body == second.json()
        assert body["ready"] is False
        assert body["ready_tool_ids"] == ["trivy"]
        assert body["recommended_action"] == "repair_scanner_runtime"
        assert body["preparation_available"] is False
        assert {item["id"] for item in body["blocked_tools"]} == {
            "bearer",
            "checkov",
            "gitleaks",
            "grype",
            "opengrep",
            "syft",
            "trufflehog",
        }
        assert body["cache_rollback"] == {
            "eligible": False,
            "reason_code": "no_previous_generation",
            "reason": "No previous-good scanner cache generation is available.",
            "target_generation": None,
        }
        assert all(
            item["blocking_reasons"]
            == ["Scanner runtime readiness data failed validation."]
            for item in body["blocked_tools"]
        )
        assert len(body["revision"]) == 64
    finally:
        runtime.engine.dispose()


def test_preflight_never_claims_cache_preparation_repairs_a_missing_binary() -> None:
    runtime = _runtime()
    blocked_row = {
        "id": "grype",
        "name": "Grype",
        "enabled": True,
        "runtime_ready": False,
        "readiness": {
            "binary": {
                "state": "missing",
                "reason": "Grype binary is missing from the scanner image.",
                "component_ids": [],
            },
            "data": {
                "state": "missing",
                "reason": "Grype database is missing.",
                "component_ids": ["grype-db"],
            },
            "rules": {"state": "not_required", "reason": None, "component_ids": []},
            "execution": {"state": "ready", "reason": None, "component_ids": []},
        },
    }
    try:
        with runtime.session_factory() as db:
            with (
                patch(
                    "kodesec_api.main._scanner_runtime_snapshot",
                    return_value=_runtime_snapshot({}),
                ),
                patch("kodesec_api.main._scanner_tool_rows", return_value=[blocked_row]),
            ):
                body = _scanner_preflight(db, runtime.settings)
        assert body["ready"] is False
        assert body["required_component_ids"] == ["grype-db"]
        assert body["preparation_available"] is False
        assert body["recommended_action"] == "repair_scanner_runtime"
        assert body["blocked_tools"] == [{
            "id": "grype",
            "name": "Grype",
            "blocking_reasons": [
                "Grype binary is missing from the scanner image.",
                "Grype database is missing.",
            ],
            "required_component_ids": ["grype-db"],
            "preparation_blocking_reasons": [
                "Grype binary is missing from the scanner image.",
            ],
        }]
    finally:
        runtime.engine.dispose()


def test_preflight_reports_validated_runtime_generation_without_updater_history() -> None:
    runtime = _runtime()
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    active_generation = "a" * 64
    readiness = {
        "binary": {"state": "ready", "reason": None, "component_ids": []},
        "data": {"state": "not_required", "reason": None, "component_ids": []},
        "rules": {"state": "not_required", "reason": None, "component_ids": []},
        "execution": {"state": "ready", "reason": None, "component_ids": []},
    }
    runtime_inventory = {
        tool_id: {
            "id": tool_id,
            "available": True,
            "status": "ready",
            "installed_version": str(defaults["current_version"]),
            "readiness": readiness,
            "runtime_ready": True,
        }
        for tool_id, defaults in SCANNER_TOOL_REGISTRY.items()
        if defaults["source"] == "external"
    }
    try:
        with patch(
            "kodesec_api.main._scanner_runtime_snapshot",
            return_value=_runtime_snapshot(
                runtime_inventory,
                active_generation=active_generation,
            ),
        ):
            with TestClient(app) as client:
                response = client.get("/v1/scanner/preflight")
        assert response.status_code == 200, response.text
        assert response.json()["ready"] is True
        assert response.json()["active_generation"] == active_generation
        with runtime.session_factory() as db:
            assert db.get(ScannerLifecycleState, "cache").active_generation is None
    finally:
        runtime.engine.dispose()


def test_degraded_readiness_does_not_rewrite_reported_availability_or_status() -> None:
    runtime = _runtime()
    readiness = _ready_readiness()
    readiness["data"] = {
        "state": "stale",
        "reason": "cache component freshness window expired",
        "component_ids": ["trivy-db"],
    }
    runtime_inventory = {
        "trivy": {
            "id": "trivy",
            "available": True,
            "status": "ready",
            "installed_version": "0.73.0",
            "readiness": readiness,
            "runtime_ready": False,
        }
    }
    try:
        with runtime.session_factory() as db:
            with patch(
                "kodesec_api.main._scanner_runtime_snapshot",
                return_value=_runtime_snapshot(runtime_inventory),
            ):
                row = next(
                    item
                    for item in _scanner_tool_rows(db, runtime.settings)
                    if item["id"] == "trivy"
                )
        assert row["available"] is True
        assert row["status"] == "ready"
        assert row["runtime_ready"] is False
        assert row["readiness"]["data"] == readiness["data"]
    finally:
        runtime.engine.dispose()


def test_previous_good_fallback_reason_passes_through_but_stays_non_ready() -> None:
    reason = "active cache generation is invalid; previous-good is not execution-ready"
    readiness = _ready_readiness()
    readiness["data"] = {
        "state": "invalid",
        "reason": reason,
        "component_ids": ["trivy-db"],
    }
    readiness["rules"] = {
        "state": "invalid",
        "reason": reason,
        "component_ids": [],
    }

    normalized, runtime_ready = _scanner_runtime_readiness(
        {"readiness": readiness, "runtime_ready": False}
    )

    assert runtime_ready is False
    assert normalized is not None
    assert normalized["data"] == {
        "state": "invalid",
        "reason": reason,
        "component_ids": ["trivy-db"],
    }
    assert normalized["rules"] == {
        "state": "invalid",
        "reason": reason,
        "component_ids": [],
    }


@pytest.mark.parametrize(
    "reason",
    [
        "rules canary evidence is not attested",
        "cache rule canary receipts differ from the rules lock",
    ],
)
def test_fixed_rule_canary_reason_passes_through_but_stays_non_ready(
    reason: str,
) -> None:
    readiness = _ready_readiness()
    readiness["rules"] = {
        "state": "invalid",
        "reason": reason,
        "component_ids": ["opengrep-reviewed-rules"],
    }

    normalized, runtime_ready = _scanner_runtime_readiness(
        {"readiness": readiness, "runtime_ready": False}
    )

    assert runtime_ready is False
    assert normalized is not None
    assert normalized["rules"] == {
        "state": "invalid",
        "reason": reason,
        "component_ids": ["opengrep-reviewed-rules"],
    }


def test_fixed_binary_license_reason_passes_through_but_stays_non_ready() -> None:
    readiness = _ready_readiness()
    readiness["binary"] = {
        "state": "unattested",
        "reason": "binary license evidence is not attested",
        "component_ids": [],
    }

    normalized, runtime_ready = _scanner_runtime_readiness(
        {"readiness": readiness, "runtime_ready": False}
    )

    assert runtime_ready is False
    assert normalized is not None
    assert normalized["binary"] == readiness["binary"]


def _malformed_runtime(case: str) -> dict[str, object]:
    runtime: dict[str, object] = {
        "readiness": deepcopy(_ready_readiness()),
        "runtime_ready": True,
    }
    readiness = runtime["readiness"]
    assert isinstance(readiness, dict)
    if case == "extra_key":
        readiness["binary"]["path"] = "/workspace/private/tool"
    elif case == "unsafe_reason":
        readiness["binary"] = {
            "state": "invalid",
            "reason": "https://attacker.invalid/private/path",
            "component_ids": [],
        }
        runtime["runtime_ready"] = False
    elif case == "unknown_component":
        readiness["data"]["component_ids"] = ["/workspace/private/cache"]
    elif case == "wrong_component_facet":
        readiness["rules"]["component_ids"] = ["trivy-db"]
    elif case == "duplicate_component":
        readiness["data"]["component_ids"] = ["trivy-db", "trivy-db"]
    elif case == "wrong_collection_type":
        readiness["data"]["component_ids"] = ("trivy-db",)
    elif case == "unknown_state":
        readiness["binary"]["state"] = "healthy"
    elif case == "inconsistent_aggregate":
        runtime["runtime_ready"] = False
    elif case == "non_boolean_aggregate":
        runtime["runtime_ready"] = 1
    elif case == "missing_facet":
        del readiness["execution"]
    elif case == "oversized_reason":
        readiness["binary"] = {
            "state": "invalid",
            "reason": "x" * 513,
            "component_ids": [],
        }
        runtime["runtime_ready"] = False
    else:  # pragma: no cover - keeps additions explicit
        raise AssertionError(case)
    return runtime


@pytest.mark.parametrize(
    "case",
    [
        "extra_key",
        "unsafe_reason",
        "unknown_component",
        "wrong_component_facet",
        "duplicate_component",
        "wrong_collection_type",
        "unknown_state",
        "inconsistent_aggregate",
        "non_boolean_aggregate",
        "missing_facet",
        "oversized_reason",
    ],
)
def test_malformed_runtime_readiness_is_masked_fail_closed(case: str) -> None:
    malformed = _malformed_runtime(case)
    readiness, runtime_ready = _scanner_runtime_readiness(malformed)

    assert runtime_ready is False
    assert readiness is not None
    assert set(readiness) == {"binary", "data", "rules", "execution"}
    assert {
        (facet["state"], facet["reason"], tuple(facet["component_ids"]))
        for facet in readiness.values()
    } == {("invalid", "Scanner runtime readiness data failed validation.", ())}
    serialized = json.dumps(readiness)
    assert "/workspace/private" not in serialized
    assert "attacker.invalid" not in serialized
    assert "x" * 80 not in serialized


@pytest.mark.parametrize("reason", [
    "no validated cache generation is selected for scanner execution",
    "no validated active or previous-good cache generation exists",
])
def test_unavailable_cache_guidance_preserves_blocking_state(reason: str) -> None:
    facets = _ready_readiness()
    facets["data"] = {"state": "unavailable", "reason": reason, "component_ids": ["trivy-db"]}
    readiness, ready = _scanner_runtime_readiness({"id": "trivy", "readiness": facets, "runtime_ready": False})
    assert ready is False
    assert readiness["data"] == facets["data"]
    assert readiness["binary"]["state"] == "ready"


def test_runtime_without_current_readiness_fields_is_invalid_fail_closed() -> None:
    readiness, runtime_ready = _scanner_runtime_readiness(
        {"available": False, "status": "missing", "installed_version": None}
    )
    assert runtime_ready is False
    assert set(readiness) == {"binary", "data", "rules", "execution"}
    assert {
        (facet["state"], facet["reason"], tuple(facet["component_ids"]))
        for facet in readiness.values()
    } == {("invalid", "Scanner runtime readiness data failed validation.", ())}


_REFRESH_WARNING = (
    "Refresh due: reviewed data is at least 7 days old; newer vulnerabilities may be missing. "
    "Update reviewed source before the 14-day expiry."
)


@pytest.mark.parametrize("components", [["trivy-db", "trivy-java-db"], ["grype-db"]])
def test_reviewed_data_refresh_advisory_preserves_ready_state_and_guidance(components) -> None:
    facets = _ready_readiness()
    facets["data"] = {"state": "ready", "reason": _REFRESH_WARNING, "component_ids": components}
    readiness, ready = _scanner_runtime_readiness({"readiness": facets, "runtime_ready": True})
    assert ready is True
    assert readiness["data"] == {**facets["data"], "component_ids": sorted(components)}


@pytest.mark.parametrize("mutation", [
    "binary", "rules", "execution", "empty_components", "unknown_component",
    "not_required", "stale", "invalid", "modified_warning", "inconsistent_aggregate",
])
def test_refresh_advisory_cannot_authorize_other_facets_or_invalid_data(mutation) -> None:
    facets = _ready_readiness()
    runtime = {"readiness": facets, "runtime_ready": True}
    facets["data"]["reason"] = _REFRESH_WARNING
    if mutation in {"binary", "rules", "execution"}:
        facets["data"]["reason"] = None
        facets[mutation]["reason"] = _REFRESH_WARNING
    elif mutation == "empty_components":
        facets["data"]["component_ids"] = []
    elif mutation == "unknown_component":
        facets["data"]["component_ids"] = ["/private/cache"]
    elif mutation in {"not_required", "stale", "invalid"}:
        facets["data"]["state"] = mutation
        runtime["runtime_ready"] = mutation == "not_required"
    elif mutation == "modified_warning":
        facets["data"]["reason"] += " Visit https://attacker.invalid"
    else:
        runtime["runtime_ready"] = False
    readiness, ready = _scanner_runtime_readiness(runtime)
    assert ready is False
    assert all(facet["state"] == "invalid" for facet in readiness.values())
    assert "attacker.invalid" not in json.dumps(readiness)


def _verification(state="verifying", target="active"):
    return {
        "state": state, "target": target, "generation_id": "a" * 64,
        "phase": "validating", "component_id": "grype-db",
        "started_at": "2026-09-07T12:00:00+00:00",
        "last_activity_at": "2026-09-07T12:00:01+00:00",
        "bytes_verified": None, "bytes_total": None,
    }


def _verification_inventory(state="verifying"):
    facet_state, reason = {
        "verifying": ("verifying", "scanner cache verification is in progress"),
        "timed_out": ("verification_timeout", "scanner cache verification timed out"),
        "failed": ("verification_failed", "scanner cache verification could not complete"),
    }[state]
    readiness = _ready_readiness()
    readiness["data"] = {"state": facet_state, "reason": reason, "component_ids": ["trivy-db"]}
    return {"trivy": {"id": "trivy", "available": True, "status": "ready",
        "readiness": readiness, "runtime_ready": False}}


def _verification_request():
    request = Request({"type": "http", "method": "POST", "path": "/v1/scanner/cache/verification/retry",
        "headers": [(b"idempotency-key", b"synthetic-verification-retry")]})
    request.state.auth = AuthContext(kind="browser", subject="synthetic", scopes=frozenset({"api:write"}))
    return request


def _scanner_response(payload, status=200):
    return httpx.Response(status, json=payload, request=httpx.Request("GET", "http://scanner:8091/tools"))


@pytest.mark.parametrize("state", ["verifying", "timed_out", "failed"])
def test_verification_preflight_is_responsive_non_ready_and_not_a_download(state):
    runtime = _runtime()
    verification = _verification(state)
    payload = {"tools": list(_verification_inventory(state).values()), "active_generation": None,
        "cache_verification": verification}
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    try:
        with patch("kodesec_api.main.httpx.Client.get", return_value=_scanner_response(payload)) as get:
            with TestClient(app) as client:
                response = client.request("GET", "/v1/scanner/preflight")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["cache_verification"] == verification
        assert body["ready"] is body["preparation_available"] is False
        assert body["active_generation"] is None
        assert body["recommended_action"] == ("wait_for_scanner_verification" if state == "verifying" else "retry_scanner_verification")
        assert get.call_count == 1
        trivy = next(tool for tool in body["blocked_tools"] if tool["id"] == "trivy")
        assert trivy["required_component_ids"] == []
        assert trivy["preparation_blocking_reasons"] == trivy["blocking_reasons"]
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("changes", [
    {"extra": "not-public"}, {"generation_id": "invalid"}, {"target": "previous_good"},
    {"component_id": "unknown"}, {"phase": "download"}, {"state": "ready"},
    {"bytes_verified": True, "bytes_total": 1}, {"bytes_verified": 1, "bytes_total": None},
    {"bytes_verified": 2, "bytes_total": 1}, {"bytes_verified": 0, "bytes_total": 8 * 1024**3 + 1},
    {"started_at": "2026-09-07T12:00:00+01:00"}, {"started_at": "2026-02-30T12:00:00Z"},
    {"last_activity_at": "2026-09-07T11:59:59Z"},
])
def test_verification_runtime_refuses_unbounded_or_inconsistent_payload(changes):
    runtime = _runtime()
    payload = {"tools": [], "active_generation": None, "cache_verification": {**_verification(), **changes}}
    try:
        with patch("kodesec_api.main.httpx.Client.get", return_value=_scanner_response(payload)):
            with pytest.raises(HTTPException) as caught:
                _scanner_runtime_snapshot(runtime.settings)
        assert caught.value.status_code == 502
        assert caught.value.detail["code"] == "scanner_runtime_protocol_invalid"
        assert "not-public" not in json.dumps(caught.value.detail)
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("mismatch", ["missing", "state", "generation", "reason"])
def test_verification_runtime_facets_must_match_the_current_observation(mismatch):
    runtime = _runtime()
    payload = {"tools": list(_verification_inventory().values()), "active_generation": None,
        "cache_verification": _verification()}
    if mismatch == "missing":
        payload.pop("cache_verification")
    elif mismatch == "state":
        payload["cache_verification"]["state"] = "failed"
    elif mismatch == "generation":
        payload["active_generation"] = "b" * 64
    else:
        item = payload["tools"][0]
        item["readiness"]["data"]["reason"] = "download arbitrary files"
        readiness, ready = _scanner_runtime_readiness(item)
        assert not ready and all(facet["state"] == "invalid" for facet in readiness.values())
        runtime.engine.dispose()
        return
    try:
        with patch("kodesec_api.main.httpx.Client.get", return_value=_scanner_response(payload)):
            with pytest.raises(HTTPException) as caught:
                _scanner_runtime_snapshot(runtime.settings)
        assert caught.value.status_code == 502
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("target", ["active", "previous_good"])
def test_verification_activity_does_not_churn_preflight_revision(target):
    runtime = _runtime()
    verification = _verification(target=target)
    rows = [{"id": "trivy", "name": "Trivy", "enabled": True,
        "runtime_ready": True, "readiness": _ready_readiness()}]
    snapshot = _ScannerRuntimeSnapshot(tools={}, active_generation=None,
        cache_verification=verification if target == "active" else None)
    rollback = {"eligible": False, "reason_code": "no_previous_generation",
        "reason": "No previous-good scanner cache generation is available.", "target_generation": None}
    if target == "previous_good":
        rollback.update(reason_code="previous_generation_verifying", reason="Previous cache verification is in progress.",
            target_generation=verification["generation_id"], verification=verification)
    try:
        with runtime.session_factory() as db, patch("kodesec_api.main._scanner_runtime_snapshot", return_value=snapshot), \
            patch("kodesec_api.main._scanner_tool_rows", return_value=rows), \
            patch("kodesec_api.main._scanner_cache_rollback_eligibility", return_value=rollback):
            first = _scanner_preflight(db, runtime.settings)
            verification.update(phase="hashing", component_id="trivy-db",
                last_activity_at="2026-09-07T12:00:02Z", bytes_verified=2, bytes_total=8 * 1024**3)
            second = _scanner_preflight(db, runtime.settings)
            assert first["revision"] == second["revision"]
            assert first != second
            assert second["ready"] is (target == "previous_good")
            verification["state"] = "timed_out"
            if target == "previous_good":
                rollback.update(reason_code="previous_generation_verification_timeout", reason="Previous verification timed out.")
            assert _scanner_preflight(db, runtime.settings)["revision"] != first["revision"]
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("state,code", [
    ("verifying", "previous_generation_verifying"),
    ("timed_out", "previous_generation_verification_timeout"),
    ("failed", "previous_generation_verification_failed"),
])
def test_verification_previous_good_is_forwarded_as_exact_non_ready_state(state, code):
    runtime = _runtime()
    verification = _verification(state, target="previous_good")
    payload = {"eligible": False, "reason_code": code, "reason": "Previous cache verification needs attention.",
        "target_generation": verification["generation_id"], "verification": verification}
    try:
        with runtime.session_factory() as db:
            lifecycle = db.get(ScannerLifecycleState, "cache")
            lifecycle.previous_generation = verification["generation_id"]
            db.commit()
            with patch("kodesec_api.main.httpx.Client.get", return_value=_scanner_response(payload)):
                assert _scanner_cache_rollback_eligibility(db, runtime.settings) == payload
            payload["verification"] = {**verification, "generation_id": "b" * 64}
            with patch("kodesec_api.main.httpx.Client.get", return_value=_scanner_response(payload)):
                rejected = _scanner_cache_rollback_eligibility(db, runtime.settings)
            assert rejected["reason_code"] == "scanner_eligibility_invalid"
            assert "verification" not in rejected
            assert list(db.scalars(select(Job))) == []
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("action", ["scan", "prepare", "update"])
@pytest.mark.parametrize("state", ["verifying", "timed_out", "failed"])
def test_verification_blocks_new_scan_and_preparation_without_a_job(action, state):
    runtime = _runtime()
    verification = _verification(state)
    preflight = {"ready": False, "cache_verification": verification}
    try:
        with runtime.session_factory() as db:
            project = Project(name="verification-fixture", repo_path="/workspace/verification-fixture", default_branch="main")
            db.add(project)
            db.commit()
            with patch("kodesec_api.main._scanner_preflight", return_value=preflight), \
                patch("kodesec_api.main._scanner_runtime_snapshot", return_value=_ScannerRuntimeSnapshot(
                    tools={}, active_generation=None, cache_verification=verification)):
                with pytest.raises(HTTPException) as caught:
                    if action == "scan":
                        create_scan(ScanCreate(project_id=project.id, use_ai=False), _verification_request(), runtime=runtime, db=db)
                    elif action == "prepare":
                        prepare_scanners(_verification_request(), runtime=runtime, db=db)
                    else:
                        update_scanner_cache(ScannerCacheUpdateRequest(component_ids=["grype-db"]),
                            _verification_request(), runtime=runtime, db=db)
            assert caught.value.status_code == 409
            assert caught.value.detail["code"] == "scanner_cache_verification_required"
            assert caught.value.detail["action"] == ("wait_for_scanner_verification" if state == "verifying" else "retry_scanner_verification")
            assert list(db.scalars(select(Job))) == []
            assert list(db.scalars(select(Scan))) == []
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("target", ["active", "previous_good"])
def test_verification_retry_forwards_only_exact_target_and_returns_pending(target):
    runtime = _runtime()
    payload = ScannerCacheVerificationRetryRequest(target=target, expected_generation="a" * 64)
    verification = _verification(target=target)
    try:
        with patch("kodesec_api.main.httpx.Client.post", return_value=_scanner_response(verification, 202)) as post:
            first = retry_scanner_cache_verification(payload, _verification_request(), runtime=runtime)
            second = retry_scanner_cache_verification(payload, _verification_request(), runtime=runtime)
        assert first == second == verification
        assert post.call_count == 2
        assert post.call_args.args == ("http://scanner:8091/cache/verification/retry",)
        assert post.call_args.kwargs == {"json": payload.model_dump()}
        with runtime.session_factory() as db:
            assert list(db.scalars(select(Job))) == []
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("kind", ["scanner_cache_update", "scanner_catalog_check"])
def test_verification_blocks_preparation_job_retry_before_mutation(kind):
    runtime = _runtime()
    try:
        with runtime.session_factory() as db:
            job = Job(kind=kind, title="Synthetic preparation retry", status="failed", stage="failed",
                payload={"v": 1, "operation": "cache_update" if kind == "scanner_cache_update" else "catalog_check",
                    "preparation": {"schema_version": 1}}, revision=2, attempt=1, max_attempts=3)
            db.add(job)
            db.commit()
            before = {column.name: deepcopy(getattr(job, column.name)) for column in Job.__table__.columns}
            with patch("kodesec_api.main._scanner_runtime_snapshot", return_value=_ScannerRuntimeSnapshot(
                tools={}, active_generation=None, cache_verification=_verification())), \
                patch("kodesec_api.main.retry_failed_job") as mutation:
                with pytest.raises(HTTPException) as caught:
                    retry_job(job.id, JobRetryRequest(expected_revision=2), runtime=runtime, db=db)
            assert caught.value.status_code == 409
            assert caught.value.detail["action"] == "wait_for_scanner_verification"
            mutation.assert_not_called()
            db.refresh(job)
            assert {column.name: getattr(job, column.name) for column in Job.__table__.columns} == before
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("code", ["cache_verification_changed", "cache_verification_not_retryable"])
def test_verification_retry_maps_only_safe_conflict_messages(code):
    runtime = _runtime()
    payload = ScannerCacheVerificationRetryRequest(target="active", expected_generation="a" * 64)
    try:
        with patch("kodesec_api.main.httpx.Client.post", return_value=_scanner_response({"detail": {
            "code": code, "message": "unsafe internal diagnostic body"}}, 409)):
            with pytest.raises(HTTPException) as caught:
                retry_scanner_cache_verification(payload, _verification_request(), runtime=runtime)
        assert caught.value.status_code == 409 and caught.value.detail["code"] == code
        assert caught.value.detail["action"] == "refresh_scanner_preflight"
        assert "unsafe internal" not in str(caught.value.detail)
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("response", [
    _scanner_response({**_verification(), "generation_id": "b" * 64}, 202),
    _scanner_response(_verification(target="previous_good"), 202),
    _scanner_response(_verification(state="failed"), 202),
    _scanner_response({"detail": {"code": "unknown", "message": "unsafe internal diagnostic body"}}, 409),
    _scanner_response({"detail": "unsafe internal diagnostic body"}, 500),
    httpx.Response(202, content=b"x" * 4097),
])
def test_verification_retry_rejects_invalid_or_mismatched_scanner_response(response):
    runtime = _runtime()
    payload = ScannerCacheVerificationRetryRequest(target="active", expected_generation="a" * 64)
    try:
        with patch("kodesec_api.main.httpx.Client.post", return_value=response):
            with pytest.raises(HTTPException) as caught:
                retry_scanner_cache_verification(payload, _verification_request(), runtime=runtime)
        assert caught.value.status_code == 502
        assert caught.value.detail["code"] == "scanner_verification_retry_protocol_invalid"
        assert "unsafe internal" not in str(caught.value.detail)
    finally:
        runtime.engine.dispose()


@pytest.mark.parametrize("authority,status", [("none", 401), ("ide", 403), ("missing_origin", 403), ("missing_csrf", 403), ("browser", 202)])
def test_verification_retry_uses_existing_browser_origin_csrf_and_ide_denial(authority, status):
    runtime = _runtime()
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    app.add_middleware(SecurityBoundaryMiddleware, runtime=runtime)
    context = AuthContext(kind="browser", subject="synthetic", scopes=frozenset({"api:write"}), session_nonce="synthetic-session")
    headers = {"Idempotency-Key": "synthetic-verification-retry"}
    if authority != "missing_origin":
        headers["Origin"] = "http://127.0.0.1:8080"
    if authority != "missing_csrf":
        headers["X-CSRF-Token"] = csrf_token(runtime.settings, context.session_nonce)
    if authority == "ide":
        headers["Authorization"] = "Bearer synthetic-test-authority"
    try:
        with patch.object(SecurityBoundaryMiddleware, "_validate_browser_session", return_value=None if authority == "none" else context), \
            patch.object(SecurityBoundaryMiddleware, "_validate_capability", return_value=AuthContext(kind="ide", subject="synthetic-ide", scopes=frozenset({"api:write"}))), \
            patch("kodesec_api.main.httpx.Client.post", return_value=_scanner_response(_verification(), 202)) as post:
            with TestClient(app, base_url="http://127.0.0.1:8080") as client:
                response = client.request("POST", "/v1/scanner/cache/verification/retry", headers=headers,
                    json={"target": "active", "expected_generation": "a" * 64})
        assert response.status_code == status, response.text
        assert post.call_count == (1 if status == 202 else 0)
    finally:
        runtime.engine.dispose()
