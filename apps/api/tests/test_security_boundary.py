from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import kodesec_api.main as main_module
import kodesec_api.security as security_module
from sqlalchemy import select
from starlette.datastructures import Headers

from kodesec_api.app import create_app
from kodesec_api.auth import (
    AuthContext,
    CAPABILITY_PREFIX,
    DYNAMIC_BROWSER_PAIRING_KEY,
    IDE_CAPABILITY_SCOPES,
    SESSION_COOKIE,
)
from kodesec_api.db import Runtime, initialize_database
from kodesec_api.local_url import normalize_local_ollama_url, parse_declared_ollama_hosts
from kodesec_api.main import _component_apply_command, _component_rows, _http_component
from kodesec_api.models import Finding, GatePolicy, IdeEnrollment, IdeSourceOpenCommand, Job, Project, RuntimeConfig, Scan
from kodesec_api.settings import Settings
from kodesec_api.static_files import mount_static_application
from kodesec_api.security import AdvisorRequestAudit, SecurityBoundaryMiddleware
from kodesec_api.security import ide_scope_for_request


ORIGIN = "http://127.0.0.1:8080"
INSTALLATION_SECRET = "i" * 48
BOOTSTRAP_TOKEN = "b" * 48
ADVISOR_FIXTURE_HOST = "10.23.45.67"
ADVISOR_FIXTURE_MODEL = "fixture-advisor:latest"
MUTATING_ROUTES = [
    ("PUT", "/v1/config"),
    ("PATCH", "/v1/config/advisor"),
    ("PATCH", "/v1/config/gate"),
    ("PATCH", "/v1/config/components"),
    ("POST", "/v1/advisor/providers"),
    ("PUT", "/v1/advisor/providers/direct-lab"),
    ("DELETE", "/v1/advisor/providers/direct-lab"),
    ("POST", "/v1/advisor/providers/direct-lab/commands"),
    ("POST", "/v1/scanner/tools/check-latest"),
    ("POST", "/v1/scanner/prepare"),
    ("POST", "/v1/scanner/cache/update"),
    ("POST", "/v1/scanner/cache/rollback"),
    ("PATCH", "/v1/scanner/tools/trivy"),
    ("POST", "/v1/scanner/tools/trivy/update"),
    ("POST", "/v1/projects"),
    ("POST", "/v1/source-snapshots"),
    ("DELETE", "/v1/projects/1"),
    ("POST", "/v1/scans"),
    ("DELETE", "/v1/scans/1"),
    ("POST", "/v1/scans/1/triage"),
    ("POST", "/v1/findings/bulk"),
    ("POST", "/v1/findings/1/triage"),
    ("PATCH", "/v1/findings/1/lifecycle"),
    ("DELETE", "/v1/findings/1"),
    ("POST", "/v1/jobs/1/cancel"),
    ("POST", "/v1/jobs/1/retry"),
    ("POST", "/v1/jobs/1/reconcile"),
    ("PUT", "/v1/gate-policies/1"),
    ("POST", "/v1/auth/logout"),
    ("POST", "/v1/auth/browser/pairing-token"),
    ("POST", f"/v1/auth/ide/enrollments/{'ker1_' + 'x' * 24}/decision"),
    ("DELETE", "/v1/auth/ide/capabilities/test"),
    ("DELETE", "/v1/auth/ide/capabilities/test/pending"),
    ("DELETE", "/v1/auth/ide/capabilities/ks1_" + "x" * 43 + "/invalid"),
]


@pytest.fixture()
def secure_client(postgres_engine, tmp_path: Path):
    static_root = tmp_path / "static"
    assets = static_root / "assets"
    assets.mkdir(parents=True)
    (static_root / "index.html").write_text("<!doctype html><title>CodeSecurity test</title><main>secure workbench</main>", encoding="utf-8")
    (assets / "app-deadbeef.js").write_text("globalThis.kodesecTest = true;", encoding="utf-8")
    outside_asset = tmp_path / "outside.js"
    outside_asset.write_text("globalThis.outside = true;", encoding="utf-8")
    try:
        (assets / "escape.js").symlink_to(outside_asset)
    except OSError:
        pass

    initialize_database(postgres_engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL=str(postgres_engine.url),
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_SOURCE_SNAPSHOT_DIR=str(tmp_path / "source-snapshots"),
        KODESEC_STATIC_DIR=str(static_root),
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )
    runtime = Runtime.create(settings, engine=postgres_engine)
    app = create_app(runtime_override=runtime)
    with TestClient(app, base_url=ORIGIN) as client:
        yield client


def _bootstrap(client: TestClient) -> str:
    if client.cookies.get(SESSION_COOKIE):
        retained = client.get("/v1/auth/session")
        assert retained.status_code == 200, retained.text
        return str(retained.json()["csrf_token"])
    response = client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": BOOTSTRAP_TOKEN},
    )
    assert response.status_code == 200, response.text
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    return str(response.json()["csrf_token"])


def test_cookie_parser_fails_closed_only_for_cookie_syntax(monkeypatch) -> None:
    malformed = Headers({"cookie": "session=value; $bad=attribute"})
    assert SecurityBoundaryMiddleware._cookie(malformed, SESSION_COOKIE) == ""

    class BrokenCookieParser:
        def load(self, _value: str) -> None:
            raise RuntimeError("unexpected parser failure")

    monkeypatch.setattr(security_module, "SimpleCookie", BrokenCookieParser)
    with pytest.raises(RuntimeError, match="unexpected parser failure"):
        SecurityBoundaryMiddleware._cookie(Headers({"cookie": "session=value"}), SESSION_COOKIE)


def _pairing_token(client: TestClient) -> str:
    del client
    return "browser-reviewed-device-enrollment"


def _pair_ide(
    client: TestClient,
    *,
    pairing_token: str,
    client_name: str,
    client_slot: str,
    expected_active_generation: int,
    activate: bool,
) -> tuple[dict[str, object], dict[str, str]]:
    paired = client.post(
        "/v1/auth/ide/enrollments",
        json={
            "client_name": client_name,
            "client_slot": client_slot,
            "expected_active_generation": expected_active_generation,
        },
    )
    assert pairing_token == "browser-reviewed-device-enrollment"
    assert paired.status_code == 201, paired.text
    payload = paired.json()
    csrf = _bootstrap(client)
    approved = client.post(
        f"/v1/auth/ide/enrollments/{payload['request_id']}/decision",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "decision": "approved",
            "expected_revision": payload["revision"],
            "expected_generation": payload["generation"],
        },
    )
    assert approved.status_code == 200, approved.text
    bearer = {"Authorization": f"Bearer {payload['capability']}"}
    if activate:
        activated = client.post("/v1/auth/ide/activate", headers=bearer)
        assert activated.status_code == 200, activated.text
        assert activated.json()["client_slot"] == client_slot
        assert activated.json()["generation"] == payload["generation"]
        assert activated.json()["scopes"] == list(IDE_CAPABILITY_SCOPES)
    return payload, bearer


def test_git_push_repository_requires_explicit_owner_grant_and_current_ide(secure_client: TestClient):
    """Real middleware, persistent capability and CSRF checks; no auth mocks."""
    from hashlib import sha256
    root = "/workspaces/git-fixture"
    repository = sha256(f"lomo-git-repository/v1\0{root}\0{root}/.git".encode()).hexdigest()
    route = f"/v1/git/push-protection/{repository}"
    registration = {"repository_id": repository, "name": "Git fixture", "project_id": None,
        "root_path": root, "git_directory": root + "/.git"}
    assert secure_client.get(route).status_code == 401
    slot = "ks1_" + "s" * 43
    paired, bearer = _pair_ide(secure_client, pairing_token=_pairing_token(secure_client),
        client_name="Push protection fixture", client_slot=slot, expected_active_generation=0, activate=True)
    assert paired["scopes"] == list(IDE_CAPABILITY_SCOPES), "this feature must not silently broaden retained authority"
    response = secure_client.post("/v1/git/push-protection", headers=bearer, json=registration)
    assert response.status_code == 201, response.text
    pending = response.json()
    assert pending["members"][0]["state"] == "requested" and pending["enabled"] is False
    # Empty tree is a genuine immutable Git tree, requiring no source body.
    empty_tree = sha256(b"tree 0\0").hexdigest()
    payload = {"object_format": "sha256", "tree_oid": empty_tree, "files": []}
    denied = secure_client.post(route + "/trees", headers=bearer, json=payload)
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "push_approval_required"
    approval = route + f"/members/{slot}/1"
    decision = {"expected_revision": pending["revision"], "approve": True}
    assert secure_client.post(approval, headers=bearer, json=decision).status_code == 403
    assert secure_client.post(approval, headers={"Origin": ORIGIN}, json=decision).status_code == 403
    owner = {"Origin": ORIGIN, "X-CSRF-Token": _bootstrap(secure_client)}
    approved = secure_client.post(approval, headers=owner, json=decision)
    assert approved.status_code == 200, approved.text
    assert approved.json()["members"][0]["state"] == "approved"
    uploaded = secure_client.post(route + "/trees", headers=bearer, json=payload)
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["source_id"] == repository
    assert secure_client.post(route + "/trees", headers=owner, json=payload).status_code == 403
    revoked = secure_client.request("DELETE", f"/v1/auth/ide/capabilities/{slot}", headers=owner,
        json={"expected_latest_generation": 1, "expected_active_generation": 1, "expected_pending_generation": None})
    assert revoked.status_code == 200, revoked.text
    assert secure_client.post(route + "/trees", headers=bearer, json=payload).status_code == 401


def test_git_push_removal_requires_current_grant_and_preserves_project(secure_client: TestClient):
    """Real middleware, CSRF and member boundaries for exact host cleanup."""
    from hashlib import sha256
    root = "/workspaces/long-source-folder/git-push-acceptance/synthetic-removal-fixture/source"
    repository = sha256(f"lomo-git-repository/v1\0{root}\0{root}/.git".encode()).hexdigest()
    route = f"/v1/git/push-protection/{repository}"
    slot = "ks1_" + "m" * 43
    _, bearer = _pair_ide(secure_client, pairing_token=_pairing_token(secure_client),
        client_name="Removal fixture", client_slot=slot, expected_active_generation=0, activate=True)
    created = secure_client.post("/v1/git/push-protection", headers=bearer, json={
        "repository_id": repository, "name": "Removal fixture", "root_path": root, "git_directory": root + "/.git"})
    assert created.status_code == 201, created.text
    pending = created.json()
    removal = {"expected_revision": pending["revision"], "confirm_removal": True, "hook_digest": None}
    denied = secure_client.post(route + "/remove", headers=bearer, json=removal)
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "push_approval_required"
    assert secure_client.post(route + "/remove", headers={"Origin": ORIGIN}, json=removal).status_code == 403
    owner = {"Origin": ORIGIN, "X-CSRF-Token": _bootstrap(secure_client)}
    approved = secure_client.post(route + f"/members/{slot}/1", headers=owner,
        json={"expected_revision": pending["revision"], "approve": True})
    assert approved.status_code == 200, approved.text
    removal["expected_revision"] = approved.json()["revision"]
    assert secure_client.post(route + "/remove", headers=owner, json=removal).status_code == 403
    guard = secure_client.delete(f'/v1/projects/{pending["project_id"]}', headers=owner)
    assert guard.status_code == 409 and guard.json()["detail"]["code"] == "push_protection_attached"
    removed = secure_client.post(route + "/remove", headers=bearer, json=removal)
    assert removed.status_code == 200, removed.text
    assert removed.json()["removed"] is True and removed.json()["already_removed"] is False
    assert secure_client.get(f'/v1/projects/{pending["project_id"]}', headers=owner).status_code == 200
    retry = secure_client.post(route + "/remove", headers=bearer, json=removal)
    assert retry.status_code == 200 and retry.json()["already_removed"] is True
    revoked = secure_client.request("DELETE", f"/v1/auth/ide/capabilities/{slot}", headers=owner,
        json={"expected_latest_generation": 1, "expected_active_generation": 1, "expected_pending_generation": None})
    assert revoked.status_code == 200, revoked.text
    assert secure_client.post(route + "/remove", headers=bearer, json=removal).status_code == 401


def test_advisor_provider_crud_is_revision_fenced_and_redacted(
    secure_client: TestClient,
) -> None:
    csrf = _bootstrap(secure_client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    provider = {
        "id": "direct-lab",
        "name": "Lab Advisor",
        "transport": "direct",
        "priority": 0,
        "enabled": True,
        "base_url": f"http://{ADVISOR_FIXTURE_HOST}:11434",
        "model": ADVISOR_FIXTURE_MODEL,
        "model_digest": "a" * 64,
        "ssh_host": None,
        "ssh_port": None,
        "ssh_user": None,
    }
    created = secure_client.post(
        "/v1/advisor/providers",
        headers=headers,
        json={"expected_revision": 1, "provider": provider},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["revision"] == 2
    assert body["providers"][0]["authorization"] == "required"
    assert body["providers"][0]["content_disclosure_approved"] is False
    assert body["providers"][0]["config_revision"] == 1
    assert len(body["providers"][0]["config_digest"]) == 64
    assert body["providers"][0]["eligible"] is False
    assert body["providers"][0]["reason_code"] == "authorization_required"
    assert body["providers"][0]["remediation"] == "authorize"
    assert all(
        forbidden not in json.dumps(body).lower()
        for forbidden in ("private_key", "identity_file", "known_hosts", "fingerprint")
    )
    stale = secure_client.put(
        "/v1/advisor/providers/direct-lab",
        headers=headers,
        json={"expected_revision": 1, "provider": provider | {"name": "Changed"}},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["safe_details"] == {"current_revision": 2}
    consent_key = "advisor.provider.consent.v1.direct-lab"
    receipt_key = "advisor.provider.receipt.v1.direct-lab"
    with secure_client.app.state.runtime.session_factory() as db, db.begin():
        db.add(
            RuntimeConfig(
                key=consent_key,
                value=json.dumps(
                    {
                        "schema": "lomo-advisor-source-consent/v1",
                        "provider_id": "direct-lab",
                        "provider_config_revision": body["providers"][0]["config_revision"],
                        "provider_config_digest": body["providers"][0]["config_digest"],
                        "transport": "direct",
                        "destination": f"http://{ADVISOR_FIXTURE_HOST}:11434",
                        "disclosure_mode": "finding_evidence",
                        "payload_categories": [
                            "finding_identity",
                            "source_location",
                            "repository_context",
                            "bounded_code_snippet",
                            "bounded_scanner_metadata",
                        ],
                        "model": ADVISOR_FIXTURE_MODEL,
                        "model_digest": "a" * 64,
                        "approved_at": "2026-08-25T12:00:00Z",
                    },
                    separators=(",", ":"),
                ),
            )
        )
        db.add(
            RuntimeConfig(
                key=receipt_key,
                value=json.dumps(
                    {
                        "schema": "lomo-advisor-provider-receipt/v1",
                        "provider_id": "direct-lab",
                        "kind": "direct",
                        "route": "direct",
                        "model": ADVISOR_FIXTURE_MODEL,
                        "model_digest": "a" * 64,
                        "status": "ready",
                        "tested_at": "2026-08-25T12:00:00Z",
                        "revision": body["providers"][0]["config_revision"],
                    },
                    separators=(",", ":"),
                ),
            )
        )
    assert secure_client.get(
        "/v1/advisor/providers/direct-lab/receipt"
    ).status_code == 200
    changed = secure_client.put(
        "/v1/advisor/providers/direct-lab",
        headers=headers,
        json={
            "expected_revision": 2,
            "provider": provider
            | {
                "name": "Changed",
                "base_url": "http://10.23.45.68:11434",
            },
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["revision"] == 3
    with secure_client.app.state.runtime.session_factory() as db:
        assert db.get(RuntimeConfig, consent_key) is None
        assert db.get(RuntimeConfig, receipt_key) is None
    assert secure_client.get(
        "/v1/advisor/providers/direct-lab/receipt"
    ).status_code == 404
    deleted = secure_client.request(
        "DELETE",
        "/v1/advisor/providers/direct-lab",
        headers=headers,
        json={"expected_revision": 3},
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["providers"] == []


def _ready_scanner_runtime_inventory() -> dict[str, dict[str, object]]:
    readiness = {
        "binary": {"state": "ready", "reason": None, "component_ids": []},
        "data": {"state": "not_required", "reason": None, "component_ids": []},
        "rules": {"state": "not_required", "reason": None, "component_ids": []},
        "execution": {"state": "ready", "reason": None, "component_ids": []},
    }
    return {
        tool_id: {
            "id": tool_id,
            "available": True,
            "status": "ready",
            "installed_version": metadata["current_version"],
            "readiness": readiness,
            "runtime_ready": True,
        }
        for tool_id, metadata in main_module.SCANNER_TOOL_REGISTRY.items()
        if metadata["source"] == "external"
    }


def test_browser_bootstrap_session_csrf_and_replay(secure_client: TestClient) -> None:
    assert secure_client.get("/v1/projects").status_code == 401
    assert secure_client.post("/v1/auth/bootstrap", json={"bootstrap_token": BOOTSTRAP_TOKEN}).status_code == 403
    assert secure_client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": "wrong"},
    ).status_code == 401

    csrf = _bootstrap(secure_client)
    replay = secure_client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": BOOTSTRAP_TOKEN},
    )
    assert replay.status_code == 409

    session = secure_client.get("/v1/auth/session")
    assert session.status_code == 200
    assert session.headers["cache-control"] == "no-store"
    assert session.json()["csrf_token"] == csrf

    payload = {"name": "browser-project", "repo_path": "/workspaces/browser", "default_branch": "main"}
    assert secure_client.post("/v1/projects", json=payload).status_code == 403
    assert secure_client.post(
        "/v1/projects",
        headers={"Origin": ORIGIN, "X-CSRF-Token": "bad"},
        json=payload,
    ).status_code == 403
    created = secure_client.post(
        "/v1/projects",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json=payload,
    )
    assert created.status_code == 201, created.text
    outside = secure_client.post(
        "/v1/projects",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={"name": "outside", "repo_path": "/tmp/outside", "default_branch": "main"},
    )
    assert outside.status_code == 422
    assert outside.json()["detail"] == {
        "code": "source_outside_allowed_root",
        "message": "The selected directory is outside the authorized source root.",
        "action": "authorize_source",
        "safe_details": {
            "selected_source": "/tmp/outside",
            "configured_source_boundary": "/workspaces",
        },
        "context": {
            "source_target": {
                "kind": "mounted_directory",
                "display_path": "/tmp/outside",
            },
            "authorization_boundary": {
                "kind": "allowed_roots",
                "display_paths": ["/workspaces"],
            },
            "selected_path": "/tmp/outside",
            "allowed_roots": ["/workspaces"],
        },
    }


def test_every_mutating_route_requires_authentication_and_browser_csrf(secure_client: TestClient) -> None:
    for method, path in MUTATING_ROUTES:
        response = secure_client.request(method, path, headers={"Origin": ORIGIN}, json={})
        assert response.status_code in {401, 429}, (method, path, response.text)

    _bootstrap(secure_client)
    for method, path in MUTATING_ROUTES:
        response = secure_client.request(method, path, headers={"Origin": ORIGIN}, json={})
        assert response.status_code == 403, (method, path, response.text)


def test_invalid_slot_recovery_rejects_ide_bearer(secure_client: TestClient) -> None:
    slot = "ks1_" + "y" * 43
    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="IDE cannot recover invalid server state",
        client_slot=slot,
        expected_active_generation=0,
        activate=True,
    )
    denied = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}/invalid",
        headers=bearer,
        json={"recovery_token": "kir1_" + "a" * 64},
    )
    assert denied.status_code == 403, denied.text
    assert denied.json() == {
        "detail": "IDE capability does not permit this endpoint"
    }


def test_ide_slot_pending_activation_rotation_and_recovery_are_exact(
    secure_client: TestClient,
) -> None:
    slot = "ks1_" + "q" * 43

    first, first_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="first durable profile",
        client_slot=slot,
        expected_active_generation=0,
        activate=False,
    )
    assert first["client_slot"] == slot
    assert first["generation"] == 1
    assert first["scopes"] == list(IDE_CAPABILITY_SCOPES)
    assert secure_client.post(
        "/v1/projects",
        headers=first_bearer,
        json={"name": "pending-must-be-inert", "repo_path": "/workspaces/pending", "default_branch": "main"},
    ).status_code == 401

    activated = secure_client.post("/v1/auth/ide/activate", headers=first_bearer)
    assert activated.status_code == 200, activated.text
    assert activated.json()["generation"] == 1
    assert secure_client.post("/v1/auth/ide/activate", headers=first_bearer).status_code == 200
    created = secure_client.post(
        "/v1/projects",
        headers=first_bearer,
        json={"name": "active-generation-one", "repo_path": "/workspaces/active-one", "default_branch": "main"},
    )
    assert created.status_code == 201, created.text

    second, second_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="second durable profile",
        client_slot=slot,
        expected_active_generation=1,
        activate=False,
    )
    assert second["generation"] == 2
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=first_bearer,
        json={"repo_path": "/workspaces/active-one"},
    ).status_code == 200
    assert secure_client.get("/v1/projects", headers=second_bearer).status_code == 401

    csrf = _bootstrap(secure_client)
    browser_headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    listed = secure_client.get("/v1/auth/ide/capabilities")
    assert listed.status_code == 200, listed.text
    slot_state = next(item for item in listed.json() if item["id"] == slot)
    assert {key: slot_state[key] for key in (
        "id",
        "client_name",
        "active",
        "revoked",
        "active_generation",
        "latest_generation",
        "pending_activation",
        "pending_generation",
        "pending_client_name",
    )} == {
        "id": slot,
        "client_name": "first durable profile",
        "active": True,
        "revoked": False,
        "active_generation": 1,
        "latest_generation": 2,
        "pending_activation": True,
        "pending_generation": 2,
        "pending_client_name": "second durable profile",
    }
    cancelled = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}/pending",
        headers=browser_headers,
        json={"expected_pending_generation": 2},
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {"cancelled": True}
    assert secure_client.post("/v1/auth/ide/activate", headers=second_bearer).status_code == 401
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=first_bearer,
        json={"repo_path": "/workspaces/active-one"},
    ).status_code == 200

    third, third_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="third durable profile",
        client_slot=slot,
        expected_active_generation=1,
        activate=False,
    )
    assert third["generation"] == 3
    assert secure_client.post("/v1/auth/ide/activate", headers=third_bearer).status_code == 200
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=first_bearer,
        json={"repo_path": "/workspaces/active-one"},
    ).status_code == 401

    stale_reset = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}",
        headers=browser_headers,
        json={
            "expected_latest_generation": 2,
            "expected_active_generation": 3,
            "expected_pending_generation": None,
        },
    )
    assert stale_reset.status_code == 409
    assert stale_reset.json()["detail"]["code"] == "ide_pairing_reset_generation_conflict"
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=third_bearer,
        json={"repo_path": "/workspaces/active-one"},
    ).status_code == 200

    blocked_recovery = secure_client.post(
        "/v1/auth/ide/enrollments",
        json={
            "client_name": "missing local authority",
            "client_slot": slot,
            "expected_active_generation": 0,
        },
    )
    assert blocked_recovery.status_code == 409
    assert blocked_recovery.json()["detail"]["code"] == "ide_enrollment_generation_conflict"
    assert blocked_recovery.json()["detail"]["action"] == (
        "revoke_or_restore_profile_authority"
    )
    revoked = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}",
        headers=browser_headers,
        json={
            "expected_latest_generation": 3,
            "expected_active_generation": 3,
            "expected_pending_generation": None,
        },
    )
    assert revoked.status_code == 200
    assert secure_client.get("/v1/events", headers=third_bearer).status_code == 401
    retained = next(
        item for item in secure_client.get("/v1/auth/ide/capabilities").json()
        if item["id"] == slot
    )
    assert retained["client_name"] == "third durable profile"
    assert retained["active_generation"] == 3
    assert retained["latest_generation"] == 3
    assert retained["active"] is False
    assert retained["revoked"] is True

    abandoned, _ = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="abandoned pending",
        client_slot=slot,
        expected_active_generation=0,
        activate=False,
    )
    assert abandoned["generation"] == 4
    assert secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}/pending",
        headers=browser_headers,
        json={"expected_pending_generation": 4},
    ).json() == {"cancelled": True}
    successor, successor_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="successor pending",
        client_slot=slot,
        expected_active_generation=3,
        activate=False,
    )
    assert successor["generation"] == 5
    stale_browser_cleanup = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}/pending",
        headers=browser_headers,
        json={"expected_pending_generation": 4},
    )
    assert stale_browser_cleanup.status_code == 409
    assert stale_browser_cleanup.json()["detail"] == {
        "code": "ide_pairing_pending_generation_conflict",
        "message": "The pending IDE authority changed before this cancellation request was applied.",
        "action": "refresh_paired_ide_clients",
    }
    after_stale_cleanup = next(
        item for item in secure_client.get("/v1/auth/ide/capabilities").json()
        if item["id"] == slot
    )
    assert after_stale_cleanup["pending_generation"] == 5
    stale_full_reset = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}",
        headers=browser_headers,
        json={
            "expected_latest_generation": 4,
            "expected_active_generation": 3,
            "expected_pending_generation": 4,
        },
    )
    assert stale_full_reset.status_code == 409
    assert stale_full_reset.json()["detail"]["code"] == (
        "ide_pairing_reset_generation_conflict"
    )
    after_stale_reset = next(
        item for item in secure_client.get("/v1/auth/ide/capabilities").json()
        if item["id"] == slot
    )
    assert after_stale_reset["pending_generation"] == 5
    late_cleanup = secure_client.delete(
        "/v1/auth/ide/pending",
        headers={"Authorization": f"Bearer {abandoned['capability']}"},
    )
    assert late_cleanup.status_code == 401
    assert secure_client.post("/v1/auth/ide/activate", headers=successor_bearer).status_code == 200


def test_expired_pending_is_typed_inert_and_preserves_active_route_separation(
    secure_client: TestClient,
) -> None:
    slot = "ks1_" + "t" * 43
    _, active_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="retained active",
        client_slot=slot,
        expected_active_generation=0,
        activate=True,
    )
    pending, pending_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="expired candidate",
        client_slot=slot,
        expected_active_generation=1,
        activate=False,
    )
    with secure_client.app.state.runtime.session_factory.begin() as db:
        row = db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{slot}")
        assert row is not None
        record = json.loads(row.value)
        issued_at = datetime.now(timezone.utc) - timedelta(minutes=11)
        record["pending"]["issued_at"] = issued_at.isoformat()
        record["pending"]["activation_expires_at"] = (
            issued_at + timedelta(minutes=10)
        ).isoformat()
        row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
        enrollment = db.scalar(select(IdeEnrollment).where(
            IdeEnrollment.client_slot == slot,
            IdeEnrollment.generation == pending["generation"],
        ))
        assert enrollment is not None
        enrollment.requested_at = issued_at
        enrollment.decision_at = issued_at + timedelta(seconds=1)
        enrollment.activation_expires_at = issued_at + timedelta(minutes=10)

    assert secure_client.post(
        "/v1/projects/resolve",
        headers=pending_bearer,
        json={"repo_path": "/workspaces/not-created"},
    ).status_code == 401
    expired = secure_client.post("/v1/auth/ide/activate", headers=pending_bearer)
    assert expired.status_code == 410
    assert expired.json()["detail"] == {
        "code": "ide_enrollment_expired",
        "message": "The approved IDE enrollment expired before durable local activation.",
        "action": "start_new_enrollment",
    }
    assert secure_client.delete("/v1/auth/ide/pending", headers=active_bearer).status_code == 401
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=active_bearer,
        json={"repo_path": "/workspaces/not-created"},
    ).status_code == 404

    csrf = _bootstrap(secure_client)
    browser_headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    assert secure_client.post(
        "/v1/auth/ide/activate",
        headers=browser_headers,
    ).status_code == 401
    cancelled = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}/pending",
        headers=browser_headers,
        json={"expected_pending_generation": pending["generation"]},
    )
    assert cancelled.status_code == 200, cancelled.text
    retained = next(
        item for item in secure_client.get("/v1/auth/ide/capabilities").json()
        if item["id"] == slot
    )
    assert retained["active"] is True
    assert retained["active_generation"] == 1
    assert retained["latest_generation"] == 2
    assert retained["pending_generation"] is None


def test_pending_only_slot_reset_preserves_generation_and_allows_expected_zero(
    secure_client: TestClient,
) -> None:
    slot = "ks1_" + "u" * 43
    first, first_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="lost pending file",
        client_slot=slot,
        expected_active_generation=0,
        activate=False,
    )
    csrf = _bootstrap(secure_client)
    reset = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{slot}",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "expected_latest_generation": 1,
            "expected_active_generation": None,
            "expected_pending_generation": 1,
        },
    )
    assert reset.status_code == 200, reset.text
    state = next(
        item for item in secure_client.get("/v1/auth/ide/capabilities").json()
        if item["id"] == slot
    )
    assert state["active_generation"] is None
    assert state["latest_generation"] == 1
    assert state["pending_generation"] is None
    assert secure_client.post("/v1/auth/ide/activate", headers=first_bearer).status_code == 401

    successor, successor_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="replacement pending file",
        client_slot=slot,
        expected_active_generation=0,
        activate=False,
    )
    assert first["generation"] == 1
    assert successor["generation"] == 2
    assert secure_client.post("/v1/auth/ide/activate", headers=successor_bearer).status_code == 200


def test_ide_pairing_bearer_scope_and_revocation(secure_client: TestClient) -> None:
    pairing_token = _pairing_token(secure_client)
    slot = "ks1_" + "a" * 43
    paired, bearer = _pair_ide(
        secure_client,
        pairing_token=pairing_token,
        client_name="VS Code test",
        client_slot=slot,
        expected_active_generation=0,
        activate=True,
    )
    capability = str(paired["capability"])
    assert paired["scopes"] == list(IDE_CAPABILITY_SCOPES)
    assert capability.startswith("kc1.")
    assert pairing_token not in json.dumps(paired)
    assert secure_client.get("/v1/projects", headers=bearer).status_code == 403
    created = secure_client.post(
        "/v1/projects",
        headers=bearer,
        json={"name": "ide-project", "repo_path": "/workspaces/ide", "default_branch": "main"},
    )
    assert created.status_code == 201, created.text
    resolved = secure_client.post(
        "/v1/projects/resolve",
        headers=bearer,
        json={"repo_path": "/workspaces/ide"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["id"] == created.json()["id"]
    assert secure_client.get("/v1/auth/ide/capabilities", headers=bearer).status_code == 403

    csrf = _bootstrap(secure_client)
    capabilities = secure_client.get("/v1/auth/ide/capabilities")
    assert capabilities.status_code == 200
    capability_id = capabilities.json()[0]["id"]
    assert capability not in capabilities.text
    revoked = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{capability_id}",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "expected_latest_generation": 1,
            "expected_active_generation": 1,
            "expected_pending_generation": None,
        },
    )
    assert revoked.status_code == 200
    assert secure_client.post(
        "/v1/projects/resolve",
        headers=bearer,
        json={"repo_path": "/workspaces/ide"},
    ).status_code == 401


def test_browser_issues_one_time_key_for_a_distinct_browser_session(
    secure_client: TestClient,
) -> None:
    route = "/v1/auth/browser/pairing-token"
    assert secure_client.post(route, headers={"Origin": ORIGIN}).status_code == 401
    csrf = _bootstrap(secure_client)
    assert secure_client.post(route, headers={"Origin": ORIGIN}).status_code == 403
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}

    paired_ide, ide_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="browser issuer boundary",
        client_slot="ks1_" + "e" * 43,
        expected_active_generation=0,
        activate=True,
    )
    ide_capability = paired_ide["capability"]
    ide_request_code = paired_ide["verification_code"]
    assert secure_client.post(
        route,
        headers=ide_bearer,
    ).status_code == 403

    superseded_response = secure_client.post(route, headers=headers)
    assert superseded_response.status_code == 200, superseded_response.text
    assert superseded_response.headers["cache-control"] == "no-store"
    assert superseded_response.headers["pragma"] == "no-cache"
    superseded = superseded_response.json()["bootstrap_token"]
    assert superseded.startswith("kb1.")
    assert superseded_response.json()["expires_in"] == 600

    current_response = secure_client.post(route, headers=headers)
    assert current_response.status_code == 200, current_response.text
    current = current_response.json()["bootstrap_token"]
    assert current != superseded
    with secure_client.app.state.runtime.session_factory() as db:
        stored = db.get(RuntimeConfig, DYNAMIC_BROWSER_PAIRING_KEY)
        assert stored is not None
        assert superseded not in stored.value
        assert current not in stored.value

    target = TestClient(secure_client.app, base_url=ORIGIN)
    replay = TestClient(secure_client.app, base_url=ORIGIN)
    try:
        replaced = target.post(
            "/v1/auth/bootstrap",
            headers={"Origin": ORIGIN},
            json={"bootstrap_token": superseded},
        )
        assert replaced.status_code == 409
        assert replaced.json()["detail"] == {
            "code": "browser_pairing_token_superseded",
            "message": "This browser pairing key is no longer current because a newer key was generated.",
            "action": "obtain_new_browser_pairing_token",
        }

        ide_key_rejected = target.post(
            "/v1/auth/bootstrap",
            headers={"Origin": ORIGIN},
            json={"bootstrap_token": ide_request_code},
        )
        assert ide_key_rejected.status_code == 401
        ide_capability_rejected = target.post(
            "/v1/auth/bootstrap",
            headers={"Origin": ORIGIN},
            json={"bootstrap_token": ide_capability},
        )
        assert ide_capability_rejected.status_code == 401

        consumed = target.post(
            "/v1/auth/bootstrap",
            headers={"Origin": ORIGIN},
            json={"bootstrap_token": current},
        )
        assert consumed.status_code == 200, consumed.text
        cookie = consumed.headers["set-cookie"].lower()
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert target.get("/v1/auth/session").status_code == 200

        consumed_again = replay.post(
            "/v1/auth/bootstrap",
            headers={"Origin": ORIGIN},
            json={"bootstrap_token": current},
        )
        assert consumed_again.status_code == 409
        assert consumed_again.json()["detail"] == {
            "code": "browser_pairing_token_consumed",
            "message": "The one-time browser pairing key was already used.",
            "action": "obtain_new_browser_pairing_token",
        }
        assert replay.get("/v1/auth/session").status_code == 401
    finally:
        target.close()
        replay.close()


def test_capability_revoke_notifies_matching_stream_only_after_commit(
    secure_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability_id = "ks1_" + "f" * 43
    paired, _ = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="revoke callback",
        client_slot=capability_id,
        expected_active_generation=0,
        activate=True,
    )
    capability = str(paired["capability"])

    csrf = _bootstrap(secure_client)
    broker = secure_client.app.state.event_wake_broker
    observed: list[tuple[str, bool]] = []

    def observe(subject: str) -> int:
        with secure_client.app.state.runtime.session_factory() as db:
            row = db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{capability_id}")
            assert row is not None
            record = json.loads(row.value)
            observed.append((subject, record["active"]["revoked_at"] is not None))
        return 1

    monkeypatch.setattr(broker, "revoke_ide_slot", observe)
    revoked = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{capability_id}",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "expected_latest_generation": 1,
            "expected_active_generation": 1,
            "expected_pending_generation": None,
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert observed == [(capability_id, True)]
    revoked_again = secure_client.request(
        "DELETE",
        f"/v1/auth/ide/capabilities/{capability_id}",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "expected_latest_generation": 1,
            "expected_active_generation": 1,
            "expected_pending_generation": None,
        },
    )
    assert revoked_again.status_code == 200, revoked_again.text
    assert observed == [
        (capability_id, True),
        (capability_id, True),
    ]
    assert secure_client.get(
        "/v1/events",
        headers={
            "Authorization": f"Bearer {capability}",
            "Last-Event-ID": "0",
        },
    ).status_code == 401


def test_activation_replaces_retained_generation_before_stream_notification(
    secure_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = "ks1_" + "j" * 43
    first, first_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="retained authority",
        client_slot=slot,
        expected_active_generation=0,
        activate=True,
    )
    second, second_bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="durable successor",
        client_slot=slot,
        expected_active_generation=1,
        activate=False,
    )
    assert first["generation"] == 1
    assert second["generation"] == 2

    observed: list[str] = []

    def fail_after_observing_commit(subject: str) -> int:
        with secure_client.app.state.runtime.session_factory() as db:
            row = db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{slot}")
            assert row is not None
            record = json.loads(row.value)
            assert record["active"]["generation"] == 2
            assert record["pending"] is None
        observed.append(subject)
        if len(observed) == 1:
            raise RuntimeError("simulated post-commit stream notification failure")
        return 1

    monkeypatch.setattr(
        secure_client.app.state.event_wake_broker,
        "revoke_ide_slot",
        fail_after_observing_commit,
    )
    with pytest.raises(RuntimeError, match="post-commit stream notification failure"):
        secure_client.post("/v1/auth/ide/activate", headers=second_bearer)

    retried = secure_client.post("/v1/auth/ide/activate", headers=second_bearer)
    assert retried.status_code == 200, retried.text
    assert retried.json()["generation"] == 2
    assert observed == [slot, slot]
    assert secure_client.get("/v1/events", headers=first_bearer).status_code == 401


def test_ide_route_scope_map_is_explicit_and_closed() -> None:
    allowed = {
        ("POST", "/v1/auth/ide/browser-invitations"): "browser:invite",
        (
            "GET",
            "/v1/auth/ide/browser-invitations/abcdefghijklmnopqrstuvwx/membership",
        ): "browser:invite",
        ("GET", "/v1/events"): "event:read",
        ("POST", "/v1/ide/source-open-commands/0123456789abcdef0123456789abcdef/ack"): "source:open-ack",
        ("GET", "/v1/ide/source-open-commands/0123456789abcdef0123456789abcdef/context"): "source:open-context",
        ("GET", "/v1/advisor/providers"): "finding:advisor",
        ("GET", "/v1/advisor/triage-request-audit"): "finding:advisor",
        ("POST", "/v1/projects/resolve"): "project:resolve",
        ("POST", "/v1/projects"): "project:create",
        ("POST", "/v1/source-snapshots"): "source:snapshot",
        ("GET", "/v1/projects/7/scans/latest"): "scan:read",
        ("POST", "/v1/scans"): "scan:create",
        ("GET", "/v1/scans/41"): "scan:read",
        ("GET", "/v1/scans/41/summary"): "scan:read",
        ("GET", "/v1/scans/41/finding-files"): "finding:read",
        ("GET", "/v1/scans/41/finding-diagnostics"): "finding:read",
        ("GET", "/v1/scans/41/findings"): "finding:read",
        ("GET", "/v1/scans/41/findings/9"): "finding:read",
        ("POST", "/v1/findings/9/triage"): "finding:advisor",
        ("PATCH", "/v1/findings/9/lifecycle"): "finding:lifecycle",
        ("DELETE", "/v1/findings/9"): "finding:delete",
        ("GET", "/v1/jobs/12"): "job:read",
        ("POST", "/v1/jobs/12/cancel"): "job:cancel",
    }
    assert {scope for scope in allowed.values()} == set(IDE_CAPABILITY_SCOPES)
    for (method, path), expected_scope in allowed.items():
        assert ide_scope_for_request(method, path) == expected_scope

    for method, path in (
        ("GET", "/v1/config"),
        ("GET", "/v1/advisor/local-models"),
        ("GET", "/v1/advisor/providers/direct-lab"),
        ("POST", "/v1/advisor/triage-request-audit"),
        ("GET", "/v1/advisor/providers/direct-lab/receipt"),
        ("POST", "/v1/advisor/providers"),
        ("PUT", "/v1/advisor/providers/direct-lab"),
        ("DELETE", "/v1/advisor/providers/direct-lab"),
        ("POST", "/v1/advisor/providers/direct-lab/commands"),
        ("POST", "/v1/events"),
        ("PUT", "/v1/config"),
        ("PATCH", "/v1/config/advisor"),
        ("PATCH", "/v1/config/gate"),
        ("PATCH", "/v1/config/components"),
        ("GET", "/v1/projects"),
        ("GET", "/v1/projects/7"),
        ("DELETE", "/v1/projects/7"),
        ("GET", "/v1/scans"),
        ("DELETE", "/v1/scans/41"),
        ("POST", "/v1/scans/41/finding-files"),
        ("POST", "/v1/scans/41/finding-diagnostics"),
        ("POST", "/v1/scans/41/triage"),
        ("POST", "/v1/findings/bulk"),
        ("GET", "/v1/findings/9/packet"),
        ("POST", "/v1/jobs/12/retry"),
        ("POST", "/v1/jobs/12/reconcile"),
        ("GET", "/v1/gate-policies/7"),
        ("PUT", "/v1/gate-policies/7"),
        ("GET", "/v1/scanner/tools"),
        ("GET", "/v1/auth/ide/capabilities"),
        ("DELETE", "/v1/auth/ide/capabilities/test"),
        ("DELETE", "/v1/auth/ide/capabilities/ks1_" + "x" * 43 + "/invalid"),
    ):
        assert ide_scope_for_request(method, path) is None


def test_source_open_context_is_exact_recipient_only_and_does_not_grant_project_read(
    secure_client: TestClient,
) -> None:
    capabilities: list[tuple[str, str]] = []
    for offset, client_name in enumerate(("source context target", "other IDE")):
        paired, _ = _pair_ide(
            secure_client,
            pairing_token=_pairing_token(secure_client),
            client_name=client_name,
            client_slot="ks1_" + chr(ord("h") + offset) * 43,
            expected_active_generation=0,
            activate=True,
        )
        capability = str(paired["capability"])
        capabilities.append((capability, capability.split(".", 2)[1]))
    (target_capability, target_id), (other_capability, _) = capabilities
    command_id = "a" * 32
    with secure_client.app.state.runtime.session_factory.begin() as db:
        project = Project(name="nested source context", repo_path="/workspaces/current/k8s")
        db.add(project)
        db.flush()
        db.add(IdeSourceOpenCommand(
            id=command_id,
            requester_subject="browser:source-context-test",
            idempotency_key="1" * 67,
            request_digest="2" * 64,
            target_capability_id=target_id,
            expected_target_generation=1,
            project_id=project.id,
            project_repo_path=project.repo_path,
            scan_id=41,
            finding_id=501,
            scan_finding_number=3,
            expected_finding_revision=2,
            expected_findings_revision=9,
            status="queued",
            revision=1,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ))
        project_id = project.id

    target_headers = {"Authorization": f"Bearer {target_capability}"}
    context = secure_client.get(
        f"/v1/ide/source-open-commands/{command_id}/context",
        headers=target_headers,
    )
    assert context.status_code == 200, context.text
    assert context.json() == {
        "v": 1,
        "command_id": command_id,
        "project_id": project_id,
        "project_repo_path": "/workspaces/current/k8s",
    }
    assert secure_client.get(f"/v1/projects/{project_id}", headers=target_headers).status_code == 403
    assert secure_client.get(
        f"/v1/ide/source-open-commands/{command_id}/context",
        headers={"Authorization": f"Bearer {other_capability}"},
    ).status_code == 404

    with secure_client.app.state.runtime.session_factory.begin() as db:
        command = db.get(IdeSourceOpenCommand, command_id)
        assert command is not None
        command.status = "opened"
        command.acknowledged_at = datetime.now(timezone.utc)
    terminal = secure_client.get(
        f"/v1/ide/source-open-commands/{command_id}/context",
        headers=target_headers,
    )
    assert terminal.status_code == 409
    assert terminal.json()["detail"]["code"] == "ide_source_command_not_pending"

    expired_id = "b" * 32
    with secure_client.app.state.runtime.session_factory.begin() as db:
        db.add(IdeSourceOpenCommand(
            id=expired_id,
            requester_subject="browser:source-context-test",
            idempotency_key="3" * 67,
            request_digest="4" * 64,
            target_capability_id=target_id,
            expected_target_generation=1,
            project_id=project_id,
            project_repo_path="/workspaces/current/k8s",
            scan_id=41,
            finding_id=501,
            scan_finding_number=3,
            expected_finding_revision=2,
            expected_findings_revision=9,
            status="queued",
            revision=1,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=6),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        ))
    expired = secure_client.get(
        f"/v1/ide/source-open-commands/{expired_id}/context",
        headers=target_headers,
    )
    assert expired.status_code == 409
    assert expired.json()["detail"]["code"] == "ide_source_command_not_pending"
    with secure_client.app.state.runtime.session_factory() as db:
        assert db.get(IdeSourceOpenCommand, expired_id).status == "expired"


def test_advisor_request_audit_is_bounded_process_authoritative_and_body_free() -> None:
    audit = AdvisorRequestAudit(maximum_entries=2, instance_id="a" * 32)
    initial = audit.snapshot(501, 0)
    assert initial == {
        "schema": "lomo-advisor-request-audit/v1",
        "instance_id": "a" * 32,
        "finding_id": 501,
        "latest_sequence": 0,
        "retained_from_sequence": 1,
        "requested_after_sequence": 0,
        "matching_request_count": 0,
        "cursor_retained": True,
    }

    audit.observe("GET", "/v1/findings/501/triage")
    audit.observe("POST", "/v1/findings/0/triage")
    audit.observe("POST", "/v1/findings/501/triage")
    audit.observe("POST", "/v1/findings/502/triage")
    audit.observe("POST", "/v1/findings/501/triage")

    retained = audit.snapshot(501, 1)
    assert retained["latest_sequence"] == 3
    assert retained["retained_from_sequence"] == 2
    assert retained["matching_request_count"] == 1
    assert retained["cursor_retained"] is True
    expired = audit.snapshot(501, 0)
    assert expired["matching_request_count"] == 0
    assert expired["cursor_retained"] is False
    assert set(expired) == {
        "schema",
        "instance_id",
        "finding_id",
        "latest_sequence",
        "retained_from_sequence",
        "requested_after_sequence",
        "matching_request_count",
        "cursor_retained",
    }


def test_advisor_request_audit_records_admitted_triage_before_downstream_rejection() -> None:
    audit = AdvisorRequestAudit(instance_id="c" * 32)
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite:///:memory:",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )
    reached = False

    async def downstream(scope, receive, send):
        nonlocal reached
        reached = True
        await send({"type": "http.response.start", "status": 422, "headers": []})
        await send({"type": "http.response.body", "body": b'{"detail":"rejected"}'})

    middleware = SecurityBoundaryMiddleware(
        downstream,
        SimpleNamespace(settings=settings),
        advisor_request_audit=audit,
    )
    middleware._validate_capability = lambda _token: AuthContext(
        kind="ide",
        subject="ks1_" + "v" * 43,
        scopes=frozenset({"finding:advisor"}),
        capability_generation=1,
    )
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/findings/501/triage",
        "raw_path": b"/v1/findings/501/triage",
        "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1:8080"),
            (b"authorization", b"Bearer fixture-capability"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(middleware(scope, receive, send))
    assert reached is True
    assert messages[0]["status"] == 422
    observed = audit.snapshot(501, 0)
    assert observed["cursor_retained"] is True
    assert observed["matching_request_count"] == 1


def test_advisor_request_audit_observes_rejected_authenticated_triage(
    secure_client: TestClient,
) -> None:
    csrf = _bootstrap(secure_client)
    before_response = secure_client.get(
        "/v1/advisor/triage-request-audit",
        params={"finding_id": 501, "after_sequence": 0},
    )
    assert before_response.status_code == 200, before_response.text
    before = before_response.json()

    rejected = secure_client.post(
        "/v1/findings/501/triage",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={},
    )
    assert rejected.status_code == 422

    after_response = secure_client.get(
        "/v1/advisor/triage-request-audit",
        params={
            "finding_id": 501,
            "after_sequence": before["latest_sequence"],
        },
    )
    assert after_response.status_code == 200, after_response.text
    after = after_response.json()
    assert after["instance_id"] == before["instance_id"]
    assert after["requested_after_sequence"] == before["latest_sequence"]
    assert after["cursor_retained"] is True
    assert after["matching_request_count"] == 1


def test_ide_advisor_scope_reads_only_the_redacted_provider_collection(
    secure_client: TestClient,
) -> None:
    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="advisor-provider-reader",
        client_slot="ks1_" + "k" * 43,
        expected_active_generation=0,
        activate=True,
    )

    listed = secure_client.get("/v1/advisor/providers", headers=bearer)
    assert listed.status_code == 200, listed.text
    encoded = json.dumps(listed.json()).lower()
    assert all(
        forbidden not in encoded
        for forbidden in (
            "private_key",
            "identity_file",
            "known_hosts",
            "fingerprint",
        )
    )

    denied = (
        ("GET", "/v1/advisor/providers/local-test/receipt"),
        ("POST", "/v1/advisor/providers"),
        ("PUT", "/v1/advisor/providers/local-test"),
        ("DELETE", "/v1/advisor/providers/local-test"),
        ("POST", "/v1/advisor/providers/local-test/commands"),
    )
    for method, path in denied:
        response = secure_client.request(method, path, headers=bearer, json={})
        assert response.status_code == 403, (method, path, response.text)
        assert response.json() == {
            "detail": "IDE capability does not permit this endpoint"
        }


def test_ide_finding_read_scope_reaches_diagnostics_but_no_write_variant(
    secure_client: TestClient,
) -> None:
    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="diagnostic-reader",
        client_slot="ks1_" + "l" * 43,
        expected_active_generation=0,
        activate=True,
    )
    missing = secure_client.get(
        "/v1/scans/999999/finding-diagnostics", headers=bearer
    )
    assert missing.status_code == 404
    denied = secure_client.post(
        "/v1/scans/999999/finding-diagnostics", headers=bearer
    )
    assert denied.status_code == 403
    assert denied.json() == {"detail": "IDE capability does not permit this endpoint"}


def test_event_stream_requires_auth_header_cursor_and_forbids_query_state(
    secure_client: TestClient,
) -> None:
    assert secure_client.get("/v1/events", headers={"Last-Event-ID": "0"}).status_code == 401

    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="SSE security test",
        client_slot="ks1_" + "m" * 43,
        expected_active_generation=0,
        activate=True,
    )

    invalid = secure_client.get(
        "/v1/events",
        headers={**bearer, "Last-Event-ID": "-1"},
    )
    assert invalid.status_code == 400
    assert "non-negative decimal" in invalid.text
    assert secure_client.get("/v1/events?cursor=0", headers=bearer).status_code == 400

    with secure_client.stream(
        "GET",
        "/v1/events",
        headers={**bearer, "Last-Event-ID": str(2**63 - 1)},
    ) as response:
        body = response.read()
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-cache, no-transform"
        assert response.headers["x-accel-buffering"] == "no"
    assert body.index(b"event: stream.ready") < body.index(b"event: stream.reset")
    assert b'"reason":"cursor_ahead"' in body

    _bootstrap(secure_client)
    with secure_client.stream(
        "GET",
        "/v1/events",
        headers={"Last-Event-ID": str(2**63 - 1)},
    ) as browser_response:
        browser_body = browser_response.read()
        assert browser_response.status_code == 200
    assert b"event: stream.ready" in browser_body
    assert b"event: stream.reset" in browser_body


def test_nonconforming_broad_ide_capability_record_is_invalidated(
    secure_client: TestClient,
) -> None:
    slot = "ks1_" + "n" * 43
    paired, _ = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="broad-scope-test",
        client_slot=slot,
        expected_active_generation=0,
        activate=True,
    )
    capability = str(paired["capability"])
    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        row = db.get(RuntimeConfig, f"{CAPABILITY_PREFIX}{slot}")
        assert row is not None
        record = json.loads(row.value)
        record["active"]["scopes"] = ["api:read", "api:write"]
        row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
        db.add(row)
        db.commit()

    response = secure_client.post(
        "/v1/projects/resolve",
        headers={"Authorization": f"Bearer {capability}"},
        json={"repo_path": "/workspaces/broad-scope-test"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication required"}


def test_ide_capability_denies_operator_and_administration_endpoints(
    secure_client: TestClient,
) -> None:
    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="least-privilege-test",
        client_slot="ks1_" + "o" * 43,
        expected_active_generation=0,
        activate=True,
    )
    denied = (
        ("GET", "/v1/config"),
        ("PUT", "/v1/config"),
        ("PATCH", "/v1/config/advisor"),
        ("PATCH", "/v1/config/gate"),
        ("PATCH", "/v1/config/components"),
        ("GET", "/v1/scanner/tools"),
        ("GET", "/v1/scanner/lifecycle"),
        ("POST", "/v1/scanner/tools/check-latest"),
        ("POST", "/v1/scanner/prepare"),
        ("POST", "/v1/scanner/cache/update"),
        ("POST", "/v1/scanner/cache/rollback"),
        ("PATCH", "/v1/scanner/tools/trivy"),
        ("POST", "/v1/scanner/tools/trivy/update"),
        ("GET", "/v1/gate-policies/1"),
        ("PUT", "/v1/gate-policies/1"),
        ("GET", "/v1/projects"),
        ("GET", "/v1/projects/1"),
        ("DELETE", "/v1/projects/1"),
        ("GET", "/v1/scans"),
        ("DELETE", "/v1/scans/1"),
        ("POST", "/v1/scans/1/triage"),
        ("POST", "/v1/findings/bulk"),
        ("GET", "/v1/findings/1/packet"),
        ("GET", "/v1/jobs"),
        ("POST", "/v1/jobs/1/retry"),
        ("POST", "/v1/jobs/1/reconcile"),
        ("GET", "/v1/dashboard/summary"),
        ("GET", "/v1/auth/ide/capabilities"),
        ("DELETE", "/v1/auth/ide/capabilities/test"),
    )
    for method, path in denied:
        response = secure_client.request(method, path, headers=bearer, json={})
        assert response.status_code == 403, (method, path, response.text)
        assert response.json() == {"detail": "IDE capability does not permit this endpoint"}


def test_ide_job_scope_is_limited_to_its_scan_and_advisor_commands(
    secure_client: TestClient,
) -> None:
    paired, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="job-owner-test",
        client_slot="ks1_" + "p" * 43,
        expected_active_generation=0,
        activate=True,
    )
    capability = str(paired["capability"])
    capability_id = capability.split(".", 2)[1]
    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        owned = Job(
            kind="scan",
            title="Owned extension scan",
            status="queued",
            client_id=f"ide:{capability_id}",
            idempotency_key="h1$" + "a" * 64,
            payload={"v": 1},
        )
        browser_scan = Job(
            kind="scan",
            title="Browser scan",
            status="queued",
            client_id="browser:local-browser",
            idempotency_key="h1$" + "b" * 64,
            payload={"v": 1},
        )
        lifecycle = Job(
            kind="scanner_cache_update",
            title="Operator cache update",
            status="queued",
            client_id="browser:local-browser",
            idempotency_key="h1$" + "c" * 64,
            payload={"v": 1},
        )
        db.add_all([owned, browser_scan, lifecycle])
        db.commit()
        owned_id = owned.id
        browser_id = browser_scan.id
        lifecycle_id = lifecycle.id

    assert secure_client.get(f"/v1/jobs/{owned_id}", headers=bearer).status_code == 200
    cancelled = secure_client.post(f"/v1/jobs/{owned_id}/cancel", headers=bearer)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "cancelling"

    for job_id in (browser_id, lifecycle_id):
        read = secure_client.get(f"/v1/jobs/{job_id}", headers=bearer)
        cancel = secure_client.post(f"/v1/jobs/{job_id}/cancel", headers=bearer)
        assert read.status_code == 403
        assert cancel.status_code == 403
        assert read.json() == {"detail": "IDE capability cannot access this job"}
        assert cancel.json() == {"detail": "IDE capability cannot access this job"}

    with runtime.session_factory() as db:
        assert db.get(Job, browser_id).status == "queued"
        assert db.get(Job, lifecycle_id).status == "queued"


def test_concurrent_project_creation_returns_one_stable_binding_without_500(
    secure_client: TestClient,
) -> None:
    _, bearer = _pair_ide(
        secure_client,
        pairing_token=_pairing_token(secure_client),
        client_name="project-race-test",
        client_slot="ks1_" + "r" * 43,
        expected_active_generation=0,
        activate=True,
    )
    payload = {
        "name": "shared-basename",
        "repo_path": "/workspaces/race/shared-basename",
        "default_branch": "main",
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(
                lambda _: secure_client.post("/v1/projects", headers=bearer, json=payload),
                range(2),
            )
        )
    assert sorted(response.status_code for response in responses) == [201, 409]
    assert all(response.status_code != 500 for response in responses)
    resolved = secure_client.post(
        "/v1/projects/resolve",
        headers=bearer,
        json={"repo_path": payload["repo_path"]},
    )
    assert resolved.status_code == 200
    created = next(response for response in responses if response.status_code == 201)
    assert resolved.json()["id"] == created.json()["id"]


def test_scoped_runtime_updates_preserve_concurrent_scopes_and_apply_gate_atomically(
    secure_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        project = Project(
            name="scoped-runtime",
            repo_path="/workspaces/scoped-runtime",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed")
        db.add(scan)
        db.flush()
        db.add(Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="scoped.runtime.high",
            severity="high",
            file_path="src/runtime.py",
            start_line=1,
            end_line=1,
            message="scoped runtime gate fixture",
            fingerprint="scoped-runtime-high",
        ))
        db.commit()
        project_id = project.id
        scan_id = scan.id
        scan_revision = scan.revision

    csrf = _bootstrap(secure_client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    requests = (
        (
            "/v1/config/advisor",
            {
                "ai_mode": "off",
                "ollama_base_url": "http://127.0.0.1:11434",
                "ollama_model": "qwen3:14b",
                "ollama_thinking": True,
                "auto_triage_limit": 7,
            },
        ),
        (
            "/v1/config/components",
            {
                "component_monitoring_enabled": True,
                "component_git_proxy_enabled": False,
                "component_db_admin_enabled": True,
            },
        ),
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(
            lambda item: secure_client.patch(item[0], headers=headers, json=item[1]),
            requests,
        ))
    assert [response.status_code for response in responses] == [200, 200]

    config = secure_client.get("/v1/config").json()
    assert config["ai_mode"] == "off"
    assert config["ollama_model"] == "qwen3:14b"
    assert config["ollama_thinking"] is True
    assert config["component_monitoring_enabled"] is True
    assert config["component_git_proxy_enabled"] is False
    assert config["component_db_admin_enabled"] is True

    cross_scope = secure_client.patch(
        "/v1/config/advisor",
        headers=headers,
        json={**requests[0][1], "gate_active": False},
    )
    assert cross_scope.status_code == 422
    assert secure_client.get("/v1/config").json()["gate_active"] is True

    gate = secure_client.patch(
        "/v1/config/gate",
        headers=headers,
        json={
            "gate_preset": "custom",
            "gate_active": True,
            "gate_max_critical": 0,
            "gate_max_high": 0,
            "gate_block_secrets": False,
            "gate_apply_to_existing": True,
        },
    )
    assert gate.status_code == 200, gate.text
    assert gate.json()["component_monitoring_enabled"] is True
    assert gate.json()["ollama_model"] == "qwen3:14b"
    with runtime.session_factory() as db:
        policy = db.scalar(select(GatePolicy).where(GatePolicy.project_id == project_id))
        updated_scan = db.get(Scan, scan_id)
        assert policy is not None
        assert policy.max_high == 0
        assert updated_scan is not None
        assert updated_scan.revision == scan_revision + 1
        assert updated_scan.gate_decision == "fail"

    committed_config = secure_client.get("/v1/config").json()
    committed_scan = secure_client.get(f"/v1/scans/{scan_id}").json()

    def fail_gate_recalculation(_db, _project_id: int) -> None:
        raise RuntimeError("generated gate recalculation failure")

    monkeypatch.setattr(main_module, "_recalculate_project_scan_gates", fail_gate_recalculation)
    with pytest.raises(RuntimeError, match="generated gate recalculation failure"):
        secure_client.patch(
            "/v1/config/gate",
            headers=headers,
            json={
                "gate_preset": "observe",
                "gate_active": False,
                "gate_max_critical": -1,
                "gate_max_high": -1,
                "gate_block_secrets": False,
                "gate_apply_to_existing": True,
            },
        )
    rolled_back_config = secure_client.get("/v1/config").json()
    assert {
        key: rolled_back_config[key]
        for key in (
            "gate_preset",
            "gate_active",
            "gate_max_critical",
            "gate_max_high",
            "gate_block_secrets",
        )
    } == {
        key: committed_config[key]
        for key in (
            "gate_preset",
            "gate_active",
            "gate_max_critical",
            "gate_max_high",
            "gate_block_secrets",
        )
    }
    assert secure_client.get(f"/v1/scans/{scan_id}").json() == committed_scan


def test_host_origin_url_credentials_and_secret_responses(secure_client: TestClient) -> None:
    invalid_host = secure_client.get("/healthz", headers={"Host": "attacker.invalid"})
    assert invalid_host.status_code == 400
    assert invalid_host.headers["x-content-type-options"] == "nosniff"
    assert invalid_host.headers["x-frame-options"] == "DENY"
    assert secure_client.get("/healthz", headers={"Host": "localhost:8080"}).status_code == 400
    assert secure_client.get("/", headers={"Origin": "https://attacker.invalid"}).status_code == 403
    for query in (
        "token=secret",
        "password=secret",
        "client_secret=secret",
        "clientSecret=secret",
        "apiKey=secret",
        "deploy-credential=secret",
        "passphrase=secret",
        "private_key=secret",
        "X-Amz-Signature=secret",
    ):
        assert secure_client.get(f"/v1/projects?{query}").status_code == 400
    assert secure_client.get("/healthz?format=json").status_code == 200

    csrf = _bootstrap(secure_client)
    config = secure_client.get("/v1/config")
    assert config.status_code == 200
    body = config.text
    for secret in (INSTALLATION_SECRET, BOOTSTRAP_TOKEN):
        assert secret not in body
    for forbidden_name in ("password", "component_credentials", "installation_secret", "bootstrap_token", "pairing_token"):
        assert forbidden_name not in body.lower()

    wrong_origin = secure_client.put(
        "/v1/config",
        headers={"Origin": "https://attacker.invalid", "X-CSRF-Token": csrf},
        json={},
    )
    assert wrong_origin.status_code == 403


def test_rejected_url_credential_is_removed_from_access_log_scope(secure_client: TestClient) -> None:
    runtime = secure_client.app.state.runtime
    reached = False

    async def downstream(scope, receive, send):
        nonlocal reached
        reached = True

    middleware = SecurityBoundaryMiddleware(downstream, runtime)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/v1/projects",
        "raw_path": b"/v1/projects",
        "query_string": b"client_secret=must-not-reach-access-log",
        "headers": [(b"host", b"127.0.0.1:8080")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(middleware(scope, receive, send))
    assert reached is False
    assert scope["query_string"] == b"redacted=1"
    assert all(b"must-not-reach-access-log" not in repr(message).encode() for message in messages)
    assert messages[0]["status"] == 400


def test_component_status_probes_desired_off_profiles_and_reports_absence(monkeypatch) -> None:
    calls: list[str] = []

    class ProbeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {
                "ok": True,
                "engine": "kodesec-worker",
                "database": "ok",
                "status": "pass",
            }

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            assert timeout == 1.0
            assert follow_redirects is False
            assert trust_env is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            calls.append(str(url))
            if str(url) not in {
                "http://127.0.0.1:8080/healthz",
                "http://scanner:8091/healthz",
            }:
                request = httpx.Request("GET", str(url))
                raise httpx.ConnectError("not observed", request=request)
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    values = {
        "component_monitoring_enabled": False,
        "component_git_proxy_enabled": False,
        "component_db_admin_enabled": False,
    }
    rows = _component_rows(values, Settings(_env_file=None, KODESEC_CONTROL_ORIGINS=ORIGIN))
    assert set(calls) == {
        "http://127.0.0.1:8080/healthz",
        "http://scanner:8091/healthz",
        "http://grafana:3000/api/health",
        "http://prometheus:9090/-/ready",
        "http://gitea:3000/api/healthz",
        "http://adminer:8080",
    }
    core = [row for row in rows if row["profile"] == "core"]
    assert all(row["required"] is True for row in core)
    assert all(row["observed_state"] == "running" for row in core)
    assert all(row["reachable"] is True and row["healthy"] is True for row in core)
    assert all(row["reason_code"] == "health_response_accepted" for row in core)
    optional = [row for row in rows if row["profile"] != "core"]
    assert {row["id"] for row in optional} == {
        "grafana",
        "prometheus",
        "gitea",
        "adminer",
    }
    assert all(row["desired_state"] == "disabled" for row in optional)
    assert all(row["observed_state"] == "not_observed" for row in optional)
    assert all(row["reason_code"] == "not_observed" for row in optional)
    assert all(
        row["message"] == "Not observed; optional component is desired off."
        for row in optional
    )
    assert all(row["required"] is False for row in optional)


def test_component_status_reports_reachable_desired_off_service_as_drift(
    monkeypatch,
) -> None:
    class ProbeResponse:
        status_code = 200
        content = b"{}"

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    row = _http_component(
        "adminer",
        "http://127.0.0.1:8082",
        False,
        "db-admin",
        "make apply-components COMPONENTS=core",
        "http://adminer:8080",
        (200,),
    )
    assert row["desired_state"] == "disabled"
    assert row["observed_state"] == "running_undesired"
    assert row["reachable"] is True
    assert row["healthy"] is True
    assert row["reason_code"] == "running_undesired"
    assert "stop it without deleting data" in row["message"]


@pytest.mark.parametrize(
    ("monitoring", "git_proxy", "db_admin", "expected"),
    [
        (False, False, False, "core"),
        (True, False, False, "monitoring"),
        (False, True, False, "git-proxy"),
        (False, False, True, "db-admin"),
        (True, True, False, "monitoring-git-proxy"),
        (True, False, True, "monitoring-db-admin"),
        (False, True, True, "git-proxy-db-admin"),
        (True, True, True, "all"),
    ],
)
def test_component_apply_command_is_one_of_eight_fixed_values(
    monitoring: bool,
    git_proxy: bool,
    db_admin: bool,
    expected: str,
) -> None:
    command = _component_apply_command(
        {
            "component_monitoring_enabled": monitoring,
            "component_git_proxy_enabled": git_proxy,
            "component_db_admin_enabled": db_admin,
        }
    )
    assert command == f"make apply-components COMPONENTS={expected}"


def test_component_status_uses_semantic_per_component_health_endpoints(
    monkeypatch,
) -> None:
    calls: list[str] = []

    class ProbeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {
                "ok": True,
                "engine": "kodesec-worker",
                "database": "ok",
                "status": "pass",
            }

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            assert timeout == 1.0
            assert follow_redirects is False
            assert trust_env is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            calls.append(str(url))
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    rows = _component_rows(
        {
            "component_monitoring_enabled": True,
            "component_git_proxy_enabled": True,
            "component_db_admin_enabled": True,
        },
        Settings(_env_file=None, KODESEC_CONTROL_ORIGINS=ORIGIN),
    )
    assert set(calls) == {
        "http://127.0.0.1:8080/healthz",
        "http://scanner:8091/healthz",
        "http://grafana:3000/api/health",
        "http://prometheus:9090/-/ready",
        "http://gitea:3000/api/healthz",
        "http://adminer:8080",
    }
    assert all(row["observed_state"] == "running" for row in rows)
    assert all(row["reachable"] is True and row["healthy"] is True for row in rows)


@pytest.mark.parametrize("status_code", [201, 204, 302, 401, 403, 404, 499, 500])
def test_component_status_rejects_every_unaccepted_health_response(
    monkeypatch,
    status_code: int,
) -> None:
    class ProbeResponse:
        def __init__(self, response_status: int) -> None:
            self.status_code = response_status

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            assert timeout == 1.0
            assert follow_redirects is False
            assert trust_env is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            assert url == "http://service/healthz"
            return ProbeResponse(status_code)

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    row = _http_component(
        "service",
        "http://127.0.0.1:9999",
        True,
        "monitoring",
        "make up-monitoring",
        "http://service/healthz",
        (200,),
    )
    assert row == {
        "id": "service",
        "required": False,
        "desired_enabled": True,
        "desired_state": "enabled",
        "observed_state": "unhealthy",
        "reachable": True,
        "healthy": False,
        "url": "http://127.0.0.1:9999",
        "profile": "monitoring",
        "apply_command": "make up-monitoring",
        "reason_code": "health_response_rejected",
        "message": "Running, but its health endpoint did not return the accepted healthy response.",
    }


@pytest.mark.parametrize("health_body", [{}, {"ok": False}, {"ok": "true"}, ["ok"]])
def test_component_status_rejects_healthy_status_with_invalid_kodesec_body(
    monkeypatch,
    health_body,
) -> None:
    class ProbeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return health_body

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    row = _http_component(
        "control",
        ORIGIN,
        True,
        "core",
        "make up",
        f"{ORIGIN}/healthz",
        (200,),
        "control",
    )
    assert row["reachable"] is True
    assert row["healthy"] is False
    assert row["observed_state"] == "unhealthy"
    assert row["reason_code"] == "health_response_rejected"


@pytest.mark.parametrize(
    ("health_contract", "health_body"),
    [
        ("scanner", {"ok": True, "engine": "foreign-engine"}),
        ("grafana", {"database": "starting"}),
        ("gitea", {"status": "fail"}),
    ],
)
def test_component_status_rejects_endpoint_specific_unhealthy_body(
    monkeypatch,
    health_contract: str,
    health_body: dict[str, object],
) -> None:
    class ProbeResponse:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return health_body

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    row = _http_component(
        "service",
        ORIGIN,
        True,
        "monitoring",
        "make up",
        f"{ORIGIN}/healthz",
        (200,),
        health_contract,
    )
    assert row["reachable"] is True
    assert row["healthy"] is False
    assert row["observed_state"] == "unhealthy"


@pytest.mark.parametrize("oversized", [False, True])
def test_component_status_rejects_unparseable_or_oversized_health_body(
    monkeypatch,
    oversized: bool,
) -> None:
    class ProbeResponse:
        status_code = 200
        content = b"x" * (4097 if oversized else 8)

        @staticmethod
        def json():
            if oversized:
                raise AssertionError("oversized health JSON must not be parsed")
            raise ValueError("not JSON")

    class ProbeClient:
        def __init__(self, *, timeout, follow_redirects, trust_env):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            return ProbeResponse()

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    row = _http_component(
        "control",
        ORIGIN,
        True,
        "core",
        "make up",
        f"{ORIGIN}/healthz",
        (200,),
        "control",
    )
    assert row["reachable"] is True
    assert row["healthy"] is False
    assert row["observed_state"] == "unhealthy"
    assert row["reason_code"] == "health_response_rejected"


def test_component_status_distinguishes_not_running_from_unknown(monkeypatch) -> None:
    class ProbeClient:
        error: Exception

        def __init__(self, *, timeout, follow_redirects, trust_env):
            assert timeout == 1.0
            assert follow_redirects is False
            assert trust_env is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url):
            raise self.error

    monkeypatch.setattr("kodesec_api.main.httpx.Client", ProbeClient)
    request = httpx.Request("GET", "http://service/healthz")
    ProbeClient.error = httpx.ConnectError("connection refused", request=request)
    not_running = _http_component(
        "service", "http://127.0.0.1:9999", True, "monitoring", "make up", "http://service/healthz"
    )
    assert not_running["observed_state"] == "not_running"
    assert not_running["reachable"] is False
    assert not_running["reason_code"] == "not_reachable"

    ProbeClient.error = httpx.ReadTimeout("probe timed out", request=request)
    unknown = _http_component(
        "service", "http://127.0.0.1:9999", True, "monitoring", "make up", "http://service/healthz"
    )
    assert unknown["observed_state"] == "unknown"
    assert unknown["reachable"] is False
    assert unknown["reason_code"] == "probe_timeout"


def test_api_reads_worker_advisor_receipts_without_contacting_ollama(secure_client: TestClient, monkeypatch) -> None:
    def unexpected_probe(*args, **kwargs):
        raise AssertionError("the API must not contact the worker-owned advisor")

    assert not hasattr(main_module, "_worker_ollama_available_sync")
    assert not hasattr(main_module, "_triage_finding_sync")
    monkeypatch.setattr("kodesec_api.jobs.advisor.worker_ollama_available_sync", unexpected_probe)
    response = secure_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["ai"] == {
        "mode": "auto",
        "available": False,
        "base_url": "http://127.0.0.1:11434",
        "model": "qwen3:8b",
        "thinking": False,
        "models": [],
        "reason": "work_processing_unavailable",
    }
    _bootstrap(secure_client)
    config = secure_client.get("/v1/config")
    assert config.status_code == 200
    assert config.json()["ollama_available"] is False
    assert config.json()["ollama_reason"] == "work_processing_unavailable"


def test_validation_never_reflects_credentials_and_api_state_is_not_cached(secure_client: TestClient) -> None:
    submitted = "not-a-real-bootstrap-value-" * 12
    invalid = secure_client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": submitted},
    )
    assert invalid.status_code == 422
    assert invalid.headers["cache-control"] == "no-store"
    assert submitted not in invalid.text
    assert "input" not in invalid.json()["detail"][0]

    _bootstrap(secure_client)
    projects = secure_client.get("/v1/projects")
    assert projects.status_code == 200
    assert projects.headers["cache-control"] == "no-store"


def test_static_asset_ranges_with_updated_server(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (tmp_path / "index.html").write_text("<main>workbench</main>", encoding="utf-8")
    content = bytes(range(256)) * 4
    (assets / "fixture.bin").write_bytes(content)
    app = FastAPI()
    mount_static_application(app, tmp_path)
    with TestClient(app) as client:
        # Reverse-ordered overlapping ranges exercise the corrected merge path.
        ranges = ",".join(f"{offset}-{offset + 2}" for offset in range(511, -1, -1))
        response = client.get("/assets/fixture.bin", headers={"Range": f"bytes={ranges}"})
        assert response.status_code == 206
        assert response.headers["content-range"] == "bytes 0-513/1024"
        assert response.content == content[:514]
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"

        invalid = client.get("/assets/fixture.bin", headers={"Range": "bytes=--" * 1000})
        assert invalid.status_code == 400
        outside = client.get("/assets/fixture.bin", headers={"Range": "bytes=2048-4096"})
        assert outside.status_code == 416
        assert outside.headers["content-range"] == "bytes */1024"
        assert client.get("/assets/fixture.bin").content == content


def test_static_spa_delivery_and_api_non_shadowing(secure_client: TestClient) -> None:
    root = secure_client.get("/")
    assert root.status_code == 200
    assert "secure workbench" in root.text
    assert root.headers["cache-control"] == "no-cache, no-store, must-revalidate"
    assert root.headers["content-security-policy"].startswith("default-src 'self'")

    deep_link = secure_client.get("/findings/S3-F004")
    assert deep_link.status_code == 200
    assert "secure workbench" in deep_link.text

    asset = secure_client.get("/assets/app-deadbeef.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert secure_client.head("/assets/app-deadbeef.js").status_code == 200
    ranged = secure_client.get("/assets/app-deadbeef.js", headers={"Range": "bytes=0-5"})
    assert ranged.status_code == 206
    assert ranged.headers["content-range"].startswith("bytes 0-5/")
    assert secure_client.get("/assets/escape.js").status_code == 404
    assert secure_client.get("/assets/%2e%2e/index.html").status_code == 404
    assert secure_client.get("/%2e%2e/openapi.json").status_code == 404
    assert secure_client.get("/%ff").status_code == 404
    assert secure_client.get("/%25ff").status_code == 404
    assert secure_client.get("/assets/missing").status_code == 404
    assert secure_client.get("/missing.js").status_code == 404
    assert secure_client.get("/v1/not-a-route").status_code == 401

    _bootstrap(secure_client)
    assert secure_client.get("/v1/not-a-route").status_code == 404


def test_scan_local_finding_ids_survive_deletion(secure_client: TestClient) -> None:
    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        project = Project(
            name="stable-identifiers",
            repo_path="/workspaces/stable-identifiers",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed")
        db.add(scan)
        db.flush()
        first = Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="first.rule",
            severity="critical",
            file_path="src/first.py",
            start_line=1,
            end_line=1,
            message="first",
            fingerprint="stable-first",
        )
        second = Finding(
            scan_id=scan.id,
            scan_finding_number=2,
            scanner="fixture",
            rule_id="second.rule",
            severity="high",
            file_path="src/second.py",
            start_line=2,
            end_line=2,
            message="second",
            fingerprint="stable-second",
        )
        db.add_all([first, second])
        db.flush()
        job = Job(
            kind="advisor",
            title="Advisor triage",
            status="completed",
            scan_id=scan.id,
            finding_id=second.id,
        )
        db.add(job)
        db.commit()
        scan_id = scan.id
        first_id = first.id
        second_id = second.id
        job_id = job.id

    csrf = _bootstrap(secure_client)
    before = secure_client.get(f"/v1/scans/{scan_id}/findings")
    assert before.status_code == 200
    assert [item["display_id"] for item in before.json()["items"]] == [
        f"S{scan_id}-F001",
        f"S{scan_id}-F002",
    ]

    deleted = secure_client.delete(
        f"/v1/findings/{first_id}?expected_revision=1",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 200
    remaining = secure_client.get(f"/v1/findings/{second_id}")
    assert remaining.status_code == 200
    assert remaining.json()["scan_finding_number"] == 2
    assert remaining.json()["display_id"] == f"S{scan_id}-F002"
    jobs = secure_client.get("/v1/jobs").json()
    persisted_job = next(item for item in jobs if item["id"] == job_id)
    assert persisted_job["finding_display_id"] == f"S{scan_id}-F002"


def test_scan_command_is_atomic_idempotent_and_redacted(
    secure_client: TestClient, monkeypatch
) -> None:
    monkeypatch.setattr(
        main_module,
        "_scanner_runtime_snapshot",
        lambda _settings: main_module._ScannerRuntimeSnapshot(
            tools=_ready_scanner_runtime_inventory(),
            active_generation=None,
        ),
    )
    csrf = _bootstrap(secure_client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    project = secure_client.post(
        "/v1/projects",
        headers=headers,
        json={"name": "durable-command", "repo_path": "/workspaces/durable-command"},
    ).json()
    command = {
        "project_id": project["id"],
        "mode": "incremental_diff",
        "base_ref": "release/phase-1",
        "head_ref": "main",
        "use_ai": False,
    }
    assert secure_client.post("/v1/scans", headers=headers, json=command).status_code == 422
    rejected_secret = secure_client.post(
        "/v1/scans",
        headers={**headers, "Idempotency-Key": "scan-command-secret"},
        json={**command, "base_ref": "password=fixture-credential"},
    )
    assert rejected_secret.status_code == 422
    keyed = {**headers, "Idempotency-Key": "scan-command-0001"}
    created = secure_client.post("/v1/scans", headers=keyed, json=command)
    assert created.status_code == 202, created.text
    replay = secure_client.post("/v1/scans", headers=keyed, json=command)
    assert replay.status_code == 202
    assert replay.json()["id"] == created.json()["id"]
    assert replay.json()["job_id"] == created.json()["job_id"]
    conflict = secure_client.post(
        "/v1/scans",
        headers=keyed,
        json={**command, "head_ref": "different"},
    )
    assert conflict.status_code == 409

    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        jobs = list(db.query(Job).filter(Job.scan_id == created.json()["id"]))
        assert len(jobs) == 1
        persisted = jobs[0]
        assert len(persisted.payload["request_digest"]) == 64
        assert persisted.idempotency_key != "scan-command-0001"
        assert persisted.idempotency_key.startswith("h1$")
        assert len(persisted.idempotency_key) == 67
        assert "fixture-credential" not in str(persisted.payload)
        scan = db.get(Scan, persisted.scan_id)
        assert scan and scan.base_ref == "release/phase-1"
        assert db.query(Scan).count() == 1


def test_active_jobs_guard_deletion_and_support_cancel_retry(secure_client: TestClient) -> None:
    csrf = _bootstrap(secure_client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    runtime = secure_client.app.state.runtime
    with runtime.session_factory() as db:
        project = Project(name="guarded", repo_path="/workspaces/guarded", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="pending", gate_reasons=[], scanner_summary={})
        db.add(scan)
        db.flush()
        job = Job(
            kind="scan",
            title="Guarded scan",
            status="queued",
            stage="queued",
            payload={"v": 1, "operation": "scan", "use_ai": False},
            checkpoint={},
            priority=0,
            attempt=0,
            max_attempts=3,
            revision=1,
            scan_id=scan.id,
        )
        db.add(job)
        db.commit()
        project_id, scan_id, job_id = project.id, scan.id, job.id

    assert secure_client.delete(f"/v1/scans/{scan_id}", headers=headers).status_code == 409
    assert secure_client.delete(f"/v1/projects/{project_id}", headers=headers).status_code == 409
    cancelled = secure_client.post(f"/v1/jobs/{job_id}/cancel", headers=headers, json={})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelling"
    repeated = secure_client.post(f"/v1/jobs/{job_id}/cancel", headers=headers, json={})
    assert repeated.status_code == 200
    assert repeated.json()["revision"] == cancelled.json()["revision"]

    with runtime.session_factory() as db:
        persisted = db.get(Job, job_id)
        assert persisted
        persisted.status = "failed"
        persisted.stage = "failed"
        persisted.completed_at = persisted.updated_at
        persisted.cancel_requested_at = None
        persisted.lease_owner = None
        persisted.lease_expires_at = None
        persisted.revision += 1
        db.commit()
        revision = persisted.revision
    retried = secure_client.post(
        f"/v1/jobs/{job_id}/retry",
        headers=headers,
        json={"expected_revision": revision},
    )
    assert retried.status_code == 200
    assert retried.json()["status"] == "queued"
    assert secure_client.post(
        f"/v1/jobs/{job_id}/retry",
        headers=headers,
        json={"expected_revision": revision},
    ).status_code == 409


def test_advisor_admission_requires_terminal_scan_and_active_findings(
    secure_client: TestClient,
    seed_ready_local_advisor,
) -> None:
    csrf = _bootstrap(secure_client)
    headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": csrf,
        "Idempotency-Key": "advisor-admission-fixture",
    }
    runtime = secure_client.app.state.runtime
    provider_pin = seed_ready_local_advisor(runtime)
    with runtime.session_factory() as db:
        project = Project(name="advisor-admission", repo_path="/workspaces/advisor", default_branch="main")
        db.add(project)
        db.flush()
        running_scan = Scan(project_id=project.id, mode="full", status="running", gate_reasons=[], scanner_summary={})
        completed_scan = Scan(project_id=project.id, mode="full", status="completed", gate_reasons=[], scanner_summary={})
        empty_scan = Scan(project_id=project.id, mode="full", status="completed", gate_reasons=[], scanner_summary={})
        db.add_all([running_scan, completed_scan, empty_scan])
        db.flush()
        running_finding = Finding(
            scan_id=running_scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="running.rule",
            severity="high",
            file_path="src/running.py",
            start_line=1,
            end_line=1,
            message="not terminal",
            fingerprint="advisor-running",
            suppressed=False,
        )
        active = Finding(
            scan_id=completed_scan.id,
            scan_finding_number=1,
            scanner="fixture",
            rule_id="active.rule",
            severity="high",
            file_path="src/active.py",
            start_line=1,
            end_line=1,
            message="active",
            fingerprint="advisor-active",
            suppressed=False,
        )
        suppressed = Finding(
            scan_id=completed_scan.id,
            scan_finding_number=2,
            scanner="fixture",
            rule_id="suppressed.rule",
            severity="medium",
            file_path="src/suppressed.py",
            start_line=2,
            end_line=2,
            message="suppressed",
            fingerprint="advisor-suppressed",
            suppressed=True,
        )
        db.add_all([running_finding, active, suppressed])
        db.commit()
        running_scan_id = running_scan.id
        completed_scan_id = completed_scan.id
        empty_scan_id = empty_scan.id
        running_finding_id = running_finding.id
        active_id = active.id
        suppressed_id = suppressed.id

    running = secure_client.post(
        f"/v1/scans/{running_scan_id}/triage",
        headers=headers,
        json={"advisor_provider_pin": provider_pin},
    )
    assert running.status_code == 409
    assert running.json()["detail"] == "advisor triage requires a terminal scan with persisted findings"

    running_single = secure_client.post(
        f"/v1/findings/{running_finding_id}/triage",
        headers={**headers, "Idempotency-Key": "advisor-running-single-fixture"},
        json={
            "expected_revision": 1,
            "advisor_provider_pin": provider_pin,
        },
    )
    assert running_single.status_code == 409
    assert running_single.json()["detail"]["code"] == "advisor_scan_not_terminal"

    running_bulk = secure_client.post(
        "/v1/findings/bulk",
        headers={**headers, "Idempotency-Key": "advisor-running-bulk-fixture"},
        json={
            "action": "triage",
            "finding_ids": [running_finding_id],
            "expected_revisions": {str(running_finding_id): 1},
            "advisor_provider_pin": provider_pin,
        },
    )
    assert running_bulk.status_code == 409
    assert running_bulk.json()["detail"] == "advisor triage requires a terminal scan with persisted findings"

    empty = secure_client.post(
        f"/v1/scans/{empty_scan_id}/triage",
        headers={**headers, "Idempotency-Key": "advisor-empty-fixture"},
        json={"advisor_provider_pin": provider_pin},
    )
    assert empty.status_code == 409
    assert empty.json()["detail"] == "advisor triage requires at least one eligible active finding"

    suppressed_response = secure_client.post(
        f"/v1/findings/{suppressed_id}/triage",
        headers={**headers, "Idempotency-Key": "advisor-suppressed-fixture"},
        json={
            "expected_revision": 1,
            "advisor_provider_pin": provider_pin,
        },
    )
    assert suppressed_response.status_code == 409
    assert suppressed_response.json()["detail"]["code"] == "finding_changed"

    mixed = secure_client.post(
        "/v1/findings/bulk",
        headers={**headers, "Idempotency-Key": "advisor-mixed-fixture"},
        json={
            "action": "triage",
            "finding_ids": [active_id, suppressed_id],
            "expected_revisions": {str(active_id): 1, str(suppressed_id): 1},
            "advisor_provider_pin": provider_pin,
        },
    )
    assert mixed.status_code == 409
    assert mixed.json()["detail"] == "bulk advisor triage accepts active findings only"

    missing_bulk_fence = secure_client.post(
        "/v1/findings/bulk",
        headers={**headers, "Idempotency-Key": "advisor-missing-bulk-fence-fixture"},
        json={
            "action": "triage",
            "finding_ids": [active_id],
            "advisor_provider_pin": provider_pin,
        },
    )
    assert missing_bulk_fence.status_code == 422
    assert missing_bulk_fence.json()["detail"] == (
        "expected_revisions must contain exactly one revision for every selected finding"
    )

    stale_bulk = secure_client.post(
        "/v1/findings/bulk",
        headers={**headers, "Idempotency-Key": "advisor-stale-bulk-fixture"},
        json={
            "action": "triage",
            "finding_ids": [active_id],
            "expected_revisions": {str(active_id): 2},
            "advisor_provider_pin": provider_pin,
        },
    )
    assert stale_bulk.status_code == 409
    assert stale_bulk.json()["detail"] == {
        "code": "revision_conflict",
        "message": "one or more findings changed after they were loaded; refresh before retrying",
        "revisions": {str(active_id): 1},
    }
    with runtime.session_factory() as db:
        assert db.query(Job).filter(Job.kind == "advisor").count() == 0

    stale = secure_client.post(
        f"/v1/findings/{active_id}/triage",
        headers={**headers, "Idempotency-Key": "advisor-stale-fixture"},
        json={
            "expected_revision": 2,
            "advisor_provider_pin": provider_pin,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "revision_conflict"
    assert stale.json()["detail"]["context"] == {
        "finding_id": active_id,
        "expected_revision": 2,
        "current_revision": 1,
    }

    accepted = secure_client.post(
        f"/v1/findings/{active_id}/triage",
        headers={**headers, "Idempotency-Key": "advisor-active-fixture"},
        json={
            "expected_revision": 1,
            "advisor_provider_pin": provider_pin,
        },
    )
    assert accepted.status_code == 202
    assert accepted.json()["kind"] == "advisor"
    assert accepted.json()["finding_id"] == active_id
    with runtime.session_factory() as db:
        advisor_jobs = list(db.query(Job).filter(Job.kind == "advisor"))
        assert len(advisor_jobs) == 1
        assert advisor_jobs[0].scan_id == completed_scan_id
        assert advisor_jobs[0].payload["expected_revisions"] == {
            str(active_id): 1
        }


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1:11434",
        "http://example.com:11434",
        "http://127.0.0.1:80",
        "http://user@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
        "file:///tmp/ollama",
    ],
)
def test_remote_or_ambiguous_ollama_urls_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_local_ollama_url(value)


@pytest.mark.parametrize(
    "value",
    ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434", "http://host.docker.internal:11434"],
)
def test_exact_same_device_ollama_urls_are_accepted(value: str) -> None:
    assert normalize_local_ollama_url(value) == value


def test_exact_operator_declared_ollama_host_is_opt_in() -> None:
    relay_url = "http://192.0.2.205:11434"
    with pytest.raises(ValueError):
        normalize_local_ollama_url(relay_url)

    declared = parse_declared_ollama_hosts("192.0.2.205")
    assert normalize_local_ollama_url(relay_url, declared) == relay_url
    with pytest.raises(ValueError):
        normalize_local_ollama_url("http://192.0.2.206:11434", declared)


@pytest.mark.parametrize(
    "value",
    ["192.0.2.0/24", "*.example.test", "http://192.0.2.205", "relay:11434", "relay."],
)
def test_declared_ollama_host_rejects_ambiguous_or_broad_entries(value: str) -> None:
    with pytest.raises(ValueError):
        parse_declared_ollama_hosts(value)


def test_security_settings_accept_exact_declared_ollama_relay() -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        OLLAMA_BASE_URL="http://192.0.2.205:11434",
        KODESEC_OLLAMA_ALLOWED_HOSTS="192.0.2.205",
    )
    settings.validate_security_material()


def test_security_settings_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KODESEC_ALLOWED_ROOTS", raising=False)
    weak = Settings(_env_file=None, DATABASE_URL="sqlite+pysqlite://", KODESEC_CONTROL_ORIGINS=ORIGIN)
    with pytest.raises(RuntimeError, match="missing or weak"):
        weak.validate_security_material()

    non_loopback = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS="http://192.0.2.10:8080",
    )
    with pytest.raises(RuntimeError, match="not an exact loopback"):
        non_loopback.validate_security_material()

    multiple_origins = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=f"{ORIGIN},http://localhost:8080",
    )
    with pytest.raises(RuntimeError, match="exactly one"):
        multiple_origins.validate_security_material()

    broad_source = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/Users",
    )
    with pytest.raises(RuntimeError, match="too broad"):
        broad_source.validate_security_material()

    snapshot_inside_source = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=INSTALLATION_SECRET,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_SOURCE_SNAPSHOT_DIR="/workspaces/source-snapshots",
    )
    with pytest.raises(RuntimeError, match="separate absolute dedicated"):
        snapshot_inside_source.validate_security_material()

    multiple_sources = broad_source.model_copy(update={"allowed_roots": "/workspaces/demo,/other/日本語 space"})
    multiple_sources.validate_security_material()
    for roots in ["/workspaces,/workspaces", "/workspaces,", "/workspaces,/other/../escape", ",".join(f"/repo/{i}" for i in range(33))]:
        with pytest.raises(RuntimeError, match="source roots"):
            multiple_sources.model_copy(update={"allowed_roots": roots}).validate_security_material()
    with pytest.raises(RuntimeError, match="separate absolute dedicated"):
        multiple_sources.model_copy(update={"allowed_roots": "/workspaces,/data/source-snapshots/child"}).validate_security_material()

    with pytest.raises(RuntimeError, match="DATABASE_URL is required"):
        Settings(_env_file=None).validate_database_configuration()
    with pytest.raises(RuntimeError, match="predictable development credential"):
        Settings(
            _env_file=None,
            DATABASE_URL="postgresql+psycopg2://kodesec:kodesec@127.0.0.1:5432/kodesec",
        ).validate_database_configuration()


def _project_gate_fixture(client: TestClient):
    runtime = client.app.state.runtime
    projects = []
    with runtime.session_factory() as db:
        for name in ('policy-target', 'policy-neighbor'):
            project = Project(name=name, repo_path=f'/workspaces/{name}', default_branch='main')
            db.add(project)
            db.flush()
            db.add(GatePolicy(project_id=project.id, active=True, max_critical=0, max_high=-1, block_secrets=True))
            scan = Scan(project_id=project.id, mode='full', status='completed', gate_decision='pass')
            db.add(scan)
            db.flush()
            db.add(Finding(scan_id=scan.id, scan_finding_number=1, scanner='fixture', rule_id='project.gate.high',
                           severity='high', file_path='app.py', message='Project-specific gate fixture', fingerprint=name))
            projects.append((project.id, scan.id))
        db.commit()
    return projects


def test_project_gate_save_is_scoped_and_rejects_stale_policy(secure_client: TestClient):
    target, neighbor = _project_gate_fixture(secure_client)
    headers = {'Origin': ORIGIN, 'X-CSRF-Token': _bootstrap(secure_client)}
    before = secure_client.get(f'/v1/gate-policies/{target[0]}').json()
    expected = {key: value for key, value in before.items() if key != 'project_id'}
    adjacent = secure_client.get(f'/v1/scans/{neighbor[1]}').json()
    original = secure_client.get(f'/v1/scans/{target[1]}').json()
    config = secure_client.get('/v1/config').json()
    payload = {**expected, 'max_high': 0, 'expected_policy': expected}
    saved = secure_client.put(f'/v1/gate-policies/{target[0]}', headers=headers, json=payload)
    assert saved.status_code == 200, saved.text
    scan = secure_client.get(f'/v1/scans/{target[1]}').json()
    assert scan['gate_decision'] == 'fail'
    assert scan['revision'] == original['revision'] + 1
    assert scan['findings_revision'] == original['findings_revision']
    assert secure_client.get(f'/v1/scans/{neighbor[1]}').json() == adjacent
    assert secure_client.get('/v1/config').json() == config
    stale = secure_client.put(f'/v1/gate-policies/{target[0]}', headers=headers, json={**payload, 'max_high': 2})
    assert stale.status_code == 409
    assert secure_client.get(f'/v1/scans/{target[1]}').json() == scan
    assert secure_client.get(f'/v1/gate-policies/{target[0]}').json() == saved.json()
    for invalid in ({**expected, 'max_high': 0}, {**payload, 'project_id': neighbor[0]}):
        assert secure_client.put(f'/v1/gate-policies/{target[0]}', headers=headers, json=invalid).status_code == 422


def test_concurrent_project_gate_saves_cannot_overwrite_the_same_observed_policy(secure_client: TestClient):
    target, _ = _project_gate_fixture(secure_client)
    headers = {'Origin': ORIGIN, 'X-CSRF-Token': _bootstrap(secure_client)}
    expected = {'active': True, 'max_critical': 0, 'max_high': -1, 'block_secrets': True}
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda high: secure_client.put(f'/v1/gate-policies/{target[0]}',
            headers=headers, json={**expected, 'max_high': high, 'expected_policy': expected}), [0, 1]))
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response for response in responses if response.status_code == 200)
    assert secure_client.get(f'/v1/gate-policies/{target[0]}').json() == winner.json()
    assert secure_client.get(f'/v1/scans/{target[1]}').json()['revision'] == 2


def test_project_gate_and_scan_recalculation_roll_back_together(secure_client: TestClient, monkeypatch):
    target, _ = _project_gate_fixture(secure_client)
    headers = {'Origin': ORIGIN, 'X-CSRF-Token': _bootstrap(secure_client)}
    before = secure_client.get(f'/v1/gate-policies/{target[0]}').json()
    scan = secure_client.get(f'/v1/scans/{target[1]}').json()
    expected = {key: value for key, value in before.items() if key != 'project_id'}
    def fail(_db, _project_id):
        raise RuntimeError('project gate recalculation fault')
    monkeypatch.setattr(main_module, '_recalculate_project_scan_gates', fail)
    with pytest.raises(RuntimeError, match='project gate recalculation fault'):
        secure_client.put(f'/v1/gate-policies/{target[0]}', headers=headers,
                          json={**expected, 'max_high': 0, 'expected_policy': expected})
    assert secure_client.get(f'/v1/gate-policies/{target[0]}').json() == before
    assert secure_client.get(f'/v1/scans/{target[1]}').json() == scan
