from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import Request, Response
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import StaticPool

from kodesec_api.app import create_app
from kodesec_api.auth import (
    BROWSER_SESSION_PREFIX,
    IDE_BROWSER_INVITATION_PREFIX,
    IDE_BROWSER_MEMBERSHIP_PREFIX,
    IDE_BROWSER_MEMBERSHIP_WAIT_SECONDS,
    INSTALLATION_SECRET_BINDING_KEY,
    SESSION_COOKIE,
    AuthContext,
    InstallationSecretBindingError,
    _prune_browser_sessions,
    wait_for_ide_browser_membership,
)
from kodesec_api.db import Base, Runtime, SchemaVerification
from kodesec_api.events import EventWakeBroker
from kodesec_api.models import RuntimeConfig
from kodesec_api.settings import Settings


ORIGIN = "http://127.0.0.1:18088"
INSTALLATION_SECRET = "installation-secret-" * 3
BOOTSTRAP_TOKEN = "bootstrap-token-" * 4


def _settings(tmp_path: Path, *, installation_secret: str = INSTALLATION_SECRET) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_INSTALLATION_SECRET=installation_secret,
        KODESEC_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_SOURCE_SNAPSHOT_DIR=str(tmp_path / "source-snapshots"),
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )


def _engine():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


@contextmanager
def _auth_only_startup():
    # Exercise the real app lifespan and `_startup` secret-binding call while
    # replacing only PostgreSQL schema/publication work irrelevant to auth.
    with (
        patch(
            "kodesec_api.main.init_db",
            return_value=SchemaVerification(
                identity="auth-test",
                fingerprint="a" * 64,
                initialized_at=datetime(2026, 8, 28, tzinfo=timezone.utc),
            ),
        ),
        patch("kodesec_api.main.enforce_runtime_publication_boundaries"),
    ):
        yield


def _bootstrap(client: TestClient) -> tuple[str, str]:
    response = client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": BOOTSTRAP_TOKEN},
    )
    assert response.status_code == 200, response.text
    token = client.cookies.get(SESSION_COOKIE)
    assert token is not None
    return token, str(response.json()["csrf_token"])


def _pair_and_activate_ide(
    owner: TestClient,
    csrf: str,
    *,
    slot_character: str,
    name: str,
) -> str:
    paired = owner.post(
        "/v1/auth/ide/enrollments",
        json={
            "client_name": name,
            "client_slot": "ks1_" + slot_character * 43,
            "expected_active_generation": 0,
        },
    )
    assert paired.status_code == 201, paired.text
    approved = owner.post(
        f"/v1/auth/ide/enrollments/{paired.json()['request_id']}/decision",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "decision": "approved",
            "expected_revision": paired.json()["revision"],
            "expected_generation": paired.json()["generation"],
        },
    )
    assert approved.status_code == 200, approved.text
    capability = str(paired.json()["capability"])
    activated = owner.post(
        "/v1/auth/ide/activate",
        headers={"Authorization": f"Bearer {capability}"},
    )
    assert activated.status_code == 200, activated.text
    assert set(activated.json()) == {"client_slot", "generation", "scopes"}
    return capability


def test_same_database_and_secret_recreate_retains_browser_and_ide_authority(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            first_app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(first_app, base_url=ORIGIN) as first:
                browser_token, csrf = _bootstrap(first)
                capability = _pair_and_activate_ide(
                    first,
                    csrf,
                    slot_character="p",
                    name="persistent IDE",
                )
                created = first.post(
                    "/v1/projects",
                    headers={"Authorization": f"Bearer {capability}"},
                    json={"name": "persisted", "repo_path": "/workspaces/persisted"},
                )
                assert created.status_code == 201, created.text

            with engine.connect() as connection:
                rows = connection.execute(
                    select(RuntimeConfig.key, RuntimeConfig.value).where(
                        RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%")
                    )
                ).all()
            assert len(rows) == 1
            session_key, stored_value = rows[0]
            assert session_key.endswith(browser_token.split(".", 1)[0])
            assert browser_token not in stored_value
            assert set(json.loads(stored_value)) == {
                "digest",
                "member_name",
                    "member_kind",
                    "created_at",
                    "last_seen_at",
                }
            with engine.begin() as connection:
                connection.execute(RuntimeConfig.__table__.insert().values(
                    key=f"{BROWSER_SESSION_PREFIX}{'z' * 32}",
                    value=json.dumps({
                        "digest": "not-a-verifier",
                        "member_name": "Corrupt browser member",
                        "member_kind": "browser",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "last_seen_at": datetime.now(timezone.utc).isoformat(),
                    }, separators=(",", ":"), sort_keys=True),
                ))

            second_app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(second_app, base_url=ORIGIN) as second:
                second.cookies.set(SESSION_COOKIE, browser_token)
                session = second.get("/v1/auth/session")
                assert session.status_code == 200, session.text
                assert session.json()["csrf_token"] == csrf
                assert session.json()["expires_in"] == 34_560_000
                assert "max-age=34560000" in session.headers["set-cookie"].lower()
                visible_members = second.get("/v1/auth/browser/sessions")
                assert visible_members.status_code == 200, visible_members.text
                assert len(visible_members.json()) == 1
                assert all(
                    member["member_name"] != "Corrupt browser member"
                    for member in visible_members.json()
                )
                resolved = second.post(
                    "/v1/projects/resolve",
                    headers={"Authorization": f"Bearer {capability}"},
                    json={"repo_path": "/workspaces/persisted"},
                )
                assert resolved.status_code == 200, resolved.text
                replay = second.post(
                    "/v1/auth/bootstrap",
                    headers={"Origin": ORIGIN},
                    json={"bootstrap_token": BOOTSTRAP_TOKEN},
                )
                assert replay.status_code == 409
    finally:
        engine.dispose()


def test_session_renews_stable_csrf_and_remains_active_until_explicit_logout(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    runtime = Runtime.create(settings, engine=engine)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=runtime)
            with TestClient(app, base_url=ORIGIN) as client:
                browser_token, csrf = _bootstrap(client)
                session_id = browser_token.split(".", 1)[0]
                session_key = f"{BROWSER_SESSION_PREFIX}{session_id}"
                stale_activity = datetime.now(timezone.utc) - timedelta(days=800)
                with runtime.session_factory() as db:
                    row = db.get(RuntimeConfig, session_key)
                    record = json.loads(row.value)
                    record["created_at"] = stale_activity.isoformat()
                    record["last_seen_at"] = stale_activity.isoformat()
                    row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
                    db.commit()

                renewed = client.get("/v1/auth/session")
                assert renewed.status_code == 200, renewed.text
                assert renewed.json() == {
                    "authenticated": True,
                    "csrf_token": csrf,
                    "expires_in": 34_560_000,
                }
                assert client.cookies.get(SESSION_COOKIE) == browser_token
                with runtime.session_factory() as db:
                    renewed_record = json.loads(db.get(RuntimeConfig, session_key).value)
                assert datetime.fromisoformat(renewed_record["last_seen_at"]) > stale_activity

                logged_out = client.post(
                    "/v1/auth/logout",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                )
                assert logged_out.status_code == 200, logged_out.text
                assert "max-age=0" in logged_out.headers["set-cookie"].lower()
                with runtime.session_factory() as db:
                    assert db.get(RuntimeConfig, session_key) is None
                assert client.get("/v1/auth/session").status_code == 401
    finally:
        engine.dispose()


def test_browser_membership_outlives_cookie_max_age_until_exact_revoke(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    runtime = Runtime.create(settings, engine=engine)
    stale_activity = datetime.now(timezone.utc) - timedelta(days=800)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=runtime)
            with (
                TestClient(app, base_url=ORIGIN) as owner,
                TestClient(app, base_url=ORIGIN) as additional_browser,
            ):
                owner_token, csrf = _bootstrap(owner)
                pairing = owner.post(
                    "/v1/auth/browser/pairing-token",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                )
                assert pairing.status_code == 200, pairing.text
                added = additional_browser.post(
                    "/v1/auth/bootstrap",
                    headers={"Origin": ORIGIN},
                    json={"bootstrap_token": pairing.json()["bootstrap_token"]},
                )
                assert added.status_code == 200, added.text
                additional_token = additional_browser.cookies.get(SESSION_COOKIE)
                assert additional_token is not None
                additional_session_id = additional_token.split(".", 1)[0]

                with runtime.session_factory() as db:
                    row = db.get(
                        RuntimeConfig,
                        f"{BROWSER_SESSION_PREFIX}{additional_session_id}",
                    )
                    record = json.loads(row.value)
                    record["created_at"] = stale_activity.isoformat()
                    record["last_seen_at"] = stale_activity.isoformat()
                    row.value = json.dumps(record, separators=(",", ":"), sort_keys=True)
                    _prune_browser_sessions(db, datetime.now(timezone.utc))
                    db.commit()

                members = owner.get("/v1/auth/browser/sessions")
                assert members.status_code == 200, members.text
                assert len(members.json()) == 2
                additional_member = next(
                    member for member in members.json()
                    if member["id"] == f"kbm1_{additional_session_id}"
                )
                assert (
                    datetime.fromisoformat(additional_member["last_seen_at"])
                    == stale_activity
                )

                renewed = additional_browser.get("/v1/auth/session")
                assert renewed.status_code == 200, renewed.text
                assert renewed.json()["expires_in"] == 34_560_000
                assert "max-age=34560000" in renewed.headers["set-cookie"].lower()

                revoked = owner.request(
                    "DELETE",
                    f"/v1/auth/browser/sessions/{additional_member['id']}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={"expected_created_at": additional_member["created_at"]},
                )
                assert revoked.status_code == 200, revoked.text
                assert revoked.json() == {"revoked": True, "current": False}
                assert additional_browser.get("/v1/auth/session").status_code == 401
                assert owner.get("/v1/auth/session").status_code == 200
                retained = owner.get("/v1/auth/browser/sessions")
                assert retained.status_code == 200, retained.text
                assert [member["id"] for member in retained.json()] == [
                    f"kbm1_{owner_token.split('.', 1)[0]}"
                ]
    finally:
        engine.dispose()


def test_two_ide_profiles_and_two_browsers_reuse_restart_and_revoke_independently(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)

    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as owner:
                owner_token, csrf = _bootstrap(owner)
                ide_one = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="a",
                    name="Primary VS Code",
                )
                ide_two = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="b",
                    name="Secondary VS Code",
                )

                invitations = []
                for capability in (ide_one, ide_two):
                    issued = owner.post(
                        "/v1/auth/ide/browser-invitations",
                        headers={"Authorization": f"Bearer {capability}"},
                        json={"purpose": "integrated_dashboard"},
                    )
                    assert issued.status_code == 200, issued.text
                    invitation = issued.json()["bootstrap_token"]
                    assert invitation.startswith("kbi1.")
                    invitations.append(invitation)

                browser_one = TestClient(app, base_url=ORIGIN)
                browser_two = TestClient(app, base_url=ORIGIN)
                try:
                    first = browser_one.post(
                        "/v1/auth/bootstrap",
                        headers={"Origin": ORIGIN},
                        json={"bootstrap_token": invitations[0]},
                    )
                    second = browser_two.post(
                        "/v1/auth/bootstrap",
                        headers={"Origin": ORIGIN},
                        json={"bootstrap_token": invitations[1]},
                    )
                    assert first.status_code == 200, first.text
                    assert second.status_code == 200, second.text
                    browser_one_token = browser_one.cookies.get(SESSION_COOKIE)
                    browser_two_token = browser_two.cookies.get(SESSION_COOKIE)
                    assert browser_one_token and browser_two_token

                    members = owner.get("/v1/auth/browser/sessions")
                    assert members.status_code == 200, members.text
                    rows = members.json()
                    assert len(rows) == 3
                    assert {row["member_name"].rsplit(" · ", 1)[0] for row in rows} == {
                        "Installation owner browser",
                        "Primary VS Code integrated dashboard",
                        "Secondary VS Code integrated dashboard",
                    }
                    assert len({row["member_name"] for row in rows}) == 3

                    extra_issue = owner.post(
                        "/v1/auth/ide/browser-invitations",
                        headers={"Authorization": f"Bearer {ide_one}"},
                        json={"purpose": "extra_browser"},
                    )
                    assert extra_issue.status_code == 200, extra_issue.text
                    extra_invitation = extra_issue.json()
                    already_paired = browser_one.post(
                        "/v1/auth/bootstrap",
                        headers={"Origin": ORIGIN},
                        json={"bootstrap_token": extra_invitation["bootstrap_token"]},
                    )
                    assert already_paired.status_code == 409, already_paired.text
                    assert already_paired.json()["detail"] == {
                        "code": "browser_already_paired",
                        "message": "This browser is already paired. Open the one-time pairing code in another browser or an unpaired browser profile.",
                        "action": "use_unpaired_browser_profile",
                    }
                    assert browser_one.cookies.get(SESSION_COOKIE) == browser_one_token
                    assert len(owner.get("/v1/auth/browser/sessions").json()) == 3

                    pending = owner.get(
                        f"/v1/auth/ide/browser-invitations/{extra_invitation['invitation_id']}/membership",
                        headers={"Authorization": f"Bearer {ide_one}"},
                    )
                    assert pending.status_code == 200, pending.text
                    assert pending.json()["status"] == "pending"

                    with TestClient(app, base_url=ORIGIN) as extra_browser:
                        consumed = extra_browser.post(
                            "/v1/auth/bootstrap",
                            headers={"Origin": ORIGIN},
                            json={"bootstrap_token": extra_invitation["bootstrap_token"]},
                        )
                        assert consumed.status_code == 200, consumed.text
                        extra_rows = owner.get("/v1/auth/browser/sessions").json()
                        assert len(extra_rows) == 4
                        extra_member = next(
                            row for row in extra_rows
                            if row["member_name"].startswith("Additional browser from Primary VS Code · ")
                        )
                        assert extra_member["member_kind"] == "browser"
                        active = owner.get(
                            f"/v1/auth/ide/browser-invitations/{extra_invitation['invitation_id']}/membership",
                            headers={"Authorization": f"Bearer {ide_one}"},
                        )
                        assert active.status_code == 200, active.text
                        assert active.json()["member_id"] == extra_member["id"]

                        revoked_extra = owner.request(
                            "DELETE",
                            f"/v1/auth/browser/sessions/{extra_member['id']}",
                            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                            json={"expected_created_at": extra_member["created_at"]},
                        )
                        assert revoked_extra.status_code == 200, revoked_extra.text
                        assert extra_browser.get("/v1/auth/session").status_code == 401
                    missing = owner.get(
                        f"/v1/auth/ide/browser-invitations/{extra_invitation['invitation_id']}/membership",
                        headers={"Authorization": f"Bearer {ide_one}"},
                    )
                    assert missing.status_code == 200, missing.text
                    assert missing.json() == {
                        "invitation_id": extra_invitation["invitation_id"],
                        "status": "missing_or_revoked",
                    }
                    assert len(owner.get("/v1/auth/browser/sessions").json()) == 3
                    with app.state.runtime.session_factory() as db:
                        invitation_rows = db.scalar(
                            select(func.count()).select_from(RuntimeConfig).where(
                                RuntimeConfig.key.like(f"{IDE_BROWSER_INVITATION_PREFIX}%")
                            )
                        )
                        membership_rows = db.scalar(
                            select(func.count()).select_from(RuntimeConfig).where(
                                RuntimeConfig.key.like(f"{IDE_BROWSER_MEMBERSHIP_PREFIX}%")
                            )
                        )
                    assert invitation_rows == 0
                    assert membership_rows == 2
                finally:
                    browser_one.close()
                    browser_two.close()

            restarted = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with (
                TestClient(restarted, base_url=ORIGIN) as restarted_owner,
                TestClient(restarted, base_url=ORIGIN) as restarted_one,
                TestClient(restarted, base_url=ORIGIN) as restarted_two,
            ):
                restarted_owner.cookies.set(SESSION_COOKIE, owner_token)
                restarted_one.cookies.set(SESSION_COOKIE, browser_one_token)
                restarted_two.cookies.set(SESSION_COOKIE, browser_two_token)
                assert restarted_one.get("/v1/auth/session").status_code == 200
                assert restarted_two.get("/v1/auth/session").status_code == 200
                members = restarted_owner.get("/v1/auth/browser/sessions").json()
                target = next(
                    row for row in members
                    if row["member_name"].startswith("Primary VS Code integrated dashboard · ")
                )
                revoked = restarted_owner.request(
                    "DELETE",
                    f"/v1/auth/browser/sessions/{target['id']}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={"expected_created_at": target["created_at"]},
                )
                assert revoked.status_code == 200, revoked.text
                assert revoked.json() == {"revoked": True, "current": False}
                assert restarted_one.get("/v1/auth/session").status_code == 401
                assert restarted_two.get("/v1/auth/session").status_code == 200
                assert restarted_owner.get("/v1/auth/session").status_code == 200
                for capability in (ide_one, ide_two):
                    response = restarted_owner.post(
                        "/v1/projects/resolve",
                        headers={"Authorization": f"Bearer {capability}"},
                        json={"repo_path": "/workspaces/not-registered"},
                    )
                    assert response.status_code == 404, response.text
                ide_revoke = restarted_owner.request(
                    "DELETE",
                    f"/v1/auth/ide/capabilities/{'ks1_' + 'a' * 43}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "expected_latest_generation": 1,
                        "expected_active_generation": 1,
                        "expected_pending_generation": None,
                    },
                )
                assert ide_revoke.status_code == 200, ide_revoke.text
                assert restarted_owner.get("/v1/auth/session").status_code == 200
                assert restarted_two.get("/v1/auth/session").status_code == 200
                assert restarted_owner.post(
                    "/v1/projects/resolve",
                    headers={"Authorization": f"Bearer {ide_one}"},
                    json={"repo_path": "/workspaces/not-registered"},
                ).status_code == 401
                assert restarted_owner.post(
                    "/v1/projects/resolve",
                    headers={"Authorization": f"Bearer {ide_two}"},
                    json={"repo_path": "/workspaces/not-registered"},
                ).status_code == 404
    finally:
        engine.dispose()


def test_ide_browser_invitation_cannot_outlive_its_issuing_ide_generation(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as owner:
                _, csrf = _bootstrap(owner)
                capability = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="r",
                    name="Revoked VS Code",
                )
                issued = owner.post(
                    "/v1/auth/ide/browser-invitations",
                    headers={"Authorization": f"Bearer {capability}"},
                    json={"purpose": "integrated_dashboard"},
                )
                assert issued.status_code == 200, issued.text
                invitation = issued.json()["bootstrap_token"]

                revoked = owner.request(
                    "DELETE",
                    f"/v1/auth/ide/capabilities/{'ks1_' + 'r' * 43}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "expected_latest_generation": 1,
                        "expected_active_generation": 1,
                        "expected_pending_generation": None,
                    },
                )
                assert revoked.status_code == 200, revoked.text

                with app.state.runtime.session_factory() as db:
                    members_before = db.scalar(
                        select(func.count()).select_from(RuntimeConfig).where(
                            RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%")
                        )
                    )
                assert members_before == 1

                with TestClient(app, base_url=ORIGIN) as new_browser:
                    for _ in range(2):
                        rejected = new_browser.post(
                            "/v1/auth/bootstrap",
                            headers={"Origin": ORIGIN},
                            json={"bootstrap_token": invitation},
                        )
                        assert rejected.status_code == 409, rejected.text
                        assert rejected.json()["detail"] == {
                            "code": "ide_browser_invitation_issuer_revoked",
                            "message": "The VS Code profile that created this browser invitation is no longer authorized.",
                            "action": "pair_extension",
                        }
                        assert new_browser.cookies.get(SESSION_COOKIE) is None

                with app.state.runtime.session_factory() as db:
                    members_after = db.scalar(
                        select(func.count()).select_from(RuntimeConfig).where(
                            RuntimeConfig.key.like(f"{BROWSER_SESSION_PREFIX}%")
                        )
                    )
                assert members_after == members_before
    finally:
        engine.dispose()


def test_ide_browser_membership_acknowledges_once_and_reconciles_revocation(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as owner:
                _, csrf = _bootstrap(owner)
                primary = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="m",
                    name="Membership VS Code",
                )
                secondary = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="n",
                    name="Other VS Code",
                )
                primary_headers = {"Authorization": f"Bearer {primary}"}
                issued = owner.post(
                    "/v1/auth/ide/browser-invitations",
                    headers=primary_headers,
                    json={"purpose": "integrated_dashboard"},
                )
                assert issued.status_code == 200, issued.text
                payload = issued.json()
                assert payload["purpose"] == "integrated_dashboard"
                invitation_id = payload["invitation_id"]

                pending = owner.get(
                    f"/v1/auth/ide/browser-invitations/{invitation_id}/membership",
                    headers=primary_headers,
                )
                assert pending.status_code == 200, pending.text
                assert pending.json() == {
                    "invitation_id": invitation_id,
                    "status": "pending",
                    "purpose": "integrated_dashboard",
                    "expires_at": payload["expires_at"],
                }
                assert len(owner.get("/v1/auth/browser/sessions").json()) == 1

                with TestClient(app, base_url=ORIGIN) as integrated_browser:
                    consumed = integrated_browser.post(
                        "/v1/auth/bootstrap",
                        headers={"Origin": ORIGIN},
                        json={"bootstrap_token": payload["bootstrap_token"]},
                    )
                    assert consumed.status_code == 200, consumed.text
                    active = owner.get(
                        f"/v1/auth/ide/browser-invitations/{invitation_id}/membership",
                        headers=primary_headers,
                    )
                    assert active.status_code == 200, active.text
                    active_payload = active.json()
                    assert active_payload["status"] == "active"
                    assert active_payload["purpose"] == "integrated_dashboard"
                    assert active_payload["member_id"].startswith("kbm1_")
                    assert len(owner.get("/v1/auth/browser/sessions").json()) == 2

                    replay = integrated_browser.post(
                        "/v1/auth/bootstrap",
                        headers={"Origin": ORIGIN},
                        json={"bootstrap_token": payload["bootstrap_token"]},
                    )
                    assert replay.status_code == 409, replay.text
                    assert len(owner.get("/v1/auth/browser/sessions").json()) == 2

                    hidden = owner.get(
                        f"/v1/auth/ide/browser-invitations/{invitation_id}/membership",
                        headers={"Authorization": f"Bearer {secondary}"},
                    )
                    assert hidden.status_code == 404, hidden.text

                    member = next(
                        row for row in owner.get("/v1/auth/browser/sessions").json()
                        if row["id"] == active_payload["member_id"]
                    )
                    revoked = owner.request(
                        "DELETE",
                        f"/v1/auth/browser/sessions/{member['id']}",
                        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                        json={"expected_created_at": member["created_at"]},
                    )
                    assert revoked.status_code == 200, revoked.text
                    missing = owner.get(
                        f"/v1/auth/ide/browser-invitations/{invitation_id}/membership",
                        headers=primary_headers,
                    )
                    assert missing.status_code == 200, missing.text
                    assert missing.json() == {
                        "invitation_id": invitation_id,
                        "status": "missing_or_revoked",
                    }
                    assert owner.get("/v1/auth/session").status_code == 200
    finally:
        engine.dispose()


def test_reapproved_profile_reconciles_only_its_completed_dashboard_member(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as owner:
                _, csrf = _bootstrap(owner)
                original = _pair_and_activate_ide(owner, csrf, slot_character="d", name="Dashboard IDE")
                other = _pair_and_activate_ide(owner, csrf, slot_character="e", name="Other IDE")
                original_headers = {"Authorization": f"Bearer {original}"}
                receipts = {}
                for purpose in ("integrated_dashboard", "extra_browser"):
                    issued = owner.post(
                        "/v1/auth/ide/browser-invitations",
                        headers=original_headers, json={"purpose": purpose},
                    )
                    assert issued.status_code == 200, issued.text
                    with TestClient(app, base_url=ORIGIN) as browser:
                        consumed = browser.post(
                            "/v1/auth/bootstrap", headers={"Origin": ORIGIN},
                            json={"bootstrap_token": issued.json()["bootstrap_token"]},
                        )
                        assert consumed.status_code == 200, consumed.text
                    membership_path = (
                        f"/v1/auth/ide/browser-invitations/{issued.json()['invitation_id']}/membership"
                    )
                    acknowledged = owner.get(membership_path, headers=original_headers)
                    assert acknowledged.status_code == 200, acknowledged.text
                    receipts[purpose] = (membership_path, acknowledged.json())
                pending = owner.post(
                    "/v1/auth/ide/browser-invitations", headers=original_headers,
                    json={"purpose": "integrated_dashboard"},
                )
                assert pending.status_code == 200, pending.text
                members_before = owner.get("/v1/auth/browser/sessions").json()
                revoked = owner.request(
                    "DELETE", f"/v1/auth/ide/capabilities/{'ks1_' + 'd' * 43}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "expected_latest_generation": 1,
                        "expected_active_generation": 1,
                        "expected_pending_generation": None,
                    },
                )
                assert revoked.status_code == 200, revoked.text
                dashboard_path, dashboard_receipt = receipts["integrated_dashboard"]
                assert owner.get(dashboard_path, headers=original_headers).status_code == 401

                requested = owner.post(
                    "/v1/auth/ide/enrollments",
                    json={
                        "client_name": "Reapproved Dashboard IDE",
                        "client_slot": "ks1_" + "d" * 43,
                        "expected_active_generation": 0,
                    },
                )
                assert requested.status_code == 201, requested.text
                replacement = requested.json()["capability"]
                replacement_headers = {"Authorization": f"Bearer {replacement}"}
                assert replacement.split(".")[2] == "2"
                assert owner.get(dashboard_path, headers=replacement_headers).status_code == 401
                approved = owner.post(
                    f"/v1/auth/ide/enrollments/{requested.json()['request_id']}/decision",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={
                        "decision": "approved", "expected_revision": requested.json()["revision"],
                        "expected_generation": 2,
                    },
                )
                assert approved.status_code == 200, approved.text
                assert owner.get(dashboard_path, headers=replacement_headers).status_code == 401
                activated = owner.post("/v1/auth/ide/activate", headers=replacement_headers)
                assert activated.status_code == 200, activated.text
                reconciled = owner.get(dashboard_path, headers=replacement_headers)
                assert reconciled.status_code == 200, reconciled.text
                assert "set-cookie" not in reconciled.headers
                assert reconciled.json() == dashboard_receipt
                assert set(reconciled.json()) == {
                    "status", "invitation_id", "purpose", "member_id", "created_at",
                }
                assert owner.get(dashboard_path, headers={"Authorization": f"Bearer {other}"}).status_code == 404
                assert owner.get(receipts["extra_browser"][0], headers=replacement_headers).status_code == 404
                assert owner.get(
                    f"/v1/auth/ide/browser-invitations/{pending.json()['invitation_id']}/membership",
                    headers=replacement_headers,
                ).status_code == 404
                with TestClient(app, base_url=ORIGIN) as unpaired_browser:
                    refused = unpaired_browser.post(
                        "/v1/auth/bootstrap", headers={"Origin": ORIGIN},
                        json={"bootstrap_token": pending.json()["bootstrap_token"]},
                    )
                    assert refused.status_code == 409, refused.text
                    assert unpaired_browser.cookies.get(SESSION_COOKIE) is None
                assert owner.get(dashboard_path, headers=original_headers).status_code == 401
                assert owner.get("/v1/auth/browser/sessions").json() == members_before

                receipt_key = f"{IDE_BROWSER_MEMBERSHIP_PREFIX}{dashboard_receipt['invitation_id']}"
                with app.state.runtime.session_factory() as db:
                    row = db.get(RuntimeConfig, receipt_key)
                    assert row is not None
                    original_record = row.value
                    future_record = json.loads(original_record)
                    future_record["issuer_generation"] = 3
                    row.value = json.dumps(future_record)
                    db.commit()
                assert owner.get(dashboard_path, headers=replacement_headers).status_code == 404
                with app.state.runtime.session_factory() as db:
                    mismatched_member = json.loads(original_record)
                    mismatched_member["member_created_at"] = "2026-01-01T00:00:00+00:00"
                    db.get(RuntimeConfig, receipt_key).value = json.dumps(mismatched_member)
                    db.commit()
                assert owner.get(dashboard_path, headers=replacement_headers).json() == {
                    "invitation_id": dashboard_receipt["invitation_id"],
                    "status": "missing_or_revoked",
                }
                with app.state.runtime.session_factory() as db:
                    db.get(RuntimeConfig, receipt_key).value = original_record
                    db.commit()
                member_revoked = owner.request(
                    "DELETE", f"/v1/auth/browser/sessions/{dashboard_receipt['member_id']}",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
                    json={"expected_created_at": dashboard_receipt["created_at"]},
                )
                assert member_revoked.status_code == 200, member_revoked.text
                assert owner.get(dashboard_path, headers=replacement_headers).json() == {
                    "invitation_id": dashboard_receipt["invitation_id"],
                    "status": "missing_or_revoked",
                }
    finally:
        engine.dispose()


def test_ide_browser_membership_wait_rereads_after_committed_wake(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    try:
        with _auth_only_startup():
            app = create_app(runtime_override=Runtime.create(settings, engine=engine))
            with TestClient(app, base_url=ORIGIN) as owner:
                _, csrf = _bootstrap(owner)
                capability = _pair_and_activate_ide(
                    owner,
                    csrf,
                    slot_character="q",
                    name="Concurrent membership VS Code",
                )
                issued = owner.post(
                    "/v1/auth/ide/browser-invitations",
                    headers={"Authorization": f"Bearer {capability}"},
                    json={"purpose": "integrated_dashboard"},
                )
                assert issued.status_code == 200, issued.text
                payload = issued.json()
                broker = EventWakeBroker(engine, app.state.runtime.session_factory)
                closed = False

                class CommitDuringWait:
                    async def wait(self, timeout: float) -> bool:
                        assert timeout == IDE_BROWSER_MEMBERSHIP_WAIT_SECONDS
                        with TestClient(app, base_url=ORIGIN) as integrated_browser:
                            consumed = integrated_browser.post(
                                "/v1/auth/bootstrap",
                                headers={"Origin": ORIGIN},
                                json={"bootstrap_token": payload["bootstrap_token"]},
                            )
                            assert consumed.status_code == 200, consumed.text
                        return True

                    def close(self) -> None:
                        nonlocal closed
                        closed = True

                async def subscribe(subject: str):
                    assert subject == f"ide-browser-invitation:{payload['invitation_id']}"
                    return CommitDuringWait()

                monkeypatch.setattr(broker, "subscribe", subscribe)
                request = Request({
                    "type": "http",
                    "method": "GET",
                    "path": f"/v1/auth/ide/browser-invitations/{payload['invitation_id']}/membership",
                    "headers": [],
                    "app": SimpleNamespace(
                        state=SimpleNamespace(event_wake_broker=broker),
                    ),
                })
                _, slot, generation, _ = capability.split(".")
                context = AuthContext(
                    kind="ide",
                    subject=slot,
                    scopes=frozenset({"browser:invite"}),
                    capability_generation=int(generation),
                )
                runtime = SimpleNamespace(
                    session_factory=app.state.runtime.session_factory,
                    engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
                )
                result = asyncio.run(wait_for_ide_browser_membership(
                    payload["invitation_id"],
                    request,
                    Response(),
                    context=context,
                    runtime=runtime,
                ))
                assert result.status == "active"
                assert result.purpose == "integrated_dashboard"
                assert result.member_id.startswith("kbm1_")
                assert closed is True
    finally:
        engine.dispose()


def test_invalid_browser_member_pruning_is_bounded(tmp_path: Path) -> None:
    engine = _engine()
    settings = _settings(tmp_path)
    runtime = Runtime.create(settings, engine=engine)
    now = datetime.now(timezone.utc)
    revoked = {
        "digest": "not-a-verifier",
        "member_name": "Invalid browser",
        "member_kind": "browser",
        "created_at": (now - timedelta(days=2)).isoformat(),
        "last_seen_at": (now - timedelta(days=1)).isoformat(),
    }
    try:
        with runtime.session_factory() as db:
            for index in range(3):
                db.add(RuntimeConfig(
                    key=f"{BROWSER_SESSION_PREFIX}{index:032d}",
                    value=json.dumps(revoked, separators=(",", ":"), sort_keys=True),
                ))
            db.commit()
            _prune_browser_sessions(db, now, limit=2)
            db.commit()
            remaining = db.scalar(select(func.count()).select_from(RuntimeConfig))
        assert remaining == 1
    finally:
        engine.dispose()


def test_changed_installation_secret_fails_startup_without_mutating_authority(tmp_path: Path) -> None:
    engine = _engine()
    original = _settings(tmp_path)
    try:
        with _auth_only_startup():
            first_app = create_app(runtime_override=Runtime.create(original, engine=engine))
            with TestClient(first_app, base_url=ORIGIN) as first:
                browser_token, csrf = _bootstrap(first)
                _pair_and_activate_ide(
                    first,
                    csrf,
                    slot_character="w",
                    name="binding witness",
                )

            with engine.connect() as connection:
                before = dict(connection.execute(select(RuntimeConfig.key, RuntimeConfig.value)).all())
            changed = _settings(tmp_path, installation_secret="different-installation-secret-" * 2)
            changed_app = create_app(runtime_override=Runtime.create(changed, engine=engine))
            with pytest.raises(InstallationSecretBindingError) as raised:
                with TestClient(changed_app, base_url=ORIGIN):
                    pass
            assert raised.value.code == "installation_secret_binding_mismatch"
            assert raised.value.action == "restore_original_installation_secret_or_matching_database"
            with engine.connect() as connection:
                after = dict(connection.execute(select(RuntimeConfig.key, RuntimeConfig.value)).all())
            assert after == before
            assert INSTALLATION_SECRET_BINDING_KEY in after
            assert browser_token not in json.dumps(after)
    finally:
        engine.dispose()
