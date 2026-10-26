from __future__ import annotations

from unittest.mock import call, patch
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from kodesec_api.app import create_app
from kodesec_api.auth import enforce_installation_secret_binding
from kodesec_api.db import Base, Runtime, initialize_database
from kodesec_api.settings import Settings


def _settings(label: str, port: int) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL=f"sqlite+pysqlite:///{label}",
        SCANNER_URL=f"http://scanner-{label}:8091",
        KODESEC_INSTALLATION_SECRET=label * 48,
        KODESEC_BOOTSTRAP_TOKEN=f"bootstrap-{label}" * 4,
        KODESEC_CONTROL_ORIGINS=f"http://127.0.0.1:{port}",
        KODESEC_ALLOWED_ROOTS="/workspaces",
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )


def _sqlite_runtime(settings: Settings) -> Runtime:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return Runtime.create(settings, engine=engine)


@pytest.mark.parametrize("identity", ["", "012345ABCDEf", "a" * 13, "012345abcde\n"])
def test_config_installation_identity_must_be_exact_generated_identity(identity: str) -> None:
    settings = _settings("identity", 18089).model_copy(update={"installation_id": identity})
    with pytest.raises(RuntimeError, match="KODESEC_INSTALLATION_ID"):
        settings.validate_security_material()


def test_config_returns_only_public_installation_identity_after_authentication() -> None:
    settings = _settings("identity", 18089).model_copy(update={"installation_id": "abcdef012345"})
    runtime = _sqlite_runtime(settings)
    with runtime.session_factory() as db:
        enforce_installation_secret_binding(db, settings)
    app = create_app(runtime_override=runtime)
    with patch("kodesec_api.app._startup"), TestClient(app, base_url=settings.control_origin_list[0]) as client:
        assert client.get("/v1/config").status_code == 401
        paired = client.post("/v1/auth/bootstrap", headers={"Origin": settings.control_origin_list[0]},
            json={"bootstrap_token": settings.bootstrap_token})
        assert paired.status_code == 200
        response = client.get("/v1/config")
        assert response.status_code == 200
        assert response.json()["installation_id"] == settings.installation_id
        assert settings.installation_secret not in response.text
        assert settings.bootstrap_token not in response.text
        assert "state_dir" not in response.text and "runtime.env" not in response.text
    compose = (Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text()
    api = compose.split("\n  api:\n", 1)[1].split("\n  api-ingress:", 1)[0]
    assert "KODESEC_INSTALLATION_ID: ${KODESEC_INSTALLATION_ID:?run make init}" in api


def test_simultaneous_factory_lifespans_keep_sessions_and_settings_isolated() -> None:
    settings_a = _settings("a", 18081)
    settings_b = _settings("b", 18082)
    runtime_a = _sqlite_runtime(settings_a)
    runtime_b = _sqlite_runtime(settings_b)
    with runtime_a.session_factory() as db:
        enforce_installation_secret_binding(db, settings_a)
    with runtime_b.session_factory() as db:
        enforce_installation_secret_binding(db, settings_b)
    app_a = create_app(runtime_override=runtime_a)
    app_b = create_app(runtime_override=runtime_b)
    try:
        with patch("kodesec_api.app._startup") as startup:
            with TestClient(app_a, base_url=settings_a.control_origin_list[0]) as client_a:
                with TestClient(app_b, base_url=settings_b.control_origin_list[0]) as client_b:
                    assert startup.call_args_list == [call(runtime_a), call(runtime_b)]
                    pair_a = client_a.post(
                        "/v1/auth/ide/enrollments",
                        json={
                            "client_name": "runtime-a",
                            "client_slot": "ks1_" + "a" * 43,
                            "expected_active_generation": 0,
                        },
                    )
                    pair_b = client_b.post(
                        "/v1/auth/ide/enrollments",
                        json={
                            "client_name": "runtime-b",
                            "client_slot": "ks1_" + "b" * 43,
                            "expected_active_generation": 0,
                        },
                    )
                    assert pair_a.status_code == 201, pair_a.text
                    assert pair_b.status_code == 201, pair_b.text
                    for client, settings, enrollment in (
                        (client_a, settings_a, pair_a.json()),
                        (client_b, settings_b, pair_b.json()),
                    ):
                        browser = client.post(
                            "/v1/auth/bootstrap",
                            headers={"Origin": settings.control_origin_list[0]},
                            json={"bootstrap_token": settings.bootstrap_token},
                        )
                        assert browser.status_code == 200, browser.text
                        approved = client.post(
                            f"/v1/auth/ide/enrollments/{enrollment['request_id']}/decision",
                            headers={
                                "Origin": settings.control_origin_list[0],
                                "X-CSRF-Token": browser.json()["csrf_token"],
                            },
                            json={
                                "decision": "approved",
                                "expected_revision": enrollment["revision"],
                                "expected_generation": enrollment["generation"],
                            },
                        )
                        assert approved.status_code == 200, approved.text
                    bearer_a = {"Authorization": f"Bearer {pair_a.json()['capability']}"}
                    bearer_b = {"Authorization": f"Bearer {pair_b.json()['capability']}"}
                    assert client_a.post("/v1/auth/ide/activate", headers=bearer_a).status_code == 200
                    assert client_b.post("/v1/auth/ide/activate", headers=bearer_b).status_code == 200

                    created = client_a.post(
                        "/v1/projects",
                        headers=bearer_a,
                        json={"name": "only-a", "repo_path": "/workspaces/a", "default_branch": "main"},
                    )
                    assert created.status_code == 201, created.text
                    assert client_a.post(
                        "/v1/projects/resolve",
                        headers=bearer_a,
                        json={"repo_path": "/workspaces/a"},
                    ).json()["name"] == "only-a"
                    assert client_b.post(
                        "/v1/projects/resolve",
                        headers=bearer_b,
                        json={"repo_path": "/workspaces/a"},
                    ).status_code == 404

                    assert client_b.post(
                        "/v1/projects/resolve",
                        headers=bearer_a,
                        json={"repo_path": "/workspaces/a"},
                    ).status_code == 401
                    assert client_a.post(
                        "/v1/projects/resolve",
                        headers=bearer_b,
                        json={"repo_path": "/workspaces/a"},
                    ).status_code == 401
                    assert client_a.get("/docs", headers=bearer_a).status_code == 403
                    assert client_a.get("/redoc", headers=bearer_a).status_code == 403

                # Runtime B's shutdown cannot disturb the still-active A lifespan.
                assert client_a.post(
                    "/v1/projects/resolve",
                    headers=bearer_a,
                    json={"repo_path": "/workspaces/a"},
                ).json()["name"] == "only-a"
        assert app_a.state.runtime.settings.scanner_url == "http://scanner-a:8091"
        assert app_b.state.runtime.settings.scanner_url == "http://scanner-b:8091"
        assert runtime_a.session_factory.kw["bind"] is runtime_a.engine
        assert runtime_b.session_factory.kw["bind"] is runtime_b.engine
        assert runtime_a.engine is not runtime_b.engine
    finally:
        runtime_a.engine.dispose()
        runtime_b.engine.dispose()


def test_factory_rejects_reusing_one_runtime() -> None:
    runtime = _sqlite_runtime(_settings("one-app", 18084))
    try:
        first_app = create_app(runtime_override=runtime)
        assert first_app.state.runtime is runtime
        with pytest.raises(RuntimeError, match="already attached"):
            create_app(runtime_override=runtime)
    finally:
        runtime.engine.dispose()


def test_runtime_disposes_only_owned_engine_and_only_once() -> None:
    owned = _sqlite_runtime(_settings("owned-once", 18085))
    external = _sqlite_runtime(_settings("external", 18086))
    owned.owns_engine = True
    try:
        with patch.object(owned.engine, "dispose", wraps=owned.engine.dispose) as owned_dispose:
            owned.dispose()
            owned.dispose()
            owned_dispose.assert_called_once_with()
        with patch.object(external.engine, "dispose", wraps=external.engine.dispose) as external_dispose:
            external.dispose()
            external.dispose()
            external_dispose.assert_not_called()
    finally:
        external.engine.dispose()


@pytest.mark.parametrize("owns_engine", [True, False])
def test_factory_static_mount_failure_cleans_up_only_owned_engine(owns_engine: bool) -> None:
    runtime = _sqlite_runtime(_settings(f"assembly-{owns_engine}", 18087 if owns_engine else 18088))
    runtime.owns_engine = owns_engine
    try:
        with (
            patch.object(runtime.engine, "dispose", wraps=runtime.engine.dispose) as dispose,
            patch("kodesec_api.app.mount_static_application", side_effect=RuntimeError("static fixture failed")),
        ):
            with pytest.raises(RuntimeError, match="static fixture failed"):
                create_app(runtime_override=runtime)
            if owns_engine:
                dispose.assert_called_once_with()
                runtime.dispose()
                dispose.assert_called_once_with()
            else:
                dispose.assert_not_called()
                # An external runtime is still usable because no app was returned.
                with patch("kodesec_api.app.mount_static_application"):
                    assert create_app(runtime_override=runtime).state.runtime is runtime
                dispose.assert_not_called()
    finally:
        if not owns_engine:
            runtime.engine.dispose()


def test_factory_disposes_an_owned_engine_after_lifespan(postgres_engine, tmp_path) -> None:
    settings = _settings("owned", 18083).model_copy(
        update={
            "database_url": str(postgres_engine.url),
            "artifact_dir": str(tmp_path / "artifacts"),
        }
    )
    initialize_database(postgres_engine)
    runtime = Runtime.create(settings, engine=postgres_engine)
    runtime.owns_engine = True
    app = create_app(runtime_override=runtime)

    with patch.object(postgres_engine, "dispose", wraps=postgres_engine.dispose) as dispose:
        with TestClient(app, base_url=settings.control_origin_list[0]):
            pass
        dispose.assert_called_once_with()
