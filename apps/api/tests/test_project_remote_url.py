from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from kodesec_api.app import create_app
from kodesec_api.auth import enforce_installation_secret_binding
from kodesec_api.db import Base, Runtime
from kodesec_api.schemas import ProjectCreate
from kodesec_api.settings import Settings


@pytest.mark.parametrize(
    ("remote_url", "expected"),
    [
        (None, None),
        ("   ", None),
        ("https://github.com/lomo-dev/code-security.git", "https://github.com/lomo-dev/code-security.git"),
        (" ssh://git@127.0.0.1:2222/owner/repo.git ", "ssh://git@127.0.0.1:2222/owner/repo.git"),
        ("ssh://github.com/owner/repo.git", "ssh://github.com/owner/repo.git"),
        ("git@github.com:owner/repo.git", "git@github.com:owner/repo.git"),
        ("github.com:owner/repo.git", "github.com:owner/repo.git"),
        ("git@[::1]:owner/repo.git", "git@[::1]:owner/repo.git"),
        ("local://examples/vulnerable-demo", "local://examples/vulnerable-demo"),
    ],
)
def test_project_remote_url_accepts_supported_credential_free_forms(
    remote_url: str | None,
    expected: str | None,
) -> None:
    project = ProjectCreate(name="fixture", repo_path="/workspaces/fixture", remote_url=remote_url)

    assert project.remote_url == expected


@pytest.mark.parametrize(
    "remote_url",
    [
        "https://user@example.test/owner/repo.git",
        "https://user:password@example.test/owner/repo.git",
        "https://example.test/owner/repo.git?access_token=fixture",
        "https://example.test/owner/repo.git#credential",
        "ssh://alice@example.test/owner/repo.git",
        "ssh://git:password@example.test/owner/repo.git",
        "alice@example.test:owner/repo.git",
        "user:password@example.test:owner/repo.git",
        "http://example.test/owner/repo.git",
        "git://example.test/owner/repo.git",
        "file:///workspaces/repo",
        "ftp://example.test/owner/repo.git",
        "javascript:alert(1)",
        "data:text/plain,fixture",
        "https:///owner/repo.git",
        "https://example.test",
        "https://example.test:99999/owner/repo.git",
        "https://999.999.999.999/owner/repo.git",
        "https://example.test/owner/%ZZrepo.git",
        "https://example.test/owner/%0Arepo.git",
        "https://example.test/owner/repo.git\nAuthorization: fixture",
        "https://example.test/owner/repo.git\r",
        "\thttps://example.test/owner/repo.git",
        "git@example.test:",
        "git@example.test:../repo.git",
        "git@example.test:owner/repo.git?access_token=fixture",
        "local://user@example.test/repo.git",
        "local://examples/../repo.git",
        "local:///absolute/repo.git",
        "//example.test/owner/repo.git",
    ],
)
def test_project_remote_url_rejects_credentials_controls_and_malformed_inputs(remote_url: str) -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(name="fixture", repo_path="/workspaces/fixture", remote_url=remote_url)


@pytest.fixture()
def project_api() -> Iterator[tuple[TestClient, dict[str, str]]]:
    origin = "http://127.0.0.1:18104"
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        SCANNER_URL="http://scanner:8091",
        KODESEC_INSTALLATION_SECRET="installation-fixture-" * 3,
        KODESEC_BOOTSTRAP_TOKEN="bootstrap-fixture-" * 4,
        KODESEC_CONTROL_ORIGINS=origin,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(settings, engine=engine)
    with runtime.session_factory() as db:
        enforce_installation_secret_binding(db, settings)
    client = TestClient(create_app(runtime_override=runtime), base_url=origin)
    pair = client.post(
        "/v1/auth/ide/enrollments",
        json={
            "client_name": "remote-url-test",
            "client_slot": "ks1_" + "r" * 43,
            "expected_active_generation": 0,
        },
    )
    assert pair.status_code == 201, pair.text
    browser = client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": origin},
        json={"bootstrap_token": settings.bootstrap_token},
    )
    assert browser.status_code == 200, browser.text
    approved = client.post(
        f"/v1/auth/ide/enrollments/{pair.json()['request_id']}/decision",
        headers={"Origin": origin, "X-CSRF-Token": browser.json()["csrf_token"]},
        json={
            "decision": "approved",
            "expected_revision": pair.json()["revision"],
            "expected_generation": pair.json()["generation"],
        },
    )
    assert approved.status_code == 200, approved.text
    headers = {"Authorization": f"Bearer {pair.json()['capability']}"}
    activated = client.post("/v1/auth/ide/activate", headers=headers)
    assert activated.status_code == 200, activated.text
    try:
        yield client, headers
    finally:
        client.close()
        engine.dispose()


def test_project_api_persists_normalized_remote_and_rejects_secret_userinfo(
    project_api: tuple[TestClient, dict[str, str]],
) -> None:
    client, headers = project_api
    accepted = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": "accepted",
            "repo_path": "/workspaces/accepted",
            "remote_url": "  git@github.com:lomo-dev/code-security.git  ",
            "default_branch": "main",
        },
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["remote_url"] == "git@github.com:lomo-dev/code-security.git"

    secret = "fixture-password-must-not-be-reflected"
    rejected = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": "rejected",
            "repo_path": "/workspaces/rejected",
            "remote_url": f"https://user:{secret}@example.test/owner/repo.git",
            "default_branch": "main",
        },
    )
    assert rejected.status_code == 422
    assert rejected.headers["cache-control"] == "no-store"
    assert secret not in rejected.text
    resolved = client.post(
        "/v1/projects/resolve",
        headers=headers,
        json={"repo_path": "/workspaces/accepted"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["name"] == "accepted"
    assert client.post(
        "/v1/projects/resolve",
        headers=headers,
        json={"repo_path": "/workspaces/rejected"},
    ).status_code == 404
    assert client.get("/v1/projects", headers=headers).status_code == 403


def test_project_api_binds_canonical_paths_and_allows_same_basename_roots(
    project_api: tuple[TestClient, dict[str, str]],
) -> None:
    client, headers = project_api
    first = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": " service ",
            "repo_path": "/workspaces/team-a//service/.",
            "default_branch": "main",
        },
    )
    second = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": "service",
            "repo_path": "/workspaces/team-b/service/",
            "default_branch": "main",
        },
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["name"] == second.json()["name"] == "service"
    assert first.json()["repo_path"] == "/workspaces/team-a/service"
    assert second.json()["repo_path"] == "/workspaces/team-b/service"
    assert first.json()["id"] != second.json()["id"]

    for expected in (first.json(), second.json()):
        resolved = client.post(
            "/v1/projects/resolve",
            headers=headers,
            json={"repo_path": f"{expected['repo_path']}//."},
        )
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["id"] == expected["id"]

    duplicate = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": "different-label",
            "repo_path": "/workspaces/team-a/service/",
            "default_branch": "main",
        },
    )
    assert duplicate.status_code == 409
    assert "canonical source path" in duplicate.text
