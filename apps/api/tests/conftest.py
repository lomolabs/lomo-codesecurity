from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.schema import CreateSchema, DropSchema

from kodesec_api.advisor import providers


API_ROOT = Path(__file__).resolve().parents[1]
_ADVISOR_TEST_MODEL = "fixture-advisor:latest"
_ADVISOR_TEST_MODEL_DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def generated_test_installation_identity(monkeypatch):
    """Test factories share a non-secret initial-install ID, not a production default."""
    monkeypatch.setenv("KODESEC_INSTALLATION_ID", "012345abcdef")


@pytest.fixture()
def seed_ready_local_advisor():
    """Persist one exact tested local provider and return its admission pin."""

    def seed(runtime) -> dict[str, object]:
        profile = providers.normalize_profile(
            {
                "id": "local-test",
                "name": "Test-local Advisor",
                "transport": "local",
                "priority": 0,
                "enabled": True,
                "base_url": None,
                "model": _ADVISOR_TEST_MODEL,
                "model_digest": _ADVISOR_TEST_MODEL_DIGEST,
                "ssh_host": None,
                "ssh_port": None,
                "ssh_user": None,
            }
        )
        collection = providers.update_provider_status(
            {"revision": 1, "active_provider_id": None, "providers": [profile]},
            profile["id"],
            status="available",
            reason=None,
            reason_code=None,
            remediation="none",
        )
        ready = collection["providers"][0]
        with runtime.session_factory() as db, db.begin():
            providers.save_collection(db, collection)
            providers.save_receipt(
                db,
                {
                    "schema": "lomo-advisor-provider-receipt/v1",
                    "provider_id": ready["id"],
                    "kind": "local",
                    "route": "local",
                    "model": ready["model"],
                    "model_digest": ready["model_digest"],
                    "status": "ready",
                    "tested_at": "2026-08-25T12:00:00Z",
                    "revision": ready["config_revision"],
                },
            )
        return {
            "provider_collection_revision": collection["revision"],
            "provider_id": ready["id"],
            "transport": "local",
            "provider_config_revision": ready["config_revision"],
            "provider_config_digest": ready["config_digest"],
            "model": ready["model"],
            "model_digest": ready["model_digest"],
        }

    return seed


@pytest.fixture(scope="session")
def postgres_test_url() -> str:
    url = os.environ.get("KODESEC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("set KODESEC_TEST_DATABASE_URL to an isolated PostgreSQL database")
    if make_url(url).get_backend_name() != "postgresql":
        pytest.fail("KODESEC_TEST_DATABASE_URL must use PostgreSQL")
    return url


@pytest.fixture()
def postgres_engine(postgres_test_url: str) -> Engine:
    schema = f"kodesec_test_{uuid4().hex}"
    administration_engine = create_engine(postgres_test_url, pool_pre_ping=True, future=True)
    with administration_engine.begin() as connection:
        connection.execute(CreateSchema(schema))

    test_engine = create_engine(
        postgres_test_url,
        connect_args={"options": f"-csearch_path={schema}"},
        pool_pre_ping=True,
        future=True,
    )
    try:
        yield test_engine
    finally:
        test_engine.dispose()
        with administration_engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))
        administration_engine.dispose()
