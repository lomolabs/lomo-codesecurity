from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from kodesec_api.db import Base, Runtime
from kodesec_api.main import router
from kodesec_api.models import Job
from kodesec_api.settings import Settings


@pytest.fixture()
def job_api() -> Iterator[tuple[TestClient, Runtime]]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    runtime = Runtime.create(Settings(_env_file=None, DATABASE_URL="sqlite+pysqlite://"), engine=engine)
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    try:
        with TestClient(app) as client:
            yield client, runtime
    finally:
        engine.dispose()


def test_active_job_query_does_not_lose_old_work_behind_terminal_history(
    job_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = job_api
    with runtime.session_factory() as db:
        active = Job(kind="scan", title="old active scan", status="running")
        db.add(active)
        db.flush()
        active_id = active.id
        db.add_all(
            [Job(kind="scan", title=f"terminal history {index}", status="completed") for index in range(100)]
        )
        db.commit()

    history = client.get("/v1/jobs")
    assert history.status_code == 200
    assert len(history.json()) == 100
    assert all(item["id"] != active_id for item in history.json())

    current = client.get("/v1/jobs?status=active&limit=500")
    assert current.status_code == 200
    assert [(item["id"], item["status"]) for item in current.json()] == [(active_id, "running")]


def test_job_query_exposes_only_bounded_updater_activity(
    job_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = job_api
    observed_at = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    with runtime.session_factory() as db:
        job = Job(
            kind="scanner_cache_update",
            title="Update verified offline scanner cache",
            status="running",
            stage="downloading",
            heartbeat_at=observed_at,
            checkpoint={
                "updater_activity": {
                    "status": "running",
                    "stage": "downloading",
                    "updated_at": "2026-08-24T12:00:00Z",
                    "component_id": "grype-db",
                    "component_index": 2,
                    "component_total": 6,
                    "bytes_completed": 50,
                    "bytes_total": 100,
                }
            },
        )
        db.add(job)
        db.flush()
        job_id = job.id
        db.commit()

    response = client.get(f"/v1/jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["heartbeat_at"].startswith("2026-08-24T12:00:00")
    assert body["activity"] == {
        "component_id": "grype-db",
        "component_index": 2,
        "component_total": 6,
        "bytes_completed": 50,
        "bytes_total": 100,
        "updated_at": "2026-08-24T12:00:00Z",
    }
