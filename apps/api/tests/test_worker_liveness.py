from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import kodesec_api.main as main_module
from kodesec_api.jobs.liveness import (
    WORKER_ADVISOR_CATALOG_KEY,
    WORKER_ADVISOR_KEY,
    fresh_worker_id,
    record_worker_advisor_catalog,
    record_worker_advisor_status,
    record_worker_heartbeat,
    worker_advisor_catalog_failure_reason,
    worker_advisor_catalog,
    worker_advisor_status,
)
from kodesec_api.models import RuntimeConfig
from kodesec_api.worker import _AdvisorReceiptPublisher


def _config(**changes) -> dict:
    values = {
        "ai_mode": "auto",
        "ollama_base_url": "http://127.0.0.1:11434",
        "ollama_model": "fixture-model",
        "ollama_thinking": False,
    }
    values.update(changes)
    return values


def test_api_router_has_no_worker_advisor_transport() -> None:
    assert not hasattr(main_module, "worker_ollama_available_sync")
    assert not hasattr(main_module, "triage_finding_sync")
    source = inspect.getsource(main_module)
    assert "/api/tags" not in source
    assert "/api/generate" not in source


@pytest.mark.parametrize(
    "reason",
    (
        "advisor_connector_protocol",
        "advisor_connector_unavailable",
        "advisor_provider_local_unavailable",
        "advisor_provider_tags_invalid",
    ),
)
def test_local_catalog_failure_preserves_its_safe_reason(reason: str) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    RuntimeConfig.__table__.create(engine)
    now = datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc)
    try:
        with Session(engine) as db, db.begin():
            record_worker_advisor_catalog(
                db, "worker-fixture", catalog=None, reason=reason, now=now
            )
        with Session(engine) as db:
            stored = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
            assert stored is not None
            assert json.loads(stored.value)["reason"] == reason
            assert worker_advisor_catalog(
                db,
                worker_id="worker-fixture",
                stale_after_seconds=90,
                now=now + timedelta(seconds=1),
            ) == (None, reason)
    finally:
        engine.dispose()


def test_advisor_receipt_publisher_repeats_on_independent_bounded_schedule() -> None:
    publisher = object.__new__(_AdvisorReceiptPublisher)
    publisher._success_interval = 60.0
    publisher._retry_interval = 5.0
    outcomes = iter((True, False))
    probes: list[bool] = []
    waits: list[float] = []

    def publish_once() -> bool:
        result = next(outcomes)
        probes.append(result)
        return result

    class ControlledStop:
        def is_set(self) -> bool:
            return False

        def wait(self, interval: float) -> bool:
            waits.append(interval)
            return len(waits) == 2

    publisher._publish_once = publish_once
    publisher._stop = ControlledStop()
    publisher._run()

    assert probes == [True, False]
    assert waits == [60.0, 5.0]


def test_worker_advisor_receipt_is_bounded_redacted_and_config_bound() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    RuntimeConfig.__table__.create(engine)
    now = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
    config = _config()
    try:
        with Session(engine) as db, db.begin():
            record_worker_heartbeat(db, "worker-fixture", now=now)
            record_worker_advisor_status(
                db,
                "worker-fixture",
                config,
                available=True,
                models=["fixture-model", "password=not-a-real-value"],
                reason="Authorization: Bearer not-a-real-value",
                now=now,
            )
        with Session(engine) as db:
            available, models, reason = worker_advisor_status(
                db,
                config,
                worker_id=fresh_worker_id(
                    db, stale_after_seconds=300, now=now + timedelta(seconds=10)
                ),
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            )
            stored = db.get(RuntimeConfig, WORKER_ADVISOR_KEY)
            assert stored is not None
            assert "not-a-real-value" not in stored.value
        assert available is True
        assert models == ["fixture-model", "password=[REDACTED]"]
        assert reason == "Authorization: [REDACTED]"

        with Session(engine) as db:
            assert worker_advisor_status(
                db,
                _config(ollama_model="changed-model"),
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (False, [], "worker_configuration_pending")
            assert worker_advisor_status(
                db,
                config,
                worker_id=None,
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (False, [], "work_processing_unavailable")
            assert worker_advisor_status(
                db,
                config,
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=301),
            ) == (False, [], "worker_advisor_status_stale")
            assert worker_advisor_status(
                db,
                config,
                worker_id="replacement-worker",
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (False, [], "worker_advisor_status_owner_mismatch")
    finally:
        engine.dispose()


def test_worker_local_catalog_receipt_is_bounded_fresh_and_fail_closed() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    RuntimeConfig.__table__.create(engine)
    now = datetime(2026, 8, 30, 8, 0, tzinfo=timezone.utc)
    catalog = {
        "schema": "lomo-advisor-local-catalog/v1",
        "source": "dedicated_local_connector",
        "models": [
            {
                "name": "qwen3:8b",
                "digest": "a" * 64,
                "size_bytes": 5_200_000_000,
                "storage": "local_weights",
            },
            {
                "name": "minimax-m3:cloud",
                "digest": "b" * 64,
                "size_bytes": 301,
                "storage": "cloud_stub",
            },
        ],
        "recommended_model": "qwen3:8b",
    }
    try:
        with Session(engine) as db, db.begin():
            record_worker_heartbeat(db, "worker-fixture", now=now)
            record_worker_advisor_catalog(
                db,
                "worker-fixture",
                catalog=catalog,
                reason=None,
                now=now,
            )
        with Session(engine) as db:
            assert worker_advisor_catalog(
                db,
                worker_id=fresh_worker_id(
                    db, stale_after_seconds=300, now=now + timedelta(seconds=10)
                ),
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (catalog, None)
            stored = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
            assert stored is not None
            assert "host.docker.internal" not in stored.value
            assert worker_advisor_catalog(
                db,
                worker_id=None,
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (None, "work_processing_unavailable")
            assert worker_advisor_catalog(
                db,
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=301),
            ) == (None, "worker_advisor_catalog_stale")
            assert worker_advisor_catalog(
                db,
                worker_id="replacement-worker",
                stale_after_seconds=300,
                now=now + timedelta(seconds=10),
            ) == (None, "worker_advisor_catalog_owner_mismatch")

        with Session(engine) as db, db.begin():
            record_worker_advisor_catalog(
                db,
                "worker-fixture",
                catalog=None,
                reason="advisor_connector_unavailable",
                now=now + timedelta(seconds=20),
            )
        with Session(engine) as db:
            assert worker_advisor_catalog(
                db,
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=21),
            ) == (None, "advisor_connector_unavailable")

        with Session(engine) as db, db.begin():
            stored = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
            assert stored is not None
            corrupted = json.loads(stored.value)
            corrupted["catalog"] = {
                **catalog,
                "models": [{**catalog["models"][0], "size_bytes": "5200000000"}],
            }
            corrupted["reason"] = None
            stored.value = json.dumps(corrupted)
        with Session(engine) as db:
            assert worker_advisor_catalog(
                db,
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=22),
            ) == (None, "invalid_worker_advisor_catalog")

        with (
            Session(engine) as db,
            db.begin(),
            pytest.raises(ValueError, match="failure reason is invalid"),
        ):
            record_worker_advisor_catalog(
                db,
                "worker-fixture",
                catalog=None,
                reason="advisor_provider_route_misconfigured",
                now=now + timedelta(seconds=23),
            )
        with Session(engine) as db, db.begin(), pytest.raises(ValueError):
            record_worker_advisor_catalog(
                db,
                "worker-fixture",
                catalog={
                    **catalog,
                    "models": [
                        {**catalog["models"][0], "name": "qwen3:8b\u2028spoofed"}
                    ],
                    "recommended_model": "qwen3:8b\u2028spoofed",
                },
                reason=None,
                now=now + timedelta(seconds=24),
            )
        with Session(engine) as db, db.begin():
            stored = db.get(RuntimeConfig, WORKER_ADVISOR_CATALOG_KEY)
            assert stored is not None
            wrong_route = json.loads(stored.value)
            wrong_route["catalog"] = None
            wrong_route["reason"] = "advisor_provider_route_misconfigured"
            stored.value = json.dumps(wrong_route)
        with Session(engine) as db:
            assert worker_advisor_catalog(
                db,
                worker_id="worker-fixture",
                stale_after_seconds=300,
                now=now + timedelta(seconds=25),
            ) == (None, "invalid_worker_advisor_catalog")
        assert (
            worker_advisor_catalog_failure_reason(
                "advisor_provider_route_misconfigured"
            )
            == "advisor_connector_protocol"
        )
        assert (
            worker_advisor_catalog_failure_reason("unknown_connector_failure")
            == "advisor_connector_protocol"
        )
    finally:
        engine.dispose()
