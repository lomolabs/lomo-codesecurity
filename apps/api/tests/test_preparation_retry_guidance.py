"""An unavailable preparation retry must not be offered as a working control."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from kodesec_api import main
from kodesec_api.jobs.repository import InvalidJobTransition, retry_failed_job
from kodesec_api.models import Job
from kodesec_api.preparation_budget import issue_budget
from test_scanner_lifecycle_api import _runtime


@pytest.mark.parametrize("kind", ["scanner_catalog_check", "scanner_cache_update"])
@pytest.mark.parametrize("budget_state", ["valid", "expired", "boundary", "missing", "invalid"])
def test_preparation_retry_projection_agrees_with_command(kind, budget_state):
    runtime = _runtime()
    now = datetime.now(timezone.utc)
    issued = now - timedelta(seconds={"expired": 1201, "boundary": 1200}.get(budget_state, 0))
    payload = {"v": 1, "preparation_budget": issue_budget(now=issued).model_dump(mode="json")}
    if budget_state == "missing":
        del payload["preparation_budget"]
    elif budget_state == "invalid":
        payload["preparation_budget"] = {"schema_version": 99}
    with runtime.session_factory() as db:
        job = Job(kind=kind, title="Prepare scanners", status="failed", stage="failed",
                  payload=payload, checkpoint={}, attempt=2, max_attempts=3, revision=7,
                  created_at=now, updated_at=now, completed_at=now)
        db.add(job)
        db.commit()
        original = (job.status, job.revision, job.payload, job.completed_at)
        with patch.object(main, "_utcnow", return_value=now):
            result = main._job_to_out(db, job)
        assert (job.status, job.revision, job.payload, job.completed_at) == original
        assert result["can_retry"] is (budget_state == "valid")
        if budget_state == "valid":
            assert result["retry_blocked_reason"] is None
            retry_failed_job(db, job.id, expected_revision=7, now=now)
            assert job.status == "queued"
        else:
            assert "Open Tools to check scanner readiness" in result["retry_blocked_reason"]
            with pytest.raises(InvalidJobTransition, match="scanner_preparation"):
                retry_failed_job(db, job.id, expected_revision=7, now=now)
            assert (job.status, job.revision, job.payload, job.completed_at) == original


def test_clock_rollback_does_not_offer_an_expired_preparation_retry():
    runtime = _runtime()
    issued = datetime.now(timezone.utc) - timedelta(seconds=1300)
    with runtime.session_factory() as db:
        job = Job(kind="scanner_cache_update", title="Prepare scanners", status="failed",
                  payload={"v": 1, "preparation_budget": issue_budget(now=issued).model_dump(mode="json")},
                  checkpoint={}, attempt=2, max_attempts=3, revision=7,
                  created_at=issued, updated_at=issued + timedelta(seconds=1201))
        db.add(job)
        db.commit()
        with patch.object(main, "_utcnow", return_value=issued + timedelta(seconds=60)):
            result = main._job_to_out(db, job)
        assert result["can_retry"] is False
        assert "expired" in result["retry_blocked_reason"]


@pytest.mark.parametrize("kind", ["scan", "scanner_cache_rollback"])
def test_other_job_kinds_keep_their_existing_retry_behavior(kind):
    runtime = _runtime()
    with runtime.session_factory() as db:
        job = Job(kind=kind, title="Retryable work", status="failed", payload={"v": 1},
                  checkpoint={}, attempt=1, max_attempts=3, revision=1)
        db.add(job)
        db.commit()
        result = main._job_to_out(db, job)
        assert result["can_retry"] is True
        assert result["retry_blocked_reason"] is None
