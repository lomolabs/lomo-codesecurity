from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

from kodesec_scanner.preparation_budget import issue_budget
from kodesec_scanner.updater import (
    OperationActivity,
    OperationConflictError,
    OperationContext,
    OperationRequest,
    OperationStateError,
    OperationStore,
    operation_request_digest,
)

NOW = "2026-08-12T21:00:00Z"
LATER = "2026-08-12T21:00:03Z"


def request() -> OperationRequest:
    components = ["bearer-rules", "grype-db"]
    budget = issue_budget(now=datetime.fromisoformat(NOW.replace("Z", "+00:00")))
    return OperationRequest(
        schema_version=2,
        preparation_budget=budget,
        operation_id=uuid4(),
        request_digest=operation_request_digest(
            schema_version=2, kind="cache_update", requested_components=components,
            preparation_budget=budget,
        ),
        kind="cache_update",
        requested_components=components,
        attempt=1,
        max_attempts=3,
    )


def active(tmp_path: Path) -> tuple[OperationStore, OperationContext]:
    store = OperationStore(tmp_path / "cache")
    req = request()
    store.create_or_get(req, now=NOW)
    store.transition(
        req.operation_id,
        status="running",
        stage="downloading",
        activity=OperationActivity(component_id="bearer-rules", component_index=1, component_total=2),
        now=NOW,
    )
    context = OperationContext(request=req, store=store, wall_now=lambda: NOW)
    # Clock recovery reads the durable record once before these tests count the
    # ledger reads belonging to each byte-progress callback.
    context.remaining_seconds(900)
    return store, context


def test_byte_progress_reads_one_current_record_and_keeps_component(tmp_path, monkeypatch):
    store, context = active(tmp_path)
    original_load = OperationStore._load_unlocked
    calls = 0

    def counted(self, operation_id):
        nonlocal calls
        calls += 1
        return original_load(self, operation_id)

    monkeypatch.setattr(OperationStore, "_load_unlocked", counted)
    updated = context.byte_progress(7, 10, force=True, now=LATER)
    assert calls == 1
    assert updated.activity == OperationActivity(
        component_id="bearer-rules", component_index=1, component_total=2,
        bytes_completed=7, bytes_total=10,
    )
    # A later component selection must be derived from the record read under
    # the same lock, rather than carried over from an earlier callback.
    store.transition(
        context.request.operation_id, status="running", stage="validating_generation",
        activity=OperationActivity(component_id="grype-db", component_index=2, component_total=2),
        now="2026-08-12T21:00:04Z",
    )
    calls = 0
    updated = context.byte_progress(2, 12, force=True, now="2026-08-12T21:00:05Z")
    assert calls == 1
    assert updated.activity == OperationActivity(
        component_id="grype-db", component_index=2, component_total=2,
        bytes_completed=2, bytes_total=12,
    )


def test_byte_progress_rechecks_cancel_on_every_call(tmp_path, monkeypatch):
    store, context = active(tmp_path)
    original_load = OperationStore._load_unlocked
    calls = 0

    def counted(self, operation_id):
        nonlocal calls
        calls += 1
        return original_load(self, operation_id)

    monkeypatch.setattr(OperationStore, "_load_unlocked", counted)
    first = context.byte_progress(1, 10, now=NOW)
    assert calls == 1
    assert first.activity is not None and first.activity.bytes_completed is None
    store.request_cancel(context.request.operation_id, request_digest=context.request.request_digest, now=LATER)
    calls = 0
    with pytest.raises(OperationStateError, match="cancellation requested"):
        context.byte_progress(2, 10, force=True, now="2026-08-12T21:00:04Z")
    assert calls == 1


def test_byte_progress_preserves_throttle_and_digest_gate(tmp_path):
    store, context = active(tmp_path)
    before = store.load(context.request.operation_id)
    throttled = context.byte_progress(1, 10, now="2026-08-12T21:00:01Z")
    assert throttled == before
    updated = context.byte_progress(1, 10, now=LATER)
    assert updated.activity is not None and updated.activity.bytes_completed == 1
    wrong = "0" * 64 if context.request.request_digest != "0" * 64 else "1" * 64
    with pytest.raises(OperationConflictError, match="digest does not match"):
        store.update_byte_progress(context.request.operation_id, request_digest=wrong,
                                   completed=2, total=10, force=True, now=LATER)
    with pytest.raises(OperationConflictError, match="digest header is malformed"):
        store.update_byte_progress(context.request.operation_id, request_digest="invalid",
                                   completed=2, total=10, force=True, now=LATER)


def test_byte_progress_without_selected_activity_keeps_record_unchanged(tmp_path):
    store = OperationStore(tmp_path / "cache")
    req = request()
    before, _ = store.create_or_get(req, now=NOW)
    context = OperationContext(request=req, store=store, wall_now=lambda: NOW)
    assert context.byte_progress(1, 10, force=True, now=LATER) == before
    assert store.load(req.operation_id) == before


@pytest.mark.parametrize("completed,total", [(-1, 10), (11, 10), (0, 0)])
def test_byte_progress_rejects_invalid_counters_without_writing(tmp_path, completed, total):
    store, context = active(tmp_path)
    before = store.load(context.request.operation_id)
    with pytest.raises(OperationStateError, match="state contract"):
        context.byte_progress(completed, total, force=True, now=LATER)
    assert store.load(context.request.operation_id) == before
