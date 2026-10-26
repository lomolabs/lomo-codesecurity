from __future__ import annotations

import threading
import os
import tempfile
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault(
    "KODESEC_SCRATCH_DIR",
    str(Path(tempfile.mkdtemp(prefix="kodesec-runtime-cache-test-")) / "scratch"),
)

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from kodesec_scanner import cache_manifest as manifest
from kodesec_scanner import main, runtime_cache, tools, updater
from kodesec_scanner.runtime_cache import RuntimeCacheVerifier, VerificationConflict
import test_cache_manifest as cache_fixtures
from test_cache_manifest import OPERATION_ID, RULES_LOCK, TOOLS_LOCK, _prepare_generation


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / "cache"
    generation = _prepare_generation(root, content=b"reviewed")
    pointer = manifest.activate_generation(root, generation.generation_id, OPERATION_ID)
    return root, pointer


@pytest.fixture
def verifier(cache):
    root, _ = cache
    service = RuntimeCacheVerifier(root, TOOLS_LOCK, RULES_LOCK)
    service.start()
    yield service
    assert service.shutdown()


def resolve(service):
    return service.resolve(service.cache_root,
        tool_lock_sha256=manifest.load_tool_lock(service.tool_lock_path).sha256,
        rules_lock_sha256=manifest.load_rules_lock(service.rules_lock_path).sha256)


def terminal(service, target="active"):
    # Condition notification observes actual worker completion, not a guessed delay.
    with service._condition:
        assert service._condition.wait_for(
            lambda: service._tasks[target].state != "verifying", timeout=5)
        return service._tasks[target]


def test_pending_is_nonblocking_single_worker_and_exposes_actual_progress(cache, verifier, monkeypatch):
    root, pointer = cache
    entered, release = threading.Event(), threading.Event()
    original = runtime_cache.validate_generation
    calls = []

    def verify(*args, **kwargs):
        calls.append(args[1])
        kwargs["progress"]("bearer-rules", 1, 1, 3, 8)
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        pending = resolve(verifier)
        assert pending.state == "verifying" and pending.generation is None
        assert entered.wait(5)
        with ThreadPoolExecutor(max_workers=2) as readers:
            first = readers.submit(resolve, verifier).result(timeout=5)
            second = readers.submit(resolve, verifier).result(timeout=5)
        assert not release.is_set()  # Neither reader waited for the held verification.
        assert first.verification == second.verification
        assert first.verification.component_id == "bearer-rules"
        assert first.verification.bytes_verified == 3
        assert first.verification.bytes_total == 8
        assert first.verification.phase == "hashing"
        assert first.verification.last_activity_at >= first.verification.started_at
        assert verifier.retry("active", pointer.active.generation_id) == second.verification
        assert calls == [pointer.active.generation_id]
    finally:
        release.set()
    assert terminal(verifier).state == "ready"
    ready = resolve(verifier)
    assert ready.generation.reference == pointer.active
    assert ready.verification is None
    resolve(verifier)
    assert calls == [pointer.active.generation_id]


@pytest.mark.parametrize("failure,state", [
    (runtime_cache._VerificationDeadline(), "verification_timeout"),
    (manifest.GrypeContentValidationError("deadline"), "verification_timeout"),
    (OSError("private diagnostic must not escape"), "verification_failed"),
    (RuntimeError("private diagnostic must not escape"), "verification_failed"),
    (TypeError("private diagnostic must not escape"), "verification_failed"),
])
def test_failure_requires_explicit_exact_retry(verifier, cache, monkeypatch, caplog, failure, state):
    _, pointer = cache
    calls = []
    original = runtime_cache.validate_generation

    def verify(*args, **kwargs):
        calls.append(args[1])
        if len(calls) == 1:
            raise failure
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    resolve(verifier)
    terminal(verifier)
    first = resolve(verifier)
    second = resolve(verifier)
    assert first.state == second.state == state
    assert first.verification == second.verification
    assert len(calls) == 1
    assert "private" not in first.verification.model_dump_json()
    assert "private" not in caplog.text
    assert verifier._thread.is_alive()
    with pytest.raises(VerificationConflict) as stale:
        verifier.retry("active", "0" * 64)
    assert stale.value.code == "cache_verification_changed"
    retried = verifier.retry("active", pointer.active.generation_id)
    assert retried.state == "verifying"
    assert terminal(verifier).state == "ready"
    assert resolve(verifier).state == "ready"
    assert len(calls) == 2
    with pytest.raises(VerificationConflict) as ready:
        verifier.retry("active", pointer.active.generation_id)
    assert ready.value.code == "cache_verification_not_retryable"


def test_corruption_is_not_timeout_or_retryable(verifier, cache, monkeypatch):
    def invalid(*args, **kwargs):
        raise manifest.CacheValidationError("bad checksum")

    monkeypatch.setattr(runtime_cache, "validate_generation", invalid)
    resolve(verifier)
    assert terminal(verifier).state == "invalid"
    assert resolve(verifier).state == "invalid"
    with pytest.raises(VerificationConflict):
        verifier.retry("active", cache[1].active.generation_id)


def test_unreviewed_component_never_becomes_public_activity(verifier, monkeypatch):
    def verify(*args, **kwargs):
        kwargs["progress"]("unreviewed", 1, 1, 0, 1)
        pytest.fail("unreviewed component was accepted")

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    resolve(verifier)
    assert terminal(verifier).state == "invalid"
    assert resolve(verifier).verification is None


def test_production_scan_uses_owned_verifier_not_synchronous_resolution(verifier, monkeypatch):
    monkeypatch.setattr(main, "cache_verifier", verifier)
    request, control, result = object(), object(), object()

    def execute(observed_request, observed_control, *, resolver):
        assert observed_request is request and observed_control is control
        assert resolver == verifier.resolve
        return result

    monkeypatch.setattr(main, "_execute_scan", execute)
    assert main._execute_runtime_scan(request, control) is result


@pytest.mark.parametrize("old_capture_failed", [False, True])
def test_old_concurrent_observation_cannot_cancel_new_task(cache, verifier, tmp_path, monkeypatch, old_capture_failed):
    root, first = cache
    second = add_generation(root, tmp_path, b"new-current")
    captured, release = threading.Event(), threading.Event()
    original = verifier._capture

    def capture(target):
        result = original(target)
        if threading.current_thread().name.startswith("old-reader") and not captured.is_set():
            captured.set()
            assert release.wait(5)
            if old_capture_failed:
                raise manifest.CacheValidationError("old missing pointer")
        return result

    monkeypatch.setattr(verifier, "_capture", capture)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="old-reader") as readers:
        old = readers.submit(resolve, verifier)
        try:
            assert captured.wait(5)
            manifest.activate_generation(root, second.generation_id, OPERATION_ID)
            resolve(verifier)
            current_task = terminal(verifier)
            assert current_task.reference.generation_id == second.generation_id
            release.set()
            result = old.result(timeout=5)
            assert result.state == "ready"
            assert result.generation.manifest.generation_id == second.generation_id
            assert verifier._tasks["active"] is current_task
            assert not current_task.cancel.is_set()
        finally:
            release.set()


def add_generation(cache_root, tmp_path, content):
    other = tmp_path / "other"
    candidate = _prepare_generation(other, content=content)
    destination_parent = cache_root / "generations"
    parent_mode = stat.S_IMODE(destination_parent.stat().st_mode)
    destination_parent.chmod(0o700)
    source = other / "generations" / candidate.generation_id
    source.parent.chmod(0o700)
    source.chmod(0o700)
    destination = source.rename(destination_parent / candidate.generation_id)
    destination.chmod(0o500)
    destination_parent.chmod(parent_mode)
    return candidate


def test_pointer_change_discards_inflight_result(cache, verifier, tmp_path, monkeypatch):
    root, first = cache
    second = add_generation(root, tmp_path, b"second")
    entered, release = threading.Event(), threading.Event()
    original = runtime_cache.validate_generation

    def verify(*args, **kwargs):
        if args[1] == first.active.generation_id:
            entered.set()
            assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        resolve(verifier)
        assert entered.wait(5)
        previous_task = verifier._tasks["active"]
        manifest.activate_generation(root, second.generation_id, OPERATION_ID)
        changed = resolve(verifier)
        assert changed.state == "verifying"
        assert changed.verification.generation_id == second.generation_id
        assert changed.generation is None and previous_task.cancel.is_set()
    finally:
        release.set()
    assert terminal(verifier).state == "ready"
    assert previous_task.state == "cancelled"
    assert previous_task.generation is None
    assert resolve(verifier).generation.manifest.generation_id == second.generation_id


def test_previous_good_verification_does_not_invalidate_ready_active(cache, verifier, tmp_path, monkeypatch):
    root, pointer = cache
    resolve(verifier)
    terminal(verifier)
    active_task = verifier._tasks["active"]
    # Adding another sealed tree and selecting only previous_good cannot
    # re-hash or make the already-verified active reference unavailable.
    previous = add_generation(root, tmp_path, b"previous")
    previous_ref = manifest.validate_generation(root, previous.generation_id).reference
    pointer = pointer.model_copy(update={"previous_good": previous_ref, "revision": pointer.revision + 1})
    manifest._atomic_write_json(root, "active.json", pointer.model_dump(mode="json"), manifest.MAX_ACTIVE_POINTER_BYTES)
    entered, release = threading.Event(), threading.Event()
    original = runtime_cache.validate_generation

    def verify(*args, **kwargs):
        assert args[1] == previous.generation_id
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        rollback = updater.evaluate_cache_rollback_eligibility(root,
            manifest.load_tool_lock(TOOLS_LOCK), manifest.load_rules_lock(RULES_LOCK),
            resolver=verifier.resolve_previous)
        assert entered.wait(5)
        assert rollback.eligible is False
        assert rollback.reason_code == "previous_generation_verifying"
        assert rollback.verification.target == "previous_good"
        assert rollback.target_generation == previous.generation_id
        assert resolve(verifier).state == "ready"
        assert verifier._tasks["active"] is active_task
    finally:
        release.set()
    assert terminal(verifier, "previous_good").state == "ready"
    # The independent rollback proof still goes through semantic admission.
    eligibility = updater.evaluate_cache_rollback_eligibility(root,
        manifest.load_tool_lock(TOOLS_LOCK), manifest.load_rules_lock(RULES_LOCK),
        resolver=verifier.resolve_previous)
    assert eligibility.eligible
    assert eligibility.verification is None
    assert verifier._tasks["active"] is active_task


@pytest.mark.parametrize("corrupt", [False, True])
def test_previous_lock_authority_is_distinct_from_payload_integrity(
    cache, verifier, tmp_path, monkeypatch, corrupt,
):
    root, pointer = cache
    resolve(verifier)
    terminal(verifier)
    active_task = verifier._tasks["active"]
    older_lock = tmp_path / "older-tools.json"
    older_lock.write_bytes(TOOLS_LOCK.read_bytes() + b"\n")
    with monkeypatch.context() as previous_source:
        previous_source.setattr(cache_fixtures, "TOOLS_LOCK", older_lock)
        previous = add_generation(root, tmp_path, b"previous")
    reference = manifest.validate_generation(root, previous.generation_id).reference
    pointer = pointer.model_copy(update={"previous_good": reference, "revision": pointer.revision + 1})
    manifest._atomic_write_json(root, "active.json", pointer.model_dump(mode="json"), manifest.MAX_ACTIVE_POINTER_BYTES)
    if corrupt:
        payload = root / "generations" / previous.generation_id / "bearer/rules/python.yml"
        payload.chmod(0o600)
        payload.write_bytes(b"tampered")
        payload.chmod(0o400)

    tools_lock, rules_lock = manifest.load_tool_lock(TOOLS_LOCK), manifest.load_rules_lock(RULES_LOCK)
    updater.evaluate_cache_rollback_eligibility(root, tools_lock, rules_lock, resolver=verifier.resolve_previous)
    terminal(verifier, "previous_good")
    eligibility = updater.evaluate_cache_rollback_eligibility(
        root, tools_lock, rules_lock, resolver=verifier.resolve_previous,
    )
    assert eligibility.eligible is False
    assert eligibility.target_generation == previous.generation_id
    assert eligibility.reason_code == ("previous_generation_invalid" if corrupt else "different_reviewed_locks")
    assert manifest.load_active_pointer(root) == pointer
    assert resolve(verifier).generation.reference == pointer.active
    assert verifier._tasks["active"] is active_task


def test_active_generation_still_requires_its_reviewed_authority(cache, verifier, tmp_path, monkeypatch):
    root, _ = cache
    older_lock = tmp_path / "older-tools.json"
    older_lock.write_bytes(TOOLS_LOCK.read_bytes() + b"\n")
    with monkeypatch.context() as previous_source:
        previous_source.setattr(cache_fixtures, "TOOLS_LOCK", older_lock)
        previous = add_generation(root, tmp_path, b"previous")
    pointer = manifest.activate_generation(root, previous.generation_id, OPERATION_ID)
    resolve(verifier)
    terminal(verifier)
    result = resolve(verifier)
    assert result.state == "invalid"
    assert result.generation is None
    assert manifest.load_active_pointer(root) == pointer


def test_reselected_cancelled_identity_requires_retry(cache, verifier, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def verify(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        raise runtime_cache._VerificationCancelled()

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        resolve(verifier)
        assert entered.wait(5)
        original = verifier._tasks["active"]
    finally:
        release.set()
    assert terminal(verifier).state == "cancelled"
    result = resolve(verifier)
    assert result.state == "verification_failed"
    assert result.verification.generation_id == cache[1].active.generation_id
    assert verifier._tasks["active"] is original
    assert resolve(verifier).verification == result.verification


def test_retry_during_shutdown_does_not_acknowledge_queued_work(cache, verifier, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def verify(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        kwargs["checkpoint"]()

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        resolve(verifier)
        assert entered.wait(5)
        # Hold the real worker until after shutdown has signalled cancellation.
        with ThreadPoolExecutor(max_workers=1) as callers:
            stopped = callers.submit(verifier.shutdown)
            assert verifier._tasks["active"].cancel.wait(5)
            with pytest.raises(VerificationConflict) as refused:
                verifier.retry("active", cache[1].active.generation_id)
            assert refused.value.code == "cache_verification_not_retryable"
            release.set()
            assert stopped.result(timeout=5)
    finally:
        release.set()


def test_generation_metadata_and_locks_invalidate_ready_proof(cache, verifier):
    root, pointer = cache
    resolve(verifier)
    terminal(verifier)
    original = verifier._tasks["active"]
    generation_path = root / "generations" / pointer.active.generation_id
    generation_path.chmod(0o700)
    try:
        assert resolve(verifier).state == "verifying"
        assert verifier._tasks["active"] is not original
        assert terminal(verifier).state == "invalid"
        with pytest.raises(manifest.CacheValidationError, match="locks changed"):
            verifier.resolve(root, tool_lock_sha256="0" * 64,
                rules_lock_sha256=manifest.load_rules_lock(RULES_LOCK).sha256)
    finally:
        generation_path.chmod(0o500)


def test_shutdown_cancels_verification_at_real_checkpoint(verifier, monkeypatch):
    entered = threading.Event()

    def verify(*args, **kwargs):
        entered.set()
        assert verifier._running.cancel.wait(5)
        kwargs["checkpoint"]()
        pytest.fail("cancelled validation continued")

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    resolve(verifier)
    assert entered.wait(5)
    assert verifier.shutdown()
    assert not verifier._thread.is_alive()
    assert verifier._tasks["active"].generation is None
    with pytest.raises(RuntimeError, match="outside"):
        resolve(verifier)


def test_pending_tools_and_private_http_routes_use_lifecycle_owner(cache, monkeypatch):
    root, pointer = cache
    previous = add_generation(root, root.parent, b"previous")
    previous_ref = manifest.validate_generation(root, previous.generation_id).reference
    pointer = pointer.model_copy(update={"previous_good": previous_ref, "revision": pointer.revision + 1})
    manifest._atomic_write_json(root, "active.json", pointer.model_dump(mode="json"), manifest.MAX_ACTIVE_POINTER_BYTES)
    entered, release = threading.Event(), threading.Event()
    original = runtime_cache.validate_generation

    def verify(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    monkeypatch.setattr(main.settings, "tool_cache_dir", str(root))
    monkeypatch.setattr(main.settings, "tool_lock_path", str(TOOLS_LOCK))
    monkeypatch.setattr(main.settings, "rules_lock_path", str(RULES_LOCK))
    monkeypatch.setattr(main.run_registry, "shutdown", lambda: True)
    with TestClient(main.app) as client:
        try:
            response = client.get("/tools")
            assert response.status_code == 200
            snapshot = response.json()
            assert snapshot["active_generation"] is None
            assert snapshot["cache_verification"]["state"] == "verifying"
            assert entered.wait(5)
            bearer = next(tool for tool in snapshot["tools"] if tool["id"] == "bearer")
            assert not bearer["runtime_ready"]
            assert bearer["readiness"]["rules"]["state"] == "verifying"
            assert root.as_posix() not in response.text
            rollback = client.get("/cache/rollback-eligibility")
            assert rollback.status_code == 200
            observation = rollback.json()["verification"]
            assert observation["target"] == "previous_good"
            assert observation["phase"] == "queued"
            assert {key: observation[key] for key in ("component_id", "bytes_verified", "bytes_total")} == {
                "component_id": None, "bytes_verified": None, "bytes_total": None,
            }
            body = {"target": "active", "expected_generation": pointer.active.generation_id}
            assert client.post("/cache/verification/retry", json=body).status_code == 202
            assert client.post("/cache/verification/retry", json={**body, "path": "/"}).status_code == 422
            conflict = client.post("/cache/verification/retry", json={**body, "expected_generation": "0" * 64})
            assert conflict.status_code == 409
            assert conflict.json()["detail"]["code"] == "cache_verification_changed"
        finally:
            release.set()
    assert main.cache_verifier is None


def test_deadline_is_owned_by_verification_not_status_requests(verifier, monkeypatch):
    from types import SimpleNamespace

    entered, advance = threading.Event(), threading.Event()
    now = [100.0]
    monkeypatch.setattr(runtime_cache, "time", SimpleNamespace(monotonic=lambda: now[0]))

    def verify(*args, **kwargs):
        entered.set()
        assert advance.wait(5)
        now[0] += 901
        kwargs["checkpoint"]()
        pytest.fail("expired validation continued")

    monkeypatch.setattr(runtime_cache, "validate_generation", verify)
    try:
        resolve(verifier)
        assert entered.wait(5)
        assert resolve(verifier).state == "verifying"
        advance.set()
        assert terminal(verifier).state == "timed_out"
        assert resolve(verifier).state == "verification_timeout"
    finally:
        advance.set()


@pytest.mark.parametrize("changes", [
    {"component_id": "unreviewed"}, {"bytes_verified": 2, "bytes_total": 1},
    {"bytes_total": 1}, {"started_at": datetime(2026, 1, 1)},
    {"last_activity_at": datetime(2025, 1, 1, tzinfo=UTC)},
])
def test_observation_refuses_unsafe_or_misleading_activity(changes):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError):
        manifest.CacheVerification(**{
            "state": "verifying", "target": "active", "generation_id": "a" * 64,
            "phase": "queued", "started_at": now, "last_activity_at": now, **changes,
        })


def test_runtime_failure_log_has_bounded_state_and_no_exception_content(verifier, monkeypatch, caplog):
    def fail(*args, **kwargs):
        kwargs['progress']('grype-db', 1, 1, 0, 10)
        raise OSError('private-project-or-capability-must-not-leak')

    monkeypatch.setattr(runtime_cache, 'validate_generation', fail)
    resolve(verifier)
    assert terminal(verifier).state == 'failed'
    assert 'scanner runtime cache verification failed target=active component_id=grype-db' in caplog.text
    assert 'state=failed phase=validating elapsed_ms=' in caplog.text
    assert 'private-project-or-capability-must-not-leak' not in caplog.text
    assert str(verifier.cache_root) not in caplog.text
