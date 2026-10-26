from __future__ import annotations

from kodesec_scanner.preparation_budget import issue_budget

import hashlib
import io
import json
import os
import stat
import tarfile
import time
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[3]
os.environ.setdefault("KODESEC_TOOL_LOCK_PATH", str(ROOT / "scanner-tools.lock.json"))
os.environ.setdefault("KODESEC_RULES_LOCK_PATH", str(ROOT / "scanner-rules.lock.json"))

from kodesec_scanner import updater
from kodesec_scanner.cache_manifest import load_rules_lock, load_tool_lock
from kodesec_scanner.settings import UpdaterSettings
from kodesec_scanner.updater import (
    CatalogOperationResult,
    LockedLifecycleHandlers,
    OperationActivity,
    OperationContext,
    OperationRequest,
    OperationStateError,
    OperationStore,
    canonical_canary_output_sha256,
    download_locked_asset,
    extract_locked_tar_gz,
    operation_request_digest,
    prepare_cache_layout,
)
from kodesec_scanner.updater_main import create_app


TOOLS = load_tool_lock(ROOT / "scanner-tools.lock.json")
RULES = load_rules_lock(ROOT / "scanner-rules.lock.json")


def _async_test_deadline_seconds() -> float:
    raw = os.environ.get("KODESEC_TEST_ASYNC_DEADLINE_SECONDS", "5")
    try:
        seconds = float(raw)
    except ValueError as exc:
        raise RuntimeError("KODESEC_TEST_ASYNC_DEADLINE_SECONDS must be numeric") from exc
    if not 0.5 <= seconds <= 60:
        raise RuntimeError(
            "KODESEC_TEST_ASYNC_DEADLINE_SECONDS must be between 0.5 and 60"
        )
    return seconds


def _request(kind: str = "catalog_check", components: list[str] | None = None, *, issued_at=None) -> OperationRequest:
    requested = [] if components is None else components
    budget = issue_budget(now=issued_at) if kind != "cache_rollback" else None
    version = 2 if budget is not None else 1
    return OperationRequest(
        schema_version=version,
        preparation_budget=budget,
        operation_id=uuid4(),
        request_digest=operation_request_digest(
            schema_version=version,
        preparation_budget=budget,
            kind=kind,  # type: ignore[arg-type]
            requested_components=requested,
        ),
        kind=kind,  # type: ignore[arg-type]
        requested_components=requested,
        attempt=1,
        max_attempts=3,
    )


def _settings(tmp_path: Path) -> UpdaterSettings:
    tmp_path.mkdir(parents=True, exist_ok=True)
    scratch = tmp_path / "scratch"
    tools = tmp_path / "tools.json"
    rules = tmp_path / "rules.json"
    tools.write_bytes((ROOT / "scanner-tools.lock.json").read_bytes())
    rules.write_bytes((ROOT / "scanner-rules.lock.json").read_bytes())
    return UpdaterSettings(
        KODESEC_TOOL_CACHE_DIR=str(tmp_path / "cache"),
        KODESEC_UPDATER_SCRATCH_DIR=str(scratch),
        KODESEC_TOOL_LOCK_PATH=str(tools),
        KODESEC_RULES_LOCK_PATH=str(rules),
    )


def test_async_test_deadline_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KODESEC_TEST_ASYNC_DEADLINE_SECONDS", raising=False)
    assert _async_test_deadline_seconds() == 5
    monkeypatch.setenv("KODESEC_TEST_ASYNC_DEADLINE_SECONDS", "10")
    assert _async_test_deadline_seconds() == 10
    monkeypatch.setenv("KODESEC_TEST_ASYNC_DEADLINE_SECONDS", "invalid")
    with pytest.raises(RuntimeError, match="must be numeric"):
        _async_test_deadline_seconds()
    monkeypatch.setenv("KODESEC_TEST_ASYNC_DEADLINE_SECONDS", "61")
    with pytest.raises(RuntimeError, match="between 0.5 and 60"):
        _async_test_deadline_seconds()


def test_wire_digest_exactly_matches_api_compact_json() -> None:
    payload = {
        "kind": "cache_update",
        "requested_components": ["bearer-rules"],
        "schema_version": 1,
    }
    expected = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert operation_request_digest(**payload) == expected


def test_runtime_boundary_normalizes_only_owned_real_cache_directories(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir(mode=0o755)
    generations = cache_root / "generations"
    staging = cache_root / "staging"
    tombstones = cache_root / "tombstones"
    generations.mkdir(mode=0o755)
    staging.mkdir(mode=0o750)
    tombstones.mkdir(mode=0o755)

    prepare_cache_layout(cache_root)

    assert stat.S_IMODE(cache_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(generations.stat().st_mode) == 0o700
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700
    assert stat.S_IMODE(tombstones.stat().st_mode) == 0o700


def test_runtime_boundary_never_chmods_wrong_owner_symlink_or_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_owner = tmp_path / "wrong-owner"
    wrong_owner.mkdir(mode=0o755)
    actual_uid = os.getuid()
    monkeypatch.setattr(updater.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(Exception, match="not an owner-owned real directory"):
        prepare_cache_layout(wrong_owner)
    assert stat.S_IMODE(wrong_owner.stat().st_mode) == 0o755
    monkeypatch.undo()

    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(Exception, match="not an owner-owned real directory"):
        prepare_cache_layout(alias)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755

    mounted = tmp_path / "mounted"
    mounted.mkdir(mode=0o755)
    monkeypatch.setattr(updater, "_cache_layout_is_mount", lambda path: path == mounted)
    with pytest.raises(Exception, match="mount does not have the required private mode"):
        prepare_cache_layout(mounted)
    assert stat.S_IMODE(mounted.stat().st_mode) == 0o755


def test_runtime_boundary_never_chmods_a_nested_mount_or_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir(mode=0o700)
    generations = cache_root / "generations"
    generations.mkdir(mode=0o755)
    staging = cache_root / "staging"
    staging.mkdir(mode=0o700)
    monkeypatch.setattr(
        updater,
        "_cache_layout_is_mount",
        lambda path: path == generations,
    )

    with pytest.raises(Exception, match="child mount"):
        prepare_cache_layout(cache_root)

    assert stat.S_IMODE(generations.stat().st_mode) == 0o755
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700

    generations.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    generations.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(updater, "_cache_layout_is_mount", lambda _path: False)
    with pytest.raises(Exception, match="unsafe owned directory"):
        prepare_cache_layout(cache_root)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755


def test_component_activity_is_bounded_and_persisted(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request("cache_update", ["grype-db"])
    store.create_or_get(request)
    context = OperationContext(request=request, store=store)

    running = context.progress(
        "downloading",
        component_id="grype-db",
        component_index=1,
        component_total=1,
    )
    assert running.activity is not None
    assert running.activity.component_id == "grype-db"

    observed = context.byte_progress(5, 10, force=True)
    assert observed.activity is not None
    assert observed.activity.bytes_completed == 5
    assert observed.activity.bytes_total == 10
    assert observed.last_activity_at == observed.updated_at
    assert store.load(request.operation_id).activity == observed.activity


def test_component_activity_writes_are_rate_limited(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    from datetime import datetime, timezone
    request = _request("cache_update", ["grype-db"], issued_at=datetime(2026, 8, 24, 12, tzinfo=timezone.utc))
    store.create_or_get(request, now="2026-08-24T12:00:00Z")
    initial = store.transition(
        request.operation_id,
        status="running",
        stage="downloading",
        activity=OperationActivity(
            component_id="grype-db",
            component_index=1,
            component_total=1,
        ),
        now="2026-08-24T12:00:01Z",
    )
    assert initial.activity is not None
    suppressed = store.update_activity(
        request.operation_id,
        request_digest=request.request_digest,
        activity=initial.activity.model_copy(
            update={"bytes_completed": 1, "bytes_total": 10}
        ),
        now="2026-08-24T12:00:02Z",
    )
    assert suppressed == initial

    persisted = store.update_activity(
        request.operation_id,
        request_digest=request.request_digest,
        activity=initial.activity.model_copy(
            update={"bytes_completed": 2, "bytes_total": 10}
        ),
        now="2026-08-24T12:00:03Z",
    )
    assert persisted.activity is not None
    assert persisted.activity.bytes_completed == 2
    assert persisted.updated_at == "2026-08-24T12:00:03Z"


def test_http_create_get_delete_and_private_boundary(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), allowed_hosts=frozenset({"testserver"}))
    request = _request()
    with TestClient(app) as client:
        assert client.get("/healthz").json()["preparation_budget_schema_version"] == 4
        started = client.post("/operations", json=request.model_dump(mode="json"))
        assert started.status_code in {200, 202}
        digest = request.request_digest
        terminal = None
        deadline = time.monotonic() + _async_test_deadline_seconds()
        while True:
            observed = client.get(
                f"/operations/{request.operation_id}",
                headers={"X-KodeSec-Request-Digest": digest},
            )
            assert observed.status_code == 200
            terminal = observed.json()
            if terminal["status"] in {"completed", "failed", "cancelled"}:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.01, remaining))
        assert terminal is not None
        assert terminal["status"] == "completed"
        assert terminal["result"]["kind"] == "catalog"
        assert client.get(f"/operations/{request.operation_id}").status_code == 422
        assert client.get(
            f"/operations/{request.operation_id}",
            headers={"X-KodeSec-Request-Digest": "0" * 64},
        ).status_code == 409
        replay = client.post("/operations", json=request.model_dump(mode="json"))
        assert replay.status_code == 200
        cancelled = client.delete(
            f"/operations/{request.operation_id}",
            headers={"X-KodeSec-Request-Digest": digest},
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "completed"

    rejected = create_app(_settings(tmp_path / "other"), allowed_hosts=frozenset({"fixed:8092"}))
    with TestClient(rejected) as client:
        assert client.get("/healthz").status_code == 400


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, url: str) -> None:
        super().__init__(payload)
        self._url = url
        self.headers = {}

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def test_locked_download_checks_exact_size_digest_and_redirect(tmp_path: Path) -> None:
    payload = b"reviewed archive"
    store = OperationStore(tmp_path / "cache")
    request = _request("cache_update", ["bearer-rules"])
    store.create_or_get(request)
    context = OperationContext(request=request, store=store)

    def opener(request_object: object, timeout: float) -> _Response:
        del timeout
        return _Response(payload, request_object.full_url)  # type: ignore[attr-defined]

    destination = tmp_path / "asset.tar.gz"
    download_locked_asset(
        url="https://example.invalid/asset.tar.gz",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        expected_size=len(payload),
        destination=destination,
        context=context,
        timeout_seconds=1,
        opener=opener,
    )
    assert destination.read_bytes() == payload

    def redirect(_request: object, _timeout: float) -> _Response:
        return _Response(payload, "https://other.invalid/asset.tar.gz")

    with pytest.raises(Exception, match="unapproved redirect"):
        download_locked_asset(
            url="https://example.invalid/asset.tar.gz",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size=len(payload),
            destination=tmp_path / "redirect.tar.gz",
            context=context,
            timeout_seconds=1,
            opener=redirect,
        )


def test_archive_extraction_rejects_traversal_and_links(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "cache")
    request = _request("cache_update", ["bearer-rules"])
    store.create_or_get(request)
    context = OperationContext(request=request, store=store)
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("../escape.yml")
        content = b"id: unsafe\n"
        member.size = len(content)
        bundle.addfile(member, io.BytesIO(content))
    with pytest.raises(Exception, match="unsafe path"):
        extract_locked_tar_gz(archive, tmp_path / "out", context)


def test_unattested_rule_canary_fails_closed_before_promotion(tmp_path: Path) -> None:
    payload = json.loads((ROOT / "scanner-rules.lock.json").read_text(encoding="utf-8"))
    opengrep = next(
        item for item in payload["rule_sets"] if item["id"] == "opengrep-reviewed-rules"
    )
    opengrep["canaries"][0].update(
        {
            "state": "unattested",
            "output_sha256": None,
            "reason": "test-only missing runtime evidence",
        }
    )
    rules_path = tmp_path / "rules-unattested.json"
    rules_path.write_text(json.dumps(payload), encoding="utf-8")
    handlers = LockedLifecycleHandlers(
        tools=TOOLS,
        rules=load_rules_lock(rules_path),
        cache_root=tmp_path / "cache",
        scratch_root=tmp_path / "scratch",
    )
    store = OperationStore(tmp_path / "cache")
    request = _request("cache_update", ["opengrep-reviewed-rules"])
    store.create_or_get(request)
    with pytest.raises(Exception, match="canary evidence is not verified"):
        handlers.cache_update(OperationContext(request=request, store=store))


def test_canonical_canary_digest_binds_semantics() -> None:
    first = canonical_canary_output_sha256(
        canary_id="positive",
        fixture_sha256="1" * 64,
        exit_code=0,
        result_count=1,
        rule_ids=["rules.one"],
    )
    second = canonical_canary_output_sha256(
        canary_id="positive",
        fixture_sha256="1" * 64,
        exit_code=0,
        result_count=0,
        rule_ids=[],
    )
    assert first != second
