from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from kodesec_api import main as main_module
from kodesec_api.app import create_app
from kodesec_api.db import Runtime, initialize_database
from kodesec_api.models import Job, Scan
from kodesec_api.schemas import SourceSnapshotCreate, ScanSourceSnapshotOut
from kodesec_api.schemas import SourceSnapshotFile, SourceSnapshotLimitsOut
from kodesec_api.jobs.repository import _redact_job_document
from kodesec_api.settings import Settings
from kodesec_api.source_snapshots import (
    SourceSnapshotError,
    delete_source_snapshots,
    store_source_snapshot,
    inspect_source_snapshot,
    validate_source_snapshot,
)


ORIGIN = "http://127.0.0.1:8080"
SOURCE_ID = "1" * 64


def _file(path: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


def _payload() -> SourceSnapshotCreate:
    return SourceSnapshotCreate.model_validate(
        {
            "source_id": SOURCE_ID,
            "name": "windows-fixture",
            "files": [
                _file("app.py", b"print('fixture')\n"),
                _file("k8s/deployment.yaml", b"kind: Deployment\n"),
            ],
        }
    )


@pytest.mark.parametrize("size", [2 * 1024 * 1024, 5_800_000, 8 * 1024 * 1024])
def test_snapshot_large_asset_is_sealed_revalidated_and_reused_without_byte_changes(tmp_path, size):
    content = b"\x89PNG\r\n\x1a\n" + b"x" * (size - 8)
    payload = SourceSnapshotCreate(source_id=SOURCE_ID, name="asset-boundary", files=[_file("docs/image.png", content)])
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    digest, source, count, total = store_source_snapshot(settings, payload)
    assert (count, total) == (1, size)
    assert (source / "docs/image.png").read_bytes() == content
    assert validate_source_snapshot(settings, digest, source_id=SOURCE_ID) == source
    assert store_source_snapshot(settings, payload) == (digest, source, count, total)
    assert delete_source_snapshots(settings, SOURCE_ID) == 1


def test_snapshot_transfer_limits_are_typed_and_do_not_expand_analysis_or_total():
    limits = SourceSnapshotLimitsOut().model_dump()
    assert limits == {
        "schema_version": 1, "max_file_bytes": 8_388_608, "max_total_bytes": 67_108_864,
        "max_files": 5000, "max_encoded_request_bytes": 117_440_512,
        "eligible_source_max_file_bytes": 1_048_576,
    }
    with pytest.raises(ValueError):
        SourceSnapshotFile.model_validate(_file("docs/image.png", b"x" * (8 * 1024 * 1024 + 1)))
    with pytest.raises(ValueError, match="64 MiB"):
        SourceSnapshotCreate(source_id=SOURCE_ID, name="too-large", files=[
            _file(f"asset-{index}.png", b"x" * (8 * 1024 * 1024)) for index in range(9)
        ])


def test_health_exposes_transfer_contract_even_while_services_are_unavailable(monkeypatch):
    class UnavailableDatabase:
        def execute(self, _statement):
            raise RuntimeError("fixture database unavailable")

        def rollback(self):
            pass

    class UnavailableScanner:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def get(self, _url):
            return SimpleNamespace(status_code=503)

    monkeypatch.setattr(main_module.httpx, "Client", UnavailableScanner)
    health = main_module.healthz(SimpleNamespace(settings=SimpleNamespace(scanner_url="http://scanner:8091")),
        UnavailableDatabase())
    assert health["ok"] is False
    assert health["source_snapshot_limits"] == SourceSnapshotLimitsOut().model_dump()


def _empty_directory_payload() -> SourceSnapshotCreate:
    return SourceSnapshotCreate.model_validate(
        {
            "source_id": SOURCE_ID,
            "name": "windows-empty-directory",
            "directory_scope": "services/empty",
            "files": [],
        }
    )


def test_snapshot_storage_is_bounded_source_bound_and_detects_tampering(tmp_path: Path) -> None:
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    digest, source, file_count, total_bytes = store_source_snapshot(settings, _payload())

    assert source == tmp_path / "source-snapshots" / "generations" / digest / "source"
    assert file_count == 2
    assert total_bytes == len(b"print('fixture')\nkind: Deployment\n")
    assert validate_source_snapshot(settings, digest, source_id=SOURCE_ID) == source
    with pytest.raises(SourceSnapshotError, match="does not match the selected Windows source"):
        validate_source_snapshot(settings, digest, source_id="2" * 64)

    (source / "app.py").write_bytes(b"changed\n")
    with pytest.raises(SourceSnapshotError, match="sealed manifest"):
        validate_source_snapshot(settings, digest, source_id=SOURCE_ID)


def test_empty_directory_scope_is_sealed_materialized_and_rejects_siblings(tmp_path: Path) -> None:
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    digest, source, file_count, total_bytes = store_source_snapshot(
        settings,
        _empty_directory_payload(),
    )

    selected = source / "services" / "empty"
    assert selected.is_dir()
    assert list(selected.iterdir()) == []
    assert not (source / "sibling").exists()
    assert file_count == 0
    assert total_bytes == 0
    other = SourceSnapshotCreate.model_validate(
        {
            "source_id": SOURCE_ID,
            "name": "windows-other-empty-directory",
            "directory_scope": "services/another-empty",
            "files": [],
        }
    )
    other_digest, other_source, _, _ = store_source_snapshot(settings, other)
    assert other_digest != digest
    assert (other_source / "services" / "another-empty").is_dir()
    assert validate_source_snapshot(
        settings,
        digest,
        source_id=SOURCE_ID,
        scan_target=("services/empty", "directory"),
    ) == source
    with pytest.raises(SourceSnapshotError, match="exact selected directory scope"):
        validate_source_snapshot(
            settings,
            digest,
            source_id=SOURCE_ID,
            scan_target=("services", "directory"),
        )
    with pytest.raises(SourceSnapshotError, match="scan target is invalid"):
        validate_source_snapshot(
            settings,
            digest,
            source_id=SOURCE_ID,
            scan_target=("../outside", "directory"),
        )
    (source / "sibling").mkdir()
    with pytest.raises(SourceSnapshotError, match="sealed manifest"):
        validate_source_snapshot(settings, digest, source_id=SOURCE_ID)


def test_snapshot_cleanup_removes_only_the_deleted_source_generations(tmp_path: Path) -> None:
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    first_digest, first_source, _, _ = store_source_snapshot(settings, _payload())
    other = _payload().model_copy(update={"source_id": "2" * 64})
    other_digest, other_source, _, _ = store_source_snapshot(settings, other)

    assert delete_source_snapshots(settings, SOURCE_ID) == 1
    assert not first_source.parent.exists()
    assert validate_source_snapshot(settings, other_digest, source_id="2" * 64) == other_source
    assert first_digest != other_digest


def test_snapshot_validation_rejects_a_replaced_manifest_link(tmp_path: Path) -> None:
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    digest, source, _, _ = store_source_snapshot(settings, _payload())
    manifest = source.parent / "manifest.json"
    outside = tmp_path / "outside-manifest.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    try:
        manifest.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SourceSnapshotError, match="manifest is unsafe"):
        validate_source_snapshot(settings, digest, source_id=SOURCE_ID)


def test_snapshot_schema_rejects_traversal_duplicates_and_digest_substitution(
    tmp_path: Path,
) -> None:
    valid = _file("app.py", b"print('fixture')\n")
    with pytest.raises(ValueError, match="canonical project-relative"):
        SourceSnapshotCreate.model_validate(
            {"source_id": SOURCE_ID, "name": "fixture", "files": [valid | {"path": "../app.py"}]}
        )
    with pytest.raises(ValueError, match="unique and sorted"):
        SourceSnapshotCreate.model_validate(
            {"source_id": SOURCE_ID, "name": "fixture", "files": [valid, valid]}
        )
    with pytest.raises(ValueError, match="canonical project-relative"):
        SourceSnapshotCreate.model_validate(
            {
                "source_id": SOURCE_ID,
                "name": "fixture",
                "directory_scope": "../outside",
                "files": [],
            }
        )
    with pytest.raises(ValueError, match="inside directory_scope"):
        SourceSnapshotCreate.model_validate(
            {
                "source_id": SOURCE_ID,
                "name": "fixture",
                "directory_scope": "services/api",
                "files": [valid],
            }
        )
    with pytest.raises(SourceSnapshotError, match="changed before admission"):
        store_source_snapshot(
            SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots")),
            SourceSnapshotCreate.model_validate(
                {
                    "source_id": SOURCE_ID,
                    "name": "fixture",
                    "files": [valid | {"sha256": "3" * 64}],
                }
            ),
        )


@pytest.fixture()
def snapshot_client(postgres_engine, tmp_path: Path):
    initialize_database(postgres_engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL=str(postgres_engine.url),
        KODESEC_INSTALLATION_SECRET="i" * 48,
        KODESEC_BOOTSTRAP_TOKEN="b" * 48,
        KODESEC_ADVISOR_GRANT_SECRET="g" * 48,
        KODESEC_CONTROL_ORIGINS=ORIGIN,
        KODESEC_ALLOWED_ROOTS="/workspaces",
        KODESEC_ARTIFACT_DIR=str(tmp_path / "artifacts"),
        KODESEC_SOURCE_SNAPSHOT_DIR=str(tmp_path / "source-snapshots"),
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
    )
    runtime = Runtime.create(settings, engine=postgres_engine)
    with TestClient(create_app(runtime_override=runtime), base_url=ORIGIN) as client:
        yield client


def _browser_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/v1/auth/bootstrap",
        headers={"Origin": ORIGIN},
        json={"bootstrap_token": "b" * 48},
    )
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def test_snapshot_route_binds_project_digest_and_scan_job(
    snapshot_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = _browser_headers(snapshot_client)
    payload = _payload().model_dump(mode="json")
    admitted = snapshot_client.post("/v1/source-snapshots", headers=headers, json=payload)
    assert admitted.status_code == 201, admitted.text
    receipt = admitted.json()
    assert receipt["project"]["repo_path"] == f"/source-snapshots/native-windows/{SOURCE_ID}"
    assert receipt["directory_scope"] is None
    assert receipt["file_count"] == 2
    assert len(receipt["snapshot_digest"]) == 64

    missing = snapshot_client.post(
        "/v1/scans",
        headers=headers | {"Idempotency-Key": "snapshot-missing-digest"},
        json={"project_id": receipt["project"]["id"], "mode": "full"},
    )
    assert missing.status_code == 409
    assert missing.json()["detail"]["code"] == "source_snapshot_required"

    monkeypatch.setattr(
        main_module,
        "_scanner_preflight",
        lambda *_args: {
            "revision": "4" * 64,
            "enabled_tool_ids": ["gitleaks"],
            "ready_tool_ids": ["gitleaks"],
            "blocked_tools": [],
            "required_component_ids": [],
            "recommended_action": "scan",
            "preparation_available": True,
        },
    )
    created = snapshot_client.post(
        "/v1/scans",
        headers=headers | {"Idempotency-Key": "snapshot-bound-scan"},
        json={
            "project_id": receipt["project"]["id"],
            "mode": "full",
            "source_snapshot_digest": receipt["snapshot_digest"],
        },
    )
    assert created.status_code == 202, created.text
    with snapshot_client.app.state.runtime.session_factory() as db:
        job = db.get(Job, created.json()["job_id"])
        assert job is not None
        assert job.payload["source_snapshot_digest"] == receipt["snapshot_digest"]
        assert "content_base64" not in json.dumps(job.payload)
    observed = snapshot_client.get(f"/v1/scans/{created.json()['id']}")
    assert observed.status_code == 200
    assert observed.json()["source_snapshot"] == created.json()["source_snapshot"]
    assert observed.json()["source_snapshot"]["snapshot_digest"] == receipt["snapshot_digest"]
    assert observed.json()["source_snapshot"]["file_count"] == 2
    assert observed.json()["job_id"] == created.json()["job_id"]


def test_native_scan_provenance_is_bound_body_free_and_refuses_corrupt_history(tmp_path: Path) -> None:
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    payloads = [
        _payload(),
        SourceSnapshotCreate.model_validate({
            "source_id": SOURCE_ID, "name": "nested", "directory_scope": "k8s",
            "files": [_file("k8s/deployment.yaml", b"kind: Deployment\n")],
        }),
        SourceSnapshotCreate.model_validate({
            "source_id": SOURCE_ID, "name": "file",
            "files": [_file("app.py", b"print('fixture')\n")],
        }),
    ]
    cases = [(None, None), ("k8s", "directory"), ("app.py", "file")]
    receipts = []
    for index, (payload, target) in enumerate(zip(payloads, cases, strict=True), 1):
        digest, source, count, size = store_source_snapshot(settings, payload)
        inspected = inspect_source_snapshot(settings, digest, source_id=SOURCE_ID, scan_target=target)
        assert inspected.source == source
        receipt = ScanSourceSnapshotOut(
            source_id=inspected.source_id, snapshot_digest=inspected.snapshot_digest,
            directory_scope=inspected.directory_scope, target_path=target[0], target_kind=target[1],
            file_count=inspected.file_count, total_bytes=inspected.total_bytes,
        ).model_dump(mode="json")
        assert (receipt["file_count"], receipt["total_bytes"]) == (count, size)
        job_payload = _redact_job_document({
            "scan_id": index, "project_id": 7, "target_path": target[0], "target_kind": target[1],
            "source_snapshot_digest": digest, "source_snapshot": receipt,
            "advisor": {"password": "must-not-leak"},
        })
        assert job_payload["source_snapshot"] == receipt
        scan = Scan(id=index, project_id=7, mode="full", status="pending", gate_reasons=[], scanner_summary={})
        job = Job(id=index + 100, scan_id=index, kind="scan", payload=job_payload, revision=1)
        projected = main_module._scan_to_out(scan, job)
        assert projected["source_snapshot"] == receipt
        assert "must-not-leak" not in json.dumps(projected, default=str)
        assert set(receipt) == {
            "kind", "source_id", "snapshot_digest", "directory_scope", "target_path",
            "target_kind", "file_count", "total_bytes",
        }
        for field, bad in [("snapshot_digest", "2" * 64), ("target_path", "wrong.py"),
                           ("file_count", True), ("total_bytes", -1), ("unexpected", "secret")]:
            job.payload = {**job_payload, "source_snapshot": {**receipt, field: bad}}
            assert main_module._scan_to_out(scan, job)["source_snapshot"] is None
        job.payload = job_payload
        job.payload = {**job_payload, "project_id": 8}
        assert main_module._scan_to_out(scan, job)["source_snapshot"] is None
        for identity in ("scan_id", "project_id"):
            job.payload = {**job_payload, identity: True}
            assert main_module._scan_to_out(scan, job)["source_snapshot"] is None
        job.payload = job_payload
        job.scan_id = index + 1
        assert main_module._scan_to_out(scan, job)["source_snapshot"] is None
        receipts.append(receipt)
    assert len({item["snapshot_digest"] for item in receipts}) == 3
    assert main_module._scan_to_out(scan)["source_snapshot"] is None
    unsafe = {**receipts[2], "target_path": "ghp_abcdefghijk.py"}
    assert _redact_job_document({"source_snapshot": unsafe})["source_snapshot"] == "[REDACTED]"


def test_snapshot_route_rejects_a_scan_that_broadens_an_empty_directory_scope(
    snapshot_client: TestClient,
) -> None:
    headers = _browser_headers(snapshot_client)
    admitted = snapshot_client.post(
        "/v1/source-snapshots",
        headers=headers,
        json=_empty_directory_payload().model_dump(mode="json"),
    )
    assert admitted.status_code == 201, admitted.text
    receipt = admitted.json()
    assert receipt["directory_scope"] == "services/empty"
    assert receipt["file_count"] == 0

    broadened = snapshot_client.post(
        "/v1/scans",
        headers=headers | {"Idempotency-Key": "snapshot-broadened-directory"},
        json={
            "project_id": receipt["project"]["id"],
            "mode": "full",
            "target_path": "services",
            "target_kind": "directory",
            "source_snapshot_digest": receipt["snapshot_digest"],
        },
    )
    assert broadened.status_code == 422, broadened.text
    assert broadened.json()["detail"]["code"] == "source_snapshot_invalid"
