from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import anyio
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import StaticPool

from kodesec_api.artifact_boundary import (
    ARTIFACT_BOUNDARY_MARKER,
    MAX_PUBLISHABLE_SBOM_BYTES,
    ArtifactBoundaryError,
    admit_scan_artifacts,
    delete_scan_artifact_tree,
    enforce_artifact_publication_boundary,
    prepare_artifact_download,
)
from kodesec_api.db import Base, Runtime
from kodesec_api.main import download_artifact, open_artifact
from kodesec_api.models import Project, RuntimeConfig, Scan, ScanArtifact
from kodesec_api.redaction import REDACTED
from kodesec_api.settings import Settings


def _runtime(artifact_dir: Path) -> Runtime:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return Runtime.create(
        Settings(_env_file=None, KODESEC_ARTIFACT_DIR=str(artifact_dir)),
        engine=engine,
    )


def _scan(runtime: Runtime, *, name: str = "fixture") -> int:
    with runtime.session_factory() as db:
        project = Project(name=name, repo_path=f"/workspace/{name}", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.commit()
        return scan.id


def _declared_syft_sbom(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "scanner": "syft",
        "artifact_type": "sbom",
        "format": "cyclonedx-json",
        "path": str(path),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_startup_revalidates_attested_rows_and_keeps_only_sanitized_sbom(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    tool_dir = artifact_dir / "scans" / "1" / "syft"
    raw_dir = artifact_dir / "scans" / "1" / "gitleaks"
    tool_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)
    sbom = tool_dir / "syft.cyclonedx.json"
    raw = raw_dir / "gitleaks.sarif"
    malformed = tool_dir / "malformed.json"
    unattested = tool_dir / "unattested.json"
    orphan = raw_dir / "crash-left.stdout.txt"
    fixture = "fixture-credential-not-valid"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "password": fixture, "metadata": {"safe": "context"}}), encoding="utf-8")
    raw.write_text(json.dumps({"authorization": f"Bearer {fixture}"}), encoding="utf-8")
    malformed.write_text("{not-json", encoding="utf-8")
    unattested.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    orphan.write_text(f"password={fixture}", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside remains", encoding="utf-8")
    escaped = tmp_path / "escaped.txt"
    escaped.write_text("escaped remains", encoding="utf-8")
    symlink = artifact_dir / "outside-link"
    root_sentinel = artifact_dir / "operator-note.txt"
    root_sentinel.write_text("not scanner-owned", encoding="utf-8")
    try:
        symlink.symlink_to(outside)
    except OSError:
        symlink = None

    runtime = _runtime(artifact_dir)
    with runtime.session_factory() as db:
        project = Project(name="fixture", repo_path="/workspace/fixture", default_branch="main")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, mode="full", status="completed", scanner_summary={}, gate_reasons=[])
        db.add(scan)
        db.flush()
        for path, scanner, kind, fmt in (
            (sbom, "syft", "sbom", "cyclonedx-json"),
            (raw, "gitleaks", "findings", "sarif"),
            (malformed, "syft", "sbom", "cyclonedx-json"),
        ):
            db.add(
                ScanArtifact(
                    scan_id=scan.id,
                    scanner=scanner,
                    artifact_type=kind,
                    format=fmt,
                    path=str(path),
                    size_bytes=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        db.add(
            ScanArtifact(
                scan_id=scan.id,
                scanner="syft",
                artifact_type="sbom",
                format="cyclonedx-json",
                path=str(unattested),
                size_bytes=unattested.stat().st_size,
                sha256="0" * 64,
            )
        )
        db.add(
            ScanArtifact(
                scan_id=scan.id,
                scanner="fixture",
                artifact_type="log",
                format="text",
                path=str(artifact_dir / ".." / escaped.name),
                size_bytes=escaped.stat().st_size,
                sha256=hashlib.sha256(escaped.read_bytes()).hexdigest(),
            )
        )
        db.commit()

    assert enforce_artifact_publication_boundary(runtime) is True
    rendered = sbom.read_text(encoding="utf-8")
    assert fixture not in rendered
    assert REDACTED in rendered
    assert not raw.exists()
    assert not malformed.exists()
    assert not unattested.exists()
    assert not orphan.exists()
    assert outside.read_text(encoding="utf-8") == "outside remains"
    assert escaped.read_text(encoding="utf-8") == "escaped remains"
    assert root_sentinel.read_text(encoding="utf-8") == "not scanner-owned"
    if symlink is not None:
        assert symlink.is_symlink()

    with runtime.session_factory() as db:
        artifacts = list(db.scalars(select(ScanArtifact)))
        assert len(artifacts) == 1
        assert artifacts[0].path == str(sbom.resolve())
        assert artifacts[0].size_bytes == sbom.stat().st_size
        assert artifacts[0].sha256 == hashlib.sha256(sbom.read_bytes()).hexdigest()
        assert db.scalar(select(func.count(RuntimeConfig.key)).where(RuntimeConfig.key == ARTIFACT_BOUNDARY_MARKER)) == 1
    # Enforcement runs on every startup so a crash-left atomic temporary file
    # cannot survive merely because the startup marker already exists.
    crash_left = sbom.parent / ".syft.crash-left.json"
    crash_left.write_text(f"password={fixture}", encoding="utf-8")
    before_restart = sbom.stat()
    assert enforce_artifact_publication_boundary(runtime) is False
    assert not crash_left.exists()
    after_restart = sbom.stat()
    for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                  "st_mtime_ns", "st_ctime_ns"):
        assert getattr(after_restart, field) == getattr(before_restart, field)
    assert sbom.read_text(encoding="utf-8") == rendered
    runtime.engine.dispose()


@pytest.mark.parametrize("change", ["invalid", "sanitized", "remapped"])
def test_startup_artifact_changes_advance_only_the_owning_scan_revision_once(
    tmp_path: Path, change: str,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    affected_id = _scan(runtime, name="affected")
    unchanged_id = _scan(runtime, name="unchanged")
    empty_id = _scan(runtime, name="empty")
    with runtime.session_factory() as db:
        for scan_id in (affected_id, unchanged_id):
            tool_dir = artifact_dir / "scans" / str(scan_id) / "syft"
            tool_dir.mkdir(parents=True)
            for index in range(2):
                path = tool_dir / f"sbom-{index}.json"
                path.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
                artifact = admit_scan_artifacts(
                    db, runtime.settings, scan_id, [_declared_syft_sbom(path)],
                )[0]
                if scan_id == affected_id:
                    if change == "invalid":
                        path.write_text("{not-json", encoding="utf-8")
                    elif change == "sanitized":
                        path.write_text(json.dumps({
                            "bomFormat": "CycloneDX", "password": "fixture-credential-not-valid",
                        }), encoding="utf-8")
                        declaration = _declared_syft_sbom(path)
                        artifact.size_bytes = declaration["size_bytes"]
                        artifact.sha256 = declaration["sha256"]
                    else:
                        artifact.path = f"{path.parent}/./{path.name}"
        for scan_id, revision, findings_revision in (
            (affected_id, 7, 3), (unchanged_id, 11, 5), (empty_id, 13, 9),
        ):
            scan = db.get(Scan, scan_id)
            assert scan is not None
            scan.revision = revision
            scan.findings_revision = findings_revision
        db.commit()
        unchanged_index = [
            (artifact.id, artifact.path, artifact.size_bytes, artifact.sha256)
            for artifact in db.scalars(
                select(ScanArtifact).where(ScanArtifact.scan_id == unchanged_id).order_by(ScanArtifact.id)
            )
        ]

    assert enforce_artifact_publication_boundary(runtime) is True
    with runtime.session_factory() as db:
        assert [
            (scan.id, scan.revision, scan.findings_revision)
            for scan in db.scalars(select(Scan).order_by(Scan.id))
        ] == [(affected_id, 8, 3), (unchanged_id, 11, 5), (empty_id, 13, 9)]
        affected_artifacts = list(db.scalars(
            select(ScanArtifact).where(ScanArtifact.scan_id == affected_id).order_by(ScanArtifact.id)
        ))
        assert len(affected_artifacts) == (0 if change == "invalid" else 2)
        for artifact in affected_artifacts:
            path = Path(artifact.path)
            assert artifact.path == str(path)
            assert artifact.size_bytes == path.stat().st_size
            assert artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
            assert "fixture-credential-not-valid" not in path.read_text(encoding="utf-8")
        assert [
            (artifact.id, artifact.path, artifact.size_bytes, artifact.sha256)
            for artifact in db.scalars(
                select(ScanArtifact).where(ScanArtifact.scan_id == unchanged_id).order_by(ScanArtifact.id)
            )
        ] == unchanged_index

    def physical_tree() -> dict[Path, tuple[int, ...]]:
        return {
            path.relative_to(artifact_dir): tuple(getattr(path.stat(), field) for field in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                "st_mtime_ns", "st_ctime_ns",
            ))
            for path in (artifact_dir, *artifact_dir.rglob("*"))
        }

    before_restart = physical_tree()
    assert enforce_artifact_publication_boundary(runtime) is False
    assert physical_tree() == before_restart
    with runtime.session_factory() as db:
        assert [
            (scan.id, scan.revision, scan.findings_revision)
            for scan in db.scalars(select(Scan).order_by(Scan.id))
        ] == [(affected_id, 8, 3), (unchanged_id, 11, 5), (empty_id, 13, 9)]
    runtime.engine.dispose()


def test_startup_artifact_revision_and_index_changes_roll_back_together(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime)
    tool_dir = artifact_dir / "scans" / str(scan_id) / "syft"
    tool_dir.mkdir(parents=True)
    path = tool_dir / "sbom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    with runtime.session_factory() as db:
        artifact = admit_scan_artifacts(db, runtime.settings, scan_id, [_declared_syft_sbom(path)])[0]
        db.commit()
        artifact_id = artifact.id
    path.write_text("{not-json", encoding="utf-8")

    with patch(
        "kodesec_api.artifact_boundary._sweep_scans",
        side_effect=ArtifactBoundaryError("fixture sweep failure"),
    ), pytest.raises(ArtifactBoundaryError, match="fixture sweep failure"):
        enforce_artifact_publication_boundary(runtime)
    with runtime.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert (scan.revision, scan.findings_revision) == (1, 1)
        assert db.get(ScanArtifact, artifact_id) is not None
        assert db.get(RuntimeConfig, ARTIFACT_BOUNDARY_MARKER) is None

    assert enforce_artifact_publication_boundary(runtime) is True
    with runtime.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert (scan.revision, scan.findings_revision) == (2, 1)
        assert db.get(ScanArtifact, artifact_id) is None
    runtime.engine.dispose()


def test_artifact_root_symlink_fails_closed_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    sentinel = target / "sentinel"
    sentinel.write_text("preserved", encoding="utf-8")
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    link = runtime_root / "artifacts"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    runtime = _runtime(link)
    with pytest.raises(RuntimeError, match="non-symlink"):
        enforce_artifact_publication_boundary(runtime)
    assert sentinel.read_text(encoding="utf-8") == "preserved"
    runtime.engine.dispose()


@pytest.mark.parametrize("root", [Path("/"), Path("/artifacts"), Path("relative/artifacts")])
def test_dangerously_broad_or_relative_artifact_roots_fail_before_cleanup(root: Path, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("preserved", encoding="utf-8")
    runtime = _runtime(root)
    with pytest.raises(ArtifactBoundaryError, match="dedicated path"):
        enforce_artifact_publication_boundary(runtime)
    assert sentinel.read_text(encoding="utf-8") == "preserved"
    runtime.engine.dispose()


def test_mistyped_root_and_symlink_ancestor_fail_without_creating_or_cleaning(tmp_path: Path) -> None:
    mistyped = tmp_path / "artifcats"
    runtime = _runtime(mistyped)
    with pytest.raises(ArtifactBoundaryError, match="ending in /artifacts"):
        enforce_artifact_publication_boundary(runtime)
    assert not mistyped.exists()
    runtime.engine.dispose()

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    runtime = _runtime(alias / "artifacts")
    with pytest.raises(ArtifactBoundaryError, match="symlink ancestors"):
        enforce_artifact_publication_boundary(runtime)
    assert not (real_parent / "artifacts").exists()
    runtime.engine.dispose()


def test_scans_symlink_fails_closed_and_root_content_is_never_swept(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    sentinel = artifact_dir / "sentinel.txt"
    sentinel.write_text("operator-owned", encoding="utf-8")
    outside = tmp_path / "outside-scans"
    outside.mkdir()
    outside_sentinel = outside / "sentinel.txt"
    outside_sentinel.write_text("outside", encoding="utf-8")
    try:
        (artifact_dir / "scans").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    runtime = _runtime(artifact_dir)
    with pytest.raises(ArtifactBoundaryError, match="missing or unsafe"):
        enforce_artifact_publication_boundary(runtime)
    assert sentinel.read_text(encoding="utf-8") == "operator-owned"
    assert outside_sentinel.read_text(encoding="utf-8") == "outside"
    runtime.engine.dispose()


def test_scanner_result_admission_keeps_only_exact_redacted_syft_sbom(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime)
    valid_dir = artifact_dir / "scans" / str(scan_id) / "syft"
    raw_dir = artifact_dir / "scans" / str(scan_id) / "gitleaks"
    wrong_scan_dir = artifact_dir / "scans" / str(scan_id + 1) / "syft"
    valid_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)
    wrong_scan_dir.mkdir(parents=True)

    fixture = "scanner-admission-secret"
    valid = valid_dir / "syft.cyclonedx.json"
    valid.write_text(json.dumps({"bomFormat": "CycloneDX", "password": fixture}), encoding="utf-8")
    valid_raw = valid.read_bytes()
    malformed = valid_dir / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    oversized = valid_dir / "oversized.json"
    oversized.write_text('{"bomFormat":"CycloneDX","value":"', encoding="utf-8")
    with oversized.open("r+b") as handle:
        handle.truncate(MAX_PUBLISHABLE_SBOM_BYTES + 1)
    raw = raw_dir / "gitleaks.sarif"
    raw.write_text("raw", encoding="utf-8")
    wrong_scan = wrong_scan_dir / "wrong-scan.json"
    wrong_scan.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    symlink = valid_dir / "symlink.json"
    try:
        symlink.symlink_to(outside)
    except OSError:
        symlink = None

    entries = [
        {
            "scanner": "syft",
            "artifact_type": "sbom",
            "format": "cyclonedx-json",
            "path": str(valid),
            "size_bytes": len(valid_raw),
            "sha256": hashlib.sha256(valid_raw).hexdigest(),
        },
        {"scanner": "syft", "artifact_type": "sbom", "format": "cyclonedx-json", "path": str(malformed)},
        {"scanner": "syft", "artifact_type": "sbom", "format": "cyclonedx-json", "path": str(oversized)},
        {"scanner": "gitleaks", "artifact_type": "findings", "format": "sarif", "path": str(raw)},
        {"scanner": "syft", "artifact_type": "sbom", "format": "cyclonedx-json", "path": str(wrong_scan)},
        {"scanner": "syft", "artifact_type": "sbom", "format": "cyclonedx-json", "path": str(outside)},
    ]
    if symlink is not None:
        entries.append({"scanner": "syft", "artifact_type": "sbom", "format": "cyclonedx-json", "path": str(symlink)})

    with runtime.session_factory() as db:
        admitted = admit_scan_artifacts(db, runtime.settings, scan_id, entries)
        db.commit()
        assert len(admitted) == 1
        artifact_id = admitted[0].id
    rendered = valid.read_text(encoding="utf-8")
    assert fixture not in rendered
    assert REDACTED in rendered
    assert not malformed.exists()
    assert not oversized.exists()
    assert not raw.exists()
    assert wrong_scan.exists()
    assert outside.exists()
    if symlink is not None:
        assert not symlink.exists() and not symlink.is_symlink()
    with runtime.session_factory() as db:
        artifact = db.get(ScanArtifact, artifact_id)
        assert artifact
        assert artifact.path == str(valid)
        assert artifact.size_bytes == valid.stat().st_size
        assert artifact.sha256 == hashlib.sha256(valid.read_bytes()).hexdigest()
    runtime.engine.dispose()


def test_scan_cleanup_is_exact_and_does_not_follow_symlinks(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    current = artifact_dir / "scans" / "1" / "syft"
    other = artifact_dir / "scans" / "2" / "syft"
    current.mkdir(parents=True)
    other.mkdir(parents=True)
    (current / "artifact.json").write_text("delete", encoding="utf-8")
    other_file = other / "artifact.json"
    other_file.write_text("preserve", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "sentinel"
    outside_file.write_text("preserve", encoding="utf-8")
    try:
        (current / "outside-link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pass
    runtime = _runtime(artifact_dir)
    delete_scan_artifact_tree(runtime.settings, 1)
    assert not (artifact_dir / "scans" / "1").exists()
    assert other_file.read_text(encoding="utf-8") == "preserve"
    assert outside_file.read_text(encoding="utf-8") == "preserve"
    runtime.engine.dispose()


def test_operational_artifact_rewrite_failure_is_not_silently_dropped(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime, name="rewrite-failure")
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    raw = path.read_bytes()
    with runtime.session_factory() as db, patch(
        "kodesec_api.artifact_boundary._atomic_rewrite",
        side_effect=ArtifactBoundaryError("fixture ENOSPC"),
    ):
        with pytest.raises(ArtifactBoundaryError, match="ENOSPC"):
            admit_scan_artifacts(
                db,
                runtime.settings,
                scan_id,
                [
                    {
                        "scanner": "syft",
                        "artifact_type": "sbom",
                        "format": "cyclonedx-json",
                        "path": str(path),
                        "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ],
            )
        assert db.scalar(select(func.count(ScanArtifact.id))) == 0
    runtime.engine.dispose()


@pytest.mark.parametrize("source_location", [
    pytest.param("manifests café/requirements.txt", id="unicode-directory"),
    pytest.param(
        "tests/scanner-runtime/fixtures/dependencies/positive/requirements.txt",
        id="long-multicomponent-path",
    ),
    pytest.param("bearer/requirements.txt", id="bearer-directory"),
    pytest.param("/".join(["a"] * 2040) + "/requirements.txt", id="4096-byte-boundary"),
])
def test_syft_source_locations_survive_admission_and_startup_redaction(
    tmp_path: Path, source_location: str,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime, name="source-location")
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    valid = {"name": "syft:location:0:path", "value": source_location}
    rejected = [
        {**valid, "value": value} for value in (
            "../requirements.txt", "/requirements.txt", "C:/requirements.txt",
            "file:///requirements.txt", "a\\requirements.txt", "./requirements.txt",
            "a//requirements.txt", "a/../requirements.txt", "requirements.txt\x00",
            "requirements\u202e.txt", "requirements\ud800.txt", " requirements.txt",
            "a" * 4097, "ghp_fixture_not_a_valid_secret_123456789", "[REDACTED]", 1,
            "src/" + "a" * 32 + "/requirements.txt",
            "src/ghp_fixture_canary_only/requirements.txt",
            "src/eyJmb28.eyJmb28.c2lnbmF0dXJl/requirements.txt",
            "src/password=fixture/requirements.txt",
            "src/file?token=fixture/requirements.txt",
            "Bearer /foo", "prefix/Bearer /foo/file.txt", "password=/foo",
            "src/-----BEGIN PRIVATE KEY-----/fixture/requirements.txt",
            "src/[REDACTED]/requirements.txt",
            "/".join(["a"] * 2040) + "/requirements.txtx",
        )
    ] + [{**valid, "name": "password"}, {**valid, "note": "lookalike"}]
    path.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{
            "name": "fixture-package", "properties": [valid, *rejected],
            "untyped": valid, "value": "fixture private value",
        }],
    }), encoding="utf-8")
    with runtime.session_factory() as db:
        admitted = admit_scan_artifacts(db, runtime.settings, scan_id, [_declared_syft_sbom(path)])
        assert len(admitted) == 1
        db.commit()
    published = path.read_bytes()
    component = json.loads(published)["components"][0]
    assert component["properties"][0] == valid
    assert [item["value"] for item in component["properties"][1:]] == [REDACTED] * len(rejected)
    assert component["untyped"]["value"] == REDACTED
    assert component["value"] == REDACTED
    enforce_artifact_publication_boundary(runtime)
    assert path.read_bytes() == published
    with runtime.session_factory() as db:
        admitted = db.scalar(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id))
        assert admitted is not None
        assert admitted.sha256 == hashlib.sha256(published).hexdigest()
    runtime.engine.dispose()


def test_cyclonedx_hash_identity_survives_credential_redaction(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime, name="hash-identity")
    digest = "A1" * 32
    hash_lookalike = "B2" * 32
    wrong_length_digest = "C3" * 20
    unrecognized_digest = "D4" * 32
    secret = "fixture-credential"
    source_path = "/workspace/private-owner/repository"
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {
                    "component": {
                        "type": "file",
                        "name": source_path,
                        "bom-ref": f"root:{source_path}",
                    },
                    "property": f"staged from {source_path}",
                },
                "dependencies": [{"ref": f"root:{source_path}", "dependsOn": []}],
                "components": [
                    {
                        "name": "fixture",
                        "purl": "pkg:pypi/fixture@1.0.0",
                        "hashes": [
                            {"alg": "SHA-256", "content": digest},
                            {"alg": "SHA-256", "content": wrong_length_digest},
                            {"alg": "SHA-999", "content": unrecognized_digest},
                            {"alg": "SHA-256", "content": hash_lookalike, "note": "not a hash record"},
                        ],
                        "evidence": {"alg": "SHA-256", "content": hash_lookalike},
                        "hash": hash_lookalike,
                        "digest": hash_lookalike,
                        "sha256": hash_lookalike,
                        "credentials": {"alg": "SHA-256", "content": hash_lookalike},
                        "properties": [{"name": "password", "value": secret}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with runtime.session_factory() as db:
        admitted = admit_scan_artifacts(
            db,
            runtime.settings,
            scan_id,
            [_declared_syft_sbom(path)],
        )
        assert len(admitted) == 1
    rendered = path.read_text(encoding="utf-8")
    payload = json.loads(rendered)
    assert source_path not in rendered
    assert payload["metadata"]["component"]["name"] == "source"
    assert payload["metadata"]["component"]["bom-ref"] == "urn:kodesec:source"
    assert payload["metadata"]["property"] == "staged from source"
    assert payload["dependencies"][0]["ref"] == "urn:kodesec:source"
    component = payload["components"][0]
    assert component["name"] == "fixture"
    assert component["purl"] == "pkg:pypi/fixture@1.0.0"
    assert component["hashes"][0]["content"] == digest.lower()
    assert component["hashes"][1]["content"] == REDACTED
    assert component["hashes"][2]["content"] == REDACTED
    assert component["hashes"][3]["content"] == REDACTED
    assert component["evidence"]["content"] == REDACTED
    assert component["hash"] == REDACTED
    assert component["digest"] == REDACTED
    assert component["sha256"] == REDACTED
    assert component["credentials"] == REDACTED
    assert secret not in rendered
    assert REDACTED in rendered
    runtime.engine.dispose()


async def _response_body(response) -> bytes:
    chunks = [chunk async for chunk in response.body_iterator]
    return b"".join(chunks)


def test_open_and_download_use_verified_stable_content_and_no_store(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime)
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    with runtime.session_factory() as db:
        admitted = admit_scan_artifacts(
            db,
            runtime.settings,
            scan_id,
            [_declared_syft_sbom(path)],
        )
        db.commit()
        artifact_id = admitted[0].id
        open_response = open_artifact(artifact_id, runtime=runtime, db=db)
        download_response = download_artifact(artifact_id, runtime=runtime, db=db)
        expected = path.read_bytes()
        # Mutating the pathname after preparation cannot change the stable response.
        path.write_text(json.dumps({"bomFormat": "CycloneDX", "mutated": True}), encoding="utf-8")
        assert anyio.run(_response_body, open_response) == expected
        assert anyio.run(_response_body, download_response) == expected
        expected_filename = f"lomo-codesecurity-scan-{scan_id}-syft.cyclonedx.json"
        assert open_response.headers["content-disposition"] == (
            f'inline; filename="{expected_filename}"; filename*=UTF-8\'\'{expected_filename}'
        )
        assert download_response.headers["content-disposition"] == (
            f'attachment; filename="{expected_filename}"; filename*=UTF-8\'\'{expected_filename}'
        )
        for response in (open_response, download_response):
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["content-length"] == str(len(expected))
            assert response.media_type == "application/vnd.cyclonedx+json"
    runtime.engine.dispose()


def test_download_rejects_hash_mutation_and_symlink_substitution(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime)
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    with runtime.session_factory() as db:
        admitted = admit_scan_artifacts(
            db,
            runtime.settings,
            scan_id,
            [_declared_syft_sbom(path)],
        )
        db.commit()
        artifact_id = admitted[0].id
        artifact = db.get(ScanArtifact, artifact_id)
        assert artifact

        path.write_text(json.dumps({"bomFormat": "CycloneDX", "changed": True}), encoding="utf-8")
        with pytest.raises(ArtifactBoundaryError, match="no longer matches"):
            prepare_artifact_download(artifact, runtime.settings)

        outside = tmp_path / "outside.json"
        outside.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink unavailable: {exc}")
        with pytest.raises(ArtifactBoundaryError, match="missing or unsafe"):
            prepare_artifact_download(artifact, runtime.settings)
        assert outside.exists()
    runtime.engine.dispose()


def test_download_translates_bounded_response_storage_exhaustion(tmp_path: Path, monkeypatch) -> None:
    artifact_dir = tmp_path / "artifacts"
    runtime = _runtime(artifact_dir)
    scan_id = _scan(runtime)
    path = artifact_dir / "scans" / str(scan_id) / "syft" / "syft.cyclonedx.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")

    class ExhaustedSpool:
        def write(self, chunk):
            raise OSError(28, "No space left on device")

        def close(self):
            return None

    with runtime.session_factory() as db:
        artifact = admit_scan_artifacts(
            db,
            runtime.settings,
            scan_id,
            [_declared_syft_sbom(path)],
        )[0]
        db.commit()
        monkeypatch.setattr("kodesec_api.artifact_boundary.tempfile.SpooledTemporaryFile", lambda **kwargs: ExhaustedSpool())
        with pytest.raises(ArtifactBoundaryError, match="bounded response storage"):
            prepare_artifact_download(artifact, runtime.settings)
    runtime.engine.dispose()
