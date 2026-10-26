from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
import urllib.request
import zlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner.cache_manifest import CacheFileRecord, canonical_json_bytes
from kodesec_scanner import trivy_db_lock_candidate as candidate
from kodesec_scanner.trivy_db_lock_candidate import (
    CandidateValidationError,
    CommandResult,
    EMPTY_CONFIG_DIGEST,
    MAX_LAYER_BYTES,
    OciManifestEvidence,
    TrivyMetadataEvidence,
    build_proposal_receipt,
    extract_layer_tar_gz,
    installed_content_evidence,
    parse_trivy_canary_json,
    run_canary,
    run_fetch,
    run_preflight,
    strict_json_object,
    validate_layer_file,
    validate_manifest_pair,
    validate_metadata_bytes,
    validate_canary_receipt,
    validate_fetch_receipt,
    validate_preflight_receipt,
    write_private_receipt,
)


ROOT = Path(__file__).resolve().parents[3]
INVOCATION_ID = "a" * 32


def _manifest(
    *,
    layer: bytes = b"layer",
    created: str = "2026-08-13T12:00:00Z",
    component_id: str = "trivy-db",
) -> bytes:
    profile = candidate.candidate_profile(component_id)
    value = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.aquasec.trivy.config.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": EMPTY_CONFIG_DIGEST,
            "size": 2,
            "data": "e30=",
        },
        "layers": [
            {
                "mediaType": profile.layer_media_type,
                "digest": "sha256:" + hashlib.sha256(layer).hexdigest(),
                "size": len(layer),
                "annotations": {
                    "org.opencontainers.image.title": profile.layer_title
                },
            }
        ],
        "annotations": {"org.opencontainers.image.created": created},
    }
    return json.dumps(value, separators=(",", ":")).encode()


def _manifest_evidence(
    raw: bytes | None = None, component_id: str = "trivy-db"
) -> OciManifestEvidence:
    body = raw or _manifest(component_id=component_id)
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    return validate_manifest_pair(
        tag_body=body,
        tag_digest_header=digest,
        digest_body=body,
        digest_digest_header=digest,
        component_id=component_id,
    )


def _tar_gz(path: Path, members: list[tuple[str, bytes, str]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, kind in members:
            item = tarfile.TarInfo(name)
            item.mtime = 0
            if kind == "file":
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            elif kind == "dir":
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            elif kind == "symlink":
                item.type = tarfile.SYMTYPE
                item.linkname = "trivy.db"
                archive.addfile(item)
            elif kind == "hardlink":
                item.type = tarfile.LNKTYPE
                item.linkname = "trivy.db"
                archive.addfile(item)
            else:  # pragma: no cover - test helper guard
                raise AssertionError(kind)


def _extract(
    archive: Path,
    destination: Path,
    *,
    maximum_entries: int = 20_000,
    maximum_bytes: int = 2 * 1024 * 1024 * 1024,
) -> tuple[CacheFileRecord, ...]:
    return extract_layer_tar_gz(
        archive,
        destination,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        expected_size_bytes=archive.stat().st_size,
        maximum_entries=maximum_entries,
        maximum_bytes=maximum_bytes,
    )


def _current_canaries() -> list[dict[str, object]]:
    return [
        {
            "id": "source-vulnerabilities-positive",
            "fixture_path": "dependencies/positive",
            "fixture_kind": "tree",
            "fixture_hash_algorithm": "kodesec-canonical-tree-v1",
            "fixture_sha256": "2" * 64,
        },
        {
            "id": "source-vulnerabilities-zero",
            "fixture_path": "dependencies/zero",
            "fixture_kind": "tree",
            "fixture_hash_algorithm": "kodesec-canonical-tree-v1",
            "fixture_sha256": "3" * 64,
        },
    ]


def _proposal_kwargs() -> dict[str, object]:
    metadata_raw = _metadata()
    implementation_bundle = {
        "hash_algorithm": "kodesec-python-bundle-v1",
        "files": [
            {"path": "cache_manifest.py", "size_bytes": 1, "sha256": "a" * 64},
            {"path": "tools.py", "size_bytes": 1, "sha256": "b" * 64},
            {
                "path": "trivy_db_lock_candidate.py",
                "size_bytes": 1,
                "sha256": "c" * 64,
            },
            {"path": "updater.py", "size_bytes": 1, "sha256": "d" * 64},
        ],
    }
    implementation_bundle.update(
        {
            "sha256": hashlib.sha256(
                canonical_json_bytes(implementation_bundle["files"])
            ).hexdigest(),
            "file_count": 4,
            "size_bytes": 4,
        }
    )
    return {
        "current_lock_sha256": "4" * 64,
        "baked_lock_sha256": "4" * 64,
        "image_id": "sha256:" + "5" * 64,
        "architecture": "arm64",
        "trivy_version": "0.73.0",
        "trivy_executable_path": "/usr/local/bin/trivy",
        "trivy_executable_sha256": "7" * 64,
        "tool_manifest_sha256": "6" * 64,
        "implementation_bundle": implementation_bundle,
        "host_cli_sha256": "9" * 64,
        "host_execution_identity": {"uid": 502, "gid": 20},
        "build_receipt": {
            "schema": "kodesec.scanner-build-receipt/v2",
            "receipt_sha256": "e" * 64,
        },
        "evidence_receipts": {
            "preflight": {
                "schema": "kodesec.trivy-db-lock-candidate-preflight/v1",
                "receipt_sha256": "a" * 64,
            },
            "fetch": {
                "schema": "kodesec.trivy-db-lock-candidate-fetch/v1",
                "receipt_sha256": "b" * 64,
            },
            "canary": {
                "schema": "kodesec.trivy-db-lock-candidate-canary/v1",
                "receipt_sha256": "c" * 64,
            },
        },
        "manifest": _manifest_evidence(),
        "metadata": TrivyMetadataEvidence(
            updated_at="2026-08-13T11:00:00Z",
            next_update="2026-08-14T11:00:00Z",
            downloaded_at=candidate.RAW_TRIVY_DOWNLOADED_AT,
            observed_at="2026-08-13T12:30:00Z",
            maximum_age_seconds=candidate.TRIVY_DB_MAX_AGE_SECONDS,
            minimum_remaining_seconds=candidate.MINIMUM_REMAINING_SECONDS,
            size_bytes=len(metadata_raw),
            sha256=hashlib.sha256(metadata_raw).hexdigest(),
        ),
        "installed_records": [
            CacheFileRecord(path="trivy.db", size_bytes=8, sha256="1" * 64),
            CacheFileRecord(
                path="metadata.json",
                size_bytes=len(metadata_raw),
                sha256=hashlib.sha256(metadata_raw).hexdigest(),
            ),
        ],
        "current_canaries": _current_canaries(),
        "canaries": [
            {
                "canary_id": "source-vulnerabilities-positive",
                "fixture_sha256": "2" * 64,
                "exit_code": 0,
                "result_count": 2,
                "ids": ["CVE-1", "CVE-2"],
            },
            {
                "canary_id": "source-vulnerabilities-zero",
                "fixture_sha256": "3" * 64,
                "exit_code": 0,
                "result_count": 0,
                "ids": [],
            },
        ],
    }


def _java_proposal_kwargs() -> dict[str, object]:
    values = _proposal_kwargs()
    metadata_raw = _java_metadata()
    _, current_canaries = candidate._trivy_requirement_contract(
        ROOT / "scanner-tools.lock.json", "trivy-java-db"
    )
    values.update(
        {
            "component_id": "trivy-java-db",
            "evidence_receipts": {
                phase: {
                    "schema": (
                        f"kodesec.trivy-java-db-lock-candidate-{phase}/v1"
                    ),
                    "receipt_sha256": digest * 64,
                }
                for phase, digest in (
                    ("preflight", "a"),
                    ("fetch", "b"),
                    ("canary", "c"),
                )
            },
            "manifest": _manifest_evidence(component_id="trivy-java-db"),
            "metadata": TrivyMetadataEvidence(
                updated_at="2026-08-20T01:00:00Z",
                next_update="2026-08-23T01:00:00Z",
                downloaded_at=candidate.RAW_TRIVY_DOWNLOADED_AT,
                observed_at="2026-08-20T12:00:00Z",
                maximum_age_seconds=candidate.TRIVY_JAVA_DB_MAX_AGE_SECONDS,
                minimum_remaining_seconds=candidate.MINIMUM_REMAINING_SECONDS,
                size_bytes=len(metadata_raw),
                sha256=hashlib.sha256(metadata_raw).hexdigest(),
            ),
            "installed_records": [
                CacheFileRecord(
                    path="metadata.json",
                    size_bytes=len(metadata_raw),
                    sha256=hashlib.sha256(metadata_raw).hexdigest(),
                ),
                CacheFileRecord(
                    path="trivy-java.db", size_bytes=8, sha256="1" * 64
                ),
            ],
            "current_canaries": current_canaries,
            "canaries": [
                {
                    "canary_id": "java-artifacts-positive",
                    "fixture_sha256": current_canaries[0]["fixture_sha256"],
                    "exit_code": 0,
                    "result_count": 1,
                    "ids": ["CVE-2021-44228"],
                },
                {
                    "canary_id": "java-artifacts-zero",
                    "fixture_sha256": current_canaries[1]["fixture_sha256"],
                    "exit_code": 0,
                    "result_count": 0,
                    "ids": [],
                },
            ],
        }
    )
    return values


def test_strict_json_rejects_duplicate_nonfinite_and_invalid_utf8() -> None:
    assert strict_json_object(b'{"a":1}', label="value", maximum_bytes=8) == {"a": 1}
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":"\xff"}'):
        with pytest.raises(CandidateValidationError):
            strict_json_object(raw, label="value", maximum_bytes=64)


def test_manifest_pair_binds_exact_tag_digest_schema_and_layer() -> None:
    body = _manifest(layer=b"payload")
    evidence = _manifest_evidence(body)
    assert evidence.manifest_digest == hashlib.sha256(body).hexdigest()
    assert evidence.layer_digest == hashlib.sha256(b"payload").hexdigest()
    assert evidence.layer_size_bytes == 7

    with pytest.raises(CandidateValidationError, match="bodies differ"):
        validate_manifest_pair(
            tag_body=body,
            tag_digest_header="sha256:" + hashlib.sha256(body).hexdigest(),
            digest_body=body + b" ",
            digest_digest_header="sha256:" + hashlib.sha256(body + b" ").hexdigest(),
        )
    with pytest.raises(CandidateValidationError, match="response digest"):
        validate_manifest_pair(
            tag_body=body,
            tag_digest_header="sha256:" + "0" * 64,
            digest_body=body,
            digest_digest_header="sha256:" + hashlib.sha256(body).hexdigest(),
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda value: value.update({"extra": True}), "schema differs"),
        (lambda value: value.update({"schemaVersion": True}), "schema differs"),
        (
            lambda value: value["layers"].append(dict(value["layers"][0])),
            "schema differs",
        ),
        (
            lambda value: value["layers"][0].update({"size": MAX_LAYER_BYTES + 1}),
            "schema differs",
        ),
        (lambda value: value["config"].update({"data": "AAAA"}), "schema differs"),
        (lambda value: value["annotations"].update({"extra": "x"}), "schema differs"),
    ],
)
def test_manifest_pair_rejects_schema_drift(mutator, message: str) -> None:
    value = json.loads(_manifest())
    mutator(value)
    body = json.dumps(value, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    with pytest.raises(CandidateValidationError, match=message):
        validate_manifest_pair(
            tag_body=body,
            tag_digest_header=digest,
            digest_body=body,
            digest_digest_header=digest,
        )


def test_layer_file_requires_exact_regular_stable_bytes(tmp_path: Path) -> None:
    layer = tmp_path / "db.tar.gz"
    layer.write_bytes(b"candidate")
    validate_layer_file(
        layer,
        expected_sha256=hashlib.sha256(b"candidate").hexdigest(),
        expected_size_bytes=9,
    )
    with pytest.raises(CandidateValidationError):
        validate_layer_file(layer, expected_sha256="0" * 64, expected_size_bytes=9)
    alias = tmp_path / "alias"
    alias.symlink_to(layer)
    with pytest.raises(CandidateValidationError, match="safe regular"):
        validate_layer_file(alias, expected_sha256="0" * 64, expected_size_bytes=9)


def test_bounded_streaming_archive_extracts_regular_files(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "candidate.tar.gz"
    _tar_gz(
        archive,
        [
            ("db", b"", "dir"),
            ("db/trivy.db", b"database", "file"),
            ("db/metadata.json", b"{}", "file"),
        ],
    )
    destination = tmp_path / "out"
    records = _extract(archive, destination, maximum_entries=3, maximum_bytes=10)
    assert [record.path for record in records] == ["db/metadata.json", "db/trivy.db"]
    assert (destination / "db/trivy.db").read_bytes() == b"database"
    assert stat_mode(destination) == 0o500
    assert stat_mode(destination / "db/trivy.db") == 0o400


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize(
    "members",
    [
        [("../escape", b"x", "file")],
        [("/absolute", b"x", "file")],
        [("trivy.db", b"x", "file"), ("trivy.db", b"y", "file")],
        [("link", b"", "symlink")],
        [("link", b"", "hardlink")],
        [("empty", b"", "dir")],
    ],
)
def test_archive_rejects_unsafe_duplicate_link_and_empty_directory(
    tmp_path: Path, members: list[tuple[str, bytes, str]]
) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "candidate.tar.gz"
    _tar_gz(archive, members)
    destination = tmp_path / "out"
    with pytest.raises(CandidateValidationError):
        _extract(archive, destination, maximum_entries=8, maximum_bytes=1024)
    assert not destination.exists()


def test_archive_rejects_prospective_entry_and_byte_overrun(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "candidate.tar.gz"
    _tar_gz(archive, [("one", b"123", "file"), ("two", b"456", "file")])
    with pytest.raises(CandidateValidationError, match="entry count"):
        _extract(archive, tmp_path / "entries", maximum_entries=1, maximum_bytes=8)
    with pytest.raises(CandidateValidationError, match="byte bound"):
        _extract(archive, tmp_path / "bytes", maximum_entries=2, maximum_bytes=5)


def test_archive_counts_root_headers_prospectively_and_bounds_time(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "roots.tar.gz"
    _tar_gz(
        archive,
        [("./", b"", "dir"), ("./", b"", "dir"), ("trivy.db", b"x", "file")],
    )
    with pytest.raises(CandidateValidationError, match="entry count"):
        extract_layer_tar_gz(
            archive,
            tmp_path / "roots",
            expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            expected_size_bytes=archive.stat().st_size,
            maximum_entries=2,
            maximum_bytes=16,
        )
    assert not (tmp_path / "roots").exists()

    moments = iter((0.0, 2.0))
    with pytest.raises(CandidateValidationError, match="time bound"):
        extract_layer_tar_gz(
            archive,
            tmp_path / "timed",
            expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            expected_size_bytes=archive.stat().st_size,
            maximum_entries=4,
            maximum_bytes=16,
            maximum_seconds=1,
            monotonic=lambda: next(moments),
        )
    assert not (tmp_path / "timed").exists()


def test_archive_rejects_nonzero_directory_payload(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "directory-payload.tar.gz"
    item = tarfile.TarInfo("directory")
    item.type = tarfile.DIRTYPE
    item.size = 1
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.addfile(item, io.BytesIO(b"x"))
    with pytest.raises(CandidateValidationError, match="directory carries"):
        _extract(archive, tmp_path / "out", maximum_entries=2, maximum_bytes=16)


def test_bounded_gzip_reader_rejects_oversized_parser_request_and_output() -> None:
    compressed = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    payload = compressed.compress(b"x" * 8192) + compressed.flush()
    reader = candidate._BoundedGzipReader(io.BytesIO(payload), maximum_bytes=1024)
    with pytest.raises(CandidateValidationError, match="hard byte bound"):
        reader.read(512)

    compressed = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    payload = compressed.compress(b"x") + compressed.flush()
    reader = candidate._BoundedGzipReader(io.BytesIO(payload), maximum_bytes=1024)
    with pytest.raises(CandidateValidationError, match="oversized metadata"):
        reader.read(1024 * 1024 + 1)


def test_archive_rejects_oversized_gnu_longname_before_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    archive = tmp_path / "gnu-longname.tar.gz"
    header = tarfile.TarInfo("././@LongLink")
    header.type = tarfile.GNUTYPE_LONGNAME
    header.size = 2 * 1024 * 1024
    block = header.tobuf(format=tarfile.GNU_FORMAT)
    padding = b"\0" * (tarfile.BLOCKSIZE * 2)
    compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    archive.write_bytes(compressor.compress(block + padding) + compressor.flush())

    monkeypatch.setattr(candidate, "MAX_TAR_STREAM_BYTES", 4 * 1024 * 1024)
    with pytest.raises(CandidateValidationError, match="extension metadata"):
        _extract(archive, tmp_path / "out", maximum_entries=4, maximum_bytes=1024)
    assert not (tmp_path / "out").exists()


def _metadata(
    *,
    updated: str = "2026-08-13T11:00:00Z",
    downloaded: object = "0001-01-01T00:00:00Z",
    next_update: str = "2026-08-14T11:00:00Z",
) -> bytes:
    return json.dumps(
        {
            "Version": 2,
            "NextUpdate": next_update,
            "UpdatedAt": updated,
            "DownloadedAt": downloaded,
        },
        separators=(",", ":"),
    ).encode()


def _java_metadata(
    *,
    updated: str = "2026-08-20T01:00:00Z",
    downloaded: object = "0001-01-01T00:00:00Z",
    next_update: str = "2026-08-23T01:00:00Z",
) -> bytes:
    return json.dumps(
        {
            "Version": 1,
            "NextUpdate": next_update,
            "UpdatedAt": updated,
            "DownloadedAt": downloaded,
        },
        separators=(",", ":"),
    ).encode()


def test_java_profile_is_exact_and_cannot_cross_bind_os_contract() -> None:
    profile = candidate.candidate_profile("trivy-java-db")
    assert profile.discovery_ref == "ghcr.io/aquasecurity/trivy-java-db:1"
    assert profile.cache_subpath == "trivy/java-db"
    assert profile.layer_media_type == (
        "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
    )
    assert profile.layer_title == "javadb.tar.gz"
    assert profile.metadata_version == 1
    assert profile.canary_ids == ("java-artifacts-positive", "java-artifacts-zero")
    assert profile.fixture_kinds == ("file", "tree")

    _, canaries = candidate._trivy_requirement_contract(
        ROOT / "scanner-tools.lock.json", "trivy-java-db"
    )
    assert [(item["id"], item["fixture_path"]) for item in canaries] == [
        (
            "java-artifacts-positive",
            "trivy/java/log4j-core-2.14.1.jar",
        ),
        ("java-artifacts-zero", "dependencies/zero"),
    ]

    java_manifest = _manifest(component_id="trivy-java-db")
    digest = "sha256:" + hashlib.sha256(java_manifest).hexdigest()
    validate_manifest_pair(
        tag_body=java_manifest,
        tag_digest_header=digest,
        digest_body=java_manifest,
        digest_digest_header=digest,
        component_id="trivy-java-db",
    )
    with pytest.raises(CandidateValidationError, match="differs from its component"):
        validate_manifest_pair(
            tag_body=java_manifest,
            tag_digest_header=digest,
            digest_body=java_manifest,
            digest_digest_header=digest,
        )
    with pytest.raises(CandidateValidationError, match="not admitted"):
        candidate.candidate_profile("../trivy-java-db")


def test_metadata_requires_exact_fresh_version_two_chronology() -> None:
    now = datetime(2026, 8, 13, 12, 30, tzinfo=UTC)
    evidence = validate_metadata_bytes(_metadata(), now=now, maximum_age_seconds=172800)
    assert evidence.next_update == "2026-08-14T11:00:00Z"
    assert evidence.downloaded_at == candidate.RAW_TRIVY_DOWNLOADED_AT

    hostile = json.loads(_metadata())
    hostile["Version"] = True
    with pytest.raises(CandidateValidationError, match="Version"):
        validate_metadata_bytes(
            json.dumps(hostile).encode(), now=now, maximum_age_seconds=172800
        )
    overdue_refresh = validate_metadata_bytes(
        _metadata(next_update="2026-08-13T12:00:00Z"),
        now=now,
        maximum_age_seconds=172800,
    )
    assert overdue_refresh.next_update == "2026-08-13T12:00:00Z"
    with pytest.raises(CandidateValidationError, match="expired"):
        validate_metadata_bytes(
            _metadata(),
            now=datetime(2026, 8, 15, 11, 0, tzinfo=UTC),
            maximum_age_seconds=172800,
        )
    with pytest.raises(CandidateValidationError, match="fields"):
        validate_metadata_bytes(
            _metadata()[:-1] + b',"extra":1}', now=now, maximum_age_seconds=172800
        )
    with pytest.raises(CandidateValidationError, match="lifetime"):
        validate_metadata_bytes(
            _metadata(),
            now=now,
            maximum_age_seconds=172800,
            minimum_remaining_seconds=170_000,
        )
    with pytest.raises(CandidateValidationError, match="interval"):
        validate_metadata_bytes(
            _metadata(next_update="2026-08-14T11:00:01Z"),
            now=now,
            maximum_age_seconds=172800,
        )
    with pytest.raises(CandidateValidationError, match="oversized"):
        validate_metadata_bytes(
            b"{" + b" " * 4096 + b"}", now=now, maximum_age_seconds=172800
        )


@pytest.mark.parametrize(
    "downloaded",
    [
        "2026-08-13T12:00:00Z",
        "0001-01-01T00:00:00.0Z",
        "0001-01-01T00:00:00+00:00",
        None,
        0,
    ],
)
def test_raw_metadata_requires_exact_publisher_zero_downloaded_at(
    downloaded: object,
) -> None:
    with pytest.raises(CandidateValidationError, match="publisher zero time"):
        validate_metadata_bytes(
            _metadata(downloaded=downloaded),
            now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
            maximum_age_seconds=candidate.TRIVY_DB_MAX_AGE_SECONDS,
        )


def test_metadata_twelve_hour_remaining_boundary_is_exact() -> None:
    validate_metadata_bytes(
        _metadata(),
        now=datetime(2026, 8, 26, 23, 0, tzinfo=UTC),
        maximum_age_seconds=candidate.TRIVY_DB_MAX_AGE_SECONDS,
        minimum_remaining_seconds=candidate.MINIMUM_REMAINING_SECONDS,
    )
    with pytest.raises(CandidateValidationError, match="lifetime"):
        validate_metadata_bytes(
            _metadata(),
            now=datetime(2026, 8, 26, 23, 0, 1, tzinfo=UTC),
            maximum_age_seconds=candidate.TRIVY_DB_MAX_AGE_SECONDS,
            minimum_remaining_seconds=candidate.MINIMUM_REMAINING_SECONDS,
        )


def test_java_metadata_requires_version_one_and_bounded_publisher_interval() -> None:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    evidence = validate_metadata_bytes(
        _java_metadata(),
        now=now,
        maximum_age_seconds=candidate.TRIVY_JAVA_DB_MAX_AGE_SECONDS,
        minimum_remaining_seconds=candidate.MINIMUM_REMAINING_SECONDS,
        expected_version=1,
        maximum_update_interval_seconds=(
            candidate.TRIVY_JAVA_DB_MAX_UPDATE_INTERVAL_SECONDS
        ),
    )
    assert evidence.next_update == "2026-08-23T01:00:00Z"
    with pytest.raises(CandidateValidationError, match="Version"):
        validate_metadata_bytes(
            _java_metadata(),
            now=now,
            maximum_age_seconds=candidate.TRIVY_JAVA_DB_MAX_AGE_SECONDS,
        )
    with pytest.raises(CandidateValidationError, match="interval"):
        validate_metadata_bytes(
            _java_metadata(next_update="2026-08-24T01:00:01Z"),
            now=now,
            maximum_age_seconds=candidate.TRIVY_JAVA_DB_MAX_AGE_SECONDS,
            expected_version=1,
            maximum_update_interval_seconds=(
                candidate.TRIVY_JAVA_DB_MAX_UPDATE_INTERVAL_SECONDS
            ),
        )


def test_installed_content_excludes_only_metadata() -> None:
    records = [
        CacheFileRecord(
            path="trivy.db",
            size_bytes=8,
            sha256=hashlib.sha256(b"database").hexdigest(),
        ),
        CacheFileRecord(
            path="metadata.json", size_bytes=2, sha256=hashlib.sha256(b"{}").hexdigest()
        ),
    ]
    evidence = installed_content_evidence(records)
    assert evidence["file_count"] == 1
    assert evidence["size_bytes"] == 8
    assert evidence["volatile_paths"] == ["metadata.json"]
    with pytest.raises(CandidateValidationError):
        installed_content_evidence(records[:1])


def test_java_support_db_must_match_current_os_db_installed_content(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    support = tmp_path / "db"
    support.mkdir(mode=0o700)
    (support / "trivy.db").write_bytes(b"database")
    (support / "metadata.json").write_bytes(_metadata())
    for path in support.iterdir():
        path.chmod(0o400)
    support.chmod(0o500)
    tree = candidate.collect_canonical_tree(support, require_immutable=True)

    lock_value = json.loads((ROOT / "scanner-tools.lock.json").read_bytes())
    trivy = next(item for item in lock_value["tools"] if item["id"] == "trivy")
    os_db = next(
        item for item in trivy["requirements"] if item["id"] == "trivy-db"
    )
    os_db["installed_content"] = installed_content_evidence(tree.files)
    os_db["installed_size_bytes"] = tree.size_bytes
    lock_path = tmp_path / "scanner-tools.lock.json"
    lock_path.write_bytes(canonical_json_bytes(lock_value))
    validated = candidate._validated_trivy_support_tree(lock_path, support)
    assert validated.sha256 == tree.sha256

    (support / "trivy.db").chmod(0o600)
    (support / "trivy.db").write_bytes(b"different")
    (support / "trivy.db").chmod(0o400)
    with pytest.raises(CandidateValidationError, match="differs from the current lock"):
        candidate._validated_trivy_support_tree(lock_path, support)


def test_java_canary_fails_before_execution_without_os_support_db() -> None:
    with pytest.raises(candidate._InnerFailure) as captured:
        run_canary(
            current_lock=ROOT / "scanner-tools.lock.json",
            candidate_db=Path("/run/kodesec-review/candidate-cache/java-db"),
            positive_fixture=Path("unused-positive"),
            zero_fixture=Path("unused-zero"),
            scratch_root=Path("unused-scratch"),
            invocation_id=INVOCATION_ID,
            component_id="trivy-java-db",
        )
    assert captured.value.mode == "canary"
    assert captured.value.code == "input"


def test_proposal_receipt_is_canonical_non_authoritative_and_no_overwrite(
    tmp_path: Path,
) -> None:
    receipt = build_proposal_receipt(**_proposal_kwargs())
    manifest = _proposal_kwargs()["manifest"]
    assert isinstance(manifest, OciManifestEvidence)
    assert receipt["authoritative"] is False
    assert (
        receipt["proposed_replacement"]["source"]["sha256"] == manifest.manifest_digest
    )
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_sha256")
    assert digest == hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()

    output = tmp_path / "receipt.json"
    write_private_receipt(output, receipt)
    assert stat_mode(output) == 0o600
    assert json.loads(output.read_text()) == receipt
    with pytest.raises(FileExistsError):
        write_private_receipt(output, receipt)


def test_java_proposal_and_private_receipt_are_component_bound(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    receipt = build_proposal_receipt(**_java_proposal_kwargs())
    assert receipt["schema"] == "kodesec.trivy-java-db-lock-candidate/v1"
    replacement = receipt["proposed_replacement"]
    assert replacement["source"]["discovery_ref"] == (
        "ghcr.io/aquasecurity/trivy-java-db:1"
    )
    assert replacement["source"]["immutable_ref"].startswith(
        "ghcr.io/aquasecurity/trivy-java-db@sha256:"
    )
    assert [item["id"] for item in replacement["canaries"]] == [
        "java-artifacts-positive",
        "java-artifacts-zero",
    ]

    output = tmp_path / "java-receipt.json"
    write_private_receipt(output, receipt, component_id="trivy-java-db")
    assert output.read_bytes() == canonical_json_bytes(receipt)
    with pytest.raises(CandidateValidationError, match="identity"):
        write_private_receipt(tmp_path / "wrong-profile.json", receipt)


def test_proposal_rejects_unsorted_or_incomplete_canaries() -> None:
    values = _proposal_kwargs()
    values["canaries"] = []
    with pytest.raises(CandidateValidationError):
        build_proposal_receipt(**values)


@pytest.mark.parametrize(
    ("canary_id", "updates", "message"),
    [
        ("source-vulnerabilities-positive", {"exit_code": 1}, "exit successfully"),
        (
            "source-vulnerabilities-positive",
            {"result_count": 0, "ids": []},
            "positive canary",
        ),
        (
            "source-vulnerabilities-zero",
            {"result_count": 1, "ids": ["CVE-1"]},
            "zero canary",
        ),
        (
            "source-vulnerabilities-positive",
            {"fixture_sha256": "9" * 64},
            "fixture differs",
        ),
    ],
)
def test_proposal_rejects_false_canary_semantics(
    canary_id: str, updates: dict[str, object], message: str
) -> None:
    values = _proposal_kwargs()
    canaries = values["canaries"]
    assert isinstance(canaries, list)
    for item in canaries:
        if item["canary_id"] == canary_id:
            item.update(updates)
    with pytest.raises(CandidateValidationError, match=message):
        build_proposal_receipt(**values)


def test_proposal_binds_baked_lock_binary_metadata_and_installed_records() -> None:
    for key, value in (
        ("baked_lock_sha256", "8" * 64),
        ("trivy_executable_path", "/tmp/trivy"),
    ):
        values = _proposal_kwargs()
        values[key] = value
        with pytest.raises(CandidateValidationError):
            build_proposal_receipt(**values)

    values = _proposal_kwargs()
    records = values["installed_records"]
    assert isinstance(records, list)
    records[-1] = CacheFileRecord(path="metadata.json", size_bytes=1, sha256="0" * 64)
    with pytest.raises(CandidateValidationError, match="metadata bytes"):
        build_proposal_receipt(**values)


def test_private_receipt_refuses_unsafe_parent_and_cleans_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = build_proposal_receipt(**_proposal_kwargs())
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(CandidateValidationError, match="owner-only"):
        write_private_receipt(public / "receipt.json", receipt)

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    original_write = candidate.os.write
    calls = 0

    def fail_first_write(descriptor: int, payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected")
        return original_write(descriptor, payload)

    monkeypatch.setattr(candidate.os, "write", fail_first_write)
    with pytest.raises(OSError, match="injected"):
        write_private_receipt(private / "receipt.json", receipt)
    assert list(private.iterdir()) == []


def test_private_receipt_parent_fsync_failure_invalidates_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = build_proposal_receipt(**_proposal_kwargs())
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "receipt.json"
    original_fsync = candidate.os.fsync
    directory_calls = 0

    def fail_first_directory_fsync(descriptor: int) -> None:
        nonlocal directory_calls
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_calls += 1
            if directory_calls == 1:
                raise KeyboardInterrupt("injected parent fsync interrupt")
        original_fsync(descriptor)

    monkeypatch.setattr(candidate.os, "fsync", fail_first_directory_fsync)
    with pytest.raises(KeyboardInterrupt, match="parent fsync interrupt"):
        write_private_receipt(output, receipt)
    assert not output.exists()
    assert list(private.iterdir()) == []


def test_private_receipt_rejects_post_link_hardlink_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = build_proposal_receipt(**_proposal_kwargs())
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "receipt.json"
    alias = private / "hostile-alias"
    original_fsync = candidate.os.fsync
    directory_calls = 0

    def inject_hardlink_before_verification(descriptor: int) -> None:
        nonlocal directory_calls
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_calls += 1
            if directory_calls == 1:
                os.link(output, alias)
        original_fsync(descriptor)

    monkeypatch.setattr(candidate.os, "fsync", inject_hardlink_before_verification)
    with pytest.raises(CandidateValidationError, match="publication identity"):
        write_private_receipt(output, receipt)
    assert not output.exists()
    assert alias.exists()
    assert stat_mode(alias) == 0o000
    assert alias.stat().st_size == len(b"INVALID\n")


class _FakeResponse:
    def __init__(
        self,
        url: str,
        body: bytes,
        *,
        content_type: str,
        digest: str | None = None,
        final_url: str | None = None,
        content_length: int | None = None,
        status: int = 200,
        location: str | None = None,
    ) -> None:
        self.status = status
        self._url = final_url or url
        self._body = io.BytesIO(body)
        self.closed = False
        self.headers = {
            "Content-Type": content_type,
            "Content-Length": str(
                len(body) if content_length is None else content_length
            ),
        }
        if digest is not None:
            self.headers["Docker-Content-Digest"] = digest
        if location is not None:
            self.headers["Location"] = location

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def close(self) -> None:
        self.closed = True


def test_urllib_redirect_handler_exposes_response_without_following() -> None:
    handler = candidate._ExposeRedirectHandler()
    response = object()
    for status in (301, 302, 303, 307, 308):
        method = getattr(handler, f"http_error_{status}")
        assert method(None, response, status, "redirect", {}) is response
    assert "redirect_request" not in candidate._ExposeRedirectHandler.__dict__

    # Building the real opener must install our response handler ahead of
    # urllib's default redirect follower; this remains network-free.
    opener = urllib.request.build_opener(handler)
    installed = [type(item) for item in opener.handlers]
    assert candidate._ExposeRedirectHandler in installed


class _FakeTransport:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, str], float]] = []

    def __call__(
        self, url: str, *, headers: dict[str, str], timeout_seconds: float
    ) -> _FakeResponse:
        self.requests.append((url, dict(headers), timeout_seconds))
        specification = self.responses[url]
        return _FakeResponse(url, **specification)


def _registry_transport(
    layer: bytes,
    *,
    token_body: bytes = b'{"token":"abcdefghijklmnop"}',
    token_final_url: str | None = None,
    config_redirect: str | None = None,
    layer_redirect: str | None = None,
    redirected_responses: dict[str, dict[str, object]] | None = None,
    component_id: str = "trivy-db",
) -> tuple[_FakeTransport, bytes]:
    profile = candidate.candidate_profile(component_id)
    manifest = _manifest(layer=layer, component_id=component_id)
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    base = f"https://ghcr.io/v2/{profile.repository}"
    tag_url = f"{base}/manifests/{profile.reference}"
    digest_url = f"{base}/manifests/{manifest_digest}"
    config_url = f"{base}/blobs/{EMPTY_CONFIG_DIGEST}"
    layer_url = f"{base}/blobs/{layer_digest}"
    responses: dict[str, dict[str, object]] = {
        profile.token_url: {
            "body": token_body,
            "content_type": "application/json; charset=utf-8",
            "final_url": token_final_url,
        },
        tag_url: {
            "body": manifest,
            "content_type": candidate.MANIFEST_MEDIA_TYPE,
            "digest": manifest_digest,
        },
        digest_url: {
            "body": manifest,
            "content_type": candidate.MANIFEST_MEDIA_TYPE,
            "digest": manifest_digest,
        },
        config_url: {
            "body": b"{}",
            "content_type": candidate.EMPTY_CONFIG_MEDIA_TYPE,
            "digest": EMPTY_CONFIG_DIGEST,
            **(
                {"status": 307, "location": config_redirect}
                if config_redirect is not None
                else {}
            ),
        },
        layer_url: {
            "body": layer,
            "content_type": profile.layer_media_type,
            "digest": layer_digest,
            **(
                {"status": 307, "location": layer_redirect}
                if layer_redirect is not None
                else {}
            ),
        },
    }
    responses.update(redirected_responses or {})
    return (
        _FakeTransport(responses),
        manifest,
    )


def _candidate_layer(
    tmp_path: Path,
    *,
    name: str = "registry-layer.tar.gz",
    component_id: str = "trivy-db",
) -> bytes:
    archive = tmp_path / name
    database_name = "trivy.db" if component_id == "trivy-db" else "trivy-java.db"
    metadata = _metadata() if component_id == "trivy-db" else _java_metadata()
    _tar_gz(
        archive,
        [
            (database_name, b"database", "file"),
            ("metadata.json", metadata, "file"),
        ],
    )
    return archive.read_bytes()


def test_fetch_uses_only_fixed_bounded_registry_requests_and_seals_tree(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    layer = _candidate_layer(tmp_path)
    transport, manifest_body = _registry_transport(layer)
    receipt = run_fetch(
        registry="ghcr.io",
        repository="aquasecurity/trivy-db",
        reference="2",
        output_dir=output,
        transport=transport,
        now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
        monotonic=lambda: 1.0,
        invocation_id=INVOCATION_ID,
    )
    raw = canonical_json_bytes(receipt)
    parsed, manifest, metadata, records = validate_fetch_receipt(
        raw, now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC)
    )
    assert parsed == receipt
    assert manifest.manifest_digest == hashlib.sha256(manifest_body).hexdigest()
    assert metadata.next_update == "2026-08-14T11:00:00Z"
    assert [item.path for item in records] == ["metadata.json", "trivy.db"]
    assert {item.name for item in output.iterdir()} == {
        "candidate-db",
        "fetch-receipt.json",
        "layer.tar.gz",
    }
    assert (output / "fetch-receipt.json").read_bytes() == raw
    assert stat_mode(output / "candidate-db") == 0o500
    assert stat_mode(output / "layer.tar.gz") == 0o400
    assert [url for url, _, _ in transport.requests] == [
        candidate.TOKEN_URL,
        "https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2",
        "https://ghcr.io/v2/aquasecurity/trivy-db/manifests/"
        + "sha256:"
        + hashlib.sha256(manifest_body).hexdigest(),
        "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/" + EMPTY_CONFIG_DIGEST,
        "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:"
        + hashlib.sha256(layer).hexdigest(),
    ]
    assert "Authorization" not in transport.requests[0][1]
    assert all(
        headers["Authorization"] == "Bearer abcdefghijklmnop"
        for _, headers, _ in transport.requests[1:]
    )
    assert all(timeout <= 30 for _, _, timeout in transport.requests)


def test_java_fetch_uses_only_fixed_java_registry_and_receipt_contract(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    layer = _candidate_layer(tmp_path, component_id="trivy-java-db")
    transport, manifest_body = _registry_transport(
        layer, component_id="trivy-java-db"
    )
    receipt = run_fetch(
        registry="ghcr.io",
        repository="aquasecurity/trivy-java-db",
        reference="1",
        output_dir=output,
        transport=transport,
        now=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
        monotonic=lambda: 1.0,
        invocation_id=INVOCATION_ID,
        component_id="trivy-java-db",
    )
    raw = canonical_json_bytes(receipt)
    parsed, manifest, metadata, records = validate_fetch_receipt(
        raw,
        now=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
        component_id="trivy-java-db",
    )
    assert parsed["schema"] == "kodesec.trivy-java-db-lock-candidate-fetch/v1"
    assert manifest.manifest_digest == hashlib.sha256(manifest_body).hexdigest()
    assert metadata.maximum_age_seconds == candidate.TRIVY_JAVA_DB_MAX_AGE_SECONDS
    assert [item.path for item in records] == ["metadata.json", "trivy-java.db"]
    profile = candidate.candidate_profile("trivy-java-db")
    assert [url for url, _, _ in transport.requests] == [
        profile.token_url,
        "https://ghcr.io/v2/aquasecurity/trivy-java-db/manifests/1",
        "https://ghcr.io/v2/aquasecurity/trivy-java-db/manifests/"
        + "sha256:"
        + hashlib.sha256(manifest_body).hexdigest(),
        "https://ghcr.io/v2/aquasecurity/trivy-java-db/blobs/"
        + EMPTY_CONFIG_DIGEST,
        "https://ghcr.io/v2/aquasecurity/trivy-java-db/blobs/sha256:"
        + hashlib.sha256(layer).hexdigest(),
    ]
    with pytest.raises(CandidateValidationError):
        validate_fetch_receipt(
            raw,
            now=datetime(2026, 8, 20, 12, 0, tzinfo=UTC),
        )


def test_blob_redirect_allows_one_exact_cdn_hop_and_strips_authorization(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    layer = _candidate_layer(tmp_path)
    config_cdn = "https://pkg-containers.githubusercontent.com/oci/config?sig=abc"
    layer_cdn = "https://pkg-containers.githubusercontent.com/oci/layer?sig=def"
    transport, _ = _registry_transport(
        layer,
        config_redirect=config_cdn,
        layer_redirect=layer_cdn,
        redirected_responses={
            config_cdn: {
                "body": b"{}",
                "content_type": "application/octet-stream",
            },
            layer_cdn: {
                "body": layer,
                "content_type": "application/octet-stream",
            },
        },
    )
    run_fetch(
        registry="ghcr.io",
        repository="aquasecurity/trivy-db",
        reference="2",
        output_dir=output,
        transport=transport,
        now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
        monotonic=lambda: 1.0,
        invocation_id=INVOCATION_ID,
    )
    requests = {url: headers for url, headers, _ in transport.requests}
    assert requests[config_cdn].get("Authorization") is None
    assert requests[layer_cdn].get("Authorization") is None
    assert requests[config_cdn]["Accept-Encoding"] == "identity"
    assert requests[layer_cdn]["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "redirect_url",
    [
        "http://pkg-containers.githubusercontent.com/oci/blob?sig=x",
        "https://pkg-containers.githubusercontent.com.evil.invalid/oci/blob?sig=x",
        "https://evil.invalid/oci/blob?sig=x",
        "https://user@pkg-containers.githubusercontent.com/oci/blob?sig=x",
        "https://pkg-containers.githubusercontent.com:444/oci/blob?sig=x",
        "https://pkg-containers.githubusercontent.com/oci/blob?sig=x#fragment",
        "https://pkg-containers.githubusercontent.com/oci/../blob?sig=x",
    ],
)
def test_blob_redirect_rejects_unreviewed_targets_before_following(
    tmp_path: Path, redirect_url: str
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    transport, _ = _registry_transport(
        _candidate_layer(tmp_path), config_redirect=redirect_url
    )
    with pytest.raises(CandidateValidationError, match="redirect target"):
        run_fetch(
            registry="ghcr.io",
            repository="aquasecurity/trivy-db",
            reference="2",
            output_dir=output,
            transport=transport,
            now=datetime(2026, 8, 26, 23, 0, 1, tzinfo=UTC),
            monotonic=lambda: 1.0,
            invocation_id=INVOCATION_ID,
        )
    assert redirect_url not in [url for url, _, _ in transport.requests]


def test_blob_redirect_rejects_second_redirect_and_wrong_cdn_bytes(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    redirect = "https://pkg-containers.githubusercontent.com/oci/config?sig=abc"
    for name, redirected_response, message in (
        (
            "second",
            {
                "body": b"",
                "content_type": "application/octet-stream",
                "status": 307,
                "location": "https://pkg-containers.githubusercontent.com/oci/again?sig=x",
            },
            "second blob redirect",
        ),
        (
            "wrong",
            {"body": b"xx", "content_type": "application/octet-stream"},
            "empty config bytes",
        ),
    ):
        layer = _candidate_layer(tmp_path, name=f"{name}-layer.tar.gz")
        output = tmp_path / name
        output.mkdir(mode=0o700)
        transport, _ = _registry_transport(
            layer,
            config_redirect=redirect,
            redirected_responses={redirect: redirected_response},
        )
        with pytest.raises(CandidateValidationError, match=message):
            run_fetch(
                registry="ghcr.io",
                repository="aquasecurity/trivy-db",
                reference="2",
                output_dir=output,
                transport=transport,
                now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
                monotonic=lambda: 1.0,
                invocation_id=INVOCATION_ID,
            )


@pytest.mark.parametrize(
    ("token_body", "final_url", "message"),
    [
        (
            b'{"token":"abcdefghijklmnop","token":"abcdefghijklmnop"}',
            None,
            "duplicate",
        ),
        (b'{"token":"abcdefghijklmnop"}', "https://evil.invalid/token", "final URL"),
        (b'{"token":"short"}', None, "malformed"),
    ],
)
def test_fetch_rejects_hostile_token_and_redirect_before_writing(
    tmp_path: Path, token_body: bytes, final_url: str | None, message: str
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    transport, _ = _registry_transport(
        _candidate_layer(tmp_path),
        token_body=token_body,
        token_final_url=final_url,
    )
    with pytest.raises(CandidateValidationError, match=message):
        run_fetch(
            registry="ghcr.io",
            repository="aquasecurity/trivy-db",
            reference="2",
            output_dir=output,
            transport=transport,
            now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
            monotonic=lambda: 1.0,
            invocation_id=INVOCATION_ID,
        )
    assert list(output.iterdir()) == []


def test_fetch_rejects_oversized_claim_and_too_short_remaining_lifetime(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    layer = _candidate_layer(tmp_path)
    transport, _ = _registry_transport(layer)
    transport.responses[candidate.TOKEN_URL]["content_length"] = (
        candidate.MAX_TOKEN_BYTES + 1
    )
    output = tmp_path / "oversized"
    output.mkdir(mode=0o700)
    with pytest.raises(CandidateValidationError, match="length"):
        run_fetch(
            registry="ghcr.io",
            repository="aquasecurity/trivy-db",
            reference="2",
            output_dir=output,
            transport=transport,
            now=datetime(2026, 8, 13, 12, 30, tzinfo=UTC),
            monotonic=lambda: 1.0,
            invocation_id=INVOCATION_ID,
        )

    short_archive = tmp_path / "short.tar.gz"
    _tar_gz(
        short_archive,
        [
            ("trivy.db", b"database", "file"),
            (
                "metadata.json",
                _metadata(next_update="2026-08-13T15:00:00Z"),
                "file",
            ),
        ],
    )
    short_transport, _ = _registry_transport(short_archive.read_bytes())
    short_output = tmp_path / "short-output"
    short_output.mkdir(mode=0o700)
    with pytest.raises(CandidateValidationError, match="lifetime"):
        run_fetch(
            registry="ghcr.io",
            repository="aquasecurity/trivy-db",
            reference="2",
            output_dir=short_output,
            transport=short_transport,
            now=datetime(2026, 8, 26, 23, 0, 1, tzinfo=UTC),
            monotonic=lambda: 1.0,
            invocation_id=INVOCATION_ID,
        )


def _immutable_candidate_db(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    database = cache / "db"
    database.mkdir(mode=0o700)
    (database / "trivy.db").write_bytes(b"database")
    (database / "metadata.json").write_bytes(_metadata())
    for path in database.iterdir():
        path.chmod(0o400)
    database.chmod(0o500)
    return database


class _FakeCanaryRunner:
    def __init__(
        self,
        *,
        returncode: int = 0,
        omitted_results_for: frozenset[str] = frozenset(),
        null_results_for: frozenset[str] = frozenset(),
    ) -> None:
        self.returncode = returncode
        self.omitted_results_for = omitted_results_for
        self.null_results_for = null_results_for
        self.calls: list[tuple[tuple[str, ...], dict[str, str], Path]] = []

    def __call__(
        self,
        argv,
        *,
        cwd,
        environment,
        timeout_seconds,
        result_path=None,
        maximum_result_bytes=candidate.MAX_CANARY_JSON_BYTES,
    ) -> CommandResult:
        assert result_path is not None
        self.calls.append((tuple(argv), dict(environment), result_path))
        canary_kind = "positive" if str(argv[-1]).endswith("positive") else "zero"
        vulnerabilities = (
            [
                {"VulnerabilityID": "CVE-2"},
                {"VulnerabilityID": "CVE-1"},
                {"VulnerabilityID": "CVE-2"},
            ]
            if canary_kind == "positive"
            else []
        )
        payload = {
            "SchemaVersion": 2,
            "Trivy": {"Version": candidate.TRIVY_VERSION},
            "ReportID": "019ffc3c-cb3f-7841-b421-2a9b3a40009c",
            "CreatedAt": "2026-08-13T17:47:50.463542198Z",
            "ArtifactName": str(argv[-1]),
            "ArtifactType": "filesystem",
        }
        if canary_kind not in self.omitted_results_for:
            payload["Results"] = (
                None
                if canary_kind in self.null_results_for
                else [{"Vulnerabilities": vulnerabilities}]
            )
        result_path.write_bytes(json.dumps(payload, separators=(",", ":")).encode())
        return CommandResult(returncode=self.returncode, stdout=b"", stderr=b"")


def test_java_canary_command_is_fixed_offline_rootfs_library_scan() -> None:
    command = candidate._trivy_canary_command(
        candidate_db=Path("/run/kodesec-review/candidate-cache/java-db"),
        fixture=Path(
            "/usr/local/share/kodesec/canaries/trivy/java/"
            "log4j-core-2.14.1.jar"
        ),
        output=Path("/run/kodesec-scratch/result.json"),
        component_id="trivy-java-db",
    )
    assert command[1] == "rootfs"
    assert command[-1].endswith("/trivy/java/log4j-core-2.14.1.jar")
    assert command[command.index("--pkg-types") + 1] == "library"
    assert command[command.index("--parallel") + 1] == "1"
    assert {
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--disable-telemetry",
        "--skip-version-check",
    }.issubset(command)
    digest = candidate._trivy_canary_command_sha256(
        "java-artifacts-positive", "trivy-java-db"
    )
    assert len(digest) == 64
    with pytest.raises(CandidateValidationError, match="unsupported"):
        candidate._trivy_canary_command_sha256(
            "source-vulnerabilities-positive", "trivy-java-db"
        )


@pytest.mark.parametrize(
    ("component_id", "candidate_db", "positive_fixture"),
    [
        (
            "trivy-db",
            "/run/kodesec-review/candidate-cache/java-db",
            "/usr/local/share/kodesec/canaries/trivy/java/"
            "log4j-core-2.14.1.jar",
        ),
        (
            "trivy-java-db",
            "/run/kodesec-review/candidate-cache/db",
            "/run/kodesec-review/positive",
        ),
    ],
)
def test_inner_canary_paths_cannot_cross_component_profiles(
    capsysbinary: pytest.CaptureFixture[bytes],
    component_id: str,
    candidate_db: str,
    positive_fixture: str,
) -> None:
    result = candidate.inner_main(
        [
            "canary",
            "--component-id",
            component_id,
            "--current-lock",
            "/run/kodesec-review/current-lock.json",
            "--candidate-db",
            candidate_db,
            "--positive-fixture",
            positive_fixture,
            "--zero-fixture",
            "/run/kodesec-review/zero",
            "--invocation-id",
            INVOCATION_ID,
        ]
    )
    captured = capsysbinary.readouterr()
    assert result == 2
    assert captured.out == b""
    assert captured.err == b"kodesec_candidate_failure/v1 canary unexpected\n"


def test_canary_uses_db_parent_offline_sterile_env_and_strict_semantics(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    database = _immutable_candidate_db(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    runner = _FakeCanaryRunner(omitted_results_for=frozenset({"zero"}))
    receipt = run_canary(
        current_lock=ROOT / "scanner-tools.lock.json",
        candidate_db=database,
        positive_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/positive",
        zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
        scratch_root=scratch,
        runner=runner,
        invocation_id=INVOCATION_ID,
    )
    parsed, proposal_canaries = validate_canary_receipt(canonical_json_bytes(receipt))
    assert parsed == receipt
    assert proposal_canaries[0]["result_count"] == 3
    assert proposal_canaries[0]["ids"] == ["CVE-1", "CVE-2"]
    assert proposal_canaries[1]["ids"] == []
    assert len(runner.calls) == 2
    for argv, environment, _ in runner.calls:
        cache_index = argv.index("--cache-dir")
        assert argv[cache_index + 1] == str(database.parent)
        assert "--offline-scan" in argv
        assert "--skip-db-update" in argv
        assert not any("proxy" in key.lower() for key in environment)
        assert environment["HOME"].startswith(str(scratch))


def _real_zero_canary_output(*, include_null_results: bool = False) -> bytes:
    raw = (
        b'{\n  "SchemaVersion": 2,\n  "Trivy": {\n'
        b'    "Version": "0.73.0"\n  },\n'
        b'  "ReportID": "019ffc3c-cb3f-7841-b421-2a9b3a40009c",\n'
        b'  "CreatedAt": "2026-08-13T17:47:50.463542198Z",\n'
        b'  "ArtifactName": "/fixture",\n'
        b'  "ArtifactType": "filesystem"\n}\n'
    )
    if not include_null_results:
        return raw
    payload = json.loads(raw)
    payload["Results"] = None
    return json.dumps(payload, separators=(",", ":")).encode()


@pytest.mark.parametrize("include_null_results", [False, True])
def test_canary_json_accepts_bound_real_zero_result_shape(
    include_null_results: bool,
) -> None:
    assert parse_trivy_canary_json(
        _real_zero_canary_output(include_null_results=include_null_results),
        canary_id="source-vulnerabilities-zero",
        expected_artifact_name="/fixture",
    ) == (0, [])


def test_canary_json_rejects_truncated_bare_schema() -> None:
    with pytest.raises(CandidateValidationError):
        parse_trivy_canary_json(
            b'{"SchemaVersion":2}',
            canary_id="source-vulnerabilities-zero",
            expected_artifact_name="/fixture",
        )


@pytest.mark.parametrize("results", [False, "none", 0, {}])
def test_canary_json_rejects_wrong_type_results(results: object) -> None:
    payload = json.loads(_real_zero_canary_output())
    payload["Results"] = results

    with pytest.raises(CandidateValidationError):
        parse_trivy_canary_json(
            json.dumps(payload, separators=(",", ":")).encode(),
            canary_id="source-vulnerabilities-zero",
            expected_artifact_name="/fixture",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Trivy", {"Version": "0.73.1"}),
        ("Trivy", {"Version": "0.73.0", "extra": True}),
        ("ReportID", "not-a-uuid"),
        ("CreatedAt", "2026-02-30T17:47:50Z"),
        ("ArtifactName", "/different-fixture"),
        ("ArtifactType", "container_image"),
    ],
)
def test_canary_json_rejects_empty_result_envelope_drift(
    field: str, value: object
) -> None:
    payload = json.loads(_real_zero_canary_output())
    payload[field] = value

    with pytest.raises(CandidateValidationError):
        parse_trivy_canary_json(
            json.dumps(payload, separators=(",", ":")).encode(),
            canary_id="source-vulnerabilities-zero",
            expected_artifact_name="/fixture",
        )


def test_canary_json_allows_inert_extra_empty_envelope_field() -> None:
    payload = json.loads(_real_zero_canary_output())
    payload["extra"] = "field"

    assert parse_trivy_canary_json(
        json.dumps(payload, separators=(",", ":")).encode(),
        canary_id="source-vulnerabilities-zero",
        expected_artifact_name="/fixture",
    ) == (0, [])


def test_canary_json_rejects_duplicate_nonfinite_and_malformed_results() -> None:
    for raw in (
        b'{"SchemaVersion":2,"SchemaVersion":2,"Results":[]}',
        b'{"SchemaVersion":2,"Results":[],"x":NaN}',
    ):
        with pytest.raises(CandidateValidationError):
            parse_trivy_canary_json(raw)

    payload = json.loads(_real_zero_canary_output())
    payload["Results"] = [{"Vulnerabilities": [{}]}]
    with pytest.raises(CandidateValidationError):
        parse_trivy_canary_json(
            json.dumps(payload, separators=(",", ":")).encode(),
            canary_id="source-vulnerabilities-positive",
            expected_artifact_name="/fixture",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Trivy", {"Version": "0.73.1"}),
        ("ArtifactName", "/different-fixture"),
    ],
)
def test_canary_json_rejects_list_result_envelope_drift(
    field: str, value: object
) -> None:
    payload = json.loads(_real_zero_canary_output())
    payload["Results"] = [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}]
    payload[field] = value

    with pytest.raises(CandidateValidationError):
        parse_trivy_canary_json(
            json.dumps(payload, separators=(",", ":")).encode(),
            canary_id="source-vulnerabilities-positive",
            expected_artifact_name="/fixture",
        )


@pytest.mark.parametrize("empty_results_form", ["omitted", "null"])
def test_canary_rejects_omitted_or_null_results_for_positive_fixture_as_output(
    tmp_path: Path, empty_results_form: str
) -> None:
    tmp_path.chmod(0o700)
    database = _immutable_candidate_db(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)

    with pytest.raises(
        candidate._InnerFailure,
    ) as captured:
        runner = _FakeCanaryRunner(
            omitted_results_for=(
                frozenset({"positive"})
                if empty_results_form == "omitted"
                else frozenset()
            ),
            null_results_for=(
                frozenset({"positive"}) if empty_results_form == "null" else frozenset()
            ),
        )
        run_canary(
            current_lock=ROOT / "scanner-tools.lock.json",
            candidate_db=database,
            positive_fixture=ROOT
            / "tests/scanner-runtime/fixtures/dependencies/positive",
            zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
            scratch_root=scratch,
            runner=runner,
            invocation_id=INVOCATION_ID,
        )
    assert captured.value.mode == "canary"
    assert captured.value.code == "output"


def test_canary_rejects_empty_results_list_for_positive_fixture_semantically(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    database = _immutable_candidate_db(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)

    class _EmptyPositiveListRunner(_FakeCanaryRunner):
        def __call__(self, argv, **kwargs) -> CommandResult:
            result = super().__call__(argv, **kwargs)
            if str(argv[-1]).endswith("positive"):
                result_path = kwargs["result_path"]
                payload = json.loads(result_path.read_bytes())
                payload["Results"] = []
                result_path.write_bytes(
                    json.dumps(payload, separators=(",", ":")).encode()
                )
            return result

    with pytest.raises(
        candidate._InnerFailure,
        match="positive canary produced no vulnerabilities",
    ) as captured:
        run_canary(
            current_lock=ROOT / "scanner-tools.lock.json",
            candidate_db=database,
            positive_fixture=ROOT
            / "tests/scanner-runtime/fixtures/dependencies/positive",
            zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
            scratch_root=scratch,
            runner=_EmptyPositiveListRunner(),
            invocation_id=INVOCATION_ID,
        )
    assert captured.value.mode == "canary"
    assert captured.value.code == "semantics"


def test_canary_rejects_nonzero_process_even_with_valid_output(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    database = _immutable_candidate_db(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    with pytest.raises(CandidateValidationError, match="exit successfully"):
        run_canary(
            current_lock=ROOT / "scanner-tools.lock.json",
            candidate_db=database,
            positive_fixture=ROOT
            / "tests/scanner-runtime/fixtures/dependencies/positive",
            zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
            scratch_root=scratch,
            runner=_FakeCanaryRunner(returncode=7),
            invocation_id=INVOCATION_ID,
        )


@pytest.mark.parametrize(
    "phase",
    ["input", "fixtures", "candidate_tree", "command", "output", "semantics"],
)
def test_canary_assigns_every_allowlisted_failure_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    tmp_path.chmod(0o700)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    candidate_db = tmp_path / "cache" / ("wrong" if phase == "input" else "db")
    candidate_db.parent.mkdir(mode=0o700)
    candidate_db.mkdir(mode=0o500)
    canaries = _current_canaries()
    current = SimpleNamespace(sha256="1" * 64, path=Path("current.json"))

    monkeypatch.setattr(
        candidate,
        "_trivy_requirement_contract",
        lambda _path: (current, canaries),
    )

    def fixture(*_args, **_kwargs) -> None:
        if phase == "fixtures":
            raise CandidateValidationError("secret fixture detail")

    def tree(*_args, **_kwargs):
        if phase == "candidate_tree":
            raise candidate.CacheValidationError("secret candidate-tree detail")
        return SimpleNamespace(
            algorithm="kodesec-canonical-tree-v1",
            sha256="2" * 64,
            file_count=1,
            size_bytes=1,
            files=[SimpleNamespace(path="metadata.json")],
        )

    def runner(
        argv,
        *,
        cwd,
        environment,
        timeout_seconds,
        result_path=None,
        maximum_result_bytes=candidate.MAX_CANARY_JSON_BYTES,
    ) -> CommandResult:
        del cwd, environment, timeout_seconds, maximum_result_bytes
        assert result_path is not None
        if phase == "command":
            return CommandResult(returncode=7, stdout=b"", stderr=b"secret")
        if phase == "output":
            result_path.write_bytes(b"{")
        else:
            result_path.write_bytes(
                json.dumps(
                    {
                        "SchemaVersion": 2,
                        "Trivy": {"Version": candidate.TRIVY_VERSION},
                        "ReportID": "019ffc3c-cb3f-7841-b421-2a9b3a40009c",
                        "CreatedAt": "2026-08-13T17:47:50.463542198Z",
                        "ArtifactName": str(argv[-1]),
                        "ArtifactType": "filesystem",
                        "Results": [],
                    },
                    separators=(",", ":"),
                ).encode()
            )
        return CommandResult(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(candidate, "_verify_fixture_tree", fixture)
    monkeypatch.setattr(candidate, "collect_canonical_tree", tree)
    with pytest.raises(candidate._InnerFailure) as captured:
        run_canary(
            current_lock=Path("current.json"),
            candidate_db=candidate_db,
            positive_fixture=Path("positive"),
            zero_fixture=Path("zero"),
            scratch_root=scratch,
            runner=runner,
            invocation_id=INVOCATION_ID,
        )
    assert captured.value.mode == "canary"
    assert captured.value.code == phase


def test_preflight_binds_exact_locks_binary_manifest_fixtures_and_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    current = tmp_path / "current.json"
    baked = tmp_path / "baked.json"
    shutil.copyfile(ROOT / "scanner-tools.lock.json", current)
    shutil.copyfile(ROOT / "scanner-tools.lock.json", baked)
    trivy = tmp_path / "trivy"
    trivy.write_bytes(b"reviewed-trivy")
    trivy.chmod(0o755)
    trivy_sha256 = hashlib.sha256(b"reviewed-trivy").hexdigest()
    tools: dict[str, object] = {
        tool_id: {
            "command": candidate.TOOL_VERSION_COMMANDS[tool_id],
            "installed_version": candidate.EXTERNAL_TOOL_VERSIONS[tool_id],
            "path": f"/usr/local/bin/{tool_id}",
            "sha256": hashlib.sha256(tool_id.encode()).hexdigest(),
        }
        for tool_id in candidate.EXTERNAL_TOOL_IDS
    }
    tools["opengrep"]["runtime_components"] = {
        "opengrep_core": {
            "path": "/usr/local/share/kodesec/opengrep-home/opengrep.bin",
            "sha256": "a" * 64,
        }
    }
    bearer_build = {
        "kind": "bearer-source-build", "recipe_sha256": "a" * 64,
        "receipt_sha256": "b" * 64, "platform": "linux/arm64",
        "binary_sha256": tools["bearer"]["sha256"],
    }
    tools["bearer"]["source_build"] = bearer_build

    def source_build_verifier(locked, binary):
        assert locked == candidate.load_tool_lock(baked).value.tool("bearer").binary.source_build
        assert binary == Path("/usr/local/bin/bearer")
        return bearer_build

    monkeypatch.setattr(candidate, "verify_source_build", source_build_verifier)
    tools["trivy"] = {
        "command": ["trivy", "--version"],
        "installed_version": "0.73.0",
        "path": str(trivy),
        "sha256": trivy_sha256,
    }
    manifest = tmp_path / "tool-manifest.json"
    manifest.write_bytes(canonical_json_bytes({"schema_version": 1, "tools": tools}))
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)

    def version_runner(*_args, **_kwargs) -> CommandResult:
        return CommandResult(returncode=0, stdout=b"Version: 0.73.0\n", stderr=b"")

    monkeypatch.setattr(candidate, "TRIVY_EXECUTABLE_PATH", str(trivy))
    receipt = run_preflight(
        current_lock=current,
        baked_lock=baked,
        trivy_path=trivy,
        tool_manifest=manifest,
        positive_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/positive",
        zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
        expected_architecture="arm64",
        scratch_root=scratch,
        runner=version_runner,
        machine_provider=lambda: "aarch64",
        executable_uid=os.getuid(),
        invocation_id=INVOCATION_ID,
    )
    parsed = validate_preflight_receipt(canonical_json_bytes(receipt))
    assert parsed["current_lock_sha256"] == parsed["baked_lock_sha256"]
    assert parsed["scanner"]["trivy_executable_sha256"] == trivy_sha256
    assert parsed["scanner"]["implementation_bundle"] == (
        candidate.implementation_bundle_evidence(
            Path(candidate.__file__).resolve(strict=True).parent,
            expected_uid=os.getuid(),
        )
    )

    for mutation in ("missing", "receipt", "binary", "extra", "unlocked"):
        changed = json.loads(manifest.read_bytes())
        entry = changed["tools"]["bearer"]
        if mutation == "missing":
            del entry["source_build"]
        elif mutation == "receipt":
            entry["source_build"]["receipt_sha256"] = "c" * 64
        elif mutation == "binary":
            entry["sha256"] = "c" * 64
        elif mutation == "extra":
            entry["source_build"]["unknown"] = True
        else:
            changed["tools"]["trivy"]["source_build"] = bearer_build
        with pytest.raises(CandidateValidationError):
            candidate._validate_tool_manifest(
                canonical_json_bytes(changed), trivy_path=trivy,
                trivy_sha256=trivy_sha256, tool_lock_path=baked,
            )

    baked.write_bytes(baked.read_bytes() + b"\n")
    with pytest.raises(CandidateValidationError, match="locks differ"):
        run_preflight(
            current_lock=current,
            baked_lock=baked,
            trivy_path=trivy,
            tool_manifest=manifest,
            positive_fixture=ROOT
            / "tests/scanner-runtime/fixtures/dependencies/positive",
            zero_fixture=ROOT / "tests/scanner-runtime/fixtures/dependencies/zero",
            expected_architecture="arm64",
            scratch_root=scratch,
            runner=version_runner,
            machine_provider=lambda: "aarch64",
            executable_uid=os.getuid(),
            invocation_id=INVOCATION_ID,
        )


@pytest.mark.parametrize(
    "phase",
    [
        "architecture",
        "current_lock",
        "baked_lock",
        "lock_binding",
        "fixtures",
        "trivy_binary",
        "tool_manifest",
        "implementation_bundle",
        "version_probe",
    ],
)
def test_preflight_assigns_every_allowlisted_failure_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    tmp_path.chmod(0o700)
    current = tmp_path / "current.json"
    baked = tmp_path / "baked.json"
    trivy = tmp_path / "trivy"
    manifest = tmp_path / "tool-manifest.json"
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    canaries = _current_canaries()

    def contract(path: Path):
        if phase == "current_lock" and path == current:
            raise CandidateValidationError("secret current-lock detail")
        if phase == "baked_lock" and path == baked:
            raise CandidateValidationError("secret baked-lock detail")
        digest = "2" * 64 if phase == "lock_binding" and path == baked else "1" * 64
        return SimpleNamespace(sha256=digest, path=path), canaries

    def fixture(*_args, **_kwargs) -> None:
        if phase == "fixtures":
            raise CandidateValidationError("secret fixture detail")

    def binary(*_args, **_kwargs) -> str:
        if phase == "trivy_binary":
            raise CandidateValidationError("secret binary detail")
        return "3" * 64

    def manifest_bytes(*_args, **_kwargs) -> bytes:
        if phase == "tool_manifest":
            raise CandidateValidationError("secret manifest detail")
        return b"reviewed-manifest"

    def implementation(*_args, **_kwargs) -> dict[str, object]:
        if phase == "implementation_bundle":
            raise CandidateValidationError("secret implementation detail")
        return {"sha256": "5" * 64}

    def version(*_args, **_kwargs) -> CommandResult:
        if phase == "version_probe":
            return CommandResult(returncode=7, stdout=b"", stderr=b"secret")
        return CommandResult(returncode=0, stdout=b"Version: 0.73.0\n", stderr=b"")

    monkeypatch.setattr(candidate, "_trivy_requirement_contract", contract)
    monkeypatch.setattr(candidate, "_verify_fixture_tree", fixture)
    monkeypatch.setattr(candidate, "_regular_file_sha256", binary)
    monkeypatch.setattr(candidate, "_bounded_regular_bytes", manifest_bytes)
    monkeypatch.setattr(
        candidate, "_validate_tool_manifest", lambda *_a, **_k: "4" * 64
    )
    monkeypatch.setattr(candidate, "implementation_bundle_evidence", implementation)

    with pytest.raises(candidate._InnerFailure) as captured:
        run_preflight(
            current_lock=current,
            baked_lock=baked,
            trivy_path=trivy,
            tool_manifest=manifest,
            positive_fixture=tmp_path / "positive",
            zero_fixture=tmp_path / "zero",
            expected_architecture="arm64",
            scratch_root=scratch,
            runner=version,
            machine_provider=(
                (lambda: "amd64") if phase == "architecture" else (lambda: "arm64")
            ),
            executable_uid=os.getuid(),
            invocation_id=INVOCATION_ID,
        )
    assert captured.value.mode == "preflight"
    assert captured.value.code == phase


def test_inner_entrypoint_emits_exactly_one_canonical_receipt(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    receipt = candidate._seal_receipt(
        {
            "schema": "test/v1",
            "value": "exact",
        }
    )

    class _Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "fetch",
                    "registry": "ghcr.io",
                    "repository": "aquasecurity/trivy-db",
                    "reference": "2",
                    "output_dir": Path("/run/kodesec-review/output"),
                    "invocation_id": INVOCATION_ID,
                },
            )()

    monkeypatch.setattr(candidate, "_inner_parser", lambda: _Parser())
    monkeypatch.setattr(candidate, "run_fetch", lambda **_kwargs: receipt)
    assert candidate.inner_main([]) == 0
    captured = capsysbinary.readouterr()
    assert captured.out == canonical_json_bytes(receipt)
    assert captured.err == b""


def test_inner_java_canary_forwards_exact_os_support_cache_child(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    receipt = candidate._seal_receipt({"schema": "test/v1", "value": "java"})
    observed: dict[str, object] = {}

    class _Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "canary",
                    "component_id": "trivy-java-db",
                    "current_lock": candidate._INNER_CURRENT_LOCK,
                    "candidate_db": candidate._INNER_CANDIDATE_JAVA_DB,
                    "support_trivy_db": candidate._INNER_CANDIDATE_DB,
                    "positive_fixture": candidate._INNER_JAVA_POSITIVE,
                    "zero_fixture": candidate._INNER_ZERO,
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def run(**kwargs):
        observed.update(kwargs)
        return receipt

    monkeypatch.setattr(candidate, "_inner_parser", lambda: _Parser())
    monkeypatch.setattr(candidate, "run_canary", run)
    assert candidate.inner_main([]) == 0
    assert observed["support_trivy_db"] == candidate._INNER_CANDIDATE_DB
    assert observed["component_id"] == "trivy-java-db"
    captured = capsysbinary.readouterr()
    assert captured.out == canonical_json_bytes(receipt)
    assert captured.err == b""
