"""Real SQLite effects at the Grype lock, updater and sealed-cache boundaries."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
import xxhash
from pydantic import ValidationError

from kodesec_scanner import cache_manifest as cache
from kodesec_scanner import grype_identity
from kodesec_scanner import updater


ROOT = Path(__file__).resolve().parents[3]
TOOLS = cache.load_tool_lock(ROOT / "scanner-tools.lock.json")


@pytest.fixture(autouse=True)
def _isolated_grype_proofs():
    cache.clear_grype_logical_proof_cache()
    yield
    cache.clear_grype_logical_proof_cache()


def _database(root: Path, *, reverse_indexes: bool = False) -> cache.CanonicalTree:
    target = root / "6"
    target.mkdir(parents=True, mode=0o700)
    path = target / "vulnerability.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT, severity INTEGER)")
        db.executemany("INSERT INTO packages VALUES (?,?,?)", [(i, f"package-{i}", i % 5) for i in range(120)])
        indexes = ["CREATE INDEX by_name ON packages(name)", "CREATE INDEX by_severity ON packages(severity)"]
        for statement in reversed(indexes) if reverse_indexes else indexes:
            db.execute(statement)
    path.chmod(0o600)
    _import_record(target)
    return cache.collect_canonical_tree(root)


def _import_record(target: Path, *, digest: str | None = None) -> None:
    physical = (target / "vulnerability.db").read_bytes()
    metadata = {"digest": digest or "xxh64:" + xxhash.xxh64(physical).hexdigest(), "source": "manual import", "client_version": "v6.1.9"}
    path = target / "import.json"
    path.write_text(json.dumps(metadata, indent=" ") + "\n")
    path.chmod(0o600)


def _requirement(tree: cache.CanonicalTree, logical: cache.GrypeLogicalContentReceipt):
    value = TOOLS.value.tool("grype").requirements[0].model_dump(mode="json")
    value.update(installed_size_bytes=tree.size_bytes, installed_content={
        "hash_algorithm": cache.GRYPE_LOGICAL_TREE_HASH_ALGORITHM,
        "sha256": cache.canonical_tree_sha256(cache.grype_logical_tree_records(tree.files, logical)),
        "file_count": tree.file_count, "size_bytes": tree.size_bytes, "volatile_paths": [],
    })
    return cache.ComponentRequirementLock.model_validate(value)


def _receipt(tree: cache.CanonicalTree, logical: cache.GrypeLogicalContentReceipt):
    return cache.CacheComponentReceipt(
        component_id="grype-db", tool_id="grype", kind="database", root="grype",
        immutable_ref="https://grype.anchore.io/databases/v6/synthetic.tar.zst",
        source_sha256="a" * 64, updated_at="2026-09-07T06:38:20Z", expires_at="2026-09-14T06:38:20Z",
        files=[item.model_copy(update={"path": "grype/" + item.path}) for item in tree.files],
        canaries=[cache.CanaryReceipt(canary_id="synthetic-zero", fixture_sha256="b" * 64,
            output_sha256="c" * 64, exit_code=0, result_count=0, expected_ids=[], observed_ids=[], passed=True)],
        grype_logical_content=logical,
    )


def test_grype_failure_phase_survives_content_boundary_without_retaining_proof(tmp_path, monkeypatch):
    tree = _database(tmp_path)
    timing = grype_identity.GrypeValidationTiming("sqlite_integrity", 500, 600, False)
    failure = grype_identity.GrypeIdentityError("deadline")
    failure.validation_timing = timing

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", fail)
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(tmp_path, tree.files)
    assert caught.value.code == "deadline"
    assert caught.value.retryable
    assert caught.value.validation_timing is timing
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


def test_grype_cache_contract_accepts_only_verified_alternate_index_layout(tmp_path: Path):
    first, second = tmp_path / "first", tmp_path / "second"
    tree_a = _database(first)
    tree_b = _database(second, reverse_indexes=True)
    assert tree_a.sha256 != tree_b.sha256
    logical_a = cache.verify_grype_logical_content(first, tree_a.files)
    logical_b = cache.verify_grype_logical_content(second, tree_b.files)
    assert logical_a == logical_b
    requirement = _requirement(tree_a, logical_a)
    updater._validate_installed_content(tree_b, requirement, grype_logical_content=logical_b)
    receipt = _receipt(tree_b, logical_b)
    assert cache.receipt_matches_installed_content(receipt, requirement)
    assert not cache.receipt_matches_installed_content(receipt.model_copy(update={"grype_logical_content": None}), requirement)
    with pytest.raises(updater.OperationError, match="missing"):
        updater._validate_installed_content(tree_b, requirement)


@pytest.mark.parametrize("mutation", ["checksum", "source", "client_version", "extra", "duplicate"])
def test_grype_cache_contract_rejects_untrusted_import_record(tmp_path: Path, mutation: str):
    root = tmp_path / "grype"
    _database(root)
    path = root / "6/import.json"
    metadata = json.loads(path.read_text())
    if mutation == "duplicate":
        path.write_text('{"digest":"xxh64:0000000000000000",' + path.read_text()[1:])
    else:
        metadata[{"checksum": "digest", "extra": "unexpected"}.get(mutation, mutation)] = {
            "checksum": "xxh64:0000000000000000", "source": "unapproved", "client_version": "v7.0.0", "extra": "data"
        }[mutation]
        path.write_text(json.dumps(metadata))
    tree = cache.collect_canonical_tree(root)
    with pytest.raises(cache.GrypeContentValidationError, match="import_"):
        cache.verify_grype_logical_content(root, tree.files)


def test_grype_cache_contract_rejects_wrong_component_and_volatile_override(tmp_path: Path):
    root = tmp_path / "grype"
    tree = _database(root)
    logical = cache.verify_grype_logical_content(root, tree.files)
    value = _requirement(tree, logical).model_dump(mode="json")
    for change in ({"id": "trivy-db"}, {"cache_subpath": "elsewhere"},
        {"installed_content": {**value["installed_content"], "volatile_paths": ["6/import.json"]}}):
        with pytest.raises(ValidationError, match="exact Grype v6"):
            cache.ComponentRequirementLock.model_validate({**value, **change})
    with pytest.raises(ValidationError, match="exact Grype component"):
        cache.CacheComponentReceipt.model_validate({**_receipt(tree, logical).model_dump(mode="json"), "tool_id": "trivy"})


def _sealed_generation(tmp_path: Path, *, forged_manifest: bool = False,
                       later_component: bool = False):
    cache_root = tmp_path / "cache"
    stage = cache_root / "generations/stage"
    grype_root = stage / "grype"
    tree = _database(grype_root)
    logical = cache.verify_grype_logical_content(grype_root, tree.files)
    if forged_manifest:
        # Attacker recomputes file/manifest hashes but retains the reviewed logical claim.
        with sqlite3.connect(grype_root / "6/vulnerability.db") as db:
            db.execute("UPDATE packages SET name='changed' WHERE id=1")
        _import_record(grype_root / "6")
        tree = cache.collect_canonical_tree(grype_root)
    components = [_receipt(tree, logical)]
    if later_component:
        extra_path = stage / "trivy/db/metadata.json"
        extra_path.parent.mkdir(parents=True)
        extra_path.write_bytes(b"later component")
        extra_path.chmod(0o600)
        components.append(cache.CacheComponentReceipt(
            component_id="trivy-db", tool_id="trivy", kind="database", root="trivy/db",
            immutable_ref="ghcr.io/aquasecurity/trivy-db@sha256:" + "a" * 64,
            source_sha256="a" * 64, updated_at="2026-09-07T07:00:00Z",
            expires_at="2026-09-14T07:00:00Z",
            files=[cache.CacheFileRecord(path="trivy/db/metadata.json",
                size_bytes=len(b"later component"),
                sha256=hashlib.sha256(b"later component").hexdigest())],
            canaries=[cache.CanaryReceipt(canary_id="synthetic-later",
                fixture_sha256="b" * 64, output_sha256="c" * 64, exit_code=0,
                result_count=0, expected_ids=[], observed_ids=[], passed=True)],
        ))
    manifest = cache.GenerationManifest.create(tool_lock_sha256=TOOLS.sha256, rules_lock_sha256="d" * 64,
        created_at="2026-09-07T07:00:00Z", components=components)
    destination = stage.parent / manifest.generation_id
    stage.rename(destination)
    cache.write_generation_manifest(destination, manifest)
    return cache_root, manifest, destination


@pytest.mark.parametrize("forged_manifest", [False, True])
def test_grype_cache_contract_revalidates_actual_database_not_manifest_claim(tmp_path: Path, forged_manifest: bool):
    cache_root, manifest, destination = _sealed_generation(tmp_path, forged_manifest=forged_manifest)
    if forged_manifest:
        with pytest.raises(cache.GrypeContentValidationError, match="data"):
            cache.validate_generation(cache_root, manifest.generation_id)
    else:
        assert cache.validate_generation(cache_root, manifest.generation_id).manifest == manifest
        path = destination / "grype/6/vulnerability.db"
        path.chmod(0o600)
        with path.open("r+b") as stream:
            stream.seek(128)
            stream.write(b"changed")
        path.chmod(0o400)
        with pytest.raises(cache.GrypeContentValidationError):
            cache.validate_generation(cache_root, manifest.generation_id)


@pytest.mark.parametrize("cancel", [False, True])
def test_grype_generation_activity_precedes_completed_bytes_and_keeps_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool,
):
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    observations = []
    checkpoints = 0
    failure = updater.OperationStateError("cancelled")
    original = cache.verify_grype_logical_content

    def checkpoint():
        nonlocal checkpoints
        checkpoints += 1

    def verify(root, files, *, checkpoint, _observation_sink):
        assert observations == [("grype-db", 1, 1, 0, manifest.total_size_bytes)]
        if cancel:
            raise failure
        before = checkpoints
        result = original(root, files, checkpoint=checkpoint,
            _observation_sink=_observation_sink)
        assert checkpoints > before
        assert observations[-1][3] == 0
        return result

    monkeypatch.setattr(cache, "verify_grype_logical_content", verify)
    if cancel:
        with pytest.raises(updater.OperationStateError) as caught:
            cache.validate_generation(cache_root, manifest.generation_id,
                checkpoint=checkpoint, progress=lambda *values: observations.append(values))
        assert caught.value is failure
        assert observations[-1][3] == 0
    else:
        cache.validate_generation(cache_root, manifest.generation_id,
            checkpoint=checkpoint, progress=lambda *values: observations.append(values))
        assert observations[-1][3:] == (manifest.total_size_bytes, manifest.total_size_bytes)


def test_generation_reuses_only_its_own_fresh_grype_database_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    cache.clear_grype_logical_proof_cache()
    logical_calls = _logical_calls(monkeypatch)
    physical_reads = []
    manifest_reads = []
    original_observe = grype_identity.observe_grype_file
    original_hash = cache._hash_generation_file

    def observe(path, **kwargs):
        physical_reads.append(path)
        return original_observe(path, **kwargs)

    def hash_file(path, *args):
        manifest_reads.append(path)
        return original_hash(path, *args)

    monkeypatch.setattr(grype_identity, "observe_grype_file", observe)
    monkeypatch.setattr(cache, "_hash_generation_file", hash_file)
    for _ in range(2):
        progress = []
        assert cache.validate_generation(cache_root, manifest.generation_id,
            progress=lambda *values: progress.append(values)).manifest == manifest
        assert progress[-1][3:] == (manifest.total_size_bytes, manifest.total_size_bytes)
    assert len(logical_calls) == 1
    # The first cold proof reads the DB inside the combined SQL computation;
    # the later warm proof uses the observe-first path. Both physically read it.
    assert [path.name for path in physical_reads] == [
        "import.json", "import.json", "vulnerability.db",
    ]
    assert [path.name for path in manifest_reads] == ["import.json"] * 2


@pytest.mark.parametrize("mutation", ["bytes", "sidecar", "cancel"])
def test_generation_reused_hash_keeps_final_progress_fence(
    tmp_path: Path, mutation: str,
):
    cache_root, manifest, generation = _sealed_generation(tmp_path)
    database = generation / "grype" / cache.GRYPE_DATABASE_PATH
    failure = updater.OperationStateError("cancelled")
    changed = False

    def progress(component_id, _index, _total, completed, total):
        nonlocal changed
        if component_id != "grype-db" or completed != total or changed:
            return
        changed = True
        if mutation == "bytes":
            database.chmod(0o600)
            with database.open("r+b") as stream:
                stream.seek(128)
                stream.write(b"changed")
            database.chmod(0o400)
        elif mutation == "sidecar":
            database.parent.chmod(0o700)
            database.with_name(database.name + "-wal").write_bytes(b"changed")
            database.parent.chmod(0o500)
        else:
            raise failure

    error = updater.OperationStateError if mutation == "cancel" else cache.GrypeContentValidationError
    with pytest.raises(error) as caught:
        cache.validate_generation(cache_root, manifest.generation_id, progress=progress)
    if mutation == "cancel":
        assert caught.value is failure
    else:
        assert caught.value.code in {"changed", "file"}
    assert changed


def test_generation_hashes_database_if_verifier_does_not_supply_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    original_verify = cache.verify_grype_logical_content
    original_hash = cache._hash_generation_file
    hashed = []

    def verify(root, files, *, checkpoint, _observation_sink):
        assert not _observation_sink
        return original_verify(root, files, checkpoint=checkpoint)

    def hash_file(path, *args):
        hashed.append(path.name)
        return original_hash(path, *args)

    monkeypatch.setattr(cache, "verify_grype_logical_content", verify)
    monkeypatch.setattr(cache, "_hash_generation_file", hash_file)
    cache.validate_generation(cache_root, manifest.generation_id)
    assert hashed == ["import.json", "vulnerability.db"]


@pytest.mark.parametrize("mismatch", ["path", "sha256", "size_bytes"])
def test_generation_refuses_mismatched_internal_grype_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str,
):
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    original_verify = cache.verify_grype_logical_content

    def verify(root, files, *, checkpoint, _observation_sink):
        result = original_verify(root, files, checkpoint=checkpoint,
            _observation_sink=_observation_sink)
        observation = _observation_sink[0]
        value = {
            "path": {"_path": observation._path.with_name("different.db")},
            "sha256": {"sha256": "0" * 64},
            "size_bytes": {"size_bytes": observation.size_bytes + 1},
        }[mismatch]
        _observation_sink[0] = replace(observation, **value)
        return result

    monkeypatch.setattr(cache, "verify_grype_logical_content", verify)
    with pytest.raises(cache.CacheValidationError, match="observation does not match"):
        cache.validate_generation(cache_root, manifest.generation_id)


def test_generation_rechecks_grype_after_final_cancellation_callback(
    tmp_path: Path,
):
    cache_root, manifest, generation = _sealed_generation(tmp_path)
    database = generation / "grype" / cache.GRYPE_DATABASE_PATH
    completed = False
    mutated = False

    def progress(component_id, _index, _total, observed, total):
        nonlocal completed
        if component_id == "grype-db" and observed == total:
            completed = True

    def checkpoint():
        nonlocal mutated
        if completed and not mutated:
            database.chmod(0o600)
            with database.open("r+b") as stream:
                stream.seek(128)
                stream.write(b"changed")
            database.chmod(0o400)
            mutated = True

    with pytest.raises(cache.GrypeContentValidationError, match="changed"):
        cache.validate_generation(cache_root, manifest.generation_id,
            checkpoint=checkpoint, progress=progress)
    assert completed and mutated


def test_generation_rechecks_grype_after_later_component_callback(
    tmp_path: Path,
):
    cache_root, manifest, generation = _sealed_generation(tmp_path, later_component=True)
    database = generation / "grype" / cache.GRYPE_DATABASE_PATH
    changed = False

    def progress(component_id, _index, _total, observed, _size):
        nonlocal changed
        if component_id == "trivy-db" and observed == 0 and not changed:
            database.chmod(0o600)
            with database.open("r+b") as stream:
                stream.seek(128)
                stream.write(b"changed")
            database.chmod(0o400)
            changed = True

    with pytest.raises(cache.GrypeContentValidationError, match="changed"):
        cache.validate_generation(cache_root, manifest.generation_id, progress=progress)
    assert changed


def test_failed_grype_verification_never_fills_observation_sink(tmp_path: Path):
    root = tmp_path / "grype"
    tree = _database(root)
    database = root / cache.GRYPE_DATABASE_PATH
    with database.open("r+b") as stream:
        stream.seek(128)
        stream.write(b"changed")
    sink = []
    with pytest.raises(cache.GrypeContentValidationError):
        cache.verify_grype_logical_content(root, tree.files, _observation_sink=sink)
    assert sink == []


@pytest.mark.parametrize("action", ["active", "previous", "cached", "rollback"])
def test_grype_timeout_is_not_corruption_fallback_or_cached_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
):
    cache_root, manifest, _ = _sealed_generation(tmp_path)
    validated = cache.validate_generation(cache_root, manifest.generation_id)
    previous = cache.GenerationReference(generation_id="e" * 64, manifest_sha256="f" * 64)
    pointer = cache.ActiveGenerationPointer(schema_version=1, revision=1,
        active=validated.reference, previous_good=previous,
        activated_at="2026-09-07T07:00:00Z", operation_id="10000000-0000-4000-8000-000000000001")
    pointer_path = cache_root / "active.json"
    pointer_bytes = cache.canonical_json_bytes(pointer.model_dump(mode="json"))
    pointer_path.write_bytes(pointer_bytes)
    pointer_path.chmod(0o600)
    calls = []
    failure = cache.GrypeContentValidationError("deadline")

    def validate(root, generation_id, **kwargs):
        calls.append(generation_id)
        if action == "previous" and generation_id == manifest.generation_id:
            raise cache.CacheValidationError("deterministically invalid fixture")
        raise failure

    monkeypatch.setattr(cache, "validate_generation", validate)
    cache.clear_runtime_generation_cache()
    if action == "cached":
        # Keep a stable immutable-pointer identity without inventing a second DB.
        monkeypatch.setattr(cache, "_runtime_generation_identity", lambda *args, **kwargs: ("unchanged",))
        invoke = lambda: cache.resolve_active_generation_cached(cache_root,
            tool_lock_sha256=TOOLS.sha256, rules_lock_sha256="d" * 64)
    elif action == "rollback":
        invoke = lambda: cache.rollback_to_previous_good(cache_root, pointer.operation_id)
    else:
        invoke = lambda: cache.resolve_active_generation(cache_root)
    for _ in range(2 if action == "cached" else 1):
        with pytest.raises(cache.GrypeContentValidationError) as caught:
            invoke()
        assert caught.value is failure
    assert calls == ([manifest.generation_id, previous.generation_id] if action == "previous"
        else [manifest.generation_id] * (2 if action == "cached" else 1))
    assert pointer_path.read_bytes() == pointer_bytes
    cache.clear_runtime_generation_cache()


def _logical_calls(monkeypatch: pytest.MonkeyPatch):
    calls = []
    original = grype_identity.compute_grype_logical_identity

    def compute(path, **kwargs):
        calls.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", compute)
    return calls


def test_grype_proof_reuse_reads_both_actual_files_after_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    first, copied = tmp_path / "first", tmp_path / "copied"
    tree = _database(first)
    shutil.copytree(first, copied)
    calls = _logical_calls(monkeypatch)
    reads = []
    original = grype_identity.observe_grype_file

    def observe(path, **kwargs):
        reads.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(grype_identity, "observe_grype_file", observe)
    result = cache.verify_grype_logical_content(first, tree.files)
    assert cache.verify_grype_logical_content(copied, tree.files) == result
    assert calls == [first / cache.GRYPE_DATABASE_PATH]
    assert reads == [
        first / cache.GRYPE_IMPORT_METADATA_PATH,
        copied / cache.GRYPE_IMPORT_METADATA_PATH,
        copied / cache.GRYPE_DATABASE_PATH,
    ]


def test_cold_hit_and_nonempty_miss_hash_real_database_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first"
    first_tree = _database(first)
    physical_reads: list[Path] = []
    original = grype_identity._physical_identity

    def physical(path: Path, *args: object):
        physical_reads.append(path)
        return original(path, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(grype_identity, "_physical_identity", physical)
    first_result = cache.verify_grype_logical_content(first, first_tree.files)
    assert [p for p in physical_reads if p.name == "vulnerability.db"] == [
        first / cache.GRYPE_DATABASE_PATH,
    ]
    assert cache.verify_grype_logical_content(first, first_tree.files) == first_result
    assert len([p for p in physical_reads if p.name == "vulnerability.db"]) == 2

    second = tmp_path / "second"
    _database(second)
    with sqlite3.connect(second / cache.GRYPE_DATABASE_PATH) as db:
        db.execute("UPDATE packages SET name='different' WHERE id=1")
    _import_record(second / "6")
    second_tree = cache.collect_canonical_tree(second)
    cache.verify_grype_logical_content(second, second_tree.files)
    # A nonempty cache retains the old observe-first lookup: the miss still
    # performs its independent physical hash inside SQL computation.
    assert [p for p in physical_reads if p.name == "vulnerability.db"] == [
        first / cache.GRYPE_DATABASE_PATH,
        first / cache.GRYPE_DATABASE_PATH,
        second / cache.GRYPE_DATABASE_PATH,
        second / cache.GRYPE_DATABASE_PATH,
    ]


@pytest.mark.parametrize("relative", [
    cache.GRYPE_DATABASE_PATH, cache.GRYPE_IMPORT_METADATA_PATH,
])
def test_cold_proof_rejects_bad_claimed_digest_without_caching(
    tmp_path: Path, relative: str,
) -> None:
    root = tmp_path / "grype"
    tree = _database(root)
    forged = [
        record.model_copy(update={"sha256": "0" * 64}) if record.path == relative
        else record for record in tree.files
    ]
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, forged)
    assert caught.value.code == (
        "changed" if relative == cache.GRYPE_DATABASE_PATH else "import_metadata"
    )
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


def test_cold_proof_rejects_bad_import_checksum_without_caching(tmp_path: Path) -> None:
    root = tmp_path / "grype"
    _database(root)
    _import_record(root / "6", digest="xxh64:" + "0" * 16)
    tree = cache.collect_canonical_tree(root)
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, tree.files)
    assert caught.value.code == "import_checksum"
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


@pytest.mark.parametrize("kind", ["missing", "wrong_path", "wrong_sha", "duplicate"])
def test_cold_proof_refuses_missing_or_forged_output_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    root = tmp_path / "grype"
    tree = _database(root)
    original = grype_identity.compute_grype_logical_identity

    def broken(path: Path, **kwargs: object):
        outer = kwargs.pop("_observation_sink")
        own: list[grype_identity.GrypeFileObservation] = []
        result = original(path, _observation_sink=own, **kwargs)  # type: ignore[arg-type]
        assert len(own) == 1 and isinstance(outer, list)
        if kind == "wrong_path":
            outer.append(replace(own[0], _path=root / "6/other.db"))
        elif kind == "wrong_sha":
            outer.append(replace(own[0], sha256="0" * 64))
        elif kind == "duplicate":
            outer.extend([own[0], own[0]])
        return result

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", broken)
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, tree.files)
    assert caught.value.code == "changed"
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


@pytest.mark.parametrize("change", ["sidecar", "database_hardlink", "root_alias"])
def test_cold_proof_preserves_path_and_sidecar_rejections(
    tmp_path: Path, change: str,
) -> None:
    root = tmp_path / "grype"
    tree = _database(root)
    if change == "sidecar":
        (root / "6/vulnerability.db-wal").write_bytes(b"synthetic")
    elif change == "database_hardlink":
        os.link(root / cache.GRYPE_DATABASE_PATH, tmp_path / "hardlink")
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, tree.files)
    assert caught.value.code == "file"
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


@pytest.mark.parametrize("change", ["cancel", "database", "metadata"])
def test_cold_proof_final_callback_cannot_publish_stale_or_cancelled_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    root = tmp_path / "grype"
    tree = _database(root)
    completed_sql = False
    original = grype_identity.compute_grype_logical_identity

    def compute(path: Path, **kwargs: object):
        nonlocal completed_sql
        result = original(path, **kwargs)  # type: ignore[arg-type]
        completed_sql = True
        return result

    def checkpoint() -> None:
        nonlocal completed_sql
        if not completed_sql:
            return
        completed_sql = False
        if change == "cancel":
            raise RuntimeError("cancelled")
        path = root / (
            cache.GRYPE_DATABASE_PATH if change == "database"
            else cache.GRYPE_IMPORT_METADATA_PATH
        )
        with path.open("ab") as output:
            output.write(b"x")

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", compute)
    with pytest.raises(RuntimeError if change == "cancel" else cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, tree.files, checkpoint=checkpoint)
    if change != "cancel":
        assert caught.value.code == "changed"
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE


@pytest.mark.parametrize("relative,code", [
    (cache.GRYPE_DATABASE_PATH, "changed"),
    (cache.GRYPE_IMPORT_METADATA_PATH, "import_metadata"),
])
def test_grype_proof_reuse_rejects_forged_physical_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str, code: str,
):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    cache.verify_grype_logical_content(root, tree.files)
    forged = [record.model_copy(update={"sha256": "0" * 64}) if record.path == relative
        else record for record in tree.files]
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, forged)
    assert caught.value.code == code
    assert len(calls) == 1


def test_grype_proof_reuse_rechecks_changed_bytes_and_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    first = cache.verify_grype_logical_content(root, tree.files)
    with sqlite3.connect(root / cache.GRYPE_DATABASE_PATH) as db:
        db.execute("UPDATE packages SET name='changed' WHERE id=1")
    # Reusing the old caller record must fail before lookup, even at the same path.
    with pytest.raises(cache.GrypeContentValidationError, match="changed"):
        cache.verify_grype_logical_content(root, tree.files)
    assert len(calls) == 1
    _import_record(root / "6")
    updated = cache.collect_canonical_tree(root)
    second = cache.verify_grype_logical_content(root, updated.files)
    assert second.database_logical_sha256 != first.database_logical_sha256
    assert len(calls) == 2
    with pytest.raises(updater.OperationError):
        updater._validate_installed_content(updated, _requirement(tree, first), grype_logical_content=second)


def test_grype_proof_reuse_rejects_forged_database_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    cache.verify_grype_logical_content(root, tree.files)
    forged = [record.model_copy(update={"size_bytes": record.size_bytes + 1})
        if record.path == cache.GRYPE_DATABASE_PATH else record for record in tree.files]
    with pytest.raises(cache.GrypeContentValidationError, match="changed"):
        cache.verify_grype_logical_content(root, forged)
    assert len(calls) == 1


@pytest.mark.parametrize("code", ["integrity", "deadline"])
def test_grype_proof_reuse_does_not_cache_failed_or_timed_out_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str,
):
    root = tmp_path / "grype"
    tree = _database(root)
    original = grype_identity.compute_grype_logical_identity
    calls = 0

    def compute(path, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise grype_identity.GrypeIdentityError(code)
        return original(path, **kwargs)

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", compute)
    with pytest.raises(cache.GrypeContentValidationError) as caught:
        cache.verify_grype_logical_content(root, tree.files)
    assert caught.value.code == code
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE
    result = cache.verify_grype_logical_content(root, tree.files)
    assert cache.verify_grype_logical_content(root, tree.files) == result
    assert calls == 2


@pytest.mark.parametrize("after_hashing", [False, True])
def test_grype_proof_reuse_still_honors_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_hashing: bool,
):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    cache.verify_grype_logical_content(root, tree.files)
    failure = updater.OperationStateError("cancelled")
    reads = []
    original = grype_identity.observe_grype_file

    def observe(path, **kwargs):
        result = original(path, **kwargs)
        reads.append(path)
        return result

    def cancel():
        if not after_hashing or len(reads) == 2:
            raise failure

    monkeypatch.setattr(grype_identity, "observe_grype_file", observe)
    with pytest.raises(updater.OperationStateError) as caught:
        cache.verify_grype_logical_content(root, tree.files, checkpoint=cancel)
    assert caught.value is failure
    assert len(calls) == 1
    assert len(reads) == (2 if after_hashing else 0)


@pytest.mark.parametrize("relative", [cache.GRYPE_DATABASE_PATH, cache.GRYPE_IMPORT_METADATA_PATH])
def test_grype_proof_reuse_does_not_cache_inputs_changed_after_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str,
):
    root = tmp_path / "grype"
    tree = _database(root)
    path = root / relative
    before = path.read_bytes()
    original = grype_identity.compute_grype_logical_identity
    calls = 0
    mutate = False

    def compute(database, **kwargs):
        nonlocal calls, mutate
        calls += 1
        result = original(database, **kwargs)
        mutate = calls == 1
        return result

    def checkpoint():
        nonlocal mutate
        if mutate:
            path.write_bytes(before + b"changed")
            mutate = False

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", compute)
    with pytest.raises(cache.GrypeContentValidationError, match="changed"):
        cache.verify_grype_logical_content(root, tree.files, checkpoint=checkpoint)
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE
    path.write_bytes(before)
    cache.verify_grype_logical_content(root, tree.files)
    assert calls == 2


def test_grype_proof_reuse_metadata_only_change_requires_new_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    first = cache.verify_grype_logical_content(root, tree.files)
    path = root / cache.GRYPE_IMPORT_METADATA_PATH
    metadata = json.loads(path.read_text())
    path.write_text(json.dumps({**metadata, "client_version": "v6.1.10"}))
    updated = cache.collect_canonical_tree(root)
    second = cache.verify_grype_logical_content(root, updated.files)
    assert first.database_logical_sha256 == second.database_logical_sha256
    assert first.import_metadata_logical_sha256 != second.import_metadata_logical_sha256
    assert len(calls) == 2


@pytest.mark.parametrize("failure_kind", ["cancelled", "deadline"])
def test_grype_proof_reuse_does_not_publish_after_final_checkpoint_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_kind: str,
):
    root = tmp_path / "grype"
    tree = _database(root)
    original = grype_identity.compute_grype_logical_identity
    clock = [0.0]
    calls = 0
    finished = False
    failure = updater.OperationStateError("cancelled")
    monkeypatch.setattr(cache.time, "monotonic", lambda: clock[0])

    def compute(path, **kwargs):
        nonlocal calls, finished
        calls += 1
        result = original(path, **kwargs)
        finished = True
        if calls == 1 and failure_kind == "deadline":
            clock[0] = cache.GRYPE_IDENTITY_TIMEOUT_SECONDS + 1
        return result

    def checkpoint():
        if calls == 1 and finished and failure_kind == "cancelled":
            raise failure

    monkeypatch.setattr(grype_identity, "compute_grype_logical_identity", compute)
    error = updater.OperationStateError if failure_kind == "cancelled" else cache.GrypeContentValidationError
    with pytest.raises(error) as caught:
        cache.verify_grype_logical_content(root, tree.files, checkpoint=checkpoint)
    assert caught.value is failure if failure_kind == "cancelled" else caught.value.code == "deadline"
    assert not cache._GRYPE_LOGICAL_PROOF_CACHE
    cache.verify_grype_logical_content(root, tree.files)
    assert calls == 2


@pytest.mark.parametrize("change", ["sidecar", "database_hardlink", "metadata_hardlink", "root_alias"])
def test_grype_proof_reuse_keeps_current_structural_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
):
    root = tmp_path / "grype"
    tree = _database(root)
    calls = _logical_calls(monkeypatch)
    cache.verify_grype_logical_content(root, tree.files)
    if change == "sidecar":
        (root / "6/vulnerability.db-wal").write_bytes(b"synthetic")
    elif change == "root_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    else:
        relative = cache.GRYPE_DATABASE_PATH if change == "database_hardlink" else cache.GRYPE_IMPORT_METADATA_PATH
        os.link(root / relative, tmp_path / "hardlink")
    with pytest.raises(cache.GrypeContentValidationError, match="file"):
        cache.verify_grype_logical_content(root, tree.files)
    assert len(calls) == 1


def test_grype_proof_reuse_retains_only_two_recent_successes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    inputs = []
    for index in range(3):
        root = tmp_path / str(index)
        _database(root)
        with sqlite3.connect(root / cache.GRYPE_DATABASE_PATH) as db:
            db.execute("UPDATE packages SET name=? WHERE id=1", (f"distinct-{index}",))
        _import_record(root / "6")
        inputs.append((root, cache.collect_canonical_tree(root).files))
    calls = _logical_calls(monkeypatch)
    for root, files in inputs:
        cache.verify_grype_logical_content(root, files)
    assert len(cache._GRYPE_LOGICAL_PROOF_CACHE) == 2
    cache.verify_grype_logical_content(*inputs[1])
    assert len(calls) == 3
    cache.verify_grype_logical_content(*inputs[0])
    assert len(calls) == 4
    assert len(cache._GRYPE_LOGICAL_PROOF_CACHE) == 2
