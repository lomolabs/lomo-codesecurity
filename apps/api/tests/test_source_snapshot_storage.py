from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from kodesec_api import source_snapshots as snapshots
from kodesec_api.schemas import SourceSnapshotCreate


def payload(source: str = "1", path: str = "nested/file.txt") -> SourceSnapshotCreate:
    content = b"bounded source fixture\n"
    return SourceSnapshotCreate.model_validate({
        "source_id": source * 64, "name": "Storage fixture",
        "files": [{"path": path, "content_base64": base64.b64encode(content).decode(),
            "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}],
    })


@pytest.fixture
def storage(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(snapshots.os, "fstatvfs", lambda _: SimpleNamespace(
        f_frsize=4096, f_bsize=4096, f_bavail=10 * 1024 * 1024 * 1024 // 4096))
    return SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))


def forbid_payload_write(monkeypatch) -> None:
    def forbidden(*_):
        pytest.fail("storage refusal must occur before any payload write")
    monkeypatch.setattr(snapshots, "_write_file", forbidden)


def test_low_space_refuses_before_write_and_identical_generation_remains_reusable(storage, monkeypatch):
    original = snapshots.store_source_snapshot(storage, payload())
    monkeypatch.setattr(snapshots.os, "fstatvfs", lambda _: SimpleNamespace(f_frsize=4096, f_bsize=4096, f_bavail=0))
    forbid_payload_write(monkeypatch)
    assert snapshots.store_source_snapshot(storage, payload()) == original
    with pytest.raises(snapshots.SourceSnapshotError, match="2 GiB free-space reserve") as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_full"
    assert "No stored data was deleted" in str(caught.value)
    assert list((Path(storage.source_snapshot_dir) / "generations").iterdir()) == [original[1].parent]


@pytest.mark.parametrize("limit", ["bytes", "generations", "entries"])
def test_aggregate_limits_preserve_existing_and_reject_new_payload(storage, monkeypatch, limit):
    original = snapshots.store_source_snapshot(storage, payload())
    constant = {"bytes": "MAX_STORED_SOURCE_SNAPSHOT_BYTES",
        "generations": "MAX_STORED_SOURCE_SNAPSHOT_GENERATIONS",
        "entries": "MAX_SOURCE_SNAPSHOT_STORAGE_ENTRIES"}[limit]
    monkeypatch.setattr(snapshots, constant, 1)
    forbid_payload_write(monkeypatch)
    assert snapshots.store_source_snapshot(storage, payload()) == original
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_full"
    assert original[1].is_dir()


def test_interrupted_generation_bytes_are_accounted_and_never_deleted(storage, monkeypatch):
    original = snapshots.store_source_snapshot(storage, payload())
    root = Path(storage.source_snapshot_dir)
    pending = root / "generations" / ".pending-abcdefgh"
    pending.mkdir(mode=0o700)
    interrupted = pending / "unfinished"
    interrupted.write_bytes(b"x" * 12_000)
    with snapshots._publication_lock(root) as descriptor:
        used, entries, count = snapshots._storage_inventory(descriptor, 4096)
    assert used >= 12_000 and entries >= 6 and count == 2
    monkeypatch.setattr(snapshots, "MAX_STORED_SOURCE_SNAPSHOT_BYTES", used)
    forbid_payload_write(monkeypatch)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_full"
    assert interrupted.read_bytes() == b"x" * 12_000
    assert original[1].is_dir()


@pytest.mark.parametrize("unsafe", ["unknown", "linked_source", "linked_lock", "hardlinked_lock"])
def test_unknown_and_linked_storage_refuses_without_writing(storage, monkeypatch, tmp_path, unsafe):
    snapshots.store_source_snapshot(storage, payload())
    root = Path(storage.source_snapshot_dir)
    outside = tmp_path / "outside"
    outside.write_bytes(b"unrelated preserved bytes")
    if unsafe == "unknown":
        (root / "generations" / "unexpected").mkdir()
    elif unsafe == "linked_source":
        pending = root / "generations" / ".pending-abcdefgh"
        pending.mkdir(mode=0o700)
        (pending / "linked").symlink_to(outside)
    else:
        lock = root / ".publication.lock"
        if unsafe == "linked_lock":
            lock.unlink()
            lock.symlink_to(outside)
        else:
            os.link(lock, tmp_path / "lock-alias")
    forbid_payload_write(monkeypatch)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_unavailable"
    assert outside.read_bytes() == b"unrelated preserved bytes"


def test_unreadable_metadata_and_excessive_depth_fail_before_payload(storage, monkeypatch):
    snapshots.store_source_snapshot(storage, payload())
    forbid_payload_write(monkeypatch)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2", "/".join(["deep"] * 65) + "/file.txt"))
    assert caught.value.code == "snapshot_storage_full"
    def inaccessible(_):
        raise PermissionError("synthetic unreadable metadata")
    monkeypatch.setattr(snapshots.os, "scandir", inaccessible)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_unavailable"


def test_directory_replaced_by_link_during_inventory_is_not_followed(storage, monkeypatch, tmp_path):
    snapshots.store_source_snapshot(storage, payload())
    generations = Path(storage.source_snapshot_dir) / "generations"
    pending = generations / ".pending-abcdefgh"
    pending.mkdir(mode=0o700)
    outside = tmp_path / "unrelated"
    outside.mkdir()
    (outside / "kept").write_bytes(b"outside")
    original_open = os.open
    swapped = False
    def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == pending.name and dir_fd is not None and not swapped:
            swapped = True
            pending.rename(generations / ".pending-ijklmnop")
            pending.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(snapshots.os, "open", replace_before_open)
    forbid_payload_write(monkeypatch)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert swapped and caught.value.code == "snapshot_storage_unavailable"
    assert (outside / "kept").read_bytes() == b"outside"


def test_unreadable_generation_iterator_closes_its_descriptor(storage, monkeypatch):
    snapshots.store_source_snapshot(storage, payload())
    real_scandir = os.scandir
    refused = []
    # Descriptor identity is portable between the API's Linux container and Mac.
    generations_inode = (Path(storage.source_snapshot_dir) / "generations").stat().st_ino
    def inaccessible_generations(descriptor):
        if os.fstat(descriptor).st_ino == generations_inode:
            refused.append(descriptor)
            raise PermissionError("synthetic unreadable generations")
        return real_scandir(descriptor)
    monkeypatch.setattr(snapshots.os, "scandir", inaccessible_generations)
    forbid_payload_write(monkeypatch)
    with pytest.raises(snapshots.SourceSnapshotError) as caught:
        snapshots.store_source_snapshot(storage, payload("2"))
    assert caught.value.code == "snapshot_storage_unavailable" and len(refused) == 1
    with pytest.raises(OSError):
        os.fstat(refused[0])


def test_publication_reservation_serializes_new_writes_and_explicit_deletion(storage, monkeypatch):
    entered, release = Event(), Event()
    write = snapshots._write_file
    def held_write(path, content):
        entered.set()
        assert release.wait(5), "test must release the simulated in-flight publication"
        return write(path, content)
    monkeypatch.setattr(snapshots, "_write_file", held_write)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(snapshots.store_source_snapshot, storage, payload())
        try:
            assert entered.wait(5)
            for operation in (
                lambda: snapshots.store_source_snapshot(storage, payload("2")),
                lambda: snapshots.delete_source_snapshots(storage, "1" * 64),
            ):
                with pytest.raises(snapshots.SourceSnapshotError) as caught:
                    operation()
                assert caught.value.code == "snapshot_storage_busy"
            assert len(list((Path(storage.source_snapshot_dir) / "generations").iterdir())) == 1
        finally:
            release.set()
        original = first.result(timeout=5)
    assert snapshots.store_source_snapshot(storage, payload()) == original
    assert snapshots.delete_source_snapshots(storage, "1" * 64) == 1
    assert not original[1].exists()


def test_exact_deletion_preserves_pending_and_unrelated_generations(storage):
    original = snapshots.store_source_snapshot(storage, payload())
    neighbour = snapshots.store_source_snapshot(storage, payload("2"))
    pending = Path(storage.source_snapshot_dir) / "generations" / ".pending-abcdefgh"
    pending.mkdir(mode=0o700)
    (pending / "unfinished").write_bytes(b"preserve interrupted bytes")
    assert snapshots.delete_source_snapshots(storage, "1" * 64) == 1
    assert not original[1].exists()
    assert snapshots.validate_source_snapshot(storage, neighbour[0]) == neighbour[1]
    assert (pending / "unfinished").read_bytes() == b"preserve interrupted bytes"
    assert snapshots.delete_source_snapshots(storage, "1" * 64) == 0


def test_deletion_without_generations_is_idempotent_and_inventory_is_bounded(storage, monkeypatch):
    root = Path(storage.source_snapshot_dir)
    root.mkdir(mode=0o700)
    assert snapshots.delete_source_snapshots(storage, "1" * 64) == 0
    original = snapshots.store_source_snapshot(storage, payload())
    snapshots.store_source_snapshot(storage, payload("2"))
    monkeypatch.setattr(snapshots, "MAX_STORED_SOURCE_SNAPSHOT_GENERATIONS", 1)
    with pytest.raises(snapshots.SourceSnapshotError, match="review bound"):
        snapshots.delete_source_snapshots(storage, "1" * 64)
    assert original[1].exists(), "review must finish before deleting any generation"
