from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from contextlib import contextmanager
from typing import Iterable, Iterator

from .schemas import (
    MAX_SOURCE_SNAPSHOT_BYTES,
    MAX_SOURCE_SNAPSHOT_FILE_BYTES,
    MAX_SOURCE_SNAPSHOT_FILES,
    SourceSnapshotCreate,
    normalize_scan_target_path,
)
from .settings import Settings


SOURCE_SNAPSHOT_PROJECT_PREFIX = "/source-snapshots/native-windows"
SOURCE_SNAPSHOT_SCHEMA = "lomo-source-snapshot/v1"
MAX_SOURCE_SNAPSHOT_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_STORED_SOURCE_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
SOURCE_SNAPSHOT_FREE_RESERVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_STORED_SOURCE_SNAPSHOT_GENERATIONS = 256
MAX_SOURCE_SNAPSHOT_STORAGE_ENTRIES = 65_536
MAX_SOURCE_SNAPSHOT_DIRECTORY_DEPTH = 64
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_PENDING_GENERATION = re.compile(r"\.pending-[a-z0-9_]{8}\Z")
_STORAGE_GUIDANCE = (
    "Review and explicitly remove obsolete snapshot projects or interrupted snapshot data, "
    "or provide more storage, then retry. No stored data was deleted."
)


class SourceSnapshotError(ValueError):
    """A native source snapshot failed its bounded local ingestion contract."""

    def __init__(self, message: str, *, code: str = "snapshot_invalid") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidatedSourceSnapshot:
    source: Path
    snapshot_digest: str
    source_id: str
    directory_scope: str | None
    file_count: int
    total_bytes: int


def source_snapshot_project_path(source_id: str, *, kind: str = "native-windows") -> str:
    if _SHA256.fullmatch(source_id) is None:
        raise SourceSnapshotError("source snapshot identity must be a lowercase SHA-256 digest")
    if kind not in {"native-windows", "git-commit"}:
        raise SourceSnapshotError("source snapshot kind is invalid")
    return f"/source-snapshots/{kind}/{source_id}"


def is_source_snapshot_project(repo_path: str) -> bool:
    return re.fullmatch(r"/source-snapshots/(?:native-windows|git-commit)/[0-9a-f]{64}", repo_path) is not None


def source_snapshot_project_kind(repo_path: str) -> str:
    if not is_source_snapshot_project(repo_path):
        raise SourceSnapshotError("project is not bound to a source snapshot identity")
    return repo_path.split("/")[2]


def source_snapshot_project_source_id(repo_path: str) -> str:
    if not is_source_snapshot_project(repo_path):
        raise SourceSnapshotError("project is not bound to a native source snapshot identity")
    return repo_path.rsplit("/", 1)[-1]


def _snapshot_root(settings: Settings, *, create: bool) -> Path:
    root = Path(settings.source_snapshot_dir)
    if (
        not root.is_absolute()
        or ".." in root.parts
        or root.name != "source-snapshots"
        or len(root.parts) < 3
        or not _NOFOLLOW
        or not _DIRECTORY
    ):
        raise SourceSnapshotError("source snapshot root is not a dedicated no-follow directory")
    lexical = root.absolute()
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        raise SourceSnapshotError("source snapshot root parent is unavailable") from exc
    if parent != lexical.parent or not parent.is_dir():
        raise SourceSnapshotError("source snapshot root must not traverse a link ancestor")
    try:
        metadata = lexical.lstat()
    except FileNotFoundError:
        if not create:
            raise SourceSnapshotError("source snapshot root is unavailable")
        try:
            lexical.mkdir(mode=0o700)
            metadata = lexical.lstat()
        except OSError as exc:
            raise SourceSnapshotError("source snapshot root could not be initialized") from exc
    except OSError as exc:
        raise SourceSnapshotError("source snapshot root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SourceSnapshotError("source snapshot root is not a regular directory")
    if lexical.resolve(strict=True) != lexical:
        raise SourceSnapshotError("source snapshot root must not traverse a link ancestor")
    return lexical


def _canonical_manifest(
    payload: SourceSnapshotCreate,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    decoded: list[tuple[str, bytes]] = []
    manifest_files: list[dict[str, object]] = []
    total = 0
    for item in payload.files:
        try:
            content = base64.b64decode(item.content_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise SourceSnapshotError(
                f"source snapshot file {item.path} is not canonical base64"
            ) from exc
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != item.size_bytes or digest != item.sha256:
            raise SourceSnapshotError(f"source snapshot file {item.path} changed before admission")
        total += len(content)
        if total > MAX_SOURCE_SNAPSHOT_BYTES:
            raise SourceSnapshotError("source snapshot exceeds the 64 MiB total limit")
        decoded.append((item.path, content))
        manifest_files.append(
            {"path": item.path, "sha256": item.sha256, "size_bytes": item.size_bytes}
        )
    manifest: dict[str, object] = {
        "schema": SOURCE_SNAPSHOT_SCHEMA,
        "source_id": payload.source_id,
        "directory_scope": payload.directory_scope,
        "files": manifest_files,
        "file_count": len(manifest_files),
        "total_bytes": total,
    }
    return manifest, decoded


def _manifest_bytes(manifest: dict[str, object]) -> bytes:
    return json.dumps(
        manifest,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _write_file(path: Path, content: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
        )
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short source snapshot write")
            offset += written
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise SourceSnapshotError("source snapshot contains an unsafe or oversized file")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(content) > maximum_bytes
            or len(content) != after.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise SourceSnapshotError("source snapshot changed during validation")
        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sync_directories(paths: Iterable[Path]) -> None:
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _generation_path(settings: Settings, digest: str) -> Path:
    if _SHA256.fullmatch(digest) is None:
        raise SourceSnapshotError("source snapshot digest must be lowercase SHA-256")
    return _snapshot_root(settings, create=False) / "generations" / digest


def validate_source_snapshot(
    settings: Settings,
    digest: str,
    *,
    source_id: str | None = None,
    scan_target: tuple[str | None, str | None] | None = None,
) -> Path:
    return inspect_source_snapshot(
        settings, digest, source_id=source_id, scan_target=scan_target,
    ).source


def inspect_source_snapshot(
    settings: Settings,
    digest: str,
    *,
    source_id: str | None = None,
    scan_target: tuple[str | None, str | None] | None = None,
) -> ValidatedSourceSnapshot:
    """Validate once and bind body-free admission metadata to those exact bytes."""
    generation = _generation_path(settings, digest)
    try:
        metadata = generation.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SourceSnapshotError("source snapshot generation is not a directory")
        if generation.resolve(strict=True) != generation:
            raise SourceSnapshotError("source snapshot generation traverses a link")
        manifest_path = generation / "manifest.json"
        manifest_metadata = manifest_path.lstat()
        if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(manifest_metadata.st_mode):
            raise SourceSnapshotError("source snapshot manifest is unsafe")
        raw_manifest = _read_regular_file(
            manifest_path,
            maximum_bytes=MAX_SOURCE_SNAPSHOT_MANIFEST_BYTES,
        )
        if hashlib.sha256(raw_manifest).hexdigest() != digest:
            raise SourceSnapshotError(
                "source snapshot manifest digest does not match its generation"
            )
        manifest = json.loads(raw_manifest)
    except SourceSnapshotError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceSnapshotError("source snapshot generation is unavailable or malformed") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "source_id", "directory_scope", "files", "file_count", "total_bytes"
    } or manifest.get("schema") != SOURCE_SNAPSHOT_SCHEMA:
        raise SourceSnapshotError("source snapshot manifest schema is invalid")
    if (
        not isinstance(manifest.get("source_id"), str)
        or _SHA256.fullmatch(manifest["source_id"]) is None
        or (source_id is not None and manifest["source_id"] != source_id)
    ):
        raise SourceSnapshotError(
            "source snapshot does not match the selected Windows source",
            code="source_mismatch",
        )
    directory_scope = manifest.get("directory_scope")
    if directory_scope is not None:
        try:
            valid_directory_scope = (
                isinstance(directory_scope, str)
                and normalize_scan_target_path(directory_scope) == directory_scope
            )
        except (TypeError, ValueError):
            valid_directory_scope = False
        if not valid_directory_scope:
            raise SourceSnapshotError("source snapshot directory scope is invalid")
    if scan_target is not None:
        target_path, target_kind = scan_target
        try:
            valid_scan_target = (
                (target_path is None) == (target_kind is None)
                and target_kind in {None, "file", "directory"}
                and (
                    target_path is None
                    or isinstance(target_path, str)
                    and normalize_scan_target_path(target_path) == target_path
                )
            )
        except (TypeError, ValueError):
            valid_scan_target = False
        if not valid_scan_target:
            raise SourceSnapshotError("source snapshot scan target is invalid")
        expected_scope = target_path if target_kind == "directory" else None
        if directory_scope != expected_scope:
            raise SourceSnapshotError(
                "source snapshot does not match the exact selected directory scope",
                code="scope_mismatch",
            )
    files = manifest.get("files")
    if (
        not isinstance(files, list)
        or len(files) > MAX_SOURCE_SNAPSHOT_FILES
        or manifest.get("file_count") != len(files)
        or isinstance(manifest.get("file_count"), bool)
        or not isinstance(manifest.get("total_bytes"), int)
        or isinstance(manifest.get("total_bytes"), bool)
        or manifest["total_bytes"] < 0
        or manifest["total_bytes"] > MAX_SOURCE_SNAPSHOT_BYTES
    ):
        raise SourceSnapshotError("source snapshot manifest bounds are invalid")
    source = generation / "source"
    try:
        source_metadata = source.lstat()
        if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISDIR(source_metadata.st_mode):
            raise SourceSnapshotError("source snapshot source root is unsafe")
    except OSError as exc:
        raise SourceSnapshotError("source snapshot source root is unavailable") from exc

    expected: dict[str, tuple[str, int]] = {}
    for item in files:
        valid = (
            isinstance(item, dict)
            and set(item) == {"path", "sha256", "size_bytes"}
            and isinstance(item.get("path"), str)
            and isinstance(item.get("sha256"), str)
            and _SHA256.fullmatch(item["sha256"]) is not None
            and isinstance(item.get("size_bytes"), int)
            and not isinstance(item.get("size_bytes"), bool)
            and 0 <= item["size_bytes"] <= MAX_SOURCE_SNAPSHOT_FILE_BYTES
            and item["path"] not in expected
        )
        try:
            valid = valid and normalize_scan_target_path(item["path"]) == item["path"]
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise SourceSnapshotError("source snapshot manifest file entry is invalid")
        expected[item["path"]] = (item["sha256"], item["size_bytes"])

    expected_directories: set[str] = set()
    for relative in expected:
        parts = relative.split("/")[:-1]
        expected_directories.update(
            "/".join(parts[:index]) for index in range(1, len(parts) + 1)
        )
    if isinstance(directory_scope, str):
        parts = directory_scope.split("/")
        expected_directories.update(
            "/".join(parts[:index]) for index in range(1, len(parts) + 1)
        )
        prefix = f"{directory_scope}/"
        if any(not relative.startswith(prefix) for relative in expected):
            raise SourceSnapshotError("source snapshot files escape the sealed directory scope")

    observed: dict[str, tuple[str, int]] = {}
    observed_directories: set[str] = set()
    for current, directories, names in os.walk(source, followlinks=False):
        directories.sort()
        names.sort()
        current_path = Path(current)
        for name in directories:
            child = current_path / name
            child_metadata = child.lstat()
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(child_metadata.st_mode):
                raise SourceSnapshotError("source snapshot contains an unsafe directory")
            relative = child.relative_to(source).as_posix()
            try:
                if normalize_scan_target_path(relative) != relative:
                    raise ValueError("non-canonical source snapshot directory")
            except (TypeError, ValueError) as exc:
                raise SourceSnapshotError("source snapshot contains an unsafe directory") from exc
            observed_directories.add(relative)
        for name in names:
            child = current_path / name
            child_metadata = child.lstat()
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISREG(child_metadata.st_mode):
                raise SourceSnapshotError("source snapshot contains an unsafe file")
            relative = child.relative_to(source).as_posix()
            if child_metadata.st_size > MAX_SOURCE_SNAPSHOT_FILE_BYTES:
                raise SourceSnapshotError("source snapshot contains an oversized file")
            content = _read_regular_file(child, maximum_bytes=MAX_SOURCE_SNAPSHOT_FILE_BYTES)
            observed[relative] = (hashlib.sha256(content).hexdigest(), len(content))
    if (
        observed != expected
        or observed_directories != expected_directories
        or sum(size for _, size in observed.values()) != manifest["total_bytes"]
    ):
        raise SourceSnapshotError("source snapshot files do not match the sealed manifest")
    return ValidatedSourceSnapshot(
        source=source,
        snapshot_digest=digest,
        source_id=manifest["source_id"],
        directory_scope=directory_scope,
        file_count=len(expected),
        total_bytes=manifest["total_bytes"],
    )


def _storage_error(message: str, *, code: str = "snapshot_storage_unavailable") -> SourceSnapshotError:
    return SourceSnapshotError(f"{message} {_STORAGE_GUIDANCE}", code=code)


@contextmanager
def _publication_lock(root: Path) -> Iterator[int]:
    """Serialize this API filesystem's publications/deletions without waiting."""
    root_fd = lock_fd = -1
    locked = False
    try:
        root_fd = os.open(root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        root_stat = os.fstat(root_fd)
        if root_stat.st_uid != os.geteuid() or root_stat.st_mode & 0o022:
            raise _storage_error("Snapshot storage must be owned and writable only by the API account.")
        lock_fd = os.open(".publication.lock", os.O_RDWR | os.O_CREAT | _NOFOLLOW | _CLOEXEC, 0o600, dir_fd=root_fd)
        observed = os.fstat(lock_fd)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
            or observed.st_uid != os.geteuid() or observed.st_mode & 0o077 or observed.st_size != 0):
            raise _storage_error("Snapshot publication lock is not a private regular file.")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SourceSnapshotError("Another snapshot publication or deletion is in progress. Retry when it finishes; no payload was written.", code="snapshot_storage_busy") from exc
        locked = True
        current = os.stat(".publication.lock", dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino):
            raise _storage_error("Snapshot publication lock changed during admission.")
        yield root_fd
    except SourceSnapshotError:
        raise
    except OSError as exc:
        raise _storage_error("Snapshot storage admission is unavailable.") from exc
    finally:
        if lock_fd >= 0:
            if locked:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _storage_inventory(root_fd: int, block_size: int) -> tuple[int, int, int]:
    """Bounded metadata only; orphan pending bytes remain charged, never removed."""
    allocated = entries = generation_count = 0
    with os.scandir(root_fd) as root_entries:
        for entry in root_entries:
            if entry.name not in {".publication.lock", "generations"}:
                raise _storage_error("Snapshot storage has an unknown top-level entry.")
    generations_fd = os.open("generations", os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=root_fd)
    try:
        generations_iterator = os.scandir(generations_fd)
    except OSError:
        os.close(generations_fd)
        raise
    stack = [(generations_iterator, generations_fd, 0)]
    try:
        # Explicit iterators stop before unbounded sibling-name allocation.
        while stack:
            iterator, directory_fd, depth = stack[-1]
            entry = next(iterator, None)
            if entry is None:
                iterator.close()
                os.close(directory_fd)
                stack.pop()
                continue
            entries += 1
            if entries > MAX_SOURCE_SNAPSHOT_STORAGE_ENTRIES:
                raise _storage_error("Snapshot storage exceeds its 65,536-entry metadata budget.", code="snapshot_storage_full")
            item = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            is_directory = stat.S_ISDIR(item.st_mode)
            if depth == 0:
                generation_count += 1
                if generation_count >= MAX_STORED_SOURCE_SNAPSHOT_GENERATIONS:
                    raise _storage_error("Snapshot storage has reached its 256-generation budget.", code="snapshot_storage_full")
                if not is_directory or (_SHA256.fullmatch(entry.name) is None and _PENDING_GENERATION.fullmatch(entry.name) is None):
                    raise _storage_error("Snapshot generations contain an unknown entry.")
            if (not (is_directory or stat.S_ISREG(item.st_mode))
                or item.st_uid != os.geteuid() or item.st_mode & 0o022
                or (stat.S_ISREG(item.st_mode) and item.st_nlink != 1)):
                raise _storage_error("Snapshot storage contains linked or unsafe metadata.")
            allocated += max(item.st_size, getattr(item, "st_blocks", 0) * 512) + block_size
            if allocated > MAX_STORED_SOURCE_SNAPSHOT_BYTES:
                raise _storage_error("Snapshot storage exceeds its 2 GiB retained-data budget.", code="snapshot_storage_full")
            if is_directory:
                if depth >= MAX_SOURCE_SNAPSHOT_DIRECTORY_DEPTH + 2:
                    raise _storage_error("Snapshot storage exceeds its 64-directory source-depth budget.", code="snapshot_storage_full")
                child_fd = os.open(entry.name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=directory_fd)
                try:
                    current = os.fstat(child_fd)
                    if (item.st_dev, item.st_ino) != (current.st_dev, current.st_ino):
                        raise _storage_error("Snapshot directory changed during storage admission.")
                    child_iterator = os.scandir(child_fd)
                except (OSError, SourceSnapshotError):
                    os.close(child_fd)
                    raise
                stack.append((child_iterator, child_fd, depth + 1))
    finally:
        for iterator, directory_fd, _ in reversed(stack):
            iterator.close()
            os.close(directory_fd)
    return allocated, entries, generation_count


def _admit_snapshot_storage(root_fd: int, manifest: dict[str, object], rendered: bytes, decoded: list[tuple[str, bytes]]) -> None:
    filesystem = os.fstatvfs(root_fd)
    block_size = max(4096, filesystem.f_frsize, filesystem.f_bsize)
    directories: set[str] = set()
    for relative in [*(name for name, _ in decoded), str(manifest["directory_scope"] or "") + "/"]:
        if relative.count("/") > MAX_SOURCE_SNAPSHOT_DIRECTORY_DEPTH:
            raise _storage_error("New snapshot exceeds the 64-directory source-depth budget.", code="snapshot_storage_full")
        parent = relative.rpartition("/")[0]
        while parent:
            directories.add(parent)
            if len(directories) > MAX_SOURCE_SNAPSHOT_STORAGE_ENTRIES:
                raise _storage_error("New snapshot exceeds the bounded storage-entry budget.", code="snapshot_storage_full")
            parent = parent.rpartition("/")[0]
    # Round every new entry up and reserve one extra block of metadata per entry.
    new_entries = len(decoded) + len(directories) + 3  # generation, source, manifest
    new_bytes = sum(((len(content) + block_size - 1) // block_size + 1) * block_size for _, content in decoded)
    new_bytes += ((len(rendered) + block_size - 1) // block_size + 1) * block_size
    new_bytes += (len(directories) + 2) * 2 * block_size
    allocated, entries, _ = _storage_inventory(root_fd, block_size)
    if allocated + new_bytes > MAX_STORED_SOURCE_SNAPSHOT_BYTES or entries + new_entries > MAX_SOURCE_SNAPSHOT_STORAGE_ENTRIES:
        raise _storage_error("New snapshot would exceed the 2 GiB / 65,536-entry storage budget.", code="snapshot_storage_full")
    filesystem = os.fstatvfs(root_fd)
    if filesystem.f_bavail * filesystem.f_frsize < SOURCE_SNAPSHOT_FREE_RESERVE_BYTES + new_bytes:
        raise _storage_error("New snapshot needs its full write allocation plus a 2 GiB free-space reserve.", code="snapshot_storage_full")


def store_source_snapshot(
    settings: Settings,
    payload: SourceSnapshotCreate,
) -> tuple[str, Path, int, int]:
    manifest, decoded = _canonical_manifest(payload)
    rendered = _manifest_bytes(manifest)
    digest = hashlib.sha256(rendered).hexdigest()
    root = _snapshot_root(settings, create=True)
    with _publication_lock(root) as root_fd:
        return _store_locked_snapshot(settings, payload, manifest, decoded, rendered, digest, root, root_fd)


def _store_locked_snapshot(settings: Settings, payload: SourceSnapshotCreate, manifest: dict[str, object], decoded: list[tuple[str, bytes]], rendered: bytes, digest: str, root: Path, root_fd: int) -> tuple[str, Path, int, int]:
    generations = root / "generations"
    try:
        generations.mkdir(mode=0o700, exist_ok=True)
        generations_metadata = generations.lstat()
        if (not stat.S_ISDIR(generations_metadata.st_mode)
            or generations_metadata.st_uid != os.geteuid() or generations_metadata.st_mode & 0o022):
            raise SourceSnapshotError("source snapshot generations root is unsafe")
    except OSError as exc:
        raise SourceSnapshotError("source snapshot generations root is unavailable") from exc

    generation = generations / digest
    if generation.exists():
        return (
            digest,
            validate_source_snapshot(settings, digest),
            int(manifest["file_count"]),
            int(manifest["total_bytes"]),
        )

    _admit_snapshot_storage(root_fd, manifest, rendered, decoded)
    pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=generations))
    source = pending / "source"
    try:
        source.mkdir(mode=0o700)
        touched_directories: set[Path] = {source}
        if payload.directory_scope is not None:
            scoped_directory = source.joinpath(*payload.directory_scope.split("/"))
            scoped_directory.mkdir(mode=0o700, parents=True)
            cursor = scoped_directory
            while cursor != pending:
                touched_directories.add(cursor)
                cursor = cursor.parent
        for relative, content in decoded:
            destination = source.joinpath(*relative.split("/"))
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cursor = destination.parent
            while cursor != pending:
                touched_directories.add(cursor)
                cursor = cursor.parent
            _write_file(destination, content)
        _write_file(pending / "manifest.json", rendered)
        _sync_directories(
            sorted(touched_directories, key=lambda path: len(path.parts), reverse=True)
        )
        _sync_directories([pending])
        try:
            os.rename(pending, generation)
        except OSError as exc:
            if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
            shutil.rmtree(pending)
        _sync_directories([generations])
        validated = validate_source_snapshot(settings, digest)
        return digest, validated, int(manifest["file_count"]), int(manifest["total_bytes"])
    except (OSError, SourceSnapshotError) as exc:
        if pending.exists():
            shutil.rmtree(pending)
        if isinstance(exc, SourceSnapshotError):
            raise
        raise SourceSnapshotError("source snapshot could not be sealed atomically") from exc


def delete_source_snapshots(settings: Settings, source_id: str) -> int:
    """Remove sealed generations owned by one deleted native source project."""

    if _SHA256.fullmatch(source_id) is None:
        raise SourceSnapshotError("source snapshot identity must be lowercase SHA-256")
    root = _snapshot_root(settings, create=False)
    with _publication_lock(root):
        return _delete_locked_source_snapshots(settings, source_id)


def _delete_locked_source_snapshots(settings: Settings, source_id: str) -> int:

    if _SHA256.fullmatch(source_id) is None:
        raise SourceSnapshotError("source snapshot identity must be lowercase SHA-256")
    try:
        generations = _snapshot_root(settings, create=False) / "generations"
        metadata = generations.lstat()
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise SourceSnapshotError("source snapshot generations root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SourceSnapshotError("source snapshot generations root is unsafe")

    names: list[str] = []
    with os.scandir(generations) as entries:
        for entry in entries:
            if len(names) >= MAX_STORED_SOURCE_SNAPSHOT_GENERATIONS:
                raise _storage_error("Snapshot deletion exceeds its 256-generation review bound; review exact obsolete entries first.")
            names.append(entry.name)
    owned: list[Path] = []
    for name in sorted(names):
        generation = generations / name
        if _PENDING_GENERATION.fullmatch(name) is not None:
            pending = generation.lstat()
            if not stat.S_ISDIR(pending.st_mode) or pending.st_uid != os.geteuid() or pending.st_mode & 0o022:
                raise _storage_error("Interrupted snapshot metadata is unsafe; it was left unchanged.")
            # No digest/source binding exists yet: it is never owned by this
            # project deletion. Keep its bytes charged until explicit review.
            continue
        if _SHA256.fullmatch(generation.name) is None:
            raise SourceSnapshotError("source snapshot generations root contains an unknown entry")
        try:
            validate_source_snapshot(settings, generation.name, source_id=source_id)
        except SourceSnapshotError as exc:
            if exc.code == "source_mismatch":
                continue
            raise
        owned.append(generation)
    for generation in owned:
        shutil.rmtree(generation)
    if owned:
        _sync_directories([generations])
    return len(owned)
