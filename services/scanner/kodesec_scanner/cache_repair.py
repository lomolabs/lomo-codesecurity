"""Replace one damaged, solely selected cache without adopting its contents.

Callers hold the generation lock. A durable intent precedes candidate publication;
the unchanged old/new pointer decides which exact owned tree may be retired after
an interruption. Neither repair nor retirement makes damaged data a rollback.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import Callable, Literal
from uuid import UUID

from pydantic import Field, model_validator

from .cache_manifest import (
    ActiveGenerationPointer, CacheValidationError, GenerationReference,
    ResolvedGeneration, ValidatedGeneration, _StrictModel, _atomic_write_json,
    _decode_json_object, _read_bounded_regular_file, _require_relative_path, _secure_directory,
    load_active_pointer, validate_generation, MAX_ACTIVE_POINTER_BYTES,
    MAX_GENERATION_BYTES, MAX_GENERATION_DEPTH, MAX_GENERATION_FILES,
    MAX_GENERATION_MANIFEST_BYTES, CACHE_COMPONENT_IDS,
)

INTENT_NAME = "repair-intent.json"
MAX_INTENT_BYTES = 16 * 1024 * 1024


def rename_exclusive(source: Path, destination: Path, *, src_dir_fd=-100, dst_dir_fd=-100) -> None:
    """Atomically refuse even a concurrently created empty destination."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux" and hasattr(library, "renameat2"):
        function = library.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                            ctypes.c_char_p, ctypes.c_uint]
        arguments = (src_dir_fd, os.fsencode(source), dst_dir_fd, os.fsencode(destination), 1)
    elif sys.platform == "darwin" and hasattr(library, "renameatx_np"):
        function = library.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        arguments = (src_dir_fd, os.fsencode(source), dst_dir_fd, os.fsencode(destination), 4)
    else:
        raise OSError(errno.ENOTSUP, "exclusive rename is unavailable")
    function.restype = ctypes.c_int
    if function(*arguments) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_root(root: Path) -> Path:
    root = _secure_directory(root, "repair cache root")
    for directory in (root, _secure_directory(root / "generations", "repair generations")):
        info = directory.lstat()
        if (info.st_uid != os.getuid() or info.st_gid != os.getgid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != root.lstat().st_dev):
            raise CacheValidationError("repair roots must be private and same-device")
    return root


def _private_bytes(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or info.st_gid != os.getgid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_dev != path.parent.lstat().st_dev):
        raise CacheValidationError("repair record is not a private owned file")
    data = _read_bounded_regular_file(path, maximum, "repair record")
    if _identity(info) != _identity(path.lstat()):
        raise CacheValidationError("repair record changed during read")
    return data


def _inventory(root: Path, tree: Path, checkpoint=None, *, published=False) -> dict[str, tuple[int, ...]]:
    """Bound metadata only. This is ownership proof, never content validation."""
    result = {}
    pending = [(tree, ".")]
    total = 0
    device = root.lstat().st_dev
    while pending:
        if checkpoint is not None and len(result) % 64 == 0:
            checkpoint()
        path, relative = pending.pop()
        info = path.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        modes = {0o500, 0o700} if published and relative == "." else {0o500} if directory else {0o400}
        if (info.st_dev != device or info.st_uid != os.getuid()
                or info.st_gid != os.getgid() or stat.S_IMODE(info.st_mode) not in modes
                or not (directory or stat.S_ISREG(info.st_mode))
                or not directory and info.st_nlink != 1):
            raise CacheValidationError("damaged generation ownership is unsafe")
        if relative != ".":
            _require_relative_path(relative, "repair generation entry")
        if len(relative.split("/")) > MAX_GENERATION_DEPTH:
            raise CacheValidationError("repair generation is too deep")
        result[relative] = _identity(info)
        total += 0 if directory else info.st_size
        if len(result) > MAX_GENERATION_FILES or total > MAX_GENERATION_BYTES:
            raise CacheValidationError("repair generation exceeds its inventory bound")
        if directory:
            children = []
            with os.scandir(path) as entries:
                for entry in entries:
                    if len(result) + len(pending) + len(children) >= MAX_GENERATION_FILES:
                        raise CacheValidationError("repair directory exceeds its inventory bound")
                    children.append(entry)
            for child in children:
                name = child.name if relative == "." else f"{relative}/{child.name}"
                pending.append((path / child.name, name))
    return result


class RepairSource(_StrictModel):
    pointer: ActiveGenerationPointer
    pointer_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    entries: dict[str, tuple[int, ...]]


class RepairIntent(_StrictModel):
    schema_version: Literal[1] = 1
    operation_id: str
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: RepairSource
    candidate: GenerationReference
    candidate_entries: dict[str, tuple[int, ...]]
    published_pointer: ActiveGenerationPointer | None = None
    published_entries: dict[str, tuple[int, ...]] | None = None

    @model_validator(mode="after")
    def validate_binding(self):
        if str(UUID(self.operation_id)) != self.operation_id:
            raise ValueError("noncanonical repair operation")
        old = self.source.pointer
        if old.previous_good is not None or old.active.generation_id == self.candidate.generation_id:
            raise ValueError("repair requires a distinct single damaged selection")
        if (self.published_pointer is None) != (self.published_entries is None):
            raise ValueError("repair publication requires its verified inventory")
        for index, entries in enumerate((self.source.entries, self.candidate_entries, self.published_entries)):
            if entries is None:
                continue
            if index == 0 and not entries:
                continue  # An exact absent selection has no bytes to retire.
            if not 1 <= len(entries) <= MAX_GENERATION_FILES or "." not in entries:
                raise ValueError("bounded repair inventory required")
            for path, identity in entries.items():
                if path != ".":
                    _require_relative_path(path, "repair entry")
                if len(identity) != 9 or any(type(value) is not int or value < 0 for value in identity):
                    raise ValueError("invalid repair entry identity")
        new = self.published_pointer
        if new is not None and (new.active != self.candidate or new.previous_good is not None
                or new.revision != old.revision + 1 or new.operation_id != self.operation_id):
            raise ValueError("repair publication binding differs")
        return self


def admit_repair(root: Path, resolved: ResolvedGeneration, checkpoint=None) -> RepairSource:
    root = _private_root(root)
    if (resolved.state != "invalid" or resolved.pointer is None
            or resolved.pointer.previous_good is not None):
        raise CacheValidationError("repair requires a known invalid sole generation")
    if (root / INTENT_NAME).exists() or (root / INTENT_NAME).is_symlink():
        raise CacheValidationError("pending cache repair must be reconciled first")
    raw = _private_bytes(root / "active.json", MAX_ACTIVE_POINTER_BYTES)
    if load_active_pointer(root) != resolved.pointer:
        raise CacheValidationError("repair selection changed")
    selected = root / "generations" / resolved.pointer.active.generation_id
    try:
        selected.lstat()
    except FileNotFoundError:
        entries = {}
    else:
        entries = _inventory(root, selected, checkpoint)
    return RepairSource(pointer=resolved.pointer, pointer_sha256=hashlib.sha256(raw).hexdigest(), entries=entries)


def _require_source(root: Path, source: RepairSource, checkpoint=None) -> None:
    raw = _private_bytes(root / "active.json", MAX_ACTIVE_POINTER_BYTES)
    if hashlib.sha256(raw).hexdigest() != source.pointer_sha256:
        raise CacheValidationError("repair source pointer changed")
    selected = root / "generations" / source.pointer.active.generation_id
    if not source.entries:
        try:
            selected.lstat()
        except FileNotFoundError:
            return
        raise CacheValidationError("missing repair generation appeared")
    observed = _inventory(root, selected, checkpoint)
    if observed != source.entries:
        raise CacheValidationError("damaged generation changed during repair")


def record_candidate(root: Path, source: RepairSource, candidate: ValidatedGeneration,
                     operation_id: str, request_digest: str, checkpoint=None) -> None:
    """Persist ownership before a sealed candidate leaves private staging."""
    root = _private_root(root)
    _require_source(root, source, checkpoint)
    expected = root / "staging" / operation_id / "candidate" / "generations" / candidate.manifest.generation_id
    if candidate.path != expected or expected.is_symlink():
        raise CacheValidationError("repair candidate is outside its owned operation")
    if (root / INTENT_NAME).exists() or (root / INTENT_NAME).is_symlink():
        raise CacheValidationError("repair intent already exists")
    intent = RepairIntent(operation_id=operation_id, request_digest=request_digest,
                          source=source, candidate=candidate.reference,
                          candidate_entries=_inventory(root, candidate.path, checkpoint))
    record = _require_operation(root, intent, checkpoint)
    if record.status != "running" or record.cancel_requested_at is not None:
        raise CacheValidationError("repair candidate requires a running uncancelled operation")
    _atomic_write_json(root, INTENT_NAME, intent.model_dump(mode="json"), MAX_INTENT_BYTES)


def _load(root: Path) -> tuple[RepairIntent, bytes]:
    data = _private_bytes(root / INTENT_NAME, MAX_INTENT_BYTES)
    try:
        _decode_json_object(data, "cache repair intent")
        return RepairIntent.model_validate_json(data), data
    except ValueError as exc:
        raise CacheValidationError("cache repair intent failed strict validation") from exc


def _require_operation(root: Path, intent: RepairIntent, checkpoint=None):
    from .updater import OperationStore
    store = OperationStore(root)
    with store._ledger_lock(checkpoint=checkpoint):
        record = store._load_unlocked(UUID(intent.operation_id))
    if (record.request_digest != intent.request_digest or record.kind != "cache_update"
            or record.preparation_budget is None
            or set(record.requested_components) != set(CACHE_COMPONENT_IDS)):
        raise CacheValidationError("repair does not match an admitted complete preparation")
    return record


def retained_operation_id(root: Path) -> UUID | None:
    """Protect repair evidence during ledger admission without lock inversion."""
    path = root / INTENT_NAME
    if not path.exists() and not path.is_symlink():
        return None
    intent, _ = _load(root)
    return UUID(intent.operation_id)


def _candidate_inventory(root: Path, intent: RepairIntent, checkpoint=None):
    current = _inventory(root, root / "generations" / intent.candidate.generation_id, checkpoint, published=True)
    # Publication reopens/reseals only the root and changes its ctime. Its inode,
    # contents and every descendant identity must still match the staged proof.
    def comparable(entries):
        return {name: tuple(v for i, v in enumerate(row) if name != "." or i not in {2, 8})
                for name, row in entries.items()}
    if comparable(current) != comparable(intent.candidate_entries):
        raise CacheValidationError("repair candidate ownership changed")
    return current


def publication_proof(root: Path, operation_id: str, request_digest: str,
                      requested_components: list[str], pointer: ActiveGenerationPointer,
                      checkpoint=None) -> bool:
    """Verify a repair commit under the caller's already-held operation lock.

    The caller supplies the durable admitted record. This is not a readiness
    check and must never be used to admit a scan or a new activation.
    """
    path = root / INTENT_NAME
    if not path.exists() and not path.is_symlink():
        return False
    intent, _ = _load(_private_root(root))
    if (intent.operation_id != operation_id or intent.request_digest != request_digest
            or set(requested_components) != set(CACHE_COMPONENT_IDS)
            or intent.published_pointer != pointer):
        raise CacheValidationError("repair publication does not match its admitted operation")
    _require_published(root, intent, checkpoint)
    return True


def _require_published(root: Path, intent: RepairIntent, checkpoint=None) -> None:
    # The commit fence fully validated these sealed bytes. Require every inode
    # and metadata identity plus the bounded manifest digest, without rehashing
    # multi-GiB data under startup's metadata clock.
    candidate = root / "generations" / intent.candidate.generation_id
    if _inventory(root, candidate, checkpoint) != intent.published_entries:
        raise CacheValidationError("published repair generation changed")
    manifest = _read_bounded_regular_file(candidate / "manifest.json",
                                         MAX_GENERATION_MANIFEST_BYTES, "repair manifest")
    if hashlib.sha256(manifest).hexdigest() != intent.candidate.manifest_sha256:
        raise CacheValidationError("published repair manifest changed")


def activate_repair(root: Path, generation_id: str, operation_id: str, request_digest: str, *,
                    checkpoint=None, progress=None, prepare_publication: Callable) -> ActiveGenerationPointer:
    root = _private_root(root)
    intent, _ = _load(root)
    if (intent.operation_id != operation_id or intent.request_digest != request_digest
            or intent.candidate.generation_id != generation_id):
        raise CacheValidationError("repair activation identity differs")
    _require_operation(root, intent, checkpoint)
    _require_source(root, intent.source, checkpoint)
    _candidate_inventory(root, intent, checkpoint)
    candidate = validate_generation(root, generation_id,
        expected_manifest_sha256=intent.candidate.manifest_sha256, checkpoint=checkpoint, progress=progress)
    _candidate_inventory(root, intent, checkpoint)
    published_entries = _inventory(root, candidate.path, checkpoint)
    activated_at = prepare_publication(candidate)
    pointer = ActiveGenerationPointer(schema_version=1, revision=intent.source.pointer.revision + 1,
        active=candidate.reference, previous_good=None, activated_at=activated_at, operation_id=operation_id)
    # No cancellation after the caller's existing commit fence. Persist enough
    # information to distinguish old-pointer cleanup from completed publication.
    intent = intent.model_copy(update={"published_pointer": pointer, "published_entries": published_entries})
    _atomic_write_json(root, INTENT_NAME, intent.model_dump(mode="json"), MAX_INTENT_BYTES)
    _require_source(root, intent.source)
    _atomic_write_json(root, "active.json", pointer.model_dump(mode="json"), MAX_ACTIVE_POINTER_BYTES)
    return pointer


def recover_repair(root: Path, checkpoint=None) -> bool:
    """Retire only the exact unselected tree; never publish or renew a job."""
    path = root / INTENT_NAME
    if not path.exists() and not path.is_symlink():
        return False
    root = _private_root(root)
    intent, raw = _load(root)
    record = _require_operation(root, intent, checkpoint)
    pointer = load_active_pointer(root)
    if pointer == intent.source.pointer:
        _require_source(root, intent.source, checkpoint)
        target = intent.candidate.generation_id
        expected = intent.candidate_entries
        abandoned_candidate = True
    elif intent.published_pointer is not None and pointer == intent.published_pointer:
        _require_published(root, intent, checkpoint)
        target = intent.source.pointer.active.generation_id
        expected = intent.source.entries
        abandoned_candidate = False
    else:
        raise CacheValidationError("cache repair pointer outcome is uncertain")
    # Import lazily: the updater owns receipt-backed retirement, not this module.
    from .updater import _recover_generation_tombstones, _retire_owned_generation
    _recover_generation_tombstones(root, checkpoint)
    tree = root / "generations" / target
    if tree.exists() or tree.is_symlink():
        current = (_candidate_inventory(root, intent, checkpoint) if abandoned_candidate
                   else _inventory(root, tree, checkpoint))
        if not abandoned_candidate and current != expected:
            raise CacheValidationError("damaged generation changed before retirement")
        # This helper validates metadata and retires an exact receipt. Content
        # validation remains mandatory for ordinary pruning. Here the durable
        # repair intent is the distinct authority for replacing damaged data.
        _retire_owned_generation(root, target, current, checkpoint=checkpoint)
    if not abandoned_candidate and record.status not in {"completed", "failed", "cancelled"}:
        # Keep the validated commit proof across a crash before terminal ledger
        # persistence. Startup can reconcile the exact outcome without a new
        # generation validation clock; it cannot renew preparation.
        return True
    if checkpoint is not None:
        checkpoint()
    if _private_bytes(path, MAX_INTENT_BYTES) != raw or load_active_pointer(root) != pointer:
        raise CacheValidationError("repair state changed before completion")
    path.unlink()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True
