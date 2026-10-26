#!/usr/bin/env python3
"""Build one locally reviewed scanner image and emit its canonical receipt.

This producer is intentionally separate from the Trivy DB candidate workflow.
It freezes the exact Docker invocation and source inventory, rejects unsafe or
unexpected build inputs, and leaves only one owned review tag for the candidate
consumer.  The consumer is responsible for removing that tag after it has
finished its isolated evidence runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from docker_runtime_contract import (  # noqa: E402
    DockerRuntimeContractError,
    RuntimePaths,
    ScannerReviewBuildTarget,
    combined_observation,
    executable_argv,
    normalize_buildx_observation,
    normalize_daemon_observation,
    owned_local_repo_digests,
    prepare_runtime,
    remove_runtime,
    revalidate_runtime,
    scanner_review_build_target,
)
from source_provenance import (  # noqa: E402
    BUILD_IDENTITY_LABEL,
    SCANNER_IMAGE_INPUT_PATHS,
    SourceProvenance,
    SourceProvenanceError,
    resolve_source_provenance,
)
from scanner_build_contract import (  # noqa: E402
    SCANNER_BUILD_ARGS,
    SCANNER_BEARER_OFFLINE_BUILD_DIRECTIVE,
    SCANNER_BUILDER_BUILD_ARGS,
    SCANNER_COPY_DIRECTIVES,
    SCANNER_FROM_DIRECTIVES,
    SCANNER_RUNTIME_BASE_IMAGE,
    SCANNER_COPY_FILES,
    SCANNER_COPY_ROOTS,
    SCANNER_COPY_SINGLE_FILES,
)


SCHEMA = "kodesec.scanner-build-receipt/v2"
RUNTIME_OBSERVATION_SCHEMA = "kodesec.docker-runtime-observation-receipt/v1"
RUNTIME_OBSERVATION_NAME = "docker-runtime-observation.json"
RUNTIME_DIRECTORY_NAME = ".docker-runtime"
REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER_PATH = Path(__file__).resolve()
PRODUCER_RELATIVE_PATH = "scripts/scanner-build-receipt.py"
DOCKERFILE_PATH = "services/scanner/Dockerfile"
DOCKERIGNORE_PATH = ".dockerignore"
STAGED_CONTEXT_NAME = ".scanner-build-context"
try:
    REVIEW_TARGET: ScannerReviewBuildTarget | None = scanner_review_build_target(
        platform.system(), platform.machine()
    )
except DockerRuntimeContractError:
    REVIEW_TARGET = None
PLATFORM = REVIEW_TARGET.image_platform if REVIEW_TARGET is not None else ""
ARCHITECTURE = REVIEW_TARGET.image_architecture if REVIEW_TARGET is not None else ""
BUILD_NETWORK = "default"
OWNERSHIP_LABEL_KEY = "io.lomodev.kodesec.trivy-review-build"
BASE_IMAGE = SCANNER_RUNTIME_BASE_IMAGE
FROM_DIRECTIVES = SCANNER_FROM_DIRECTIVES
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_BUILD_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_BUILD_SECONDS = 3600
MAX_CONTROL_SECONDS = 60
READ_CHUNK_BYTES = 64 * 1024
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
OWNED_TAG = re.compile(r"lomo-kodesec-scanner:trivy-review-([0-9a-f]{32})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ENVIRONMENT_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
MAX_CONTAINER_ID = (1 << 31) - 1

BUILD_ARGS = SCANNER_BUILD_ARGS

COPY_DIRECTIVES = SCANNER_COPY_DIRECTIVES

COPY_FILES = SCANNER_COPY_FILES
COPY_ROOTS = SCANNER_COPY_ROOTS
COPY_SINGLE_FILES = SCANNER_COPY_SINGLE_FILES

BUILD_INPUT_FILES: tuple[str, ...] = tuple(
    sorted(
        {
            PRODUCER_RELATIVE_PATH,
            "scripts/scanner_build_contract.py",
            "scripts/source_provenance.py",
            "scripts/grype-db-lock-candidate.py",
            "scripts/docker_runtime_contract.py",
            DOCKERFILE_PATH,
            DOCKERIGNORE_PATH,
            *COPY_FILES,
        },
        key=lambda item: item.encode("utf-8"),
    )
)

EXPECTED_CMD: list[str] = [
    "uvicorn",
    "kodesec_scanner.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8091",
]
REQUIRED_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "PIP_NO_CACHE_DIR": "1",
}
ALLOWED_ENVIRONMENT_KEYS = {
    "PATH",
    "LANG",
    "GPG_KEY",
    "PYTHON_VERSION",
    "PYTHON_SHA256",
    *REQUIRED_ENVIRONMENT,
}


class BuildReceiptError(RuntimeError):
    """The local build boundary could not prove an invariant."""


class DockerProcessCleanupUncertain(BuildReceiptError):
    """The Docker client may still be able to mutate invocation-owned state."""


@dataclass(frozen=True)
class HostIdentity:
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if (
            type(self.uid) is not int
            or type(self.gid) is not int
            or not 1 <= self.uid <= MAX_CONTAINER_ID
            or not 1 <= self.gid <= MAX_CONTAINER_ID
        ):
            raise BuildReceiptError("invoking_identity_invalid")


@dataclass(frozen=True)
class CompletedDocker:
    stdout: bytes
    stderr: bytes


class DockerStatusFailed(BuildReceiptError):
    """A reaped nonzero client; bounded output is for explicit private review."""

    def __init__(self, returncode: int, completed: CompletedDocker) -> None:
        # Normal error reporting must never interpolate raw command output.
        super().__init__("docker_status_failed")
        self.returncode = returncode
        self.completed = completed


_ACTIVE_RUNTIME: RuntimePaths | None = None


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def require_host_identity() -> HostIdentity:
    return HostIdentity(uid=os.getuid(), gid=os.getgid())


def require_review_build_host() -> ScannerReviewBuildTarget:
    try:
        observed = scanner_review_build_target(platform.system(), platform.machine())
    except DockerRuntimeContractError as exc:
        raise BuildReceiptError("build_host_unsupported") from exc
    if REVIEW_TARGET is None or observed != REVIEW_TARGET:
        raise BuildReceiptError("build_host_identity_changed")
    return observed


def _require_repo_root(identity: HostIdentity) -> Path:
    try:
        metadata = REPO_ROOT.lstat()
        resolved = REPO_ROOT.resolve(strict=True)
    except OSError as exc:
        raise BuildReceiptError("repository_root_unavailable") from exc
    if (
        REPO_ROOT.is_symlink()
        or resolved != REPO_ROOT
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or metadata.st_mode & 0o022
    ):
        raise BuildReceiptError("repository_root_unsafe")
    return REPO_ROOT


def _directory_identity(
    path: Path, *, identity: HostIdentity, label: str
) -> tuple[int, ...]:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BuildReceiptError(f"{label}_unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or metadata.st_mode & 0o022
    ):
        raise BuildReceiptError(f"{label}_unsafe")
    return _identity_tuple(metadata)


def _reviewed_repo_directories(*, identity: HostIdentity) -> dict[str, tuple[int, ...]]:
    directories: set[Path] = {REPO_ROOT}
    for relative in BUILD_INPUT_FILES:
        current = (REPO_ROOT / relative).parent
        while current != REPO_ROOT:
            directories.add(current)
            current = current.parent
    for root_relative in COPY_ROOTS:
        root = REPO_ROOT / root_relative
        for current_name, directory_names, _ in os.walk(
            root, topdown=True, followlinks=False
        ):
            current = Path(current_name)
            directories.add(current)
            directory_names[:] = sorted(
                (name for name in directory_names if name != "__pycache__"),
                key=lambda item: item.encode("utf-8"),
            )
            directories.update(current / name for name in directory_names)
    return {
        path.relative_to(REPO_ROOT).as_posix() or ".": _directory_identity(
            path, identity=identity, label="build_input_directory"
        )
        for path in sorted(
            directories,
            key=lambda item: item.relative_to(REPO_ROOT).as_posix().encode("utf-8"),
        )
    }


def require_new_private_output(path: Path, *, identity: HostIdentity) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise BuildReceiptError("output_dir_invalid")
    if path.exists() or path.is_symlink():
        raise BuildReceiptError("output_dir_exists")
    try:
        parent = path.parent
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise BuildReceiptError("output_parent_unavailable") from exc
    if (
        parent.is_symlink()
        or resolved != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise BuildReceiptError("output_parent_not_private")
    return path


def _identity_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_file_bytes(
    path: Path, *, relative: str, identity: HostIdentity
) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BuildReceiptError(f"build_input_unavailable:{relative}") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != identity.uid
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not 0 < before.st_size <= 16 * 1024 * 1024
    ):
        raise BuildReceiptError(f"build_input_unsafe:{relative}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    payload = bytearray()
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(before):
            raise BuildReceiptError(f"build_input_changed:{relative}")
        while chunk := os.read(descriptor, 1024 * 1024):
            payload.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity_tuple(after) != _identity_tuple(before):
        raise BuildReceiptError(f"build_input_changed:{relative}")
    identity_payload = canonical_json_bytes(list(_identity_tuple(after)))
    record = {
        "path": relative,
        "mode": format(stat.S_IMODE(after.st_mode), "04o"),
        "size_bytes": after.st_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "identity_sha256": hashlib.sha256(identity_payload).hexdigest(),
    }
    return record, bytes(payload)


def _stable_file(
    path: Path, *, relative: str, identity: HostIdentity
) -> dict[str, Any]:
    record, _ = _stable_file_bytes(path, relative=relative, identity=identity)
    return record


def _validate_inventory() -> None:
    expected_files = set(COPY_FILES)
    observed_files: set[str] = set()
    for root_relative in COPY_ROOTS:
        root = REPO_ROOT / root_relative
        try:
            root_metadata = root.lstat()
        except OSError as exc:
            raise BuildReceiptError(f"copy_root_unavailable:{root_relative}") from exc
        if (
            root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_mode & 0o022
        ):
            raise BuildReceiptError(f"copy_root_unsafe:{root_relative}")
        for current_name, directory_names, file_names in os.walk(
            root, topdown=True, followlinks=False
        ):
            current = Path(current_name)
            directory_names[:] = sorted(
                (name for name in directory_names if name != "__pycache__"),
                key=lambda item: item.encode("utf-8"),
            )
            for name in directory_names:
                child = current / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise BuildReceiptError(
                        f"copy_inventory_special:{child.relative_to(REPO_ROOT).as_posix()}"
                    )
                if metadata.st_mode & 0o022:
                    raise BuildReceiptError(
                        f"copy_inventory_writable:{child.relative_to(REPO_ROOT).as_posix()}"
                    )
            for name in sorted(file_names, key=lambda item: item.encode("utf-8")):
                if name.endswith((".pyc", ".pyo")):
                    continue
                child = current / name
                relative = child.relative_to(REPO_ROOT).as_posix()
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    raise BuildReceiptError(f"copy_inventory_special:{relative}")
                observed_files.add(relative)
    observed_files.update(COPY_SINGLE_FILES)
    if observed_files != expected_files:
        raise BuildReceiptError("copy_inventory_unexpected")


def _validate_dockerfile(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise BuildReceiptError("dockerfile_not_utf8") from exc
    lines = text.splitlines()
    from_lines = [line for line in lines if line.startswith("FROM ")]
    copy_lines = tuple(line for line in lines if line.startswith("COPY "))
    arg_lines = tuple(line for line in lines if line.startswith("ARG "))
    expected_args = (
        *(f"ARG {key}={value}" for key, value in SCANNER_BUILDER_BUILD_ARGS),
        *(f"ARG {key}={value}" for key, value in BUILD_ARGS),
        "ARG KODESEC_SOURCE_COMMIT",
        "ARG KODESEC_SOURCE_TREE",
        "ARG KODESEC_SOURCE_KIND=git",
        "ARG KODESEC_SOURCE_DIGEST=",
    )
    if tuple(from_lines) != FROM_DIRECTIVES:
        raise BuildReceiptError("dockerfile_base_not_pinned")
    builder_lines = lines[lines.index(FROM_DIRECTIVES[0]) + 1:lines.index(FROM_DIRECTIVES[1])]
    if builder_lines.count(SCANNER_BEARER_OFFLINE_BUILD_DIRECTIVE) != 1:
        raise BuildReceiptError("dockerfile_bearer_build_not_offline")
    if copy_lines != COPY_DIRECTIVES:
        raise BuildReceiptError("dockerfile_copy_contract_changed")
    if arg_lines != expected_args:
        raise BuildReceiptError("dockerfile_build_args_changed")


def collect_build_inputs(*, identity: HostIdentity) -> dict[str, Any]:
    _require_repo_root(identity)
    _validate_inventory()
    directories_before = _reviewed_repo_directories(identity=identity)
    captured = [
        _stable_file_bytes(REPO_ROOT / relative, relative=relative, identity=identity)
        for relative in BUILD_INPUT_FILES
    ]
    records = [item[0] for item in captured]
    if [item["path"] for item in records] != sorted(
        set(BUILD_INPUT_FILES), key=lambda item: item.encode("utf-8")
    ):
        raise BuildReceiptError("build_input_inventory_invalid")
    dockerfile_payload = next(
        payload for record, payload in captured if record["path"] == DOCKERFILE_PATH
    )
    _validate_dockerfile(dockerfile_payload)
    if _reviewed_repo_directories(identity=identity) != directories_before:
        raise BuildReceiptError("build_input_directories_changed")
    content_records = [
        {key: item[key] for key in ("path", "mode", "size_bytes", "sha256")}
        for item in records
    ]
    return {
        "hash_algorithm": "kodesec-scanner-build-inputs-v1",
        "sha256": hashlib.sha256(canonical_json_bytes(content_records)).hexdigest(),
        "identity_sha256": hashlib.sha256(
            canonical_json_bytes(
                [
                    {"path": item["path"], "identity_sha256": item["identity_sha256"]}
                    for item in records
                ]
            )
        ).hexdigest(),
        "file_count": len(records),
        "size_bytes": sum(item["size_bytes"] for item in records),
        "files": records,
    }


def _write_staged_file(path: Path, payload: bytes, *, identity: HostIdentity) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o400)
    completed = False
    try:
        total = 0
        while total < len(payload):
            written = os.write(descriptor, payload[total:])
            if written <= 0:
                raise BuildReceiptError("staged_context_write_failed")
            total += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != identity.uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != len(payload)
        ):
            raise BuildReceiptError("staged_context_file_unproven")
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            try:
                path.unlink()
            except OSError:
                pass


def stage_build_context(
    context_dir: Path, *, identity: HostIdentity
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture reviewed repo files once and build only from those exact bytes."""

    _require_repo_root(identity)
    _validate_inventory()
    directory_identities = _reviewed_repo_directories(identity=identity)
    try:
        context_dir.mkdir(mode=0o700, parents=False)
        context_dir.chmod(0o700)
    except OSError as exc:
        raise BuildReceiptError("staged_context_creation_failed") from exc
    _directory_identity(context_dir, identity=identity, label="staged_context")
    source_records: list[dict[str, Any]] = []
    staged_records: list[dict[str, Any]] = []
    captured_payloads: dict[str, bytes] = {}
    created_directories: set[Path] = {context_dir}
    for relative in BUILD_INPUT_FILES:
        record, payload = _stable_file_bytes(
            REPO_ROOT / relative, relative=relative, identity=identity
        )
        source_records.append(record)
        captured_payloads[relative] = payload
        destination = context_dir / relative
        missing: list[Path] = []
        current = destination.parent
        while current != context_dir and current not in created_directories:
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700, parents=False)
            directory.chmod(0o700)
            created_directories.add(directory)
        _write_staged_file(destination, payload, identity=identity)
    if _reviewed_repo_directories(identity=identity) != directory_identities:
        raise BuildReceiptError("build_input_directories_changed")
    dockerfile_payload = captured_payloads[DOCKERFILE_PATH]
    _validate_dockerfile(dockerfile_payload)
    for directory in sorted(
        created_directories,
        key=lambda item: len(item.relative_to(context_dir).parts),
        reverse=True,
    ):
        directory.chmod(0o500)
    for relative in BUILD_INPUT_FILES:
        staged_path = context_dir / relative
        record, payload = _stable_file_bytes(
            staged_path, relative=relative, identity=identity
        )
        if payload != captured_payloads[relative]:
            raise BuildReceiptError("staged_context_content_mismatch")
        staged_records.append(record)
    context_directories_before = {
        path.relative_to(context_dir).as_posix() or ".": _directory_identity(
            path, identity=identity, label="staged_context_directory"
        )
        for path in sorted(
            created_directories,
            key=lambda item: item.relative_to(context_dir).as_posix().encode("utf-8"),
        )
    }
    observed_files = {
        child.relative_to(context_dir).as_posix()
        for child in context_dir.rglob("*")
        if child.is_file() and not child.is_symlink()
    }
    observed_directories = {
        child
        for child in context_dir.rglob("*")
        if child.is_dir() and not child.is_symlink()
    } | {context_dir}
    if (
        observed_files != set(BUILD_INPUT_FILES)
        or observed_directories != created_directories
    ):
        raise BuildReceiptError("staged_context_inventory_unexpected")
    if {
        path.relative_to(context_dir).as_posix() or ".": _directory_identity(
            path, identity=identity, label="staged_context_directory"
        )
        for path in sorted(
            created_directories,
            key=lambda item: item.relative_to(context_dir).as_posix().encode("utf-8"),
        )
    } != context_directories_before:
        raise BuildReceiptError("staged_context_directories_changed")

    def manifest(records: list[dict[str, Any]], *, algorithm: str) -> dict[str, Any]:
        content_records = [
            {key: item[key] for key in ("path", "mode", "size_bytes", "sha256")}
            for item in records
        ]
        return {
            "hash_algorithm": algorithm,
            "sha256": hashlib.sha256(canonical_json_bytes(content_records)).hexdigest(),
            "identity_sha256": hashlib.sha256(
                canonical_json_bytes(
                    [
                        {
                            "path": item["path"],
                            "identity_sha256": item["identity_sha256"],
                        }
                        for item in records
                    ]
                )
            ).hexdigest(),
            "file_count": len(records),
            "size_bytes": sum(item["size_bytes"] for item in records),
            "files": records,
        }

    return (
        manifest(source_records, algorithm="kodesec-scanner-build-inputs-v1"),
        manifest(staged_records, algorithm="kodesec-scanner-staged-context-v1"),
    )


def _revalidate_staged_context(
    context_dir: Path,
    *,
    expected: Mapping[str, Any],
    identity: HostIdentity,
) -> None:
    """Re-prove the exact staged tree immediately before spawning Docker."""

    expected_directories = {context_dir}
    for relative in BUILD_INPUT_FILES:
        current = (context_dir / relative).parent
        while current != context_dir:
            expected_directories.add(current)
            current = current.parent

    def directory_identities() -> dict[str, tuple[int, ...]]:
        observed: set[Path] = {context_dir}
        try:
            for current_name, directory_names, file_names in os.walk(
                context_dir, topdown=True, followlinks=False
            ):
                current = Path(current_name)
                directory_names[:] = sorted(
                    directory_names, key=lambda item: item.encode("utf-8")
                )
                file_names[:] = sorted(
                    file_names, key=lambda item: item.encode("utf-8")
                )
                observed.update(current / name for name in directory_names)
                for name in file_names:
                    child = current / name
                    if (
                        child.relative_to(context_dir).as_posix()
                        not in BUILD_INPUT_FILES
                    ):
                        raise BuildReceiptError("staged_context_inventory_changed")
        except OSError as exc:
            raise BuildReceiptError("staged_context_inventory_unavailable") from exc
        if observed != expected_directories:
            raise BuildReceiptError("staged_context_inventory_changed")
        result: dict[str, tuple[int, ...]] = {}
        for directory in sorted(
            observed,
            key=lambda item: item.relative_to(context_dir).as_posix().encode("utf-8"),
        ):
            metadata = _directory_identity(
                directory, identity=identity, label="staged_context_directory"
            )
            if stat.S_IMODE(metadata[2]) != 0o500:
                raise BuildReceiptError("staged_context_directory_mode_changed")
            result[directory.relative_to(context_dir).as_posix() or "."] = metadata
        return result

    directories_before = directory_identities()
    records = [
        _stable_file(context_dir / relative, relative=relative, identity=identity)
        for relative in BUILD_INPUT_FILES
    ]
    content_records = [
        {key: item[key] for key in ("path", "mode", "size_bytes", "sha256")}
        for item in records
    ]
    observed_manifest = {
        "hash_algorithm": "kodesec-scanner-staged-context-v1",
        "sha256": hashlib.sha256(canonical_json_bytes(content_records)).hexdigest(),
        "identity_sha256": hashlib.sha256(
            canonical_json_bytes(
                [
                    {
                        "path": item["path"],
                        "identity_sha256": item["identity_sha256"],
                    }
                    for item in records
                ]
            )
        ).hexdigest(),
        "file_count": len(records),
        "size_bytes": sum(item["size_bytes"] for item in records),
        "files": records,
    }
    if observed_manifest != expected:
        raise BuildReceiptError("staged_context_changed_before_spawn")
    if directory_identities() != directories_before:
        raise BuildReceiptError("staged_context_directories_changed_before_spawn")


def build_argv(
    *,
    tag: str,
    iidfile: Path,
    context_dir: Path,
    provenance: SourceProvenance,
) -> tuple[str, ...]:
    match = OWNED_TAG.fullmatch(tag)
    if (
        match is None
        or not iidfile.is_absolute()
        or not context_dir.is_absolute()
        or context_dir.name != STAGED_CONTEXT_NAME
    ):
        raise BuildReceiptError("build_identity_invalid")
    command = [
        "buildx",
        "build",
        "--builder=default",
        "--load",
        "--pull",
        "--no-cache",
        f"--network={BUILD_NETWORK}",
        f"--platform={PLATFORM}",
        f"--file={context_dir / DOCKERFILE_PATH}",
        f"--tag={tag}",
        f"--iidfile={iidfile}",
        f"--label={OWNERSHIP_LABEL_KEY}={match.group(1)}",
    ]
    for key, value in (*provenance.build_args(), *BUILD_ARGS):
        command.append(f"--build-arg={key}={value}")
    command.append(str(context_dir))
    return tuple(command)


def _run_bounded(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_output_bytes: int,
    pre_spawn_check: Callable[[], None] | None = None,
) -> CompletedDocker:
    if pre_spawn_check is not None:
        pre_spawn_check()
    try:
        runtime = _ACTIVE_RUNTIME
        if runtime is None:
            raise BuildReceiptError("docker_runtime_not_configured")
        revalidate_runtime(runtime, invoking_uid=os.getuid())
        process = subprocess.Popen(
            list(argv),
            cwd=runtime.root,
            env=runtime.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise BuildReceiptError("docker_execution_failed") from exc
    except BaseException as exc:
        raise DockerProcessCleanupUncertain("docker_process_start_uncertain") from exc
    selector: selectors.BaseSelector | None = None
    primary: BaseException | None = None
    result: CompletedDocker | None = None
    natural_exit_observed = False
    try:
        if process.stdout is None or process.stderr is None:
            raise BuildReceiptError("docker_capture_unavailable")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout.fileno(): "stdout",
            process.stderr.fileno(): "stderr",
        }
        deadline = time.monotonic() + timeout_seconds
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BuildReceiptError("docker_execution_timed_out")
            events = selector.select(remaining)
            if not events:
                raise BuildReceiptError("docker_execution_timed_out")
            for key, _ in events:
                label = streams[key.fd]
                allowance = maximum_output_bytes - len(captured[label])
                chunk = os.read(key.fd, min(READ_CHUNK_BYTES, allowance + 1))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                if len(chunk) > allowance:
                    raise BuildReceiptError("docker_output_oversized")
                captured[label].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BuildReceiptError("docker_execution_timed_out")
        returncode = process.wait(timeout=remaining)
        natural_exit_observed = True
        if returncode != 0:
            raise DockerStatusFailed(
                returncode,
                CompletedDocker(bytes(captured["stdout"]), bytes(captured["stderr"])),
            )
        result = CompletedDocker(bytes(captured["stdout"]), bytes(captured["stderr"]))
    except BaseException as exc:
        primary = exc
    cleanup_errors: list[BaseException] = []
    forced_stop = False
    try:
        running = process.poll() is None
    except BaseException as exc:
        running = True
        cleanup_errors.append(exc)
    if running or not natural_exit_observed:
        forced_stop = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                process.wait(timeout=5)
            except BaseException as exc:
                cleanup_errors.append(exc)
        except BaseException as exc:
            cleanup_errors.append(exc)
            # A failed/interrupted wait is not proof of exit.  Make one more
            # bounded kill/wait attempt while retaining the original failure.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as kill_exc:
                cleanup_errors.append(kill_exc)
            try:
                process.wait(timeout=5)
            except BaseException as wait_exc:
                cleanup_errors.append(wait_exc)
    try:
        if process.poll() is None:
            cleanup_errors.append(BuildReceiptError("docker_process_survived_cleanup"))
    except BaseException as exc:
        cleanup_errors.append(exc)
    try:
        if selector is not None:
            selector.close()
    except BaseException as exc:
        cleanup_errors.append(exc)
    try:
        if process.stdout is not None:
            process.stdout.close()
    except BaseException as exc:
        cleanup_errors.append(exc)
    try:
        if process.stderr is not None:
            process.stderr.close()
    except BaseException as exc:
        cleanup_errors.append(exc)
    try:
        runtime = _ACTIVE_RUNTIME
        if runtime is None:
            raise BuildReceiptError("docker_runtime_lost")
        revalidate_runtime(runtime, invoking_uid=os.getuid())
    except BaseException as exc:
        cleanup_errors.append(exc)
    if cleanup_errors:
        raise DockerProcessCleanupUncertain(
            "docker_process_cleanup_uncertain"
        ) from cleanup_errors[0]
    if forced_stop or (primary is not None and not natural_exit_observed):
        raise DockerProcessCleanupUncertain(
            "docker_process_completion_uncertain"
        ) from primary
    if primary is not None:
        raise primary
    assert result is not None
    return result


def run_docker(
    argv: Sequence[str],
    *,
    timeout_seconds: int = MAX_BUILD_SECONDS,
    pre_spawn_check: Callable[[], None] | None = None,
) -> CompletedDocker:
    runtime = _ACTIVE_RUNTIME
    if (
        runtime is None
        or not argv
        or argv[0] not in {"docker", "buildx"}
        or not 1 <= timeout_seconds <= MAX_BUILD_SECONDS
    ):
        raise BuildReceiptError("docker_argv_invalid")
    executed = executable_argv(runtime, argv)
    maximum = (
        MAX_BUILD_OUTPUT_BYTES
        if len(argv) > 1 and argv[1] == "build"
        else MAX_RECEIPT_BYTES
    )
    return _run_bounded(
        executed,
        timeout_seconds=timeout_seconds,
        maximum_output_bytes=maximum,
        pre_spawn_check=pre_spawn_check,
    )


def _tag_list_argv(tag: str) -> tuple[str, ...]:
    if OWNED_TAG.fullmatch(tag) is None:
        raise BuildReceiptError("owned_tag_invalid")
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        f"--filter=reference={tag}",
        "--format={{.Repository}}:{{.Tag}}|{{.ID}}",
    )


def _tag_listing(completed: CompletedDocker, *, tag: str) -> str | None:
    if completed.stderr:
        return None
    if completed.stdout == b"":
        return ""
    try:
        rendered = completed.stdout.decode("ascii", errors="strict")
    except UnicodeError:
        return None
    lines = rendered.splitlines()
    if len(lines) != 1:
        return None
    prefix = f"{tag}|"
    if not lines[0].startswith(prefix) or not IMAGE_ID.fullmatch(
        lines[0][len(prefix) :]
    ):
        return None
    return lines[0][len(prefix) :]


def _label_list_argv(invocation_id: str) -> tuple[str, ...]:
    if INVOCATION_ID.fullmatch(invocation_id) is None:
        raise BuildReceiptError("invocation_id_invalid")
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        f"--filter=label={OWNERSHIP_LABEL_KEY}={invocation_id}",
        "--format={{.ID}}",
    )


def _all_image_ids_argv() -> tuple[str, ...]:
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        "--format={{.ID}}",
    )


def _image_id_listing(completed: CompletedDocker) -> set[str] | None:
    if completed.stderr:
        return None
    if completed.stdout == b"":
        return set()
    try:
        lines = completed.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        return None
    if any(IMAGE_ID.fullmatch(line) is None for line in lines):
        return None
    return set(lines)


def _label_listing(completed: CompletedDocker) -> str | None:
    if completed.stderr:
        return None
    if completed.stdout == b"":
        return ""
    try:
        lines = completed.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        return None
    if len(lines) != 1 or IMAGE_ID.fullmatch(lines[0]) is None:
        return None
    return lines[0]


def _cleanup_inspect_argv(reference: str) -> tuple[str, ...]:
    if OWNED_TAG.fullmatch(reference) is None and IMAGE_ID.fullmatch(reference) is None:
        raise BuildReceiptError("cleanup_image_reference_invalid")
    return ("docker", "image", "inspect", "--format={{json .}}", reference)


def _validate_cleanup_image(
    completed: CompletedDocker,
    *,
    image_id: str,
    tag: str,
    invocation_id: str,
    allow_untagged: bool,
    provenance: SourceProvenance,
) -> None:
    if completed.stderr or not 0 < len(completed.stdout) <= MAX_RECEIPT_BYTES:
        raise BuildReceiptError("owned_image_inspect_unproven")
    value = _strict_json_object(completed.stdout, label="owned_image_inspect")
    if (
        value.get("Id") != image_id
        or value.get("Os") != "linux"
        or value.get("Architecture") != ARCHITECTURE
        or not isinstance(value.get("Config"), dict)
        or value["Config"].get("Labels")
        != {OWNERSHIP_LABEL_KEY: invocation_id, **provenance.labels("scanner")}
    ):
        raise BuildReceiptError("owned_image_identity_mismatch")
    repo_tags = value.get("RepoTags")
    if not owned_local_repo_digests(tag, image_id, value.get("RepoDigests")):
        raise BuildReceiptError("owned_image_has_foreign_refs")
    if allow_untagged and repo_tags in (None, []):
        return
    if repo_tags != [tag]:
        raise BuildReceiptError("owned_image_has_foreign_refs")


def _observe_build_identity(*, tag: str, invocation_id: str) -> tuple[str, str]:
    tag_result = run_docker(_tag_list_argv(tag), timeout_seconds=MAX_CONTROL_SECONDS)
    label_result = run_docker(
        _label_list_argv(invocation_id), timeout_seconds=MAX_CONTROL_SECONDS
    )
    tag_id = _tag_listing(tag_result, tag=tag)
    label_id = _label_listing(label_result)
    if tag_id is None or label_id is None:
        raise BuildReceiptError("owned_image_listing_unproven")
    return tag_id, label_id


def prove_build_identity_absent(*, tag: str, invocation_id: str) -> None:
    for _ in range(3):
        try:
            tag_id, label_id = _observe_build_identity(
                tag=tag, invocation_id=invocation_id
            )
        except BaseException as exc:
            raise BuildReceiptError("owned_image_absence_unproven") from exc
        if tag_id != "" or label_id != "":
            raise BuildReceiptError("owned_image_absence_unproven")


def _prove_removed_image_absent(
    *, tag: str, invocation_id: str, expected_id: str
) -> None:
    for _ in range(3):
        try:
            tag_id, label_id = _observe_build_identity(
                tag=tag, invocation_id=invocation_id
            )
            ids = _image_id_listing(
                run_docker(_all_image_ids_argv(), timeout_seconds=MAX_CONTROL_SECONDS)
            )
        except BaseException as exc:
            raise BuildReceiptError("owned_image_absence_unproven") from exc
        if tag_id != "" or label_id != "" or ids is None or expected_id in ids:
            raise BuildReceiptError("owned_image_absence_unproven")


def _cleanup_owned_image(
    *,
    tag: str,
    invocation_id: str,
    expected_id: str | None,
    provenance: SourceProvenance,
) -> None:
    try:
        tag_id, label_id = _observe_build_identity(tag=tag, invocation_id=invocation_id)
        if tag_id == "" and label_id == "":
            prove_build_identity_absent(tag=tag, invocation_id=invocation_id)
            return
        if tag_id and label_id != tag_id:
            raise BuildReceiptError("owned_tag_replaced_or_unattested")
        if tag_id == "" and not label_id:
            raise BuildReceiptError("owned_image_listing_unproven")
        owned_id = label_id
        if expected_id is not None and owned_id != expected_id:
            raise BuildReceiptError("owned_image_id_mismatch")
        allow_untagged = tag_id == ""
        inspected = run_docker(
            _cleanup_inspect_argv(owned_id), timeout_seconds=MAX_CONTROL_SECONDS
        )
        _validate_cleanup_image(
            inspected,
            image_id=owned_id,
            tag=tag,
            invocation_id=invocation_id,
            allow_untagged=allow_untagged,
            provenance=provenance,
        )
        run_docker(
            # Remove by the identity we just inspected.  Removing by tag would
            # create a race in which a concurrent principal could retarget the
            # tag between inspect and rm and have its foreign reference deleted.
            ("docker", "image", "rm", owned_id),
            timeout_seconds=MAX_CONTROL_SECONDS,
        )
        _prove_removed_image_absent(
            tag=tag,
            invocation_id=invocation_id,
            expected_id=owned_id,
        )
    except BuildReceiptError:
        raise
    except BaseException as exc:
        raise BuildReceiptError("owned_image_cleanup_uncertain") from exc


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BuildReceiptError(f"{label}_duplicate_key")
            result[key] = value
        return result

    def reject_nonfinite(_: str) -> None:
        raise BuildReceiptError(f"{label}_nonfinite")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise BuildReceiptError(f"{label}_nonfinite")
        return parsed

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except BuildReceiptError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise BuildReceiptError(f"{label}_invalid") from exc
    if not isinstance(value, dict):
        raise BuildReceiptError(f"{label}_invalid")
    return value


def _load_runtime_observation(
    path: Path, *, identity: HostIdentity
) -> tuple[dict[str, Any], dict[str, str]]:
    if (
        not path.is_absolute()
        or path.name != RUNTIME_OBSERVATION_NAME
        or path.is_symlink()
    ):
        raise BuildReceiptError("runtime_observation_path_invalid")
    try:
        parent = path.parent.lstat()
        before = path.lstat()
        children = {item.name for item in path.parent.iterdir()}
    except OSError as exc:
        raise BuildReceiptError("runtime_observation_unavailable") from exc
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != identity.uid
        or stat.S_IMODE(parent.st_mode) != 0o700
        or children != {RUNTIME_OBSERVATION_NAME}
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != identity.uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 0 < before.st_size <= MAX_RECEIPT_BYTES
    ):
        raise BuildReceiptError("runtime_observation_identity_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    payload = bytearray()
    try:
        if _identity_tuple(os.fstat(descriptor)) != _identity_tuple(before):
            raise BuildReceiptError("runtime_observation_identity_invalid")
        while chunk := os.read(descriptor, 64 * 1024):
            payload.extend(chunk)
            if len(payload) > MAX_RECEIPT_BYTES:
                raise BuildReceiptError("runtime_observation_oversized")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity_tuple(after) != _identity_tuple(before):
        raise BuildReceiptError("runtime_observation_changed")
    raw = bytes(payload)
    receipt = _strict_json_object(raw, label="runtime_observation")
    if raw != canonical_json_bytes(receipt) or set(receipt) != {
        "schema",
        "authoritative",
        "execution",
        "observation",
        "receipt_sha256",
    }:
        raise BuildReceiptError("runtime_observation_receipt_invalid")
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_sha256", None)
    if (
        receipt.get("schema") != RUNTIME_OBSERVATION_SCHEMA
        or receipt.get("authoritative") is not False
        or not isinstance(claimed, str)
        or claimed != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    ):
        raise BuildReceiptError("runtime_observation_receipt_invalid")
    execution = receipt.get("execution")
    observation = receipt.get("observation")
    if (
        not isinstance(execution, dict)
        or execution.get("schema") != "kodesec.docker-runtime-execution/v1"
        or set(execution) != {
            "schema",
            "docker",
            "buildx",
            "daemon",
            "environment",
            "policy",
        }
        or not isinstance(observation, dict)
        or observation.get("schema") != "kodesec.docker-runtime-observation/v1"
        or not SHA256.fullmatch(str(observation.get("sha256", "")))
    ):
        raise BuildReceiptError("runtime_observation_contract_invalid")
    for label in ("docker", "buildx"):
        value = execution.get(label)
        if not isinstance(value, dict) or set(value) != {"source", "snapshot"}:
            raise BuildReceiptError("runtime_observation_contract_invalid")
        source = value.get("source")
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("path"), str)
            or not Path(source["path"]).is_absolute()
            or not SHA256.fullmatch(str(source.get("sha256", "")))
        ):
            raise BuildReceiptError("runtime_observation_contract_invalid")
    daemon = execution.get("daemon")
    if (
        not isinstance(daemon, dict)
        or set(daemon) != {"host", "socket"}
        or not isinstance(daemon.get("host"), str)
    ):
        raise BuildReceiptError("runtime_observation_contract_invalid")
    return receipt, {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "receipt_sha256": claimed,
    }


def _observe_active_runtime() -> dict[str, Any]:
    version = run_docker(
        ("docker", "version", "--format={{json .}}"),
        timeout_seconds=MAX_CONTROL_SECONDS,
    )
    info = run_docker(
        ("docker", "info", "--format={{json .}}"),
        timeout_seconds=MAX_CONTROL_SECONDS,
    )
    buildx = run_docker(
        ("buildx", "ls", "--format=json", "--no-trunc"),
        timeout_seconds=MAX_CONTROL_SECONDS,
    )
    if version.stderr or info.stderr or buildx.stderr:
        raise BuildReceiptError("runtime_observation_stderr_nonempty")
    try:
        return combined_observation(
            normalize_daemon_observation(version.stdout, info.stdout),
            normalize_buildx_observation(buildx.stdout),
        )
    except DockerRuntimeContractError as exc:
        raise BuildReceiptError("runtime_observation_invalid") from exc


def _prepare_authorized_runtime(
    observation_path: Path,
    output_dir: Path,
    *,
    identity: HostIdentity,
) -> tuple[RuntimePaths, dict[str, Any], dict[str, str]]:
    receipt, receipt_identity = _load_runtime_observation(
        observation_path, identity=identity
    )
    execution = receipt["execution"]
    try:
        runtime = prepare_runtime(
            output_dir / RUNTIME_DIRECTORY_NAME,
            docker_executable=Path(execution["docker"]["source"]["path"]),
            docker_sha256=execution["docker"]["source"]["sha256"],
            buildx_executable=Path(execution["buildx"]["source"]["path"]),
            buildx_sha256=execution["buildx"]["source"]["sha256"],
            docker_host=execution["daemon"]["host"],
            invoking_uid=identity.uid,
        )
    except DockerRuntimeContractError as exc:
        raise BuildReceiptError("docker_runtime_preparation_failed") from exc
    global _ACTIVE_RUNTIME
    _ACTIVE_RUNTIME = runtime
    if _observe_active_runtime() != receipt["observation"]:
        raise BuildReceiptError("docker_runtime_observation_drift")
    return runtime, receipt, receipt_identity


def _normalize_security_config(
    value: Any,
    *,
    invocation_id: str,
    provenance: SourceProvenance,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuildReceiptError("image_config_invalid")
    entrypoint = value.get("Entrypoint")
    command = value.get("Cmd")
    user = value.get("User")
    working_dir = value.get("WorkingDir")
    volumes = value.get("Volumes")
    environment = value.get("Env")
    labels = value.get("Labels")
    if (
        entrypoint is not None
        or command != EXPECTED_CMD
        or user != "kodesec"
        or working_dir != "/app"
        or volumes not in (None, {})
        or labels != {OWNERSHIP_LABEL_KEY: invocation_id, **provenance.labels("scanner")}
        or not isinstance(environment, list)
        or not 1 <= len(environment) <= 16
    ):
        raise BuildReceiptError("image_security_config_invalid")
    normalized_environment: list[str] = []
    environment_values: dict[str, str] = {}
    for item in environment:
        if (
            not isinstance(item, str)
            or len(item) > 1024
            or "=" not in item
            or any(char in item for char in "\r\n\x00")
        ):
            raise BuildReceiptError("image_environment_invalid")
        key, item_value = item.split("=", 1)
        if (
            ENVIRONMENT_KEY.fullmatch(key) is None
            or key not in ALLOWED_ENVIRONMENT_KEYS
            or key in environment_values
        ):
            raise BuildReceiptError("image_environment_invalid")
        environment_values[key] = item_value
        normalized_environment.append(item)
    if any(
        environment_values.get(key) != expected
        for key, expected in REQUIRED_ENVIRONMENT.items()
    ):
        raise BuildReceiptError("image_environment_invalid")
    return {
        "Entrypoint": None,
        "Cmd": list(command),
        "User": user,
        "WorkingDir": working_dir,
        "Volumes": None,
        "Env": normalized_environment,
        "Labels": {OWNERSHIP_LABEL_KEY: invocation_id, **provenance.labels("scanner")},
    }


def parse_image_inspect(
    raw: bytes,
    *,
    tag: str,
    expected_id: str,
    provenance: SourceProvenance,
) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_RECEIPT_BYTES or not IMAGE_ID.fullmatch(expected_id):
        raise BuildReceiptError("image_inspect_invalid")
    value = _strict_json_object(raw, label="image_inspect")
    required = {"Id", "Os", "Architecture", "RepoTags", "RepoDigests", "Config"}
    if not required.issubset(value):
        raise BuildReceiptError("image_inspect_shape_invalid")
    if (
        value["Id"] != expected_id
        or value["Os"] != "linux"
        or value["Architecture"] != ARCHITECTURE
        or value["RepoTags"] != [tag]
        or not owned_local_repo_digests(tag, expected_id, value["RepoDigests"])
    ):
        raise BuildReceiptError("image_identity_mismatch")
    match = OWNED_TAG.fullmatch(tag)
    if match is None:
        raise BuildReceiptError("owned_tag_invalid")
    config = _normalize_security_config(
        value["Config"],
        invocation_id=match.group(1),
        provenance=provenance,
    )
    return {
        "id": expected_id,
        "os": "linux",
        "architecture": ARCHITECTURE,
        "owned_tag": tag,
        "security_config": config,
    }


def _read_iidfile(path: Path, *, identity: HostIdentity) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise BuildReceiptError("iidfile_unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != identity.uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 71 <= before.st_size <= 72
    ):
        raise BuildReceiptError("iidfile_identity_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, 73)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity_tuple(before) != _identity_tuple(opened) or _identity_tuple(
        before
    ) != _identity_tuple(after):
        raise BuildReceiptError("iidfile_identity_invalid")
    rendered = payload.rstrip(b"\n")
    if payload not in (rendered, rendered + b"\n"):
        raise BuildReceiptError("iidfile_identity_invalid")
    try:
        image_id = rendered.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise BuildReceiptError("iidfile_identity_invalid") from exc
    if IMAGE_ID.fullmatch(image_id) is None:
        raise BuildReceiptError("iidfile_identity_invalid")
    try:
        path.unlink()
    except OSError as exc:
        raise BuildReceiptError("iidfile_cleanup_uncertain") from exc
    if path.exists() or path.is_symlink():
        raise BuildReceiptError("iidfile_cleanup_uncertain")
    return image_id


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _invalidate_receipt(path: Path, *, identity: HostIdentity) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BuildReceiptError("receipt_invalidation_uncertain") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or not 1 <= metadata.st_nlink <= 2
    ):
        raise BuildReceiptError("receipt_invalidation_uncertain")
    invalidated = False
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if _identity_tuple(opened) != _identity_tuple(metadata):
                raise BuildReceiptError("receipt_invalidation_uncertain")
            os.fchmod(descriptor, 0o000)
            os.ftruncate(descriptor, 0)
            os.write(descriptor, b"INVALID\n")
            os.fsync(descriptor)
            invalidated = True
            current = path.lstat()
            if (
                current.st_dev,
                current.st_ino,
                current.st_uid,
            ) != (opened.st_dev, opened.st_ino, opened.st_uid):
                raise BuildReceiptError("receipt_removal_uncertain")
        finally:
            os.close(descriptor)
            descriptor = -1
        path.unlink()
        _fsync_directory(path.parent)
    except BuildReceiptError:
        raise
    except OSError as exc:
        if invalidated:
            # A remaining mode-000 INVALID marker is not a consumable receipt.
            raise BuildReceiptError("receipt_removal_uncertain") from exc
        raise BuildReceiptError("receipt_invalidation_uncertain") from exc


def _publish_private(
    path: Path,
    payload: bytes,
    *,
    identity: HostIdentity,
    invocation_id: str,
) -> None:
    if not 0 < len(payload) <= MAX_RECEIPT_BYTES:
        raise BuildReceiptError("receipt_size_invalid")
    parent = path.parent
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or path.exists()
        or path.is_symlink()
    ):
        raise BuildReceiptError("receipt_destination_unsafe")
    if INVOCATION_ID.fullmatch(invocation_id) is None:
        raise BuildReceiptError("invocation_id_invalid")
    temporary = parent / f".{path.name}.{invocation_id}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise BuildReceiptError("receipt_temporary_exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    published = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        total = 0
        while total < len(payload):
            written = os.write(descriptor, payload[total:])
            if written <= 0:
                raise BuildReceiptError("receipt_write_failed")
            total += written
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != identity.uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size != len(payload)
        ):
            raise BuildReceiptError("receipt_publication_unproven")
        os.close(descriptor)
        descriptor = -1
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.link(
                temporary.name,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            published = True
            os.unlink(temporary.name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        final = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(final.st_mode)
            or final.st_uid != identity.uid
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_size != len(payload)
        ):
            raise BuildReceiptError("receipt_publication_unproven")
    except BaseException as primary:
        cleanup_error: BaseException | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_error = exc
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup_error = cleanup_error or exc
        if published or path.exists() or path.is_symlink():
            try:
                _invalidate_receipt(path, identity=identity)
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise BuildReceiptError("receipt_rollback_uncertain") from cleanup_error
        raise primary


def _remove_staged_context(path: Path, *, identity: HostIdentity) -> None:
    try:
        root = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BuildReceiptError("staged_context_cleanup_uncertain") from exc
    if (
        path.name != STAGED_CONTEXT_NAME
        or path.is_symlink()
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != identity.uid
        or path.resolve(strict=True) != path
    ):
        raise BuildReceiptError("staged_context_cleanup_uncertain")
    try:
        for current_name, directory_names, file_names in os.walk(
            path, topdown=False, followlinks=False
        ):
            current = Path(current_name)
            current_metadata = current.lstat()
            if (
                current.is_symlink()
                or not stat.S_ISDIR(current_metadata.st_mode)
                or current_metadata.st_uid != identity.uid
            ):
                raise BuildReceiptError("staged_context_cleanup_uncertain")
            # The staged tree is deliberately owner-read/execute-only while
            # Docker consumes it.  Restore write permission on each reviewed
            # directory before unlinking its children (required on Darwin).
            current.chmod(0o700)
            for name in file_names:
                child = current / name
                metadata = child.lstat()
                if (
                    child.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                    or metadata.st_nlink != 1
                ):
                    raise BuildReceiptError("staged_context_cleanup_uncertain")
                child.chmod(0o600)
                child.unlink()
            for name in directory_names:
                child = current / name
                metadata = child.lstat()
                if (
                    child.is_symlink()
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                ):
                    raise BuildReceiptError("staged_context_cleanup_uncertain")
                child.chmod(0o700)
                child.rmdir()
        path.rmdir()
    except BuildReceiptError:
        raise
    except OSError as exc:
        raise BuildReceiptError("staged_context_cleanup_uncertain") from exc


def _remove_private_output(path: Path, *, identity: HostIdentity) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or path.resolve(strict=True) != path
    ):
        raise BuildReceiptError("output_cleanup_uncertain")
    for child in path.iterdir():
        child_metadata = child.lstat()
        if (
            child.is_symlink()
            or not stat.S_ISREG(child_metadata.st_mode)
            or child_metadata.st_uid != identity.uid
            or child_metadata.st_nlink != 1
        ):
            raise BuildReceiptError("output_cleanup_uncertain")
        child.unlink()
    path.rmdir()


def produce(
    output_dir: Path,
    runtime_observation_path: Path,
    *,
    identity: HostIdentity,
) -> Path:
    observed_identity = require_host_identity()
    if identity != observed_identity:
        raise BuildReceiptError("invoking_identity_changed")
    review_target = require_review_build_host()
    _require_repo_root(identity)
    try:
        provenance = resolve_source_provenance(
            REPO_ROOT,
            (
                *SCANNER_IMAGE_INPUT_PATHS,
                PRODUCER_RELATIVE_PATH,
                "scripts/docker_runtime_contract.py",
                "scripts/grype-db-lock-candidate.py",
                "scripts/source_provenance.py",
            ),
        )
    except SourceProvenanceError as exc:
        raise BuildReceiptError("source_provenance_invalid") from exc
    if provenance.kind != "git":
        raise BuildReceiptError("review_build_requires_git_source")
    invocation_id = secrets.token_hex(16)
    tag = f"lomo-kodesec-scanner:trivy-review-{invocation_id}"
    iidfile = output_dir / ".scanner-build.iid"
    context_dir = output_dir / STAGED_CONTEXT_NAME
    receipt_path = output_dir / "scanner-build-receipt.json"
    created = False
    succeeded = False
    build_attempted = False
    image_id: str | None = None
    primary: BaseException | None = None
    result: Path | None = None
    runtime: RuntimePaths | None = None
    runtime_observation: dict[str, Any] | None = None
    runtime_observation_identity: dict[str, str] | None = None
    try:
        output_dir.mkdir(mode=0o700, parents=False)
        output_dir.chmod(0o700)
        created = True
        (
            runtime,
            runtime_observation,
            runtime_observation_identity,
        ) = _prepare_authorized_runtime(
            runtime_observation_path,
            output_dir,
            identity=identity,
        )
        prove_build_identity_absent(tag=tag, invocation_id=invocation_id)
        if iidfile.exists() or iidfile.is_symlink():
            raise BuildReceiptError("iidfile_preexisting")
        before, staged_context = stage_build_context(context_dir, identity=identity)
        producer_record = next(
            item for item in before["files"] if item["path"] == PRODUCER_RELATIVE_PATH
        )
        argv = build_argv(
            tag=tag,
            iidfile=iidfile,
            context_dir=context_dir,
            provenance=provenance,
        )
        previous_umask = os.umask(0o077)
        try:
            build_attempted = True
            run_docker(
                argv,
                timeout_seconds=MAX_BUILD_SECONDS,
                pre_spawn_check=lambda: _revalidate_staged_context(
                    context_dir,
                    expected=staged_context,
                    identity=identity,
                ),
            )
        finally:
            os.umask(previous_umask)
        image_id = _read_iidfile(iidfile, identity=identity)
        inspected = run_docker(
            ("docker", "image", "inspect", "--format={{json .}}", tag),
            timeout_seconds=MAX_CONTROL_SECONDS,
        )
        if inspected.stderr:
            raise BuildReceiptError("image_inspect_stderr_nonempty")
        image = parse_image_inspect(
            inspected.stdout,
            tag=tag,
            expected_id=image_id,
            provenance=provenance,
        )
        after = collect_build_inputs(identity=identity)
        if after != before:
            raise BuildReceiptError("build_inputs_changed_during_build")
        # Docker no longer needs the context after the CLI has exited and the
        # exact image identity is known.  A receipt is never published while a
        # mutable staging tree survives.
        _remove_staged_context(context_dir, identity=identity)
        receipt: dict[str, Any] = {
            "schema": SCHEMA,
            "authoritative": False,
            "invocation_id": invocation_id,
            "producer": {
                "path": PRODUCER_RELATIVE_PATH,
                "sha256": producer_record["sha256"],
            },
            "host_execution_identity": {
                "uid": identity.uid,
                "gid": identity.gid,
                "system": review_target.host_system,
                "machine": review_target.host_machine,
            },
            "docker_runtime": {
                "observation_receipt": runtime_observation_identity,
                "observation": runtime_observation["observation"],
                "execution": runtime.record(),
            },
            "build": {
                "platform": PLATFORM,
                "network": BUILD_NETWORK,
                "pull": True,
                "no_cache": True,
                "context": str(context_dir),
                "dockerfile": str(context_dir / DOCKERFILE_PATH),
                "tag": tag,
                "source": {
                    "commit": provenance.commit,
                    "tree": provenance.tree,
                    "build_identity": provenance.labels("scanner")[BUILD_IDENTITY_LABEL],
                },
                "args": [
                    {"name": key, "value": value}
                    for key, value in (*provenance.build_args(), *BUILD_ARGS)
                ],
                "argv": list(argv),
                "argv_sha256": hashlib.sha256(
                    canonical_json_bytes(list(argv))
                ).hexdigest(),
            },
            "inputs_before": before,
            "inputs_after": after,
            "staged_context": staged_context,
            "image": image,
            "lifecycle": {
                "tag_absent_before": True,
                "tag_held_for_consumer": True,
                "iidfile_absent_before": True,
                "iidfile_removed": True,
                "staged_context_removed": True,
                "runtime_snapshots_held_for_consumer": True,
            },
        }
        receipt["receipt_sha256"] = hashlib.sha256(
            canonical_json_bytes(receipt)
        ).hexdigest()
        _publish_private(
            receipt_path,
            canonical_json_bytes(receipt),
            identity=identity,
            invocation_id=invocation_id,
        )
        succeeded = True
        result = receipt_path
    except BaseException as exc:
        primary = exc
    if not succeeded:
        cleanup_errors: list[BaseException] = []

        def attempt(operation) -> None:
            try:
                operation()
            except BaseException as exc:
                cleanup_errors.append(exc)

        attempt(lambda: _invalidate_receipt(receipt_path, identity=identity))
        process_cleanup_uncertain = isinstance(primary, DockerProcessCleanupUncertain)
        if build_attempted and not process_cleanup_uncertain:
            attempt(
                lambda: _cleanup_owned_image(
                    tag=tag,
                    invocation_id=invocation_id,
                    expected_id=image_id,
                    provenance=provenance,
                )
            )

        def remove_iidfile() -> None:
            try:
                metadata = iidfile.lstat()
            except FileNotFoundError:
                return
            if (
                iidfile.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != identity.uid
                or metadata.st_nlink != 1
            ):
                raise BuildReceiptError("iidfile_cleanup_uncertain")
            iidfile.unlink()

        if not process_cleanup_uncertain:
            attempt(remove_iidfile)
            attempt(lambda: _remove_staged_context(context_dir, identity=identity))
            if runtime is not None:
                attempt(lambda: remove_runtime(runtime, invoking_uid=identity.uid))
            if created:
                attempt(lambda: _remove_private_output(output_dir, identity=identity))
        global _ACTIVE_RUNTIME
        _ACTIVE_RUNTIME = None
        if cleanup_errors:
            raise BuildReceiptError(
                "build_cleanup_uncertain:"
                + ",".join(type(item).__name__ for item in cleanup_errors)
            ) from cleanup_errors[0]
    if primary is not None:
        raise primary
    _ACTIVE_RUNTIME = None
    assert result is not None
    return result


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runtime-observation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        args.identity = require_host_identity()
        args.output_dir = require_new_private_output(
            args.output_dir, identity=args.identity
        )
    except BuildReceiptError as exc:
        parser.error(str(exc))
    return args


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        receipt = produce(
            arguments.output_dir,
            arguments.runtime_observation,
            identity=arguments.identity,
        )
    except DockerProcessCleanupUncertain as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except (BuildReceiptError, DockerRuntimeContractError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
