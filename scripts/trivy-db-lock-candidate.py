#!/usr/bin/env python3
"""Fail-closed host boundary for reviewing a Trivy DB lock candidate.

The three container runs deliberately cannot see the same inputs: preflight
sees the current lock and fixtures without network, fetch sees only a new
private output directory with registry egress, and canary sees only the
candidate DB plus current lock/fixtures without network.  Their exact receipts
must agree before this script emits a non-authoritative lock proposal.
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
from typing import Any, Mapping, Sequence

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from docker_runtime_contract import (  # noqa: E402
    DockerRuntimeContractError,
    RuntimePaths,
    combined_observation,
    executable_argv,
    normalize_buildx_observation,
    normalize_daemon_observation,
    owned_local_repo_digests,
    revalidate_runtime,
    scanner_review_build_target,
)
from source_provenance import (  # noqa: E402
    BUILD_IDENTITY_LABEL,
    SourceProvenance,
    SourceProvenanceError,
    resolve_source_provenance,
)
from scanner_build_contract import (  # noqa: E402
    SCANNER_BUILD_ARGS,
    SCANNER_COPY_FILES,
    SCANNER_COPY_ROOTS,
    SCANNER_COPY_SINGLE_FILES,
)


IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
TRIVY_VERSION = "0.73.0"
TRIVY_PATH = "/usr/local/bin/trivy"
LOCK_IN_IMAGE = "/usr/local/share/kodesec/locks/scanner-tools.lock.json"
TOOL_MANIFEST_IN_IMAGE = "/usr/local/share/kodesec/tool-manifest.json"
REVIEW_ROOT = "/run/kodesec-review"
MAX_DOCKER_OUTPUT_BYTES = 1024 * 1024
MAX_DOCKER_TIMEOUT_SECONDS = 900
DOCKER_CONTROL_TIMEOUT_SECONDS = 30
MAX_CONTAINER_NAME_BYTES = 128
READ_CHUNK_BYTES = 64 * 1024
MAX_CONTAINER_ID = (1 << 31) - 1
CONTAINER_ID = re.compile(rb"[0-9a-f]{64}\Z")
REPO_ROOT = Path(__file__).resolve().parents[1]
CURRENT_LOCK_PATH = REPO_ROOT / "scanner-tools.lock.json"
POSITIVE_FIXTURE_PATH = (
    REPO_ROOT / "tests/scanner-runtime/fixtures/dependencies/positive"
)
ZERO_FIXTURE_PATH = REPO_ROOT / "tests/scanner-runtime/fixtures/dependencies/zero"
JAVA_POSITIVE_FIXTURE_IN_IMAGE = (
    "/usr/local/share/kodesec/canaries/trivy/java/log4j-core-2.14.1.jar"
)
SCANNER_PACKAGE_ROOT = REPO_ROOT / "services/scanner"
BUILD_RECEIPT_SCHEMA = "kodesec.scanner-build-receipt/v2"
BUILD_RECEIPT_NAME = "scanner-build-receipt.json"
BUILD_PRODUCER_PATH = REPO_ROOT / "scripts/scanner-build-receipt.py"
BUILD_PRODUCER_RELATIVE_PATH = "scripts/scanner-build-receipt.py"
BUILD_DOCKERFILE = "services/scanner/Dockerfile"
BUILD_DOCKERIGNORE = ".dockerignore"
BUILD_STAGED_CONTEXT_NAME = ".scanner-build-context"
try:
    REVIEW_TARGET = scanner_review_build_target(platform.system(), platform.machine())
except DockerRuntimeContractError:
    REVIEW_TARGET = None
BUILD_PLATFORM = REVIEW_TARGET.image_platform if REVIEW_TARGET is not None else ""
BUILD_ARCHITECTURE = REVIEW_TARGET.image_architecture if REVIEW_TARGET is not None else ""
BUILD_NETWORK = "default"
BUILD_OWNERSHIP_LABEL_KEY = "io.lomodev.kodesec.trivy-review-build"
BUILD_TAG = re.compile(r"lomo-kodesec-scanner:trivy-review-([0-9a-f]{32})\Z")
BUILD_ARGS = SCANNER_BUILD_ARGS
BUILD_COPY_ROOTS = SCANNER_COPY_ROOTS
BUILD_COPY_SINGLE_FILES = SCANNER_COPY_SINGLE_FILES
BUILD_COPY_FILES = SCANNER_COPY_FILES
BUILD_INPUT_FILES: tuple[str, ...] = tuple(
    sorted(
        {
            BUILD_PRODUCER_RELATIVE_PATH,
            "scripts/scanner_build_contract.py",
            "scripts/source_provenance.py",
            "scripts/grype-db-lock-candidate.py",
            "scripts/docker_runtime_contract.py",
            BUILD_DOCKERFILE,
            BUILD_DOCKERIGNORE,
            *BUILD_COPY_FILES,
        },
        key=lambda item: item.encode("utf-8"),
    )
)
BUILD_EXPECTED_CMD: list[str] = [
    "uvicorn",
    "kodesec_scanner.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8091",
]
BUILD_REQUIRED_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "PIP_NO_CACHE_DIR": "1",
}
BUILD_ALLOWED_ENVIRONMENT_KEYS = {
    "PATH",
    "LANG",
    "GPG_KEY",
    "PYTHON_VERSION",
    "PYTHON_SHA256",
    *BUILD_REQUIRED_ENVIRONMENT,
}
INNER_FAILURE_MARKER = b"kodesec_candidate_failure/v1"
INNER_FAILURE_CODES = {
    "preflight": frozenset(
        {
            "architecture",
            "current_lock",
            "baked_lock",
            "lock_binding",
            "fixtures",
            "trivy_binary",
            "tool_manifest",
            "implementation_bundle",
            "version_probe",
            "unexpected",
        }
    ),
    "fetch": frozenset({"validation", "unexpected"}),
    "canary": frozenset(
        {
            "input",
            "fixtures",
            "candidate_tree",
            "command",
            "output",
            "semantics",
            "unexpected",
        }
    ),
}
GRYPE_INNER_FAILURE_CODES = {
    "preflight": frozenset({"validation", "unexpected"}),
    "fetch": frozenset(
        {"network", "listing", "archive", "validation", "unexpected"}
    ),
    "import": frozenset(
        {"input", "command", "status", "tree", "timeout", "validation", "unexpected"}
    ),
    "canary": frozenset(
        {
            "input",
            "command",
            "output",
            "semantics",
            "tree",
            "validation",
            "unexpected",
        }
    ),
}

COMPONENT_CONTRACTS: Mapping[str, Mapping[str, str]] = {
    "trivy-db": {
        "repository": "aquasecurity/trivy-db",
        "reference": "2",
        "cache_child": "db",
        "receipt_prefix": "kodesec.trivy-db-lock-candidate",
    },
    "trivy-java-db": {
        "repository": "aquasecurity/trivy-java-db",
        "reference": "1",
        "cache_child": "java-db",
        "receipt_prefix": "kodesec.trivy-java-db-lock-candidate",
    },
}

DOCKER_RUN_MODES: Mapping[str, frozenset[str]] = {
    "trivy-db": frozenset({"preflight", "fetch", "canary"}),
    "trivy-java-db": frozenset({"preflight", "fetch", "canary"}),
    # The host-only Grype lock producer reuses this module's owned-container
    # lifecycle without becoming a Trivy candidate component.
    "grype-db": frozenset({"preflight", "fetch", "import", "canary"}),
}


def _component_contract(component_id: str) -> Mapping[str, str]:
    try:
        return COMPONENT_CONTRACTS[component_id]
    except (KeyError, TypeError) as exc:
        raise CandidateCliError("component_id_invalid") from exc


def _docker_run_modes(component_id: str) -> frozenset[str]:
    try:
        return DOCKER_RUN_MODES[component_id]
    except (KeyError, TypeError) as exc:
        raise CandidateCliError("docker_run_component_invalid") from exc


class CandidateCliError(RuntimeError):
    """The host review boundary could not prove an invariant."""


class DockerProcessCleanupUncertain(CandidateCliError):
    """A Docker client may still mutate invocation-owned state."""


def _inner_failure_status(
    argv: Sequence[str], *, returncode: int, stdout: bytes, stderr: bytes
) -> str | None:
    """Translate only one exact allowlisted inner marker; never echo stderr."""

    contracts = [
        (mode, INNER_FAILURE_CODES[mode])
        for mode in INNER_FAILURE_CODES
        if mode in argv
    ] + [
        (mode, GRYPE_INNER_FAILURE_CODES[mode])
        for mode in GRYPE_INNER_FAILURE_CODES
        if f"internal-{mode}" in argv
    ]
    if returncode != 2 or stdout or len(contracts) != 1:
        return None
    mode, allowed_codes = contracts[0]
    for code in allowed_codes:
        expected = INNER_FAILURE_MARKER + f" {mode} {code}\n".encode("ascii")
        if stderr == expected:
            return f"{mode}_{code}"
    return None


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
            raise CandidateCliError("invoking_identity_invalid")


@dataclass(frozen=True)
class ReviewInputs:
    image_id: str
    architecture: str
    output_dir: Path
    identity: HostIdentity
    invocation_id: str
    component_id: str = "trivy-db"
    support_trivy_db: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, HostIdentity):
            raise CandidateCliError("invoking_identity_invalid")
        if not isinstance(self.invocation_id, str) or not INVOCATION_ID.fullmatch(
            self.invocation_id
        ):
            raise CandidateCliError("invocation_id_invalid")
        _component_contract(self.component_id)
        if (self.component_id == "trivy-java-db") != (
            self.support_trivy_db is not None
        ):
            raise CandidateCliError("support_trivy_db_invalid")


@dataclass(frozen=True)
class CompletedDocker:
    stdout: bytes
    stderr: bytes


_ACTIVE_RUNTIME: RuntimePaths | None = None


@dataclass(frozen=True)
class DockerRunIdentity:
    name: str
    cidfile: Path

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not re.fullmatch(
                r"(?:kodesec-trivy-(?:db|java-db)-[0-9a-f]{32}-(?:preflight|fetch|canary)|kodesec-grype-db-[0-9a-f]{32}-(?:preflight|fetch|import|canary))",
                self.name,
            )
            or len(self.name) > MAX_CONTAINER_NAME_BYTES
            or not self.cidfile.is_absolute()
            or self.cidfile.name != f"{self.name}.cid"
        ):
            raise CandidateCliError("docker_run_identity_invalid")


def require_image_id(value: str) -> str:
    if not IMAGE_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("image must be one exact lowercase sha256 ID")
    return value


def require_host_identity(
    *, uid: int | None = None, gid: int | None = None
) -> HostIdentity:
    """Return the invoking non-root identity accepted by Docker's user boundary."""

    observed_uid = os.getuid() if uid is None else uid
    observed_gid = os.getgid() if gid is None else gid
    return HostIdentity(uid=observed_uid, gid=observed_gid)


def require_new_private_output(
    path: Path, *, identity: HostIdentity | None = None
) -> Path:
    """Validate a narrow absolute output path without creating it."""

    owner = identity or require_host_identity()
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CandidateCliError("output_dir_invalid")
    if path.exists() or path.is_symlink():
        raise CandidateCliError("output_dir_exists")
    parent = path.parent
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError("output_parent_unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner.uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != parent
    ):
        raise CandidateCliError("output_parent_not_private")
    if "," in str(path) or any(char in str(path) for char in "\r\n\x00"):
        raise CandidateCliError("output_path_unsafe_for_mount")
    return path


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


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


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise CandidateCliError(f"{label}_duplicate_key")
            result[key] = item
        return result

    def reject_nonfinite(_: str) -> None:
        raise CandidateCliError(f"{label}_nonfinite_number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise CandidateCliError(f"{label}_nonfinite_number")
        return parsed

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except CandidateCliError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CandidateCliError(f"{label}_invalid") from exc
    if not isinstance(value, dict):
        raise CandidateCliError(f"{label}_invalid")
    return value


def _read_private_build_receipt(path: Path, *, identity: HostIdentity) -> bytes:
    if not path.is_absolute() or path.name != BUILD_RECEIPT_NAME or path.is_symlink():
        raise CandidateCliError("build_receipt_path_invalid")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
        before = path.lstat()
    except OSError as exc:
        raise CandidateCliError("build_receipt_unavailable") from exc
    if (
        parent.is_symlink()
        or parent.resolve(strict=True) != parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != identity.uid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != identity.uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 0 < before.st_size <= MAX_DOCKER_OUTPUT_BYTES
    ):
        raise CandidateCliError("build_receipt_identity_invalid")
    try:
        children = {item.name for item in parent.iterdir()}
    except OSError as exc:
        raise CandidateCliError("build_receipt_parent_unreadable") from exc
    if children != {BUILD_RECEIPT_NAME, ".docker-runtime"}:
        raise CandidateCliError("build_receipt_parent_not_exact")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    payload = bytearray()
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(before):
            raise CandidateCliError("build_receipt_identity_invalid")
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_DOCKER_OUTPUT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > MAX_DOCKER_OUTPUT_BYTES:
                raise CandidateCliError("build_receipt_identity_invalid")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity_tuple(after) != _identity_tuple(before):
        raise CandidateCliError("build_receipt_changed_while_reading")
    return bytes(payload)


def _stable_build_input_record(
    path: Path, *, relative: str, identity: HostIdentity
) -> dict[str, Any]:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError(f"build_input_unavailable:{relative}") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != identity.uid
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not 0 < before.st_size <= 16 * 1024 * 1024
    ):
        raise CandidateCliError(f"build_input_unsafe:{relative}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(before):
            raise CandidateCliError(f"build_input_changed:{relative}")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity_tuple(after) != _identity_tuple(before):
        raise CandidateCliError(f"build_input_changed:{relative}")
    return {
        "path": relative,
        "mode": format(stat.S_IMODE(after.st_mode), "04o"),
        "size_bytes": after.st_size,
        "sha256": digest.hexdigest(),
        "identity_sha256": hashlib.sha256(
            _canonical_json_bytes(list(_identity_tuple(after)))
        ).hexdigest(),
    }


def _build_directory_identity(
    path: Path, *, identity: HostIdentity, label: str
) -> tuple[int, ...]:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError(f"{label}_unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or metadata.st_mode & 0o022
    ):
        raise CandidateCliError(f"{label}_unsafe")
    return _identity_tuple(metadata)


def _reviewed_build_directories(
    *, identity: HostIdentity
) -> dict[str, tuple[int, ...]]:
    directories: set[Path] = {REPO_ROOT}
    for relative in BUILD_INPUT_FILES:
        current = (REPO_ROOT / relative).parent
        while current != REPO_ROOT:
            directories.add(current)
            current = current.parent
    for root_relative in BUILD_COPY_ROOTS:
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
        path.relative_to(REPO_ROOT).as_posix() or ".": _build_directory_identity(
            path, identity=identity, label="build_input_directory"
        )
        for path in sorted(
            directories,
            key=lambda item: item.relative_to(REPO_ROOT).as_posix().encode("utf-8"),
        )
    }


def _validate_build_copy_inventory() -> None:
    observed: set[str] = set(BUILD_COPY_SINGLE_FILES)
    for root_relative in BUILD_COPY_ROOTS:
        root = REPO_ROOT / root_relative
        try:
            root_metadata = root.lstat()
        except OSError as exc:
            raise CandidateCliError(
                f"build_copy_root_unavailable:{root_relative}"
            ) from exc
        if (
            root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or root_metadata.st_mode & 0o022
        ):
            raise CandidateCliError(f"build_copy_root_unsafe:{root_relative}")
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
                if (
                    child.is_symlink()
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o022
                ):
                    raise CandidateCliError("build_copy_inventory_unsafe")
            for name in sorted(file_names, key=lambda item: item.encode("utf-8")):
                if name.endswith((".pyc", ".pyo")):
                    continue
                child = current / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    raise CandidateCliError("build_copy_inventory_unsafe")
                observed.add(child.relative_to(REPO_ROOT).as_posix())
    if observed != set(BUILD_COPY_FILES):
        raise CandidateCliError("build_copy_inventory_unexpected")


def _collect_build_inputs(*, identity: HostIdentity) -> dict[str, Any]:
    directories_before = _reviewed_build_directories(identity=identity)
    _validate_build_copy_inventory()
    records = [
        _stable_build_input_record(
            REPO_ROOT / relative, relative=relative, identity=identity
        )
        for relative in BUILD_INPUT_FILES
    ]
    if _reviewed_build_directories(identity=identity) != directories_before:
        raise CandidateCliError("build_input_directories_changed")
    content_records = [
        {key: item[key] for key in ("path", "mode", "size_bytes", "sha256")}
        for item in records
    ]
    return {
        "hash_algorithm": "kodesec-scanner-build-inputs-v1",
        "sha256": hashlib.sha256(_canonical_json_bytes(content_records)).hexdigest(),
        "identity_sha256": hashlib.sha256(
            _canonical_json_bytes(
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


def _normalize_build_security_config(
    value: Any,
    *,
    invocation_id: str,
    provenance: SourceProvenance,
    exact: bool = True,
) -> dict[str, Any]:
    required_fields = {
        "Entrypoint",
        "Cmd",
        "User",
        "WorkingDir",
        "Volumes",
        "Env",
        "Labels",
    }
    # Docker omits nullable Config fields from `inspect --format={{json .}}`
    # on some engines.  Canonical receipts must still carry the complete
    # normalized shape, while a raw daemon observation may omit only the two
    # fields whose reviewed value is null.
    required_observed_fields = required_fields - {"Entrypoint", "Volumes"}
    if (
        not isinstance(value, dict)
        or (exact and set(value) != required_fields)
        or not (required_fields if exact else required_observed_fields).issubset(value)
    ):
        raise CandidateCliError("build_image_security_config_invalid")
    entrypoint = value.get("Entrypoint")
    volumes = value.get("Volumes")
    if (
        entrypoint is not None
        or value["Cmd"] != BUILD_EXPECTED_CMD
        or value["User"] != "kodesec"
        or value["WorkingDir"] != "/app"
        or (volumes is not None if exact else volumes not in (None, {}))
        or value["Labels"]
        != {BUILD_OWNERSHIP_LABEL_KEY: invocation_id, **provenance.labels("scanner")}
        or not isinstance(value["Env"], list)
        or not 1 <= len(value["Env"]) <= 16
    ):
        raise CandidateCliError("build_image_security_config_invalid")
    environment: dict[str, str] = {}
    normalized: list[str] = []
    for item in value["Env"]:
        if (
            not isinstance(item, str)
            or not 0 < len(item) <= 1024
            or "=" not in item
            or any(char in item for char in "\r\n\x00")
        ):
            raise CandidateCliError("build_image_environment_invalid")
        key, item_value = item.split("=", 1)
        if (
            not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key)
            or key not in BUILD_ALLOWED_ENVIRONMENT_KEYS
            or key in environment
        ):
            raise CandidateCliError("build_image_environment_invalid")
        environment[key] = item_value
        normalized.append(item)
    if any(
        environment.get(key) != expected
        for key, expected in BUILD_REQUIRED_ENVIRONMENT.items()
    ):
        raise CandidateCliError("build_image_environment_invalid")
    return {
        "Entrypoint": None,
        "Cmd": list(BUILD_EXPECTED_CMD),
        "User": "kodesec",
        "WorkingDir": "/app",
        "Volumes": None,
        "Env": normalized,
        "Labels": {
            BUILD_OWNERSHIP_LABEL_KEY: invocation_id,
            **provenance.labels("scanner"),
        },
    }


def _expected_build_argv(
    *,
    tag: str,
    iidfile: Path,
    context_dir: Path,
    provenance: SourceProvenance,
) -> list[str]:
    match = BUILD_TAG.fullmatch(tag)
    if (
        match is None
        or not iidfile.is_absolute()
        or not context_dir.is_absolute()
        or context_dir.name != BUILD_STAGED_CONTEXT_NAME
    ):
        raise CandidateCliError("build_invocation_invalid")
    return [
        "buildx",
        "build",
        "--builder=default",
        "--load",
        "--pull",
        "--no-cache",
        f"--network={BUILD_NETWORK}",
        f"--platform={BUILD_PLATFORM}",
        f"--file={context_dir / BUILD_DOCKERFILE}",
        f"--tag={tag}",
        f"--iidfile={iidfile}",
        f"--label={BUILD_OWNERSHIP_LABEL_KEY}={match.group(1)}",
        *(
            f"--build-arg={key}={value}"
            for key, value in (*provenance.build_args(), *BUILD_ARGS)
        ),
        str(context_dir),
    ]


def _receipt_build_provenance(build: Mapping[str, Any]) -> SourceProvenance:
    value = build.get("source")
    if not isinstance(value, Mapping) or set(value) != {
        "commit",
        "tree",
        "build_identity",
    }:
        raise CandidateCliError("build_source_provenance_invalid")
    try:
        provenance = SourceProvenance(commit=value["commit"], tree=value["tree"])
    except (KeyError, TypeError, SourceProvenanceError) as exc:
        raise CandidateCliError("build_source_provenance_invalid") from exc
    if value["build_identity"] != provenance.labels("scanner")[BUILD_IDENTITY_LABEL]:
        raise CandidateCliError("build_source_provenance_invalid")
    return provenance


def _validate_staged_context_manifest(value: Any, *, source: Mapping[str, Any]) -> None:
    fields = {
        "hash_algorithm",
        "sha256",
        "identity_sha256",
        "file_count",
        "size_bytes",
        "files",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CandidateCliError("build_staged_context_invalid")
    source_files = source.get("files")
    staged_files = value.get("files")
    if (
        value.get("hash_algorithm") != "kodesec-scanner-staged-context-v1"
        or not isinstance(source_files, list)
        or not isinstance(staged_files, list)
        or len(staged_files) != len(source_files)
        or value.get("file_count") != len(source_files)
        or value.get("size_bytes") != sum(item["size_bytes"] for item in source_files)
    ):
        raise CandidateCliError("build_staged_context_invalid")
    normalized: list[dict[str, Any]] = []
    identities: list[dict[str, str]] = []
    for staged, original in zip(staged_files, source_files, strict=True):
        if (
            not isinstance(staged, dict)
            or set(staged)
            != {"path", "mode", "size_bytes", "sha256", "identity_sha256"}
            or staged.get("path") != original["path"]
            or staged.get("mode") != "0400"
            or staged.get("size_bytes") != original["size_bytes"]
            or staged.get("sha256") != original["sha256"]
            or not isinstance(staged.get("identity_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", staged["identity_sha256"]) is None
        ):
            raise CandidateCliError("build_staged_context_invalid")
        normalized.append(
            {key: staged[key] for key in ("path", "mode", "size_bytes", "sha256")}
        )
        identities.append(
            {
                "path": staged["path"],
                "identity_sha256": staged["identity_sha256"],
            }
        )
    if (
        value.get("sha256")
        != hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest()
        or value.get("identity_sha256")
        != hashlib.sha256(_canonical_json_bytes(identities)).hexdigest()
    ):
        raise CandidateCliError("build_staged_context_invalid")


def require_review_build_host():
    try:
        observed_target = scanner_review_build_target(platform.system(), platform.machine())
    except DockerRuntimeContractError as exc:
        raise CandidateCliError("build_host_identity_mismatch") from exc
    if REVIEW_TARGET is None or observed_target != REVIEW_TARGET:
        raise CandidateCliError("build_host_identity_mismatch")
    return observed_target


def validate_build_receipt(path: Path, *, identity: HostIdentity) -> dict[str, Any]:
    raw = _read_private_build_receipt(path, identity=identity)
    receipt = _strict_json_object(raw, label="build_receipt")
    fields = {
        "schema",
        "authoritative",
        "invocation_id",
        "producer",
        "host_execution_identity",
        "docker_runtime",
        "build",
        "inputs_before",
        "inputs_after",
        "staged_context",
        "image",
        "lifecycle",
        "receipt_sha256",
    }
    if set(receipt) != fields or raw != _canonical_json_bytes(receipt):
        raise CandidateCliError("build_receipt_fields_invalid")
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_sha256", None)
    invocation_id = receipt.get("invocation_id")
    if (
        receipt.get("schema") != BUILD_RECEIPT_SCHEMA
        or receipt.get("authoritative") is not False
        or not isinstance(invocation_id, str)
        or not INVOCATION_ID.fullmatch(invocation_id)
        or not isinstance(claimed, str)
        or not re.fullmatch(r"[0-9a-f]{64}", claimed)
        or claimed != hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    ):
        raise CandidateCliError("build_receipt_identity_invalid")
    host = receipt["host_execution_identity"]
    review_target = require_review_build_host()
    if (
        host
        != {
            "uid": identity.uid,
            "gid": identity.gid,
            "system": review_target.host_system,
            "machine": review_target.host_machine,
        }
    ):
        raise CandidateCliError("build_host_identity_mismatch")
    tag = f"lomo-kodesec-scanner:trivy-review-{invocation_id}"
    build = receipt["build"]
    provenance = _receipt_build_provenance(build)
    try:
        current_provenance = resolve_source_provenance(REPO_ROOT, BUILD_INPUT_FILES)
    except SourceProvenanceError as exc:
        raise CandidateCliError("build_source_provenance_invalid") from exc
    if provenance != current_provenance:
        raise CandidateCliError("build_source_provenance_mismatch")
    context_dir = path.parent / BUILD_STAGED_CONTEXT_NAME
    expected_argv = _expected_build_argv(
        tag=tag,
        iidfile=path.parent / ".scanner-build.iid",
        context_dir=context_dir,
        provenance=provenance,
    )
    expected_build = {
        "platform": BUILD_PLATFORM,
        "network": BUILD_NETWORK,
        "pull": True,
        "no_cache": True,
        "context": str(context_dir),
        "dockerfile": str(context_dir / BUILD_DOCKERFILE),
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
        "argv": expected_argv,
        "argv_sha256": hashlib.sha256(_canonical_json_bytes(expected_argv)).hexdigest(),
    }
    if build != expected_build:
        raise CandidateCliError("build_invocation_mismatch")
    local_inputs = _collect_build_inputs(identity=identity)
    if (
        receipt["inputs_before"] != receipt["inputs_after"]
        or receipt["inputs_before"] != local_inputs
    ):
        raise CandidateCliError("build_source_binding_mismatch")
    _validate_staged_context_manifest(
        receipt["staged_context"], source=receipt["inputs_before"]
    )
    producer = receipt["producer"]
    producer_record = next(
        item
        for item in local_inputs["files"]
        if item["path"] == BUILD_PRODUCER_RELATIVE_PATH
    )
    if producer != {
        "path": BUILD_PRODUCER_RELATIVE_PATH,
        "sha256": producer_record["sha256"],
    }:
        raise CandidateCliError("build_producer_binding_mismatch")
    runtime_value = receipt["docker_runtime"]
    if not isinstance(runtime_value, dict) or set(runtime_value) != {
        "observation_receipt",
        "observation",
        "execution",
    }:
        raise CandidateCliError("build_runtime_receipt_invalid")
    execution = runtime_value["execution"]
    observation = runtime_value["observation"]
    observation_receipt = runtime_value["observation_receipt"]
    if (
        not isinstance(execution, dict)
        or execution.get("schema") != "kodesec.docker-runtime-execution/v1"
        or not isinstance(observation, dict)
        or observation.get("schema") != "kodesec.docker-runtime-observation/v1"
        or not isinstance(observation_receipt, dict)
        or set(observation_receipt) != {"path", "sha256", "receipt_sha256"}
        or any(
            not isinstance(observation_receipt.get(key), str)
            or not re.fullmatch(r"[0-9a-f]{64}", observation_receipt[key])
            for key in ("sha256", "receipt_sha256")
        )
    ):
        raise CandidateCliError("build_runtime_receipt_invalid")
    if not isinstance(execution.get("environment"), dict):
        raise CandidateCliError("build_runtime_execution_mismatch")
    image = receipt["image"]
    if not isinstance(image, dict) or set(image) != {
        "id",
        "os",
        "architecture",
        "owned_tag",
        "security_config",
    }:
        raise CandidateCliError("build_image_receipt_invalid")
    if (
        not isinstance(image["id"], str)
        or not IMAGE_ID.fullmatch(image["id"])
        or image["os"] != "linux"
        or image["architecture"] != BUILD_ARCHITECTURE
        or image["owned_tag"] != tag
        or image["security_config"]
        != _normalize_build_security_config(
            image["security_config"],
            invocation_id=invocation_id,
            provenance=provenance,
        )
    ):
        raise CandidateCliError("build_image_receipt_invalid")
    if receipt["lifecycle"] != {
        "tag_absent_before": True,
        "tag_held_for_consumer": True,
        "iidfile_absent_before": True,
        "iidfile_removed": True,
        "staged_context_removed": True,
        "runtime_snapshots_held_for_consumer": True,
    }:
        raise CandidateCliError("build_lifecycle_receipt_invalid")
    return receipt


def _activate_build_runtime(
    receipt: Mapping[str, Any], receipt_path: Path, *, identity: HostIdentity
) -> RuntimePaths:
    execution = receipt["docker_runtime"]["execution"]
    try:
        environment = execution["environment"]
        runtime = RuntimePaths(
            root=receipt_path.parent / ".docker-runtime",
            docker=Path(execution["docker"]["snapshot"]["path"]),
            buildx=Path(execution["buildx"]["snapshot"]["path"]),
            home=Path(environment["HOME"]),
            docker_config=Path(environment["DOCKER_CONFIG"]),
            buildx_config=Path(environment["BUILDX_CONFIG"]),
            temporary=Path(environment["TMPDIR"]),
            docker_host=execution["daemon"]["host"],
            source_docker=execution["docker"]["source"],
            source_buildx=execution["buildx"]["source"],
            snapshot_docker=execution["docker"]["snapshot"],
            snapshot_buildx=execution["buildx"]["snapshot"],
            socket=execution["daemon"]["socket"],
        )
        if runtime.record() != execution:
            raise CandidateCliError("build_runtime_execution_mismatch")
        revalidate_runtime(runtime, invoking_uid=identity.uid)
    except (KeyError, TypeError, DockerRuntimeContractError) as exc:
        raise CandidateCliError("build_runtime_execution_mismatch") from exc
    global _ACTIVE_RUNTIME
    _ACTIVE_RUNTIME = runtime
    version = run_docker_control(("docker", "version", "--format={{json .}}"))
    info = run_docker_control(("docker", "info", "--format={{json .}}"))
    buildx = run_docker(
        ("buildx", "ls", "--format=json", "--no-trunc"),
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )
    if version.stderr or info.stderr or buildx.stderr:
        raise CandidateCliError("build_runtime_observation_stderr_nonempty")
    try:
        current = combined_observation(
            normalize_daemon_observation(version.stdout, info.stdout),
            normalize_buildx_observation(buildx.stdout),
        )
    except DockerRuntimeContractError as exc:
        raise CandidateCliError("build_runtime_observation_invalid") from exc
    if current != receipt["docker_runtime"]["observation"]:
        raise CandidateCliError("build_runtime_observation_drift")
    return runtime


def build_image_inspect_argv(reference: str) -> tuple[str, ...]:
    if BUILD_TAG.fullmatch(reference) is None and IMAGE_ID.fullmatch(reference) is None:
        raise CandidateCliError("build_image_reference_invalid")
    return ("docker", "image", "inspect", "--format={{json .}}", reference)


def parse_built_image_inspect(
    raw: bytes, *, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_DOCKER_OUTPUT_BYTES:
        raise CandidateCliError("build_image_inspect_invalid")
    value = _strict_json_object(raw, label="build_image_inspect")
    image = receipt["image"]
    invocation_id = receipt["invocation_id"]
    tag = receipt["build"]["tag"]
    provenance = _receipt_build_provenance(receipt["build"])
    if (
        not {"Id", "Os", "Architecture", "RepoTags", "RepoDigests", "Config"}.issubset(
            value
        )
        or value["Id"] != image["id"]
        or value["Os"] != "linux"
        or value["Architecture"] != BUILD_ARCHITECTURE
        or value["RepoTags"] != [tag]
        or not owned_local_repo_digests(tag, image["id"], value["RepoDigests"])
    ):
        raise CandidateCliError("build_image_identity_mismatch")
    observed = {
        "id": image["id"],
        "os": "linux",
        "architecture": BUILD_ARCHITECTURE,
        "owned_tag": tag,
        "security_config": _normalize_build_security_config(
            value["Config"],
            invocation_id=invocation_id,
            provenance=provenance,
            exact=False,
        ),
    }
    if observed != image:
        raise CandidateCliError("build_image_config_mismatch")
    return observed


def _mount(source: Path, target: str, *, readonly: bool) -> str:
    try:
        metadata = source.lstat()
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError("mount_source_unavailable") from exc
    if (
        source.is_symlink()
        or resolved != source
        or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))
    ):
        raise CandidateCliError("mount_source_unsafe")
    rendered = str(resolved)
    if (
        "," in rendered
        or any(char in rendered for char in "\r\n\x00")
        or not target.startswith(f"{REVIEW_ROOT}/")
        or "," in target
        or any(char in target for char in "\r\n\x00")
    ):
        raise CandidateCliError("mount_source_unsafe")
    suffix = ",readonly" if readonly else ""
    return f"type=bind,source={rendered},target={target}{suffix}"


def _require_private_directory(
    path: Path, *, empty: bool, identity: HostIdentity
) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError("private_directory_unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != path
    ):
        raise CandidateCliError("private_directory_invalid")
    if empty:
        try:
            if next(path.iterdir(), None) is not None:
                raise CandidateCliError("private_directory_not_empty")
        except OSError as exc:
            raise CandidateCliError("private_directory_unreadable") from exc
    return path


def _require_immutable_support_directory(
    path: Path, *, identity: HostIdentity
) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError("support_trivy_db_unavailable") from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or resolved != path
    ):
        raise CandidateCliError("support_trivy_db_invalid")
    return path


def inspect_argv(*, docker: str, image_id: str) -> tuple[str, ...]:
    require_image_id(image_id)
    return (docker, "image", "inspect", "--format={{json .}}", image_id)


def _docker_run_prefix(
    *,
    docker: str,
    image_id: str,
    network: str,
    mounts: Sequence[str],
    identity: HostIdentity,
    run_identity: DockerRunIdentity | None = None,
    candidate_cache_tmpfs: bool = False,
) -> tuple[str, ...]:
    require_image_id(image_id)
    validated_identity = HostIdentity(uid=identity.uid, gid=identity.gid)
    if network not in {"none", "bridge"}:
        raise CandidateCliError("docker_network_invalid")
    command = [
        docker,
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        f"--user={validated_identity.uid}:{validated_identity.gid}",
        "--entrypoint=/usr/local/bin/python",
        "--pull=never",
        f"--network={network}",
        (
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,"
            f"uid={validated_identity.uid},gid={validated_identity.gid}"
        ),
        (
            "--tmpfs=/run/kodesec-scratch:rw,noexec,nosuid,nodev,size=64m,"
            f"mode=0700,uid={validated_identity.uid},gid={validated_identity.gid}"
        ),
    ]
    if candidate_cache_tmpfs:
        if network != "none":
            raise CandidateCliError("candidate_cache_network_invalid")
        command.append(
            "--tmpfs=/run/kodesec-review/candidate-cache:"
            "rw,noexec,nosuid,nodev,size=64m,mode=0700,"
            f"uid={validated_identity.uid},gid={validated_identity.gid}"
        )
    if run_identity is not None:
        command[3:3] = (
            "--name",
            run_identity.name,
            "--cidfile",
            str(run_identity.cidfile),
        )
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        command.append(f"--env={name}=")
    for mount in mounts:
        command.extend(("--mount", mount))
    command.extend(
        (
            image_id,
            "-I",
            "-B",
            "-X",
            "pycache_prefix=/run/kodesec-scratch/pycache",
            "-m",
            "kodesec_scanner.trivy_db_lock_candidate",
        )
    )
    return tuple(command)


def preflight_argv(
    inputs: ReviewInputs,
    *,
    docker: str = "docker",
    run_identity: DockerRunIdentity | None = None,
) -> tuple[str, ...]:
    if inputs.architecture not in {"amd64", "arm64"}:
        raise CandidateCliError("image_architecture_unsupported")
    positive = (
        f"{REVIEW_ROOT}/positive"
        if inputs.component_id == "trivy-db"
        else JAVA_POSITIVE_FIXTURE_IN_IMAGE
    )
    mounts = [
        _mount(CURRENT_LOCK_PATH, f"{REVIEW_ROOT}/current-lock.json", readonly=True),
        _mount(ZERO_FIXTURE_PATH, f"{REVIEW_ROOT}/zero", readonly=True),
    ]
    if inputs.component_id == "trivy-db":
        mounts.insert(
            1,
            _mount(POSITIVE_FIXTURE_PATH, positive, readonly=True),
        )
    command = _docker_run_prefix(
        docker=docker,
        image_id=inputs.image_id,
        network="none",
        mounts=tuple(mounts),
        identity=inputs.identity,
        run_identity=run_identity,
    ) + (
        "preflight",
    )
    if inputs.component_id != "trivy-db":
        command += ("--component-id", inputs.component_id)
    return command + (
        "--current-lock",
        f"{REVIEW_ROOT}/current-lock.json",
        "--baked-lock",
        LOCK_IN_IMAGE,
        "--trivy-path",
        TRIVY_PATH,
        "--trivy-version",
        TRIVY_VERSION,
        "--expected-architecture",
        inputs.architecture,
        "--tool-manifest",
        TOOL_MANIFEST_IN_IMAGE,
        "--positive-fixture",
        positive,
        "--zero-fixture",
        f"{REVIEW_ROOT}/zero",
        "--invocation-id",
        inputs.invocation_id,
    )


def fetch_argv(
    inputs: ReviewInputs,
    *,
    docker: str = "docker",
    run_identity: DockerRunIdentity | None = None,
) -> tuple[str, ...]:
    _require_private_directory(inputs.output_dir, empty=True, identity=inputs.identity)
    mounts = (_mount(inputs.output_dir, f"{REVIEW_ROOT}/output", readonly=False),)
    contract = _component_contract(inputs.component_id)
    command = _docker_run_prefix(
        docker=docker,
        image_id=inputs.image_id,
        network="bridge",
        mounts=mounts,
        identity=inputs.identity,
        run_identity=run_identity,
    ) + (
        "fetch",
    )
    if inputs.component_id != "trivy-db":
        command += ("--component-id", inputs.component_id)
    return command + (
        "--registry",
        "ghcr.io",
        "--repository",
        contract["repository"],
        "--reference",
        contract["reference"],
        "--output-dir",
        f"{REVIEW_ROOT}/output",
        "--invocation-id",
        inputs.invocation_id,
    )


def canary_argv(
    inputs: ReviewInputs,
    *,
    docker: str = "docker",
    run_identity: DockerRunIdentity | None = None,
) -> tuple[str, ...]:
    _require_private_directory(inputs.output_dir, empty=False, identity=inputs.identity)
    candidate_db = inputs.output_dir / "candidate-db"
    try:
        candidate_metadata = candidate_db.lstat()
    except OSError as exc:
        raise CandidateCliError("candidate_db_unavailable") from exc
    if (
        candidate_db.is_symlink()
        or not stat.S_ISDIR(candidate_metadata.st_mode)
        or candidate_metadata.st_uid != inputs.identity.uid
        or stat.S_IMODE(candidate_metadata.st_mode) != 0o500
        or candidate_db.resolve(strict=True) != candidate_db
    ):
        raise CandidateCliError("candidate_db_invalid")
    contract = _component_contract(inputs.component_id)
    candidate_target = f"{REVIEW_ROOT}/candidate-cache/{contract['cache_child']}"
    positive = (
        f"{REVIEW_ROOT}/positive"
        if inputs.component_id == "trivy-db"
        else JAVA_POSITIVE_FIXTURE_IN_IMAGE
    )
    mounts = [
        _mount(CURRENT_LOCK_PATH, f"{REVIEW_ROOT}/current-lock.json", readonly=True),
        _mount(candidate_db, candidate_target, readonly=True),
        _mount(ZERO_FIXTURE_PATH, f"{REVIEW_ROOT}/zero", readonly=True),
    ]
    if inputs.component_id == "trivy-db":
        mounts.insert(
            2,
            _mount(POSITIVE_FIXTURE_PATH, positive, readonly=True),
        )
    elif inputs.support_trivy_db is not None:
        support = _require_immutable_support_directory(
            inputs.support_trivy_db, identity=inputs.identity
        )
        mounts.insert(
            1,
            _mount(
                support,
                f"{REVIEW_ROOT}/candidate-cache/db",
                readonly=True,
            ),
        )
    command = _docker_run_prefix(
        docker=docker,
        image_id=inputs.image_id,
        network="none",
        mounts=tuple(mounts),
        identity=inputs.identity,
        run_identity=run_identity,
        candidate_cache_tmpfs=True,
    ) + (
        "canary",
    )
    if inputs.component_id != "trivy-db":
        command += ("--component-id", inputs.component_id)
    arguments = command + (
        "--current-lock",
        f"{REVIEW_ROOT}/current-lock.json",
        "--candidate-db",
        candidate_target,
        "--positive-fixture",
        positive,
        "--zero-fixture",
        f"{REVIEW_ROOT}/zero",
        "--invocation-id",
        inputs.invocation_id,
    )
    if inputs.support_trivy_db is not None:
        arguments += (
            "--support-trivy-db",
            f"{REVIEW_ROOT}/candidate-cache/db",
        )
    return arguments


def parse_image_inspect(raw: bytes, *, expected_id: str) -> str:
    if not IMAGE_ID.fullmatch(expected_id):
        raise CandidateCliError("expected_image_id_invalid")
    if not raw or len(raw) > MAX_DOCKER_OUTPUT_BYTES:
        raise CandidateCliError("image_inspect_output_invalid")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise CandidateCliError("image_inspect_duplicate_key")
            result[key] = item
        return result

    def reject_nonfinite(_: str) -> None:
        raise CandidateCliError("image_inspect_nonfinite_number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise CandidateCliError("image_inspect_nonfinite_number")
        return parsed

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except CandidateCliError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CandidateCliError("image_inspect_output_invalid") from exc
    required = {"Id", "Os", "Architecture", "Config"}
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not isinstance(value["Id"], str)
        or not isinstance(value["Os"], str)
        or not isinstance(value["Architecture"], str)
        or not isinstance(value["Config"], dict)
        or value["Config"].get("Volumes") not in (None, {})
    ):
        raise CandidateCliError("image_inspect_shape_invalid")
    if value["Id"] != expected_id or value["Os"] != "linux":
        raise CandidateCliError("image_identity_mismatch")
    architecture = value["Architecture"]
    if architecture not in {"amd64", "arm64"}:
        raise CandidateCliError("image_architecture_unsupported")
    return architecture


def _run_bounded_process(
    argv: Sequence[str], *, timeout_seconds: int
) -> CompletedDocker:
    """Drain both child pipes concurrently without materializing excess output."""

    runtime = _ACTIVE_RUNTIME
    try:
        if runtime is not None:
            revalidate_runtime(runtime, invoking_uid=os.getuid())
        process = subprocess.Popen(
            list(argv),
            cwd=runtime.root if runtime is not None else REPO_ROOT,
            env=runtime.environment() if runtime is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise CandidateCliError("docker_execution_failed") from exc
    except BaseException as exc:
        raise DockerProcessCleanupUncertain("docker_process_start_uncertain") from exc
    selector: selectors.BaseSelector | None = None
    primary: BaseException | None = None
    result: CompletedDocker | None = None
    natural_exit_observed = False
    try:
        if process.stdout is None or process.stderr is None:
            raise CandidateCliError("docker_capture_unavailable")
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
                raise CandidateCliError("docker_execution_timed_out")
            events = selector.select(remaining)
            if not events:
                raise CandidateCliError("docker_execution_timed_out")
            for key, _ in events:
                label = streams[key.fd]
                allowance = MAX_DOCKER_OUTPUT_BYTES - len(captured[label])
                try:
                    chunk = os.read(key.fd, min(READ_CHUNK_BYTES, allowance + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                if len(chunk) > allowance:
                    raise CandidateCliError("docker_output_oversized")
                captured[label].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CandidateCliError("docker_execution_timed_out")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CandidateCliError("docker_execution_timed_out") from exc
        natural_exit_observed = True
        if returncode != 0:
            marker_status = _inner_failure_status(
                argv,
                returncode=returncode,
                stdout=bytes(captured["stdout"]),
                stderr=bytes(captured["stderr"]),
            )
            raise CandidateCliError(marker_status or "docker_status_failed")
        result = CompletedDocker(
            stdout=bytes(captured["stdout"]), stderr=bytes(captured["stderr"])
        )
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
            cleanup_errors.append(CandidateCliError("docker_process_survived_cleanup"))
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
    if runtime is not None:
        try:
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
    argv: Sequence[str], *, timeout_seconds: int = MAX_DOCKER_TIMEOUT_SECONDS
) -> CompletedDocker:
    """Run fixed Docker argv with bounded time and captured output."""

    if not 1 <= timeout_seconds <= MAX_DOCKER_TIMEOUT_SECONDS:
        raise ValueError("docker timeout is outside its hard bound")
    runtime = _ACTIVE_RUNTIME
    if runtime is None or not argv or argv[0] not in {"docker", "buildx"}:
        raise CandidateCliError("docker_argv_invalid")
    return _run_bounded_process(
        executable_argv(runtime, argv), timeout_seconds=timeout_seconds
    )


def run_docker_control(
    argv: Sequence[str], *, timeout_seconds: int = DOCKER_CONTROL_TIMEOUT_SECONDS
) -> CompletedDocker:
    """Run one bounded Docker lifecycle command without relaxing status checks."""

    if not 1 <= timeout_seconds <= DOCKER_CONTROL_TIMEOUT_SECONDS:
        raise ValueError("docker control timeout is outside its hard bound")
    runtime = _ACTIVE_RUNTIME
    if runtime is None or not argv or argv[0] != "docker":
        raise CandidateCliError("docker_control_argv_invalid")
    return _run_bounded_process(
        executable_argv(runtime, argv), timeout_seconds=timeout_seconds
    )


def _container_list_argv(name: str) -> tuple[str, ...]:
    if not re.fullmatch(
        r"(?:kodesec-trivy-(?:db|java-db)-[0-9a-f]{32}-(?:preflight|fetch|canary)|kodesec-grype-db-[0-9a-f]{32}-(?:preflight|fetch|import|canary))",
        name,
    ):
        raise CandidateCliError("docker_run_identity_invalid")
    return (
        "docker",
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        f"name=^/{name}$",
        "--format={{.ID}}",
    )


def _classify_container_listing(completed: CompletedDocker) -> str:
    if completed.stderr:
        return "unproven"
    if completed.stdout == b"":
        return "absent"
    if completed.stdout.endswith(b"\n") and CONTAINER_ID.fullmatch(
        completed.stdout[:-1]
    ):
        return "present"
    return "unproven"


def _build_tag_list_argv(tag: str) -> tuple[str, ...]:
    if BUILD_TAG.fullmatch(tag) is None:
        raise CandidateCliError("build_tag_invalid")
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        f"--filter=reference={tag}",
        "--format={{.Repository}}:{{.Tag}}|{{.ID}}",
    )


def _classify_build_tag(
    completed: CompletedDocker, *, tag: str, expected_id: str
) -> str:
    if completed.stderr:
        return "unproven"
    if completed.stdout == b"":
        return "absent"
    try:
        rendered = completed.stdout.decode("ascii", errors="strict")
    except UnicodeError:
        return "unproven"
    lines = rendered.splitlines()
    expected = f"{tag}|{expected_id}"
    if lines == [expected]:
        return "owned"
    if len(lines) == 1 and lines[0].startswith(f"{tag}|"):
        return "foreign"
    return "unproven"


def _build_label_list_argv(invocation_id: str) -> tuple[str, ...]:
    if INVOCATION_ID.fullmatch(invocation_id) is None:
        raise CandidateCliError("build_invocation_id_invalid")
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        f"--filter=label={BUILD_OWNERSHIP_LABEL_KEY}={invocation_id}",
        "--format={{.ID}}",
    )


def _all_build_image_ids_argv() -> tuple[str, ...]:
    return (
        "docker",
        "image",
        "ls",
        "--all",
        "--no-trunc",
        "--format={{.ID}}",
    )


def _classify_all_build_image_ids(
    completed: CompletedDocker, *, expected_id: str
) -> str:
    if completed.stderr:
        return "unproven"
    if completed.stdout == b"":
        return "absent"
    try:
        lines = completed.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        return "unproven"
    if any(IMAGE_ID.fullmatch(line) is None for line in lines):
        return "unproven"
    return "present" if expected_id in lines else "absent"


def _classify_build_label(completed: CompletedDocker, *, expected_id: str) -> str:
    if completed.stderr:
        return "unproven"
    if completed.stdout == b"":
        return "absent"
    try:
        lines = completed.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        return "unproven"
    if lines == [expected_id]:
        return "owned"
    if len(lines) == 1 and IMAGE_ID.fullmatch(lines[0]):
        return "foreign"
    return "unproven"


def _observe_build_handoff(
    *, tag: str, invocation_id: str, expected_id: str
) -> tuple[str, str]:
    try:
        tag_completed = run_docker_control(_build_tag_list_argv(tag))
        label_completed = run_docker_control(_build_label_list_argv(invocation_id))
    except BaseException as exc:
        raise CandidateCliError("build_tag_ownership_unproven") from exc
    return (
        _classify_build_tag(tag_completed, tag=tag, expected_id=expected_id),
        _classify_build_label(label_completed, expected_id=expected_id),
    )


def _require_owned_build_image(*, receipt: Mapping[str, Any]) -> None:
    tag = receipt["build"]["tag"]
    invocation_id = receipt["invocation_id"]
    expected_id = receipt["image"]["id"]
    tag_state, label_state = _observe_build_handoff(
        tag=tag, invocation_id=invocation_id, expected_id=expected_id
    )
    if tag_state == "foreign" or label_state == "foreign":
        raise CandidateCliError("build_tag_replaced_by_foreign_image")
    if (tag_state, label_state) != ("owned", "owned"):
        raise CandidateCliError("build_tag_ownership_unproven")
    for reference in (tag, expected_id):
        inspected = run_docker(build_image_inspect_argv(reference), timeout_seconds=60)
        if inspected.stderr:
            raise CandidateCliError("image_inspect_stderr_nonempty")
        parse_built_image_inspect(inspected.stdout, receipt=receipt)


def _prove_build_handoff_absent(
    *, tag: str, invocation_id: str, expected_id: str
) -> None:
    for _ in range(3):
        tag_state, label_state = _observe_build_handoff(
            tag=tag, invocation_id=invocation_id, expected_id=expected_id
        )
        try:
            id_state = _classify_all_build_image_ids(
                run_docker_control(_all_build_image_ids_argv()),
                expected_id=expected_id,
            )
        except BaseException as exc:
            raise CandidateCliError("build_tag_cleanup_uncertain") from exc
        if (tag_state, label_state, id_state) != (
            "absent",
            "absent",
            "absent",
        ):
            raise CandidateCliError("build_tag_cleanup_uncertain")


def _parse_cleanup_build_image(
    completed: CompletedDocker,
    *,
    receipt: Mapping[str, Any],
    allow_untagged: bool,
) -> None:
    if completed.stderr or not 0 < len(completed.stdout) <= MAX_DOCKER_OUTPUT_BYTES:
        raise CandidateCliError("build_tag_cleanup_uncertain")
    value = _strict_json_object(completed.stdout, label="build_cleanup_inspect")
    image = receipt["image"]
    provenance = _receipt_build_provenance(receipt["build"])
    expected_tags: Any = value.get("RepoTags")
    if (
        not {"Id", "Os", "Architecture", "RepoTags", "RepoDigests", "Config"}.issubset(
            value
        )
        or value["Id"] != image["id"]
        or value["Os"] != "linux"
        or value["Architecture"] != BUILD_ARCHITECTURE
        or not owned_local_repo_digests(
            receipt["build"]["tag"], image["id"], value["RepoDigests"]
        )
        or (
            expected_tags not in (None, [])
            if allow_untagged
            else expected_tags != [receipt["build"]["tag"]]
        )
        or _normalize_build_security_config(
            value["Config"],
            invocation_id=receipt["invocation_id"],
            provenance=provenance,
            exact=False,
        )
        != image["security_config"]
    ):
        raise CandidateCliError("build_tag_cleanup_identity_mismatch")


def _cleanup_owned_build_image(*, receipt: Mapping[str, Any]) -> None:
    tag = receipt["build"]["tag"]
    invocation_id = receipt["invocation_id"]
    expected_id = receipt["image"]["id"]
    tag_state, label_state = _observe_build_handoff(
        tag=tag, invocation_id=invocation_id, expected_id=expected_id
    )
    if tag_state == "foreign" or label_state == "foreign":
        raise CandidateCliError("build_tag_foreign_ref_preserved")
    if (tag_state, label_state) == ("absent", "absent"):
        _prove_build_handoff_absent(
            tag=tag, invocation_id=invocation_id, expected_id=expected_id
        )
        return
    if (tag_state, label_state) not in {
        ("owned", "owned"),
        ("absent", "owned"),
    }:
        raise CandidateCliError("build_tag_cleanup_uncertain")
    allow_untagged = tag_state == "absent"
    try:
        inspected = run_docker(
            build_image_inspect_argv(expected_id), timeout_seconds=60
        )
        _parse_cleanup_build_image(
            inspected, receipt=receipt, allow_untagged=allow_untagged
        )
        # Delete by the inspected immutable identity, never by mutable tag.
        run_docker_control(("docker", "image", "rm", expected_id))
        _prove_build_handoff_absent(
            tag=tag, invocation_id=invocation_id, expected_id=expected_id
        )
    except BaseException as exc:
        if isinstance(exc, CandidateCliError):
            raise
        raise CandidateCliError("build_tag_cleanup_uncertain") from exc


def _prove_container_absent(run_identity: DockerRunIdentity) -> None:
    try:
        proof = run_docker_control(_container_list_argv(run_identity.name))
    except BaseException as exc:
        raise CandidateCliError("docker_container_absence_unproven") from exc
    if _classify_container_listing(proof) != "absent":
        raise CandidateCliError("docker_container_absence_unproven")


def _validate_owned_run_argv(
    argv: Sequence[str], *, run_identity: DockerRunIdentity
) -> tuple[str, ...]:
    command = tuple(argv)
    if (
        command[:2] != ("docker", "run")
        or command.count("--name") != 1
        or command.count("--cidfile") != 1
        or any(item.startswith("--name=") for item in command)
        or any(item.startswith("--cidfile=") for item in command)
    ):
        raise CandidateCliError("docker_owned_argv_invalid")
    try:
        name_index = command.index("--name")
        cidfile_index = command.index("--cidfile")
        observed_name = command[name_index + 1]
        observed_cidfile = command[cidfile_index + 1]
    except IndexError as exc:
        raise CandidateCliError("docker_owned_argv_invalid") from exc
    if observed_name != run_identity.name or observed_cidfile != str(
        run_identity.cidfile
    ):
        raise CandidateCliError("docker_owned_argv_invalid")
    return command


def _validate_new_cidfile(path: Path, *, identity: HostIdentity) -> None:
    if path.exists() or path.is_symlink():
        raise CandidateCliError("docker_cidfile_exists")
    parent = path.parent
    _require_private_directory(parent, empty=False, identity=identity)


def _consume_cidfile(path: Path, *, identity: HostIdentity, required: bool) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise CandidateCliError("docker_cidfile_missing")
        return
    except OSError as exc:
        raise CandidateCliError("docker_cidfile_identity_invalid") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or metadata.st_nlink != 1
        or metadata.st_size != 64
    ):
        raise CandidateCliError("docker_cidfile_identity_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, 65)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_nlink,
        )
        or not CONTAINER_ID.fullmatch(payload)
    ):
        raise CandidateCliError("docker_cidfile_identity_invalid")
    try:
        path.unlink()
    except OSError as exc:
        raise CandidateCliError("docker_cidfile_cleanup_uncertain") from exc


def _cleanup_container(
    run_identity: DockerRunIdentity,
    *,
    identity: HostIdentity,
    require_cidfile: bool,
    preserve_cidfile: bool = False,
) -> BaseException | None:
    removal_interruption: BaseException | None = None
    try:
        run_docker_control(
            ("docker", "rm", "--force", run_identity.name),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
    except BaseException as exc:
        removal_interruption = exc
    _prove_container_absent(run_identity)
    if not preserve_cidfile:
        _consume_cidfile(
            run_identity.cidfile,
            identity=identity,
            required=require_cidfile,
        )
    if isinstance(removal_interruption, (KeyboardInterrupt, SystemExit)):
        return removal_interruption
    return None


def run_owned_container(
    argv: Sequence[str],
    *,
    run_identity: DockerRunIdentity,
    identity: HostIdentity,
    timeout_seconds: int,
) -> CompletedDocker:
    """Run one named container and prove it cannot survive any outcome."""

    command = _validate_owned_run_argv(argv, run_identity=run_identity)
    _validate_new_cidfile(run_identity.cidfile, identity=identity)
    try:
        proof = run_docker_control(_container_list_argv(run_identity.name))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        raise CandidateCliError("docker_container_preabsence_unproven") from exc
    classification = _classify_container_listing(proof)
    if classification == "present":
        raise CandidateCliError("docker_container_preexisting")
    if classification != "absent":
        raise CandidateCliError("docker_container_preabsence_unproven")
    primary: BaseException | None = None
    result: CompletedDocker | None = None
    try:
        result = run_docker(command, timeout_seconds=timeout_seconds)
    except BaseException as exc:
        primary = exc
    try:
        process_uncertain = isinstance(primary, DockerProcessCleanupUncertain)
        cleanup_interruption = _cleanup_container(
            run_identity,
            identity=identity,
            require_cidfile=result is not None,
            preserve_cidfile=process_uncertain,
        )
    except CandidateCliError as cleanup_exc:
        if isinstance(primary, DockerProcessCleanupUncertain):
            raise DockerProcessCleanupUncertain(
                f"docker_process_forensic_state_preserved:{run_identity.cidfile.parent}"
            ) from cleanup_exc
        if str(cleanup_exc).startswith("docker_cidfile_"):
            raise
        raise CandidateCliError("docker_container_cleanup_uncertain") from cleanup_exc
    except BaseException as cleanup_exc:
        if isinstance(primary, DockerProcessCleanupUncertain):
            raise DockerProcessCleanupUncertain(
                f"docker_process_forensic_state_preserved:{run_identity.cidfile.parent}"
            ) from cleanup_exc
        raise CandidateCliError("docker_container_cleanup_uncertain") from cleanup_exc
    if isinstance(primary, DockerProcessCleanupUncertain):
        # Killing/reaping the client is not proof that the daemon-side create
        # request cannot publish the named container later.  Preserve the
        # private lifecycle directory/cidfile as non-success diagnostics.
        raise DockerProcessCleanupUncertain(
            f"docker_process_forensic_state_preserved:{run_identity.cidfile.parent}"
        ) from primary
    if cleanup_interruption is not None:
        raise cleanup_interruption
    if primary is not None:
        raise primary
    assert result is not None
    return result


def _candidate_core():
    rendered = str(SCANNER_PACKAGE_ROOT)
    if rendered not in sys.path:
        sys.path.insert(0, rendered)
    try:
        from kodesec_scanner import trivy_db_lock_candidate
    except ImportError as exc:
        raise CandidateCliError("candidate_core_unavailable") from exc
    return trivy_db_lock_candidate


def _receipt_stdout(completed: CompletedDocker, *, label: str) -> bytes:
    if completed.stderr or not completed.stdout.endswith(b"\n"):
        raise CandidateCliError(f"{label}_receipt_stream_invalid")
    if (
        len(completed.stdout) <= 1
        or b"\n" in completed.stdout[:-1]
        or len(completed.stdout) > MAX_DOCKER_OUTPUT_BYTES
    ):
        raise CandidateCliError(f"{label}_receipt_stream_invalid")
    # Preserve the one canonical LF: downstream validators and the fetch
    # stream-vs-disk comparison use the same canonical_json_bytes contract.
    return completed.stdout


def _read_private_receipt(path: Path, *, identity: HostIdentity) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CandidateCliError("fetch_receipt_unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != identity.uid
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 0 < before.st_size <= MAX_DOCKER_OUTPUT_BYTES
    ):
        raise CandidateCliError("fetch_receipt_identity_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    payload = bytearray()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CandidateCliError("fetch_receipt_identity_invalid")
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, MAX_DOCKER_OUTPUT_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > MAX_DOCKER_OUTPUT_BYTES:
                raise CandidateCliError("fetch_receipt_identity_invalid")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    ):
        raise CandidateCliError("fetch_receipt_identity_invalid")
    return bytes(payload)


def _stable_source_sha256(path: Path, *, label: str) -> str:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateCliError(f"{label}_unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_size <= 0
        or before.st_size > 4 * 1024 * 1024
    ):
        raise CandidateCliError(f"{label}_identity_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CandidateCliError(f"{label}_identity_invalid")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    ):
        raise CandidateCliError(f"{label}_identity_invalid")
    return digest.hexdigest()


def _verify_fetch_output_shape(output_dir: Path, *, identity: HostIdentity) -> None:
    _require_private_directory(output_dir, empty=False, identity=identity)
    try:
        children = {item.name: item for item in output_dir.iterdir()}
    except OSError as exc:
        raise CandidateCliError("fetch_output_unreadable") from exc
    if set(children) != {"candidate-db", "fetch-receipt.json", "layer.tar.gz"}:
        raise CandidateCliError("fetch_output_shape_invalid")
    candidate_db = children["candidate-db"]
    layer = children["layer.tar.gz"]
    try:
        candidate_metadata = candidate_db.lstat()
        layer_metadata = layer.lstat()
    except OSError as exc:
        raise CandidateCliError("fetch_output_shape_invalid") from exc
    if (
        candidate_db.is_symlink()
        or not stat.S_ISDIR(candidate_metadata.st_mode)
        or candidate_metadata.st_uid != identity.uid
        or stat.S_IMODE(candidate_metadata.st_mode) != 0o500
        or layer.is_symlink()
        or not stat.S_ISREG(layer_metadata.st_mode)
        or layer_metadata.st_nlink != 1
        or layer_metadata.st_uid != identity.uid
        or stat.S_IMODE(layer_metadata.st_mode) != 0o400
    ):
        raise CandidateCliError("fetch_output_shape_invalid")


def _remove_owned_output_tree(path: Path, *, identity: HostIdentity) -> None:
    """Remove only the exact private invocation directory without following links."""

    try:
        root = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise CandidateCliError("output_cleanup_uncertain") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != identity.uid
        or path.resolve(strict=True) != path
    ):
        raise CandidateCliError("output_cleanup_uncertain")
    try:
        for current_name, directories, files in os.walk(
            path, topdown=False, followlinks=False
        ):
            current = Path(current_name)
            current_metadata = current.lstat()
            if (
                current.is_symlink()
                or not stat.S_ISDIR(current_metadata.st_mode)
                or current_metadata.st_uid != identity.uid
            ):
                raise CandidateCliError("output_cleanup_uncertain")
            current.chmod(stat.S_IMODE(current_metadata.st_mode) | 0o700)
            for name in files:
                child = current / name
                metadata = child.lstat()
                if (
                    child.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                    or metadata.st_nlink != 1
                ):
                    raise CandidateCliError("output_cleanup_uncertain")
                child.unlink()
            for name in directories:
                child = current / name
                metadata = child.lstat()
                if (
                    child.is_symlink()
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != identity.uid
                ):
                    raise CandidateCliError("output_cleanup_uncertain")
                child.chmod(stat.S_IMODE(metadata.st_mode) | 0o700)
                child.rmdir()
        path.rmdir()
    except CandidateCliError:
        raise
    except OSError as exc:
        raise CandidateCliError("output_cleanup_uncertain") from exc
    if path.exists() or path.is_symlink():
        raise CandidateCliError("output_cleanup_uncertain")


def _invalidate_candidate_receipt(path: Path, *, identity: HostIdentity) -> None:
    """Make a partially published final receipt non-consumable before cleanup."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise CandidateCliError("candidate_receipt_invalidation_uncertain") from exc
    if (
        path.name != "candidate-receipt.json"
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != identity.uid
        or metadata.st_nlink != 1
    ):
        raise CandidateCliError("candidate_receipt_invalidation_uncertain")
    invalidated = False
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if _identity_tuple(opened) != _identity_tuple(metadata):
                raise CandidateCliError("candidate_receipt_invalidation_uncertain")
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
                raise CandidateCliError("candidate_receipt_removal_uncertain")
        finally:
            os.close(descriptor)
        path.unlink()
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except CandidateCliError:
        raise
    except OSError as exc:
        label = (
            "candidate_receipt_removal_uncertain"
            if invalidated
            else "candidate_receipt_invalidation_uncertain"
        )
        raise CandidateCliError(label) from exc


def _create_lifecycle_directory(
    output_dir: Path,
    *,
    invocation_id: str,
    identity: HostIdentity,
    component_id: str = "trivy-db",
) -> Path:
    if not INVOCATION_ID.fullmatch(invocation_id):
        raise CandidateCliError("invocation_id_invalid")
    _require_private_directory(output_dir.parent, empty=False, identity=identity)
    _docker_run_modes(component_id)
    lifecycle_dir = output_dir.parent / (
        f".kodesec-{component_id}-{invocation_id}.docker"
    )
    created = False
    try:
        lifecycle_dir.mkdir(mode=0o700, parents=False)
        created = True
        lifecycle_dir.chmod(0o700)
        _require_private_directory(lifecycle_dir, empty=True, identity=identity)
    except Exception as exc:
        if created:
            try:
                lifecycle_dir.rmdir()
            except OSError as cleanup_exc:
                raise CandidateCliError(
                    "docker_lifecycle_directory_cleanup_uncertain"
                ) from cleanup_exc
        if isinstance(exc, CandidateCliError):
            raise
        raise CandidateCliError("docker_lifecycle_directory_creation_failed") from exc
    return lifecycle_dir


def _remove_lifecycle_directory(path: Path, *, identity: HostIdentity) -> None:
    try:
        _require_private_directory(path, empty=True, identity=identity)
        path.rmdir()
    except CandidateCliError as exc:
        raise CandidateCliError(
            f"docker_lifecycle_directory_cleanup_uncertain:{path}"
        ) from exc
    except OSError as exc:
        raise CandidateCliError(
            f"docker_lifecycle_directory_cleanup_uncertain:{path}"
        ) from exc


def _docker_run_identity(
    *,
    invocation_id: str,
    mode: str,
    lifecycle_dir: Path,
    component_id: str = "trivy-db",
) -> DockerRunIdentity:
    modes = _docker_run_modes(component_id)
    if mode not in modes:
        raise CandidateCliError("docker_mode_invalid")
    name = f"kodesec-{component_id}-{invocation_id}-{mode}"
    return DockerRunIdentity(name=name, cidfile=lifecycle_dir / f"{name}.cid")


def orchestrate(
    build_receipt_path: Path,
    output_dir: Path,
    *,
    identity: HostIdentity,
    component_id: str = "trivy-db",
    support_trivy_db: Path | None = None,
) -> Path:
    """Run the separated evidence producers and publish one final proposal."""

    require_review_build_host()
    _component_contract(component_id)
    if (component_id == "trivy-java-db") != (support_trivy_db is not None):
        raise CandidateCliError("support_trivy_db_invalid")
    if support_trivy_db is not None:
        _require_immutable_support_directory(support_trivy_db, identity=identity)
    invoking_identity = require_host_identity()
    if identity != invoking_identity:
        raise CandidateCliError("invoking_identity_changed")
    # Prove the host-side pure validation core is importable before validating
    # or activating a one-use held build receipt. A missing launcher dependency
    # must not consume an otherwise valid review image.
    core = _candidate_core()
    build_receipt = validate_build_receipt(
        build_receipt_path, identity=invoking_identity
    )
    _activate_build_runtime(
        build_receipt, build_receipt_path, identity=invoking_identity
    )
    image_id = build_receipt["image"]["id"]
    created = False
    committed = False
    build_cleanup_succeeded = False
    primary: BaseException | None = None
    result: Path | None = None
    try:
        _require_owned_build_image(receipt=build_receipt)
        architecture = build_receipt["image"]["architecture"]
        if (
            _collect_build_inputs(identity=invoking_identity)
            != build_receipt["inputs_after"]
        ):
            raise CandidateCliError("build_source_binding_changed_before_egress")
        try:
            output_dir.mkdir(mode=0o700, parents=False)
            created = True
            output_dir.chmod(0o700)
        except OSError as exc:
            raise CandidateCliError("output_directory_creation_failed") from exc
        _require_private_directory(output_dir, empty=True, identity=invoking_identity)
        final_path, final_receipt = _orchestrate_created_output(
            core=core,
            image_id=image_id,
            architecture=architecture,
            output_dir=output_dir,
            identity=invoking_identity,
            build_receipt_identity={
                "schema": build_receipt["schema"],
                "receipt_sha256": build_receipt["receipt_sha256"],
            },
            build_inputs=build_receipt["inputs_after"],
            build_receipt=build_receipt,
            component_id=component_id,
            support_trivy_db=support_trivy_db,
        )
        # The final proposal does not become consumable until the exact held
        # build identity has been removed and its tag and label are repeatedly
        # proven absent.
        _cleanup_owned_build_image(receipt=build_receipt)
        build_cleanup_succeeded = True
        try:
            if component_id == "trivy-db":
                core.write_private_receipt(final_path, final_receipt)
            else:
                core.write_private_receipt(
                    final_path, final_receipt, component_id=component_id
                )
        except Exception as exc:
            raise CandidateCliError("final_receipt_publication_failed") from exc
        committed = True
        result = final_path
    except BaseException as exc:
        primary = exc
    if not committed:
        if isinstance(primary, DockerProcessCleanupUncertain):
            # A daemon-side create/run or image operation may still publish
            # after its client was reaped.  Keep the exact private output and
            # lifecycle identities for diagnosis and do not make further
            # lifecycle claims.  The final commit marker must remain absent.
            if created:
                try:
                    _invalidate_candidate_receipt(
                        output_dir / "candidate-receipt.json",
                        identity=invoking_identity,
                    )
                except BaseException as exc:
                    raise CandidateCliError(
                        f"candidate_forensic_state_uncertain:{output_dir}"
                    ) from exc
            raise primary
        cleanup_errors: list[BaseException] = []

        def attempt(operation) -> None:
            try:
                operation()
            except BaseException as exc:
                cleanup_errors.append(exc)

        if not build_cleanup_succeeded:
            attempt(lambda: _cleanup_owned_build_image(receipt=build_receipt))
        if created:
            final_path = output_dir / "candidate-receipt.json"
            attempt(
                lambda: _invalidate_candidate_receipt(
                    final_path, identity=invoking_identity
                )
            )
            attempt(
                lambda: _remove_owned_output_tree(
                    output_dir, identity=invoking_identity
                )
            )
        if cleanup_errors:
            if len(cleanup_errors) == 1:
                raise cleanup_errors[0]
            raise CandidateCliError(
                "candidate_cleanup_uncertain:"
                + ",".join(type(item).__name__ for item in cleanup_errors)
            ) from cleanup_errors[0]
    if primary is not None:
        raise primary
    assert result is not None
    return result


def _orchestrate_created_output(
    *,
    core: object,
    image_id: str,
    architecture: str,
    output_dir: Path,
    identity: HostIdentity,
    build_receipt_identity: Mapping[str, str],
    build_inputs: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
    component_id: str = "trivy-db",
    support_trivy_db: Path | None = None,
) -> tuple[Path, Mapping[str, Any]]:
    inputs = ReviewInputs(
        image_id=image_id,
        architecture=architecture,
        output_dir=output_dir,
        identity=identity,
        invocation_id=secrets.token_hex(16),
        component_id=component_id,
        support_trivy_db=support_trivy_db,
    )
    lifecycle_dir = _create_lifecycle_directory(
        output_dir,
        invocation_id=inputs.invocation_id,
        identity=identity,
        component_id=component_id,
    )
    preserve_lifecycle = False
    try:
        return _orchestrate_owned_runs(
            core=core,
            inputs=inputs,
            lifecycle_dir=lifecycle_dir,
            build_receipt_identity=build_receipt_identity,
            build_inputs=build_inputs,
            build_receipt=build_receipt,
        )
    except DockerProcessCleanupUncertain:
        preserve_lifecycle = True
        raise
    finally:
        if not preserve_lifecycle:
            _remove_lifecycle_directory(lifecycle_dir, identity=identity)


def _orchestrate_owned_runs(
    *,
    core: object,
    inputs: ReviewInputs,
    lifecycle_dir: Path,
    build_receipt_identity: Mapping[str, str],
    build_inputs: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
) -> tuple[Path, Mapping[str, Any]]:
    image_id = inputs.image_id
    architecture = inputs.architecture
    output_dir = inputs.output_dir
    identity = inputs.identity
    component_id = inputs.component_id
    contract = _component_contract(component_id)

    preflight_run = _docker_run_identity(
        invocation_id=inputs.invocation_id,
        mode="preflight",
        lifecycle_dir=lifecycle_dir,
        component_id=component_id,
    )
    preflight_raw = _receipt_stdout(
        run_owned_container(
            preflight_argv(inputs, run_identity=preflight_run),
            run_identity=preflight_run,
            identity=identity,
            timeout_seconds=120,
        ),
        label="preflight",
    )
    try:
        preflight = core.validate_preflight_receipt(preflight_raw, component_id)
    except Exception as exc:
        raise CandidateCliError("preflight_receipt_invalid") from exc
    if preflight["scanner"]["architecture"] != architecture:
        raise CandidateCliError("preflight_architecture_mismatch")
    if preflight["invocation_id"] != inputs.invocation_id:
        raise CandidateCliError("preflight_invocation_mismatch")
    try:
        local_implementation_bundle = core.implementation_bundle_evidence(
            Path(core.__file__).resolve(strict=True).parent,
            expected_uid=identity.uid,
        )
    except Exception as exc:
        raise CandidateCliError("local_implementation_bundle_invalid") from exc
    if preflight["scanner"]["implementation_bundle"] != local_implementation_bundle:
        raise CandidateCliError("implementation_bundle_image_mismatch")
    host_cli_sha256 = _stable_source_sha256(
        Path(__file__).resolve(strict=True), label="host_candidate_cli"
    )
    if _collect_build_inputs(identity=identity) != build_inputs:
        raise CandidateCliError("build_source_binding_changed_before_egress")
    _require_owned_build_image(receipt=build_receipt)

    fetch_run = _docker_run_identity(
        invocation_id=inputs.invocation_id,
        mode="fetch",
        lifecycle_dir=lifecycle_dir,
        component_id=component_id,
    )
    fetch_raw = _receipt_stdout(
        run_owned_container(
            fetch_argv(inputs, run_identity=fetch_run),
            run_identity=fetch_run,
            identity=identity,
            timeout_seconds=MAX_DOCKER_TIMEOUT_SECONDS,
        ),
        label="fetch",
    )
    _verify_fetch_output_shape(output_dir, identity=identity)
    if (
        _read_private_receipt(output_dir / "fetch-receipt.json", identity=identity)
        != fetch_raw
    ):
        raise CandidateCliError("fetch_receipt_stream_disk_mismatch")
    try:
        fetch, manifest, metadata, installed_records = core.validate_fetch_receipt(
            fetch_raw, component_id=component_id
        )
    except Exception as exc:
        raise CandidateCliError("fetch_receipt_invalid") from exc
    if fetch["invocation_id"] != inputs.invocation_id:
        raise CandidateCliError("fetch_invocation_mismatch")

    canary_run = _docker_run_identity(
        invocation_id=inputs.invocation_id,
        mode="canary",
        lifecycle_dir=lifecycle_dir,
        component_id=component_id,
    )
    canary_raw = _receipt_stdout(
        run_owned_container(
            canary_argv(inputs, run_identity=canary_run),
            run_identity=canary_run,
            identity=identity,
            timeout_seconds=MAX_DOCKER_TIMEOUT_SECONDS,
        ),
        label="canary",
    )
    try:
        canary, proposal_canaries = core.validate_canary_receipt(
            canary_raw, component_id
        )
    except Exception as exc:
        raise CandidateCliError("canary_receipt_invalid") from exc
    if (
        canary["invocation_id"] != inputs.invocation_id
        or fetch["invocation_id"] != preflight["invocation_id"]
        or canary["invocation_id"] != preflight["invocation_id"]
        or canary["current_lock_sha256"] != preflight["current_lock_sha256"]
        or canary["candidate_tree"] != fetch["installed_tree"]
    ):
        raise CandidateCliError("cross_receipt_identity_mismatch")

    scanner = preflight["scanner"]
    try:
        final_receipt = core.build_proposal_receipt(
            current_lock_sha256=preflight["current_lock_sha256"],
            baked_lock_sha256=preflight["baked_lock_sha256"],
            image_id=image_id,
            architecture=architecture,
            trivy_version=scanner["trivy_version"],
            trivy_executable_path=scanner["trivy_executable_path"],
            trivy_executable_sha256=scanner["trivy_executable_sha256"],
            tool_manifest_sha256=scanner["tool_manifest_sha256"],
            implementation_bundle=scanner["implementation_bundle"],
            host_cli_sha256=host_cli_sha256,
            host_execution_identity={
                "uid": identity.uid,
                "gid": identity.gid,
            },
            evidence_receipts={
                label: {
                    "schema": receipt["schema"],
                    "receipt_sha256": receipt["receipt_sha256"],
                }
                for label, receipt in (
                    ("preflight", preflight),
                    ("fetch", fetch),
                    ("canary", canary),
                )
            },
            build_receipt=build_receipt_identity,
            manifest=manifest,
            metadata=metadata,
            installed_records=installed_records,
            current_canaries=preflight["current_canaries"],
            canaries=proposal_canaries,
            component_id=component_id,
        )
        core.write_private_evidence_receipt(
            output_dir / "preflight-receipt.json",
            preflight,
            schema=f"{contract['receipt_prefix']}-preflight/v1",
            fields={
                "schema",
                "invocation_id",
                "current_lock_sha256",
                "baked_lock_sha256",
                "scanner",
                "current_canaries",
            },
        )
        canary_fields = {
            "schema",
            "invocation_id",
            "current_lock_sha256",
            "candidate_tree",
            "canaries",
        }
        if component_id == "trivy-java-db":
            canary_fields.add("support_trivy_db")
        core.write_private_evidence_receipt(
            output_dir / "canary-receipt.json",
            canary,
            schema=f"{contract['receipt_prefix']}-canary/v1",
            fields=canary_fields,
        )
    except Exception as exc:
        raise CandidateCliError("final_receipt_composition_failed") from exc
    return output_dir / "candidate-receipt.json", final_receipt


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--component-id",
        choices=tuple(COMPONENT_CONTRACTS),
        default="trivy-db",
    )
    parser.add_argument("--build-receipt", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--support-trivy-db", type=Path)
    args = parser.parse_args(argv)
    try:
        require_review_build_host()
        args.identity = require_host_identity()
        args.output_dir = require_new_private_output(
            args.output_dir, identity=args.identity
        )
        if (args.component_id == "trivy-java-db") != (
            args.support_trivy_db is not None
        ):
            raise CandidateCliError("support_trivy_db_invalid")
        if args.support_trivy_db is not None:
            args.support_trivy_db = _require_immutable_support_directory(
                args.support_trivy_db, identity=args.identity
            )
    except CandidateCliError as exc:
        parser.error(str(exc))
    return args


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        final_path = orchestrate(
            arguments.build_receipt,
            arguments.output_dir,
            identity=arguments.identity,
            component_id=arguments.component_id,
            support_trivy_db=arguments.support_trivy_db,
        )
    except DockerProcessCleanupUncertain as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except CandidateCliError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(final_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
