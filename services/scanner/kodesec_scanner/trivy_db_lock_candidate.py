"""Pure validation primitives for a reviewed Trivy DB lock candidate.

This module deliberately performs no network access, Docker invocation, or lock
mutation.  A host-side orchestrator may feed it registry response bytes and a
downloaded layer, but those inputs remain untrusted until every identity,
archive, metadata, installed-tree, and canary invariant below succeeds.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import resource
import secrets
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    Protocol,
    Sequence,
)

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .cache_manifest import (
    CANONICAL_TREE_HASH_ALGORITHM,
    EXTERNAL_TOOL_IDS,
    CacheValidationError,
    CacheFileRecord,
    LockValidationError,
    canonical_json_bytes,
    canonical_tree_sha256,
    collect_canonical_tree,
    load_tool_lock,
)
from .tools import EXTERNAL_TOOL_VERSIONS, TOOL_VERSION_COMMANDS
from .source_build import verify_source_build
from .updater import canonical_canary_output_sha256


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_METADATA_BYTES = 4 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_LAYER_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_ARCHIVE_DEPTH = 16
MAX_INSTALLED_BYTES = 2 * 1024 * 1024 * 1024
MAX_INSTALLED_FILES = 20_000
MAX_INSTALLED_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TAR_STREAM_BYTES = MAX_INSTALLED_BYTES + 64 * 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
MAX_TOOL_MANIFEST_BYTES = 256 * 1024
MAX_IMPLEMENTATION_FILES = 256
MAX_IMPLEMENTATION_BYTES = 8 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_CANARY_JSON_BYTES = 16 * 1024 * 1024
MAX_CANARY_IDS = 512
MAX_COMMAND_SECONDS = 300
MAX_FETCH_SECONDS = 900
MAX_EXTRACTION_SECONDS = 300
TRIVY_DB_MAX_AGE_SECONDS = 1_209_600
TRIVY_DB_MAX_UPDATE_INTERVAL_SECONDS = 86_400
TRIVY_JAVA_DB_MAX_AGE_SECONDS = 1_209_600
TRIVY_JAVA_DB_MAX_UPDATE_INTERVAL_SECONDS = 345_600
# NextUpdate is a publisher refresh hint, not a hard scanning expiry. The
# remaining-life floor therefore applies to the reviewed fourteen-day window
# anchored at UpdatedAt; an overdue refresh hint remains useful provenance.
MINIMUM_REMAINING_SECONDS = 43_200
RAW_TRIVY_DOWNLOADED_AT = "0001-01-01T00:00:00Z"
TRIVY_DB_DISCOVERY_REF = "ghcr.io/aquasecurity/trivy-db:2"
TRIVY_DB_REGISTRY = "ghcr.io"
TRIVY_DB_REPOSITORY = "aquasecurity/trivy-db"
TRIVY_DB_REFERENCE = "2"
TRIVY_VERSION = "0.73.0"
TRIVY_EXECUTABLE_PATH = "/usr/local/bin/trivy"
TOKEN_URL = (
    "https://ghcr.io/token?service=ghcr.io&"
    "scope=repository%3Aaquasecurity%2Ftrivy-db%3Apull"
)
# GHCR currently hands blob payloads to this exact object-storage host.  Keep
# this enumerated: suffix/pattern trust would admit attacker-controlled names.
BLOB_REDIRECT_HOSTS = frozenset({"pkg-containers.githubusercontent.com"})
MAX_REDIRECT_URL_BYTES = 8192
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
EMPTY_CONFIG_BYTES = b"{}"
EMPTY_CONFIG_DIGEST = "sha256:" + hashlib.sha256(EMPTY_CONFIG_BYTES).hexdigest()

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_UUID7 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


@dataclass(frozen=True)
class TrivyDbCandidateProfile:
    component_id: Literal["trivy-db", "trivy-java-db"]
    cache_child: Literal["db", "java-db"]
    cache_subpath: str
    discovery_ref: str
    repository: str
    reference: str
    token_url: str
    layer_media_type: str
    layer_title: str
    metadata_version: int
    maximum_age_seconds: int
    maximum_update_interval_seconds: int
    maximum_layer_bytes: int
    canary_ids: tuple[str, str]
    fixture_paths: tuple[str, str]
    fixture_kinds: tuple[Literal["file", "tree"], Literal["file", "tree"]]
    receipt_prefix: str


_TRIVY_DB_PROFILES: Mapping[str, TrivyDbCandidateProfile] = {
    "trivy-db": TrivyDbCandidateProfile(
        component_id="trivy-db",
        cache_child="db",
        cache_subpath="trivy/db",
        discovery_ref=TRIVY_DB_DISCOVERY_REF,
        repository=TRIVY_DB_REPOSITORY,
        reference=TRIVY_DB_REFERENCE,
        token_url=TOKEN_URL,
        layer_media_type="application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
        layer_title="db.tar.gz",
        metadata_version=2,
        maximum_age_seconds=TRIVY_DB_MAX_AGE_SECONDS,
        maximum_update_interval_seconds=TRIVY_DB_MAX_UPDATE_INTERVAL_SECONDS,
        maximum_layer_bytes=256 * 1024 * 1024,
        canary_ids=(
            "source-vulnerabilities-positive",
            "source-vulnerabilities-zero",
        ),
        fixture_paths=("dependencies/positive", "dependencies/zero"),
        fixture_kinds=("tree", "tree"),
        receipt_prefix="kodesec.trivy-db-lock-candidate",
    ),
    "trivy-java-db": TrivyDbCandidateProfile(
        component_id="trivy-java-db",
        cache_child="java-db",
        cache_subpath="trivy/java-db",
        discovery_ref="ghcr.io/aquasecurity/trivy-java-db:1",
        repository="aquasecurity/trivy-java-db",
        reference="1",
        token_url=(
            "https://ghcr.io/token?service=ghcr.io&"
            "scope=repository%3Aaquasecurity%2Ftrivy-java-db%3Apull"
        ),
        layer_media_type=(
            "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
        ),
        layer_title="javadb.tar.gz",
        metadata_version=1,
        maximum_age_seconds=TRIVY_JAVA_DB_MAX_AGE_SECONDS,
        maximum_update_interval_seconds=TRIVY_JAVA_DB_MAX_UPDATE_INTERVAL_SECONDS,
        maximum_layer_bytes=2 * 1024 * 1024 * 1024,
        canary_ids=("java-artifacts-positive", "java-artifacts-zero"),
        fixture_paths=(
            "trivy/java/log4j-core-2.14.1.jar",
            "dependencies/zero",
        ),
        fixture_kinds=("file", "tree"),
        receipt_prefix="kodesec.trivy-java-db-lock-candidate",
    ),
}


def candidate_profile(component_id: str = "trivy-db") -> TrivyDbCandidateProfile:
    try:
        return _TRIVY_DB_PROFILES[component_id]
    except (KeyError, TypeError) as exc:
        raise CandidateValidationError(
            "Trivy DB candidate component is not admitted"
        ) from exc


_INNER_FAILURE_MARKER = "kodesec_candidate_failure/v1"
_INNER_FAILURE_CODES = {
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


class _BoundedGzipReader:
    """Seek-free gzip reader that caps every request and total output bytes."""

    def __init__(self, source: Any, *, maximum_bytes: int) -> None:
        self._source = source
        self._maximum = maximum_bytes
        self._observed = 0
        self._buffer = bytearray()
        self._eof = False
        self._compressed = b""
        self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._observed - len(self._buffer)

    def _fill(self, requested: int) -> None:
        while len(self._buffer) < requested and not self._eof:
            if not self._compressed:
                self._compressed = self._source.read(1024 * 1024)
            if not self._compressed:
                if not self._decompressor.eof:
                    raise CandidateValidationError("layer gzip stream is truncated")
                self._eof = True
                break
            try:
                produced = self._decompressor.decompress(
                    self._compressed,
                    min(1024 * 1024, self._maximum + 1 - self._observed),
                )
            except zlib.error as exc:
                raise CandidateValidationError(
                    "layer gzip stream is malformed"
                ) from exc
            self._compressed = self._decompressor.unconsumed_tail
            self._buffer.extend(produced)
            self._observed += len(produced)
            if self._observed > self._maximum:
                raise CandidateValidationError(
                    "layer tar stream exceeds its hard byte bound"
                )
            if self._decompressor.eof:
                if self._decompressor.unused_data:
                    raise CandidateValidationError("layer gzip stream is concatenated")
                self._eof = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > 1024 * 1024:
            raise CandidateValidationError(
                "tar parser requested an oversized metadata block"
            )
        self._fill(size)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def readinto(self, target: bytearray | memoryview) -> int:
        if len(target) > 1024 * 1024:
            raise CandidateValidationError(
                "tar parser requested an oversized metadata block"
            )
        value = self.read(len(target))
        target[: len(value)] = value
        return len(value)


class _StrictTarInfo(tarfile.TarInfo):
    """Reject tar extension headers before stdlib allocates their payload."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise CandidateValidationError(
                "layer tar extension metadata or special entry is prohibited"
            )
        return super()._proc_member(archive)


class CandidateValidationError(ValueError):
    """Untrusted candidate evidence failed a strict admission invariant."""


class _InnerFailure(CandidateValidationError):
    """Carry one allowlisted inner phase without exposing exception details."""

    def __init__(self, mode: str, code: str, message: str) -> None:
        super().__init__(message)
        self.mode = mode
        self.code = code


@contextmanager
def _inner_failure_phase(mode: str, code: str) -> Iterator[None]:
    allowed = _INNER_FAILURE_CODES.get(mode)
    if allowed is None or code not in allowed or code == "unexpected":
        raise RuntimeError("inner failure phase is not allowlisted")
    try:
        yield
    except _InnerFailure:
        raise
    except (
        CandidateValidationError,
        CacheValidationError,
        LockValidationError,
    ) as exc:
        # Preserve the existing exception text for direct library callers and
        # tests, but inner_main emits only mode+enum from this typed wrapper.
        raise _InnerFailure(mode, code, str(exc)) from exc


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
        result_path: Path | None = None,
        maximum_result_bytes: int = MAX_CANARY_JSON_BYTES,
    ) -> CommandResult: ...


class HttpResponse(Protocol):
    status: int
    headers: Any

    def geturl(self) -> str: ...

    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class HttpTransport(Protocol):
    def __call__(
        self, url: str, *, headers: Mapping[str, str], timeout_seconds: float
    ) -> HttpResponse: ...


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateValidationError("JSON contains a duplicate object key")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise CandidateValidationError(f"JSON contains a non-finite number: {value}")


def strict_json_object(raw: bytes, *, label: str, maximum_bytes: int) -> dict[str, Any]:
    """Decode one bounded, unambiguous UTF-8 JSON object."""

    if not raw or len(raw) > maximum_bytes:
        raise CandidateValidationError(f"{label} is empty or oversized")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, CandidateValidationError):
            raise
        raise CandidateValidationError(
            f"{label} is not strict, unambiguous UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise CandidateValidationError(f"{label} must contain one JSON object")
    return value


def _bounded_regular_bytes(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    """Read one unchanged, single-link regular file through a no-follow fd."""

    if maximum_bytes <= 0:
        raise ValueError("file byte bound must be positive")
    try:
        before = path.lstat()
    except OSError as exc:
        raise CandidateValidationError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise CandidateValidationError(f"{label} is not one bounded regular file")
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except OSError as exc:
        raise CandidateValidationError(f"{label} cannot be opened safely") from exc
    payload = bytearray()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise CandidateValidationError(f"{label} changed before reading")
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, maximum_bytes + 1 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum_bytes:
                raise CandidateValidationError(f"{label} exceeds its hard byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not payload or (
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
        raise CandidateValidationError(f"{label} changed while reading")
    return bytes(payload)


def _regular_file_sha256(
    path: Path,
    *,
    label: str,
    require_executable: bool = False,
    expected_uid: int | None = None,
) -> str:
    """Hash a stable image file and enforce its reviewed ownership/mode."""

    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_mode & 0o022
        or (expected_uid is not None and before.st_uid != expected_uid)
        or (require_executable and before.st_mode & 0o111 == 0)
    ):
        raise CandidateValidationError(f"{label} identity or permissions are unsafe")
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise CandidateValidationError(f"{label} changed before reading")
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
        raise CandidateValidationError(f"{label} changed while hashing")
    return digest.hexdigest()


def implementation_bundle_evidence(
    package_root: Path,
    *,
    expected_uid: int | None,
) -> dict[str, Any]:
    """Bind every installed package module used by the candidate workflow."""

    try:
        root_metadata = package_root.lstat()
        resolved_root = package_root.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError(
            "candidate implementation package is unavailable"
        ) from exc
    if (
        package_root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or resolved_root != package_root
        or root_metadata.st_mode & 0o022
        or (expected_uid is not None and root_metadata.st_uid != expected_uid)
    ):
        raise CandidateValidationError("candidate implementation package is unsafe")
    paths = sorted(
        package_root.glob("*.py"), key=lambda item: item.name.encode("utf-8")
    )
    if not 1 <= len(paths) <= MAX_IMPLEMENTATION_FILES:
        raise CandidateValidationError(
            "candidate implementation module count is invalid"
        )
    records: list[dict[str, Any]] = []
    total = 0
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CandidateValidationError(
                "candidate implementation module disappeared"
            ) from exc
        total += metadata.st_size
        if metadata.st_size <= 0 or total > MAX_IMPLEMENTATION_BYTES:
            raise CandidateValidationError(
                "candidate implementation bundle is oversized"
            )
        records.append(
            {
                "path": path.name,
                "size_bytes": metadata.st_size,
                "sha256": _regular_file_sha256(
                    path,
                    label=f"candidate implementation {path.name}",
                    expected_uid=expected_uid,
                ),
            }
        )
    names = {item["path"] for item in records}
    if not {
        "trivy_db_lock_candidate.py",
        "cache_manifest.py",
        "tools.py",
        "updater.py",
    }.issubset(names):
        raise CandidateValidationError("candidate implementation bundle is incomplete")
    return {
        "hash_algorithm": "kodesec-python-bundle-v1",
        "sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
        "file_count": len(records),
        "size_bytes": total,
        "files": records,
    }


def _seal_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(value)
    if "receipt_sha256" in receipt:
        raise CandidateValidationError("receipt digest field was supplied prematurely")
    receipt["receipt_sha256"] = hashlib.sha256(
        canonical_json_bytes(receipt)
    ).hexdigest()
    return receipt


def _parse_sealed_receipt(
    raw: bytes,
    *,
    label: str,
    schema: str,
    fields: set[str],
) -> dict[str, Any]:
    value = strict_json_object(raw, label=label, maximum_bytes=MAX_RECEIPT_BYTES)
    if set(value) != fields | {"receipt_sha256"} or value.get("schema") != schema:
        raise CandidateValidationError(f"{label} fields or schema are not exact")
    claimed = value.get("receipt_sha256")
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    if (
        not isinstance(claimed, str)
        or not _SHA256.fullmatch(claimed)
        or claimed != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        or raw != canonical_json_bytes(value)
    ):
        raise CandidateValidationError(f"{label} canonical identity is invalid")
    return value


def _parse_utc(value: str, *, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339_UTC.fullmatch(value):
        raise CandidateValidationError(f"{label} must be an RFC3339 UTC timestamp")
    normalized = value
    if "." in value:
        whole, fraction = value[:-1].split(".", 1)
        normalized = f"{whole}.{fraction[:6].ljust(6, '0')}Z"
    try:
        return datetime.fromisoformat(normalized[:-1] + "+00:00")
    except ValueError as exc:
        raise CandidateValidationError(f"{label} is not a real timestamp") from exc


def _require_invocation_id(value: str) -> str:
    if not isinstance(value, str) or not _INVOCATION_ID.fullmatch(value):
        raise CandidateValidationError("candidate invocation ID is malformed")
    return value


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _result_file_size(path: Path | None, *, maximum_bytes: int) -> None:
    if path is None:
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateValidationError("command result file is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
    ):
        raise CandidateValidationError("command result file exceeds its safe identity")


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    result_path: Path | None = None,
    maximum_result_bytes: int = MAX_CANARY_JSON_BYTES,
) -> CommandResult:
    """Run one argv with bounded concurrent stdout, stderr, time, and result file."""

    if (
        not argv
        or len(argv) > 64
        or any(
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8", errors="strict")) > 4096
            or _CONTROL.search(item)
            for item in argv
        )
    ):
        raise CandidateValidationError("command argv is malformed or oversized")
    if not 1 <= timeout_seconds <= MAX_COMMAND_SECONDS:
        raise ValueError("command timeout is outside its hard bound")
    if not 1 <= maximum_result_bytes <= MAX_CANARY_JSON_BYTES:
        raise ValueError("command result bound is outside its hard bound")
    try:
        cwd_metadata = cwd.lstat()
    except OSError as exc:
        raise CandidateValidationError(
            "command working directory is unavailable"
        ) from exc
    if cwd.is_symlink() or not stat.S_ISDIR(cwd_metadata.st_mode):
        raise CandidateValidationError("command working directory is unsafe")
    if result_path is not None:
        _result_file_size(result_path, maximum_bytes=maximum_result_bytes)

    def bound_child_files() -> None:
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (maximum_result_bytes, maximum_result_bytes),
        )

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=bound_child_files,
        )
    except OSError as exc:
        raise CandidateValidationError("bounded command could not start") from exc
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        _kill_process_group(process)
        raise CandidateValidationError("bounded command pipes are unavailable")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {process.stdout.fileno(): "stdout", process.stderr.fileno(): "stderr"}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CandidateValidationError("bounded command timed out")
            events = selector.select(min(remaining, 0.1))
            _result_file_size(result_path, maximum_bytes=maximum_result_bytes)
            for key, _ in events:
                label = streams[key.fd]
                allowance = MAX_COMMAND_OUTPUT_BYTES - len(captured[label])
                try:
                    chunk = os.read(key.fd, min(64 * 1024, allowance + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                if len(chunk) > allowance:
                    raise CandidateValidationError(
                        f"bounded command {label} exceeds its hard byte bound"
                    )
                captured[label].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CandidateValidationError("bounded command timed out")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CandidateValidationError("bounded command timed out") from exc
        _result_file_size(result_path, maximum_bytes=maximum_result_bytes)
        return CommandResult(
            returncode=returncode,
            stdout=bytes(captured["stdout"]),
            stderr=bytes(captured["stderr"]),
        )
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _ConfigDescriptor(_StrictModel):
    mediaType: str
    digest: str
    size: int
    data: str

    @field_validator("mediaType")
    @classmethod
    def exact_media_type(cls, value: str) -> str:
        if value != "application/vnd.oci.empty.v1+json":
            raise ValueError("OCI config media type is not the reviewed empty config")
        return value

    @field_validator("digest")
    @classmethod
    def exact_digest(cls, value: str) -> str:
        if value != EMPTY_CONFIG_DIGEST:
            raise ValueError("OCI config digest is not the reviewed empty config")
        return value

    @field_validator("size")
    @classmethod
    def exact_size(cls, value: int) -> int:
        if value != len(EMPTY_CONFIG_BYTES):
            raise ValueError("OCI config size is not exact")
        return value

    @field_validator("data")
    @classmethod
    def exact_data(cls, value: str) -> str:
        if value != "e30=":
            raise ValueError("OCI config data is not the reviewed empty config")
        return value


class _LayerDescriptor(_StrictModel):
    mediaType: str
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size: int = Field(gt=0, le=MAX_LAYER_BYTES)
    annotations: dict[str, str]

    @field_validator("mediaType")
    @classmethod
    def exact_media_type(cls, value: str) -> str:
        if value not in {
            profile.layer_media_type for profile in _TRIVY_DB_PROFILES.values()
        }:
            raise ValueError("Trivy DB layer media type is not exact")
        return value

    @field_validator("annotations")
    @classmethod
    def exact_annotations(cls, value: dict[str, str]) -> dict[str, str]:
        if value not in [
            {"org.opencontainers.image.title": profile.layer_title}
            for profile in _TRIVY_DB_PROFILES.values()
        ]:
            raise ValueError("Trivy DB layer annotations are not exact")
        return value


class _Manifest(_StrictModel):
    schemaVersion: int
    mediaType: str
    artifactType: str
    config: _ConfigDescriptor
    layers: list[_LayerDescriptor]
    annotations: dict[str, str]

    @field_validator("schemaVersion")
    @classmethod
    def exact_schema(cls, value: int) -> int:
        if value != 2:
            raise ValueError("OCI schema version is not 2")
        return value

    @field_validator("mediaType")
    @classmethod
    def exact_media_type(cls, value: str) -> str:
        if value != "application/vnd.oci.image.manifest.v1+json":
            raise ValueError("OCI manifest media type is not exact")
        return value

    @field_validator("artifactType")
    @classmethod
    def exact_artifact_type(cls, value: str) -> str:
        if value != "application/vnd.aquasec.trivy.config.v1+json":
            raise ValueError("Trivy artifact type is not exact")
        return value

    @field_validator("layers")
    @classmethod
    def one_layer(cls, value: list[_LayerDescriptor]) -> list[_LayerDescriptor]:
        if len(value) != 1:
            raise ValueError("Trivy DB manifest must contain exactly one layer")
        return value

    @field_validator("annotations")
    @classmethod
    def exact_annotations(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != {"org.opencontainers.image.created"}:
            raise ValueError("OCI manifest annotations are not exact")
        _parse_utc(value["org.opencontainers.image.created"], label="OCI created")
        return value


@dataclass(frozen=True)
class OciManifestEvidence:
    manifest_digest: str
    created_at: str
    layer_digest: str
    layer_size_bytes: int


def _normalize_digest_header(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise CandidateValidationError(f"{label} is not one lowercase SHA-256 digest")
    return value


def validate_manifest_pair(
    *,
    tag_body: bytes,
    tag_digest_header: str,
    digest_body: bytes,
    digest_digest_header: str,
    component_id: str = "trivy-db",
) -> OciManifestEvidence:
    """Bind tag resolution and immutable-digest refetch to identical bytes."""

    if tag_body != digest_body:
        raise CandidateValidationError("tag and digest manifest bodies differ")
    observed = "sha256:" + hashlib.sha256(tag_body).hexdigest()
    if (
        _normalize_digest_header(tag_digest_header, label="tag response digest")
        != observed
        or _normalize_digest_header(
            digest_digest_header, label="digest response digest"
        )
        != observed
    ):
        raise CandidateValidationError("manifest body and response digest disagree")
    profile = candidate_profile(component_id)
    try:
        manifest = _Manifest.model_validate(
            strict_json_object(
                tag_body,
                label="Trivy DB OCI manifest",
                maximum_bytes=MAX_MANIFEST_BYTES,
            )
        )
    except ValidationError as exc:
        raise CandidateValidationError("Trivy DB OCI manifest schema differs") from exc
    layer = manifest.layers[0]
    if (
        layer.mediaType != profile.layer_media_type
        or layer.annotations != {"org.opencontainers.image.title": profile.layer_title}
        or layer.size > profile.maximum_layer_bytes
    ):
        raise CandidateValidationError(
            "Trivy DB OCI manifest differs from its component"
        )
    return OciManifestEvidence(
        manifest_digest=observed.removeprefix("sha256:"),
        created_at=manifest.annotations["org.opencontainers.image.created"],
        layer_digest=layer.digest.removeprefix("sha256:"),
        layer_size_bytes=layer.size,
    )


def validate_layer_file(
    path: Path, *, expected_sha256: str, expected_size_bytes: int
) -> None:
    if not _SHA256.fullmatch(expected_sha256):
        raise CandidateValidationError("layer SHA-256 is malformed")
    if expected_size_bytes <= 0 or expected_size_bytes > MAX_LAYER_BYTES:
        raise CandidateValidationError("layer size is outside its bound")
    try:
        before = path.lstat()
    except OSError as exc:
        raise CandidateValidationError("layer file is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise CandidateValidationError("layer file is not a safe regular file")
    if before.st_size != expected_size_bytes:
        raise CandidateValidationError("layer file size differs from its descriptor")
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    digest = hashlib.sha256()
    observed = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise CandidateValidationError("layer file changed before reading")
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, expected_size_bytes + 1 - observed)
            )
            if not chunk:
                break
            observed += len(chunk)
            if observed > expected_size_bytes:
                raise CandidateValidationError("layer file exceeds its descriptor")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        observed != expected_size_bytes
        or digest.hexdigest() != expected_sha256
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    ):
        raise CandidateValidationError(
            "layer bytes or identity differ from the descriptor"
        )


def _archive_name(value: str) -> str | None:
    normalized = value.removeprefix("./").rstrip("/")
    if not normalized:
        return None
    if len(normalized.encode("utf-8", errors="strict")) > 4096 or _CONTROL.search(
        normalized
    ):
        raise CandidateValidationError("archive member name is unsafe")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or len(path.parts) > MAX_ARCHIVE_DEPTH
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CandidateValidationError("archive member path is unsafe")
    return path.as_posix()


def extract_layer_tar_gz(
    archive: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
    maximum_entries: int = MAX_ARCHIVE_ENTRIES,
    maximum_bytes: int = MAX_INSTALLED_BYTES,
    maximum_seconds: int = MAX_EXTRACTION_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[CacheFileRecord, ...]:
    """Stream one verified gzip layer into a new private destination."""

    if not 0 < maximum_entries <= MAX_ARCHIVE_ENTRIES:
        raise ValueError("maximum_entries is outside the hard bound")
    if not 0 < maximum_bytes <= MAX_INSTALLED_BYTES:
        raise ValueError("maximum_bytes is outside the hard bound")
    if not 1 <= maximum_seconds <= MAX_EXTRACTION_SECONDS:
        raise ValueError("maximum_seconds is outside the hard bound")
    deadline = monotonic() + maximum_seconds
    if not _SHA256.fullmatch(expected_sha256):
        raise CandidateValidationError("layer SHA-256 is malformed")
    if not 0 < expected_size_bytes <= MAX_LAYER_BYTES:
        raise CandidateValidationError("layer size is outside its hard bound")
    if destination.exists() or destination.is_symlink():
        raise CandidateValidationError("archive destination already exists")
    parent = destination.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError(
            "archive destination parent is unavailable"
        ) from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or resolved_parent != parent
    ):
        raise CandidateValidationError(
            "archive destination parent must be one direct owner-only directory"
        )
    try:
        archive_before = archive.lstat()
    except OSError as exc:
        raise CandidateValidationError("layer archive is unavailable") from exc
    if (
        archive.is_symlink()
        or not stat.S_ISREG(archive_before.st_mode)
        or archive_before.st_nlink != 1
        or archive_before.st_size != expected_size_bytes
    ):
        raise CandidateValidationError("layer archive is not the expected regular file")
    archive_descriptor = os.open(archive, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    archive_digest = hashlib.sha256()
    archive_observed = 0
    opened = os.fstat(archive_descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino)
        != (archive_before.st_dev, archive_before.st_ino)
    ):
        os.close(archive_descriptor)
        raise CandidateValidationError("layer archive changed before reading")
    while True:
        chunk = os.read(
            archive_descriptor,
            min(1024 * 1024, expected_size_bytes + 1 - archive_observed),
        )
        if not chunk:
            break
        archive_observed += len(chunk)
        if archive_observed > expected_size_bytes:
            os.close(archive_descriptor)
            raise CandidateValidationError("layer archive exceeds its descriptor")
        archive_digest.update(chunk)
    if (
        archive_observed != expected_size_bytes
        or archive_digest.hexdigest() != expected_sha256
    ):
        os.close(archive_descriptor)
        raise CandidateValidationError("layer archive bytes differ from its descriptor")
    os.lseek(archive_descriptor, 0, os.SEEK_SET)
    try:
        destination.mkdir(mode=0o700, parents=False)
    except Exception:
        os.close(archive_descriptor)
        raise
    seen: set[str] = set()
    records: list[CacheFileRecord] = []
    total = 0
    entries = 0
    try:
        archive_stream = os.fdopen(archive_descriptor, "rb", closefd=False)
        try:
            bounded_stream = _BoundedGzipReader(
                archive_stream, maximum_bytes=MAX_TAR_STREAM_BYTES
            )
            with tarfile.open(
                fileobj=bounded_stream, mode="r|", tarinfo=_StrictTarInfo
            ) as bundle:
                for member in bundle:
                    if monotonic() >= deadline:
                        raise CandidateValidationError(
                            "archive extraction exceeded its time bound"
                        )
                    entries += 1
                    if entries > maximum_entries:
                        raise CandidateValidationError(
                            "archive entry count or identity is unsafe"
                        )
                    name = _archive_name(member.name)
                    if name is None:
                        if (
                            member.name not in {".", "./"}
                            or not member.isdir()
                            or member.size != 0
                        ):
                            raise CandidateValidationError(
                                "archive root entry is unsafe"
                            )
                        continue
                    if name in seen:
                        raise CandidateValidationError(
                            "archive entry count or identity is unsafe"
                        )
                    seen.add(name)
                    target = destination.joinpath(*PurePosixPath(name).parts)
                    if member.isdir():
                        if member.size != 0:
                            raise CandidateValidationError(
                                "archive directory carries an unexpected payload"
                            )
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    if (
                        not member.isfile()
                        or member.issym()
                        or member.islnk()
                        or member.size < 0
                        or member.size > MAX_INSTALLED_FILE_BYTES
                    ):
                        raise CandidateValidationError(
                            "archive contains a link or special entry"
                        )
                    total += member.size
                    if total > maximum_bytes:
                        raise CandidateValidationError("archive exceeds its byte bound")
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    source = bundle.extractfile(member)
                    if source is None:
                        raise CandidateValidationError("archive member cannot be read")
                    descriptor = os.open(
                        target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                        0o400,
                    )
                    digest = hashlib.sha256()
                    observed = 0
                    try:
                        while True:
                            if monotonic() >= deadline:
                                raise CandidateValidationError(
                                    "archive extraction exceeded its time bound"
                                )
                            chunk = source.read(
                                min(1024 * 1024, member.size + 1 - observed)
                            )
                            if not chunk:
                                break
                            observed += len(chunk)
                            if observed > member.size:
                                raise CandidateValidationError(
                                    "archive member exceeds its header"
                                )
                            digest.update(chunk)
                            offset = 0
                            while offset < len(chunk):
                                written = os.write(descriptor, chunk[offset:])
                                if written <= 0:
                                    raise CandidateValidationError(
                                        "archive write made no progress"
                                    )
                                offset += written
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                        source.close()
                    if observed != member.size:
                        raise CandidateValidationError("archive member is truncated")
                    records.append(
                        CacheFileRecord(
                            path=name, size_bytes=observed, sha256=digest.hexdigest()
                        )
                    )
        finally:
            archive_stream.close()
        archive_after = os.fstat(archive_descriptor)
        try:
            path_after = archive.lstat()
        except OSError as exc:
            raise CandidateValidationError(
                "layer archive disappeared during extraction"
            ) from exc
        if (
            archive_after.st_dev,
            archive_after.st_ino,
            archive_after.st_size,
            archive_after.st_mtime_ns,
            archive_after.st_ctime_ns,
            archive_after.st_mode,
            archive_after.st_nlink,
        ) != (
            archive_before.st_dev,
            archive_before.st_ino,
            archive_before.st_size,
            archive_before.st_mtime_ns,
            archive_before.st_ctime_ns,
            archive_before.st_mode,
            archive_before.st_nlink,
        ) or (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
            path_after.st_mode,
            path_after.st_nlink,
        ) != (
            archive_before.st_dev,
            archive_before.st_ino,
            archive_before.st_size,
            archive_before.st_mtime_ns,
            archive_before.st_ctime_ns,
            archive_before.st_mode,
            archive_before.st_nlink,
        ):
            raise CandidateValidationError("layer archive changed during extraction")
        if not records:
            raise CandidateValidationError("archive contains no regular files")
        required_directories: set[str] = set()
        for record in records:
            parts = record.path.split("/")[:-1]
            required_directories.update(
                "/".join(parts[:index]) for index in range(1, len(parts) + 1)
            )
        actual_directories = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_dir()
        }
        if actual_directories != required_directories:
            raise CandidateValidationError("archive contains an empty directory")
        destination.chmod(0o500)
        for path in actual_directories:
            (destination / path).chmod(0o500)
        return tuple(sorted(records, key=lambda item: item.path.encode("utf-8")))
    except Exception:
        for root, directories, files in os.walk(
            destination, topdown=False, followlinks=False
        ):
            for name in files:
                (Path(root) / name).unlink(missing_ok=True)
            for name in directories:
                child = Path(root) / name
                if child.is_symlink():
                    child.unlink(missing_ok=True)
                else:
                    child.rmdir()
        destination.rmdir()
        raise
    finally:
        os.close(archive_descriptor)


@dataclass(frozen=True)
class TrivyMetadataEvidence:
    updated_at: str
    next_update: str
    downloaded_at: str
    observed_at: str
    maximum_age_seconds: int
    minimum_remaining_seconds: int
    size_bytes: int
    sha256: str


def validate_metadata_bytes(
    raw: bytes,
    *,
    now: datetime,
    maximum_age_seconds: int,
    minimum_remaining_seconds: int = 0,
    expected_version: int = 2,
    maximum_update_interval_seconds: int = TRIVY_DB_MAX_UPDATE_INTERVAL_SECONDS,
) -> TrivyMetadataEvidence:
    payload = strict_json_object(
        raw, label="Trivy DB metadata", maximum_bytes=MAX_METADATA_BYTES
    )
    if set(payload) != {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}:
        raise CandidateValidationError("Trivy DB metadata fields are not exact")
    if (
        isinstance(payload["Version"], bool)
        or payload["Version"] != expected_version
    ):
        raise CandidateValidationError("Trivy DB metadata Version is not exact")
    updated_raw = payload["UpdatedAt"]
    next_raw = payload["NextUpdate"]
    downloaded_raw = payload["DownloadedAt"]
    updated = _parse_utc(updated_raw, label="Trivy DB UpdatedAt")
    next_update = _parse_utc(next_raw, label="Trivy DB NextUpdate")
    if downloaded_raw != RAW_TRIVY_DOWNLOADED_AT:
        raise CandidateValidationError(
            "raw Trivy DB DownloadedAt is not the exact publisher zero time"
        )
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    moment = now.astimezone(UTC)
    if not 60 <= maximum_age_seconds <= 31 * 24 * 60 * 60:
        raise ValueError("maximum_age_seconds is outside its hard bound")
    if not 0 <= minimum_remaining_seconds <= maximum_age_seconds:
        raise ValueError("minimum_remaining_seconds is outside its hard bound")
    hard_expires = updated + timedelta(seconds=maximum_age_seconds)
    if updated > moment or hard_expires <= moment:
        raise CandidateValidationError("Trivy DB candidate is expired or too old")
    if (
        not 60 <= maximum_update_interval_seconds <= maximum_age_seconds
        or next_update <= updated
        or next_update - updated > timedelta(
            seconds=maximum_update_interval_seconds
        )
    ):
        raise CandidateValidationError("Trivy DB freshness interval exceeds policy")
    if hard_expires - moment < timedelta(seconds=minimum_remaining_seconds):
        raise CandidateValidationError("Trivy DB candidate lacks the required lifetime")
    return TrivyMetadataEvidence(
        updated_at=updated_raw,
        next_update=next_raw,
        downloaded_at=downloaded_raw,
        observed_at=moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
        maximum_age_seconds=maximum_age_seconds,
        minimum_remaining_seconds=minimum_remaining_seconds,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def installed_content_evidence(
    records: Iterable[CacheFileRecord], *, volatile_path: str = "metadata.json"
) -> dict[str, Any]:
    normalized = tuple(records)
    stable = tuple(item for item in normalized if item.path != volatile_path)
    if len(stable) + 1 != len(normalized) or not any(
        item.path == volatile_path for item in normalized
    ):
        raise CandidateValidationError(
            "installed tree requires exactly one metadata.json"
        )
    if not stable:
        raise CandidateValidationError("installed tree contains no stable DB payload")
    if (
        len(stable) > MAX_INSTALLED_FILES
        or sum(item.size_bytes for item in stable) > MAX_INSTALLED_BYTES
    ):
        raise CandidateValidationError("installed DB tree exceeds its bound")
    return {
        "hash_algorithm": CANONICAL_TREE_HASH_ALGORITHM,
        "sha256": canonical_tree_sha256(stable),
        "file_count": len(stable),
        "size_bytes": sum(item.size_bytes for item in stable),
        "volatile_paths": [volatile_path],
    }


def _private_scratch(root: Path, *, prefix: str) -> tempfile.TemporaryDirectory[str]:
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError("scratch root is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or resolved != root:
        raise CandidateValidationError("scratch root is unsafe")
    temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=root)
    Path(temporary.name).chmod(0o700)
    return temporary


def _sterile_environment(scratch: Path) -> dict[str, str]:
    home = scratch / "home"
    temporary = scratch / "tmp"
    xdg = scratch / "xdg"
    for path in (home, temporary, xdg):
        path.mkdir(mode=0o700)
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": str(temporary),
        "TRIVY_DISABLE_VEX_NOTICE": "true",
        "XDG_CACHE_HOME": str(xdg),
    }


def _normalized_architecture(machine: str) -> Literal["amd64", "arm64"]:
    normalized = machine.strip().lower()
    if normalized in {"x86_64", "amd64"}:
        return "amd64"
    if normalized in {"aarch64", "arm64"}:
        return "arm64"
    raise CandidateValidationError("runtime architecture is unsupported")


def _trivy_requirement_contract(
    lock_path: Path, component_id: str = "trivy-db"
) -> tuple[Any, list[dict[str, Any]]]:
    profile = candidate_profile(component_id)
    try:
        loaded = load_tool_lock(lock_path)
        tool = loaded.value.tool("trivy")
    except (KeyError, CacheValidationError, LockValidationError) as exc:
        raise CandidateValidationError("Trivy tool lock is invalid") from exc
    if tool.version != TRIVY_VERSION:
        raise CandidateValidationError("Trivy lock version is not exact")
    matching = [item for item in tool.requirements if item.id == profile.component_id]
    if len(matching) != 1:
        raise CandidateValidationError("Trivy DB requirement is not unique")
    requirement = matching[0]
    if (
        requirement.kind != "database"
        or requirement.required is not True
        or requirement.provenance != "verified"
        or requirement.cache_subpath != profile.cache_subpath
        or requirement.source.kind != "oci"
        or requirement.source.discovery_ref != profile.discovery_ref
        or requirement.max_age_seconds != profile.maximum_age_seconds
        or requirement.data_contract is None
        or requirement.data_contract.kind
        != (
            "trivy-db-metadata/v2"
            if profile.component_id == "trivy-db"
            else "trivy-java-db-metadata/v2"
        )
        or requirement.data_contract.schema_version != profile.metadata_version
        or requirement.data_contract.timestamp_kind != "intrinsic"
    ):
        raise CandidateValidationError("Trivy DB lock contract differs from policy")
    canaries: list[dict[str, Any]] = []
    for canary in requirement.canaries:
        if canary.id not in profile.canary_ids:
            continue
        canaries.append(
            {
                "id": canary.id,
                "fixture_path": canary.fixture_path,
                "fixture_kind": canary.fixture_kind,
                "fixture_hash_algorithm": canary.fixture_hash_algorithm,
                "fixture_sha256": canary.fixture_sha256,
            }
        )
    canaries.sort(key=lambda item: item["id"])
    expected = list(
        zip(profile.canary_ids, profile.fixture_paths, profile.fixture_kinds)
    )
    observed = [
        (item["id"], item["fixture_path"], item["fixture_kind"])
        for item in canaries
    ]
    if len(requirement.canaries) != 2 or observed != expected or any(
        item["fixture_hash_algorithm"]
        != (
            "sha256-file-v1"
            if item["fixture_kind"] == "file"
            else CANONICAL_TREE_HASH_ALGORITHM
        )
        for item in canaries
    ):
        raise CandidateValidationError("Trivy DB current canary contract is not exact")
    return loaded, canaries


def _validated_trivy_support_tree(lock_path: Path, support_db: Path) -> Any:
    """Bind Java canary's required OS DB support bytes to the current lock."""

    try:
        loaded = load_tool_lock(lock_path)
        tool = loaded.value.tool("trivy")
    except (KeyError, CacheValidationError, LockValidationError) as exc:
        raise CandidateValidationError("Trivy tool lock is invalid") from exc
    matching = [item for item in tool.requirements if item.id == "trivy-db"]
    if len(matching) != 1:
        raise CandidateValidationError("Trivy OS DB support requirement is not unique")
    requirement = matching[0]
    if (
        requirement.installed_content is None
        or requirement.installed_size_bytes is None
    ):
        raise CandidateValidationError("Trivy OS DB support contract is incomplete")
    try:
        tree = collect_canonical_tree(
            support_db,
            require_immutable=True,
            maximum_files=MAX_INSTALLED_FILES,
            maximum_bytes=MAX_INSTALLED_BYTES,
        )
    except CacheValidationError as exc:
        raise CandidateValidationError("Trivy OS DB support tree is unsafe") from exc
    installed = installed_content_evidence(tree.files)
    expected = requirement.installed_content.model_dump(mode="json")
    if (
        installed != expected
        or tree.size_bytes < installed["size_bytes"] + 1
        or tree.size_bytes > requirement.installed_size_bytes + MAX_METADATA_BYTES
    ):
        raise CandidateValidationError(
            "Trivy OS DB support tree differs from the current lock"
        )
    return tree


def _verify_fixture_tree(path: Path, expected_sha256: str, *, label: str) -> None:
    if not _SHA256.fullmatch(expected_sha256):
        raise CandidateValidationError(f"{label} expected SHA-256 is malformed")
    try:
        observed = collect_canonical_tree(
            path,
            maximum_files=128,
            maximum_bytes=4 * 1024 * 1024,
        )
    except CacheValidationError as exc:
        raise CandidateValidationError(f"{label} is unsafe") from exc
    if (
        observed.algorithm != CANONICAL_TREE_HASH_ALGORITHM
        or observed.sha256 != expected_sha256
    ):
        raise CandidateValidationError(f"{label} differs from the current lock")


def _verify_fixture(
    path: Path,
    expected_sha256: str,
    *,
    fixture_kind: str,
    label: str,
) -> None:
    if fixture_kind == "tree":
        _verify_fixture_tree(path, expected_sha256, label=label)
        return
    if fixture_kind != "file":
        raise CandidateValidationError(f"{label} fixture kind is unsupported")
    observed = _regular_file_sha256(path, label=label)
    if observed != expected_sha256:
        raise CandidateValidationError(f"{label} differs from the current lock")


def _validate_tool_manifest(
    raw: bytes, *, trivy_path: Path, trivy_sha256: str, tool_lock_path: Path,
) -> str:
    payload = strict_json_object(
        raw, label="scanner tool manifest", maximum_bytes=MAX_TOOL_MANIFEST_BYTES
    )
    if set(payload) != {"schema_version", "tools"} or payload["schema_version"] != 1:
        raise CandidateValidationError("scanner tool manifest fields are not exact")
    tools = payload["tools"]
    if not isinstance(tools, dict) or set(tools) != EXTERNAL_TOOL_IDS:
        raise CandidateValidationError("scanner tool manifest catalog is not exact")
    if raw != canonical_json_bytes(payload):
        raise CandidateValidationError("scanner tool manifest is not canonical")
    locked_tools = load_tool_lock(tool_lock_path).value
    for tool_id, expected_version in EXTERNAL_TOOL_VERSIONS.items():
        tool_entry = tools.get(tool_id)
        source_build = locked_tools.tool(tool_id).binary.source_build
        expected_fields = {"command", "installed_version", "path", "sha256"}
        if source_build is not None:
            expected_fields.add("source_build")
        if tool_id == "opengrep":
            expected_fields.add("runtime_components")
        if not isinstance(tool_entry, dict) or set(tool_entry) != expected_fields:
            raise CandidateValidationError(
                "scanner tool manifest entry fields are not exact"
            )
        binary_path = tool_entry["path"]
        if (
            tool_entry["command"] != TOOL_VERSION_COMMANDS[tool_id]
            or tool_entry["installed_version"] != expected_version
            or not isinstance(binary_path, str)
            or (
                binary_path != str(trivy_path)
                if tool_id == "trivy"
                else not binary_path.startswith("/usr/local/")
            )
            or ".." in PurePosixPath(binary_path).parts
            or not isinstance(tool_entry["sha256"], str)
            or not _SHA256.fullmatch(tool_entry["sha256"])
        ):
            raise CandidateValidationError(
                "scanner tool manifest entry identity is malformed"
            )
        if source_build is not None:
            verified = verify_source_build(source_build, Path(binary_path))
            if (tool_entry["source_build"] != verified
                    or tool_entry["sha256"] != verified["binary_sha256"]):
                raise CandidateValidationError("scanner source-build manifest differs")
        if tool_id == "opengrep":
            components = tool_entry["runtime_components"]
            core = (
                components.get("opengrep_core")
                if isinstance(components, dict)
                else None
            )
            if (
                not isinstance(components, dict)
                or set(components) != {"opengrep_core"}
                or not isinstance(core, dict)
                or set(core) != {"path", "sha256"}
                or not isinstance(core["path"], str)
                or not core["path"].startswith("/usr/local/")
                or ".." in PurePosixPath(core["path"]).parts
                or not isinstance(core["sha256"], str)
                or not _SHA256.fullmatch(core["sha256"])
            ):
                raise CandidateValidationError(
                    "scanner OpenGrep runtime manifest is malformed"
                )
    trivy = tools.get("trivy")
    assert isinstance(trivy, dict)  # established by the complete catalog loop
    if (
        trivy["command"] != ["trivy", "--version"]
        or trivy["installed_version"] != TRIVY_VERSION
        or trivy["path"] != str(trivy_path)
        or trivy["sha256"] != trivy_sha256
    ):
        raise CandidateValidationError("scanner Trivy manifest identity differs")
    return hashlib.sha256(raw).hexdigest()


def run_preflight(
    *,
    current_lock: Path,
    baked_lock: Path,
    trivy_path: Path,
    tool_manifest: Path,
    positive_fixture: Path,
    zero_fixture: Path,
    expected_architecture: str,
    scratch_root: Path,
    runner: CommandRunner = run_bounded_command,
    machine_provider: Callable[[], str] = platform.machine,
    executable_uid: int | None = 0,
    invocation_id: str,
    component_id: str = "trivy-db",
) -> dict[str, Any]:
    """Bind the mounted repository lock/fixtures to the immutable scanner image."""

    invocation = _require_invocation_id(invocation_id)
    profile = candidate_profile(component_id)
    with _inner_failure_phase("preflight", "architecture"):
        if expected_architecture not in {"amd64", "arm64"}:
            raise CandidateValidationError("expected architecture is unsupported")
        observed_architecture = _normalized_architecture(machine_provider())
        if observed_architecture != expected_architecture:
            raise CandidateValidationError(
                "runtime architecture differs from inspection"
            )
    with _inner_failure_phase("preflight", "current_lock"):
        current, canaries = (
            _trivy_requirement_contract(current_lock)
            if component_id == "trivy-db"
            else _trivy_requirement_contract(current_lock, component_id)
        )
    with _inner_failure_phase("preflight", "baked_lock"):
        baked, baked_canaries = (
            _trivy_requirement_contract(baked_lock)
            if component_id == "trivy-db"
            else _trivy_requirement_contract(baked_lock, component_id)
        )
    with _inner_failure_phase("preflight", "lock_binding"):
        if (
            current.sha256 != baked.sha256
            or canaries != baked_canaries
            or current.path == baked.path
        ):
            raise CandidateValidationError("repository and baked scanner locks differ")
    with _inner_failure_phase("preflight", "fixtures"):
        fixture_by_id = {
            profile.canary_ids[0]: positive_fixture,
            profile.canary_ids[1]: zero_fixture,
        }
        for canary in canaries:
            _verify_fixture(
                fixture_by_id[canary["id"]],
                canary["fixture_sha256"],
                fixture_kind=canary["fixture_kind"],
                label=canary["id"],
            )
    with _inner_failure_phase("preflight", "trivy_binary"):
        trivy_sha256 = _regular_file_sha256(
            trivy_path,
            label="Trivy executable",
            require_executable=True,
            expected_uid=executable_uid,
        )
    with _inner_failure_phase("preflight", "tool_manifest"):
        manifest_raw = _bounded_regular_bytes(
            tool_manifest,
            maximum_bytes=MAX_TOOL_MANIFEST_BYTES,
            label="scanner tool manifest",
        )
        tool_manifest_sha256 = _validate_tool_manifest(
            manifest_raw, trivy_path=trivy_path, trivy_sha256=trivy_sha256,
            tool_lock_path=baked_lock,
        )
    with _inner_failure_phase("preflight", "implementation_bundle"):
        implementation_bundle = implementation_bundle_evidence(
            Path(__file__).resolve(strict=True).parent,
            expected_uid=executable_uid,
        )
    with _inner_failure_phase("preflight", "version_probe"):
        with _private_scratch(scratch_root, prefix="preflight-") as temporary_name:
            scratch = Path(temporary_name)
            result = runner(
                (str(trivy_path), "--version"),
                cwd=scratch,
                environment=_sterile_environment(scratch),
                timeout_seconds=30,
            )
        if (
            result.returncode != 0
            or result.stderr
            or not result.stdout
            or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES
        ):
            raise CandidateValidationError(
                "Trivy version probe failed or produced stderr"
            )
        try:
            version_output = result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise CandidateValidationError("Trivy version output is not UTF-8") from exc
        if version_output != f"Version: {TRIVY_VERSION}":
            raise CandidateValidationError("Trivy version probe differs from the lock")
    return _seal_receipt(
        {
            "schema": f"{profile.receipt_prefix}-preflight/v1",
            "invocation_id": invocation,
            "current_lock_sha256": current.sha256,
            "baked_lock_sha256": baked.sha256,
            "scanner": {
                "architecture": observed_architecture,
                "trivy_version": TRIVY_VERSION,
                "trivy_executable_path": str(trivy_path),
                "trivy_executable_sha256": trivy_sha256,
                "tool_manifest_sha256": tool_manifest_sha256,
                "implementation_bundle": implementation_bundle,
            },
            "current_canaries": canaries,
        }
    )


class _ExposeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirect responses to the caller without following any hop."""

    def _expose(
        self,
        request: Any,
        response: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> Any:
        del request, code, message, headers
        return response

    http_error_301 = _expose
    http_error_302 = _expose
    http_error_303 = _expose
    http_error_307 = _expose
    http_error_308 = _expose


class DirectHttpsTransport:
    """HTTPS-only transport with system trust, no proxies, and no redirects."""

    def __init__(self) -> None:
        context = ssl.create_default_context(
            cafile="/etc/ssl/certs/ca-certificates.crt"
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _ExposeRedirectHandler(),
            urllib.request.HTTPSHandler(context=context),
        )

    def __call__(
        self, url: str, *, headers: Mapping[str, str], timeout_seconds: float
    ) -> HttpResponse:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("HTTP request timeout is outside its hard bound")
        request = urllib.request.Request(
            url,
            method="GET",
            headers=dict(headers),
        )
        try:
            return self._opener.open(request, timeout=timeout_seconds)
        except CandidateValidationError:
            raise
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise CandidateValidationError("fixed registry request failed") from exc


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name, [])
    elif isinstance(headers, Mapping):
        values = [
            value
            for key, value in headers.items()
            if isinstance(key, str) and key.lower() == name.lower()
        ]
    else:
        raise CandidateValidationError("registry response headers are unavailable")
    if not isinstance(values, list):
        values = list(values)
    if len(values) != 1 or not isinstance(values[0], str):
        raise CandidateValidationError(f"registry {name} header is not singular")
    value = values[0].strip()
    if not value or len(value) > 4096 or _CONTROL.search(value):
        raise CandidateValidationError(f"registry {name} header is malformed")
    return [value]


def _single_header(headers: Any, name: str) -> str:
    return _header_values(headers, name)[0]


def _response_prelude(
    response: HttpResponse,
    *,
    expected_url: str,
    maximum_bytes: int,
    content_types: set[str],
    expected_digest: str | None,
) -> int:
    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or response.status != 200
        or response.geturl() != expected_url
    ):
        raise CandidateValidationError("registry response status or final URL differs")
    content_type = (
        _single_header(response.headers, "Content-Type").split(";", 1)[0].strip()
    )
    if content_type not in content_types:
        raise CandidateValidationError("registry response media type differs")
    raw_length = _single_header(response.headers, "Content-Length")
    if (
        not raw_length.isascii()
        or not raw_length.isdecimal()
        or str(int(raw_length)) != raw_length
    ):
        raise CandidateValidationError("registry Content-Length is malformed")
    content_length = int(raw_length)
    if not 0 < content_length <= maximum_bytes:
        raise CandidateValidationError(
            "registry response length exceeds its hard bound"
        )
    encodings = []
    if hasattr(response.headers, "get_all"):
        encodings = response.headers.get_all("Content-Encoding", [])
    elif isinstance(response.headers, Mapping):
        encodings = [
            value
            for key, value in response.headers.items()
            if isinstance(key, str) and key.lower() == "content-encoding"
        ]
    if encodings and encodings != ["identity"]:
        raise CandidateValidationError("registry content encoding is prohibited")
    if hasattr(response.headers, "get_all"):
        transfer_encodings = response.headers.get_all("Transfer-Encoding", [])
    elif isinstance(response.headers, Mapping):
        transfer_encodings = [
            value
            for key, value in response.headers.items()
            if isinstance(key, str) and key.lower() == "transfer-encoding"
        ]
    else:  # pragma: no cover - headers were validated above
        transfer_encodings = []
    if transfer_encodings:
        raise CandidateValidationError("registry transfer encoding is prohibited")
    if expected_digest is not None:
        observed_digest = _single_header(response.headers, "Docker-Content-Digest")
        if observed_digest != expected_digest:
            raise CandidateValidationError("registry response digest header differs")
    return content_length


def _open_fixed_response(
    transport: HttpTransport,
    *,
    url: str,
    headers: Mapping[str, str],
    deadline: float,
    monotonic: Callable[[], float],
) -> HttpResponse:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise CandidateValidationError("registry fetch exceeded its time bound")
    if not url.startswith("https://ghcr.io/") or _CONTROL.search(url):
        raise CandidateValidationError("registry request URL is not fixed HTTPS")
    return transport(url, headers=headers, timeout_seconds=min(30.0, remaining))


def _redirect_location(response: HttpResponse) -> str:
    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or response.status not in {302, 307}
    ):
        raise CandidateValidationError("blob response is neither final nor redirect")
    return _single_header(response.headers, "Location")


def _validate_blob_redirect_url(value: str) -> str:
    if not isinstance(value, str):
        raise CandidateValidationError("blob redirect URL is malformed")
    if len(
        value.encode("utf-8", errors="strict")
    ) > MAX_REDIRECT_URL_BYTES or _CONTROL.search(value):
        raise CandidateValidationError("blob redirect URL is oversized or unsafe")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CandidateValidationError("blob redirect URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in BLOB_REDIRECT_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or not parsed.path.startswith("/")
        or len(parsed.path.encode("utf-8", errors="strict")) > 4096
        or len(parsed.query.encode("utf-8", errors="strict")) > 4096
        or _CONTROL.search(parsed.path)
        or _CONTROL.search(parsed.query)
        or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:])
    ):
        raise CandidateValidationError(
            "blob redirect target is outside the exact allowlist"
        )
    if urllib.parse.urlunsplit(parsed) != value:
        raise CandidateValidationError("blob redirect URL is not canonical")
    return value


def _open_blob_response(
    transport: HttpTransport,
    *,
    url: str,
    headers: Mapping[str, str],
    deadline: float,
    monotonic: Callable[[], float],
) -> tuple[HttpResponse, str, bool]:
    """Open a GHCR blob with at most one reviewed, credential-free redirect."""

    first = _open_fixed_response(
        transport,
        url=url,
        headers=headers,
        deadline=deadline,
        monotonic=monotonic,
    )
    if first.status == 200:
        return first, url, True
    try:
        if first.geturl() != url:
            raise CandidateValidationError("blob redirect response final URL differs")
        redirected_url = _validate_blob_redirect_url(_redirect_location(first))
    finally:
        first.close()
    redirected_headers = {
        key: value for key, value in headers.items() if key.lower() != "authorization"
    }
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise CandidateValidationError("registry fetch exceeded its time bound")
    second = transport(
        redirected_url,
        headers=redirected_headers,
        timeout_seconds=min(30.0, remaining),
    )
    if second.status != 200:
        second.close()
        raise CandidateValidationError("second blob redirect or failure is prohibited")
    return second, redirected_url, False


def _read_registry_body(
    response: HttpResponse,
    *,
    expected_url: str,
    maximum_bytes: int,
    content_types: set[str],
    expected_digest: str | None,
    deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    expected_length = _response_prelude(
        response,
        expected_url=expected_url,
        maximum_bytes=maximum_bytes,
        content_types=content_types,
        expected_digest=expected_digest,
    )
    payload = bytearray()
    while True:
        if monotonic() >= deadline:
            raise CandidateValidationError("registry fetch exceeded its time bound")
        chunk = response.read(min(1024 * 1024, maximum_bytes + 1 - len(payload)))
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise CandidateValidationError("registry response yielded non-bytes")
        payload.extend(chunk)
        if len(payload) > maximum_bytes:
            raise CandidateValidationError(
                "registry response exceeds its hard byte bound"
            )
    if len(payload) != expected_length:
        raise CandidateValidationError(
            "registry response length differs from its header"
        )
    return bytes(payload)


def _request_registry_bytes(
    transport: HttpTransport,
    *,
    url: str,
    headers: Mapping[str, str],
    maximum_bytes: int,
    content_types: set[str],
    expected_digest: str | None,
    deadline: float,
    monotonic: Callable[[], float],
    allow_blob_redirect: bool = False,
) -> bytes:
    if allow_blob_redirect:
        response, expected_url, require_digest_header = _open_blob_response(
            transport,
            url=url,
            headers=headers,
            deadline=deadline,
            monotonic=monotonic,
        )
    else:
        response = _open_fixed_response(
            transport,
            url=url,
            headers=headers,
            deadline=deadline,
            monotonic=monotonic,
        )
        expected_url = url
        require_digest_header = True
    try:
        return _read_registry_body(
            response,
            expected_url=expected_url,
            maximum_bytes=maximum_bytes,
            content_types=content_types,
            expected_digest=expected_digest if require_digest_header else None,
            deadline=deadline,
            monotonic=monotonic,
        )
    finally:
        response.close()


def _registry_headers(*, token: str | None, accept: str) -> dict[str, str]:
    headers = {
        "Accept": accept,
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": "kodesec-trivy-db-lock-candidate/1",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_registry_token(raw: bytes) -> str:
    payload = strict_json_object(
        raw, label="registry token", maximum_bytes=MAX_TOKEN_BYTES
    )
    if set(payload) != {"token"}:
        raise CandidateValidationError("registry token response fields are not exact")
    token = payload["token"]
    if (
        not isinstance(token, str)
        or not 16 <= len(token) <= 16 * 1024
        or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token)
    ):
        raise CandidateValidationError("registry token is malformed")
    return token


def _download_registry_layer(
    transport: HttpTransport,
    *,
    url: str,
    headers: Mapping[str, str],
    path: Path,
    expected_sha256: str,
    expected_size: int,
    deadline: float,
    monotonic: Callable[[], float],
    layer_media_type: str = LAYER_MEDIA_TYPE,
) -> None:
    if path.exists() or path.is_symlink():
        raise CandidateValidationError("layer output already exists")
    response, expected_url, require_digest_header = _open_blob_response(
        transport,
        url=url,
        headers=headers,
        deadline=deadline,
        monotonic=monotonic,
    )
    descriptor: int | None = None
    created = False
    try:
        content_length = _response_prelude(
            response,
            expected_url=expected_url,
            maximum_bytes=MAX_LAYER_BYTES,
            content_types={"application/octet-stream", layer_media_type},
            expected_digest=(
                "sha256:" + expected_sha256 if require_digest_header else None
            ),
        )
        if content_length != expected_size:
            raise CandidateValidationError(
                "layer response size differs from its descriptor"
            )
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
        )
        created = True
        digest = hashlib.sha256()
        observed = 0
        while True:
            if monotonic() >= deadline:
                raise CandidateValidationError("registry fetch exceeded its time bound")
            chunk = response.read(min(1024 * 1024, expected_size + 1 - observed))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise CandidateValidationError("layer response yielded non-bytes")
            observed += len(chunk)
            if observed > expected_size:
                raise CandidateValidationError("layer response exceeds its descriptor")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                count = os.write(descriptor, chunk[offset:])
                if count <= 0:
                    raise CandidateValidationError("layer write made no progress")
                offset += count
        if observed != expected_size or digest.hexdigest() != expected_sha256:
            raise CandidateValidationError(
                "layer response bytes differ from its descriptor"
            )
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.close(descriptor)
        descriptor = None
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise
    finally:
        response.close()


def _require_empty_private_output(path: Path) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError("fetch output directory is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != path
        or next(path.iterdir(), None) is not None
    ):
        raise CandidateValidationError(
            "fetch output directory is not empty and private"
        )


def run_fetch(
    *,
    registry: str,
    repository: str,
    reference: str,
    output_dir: Path,
    transport: HttpTransport | None = None,
    now: datetime | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    invocation_id: str,
    component_id: str = "trivy-db",
) -> dict[str, Any]:
    """Fetch and extract the one fixed Trivy DB OCI artifact."""

    profile = candidate_profile(component_id)
    if (registry, repository, reference) != (
        TRIVY_DB_REGISTRY,
        profile.repository,
        profile.reference,
    ):
        raise CandidateValidationError("registry source is not the fixed Trivy DB ref")
    invocation = _require_invocation_id(invocation_id)
    _require_empty_private_output(output_dir)
    http = transport or DirectHttpsTransport()
    deadline = monotonic() + MAX_FETCH_SECONDS
    token_raw = _request_registry_bytes(
        http,
        url=profile.token_url,
        headers=_registry_headers(token=None, accept="application/json"),
        maximum_bytes=MAX_TOKEN_BYTES,
        content_types={"application/json"},
        expected_digest=None,
        deadline=deadline,
        monotonic=monotonic,
    )
    token = _parse_registry_token(token_raw)
    manifest_base = f"https://ghcr.io/v2/{profile.repository}/manifests/"
    tag_url = manifest_base + profile.reference
    tag_headers = _registry_headers(token=token, accept=MANIFEST_MEDIA_TYPE)
    tag_response = _open_fixed_response(
        http,
        url=tag_url,
        headers=tag_headers,
        deadline=deadline,
        monotonic=monotonic,
    )
    try:
        tag_digest_header = _single_header(
            tag_response.headers, "Docker-Content-Digest"
        )
        tag_body = _read_registry_body(
            tag_response,
            expected_url=tag_url,
            maximum_bytes=MAX_MANIFEST_BYTES,
            content_types={MANIFEST_MEDIA_TYPE},
            expected_digest=tag_digest_header,
            deadline=deadline,
            monotonic=monotonic,
        )
    finally:
        tag_response.close()
    tag_digest = _normalize_digest_header(
        tag_digest_header, label="tag response digest"
    )
    digest_url = manifest_base + tag_digest
    digest_response = _open_fixed_response(
        http,
        url=digest_url,
        headers=tag_headers,
        deadline=deadline,
        monotonic=monotonic,
    )
    try:
        digest_digest_header = _single_header(
            digest_response.headers, "Docker-Content-Digest"
        )
        digest_body = _read_registry_body(
            digest_response,
            expected_url=digest_url,
            maximum_bytes=MAX_MANIFEST_BYTES,
            content_types={MANIFEST_MEDIA_TYPE},
            expected_digest=digest_digest_header,
            deadline=deadline,
            monotonic=monotonic,
        )
    finally:
        digest_response.close()
    manifest = validate_manifest_pair(
        tag_body=tag_body,
        tag_digest_header=tag_digest_header,
        digest_body=digest_body,
        digest_digest_header=digest_digest_header,
        component_id=component_id,
    )
    blob_base = f"https://ghcr.io/v2/{profile.repository}/blobs/sha256:"
    config_url = blob_base + EMPTY_CONFIG_DIGEST.removeprefix("sha256:")
    config_body = _request_registry_bytes(
        http,
        url=config_url,
        headers=_registry_headers(token=token, accept=EMPTY_CONFIG_MEDIA_TYPE),
        maximum_bytes=MAX_CONFIG_BYTES,
        content_types={"application/octet-stream", EMPTY_CONFIG_MEDIA_TYPE},
        expected_digest=EMPTY_CONFIG_DIGEST,
        deadline=deadline,
        monotonic=monotonic,
        allow_blob_redirect=True,
    )
    if config_body != EMPTY_CONFIG_BYTES:
        raise CandidateValidationError("OCI empty config bytes differ")
    layer_url = blob_base + manifest.layer_digest
    layer_path = output_dir / "layer.tar.gz"
    _download_registry_layer(
        http,
        url=layer_url,
        headers=_registry_headers(token=token, accept=profile.layer_media_type),
        path=layer_path,
        expected_sha256=manifest.layer_digest,
        expected_size=manifest.layer_size_bytes,
        deadline=deadline,
        monotonic=monotonic,
        layer_media_type=profile.layer_media_type,
    )
    destination = output_dir / "candidate-db"
    records = extract_layer_tar_gz(
        layer_path,
        destination,
        expected_sha256=manifest.layer_digest,
        expected_size_bytes=manifest.layer_size_bytes,
    )
    metadata_records = [item for item in records if item.path == "metadata.json"]
    if len(metadata_records) != 1:
        raise CandidateValidationError("candidate requires one root metadata.json")
    metadata_raw = _bounded_regular_bytes(
        destination / "metadata.json",
        maximum_bytes=MAX_METADATA_BYTES,
        label="Trivy DB metadata",
    )
    moment = now or datetime.now(UTC)
    metadata = validate_metadata_bytes(
        metadata_raw,
        now=moment,
        maximum_age_seconds=profile.maximum_age_seconds,
        minimum_remaining_seconds=MINIMUM_REMAINING_SECONDS,
        expected_version=profile.metadata_version,
        maximum_update_interval_seconds=profile.maximum_update_interval_seconds,
    )
    all_tree_sha256 = canonical_tree_sha256(records)
    receipt = _seal_receipt(
        {
            "schema": f"{profile.receipt_prefix}-fetch/v1",
            "invocation_id": invocation,
            "source": {
                "discovery_ref": profile.discovery_ref,
                "token_endpoint": profile.token_url,
            },
            "oci": {
                "manifest_sha256": manifest.manifest_digest,
                "created_at": manifest.created_at,
                "layer_sha256": manifest.layer_digest,
                "layer_size_bytes": manifest.layer_size_bytes,
                "config_sha256": EMPTY_CONFIG_DIGEST.removeprefix("sha256:"),
            },
            "metadata": {
                "updated_at": metadata.updated_at,
                "next_update": metadata.next_update,
                "downloaded_at": metadata.downloaded_at,
                "observed_at": metadata.observed_at,
                "size_bytes": metadata.size_bytes,
                "sha256": metadata.sha256,
                "maximum_age_seconds": metadata.maximum_age_seconds,
                "minimum_remaining_seconds": metadata.minimum_remaining_seconds,
            },
            "installed_records": [item.model_dump(mode="json") for item in records],
            "installed_tree": {
                "hash_algorithm": CANONICAL_TREE_HASH_ALGORITHM,
                "sha256": all_tree_sha256,
                "file_count": len(records),
                "size_bytes": sum(item.size_bytes for item in records),
            },
        }
    )
    write_private_evidence_receipt(
        output_dir / "fetch-receipt.json",
        receipt,
        schema=f"{profile.receipt_prefix}-fetch/v1",
        fields={
            "schema",
            "invocation_id",
            "source",
            "oci",
            "metadata",
            "installed_records",
            "installed_tree",
        },
    )
    return receipt


def _trivy_canary_command(
    *,
    candidate_db: Path,
    fixture: Path,
    output: Path,
    component_id: str = "trivy-db",
) -> tuple[str, ...]:
    profile = candidate_profile(component_id)
    if candidate_db.name != profile.cache_child:
        raise CandidateValidationError("candidate DB must be the exact cache child")
    common = (
        TRIVY_EXECUTABLE_PATH,
        "fs" if profile.component_id == "trivy-db" else "rootfs",
        "--quiet",
        "--cache-dir",
        str(candidate_db.parent),
        "--format",
        "json",
        "--output",
        str(output),
        "--scanners",
        "vuln",
    )
    java = (
        ("--pkg-types", "library", "--parallel", "1")
        if profile.component_id == "trivy-java-db"
        else ()
    )
    return common + java + (
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--disable-telemetry",
        "--skip-version-check",
        str(fixture),
    )


def _trivy_canary_command_sha256(
    canary_id: str, component_id: str = "trivy-db"
) -> str:
    profile = candidate_profile(component_id)
    if canary_id not in profile.canary_ids:
        raise CandidateValidationError("canary command identity is unsupported")
    fixture = {
        profile.canary_ids[0]: (
            "/run/kodesec-review/positive"
            if profile.component_id == "trivy-db"
            else "/usr/local/share/kodesec/canaries/trivy/java/"
            "log4j-core-2.14.1.jar"
        ),
        profile.canary_ids[1]: "/run/kodesec-review/zero",
    }[canary_id]
    contract = (
        TRIVY_EXECUTABLE_PATH,
        "fs" if profile.component_id == "trivy-db" else "rootfs",
        "--quiet",
        "--cache-dir",
        "/run/kodesec-review/candidate-cache",
        "--format",
        "json",
        "--output",
        "$PRIVATE_RESULT",
        "--scanners",
        "vuln",
    ) + (
        ("--pkg-types", "library", "--parallel", "1")
        if profile.component_id == "trivy-java-db"
        else ()
    ) + (
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--disable-telemetry",
        "--skip-version-check",
        fixture,
    )
    return hashlib.sha256(canonical_json_bytes(list(contract))).hexdigest()


def _validate_trivy_canary_envelope(
    payload: Mapping[str, Any],
    *,
    expected_artifact_name: str | None,
) -> None:
    trivy = payload.get("Trivy")
    if (
        not isinstance(trivy, dict)
        or set(trivy) != {"Version"}
        or trivy.get("Version") != TRIVY_VERSION
    ):
        raise CandidateValidationError("Trivy canary version is not exact")
    report_id = payload.get("ReportID")
    if not isinstance(report_id, str) or not _UUID7.fullmatch(report_id):
        raise CandidateValidationError("Trivy canary report ID is malformed")
    _parse_utc(payload.get("CreatedAt"), label="Trivy canary CreatedAt")
    artifact_name = payload.get("ArtifactName")
    if (
        not isinstance(expected_artifact_name, str)
        or not 0 < len(expected_artifact_name) <= 4096
        or _CONTROL.search(expected_artifact_name)
        or not isinstance(artifact_name, str)
        or artifact_name != expected_artifact_name
    ):
        raise CandidateValidationError("Trivy canary artifact name is not exact")
    if payload.get("ArtifactType") != "filesystem":
        raise CandidateValidationError("Trivy canary artifact type is not exact")


def parse_trivy_canary_json(
    raw: bytes,
    *,
    canary_id: str | None = None,
    expected_artifact_name: str | None = None,
    component_id: str = "trivy-db",
) -> tuple[int, list[str]]:
    profile = candidate_profile(component_id)
    payload = strict_json_object(
        raw, label="Trivy canary output", maximum_bytes=MAX_CANARY_JSON_BYTES
    )
    schema_version = payload.get("SchemaVersion")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 2
    ):
        raise CandidateValidationError("Trivy canary schema version is not exact")
    _validate_trivy_canary_envelope(
        payload, expected_artifact_name=expected_artifact_name
    )
    results = payload.get("Results")
    if "Results" not in payload or results is None:
        # Trivy 0.73.0 omits Results for this exact zero-result filesystem
        # report.  Admit that shape (and its explicit-null equivalent) only
        # after binding the complete envelope to the invoked fixture.
        if canary_id != profile.canary_ids[1]:
            raise CandidateValidationError(
                "Trivy empty canary result is not allowed for this fixture"
            )
        results = []
    elif not isinstance(results, list):
        raise CandidateValidationError("Trivy canary Results is not a list")
    identifiers: list[str] = []
    result_count = 0
    for result in results:
        if not isinstance(result, dict):
            raise CandidateValidationError("Trivy canary result is not an object")
        vulnerabilities = result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise CandidateValidationError("Trivy vulnerabilities is not a list")
        for vulnerability in vulnerabilities:
            identifier = (
                vulnerability.get("VulnerabilityID")
                if isinstance(vulnerability, dict)
                else None
            )
            if (
                not isinstance(identifier, str)
                or not 0 < len(identifier) <= 256
                or _CONTROL.search(identifier)
            ):
                raise CandidateValidationError("Trivy vulnerability ID is malformed")
            identifiers.append(identifier)
            result_count += 1
            if result_count > 10_000:
                raise CandidateValidationError(
                    "Trivy vulnerability count exceeds its bound"
                )
    unique_identifiers = sorted(set(identifiers))
    if len(unique_identifiers) > MAX_CANARY_IDS:
        raise CandidateValidationError(
            "Trivy unique vulnerability IDs exceed their bound"
        )
    return result_count, unique_identifiers


def _new_result_file(path: Path) -> tuple[int, int, int]:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
        0o600,
    )
    try:
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return (metadata.st_dev, metadata.st_ino, metadata.st_nlink)


def _read_result_file(path: Path, identity: tuple[int, int, int]) -> bytes:
    raw = _bounded_regular_bytes(
        path,
        maximum_bytes=MAX_CANARY_JSON_BYTES,
        label="Trivy canary output",
    )
    metadata = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != identity:
        raise CandidateValidationError("Trivy canary output identity changed")
    return raw


def run_canary(
    *,
    current_lock: Path,
    candidate_db: Path,
    positive_fixture: Path,
    zero_fixture: Path,
    scratch_root: Path,
    runner: CommandRunner = run_bounded_command,
    invocation_id: str,
    component_id: str = "trivy-db",
    support_trivy_db: Path | None = None,
) -> dict[str, Any]:
    """Run the exact positive and zero Trivy scans against a read-only DB."""

    with _inner_failure_phase("canary", "input"):
        profile = candidate_profile(component_id)
        if candidate_db.name != profile.cache_child:
            raise CandidateValidationError(
                "candidate DB must be the exact cache child"
            )
        invocation = _require_invocation_id(invocation_id)
        current, canaries = (
            _trivy_requirement_contract(current_lock)
            if component_id == "trivy-db"
            else _trivy_requirement_contract(current_lock, component_id)
        )
        if profile.component_id == "trivy-java-db":
            if support_trivy_db is None or support_trivy_db.name != "db":
                raise CandidateValidationError(
                    "Java canary requires the exact Trivy OS DB cache child"
                )
        elif support_trivy_db is not None:
            raise CandidateValidationError("OS DB canary forbids a support DB")
    with _inner_failure_phase("canary", "fixtures"):
        fixture_by_id = {
            profile.canary_ids[0]: positive_fixture,
            profile.canary_ids[1]: zero_fixture,
        }
        for canary in canaries:
            _verify_fixture(
                fixture_by_id[canary["id"]],
                canary["fixture_sha256"],
                fixture_kind=canary["fixture_kind"],
                label=canary["id"],
            )
    with _inner_failure_phase("canary", "candidate_tree"):
        support_tree = (
            _validated_trivy_support_tree(current_lock, support_trivy_db)
            if support_trivy_db is not None
            else None
        )
        try:
            candidate_tree = collect_canonical_tree(
                candidate_db,
                require_immutable=True,
                maximum_files=MAX_INSTALLED_FILES,
                maximum_bytes=MAX_INSTALLED_BYTES,
            )
        except CacheValidationError as exc:
            raise CandidateValidationError(
                "candidate DB tree is unsafe or mutable"
            ) from exc
        if not any(item.path == "metadata.json" for item in candidate_tree.files):
            raise CandidateValidationError("candidate DB metadata is missing")
    observations: list[dict[str, Any]] = []
    with _private_scratch(scratch_root, prefix="canary-") as temporary_name:
        scratch = Path(temporary_name)
        for canary in canaries:
            canary_scratch = scratch / canary["id"]
            canary_scratch.mkdir(mode=0o700)
            environment = _sterile_environment(canary_scratch)
            output = canary_scratch / "result.json"
            with _inner_failure_phase("canary", "output"):
                output_identity = _new_result_file(output)
            with _inner_failure_phase("canary", "command"):
                command = _trivy_canary_command(
                    candidate_db=candidate_db,
                    fixture=fixture_by_id[canary["id"]],
                    output=output,
                    component_id=component_id,
                )
                result = runner(
                    command,
                    cwd=canary_scratch,
                    environment=environment,
                    timeout_seconds=MAX_COMMAND_SECONDS,
                    result_path=output,
                    maximum_result_bytes=MAX_CANARY_JSON_BYTES,
                )
                if result.returncode != 0:
                    raise CandidateValidationError(
                        "Trivy canary did not exit successfully"
                    )
            with _inner_failure_phase("canary", "output"):
                output_raw = _read_result_file(output, output_identity)
                result_count, identifiers = parse_trivy_canary_json(
                    output_raw,
                    canary_id=canary["id"],
                    expected_artifact_name=str(fixture_by_id[canary["id"]]),
                    component_id=component_id,
                )
            observation = {
                "canary_id": canary["id"],
                "fixture_sha256": canary["fixture_sha256"],
                "exit_code": result.returncode,
                "result_count": result_count,
                "ids": identifiers,
            }
            # Reuse the final proposal's semantic admission rules now so a
            # malformed positive/zero result never becomes an inner receipt.
            with _inner_failure_phase("canary", "semantics"):
                if canary["id"] == profile.canary_ids[0] and (
                    result_count <= 0 or not identifiers
                ):
                    raise CandidateValidationError(
                        "positive canary produced no vulnerabilities"
                    )
                if canary["id"] == profile.canary_ids[1] and (
                    result_count != 0 or identifiers
                ):
                    raise CandidateValidationError(
                        "zero canary produced vulnerability evidence"
                    )
            observation.update(
                {
                    "command_sha256": _trivy_canary_command_sha256(
                        canary["id"], component_id
                    ),
                    "result_sha256": hashlib.sha256(output_raw).hexdigest(),
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                }
            )
            observations.append(observation)
    observations.sort(key=lambda item: item["canary_id"])
    receipt = {
        "schema": f"{profile.receipt_prefix}-canary/v1",
        "invocation_id": invocation,
        "current_lock_sha256": current.sha256,
        "candidate_tree": {
            "hash_algorithm": candidate_tree.algorithm,
            "sha256": candidate_tree.sha256,
            "file_count": candidate_tree.file_count,
            "size_bytes": candidate_tree.size_bytes,
        },
        "canaries": observations,
    }
    if support_tree is not None:
        receipt["support_trivy_db"] = {
            "hash_algorithm": support_tree.algorithm,
            "sha256": support_tree.sha256,
            "file_count": support_tree.file_count,
            "size_bytes": support_tree.size_bytes,
            "installed_content": installed_content_evidence(support_tree.files),
        }
    return _seal_receipt(receipt)


def validate_preflight_receipt(
    raw: bytes, component_id: str = "trivy-db"
) -> dict[str, Any]:
    profile = candidate_profile(component_id)
    value = _parse_sealed_receipt(
        raw,
        label="preflight receipt",
        schema=f"{profile.receipt_prefix}-preflight/v1",
        fields={
            "schema",
            "invocation_id",
            "current_lock_sha256",
            "baked_lock_sha256",
            "scanner",
            "current_canaries",
        },
    )
    _require_invocation_id(value["invocation_id"])
    if (
        not isinstance(value["current_lock_sha256"], str)
        or not _SHA256.fullmatch(value["current_lock_sha256"])
        or value["baked_lock_sha256"] != value["current_lock_sha256"]
    ):
        raise CandidateValidationError("preflight lock identity is invalid")
    scanner = value["scanner"]
    if not isinstance(scanner, dict) or set(scanner) != {
        "architecture",
        "trivy_version",
        "trivy_executable_path",
        "trivy_executable_sha256",
        "tool_manifest_sha256",
        "implementation_bundle",
    }:
        raise CandidateValidationError("preflight scanner fields are not exact")
    if (
        scanner["architecture"] not in {"amd64", "arm64"}
        or scanner["trivy_version"] != TRIVY_VERSION
        or scanner["trivy_executable_path"] != TRIVY_EXECUTABLE_PATH
        or not isinstance(scanner["trivy_executable_sha256"], str)
        or not _SHA256.fullmatch(scanner["trivy_executable_sha256"])
        or not isinstance(scanner["tool_manifest_sha256"], str)
        or not _SHA256.fullmatch(scanner["tool_manifest_sha256"])
    ):
        raise CandidateValidationError("preflight scanner identity is invalid")
    _validate_implementation_bundle(scanner["implementation_bundle"])
    _validate_current_canaries(value["current_canaries"], component_id)
    return value


def _validate_implementation_bundle(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "hash_algorithm",
        "sha256",
        "file_count",
        "size_bytes",
        "files",
    }:
        raise CandidateValidationError("implementation bundle fields are not exact")
    files = value["files"]
    if (
        value["hash_algorithm"] != "kodesec-python-bundle-v1"
        or not isinstance(value["sha256"], str)
        or not _SHA256.fullmatch(value["sha256"])
        or isinstance(value["file_count"], bool)
        or not isinstance(value["file_count"], int)
        or not 1 <= value["file_count"] <= MAX_IMPLEMENTATION_FILES
        or not isinstance(files, list)
        or len(files) != value["file_count"]
        or isinstance(value["size_bytes"], bool)
        or not isinstance(value["size_bytes"], int)
        or not 1 <= value["size_bytes"] <= MAX_IMPLEMENTATION_BYTES
    ):
        raise CandidateValidationError("implementation bundle identity is malformed")
    names: list[str] = []
    total = 0
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size_bytes", "sha256"}
            or not isinstance(item["path"], str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", item["path"])
            or isinstance(item["size_bytes"], bool)
            or not isinstance(item["size_bytes"], int)
            or not 0 < item["size_bytes"] <= MAX_IMPLEMENTATION_BYTES
            or not isinstance(item["sha256"], str)
            or not _SHA256.fullmatch(item["sha256"])
        ):
            raise CandidateValidationError("implementation bundle file is malformed")
        names.append(item["path"])
        total += item["size_bytes"]
    if (
        names != sorted(set(names), key=lambda item: item.encode("utf-8"))
        or total != value["size_bytes"]
        or value["sha256"] != hashlib.sha256(canonical_json_bytes(files)).hexdigest()
        or not {
            "trivy_db_lock_candidate.py",
            "cache_manifest.py",
            "tools.py",
            "updater.py",
        }.issubset(names)
    ):
        raise CandidateValidationError("implementation bundle contents differ")
    return value


def _validate_current_canaries(
    value: Any, component_id: str = "trivy-db"
) -> list[dict[str, Any]]:
    profile = candidate_profile(component_id)
    if not isinstance(value, list) or len(value) != 2:
        raise CandidateValidationError("current canary receipt list is not exact")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "fixture_path",
            "fixture_kind",
            "fixture_hash_algorithm",
            "fixture_sha256",
        }:
            raise CandidateValidationError(
                "current canary receipt fields are not exact"
            )
        if (
            item["id"] not in profile.canary_ids
            or item["fixture_kind"] not in {"file", "tree"}
            or item["fixture_hash_algorithm"]
            != (
                "sha256-file-v1"
                if item["fixture_kind"] == "file"
                else CANONICAL_TREE_HASH_ALGORITHM
            )
            or not isinstance(item["fixture_sha256"], str)
            or not _SHA256.fullmatch(item["fixture_sha256"])
        ):
            raise CandidateValidationError("current canary receipt is malformed")
        normalized.append(item)
    normalized.sort(key=lambda item: item["id"])
    if (
        [item["id"] for item in normalized] != list(profile.canary_ids)
        or tuple(item["fixture_path"] for item in normalized) != profile.fixture_paths
        or tuple(item["fixture_kind"] for item in normalized) != profile.fixture_kinds
        or value != normalized
    ):
        raise CandidateValidationError("current canary receipt order or paths differ")
    return normalized


def _validate_tree_receipt(value: Any, records: Sequence[CacheFileRecord]) -> None:
    if not isinstance(value, dict) or set(value) != {
        "hash_algorithm",
        "sha256",
        "file_count",
        "size_bytes",
    }:
        raise CandidateValidationError("candidate tree receipt fields are not exact")
    if (
        value["hash_algorithm"] != CANONICAL_TREE_HASH_ALGORITHM
        or value["sha256"] != canonical_tree_sha256(records)
        or value["file_count"] != len(records)
        or value["size_bytes"] != sum(item.size_bytes for item in records)
    ):
        raise CandidateValidationError("candidate tree receipt identity differs")


def validate_fetch_receipt(
    raw: bytes,
    *,
    now: datetime | None = None,
    component_id: str = "trivy-db",
) -> tuple[
    dict[str, Any],
    OciManifestEvidence,
    TrivyMetadataEvidence,
    tuple[CacheFileRecord, ...],
]:
    profile = candidate_profile(component_id)
    value = _parse_sealed_receipt(
        raw,
        label="fetch receipt",
        schema=f"{profile.receipt_prefix}-fetch/v1",
        fields={
            "schema",
            "invocation_id",
            "source",
            "oci",
            "metadata",
            "installed_records",
            "installed_tree",
        },
    )
    _require_invocation_id(value["invocation_id"])
    if value["source"] != {
        "discovery_ref": profile.discovery_ref,
        "token_endpoint": profile.token_url,
    }:
        raise CandidateValidationError("fetch receipt source is not exact")
    oci = value["oci"]
    if not isinstance(oci, dict) or set(oci) != {
        "manifest_sha256",
        "created_at",
        "layer_sha256",
        "layer_size_bytes",
        "config_sha256",
    }:
        raise CandidateValidationError("fetch OCI receipt fields are not exact")
    if (
        not isinstance(oci["manifest_sha256"], str)
        or not _SHA256.fullmatch(oci["manifest_sha256"])
        or not isinstance(oci["layer_sha256"], str)
        or not _SHA256.fullmatch(oci["layer_sha256"])
        or isinstance(oci["layer_size_bytes"], bool)
        or not isinstance(oci["layer_size_bytes"], int)
        or not 0 < oci["layer_size_bytes"] <= profile.maximum_layer_bytes
        or oci["config_sha256"] != EMPTY_CONFIG_DIGEST.removeprefix("sha256:")
    ):
        raise CandidateValidationError("fetch OCI receipt identity is malformed")
    _parse_utc(oci["created_at"], label="OCI created")
    manifest = OciManifestEvidence(
        manifest_digest=oci["manifest_sha256"],
        created_at=oci["created_at"],
        layer_digest=oci["layer_sha256"],
        layer_size_bytes=oci["layer_size_bytes"],
    )
    metadata_value = value["metadata"]
    if not isinstance(metadata_value, dict) or set(metadata_value) != {
        "updated_at",
        "next_update",
        "downloaded_at",
        "observed_at",
        "size_bytes",
        "sha256",
        "maximum_age_seconds",
        "minimum_remaining_seconds",
    }:
        raise CandidateValidationError("fetch metadata receipt fields are not exact")
    if (
        metadata_value["maximum_age_seconds"] != profile.maximum_age_seconds
        or metadata_value["minimum_remaining_seconds"] != MINIMUM_REMAINING_SECONDS
        or metadata_value["downloaded_at"] != RAW_TRIVY_DOWNLOADED_AT
        or isinstance(metadata_value["size_bytes"], bool)
        or not isinstance(metadata_value["size_bytes"], int)
        or not 0 < metadata_value["size_bytes"] <= MAX_METADATA_BYTES
        or not isinstance(metadata_value["sha256"], str)
        or not _SHA256.fullmatch(metadata_value["sha256"])
    ):
        raise CandidateValidationError("fetch metadata receipt identity is malformed")
    updated = _parse_utc(metadata_value["updated_at"], label="Trivy DB UpdatedAt")
    next_update = _parse_utc(metadata_value["next_update"], label="Trivy DB NextUpdate")
    observed = _parse_utc(metadata_value["observed_at"], label="fetch observed_at")
    host_now = now or datetime.now(UTC)
    if host_now.tzinfo is None or host_now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    host_moment = host_now.astimezone(UTC)
    if (
        updated > observed
        or observed - updated > timedelta(seconds=profile.maximum_age_seconds)
        or next_update - updated
        > timedelta(seconds=profile.maximum_update_interval_seconds)
        or observed > host_moment + timedelta(minutes=5)
        or host_moment - observed > timedelta(minutes=5)
        or host_moment - updated > timedelta(seconds=profile.maximum_age_seconds)
        or updated
        + timedelta(seconds=profile.maximum_age_seconds)
        - host_moment
        < timedelta(seconds=MINIMUM_REMAINING_SECONDS)
    ):
        raise CandidateValidationError("fetch metadata receipt is stale or replayed")
    metadata = TrivyMetadataEvidence(
        updated_at=metadata_value["updated_at"],
        next_update=metadata_value["next_update"],
        downloaded_at=metadata_value["downloaded_at"],
        observed_at=metadata_value["observed_at"],
        maximum_age_seconds=metadata_value["maximum_age_seconds"],
        minimum_remaining_seconds=metadata_value["minimum_remaining_seconds"],
        size_bytes=metadata_value["size_bytes"],
        sha256=metadata_value["sha256"],
    )
    raw_records = value["installed_records"]
    if (
        not isinstance(raw_records, list)
        or not 1 <= len(raw_records) <= MAX_INSTALLED_FILES
    ):
        raise CandidateValidationError("fetch installed records are not bounded")
    try:
        records = tuple(CacheFileRecord.model_validate(item) for item in raw_records)
    except ValidationError as exc:
        raise CandidateValidationError("fetch installed record is invalid") from exc
    if list(records) != sorted(records, key=lambda item: item.path.encode("utf-8")):
        raise CandidateValidationError("fetch installed records are not sorted")
    _validate_tree_receipt(value["installed_tree"], records)
    metadata_records = [item for item in records if item.path == "metadata.json"]
    if (
        len(metadata_records) != 1
        or metadata_records[0].size_bytes != metadata.size_bytes
        or metadata_records[0].sha256 != metadata.sha256
    ):
        raise CandidateValidationError(
            "fetch metadata is not bound to its installed record"
        )
    installed_content_evidence(records)
    return value, manifest, metadata, records


def validate_canary_receipt(
    raw: bytes, component_id: str = "trivy-db"
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    profile = candidate_profile(component_id)
    fields = {
        "schema",
        "invocation_id",
        "current_lock_sha256",
        "candidate_tree",
        "canaries",
    }
    if profile.component_id == "trivy-java-db":
        fields.add("support_trivy_db")
    value = _parse_sealed_receipt(
        raw,
        label="canary receipt",
        schema=f"{profile.receipt_prefix}-canary/v1",
        fields=fields,
    )
    _require_invocation_id(value["invocation_id"])
    if not isinstance(value["current_lock_sha256"], str) or not _SHA256.fullmatch(
        value["current_lock_sha256"]
    ):
        raise CandidateValidationError("canary receipt lock identity is malformed")
    tree = value["candidate_tree"]
    if not isinstance(tree, dict) or set(tree) != {
        "hash_algorithm",
        "sha256",
        "file_count",
        "size_bytes",
    }:
        raise CandidateValidationError("canary candidate tree fields are not exact")
    if (
        tree["hash_algorithm"] != CANONICAL_TREE_HASH_ALGORITHM
        or not isinstance(tree["sha256"], str)
        or not _SHA256.fullmatch(tree["sha256"])
        or isinstance(tree["file_count"], bool)
        or not isinstance(tree["file_count"], int)
        or not 1 <= tree["file_count"] <= MAX_INSTALLED_FILES
        or isinstance(tree["size_bytes"], bool)
        or not isinstance(tree["size_bytes"], int)
        or not 1 <= tree["size_bytes"] <= MAX_INSTALLED_BYTES
    ):
        raise CandidateValidationError("canary candidate tree identity is malformed")
    if profile.component_id == "trivy-java-db":
        support = value["support_trivy_db"]
        if not isinstance(support, dict) or set(support) != {
            "hash_algorithm",
            "sha256",
            "file_count",
            "size_bytes",
            "installed_content",
        }:
            raise CandidateValidationError("canary support DB fields are not exact")
        installed = support["installed_content"]
        if (
            support["hash_algorithm"] != CANONICAL_TREE_HASH_ALGORITHM
            or not isinstance(support["sha256"], str)
            or not _SHA256.fullmatch(support["sha256"])
            or isinstance(support["file_count"], bool)
            or not isinstance(support["file_count"], int)
            or not 2 <= support["file_count"] <= MAX_INSTALLED_FILES
            or isinstance(support["size_bytes"], bool)
            or not isinstance(support["size_bytes"], int)
            or not 1 <= support["size_bytes"] <= MAX_INSTALLED_BYTES
            or not isinstance(installed, dict)
            or set(installed)
            != {
                "hash_algorithm",
                "sha256",
                "file_count",
                "size_bytes",
                "volatile_paths",
            }
            or installed["hash_algorithm"] != CANONICAL_TREE_HASH_ALGORITHM
            or not isinstance(installed["sha256"], str)
            or not _SHA256.fullmatch(installed["sha256"])
            or isinstance(installed["file_count"], bool)
            or not isinstance(installed["file_count"], int)
            or installed["file_count"] != support["file_count"] - 1
            or isinstance(installed["size_bytes"], bool)
            or not isinstance(installed["size_bytes"], int)
            or not 1 <= installed["size_bytes"] < support["size_bytes"]
            or installed["volatile_paths"] != ["metadata.json"]
        ):
            raise CandidateValidationError("canary support DB identity is malformed")
    raw_canaries = value["canaries"]
    if not isinstance(raw_canaries, list) or len(raw_canaries) != 2:
        raise CandidateValidationError("canary observations are not exact")
    proposal_canaries: list[dict[str, Any]] = []
    seen: list[str] = []
    for item in raw_canaries:
        if not isinstance(item, dict) or set(item) != {
            "canary_id",
            "fixture_sha256",
            "exit_code",
            "result_count",
            "ids",
            "command_sha256",
            "result_sha256",
            "stdout_sha256",
            "stderr_sha256",
        }:
            raise CandidateValidationError("canary observation fields are not exact")
        seen.append(item["canary_id"] if isinstance(item["canary_id"], str) else "")
        ids = item["ids"]
        if (
            item["canary_id"] not in profile.canary_ids
            or not isinstance(item["fixture_sha256"], str)
            or not _SHA256.fullmatch(item["fixture_sha256"])
            or isinstance(item["exit_code"], bool)
            or not isinstance(item["exit_code"], int)
            or item["exit_code"] != 0
            or isinstance(item["result_count"], bool)
            or not isinstance(item["result_count"], int)
            or not 0 <= item["result_count"] <= 10_000
            or not isinstance(ids, list)
            or ids != sorted(set(ids))
            or len(ids) > MAX_CANARY_IDS
            or not all(
                isinstance(identifier, str)
                and 0 < len(identifier) <= 256
                and not _CONTROL.search(identifier)
                for identifier in ids
            )
            or any(
                not isinstance(item[key], str) or not _SHA256.fullmatch(item[key])
                for key in (
                    "command_sha256",
                    "result_sha256",
                    "stdout_sha256",
                    "stderr_sha256",
                )
            )
        ):
            raise CandidateValidationError("canary observation identity is malformed")
        if item["command_sha256"] != _trivy_canary_command_sha256(
            item["canary_id"], component_id
        ):
            raise CandidateValidationError("canary command contract identity differs")
        if len(ids) > item["result_count"]:
            raise CandidateValidationError("canary unique IDs exceed its result count")
        if item["canary_id"] == profile.canary_ids[0] and (
            item["result_count"] <= 0 or not ids
        ):
            raise CandidateValidationError(
                "positive canary produced no vulnerabilities"
            )
        if item["canary_id"] == profile.canary_ids[1] and (
            item["result_count"] != 0 or ids
        ):
            raise CandidateValidationError(
                "zero canary produced vulnerability evidence"
            )
        proposal_canaries.append(
            {
                key: item[key]
                for key in (
                    "canary_id",
                    "fixture_sha256",
                    "exit_code",
                    "result_count",
                    "ids",
                )
            }
        )
    if seen != list(profile.canary_ids):
        raise CandidateValidationError("canary observations are not sorted or unique")
    return value, proposal_canaries


def build_proposal_receipt(
    *,
    current_lock_sha256: str,
    baked_lock_sha256: str,
    image_id: str,
    architecture: str,
    trivy_version: str,
    trivy_executable_path: str,
    trivy_executable_sha256: str,
    tool_manifest_sha256: str,
    implementation_bundle: Mapping[str, Any],
    host_cli_sha256: str,
    host_execution_identity: Mapping[str, Any],
    evidence_receipts: Mapping[str, Mapping[str, Any]],
    build_receipt: Mapping[str, Any],
    manifest: OciManifestEvidence,
    metadata: TrivyMetadataEvidence,
    installed_records: Iterable[CacheFileRecord],
    current_canaries: Iterable[Mapping[str, Any]],
    canaries: Iterable[Mapping[str, Any]],
    component_id: str = "trivy-db",
) -> dict[str, Any]:
    """Return a canonical, non-authoritative proposed replacement receipt."""

    profile = candidate_profile(component_id)
    for label, digest in (
        ("current lock", current_lock_sha256),
        ("baked lock", baked_lock_sha256),
        ("Trivy executable", trivy_executable_sha256),
        ("tool manifest", tool_manifest_sha256),
        ("host candidate CLI", host_cli_sha256),
    ):
        if not _SHA256.fullmatch(digest):
            raise CandidateValidationError(f"{label} SHA-256 is malformed")
    if baked_lock_sha256 != current_lock_sha256:
        raise CandidateValidationError("repository and baked scanner locks differ")
    if not _IMAGE_ID.fullmatch(image_id):
        raise CandidateValidationError("scanner image ID is malformed")
    if architecture not in {"amd64", "arm64"}:
        raise CandidateValidationError("scanner image architecture is unsupported")
    if trivy_version != "0.73.0":
        raise CandidateValidationError("scanner Trivy version differs from the lock")
    if trivy_executable_path != "/usr/local/bin/trivy":
        raise CandidateValidationError("scanner Trivy executable path is not exact")
    normalized_bundle = _validate_implementation_bundle(dict(implementation_bundle))
    if set(host_execution_identity) != {"uid", "gid"} or any(
        isinstance(host_execution_identity[key], bool)
        or not isinstance(host_execution_identity[key], int)
        or not 1 <= host_execution_identity[key] <= (1 << 31) - 1
        for key in ("uid", "gid")
    ):
        raise CandidateValidationError("host execution identity is invalid")
    expected_evidence_schemas = {
        "preflight": f"{profile.receipt_prefix}-preflight/v1",
        "fetch": f"{profile.receipt_prefix}-fetch/v1",
        "canary": f"{profile.receipt_prefix}-canary/v1",
    }
    if set(evidence_receipts) != set(expected_evidence_schemas):
        raise CandidateValidationError("inner evidence receipt set is not exact")
    normalized_evidence: dict[str, dict[str, str]] = {}
    for label, schema in expected_evidence_schemas.items():
        identity = evidence_receipts[label]
        if (
            not isinstance(identity, Mapping)
            or set(identity) != {"schema", "receipt_sha256"}
            or identity["schema"] != schema
            or not isinstance(identity["receipt_sha256"], str)
            or not _SHA256.fullmatch(identity["receipt_sha256"])
        ):
            raise CandidateValidationError("inner evidence receipt identity is invalid")
        normalized_evidence[label] = dict(identity)
    if (
        not isinstance(build_receipt, Mapping)
        or set(build_receipt) != {"schema", "receipt_sha256"}
        or build_receipt["schema"] != "kodesec.scanner-build-receipt/v2"
        or not isinstance(build_receipt["receipt_sha256"], str)
        or not _SHA256.fullmatch(build_receipt["receipt_sha256"])
    ):
        raise CandidateValidationError("scanner build receipt identity is invalid")
    normalized_build_receipt = dict(build_receipt)
    if (
        not _SHA256.fullmatch(manifest.manifest_digest)
        or not _SHA256.fullmatch(manifest.layer_digest)
        or not 0 < manifest.layer_size_bytes <= profile.maximum_layer_bytes
    ):
        raise CandidateValidationError("OCI manifest evidence is malformed")
    _parse_utc(manifest.created_at, label="OCI created")
    metadata_updated = _parse_utc(metadata.updated_at, label="Trivy DB UpdatedAt")
    metadata_next = _parse_utc(metadata.next_update, label="Trivy DB NextUpdate")
    metadata_observed = _parse_utc(metadata.observed_at, label="fetch observed_at")
    if (
        metadata_next <= metadata_updated
        or metadata_updated > metadata_observed
        or metadata.downloaded_at != RAW_TRIVY_DOWNLOADED_AT
        or metadata_next - metadata_updated
        > timedelta(seconds=profile.maximum_update_interval_seconds)
        or metadata_observed - metadata_updated
        > timedelta(seconds=metadata.maximum_age_seconds)
        or metadata_updated
        + timedelta(seconds=metadata.maximum_age_seconds)
        - metadata_observed
        < timedelta(seconds=metadata.minimum_remaining_seconds)
        or metadata.maximum_age_seconds != profile.maximum_age_seconds
        or metadata.minimum_remaining_seconds != MINIMUM_REMAINING_SECONDS
        or not 0 < metadata.size_bytes <= MAX_METADATA_BYTES
        or not _SHA256.fullmatch(metadata.sha256)
    ):
        raise CandidateValidationError("Trivy DB metadata interval is invalid")
    records = tuple(installed_records)
    metadata_records = [item for item in records if item.path == "metadata.json"]
    if (
        len(metadata_records) != 1
        or metadata_records[0].size_bytes != metadata.size_bytes
        or metadata_records[0].sha256 != metadata.sha256
    ):
        raise CandidateValidationError(
            "metadata bytes are not bound to the installed tree"
        )
    installed_content = installed_content_evidence(records)
    installed_size_bytes = sum(item.size_bytes for item in records)
    if installed_size_bytes <= 0 or installed_size_bytes > MAX_INSTALLED_BYTES:
        raise CandidateValidationError("installed DB size is outside its bound")

    current_by_id: dict[str, Mapping[str, Any]] = {}
    expected_current_keys = {
        "id",
        "fixture_path",
        "fixture_kind",
        "fixture_hash_algorithm",
        "fixture_sha256",
    }
    for current in current_canaries:
        if set(current) != expected_current_keys or not isinstance(current["id"], str):
            raise CandidateValidationError(
                "current canary contract fields are not exact"
            )
        if current["id"] in current_by_id:
            raise CandidateValidationError("current canary identities are not unique")
        if (
            current["fixture_kind"] not in {"file", "tree"}
            or current["fixture_hash_algorithm"]
            != (
                "sha256-file-v1"
                if current["fixture_kind"] == "file"
                else CANONICAL_TREE_HASH_ALGORITHM
            )
            or not isinstance(current["fixture_path"], str)
            or not isinstance(current["fixture_sha256"], str)
            or not _SHA256.fullmatch(current["fixture_sha256"])
        ):
            raise CandidateValidationError(
                "current canary fixture contract is malformed"
            )
        current_by_id[current["id"]] = current
    if set(current_by_id) != set(profile.canary_ids):
        raise CandidateValidationError("current lock lacks the exact Trivy DB canaries")
    if tuple(current_by_id[item]["fixture_path"] for item in profile.canary_ids) != (
        profile.fixture_paths
    ):
        raise CandidateValidationError("current canary fixture paths are not exact")
    normalized_canaries: list[dict[str, Any]] = []
    for item in canaries:
        required = {
            "canary_id",
            "fixture_sha256",
            "exit_code",
            "result_count",
            "ids",
        }
        if set(item) != required:
            raise CandidateValidationError("canary evidence fields are not exact")
        if not isinstance(item["canary_id"], str):
            raise CandidateValidationError("canary identity is malformed")
        ids = item["ids"]
        if (
            not isinstance(ids, list)
            or ids != sorted(set(ids))
            or len(ids) > MAX_CANARY_IDS
            or not all(
                isinstance(value, str)
                and 0 < len(value) <= 256
                and not _CONTROL.search(value)
                for value in ids
            )
        ):
            raise CandidateValidationError(
                "canary identifiers are not sorted and unique"
            )
        current = current_by_id.get(item["canary_id"])
        if (
            current is None
            or not isinstance(item["fixture_sha256"], str)
            or item["fixture_sha256"] != current["fixture_sha256"]
        ):
            raise CandidateValidationError(
                "canary fixture differs from the current lock"
            )
        if (
            isinstance(item["exit_code"], bool)
            or not isinstance(item["exit_code"], int)
            or not 0 <= item["exit_code"] <= 255
            or isinstance(item["result_count"], bool)
            or not isinstance(item["result_count"], int)
            or not len(ids) <= item["result_count"] <= 10_000
        ):
            raise CandidateValidationError("canary counts or exit code are invalid")
        if item["exit_code"] != 0:
            raise CandidateValidationError("Trivy canary must exit successfully")
        if item["canary_id"] == profile.canary_ids[0] and (
            item["result_count"] <= 0 or not ids
        ):
            raise CandidateValidationError(
                "positive canary produced no vulnerabilities"
            )
        if item["canary_id"] == profile.canary_ids[1] and (
            item["result_count"] != 0 or ids
        ):
            raise CandidateValidationError(
                "zero canary produced vulnerability evidence"
            )
        try:
            digest = canonical_canary_output_sha256(
                canary_id=item["canary_id"],
                fixture_sha256=item["fixture_sha256"],
                exit_code=item["exit_code"],
                result_count=item["result_count"],
                rule_ids=ids,
            )
        except (TypeError, ValueError) as exc:
            raise CandidateValidationError("canary identity is malformed") from exc
        normalized_canaries.append(
            {
                "id": item["canary_id"],
                "fixture_path": current["fixture_path"],
                "fixture_kind": current["fixture_kind"],
                "fixture_hash_algorithm": current["fixture_hash_algorithm"],
                "fixture_sha256": item["fixture_sha256"],
                "output_sha256": digest,
                "expected_exit_code": item["exit_code"],
                "expected_result_count": item["result_count"],
                "expected_ids": ids,
            }
        )
    normalized_canaries.sort(key=lambda item: item["id"])
    if len(normalized_canaries) != 2 or [
        item["id"] for item in normalized_canaries
    ] != list(profile.canary_ids):
        raise CandidateValidationError(
            "candidate requires the exact positive/zero canaries"
        )
    proposal = {
        "source": {
            "kind": "oci",
            "discovery_ref": profile.discovery_ref,
            "immutable_ref": (
                f"ghcr.io/{profile.repository}@sha256:" + manifest.manifest_digest
            ),
            "sha256": manifest.manifest_digest,
            "size_bytes": manifest.layer_size_bytes,
        },
        "installed_size_bytes": installed_size_bytes,
        "max_age_seconds": profile.maximum_age_seconds,
        "data_contract": {
            "kind": (
                "trivy-db-metadata/v2"
                if profile.component_id == "trivy-db"
                else "trivy-java-db-metadata/v2"
            ),
            "schema_version": profile.metadata_version,
            "timestamp_kind": "intrinsic",
            "publisher_updated_at": metadata.updated_at,
            "publisher_refresh_due_at": metadata.next_update,
        },
        "installed_content": dict(installed_content),
        "canaries": normalized_canaries,
    }
    receipt = {
        "schema": f"{profile.receipt_prefix}/v1",
        "authoritative": False,
        "current_lock_sha256": current_lock_sha256,
        "baked_lock_sha256": baked_lock_sha256,
        "scanner_image": {
            "id": image_id,
            "architecture": architecture,
            "trivy_version": trivy_version,
            "trivy_executable_path": trivy_executable_path,
            "trivy_executable_sha256": trivy_executable_sha256,
            "tool_manifest_sha256": tool_manifest_sha256,
            "implementation_bundle": normalized_bundle,
            "host_cli_sha256": host_cli_sha256,
        },
        "host_execution_identity": dict(host_execution_identity),
        "build_receipt": normalized_build_receipt,
        "evidence_receipts": normalized_evidence,
        "oci": {
            "manifest_sha256": manifest.manifest_digest,
            "created_at": manifest.created_at,
            "layer_sha256": manifest.layer_digest,
            "layer_size_bytes": manifest.layer_size_bytes,
        },
        "metadata": {
            "updated_at": metadata.updated_at,
            "next_update": metadata.next_update,
            "downloaded_at": metadata.downloaded_at,
            "observed_at": metadata.observed_at,
            "maximum_age_seconds": metadata.maximum_age_seconds,
            "minimum_remaining_seconds": metadata.minimum_remaining_seconds,
        },
        "proposed_replacement": proposal,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        canonical_json_bytes(receipt)
    ).hexdigest()
    return receipt


def _publish_private_payload(path: Path, payload: bytes) -> None:
    """Publish bounded bytes atomically without following or replacing paths."""

    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CandidateValidationError("receipt path must be a narrow absolute path")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise CandidateValidationError("receipt parent is unavailable") from exc
    if parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise CandidateValidationError("receipt parent is unsafe")
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError("receipt parent cannot be resolved") from exc
    if (
        resolved_parent != parent
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise CandidateValidationError(
            "receipt parent must be a direct owner-only directory"
        )
    if not payload or len(payload) > MAX_RECEIPT_BYTES:
        raise CandidateValidationError("candidate receipt is empty or oversized")
    directory_descriptor = -1
    descriptor = -1
    temporary_name = f".{path.name}.tmp-{secrets.token_hex(16)}"
    published = False
    invalidated = False
    staged_identity: tuple[int, int] | None = None
    try:
        directory_descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW | _CLOEXEC
        )
        opened_parent = os.fstat(directory_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise CandidateValidationError("receipt parent identity changed")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
            dir_fd=directory_descriptor,
        )
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise CandidateValidationError("receipt write made no progress")
            offset += count
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        staged_identity = (staged.st_dev, staged.st_ino)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_uid != os.getuid()
            or staged.st_nlink != 1
            or stat.S_IMODE(staged.st_mode) != 0o600
            or staged.st_size != len(payload)
        ):
            raise CandidateValidationError("receipt staging identity is invalid")
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        final = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        held = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != staged_identity
            or (held.st_dev, held.st_ino) != staged_identity
            or not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.getuid()
            or final.st_nlink != 1
            or held.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_size != len(payload)
        ):
            raise CandidateValidationError("receipt publication identity is invalid")
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        if published and descriptor >= 0:
            try:
                os.fchmod(descriptor, 0o000)
                os.ftruncate(descriptor, 0)
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"INVALID\n")
                os.fsync(descriptor)
                invalidated = True
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            if directory_descriptor >= 0:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            cleanup_errors.append(exc)
        if published and directory_descriptor >= 0:
            try:
                final = os.stat(
                    path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    staged_identity is not None
                    and (
                        final.st_dev,
                        final.st_ino,
                    )
                    == staged_identity
                ):
                    os.unlink(path.name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                cleanup_errors.append(exc)
        if directory_descriptor >= 0:
            try:
                os.fsync(directory_descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if published and not invalidated:
            cleanup_errors.append(
                CandidateValidationError("receipt rollback invalidation failed")
            )
        if cleanup_errors:
            raise CandidateValidationError("receipt rollback is uncertain") from (
                cleanup_errors[0]
            )
        raise primary
    finally:
        close_errors: list[BaseException] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as exc:
                close_errors.append(exc)
        if directory_descriptor >= 0:
            try:
                os.close(directory_descriptor)
            except BaseException as exc:
                close_errors.append(exc)
        if close_errors and sys.exc_info()[0] is None:
            raise CandidateValidationError("receipt descriptor cleanup failed") from (
                close_errors[0]
            )


def write_private_evidence_receipt(
    path: Path,
    receipt: Mapping[str, Any],
    *,
    schema: str,
    fields: set[str],
) -> None:
    payload = canonical_json_bytes(dict(receipt))
    _parse_sealed_receipt(
        payload,
        label="candidate evidence receipt",
        schema=schema,
        fields=fields,
    )
    _publish_private_payload(path, payload)


def write_private_receipt(
    path: Path,
    receipt: Mapping[str, Any],
    component_id: str = "trivy-db",
) -> None:
    """Write one private final receipt without following or overwriting any path."""

    profile = candidate_profile(component_id)
    receipt_value = dict(receipt)
    if set(receipt_value) != {
        "schema",
        "authoritative",
        "current_lock_sha256",
        "baked_lock_sha256",
        "scanner_image",
        "host_execution_identity",
        "build_receipt",
        "evidence_receipts",
        "oci",
        "metadata",
        "proposed_replacement",
        "receipt_sha256",
    }:
        raise CandidateValidationError("candidate receipt fields are not exact")
    claimed_digest = receipt_value.pop("receipt_sha256")
    if (
        receipt_value.get("schema") != f"{profile.receipt_prefix}/v1"
        or receipt_value.get("authoritative") is not False
        or not isinstance(claimed_digest, str)
        or not _SHA256.fullmatch(claimed_digest)
        or claimed_digest
        != hashlib.sha256(canonical_json_bytes(receipt_value)).hexdigest()
    ):
        raise CandidateValidationError("candidate receipt identity is invalid")
    receipt_value["receipt_sha256"] = claimed_digest
    payload = canonical_json_bytes(receipt_value)
    _publish_private_payload(path, payload)


_INNER_CURRENT_LOCK = Path("/run/kodesec-review/current-lock.json")
_INNER_BAKED_LOCK = Path("/usr/local/share/kodesec/locks/scanner-tools.lock.json")
_INNER_TOOL_MANIFEST = Path("/usr/local/share/kodesec/tool-manifest.json")
_INNER_POSITIVE = Path("/run/kodesec-review/positive")
_INNER_ZERO = Path("/run/kodesec-review/zero")
_INNER_JAVA_POSITIVE = Path(
    "/usr/local/share/kodesec/canaries/trivy/java/log4j-core-2.14.1.jar"
)
_INNER_FETCH_OUTPUT = Path("/run/kodesec-review/output")
_INNER_CANDIDATE_DB = Path("/run/kodesec-review/candidate-cache/db")
_INNER_CANDIDATE_JAVA_DB = Path("/run/kodesec-review/candidate-cache/java-db")
_INNER_SCRATCH = Path("/run/kodesec-scratch")


def _exact_path(value: str, expected: Path) -> Path:
    if value != str(expected):
        raise ValueError("inner path differs from its fixed mount target")
    return expected


def _inner_parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="Bounded container-side Trivy DB candidate evidence producer."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument(
        "--component-id", default="trivy-db", choices=tuple(_TRIVY_DB_PROFILES)
    )
    preflight.add_argument(
        "--current-lock",
        required=True,
        type=lambda item: _exact_path(item, _INNER_CURRENT_LOCK),
    )
    preflight.add_argument("--invocation-id", required=True)
    preflight.add_argument(
        "--baked-lock",
        required=True,
        type=lambda item: _exact_path(item, _INNER_BAKED_LOCK),
    )
    preflight.add_argument(
        "--trivy-path",
        required=True,
        type=lambda item: _exact_path(item, Path(TRIVY_EXECUTABLE_PATH)),
    )
    preflight.add_argument("--trivy-version", required=True, choices=[TRIVY_VERSION])
    preflight.add_argument(
        "--expected-architecture", required=True, choices=["amd64", "arm64"]
    )
    preflight.add_argument(
        "--tool-manifest",
        required=True,
        type=lambda item: _exact_path(item, _INNER_TOOL_MANIFEST),
    )
    preflight.add_argument(
        "--positive-fixture",
        required=True,
        type=Path,
    )
    preflight.add_argument(
        "--zero-fixture",
        required=True,
        type=lambda item: _exact_path(item, _INNER_ZERO),
    )

    fetch = subparsers.add_parser("fetch")
    fetch.add_argument(
        "--component-id", default="trivy-db", choices=tuple(_TRIVY_DB_PROFILES)
    )
    fetch.add_argument("--registry", required=True, choices=[TRIVY_DB_REGISTRY])
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--reference", required=True)
    fetch.add_argument(
        "--output-dir",
        required=True,
        type=lambda item: _exact_path(item, _INNER_FETCH_OUTPUT),
    )
    fetch.add_argument("--invocation-id", required=True)

    canary = subparsers.add_parser("canary")
    canary.add_argument(
        "--component-id", default="trivy-db", choices=tuple(_TRIVY_DB_PROFILES)
    )
    canary.add_argument(
        "--current-lock",
        required=True,
        type=lambda item: _exact_path(item, _INNER_CURRENT_LOCK),
    )
    canary.add_argument("--invocation-id", required=True)
    canary.add_argument(
        "--candidate-db",
        required=True,
        type=Path,
    )
    canary.add_argument("--support-trivy-db", type=Path)
    canary.add_argument(
        "--positive-fixture",
        required=True,
        type=Path,
    )
    canary.add_argument(
        "--zero-fixture",
        required=True,
        type=lambda item: _exact_path(item, _INNER_ZERO),
    )
    return parser


def inner_main(argv: Sequence[str] | None = None) -> int:
    arguments = _inner_parser().parse_args(argv)
    try:
        parsed_component_id = getattr(arguments, "component_id", None)
        component_id = parsed_component_id or "trivy-db"
        profile = candidate_profile(component_id)
        expected_positive = (
            _INNER_POSITIVE
            if profile.component_id == "trivy-db"
            else _INNER_JAVA_POSITIVE
        )
        if (
            parsed_component_id is not None
            and arguments.mode in {"preflight", "canary"}
            and arguments.positive_fixture != expected_positive
        ):
            raise CandidateValidationError("positive fixture path is not exact")
        expected_candidate = (
            _INNER_CANDIDATE_DB
            if profile.component_id == "trivy-db"
            else _INNER_CANDIDATE_JAVA_DB
        )
        if (
            parsed_component_id is not None
            and arguments.mode == "canary"
            and arguments.candidate_db != expected_candidate
        ):
            raise CandidateValidationError("candidate cache path is not exact")
        support_trivy_db = getattr(arguments, "support_trivy_db", None)
        if arguments.mode == "canary" and (
            (
                profile.component_id == "trivy-java-db"
                and support_trivy_db != _INNER_CANDIDATE_DB
            )
            or (profile.component_id == "trivy-db" and support_trivy_db is not None)
        ):
            raise CandidateValidationError("support cache path is not exact")
        if arguments.mode == "preflight":
            receipt = run_preflight(
                current_lock=arguments.current_lock,
                baked_lock=arguments.baked_lock,
                trivy_path=arguments.trivy_path,
                tool_manifest=arguments.tool_manifest,
                positive_fixture=arguments.positive_fixture,
                zero_fixture=arguments.zero_fixture,
                expected_architecture=arguments.expected_architecture,
                scratch_root=_INNER_SCRATCH,
                invocation_id=arguments.invocation_id,
                component_id=component_id,
            )
        elif arguments.mode == "fetch":
            receipt = run_fetch(
                registry=arguments.registry,
                repository=arguments.repository,
                reference=arguments.reference,
                output_dir=arguments.output_dir,
                invocation_id=arguments.invocation_id,
                component_id=component_id,
            )
        elif arguments.mode == "canary":
            receipt = run_canary(
                current_lock=arguments.current_lock,
                candidate_db=arguments.candidate_db,
                positive_fixture=arguments.positive_fixture,
                zero_fixture=arguments.zero_fixture,
                scratch_root=_INNER_SCRATCH,
                invocation_id=arguments.invocation_id,
                component_id=component_id,
                support_trivy_db=support_trivy_db,
            )
        else:  # pragma: no cover - argparse closes this branch
            raise CandidateValidationError("inner mode is unsupported")
    except Exception as exc:
        mode = arguments.mode
        allowed = _INNER_FAILURE_CODES.get(mode, frozenset())
        if isinstance(exc, _InnerFailure) and exc.mode == mode and exc.code in allowed:
            code = exc.code
        elif mode == "fetch" and isinstance(
            exc, (CandidateValidationError, CacheValidationError, LockValidationError)
        ):
            code = "validation"
        else:
            code = "unexpected"
        if code not in allowed:
            code = "unexpected"
        os.sys.stderr.buffer.write(
            f"{_INNER_FAILURE_MARKER} {mode} {code}\n".encode("ascii")
        )
        return 2
    # canonical_json_bytes is the repository's wire-and-disk receipt contract;
    # it already includes exactly one terminating LF.
    os.sys.stdout.buffer.write(canonical_json_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(inner_main())
