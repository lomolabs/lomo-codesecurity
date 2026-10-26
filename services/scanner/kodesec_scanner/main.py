from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from contextlib import asynccontextmanager, ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from . import __version__
from .external import (
    ExecutionControl,
    RunCancelled,
    RunDeadlineExceeded,
    request_scratch_directory,
    run_captured_command,
    run_external_tool,
)
from .cache_manifest import CacheVerification, ResolvedGeneration, load_rules_lock, load_tool_lock
from .runtime_cache import RuntimeCacheVerifier, VerificationConflict
from .models import (
    RUN_RESULT_PAGE_LIMIT,
    Finding,
    RunFindingPageRequest,
    RunFindingPageResponse,
    RunListResponse,
    RunResultAckRequest,
    RunResultAckResponse,
    RunStartRequest,
    RunStateResponse,
    ScanRequest,
    ScanResponse,
    canonical_json_bytes,
)
from .redaction import redact_finding
from .rules import TEXT_EXTENSIONS, scan_text_file, is_docker_source_name
from .run_control import (
    CaptureStorageError,
    RunCapacityError,
    RunConflictError,
    RunCursorError,
    RunNotFoundError,
    RunRegistry,
    RunResultStorageError,
    RunResultUnavailableError,
    SourceBoundaryError,
)
from .settings import get_settings
from .source_io import SourceEvidenceError, SourceTextReader, read_regular_file_at
from .tools import (
    SCANNER_TOOLS,
    external_tool_ids,
    internal_tool_ids,
    scanner_tool_ids,
    scanner_tools_snapshot_with_runtime,
    scanner_runtime_context,
    tool_runtime_state,
)
from .updater import CacheRollbackEligibility, evaluate_cache_rollback_eligibility

settings = get_settings()
cache_verifier: RuntimeCacheVerifier | None = None


def _runtime_verifier() -> RuntimeCacheVerifier:
    if cache_verifier is None:
        raise RuntimeError("scanner cache verifier has not started")
    return cache_verifier


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    global cache_verifier
    verifier = RuntimeCacheVerifier(
        Path(settings.tool_cache_dir), Path(settings.tool_lock_path), Path(settings.rules_lock_path),
    )
    verifier.start()
    cache_verifier = verifier
    try:
        yield
    finally:
        try:
            runs_stopped = run_registry.shutdown()
        finally:
            verification_stopped = verifier.shutdown()
            cache_verifier = None
        if not runs_stopped or not verification_stopped:
            raise RuntimeError("scanner shutdown exceeded its active-work cleanup deadline")


app = FastAPI(title="Lomo CodeSecurity Scanner", version=__version__, lifespan=_lifespan)

scans_total = Counter("kodesec_scanner_scans_total", "Scanner runs", ["status"])
scan_duration = Histogram("kodesec_scanner_scan_duration_seconds", "Scanner duration")

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".turbo",
    ".cache",
}

GIT_OBJECT_ID = re.compile(r"[0-9a-fA-F]{4,64}")
MAX_GIT_REF_LENGTH = 255
INCREMENTAL_MODE_FALLBACK_WARNING = (
    "incremental-diff-fallback-full"
)
SOURCE_COVERAGE_ERROR_PREFIX = "source_coverage"
SUPPORTED_TEXT_EXTENSIONS = frozenset(extension.lower() for extension in TEXT_EXTENSIONS)
MAX_DIRECTORY_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_CAPTURE_FILE_BYTES = 8 * 1024 * 1024


@dataclass
class SourceCoverage:
    """Bounded, path-free evidence for the source files considered locally."""

    selected_files: list[Path] = field(default_factory=list)
    eligible_files: int = 0
    overflow_files: int = 0
    read_files: int = 0
    oversized_files: int = 0
    binary_files: int = 0
    invalid_utf8_files: int = 0
    unreadable_files: int = 0
    unsupported_type_files: int = 0
    total_bytes_overflow_files: int = 0

    @property
    def complete(self) -> bool:
        return not any(
            (
                self.overflow_files,
                self.oversized_files,
                self.binary_files,
                self.invalid_utf8_files,
                self.unreadable_files,
                self.unsupported_type_files,
                self.total_bytes_overflow_files,
            )
        )

    def reason_counts(self) -> dict[str, int]:
        return {
            reason: count
            for reason, count in (
                ("eligible_file_limit_exceeded", self.overflow_files),
                ("eligible_file_too_large", self.oversized_files),
                ("eligible_file_binary", self.binary_files),
                ("eligible_file_invalid_utf8", self.invalid_utf8_files),
                ("eligible_file_unreadable", self.unreadable_files),
                ("eligible_file_unsupported_type", self.unsupported_type_files),
                (
                    "eligible_file_capture_total_bytes_exceeded",
                    self.total_bytes_overflow_files,
                ),
            )
            if count
        }

    def as_receipt(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "eligible_files": self.eligible_files,
            "selected_files": len(self.selected_files),
            "read_files": self.read_files,
            "omitted_files": self.overflow_files + self.total_bytes_overflow_files,
            "max_files": settings.max_files,
            "max_file_bytes": settings.max_file_bytes,
            "reason_counts": self.reason_counts(),
        }


@dataclass
class DirectoryCapture:
    """An immutable selected subtree or a private Gitleaks whole-root source view."""

    root: Path
    source_coverage: SourceCoverage = field(default_factory=SourceCoverage)
    captured_files: int = 0
    captured_bytes: int = 0
    inventory_sha256: str | None = None
    overflow_files: int = 0
    oversized_files: int = 0
    unreadable_files: int = 0
    unsupported_type_files: int = 0
    total_bytes_overflow_files: int = 0

    @property
    def complete(self) -> bool:
        return not any(
            (
                self.overflow_files,
                self.oversized_files,
                self.unreadable_files,
                self.unsupported_type_files,
                self.total_bytes_overflow_files,
            )
        )

    def reason_counts(self) -> dict[str, int]:
        return {
            reason: count
            for reason, count in (
                ("capture_file_limit_exceeded", self.overflow_files),
                ("capture_file_too_large", self.oversized_files),
                ("capture_file_unreadable", self.unreadable_files),
                ("capture_entry_unsupported_type", self.unsupported_type_files),
                ("capture_total_bytes_exceeded", self.total_bytes_overflow_files),
            )
            if count
        }

    def as_receipt(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "captured_files": self.captured_files,
            "captured_bytes": self.captured_bytes,
            "omitted_files": sum(self.reason_counts().values()),
            "max_files": settings.max_files,
            "max_file_bytes": settings.max_file_bytes,
            "max_total_bytes": MAX_DIRECTORY_CAPTURE_BYTES,
            "max_capture_file_bytes": MAX_DIRECTORY_CAPTURE_FILE_BYTES,
            "reason_counts": self.reason_counts(),
        }


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    # Health is a fixed-size liveness contract. Source roots and the tool catalog
    # grow with configuration and belong to their dedicated authenticated views.
    return {
        "ok": True,
        "version": __version__,
        "engine": "kodesec-worker",
    }


@app.get("/tools")
def tools() -> dict[str, Any]:
    snapshot = scanner_tools_snapshot_with_runtime(
        tool_lock_path=Path(settings.tool_lock_path),
        rules_lock_path=Path(settings.rules_lock_path),
        cache_root=Path(settings.tool_cache_dir),
        resolver=_runtime_verifier().resolve,
    )
    return {
        "tools": snapshot.tools,
        "active_generation": snapshot.active_generation,
        "cache_verification": snapshot.cache_verification.model_dump(mode="json") if snapshot.cache_verification else None,
    }


@app.get(
    "/cache/rollback-eligibility",
    response_model=CacheRollbackEligibility,
)
def cache_rollback_eligibility() -> CacheRollbackEligibility:
    """Return a read-only proof for the exact previous-good cache target."""

    return evaluate_cache_rollback_eligibility(
        Path(settings.tool_cache_dir),
        load_tool_lock(Path(settings.tool_lock_path)),
        load_rules_lock(Path(settings.rules_lock_path)),
        resolver=_runtime_verifier().resolve_previous,
    )


class CacheVerificationRetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target: Literal["active", "previous_good"]
    expected_generation: str = Field(pattern=r"^[0-9a-f]{64}$")


@app.post("/cache/verification/retry", status_code=202, response_model=CacheVerification)
def retry_cache_verification(payload: CacheVerificationRetryRequest) -> CacheVerification:
    try:
        return _runtime_verifier().retry(payload.target, payload.expected_generation)
    except VerificationConflict as exc:
        message = {
            "cache_verification_changed": "The scanner cache target changed; refresh scanner status.",
            "cache_verification_not_retryable": "This scanner cache verification cannot be retried in its current state.",
        }[exc.code]
        raise HTTPException(409, {"code": exc.code, "message": message}) from exc


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _ensure_allowed(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourceBoundaryError("repo_path does not exist or cannot be resolved") from exc
    if not resolved.is_dir():
        raise SourceBoundaryError("repo_path does not exist or is not a directory")
    for root in settings.allowed_root_list:
        try:
            resolved.relative_to(Path(root).resolve(strict=True))
            return resolved
        except (OSError, RuntimeError, ValueError):
            continue
    raise SourceBoundaryError("repo_path is outside the configured source boundary")


def _ensure_snapshot_binding(repo: Path, digest: str | None) -> None:
    snapshot_root = Path(settings.source_snapshot_dir).resolve(strict=False)
    generation_root = snapshot_root / "generations"
    if digest is not None:
        try:
            expected = (generation_root / digest / "source").resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SourceBoundaryError("source snapshot digest is unavailable") from exc
        if repo != expected:
            raise SourceBoundaryError(
                "repo_path does not match the immutable source snapshot digest"
            )
        return
    try:
        repo.relative_to(generation_root)
    except ValueError:
        return
    raise SourceBoundaryError("source snapshot repo_path requires an immutable snapshot digest")


def _resolve_candidate(repo: Path, candidate: Path) -> Path:
    """Resolve a source entry and prove its canonical path stays below repo."""

    try:
        root = repo.resolve(strict=True)
        unresolved = candidate if candidate.is_absolute() else root / candidate
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        try:
            display = candidate.relative_to(repo).as_posix()
        except ValueError:
            display = candidate.as_posix()
        raise SourceBoundaryError(f"source entry escapes or cannot be resolved: {display}") from exc
    return resolved


def _git(
    repo: Path,
    args: list[str],
    timeout: int = 20,
    control: ExecutionControl | None = None,
) -> str:
    git_env = os.environ.copy()
    for key in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIFF_OPTS",
        "GIT_DIR",
        "GIT_EXTERNAL_DIFF",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        git_env.pop(key, None)
    for key in list(git_env):
        if key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            git_env.pop(key, None)
    git_env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = run_captured_command(
        ["git", "-c", "diff.external=", "-C", str(repo), *args],
        repo,
        timeout,
        env=git_env,
        control=control,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "git command failed").strip()
        raise RuntimeError(detail[:2000])
    return result.stdout


def _call_git(
    repo: Path,
    args: list[str],
    timeout: int,
    control: ExecutionControl | None,
) -> str:
    if control is None:
        return _git(repo, args, timeout)
    return _git(repo, args, timeout, control)


def _resolve_git_commit(repo: Path, value: str, control: ExecutionControl | None = None) -> str:
    if not value or value != value.strip() or len(value) > MAX_GIT_REF_LENGTH:
        raise ValueError("git ref is empty, padded, or too long")
    if value.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("git ref contains forbidden option or control characters")
    if value != "HEAD" and not GIT_OBJECT_ID.fullmatch(value):
        _call_git(repo, ["check-ref-format", "--branch", value], 20, control)
    revision = _call_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}"],
        20,
        control,
    ).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
        raise RuntimeError("git ref did not resolve to one commit object")
    return revision.lower()


def _call_resolve_git_commit(repo: Path, value: str, control: ExecutionControl | None) -> str:
    if control is None:
        return _resolve_git_commit(repo, value)
    return _resolve_git_commit(repo, value, control)


def _changed_files(
    repo: Path,
    base_ref: str | None,
    head_ref: str | None,
    control: ExecutionControl | None = None,
) -> tuple[list[Path], str | None]:
    if not base_ref:
        return [], "base_ref missing"
    head = head_ref or "HEAD"
    try:
        base_commit = _call_resolve_git_commit(repo, base_ref, control)
        head_commit = _call_resolve_git_commit(repo, head, control)
        output = _call_git(
            repo,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "--diff-filter=ACMRT",
                "-z",
                base_commit,
                head_commit,
                "--",
            ],
            60,
            control,
        )
        files = [
            _resolve_candidate(repo, Path(relative))
            for relative in output.split("\0")
            if relative
        ]
    except (SourceBoundaryError, RunCancelled, RunDeadlineExceeded):
        raise
    except Exception:
        return [], "incremental_diff_planning_failed"
    return files, None


def _walk_files(
    repo: Path, control: ExecutionControl | None = None, *, sealed_snapshot: bool = False,
) -> SourceCoverage:
    coverage = SourceCoverage()
    seen: set[Path] = set()

    def enumeration_failed(exc: OSError) -> None:
        raise SourceBoundaryError("source tree cannot be enumerated completely") from exc

    for root, dirs, names in os.walk(
        repo,
        followlinks=False,
        onerror=enumeration_failed,
    ):
        if control is not None:
            control.checkpoint()
        current = _resolve_candidate(repo, Path(root))
        next_dirs: list[str] = []
        for item in sorted(dirs):
            if control is not None:
                control.checkpoint()
            candidate = current / item
            resolved = _resolve_candidate(repo, candidate)
            if not sealed_snapshot and (item in SKIP_DIRS or item.startswith(".kodesec")):
                continue
            if candidate.is_symlink():
                continue
            if resolved.is_dir():
                next_dirs.append(item)
        dirs[:] = next_dirs
        for name in sorted(names):
            if control is not None:
                control.checkpoint()
            candidate = current / name
            resolved = _resolve_candidate(repo, candidate)
            if not _eligible_source_name(resolved) or resolved in seen:
                continue
            seen.add(resolved)
            coverage.eligible_files += 1
            try:
                regular_file = resolved.is_file()
            except OSError:
                regular_file = False
            if not regular_file:
                coverage.unsupported_type_files += 1
                continue
            if len(coverage.selected_files) >= settings.max_files:
                coverage.overflow_files += 1
                continue
            coverage.selected_files.append(resolved)
    return coverage


def _open_authorized_repository(repo: Path, subject: str, control: ExecutionControl | None = None) -> int:
    """Open the repository through the deepest configured root without following links."""

    anchors: dict[Path, tuple[tuple[str, ...], int, int]] = {}
    check = control.checkpoint if control else (lambda: None)
    check()
    for configured_root in settings.allowed_root_list:
        check()
        try:
            root = Path(configured_root).resolve(strict=True)
            relative_repo = repo.relative_to(root)
            metadata = root.stat()
            anchors[root] = (relative_repo.parts, metadata.st_dev, metadata.st_ino)
        except (OSError, RuntimeError, ValueError):
            continue
    if not anchors:
        raise SourceBoundaryError(f"{subject} does not have an authorized source root")
    allowed_root = max(anchors, key=lambda root: len(root.parts))
    repo_parts, root_device, root_inode = anchors[allowed_root]
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | nofollow
    descriptor = -1
    try:
        check()
        descriptor = os.open(allowed_root, directory_flags)
        opened_root = os.fstat(descriptor)
        if (
            opened_root.st_dev != root_device
            or opened_root.st_ino != root_inode
            or not stat.S_ISDIR(opened_root.st_mode)
        ):
            raise SourceBoundaryError(f"authorized source root changed before {subject} selection")
        for part in repo_parts:
            check()
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SourceBoundaryError("selected repository is no longer a directory")
        check()
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _read_target_file(repo: Path, target_path: str, control: ExecutionControl | None = None) -> tuple[Path, bytes]:
    """Read one exact file through an fd-relative, no-symlink directory walk."""

    parts = target_path.split("/")
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or not _eligible_source_name(Path(parts[-1]))
    ):
        raise SourceBoundaryError("exact file target is not a supported regular source file")
    descriptor = -1
    try:
        descriptor = _open_authorized_repository(repo, "exact file target", control)
        content = read_regular_file_at(
            descriptor,
            target_path,
            settings.max_file_bytes,
            checkpoint=control.checkpoint if control else None,
        )
    except SourceEvidenceError as exc:
        if exc.reason == "source_file_oversized":
            raise SourceBoundaryError(
                "exact file target exceeds the source file size limit"
            ) from exc
        if exc.reason == "source_file_changed":
            raise SourceBoundaryError(
                "exact file target changed while it was being read"
            ) from exc
        if exc.reason == "unsupported_source_type":
            raise SourceBoundaryError(
                "exact file target is not a supported regular source file"
            ) from exc
        raise SourceBoundaryError(
            "exact file target must not traverse a symbolic link and must remain readable"
        ) from exc
    except SourceBoundaryError:
        raise
    except OSError as exc:
        raise SourceBoundaryError(
            "exact file target must not traverse a symbolic link and must remain readable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > settings.max_file_bytes:
        raise SourceBoundaryError("exact file target exceeds the source file size limit")
    return repo.joinpath(*parts), content


def _target_file_coverage(repo: Path, target_path: str) -> SourceCoverage:
    """Resolve one exact file using the descriptor-safe source boundary."""

    source, _ = _read_target_file(repo, target_path)
    return SourceCoverage(selected_files=[source], eligible_files=1)


def _capture_target_directory(
    repo: Path,
    target_path: str | None,
    request_scratch: Path,
    control: ExecutionControl,
    *, sealed_snapshot: bool = False,
    gitleaks_whole_root: bool = False,
) -> DirectoryCapture:
    """Capture a selected subtree or the pinned Gitleaks whole-root source view."""

    parts = [] if gitleaks_whole_root and target_path is None else (target_path or "").split("/")
    if (not parts and not gitleaks_whole_root) or any(part in {"", ".", ".."} for part in parts):
        raise SourceBoundaryError("selected directory target is not a safe relative path")
    source_root = request_scratch / ("gitleaks-source" if gitleaks_whole_root else "selected-source")
    try:
        source_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        if parts:
            source_root.joinpath(*parts).mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        raise CaptureStorageError("selected source capture storage is unavailable") from exc
    capture = DirectoryCapture(root=source_root)
    inventory = hashlib.sha256(b"lomo-gitleaks-captured-inventory/v1\0")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | nofollow
    descriptor = -1

    def account_omission(reason: str, eligible: bool) -> None:
        if reason == "overflow":
            capture.overflow_files += 1
            if eligible:
                capture.source_coverage.overflow_files += 1
        elif reason == "oversized":
            capture.oversized_files += 1
            if eligible:
                capture.source_coverage.oversized_files += 1
        elif reason == "unreadable":
            capture.unreadable_files += 1
            if eligible:
                capture.source_coverage.unreadable_files += 1
        elif reason == "total_bytes":
            capture.total_bytes_overflow_files += 1
            if eligible:
                capture.source_coverage.total_bytes_overflow_files += 1
        else:
            capture.unsupported_type_files += 1
            if eligible:
                capture.source_coverage.unsupported_type_files += 1

    def capture_file(
        directory_descriptor: int,
        name: str,
        relative: tuple[str, ...],
        metadata: os.stat_result,
    ) -> None:
        logical_path = repo.joinpath(*relative)
        eligible = _eligible_source_name(logical_path)
        maximum_bytes = MAX_DIRECTORY_CAPTURE_FILE_BYTES
        if eligible:
            capture.source_coverage.eligible_files += 1
        if not stat.S_ISREG(metadata.st_mode):
            account_omission("unsupported", eligible)
            return
        if metadata.st_size > maximum_bytes:
            account_omission("oversized", eligible)
            return
        if capture.captured_files >= settings.max_files:
            account_omission("overflow", eligible)
            return
        if capture.captured_bytes + metadata.st_size > MAX_DIRECTORY_CAPTURE_BYTES:
            account_omission("total_bytes", eligible)
            return

        source_descriptor = -1
        try:
            try:
                source_descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | nofollow | os.O_NONBLOCK,
                    dir_fd=directory_descriptor,
                )
                before = os.fstat(source_descriptor)
            except OSError:
                account_omission("unreadable", eligible)
                return
            enumerated_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            opened_identity = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            if not stat.S_ISREG(before.st_mode) or opened_identity != enumerated_identity:
                raise SourceBoundaryError("selected directory changed before immutable capture")

            destination = source_root.joinpath(*relative)
            try:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as exc:
                raise CaptureStorageError(
                    "selected source capture storage is unavailable"
                ) from exc
            read_failed = False
            size = 0
            content_digest = hashlib.sha256()
            try:
                with destination.open("xb") as destination_handle:
                    remaining = maximum_bytes + 1
                    while remaining > 0:
                        control.checkpoint()
                        try:
                            chunk = os.read(source_descriptor, min(64 * 1024, remaining))
                        except OSError:
                            read_failed = True
                            break
                        if not chunk:
                            break
                        destination_handle.write(chunk)
                        if gitleaks_whole_root:
                            content_digest.update(chunk)
                        size += len(chunk)
                        remaining -= len(chunk)
                    control.checkpoint()
            except OSError as exc:
                raise CaptureStorageError(
                    "selected source capture storage is unavailable"
                ) from exc
            if read_failed:
                try:
                    destination.unlink(missing_ok=True)
                except OSError as exc:
                    raise CaptureStorageError(
                        "selected source capture storage is unavailable"
                    ) from exc
                account_omission("unreadable", eligible)
                return
            try:
                after = os.fstat(source_descriptor)
            except OSError:
                try:
                    destination.unlink(missing_ok=True)
                except OSError as exc:
                    raise CaptureStorageError(
                        "selected source capture storage is unavailable"
                    ) from exc
                account_omission("unreadable", eligible)
                return
            captured_identity = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if captured_identity != opened_identity or size != before.st_size:
                raise SourceBoundaryError("selected directory changed during immutable capture")
            try:
                destination.chmod(0o400)
            except OSError as exc:
                raise CaptureStorageError(
                    "selected source capture storage is unavailable"
                ) from exc
            if gitleaks_whole_root:
                inventory.update(canonical_json_bytes({
                    "kind": "file", "path": "/".join(relative), "size_bytes": size,
                    "sha256": content_digest.hexdigest(),
                }) + b"\n")
            capture.captured_files += 1
            capture.captured_bytes += size
            if eligible:
                capture.source_coverage.selected_files.append(destination)
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)

    def walk(directory_descriptor: int, relative_parts: tuple[str, ...]) -> None:
        control.checkpoint()
        directory_before = os.fstat(directory_descriptor) if gitleaks_whole_root else None
        try:
            names = sorted(os.listdir(directory_descriptor))
        except OSError as exc:
            raise SourceBoundaryError("selected directory cannot be enumerated completely") from exc
        for name in names:
            control.checkpoint()
            if (
                not name
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
                or any(
                    ord(character) < 32
                    or 127 <= ord(character) <= 159
                    or character in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                    for character in name
                )
            ):
                raise SourceBoundaryError("selected directory contains an unsafe source name")
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise SourceBoundaryError("selected directory changed during enumeration") from exc
            relative = (*relative_parts, name)
            if stat.S_ISLNK(metadata.st_mode):
                account_omission("unsupported", False)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if gitleaks_whole_root:
                    # Pinned Gitleaks 8.30.1 sources/files.go uses its embedded
                    # config/gitleaks.toml global /\.git$ allowlist before descent.
                    # Preserve all other source/control bytes; do not reuse lite exclusions.
                    if name == ".git":
                        continue
                elif not sealed_snapshot and (name in SKIP_DIRS or name.startswith(".kodesec")):
                    continue
                child = -1
                try:
                    if gitleaks_whole_root:
                        try:
                            source_root.joinpath(*relative).mkdir(mode=0o700, parents=True, exist_ok=False)
                        except OSError as exc:
                            raise CaptureStorageError("source capture storage is unavailable") from exc
                        inventory.update(canonical_json_bytes({
                            "kind": "directory", "path": "/".join(relative),
                        }) + b"\n")
                    child = os.open(name, directory_flags, dir_fd=directory_descriptor)
                    opened_directory = os.fstat(child)
                    if gitleaks_whole_root and any(
                        getattr(opened_directory, attribute) != getattr(metadata, attribute)
                        for attribute in ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
                    ):
                        raise SourceBoundaryError("source directory changed before immutable capture")
                    if not stat.S_ISDIR(opened_directory.st_mode):
                        raise SourceBoundaryError("selected directory contains a non-directory entry")
                    walk(child, relative)
                except SourceBoundaryError:
                    raise
                except OSError as exc:
                    raise SourceBoundaryError(
                        "selected directory must not traverse a symbolic link and must remain readable"
                    ) from exc
                finally:
                    if child >= 0:
                        os.close(child)
                continue
            capture_file(directory_descriptor, name, relative, metadata)
        if directory_before is not None:
            directory_after = os.fstat(directory_descriptor)
            def identity(metadata: os.stat_result) -> tuple[int, ...]:
                return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                        metadata.st_mtime_ns, metadata.st_ctime_ns)
            if identity(directory_before) != identity(directory_after):
                raise SourceBoundaryError("source directory changed during immutable capture")

    try:
        descriptor = _open_authorized_repository(repo, "selected directory")
        for part in parts:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SourceBoundaryError("selected directory target is not a directory")
        walk(descriptor, tuple(parts))
    except SourceBoundaryError:
        raise
    except OSError as exc:
        raise SourceBoundaryError(
            "selected directory must not traverse a symbolic link and must remain readable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        for current, directories, _files in os.walk(
            source_root,
            topdown=False,
            followlinks=False,
        ):
            control.checkpoint()
            for directory in directories:
                (Path(current) / directory).chmod(0o500)
        source_root.chmod(0o500)
    except OSError as exc:
        raise CaptureStorageError("selected source capture storage is unavailable") from exc
    if gitleaks_whole_root:
        capture.inventory_sha256 = inventory.hexdigest()
    return capture


def _stage_target_file(
    repo: Path,
    target_path: str,
    scratch_dir: Path,
    *,
    content: bytes | None = None,
) -> Path:
    """Create a private single-file source view for every external adapter."""

    try:
        if content is None:
            _, content = _read_target_file(repo, target_path)
        source_root = scratch_dir / "selected-source"
        source_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        destination = source_root.joinpath(*target_path.split("/"))
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if len(content) > settings.max_file_bytes:
            raise SourceBoundaryError("exact file target exceeds the source file size limit")
        with destination.open("xb") as destination_handle:
            destination_handle.write(content)
        destination.chmod(0o600)
        return source_root
    except SourceBoundaryError:
        raise
    except OSError as exc:
        raise CaptureStorageError("selected source capture storage is unavailable") from exc


def _eligible_source_name(path: Path) -> bool:
    if path.name.lower() in {".env", ".env.local", ".env.production"}:
        return True
    if is_docker_source_name(path):
        return True
    return path.suffix.lower() in SUPPORTED_TEXT_EXTENSIONS


def _read_text(reader: SourceTextReader, relative_path: str) -> tuple[str | None, str]:
    try:
        raw = reader.read_bytes(relative_path)
    except SourceEvidenceError as exc:
        outcome = {"source_file_oversized": "eligible_file_too_large",
                   "unsupported_source_type": "eligible_file_unsupported_type"}
        return None, outcome.get(exc.reason, "eligible_file_unreadable")
    return _decode_source_text(raw)


def _decode_source_text(raw: bytes) -> tuple[str | None, str]:
    if len(raw) > settings.max_file_bytes:
        return None, "eligible_file_too_large"
    if b"\x00" in raw[:4096]:
        return None, "eligible_file_binary"
    try:
        return raw.decode("utf-8"), "read"
    except UnicodeDecodeError:
        return None, "eligible_file_invalid_utf8"


def _scan_files(
    repo: Path,
    coverage: SourceCoverage,
    enabled_tools: set[str],
    control: ExecutionControl | None = None,
    exact_target_content: bytes | None = None,
    captured_source: DirectoryCapture | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    with ExitStack() as ownership:
        reader = None
        if exact_target_content is None:
            if captured_source is not None:
                if repo != captured_source.root or coverage is not captured_source.source_coverage:
                    raise SourceBoundaryError("selected directory capture does not match its source evidence")
                # This private source view was created by the authorized capture;
                # it does not add its scratch directory to host authorization.
                reader = ownership.enter_context(SourceTextReader(repo, settings.max_file_bytes,
                    checkpoint=control.checkpoint if control else None))
            else:
                descriptor = _open_authorized_repository(repo, "workspace scan", control)
                ownership.callback(os.close, descriptor)
                reader = ownership.enter_context(SourceTextReader(repo, settings.max_file_bytes,
                    checkpoint=control.checkpoint if control else None, root_descriptor=descriptor))
        for candidate in coverage.selected_files:
            if control is not None:
                control.checkpoint()
            if exact_target_content is None:
                path = _resolve_candidate(repo, candidate)
                if not _eligible_source_name(path):
                    coverage.unsupported_type_files += 1
                    continue
                text, outcome = _read_text(reader, path.relative_to(repo).as_posix())
            else:
                if len(coverage.selected_files) != 1 or not _eligible_source_name(candidate):
                    raise SourceBoundaryError("exact file source snapshot is inconsistent")
                path = candidate
                text, outcome = _decode_source_text(exact_target_content)
            if text is None:
                if outcome == "eligible_file_too_large":
                    coverage.oversized_files += 1
                elif outcome == "eligible_file_binary":
                    coverage.binary_files += 1
                elif outcome == "eligible_file_invalid_utf8":
                    coverage.invalid_utf8_files += 1
                elif outcome == "eligible_file_unsupported_type":
                    coverage.unsupported_type_files += 1
                else:
                    coverage.unreadable_files += 1
                continue
            coverage.read_files += 1
            # External-only requests still validate source without running lite.
            if not enabled_tools:
                continue
            for finding in scan_text_file(
                repo, path, text, enabled_tools=enabled_tools,
                checkpoint=control.checkpoint if control is not None else None,
            ):
                if finding.scanner in enabled_tools:
                    findings.append(finding)
    return _canonicalize_findings(findings)


def _canonicalize_findings(findings: list[Finding]) -> list[Finding]:
    """Order evidence deterministically and reject ambiguous fingerprints."""

    unique: dict[str, tuple[bytes, Finding]] = {}
    for finding in findings:
        encoded = canonical_json_bytes(finding.model_dump(mode="json"))
        existing = unique.get(finding.fingerprint)
        if existing is None:
            unique[finding.fingerprint] = (encoded, finding)
        elif existing[0] != encoded:
            raise RuntimeError("finding_fingerprint_collision")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        (item[1] for item in unique.values()),
        key=lambda finding: (
            severity_rank[finding.severity],
            finding.file_path,
            finding.start_line or 0,
            finding.start_column or 0,
            finding.end_line or 0,
            finding.end_column or 0,
            finding.scanner,
            finding.rule_id,
            finding.fingerprint,
        ),
    )


def _execute_scan(
    payload: ScanRequest, control: ExecutionControl,
    *, resolver: Callable[..., ResolvedGeneration] | None = None,
) -> ScanResponse:
    started = time.monotonic()
    control.checkpoint()
    settings.validate_storage_boundaries()
    repo = _ensure_allowed(Path(payload.repo_path))
    _ensure_snapshot_binding(repo, payload.source_snapshot_digest)
    with request_scratch_directory(settings.scratch_dir, payload.scan_id) as request_scratch:
        return _execute_scan_in_scratch(
            payload,
            control,
            started,
            repo,
            request_scratch,
            sealed_snapshot=payload.source_snapshot_digest is not None,
            resolver=resolver,
        )


def _execute_scan_in_scratch(
    payload: ScanRequest,
    control: ExecutionControl,
    started: float,
    repo: Path,
    request_scratch: Path,
    *, resolver: Callable[..., ResolvedGeneration] | None = None,
    sealed_snapshot: bool = False,
) -> ScanResponse:
    errors: list[str] = []
    warnings: list[str] = []
    source_coverage: SourceCoverage
    effective_mode = payload.mode
    changed_count = None
    directory_capture: DirectoryCapture | None = None

    target_content: bytes | None = None
    try:
        if payload.target_kind == "file":
            assert payload.target_path is not None
            target_source, target_content = _read_target_file(repo, payload.target_path, control)
            source_coverage = SourceCoverage(
                selected_files=[target_source],
                eligible_files=1,
            )
        elif payload.target_kind == "directory":
            assert payload.target_path is not None
            directory_capture = _capture_target_directory(
                repo,
                payload.target_path,
                request_scratch,
                control,
                sealed_snapshot=sealed_snapshot,
            )
            source_coverage = directory_capture.source_coverage
        else:
            source_coverage = _walk_files(repo, control, sealed_snapshot=sealed_snapshot)
        if payload.mode == "incremental_diff":
            # The core external scanners do not share one safe, complete
            # changed-file input contract.  They therefore scan the repository
            # root even when the internal lite scanners could consume a diff.
            # Run every enabled scanner against the same full source view and
            # report that fallback explicitly instead of claiming an
            # incremental result that was never produced.
            effective_mode = "full"
            warnings.append(INCREMENTAL_MODE_FALLBACK_WARNING)
    except SourceBoundaryError:
        raise
    except CaptureStorageError:
        raise

    enabled_tools = set(payload.enabled_tools)
    valid_tools = scanner_tool_ids()
    invalid_tools = sorted(enabled_tools - valid_tools)
    if invalid_tools:
        errors.append(f"unknown scanner tools ignored: {', '.join(invalid_tools)}")
    enabled_tools &= valid_tools
    if "grype" in enabled_tools and "syft" not in enabled_tools:
        errors.append("grype: syft_dependency_not_enabled")
        enabled_tools.discard("grype")

    publish_root = Path(settings.artifact_dir) / "scans" / str(payload.scan_id)
    try:
        internal_source = directory_capture.root if directory_capture is not None else repo
        findings = _scan_files(
            internal_source,
            source_coverage,
            enabled_tools & internal_tool_ids(),
            control,
            target_content,
            directory_capture,
        )
    except SourceBoundaryError:
        raise
    errors.extend(
        f"{SOURCE_COVERAGE_ERROR_PREFIX}: {reason}"
        for reason in source_coverage.reason_counts()
    )
    if directory_capture is not None:
        errors.extend(
            f"{SOURCE_COVERAGE_ERROR_PREFIX}: {reason}"
            for reason in directory_capture.reason_counts()
        )
    artifacts = []
    external_runs = []
    external_inputs: dict[str, Path] = {}
    cache_generation_id: str | None = None
    cache_manifest_sha256: str | None = None
    resolved_component_ids: list[str] = []
    runtime_context = scanner_runtime_context(
        tool_lock_path=Path(settings.tool_lock_path),
        rules_lock_path=Path(settings.rules_lock_path),
        cache_root=Path(settings.tool_cache_dir),
        checkpoint=control.checkpoint,
        resolver=resolver,
        requested_tools=enabled_tools,
        verification_wait=lambda: control.cancel_event.wait(min(0.25, control.remaining_seconds())),
    )
    readiness_by_id = dict(runtime_context.readiness_by_id)
    requested_external = enabled_tools & external_tool_ids()
    required_components: list[str] = []
    if requested_external and runtime_context.tools is not None:
        required_components = sorted(
            requirement.id
            for tool in runtime_context.tools.value.tools
            if tool.id in requested_external
            and readiness_by_id.get(tool.id) is not None
            and readiness_by_id[tool.id].ready
            for requirement in tool.requirements
            if requirement.required
        )
        if required_components:
            # This must resolve from the exact generation used for readiness.
            # An inconsistency is a scanner preflight failure, not permission to
            # retry against a newer pointer or run with missing inputs.
            snapshot = runtime_context.resolve_components(required_components)
            external_inputs.update(snapshot.roots)
            cache_generation_id = snapshot.generation_id
            cache_manifest_sha256 = snapshot.manifest_sha256
            resolved_component_ids = sorted(snapshot.roots)
    try:
        if payload.target_kind == "file" and requested_external:
            assert payload.target_path is not None and target_content is not None
            external_source = _stage_target_file(
                repo,
                payload.target_path,
                request_scratch,
                content=target_content,
            )
        elif payload.target_kind == "directory":
            assert directory_capture is not None
            external_source = directory_capture.root
        else:
            external_source = repo
    except CaptureStorageError:
        raise
    except SourceBoundaryError:
        raise
    gitleaks_capture: DirectoryCapture | None = None
    if ("gitleaks" in requested_external and payload.target_kind is None
            and not sealed_snapshot):
        gitleaks_capture = _capture_target_directory(
            repo, None, request_scratch, control, gitleaks_whole_root=True,
        )
        errors.extend(
            f"{SOURCE_COVERAGE_ERROR_PREFIX}: {reason}"
            for reason in gitleaks_capture.reason_counts()
        )
    execution_order = sorted(
        requested_external,
        key=lambda tool_id: (
            0 if tool_id == "syft" else 2 if tool_id == "grype" else 1,
            tool_id,
        ),
    )
    for tool_id in execution_order:
        control.checkpoint()
        runtime = runtime_context.runtime_by_id.get(
            tool_id,
            {
                "id": tool_id,
                "available": False,
                "status": "unverified",
                "installed_version": None,
            },
        )
        readiness = readiness_by_id.get(tool_id)
        readiness_payload = (
            {
                "binary": readiness.binary.model_dump(mode="json"),
                "data": readiness.data.model_dump(mode="json"),
                "rules": readiness.rules.model_dump(mode="json"),
                "execution": readiness.execution.model_dump(mode="json"),
            }
            if readiness is not None
            else None
        )
        if not runtime.get("available") or readiness is None or not readiness.ready:
            external_runs.append(
                {
                    "id": tool_id,
                    "status": "unavailable",
                    "error": (
                        "binary_not_found"
                        if not runtime.get("available")
                        else "runtime_not_ready"
                    ),
                    "findings_count": 0,
                    "artifacts_count": 0,
                    "exit_code": None,
                    "parse_integrity": None,
                    "runtime_ready": False,
                    "readiness": readiness_payload,
                    "cache_generation_id": cache_generation_id,
                }
            )
            errors.append(
                f"{tool_id}: "
                + ("binary_not_found" if not runtime.get("available") else "runtime_not_ready")
            )
            continue
        if tool_id == "gitleaks" and gitleaks_capture is not None and not gitleaks_capture.complete:
            external_runs.append({
                "id": tool_id, "status": "failed", "error": "source_capture_incomplete",
                "findings_count": 0, "artifacts_count": 0, "exit_code": None,
                "parse_integrity": None, "runtime_ready": True,
                "readiness": readiness_payload, "cache_generation_id": cache_generation_id,
            })
            errors.append("gitleaks: source_capture_incomplete")
            continue
        result = run_external_tool(
            tool_id,
            gitleaks_capture.root if tool_id == "gitleaks" and gitleaks_capture is not None else external_source,
            request_scratch,
            publish_root,
            Path(settings.tool_cache_dir),
            settings.external_tool_timeout,
            control,
            external_inputs,
        )
        findings.extend(result.findings)
        artifacts.extend(result.artifacts)
        if tool_id == "syft" and result.status == "completed":
            sbom = next(
                (
                    Path(artifact.path)
                    for artifact in result.artifacts
                    if artifact.scanner == "syft"
                    and artifact.artifact_type == "sbom"
                    and artifact.format == "cyclonedx-json"
                ),
                None,
            )
            if sbom is not None:
                external_inputs["syft_sbom"] = sbom
        external_runs.append(
            {
                "id": tool_id,
                "status": result.status,
                "error": result.error,
                "findings_count": len(result.findings),
                "artifacts_count": len(result.artifacts),
                "exit_code": result.exit_code,
                "parse_integrity": result.parse_integrity,
                "runtime_ready": readiness.ready,
                "readiness": readiness_payload,
                "cache_generation_id": cache_generation_id,
            }
        )
        if result.status in {"failed", "unavailable"}:
            errors.append(f"{tool_id}: {result.error or result.status}")

    control.checkpoint()
    findings = _canonicalize_findings(findings)
    redacted_findings: list[Finding] = []
    for finding in findings:
        control.checkpoint()
        redacted_findings.append(redact_finding(finding))
    control.checkpoint()
    findings = redacted_findings
    artifacts = sorted(
        artifacts,
        key=lambda artifact: canonical_json_bytes(artifact.model_dump(mode="json")),
    )
    status = "partial" if errors else "completed"
    scans_total.labels(status=status).inc()
    scan_duration.observe(max(time.monotonic() - started, 0))

    severity_counts: dict[str, int] = {}
    scanner_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        scanner_counts[finding.scanner] = scanner_counts.get(finding.scanner, 0) + 1

    tool_runs = []
    for tool in SCANNER_TOOLS:
        runtime = (
            tool_runtime_state(tool["id"])
            if tool.get("source") == "internal"
            else runtime_context.runtime_by_id.get(
                tool["id"],
                {
                    "id": tool["id"],
                    "available": False,
                    "status": "unverified",
                    "installed_version": None,
                },
            )
        )
        readiness = readiness_by_id.get(tool["id"])
        if tool.get("source") == "internal":
            readiness_payload = {
                "binary": {"state": "ready", "reason": None, "component_ids": []},
                "data": {"state": "not_required", "reason": None, "component_ids": []},
                "rules": {"state": "not_required", "reason": None, "component_ids": []},
                "execution": {"state": "ready", "reason": None, "component_ids": []},
            }
            runtime_ready = True
        else:
            readiness_payload = (
                {
                    "binary": readiness.binary.model_dump(mode="json"),
                    "data": readiness.data.model_dump(mode="json"),
                    "rules": readiness.rules.model_dump(mode="json"),
                    "execution": readiness.execution.model_dump(mode="json"),
                }
                if readiness is not None
                else None
            )
            runtime_ready = bool(readiness and readiness.ready)
        external_run = next((item for item in external_runs if item["id"] == tool["id"]), None)
        status_value = "skipped"
        if tool["id"] in enabled_tools:
            status_value = external_run["status"] if external_run else "ran"
        tool_runs.append(
            {
                **tool,
                **runtime,
                "enabled": tool["id"] in enabled_tools,
                "findings_count": scanner_counts.get(tool["id"], 0),
                "artifacts_count": len([artifact for artifact in artifacts if artifact.scanner == tool["id"]]),
                "status": status_value,
                "error": external_run.get("error") if external_run else None,
                "exit_code": external_run.get("exit_code") if external_run else None,
                "parse_integrity": external_run.get("parse_integrity") if external_run else None,
                "readiness": readiness_payload,
                "runtime_ready": runtime_ready,
                "cache_generation_id": cache_generation_id,
            }
        )

    return ScanResponse(
        status=status,
        findings=findings,
        artifacts=artifacts,
        summary={
            "engine": "kodesec-worker",
            "requested_mode": payload.mode,
            "effective_mode": effective_mode,
            "scope": (
                {"kind": payload.target_kind, "target_path": payload.target_path}
                if payload.target_path is not None
                else {"kind": "workspace"}
            ),
            "files_considered": len(source_coverage.selected_files),
            "changed_files_count": changed_count,
            "source_coverage": source_coverage.as_receipt(),
            **(
                {"source_capture": directory_capture.as_receipt()}
                if directory_capture is not None
                else {}
            ),
            **({"gitleaks_source_capture": {
                **gitleaks_capture.as_receipt(),
                "inventory_schema": "lomo-gitleaks-captured-inventory/v1",
                "inventory_sha256": gitleaks_capture.inventory_sha256,
                "directory_exclusion_policy": "gitleaks-8.30.1-dotgit",
            }} if gitleaks_capture is not None else {}),
            "findings_total": len(findings),
            "severity_counts": severity_counts,
            "scanner_counts": scanner_counts,
            "tools": tool_runs,
            "artifacts": [artifact.model_dump() for artifact in artifacts],
            "external_runs": external_runs,
            "cache_generation": {
                "generation_id": cache_generation_id,
                "manifest_sha256": cache_manifest_sha256,
                "component_ids": resolved_component_ids,
            },
            "warnings": warnings,
            "errors": errors,
        },
    )


def _execute_runtime_scan(payload: ScanRequest, control: ExecutionControl) -> ScanResponse:
    return _execute_scan(payload, control, resolver=_runtime_verifier().resolve)


run_registry = RunRegistry(
    _execute_runtime_scan,
    deadline_seconds=settings.run_deadline_seconds,
    retention_seconds=settings.run_result_retention_seconds,
    max_terminal_records=settings.run_result_max_records,
    result_dir=settings.run_result_dir,
    max_findings=settings.run_result_max_findings,
    max_item_bytes=settings.run_result_max_item_bytes,
    max_page_bytes=settings.run_result_max_page_bytes,
    max_run_bytes=settings.run_result_max_run_bytes,
    max_total_bytes=settings.run_result_max_total_bytes,
    max_active_runs=settings.max_active_runs,
    termination_grace_seconds=settings.process_termination_grace_seconds,
    shutdown_wait_seconds=settings.shutdown_wait_seconds,
)


@app.post("/runs", response_model=RunStateResponse, status_code=202)
def start_run(payload: RunStartRequest) -> RunStateResponse:
    try:
        return run_registry.start(payload)
    except RunConflictError as exc:
        raise HTTPException(
            409,
            {
                "code": "run_id_conflict",
                "message": "run_id is already bound to a different request",
            },
        ) from exc
    except RunCapacityError as exc:
        raise HTTPException(
            409,
            {
                "code": "scanner_capacity",
                "message": "scanner active-run capacity is exhausted",
            },
        ) from exc


@app.get("/runs", response_model=RunListResponse)
def list_runs(active_only: bool = False) -> RunListResponse:
    return RunListResponse(runs=run_registry.list(active_only=active_only))


@app.get("/runs/{run_id}", response_model=RunStateResponse)
def get_run(run_id: UUID) -> RunStateResponse:
    try:
        return run_registry.get(run_id)
    except RunNotFoundError as exc:
        raise HTTPException(404, "scanner run was not found or its recovery window expired") from exc
    except RunResultStorageError as exc:
        raise HTTPException(500, "scanner run recovery state failed its integrity check") from exc


@app.get("/runs/{run_id}/findings", response_model=RunFindingPageResponse)
def get_run_findings(
    run_id: UUID,
    request_digest: str = Query(pattern=r"^[0-9a-f]{64}$"),
    cursor: str | None = Query(default=None, min_length=1, max_length=2048),
    limit: int = Query(default=RUN_RESULT_PAGE_LIMIT, ge=1, le=RUN_RESULT_PAGE_LIMIT),
) -> RunFindingPageResponse:
    # FastAPI parses typed query values first; the strict internal model then
    # prevents coercion if this function is called outside ASGI.
    try:
        request = RunFindingPageRequest(
            request_digest=request_digest,
            cursor=cursor,
            limit=limit,
        )
        return run_registry.page(run_id, request)
    except ValidationError as exc:
        raise HTTPException(422, "scanner finding-page request is invalid") from exc
    except RunNotFoundError as exc:
        raise HTTPException(404, "scanner run was not found or its recovery window expired") from exc
    except RunConflictError as exc:
        raise HTTPException(
            409,
            {"code": "run_id_conflict", "message": "run identity or result binding does not match"},
        ) from exc
    except RunCursorError as exc:
        raise HTTPException(422, "scanner finding cursor is invalid or stale") from exc
    except RunResultUnavailableError as exc:
        raise HTTPException(410, "scanner result was acknowledged or is unavailable") from exc
    except RunResultStorageError as exc:
        raise HTTPException(500, "scanner result failed its sealed integrity check") from exc


@app.post("/runs/{run_id}/result/ack", response_model=RunResultAckResponse)
def acknowledge_run_result(
    run_id: UUID,
    payload: RunResultAckRequest,
) -> RunResultAckResponse:
    try:
        return run_registry.acknowledge(run_id, payload)
    except RunNotFoundError as exc:
        raise HTTPException(404, "scanner run was not found or its recovery window expired") from exc
    except RunConflictError as exc:
        raise HTTPException(
            409,
            {"code": "run_id_conflict", "message": "run identity or result binding does not match"},
        ) from exc
    except RunResultUnavailableError as exc:
        raise HTTPException(409, "scanner run has no completed result to acknowledge") from exc
    except RunResultStorageError as exc:
        raise HTTPException(500, "scanner result could not be discarded safely") from exc


@app.delete("/runs/{run_id}", response_model=RunStateResponse, status_code=202)
def cancel_run(
    run_id: UUID,
    request_digest: str | None = None,
    result_digest: str | None = None,
) -> RunStateResponse:
    if request_digest is not None and re.fullmatch(r"[0-9a-f]{64}", request_digest) is None:
        raise HTTPException(422, "request_digest must be a lowercase SHA-256 digest")
    if result_digest is not None and re.fullmatch(r"[0-9a-f]{64}", result_digest) is None:
        raise HTTPException(422, "result_digest must be a lowercase SHA-256 digest")
    if result_digest is not None and request_digest is None:
        raise HTTPException(422, "result_digest requires request_digest")
    try:
        return run_registry.cancel(
            run_id,
            request_digest=request_digest,
            result_digest=result_digest,
        )
    except RunNotFoundError as exc:
        raise HTTPException(404, "scanner run was not found or its recovery window expired") from exc
    except RunConflictError as exc:
        raise HTTPException(
            409,
            {
                "code": "run_id_conflict",
                "message": "run_id is already bound to a different request",
            },
        ) from exc
