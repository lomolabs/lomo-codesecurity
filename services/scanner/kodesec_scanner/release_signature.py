"""One stdlib-only, offline Cosign boundary shared by launcher and updater.

Trust is supplied by reviewed release configuration, never by the artifact.
Verified bytes are returned so callers cannot accidentally parse a replacement.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
from typing import Callable, NamedTuple

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_TRUST_ROOT_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024


class SignatureVerificationError(ValueError):
    """Only fixed, non-secret diagnostics cross the verification boundary."""

    def __init__(self, code: str):
        if code not in {"trust", "file", "changed", "signature", "timeout", "executable"}:
            raise ValueError("unrecognized signature verification failure")
        self.code = code
        super().__init__(f"release signature verification failed: {code}")


class CosignTrust(NamedTuple):
    executable: Path
    executable_sha256: str
    trusted_root: Path
    trusted_root_sha256: str
    certificate_identity: str
    oidc_issuer: str


class VerifiedBlob(NamedTuple):
    artifact: bytes
    sha256: str
    bundle_sha256: str
    trust_sha256: str


def _read_file(path: Path, limit: int) -> bytes:
    try:
        if not path.is_absolute():
            raise SignatureVerificationError("file")
        for parent in (path, *path.parents):
            if parent.is_symlink():
                raise SignatureVerificationError("file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
                raise SignatureVerificationError("file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ) or len(raw) != before.st_size:
                raise SignatureVerificationError("changed")
            return raw
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SignatureVerificationError("file") from exc


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _immutable_executable(path: Path) -> bool:
    """The scanner's executable belongs to its read-only image, never tmpfs."""
    if os.name != "posix":
        return False
    metadata = path.stat()
    return (metadata.st_uid in {0, os.getuid()} and not metadata.st_mode & 0o022
        and bool(metadata.st_mode & 0o111)
        and bool(os.statvfs(path).f_flag & os.ST_RDONLY))


def _executable_identity(path: Path) -> tuple[int, ...]:
    item = path.stat()
    return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _stop(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def verify_blob(
    artifact: Path, bundle: Path, trust: CosignTrust, *,
    checkpoint: Callable[[], object] | None = None,
    timeout_seconds: float = 30,
) -> VerifiedBlob:
    """Verify a bounded Sigstore bundle against exact offline trust and pins.

    No executable lookup, TUF/network refresh, regex identity, shell, ambient
    proxy/token configuration, or unbounded process output is admitted.
    Cancellation exceptions retain their identity after child cleanup.
    """
    if not isinstance(trust, CosignTrust) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (trust.executable_sha256, trust.trusted_root_sha256)
    ) or any(
        not isinstance(value, str) or not 1 <= len(value) <= 2048 or
        not value.startswith("https://") or any(ord(char) < 33 or ord(char) > 126 for char in value)
        for value in (trust.certificate_identity, trust.oidc_issuer)
    ):
        raise SignatureVerificationError("trust")
    if isinstance(timeout_seconds, bool) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise SignatureVerificationError("trust")
    if checkpoint is not None:
        checkpoint()
    raw = _read_file(artifact, MAX_ARTIFACT_BYTES)
    signed_bundle = _read_file(bundle, MAX_BUNDLE_BYTES)
    trusted_root = _read_file(trust.trusted_root, MAX_TRUST_ROOT_BYTES)
    executable = _read_file(trust.executable, MAX_EXECUTABLE_BYTES)
    if _digest(trusted_root) != trust.trusted_root_sha256:
        raise SignatureVerificationError("trust")
    if _digest(executable) != trust.executable_sha256:
        raise SignatureVerificationError("executable")
    if not _immutable_executable(trust.executable):
        raise SignatureVerificationError("executable")
    executable_identity = _executable_identity(trust.executable)
    del executable
    # Private noexec tmpfs contains only bounded data. The pinned Cosign binary
    # stays on the immutable image filesystem; it is never copied or installed.
    with tempfile.TemporaryDirectory(prefix="kodesec-signature-") as private:
        directory = Path(private)
        names = {"artifact": raw, "bundle": signed_bundle, "trusted-root": trusted_root}
        for name, contents in names.items():
            destination = directory / name
            with destination.open("xb") as stream:
                stream.write(contents)
            destination.chmod(0o600)
        command = [str(trust.executable), "verify-blob", "--offline", "--bundle", str(directory / "bundle"),
                   "--trusted-root", str(directory / "trusted-root"),
                   "--certificate-identity", trust.certificate_identity,
                   "--certificate-oidc-issuer", trust.oidc_issuer, str(directory / "artifact")]
        environment = {"HOME": str(directory), "TMPDIR": str(directory), "NO_COLOR": "1"}
        try:
            if _executable_identity(trust.executable) != executable_identity:
                raise SignatureVerificationError("changed")
            process = subprocess.Popen(command, cwd=directory, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=os.name == "posix")
        except OSError as exc:
            raise SignatureVerificationError("executable") from exc
        try:
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if checkpoint is not None:
                    checkpoint()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SignatureVerificationError("timeout")
                try:
                    process.wait(timeout=min(remaining, 0.05))
                except subprocess.TimeoutExpired:
                    pass
            if process.returncode != 0:
                raise SignatureVerificationError("signature")
            if _executable_identity(trust.executable) != executable_identity:
                raise SignatureVerificationError("changed")
            if checkpoint is not None:
                checkpoint()
        finally:
            _stop(process)
    return VerifiedBlob(raw, _digest(raw), _digest(signed_bundle), _digest(trusted_root))
