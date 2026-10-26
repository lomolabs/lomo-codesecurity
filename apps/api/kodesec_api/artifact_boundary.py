from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Runtime
from .models import Job, RuntimeConfig, Scan, ScanArtifact
from .redaction import has_source_path_credentials, redact_json
from .settings import Settings


ARTIFACT_BOUNDARY_MARKER = "artifact_publication_boundary.ready"
MAX_PUBLISHABLE_SBOM_BYTES = 8 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]+\Z")
_CYCLONEDX_HASH_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}
_STABLE_SOURCE_NAME = "source"
_STABLE_SOURCE_BOM_REF = "urn:kodesec:source"


def _cyclonedx_hash_content(value: dict[Any, Any]) -> str | None:
    """Return one canonical standard hash value, never a hash-shaped lookalike."""

    if set(value) != {"alg", "content"}:
        return None
    algorithm = value.get("alg")
    content = value.get("content")
    expected_length = (
        _CYCLONEDX_HASH_LENGTHS.get(algorithm)
        if isinstance(algorithm, str)
        else None
    )
    if (
        expected_length is None
        or not isinstance(content, str)
        or len(content) != expected_length
        or _HEX_DIGEST.fullmatch(content) is None
    ):
        return None
    return content.lower()


def _cyclonedx_source_location(value: dict[Any, Any]) -> str | None:
    """Preserve only Syft's bounded, typed relative source location."""

    if set(value) != {"name", "value"}:
        return None
    name, path = value.get("name"), value.get("value")
    if (
        not isinstance(name, str)
        or re.fullmatch(r"syft:location:(?:0|[1-9][0-9]*):path", name) is None
        or not isinstance(path, str)
        or not path
        or path != path.strip()
        or path.startswith("/")
        or ":" in path
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in path)
    ):
        return None
    if len(path.encode("utf-8")) > 4096:
        return None
    if has_source_path_credentials(path):
        return None
    return path


def _redact_cyclonedx(
    value: Any,
    key: str = "",
    *,
    depth: int = 0,
    hash_record: bool = False,
    property_record: bool = False,
) -> Any:
    """Redact evidence while retaining structurally valid SBOM identifiers."""

    if depth >= 64 and isinstance(value, (dict, list)):
        return "[REDACTED]"
    if key and redact_json(None, key) == "[REDACTED]":
        return "[REDACTED]"
    if isinstance(value, dict):
        hash_content = _cyclonedx_hash_content(value) if hash_record else None
        source_location = _cyclonedx_source_location(value) if property_record else None
        return {
            str(item_key): (
                hash_content
                if hash_content is not None and item_key == "content"
                else source_location
                if source_location is not None and item_key == "value"
                else _redact_cyclonedx(item, str(item_key), depth=depth + 1)
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_cyclonedx(
                item,
                depth=depth + 1,
                hash_record=key == "hashes",
                property_record=key == "properties",
            )
            for item in value
        ]
    return redact_json(value, key, _depth=depth)


def _normalize_cyclonedx_source(payload: Any) -> Any:
    """Remove a staged repository path while preserving CycloneDX references."""

    if not isinstance(payload, dict):
        return payload
    metadata = payload.get("metadata")
    source_component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(source_component, dict):
        return payload
    source_name = source_component.get("name")
    if not isinstance(source_name, str):
        return payload
    without_scheme = source_name.removeprefix("file://")
    if not (
        without_scheme.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", without_scheme)
    ):
        return payload
    old_bom_ref = source_component.get("bom-ref")
    path_tokens = {
        source_name,
        without_scheme,
        without_scheme.replace("\\", "/"),
        without_scheme.replace("/", "\\"),
    }
    path_tokens = {token for token in path_tokens if token not in {"", "/", "\\"}}

    def clean_string(value: str) -> str:
        if isinstance(old_bom_ref, str) and value == old_bom_ref:
            return _STABLE_SOURCE_BOM_REF
        for token in sorted(path_tokens, key=len, reverse=True):
            value = value.replace(token, _STABLE_SOURCE_NAME)
        return value

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in value.items():
                normalized_key = clean_string(str(key))
                if normalized_key in result:
                    raise ArtifactBoundaryError(
                        "CycloneDX source normalization produced a key collision"
                    )
                result[normalized_key] = clean(item)
            return result
        if isinstance(value, list):
            return [clean(item) for item in value]
        return clean_string(value) if isinstance(value, str) else value

    normalized = clean(payload)
    normalized_source = normalized["metadata"]["component"]
    normalized_source["name"] = _STABLE_SOURCE_NAME
    normalized_source["bom-ref"] = _STABLE_SOURCE_BOM_REF
    return normalized


class ArtifactBoundaryError(RuntimeError):
    """An artifact path or file failed the local publication contract."""


class ArtifactAttestationError(ArtifactBoundaryError):
    """A durable raw-to-sanitized artifact provenance binding changed."""


@dataclass
class VerifiedArtifactDownload:
    filename: str
    size_bytes: int
    content: BinaryIO


def _owned_root(value: str) -> Path:
    """Return the exact dedicated artifact root without creating broad parents."""

    root = Path(value)
    if (
        not root.is_absolute()
        or ".." in root.parts
        or root.name != "artifacts"
        or len(root.parts) < 3
    ):
        raise ArtifactBoundaryError(
            "artifact publication root must be an absolute dedicated path ending in /artifacts"
        )
    if not _NOFOLLOW or not getattr(os, "O_DIRECTORY", 0):
        raise ArtifactBoundaryError("artifact publication requires no-follow directory operations")

    lexical = root.absolute()
    try:
        parent = lexical.parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactBoundaryError("artifact publication root parent must already exist") from exc
    if parent != lexical.parent or not parent.is_dir():
        raise ArtifactBoundaryError("artifact publication root must not traverse symlink ancestors")

    try:
        metadata = lexical.lstat()
    except FileNotFoundError:
        try:
            lexical.mkdir(mode=0o750)
        except OSError as exc:
            raise ArtifactBoundaryError("artifact publication root could not be created") from exc
        metadata = lexical.lstat()
    except OSError as exc:
        raise ArtifactBoundaryError("artifact publication root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ArtifactBoundaryError("artifact publication root must be a non-symlink directory")
    if lexical.resolve(strict=True) != lexical:
        raise ArtifactBoundaryError("artifact publication root must not traverse symlink ancestors")
    return lexical


def _open_directory(name: str, *, dir_fd: int | None = None) -> int:
    try:
        return os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=dir_fd)
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise ArtifactBoundaryError("artifact directory is missing or unsafe") from exc


def _open_scans_directory(root: Path, *, create: bool) -> tuple[int, int]:
    root_fd = _open_directory(str(root))
    try:
        if create:
            try:
                os.mkdir("scans", mode=0o750, dir_fd=root_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise ArtifactBoundaryError("artifact scans directory could not be created") from exc
        scans_fd = _open_directory("scans", dir_fd=root_fd)
        return root_fd, scans_fd
    except Exception:
        os.close(root_fd)
        raise


def _artifact_location(root: Path, scan_id: int, value: object) -> tuple[str, str] | None:
    """Validate an exact direct child of scans/<scan id>/<tool>."""

    if scan_id < 1 or not isinstance(value, str) or not value or "\x00" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return None
    expected_scan = root / "scans" / str(scan_id)
    try:
        relative = candidate.relative_to(expected_scan)
    except ValueError:
        return None
    if len(relative.parts) != 2:
        return None
    tool, filename = relative.parts
    if tool in {"", ".", ".."} or filename in {"", ".", ".."} or filename.startswith("."):
        return None
    return tool, filename


def _open_tool_directory(root: Path, scan_id: int, tool: str) -> tuple[int, int, int, int]:
    root_fd, scans_fd = _open_scans_directory(root, create=False)
    try:
        scan_fd = _open_directory(str(scan_id), dir_fd=scans_fd)
        try:
            tool_fd = _open_directory(tool, dir_fd=scan_fd)
            return root_fd, scans_fd, scan_fd, tool_fd
        except Exception:
            os.close(scan_fd)
            raise
    except Exception:
        os.close(scans_fd)
        os.close(root_fd)
        raise


def _close_descriptors(*descriptors: int) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_artifact_fd(root: Path, scan_id: int, value: object) -> tuple[int, tuple[int, int, int, int], str]:
    location = _artifact_location(root, scan_id, value)
    if location is None or location[0] != "syft":
        raise ArtifactBoundaryError("artifact path is outside the exact Syft scan directory")
    tool, filename = location
    descriptors = _open_tool_directory(root, scan_id, tool)
    descriptor = -1
    try:
        descriptor = os.open(
            filename,
            os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=descriptors[-1],
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactBoundaryError("artifact is not a regular file")
        return descriptor, descriptors, filename
    except Exception as exc:
        if descriptor >= 0:
            os.close(descriptor)
        _close_descriptors(*descriptors)
        if isinstance(exc, ArtifactBoundaryError):
            raise
        raise ArtifactBoundaryError("artifact file is missing or unsafe") from exc


def _read_bounded(descriptor: int) -> tuple[bytes, int, str]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PUBLISHABLE_SBOM_BYTES:
        raise ArtifactBoundaryError("artifact exceeds the publication limit or is not regular")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, MAX_PUBLISHABLE_SBOM_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_PUBLISHABLE_SBOM_BYTES:
            raise ArtifactBoundaryError("artifact exceeds the publication limit")
    after = os.fstat(descriptor)
    identity_before = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if identity_before != identity_after or total != after.st_size:
        raise ArtifactBoundaryError("artifact changed while it was being read")
    payload = b"".join(chunks)
    return payload, total, hashlib.sha256(payload).hexdigest()


def _parse_cyclonedx(payload: bytes) -> Any:
    try:
        parsed: Any = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactBoundaryError("artifact is not valid UTF-8 CycloneDX JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("bomFormat") != "CycloneDX":
        raise ArtifactBoundaryError("artifact is not a CycloneDX document")
    return parsed


def _render_admitted_cyclonedx(payload: bytes) -> bytes:
    parsed = _parse_cyclonedx(payload)
    return (
        json.dumps(
            _redact_cyclonedx(_normalize_cyclonedx_source(parsed)),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _atomic_rewrite(tool_fd: int, filename: str, payload: bytes) -> tuple[int, str]:
    if len(payload) > MAX_PUBLISHABLE_SBOM_BYTES:
        raise ArtifactBoundaryError("redacted artifact exceeds the publication limit")
    temporary_name = f".admit-{secrets.token_hex(16)}.json"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o640,
            dir_fd=tool_fd,
        )
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fchmod(descriptor, 0o640)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_name, filename, src_dir_fd=tool_fd, dst_dir_fd=tool_fd)
        os.fsync(tool_fd)
        return len(payload), hashlib.sha256(payload).hexdigest()
    except OSError as exc:
        raise ArtifactBoundaryError("artifact could not be atomically admitted") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=tool_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _remove_returned_entry(root: Path, scan_id: int, value: object) -> None:
    """Unlink only a direct entry in this scan's product-owned tool directory."""

    location = _artifact_location(root, scan_id, value)
    if location is None:
        return
    tool, filename = location
    try:
        descriptors = _open_tool_directory(root, scan_id, tool)
    except ArtifactBoundaryError:
        return
    try:
        try:
            os.unlink(filename, dir_fd=descriptors[-1])
        except (FileNotFoundError, IsADirectoryError, OSError):
            pass
    finally:
        _close_descriptors(*descriptors)


def _provenance_record(
    root: Path,
    scan_id: int,
    item: Mapping[str, object],
    *,
    allow_sanitized: bool,
) -> dict[str, object]:
    declaration = {
        "scanner": item.get("scanner"),
        "artifact_type": item.get("artifact_type"),
        "format": item.get("format"),
        "path": item.get("path"),
        "size_bytes": item.get("size_bytes"),
        "sha256": item.get("sha256"),
    }
    invalid = {
        "declaration": declaration,
        "admissible": False,
        "sanitized_size_bytes": None,
        "sanitized_sha256": None,
    }
    if (
        set(item) != set(declaration)
        or item.get("scanner") != "syft"
        or item.get("artifact_type") != "sbom"
        or item.get("format") != "cyclonedx-json"
        or not isinstance(item.get("size_bytes"), int)
        or isinstance(item.get("size_bytes"), bool)
        or not isinstance(item.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
    ):
        return invalid

    descriptor = -1
    descriptors: tuple[int, int, int, int] = ()
    try:
        try:
            descriptor, descriptors, _filename = _open_artifact_fd(
                root,
                scan_id,
                item.get("path"),
            )
            observed, observed_size, observed_digest = _read_bounded(descriptor)
            rendered = _render_admitted_cyclonedx(observed)
        except ArtifactBoundaryError:
            return invalid
        raw_matches = (
            item.get("size_bytes") == observed_size
            and hmac.compare_digest(str(item.get("sha256")), observed_digest)
        )
        sanitized_matches = allow_sanitized and hmac.compare_digest(observed, rendered)
        if not raw_matches and not sanitized_matches:
            return invalid
        return {
            "declaration": declaration,
            "admissible": True,
            "sanitized_size_bytes": len(rendered),
            "sanitized_sha256": hashlib.sha256(rendered).hexdigest(),
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if descriptors:
            _close_descriptors(*descriptors)


def _collect_artifact_provenance(
    root: Path,
    scan_id: int,
    entries: list[Mapping[str, object]],
    *,
    allow_sanitized: bool,
) -> tuple[str, list[dict[str, object]]]:
    records = [
        _provenance_record(root, scan_id, item, allow_sanitized=allow_sanitized)
        for item in entries
    ]
    encoded = json.dumps(
        records,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), records


def prepare_scan_artifact_provenance(
    settings: Settings,
    scan_id: int,
    entries: object,
    *,
    expected_digest: str | None = None,
) -> str:
    """Seal one complete ordered raw-to-sanitized artifact binding.

    A retry may observe a mixture of declared raw and already-sanitized files,
    but only a binding previously committed in the durable job checkpoint may
    authorize that second form.
    """

    if not isinstance(entries, list) or any(not isinstance(item, Mapping) for item in entries):
        raise ArtifactAttestationError("artifact manifest is not an ordered mapping collection")
    root = _owned_root(settings.artifact_dir)
    digest, _records = _collect_artifact_provenance(
        root,
        scan_id,
        entries,
        allow_sanitized=expected_digest is not None,
    )
    if any(record.get("admissible") is not True for record in _records):
        raise ArtifactAttestationError(
            "artifact manifest contains evidence that cannot be attested"
        )
    if expected_digest is not None and not hmac.compare_digest(digest, expected_digest):
        raise ArtifactAttestationError("artifact provenance changed after its durable checkpoint")
    return digest


def _admit_one(
    root: Path,
    scan_id: int,
    item: Mapping[str, object],
    *,
    expected_record: Mapping[str, object] | None = None,
) -> tuple[str, int, str] | None:
    publishable = (
        item.get("scanner") == "syft"
        and item.get("artifact_type") == "sbom"
        and item.get("format") == "cyclonedx-json"
    )
    path_value = item.get("path")
    if not publishable:
        _remove_returned_entry(root, scan_id, path_value)
        return None

    descriptor = -1
    descriptors: tuple[int, int, int, int] = ()
    try:
        try:
            descriptor, descriptors, filename = _open_artifact_fd(root, scan_id, path_value)
            raw, observed_size, observed_digest = _read_bounded(descriptor)
            rendered = _render_admitted_cyclonedx(raw)
        except ArtifactBoundaryError:
            # Malformed, oversized, missing, or out-of-bound scanner output is
            # rejected as unpublishable evidence. Operational failures after
            # validation must propagate so the durable job cannot report a
            # successful scan while losing an expected artifact.
            _remove_returned_entry(root, scan_id, path_value)
            return None
        if expected_record is not None:
            declaration = {
                "scanner": item.get("scanner"),
                "artifact_type": item.get("artifact_type"),
                "format": item.get("format"),
                "path": item.get("path"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            }
            expected_size = expected_record.get("sanitized_size_bytes")
            expected_digest = expected_record.get("sanitized_sha256")
            rendered_digest = hashlib.sha256(rendered).hexdigest()
            if (
                expected_record.get("declaration") != declaration
                or expected_record.get("admissible") is not True
                or not isinstance(expected_size, int)
                or isinstance(expected_size, bool)
                or not isinstance(expected_digest, str)
                or len(rendered) != expected_size
                or not hmac.compare_digest(rendered_digest, expected_digest)
            ):
                raise ArtifactAttestationError(
                    "artifact changed after complete provenance validation"
                )
            raw_matches = (
                item.get("size_bytes") == observed_size
                and isinstance(item.get("sha256"), str)
                and hmac.compare_digest(str(item.get("sha256")), observed_digest)
            )
            sanitized_matches = (
                observed_size == expected_size
                and hmac.compare_digest(observed_digest, expected_digest)
                and hmac.compare_digest(raw, rendered)
            )
            if not raw_matches and not sanitized_matches:
                raise ArtifactAttestationError(
                    "artifact is neither its declared raw nor sealed sanitized form"
                )
            if sanitized_matches:
                return (
                    str(root / "scans" / str(scan_id) / "syft" / filename),
                    observed_size,
                    observed_digest,
                )
        else:
            declared_size = item.get("size_bytes")
            declared_digest = item.get("sha256")
            if (
                not isinstance(declared_size, int)
                or isinstance(declared_size, bool)
                or declared_size != observed_size
                or not isinstance(declared_digest, str)
                or not hmac.compare_digest(declared_digest, observed_digest)
            ):
                _remove_returned_entry(root, scan_id, path_value)
                return None
            if hmac.compare_digest(raw, rendered):
                return (
                    str(root / "scans" / str(scan_id) / "syft" / filename),
                    observed_size,
                    observed_digest,
                )
        try:
            size, digest = _atomic_rewrite(descriptors[-1], filename, rendered)
        except ArtifactBoundaryError:
            raise
        return str(root / "scans" / str(scan_id) / "syft" / filename), size, digest
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if descriptors:
            _close_descriptors(*descriptors)


def admit_scan_artifacts(
    db: Session,
    settings: Settings,
    scan_id: int,
    entries: object,
    *,
    provenance_digest: str | None = None,
) -> list[ScanArtifact]:
    """Validate, redact, atomically publish, and index scanner-returned artifacts."""

    admitted: list[ScanArtifact] = []
    if not isinstance(entries, list) or not entries:
        return admitted
    root = _owned_root(settings.artifact_dir)
    expected_records: list[dict[str, object]] | None = None
    if provenance_digest is not None:
        observed_digest, expected_records = _collect_artifact_provenance(
            root,
            scan_id,
            entries,
            allow_sanitized=True,
        )
        if not hmac.compare_digest(observed_digest, provenance_digest):
            raise ArtifactAttestationError(
                "artifact provenance changed after its durable checkpoint"
            )
    for index, item in enumerate(entries):
        if not isinstance(item, Mapping):
            if provenance_digest is not None:
                raise ArtifactAttestationError(
                    "artifact manifest changed after strict transport validation"
                )
            continue
        result = _admit_one(
            root,
            scan_id,
            item,
            expected_record=expected_records[index] if expected_records is not None else None,
        )
        if result is None:
            continue
        path, size, digest = result
        artifact = ScanArtifact(
            scan_id=scan_id,
            scanner="syft",
            artifact_type="sbom",
            format="cyclonedx-json",
            path=path,
            size_bytes=size,
            sha256=digest,
        )
        db.add(artifact)
        admitted.append(artifact)
    return admitted


def _delete_descriptor_tree(directory_fd: int, keep: set[tuple[str, ...]], prefix: tuple[str, ...]) -> None:
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        raise ArtifactBoundaryError("artifact scan tree could not be inspected safely") from exc
    for name in names:
        relative = (*prefix, name)
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            if relative in keep:
                # Active scanner runs publish into their dedicated scan tree
                # before the worker can atomically index the terminal result.
                # Keep that exact subtree intact across API restarts.
                continue
            try:
                child_fd = _open_directory(name, dir_fd=directory_fd)
            except ArtifactBoundaryError:
                continue
            try:
                _delete_descriptor_tree(child_fd, keep, relative)
            finally:
                os.close(child_fd)
            try:
                os.rmdir(name, dir_fd=directory_fd)
            except OSError:
                pass
        elif relative not in keep:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass


def _sweep_scans(root: Path, keep: set[tuple[str, ...]]) -> None:
    root_fd, scans_fd = _open_scans_directory(root, create=True)
    try:
        _delete_descriptor_tree(scans_fd, keep, ())
    finally:
        _close_descriptors(root_fd, scans_fd)


def delete_scan_artifact_tree(settings: Settings, scan_id: int) -> None:
    """Delete only the exact product-owned scans/<scan id> subtree."""

    root = _owned_root(settings.artifact_dir)
    root_fd, scans_fd = _open_scans_directory(root, create=True)
    try:
        name = str(scan_id)
        try:
            metadata = os.stat(name, dir_fd=scans_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            scan_fd = _open_directory(name, dir_fd=scans_fd)
            try:
                _delete_descriptor_tree(scan_fd, set(), (name,))
            finally:
                os.close(scan_fd)
            try:
                os.rmdir(name, dir_fd=scans_fd)
            except OSError:
                pass
        else:
            try:
                os.unlink(name, dir_fd=scans_fd)
            except OSError:
                pass
    finally:
        _close_descriptors(root_fd, scans_fd)


def prepare_artifact_download(artifact: ScanArtifact, settings: Settings) -> VerifiedArtifactDownload:
    """Copy one verified no-follow artifact into stable bounded response storage."""

    if (
        artifact.scanner != "syft"
        or artifact.artifact_type != "sbom"
        or artifact.format != "cyclonedx-json"
    ):
        raise ArtifactBoundaryError("artifact is not publishable")
    root = _owned_root(settings.artifact_dir)
    descriptor = -1
    descriptors: tuple[int, int, int, int] = ()
    spool: BinaryIO | None = None
    try:
        descriptor, descriptors, filename = _open_artifact_fd(root, artifact.scan_id, artifact.path)
        before = os.fstat(descriptor)
        if before.st_size > MAX_PUBLISHABLE_SBOM_BYTES:
            raise ArtifactBoundaryError("artifact exceeds the download limit")
        spool = tempfile.SpooledTemporaryFile(max_size=_COPY_CHUNK_BYTES, mode="w+b")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_PUBLISHABLE_SBOM_BYTES:
                raise ArtifactBoundaryError("artifact exceeds the download limit")
            digest.update(chunk)
            spool.write(chunk)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        expected_digest = str(artifact.sha256).lower()
        if (
            before_identity != after_identity
            or size != after.st_size
            or size != artifact.size_bytes
            or len(expected_digest) != 64
            or not hmac.compare_digest(digest.hexdigest(), expected_digest)
        ):
            raise ArtifactBoundaryError("artifact content no longer matches its index")
        spool.seek(0)
        return VerifiedArtifactDownload(filename=filename, size_bytes=size, content=spool)
    except OSError as exc:
        if spool is not None:
            spool.close()
        raise ArtifactBoundaryError("artifact could not be copied into bounded response storage") from exc
    except Exception:
        if spool is not None:
            spool.close()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if descriptors:
            _close_descriptors(*descriptors)


def enforce_artifact_publication_boundary(runtime: Runtime) -> bool:
    """Revalidate attested rows and sweep unreferenced scanner-owned artifacts."""

    root = _owned_root(runtime.settings.artifact_dir)
    with runtime.session_factory() as db:
        first_run = db.get(RuntimeConfig, ARTIFACT_BOUNDARY_MARKER) is None
        keep: set[tuple[str, ...]] = set()
        active_scan_ids = db.scalars(
            select(Job.scan_id).where(
                Job.scan_id.is_not(None),
                Job.kind == "scan",
                Job.status.in_(("queued", "leased", "running", "cancelling")),
            )
        )
        keep.update((str(scan_id),) for scan_id in active_scan_ids if scan_id is not None)
        # Match scanner persistence's parent-first locking: artifact changes
        # and the summary revision must become visible in the same transaction.
        # Lock multiple parents in stable order before revalidating their rows.
        scans = db.scalars(
            select(Scan)
            .where(Scan.id.in_(select(ScanArtifact.scan_id)))
            .order_by(Scan.id.asc())
            .with_for_update()
        )
        for scan in scans:
            changed = False
            for artifact in db.scalars(
                select(ScanArtifact)
                .where(ScanArtifact.scan_id == scan.id)
                .order_by(ScanArtifact.id.asc())
            ):
                item: Mapping[str, object] = {
                    "scanner": artifact.scanner,
                    "artifact_type": artifact.artifact_type,
                    "format": artifact.format,
                    "path": artifact.path,
                    "size_bytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                }
                result = _admit_one(root, scan.id, item)
                if result is None:
                    db.delete(artifact)
                    changed = True
                    continue
                path, size, digest = result
                if (artifact.path, artifact.size_bytes, artifact.sha256) != result:
                    artifact.path = path
                    artifact.size_bytes = size
                    artifact.sha256 = digest
                    changed = True
                location = _artifact_location(root, scan.id, path)
                if location is not None:
                    keep.add((str(scan.id), *location))
            if changed:
                # The finding collection is untouched; invalidate the broader
                # detail snapshot without advancing findings_revision.
                scan.revision += 1
        db.flush()
        _sweep_scans(root, keep)
        if first_run:
            db.add(RuntimeConfig(key=ARTIFACT_BOUNDARY_MARKER, value="completed"))
        db.commit()
        return first_run
