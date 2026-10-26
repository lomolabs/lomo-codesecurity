#!/usr/bin/env python3
"""Produce a deterministic, non-authoritative Grype v6 DB lock proposal.

This host-only review program deliberately separates an offline image/source
preflight, an egress-only source-blind fetch, a source-blind offline import,
and offline Syft-to-Grype semantic canaries.  It never edits the lock or a
product cache.  The final receipt proposes only the six mutable requirement
fields admitted by the review contract.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER_PATH = Path(__file__).resolve()
PRODUCER_RELATIVE_PATH = "scripts/grype-db-lock-candidate.py"
CURRENT_LOCK_PATH = REPO_ROOT / "scanner-tools.lock.json"
POSITIVE_FIXTURE_PATH = REPO_ROOT / "tests/scanner-runtime/fixtures/dependencies/positive"
ZERO_FIXTURE_PATH = REPO_ROOT / "tests/scanner-runtime/fixtures/dependencies/zero"
BUILD_RECEIPT_SCHEMA = "kodesec.scanner-build-receipt/v2"
BUILD_RECEIPT_NAME = "scanner-build-receipt.json"
LISTING_URL = "https://grype.anchore.io/databases/v6/latest.json"
LISTING_FIELDS = frozenset({"status", "schemaVersion", "built", "path", "checksum"})
GRYPE_VERSION = "0.117.0"
SYFT_VERSION = "1.51.0"
GRYPE_PATH = "/usr/local/bin/grype"
SYFT_PATH = "/usr/local/bin/syft"
LOCK_IN_IMAGE = "/usr/local/share/kodesec/locks/scanner-tools.lock.json"
TOOL_MANIFEST_IN_IMAGE = "/usr/local/share/kodesec/tool-manifest.json"
REVIEW_ROOT = "/run/kodesec-grype-review"
MAX_LISTING_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_COMMAND_BYTES = 64 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 64 * 1024
MAX_CANARY_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_CANARY_RESULTS = 10_000
MAX_CANARY_IDS = 512
MAX_CANARY_ID_BYTES = 256
CANARY_OUTPUT_HASH_ALGORITHM = "kodesec-canary-result-v1"
INNER_FAILURE_MARKER = b"kodesec_candidate_failure/v1"
INNER_FAILURE_CODES: Mapping[str, frozenset[str]] = {
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
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA_VERSION = re.compile(r"v6\.[0-9]+\.[0-9]+\Z")
INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
SAFE_ARCHIVE_NAME = re.compile(r"vulnerability-db_v6\.[0-9]+\.[0-9]+_[A-Za-z0-9T:._+-]+\.tar\.zst\Z")
PROXY_KEYS = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}
)
PROPOSED_FIELDS = frozenset(
    {"source", "max_age_seconds", "data_contract", "installed_size_bytes", "installed_content", "canaries"}
)
UNCERTAIN_DOCKER_ERROR_PREFIXES = (
    "docker_process_",
    "docker_container_",
    "docker_cidfile_",
    "docker_lifecycle_",
)


class CandidateError(RuntimeError):
    """A review invariant could not be proved."""


class DockerProcessCleanupUncertain(CandidateError):
    """A daemon-side container operation may still mutate owned state."""


def _load_hardened_host():
    path = REPO_ROOT / "scripts/trivy-db-lock-candidate.py"
    spec = importlib.util.spec_from_file_location("_kodesec_trivy_candidate_host", path)
    if spec is None or spec.loader is None:
        raise CandidateError("hardened_host_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def strict_json(raw: bytes, *, label: str, maximum: int = MAX_RECEIPT_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise CandidateError(f"{label}_size_invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise CandidateError(f"{label}_duplicate_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise CandidateError(f"{label}_nonfinite")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except CandidateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"{label}_json_invalid") from exc
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_regular_file(
    path: Path,
    *,
    label: str,
    maximum: int,
    capture: bool = False,
) -> tuple[bytes | None, dict[str, Any]]:
    """Read one bounded regular file without accepting alias or identity races."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise CandidateError(f"{label}_unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= maximum
    ):
        raise CandidateError(f"{label}_identity_invalid")
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    payload = bytearray() if capture else None
    observed = 0
    try:
        opened = os.fstat(descriptor)
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - observed)):
            observed += len(chunk)
            if observed > maximum:
                raise CandidateError(f"{label}_size_invalid")
            digest.update(chunk)
            if payload is not None:
                payload.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity != after_identity or (opened.st_dev, opened.st_ino) != (
        before.st_dev,
        before.st_ino,
    ) or observed != before.st_size:
        raise CandidateError(f"{label}_changed")
    evidence = {"size_bytes": observed, "sha256": digest.hexdigest()}
    return (bytes(payload) if payload is not None else None), evidence


def semantic_canary_sha256(
    *,
    canary_id: str,
    fixture_sha256: str,
    result_count: int,
    rule_ids: list[str],
) -> str:
    payload = {
        "algorithm": CANARY_OUTPUT_HASH_ALGORITHM,
        "canary_id": canary_id,
        "exit_code": 0,
        "fixture_sha256": fixture_sha256,
        "result_count": result_count,
        "rule_ids": rule_ids,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def grype_result_semantics(payload: Any) -> tuple[int, list[str]]:
    matches = payload.get("matches") if type(payload) is dict else None
    if type(matches) is not list:
        raise CandidateError("canary_output_invalid")
    identifiers: list[str] = []
    for match in matches:
        vulnerability = match.get("vulnerability") if type(match) is dict else None
        identifier = vulnerability.get("id") if type(vulnerability) is dict else None
        if (
            type(identifier) is not str
            or not identifier
            or identifier != identifier.strip()
            or len(identifier) > MAX_CANARY_ID_BYTES
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in identifier)
        ):
            raise CandidateError("canary_result_id_invalid")
        identifiers.append(identifier)
        if len(identifiers) > MAX_CANARY_RESULTS:
            raise CandidateError("canary_result_count_invalid")
    unique = sorted(set(identifiers))
    if len(unique) > MAX_CANARY_IDS:
        raise CandidateError("canary_result_ids_invalid")
    return len(identifiers), unique


def _timestamp(value: Any, *, label: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise CandidateError(f"{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CandidateError(f"{label}_invalid") from exc
    if parsed.tzinfo is None or parsed.astimezone(UTC).isoformat().replace("+00:00", "Z") != value:
        raise CandidateError(f"{label}_invalid")
    return value


def parse_listing(raw: bytes) -> dict[str, str]:
    value = strict_json(raw, label="listing")
    if type(value) is not dict:
        raise CandidateError("listing_shape_invalid")
    item = value
    if set(item) != LISTING_FIELDS or item.get("status") != "active":
        raise CandidateError("listing_fields_invalid")
    schema_version = item.get("schemaVersion")
    checksum = item.get("checksum")
    path = item.get("path")
    if type(schema_version) is not str or not SCHEMA_VERSION.fullmatch(schema_version):
        raise CandidateError("listing_schema_invalid")
    if type(checksum) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
        raise CandidateError("listing_checksum_invalid")
    if type(path) is not str:
        raise CandidateError("listing_path_invalid")
    built = _timestamp(item.get("built"), label="listing_built")
    return {"status": "active", "schemaVersion": schema_version, "built": built, "path": path, "checksum": checksum}


def resolve_archive_url(relative_path: str) -> str:
    if not relative_path or "\\" in relative_path or any(ord(char) < 0x20 for char in relative_path):
        raise CandidateError("listing_path_unsafe")
    parsed = urllib.parse.urlsplit(relative_path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or relative_path.startswith("/"):
        raise CandidateError("listing_path_unsafe")
    pure = PurePosixPath(relative_path)
    if len(pure.parts) != 1 or any(part in {"", ".", ".."} for part in pure.parts) or not SAFE_ARCHIVE_NAME.fullmatch(pure.name):
        raise CandidateError("listing_path_unsafe")
    resolved = urllib.parse.urljoin(LISTING_URL, relative_path)
    target = urllib.parse.urlsplit(resolved)
    if target.scheme != "https" or target.hostname != "grype.anchore.io" or target.port not in {None, 443}:
        raise CandidateError("archive_url_unsafe")
    if not target.path.startswith("/databases/v6/") or urllib.parse.unquote(target.path) != target.path:
        raise CandidateError("archive_url_unsafe")
    return resolved


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise CandidateError("http_redirect_rejected")


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _single_header(headers: Any, name: str) -> str:
    values = headers.get_all(name, [])
    if len(values) != 1 or type(values[0]) is not str:
        raise CandidateError("http_header_invalid")
    return values[0]


def fetch_exact(url: str, *, destination: Path | None, maximum: int, expected_type: str | None = None) -> tuple[bytes | None, int, str]:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise CandidateError("http_url_invalid")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "kodesec-grype-lock-review/1"})
    try:
        response = _opener().open(request, timeout=60)
    except CandidateError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise CandidateError("http_request_failed") from exc
    with response:
        if response.status != 200 or response.geturl() != url:
            raise CandidateError("http_response_invalid")
        if _single_header(response.headers, "Content-Encoding").lower() != "identity" if response.headers.get_all("Content-Encoding", []) else False:
            raise CandidateError("http_encoding_invalid")
        if expected_type is not None and _single_header(response.headers, "Content-Type").split(";", 1)[0].strip().lower() != expected_type:
            raise CandidateError("http_content_type_invalid")
        raw_length = _single_header(response.headers, "Content-Length")
        if not raw_length.isascii() or not raw_length.isdigit() or raw_length.startswith("0"):
            raise CandidateError("http_content_length_invalid")
        length = int(raw_length)
        if length < 1 or length > maximum:
            raise CandidateError("http_content_length_invalid")
        digest = hashlib.sha256()
        received = 0
        captured = bytearray() if destination is None else None
        handle = destination.open("xb") if destination is not None else None
        try:
            while chunk := response.read(min(64 * 1024, length - received + 1)):
                received += len(chunk)
                if received > length:
                    raise CandidateError("http_length_mismatch")
                digest.update(chunk)
                if handle is not None:
                    handle.write(chunk)
                else:
                    assert captured is not None
                    captured.extend(chunk)
            if received != length:
                raise CandidateError("http_length_mismatch")
            if handle is not None:
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if handle is not None:
                handle.close()
        return (bytes(captured) if captured is not None else None, length, digest.hexdigest())


def collect_tree(root: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort(key=lambda item: item.encode())
        files.sort(key=lambda item: item.encode())
        base = Path(current)
        for name in directories:
            path = base / name
            if path.is_symlink():
                raise CandidateError("installed_tree_unsafe")
        for name in files:
            path = base / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CandidateError("installed_tree_unsafe")
            relative = path.relative_to(root).as_posix()
            records.append({"path": relative, "size_bytes": metadata.st_size, "sha256": sha256_file(path)})
    if not records:
        raise CandidateError("installed_tree_empty")
    records.sort(key=lambda item: item["path"].encode())
    return {
        "hash_algorithm": "kodesec-canonical-tree-v1",
        "sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
        "file_count": len(records),
        "size_bytes": sum(item["size_bytes"] for item in records),
        "volatile_paths": [],
    }


def collect_grype_installed_content(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use the runtime's exact logical contract; retain its physical evidence."""
    from kodesec_scanner.cache_manifest import (
        CacheValidationError,
        GrypeContentValidationError,
        GRYPE_LOGICAL_TREE_HASH_ALGORITHM,
        canonical_tree_sha256,
        collect_canonical_tree,
        grype_logical_tree_records,
        verify_grype_logical_content,
    )

    try:
        observed = collect_canonical_tree(root, maximum_files=2)
        logical = verify_grype_logical_content(root, observed.files)
    except CacheValidationError as exc:
        if isinstance(exc, GrypeContentValidationError) and exc.retryable:
            raise CandidateError("installed_tree_validation_timeout") from exc
        raise CandidateError("installed_tree_invalid") from exc
    physical = {
        "hash_algorithm": observed.algorithm,
        "sha256": observed.sha256,
        "file_count": observed.file_count,
        "size_bytes": observed.size_bytes,
        "volatile_paths": [],
    }
    installed = {
        **physical,
        "hash_algorithm": GRYPE_LOGICAL_TREE_HASH_ALGORITHM,
        "sha256": canonical_tree_sha256(grype_logical_tree_records(observed.files, logical)),
    }
    return installed, physical


def seal_tree(root: Path) -> None:
    directories: list[Path] = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        directories.append(base)
        for name in names:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise CandidateError("installed_tree_unsafe")
        for name in files:
            path = base / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CandidateError("installed_tree_unsafe")
            path.chmod(0o400)
    for path in reversed(directories):
        path.chmod(0o500)


def _run(command: Sequence[str], *, environment: Mapping[str, str], cwd: Path | None = None, maximum: int = MAX_COMMAND_BYTES) -> bytes:
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=dict(environment), timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateError("command_failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > maximum or len(completed.stderr) > MAX_COMMAND_STDERR_BYTES:
        raise CandidateError("command_failed")
    return completed.stdout


def _offline_environment(cache: Path, scratch: Path) -> dict[str, str]:
    return {
        "HOME": str(scratch), "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_CACHE_DIR": str(cache),
        "SYFT_CHECK_FOR_APP_UPDATE": "false", "NO_COLOR": "1",
        **{key: "" for key in PROXY_KEYS},
    }


def _tool_record(manifest: Mapping[str, Any], tool: str, version: str, path: str) -> dict[str, str]:
    tools = manifest.get("tools")
    item = tools.get(tool) if type(tools) is dict else None
    if type(item) is not dict or item.get("installed_version") != version or item.get("path") != path:
        raise CandidateError("tool_manifest_invalid")
    digest = item.get("sha256")
    if type(digest) is not str or not SHA256.fullmatch(digest) or sha256_file(Path(path)) != digest:
        raise CandidateError("tool_manifest_invalid")
    return {"version": version, "path": path, "sha256": digest}


def inner_preflight(args: argparse.Namespace) -> dict[str, Any]:
    current_raw = Path(args.current_lock).read_bytes()
    baked_raw = Path(args.baked_lock).read_bytes()
    if current_raw != baked_raw:
        raise CandidateError("lock_binding_mismatch")
    producer_sha = sha256_file(Path(args.producer))
    if producer_sha != args.producer_sha256:
        raise CandidateError("producer_binding_mismatch")
    build_receipt_sha = sha256_file(Path(args.build_receipt))
    if build_receipt_sha != args.build_receipt_file_sha256:
        raise CandidateError("build_receipt_binding_mismatch")
    manifest = strict_json(Path(args.tool_manifest).read_bytes(), label="tool_manifest")
    if type(manifest) is not dict:
        raise CandidateError("tool_manifest_invalid")
    return {
        "schema": "kodesec.grype-db-lock-candidate-preflight/v1", "authoritative": False,
        "invocation_id": args.invocation_id, "current_lock_sha256": hashlib.sha256(current_raw).hexdigest(),
        "baked_lock_sha256": hashlib.sha256(baked_raw).hexdigest(), "producer_sha256": producer_sha,
        "source_commit": args.source_commit, "build_receipt_file_sha256": build_receipt_sha,
        "tools": {"grype": _tool_record(manifest, "grype", GRYPE_VERSION, GRYPE_PATH), "syft": _tool_record(manifest, "syft", SYFT_VERSION, SYFT_PATH)},
    }


def inner_fetch(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output_dir)
    if any(value for key, value in os.environ.items() if key in PROXY_KEYS and value):
        raise CandidateError("proxy_environment_rejected")
    listing_raw, listing_length, listing_sha = fetch_exact(LISTING_URL, destination=None, maximum=MAX_LISTING_BYTES, expected_type="application/json")
    assert listing_raw is not None
    listing = parse_listing(listing_raw)
    archive_url = resolve_archive_url(listing["path"])
    listing_path = output / "latest.json"
    listing_path.write_bytes(listing_raw)
    listing_path.chmod(0o400)
    archive_path = output / "vulnerability-db.tar.zst"
    _, archive_length, archive_sha = fetch_exact(archive_url, destination=archive_path, maximum=MAX_ARCHIVE_BYTES, expected_type="application/zstd")
    if archive_sha != listing["checksum"].removeprefix("sha256:"):
        raise CandidateError("archive_checksum_mismatch")
    archive_path.chmod(0o400)
    return {
        "schema": "kodesec.grype-db-lock-candidate-fetch/v1", "authoritative": False, "invocation_id": args.invocation_id,
        "listing": {"url": LISTING_URL, "size_bytes": listing_length, "sha256": listing_sha, "entry": listing},
        "archive": {"resolved_url": archive_url, "content_type": "application/zstd", "content_length": archive_length, "size_bytes": archive_length, "sha256": archive_sha},
    }


def inner_import(args: argparse.Namespace) -> dict[str, Any]:
    archive = Path(args.archive)
    cache = Path(args.cache)
    scratch = Path(args.scratch)
    if not cache.is_dir() or cache.is_symlink() or any(cache.iterdir()):
        raise CandidateError("candidate_cache_invalid")
    _, archive_before = stable_regular_file(
        archive,
        label="archive",
        maximum=MAX_ARCHIVE_BYTES,
    )
    environment = _offline_environment(cache, scratch)
    _run((GRYPE_PATH, "db", "import", str(archive)), environment=environment)
    _, archive_after = stable_regular_file(
        archive,
        label="archive",
        maximum=MAX_ARCHIVE_BYTES,
    )
    if archive_after != archive_before:
        raise CandidateError("archive_changed_during_import")
    raw = _run((GRYPE_PATH, "db", "status", "-o", "json"), environment=environment, maximum=MAX_RECEIPT_BYTES)
    status_value = strict_json(raw, label="grype_status")
    expected = {"schemaVersion", "from", "built", "path", "valid"}
    if type(status_value) is not dict or set(status_value) != expected or status_value.get("from") != "manual import" or status_value.get("valid") is not True:
        raise CandidateError("grype_status_invalid")
    if type(status_value.get("schemaVersion")) is not str or not SCHEMA_VERSION.fullmatch(status_value["schemaVersion"]):
        raise CandidateError("grype_status_invalid")
    _timestamp(status_value.get("built"), label="grype_status_built")
    status_path = Path(status_value.get("path", ""))
    try:
        status_path.resolve(strict=True).relative_to(cache.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise CandidateError("grype_status_path_unsafe") from exc
    installed, physical = collect_grype_installed_content(cache)
    seal_tree(cache)
    return {
        "schema": "kodesec.grype-db-lock-candidate-import/v1",
        "authoritative": False,
        "invocation_id": args.invocation_id,
        "archive": archive_after,
        "status": status_value,
        "installed_content": installed,
        "physical_content": physical,
    }


def _canary(fixture: Path, *, cache: Path, scratch: Path, canary_id: str, expect_positive: bool) -> dict[str, Any]:
    environment = _offline_environment(cache, scratch)
    sbom = scratch / f"{canary_id}.cdx.json"
    result = scratch / f"{canary_id}.grype.json"
    fixture_sha256 = collect_tree(fixture)["sha256"]
    _run((SYFT_PATH, f"dir:{fixture}", "-o", f"cyclonedx-json={sbom}"), environment=environment)
    _run((GRYPE_PATH, f"sbom:{sbom}", "-o", "json", "--file", str(result)), environment=environment)
    raw, _ = stable_regular_file(
        result,
        label="grype_canary",
        maximum=MAX_CANARY_OUTPUT_BYTES,
        capture=True,
    )
    assert raw is not None
    payload = strict_json(
        raw,
        label="grype_canary",
        maximum=MAX_CANARY_OUTPUT_BYTES,
    )
    result_count, ids = grype_result_semantics(payload)
    if (expect_positive and result_count == 0) or (not expect_positive and result_count != 0):
        raise CandidateError("canary_semantics_invalid")
    return {
        "id": canary_id, "fixture_path": f"dependencies/{'positive' if expect_positive else 'zero'}", "fixture_kind": "tree",
        "fixture_hash_algorithm": "kodesec-canonical-tree-v1", "fixture_sha256": fixture_sha256,
        "output_sha256": semantic_canary_sha256(
            canary_id=canary_id,
            fixture_sha256=fixture_sha256,
            result_count=result_count,
            rule_ids=ids,
        ),
        "expected_exit_code": 0, "expected_result_count": result_count, "expected_ids": ids,
    }


def inner_canary(args: argparse.Namespace) -> dict[str, Any]:
    cache, scratch = Path(args.cache), Path(args.scratch)
    candidate_tree = collect_tree(cache)
    canaries = [
        _canary(Path(args.positive_fixture), cache=cache, scratch=scratch, canary_id="sbom-vulnerabilities-positive", expect_positive=True),
        _canary(Path(args.zero_fixture), cache=cache, scratch=scratch, canary_id="sbom-vulnerabilities-zero", expect_positive=False),
    ]
    if collect_tree(cache) != candidate_tree:
        raise CandidateError("installed_tree_changed_during_canary")
    return {
        "schema": "kodesec.grype-db-lock-candidate-canary/v1", "authoritative": False, "invocation_id": args.invocation_id,
        "candidate_tree": candidate_tree,
        "canaries": canaries,
    }


def _mount(source: Path, target: str, *, readonly: bool) -> str:
    source = source.resolve(strict=True)
    if "," in str(source) or "=" in str(source):
        raise CandidateError("mount_source_unsafe")
    return f"type=bind,source={source},target={target}" + (",readonly" if readonly else "")


def docker_argv(*, image_id: str, identity: Any, invocation_id: str, phase: str, run_identity: Any, mounts: Sequence[str], network: str, arguments: Sequence[str]) -> tuple[str, ...]:
    if phase not in {"preflight", "fetch", "import", "canary"} or network not in {"none", "bridge"}:
        raise CandidateError("docker_phase_invalid")
    name = f"kodesec-grype-db-{invocation_id}-{phase}"
    if run_identity.name != name or run_identity.cidfile.name != f"{name}.cid":
        raise CandidateError("docker_run_identity_invalid")
    # Grype stages its uncompressed v6 SQLite database in /tmp during import;
    # keep that proven requirement bounded without enlarging any other phase.
    temporary_size = "4g" if phase == "import" else "64m"
    command = [
        "docker", "run", "--rm", "--name", name, "--cidfile", str(run_identity.cidfile), "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
        f"--user={identity.uid}:{identity.gid}", "--entrypoint=/usr/local/bin/python", "--pull=never", f"--network={network}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={temporary_size},mode=0700,uid={identity.uid},gid={identity.gid}",
        f"--tmpfs={REVIEW_ROOT}/scratch:rw,noexec,nosuid,nodev,size=128m,mode=0700,uid={identity.uid},gid={identity.gid}",
    ]
    command.extend(f"--env={key}=" for key in sorted(PROXY_KEYS))
    for mount in mounts:
        command.extend(("--mount", mount))
    command.extend((image_id, "-I", "-B", f"{REVIEW_ROOT}/producer.py", f"internal-{phase}", *arguments))
    return tuple(command)


def phase_argv(
    phase: str,
    *,
    image_id: str,
    identity: Any,
    invocation_id: str,
    run_identity: Any,
    output_dir: Path,
    producer_sha256: str,
    build_receipt_path: Path | None = None,
    build_receipt_file_sha256: str | None = None,
    source_commit: str | None = None,
) -> tuple[str, ...]:
    producer_mount = _mount(PRODUCER_PATH, f"{REVIEW_ROOT}/producer.py", readonly=True)
    common = ("--invocation-id", invocation_id)
    if phase == "preflight":
        if build_receipt_path is None or build_receipt_file_sha256 is None or source_commit is None:
            raise CandidateError("preflight_binding_missing")
        mounts = (
            producer_mount, _mount(CURRENT_LOCK_PATH, f"{REVIEW_ROOT}/current-lock.json", readonly=True),
            _mount(build_receipt_path, f"{REVIEW_ROOT}/scanner-build-receipt.json", readonly=True),
        )
        arguments = (*common, "--current-lock", f"{REVIEW_ROOT}/current-lock.json", "--baked-lock", LOCK_IN_IMAGE, "--tool-manifest", TOOL_MANIFEST_IN_IMAGE, "--producer", f"{REVIEW_ROOT}/producer.py", "--producer-sha256", producer_sha256, "--build-receipt", f"{REVIEW_ROOT}/scanner-build-receipt.json", "--build-receipt-file-sha256", build_receipt_file_sha256, "--source-commit", source_commit)
        return docker_argv(image_id=image_id, identity=identity, invocation_id=invocation_id, phase=phase, run_identity=run_identity, mounts=mounts, network="none", arguments=arguments)
    if phase == "fetch":
        mounts = (producer_mount, _mount(output_dir, f"{REVIEW_ROOT}/output", readonly=False))
        return docker_argv(image_id=image_id, identity=identity, invocation_id=invocation_id, phase=phase, run_identity=run_identity, mounts=mounts, network="bridge", arguments=(*common, "--output-dir", f"{REVIEW_ROOT}/output"))
    if phase == "import":
        mounts = (producer_mount, _mount(output_dir / "vulnerability-db.tar.zst", f"{REVIEW_ROOT}/vulnerability-db.tar.zst", readonly=True), _mount(output_dir / "candidate-db", f"{REVIEW_ROOT}/candidate-db", readonly=False))
        return docker_argv(image_id=image_id, identity=identity, invocation_id=invocation_id, phase=phase, run_identity=run_identity, mounts=mounts, network="none", arguments=(*common, "--archive", f"{REVIEW_ROOT}/vulnerability-db.tar.zst", "--cache", f"{REVIEW_ROOT}/candidate-db", "--scratch", f"{REVIEW_ROOT}/scratch"))
    if phase == "canary":
        mounts = (producer_mount, _mount(output_dir / "candidate-db", f"{REVIEW_ROOT}/candidate-db", readonly=True), _mount(POSITIVE_FIXTURE_PATH, f"{REVIEW_ROOT}/positive", readonly=True), _mount(ZERO_FIXTURE_PATH, f"{REVIEW_ROOT}/zero", readonly=True))
        return docker_argv(image_id=image_id, identity=identity, invocation_id=invocation_id, phase=phase, run_identity=run_identity, mounts=mounts, network="none", arguments=(*common, "--cache", f"{REVIEW_ROOT}/candidate-db", "--scratch", f"{REVIEW_ROOT}/scratch", "--positive-fixture", f"{REVIEW_ROOT}/positive", "--zero-fixture", f"{REVIEW_ROOT}/zero"))
    raise CandidateError("docker_phase_invalid")


def _git_clean_commit() -> str:
    commands = (("git", "status", "--porcelain=v1", "--untracked-files=all"), ("git", "rev-parse", "HEAD"), ("git", "ls-files", "--error-unmatch", PRODUCER_RELATIVE_PATH))
    outputs = []
    for command in commands:
        completed = subprocess.run(command, cwd=REPO_ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
        if completed.returncode != 0 or len(completed.stdout) > MAX_RECEIPT_BYTES:
            raise CandidateError("source_identity_unavailable")
        outputs.append(completed.stdout)
    if outputs[0] != b"":
        raise CandidateError("source_not_clean")
    commit = outputs[1].decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or outputs[2].decode().strip() != PRODUCER_RELATIVE_PATH:
        raise CandidateError("source_identity_invalid")
    return commit


def _revalidate_source(host: Any, build: Mapping[str, Any], *, commit: str, producer_sha256: str) -> None:
    if _git_clean_commit() != commit or sha256_file(PRODUCER_PATH) != producer_sha256:
        raise CandidateError("source_binding_changed")
    if host._collect_build_inputs(identity=host.require_host_identity()) != build["inputs_after"]:
        raise CandidateError("build_source_binding_changed")


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    value = dict(receipt)
    value["receipt_sha256"] = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)


def _raise_host_candidate_error(exc: BaseException) -> None:
    message = str(exc)
    if message.startswith(UNCERTAIN_DOCKER_ERROR_PREFIXES):
        raise DockerProcessCleanupUncertain(message) from exc
    raise CandidateError(message) from exc


def _create_lifecycle_directory(
    host: Any,
    output_dir: Path,
    *,
    invocation_id: str,
    identity: Any,
) -> Path:
    try:
        return host._create_lifecycle_directory(
            output_dir,
            invocation_id=invocation_id,
            identity=identity,
            component_id="grype-db",
        )
    except host.CandidateCliError as exc:
        _raise_host_candidate_error(exc)


def _remove_lifecycle_directory(host: Any, path: Path, *, identity: Any) -> None:
    try:
        host._remove_lifecycle_directory(path, identity=identity)
    except host.CandidateCliError as exc:
        _raise_host_candidate_error(exc)


def _run_phase(host: Any, argv: tuple[str, ...], *, run_identity: Any, identity: Any, phase: str) -> bytes:
    try:
        completed = host.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=identity,
            timeout_seconds=900,
        )
        return host._receipt_stdout(completed, label=phase)
    except host.DockerProcessCleanupUncertain as exc:
        raise DockerProcessCleanupUncertain(str(exc)) from exc
    except host.CandidateCliError as exc:
        _raise_host_candidate_error(exc)


def build_final(*, commit: str, build: Mapping[str, Any], preflight: Mapping[str, Any], fetch: Mapping[str, Any], imported: Mapping[str, Any], canary: Mapping[str, Any]) -> dict[str, Any]:
    listing = fetch["listing"]["entry"]
    status = imported["status"]
    if status["schemaVersion"] != listing["schemaVersion"] or status["built"] != listing["built"]:
        raise CandidateError("listing_import_identity_mismatch")
    archive_identity = {
        "size_bytes": fetch["archive"]["size_bytes"],
        "sha256": fetch["archive"]["sha256"],
    }
    if imported.get("archive") != archive_identity:
        raise CandidateError("fetch_import_archive_mismatch")
    if (
        not imported.get("physical_content")
        or canary.get("candidate_tree") != imported["physical_content"]
    ):
        raise CandidateError("import_canary_tree_mismatch")
    invocation_ids = {
        value.get("invocation_id")
        for value in (preflight, fetch, imported, canary)
    }
    invocation_id = next(iter(invocation_ids), None)
    if (
        len(invocation_ids) != 1
        or type(invocation_id) is not str
        or not INVOCATION_ID.fullmatch(invocation_id)
    ):
        raise CandidateError("cross_receipt_invocation_mismatch")
    proposed = {
        "source": {"kind": "https", "discovery_ref": LISTING_URL, "immutable_ref": fetch["archive"]["resolved_url"], "sha256": fetch["archive"]["sha256"], "size_bytes": fetch["archive"]["size_bytes"]},
        "max_age_seconds": 1209600,
        "data_contract": {"kind": "grype-db-status/v1", "schema_version": status["schemaVersion"], "built_at": status["built"], "timestamp_kind": "intrinsic"},
        "installed_size_bytes": imported["installed_content"]["size_bytes"], "installed_content": imported["installed_content"], "canaries": canary["canaries"],
    }
    if set(proposed) != PROPOSED_FIELDS:
        raise CandidateError("proposed_fields_invalid")
    return {
        "schema": "kodesec.grype-db-lock-candidate/v1", "authoritative": False, "component_id": "grype-db",
        "source_commit": commit, "current_lock_sha256": preflight["current_lock_sha256"], "baked_lock_sha256": preflight["baked_lock_sha256"],
        "producer": {"path": PRODUCER_RELATIVE_PATH, "sha256": preflight["producer_sha256"]},
        "build_receipt": {"schema": build["schema"], "receipt_sha256": build["receipt_sha256"]},
        "evidence_receipts": {key: {"schema": value["schema"], "receipt_sha256": value["receipt_sha256"]} for key, value in (("preflight", preflight), ("fetch", fetch), ("import", imported), ("canary", canary))},
        "proposed_replacement": proposed,
    }


def orchestrate(build_receipt_path: Path, output_dir: Path) -> Path:
    host = _load_hardened_host()
    identity = host.require_host_identity()
    output_dir = host.require_new_private_output(output_dir, identity=identity)
    commit = _git_clean_commit()
    build = host.validate_build_receipt(build_receipt_path, identity=identity)
    build_receipt_file_sha = sha256_file(build_receipt_path)
    producer_sha = sha256_file(PRODUCER_PATH)
    producer_records = [item for item in build["inputs_after"]["files"] if item["path"] == PRODUCER_RELATIVE_PATH]
    if len(producer_records) != 1 or producer_records[0]["sha256"] != producer_sha:
        raise CandidateError("build_producer_binding_mismatch")
    host._activate_build_runtime(build, build_receipt_path, identity=identity)
    host._require_owned_build_image(receipt=build)
    invocation_id = os.urandom(16).hex()
    build_cleanup_succeeded = False
    lifecycle_dir: Path | None = None
    preserve_lifecycle = False
    try:
        output_dir.mkdir(mode=0o700)
        output_dir.chmod(0o700)
        host._require_private_directory(output_dir, empty=True, identity=identity)
        lifecycle_dir = _create_lifecycle_directory(
            host,
            output_dir,
            invocation_id=invocation_id,
            identity=identity,
        )
        receipts: dict[str, dict[str, Any]] = {}
        for phase in ("preflight", "fetch"):
            run_identity = host._docker_run_identity(
                invocation_id=invocation_id,
                mode=phase,
                lifecycle_dir=lifecycle_dir,
                component_id="grype-db",
            )
            argv = phase_argv(
                phase, image_id=build["image"]["id"], identity=identity,
                invocation_id=invocation_id, run_identity=run_identity,
                output_dir=output_dir,
                producer_sha256=producer_sha, build_receipt_path=build_receipt_path,
                build_receipt_file_sha256=build_receipt_file_sha, source_commit=commit,
            )
            raw = _run_phase(
                host,
                argv,
                run_identity=run_identity,
                identity=identity,
                phase=phase,
            )
            receipt = strict_json(raw, label=phase)
            if type(receipt) is not dict or receipt.get("invocation_id") != invocation_id:
                raise CandidateError(f"{phase}_receipt_invalid")
            _write_receipt(output_dir / f"{phase}-receipt.json", receipt)
            receipts[phase] = strict_json((output_dir / f"{phase}-receipt.json").read_bytes(), label=phase)
            if phase == "preflight":
                _revalidate_source(host, build, commit=commit, producer_sha256=producer_sha)
                host._require_owned_build_image(receipt=build)
        candidate_db = output_dir / "candidate-db"
        candidate_db.mkdir(mode=0o700)
        for phase in ("import", "canary"):
            run_identity = host._docker_run_identity(
                invocation_id=invocation_id,
                mode=phase,
                lifecycle_dir=lifecycle_dir,
                component_id="grype-db",
            )
            argv = phase_argv(phase, image_id=build["image"]["id"], identity=identity, invocation_id=invocation_id, run_identity=run_identity, output_dir=output_dir, producer_sha256=producer_sha)
            raw = _run_phase(
                host,
                argv,
                run_identity=run_identity,
                identity=identity,
                phase=phase,
            )
            receipt = strict_json(raw, label=phase)
            if type(receipt) is not dict or receipt.get("invocation_id") != invocation_id:
                raise CandidateError(f"{phase}_receipt_invalid")
            _write_receipt(output_dir / f"{phase}-receipt.json", receipt)
            receipts[phase] = strict_json((output_dir / f"{phase}-receipt.json").read_bytes(), label=phase)
        for phase, receipt in receipts.items():
            raw, _ = stable_regular_file(
                output_dir / f"{phase}-receipt.json",
                label=f"{phase}_receipt",
                maximum=MAX_RECEIPT_BYTES,
                capture=True,
            )
            assert raw is not None
            if strict_json(raw, label=phase) != receipt:
                raise CandidateError(f"{phase}_receipt_changed")
        final = build_final(commit=commit, build=build, preflight=receipts["preflight"], fetch=receipts["fetch"], imported=receipts["import"], canary=receipts["canary"])
        _revalidate_source(host, build, commit=commit, producer_sha256=producer_sha)
        host._require_owned_build_image(receipt=build)
        _remove_lifecycle_directory(host, lifecycle_dir, identity=identity)
        lifecycle_dir = None
        host._cleanup_owned_build_image(receipt=build)
        build_cleanup_succeeded = True
        path = output_dir / "candidate-receipt.json"
        _write_receipt(path, final)
        return path
    except DockerProcessCleanupUncertain:
        preserve_lifecycle = True
        raise
    except BaseException as primary:
        if not build_cleanup_succeeded:
            try:
                host._cleanup_owned_build_image(receipt=build)
            except BaseException as cleanup_error:
                preserve_lifecycle = True
                raise DockerProcessCleanupUncertain(
                    "build_image_cleanup_uncertain"
                ) from cleanup_error
        if isinstance(primary, host.CandidateCliError):
            _raise_host_candidate_error(primary)
        raise primary
    finally:
        if lifecycle_dir is not None and not preserve_lifecycle:
            _remove_lifecycle_directory(host, lifecycle_dir, identity=identity)


def _internal_parser(mode: str) -> argparse.ArgumentParser:
    class InternalArgumentParser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            raise CandidateError("arguments_invalid")

    parser = InternalArgumentParser(add_help=False)
    parser.add_argument("--invocation-id", required=True)
    if mode == "preflight":
        parser.add_argument("--current-lock", required=True)
        parser.add_argument("--baked-lock", required=True)
        parser.add_argument("--tool-manifest", required=True)
        parser.add_argument("--producer", required=True)
        parser.add_argument("--producer-sha256", required=True)
        parser.add_argument("--build-receipt", required=True)
        parser.add_argument("--build-receipt-file-sha256", required=True)
        parser.add_argument("--source-commit", required=True)
    elif mode == "fetch":
        parser.add_argument("--output-dir", required=True)
    elif mode == "import":
        parser.add_argument("--archive", required=True)
        parser.add_argument("--cache", required=True)
        parser.add_argument("--scratch", required=True)
    elif mode == "canary":
        parser.add_argument("--cache", required=True)
        parser.add_argument("--scratch", required=True)
        parser.add_argument("--positive-fixture", required=True)
        parser.add_argument("--zero-fixture", required=True)
    return parser


def _inner_failure_code(mode: str, error: CandidateError) -> str:
    """Reduce an internal failure to one phase-local, non-sensitive code."""

    status = str(error)
    if mode == "fetch":
        if status.startswith("http_") or status == "proxy_environment_rejected":
            return "network"
        if status.startswith("listing_") or status == "archive_url_unsafe":
            return "listing"
        if status.startswith("archive_"):
            return "archive"
    elif mode == "import":
        if status.startswith("archive_") or status == "candidate_cache_invalid":
            return "input"
        if status == "installed_tree_validation_timeout":
            return "timeout"
        if status == "command_failed":
            return "command"
        if status.startswith("grype_status_"):
            return "status"
        if status.startswith("installed_tree_"):
            return "tree"
    elif mode == "canary":
        if status == "command_failed":
            return "command"
        if status.startswith(("grype_canary_", "canary_output_", "canary_result_")):
            return "output"
        if status == "canary_semantics_invalid":
            return "semantics"
        if status.startswith("installed_tree_"):
            return "tree"
        if status.endswith("_invalid"):
            return "input"
    return "validation"


def _emit_inner_failure(mode: str, code: str) -> None:
    if code not in INNER_FAILURE_CODES[mode]:
        code = "unexpected"
    sys.stderr.buffer.write(
        INNER_FAILURE_MARKER + f" {mode} {code}\n".encode("ascii")
    )


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        if values and values[0].startswith("internal-"):
            mode = values.pop(0).removeprefix("internal-")
            if mode not in {"preflight", "fetch", "import", "canary"}:
                raise CandidateError("internal_mode_invalid")
            try:
                args = _internal_parser(mode).parse_args(values)
                if not INVOCATION_ID.fullmatch(args.invocation_id):
                    raise CandidateError("invocation_id_invalid")
                result = {
                    "preflight": inner_preflight,
                    "fetch": inner_fetch,
                    "import": inner_import,
                    "canary": inner_canary,
                }[mode](args)
            except CandidateError as exc:
                _emit_inner_failure(mode, _inner_failure_code(mode, exc))
                return 2
            except Exception:
                _emit_inner_failure(mode, "unexpected")
                return 2
            sys.stdout.buffer.write(canonical_json_bytes(result))
            return 0
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--build-receipt", required=True, type=Path)
        parser.add_argument("--output-dir", required=True, type=Path)
        args = parser.parse_args(values)
        path = orchestrate(args.build_receipt, args.output_dir)
        print(f"non-authoritative Grype DB candidate: {path}")
        return 0
    except DockerProcessCleanupUncertain as exc:
        print(f"grype DB lock candidate failed: {exc}", file=sys.stderr)
        return 75
    except CandidateError as exc:
        print(f"grype DB lock candidate failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
