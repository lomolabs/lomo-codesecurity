"""Exact host Docker/Buildx execution contract for scanner evidence producers.

This module is intentionally stdlib-only.  It validates caller-selected
executables, creates invocation-private immutable copies, builds a fixed Docker
environment, and normalizes the stable daemon/builder facts that an independent
observation receipt authorizes.  It never discovers a CLI, context, plugin, or
daemon from ambient process state.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UNIX_HOST = re.compile(r"unix://(/[^\x00\r\n]+)\Z")
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
CONFIG_BYTES = b'{"auths":{}}\n'
FIXED_PATH = "/usr/bin:/bin"


class DockerRuntimeContractError(RuntimeError):
    """The exact Docker runtime boundary could not be established."""


@dataclass(frozen=True)
class ScannerReviewBuildTarget:
    """One explicitly supported host/image pair for scanner review evidence."""

    host_system: str
    host_machine: str
    image_platform: str
    image_architecture: str


def scanner_review_build_target(system: str, machine: str) -> ScannerReviewBuildTarget:
    """Resolve only reviewed native scanner-build hosts; never emulate a target."""

    normalized_system = system.strip()
    normalized_machine = machine.strip().lower()
    if normalized_system == "Darwin" and normalized_machine in {"arm64", "aarch64"}:
        return ScannerReviewBuildTarget("Darwin", "arm64", "linux/arm64", "arm64")
    if normalized_system == "Linux" and normalized_machine in {"x86_64", "amd64"}:
        return ScannerReviewBuildTarget("Linux", "amd64", "linux/amd64", "amd64")
    raise DockerRuntimeContractError("scanner_review_build_host_unsupported")


def owned_local_repo_digests(tag: str, image_id: str, repo_digests: object) -> bool:
    """Admit no digest references except Buildx's exact local owned reference."""

    if repo_digests in (None, []):
        return True
    if (
        not isinstance(repo_digests, list)
        or len(repo_digests) != 1
        or not isinstance(repo_digests[0], str)
        or not image_id.startswith("sha256:")
        or len(image_id) != 71
        or any(character not in "0123456789abcdef" for character in image_id[7:])
        or ":" not in tag
    ):
        return False
    repository = tag.rsplit(":", 1)[0]
    return repository == "lomo-kodesec-scanner" and repo_digests == [
        f"lomo-kodesec-scanner@{image_id}"
    ]


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    docker: Path
    buildx: Path
    home: Path
    docker_config: Path
    buildx_config: Path
    temporary: Path
    docker_host: str
    source_docker: Mapping[str, Any]
    source_buildx: Mapping[str, Any]
    snapshot_docker: Mapping[str, Any]
    snapshot_buildx: Mapping[str, Any]
    socket: Mapping[str, Any]

    def environment(self) -> dict[str, str]:
        return {
            "BUILDX_CONFIG": str(self.buildx_config),
            "DOCKER_CONFIG": str(self.docker_config),
            "DOCKER_HOST": self.docker_host,
            "HOME": str(self.home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": FIXED_PATH,
            "TMPDIR": str(self.temporary),
        }

    def record(self) -> dict[str, Any]:
        return {
            "schema": "kodesec.docker-runtime-execution/v1",
            "docker": {
                "source": dict(self.source_docker),
                "snapshot": dict(self.snapshot_docker),
            },
            "buildx": {
                "source": dict(self.source_buildx),
                "snapshot": dict(self.snapshot_buildx),
            },
            "daemon": {
                "host": self.docker_host,
                "socket": dict(self.socket),
            },
            "environment": self.environment(),
            "policy": {
                "context": "explicit-host-no-context",
                "docker_config_sha256": hashlib.sha256(CONFIG_BYTES).hexdigest(),
                "network_proxy_environment_inherited": False,
                "path_discovery": False,
            },
        }


def canonical_json_bytes(value: Any) -> bytes:
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


def executable_identity(
    path: Path,
    *,
    expected_sha256: str,
    invoking_uid: int,
    label: str,
) -> dict[str, Any]:
    if (
        not path.is_absolute()
        or not SHA256.fullmatch(expected_sha256)
        or path.name in {"", ".", ".."}
    ):
        raise DockerRuntimeContractError(f"{label}_identity_invalid")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DockerRuntimeContractError(f"{label}_unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid not in {0, invoking_uid}
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not before.st_mode & 0o111
        or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES
    ):
        raise DockerRuntimeContractError(f"{label}_unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(before):
            raise DockerRuntimeContractError(f"{label}_changed")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    observed_sha256 = digest.hexdigest()
    if _identity_tuple(after) != _identity_tuple(before):
        raise DockerRuntimeContractError(f"{label}_changed")
    if observed_sha256 != expected_sha256:
        raise DockerRuntimeContractError(f"{label}_sha256_mismatch")
    record = {
        "path": str(path),
        "sha256": observed_sha256,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        "nlink": before.st_nlink,
        "size_bytes": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }
    record["identity_sha256"] = hashlib.sha256(canonical_json_bytes(record)).hexdigest()
    return record


def _socket_identity(docker_host: str, *, invoking_uid: int) -> dict[str, Any]:
    match = UNIX_HOST.fullmatch(docker_host)
    if match is None:
        raise DockerRuntimeContractError("docker_host_invalid")
    supplied = Path(match.group(1))
    try:
        resolved = supplied.resolve(strict=True)
        metadata = resolved.lstat()
        parent = resolved.parent.lstat()
    except OSError as exc:
        raise DockerRuntimeContractError("docker_socket_unavailable") from exc
    if (
        resolved.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, invoking_uid}
        or metadata.st_mode & 0o002
        or resolved.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_mode & 0o002 and not parent.st_mode & stat.S_ISVTX
    ):
        raise DockerRuntimeContractError("docker_socket_unsafe")
    return {
        "path": str(resolved),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _copy_executable(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    invoking_uid: int,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_record = executable_identity(
        source,
        expected_sha256=expected_sha256,
        invoking_uid=invoking_uid,
        label=f"source_{label}",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    target = os.open(destination, flags, 0o500)
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while chunk := os.read(source_fd, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(target, view)
                if written <= 0:
                    raise DockerRuntimeContractError(f"snapshot_{label}_write_failed")
                view = view[written:]
        os.fsync(target)
    finally:
        os.close(source_fd)
        os.close(target)
    destination.chmod(0o500)
    snapshot_record = executable_identity(
        destination,
        expected_sha256=expected_sha256,
        invoking_uid=invoking_uid,
        label=f"snapshot_{label}",
    )
    return source_record, snapshot_record


def prepare_runtime(
    root: Path,
    *,
    docker_executable: Path,
    docker_sha256: str,
    buildx_executable: Path,
    buildx_sha256: str,
    docker_host: str,
    invoking_uid: int,
) -> RuntimePaths:
    if root.exists() or root.is_symlink() or not root.is_absolute():
        raise DockerRuntimeContractError("runtime_root_exists")
    parent = root.parent
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != invoking_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise DockerRuntimeContractError("runtime_parent_not_private")
    root.mkdir(mode=0o700)
    directories = {
        name: root / name
        for name in ("home", "docker-config", "buildx-config", "tmp", "bin")
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    config = directories["docker-config"] / "config.json"
    descriptor = os.open(
        config,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, CONFIG_BYTES)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    docker_snapshot = directories["bin"] / "docker"
    # Docker CLI plugins and multicall distributions dispatch on argv[0].
    # Preserve the standard standalone plugin basename in the private snapshot.
    buildx_snapshot = directories["bin"] / "docker-buildx"
    source_docker, snapshot_docker = _copy_executable(
        docker_executable,
        docker_snapshot,
        expected_sha256=docker_sha256,
        invoking_uid=invoking_uid,
        label="docker",
    )
    source_buildx, snapshot_buildx = _copy_executable(
        buildx_executable,
        buildx_snapshot,
        expected_sha256=buildx_sha256,
        invoking_uid=invoking_uid,
        label="buildx",
    )
    socket = _socket_identity(docker_host, invoking_uid=invoking_uid)
    return RuntimePaths(
        root=root,
        docker=docker_snapshot,
        buildx=buildx_snapshot,
        home=directories["home"],
        docker_config=directories["docker-config"],
        buildx_config=directories["buildx-config"],
        temporary=directories["tmp"],
        docker_host=f"unix://{socket['path']}",
        source_docker=source_docker,
        source_buildx=source_buildx,
        snapshot_docker=snapshot_docker,
        snapshot_buildx=snapshot_buildx,
        socket=socket,
    )


def revalidate_runtime(runtime: RuntimePaths, *, invoking_uid: int) -> None:
    expected_root = {"bin", "home", "docker-config", "buildx-config", "tmp"}
    if {item.name for item in runtime.root.iterdir()} != expected_root:
        raise DockerRuntimeContractError("runtime_tree_drift")
    if {item.name for item in runtime.docker.parent.iterdir()} != {
        "docker",
        "docker-buildx",
    }:
        raise DockerRuntimeContractError("runtime_binary_tree_drift")
    docker_config_names = {item.name for item in runtime.docker_config.iterdir()}
    if docker_config_names not in (
        {"config.json"},
        {"config.json", ".token_seed", ".token_seed.lock"},
    ):
        raise DockerRuntimeContractError("docker_config_tree_drift")
    if any(runtime.home.iterdir()):
        raise DockerRuntimeContractError("runtime_home_drift")
    for label, path, record in (
        ("source_docker", Path(runtime.source_docker["path"]), runtime.source_docker),
        ("source_buildx", Path(runtime.source_buildx["path"]), runtime.source_buildx),
        ("snapshot_docker", runtime.docker, runtime.snapshot_docker),
        ("snapshot_buildx", runtime.buildx, runtime.snapshot_buildx),
    ):
        observed = executable_identity(
            path,
            expected_sha256=str(record["sha256"]),
            invoking_uid=invoking_uid,
            label=label,
        )
        if observed != record:
            raise DockerRuntimeContractError(f"{label}_identity_drift")
    if _socket_identity(runtime.docker_host, invoking_uid=invoking_uid) != runtime.socket:
        raise DockerRuntimeContractError("docker_socket_identity_drift")
    config = runtime.docker_config / "config.json"
    if config.read_bytes() != CONFIG_BYTES or stat.S_IMODE(config.stat().st_mode) != 0o600:
        raise DockerRuntimeContractError("docker_config_drift")
    if ".token_seed" in docker_config_names:
        token_seed = runtime.docker_config / ".token_seed"
        token_lock = runtime.docker_config / ".token_seed.lock"
        for label, path, expected_size in (
            ("docker_token_seed", token_seed, None),
            ("docker_token_seed_lock", token_lock, 0),
        ):
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != invoking_uid
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (expected_size is not None and metadata.st_size != expected_size)
            ):
                raise DockerRuntimeContractError(f"{label}_invalid")
        if not 0 < token_seed.stat().st_size <= 4096:
            raise DockerRuntimeContractError("docker_token_seed_invalid")
        seeds = _strict_object(token_seed.read_bytes(), label="docker_token_seed")
        if not seeds:
            raise DockerRuntimeContractError("docker_token_seed_invalid")
        for registry, value in seeds.items():
            if (
                not isinstance(registry, str)
                or not registry
                or any(character in registry for character in "\x00\r\n")
                or not isinstance(value, dict)
                or set(value) != {"Seed"}
                or not isinstance(value["Seed"], str)
            ):
                raise DockerRuntimeContractError("docker_token_seed_invalid")
            try:
                decoded = base64.b64decode(value["Seed"], validate=True)
            except ValueError as exc:
                raise DockerRuntimeContractError("docker_token_seed_invalid") from exc
            if len(decoded) != 16:
                raise DockerRuntimeContractError("docker_token_seed_invalid")


def remove_runtime(runtime: RuntimePaths, *, invoking_uid: int) -> None:
    revalidate_runtime(runtime, invoking_uid=invoking_uid)
    shutil.rmtree(runtime.root)
    if runtime.root.exists() or runtime.root.is_symlink():
        raise DockerRuntimeContractError("runtime_cleanup_uncertain")


def executable_argv(runtime: RuntimePaths, argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        raise DockerRuntimeContractError("runtime_argv_invalid")
    if argv[0] == "docker":
        executable = runtime.docker
    elif argv[0] == "buildx":
        executable = runtime.buildx
    else:
        raise DockerRuntimeContractError("runtime_argv_invalid")
    return (str(executable), *argv[1:])


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise DockerRuntimeContractError(f"{label}_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DockerRuntimeContractError(f"{label}_nonfinite")
            ),
        )
    except DockerRuntimeContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DockerRuntimeContractError(f"{label}_invalid_json") from exc
    if not isinstance(value, dict):
        raise DockerRuntimeContractError(f"{label}_not_object")
    return value


def normalize_daemon_observation(version_raw: bytes, info_raw: bytes) -> dict[str, Any]:
    version = _strict_object(version_raw, label="docker_version")
    info = _strict_object(info_raw, label="docker_info")
    server = version.get("Server")
    if not isinstance(server, dict):
        raise DockerRuntimeContractError("docker_version_server_invalid")
    required_version = ("Version", "ApiVersion", "MinAPIVersion", "GitCommit", "Os", "Arch")
    if any(not isinstance(server.get(key), str) or not server[key] for key in required_version):
        raise DockerRuntimeContractError("docker_version_server_invalid")
    required_info = (
        "ID", "Name", "ServerVersion", "KernelVersion", "OperatingSystem",
        "OSType", "Architecture", "DockerRootDir", "Driver", "CgroupDriver",
        "CgroupVersion", "DefaultRuntime",
    )
    if any(not isinstance(info.get(key), str) or not info[key] for key in required_info):
        raise DockerRuntimeContractError("docker_info_identity_invalid")
    architecture_aliases = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "amd64": "amd64",
        "x86_64": "amd64",
    }
    if (
        info["ServerVersion"] != server["Version"]
        or info["OSType"] != server["Os"]
        or architecture_aliases.get(info["Architecture"], info["Architecture"])
        != architecture_aliases.get(server["Arch"], server["Arch"])
    ):
        raise DockerRuntimeContractError("docker_observation_cross_identity_invalid")
    runtimes = info.get("Runtimes")
    if not isinstance(runtimes, dict) or info["DefaultRuntime"] not in runtimes:
        raise DockerRuntimeContractError("docker_runtimes_invalid")
    normalized_runtimes: list[dict[str, Any]] = []
    for name in sorted(runtimes, key=lambda item: item.encode("utf-8")):
        runtime = runtimes[name]
        if not isinstance(runtime, dict) or not isinstance(runtime.get("path"), str):
            raise DockerRuntimeContractError("docker_runtimes_invalid")
        args = runtime.get("runtimeArgs", [])
        if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
            raise DockerRuntimeContractError("docker_runtimes_invalid")
        normalized_runtimes.append({"name": name, "path": runtime["path"], "args": args})
    security = info.get("SecurityOptions")
    if not isinstance(security, list) or any(not isinstance(item, str) for item in security):
        raise DockerRuntimeContractError("docker_security_options_invalid")
    registry = info.get("RegistryConfig")
    if not isinstance(registry, dict):
        raise DockerRuntimeContractError("docker_registry_config_invalid")
    projection = {
        "schema": "kodesec.docker-daemon-observation/v1",
        "server": {key: server[key] for key in required_version},
        "engine": {key: info[key] for key in required_info},
        "runtimes": normalized_runtimes,
        "security_options": sorted(security, key=lambda item: item.encode("utf-8")),
        "live_restore_enabled": info.get("LiveRestoreEnabled") is True,
        "proxies": {
            key: info.get(key, "") for key in ("HTTPProxy", "HTTPSProxy", "NoProxy")
            if isinstance(info.get(key, ""), str)
        },
        "registry_config": registry,
    }
    projection["sha256"] = hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
    return projection


def normalize_buildx_observation(raw: bytes) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if line:
            rows.append(_strict_object(line, label="buildx_row"))
    if not rows:
        raise DockerRuntimeContractError("buildx_observation_empty")
    selected = [row for row in rows if row.get("Name") == "default"]
    if len(selected) != 1:
        raise DockerRuntimeContractError("buildx_default_builder_invalid")
    row = selected[0]
    if (
        not isinstance(row.get("Driver"), str)
        or not row["Driver"]
        or not isinstance(row.get("Dynamic"), bool)
        or not isinstance(row.get("Nodes"), list)
        or len(row["Nodes"]) != 1
        or not isinstance(row["Nodes"][0], dict)
    ):
        raise DockerRuntimeContractError("buildx_default_builder_invalid")
    node = row["Nodes"][0]
    string_fields = ("Name", "Endpoint", "Status", "Version")
    if any(not isinstance(node.get(key), str) or not node[key] for key in string_fields):
        raise DockerRuntimeContractError("buildx_default_builder_invalid")
    for key in ("Platforms", "IDs"):
        if (
            not isinstance(node.get(key), list)
            or not node[key]
            or any(not isinstance(item, str) or not item for item in node[key])
        ):
            raise DockerRuntimeContractError("buildx_default_builder_invalid")
    projection = {
        "schema": "kodesec.buildx-observation/v1",
        "name": "default",
        "driver": row["Driver"],
        "dynamic": row["Dynamic"],
        "node": {
            **{key.lower(): node[key] for key in string_fields},
            "platforms": sorted(node["Platforms"], key=lambda item: item.encode("utf-8")),
            "ids": sorted(node["IDs"], key=lambda item: item.encode("utf-8")),
        },
    }
    projection["sha256"] = hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
    return projection


def combined_observation(
    daemon: Mapping[str, Any], buildx: Mapping[str, Any]
) -> dict[str, Any]:
    value = {
        "schema": "kodesec.docker-runtime-observation/v1",
        "daemon": dict(daemon),
        "buildx": dict(buildx),
    }
    value["sha256"] = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return value
