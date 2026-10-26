from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/docker_runtime_contract.py"


def _load_contract():
    spec = importlib.util.spec_from_file_location("docker_runtime_contract", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


contract = _load_contract()


def _executable(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    path.chmod(0o500)
    return hashlib.sha256(payload).hexdigest()


def _runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tmp_path.chmod(0o700)
    docker = tmp_path / "docker-source"
    buildx = tmp_path / "buildx-source"
    docker_sha = _executable(docker, b"docker-exact\n")
    buildx_sha = _executable(buildx, b"buildx-exact\n")
    socket_path = tmp_path / "engine.sock"
    socket_path.write_bytes(b"synthetic-socket-identity")
    socket_record = {
        "path": str(socket_path),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "device": 1,
        "inode": 2,
        "mode": "0600",
        "mtime_ns": 3,
        "ctime_ns": 4,
    }
    monkeypatch.setattr(
        contract,
        "_socket_identity",
        lambda _host, *, invoking_uid: socket_record,
    )
    runtime = contract.prepare_runtime(
        tmp_path / "runtime",
        docker_executable=docker,
        docker_sha256=docker_sha,
        buildx_executable=buildx,
        buildx_sha256=buildx_sha,
        docker_host=f"unix://{socket_path}",
        invoking_uid=os.getuid(),
    )
    return runtime, socket_path


def _version() -> bytes:
    return json.dumps(
        {
            "Client": {"Version": "ignored"},
            "Server": {
                "Version": "29.4.0",
                "ApiVersion": "1.53",
                "MinAPIVersion": "1.24",
                "GitCommit": "deadbeef",
                "Os": "linux",
                "Arch": "arm64",
            },
        },
        separators=(",", ":"),
    ).encode()


def _info(**changes: object) -> bytes:
    value = {
        "ID": "ENGINE-ID",
        "Name": "reviewed-engine",
        "ServerVersion": "29.4.0",
        "KernelVersion": "6.12.0",
        "OperatingSystem": "Linux",
        "OSType": "linux",
        "Architecture": "arm64",
        "DockerRootDir": "/var/lib/docker",
        "Driver": "overlay2",
        "CgroupDriver": "cgroupfs",
        "CgroupVersion": "2",
        "DefaultRuntime": "runc",
        "Runtimes": {"runc": {"path": "runc"}},
        "SecurityOptions": ["name=seccomp", "name=cgroupns"],
        "LiveRestoreEnabled": True,
        "HTTPProxy": "",
        "HTTPSProxy": "",
        "NoProxy": "",
        "RegistryConfig": {
            "Mirrors": [],
            "InsecureRegistryCIDRs": ["127.0.0.0/8"],
            "IndexConfigs": {},
        },
        "Containers": 1,
        "Images": 2,
        "SystemTime": "volatile",
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


def test_private_runtime_uses_exact_snapshots_and_fixed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, socket_path = _runtime(tmp_path, monkeypatch)
    assert contract.executable_argv(runtime, ("docker", "info"))[0] == str(
        runtime.docker
    )
    assert contract.executable_argv(runtime, ("buildx", "version"))[0] == str(
        runtime.buildx
    )
    assert runtime.docker.read_bytes() == b"docker-exact\n"
    assert runtime.buildx.read_bytes() == b"buildx-exact\n"
    assert runtime.buildx.name == "docker-buildx"
    assert stat.S_IMODE(runtime.docker.stat().st_mode) == 0o500
    assert runtime.environment() == {
        "BUILDX_CONFIG": str(runtime.buildx_config),
        "DOCKER_CONFIG": str(runtime.docker_config),
        "DOCKER_HOST": f"unix://{socket_path}",
        "HOME": str(runtime.home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(runtime.temporary),
    }
    assert runtime.record()["policy"]["path_discovery"] is False
    contract.revalidate_runtime(runtime, invoking_uid=os.getuid())


def test_runtime_rejects_digest_drift_and_path_shadowing(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    executable = tmp_path / "docker"
    digest = _executable(executable, b"reviewed")
    with pytest.raises(contract.DockerRuntimeContractError, match="sha256"):
        contract.executable_identity(
            executable,
            expected_sha256="0" * 64,
            invoking_uid=os.getuid(),
            label="docker",
        )
    alias = tmp_path / "docker-alias"
    alias.symlink_to(executable)
    with pytest.raises(contract.DockerRuntimeContractError, match="unsafe"):
        contract.executable_identity(
            alias,
            expected_sha256=digest,
            invoking_uid=os.getuid(),
            label="docker",
        )


def test_daemon_projection_ignores_counts_and_normalizes_missing_runtime_args() -> None:
    first = contract.normalize_daemon_observation(_version(), _info())
    second = contract.normalize_daemon_observation(
        _version(), _info(Containers=999, Images=888, SystemTime="later")
    )
    aliased = contract.normalize_daemon_observation(
        _version(), _info(Architecture="aarch64")
    )
    assert first == second
    assert aliased["engine"]["Architecture"] == "aarch64"
    assert first["runtimes"] == [{"name": "runc", "path": "runc", "args": []}]
    assert first["engine"]["ID"] == "ENGINE-ID"
    assert contract.SHA256.fullmatch(first["sha256"])


def test_daemon_projection_rejects_route_or_cross_identity_drift() -> None:
    baseline = contract.normalize_daemon_observation(_version(), _info())
    changed = contract.normalize_daemon_observation(
        _version(), _info(HTTPProxy="http://proxy.invalid")
    )
    assert baseline["sha256"] != changed["sha256"]
    with pytest.raises(
        contract.DockerRuntimeContractError, match="cross_identity"
    ):
        contract.normalize_daemon_observation(
            _version(), _info(Architecture="amd64")
        )


def test_buildx_projection_requires_one_exact_default_builder() -> None:
    raw = json.dumps(
        {
            "Name": "default",
            "Driver": "docker",
            "Dynamic": False,
            "Nodes": [
                {
                    "Name": "default",
                    "Endpoint": "default",
                    "Status": "running",
                    "Version": "v0.29.0",
                    "Platforms": ["linux/amd64", "linux/arm64"],
                    "IDs": ["ENGINE-ID"],
                }
            ],
            "LastActivity": "volatile",
        },
        separators=(",", ":"),
    ).encode()
    observed = contract.normalize_buildx_observation(raw + b"\n")
    assert observed["name"] == "default"
    assert "lastactivity" not in observed
    assert observed["node"]["version"] == "v0.29.0"
    assert contract.SHA256.fullmatch(observed["sha256"])
    with pytest.raises(contract.DockerRuntimeContractError, match="default"):
        contract.normalize_buildx_observation(raw + b"\n" + raw + b"\n")


def test_runtime_cleanup_rejects_modified_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, _socket_path = _runtime(tmp_path, monkeypatch)
    runtime.docker.chmod(0o700)
    with pytest.raises(contract.DockerRuntimeContractError):
        contract.remove_runtime(runtime, invoking_uid=os.getuid())
    assert runtime.root.exists()


def test_runtime_accepts_only_bounded_noncredential_docker_token_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, _socket_path = _runtime(tmp_path, monkeypatch)
    seed = base64.b64encode(b"0123456789abcdef").decode("ascii")
    (runtime.docker_config / ".token_seed").write_text(
        json.dumps({"registry-1.docker.io": {"Seed": seed}}), encoding="utf-8"
    )
    (runtime.docker_config / ".token_seed").chmod(0o600)
    (runtime.docker_config / ".token_seed.lock").write_bytes(b"")
    (runtime.docker_config / ".token_seed.lock").chmod(0o600)
    contract.revalidate_runtime(runtime, invoking_uid=os.getuid())

    (runtime.docker_config / ".token_seed").write_text(
        json.dumps({"auths": {"Seed": seed, "credential": "hostile"}}),
        encoding="utf-8",
    )
    with pytest.raises(contract.DockerRuntimeContractError, match="token_seed"):
        contract.revalidate_runtime(runtime, invoking_uid=os.getuid())
