from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/docker-runtime-observation.py"


def _load_observer():
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec = importlib.util.spec_from_file_location("docker_runtime_observation", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPT.parent))


observer = _load_observer()


def _version() -> bytes:
    return json.dumps(
        {
            "Server": {
                "Version": "29.4.0",
                "ApiVersion": "1.53",
                "MinAPIVersion": "1.24",
                "GitCommit": "deadbeef",
                "Os": "linux",
                "Arch": "arm64",
            }
        }
    ).encode()


def _info() -> bytes:
    return json.dumps(
        {
            "ID": "ENGINE-ID",
            "Name": "engine",
            "ServerVersion": "29.4.0",
            "KernelVersion": "6.12",
            "OperatingSystem": "Linux",
            "OSType": "linux",
            "Architecture": "arm64",
            "DockerRootDir": "/var/lib/docker",
            "Driver": "overlay2",
            "CgroupDriver": "cgroupfs",
            "CgroupVersion": "2",
            "DefaultRuntime": "runc",
            "Runtimes": {"runc": {"path": "runc"}},
            "SecurityOptions": [],
            "LiveRestoreEnabled": True,
            "RegistryConfig": {"Mirrors": [], "IndexConfigs": {}},
        }
    ).encode()


def _buildx() -> bytes:
    return json.dumps(
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
                    "Platforms": ["linux/arm64"],
                    "IDs": ["ENGINE-ID"],
                }
            ],
        }
    ).encode()


def test_observation_uses_only_three_exact_read_only_commands() -> None:
    calls: list[tuple[str, ...]] = []
    outputs = [_version(), _info(), _buildx()]

    def run(_runtime, argv):
        calls.append(tuple(argv))
        return outputs[len(calls) - 1]

    receipt = observer.observe(object(), invoking_uid=502, runner=run)
    assert calls == [
        ("docker", "version", "--format={{json .}}"),
        ("docker", "info", "--format={{json .}}"),
        ("buildx", "ls", "--format=json", "--no-trunc"),
    ]
    assert receipt["schema"] == "kodesec.docker-runtime-observation/v1"
    assert len(receipt["sha256"]) == 64


def test_main_preserves_typed_cleanup_uncertainty_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        observer,
        "produce",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            observer.ObservationCleanupUncertain("cleanup_uncertain")
        ),
    )
    result = observer.main(
        [
            "--output-dir",
            str(tmp_path / "output"),
            "--docker-executable",
            "/absolute/docker",
            "--docker-sha256",
            "0" * 64,
            "--buildx-executable",
            "/absolute/buildx",
            "--buildx-sha256",
            "1" * 64,
            "--docker-host",
            "unix:///absolute/docker.sock",
        ]
    )
    assert result == 75


def test_natural_nonzero_probe_is_not_cleanup_uncertainty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(observer, "revalidate_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        observer,
        "executable_argv",
        lambda *_args, **_kwargs: [sys.executable, "-c", "raise SystemExit(7)"],
    )

    class Runtime:
        root = tmp_path

        @staticmethod
        def environment() -> dict[str, str]:
            return {"PATH": "/usr/bin:/bin"}

    with pytest.raises(observer.ObservationError, match="probe_status_failed") as raised:
        observer._bounded(Runtime(), ("docker", "version"), invoking_uid=502)

    assert not isinstance(raised.value, observer.ObservationCleanupUncertain)


def _owned_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Real child capture with a disposable runtime, never a Docker subprocess."""
    import shutil

    tmp_path.chmod(0o700)

    class Runtime:
        root = tmp_path / "output" / ".runtime"

        @staticmethod
        def environment() -> dict[str, str]:
            return {"PATH": "/usr/bin:/bin"}

        @staticmethod
        def record() -> dict[str, str]:
            return {"schema": "test-runtime-record"}

    runtime = Runtime()

    def prepare(path, **_kwargs):
        assert path == runtime.root
        path.mkdir(mode=0o700)
        return runtime

    removed = []

    def remove(selected, **_kwargs):
        assert selected is runtime
        removed.append(selected.root)
        shutil.rmtree(selected.root)

    monkeypatch.setattr(observer, "prepare_runtime", prepare)
    monkeypatch.setattr(observer, "remove_runtime", remove)
    monkeypatch.setattr(observer, "revalidate_runtime", lambda *_args, **_kwargs: None)
    return runtime, removed


def _produce(tmp_path: Path) -> Path:
    return observer.produce(
        tmp_path / "output", docker_executable=Path("/absolute/docker"),
        docker_sha256="0" * 64, buildx_executable=Path("/absolute/buildx"),
        buildx_sha256="1" * 64, docker_host="unix:///absolute/docker.sock",
    )


@pytest.mark.parametrize("phase", ["version", "info", "buildx"])
def test_real_nonzero_failure_persists_only_safe_captured_projection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str
) -> None:
    import hashlib
    import stat

    runtime, removed = _owned_runtime(monkeypatch, tmp_path)
    calls = []
    raw_stdout = b"credential-bearing Docker output never persists"
    raw_stderr = b"password=private-test-value token=private-test-value"
    outputs = {"version": _version(), "info": _info(), "buildx": _buildx()}

    def executable(_runtime, argv):
        selected = observer.PROBE_PHASES[tuple(argv[:2])]
        calls.append(selected)
        if selected == phase:
            code = (f"import sys;sys.stdout.buffer.write({raw_stdout!r});"
                    f"sys.stderr.buffer.write({raw_stderr!r});raise SystemExit(7)")
        else:
            code = f"import sys;sys.stdout.buffer.write({outputs[selected]!r})"
        return [sys.executable, "-c", code]

    monkeypatch.setattr(observer, "executable_argv", executable)
    with pytest.raises(observer.ObservationError, match="^probe_status_failed$") as raised:
        _produce(tmp_path)
    assert not isinstance(raised.value, observer.ObservationCleanupUncertain)
    assert calls == ["version", "info", "buildx"][:["version", "info", "buildx"].index(phase) + 1]
    failure_path = tmp_path / "output" / observer.FAILURE_NAME
    payload = failure_path.read_bytes()
    failure = json.loads(payload)
    assert failure["phase"] == phase
    assert failure["native_exit"] == 7
    assert failure["natural_exit_observed"] is True
    assert failure["process_cleanup_confirmed"] is True
    assert failure["runtime_cleanup_confirmed"] is True
    for stream, raw in (("stdout", raw_stdout), ("stderr", raw_stderr)):
        assert failure[f"{stream}_captured_bytes"] == len(raw)
        assert failure[f"{stream}_sha256"] == hashlib.sha256(raw).hexdigest()
        assert raw not in payload
    assert len(payload) <= observer.MAX_FAILURE_BYTES
    assert stat.S_IMODE(failure_path.stat().st_mode) == 0o600
    assert failure_path.stat().st_nlink == 1
    assert removed == [runtime.root] and not runtime.root.exists()
    assert not (tmp_path / "output" / observer.RECEIPT_NAME).exists()


def test_success_receipt_shape_and_bytes_remain_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import hashlib

    runtime, removed = _owned_runtime(monkeypatch, tmp_path)
    outputs = [_version(), _info(), _buildx()]
    calls = []

    def run(_runtime, argv):
        calls.append(tuple(argv))
        return outputs[len(calls) - 1]

    observation = observer.observe(runtime, invoking_uid=0, runner=run)
    monkeypatch.setattr(observer, "observe", lambda *_args, **_kwargs: observation)
    expected = {"schema": "kodesec.docker-runtime-observation-receipt/v1",
                "authoritative": False, "execution": runtime.record(), "observation": observation}
    expected["receipt_sha256"] = hashlib.sha256(observer.canonical_json_bytes(expected)).hexdigest()
    result = _produce(tmp_path)
    assert result.read_bytes() == observer.canonical_json_bytes(expected)
    assert not (result.parent / observer.FAILURE_NAME).exists()
    assert removed == [runtime.root] and not runtime.root.exists()


def test_real_timeout_projection_keeps_unknown_child_semantics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _owned_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(observer, "MAX_SECONDS", 0.05)
    monkeypatch.setattr(observer, "executable_argv",
                        lambda *_args: [sys.executable, "-c", "import time;time.sleep(2)"])
    with pytest.raises(observer.ObservationCleanupUncertain, match="probe_completion_uncertain"):
        _produce(tmp_path)
    failure = json.loads((tmp_path / "output" / observer.FAILURE_NAME).read_text())
    assert failure["phase"] == "version"
    assert failure["natural_exit_observed"] is False
    assert failure["native_exit"] is None
    assert failure["process_cleanup_confirmed"] is False
    assert failure["runtime_cleanup_confirmed"] is True


def test_runtime_cleanup_failure_remains_unknown_and_retains_private_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, _ = _owned_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(observer, "executable_argv",
                        lambda *_args: [sys.executable, "-c", "raise SystemExit(9)"])

    def refuse_remove(*_args, **_kwargs):
        raise RuntimeError("private cleanup failure never serialized")

    monkeypatch.setattr(observer, "remove_runtime", refuse_remove)
    with pytest.raises(observer.ObservationCleanupUncertain, match="runtime_forensic_state_preserved"):
        _produce(tmp_path)
    failure = json.loads((tmp_path / "output" / observer.FAILURE_NAME).read_text())
    assert failure["native_exit"] == 9
    assert failure["natural_exit_observed"] is True
    assert failure["process_cleanup_confirmed"] is True
    assert failure["runtime_cleanup_confirmed"] is False
    assert runtime.root.exists()


def test_post_child_revalidation_failure_is_not_normalized_to_cleanup_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _owned_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(observer, "executable_argv",
                        lambda *_args: [sys.executable, "-c", "raise SystemExit(8)"])
    calls = []

    def revalidate(*_args, **_kwargs):
        calls.append(True)
        if len(calls) > 1:
            raise RuntimeError("runtime identity changed")

    monkeypatch.setattr(observer, "revalidate_runtime", revalidate)
    with pytest.raises(observer.ObservationCleanupUncertain, match="probe_cleanup_uncertain"):
        _produce(tmp_path)
    failure = json.loads((tmp_path / "output" / observer.FAILURE_NAME).read_text())
    assert failure["native_exit"] == 8 and failure["natural_exit_observed"] is True
    assert failure["process_cleanup_confirmed"] is False


def test_oversized_capture_reports_captured_prefix_counts_not_output_totals(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _owned_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(observer, "executable_argv",
                        lambda *_args: [sys.executable, "-c", f"import sys;sys.stdout.write('x'*{observer.MAX_OUTPUT_BYTES + 1})"])
    with pytest.raises(observer.ObservationCleanupUncertain):
        _produce(tmp_path)
    failure = json.loads((tmp_path / "output" / observer.FAILURE_NAME).read_text())
    assert failure["capture_limit_bytes_per_stream"] == observer.MAX_OUTPUT_BYTES
    assert failure["stdout_captured_bytes"] <= observer.MAX_OUTPUT_BYTES
    assert "stdout_bytes" not in failure
    assert failure["native_exit"] is None
    assert failure["natural_exit_observed"] is False


def test_failure_projection_rejects_raw_or_extra_fields_and_existing_destination(
    tmp_path: Path,
) -> None:
    import os

    tmp_path.chmod(0o700)
    projection = observer._failure_projection(
        "version", {"stdout": bytearray(), "stderr": bytearray()}, native_exit=7,
        natural_exit_observed=True, process_cleanup_confirmed=True,
    )
    with pytest.raises(observer.ObservationError, match="failure_projection_invalid"):
        observer._publish_failure(tmp_path, {**projection, "stderr": "secret"}, uid=os.getuid())
    observer._publish_failure(tmp_path, projection, uid=os.getuid())
    original = (tmp_path / observer.FAILURE_NAME).read_bytes()
    with pytest.raises(observer.ObservationError, match="receipt_destination_invalid"):
        observer._publish_failure(tmp_path, projection, uid=os.getuid())
    assert (tmp_path / observer.FAILURE_NAME).read_bytes() == original


def test_main_nonzero_probe_keeps_original_stderr_code_and_exit_two(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _owned_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(observer, "executable_argv",
                        lambda *_args: [sys.executable, "-c", "raise SystemExit(7)"])
    result = observer.main([
        "--output-dir", str(tmp_path / "output"), "--docker-executable", "/absolute/docker",
        "--docker-sha256", "0" * 64, "--buildx-executable", "/absolute/buildx",
        "--buildx-sha256", "1" * 64, "--docker-host", "unix:///absolute/docker.sock",
    ])
    assert result == 2
    assert capsys.readouterr().err == "probe_status_failed\n"
    assert (tmp_path / "output" / observer.FAILURE_NAME).exists()
