from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from kodesec_scanner import external
from kodesec_scanner.redaction import redact_text


@pytest.mark.parametrize("scanner", ["gitleaks", "checkov", "trivy", "bearer", "opengrep", "grype", "syft", "trufflehog"])
def test_scan_environment_excludes_ambient_secrets_and_control_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str,
) -> None:
    for key in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "TRIVY_CONFIG", "TRIVY_IGNORE_FILE",
                "CKV_EXTERNAL_CHECKS_DIR", "CKV_EXTERNAL_CHECKS_GIT", "CKV_IGNORED_DIRECTORIES",
                "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "AWS_SECRET_ACCESS_KEY",
                "HTTPS_PROXY", "GRYPE_CONFIG", "SYFT_CONFIG", "BEARER_CONFIG", "PATH"):
        monkeypatch.setenv(key, "source-controlled-or-secret")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "../source/locale")
    environment, cache = external._tool_environment(scanner, tmp_path, tmp_path / "persistent")
    assert all(value != "source-controlled-or-secret" for value in environment.values())
    assert environment["LANG"] == "C.UTF-8"
    assert "LC_ALL" not in environment
    assert all(Path(item).is_absolute() for item in environment["PATH"].split(os.pathsep))
    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["XDG_CACHE_HOME"] == str(cache)
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700


@pytest.mark.parametrize(("scanner", "name"), [
    ("gitleaks", ".gitleaksignore"), ("checkov", ".checkov.yaml"), ("checkov", ".checkov.yml"),
])
@pytest.mark.parametrize("kind", ["file", "directory", "broken_symlink"])
def test_source_controls_fail_before_execution_without_mutating_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, name: str, kind: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    control = repo / name
    if kind == "file":
        control.write_bytes(b"external-checks-dir: ./untrusted-checks\n")
    elif kind == "directory":
        control.mkdir()
    else:
        control.symlink_to("missing-config")
    before = control.lstat()
    invoked: list[object] = []
    monkeypatch.setattr(external, "_run_command", lambda *args, **kwargs: invoked.append(args))
    with external.request_scratch_directory(str(tmp_path / "scratch"), 1) as request:
        result = external.run_external_tool(scanner, repo, request, tmp_path / "publish", tmp_path / "cache", 30)
    assert result.status == "failed"
    assert result.error == f"source_control_unsupported:{scanner}"
    assert redact_text(result.error) == result.error
    assert invoked == []
    assert control.lstat().st_ino == before.st_ino
    if kind == "file":
        assert control.read_bytes() == b"external-checks-dir: ./untrusted-checks\n"
    elif kind == "broken_symlink":
        assert control.readlink() == Path("missing-config")


@pytest.mark.parametrize("scanner", ["gitleaks", "checkov", "trivy", "bearer"])
def test_native_commands_use_owned_config_and_private_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    root_controls = {
        ".gitleaks.toml": "[allowlist]\nregexes = ['.*']\n",
        "trivy.yaml": "skip-dirs: ['**']\n",
        ".trivyignore": "CVE-2099-12345\n",
        "trivy-secret.yaml": "disable-rules: ['aws-access-key-id']\n",
    }
    for name, content in root_controls.items():
        (repo / name).write_text(content, encoding="utf-8")
    # Nested configs are source evidence, not an automatically discovered root
    # config in these pinned producers. Their native path scope needs canaries.
    nested = repo / "nested"
    nested.mkdir()
    for name in (".gitleaksignore", ".checkov.yml", "trivy.yaml", ".trivyignore", "trivy-secret.yaml"):
        (nested / name).write_text("source bytes\n", encoding="utf-8")
    observed: list[list[str]] = []

    def fake_run(scanner_id: str, command: list[str], cwd: Path, timeout: int,
                 raw_dir: Path, env: dict[str, str] | None = None,
                 *, stdout_path: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        assert cwd == raw_dir and cwd != repo
        assert env is not None and env["HOME"] == str(raw_dir / "home")
        assert str(repo) in command or f"--directory={repo}" in command
        if scanner == "gitleaks":
            config = Path(command[command.index("--config") + 1])
            assert config.read_text() == "[extend]\nuseDefault = true\n"
            assert "--ignore-gitleaks-allow" in command
            assert command[command.index("--gitleaks-ignore-path") + 1] == str(raw_dir)
            output = Path(command[command.index("--report-path") + 1])
        elif scanner == "checkov":
            assert f"--directory={repo}" in command
            assert "-d" not in command and "--directory" not in command
            config = Path(command[command.index("--config-file") + 1])
            assert config.read_text() == "{}\n"
            assert env["PYTHONSAFEPATH"] == "1"
            assert "--skip-download" in command
            assert "--external-checks-dir" not in command
            output = raw_dir / "results_sarif.sarif"
        elif scanner == "bearer":
            config = Path(command[command.index("--config-file") + 1])
            assert config.read_text() == "{}\n"
            assert "--disable-version-check" in command
            output = Path(command[command.index("--output") + 1])
        else:
            config = Path(command[command.index("--config") + 1])
            secret_config = Path(command[command.index("--secret-config") + 1])
            ignore = Path(command[command.index("--ignorefile") + 1])
            assert config.read_text() == secret_config.read_text() == "{}\n"
            assert ignore.read_bytes() == b""
            assert secret_config.parent == ignore.parent == raw_dir
            assert "--offline-scan" in command and "--skip-check-update" in command
            output = Path(command[command.index("--output") + 1])
        assert config.parent == raw_dir
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        output.write_text(
            '{"source":"Bearer","version":"2.1.0+lomo.1","findings":[],"errors":[]}'
            if scanner == "bearer" else '{"runs":[]}', encoding="utf-8",
        )
        observed.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(external, "_run_command", fake_run)
    runtime = tmp_path / "generation"
    inputs = {key: runtime / "trivy" / suffix for key, suffix in (
        ("trivy-db", "db"), ("trivy-java-db", "java-db"), ("trivy-checks", "checks"),
    )}
    for path in inputs.values():
        path.mkdir(parents=True)
    inputs["bearer-rules"] = runtime / "bearer" / "rules"
    inputs["bearer-rules"].mkdir(parents=True)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 2) as request:
        result = external.run_external_tool(scanner, repo, request, tmp_path / "publish", tmp_path / "cache", 30, inputs=inputs)
    assert result.status == "completed", result.error
    assert len(observed) == (2 if scanner == "trivy" else 1)
    assert all(path.read_text() == "source bytes\n" for path in nested.iterdir())
    assert all((repo / name).read_text() == content for name, content in root_controls.items())


def test_trusted_config_never_follows_or_overwrites_existing_entry(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "owned.yaml").symlink_to(outside)
    with pytest.raises(FileExistsError):
        external._trusted_tool_config(scratch, "owned.yaml", "{}\n")
    assert outside.read_text() == "unchanged"


def test_checkov_config_created_during_invocation_has_no_discovery_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(scanner: str, command: list[str], cwd: Path, timeout: int,
                 raw_dir: Path, env: dict[str, str] | None = None,
                 *, stdout_path: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        (repo / ".checkov.yml").write_text("external-checks-dir: ./source-plugin\n")
        assert not any(token in ("-d", "--directory") for token in command)
        assert f"--directory={repo}" in command
        assert cwd == raw_dir and env is not None and env["HOME"] != str(repo)
        (raw_dir / "results_sarif.sarif").write_text('{"runs":[]}')
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(external, "_run_command", fake_run)
    with external.request_scratch_directory(str(tmp_path / "scratch"), 3) as request:
        result = external.run_external_tool("checkov", repo, request, tmp_path / "publish", tmp_path / "cache", 30)
    assert result.status == "completed"
    assert (repo / ".checkov.yml").read_text() == "external-checks-dir: ./source-plugin\n"


@pytest.mark.parametrize("scanner", ["grype", "syft", "trufflehog"])
def test_remaining_native_producers_use_private_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    publish = tmp_path / "publish"
    publish.mkdir()
    sbom = publish / "syft.json"
    sbom.write_text('{}')
    database = tmp_path / "database"
    database.mkdir()
    observed: list[list[str]] = []

    def fake_run(scanner: str, command: list[str], cwd: Path, timeout: int,
                 raw_dir: Path, env: dict[str, str] | None = None,
                 *, stdout_path: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        assert cwd == scratch and cwd != repo
        assert env is not None and env["HOME"] == str(scratch / "home")
        observed.append(command)
        if scanner == "trufflehog":
            assert stdout_path is not None
            stdout_path.write_text('')
        elif scanner == "grype":
            Path(command[command.index("--file") + 1]).write_text('{"runs":[]}')
        else:
            (raw_dir / "syft.cyclonedx.json").write_text('{}')
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(external, "_run_command", fake_run)
    monkeypatch.setattr(external, "_publish_sanitized_sbom", lambda *args: None)
    result = external._run_external_tool(
        scanner, repo, scratch, publish, tmp_path / "cache", 30, 0,
        inputs={"syft_sbom": sbom, "grype-db": database},
    )
    assert result.status == "completed", result.error
    assert len(observed) == 1
