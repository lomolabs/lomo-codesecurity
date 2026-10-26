from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "apply_components.py"
MODULE_SPEC = importlib.util.spec_from_file_location("apply_components", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
apply_components = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(apply_components)


EXPECTED_PROFILES = {
    "core": (),
    "monitoring": ("monitoring",),
    "git-proxy": ("git-proxy",),
    "db-admin": ("db-admin",),
    "monitoring-git-proxy": ("monitoring", "git-proxy"),
    "monitoring-db-admin": ("monitoring", "db-admin"),
    "git-proxy-db-admin": ("git-proxy", "db-admin"),
    "all": ("monitoring", "git-proxy", "db-admin"),
}
OPTIONAL_BY_PROFILE = {
    "monitoring": ("grafana", "prometheus"),
    "git-proxy": ("gitea",),
    "db-admin": ("adminer",),
}
CORE_SERVICES = {
    "postgres",
    "schema-init",
    "scanner",
    "scanner-updater",
    "api",
    "api-ingress",
    "worker",
    "advisor-connector",
}


def _command_operation(command: tuple[str, ...]) -> tuple[str, int]:
    for operation in ("rm", "up"):
        if operation in command:
            return operation, command.index(operation)
    raise AssertionError(f"missing Compose operation: {command!r}")


def test_all_eight_component_plans_touch_only_exact_optional_services() -> None:
    assert apply_components.COMPONENT_SETS == EXPECTED_PROFILES
    runtime = Path("/private/tmp/runtime.env")
    compose_file = Path("/workspace/docker-compose.yml")
    volume_override = Path("/run/user/1000/existing-volumes.yaml")
    project = "lomo-code-security-012345abcdef"
    all_optional = set().union(
        *(set(services) for services in OPTIONAL_BY_PROFILE.values())
    )

    for selection, selected_profiles in EXPECTED_PROFILES.items():
        commands = apply_components.build_compose_commands(
            selection,
            runtime,
            project,
            compose_file,
            volume_override,
        )
        assert [command.operation for command in commands] == [
            *(["remove_optional"] if selection != "all" else []),
            *(["start_optional"] if selection != "core" else []),
        ]

        selected_services = tuple(
            service
            for profile in selected_profiles
            for service in OPTIONAL_BY_PROFILE[profile]
        )
        selected_service_set = set(selected_services)
        if selection != "all":
            removal = commands[0].argv
            _, removal_index = _command_operation(removal)
            assert removal[removal_index + 1 : removal_index + 3] == ("--force", "--stop")
            removed_services = set(removal[removal_index + 3 :])
            assert removed_services == all_optional - selected_service_set
            assert not (removed_services & selected_service_set)

        if selection != "core":
            up = commands[-1].argv
            _, up_index = _command_operation(up)
            assert up[up_index + 1 : up_index + 6] == (
                "--detach",
                "--no-build",
                "--no-deps",
                "--pull",
                "never",
            )
            assert up[up_index + 6 :] == selected_services
            actual_profiles = tuple(
                up[index + 1]
                for index, argument in enumerate(up)
                if argument == "--profile"
            )
            assert actual_profiles == selected_profiles

        flattened = {argument for command in commands for argument in command.argv}
        assert not flattened.intersection(
            {"down", "--build", "--volumes", "--remove-orphans", "volume"}
        )
        assert not flattened.intersection(CORE_SERVICES)
        for command in commands:
            file_indexes = [
                index
                for index, argument in enumerate(command.argv)
                if argument == "--file"
            ]
            assert [command.argv[index + 1] for index in file_indexes] == [
                os.fspath(compose_file),
                os.fspath(volume_override),
            ]


@pytest.mark.parametrize(
    "invalid",
    ["", "CORE", "core ", "monitoring,git-proxy", "all;docker down", "../core"],
)
def test_component_plan_rejects_every_non_catalog_selection(invalid: str) -> None:
    with pytest.raises(SystemExit) as error:
        apply_components.build_compose_commands(
            invalid,
            Path("/private/tmp/runtime.env"),
            "lomo-code-security-012345abcdef",
            Path("/workspace/docker-compose.yml"),
            Path("/run/user/1000/existing-volumes.yaml"),
        )
    assert error.value.code == 2


def _private_runtime(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runtime = state / "runtime.env"
    runtime.write_text(
        "COMPOSE_PROJECT_NAME=lomo-code-security-012345abcdef\n",
        encoding="utf-8",
    )
    runtime.chmod(0o600)
    return state, runtime


def _read_http_when_ready(url: str) -> bytes:
    deadline = time.monotonic() + 5
    while True:
        try:
            with urlopen(url, timeout=1) as response:
                return response.read()
        except (URLError, OSError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def _fake_docker(tmp_path: Path) -> tuple[Path, Path, Path]:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    calls_log = tmp_path / "docker-calls.jsonl"
    overrides_log = tmp_path / "compose-overrides.jsonl"
    fake_docker = binary_dir / "docker"
    fake_docker.write_text(
        f"#!{sys.executable}\n"
        "import json, os, stat, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['KODESEC_FAKE_DOCKER_LOG'], 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(args) + '\\n')\n"
        "if args[:4] == ['volume', 'ls', '--quiet', '--filter']:\n"
        "    selector = args[4]\n"
        "    if not selector.startswith('name=^') or not selector.endswith('$'):\n"
        "        raise SystemExit(91)\n"
        "    volume_name = selector[6:-1]\n"
        "    if volume_name == os.environ.get('KODESEC_FAKE_VOLUME_FAILURE'):\n"
        "        raise SystemExit(17)\n"
        "    existing = set(filter(None, os.environ.get('KODESEC_FAKE_VOLUMES', '').split(',')))\n"
        "    if volume_name in existing:\n"
        "        print(volume_name)\n"
        "elif args[:1] == ['compose']:\n"
        "    file_indexes = [index for index, value in enumerate(args) if value == '--file']\n"
        "    override = args[file_indexes[1] + 1]\n"
        "    evidence = {\n"
        "        'path': override,\n"
        "        'mode': stat.S_IMODE(os.stat(override).st_mode),\n"
        "        'content': open(override, encoding='utf-8').read(),\n"
        "    }\n"
        "    with open(os.environ['KODESEC_FAKE_OVERRIDE_LOG'], 'a', encoding='utf-8') as handle:\n"
        "        handle.write(json.dumps(evidence) + '\\n')\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o700)
    return binary_dir, calls_log, overrides_log


def test_host_script_executes_fixed_stop_then_up_plan_without_shell(
    tmp_path: Path,
) -> None:
    state, runtime = _private_runtime(tmp_path)
    binary_dir, calls_log, overrides_log = _fake_docker(tmp_path)
    project = "lomo-code-security-012345abcdef"
    existing_keys = (
        "pg_data",
        "artifacts",
        "source_snapshots",
        "scanner_cache",
        "gitea_data",
    )
    existing_volumes = tuple(f"{project}_{key}" for key in existing_keys)
    result = subprocess.run(
        [sys.executable, os.fspath(SCRIPT)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": os.fspath(binary_dir) + os.pathsep + os.environ.get("PATH", ""),
            "KODESEC_STATE_DIR": os.fspath(state),
            "KODESEC_RUNTIME_ENV": os.fspath(runtime),
            "KODESEC_COMPONENT_SET": "monitoring",
            "KODESEC_FAKE_DOCKER_LOG": os.fspath(calls_log),
            "KODESEC_FAKE_OVERRIDE_LOG": os.fspath(overrides_log),
            "KODESEC_FAKE_VOLUMES": ",".join(existing_volumes),
            "COMPOSE_PROFILES": "attacker-profile",
            "COMPOSE_FILE": "/tmp/attacker-compose.yml",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
    ]
    assert calls[:8] == [
        [
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{project}_{key}$",
        ]
        for key in apply_components.VOLUME_KEYS
    ]
    compose_calls = calls[8:]
    assert len(compose_calls) == 2
    assert compose_calls[0][-5:] == ["rm", "--force", "--stop", "gitea", "adminer"]
    assert compose_calls[1][-10:] == [
        "--profile",
        "monitoring",
        "up",
        "--detach",
        "--no-build",
        "--no-deps",
        "--pull",
        "never",
        "grafana",
        "prometheus",
    ]
    assert "/tmp/attacker-compose.yml" not in compose_calls[0] + compose_calls[1]
    overrides = [
        json.loads(line)
        for line in overrides_log.read_text(encoding="utf-8").splitlines()
    ]
    assert len(overrides) == 2
    assert {entry["path"] for entry in overrides} == {overrides[0]["path"]}
    assert {entry["mode"] for entry in overrides} == {0o600}
    assert Path(overrides[0]["path"]).parent == state
    assert overrides[0]["content"] == """volumes:
  pg_data:
    external: true
    name: lomo-code-security-012345abcdef_pg_data
  artifacts:
    external: true
    name: lomo-code-security-012345abcdef_artifacts
  source_snapshots:
    external: true
    name: lomo-code-security-012345abcdef_source_snapshots
  scanner_cache:
    external: true
    name: lomo-code-security-012345abcdef_scanner_cache
  gitea_data:
    external: true
    name: lomo-code-security-012345abcdef_gitea_data
"""
    assert overrides[0]["content"] == overrides[1]["content"]
    assert not Path(overrides[0]["path"]).exists()
    assert not tuple(state.glob(".apply-components-volumes-*.yaml"))
    assert stat.S_IMODE((state / ".apply-components.lock").stat().st_mode) == 0o600


def test_host_script_fails_closed_when_volume_inventory_fails(tmp_path: Path) -> None:
    state, runtime = _private_runtime(tmp_path)
    binary_dir, calls_log, overrides_log = _fake_docker(tmp_path)
    result = subprocess.run(
        [sys.executable, os.fspath(SCRIPT)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": os.fspath(binary_dir) + os.pathsep + os.environ.get("PATH", ""),
            "KODESEC_STATE_DIR": os.fspath(state),
            "KODESEC_RUNTIME_ENV": os.fspath(runtime),
            "KODESEC_COMPONENT_SET": "all",
            "KODESEC_FAKE_DOCKER_LOG": os.fspath(calls_log),
            "KODESEC_FAKE_OVERRIDE_LOG": os.fspath(overrides_log),
            "KODESEC_FAKE_VOLUME_FAILURE": (
                "lomo-code-security-012345abcdef_pg_data"
            ),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Product volume inventory failed with exit status 17." in result.stderr
    calls = [
        json.loads(line)
        for line in calls_log.read_text(encoding="utf-8").splitlines()
    ]
    assert calls == [
        [
            "volume",
            "ls",
            "--quiet",
            "--filter",
            "name=^lomo-code-security-012345abcdef_pg_data$",
        ]
    ]
    assert not overrides_log.exists()
    assert not tuple(state.glob(".apply-components-volumes-*.yaml"))


def test_makefile_exposes_only_the_validating_component_host_boundary() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("apply-components: init\n", 1)[1].split("\n\n", 1)[0]
    assert 'KODESEC_COMPONENT_SET="$(COMPONENTS)"' in target
    assert "scripts/apply_components.py" in target
    assert "docker compose" not in target
    assert " down" not in target
    assert "--volumes" not in target


@pytest.mark.skipif(
    os.environ.get("KODESEC_RUN_DOCKER_COMPONENT_RECONCILIATION") != "1",
    reason="isolated Docker reconciliation acceptance is opt-in",
)
def test_real_full_to_lean_reconciliation_preserves_named_volume(
    tmp_path: Path,
) -> None:
    """Isolated real-Docker acceptance; never targets the live product project."""
    image = os.environ.get("KODESEC_COMPONENT_TEST_IMAGE", "python:3.12-slim")
    if subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
    ).returncode:
        pytest.skip(f"local test image is unavailable: {image}")
    project = f"lomo-code-security-{secrets.token_hex(6)}"
    state, runtime = _private_runtime(tmp_path)
    runtime.write_text(f"COMPOSE_PROJECT_NAME={project}\n", encoding="utf-8")
    compose_file = tmp_path / "compose.yml"
    services = {
        "core": "",
        "grafana": "monitoring",
        "prometheus": "monitoring",
        "gitea": "git-proxy",
        "adminer": "db-admin",
    }
    lines = ["services:"]
    for service, profile in services.items():
        lines.extend(
            [
                f"  {service}:",
                f"    image: {image}",
                f"    command: [\"sh\", \"-c\", \"mkdir -p /www && printf '{service}' >/www/index.html && exec python -m http.server 8080 --directory /www\"]",
            ]
        )
        if profile:
            lines.append(f"    profiles: [\"{profile}\"]")
            lines.append('    ports: ["127.0.0.1::8080"]')
        if service == "gitea":
            lines.append("    volumes: [\"gitea_data:/data\"]")
    lines.extend(["volumes:", "  gitea_data:"])
    compose_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    base = [
        "docker",
        "compose",
        "--env-file",
        os.fspath(runtime),
        "--project-name",
        project,
        "--file",
        os.fspath(compose_file),
    ]
    environment = {**os.environ, "COMPOSE_PROFILES": ""}
    volume_override = tmp_path / "existing-volumes.yaml"
    volume_override.write_text("volumes: {}\n", encoding="utf-8")
    try:
        subprocess.run([*base, "up", "--detach", "core"], env=environment, check=True)
        for command in apply_components.build_compose_commands(
            "core", runtime, project, compose_file, volume_override
        ):
            subprocess.run(command.argv, env=environment, check=True)
        for command in apply_components.build_compose_commands(
            "all", runtime, project, compose_file, volume_override
        ):
            subprocess.run(command.argv, env=environment, check=True)
        published = subprocess.run(
            [*base, "--profile", "git-proxy", "port", "gitea", "8080"],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        assert _read_http_when_ready(f"http://{published}") == b"gitea"
        subprocess.run(
            [*base, "--profile", "git-proxy", "exec", "-T", "gitea", "sh", "-c", "echo preserved >/data/marker"],
            env=environment,
            check=True,
        )
        for command in apply_components.build_compose_commands(
            "core", runtime, project, compose_file, volume_override
        ):
            subprocess.run(command.argv, env=environment, check=True)
        running = subprocess.run(
            [*base, "ps", "--services", "--filter", "status=running"],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        assert running.stdout.split() == ["core"]
        with pytest.raises(URLError):
            urlopen(f"http://{published}", timeout=1)
        subprocess.run(
            ["docker", "volume", "inspect", f"{project}_gitea_data"],
            capture_output=True,
            check=True,
        )
        for command in apply_components.build_compose_commands(
            "git-proxy", runtime, project, compose_file, volume_override
        ):
            subprocess.run(command.argv, env=environment, check=True)
        marker = subprocess.run(
            [*base, "--profile", "git-proxy", "exec", "-T", "gitea", "cat", "/data/marker"],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        assert marker.stdout.strip() == "preserved"
    finally:
        subprocess.run(
            [
                *base,
                "--profile",
                "monitoring",
                "--profile",
                "git-proxy",
                "--profile",
                "db-admin",
                "down",
                "--volumes",
            ],
            env=environment,
            check=False,
        )
