#!/usr/bin/env python3
"""Reconcile one validated optional-component selection without deleting data."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Literal, NamedTuple, NoReturn


MAX_RUNTIME_BYTES = 128 * 1024
MAX_VOLUME_INVENTORY_BYTES = 4 * 1024
PROJECT_NAME_PATTERN = re.compile(r"lomo-code-security-[a-f0-9]{12}")
OPTIONAL_SERVICES = {
    "monitoring": ("grafana", "prometheus"),
    "git-proxy": ("gitea",),
    "db-admin": ("adminer",),
}
COMPONENT_SETS = {
    "core": (),
    "monitoring": ("monitoring",),
    "git-proxy": ("git-proxy",),
    "db-admin": ("db-admin",),
    "monitoring-git-proxy": ("monitoring", "git-proxy"),
    "monitoring-db-admin": ("monitoring", "db-admin"),
    "git-proxy-db-admin": ("git-proxy", "db-admin"),
    "all": ("monitoring", "git-proxy", "db-admin"),
}
VOLUME_KEYS = (
    "pg_data",
    "artifacts",
    "source_snapshots",
    "scanner_cache",
    "gitea_data",
    "gitea_config",
    "prometheus_data",
    "grafana_data",
)


class ComposeCommand(NamedTuple):
    """One fixed, argument-vector-only optional-component operation."""

    operation: Literal["remove_optional", "start_optional"]
    argv: tuple[str, ...]


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def _selected_profiles(component_set: str) -> tuple[str, ...]:
    try:
        return COMPONENT_SETS[component_set]
    except KeyError:
        fail("COMPONENTS must be one of: " + ", ".join(COMPONENT_SETS) + ".")


def _validate_project_name(project_name: str) -> None:
    if PROJECT_NAME_PATTERN.fullmatch(project_name) is None:
        fail("Runtime configuration has a missing or malformed COMPOSE_PROJECT_NAME.")


def _state_and_runtime() -> tuple[Path, Path]:
    state = Path(
        os.environ.get(
            "KODESEC_STATE_DIR",
            os.path.join(
                os.environ.get(
                    "XDG_STATE_HOME", os.path.join(Path.home(), ".local", "state")
                ),
                "lomo-kodesec",
            ),
        )
    )
    if state.is_symlink():
        fail("Refusing a symlink runtime state directory.")
    try:
        canonical_state = state.resolve(strict=True)
    except OSError as error:
        fail(f"Runtime state is not initialized: {type(error).__name__}; run 'make init'.")
    metadata = os.lstat(canonical_state)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        fail("Runtime state directory must be owner-only mode 0700.")
    runtime = Path(
        os.environ.get("KODESEC_RUNTIME_ENV", str(canonical_state / "runtime.env"))
    )
    if (
        runtime.parent.resolve(strict=False) != canonical_state
        or runtime.name in {"", ".", ".."}
    ):
        fail("Runtime environment must be a direct child of the runtime state directory.")
    return canonical_state, runtime


def _runtime_values(runtime: Path) -> dict[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(runtime, flags)
    except OSError as error:
        fail(f"Runtime configuration is unavailable: {type(error).__name__}; run 'make init'.")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            fail("Runtime configuration must be an owner-only mode-0600 single-link file.")
        if metadata.st_size > MAX_RUNTIME_BYTES:
            fail("Runtime configuration exceeds the bounded size limit.")
        payload = bytearray()
        while len(payload) <= MAX_RUNTIME_BYTES:
            chunk = os.read(
                descriptor,
                min(16 * 1024, MAX_RUNTIME_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_RUNTIME_BYTES:
            fail("Runtime configuration exceeds the bounded size limit.")
        try:
            text = bytes(payload).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("Runtime configuration is not valid UTF-8.")
    finally:
        os.close(descriptor)

    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"Runtime configuration contains a duplicate field: {key}.")
        values[key] = value
    return values


def build_compose_commands(
    component_set: str,
    runtime: Path,
    project_name: str,
    compose_file: Path,
    volume_override: Path,
) -> tuple[ComposeCommand, ...]:
    """Return an optional-service-only reconciliation plan for one selection."""
    selected_profiles = _selected_profiles(component_set)
    _validate_project_name(project_name)

    base = (
        "docker",
        "compose",
        "--env-file",
        os.fspath(runtime),
        "--project-name",
        project_name,
        "--file",
        os.fspath(compose_file),
        "--file",
        os.fspath(volume_override),
    )
    deselected_services = tuple(
        service
        for profile, services in OPTIONAL_SERVICES.items()
        if profile not in selected_profiles
        for service in services
    )
    commands: list[ComposeCommand] = []
    if deselected_services:
        commands.append(
            ComposeCommand(
                "remove_optional",
                (*base, "rm", "--force", "--stop", *deselected_services),
            )
        )
    profile_args = tuple(
        argument
        for profile in selected_profiles
        for argument in ("--profile", profile)
    )
    selected_services = tuple(
        service
        for profile in selected_profiles
        for service in OPTIONAL_SERVICES[profile]
    )
    if selected_services:
        commands.append(
            ComposeCommand(
                "start_optional",
                (
                    *base,
                    *profile_args,
                    "up",
                    "--detach",
                    "--no-build",
                    "--no-deps",
                    "--pull",
                    "never",
                    *selected_services,
                ),
            )
        )
    return tuple(commands)


def _volume_exists(volume_name: str, environment: dict[str, str]) -> bool:
    command = (
        "docker",
        "volume",
        "ls",
        "--quiet",
        "--filter",
        f"name=^{volume_name}$",
    )
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"Cannot inventory existing product volumes: {type(error).__name__}.")
    assert process.stdout is not None
    payload = process.stdout.read(MAX_VOLUME_INVENTORY_BYTES + 1)
    if len(payload) > MAX_VOLUME_INVENTORY_BYTES:
        process.kill()
        process.wait()
        fail("Product volume inventory exceeded the bounded output limit.")
    returncode = process.wait()
    if returncode != 0:
        fail(f"Product volume inventory failed with exit status {returncode}.")
    try:
        output = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("Product volume inventory returned invalid UTF-8.")
    if output == "":
        return False
    if output not in {volume_name, f"{volume_name}\n", f"{volume_name}\r\n"}:
        fail("Product volume inventory returned an unexpected volume name.")
    return True


def _existing_volume_keys(
    project_name: str,
    environment: dict[str, str],
) -> tuple[str, ...]:
    _validate_project_name(project_name)
    return tuple(
        key
        for key in VOLUME_KEYS
        if _volume_exists(f"{project_name}_{key}", environment)
    )


def _create_volume_override(
    state: Path,
    project_name: str,
    existing_keys: tuple[str, ...],
) -> Path:
    _validate_project_name(project_name)
    if any(key not in VOLUME_KEYS for key in existing_keys):
        fail("Refusing a non-catalog product volume override.")
    if existing_keys:
        lines = ["volumes:"]
        for key in existing_keys:
            lines.extend(
                (
                    f"  {key}:",
                    "    external: true",
                    f"    name: {project_name}_{key}",
                )
            )
        payload = "\n".join(lines) + "\n"
    else:
        payload = "volumes: {}\n"

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".apply-components-volumes-",
            suffix=".yaml",
            dir=state,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
    except OSError as error:
        fail(f"Cannot create the temporary product volume override: {type(error).__name__}.")
    return Path(temporary_name)


def _locked_state_file(state: Path):
    lock_path = state / ".apply-components.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        fail(f"Cannot open component reconciliation lock: {type(error).__name__}.")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        fail("Component reconciliation lock must be an owner-only mode-0600 file.")
    return os.fdopen(descriptor, "r+")


def main() -> None:
    os.umask(0o077)
    component_set = os.environ.get("KODESEC_COMPONENT_SET", "")
    state, runtime = _state_and_runtime()
    values = _runtime_values(runtime)
    if values.get("COMPOSE_PROFILES", ""):
        fail("Runtime configuration must not override COMPOSE_PROFILES.")
    project_name = values.get("COMPOSE_PROJECT_NAME", "")
    _selected_profiles(component_set)
    _validate_project_name(project_name)
    repo_root = Path(__file__).resolve().parents[1]
    compose_file = repo_root / "docker-compose.yml"
    environment = os.environ.copy()
    environment["COMPOSE_PROFILES"] = ""
    environment["COMPOSE_PROJECT_NAME"] = project_name
    environment.pop("COMPOSE_FILE", None)
    environment.pop("COMPOSE_PATH_SEPARATOR", None)

    with _locked_state_file(state) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing_keys = _existing_volume_keys(project_name, environment)
        volume_override = _create_volume_override(state, project_name, existing_keys)
        try:
            commands = build_compose_commands(
                component_set,
                runtime,
                project_name,
                compose_file,
                volume_override,
            )
            for command in commands:
                subprocess.run(command.argv, cwd=repo_root, env=environment, check=True)
        finally:
            volume_override.unlink()
    print(f"Applied validated component selection: {component_set}.")


if __name__ == "__main__":
    main()
