#!/usr/bin/env python3
"""Run the product Compose file using only the validated runtime authority."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn

from source_roots import MAX_RUNTIME_BYTES, SourceRootError, configured_source_roots, validated_source_root


MAX_COMPOSE_BYTES = 256 * 1024
PROJECT_NAME = re.compile(r"lomo-code-security-[a-f0-9]{12}\Z")
RUNTIME_KEY = re.compile(r"[A-Z][A-Z0-9_]*\Z")
COMPOSE_INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}")
SOURCE_PROVENANCE_KEYS = {
    "KODESEC_SOURCE_COMMIT", "KODESEC_SOURCE_TREE", "KODESEC_SOURCE_KIND", "KODESEC_SOURCE_DIGEST",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def read_runtime(path: Path) -> dict[str, str]:
    try:
        supplied_metadata = path.lstat()
    except OSError as error:
        fail(f"Runtime configuration is unavailable: {type(error).__name__}; run make init")
    if stat.S_ISLNK(supplied_metadata.st_mode):
        fail("Runtime configuration must not be a symbolic link.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"Runtime configuration is unavailable: {type(error).__name__}; run make init")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_RUNTIME_BYTES
        ):
            fail("Runtime configuration must be an owner-only, single-link regular file.")
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
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail("Runtime configuration contains a malformed field.")
        key, value = line.split("=", 1)
        if not RUNTIME_KEY.fullmatch(key):
            fail("Runtime configuration contains a malformed field name.")
        if key in values:
            fail(f"Runtime configuration contains a duplicate field: {key}.")
        values[key] = value
    return values


def compose_interpolation_keys(path: Path) -> set[str]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > MAX_COMPOSE_BYTES
    ):
        fail("The checked-in Compose authority is unavailable or malformed.")
    text = path.read_text(encoding="utf-8")
    matches = COMPOSE_INTERPOLATION.findall(text)
    if text.count("${") != len(matches):
        fail("The checked-in Compose authority contains an unsupported interpolation.")
    return {key.upper() for key in matches}


def main(arguments: list[str]) -> None:
    if len(arguments) < 2:
        fail("Usage: scripts/runtime-compose.py /absolute/runtime.env <compose arguments...>")
    supplied_runtime = Path(arguments[0])
    values = read_runtime(supplied_runtime)
    try:
        source_roots = configured_source_roots(
            values.get("KODESEC_REPO_ROOT", ""), values.get("KODESEC_ALLOWED_ROOTS", ""),
        )
    except SourceRootError as error:
        fail(str(error))
    if any(argument in {"up", "create", "run", "start", "restart", "watch"} for argument in arguments[1:]):
        for root in source_roots:
            try:
                if validated_source_root(root).as_posix() != root:
                    fail("An authorized source now resolves to a different host path. Restore it or explicitly re-authorize the exact source; no container was started.")
            except SourceRootError as error:
                fail(f"Source startup preflight failed: {error} Restore or remove the exact authorization; teardown remains available.")
    runtime = Path(os.path.abspath(supplied_runtime))
    project_name = values.get("COMPOSE_PROJECT_NAME", "")
    if not PROJECT_NAME.fullmatch(project_name):
        fail("Runtime configuration has a missing or malformed Compose project name.")

    repo_root = Path(__file__).resolve().parent.parent
    compose_file = repo_root / "docker-compose.yml"
    if SOURCE_PROVENANCE_KEYS & values.keys():
        fail("Runtime configuration must not supply image-build source provenance.")
    blocked = (
        {key.upper() for key in values}
        | compose_interpolation_keys(compose_file)
    ) - SOURCE_PROVENANCE_KEYS
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in blocked and not key.upper().startswith("COMPOSE_")
    }
    command = [
        "docker",
        "compose",
        "--project-name",
        project_name,
    ]
    try:
        # Additional mounts are derived only from the validated owner runtime,
        # not an ambient Compose override. Freeze the same runtime for Docker:
        # an owner changing authorization meanwhile must not mix two root sets.
        # Private files preserve interactive stdin and disappear with the child.
        with tempfile.TemporaryDirectory(prefix=".source-mounts-", dir=runtime.parent) as directory:
            snapshot = Path(directory) / "runtime.env"
            with open(snapshot, "x", encoding="utf-8", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
            command.extend(["--env-file", os.fspath(snapshot), "--file", os.fspath(compose_file)])
            override = Path(directory) / "sources.json"
            if len(source_roots) > 1:
                with open(override, "x", encoding="utf-8", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                    json.dump({"services": {"scanner": {"volumes": [
                        {"type": "bind", "source": root, "target": root,
                         "read_only": True, "bind": {"create_host_path": False}}
                        for root in source_roots[1:]
                    ]}}}, stream)
                command.extend(["--file", os.fspath(override)])
            result = subprocess.run(
                [*command, *arguments[1:]],
                env=environment, check=False,
            )
        raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
    except FileNotFoundError:
        fail("Docker Compose is not installed or is not available on PATH.")
    except PermissionError:
        fail("Docker Compose could not be executed with the current permissions.")


if __name__ == "__main__":
    main(sys.argv[1:])
