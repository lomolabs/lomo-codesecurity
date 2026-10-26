from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .cache_manifest import ToolLockFile, load_tool_lock
from .source_build import verify_source_build
from .tools import (
    EXTERNAL_TOOL_VERSIONS,
    OPENGREP_CORE_PATH,
    OPENGREP_EXECUTABLE_PATH,
    OPENGREP_HOME_PATH,
    TOOL_VERSION_COMMANDS,
    binary_sha256,
    version_output_matches,
)


MAX_VERSION_OUTPUT_BYTES = 64 * 1024
DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS = 30
MAX_VERSION_PROBE_TIMEOUT_SECONDS = 60


def _version_probe_timeout(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_VERSION_PROBE_TIMEOUT_SECONDS:
        raise ValueError(
            f"version probe timeout must be an integer from 1 to {MAX_VERSION_PROBE_TIMEOUT_SECONDS} seconds"
        )
    return value


def _probe_platform_factor(platform: str) -> float:
    try:
        return {"mac": 1, "linux": 2.6, "windows": 3.9}[platform]
    except (KeyError, TypeError) as exc:
        raise ValueError("version probe platform must be mac, linux, or windows") from exc


def _version_environment(command: list[str]) -> dict[str, str]:
    environment = {
        **os.environ,
        "BEARER_TELEMETRY_ENABLED": "false",
        "CHECKOV_SKIP_FRAMEWORK_DOWNLOADS": "true",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "NO_COLOR": "1",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }
    if Path(command[0]).name == "opengrep":
        environment["HOME"] = str(OPENGREP_HOME_PATH)
        environment["PATH"] = os.pathsep.join(
            part
            for part in (
                str(OPENGREP_EXECUTABLE_PATH.parent),
                environment.get("PATH", ""),
            )
            if part
        )
    return environment


def _bounded_version_output(
    command: list[str],
    *,
    timeout_seconds: int = DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS,
    platform: str = "mac",
) -> str:
    deadline = _version_probe_timeout(timeout_seconds) * _probe_platform_factor(platform)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=_version_environment(command),
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=deadline)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise RuntimeError(f"version probe timed out: {command[0]}") from exc
        output.seek(0, os.SEEK_END)
        size = output.tell()
        if size > MAX_VERSION_OUTPUT_BYTES:
            raise RuntimeError(f"version probe output is too large: {command[0]}")
        output.seek(0)
        rendered = output.read().decode("utf-8", errors="replace").strip()
    if return_code != 0:
        raise RuntimeError(f"version probe failed: {command[0]} (exit {return_code})")
    return rendered


def verified_manifest(
    *,
    probe_timeout_seconds: int = DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS,
    tool_lock: ToolLockFile | None = None,
    platform: str = "mac",
) -> dict[str, Any]:
    deadline = _version_probe_timeout(probe_timeout_seconds)
    _probe_platform_factor(platform)
    tools: dict[str, Any] = {}
    for tool_id, expected_version in EXTERNAL_TOOL_VERSIONS.items():
        command = TOOL_VERSION_COMMANDS[tool_id]
        discovered = shutil.which(command[0])
        if not discovered:
            raise RuntimeError(f"required scanner binary is missing: {tool_id}")
        binary = Path(discovered).resolve(strict=True)
        output = _bounded_version_output(command, timeout_seconds=deadline, platform=platform)
        if not version_output_matches(output, expected_version):
            raise RuntimeError(
                f"scanner version mismatch for {tool_id}: expected {expected_version}"
            )
        tool_manifest: dict[str, Any] = {
            "command": command,
            "installed_version": expected_version,
            "path": str(binary),
            "sha256": binary_sha256(binary),
        }
        if tool_lock is not None:
            locked = tool_lock.tool(tool_id)
            if locked.version != expected_version:
                raise RuntimeError(f"scanner lock version mismatch: {tool_id}")
            if locked.binary.source_build is not None:
                tool_manifest["source_build"] = verify_source_build(locked.binary.source_build, binary)
        if tool_id == "opengrep":
            if OPENGREP_CORE_PATH.parent.name != f"v{expected_version}":
                raise RuntimeError("OpenGrep core path does not match the pinned version")
            if OPENGREP_CORE_PATH.is_symlink() or not OPENGREP_CORE_PATH.is_file():
                raise RuntimeError("required OpenGrep native core is missing")
            if OPENGREP_CORE_PATH.stat().st_mode & 0o111 == 0:
                raise RuntimeError("required OpenGrep native core is not executable")
            core = OPENGREP_CORE_PATH.resolve(strict=True)
            if (
                not OPENGREP_EXECUTABLE_PATH.is_symlink()
                or OPENGREP_EXECUTABLE_PATH.resolve(strict=True) != core
            ):
                raise RuntimeError("OpenGrep native executable alias is invalid")
            tool_manifest["runtime_components"] = {
                "opengrep_core": {
                    "path": str(core),
                    "sha256": binary_sha256(core),
                }
            }
        tools[tool_id] = tool_manifest
    return {"schema_version": 1, "tools": tools}


def write_manifest(
    path: Path,
    *,
    probe_timeout_seconds: int = DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS,
    tool_lock_path: Path = Path("/usr/local/share/kodesec/locks/scanner-tools.lock.json"),
    platform: str = "mac",
) -> None:
    manifest = verified_manifest(
        probe_timeout_seconds=probe_timeout_seconds,
        tool_lock=load_tool_lock(tool_lock_path).value,
        platform=platform,
    )
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".tool-manifest.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o444)
            json.dump(manifest, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail closed unless all curated scanners are exact.")
    parser.add_argument("--write", type=Path, required=True)
    parser.add_argument(
        "--probe-timeout-seconds",
        type=int,
        default=DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS,
        help="Mac-reference version probe deadline (1-60 seconds; default: 30), scaled once by --platform.",
    )
    parser.add_argument("--platform", choices=("mac", "linux", "windows"), default="mac")
    arguments = parser.parse_args()
    try:
        probe_timeout_seconds = _version_probe_timeout(arguments.probe_timeout_seconds)
    except ValueError as exc:
        parser.error(str(exc))
    write_manifest(
        arguments.write,
        probe_timeout_seconds=probe_timeout_seconds,
        platform=arguments.platform,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
