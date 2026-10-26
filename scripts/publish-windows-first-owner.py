#!/usr/bin/env python3
"""Hand one existing WSL installer bootstrap to the same Windows account.

Only the reviewed four-field bootstrap crosses stdin. Runtime secrets stay in
WSL, and the native publication journal prevents replay after consumption.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


FILE_NAME = "first-owner-browser-v1.json"
MAX_RUNTIME_BYTES = 64 * 1024
MAX_BOOTSTRAP_BYTES = 2048
SCRIPT = Path(__file__).with_name("publish-windows-first-owner.ps1")
STORAGE_SCRIPT = Path(__file__).with_name("windows-installer-storage.ps1")


class HandoffError(ValueError):
    """Secret-safe installer refusal; callers must not print subprocess output."""


def private_read(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= limit):
            raise HandoffError("First-owner handoff requires a bounded owner-private regular file.")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                  value.st_mode, value.st_uid, value.st_nlink)
        if len(data) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
            raise HandoffError("First-owner handoff input changed while read; no authority was published.")
        return bytes(data)
    finally:
        os.close(descriptor)


def no_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HandoffError("First-owner handoff input contains duplicate fields.")
        result[key] = value
    return result


def handoff_request(state: Path, runtime: Path) -> dict[str, object]:
    metadata = os.lstat(state)
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700
            or state.resolve(strict=True) != state or runtime.parent != state):
        raise HandoffError("First-owner handoff requires the exact owner-private runtime directory.")
    values: dict[str, str] = {}
    for line in private_read(runtime, MAX_RUNTIME_BYTES).decode("utf-8", errors="strict").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise HandoffError("First-owner runtime configuration is malformed.")
        key, value = line.split("=", 1)
        if key in values:
            raise HandoffError("First-owner runtime configuration contains duplicate fields.")
        values[key] = value
    installation = values.get("KODESEC_INSTALLATION_ID", "")
    port = values.get("CONTROL_PORT", "")
    token = values.get("KODESEC_BOOTSTRAP_TOKEN", "")
    if (not re.fullmatch(r"[a-f0-9]{12}", installation)
            or not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)):
        raise HandoffError("First-owner runtime identity is malformed.")
    origin = f"http://127.0.0.1:{port}"
    try:
        raw = private_read(state / FILE_NAME, MAX_BOOTSTRAP_BYTES)
    except FileNotFoundError:
        bootstrap = None
    else:
        bootstrap = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=no_duplicate_fields)
        if (not isinstance(bootstrap, dict) or set(bootstrap) != {"v", "installation_id", "control_origin", "bootstrap_token"}
                or type(bootstrap["v"]) is not int or bootstrap["v"] != 1
                or bootstrap["installation_id"] != installation or bootstrap["control_origin"] != origin
                or bootstrap["bootstrap_token"] != token):
            raise HandoffError("Existing first-owner authority does not match this installation; no authority was published.")
    return {"installation_id": installation, "control_origin": origin, "bootstrap": bootstrap}


def native_powershell() -> str:
    if sys.platform != "linux" or "microsoft" not in Path("/proc/sys/kernel/osrelease").read_text().lower():
        raise HandoffError("Native Windows first-owner handoff must run inside Windows WSL.")
    supplied = shutil.which("powershell.exe")
    if not supplied:
        raise HandoffError("Windows PowerShell interop is unavailable; native first-owner handoff was not performed.")
    executable = Path(supplied).resolve(strict=True)
    mapped = subprocess.run(["wslpath", "-w", str(executable)], capture_output=True, text=True, timeout=10, check=False)
    native = mapped.stdout.rstrip("\r\n")
    if (mapped.returncode != 0 or not re.fullmatch(
            r"[A-Za-z]:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe", native, re.IGNORECASE)):
        raise HandoffError("Refusing a non-system PowerShell executable for first-owner handoff.")
    return str(executable)


def native_program() -> str:
    return STORAGE_SCRIPT.read_text(encoding="utf-8") + "\n" + SCRIPT.read_text(encoding="utf-8")


def publish(request: dict[str, object], executable: str) -> str:
    program = native_program()
    if len(program.encode("utf-8")) > 24 * 1024:
        raise HandoffError("Native first-owner handoff program exceeds its reviewed bound.")
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", program],
        input=json.dumps(request, separators=(",", ":")), capture_output=True, text=True,
        timeout=30, check=False,
    )
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 4096:
        raise HandoffError("Native first-owner handoff was refused or incomplete. Review this account's local installer storage; existing credentials and permissions were not replaced.")
    response = json.loads(result.stdout, object_pairs_hook=no_duplicate_fields)
    if (not isinstance(response, dict) or set(response) != {"status", "installation_id", "control_origin"}
            or response["installation_id"] != request["installation_id"]
            or response["control_origin"] != request["control_origin"]
            or response["status"] not in {"published", "retained", "unavailable"}):
        raise HandoffError("Native first-owner handoff returned an invalid receipt.")
    return str(response["status"])


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: publish-windows-first-owner.py STATE_DIR RUNTIME_ENV")
    try:
        executable = native_powershell()
        request = handoff_request(Path(sys.argv[1]), Path(sys.argv[2]))
        status = publish(request, executable)
    except (HandoffError, OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, HandoffError) else "Native first-owner handoff could not complete; no retry authority was generated."
        raise SystemExit(message) from None
    messages = {
        "published": "The existing first-owner authority is ready for native Windows VS Code in this account.",
        "retained": "Native Windows first-owner publication was already recorded; no authority was replaced or recreated.",
        "unavailable": "No unconsumed first-owner authority remains. Additional native editors use approval in the existing owner browser.",
    }
    print(messages[status])


if __name__ == "__main__":
    main()
