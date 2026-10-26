#!/usr/bin/env python3
"""Publish only the one-use browser bootstrap needed by the first IDE profile."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NoReturn


FILE_NAME = "first-owner-browser-v1.json"


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: publish-first-owner-bootstrap.py STATE_DIR RUNTIME_ENV")
    state = Path(sys.argv[1])
    runtime = Path(sys.argv[2])
    state_metadata = os.lstat(state)
    runtime_metadata = os.lstat(runtime)
    if (
        not stat.S_ISDIR(state_metadata.st_mode)
        or stat.S_ISLNK(state_metadata.st_mode)
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
        or state_metadata.st_uid != os.getuid()
    ):
        fail("Runtime state directory must be an owner-only mode-0700 directory.")
    if (
        runtime.parent.resolve(strict=True) != state.resolve(strict=True)
        or not stat.S_ISREG(runtime_metadata.st_mode)
        or stat.S_ISLNK(runtime_metadata.st_mode)
        or runtime_metadata.st_nlink != 1
        or stat.S_IMODE(runtime_metadata.st_mode) != 0o600
        or runtime_metadata.st_uid != os.getuid()
    ):
        fail("Runtime environment must be an owner-only mode-0600 direct child.")

    values: dict[str, str] = {}
    for line in runtime.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"duplicate runtime field: {key}")
        values[key] = value
    required = {"KODESEC_INSTALLATION_ID", "CONTROL_PORT", "KODESEC_BOOTSTRAP_TOKEN"}
    missing = required - values.keys()
    if missing:
        fail(f"missing first-owner bootstrap fields: {', '.join(sorted(missing))}")
    installation_id = values["KODESEC_INSTALLATION_ID"]
    if not re.fullmatch(r"[a-f0-9]{12}", installation_id):
        fail("invalid first-owner installation identity")
    token = values["KODESEC_BOOTSTRAP_TOKEN"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        fail("invalid first-owner bootstrap material")
    try:
        port = int(values["CONTROL_PORT"])
    except ValueError:
        fail("invalid first-owner control port")
    if not 1 <= port <= 65535:
        fail("invalid first-owner control port")

    artifact = state / FILE_NAME
    if artifact.is_symlink():
        fail("refusing a symbolic-link first-owner bootstrap artifact")
    payload = json.dumps(
        {
            "bootstrap_token": token,
            "control_origin": f"http://127.0.0.1:{port}",
            "installation_id": installation_id,
            "v": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{FILE_NAME}.", dir=state, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, artifact)
        directory = os.open(state, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
