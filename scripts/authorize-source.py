#!/usr/bin/env python3
"""Add reviewed narrow source roots or remove one installation-owned root safely.

The web workbench copies an encoded command instead of interpolating a host
path into shell syntax.  This script is the privileged host boundary: it
validates the exact directory and owner-only runtime file, then atomically
updates only the two source-root fields.  It never reads or prints secrets.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NoReturn
from source_roots import (
    MAX_RUNTIME_BYTES, MAX_SOURCE_ROOT_BYTES, MAX_SOURCE_ROOTS, SourceRootError, configured_source_roots, validated_source_root,
)


SOURCE_KEYS = ("KODESEC_REPO_ROOT", "KODESEC_ALLOWED_ROOTS")


def _assert_expected_installation(original: str) -> None:
    expected = os.environ.get("KODESEC_EXPECT_INSTALLATION_ID")
    if expected is None:
        return  # An explicit interactive host operation need not originate in Web.
    identities = [line.split("=", 1)[1] for line in original.splitlines()
                  if line.startswith("KODESEC_INSTALLATION_ID=")]
    if re.fullmatch(r"[a-f0-9]{12}", expected) is None or identities != [expected]:
        fail("The selected runtime does not match this CodeSecurity installation. Select its exact STATE_DIR and rerun the guarded command; no runtime or source authorizations were changed.")


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def _decode_source_root() -> str:
    encoded = os.environ.get("KODESEC_SOURCE_ROOT_B64", "")
    if not encoded:
        if not sys.stdin.isatty():
            fail(
                "No source root was supplied. Use the workbench's Copy host command "
                "action, or run 'make authorize-source' in an interactive terminal."
            )
        selected = input("Exact narrow source root to authorize: ")
        return selected
    if len(encoded) > MAX_SOURCE_ROOT_BYTES * 2 or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in encoded
    ):
        fail("The encoded source root is malformed.")
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
        selected = payload.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"The encoded source root is malformed: {type(error).__name__}.")
    if len(payload) > MAX_SOURCE_ROOT_BYTES:
        fail("The selected source root exceeds the 4096-byte limit.")
    return selected


def _decode_source_roots(operation: str) -> list[str]:
    encoded = os.environ.get("KODESEC_SOURCE_ROOTS_B64", "")
    if not encoded:
        return [_decode_source_root()]
    if os.environ.get("KODESEC_SOURCE_ROOT_B64") or operation != "add":
        fail("Batch authorization only adds reviewed roots; do not combine it with single-root or removal input.")
    if "KODESEC_EXPECT_INSTALLATION_ID" not in os.environ:
        fail("Batch authorization requires the reviewed installation identity; no roots were changed.")
    if len(encoded) > 4 * ((MAX_RUNTIME_BYTES + 2) // 3) or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        fail("The encoded source-root batch is malformed or exceeds its bound.")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(raw) > MAX_RUNTIME_BYTES:
            fail("The source-root batch exceeds its bounded size limit.")
        roots = json.loads(raw.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError, RecursionError):
        fail("The encoded source-root batch is malformed.")
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_SOURCE_ROOTS \
            or any(not isinstance(root, str) for root in roots) \
            or len(set(roots)) != len(roots):
        fail("Choose between one and 32 distinct exact source roots for the batch.")
    try:
        if any(len(root.encode("utf-8")) > MAX_SOURCE_ROOT_BYTES for root in roots):
            fail("A selected source root exceeds the 4096-byte limit.")
    except UnicodeError:
        fail("The source-root batch contains invalid Unicode.")
    return roots




def _runtime_path() -> Path:
    state = Path(
        os.environ.get(
            "KODESEC_STATE_DIR",
            os.path.join(
                os.environ.get("XDG_STATE_HOME", os.path.join(Path.home(), ".local", "state")),
                "lomo-kodesec",
            ),
        )
    )
    if state.is_symlink():
        fail("Refusing a symlink runtime state directory.")
    try:
        canonical_state = state.resolve(strict=True)
    except OSError as error:
        if "KODESEC_EXPECT_INSTALLATION_ID" in os.environ:
            fail("The selected installation state is unavailable. Select this installation's exact STATE_DIR and rerun the guarded command; no runtime was created.")
        fail(f"Runtime state is not initialized: {type(error).__name__}; run 'make init'.")
    runtime = Path(
        os.environ.get("KODESEC_RUNTIME_ENV", str(canonical_state / "runtime.env"))
    )
    if runtime.parent.resolve(strict=False) != canonical_state or runtime.name in {"", ".", ".."}:
        fail("Runtime environment must be a direct child of the runtime state directory.")
    state_stat = os.lstat(canonical_state)
    if (
        not stat.S_ISDIR(state_stat.st_mode)
        or stat.S_IMODE(state_stat.st_mode) != 0o700
        or state_stat.st_uid != os.getuid()
    ):
        fail("Runtime state directory must be owner-only mode 0700.")
    return runtime


def _read_private_runtime(runtime: Path) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(runtime, flags)
    except OSError as error:
        if "KODESEC_EXPECT_INSTALLATION_ID" in os.environ:
            fail("The selected installation runtime is unavailable. Select this installation's exact STATE_DIR and rerun the guarded command; no runtime was created.")
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
            chunk = os.read(descriptor, min(16 * 1024, MAX_RUNTIME_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_RUNTIME_BYTES:
            fail("Runtime configuration exceeds the bounded size limit.")
        try:
            return bytes(payload).decode("utf-8", errors="strict"), metadata
        except UnicodeDecodeError:
            fail("Runtime configuration is not valid UTF-8.")
    finally:
        os.close(descriptor)


def _updated_runtime(original: str, source_roots: list[str], operation: str) -> str:
    lines = original.splitlines(keepends=True)
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        content = line.rstrip("\r\n")
        if not content or content.startswith("#") or "=" not in content:
            continue
        key = content.split("=", 1)[0]
        if key in positions:
            fail(f"Runtime configuration contains a duplicate field: {key}.")
        positions[key] = index
    missing = [key for key in SOURCE_KEYS if key not in positions]
    if missing:
        fail(f"Runtime configuration is missing source fields: {', '.join(missing)}.")
    values = {
        key: lines[positions[key]].rstrip("\r\n").split("=", 1)[1]
        for key in SOURCE_KEYS
    }
    roots = configured_source_roots(values["KODESEC_REPO_ROOT"], values["KODESEC_ALLOWED_ROOTS"])
    if operation == "remove":
        source_root = source_roots[0]
        if source_root not in roots:
            raise SourceRootError("The exact source root is not currently authorized; no roots were changed.")
        roots.remove(source_root)
        if not roots:
            raise SourceRootError("Cannot remove the last source root; authorize its replacement first.")
    else:
        roots.extend(source_root for source_root in source_roots if source_root not in roots)
    configured_source_roots(roots[0], ",".join(roots))
    replacements = {"KODESEC_REPO_ROOT": roots[0], "KODESEC_ALLOWED_ROOTS": ",".join(roots)}
    for key in SOURCE_KEYS:
        ending = "\n" if lines[positions[key]].endswith("\n") else ""
        lines[positions[key]] = f"{key}={replacements[key]}{ending}"
    updated = "".join(lines)
    if len(updated.encode("utf-8")) > MAX_RUNTIME_BYTES:
        raise SourceRootError("The source change exceeds the 64-KiB runtime configuration limit; no authorizations were changed.")
    return updated


def _write_private_runtime(runtime: Path, original_stat: os.stat_result, updated: str) -> None:
    current = os.lstat(runtime)
    stable_identity = (
        current.st_dev == original_stat.st_dev
        and current.st_ino == original_stat.st_ino
        and current.st_size == original_stat.st_size
        and current.st_mtime_ns == original_stat.st_mtime_ns
        and current.st_nlink == 1
        and stat.S_ISREG(current.st_mode)
        and stat.S_IMODE(current.st_mode) == 0o600
        and current.st_uid == os.getuid()
    )
    if not stable_identity:
        fail("Runtime configuration changed during authorization; retry from current state.")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{runtime.name}.source-root-",
        dir=runtime.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = updated.encode("utf-8")
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("runtime configuration write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, runtime)
        directory = os.open(runtime.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def _source_transaction(runtime: Path):
    """Serialize the full read/derive/replace transaction, not just the rename."""
    try:
        descriptor = os.open(runtime.parent / ".source-roots.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as error:
        fail(f"Source authorization lock is unavailable: {type(error).__name__}; no roots were changed.")
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
            fail("Source authorization lock must be an owner-only single-link regular file.")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def main() -> None:
    if sys.argv[1:] == ["--check-installation"]:
        if "KODESEC_EXPECT_INSTALLATION_ID" not in os.environ:
            fail("An expected installation identity is required for this check.")
        runtime = _runtime_path()
        original, _ = _read_private_runtime(runtime)
        _assert_expected_installation(original)
        return
    if sys.argv[1:]:
        fail("Unsupported source authorization arguments; no roots were changed.")
    operation = os.environ.get("KODESEC_SOURCE_OPERATION", "add")
    if operation not in {"add", "remove"}:
        fail("Source operation must be 'add' or 'remove'; no roots were changed.")
    selected = _decode_source_roots(operation)
    batch = bool(os.environ.get("KODESEC_SOURCE_ROOTS_B64"))
    try:
        # Removal uses the exact persisted identity, even if the directory is gone.
        source_roots = [str(validated_source_root(root)) for root in selected] if operation == "add" else selected
        if batch and (source_roots != selected or len(set(source_roots)) != len(source_roots)):
            fail("Review canonical, distinct source-root identities before batch authorization.")
        if batch and any(Path(left) in Path(right).parents for left in source_roots for right in source_roots if left != right):
            fail("Select independent narrow roots; a batch must not include their parent or overlapping directories.")
        if operation == "remove":
            configured_source_roots(source_roots[0], source_roots[0])
    except SourceRootError as error:
        fail(str(error))
    runtime = _runtime_path()
    if "KODESEC_EXPECT_INSTALLATION_ID" in os.environ:
        original, _ = _read_private_runtime(runtime)
        _assert_expected_installation(original)
    with _source_transaction(runtime):
        original, metadata = _read_private_runtime(runtime)
        _assert_expected_installation(original)
        try:
            if operation == "add" and any(str(validated_source_root(root)) != root for root in source_roots):
                fail("A selected source root changed during authorization; review it again.")
            updated = _updated_runtime(original, source_roots, operation)
        except SourceRootError as error:
            fail(str(error))
        if updated != original:
            _write_private_runtime(runtime, metadata, updated)
    if batch:
        print(f"Reviewed source-root batch {'was already authorized' if updated == original else 'authorized atomically'} ({len(source_roots)} roots):")
        for source_root in source_roots:
            print(f"  {source_root}")
        print("All other source authorizations and stored projects are preserved.")
    elif updated == original:
        print(f"Source root is already authorized: {source_roots[0]}")
    else:
        label = "Authorized" if operation == "add" else "Removed authorization for"
        print(f"{label} exact read-only source root: {source_roots[0]}")
        print("All other source authorizations and stored projects are preserved.")
    if os.environ.get("KODESEC_SOURCE_APPLY") == "1":
        print(
            "Applying the source boundary by recreating only scanner, API, and worker "
            "from installed images."
        )
    else:
        print(
            "Run 'make apply-source' to recreate only scanner, API, and worker from "
            "installed images; existing database and scanner-cache volumes are preserved."
        )


if __name__ == "__main__":
    main()
