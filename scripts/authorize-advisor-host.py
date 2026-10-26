#!/usr/bin/env python3
"""Authorize one exact Advisor direct host or pinned SSH provider safely."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn

MAX_DOCUMENT_BYTES = 16 * 1024
MAX_RUNTIME_BYTES = 128 * 1024
SAFE_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?\Z")
PROVIDER_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
AUTHORIZED_KEYS_POLICY = 'restrict,port-forwarding,permitopen="127.0.0.1:11434"'
SSH_ATTESTATION = "I_HAVE_INSTALLED_THE_RESTRICTED_ADVISOR_KEY"


def normalize_host(value: object, *, name: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if (
        not host
        or len(host) > 15
        or any(character in host for character in "/\\@:%[]")
    ):
        fail(f"{name} must be one exact IPv4 address.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        fail(f"{name} must be one exact IPv4 address.")
    if address.version != 4 or any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    ):
        fail(f"{name} targets an unsafe special-purpose address.")
    return address.compressed


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def _decode() -> dict[str, Any]:
    encoded = os.environ.get("KODESEC_ADVISOR_AUTHORIZATION_B64", "")
    if not encoded or len(encoded) > MAX_DOCUMENT_BYTES * 2 or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in encoded
    ):
        fail("KODESEC_ADVISOR_AUTHORIZATION_B64 is missing or malformed.")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                fail("Advisor authorization contains a duplicate JSON field.")
            result[key] = value
        return result
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        fail("Advisor authorization is not strict UTF-8 JSON.")
    if len(raw) > MAX_DOCUMENT_BYTES or not isinstance(document, dict):
        fail("Advisor authorization exceeds its bound or is not an object.")
    return document


def _state() -> tuple[Path, Path]:
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
        state = state.resolve(strict=True)
    except OSError:
        fail("Runtime state is not initialized; run 'make init'.")
    metadata = os.lstat(state)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        fail("Runtime state directory must be owner-only mode 0700.")
    runtime = Path(os.environ.get("KODESEC_RUNTIME_ENV", str(state / "runtime.env")))
    if runtime.parent.resolve(strict=False) != state:
        fail("Runtime environment must be a direct child of runtime state.")
    return state, runtime


def _safe_read(path: Path, maximum: int, *, private: bool = True) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"Required authorization input is unavailable: {type(exc).__name__}.")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
            or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            fail("Authorization input must be an owner-only regular single-link file.")
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > maximum:
            fail("Authorization input exceeds its bounded size.")
        return bytes(payload), metadata
    finally:
        os.close(descriptor)


def _atomic(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("authorization write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


def _runtime_values(runtime: Path) -> tuple[list[str], dict[str, str], os.stat_result]:
    raw, metadata = _safe_read(runtime, MAX_RUNTIME_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("Runtime configuration is not UTF-8.")
    lines = text.splitlines()
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"Runtime configuration contains duplicate field: {key}.")
        values[key] = value
    return lines, values, metadata


def _update_runtime(runtime: Path, key: str, item: str) -> None:
    lines, values, original = _runtime_values(runtime)
    current = [part.strip() for part in values.get(key, "").split(",") if part.strip()]
    if item not in current:
        current.append(item)
    current = sorted(set(current))
    updated = False
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = f"{key}={','.join(current)}"
            updated = True
            break
    if not updated:
        fail(f"Runtime configuration is missing {key}; rerun 'make init'.")
    now = os.lstat(runtime)
    if (now.st_dev, now.st_ino, now.st_mtime_ns, now.st_size) != (
        original.st_dev,
        original.st_ino,
        original.st_mtime_ns,
        original.st_size,
    ):
        fail("Runtime configuration changed during authorization; retry.")
    _atomic(runtime, ("\n".join(lines) + "\n").encode("utf-8"))


def _owner_directory(path: Path, *, parent: Path) -> Path:
    if path.parent != parent or parent.is_symlink():
        fail("Authorization directory escaped its owner-only parent.")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        fail("Authorization directory must be owner-only mode 0700.")
    return path


def _public_key_payload(value: bytes) -> tuple[bytes, str]:
    try:
        text = value.decode("ascii").strip()
        fields = text.split()
        if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
            raise ValueError
        key_bytes = base64.b64decode(fields[1], validate=True)
    except (UnicodeDecodeError, ValueError):
        fail("Dedicated Advisor public key is not valid Ed25519 material.")
    public = f"ssh-ed25519 {fields[1]} lomo-kodesec-advisor\n".encode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_bytes).digest()
    ).decode("ascii").rstrip("=")
    return public, fingerprint


def _derive_public_key(identity: Path) -> bytes:
    try:
        completed = subprocess.run(
            ["/usr/bin/ssh-keygen", "-y", "-f", str(identity)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
            env={"HOME": str(identity.parent), "LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("Could not validate the dedicated Advisor identity.")
    if completed.returncode != 0 or len(completed.stdout) > 16 * 1024:
        fail("Dedicated Advisor identity is invalid or not Ed25519.")
    return completed.stdout


def _dedicated_identity(destination: Path, provider_id: str) -> tuple[bytes, str]:
    identity = destination / "id_ed25519"
    public_path = destination / "id_ed25519.pub"
    authorization_path = destination / "authorization.json"
    exists = [path.exists() or path.is_symlink() for path in (identity, public_path)]
    if any(exists) and not all(exists):
        fail("Dedicated Advisor identity state is incomplete; refusing key replacement.")
    if all(exists):
        private_payload, _ = _safe_read(identity, 32 * 1024)
        stored_public, _ = _safe_read(public_path, 16 * 1024)
        if not private_payload:
            fail("Dedicated Advisor identity is empty.")
        raw_authorization, _ = _safe_read(authorization_path, MAX_DOCUMENT_BYTES)
        try:
            authorization = json.loads(raw_authorization)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("Dedicated Advisor identity provenance is invalid.")
        if (
            not isinstance(authorization, dict)
            or authorization.get("provider_id") != provider_id
            or authorization.get("identity_origin") != "generated_provider_dedicated"
        ):
            fail("Refusing to reuse an identity without dedicated-key provenance.")
        derived_public, derived_fingerprint = _public_key_payload(
            _derive_public_key(identity)
        )
        normalized_stored, stored_fingerprint = _public_key_payload(stored_public)
        if derived_public != normalized_stored or derived_fingerprint != stored_fingerprint:
            fail("Dedicated Advisor identity and public key do not match.")
        return normalized_stored, stored_fingerprint

    temporary_dir = Path(tempfile.mkdtemp(prefix=".advisor-keygen.", dir=destination))
    os.chmod(temporary_dir, 0o700)
    temporary_identity = temporary_dir / "id_ed25519"
    try:
        completed = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"lomo-kodesec-advisor:{provider_id}",
                "-f",
                str(temporary_identity),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
            env={"HOME": str(temporary_dir), "LANG": "C", "PATH": "/usr/bin:/bin"},
        )
        if completed.returncode != 0:
            fail("Could not generate the dedicated Ed25519 Advisor identity.")
        private_payload, _ = _safe_read(temporary_identity, 32 * 1024)
        public_payload, _ = _safe_read(
            temporary_identity.with_suffix(".pub"), 16 * 1024, private=False
        )
        normalized_public, public_fingerprint = _public_key_payload(public_payload)
        _atomic(identity, private_payload)
        _atomic(public_path, normalized_public)
    finally:
        for temporary in (
            temporary_identity,
            temporary_identity.with_suffix(".pub"),
        ):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        try:
            temporary_dir.rmdir()
        except OSError:
            pass
    return normalized_public, public_fingerprint


def main() -> None:
    document = _decode()
    state, runtime = _state()
    provider_id = str(document.get("provider_id") or "")
    transport = str(document.get("transport") or "")
    if PROVIDER_ID.fullmatch(provider_id) is None or transport not in {"direct", "ssh"}:
        fail("Authorization requires one safe provider_id and direct or ssh transport.")
    host = normalize_host(document.get("host"), name="host")
    if transport == "direct":
        if set(document) != {"schema", "provider_id", "transport", "host"} or document.get(
            "schema"
        ) != "lomo-advisor-host-authorization/v1":
            fail("Direct authorization fields do not match schema v1.")
        _update_runtime(runtime, "KODESEC_ADVISOR_DIRECT_HOSTS", host)
        print(f"Authorized exact direct Advisor host {host} for provider {provider_id}.")
        print("Run 'make up' to re-apply the connector boundary; existing database and cache volumes are preserved.")
        return

    basic_keys = {
        "schema",
        "provider_id",
        "transport",
        "host",
        "port",
        "user",
    }
    document_keys = frozenset(document)
    if document_keys != frozenset(basic_keys) or document.get("schema") != "lomo-advisor-host-authorization/v1":
        fail("SSH authorization fields do not match schema v1.")
    if document.get("port") != 22:
        fail("SSH Advisor authorization requires exact port 22.")
    user = str(document.get("user") or "")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", user) is None:
        fail("SSH user is invalid.")
    if os.environ.get("KODESEC_ADVISOR_IDENTITY_FILE"):
        fail("Importing or reusing an operator identity is forbidden; a dedicated key is generated.")
    known_hosts_value = os.environ.get("KODESEC_ADVISOR_KNOWN_HOSTS_FILE", "").strip()
    fingerprint = os.environ.get(
        "KODESEC_ADVISOR_HOST_KEY_FINGERPRINT", ""
    ).strip()
    if not known_hosts_value or not fingerprint:
        if not sys.stdin.isatty():
            fail(
                "SSH authorization requires an interactive terminal or the narrow known-hosts and fingerprint CI variables."
            )
        known_hosts_value = input("Owner-only exact known_hosts file: ").strip()
        fingerprint = input(
            "Out-of-band SSH host-key SHA256 fingerprint: "
        ).strip()
    if SAFE_FINGERPRINT.fullmatch(fingerprint) is None:
        fail("SSH host-key fingerprint is invalid.")
    known_hosts = Path(known_hosts_value)
    if not known_hosts.is_absolute():
        fail("SSH known_hosts input must be an absolute path.")
    known_hosts_payload, _known_hosts_stat = _safe_read(known_hosts, 64 * 1024)
    try:
        entries = [
            line
            for line in known_hosts_payload.decode("utf-8").splitlines()
            if line and not line.startswith("#")
        ]
    except UnicodeDecodeError:
        fail("SSH known_hosts input is not UTF-8.")
    if len(entries) != 1:
        fail("SSH known_hosts must contain exactly one unambiguous host key.")
    fields = entries[0].split()
    accepted_hosts = {host, f"[{host}]:22"}
    if (
        len(fields) != 3
        or fields[0] not in accepted_hosts
        or fields[1] != "ssh-ed25519"
    ):
        fail("SSH known_hosts must contain the exact host:22 ssh-ed25519 key.")
    try:
        key_bytes = base64.b64decode(fields[2], validate=True)
    except ValueError:
        fail("SSH known_hosts contains malformed key material.")
    observed_fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_bytes).digest()
    ).decode("ascii").rstrip("=")
    if observed_fingerprint != fingerprint.rstrip("="):
        fail("SSH host key does not match the out-of-band fingerprint.")
    auth_root = _owner_directory(state / "advisor-auth", parent=state)
    destination = _owner_directory(auth_root / provider_id, parent=auth_root)
    public_key, public_key_fingerprint = _dedicated_identity(
        destination, provider_id
    )
    _atomic(destination / "known_hosts", known_hosts_payload)
    authorization = {
        "schema": "lomo-advisor-ssh-authorization/v1",
        "provider_id": provider_id,
        "host": host,
        "port": 22,
        "user": user,
        "host_key_fingerprint": fingerprint,
        "identity_origin": "generated_provider_dedicated",
        "identity_public_key_fingerprint": public_key_fingerprint,
        "restricted_account_attested": False,
        "authorized_keys_policy": AUTHORIZED_KEYS_POLICY,
    }
    # Persist non-authorized provenance before the operator installs the key.
    # An interrupted first run can then resume without replacing the dedicated
    # identity, while the connector still rejects this un-attested state.
    _atomic(
        destination / "authorization.json",
        (json.dumps(authorization, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"),
    )
    print("Install only this generated public key on the remote forwarding account:")
    print(public_key.decode("ascii").strip())
    print(f"Required authorized_keys restrictions: {AUTHORIZED_KEYS_POLICY}")
    attestation = os.environ.get(
        "KODESEC_ADVISOR_SSH_RESTRICTIONS_ATTESTED", ""
    ).strip()
    if attestation != SSH_ATTESTATION:
        if not sys.stdin.isatty():
            fail(
                "SSH authorization requires explicit restricted-account attestation; "
                f"set KODESEC_ADVISOR_SSH_RESTRICTIONS_ATTESTED={SSH_ATTESTATION} only after installation."
            )
        attestation = input(
            "After installing the key with the exact restrictions above, type "
            f"{SSH_ATTESTATION}: "
        ).strip()
    if attestation != SSH_ATTESTATION:
        fail("Restricted SSH forwarding-account attestation was not confirmed.")
    authorization["restricted_account_attested"] = True
    _atomic(
        destination / "authorization.json",
        (json.dumps(authorization, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"),
    )
    _update_runtime(runtime, "KODESEC_ADVISOR_SSH_PROVIDER_IDS", provider_id)
    print(f"Authorized pinned SSH Advisor provider {provider_id} at {host}:22.")
    print("Run 'make up' after installing the public key to re-apply the connector boundary; existing database and cache volumes are preserved.")


if __name__ == "__main__":
    main()
