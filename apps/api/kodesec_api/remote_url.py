from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import SplitResult, urlsplit


_ALLOWED_SCHEMES = frozenset({"https", "local", "ssh"})
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_ENCODED_CONTROL = re.compile(r"%(?:0[0-9A-F]|1[0-9A-F]|7F|8[0-9A-F]|9[0-9A-F])", re.IGNORECASE)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-F]{2})", re.IGNORECASE)
_LOCAL_REMOTE = re.compile(r"[A-Za-z0-9._~/-]+")
_SCP_REMOTE = re.compile(
    r"(?:(?P<username>[A-Za-z0-9][A-Za-z0-9._-]{0,63})@)?"
    r"(?P<host>\[[^\[\]]+\]|[^:/@]+):(?P<path>.+)"
)


def _validate_common_characters(value: str) -> None:
    if "\\" in value or any(character.isspace() for character in value):
        raise ValueError("remote_url contains unsafe characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError("remote_url contains control characters")
    if _INVALID_PERCENT_ESCAPE.search(value):
        raise ValueError("remote_url contains a malformed percent escape")
    if _ENCODED_CONTROL.search(value):
        raise ValueError("remote_url contains an encoded control character")


def _validate_hostname(value: str) -> None:
    hostname = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    if not hostname or "%" in hostname:
        raise ValueError("remote_url must include a valid host")

    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        if re.fullmatch(r"[0-9.]+", hostname):
            raise ValueError("remote_url must include a valid host") from None

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError as exc:
        raise ValueError("remote_url must include a valid host") from exc
    if not ascii_hostname or len(ascii_hostname) > 253:
        raise ValueError("remote_url must include a valid host")
    if any(not _DNS_LABEL.fullmatch(label) for label in ascii_hostname.split(".")):
        raise ValueError("remote_url must include a valid host")


def _validate_port(parts: SplitResult) -> None:
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("remote_url contains an invalid port") from exc
    if port == 0:
        raise ValueError("remote_url contains an invalid port")


def _validate_repository_path(path: str) -> None:
    if not path or path == "/" or path.startswith("-") or any(character in path for character in "@?#"):
        raise ValueError("remote_url must include a repository path")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("remote_url contains an unsafe repository path")


def _validate_local_remote(parts: SplitResult) -> None:
    if not parts.netloc or parts.query or parts.fragment or "@" in parts.netloc or ":" in parts.netloc:
        raise ValueError("local remote_url must not contain authority credentials or suffixes")
    local_name = f"{parts.netloc}{parts.path}"
    if not local_name or not _LOCAL_REMOTE.fullmatch(local_name):
        raise ValueError("local remote_url is malformed")
    if any(segment in {".", ".."} for segment in local_name.split("/")):
        raise ValueError("local remote_url contains an unsafe path")


def _validate_uri(value: str) -> None:
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValueError("remote_url is malformed") from exc
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError("remote_url scheme must be https, ssh, or local")
    if scheme == "local":
        _validate_local_remote(parts)
        return
    if not parts.netloc or not parts.hostname:
        raise ValueError("remote_url must include a valid host")
    if parts.query or parts.fragment:
        raise ValueError("remote_url must not contain a query or fragment")

    _validate_hostname(parts.hostname)
    _validate_port(parts)
    if scheme == "https":
        if parts.username is not None or parts.password is not None:
            raise ValueError("remote_url must not contain credentials or userinfo")
    else:
        if parts.password is not None or parts.username not in {None, "git"}:
            raise ValueError("SSH remote_url supports only credential-free git userinfo")
    _validate_repository_path(parts.path)


def _validate_scp_remote(value: str) -> None:
    match = _SCP_REMOTE.fullmatch(value)
    if match is None:
        raise ValueError("remote_url must be an absolute URL or SCP-style Git remote")
    username = match.group("username")
    host = match.group("host")
    path = match.group("path")
    if username not in {None, "git"}:
        raise ValueError("SCP-style remote_url supports only credential-free git userinfo")
    if username is None:
        unbracketed_host = host[1:-1] if host.startswith("[") else host
        if host != "localhost" and "." not in unbracketed_host and ":" not in unbracketed_host:
            raise ValueError("remote_url has an unsupported or missing scheme")
    _validate_hostname(host)
    _validate_repository_path(path)


def normalize_remote_url(value: str | None) -> str | None:
    """Validate credential-free Git remote metadata without resolving or contacting it."""

    if value is None:
        return None
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError("remote_url contains control characters")
    candidate = value.strip()
    if not candidate:
        return None
    _validate_common_characters(candidate)
    if "://" in candidate:
        _validate_uri(candidate)
    else:
        _validate_scp_remote(candidate)
    return candidate
