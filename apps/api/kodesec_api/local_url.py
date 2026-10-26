from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit


_LOCAL_OLLAMA_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "host.docker.internal"})
_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_MAX_DECLARED_OLLAMA_HOSTS = 8


def parse_declared_ollama_hosts(value: str) -> frozenset[str]:
    """Parse a bounded list of exact operator-approved Ollama host names.

    Entries are hosts only, never URLs, CIDRs, wildcard domains, or host:port
    pairs. URL shape and the fixed Ollama port are still enforced separately.
    """

    raw_hosts = [item.strip().lower() for item in value.split(",") if item.strip()]
    if len(raw_hosts) > _MAX_DECLARED_OLLAMA_HOSTS:
        raise ValueError(f"at most {_MAX_DECLARED_OLLAMA_HOSTS} Ollama hosts may be declared")

    hosts: set[str] = set()
    for host in raw_hosts:
        if any(character.isspace() for character in host) or host.endswith("."):
            raise ValueError("declared Ollama hosts must be exact host names")
        try:
            normalized = ipaddress.ip_address(host).compressed.lower()
        except ValueError:
            if not _DNS_HOST_RE.fullmatch(host):
                raise ValueError("declared Ollama hosts must be exact IP addresses or DNS names")
            normalized = host
        hosts.add(normalized)
    return frozenset(hosts)


def normalize_local_ollama_url(value: str, allowed_hosts: Iterable[str] = ()) -> str:
    candidate = value.strip().rstrip("/")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Ollama URL is malformed") from exc

    if parsed.scheme != "http":
        raise ValueError("Ollama URL must use local HTTP")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Ollama URL cannot contain user information")
    hostname = (parsed.hostname or "").lower()
    declared_hosts = frozenset(item.lower() for item in allowed_hosts)
    if hostname not in _LOCAL_OLLAMA_HOSTS | declared_hosts:
        raise ValueError("Ollama URL must target the same device")
    if port != 11434:
        raise ValueError("Ollama URL must use the local Ollama port 11434")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Ollama URL cannot contain a path, query, or fragment")
    return candidate
