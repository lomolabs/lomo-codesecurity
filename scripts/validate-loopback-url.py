#!/usr/bin/env python3
"""Print a canonical explicit-port HTTP loopback origin or fail closed."""

from __future__ import annotations

import sys
from urllib.parse import urlsplit


def normalize(value: str) -> str:
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL") from exc
    if parsed.scheme != "http":
        raise ValueError("scheme must be http")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("host must be loopback")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are forbidden")
    if port is None or not 1 <= port <= 65535:
        raise ValueError("an explicit valid port is required")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("path, query, and fragment are forbidden")
    host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{host}:{port}"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-loopback-url.py URL", file=sys.stderr)
        return 2
    try:
        print(normalize(sys.argv[1]))
    except ValueError as exc:
        print(f"refusing non-loopback URL: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
