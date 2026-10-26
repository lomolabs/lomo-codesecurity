from __future__ import annotations

import json
import socket
import sys
from collections.abc import Callable


MAX_HEALTH_RESPONSE_BYTES = 16_384
SocketConnector = Callable[[tuple[str, int], float], socket.socket]


def health_endpoint_ok(
    host: str = "127.0.0.1",
    port: int = 8080,
    path: str = "/healthz",
    *,
    timeout_seconds: float = 2.0,
    connector: SocketConnector = socket.create_connection,
) -> bool:
    if (
        not host
        or "\r" in host
        or "\n" in host
        or not 1 <= port <= 65_535
        or not path.startswith("/")
        or "\r" in path
        or "\n" in path
    ):
        return False
    connection: socket.socket | None = None
    try:
        connection = connector((host, port), timeout_seconds)
        connection.settimeout(timeout_seconds)
        connection.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                return False
            response.extend(chunk)
            if len(response) > MAX_HEALTH_RESPONSE_BYTES:
                return False
        header_bytes, body = bytes(response).split(b"\r\n\r\n", 1)
        header_lines = header_bytes.split(b"\r\n")
        if not header_lines or not header_lines[0].startswith(b"HTTP/1.1 200 "):
            return False
        content_length: int | None = None
        for line in header_lines[1:]:
            name, separator, raw_value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                content_length = int(raw_value.strip())
                break
        if content_length is None or content_length < 1 or content_length > MAX_HEALTH_RESPONSE_BYTES:
            return False
        while len(body) < content_length:
            chunk = connection.recv(min(4096, content_length - len(body)))
            if not chunk:
                return False
            body += chunk
        payload = json.loads(body[:content_length])
        return isinstance(payload, dict) and payload.get("ok") is True
    except (OSError, ValueError):
        return False
    finally:
        if connection is not None:
            connection.close()


def main() -> int:
    return 0 if health_endpoint_ok() else 1


if __name__ == "__main__":
    sys.exit(main())
