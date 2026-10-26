from __future__ import annotations

from collections.abc import Iterable

from kodesec_api.http_health import health_endpoint_ok


class FakeSocket:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self.chunks = iter(chunks)
        self.request = b""
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        return None

    def sendall(self, value: bytes) -> None:
        self.request += value

    def recv(self, _limit: int) -> bytes:
        return next(self.chunks, b"")

    def close(self) -> None:
        self.closed = True


def test_health_probe_requires_http_success_and_truthful_ok_body() -> None:
    healthy_body = b'{"ok": true, "worker": true, "db":true}'
    healthy = FakeSocket([
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(healthy_body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n",
        healthy_body,
    ])
    unhealthy = FakeSocket([
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"ok\":false}",
    ])
    deceptive_body = b'{"ok":false,"note":"\\\"ok\\\":true"}'
    deceptive = FakeSocket([
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(deceptive_body)).encode("ascii")
        + b"\r\n\r\n"
        + deceptive_body,
    ])
    trailing_body = b'{"ok":true} garbage'
    trailing = FakeSocket([
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(trailing_body)).encode("ascii")
        + b"\r\n\r\n"
        + trailing_body,
    ])

    assert health_endpoint_ok(connector=lambda _address, _timeout: healthy)
    assert not health_endpoint_ok(connector=lambda _address, _timeout: unhealthy)
    assert not health_endpoint_ok(connector=lambda _address, _timeout: deceptive)
    assert not health_endpoint_ok(connector=lambda _address, _timeout: trailing)
    assert healthy.request == (
        b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n"
    )
    assert healthy.closed is True
    assert unhealthy.closed is True
