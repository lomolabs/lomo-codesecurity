from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


FETCHER = Path(__file__).parents[1] / "scripts" / "fetch-locked-asset.sh"
PAYLOAD = (b"lomo-resumable-scanner-asset\n" * 8192)[:196_608]


class _RangeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, honor_ranges: bool) -> None:
        super().__init__(("127.0.0.1", 0), _RangeHandler)
        self.honor_ranges = honor_ranges
        self.requests: list[str | None] = []


class _RangeHandler(BaseHTTPRequestHandler):
    server: _RangeServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        requested_range = self.headers.get("Range")
        self.server.requests.append(requested_range)
        if len(self.server.requests) == 1:
            prefix = 65_536
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD[:prefix])
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return

        if self.server.honor_ranges and requested_range is not None:
            offset = int(requested_range.removeprefix("bytes=").removesuffix("-"))
            body = PAYLOAD[offset:]
            self.send_response(206)
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Range", f"bytes {offset}-{len(PAYLOAD) - 1}/{len(PAYLOAD)}"
            )
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _run_fetcher(
    server: _RangeServer, destination: Path, sha256: str
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS": "5",
        "SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS": "15",
        "SCANNER_DOWNLOAD_MAX_ATTEMPTS": "3",
        "SCANNER_DOWNLOAD_CONNECT_TIMEOUT_SECONDS": "2",
        "SCANNER_DOWNLOAD_RETRY_BASE_DELAY_SECONDS": "1",
    }
    return subprocess.run(
        (
            "/bin/sh",
            str(FETCHER),
            f"http://127.0.0.1:{server.server_port}/asset",
            str(destination),
            sha256,
            str(len(PAYLOAD)),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )


def test_fetcher_resumes_exact_range_and_verifies_final_asset(tmp_path: Path) -> None:
    server = _RangeServer(honor_ranges=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        destination = tmp_path / "asset.bin"
        result = _run_fetcher(
            server, destination, hashlib.sha256(PAYLOAD).hexdigest()
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 0, result.stderr
    assert destination.read_bytes() == PAYLOAD
    assert server.requests == [None, "bytes=65536-"]


def test_fetcher_fails_closed_when_origin_ignores_resume_range(tmp_path: Path) -> None:
    server = _RangeServer(honor_ranges=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        destination = tmp_path / "asset.bin"
        result = _run_fetcher(
            server, destination, hashlib.sha256(PAYLOAD).hexdigest()
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode != 0
    assert destination.read_bytes() == PAYLOAD[:65_536]
    assert server.requests == [None, "bytes=65536-"]


def test_fetcher_rejects_checksum_mismatch_without_retry(tmp_path: Path) -> None:
    class _CompleteHandler(_RangeHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            self.server.requests.append(self.headers.get("Range"))
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)

    server = _RangeServer(honor_ranges=True)
    server.RequestHandlerClass = _CompleteHandler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _run_fetcher(server, tmp_path / "asset.bin", "0" * 64)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 65
    assert server.requests == [None]
