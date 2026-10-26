"""Exercise the shipped Uvicorn shutdown command with a live event stream.

The ASGI fixture isolates server drain/lifespan behavior. Real authenticated API
restart, persistence and editor recovery still require candidate qualification.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(os.name != "posix", reason="Linux-container signal contract")
@pytest.mark.parametrize("bounded", [False, True])
def test_event_stream_does_not_prevent_lifespan_shutdown(tmp_path: Path, bounded: bool) -> None:
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    command = json.loads(next(line[4:] for line in dockerfile.read_text().splitlines() if line.startswith("CMD ")))
    assert command[:3] == ["uvicorn", "kodesec_api.app:create_app", "--factory"]
    assert command[command.index("--timeout-graceful-shutdown") + 1] == "5"
    if not bounded:
        # Original control: the same open stream prevents ordinary SIGTERM exit.
        index = command.index("--timeout-graceful-shutdown")
        del command[index:index + 2]
    command[1] = "shutdown_fixture:create_app"
    (tmp_path / "shutdown_fixture.py").write_text('''
import asyncio
from pathlib import Path

def create_app():
    async def app(scope, receive, send):
        if scope['type'] == 'lifespan':
            assert (await receive())['type'] == 'lifespan.startup'
            await send({'type': 'lifespan.startup.complete'})
            assert (await receive())['type'] == 'lifespan.shutdown'
            Path('lifespan-closed').write_text('closed')
            await send({'type': 'lifespan.shutdown.complete'})
        else:
            await send({'type': 'http.response.start', 'status': 200,
                        'headers': [(b'content-type', b'text/event-stream')]})
            await send({'type': 'http.response.body', 'body': b': ready\\n\\n', 'more_body': True})
            try:
                await asyncio.Event().wait()
            finally:
                Path('stream-closed').write_text('closed')
    return app
''')
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    command += ["--fd", str(listener.fileno())]
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("KODESEC_", "PYTHON"))}
    environment["PYTHONPATH"] = str(tmp_path)
    process = None
    try:
        with (tmp_path / "server.log").open("wb") as log:
            process = subprocess.Popen([sys.executable, "-m", *command], cwd=tmp_path,
                env=environment, pass_fds=(listener.fileno(),), stdout=log, stderr=log)
            with socket.create_connection(listener.getsockname(), timeout=5) as client:
                client.settimeout(5)
                client.sendall(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")
                received = b""
                while b": ready" not in received:
                    chunk = client.recv(4096)
                    assert chunk and len(received) + len(chunk) < 16384
                    received += chunk
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                if bounded:
                    # Uvicorn re-raises the received signal after graceful
                    # cleanup when running as an ordinary POSIX subprocess.
                    assert process.wait(timeout=8) == -signal.SIGTERM
                    assert time.monotonic() - started < 8
                    assert (tmp_path / "stream-closed").read_text() == "closed"
                    assert (tmp_path / "lifespan-closed").read_text() == "closed"
                else:
                    with pytest.raises(subprocess.TimeoutExpired):
                        process.wait(timeout=1)
                    assert not (tmp_path / "lifespan-closed").exists()
    finally:
        listener.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
