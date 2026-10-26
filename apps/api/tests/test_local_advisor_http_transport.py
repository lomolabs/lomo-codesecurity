"""Actual pinned HTTPX/httpcore loopback witness; no Ollama/MockTransport."""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import httpcore
import httpx
from fastapi import HTTPException
from starlette.requests import Request
import pytest

from kodesec_api.advisor import grants, providers

ROOT = Path(__file__).resolve().parents[3]
SECRET = "owned-loopback-advisor-test-secret-" * 3
MODEL = "owned-loopback-fixture:latest"
DIGEST = "a" * 64


def connector_module():
    path = ROOT / "services/advisor_connector/app.py"
    spec = importlib.util.spec_from_file_location("owned_transport_connector", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.GRANT_SECRET = SECRET
    return module


def request(path, body):
    raw = json.dumps(body).encode()
    consumed = False

    async def receive():
        nonlocal consumed
        if not consumed:
            consumed = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await asyncio.Event().wait()

    return Request({"type": "http", "method": "POST", "path": path,
                    "headers": [(b"content-length", str(len(raw)).encode())],
                    "query_string": b""}, receive)


def test_real_body_send_witness_and_authenticated_owned_cancel(monkeypatch):
    assert httpx.__version__ == "0.28.1"
    assert httpcore.__version__ == "1.0.9"
    connector = connector_module()
    profile = providers.normalize_profile({
        "id": "owned-loopback", "name": "Owned loopback", "transport": "local",
        "priority": 0, "enabled": True, "base_url": None, "model": MODEL,
        "model_digest": DIGEST, "ssh_host": None, "ssh_port": None, "ssh_user": None,
    })
    payload = {"model": MODEL, "prompt": "synthetic bounded fixture", "format": connector._OUTPUT_SCHEMA,
               "stream": False, "think": False,
               "options": {"temperature": 0, "top_p": 1, "num_predict": 32, "num_ctx": 1024}}
    grant = grants.mint_local_operation_grant(SECRET, profile, payload["prompt"])
    document = {"provider": profile, "request": payload, "confirmation": None, "grant": grant}
    binding = grants.local_operation_binding(profile, grant["prompt_sha256"])
    observe = grants.mint_local_observation_grant(SECRET, binding, grant["nonce"])
    cancel = grants.mint_local_cancellation_grant(SECRET, binding, grant["nonce"])
    real_client = httpx.AsyncClient

    async def scenario():
        tags_received, release_tags = asyncio.Event(), asyncio.Event()
        generate_received, peer_closed = asyncio.Event(), asyncio.Event()
        server_tasks, writers, clients = set(), set(), []
        requests = []
        generation = None

        class TrackedRealClient(real_client):
            def __init__(self, **kwargs):
                assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
                super().__init__(**kwargs)
                clients.append(self)

        async def handle(reader, writer):
            task = asyncio.current_task()
            server_tasks.add(task)
            writers.add(writer)
            try:
                async with asyncio.timeout(4):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    assert len(headers) < 8192
                    method, path, _ = headers.split(b"\r\n", 1)[0].split()
                    lengths = [line.split(b":", 1)[1].strip() for line in headers.split(b"\r\n")
                               if line.lower().startswith(b"content-length:")]
                    length = int(lengths[0]) if lengths else 0
                    assert 0 <= length <= 4096
                    body = await reader.readexactly(length)
                    requests.append((method.decode(), path.decode(), body))
                    if path == b"/api/generate":
                        assert method == b"POST" and json.loads(body) == payload
                        generate_received.set()
                        # No response headers or JSON exist to publish as a result.
                        assert await reader.read(1) == b""
                        peer_closed.set()
                        return
                    if path == b"/api/tags":
                        tags_received.set()
                        await release_tags.wait()
                        result = {"models": [{"name": MODEL, "digest": DIGEST, "size": 1}]}
                    else:
                        assert path == b"/api/unrelated" and method == b"POST"
                        result = {"unrelated": True}
                    raw = json.dumps(result).encode()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                                 + b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                writers.discard(writer)
                server_tasks.discard(task)

        server = await asyncio.start_server(handle, "127.0.0.1", 0, limit=8192)
        host, port = server.sockets[0].getsockname()[:2]
        assert host == "127.0.0.1"
        origin = f"http://{host}:{port}"
        monkeypatch.setattr(connector, "_dedicated_local_url", lambda: origin)
        monkeypatch.setattr(connector.httpx, "AsyncClient", TrackedRealClient)
        try:
            async with asyncio.timeout(5):
                await connector.admit_operation(request("/v1/operations", document))
                generation = asyncio.create_task(connector.generate(request("/v1/generate", document)))
                await tags_received.wait()
                state = connector._observe_local_operation(observe)
                assert state["status"] == "running" and state["cleanup"] == "pending"
                assert state["owned_generation_active"] is False
                async with real_client(trust_env=False) as unrelated:
                    response = await unrelated.post(origin + "/api/unrelated", json={"unrelated": True})
                    assert response.status_code == 200
                assert connector._observe_local_operation(observe)["owned_generation_active"] is False
                release_tags.set()
                await generate_received.wait()
                # The callback was invoked by the real HTTP/1.1 transport, never by this test.
                active = connector._observe_local_operation(observe)
                assert active["owned_generation_active"] is True and active["cleanup"] == "pending"
                assert not generation.done() and len(clients) == 2 and not clients[-1].is_closed
                ack = await connector.cancel_operation(request("/v1/cancel", {"cancellation_grant": cancel}))
                assert ack == {"operation_id": grant["nonce"], "status": "cancelled", "cleanup": "confirmed"}
                assert all(client.is_closed for client in clients), "ACK requires actual owned HTTP client closure"
                with pytest.raises(HTTPException) as error:
                    await generation
                assert error.value.status_code == 499
                await peer_closed.wait()
                final = connector._observe_local_operation(observe)
                assert final == {**active, "status": "cancelled", "cleanup": "confirmed",
                                 "owned_generation_active": False}
                operation = connector._OPERATIONS[grant["nonce"]]
                assert operation.completed.is_set() and operation.cancel_requested.is_set()
                assert [path for method, path, body in requests].count("/api/generate") == 1
        finally:
            async with asyncio.timeout(2):
                server.close()
                await server.wait_closed()
                if generation is not None and not generation.done():
                    generation.cancel()
                    await asyncio.gather(generation, return_exceptions=True)
                for writer in tuple(writers):
                    writer.close()
                for task in tuple(server_tasks):
                    task.cancel()
                await asyncio.gather(*tuple(server_tasks), return_exceptions=True)
                for client in clients:
                    await client.aclose()
            assert all(client.is_closed for client in clients)
            assert not server.is_serving()

    asyncio.run(scenario())
