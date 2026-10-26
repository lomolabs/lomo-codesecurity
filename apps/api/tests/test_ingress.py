from __future__ import annotations

import argparse
import asyncio
import gc
import os
import signal
import weakref

import pytest

from kodesec_api.ingress import create_ingress_server


async def _request_through_ingress() -> bytes:
    writer: asyncio.StreamWriter | None = None

    async def answer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    target = await asyncio.start_server(answer, "127.0.0.1", 0)
    target_port = target.sockets[0].getsockname()[1]
    ingress = await create_ingress_server(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=target_port,
    )
    ingress_port = ingress.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", ingress_port)
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=2)
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        ingress.close()
        target.close()
        await ingress.wait_closed()
        await target.wait_closed()


def test_ingress_relays_raw_http_without_application_credentials() -> None:
    response = asyncio.run(_request_through_ingress())
    assert response.endswith(b"\r\n\r\nok")


async def _request_with_half_close() -> tuple[bytes, bytes]:
    received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def answer_after_eof(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        payload = await reader.read()
        received.set_result(payload)
        writer.write(b"response-after-request-eof")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    target = await asyncio.start_server(answer_after_eof, "127.0.0.1", 0)
    target_port = target.sockets[0].getsockname()[1]
    ingress = await create_ingress_server(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=target_port,
    )
    ingress_port = ingress.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", ingress_port)
    try:
        writer.write(b"request-before-half-close")
        await writer.drain()
        writer.write_eof()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        request = await asyncio.wait_for(received, timeout=2)
        return request, response
    finally:
        writer.close()
        await writer.wait_closed()
        ingress.close()
        target.close()
        await ingress.wait_closed()
        await target.wait_closed()


def test_ingress_preserves_tcp_half_close_for_response_delivery() -> None:
    request, response = asyncio.run(_request_with_half_close())
    assert request == b"request-before-half-close"
    assert response == b"response-after-request-eof"


async def _exercise_connection_capacity() -> tuple[bytes, bytes, bytes]:
    accepted = 0
    capacity_reached = asyncio.Event()

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepted
        accepted += 1
        if accepted == 2:
            capacity_reached.set()
        try:
            while payload := await reader.read(1024):
                writer.write(payload)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    target = await asyncio.start_server(echo, "127.0.0.1", 0)
    target_port = target.sockets[0].getsockname()[1]
    ingress = await create_ingress_server(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=target_port,
        max_connections=2,
    )
    ingress_port = ingress.sockets[0].getsockname()[1]
    first_reader, first_writer = await asyncio.open_connection(
        "127.0.0.1", ingress_port
    )
    second_reader, second_writer = await asyncio.open_connection(
        "127.0.0.1", ingress_port
    )
    third_writer: asyncio.StreamWriter | None = None
    try:
        await asyncio.wait_for(capacity_reached.wait(), timeout=2)
        third_reader, third_writer = await asyncio.open_connection(
            "127.0.0.1", ingress_port
        )
        rejected = await asyncio.wait_for(third_reader.read(1), timeout=2)

        first_writer.write(b"first-one")
        second_writer.write(b"second")
        await first_writer.drain()
        await second_writer.drain()
        first_one = await asyncio.wait_for(first_reader.readexactly(9), timeout=2)
        second = await asyncio.wait_for(second_reader.readexactly(6), timeout=2)
        first_writer.write(b"first-two")
        await first_writer.drain()
        first_two = await asyncio.wait_for(first_reader.readexactly(9), timeout=2)
        return rejected, first_one + first_two, second
    finally:
        if third_writer is not None:
            third_writer.close()
            await third_writer.wait_closed()
        for writer in (first_writer, second_writer):
            writer.close()
            await writer.wait_closed()
        ingress.close()
        target.close()
        await ingress.wait_closed()
        await target.wait_closed()


def test_ingress_rejects_overflow_without_disrupting_long_lived_clients() -> None:
    rejected, first, second = asyncio.run(_exercise_connection_capacity())
    assert rejected == b""
    assert first == b"first-onefirst-two"
    assert second == b"second"


async def _connect_with_unavailable_backend() -> bytes:
    unavailable = await asyncio.start_server(lambda _reader, _writer: None, "127.0.0.1", 0)
    unavailable_port = unavailable.sockets[0].getsockname()[1]
    unavailable.close()
    await unavailable.wait_closed()
    ingress = await create_ingress_server(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=unavailable_port,
    )
    ingress_port = ingress.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", ingress_port)
    try:
        return await asyncio.wait_for(reader.read(1), timeout=2)
    finally:
        writer.close()
        await writer.wait_closed()
        ingress.close()
        await ingress.wait_closed()


def test_ingress_closes_client_when_backend_is_unavailable() -> None:
    assert asyncio.run(_connect_with_unavailable_backend()) == b""


def test_ingress_owns_disconnected_handlers_until_cleanup(monkeypatch) -> None:
    """Socket protocols may drop their handler reference after disconnect."""
    import kodesec_api.ingress as module

    async def exercise() -> None:
        accepted = None
        entered = asyncio.Event()
        finished = asyncio.Event()

        async def server(callback, *args, **kwargs):
            nonlocal accepted
            accepted = callback
            return object()

        async def connection(*args, **kwargs):
            entered.set()
            try:
                # No external transport retains this waiter's task after EOF.
                await asyncio.get_running_loop().create_future()
            finally:
                finished.set()

        monkeypatch.setattr(module.asyncio, "start_server", server)
        monkeypatch.setattr(module, "_handle_connection", connection)
        await module.create_ingress_server(
            listen_host="127.0.0.1", listen_port=0,
            target_host="127.0.0.1", target_port=1,
        )
        owner = accepted(None, None)
        reference = weakref.ref(owner)
        await entered.wait()
        del owner
        gc.collect()
        try:
            assert reference() is not None, "live ingress handler lost its owner"
            assert not finished.is_set()
        finally:
            if reference() is not None:
                reference().cancel()
                await asyncio.gather(reference(), return_exceptions=True)
        assert finished.is_set()
        await asyncio.sleep(0)
        gc.collect()
        assert reference() is None, "completed ingress handler remains retained"

    asyncio.run(exercise())


def test_sigterm_reaps_live_clients_upstream_and_listener(monkeypatch) -> None:
    import kodesec_api.ingress as module

    async def exercise() -> None:
        connected = asyncio.Event()
        closed = asyncio.Event()

        async def peer(reader, writer):
            connected.set()
            try:
                assert await reader.read() == b''
            finally:
                writer.close()
                await writer.wait_closed()
                closed.set()

        target = await asyncio.start_server(peer, '127.0.0.1', 0)
        original = module.create_ingress_server
        admitted = asyncio.get_running_loop().create_future()

        async def observed(**kwargs):
            server = await original(**kwargs)
            admitted.set_result((server, kwargs['_connections'], kwargs['_clients']))
            return server

        monkeypatch.setattr(module, 'create_ingress_server', observed)
        previous = signal.getsignal(signal.SIGTERM)
        owner = asyncio.create_task(module._serve(argparse.Namespace(
            listen_host='127.0.0.1', listen_port=0,
            target_host='127.0.0.1', target_port=target.sockets[0].getsockname()[1])))
        server, handlers, clients = await asyncio.wait_for(admitted, 2)
        reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
        try:
            await asyncio.wait_for(connected.wait(), 2)
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(owner, 2)
            assert await asyncio.wait_for(reader.read(), 2) == b''
            await asyncio.wait_for(closed.wait(), 2)
            assert not handlers and not clients
            assert signal.getsignal(signal.SIGTERM) == previous
        finally:
            writer.close()
            await writer.wait_closed()
            target.close()
            await target.wait_closed()
            if not owner.done():
                owner.cancel()
                await asyncio.gather(owner, return_exceptions=True)

    asyncio.run(exercise())


def test_shutdown_closes_an_accepted_handler_before_its_first_turn(monkeypatch) -> None:
    import kodesec_api.ingress as module

    async def exercise() -> None:
        class Writer:
            aborted = False
            @property
            def transport(self):
                return self
            def abort(self):
                self.aborted = True

        writer = Writer()
        observed = {}

        class Server:
            def close(self):
                observed['listener_closed'] = True
            async def wait_closed(self):
                assert writer.aborted

        async def accept(callback, *args, **kwargs):
            callback(None, writer)
            return Server()

        original = module.create_ingress_server
        async def create(**kwargs):
            server = await original(**kwargs)
            observed['handlers'] = kwargs['_connections']
            observed['clients'] = kwargs['_clients']
            kwargs['_shutdown'].set()
            return server

        monkeypatch.setattr(module.asyncio, 'start_server', accept)
        monkeypatch.setattr(module, 'create_ingress_server', create)
        await module._serve(argparse.Namespace(listen_host='127.0.0.1', listen_port=1,
            target_host='127.0.0.1', target_port=2))
        assert observed['listener_closed'] and writer.aborted
        assert not observed['handlers'] and not observed['clients']

    asyncio.run(exercise())


@pytest.mark.parametrize("repeat_cancel", [False, True])
def test_ingress_cancellation_reaps_both_relays_and_releases_capacity(
    monkeypatch, repeat_cancel: bool,
) -> None:
    import kodesec_api.ingress as module

    async def exercise() -> None:
        started = asyncio.Event()
        finishing = asyncio.Event()
        release = asyncio.Event()
        relays = []

        class Writer:
            closed = False

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        client, upstream = Writer(), Writer()

        async def connect(*args):
            return object(), upstream

        async def relay(*args):
            relays.append(asyncio.current_task())
            if len(relays) == 2:
                started.set()
            try:
                await asyncio.get_running_loop().create_future()
            finally:
                if repeat_cancel:
                    finishing.set()
                    await release.wait()

        monkeypatch.setattr(module.asyncio, "open_connection", connect)
        monkeypatch.setattr(module, "_relay", relay)
        capacity = module._ConnectionCapacity(1)
        owner = asyncio.create_task(module._handle_connection(
            object(), client, target_host="127.0.0.1", target_port=1, capacity=capacity,
        ))
        await started.wait()
        owner.cancel()
        if repeat_cancel:
            await finishing.wait()
            owner.cancel()
            await asyncio.sleep(0)
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await owner
        try:
            assert all(task.done() for task in relays), "ingress left child relays pending"
            assert client.closed and upstream.closed
            assert capacity.active == 0
        finally:
            for task in relays:
                task.cancel()
            await asyncio.gather(*relays, return_exceptions=True)

    asyncio.run(exercise())
