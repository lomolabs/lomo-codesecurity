"""Credential-free TCP ingress for a loopback-published internal API."""

from __future__ import annotations

import argparse
import asyncio
import signal
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass


BUFFER_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 5.0
MAX_CONNECTIONS = 64


@dataclass(slots=True)
class _ConnectionCapacity:
    maximum: int
    active: int = 0
    shutdown: asyncio.Event | None = None

    @property
    def stopping(self) -> bool:
        return self.shutdown is not None and self.shutdown.is_set()

    def claim(self) -> bool:
        """Claim capacity without queuing another accepted client socket."""

        if self.stopping or self.active >= self.maximum:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        if self.active <= 0:
            raise RuntimeError("ingress connection capacity underflow")
        self.active -= 1


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while payload := await reader.read(BUFFER_BYTES):
        writer.write(payload)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()
        await writer.drain()


async def _close(writer: asyncio.StreamWriter, *, abort: bool = False) -> None:
    if abort:
        writer.transport.abort()
    else:
        writer.close()
    with suppress(BrokenPipeError, ConnectionError):
        await writer.wait_closed()


async def _finish_connection(
    relays: tuple[asyncio.Task[None], ...],
    upstream_writer: asyncio.StreamWriter | None,
    client_writer: asyncio.StreamWriter,
    capacity: _ConnectionCapacity,
) -> None:
    try:
        for task in relays:
            if not task.done():
                task.cancel()
        await asyncio.gather(*relays, return_exceptions=True)
    finally:
        try:
            if upstream_writer is not None:
                await _close(upstream_writer, abort=capacity.stopping)
        finally:
            try:
                await _close(client_writer, abort=capacity.stopping)
            finally:
                capacity.release()


async def _handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    target_host: str,
    target_port: int,
    capacity: _ConnectionCapacity,
) -> None:
    if not capacity.claim():
        await _close(client_writer, abort=capacity.stopping)
        return

    upstream_writer: asyncio.StreamWriter | None = None
    relays: tuple[asyncio.Task[None], ...] = ()
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )
        client_to_upstream = asyncio.create_task(_relay(client_reader, upstream_writer))
        upstream_to_client = asyncio.create_task(_relay(upstream_reader, client_writer))
        relays = (client_to_upstream, upstream_to_client)
        done, _pending = await asyncio.wait(
            relays,
            return_when=asyncio.FIRST_EXCEPTION,
        )
        for task in done:
            task.result()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        cleanup = asyncio.create_task(_finish_connection(
            relays, upstream_writer, client_writer, capacity,
        ))
        cancelled = False
        # Repeated cancellation must not orphan cleanup or release the owner
        # while socket writers or child relays are still live.
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError


async def create_ingress_server(
    *,
    listen_host: str,
    listen_port: int,
    target_host: str,
    target_port: int,
    max_connections: int = MAX_CONNECTIONS,
    _connections: set[asyncio.Task[None]] | None = None,
    _clients: set[asyncio.StreamWriter] | None = None,
    _shutdown: asyncio.Event | None = None,
) -> asyncio.Server:
    """Create a bounded raw-TCP relay without parsing or logging payloads."""

    if max_connections < 1:
        raise ValueError("max_connections must be positive")
    capacity = _ConnectionCapacity(max_connections, shutdown=_shutdown)
    connections: set[asyncio.Task[None]] = _connections if _connections is not None else set()
    clients: set[asyncio.StreamWriter] = _clients if _clients is not None else set()

    def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> asyncio.Task[None]:
        # A disconnected StreamReaderProtocol releases its handler reference.
        # Retain the owner until its relays and both socket writers are reaped.
        owner = asyncio.create_task(_handle_connection(
            reader, writer, target_host=target_host,
            target_port=target_port, capacity=capacity,
        ))
        connections.add(owner)
        clients.add(writer)

        def release(task: asyncio.Task[None]) -> None:
            connections.discard(task)
            clients.discard(writer)

        owner.add_done_callback(release)
        return owner

    return await asyncio.start_server(
        handler,
        listen_host,
        listen_port,
        limit=BUFFER_BYTES,
        backlog=MAX_CONNECTIONS,
    )


def _positive_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Relay one fixed TCP listener to one fixed internal target."
    )
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=_positive_port)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=_positive_port)
    return parser.parse_args(argv)


async def _serve(arguments: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    connections: set[asyncio.Task[None]] = set()
    clients: set[asyncio.StreamWriter] = set()
    previous = signal.getsignal(signal.SIGTERM)
    # Container PID 1 ignores a default SIGTERM disposition. An explicit
    # handler closes admission and reaps owned relays before process exit.
    loop.add_signal_handler(signal.SIGTERM, shutdown.set)
    server = None
    try:
        server = await create_ingress_server(
            listen_host=arguments.listen_host,
            listen_port=arguments.listen_port,
            target_host=arguments.target_host,
            target_port=arguments.target_port,
            _connections=connections,
            _clients=clients,
            _shutdown=shutdown,
        )
        await shutdown.wait()
    finally:
        shutdown.set()
        if server is not None:
            server.close()
        # An accepted handler may not have entered its coroutine yet. Close
        # its transport before cancellation so that case cannot leak a socket.
        for client in tuple(clients):
            client.transport.abort()
        owners = tuple(connections)
        for owner in owners:
            owner.cancel()
        # Shutdown aborts only these owned transports; normal EOF retains its
        # graceful half-close behavior. Cleanup still owns capacity until reaped.
        await asyncio.gather(*owners, return_exceptions=True)
        if server is not None:
            await server.wait_closed()
        loop.remove_signal_handler(signal.SIGTERM)
        signal.signal(signal.SIGTERM, previous)


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _arguments(argv)
    try:
        asyncio.run(_serve(arguments))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
