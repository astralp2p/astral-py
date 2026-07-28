"""`StreamTransport` and `StreamServer`: asyncio TCP and unix sockets.

One `Transport` implementation covers both `tcp:` and `unix:`, because
`asyncio.open_connection` and `asyncio.open_unix_connection` return the same
`(StreamReader, StreamWriter)` pair. The reader is the only read buffer in the
stack, and `detach()` on a channel hands this same object onward, so the
channel -> raw-stream handover strands nothing (design section 3.2, rule 1).

`StreamServer` accepts connections into a bounded pending queue. A connection
past the bound is closed immediately rather than left unanswered: astrald's
apphost wedges precisely because accepted-but-unserved connections are never
closed (design section 3.9, astrald bug G-13), and an SDK listener that hoarded
them would reproduce the bug on the app side. `aclose()` closes every pending
connection for the same reason.

**Closing is bounded and then forced.** `StreamWriter.close()` releases the
descriptor only when nothing is queued behind it; with bytes still buffered it
keeps the socket and keeps writing, so a peer that stops reading can otherwise
pin `aclose()` forever and keep the connection ESTABLISHED. `aclose()` therefore
waits `CLOSE_TIMEOUT` for the flush and then calls `abort()`, and `closed`
reports the descriptor rather than the call: a flag that latched on entry would
say "closed" of a live socket, which is precisely the blindness that let this
hazard sit unnoticed.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import random
import socket as _socket
import tempfile
from collections import deque
from typing import Awaitable, Callable, Final

from ..errors import ParseError, TransportError, TransportUnsupported
from ..types import ascii_int
from .base import Server, Transport

__all__ = [
    "CLOSE_TIMEOUT",
    "DEFAULT_MAX_PENDING",
    "HAS_UNIX_SOCKETS",
    "StreamServer",
    "StreamTransport",
    "open_stream",
    "serve_stream",
    "serve_stream_any",
]

HAS_UNIX_SOCKETS: Final[bool] = hasattr(_socket, "AF_UNIX")

# astral-go's ipc.ListenAny names an ephemeral unix socket
# `$TMPDIR/apphostclient.<16 chars from [a-z0-9_]>`; the prefix is reproduced so
# a file left behind by either implementation is recognisable.
_TEMP_PREFIX: Final = "apphostclient."
_TEMP_ALPHABET: Final = "abcdefghijklmnopqrstuvwxyz0123456789_"

# The pending-connection bound. Well under astrald's 32 workers, and a refusal
# beyond it is deliberate: a closed connection reports failure to its dialer at
# once, an unaccepted one hangs it.
DEFAULT_MAX_PENDING: Final = 16

# How long `aclose()` lets queued bytes reach the peer before it stops waiting
# and aborts. Seconds rather than minutes, because the alternative to a bounded
# wait is not a longer wait but an unbounded one: asyncio's
# `_SelectorTransport.close()` schedules the descriptor's release only when the
# write buffer is **empty**, and with bytes still queued it keeps the socket and
# keeps trying to write them for as long as the peer refuses to read.
CLOSE_TIMEOUT: Final = 2.0

# Loop turns `aclose()` gives `abort()` to run its `connection_lost` callback.
# One is enough -- the callback is queued ahead of the sleeping task -- and the
# rest are there so a busy loop cannot turn a bound into a race.
_ABORT_TURNS: Final = 10


class StreamTransport(Transport):
    """A byte stream over an `asyncio.StreamReader` / `StreamWriter` pair."""

    __slots__ = (
        "_reader",
        "_writer",
        "_endpoint",
        "_closing",
        "_closed",
        "_released",
        "_wrote_eof",
        "close_timeout",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        endpoint: str,
        *,
        close_timeout: float = CLOSE_TIMEOUT,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._endpoint = endpoint
        # Two flags, because they answer different questions and only one of
        # them is a fact. `_closing` latches the moment a close begins and is
        # what refuses further writes; `_closed` says the descriptor is gone.
        self._closing = False
        self._closed = False
        self._released = asyncio.Event()
        self._wrote_eof = False
        self.close_timeout = close_timeout

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def closed(self) -> bool:
        """Whether the descriptor has actually been released.

        Not "aclose() was called": the two are not the same instant, and a flag
        that reported the call would report a live socket as closed for as long
        as the flush took. The leak assertions in the test suite count real
        descriptors precisely because a flag can only ever be a promise.
        """
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    @property
    def reader(self) -> asyncio.StreamReader:
        """The one read buffer in the stack.

        Exposed so a raw stream taken over from a channel reads from the same
        object the framing layer read from.
        """
        return self._reader

    @property
    def writer(self) -> asyncio.StreamWriter:
        return self._writer

    async def readexactly(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"negative read length {n}")
        if n == 0:
            return b""
        # asyncio.IncompleteReadError is an EOFError carrying `.partial`, so a
        # truncated read is already distinguishable. A zero-length partial is a
        # clean close and is reported as a bare EOFError, which keeps a frame
        # boundary distinguishable from a truncation at every call site.
        try:
            return await self._reader.readexactly(n)
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                raise EOFError("stream closed") from None
            raise

    async def read(self, n: int = -1) -> bytes:
        return await self._reader.read(n)

    def write(self, data: bytes) -> None:
        if self._closing or self._wrote_eof or self._writer.is_closing():
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")
        self._writer.write(data)

    async def drain(self) -> None:
        if self._closing:
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")
        await self._writer.drain()

    def write_eof(self) -> None:
        if self._closing:
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")
        if self._wrote_eof:
            return
        if not self._writer.can_write_eof():
            raise TransportUnsupported(f"{self._endpoint}: half-close is unsupported")
        self._wrote_eof = True
        self._writer.write_eof()

    async def aclose(self) -> None:
        """Close the connection in bounded time, whatever the peer does.

        `close()` alone does not do it, and that gap is the whole of this
        method. asyncio's `_SelectorTransport.close()` schedules
        `_call_connection_lost` -- the callback that actually closes the socket
        -- only when its write buffer is **empty**; with bytes still queued it
        keeps the descriptor registered and keeps trying to write. Against a
        peer that accepted the connection and stopped reading, `wait_closed()`
        therefore never returns: measured on this tree, still blocked past 8 s
        with 14,143,381 bytes buffered and the socket still ESTABLISHED. That is
        a leaked connection holding one of astrald's 32 apphost workers (design
        section 3.9, bug G-13) inside the very call whose job is to release it.

        So the flush is bounded and then `abort()` finishes the job: it discards
        the queued bytes and releases the descriptor rather than waiting for a
        reader that is not coming. Unsendable bytes are worth less than the
        worker they would pin. Cancellation takes the same route, because a
        close abandoned mid-flush would leave exactly the descriptor it was
        called to release.
        """
        if self._closing:
            # A concurrent close owns the socket. Wait for it rather than
            # closing twice, so `closed` is true for every caller on return.
            await self._released.wait()
            return
        self._closing = True
        try:
            with contextlib.suppress(OSError):
                self._writer.close()
            try:
                await self._flush()
            except TimeoutError:
                # Ahead of the `Exception` arm deliberately: the builtin
                # `TimeoutError` **is** an `OSError`, so catching the connection
                # faults first would swallow the expiry and skip the abort.
                await self._force_close()
            except Exception:
                # A dead connection reported through the flush -- a reset, a
                # broken pipe. `aclose()` does not raise on a transport fault,
                # and the abort is a no-op once `connection_lost` has run.
                self._abort()
            except BaseException:
                # Cancellation lands here, and `close()` has not necessarily
                # released anything, so abort before the exception leaves.
                self._abort()
                raise
        finally:
            self._closed = True
            self._released.set()

    async def _flush(self) -> None:
        """Wait for the queued bytes and the descriptor, `close_timeout` at most.

        Called once and once only. `wait_closed()` awaits the protocol's close
        future directly, so cancelling that await -- which is how the deadline
        arrives -- cancels the future itself, and a second `wait_closed()` on the
        same writer then raises `CancelledError` for ever after. What follows an
        expired flush is `_force_close`, never another flush.
        """
        async with asyncio.timeout(self.close_timeout):
            await self._writer.wait_closed()

    async def _force_close(self) -> None:
        """Abort, then give the loop the turn it needs to hand the socket back."""
        self._abort()
        for _ in range(_ABORT_TURNS):
            if self._descriptor_gone():
                return
            await asyncio.sleep(0)

    def _abort(self) -> None:
        """Discard whatever is queued and release the descriptor.

        The release `close()` promises and delivers only on an empty buffer.
        `abort()` clears the buffer and schedules `connection_lost`, which is the
        callback that closes the socket, so the release lands one loop iteration
        later rather than inside this call.
        """
        transport = self._writer.transport
        if transport is None:  # pragma: no cover -- a live writer has one
            return
        with contextlib.suppress(Exception):
            transport.abort()

    def _descriptor_gone(self) -> bool:
        """Whether the socket underneath this writer has been closed.

        Read from the socket rather than from a flag, for the same reason
        `closed` is: the flag was the thing that lied.
        """
        sock = self._writer.get_extra_info("socket")
        if sock is None:
            return True
        try:
            return sock.fileno() < 0
        except OSError:  # pragma: no cover -- a closed socket answers -1
            return True


class StreamServer(Server):
    """An asyncio TCP or unix server handing out `StreamTransport`s."""

    __slots__ = (
        "_server",
        "_endpoint",
        "_proto",
        "_pending",
        "_arrived",
        "_closing",
        "_closed",
        "_sweep",
        "_max_pending",
        "_unix_path",
        "accepted",
        "refused",
    )

    def __init__(self, proto: str, *, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._server: asyncio.AbstractServer | None = None
        self._endpoint = f"{proto}:"
        self._proto = proto
        self._pending: deque[StreamTransport] = deque()
        self._arrived = asyncio.Event()
        # The same two flags `StreamTransport` carries, for the same reason:
        # `_closing` latches when the close begins and is what refuses new and
        # waiting connections; `_closed` says the pending queue is drained and
        # every descriptor this server owns is gone.
        self._closing = False
        self._closed = False
        # A lock rather than an event: an event a cancelled drain sets anyway
        # would report a listener shut with queued connections still open.
        self._sweep = asyncio.Lock()
        self._max_pending = max_pending
        self._unix_path: str | None = None
        self.accepted = 0
        # Connections closed for exceeding the pending bound. A non-zero count
        # means the accept loop is too slow to keep up, which is worth an
        # assertion in a test rather than a silent stall.
        self.refused = 0

    def _bind(
        self,
        server: asyncio.AbstractServer,
        endpoint: str,
        *,
        unix_path: str | None = None,
    ) -> None:
        self._server = server
        self._endpoint = endpoint
        self._unix_path = unix_path

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def proto(self) -> str:
        return self._proto

    @property
    def closed(self) -> bool:
        """Whether the close has completed: not listening, nothing pending.

        A fact, not the fact that `aclose()` was called. Draining the pending
        queue awaits a bounded flush per connection, so between the call and
        this flag there is a window in which the server still owns live
        descriptors -- and a flag that reported the call would deny it.
        """
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    @property
    def pending(self) -> int:
        """Connections accepted by the OS and not yet claimed by `accept()`."""
        return len(self._pending)

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """asyncio's connection callback. Returns at once, queues the transport.

        Returning does not close the connection -- asyncio leaves closing to the
        writer -- so the transport lives in the pending queue until `accept()`
        takes it or `aclose()` closes it.
        """
        conn = StreamTransport(reader, writer, self._peer_endpoint(writer))
        if self._closing or len(self._pending) >= self._max_pending:
            self.refused += 1
            await conn.aclose()
            return
        self._pending.append(conn)
        self._arrived.set()

    def _peer_endpoint(self, writer: asyncio.StreamWriter) -> str:
        """The dialer's address in endpoint form, for logs and `repr`."""
        if self._proto == "unix":
            return self._endpoint
        peer = writer.get_extra_info("peername")
        if isinstance(peer, tuple) and len(peer) >= 2:
            return f"tcp:{_join_host_port(str(peer[0]), int(peer[1]))}"
        return self._endpoint

    async def accept(self) -> StreamTransport:
        while True:
            if self._pending:
                self.accepted += 1
                return self._pending.popleft()
            if self._closing:
                raise TransportError(f"{self._endpoint}: server is closed")
            self._arrived.clear()
            await self._arrived.wait()

    async def aclose(self) -> None:
        """Stop listening, close every pending connection, unlink the path.

        Returning means all three have happened, for a second concurrent caller
        as much as for the first: draining the pending queue awaits a bounded
        flush per connection, and a second caller that returned during it would
        report a listener shut while connections it owns were still open. That
        is the same promise-ahead-of-fact this whole file was corrected for.

        **A cancelled drain releases the queue anyway and does not claim to have
        finished.** The drain used to `popleft()` and await one close at a time
        with `_closed` latched in a `finally`, so a `CancelledError` landing in
        it abandoned every remaining queued connection with `closed=True` --
        measured at five of six still open, and a second `aclose()` returning at
        once on the fast path. Each close is now shielded, so it completes
        whatever happens here, the entry leaves the queue only once its close
        returned, and `_closed` is latched only when the queue is empty.
        """
        if self._closed:
            return
        # Latched before anything is awaited: a drain cancelled a moment later
        # still stopped `accept()` handing out connections.
        self._closing = True
        async with self._sweep:
            if self._closed:
                return
            try:
                # Wake every waiter before anything else, so a task parked in
                # accept() observes the close instead of the empty queue.
                self._arrived.set()
                if self._server is not None:
                    # `close()` closes the listening socket synchronously, which
                    # is the whole of "stop accepting". `wait_closed()` is
                    # deliberately not awaited: since Python 3.12.1 it waits for
                    # every open connection to finish, including the ones
                    # `accept()` handed to a caller, so awaiting it here would
                    # deadlock on connections this server does not own.
                    self._server.close()
                while self._pending:
                    transport = self._pending[0]
                    with contextlib.suppress(Exception):
                        await asyncio.shield(transport.aclose())
                    # Dropped only now: an entry removed before its close
                    # returned is one a cancellation loses track of.
                    if self._pending and self._pending[0] is transport:
                        self._pending.popleft()
                # asyncio does not unlink a unix socket path on close; a file
                # left behind is what forces astral-go's stale-socket dance at
                # listen time.
                if self._unix_path is not None:
                    try:
                        os.unlink(self._unix_path)
                    except OSError:
                        pass
                    self._unix_path = None
            finally:
                self._closed = not self._pending

    def __repr__(self) -> str:
        if self._closed:
            state = "closed"
        elif self._closing:
            state = "closing"
        else:
            state = "listening"
        return f"StreamServer({self._endpoint!r}, {state}, pending={len(self._pending)})"


async def open_stream(proto: str, addr: str, endpoint: str) -> StreamTransport:
    """Dial one TCP or unix address. `OSError` reaches the caller unchanged.

    `addr` is already resolved: a unix path arrives expanded. astrald expands a
    leading `~/` when listening and not when dialing (astral-go bug G-15), so the
    documented default `unix:~/.apphost.sock` is undialable there; `dial()` in
    this package expands on both sides, and this function assumes it has.
    """
    if proto == "tcp":
        host, port = _split_host_port(addr)
        reader, writer = await asyncio.open_connection(host, port)
    elif proto == "unix":
        _require_unix()
        reader, writer = await asyncio.open_unix_connection(addr)
    else:
        raise TransportUnsupported(f"{proto}: not a stream protocol")
    return StreamTransport(reader, writer, endpoint)


_OnConnect = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def serve_stream(
    proto: str,
    addr: str,
    *,
    max_pending: int = DEFAULT_MAX_PENDING,
    unlink_stale: bool = False,
) -> StreamServer:
    """Bind one TCP or unix address.

    `unlink_stale` reproduces astral-go's `ipc.Listen`, which removes the socket
    file and retries once when the bind reports the address already in use. It
    defaults off, because that removal is unconditional in astral-go: a path
    typo there deletes a live node's socket.

    A bind that fails is a `TransportError`: a port already taken, a unix path
    longer than `sockaddr_un` holds or one whose directory does not exist are
    all faults of the address this listener was handed, and a raw `OSError`
    would put them outside the hierarchy the caller catches.
    """
    server = StreamServer(proto, max_pending=max_pending)

    async def on_connect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await server._on_connect(reader, writer)

    if proto == "tcp":
        host, port = _split_host_port(addr)
        try:
            bound = await asyncio.start_server(on_connect, host, port)
        except OSError as exc:
            raise TransportError(f"tcp:{addr}: {exc}") from exc
        server._bind(bound, _tcp_endpoint(bound))
        return server

    if proto == "unix":
        _require_unix()
        try:
            try:
                bound = await _bind_unix(on_connect, addr)
            except OSError as exc:
                if not (unlink_stale and _in_use(exc)):
                    raise
                os.unlink(addr)
                bound = await _bind_unix(on_connect, addr)
        except OSError as exc:
            raise TransportError(f"unix:{addr}: {exc}") from exc
        server._bind(bound, f"unix:{addr}", unix_path=addr)
        return server

    raise TransportUnsupported(f"{proto}: not a stream protocol")


async def _bind_unix(on_connect: _OnConnect, addr: str) -> asyncio.AbstractServer:
    """Bind one unix path, and **only** bind it.

    The socket is created and bound here rather than by passing `path=` to
    `asyncio.start_unix_server`, because since CPython 3.13 that path removes an
    existing socket file before binding -- unconditionally, whether or not a live
    server is listening on it, and regardless of `cleanup_socket`
    (`unix_events.py`, `create_unix_server`). Handing it the path would make
    `unlink_stale=False` a lie and would let `listen("unix:~/.apphost.sock")`
    silently unlink a running node's socket: the node keeps serving a socket
    nothing can reach any more, and every later client dials whoever took the
    path. Binding ourselves puts that decision back where the argument says it
    is, and a stale file surfaces as `EADDRINUSE` for the caller to opt into
    clearing.
    """
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        sock.bind(addr)
    except BaseException:
        sock.close()
        raise
    try:
        return await asyncio.start_unix_server(on_connect, sock=sock)
    except BaseException:
        sock.close()
        raise


async def serve_stream_any(
    proto: str = "tcp", *, max_pending: int = DEFAULT_MAX_PENDING
) -> StreamServer:
    """Bind an ephemeral address, mirroring astral-go's `ipc.ListenAny`.

    `tcp` binds `127.0.0.1:0`; `unix` binds
    `$TMPDIR/apphostclient.<16 random chars>`. Loopback rather than every
    interface: an inbound apphost handler is local-only, and the node rejects a
    registration whose query origin is the network.
    """
    if proto == "tcp":
        return await serve_stream("tcp", "127.0.0.1:0", max_pending=max_pending)
    if proto == "unix":
        _require_unix()
        return await serve_stream("unix", _temp_socket_path(), max_pending=max_pending)
    raise TransportUnsupported(f"{proto}: not a stream protocol")


# --- address helpers -----------------------------------------------------


def _split_host_port(addr: str) -> tuple[str, int]:
    """`host:port`, with `[::1]:8625` for a literal IPv6 address.

    A malformed address is a `ParseError`, not a bare `ValueError`. The endpoint
    arrives from `ASTRAL_ENDPOINT` (design section 3.3), so this is an
    externally supplied path, and `tcp:` and `tcp:notaport` are the same class
    of typo: both must land inside the SDK's hierarchy and neither must ever be
    retried. `ParseError` subclasses `ValueError`, so a caller that catches the
    builtin still catches this.
    """
    if addr.startswith("["):
        host, sep, rest = addr[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ParseError(f"invalid tcp address {addr!r}")
        port_text = rest[1:]
    else:
        host, sep, port_text = addr.rpartition(":")
        if not sep:
            raise ParseError(f"invalid tcp address {addr!r}: no port")
    port = ascii_int(port_text)
    if port is None:
        raise ParseError(f"invalid tcp address {addr!r}: port is not a number")
    if not 0 <= port <= 65535:
        raise ParseError(f"invalid tcp address {addr!r}: port out of range")
    return host, port


def _join_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _tcp_endpoint(server: asyncio.AbstractServer) -> str:
    sock = next(iter(server.sockets or ()), None)
    if sock is None:  # pragma: no cover -- a bound server always has a socket
        raise TransportError("tcp: server has no socket")
    addr = sock.getsockname()
    return f"tcp:{_join_host_port(str(addr[0]), int(addr[1]))}"


def _temp_socket_path() -> str:
    name = "".join(random.choice(_TEMP_ALPHABET) for _ in range(16))
    return os.path.join(tempfile.gettempdir(), _TEMP_PREFIX + name)


def _in_use(exc: OSError) -> bool:
    return exc.errno == errno.EADDRINUSE or "already in use" in str(exc)


def _require_unix() -> None:
    if not HAS_UNIX_SOCKETS:  # pragma: no cover -- POSIX only in this tree
        raise TransportUnsupported("unix: this platform has no unix sockets")
