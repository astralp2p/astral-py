"""The two seams of the async layer: a byte stream and a connection source.

`Transport` is a byte stream and nothing else. No framing knowledge lives in
this module: a transport moves bytes, and every layout question -- where a type
tag sits, how long a payload is, what terminates a stream -- belongs to
`astral.channel`. The split is forced by the WebSocket JSON subprotocol, which
is message-oriented and has no byte stream underneath it, so a channel cannot be
defined as a transport decorator.

Two rules bind every implementation, and both come from the channel -> raw-stream
handover (design section 3.2):

1. A transport buffers reads in exactly one place, and that buffer survives the
   handover. `StreamTransport` holds an `asyncio.StreamReader`; the raw stream
   reads from the same object the framing layer read from, so no byte is
   stranded. A transport that wrapped a second buffer around the first would
   break the protocol.
2. `write()` is synchronous, non-blocking and order-preserving. A caller
   serialises one frame into one `bytes` and issues one `write()`, so
   cancellation cannot land mid-frame and no write lock is needed anywhere in
   the SDK.

EOF has two shapes and the difference is load-bearing. `read()` returns `b""` at
end of stream. `readexactly(n)` raises `EOFError`; when the stream ended after
some but not all of the requested bytes, the exception is an `IncompleteRead`
carrying the partial bytes. A framing layer reads its first byte at a frame
boundary, where a bare `EOFError` is a clean close, and every later byte of that
frame, where any EOF is a truncated frame.

`aclose()` is idempotent, never raises on a transport fault, and **returns only
once the close has completed**: a second concurrent caller waits for the first
rather than returning while the descriptor is still open, so `closed` is true
whenever any caller's `aclose()` returns. A promise that outran the fact is
exactly how a leaked connection went unnoticed once already. Every connection
this SDK opens is closed on every path, including cancellation and exceptions:
astrald serves apphost connections from a fixed pool of 32 workers and does not
notice a peer that vanished, so a leaked connection burns one worker
permanently and 32 of them wedge the node's whole app surface (design section
3.9, astrald bug G-13).
"""

from __future__ import annotations

import abc
import asyncio
from types import TracebackType
from typing import AsyncIterator

from ..errors import TransportError

__all__ = ["IncompleteRead", "Server", "Transport"]

# The stdlib's own partial-read error, and a subclass of EOFError: one `except
# EOFError` catches both a clean close and a truncated read, and `.partial`
# distinguishes them. Re-exported so nothing above this module reaches into
# asyncio for it.
IncompleteRead = asyncio.IncompleteReadError


class Transport(abc.ABC):
    """A bidirectional byte stream with an endpoint string."""

    __slots__ = ()

    @property
    @abc.abstractmethod
    def endpoint(self) -> str:
        """The `proto:addr` string this transport was reached at."""

    @property
    @abc.abstractmethod
    def closed(self) -> bool:
        """Whether the close has completed and the connection is gone.

        Not "aclose() was called": the two are not the same instant, and only
        the second is a fact. True whenever an `aclose()` has returned.
        """

    @abc.abstractmethod
    async def readexactly(self, n: int) -> bytes:
        """Read exactly `n` bytes.

        Raises `EOFError` when the stream ends at byte zero, and
        `IncompleteRead` -- an `EOFError` carrying `.partial` -- when it ends
        after some of them. `n == 0` returns `b""` without awaiting a byte.
        """

    @abc.abstractmethod
    async def read(self, n: int = -1) -> bytes:
        """Read up to `n` bytes, or to EOF when `n` is negative.

        Returns fewer than `n` bytes whenever fewer have arrived, and `b""` at
        end of stream. A short read is not an error.
        """

    @abc.abstractmethod
    def write(self, data: bytes) -> None:
        """Buffer `data` for sending. Synchronous, non-blocking, ordered."""

    @abc.abstractmethod
    async def drain(self) -> None:
        """Wait until the send buffer is below the high-water mark."""

    @abc.abstractmethod
    def write_eof(self) -> None:
        """Half-close the send direction. The read direction stays open."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Close both directions. Idempotent, and never raises on a fault.

        Returns only once `closed` is true, for a second concurrent caller as
        much as for the first.
        """

    async def __aenter__(self) -> "Transport":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"{type(self).__name__}({self.endpoint!r}, {state})"


class Server(abc.ABC):
    """A source of accepted `Transport`s.

    One connection at a time, pulled by the caller: `accept()` hands back a
    transport and the caller owns it from that moment. A queued connection that
    is never accepted is closed by `aclose()`, because a connection nobody owns
    is a connection nobody closes.
    """

    __slots__ = ()

    @property
    @abc.abstractmethod
    def endpoint(self) -> str:
        """The `proto:addr` string a peer dials to reach this server.

        Reconstituted from the bound address, so an ephemeral port or a
        generated socket path is resolved. This is the string
        `apphost.register_handler` receives.
        """

    @property
    @abc.abstractmethod
    def closed(self) -> bool:
        """Whether the close has completed: not listening, nothing pending."""

    @abc.abstractmethod
    async def accept(self) -> Transport:
        """Wait for the next connection.

        Raises `TransportError` once the server is closed.
        """

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Stop listening and close every connection not yet accepted.

        Idempotent, and returns only once that is done -- a second concurrent
        caller waits for the first rather than returning while the pending queue
        is still draining. Connections already handed to `accept()` belong to
        their caller and are not touched.
        """

    async def __aiter__(self) -> AsyncIterator[Transport]:
        """Every connection until the server closes."""
        while True:
            try:
                conn = await self.accept()
            except TransportError:
                return
            yield conn

    async def __aenter__(self) -> "Server":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "listening"
        return f"{type(self).__name__}({self.endpoint!r}, {state})"
