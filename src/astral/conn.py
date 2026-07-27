"""`QueryStream`: an accepted query's bidirectional stream.

After `query_accepted_msg` the apphost connection stops being a message channel
and becomes the query's raw bidirectional bytestream. There is no apphost framing
left, and **whatever framing appears next is whatever the two endpoints agreed
on** -- by convention the same binary object channel, but `out=text` yields text
lines and `objects.read` yields no framing at all. A `QueryStream` therefore
holds a `Transport` and offers two views of it:

- the raw view: `read`, `readexactly`, `write`, `send_bytes`, `drain`,
  `write_eof`;
- the framed view: `channel()`, and the `receive`/`send`/`send_eos` and
  `async for` shorthands over it.

The two views are safe to interleave, and that is a property of the design rather
than luck: the channel holds no read buffer of its own, so a frame read and a
raw read draw from the same one buffer in the transport (design section 3.2,
rule 1). Reading one frame and then reading the tail raw is a legitimate
sequence, and it is what a mixed-framing op needs.

The framed view is created **lazily**. An accepted query does not always carry
objects -- `objects.read` is the RAW op whose body is unframed bytes -- so
constructing a framer eagerly would encode an assumption the protocol does not
make. One stream carries one framing: a second `channel()` call with different
formats raises rather than silently framing the same bytes two ways.

The raw view is capped like everything else. `read(-1)` accumulates against
`max_alloc`, because the body's length is the responder's to choose and design
section 2.1 makes an attacker-controlled length a checked length everywhere
else; a responder that streams without ever closing would otherwise grow the
client's resident set until the process dies.

Termination is per-op and never universal: `eos` is a convention the op handler
emits, and `apphost.whoami` and `dir.alias_map` end at bare EOF with no `eos`
(astral-docs bug D-23). Iteration therefore stops at `eos` **or** EOF and
`saw_eos` records which happened; nothing here ever blocks waiting for an `eos`.
Deciding what an `error_message` object means is `Stream`'s job one layer up,
because that decision belongs to the query, not to the bytes.

`aclose()` is idempotent, never raises, and **returns only once the stream is
actually closed** -- a second concurrent caller waits for the first rather than
reporting a close that has not happened yet, exactly as the transport under it
does. A stream is an async context manager
and the SDK's own code always uses one: astrald serves apphost connections from a
fixed pool of 32 workers and never notices a peer that vanished, so an abandoned
stream burns one worker permanently and 32 of them wedge the node's whole app
surface (design section 3.9, astrald bug G-13). There is no `__del__` fallback,
deliberately.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import TracebackType
from typing import Any, AsyncIterator, Final

from .channel import Channel, Format, open_channel
from .errors import AllocationLimit
from .object import EOS, Query
from .registry import Blueprints
from .transport import Transport
from .types import Identity, Nonce
from .wire import DEFAULT_MAX_ALLOC

__all__ = ["QueryStream"]

# How much of an unframed body one read asks for at a time. Only a chunk size:
# the bound that matters is `max_alloc`, checked against the running total.
_READ_CHUNK: Final = 64 * 1024


class QueryStream:
    """The bytestream of one accepted query, raw and framed."""

    __slots__ = (
        "_transport",
        "_query",
        "_outbound",
        "_endpoint",
        "_registry",
        "_allow_unparsed",
        "_max_alloc",
        "_channel",
        "_formats",
        "_closing",
        "_closed",
        "_released",
    )

    def __init__(
        self,
        transport: Transport,
        query: Query,
        *,
        outbound: bool = True,
        endpoint: str | None = None,
        registry: Blueprints | None = None,
        allow_unparsed: bool = False,
        max_alloc: int = DEFAULT_MAX_ALLOC,
    ) -> None:
        self._transport = transport
        self._query = query
        self._outbound = outbound
        self._endpoint = endpoint if endpoint is not None else transport.endpoint
        self._registry = registry
        self._allow_unparsed = allow_unparsed
        self._max_alloc = max_alloc
        self._channel: Channel | None = None
        self._formats: tuple[str, str] | None = None
        self._closing = False
        self._closed = False
        self._released = asyncio.Event()

    def __repr__(self) -> str:
        way = "outbound" if self._outbound else "inbound"
        # Three states, not two: a close in flight is a stream still open, and a
        # `repr` that called it closed would be the same lie `closed` avoids.
        if not self._closing:
            state = "open"
        else:
            state = "closed" if self._closed else "closing"
        return f"QueryStream({self._query.query_string!r}, {way}, {state})"

    # --- the query ---

    @property
    def query(self) -> Query:
        """The query this stream carries: nonce, caller, target, query string."""
        return self._query

    @property
    def query_string(self) -> str:
        return self._query.query_string

    @property
    def nonce(self) -> Nonce:
        """The query's correlator. What `apphost.cancel?id=` names."""
        return self._query.nonce

    @property
    def outbound(self) -> bool:
        """Whether this side sent the query. Decides which identity is local."""
        return self._outbound

    @property
    def local_id(self) -> Identity | None:
        """The caller on an outbound stream, the target on an inbound one."""
        return self._query.caller if self._outbound else self._query.target

    @property
    def remote_id(self) -> Identity | None:
        """The target on an outbound stream, the caller on an inbound one."""
        return self._query.target if self._outbound else self._query.caller

    # --- the transport ---

    @property
    def transport(self) -> Transport:
        """The one byte stream, and the one read buffer, both views share."""
        return self._transport

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def closed(self) -> bool:
        """Whether the transport is closed, descriptor included.

        Set when `aclose()` has finished rather than when it was called: a
        stuffed write buffer takes a bounded flush to close, and a flag that
        latched on entry would report a live connection as closed for the whole
        of it. True whenever an `aclose()` has returned, whichever caller's it
        was.
        """
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    # --- the raw view ---

    async def read(self, n: int = -1) -> bytes:
        """Up to `n` bytes, or everything to EOF when `n` is negative.

        `b""` is end of stream. The unframed response of `objects.read` is read
        exactly this way.

        Reading to EOF is bounded by `max_alloc`, the same cap every declared
        length in the wire core is checked against (design section 2.1), and
        passing it raises `AllocationLimit`. The body's length is the
        responder's to choose and this is the one attacker-controlled length in
        the SDK with no prefix to check before allocating: a responder that
        streams and never closes would otherwise grow the client's resident set
        without bound -- measured at +177 MiB and still climbing. A caller that
        wants a different bound builds the stream with a different `max_alloc`,
        so there is exactly one limit and not two.
        """
        if n >= 0:
            return await self._transport.read(n)
        out = bytearray()
        while True:
            # One byte past the cap, so a body of exactly `max_alloc` bytes is
            # readable and the first byte beyond it is refused.
            chunk = await self._transport.read(
                min(_READ_CHUNK, self._max_alloc - len(out) + 1)
            )
            if not chunk:
                return bytes(out)
            out += chunk
            if len(out) > self._max_alloc:
                raise AllocationLimit(
                    f"{self._endpoint}: the response body passed max_alloc "
                    f"{self._max_alloc} bytes and has not ended"
                )

    async def readexactly(self, n: int) -> bytes:
        """Exactly `n` bytes, or `EOFError` -- `IncompleteRead` on a truncation."""
        return await self._transport.readexactly(n)

    def write(self, data: bytes) -> None:
        """Buffer bytes for sending. Synchronous, ordered, never partial."""
        self._transport.write(data)

    async def send_bytes(self, data: bytes) -> None:
        """Write and drain. The back-pressure point of the raw view."""
        self._transport.write(data)
        await self._transport.drain()

    async def drain(self) -> None:
        await self._transport.drain()

    def write_eof(self) -> None:
        """Half-close the send direction, leaving the read direction open.

        Verified live against the node: after `shutdown(SHUT_WR)` on an accepted
        query the response object still arrived, then EOF. This is how a
        write-and-answer op signals that its input is complete when the op reads
        to EOF rather than to an `eos`.
        """
        self._transport.write_eof()

    # --- the framed view ---

    def channel(
        self, fmt_in: str = Format.BIN, fmt_out: str = Format.BIN
    ) -> Channel:
        """The object stream over this same transport, created on first use.

        One stream carries one framing: a later call asking for different formats
        raises, because two framers over one buffer would each read frames the
        other needed.
        """
        formats = (str(fmt_in or Format.BIN), str(fmt_out or Format.BIN))
        if self._channel is not None:
            if formats != self._formats:
                raise RuntimeError(
                    f"{self!r}: already framed as {self._formats[0]}/{self._formats[1]}, "  # type: ignore[index]
                    f"cannot reframe as {formats[0]}/{formats[1]}"
                )
            return self._channel
        self._channel = open_channel(
            self._transport,
            fmt_in,
            fmt_out,
            allow_unparsed=self._allow_unparsed,
            registry=self._registry,
            max_alloc=self._max_alloc,
        )
        self._formats = formats
        return self._channel

    @property
    def framed(self) -> bool:
        """Whether a framed view has been opened on this stream."""
        return self._channel is not None

    @property
    def saw_eos(self) -> bool:
        """Whether the framed view has consumed an `eos`.

        `False` on a stream nobody framed: an unframed body has no `eos` to see.
        """
        return self._channel is not None and self._channel.saw_eos

    async def receive(self) -> Any:
        """One object off the framed view. `EOFError` at a clean end of stream."""
        return await self.channel().receive()

    async def send(self, obj: Any) -> None:
        """One object onto the framed view, in exactly one `write()`."""
        await self.channel().send(obj)

    async def send_eos(self) -> None:
        """The `eos` terminator, for an op that reads its input to one."""
        await self.send(EOS())

    def __aiter__(self) -> AsyncIterator[Any]:
        """Every object up to the first `eos` or to EOF.

        Error objects are yielded unchanged: turning an `error_message` into a
        raised `RemoteError` is `Stream`'s decision, one layer up.
        """
        return self.channel().__aiter__()

    # --- lifetime ---

    async def aclose(self) -> None:
        """Close the transport. Idempotent, and never raises on a fault.

        **Returning means closed**, for every caller and not only for the first
        one. A concurrent second call waits for the first close to finish rather
        than closing twice or walking away, so `closed` is true whenever this
        returns. The alternative was measured -- a second caller returned in
        0.00 s reporting `closed=False` with the descriptor still open, while
        the first was two seconds into a bounded flush -- and a shutdown that
        counted that stream as released would have counted a live one.

        `_closing` latches first and `_closed` only once the transport is
        actually gone, so `closed` stays a fact rather than an intention.
        """
        if self._closing:
            await self._released.wait()
            return
        self._closing = True
        try:
            with contextlib.suppress(Exception):
                await self._transport.aclose()
        finally:
            self._closed = True
            self._released.set()

    async def __aenter__(self) -> "QueryStream":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
