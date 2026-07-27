"""`Stream`: one query's object stream, with the policy the query decides.

`QueryStream` (layer 2) owns the bytes: one transport, a raw view and a framed
view over the same read buffer. `Stream` owns everything that depends on
knowing *which query* those bytes belong to, and that is exactly three things
layer 2 cannot decide for itself:

1. **What an `error_message` object means.** It is an ordinary object on the
   wire, so the channel yields it like any other. Whether it is data or a
   failure is the query's question, and the answer differs per call site: a
   pipeline stage that yields one downstream has injected a wrong-typed object
   into the next stage, so `__aiter__`, `collect()`, `value()`, `first()`,
   `follow()`, `snapshot()` and `live()` all raise `RemoteError`. The CLI wants
   it as data, prints it to stderr and keeps going, so `raw_objects()` yields
   everything and raises nothing. That inverts the legacy default deliberately
   (design section 4.2).
2. **What an `eos` means.** It is a convention the op handler emits, not a
   transport signal, and it is per-op and **not discoverable from the wire**
   (design section 4.7). On an ordinary streaming op it terminates. On a
   follow-mode op -- `tree.get?follow=true`, `services.discover?follow=true`,
   `objects.scan?follow=true` -- the first one is a **snapshot/live separator**
   and the channel stays open behind it. Conflating the two truncates a follow
   stream at its separator or deadlocks an ordinary one waiting for a second
   `eos` that never comes, so the caller declares which shape it expects by
   choosing the iterator, and nothing here infers one.
3. **When the stream is over.** `eos` **or** EOF, never `eos` alone:
   `apphost.whoami` sends one `identity` and closes, `dir.alias_map` sends one
   map and closes, and neither sends an `eos` (astral-docs bug D-23, verified
   live this session). `terminated_by` records which arrived, because a caller
   that must distinguish a complete stream from a truncated one has no other
   way to ask.

**Not every accepted query is an object stream at all.** `objects.read` answers
with unframed bytes (design section 4.7, mode RAW), so the framed view stays
unbuilt until something asks for an object and `read_bytes()` reads the body
straight off the transport. A `Stream` that framed itself on construction would
encode an assumption the protocol does not make.

**One reader.** There is no multiplexing on the IPC leg (design section 3.7), so
two tasks reading one stream split its frames between them: each gets half the
objects, and a read abandoned mid-frame leaves the next whole frame to be read
as something the responder never sent. The guard refuses the *second concurrent*
read and leaves the first untouched, so the caller that broke the rule is the one
that fails. Sequential readers are fine and are the point -- `snapshot()` then
`live()` is two iterators over one stream, in order.

**An abandoned read is the quiet forgery, and it is the documented usage.** The
deadline on `collect()`, `value()` and `first()`, and the `asyncio.timeout`
around an `async for` that `__aiter__` tells callers to write, all arrive in the
channel as `CancelledError`. A read cut off between a frame's tag and its payload
has consumed part of the frame and left the rest, so the peer's next whole frame
is returned as an object it never sent -- and the responder chooses those bytes.
Measured: a responder sending one `uint64` header-first, read with
`first(timeout=0.15)`, and the next read returns `Ack()` assembled out of the
integer's own payload. `QueryTimeout` is an ordinary catchable error and retrying
after one is the natural thing to do, so the stream must not still look usable.
It does not: a read abandoned anywhere but at a frame boundary closes the stream
and every later read raises `StreamCorrupted`. A read abandoned *at* a boundary
costs nothing and stays harmless, which is what `Channel.at_frame_boundary` is
for and is why an idle follow stream's deadline is safe. This is layer 2's rule
for the control channel (`Session._recv`), applied to the query stream.

**Closing is not optional and is not deferred.** astrald serves apphost from a
fixed pool of 32 workers, runs one connection synchronously per worker and never
notices a peer that vanished, so an abandoned stream burns one worker until the
node restarts and 32 of them wedge every local app (astrald bug G-13, design
section 3.9). `aclose()` is idempotent, raises no fault of its own, returns only
once the descriptor is gone, and releases the client's connection permit **after** that
-- releasing it first would let the next query dial while this connection is
still open, which is the one way a bounded client exceeds its bound. There is no
`__del__` fallback, deliberately: `async with` is the contract.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import TracebackType
from typing import Any, AsyncIterator, Callable, Final, Literal

from .channel import Format, is_eos
from .conn import QueryStream
from .errors import (
    ConcurrentRead,
    ProtocolError,
    QueryTimeout,
    RemoteError,
    StreamClosed,
    StreamCorrupted,
)
from .object import EOS, Query
from .session import CANCEL_TIMEOUT, Connector, cancel_query
from .transport import Transport
from .types import Identity, Nonce

__all__ = ["Stream"]

# What a read stops for. The op declares its shape; nothing here infers one.
_UNTIL_EOS: Final = "eos"
"""An `eos` ends the stream. Every non-follow op, and the default."""
_UNTIL_SEPARATOR: Final = "separator"
"""An `eos` is the snapshot/live boundary: stop, but the stream is not over."""
_UNTIL_END: Final = "end"
"""An `eos` crosses into live mode; only EOF or a second `eos` ends the stream."""

_ERROR_TYPE: Final = "error_message"


class _End:
    """The end of a stream, distinguishable from every object including `None`."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "END"


_END: Final = _End()


def _is_error(obj: Any) -> bool:
    """Whether an object is an `error_message`.

    By type name rather than by class, exactly as `channel.is_eos` matches, so a
    runtime record decoded under the same name reads as an error too.
    """
    return getattr(obj, "ASTRAL_TYPE", None) == _ERROR_TYPE


class Stream:
    """One accepted query's stream: objects, raw bytes, and a deterministic close."""

    __slots__ = (
        "_conn",
        "_read_fmt",
        "_write_fmt",
        "_connector",
        "_cancel_timeout",
        "_on_close",
        "_raw",
        "_released_permit",
        "_terminated_by",
        "_live",
        "_reading",
        "_closing",
        "_closed",
        "_released",
    )

    def __init__(
        self,
        conn: QueryStream,
        *,
        fmt_in: str = Format.BIN,
        fmt_out: str = Format.BIN,
        connector: Connector | None = None,
        cancel_timeout: float | None = CANCEL_TIMEOUT,
        on_close: Callable[["Stream"], None] | None = None,
        raw: bool = False,
    ) -> None:
        """Wrap an accepted query's transport.

        `fmt_in` and `fmt_out` are the formats named by the query string's `in=`
        and `out=` parameters, in the caller's view: `in=` is the format the
        responder *reads*, so it is what this side writes, and `out=` is the
        format the responder *writes*, so it is what this side reads.
        `open_channel` takes them the other way round -- read format first -- and
        the swap happens here, once, rather than in every call site that would
        otherwise get it backwards. `Client.query` is what reconciles the
        keywords with the query string it actually sends; by here they agree.

        `raw=True` is the RAW mode of design section 4.7, declared by the op and
        carried here so that it constrains something. A RAW response is unframed
        bytes -- `objects.read` returns a stored file -- so framing it decodes the
        file as protocol, and a file whose leading bytes happen to spell
        `string8(type) ++ bytes32(payload)` is then handed to the caller as an
        object the responder never sent. Those bytes are arbitrary by definition,
        so every object reader and every object send refuses on a RAW stream.

        The rule is deliberately one-way. `read_bytes()` on a stream *not*
        declared RAW stays legal, because reading a frame and then reading the
        tail raw is a real op shape and the two views share one buffer by design
        (`conn.py`, design section 3.2 rule 1). Nothing is misread that way: raw
        bytes asked for as raw bytes arrive as raw bytes. The asymmetry is the
        hazard's, not the API's.

        `on_close` runs exactly once, after the descriptor is gone. It is the
        client's permit release and stream deregistration, and it is
        synchronous because nothing in it may extend the window in which this
        connection is closed but its permit is not yet free.
        """
        self._conn = conn
        self._read_fmt = fmt_out
        self._write_fmt = fmt_in
        self._connector = connector
        self._cancel_timeout = cancel_timeout
        self._on_close = on_close
        self._raw = raw
        self._released_permit = False
        self._terminated_by: Literal["eos", "eof"] | None = None
        self._live = False
        self._reading = False
        self._closing = False
        self._closed = False
        self._released = asyncio.Event()

    def __repr__(self) -> str:
        # Three states, not two: a close in flight is a stream still open.
        if not self._closing:
            state = "open"
        else:
            state = "closed" if self._closed else "closing"
        end = f", {self._terminated_by}" if self._terminated_by else ""
        return f"Stream({self.query_string!r}, {state}{end})"

    # --- the query ---

    @property
    def conn(self) -> QueryStream:
        """The layer-2 stream: the raw view, the framed view, one transport."""
        return self._conn

    @property
    def transport(self) -> Transport:
        return self._conn.transport

    @property
    def query(self) -> Query:
        """The query this stream carries: nonce, caller, target, query string."""
        return self._conn.query

    @property
    def query_string(self) -> str:
        return self._conn.query_string

    @property
    def nonce(self) -> Nonce:
        """The query's correlator. What `apphost.cancel?id=` names."""
        return self._conn.nonce

    @property
    def outbound(self) -> bool:
        """Whether this side sent the query."""
        return self._conn.outbound

    @property
    def local_id(self) -> Identity | None:
        """The caller on an outbound stream, the target on an inbound one."""
        return self._conn.local_id

    @property
    def remote_id(self) -> Identity | None:
        """The target on an outbound stream, the caller on an inbound one."""
        return self._conn.remote_id

    @property
    def endpoint(self) -> str:
        return self._conn.endpoint

    # --- termination ---

    @property
    def terminated_by(self) -> Literal["eos", "eof"] | None:
        """How the stream ended, or `None` while it has not.

        `"eos"` is the op's terminator and `"eof"` is the responder closing.
        Both are legitimate endings and which one arrives is per-op, so a caller
        that needs to tell a complete stream from a truncated one reads this
        rather than assuming (astral-docs bug D-23).

        A follow-mode separator does not set it: the stream is not over there.
        """
        return self._terminated_by

    @property
    def saw_eos(self) -> bool:
        """Whether an `eos` has been consumed, terminator or separator alike."""
        return self._conn.saw_eos

    @property
    def is_live(self) -> bool:
        """Whether a follow stream has crossed its snapshot/live separator."""
        return self._live

    @property
    def raw(self) -> bool:
        """Whether the op declared RAW mode, so the body is unframed bytes.

        `objects.read` is the only one (design section 4.7). A caller handed a
        stream can ask rather than guess, and every object reader here refuses
        when it is true.
        """
        return self._raw

    @property
    def corrupt(self) -> bool:
        """Whether a read was abandoned inside a frame, ending the stream.

        The stream is closed by then. What remains is that a later read must not
        look plausible, because the bytes it would return are the tail of a frame
        the responder chose.
        """
        return self._conn.corrupt

    @property
    def closed(self) -> bool:
        """Whether the transport is closed, descriptor included."""
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    # --- the one read path ---

    async def _receive(self) -> Any:
        """One object off the framed view, from the one reader a stream allows.

        The three policies this layer owns, and nothing else: a RAW-declared
        stream frames nothing, a closed stream reads nothing, and a stream reads
        from one task at a time. The frame-boundary rule underneath belongs to
        `QueryStream.receive`, which is where layer 2 keeps it for the control
        channel too, so there is one implementation and not three.

        The one thing this layer has to add to it: a `QueryStream` that closed
        itself on a lost boundary has released the descriptor, and the connection
        **permit** and the client's registration are this layer's to release.
        Leaving them held would keep a bounded client one connection short of its
        bound for the rest of its life, over a connection that is already gone.
        """
        self._require_framed("read objects")
        if self._conn.corrupt:
            # Before the closed check, which would otherwise fire first and
            # report the symptom in place of the cause: this stream is closed
            # *because* a read desynchronised it, and a caller retrying after a
            # deadline has to be told which. `QueryStream.receive` owns that
            # message and raises before it touches the transport, so calling it
            # is how there stays exactly one.
            return await self._conn.receive(self._read_fmt, self._write_fmt)
        if self._closing:
            raise StreamClosed(f"{self!r}: the stream is closed")
        if self._reading:
            raise ConcurrentRead(
                f"{self!r}: a read is already in flight; one query is one stream "
                "and concurrency is more queries"
            )
        self._reading = True
        try:
            return await self._conn.receive(self._read_fmt, self._write_fmt)
        except EOFError:
            raise
        except BaseException:
            if self._conn.corrupt and not self._closing:
                await self.aclose()
            raise
        finally:
            self._reading = False

    async def _next_object(self, *, until: str, raise_on_error: bool) -> Any:
        """THE read path. One object, or `_END` when this iteration is over.

        Every iterator on this class is a loop over this method, so the `eos`
        rules and the error rule exist once. `until` is the op's declared shape
        and is never inferred: `_UNTIL_EOS` treats the first `eos` as the
        terminator it is on every non-follow op, `_UNTIL_SEPARATOR` treats it as
        the snapshot boundary and leaves the stream open behind it, and
        `_UNTIL_END` crosses that boundary and runs until EOF.
        """
        while True:
            try:
                obj = await self._receive()
            except EOFError:
                self._terminated_by = "eof"
                return _END
            if is_eos(obj):
                if until == _UNTIL_SEPARATOR:
                    # The snapshot is complete. The stream is not, so
                    # `terminated_by` stays unset.
                    self._live = True
                    return _END
                if until == _UNTIL_EOS or self._live:
                    # A second `eos` in follow mode is the op ending: there is
                    # only one snapshot boundary, so nothing else it can be.
                    self._terminated_by = "eos"
                    return _END
                self._live = True
                continue
            if raise_on_error and _is_error(obj):
                raise RemoteError(
                    str(obj), query=self.query_string, endpoint=self.endpoint
                )
            return obj

    async def _walk(self, *, until: str, raise_on_error: bool) -> AsyncIterator[Any]:
        while True:
            obj = await self._next_object(until=until, raise_on_error=raise_on_error)
            if obj is _END:
                return
            yield obj

    # --- iteration ---

    def __aiter__(self) -> AsyncIterator[Any]:
        """Every object up to the first `eos` or to EOF.

        Raises `RemoteError` on an `error_message`, because yielding one is how a
        failed stage feeds a wrong-typed object to the next. `raw_objects()` is
        the view that wants it as data.

        A deadline belongs to the consumer: wrap the `async for` in
        `asyncio.timeout` rather than looking for a `timeout` argument here,
        because what a per-object deadline should be is per-op (`follow` streams
        are idle for as long as nothing happens) and only the caller knows.
        """
        return self._walk(until=_UNTIL_EOS, raise_on_error=True)

    def raw_objects(self) -> AsyncIterator[Any]:
        """Every object, errors included, raising nothing.

        The CLI's view: an `error_message` goes to stderr and sets exit 1 while
        iteration continues, so a partial stream still prints (design section
        6.1). The `eos` is consumed and not yielded, exactly as `__aiter__` does;
        the error policy is the only difference between the two.
        """
        return self._walk(until=_UNTIL_EOS, raise_on_error=False)

    async def follow(self) -> AsyncIterator[tuple[Any, bool]]:
        """`(object, live)` pairs across the snapshot/live separator.

        The primitive that `snapshot()` and `live()` are written over. Follow-mode
        ops send an `eos` that is a boundary rather than a terminator, so this
        iterator crosses it and keeps reading; `live` is `False` for the snapshot
        and `True` for everything after. The legacy `follow()` swallowed the
        boundary entirely, which left a caller unable to tell a stored value from
        a change to it.

        Ends at EOF, or at a second `eos` -- there is exactly one boundary, so a
        second one is the op ending. Never call this on a non-follow op: its
        terminating `eos` would be read as a boundary and the iterator would then
        block until the responder closed.
        """
        while True:
            obj = await self._next_object(until=_UNTIL_END, raise_on_error=True)
            if obj is _END:
                return
            yield obj, self._live

    def snapshot(self) -> AsyncIterator[Any]:
        """The stored state of a follow stream, stopping **at** the separator.

        Exactly the separator is consumed and no live object is read, so
        `live()` afterwards resumes where this left off.
        """
        return self._walk(until=_UNTIL_SEPARATOR, raise_on_error=True)

    async def live(self) -> AsyncIterator[Any]:
        """The updates of a follow stream, discarding the snapshot.

        On a stream whose separator has already been consumed -- by `snapshot()`
        -- nothing is discarded and this yields the updates from that point.
        """
        async for obj, live in self.follow():
            if live:
                yield obj

    # --- the shape helpers (design section 4.7) ---

    async def collect(self, *, timeout: float | None = None) -> list[Any]:
        """Every object to the terminator. The ST helper.

        Never call this on a follow-mode op or on `user.sync_assets`: the first
        ends at a separator this waits past, and the second ends with a bare
        `uint64` and no `eos` at all, so both hang until the responder closes
        (design section 3.10).
        """
        async with self._deadline(timeout, "the stream did not end"):
            return [obj async for obj in self]

    async def value(self, *, timeout: float | None = None) -> Any:
        """Exactly one object, then the end of the stream. The RR helper.

        Both failures are the op breaking its declared shape rather than the
        transport failing, so both are `ProtocolError`: an RR op that answers
        with nothing has told the caller nothing, and one that answers twice has
        made the caller's single return value a lie about the second object.
        """
        async with self._deadline(timeout, "the stream did not answer"):
            first = await self._next_object(until=_UNTIL_EOS, raise_on_error=True)
            if first is _END:
                raise ProtocolError(
                    f"{self.query_string}: expected one object, the stream ended "
                    f"with none ({self._terminated_by})"
                )
            extra = await self._next_object(until=_UNTIL_EOS, raise_on_error=True)
            if extra is not _END:
                raise ProtocolError(
                    f"{self.query_string}: expected one object, got at least two "
                    f"(the second is {getattr(extra, 'ASTRAL_TYPE', '?')!r})"
                )
            return first

    async def first(self, *, timeout: float | None = None) -> Any | None:
        """The next object, or `None` at the end of the stream.

        Does not require the stream to end, so it is the head of a stream rather
        than the whole of it. `value()` is the one that insists.
        """
        async with self._deadline(timeout, "the stream did not answer"):
            obj = await self._next_object(until=_UNTIL_EOS, raise_on_error=True)
            return None if obj is _END else obj

    # --- sending ---

    async def send(self, obj: Any, *, timeout: float | None = None) -> None:
        """One object onto the stream, in exactly one `write()`.

        The body-input ops need this: `tree.set`, `crypto.sign_*`,
        `crypto.verify_*`, `objects.store/push/create`, `auth.sign_contract` and
        the rest of the list in design section 4.7. Passing their input as a
        query argument instead is the single most common way to get an op wrong,
        and on `crypto.verify_*` it silently never verifies.

        `timeout` bounds the drain, which is where a peer that stopped reading
        pins the send.
        """
        self._require_open()
        self._require_framed("send objects")
        async with self._deadline(timeout, f"{_type_of(obj)} was not sent"):
            await self._conn.channel(self._read_fmt, self._write_fmt).send(obj)

    async def send_eos(self, *, timeout: float | None = None) -> None:
        """The `eos` terminator, for an op that reads its input to one.

        astral-go's `objects.register_blueprint` and `objects.store` clients
        never send it (bug G-10), so the op waits for input that never ends.
        """
        await self.send(EOS(), timeout=timeout)

    async def send_bytes(self, data: bytes, *, timeout: float | None = None) -> None:
        """Unframed bytes, written and drained. The raw view's back-pressure point."""
        self._require_open()
        async with self._deadline(timeout, "the body was not sent"):
            await self._conn.send_bytes(data)

    async def read_bytes(self, n: int = -1, *, timeout: float | None = None) -> bytes:
        """Up to `n` unframed bytes, or the whole body when `n` is negative.

        The RAW mode of design section 4.7, and `objects.read` is its only op:
        the response is not a framed object channel at all. `b""` is the end of
        the stream and sets `terminated_by`, so a raw body reports its ending in
        the same vocabulary an object stream does.

        Reading to EOF is bounded by the stream's `max_alloc`, because the body's
        length is the responder's to choose and it is the one attacker-controlled
        length in the SDK with no prefix to check first.
        """
        self._require_open()
        async with self._deadline(timeout, "the body did not arrive"):
            data = await self._conn.read(n)
        # `read(-1)` returns only at EOF, and a short read of `b""` is EOF. A
        # zero-length request is neither and must not be reported as an ending.
        if n < 0 or (n > 0 and not data):
            self._terminated_by = "eof"
        return data

    async def write_eof(self) -> None:
        """Half-close the send direction, leaving the read direction open.

        Drains first, so the bytes already written are on their way before the
        peer is told there are no more. Verified live: after `shutdown(SHUT_WR)`
        on an accepted query the response object still arrived, then EOF. This is
        how a write-and-answer op signals that its input is complete when the op
        reads to EOF rather than to an `eos`.
        """
        self._require_open()
        await self._conn.drain()
        self._conn.write_eof()

    # --- cancellation ---

    async def cancel(self, *, cause: str | None = None) -> bool:
        """Ask the node to cancel this query, on a **fresh** connection.

        The protocol has no in-band cancel: a query is cancelled by routing
        `apphost.cancel?id=<nonce>` from a separate session, after which this
        stream sees `error_msg{canceled}` or EOF. Returns whether the cancel
        query was accepted, and never raises.

        This does not close the stream. Cancelling asks the responder to stop;
        closing is still the caller's, and is still what frees the node worker.
        """
        if self._connector is None:
            return False
        return await cancel_query(
            self._connector, self.nonce, cause=cause, timeout=self._cancel_timeout
        )

    # --- lifetime ---

    def _require_open(self) -> None:
        if self._closing:
            raise StreamClosed(f"{self!r}: the stream is closed")

    def _require_framed(self, what: str) -> None:
        """Refuse an object operation on a stream the op declared RAW.

        `objects.read` answers with a stored file, so the bytes are the
        responder's or an attacker's to choose. Framing them is not a decode
        failure but a decode *success* on the wrong bytes, which is why this
        raises rather than warning.
        """
        if self._raw:
            raise ProtocolError(
                f"{self.query_string}: this op answers with unframed bytes (RAW "
                f"mode, design section 4.7), so it cannot {what}; read_bytes() is "
                "the whole of its response"
            )

    @contextlib.asynccontextmanager
    async def _deadline(self, timeout: float | None, what: str) -> AsyncIterator[None]:
        """One deadline, reported in the hierarchy's vocabulary.

        A bare `TimeoutError` is outside `AstralError`, so a caller catching the
        documented catch-all would miss every deadline this class sets.
        """
        try:
            async with asyncio.timeout(timeout):
                yield
        except TimeoutError as exc:
            raise QueryTimeout(
                f"{self.query_string}: {what} within {timeout}s"
            ) from exc

    async def aclose(self) -> None:
        """Close the stream. Idempotent, and never raises a fault of its own.

        A `CancelledError` aimed at the caller propagates -- the transport aborts
        rather than flushing and the descriptor is gone either way -- because a
        close that swallowed one would break structured cancellation while
        claiming to have done the caller a favour.

        **Returning means closed**, for every caller: a concurrent second call
        waits for the first rather than reporting a released connection whose
        descriptor is still open, because a client that counted that as free
        would count a node worker free that is still held.

        The permit is released **after** the transport is gone and never before.
        A release on entry would let the next queued query dial into the node
        while this connection is still open, so a client bounded at N would hold
        N+1 -- which is the bound failing in exactly the way design section 3.9
        says the node cannot absorb.
        """
        if self._closing:
            await self._released.wait()
            return
        self._closing = True
        try:
            await self._conn.aclose()
        finally:
            self._closed = True
            self._release()
            self._released.set()

    def _release(self) -> None:
        """Hand the client back its permit and its registration, exactly once."""
        if self._released_permit:
            return
        self._released_permit = True
        if self._on_close is not None:
            # A fault in the client's bookkeeping must not leave `aclose()`
            # raising: the descriptor is already gone by here, which is the part
            # the node's worker pool depends on.
            with contextlib.suppress(Exception):
                self._on_close(self)

    async def __aenter__(self) -> "Stream":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def _type_of(obj: Any) -> str:
    return getattr(obj, "ASTRAL_TYPE", type(obj).__name__)
