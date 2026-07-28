"""The object-stream seam: the `Channel` ABC, the format tokens, `open_channel`.

A `Channel` is an object stream over a `Transport`. The two are separate seams
because the WebSocket JSON subprotocol is message-oriented and has no byte stream
underneath it, so a channel cannot be a transport decorator (design section 3.1).

Two rules bind every implementation:

1. **A framing that can be handed over holds no read buffer of its own.** On
   `query_accepted_msg` the connection stops being a message channel and becomes
   the query's raw bidirectional bytestream; a buffer of the channel's own would
   strand the first raw bytes. `BinaryChannel` reads a length and then exactly
   that many bytes, so every read goes through the transport, whose
   `asyncio.StreamReader` is the same buffer before and after the handover, and
   `detach()` is a no-op handover of the identical object (design section 3.2,
   rule 1). No other framing announces a length: a line is located by its
   terminator and a canonical object by its own decoder, so both must read ahead
   and both keep the surplus. That is exactly why `detach()` is theirs to refuse
   and why a session over one answers false to `supports_raw_stream`.
2. **One `write()` per object.** A frame is serialised whole and issued in one
   call, so frames cannot interleave and cancellation cannot land mid-frame. No
   write lock exists anywhere in the SDK (design section 3.2, rule 2).

`detach()` is legal on `BinaryChannel` alone, and the protocol never needs it
elsewhere: the apphost handshake is binary on every transport.

Format tokens are undocumented as a set (astral-docs bug D-7). The complete set,
from astral-go's `channel/common.go`: `bin`, `json`, `text`, `canonical`,
`base64`, `render`; `base64` and `render` are output-only, and an empty token
means `bin`. A node silently accepts an unknown `out=` and then produces zero
bytes (astral-docs bug D-24), so validation is client-side.
"""

from __future__ import annotations

import abc
import enum
from types import TracebackType
from typing import Any, AsyncIterator, Final

from ..errors import ParseError, TransportUnsupported
from ..registry import Blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC

__all__ = [
    "Channel",
    "Format",
    "INPUT_FORMATS",
    "OUTPUT_FORMATS",
    "SplitChannel",
    "TEXT_OUTPUT_FORMATS",
    "is_eos",
    "open_channel",
    "parse_format",
]


class Format(enum.StrEnum):
    """A channel format token, as it appears in an `in=` or `out=` parameter."""

    BIN = "bin"
    JSON = "json"
    TEXT = "text"
    CANONICAL = "canonical"
    BASE64 = "base64"
    RENDER = "render"


INPUT_FORMATS: Final = frozenset(
    {Format.BIN, Format.JSON, Format.TEXT, Format.CANONICAL}
)
OUTPUT_FORMATS: Final = frozenset(Format)

TEXT_OUTPUT_FORMATS: Final = frozenset({Format.TEXT, Format.BASE64, Format.RENDER})
"""The outputs one `TextChannel` writes.

`base64` and `render` are that channel's variants rather than channels of their
own, so `text` in with any of them out is one implementation and needs no split.
"""

# The object type that terminates an object stream. Compared by name rather than
# by class, so a runtime record decoded under the same name reads as a
# terminator too.
_EOS_TYPE: Final = "eos"


def parse_format(token: str, *, output: bool) -> Format:
    """Validate one format token. An empty token is `bin`, as in astral-go.

    Raises `ParseError` for an unknown token and for `base64` or `render` in an
    input position. A `ParseError` and not a bare `ValueError`: this token comes
    off a query string a caller wrote, so it is one more unparsable text form,
    and `Client.query(fmt_out=...)` puts it on the public surface where the
    documented `except AstralError` has to catch it. It is a `ValueError` as
    well, so nothing that already caught one stops working.
    """
    name = token or Format.BIN
    try:
        fmt = Format(name)
    except ValueError:
        allowed = ", ".join(sorted(f.value for f in (OUTPUT_FORMATS if output else INPUT_FORMATS)))
        raise ParseError(
            f"unknown channel format {token!r}: expected one of {allowed}"
        ) from None
    if not output and fmt not in INPUT_FORMATS:
        raise ParseError(f"channel format {fmt.value!r} is output-only")
    return fmt


def is_eos(obj: Any) -> bool:
    """Whether an object is the `eos` terminator."""
    return getattr(obj, "ASTRAL_TYPE", None) == _EOS_TYPE


class Channel(abc.ABC):
    """A bidirectional object stream over one transport."""

    __slots__ = ()

    @property
    @abc.abstractmethod
    def transport(self) -> Transport:
        """The transport this channel frames over."""

    @property
    @abc.abstractmethod
    def saw_eos(self) -> bool:
        """Whether an `eos` object has been received.

        `eos` is a convention of the op handler, not a transport signal, and it
        is per-op: some ops end with `eos`, some end at bare EOF (astral-docs bug
        D-23). A consumer terminates on either and must be able to tell which.
        """

    @property
    @abc.abstractmethod
    def at_frame_boundary(self) -> bool:
        """Whether the reader sits between frames rather than inside one.

        A read abandoned mid-frame -- a deadline expiring, a caller cancelling
        -- leaves the bytes it already consumed gone and the rest of the frame
        still to come, so every later read is one frame out of step and the peer
        chooses what the next message says. That is the forgery the framing-fault
        rule exists to prevent, arriving through cancellation instead of through
        a bad length, and nothing above the channel can tell the two cases apart
        from the outside. So the channel answers it, and every implementation
        must.
        """

    @abc.abstractmethod
    async def receive(self) -> Any:
        """Read one object.

        Raises `EOFError` at a clean end of stream, and `StreamCorrupted` when
        the stream ends mid-frame or the framing is unreadable.
        """

    @abc.abstractmethod
    async def send(self, obj: Any) -> None:
        """Write one object as exactly one `Transport.write()`, then drain."""

    @abc.abstractmethod
    def detach(self) -> Transport:
        """Stop framing and hand the transport to the caller.

        Legal only where the framing is byte-exact, which is `BinaryChannel`
        alone. The channel is inert afterwards: `receive()` and `send()` raise,
        and `aclose()` does nothing, because the transport now belongs to the
        caller.
        """

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Close the transport. Idempotent, and a no-op after `detach()`.

        Returns only once the transport is closed, which it inherits by
        delegating rather than by guarding: the transport owns that promise.
        """

    async def __aiter__(self) -> AsyncIterator[Any]:
        """Every object up to the first `eos` or to EOF.

        The `eos` is consumed and not yielded; `saw_eos` records it. Error
        objects are yielded unchanged -- raising on `error_message` is `Stream`'s
        job, one layer up, because a channel has no notion of a query.
        """
        while True:
            try:
                obj = await self.receive()
            except EOFError:
                return
            if is_eos(obj):
                return
            yield obj

    async def __aenter__(self) -> "Channel":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class SplitChannel(Channel):
    """A channel that reads one format and writes another.

    astral-go builds its receiver and its sender independently
    (`newReceiver`/`newSender`), so a query saying `out=json` with no `in=`
    reads JSON and writes binary. That pair is the common case, not an exotic
    one: `in=` is what the responder reads and `out=` is what it writes, and a
    caller who names only the answer's format has asked for exactly this.

    The read half owns everything the read side reports -- `saw_eos`,
    `at_frame_boundary` -- and both halves frame over one transport.
    """

    __slots__ = ("_reader", "_writer")

    def __init__(self, reader: Channel, writer: Channel) -> None:
        self._reader = reader
        self._writer = writer

    def __repr__(self) -> str:
        return f"SplitChannel(reads {self._reader!r}, writes {self._writer!r})"

    @property
    def reader(self) -> Channel:
        """The half that receives."""
        return self._reader

    @property
    def writer(self) -> Channel:
        """The half that sends."""
        return self._writer

    @property
    def transport(self) -> Transport:
        return self._reader.transport

    @property
    def saw_eos(self) -> bool:
        return self._reader.saw_eos

    @property
    def at_frame_boundary(self) -> bool:
        return self._reader.at_frame_boundary

    async def receive(self) -> Any:
        return await self._reader.receive()

    async def send(self, obj: Any) -> None:
        await self._writer.send(obj)

    def detach(self) -> Transport:
        raise TransportUnsupported(
            f"channel reads {type(self._reader).__name__} and writes "
            f"{type(self._writer).__name__}: detach() is legal on a binary "
            "channel alone, and a pair of formats is never one (design section "
            "3.1)"
        )

    async def aclose(self) -> None:
        """Close both halves. They share one transport, whose close is idempotent."""
        try:
            await self._reader.aclose()
        finally:
            await self._writer.aclose()


def _channel_for(
    fmt: Format,
    transport: Transport,
    *,
    fmt_out: Format | None = None,
    allow_unparsed: bool = False,
    registry: Blueprints | None = None,
    max_alloc: int = DEFAULT_MAX_ALLOC,
) -> Channel:
    """The channel class one format token names.

    Imported here rather than at module scope: `astral.channel` is imported by
    the session, and a format nobody asked for costs nothing to leave unloaded.
    """
    common: dict[str, Any] = {"registry": registry, "max_alloc": max_alloc}
    if fmt is Format.BIN:
        from .binary import BinaryChannel

        return BinaryChannel(transport, allow_unparsed=allow_unparsed, **common)
    if fmt is Format.JSON:
        from .jsonl import JSONLinesChannel

        return JSONLinesChannel(transport, allow_unparsed=allow_unparsed, **common)
    if fmt is Format.CANONICAL:
        from .canonical import CanonicalChannel

        return CanonicalChannel(transport, allow_unparsed=allow_unparsed, **common)
    from .textchan import TextChannel

    return TextChannel(
        transport,
        fmt_out=fmt_out if fmt_out is not None else Format.TEXT,
        allow_unparsed=allow_unparsed,
        **common,
    )


def open_channel(
    transport: Transport,
    fmt_in: str = Format.BIN,
    fmt_out: str = Format.BIN,
    *,
    allow_unparsed: bool = False,
    registry: Blueprints | None = None,
    max_alloc: int = DEFAULT_MAX_ALLOC,
) -> Channel:
    """A channel over `transport`, reading `fmt_in` and writing `fmt_out`.

    The two directions are independent, matching astral-go's
    `channel.WithFormats`, and a pair that needs two implementations becomes a
    `SplitChannel`. `fmt_in` is validated as an input format, which is what
    rejects `base64` and `render`: both exist as output alone, and `render` has
    no parser anywhere -- astral-go's `newReceiver` answers "unsupported input
    format" for it.

    Note the direction of these names. They are the **channel's**: `fmt_in` is
    what this channel reads. A query string's `in=`/`out=` are the responder's,
    so a caller passing them through swaps the two, which `Stream` does.
    """
    parsed_in = parse_format(fmt_in, output=False)
    parsed_out = parse_format(fmt_out, output=True)
    common: dict[str, Any] = {
        "allow_unparsed": allow_unparsed,
        "registry": registry,
        "max_alloc": max_alloc,
    }
    # One text channel covers `text` in with any of its three outs, so the pair
    # is split only where two implementations are genuinely needed.
    if parsed_in is Format.TEXT and parsed_out in TEXT_OUTPUT_FORMATS:
        return _channel_for(parsed_in, transport, fmt_out=parsed_out, **common)
    if parsed_in is parsed_out:
        return _channel_for(parsed_in, transport, **common)
    return SplitChannel(
        _channel_for(parsed_in, transport, **common),
        _channel_for(parsed_out, transport, fmt_out=parsed_out, **common),
    )
