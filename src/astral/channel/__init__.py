"""The object-stream seam: the `Channel` ABC, the format tokens, `open_channel`.

A `Channel` is an object stream over a `Transport`. The two are separate seams
because the WebSocket JSON subprotocol is message-oriented and has no byte stream
underneath it, so a channel cannot be a transport decorator (design section 3.1).

Two rules bind every implementation:

1. **No read buffer above the transport.** On `query_accepted_msg` the connection
   stops being a message channel and becomes the query's raw bidirectional
   bytestream; a buffer of the channel's own would strand the first raw bytes.
   Every framing read goes through the transport, whose `asyncio.StreamReader` is
   the same buffer before and after the handover, so `detach()` is a no-op
   handover of the identical object (design section 3.2, rule 1).
2. **One `write()` per object.** A frame is serialised whole and issued in one
   call, so frames cannot interleave and cancellation cannot land mid-frame. No
   write lock exists anywhere in the SDK (design section 3.2, rule 2).

`detach()` is legal on `BinaryChannel` alone. A line-oriented receiver may hold a
partial line, and the protocol never needs the handover there: the apphost
handshake is binary on every transport.

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
    `channel.WithFormats`. Only `bin` is implemented; the line-oriented and
    canonical channels land with step 14, and asking for one raises
    `TransportUnsupported` rather than silently framing as binary.
    """
    parsed_in = parse_format(fmt_in, output=False)
    parsed_out = parse_format(fmt_out, output=True)
    if parsed_in is not Format.BIN or parsed_out is not Format.BIN:
        raise TransportUnsupported(
            f"channel format {parsed_in.value}/{parsed_out.value}: the json, text, "
            "canonical, base64 and render channels land with channel/jsonl.py, "
            "channel/textchan.py and channel/canonical.py"
        )
    from .binary import BinaryChannel

    return BinaryChannel(
        transport,
        allow_unparsed=allow_unparsed,
        registry=registry,
        max_alloc=max_alloc,
    )
