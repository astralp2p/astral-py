"""The line framing: one object per newline-terminated line.

Two formats share it -- `json` and `text` -- so it is written once and neither
module restates it. The subclass supplies one encoder and one decoder, both over
a whole line; everything else about the framing lives here.

```
<line> \n <line> \n ...
```

The framing carries no length, so a line is located by its terminator alone.
Three consequences, and each one is a rule rather than a preference:

- **A partial line is a truncated frame.** The stream ending with bytes and no
  newline reports `StreamCorrupted`, and `at_frame_boundary` goes false.
  astral-go's `bufio.ReadString('\\n')` returns those bytes alongside `io.EOF`
  and its receiver discards them, so a final line the peer never terminated is
  silently dropped; a truncated `#[uint8] 12` reads as `#[uint8] 1`, which is a
  plausible wrong value rather than a fault, so the divergence is deliberate.
- **The first fault latches.** A line framing can locate the next line after a
  decode fault, but astral-go's receivers do not and say so
  (`json_receiver.go`, `text_receiver.go`: "the policy here is fail-fast: the
  first non-nil error latches and subsequent Receive() calls return it without
  touching the reader"). The latch is matched, including the `EOFError` that
  ends the stream: an ended stream stays ended.
- **`allow_unparsed` is accepted and not honoured**, matching those same
  receivers. An `UnparsedObject` is a type name plus its **binary** payload; a
  JSON line carries a JSON value and a text line may carry the type's own text
  form, and neither can be turned into a binary payload without inventing one.
  An unknown type is therefore `StreamCorrupted` wrapping `BlueprintNotFound`.

**The read buffer is this framing's own, and that is what forbids `detach()`.**
A line is found by reading ahead, so the bytes after the newline are in the
channel and not in the transport, and a raw stream taking the transport over
would start mid-line (design section 3.1). The same buffer makes a cancelled
read harmless: every byte read from the transport is retained, so an abandoned
`receive()` strands nothing and the next one resumes from the same position.
That is the opposite of `BinaryChannel`, where an abandoned read has consumed a
tag whose payload is still on the wire, and it is why `at_frame_boundary` is
true here except after a truncation.

For the same reason a line channel and the raw byte view of one `QueryStream`
are mutually exclusive: bytes already in this buffer are invisible to
`QueryStream.read`.
"""

from __future__ import annotations

import abc
from typing import Any, ClassVar, Final

from ..errors import AllocationLimit, StreamCorrupted, TransportUnsupported
from ..registry import Blueprints, default_blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC
from . import Channel, Format, is_eos

__all__ = ["LineChannel"]

NEWLINE: Final = b"\n"

# One read of the transport. Large enough that a line costs one read, bounded so
# a single read cannot outgrow the allocation cap on its own.
CHUNK: Final = 65536

# The pair every string on the wire uses. Go strings are byte containers, and
# surrogateescape is the only error handler that round-trips arbitrary bytes
# through `str` byte-exactly.
_ENCODING: Final = "utf-8"
_ERRORS: Final = "surrogateescape"


class LineChannel(Channel):
    """An object stream framed by newlines. One format per subclass."""

    __slots__ = (
        "_conn",
        "_registry",
        "_max_alloc",
        "_buf",
        "_saw_eos",
        "_eof",
        "_error",
        "_stranded",
    )

    FORMAT: ClassVar[Format] = Format.TEXT
    """The token this framing answers to in `in=` and `out=`."""

    def __init__(
        self,
        transport: Transport,
        *,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        allow_unparsed: bool = False,
    ) -> None:
        """`allow_unparsed` is accepted for one call site and not honoured.

        `open_channel` passes it to every format because `BinaryChannel` can
        honour it. This framing cannot, for the reason the module docstring
        states, and refusing the whole channel over a tolerance hint would make
        `out=json` unreachable from any caller that sets the hint once for every
        format. The hint is dropped and `allow_unparsed` answers false, so
        nothing reports a tolerance it does not have.
        """
        self._conn = transport
        self._registry = default_blueprints() if registry is None else registry
        self._max_alloc = max_alloc
        # Bytes read from the transport and not yet returned as a line. Holds
        # whole lines as readily as a fragment: a read is sized for the
        # transport, not for the framing.
        self._buf = bytearray()
        self._saw_eos = False
        self._eof = False
        self._error: Exception | None = None
        self._stranded = False

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._conn.endpoint!r}, {self.FORMAT.value})"

    # --- Channel ---

    @property
    def transport(self) -> Transport:
        return self._conn

    @property
    def registry(self) -> Blueprints:
        """The registry every line on this channel decodes through."""
        return self._registry

    @property
    def allow_unparsed(self) -> bool:
        """Always false. A line framing cannot carry an unparsed object."""
        return False

    @property
    def saw_eos(self) -> bool:
        return self._saw_eos

    @property
    def at_frame_boundary(self) -> bool:
        """Whether the reader sits between lines.

        True until the stream ends inside a line. A cancelled or expired read
        leaves every byte it consumed in this channel's buffer, so it cannot
        strand a fragment; a stream that ended mid-line has a fragment nothing
        will ever complete, and that is the one case a caller must not treat as
        recoverable.

        The carrier's answer is conjoined, because this channel's buffer is not
        the only place a byte can be stranded: a `WebSocketByteTransport` can be
        half a WebSocket frame out of step while this buffer holds a clean line
        boundary, and a caller that believed the line boundary would keep a
        connection whose next bytes are the peer's to reframe.
        """
        return not self._stranded and self._carrier_at_boundary()

    def _carrier_at_boundary(self) -> bool:
        """The carrier's own boundary fact, defaulting to true.

        `getattr` because this channel serves two seams: `Transport` declares
        the property, and `MessageStream` -- the `astral.json.v1` carrier
        `WebSocketJSONChannel` frames over -- is a structural protocol whose
        implementations need not. `WebSocketClient` does answer it.
        """
        return bool(getattr(self._conn, "at_frame_boundary", True))

    @property
    def latched(self) -> bool:
        """Whether a fault has ended this channel for good."""
        return self._error is not None

    async def receive(self) -> Any:
        if self._error is not None:
            raise self._error
        try:
            line = await self._read_line()
            obj = self._decode_line(line)
        except Exception as exc:
            # Deliberately `Exception` and not `BaseException`: a cancelled read
            # is not a fault of the stream and must not end it. `EOFError` is
            # latched with the rest, because the end of a stream is permanent.
            self._error = exc
            raise
        if is_eos(obj):
            self._saw_eos = True
        return obj

    async def send(self, obj: Any) -> None:
        """One object as one line, in one write.

        The line is serialised whole before anything is written, so a fault in
        the encoder writes nothing at all and cancellation cannot land mid-line
        (design section 3.2, rule 2).
        """
        await self._send_line(self._encode_line(obj))

    def detach(self) -> Transport:
        raise TransportUnsupported(
            f"{self.FORMAT.value} channel: detach() needs byte-exact framing. A "
            f"line framing reads ahead, and {len(self._buf)} byte(s) sit in this "
            "channel rather than in the transport, so a raw stream would start "
            "mid-line. Only the binary channel hands a transport over (design "
            "section 3.1)."
        )

    async def aclose(self) -> None:
        await self._conn.aclose()

    # --- framing ---

    async def _read_line(self) -> str:
        """One line, terminator stripped. `EOFError` at a clean end of stream."""
        while True:
            cut = self._buf.find(NEWLINE)
            if cut >= 0:
                line = bytes(self._buf[:cut])
                del self._buf[: cut + 1]
                return line.decode(_ENCODING, _ERRORS)
            if self._eof:
                if not self._buf:
                    raise EOFError("end of object stream")
                self._stranded = True
                raise StreamCorrupted(
                    f"{self.FORMAT.value} channel: the stream ended {len(self._buf)} "
                    "byte(s) into a line with no terminator, so what it carries "
                    "cannot be told from a whole object"
                )
            if len(self._buf) > self._max_alloc:
                # A line prefix is attacker-controlled and the framing gives no
                # length to check, so the only bound is how much has arrived.
                # Stranded as surely as a truncation: the rest of the line is
                # still coming and nothing will read it.
                self._stranded = True
                raise AllocationLimit(
                    f"{self.FORMAT.value} channel: {len(self._buf)} bytes with no "
                    f"line terminator exceeds max_alloc {self._max_alloc}"
                )
            chunk = await self._read_chunk()
            if not chunk:
                self._eof = True
                continue
            self._buf += chunk

    async def _read_chunk(self) -> bytes:
        """More bytes for the buffer. `b""` is end of stream."""
        return await self._conn.read(CHUNK)

    async def _send_line(self, line: str) -> None:
        """Write one encoded line, terminator included, and drain."""
        self._conn.write(line.encode(_ENCODING, _ERRORS))
        await self._conn.drain()

    # --- the format ---

    @abc.abstractmethod
    def _decode_line(self, line: str) -> Any:
        """The object one line carries, terminator already stripped."""

    @abc.abstractmethod
    def _encode_line(self, obj: Any) -> str:
        """One object as a line, terminator included."""
