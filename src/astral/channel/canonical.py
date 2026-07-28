"""`CanonicalChannel`: `Stamp ++ string8(type) ++ payload`, with no length at all.

The framing that genuinely differs (astral-docs bug D-12). Three of the four
containers carry a length somewhere; this one carries none:

| Container | Layout |
|---|---|
| Binary channel frame | `string8(type)` ++ `bytes32(payload)` |
| Bundle element | `bytes32( string8(type) ++ payload )` |
| **Canonical** | `Stamp` ++ `string8(type)` ++ `payload` |
| Polymorphic field | `string8(type)` ++ `payload` |

`Stamp` is `41 44 43 30`, the ASCII `ADC0`. What the node writes, verified
against `furry-bolt` this session -- six objects back to back, no separator, no
terminator:

```
dir.filters?out=canonical
41444330 07 "string8" 09 "localnode"  41444330 07 "string8" 06 "linked" …
41444330 03 "eos"
```

**An object's length is its own decoder's business.** Nothing announces it, so
the receiver reads what has arrived, decodes from the start of the buffer, and
on `ShortRead` reads more and decodes again; the reader's `pos` after a
successful decode is the object's length. The decoders are pure functions of
their bytes, so a retry costs time and nothing else. astral-go instead hands the
socket to `object.ReadFrom` directly, which its own comment concedes leaves the
stream indeterminate on any error.

Three types cannot cross this framing, and the format is what excludes them, not
this implementation:

- **An untyped blob.** The type tag is what says where the payload starts, and a
  zero-length tag names no type. astral-go's `CanonicalSender` writes one
  anyway and its `CanonicalReceiver` then answers `blueprint not found:` on it;
  `codec.Canonical` refuses on the send side instead.
- **An `UnparsedObject`.** There is no length to skip, so an unknown type ends
  the stream. `allow_unparsed` is accepted and not honoured.
- **Any type whose decoder reads to the end of its input.** `Blob` and
  `UnparsedObject` are the only two, and neither is reachable here. A third
  would be undecodable in this framing for astral-go as well -- there, it would
  consume the whole socket.

**The first fault latches**, matching `CanonicalReceiver`: after a fault the
next object's first byte cannot be located, so a later read would be whatever
the peer chose. A cancelled read is not a fault: every byte read from the
transport stays in this channel's buffer, so an abandoned `receive()` strands
nothing. That buffer is also why `detach()` is refused -- the bytes after an
object are here, not in the transport.
"""

from __future__ import annotations

from typing import Any, Final

from ..codec import Canonical, canonical_bytes
from ..codec.binary import ObjectReader, read_object
from ..errors import (
    AllocationLimit,
    ShortRead,
    StreamCorrupted,
    TransportUnsupported,
)
from ..registry import Blueprints, default_blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC
from . import Channel, Format, is_eos

__all__ = ["CanonicalChannel"]

# One read of the transport, as in the line framing.
CHUNK: Final = 65536


class CanonicalChannel(Channel):
    """An object stream in the canonical framing."""

    __slots__ = (
        "_transport",
        "_registry",
        "_max_alloc",
        "_buf",
        "_saw_eos",
        "_eof",
        "_error",
        "_stranded",
    )

    FORMAT: Final = Format.CANONICAL

    def __init__(
        self,
        transport: Transport,
        *,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        allow_unparsed: bool = False,
    ) -> None:
        """`allow_unparsed` is accepted and not honoured.

        `open_channel` passes it to every format. This one cannot honour it: an
        unknown type has no length to skip, so the next object's first byte is
        unlocatable and the stream is over either way.
        """
        self._transport = transport
        self._registry = default_blueprints() if registry is None else registry
        self._max_alloc = max_alloc
        # Bytes read from the transport and not yet consumed by an object.
        self._buf = bytearray()
        self._saw_eos = False
        self._eof = False
        self._error: Exception | None = None
        self._stranded = False

    def __repr__(self) -> str:
        return f"CanonicalChannel({self._transport.endpoint!r})"

    # --- Channel ---

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def registry(self) -> Blueprints:
        """The registry every object on this channel decodes through."""
        return self._registry

    @property
    def allow_unparsed(self) -> bool:
        """Always false. There is no length prefix to skip an unknown type with."""
        return False

    @property
    def saw_eos(self) -> bool:
        return self._saw_eos

    @property
    def at_frame_boundary(self) -> bool:
        """Whether the next object's first byte is locatable.

        True until a fault, and a cancelled or expired read is not one: every
        byte consumed from the transport is in this channel's buffer, so an
        abandoned `receive()` leaves the position exactly where it was. A decode
        fault or a stream that ended inside an object is the case a caller must
        not treat as recoverable -- nothing says how many bytes the object
        should have been, so no later read can be trusted.

        The carrier's answer is conjoined for the reason `BinaryChannel` gives:
        this channel's buffer is not the only place a byte can be stranded, and
        a transport that frames -- WebSocket, chunked HTTP -- can be out of step
        underneath a buffer that looks clean.
        """
        return not self._stranded and self._transport.at_frame_boundary

    @property
    def latched(self) -> bool:
        """Whether a fault has ended this channel for good."""
        return self._error is not None

    async def receive(self) -> Any:
        if self._error is not None:
            raise self._error
        try:
            obj = await self._read_object()
        except Exception as exc:
            # A clean end of stream leaves the reader where it was: the buffer
            # was empty, so nothing is stranded. Every other fault leaves the
            # next object's first byte unlocatable, because nothing said how
            # long this one was. Both latch -- an ended stream stays ended --
            # and `Exception` rather than `BaseException`, so a cancelled read
            # is not a fault of the stream.
            if not isinstance(exc, EOFError):
                self._stranded = True
            self._error = exc
            raise
        if is_eos(obj):
            self._saw_eos = True
        return obj

    async def send(self, obj: Any) -> None:
        """One object as one write: stamp, type, payload.

        The frame is serialised whole before anything is written, so an empty
        object type -- which `codec.Canonical` refuses -- writes no byte at all,
        and cancellation cannot land mid-object (design section 3.2, rule 2).
        """
        frame = canonical_bytes(obj)
        self._transport.write(frame)
        await self._transport.drain()

    def detach(self) -> Transport:
        raise TransportUnsupported(
            "canonical channel: detach() needs byte-exact framing. This framing "
            f"has no length prefix, so it reads ahead, and {len(self._buf)} "
            "byte(s) sit in this channel rather than in the transport. Only the "
            "binary channel hands a transport over (design section 3.1)."
        )

    async def aclose(self) -> None:
        await self._transport.aclose()

    # --- framing ---

    async def _read_object(self) -> Any:
        """One object. `EOFError` at a clean end of stream.

        Decode-and-retry rather than read-a-length-then-decode, because there is
        no length. Each attempt starts at the buffer's first byte, so a decoder
        that consumed part of a short buffer has consumed nothing that matters.
        """
        while True:
            if self._buf:
                reader = ObjectReader(
                    bytes(self._buf), registry=self._registry, max_alloc=self._max_alloc
                )
                try:
                    obj = self._decode(reader)
                except ShortRead:
                    pass
                else:
                    del self._buf[: reader.pos]
                    return obj
            if self._eof:
                if not self._buf:
                    raise EOFError("end of object stream")
                raise StreamCorrupted(
                    f"canonical channel: the stream ended {len(self._buf)} byte(s) "
                    "into an object, and the framing carries no length to say how "
                    "many were missing"
                )
            if len(self._buf) > self._max_alloc:
                # The framing announces no length, so the only bound on one
                # object is how much has arrived.
                raise AllocationLimit(
                    f"canonical channel: {len(self._buf)} buffered bytes decode to "
                    f"no whole object and exceed max_alloc {self._max_alloc}"
                )
            chunk = await self._transport.read(CHUNK)
            if not chunk:
                self._eof = True
                continue
            self._buf += chunk

    def _decode(self, reader: ObjectReader) -> Any:
        """`Stamp ++ string8(type) ++ payload`, from the front of the buffer."""
        type_name = Canonical.read(reader)
        if not type_name:
            raise StreamCorrupted(
                "canonical channel: a zero-length type tag names no type, and the "
                "framing has no length prefix to locate what follows it; an "
                "untyped blob cannot cross this framing"
            )
        return read_object(reader, type_name)
