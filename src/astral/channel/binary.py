"""`BinaryChannel`: `string8(type) ++ bytes32(payload)`.

The framing the apphost handshake always uses, on every transport, and the only
one where `detach()` is legal.

```
byte      typeLen        0..255
byte[]    typeName       typeLen bytes
uint32    payloadLen     big-endian
byte[]    payload        payloadLen bytes
```

The type tag sits **outside** the length prefix. Three other containers carry a
type tag in a different place, and confusing them is the single most common
reimplementation error; `codec.channel_frame` is the one place this layout is
written, so the send side calls it rather than restating it. The read side cannot:
`codec.read_channel_frame` needs the whole frame in memory first, which is exactly
the read-ahead design section 3.2 forbids. It therefore reads the four fields
straight from the transport, in order, and consumes not one byte beyond the
payload.

Four receive rules, all inherited from astral-go's `BinaryReceiver`:

- A zero-length type tag is an untyped `Blob`. `blob` is not a registered type --
  astral-go's `Add` rejects an empty type and discards the error (bug G-19) -- so
  the mapping is an explicit special case.
- The payload is decoded from a reader bounded to exactly the frame's payload,
  never from the transport. A type that reads greedily to the end of its input,
  `Blob` and `UnparsedObject`, therefore consumes one frame and no more, and a
  decoder that under-reads its payload cannot desynchronise the stream.
- An unknown type name yields `BlueprintNotFound`, or an `UnparsedObject` when
  `allow_unparsed` is set. Binary framing is the only format where an unknown
  type is recoverable, because the length prefix locates the next frame.
- The declared payload length is checked against `max_alloc` before a byte is
  read. A `uint32` length is attacker-controlled, and a hostile four-billion
  count must cost bytes, not gigabytes.

The channel does not latch on error: `BlueprintNotFound` leaves the stream
readable at the next frame boundary, which is the whole point of the length
prefix. A framing fault -- a truncated frame, a length past `max_alloc` -- leaves
the stream unusable, and the caller closes the channel.

**A read is abandoned as often as it faults**, and abandonment is the quieter
hazard: a deadline expiring or a caller cancelling raises nothing the channel
sees, yet a `receive()` cut off between the tag and the payload has consumed
part of a frame and left the rest. Every later read is then one frame out of
step and the peer chooses what the next message says -- the same forgery a bad
length prefix opens, arriving through cancellation instead. `at_frame_boundary`
is the fact a caller needs to tell the harmless case from that one.
"""

from __future__ import annotations

from typing import Any, Final

from ..codec import channel_frame, payload_bytes
from ..codec.binary import ObjectReader
from ..errors import (
    AllocationLimit,
    BlueprintNotFound,
    StreamClosed,
    StreamCorrupted,
)
from ..object import Blob, UnparsedObject
from ..registry import Blueprints, default_blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC
from . import Channel, is_eos

__all__ = ["BinaryChannel"]

_DETACHED: Final = "channel is detached: the transport belongs to the caller"

# The pair `wire.py` uses for every string on the wire. Go strings are byte
# containers, and surrogateescape is the only error handler that round-trips
# arbitrary bytes through `str` byte-exactly.
_ENCODING: Final = "utf-8"
_ERRORS: Final = "surrogateescape"


class BinaryChannel(Channel):
    """An object stream in the binary framing."""

    __slots__ = (
        "_transport",
        "_registry",
        "_allow_unparsed",
        "_max_alloc",
        "_saw_eos",
        "_detached",
        "_mid_frame",
    )

    def __init__(
        self,
        transport: Transport,
        *,
        allow_unparsed: bool = False,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
    ) -> None:
        self._transport = transport
        self._registry = default_blueprints() if registry is None else registry
        self._allow_unparsed = allow_unparsed
        self._max_alloc = max_alloc
        self._saw_eos = False
        self._detached = False
        # Whether a frame is half-read. Flipped at the two exact instants the
        # reader crosses a frame boundary, so a caller that abandons a read can
        # ask whether it stranded anything.
        self._mid_frame = False

    def __repr__(self) -> str:
        state = "detached" if self._detached else "framing"
        return f"BinaryChannel({self._transport.endpoint!r}, {state})"

    # --- Channel ---

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def registry(self) -> Blueprints:
        """The registry every frame on this channel decodes through."""
        return self._registry

    @property
    def allow_unparsed(self) -> bool:
        return self._allow_unparsed

    @property
    def detached(self) -> bool:
        return self._detached

    @property
    def saw_eos(self) -> bool:
        return self._saw_eos

    @property
    def at_frame_boundary(self) -> bool:
        """Whether the reader sits between frames. Exact, not approximate.

        It goes false when a frame's first byte is consumed and true again when
        its last one is, so an abandoned read is harmless exactly when this is
        true. What makes that exact is that the only read issued while it is
        true is a single byte: one byte is either consumed or it is not, so a
        cancelled read at a boundary cannot have half-taken anything.

        Do not weaken that to a wider read on the assumption that `readexactly`
        is atomic. It is on `StreamTransport`, where asyncio consumes its buffer
        only once the whole request is present, but not on `MemTransport`, which
        accumulates chunks into a local buffer that a cancellation discards --
        and `MemTransport.at_frame_boundary` says so, which is the other half of
        this answer.

        **The carrier's own framing counts too, and this channel cannot see it.**
        Over `WebSocketByteTransport` a read abandoned between a WebSocket
        frame's header and its payload strands half a frame before this channel
        has been handed a single byte, so `_mid_frame` alone answered `True` for
        a stream the peer's own data would then reframe. The transport answers
        for its layer, this flag for ours, and a boundary is both.
        """
        return not self._mid_frame and self._transport.at_frame_boundary

    async def receive(self) -> Any:
        if self._detached:
            raise StreamClosed(_DETACHED)
        type_name = await self._read_type()
        payload = await self._read_payload()
        # Back at a boundary: `_decode` reads from the payload it was handed and
        # never from the transport, so a decode that raises leaves the next
        # frame's first byte exactly where it was.
        self._mid_frame = False
        obj = self._decode(type_name, payload)
        if is_eos(obj):
            self._saw_eos = True
        return obj

    async def send(self, obj: Any) -> None:
        if self._detached:
            raise StreamClosed(_DETACHED)
        # One `bytes`, one `write()`. The frame is committed before the only
        # cancellable point in the method, so cancellation cannot land mid-frame
        # and no write lock is needed.
        frame = channel_frame(getattr(obj, "ASTRAL_TYPE", ""), payload_bytes(obj))
        self._transport.write(frame)
        await self._transport.drain()

    def detach(self) -> Transport:
        """Hand the transport over. No byte is in flight anywhere but the transport."""
        self._detached = True
        return self._transport

    async def aclose(self) -> None:
        if self._detached:
            return
        await self._transport.aclose()

    # --- framing ---

    async def _read_type(self) -> str:
        """`string8`. EOF on its first byte is a clean end of stream."""
        head = await self._read(1, at_boundary=True)
        # One byte of this frame has left the reader and cannot be put back.
        self._mid_frame = True
        length = head[0]
        if length == 0:
            return ""
        return (await self._read(length)).decode(_ENCODING, _ERRORS)

    async def _read_payload(self) -> bytes:
        """`bytes32`, with the allocation cap enforced before the read."""
        declared = int.from_bytes(await self._read(4), "big")
        if declared > self._max_alloc:
            raise AllocationLimit(
                f"binary channel: payload length {declared} exceeds max_alloc "
                f"{self._max_alloc}"
            )
        if declared == 0:
            return b""
        return await self._read(declared)

    async def _read(self, n: int, *, at_boundary: bool = False) -> bytes:
        try:
            return await self._transport.readexactly(n)
        except EOFError as exc:
            partial = getattr(exc, "partial", b"")
            if at_boundary and not partial:
                raise
            raise StreamCorrupted(
                f"binary channel: truncated frame, wanted {n} bytes, got {len(partial)}"
            ) from exc

    def _decode(self, type_name: str, payload: bytes) -> Any:
        if not type_name:
            return Blob(payload)

        proto = self._registry.new(type_name)
        if proto is None:
            if self._allow_unparsed:
                return UnparsedObject(type_name, payload)
            raise BlueprintNotFound(type_name)

        reader = ObjectReader(
            payload, registry=self._registry, max_alloc=self._max_alloc
        )
        try:
            return proto.read_payload(reader)
        except (BlueprintNotFound, StreamCorrupted) as exc:
            # A type name the registry does not know, nested inside a payload:
            # fatal at field granularity, recoverable here, because the frame
            # length already located the next frame.
            if self._allow_unparsed and _missing_blueprint(exc):
                return UnparsedObject(type_name, payload)
            raise


def _missing_blueprint(exc: BaseException) -> bool:
    return isinstance(exc, BlueprintNotFound) or isinstance(
        exc.__cause__, BlueprintNotFound
    )
