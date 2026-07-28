"""A minimal RFC 6455 client, and the byte transport for `astral.binary.v1`.

The client half of RFC 6455 that this SDK needs is small and bounded: an HTTP
upgrade with `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` validation, client-masked
frames from `os.urandom`, ping/pong/close control frames, and receive-side
fragmentation reassembly. **No extensions are offered** -- no `permessage-deflate`
-- there is no server role, and frame and message sizes are capped. Forcing every
embedder to take a `websockets` dependency for an alternate transport is the
worse trade (design section 8.1).

The upgrade is an HTTP/1.1 request, so it is formatted and parsed by
`transport/http.py`. One HTTP parser exists in this package and both users share
it.

**A WebSocket message is not an apphost frame.** Verified against `furry-bolt`
this session: the node's first two binary frames on `astral.binary.v1` carry one
byte (`0x19`) and then 25 bytes (`mod.apphost.host_info_msg`) -- the length
prefix and the type name of a single apphost frame, split across two WebSocket
messages. astral-go's `BinarySender.Send` issues **four** `Write` calls per frame
-- `String8.WriteTo` writes the length byte and then the name, `Bytes32.WriteTo`
the length and then the payload (`astral/channel/binary_sender.go`,
`astral/string_types.go:21`, `astral/byte_types.go:160`) -- and
`websocket.NetConn` maps one `Write` to one message. Frame boundaries therefore
carry no information whatsoever. `WebSocketByteTransport` concatenates every
binary payload into one byte stream and never treats a message boundary as a
record boundary.

The byte transport holds the stack's one read buffer above the socket, and
`BinaryChannel.detach()` hands back this same object, so the channel ->
raw-stream handover strands nothing (design section 3.2, rule 1). Each `write()`
becomes exactly one masked frame issued in exactly one underlying `write()`, so
cancellation cannot land mid-frame and no write lock is needed (rule 2).

Two subprotocols exist on the node (`astrald/mod/apphost/src/ws_server.go`):

| Subprotocol | Frames | Carrier |
|---|---|---|
| `astral.binary.v1` | binary | the `string8(type) ++ bytes32(payload)` byte stream |
| `astral.json.v1` | text | one `{"Type":…,"Object":…}` envelope per frame |

`open_websocket()` negotiates the binary one and returns a `Transport`, so
`session.py` needs no change: WS-binary is a byte stream like any other. The JSON
subprotocol is message-oriented and has no byte stream underneath, so it is
served by `WebSocketClient` directly and framed by a `Channel` (design section
3.1). Auth on both is **in-protocol** -- `auth_token_msg`, not an HTTP header --
so no token reaches this module.

What the transport cannot do: `write_eof()` raises. WebSocket has no half-close;
the only "no more from me" it has is a Close frame, which ends both directions.
An op that reads its input to EOF rather than to an `eos` is therefore
unreachable over WebSocket, and says so rather than hanging.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import enum
import hashlib
import os
import ssl as _ssl
from dataclasses import dataclass
from typing import Final, Mapping, NoReturn, Sequence

from ..errors import ConcurrentRead, NodeUnavailable, TransportError, TransportUnsupported
from .base import IncompleteRead, Transport
from .http import (
    ResponseHead,
    format_request,
    open_web_connection,
    parse_web_endpoint,
    read_response_head,
)

__all__ = [
    "CloseCode",
    "DEFAULT_WS_PATH",
    "Frame",
    "MAX_FRAME_SIZE",
    "MAX_MESSAGE_SIZE",
    "Message",
    "Opcode",
    "SUBPROTOCOL_BINARY",
    "SUBPROTOCOL_JSON",
    "WebSocketByteTransport",
    "WebSocketClient",
    "connect_websocket",
    "open_websocket",
]

_GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
"""RFC 6455 section 1.3. The constant the accept token is derived with."""

SUBPROTOCOL_BINARY: Final = "astral.binary.v1"
SUBPROTOCOL_JSON: Final = "astral.json.v1"
DEFAULT_WS_PATH: Final = "/.ws"

MAX_FRAME_SIZE: Final = 16 * 1024 * 1024
"""Cap on one frame's payload. Nothing the apphost protocol sends approaches it;
a larger declared length is a desynchronised stream, not a large object."""

MAX_MESSAGE_SIZE: Final = 16 * 1024 * 1024
"""Cap on one reassembled message. A peer can otherwise spend this process's
memory one continuation frame at a time, with every frame inside the frame cap."""

MAX_MESSAGE_FRAGMENTS: Final = 4096
"""Cap on how many frames one message may be cut into.

The byte cap alone does not bound the reassembly, because a fragment costs heap
whatever its payload weighs: a `bytes` object of one byte is about 34 bytes of
header plus a list slot, so a peer sending one-byte continuations spends roughly
14 bytes of this process per 3 bytes of wire, and a peer sending **zero**-byte
continuations adds nothing to `size` at all and can fragment for ever. Measured:
400,000 one-byte frames are 1.2 MB on the wire and 16.9 MB of heap, and 200,000
zero-byte frames trip nothing.

4096 is far above anything the protocol produces -- astrald's sender writes a
whole apphost frame in three `Write` calls and astral-go's writes one -- and far
below the point where the accounting matters."""

_MAX_CONTROL_PAYLOAD: Final = 125
_CONNECT_TIMEOUT: Final = 5.0

CLOSE_FRAME_TIMEOUT: Final = 2.0
"""How long a close waits for its courtesy Close frame to reach the peer.

The frame is a courtesy; the descriptor is the resource. `send_close` ends in
`Transport.drain()`, which waits for the send buffer to fall under the
high-water mark and has no bound of its own, so against a peer that accepted
the connection and stopped reading it never returns -- and the bounded
`Transport.aclose()` underneath, the call that actually releases the
descriptor, is never reached. Measured on this tree before the bound existed:
`WebSocketClient.aclose()` still blocked after 10.0 s with 64,553,856 bytes
queued, `closed` false and two descriptors held, against 2.01 s and a released
descriptor for the same peer over a plain `StreamTransport`. Each pinned
connection is one of astrald's 32 apphost workers (design section 3.9, bug
G-13).

`transport/socket.py`'s `CLOSE_TIMEOUT` in value and in reasoning: the
alternative to a bounded wait is not a tidier close but an unbounded one. Held
separately because it bounds a different thing -- a WebSocket control frame,
not the socket flush that follows it -- and a close that hit both waits at most
for their sum."""


class Opcode(enum.IntEnum):
    """RFC 6455 section 5.2. Every other value is a protocol error."""

    CONT = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

    @property
    def is_control(self) -> bool:
        return self >= 0x8


class CloseCode(enum.IntEnum):
    """The close codes this client sends. RFC 6455 section 7.4.1."""

    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    TOO_BIG = 1009


def _is_wire_close_code(code: int) -> bool:
    """Whether a close code may appear on the wire, so it may be echoed back."""
    return 1000 <= code <= 1003 or 1007 <= code <= 1011 or 3000 <= code <= 4999


@dataclass(frozen=True, slots=True)
class Frame:
    """One frame, unmasked and validated."""

    fin: bool
    opcode: Opcode
    payload: bytes


@dataclass(frozen=True, slots=True)
class Message:
    """One reassembled message. A text message is valid UTF-8 by construction."""

    opcode: Opcode
    data: bytes

    @property
    def is_text(self) -> bool:
        return self.opcode is Opcode.TEXT

    @property
    def text(self) -> str:
        return self.data.decode("utf-8")


def _mask(payload: bytes, key: bytes) -> bytes:
    """XOR a payload with a 4-byte key, as RFC 6455 section 5.3 defines it.

    One big-integer XOR rather than a per-byte loop: the operation runs in C and
    the raw stream after an accepted query is the whole of an object's bytes.
    """
    size = len(payload)
    if not size:
        return b""
    repeated = (key * (size // 4 + 1))[:size]
    return (
        int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")
    ).to_bytes(size, "big")


class WebSocketClient:
    """A client-side WebSocket over any `Transport`.

    Message-oriented: `receive()` reassembles fragments, `send_binary()` and
    `send_text()` each issue one unfragmented frame. Control frames are handled
    inside the read path -- a ping is answered with a pong carrying the same
    payload, a pong is discarded, a close is echoed and then ends the stream with
    `EOFError`.

    Every protocol violation the peer commits closes the connection with the
    close code RFC 6455 assigns and raises `TransportError`. There is no
    resynchronisation: a stream whose framing is wrong cannot be trusted about
    where the next frame starts.
    """

    __slots__ = (
        "_transport",
        "_endpoint",
        "_subprotocol",
        "max_frame_size",
        "max_message_size",
        "max_message_fragments",
        "_ended",
        "_fault",
        "_close_sent",
        "_close_code",
        "_close_reason",
        "_reading",
        "_mid_frame",
        "_mid_message",
        "pings_answered",
        "last_pong",
    )

    def __init__(
        self,
        transport: Transport,
        *,
        endpoint: str | None = None,
        subprotocol: str = "",
        max_frame_size: int = MAX_FRAME_SIZE,
        max_message_size: int = MAX_MESSAGE_SIZE,
        max_message_fragments: int = MAX_MESSAGE_FRAGMENTS,
    ) -> None:
        self._transport = transport
        self._endpoint = endpoint if endpoint is not None else transport.endpoint
        self._subprotocol = subprotocol
        self.max_frame_size = max_frame_size
        self.max_message_size = max_message_size
        self.max_message_fragments = max_message_fragments
        self._ended = False
        self._fault: TransportError | None = None
        self._close_sent = False
        self._close_code: int | None = None
        self._close_reason = ""
        self._reading = False
        # Whether a frame is half-read: its header has left the transport and
        # its payload has not. `BinaryChannel._mid_frame` is the same fact one
        # layer up about a different framing, and the two are independent --
        # this one goes true before the channel above has been handed a single
        # byte, which is exactly the window in which the channel's answer alone
        # was wrong.
        self._mid_frame = False
        # The same fact for the reassembler: whether whole frames of a
        # fragmented message have been taken off the wire and dropped. Only
        # `receive()` fragments, so this stays false on the byte-stream leg.
        self._mid_message = False
        # Two counters rather than a queue: a keepalive needs to know its pong
        # came back, and an unbounded log of them is a leak on a connection that
        # runs for months.
        self.pings_answered = 0
        self.last_pong: bytes | None = None

    # --- construction ---

    @classmethod
    async def over(
        cls,
        transport: Transport,
        *,
        endpoint: str,
        path: str = DEFAULT_WS_PATH,
        authority: str = "",
        subprotocols: Sequence[str] = (SUBPROTOCOL_BINARY,),
        origin: str | None = None,
        headers: Mapping[str, str] | None = None,
        max_frame_size: int = MAX_FRAME_SIZE,
        max_message_size: int = MAX_MESSAGE_SIZE,
    ) -> "WebSocketClient":
        """Run the client handshake over a transport the caller already holds.

        The transport belongs to the caller until this returns; on failure it is
        closed here, because a handshake that did not complete hands nothing
        back.

        `Sec-WebSocket-Key` is 16 bytes from `os.urandom`, and the reply's
        `Sec-WebSocket-Accept` is checked against it. The check is not
        ceremonial: it is what proves the peer is a WebSocket server and not a
        cache, a proxy or an HTTP endpoint that answered 101 by accident.
        """
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request: dict[str, str] = {
            "Host": authority or endpoint,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
        }
        if subprotocols:
            request["Sec-WebSocket-Protocol"] = ", ".join(subprotocols)
        if origin is not None:
            request["Origin"] = origin
        request.update(headers or {})
        try:
            transport.write(format_request("GET", path, request))
            await transport.drain()
            head = await read_response_head(transport)
            negotiated = _validate_upgrade(head, key, subprotocols, endpoint)
        except BaseException:
            await transport.aclose()
            raise
        return cls(
            transport,
            endpoint=endpoint,
            subprotocol=negotiated,
            max_frame_size=max_frame_size,
            max_message_size=max_message_size,
        )

    # --- state ---

    @property
    def transport(self) -> Transport:
        """The byte stream underneath. The one buffer in the stack."""
        return self._transport

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def subprotocol(self) -> str:
        """The negotiated subprotocol, or `""` when the server named none."""
        return self._subprotocol

    @property
    def closed(self) -> bool:
        """Whether the connection is gone, descriptor included."""
        return self._transport.closed

    @property
    def ended(self) -> bool:
        """Whether no further message can arrive: a close was seen or sent."""
        return self._ended

    @property
    def at_frame_boundary(self) -> bool:
        """Whether the reader sits between frames rather than inside one.

        `Channel.at_frame_boundary`'s question, asked of the WebSocket framing
        rather than of the apphost framing above it, and both answers are needed
        because the two frames are unrelated. `_read_frame` consumes a two-byte
        header and then awaits the payload; a deadline or a cancellation landing
        between them leaves half a frame on the wire, and the *next* read then
        parses that payload's first two bytes as a frame header -- so the peer's
        data, not its framing, chooses where the next message starts. That is
        the forgery `session.py:_recv` and `conn.py:receive` close a connection
        to prevent, and before this property existed they could not see it:
        `BinaryChannel` had been handed no byte, so it answered `True`.
        Measured: a peer sends `\\x82\\x0512345REALDATA` header-first, a 0.5 s
        deadline expires between the two halves, the channel reports
        `at_frame_boundary = True`, and the next transport read answers
        `b'12345'` -- a message boundary the peer never sent.

        The carrier's own answer is conjoined, because a transport that strands
        bytes inside `readexactly` strands them for this framing too.
        """
        return (
            not self._mid_frame
            and not self._mid_message
            and self._transport.at_frame_boundary
        )

    @property
    def close_code(self) -> int | None:
        """The code the peer closed with, or `None` while it has not.

        A Close frame with no payload records `1000`: RFC 6455 section 5.5.1
        makes the code optional and defines its absence as a normal closure.
        """
        return self._close_code

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def __repr__(self) -> str:
        state = "closed" if self.closed else ("ended" if self._ended else "open")
        return f"WebSocketClient({self._endpoint!r}, {self._subprotocol!r}, {state})"

    # --- receiving ---

    async def receive(self) -> Message:
        """One reassembled message.

        Raises `EOFError` at a clean end of stream -- the peer's Close frame, or
        its departure at a frame boundary -- and `TransportError` for a framing
        or protocol fault.
        """
        fragments: list[bytes] = []
        try:
            return await self._reassemble(fragments)
        except BaseException:
            # Whole frames taken off the wire and dropped with the local list.
            # The next `receive()` would meet a continuation frame with nothing
            # to continue, so the message stream is out of step exactly as the
            # frame stream is when a payload is abandoned.
            if fragments:
                self._mid_message = True
            raise

    async def _reassemble(self, fragments: list[bytes]) -> Message:
        """`receive`'s loop, with the fragment list owned by the caller."""
        opcode: Opcode | None = None
        size = 0
        while True:
            frame = await self.receive_frame()
            if frame.opcode is Opcode.CONT:
                if opcode is None:
                    await self._fail(
                        CloseCode.PROTOCOL_ERROR, "a continuation frame began a message"
                    )
            elif opcode is not None:
                await self._fail(
                    CloseCode.PROTOCOL_ERROR, "a data frame interrupted a fragmented message"
                )
            else:
                opcode = frame.opcode
            size += len(frame.payload)
            if size > self.max_message_size:
                await self._fail(
                    CloseCode.TOO_BIG,
                    f"message exceeds {self.max_message_size} bytes",
                )
            fragments.append(frame.payload)
            # Counted as well as weighed: a fragment costs heap whatever its
            # payload weighs, so the byte cap bounds a large message and this
            # bounds a finely-cut one. See MAX_MESSAGE_FRAGMENTS.
            if len(fragments) > self.max_message_fragments:
                await self._fail(
                    CloseCode.TOO_BIG,
                    f"message exceeds {self.max_message_fragments} fragments",
                )
            if not frame.fin:
                continue
            data = b"".join(fragments)
            assert opcode is not None
            if opcode is Opcode.TEXT:
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    await self._fail(
                        CloseCode.INVALID_PAYLOAD, "a text message is not valid utf-8"
                    )
            return Message(opcode, data)

    async def receive_text(self) -> str:
        """The next text message. Binary messages are dropped.

        Dropping rather than raising is the `astral.json.v1` contract: the
        subprotocol is text-only and a binary frame on it carries nothing this
        client can read (design section 3.1).
        """
        while True:
            message = await self.receive()
            if message.is_text:
                return message.text

    async def receive_frame(self) -> Frame:
        """The next `TEXT`, `BINARY` or `CONT` frame. Control frames are served here.

        One reader at a time, at frame granularity: a second concurrent reader
        raises `ConcurrentRead` rather than taking half of the first one's frame.
        Two readers that alternate whole frames of one fragmented message still
        break that message, and the reassembler says so -- there is no
        multiplexing on this leg and none is simulated.
        """
        if self._reading:
            raise ConcurrentRead(
                f"{self._endpoint}: a second read on one websocket splits its frames"
            )
        self._reading = True
        try:
            while True:
                frame = await self._read_frame()
                match frame.opcode:
                    case Opcode.PING:
                        await self.send_frame(Opcode.PONG, frame.payload)
                        self.pings_answered += 1
                    case Opcode.PONG:
                        self.last_pong = frame.payload
                    case Opcode.CLOSE:
                        await self._on_close(frame.payload)
                    case _:
                        return frame
        finally:
            self._reading = False

    async def _read_frame(self) -> Frame:
        """One frame off the wire, validated against everything we never offered.

        **A read abandoned inside a frame latches a fault**, exactly as a framing
        violation does, and for the same reason: what follows the abandoned
        payload is not the next frame's header, so there is nothing left to
        resynchronise to. `at_frame_boundary` reports the same fact to whoever
        asks, which is how a channel above closes the connection rather than
        reading on; the latch is what protects a reader that has no channel above
        it -- the raw byte stream of an accepted query -- where nothing asks.

        A read abandoned **at** a boundary strands nothing and latches nothing:
        `readexactly` consumes its buffer only once the whole request is present,
        so the two header bytes are either taken together or not at all. That is
        what keeps an idle follow stream's deadline harmless over this carrier
        as much as over a socket.
        """
        if self._fault is not None:
            # Before the `_ended` branch, which would report the symptom -- a
            # stream that has ended -- in place of the cause.
            raise self._fault
        if self._ended:
            raise EOFError(f"{self._endpoint}: the websocket has ended")
        try:
            return await self._read_frame_body()
        except BaseException:
            if self._mid_frame and self._fault is None:
                # No I/O on this path: it runs inside an exception unwind, and a
                # cancellation unwind cannot await. The connection is closed by
                # whoever handles the fault -- `Session._recv` and
                # `QueryStream.receive` already do -- and every later read here
                # raises rather than framing the peer's payload as a header.
                self._fault = TransportError(
                    f"{self._endpoint}: a read was abandoned between a frame's "
                    "header and its payload, so the rest of that frame is still "
                    "on the wire and the next read would take its first two "
                    "bytes for a frame header"
                )
            raise

    async def _read_frame_body(self) -> Frame:
        """`_read_frame` without the boundary bookkeeping around it."""
        head = await self._transport.readexactly(2)
        # Two bytes of this frame have left the transport and cannot be put back.
        self._mid_frame = True
        first, second = head[0], head[1]
        if first & 0x70:
            await self._fail(
                CloseCode.PROTOCOL_ERROR,
                "a reserved bit is set and no extension was negotiated",
            )
        try:
            opcode = Opcode(first & 0x0F)
        except ValueError:
            await self._fail(CloseCode.PROTOCOL_ERROR, f"unknown opcode 0x{first & 0x0F:x}")
        fin = bool(first & 0x80)
        length = second & 0x7F
        if length == 126:
            length = int.from_bytes(await self._transport.readexactly(2), "big")
            if length < 126:
                await self._fail(
                    CloseCode.PROTOCOL_ERROR, f"length {length} is not minimally encoded"
                )
        elif length == 127:
            length = int.from_bytes(await self._transport.readexactly(8), "big")
            if length < 65536 or length >> 63:
                await self._fail(
                    CloseCode.PROTOCOL_ERROR, f"length {length} is not minimally encoded"
                )
        if second & 0x80:
            # RFC 6455 section 5.1: a server frame is never masked, and a client
            # that accepted one would accept a proxy's rewrite of the stream.
            await self._fail(CloseCode.PROTOCOL_ERROR, "a server frame must not be masked")
        if opcode.is_control:
            if not fin:
                await self._fail(
                    CloseCode.PROTOCOL_ERROR, "a control frame must not be fragmented"
                )
            if length > _MAX_CONTROL_PAYLOAD:
                await self._fail(
                    CloseCode.PROTOCOL_ERROR,
                    f"a control frame carries {length} bytes, over {_MAX_CONTROL_PAYLOAD}",
                )
        if length > self.max_frame_size:
            await self._fail(
                CloseCode.TOO_BIG, f"frame declares {length} bytes, over {self.max_frame_size}"
            )
        payload = await self._transport.readexactly(length) if length else b""
        # Back at a boundary: every byte this frame declared has been taken.
        self._mid_frame = False
        return Frame(fin, opcode, payload)

    async def _on_close(self, payload: bytes) -> NoReturn:
        """Record the peer's close, echo it, end the stream.

        RFC 6455 section 5.5.1: the endpoint that receives a Close sends one back
        and then closes. The echo carries the peer's own code when that code may
        appear on the wire, and `1002` when it may not, because a code the peer
        invented is a framing fault and not a reason.
        """
        if len(payload) == 1:
            await self._fail(CloseCode.PROTOCOL_ERROR, "a close frame carries one byte")
        code = int.from_bytes(payload[:2], "big") if payload else CloseCode.NORMAL
        self._close_code = code
        self._close_reason = payload[2:].decode("utf-8", "replace")
        self._ended = True
        await self._close_bounded(
            code if _is_wire_close_code(code) else CloseCode.PROTOCOL_ERROR
        )
        raise EOFError(f"{self._endpoint}: the peer closed with {code} {self._close_reason!r}")

    async def _fail(self, code: CloseCode, message: str) -> NoReturn:
        """Close with `code` and raise. The connection is not resynchronised.

        The fault **latches**. Ending the stream without keeping it told the
        first reader the framing was violated and every later reader that the
        peer had finished normally: `_read_frame` turned `_ended` into
        `EOFError`, and `WebSocketByteTransport._fill` turns `EOFError` into
        `read()` answering `b""`, which is the transport seam's spelling of a
        clean end of stream. A violated connection has to report the violation
        to whoever asks, exactly as `CanonicalChannel` and `LineChannel` re-raise
        their own stored error rather than reporting EOF.
        """
        self._ended = True
        fault = TransportError(f"{self._endpoint}: {message}")
        self._fault = fault
        await self._close_bounded(code, message[: _MAX_CONTROL_PAYLOAD - 8])
        raise fault

    async def _close_bounded(self, code: int, reason: str = "") -> None:
        """The courtesy Close frame, bounded; then the transport, always.

        The one close path of this class, so the ordering cannot be got wrong in
        one of the three places that need it. Two rules, and both were broken
        before it existed:

        - the Close frame is bounded at `CLOSE_FRAME_TIMEOUT`, because
          `send_close` ends in an unbounded `drain()` and a peer that stopped
          reading would otherwise hold the descriptor for as long as it liked;
        - the transport close runs in a `finally`, because `contextlib.suppress`
          does not catch a `CancelledError` and a cancellation landing in the
          courtesy frame skipped the only call that releases anything.

        `Transport.aclose()` is itself bounded and aborts what it cannot flush,
        so this returns in `CLOSE_FRAME_TIMEOUT + CLOSE_TIMEOUT` at worst
        whatever the peer does.
        """
        try:
            if not self._close_sent and not self._transport.closed:
                # `suppress` outside the timeout: an expiry arrives as
                # `TimeoutError`, which is an `Exception` and is swallowed here,
                # while a cancellation aimed at the caller stays a
                # `CancelledError` and leaves through the `finally`.
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(CLOSE_FRAME_TIMEOUT):
                        await self.send_close(code, reason)
        finally:
            await self._transport.aclose()

    # --- sending ---

    def write_frame(self, opcode: Opcode, payload: bytes = b"") -> None:
        """Serialise one masked frame and issue exactly one `Transport.write()`.

        Synchronous, so a caller that must not await between frames does not.
        The mask is four fresh bytes from `os.urandom` per frame, as RFC 6455
        section 5.3 requires of every client frame.
        """
        if self._close_sent and opcode is not Opcode.CLOSE:
            raise ConnectionResetError(f"{self._endpoint}: the websocket is closed")
        size = len(payload)
        header = bytearray()
        header.append(0x80 | int(opcode))
        if size < 126:
            header.append(0x80 | size)
        elif size < 65536:
            header.append(0x80 | 126)
            header += size.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += size.to_bytes(8, "big")
        key = os.urandom(4)
        header += key
        self._transport.write(bytes(header) + _mask(payload, key))

    async def send_frame(self, opcode: Opcode, payload: bytes = b"") -> None:
        """One frame, then the back-pressure wait."""
        self.write_frame(opcode, payload)
        await self._transport.drain()

    async def send_binary(self, data: bytes) -> None:
        await self.send_frame(Opcode.BINARY, data)

    async def send_text(self, text: str) -> None:
        await self.send_frame(Opcode.TEXT, text.encode("utf-8"))

    async def ping(self, data: bytes = b"") -> None:
        """A ping. The pong that answers it is consumed by the read path."""
        await self.send_frame(Opcode.PING, data[:_MAX_CONTROL_PAYLOAD])

    async def send_close(self, code: int = CloseCode.NORMAL, reason: str = "") -> None:
        """One Close frame. Further sends raise; further reads drain to `EOFError`."""
        payload = code.to_bytes(2, "big") + reason.encode("utf-8")[: _MAX_CONTROL_PAYLOAD - 2]
        self._close_sent = True
        self.write_frame(Opcode.CLOSE, payload)
        await self._transport.drain()

    async def aclose(self, code: int = CloseCode.NORMAL, reason: str = "") -> None:
        """Send a Close, then close the connection. Idempotent, never raises.

        The peer's Close echo is **not** waited for. RFC 6455 section 7.1.1
        permits closing the connection without it, and a wait would be unbounded
        against a peer that is still streaming: the alternative to closing now is
        not a tidier close but a descriptor held open by whatever the peer does
        next.

        Returns only once the connection is gone, for a second concurrent caller
        as much as for the first -- the promise is the underlying transport's and
        is inherited by delegating to it rather than by guarding around it.

        **The Close frame is bounded and the transport close is unconditional.**
        The courtesy frame ends in an unbounded `drain()`, so ordering it ahead
        of the release without a bound handed a deaf peer the descriptor for
        ever -- measured at 10 s and counting where a plain socket released in
        2.01 s. `_close_bounded` holds that ordering for all three close paths.
        """
        self._ended = True
        await self._close_bounded(code, reason)

    async def __aenter__(self) -> "WebSocketClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self.aclose()


def _validate_upgrade(
    head: ResponseHead, key: str, subprotocols: Sequence[str], endpoint: str
) -> str:
    """Check a `101 Switching Protocols` reply, and return the subprotocol.

    Header lookup is case-insensitive because Go answers `Sec-Websocket-Accept`
    where RFC 6455 writes `Sec-WebSocket-Accept` -- verified against `furry-bolt`.
    An extension in the reply is refused: none was offered, and a client that
    ignored one would decode frames a `permessage-deflate` peer never sent.
    """
    if head.status != 101:
        raise TransportError(
            f"{endpoint}: the upgrade was refused with HTTP {head.status} "
            f"{head.reason!r} -- the node serves the upgrade at {DEFAULT_WS_PATH} "
            "and answers 401 on every other path"
        )
    if head.headers.get("Upgrade", "").lower() != "websocket":
        raise TransportError(f"{endpoint}: the reply does not upgrade to websocket")
    if "upgrade" not in head.headers.tokens("Connection"):
        raise TransportError(f"{endpoint}: the reply's Connection header is not Upgrade")
    expected = base64.b64encode(
        hashlib.sha1((key + _GUID).encode("ascii")).digest()
    ).decode("ascii")
    if head.headers.get("Sec-WebSocket-Accept", "") != expected:
        raise TransportError(
            f"{endpoint}: Sec-WebSocket-Accept does not match the key sent -- the "
            "peer is not a websocket server"
        )
    if head.headers.get("Sec-WebSocket-Extensions", "").strip():
        raise TransportError(
            f"{endpoint}: the peer negotiated extension "
            f"{head.headers['Sec-WebSocket-Extensions']!r}, and none was offered"
        )
    negotiated = head.headers.get("Sec-WebSocket-Protocol", "").strip()
    if negotiated and negotiated not in subprotocols:
        raise TransportError(
            f"{endpoint}: the peer chose subprotocol {negotiated!r}, which was not offered"
        )
    return negotiated


class WebSocketByteTransport(Transport):
    """The `astral.binary.v1` byte stream: binary payloads, concatenated.

    A `Transport` and nothing more, so `session.py` reaches a node over
    WebSocket with no knowledge that it did. Message boundaries are discarded on
    receive, because the node's are an artefact of astral-go's three-`Write`
    sender and carry no meaning; each `write()` is one frame, because that is the
    cheapest framing that keeps rule 2.

    Text frames are dropped: this subprotocol carries binary, and a text frame on
    it is a peer speaking the other one.
    """

    __slots__ = ("_ws", "_buf", "_eof")

    def __init__(self, ws: WebSocketClient) -> None:
        self._ws = ws
        self._buf = bytearray()
        self._eof = False

    @property
    def websocket(self) -> WebSocketClient:
        return self._ws

    @property
    def endpoint(self) -> str:
        return self._ws.endpoint

    @property
    def closed(self) -> bool:
        return self._ws.closed

    @property
    def buffered(self) -> int:
        """Bytes taken off frames and not yet handed to a reader."""
        return len(self._buf)

    @property
    def at_frame_boundary(self) -> bool:
        """The WebSocket framing's boundary fact, for the layers above.

        A byte stream over a framed carrier has a boundary of its own, and this
        is the one place that knows it. Nothing this transport buffers is ever
        stranded -- `_buf` survives a cancelled read, and `readexactly` takes
        from it only once the whole request is present -- so the answer is
        entirely the WebSocket client's.
        """
        return self._ws.at_frame_boundary

    async def readexactly(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"negative read length {n}")
        if n == 0:
            return b""
        while len(self._buf) < n:
            if not await self._fill():
                if not self._buf:
                    raise EOFError("stream closed")
                partial = bytes(self._buf)
                self._buf.clear()
                raise IncompleteRead(partial, n)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        if n < 0:
            while await self._fill():
                pass
            out = bytes(self._buf)
            self._buf.clear()
            return out
        while not self._buf:
            if not await self._fill():
                return b""
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def _fill(self) -> bool:
        """Take one more frame's payload. False at end of stream.

        Frame granularity rather than message granularity: a message here is
        whatever the sender's last `Write` happened to be, so waiting for a FIN
        would stall a byte stream that is complete without one.
        """
        while not self._eof:
            try:
                frame = await self._ws.receive_frame()
            except EOFError:
                self._eof = True
                return False
            if frame.opcode is Opcode.TEXT:
                continue
            if frame.payload:
                self._buf += frame.payload
                return True
        return False

    def write(self, data: bytes) -> None:
        """One binary frame. An empty write sends nothing.

        A zero-length frame is legal and pointless: the byte stream it carries is
        empty, and sending one would put a message on the wire that says nothing.
        """
        if not data:
            return
        self._ws.write_frame(Opcode.BINARY, bytes(data))

    async def drain(self) -> None:
        await self._ws.transport.drain()

    def write_eof(self) -> None:
        """Refused: WebSocket has no half-close.

        The only end-of-send WebSocket has is a Close frame, and a Close ends
        both directions -- the peer stops reading and stops writing. An op whose
        input ends at EOF rather than at an `eos` is therefore unreachable over
        this transport, and hearing so is better than a stream that never
        answers.
        """
        raise TransportUnsupported(
            f"{self.endpoint}: websocket has no half-close -- a close frame ends "
            "both directions, so an op that reads its input to EOF needs the ipc "
            "transport"
        )

    async def aclose(self) -> None:
        await self._ws.aclose()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"WebSocketByteTransport({self.endpoint!r}, {state})"


# --- dialing --------------------------------------------------------------


async def connect_websocket(
    endpoint: str,
    *,
    subprotocols: Sequence[str] = (SUBPROTOCOL_BINARY,),
    timeout: float | None = _CONNECT_TIMEOUT,
    origin: str | None = None,
    headers: Mapping[str, str] | None = None,
    ssl_context: _ssl.SSLContext | None = None,
    max_frame_size: int = MAX_FRAME_SIZE,
    max_message_size: int = MAX_MESSAGE_SIZE,
) -> WebSocketClient:
    """Dial a `ws:`/`wss:` endpoint and complete the upgrade.

    `timeout` covers the connect **and** the upgrade: a peer that accepts the
    socket and never answers the request is the same failure as one that never
    accepted it, and both must be bounded.

    A connect fault is `NodeUnavailable` -- nothing was sent, so a retry is safe.
    A refused or malformed upgrade is `TransportError`: the peer answered, and
    answering the same way again is all a retry would achieve.
    """
    address = parse_web_endpoint(endpoint, default_path=DEFAULT_WS_PATH)
    opened: Transport | None = None
    try:
        async with asyncio.timeout(timeout):
            try:
                opened = await open_web_connection(address, endpoint, ssl_context)
            except OSError as exc:
                raise NodeUnavailable(f"{endpoint}: {exc}") from exc
            client = await WebSocketClient.over(
                opened,
                endpoint=endpoint,
                path=address.path,
                authority=address.authority,
                subprotocols=subprotocols,
                origin=origin,
                headers=headers,
                max_frame_size=max_frame_size,
                max_message_size=max_message_size,
            )
            # `over` owns the transport from here: it closed it itself on every
            # failure path, and on success the client holds it.
            opened = None
            return client
    except TimeoutError as exc:
        raise NodeUnavailable(
            f"{endpoint}: no upgrade within {timeout}s"
        ) from exc
    except EOFError as exc:
        raise TransportError(f"{endpoint}: closed during the upgrade") from exc
    finally:
        if opened is not None:
            await opened.aclose()


async def open_websocket(
    endpoint: str,
    *,
    subprotocols: Sequence[str] = (SUBPROTOCOL_BINARY,),
    timeout: float | None = _CONNECT_TIMEOUT,
    origin: str | None = None,
    headers: Mapping[str, str] | None = None,
    ssl_context: _ssl.SSLContext | None = None,
    max_frame_size: int = MAX_FRAME_SIZE,
) -> WebSocketByteTransport:
    """Dial a `ws:`/`wss:` endpoint as a byte stream. What `dial()` calls.

    `astral.binary.v1` is what is offered by default, because a byte stream is
    what a `Transport` is. A caller may offer more -- to learn what a peer
    speaks -- and a peer that then picks `astral.json.v1` is refused with
    `TransportUnsupported` rather than silently handed to a binary framer: one
    json envelope per text frame has no byte stream underneath it. A peer that
    names a subprotocol nobody offered is refused one layer earlier, by the
    handshake, as RFC 6455 section 4.1 requires.
    """
    client = await connect_websocket(
        endpoint,
        subprotocols=subprotocols,
        timeout=timeout,
        origin=origin,
        headers=headers,
        ssl_context=ssl_context,
        max_frame_size=max_frame_size,
    )
    if client.subprotocol not in ("", SUBPROTOCOL_BINARY):
        await client.aclose(CloseCode.PROTOCOL_ERROR, "binary subprotocol required")
        raise TransportUnsupported(
            f"{endpoint}: the peer negotiated {client.subprotocol!r}, which frames "
            f"one json envelope per text frame and has no byte stream underneath; "
            f"{SUBPROTOCOL_BINARY} is what a Transport carries"
        )
    return WebSocketByteTransport(client)
