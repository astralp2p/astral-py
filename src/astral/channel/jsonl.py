"""The JSON channels: one `{"Type","Object"}` envelope per line, and per WS frame.

Two channels, one encoding:

| Channel | Carrier | Framing |
|---|---|---|
| `JSONLinesChannel` | a byte transport | one envelope per newline-terminated line |
| `WebSocketJSONChannel` | a message stream | one envelope per **text** frame, newline included |

The encoding is `codec.jsoncodec`'s and nothing here re-derives it. What the
node writes, verified against `furry-bolt` this session:

```
apphost.whoami?out=json   {"Type":"identity","Object":"03b27049…ae1"}\n
dir.alias_map?out=json    {"Type":"mod.dir.alias_map","Object":{"Aliases":{…}}}\n
dir.filters?out=json      five string8 lines, then {"Type":"eos","Object":null}\n
```

`eos` is an ordinary object in this framing, so a JSON stream terminates exactly
as a binary one does -- on `eos` or on EOF, per op (astral-docs bug D-23).

Two objects this channel refuses to send, both of which astral-go sends and its
own receiver then cannot read:

- **An untyped blob.** The envelope is the only thing naming a type, so
  `{"Type":""}` names none. astral-go's `JSONSender` writes it and its
  `JSONReceiver` answers `stream corrupted: blueprint not found:` on the same
  line. `jsoncodec.envelope` raises instead.
- **An `UnparsedObject`.** astral-go rejects it explicitly ("cannot send
  unparsed objects over JSON"); here `UnparsedObject.json()` raises, which is
  the same refusal one layer down.

`astral.json.v1` is astrald's WebSocket subprotocol and its framing is pinned by
`mod/apphost/src/ws_conn.go`: writes are re-framed on newlines so that **each
newline-terminated line becomes exactly one text frame**, terminator included.
Its read side is a byte stream across frames, so it accepts any chunking; this
one accepts a frame with no terminator as a whole line, because the subprotocol
promises one envelope per frame. Binary frames on that subprotocol are dropped,
counted in `dropped_binary`.
"""

from __future__ import annotations

from typing import Any, ClassVar, Protocol

from ..codec import jsoncodec
from ..errors import StreamCorrupted, TransportUnsupported
from ..registry import Blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC
from . import Format
from .lines import NEWLINE, LineChannel

__all__ = [
    "JSONLinesChannel",
    "Message",
    "MessageStream",
    "WebSocketJSONChannel",
]


class JSONLinesChannel(LineChannel):
    """One JSON envelope per line, over a byte transport."""

    __slots__ = ()

    FORMAT: ClassVar[Format] = Format.JSON

    def _decode_line(self, line: str) -> Any:
        obj = jsoncodec.decode_line(line, registry=self._registry)
        if obj is None:
            # `read_envelope` maps a JSON `null` to `None`, which is how an
            # absent polymorphic **field** is spelled. A whole line is not a
            # field: nothing names a type, so there is nothing to construct.
            raise StreamCorrupted(
                "json channel: a bare `null` line names no type; an envelope is "
                '{"Type": …, "Object": …}'
            )
        return obj

    def _encode_line(self, obj: Any) -> str:
        return jsoncodec.encode_line(obj)


class Message(Protocol):
    """One reassembled WebSocket message."""

    @property
    def is_text(self) -> bool:
        """Whether the message came in a text frame."""

    @property
    def data(self) -> bytes:
        """The message payload."""


class MessageStream(Protocol):
    """A message-oriented connection: WebSocket frames, not bytes.

    The second carrier, and the reason `Channel` and `Transport` are two seams
    rather than one (design section 3.1): `astral.json.v1` has no byte stream
    underneath it, so a channel cannot be defined as a transport decorator.

    `astral.transport.websocket.WebSocketClient` is the implementation, and this
    is its shape rather than a shape of its own: `connect_websocket(endpoint,
    subprotocols=("astral.json.v1",))` returns one, and `open_websocket` refuses
    that subprotocol precisely because a `Transport` cannot carry it. The
    protocol is structural so that neither module imports the other.

    A `WebSocketByteTransport` speaking `astral.binary.v1` is a `Transport` and
    implements none of this: there, frames concatenate into one byte stream and
    the binary channel frames it.
    """

    @property
    def endpoint(self) -> str:
        """The `proto:addr` string this stream was reached at."""

    @property
    def closed(self) -> bool:
        """Whether the close has completed."""

    @property
    def at_frame_boundary(self) -> bool:
        """Whether an abandoned `receive()` stranded nothing.

        `Transport.at_frame_boundary`'s question for the message seam. A
        cancelled reassembly drops whole frames it had already taken, and a
        cancelled frame read leaves half a frame on the wire; either way the
        channel above must not treat the connection as recoverable.
        `LineChannel` reads this through `getattr` and defaults it to true, so a
        message stream that predates the property still works.
        """

    async def receive(self) -> Message:
        """One reassembled message. `EOFError` at a clean close."""

    async def send_text(self, text: str) -> None:
        """Send one text message as exactly one frame."""

    async def aclose(self) -> None:
        """Close the connection. Idempotent."""


class WebSocketJSONChannel(JSONLinesChannel):
    """`astral.json.v1`: one envelope per WebSocket text frame."""

    __slots__ = ("_messages", "_dropped_binary")

    def __init__(
        self,
        messages: MessageStream,
        *,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        allow_unparsed: bool = False,
    ) -> None:
        super().__init__(
            messages,  # type: ignore[arg-type]
            registry=registry,
            max_alloc=max_alloc,
            allow_unparsed=allow_unparsed,
        )
        self._messages = messages
        self._dropped_binary = 0

    def __repr__(self) -> str:
        return f"WebSocketJSONChannel({self._messages.endpoint!r})"

    @property
    def transport(self) -> MessageStream:  # type: ignore[override]
        """The message stream. **Not** a byte `Transport`.

        `Channel.transport` is declared as one because every other channel has
        one. This carrier does not, which is the whole reason the two seams
        exist, and it is why a session over `astral.json.v1` answers false to
        `supports_raw_stream` (design section 3.1).
        """
        return self._messages

    @property
    def dropped_binary(self) -> int:
        """Binary frames discarded. The subprotocol carries text frames only."""
        return self._dropped_binary

    def detach(self) -> Transport:
        raise TransportUnsupported(
            "astral.json.v1 channel: detach() hands over a byte stream and this "
            "carrier has none -- it is a sequence of WebSocket messages. A raw "
            "query stream needs astral.binary.v1 (design section 3.1)."
        )

    async def _read_chunk(self) -> bytes:
        """The next text frame, terminated. Binary frames are dropped.

        A frame with no terminator is a whole line: the subprotocol promises one
        envelope per frame, and a reader that instead waited for a newline would
        hold the last object of every well-formed peer that omits it.
        """
        while True:
            try:
                message = await self._messages.receive()
            except EOFError:
                return b""
            if not message.is_text:
                self._dropped_binary += 1
                continue
            payload = message.data
            if payload.endswith(NEWLINE):
                return payload
            return payload + NEWLINE

    async def _send_line(self, line: str) -> None:
        """One object as one text frame, terminator included.

        astrald's own writer keeps the terminator inside the frame
        (`ws_conn.go` writes `pending[:i+1]`), so a frame this channel sends is
        byte-identical to one the node sends.
        """
        await self._messages.send_text(line)
