"""Tier B and C: the JSON channels -- one envelope per line, one per WS frame.

Four jobs:

1. Pin the line bytes in both directions against **captures taken from
   `furry-bolt` this session**, so a pass means the node would have been
   satisfied by these exact bytes.
2. Pin the line framing's rules, which `channel/lines.py` owns and two formats
   share: a partial line is a truncation, the first fault latches, `detach()` is
   refused, and a cancelled read strands nothing.
3. Pin what this channel refuses to send. An untyped blob and an
   `UnparsedObject` both have envelopes astral-go writes and its own receiver
   then cannot read.
4. Pin `astral.json.v1`: one newline-terminated envelope per **text** frame,
   binary frames dropped.

Every async test is `bounded`.
"""

from __future__ import annotations

import asyncio
import unittest

from astral import primitives as P
from astral.channel import Format, open_channel
from astral.channel.jsonl import JSONLinesChannel, WebSocketJSONChannel
from astral.channel.lines import CHUNK
from astral.errors import (
    AllocationLimit,
    ParseError,
    SchemaError,
    StreamCorrupted,
    TransportUnsupported,
)
from astral.object import Ack, Blob, EOS, ErrorMessage, UnparsedObject
from astral.transport import MemTransport
from astral.transport.websocket import (
    Message,
    Opcode,
    WebSocketClient,
    connect_websocket,
)
from astral.types import Identity

from live_support import LiveCase
from mock_apphost import FURRY_BOLT, bounded

# The two message kinds `astral.json.v1` distinguishes.
TEXT = Opcode.TEXT
BINARY = Opcode.BINARY

# Captured from `furry-bolt` this session, byte for byte.
LIVE_WHOAMI = (
    b'{"Type":"identity","Object":"03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94'
    b'b6b54a3978df81185bd7ae1"}\n'
)
LIVE_ALIAS_MAP = (
    b'{"Type":"mod.dir.alias_map","Object":{"Aliases":{"furry-bolt":"03b270494'
    b'8bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"}}}\n'
)
LIVE_FILTERS = (
    b'{"Type":"string8","Object":"linked"}\n'
    b'{"Type":"string8","Object":"localswarm"}\n'
    b'{"Type":"string8","Object":"localuser"}\n'
    b'{"Type":"string8","Object":"all"}\n'
    b'{"Type":"string8","Object":"localnode"}\n'
    b'{"Type":"eos","Object":null}\n'
)


def channel(transport: MemTransport, **kw) -> JSONLinesChannel:  # type: ignore[no-untyped-def]
    return JSONLinesChannel(transport, **kw)


def fed(data: bytes, *, eof: bool = True, **kw) -> JSONLinesChannel:  # type: ignore[no-untyped-def]
    t = MemTransport.solo()
    t.feed(data)
    if eof:
        t.feed_eof()
    return channel(t, **kw)


class SendTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_scalar_line_matches_the_nodes_own_bytes(self):
        t = MemTransport.solo()
        await channel(t).send(FURRY_BOLT)
        self.assertEqual(t.sent, LIVE_WHOAMI)

    @bounded()
    async def test_eos_is_an_ordinary_object_with_a_null_payload(self):
        t = MemTransport.solo()
        await channel(t).send(EOS())
        self.assertEqual(t.sent, b'{"Type":"eos","Object":null}\n')

    @bounded()
    async def test_every_object_is_exactly_one_write(self):
        """Design section 3.2 rule 2. The line is serialised whole first, so
        cancellation cannot land mid-line and no write lock exists."""
        t = MemTransport.solo()
        ch = channel(t)
        for obj in (P.Uint32(1), P.String8("hi"), Ack(), EOS()):
            await ch.send(obj)
        self.assertEqual(len(t.writes), 4)
        self.assertEqual(t.writes[0], b'{"Type":"uint32","Object":1}\n')
        self.assertEqual(t.writes[2], b'{"Type":"ack","Object":null}\n')

    @bounded()
    async def test_an_untyped_blob_is_refused_rather_than_sent_unreadable(self):
        """astral-go's JSONSender writes `{"Type":""}` and its own JSONReceiver
        answers `blueprint not found:` on that line. The envelope is the only
        thing naming a type, so an untyped object has nowhere to put one."""
        t = MemTransport.solo()
        with self.assertRaises(SchemaError):
            await channel(t).send(Blob(b"raw"))
        self.assertEqual(t.writes, [])

    @bounded()
    async def test_an_unparsed_object_is_refused_and_named(self):
        t = MemTransport.solo()
        with self.assertRaises(ParseError) as caught:
            await channel(t).send(UnparsedObject("test.absent", b"\x01"))
        self.assertIn("test.absent", str(caught.exception))
        self.assertEqual(t.writes, [])

    @bounded()
    async def test_a_record_round_trips_through_its_own_line(self):
        import astral.api  # noqa: F401 -- registers mod.dir.alias_map

        left, right = MemTransport.pair()
        alias_map = await fed(LIVE_ALIAS_MAP).receive()
        await channel(left).send(alias_map)
        self.assertEqual(left.sent, LIVE_ALIAS_MAP)
        self.assertEqual(await channel(right).receive(), alias_map)


class ReceiveTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_live_whoami_line_decodes_to_the_hosts_identity(self):
        received = await fed(LIVE_WHOAMI).receive()
        self.assertIsInstance(received, Identity)
        self.assertEqual(received, FURRY_BOLT)

    @bounded()
    async def test_the_live_filter_stream_stops_at_the_eos_line(self):
        ch = fed(LIVE_FILTERS)
        seen = [obj async for obj in ch]
        self.assertEqual(
            [str(o) for o in seen],
            ["linked", "localswarm", "localuser", "all", "localnode"],
        )
        self.assertTrue(ch.saw_eos)
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_a_stream_that_ends_with_no_eos_ends_at_bare_eof(self):
        """Termination is per-op: `apphost.whoami` sends one object and closes
        (astral-docs bug D-23)."""
        ch = fed(LIVE_WHOAMI)
        seen = [obj async for obj in ch]
        self.assertEqual(seen, [FURRY_BOLT])
        self.assertFalse(ch.saw_eos)

    @bounded()
    async def test_a_line_split_across_arrivals_reassembles(self):
        t = MemTransport.solo(max_chunk=1)
        t.feed(LIVE_FILTERS)
        t.feed_eof()
        ch = channel(t)
        self.assertEqual(len([obj async for obj in ch]), 5)
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_several_lines_in_one_arrival_are_read_one_at_a_time(self):
        ch = fed(LIVE_FILTERS, eof=False)
        self.assertEqual(str(await ch.receive()), "linked")
        self.assertEqual(str(await ch.receive()), "localswarm")

    @bounded()
    async def test_a_clean_eof_between_lines_is_eof_error(self):
        ch = fed(LIVE_WHOAMI)
        await ch.receive()
        with self.assertRaises(EOFError):
            await ch.receive()
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_a_line_with_no_terminator_is_a_truncation_not_an_object(self):
        """astral-go discards it: `bufio.ReadString` returns the bytes alongside
        `io.EOF` and the receiver drops them. A truncated line can decode to a
        plausible wrong value, so it is reported here."""
        ch = fed(LIVE_WHOAMI.rstrip(b"\n"))
        with self.assertRaises(StreamCorrupted):
            await ch.receive()
        self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_an_unknown_type_ends_the_stream(self):
        ch = fed(b'{"Type":"test.absent","Object":1}\n' + LIVE_WHOAMI)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_a_bare_null_line_names_no_type(self):
        """`null` is how an absent polymorphic **field** is spelled. A whole line
        is not a field."""
        ch = fed(b"null\n")
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_malformed_json_is_a_parse_error(self):
        ch = fed(b'{"Type":"uint8"\n')
        with self.assertRaises(ParseError):
            await ch.receive()

    @bounded()
    async def test_an_error_message_object_is_data_not_an_exception(self):
        """Raising on `error_message` is `Stream`'s job, one layer up: a channel
        has no notion of a query."""
        received = await fed(b'{"Type":"error_message","Object":"nope"}\n').receive()
        self.assertEqual(received, ErrorMessage("nope"))

    @bounded()
    async def test_a_line_past_max_alloc_with_no_terminator_is_refused(self):
        """The framing gives no length to check, so the only bound is how much
        has arrived. What is buffered is a fragment of a line nothing will
        finish, which is the same standing a truncation has."""
        t = MemTransport.solo()
        t.feed(b"x" * 200)
        ch = channel(t, max_alloc=64)
        with self.assertRaises(AllocationLimit):
            await ch.receive()
        self.assertFalse(ch.at_frame_boundary)


class LatchTest(unittest.IsolatedAsyncioTestCase):
    """The first fault ends the channel, matching astral-go's JSONReceiver.

    A line framing could resynchronise -- the next newline is right there -- and
    astral-go's receiver deliberately does not: "the policy here is fail-fast:
    the first non-nil error latches and subsequent Receive() calls return it
    without touching the reader".
    """

    @bounded()
    async def test_a_fault_repeats_without_touching_the_transport(self):
        t = MemTransport.solo()
        t.feed(b'{"Type":"test.absent","Object":1}\n')
        ch = channel(t)
        with self.assertRaises(StreamCorrupted) as first:
            await ch.receive()
        # A whole line arrives after the fault and stays unread.
        t.feed(LIVE_WHOAMI)
        with self.assertRaises(StreamCorrupted) as second:
            await ch.receive()
        self.assertIs(first.exception, second.exception)
        self.assertEqual(t.buffered, len(LIVE_WHOAMI))
        self.assertTrue(ch.latched)

    @bounded()
    async def test_the_end_of_a_stream_is_latched_too(self):
        ch = fed(b"")
        with self.assertRaises(EOFError):
            await ch.receive()
        with self.assertRaises(EOFError):
            await ch.receive()

    @bounded()
    async def test_a_cancelled_read_is_not_a_fault_and_strands_nothing(self):
        """The line buffer is this channel's own, so every byte a cancelled read
        consumed is still here. That is the opposite of the binary channel, where
        an abandoned read leaves a payload on the wire."""
        t = MemTransport.solo()
        t.feed(LIVE_WHOAMI[:20])
        ch = channel(t)
        task = asyncio.ensure_future(ch.receive())
        for _ in range(4):
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(ch.latched)
        self.assertTrue(ch.at_frame_boundary)
        t.feed(LIVE_WHOAMI[20:])
        self.assertEqual(await ch.receive(), FURRY_BOLT)


class HandoverTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_detach_is_refused_because_the_channel_holds_the_bytes(self):
        ch = fed(LIVE_FILTERS, eof=False)
        await ch.receive()
        with self.assertRaises(TransportUnsupported) as caught:
            ch.detach()
        self.assertIn("json", str(caught.exception))

    @bounded()
    async def test_allow_unparsed_is_accepted_and_not_honoured(self):
        """astral-go says the same of its JSON receiver. An `UnparsedObject` is a
        type name plus its **binary** payload, and a JSON line carries neither."""
        ch = fed(b'{"Type":"test.absent","Object":1}\n', allow_unparsed=True)
        self.assertFalse(ch.allow_unparsed)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_aclose_closes_the_transport_and_is_idempotent(self):
        t = MemTransport.solo()
        ch = channel(t)
        await ch.aclose()
        await ch.aclose()
        self.assertTrue(t.closed)

    @bounded()
    async def test_the_context_manager_closes_on_the_exception_path(self):
        t = MemTransport.solo()
        with self.assertRaises(RuntimeError):
            async with channel(t):
                raise RuntimeError("boom")
        self.assertTrue(t.closed)

    @bounded()
    async def test_open_channel_builds_it_for_the_json_pair(self):
        t = MemTransport.solo()
        ch = open_channel(t, "json", "json")
        self.assertIsInstance(ch, JSONLinesChannel)
        self.assertIs(ch.FORMAT, Format.JSON)


# --- astral.json.v1 -------------------------------------------------------


class FakeMessages:
    """A message stream: WebSocket frames without a WebSocket.

    The seam `WebSocketJSONChannel` is written against, and the shape
    `astral.transport.websocket.WebSocketClient` already has. A byte transport
    cannot stand in for it, which is the whole reason `Channel` and `Transport`
    are two seams (design section 3.1).
    """

    def __init__(self, incoming: list[tuple[bool, bytes]] | None = None) -> None:
        self.incoming = [Message(TEXT if text else BINARY, data) for text, data in (incoming or [])]
        self.sent: list[str] = []
        self.closed = False
        self.endpoint = "ws:127.0.0.1:8625/.ws"

    async def receive(self) -> Message:
        if not self.incoming:
            raise EOFError("closed")
        return self.incoming.pop(0)

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def aclose(self) -> None:
        self.closed = True


class WebSocketJSONTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_one_object_is_one_text_frame_with_its_terminator(self):
        """astrald keeps the newline inside the frame -- `ws_conn.go` writes
        `pending[:i+1]` -- so a frame sent here is byte-identical to one it
        sends."""
        messages = FakeMessages()
        ch = WebSocketJSONChannel(messages)
        await ch.send(FURRY_BOLT)
        await ch.send(EOS())
        self.assertEqual(
            [line.encode() for line in messages.sent],
            [LIVE_WHOAMI, b'{"Type":"eos","Object":null}\n'],
        )

    @bounded()
    async def test_one_frame_carries_one_envelope(self):
        ch = WebSocketJSONChannel(
            FakeMessages([(True, LIVE_WHOAMI), (True, b'{"Type":"eos","Object":null}\n')])
        )
        self.assertEqual([obj async for obj in ch], [FURRY_BOLT])
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_a_frame_with_no_terminator_is_still_a_whole_envelope(self):
        """The subprotocol promises one envelope per frame. A reader that waited
        for a newline would hold the last object of any peer that omits it."""
        ch = WebSocketJSONChannel(FakeMessages([(True, LIVE_WHOAMI.rstrip(b"\n"))]))
        self.assertEqual(await ch.receive(), FURRY_BOLT)

    @bounded()
    async def test_binary_frames_are_dropped_and_counted(self):
        ch = WebSocketJSONChannel(
            FakeMessages([(False, b"\x00\x01"), (False, b"\x02"), (True, LIVE_WHOAMI)])
        )
        self.assertEqual(await ch.receive(), FURRY_BOLT)
        self.assertEqual(ch.dropped_binary, 2)

    @bounded()
    async def test_a_closed_stream_is_a_clean_end_of_objects(self):
        ch = WebSocketJSONChannel(FakeMessages([(True, LIVE_WHOAMI)]))
        self.assertEqual(await ch.receive(), FURRY_BOLT)
        with self.assertRaises(EOFError):
            await ch.receive()

    @bounded()
    async def test_a_frame_carrying_two_envelopes_is_read_as_two_objects(self):
        """astrald re-frames on newlines and never sends this. A peer that does
        cannot desynchronise a reader that frames on the terminator anyway."""
        ch = WebSocketJSONChannel(FakeMessages([(True, LIVE_FILTERS)]))
        self.assertEqual(len([obj async for obj in ch]), 5)
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_the_carrier_is_a_message_stream_and_detach_says_so(self):
        messages = FakeMessages()
        ch = WebSocketJSONChannel(messages)
        self.assertIs(ch.transport, messages)
        with self.assertRaises(TransportUnsupported) as caught:
            ch.detach()
        self.assertIn("astral.binary.v1", str(caught.exception))

    @bounded()
    async def test_aclose_closes_the_message_stream(self):
        messages = FakeMessages()
        await WebSocketJSONChannel(messages).aclose()
        self.assertTrue(messages.closed)


class SeamTest(unittest.IsolatedAsyncioTestCase):
    """The seam is `WebSocketClient`'s own shape, not a shape of its own.

    `connect_websocket(endpoint, subprotocols=("astral.json.v1",))` returns the
    carrier this channel frames; `open_websocket` refuses that subprotocol
    precisely because a `Transport` cannot carry it.
    """

    def test_the_websocket_client_satisfies_the_message_stream_protocol(self):
        for name in ("receive", "send_text", "aclose", "endpoint", "closed"):
            with self.subTest(member=name):
                self.assertTrue(hasattr(WebSocketClient, name))
        self.assertTrue(hasattr(Message, "is_text"))
        self.assertTrue(hasattr(Message, "data"))

    @bounded()
    async def test_an_envelope_round_trips_over_a_real_websocket(self):
        """End to end: a real RFC 6455 client, one text frame per object, and a
        server that answers what it was sent."""
        from mock_web import WSMock

        seen: list[bytes] = []

        async def echo(conn) -> None:  # type: ignore[no-untyped-def]
            payload = await conn.recv_data()
            seen.append(payload)
            await conn.send_text(payload.decode())
            await conn.send_text('{"Type":"eos","Object":null}\n')

        async with WSMock(echo, subprotocols=["astral.json.v1"]) as server:
            client = await connect_websocket(
                server.endpoint, subprotocols=("astral.json.v1",)
            )
            self.assertEqual(client.subprotocol, "astral.json.v1")
            async with WebSocketJSONChannel(client) as channel:
                await channel.send(FURRY_BOLT)
                self.assertEqual(await channel.receive(), FURRY_BOLT)
                self.assertIsInstance(await channel.receive(), EOS)
                self.assertTrue(channel.saw_eos)
            self.assertEqual(server.errors, [])
        # One text frame per object, terminator included, exactly as astrald's
        # own writer frames it.
        self.assertEqual(seen, [LIVE_WHOAMI])


class ChunkTest(unittest.TestCase):
    def test_one_read_cannot_outgrow_the_default_allocation_cap(self):
        from astral.wire import DEFAULT_MAX_ALLOC

        self.assertLess(CHUNK, DEFAULT_MAX_ALLOC)


# --- Tier C ---------------------------------------------------------------


class LiveJSONTest(LiveCase):
    """The node's own JSON lines, decoded and re-encoded byte for byte.

    Read-only and anonymous. The bytes are fetched through the raw view rather
    than through a JSON channel, because a decoder that agreed with this SDK
    would prove nothing about the node.
    """

    async def raw(self, qs: str) -> bytes:
        async with await self.client() as client:
            async with client.stream(qs, raw=True) as stream:
                return await stream.read_bytes(timeout=15.0)

    async def objects(self, data: bytes) -> list:
        t = MemTransport.solo()
        t.feed(data)
        t.feed_eof()
        ch = JSONLinesChannel(t)
        out = []
        while True:
            try:
                out.append(await ch.receive())
            except EOFError:
                return out

    @bounded(30.0)
    async def test_the_whoami_envelope_carries_the_hosts_identity(self):
        [identity] = await self.objects(await self.raw("apphost.whoami?out=json"))
        self.assertIsInstance(identity, Identity)
        self.assertEqual(len(identity.key), 33)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_filter_stream_ends_with_an_eos_envelope(self):
        objects = await self.objects(await self.raw("dir.filters?out=json"))
        self.assertIsInstance(objects[-1], EOS)
        self.assertGreater(len(objects), 1)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_re_encoding_the_nodes_stream_reproduces_its_bytes(self):
        """The strongest assertion available without a second implementation:
        decode what the node wrote, write it back, compare. Immune to the data
        drifting between two requests."""
        for qs in ("dir.alias_map", "objects.repositories", "objects.blueprints"):
            with self.subTest(op=qs):
                data = await self.raw(f"{qs}?out=json")
                t = MemTransport.solo()
                ch = JSONLinesChannel(t)
                for obj in await self.objects(data):
                    await ch.send(obj)
                self.assertEqual(t.sent, data)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
