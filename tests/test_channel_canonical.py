"""Tier B and C: the canonical channel -- `Stamp ++ string8(type) ++ payload`.

The framing that genuinely differs (astral-docs bug D-12): no length prefix
anywhere, so an object's extent is its own decoder's business and nothing else
locates the next one.

Five jobs:

1. Pin the frame bytes in both directions against a **capture taken from
   `furry-bolt` this session**, six objects back to back with no separator.
2. Pin the decode-and-retry rule: an object arriving one byte at a time decodes
   exactly once, at its true length, and the reader's `pos` is that length.
3. Pin what the framing excludes -- an untyped blob on either side, and an
   unknown type -- and prove each is refused rather than mis-framed.
4. Pin the latch. After a fault the next object's first byte is unlocatable, so
   every later read would be whatever the peer chose.
5. Pin that a cancelled read is not a fault: the buffer is this channel's, so
   nothing is stranded.

Every async test is `bounded`.
"""

from __future__ import annotations

import asyncio
import unittest

from astral import primitives as P
from astral.channel import Format, open_channel
from astral.channel.canonical import CanonicalChannel
from astral.codec import STAMP, canonical
from astral.errors import (
    AllocationLimit,
    ParseError,
    SchemaError,
    StreamCorrupted,
    TransportUnsupported,
)
from astral.object import Ack, Blob, EOS, ErrorMessage, UnparsedObject
from astral.transport import MemTransport
from astral.types import Identity

from live_support import LiveCase
from mock_apphost import FURRY_BOLT, bounded

# `dir.filters?out=canonical` on the live node, byte for byte: two of the five
# filters and the terminator, with nothing between them.
LIVE_FILTERS = bytes.fromhex(
    "4144433007737472696e6738096c6f63616c6e6f6465"
    "4144433007737472696e6738066c696e6b6564"
    "4144433003656f73"
)
# `apphost.whoami?out=canonical`: stamp, type, and 33 flat identity bytes.
LIVE_WHOAMI = bytes.fromhex(
    "41444330"
    "086964656e74697479"
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)
# `dir.alias_map?out=canonical`: one record, uint32 count and all.
LIVE_ALIAS_MAP = bytes.fromhex(
    "41444330"
    "116d6f642e6469722e616c6961735f6d6170"
    "00000001000a66757272792d626f6c74"
    "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)


def channel(transport: MemTransport, **kw) -> CanonicalChannel:  # type: ignore[no-untyped-def]
    return CanonicalChannel(transport, **kw)


def fed(data: bytes, *, eof: bool = True, **kw) -> CanonicalChannel:  # type: ignore[no-untyped-def]
    t = MemTransport.solo()
    t.feed(data)
    if eof:
        t.feed_eof()
    return channel(t, **kw)


class SendTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_frame_is_a_stamp_a_type_and_a_payload(self):
        t = MemTransport.solo()
        await channel(t).send(P.Uint32(42))
        self.assertEqual(t.sent.hex(), "41444330" "0675696e743332" "0000002a")
        self.assertTrue(t.sent.startswith(STAMP))

    @bounded()
    async def test_the_live_filter_stream_is_reproduced_exactly(self):
        t = MemTransport.solo()
        ch = channel(t)
        await ch.send(P.String8("localnode"))
        await ch.send(P.String8("linked"))
        await ch.send(EOS())
        self.assertEqual(t.sent, LIVE_FILTERS)

    @bounded()
    async def test_the_live_identity_frame_is_reproduced_exactly(self):
        t = MemTransport.solo()
        await channel(t).send(FURRY_BOLT)
        self.assertEqual(t.sent, LIVE_WHOAMI)

    @bounded()
    async def test_a_zero_payload_object_is_a_stamp_and_a_type_alone(self):
        t = MemTransport.solo()
        await channel(t).send(EOS())
        self.assertEqual(t.sent, STAMP + b"\x03eos")

    @bounded()
    async def test_every_object_is_exactly_one_write(self):
        t = MemTransport.solo()
        ch = channel(t)
        for obj in (P.Uint32(1), P.String8("hi"), Ack(), EOS()):
            await ch.send(obj)
        self.assertEqual(len(t.writes), 4)
        self.assertEqual(t.writes[3], STAMP + b"\x03eos")

    @bounded()
    async def test_an_untyped_blob_is_refused_before_a_byte_is_written(self):
        """astral-go's CanonicalSender writes a zero-length type tag and its own
        CanonicalReceiver then answers `blueprint not found:`. The type tag is
        what says where the payload starts, so an untyped object cannot cross
        this framing at all."""
        t = MemTransport.solo()
        with self.assertRaises(SchemaError):
            await channel(t).send(Blob(b"raw"))
        self.assertEqual(t.writes, [])

    @bounded()
    async def test_an_unparsed_object_keeps_its_name_and_its_payload(self):
        """It has a type name and a binary payload, which is everything this
        framing carries. Only the receiving side cannot recover from one."""
        t = MemTransport.solo()
        await channel(t).send(UnparsedObject("test.absent", b"\x01\x02"))
        self.assertEqual(t.sent, STAMP + b"\x0btest.absent" + b"\x01\x02")


class ReceiveTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_live_filter_stream_decodes_and_stops_at_the_eos(self):
        ch = fed(LIVE_FILTERS)
        seen = [obj async for obj in ch]
        self.assertEqual(seen, [P.String8("localnode"), P.String8("linked")])
        self.assertTrue(ch.saw_eos)
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_the_live_identity_frame_decodes_to_thirty_three_flat_bytes(self):
        received = await fed(LIVE_WHOAMI).receive()
        self.assertIsInstance(received, Identity)
        self.assertEqual(received, FURRY_BOLT)

    @bounded()
    async def test_a_record_decodes_from_the_live_capture(self):
        import astral.api  # noqa: F401 -- registers mod.dir.alias_map

        alias_map = await fed(LIVE_ALIAS_MAP).receive()
        self.assertEqual(alias_map.aliases, {"furry-bolt": FURRY_BOLT})

    @bounded()
    async def test_an_object_arriving_one_byte_at_a_time_decodes_once(self):
        """The decode-and-retry rule. Each attempt starts at the buffer's first
        byte, so a decoder that consumed part of a short buffer consumed nothing
        that matters."""
        t = MemTransport.solo(max_chunk=1)
        t.feed(LIVE_FILTERS)
        t.feed_eof()
        ch = channel(t)
        self.assertEqual([obj async for obj in ch], [P.String8("localnode"), P.String8("linked")])
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_the_object_after_one_that_over_read_nothing_is_intact(self):
        """No length announces where an object ends, so the proof that the
        length was right is that the next object decodes."""
        ch = fed(LIVE_WHOAMI + LIVE_FILTERS)
        self.assertEqual(await ch.receive(), FURRY_BOLT)
        self.assertEqual(await ch.receive(), P.String8("localnode"))

    @bounded()
    async def test_an_error_message_object_is_data_not_an_exception(self):
        received = await fed(canonical("error_message", b"\x00\x04nope")).receive()
        self.assertEqual(received, ErrorMessage("nope"))

    @bounded()
    async def test_a_clean_eof_between_objects_is_eof_error(self):
        ch = fed(LIVE_WHOAMI)
        await ch.receive()
        with self.assertRaises(EOFError):
            await ch.receive()
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_a_stream_that_ends_inside_an_object_is_a_truncation(self):
        for keep in (1, 4, 6, len(LIVE_WHOAMI) - 1):
            with self.subTest(keep=keep):
                ch = fed(LIVE_WHOAMI[:keep])
                with self.assertRaises(StreamCorrupted):
                    await ch.receive()
                self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_a_wrong_stamp_is_a_parse_error(self):
        ch = fed(b"ADC1" + b"\x03eos")
        with self.assertRaises(ParseError):
            await ch.receive()
        self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_a_zero_length_type_tag_names_no_type(self):
        """What astral-go's own sender writes for an untyped blob. There is no
        length prefix to locate what follows it, so the stream ends here."""
        ch = fed(STAMP + b"\x00" + b"raw")
        with self.assertRaises(StreamCorrupted) as caught:
            await ch.receive()
        self.assertIn("untyped blob", str(caught.exception))

    @bounded()
    async def test_an_unknown_type_ends_the_stream(self):
        ch = fed(canonical("test.absent", b"\x01") + LIVE_WHOAMI)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_allow_unparsed_is_accepted_and_not_honoured(self):
        """There is no length to skip an unknown payload with, so tolerance is
        not available in this framing at any price."""
        ch = fed(canonical("test.absent", b"\x01"), allow_unparsed=True)
        self.assertFalse(ch.allow_unparsed)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_a_buffer_past_max_alloc_that_decodes_to_nothing_is_refused(self):
        """The framing announces no length, so the only bound on one object is
        how much has arrived."""
        t = MemTransport.solo()
        t.feed(STAMP + b"\x08string64" + b"\xff" * 200)
        ch = channel(t, max_alloc=64)
        with self.assertRaises(AllocationLimit):
            await ch.receive()


class LatchTest(unittest.IsolatedAsyncioTestCase):
    """The first fault ends the channel, matching astral-go's CanonicalReceiver:
    "Any error after Stamp consumption leaves the stream in an indeterminate
    state, so we latch the first non-nil error and refuse subsequent reads."
    """

    @bounded()
    async def test_a_fault_repeats_without_touching_the_transport(self):
        t = MemTransport.solo()
        t.feed(canonical("test.absent", b"\x01"))
        ch = channel(t)
        with self.assertRaises(StreamCorrupted) as first:
            await ch.receive()
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
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_a_cancelled_read_is_not_a_fault_and_strands_nothing(self):
        t = MemTransport.solo()
        t.feed(LIVE_WHOAMI[:10])
        ch = channel(t)
        task = asyncio.ensure_future(ch.receive())
        for _ in range(4):
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(ch.latched)
        self.assertTrue(ch.at_frame_boundary)
        t.feed(LIVE_WHOAMI[10:])
        self.assertEqual(await ch.receive(), FURRY_BOLT)


class HandoverTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_detach_is_refused_because_the_channel_holds_the_bytes(self):
        ch = fed(LIVE_FILTERS, eof=False)
        await ch.receive()
        with self.assertRaises(TransportUnsupported) as caught:
            ch.detach()
        self.assertIn("canonical", str(caught.exception))

    @bounded()
    async def test_aclose_closes_the_transport_and_is_idempotent(self):
        t = MemTransport.solo()
        ch = channel(t)
        await ch.aclose()
        await ch.aclose()
        self.assertTrue(t.closed)

    @bounded()
    async def test_open_channel_builds_it_for_the_canonical_pair(self):
        ch = open_channel(MemTransport.solo(), "canonical", "canonical")
        self.assertIsInstance(ch, CanonicalChannel)
        self.assertIs(ch.FORMAT, Format.CANONICAL)


# --- Tier C ---------------------------------------------------------------


class LiveCanonicalTest(LiveCase):
    """The node's own canonical stream, decoded and re-encoded byte for byte."""

    async def raw(self, qs: str) -> bytes:
        async with await self.client() as client:
            async with client.stream(qs, raw=True) as stream:
                return await stream.read_bytes(timeout=15.0)

    async def objects(self, data: bytes) -> list:
        t = MemTransport.solo()
        t.feed(data)
        t.feed_eof()
        ch = CanonicalChannel(t)
        out = []
        while True:
            try:
                out.append(await ch.receive())
            except EOFError:
                return out

    @bounded(30.0)
    async def test_the_stream_is_stamped_objects_with_no_length_prefix(self):
        data = await self.raw("dir.filters?out=canonical")
        self.assertTrue(data.startswith(STAMP))
        objects = await self.objects(data)
        self.assertIsInstance(objects[-1], EOS)
        self.assertGreater(len(objects), 1)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_re_encoding_the_nodes_stream_reproduces_its_bytes(self):
        """Every object's length has to be exactly right for this to hold: one
        byte short anywhere and the next stamp lands in the wrong place."""
        for qs in ("apphost.whoami", "dir.alias_map", "objects.repositories"):
            with self.subTest(op=qs):
                data = await self.raw(f"{qs}?out=canonical")
                t = MemTransport.solo()
                ch = CanonicalChannel(t)
                for obj in await self.objects(data):
                    await ch.send(obj)
                self.assertEqual(t.sent, data)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_a_hundred_and_fifty_objects_frame_with_no_length_between_them(self):
        """`objects.blueprints` is the longest stream the read-only set has, and
        every object in it is a bare `string8` -- the sharpest form of "nothing
        announces where an object ends"."""
        objects = await self.objects(await self.raw("objects.blueprints?out=canonical"))
        self.assertGreater(len(objects), 100)
        self.assertIsInstance(objects[-1], EOS)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
