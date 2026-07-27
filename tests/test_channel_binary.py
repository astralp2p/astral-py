"""Tier B: the binary channel, and the two invariants of design section 7.2.

The framing under test is `string8(type) ++ bytes32(payload)`, with the type tag
outside the length prefix.

Four jobs:

1. Pin the frame bytes in both directions, including the untyped-blob path, which
   is the one place an empty type tag is legal.
2. Prove the framing invariant: a known type decodes to its registered object, an
   unknown one is recoverable through the length prefix alone, and a type that
   reads greedily to the end of its input is handed a reader bounded to exactly
   one payload -- never the transport.
3. Prove invariant 1 of design section 7.2, no stranded bytes at the handover: an
   acceptance frame and the first raw bytes arriving in one write must both be
   visible, the frame to `receive()` and the bytes to the detached transport.
4. Prove invariant 2, one `write()` per frame, against the transport's own record
   of its calls.

Every async test is `bounded`.
"""

from __future__ import annotations

import asyncio
import unittest

from astral import primitives as P
from astral.channel import Format, is_eos, open_channel, parse_format
from astral.channel.binary import BinaryChannel
from astral.errors import (
    AllocationLimit,
    BlueprintNotFound,
    StreamCorrupted,
    TransportUnsupported,
    ValueTooLarge,
)
from astral.object import Ack, Blob, EOS, UnparsedObject
from astral.record import record, wire
from astral.registry import Blueprints, default_blueprints
from astral.session import HostInfoMsg
from astral.spec import Any as AnySpec, Primitive
from astral.transport import MemTransport
from astral.wire import Reader, Writer

from mock_apphost import FURRY_BOLT, FURRY_BOLT_ALIAS, bounded, frame, host_info_payload

# Every test-only schema registers in a child of the process registry, so the
# process registry keeps exactly the types layer 1 and the session declared.
# `HostInfoMsg` is the real control message, resolved through the parent: a
# control message is a registered record like any other, so the framing layer
# needs no message table of its own.
_TEST = Blueprints(default_blueprints())


@record("test.greedy", registry=_TEST)
class Greedy:
    """A type that reads to the end of its reader. The bounded-reader canary."""

    data: bytes = wire("Data", Primitive("bytes8"), default=b"")

    def write_payload(self, w: Writer) -> None:
        w.raw(self.data)

    @classmethod
    def read_payload(cls, r: Reader) -> "Greedy":
        return cls(data=r.rest())


@record("test.wrapper", registry=_TEST)
class Wrapper:
    """One polymorphic field, so an unknown type name can sit inside a payload."""

    inner: object = wire("Inner", AnySpec())


def channel(transport: MemTransport, **kw) -> BinaryChannel:  # type: ignore[no-untyped-def]
    kw.setdefault("registry", _TEST)
    return BinaryChannel(transport, **kw)


class SendTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_frame_layout_is_type_outside_the_length_prefix(self):
        t = MemTransport.solo()
        await channel(t).send(P.Uint32(42))
        self.assertEqual(t.sent.hex(), "06" "75696e743332" "00000004" "0000002a")

    @bounded()
    async def test_an_untyped_blob_writes_a_zero_length_type_tag(self):
        """The one legal empty type tag. The three type encoders all reject one,
        so this path bypasses them (astral-docs bug D-5)."""
        t = MemTransport.solo()
        await channel(t).send(Blob(b"hello"))
        self.assertEqual(t.sent.hex(), "00" "00000005" "68656c6c6f")

    @bounded()
    async def test_a_zero_payload_object_is_a_four_byte_zero_length(self):
        t = MemTransport.solo()
        await channel(t).send(Ack())
        self.assertEqual(t.sent, b"\x03ack\x00\x00\x00\x00")

    @bounded()
    async def test_every_frame_is_exactly_one_write_call(self):
        """Design section 3.2 rule 2. One write per frame is what makes a write
        lock unnecessary and cancellation mid-frame impossible."""
        t = MemTransport.solo()
        ch = channel(t)
        for obj in (P.Uint32(1), P.String8("hi"), Ack(), EOS(), Blob(b"x" * 300)):
            await ch.send(obj)
        self.assertEqual(len(t.writes), 5)
        self.assertEqual(t.writes[0], frame("uint32", b"\x00\x00\x00\x01"))
        self.assertEqual(t.writes[3], frame("eos"))

    @bounded()
    async def test_a_record_round_trips_through_its_own_frame(self):
        left, right = MemTransport.pair()
        message = HostInfoMsg(identity=FURRY_BOLT, alias=FURRY_BOLT_ALIAS)
        await channel(left).send(message)
        self.assertEqual(await channel(right).receive(), message)

    @bounded()
    async def test_a_type_name_past_the_string8_cap_is_refused_before_any_byte(self):
        t = MemTransport.solo()
        with self.assertRaises(ValueTooLarge):
            await channel(t).send(UnparsedObject("x" * 256, b""))
        self.assertEqual(t.writes, [])


class ReceiveTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_known_type_decodes_to_its_registered_object(self):
        t = MemTransport.solo()
        t.feed(frame(HostInfoMsg.ASTRAL_TYPE, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        received = await channel(t).receive()
        self.assertIsInstance(received, HostInfoMsg)
        self.assertEqual(received.identity, FURRY_BOLT)
        self.assertEqual(received.alias, FURRY_BOLT_ALIAS)

    @bounded()
    async def test_the_live_host_info_frame_decodes_byte_for_byte(self):
        """The frame captured from the live node, from the design's must-pass table:
        `19 "mod.apphost.host_info_msg" 0000002d 01 <33B> 0a "furry-bolt"`."""
        captured = bytes.fromhex(
            "19"
            "6d6f642e617070686f73742e686f73745f696e666f5f6d7367"
            "0000002d"
            "01"
            "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
            "0a"
            "66757272792d626f6c74"
        )
        self.assertEqual(
            captured,
            frame(HostInfoMsg.ASTRAL_TYPE, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)),
        )
        t = MemTransport.solo()
        t.feed(captured)
        received = await channel(t).receive()
        self.assertEqual(received, HostInfoMsg(identity=FURRY_BOLT, alias=FURRY_BOLT_ALIAS))

    @bounded()
    async def test_an_empty_type_tag_is_an_untyped_blob_bounded_to_its_frame(self):
        """`Blob` reads to the end of its reader, and the frame after it is already
        buffered, so this is the sharpest form of the bounded-reader rule."""
        t = MemTransport.solo()
        t.feed(frame("", b"raw") + frame("ack"))
        ch = channel(t)
        received = await ch.receive()
        self.assertIsInstance(received, Blob)
        self.assertEqual(received, b"raw")
        self.assertEqual(await ch.receive(), Ack())

    @bounded()
    async def test_an_unknown_type_raises_and_leaves_the_next_frame_readable(self):
        """Binary framing is the only format where an unknown type is recoverable:
        the length prefix already located the next frame."""
        t = MemTransport.solo()
        t.feed(frame("test.absent", b"\x01\x02") + frame("uint32", b"\x00\x00\x00\x07"))
        ch = channel(t)
        with self.assertRaises(BlueprintNotFound):
            await ch.receive()
        self.assertEqual(await ch.receive(), P.Uint32(7))

    @bounded()
    async def test_allow_unparsed_preserves_the_type_name_and_the_payload(self):
        t = MemTransport.solo()
        t.feed(frame("test.absent", b"\x01\x02"))
        received = await channel(t, allow_unparsed=True).receive()
        self.assertEqual(received, UnparsedObject("test.absent", b"\x01\x02"))

    @bounded()
    async def test_allow_unparsed_also_covers_an_unknown_type_inside_a_payload(self):
        """astral-go's receiver treats a missing blueprint raised mid-payload the
        same way, because the frame length still locates the next frame."""
        payload = b"\x0btest.absent" + b"\xff"
        t = MemTransport.solo()
        t.feed(frame("test.wrapper", payload))
        with self.assertRaises(StreamCorrupted):
            await channel(t).receive()

        t2 = MemTransport.solo()
        t2.feed(frame("test.wrapper", payload))
        self.assertEqual(
            await channel(t2, allow_unparsed=True).receive(),
            UnparsedObject("test.wrapper", payload),
        )

    @bounded()
    async def test_a_greedy_type_is_bounded_to_exactly_one_payload(self):
        """The rule the whole codec rests on: a type that reads to the end of its
        input must be handed one frame's payload, never the transport."""
        t = MemTransport.solo()
        t.feed(frame("test.greedy", b"mine") + frame("uint32", b"\x00\x00\x00\x09"))
        ch = channel(t)
        first = await ch.receive()
        self.assertEqual(first, Greedy(data=b"mine"))
        self.assertEqual(await ch.receive(), P.Uint32(9))

    @bounded()
    async def test_a_payload_longer_than_its_type_needs_cannot_desynchronise(self):
        t = MemTransport.solo()
        t.feed(frame("uint32", b"\x00\x00\x00\x01trailing") + frame("ack", b""))
        ch = channel(t)
        self.assertEqual(await ch.receive(), P.Uint32(1))
        self.assertEqual(await ch.receive(), Ack())

    @bounded()
    async def test_a_clean_eof_at_a_frame_boundary_is_eof_error(self):
        t = MemTransport.solo()
        t.feed(frame("ack"))
        t.feed_eof()
        ch = channel(t)
        self.assertEqual(await ch.receive(), Ack())
        with self.assertRaises(EOFError):
            await ch.receive()

    @bounded()
    async def test_a_truncated_frame_is_stream_corrupted_not_a_clean_eof(self):
        for keep in (1, 4, 8, 11):
            with self.subTest(keep=keep):
                t = MemTransport.solo()
                t.feed(frame("uint32", b"\x00\x00\x00\x01")[:keep])
                t.feed_eof()
                with self.assertRaises(StreamCorrupted):
                    await channel(t).receive()

    @bounded()
    async def test_a_declared_payload_length_past_max_alloc_is_refused_unread(self):
        """A `uint32` payload length is attacker-controlled. The cap is checked
        before a byte is read, so a hostile length costs bytes, not gigabytes."""
        t = MemTransport.solo()
        t.feed(b"\x06uint32" + (0xFFFFFFFF).to_bytes(4, "big"))
        with self.assertRaises(AllocationLimit):
            await channel(t, max_alloc=64).receive()

    @bounded()
    async def test_the_registry_travels_with_the_channel(self):
        t = MemTransport.solo()
        t.feed(frame("test.greedy", b"x"))
        with self.assertRaises(BlueprintNotFound):
            await BinaryChannel(t, registry=default_blueprints()).receive()

    @bounded()
    async def test_a_frame_split_across_arrivals_reassembles(self):
        left, right = MemTransport.pair(peer_max_chunk=1)
        payload = host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)
        left.write(frame(HostInfoMsg.ASTRAL_TYPE, payload))
        received = await channel(right).receive()
        self.assertEqual(received.alias, FURRY_BOLT_ALIAS)


class IterationTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_iteration_stops_at_eos_and_records_it(self):
        t = MemTransport.solo()
        t.feed(frame("uint32", b"\x00\x00\x00\x01") + frame("uint32", b"\x00\x00\x00\x02"))
        t.feed(frame("eos") + frame("uint32", b"\x00\x00\x00\x03"))
        ch = channel(t)
        self.assertFalse(ch.saw_eos)
        seen = [obj async for obj in ch]
        self.assertEqual(seen, [P.Uint32(1), P.Uint32(2)])
        self.assertTrue(ch.saw_eos)
        # The channel is still at a frame boundary: the eos was consumed, not
        # skipped, so a follow-mode reader continues from here.
        self.assertEqual(await ch.receive(), P.Uint32(3))

    @bounded()
    async def test_iteration_stops_at_bare_eof_with_no_eos(self):
        """Termination is per-op: `apphost.whoami` ends at EOF with no `eos`
        (astral-docs bug D-23)."""
        t = MemTransport.solo()
        t.feed(frame("identity", FURRY_BOLT.key))
        t.feed_eof()
        ch = channel(t)
        seen = [obj async for obj in ch]
        self.assertEqual(seen, [FURRY_BOLT])
        self.assertFalse(ch.saw_eos)

    def test_is_eos_matches_by_type_name(self):
        self.assertTrue(is_eos(EOS()))
        self.assertFalse(is_eos(Ack()))
        self.assertFalse(is_eos(None))


class FrameBoundaryTest(unittest.IsolatedAsyncioTestCase):
    """`at_frame_boundary`: whether an abandoned read stranded anything.

    A `receive()` cut off by a deadline or a cancellation raises no `WireError`
    and leaves no trace, yet one cut off between a frame's tag and its payload
    has consumed part of the frame and left the rest. Every later read is then
    one frame out of step and the peer chooses what the next message says. The
    session closes on that and must not close on the harmless case, so the
    channel has to answer exactly rather than approximately -- which it can,
    because `readexactly` is all-or-nothing.
    """

    @bounded()
    async def test_a_fresh_channel_and_a_completed_frame_are_both_at_a_boundary(self):
        t = MemTransport.solo()
        t.feed(frame("uint32", b"\x00\x00\x00\x01"))
        ch = channel(t)
        self.assertTrue(ch.at_frame_boundary)
        self.assertEqual(await ch.receive(), P.Uint32(1))
        self.assertTrue(ch.at_frame_boundary)

    @bounded()
    async def test_a_read_cancelled_before_the_first_byte_stranded_nothing(self):
        """The idle case: nothing has arrived, so nothing was consumed. This is
        what keeps a registration's deadline from tearing down a healthy
        connection."""
        t = MemTransport.solo()
        ch = channel(t)
        task = asyncio.ensure_future(ch.receive())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(ch.at_frame_boundary)
        # And the channel is genuinely still usable.
        t.feed(frame("uint32", b"\x00\x00\x00\x07"))
        self.assertEqual(await ch.receive(), P.Uint32(7))

    @bounded()
    async def test_a_read_cancelled_inside_a_frame_says_so(self):
        """The tag and the four length bytes are gone from the reader and the
        payload never arrived. What follows in the stream is the tail of a frame
        nobody will finish reading."""
        whole = frame("uint32", b"\x00\x00\x00\x01")
        t = MemTransport.solo()
        # Everything but the payload: 1 tag byte + "uint32" + 4 length bytes.
        t.feed(whole[: 1 + len("uint32") + 4])
        ch = channel(t)
        task = asyncio.ensure_future(ch.receive())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(t.buffered, 0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_a_decode_that_raises_leaves_the_reader_at_a_boundary(self):
        """`BlueprintNotFound` is recoverable precisely because the length prefix
        already located the next frame: the payload was read whole before the
        decode was attempted, so nothing is stranded."""
        t = MemTransport.solo()
        t.feed(frame("test.unknown", b"\x00") + frame("uint32", b"\x00\x00\x00\x05"))
        ch = channel(t)
        with self.assertRaises(BlueprintNotFound):
            await ch.receive()
        self.assertTrue(ch.at_frame_boundary)
        self.assertEqual(await ch.receive(), P.Uint32(5))

    @bounded()
    async def test_a_truncated_frame_is_not_at_a_boundary(self):
        """A `StreamCorrupted` says the same thing the flag does, and the flag
        must agree: the frame was entered and never left."""
        whole = frame("uint32", b"\x00\x00\x00\x01")
        t = MemTransport.solo()
        t.feed(whole[:-2])
        t.feed_eof()
        ch = channel(t)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()
        self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_a_clean_eof_at_the_first_byte_is_still_a_boundary(self):
        """EOF where a frame would have started is an ending, not a truncation,
        and the reader has not moved."""
        t = MemTransport.solo()
        t.feed_eof()
        ch = channel(t)
        with self.assertRaises(EOFError):
            await ch.receive()
        self.assertTrue(ch.at_frame_boundary)


class HandoverTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_no_stranded_bytes_when_the_acceptance_and_the_body_share_a_write(self):
        """Invariant 1 of design section 7.2. The channel holds no read buffer of
        its own, so the bytes after the acceptance frame are still there for the
        detached transport."""
        t = MemTransport.solo()
        t.feed(frame("ack") + b"raw stream bytes")
        t.feed_eof()
        ch = channel(t)
        self.assertEqual(await ch.receive(), Ack())
        raw = ch.detach()
        self.assertIs(raw, t)
        self.assertEqual(await raw.read(-1), b"raw stream bytes")

    @bounded()
    async def test_detach_leaves_the_channel_inert_and_the_transport_to_the_caller(self):
        t = MemTransport.solo()
        ch = channel(t)
        self.assertIs(ch.detach(), t)
        self.assertTrue(ch.detached)
        with self.assertRaises(RuntimeError):
            await ch.receive()
        with self.assertRaises(RuntimeError):
            await ch.send(Ack())
        await ch.aclose()
        self.assertFalse(t.closed)

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


class OpenChannelTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_default_format_pair_is_the_binary_channel(self):
        t = MemTransport.solo()
        ch = open_channel(t, registry=_TEST)
        self.assertIsInstance(ch, BinaryChannel)
        self.assertIs(ch.transport, t)
        self.assertIs(ch.registry, _TEST)

    @bounded()
    async def test_an_empty_format_token_is_bin(self):
        t = MemTransport.solo()
        self.assertIsInstance(open_channel(t, "", ""), BinaryChannel)

    @bounded()
    async def test_the_unbuilt_formats_are_named_rather_than_framed_as_binary(self):
        t = MemTransport.solo()
        for fmt in ("json", "text", "canonical"):
            with self.subTest(fmt=fmt):
                with self.assertRaises(TransportUnsupported):
                    open_channel(t, fmt, "bin")
        for fmt in ("base64", "render"):
            with self.subTest(fmt=fmt):
                with self.assertRaises(TransportUnsupported):
                    open_channel(t, "bin", fmt)

    def test_format_tokens_are_validated_client_side(self):
        """A node silently accepts an unknown `out=` and then produces zero bytes
        (astral-docs bug D-24), so the check has to be here."""
        self.assertIs(parse_format("bin", output=False), Format.BIN)
        self.assertIs(parse_format("", output=True), Format.BIN)
        with self.assertRaises(ValueError):
            parse_format("xml", output=True)
        with self.assertRaises(ValueError):
            parse_format("base64", output=False)
        self.assertIs(parse_format("base64", output=True), Format.BASE64)


if __name__ == "__main__":
    unittest.main()
