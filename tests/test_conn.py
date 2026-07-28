"""Tier B: `QueryStream`, the accepted query's two views of one transport.

The jobs:

1. Prove the raw view and the framed view share one buffer, so reading a frame
   and then reading the tail raw works and strands nothing. That is design
   section 3.2 rule 1 restated one layer up: the channel holds no buffer of its
   own, so mixing the views is safe by construction rather than by luck.
2. Prove the framed view is created lazily and only once. `objects.read` answers
   with unframed bytes, so a stream that framed itself eagerly would encode an
   assumption the protocol does not make.
3. Prove termination is `eos` **or** EOF and that the stream says which, because
   `apphost.whoami` and `dir.alias_map` end at bare EOF (astral-docs bug D-23).
4. Prove the hygiene rules: identity direction, half-close, an idempotent
   `aclose()` that never raises, and a context manager that closes on the
   exception path.

Every async test is `bounded`.
"""

from __future__ import annotations

import asyncio
import unittest

from astral import primitives as P
from astral.conn import QueryStream
from astral.errors import AllocationLimit, TransportUnsupported
from astral.object import Ack, Query
from astral.transport import MemTransport
from astral.types import Identity, Nonce

from mock_apphost import FURRY_BOLT, bounded, frame, refusing, until

CALLER = Identity.parse("02" + "11" * 32)
NONCE = Nonce(0x1122334455667788)


def query(text: str = "apphost.whoami") -> Query:
    return Query(nonce=NONCE, caller=CALLER, target=FURRY_BOLT, query_string=text)


def stream(**kw) -> tuple[MemTransport, MemTransport, QueryStream]:  # type: ignore[no-untyped-def]
    """A stream over one half of a memory pair, and both halves for assertions."""
    kind = kw.pop("transport", MemTransport)
    local, remote = MemTransport.pair("conn")
    local = kind(local._in, local._out, local.endpoint)
    return local, remote, QueryStream(local, kw.pop("query", query()), **kw)


class QueryTest(unittest.TestCase):
    def test_an_outbound_stream_is_local_caller_remote_target(self):
        _, _, s = stream()
        self.assertTrue(s.outbound)
        self.assertEqual(s.local_id, CALLER)
        self.assertEqual(s.remote_id, FURRY_BOLT)
        self.assertEqual(s.nonce, NONCE)
        self.assertEqual(s.query_string, "apphost.whoami")

    def test_an_inbound_stream_swaps_them(self):
        """The direction decides which identity is ours, exactly as astral-go's
        `apphost.Conn` does."""
        _, _, s = stream(outbound=False)
        self.assertFalse(s.outbound)
        self.assertEqual(s.local_id, FURRY_BOLT)
        self.assertEqual(s.remote_id, CALLER)

    def test_an_anonymous_caller_is_none_on_both_sides(self):
        anon = Query(nonce=NONCE, caller=None, target=FURRY_BOLT, query_string="x")
        _, _, s = stream(query=anon)
        self.assertIsNone(s.local_id)
        _, _, inbound = stream(query=anon, outbound=False)
        self.assertIsNone(inbound.remote_id)

    def test_the_endpoint_defaults_to_the_transports(self):
        local, _, s = stream()
        self.assertEqual(s.endpoint, local.endpoint)
        _, _, named = stream(endpoint="tcp:127.0.0.1:8625")
        self.assertEqual(named.endpoint, "tcp:127.0.0.1:8625")


class RawViewTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_unframed_bytes_read_straight_through(self):
        """The `objects.read` shape: the response body is not an object stream."""
        local, remote, s = stream()
        remote.write(b"\x00\x01\x02unframed")
        remote.write_eof()
        self.assertEqual(await s.read(-1), b"\x00\x01\x02unframed")
        self.assertEqual(await s.read(-1), b"")

    @bounded()
    async def test_reading_to_eof_is_bounded_by_max_alloc(self):
        """The one attacker-controlled length in the SDK with no prefix to check.

        `objects.read` is the RAW op and its body is whatever the responder
        sends; `read(-1)` used to hand `StreamReader.read(-1)` an endless body
        and accumulate to death -- measured at +177 MiB and still climbing. The
        cap is `max_alloc`, the same one every declared length in the wire core
        is checked against, and not a second limit invented here.
        """
        local, remote, s = stream(max_alloc=1024)
        remote.write(b"z" * 4096)
        with self.assertRaises(AllocationLimit) as caught:
            await s.read(-1)
        self.assertIn("max_alloc", str(caught.exception))

    @bounded()
    async def test_a_body_of_exactly_max_alloc_still_reads(self):
        """The cap is a limit, not an off-by-one: the last legal byte is legal."""
        local, remote, s = stream(max_alloc=1024)
        remote.write(b"z" * 1024)
        remote.write_eof()
        self.assertEqual(await s.read(-1), b"z" * 1024)

    @bounded()
    async def test_a_bounded_read_is_the_callers_own_length(self):
        """`read(n)` is bounded by `n` already, so the cap does not touch it."""
        local, remote, s = stream(max_alloc=8)
        remote.write(b"z" * 64)
        self.assertEqual(await s.read(64), b"z" * 64)

    @bounded()
    async def test_readexactly_and_short_reads(self):
        local, remote, s = stream()
        remote.write(b"12345")
        self.assertEqual(await s.readexactly(2), b"12")
        self.assertEqual(await s.read(10), b"345")

    @bounded()
    async def test_send_bytes_writes_and_drains(self):
        local, remote, s = stream()
        await s.send_bytes(b"payload")
        self.assertEqual(await remote.read(7), b"payload")
        self.assertEqual(local.writes, [b"payload"])

    @bounded()
    async def test_write_eof_half_closes_and_leaves_reading_open(self):
        """Verified live: after `shutdown(SHUT_WR)` on an accepted query the
        response object still arrived, then EOF."""
        local, remote, s = stream()
        s.write_eof()
        self.assertEqual(await remote.read(-1), b"")
        remote.write(frame("ack"))
        self.assertEqual(await s.receive(), Ack())


class FramedViewTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_framed_view_is_lazy(self):
        _, _, s = stream()
        self.assertFalse(s.framed)
        self.assertFalse(s.saw_eos)
        s.channel()
        self.assertTrue(s.framed)

    @bounded()
    async def test_the_same_channel_comes_back_every_time(self):
        _, _, s = stream()
        self.assertIs(s.channel(), s.channel("bin", "bin"))

    @bounded()
    async def test_reframing_a_stream_is_refused(self):
        """Two framers over one buffer would each eat frames the other needed."""
        _, _, s = stream()
        s.channel()
        with self.assertRaises(RuntimeError):
            s.channel("json", "json")

    @bounded()
    async def test_a_line_framing_frames_the_same_stream(self):
        """The framed view is whichever framing the formats name. `text` in and
        out is one `TextChannel`, and it reads the node's `#[type] body` lines
        off the same transport the binary view would have framed."""
        from astral.channel.textchan import TextChannel

        _, remote, s = stream()
        remote.write(b"#[uint32] 9\n")
        channel = s.channel("text", "text")
        self.assertIsInstance(channel, TextChannel)
        self.assertEqual(await s.receive("text", "text"), P.Uint32(9))

    @bounded()
    async def test_a_line_framing_cannot_be_handed_over_as_a_raw_stream(self):
        """`detach()` is legal on the binary channel alone: a line receiver
        reads ahead, so the bytes after a line are in the channel rather than in
        the transport (design section 3.1)."""
        _, _, s = stream()
        with self.assertRaises(TransportUnsupported):
            s.channel("json", "json").detach()

    @bounded()
    async def test_send_and_receive_one_object(self):
        local, remote, s = stream()
        await s.send(P.Uint32(7))
        self.assertEqual(remote.buffered, len(frame("uint32", b"\x00\x00\x00\x07")))
        remote.write(frame("uint32", b"\x00\x00\x00\x09"))
        self.assertEqual(await s.receive(), P.Uint32(9))
        # Invariant 2 of design section 7.2, on the stream as well as the channel.
        self.assertEqual(len(local.writes), 1)

    @bounded()
    async def test_send_eos_writes_the_terminator(self):
        local, remote, s = stream()
        await s.send_eos()
        self.assertEqual(local.sent, frame("eos"))

    @bounded()
    async def test_iteration_stops_at_eos_and_records_it(self):
        local, remote, s = stream()
        remote.write(frame("uint32", b"\x00\x00\x00\x01") + frame("eos"))
        self.assertEqual([obj async for obj in s], [P.Uint32(1)])
        self.assertTrue(s.saw_eos)

    @bounded()
    async def test_iteration_stops_at_bare_eof_with_no_eos(self):
        """Termination is per-op: `apphost.whoami` and `dir.alias_map` send no
        `eos` at all, so nothing may wait for one."""
        local, remote, s = stream()
        remote.write(frame("identity", FURRY_BOLT.key))
        remote.write_eof()
        self.assertEqual([obj async for obj in s], [FURRY_BOLT])
        self.assertFalse(s.saw_eos)

    @bounded()
    async def test_an_error_object_is_yielded_rather_than_raised(self):
        """Raising on `error_message` is `Stream`'s decision one layer up: a
        stream of bytes has no notion of what an error means to a query."""
        local, remote, s = stream()
        remote.write(frame("error_message", b"\x00\x04oops"))
        remote.write_eof()
        seen = [obj async for obj in s]
        self.assertEqual([str(obj) for obj in seen], ["oops"])


class MixedViewTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_frame_then_the_raw_tail_in_one_write(self):
        """One buffer, two views. A framer with a read buffer of its own would
        strand the tail here -- which is the exact hazard at the handover."""
        local, remote, s = stream()
        remote.write(frame("ack") + b"raw tail")
        remote.write_eof()
        self.assertEqual(await s.receive(), Ack())
        self.assertEqual(await s.read(-1), b"raw tail")

    @bounded()
    async def test_raw_bytes_then_a_frame(self):
        local, remote, s = stream()
        remote.write(b"1234" + frame("ack"))
        self.assertEqual(await s.readexactly(4), b"1234")
        self.assertEqual(await s.receive(), Ack())


class LifetimeTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_aclose_is_idempotent_and_closes_the_transport(self):
        local, _, s = stream()
        await s.aclose()
        await s.aclose()
        self.assertTrue(local.closed)
        self.assertTrue(s.closed)

    @bounded()
    async def test_the_context_manager_closes_on_the_exception_path(self):
        local, _, s = stream()
        with self.assertRaises(RuntimeError):
            async with s:
                raise RuntimeError("boom")
        self.assertTrue(local.closed)

    @bounded()
    async def test_aclose_never_raises_on_a_broken_transport(self):
        class Broken(MemTransport):
            async def aclose(self) -> None:
                raise OSError("already gone")

        local, remote = MemTransport.pair()
        broken = Broken(local._in, local._out, "mem:broken")
        await QueryStream(broken, query()).aclose()

    @bounded()
    async def test_closing_mid_iteration_ends_the_iteration(self):
        local, remote, s = stream()
        remote.write(frame("uint32", b"\x00\x00\x00\x01"))
        seen = []
        async for obj in s:
            seen.append(obj)
            await s.aclose()
        self.assertEqual(seen, [P.Uint32(1)])

    @bounded()
    async def test_a_second_aclose_waits_for_the_first_instead_of_lying(self):
        """`aclose()` returning must mean closed, for the second caller too.

        The transport underneath has always waited; this layer only latched a
        flag and returned. Measured against a deaf peer with 16 MiB queued:
        `StreamTransport`'s second caller returned after 1.95 s with the
        descriptor gone, while `QueryStream`'s returned after 0.00 s reporting
        `closed=False` with the descriptor still open. Nothing leaks -- the
        first closer finishes eventually -- but a shutdown that counted this
        stream as released would have counted a live one, which on astrald is a
        worker still held out of 32.
        """
        local, _remote, s = stream(query=query(), transport=_SlowClose)
        first = asyncio.ensure_future(s.aclose())
        self.assertTrue(await until(lambda: local.closing_now.is_set()))
        second = asyncio.ensure_future(s.aclose())
        # Every chance to finish, and it must not have taken one.
        await until(lambda: second.done())
        self.assertFalse(second.done(), "the second aclose() returned early")
        self.assertFalse(s.closed)
        local.release.set()
        await asyncio.gather(first, second)
        self.assertTrue(s.closed)
        self.assertTrue(local.closed)


    @bounded()
    async def test_closed_is_the_transports_answer_and_not_this_calls(self):
        """`closed` used to be latched in a `finally`, whatever the carrier did.

        Over a carrier whose close did not complete that made it a promise: a
        cancelled teardown reported `closed=True` on a socket `ss` still called
        ESTABLISHED with 2,428,928 bytes queued, and every later `aclose()`
        returned in 0.0000 s on the idempotent fast path, so nothing could ever
        release it again. The flag is now read from the transport, and a close
        that reached nothing leaves the stream *closing* so the next one
        resumes.
        """
        carrier = refusing()
        s = QueryStream(carrier, query())
        await s.aclose()
        self.assertFalse(s.closed)
        self.assertFalse(carrier.closed)
        await s.aclose()
        self.assertFalse(s.closed)
        await s.aclose()
        self.assertTrue(s.closed)
        self.assertTrue(carrier.closed)
        self.assertEqual(carrier.aclose_calls, 3)


class _SlowClose(MemTransport):
    """A transport whose close suspends until the test lets it finish.

    A deaf loopback peer with a stuffed buffer produces the same suspension and
    costs two seconds a case; this produces it in one loop turn and makes the
    assertion about the layer under test rather than about the kernel.
    """

    def __init__(self, *args, **kw) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kw)
        self.closing_now = asyncio.Event()
        self.release = asyncio.Event()

    async def aclose(self) -> None:
        self.closing_now.set()
        await self.release.wait()
        await super().aclose()


if __name__ == "__main__":
    unittest.main()
