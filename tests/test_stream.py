"""Tier B: `Stream`, the policy layer over one query's bytes.

`QueryStream` is tested in `test_conn.py` and owns the framing. What is tested
here is everything that depends on knowing which query the bytes belong to, and
every one of these assertions exists because getting it wrong is silent:

1. **Termination is `eos` or EOF, and never `eos` alone.** Verified live this
   session: `apphost.whoami` answers with one `identity` and closes, reporting
   `terminated_by == "eof"` and `saw_eos == False`, while `objects.blueprints`
   answers with 153 `string8` objects and an `eos`. Both shapes are legal, the
   op decides which, and nothing in the SDK may wait for an `eos` (astral-docs
   bug D-23).
2. **A follow stream's first `eos` is a separator, not a terminator.** Reading it
   as a terminator truncates the stream at its snapshot; waiting for a second one
   on an ordinary op blocks until the responder closes. The op declares which,
   the caller chooses the iterator, and nothing infers one (design section 4.7).
3. **An `error_message` is an object on the wire and a failure in the query.**
   Every iterator raises `RemoteError`; `raw_objects()` alone yields it, which is
   what the CLI needs to print a partial stream.
4. **The permit is handed back after the descriptor is gone.** A release on entry
   would let a bounded client hold one more connection than its bound, which is
   the one resource astrald cannot absorb (bug G-13, design section 3.9).

Every async test is `bounded`; no test contacts a node.
"""

from __future__ import annotations

import asyncio
import unittest

from astral import primitives as P
from astral.channel import Format
from astral.conn import QueryStream
from astral.errors import (
    ProtocolError,
    QueryTimeout,
    RemoteError,
    StreamCorrupted,
)
from astral.object import Ack, ErrorMessage, Query
from astral.stream import Stream
from astral.transport import MemTransport
from astral.types import Identity, Nonce
from astral.wire import Writer

from mock_apphost import EOS as EOS_TYPE, FURRY_BOLT, bounded, frame, until

CALLER = Identity.parse("02" + "11" * 32)
NONCE = Nonce(0x1122334455667788)


def u8(value: int) -> bytes:
    return frame("uint8", bytes([value]))


def err(message: str) -> bytes:
    w = Writer()
    w.string16(message)
    return frame("error_message", w.getvalue())


def eos() -> bytes:
    return frame(EOS_TYPE)


def a_query(text: str = "apphost.whoami") -> Query:
    return Query(nonce=NONCE, caller=CALLER, target=FURRY_BOLT, query_string=text)


def make(
    body: bytes = b"", *, close: bool = True, **kw: object
) -> tuple[MemTransport, Stream]:
    """A stream whose responder has already sent `body`.

    `close` half-closes the responder, which is the bare EOF every non-`eos` op
    ends with.
    """
    local, remote = MemTransport.pair("stream")
    if body:
        remote.write(body)
    if close:
        remote.write_eof()
    conn = QueryStream(local, kw.pop("query", a_query()))  # type: ignore[arg-type]
    return remote, Stream(conn, **kw)  # type: ignore[arg-type]


class TerminationTest(unittest.IsolatedAsyncioTestCase):
    """`eos` or EOF, and the stream says which."""

    @bounded()
    async def test_a_stream_ending_at_eos_reports_eos(self):
        _, s = make(u8(1) + u8(2) + eos())
        async with s:
            self.assertEqual([o async for o in s], [P.Uint8(1), P.Uint8(2)])
            self.assertEqual(s.terminated_by, "eos")
            self.assertTrue(s.saw_eos)

    @bounded()
    async def test_a_stream_ending_at_bare_eof_reports_eof(self):
        """The live `apphost.whoami` shape: one object, no `eos`, then close.

        A consumer that waited for an `eos` here would block until the responder
        closed, and on a responder that kept the connection open it would block
        forever holding one of the node's 32 workers.
        """
        _, s = make(u8(7))
        async with s:
            self.assertEqual([o async for o in s], [P.Uint8(7)])
            self.assertEqual(s.terminated_by, "eof")
            self.assertFalse(s.saw_eos)

    @bounded()
    async def test_terminated_by_is_none_until_the_stream_ends(self):
        _, s = make(u8(1) + eos())
        async with s:
            self.assertIsNone(s.terminated_by)
            self.assertEqual(await s.first(), P.Uint8(1))
            self.assertIsNone(s.terminated_by)
            self.assertIsNone(await s.first())
            self.assertEqual(s.terminated_by, "eos")

    @bounded()
    async def test_an_empty_stream_yields_nothing_and_reports_its_ending(self):
        for body, ending in ((b"", "eof"), (eos(), "eos")):
            with self.subTest(ending=ending):
                _, s = make(body)
                async with s:
                    self.assertEqual([o async for o in s], [])
                    self.assertEqual(s.terminated_by, ending)


class ErrorPolicyTest(unittest.IsolatedAsyncioTestCase):
    """An `error_message` is data on the wire and a failure in the query."""

    @bounded()
    async def test_iteration_raises_on_an_error_object(self):
        """Yielding one is how a failed stage feeds a wrong-typed object onward."""
        _, s = make(u8(1) + err("no such repository") + u8(2))
        async with s:
            seen = []
            with self.assertRaises(RemoteError) as caught:
                async for obj in s:
                    seen.append(obj)
            self.assertEqual(seen, [P.Uint8(1)])
            # `.message` is the responder's own text, unprefixed, for a caller
            # matching on it; `str()` names the query, because "record not found"
            # does not say which of a program's ten queries produced it.
            self.assertEqual(caught.exception.message, "no such repository")
            self.assertEqual(
                str(caught.exception), f"{s.query_string}: no such repository"
            )
            self.assertEqual(caught.exception.query, s.query_string)
            self.assertEqual(caught.exception.endpoint, s.endpoint)

    @bounded()
    async def test_raw_objects_yields_errors_and_raises_nothing(self):
        """The CLI's view: print the error, keep going, exit 1."""
        _, s = make(u8(1) + err("boom") + u8(2) + eos())
        async with s:
            got = [o async for o in s.raw_objects()]
        self.assertEqual(got, [P.Uint8(1), ErrorMessage("boom"), P.Uint8(2)])

    @bounded()
    async def test_the_helpers_all_raise_on_an_error_object(self):
        for name in ("collect", "value", "first"):
            with self.subTest(helper=name):
                _, s = make(err("denied") + eos())
                async with s:
                    with self.assertRaises(RemoteError):
                        await getattr(s, name)()

    @bounded()
    async def test_follow_raises_on_an_error_object(self):
        _, s = make(err("gone"), close=False)
        async with s:
            with self.assertRaises(RemoteError):
                async for _ in s.follow():
                    pass


class FollowTest(unittest.IsolatedAsyncioTestCase):
    """The first `eos` of a follow-mode op is a boundary, not an ending."""

    @bounded()
    async def test_follow_crosses_the_separator_and_flags_the_live_half(self):
        _, s = make(u8(1) + u8(2) + eos() + u8(9))
        async with s:
            pairs = [pair async for pair in s.follow()]
        self.assertEqual(
            pairs, [(P.Uint8(1), False), (P.Uint8(2), False), (P.Uint8(9), True)]
        )

    @bounded()
    async def test_follow_ends_at_eof_not_at_the_separator(self):
        _, s = make(u8(1) + eos() + u8(9))
        async with s:
            [_ async for _ in s.follow()]
            self.assertEqual(s.terminated_by, "eof")

    @bounded()
    async def test_a_second_eos_ends_a_follow_stream(self):
        """There is exactly one snapshot boundary, so a second `eos` is the op
        ending. Held open afterwards, to prove the stream stopped on the `eos`
        rather than on the close."""
        _, s = make(u8(1) + eos() + u8(9) + eos(), close=False)
        async with s:
            pairs = [pair async for pair in s.follow()]
            self.assertEqual(pairs, [(P.Uint8(1), False), (P.Uint8(9), True)])
            self.assertEqual(s.terminated_by, "eos")

    @bounded()
    async def test_snapshot_stops_at_the_separator_without_over_reading(self):
        """`snapshot()` then `live()` is two iterators over one stream, in order.

        The separator is consumed and nothing beyond it is, so the first live
        object is still there for `live()` to yield. An implementation that read
        one object past the boundary to discover it would silently drop that
        object.
        """
        _, s = make(u8(1) + u8(2) + eos() + u8(9) + u8(10))
        async with s:
            self.assertEqual(
                [o async for o in s.snapshot()], [P.Uint8(1), P.Uint8(2)]
            )
            self.assertTrue(s.is_live)
            # A snapshot boundary is not an ending.
            self.assertIsNone(s.terminated_by)
            self.assertEqual([o async for o in s.live()], [P.Uint8(9), P.Uint8(10)])
            self.assertEqual(s.terminated_by, "eof")

    @bounded()
    async def test_live_alone_discards_the_snapshot(self):
        _, s = make(u8(1) + u8(2) + eos() + u8(9))
        async with s:
            self.assertEqual([o async for o in s.live()], [P.Uint8(9)])

    @bounded()
    async def test_snapshot_on_a_stream_that_ends_at_eof_yields_everything(self):
        """A follow op whose responder closed before sending a separator. The
        snapshot is what arrived; `is_live` stays false, so a caller can tell."""
        _, s = make(u8(1) + u8(2))
        async with s:
            self.assertEqual(
                [o async for o in s.snapshot()], [P.Uint8(1), P.Uint8(2)]
            )
            self.assertFalse(s.is_live)
            self.assertEqual(s.terminated_by, "eof")

    @bounded()
    async def test_iteration_stops_at_the_separator_because_it_was_asked_to(self):
        """`__aiter__` on a follow stream truncates at the boundary, and that is
        the contract rather than a defect: the shape is not on the wire, so the
        caller declaring the wrong one gets the wrong answer. This pins which
        wrong answer -- a truncation the caller can see in `terminated_by`, not a
        block that holds a node worker."""
        _, s = make(u8(1) + eos() + u8(9), close=False)
        async with s:
            self.assertEqual([o async for o in s], [P.Uint8(1)])
            self.assertEqual(s.terminated_by, "eos")


class ShapeHelperTest(unittest.IsolatedAsyncioTestCase):
    """`collect`, `value` and `first` -- the ST and RR helpers of section 4.7."""

    @bounded()
    async def test_collect_drains_to_the_terminator(self):
        for body, ending in ((u8(1) + u8(2) + eos(), "eos"), (u8(1) + u8(2), "eof")):
            with self.subTest(ending=ending):
                _, s = make(body)
                async with s:
                    self.assertEqual(await s.collect(), [P.Uint8(1), P.Uint8(2)])
                    self.assertEqual(s.terminated_by, ending)

    @bounded()
    async def test_value_returns_the_one_object_of_an_rr_op(self):
        for body in (u8(42), u8(42) + eos()):
            with self.subTest(body=body.hex()):
                _, s = make(body)
                async with s:
                    self.assertEqual(await s.value(), P.Uint8(42))

    @bounded()
    async def test_value_refuses_a_stream_that_answered_twice(self):
        """Returning the first and dropping the second would make this call's
        single return value a lie about the rest of the stream."""
        _, s = make(u8(1) + u8(2) + eos())
        async with s:
            with self.assertRaises(ProtocolError) as caught:
                await s.value()
        self.assertIn("at least two", str(caught.exception))

    @bounded()
    async def test_value_refuses_a_stream_that_answered_with_nothing(self):
        _, s = make(eos())
        async with s:
            with self.assertRaises(ProtocolError) as caught:
                await s.value()
        self.assertIn("ended with none", str(caught.exception))

    @bounded()
    async def test_first_is_none_at_the_end_and_does_not_insist_on_it(self):
        _, s = make(u8(1) + u8(2) + eos())
        async with s:
            self.assertEqual(await s.first(), P.Uint8(1))
            self.assertEqual(await s.first(), P.Uint8(2))
            self.assertIsNone(await s.first())

    @bounded()
    async def test_a_helper_deadline_is_reported_in_the_hierarchy(self):
        """A bare `TimeoutError` is outside `AstralError`, so a caller catching
        the documented catch-all would miss every deadline this class sets."""
        _, s = make(u8(1), close=False)
        async with s:
            with self.assertRaises(QueryTimeout):
                await s.collect(timeout=0.05)


class RawViewTest(unittest.IsolatedAsyncioTestCase):
    """RAW mode: `objects.read` answers with no framing at all."""

    @bounded()
    async def test_read_bytes_reads_the_unframed_body(self):
        _, s = make(b"\x00\x01not a frame")
        async with s:
            self.assertEqual(await s.read_bytes(), b"\x00\x01not a frame")
            self.assertEqual(s.terminated_by, "eof")

    @bounded()
    async def test_a_partial_raw_read_does_not_claim_the_stream_ended(self):
        _, s = make(b"abcdef")
        async with s:
            self.assertEqual(await s.read_bytes(3), b"abc")
            self.assertIsNone(s.terminated_by)
            self.assertEqual(await s.read_bytes(3), b"def")
            self.assertEqual(await s.read_bytes(3), b"")
            self.assertEqual(s.terminated_by, "eof")

    @bounded()
    async def test_the_framed_view_is_never_built_for_a_raw_body(self):
        """An accepted query does not always carry objects. Framing one that
        does not would decode the file as protocol."""
        _, s = make(b"plain bytes")
        async with s:
            await s.read_bytes()
            self.assertFalse(s.conn.framed)


class SendTest(unittest.IsolatedAsyncioTestCase):
    """The body-input ops. Passing their input as a query argument is the single
    most common way to get an op wrong, and on `crypto.verify_*` it silently
    never verifies."""

    @bounded()
    async def test_send_writes_one_frame_and_send_eos_terminates(self):
        remote, s = make(close=False)
        async with s:
            await s.send(Ack())
            await s.send_eos()
        got = await remote.read(len(frame("ack")) + len(eos()))
        self.assertEqual(got, frame("ack") + eos())

    @bounded()
    async def test_send_bytes_writes_unframed(self):
        remote, s = make(close=False)
        async with s:
            await s.send_bytes(b"raw input")
        self.assertEqual(await remote.read(9), b"raw input")

    @bounded()
    async def test_write_eof_half_closes_and_leaves_reading_open(self):
        """Verified live: after `shutdown(SHUT_WR)` on an accepted query the
        response object still arrived, then EOF."""
        remote, s = make(close=False)
        async with s:
            await s.send(Ack())
            await s.write_eof()
            self.assertEqual(await remote.read(-1), frame("ack"))
            remote.write(u8(5))
            remote.write_eof()
            self.assertEqual(await s.collect(), [P.Uint8(5)])

    @bounded()
    async def test_sending_on_a_closed_stream_raises(self):
        _, s = make()
        await s.aclose()
        with self.assertRaises(RuntimeError):
            await s.send(Ack())
        with self.assertRaises(RuntimeError):
            await s.send_bytes(b"x")
        with self.assertRaises(RuntimeError):
            await s.read_bytes()


class OneReaderTest(unittest.IsolatedAsyncioTestCase):
    """There is no multiplexing on the IPC leg, so two readers split one stream."""

    @bounded()
    async def test_a_second_concurrent_read_is_refused_and_the_first_survives(self):
        """The caller that broke the rule fails; the read it interrupted does not.

        Without the guard the second read fails inside `StreamReader` with a bare
        `RuntimeError` having already consumed part of a frame, and every later
        read is one frame out of step -- which is the responder choosing what the
        next message says.
        """
        remote, s = make(close=False)
        async with s:
            first = asyncio.create_task(s.first())
            await until(lambda: not first.done() and s._reading)  # noqa: SLF001
            with self.assertRaises(RuntimeError) as caught:
                await s.first()
            self.assertIn("already in flight", str(caught.exception))
            remote.write(u8(3))
            self.assertEqual(await first, P.Uint8(3))

    @bounded()
    async def test_sequential_readers_are_fine(self):
        _, s = make(u8(1) + u8(2))
        async with s:
            self.assertEqual(await s.first(), P.Uint8(1))
            self.assertEqual(await s.collect(), [P.Uint8(2)])


class LifetimeTest(unittest.IsolatedAsyncioTestCase):
    """Closing is the worker-pool discipline, and it is not deferred."""

    @bounded()
    async def test_aclose_is_idempotent_and_closes_the_transport(self):
        local, s = make()
        await s.aclose()
        self.assertTrue(s.closed)
        self.assertTrue(s.conn.closed)
        await s.aclose()
        self.assertTrue(s.closed)

    @bounded()
    async def test_a_second_concurrent_close_waits_for_the_first(self):
        """A close that returned early would report a connection released whose
        descriptor is still open, and a client counting that would count a node
        worker free that is still held."""
        _, s = make()
        first = asyncio.create_task(s.aclose())
        second = asyncio.create_task(s.aclose())
        await asyncio.gather(first, second)
        self.assertTrue(s.closed)

    @bounded()
    async def test_the_permit_is_released_after_the_descriptor_is_gone(self):
        """Releasing on entry would let the next query dial while this connection
        is still open, so a client bounded at N would hold N+1."""
        seen: list[tuple[bool, bool]] = []
        _, s = make(on_close=lambda st: seen.append((st.closed, st.conn.closed)))
        await s.aclose()
        self.assertEqual(seen, [(True, True)])

    @bounded()
    async def test_the_release_callback_runs_exactly_once(self):
        calls: list[Stream] = []
        _, s = make(on_close=calls.append)
        await s.aclose()
        await s.aclose()
        self.assertEqual(len(calls), 1)

    @bounded()
    async def test_a_faulty_release_callback_does_not_make_aclose_raise(self):
        """The descriptor is already gone by then, which is the part the node's
        worker pool depends on. A bookkeeping fault must not undo it."""

        def boom(_: Stream) -> None:
            raise RuntimeError("bookkeeping")

        _, s = make(on_close=boom)
        await s.aclose()
        self.assertTrue(s.closed)

    @bounded()
    async def test_the_context_manager_closes_on_the_exception_path(self):
        _, s = make()
        with self.assertRaises(ValueError):
            async with s:
                raise ValueError("boom")
        self.assertTrue(s.closed)

    @bounded()
    async def test_reading_a_closed_stream_raises_rather_than_ending_quietly(self):
        _, s = make(u8(1))
        await s.aclose()
        with self.assertRaises(RuntimeError):
            await s.first()

    @bounded()
    async def test_cancel_without_a_connector_reports_that_it_cannot(self):
        """A stream over a transport the caller supplied has no way to open the
        second connection a cancel needs, and says so rather than pretending."""
        _, s = make()
        async with s:
            self.assertFalse(await s.cancel())

    def test_repr_distinguishes_closing_from_closed(self):
        _, s = make()
        self.assertIn("open", repr(s))
        s._closing = True  # noqa: SLF001
        self.assertIn("closing", repr(s))
        s._closed = True  # noqa: SLF001
        self.assertIn("closed", repr(s))


class DirectionTest(unittest.TestCase):
    """Which identity is ours depends on which side sent the query."""

    def test_an_outbound_stream_is_local_caller_remote_target(self):
        _, s = make()
        self.assertTrue(s.outbound)
        self.assertEqual(s.local_id, CALLER)
        self.assertEqual(s.remote_id, FURRY_BOLT)
        self.assertEqual(s.nonce, NONCE)
        self.assertEqual(s.query_string, "apphost.whoami")
        self.assertIs(s.query, s.conn.query)

    def test_the_formats_are_the_query_strings_and_are_swapped_once(self):
        """`in=` is what the responder reads, so it is what this side writes.
        The channel takes the read format first, and the swap happens in one
        place -- here -- rather than in every call site."""
        _, s = make(fmt_in=Format.BIN, fmt_out=Format.BIN)
        self.assertEqual(s._read_fmt, Format.BIN)  # noqa: SLF001
        self.assertEqual(s._write_fmt, Format.BIN)  # noqa: SLF001


class AbandonedReadTest(unittest.IsolatedAsyncioTestCase):
    """A read cut off inside a frame makes the stream unusable, not plausible."""

    @bounded()
    async def test_a_timed_out_read_inside_a_frame_ends_the_stream(self):
        """The responder sends ONE object, header first and payload later, and
        the payload's own bytes spell a whole `ack` frame. Before the guard, the
        timeout was an ordinary catchable error, the stream still reported
        `closed=False terminated_by=None`, and the natural retry returned
        `Ack()` -- an object the responder never sent, out of an integer it did.
        Any responder can choose those bytes."""
        forged = frame("ack")  # 0x03 'a' 'c' 'k' 0x00 0x00 0x00 0x00
        self.assertEqual(len(forged), 8)
        head = frame("uint64", forged)[: -len(forged)]

        remote, s = make(head, close=False)
        async with s:
            with self.assertRaises(QueryTimeout):
                await s.first(timeout=0.05)
            remote.write(forged)

            self.assertTrue(s.corrupt)
            self.assertTrue(s.closing)
            with self.assertRaises(StreamCorrupted):
                await s.first(timeout=0.5)

    @bounded()
    async def test_a_read_abandoned_at_a_frame_boundary_stays_harmless(self):
        """What makes an idle follow stream's deadline safe: nothing was
        consumed, so nothing is out of step and the stream survives."""
        remote, s = make(close=False)
        async with s:
            with self.assertRaises(QueryTimeout):
                await s.first(timeout=0.05)
            self.assertFalse(s.corrupt)
            self.assertFalse(s.closing)
            remote.write(u8(9))
            self.assertEqual(await s.first(timeout=0.5), P.Uint8(9))

    @bounded()
    async def test_the_guard_lives_on_the_query_stream_so_every_reader_has_it(self):
        """`QueryStream.receive()` is public and is the third site of this class,
        alongside `Session._recv` and `Stream`. Putting the rule there is what
        makes it one implementation rather than three that drift."""
        forged = frame("ack")
        head = frame("uint64", forged)[: -len(forged)]
        local, remote = MemTransport.pair("conn")
        remote.write(head)
        conn = QueryStream(local, a_query())
        async with conn:
            with self.assertRaises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await conn.receive()
            remote.write(forged)
            self.assertTrue(conn.corrupt)
            self.assertTrue(conn.closed)
            with self.assertRaises(StreamCorrupted):
                await conn.receive()
            with self.assertRaises(StreamCorrupted):
                async for _ in conn:
                    pass

    @bounded()
    async def test_a_corrupt_stream_hands_back_its_connection_permit(self):
        """The connection is gone the moment the boundary is lost; the *permit*
        and the client's registration are the layer above's, and a bounded client
        that never got them back would be one connection short for the rest of
        its life over a connection that no longer exists."""
        released: list[Stream] = []
        forged = frame("ack")
        head = frame("uint64", forged)[: -len(forged)]
        _, s = make(head, close=False, on_close=released.append)
        async with s:
            with self.assertRaises(QueryTimeout):
                await s.first(timeout=0.05)
            # Inside the block, and that is the assertion: the connection is
            # already gone, so waiting for the caller's `async with` to end
            # would hold the permit over nothing.
            self.assertEqual(released, [s])
            self.assertTrue(s.closed)
        self.assertEqual(released, [s])

    @bounded()
    async def test_a_cancelled_read_inside_a_frame_ends_the_stream_too(self):
        """A deadline and a caller's own `cancel()` arrive identically."""
        forged = frame("ack")
        head = frame("uint64", forged)[: -len(forged)]
        _, s = make(head, close=False)
        async with s:
            task = asyncio.ensure_future(s.first())
            await until(lambda: s._reading)  # noqa: SLF001
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(s.corrupt)
            with self.assertRaises(StreamCorrupted):
                await s.first(timeout=0.5)


class RawModeTest(unittest.IsolatedAsyncioTestCase):
    """A RAW stream is unframed bytes, and refuses to be read as protocol."""

    @bounded()
    async def test_the_declaration_is_visible_and_is_off_by_default(self):
        _, s = make()
        self.assertFalse(s.raw)
        _, r = make(raw=True)
        self.assertTrue(r.raw)

    @bounded()
    async def test_raw_bytes_on_an_undeclared_stream_stay_legal(self):
        """The rule is one-way on purpose: reading a frame and then the tail raw
        is a real op shape, and the two views share one buffer by design."""
        _, s = make(u8(1) + b"tail")
        async with s:
            self.assertEqual(await s.first(), P.Uint8(1))
            self.assertEqual(await s.read_bytes(), b"tail")


if __name__ == "__main__":
    unittest.main()
