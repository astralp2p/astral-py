"""Tier B: inbound serving -- the listener, the op table, and the registrar.

The gate of implementation step 10, and each part of it is here because the
failure it catches is invisible from inside the SDK:

1. **Every serving path is exercised against a dialer that is not the SDK.**
   `MockDialer` writes `mod.apphost.handle_query_msg` from hand-rolled bytes and
   asserts the SDK answers exactly one of `ack`, `query_rejected_msg`,
   `error_msg` or a close (design section 4.3 step 9), so a wrong layout on one
   side cannot agree with a wrong layout on the other.
2. **Concurrency, because astral-go does not have it.** `Handler.Route` accepts
   one connection, blocks on its first frame and then blocks on routing before
   accepting the next, so one slow dialer stalls every inbound query (astral-go
   bug G-14). The test that catches it dials three times and requires all three
   to be in a handler at once.
3. **Nothing leaks, down any path.** A handler that raises, a handler that never
   answers, a token mismatch, a first frame that never arrives, a cancelled
   service: each ends with the kernel asked whether a descriptor is still open.
   A flag is a promise, a descriptor is a fact, and an abandoned connection is
   one of astrald's 32 apphost workers held until the node restarts (bug G-13).
4. **The registration order is the node's, not a preference.** `apphost.bind`
   before `apphost.register_handler` before `bind_msg` before the hooks, and the
   bind stream closed last, because that stream is the only deterministic
   deregistration astrald has: handler removal is otherwise lazy, on the next
   failed push (astral-docs bug D-13).

Every async test is `bounded`; no test in this file contacts a node.

**Step 10's gate is only half met, and `LiveServeTest` records why.** Design
section 10 gates this step on the `MockDialer` suite *and* a live
register-handler round trip when a token is available. There is no token in this
environment, so the live half skips and every path in `serve.py` and
`registrar.py` rests on `MockApphost` and `MockDialer` -- which cannot falsify
the BD and RR declarations `apphost.bind` and `apphost.register_handler` carry,
because the mocks were written from the same reading of the same source. Those
two were checked against astrald's source instead, which is weaker evidence and
is named as such where it is used.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import unittest

import astral
from astral.client import DEFAULT_MAX_PERSISTENT, Client, connect
from astral.errors import (
    BadArgument,
    Denied,
    NodeUnavailable,
    FeatureUnavailable,
    ProtocolError,
    QueryTimeout,
    RemoteError,
    RouteNotFound,
    StreamClosed,
    TransportUnsupported,
)
from astral.object import Ack, EOS, ErrorMessage
from astral.registrar import (
    DEFAULT_JITTER,
    Gate,
    OP_REGISTER_SEARCHER,
    Registrar,
    Registration,
    op_hook,
)
from astral.serve import (
    DEFAULT_PROTO,
    ERROR_HISTORY,
    OP_SEARCH,
    IncomingQuery,
    PendingQuery,
    Service,
    echo_handler,
    object_handler,
)
from astral.session import (
    OP_BIND,
    OP_REGISTER_HANDLER,
    REJECT_INVALID_QUERY,
    Session,
)
from astral.spec import Primitive
from astral.transport import Transport, dial
from astral.types import Identity, Nonce
from astral.wire import Writer

from mock_apphost import (
    ACK,
    EOS as EOS_TYPE,
    Accept,
    ErrorMsg as ErrorRoute,
    FURRY_BOLT,
    INCOMING_QUERY,
    QUERY_REJECTED,
    MockApphost,
    MockConn,
    RouteQuery,
    bounded,
    frame,
    incoming_query_payload,
    leaked_sockets,
    parse_attach_query,
    parse_register_service,
    parse_reject_incoming,
    socket_fds,
    until,
)
from mock_dialer import MockDialer

OTHER = Identity.parse("02" + "11" * 32)


def u8(value: int) -> tuple[str, bytes]:
    return ("uint8", bytes([value]))


def error_frame(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ACK_ONCE = Accept(objects=[(ACK, b"")])
"""What `apphost.register_handler` and every `objects.register_*` op answer: one
`ack`, then the responder closes. Registration is not channel-scoped -- astrald's
`OpRegisterSearcher` returns into a deferred `ch.Close()` (design section 4.6)."""

BIND_ROUTE = Accept(objects=[(ACK, b"")], read=True)
"""What `apphost.bind` answers: one `ack`, then it reads `bind_msg` objects until
the guest closes, and removes every handler registered under those tokens."""


def registrar_routes(**extra: object) -> dict[str, object]:
    """The two ops a registrar needs, plus whatever a test adds."""
    routes: dict[str, object] = {OP_BIND: BIND_ROUTE, OP_REGISTER_HANDLER: ACK_ONCE}
    routes.update(extra)
    return routes


# --- the case ------------------------------------------------------------


class ServeCase(unittest.IsolatedAsyncioTestCase):
    """Services and dialers, closed by the teardown, with the descriptors counted."""

    async def asyncSetUp(self) -> None:
        self.services: list[Service] = []
        self.dialers: list[MockDialer] = []
        self.clients: list[Client] = []
        # Taken inside the loop, so the loop's own self-pipe is in the baseline.
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for dialer in self.dialers:
            await dialer.aclose()
        for service in self.services:
            await service.aclose()
        for client in self.clients:
            await client.aclose()

    async def service(self, **kw: object) -> Service:
        """A listening service, closed by the teardown whatever the test does."""
        service = Service(**kw)  # type: ignore[arg-type]
        self.services.append(service)
        await service.listen(DEFAULT_PROTO)
        return service

    def dialer(self, service: Service, **kw: object) -> MockDialer:
        dialer = MockDialer(service.endpoint, service.token, **kw)  # type: ignore[arg-type]
        self.dialers.append(dialer)
        return dialer

    async def client(
        self, mock: MockApphost, *, token: str | None = None, **kw: object
    ) -> Client:
        async def open_session() -> Session:
            return await Session.over(
                await mock.open(),
                endpoint="mem:mock",
                token=token,
                connector=open_session,
            )

        client = await connect(connector=open_session, **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return client

    async def assert_no_open_sockets(self) -> None:
        if self.sockets_before is None:  # pragma: no cover -- Linux in this tree
            self.skipTest("no /proc/self/fd: descriptors cannot be counted here")
        base = self.sockets_before
        leaked = leaked_sockets(base)
        if leaked:
            # asyncio releases a descriptor from a `call_soon` callback, so the
            # table settles a turn after the close rather than inside it.
            await until(lambda: not leaked_sockets(base))
            leaked = leaked_sockets(base)
        self.assertEqual(
            leaked,
            set(),
            f"{len(leaked)} socket descriptor(s) left open: {sorted(leaked)} -- "
            "each one is a node worker of 32",
        )


# --- the answer, and the four ways to give it -----------------------------


class AnswerTest(ServeCase):
    """Design section 4.3 step 9: exactly one of four answers, and nothing else."""

    @bounded()
    async def test_a_mounted_op_accepts_and_streams_its_answer(self):
        """The ack is one frame and the body follows it on the same connection.
        The acceptance is written before the handler is given the writer at all,
        which is the whole of astral-go's `lockableWriteCloser` and needs no lock."""
        service = await self.service()
        service.mount("x.hello", object_handler([Ack()]))
        dialer = self.dialer(service)

        answered = await dialer.query("x.hello")
        self.assertTrue(answered.accepted, answered)
        body = await dialer.objects(answered.conn)
        self.assertEqual([t for t, _ in body], [ACK, EOS_TYPE])
        self.assertEqual(service.served, 1)

    @bounded()
    async def test_an_unmounted_op_is_skipped(self):
        """`error_msg{route_not_found}`: the caller is told exactly what it would
        have been told had this handler never been registered, which is
        astral-go's `Skip()` and `OpRouter`'s `RouteNotFound` alike."""
        service = await self.service()
        dialer = self.dialer(service)
        answered = await dialer.query("x.nothing")
        self.assertTrue(answered.route_not_found, answered)

    @bounded()
    async def test_a_rejection_carries_its_code(self):
        service = await self.service()

        async def refuse(q: PendingQuery) -> None:
            await q.reject(4)

        service.mount("x.no", refuse)
        answered = await self.dialer(service).query("x.no")
        self.assertEqual(answered.kind, QUERY_REJECTED)
        self.assertEqual(answered.code, 4)

    @bounded()
    async def test_reject_code_zero_is_refused_and_leaves_the_query_answerable(self):
        """0 is success in astral-go's own table. Its three responder paths
        disagree -- two coerce it and `apps.PendingQuery.RejectWithCode` puts it
        on the wire -- so a silent rewrite hides a caller's bug and is not even
        applied consistently. The refusal happens before the answer is claimed,
        so the handler can still answer properly."""
        service = await self.service()
        seen: list[BaseException] = []

        async def bad(q: PendingQuery) -> None:
            try:
                await q.reject(0)
            except BadArgument as exc:
                seen.append(exc)
            self.assertFalse(q.answered)
            await q.reject(1)

        service.mount("x.zero", bad)
        answered = await self.dialer(service).query("x.zero")
        self.assertEqual(answered.code, 1)
        self.assertEqual(len(seen), 1)

    @bounded()
    async def test_closing_answers_nothing_at_all(self):
        """astrald's `ch.Switch(ExpectAck, ...)` reads the close through its
        catch-all error branch as `route_not_found`, so the caller is told the
        same thing one frame later and with no frame on the wire."""
        service = await self.service()

        async def hang_up(q: PendingQuery) -> None:
            await q.aclose()

        service.mount("x.bye", hang_up)
        answered = await self.dialer(service).query("x.bye")
        self.assertEqual(answered.kind, "closed")

    @bounded()
    async def test_a_second_answer_is_refused(self):
        """One query has one answer. A second frame on the same connection is one
        the node reads as belonging to the response body."""
        service = await self.service()
        seen: list[BaseException] = []

        async def twice(q: PendingQuery) -> None:
            await q.reject(1)
            try:
                await q.skip()
            except StreamClosed as exc:
                seen.append(exc)

        service.mount("x.twice", twice)
        answered = await self.dialer(service).query("x.twice")
        self.assertEqual(answered.code, 1)
        await until(lambda: bool(seen))
        self.assertEqual(len(seen), 1)
        self.assertIn("already rejected", str(seen[0]))

    @bounded()
    async def test_a_handler_that_answers_nothing_has_the_query_skipped(self):
        """astrald's `IPCHandler.RouteQuery` calls `ch.Switch(ExpectAck, ...)`
        with no deadline and no context, so an unanswered query blocks that
        goroutine for as long as the connection lives. A handler that forgets is
        the commonest way to produce one."""
        service = await self.service()

        async def forget(q: PendingQuery) -> None:
            return None

        service.mount("x.forget", forget)
        answered = await self.dialer(service).query("x.forget")
        self.assertTrue(answered.route_not_found, answered)

    @bounded()
    async def test_a_handler_that_raises_has_the_query_skipped_and_the_fault_kept(self):
        service = await self.service()

        async def boom(q: PendingQuery) -> None:
            raise ZeroDivisionError("handler fault")

        service.mount("x.boom", boom)
        answered = await self.dialer(service).query("x.boom")
        self.assertTrue(answered.route_not_found, answered)
        self.assertTrue(any(isinstance(e, ZeroDivisionError) for e in service.errors))

    @bounded()
    async def test_an_unanswered_query_is_skipped_when_the_answer_deadline_expires(self):
        """The deadline bounds the decision and not the body: astrald waits for
        the `ack` forever, so a handler that neither accepts nor rejects pins one
        of its goroutines."""
        service = await self.service(answer_timeout=0.1)
        release = asyncio.Event()

        async def stall(q: PendingQuery) -> None:
            await release.wait()

        service.mount("x.stall", stall)
        try:
            answered = await self.dialer(service).query("x.stall")
            self.assertTrue(answered.route_not_found, answered)
            self.assertTrue(any(isinstance(e, TimeoutError) for e in service.errors))
        finally:
            release.set()

    @bounded()
    async def test_the_answer_deadline_does_not_bound_the_response_body(self):
        """A follow-mode responder streams for hours after its `ack`. Bounding
        the body would kill exactly the ops the deadline exists to protect."""
        service = await self.service(answer_timeout=0.1)
        release = asyncio.Event()

        async def slow_body(q: PendingQuery) -> None:
            async with await q.accept() as stream:
                await release.wait()
                await stream.send(Ack())
                await stream.send_eos()

        service.mount("x.slow", slow_body)
        dialer = self.dialer(service)
        answered = await dialer.query("x.slow")
        self.assertTrue(answered.accepted, answered)
        await asyncio.sleep(0.25)
        release.set()
        body = await dialer.objects(answered.conn)
        self.assertEqual([t for t, _ in body], [ACK, EOS_TYPE])


# --- the first frame, and what a bad one costs ----------------------------


class FirstFrameTest(ServeCase):
    """Design section 4.3 step 8: neither failure kills the listener."""

    @bounded()
    async def test_a_token_mismatch_is_denied_and_the_listener_keeps_serving(self):
        """The token is the only thing between this listener and any local
        process that finds the socket, so a mismatch must be cheap for the
        listener and fatal for that one connection."""
        service = await self.service()
        service.mount("x.ok", object_handler([Ack()]))
        dialer = self.dialer(service)

        answered = await dialer.query("x.ok", token=Nonce(int(service.token) ^ 1))
        self.assertTrue(answered.denied, answered)

        good = await dialer.query("x.ok")
        self.assertTrue(good.accepted, good)

    @bounded()
    async def test_a_wrong_first_frame_type_is_a_protocol_error(self):
        """The first frame is `handle_query_msg` and nothing else. `ping_msg` is
        the exact frame astrald itself answers `protocol_error` to (bug G-17)."""
        service = await self.service()
        service.mount("x.ok", object_handler([Ack()]))
        dialer = self.dialer(service)

        conn = await dialer.send_first("mod.apphost.ping_msg")
        answered = await dialer.read_answer(conn)
        self.assertTrue(answered.protocol_error, answered)

        good = await dialer.query("x.ok")
        self.assertTrue(good.accepted, good)

    @bounded()
    async def test_a_first_frame_that_never_arrives_closes_one_connection(self):
        service = await self.service(first_frame_timeout=0.1)
        service.mount("x.ok", object_handler([Ack()]))
        dialer = self.dialer(service)

        conn = await dialer.silent()
        answered = await dialer.read_answer(conn, timeout=2.0)
        self.assertEqual(answered.kind, "closed")

        good = await dialer.query("x.ok")
        self.assertTrue(good.accepted, good)

    @bounded()
    async def test_an_unparsable_first_frame_does_not_kill_the_listener(self):
        service = await self.service(first_frame_timeout=1.0)
        service.mount("x.ok", object_handler([Ack()]))
        dialer = self.dialer(service)

        conn = await dialer.open()
        conn.send_raw(b"GET / HTTP/1.1\r\n\r\n")
        await conn.flush()
        await conn.transport.aclose()

        good = await dialer.query("x.ok")
        self.assertTrue(good.accepted, good)


# --- concurrency, which astral-go does not have ---------------------------


class ConcurrencyTest(ServeCase):
    @bounded()
    async def test_three_dialers_are_in_a_handler_at_once(self):
        """astral-go's accept loop accepts one connection, blocks on its first
        frame and then blocks on routing before accepting the next, so one slow
        dialer stalls every other inbound query (bug G-14). This deadlocks
        against that loop and passes against a task per connection."""
        service = await self.service()
        barrier = asyncio.Barrier(3)

        async def wait_for_siblings(q: PendingQuery) -> None:
            await barrier.wait()
            async with await q.accept() as stream:
                await stream.send_eos()

        service.mount("x.together", wait_for_siblings)
        dialer = self.dialer(service)

        answers = await asyncio.gather(
            *(dialer.query("x.together", timeout=4.0) for _ in range(3))
        )
        self.assertTrue(all(a.accepted for a in answers), answers)
        self.assertEqual(service.served, 3)

    @bounded()
    async def test_a_stalled_handler_does_not_stall_the_next_query(self):
        service = await self.service(answer_timeout=None)
        release = asyncio.Event()

        async def stall(q: PendingQuery) -> None:
            await release.wait()
            await q.skip()

        async def quick(q: PendingQuery) -> None:
            await q.reject(2)

        service.mount("x.stall", stall)
        service.mount("x.quick", quick)
        dialer = self.dialer(service)
        try:
            stalled = asyncio.ensure_future(dialer.query("x.stall", timeout=4.0))
            await until(lambda: service.served >= 1)
            quickly = await dialer.query("x.quick")
            self.assertEqual(quickly.code, 2)
            self.assertFalse(stalled.done())
        finally:
            release.set()
            await stalled


# --- the op table ---------------------------------------------------------


class OpTableTest(ServeCase):
    @bounded()
    async def test_declared_parameters_are_decoded_and_the_rest_stay_text(self):
        """A query string carries the bare payload half of each value's text
        encoding and not its type, so the type comes from the declaration or from
        nowhere. An undeclared key still reaches the handler as text; astrald
        drops it (astral-docs bug D-17)."""
        service = await self.service()
        seen: list[PendingQuery] = []

        async def record(q: PendingQuery) -> None:
            seen.append(q)
            await q.reject(1)

        service.mount("x.args", record, params={"n": Primitive("uint16")})
        await self.dialer(service).query("x.args?n=513&extra=hi")
        self.assertEqual(seen[0].args["n"], 513)
        self.assertEqual(seen[0].params["extra"], "hi")
        self.assertNotIn("extra", seen[0].args)
        self.assertEqual(seen[0].op, "x.args")

    @bounded()
    async def test_a_missing_required_parameter_is_an_invalid_query(self):
        """Code 2 is `CodeInvalidQuery` in astral-go's own table, and this is
        exactly that: the op exists, the arguments do not satisfy it."""
        service = await self.service()
        service.mount(
            "x.need",
            object_handler([Ack()]),
            params={"id": Primitive("string8")},
            required=["id"],
        )
        answered = await self.dialer(service).query("x.need")
        self.assertEqual(answered.code, REJECT_INVALID_QUERY)

    @bounded()
    async def test_an_unparsable_parameter_is_an_invalid_query(self):
        service = await self.service()
        service.mount("x.args", object_handler([Ack()]), params={"n": Primitive("uint8")})
        answered = await self.dialer(service).query("x.args?n=999")
        self.assertEqual(answered.code, REJECT_INVALID_QUERY)

    @bounded()
    async def test_the_fallback_handler_serves_what_no_op_claims(self):
        seen: list[str] = []

        async def fallback(q: PendingQuery) -> None:
            seen.append(q.op)
            await q.reject(1)

        service = await self.service(handler=fallback)
        service.mount("x.claimed", object_handler([Ack()]))
        await self.dialer(service).query("x.unclaimed?a=1")
        self.assertEqual(seen, ["x.unclaimed"])

    def test_mounting_a_name_twice_is_refused(self):
        service = Service()
        service.mount("x.a", object_handler([]))
        with self.assertRaises(BadArgument):
            service.mount("x.a", object_handler([]))
        service.unmount("x.a")
        with self.assertRaises(BadArgument):
            service.unmount("x.a")

    def test_a_required_parameter_with_no_spec_is_refused(self):
        """Nothing would decode it, so the requirement could never be met."""
        service = Service()
        with self.assertRaises(BadArgument):
            service.mount("x.a", object_handler([]), required=["id"])

    def test_the_provider_sugar_mounts_the_op_and_adds_the_hook(self):
        """Design section 4.6: the app serves the scoped op on its own identity
        and re-registers after every reconnect. There is no serving loop."""
        service = Service()
        service.add_searcher(object_handler([]))
        self.assertEqual(service.mounted, (OP_SEARCH,))
        self.assertEqual(len(service.hooks), 1)


# --- the framing a responder may write ------------------------------------


class FramingTest(ServeCase):
    @bounded()
    async def test_a_format_this_sdk_cannot_write_leaves_the_query_answerable(self):
        """A node silently accepts an unknown `out=` and produces zero bytes
        (astral-docs bug D-24). A responder that accepted and then wrote nothing
        would reproduce it, so the acceptance is refused **before** it is claimed
        and the query is skipped."""
        service = await self.service()
        seen: list[BaseException] = []

        async def try_accept(q: PendingQuery) -> None:
            try:
                await q.accept()
            except TransportUnsupported as exc:
                seen.append(exc)
            self.assertFalse(q.answered)

        service.mount("x.json", try_accept)
        answered = await self.dialer(service).query("x.json?out=json")
        self.assertTrue(answered.route_not_found, answered)
        self.assertEqual(len(seen), 1)

    @bounded()
    async def test_a_format_disagreement_is_refused_rather_than_resolved(self):
        """The caller built its own channel from the query string, so a responder
        that quietly preferred either answer would frame one exchange two ways.
        `Client._framing` applies the same rule from the other side."""
        service = await self.service()
        seen: list[BaseException] = []

        async def wrong_format(q: PendingQuery) -> None:
            try:
                await q.accept(fmt_out="text")
            except BadArgument as exc:
                seen.append(exc)
            await q.accept()

        service.mount("x.fmt", wrong_format)
        answered = await self.dialer(service).query("x.fmt?out=bin")
        self.assertTrue(answered.accepted, answered)
        self.assertEqual(len(seen), 1)
        self.assertIn("cannot differ", str(seen[0]))

    @bounded()
    async def test_echo_reads_and_writes_on_one_accepted_stream(self):
        """The bidirectional shape, and the smallest complete responder."""
        service = await self.service()
        service.mount("x.echo", echo_handler())
        dialer = self.dialer(service)

        answered = await dialer.query("x.echo")
        self.assertTrue(answered.accepted, answered)
        conn = answered.conn
        conn.send_raw(frame("uint8", bytes([7])) + frame(EOS_TYPE))
        await conn.flush()
        body = await dialer.objects(conn)
        self.assertEqual(body, [u8(7), (EOS_TYPE, b"")])

    @bounded()
    async def test_an_error_message_object_is_the_responders_to_send(self):
        """An `error_message` in a query stream is data on this side of the wire
        and a `RemoteError` on the caller's. The responder writes one; nothing
        here turns it into an exception."""
        service = await self.service()
        service.mount("x.err", object_handler([ErrorMessage("record not found")]))
        dialer = self.dialer(service)
        answered = await dialer.query("x.err")
        body = await dialer.objects(answered.conn)
        self.assertEqual(body, [error_frame("record not found"), (EOS_TYPE, b"")])


# --- shutdown and leaks ---------------------------------------------------


class ShutdownTest(ServeCase):
    @bounded()
    async def test_aclose_closes_the_listener_and_every_live_connection(self):
        service = await self.service(answer_timeout=None)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def hold(q: PendingQuery) -> None:
            async with await q.accept():
                entered.set()
                await release.wait()

        service.mount("x.hold", hold)
        dialer = self.dialer(service)
        answered = await dialer.query("x.hold")
        self.assertTrue(answered.accepted, answered)
        await entered.wait()
        self.assertEqual(
            service.live_queries, 1, "the session became the stream at the acceptance"
        )

        endpoint = service.endpoint
        closer = asyncio.ensure_future(service.aclose())
        await asyncio.sleep(0)
        release.set()
        await closer

        self.assertTrue(service.closed)
        self.assertEqual(service.live_queries, 0)
        with self.assertRaises(astral.AstralError):
            await dial(endpoint)
        await dialer.aclose()
        await self.assert_no_open_sockets()

    @bounded()
    async def test_an_accepted_stream_closes_when_its_handler_returns(self):
        """One inbound query is one connection, so a handler that returns holding
        its stream has leaked one of astrald's 32 apphost workers. The service
        closes it whether the handler did or not."""
        service = await self.service()
        kept: list[object] = []

        async def leak(q: PendingQuery) -> None:
            kept.append(await q.accept())

        service.mount("x.leak", leak)
        dialer = self.dialer(service)
        answered = await dialer.query("x.leak")
        self.assertTrue(answered.accepted, answered)
        await until(lambda: bool(kept) and kept[0].closed)  # type: ignore[attr-defined]
        self.assertTrue(kept[0].closed)  # type: ignore[attr-defined]

    @bounded()
    async def test_aclose_is_idempotent_and_a_second_caller_waits(self):
        service = await self.service()
        await service.aclose()
        self.assertTrue(service.closed)
        await asyncio.gather(service.aclose(), service.aclose())
        self.assertTrue(service.closed)

    @bounded()
    async def test_a_service_closed_while_a_handler_hangs_still_returns(self):
        """The task group cancels every child on the way out, so a handler
        awaiting something the service does not own bounds the shutdown at
        `close_timeout` rather than making it unbounded."""
        service = await self.service(answer_timeout=None, close_timeout=0.3)
        entered = asyncio.Event()

        async def forever(q: PendingQuery) -> None:
            await q.accept()
            entered.set()
            await asyncio.Event().wait()

        service.mount("x.forever", forever)
        dialer = self.dialer(service)
        answered = await dialer.query("x.forever")
        self.assertTrue(answered.accepted, answered)
        await entered.wait()

        await service.aclose()
        self.assertTrue(service.closed)
        await dialer.aclose()
        await self.assert_no_open_sockets()

    @bounded()
    async def test_every_refusal_path_closes_its_descriptor(self):
        service = await self.service(first_frame_timeout=0.2, answer_timeout=0.2)

        async def boom(q: PendingQuery) -> None:
            raise ZeroDivisionError

        service.mount("x.boom", boom)
        dialer = self.dialer(service)

        await dialer.query("x.none")
        await dialer.query("x.boom")
        await dialer.query("x.none", token=Nonce(int(service.token) ^ 1))
        conn = await dialer.send_first("mod.apphost.ping_msg")
        await dialer.read_answer(conn)
        silent = await dialer.silent()
        await dialer.read_answer(silent, timeout=2.0)

        await dialer.aclose()
        await service.aclose()
        await self.assert_no_open_sockets()

    def test_listening_before_start_is_refused(self):
        service = Service()
        with self.assertRaises(StreamClosed):
            _ = service.endpoint

    @bounded()
    async def test_a_listen_that_fails_to_bind_owns_no_task(self):
        """`_start()` runs before the bind, deliberately -- the accept loop has
        to exist before the listener does -- and a bind that then raised left the
        `astral-service` supervisor parked inside an open `TaskGroup` with
        nothing to set `_stop`. The natural reaction to "address already in use"
        is to drop the object, and the object could not say it still owned a
        task: `listening` False, `closed` False, and under `-X dev` a "Task was
        destroyed but it is pending"."""
        held = await self.service()
        endpoint = held.endpoint

        before = {t for t in asyncio.all_tasks() if t.get_name() == "astral-service"}
        doomed = Service()
        with self.assertRaises(astral.AstralError):
            await doomed.listen(DEFAULT_PROTO, endpoint=endpoint)
        self.assertFalse(doomed.listening)
        after = {t for t in asyncio.all_tasks() if t.get_name() == "astral-service"}
        self.assertEqual(
            after - before, set(), "the failed listen() left a supervisor running"
        )
        # And the object is still usable: the undo replaced the stop event
        # rather than leaving one already set.
        self.assertIsNotNone(await doomed.listen(DEFAULT_PROTO))
        self.assertTrue(doomed.listening)
        await doomed.aclose()

    @bounded()
    async def test_a_listen_that_fails_keeps_a_supervisor_the_caller_entered(self):
        """The undo is scoped to what the failing call started. A service the
        caller entered with `async with` owns its task group, and a bind that
        does not take must not close it under them."""
        held = await self.service()
        async with Service() as entered:
            supervisor = entered._supervisor
            self.assertIsNotNone(supervisor)
            with self.assertRaises(astral.AstralError):
                await entered.listen(DEFAULT_PROTO, endpoint=held.endpoint)
            self.assertIs(entered._supervisor, supervisor)
            self.assertFalse(supervisor.done())

    @bounded(30.0)
    async def test_a_cancelled_aclose_releases_everything_and_reports_closing(self):
        """The canonical bounded shutdown is `wait_for(service.aclose(), t)`, and
        a `CancelledError` landing in the walk used to stop it wherever it landed
        while the `finally` marked the service closed anyway -- five inbound
        queries still live, six tasks still running, and a second `aclose()`
        returning at once on the idempotent fast path. Every step is shielded, so
        it finishes regardless, and `closed` is latched only when nothing is
        left."""
        for turns_before_cancel in (1, 2, 3, 5):
            with self.subTest(turns=turns_before_cancel):
                service = await self.service(answer_timeout=0.2, close_timeout=1.0)

                async def hold(q: PendingQuery) -> None:
                    async with await q.accept():
                        await asyncio.Event().wait()

                service.mount("x.hold", hold)
                dialers = [self.dialer(service) for _ in range(4)]
                for dialer in dialers:
                    self.assertTrue((await dialer.query("x.hold")).accepted)
                await until(lambda: service.live_queries >= 4)

                closer = asyncio.ensure_future(service.aclose())
                for _ in range(turns_before_cancel):
                    await asyncio.sleep(0)
                closer.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await closer

                # The state is honest: the walk did not finish, so the service
                # is `closing` and not `closed`. This is the half that used to
                # be a lie, and it is what makes the retry below do anything.
                self.assertTrue(service.closing)
                self.assertFalse(
                    service.closed, "latched closed with connections still live"
                )
                # And the walk resumes rather than short-circuiting.
                await service.aclose()
                self.assertTrue(service.closed)
                self.assertEqual(
                    service.live_queries,
                    0,
                    "a cancelled teardown abandoned live connections",
                )
                for dialer in dialers:
                    await dialer.aclose()
                await self.assert_no_open_sockets()

    @bounded()
    async def test_a_service_that_could_not_finish_closing_does_not_report_closed(self):
        """`closed` is the drained fact, not the call. A supervisor that outlived
        both budgets, a session still held, a registrar still open: any one of
        them leaves the service `closing`, because a caller that believed
        `closed` would count node workers free that are still held."""
        service = await self.service()
        self.assertFalse(service.closed)
        self.assertFalse(service.closing)
        # A registrar that has not been closed is enough on its own.
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            service.attach_registrar(registrar)
            await service.aclose()
            self.assertTrue(registrar.closed)
            self.assertTrue(service.closed)


# --- the readiness gate ---------------------------------------------------


class GateTest(unittest.IsolatedAsyncioTestCase):
    """The generation semantics of astral-go's `sig.Value[chan struct{}]`."""

    @bounded()
    async def test_a_generation_admitted_stays_admitted(self):
        """A waiter admitted by generation n is not retracted by a later
        disconnect: the decision was made when it sampled the gate, and
        `Event.clear()` would unmake it behind the task that made it."""
        gate = Gate()
        gate.open()
        generation = gate.snapshot()
        gate.close()
        self.assertFalse(gate.is_open)
        self.assertTrue(generation.is_set())
        await asyncio.wait_for(generation.wait(), 1.0)

    @bounded()
    async def test_a_waiter_that_arrives_after_a_close_waits_for_the_next_open(self):
        gate = Gate()
        gate.open()
        gate.close()
        waiter = asyncio.ensure_future(gate.wait(2.0))
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())
        gate.open()
        await waiter

    @bounded()
    async def test_an_expired_wait_is_in_the_hierarchy(self):
        """A bare `TimeoutError` is outside `AstralError`, so a caller catching
        the documented catch-all would miss it."""
        gate = Gate()
        with self.assertRaises(QueryTimeout):
            await gate.wait(0.01)
        self.assertIsInstance(Gate(), Gate)


# --- the registrar --------------------------------------------------------


class RegistrarTest(ServeCase):
    @bounded()
    async def test_the_registration_order_is_bind_then_op_then_token_then_hooks(self):
        """astrald removes a handler eagerly only through `op_bind`'s deferred
        `removeHandlersByToken`; everything else is lazy, on the next failed push
        (astral-docs bug D-13). So the bind session has to exist before the
        handler does, and the token has to reach it."""
        async with MockApphost(
            routes=registrar_routes(**{OP_REGISTER_SEARCHER: ACK_ONCE})
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            registrar.add_hook(op_hook(OP_REGISTER_SEARCHER))
            token = Nonce.random()
            await registrar.register("unix:/tmp/x.sock", token)
            await registrar.start()
            try:
                self.assertTrue(registrar.ready)
                self.assertEqual(
                    [q.op for q in mock.queries],
                    [OP_BIND, OP_REGISTER_HANDLER, OP_REGISTER_SEARCHER],
                )
                handler_query = mock.queries[1]
                self.assertIn("endpoint=unix%3A%2Ftmp%2Fx.sock", handler_query.query)
                self.assertIn(f"token={token}", handler_query.query)
                await until(lambda: bool(mock.bind_tokens))
                self.assertEqual(mock.bind_tokens, [token])
            finally:
                await registrar.aclose()

    @bounded()
    async def test_a_node_that_refuses_bind_is_an_exception_not_a_retry(self):
        """Retrying belongs to a connection that worked and then dropped.
        Retrying one that never worked turns a permanent misconfiguration into a
        service that silently answers nothing. astral-go draws the same line:
        `AppRegistrar.run` returns on a failed dial."""
        async with MockApphost() as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            with self.assertRaises(RouteNotFound):
                await registrar.start()
            self.assertFalse(registrar.ready)
            self.assertFalse(registrar.running)
            self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT)
            await registrar.aclose()

    @bounded()
    async def test_a_hook_that_fails_aborts_the_cycle_and_closes_the_bind_stream(self):
        """A half-registered app answers queries it cannot serve."""
        async with MockApphost(
            routes=registrar_routes(
                **{OP_REGISTER_SEARCHER: Accept(objects=[error_frame("denied")])}
            )
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            registrar.add_hook(op_hook(OP_REGISTER_SEARCHER))
            await registrar.register("unix:/tmp/x.sock", Nonce.random())
            with self.assertRaises(RemoteError):
                await registrar.start()
            self.assertIsNone(registrar.bind_stream)
            self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT)
            await registrar.aclose()

    @bounded()
    async def test_a_hook_whose_answer_is_not_an_ack_aborts_the_cycle(self):
        async with MockApphost(
            routes=registrar_routes(**{OP_REGISTER_SEARCHER: Accept(objects=[u8(1)])})
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            registrar.add_hook(op_hook(OP_REGISTER_SEARCHER))
            with self.assertRaises(ProtocolError):
                await registrar.start()
            await registrar.aclose()

    @bounded()
    async def test_the_bind_stream_ending_re_registers_everything(self):
        """The node forgets every registration when the guest disconnects, hooks
        included, so a reconnect re-runs the whole cycle rather than only the
        bind."""
        drop = asyncio.Event()

        async def bind_once(conn: MockConn, query: RouteQuery) -> None:
            conn.send_raw(frame("mod.apphost.query_accepted_msg") + frame(ACK))
            await conn.flush()
            await drop.wait()

        async with MockApphost(
            routes=registrar_routes(
                **{OP_BIND: bind_once, OP_REGISTER_SEARCHER: ACK_ONCE}
            )
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            registrar.add_hook(op_hook(OP_REGISTER_SEARCHER))
            await registrar.register("unix:/tmp/x.sock", Nonce.random())
            await registrar.start()
            try:
                self.assertEqual(registrar.connects, 1)
                drop.set()
                await until(lambda: registrar.connects >= 2, turns=2000)
                self.assertGreaterEqual(registrar.connects, 2)
                ops = [q.op for q in mock.queries]
                self.assertEqual(ops.count(OP_BIND), registrar.connects)
                self.assertEqual(ops.count(OP_REGISTER_HANDLER), registrar.connects)
                self.assertEqual(ops.count(OP_REGISTER_SEARCHER), registrar.connects)
            finally:
                drop.set()
                await registrar.aclose()

    @bounded()
    async def test_register_on_a_live_registrar_registers_now(self):
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            try:
                self.assertEqual([q.op for q in mock.queries], [OP_BIND])
                token = Nonce.random()
                await registrar.register("unix:/tmp/late.sock", token)
                self.assertEqual(
                    [q.op for q in mock.queries], [OP_BIND, OP_REGISTER_HANDLER]
                )
                self.assertEqual(registrar.registrations, (
                    Registration("unix:/tmp/late.sock", token),
                ))
            finally:
                await registrar.aclose()

    @bounded()
    async def test_a_registration_the_node_refuses_is_not_recorded(self):
        """A record the node has never heard of makes the next reconnect
        re-register something that was already refused once."""
        async with MockApphost(
            routes={OP_BIND: BIND_ROUTE, OP_REGISTER_HANDLER: ErrorRoute("denied")}
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            try:
                with self.assertRaises(Denied):
                    await registrar.register("unix:/tmp/x.sock", Nonce.random())
                self.assertEqual(registrar.registrations, ())
            finally:
                await registrar.aclose()

    @bounded()
    async def test_a_registration_the_node_accepted_survives_a_failing_hook(self):
        """The other half of the rollback, and it used to be the same half.

        When `_attach` succeeds and a hook then fails, the node **has** heard of
        the endpoint: `register_handler` executed and the token is on the bind
        stream. Removing the SDK's record there left a live handler the SDK had
        forgotten -- lingering until the bind session ends, costing one routing
        attempt per query (astral-docs D-13), and never re-registered or replaced
        by any reconnect. The record is kept and the exception still propagates.
        """
        async with MockApphost(
            routes=registrar_routes(
                **{OP_REGISTER_SEARCHER: Accept(objects=[error_frame("denied")])}
            )
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            try:
                registrar.add_hook(op_hook(OP_REGISTER_SEARCHER))
                token = Nonce.random()
                with self.assertRaises(RemoteError):
                    await registrar.register("unix:/tmp/kept.sock", token)
                # The node executed the registration...
                self.assertIn(OP_REGISTER_HANDLER, [q.op for q in mock.queries])
                await until(lambda: token in mock.bind_tokens)
                self.assertIn(token, mock.bind_tokens)
                # ...so the SDK still knows about it.
                self.assertEqual(
                    registrar.registrations,
                    (Registration("unix:/tmp/kept.sock", token),),
                    "the rollback dropped a registration the node holds",
                )
            finally:
                await registrar.aclose()

    @bounded()
    async def test_aclose_closes_the_bind_stream_and_is_idempotent(self):
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            stream = registrar.bind_stream
            self.assertIsNotNone(stream)
            await registrar.aclose()
            self.assertTrue(registrar.closed)
            self.assertTrue(stream.closed)  # type: ignore[union-attr]
            self.assertIsNone(registrar.bind_stream)
            await registrar.aclose()
            self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT)

    @bounded(30.0)
    async def test_a_cancelled_aclose_still_closes_the_bind_stream(self):
        """The bind stream is the only deterministic deregistration astrald has,
        and it used to be the one thing a cancelled teardown lost: the wait on
        the run task came first, so a `CancelledError` landing there left the
        stream open with `closed=True` latched, the node still holding every
        handler and one persistent permit never returned."""
        for turns_before_cancel in (1, 2, 3, 4):
            with self.subTest(turns=turns_before_cancel):
                async with MockApphost(routes=registrar_routes()) as mock:
                    client = await self.client(mock)
                    registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
                    await registrar.register("unix:/tmp/x.sock", Nonce.random())
                    await registrar.start()
                    stream = registrar.bind_stream
                    self.assertIsNotNone(stream)

                    closer = asyncio.ensure_future(registrar.aclose())
                    for _ in range(turns_before_cancel):
                        await asyncio.sleep(0)
                    closer.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await closer

                    # The shield finishes the close the cancelled frame started.
                    await until(lambda: stream.closed, turns=4000)  # type: ignore[union-attr]
                    self.assertTrue(
                        stream.closed,  # type: ignore[union-attr]
                        "a cancelled teardown abandoned the bind stream",
                    )
                    await registrar.aclose()
                    self.assertTrue(registrar.closed)
                    self.assertIsNone(registrar.bind_stream)
                    self.assertEqual(
                        client.available_persistent, DEFAULT_MAX_PERSISTENT
                    )
                    await until(lambda: mock.live == 0)
                    self.assertEqual(mock.live, 0)
                    await client.aclose()

    def test_the_backoff_grows_to_its_ceiling_and_the_arguments_are_checked(self):
        client = object()
        r = Registrar(client, backoff_min=1.0, backoff_max=8.0, backoff_factor=2.0, jitter=0.0)  # type: ignore[arg-type]
        delays = []
        delay = 1.0
        for _ in range(5):
            delays.append(delay)
            delay = r._grow(delay)
        self.assertEqual(delays, [1.0, 2.0, 4.0, 8.0, 8.0])
        self.assertEqual(r._delay(4.0), 4.0)

    def test_a_zero_minimum_still_grows_out_of_zero(self):
        """`backoff_min=0` asks for the *first* retry to be immediate; it must
        not mean "dial at the speed of the event loop forever". `_grow` was
        `min(max, delay * factor)`, and zero times any factor is zero, so a
        registrar with a zero minimum against a node that refuses dialed 158,000
        times a second and retained 108,738 exceptions in one second of it."""
        client = object()
        r = Registrar(client, backoff_min=0.0, backoff_max=8.0, backoff_factor=2.0, jitter=0.0)  # type: ignore[arg-type]
        delay = 0.0
        series = [delay]
        for _ in range(8):
            delay = r._grow(delay)
            series.append(delay)
        # The caller's zero is honoured exactly once, where it was asked for.
        self.assertEqual(series[0], 0.0)
        self.assertTrue(
            all(d > 0.0 for d in series[1:]),
            f"the series stayed at zero: {series}",
        )
        self.assertEqual(series[-1], 8.0, "the series must still reach the ceiling")
        # And it is monotonic, so no step is a step backwards.
        self.assertEqual(series, sorted(series))

    @bounded()
    async def test_a_registrar_that_cannot_reconnect_does_not_spin_or_hoard(self):
        """The two halves compound: each spin iteration appended one exception
        with a live traceback to an unbounded list, so an unreachable node cost a
        pegged core and 17 MB a second. The delay now grows out of zero and the
        log is a bounded deque with a counter beside it."""
        attempts = 0

        class Refusing:
            closing = False

            @property
            def apphost(self):  # type: ignore[no-untyped-def]
                return self

            async def bind(self, **kw):  # type: ignore[no-untyped-def]
                nonlocal attempts
                attempts += 1
                raise NodeUnavailable("no node")

        registrar = Registrar(Refusing(), backoff_min=0.0, jitter=0.0)  # type: ignore[arg-type]
        loop = asyncio.get_running_loop()
        reconnect = asyncio.ensure_future(registrar._reconnect())
        started = loop.time()
        while loop.time() - started < 0.3:
            await asyncio.sleep(0)
        reconnect.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reconnect

        # Unbounded, this measured 47,443 attempts in the same window.
        self.assertLess(attempts, 100, f"the reconnect loop spun: {attempts} dials")
        self.assertGreaterEqual(attempts, 1, "the first retry is still immediate")
        self.assertLessEqual(len(registrar.errors), ERROR_HISTORY)
        self.assertEqual(registrar.faults, attempts)

    @bounded()
    async def test_the_peer_cannot_grow_the_error_log(self):
        """`_watch` appends one `ProtocolError` for every frame the node writes
        on the bind stream after the ack, in a loop with no ceiling, so the
        growth rate is the peer's write rate and the registrar stays `ready`
        throughout. 5,000 frames gave 5,000 retained exceptions."""
        frames = 500

        async def chatty(conn: MockConn, query: RouteQuery) -> None:
            """`op_bind`'s ack, then a flood of frames the protocol has no
            account for, then the ordinary read loop so the close still works."""
            conn.send_raw(frame("mod.apphost.query_accepted_msg") + frame(ACK))
            await conn.flush()
            for _ in range(frames):
                conn.send_frame(ACK)
            await conn.flush()
            while await conn.recv_frame_or_none() is not None:
                pass

        async with MockApphost(
            routes=registrar_routes(**{OP_BIND: chatty})
        ) as mock:
            client = await self.client(mock)
            registrar = Registrar(client, backoff_min=0.0, jitter=0.0)
            await registrar.start()
            try:
                await until(lambda: registrar.faults >= frames, turns=20000)
                self.assertGreaterEqual(registrar.faults, frames)
                self.assertLessEqual(
                    len(registrar.errors),
                    ERROR_HISTORY,
                    "the peer grew the error log without bound",
                )
                self.assertIs(type(registrar.errors), type(Service().errors))
            finally:
                await registrar.aclose()

        with self.assertRaises(BadArgument):
            Registrar(client, backoff_min=5.0, backoff_max=1.0)  # type: ignore[arg-type]
        with self.assertRaises(BadArgument):
            Registrar(client, backoff_factor=0.5)  # type: ignore[arg-type]
        with self.assertRaises(BadArgument):
            Registrar(client, jitter=1.0)  # type: ignore[arg-type]

    def test_the_jitter_stays_inside_its_fraction(self):
        """Every local app's registrar wakes at the same instant after a node
        restart, and astrald's apphost pool is 32 workers wide for all of them
        together (bug G-13)."""
        import random as _random

        client = object()
        r = Registrar(client, jitter=DEFAULT_JITTER, rng=_random.Random(0))  # type: ignore[arg-type]
        for _ in range(200):
            value = r._delay(10.0)
            self.assertGreaterEqual(value, 9.0)
            self.assertLessEqual(value, 11.0)
        self.assertEqual(r._delay(0.0), 0.0)


# --- Client.serve, end to end ---------------------------------------------


class ClientServeTest(ServeCase):
    @bounded()
    async def test_serve_registers_and_then_answers_a_dialed_query(self):
        """The whole of design section 4.3: bind, register, and then the node
        dials the endpoint the registration named."""
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            service = await client.serve(handler=object_handler([Ack()]))
            self.services.append(service)

            self.assertEqual(
                [q.op for q in mock.queries], [OP_BIND, OP_REGISTER_HANDLER]
            )
            registered = mock.queries[1].query
            self.assertIn("endpoint=", registered)
            self.assertIn(f"token={service.token}", registered)

            dialer = self.dialer(service)
            answered = await dialer.query("x.anything")
            self.assertTrue(answered.accepted, answered)
            body = await dialer.objects(answered.conn)
            self.assertEqual([t for t, _ in body], [ACK, EOS_TYPE])

    @bounded()
    async def test_client_aclose_closes_the_service_and_its_bind_stream(self):
        """Design section 3.8: serving tasks before streams, and the bind stream
        last, so the node's deferred handler sweep runs with the listener gone."""
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            service = await client.serve(handler=object_handler([Ack()]))
            endpoint = service.endpoint
            registrar = service.registrar
            self.assertIsNotNone(registrar)

            await client.aclose()
            self.assertTrue(client.closed)
            self.assertTrue(service.closed)
            self.assertTrue(registrar.closed)  # type: ignore[union-attr]
            self.assertEqual(client.live_streams, 0)
            with self.assertRaises(astral.AstralError):
                await dial(endpoint)
        await self.assert_no_open_sockets()

    @bounded()
    async def test_a_bound_endpoint_can_be_named(self):
        async with MockApphost(routes=registrar_routes()) as mock:
            client = await self.client(mock)
            service = await client.serve(
                handler=object_handler([Ack()]), proto="tcp"
            )
            self.services.append(service)
            self.assertTrue(service.endpoint.startswith("tcp:127.0.0.1:"))


# --- register-service, shipped but gated ----------------------------------


class RegisterServiceTest(ServeCase):
    """Design section 4.4 and risk R-16, which is unsettled and needs a token."""

    @bounded()
    async def test_ipc_is_gated_and_the_flag_names_the_risk(self):
        async with MockApphost(token="secret", register_service=ACK) as mock:
            client = await self.client(mock, token="secret")
            with self.assertRaises(FeatureUnavailable) as caught:
                await client.serve(mode="service")
            self.assertIn("R-16", str(caught.exception))
            self.assertIn("G-12", str(caught.exception))
            self.assertEqual(mock.conn_count, 1, "connect's own dial, and no other")

    @bounded()
    async def test_an_anonymous_session_is_refused_before_the_round_trip(self):
        """astrald tests `isAuthenticated()` first and answers `denied` even for
        the zero identity, so the refusal is a certainty and a certain refusal is
        not worth one of 32 node workers."""
        async with MockApphost(register_service=ACK) as mock:
            client = await self.client(mock)
            with self.assertRaises(Denied):
                await client.serve(mode="service", experimental=True)

    @bounded()
    async def test_a_push_is_dispatched_and_a_rejection_goes_back_on_the_registration(
        self,
    ):
        pushes: list[tuple[str, bytes]] = []

        async def registration(conn: MockConn) -> None:
            conn.send_frame("mod.apphost.host_info_msg", host_info())
            await conn.flush()
            while True:
                received = await conn.recv_frame_or_none()
                if received is None:
                    return
                type_name, payload = received
                if type_name == "mod.apphost.auth_token_msg":
                    conn.send_frame(
                        "mod.apphost.auth_success_msg", auth_success(FURRY_BOLT)
                    )
                    await conn.flush()
                elif type_name == "mod.apphost.register_service_msg":
                    self.assertEqual(parse_register_service(payload), FURRY_BOLT)
                    conn.send_frame(ACK)
                    conn.send_frame(
                        INCOMING_QUERY,
                        incoming_query_payload(
                            Nonce(0x1234), OTHER, FURRY_BOLT, "x.push?n=3"
                        ),
                    )
                    await conn.flush()
                elif type_name == "mod.apphost.reject_incoming_msg":
                    pushes.append(parse_reject_incoming(payload))
                    return

        async with MockApphost(token="secret", session=registration) as mock:
            client = await self.client(mock, token="secret")
            seen: list[IncomingQuery] = []

            async def refuse(q: IncomingQuery) -> None:
                seen.append(q)
                await q.reject(3)

            service = await client.serve(
                handler=refuse, mode="service", experimental=True
            )
            self.services.append(service)
            await until(lambda: bool(pushes), turns=2000)
            self.assertEqual(pushes, [(Nonce(0x1234), 3)])
            self.assertEqual(seen[0].op, "x.push")
            self.assertEqual(seen[0].caller, OTHER)
            self.assertEqual(seen[0].params["n"], "3")

    @bounded()
    async def test_accepting_a_push_opens_a_fresh_connection_and_attaches(self):
        """Answering an `incoming_query_msg` means a **new** connection: the
        registration stays a message channel and the unguessable `QueryID` is the
        pairing token."""
        attached: list[Nonce] = []

        async def registration(conn: MockConn) -> None:
            conn.send_frame("mod.apphost.host_info_msg", host_info())
            await conn.flush()
            first = True
            while True:
                received = await conn.recv_frame_or_none()
                if received is None:
                    return
                type_name, payload = received
                if type_name == "mod.apphost.auth_token_msg":
                    conn.send_frame(
                        "mod.apphost.auth_success_msg", auth_success(FURRY_BOLT)
                    )
                    await conn.flush()
                elif type_name == "mod.apphost.register_service_msg":
                    conn.send_frame(ACK)
                    conn.send_frame(
                        INCOMING_QUERY,
                        incoming_query_payload(
                            Nonce(0x99), OTHER, FURRY_BOLT, "x.push"
                        ),
                    )
                    await conn.flush()
                elif type_name == "mod.apphost.attach_query_msg" and first:
                    first = False
                    attached.append(parse_attach_query(payload))
                    conn.send_frame(ACK)
                    await conn.flush()
                    # The donated connection is now the responder's bytestream.
                    return

        async with MockApphost(token="secret", session=registration) as mock:
            client = await self.client(mock, token="secret")
            service = await client.serve(
                handler=object_handler([Ack()]), mode="service", experimental=True
            )
            self.services.append(service)
            await until(lambda: bool(attached), turns=2000)
            self.assertEqual(attached, [Nonce(0x99)])


def host_info() -> bytes:
    from mock_apphost import host_info_payload

    return host_info_payload(FURRY_BOLT, "furry-bolt")


def auth_success(identity: Identity) -> bytes:
    from mock_apphost import auth_success_payload

    return auth_success_payload(identity)


# --- Tier C: the live register-handler round trip -------------------------


class LiveServeTest(unittest.IsolatedAsyncioTestCase):
    """Design section 7.4's fourth row: a node **and** a token.

    `apphost.bind` and `apphost.register_handler` are both local-only and both
    mutate node state, so this tier is opt-in twice over: `ASTRAL_TEST_ENDPOINT`
    for the node and `ASTRAL_TEST_TOKEN` for the credential. It registers on the
    client's own identity and deregisters by closing the bind stream, which is
    the only eager deregistration astrald has (astral-docs bug D-13).

    **Step 10's gate is not met, and this docstring is where that is recorded.**
    Design section 10 gates step 10 on "`MockDialer` suite; live register-handler
    round trip when a token is available". The `MockDialer` half is met. The live
    half is not: `ASTRAL_TEST_TOKEN` is unset in this environment, this is the
    only method in the class, and it skips, so `serve.py` and `registrar.py` --
    the listener, the accept loop, the answer deadline, the op table, the bind
    session, the reconnect cycle -- rest entirely on `MockApphost` and
    `MockDialer`. A mock cannot falsify the two highest-risk mode declarations in
    the module, because the mock was written from the same reading of the same
    source: `apphost.bind` is declared BD and `apphost.register_handler` RR.

    Those two declarations were checked against astrald's source instead, which
    is weaker evidence and is named as such: `op_bind.go` accepts, sends
    `&astral.Ack{}`, enters `ch.Switch(WithContext, func(*apphost.BindMsg))` and
    runs `removeHandlersByToken` per collected token in a deferred sweep -- BD.
    `op_register_handler.go` accepts, adds the handler under `q.Caller()` and
    returns `ch.Send(&astral.Ack{})` -- RR. `Registrar._attach`'s order,
    `register_handler` then `bind_msg`, is the order `removeHandlersByToken`
    needs.

    Closing the gate needs a token, and minting one is `apphost.create_token`,
    which mutates. The node carries one token already and it belongs to another
    identity, so it is not this suite's to spend. Set `ASTRAL_TEST_TOKEN` out of
    band to run this.
    """

    async def asyncSetUp(self) -> None:
        from live_support import endpoint, verdict

        reason = await verdict()
        if reason:
            self.skipTest(reason)
        self.token = os.environ.get("ASTRAL_TEST_TOKEN") or None
        if self.token is None:
            self.skipTest(
                "ASTRAL_TEST_TOKEN is not set: register_handler and bind are "
                "local-only, mutate node state, and need a credential "
                "(design section 7.3). Step 10's live gate is UNMET while this "
                "skips -- the serving path is mock-only. See this class's "
                "docstring."
            )
        self.endpoint = endpoint()
        self.sockets_before = socket_fds()

    @bounded(30.0)
    async def test_a_query_routed_to_this_app_reaches_the_mounted_op(self):
        async with await connect(
            self.endpoint, token=self.token, max_concurrency=4
        ) as client:
            service = await client.serve(handler=object_handler([Ack()]))
            try:
                self.assertTrue(service.listening)
                self.assertIsNotNone(service.registrar)
                self.assertTrue(service.registrar.ready)  # type: ignore[union-attr]
                answers = await client.call(
                    "x.ping", target=client.guest_id, timeout=10.0
                )
                self.assertEqual(len(answers), 1)
                self.assertIsInstance(answers[0], Ack)
                self.assertEqual(service.served, 1)
            finally:
                await service.aclose()
        leaked = leaked_sockets(self.sockets_before)
        if leaked:
            await until(lambda: not leaked_sockets(self.sockets_before))
        self.assertEqual(leaked_sockets(self.sockets_before), set())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
