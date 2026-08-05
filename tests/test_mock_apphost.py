"""Tier B: the `MockApphost` framing tests -- the gate for the transport step.

Every exchange runs through the real `BinaryChannel` over the real `MemTransport`
and, for the core cases, over a real loopback socket, so a pass means the framing
the session step builds on is byte-correct on both paths.

The suite covers the correct host and the misbehaving one: the wedged handshake
that never greets, an EOF before the greeting, a truncated frame, a frame
declaring four gigabytes, non-frame bytes, a query that is never answered, a
response body cut mid-frame, every `error_msg` code and the reject codes. Design
section 7.2's invariant 1 -- no stranded bytes when the acceptance and the first
raw bytes share one write -- is asserted here against the mock as well as against
the channel in isolation.

Every async test is `bounded`, and every test asserts the mock recorded no
handler fault and leaked no transport.
"""

from __future__ import annotations

import ast
import asyncio
import os
import unittest

from astral import primitives as P
from astral.channel.binary import BinaryChannel
from astral.client import resolve_endpoint, resolve_token
from astral.errors import AllocationLimit, BlueprintNotFound, StreamCorrupted
from astral.object import Ack, EOS
from astral.registry import Blueprints, default_blueprints
from astral.session import HostInfoMsg, QueryAcceptedMsg, RouteQueryMsg
from astral.transport import MemTransport, Transport, default_endpoint, dial
from astral.types import Identity, Nonce, Zone

from mock_apphost import (
    ACK,
    AMBIENT_VARS,
    AUTH_SUCCESS,
    ERROR_CODES,
    ERROR_MSG,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    HANDLE_QUERY,
    HOST_INFO,
    PING,
    QUERY_ACCEPTED,
    QUERY_REJECTED,
    ROUTE_QUERY,
    Accept,
    Drop,
    ErrorMsg,
    Garbage,
    Handshake,
    Hang,
    MockApphost,
    MockConn,
    Reject,
    RouteQuery,
    auth_token_payload,
    bind_payload,
    bounded,
    frame,
    handle_query_payload,
    host_info_payload,
    parse_auth_success,
    parse_error_msg,
    parse_handle_query,
    parse_host_info,
    parse_query_rejected,
    route_query_payload,
    until,
)

_TEST = Blueprints(default_blueprints())

WHOAMI = "apphost.whoami"
IDENTITY_FRAME = ("identity", FURRY_BOLT.key)


class ApphostCase(unittest.IsolatedAsyncioTestCase):
    """Shared plumbing: a channel over the mock, and the hygiene assertions."""

    def channel(self, transport: Transport, **kw) -> BinaryChannel:  # type: ignore[no-untyped-def]
        kw.setdefault("registry", _TEST)
        return BinaryChannel(transport, **kw)

    async def frame_of(self, transport: Transport) -> tuple[str, bytes]:
        """One frame off the transport, undecoded. What the mock's own reader does."""
        head = await transport.readexactly(1)
        type_name = (await transport.readexactly(head[0])).decode() if head[0] else ""
        length = int.from_bytes(await transport.readexactly(4), "big")
        return type_name, (await transport.readexactly(length) if length else b"")

    def assert_clean(self, mock: MockApphost) -> None:
        self.assertEqual([repr(e) for e in mock.errors], [])

    async def assert_no_leaks(self, mock: MockApphost) -> None:
        await mock.aclose()
        for conn in mock.connections:
            self.assertTrue(conn.transport.closed, f"{conn} left open")
        self.assertEqual(mock.live, 0)

    async def greet(self, mock: MockApphost, transport: Transport) -> BinaryChannel:
        """Read the greeting and return the channel positioned at the next frame."""
        ch = self.channel(transport)
        greeting = await ch.receive()
        self.assertIsInstance(greeting, HostInfoMsg)
        self.assertEqual(greeting.identity, mock.host_id)
        self.assertEqual(greeting.alias, mock.alias)
        return ch

    async def route(self, ch: BinaryChannel, query: str = WHOAMI, **kw) -> object:
        """Send one `route_query_msg` through the channel and read the reply."""
        await ch.send(
            RouteQueryMsg(
                nonce=kw.pop("nonce", Nonce(0x1122334455667788)),
                caller=kw.pop("caller", None),
                target=kw.pop("target", FURRY_BOLT),
                query=query,
                zone=kw.pop("zone", Zone.ALL),
                filters=list(kw.pop("filters", ())),
            )
        )
        return await ch.receive()


class HandshakeTest(ApphostCase):
    @bounded()
    async def test_the_host_speaks_first_over_memory(self):
        async with MockApphost() as mock:
            transport = await mock.open()
            await self.greet(mock, transport)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_host_speaks_first_over_a_real_socket(self):
        async with MockApphost() as mock:
            endpoint = await mock.listen("tcp")
            self.assertTrue(endpoint.startswith("tcp:127.0.0.1:"))
            async with await dial(endpoint) as transport:
                await self.greet(mock, transport)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_host_speaks_first_over_a_unix_socket(self):
        async with MockApphost() as mock:
            endpoint = await mock.listen("unix")
            async with await dial(endpoint) as transport:
                await self.greet(mock, transport)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_greeting_frame_is_the_bytes_captured_from_the_live_node(self):
        """The design's must-pass table, verbatim:
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
        async with MockApphost() as mock:
            transport = await mock.open()
            self.assertEqual(await transport.readexactly(len(captured)), captured)
            type_name, payload = HOST_INFO, captured[30:]
            self.assertEqual(parse_host_info(payload), (FURRY_BOLT, FURRY_BOLT_ALIAS))
            self.assertEqual(frame(type_name, payload), captured)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_host_that_never_greets_never_closes_either(self):
        """astrald's wedged worker pool: the OS accepts the socket, the node never
        handshakes, and nothing times out on its own (bug G-13). The session step
        turns this into `NodeUnavailable` with `CONNECT_TIMEOUT`."""
        async with MockApphost(handshake=Handshake.SILENT) as mock:
            transport = await mock.open()
            with self.assertRaises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await self.channel(transport).receive()
            self.assertFalse(transport.closed)
            self.assertEqual(mock.live, 1)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_eof_before_the_greeting_is_a_clean_end_of_stream(self):
        async with MockApphost(handshake=Handshake.CLOSE) as mock:
            transport = await mock.open()
            with self.assertRaises(EOFError):
                await self.channel(transport).receive()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_truncated_greeting_is_stream_corrupted(self):
        async with MockApphost(handshake=Handshake.TRUNCATED) as mock:
            transport = await mock.open()
            with self.assertRaises(StreamCorrupted):
                await self.channel(transport).receive()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_greeting_of_the_wrong_type_decodes_as_that_type(self):
        """The channel is not the session: it decodes what arrived. Rejecting an
        `ack` where `host_info_msg` belongs is the session's judgement."""
        async with MockApphost(handshake=Handshake.WRONG_TYPE) as mock:
            transport = await mock.open()
            self.assertEqual(await self.channel(transport).receive(), Ack())
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_greeting_declaring_four_gigabytes_is_refused_unread(self):
        async with MockApphost(handshake=Handshake.OVERSIZE) as mock:
            transport = await mock.open()
            with self.assertRaises(AllocationLimit):
                await self.channel(transport).receive()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_non_frame_bytes_never_decode_to_a_known_type(self):
        async with MockApphost(handshake=Handshake.GARBAGE) as mock:
            transport = await mock.open()
            with self.assertRaises((BlueprintNotFound, StreamCorrupted, EOFError)):
                await self.channel(transport).receive()
            await self.assert_no_leaks(mock)


class AuthTest(ApphostCase):
    @bounded()
    async def test_a_matching_token_yields_the_guest_identity(self):
        guest = Identity.parse("02" + "11" * 32)
        async with MockApphost(token="s3cret", guest_id=guest) as mock:
            transport = await mock.open()
            await self.greet(mock, transport)
            transport.write(frame("mod.apphost.auth_token_msg", auth_token_payload("s3cret")))
            await transport.drain()
            type_name, payload = await self.frame_of(transport)
            self.assertEqual(type_name, AUTH_SUCCESS)
            self.assertEqual(parse_auth_success(payload), guest)
            self.assertEqual(mock.tokens, ["s3cret"])
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_bogus_token_fails_and_leaves_the_channel_usable(self):
        """Verified live: the node answers `auth_failed` and keeps looping."""
        async with MockApphost(
            token="s3cret", routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}
        ) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            transport.write(frame("mod.apphost.auth_token_msg", auth_token_payload("wrong")))
            await transport.drain()
            type_name, payload = await self.frame_of(transport)
            self.assertEqual(type_name, ERROR_MSG)
            self.assertEqual(parse_error_msg(payload), "auth_failed")
            self.assertIsInstance(await self.route(ch, WHOAMI), QueryAcceptedMsg)
            await self.assert_no_leaks(mock)


class RouteQueryTest(ApphostCase):
    @bounded()
    async def test_the_mock_reads_every_field_the_client_sent(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            reply = await self.route(
                ch,
                "apphost.whoami?out=bin",
                nonce=Nonce(0x1122334455667788),
                caller=None,
                target=FURRY_BOLT,
                zone=Zone.ALL,
                filters=["abc"],
            )
            self.assertIsInstance(reply, QueryAcceptedMsg)
            self.assertEqual(len(mock.queries), 1)
            query: RouteQuery = mock.queries[0]
            self.assertEqual(query.nonce, Nonce(0x1122334455667788))
            self.assertIsNone(query.caller)
            self.assertEqual(query.target, FURRY_BOLT)
            self.assertEqual(query.query, "apphost.whoami?out=bin")
            self.assertEqual(query.op, WHOAMI)
            self.assertEqual(query.zone, int(Zone.ALL))
            self.assertEqual(query.filters, ("abc",))
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_route_query_frame_matches_the_designs_worked_example(self):
        """Design section 2.5's byte-for-byte example, with the filter tail of the
        paragraph that follows it."""
        transport = MemTransport.solo()
        await self.channel(transport).send(
            RouteQueryMsg(
                nonce=Nonce(0x1122334455667788),
                caller=None,
                target=FURRY_BOLT,
                query="apphost.whoami",
                zone=Zone.ALL,
                filters=[],
            )
        )
        expected = frame(
            ROUTE_QUERY,
            route_query_payload(
                Nonce(0x1122334455667788), None, FURRY_BOLT, "apphost.whoami", 7, ()
            ),
        )
        self.assertEqual(transport.sent, expected)
        # Invariant 2 of design section 7.2, on the message the session sends most.
        self.assertEqual(len(transport.writes), 1)
        self.assertTrue(transport.sent.endswith(bytes.fromhex("0700000000")))

        transport2 = MemTransport.solo()
        await self.channel(transport2).send(
            RouteQueryMsg(
                nonce=Nonce(0),
                caller=None,
                target=None,
                query="x",
                zone=Zone.ALL,
                filters=["abc"],
            )
        )
        self.assertTrue(transport2.sent.endswith(bytes.fromhex("07" "00000001" "01" "03616263")))

    @bounded()
    async def test_an_unrouted_query_gets_route_not_found(self):
        async with MockApphost() as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            type_name, payload = await self._route_raw(ch, transport, "nope.nothing")
            self.assertEqual(type_name, ERROR_MSG)
            self.assertEqual(parse_error_msg(payload), "route_not_found")
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_failure_leaves_a_message_channel_and_a_second_query_is_served(self):
        """Verified live, and the correction to astral-docs bug D-14: only
        `query_accepted_msg` is terminal."""
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            first, _ = await self._route_raw(ch, transport, "nope.nothing")
            self.assertEqual(first, ERROR_MSG)
            second, _ = await self._route_raw(ch, transport, WHOAMI)
            self.assertEqual(second, QUERY_ACCEPTED)
            self.assertEqual(len(mock.queries), 2)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_every_error_code_arrives_verbatim(self):
        routes = {f"op.{code}": ErrorMsg(code) for code in ERROR_CODES}
        async with MockApphost(routes=routes) as mock:
            for code in ERROR_CODES:
                with self.subTest(code=code):
                    transport = await mock.open()
                    ch = await self.greet(mock, transport)
                    type_name, payload = await self._route_raw(ch, transport, f"op.{code}")
                    self.assertEqual(type_name, ERROR_MSG)
                    self.assertEqual(parse_error_msg(payload), code)
                    await transport.aclose()
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_rejection_carries_its_numeric_code(self):
        routes = {f"op.{code}": Reject(code) for code in (0, 1, 2, 3, 4, 9)}
        async with MockApphost(routes=routes) as mock:
            for code in (0, 1, 2, 3, 4, 9):
                with self.subTest(code=code):
                    transport = await mock.open()
                    ch = await self.greet(mock, transport)
                    type_name, payload = await self._route_raw(ch, transport, f"op.{code}")
                    self.assertEqual(type_name, QUERY_REJECTED)
                    self.assertEqual(parse_query_rejected(payload), code)
                    await transport.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_query_that_is_never_answered_holds_the_connection_open(self):
        async with MockApphost(routes={WHOAMI: Hang()}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            with self.assertRaises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await self.route(ch, WHOAMI)
            self.assertFalse(transport.closed)
            self.assertEqual(mock.live, 1)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_dropped_query_ends_at_eof(self):
        async with MockApphost(routes={WHOAMI: Drop()}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            with self.assertRaises(EOFError):
                await self.route(ch, WHOAMI)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_non_frame_bytes_in_place_of_a_reply(self):
        async with MockApphost(routes={WHOAMI: Garbage(b"\x04junk")}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            with self.assertRaises((StreamCorrupted, BlueprintNotFound, EOFError)):
                await self.route(ch, WHOAMI)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unexpected_message_type_gets_protocol_error_and_a_close(self):
        """Verified live with `ping_msg`, a registered type with no handler
        (astral-go bug G-17)."""
        async with MockApphost() as mock:
            transport = await mock.open()
            await self.greet(mock, transport)
            transport.write(frame(PING))
            await transport.drain()
            type_name, payload = await self.frame_of(transport)
            self.assertEqual(type_name, ERROR_MSG)
            self.assertEqual(parse_error_msg(payload), "protocol_error")
            self.assertEqual(await transport.read(1), b"")
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_anonymous_registration_is_denied_and_an_attach_is_not_found(self):
        async with MockApphost() as mock:
            transport = await mock.open()
            await self.greet(mock, transport)
            transport.write(
                frame("mod.apphost.register_service_msg", b"\x01" + bytes(33))
            )
            await transport.drain()
            type_name, payload = await self.frame_of(transport)
            self.assertEqual((type_name, parse_error_msg(payload)), (ERROR_MSG, "denied"))
            transport.write(frame("mod.apphost.attach_query_msg", bytes(8)))
            await transport.drain()
            type_name, payload = await self.frame_of(transport)
            self.assertEqual(
                (type_name, parse_error_msg(payload)), (ERROR_MSG, "route_not_found")
            )
            await self.assert_no_leaks(mock)

    async def _route_raw(
        self, ch: BinaryChannel, transport: Transport, query: str
    ) -> tuple[str, bytes]:
        await ch.send(
            RouteQueryMsg(
                nonce=Nonce.random(),
                caller=None,
                target=FURRY_BOLT,
                query=query,
                zone=Zone.ALL,
                filters=[],
            )
        )
        return await self.frame_of(transport)


class AcceptedStreamTest(ApphostCase):
    async def accept(
        self, mock: MockApphost, query: str = WHOAMI, *, over: str = "mem"
    ) -> Transport:
        """Route `query`, read the acceptance frame, hand back the raw stream."""
        if over == "mem":
            transport: Transport = await mock.open()
        else:
            transport = await dial(await mock.listen(over))
        ch = await self.greet(mock, transport)
        await ch.send(
            RouteQueryMsg(
                nonce=Nonce.random(),
                caller=None,
                target=FURRY_BOLT,
                query=query,
                zone=Zone.ALL,
                filters=[],
            )
        )
        head = await transport.readexactly(1)
        type_name = (await transport.readexactly(head[0])).decode()
        self.assertEqual(type_name, QUERY_ACCEPTED)
        self.assertEqual(await transport.readexactly(4), b"\x00\x00\x00\x00")
        # The acceptance is the point of no return: the channel is done and the
        # transport is the query's bytestream.
        return ch.detach()

    @bounded()
    async def test_a_stream_terminated_by_eos(self):
        route = Accept(objects=[("uint32", b"\x00\x00\x00\x01"), IDENTITY_FRAME], eos=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock)
            ch = self.channel(raw)
            seen = [obj async for obj in ch]
            self.assertEqual(seen, [P.Uint32(1), FURRY_BOLT])
            self.assertTrue(ch.saw_eos)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_handover_works_over_a_real_socket(self):
        """The same acceptance over loopback TCP, where the read buffer is a real
        `asyncio.StreamReader`. `detach()` hands that same reader to the raw
        stream, which is the whole of design section 3.2 rule 1."""
        route = Accept(objects=[IDENTITY_FRAME], eos=True, coalesce=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock, over="tcp")
            ch = self.channel(raw)
            self.assertEqual([obj async for obj in ch], [FURRY_BOLT])
            self.assertTrue(ch.saw_eos)
            await raw.aclose()
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_stream_terminated_by_bare_eof(self):
        """`apphost.whoami` sends one identity and closes with no `eos`."""
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            raw = await self.accept(mock)
            ch = self.channel(raw)
            seen = [obj async for obj in ch]
            self.assertEqual(seen, [FURRY_BOLT])
            self.assertFalse(ch.saw_eos)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_follow_stream_separates_the_snapshot_from_the_live_tail(self):
        route = Accept(
            objects=[("uint32", b"\x00\x00\x00\x01")],
            eos=True,
            live=[("uint32", b"\x00\x00\x00\x02")],
            hold=True,
        )
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock)
            ch = self.channel(raw)
            snapshot = [obj async for obj in ch]
            self.assertEqual(snapshot, [P.Uint32(1)])
            self.assertTrue(ch.saw_eos)
            # The separator ends the snapshot, not the channel.
            self.assertEqual(await ch.receive(), P.Uint32(2))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unframed_body_is_read_as_raw_bytes(self):
        """`objects.read` is the one RAW op: its response has no object framing."""
        async with MockApphost(routes={"objects.read": Accept(raw=b"\xde\xad\xbe\xef")}) as mock:
            raw = await self.accept(mock, "objects.read")
            self.assertEqual(await raw.read(-1), b"\xde\xad\xbe\xef")
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_no_stranded_bytes_when_the_acceptance_shares_a_write_with_the_body(self):
        """Invariant 1 of design section 7.2, end to end through the mock: the
        acceptance frame and the first raw-stream bytes arrive in one write."""
        route = Accept(objects=[IDENTITY_FRAME], eos=True, coalesce=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            transport = await mock.open()
            ch = await self.greet(mock, transport)
            await ch.send(
                RouteQueryMsg(
                    nonce=Nonce.random(),
                    caller=None,
                    target=FURRY_BOLT,
                    query=WHOAMI,
                    zone=Zone.ALL,
                    filters=[],
                )
            )
            # One write on the mock's side carried the acceptance and the body, so
            # everything is buffered before the client reads the first frame.
            self.assertTrue(await until(lambda: transport.buffered > 0))
            accepted = await ch.receive()
            self.assertIsInstance(accepted, QueryAcceptedMsg)
            # The sharpest form of the invariant: the channel consumed exactly the
            # acceptance frame and left every body byte in the transport. A channel
            # with a read buffer of its own would have stranded them.
            body_bytes = len(frame("identity", FURRY_BOLT.key)) + len(frame("eos"))
            self.assertEqual(transport.buffered, body_bytes)
            body = self.channel(ch.detach())
            self.assertEqual([obj async for obj in body], [FURRY_BOLT])
            self.assertTrue(body.saw_eos)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_body_cut_mid_frame_is_stream_corrupted(self):
        route = Accept(objects=[("uint32", b"\x00\x00\x00\x01")], truncate=6)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock)
            with self.assertRaises(StreamCorrupted):
                await self.channel(raw).receive()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_echo_shape_relays_input_objects_and_the_terminating_eos(self):
        """The WA shape: the client sends objects on the channel body and the
        server answers one per input."""
        async with MockApphost(routes={"objects.echo": Accept(echo=True)}) as mock:
            raw = await self.accept(mock, "objects.echo")
            ch = self.channel(raw)
            await ch.send(P.String8("hi"))
            self.assertEqual(await ch.receive(), P.String8("hi"))
            await ch.send(EOS())
            self.assertEqual(await ch.receive(), EOS())
            self.assertTrue(ch.saw_eos)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_client_half_close_does_not_kill_the_read_direction(self):
        """Verified live: `shutdown(SHUT_WR)` after acceptance still delivers the
        response, then EOF."""
        route = Accept(objects=[IDENTITY_FRAME], delay=0.01)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock)
            raw.write_eof()
            ch = self.channel(raw)
            self.assertEqual([obj async for obj in ch], [FURRY_BOLT])
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_host_half_close_leaves_the_write_direction_usable(self):
        route = Accept(objects=[IDENTITY_FRAME], half_close=True, hold=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            raw = await self.accept(mock)
            ch = self.channel(raw)
            self.assertEqual([obj async for obj in ch], [FURRY_BOLT])
            self.assertEqual(await raw.read(1), b"")
            await ch.send(P.String8("still writable"))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_frames_sent_on_an_accepted_stream_reach_the_host(self):
        """The `apphost.bind` shape: the accepted stream carries `bind_msg`
        frames, repeatable, one per handler token."""
        async with MockApphost(routes={"apphost.bind": Accept(read=True)}) as mock:
            raw = await self.accept(mock, "apphost.bind")
            for token in (Nonce(1), Nonce(2)):
                raw.write(frame("mod.apphost.bind_msg", bind_payload(token)))
                await raw.drain()
            raw.write_eof()
            self.assertTrue(await until(lambda: len(mock.bind_tokens) == 2))
            self.assertEqual(mock.bind_tokens, [Nonce(1), Nonce(2)])
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)


class ConcurrencyTest(ApphostCase):
    @bounded()
    async def test_the_mock_serves_connections_concurrently_and_counts_them(self):
        route = Accept(objects=[IDENTITY_FRAME], hold=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            transports = []
            for _ in range(5):
                transport = await mock.open()
                ch = await self.greet(mock, transport)
                await ch.send(
                    RouteQueryMsg(
                        nonce=Nonce.random(),
                        caller=None,
                        target=FURRY_BOLT,
                        query=WHOAMI,
                        zone=Zone.ALL,
                        filters=[],
                    )
                )
                transports.append(transport)
            for transport in transports:
                await transport.readexactly(1)
            self.assertEqual(mock.conn_count, 5)
            self.assertEqual(mock.peak_live, 5)
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_custom_session_replaces_the_default_state_machine(self):
        """The dial-back shape: no greeting, and `handle_query_msg` is the first
        frame the host sends. The escape hatch the serving step builds on."""
        token, query_id = Nonce(0xAAAA), Nonce(0xBBBB)

        async def dial_back(conn: MockConn) -> None:
            conn.send_frame(
                HANDLE_QUERY,
                handle_query_payload(token, query_id, None, FURRY_BOLT, "objects.search?q=x"),
            )
            await conn.flush()
            reply = await conn.recv_frame_or_none()
            assert reply is not None and reply[0] == ACK, reply

        async with MockApphost(handshake=Handshake.NONE, session=dial_back) as mock:
            transport = await mock.open()
            head = await transport.readexactly(1)
            type_name = (await transport.readexactly(head[0])).decode()
            self.assertEqual(type_name, HANDLE_QUERY)
            length = int.from_bytes(await transport.readexactly(4), "big")
            parsed = parse_handle_query(await transport.readexactly(length))
            self.assertEqual(parsed[0], token)
            self.assertEqual(parsed[1], query_id)
            self.assertIsNone(parsed[2])
            self.assertEqual(parsed[3], FURRY_BOLT)
            self.assertEqual(parsed[4], "objects.search?q=x")
            transport.write(frame(ACK))
            await transport.drain()
            self.assert_clean(mock)
            await self.assert_no_leaks(mock)


class PayloadCodecTest(unittest.TestCase):
    """The mock's hand-rolled payloads round-trip through its own parsers."""

    def test_host_info_and_the_two_anonymous_encodings(self):
        self.assertEqual(
            parse_host_info(host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)),
            (FURRY_BOLT, FURRY_BOLT_ALIAS),
        )
        # A nil pointer is one 0x00 byte; `anyone` is 0x01 and 33 zero bytes.
        self.assertEqual(host_info_payload(Identity.ANYONE, "x")[0:1], b"\x01")
        self.assertEqual(len(host_info_payload(Identity.ANYONE, "")), 35)

    def test_a_blob_frame_and_an_ack_frame(self):
        self.assertEqual(frame("", b"raw"), b"\x00\x00\x00\x00\x03raw")
        self.assertEqual(frame(ACK), b"\x03ack\x00\x00\x00\x00")


# --- the safety rail -----------------------------------------------------


class AmbientEnvironmentTest(unittest.TestCase):
    """The developer's own node reaches no test in this suite.

    `connect()` resolves an endpoint and a token from the environment when it is
    given neither (design section 3.3), so on a machine where astrald runs the
    suite would otherwise dial that node, or offer that node's token to a mock
    which has none and be refused. This is the case that actually happened: one
    exported `ASTRALD_APPHOST_TOKEN` cost three tests in three files, all three
    with the same `AuthFailed` against an in-process host.

    `mock_apphost.blank_ambient_environment()` runs at import and is therefore
    only as good as its reach, which is the second test here. The suite's own
    variables -- `ASTRAL_TEST_ENDPOINT`, `ASTRAL_TEST_TOKEN` -- are different
    names and are untouched, which is what keeps Tier C opt-in-able.
    """

    def test_every_production_variable_is_blank_once_the_harness_is_imported(self):
        """Blank, not absent: both resolvers skip an empty value, and an empty
        value is inherited by a subprocess where a deletion in this process would
        be, too -- but a variable that is present and empty also says the guard
        ran, which an absent one cannot."""
        for name in AMBIENT_VARS:
            with self.subTest(variable=name):
                self.assertEqual(os.environ.get(name), "")
        self.assertIsNone(resolve_token())
        self.assertEqual(resolve_endpoint(), default_endpoint())

    def test_every_test_module_that_calls_connect_imports_the_harness(self):
        """The reach of an import-time guard is which modules import it.

        Parsed rather than grepped, because `test_packaging` quotes
        `astral.connect(` inside the README text it asserts on and never calls
        it. A module reaching `connect` without this import is one ambient
        variable away from the failure this rail exists for; `live_support`
        counts because it imports the harness itself.
        """
        here = os.path.dirname(os.path.abspath(__file__))
        carriers = {"mock_apphost", "live_support"}
        for name in sorted(os.listdir(here)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=name)
            calls_connect = any(
                isinstance(node, ast.Call)
                and (
                    (isinstance(node.func, ast.Name) and node.func.id == "connect")
                    or (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "connect"
                    )
                )
                for node in ast.walk(tree)
            )
            if not calls_connect:
                continue
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            with self.subTest(module=name):
                self.assertTrue(
                    imported & carriers,
                    f"{name} calls connect() and imports neither "
                    f"{' nor '.join(sorted(carriers))}, so the ambient endpoint "
                    "and token reach it unblanked",
                )


if __name__ == "__main__":
    unittest.main()
