"""Tier B: the apphost session state machine, against `MockApphost`.

Every path through `session.py` runs here, over a memory pair **and** over a real
loopback socket for the ones where the socket could differ, so a pass means the
exchange would have satisfied the live node on the captures the surveys took.

What this suite is really guarding, in the order it matters:

1. **Connection hygiene.** astrald serves apphost connections from a fixed pool of
   32 workers and never notices a peer that vanished, so a leaked connection burns
   one worker permanently and 32 of them wedge the node's whole app surface
   (astrald bug G-13). Every failure path asserts the transport is closed, and
   `LeakTest` opens and abandons connections in bulk and asserts every single one
   of them was closed.
2. **The handover.** `query_accepted_msg` is the point of no return; the first raw
   bytes may share a write with it and must not be stranded.
3. **Cancellation.** A cancelled query issues `apphost.cancel` on a **fresh**
   connection, which is exactly what astral-go fails to do -- it dials with the
   already-cancelled context, so its cancel query is never sent (bug G-7).
4. **The nine failure replies**, eight `error_msg` codes and `query_rejected_msg`,
   each mapping to its own exception and each closing the connection.
5. **The protocol as the server implements it**, not as the prose describes it:
   auth failure leaves the connection usable, a dial-back connection has no
   greeting at all, and no path anywhere waits for an `eos`.

Every async test is `bounded`; a hanging test in an async suite wedges the whole
run. No test contacts a node.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
import unittest

from astral import primitives as P
from astral.context import Context
from astral.errors import (
    AllocationLimit,
    AstralError,
    AuthFailed,
    Denied,
    InternalError,
    NodeUnavailable,
    ParseError,
    ProtocolError,
    QueryCanceled,
    QueryRejected,
    QueryTimeout,
    RouteNotFound,
    SessionError,
    StreamCorrupted,
    TargetNotAllowed,
    TransportUnsupported,
    WireError,
)
from astral.object import Ack, EOS, Query
from astral.session import (
    ERROR_CODES,
    AttachQueryMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    HandleQueryMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    PingMsg,
    QueryAcceptedMsg,
    RegisterServiceMsg,
    RejectIncomingMsg,
    RouteQueryMsg,
    Session,
    _track_cancel,
    error_for,
    flush_cancels,
    pending_cancels,
)
from astral.transport import MemTransport, StreamTransport, Transport, dial
from astral.types import Identity, Nonce, Zone

from mock_apphost import (
    ACK,
    ATTACH_QUERY,
    AUTH_SUCCESS,
    AUTH_TOKEN,
    ERROR_MSG,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    HANDLE_QUERY,
    HOST_INFO,
    INCOMING_QUERY,
    PING,
    QUERY_ACCEPTED,
    QUERY_REJECTED,
    REGISTER_SERVICE,
    REJECT_INCOMING,
    Accept,
    Drop,
    ErrorMsg as ErrorRoute,
    Garbage,
    Handshake,
    Hang,
    MockApphost,
    MockConn,
    Reject,
    bounded,
    error_msg_payload,
    frame,
    handle_query_payload,
    host_info_payload,
    incoming_query_payload,
    leaked_sockets,
    oversize_frame,
    partial_frame,
    parse_attach_query,
    parse_query_rejected,
    parse_register_service,
    parse_reject_incoming,
    socket_fds,
    until,
)

WHOAMI = "apphost.whoami"
IDENTITY_FRAME = ("identity", FURRY_BOLT.key)
GUEST = Identity.parse("02" + "22" * 32)
CALLER = Identity.parse("03" + "33" * 32)
TOKEN = "hunter2"

# One `identity` object then EOF: the live shape of apphost.whoami, and the proof
# that nothing waits for an `eos`.
WHOAMI_ROUTE = Accept(objects=[IDENTITY_FRAME])


class SessionCase(unittest.IsolatedAsyncioTestCase):
    """Sessions over memory and over loopback, with the hygiene assertions."""

    async def asyncSetUp(self) -> None:
        self.sessions: list[Session] = []
        # Keyed by the mock itself, not by its id: a mock that went out of scope
        # would let its id be reused and hand the next one a dead listener.
        self.endpoints: dict[MockApphost, str] = {}
        # `MockApphost.listen()` binds a new listener every call and only ever
        # closes the last one, so concurrent callers must not race into it.
        self.listening = asyncio.Lock()
        # The sockets this process already holds, taken inside the loop so the
        # loop's own self-pipe is part of the baseline. Every socket that
        # appears after this and is still open at the leak assertion is one this
        # test opened and did not close.
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        # Nothing may be left in flight between tests: an abandoned cancel task
        # would leak its connection into the next one.
        await flush_cancels(5.0)
        self.assertEqual(pending_cancels(), 0)

    def connector(self, mock: MockApphost, **kw):  # type: ignore[no-untyped-def]
        """A way for a session to open another one over the same memory mock."""

        async def connect() -> Session:
            session = await Session.over(
                await mock.open(), endpoint="mem:mock", **kw
            )
            self.sessions.append(session)
            return session

        return connect

    async def endpoint(self, mock: MockApphost, proto: str = "tcp") -> str:
        async with self.listening:
            if mock not in self.endpoints:
                self.endpoints[mock] = await mock.listen(proto)
            return self.endpoints[mock]

    async def session(
        self, mock: MockApphost, *, over: str = "mem", token: str | None = None, **kw
    ) -> Session:
        """A greeted session over `mock`, tracked for the leak assertions."""
        if over == "mem":
            # The connector inherits the same knobs, so a cancel opened from this
            # session behaves like the session that opened it.
            inherited = {k: v for k, v in kw.items() if k == "cancel_timeout"}
            session = await Session.over(
                await mock.open(),
                endpoint="mem:mock",
                token=token,
                connector=self.connector(mock, **inherited),
                **kw,
            )
        else:
            session = await Session.connect(
                await self.endpoint(mock, over), token=token, **kw
            )
        self.sessions.append(session)
        return session

    async def transport(self, mock: MockApphost, over: str = "mem") -> Transport:
        """A raw transport onto the mock, for the paths that skip the greeting."""
        if over == "mem":
            return await mock.open()
        return await dial(await self.endpoint(mock, over))

    def assert_clean(self, mock: MockApphost) -> None:
        self.assertEqual([repr(e) for e in mock.errors], [])

    async def assert_no_leaks(self, mock: MockApphost) -> None:
        """Every connection, on both sides, closed. The worker-pool discipline."""
        for session in self.sessions:
            self.assertTrue(
                session.transport.closed, f"{session!r} left its transport open"
            )
        await mock.aclose()
        for conn in mock.connections:
            self.assertTrue(conn.transport.closed, f"{conn} left open")
        self.assertEqual(mock.live, 0)
        await self.assert_no_open_sockets()

    async def assert_no_open_sockets(self, since: dict[str, str] | None = None) -> None:
        """No descriptor opened since `since` is still a socket.

        `since` defaults to the baseline taken in `asyncSetUp`, so the default
        scope is the whole test.

        The `closed` flags above are what the SDK says; this is what the kernel
        says, and the two came apart once already: `aclose()` set its flag and
        then blocked inside `wait_closed()` on a socket that stayed ESTABLISHED,
        so a suite that asserted only the flags called that a clean run. A flag
        is a promise, a descriptor is a fact, and the worker-pool constraint of
        design section 3.9 is spent in facts.
        """
        if self.sockets_before is None:  # pragma: no cover -- Linux in this tree
            self.skipTest("no /proc/self/fd: descriptors cannot be counted here")
        base = self.sockets_before if since is None else since
        leaked = leaked_sockets(base)
        if leaked:
            # asyncio releases a descriptor from a `call_soon` callback, so the
            # table settles a turn after the close rather than inside it.
            await until(lambda: not leaked_sockets(base))
            leaked = leaked_sockets(base)
        self.assertEqual(
            leaked,
            set(),
            f"{len(leaked)} socket descriptor(s) left open: {sorted(leaked)}",
        )


# --- the handshake -------------------------------------------------------


class HandshakeTest(SessionCase):
    @bounded()
    async def test_the_host_speaks_first_over_memory_and_over_loopback(self):
        for over in ("mem", "tcp", "unix"):
            with self.subTest(over=over):
                async with MockApphost() as mock:
                    session = await self.session(mock, over=over)
                    self.assertEqual(session.host_id, FURRY_BOLT)
                    self.assertEqual(session.host_alias, FURRY_BOLT_ALIAS)
                    self.assertIsNone(session.guest_id)
                    self.assertFalse(session.authenticated)
                    self.assertTrue(session.supports_raw_stream)
                    await session.aclose()
                    self.assert_clean(mock)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_silent_host_fails_in_the_timeout_and_closes_the_socket(self):
        """The wedged 32-worker pool (astrald bug G-13): the connect succeeds, the
        greeting never comes, and the node never closes. A client that waited on
        the connect alone would hang forever; one that leaked the socket would
        burn a worker on the way out."""
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                # The host never speaks and never closes; the peer's own read
                # returns only when the client closes the socket, which is the
                # positive signal that the client did not leak it.
                hung = asyncio.Event()
                async with MockApphost(session=_never_greets(hung)) as mock:
                    transport = await self.transport(mock, over)
                    with self.assertRaises(NodeUnavailable) as caught:
                        await Session.over(transport, timeout=0.1)
                    self.assertIn("no greeting", str(caught.exception))
                    self.assertTrue(transport.closed)
                    self.assertTrue(await until(hung.is_set))
                    self.assert_clean(mock)

    @bounded()
    async def test_connect_bounds_the_dial_and_the_greeting_together(self):
        """Design section 3.9 item 3: `CONNECT_TIMEOUT` covers the greeting, not
        merely the connect, so a saturated node surfaces in 5 s rather than as an
        infinite hang."""
        hung = asyncio.Event()
        async with MockApphost(session=_never_greets(hung)) as mock:
            with self.assertRaises(NodeUnavailable):
                await Session.connect(await self.endpoint(mock), timeout=0.1)
            self.assertTrue(await until(hung.is_set))

    @bounded()
    async def test_every_broken_greeting_is_node_unavailable_and_closes(self):
        for handshake in (
            Handshake.CLOSE,
            Handshake.TRUNCATED,
            Handshake.GARBAGE,
            Handshake.OVERSIZE,
        ):
            with self.subTest(handshake=handshake):
                async with MockApphost(handshake=handshake) as mock:
                    transport = await self.transport(mock)
                    with self.assertRaises(NodeUnavailable):
                        await Session.over(transport)
                    self.assertTrue(transport.closed)

    @bounded()
    async def test_a_well_formed_greeting_of_the_wrong_type_is_a_protocol_error(self):
        """A node that speaks something else is not a node to retry against; a
        node that never spoke is."""
        async with MockApphost(handshake=Handshake.WRONG_TYPE) as mock:
            transport = await self.transport(mock)
            with self.assertRaises(ProtocolError):
                await Session.over(transport)
            self.assertTrue(transport.closed)

    @bounded()
    async def test_a_refused_dial_is_node_unavailable(self):
        with self.assertRaises(NodeUnavailable):
            await Session.connect("tcp:127.0.0.1:1", timeout=1.0)

    @bounded()
    async def test_a_reset_before_the_greeting_is_node_unavailable_not_an_oserror(self):
        """A restarting, OOM-killed or crashed astrald resets the socket instead
        of closing it, and a reset arrives as `ConnectionResetError` -- an
        `OSError`, outside the exception hierarchy entirely and outside the one
        class the retry decorator retries. Nothing was sent, so this is the
        retryable case, and three attempts because one reset in twenty-five
        arrives as a clean close instead."""
        endpoint, close = await self._resetting_host()
        try:
            for attempt in range(3):
                with self.subTest(attempt=attempt):
                    with self.assertRaises(NodeUnavailable):
                        await Session.connect(endpoint, timeout=2.0)
        finally:
            await close()

    @bounded()
    async def test_a_reset_read_is_node_unavailable_over_any_transport(self):
        """The mapping itself, deterministically: a transport whose read reports
        a reset rather than an EOF must still surface as the retryable class."""

        class _Reset(MemTransport):
            async def readexactly(self, n: int) -> bytes:
                raise ConnectionResetError("[Errno 104] Connection reset by peer")

        left, _right = _Reset.pair("reset")
        with self.assertRaises(NodeUnavailable) as caught:
            await Session.over(left, timeout=1.0)
        self.assertIsInstance(caught.exception.__cause__, ConnectionResetError)
        self.assertTrue(left.closed)

    @bounded()
    async def test_over_closes_the_transport_when_the_constructor_fails(self):
        """`_open_channel()` is the one method every transport variant overrides
        and it raises for every framing not yet implemented, so a configuration
        mistake must not become a burned node worker."""

        class _NoChannel(Session):
            def _open_channel(self, transport):  # type: ignore[no-untyped-def]
                raise TransportUnsupported("no channel for this format")

        left, _right = MemTransport.pair("nochannel")
        with self.assertRaises(TransportUnsupported):
            await _NoChannel.over(left, endpoint="mem:nochannel")
        self.assertTrue(left.closed)

    @bounded()
    async def test_the_auth_exchange_gets_its_own_budget_and_its_own_name(self):
        """Design section 3.6 gives the dial plus greeting and the auth exchange
        separate deadlines. Sharing one made `HANDSHAKE_TIMEOUT` inert -- auth got
        whatever the dial had not spent -- and reported an auth stall as a missing
        greeting, which is the single most confusable failure in this system."""
        async with MockApphost(session=_greet_and_hang) as mock:
            started = asyncio.get_running_loop().time()
            with self.assertRaises(NodeUnavailable) as caught:
                await Session.connect(
                    await self.endpoint(mock),
                    token=TOKEN,
                    timeout=5.0,
                    handshake_timeout=0.05,
                )
            waited = asyncio.get_running_loop().time() - started
            # The auth budget alone decides when this fails: on the shared
            # deadline it would have taken the full five seconds.
            self.assertLess(waited, 2.0)
            self.assertIn("auth_token_msg", str(caught.exception))
            self.assertNotIn("no greeting", str(caught.exception))
            self.assertTrue(await until(lambda: mock.connections[0].transport.closed))

    async def _resetting_host(self):  # type: ignore[no-untyped-def]
        """A loopback host that answers every connection with an RST.

        `SO_LINGER {on, 0}` makes `close()` abortive, which is what a dying
        astrald does to its accepted sockets.
        """

        def abort(writer: asyncio.StreamWriter) -> None:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
            writer.close()

        async def on_connect(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            abort(writer)

        server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]

        async def close() -> None:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

        return f"tcp:{host}:{port}", close

    @bounded()
    async def test_an_ungreeted_session_refuses_to_route(self):
        transport = MemTransport.solo()
        session = Session(transport)
        with self.assertRaises(RuntimeError):
            await session.route_query(WHOAMI)
        await session.aclose()

    @bounded()
    async def test_the_greeting_is_one_frame_and_nothing_more_is_read(self):
        """The session consumes exactly the greeting: a byte of read-ahead here
        would be a byte stranded at the handover later."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            transport = await mock.open()
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            self.assertEqual(transport.buffered, 0)
            await session.aclose()
            await self.assert_no_leaks(mock)


# --- auth ----------------------------------------------------------------


class AuthTest(SessionCase):
    @bounded()
    async def test_a_good_token_authenticates_the_session(self):
        async with MockApphost(token=TOKEN, guest_id=GUEST) as mock:
            session = await self.session(mock, token=TOKEN)
            self.assertEqual(session.guest_id, GUEST)
            self.assertTrue(session.authenticated)
            self.assertEqual(mock.tokens, [TOKEN])
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_token_frame_is_a_bare_string8(self):
        """astral-go hand-rolls `auth_token_msg`'s payload rather than walking a
        struct. A one-field record emits the same bytes."""
        transport = MemTransport.solo()
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        transport.feed(frame(ERROR_MSG, error_msg_payload("auth_failed")))
        session = Session(transport)
        await session._greeting(1.0)
        with self.assertRaises(AuthFailed):
            await session.auth("abc")
        self.assertEqual(transport.sent, frame(AUTH_TOKEN, b"\x03abc"))
        await session.aclose()

    @bounded()
    async def test_a_refused_token_leaves_the_connection_a_message_channel(self):
        """Verified live: the node answers `error_msg{auth_failed}` and keeps its
        read loop running, so an anonymous query on the same connection works."""
        async with MockApphost(token=TOKEN, routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            with self.assertRaises(AuthFailed):
                await session.auth("wrong")
            self.assertFalse(session.transport.closed)
            self.assertFalse(session.authenticated)
            async with await session.route_query(WHOAMI) as stream:
                self.assertEqual(await stream.receive(), FURRY_BOLT)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_connect_with_a_bad_token_closes_the_socket(self):
        """A session that never came up hands nothing back, so nothing else could
        close it."""
        async with MockApphost(token=TOKEN) as mock:
            transport = await self.transport(mock)
            with self.assertRaises(AuthFailed):
                await Session.over(transport, token="wrong")
            self.assertTrue(transport.closed)

    @bounded()
    async def test_an_unexpected_auth_reply_is_a_protocol_error(self):
        transport = MemTransport.solo()
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        transport.feed(frame(ACK))
        session = Session(transport)
        await session._greeting(1.0)
        with self.assertRaises(ProtocolError):
            await session.auth("abc")
        await session.aclose()

    @bounded()
    async def test_a_silent_node_during_auth_is_node_unavailable(self):
        async with MockApphost(session=_greet_and_hang) as mock:
            session = await self.session(mock)
            with self.assertRaises(NodeUnavailable):
                await session.auth(TOKEN, timeout=0.05)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_node_that_dies_during_auth_is_node_unavailable(self):
        """A reset is a dead connection as much as a clean close is, and it
        arrives as an `OSError` rather than an `EOFError`. Retryable: the guest
        sent a token, not a query, so a retry cannot duplicate an effect."""
        transport = _ResetsWhenDrained.solo("dies")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        session = await Session.over(transport, endpoint="mem:dies")
        with self.assertRaises(NodeUnavailable) as caught:
            await session.auth(TOKEN)
        self.assertIsInstance(caught.exception.__cause__, ConnectionResetError)
        await session.aclose()


class DesyncTest(SessionCase):
    """A framing fault costs the connection, because it costs the frame boundary.

    A reply declaring four gigabytes is refused *after* its tag and length have
    been consumed and its payload is never drained, so the byte stream is
    desynchronised and every byte the peer sends afterwards is read as a control
    message. Leaving that connection open is not merely wasteful: the peer can
    then hand the client a `query_accepted_msg` for a query the node never
    routed, and the app writes its request body into the apphost control
    channel.
    """

    def desynchronised(self) -> tuple[Session, MemTransport]:
        """A greeted session whose next control read will lose the boundary."""
        transport = MemTransport.solo("hostile")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        # A header declaring 4 GiB, with nothing behind it, and then the forgery
        # the desynchronised reader would otherwise walk straight into.
        transport.feed(oversize_frame(AUTH_SUCCESS))
        transport.feed(frame(QUERY_ACCEPTED))
        return Session(transport, endpoint="mem:hostile"), transport

    @bounded()
    async def test_a_framing_fault_in_auth_closes_and_refuses_reuse(self):
        session, transport = self.desynchronised()
        await session._greeting(1.0)
        with self.assertRaises(AllocationLimit):
            await session.auth("hunter2")
        self.assertTrue(session.closed)
        self.assertTrue(transport.closed)
        # And the forged acceptance is unreachable: the session refuses to route
        # anything at all rather than handing back a stream for a query the node
        # never saw.
        with self.assertRaises(RuntimeError):
            await session.route_query(WHOAMI)

    @bounded()
    async def test_auth_keeps_the_connection_only_for_a_refused_token(self):
        """The live node's behaviour justifies exactly one exemption. Every
        other outcome closes."""
        greeting = frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
        cases = [
            (frame(ERROR_MSG, error_msg_payload("auth_failed")), AuthFailed, False),
            (frame(ERROR_MSG, error_msg_payload("denied")), Denied, True),
            (frame(ERROR_MSG, error_msg_payload("internal_error")), InternalError, True),
            (frame(ACK), ProtocolError, True),
        ]
        for reply, error, closes in cases:
            with self.subTest(error=error.__name__):
                transport = MemTransport.solo("auth")
                transport.feed(greeting)
                transport.feed(reply)
                session = Session(transport, endpoint="mem:auth")
                await session._greeting(1.0)
                with self.assertRaises(error):
                    await session.auth("hunter2")
                self.assertEqual(session.closed, closes)
                self.assertEqual(transport.closed, closes)
                await session.aclose()

    @bounded()
    async def test_a_framing_fault_on_any_control_read_closes(self):
        """`auth` is where it was found; the rule belongs to every control read,
        so `receive()` -- the raw escape hatch the serving layer uses -- closes
        as well."""
        transport = MemTransport.solo("hostile")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        transport.feed(oversize_frame(INCOMING_QUERY))
        session = Session(transport, endpoint="mem:hostile")
        await session._greeting(1.0)
        with self.assertRaises(AllocationLimit):
            await session.receive()
        self.assertTrue(session.closed)
        self.assertTrue(transport.closed)


class BackPressureTest(SessionCase):
    """`timeout` bounds the call it names, send included.

    `Channel.send` ends in `Transport.drain()`, whose entire job is to wait for
    the peer's receive window, so a peer that accepts the connection and stops
    reading pins any send that sits outside its deadline. Every method here was
    measured blocking past its own `timeout=1.0` before this was fixed;
    `route_query` was the only one that already got it right.
    """

    def deaf(self, *frames: bytes, deaf_after: int = 0) -> _Deaf:
        transport = _Deaf.solo("deaf")
        transport.deaf_after = deaf_after
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        for extra in frames:
            transport.feed(extra)
        return transport

    async def session_over(self, transport: _Deaf) -> Session:
        session = await Session.over(transport, endpoint="mem:deaf")
        self.sessions.append(session)
        # Set rather than negotiated: authenticating would itself have to send,
        # which is the thing under test.
        session._guest_id = FURRY_BOLT
        return session

    async def assert_bounded(self, coro, error: type[BaseException]) -> None:
        """The call must raise its own typed deadline, not run into ours.

        The outer bound is what distinguishes "expired in 0.05 s" from "hung and
        was killed", which is the whole distinction this class exists to make.
        """
        started = asyncio.get_running_loop().time()
        with self.assertRaises(error):
            async with asyncio.timeout(2.0):
                await coro
        self.assertLess(asyncio.get_running_loop().time() - started, 1.0)

    @bounded()
    async def test_every_control_send_is_bounded_by_its_own_timeout(self):
        cases = [
            ("auth", lambda s: s.auth("tok", timeout=0.05), NodeUnavailable),
            (
                "register_service",
                lambda s: s.register_service(FURRY_BOLT, timeout=0.05),
                QueryTimeout,
            ),
            ("attach_query", lambda s: s.attach_query(1, timeout=0.05), QueryTimeout),
            (
                "reject_incoming",
                lambda s: s.reject_incoming(1, 2, timeout=0.05),
                QueryTimeout,
            ),
            ("route_query", lambda s: s.route_query("q", timeout=0.05), QueryTimeout),
        ]
        for name, call, error in cases:
            with self.subTest(call=name):
                # One connection each: most of these close on failure, and a
                # closed session would refuse the next call for the wrong reason.
                session = await self.session_over(self.deaf())
                await self.assert_bounded(call(session), error)

    @bounded()
    async def test_a_refusal_that_cannot_be_sent_still_closes_the_connection(self):
        """`reject_query` and `skip_query` send and then close. An unsendable
        refusal must not take the close down with it -- that is the leak the
        refusal was meant to avoid."""
        payload = handle_query_payload(Nonce(1), Nonce(2), CALLER, FURRY_BOLT, "x.y")
        for name, call in (
            ("reject_query", lambda s: s.reject_query(1, timeout=0.05)),
            ("skip_query", lambda s: s.skip_query(timeout=0.05)),
        ):
            with self.subTest(call=name):
                transport = _Deaf.solo("deaf")
                transport.feed(frame(HANDLE_QUERY, payload))
                session = Session.dialed_in(transport, endpoint="mem:deaf")
                await session.read_query(timeout=1.0)
                await self.assert_bounded(call(session), QueryTimeout)
                self.assertTrue(session.closed)
                self.assertTrue(transport.closed)

    @bounded()
    async def test_an_acceptance_that_cannot_be_sent_is_bounded_and_closes(self):
        payload = handle_query_payload(Nonce(1), Nonce(2), CALLER, FURRY_BOLT, "x.y")
        transport = _Deaf.solo("deaf")
        transport.feed(frame(HANDLE_QUERY, payload))
        session = Session.dialed_in(transport, endpoint="mem:deaf")
        await session.read_query(timeout=1.0)
        await self.assert_bounded(session.accept_query(timeout=0.05), QueryTimeout)
        self.assertTrue(session.closed)
        self.assertTrue(transport.closed)

    @bounded()
    async def test_the_bind_tokens_are_sent_inside_a_deadline(self):
        """`apphost.bind` sends after its stream is accepted, so its sends sat
        outside every deadline the method takes."""
        transport = self.deaf(frame(QUERY_ACCEPTED), frame(ACK), deaf_after=1)
        session = await self.session_over(transport)
        await self.assert_bounded(
            session.bind(Nonce(7), timeout=1.0, ack_timeout=0.05), QueryTimeout
        )
        self.assertTrue(transport.closed)


# --- routing a query -----------------------------------------------------


class RouteQueryTest(SessionCase):
    @bounded()
    async def test_an_accepted_query_hands_back_its_stream(self):
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
                    session = await self.session(mock, over=over)
                    stream = await session.route_query(WHOAMI)
                    self.assertTrue(session.spent)
                    self.assertTrue(stream.outbound)
                    self.assertEqual(stream.query_string, WHOAMI)
                    self.assertEqual(stream.remote_id, FURRY_BOLT)
                    self.assertEqual(await stream.receive(), FURRY_BOLT)
                    with self.assertRaises(EOFError):
                        await stream.receive()
                    self.assertFalse(stream.saw_eos)
                    await stream.aclose()
                    self.assert_clean(mock)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_defaults_are_the_guest_and_the_host_identities(self):
        async with MockApphost(
            token=TOKEN, guest_id=GUEST, routes={WHOAMI: WHOAMI_ROUTE}
        ) as mock:
            session = await self.session(mock, token=TOKEN)
            async with await session.route_query(WHOAMI) as stream:
                self.assertEqual(stream.local_id, GUEST)
            sent = mock.queries[0]
            self.assertEqual(sent.caller, GUEST)
            self.assertEqual(sent.target, FURRY_BOLT)
            self.assertEqual(sent.zone, int(Zone.ALL))
            self.assertEqual(sent.filters, ())
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_anonymous_caller_is_the_nil_flag_not_the_anyone_identity(self):
        """Two encodings mean the same thing and are not the same bytes: a nil
        pointer is one `0x00`, `anyone` is `0x01` and 33 zero bytes."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            transport = await mock.open()
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            stream = await session.route_query(WHOAMI)
            self.assertIsNone(mock.queries[0].caller)
            self.assertIn(b"\x00\x01" + FURRY_BOLT.key, transport.sent)
            await stream.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_explicit_none_caller_overrides_the_session_identity(self):
        async with MockApphost(
            token=TOKEN, guest_id=GUEST, routes={WHOAMI: WHOAMI_ROUTE}
        ) as mock:
            session = await self.session(mock, token=TOKEN)
            async with await session.route_query(WHOAMI, caller=None):
                pass
            self.assertIsNone(mock.queries[0].caller)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_zone_filters_and_nonce_travel_as_given(self):
        """Zone travels per hop, in this message. The `query` type has no zone
        field at all (astral-docs bug D-25)."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            async with await session.route_query(
                WHOAMI, zone=Zone.DEVICE, filters=["abc", "def"], nonce=Nonce(0xABCD)
            ) as stream:
                self.assertEqual(stream.nonce, Nonce(0xABCD))
            sent = mock.queries[0]
            self.assertEqual(sent.zone, int(Zone.DEVICE))
            self.assertEqual(sent.filters, ("abc", "def"))
            self.assertEqual(sent.nonce, Nonce(0xABCD))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_zone_is_sent_as_asked_even_when_the_node_will_narrow_it(self):
        """The node strips `ZoneNetwork` for a token-less guest whatever it sent,
        so narrowing here would only diverge from astral-go's bytes for no gain.
        `Context.anonymous()` is where a caller sees the zone that will apply."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            self.assertFalse(session.authenticated)
            async with await session.route_query(WHOAMI, zone=Zone.ALL):
                pass
            self.assertEqual(mock.queries[0].zone, int(Zone.ALL))
            await self.assert_no_leaks(mock)

    def test_the_query_object_carries_no_zone(self):
        """Zone travels per hop, in `route_query_msg`. The `query` wire type has
        no zone field at all (astral-docs bug D-25)."""
        self.assertEqual(
            [field.wire_name for field in Query.FIELDS],
            ["Nonce", "Caller", "Target", "QueryString"],
        )
        self.assertIn("Zone", [field.wire_name for field in RouteQueryMsg.FIELDS])

    @bounded()
    async def test_a_context_supplies_caller_zone_and_filters(self):
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            context = Context(identity=CALLER, zone=Zone.DEVICE).with_filters("f")
            async with await session.route_query(WHOAMI, context=context):
                pass
            sent = mock.queries[0]
            self.assertEqual(sent.caller, CALLER)
            self.assertEqual(sent.zone, int(Zone.DEVICE))
            self.assertEqual(sent.filters, ("f",))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_explicit_argument_beats_the_context(self):
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            context = Context(identity=CALLER, zone=Zone.DEVICE)
            async with await session.route_query(
                WHOAMI, context=context, zone=Zone.ALL, caller=None
            ):
                pass
            self.assertEqual(mock.queries[0].zone, int(Zone.ALL))
            self.assertIsNone(mock.queries[0].caller)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_hex_target_is_parsed_and_a_name_is_not_resolvable_here(self):
        """66 hex characters parse locally; a name needs `dir.resolve` and
        therefore belongs one layer up."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            async with await session.route_query(WHOAMI, target=CALLER.hex()):
                pass
            self.assertEqual(mock.queries[0].target, CALLER)
            session2 = await self.session(mock)
            with self.assertRaises(ParseError):
                await session2.route_query(WHOAMI, target="furry-bolt")
            await session2.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_every_nonce_is_fresh(self):
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            for _ in range(8):
                session = await self.session(mock)
                async with await session.route_query(WHOAMI):
                    pass
            self.assertEqual(len({q.nonce for q in mock.queries}), 8)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_route_query_frame_is_exactly_one_write(self):
        """Invariant 2 of design section 7.2: one write per frame is what makes a
        write lock unnecessary and a mid-frame cancellation impossible."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            transport = await mock.open()
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            async with await session.route_query(WHOAMI):
                pass
            self.assertEqual(len(transport.writes), 1)
            await self.assert_no_leaks(mock)


class FailureReplyTest(SessionCase):
    """The nine failure replies. Each maps to one exception and closes."""

    @bounded()
    async def test_every_error_code_maps_to_its_own_exception_and_closes(self):
        expected = {
            "auth_failed": AuthFailed,
            "denied": Denied,
            "route_not_found": RouteNotFound,
            "internal_error": InternalError,
            "protocol_error": ProtocolError,
            "timeout": QueryTimeout,
            "canceled": QueryCanceled,
            "target_not_allowed": TargetNotAllowed,
        }
        self.assertEqual(set(expected), set(ERROR_CODES))
        for code, error in expected.items():
            for over in ("mem", "tcp"):
                with self.subTest(code=code, over=over):
                    async with MockApphost(routes={"x.y": ErrorRoute(code)}) as mock:
                        session = await self.session(mock, over=over)
                        with self.assertRaises(error):
                            await session.route_query("x.y")
                        self.assertTrue(session.transport.closed)
                        await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_rejection_carries_its_code(self):
        for code in (1, 2, 3, 4, 9, 255):
            with self.subTest(code=code):
                async with MockApphost(routes={"x.y": Reject(code)}) as mock:
                    session = await self.session(mock)
                    with self.assertRaises(QueryRejected) as caught:
                        await session.route_query("x.y")
                    self.assertEqual(caught.exception.code, code)
                    self.assertTrue(session.transport.closed)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_reject_code_zero_reads_as_the_default(self):
        """0 is success and is never a valid rejection. The substitution is this
        SDK's: astral-go's apphost client passes the code through verbatim, so a
        Go caller sees a rejection carrying the success code."""
        async with MockApphost(routes={"x.y": Reject(0)}) as mock:
            session = await self.session(mock)
            with self.assertRaises(QueryRejected) as caught:
                await session.route_query("x.y")
            self.assertEqual(caught.exception.code, 1)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unknown_error_code_is_the_base_session_error(self):
        """The eight codes are exhaustive today. A ninth must not be folded into
        a neighbouring meaning."""
        async with MockApphost(routes={"x.y": ErrorRoute("brand_new_code")}) as mock:
            session = await self.session(mock)
            with self.assertRaises(SessionError) as caught:
                await session.route_query("x.y")
            self.assertIs(type(caught.exception), SessionError)
            self.assertIn("brand_new_code", str(caught.exception))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_connection_is_closed_even_though_the_node_would_reuse_it(self):
        """astral-docs bug D-14: after `route_not_found` the connection is still a
        message channel and a second query is served normally, verified live. We
        close anyway, matching astral-go's client -- reuse is unexercised by any
        reference implementation and an idle connection costs a node worker."""
        async with MockApphost(routes={"x.y": ErrorRoute("route_not_found")}) as mock:
            session = await self.session(mock)
            with self.assertRaises(RouteNotFound):
                await session.route_query("x.y")
            self.assertTrue(session.closed)
            self.assertTrue(session.transport.closed)
            with self.assertRaises(RuntimeError):
                await session.route_query(WHOAMI)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_node_that_closes_without_answering_is_a_protocol_error(self):
        async with MockApphost(routes={"x.y": Drop()}) as mock:
            session = await self.session(mock)
            with self.assertRaises(ProtocolError):
                await session.route_query("x.y")
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_node_that_dies_after_the_query_is_a_protocol_error(self):
        """A reset after `route_query_msg` is not `NodeUnavailable` however much
        it looks like a dial failure: the query *was* sent, so the retry
        promise -- a retry cannot duplicate an effect -- does not hold. It must
        still stay inside the hierarchy rather than escaping as an `OSError`."""
        transport = _ResetsWhenDrained.solo("dies")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        session = await Session.over(transport, endpoint="mem:dies")
        with self.assertRaises(ProtocolError) as caught:
            await session.route_query("x.y")
        self.assertIsInstance(caught.exception.__cause__, ConnectionResetError)
        self.assertTrue(transport.closed)

    @bounded()
    async def test_non_frame_bytes_are_a_stream_fault_and_close(self):
        async with MockApphost(routes={"x.y": Garbage()}) as mock:
            session = await self.session(mock)
            with self.assertRaises(StreamCorrupted):
                await session.route_query("x.y")
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unexpected_reply_type_is_a_protocol_error(self):
        async def second_greeting(conn: MockConn, query) -> None:  # type: ignore[no-untyped-def]
            conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
            await conn.flush()

        async with MockApphost(routes={"x.y": second_greeting}) as mock:
            session = await self.session(mock)
            with self.assertRaises(ProtocolError):
                await session.route_query("x.y")
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_query_that_is_never_answered_times_out_and_closes(self):
        async with MockApphost(routes={"x.y": Hang()}) as mock:
            session = await self.session(mock)
            with self.assertRaises(QueryTimeout):
                await session.route_query("x.y", timeout=0.05)
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    def test_the_error_table_is_the_whole_of_astral_gos_code_set(self):
        self.assertEqual(
            sorted(ERROR_CODES),
            [
                "auth_failed",
                "canceled",
                "denied",
                "internal_error",
                "protocol_error",
                "route_not_found",
                "target_not_allowed",
                "timeout",
            ],
        )
        self.assertIsInstance(error_for("denied"), Denied)


class HandoverTest(SessionCase):
    @bounded()
    async def test_no_stranded_bytes_when_the_acceptance_shares_a_write(self):
        """Invariant 1 of design section 7.2, through the session: the mock puts
        `query_accepted_msg` and the whole body in one write, and the session must
        hand every body byte to the stream."""
        route = Accept(objects=[IDENTITY_FRAME], eos=True, coalesce=True)
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                async with MockApphost(routes={WHOAMI: route}) as mock:
                    session = await self.session(mock, over=over)
                    stream = await session.route_query(WHOAMI)
                    self.assertIs(stream.transport, session.transport)
                    self.assertEqual([obj async for obj in stream], [FURRY_BOLT])
                    self.assertTrue(stream.saw_eos)
                    await stream.aclose()
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_session_consumed_exactly_the_acceptance_frame(self):
        """The sharpest form: after the reply the transport still holds every body
        byte, so the session read no further than the frame it needed."""
        route = Accept(objects=[IDENTITY_FRAME], eos=True, coalesce=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            transport = await mock.open()
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            stream = await session.route_query(WHOAMI)
            body = len(frame(*IDENTITY_FRAME)) + len(frame("eos"))
            self.assertEqual(transport.buffered, body)
            await stream.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_one_byte_at_a_time_transport_reassembles(self):
        route = Accept(objects=[IDENTITY_FRAME], eos=True, coalesce=True)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            transport = await mock.open(max_chunk=1)
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            async with await session.route_query(WHOAMI) as stream:
                self.assertEqual([obj async for obj in stream], [FURRY_BOLT])
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_accepted_query_need_not_carry_objects_at_all(self):
        """`objects.read` is the RAW op: its response body is unframed bytes, so
        the handover must not assume a framing."""
        route = Accept(raw=b"\x00\x01\x02 not a frame")
        async with MockApphost(routes={"objects.read": route}) as mock:
            session = await self.session(mock)
            async with await session.route_query("objects.read") as stream:
                self.assertEqual(await stream.read(-1), b"\x00\x01\x02 not a frame")
                self.assertFalse(stream.framed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_session_is_spent_after_the_handover(self):
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            stream = await session.route_query(WHOAMI)
            self.assertTrue(session.spent)
            for call in (
                session.route_query(WHOAMI),
                session.receive(),
                session.send(Ack()),
            ):
                with self.assertRaises(RuntimeError):
                    await call
            await stream.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_closing_the_session_does_not_close_the_handed_over_stream(self):
        """Ownership transfers at the acceptance: the stream closes the transport,
        and it is an async context manager so that always happens."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            stream = await session.route_query(WHOAMI)
            await session.aclose()
            self.assertFalse(stream.transport.closed)
            self.assertEqual(await stream.receive(), FURRY_BOLT)
            await stream.aclose()
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_follow_mode_eos_is_a_separator_not_a_terminator(self):
        """The `eos` of a follow-mode op separates the snapshot from the live
        tail; the stream stays open and more objects arrive after it."""
        route = Accept(objects=[IDENTITY_FRAME], eos=True, live=[IDENTITY_FRAME])
        async with MockApphost(routes={"tree.get": route}) as mock:
            session = await self.session(mock)
            async with await session.route_query("tree.get") as stream:
                self.assertEqual([obj async for obj in stream], [FURRY_BOLT])
                self.assertTrue(stream.saw_eos)
                self.assertEqual(await stream.receive(), FURRY_BOLT)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_write_and_answer_exchange_over_the_stream(self):
        async with MockApphost(routes={"objects.echo": Accept(echo=True)}) as mock:
            session = await self.session(mock)
            async with await session.route_query("objects.echo") as stream:
                await stream.send(P.Uint32(7))
                self.assertEqual(await stream.receive(), P.Uint32(7))
                await stream.send_eos()
                self.assertEqual([obj async for obj in stream], [])
                self.assertTrue(stream.saw_eos)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_truncated_body_is_a_stream_fault_not_a_clean_end(self):
        route = Accept(objects=[IDENTITY_FRAME], truncate=8)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            session = await self.session(mock)
            async with await session.route_query(WHOAMI) as stream:
                with self.assertRaises(StreamCorrupted):
                    await stream.receive()
            await self.assert_no_leaks(mock)


# --- cancellation --------------------------------------------------------


class CancelTest(SessionCase):
    """Design section 3.5, and the fix for astral-go bug G-7."""

    def routes(self, **extra):  # type: ignore[no-untyped-def]
        routes = {"slow.op": Hang(), "apphost.cancel": Accept(objects=[(ACK, b"")])}
        routes.update(extra)
        return routes

    async def cancel_in_flight(self, mock: MockApphost, session: Session, **kw) -> None:  # type: ignore[no-untyped-def]
        """Route `slow.op` and cancel it the way a caller does: from outside.

        The cancel machinery answers an external cancellation and not the SDK's
        own deadline, so every test of that machinery drives it this way.
        """
        seen = len(mock.queries)
        task = asyncio.create_task(session.route_query("slow.op", **kw))
        await until(lambda: len(mock.queries) > seen)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    @bounded()
    async def test_a_timed_out_query_does_not_dial_a_second_connection(self):
        """Our own deadline is not a caller's cancellation, however identically
        `asyncio.timeout` delivers it.

        Answering the deadline with `apphost.cancel` costs twice: the caller's
        `timeout=T` becomes T + `CANCEL_TIMEOUT` -- measured at 2.50 s for
        `timeout=0.5` before this was fixed -- and the SDK opens a second
        connection into the node whose non-answer caused the deadline, per
        timed-out query, which is demand amplification on the exact 32-worker
        pool of design section 3.9. The node either never saw the query or is
        answering nothing; closing this connection ends it there.
        """
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                async with MockApphost(routes=self.routes()) as mock:
                    session = await self.session(
                        mock, over=over, cancel_timeout=5.0
                    )
                    started = asyncio.get_running_loop().time()
                    with self.assertRaises(QueryTimeout):
                        await session.route_query(
                            "slow.op", timeout=0.05, nonce=Nonce(0xAABB)
                        )
                    waited = asyncio.get_running_loop().time() - started
                    # `timeout=T` means T. A cancel dial would have added its
                    # own 5 s budget to it.
                    self.assertLess(waited, 1.0)
                    await flush_cancels(5.0)
                    self.assertTrue(session.transport.closed)
                    self.assertEqual([q.op for q in mock.queries], ["slow.op"])
                    self.assertEqual(mock.conn_count, 1)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_externally_cancelled_query_cancels_on_a_fresh_connection(self):
        """The path the cancel machinery exists for, and the one astral-go gets
        wrong: it dials with the already-cancelled context, so its cancel query
        is never sent (bug G-7)."""
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                async with MockApphost(routes=self.routes()) as mock:
                    session = await self.session(mock, over=over)
                    task = asyncio.create_task(
                        session.route_query("slow.op", nonce=Nonce(0xAABB))
                    )
                    await until(lambda: len(mock.queries) == 1)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    await flush_cancels(5.0)
                    self.assertTrue(session.transport.closed)
                    self.assertEqual(
                        [q.op for q in mock.queries][:2], ["slow.op", "apphost.cancel"]
                    )
                    cancel = mock.queries[1]
                    self.assertEqual(cancel.query, "apphost.cancel?id=000000000000aabb")
                    # Device zone only: cancelling a query never leaves the machine.
                    self.assertEqual(cancel.zone, int(Zone.DEVICE))
                    self.assertEqual(mock.conn_count, 2)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_second_cancellation_does_not_abandon_the_cancel(self):
        """The shield earns its keep here. One `task.cancel()` is delivered and
        handled; a second -- what a `TaskGroup` abort does -- would abandon the
        cancel task mid-dial, leaving a half-open connection nobody closes. The
        task is shielded and strongly referenced, so it finishes anyway."""
        async with MockApphost(routes=self.routes()) as mock:
            session = await self.session(mock, cancel_timeout=1.0)
            task = asyncio.create_task(
                session.route_query("slow.op", nonce=Nonce(0x77))
            )
            await until(lambda: len(mock.queries) == 1)
            task.cancel()
            self.assertTrue(await until(lambda: pending_cancels() == 1))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(session.transport.closed)
            await flush_cancels(5.0)
            self.assertEqual(mock.queries[1].query, "apphost.cancel?id=0000000000000077")
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_cancel_connection_is_closed_after_use(self):
        async with MockApphost(routes=self.routes()) as mock:
            session = await self.session(mock)
            await self.cancel_in_flight(mock, session)
            await flush_cancels(5.0)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_cancel_query_does_not_cancel_itself(self):
        """`apphost.cancel` routes with the cancel hook off: a cancel that
        cancelled would open connections without end.

        The cancel here is answered by a host that never answers, which also pins
        the bound: the shielded wait is `cancel_timeout` and not a hang.
        """
        async with MockApphost(routes=self.routes(**{"apphost.cancel": Hang()})) as mock:
            session = await self.session(mock, cancel_timeout=0.2)
            started = asyncio.get_running_loop().time()
            await self.cancel_in_flight(mock, session)
            waited = asyncio.get_running_loop().time() - started
            self.assertGreaterEqual(waited, 0.2)
            self.assertLess(waited, 2.0)
            await flush_cancels(5.0)
            self.assertEqual(mock.conn_count, 2)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_failing_cancel_never_raises_and_never_leaks(self):
        """Best effort means best effort: the node answering `route_not_found`
        for `apphost.cancel` changes nothing the caller sees."""
        async with MockApphost(routes={"slow.op": Hang()}) as mock:
            session = await self.session(mock)
            await self.cancel_in_flight(mock, session)
            await flush_cancels(5.0)
            self.assertEqual([q.op for q in mock.queries], ["slow.op", "apphost.cancel"])
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_session_with_no_connector_cannot_cancel_and_says_so(self):
        async with MockApphost(routes={"slow.op": Hang()}) as mock:
            transport = await mock.open()
            session = await Session.over(transport, endpoint="mem:mock")
            self.sessions.append(session)
            with self.assertRaises(QueryTimeout):
                await session.route_query("slow.op", timeout=0.05)
            self.assertTrue(transport.closed)
            self.assertEqual(mock.conn_count, 1)
            self.assertFalse(await session.cancel(Nonce(1)))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_cancel_can_be_asked_for_explicitly(self):
        async with MockApphost(routes=self.routes()) as mock:
            session = await self.session(mock)
            self.assertTrue(await session.cancel(Nonce(0x55), cause="user quit"))
            cancel = mock.queries[0]
            self.assertEqual(cancel.op, "apphost.cancel")
            self.assertIn("cause=user+quit", cancel.query)
            self.assertIn("id=0000000000000055", cancel.query)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_cancel_is_never_left_in_flight(self):
        async with MockApphost(routes=self.routes()) as mock:
            session = await self.session(mock)
            await self.cancel_in_flight(mock, session)
            await flush_cancels(5.0)
            self.assertEqual(pending_cancels(), 0)
            await self.assert_no_leaks(mock)


class FlushCancelsTest(SessionCase):
    """`flush_cancels()` is what shutdown awaits, so its own contract is
    load-bearing in both directions: it drains other people's cancels, and it
    never swallows a cancellation aimed at itself.

    A bare `await task` swallows every one of them. Awaiting a task delegates the
    *awaiting* task's cancellation into the awaited one, so the `CancelledError`
    always arrives with `task.cancelled()` true and a guard on that flag never
    fires: the deadline argument goes inert, an enclosing `asyncio.timeout`
    expires with nothing raised, and a `TaskGroup` abort does not unwind. Worse,
    the swallowing path has cancelled the very cancels it was asked to drain.
    """

    def parked(self) -> asyncio.Task:
        """A cancel task that will not finish on its own, registered as one.

        White box deliberately: driving a real hung `apphost.cancel` would make
        these assertions depend on the mock's timing, and what is under test is
        the drain, not the dial.
        """
        task = asyncio.get_running_loop().create_task(
            asyncio.sleep(30), name="parked-cancel"
        )
        _track_cancel(task)
        return task

    async def reap(self, task: asyncio.Task) -> None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        self.assertTrue(await until(lambda: pending_cancels() == 0))

    @bounded()
    async def test_the_flush_deadline_expires_instead_of_being_swallowed(self):
        task = self.parked()
        try:
            # `QueryTimeout`, not the builtin: every deadline in this module
            # reports inside the SDK's hierarchy, so a caller catching
            # `AstralError` around its shutdown sees this one too.
            with self.assertRaises(QueryTimeout):
                await flush_cancels(0.05)
            # The cancel it could not drain is still in flight, still held and
            # still counted: forgetting it would drop the one strong reference
            # keeping its connection alive, and report a dial as finished that
            # nothing finished.
            self.assertFalse(task.cancelled())
            self.assertEqual(pending_cancels(), 1)
        finally:
            await self.reap(task)

    @bounded()
    async def test_an_enclosing_deadline_is_not_voided_by_the_flush(self):
        task = self.parked()
        try:
            with self.assertRaises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await flush_cancels()
        finally:
            await self.reap(task)

    @bounded()
    async def test_cancelling_the_flush_cancels_the_flush_and_not_the_cancel(self):
        task = self.parked()
        try:
            flusher = asyncio.create_task(flush_cancels())
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            flusher.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await flusher
            self.assertTrue(flusher.cancelled())
            # The shield earns its keep: the cancel dial this was asked to wait
            # for is still going, rather than having been cancelled by the wait.
            self.assertFalse(task.done())
        finally:
            await self.reap(task)

    @bounded()
    async def test_a_taskgroup_abort_unwinds_the_flush(self):
        """Design section 3.8's shutdown shape: `aclose()` cancels the owned
        tasks and awaits them. A flush that swallowed the abort would take the
        `apphost.cancel` dials down with it and keep the group waiting."""

        async def boom() -> None:
            await asyncio.sleep(0)
            raise RuntimeError("teardown fault")

        task = self.parked()
        try:
            with self.assertRaises(ExceptionGroup):
                async with asyncio.TaskGroup() as group:
                    group.create_task(flush_cancels())
                    group.create_task(boom())
            self.assertFalse(task.cancelled())
        finally:
            await self.reap(task)

    @bounded()
    async def test_a_cancel_that_ends_badly_is_drained_not_raised(self):
        """Best effort means best effort: a cancel that someone else cancelled,
        and one that ends in an error, are both drained and forgotten without
        disturbing the caller."""
        loop = asyncio.get_running_loop()
        cancelled = loop.create_task(asyncio.sleep(30))
        _track_cancel(cancelled)
        cancelled.cancel()
        await flush_cancels(5.0)
        self.assertEqual(pending_cancels(), 0)

        gate = asyncio.Event()

        async def fails() -> bool:
            await gate.wait()
            raise RuntimeError("the cancel dial failed")

        failing = loop.create_task(fails())
        _track_cancel(failing)
        flusher = asyncio.create_task(flush_cancels(5.0))
        # The flusher must be waiting on it before it fails, so the failure is
        # retrieved through the drain rather than by the garbage collector.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        gate.set()
        await flusher
        self.assertEqual(pending_cancels(), 0)


class CancelRegistryScopeTest(unittest.TestCase):
    """The registry of in-flight cancels belongs to the loop that owns the tasks.

    One process-wide set reports a cancel as drained that no loop ever drained --
    awaiting a task from another loop raises `RuntimeError`, which the
    best-effort handler swallows and the discard then forgets -- and reaches into
    a foreign loop to cancel its tasks from the wrong thread.
    """

    def test_a_cancel_belongs_to_its_own_loop_and_to_no_other(self):
        loop_a = asyncio.new_event_loop()
        holder: list[asyncio.Task] = []

        async def register() -> None:
            task = asyncio.get_running_loop().create_task(asyncio.sleep(30))
            _track_cancel(task)
            holder.append(task)
            self.assertEqual(pending_cancels(), 1)

        loop_a.run_until_complete(register())
        parked = holder[0]
        try:

            async def elsewhere() -> None:
                self.assertEqual(pending_cancels(), 0)
                async with asyncio.timeout(1.0):
                    await flush_cancels()

            asyncio.run(elsewhere())
            # Not drained, not cancelled, and not reported as either.
            self.assertFalse(parked.done())
        finally:
            parked.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                loop_a.run_until_complete(parked)
            loop_a.close()

    def test_pending_cancels_outside_a_loop_refuses_to_guess(self):
        """Zero would be a lie about a loop it never looked at."""
        with self.assertRaises(RuntimeError):
            pending_cancels()


# --- register-service, incoming queries, attach --------------------------


async def _greet_and_hang(conn: MockConn) -> None:
    """A host that greets and then answers nothing at all."""
    conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
    await conn.flush()
    await conn.transport.read(-1)


def _never_greets(closed: asyncio.Event):  # type: ignore[no-untyped-def]
    """A wedged host: it never greets, never closes, and watches for the peer.

    `read(-1)` returns only at EOF, so `closed` firing means the client closed
    the socket rather than abandoning it -- the assertion astrald's 32-worker
    pool makes load-bearing.
    """

    async def host(conn: MockConn) -> None:
        await conn.transport.read(-1)
        closed.set()

    return host


def _service_host(
    *,
    push: int = 1,
    query: str = "objects.search?q=x",
    ack: bool = True,
    silent: bool = False,
):
    """A host that accepts a registration and then pushes inbound queries."""

    async def session(conn: MockConn) -> None:
        conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
        await conn.flush()
        type_name, payload = await conn.recv_frame()
        assert type_name == REGISTER_SERVICE, type_name
        if silent:
            # Reads the registration and never answers it: a node whose worker
            # pool is saturated behaves exactly this way.
            await conn.transport.read(-1)
            return
        if not ack:
            conn.send_frame(ERROR_MSG, error_msg_payload("denied"))
            await conn.flush()
            return
        conn.send_frame(ACK)
        for index in range(push):
            conn.send_frame(
                INCOMING_QUERY,
                incoming_query_payload(Nonce(0x900 + index), CALLER, GUEST, query),
            )
        await conn.flush()
        while True:
            if await conn.recv_frame_or_none() is None:
                return

    return session


def _attach_host(*, ack: bool = True, body: bytes = b"", silent: bool = False):
    """A host that pairs a fresh connection with a pending inbound query."""

    async def session(conn: MockConn) -> None:
        conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
        await conn.flush()
        type_name, payload = await conn.recv_frame()
        assert type_name == ATTACH_QUERY, type_name
        if silent:
            await conn.transport.read(-1)
            return
        if not ack:
            conn.send_frame(ERROR_MSG, error_msg_payload("route_not_found"))
            await conn.flush()
            return
        conn.send_frame(ACK)
        if body:
            conn.send_raw(body)
        await conn.flush()
        while True:
            if await conn.recv_frame_or_none() is None:
                return

    return session


class RegisterServiceTest(SessionCase):
    @bounded()
    async def test_an_anonymous_session_is_refused_without_sending_a_frame(self):
        """astrald checks `isAuthenticated()` first and answers `denied` even for
        the zero identity, so the round trip is a certainty -- and a certain
        refusal is not worth one of the node's 32 workers."""
        async with MockApphost() as mock:
            session = await self.session(mock)
            with self.assertRaises(Denied):
                await session.register_service(FURRY_BOLT)
            self.assertEqual([f[0] for f in mock.connections[0].received], [])
            self.assertFalse(session.transport.closed)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_registration_keeps_the_connection_a_message_channel(self):
        async with MockApphost(token=TOKEN, guest_id=GUEST, session=_service_host()) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST  # authenticated without a token exchange
            self.assertEqual(await session.register_service(), GUEST)
            self.assertFalse(session.spent)
            pushed = await session.next_incoming(timeout=5.0)
            self.assertEqual(pushed.query_id, Nonce(0x900))
            self.assertEqual(pushed.caller, CALLER)
            self.assertEqual(pushed.query, "objects.search?q=x")
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_registered_identity_defaults_to_the_guest(self):
        async with MockApphost(session=_service_host(push=0)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            self.assertEqual(
                parse_register_service(mock.connections[0].received[0][1]), GUEST
            )
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_denied_registration_closes(self):
        async with MockApphost(session=_service_host(ack=False)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            with self.assertRaises(Denied):
                await session.register_service()
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_registration_that_is_never_answered_closes_too(self):
        """The rule is every failure reply, not merely the ones that arrive: a
        registration whose answer never comes is a connection nobody owns, and an
        unowned connection holds one of the node's 32 workers until it restarts.
        A saturated node is exactly what produces this silence."""
        async with MockApphost(session=_service_host(silent=True)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            with self.assertRaises(QueryTimeout):
                await session.register_service(timeout=0.05)
            self.assertTrue(session.closed)
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_idle_registration_deadline_is_a_domain_error(self):
        """Every sibling maps its deadline; a bare `TimeoutError` here is
        indistinguishable from the caller's own enclosing deadline expiring. The
        registration itself is healthy -- parked at a frame boundary -- so it
        stays open."""
        async with MockApphost(session=_service_host(push=0)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            with self.assertRaises(QueryTimeout) as caught:
                await session.next_incoming(timeout=0.05)
            self.assertIn("registration", str(caught.exception))
            self.assertFalse(session.closed)
            self.assertFalse(session.transport.closed)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_reject_incoming_answers_on_the_registration_connection(self):
        async with MockApphost(session=_service_host()) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            pushed = await session.next_incoming(timeout=5.0)
            await session.reject_incoming(pushed, 2)
            await until(lambda: len(mock.connections[0].received) == 2)
            type_name, payload = mock.connections[0].received[1]
            self.assertEqual(type_name, REJECT_INCOMING)
            self.assertEqual(parse_reject_incoming(payload), (Nonce(0x900), 2))
            with self.assertRaises(ValueError):
                await session.reject_incoming(pushed, 0)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_iteration_over_incoming_queries_ends_at_the_close(self):
        async with MockApphost(session=_service_host(push=3)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            seen = []
            async for pushed in session.incoming():
                seen.append(pushed.query_id)
                if len(seen) == 3:
                    await mock.aclose()
            self.assertEqual(seen, [Nonce(0x900), Nonce(0x901), Nonce(0x902)])
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_corrupt_push_fails_loudly_rather_than_resynchronising(self):
        """astrald builds the IPC guest channel **without** locked writes while the
        WebSocket one has them, so concurrent `incoming_query_msg` pushes from
        arbitrary routing goroutines can interleave one frame's three writes
        (astrald bug G-12). A reader that resynchronised past that would turn
        corrupt framing into plausible garbage; this one refuses on the **first**
        read, and closes: astrald's `Guest.Serve` then blocks in `Receive()`
        forever -- no read deadline, no idle timeout in its config -- so a caller
        that logged the fault and read on would burn one of the 32 workers."""

        async def host(conn: MockConn) -> None:
            conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
            await conn.flush()
            await conn.recv_frame()
            conn.send_frame(ACK)
            good = frame(
                INCOMING_QUERY,
                incoming_query_payload(Nonce(0x900), CALLER, GUEST, "objects.search"),
            )
            # Two pushes racing inside one frame: the header of the first, all of
            # the second, then the tail of the first.
            conn.send_raw(good[:20] + good + good[20:])
            await conn.flush()
            await conn.transport.read(-1)

        async with MockApphost(session=host) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            with self.assertRaises(WireError):
                await session.next_incoming(timeout=5.0)
            self.assertTrue(session.closed)
            self.assertTrue(session.transport.closed)
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unexpected_message_on_a_registration_is_a_protocol_error(self):
        async def host(conn: MockConn) -> None:
            conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
            await conn.flush()
            await conn.recv_frame()
            conn.send_frame(ACK)
            conn.send_frame(ACK)
            await conn.flush()
            await conn.transport.read(-1)

        async with MockApphost(session=host) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            with self.assertRaises(ProtocolError):
                await session.next_incoming(timeout=5.0)
            await session.aclose()
            await self.assert_no_leaks(mock)


class MidFrameAbandonmentTest(SessionCase):
    """A read abandoned inside a frame is the framing fault nothing raises.

    `DesyncTest` above covers the loud way the frame boundary is lost: a length
    past `max_alloc` is refused with its payload undrained and the peer's next
    bytes are read as a control message. A deadline expiring and a caller
    cancelling lose it just as completely and raise no `WireError` at all --
    `asyncio.timeout` expires by cancelling, and a cancelled `readexactly`
    leaves the frame's tag and its four length bytes already consumed. What
    follows is the same forgery: the peer's next whole frame is returned as a
    message the node never sent, and on a registration that message carries the
    caller identity the app authorises against.

    So the boundary is asked about rather than assumed. Every abandonment away
    from a boundary closes; an abandonment **at** one costs nothing and the
    connection survives, which is what keeps an idle registration's deadline
    usable.
    """

    def _stalled_host(self, ready: asyncio.Event):
        """Acks the registration, sends half a push, then only reads.

        It parks on the connection and never on the test, deliberately: a mock
        handler waiting for an event a failing assertion never sets hangs the
        whole run, because `MockApphost.__aexit__` exits its `TaskGroup`
        normally and a `TaskGroup` waits for its children. The forged frame is
        written by the test instead, off `mock.connections`.
        """

        async def host(conn: MockConn) -> None:
            conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
            await conn.flush()
            type_name, _payload = await conn.recv_frame()
            self.assertEqual(type_name, REGISTER_SERVICE)
            conn.send_frame(ACK)
            body = incoming_query_payload(Nonce(0x900), CALLER, GUEST, "real.op")
            # The tag, the type name and the four length bytes, and not one byte
            # of the payload. Everything the client needs to commit to a frame
            # and nothing it needs to finish one.
            header = 1 + len(INCOMING_QUERY) + 4
            conn.send_raw(partial_frame(INCOMING_QUERY, body, header))
            await conn.flush()
            ready.set()
            with contextlib.suppress(Exception):
                await conn.transport.read(-1)

        return host

    async def _forge(self, mock: MockApphost) -> None:
        """One whole `incoming_query_msg` of the attacker's choosing.

        Offered as the tail of the frame the client half-read: on a session left
        open this is what `next_incoming()` returns.
        """
        conn = mock.connections[-1]
        with contextlib.suppress(Exception):
            conn.send_frame(
                INCOMING_QUERY,
                incoming_query_payload(Nonce(0xDEAD), CALLER, GUEST, "forged.op"),
            )
            await conn.flush()

    @bounded()
    async def test_a_deadline_inside_a_frame_closes_before_the_peer_can_forge(self):
        """The attack, end to end, over memory and over loopback.

        Measured before the fix, on this tree: `next_incoming(timeout=0.5)`
        reported its deadline with `session.closed=False`, the peer then sent one
        whole `incoming_query_msg`, and the very next `next_incoming()` returned
        `IncomingQueryMsg(query_id=Nonce(...dead), query='forged.op')` -- a query
        the node never routed, with an attacker-chosen caller, handed to the
        app's dispatch.
        """
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                ready = asyncio.Event()
                async with MockApphost(session=self._stalled_host(ready)) as mock:
                    session = await self.session(mock, over=over)
                    session._guest_id = GUEST
                    await session.register_service()
                    await ready.wait()
                    with self.assertRaises(QueryTimeout):
                        await session.next_incoming(timeout=0.05)
                    self.assertTrue(session.closed)
                    self.assertTrue(session.transport.closed)
                    # And the forgery has nowhere to land: the session refuses
                    # rather than returning the attacker's frame.
                    await self._forge(mock)
                    with self.assertRaises(RuntimeError):
                        await session.next_incoming(timeout=1.0)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_cancelled_control_read_inside_a_frame_closes_too(self):
        """A caller's own cancellation loses the boundary exactly as a deadline
        does, and reaches `_recv` as the same `CancelledError`. `receive()` is
        the escape hatch the serving layer drives, so it is covered by the same
        rule and not by a deadline it does not have."""
        ready = asyncio.Event()
        async with MockApphost(session=self._stalled_host(ready)) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            await ready.wait()
            task = asyncio.ensure_future(session.receive())
            # Parked on the payload: the header is out of the reader and gone.
            await until(lambda: session.transport.buffered == 0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(session.closed)
            self.assertTrue(session.transport.closed)
            await self._forge(mock)
            with self.assertRaises(RuntimeError):
                await session.receive()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_deadline_at_a_frame_boundary_leaves_the_registration_usable(self):
        """The other half of the rule, and the one that keeps it honest: an idle
        registration's deadline strands nothing, so the connection survives it
        and the next push still arrives. A fix that closed on every expiry would
        tear down every healthy registration in the SDK."""
        pushed = asyncio.Event()

        async def host(conn: MockConn) -> None:
            conn.send_frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))
            await conn.flush()
            await conn.recv_frame()
            conn.send_frame(ACK)
            await conn.flush()
            await pushed.wait()
            conn.send_frame(
                INCOMING_QUERY,
                incoming_query_payload(Nonce(0x900), CALLER, GUEST, "real.op"),
            )
            await conn.flush()
            await conn.transport.read(-1)

        async with MockApphost(session=host) as mock:
            session = await self.session(mock)
            session._guest_id = GUEST
            await session.register_service()
            with self.assertRaises(QueryTimeout):
                await session.next_incoming(timeout=0.05)
            self.assertFalse(session.closed)
            pushed.set()
            arrived = await session.next_incoming(timeout=5.0)
            self.assertEqual(arrived.query, "real.op")
            await session.aclose()
            await self.assert_no_leaks(mock)


class AttachQueryTest(SessionCase):
    @bounded()
    async def test_attaching_makes_the_connection_the_responder_stream(self):
        pushed = IncomingQueryMsg(
            query_id=Nonce(0x900), caller=CALLER, target=GUEST, query="objects.search?q=x"
        )
        async with MockApphost(session=_attach_host()) as mock:
            session = await self.session(mock)
            stream = await session.attach_query(pushed)
            self.assertFalse(stream.outbound)
            self.assertEqual(stream.local_id, GUEST)
            self.assertEqual(stream.remote_id, CALLER)
            self.assertEqual(stream.query_string, "objects.search?q=x")
            self.assertEqual(stream.nonce, Nonce(0x900))
            await stream.send(EOS())
            await stream.aclose()
            self.assertEqual(
                parse_attach_query(mock.connections[0].received[0][1]), Nonce(0x900)
            )
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_attaching_skips_auth_because_the_query_id_is_the_token(self):
        async with MockApphost(session=_attach_host()) as mock:
            session = await self.session(mock)
            stream = await session.attach_query(Nonce(0x900))
            await stream.aclose()
            self.assertEqual(
                [f[0] for f in mock.connections[0].received], [ATTACH_QUERY]
            )
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unknown_query_id_is_route_not_found_and_closes(self):
        async with MockApphost(session=_attach_host(ack=False)) as mock:
            session = await self.session(mock)
            with self.assertRaises(RouteNotFound):
                await session.attach_query(Nonce(0xDEAD))
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_responder_body_is_not_stranded_either(self):
        async with MockApphost(session=_attach_host(body=frame("ack"))) as mock:
            session = await self.session(mock)
            async with await session.attach_query(Nonce(0x900)) as stream:
                self.assertEqual(await stream.receive(), Ack())
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_an_unanswered_attach_expires_and_closes(self):
        """The deadline is the server's own `QueryAttachTimeout`, the one astrald
        documents. A message that was sent is not `NodeUnavailable`: that class
        promises the query never left, which is what makes it the retry key."""
        async with MockApphost(session=_attach_host(silent=True)) as mock:
            session = await self.session(mock)
            with self.assertRaises(QueryTimeout) as caught:
                await session.attach_query(Nonce(0x900), timeout=0.05)
            self.assertNotIsInstance(caught.exception, NodeUnavailable)
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_the_default_mock_answers_attach_with_route_not_found(self):
        """What the live node answers for a random nonce, verified against it."""
        async with MockApphost() as mock:
            session = await self.session(mock)
            with self.assertRaises(RouteNotFound):
                await session.attach_query(Nonce(0xBEEF))
            await self.assert_no_leaks(mock)


# --- the dial-back path (register-handler) -------------------------------


class DialBackTest(SessionCase):
    """The node dials **us**, and there is no greeting on that connection."""

    def dialed_in(self, first: bytes = b"") -> tuple[MemTransport, MemTransport, Session]:
        node, app = MemTransport.pair("dialback")
        if first:
            node.write(first)
        session = Session.dialed_in(app, endpoint="tcp:127.0.0.1:0")
        return node, app, session

    def handle_query(self, token: int = 0x77, query: str = "objects.search?q=x") -> bytes:
        return frame(
            HANDLE_QUERY,
            handle_query_payload(Nonce(token), Nonce(0x900), CALLER, GUEST, query),
        )

    @bounded()
    async def test_the_first_frame_is_the_query_and_the_ack_precedes_the_body(self):
        """astral-go holds a write lock until the `ack` is out so a handler cannot
        answer first. Not handing over the stream until the `ack` is written is
        the same invariant without the lock."""
        node, app, session = self.dialed_in(self.handle_query())
        message = await session.read_query(token=Nonce(0x77))
        self.assertIsInstance(message, HandleQueryMsg)
        self.assertEqual(message.query, "objects.search?q=x")
        self.assertEqual(message.caller, CALLER)
        stream = await session.accept_query()
        self.assertFalse(stream.outbound)
        self.assertEqual(stream.local_id, GUEST)
        self.assertEqual(stream.remote_id, CALLER)
        await stream.send(P.Uint32(1))
        self.assertEqual(app.writes, [frame(ACK), frame("uint32", b"\x00\x00\x00\x01")])
        await stream.aclose()

    @bounded()
    async def test_a_token_mismatch_is_denied_and_closes(self):
        node, app, session = self.dialed_in(self.handle_query(token=0x11))
        with self.assertRaises(Denied):
            await session.read_query(token=Nonce(0x77))
        self.assertEqual(app.writes, [frame(ERROR_MSG, error_msg_payload("denied"))])
        self.assertTrue(app.closed)

    @bounded()
    async def test_a_wrong_first_frame_is_a_protocol_error_and_closes(self):
        node, app, session = self.dialed_in(frame(PING))
        with self.assertRaises(ProtocolError):
            await session.read_query(token=Nonce(0x77))
        self.assertEqual(app.writes, [frame(ERROR_MSG, error_msg_payload("protocol_error"))])
        self.assertTrue(app.closed)

    @bounded()
    async def test_a_silent_dialer_times_out_and_closes_with_no_reply(self):
        node, app, session = self.dialed_in()
        with self.assertRaises(ProtocolError):
            await session.read_query(timeout=0.05)
        self.assertEqual(app.writes, [])
        self.assertTrue(app.closed)

    @bounded()
    async def test_a_dialer_that_hangs_up_first_is_a_clean_eof(self):
        node, app, session = self.dialed_in()
        node.write_eof()
        with self.assertRaises(EOFError):
            await session.read_query()
        self.assertTrue(app.closed)

    @bounded()
    async def test_rejecting_sends_a_code_and_closes(self):
        node, app, session = self.dialed_in(self.handle_query())
        await session.read_query()
        await session.reject_query(2)
        self.assertEqual(len(app.writes), 1)
        type_name, payload = _one_frame(app.writes[0])
        self.assertEqual(type_name, QUERY_REJECTED)
        self.assertEqual(parse_query_rejected(payload), 2)
        self.assertTrue(app.closed)

    @bounded()
    async def test_rejecting_with_code_zero_is_a_programming_error(self):
        node, app, session = self.dialed_in(self.handle_query())
        await session.read_query()
        with self.assertRaises(ValueError):
            await session.reject_query(0)
        self.assertFalse(app.closed)
        await session.aclose()

    @bounded()
    async def test_skipping_claims_no_route_and_closes(self):
        node, app, session = self.dialed_in(self.handle_query())
        await session.read_query()
        await session.skip_query()
        self.assertEqual(app.writes, [frame(ERROR_MSG, error_msg_payload("route_not_found"))])
        self.assertTrue(app.closed)

    @bounded()
    async def test_accepting_twice_is_refused(self):
        node, app, session = self.dialed_in(self.handle_query())
        await session.read_query()
        stream = await session.accept_query()
        with self.assertRaises(RuntimeError):
            await session.accept_query()
        await stream.aclose()

    @bounded()
    async def test_accepting_without_a_query_is_refused(self):
        node, app, session = self.dialed_in()
        with self.assertRaises(RuntimeError):
            await session.accept_query()
        await session.aclose()

    @bounded()
    async def test_the_token_is_optional_so_a_listener_can_check_it_itself(self):
        node, app, session = self.dialed_in(self.handle_query(token=0x11))
        message = await session.read_query()
        self.assertEqual(message.ipc_token, Nonce(0x11))
        await session.skip_query()


# --- apphost.bind --------------------------------------------------------


class BindTest(SessionCase):
    @bounded()
    async def test_bind_acks_and_carries_one_message_per_token(self):
        route = Accept(objects=[(ACK, b"")], read=True)
        async with MockApphost(routes={"apphost.bind": route}) as mock:
            session = await self.session(mock)
            stream = await session.bind(Nonce(0x99), Nonce(0x77))
            await until(lambda: len(mock.bind_tokens) == 2)
            self.assertEqual(mock.bind_tokens, [Nonce(0x99), Nonce(0x77)])
            # Repeatable: the session stays open and takes more tokens.
            await stream.send(BindMsg(token=Nonce(0x55)))
            await until(lambda: len(mock.bind_tokens) == 3)
            self.assertEqual(mock.bind_tokens[2], Nonce(0x55))
            await stream.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_bind_that_is_not_acked_closes_the_stream(self):
        route = Accept(objects=[("uint32", b"\x00\x00\x00\x01")], hold=True)
        async with MockApphost(routes={"apphost.bind": route}) as mock:
            session = await self.session(mock)
            with self.assertRaises(ProtocolError):
                await session.bind(Nonce(1))
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_rejected_bind_closes_the_connection(self):
        async with MockApphost(routes={"apphost.bind": Reject(1)}) as mock:
            session = await self.session(mock)
            with self.assertRaises(QueryRejected):
                await session.bind(Nonce(1))
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_bind_whose_ack_never_comes_is_a_query_timeout(self):
        """The query was accepted, so this is the op failing to answer, reported
        in the same vocabulary as every other reply that never came. A bare
        `TimeoutError` would be indistinguishable from the caller's own deadline
        expiring."""
        async with MockApphost(routes={"apphost.bind": Accept(hold=True)}) as mock:
            session = await self.session(mock)
            with self.assertRaises(QueryTimeout):
                await session.bind(Nonce(1), ack_timeout=0.05)
            self.assertTrue(session.transport.closed)
            await self.assert_no_leaks(mock)


# --- the message channel itself ------------------------------------------


class MessageChannelTest(SessionCase):
    @bounded()
    async def test_ping_is_decodable_and_the_node_answers_protocol_error(self):
        """`ping_msg` is registered for decode completeness and never sent: the
        node has no handler for it and closes the connection (astrald bug G-17).
        This test is the only place the SDK sends one."""
        async with MockApphost() as mock:
            session = await self.session(mock)
            await session.send(PingMsg())
            reply = await session.receive()
            self.assertIsInstance(reply, ErrorMsg)
            self.assertEqual(reply.code, "protocol_error")
            with self.assertRaises(EOFError):
                await session.receive()
            await session.aclose()
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_second_concurrent_exchange_fails_on_its_own_account(self):
        """There is no multiplexing on the IPC leg, by design (section 3.7). What
        the session owes is that the misuse costs only the caller who committed
        it: without the interlock the second reader failed deep inside the
        framing layer and its own failure handling closed the connection under
        the first, so one mistake destroyed one valid in-flight query."""
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                routes = {"slow.op": Hang(), WHOAMI: WHOAMI_ROUTE}
                async with MockApphost(routes=routes) as mock:
                    session = await self.session(mock, over=over)
                    first = asyncio.create_task(session.route_query("slow.op"))
                    await until(lambda: len(mock.queries) == 1)
                    with self.assertRaises(RuntimeError) as caught:
                        await session.route_query(WHOAMI)
                    self.assertIn("already in flight", str(caught.exception))
                    # The bystander is untouched: still open, still the only
                    # query the node ever saw.
                    self.assertFalse(session.transport.closed)
                    self.assertEqual([q.op for q in mock.queries], ["slow.op"])
                    first.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await first
                    await flush_cancels(5.0)
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_closed_session_refuses_everything(self):
        async with MockApphost() as mock:
            session = await self.session(mock)
            await session.aclose()
            await session.aclose()
            for call in (
                session.route_query(WHOAMI),
                session.receive(),
                session.send(Ack()),
                session.register_service(GUEST),
                session.attach_query(Nonce(1)),
            ):
                with self.assertRaises(RuntimeError):
                    await call
            await self.assert_no_leaks(mock)

    def test_the_control_types_are_registered_under_their_wire_names(self):
        from astral.registry import default_blueprints

        registry = default_blueprints()
        for cls in (
            HostInfoMsg,
            AuthTokenMsg,
            ErrorMsg,
            RouteQueryMsg,
            QueryAcceptedMsg,
            RegisterServiceMsg,
            IncomingQueryMsg,
            AttachQueryMsg,
            RejectIncomingMsg,
            HandleQueryMsg,
            BindMsg,
            PingMsg,
        ):
            self.assertTrue(registry.has(cls.ASTRAL_TYPE), cls.ASTRAL_TYPE)
        # Dead on the wire: astrald never routes to its handler (bug G-16), so the
        # SDK does not ship it at all.
        self.assertFalse(registry.has("mod.apphost.register_handler_msg"))


# --- the leak detector ---------------------------------------------------


class CloseContractTest(SessionCase):
    """`aclose()` returning means closed, at every layer and for every caller.

    `StreamTransport` got this right and the two layers above it borrowed the
    closing/closed naming without the behaviour, so a second concurrent caller
    returned at once reporting `closed=False` with the descriptor still open.
    Measured against a deaf peer with 16 MiB queued: `StreamTransport`'s second
    caller returned after 1.95 s with the socket gone, `Session`'s after 0.00 s
    with it still there. Nothing leaks -- the first closer finishes -- but the
    flag says the opposite of the fact for the whole of the close, which is the
    mirror image of the defect the bounded flush was written to fix.
    """

    @bounded()
    async def test_a_second_aclose_waits_for_the_first(self):
        transport = _SlowClose.solo("slow")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        session = await Session.over(transport, endpoint="mem:slow")
        first = asyncio.ensure_future(session.aclose())
        self.assertTrue(await until(lambda: transport.closing_now.is_set()))
        second = asyncio.ensure_future(session.aclose())
        # Every chance to finish, and it must not have taken one.
        await until(lambda: second.done())
        self.assertFalse(second.done(), "the second aclose() returned early")
        self.assertFalse(session.closed)
        self.assertIn("closing", repr(session))
        transport.release.set()
        await asyncio.gather(first, second)
        self.assertTrue(session.closed)
        self.assertTrue(transport.closed)
        self.assertIn("closed", repr(session))


class DeadPeerTypingTest(SessionCase):
    """A dead peer is an `AstralError` on every control operation, not on some.

    `AstralError` is the documented catch-all, and a reset is the commonest way
    a node dies: astrald restarted or OOM-killed resets its accepted sockets,
    and the TCP endpoint is its own default. A `ConnectionResetError` escaping
    one public method is therefore not a rough edge, it is the catch-all failing
    on the common case.

    The class is every control exchange, and it is swept here rather than
    sampled. The reply half was mapped first and the send half was written
    separately and mapped only its deadline, so `accept_query`, `reject_query`,
    `skip_query`, `reject_incoming` and `send` all let a reset out raw while
    `route_query` and `auth` on the same peer raised `ProtocolError` and
    `NodeUnavailable`. Both halves now run through `Session._mapped`, which is
    the only reason a sweep can be expected to hold: the fault set is written
    once.
    """

    def _greeted(self, kind: type[MemTransport]) -> MemTransport:
        transport = kind.solo("dies")
        transport.feed(frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS)))
        return transport

    async def _session(self, kind: type[MemTransport]) -> Session:
        session = await Session.over(self._greeted(kind), endpoint="mem:dies")
        self.sessions.append(session)
        return session

    @bounded()
    async def test_every_reply_less_send_maps_a_reset(self):
        """The five methods that send and do not wait, plus the escape hatch.

        Each is driven to its send and the peer is dead by the time it drains.
        The assertion is the hierarchy, not a particular class: a caller writing
        `except AstralError` is what the SDK documents, and that is what these
        used to miss.
        """
        inbound = HandleQueryMsg(
            ipc_token=Nonce(0x77),
            id=Nonce(0x900),
            caller=CALLER,
            target=GUEST,
            query="objects.search",
        )
        cases: list[tuple[str, object]] = []

        session = await self._session(_DiesOnSend)
        session._inbound = inbound
        cases.append(("accept_query", session.accept_query(timeout=1.0)))
        session = await self._session(_DiesOnSend)
        cases.append(("reject_query", session.reject_query(2, timeout=1.0)))
        session = await self._session(_DiesOnSend)
        cases.append(("skip_query", session.skip_query(timeout=1.0)))
        session = await self._session(_DiesOnSend)
        cases.append(
            ("reject_incoming", session.reject_incoming(Nonce(0x900), 2, timeout=1.0))
        )
        session = await self._session(_DiesOnSend)
        cases.append(("send", session.send(Ack(), timeout=1.0)))

        for name, coro in cases:
            with self.subTest(method=name):
                with self.assertRaises(ProtocolError) as caught:
                    await coro
                self.assertIsInstance(caught.exception, AstralError)
                self.assertIsInstance(caught.exception.__cause__, ConnectionResetError)

    @bounded()
    async def test_a_validation_failure_survives_a_refusal_that_cannot_be_sent(self):
        """`read_query` names the fault it found, not the courtesy reply it could
        not deliver.

        The refusal's own send is mapped like every other, which is the fix; the
        consequence to guard against is that mapping masking the caller's
        diagnosis. "the refusal was not sent" says nothing about the token that
        did not match, and the docstring promises the token mismatch.
        """
        for over in ("wrong type", "bad token"):
            with self.subTest(case=over):
                transport = _DiesOnSend.solo("dies")
                if over == "wrong type":
                    transport.feed(frame(ACK))
                    expected: type[AstralError] = ProtocolError
                else:
                    transport.feed(
                        frame(
                            HANDLE_QUERY,
                            handle_query_payload(
                                Nonce(0x11), Nonce(0x900), CALLER, GUEST, "q"
                            ),
                        )
                    )
                    expected = Denied
                session = Session.dialed_in(transport, endpoint="mem:dies")
                self.sessions.append(session)
                with self.assertRaises(expected):
                    await session.read_query(token=Nonce(0x77), timeout=1.0)
                self.assertTrue(session.closed)

    @bounded()
    async def test_a_bare_receive_maps_a_reset_and_closes(self):
        """`receive()` is the escape hatch the serving layer drives. A clean
        close is its documented `EOFError` and stays one; a reset is a fault and
        joins the hierarchy, the same split `next_incoming` makes."""
        session = await self._session(_ResetsWhenDrained)
        with self.assertRaises(ProtocolError) as caught:
            await session.receive()
        self.assertIsInstance(caught.exception.__cause__, ConnectionResetError)
        self.assertTrue(session.closed)

    @bounded()
    async def test_a_clean_close_is_still_an_eof_where_it_is_an_ending(self):
        """The other half, so the fix is a mapping and not a blanket. Three
        methods report a peer that hangs up between messages as `EOFError`,
        because there it is an ending rather than a missing answer."""
        transport = self._greeted(MemTransport)
        transport.feed_eof()
        session = await Session.over(transport, endpoint="mem:eof")
        self.sessions.append(session)
        with self.assertRaises(EOFError):
            await session.receive()
        self.assertFalse(session.closed)
        await session.aclose()

    @bounded()
    async def test_a_reset_on_the_bind_stream_is_a_protocol_error(self):
        """`bind()` exchanges an `ack` and its tokens over an accepted stream,
        and they are messages it demands rather than bytes a caller chose to
        write, so they are mapped like every other session exchange. The raw
        `QueryStream` API is where the transport's own language stands.

        Both halves, because they fail in different places: the `ack` never
        arriving is a read, and the tokens never leaving is a write on a stream
        the node accepted and then dropped.
        """

        class _AcceptsThenDies(MemTransport):
            """Serves the route exchange, then reports a reset both ways."""

            def __init__(self, *args, **kw) -> None:  # type: ignore[no-untyped-def]
                super().__init__(*args, **kw)
                self.drains = 0

            async def readexactly(self, n: int) -> bytes:
                if self.buffered < n:
                    raise ConnectionResetError("[Errno 104] Connection reset by peer")
                return await super().readexactly(n)

            async def drain(self) -> None:
                self.drains += 1
                # The first drain is `route_query`'s own send, which must land.
                if self.drains > 1:
                    raise ConnectionResetError("[Errno 104] Connection reset by peer")

        for half, acked in (("the ack never arrives", False), ("the tokens", True)):
            with self.subTest(half=half):
                transport = self._greeted(_AcceptsThenDies)
                transport.feed(frame(QUERY_ACCEPTED))
                if acked:
                    transport.feed(frame(ACK))
                session = await Session.over(transport, endpoint="mem:dies")
                self.sessions.append(session)
                with self.assertRaises(ProtocolError) as caught:
                    await session.bind(Nonce(0x99), timeout=1.0, ack_timeout=1.0)
                self.assertIsInstance(caught.exception, AstralError)
                self.assertIsInstance(
                    caught.exception.__cause__, ConnectionResetError
                )
                self.assertTrue(transport.closed)

    @bounded()
    async def test_a_real_loopback_reset_is_typed_on_every_method(self):
        """The same sweep over a real socket, where the reset is a kernel RST
        rather than a raised exception: `SO_LINGER {1, 0}` is what a dying
        astrald does to its accepted sockets, and the error the SDK produces
        then comes from `StreamTransport.write`'s own `is_closing()` guard."""
        endpoint, close = await self._greeting_then_reset()
        try:
            for name in ("send", "reject_incoming", "reject_query", "skip_query"):
                with self.subTest(method=name):
                    session = await Session.connect(endpoint, timeout=2.0)
                    self.sessions.append(session)
                    await until(lambda: session.transport.writer.is_closing())
                    calls = {
                        "send": lambda: session.send(Ack(), timeout=1.0),
                        "reject_incoming": lambda: session.reject_incoming(
                            Nonce(0x900), 2, timeout=1.0
                        ),
                        "reject_query": lambda: session.reject_query(2, timeout=1.0),
                        "skip_query": lambda: session.skip_query(timeout=1.0),
                    }
                    with self.assertRaises(AstralError):
                        await calls[name]()
                    await session.aclose()
        finally:
            await close()

    async def _greeting_then_reset(self):  # type: ignore[no-untyped-def]
        """A loopback host that greets and then aborts the connection."""
        greeting = frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))

        async def on_connect(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.write(greeting)
            with contextlib.suppress(Exception):
                await writer.drain()
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
            writer.close()

        server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]

        async def close() -> None:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

        return f"tcp:{host}:{port}", close


class LeakTest(SessionCase):
    """Design section 3.9. A leaked connection is a bug of the same severity as a
    wrong byte: it burns one of the node's 32 workers permanently."""

    @bounded()
    async def test_the_leak_assertion_fails_on_a_leaked_descriptor(self):
        """The detector's own test, and it is not ceremony.

        These assertions used to read `transport.closed` and nothing else, so
        they could only ever report what the SDK believed. When `aclose()`
        latched that flag and then blocked on a socket that stayed ESTABLISHED,
        the suite called it a clean run: a detector that trusts the thing under
        test detects nothing. This proves the replacement fails on a real leak
        before it is allowed to certify anything as clean.
        """
        async with MockApphost() as mock:
            endpoint = await self.endpoint(mock, "tcp")
            # Taken with the listener already bound, so what this measures is
            # the one connection below and nothing else.
            baseline = socket_fds()
            leaked = await dial(endpoint)
            with self.assertRaises(AssertionError) as caught:
                await self.assert_no_open_sockets(baseline)
            self.assertIn("left open", str(caught.exception))
            # And it passes again once the descriptor is genuinely gone, so it
            # is a detector and not a permanent alarm.
            await leaked.aclose()
            await self.assert_no_open_sockets(baseline)

    @bounded()
    async def test_the_leak_assertion_is_not_satisfied_by_the_closed_flag(self):
        """A transport whose flag says closed while its descriptor is open must
        not pass. This is the exact shape the critical defect took."""

        class _Liar(StreamTransport):
            async def aclose(self) -> None:
                self._closing = True
                self._closed = True  # the flag, and nothing else

        async with MockApphost() as mock:
            endpoint = await self.endpoint(mock, "tcp")
            baseline = socket_fds()
            host, port = endpoint.removeprefix("tcp:").rsplit(":", 1)
            reader, writer = await asyncio.open_connection(host, int(port))
            liar = _Liar(reader, writer, endpoint)
            await liar.aclose()
            self.assertTrue(liar.closed)
            with self.assertRaises(AssertionError):
                await self.assert_no_open_sockets(baseline)
            writer.transport.abort()
            await self.assert_no_open_sockets(baseline)

    @bounded(20.0)
    async def test_many_sessions_down_every_path_all_close(self):
        routes = {
            WHOAMI: WHOAMI_ROUTE,
            "x.deny": ErrorRoute("denied"),
            "x.reject": Reject(3),
            "x.drop": Drop(),
            "x.garbage": Garbage(),
            "slow.op": Hang(),
            "apphost.cancel": Accept(objects=[(ACK, b"")]),
        }
        rounds = 8
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                self.sessions = []
                async with MockApphost(routes=routes) as mock:
                    for _ in range(rounds):
                        # 1. a query nobody reads, closed by its context manager
                        session = await self.session(mock, over=over)
                        async with await session.route_query(WHOAMI):
                            pass

                        # 2. an exception thrown through an open stream
                        session = await self.session(mock, over=over)
                        with self.assertRaises(RuntimeError):
                            async with await session.route_query(WHOAMI):
                                raise RuntimeError("boom")

                        # 3. every failure reply
                        for query, error in (
                            ("x.deny", Denied),
                            ("x.reject", QueryRejected),
                            ("x.drop", ProtocolError),
                            ("x.garbage", StreamCorrupted),
                        ):
                            session = await self.session(mock, over=over)
                            with self.assertRaises(error):
                                await session.route_query(query)

                        # 4. an exception inside the session's own block
                        with self.assertRaises(RuntimeError):
                            async with await self.session(mock, over=over):
                                raise RuntimeError("boom")

                        # 5. a query cancelled from outside
                        session = await self.session(mock, over=over)
                        seen = len(mock.queries)
                        task = asyncio.create_task(session.route_query("slow.op"))
                        await until(lambda: len(mock.queries) > seen)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task

                        # 6. a session abandoned before any query
                        session = await self.session(mock, over=over)
                        await session.aclose()

                    await flush_cancels(10.0)
                    self.assertGreaterEqual(len(self.sessions), rounds * 9)
                    # Every server-side handler but the hung ones ended on its
                    # own, before the mock was shut down. The hung ones are the
                    # point: a route that never answers holds its worker even
                    # after the client has gone, which is precisely how astrald's
                    # pool of 32 wedges, and precisely why the client side above
                    # must close on every path.
                    self.assertTrue(await until(lambda: mock.live <= rounds))
                    await self.assert_no_leaks(mock)

    @bounded()
    async def test_concurrency_is_many_connections_and_each_one_closes(self):
        """There is no multiplexing on the IPC leg by design: one connection
        carries at most one accepted query, so concurrency means connections. The
        budget that keeps this under astrald's 32 workers belongs to `Client`;
        what the session owes is that every one of them closes."""
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:

            async def one() -> None:
                session = await self.session(mock, over="tcp")
                async with await session.route_query(WHOAMI) as stream:
                    self.assertEqual(await stream.receive(), FURRY_BOLT)

            async with asyncio.TaskGroup() as group:
                for _ in range(16):
                    group.create_task(one())

            self.assertEqual(len(mock.queries), 16)
            self.assertGreater(mock.peak_live, 1)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_failing_sibling_tears_the_group_down_without_leaking(self):
        """`TaskGroup` cancels its siblings on the first exception, which is the
        unwinding path that matters: every session caught mid-query must still
        close its connection on the way out."""
        async with MockApphost(routes={"slow.op": Hang()}) as mock:

            async def hang() -> None:
                # Over a real socket: the unwinding path must release a file
                # descriptor, not merely drop a reference.
                session = await self.session(mock, over="tcp", cancel_timeout=0.2)
                await session.route_query("slow.op")

            async def boom() -> None:
                await until(lambda: len(mock.queries) >= 2)
                raise RuntimeError("boom")

            with self.assertRaises(ExceptionGroup):
                async with asyncio.TaskGroup() as group:
                    group.create_task(hang())
                    group.create_task(hang())
                    group.create_task(boom())

            await flush_cancels(5.0)
            await self.assert_no_leaks(mock)

    @bounded()
    async def test_a_cancelled_connect_leaves_no_socket_behind(self):
        """The window the design names: the deadline expiring, or the caller
        cancelling, between the connect completing and the constructor returning."""
        hung = asyncio.Event()
        async with MockApphost(session=_never_greets(hung)) as mock:
            endpoint = await self.endpoint(mock)
            task = asyncio.create_task(Session.connect(endpoint))
            await until(lambda: bool(mock.connections))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(await until(hung.is_set))

    @bounded()
    async def test_the_transport_is_closed_exactly_once_on_every_path(self):
        """Idempotence is not the whole of the rule: the session must close its
        transport once, not lean on the transport's own guard to absorb repeats
        from three different owners."""
        greeting = frame(HOST_INFO, host_info_payload(FURRY_BOLT, FURRY_BOLT_ALIAS))

        # 1. accepted, then the stream closed by its context manager
        client, host = _Counting.pair("once")
        host.write(greeting + frame("mod.apphost.query_accepted_msg") + frame("ack"))
        session = await Session.over(client, endpoint="mem:once")
        async with await session.route_query(WHOAMI) as stream:
            self.assertEqual(await stream.receive(), Ack())
        await session.aclose()
        self.assertEqual(client.closes, 1)

        # 2. a failure reply, closed by the session
        client, host = _Counting.pair("once")
        host.write(greeting + frame(QUERY_REJECTED, b"\x01"))
        session = await Session.over(client, endpoint="mem:once")
        with self.assertRaises(QueryRejected):
            await session.route_query(WHOAMI)
        await session.aclose()
        await session.aclose()
        self.assertEqual(client.closes, 1)

        # 3. cancelled mid-query, closed while unwinding
        client, host = _Counting.pair("once")
        host.write(greeting)
        session = await Session.over(client, endpoint="mem:once")
        task = asyncio.create_task(session.route_query(WHOAMI))
        await until(lambda: bool(client.writes))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await session.aclose()
        self.assertEqual(client.closes, 1)

        # 4. an exception thrown through the session's own block
        client, host = _Counting.pair("once")
        host.write(greeting)
        with self.assertRaises(RuntimeError):
            async with await Session.over(client, endpoint="mem:once"):
                raise RuntimeError("boom")
        self.assertEqual(client.closes, 1)

    @bounded()
    async def test_the_stream_of_an_abandoned_session_still_closes(self):
        async with MockApphost(routes={WHOAMI: WHOAMI_ROUTE}) as mock:
            session = await self.session(mock)
            stream = await session.route_query(WHOAMI)
            del session
            await stream.aclose()
            await self.assert_no_leaks(mock)


class _ResetsWhenDrained(MemTransport):
    """A transport that delivers what it was fed and then reports a reset.

    The peer dying rather than closing: `asyncio.StreamReader.readexactly`
    raises `ConnectionResetError` there, an `OSError` and not an `EOFError`, and
    a memory pair cannot produce one on its own.
    """

    async def readexactly(self, n: int) -> bytes:
        if self.buffered < n:
            raise ConnectionResetError("[Errno 104] Connection reset by peer")
        return await super().readexactly(n)


class _SlowClose(MemTransport):
    """A transport whose close suspends until the test lets it finish.

    A deaf loopback peer with a stuffed buffer produces the same suspension and
    costs two seconds a case; this produces it in one loop turn and keeps the
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


class _DiesOnSend(MemTransport):
    """A transport whose *send* half reports the reset.

    `_ResetsWhenDrained` kills the read; this kills the write, which is where a
    reply-less send finds out. `StreamTransport.write` raises exactly this from
    its `is_closing()` guard, so the SDK produces this error on its own account
    rather than passing a stdlib one through, and it is still no `AstralError`.
    """

    async def drain(self) -> None:
        raise ConnectionResetError("[Errno 104] Connection reset by peer")


class _Deaf(MemTransport):
    """A peer whose receive window never opens again.

    `drain()` blocks for ever from the `deaf_after`-th call onwards, which is
    precisely what `Transport.drain` is specified to do -- wait until the send
    buffer is below the high-water mark -- against a peer that has stopped
    reading. The counter is there for the sends that happen *after* a successful
    exchange, `apphost.bind`'s tokens being the case in point.
    """

    deaf_after = 0

    def __init__(self, *args, **kw) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kw)
        self.drains = 0

    async def drain(self) -> None:
        self.drains += 1
        if self.drains > self.deaf_after:
            await asyncio.Event().wait()
        await super().drain()


class _Counting(MemTransport):
    """A transport that counts every `aclose()` call, not just the effective one.

    The transport's own idempotence would hide a session that closed twice, or a
    session and a stream both claiming the same transport.
    """

    def __init__(self, *args, **kw) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kw)
        self.closes = 0

    async def aclose(self) -> None:
        self.closes += 1
        await super().aclose()


def _one_frame(data: bytes) -> tuple[str, bytes]:
    """Split one frame out of a write, for asserting on what a session sent."""
    length = data[0]
    name = data[1 : 1 + length].decode()
    size = int.from_bytes(data[1 + length : 5 + length], "big")
    return name, data[5 + length : 5 + length + size]


if __name__ == "__main__":
    unittest.main()
