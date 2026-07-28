"""Tier B: `Client`, the connection budget and the query facade over it.

The three gates of implementation step 8, and each one is here because the
failure it catches is invisible from inside the SDK:

1. **The bound actually bounds.** astrald serves apphost from 32 workers shared
   by every app on the machine, so a client that briefly holds one connection
   more than its bound is a client that helps wedge the node (bug G-13, design
   section 3.9). Concurrency is counted at the **transport**, not at the mock's
   handler and not at a flag the SDK sets: a handler-side count lags the client
   by a loop turn in both directions, and a flag is what the thing under test
   believes. `CountingTransport` counts objects that exist, which is the same
   fact a descriptor is.
2. **Cancellation cancels at the node.** A cancelled query dials
   `apphost.cancel` on a *fresh* connection, which is exactly what astral-go
   fails to do -- it dials with the already-cancelled context, so its cancel is
   never sent (bug G-7).
3. **Nothing leaks, down any path.** Every failure mode, the exception path and
   the cancellation path, and then the kernel is asked whether a descriptor is
   still open. A flag is a promise; a descriptor is a fact.

Plus the two properties the bound is worthless without: it **queues** rather
than deadlocking, and the thing that could deadlock it -- resolving a target
name, which is itself a query -- happens before any permit is taken.

Every async test is `bounded`; no test contacts a node.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import pathlib
import unittest
from unittest import mock as mocklib

import astral
from astral import primitives as P
from astral.channel import Format
from astral.client import (
    Client,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_MAX_PERSISTENT,
    StreamContext,
    connect,
    resolve_endpoint,
    resolve_token,
)
from astral.errors import (
    BadArgument,
    ClientClosed,
    FeatureUnavailable,
    NodeUnavailable,
    ProtocolError,
    QueryRejected,
    QueryTimeout,
    RemoteError,
    RouteNotFound,
    TransportUnsupported,
)
from astral.session import Session, flush_cancels, pending_cancels
from astral.transport import Transport, dial
from astral.types import Identity, Nonce, Zone
from astral.wire import Writer

import api_walk
from mock_apphost import (
    ACK,
    Accept,
    Drop,
    ErrorMsg as ErrorRoute,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    Handshake,
    Hang,
    MockApphost,
    Reject,
    bounded,
    frame,
    leaked_sockets,
    socket_fds,
    until,
)

WHOAMI = "apphost.whoami"
RESOLVE = "dir.resolve?name=furry-bolt"
IDENTITY_FRAME = ("identity", FURRY_BOLT.key)


def u8(value: int) -> tuple[str, bytes]:
    return ("uint8", bytes([value]))


def error(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


# --- counting connections where they exist -------------------------------


class Counter:
    """How many transports are open, how many ever were, and the peak."""

    __slots__ = ("open", "opened", "peak")

    def __init__(self) -> None:
        self.open = 0
        self.opened = 0
        self.peak = 0

    def __repr__(self) -> str:
        return f"Counter(open={self.open}, opened={self.opened}, peak={self.peak})"


class CountingTransport(Transport):
    """A `Transport` decorator that counts the connections a client holds.

    The concurrency bound is a claim about the client, so it is measured on the
    client's side of the wire. The mock's `live` counter cannot serve: it is
    incremented when a handler starts and decremented when the handler returns,
    both a loop turn away from the client's own open and close, so it reads high
    when the client has already closed and low when the client has just dialed.
    Against a 50-way test that is a coin toss, not an assertion.
    """

    __slots__ = ("_inner", "_counter", "_counted")

    def __init__(self, inner: Transport, counter: Counter) -> None:
        self._inner = inner
        self._counter = counter
        self._counted = True
        counter.open += 1
        counter.opened += 1
        counter.peak = max(counter.peak, counter.open)

    @property
    def inner(self) -> Transport:
        return self._inner

    @property
    def endpoint(self) -> str:
        return self._inner.endpoint

    @property
    def closed(self) -> bool:
        return self._inner.closed

    async def readexactly(self, n: int) -> bytes:
        return await self._inner.readexactly(n)

    async def read(self, n: int = -1) -> bytes:
        return await self._inner.read(n)

    def write(self, data: bytes) -> None:
        self._inner.write(data)

    async def drain(self) -> None:
        await self._inner.drain()

    def write_eof(self) -> None:
        self._inner.write_eof()

    async def aclose(self) -> None:
        try:
            await self._inner.aclose()
        finally:
            if self._counted:
                self._counted = False
                self._counter.open -= 1


class NoRawSession(Session):
    """A session whose framing cannot carry unframed bytes.

    What `astral.json.v1` over WebSocket and the HTTP transport will be: a
    line-oriented receiver may hold a partial line, so the raw handover is
    illegal there. RAW-mode ops must fail on it rather than silently get
    something else (design section 3.1).
    """

    @property
    def supports_raw_stream(self) -> bool:
        return False


class ClientCase(unittest.IsolatedAsyncioTestCase):
    """Clients over memory and over loopback, with the hygiene assertions."""

    async def asyncSetUp(self) -> None:
        self.endpoints: dict[MockApphost, str] = {}
        self.listening = asyncio.Lock()
        self.clients: list[Client] = []
        # Taken inside the loop, so the loop's own self-pipe is in the baseline.
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for client in self.clients:
            await client.aclose()
        # Nothing may be left in flight between tests: an abandoned cancel task
        # would leak its connection into the next one.
        await flush_cancels(5.0)
        self.assertEqual(pending_cancels(), 0)

    async def endpoint(self, mock: MockApphost, proto: str = "tcp") -> str:
        async with self.listening:
            if mock not in self.endpoints:
                self.endpoints[mock] = await mock.listen(proto)
            return self.endpoints[mock]

    def connector(
        self,
        mock: MockApphost,
        *,
        over: str = "mem",
        counter: Counter | None = None,
        session_class: type[Session] = Session,
        token: str | None = None,
        **kw: object,
    ):  # type: ignore[no-untyped-def]
        """A way to open one greeted session onto `mock`, counted if asked.

        The session's own connector is this same callable, so an `apphost.cancel`
        opened from a query lands on the same mock and is counted with the rest.
        """

        async def open_session() -> Session:
            if over == "mem":
                raw: Transport = await mock.open()
            else:
                raw = await dial(await self.endpoint(mock, over))
            if counter is not None:
                raw = CountingTransport(raw, counter)
            return await session_class.over(
                raw,
                endpoint=f"{over}:mock",
                token=token,
                connector=open_session,
                **kw,  # type: ignore[arg-type]
            )

        return open_session

    async def client(self, mock: MockApphost, **kw: object) -> Client:
        """A client onto `mock`, closed by the teardown whatever the test does."""
        connector_kw = {
            k: kw.pop(k)
            for k in ("over", "counter", "session_class", "token")
            if k in kw
        }
        client = await connect(
            connector=self.connector(mock, **connector_kw),  # type: ignore[arg-type]
            **kw,  # type: ignore[arg-type]
        )
        self.clients.append(client)
        return client

    async def assert_no_open_sockets(self, since: dict[str, str] | None = None) -> None:
        """No descriptor opened since `since` is still a socket.

        What the SDK believes is checked elsewhere. This is what the kernel says,
        and the two came apart once already in this codebase.
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
            leaked, set(), f"{len(leaked)} socket descriptor(s) left open: {sorted(leaked)}"
        )


# --- resolution ----------------------------------------------------------


class ResolutionTest(unittest.TestCase):
    """Design section 3.3, in one place so the CLI and the library agree."""

    def test_the_argument_wins_over_the_environment(self):
        with mocklib.patch.dict(os.environ, {"ASTRAL_ENDPOINT": "tcp:1.2.3.4:1"}):
            self.assertEqual(resolve_endpoint("unix:/tmp/x"), "unix:/tmp/x")

    def test_the_endpoint_variables_are_tried_in_order(self):
        with mocklib.patch.dict(
            os.environ,
            {"ASTRAL_ENDPOINT": "tcp:first:1", "ASTRALD_ENDPOINT": "tcp:second:2"},
        ):
            self.assertEqual(resolve_endpoint(), "tcp:first:1")
        with mocklib.patch.dict(
            os.environ, {"ASTRALD_ENDPOINT": "tcp:second:2"}, clear=True
        ):
            self.assertEqual(resolve_endpoint(), "tcp:second:2")

    def test_an_empty_variable_is_not_a_setting(self):
        """An exported-but-empty variable is how a shell script says "unset", and
        treating it as an endpoint dials the empty string."""
        with mocklib.patch.dict(os.environ, {"ASTRAL_ENDPOINT": ""}, clear=True):
            self.assertIn(resolve_endpoint(), ("unix:~/.apphost.sock", "tcp:127.0.0.1:8625"))

    def test_the_default_is_the_unix_socket_when_it_exists(self):
        with mocklib.patch.dict(os.environ, {}, clear=True):
            with mocklib.patch("os.path.exists", return_value=True):
                self.assertEqual(resolve_endpoint(), "unix:~/.apphost.sock")
            with mocklib.patch("os.path.exists", return_value=False):
                self.assertEqual(resolve_endpoint(), "tcp:127.0.0.1:8625")

    def test_the_four_token_variables_are_tried_in_order(self):
        with mocklib.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(resolve_token())
            os.environ["ASTRAL_TOKEN"] = "last"
            self.assertEqual(resolve_token(), "last")
            os.environ["ASTRALD_TOKEN"] = "second"
            self.assertEqual(resolve_token(), "second")
            os.environ["ASTRALD_APPHOST_TOKEN"] = "first"
            self.assertEqual(resolve_token(), "first")
            self.assertEqual(resolve_token("explicit"), "explicit")


# --- connecting ----------------------------------------------------------


class ConnectTest(ClientCase):
    @bounded()
    async def test_connect_learns_the_greeting_and_closes_its_connection(self):
        """A client holds no idle connection. One held open for the client's
        lifetime would spend one of the node's 32 workers doing nothing."""
        counter = Counter()
        async with MockApphost() as mock:
            client = await self.client(mock, counter=counter)
            self.assertEqual(client.host_id, FURRY_BOLT)
            self.assertEqual(client.host_alias, FURRY_BOLT_ALIAS)
            self.assertIsNone(client.guest_id)
            self.assertFalse(client.authenticated)
            self.assertEqual(counter.opened, 1)
            self.assertEqual(counter.open, 0)

    @bounded()
    async def test_a_token_is_accepted_at_connect_and_not_at_the_first_query(self):
        async with MockApphost(token="secret") as mock:
            client = await self.client(mock, token="secret")
            self.assertEqual(client.guest_id, FURRY_BOLT)
            self.assertTrue(client.authenticated)

    @bounded()
    async def test_a_node_that_never_greets_fails_rather_than_hanging(self):
        """The saturated-pool shape: the socket is accepted and nothing arrives.

        Reported as `NodeUnavailable`, the one class the retry decorator retries,
        because no query was sent and a retry cannot duplicate an effect.
        """
        async with MockApphost(handshake=Handshake.SILENT) as mock:
            # A short greeting deadline, because the point is that one exists at
            # all: the production 5 s is what makes a wedged node fail rather
            # than hang, and this test would otherwise spend it.
            opener = self.connector(mock, over="tcp", timeout=0.2)
            with self.assertRaises(NodeUnavailable):
                await connect(connector=opener)

    @bounded()
    async def test_max_concurrency_below_one_is_refused(self):
        async with MockApphost() as mock:
            with self.assertRaises(ValueError):
                await self.client(mock, max_concurrency=0)

    def test_the_default_budget_is_well_under_the_nodes_worker_pool(self):
        """8 of 32, documented as a shared-resource budget: three other apps may
        be equally greedy and the node still answers."""
        self.assertEqual(DEFAULT_MAX_CONCURRENCY, 8)


# --- the shape helpers ---------------------------------------------------


class CallTest(ClientCase):
    """`call`, `call_one` and `call_raw` are three declarations of shape."""

    @bounded()
    async def test_call_one_returns_the_single_object_of_an_rr_op(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            self.assertEqual(await client.call_one(WHOAMI), FURRY_BOLT)

    @bounded()
    async def test_call_drains_a_streaming_op_to_its_eos(self):
        route = Accept(objects=[u8(1), u8(2), u8(3)], eos=True)
        async with MockApphost(routes={"x.st": route}) as mock:
            client = await self.client(mock)
            self.assertEqual(
                await client.call("x.st"), [P.Uint8(1), P.Uint8(2), P.Uint8(3)]
            )

    @bounded()
    async def test_call_drains_a_streaming_op_that_ends_at_bare_eof(self):
        """`dir.alias_map` and `apphost.whoami` both do. Nothing waits for `eos`."""
        async with MockApphost(routes={"x.st": Accept(objects=[u8(1)])}) as mock:
            client = await self.client(mock)
            self.assertEqual(await client.call("x.st"), [P.Uint8(1)])

    @bounded()
    async def test_call_raw_reads_an_unframed_body(self):
        """`objects.read` is the only RAW op and its response is not an object
        stream at all, so "every accepted query yields objects" must never be
        assumed."""
        async with MockApphost(routes={"objects.read": Accept(raw=b"\x89PNG\r\n")}) as mock:
            client = await self.client(mock)
            self.assertEqual(await client.call_raw("objects.read"), b"\x89PNG\r\n")

    @bounded()
    async def test_call_raw_is_refused_by_a_session_that_cannot_carry_bytes(self):
        """And is refused **before** the query is routed, so the node does not
        spend a worker producing a body nobody can read."""
        async with MockApphost(routes={"objects.read": Accept(raw=b"x")}) as mock:
            client = await self.client(mock, session_class=NoRawSession)
            with self.assertRaises(TransportUnsupported):
                await client.call_raw("objects.read")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_call_one_refuses_a_stream_that_answered_twice(self):
        route = Accept(objects=[u8(1), u8(2)], eos=True)
        async with MockApphost(routes={"x.st": route}) as mock:
            client = await self.client(mock)
            with self.assertRaises(ProtocolError):
                await client.call_one("x.st")

    @bounded()
    async def test_an_error_object_is_raised_and_an_error_msg_is_not_the_same_thing(self):
        """Two different channels. `error_message` is an object inside the
        query's stream; `error_msg` is an apphost control reply. Merging them
        loses the difference between "nothing served this" and "the op ran and
        failed"."""
        routes = {
            "x.err": Accept(objects=[error("no such repository")]),
            "x.gone": ErrorRoute("route_not_found"),
        }
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock)
            with self.assertRaises(RemoteError):
                await client.call_one("x.err")
            with self.assertRaises(RouteNotFound):
                await client.call_one("x.gone")

    @bounded()
    async def test_a_rejection_carries_its_code(self):
        async with MockApphost(routes={"x.no": Reject(3)}) as mock:
            client = await self.client(mock)
            with self.assertRaises(QueryRejected) as caught:
                await client.call("x.no")
            self.assertEqual(caught.exception.code, 3)

    @bounded()
    async def test_the_stream_context_manager_closes_on_the_exception_path(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            with self.assertRaises(ValueError):
                async with client.stream(WHOAMI) as s:
                    held = s
                    raise ValueError("boom")
            self.assertTrue(held.closed)
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available, DEFAULT_MAX_CONCURRENCY)


# --- targets -------------------------------------------------------------


class TargetTest(ClientCase):
    @bounded()
    async def test_a_hex_target_is_parsed_locally(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            await client.call_one(WHOAMI, target=FURRY_BOLT.hex())
            self.assertEqual(mock.queries[-1].target, FURRY_BOLT)
            self.assertEqual([q.op for q in mock.queries], [WHOAMI])

    @bounded()
    async def test_anyone_is_a_target_and_not_a_directory_name(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            await client.call_one(WHOAMI, target="anyone")
            self.assertEqual(mock.queries[-1].target, Identity.ANYONE)

    @bounded()
    async def test_a_name_is_resolved_through_dir_resolve_before_the_query(self):
        """The apphost `Target` field is an identity; a name never travels."""
        routes = {
            RESOLVE: Accept(objects=[IDENTITY_FRAME]),
            WHOAMI: Accept(objects=[IDENTITY_FRAME]),
        }
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock)
            await client.call_one(WHOAMI, target=FURRY_BOLT_ALIAS)
            self.assertEqual([q.op for q in mock.queries], ["dir.resolve", WHOAMI])
            self.assertEqual(mock.queries[-1].target, FURRY_BOLT)

    @bounded()
    async def test_resolution_happens_before_the_permit_is_taken(self):
        """Otherwise a client at its bound deadlocks on a permit it is holding
        itself: the resolving query would wait for the permit the query that
        needs the resolution already took.
        """
        routes = {
            RESOLVE: Accept(objects=[IDENTITY_FRAME]),
            WHOAMI: Accept(objects=[IDENTITY_FRAME]),
        }
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock, max_concurrency=1)
            self.assertEqual(
                await client.call_one(WHOAMI, target=FURRY_BOLT_ALIAS), FURRY_BOLT
            )

    @bounded()
    async def test_a_resolution_that_answers_with_the_wrong_type_is_a_protocol_error(self):
        routes = {RESOLVE: Accept(objects=[u8(1)])}
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock)
            with self.assertRaises(ProtocolError):
                await client.resolve_identity(FURRY_BOLT_ALIAS)

    @bounded()
    async def test_an_unresolvable_name_surfaces_the_ops_error(self):
        routes = {RESOLVE: Accept(objects=[error("identity not found")])}
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock)
            with self.assertRaises(RemoteError):
                await client.call_one(WHOAMI, target=FURRY_BOLT_ALIAS)
            # And the query itself was never sent, so nothing was routed to a
            # target the caller did not mean.
            self.assertEqual([q.op for q in mock.queries], ["dir.resolve"])


# --- the concurrency bound ----------------------------------------------


class ConcurrencyTest(ClientCase):
    """Design section 3.7 and the first gate of step 8."""

    @bounded(30.0)
    async def test_fifty_concurrent_queries_never_exceed_the_bound(self):
        route = Accept(objects=[IDENTITY_FRAME])
        for over in ("mem", "tcp"):
            with self.subTest(over=over):
                counter = Counter()
                async with MockApphost(routes={WHOAMI: route}) as mock:
                    if over == "tcp":
                        await self.endpoint(mock, over)
                    # Taken with the listener already bound, so what this
                    # measures is the client's connections and nothing else.
                    baseline = socket_fds()
                    client = await self.client(mock, over=over, counter=counter)

                    async def one() -> object:
                        async with client.stream(WHOAMI) as s:
                            return await s.value()

                    got = await asyncio.gather(*[one() for _ in range(50)])
                    self.assertEqual(got, [FURRY_BOLT] * 50)
                    self.assertLessEqual(
                        counter.peak,
                        DEFAULT_MAX_CONCURRENCY,
                        f"held {counter.peak} connections against a bound of "
                        f"{DEFAULT_MAX_CONCURRENCY}",
                    )
                    # And the bound was actually reached, so this is a bound and
                    # not an accidental serialisation.
                    self.assertEqual(counter.peak, DEFAULT_MAX_CONCURRENCY)
                    self.assertEqual(counter.open, 0)
                    self.assertEqual(counter.opened, 51)  # 50 queries + the probe
                    await client.aclose()
                # The mock's own accepted sockets go with it, so the descriptor
                # assertion runs once both sides are down.
                await self.assert_no_open_sockets(baseline)

    @bounded(20.0)
    async def test_a_budget_of_one_serialises(self):
        counter = Counter()
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock, counter=counter, max_concurrency=1)

            async def one() -> object:
                async with client.stream(WHOAMI) as s:
                    return await s.value()

            await asyncio.gather(*[one() for _ in range(10)])
            self.assertEqual(counter.peak, 1)

    @bounded()
    async def test_the_bound_queues_in_order_rather_than_failing(self):
        """"Predictably" is the requirement: `asyncio.Semaphore` is FIFO, so
        three queries behind a bound of one complete in the order they asked."""
        order: list[int] = []
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock, max_concurrency=1)

            async def one(index: int) -> None:
                async with client.stream(WHOAMI) as s:
                    await s.value()
                order.append(index)

            tasks = [asyncio.create_task(one(i)) for i in range(3)]
            await asyncio.gather(*tasks)
        self.assertEqual(order, [0, 1, 2])

    @bounded()
    async def test_a_permit_is_freed_by_closing_the_stream_and_not_before(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock, max_concurrency=2)
            first = await client.query(WHOAMI)
            self.assertEqual(client.available, 1)
            second = await client.query(WHOAMI)
            self.assertEqual(client.available, 0)
            self.assertEqual(client.live_streams, 2)
            await first.aclose()
            self.assertEqual(client.available, 1)
            await second.aclose()
            self.assertEqual(client.available, 2)
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_an_exhausted_budget_expires_naming_the_budget(self):
        """The two ways a query can run out of time need different fixes, so the
        message has to say which happened: a committed budget is the caller's own
        concurrency, and a silent node is the node."""
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock, max_concurrency=1)
            held = await client.query(WHOAMI)
            try:
                with self.assertRaises(QueryTimeout) as caught:
                    await client.call_one(WHOAMI, timeout=0.05)
                self.assertIn("connection permits", str(caught.exception))
            finally:
                await held.aclose()

    @bounded()
    async def test_an_expired_permit_wait_leaves_the_budget_intact(self):
        """A wait that gave up must not have taken the permit it waited for."""
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock, max_concurrency=1)
            held = await client.query(WHOAMI)
            with contextlib.suppress(QueryTimeout):
                await client.call_one(WHOAMI, timeout=0.05)
            await held.aclose()
            self.assertEqual(client.available, 1)
            self.assertEqual(await client.call_one(WHOAMI), FURRY_BOLT)

    @bounded(20.0)
    async def test_a_persistent_stream_spends_nothing_from_the_budget(self):
        """Follow-mode ops, `apphost.bind` and the registrar's channel live for
        as long as the app does. A budget of 8 held forever by 8 of them is a
        client that has deadlocked itself (design section 3.7)."""
        routes = {
            "x.follow": Accept(objects=[u8(1)], eos=True, hold=True),
            WHOAMI: Accept(objects=[IDENTITY_FRAME]),
        }
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock, max_concurrency=1)
            follow = await client.query("x.follow", persistent=True, timeout=None)
            try:
                self.assertEqual(client.available, 1)
                self.assertEqual(client.live_streams, 1)
                # The budget is untouched, so an ordinary query still runs.
                self.assertEqual(await client.call_one(WHOAMI), FURRY_BOLT)
                self.assertEqual([o async for o in follow.snapshot()], [P.Uint8(1)])
            finally:
                await follow.aclose()
            self.assertEqual(client.available, 1)

    @bounded()
    async def test_a_failed_query_gives_its_permit_back(self):
        routes = {"x.deny": ErrorRoute("denied"), "x.drop": Drop(), "x.no": Reject(2)}
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock, max_concurrency=2)
            for op in ("x.deny", "x.drop", "x.no"):
                with self.subTest(op=op):
                    with self.assertRaises(Exception):
                        await client.call(op)
                    self.assertEqual(client.available, 2)
                    self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_rejected_format_takes_no_permit_and_dials_nothing(self):
        """A node silently accepts an unknown `out=` and produces zero bytes
        (astral-docs bug D-24), so the check is client-side and happens first.

        Only an unparsable token is refused now that every parsable one has a
        channel: `nonsense` is not a format at all, and `base64` is one no
        receiver anywhere reads, so neither can name this side's framing."""
        async with MockApphost() as mock:
            client = await self.client(mock)
            before = mock.conn_count
            with self.assertRaises(ValueError):
                await client.call_one(WHOAMI, fmt_out="nonsense")
            with self.assertRaises(ValueError):
                await client.call_one(WHOAMI, fmt_in=Format.BASE64)
            self.assertEqual(mock.conn_count, before)
            self.assertEqual(client.available, DEFAULT_MAX_CONCURRENCY)


# --- cancellation --------------------------------------------------------


class CancellationTest(ClientCase):
    """Design section 3.5 and the second gate of step 8."""

    def routes(self) -> dict[str, object]:
        return {
            "slow.op": Hang(),
            "apphost.cancel": Accept(objects=[(ACK, b"")]),
            WHOAMI: Accept(objects=[IDENTITY_FRAME]),
        }

    @bounded(20.0)
    async def test_a_cancelled_query_cancels_at_the_node_on_a_fresh_connection(self):
        """astral-go dials its cancel with the already-cancelled context, so the
        cancel is never sent (bug G-7). The connection is opened by a task
        nothing cancels, strongly referenced, and drained by `flush_cancels`."""
        counter = Counter()
        async with MockApphost(routes=self.routes()) as mock:  # type: ignore[arg-type]
            client = await self.client(mock, counter=counter)
            task = asyncio.create_task(
                client.query("slow.op", nonce=Nonce(0xAABB), timeout=None)
            )
            await until(lambda: len(mock.queries) == 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await flush_cancels(5.0)
            self.assertEqual(
                [q.op for q in mock.queries], ["slow.op", "apphost.cancel"]
            )
            cancel = mock.queries[1]
            self.assertEqual(cancel.query, "apphost.cancel?id=000000000000aabb")
            # Device zone only: cancelling a query never leaves the machine.
            self.assertEqual(cancel.zone, int(Zone.DEVICE))
            self.assertEqual(counter.open, 0)

    @bounded(20.0)
    async def test_a_cancelled_query_gives_its_permit_back(self):
        async with MockApphost(routes=self.routes()) as mock:  # type: ignore[arg-type]
            client = await self.client(mock, max_concurrency=1)
            task = asyncio.create_task(client.query("slow.op", timeout=None))
            await until(lambda: len(mock.queries) == 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await flush_cancels(5.0)
            self.assertEqual(client.available, 1)
            self.assertEqual(await client.call_one(WHOAMI), FURRY_BOLT)

    @bounded(20.0)
    async def test_stream_cancel_routes_apphost_cancel_and_leaves_the_stream_open(self):
        """Cancelling asks the responder to stop; closing is still the caller's,
        and closing is what frees the node's worker."""
        routes = {
            "x.stream": Accept(objects=[u8(1)], hold=True),
            "apphost.cancel": Accept(objects=[(ACK, b"")]),
        }
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock)
            async with client.stream("x.stream", nonce=Nonce(7)) as s:
                self.assertEqual(await s.first(), P.Uint8(1))
                self.assertTrue(await s.cancel())
                self.assertFalse(s.closed)
            self.assertEqual(
                [q.query for q in mock.queries][1:],
                ["apphost.cancel?id=0000000000000007"],
            )

    @bounded()
    async def test_a_clients_own_deadline_does_not_dial_a_second_connection(self):
        """Our deadline is not a caller's cancellation, however identically
        `asyncio.timeout` delivers it. Answering it with `apphost.cancel` would
        open a second connection into the node whose non-answer produced the
        deadline -- demand amplification on the pool of design section 3.9."""
        counter = Counter()
        async with MockApphost(routes=self.routes()) as mock:  # type: ignore[arg-type]
            client = await self.client(mock, counter=counter)
            with self.assertRaises(QueryTimeout):
                await client.call("slow.op", timeout=0.05)
            await flush_cancels(5.0)
            self.assertEqual([q.op for q in mock.queries], ["slow.op"])
            self.assertEqual(counter.open, 0)


# --- shutdown ------------------------------------------------------------


class _RefusesTwice(Transport):
    """A carrier whose first two `aclose()` calls release nothing.

    A stand-in for any transport whose close did not complete, which is the
    only condition under which the layers above may report `closed=False`.
    Everything else delegates, so the connection is a real one and the leak
    detector still counts it.
    """

    def __init__(self, inner: Transport, refusals: int = 2) -> None:
        self._inner = inner
        self._left = refusals

    @property
    def endpoint(self) -> str:
        return self._inner.endpoint

    @property
    def closed(self) -> bool:
        return self._inner.closed

    async def readexactly(self, n: int) -> bytes:
        return await self._inner.readexactly(n)

    async def read(self, n: int = -1) -> bytes:
        return await self._inner.read(n)

    def write(self, data: bytes) -> None:
        self._inner.write(data)

    async def drain(self) -> None:
        await self._inner.drain()

    def write_eof(self) -> None:
        self._inner.write_eof()

    async def aclose(self) -> None:
        if self._left:
            self._left -= 1
            return
        await self._inner.aclose()


class ShutdownTest(ClientCase):
    """Design section 3.8 and the third gate of step 8."""

    @bounded()
    async def test_aclose_closes_every_live_stream(self):
        routes = {
            "x.hold": Accept(objects=[u8(1)], hold=True),
            "x.follow": Accept(objects=[u8(1)], eos=True, hold=True),
        }
        counter = Counter()
        async with MockApphost(routes=routes) as mock:
            client = await self.client(mock, counter=counter)
            budgeted = await client.query("x.hold", timeout=None)
            persistent = await client.query("x.follow", persistent=True, timeout=None)
            self.assertEqual(counter.open, 2)
            await client.aclose()
            self.assertTrue(budgeted.closed)
            self.assertTrue(persistent.closed)
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(counter.open, 0)

    @bounded()
    async def test_a_stream_that_did_not_close_leaves_the_client_closing(self):
        """The walk ends whatever the streams do, and does not claim otherwise.

        `Stream.aclose()` returning no longer means the connection is gone, so
        the stream keeps its entry in `_live` until it is -- which is the point,
        the node's worker is still held. The teardown therefore takes each
        stream once rather than looping while `_live` is non-empty, which would
        have spun on that entry for ever, and `closed` stays false so a later
        `aclose()` resumes the walk. This is the shape in which a fix for the
        latch would otherwise have become a hang.
        """
        async with MockApphost(routes={"x.hold": Accept(objects=[u8(1)], hold=True)}) as mock:
            client = await self.client(mock)
            stream = await client.query("x.hold", timeout=None)
            stream.conn._transport = _RefusesTwice(  # noqa: SLF001
                stream.conn._transport  # noqa: SLF001
            )
            await client.aclose()
            self.assertFalse(client.closed)
            self.assertEqual(client.live_streams, 1)
            self.assertIn("closing", repr(client))
            await client.aclose()
            self.assertFalse(client.closed)
            # The carrier relents; the resumed walk finishes the job.
            await client.aclose()
            self.assertTrue(client.closed)
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_closed_client_refuses_new_work(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            await client.aclose()
            for call in (
                client.query(WHOAMI),
                client.call(WHOAMI),
                client.call_one(WHOAMI),
                client.call_raw(WHOAMI),
            ):
                with self.assertRaises(ClientClosed):
                    await call

    @bounded()
    async def test_aclose_is_idempotent_and_never_raises(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            await client.aclose()
            await client.aclose()
            self.assertTrue(client.closed)

    @bounded()
    async def test_a_second_concurrent_close_waits_for_the_first(self):
        async with MockApphost(routes={"x.hold": Accept(objects=[u8(1)], hold=True)}) as mock:
            client = await self.client(mock)
            await client.query("x.hold", timeout=None)
            await asyncio.gather(client.aclose(), client.aclose())
            self.assertTrue(client.closed)
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_the_context_manager_closes_on_the_exception_path(self):
        counter = Counter()
        async with MockApphost(routes={"x.hold": Accept(objects=[u8(1)], hold=True)}) as mock:
            client = await self.client(mock, counter=counter)
            with self.assertRaises(ValueError):
                async with client:
                    await client.query("x.hold", timeout=None)
                    raise ValueError("boom")
            self.assertTrue(client.closed)
            self.assertEqual(counter.open, 0)

    @bounded(20.0)
    async def test_a_query_that_lands_during_shutdown_is_closed_not_leaked(self):
        """A stream registered after `aclose()` walked the live set would outlive
        the client with nothing left to close it -- one node worker, permanently."""
        counter = Counter()
        route = Accept(objects=[IDENTITY_FRAME], delay=0.2)
        async with MockApphost(routes={WHOAMI: route}) as mock:
            client = await self.client(mock, counter=counter)
            task = asyncio.create_task(client.query(WHOAMI, timeout=None))
            await until(lambda: counter.opened > 1)
            await client.aclose()
            with self.assertRaises(ClientClosed):
                await task
            self.assertEqual(counter.open, 0)
            self.assertEqual(client.live_streams, 0)


class LeakTest(ClientCase):
    """A leaked connection is a bug of the same severity as a wrong byte."""

    @bounded(30.0)
    async def test_every_path_closes_its_descriptor(self):
        routes = {
            WHOAMI: Accept(objects=[IDENTITY_FRAME]),
            "x.eos": Accept(objects=[u8(1)], eos=True),
            "x.err": Accept(objects=[error("boom")]),
            "x.raw": Accept(raw=b"bytes"),
            "x.deny": ErrorRoute("denied"),
            "x.no": Reject(4),
            "x.drop": Drop(),
            "x.hold": Accept(objects=[u8(1)], hold=True),
            "x.truncated": Accept(objects=[u8(1)], truncate=3),
            "slow.op": Hang(),
            "apphost.cancel": Accept(objects=[(ACK, b"")]),
        }
        counter = Counter()
        async with MockApphost(routes=routes) as mock:
            endpoint = await self.endpoint(mock, "tcp")
            self.assertTrue(endpoint)
            baseline = socket_fds()
            client = await self.client(mock, over="tcp", counter=counter)

            # 1. every ordinary shape
            await client.call_one(WHOAMI)
            await client.call("x.eos")
            await client.call_raw("x.raw")

            # 2. every failure
            for op in ("x.err", "x.deny", "x.no", "x.drop", "x.truncated"):
                with contextlib.suppress(Exception):
                    await client.call(op)

            # 3. a stream nobody reads, closed by its context manager
            async with client.stream("x.hold", timeout=None):
                pass

            # 4. an exception thrown through an open stream
            with self.assertRaises(RuntimeError):
                async with client.stream("x.hold", timeout=None):
                    raise RuntimeError("boom")

            # 5. a stream abandoned to `aclose()`
            await client.query("x.hold", timeout=None)

            # 6. a cancelled query, and the cancel connection it dials
            task = asyncio.create_task(client.query("slow.op", timeout=None))
            await until(lambda: any(q.op == "slow.op" for q in mock.queries))
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await flush_cancels(5.0)

            await client.aclose()
            # The client's own claim first, then the kernel's. The mock parks a
            # `hold=True` handler until shutdown, so its half of those
            # connections closes with it and the descriptor count is only
            # meaningful once both sides are down.
            self.assertEqual(counter.open, 0, f"{counter}")
            await mock.aclose()
            await self.assert_no_open_sockets(baseline)


# --- serving: what `Client.serve` owns ------------------------------------
#
# The serving mechanics are `tests/test_serve.py`'s. What belongs here is the
# facade's own contract: the argument checks that happen before anything is
# dialed, the failure that closes what it opened, and the shutdown order.


class ServeTest(ClientCase):
    @bounded()
    async def test_an_unknown_mode_is_refused_before_anything_else(self):
        """A misspelled mode is wrong whatever else is true, so it outranks every
        other check -- and it is a `ValueError` to the stdlib reflex and an
        `AstralError` to the documented catch-all, both."""
        async with MockApphost() as mock:
            client = await self.client(mock)
            with self.assertRaises(BadArgument):
                await client.serve(FURRY_BOLT, None, mode="rpc")
            with self.assertRaises(ValueError):
                await client.serve(FURRY_BOLT, None, mode="rpc")
            with self.assertRaises(astral.AstralError):
                await client.serve(FURRY_BOLT, None, mode="rpc")
            self.assertEqual(mock.conn_count, 1, "connect's own dial, and no other")

    @bounded()
    async def test_a_handler_mode_identity_that_is_not_the_guests_is_refused(self):
        """`apphost.register_handler` takes no identity: astrald registers under
        the query's caller. The message that could name another one,
        `register_handler_msg`, is unreachable in astrald (bug G-16), so a caller
        asking for one must be told rather than silently registered as itself."""
        async with MockApphost(token="secret") as mock:
            client = await self.client(mock, token="secret")
            other = Identity.parse("02" + "11" * 32)
            with self.assertRaises(BadArgument) as caught:
                await client.serve(other, None)
            self.assertIn("G-16", str(caught.exception))
            self.assertIn(FURRY_BOLT.fingerprint(), str(caught.exception))

    @bounded()
    async def test_an_anonymous_client_cannot_name_the_identity_it_serves(self):
        """Its `guest_id` is `None`, the core router substitutes the node's own
        identity for the nil caller, and a client that cannot name the identity
        it will be registered under cannot be asked to confirm it."""
        async with MockApphost() as mock:
            client = await self.client(mock)
            with self.assertRaises(BadArgument) as caught:
                await client.serve(FURRY_BOLT, None)
            self.assertIn("anonymous", str(caught.exception))

    @bounded()
    async def test_register_service_over_ipc_needs_the_experimental_flag(self):
        """Design risk R-16 is unsettled: astrald closes the guest connection
        unconditionally after `Guest.Serve` returns and guards that close on
        `donated` only on the websocket path, so a donated responder stream over
        IPC can be closed under it."""
        async with MockApphost(token="secret") as mock:
            client = await self.client(mock, token="secret")
            with self.assertRaises(FeatureUnavailable) as caught:
                await client.serve(FURRY_BOLT, None, mode="service")
            self.assertIn("R-16", str(caught.exception))

    @bounded()
    async def test_a_registration_the_node_refuses_closes_what_it_opened(self):
        """A node with no `apphost.bind` answers `route_not_found`. `serve()`
        raises it rather than retrying: retrying belongs to a connection that
        worked and then dropped, and a service the node has never heard of
        answers nothing and reports nothing."""
        baseline = socket_fds()
        async with MockApphost() as mock:
            client = await self.client(mock)
            with self.assertRaises(RouteNotFound):
                await client.serve(ready_timeout=2.0)
            self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT)
        await self.assert_no_open_sockets(baseline)


# --- the review's findings, one regression each ---------------------------


class SlowCloseTransport(CountingTransport):
    """A transport whose close takes `delay`, like a real one flushing.

    `StreamTransport.aclose()` is bounded at `CLOSE_TIMEOUT` per connection
    against a peer that stopped reading, so the aggregate shutdown bound is what
    the walk's shape decides. This makes that shape measurable without stuffing
    32 MiB into a kernel buffer.
    """

    delay = 0.25

    async def aclose(self) -> None:
        await asyncio.sleep(self.delay)
        await super().aclose()


class TeardownTest(ClientCase):
    """`aclose()` returning means closed -- under cancellation and in bounded time."""

    async def _held(self, mock: MockApphost, count: int, **kw: object) -> Client:
        client = await self.client(mock, **kw)
        for _ in range(count):
            await client.query("x.hold")
        return client

    @bounded()
    async def test_a_cancelled_aclose_still_closes_every_stream(self):
        """The critical one. A `CancelledError` inside the walk used to abandon
        the remaining streams *and* latch `closed=True`, so the retry took the
        idempotent fast path and returned having closed nothing. Each abandoned
        connection is one of astrald's 32 workers held until the node restarts."""
        counter = Counter()
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self._held(
                mock,
                6,
                counter=counter,
                over="mem",
                max_concurrency=None,
            )
            self.assertEqual(counter.open, 6)

            task = asyncio.ensure_future(client.aclose())
            await asyncio.sleep(0)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

            await until(lambda: counter.open == 0)
            self.assertEqual(counter.open, 0, f"{counter}")
            # And the client is honest about it either way: it does not claim
            # closed while a stream is live, and a retry finishes the job.
            await client.aclose()
            self.assertTrue(client.closed)
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_retry_after_an_abandoned_aclose_does_not_short_circuit(self):
        """The fast path is only correct once the walk actually finished."""
        counter = Counter()
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self._held(
                mock, 4, counter=counter, over="mem", max_concurrency=None
            )
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(0):
                    await client.aclose()
            await client.aclose()
            self.assertTrue(client.closed)
            self.assertEqual(client.live_streams, 0)
            await until(lambda: counter.open == 0)
            self.assertEqual(counter.open, 0, f"{counter}")

    @bounded()
    async def test_streams_close_concurrently_so_the_bound_does_not_multiply(self):
        """Serially, the per-connection `CLOSE_TIMEOUT` adds: 2 s, 4 s, 8 s for
        one, two and four stuck streams, hence 16 s at the default bound of 8.
        That is also the mechanism that makes a bounded shutdown expire inside
        the walk, which is what the cancellation defect above needs."""

        class Slow(SlowCloseTransport):
            delay = 0.2

        counter = Counter()

        def connector(mock: MockApphost):  # type: ignore[no-untyped-def]
            async def open_session() -> Session:
                raw = Slow(await mock.open(), counter)
                return await Session.over(
                    raw, endpoint="mem:mock", connector=open_session
                )

            return open_session

        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await connect(connector=connector(mock), max_concurrency=None)
            self.clients.append(client)
            for _ in range(6):
                await client.query("x.hold")

            loop = asyncio.get_running_loop()
            started = loop.time()
            await client.aclose()
            spent = loop.time() - started

        self.assertEqual(counter.open, 0)
        # Six closes of 0.2 s each: 1.2 s in sequence, one 0.2 s in parallel.
        self.assertLess(spent, 0.8, f"the walk took {spent:.2f}s -- it serialised")

    @bounded()
    async def test_aclose_fails_the_queue_instead_of_feeding_it(self):
        """A query blocked on the semaphore was never told the client was
        closing, so every close handed its permit to the next waiter and the
        whole queue drained as post-close dials -- measured at 60 connections
        opened *after* `aclose()` returned, against a pool of 32."""
        counter = Counter()
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self.client(mock, counter=counter, max_concurrency=2)
            for _ in range(2):
                await client.query("x.hold")
            self.assertEqual(client.available, 0)

            queued = [
                asyncio.ensure_future(client.query("x.hold")) for _ in range(20)
            ]
            # Every one of them must be **parked on the semaphore** before the
            # teardown starts, which is the state this is about. Merely yielding
            # a turn leaves them at `query()`'s entry check instead, where the
            # refusal is the easy one and proves nothing.
            self.assertTrue(
                await until(lambda: len(client._permits._waiters or ()) == 20)  # noqa: SLF001
            )
            dialed_before = counter.opened

            await client.aclose()
            self.assertTrue(client.closed)

            refused = 0
            for task in queued:
                with contextlib.suppress(ClientClosed):
                    stream = await task
                    await stream.aclose()
                    continue
                refused += 1
            self.assertEqual(refused, 20)
            self.assertEqual(
                counter.opened,
                dialed_before,
                "a closed client dialed the node for a queued query",
            )
            self.assertEqual(counter.open, 0, f"{counter}")

    @bounded()
    async def test_a_waiter_is_failed_by_the_shutdown_and_not_by_the_query_ahead_of_it(
        self,
    ):
        """The re-check refuses a waiter once it *gets* a permit, and what hands
        it one is the query in front finishing. So a waiter with no deadline sat
        behind an in-flight route for as long as that route took, inside an
        `aclose()` that had already been called. Releasing the bound wakes it at
        the start of the teardown instead."""
        async with MockApphost(routes={"x.slow": Accept(delay=0.5)}) as mock:
            client = await self.client(mock, max_concurrency=1)
            in_flight = asyncio.ensure_future(client.query("x.slow", timeout=None))
            self.assertTrue(await until(lambda: client.available == 0))
            queued = asyncio.ensure_future(client.query("x.slow", timeout=None))
            self.assertTrue(
                await until(lambda: len(client._permits._waiters or ()) == 1)  # noqa: SLF001
            )

            closing = asyncio.ensure_future(client.aclose())
            # `until` yields loop turns and never sleeps, so the 5 s route ahead
            # cannot have elapsed: the waiter is done only if the shutdown
            # itself ended its wait.
            self.assertTrue(await until(queued.done))
            with self.assertRaises(ClientClosed):
                await queued

            in_flight.cancel()
            with contextlib.suppress(asyncio.CancelledError, ClientClosed):
                await in_flight
            await closing


class BodyDeadlineTest(ClientCase):
    """A helper that owns the stream owns its deadline."""

    @bounded()
    async def test_the_one_shot_helpers_bound_the_answer_and_not_only_the_route(self):
        """A node that accepts and then says nothing used to pin the caller
        forever with the connection open and one of 32 workers held. `timeout` is
        the only knob these four offer, because they close the stream
        themselves."""
        counter = Counter()
        calls = {
            "call": lambda c: c.call("x.hold", timeout=0.2),
            "call_one": lambda c: c.call_one("x.hold", timeout=0.2),
            "call_raw": lambda c: c.call_raw("x.hold", timeout=0.2),
            "call_with": lambda c: c.call_with("x.hold", P.Uint8(1), timeout=0.2),
        }
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self.client(mock, counter=counter)
            for name, run in calls.items():
                with self.subTest(helper=name):
                    loop = asyncio.get_running_loop()
                    started = loop.time()
                    with self.assertRaises(QueryTimeout):
                        await run(client)
                    self.assertLess(loop.time() - started, 1.0)
            await until(lambda: counter.open == 0)
            self.assertEqual(counter.open, 0, f"{counter}")

    @bounded()
    async def test_one_budget_covers_the_route_and_the_body_together(self):
        """Two deadlines would make `call(timeout=T)` cost 2T and the promise
        would still be false, only by less."""
        async with MockApphost(
            routes={"x.slow": Accept(delay=0.15, hold=True)}
        ) as mock:
            client = await self.client(mock)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout):
                await client.call_one("x.slow", timeout=0.3)
            self.assertLess(loop.time() - started, 0.55)


class TargetResolutionTest(ClientCase):
    """`timeout` is documented as the whole operation, resolution included."""

    @bounded()
    async def test_a_named_target_resolves_inside_the_callers_deadline(self):
        """`dir.resolve` is itself a query. Run outside the budget it took the
        client's 60 s default, so `query(qs, target='alice', timeout=0.2)` could
        block for 300 times the deadline the caller set."""
        async with MockApphost(
            routes={RESOLVE: Accept(hold=True), WHOAMI: Accept(objects=[IDENTITY_FRAME])}
        ) as mock:
            client = await self.client(mock, query_timeout=30.0)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout):
                await client.query(WHOAMI, target=FURRY_BOLT_ALIAS, timeout=0.2)
            self.assertLess(loop.time() - started, 1.0)

    @bounded()
    async def test_resolve_identity_takes_the_whole_query_keyword_set(self):
        """`Dir.resolve(name, zone=...)` worked and
        `Dir.resolve_identity(name, zone=...)` was a `TypeError` naming a method
        the caller never called."""
        async with MockApphost(
            routes={RESOLVE: Accept(objects=[IDENTITY_FRAME])}
        ) as mock:
            client = await self.client(mock)
            got = await client.resolve_identity(
                FURRY_BOLT_ALIAS, zone=Zone.DEVICE, timeout=5.0
            )
        self.assertEqual(got, FURRY_BOLT)
        self.assertEqual(mock.queries[-1].zone, Zone.DEVICE)


class PersistentLaneTest(ClientCase):
    """The escape hatch is a lane, not the absence of one."""

    @bounded()
    async def test_the_persistent_lane_is_bounded_too(self):
        """`persistent=True` used to touch no semaphore at all, so a client
        configured `max_concurrency=1` could hold forty connections -- more than
        the node has workers."""
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self.client(mock, max_concurrency=1, max_persistent=2)
            for _ in range(2):
                await client.query("x.hold", persistent=True)
            self.assertEqual(client.available_persistent, 0)
            with self.assertRaises(QueryTimeout) as caught:
                await client.query("x.hold", persistent=True, timeout=0.1)
            self.assertIn("persistent", str(caught.exception))
            # The query budget is untouched by any of it, which is the point of
            # having two lanes at all.
            self.assertEqual(client.available, 1)

    @bounded()
    async def test_the_worst_case_is_a_number_the_client_can_state(self):
        async with MockApphost() as mock:
            client = await self.client(mock, max_concurrency=3, max_persistent=2)
            self.assertEqual(client.max_concurrency, 3)
            self.assertEqual(client.max_persistent, 2)
            with self.assertRaises(AttributeError):
                client.max_concurrency = 64  # type: ignore[misc]

    @bounded()
    async def test_available_does_not_read_a_private_asyncio_attribute(self):
        """`Semaphore._value` is private to asyncio, and a documented public
        property must not break on a CPython rename. The count is the client's
        own, so removing the attribute changes nothing."""
        async with MockApphost(routes={"x.hold": Accept(hold=True)}) as mock:
            client = await self.client(mock, max_concurrency=2)
            stream = await client.query("x.hold")
            self.assertEqual(client.available, 1)
            renamed = client._permits.__dict__.pop("_value")  # type: ignore[union-attr]
            try:
                self.assertEqual(client.available, 1)
            finally:
                client._permits.__dict__["_value"] = renamed  # type: ignore[union-attr]
            await stream.aclose()
            self.assertEqual(client.available, 2)


class ModuleClientAttachmentTest(ClientCase):
    """Design sections 4.1 and 5.1: every module gets a cached `Client` property.

    Walked from the directory, not enumerated by hand. The hand-written form is
    what let five modules -- `objects`, `tree`, `crypto`, `auth`, `services` --
    land with no property at all while `api/__init__.py` told every reader "a
    test asserts `client.dir is client.dir` for every module": the claim was
    false, the suite stayed green, and each of the five wrote the omission into
    its own docstring as though it were somebody else's step. The sibling rule
    one paragraph above -- every module is imported eagerly -- is walked from
    the directory and it held. So this one is walked too.
    """

    @bounded()
    async def test_every_module_client_attaches_and_is_cached(self):
        """The walk is over the modules that declare **ops**.

        Design section 0.1 keeps the wire types of four excluded modules, so
        `exonet` (an abstract base class and a registry) and `endpoints` (four
        wire types) are in this package with no ops at all. A `client.exonet`
        would name a set of ops that does not exist. `api_walk` decides which
        modules are which by what each declares, so a module that gained ops and
        forgot its property still fails here.
        """
        import astral.api

        modules = api_walk.op_modules()
        self.assertGreaterEqual(len(modules), 7, "the walk found nothing to check")
        async with MockApphost() as mock:
            client = await self.client(mock)
            for name in modules:
                with self.subTest(module=name):
                    attribute = getattr(type(client), name, None)
                    self.assertIsInstance(
                        attribute,
                        functools.cached_property,
                        f"astral.api.{name} has no `client.{name}` property; "
                        "design section 5.1 requires one per module",
                    )
                    got = getattr(client, name)
                    self.assertIs(got, getattr(client, name), "not cached")
                    self.assertIs(got.client, client)
                    self.assertIs(
                        type(got), getattr(astral.api, type(got).__name__)
                    )

    @bounded()
    async def test_a_module_type_decodes_after_nothing_but_import_astral(self):
        """Registration is eager, construction is lazy. A property-local import
        alone would not do: `call_one('dir.alias_map')` never touches
        `client.dir`, and would have raised `BlueprintNotFound`."""
        from astral.registry import default_blueprints

        self.assertTrue(default_blueprints().has("mod.dir.alias_map"))
        self.assertTrue(default_blueprints().has("apphost.access_token"))

        w = Writer()
        w.uint32(1)
        w.string16(FURRY_BOLT_ALIAS)
        w.uint8(1)
        w.raw(FURRY_BOLT.key)
        async with MockApphost(
            routes={"dir.alias_map": Accept(objects=[("mod.dir.alias_map", w.getvalue())])}
        ) as mock:
            client = await self.client(mock)
            got = await client.call_one("dir.alias_map")
        self.assertEqual(type(got).ASTRAL_TYPE, "mod.dir.alias_map")
        self.assertEqual(got[FURRY_BOLT_ALIAS], FURRY_BOLT)


class FramingReconciliationTest(ClientCase):
    """The node's encoder is chosen by the query string and by nothing else."""

    @bounded()
    async def test_an_out_parameter_in_the_query_string_is_not_ignored(self):
        """`call_one('apphost.whoami?out=json')` passed every guard the SDK had
        and handed a JSON-lines body to a binary channel, because `_framing`
        validated a keyword the node never sees.

        No keyword is given here, so the query string is the whole answer: the
        JSON body the mock writes is read by a JSON channel and decodes to the
        same identity a binary body would."""
        body = b'{"Type":"identity","Object":"%s"}\n' % FURRY_BOLT.hex().encode()
        async with MockApphost(
            routes={
                "apphost.whoami?out=json": Accept(raw=body),
                "apphost.whoami?in=text": Accept(objects=[IDENTITY_FRAME]),
            }
        ) as mock:
            client = await self.client(mock)
            # `out=json` says the node writes JSON, so this side reads JSON.
            self.assertEqual(await client.call_one("apphost.whoami?out=json"), FURRY_BOLT)
            # `in=text` says the node reads text, so this side writes text; the
            # answer is still binary, because `out=` was not given.
            self.assertEqual(await client.call_one("apphost.whoami?in=text"), FURRY_BOLT)
        self.assertEqual(
            [q.query for q in mock.queries],
            ["apphost.whoami?out=json", "apphost.whoami?in=text"],
            "the query string travels as the caller wrote it",
        )

    @bounded()
    async def test_a_query_string_that_contradicts_the_keyword_is_refused(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            with self.assertRaises(BadArgument) as caught:
                await client.query("apphost.whoami?out=json", fmt_out=Format.BIN)
            self.assertIn("the node reads the query string", str(caught.exception))

    @bounded()
    async def test_an_ordinary_query_string_travels_unchanged(self):
        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            await client.call_one(WHOAMI)
            await client.call_one(f"{WHOAMI}?out=bin", fmt_out="bin")
        self.assertEqual([q.query for q in mock.queries], [WHOAMI, f"{WHOAMI}?out=bin"])

    @bounded()
    async def test_a_raw_stream_hands_over_the_bytes_of_any_format(self):
        """A RAW stream opens no channel, so which encoder the node uses is the
        caller's business and not this side's: the same `out=json` body is bytes
        here and an `Identity` through the framed path, and the raw view is what
        `tests/test_risk_register.py` reads a live `out=json` answer with. The
        token is still validated, because an unknown `out=` makes the node emit
        zero bytes and say nothing (astral-docs bug D-24)."""
        body = b'{"Type":"identity","Object":"anyone"}\n'
        async with MockApphost(
            routes={"apphost.whoami?out=json": Accept(raw=body)}
        ) as mock:
            client = await self.client(mock)
            self.assertEqual(
                await client.call_raw("apphost.whoami?out=json", timeout=5.0), body
            )
            self.assertEqual(mock.queries[-1].query, "apphost.whoami?out=json")
            # And nonsense is refused either way.
            with self.assertRaises(astral.AstralError):
                await client.call_raw("apphost.whoami?out=nonsense")

    @bounded()
    async def test_an_unknown_format_is_inside_the_hierarchy(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            with self.assertRaises(astral.AstralError):
                await client.query(WHOAMI, fmt_out="nonsense")
            with self.assertRaises(ValueError):
                await client.query(WHOAMI, fmt_out="nonsense")


class RawModeTest(ClientCase):
    """`raw=True` is a declaration that has to constrain something."""

    @bounded()
    async def test_a_raw_stream_refuses_to_frame_the_body_as_protocol(self):
        """`objects.read` returns a stored file, so its leading bytes are the
        responder's or an attacker's to choose. A file that happens to spell
        `string8(type) ++ bytes32(payload)` was handed back as a decoded object
        the responder never sent."""
        forged = b"\x05uint8\x00\x00\x00\x01\x15"
        async with MockApphost(routes={"objects.read": Accept(raw=forged)}) as mock:
            client = await self.client(mock)
            async with client.stream("objects.read", raw=True) as s:
                self.assertTrue(s.raw)
                with self.assertRaises(ProtocolError):
                    await s.first()
                with self.assertRaises(ProtocolError):
                    async for _ in s:
                        pass
                with self.assertRaises(ProtocolError):
                    await s.collect()
                with self.assertRaises(ProtocolError):
                    await s.value()
                with self.assertRaises(ProtocolError):
                    async for _ in s.follow():
                        pass
                with self.assertRaises(ProtocolError):
                    await s.send(P.Uint8(1))
                self.assertEqual(await s.read_bytes(), forged)

    @bounded()
    async def test_call_raw_declares_raw_mode_for_its_caller(self):
        async with MockApphost(routes={"objects.read": Accept(raw=b"file")}) as mock:
            client = await self.client(mock)
            self.assertEqual(await client.call_raw("objects.read"), b"file")


class OpModeHelperTest(ClientCase):
    """Design section 4.7's five shapes, five declarations."""

    @bounded()
    async def test_follow_pairs_the_three_things_a_follow_op_needs(self):
        """`persistent=True`, `timeout=None` and an iterator that crosses the
        separator. Nothing paired them, so each follow op remembered three
        unrelated things by hand or spent the budget forever."""
        async with MockApphost(
            routes={"objects.scan": Accept(objects=[u8(1)], eos=True, live=[u8(2)])}
        ) as mock:
            client = await self.client(mock, max_concurrency=1)
            async with client.follow("objects.scan?follow=true&repo=main") as s:
                self.assertEqual([o async for o in s.snapshot()], [P.Uint8(1)])
                # The budget is untouched: a follow stream on the query lane
                # would have taken this client to zero permits forever.
                self.assertEqual(client.available, 1)
                self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT - 1)
                self.assertEqual([o async for o in s.live()], [P.Uint8(2)])
            self.assertEqual(client.available_persistent, DEFAULT_MAX_PERSISTENT)

    @bounded()
    async def test_call_with_sends_the_body_and_reads_the_answers(self):
        async with MockApphost(routes={"crypto.sign_text": Accept(echo=True)}) as mock:
            client = await self.client(mock)
            answers = await client.call_with(
                "crypto.sign_text", P.Uint8(7), P.Uint8(8), expect=2
            )
        self.assertEqual(answers, [P.Uint8(7), P.Uint8(8)])

    @bounded()
    async def test_call_with_can_terminate_its_input_with_eos(self):
        async with MockApphost(routes={"objects.store": Accept(echo=True)}) as mock:
            client = await self.client(mock)
            answers = await client.call_with("objects.store", P.Uint8(7), eos=True)
        self.assertEqual(answers, [P.Uint8(7)])

    @bounded(30.0)
    async def test_call_with_interleaves_its_batch_and_does_not_deadlock(self):
        """`expect=n` declares that the op answers as it goes, and an op that
        answers as it goes deadlocks against a caller that sends the whole batch
        first: the answers fill this side's receive buffer, the responder's
        `ch.Send` blocks, it stops reading, and this side's `send()` blocks on
        its own drain. Neither moves until the budget expires.

        Driven over a real loopback socket against astrald's own `ch.Switch`
        shape -- read one frame, send one reply, flush -- because the deadlock is
        a kernel-buffer fact and an in-memory transport cannot have it. Batched,
        this wedged after 4,767 of 8,000 exchanges with the responder blocked
        mid-`flush`; interleaved it completes.

        The ops this reaches are every one that declares `expect`: `tree.set`,
        `crypto.public_key`, `crypto.sign_hash`, `crypto.sign_text`,
        `auth.sign_contract` and `apphost.sign_app_contract`.
        """
        inputs = 600
        reply = b"z" * 60000
        served = [0]

        async def switch(conn, query):  # type: ignore[no-untyped-def]
            """astrald's read-one, answer-one, flush loop."""
            conn.send_raw(frame("mod.apphost.query_accepted_msg"))
            await conn.flush()
            while True:
                got = await conn.recv_frame_or_none()
                if got is None or got[0] == "eos":
                    break
                served[0] += 1
                conn.send_frame("bytes16", len(reply).to_bytes(2, "big") + reply)
                await conn.flush()
            await conn.aclose()

        async with MockApphost(routes={"tree.set": switch}) as mock:
            endpoint = await mock.listen("tcp")
            client = await connect(endpoint, query_timeout=10.0)
            self.clients.append(client)
            body = [P.Bytes16(b"y" * 60000)] * inputs
            answers = await client.call_with(
                "tree.set", *body, eos=True, expect=inputs
            )
        self.assertEqual(len(answers), inputs)
        self.assertEqual(served[0], inputs)

    @bounded()
    async def test_stream_context_is_a_nameable_public_type(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            self.assertIsInstance(client.stream(WHOAMI), StreamContext)
            self.assertIsInstance(client.follow(WHOAMI), StreamContext)
            self.assertIn("StreamContext", astral.client.__all__)


class SurfaceTest(ClientCase):
    """What the shipped surface says about itself."""

    @bounded()
    async def test_connect_timeout_is_not_stored_where_it_is_never_read(self):
        """It configures the connector `connect()` builds. A `Client` attribute
        that reads as configuration and does nothing is worse than an absent
        one, and with a caller-supplied `connector` it was silently dropped."""
        async with MockApphost() as mock:
            client = await self.client(mock)
            self.assertFalse(hasattr(client, "connect_timeout"))

    @bounded()
    async def test_query_documents_every_keyword_it_takes(self):
        """`Client.query`'s docstring is the documentation for `**kw` across the
        whole api package, because every module client forwards to it."""
        import inspect

        doc = Client.query.__doc__ or ""
        for name in inspect.signature(Client.query).parameters:
            if name == "self":
                continue
            with self.subTest(keyword=name):
                # `persistent=True` documents `persistent`, so a
                # backtick-prefix match rather than an exact one.
                self.assertIn(f"`{name}", doc)

    @bounded()
    async def test_the_public_annotations_resolve_at_runtime(self):
        """The package ships `py.typed`, so its annotations are an interface.
        `typing.get_type_hints` raised `NameError` on three of them."""
        import typing

        from astral.api.apphost import Apphost
        from astral.api.dir import Dir

        for fn in (
            Client.query,
            Client.stream,
            Client.call,
            Client.follow,
            Client.call_with,
            Apphost.__init__,
            Apphost.bind,
            Apphost.whoami,
            Dir.__init__,
            Dir.alias_map,
        ):
            with self.subTest(fn=fn.__qualname__):
                typing.get_type_hints(fn)


class HierarchyTest(ClientCase):
    """`except astral.AstralError` catches everything the SDK raises."""

    @bounded()
    async def test_every_argument_and_state_fault_is_an_astral_error(self):
        from astral.api.dir import Dir

        async with MockApphost(routes={WHOAMI: Accept(objects=[IDENTITY_FRAME])}) as mock:
            client = await self.client(mock)
            d = Dir(client)
            stream = await client.query(WHOAMI)
            await stream.aclose()

            cases = {
                "empty resolve name": lambda: d.resolve(""),
                "empty filter identity": lambda: d.apply_filters("a", identity=""),
                "no filter names": lambda: d.apply_filters([]),
                "comma in a filter name": lambda: d.apply_filters("a,b"),
                "unknown channel format": lambda: client.call_one(WHOAMI, fmt_out="x"),
                "float duration": lambda: client.apphost.create_token(
                    FURRY_BOLT, duration=1.5
                ),
                "read after close": lambda: stream.first(),
                "serve mode": lambda: client.serve(FURRY_BOLT, None, mode="rpc"),
            }
            for name, run in cases.items():
                with self.subTest(case=name):
                    with self.assertRaises(astral.AstralError):
                        await run()

            # And each keeps the stdlib base a Python caller already reaches for.
            with self.assertRaises(ValueError):
                await d.resolve("")
            with self.assertRaises(TypeError):
                await client.apphost.create_token(FURRY_BOLT, duration=1.5)
            with self.assertRaises(RuntimeError):
                await stream.first()

    @bounded()
    async def test_a_rejection_and_a_remote_error_name_the_query(self):
        """`RemoteError: record not found` says nothing about which of a
        program's ten queries produced it, and the traceback does not either."""
        async with MockApphost(
            routes={
                "x.no": Reject(3),
                "x.err": Accept(objects=[error("record not found")]),
                "x.gone": ErrorRoute("route_not_found"),
            }
        ) as mock:
            client = await self.client(mock)
            with self.assertRaises(QueryRejected) as rejected:
                await client.call("x.no")
            self.assertIn("x.no", str(rejected.exception))
            self.assertEqual(rejected.exception.query, "x.no")
            self.assertEqual(rejected.exception.code, 3)

            with self.assertRaises(RemoteError) as remote:
                await client.call("x.err")
            self.assertIn("x.err", str(remote.exception))
            self.assertEqual(remote.exception.message, "record not found")

            with self.assertRaises(RouteNotFound) as missing:
                await client.call("x.gone")
            self.assertIn("x.gone", str(missing.exception))


if __name__ == "__main__":
    unittest.main()
