"""Tier B: endpoint strings, `MemTransport`, `StreamTransport`, `StreamServer`.

Four jobs:

1. Pin endpoint parsing: the first-colon split, `~/` expansion on dial as well as
   listen, and the rejection of astral-go's in-process protocols.
2. Prove `MemTransport` is a faithful byte stream -- partial reads, EOF, the two
   shapes of a short `readexactly`, half-close -- because every session test that
   never touches a socket rests on it.
3. Prove `StreamTransport` behaves identically over loopback TCP and over a unix
   socket, so a test that passes in memory means something on a wire.
4. Prove the hygiene rules: `aclose()` is idempotent, closes on the exception and
   the cancellation path, and a server closes the connections nobody accepted.

Every async test is `bounded`. No test contacts a node.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import tempfile
import unittest
from unittest import mock as _mock

from astral.conn import QueryStream
from astral.errors import NodeUnavailable, ParseError, TransportError, TransportUnsupported
from astral.object import Query
from astral.transport import (
    DEFAULT_TCP_ENDPOINT,
    DEFAULT_UNIX_ENDPOINT,
    Endpoint,
    IncompleteRead,
    MemTransport,
    default_endpoint,
    dial,
    expand_path,
    listen,
    listen_any,
    parse_endpoint,
)
from astral.transport.socket import StreamServer, StreamTransport, _split_host_port

from mock_apphost import bounded, socket_fds, until


class EndpointStringTest(unittest.TestCase):
    def test_the_split_takes_the_first_colon_only(self):
        parsed = parse_endpoint("tcp:127.0.0.1:8625")
        self.assertEqual(parsed, Endpoint("tcp", "127.0.0.1:8625"))
        self.assertEqual(str(parsed), "tcp:127.0.0.1:8625")

    def test_a_unix_path_keeps_its_colons_and_its_tilde(self):
        parsed = parse_endpoint("unix:~/.apphost.sock")
        self.assertEqual(parsed.proto, "unix")
        self.assertEqual(parsed.addr, "~/.apphost.sock")

    def test_the_web_protocols_parse_and_are_not_stream_protocols(self):
        for endpoint in ("ws://node/.ws", "wss://node/.ws", "http://node", "https://node"):
            with self.subTest(endpoint=endpoint):
                parsed = parse_endpoint(endpoint)
                self.assertFalse(parsed.is_stream)

    def test_a_malformed_endpoint_raises_parse_error(self):
        for text in ("", "tcp", ":8625", "tcp:"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    parse_endpoint(text)

    def test_the_go_in_process_protocols_are_rejected_by_name(self):
        for proto in ("memu", "memb"):
            with self.subTest(proto=proto):
                with self.assertRaises(TransportUnsupported) as caught:
                    parse_endpoint(f"{proto}:apphosty")
                self.assertIn(proto, str(caught.exception))

    def test_an_unknown_protocol_is_unsupported(self):
        with self.assertRaises(TransportUnsupported):
            parse_endpoint("kcp:1.2.3.4:80")

    def test_expand_path_only_touches_a_leading_tilde_slash(self):
        with _mock.patch.dict(os.environ, {"HOME": "/home/nobody"}):
            self.assertEqual(expand_path("~/.apphost.sock"), "/home/nobody/.apphost.sock")
            self.assertEqual(expand_path("/tmp/x.sock"), "/tmp/x.sock")
            self.assertEqual(expand_path("./~/x"), "./~/x")

    def test_host_port_splitting_covers_ipv6_and_rejects_junk(self):
        self.assertEqual(_split_host_port("127.0.0.1:8625"), ("127.0.0.1", 8625))
        self.assertEqual(_split_host_port("[::1]:8625"), ("::1", 8625))
        for bad in ("127.0.0.1", "127.0.0.1:x", "127.0.0.1:99999", "[::1]8625"):
            with self.subTest(bad=bad):
                # `ParseError`, and a `ValueError` besides, so nothing that
                # caught the builtin stops catching it.
                with self.assertRaises(ParseError):
                    _split_host_port(bad)
                with self.assertRaises(ValueError):
                    _split_host_port(bad)

    def test_a_malformed_tcp_address_is_rejected_by_the_parser(self):
        """`tcp:` and `tcp:notaport` are the same typo in the same environment
        variable, so they are the same error. `ValueError` was neither in the
        SDK's hierarchy nor catchable as `AstralError`, and an address the
        parser accepted was one `dial()` then refused with an untyped
        exception."""
        for bad in (
            "tcp:notaport",
            "tcp:127.0.0.1",
            "tcp:127.0.0.1:",
            "tcp:127.0.0.1:99999",
            "tcp:127.0.0.1:-1",
            "tcp:127.0.0.1:8625:extra",
            "tcp:[::1]",
            "tcp:[::1:8625",
            "tcp:[::1]8625",
            "tcp:[::1]:notaport",
            "tcp: ",
            "tcp:\x00",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ParseError):
                    parse_endpoint(bad)

    def test_the_default_endpoint_prefers_the_unix_socket_when_it_exists(self):
        with tempfile.TemporaryDirectory() as home:
            with _mock.patch.dict(os.environ, {"HOME": home}):
                self.assertEqual(default_endpoint(), DEFAULT_TCP_ENDPOINT)
                open(os.path.join(home, ".apphost.sock"), "wb").close()
                self.assertEqual(default_endpoint(), DEFAULT_UNIX_ENDPOINT)


class MemTransportTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_round_trip_carries_bytes_both_ways(self):
        left, right = MemTransport.pair()
        left.write(b"ping")
        await left.drain()
        self.assertEqual(await right.readexactly(4), b"ping")
        right.write(b"pong")
        await right.drain()
        self.assertEqual(await left.readexactly(4), b"pong")

    @bounded()
    async def test_read_returns_what_arrived_and_never_waits_for_the_rest(self):
        left, right = MemTransport.pair()
        left.write(b"abc")
        self.assertEqual(await right.read(10), b"abc")

    @bounded()
    async def test_max_chunk_forces_one_byte_per_read(self):
        left, right = MemTransport.pair(peer_max_chunk=1)
        left.write(b"abcd")
        self.assertEqual(await right.read(4), b"a")
        self.assertEqual(await right.read(4), b"b")
        # readexactly loops over the chunking, so the bound is invisible to it.
        self.assertEqual(await right.readexactly(2), b"cd")

    @bounded()
    async def test_read_blocks_until_a_byte_arrives(self):
        left, right = MemTransport.pair()
        pending = asyncio.ensure_future(right.read(4))
        await asyncio.sleep(0)
        self.assertFalse(pending.done())
        left.write(b"go")
        self.assertEqual(await pending, b"go")

    @bounded()
    async def test_read_to_eof_accumulates_every_chunk(self):
        left, right = MemTransport.pair()
        left.write(b"one")
        left.write(b"two")
        left.write_eof()
        self.assertEqual(await right.read(-1), b"onetwo")
        self.assertEqual(await right.read(-1), b"")

    @bounded()
    async def test_eof_is_empty_bytes_and_readexactly_raises_eof_error(self):
        left, right = MemTransport.pair()
        left.write_eof()
        self.assertEqual(await right.read(8), b"")
        with self.assertRaises(EOFError) as caught:
            await right.readexactly(1)
        self.assertNotIsInstance(caught.exception, IncompleteRead)

    @bounded()
    async def test_a_short_readexactly_reports_the_partial_bytes(self):
        left, right = MemTransport.pair()
        left.write(b"ab")
        left.write_eof()
        with self.assertRaises(IncompleteRead) as caught:
            await right.readexactly(5)
        self.assertEqual(caught.exception.partial, b"ab")
        self.assertIsInstance(caught.exception, EOFError)

    @bounded()
    async def test_write_eof_half_closes_and_leaves_the_read_direction_open(self):
        left, right = MemTransport.pair()
        left.write(b"question")
        left.write_eof()
        self.assertEqual(await right.readexactly(8), b"question")
        self.assertEqual(await right.read(1), b"")
        right.write(b"answer")
        self.assertEqual(await left.readexactly(6), b"answer")
        with self.assertRaises(ConnectionResetError):
            left.write(b"more")

    @bounded()
    async def test_close_delivers_written_bytes_and_then_eof(self):
        left, right = MemTransport.pair()
        left.write(b"half a frame")
        await left.aclose()
        self.assertEqual(await right.readexactly(12), b"half a frame")
        self.assertEqual(await right.read(1), b"")

    @bounded()
    async def test_close_is_idempotent_and_discards_unread_inbound_bytes(self):
        left, right = MemTransport.pair()
        right.write(b"never read")
        await left.aclose()
        await left.aclose()
        self.assertTrue(left.closed)
        self.assertEqual(await left.read(4), b"")
        with self.assertRaises(ConnectionResetError):
            left.write(b"x")

    @bounded()
    async def test_every_write_call_is_recorded_for_the_frame_invariant(self):
        left, _right = MemTransport.pair()
        left.write(b"one")
        left.write(b"two")
        self.assertEqual(left.writes, [b"one", b"two"])
        self.assertEqual(left.sent, b"onetwo")

    @bounded()
    async def test_solo_feeds_its_own_read_side(self):
        t = MemTransport.solo()
        t.feed(b"scripted")
        t.feed_eof()
        self.assertEqual(await t.read(-1), b"scripted")
        t.write(b"out")
        self.assertEqual(t.sent, b"out")

    @bounded()
    async def test_the_context_manager_closes_on_the_exception_path(self):
        left, _right = MemTransport.pair()
        with self.assertRaises(RuntimeError):
            async with left:
                raise RuntimeError("boom")
        self.assertTrue(left.closed)

    @bounded()
    async def test_a_second_waiting_reader_is_refused_as_a_socket_refuses_it(self):
        """`asyncio.StreamReader` raises when a second coroutine waits on the
        same stream. A memory transport that instead handed each reader a
        different chunk would let a concurrency defect pass in the suite that
        runs mostly over memory and fail on the first real socket."""
        left, right = MemTransport.pair()

        async def feed() -> None:
            await asyncio.sleep(0.01)
            right.write(b"AB")

        first = asyncio.create_task(left.readexactly(1))
        await asyncio.sleep(0)
        second = asyncio.create_task(left.readexactly(1))
        got = await asyncio.gather(first, second, feed(), return_exceptions=True)
        self.assertEqual(got[0], b"A")
        self.assertIsInstance(got[1], RuntimeError)
        self.assertIn("already waiting", str(got[1]))
        # The refusal leaves the stream usable: nothing was consumed for the
        # reader that was turned away.
        self.assertEqual(await left.readexactly(1), b"B")

    @bounded()
    async def test_a_reader_that_never_waits_is_not_refused(self):
        """The rule is one *waiting* reader, exactly as the stream reader states
        it: bytes already buffered are handed out without anyone parking."""
        left, right = MemTransport.pair()
        right.write(b"AB")
        got = await asyncio.gather(left.readexactly(1), left.readexactly(1))
        self.assertEqual(got, [b"A", b"B"])

    @bounded()
    async def test_writing_to_a_departed_peer_fails_the_way_loopback_fails(self):
        """Measured on loopback: the first write after the peer closed succeeds --
        the bytes reach the kernel, which only then gets an RST back -- and every
        write after that raises. Dropping all of them silently would hide from
        the memory suite exactly the fault a socket reports."""
        left, right = MemTransport.pair()
        await right.aclose()
        left.write(b"first")
        with self.assertRaises(ConnectionResetError):
            left.write(b"second")
        await left.aclose()


class _Echo:
    """A loopback server that echoes, for the socket-transport assertions."""

    def __init__(self) -> None:
        self.conns: list[StreamTransport] = []

    async def serve(self, server: StreamServer) -> None:
        while True:
            try:
                conn = await server.accept()
            except TransportError:
                return
            self.conns.append(conn)
            try:
                while True:
                    data = await conn.read(4096)
                    if not data:
                        break
                    conn.write(data)
                    await conn.drain()
            except (OSError, EOFError):
                pass
            finally:
                await conn.aclose()


class StreamTransportTest(unittest.IsolatedAsyncioTestCase):
    """The same assertions over loopback TCP and over a unix socket."""

    async def _echo_endpoint(self, proto: str) -> str:
        server = await listen_any(proto)
        echo = _Echo()
        task = asyncio.ensure_future(echo.serve(server))  # type: ignore[arg-type]
        self.addAsyncCleanup(self._shutdown, server, task)
        return server.endpoint

    async def _shutdown(self, server, task) -> None:  # type: ignore[no-untyped-def]
        await server.aclose()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @bounded()
    async def test_a_tcp_round_trip_and_the_endpoint_string(self):
        endpoint = await self._echo_endpoint("tcp")
        self.assertTrue(endpoint.startswith("tcp:127.0.0.1:"))
        async with await dial(endpoint) as t:
            self.assertEqual(t.endpoint, endpoint)
            t.write(b"hello")
            await t.drain()
            self.assertEqual(await t.readexactly(5), b"hello")

    @bounded()
    async def test_a_unix_round_trip_over_an_ephemeral_socket(self):
        endpoint = await self._echo_endpoint("unix")
        self.assertTrue(endpoint.startswith("unix:"))
        self.assertIn("apphostclient.", endpoint)
        async with await dial(endpoint) as t:
            t.write(b"hello")
            await t.drain()
            self.assertEqual(await t.readexactly(5), b"hello")

    @bounded()
    async def test_eof_and_a_short_readexactly_match_the_memory_transport(self):
        endpoint = await self._echo_endpoint("tcp")
        async with await dial(endpoint) as t:
            t.write(b"ab")
            await t.drain()
            self.assertEqual(await t.readexactly(2), b"ab")
            t.write_eof()
            with self.assertRaises(EOFError) as caught:
                await t.readexactly(1)
            self.assertNotIsInstance(caught.exception, IncompleteRead)

    @bounded()
    async def test_half_close_keeps_the_read_direction_open(self):
        endpoint = await self._echo_endpoint("tcp")
        async with await dial(endpoint) as t:
            t.write(b"question")
            t.write_eof()
            self.assertEqual(await t.readexactly(8), b"question")
            self.assertEqual(await t.read(1), b"")
            with self.assertRaises(ConnectionResetError):
                t.write(b"more")

    @bounded()
    async def test_close_is_idempotent(self):
        endpoint = await self._echo_endpoint("tcp")
        t = await dial(endpoint)
        await t.aclose()
        await t.aclose()
        self.assertTrue(t.closed)

    @bounded()
    async def test_a_tilde_path_is_expanded_on_dial_as_well_as_on_listen(self):
        """astral-go expands `~/` on listen only, so its client cannot dial the
        documented default `unix:~/.apphost.sock` (bug G-15)."""
        with tempfile.TemporaryDirectory() as home:
            with _mock.patch.dict(os.environ, {"HOME": home}):
                server = await listen("unix:~/probe.sock")
                echo = _Echo()
                task = asyncio.ensure_future(echo.serve(server))  # type: ignore[arg-type]
                try:
                    self.assertTrue(os.path.exists(os.path.join(home, "probe.sock")))
                    async with await dial("unix:~/probe.sock") as t:
                        t.write(b"tilde")
                        await t.drain()
                        self.assertEqual(await t.readexactly(5), b"tilde")
                finally:
                    await server.aclose()
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.assertFalse(os.path.exists(os.path.join(home, "probe.sock")))

    @bounded()
    async def test_the_transport_closes_on_the_cancellation_path(self):
        """A leaked connection burns one of astrald's 32 apphost workers
        permanently, so cancellation has to close as reliably as an exception."""
        endpoint = await self._echo_endpoint("tcp")
        opened: list[StreamTransport] = []

        async def blocked() -> None:
            async with await dial(endpoint) as t:
                opened.append(t)  # type: ignore[arg-type]
                await t.readexactly(1)

        task = asyncio.ensure_future(blocked())
        self.assertTrue(await until(lambda: bool(opened)))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(opened[0].closed)

    @bounded()
    async def test_a_refused_dial_is_node_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(NodeUnavailable):
                await dial(f"unix:{os.path.join(tmp, 'absent.sock')}")

    @bounded()
    async def test_a_malformed_endpoint_is_a_parse_error_and_never_retryable(self):
        """`dial()` documents that every fault is `NodeUnavailable`; a malformed
        address must not be one of them, because `NodeUnavailable` is the class
        the retry decorator retries and no retry repairs a typo."""
        for bad in ("tcp:notaport", "tcp:127.0.0.1", "tcp:127.0.0.1:99999"):
            with self.subTest(bad=bad):
                with self.assertRaises(ParseError) as caught:
                    await dial(bad)
                self.assertNotIsInstance(caught.exception, NodeUnavailable)

    @bounded()
    async def test_binding_does_not_unlink_a_live_socket_path(self):
        """`unlink_stale` defaults off so a path typo cannot delete a running
        node's socket. Since CPython 3.13 `start_unix_server` performs exactly
        that removal itself whenever it is handed a path -- unconditionally, and
        regardless of `cleanup_socket` -- so the SDK binds the socket itself.
        Without that, `listen("unix:~/.apphost.sock")` takes the node's path away
        from it: the node keeps serving a socket nothing can reach, and every
        later client reaches the app instead."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "node.sock")
            live = await listen(f"unix:{path}")
            inode = os.stat(path).st_ino
            try:
                with self.assertRaises(TransportError):
                    await listen(f"unix:{path}")
                self.assertEqual(os.stat(path).st_ino, inode)
                # Still reachable, which is the point of not unlinking it.
                client = await dial(f"unix:{path}")
                accepted = await live.accept()
                client.write(b"alive")
                await client.drain()
                self.assertEqual(await accepted.readexactly(5), b"alive")
                await client.aclose()
                await accepted.aclose()
            finally:
                await live.aclose()

    @bounded()
    async def test_unlink_stale_clears_a_leftover_socket_file_when_asked(self):
        """astral-go's `ipc.Listen` behaviour, on request rather than by default."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stale.sock")
            # A socket file with nothing behind it: bound, listening, then the
            # descriptor dropped without unlinking. What a crashed node leaves.
            leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            leftover.bind(path)
            leftover.listen(1)
            leftover.close()
            self.assertTrue(os.path.exists(path))
            with self.assertRaises(TransportError):
                await listen(f"unix:{path}")
            server = await listen(f"unix:{path}", unlink_stale=True)
            await server.aclose()

    @bounded()
    async def test_a_bind_that_fails_is_a_transport_error(self):
        """A raw `OSError` out of `listen()` is outside the hierarchy the caller
        catches, and the address it names came from the caller."""
        with self.assertRaises(ParseError):
            await listen("tcp:notaport")
        with self.assertRaises(TransportError) as caught:
            await listen("unix:" + "b" * 200)
        self.assertNotIsInstance(caught.exception, ParseError)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "taken.sock")
            server = await listen(f"unix:{path}")
            try:
                with self.assertRaises(TransportError):
                    await listen(f"unix:{path}")
            finally:
                await server.aclose()

    @bounded()
    async def test_dialing_a_web_endpoint_names_the_module_that_lands_it(self):
        with self.assertRaises(TransportUnsupported):
            await dial("ws://127.0.0.1:8624/.ws")


class _DeafPeer:
    """A loopback server that accepts, reads nothing and never closes.

    The write side of astrald's wedged worker (bug G-13): the connection is
    ESTABLISHED, the guest's frames pile up, and nothing on the far end will ever
    take them. `SO_RCVBUF` is shrunk to the kernel minimum so the client's own
    write buffer fills after a few megabytes instead of a few hundred.
    """

    def __init__(self) -> None:
        self.stop = asyncio.Event()
        self.writers: list[asyncio.StreamWriter] = []
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> str:
        self._server = await asyncio.start_server(self._on, "127.0.0.1", 0)
        sock = self._server.sockets[0]
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        host, port = sock.getsockname()[:2]
        return f"tcp:{host}:{port}"

    async def _on(self, reader, writer) -> None:  # type: ignore[no-untyped-def]
        self.writers.append(writer)
        await self.stop.wait()

    async def aclose(self) -> None:
        self.stop.set()
        for writer in self.writers:
            writer.transport.abort()
        if self._server is not None:
            self._server.close()
        # One turn for the accept callbacks to return and asyncio to release the
        # accepted descriptors, so this helper leaves nothing behind either.
        await until(lambda: False, turns=3)


def _socket_inode(transport: StreamTransport) -> str:
    """The `socket:[inode]` this transport's descriptor points at, from /proc."""
    sock = transport.writer.get_extra_info("socket")
    return os.readlink(f"/proc/self/fd/{sock.fileno()}")


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "descriptor counting is Linux")
class DeafPeerCloseTest(unittest.IsolatedAsyncioTestCase):
    """`aclose()` against a peer that stopped reading.

    The hazard this pins is asyncio's, not the SDK's:
    `_SelectorTransport.close()` schedules the descriptor's release only when
    the write buffer is **empty**, and with bytes still queued it keeps the
    socket and keeps trying to write. So `close()` then `wait_closed()` -- the
    obvious spelling, and what this transport used to do -- never returns
    against a deaf peer, and the connection stays ESTABLISHED: one of astrald's
    32 apphost workers, held by a call whose entire purpose is to release it.
    Measured before the fix: still blocked past 8 s with 14,143,381 bytes
    buffered and `closed` already reporting True.

    Every assertion here counts descriptors rather than reading flags, because
    the flag is what lied.
    """

    async def stalled(self) -> tuple[StreamTransport, _DeafPeer, str]:
        """A connection with megabytes queued behind a peer that will not read."""
        peer = _DeafPeer()
        endpoint = await peer.start()
        self.addAsyncCleanup(peer.aclose)
        transport = await dial(endpoint)
        assert isinstance(transport, StreamTransport)
        inode = _socket_inode(transport)
        for _ in range(16):
            transport.write(b"z" * (1 << 20))
        # The precondition. Without a non-empty buffer this test would pass
        # against the very implementation it exists to refuse.
        self.assertGreater(transport.writer.transport.get_write_buffer_size(), 0)
        return transport, peer, inode

    def open_sockets(self) -> set[str]:
        found = socket_fds()
        assert found is not None
        return set(found.values())

    @bounded()
    async def test_aclose_returns_and_releases_the_descriptor(self):
        transport, _peer, inode = await self.stalled()
        transport.close_timeout = 0.2
        started = asyncio.get_running_loop().time()
        await transport.aclose()
        waited = asyncio.get_running_loop().time() - started
        # Bounded by the flush budget, not by the peer's willingness to read.
        self.assertLess(waited, 2.0)
        self.assertTrue(transport.closed)
        self.assertNotIn(inode, self.open_sockets())
        # Idempotent, and the second call still finds it closed.
        await transport.aclose()
        self.assertTrue(transport.closed)

    @bounded()
    async def test_closed_reports_the_descriptor_and_not_the_intention(self):
        """The flag must not run ahead of the socket.

        `closed` reporting True while the descriptor is live is what made the
        suite's own leak assertions blind: they read the flag, the flag said
        closed, and the connection was open the whole time.
        """
        transport, _peer, inode = await self.stalled()
        transport.close_timeout = 30.0
        closing = asyncio.ensure_future(transport.aclose())
        self.assertTrue(await until(lambda: transport.closing))
        self.assertFalse(transport.closed)
        self.assertIn(inode, self.open_sockets())
        # Cancelling the flush must still release the descriptor: a close
        # abandoned half way leaves exactly the leak it was called to prevent.
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertTrue(transport.closed)
        self.assertNotIn(inode, self.open_sockets())

    @bounded()
    async def test_a_concurrent_close_waits_for_the_one_in_flight(self):
        transport, _peer, inode = await self.stalled()
        transport.close_timeout = 0.2
        await asyncio.gather(transport.aclose(), transport.aclose())
        self.assertTrue(transport.closed)
        self.assertNotIn(inode, self.open_sockets())

    @bounded()
    async def test_a_query_stream_over_a_deaf_peer_closes_too(self):
        """The shape the finding was reported in: push a body to a node that
        stalls, then close. `QueryStream.aclose()` is the SDK's own
        `async with` exit, so a hang here hangs every caller."""
        transport, _peer, inode = await self.stalled()
        transport.close_timeout = 0.2
        stream = QueryStream(transport, Query(query_string="objects.push"))
        async with asyncio.timeout(3.0):
            await stream.aclose()
        self.assertTrue(stream.closed)
        self.assertNotIn(inode, self.open_sockets())


class StreamServerTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_accept_hands_out_connections_in_arrival_order(self):
        server = await listen_any("tcp")
        async with server:
            first = await dial(server.endpoint)
            first.write(b"1")
            await first.drain()
            second = await dial(server.endpoint)
            second.write(b"2")
            await second.drain()
            a = await server.accept()
            b = await server.accept()
            try:
                self.assertEqual(await a.readexactly(1), b"1")
                self.assertEqual(await b.readexactly(1), b"2")
            finally:
                for t in (first, second, a, b):
                    await t.aclose()

    @bounded()
    async def test_closing_the_server_closes_the_connections_nobody_accepted(self):
        """A connection accepted by the OS and never claimed is the leak that
        wedges astrald's worker pool (bug G-13)."""
        server = await listen_any("tcp")
        client = await dial(server.endpoint)
        self.assertTrue(await until(lambda: server.pending == 1))
        await server.aclose()
        self.assertEqual(await client.read(1), b"")
        await client.aclose()

    @bounded()
    async def test_accept_after_close_raises_rather_than_parking_forever(self):
        server = await listen_any("tcp")
        await server.aclose()
        with self.assertRaises(TransportError):
            await server.accept()

    @bounded()
    async def test_a_parked_accept_wakes_when_the_server_closes(self):
        server = await listen_any("tcp")
        pending = asyncio.ensure_future(server.accept())
        await asyncio.sleep(0)
        await server.aclose()
        with self.assertRaises(TransportError):
            await pending

    @bounded()
    async def test_a_connection_past_the_pending_bound_is_closed_not_hoarded(self):
        server = await listen_any("tcp", max_pending=1)
        async with server:
            kept = await dial(server.endpoint)
            refused = await dial(server.endpoint)
            self.assertTrue(await until(lambda: server.refused == 1))
            self.assertEqual(server.pending, 1)
            self.assertEqual(await refused.read(1), b"")
            await kept.aclose()
            await refused.aclose()

    @bounded()
    async def test_iterating_a_server_yields_connections_and_ends_at_close(self):
        server = await listen_any("tcp")
        client = await dial(server.endpoint)
        seen: list[str] = []

        async def accept_loop() -> None:
            async for conn in server:  # type: ignore[attr-defined]
                seen.append(conn.endpoint)
                await conn.aclose()

        task = asyncio.ensure_future(accept_loop())
        self.assertTrue(await until(lambda: len(seen) == 1))
        await server.aclose()
        await task
        self.assertTrue(task.done())
        await client.aclose()

    @bounded()
    async def test_a_unix_server_unlinks_its_socket_path_on_close(self):
        server = await listen_any("unix")
        path = server.endpoint[len("unix:") :]
        self.assertTrue(os.path.exists(path))
        await server.aclose()
        self.assertFalse(os.path.exists(path))

    @bounded()
    async def test_serving_a_web_endpoint_is_unsupported(self):
        with self.assertRaises(TransportUnsupported):
            await listen("ws://127.0.0.1:0/")
        with self.assertRaises(TransportUnsupported):
            await listen_any("ws")

    @bounded()
    async def test_a_second_server_aclose_waits_for_the_pending_queue(self):
        """The same contract as the transport's, one layer sideways.

        Draining the pending queue awaits a bounded flush per connection, so a
        second caller that returned during it would report a listener shut while
        connections nobody accepted were still open -- and unaccepted
        connections are exactly the leak that wedges astrald's worker pool.

        The connection stays *in* the queue for the whole of its own close.
        Removing it first was the old shape and it is what let a cancelled drain
        lose track of the rest of the queue: `pending` is what the server still
        owns, so it drops to zero when the descriptor is gone and not when the
        close was merely begun.
        """
        server = await listen_any("tcp")
        stalled = _SlowClose()
        server._pending.append(stalled)
        first = asyncio.ensure_future(server.aclose())
        self.assertTrue(await until(lambda: stalled.closing_now.is_set()))
        second = asyncio.ensure_future(server.aclose())
        await until(lambda: second.done())
        self.assertFalse(second.done(), "the second aclose() returned early")
        self.assertEqual(server.pending, 1, "dropped from the queue before it closed")
        self.assertFalse(stalled.closed)
        stalled.release.set()
        await asyncio.gather(first, second)
        self.assertTrue(stalled.closed)
        self.assertEqual(server.pending, 0)

    @bounded()
    async def test_a_cancelled_server_aclose_still_drains_the_whole_queue(self):
        """The same defect `Service.aclose()` and `Registrar.aclose()` carried,
        one layer down: the drain used to `popleft()` and await one close at a
        time with `_closed` latched in a `finally`, so a `CancelledError` landing
        in it abandoned every remaining queued connection -- five of six still
        open, `closed=True`, and a second `aclose()` returning at once. Each
        close is shielded and the entry leaves the queue only once it is gone."""
        server = await listen_any("tcp")
        clients = [await dial(server.endpoint) for _ in range(6)]
        await until(lambda: server.pending >= 6)

        closer = asyncio.ensure_future(server.aclose())
        await asyncio.sleep(0)
        closer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await closer

        self.assertTrue(server.closing)
        self.assertFalse(server.closed, "latched closed with the queue still held")
        await server.aclose()
        self.assertEqual(server.pending, 0, "a cancelled drain abandoned the queue")
        self.assertTrue(server.closed)
        for transport in clients:
            await transport.aclose()

    @bounded()
    async def test_the_server_does_not_report_closed_while_it_still_owns_connections(self):
        """`closed` is the drained fact; `closing` is the call.

        A flag that reported the call would say "closed" while the pending queue
        still held live descriptors -- the same promise-ahead-of-fact that let a
        transport claim a socket was gone while it was flushing 14 MB.
        """
        server = await listen_any("tcp")
        stalled = _SlowClose()
        server._pending.append(stalled)
        closing = asyncio.ensure_future(server.aclose())
        self.assertTrue(await until(lambda: stalled.closing_now.is_set()))
        self.assertTrue(server.closing)
        self.assertFalse(server.closed, "reported closed while draining the queue")
        self.assertIn("closing", repr(server))
        stalled.release.set()
        await closing
        self.assertTrue(server.closed)
        self.assertIn("closed", repr(server))


class _SlowClose:
    """A pending connection whose close suspends until the test releases it.

    Enough of a transport for the queue that holds it: `aclose()` is the only
    method `StreamServer.aclose` calls on a pending connection.
    """

    def __init__(self) -> None:
        self.closing_now = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = False

    async def aclose(self) -> None:
        self.closing_now.set()
        await self.release.wait()
        self.closed = True


if __name__ == "__main__":
    unittest.main()
