"""Tier B and C: the RFC 6455 client and the `astral.binary.v1` byte transport.

Five jobs:

1. Pin the upgrade: the request the client writes, and every reply it must
   refuse -- a status that is not 101, a wrong `Sec-WebSocket-Accept`, a missing
   `Upgrade`, an extension nobody offered, a subprotocol nobody offered.
2. Pin the framing byte for byte: the mask, the three length forms, one
   `Transport.write()` per frame, and the receive-side reassembly.
3. Prove every protocol violation closes the connection with the close code RFC
   6455 assigns, rather than resynchronising on a stream it can no longer trust.
4. Prove `WebSocketByteTransport` is a `Transport`: the two EOF shapes, short
   reads, concatenation across frames, and a `write_eof` that refuses rather
   than lies.
5. Prove the seam: a whole `MockApphost` behind a WebSocket, reached by
   `astral.connect("ws://…")` with no change to `session.py`.

Every async test is `bounded`. The Tier-B tests contact no node; the Tier-C class
skips unless one answers.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import re
import unittest
from unittest import mock as mocklib

import astral
from astral.errors import (
    ConcurrentRead,
    NodeUnavailable,
    TransportError,
    TransportUnsupported,
)
from astral.session import Session
from astral.transport import MemTransport, Transport, dial
from astral.transport.base import IncompleteRead
from astral.transport.websocket import (
    CLOSE_FRAME_TIMEOUT,
    CloseCode,
    MAX_MESSAGE_SIZE,
    Opcode,
    SUBPROTOCOL_BINARY,
    SUBPROTOCOL_JSON,
    WebSocketByteTransport,
    WebSocketClient,
    connect_websocket,
    open_websocket,
)
from astral.channel.binary import BinaryChannel
from astral.transport import websocket as websocket_module
from astral.transport.mem import _Pipe
from astral.transport.socket import CLOSE_TIMEOUT as SOCKET_CLOSE_TIMEOUT

import live_support
from mock_apphost import Accept, MockApphost, bounded
from mock_web import (
    WSConn,
    WSMock,
    WSServerTransport,
    bridge,
    long_frame,
    server_frame,
    ws_accept,
)

ENDPOINT = "ws://mock:8624/.ws"


# --- helpers --------------------------------------------------------------


async def read_head(transport: Transport) -> bytes:
    """One HTTP head off a transport, and not one byte past it."""
    out = bytearray()
    while not out.endswith(b"\r\n\r\n"):
        out += await transport.readexactly(1)
    return bytes(out)


def reply(
    key: str,
    *,
    status: str = "101 Switching Protocols",
    accept: str | None = None,
    subprotocol: str | None = SUBPROTOCOL_BINARY,
    upgrade: str | None = "websocket",
    connection: str | None = "Upgrade",
    extensions: str | None = None,
) -> bytes:
    """A 101 in Go's header capitalisation, which is not RFC 6455's."""
    lines = [f"HTTP/1.1 {status}"]
    if connection is not None:
        lines.append(f"Connection: {connection}")
    lines.append(f"Sec-Websocket-Accept: {accept if accept is not None else ws_accept(key)}")
    if subprotocol is not None:
        lines.append(f"Sec-Websocket-Protocol: {subprotocol}")
    if extensions is not None:
        lines.append(f"Sec-Websocket-Extensions: {extensions}")
    if upgrade is not None:
        lines.append(f"Upgrade: {upgrade}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


async def upgrade(
    *, subprotocols: tuple[str, ...] = (SUBPROTOCOL_BINARY,), **kw: object
) -> tuple[WebSocketClient, MemTransport, bytes]:
    """A handshaken client over memory, plus the peer and the request bytes."""
    client_side, server_side = MemTransport.pair("ws")
    task = asyncio.create_task(
        WebSocketClient.over(
            client_side, endpoint=ENDPOINT, authority="mock:8624", subprotocols=subprotocols
        )
    )
    head = await read_head(server_side)
    key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
    server_side.write(reply(key, **kw))  # type: ignore[arg-type]
    return await task, server_side, head


async def upgraded_transport() -> tuple[WebSocketByteTransport, MemTransport]:
    client, server_side, _ = await upgrade()
    return WebSocketByteTransport(client), server_side


# --- the upgrade ----------------------------------------------------------


class UpgradeRequestTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_request_carries_every_header_rfc_6455_requires(self):
        _client, _peer, head = await upgrade()
        text = head.decode()
        self.assertTrue(text.startswith("GET /.ws HTTP/1.1\r\n"), text)
        self.assertIn("Host: mock:8624\r\n", text)
        self.assertIn("Upgrade: websocket\r\n", text)
        self.assertIn("Connection: Upgrade\r\n", text)
        self.assertIn("Sec-WebSocket-Version: 13\r\n", text)
        self.assertIn(f"Sec-WebSocket-Protocol: {SUBPROTOCOL_BINARY}\r\n", text)
        self.assertTrue(text.endswith("\r\n\r\n"))

    @bounded()
    async def test_the_key_is_sixteen_fresh_random_bytes(self):
        """RFC 6455 section 4.1: 16 bytes, base64, freshly random per connection.

        A key drawn once per process would let a cache replay one accept token
        for every later connection, which is the whole of what the token proves.
        """
        keys = set()
        for _ in range(4):
            _client, _peer, head = await upgrade()
            key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
            self.assertEqual(len(key), 24)
            self.assertEqual(len(_b64(key)), 16)
            keys.add(key)
        self.assertEqual(len(keys), 4)

    @bounded()
    async def test_the_upgrade_is_one_write(self):
        client_side, server_side = MemTransport.pair("ws")
        task = asyncio.create_task(
            WebSocketClient.over(client_side, endpoint=ENDPOINT, authority="mock")
        )
        head = await read_head(server_side)
        key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
        server_side.write(reply(key))
        await task
        self.assertEqual(len(client_side.writes), 1)

    @bounded()
    async def test_an_origin_and_extra_headers_are_sent_when_asked(self):
        client_side, server_side = MemTransport.pair("ws")
        task = asyncio.create_task(
            WebSocketClient.over(
                client_side,
                endpoint=ENDPOINT,
                origin="https://app.example",
                headers={"X-Proxy": "yes"},
            )
        )
        head = await read_head(server_side)
        key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
        server_side.write(reply(key))
        await task
        self.assertIn(b"Origin: https://app.example\r\n", head)
        self.assertIn(b"X-Proxy: yes\r\n", head)

    @bounded()
    async def test_no_extension_is_ever_offered(self):
        """`permessage-deflate` is not implemented, so it is not offered. A client
        that advertised it and then ignored the reply would decode compressed
        frames as raw ones."""
        _client, _peer, head = await upgrade()
        self.assertNotIn(b"Sec-WebSocket-Extensions", head)


class UpgradeReplyTest(unittest.IsolatedAsyncioTestCase):
    async def refuse(self, **kw: object) -> TransportError:
        client_side, server_side = MemTransport.pair("ws")
        task = asyncio.create_task(
            WebSocketClient.over(client_side, endpoint=ENDPOINT, authority="mock")
        )
        head = await read_head(server_side)
        key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
        server_side.write(reply(key, **kw))  # type: ignore[arg-type]
        with self.assertRaises(TransportError) as caught:
            await task
        # A handshake that did not complete hands nothing back, so it closes what
        # it opened. A leaked connection is one of astrald's 32 workers.
        self.assertTrue(client_side.closed)
        return caught.exception

    @bounded()
    async def test_the_go_capitalisation_of_the_accept_header_is_accepted(self):
        """Verified against `furry-bolt`: the node answers `Sec-Websocket-Accept`,
        not RFC 6455's `Sec-WebSocket-Accept`. A case-sensitive lookup would fail
        the handshake against the one node this SDK exists to talk to."""
        client, _peer, _head = await upgrade()
        self.assertEqual(client.subprotocol, SUBPROTOCOL_BINARY)

    @bounded()
    async def test_a_status_other_than_101_is_refused_and_names_the_path(self):
        exc = await self.refuse(status="401 Unauthorized")
        self.assertIn("401", str(exc))
        self.assertIn("/.ws", str(exc))

    @bounded()
    async def test_a_wrong_accept_token_is_refused(self):
        exc = await self.refuse(accept="AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        self.assertIn("Sec-WebSocket-Accept", str(exc))

    @bounded()
    async def test_a_reply_that_upgrades_to_nothing_is_refused(self):
        self.assertIn("upgrade", str(await self.refuse(upgrade=None)).lower())
        self.assertIn("upgrade", str(await self.refuse(upgrade="h2c")).lower())
        self.assertIn("Connection", str(await self.refuse(connection=None)))
        self.assertIn("Connection", str(await self.refuse(connection="keep-alive")))

    @bounded()
    async def test_an_extension_nobody_offered_is_refused(self):
        exc = await self.refuse(extensions="permessage-deflate")
        self.assertIn("permessage-deflate", str(exc))

    @bounded()
    async def test_a_subprotocol_nobody_offered_is_refused(self):
        exc = await self.refuse(subprotocol="chat.v1")
        self.assertIn("chat.v1", str(exc))

    @bounded()
    async def test_a_reply_naming_no_subprotocol_leaves_it_empty(self):
        client, _peer, _head = await upgrade(subprotocol=None)
        self.assertEqual(client.subprotocol, "")

    @bounded()
    async def test_a_connection_that_closes_during_the_upgrade_is_reported(self):
        client_side, server_side = MemTransport.pair("ws")
        task = asyncio.create_task(
            WebSocketClient.over(client_side, endpoint=ENDPOINT, authority="mock")
        )
        await read_head(server_side)
        await server_side.aclose()
        with self.assertRaises(EOFError):
            await task
        self.assertTrue(client_side.closed)


# --- framing --------------------------------------------------------------


class FrameWriteTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_every_client_frame_is_masked_with_fresh_bytes(self):
        """RFC 6455 section 5.3 requires a client to mask, with a key that is
        unpredictable per frame. A fixed key is the same as no key."""
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        keys = set()
        for _ in range(4):
            await client.send_binary(b"payload")
            frame = await conn.recv_frame()
            self.assertTrue(frame.masked)
            self.assertEqual(frame.payload, b"payload")
            keys.add(frame.key)
        self.assertEqual(len(keys), 4)

    @bounded()
    async def test_the_three_length_forms_are_used_at_their_boundaries(self):
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        for size, marker, extra in ((125, 125, 0), (126, 126, 2), (65535, 126, 2), (65536, 127, 8)):
            with self.subTest(size=size):
                await client.send_binary(b"x" * size)
                raw = peer_sent(client)
                self.assertEqual(raw[1] & 0x7F, marker)
                self.assertEqual(len(raw), 2 + extra + 4 + size)
                frame = await conn.recv_frame()
                self.assertEqual(len(frame.payload), size)

    @bounded()
    async def test_one_frame_is_exactly_one_transport_write(self):
        """Design section 3.2 rule 2. Cancellation cannot land mid-frame when the
        frame reaches the transport in a single call."""
        client, peer, _head = await upgrade()
        transport = client.transport
        assert isinstance(transport, MemTransport)
        before = len(transport.writes)
        await client.send_binary(b"x" * 70000)
        await client.send_text("hi")
        await client.ping(b"p")
        self.assertEqual(len(transport.writes) - before, 3)

    @bounded()
    async def test_a_text_frame_carries_utf8(self):
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        await client.send_text("héllo")
        frame = await conn.recv_frame()
        self.assertEqual(frame.opcode, int(Opcode.TEXT))
        self.assertEqual(frame.payload.decode(), "héllo")

    @bounded()
    async def test_a_send_after_close_is_refused(self):
        client, _peer, _head = await upgrade()
        await client.send_close()
        with self.assertRaises(ConnectionResetError):
            await client.send_binary(b"late")


class FrameReadTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_three_length_forms_are_read(self):
        client, peer, _head = await upgrade()
        for size in (0, 1, 125, 126, 65535, 65536):
            with self.subTest(size=size):
                peer.write(server_frame(0x2, b"y" * size))
                message = await client.receive()
                self.assertEqual(message.data, b"y" * size)

    @bounded()
    async def test_fragments_are_reassembled(self):
        client, peer, _head = await upgrade()
        peer.write(server_frame(0x2, b"one", fin=False))
        peer.write(server_frame(0x0, b"two", fin=False))
        peer.write(server_frame(0x0, b"three"))
        message = await client.receive()
        self.assertEqual(message.data, b"onetwothree")
        self.assertIs(message.opcode, Opcode.BINARY)

    @bounded()
    async def test_a_control_frame_may_interleave_a_fragmented_message(self):
        """RFC 6455 section 5.4: control frames may be injected between the
        fragments of one message, and reassembly must survive it."""
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        peer.write(server_frame(0x1, "hé".encode(), fin=False))
        peer.write(server_frame(0x9, b"beat"))
        peer.write(server_frame(0x0, b"llo"))
        message = await client.receive()
        self.assertEqual(message.text, "héllo")
        pong = await conn.recv_frame()
        self.assertEqual(pong.opcode, int(Opcode.PONG))
        self.assertEqual(pong.payload, b"beat")

    @bounded()
    async def test_a_ping_is_answered_with_the_same_payload(self):
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        peer.write(server_frame(0x9, b"ping-body"))
        peer.write(server_frame(0x2, b"after"))
        message = await client.receive()
        self.assertEqual(message.data, b"after")
        pong = await conn.recv_frame()
        self.assertEqual((pong.opcode, pong.payload), (int(Opcode.PONG), b"ping-body"))
        self.assertEqual(client.pings_answered, 1)

    @bounded()
    async def test_a_pong_is_recorded_and_discarded(self):
        client, peer, _head = await upgrade()
        peer.write(server_frame(0xA, b"keepalive"))
        peer.write(server_frame(0x2, b"data"))
        self.assertEqual((await client.receive()).data, b"data")
        self.assertEqual(client.last_pong, b"keepalive")

    @bounded()
    async def test_a_close_frame_ends_the_stream_and_is_echoed(self):
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        peer.write(server_frame(0x8, (1001).to_bytes(2, "big") + b"going away"))
        with self.assertRaises(EOFError):
            await client.receive()
        self.assertEqual(client.close_code, 1001)
        self.assertEqual(client.close_reason, "going away")
        echo = await conn.recv_frame()
        self.assertEqual(echo.opcode, int(Opcode.CLOSE))
        self.assertEqual(int.from_bytes(echo.payload[:2], "big"), 1001)
        self.assertTrue(client.ended)

    @bounded()
    async def test_an_empty_close_frame_is_a_normal_close(self):
        client, peer, _head = await upgrade()
        peer.write(server_frame(0x8))
        with self.assertRaises(EOFError):
            await client.receive()
        self.assertEqual(client.close_code, int(CloseCode.NORMAL))

    @bounded()
    async def test_a_peer_that_vanishes_at_a_frame_boundary_is_a_clean_eof(self):
        client, peer, _head = await upgrade()
        await peer.aclose()
        with self.assertRaises(EOFError):
            await client.receive()

    @bounded()
    async def test_receive_text_drops_binary_messages(self):
        """The `astral.json.v1` contract of design section 3.1."""
        client, peer, _head = await upgrade()
        peer.write(server_frame(0x2, b"\x00\x01"))
        peer.write(server_frame(0x1, b'{"Type":"eos"}'))
        self.assertEqual(await client.receive_text(), '{"Type":"eos"}')

    @bounded()
    async def test_a_second_concurrent_reader_is_refused(self):
        client, peer, _head = await upgrade()
        first = asyncio.create_task(client.receive())
        for _ in range(3):
            await asyncio.sleep(0)
        with self.assertRaises(ConcurrentRead):
            await client.receive()
        peer.write(server_frame(0x2, b"done"))
        self.assertEqual((await first).data, b"done")


class ProtocolFaultTest(unittest.IsolatedAsyncioTestCase):
    """Every violation closes with the code RFC 6455 assigns, and raises."""

    async def violate(self, *frames: bytes) -> tuple[TransportError, WSConn]:
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        for frame in frames:
            peer.write(frame)
        with self.assertRaises(TransportError) as caught:
            await client.receive()
        self.assertTrue(client.ended)
        return caught.exception, conn

    async def close_code_of(self, conn: WSConn) -> int:
        frame = await conn.recv_frame()
        self.assertEqual(frame.opcode, int(Opcode.CLOSE))
        return int.from_bytes(frame.payload[:2], "big")

    @bounded()
    async def test_a_masked_server_frame_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x2, b"nope", masked=True))
        self.assertIn("masked", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_a_reserved_bit_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x2, b"x", rsv=4))
        self.assertIn("reserved", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_an_unknown_opcode_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x3, b"x"))
        self.assertIn("opcode", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_a_fragmented_control_frame_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x9, b"x", fin=False))
        self.assertIn("fragment", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_an_oversize_control_frame_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x9, b"x" * 126))
        self.assertIn("126", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_a_non_minimal_length_is_a_protocol_error(self):
        """A 126-form header declaring 4 bytes, and a 127-form declaring 200: both
        encode a length the shorter form carries, which is how a smuggled frame
        gets two readings."""
        exc, conn = await self.violate(b"\x82\x7e\x00\x04abcd")
        self.assertIn("minimally", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))
        exc, conn = await self.violate(b"\x82\x7f" + (200).to_bytes(8, "big"))
        self.assertIn("minimally", str(exc))

    @bounded()
    async def test_a_continuation_with_no_message_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x0, b"orphan"))
        self.assertIn("continuation", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_a_data_frame_inside_a_fragmented_message_is_a_protocol_error(self):
        exc, conn = await self.violate(
            server_frame(0x2, b"first", fin=False), server_frame(0x2, b"second")
        )
        self.assertIn("interrupted", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_invalid_utf8_in_a_text_message_is_refused(self):
        exc, conn = await self.violate(server_frame(0x1, b"\xff\xfe"))
        self.assertIn("utf-8", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.INVALID_PAYLOAD))

    @bounded()
    async def test_a_one_byte_close_payload_is_a_protocol_error(self):
        exc, conn = await self.violate(server_frame(0x8, b"\x03"))
        self.assertIn("one byte", str(exc))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.PROTOCOL_ERROR))

    @bounded()
    async def test_a_frame_over_the_cap_is_refused_before_it_is_read(self):
        """The header alone is enough: a client that read the payload first would
        allocate whatever a peer declared."""
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        client.max_frame_size = 1024
        peer.write(long_frame(0x2, 0, declared=4096))
        with self.assertRaises(TransportError) as caught:
            await client.receive()
        self.assertIn("4096", str(caught.exception))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.TOO_BIG))

    @bounded()
    async def test_a_message_cut_into_too_many_fragments_is_refused(self):
        """The byte cap does not bound the reassembly, because a fragment costs
        heap whatever its payload weighs. A zero-length continuation adds nothing
        to the byte count at all, so a peer sending them fragments for ever:
        measured at 200,000 frames with the byte cap untouched, and at 400,000
        one-byte frames for 1.2 MB of wire against 16.9 MB of heap."""
        for payload in (b"", b"x"):
            with self.subTest(payload=payload):
                client, peer, _head = await upgrade()
                conn = _peer_conn(peer)
                client.max_message_fragments = 8
                for _ in range(20):
                    peer.write(server_frame(0x2 if not _ else 0x0, payload, fin=False))
                with self.assertRaises(TransportError) as caught:
                    await client.receive()
                self.assertIn("8 fragments", str(caught.exception))
                self.assertEqual(await self.close_code_of(conn), int(CloseCode.TOO_BIG))

    @bounded()
    async def test_a_protocol_fault_latches_and_is_not_reported_as_a_clean_end(self):
        """`_ended` alone told the first reader the framing was violated and
        every later reader that the peer had finished normally -- and through
        `WebSocketByteTransport`, `read()` answered `b""`, which is the transport
        seam's spelling of a clean end of stream. A violated connection cannot
        be trusted about where the next frame starts, so it says so to whoever
        asks."""
        client, peer, _head = await upgrade()
        peer.write(server_frame(0x2, b"nope", masked=True))
        with self.assertRaises(TransportError) as first:
            await client.receive()
        with self.assertRaises(TransportError) as second:
            await client.receive()
        self.assertEqual(str(first.exception), str(second.exception))
        transport = WebSocketByteTransport(client)
        with self.assertRaises(TransportError):
            await transport.read(4)

    @bounded()
    async def test_a_message_over_the_cap_is_refused_across_fragments(self):
        """Each fragment fits the frame cap; the message does not. A cap on frames
        alone lets a peer spend this process's memory one fragment at a time."""
        client, peer, _head = await upgrade()
        conn = _peer_conn(peer)
        client.max_message_size = 8
        peer.write(server_frame(0x2, b"12345", fin=False))
        peer.write(server_frame(0x0, b"67890"))
        with self.assertRaises(TransportError) as caught:
            await client.receive()
        self.assertIn("8 bytes", str(caught.exception))
        self.assertEqual(await self.close_code_of(conn), int(CloseCode.TOO_BIG))

    @bounded()
    async def test_the_default_caps_are_the_documented_ones(self):
        client, _peer, _head = await upgrade()
        self.assertEqual(client.max_message_size, MAX_MESSAGE_SIZE)
        self.assertEqual(client.max_frame_size, 16 * 1024 * 1024)


# --- the byte transport ---------------------------------------------------


class ByteTransportTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_frames_concatenate_into_one_byte_stream(self):
        """The live shape, reproduced: `furry-bolt` sends the length prefix and
        the type name of one apphost frame as two separate messages, because
        `BinarySender.Send` writes a frame with four `Write` calls and
        `websocket.NetConn` maps one `Write` to one message."""
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x2, b"\x19"))
        peer.write(server_frame(0x2, b"mod.apphost.host_info_msg"))
        self.assertEqual(await transport.readexactly(1), b"\x19")
        self.assertEqual(await transport.readexactly(25), b"mod.apphost.host_info_msg")

    @bounded()
    async def test_a_read_never_waits_for_a_frame_it_does_not_need(self):
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x2, b"abcdef"))
        self.assertEqual(await transport.read(2), b"ab")
        self.assertEqual(await transport.read(99), b"cdef")

    @bounded()
    async def test_read_returns_empty_at_eof_and_readexactly_raises(self):
        transport, peer = await upgraded_transport()
        await peer.aclose()
        self.assertEqual(await transport.read(4), b"")
        with self.assertRaises(EOFError) as caught:
            await transport.readexactly(4)
        self.assertNotIsInstance(caught.exception, IncompleteRead)

    @bounded()
    async def test_a_short_stream_is_an_incomplete_read_carrying_its_partial(self):
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x2, b"abc"))
        await peer.aclose()
        with self.assertRaises(IncompleteRead) as caught:
            await transport.readexactly(6)
        self.assertEqual(caught.exception.partial, b"abc")

    @bounded()
    async def test_read_to_eof_drains_every_frame(self):
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x2, b"one"))
        peer.write(server_frame(0x2, b"two"))
        await peer.aclose()
        self.assertEqual(await transport.read(-1), b"onetwo")

    @bounded()
    async def test_a_close_frame_ends_the_stream_cleanly(self):
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x2, b"last"))
        peer.write(server_frame(0x8, (1000).to_bytes(2, "big")))
        self.assertEqual(await transport.readexactly(4), b"last")
        self.assertEqual(await transport.read(4), b"")

    @bounded()
    async def test_text_frames_are_dropped(self):
        transport, peer = await upgraded_transport()
        peer.write(server_frame(0x1, b"chatter"))
        peer.write(server_frame(0x2, b"bytes"))
        self.assertEqual(await transport.readexactly(5), b"bytes")

    @bounded()
    async def test_a_write_is_one_binary_frame_and_an_empty_write_is_nothing(self):
        transport, peer = await upgraded_transport()
        conn = _peer_conn(peer)
        transport.write(b"")
        transport.write(b"payload")
        await transport.drain()
        frame = await conn.recv_frame()
        self.assertEqual((frame.opcode, frame.payload, frame.masked), (0x2, b"payload", True))

    @bounded()
    async def test_write_eof_is_refused_and_says_why(self):
        """WebSocket has no half-close. An op whose input ends at EOF rather than
        at an `eos` is unreachable here, and hearing so beats hanging."""
        transport, _peer = await upgraded_transport()
        with self.assertRaises(TransportUnsupported) as caught:
            transport.write_eof()
        self.assertIn("half-close", str(caught.exception))

    @bounded()
    async def test_aclose_sends_a_close_frame_and_is_idempotent(self):
        transport, peer = await upgraded_transport()
        conn = _peer_conn(peer)
        await transport.aclose()
        frame = await conn.recv_frame()
        self.assertEqual(frame.opcode, int(Opcode.CLOSE))
        self.assertEqual(int.from_bytes(frame.payload[:2], "big"), int(CloseCode.NORMAL))
        self.assertTrue(transport.closed)
        await transport.aclose()

    @bounded()
    async def test_a_negative_length_readexactly_is_refused(self):
        transport, _peer = await upgraded_transport()
        with self.assertRaises(ValueError):
            await transport.readexactly(-1)


# --- over a real socket ---------------------------------------------------


class LoopbackTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_open_websocket_upgrades_and_carries_bytes(self):
        async def echo(conn: WSConn) -> None:
            while True:
                data = await conn.recv_data()
                await conn.send_binary(data.upper())

        async with WSMock(echo) as mock:
            transport = await open_websocket(mock.endpoint)
            try:
                transport.write(b"ping")
                await transport.drain()
                self.assertEqual(await transport.readexactly(4), b"PING")
                self.assertEqual(
                    mock.requests[0].get("Sec-WebSocket-Protocol"), SUBPROTOCOL_BINARY
                )
            finally:
                await transport.aclose()
            self.assertTrue(transport.closed)

    @bounded()
    async def test_dial_returns_a_websocket_transport_for_a_ws_endpoint(self):
        async def hold(conn: WSConn) -> None:
            await conn.send_binary(b"hello")
            await conn.recv_frame()

        async with WSMock(hold) as mock:
            transport = await dial(mock.endpoint)
            try:
                self.assertIsInstance(transport, WebSocketByteTransport)
                self.assertEqual(await transport.readexactly(5), b"hello")
            finally:
                await transport.aclose()

    @bounded()
    async def test_a_refused_upgrade_is_a_transport_error_not_node_unavailable(self):
        """A peer that answers is reachable. `NodeUnavailable` is the retry key,
        and retrying a 403 collects the same 403."""
        async with WSMock(status=403) as mock:
            with self.assertRaises(TransportError) as caught:
                await open_websocket(mock.endpoint)
            self.assertNotIsInstance(caught.exception, NodeUnavailable)
            self.assertIn("403", str(caught.exception))

    @bounded()
    async def test_a_closed_port_is_node_unavailable(self):
        async with WSMock() as mock:
            endpoint = mock.endpoint
        with self.assertRaises(NodeUnavailable):
            await open_websocket(endpoint, timeout=2)

    @bounded()
    async def test_a_peer_that_closes_during_the_upgrade_is_a_transport_error(self):
        async with WSMock(close_before_reply=True) as mock:
            with self.assertRaises(TransportError) as caught:
                await open_websocket(mock.endpoint, timeout=2)
            self.assertIn("closed during the upgrade", str(caught.exception))

    @bounded()
    async def test_a_peer_that_never_answers_expires_as_node_unavailable(self):
        """The saturated-node shape one layer down: the socket is accepted, the
        request is read and no reply ever comes. Bounded, or the SDK hangs."""
        async with WSMock(silent=True) as mock:
            with self.assertRaises(NodeUnavailable) as caught:
                await open_websocket(mock.endpoint, timeout=0.3)
            self.assertIn("no upgrade", str(caught.exception))

    @bounded()
    async def test_the_json_subprotocol_is_refused_by_the_byte_transport(self):
        """`astral.json.v1` has no byte stream underneath it. A binary framer
        handed one would read JSON text as a length prefix."""
        async def idle(conn: WSConn) -> None:
            await conn.recv_frame()

        async with WSMock(idle, subprotocol=SUBPROTOCOL_JSON) as mock:
            with self.assertRaises(TransportUnsupported) as caught:
                await open_websocket(
                    mock.endpoint, subprotocols=(SUBPROTOCOL_BINARY, SUBPROTOCOL_JSON)
                )
            self.assertIn(SUBPROTOCOL_JSON, str(caught.exception))

    @bounded()
    async def test_a_subprotocol_nobody_offered_is_refused_by_the_handshake(self):
        """RFC 6455 section 4.1: a peer may answer with one of the offered
        subprotocols or with none, never with a third."""
        async def idle(conn: WSConn) -> None:
            await conn.recv_frame()

        async with WSMock(idle, subprotocol=SUBPROTOCOL_JSON) as mock:
            with self.assertRaises(TransportError) as caught:
                await open_websocket(mock.endpoint)
            self.assertIn("not offered", str(caught.exception))

    @bounded()
    async def test_the_json_subprotocol_carries_text_messages(self):
        async def talk(conn: WSConn) -> None:
            await conn.send_text('{"Type":"mod.apphost.host_info_msg"}')
            await conn.recv_frame()

        async with WSMock(talk, subprotocol=SUBPROTOCOL_JSON) as mock:
            client = await connect_websocket(mock.endpoint, subprotocols=(SUBPROTOCOL_JSON,))
            try:
                self.assertEqual(client.subprotocol, SUBPROTOCOL_JSON)
                self.assertEqual(
                    await client.receive_text(), '{"Type":"mod.apphost.host_info_msg"}'
                )
            finally:
                await client.aclose()


class DeafTransport(MemTransport):
    """A peer that accepted the connection and stopped reading.

    `drain()` never returns once `deaf` is set, which is what asyncio's writer
    does against a reader that is gone: the send buffer stays over the
    high-water mark for as long as the peer likes. Measured on a real socket at
    64 MiB queued and the connection still ESTABLISHED after ten seconds.
    """

    deaf = False

    async def drain(self) -> None:
        if self.deaf:
            await asyncio.Event().wait()


async def deaf_client() -> tuple[WebSocketClient, DeafTransport]:
    """A handshaken client whose carrier stops draining after the upgrade."""
    left, right = _Pipe(), _Pipe()
    deaf = DeafTransport(left, right, "mem:deaf")
    server_side = MemTransport(right, left, "mem:deaf")
    task = asyncio.create_task(
        WebSocketClient.over(
            deaf, endpoint=ENDPOINT, authority="mock:8624", subprotocols=(SUBPROTOCOL_BINARY,)
        )
    )
    head = await read_head(server_side)
    key = re.search(rb"Sec-WebSocket-Key: (\S+)", head).group(1).decode()
    server_side.write(reply(key))
    client = await task
    deaf.deaf = True
    return client, deaf


class BoundedCloseTest(unittest.IsolatedAsyncioTestCase):
    """The courtesy Close frame is bounded and the descriptor is not hostage to it.

    `send_close` ends in `Transport.drain()`, which has no bound. Ordering it
    ahead of the transport close without one handed a deaf peer the descriptor
    for ever: measured at 10 s and counting, `closed` false and two descriptors
    held, where the same peer over a plain `StreamTransport` released in 2.01 s.
    """

    def test_the_close_frame_bound_is_of_the_sockets_order(self):
        """A courtesy frame is worth about what a socket flush is worth, and a
        close that hit both waits at most for their sum."""
        self.assertGreater(CLOSE_FRAME_TIMEOUT, 0)
        self.assertLessEqual(CLOSE_FRAME_TIMEOUT, SOCKET_CLOSE_TIMEOUT)

    @bounded()
    async def test_a_deaf_peer_cannot_hold_the_close_open(self):
        client, deaf = await deaf_client()
        with mocklib.patch.object(websocket_module, "CLOSE_FRAME_TIMEOUT", 0.05):
            await client.aclose()
        self.assertTrue(deaf.closed)
        self.assertTrue(client.closed)

    @bounded()
    async def test_a_cancelled_close_still_releases_the_transport(self):
        """A `CancelledError` is not an `Exception` and `suppress` never caught
        it, so a cancellation landing in the courtesy frame used to skip the one
        call that releases anything. The transport close is in a `finally`."""
        client, deaf = await deaf_client()
        task = asyncio.create_task(client.aclose())
        for _ in range(20):
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(deaf.closed)

    @bounded()
    async def test_a_peer_close_and_a_protocol_fault_are_bounded_the_same_way(self):
        """`_on_close` and `_fail` reach the transport through the same helper,
        so neither can be reordered back in front of the release."""
        for label, feed in (
            ("peer close", server_frame(int(Opcode.CLOSE), b"\x03\xe8")),
            ("protocol fault", bytes([0x82 | 0x40, 0x00])),  # a reserved bit
        ):
            with self.subTest(label):
                client, deaf = await deaf_client()
                with mocklib.patch.object(websocket_module, "CLOSE_FRAME_TIMEOUT", 0.05):
                    deaf.feed(feed)
                    with self.assertRaises((EOFError, TransportError)):
                        await client.receive_frame()
                self.assertTrue(deaf.closed)


class FrameBoundaryTest(unittest.IsolatedAsyncioTestCase):
    """The WebSocket framing answers `at_frame_boundary` for the layers above.

    A read abandoned between a frame's two-byte header and its payload leaves
    half a frame on the wire. Nothing recorded it, so `BinaryChannel` -- which
    tracks the *apphost* frame and had been handed no byte -- answered `True`,
    `Session._recv` kept the connection, and the next read parsed the payload's
    first two bytes as a frame header. Measured: the peer's stream was
    `b'\\x82\\x0512345REALDATA'` and the next read answered `b'12345'`, a message
    boundary the peer never sent.
    """

    @bounded()
    async def test_a_read_abandoned_inside_a_frame_is_not_a_boundary(self):
        client, peer, _ = await upgrade()
        self.assertTrue(client.at_frame_boundary)
        peer.write(b"\x82\x05")  # the header, and none of the payload
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await client.receive_frame()
        self.assertFalse(client.at_frame_boundary)

    @bounded()
    async def test_that_read_latches_a_fault_for_a_reader_with_no_channel(self):
        """A raw byte stream has nothing above it to ask, so the fault latches
        and every later read raises rather than resynchronising."""
        client, peer, _ = await upgrade()
        peer.write(b"\x82\x05")
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await client.receive_frame()
        peer.write(b"12345REALDATA")
        with self.assertRaises(TransportError) as caught:
            await client.receive_frame()
        self.assertIn("abandoned between a frame's header and its payload", str(caught.exception))

    @bounded()
    async def test_a_read_abandoned_at_a_boundary_strands_nothing(self):
        """What keeps an idle follow stream's deadline harmless over this
        carrier: the two header bytes are taken together or not at all."""
        client, peer, _ = await upgrade()
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await client.receive_frame()
        self.assertTrue(client.at_frame_boundary)
        peer.write(server_frame(int(Opcode.BINARY), b"whole"))
        frame = await client.receive_frame()
        self.assertEqual(frame.payload, b"whole")

    @bounded()
    async def test_the_byte_transport_and_the_channel_conjoin_the_answer(self):
        """The finding itself: `BinaryChannel` over WebSocket must not report a
        boundary its carrier does not have."""
        transport, peer = await upgraded_transport()
        channel = BinaryChannel(transport)
        self.assertTrue(transport.at_frame_boundary)
        self.assertTrue(channel.at_frame_boundary)
        peer.write(b"\x82\x05")
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await channel.receive()
        self.assertFalse(transport.at_frame_boundary)
        self.assertFalse(channel.at_frame_boundary)

    @bounded()
    async def test_a_session_over_websocket_closes_on_that_read(self):
        """`Session._recv`'s rule, reaching the fact it could not see before."""
        transport, peer = await upgraded_transport()
        session = Session(transport, greeted=True)
        peer.write(b"\x82\x05")
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await session.next_incoming(timeout=None)
        self.assertTrue(session.closed)
        self.assertTrue(transport.closed)


class SessionOverWebSocketTest(unittest.IsolatedAsyncioTestCase):
    """The seam: a whole apphost session over WebSocket, `session.py` untouched."""

    @bounded()
    async def test_connect_and_query_run_over_a_websocket(self):
        route = Accept(objects=[("identity", b"\x02" * 33)], eos=True)
        async with MockApphost(routes={"apphost.whoami": route}) as mock:

            async def serve(conn: WSConn) -> None:
                node_side = WSServerTransport(conn)
                mem = await mock.open()
                await bridge(node_side, mem)

            async with WSMock(serve) as ws:
                client = await astral.connect(ws.endpoint)
                try:
                    self.assertEqual(client.host_id, mock.host_id)
                    self.assertEqual(client.endpoint, ws.endpoint)
                    stream = await client.query("apphost.whoami")
                    async with stream:
                        objects = [obj async for obj in stream]
                    self.assertEqual(len(objects), 1)
                finally:
                    await client.aclose()

    @bounded()
    async def test_a_session_over_a_websocket_supports_a_raw_stream(self):
        """WS-binary is a byte stream, so RAW-mode ops are legal on it -- unlike
        `astral.json.v1` and HTTP (design section 3.1)."""
        async with MockApphost() as mock:

            async def serve(conn: WSConn) -> None:
                await bridge(WSServerTransport(conn), await mock.open())

            async with WSMock(serve) as ws:
                transport = await dial(ws.endpoint)
                session = await Session.over(transport, endpoint=ws.endpoint)
                try:
                    self.assertTrue(session.supports_raw_stream)
                    self.assertEqual(session.host_id, mock.host_id)
                finally:
                    await session.aclose()


# --- the node -------------------------------------------------------------


WS_ENDPOINT_VAR = "ASTRAL_TEST_WS_ENDPOINT"
DEFAULT_WS_ENDPOINT = "ws://127.0.0.1:8624/.ws"


class LiveWebSocketTest(unittest.IsolatedAsyncioTestCase):
    """Tier C. Skips unless the live tier is on **and** the node's HTTP listener
    answers: `bind_http` defaults to `tcp:0.0.0.0:8624` but is configurable, so
    an unreachable WebSocket is a skip and never a failure."""

    async def asyncSetUp(self) -> None:
        reason = await live_support.verdict()
        if reason:
            self.skipTest(reason)
        self.ws_endpoint = os.environ.get(WS_ENDPOINT_VAR) or DEFAULT_WS_ENDPOINT
        try:
            client = await connect_websocket(self.ws_endpoint, timeout=3)
        except Exception as exc:  # noqa: BLE001 -- any fault is a reason to skip
            self.skipTest(f"{self.ws_endpoint}: {type(exc).__name__}: {exc}")
        await client.aclose()

    @bounded(20)
    async def test_the_node_upgrades_and_greets_over_binary_frames(self):
        transport = await open_websocket(self.ws_endpoint)
        try:
            length = (await transport.readexactly(1))[0]
            name = await transport.readexactly(length)
            self.assertEqual(name, b"mod.apphost.host_info_msg")
            size = int.from_bytes(await transport.readexactly(4), "big")
            payload = await transport.readexactly(size)
            # The greeting is `*Identity` then the alias: a nil flag, 33 bytes of
            # key, then a string8. Identity is 33 flat bytes (risk R-1).
            self.assertEqual(payload[0], 1)
            self.assertEqual(len(payload), 1 + 33 + 1 + payload[34])
        finally:
            await transport.aclose()

    @bounded(20)
    async def test_a_whole_session_runs_over_the_websocket(self):
        """The seam, against the node: `astral.connect("ws://…")` and a read-only
        op, with `session.py` unchanged."""
        client = await astral.connect(self.ws_endpoint, max_concurrency=2)
        try:
            self.assertIsNotNone(client.host_id)
            identity = await client.apphost.whoami()
            self.assertIsNotNone(identity)
            # Two ops over one WebSocket-backed client, each on its own
            # connection: `apphost.whoami` ends at bare EOF and `dir.alias_map`
            # answers one map, so both terminations are exercised over the
            # upgrade rather than only the easy one.
            aliases = await client.dir.alias_map()
            self.assertIn(client.host_alias, aliases)
        finally:
            await client.aclose()

    @bounded(20)
    async def test_the_node_negotiates_the_json_subprotocol_and_sends_text(self):
        client = await connect_websocket(self.ws_endpoint, subprotocols=(SUBPROTOCOL_JSON,))
        try:
            self.assertEqual(client.subprotocol, SUBPROTOCOL_JSON)
            greeting = await client.receive_text()
            self.assertIn("mod.apphost.host_info_msg", greeting)
        finally:
            await client.aclose()

    @bounded(20)
    async def test_a_session_runs_over_the_json_subprotocol_and_carries_no_raw(self):
        """The second carrier of design section 3.1, against the node.

        `Session` takes the `WebSocketClient` itself here: `astral.json.v1` is
        one JSON envelope per text frame and has no byte stream underneath, which
        is the whole reason `Channel` and `Transport` are two seams. It is also
        the only carrier for which `supports_raw_stream` is false, so this is
        where the RAW-op guard stops being dead code.
        """
        from astral.session import Session

        client = await connect_websocket(self.ws_endpoint, subprotocols=(SUBPROTOCOL_JSON,))
        session = await Session.over(client, endpoint=self.ws_endpoint)
        try:
            self.assertIsNotNone(session.host_id)
            self.assertFalse(session.supports_raw_stream)
            self.assertTrue(session.host_alias)
        finally:
            await session.aclose()

    @bounded(20)
    async def test_the_node_answers_a_ping_with_a_pong(self):
        client = await connect_websocket(self.ws_endpoint)
        try:
            await client.ping(b"astral")
            # The greeting is written before the pong and arrives as several
            # frames, so the pong is behind them. Bounded: a node that never
            # answers a ping fails this test rather than hanging the suite.
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(3):
                    while client.last_pong is None:
                        await client.receive()
            self.assertEqual(client.last_pong, b"astral")
        finally:
            await client.aclose()

    @bounded(20)
    async def test_an_unknown_path_is_refused_with_a_status(self):
        """The upgrade lives at `/.ws` alone; every other path is the query
        handler, which answers 401 without a token."""
        endpoint = self.ws_endpoint.rsplit("/", 1)[0] + "/not-the-upgrade"
        with self.assertRaises(TransportError) as caught:
            await connect_websocket(endpoint, timeout=3)
        self.assertIn("401", str(caught.exception))


# --- small helpers --------------------------------------------------------


def _b64(text: str) -> bytes:
    return base64.b64decode(text)


def _peer_conn(peer: MemTransport) -> WSConn:
    """A `WSConn` reading the frames a client wrote into a memory pair.

    The mock's frame reader over an in-memory peer: one parser for the socket
    tests and the memory tests alike.
    """
    return _MemConn(peer)


class _MemConn(WSConn):
    """`WSConn` over a `MemTransport` rather than an `asyncio` stream pair."""

    __slots__ = ("_transport",)

    def __init__(self, transport: MemTransport) -> None:
        self._transport = transport
        self.received = []

    async def recv_frame(self):  # type: ignore[override]
        head = await self._transport.readexactly(2)
        fin = bool(head[0] & 0x80)
        opcode = head[0] & 0x0F
        masked = bool(head[1] & 0x80)
        size = head[1] & 0x7F
        if size == 126:
            size = int.from_bytes(await self._transport.readexactly(2), "big")
        elif size == 127:
            size = int.from_bytes(await self._transport.readexactly(8), "big")
        key = await self._transport.readexactly(4) if masked else b""
        raw = await self._transport.readexactly(size) if size else b""
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(raw)) if masked else raw
        from mock_web import ClientFrame

        frame = ClientFrame(fin, opcode, payload, masked, key)
        self.received.append(frame)
        return frame

    async def send(self, data: bytes) -> None:  # type: ignore[override]
        self._transport.write(data)


def peer_sent(client: WebSocketClient) -> bytes:
    """The bytes of the client's last `write()`, whole."""
    transport = client.transport
    assert isinstance(transport, MemTransport)
    return transport.writes[-1]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
