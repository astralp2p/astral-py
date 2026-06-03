"""WebSocket transport tests: RFC 6455 framing and a loopback handshake.

A mock WebSocket server performs the upgrade handshake and speaks the apphost
protocol in JSON envelopes, exercising :class:`WebSocketClient`,
:class:`JsonWebSocketChannel` and :class:`WebSocketTransport` end to end.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.transport.websocket import WebSocketClient

HOST_ID = "02" + "ab" * 32
GUEST_ID = "03" + "cd" * 32
TOKEN = "wstoken"
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _send_text_unmasked(sock, text):
    """Send a server→client text frame (servers must not mask)."""
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    sock.sendall(bytes(header) + payload)


class TestFraming(unittest.TestCase):
    def test_roundtrip_socketpair(self):
        a, b = socket.socketpair()
        try:
            client = WebSocketClient(a)
            server = WebSocketClient(b)
            for text in ["hello", "x" * 200, "u" * 70000, "δ ünîcode ✓"]:
                client.send_text(text)
                self.assertEqual(server.recv_text(), text)
        finally:
            a.close()
            b.close()


class MockWsServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.last_query = None

    @property
    def url(self):
        return f"ws://127.0.0.1:{self.port}/.ws"

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handshake(self, conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            buf += chunk
        key = ""
        for line in buf.decode("latin1").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()
        ).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "Sec-WebSocket-Protocol: astral.json.v1\r\n\r\n"
            ).encode()
        )
        return True

    def _handle(self, conn):
        try:
            if not self._handshake(conn):
                return
            ws = WebSocketClient(conn)
            _send_text_unmasked(
                conn,
                json.dumps(
                    {
                        "Type": "mod.apphost.host_info_msg",
                        "Object": {"Identity": HOST_ID, "Alias": "mock"},
                    }
                ),
            )
            msg = json.loads(ws.recv_text())
            if msg["Type"] == "mod.apphost.auth_token_msg":
                ok = msg["Object"]["Token"] == TOKEN
                reply = (
                    {"Type": "mod.apphost.auth_success_msg", "Object": {"GuestID": GUEST_ID}}
                    if ok
                    else {"Type": "mod.apphost.error_msg", "Object": {"Code": "auth_failed"}}
                )
                _send_text_unmasked(conn, json.dumps(reply))
                if not ok:
                    return
                msg = json.loads(ws.recv_text())
            if msg["Type"] == "mod.apphost.route_query_msg":
                self.last_query = msg["Object"]["Query"]
                _send_text_unmasked(
                    conn,
                    json.dumps({"Type": "mod.apphost.query_accepted_msg", "Object": None}),
                )
                _send_text_unmasked(conn, json.dumps({"Type": "string8", "Object": "pong"}))
                _send_text_unmasked(conn, json.dumps({"Type": "eos", "Object": None}))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class WebSocketIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockWsServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_handshake(self):
        with astral.connect(self.server.url) as node:
            self.assertEqual(node.identity, HOST_ID)
            self.assertEqual(node.alias, "mock")

    def test_auth(self):
        with astral.connect(self.server.url, token=TOKEN) as node:
            self.assertEqual(node.guest_id, GUEST_ID)

    def test_query_and_json_injection(self):
        with astral.connect(self.server.url) as node:
            self.assertEqual(node.call_one("ping"), "pong")
        self.assertIn("out=json", self.server.last_query)
        self.assertIn("in=json", self.server.last_query)


if __name__ == "__main__":
    unittest.main()
