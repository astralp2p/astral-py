"""End-to-end tests for the ``ip`` protocol helper.

Exercises the three ops on the native binary transport — where
``mod.ip.ip_address`` is a bare ``bytes8`` (a uint8 length prefix + 4/16 address
bytes) and the client returns a clean IP string — and adds a JSON/ws-parity test
where the envelope ``Object`` is already the IP string.
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
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, eos
from astral.transport.binary import BinaryChannel
from astral.transport.websocket import WebSocketClient

HOST_ID = "02" + "ab" * 32
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

GATEWAY = "192.168.1.1"
LOCAL_ADDRS = ["192.168.1.42", "10.0.0.5"]
PUBLIC_ADDRS = ["203.0.113.7"]


def _ip_object(ip):
    """A ``mod.ip.ip_address`` object as it arrives over the binary channel: the
    bare ``bytes8`` payload (uint8 length prefix + the packed IPv4 bytes)."""
    packed = socket.inet_aton(ip)
    return AstralObject("mod.ip.ip_address", bytes([len(packed)]) + packed)


# ======================================================================
# Binary transport (the primary/target transport)
# ======================================================================
class IpMockNode:
    """A minimal binary apphost server tailored to the ip ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received

    @property
    def endpoint(self):
        return f"tcp:127.0.0.1:{self.port}"

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        ch = BinaryChannel(conn)
        try:
            ch.send(HostInfoMsg(Identity=HOST_ID, Alias="mock"))
            first = ch.recv()
            if isinstance(first, AuthTokenMsg):
                ch.send(AuthSuccessMsg(GuestID=HOST_ID))
                first = ch.recv()
            if isinstance(first, RouteQueryMsg):
                self._query(ch, first)
            else:
                ch.send(ErrorMsg(Code="protocol_error"))
        except Exception:
            pass
        finally:
            ch.close()

    def _query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        self.seen.append(rq.Query)
        ch.send(QueryAcceptedMsg())

        if op == "ip.default_gateway":
            ch.send(_ip_object(GATEWAY))
            ch.send(eos())
        elif op == "ip.local_addrs":
            for ip in LOCAL_ADDRS:
                ch.send(_ip_object(ip))
            ch.send(eos())
        elif op == "ip.public_ip_candidates":
            for ip in PUBLIC_ADDRS:
                ch.send(_ip_object(ip))
            ch.send(eos())
        else:
            ch.send(eos())


class IpBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = IpMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_default_gateway_returns_ip_string(self):
        with self.connect() as c:
            gw = c.ip.default_gateway()
        self.assertEqual(gw, GATEWAY)
        self.assertIsInstance(gw, str)
        self.assertIn("ip.default_gateway", self.node.seen)

    def test_local_addrs_returns_ip_string_list(self):
        with self.connect() as c:
            addrs = c.ip.local_addrs()
        self.assertEqual(addrs, LOCAL_ADDRS)
        self.assertTrue(all(isinstance(a, str) for a in addrs))
        self.assertIn("ip.local_addrs", self.node.seen)

    def test_public_ip_candidates_returns_ip_string_list(self):
        with self.connect() as c:
            addrs = c.ip.public_ip_candidates()
        self.assertEqual(addrs, PUBLIC_ADDRS)
        self.assertTrue(all(isinstance(a, str) for a in addrs))
        self.assertIn("ip.public_ip_candidates", self.node.seen)


# ======================================================================
# JSON / WebSocket parity (the Object envelope is already the IP string)
# ======================================================================
def _ws_send(sock, obj):
    """Send one server->client JSON text frame (unmasked)."""
    payload = json.dumps(obj).encode("utf-8")
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


class IpWsMock:
    """A minimal JSON/ws apphost server for the ip ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    @property
    def url(self):
        return f"ws://127.0.0.1:{self.port}/.ws"

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self):
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
        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
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
            _ws_send(conn, {"Type": "mod.apphost.host_info_msg",
                            "Object": {"Identity": HOST_ID, "Alias": "mock"}})
            msg = json.loads(ws.recv_text())
            if msg["Type"] != "mod.apphost.route_query_msg":
                return
            op = msg["Object"]["Query"].split("?", 1)[0]
            _ws_send(conn, {"Type": "mod.apphost.query_accepted_msg", "Object": None})
            if op == "ip.default_gateway":
                _ws_send(conn, {"Type": "mod.ip.ip_address", "Object": GATEWAY})
                _ws_send(conn, {"Type": "eos", "Object": None})
            elif op == "ip.local_addrs":
                for ip in LOCAL_ADDRS:
                    _ws_send(conn, {"Type": "mod.ip.ip_address", "Object": ip})
                _ws_send(conn, {"Type": "eos", "Object": None})
            else:
                _ws_send(conn, {"Type": "eos", "Object": None})
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class IpJsonParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = IpWsMock()
        cls.ws.start()

    @classmethod
    def tearDownClass(cls):
        cls.ws.stop()

    def test_default_gateway_string_over_json(self):
        with astral.connect(self.ws.url) as c:
            gw = c.ip.default_gateway()
        self.assertEqual(gw, GATEWAY)

    def test_local_addrs_strings_over_json(self):
        with astral.connect(self.ws.url) as c:
            addrs = c.ip.local_addrs()
        self.assertEqual(addrs, LOCAL_ADDRS)


if __name__ == "__main__":
    unittest.main()
