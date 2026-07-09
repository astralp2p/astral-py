"""End-to-end tests for the ``dir`` protocol helper.

Exercises the streaming/single/untyped ops on the native binary transport (the
target transport) — ``filters`` (a stream of ``string8`` names -> list),
``apply_filters`` (a single ``bool``, pinning the exact query string so a
regression back to the astral-go ``dir.set_alias`` bug is caught), ``alias_map``
(untyped: raw bytes over binary), and ``set_alias("")`` forwarding the empty
alias arg — plus a JSON/ws parity test for ``alias_map`` (the ``Aliases`` dict).
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
from astral.objects import AstralObject, ack, eos
from astral.transport.binary import BinaryChannel
from astral.transport.websocket import WebSocketClient

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
ALIAS_MAP_BYTES = b"\x00\x01alias-map-payload"
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ======================================================================
# Binary transport (the primary/target transport)
# ======================================================================
class DirMockNode:
    """A minimal binary apphost server tailored to the dir ops."""

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
                ch.send(AuthSuccessMsg(GuestID=ID_A))
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

        if op == "dir.filters":
            ch.send(AstralObject("string8", "local"))
            ch.send(AstralObject("string8", "friends"))
            ch.send(eos())
        elif op == "dir.apply_filters":
            # true only when the "friends" filter is among those requested
            match = "friends" in rq.Query
            ch.send(AstralObject("bool", match))
            ch.send(eos())
        elif op == "dir.alias_map":
            # mod.dir.alias_map is unregistered, so it comes back as raw bytes.
            ch.send(AstralObject("mod.dir.alias_map", ALIAS_MAP_BYTES))
            ch.send(eos())
        elif op == "dir.set_alias":
            ch.send(ack())
            ch.send(eos())
        else:
            ch.send(eos())


class DirBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = DirMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def connect(self):
        return astral.connect(self.node.endpoint)

    # -- filters ------------------------------------------------------------
    def test_filters_streams_to_list_of_names(self):
        with self.connect() as c:
            names = c.dir.filters()
        self.assertEqual(names, ["local", "friends"])
        self.assertIn("dir.filters", self.node.seen)

    # -- apply_filters ------------------------------------------------------
    def test_apply_filters_true_and_pins_query_string(self):
        with self.connect() as c:
            matched = c.dir.apply_filters(["local", "friends"], ID_A)
        self.assertIs(matched, True)
        # CRITICAL: the op string must be dir.apply_filters (not dir.set_alias,
        # the astral-go client's confirmed bug). Pin the exact wire query string.
        self.assertIn(
            f"dir.apply_filters?filters=local%2Cfriends&id={ID_A}", self.node.seen
        )

    def test_apply_filters_false(self):
        with self.connect() as c:
            matched = c.dir.apply_filters("local")
        self.assertIs(matched, False)
        self.assertIn("dir.apply_filters?filters=local", self.node.seen)

    def test_apply_filters_string_passthrough(self):
        with self.connect() as c:
            c.dir.apply_filters("local,friends")
        self.assertIn("dir.apply_filters?filters=local%2Cfriends", self.node.seen)

    # -- alias_map (untyped) ------------------------------------------------
    def test_alias_map_returns_raw_bytes_over_binary(self):
        with self.connect() as c:
            val = c.dir.alias_map()
        self.assertEqual(val, ALIAS_MAP_BYTES)
        self.assertIn("dir.alias_map", self.node.seen)

    # -- set_alias ----------------------------------------------------------
    def test_set_alias_empty_string_is_forwarded(self):
        # alias="" REMOVES the alias: the empty string is forwarded as the arg
        # (None would omit it). Pin the exact wire query string.
        with self.connect() as c:
            self.assertIsNone(c.dir.set_alias(ID_A, ""))
        self.assertIn(f"dir.set_alias?id={ID_A}&alias=", self.node.seen)

    def test_set_alias_none_omits_the_arg(self):
        with self.connect() as c:
            c.dir.set_alias(ID_A)
        self.assertIn(f"dir.set_alias?id={ID_A}", self.node.seen)


# ======================================================================
# JSON / WebSocket parity for alias_map (the untyped map field)
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


class DirWsMock:
    """A minimal JSON/ws apphost server for the transport-dependent alias_map op."""

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
            if op == "dir.alias_map":
                _ws_send(conn, {"Type": "mod.dir.alias_map",
                                "Object": {"Aliases": {"alice": ID_A}}})
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


class DirJsonParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = DirWsMock()
        cls.ws.start()

    @classmethod
    def tearDownClass(cls):
        cls.ws.stop()

    def test_alias_map_returns_aliases_dict_over_json(self):
        with astral.connect(self.ws.url) as c:
            aliases = c.dir.alias_map()
        # Over JSON the value is {"Aliases": {...}}; the helper unwraps to the
        # inner Aliases dict.
        self.assertEqual(aliases, {"alice": ID_A})


if __name__ == "__main__":
    unittest.main()
