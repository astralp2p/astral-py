"""End-to-end tests for the full apphost protocol helper.

Exercises all 13 ops on the native binary transport (the target transport) —
record decode over binary (list_tokens -> AccessToken, list_held_objects ->
ObjectID), arg wiring, ack/error paths, the bind body-send — and adds JSON/ws
parity tests for the transport-dependent Path-A app-contract ops (dict over JSON).
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
from astral.api.apphost import AccessToken
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objectid import ObjectID
from astral.objects import AstralObject, ack, eos
from astral.transport.binary import BinaryChannel
from astral.transport.websocket import WebSocketClient

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
BIND_TOKEN = "00112233aabbccdd"  # 16-hex nonce64
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ======================================================================
# Binary transport (the primary/target transport)
# ======================================================================
class ApphostMockNode:
    """A minimal binary apphost server tailored to the apphost ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received
        self.bind_token = None
        self.bind_event = threading.Event()
        self.signed_input = None

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

    def _token(self, ident, tok, exp):
        return AstralObject(
            "apphost.access_token",
            AccessToken(identity=ident, token=tok, expires_at=exp).encode_binary(),
        )

    def _query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        self.seen.append(rq.Query)
        ch.send(QueryAcceptedMsg())

        if op == "apphost.create_token":
            ch.send(self._token(ID_A, "newtok", 300))
            ch.send(eos())
        elif op == "apphost.register":
            ch.send(self._token(ID_A, "guesttok", 400))
            ch.send(eos())
        elif op == "apphost.list_tokens":
            ch.send(self._token(HOST_ID, "tok1", 100))
            ch.send(self._token(ID_A, "tok2", 200))
            ch.send(eos())
        elif op == "apphost.list_held_objects":
            ch.send(AstralObject("object_id.sha256", ObjectID(3, bytes([3]) * 32)))
            ch.send(AstralObject("object_id.sha256", ObjectID(7, bytes([7]) * 32)))
            ch.send(eos())
        elif op == "apphost.cancel":
            if "id=missing" in rq.Query:
                ch.send(AstralObject("error_message", "query not found"))
            else:
                ch.send(ack())
            ch.send(eos())
        elif op in ("apphost.hold_object", "apphost.unhold_object"):
            ch.send(ack())
            ch.send(eos())
        elif op == "apphost.register_handler":
            if "endpoint=bad" in rq.Query:
                ch.send(AstralObject("error_message", "bad endpoint"))
            else:
                ch.send(ack())
            ch.send(eos())
        elif op == "apphost.bind":
            ch.send(ack())
            msg = ch.recv()  # the follow-up BindMsg on the same channel
            if isinstance(msg, BindMsg):
                self.bind_token = msg.Token
            self.bind_event.set()
            while ch.recv() is not None:  # hold the binding open until client closes
                pass
        elif op == "apphost.new_app_contract":
            ch.send(AstralObject("mod.auth.contract", b"\x01\x02contract"))
            ch.send(eos())
        elif op == "apphost.install_app":
            ch.send(AstralObject("mod.auth.signed_contract", b"\x05\x06signed"))
            ch.send(eos())
        elif op == "apphost.sign_app_contract":
            # The client sends exactly one contract object on the body (no eos,
            # matching the astral-go client); we read it, then reply.
            self.signed_input = ch.recv()
            ch.send(AstralObject("mod.auth.signed_contract", b"\x03\x04signed"))
            ch.send(eos())
        else:
            ch.send(eos())


class ApphostBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = ApphostMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def connect(self):
        return astral.connect(self.node.endpoint)

    def _seen(self, predicate):
        return any(predicate(s) for s in self.node.seen)

    # -- tokens -------------------------------------------------------------
    def test_create_token_decodes_and_wires_args(self):
        with self.connect() as c:
            tok = c.apphost.create_token(ID_A, duration="1h")
        self.assertEqual(tok, AccessToken(identity=ID_A, token="newtok", expires_at=300))
        self.assertIn(f"apphost.create_token?id={ID_A}&duration=1h", self.node.seen)

    def test_register_decodes_single_token(self):
        with self.connect() as c:
            tok = c.apphost.register()
        self.assertEqual(tok, AccessToken(identity=ID_A, token="guesttok", expires_at=400))
        self.assertIn("apphost.register", self.node.seen)

    def test_list_tokens_decodes_records_over_binary(self):
        with self.connect() as c:
            toks = c.apphost.list_tokens()
        self.assertEqual(
            toks,
            [
                AccessToken(identity=HOST_ID, token="tok1", expires_at=100),
                AccessToken(identity=ID_A, token="tok2", expires_at=200),
            ],
        )
        self.assertTrue(all(isinstance(t, AccessToken) for t in toks))

    def test_list_tokens_passes_id_filter(self):
        with self.connect() as c:
            c.apphost.list_tokens(ID_A)
        self.assertTrue(self._seen(lambda s: s == f"apphost.list_tokens?id={ID_A}"))

    def test_list_tokens_omits_id_when_none(self):
        with self.connect() as c:
            c.apphost.list_tokens()
        self.assertIn("apphost.list_tokens", self.node.seen)

    # -- object holds -------------------------------------------------------
    def test_list_held_objects_decodes_object_ids(self):
        with self.connect() as c:
            held = c.apphost.list_held_objects()
        self.assertEqual(len(held), 2)
        self.assertTrue(all(isinstance(o, ObjectID) for o in held))
        self.assertEqual(
            [o.to_bytes() for o in held],
            [ObjectID(3, bytes([3]) * 32).to_bytes(), ObjectID(7, bytes([7]) * 32).to_bytes()],
        )

    def test_hold_and_unhold_return_none(self):
        with self.connect() as c:
            self.assertIsNone(c.apphost.hold_object("data1abc"))
            self.assertIsNone(c.apphost.unhold_object("data1abc"))
        self.assertIn("apphost.hold_object?id=data1abc", self.node.seen)
        self.assertIn("apphost.unhold_object?id=data1abc", self.node.seen)

    def test_hold_object_forwards_duration(self):
        # duration is documented but not sent by the astral-go client; astral-py
        # forwards it (a deliberate, doc-conformant divergence — pin it here).
        with self.connect() as c:
            c.apphost.hold_object("data1xyz", duration="24h")
        self.assertIn("apphost.hold_object?id=data1xyz&duration=24h", self.node.seen)

    # -- cancel -------------------------------------------------------------
    def test_cancel_ack(self):
        with self.connect() as c:
            self.assertIsNone(c.apphost.cancel("abcd", cause="stop"))
        self.assertIn("apphost.cancel?id=abcd&cause=stop", self.node.seen)

    def test_cancel_not_found_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.apphost.cancel("missing")

    # -- handler registration ----------------------------------------------
    def test_register_handler_pins_endpoint_and_token(self):
        with self.connect() as c:
            self.assertIsNone(c.apphost.register_handler("tcp:127.0.0.1:9001", BIND_TOKEN))
        self.assertIn(
            f"apphost.register_handler?endpoint=tcp%3A127.0.0.1%3A9001&token={BIND_TOKEN}",
            self.node.seen,
        )

    def test_register_handler_error_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.apphost.register_handler("bad", BIND_TOKEN)

    def test_bind_sends_bind_msg_and_holds_channel(self):
        self.node.bind_event.clear()
        self.node.bind_token = None
        with self.connect() as c:
            with c.apphost.bind(BIND_TOKEN):  # close-on-exit even if an assert fails
                self.assertTrue(self.node.bind_event.wait(timeout=5), "bind_msg not received")
                self.assertEqual(self.node.bind_token, BIND_TOKEN)

    # -- app contracts (untyped, Path A) ------------------------------------
    def test_new_app_contract_untyped_bytes_over_binary(self):
        with self.connect() as c:
            contract = c.apphost.new_app_contract(ID_A, duration="8760h")
        self.assertEqual(contract, b"\x01\x02contract")
        self.assertIn(f"apphost.new_app_contract?id={ID_A}&duration=8760h", self.node.seen)

    def test_install_app_untyped_bytes_over_binary(self):
        with self.connect() as c:
            signed = c.apphost.install_app(ID_A)
        self.assertEqual(signed, b"\x05\x06signed")

    def test_sign_app_contract_sends_body_and_returns_signed(self):
        with self.connect() as c:
            signed = c.apphost.sign_app_contract(b"mycontract")
        self.assertEqual(signed, b"\x03\x04signed")
        self.assertIsInstance(self.node.signed_input, AstralObject)
        self.assertEqual(self.node.signed_input.type, "mod.auth.contract")
        self.assertEqual(self.node.signed_input.value, b"mycontract")


# ======================================================================
# JSON / WebSocket parity for the Path-A app-contract ops
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


class ApphostWsMock:
    """A minimal JSON/ws apphost server for the transport-dependent ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.signed_input = None

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
            if op == "apphost.list_tokens":
                _ws_send(conn, {"Type": "apphost.access_token",
                                "Object": {"Identity": HOST_ID, "Token": "tok1",
                                           "ExpiresAt": "2027-01-01T00:00:00Z"}})
                _ws_send(conn, {"Type": "apphost.access_token",
                                "Object": {"Identity": ID_A, "Token": "tok2",
                                           "ExpiresAt": "2028-01-01T00:00:00Z"}})
                _ws_send(conn, {"Type": "eos", "Object": None})
            elif op == "apphost.new_app_contract":
                _ws_send(conn, {"Type": "mod.auth.contract",
                                "Object": {"Issuer": HOST_ID, "Subject": ID_A,
                                           "Permits": [], "ExpiresAt": "2027-01-01T00:00:00Z"}})
                _ws_send(conn, {"Type": "eos", "Object": None})
            elif op == "apphost.sign_app_contract":
                self.signed_input = json.loads(ws.recv_text())  # the body contract
                _ws_send(conn, {"Type": "mod.auth.signed_contract",
                                "Object": {"Contract": self.signed_input.get("Object"),
                                           "IssuerSig": "ed25519:AAA", "SubjectSig": "ed25519:BBB"}})
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


class ApphostJsonParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = ApphostWsMock()
        cls.ws.start()

    @classmethod
    def tearDownClass(cls):
        cls.ws.stop()

    def test_list_tokens_decodes_records_over_json(self):
        with astral.connect(self.ws.url) as c:
            toks = c.apphost.list_tokens()
        self.assertTrue(all(isinstance(t, AccessToken) for t in toks))
        self.assertEqual([t.identity for t in toks], [HOST_ID, ID_A])
        self.assertEqual([t.token for t in toks], ["tok1", "tok2"])
        # over JSON, expires_at is the RFC3339 string (not the binary uint64)
        self.assertEqual(toks[0].expires_at, "2027-01-01T00:00:00Z")

    def test_new_app_contract_returns_dict_over_json(self):
        with astral.connect(self.ws.url) as c:
            contract = c.apphost.new_app_contract(ID_A)
        self.assertIsInstance(contract, dict)
        self.assertEqual(contract["Issuer"], HOST_ID)
        self.assertEqual(contract["Subject"], ID_A)
        self.assertEqual(contract["Permits"], [])

    def test_sign_app_contract_dict_body_and_return_over_json(self):
        body = {"Issuer": HOST_ID, "Subject": ID_A, "Permits": [],
                "ExpiresAt": "2027-01-01T00:00:00Z"}
        with astral.connect(self.ws.url) as c:
            signed = c.apphost.sign_app_contract(body)
        self.assertIsInstance(signed, dict)
        self.assertIn("IssuerSig", signed)
        # the contract crossed the wire on the body as a mod.auth.contract object
        self.assertEqual(self.ws.signed_input["Type"], "mod.auth.contract")
        self.assertEqual(self.ws.signed_input["Object"], body)


if __name__ == "__main__":
    unittest.main()
