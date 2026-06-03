"""End-to-end tests over a mock binary apphost node.

A small in-process server speaks the binary channel protocol so the full stack
(client → session → binary channel → stream, and the serving path) is exercised
without a live astrald node.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.messages import (
    AttachQueryMsg,
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    QueryAcceptedMsg,
    QueryRejectedMsg,
    RegisterServiceMsg,
    RejectIncomingMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, ack, eos
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
GUEST_ID = "03" + "cd" * 32
TOKEN = "testtoken123"

ACCEPT_QID = "1111111111111111"
REJECT_QID = "2222222222222222"


class MockNode:
    """A minimal binary apphost server for tests."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        # serving correlation
        self.incoming_script = []
        self.attach_results = {}
        self.attach_events = {}
        self.rejects = {}
        self.reject_events = {}

    @property
    def endpoint(self):
        return f"tcp:127.0.0.1:{self.port}"

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

    def _handle(self, conn):
        ch = BinaryChannel(conn)
        try:
            ch.send(HostInfoMsg(Identity=HOST_ID, Alias="mock"))
            first = ch.recv()
            if isinstance(first, AuthTokenMsg):
                if first.Token == TOKEN:
                    ch.send(AuthSuccessMsg(GuestID=GUEST_ID))
                else:
                    ch.send(ErrorMsg(Code="auth_failed"))
                    return
                first = ch.recv()
            if first is None:
                return
            if isinstance(first, RouteQueryMsg):
                self._handle_query(ch, first)
            elif isinstance(first, RegisterServiceMsg):
                self._handle_register(ch, first)
            elif isinstance(first, AttachQueryMsg):
                self._handle_attach(ch, first)
            else:
                ch.send(ErrorMsg(Code="protocol_error"))
        except Exception:
            pass
        finally:
            ch.close()

    def _handle_query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        if op == "forbidden":
            ch.send(QueryRejectedMsg(Code=7))
            return
        if op == "bad":
            ch.send(ErrorMsg(Code="route_not_found"))
            return
        ch.send(QueryAcceptedMsg())
        if op in ("dir.resolve", "apphost.whoami"):
            ch.send(AstralObject("identity", HOST_ID))
            ch.send(eos())
        elif op == "ping":
            ch.send(AstralObject("string8", "pong"))
            ch.send(eos())
        elif op == "objects.read":
            ch.send_bytes(b"hello world")  # raw bytes, no framing
        elif op == "sink":
            count = 0
            while True:
                received = ch.recv()
                if received is None or (isinstance(received, AstralObject) and received.is_eos):
                    break
                count += 1
            ch.send(AstralObject("uint64", count))
            ch.send(eos())
        elif op == "fail":
            ch.send(AstralObject("error_message", "it broke"))
            ch.send(eos())
        else:
            ch.send(eos())

    def _handle_register(self, ch, rs):
        ch.send(ack())
        for qid, query in self.incoming_script:
            ch.send(
                IncomingQueryMsg(
                    QueryID=qid, Caller=GUEST_ID, Target=rs.Identity, Query=query
                )
            )
        while not self._stop:
            received = ch.recv()
            if received is None:
                break
            if isinstance(received, RejectIncomingMsg):
                self.rejects[received.QueryID] = received.Code
                event = self.reject_events.get(received.QueryID)
                if event:
                    event.set()

    def _handle_attach(self, ch, aq):
        qid = aq.QueryID
        if qid not in self.attach_events:
            ch.send(ErrorMsg(Code="route_not_found"))
            return
        ch.send(ack())
        objects = []
        while True:
            received = ch.recv()
            if received is None or (isinstance(received, AstralObject) and received.is_eos):
                break
            objects.append(received)
        self.attach_results[qid] = objects
        self.attach_events[qid].set()


class BinaryIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = MockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def connect(self, token=None):
        return astral.connect(self.node.endpoint, token=token)

    def test_handshake(self):
        with self.connect() as node:
            self.assertEqual(node.identity, HOST_ID)
            self.assertEqual(node.alias, "mock")
            self.assertEqual(node.guest_id, "")

    def test_handshake_with_token(self):
        with self.connect(token=TOKEN) as node:
            self.assertEqual(node.guest_id, GUEST_ID)

    def test_bad_token_raises(self):
        with self.assertRaises(astral.AuthError):
            self.connect(token="wrong")

    def test_simple_query(self):
        with self.connect() as node:
            self.assertEqual(node.call_one("ping"), "pong")

    def test_query_with_args(self):
        with self.connect() as node:
            self.assertEqual(node.dir.resolve("alice"), HOST_ID)

    def test_query_collect(self):
        with self.connect() as node:
            objs = node.call("ping")
            self.assertEqual(len(objs), 1)
            self.assertEqual(objs[0].type, "string8")

    def test_rejected_query(self):
        with self.connect() as node:
            with self.assertRaises(astral.QueryRejected) as ctx:
                node.call_one("forbidden")
            self.assertEqual(ctx.exception.code, 7)

    def test_error_code_query(self):
        with self.connect() as node:
            with self.assertRaises(astral.RouteNotFound):
                node.call_one("bad")

    def test_error_message_in_stream(self):
        with self.connect() as node:
            with self.assertRaises(astral.RemoteError):
                node.call_one("fail")

    def test_raw_read(self):
        with self.connect() as node:
            with node.query("objects.read", {"id": "data1abc"}) as stream:
                self.assertEqual(stream.read(), b"hello world")

    def test_input_streaming(self):
        with self.connect() as node:
            with node.query("sink") as stream:
                stream.send(astral.obj("string8", "a"))
                stream.send(astral.obj("string8", "b"))
                stream.send(astral.obj("string8", "c"))
                stream.send_eos()
                self.assertEqual(stream.value(), 3)

    def test_serving_accept_and_reject(self):
        node = self.node
        node.incoming_script = [(ACCEPT_QID, "greet"), (REJECT_QID, "forbidden")]
        node.attach_events = {ACCEPT_QID: threading.Event()}
        node.reject_events = {REJECT_QID: threading.Event()}
        node.attach_results = {}
        node.rejects = {}

        def handler(q):
            if q.query == "forbidden":
                q.reject(5)
                return
            stream = q.accept()
            stream.send(astral.obj("string8", "hi " + q.caller))
            stream.send_eos()
            stream.close()

        with self.connect(token=TOKEN) as node_client:
            reg = node_client.register(GUEST_ID, handler)
            try:
                self.assertTrue(node.attach_events[ACCEPT_QID].wait(timeout=5), "no accept")
                self.assertTrue(node.reject_events[REJECT_QID].wait(timeout=5), "no reject")
            finally:
                reg.unregister()

        results = node.attach_results[ACCEPT_QID]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].type, "string8")
        self.assertEqual(results[0].value, "hi " + GUEST_ID)
        self.assertEqual(node.rejects[REJECT_QID], 5)


if __name__ == "__main__":
    unittest.main()
