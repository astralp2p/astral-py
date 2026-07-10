"""Tests for the ``nat`` protocol helper and its records.

UNDOCUMENTED protocol — grounded ONLY in astral-go
(``api/nat/{module.go,hole.go,endpoint.go,client/list_holes.go}``) and NOT
verified against a live node. Two layers, mirroring ``test_api_user.py`` /
``test_api_exonet.py``:

* **Record round-trips** — :class:`NatEndpoint` and :class:`Hole` (which nests two
  endpoints inline) are round-tripped over BOTH framings (binary
  ``write_to``/``read_from`` and JSON ``from_value``/``encode_json``), with a
  byte-pin on the endpoint's ``structValue`` and on the hole's field order. This
  pins the two modelling calls the task hinged on: the endpoint fields are INLINED
  ``("record", NatEndpoint)`` (no ``("object",)`` type tag), and the type strings
  are the bare ``nat.hole`` / ``nat.endpoint`` (NOT the ``mod.*`` form).
* **Ops over a binary MockNode** — ``list_holes`` (default + ``with_`` filter),
  proving a streamed ``nat.hole`` decodes to a typed :class:`Hole` over binary.

Plus registry resolution for both net-new types.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.nat import Hole, Nat, NatEndpoint
from astral.codec import BinaryReader, BinaryWriter
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, eos
from astral.registry import record_for
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
ID_B = "02" + "ef" * 32
NONCE = "0011223344556677"


def _binary_roundtrip(record):
    return type(record).read_from(BinaryReader(record.encode_binary()))


def _json_roundtrip(record):
    return type(record).from_value(record.encode_json())


def _endpoint(ip="192.168.1.1", port=41000):
    return NatEndpoint(ip=socket.inet_pton(socket.AF_INET, ip), port=port)


def _hole():
    return Hole(
        nonce=NONCE,
        active_identity=ID_A,
        active_endpoint=_endpoint("192.168.1.1", 41000),
        passive_identity=ID_B,
        passive_endpoint=_endpoint("10.0.0.5", 51000),
        created_at=1750320000,
    )


# ======================================================================
# NatEndpoint record round-trips (binary + JSON)
# ======================================================================
class NatEndpointRecordTest(unittest.TestCase):
    def test_binary_pin(self):
        # structValue: IP as bytes8 (uint8 len=4 ++ 4 IPv4 bytes) ++ Port uint16.
        ep = _endpoint("192.168.1.1", 8080)
        expected = bytes([4]) + b"\xc0\xa8\x01\x01" + (8080).to_bytes(2, "big")
        self.assertEqual(ep.encode_binary(), expected)

    def test_binary_roundtrip(self):
        ep = _endpoint()
        self.assertEqual(_binary_roundtrip(ep), ep)

    def test_address_string(self):
        self.assertEqual(_endpoint("192.168.1.1", 8080).address, "192.168.1.1:8080")

    def test_json_is_address_string(self):
        self.assertEqual(_endpoint("192.168.1.1", 8080).encode_json(), "192.168.1.1:8080")

    def test_json_roundtrip_from_string(self):
        ep = _endpoint()
        self.assertEqual(_json_roundtrip(ep), ep)

    def test_ipv6_address_bracketed_and_roundtrips(self):
        raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ep = NatEndpoint(ip=raw, port=443)
        self.assertEqual(ep.address, "[2001:db8::1]:443")
        self.assertEqual(_json_roundtrip(ep), ep)
        self.assertEqual(_binary_roundtrip(ep), ep)


# ======================================================================
# Hole record round-trips (binary + JSON), incl. nested endpoints
# ======================================================================
class HoleRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        h = _hole()
        got = _binary_roundtrip(h)
        self.assertEqual(got, h)
        self.assertIsInstance(got.active_endpoint, NatEndpoint)
        self.assertIsInstance(got.passive_endpoint, NatEndpoint)
        self.assertEqual(got.active_endpoint.address, "192.168.1.1:41000")
        self.assertEqual(got.passive_endpoint.address, "10.0.0.5:51000")

    def test_binary_field_order(self):
        # nonce64(Nonce) ++ identity(ActiveIdentity) ++ record(ActiveEndpoint,
        # INLINED, no type tag) ++ identity(PassiveIdentity) ++ record(PassiveEndpoint)
        # ++ time(uint64 CreatedAt).
        h = _hole()
        writer = BinaryWriter()
        writer.nonce(NONCE)
        writer.identity(ID_A)
        h.active_endpoint.write_to(writer)
        writer.identity(ID_B)
        h.passive_endpoint.write_to(writer)
        writer.u64(1750320000)
        self.assertEqual(h.encode_binary(), writer.getvalue())

    def test_endpoints_have_no_object_type_tag(self):
        # The inlined endpoint is a structValue with NO string8(type) prefix — pin
        # that the encoding does NOT start the endpoint with its type name (which the
        # rejected ("object",) modelling would have added).
        raw = _hole().encode_binary()
        self.assertNotIn(b"nat.endpoint", raw)

    def test_json_roundtrip(self):
        h = _hole()
        back = _json_roundtrip(h)
        self.assertEqual(back, h)
        self.assertIsInstance(back.active_endpoint, NatEndpoint)

    def test_json_keys_are_pascalcase(self):
        value = _hole().encode_json()
        self.assertEqual(
            set(value),
            {
                "Nonce",
                "ActiveIdentity",
                "ActiveEndpoint",
                "PassiveIdentity",
                "PassiveEndpoint",
                "CreatedAt",
            },
        )
        # Nested endpoints marshal to their bare address strings.
        self.assertEqual(value["ActiveEndpoint"], "192.168.1.1:41000")
        self.assertEqual(value["PassiveEndpoint"], "10.0.0.5:51000")


# ======================================================================
# Registry resolution
# ======================================================================
class RegistryTest(unittest.TestCase):
    def test_types_resolve_by_bare_nat_string(self):
        # VERIFIED against the Go source: bare "nat.hole" / "nat.endpoint", NOT
        # the "mod.nat.*" form the task brief guessed.
        self.assertIs(record_for("nat.hole"), Hole)
        self.assertIs(record_for("nat.endpoint"), NatEndpoint)
        self.assertEqual(Hole.TYPE, "nat.hole")
        self.assertEqual(NatEndpoint.TYPE, "nat.endpoint")


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
class NatMockNode:
    """A minimal binary apphost server tailored to nat.list_holes."""

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

        if op == "nat.list_holes":
            for h in (
                Hole(
                    nonce=NONCE,
                    active_identity=ID_A,
                    active_endpoint=_endpoint("192.168.1.1", 41000),
                    passive_identity=ID_B,
                    passive_endpoint=_endpoint("10.0.0.5", 51000),
                    created_at=1750320000,
                ),
                Hole(
                    nonce="8899aabbccddeeff",
                    active_identity=ID_B,
                    active_endpoint=_endpoint("172.16.0.9", 42000),
                    passive_identity=ID_A,
                    passive_endpoint=_endpoint("203.0.113.7", 52000),
                    created_at=1750320123,
                ),
            ):
                ch.send(AstralObject("nat.hole", h.encode_binary()))
            ch.send(eos())
        else:
            ch.send(eos())


class NatOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = NatMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_nat_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.nat, Nat)
            self.assertIs(c.nat, c.nat)  # lazily cached

    def test_list_holes_streams_typed_holes(self):
        with self.connect() as c:
            holes = c.nat.list_holes()
        self.assertEqual(len(holes), 2)
        self.assertTrue(all(isinstance(h, Hole) for h in holes))
        self.assertEqual(holes[0].nonce, NONCE)
        self.assertEqual(holes[0].active_identity, ID_A)
        self.assertEqual(holes[0].passive_identity, ID_B)
        self.assertIsInstance(holes[0].active_endpoint, NatEndpoint)
        self.assertEqual(holes[0].active_endpoint.address, "192.168.1.1:41000")
        self.assertEqual(holes[0].passive_endpoint.address, "10.0.0.5:51000")
        self.assertEqual(holes[1].nonce, "8899aabbccddeeff")
        # Default (no filter) sends NO "with" arg.
        self.assertIn("nat.list_holes", self.node.seen)
        self.assertNotIn("nat.list_holes?with=", self.node.seen[-1])

    def test_list_holes_passes_with_filter(self):
        with self.connect() as c:
            holes = c.nat.list_holes(with_=ID_A)
        self.assertEqual(len(holes), 2)
        self.assertIn(f"nat.list_holes?with={ID_A}", self.node.seen)

    def test_list_holes_empty_with_still_sends_arg(self):
        # with_="" is not None, so the arg is sent (empty value) — the None case is
        # the only one that omits it entirely.
        with self.connect() as c:
            c.nat.list_holes(with_="")
        self.assertIn("nat.list_holes?with=", self.node.seen[-1])


if __name__ == "__main__":
    unittest.main()
