"""Tests for the ``nodes`` protocol helper and its net-new record family.

Two layers, mirroring ``test_api_user.py``:

* **Record round-trips** — each net-new ``nodes`` record (``mod.nodes.link_info``,
  ``mod.nodes.session_info``, ``mod.nodes.endpoint_with_ttl``) is round-tripped
  over BOTH framings (binary ``write_to``/``read_from`` and JSON
  ``from_value``/``encode_json``), matching the transport-decision requirement
  that structured objects decode over binary IPC too. The endpoint fields are
  POLYMORPHIC ``("object", ENDPOINTS)`` interface values wrapping the registered
  exonet endpoint records — exercised with a real ``mod.tcp.endpoint`` over both
  framings, a ``mod.tor.endpoint`` (35-byte digest), and a nil / present ``TTL``.
  ``SessionInfo`` carries a signed ``"duration"`` ``Age``.
* **Ops over a binary MockNode** — all 7 ops. Pins the streamed list ops
  (``links`` / ``sessions`` / ``resolve_endpoints``) decoding to typed records,
  the ack ops (``add_endpoint`` / ``close_link``) and their query args (endpoint
  is a query-arg STRING, not a body object), ``new_link`` returning a single
  ``LinkInfo`` with its ``endpoint`` / ``strategies`` arg encoding, and
  ``migrate_session`` acking in the start=true manual mode.

Plus registry resolution for the three net-new types and the allowed-endpoint set.

Grounding: ``protocols/nodes/`` op + type docs, astral-go ``api/nodes/*.go`` +
``api/nodes/client/*.go``, astrald ``mod/nodes/src/op_*.go``.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.exonet import TcpEndpoint, TorEndpoint
from astral.api.nodes import (
    ENDPOINTS,
    EndpointWithTTL,
    LinkInfo,
    Nodes,
    SessionInfo,
)
from astral.codec import BinaryReader, BinaryWriter
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, ack, eos
from astral.registry import record_for
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
ID_B = "02" + "ef" * 32
LINK_ID = "7c1a93b50f2e4d18"
SESSION_ID = "a1b2c3d4e5f60718"

# A real registered exonet endpoint, wrapped as a polymorphic ("object", …) value.
TCP_EP = AstralObject("mod.tcp.endpoint", TcpEndpoint.from_value("1.2.3.4:1791"))
LOCAL_EP = AstralObject("mod.tcp.endpoint", TcpEndpoint.from_value("10.0.0.5:1791"))
# A 35-byte tor digest -> valid 56-char base32 onion address.
TOR_EP = AstralObject("mod.tor.endpoint", TorEndpoint(digest=bytes(range(35)), port=1791))


def _binary_roundtrip(record):
    """Encode ``record`` to binary and decode it back through the same class."""
    writer = BinaryWriter()
    record.write_to(writer)
    return type(record).read_from(BinaryReader(writer.getvalue()))


def _json_roundtrip(record):
    """Encode ``record`` to its JSON value form and decode it back."""
    return type(record).from_value(record.encode_json())


def _link_info(**over):
    base = dict(
        id=LINK_ID,
        local_identity=HOST_ID,
        remote_identity=ID_A,
        local_endpoint=LOCAL_EP,
        remote_endpoint=TCP_EP,
        outbound=True,
        network="tcp",
        high_pressure=False,
        bytes_throughput=1024,
    )
    base.update(over)
    return LinkInfo(**base)


def _session_info(**over):
    base = dict(
        id=SESSION_ID,
        link_id=LINK_ID,
        remote_identity=ID_A,
        outbound=True,
        query="objects.get",
        bytes=4096,
        age=12_000_000_000,  # 12 seconds in ns (docs example)
    )
    base.update(over)
    return SessionInfo(**base)


# ======================================================================
# Registry
# ======================================================================
class NodesRegistryTest(unittest.TestCase):
    def test_records_registered(self):
        self.assertIs(record_for("mod.nodes.link_info"), LinkInfo)
        self.assertIs(record_for("mod.nodes.session_info"), SessionInfo)
        self.assertIs(record_for("mod.nodes.endpoint_with_ttl"), EndpointWithTTL)

    def test_allowed_endpoint_types(self):
        self.assertEqual(
            ENDPOINTS,
            {"mod.tcp.endpoint", "mod.tor.endpoint", "mod.gateway.endpoint"},
        )
        # Every allowed type must be registered (so the ("object",) read can bound).
        for t in ENDPOINTS:
            self.assertIsNotNone(record_for(t), t)


# ======================================================================
# Record round-trips (binary + JSON)
# ======================================================================
class LinkInfoRecordTest(unittest.TestCase):
    def test_binary_roundtrip_with_tcp_endpoint(self):
        li = _link_info()
        got = _binary_roundtrip(li)
        self.assertEqual(got, li)
        # The polymorphic endpoint decoded to a typed TcpEndpoint inside an AstralObject.
        self.assertIsInstance(got.remote_endpoint, AstralObject)
        self.assertEqual(got.remote_endpoint.type, "mod.tcp.endpoint")
        self.assertIsInstance(got.remote_endpoint.value, TcpEndpoint)
        self.assertEqual(got.remote_endpoint.value.address, "1.2.3.4:1791")

    def test_json_roundtrip_with_tcp_endpoint(self):
        li = _link_info()
        self.assertEqual(_json_roundtrip(li), li)

    def test_json_endpoint_adapter_shape_is_type_and_address(self):
        # astral-go JSONAdapter: {"Type": <type>, "Object": <bare address str>}.
        j = _link_info().encode_json()
        self.assertEqual(
            j["RemoteEndpoint"], {"Type": "mod.tcp.endpoint", "Object": "1.2.3.4:1791"}
        )
        self.assertEqual(
            j["LocalEndpoint"], {"Type": "mod.tcp.endpoint", "Object": "10.0.0.5:1791"}
        )

    def test_binary_field_order(self):
        # nonce64(ID) ++ identity(Local) ++ identity(Remote) ++ object(LocalEndpoint)
        # ++ object(RemoteEndpoint) ++ bool(Outbound) ++ string8(Network)
        # ++ bool(HighPressure) ++ uint64(BytesThroughput).
        li = _link_info()
        w = BinaryWriter()
        w.nonce(LINK_ID)
        w.identity(HOST_ID)
        w.identity(ID_A)
        w.string8("mod.tcp.endpoint")
        LOCAL_EP.value.write_to(w)
        w.string8("mod.tcp.endpoint")
        TCP_EP.value.write_to(w)
        w.boolean(True)
        w.string8("tcp")
        w.boolean(False)
        w.u64(1024)
        self.assertEqual(li.encode_binary(), w.getvalue())

    def test_nil_endpoints_binary_roundtrip(self):
        li = _link_info(local_endpoint=None, remote_endpoint=None)
        got = _binary_roundtrip(li)
        self.assertEqual(got, li)
        self.assertIsNone(got.local_endpoint)
        self.assertIsNone(got.remote_endpoint)

    def test_tor_endpoint_binary_and_json_roundtrip(self):
        li = _link_info(remote_endpoint=TOR_EP, network="tor")
        self.assertEqual(_binary_roundtrip(li), li)
        self.assertEqual(_json_roundtrip(li), li)


class SessionInfoRecordTest(unittest.TestCase):
    def test_binary_roundtrip_with_duration_age(self):
        si = _session_info()
        got = _binary_roundtrip(si)
        self.assertEqual(got, si)
        self.assertEqual(got.age, 12_000_000_000)

    def test_json_roundtrip_with_duration_age(self):
        si = _session_info()
        self.assertEqual(_json_roundtrip(si), si)
        self.assertEqual(si.encode_json()["Age"], 12_000_000_000)

    def test_negative_age_roundtrips_signed(self):
        # astral.Duration is a SIGNED int64; a negative Age must survive binary.
        si = _session_info(age=-5)
        self.assertEqual(_binary_roundtrip(si), si)

    def test_binary_field_order(self):
        # nonce64(ID) ++ nonce64(LinkID) ++ identity(Remote) ++ bool(Outbound)
        # ++ string16(Query) ++ uint64(Bytes) ++ duration(Age).
        si = _session_info()
        w = BinaryWriter()
        w.nonce(SESSION_ID)
        w.nonce(LINK_ID)
        w.identity(ID_A)
        w.boolean(True)
        w.string16("objects.get")
        w.u64(4096)
        w.i64(12_000_000_000)
        self.assertEqual(si.encode_binary(), w.getvalue())


class EndpointWithTTLRecordTest(unittest.TestCase):
    def test_present_ttl_binary_and_json_roundtrip(self):
        ewt = EndpointWithTTL(endpoint=TCP_EP, ttl=7_776_000)
        self.assertEqual(_binary_roundtrip(ewt), ewt)
        self.assertEqual(_json_roundtrip(ewt), ewt)
        self.assertEqual(
            ewt.encode_json(),
            {
                "Endpoint": {"Type": "mod.tcp.endpoint", "Object": "1.2.3.4:1791"},
                "TTL": 7_776_000,
            },
        )

    def test_nil_ttl_binary_and_json_roundtrip(self):
        ewt = EndpointWithTTL(endpoint=TOR_EP, ttl=None)
        got_bin = _binary_roundtrip(ewt)
        self.assertEqual(got_bin, ewt)
        self.assertIsNone(got_bin.ttl)
        self.assertEqual(_json_roundtrip(ewt), ewt)
        self.assertIsNone(ewt.encode_json()["TTL"])

    def test_nil_ttl_binary_layout(self):
        # object(tcp) ++ ptr-nil(TTL == 0x00).
        ewt = EndpointWithTTL(endpoint=TCP_EP, ttl=None)
        w = BinaryWriter()
        w.string8("mod.tcp.endpoint")
        TCP_EP.value.write_to(w)
        w.u8(0)  # ptr nil flag
        self.assertEqual(ewt.encode_binary(), w.getvalue())

    def test_present_ttl_binary_layout(self):
        # object(tcp) ++ ptr(0x01 ++ uint32(TTL)).
        ewt = EndpointWithTTL(endpoint=TCP_EP, ttl=90)
        w = BinaryWriter()
        w.string8("mod.tcp.endpoint")
        TCP_EP.value.write_to(w)
        w.u8(1)
        w.u32(90)
        self.assertEqual(ewt.encode_binary(), w.getvalue())


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
class NodesMockNode:
    """A minimal binary apphost server tailored to the 7 nodes ops."""

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

        if op == "nodes.links":
            ch.send(AstralObject("mod.nodes.link_info", _link_info().encode_binary()))
            ch.send(
                AstralObject(
                    "mod.nodes.link_info",
                    _link_info(id="3e7d2c1b9a40f582", remote_identity=ID_B).encode_binary(),
                )
            )
            ch.send(eos())

        elif op == "nodes.sessions":
            ch.send(
                AstralObject("mod.nodes.session_info", _session_info().encode_binary())
            )
            ch.send(eos())

        elif op == "nodes.resolve_endpoints":
            ch.send(
                AstralObject(
                    "mod.nodes.endpoint_with_ttl",
                    EndpointWithTTL(endpoint=TCP_EP, ttl=7_776_000).encode_binary(),
                )
            )
            ch.send(
                AstralObject(
                    "mod.nodes.endpoint_with_ttl",
                    EndpointWithTTL(endpoint=TOR_EP, ttl=None).encode_binary(),
                )
            )
            ch.send(eos())

        elif op == "nodes.add_endpoint" or op == "nodes.close_link":
            ch.send(ack())
            ch.send(eos())

        elif op == "nodes.new_link":
            ch.send(
                AstralObject(
                    "mod.nodes.link_info",
                    _link_info(bytes_throughput=0).encode_binary(),
                )
            )
            # op_new_link sends a single link_info then closes (no explicit eos).

        elif op == "nodes.migrate_session":
            ch.send(ack())
            ch.send(eos())

        else:
            ch.send(eos())


class NodesOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = NodesMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_nodes_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.nodes, Nodes)
            self.assertIs(c.nodes, c.nodes)  # lazily cached

    def test_links_streams_typed_link_infos(self):
        with self.connect() as c:
            links = c.nodes.links()
        self.assertEqual(len(links), 2)
        self.assertTrue(all(isinstance(li, LinkInfo) for li in links))
        self.assertEqual(links[0], _link_info())
        self.assertEqual(links[0].remote_endpoint.value.address, "1.2.3.4:1791")
        self.assertEqual(links[1].remote_identity, ID_B)
        self.assertIn("nodes.links", self.node.seen)

    def test_sessions_streams_typed_session_infos(self):
        with self.connect() as c:
            sessions = c.nodes.sessions()
        self.assertEqual(len(sessions), 1)
        self.assertIsInstance(sessions[0], SessionInfo)
        self.assertEqual(sessions[0], _session_info())
        self.assertEqual(sessions[0].age, 12_000_000_000)
        self.assertIn("nodes.sessions", self.node.seen)

    def test_resolve_endpoints_streams_endpoint_with_ttl(self):
        with self.connect() as c:
            eps = c.nodes.resolve_endpoints(ID_A)
        self.assertEqual(len(eps), 2)
        self.assertTrue(all(isinstance(e, EndpointWithTTL) for e in eps))
        self.assertEqual(eps[0].ttl, 7_776_000)
        self.assertEqual(eps[0].endpoint.value.address, "1.2.3.4:1791")
        self.assertIsNone(eps[1].ttl)  # nil TTL survives
        self.assertEqual(eps[1].endpoint.type, "mod.tor.endpoint")
        self.assertIn(f"nodes.resolve_endpoints?id={ID_A}", self.node.seen)

    def test_add_endpoint_acks_and_pins_args(self):
        with self.connect() as c:
            self.assertIsNone(c.nodes.add_endpoint(ID_A, "tcp:1.2.3.4:1791"))
        q = self.node.seen[-1]
        self.assertTrue(q.startswith("nodes.add_endpoint?"))
        self.assertIn(f"id={ID_A}", q)
        # The endpoint is a query-arg STRING (":" percent-encoded on the wire).
        self.assertIn("endpoint=tcp", q)

    def test_close_link_acks_and_pins_id(self):
        with self.connect() as c:
            self.assertIsNone(c.nodes.close_link(LINK_ID))
        self.assertIn(f"nodes.close_link?id={LINK_ID}", self.node.seen)

    def test_new_link_returns_single_link_info(self):
        with self.connect() as c:
            link = c.nodes.new_link(ID_A)
        self.assertIsInstance(link, LinkInfo)
        self.assertEqual(link.bytes_throughput, 0)
        self.assertEqual(link.remote_endpoint.value.address, "1.2.3.4:1791")
        self.assertIn(f"nodes.new_link?target={ID_A}", self.node.seen)

    def test_new_link_with_endpoint_arg(self):
        with self.connect() as c:
            c.nodes.new_link(ID_A, endpoint="tcp:1.2.3.4:1791")
        q = self.node.seen[-1]
        self.assertTrue(q.startswith("nodes.new_link?"))
        self.assertIn(f"target={ID_A}", q)
        self.assertIn("endpoint=tcp", q)

    def test_new_link_with_strategies_list_joined(self):
        with self.connect() as c:
            c.nodes.new_link(ID_A, strategies=["basic", "tor", "nat"])
        q = self.node.seen[-1]
        # A Python list is joined into the comma-separated wire form.
        self.assertIn("strategies=basic", q)
        self.assertIn("tor", q)
        self.assertIn("nat", q)

    def test_new_link_with_strategies_string(self):
        with self.connect() as c:
            c.nodes.new_link(ID_A, strategies="basic,tor")
        self.assertIn("strategies=basic", self.node.seen[-1])

    def test_migrate_session_start_true_acks(self):
        with self.connect() as c:
            self.assertIsNone(c.nodes.migrate_session(SESSION_ID, LINK_ID))
        q = self.node.seen[-1]
        self.assertTrue(q.startswith("nodes.migrate_session?"))
        self.assertIn(f"session_id={SESSION_ID}", q)
        self.assertIn(f"link_id={LINK_ID}", q)
        self.assertIn("start=true", q)

    def test_migrate_session_start_false_sends_arg(self):
        # start=False still forwards the arg (negotiated mode is deferred, but the
        # arg is honoured); the mock acks so the single-reply read path is fine.
        with self.connect() as c:
            c.nodes.migrate_session(SESSION_ID, LINK_ID, start=False)
        self.assertIn("start=false", self.node.seen[-1])


if __name__ == "__main__":
    unittest.main()
