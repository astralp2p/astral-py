"""Tests for the ``objects`` protocol helper and its net-new record family.

Two layers, mirroring ``test_api_user.py``:

* **Record round-trips** — each net-new ``objects`` record is round-tripped over
  BOTH framings (binary ``write_to``/``read_from`` and JSON
  ``from_value``/``encode_json``), matching the transport-decision requirement that
  structured objects decode over binary IPC too. Pins the ``Probe.Time``
  ``duration`` kind, the ``RepositoryInfo.Free`` ``uint64`` (source, not the doc's
  ``int64``), the ``Descriptor.Data`` polymorphic ``("object",)`` field (with a
  registered inner record over binary and a scalar over JSON), the empty
  ``CommitMsg``, the ``TypeSpec``/``FieldSpec`` array-of-records nesting, and the
  ``CreateObjectAction``/``ReadObjectAction`` flattened ``auth.Action``
  (``Nonce``+``ActorID``, the SOURCE fields, not the doc's ``CallerID``).
* **Ops over a binary MockNode** — the load/store-heavy op surface plus
  find/search/describe/contains(repo)/repositories/new_mem/scan(follow) and the
  create writer, delete, purge, probe, get_type, spec, blueprints, new,
  register_searcher keep-alive, push, echo.

Grounding: ``protocols/objects/`` op + type docs, astral-go ``api/objects/*.go`` +
``api/objects/client/*.go`` + ``api/auth/action.go``.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.objects import (
    CommitMsg,
    CreateObjectAction,
    Descriptor,
    FieldSpec,
    Objects,
    Probe,
    QueryTag,
    ReadObjectAction,
    RepositoryInfo,
    SearchQuery,
    SearchResult,
    TypeSpec,
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
from astral.objectid import ObjectID
from astral.objects import AstralObject, ack, blob, eos
from astral.registry import record_for
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
ID_B = "02" + "ef" * 32
OID_1 = ObjectID(11, b"\x11" * 32)
OID_2 = ObjectID(22, b"\x22" * 32)
NONCE = "0011223344556677"


def _binary_roundtrip(record):
    writer = BinaryWriter()
    record.write_to(writer)
    return type(record).read_from(BinaryReader(writer.getvalue()))


def _json_roundtrip(record):
    return type(record).from_value(record.encode_json())


# ======================================================================
# Record round-trips (binary + JSON)
# ======================================================================
class ProbeRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        p = Probe(type="string8", repo="local", mime="text/plain; charset=utf-8", time=421000)
        self.assertEqual(_binary_roundtrip(p), p)

    def test_binary_field_order(self):
        # string8(Type) ++ string8(Repo) ++ string8(Mime) ++ duration(int64 Time).
        p = Probe(type="string8", repo="local", mime="text/plain", time=421000)
        writer = BinaryWriter()
        writer.string8("string8")
        writer.string8("local")
        writer.string8("text/plain")
        writer.i64(421000)  # duration is a SIGNED int64 (nanoseconds)
        self.assertEqual(p.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        p = Probe(type="", repo="local", mime="text/plain", time=421000)
        self.assertEqual(_json_roundtrip(p), p)


class RepositoryInfoRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        ri = RepositoryInfo(name="local", label="Local storage", free=549755813888)
        self.assertEqual(_binary_roundtrip(ri), ri)

    def test_free_is_uint64_source_not_doc_int64(self):
        # astral-go's RepositoryInfo.Free is astral.Uint64 (the type doc says int64).
        # Modelled as uint64 to match the binary wire.
        _attr, _wire, kind = dict((f[0], f) for f in RepositoryInfo.FIELDS)["free"]
        self.assertEqual(kind, "uint64")
        ri = RepositoryInfo(name="main", label="World", free=0)
        writer = BinaryWriter()
        writer.string8("main")
        writer.string8("World")
        writer.u64(0)
        self.assertEqual(ri.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        ri = RepositoryInfo(name="mem0", label="Default memory", free=67108864)
        self.assertEqual(_json_roundtrip(ri), ri)


class SearchResultRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        sr = SearchResult(source_id=HOST_ID, object_id=OID_1)
        self.assertEqual(_binary_roundtrip(sr), sr)

    def test_binary_field_order(self):
        # identity(SourceID) ++ object_id(ObjectID).
        sr = SearchResult(source_id=HOST_ID, object_id=OID_1)
        writer = BinaryWriter()
        writer.identity(HOST_ID)
        writer.raw(OID_1.to_bytes())
        self.assertEqual(sr.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        sr = SearchResult(source_id=HOST_ID, object_id=OID_2)
        self.assertEqual(_json_roundtrip(sr), sr)


class QueryTagRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        qt = QueryTag(name="mime", mod="EXCLUDE", value="text/plain")
        self.assertEqual(_binary_roundtrip(qt), qt)

    def test_json_roundtrip(self):
        qt = QueryTag(name="private", mod="", value="true")
        self.assertEqual(_json_roundtrip(qt), qt)


class SearchQueryRecordTest(unittest.TestCase):
    def _query(self):
        return SearchQuery(
            query="hello world",
            tags=[
                QueryTag(name="mime", mod="", value="text/plain"),
                QueryTag(name="private", mod="EXCLUDE", value="true"),
            ],
        )

    def test_binary_roundtrip(self):
        q = self._query()
        self.assertEqual(_binary_roundtrip(q), q)

    def test_binary_field_order_query_is_string16(self):
        # string16(Query) ++ array(record QueryTag) Tags.
        q = SearchQuery(query="hi", tags=[QueryTag(name="a", mod="", value="b")])
        writer = BinaryWriter()
        writer.string16("hi")
        writer.u32(1)  # array count
        writer.u8(1)  # per-element presence flag (record elements are value-kind)
        QueryTag(name="a", mod="", value="b").write_to(writer)
        self.assertEqual(q.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        q = self._query()
        self.assertEqual(_json_roundtrip(q), q)

    def test_parse_grammar(self):
        # bare words -> Query; tag:value required; -/?/~ set the modifier; lowercased.
        q = SearchQuery.parse('-mime:text/plain ?private:true Hello World')
        self.assertEqual(q.query, "hello world")
        self.assertEqual(
            q.tags,
            [
                QueryTag(name="mime", mod="EXCLUDE", value="text/plain"),
                QueryTag(name="private", mod="OPTIONAL", value="true"),
            ],
        )

    def test_parse_quoted_value(self):
        q = SearchQuery.parse('title:"around the world"')
        self.assertEqual(q.tags, [QueryTag(name="title", mod="", value="around the world")])


class TypeSpecRecordTest(unittest.TestCase):
    def _spec(self):
        return TypeSpec(
            name="mod.objects.repository_info",
            fields=[
                FieldSpec(name="Name", type="string8", required=True),
                FieldSpec(name="Label", type="string8", required=True),
                FieldSpec(name="Free", type="int64", required=True),
            ],
        )

    def test_binary_roundtrip(self):
        ts = self._spec()
        self.assertEqual(_binary_roundtrip(ts), ts)

    def test_json_roundtrip(self):
        ts = self._spec()
        self.assertEqual(_json_roundtrip(ts), ts)

    def test_json_shape_matches_doc(self):
        ts = self._spec()
        self.assertEqual(
            ts.encode_json(),
            {
                "Name": "mod.objects.repository_info",
                "Fields": [
                    {"Name": "Name", "Type": "string8", "Required": True},
                    {"Name": "Label", "Type": "string8", "Required": True},
                    {"Name": "Free", "Type": "int64", "Required": True},
                ],
            },
        )


class CommitMsgRecordTest(unittest.TestCase):
    def test_empty_binary(self):
        # A zero-size sentinel: no bytes written or read (astral-go CommitMsg).
        cm = CommitMsg()
        self.assertEqual(cm.encode_binary(), b"")
        self.assertEqual(_binary_roundtrip(cm), cm)

    def test_json_is_empty_object(self):
        self.assertEqual(CommitMsg().encode_json(), {})
        self.assertEqual(_json_roundtrip(CommitMsg()), CommitMsg())


class ActionRecordTest(unittest.TestCase):
    def test_create_object_action_binary_roundtrip(self):
        a = CreateObjectAction(nonce=NONCE, actor_id=HOST_ID)
        self.assertEqual(_binary_roundtrip(a), a)

    def test_create_object_action_flattened_field_order(self):
        # Embedded auth.Action flattened: nonce(Nonce) ++ ptr(identity ActorID).
        # SOURCE fields (Nonce + ActorID), NOT the doc's CallerID.
        a = CreateObjectAction(nonce=NONCE, actor_id=HOST_ID)
        writer = BinaryWriter()
        writer.nonce(NONCE)
        writer.u8(1)  # ActorID ptr present
        writer.identity(HOST_ID)
        self.assertEqual(a.encode_binary(), writer.getvalue())

    def test_create_object_action_nil_actor(self):
        a = CreateObjectAction(nonce=NONCE, actor_id=None)
        self.assertEqual(_binary_roundtrip(a), a)
        self.assertEqual(_json_roundtrip(a), a)

    def test_read_object_action_binary_roundtrip(self):
        a = ReadObjectAction(nonce=NONCE, actor_id=HOST_ID, object_id=OID_1)
        self.assertEqual(_binary_roundtrip(a), a)

    def test_read_object_action_field_order(self):
        # nonce(Nonce) ++ ptr(identity ActorID) ++ object_id(ObjectID).
        a = ReadObjectAction(nonce=NONCE, actor_id=None, object_id=OID_1)
        writer = BinaryWriter()
        writer.nonce(NONCE)
        writer.u8(0)  # ActorID nil
        writer.raw(OID_1.to_bytes())
        self.assertEqual(a.encode_binary(), writer.getvalue())


class DescriptorRecordTest(unittest.TestCase):
    def test_binary_roundtrip_with_registered_inner_data(self):
        # Data is the POLYMORPHIC ("object",) kind; a mid-struct object field needs a
        # REGISTERED inner record to bound the binary read.
        inner = SearchResult(source_id=HOST_ID, object_id=OID_1)
        d = Descriptor(
            source_id=HOST_ID,
            object_id=OID_1,
            data=AstralObject("mod.objects.search_result", inner),
        )
        self.assertEqual(_binary_roundtrip(d), d)

    def test_binary_field_order(self):
        # identity(SourceID) ++ object_id(ObjectID) ++ object(Data:
        # string8(type) ++ inner.write_to).
        inner = SearchResult(source_id=HOST_ID, object_id=OID_2)
        d = Descriptor(
            source_id=HOST_ID,
            object_id=OID_1,
            data=AstralObject("mod.objects.search_result", inner),
        )
        writer = BinaryWriter()
        writer.identity(HOST_ID)
        writer.raw(OID_1.to_bytes())
        writer.string8("mod.objects.search_result")
        inner.write_to(writer)
        self.assertEqual(d.encode_binary(), writer.getvalue())

    def test_nil_data_binary_roundtrip(self):
        # nil Data == string8("") == 0x00 (self-nulling, per the ("object",) kind).
        d = Descriptor(source_id=HOST_ID, object_id=OID_1, data=None)
        self.assertEqual(_binary_roundtrip(d), d)

    def test_json_shape_scalar_data(self):
        # The docs example carries a scalar Data via the {"Type","Object"} adapter.
        d = Descriptor.from_value(
            {
                "SourceID": HOST_ID,
                "ObjectID": str(OID_1),
                "Data": {"Type": "string8", "Object": "hello"},
            }
        )
        self.assertEqual(d.source_id, HOST_ID)
        # object_id.sha256 over JSON stays the string form (scalar passthrough).
        self.assertEqual(str(d.object_id), str(OID_1))
        self.assertEqual(d.data.type, "string8")
        self.assertEqual(d.data.value, "hello")
        # And it re-emits the same adapter shape.
        self.assertEqual(
            d.encode_json()["Data"], {"Type": "string8", "Object": "hello"}
        )


# ======================================================================
# Registry resolution
# ======================================================================
class RegistryTest(unittest.TestCase):
    def test_net_new_records_resolve_by_type(self):
        self.assertIs(record_for("mod.objects.probe"), Probe)
        self.assertIs(record_for("mod.objects.repository_info"), RepositoryInfo)
        self.assertIs(record_for("mod.objects.describe_result"), Descriptor)
        self.assertIs(record_for("mod.objects.search_result"), SearchResult)
        self.assertIs(record_for("objects.type_spec"), TypeSpec)
        self.assertIs(record_for("objects.field_spec"), FieldSpec)
        self.assertIs(record_for("objects.search_query"), SearchQuery)
        self.assertIs(record_for("objects.query_tag"), QueryTag)
        self.assertIs(record_for("mod.objects.commit_msg"), CommitMsg)
        self.assertIs(record_for("mod.objects.create_object_action"), CreateObjectAction)
        self.assertIs(record_for("mod.objects.read_object_action"), ReadObjectAction)


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
class ObjectsMockNode:
    """A minimal binary apphost server tailored to the objects ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received
        self.store_body = []  # objects streamed to store
        self.create_body = []  # objects streamed to create
        self.push_body = []  # objects streamed to push

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

        if op == "objects.load":
            # A registered typed object (here a string8) comes back decoded.
            ch.send(AstralObject("string8", "hello"))

        elif op == "objects.read":
            ch.send_bytes(b"hello world")

        elif op == "objects.probe":
            p = Probe(type="string8", repo="local", mime="text/plain", time=421000)
            ch.send(AstralObject("mod.objects.probe", p.encode_binary()))

        elif op == "objects.find":
            ch.send(AstralObject("identity", HOST_ID))
            ch.send(AstralObject("identity", ID_A))
            ch.send(eos())

        elif op == "objects.search":
            for sr in (
                SearchResult(source_id=HOST_ID, object_id=OID_1),
                SearchResult(source_id=ID_A, object_id=OID_2),
            ):
                ch.send(AstralObject("mod.objects.search_result", sr.encode_binary()))
            ch.send(eos())

        elif op == "objects.describe":
            inner = SearchResult(source_id=HOST_ID, object_id=OID_1)
            d = Descriptor(
                source_id=HOST_ID,
                object_id=OID_1,
                data=AstralObject("mod.objects.search_result", inner),
            )
            ch.send(AstralObject("mod.objects.describe_result", d.encode_binary()))
            ch.send(eos())

        elif op == "objects.contains":
            ch.send(AstralObject("bool", True))

        elif op == "objects.get_type":
            ch.send(AstralObject("string8", "string8"))

        elif op == "objects.spec":
            ts = TypeSpec(
                name="mod.objects.probe",
                fields=[
                    FieldSpec(name="Type", type="string8", required=True),
                    FieldSpec(name="Time", type="duration", required=True),
                ],
            )
            ch.send(AstralObject("objects.type_spec", ts.encode_binary()))
            ch.send(eos())

        elif op == "objects.blueprints":
            for n in ("bool", "string8", "object_id.sha256"):
                ch.send(AstralObject("string8", n))
            ch.send(eos())

        elif op == "objects.new":
            ch.send(AstralObject("bool", False))

        elif op == "objects.store":
            # INPUT-BODY: read objects until eos, reply one id per object.
            while True:
                obj = ch.recv()
                if obj is None or obj.is_eos:
                    break
                self.store_body.append(obj)
                ch.send(AstralObject("object_id.sha256", OID_1))
            ch.send(eos())

        elif op == "objects.create":
            # ack the open writer, read blob chunks + a commit_msg, reply with the id.
            ch.send(ack())
            while True:
                obj = ch.recv()
                if obj is None:
                    break
                if obj.type == "mod.objects.commit_msg":
                    ch.send(AstralObject("object_id.sha256", OID_2))
                    break
                self.create_body.append(obj)

        elif op == "objects.push":
            obj = ch.recv()
            self.push_body.append(obj)
            ch.send(AstralObject("bool", True))

        elif op == "objects.delete":
            ch.send(ack())

        elif op == "objects.purge":
            ch.send(AstralObject("object_id.sha256", OID_1))
            ch.send(AstralObject("object_id.sha256", OID_2))
            ch.send(eos())

        elif op == "objects.repositories":
            for ri in (
                RepositoryInfo(name="main", label="World", free=0),
                RepositoryInfo(name="local", label="Local storage", free=549755813888),
            ):
                ch.send(AstralObject("mod.objects.repository_info", ri.encode_binary()))
            ch.send(eos())

        elif op == "objects.new_mem":
            ch.send(ack())

        elif op == "objects.remove_repository":
            ch.send(ack())

        elif op == "objects.scan":
            follow = "follow=true" in rq.Query
            ch.send(AstralObject("object_id.sha256", OID_1))
            ch.send(AstralObject("object_id.sha256", OID_2))
            ch.send(eos())  # snapshot terminator / follow separator
            if follow:
                ch.send(AstralObject("object_id.sha256", OID_1))  # live tail
                # channel then closes (no further eos)

        elif op in (
            "objects.register_searcher",
            "objects.register_describer",
            "objects.register_finder",
        ):
            ch.send(ack())  # registration held for the channel's lifetime

        elif op == "objects.echo":
            # Bidirectional debug: echo one object back.
            obj = ch.recv()
            if obj is not None:
                ch.send(obj)

        else:
            ch.send(eos())


class ObjectsOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = ObjectsMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []
        self.node.store_body = []
        self.node.create_body = []
        self.node.push_body = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_objects_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.objects, Objects)
            self.assertIs(c.objects, c.objects)  # lazily cached

    def test_load_returns_decoded_value(self):
        with self.connect() as c:
            value = c.objects.load(OID_1)
        self.assertEqual(value, "hello")
        self.assertIn(f"objects.load?id={OID_1}", self.node.seen)

    def test_load_passes_repo_and_unparsed(self):
        with self.connect() as c:
            c.objects.load(OID_1, repo="local", unparsed=True)
        q = self.node.seen[-1]
        self.assertIn("repo=local", q)
        self.assertIn("unparsed=true", q)

    def test_read_returns_raw_bytes(self):
        with self.connect() as c:
            data = c.objects.read(OID_1)
        self.assertEqual(data, b"hello world")

    def test_read_passes_offset_and_limit(self):
        with self.connect() as c:
            c.objects.read(OID_1, offset=6, limit=5)
        q = self.node.seen[-1]
        self.assertIn("offset=6", q)
        self.assertIn("limit=5", q)

    def test_probe_returns_probe(self):
        with self.connect() as c:
            p = c.objects.probe(OID_1, repo="local")
        self.assertIsInstance(p, Probe)
        self.assertEqual(p.type, "string8")
        self.assertEqual(p.repo, "local")
        self.assertEqual(p.time, 421000)
        self.assertIn("repo=local", self.node.seen[-1])

    def test_find_streams_identities(self):
        with self.connect() as c:
            ids = c.objects.find(OID_1)
        self.assertEqual(ids, [HOST_ID, ID_A])

    def test_search_streams_search_results(self):
        with self.connect() as c:
            results = c.objects.search("mime:text/plain hello")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, SearchResult) for r in results))
        self.assertEqual(results[0], SearchResult(source_id=HOST_ID, object_id=OID_1))
        self.assertIn("q=mime", self.node.seen[-1])

    def test_search_accepts_search_query_record(self):
        q = SearchQuery(query="hello", tags=[QueryTag(name="mime", mod="", value="text/plain")])
        with self.connect() as c:
            c.objects.search(q, repo="local")
        sent = self.node.seen[-1]
        self.assertIn("q=", sent)
        self.assertIn("repo=local", sent)

    def test_describe_returns_typed_descriptors(self):
        with self.connect() as c:
            descs = c.objects.describe(OID_1)
        self.assertEqual(len(descs), 1)
        self.assertIsInstance(descs[0], Descriptor)
        self.assertEqual(descs[0].source_id, HOST_ID)
        self.assertEqual(descs[0].object_id, OID_1)
        self.assertEqual(descs[0].data.type, "mod.objects.search_result")
        self.assertIsInstance(descs[0].data.value, SearchResult)

    def test_describe_passes_only_and_except(self):
        with self.connect() as c:
            c.objects.describe(OID_1, only="mod.objects.probe", except_="x")
        q = self.node.seen[-1]
        self.assertIn("only=mod.objects.probe", q)
        self.assertIn("except=x", q)

    def test_contains_requires_repo_and_returns_bool(self):
        with self.connect() as c:
            self.assertTrue(c.objects.contains(OID_1, "local"))
        q = self.node.seen[-1]
        self.assertIn("repo=local", q)
        self.assertIn(f"id={OID_1}", q)

    def test_contains_repo_is_positional_required(self):
        # repo is a required positional arg (the FIX); calling without it is a TypeError.
        with self.connect() as c:
            with self.assertRaises(TypeError):
                c.objects.contains(OID_1)

    def test_get_type_returns_type_name(self):
        with self.connect() as c:
            t = c.objects.get_type(OID_1)
        self.assertEqual(t, "string8")

    def test_spec_returns_type_specs(self):
        with self.connect() as c:
            specs = c.objects.spec("mod.objects.probe")
        self.assertEqual(len(specs), 1)
        self.assertIsInstance(specs[0], TypeSpec)
        self.assertEqual(specs[0].name, "mod.objects.probe")
        self.assertEqual(specs[0].fields[1], FieldSpec(name="Time", type="duration", required=True))
        self.assertIn("type=mod.objects.probe", self.node.seen[-1])

    def test_blueprints_streams_names(self):
        with self.connect() as c:
            names = c.objects.blueprints()
        self.assertEqual(names, ["bool", "string8", "object_id.sha256"])

    def test_new_returns_zero_value(self):
        with self.connect() as c:
            value = c.objects.new("bool")
        self.assertEqual(value, False)
        self.assertIn("type=bool", self.node.seen[-1])

    def test_store_sends_objects_and_returns_ids(self):
        with self.connect() as c:
            ids = c.objects.store(
                [AstralObject("string8", "hello"), AstralObject("string8", "world")],
                repo="local",
            )
        self.assertEqual(ids, [OID_1, OID_1])
        self.assertTrue(all(isinstance(i, ObjectID) for i in ids))
        self.assertEqual(len(self.node.store_body), 2)
        self.assertEqual(self.node.store_body[0].type, "string8")
        self.assertEqual(self.node.store_body[0].value, "hello")
        self.assertIn("repo=local", self.node.seen[-1])

    def test_store_one_returns_single_id(self):
        with self.connect() as c:
            oid = c.objects.store_one(AstralObject("string8", "hi"))
        self.assertEqual(oid, OID_1)

    def test_create_writer_commits_and_returns_id(self):
        with self.connect() as c:
            writer = c.objects.create(repo="local", alloc=1024)
            writer.write(b"hello ")
            writer.write(b"world")
            oid = writer.commit()
        self.assertEqual(oid, OID_2)
        # Two blob chunks crossed the body (untyped objects), then the commit_msg.
        self.assertEqual(len(self.node.create_body), 2)
        self.assertTrue(all(o.type == "" for o in self.node.create_body))
        self.assertEqual(self.node.create_body[0].value, b"hello ")
        q = self.node.seen[-1]
        self.assertIn("repo=local", q)
        self.assertIn("alloc=1024", q)

    def test_create_writer_as_context_manager_auto_commits(self):
        with self.connect() as c:
            with c.objects.create(repo="local") as writer:
                writer.write(b"data")
            self.assertEqual(writer._id, OID_2)

    def test_push_returns_acceptance_flag(self):
        with self.connect() as c:
            accepted = c.objects.push(AstralObject("string8", "hi"))
        self.assertTrue(accepted)
        self.assertEqual(len(self.node.push_body), 1)
        self.assertEqual(self.node.push_body[0].value, "hi")

    def test_delete_single_acks(self):
        with self.connect() as c:
            self.assertIsNone(c.objects.delete(OID_1, "local"))
        q = self.node.seen[-1]
        self.assertIn("repo=local", q)
        self.assertIn(f"id={OID_1}", q)

    def test_purge_streams_ids(self):
        with self.connect() as c:
            ids = c.objects.purge("local")
        self.assertEqual(ids, [OID_1, OID_2])
        self.assertIn("objects.purge?repo=local", self.node.seen)

    def test_repositories_streams_repository_info(self):
        with self.connect() as c:
            repos = c.objects.repositories()
        self.assertEqual(len(repos), 2)
        self.assertTrue(all(isinstance(r, RepositoryInfo) for r in repos))
        self.assertEqual(repos[0].name, "main")
        self.assertEqual(repos[1], RepositoryInfo(name="local", label="Local storage", free=549755813888))

    def test_new_mem_acks_and_passes_size(self):
        with self.connect() as c:
            self.assertIsNone(c.objects.new_mem("scratch", size="16M"))
        q = self.node.seen[-1]
        self.assertIn("name=scratch", q)
        self.assertIn("size=16M", q)

    def test_remove_repository_acks(self):
        with self.connect() as c:
            self.assertIsNone(c.objects.remove_repository("scratch"))
        self.assertIn("objects.remove_repository?name=scratch", self.node.seen)

    def test_scan_snapshot_streams_ids(self):
        with self.connect() as c:
            ids = list(c.objects.scan("local"))
        self.assertEqual(ids, [OID_1, OID_2])
        self.assertIn("objects.scan?repo=local&follow=false", self.node.seen)

    def test_scan_follow_reads_across_separator(self):
        # follow=true: the first eos is a snapshot/live SEPARATOR, then a live id.
        with self.connect() as c:
            gen = c.objects.scan("local", follow=True)
            ids = list(gen)
        self.assertEqual(ids, [OID_1, OID_2, OID_1])
        self.assertIn("objects.scan?repo=local&follow=true", self.node.seen)

    def test_register_searcher_returns_live_stream_after_ack(self):
        with self.connect() as c:
            stream = c.objects.register_searcher()
            self.assertIsNotNone(stream)
            stream.close()
        self.assertIn("objects.register_searcher", self.node.seen)

    def test_echo_returns_bidirectional_stream(self):
        with self.connect() as c:
            with c.objects.echo(only="string8") as stream:
                stream.send(AstralObject("string8", "ping"))
                back = stream.recv()
        self.assertEqual(back.type, "string8")
        self.assertEqual(back.value, "ping")
        self.assertIn("only=string8", self.node.seen[-1])


# ======================================================================
# Record SEND path (encode counterpart of the decode dispatch)
# ======================================================================
class RecordSendPathTest(unittest.TestCase):
    def test_encode_payload_encodes_probe_over_binary(self):
        from astral.payload import encode_payload

        p = Probe(type="string8", repo="local", mime="text/plain", time=421000)
        self.assertEqual(encode_payload("mod.objects.probe", p), p.encode_binary())

    def test_to_json_envelope_encodes_search_result(self):
        from astral.encoding import to_json_envelope

        sr = SearchResult(source_id=HOST_ID, object_id=OID_1)
        env = to_json_envelope(AstralObject("mod.objects.search_result", sr))
        self.assertEqual(
            env, {"Type": "mod.objects.search_result", "Object": sr.encode_json()}
        )


if __name__ == "__main__":
    unittest.main()
