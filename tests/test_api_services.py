"""Tests for the ``services`` protocol helper and its ``services.update`` record.

Two layers, grounded in ``protocols/services/`` (op + type docs) and astral-go
``api/services/`` (``update.go`` struct ``Update``, ``client/services.go``):

* **Record round-trips** — :class:`ServiceUpdate` round-trips over BOTH framings
  (binary ``write_to``/``read_from`` and JSON ``from_value``/``encode_json``),
  matching the transport-decision requirement that structured objects decode over
  binary IPC too. Covers the nullable ``ProviderID`` identity (present + nil) and the
  nullable OPAQUE ``Info`` bundle in its three JSON shapes the docs show: ``null``
  (→ ``None``), ``[]`` (empty, → ``[]``), and a non-nil bundle of framed blobs (the
  blobs must survive byte-for-byte). Plus the exact binary field order.
* **Ops over a binary MockNode** — ``discover`` collects the snapshot up to the eos
  TERMINATOR; ``discover_follow`` crosses the eos SEPARATOR via ``Stream.follow`` and
  yields the live tail; ``sync`` acks, with the ``id`` / ``follow`` args pinned and
  the error path raising.

Plus registry resolution + no double-registration for ``services.update``.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.services import Services, ServiceUpdate
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
PROVIDER_ID = "02bef8840eb35ef2ae3c83c07cb5779278904f99cb4103f71e37cc69931ae5e15f"
PROVIDER_ID_2 = "03" + "cd" * 32
# A target identity for the sync op.
SYNC_ID = "037f990e61acee8a7697966afd29dd88f3b1f8a7b14d625c4f8742bd952003a590"


def _binary_roundtrip(record):
    """Encode ``record`` to binary and decode it back through the same class."""
    writer = BinaryWriter()
    record.write_to(writer)
    return type(record).read_from(BinaryReader(writer.getvalue()))


def _json_roundtrip(record):
    """Encode ``record`` to its JSON value form and decode it back."""
    return type(record).from_value(record.encode_json())


# ======================================================================
# Record round-trips (binary + JSON)
# ======================================================================
class ServiceUpdateRecordTest(unittest.TestCase):
    def test_defaults(self):
        u = ServiceUpdate()
        self.assertEqual(
            (u.available, u.name, u.provider_id, u.info),
            (False, "", None, None),
        )

    def test_present_binary_roundtrip(self):
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[b"\x05blob"])
        self.assertEqual(_binary_roundtrip(u), u)

    def test_nil_provider_and_info_binary_roundtrip(self):
        u = ServiceUpdate(available=False, name="objects", provider_id=None, info=None)
        self.assertEqual(_binary_roundtrip(u), u)

    def test_empty_info_bundle_binary_roundtrip(self):
        # An empty (present but zero-object) Info bundle stays [] across binary.
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[])
        back = _binary_roundtrip(u)
        self.assertEqual(back.info, [])
        self.assertEqual(back, u)

    def test_info_bundle_blobs_survive_binary_roundtrip(self):
        # A non-nil OPAQUE Info bundle: the raw framed blobs survive byte-for-byte
        # (opaque passthrough — inner objects not decoded). astral.Bundle wire:
        # uint32(count) ++ bytes32(blob) per object.
        blobs = [b"\x05blob-one", b"\x00\x01\x02\x03"]
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=blobs)
        back = _binary_roundtrip(u)
        self.assertEqual(back.info, blobs)
        self.assertEqual(back, u)

    def test_binary_field_order(self):
        # bool(Available) ++ string8(Name) ++ ptr(ProviderID identity) ++
        # ptr(Info bundle) — fields in astral-go struct declaration order.
        blob = b"\xde\xad\xbe\xef"
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[blob])
        writer = BinaryWriter()
        writer.boolean(True)
        writer.string8("chat")
        writer.u8(1)  # ProviderID ptr present
        writer.identity(PROVIDER_ID)
        writer.u8(1)  # Info ptr present
        writer.u32(1)  # bundle count
        writer.bytes32(blob)
        self.assertEqual(u.encode_binary(), writer.getvalue())

    def test_nil_ptr_binary_layout(self):
        # Both nullable pointers nil: a single 0x00 flag byte each.
        u = ServiceUpdate(available=False, name="", provider_id=None, info=None)
        # bool(False)=0x00 ++ string8("")=0x00 ++ ProviderID nil=0x00 ++ Info nil=0x00
        self.assertEqual(u.encode_binary(), b"\x00\x00\x00\x00")

    def test_present_json_roundtrip(self):
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[b"a", b"bc"])
        self.assertEqual(_json_roundtrip(u), u)

    def test_json_null_info_is_none(self):
        # The discover doc example: "Info": null decodes to None.
        u = ServiceUpdate.from_value(
            {"Available": True, "Name": "objects", "ProviderID": PROVIDER_ID, "Info": None}
        )
        self.assertEqual(u, ServiceUpdate(True, "objects", PROVIDER_ID, None))
        self.assertIsNone(u.info)

    def test_json_empty_info_is_empty_list(self):
        # The type doc example: "Info": [] decodes to [] (present-but-empty bundle).
        u = ServiceUpdate.from_value(
            {"Available": True, "Name": "chat", "ProviderID": PROVIDER_ID, "Info": []}
        )
        self.assertEqual(u.info, [])
        self.assertEqual(u, ServiceUpdate(True, "chat", PROVIDER_ID, []))

    def test_json_nil_provider_is_none(self):
        u = ServiceUpdate(available=False, name="chat", provider_id=None, info=None)
        self.assertEqual(
            u.encode_json(),
            {"Available": False, "Name": "chat", "ProviderID": None, "Info": None},
        )
        self.assertEqual(_json_roundtrip(u), u)

    def test_from_value_idempotent(self):
        u = ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID)
        self.assertIs(ServiceUpdate.from_value(u), u)


# ======================================================================
# Registry resolution + no double-registration
# ======================================================================
class RegistryTest(unittest.TestCase):
    def test_record_resolves_by_type(self):
        self.assertIs(record_for("services.update"), ServiceUpdate)

    def test_no_double_registration(self):
        from astral.registry import register

        self.assertIs(register("services.update")(ServiceUpdate), ServiceUpdate)
        self.assertIs(record_for("services.update"), ServiceUpdate)


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
# The snapshot then the live tail streamed by services.discover.
SNAPSHOT = [
    ServiceUpdate(available=True, name="objects", provider_id=PROVIDER_ID, info=None),
    ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[]),
]
LIVE = [
    ServiceUpdate(available=False, name="chat", provider_id=PROVIDER_ID, info=None),
    ServiceUpdate(available=True, name="dir", provider_id=PROVIDER_ID_2, info=[b"\x01x"]),
]


class ServicesMockNode:
    """A minimal binary apphost server tailored to the services ops."""

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

    @staticmethod
    def _update_obj(update):
        # Send the record as raw binary bytes on the wire; the client decodes it
        # back to a typed ServiceUpdate via the registry (read_from).
        return AstralObject("services.update", update.encode_binary())

    def _query(self, ch, rq):
        query = rq.Query
        op = query.split("?", 1)[0]
        self.seen.append(query)
        ch.send(QueryAcceptedMsg())

        if op == "services.discover":
            if "cannot" in query:  # a discovery-cannot-start error path
                ch.send(AstralObject("error_message", "discovery cannot start"))
                ch.send(eos())
                return
            follow = "follow=true" in query
            for u in SNAPSHOT:
                ch.send(self._update_obj(u))
            ch.send(eos())  # snapshot terminator, or snapshot/live separator in follow
            if follow:
                for u in LIVE:
                    ch.send(self._update_obj(u))
                # channel close (from _handle's finally) ends the follow stream
        elif op == "services.sync":
            if "id=missing" in query:
                ch.send(AstralObject("error_message", "target identity cannot be resolved"))
            else:
                ch.send(ack())
            ch.send(eos())
        else:
            ch.send(eos())


class ServicesOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = ServicesMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_services_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.services, Services)
            self.assertIs(c.services, c.services)  # lazily cached

    def test_discover_returns_typed_snapshot(self):
        with self.connect() as c:
            got = c.services.discover()
        # Decoded to typed ServiceUpdate records over binary (via the registry),
        # stopping at the eos terminator (snapshot only, no live tail).
        self.assertTrue(all(isinstance(u, ServiceUpdate) for u in got))
        self.assertEqual(got, SNAPSHOT)
        # follow=False is pinned on the wire.
        self.assertIn("services.discover?follow=false", self.node.seen)

    def test_discover_error_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                # force the error path via an extra arg the mock keys on
                with c.query("services.discover?follow=false&cannot=1") as stream:
                    [ServiceUpdate.from_value(o.value) for o in stream.results()]

    def test_discover_follow_yields_snapshot_and_live(self):
        with self.connect() as c:
            got = list(c.services.discover_follow())
        # Crosses the eos SEPARATOR via Stream.follow and yields both halves.
        self.assertTrue(all(isinstance(u, ServiceUpdate) for u in got))
        self.assertEqual(got, SNAPSHOT + LIVE)
        self.assertIn("services.discover?follow=true", self.node.seen)

    def test_discover_follow_caller_may_break_early(self):
        # Breaking out of the loop closes the stream via the with block.
        with self.connect() as c:
            seen = []
            for u in c.services.discover_follow():
                seen.append(u)
                if len(seen) == len(SNAPSHOT):
                    break
        self.assertEqual(seen, SNAPSHOT)

    def test_sync_acks_and_pins_id(self):
        with self.connect() as c:
            self.assertIsNone(c.services.sync(SYNC_ID))
        self.assertIn(f"services.sync?id={SYNC_ID}", self.node.seen)

    def test_sync_forwards_follow_when_set(self):
        with self.connect() as c:
            self.assertIsNone(c.services.sync(SYNC_ID, follow=True))
        self.assertIn(f"services.sync?id={SYNC_ID}&follow=true", self.node.seen)

    def test_sync_omits_follow_when_none(self):
        with self.connect() as c:
            c.services.sync(SYNC_ID)
        self.assertNotIn("follow", self.node.seen[-1])

    def test_sync_error_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.services.sync("missing")


# ======================================================================
# Record SEND path (the encode counterpart of the decode dispatch)
# ======================================================================
class RecordSendPathTest(unittest.TestCase):
    def _update(self):
        return ServiceUpdate(available=True, name="chat", provider_id=PROVIDER_ID, info=[b"\x01x"])

    def test_encode_payload_encodes_a_record_over_binary(self):
        from astral.payload import encode_payload

        u = self._update()
        self.assertEqual(encode_payload("services.update", u), u.encode_binary())

    def test_to_json_envelope_encodes_a_record(self):
        from astral.encoding import to_json_envelope

        u = self._update()
        env = to_json_envelope(AstralObject("services.update", u))
        self.assertEqual(env, {"Type": "services.update", "Object": u.encode_json()})


if __name__ == "__main__":
    unittest.main()
