"""Unit tests for the wire codecs, object IDs, encoding and messages.

These validate the implementation against the byte examples given in the
astral-docs (``common-types/``, ``core-primitives/``) and check round-trips.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from astral.codec import BinaryReader, BinaryWriter, channel_frame, read_channel_frame
from astral.encoding import Zone, build_query_string, from_json_envelope, to_json_envelope, to_text
from astral.errors import EncodingError
from astral.messages import HostInfoMsg, RouteQueryMsg, message_from_object
from astral.objectid import ObjectID, compute_object_id, zbase32_decode, zbase32_encode
from astral.objects import ack, blob, eos, obj
from astral.payload import decode_payload, encode_payload


class TestBinaryPrimitives(unittest.TestCase):
    def test_array_of_uint8_documented_bytes(self):
        # binary-encoding.md: [1,2,3] -> 00 00 00 03 01 02 03
        w = BinaryWriter()
        w.u32(3)
        for v in (1, 2, 3):
            w.u8(v)
        self.assertEqual(w.getvalue(), bytes.fromhex("00000003010203"))

    def test_generic_object_documented_bytes(self):
        # common-types/object.md: uint8 21 -> 05 'uint8' 15
        w = BinaryWriter().string8("uint8").u8(21)
        self.assertEqual(w.getvalue(), bytes.fromhex("0575696e743815"))

    def test_integer_roundtrips(self):
        cases = [
            ("u8", 0), ("u8", 255), ("u16", 65535), ("u32", 2**32 - 1),
            ("u64", 2**64 - 1), ("i8", -128), ("i8", 127), ("i64", -(2**63)),
        ]
        for kind, value in cases:
            w = BinaryWriter()
            getattr(w, kind)(value)
            r = BinaryReader(w.getvalue())
            self.assertEqual(getattr(r, kind)(), value, (kind, value))

    def test_string_and_bytes_prefixes(self):
        self.assertEqual(BinaryWriter().string8("hi").getvalue(), b"\x02hi")
        self.assertEqual(BinaryWriter().string16("hi").getvalue(), b"\x00\x02hi")
        self.assertEqual(BinaryWriter().bytes32(b"abc").getvalue(), b"\x00\x00\x00\x03abc")
        r = BinaryReader(b"\x02hi")
        self.assertEqual(r.string8(), "hi")

    def test_string8_overflow(self):
        with self.assertRaises(EncodingError):
            BinaryWriter().string8("x" * 256)

    def test_identity_roundtrip_and_zero(self):
        hex_id = "02" + "ab" * 32  # 33-byte compressed key
        encoded = BinaryWriter().identity(hex_id).getvalue()
        # presence flag 0x01 followed by the 33 key bytes
        self.assertEqual(len(encoded), 34)
        self.assertEqual(encoded[0], 1)
        self.assertEqual(encoded[1:].hex(), hex_id)
        self.assertEqual(BinaryReader(encoded).identity(), hex_id)
        # null identity <-> empty string: a single 0x00 byte, no key follows
        null = BinaryWriter().identity("").getvalue()
        self.assertEqual(null, b"\x00")
        self.assertEqual(BinaryReader(null).identity(), "")

    def test_nonce_roundtrip(self):
        n = "a3f1c2d4e5b6f708"
        self.assertEqual(BinaryWriter().nonce(n).getvalue(), bytes.fromhex(n))
        self.assertEqual(BinaryReader(bytes.fromhex(n)).nonce(), n)

    def test_channel_frame(self):
        frame = channel_frame("ack", b"")
        self.assertEqual(frame, bytes.fromhex("03" + "61636b" + "00000000"))
        t, p = read_channel_frame(BinaryReader(frame))
        self.assertEqual((t, p), ("ack", b""))
        frame = channel_frame("string8", b"\x05hello")
        t, p = read_channel_frame(BinaryReader(frame))
        self.assertEqual((t, p), ("string8", b"\x05hello"))


class TestObjectID(unittest.TestCase):
    def test_zbase32_roundtrip(self):
        for data in [b"", b"\x00", bytes(range(40)), os.urandom(40)]:
            self.assertEqual(zbase32_decode(zbase32_encode(data)), data)

    def test_untyped_object_id(self):
        oid = compute_object_id(b"hello world")
        self.assertEqual(oid.size, 11)
        text = str(oid)
        self.assertTrue(text.startswith("data1"))
        self.assertEqual(ObjectID.parse(text), oid)

    def test_empty_object_id(self):
        oid = compute_object_id(b"")
        self.assertEqual(oid.size, 0)
        self.assertEqual(ObjectID.parse(str(oid)), oid)

    def test_typed_object_id_includes_header(self):
        # A typed object's encoding includes Stamp + string8(type), so it
        # differs from the untyped encoding of the same payload.
        typed = compute_object_id(b"\x15", "uint8")
        untyped = compute_object_id(b"\x15")
        self.assertNotEqual(typed, untyped)
        self.assertEqual(ObjectID.parse(str(typed)), typed)

    def test_parse_rejects_bad_prefix(self):
        with self.assertRaises(EncodingError):
            ObjectID.parse("nope")


class TestTextEncoding(unittest.TestCase):
    def test_to_text(self):
        self.assertEqual(to_text(True), "true")
        self.assertEqual(to_text(False), "false")
        self.assertEqual(to_text(42), "42")
        self.assertEqual(to_text("hello"), "hello")
        self.assertEqual(to_text(b"\x01\x02"), "0102")

    def test_build_query_string(self):
        self.assertEqual(build_query_string("dir.resolve", {"name": "alice"}), "dir.resolve?name=alice")
        self.assertEqual(
            build_query_string("tree.get", {"path": "/mod/tcp", "follow": True}),
            "tree.get?path=%2Fmod%2Ftcp&follow=true",
        )
        self.assertEqual(build_query_string("apphost.whoami"), "apphost.whoami")
        # None values are skipped
        self.assertEqual(build_query_string("op", {"a": None, "b": 1}), "op?b=1")

    def test_query_string_length_limit(self):
        with self.assertRaises(EncodingError):
            build_query_string("op", {"x": "y" * 300})


class TestZone(unittest.TestCase):
    def test_mask_and_string(self):
        self.assertEqual(Zone.to_mask("dvn"), 7)
        self.assertEqual(Zone.to_mask("d"), 1)
        self.assertEqual(Zone.to_string(7), "dvn")
        self.assertEqual(Zone.to_string(Zone.DEVICE | Zone.NETWORK), "dn")
        self.assertEqual(Zone.to_string(0), "")

    def test_bad_flag(self):
        with self.assertRaises(EncodingError):
            Zone.to_mask("x")


class TestPayloadCodec(unittest.TestCase):
    def test_scalar_roundtrips(self):
        cases = [
            ("uint8", 21), ("uint64", 123456789), ("int8", -5),
            ("string8", "hello"), ("string16", "world"), ("bool", True),
            ("bool", False), ("error_message", "boom"), ("identity", "02" + "cd" * 32),
            ("nonce64", "0011223344556677"), ("time", 1717171717000000000),
        ]
        for obj_type, value in cases:
            payload = encode_payload(obj_type, value)
            self.assertEqual(decode_payload(obj_type, payload), value, (obj_type, value))

    def test_uint8_payload_matches_docs(self):
        self.assertEqual(encode_payload("uint8", 21), b"\x15")
        self.assertEqual(encode_payload("string8", "hi"), b"\x02hi")

    def test_untyped_blob(self):
        self.assertEqual(encode_payload("", b"raw"), b"raw")
        self.assertEqual(decode_payload("", b"raw"), b"raw")

    def test_object_id_payload(self):
        oid = compute_object_id(b"hello world")
        payload = encode_payload("object_id.sha256", oid)
        self.assertEqual(len(payload), 40)
        self.assertEqual(decode_payload("object_id.sha256", payload), oid)

    def test_generic_object_payload(self):
        inner = obj("uint8", 21)
        payload = encode_payload("object", inner)
        self.assertEqual(payload, b"\x05uint8\x15")
        decoded = decode_payload("object", payload)
        self.assertEqual((decoded.type, decoded.value), ("uint8", 21))

    def test_unknown_type_passthrough(self):
        self.assertEqual(decode_payload("mod.some.struct", b"\x01\x02"), b"\x01\x02")
        self.assertEqual(encode_payload("mod.some.struct", b"\x01\x02"), b"\x01\x02")


class TestJsonEnvelope(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(to_json_envelope(obj("string8", "hi")), {"Type": "string8", "Object": "hi"})
        self.assertEqual(to_json_envelope(eos()), {"Type": "eos", "Object": None})
        self.assertEqual(to_json_envelope(ack()), {"Type": "ack", "Object": None})
        decoded = from_json_envelope({"Type": "identity", "Object": "02ab"})
        self.assertEqual((decoded.type, decoded.value), ("identity", "02ab"))

    def test_bytes_rejected_in_json(self):
        with self.assertRaises(EncodingError):
            to_json_envelope(blob(b"\x00\x01"))


class TestMessages(unittest.TestCase):
    def test_route_query_binary_roundtrip(self):
        m = RouteQueryMsg(
            Nonce="a3f1c2d4e5b6f708",
            Caller="",
            Target="02" + "ab" * 32,
            Query="dir.resolve?name=alice",
            Zone="dvn",
            Filters=["f1", "f2"],
        )
        m2 = RouteQueryMsg.decode_binary(m.encode_binary())
        self.assertEqual(m2.Nonce, m.Nonce)
        self.assertEqual(m2.Target, m.Target)
        self.assertEqual(m2.Query, m.Query)
        self.assertEqual(m2.Zone, "dvn")
        self.assertEqual(m2.Filters, ["f1", "f2"])

    def test_route_query_json_roundtrip(self):
        m = RouteQueryMsg(Nonce="0011223344556677", Target="02" + "cd" * 32, Query="ping")
        ao = m.to_object()
        self.assertEqual(ao.type, "mod.apphost.route_query_msg")
        self.assertEqual(ao.value["Zone"], "dvn")
        m2 = message_from_object(ao)
        self.assertEqual(m2.Query, "ping")
        self.assertEqual(m2.Nonce, "0011223344556677")

    def test_route_query_null_caller_binary(self):
        # An anonymous caller encodes as a single 0x00 presence flag.
        m = RouteQueryMsg(Nonce="0011223344556677", Caller="", Target="02" + "ab" * 32, Query="ping")
        encoded = m.encode_binary()
        self.assertEqual(encoded[8], 0)  # right after the 8-byte nonce
        decoded = RouteQueryMsg.decode_binary(encoded)
        self.assertEqual(decoded.Caller, "")
        self.assertEqual(decoded.Target, "02" + "ab" * 32)

    def test_host_info_msg_matches_live_bytes(self):
        # Bytes captured from a live astrald node: presence flag 0x01 + 33-byte
        # key + string8 alias.
        key = "03100c63a026097748e9a7116443971267ba4422604da2514520b69d9c5f696dd3"
        payload = bytes.fromhex("01" + key) + BinaryWriter().string8("bouncy-lurch").getvalue()
        self.assertEqual(len(payload), 47)
        msg = HostInfoMsg.decode_binary(payload)
        self.assertEqual(msg.Identity, key)
        self.assertEqual(msg.Alias, "bouncy-lurch")
        self.assertEqual(msg.encode_binary(), payload)


if __name__ == "__main__":
    unittest.main()
