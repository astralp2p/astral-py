"""Tests for the typed-record foundation: the ``Record`` base, the registry, and
binary-channel decode of a registered structured type.

The proof case is ``apphost.access_token`` — master's only structured record.
It is round-tripped over *both* framings: the binary path (through the extended
``payload.decode_payload`` -> ``Record.read_from``) and the JSON path
(``Record.from_value(dict)``), which is exactly the transport-decision
requirement: structured objects decode over binary IPC, not only over JSON.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from astral.codec import BinaryReader, BinaryWriter
from astral.payload import decode_payload
from astral.record import Record
from astral.registry import record_for, registered_types
from astral.api.apphost import AccessToken  # importing registers the record

# A valid 33-byte (66-hex) compressed public key, from the docs examples.
IDENTITY = "0282fee8775757cdd8fda8b220195f5b8611312cd145c5a1a3aa55df210e779b2c"


class TestRegistry(unittest.TestCase):
    def test_access_token_is_registered(self):
        self.assertIs(record_for("apphost.access_token"), AccessToken)
        self.assertIn("apphost.access_token", registered_types())

    def test_unregistered_type_is_none(self):
        self.assertIsNone(record_for("mod.nowhere.nothing"))


class TestAccessTokenBinary(unittest.TestCase):
    def test_decode_payload_yields_typed_record(self):
        # A structured payload for a registered type decodes to a Record over the
        # binary channel, instead of falling through to raw bytes.
        token = AccessToken(identity=IDENTITY, token="k7m2q5x9r3v4n8p1", expires_at=1927848000)
        payload = token.encode_binary()

        decoded = decode_payload("apphost.access_token", payload)

        self.assertIsInstance(decoded, AccessToken)
        self.assertEqual(decoded, token)

    def test_write_read_roundtrip(self):
        token = AccessToken(identity=IDENTITY, token="hello", expires_at=42)
        writer = BinaryWriter()
        token.write_to(writer)
        got = AccessToken.read_from(BinaryReader(writer.getvalue()))
        self.assertEqual(got, token)

    def test_null_identity_roundtrip(self):
        # The null/zero identity is a single 0x00 byte (no key follows).
        token = AccessToken(identity="", token="t", expires_at=0)
        got = AccessToken.read_from(BinaryReader(token.encode_binary()))
        self.assertEqual(got, token)
        self.assertEqual(got.identity, "")

    def test_field_order_on_the_wire(self):
        # identity(null=0x00) ++ string8("hi") ++ uint64(1)
        token = AccessToken(identity="", token="hi", expires_at=1)
        expected = bytes.fromhex("00") + bytes([2]) + b"hi" + (1).to_bytes(8, "big")
        self.assertEqual(token.encode_binary(), expected)


class TestAccessTokenJson(unittest.TestCase):
    def test_from_value_dict(self):
        value = {
            "Identity": IDENTITY,
            "Token": "k7m2q5x9r3v4n8p1",
            "ExpiresAt": "2027-05-27T12:00:00+02:00",
        }
        token = AccessToken.from_value(value)
        self.assertEqual(token.identity, IDENTITY)
        self.assertEqual(token.token, "k7m2q5x9r3v4n8p1")
        self.assertEqual(token.expires_at, "2027-05-27T12:00:00+02:00")

    def test_from_value_missing_keys_default_to_empty(self):
        token = AccessToken.from_value({})
        self.assertEqual(token, AccessToken(identity="", token="", expires_at=""))

    def test_encode_json_uses_wire_keys(self):
        token = AccessToken(identity=IDENTITY, token="t", expires_at="2027-05-27T12:00:00+02:00")
        self.assertEqual(
            token.encode_json(),
            {"Identity": IDENTITY, "Token": "t", "ExpiresAt": "2027-05-27T12:00:00+02:00"},
        )


class TestFromValueIdempotent(unittest.TestCase):
    def test_passing_a_record_returns_it(self):
        # A helper can call from_value(client.call_one(...)) uniformly: over
        # binary call_one already yields a decoded record, over JSON a dict.
        token = AccessToken(identity=IDENTITY, token="t", expires_at=0)
        self.assertIs(AccessToken.from_value(token), token)


class TestBytesFallbackPreserved(unittest.TestCase):
    def test_unregistered_structured_type_returns_raw_bytes(self):
        raw = b"\x00\x01\x02 arbitrary structured payload"
        self.assertEqual(decode_payload("mod.some.unregistered_type", raw), raw)

    def test_common_types_unchanged(self):
        # The registry branch must not disturb the known common-type decoders.
        self.assertEqual(decode_payload("uint8", b"\x15"), 21)
        self.assertEqual(decode_payload("string8", b"\x02hi"), "hi")


if __name__ == "__main__":
    unittest.main()
