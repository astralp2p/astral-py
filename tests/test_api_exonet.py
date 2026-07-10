"""Tests for the exonet endpoint records (``mod.tcp/tor/gateway.endpoint``).

Each endpoint is byte-pinned against its astral-go ``structValue`` binary payload
(``api/{tcp,tor,gateway}/endpoint.go``) and round-tripped over BOTH framings — the
binary struct form and the bare address-STRING JSON form (astral-go's endpoints
``MarshalJSON`` to a plain address string, not a ``{Field: value}`` object). A final
test carries a real ``TcpEndpoint`` inside an ``("object",)`` field over both
framings, proving the polymorphic kind decodes a registered endpoint.
"""

import base64
import os
import socket
import sys
import unittest
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral.api  # noqa: F401  (fires @register for the endpoint records)
from astral.api.exonet import GatewayEndpoint, TcpEndpoint, TorEndpoint
from astral.codec import BinaryReader, BinaryWriter
from astral.objects import AstralObject
from astral.record import Record
from astral.registry import record_for

IDENTITY = "0282fee8775757cdd8fda8b220195f5b8611312cd145c5a1a3aa55df210e779b2c"
IDENTITY2 = "0344b8f8b9d5f3a2c1e0d7b6a5948372615043f2e1d0c9b8a79685f4e3d2c1b0a9"


def _binary_roundtrip(record):
    return type(record).read_from(BinaryReader(record.encode_binary()))


def _json_roundtrip(record):
    return type(record).from_value(record.encode_json())


class TestRegistration(unittest.TestCase):
    def test_endpoints_are_registered(self):
        self.assertIs(record_for("mod.tcp.endpoint"), TcpEndpoint)
        self.assertIs(record_for("mod.tor.endpoint"), TorEndpoint)
        self.assertIs(record_for("mod.gateway.endpoint"), GatewayEndpoint)


class TestTcpEndpoint(unittest.TestCase):
    def _ep(self):
        return TcpEndpoint(ip=socket.inet_pton(socket.AF_INET, "192.168.1.1"), port=8080)

    def test_binary_pin(self):
        # structValue: IP as bytes8 (uint8 len=4 ++ 4 IPv4 bytes) ++ Port uint16.
        expected = bytes([4]) + b"\xc0\xa8\x01\x01" + (8080).to_bytes(2, "big")
        self.assertEqual(self._ep().encode_binary(), expected)

    def test_binary_roundtrip(self):
        ep = self._ep()
        self.assertEqual(_binary_roundtrip(ep), ep)

    def test_address_string(self):
        self.assertEqual(self._ep().address, "192.168.1.1:8080")

    def test_json_is_address_string(self):
        self.assertEqual(self._ep().encode_json(), "192.168.1.1:8080")

    def test_json_roundtrip_from_string(self):
        ep = self._ep()
        self.assertEqual(_json_roundtrip(ep), ep)

    def test_from_value_accepts_fields_dict(self):
        # The generic record dict form is still accepted (base64 IP, per Record).
        b64 = base64.b64encode(b"\xc0\xa8\x01\x01").decode()
        ep = TcpEndpoint.from_value({"IP": b64, "Port": 8080})
        self.assertEqual(ep, self._ep())

    def test_ipv6_address_is_bracketed(self):
        raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ep = TcpEndpoint(ip=raw, port=443)
        self.assertEqual(ep.address, "[2001:db8::1]:443")
        self.assertEqual(_json_roundtrip(ep), ep)

    def test_ipv6_binary_pin(self):
        raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ep = TcpEndpoint(ip=raw, port=443)
        expected = bytes([16]) + raw + (443).to_bytes(2, "big")
        self.assertEqual(ep.encode_binary(), expected)


class TestTorEndpoint(unittest.TestCase):
    def _ep(self):
        return TorEndpoint(digest=bytes(range(35)), port=9050)

    def test_binary_pin(self):
        # structValue: 35 RAW digest bytes (no length prefix) ++ Port uint16.
        expected = bytes(range(35)) + (9050).to_bytes(2, "big")
        self.assertEqual(self._ep().encode_binary(), expected)
        self.assertEqual(len(self._ep().encode_binary()), 35 + 2)

    def test_binary_roundtrip(self):
        ep = self._ep()
        self.assertEqual(_binary_roundtrip(ep), ep)

    def test_address_is_onion(self):
        onion = base64.b32encode(bytes(range(35))).decode().lower() + ".onion"
        self.assertEqual(self._ep().address, f"{onion}:9050")

    def test_json_is_address_string(self):
        self.assertEqual(self._ep().encode_json(), self._ep().address)

    def test_json_roundtrip_from_string(self):
        ep = self._ep()
        self.assertEqual(_json_roundtrip(ep), ep)


class TestGatewayEndpoint(unittest.TestCase):
    def _ep(self):
        return GatewayEndpoint(gateway_id=IDENTITY, target_id=IDENTITY2)

    def test_binary_pin(self):
        # structValue: GatewayID then TargetID, each *Identity via ptrValue:
        # 0x01 present-flag ++ 33 raw key bytes.
        expected = (
            b"\x01" + bytes.fromhex(IDENTITY)
            + b"\x01" + bytes.fromhex(IDENTITY2)
        )
        self.assertEqual(self._ep().encode_binary(), expected)

    def test_binary_roundtrip(self):
        ep = self._ep()
        self.assertEqual(_binary_roundtrip(ep), ep)

    def test_address_string(self):
        self.assertEqual(self._ep().address, f"{IDENTITY}:{IDENTITY2}")

    def test_json_is_address_string(self):
        self.assertEqual(self._ep().encode_json(), f"{IDENTITY}:{IDENTITY2}")

    def test_json_roundtrip_from_string(self):
        ep = self._ep()
        self.assertEqual(_json_roundtrip(ep), ep)

    def test_zero_identity_maps_to_hex_zeros(self):
        # astral-py's empty-hex zero identity stringifies to 66 hex zeros (astral-go
        # anyoneKey); the address round-trips back to "".
        ep = GatewayEndpoint(gateway_id="", target_id=IDENTITY2)
        self.assertEqual(ep.address, f"{'00' * 33}:{IDENTITY2}")
        self.assertEqual(_json_roundtrip(ep), ep)


# --- ("object",) field carrying a real registered endpoint -------------------


@dataclass(frozen=True)
class Envelope(Record):
    """A record with an ``("object",)`` field, to carry an endpoint polymorphically."""

    TYPE = "test.exonet.envelope"
    FIELDS = (("endpoint", "Endpoint", ("object",)),)
    endpoint: object = None


class TestEndpointInObjectField(unittest.TestCase):
    def _env(self):
        ep = TcpEndpoint(ip=socket.inet_pton(socket.AF_INET, "10.0.0.5"), port=1234)
        return Envelope(endpoint=AstralObject("mod.tcp.endpoint", ep))

    def test_binary_roundtrip(self):
        env = self._env()
        got = _binary_roundtrip(env)
        self.assertEqual(got, env)
        self.assertIsInstance(got.endpoint.value, TcpEndpoint)
        self.assertEqual(got.endpoint.value.port, 1234)

    def test_binary_layout(self):
        env = self._env()
        type_str = "mod.tcp.endpoint"
        ep_bytes = env.endpoint.value.encode_binary()
        expected = bytes([len(type_str)]) + type_str.encode() + ep_bytes
        self.assertEqual(env.encode_binary(), expected)

    def test_json_roundtrip(self):
        env = self._env()
        value = env.encode_json()
        # The inner endpoint JSON is its address string (endpoints marshal to text).
        self.assertEqual(
            value,
            {"Endpoint": {"Type": "mod.tcp.endpoint", "Object": "10.0.0.5:1234"}},
        )
        got = _json_roundtrip(env)
        self.assertEqual(got, env)
        self.assertIsInstance(got.endpoint.value, TcpEndpoint)


if __name__ == "__main__":
    unittest.main()
