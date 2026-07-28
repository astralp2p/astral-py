"""The four codec-only endpoint types, against the node's own answers.

No ops ship in `endpoints.py`, so there is no Tier B here. What there is:

- **Tier A** pins each type's layout, zero value, text form, JSON form and
  parser. Every byte vector is a byte `furry-bolt` produced -- `objects.new`
  builds each zero value server-side -- and every field declaration is checked
  against the blueprint `objects.get_blueprint` derived, which is the node
  describing its own type rather than this suite restating a Go struct.
- **Tier C** asks the node for both again, so a node that changed a layout
  fails here rather than corrupting a `mod.nodes.link_info` decode much later.

The claim these types exist to support is design section 0.1's: excluding a
module means excluding its **ops**, not its **types**. `mod.nodes.node_info`
carries endpoints behind numeric tags and `mod.nodes.link_info` carries two in
polymorphic slots, so `nodes` cannot decode without all four.
"""

from __future__ import annotations

import inspect
import unittest

from astral.api import endpoints as endpoints_module
from astral.api.endpoints import (
    ENDPOINTS_TYPES,
    GATEWAY_NETWORK,
    GatewayEndpoint,
    IPEndpoint,
    KCP_NETWORK,
    KcpEndpoint,
    MAX_PORT,
    NODE_INFO_TAGS,
    NODE_INFO_TAG_OF,
    TCP_ALIAS,
    TCP_NETWORK,
    TOR_DEFAULT_PORT,
    TOR_NETWORK,
    TcpEndpoint,
    TorDigest,
    TorEndpoint,
    endpoint_for_tag,
    join_host_port,
    split_host_port,
    tag_for_endpoint,
)
from astral.api.exonet import Endpoint
from astral.api.ip import IPAddress
from astral.blueprint import of as blueprint_of
from astral.blueprint import spec_of
from astral.codec.binary import object_reader, payload_bytes, read_object
from astral.codec.jsoncodec import marshal, unmarshal
from astral.codec.text import decode as text_decode
from astral.codec.text import encode as text_encode
from astral.errors import BadArgumentType, ParseError, ShortRead, StreamCorrupted
from astral.registry import default_blueprints
from astral.spec import Primitive, Ptr, Ref
from astral.types import Identity

import live_support
from mock_apphost import bounded, frame

# --- vectors, all of them bytes the node sent ----------------------------

# `objects.new?type=<name>` on `furry-bolt`. Each is the zero value the node
# built and encoded with its own codec.
LIVE_ZERO_PAYLOADS = {
    "mod.tcp.endpoint": bytes.fromhex("000000"),
    "mod.kcp.endpoint": bytes.fromhex("000000"),
    "mod.tor.endpoint": bytes.fromhex("0000"),
    "mod.tor.digest": b"",
    "mod.gateway.endpoint": bytes.fromhex("0000"),
}

# `objects.get_blueprint?type=<name>` on `furry-bolt`, decoded. The node's own
# description of each type, field name and spec carrier.
LIVE_BLUEPRINTS = {
    "mod.tcp.endpoint": [
        ("IP", Ref("mod.ip.ip_address")),
        ("Port", Primitive("uint16")),
    ],
    "mod.kcp.endpoint": [
        ("IP", Ref("mod.ip.ip_address")),
        ("Port", Primitive("uint16")),
    ],
    "mod.tor.endpoint": [
        ("Digest", Ref("mod.tor.digest")),
        ("Port", Primitive("uint16")),
    ],
    "mod.gateway.endpoint": [
        ("GatewayID", Ptr("identity")),
        ("TargetID", Ptr("identity")),
    ],
}

FURRY_BOLT = Identity.parse(
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)
# The secp256k1 generator, compressed. A real point on the curve, which is
# load-bearing for the live echo test: astral-go's `Identity.ReadFrom`
# validates the point and the node answers **nothing at all** for a frame it
# cannot decode -- not even an `error_message` -- so a made-up 33 bytes turns
# that test into a silent empty stream. Design section 5.2 records that this SDK
# deliberately does not validate; the node does.
OTHER = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

DIGEST_BYTES = bytes(range(35))
DIGEST = TorDigest(DIGEST_BYTES)
DIGEST_TEXT = (
    "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypsaijc.onion"
)

TCP = TcpEndpoint(ip=IPAddress.parse("10.21.0.5"), port=8625)
TCP6 = TcpEndpoint(ip=IPAddress.parse("fe80::1"), port=8625)
KCP = KcpEndpoint(ip=IPAddress.parse("10.21.0.5"), port=8625)
TOR = TorEndpoint(digest=DIGEST, port=1791)
GATEWAY = GatewayEndpoint(gateway_id=FURRY_BOLT, target_id=OTHER)


class LayoutTest(unittest.TestCase):
    """Each type's fields, against the blueprint the node derived."""

    def test_every_field_declaration_matches_the_node_s_blueprint(self):
        for cls in (TcpEndpoint, KcpEndpoint, TorEndpoint, GatewayEndpoint):
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertEqual(
                    [(f.wire_name, f.spec) for f in cls.FIELDS],
                    LIVE_BLUEPRINTS[cls.ASTRAL_TYPE],
                )

    def test_every_derived_blueprint_matches_the_node_s(self):
        """The SDK describes the type the way the node describes it, which is
        what a peer learning the type from a blueprint would receive."""
        for cls in (TcpEndpoint, KcpEndpoint, TorEndpoint, GatewayEndpoint):
            with self.subTest(type=cls.ASTRAL_TYPE):
                got = blueprint_of(cls)
                self.assertEqual(got.type, cls.ASTRAL_TYPE)
                self.assertEqual(got.underlying, "")
                self.assertEqual(
                    [(f.name, spec_of(f.spec)) for f in got.fields],
                    LIVE_BLUEPRINTS[cls.ASTRAL_TYPE],
                )

    def test_every_zero_value_encodes_to_the_bytes_the_node_built(self):
        for cls in (TcpEndpoint, KcpEndpoint, TorEndpoint, GatewayEndpoint):
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertEqual(
                    payload_bytes(cls()), LIVE_ZERO_PAYLOADS[cls.ASTRAL_TYPE]
                )
        self.assertEqual(payload_bytes(TorDigest()), LIVE_ZERO_PAYLOADS["mod.tor.digest"])

    def test_every_type_is_registered_under_the_name_the_node_uses(self):
        for cls in ENDPOINTS_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(default_blueprints().has(cls.ASTRAL_TYPE))
                self.assertIsInstance(default_blueprints().new(cls.ASTRAL_TYPE), cls)

    def test_the_type_sweep_names_every_declared_type(self):
        self.assertEqual(
            tuple(ENDPOINTS_TYPES),
            (TcpEndpoint, KcpEndpoint, TorDigest, TorEndpoint, GatewayEndpoint),
        )

    def test_this_module_declares_no_module_client_and_no_op(self):
        """Design section 0.1: excluding a module means excluding its ops. The
        four modules these types come from are excluded, so no op name appears
        in this file at all."""
        from astral.api.base import ModuleClient
        from astral.client import Client

        clients = [
            value
            for value in vars(endpoints_module).values()
            if inspect.isclass(value)
            and issubclass(value, ModuleClient)
            and value.__module__ == endpoints_module.__name__
        ]
        self.assertEqual(clients, [])
        self.assertFalse(hasattr(Client, "endpoints"))
        source = inspect.getsource(endpoints_module)
        for op in (
            "tcp.new_ephemeral_listener",
            "kcp.set_endpoint_local_port",
            "gateway.node_register",
        ):
            with self.subTest(op=op):
                # Named in the docstring as excluded, never as a query string.
                self.assertNotIn(f'"{op}', source)


class IPEndpointTest(unittest.TestCase):
    """`mod.tcp.endpoint` and `mod.kcp.endpoint`: one shape, two networks."""

    def test_the_two_types_share_one_implementation(self):
        self.assertTrue(issubclass(TcpEndpoint, IPEndpoint))
        self.assertTrue(issubclass(KcpEndpoint, IPEndpoint))
        self.assertEqual(payload_bytes(TCP), payload_bytes(KCP))
        self.assertNotEqual(TCP, KCP)
        self.assertEqual(TCP.network(), TCP_NETWORK)
        self.assertEqual(KCP.network(), KCP_NETWORK)

    def test_a_populated_endpoint_round_trips(self):
        for endpoint in (TCP, TCP6, KCP):
            with self.subTest(endpoint=endpoint.qualified()):
                payload = payload_bytes(endpoint)
                back = read_object(
                    object_reader(payload), type(endpoint).ASTRAL_TYPE
                )
                self.assertEqual(back, endpoint)
                self.assertEqual(payload_bytes(back), payload)

    def test_the_payload_is_the_address_then_the_port(self):
        """`04 0a150005` is the address, `21b1` is 8625 big-endian."""
        self.assertEqual(payload_bytes(TCP).hex(), "040a15000521b1")

    def test_the_address_brackets_an_ipv6_host(self):
        """Go's `net.JoinHostPort`, which is what `Address()` calls."""
        self.assertEqual(TCP.address(), "10.21.0.5:8625")
        self.assertEqual(TCP6.address(), "[fe80::1]:8625")
        self.assertEqual(join_host_port("10.21.0.5", 8625), "10.21.0.5:8625")
        self.assertEqual(join_host_port("fe80::1", 8625), "[fe80::1]:8625")

    def test_the_text_and_json_forms_are_the_address(self):
        for endpoint in (TCP, TCP6, KCP):
            with self.subTest(endpoint=endpoint.address()):
                self.assertEqual(endpoint.text(), endpoint.address())
                self.assertEqual(marshal(endpoint), endpoint.address())
                self.assertEqual(
                    unmarshal(type(endpoint).ASTRAL_TYPE, endpoint.address()),
                    endpoint,
                )

    def test_the_text_codec_round_trips(self):
        line = text_encode(TCP)
        self.assertEqual(line, "#[mod.tcp.endpoint] 10.21.0.5:8625")
        self.assertEqual(text_decode(line), TCP)
        self.assertEqual(text_decode(text_encode(TCP6)), TCP6)

    def test_the_zero_endpoint_round_trips_through_its_own_text_form(self):
        """`<nil>:0` is what `Address()` renders for an unset IP, and the parser
        reads it back. astral-go reaches the same value only because
        `ip.ParseIP` drops every error."""
        zero = TcpEndpoint()
        self.assertEqual(zero.text(), "<nil>:0")
        self.assertTrue(zero.is_zero())
        self.assertEqual(TcpEndpoint.parse(zero.text()), zero)

    def test_a_host_that_is_not_an_address_is_refused(self):
        """astral-go's `ip.ParseIP` never returns an error, so
        `tcp.ParseEndpoint('garbage:80')` succeeds with a nil IP. Not ported."""
        for text in ("garbage:80", "1.2.3:80", "010.1.1.1:80", "example.com:80"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    TcpEndpoint.parse(text)

    def test_a_port_outside_uint16_is_refused(self):
        """astral-go checks `(port >> 16) > 0`, which every negative number
        passes, so `1.2.3.4:-1` becomes port 65535. Not ported."""
        for text in ("10.21.0.5:-1", "10.21.0.5:65536", "10.21.0.5:99999"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    TcpEndpoint.parse(text)
        self.assertEqual(TcpEndpoint.parse(f"10.21.0.5:{MAX_PORT}").port, MAX_PORT)
        self.assertEqual(TcpEndpoint.parse("10.21.0.5:0").port, 0)

    def test_a_port_that_is_not_a_number_is_refused(self):
        """`int()` is wider than Go's `strconv.Atoi`: it strips whitespace,
        accepts `_` as a group separator and reads every Unicode decimal digit.
        A port the node's parser rejects must not parse here."""
        for text in (
            "10.21.0.5:",
            "10.21.0.5:http",
            "10.21.0.5:8 625",
            "10.21.0.5: 8625",
            "10.21.0.5:8_625",
            "10.21.0.5:٨٦٢٥",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    TcpEndpoint.parse(text)

    def test_parse_refuses_a_value_that_is_not_text(self):
        for value in (8625, b"10.21.0.5:8625", None):
            with self.subTest(value=value):
                with self.assertRaises(ParseError):
                    TcpEndpoint.parse(value)  # type: ignore[arg-type]

    def test_the_host_port_split_is_go_s(self):
        self.assertEqual(split_host_port("10.21.0.5:8625"), ("10.21.0.5", "8625"))
        self.assertEqual(split_host_port("[fe80::1]:8625"), ("fe80::1", "8625"))
        for text in ("fe80::1:8625", "10.21.0.5", "[fe80::1]8625", "[fe80::1"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    split_host_port(text)

    def test_json_refuses_a_value_that_is_not_a_string(self):
        with self.assertRaises(ParseError):
            unmarshal("mod.tcp.endpoint", 8625)


class TorDigestTest(unittest.TestCase):
    """`mod.tor.digest`: 35 raw bytes, and the type that cannot be declared."""

    def test_it_has_no_derivable_blueprint(self):
        """The node refuses too: `objects.get_blueprint?type=mod.tor.digest`
        answers `BlueprintFromType: want struct or *struct, got tor.Digest`.
        Design section 2.5 names `mod.tor.endpoint` as the escape hatch and the
        reason it gives -- 35 raw bytes with no length prefix -- is this type."""
        self.assertFalse(TorDigest.DERIVABLE)
        with self.assertRaises(Exception) as caught:
            blueprint_of(TorDigest)
        self.assertIn("mod.tor.digest", str(caught.exception))

    def test_the_payload_is_thirty_five_bare_bytes(self):
        payload = payload_bytes(DIGEST)
        self.assertEqual(len(payload), 35)
        self.assertEqual(payload, DIGEST_BYTES)
        self.assertEqual(
            read_object(object_reader(payload), "mod.tor.digest"), DIGEST
        )

    def test_a_short_payload_is_a_short_read(self):
        """astral-go's `io.ReadFull` reports the same fault. The length is not
        self-describing, so a lenient reader would have nothing to resynchronise
        on."""
        with self.assertRaises(ShortRead):
            read_object(object_reader(DIGEST_BYTES[:34]), "mod.tor.digest")

    def test_the_zero_digest_encodes_and_cannot_be_decoded(self):
        """astral-go's own asymmetry: `WriteTo` has no length check and
        `ReadFrom` demands 35. The node proves it -- `objects.new?type=
        mod.tor.digest` answers a zero-byte frame."""
        self.assertEqual(payload_bytes(TorDigest()), b"")
        with self.assertRaises(ShortRead):
            read_object(object_reader(b""), "mod.tor.digest")

    def test_the_text_form_is_lowercase_base32_and_onion(self):
        self.assertEqual(DIGEST.text(), DIGEST_TEXT)
        self.assertEqual(str(DIGEST), DIGEST_TEXT)
        self.assertEqual(marshal(DIGEST), DIGEST_TEXT)

    def test_parsing_accepts_either_case_and_an_optional_suffix(self):
        self.assertEqual(TorDigest.parse(DIGEST_TEXT), DIGEST)
        self.assertEqual(TorDigest.parse(DIGEST_TEXT.upper()), DIGEST)
        self.assertEqual(
            TorDigest.parse(DIGEST_TEXT.removesuffix(".onion")), DIGEST
        )
        self.assertEqual(unmarshal("mod.tor.digest", DIGEST_TEXT), DIGEST)

    def test_a_digest_of_the_wrong_length_is_refused(self):
        import base64

        for data in (b"", bytes(10), bytes(36)):
            with self.subTest(length=len(data)):
                text = base64.b32encode(data).decode().lower() + ".onion"
                with self.assertRaises(ParseError) as caught:
                    TorDigest.parse(text)
                self.assertIn("35 bytes", str(caught.exception))

    def test_a_non_base32_form_is_refused(self):
        for text in ("not base32!.onion", "aaa.onion", "1189.onion"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    TorDigest.parse(text)

    def test_construction_takes_bytes_and_refuses_text(self):
        with self.assertRaises(BadArgumentType) as caught:
            TorDigest(DIGEST_TEXT)  # type: ignore[arg-type]
        self.assertIn("parse()", str(caught.exception))
        with self.assertRaises(BadArgumentType):
            TorDigest(35)  # type: ignore[arg-type]

    def test_equality_and_hashing_are_by_value(self):
        self.assertEqual(TorDigest(DIGEST_BYTES), DIGEST)
        self.assertEqual(len({DIGEST, TorDigest(DIGEST_BYTES)}), 1)
        self.assertNotEqual(DIGEST, TorDigest(bytes(35)))
        self.assertNotEqual(DIGEST, DIGEST_BYTES)


class TorEndpointTest(unittest.TestCase):
    """`mod.tor.endpoint`: a digest and a port, with two text forms."""

    def test_the_payload_is_the_digest_then_the_port(self):
        payload = payload_bytes(TOR)
        self.assertEqual(len(payload), 37)
        self.assertEqual(payload, DIGEST_BYTES + (1791).to_bytes(2, "big"))
        self.assertEqual(
            read_object(object_reader(payload), "mod.tor.endpoint"), TOR
        )

    def test_the_zero_endpoint_encodes_to_two_bytes_and_cannot_be_decoded(self):
        """`objects.new?type=mod.tor.endpoint` answers `0000`, which its own
        reader wants 37 bytes for. astral-go cannot read its own zero value and
        neither can this -- the encoder matches the node, the decoder matches
        the node's failure."""
        self.assertEqual(payload_bytes(TorEndpoint()), bytes.fromhex("0000"))
        with self.assertRaises(ShortRead):
            read_object(object_reader(bytes.fromhex("0000")), "mod.tor.endpoint")

    def test_the_address_and_the_text_form_differ_for_the_zero_value(self):
        """astral-go's `Address()` is `unknown` and its `MarshalText` is
        `.onion:0`. Both reproduced; neither invented."""
        zero = TorEndpoint()
        self.assertTrue(zero.is_zero())
        self.assertEqual(zero.address(), "unknown")
        self.assertEqual(zero.text(), ".onion:0")
        self.assertEqual(marshal(zero), "unknown")

    def test_the_zero_value_round_trips_through_json_and_not_through_text(self):
        """The one round-trippable spelling is `unknown`, which is what
        `MarshalJSON` emits. `MarshalText`'s `.onion:0` is refused by
        astral-go's own `UnmarshalText`, and this SDK does not invent a third
        spelling to close the hole."""
        zero = TorEndpoint()
        self.assertEqual(unmarshal("mod.tor.endpoint", "unknown"), zero)
        self.assertEqual(TorEndpoint.parse("unknown"), zero)
        with self.assertRaises(ParseError):
            TorEndpoint.parse(zero.text())

    def test_a_populated_endpoint_renders_the_same_string_three_ways(self):
        expected = f"{DIGEST_TEXT}:1791"
        self.assertEqual(TOR.address(), expected)
        self.assertEqual(TOR.text(), expected)
        self.assertEqual(marshal(TOR), expected)
        self.assertEqual(TOR.qualified(), f"tor:{expected}")

    def test_parsing_defaults_a_missing_port_to_astrald_s(self):
        """astrald's parser supplies 1791; astral-go's `UnmarshalText` requires
        a port. Both accepted, so a string the node reads is a string this SDK
        reads."""
        self.assertEqual(TOR_DEFAULT_PORT, 1791)
        self.assertEqual(TorEndpoint.parse(DIGEST_TEXT), TOR)
        self.assertEqual(TorEndpoint.parse(f"{DIGEST_TEXT}:9050").port, 9050)

    def test_a_port_outside_uint16_is_refused(self):
        """astral-go's `UnmarshalText` has no check at all and truncates through
        `astral.Uint16`, so `:99999` becomes 33999. Not ported."""
        for port in ("-1", "65536", "99999"):
            with self.subTest(port=port):
                with self.assertRaises(ParseError):
                    TorEndpoint.parse(f"{DIGEST_TEXT}:{port}")

    def test_the_network_is_tor(self):
        self.assertEqual(TOR.network(), TOR_NETWORK)
        self.assertEqual(TOR_NETWORK, "tor")

    def test_the_text_codec_round_trips_a_populated_endpoint(self):
        self.assertEqual(text_decode(text_encode(TOR)), TOR)


class GatewayEndpointTest(unittest.TestCase):
    """`mod.gateway.endpoint`: two pointer identities."""

    def test_the_payload_is_two_flagged_identities(self):
        payload = payload_bytes(GATEWAY)
        self.assertEqual(len(payload), 68)
        self.assertEqual(payload, b"\x01" + FURRY_BOLT.key + b"\x01" + OTHER.key)
        self.assertEqual(
            read_object(object_reader(payload), "mod.gateway.endpoint"), GATEWAY
        )

    def test_the_zero_value_is_two_absent_flags(self):
        zero = GatewayEndpoint()
        self.assertIsNone(zero.gateway_id)
        self.assertIsNone(zero.target_id)
        self.assertTrue(zero.is_zero())
        self.assertEqual(payload_bytes(zero), bytes.fromhex("0000"))

    def test_an_absent_identity_and_the_zero_identity_are_different_bytes(self):
        """A nil pointer and a pointer to the zero identity, exactly as in Go.
        Both render the same address, and neither re-encodes to the other."""
        absent = GatewayEndpoint()
        present = GatewayEndpoint(
            gateway_id=Identity.ANYONE, target_id=Identity.ANYONE
        )
        self.assertEqual(absent.address(), present.address())
        self.assertTrue(present.is_zero())
        self.assertNotEqual(payload_bytes(absent), payload_bytes(present))
        self.assertEqual(len(payload_bytes(present)), 68)

    def test_the_address_is_the_two_identities_colon_joined(self):
        self.assertEqual(GATEWAY.address(), f"{FURRY_BOLT.hex()}:{OTHER.hex()}")
        self.assertEqual(GATEWAY.qualified(), f"gw:{GATEWAY.address()}")
        self.assertEqual(GATEWAY.network(), GATEWAY_NETWORK)

    def test_an_absent_identity_renders_as_sixty_six_zeros(self):
        """astral-go's `Identity.String()` answers `anyoneKey` for a nil
        receiver, which is 33 zero bytes in hex."""
        self.assertEqual(GatewayEndpoint().address(), f"{'00' * 33}:{'00' * 33}")

    def test_parsing_produces_identities_and_never_absence(self):
        parsed = GatewayEndpoint.parse(GATEWAY.address())
        self.assertEqual(parsed, GATEWAY)
        zero = GatewayEndpoint.parse(GatewayEndpoint().address())
        self.assertEqual(zero.gateway_id, Identity.ANYONE)
        self.assertIsNotNone(zero.target_id)
        self.assertNotEqual(payload_bytes(zero), payload_bytes(GatewayEndpoint()))

    def test_a_malformed_form_is_refused(self):
        for text in (FURRY_BOLT.hex(), "", f"{FURRY_BOLT.hex()}:nope", "a:b"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    GatewayEndpoint.parse(text)

    def test_a_gateway_equal_to_its_target_is_accepted_here(self):
        """astrald's parser refuses one and resolves both halves through the
        directory. Both need a node; a wire type has none."""
        same = GatewayEndpoint.parse(f"{FURRY_BOLT.hex()}:{FURRY_BOLT.hex()}")
        self.assertEqual(same.gateway_id, same.target_id)

    def test_the_text_and_json_forms_are_the_address(self):
        self.assertEqual(GATEWAY.text(), GATEWAY.address())
        self.assertEqual(marshal(GATEWAY), GATEWAY.address())
        self.assertEqual(
            unmarshal("mod.gateway.endpoint", GATEWAY.address()), GATEWAY
        )
        self.assertEqual(text_decode(text_encode(GATEWAY)), GATEWAY)


class NodeInfoTagTest(unittest.TestCase):
    """The numeric tags `mod.nodes.node_info` carries, and nothing else."""

    def test_the_three_tags_are_the_three_astral_go_writes(self):
        self.assertEqual(
            {tag: cls.ASTRAL_TYPE for tag, cls in NODE_INFO_TAGS.items()},
            {
                0: "mod.tcp.endpoint",
                1: "mod.tor.endpoint",
                2: "mod.gateway.endpoint",
            },
        )
        self.assertEqual(len(NODE_INFO_TAG_OF), 3)

    def test_a_tag_resolves_to_its_class_and_back(self):
        for tag, cls in NODE_INFO_TAGS.items():
            with self.subTest(tag=tag):
                self.assertIs(endpoint_for_tag(tag), cls)
                self.assertEqual(tag_for_endpoint(cls()), tag)

    def test_an_unknown_tag_poisons_the_stream(self):
        """The payload that follows a tag has no length, so a reader that
        skipped it would resynchronise on nothing. astral-go aborts the frame in
        the same place."""
        for tag in (3, 255, -1):
            with self.subTest(tag=tag):
                with self.assertRaises(StreamCorrupted):
                    endpoint_for_tag(tag)

    def test_a_kcp_endpoint_has_no_tag(self):
        """Which is why a node advertising KCP endpoints cannot be encoded into
        an invite string by astral-go at all."""
        with self.assertRaises(StreamCorrupted) as caught:
            tag_for_endpoint(KcpEndpoint())
        self.assertIn("mod.kcp.endpoint", str(caught.exception))

    def test_the_tag_table_agrees_with_the_one_node_info_reads(self):
        """Two spellings of one table, so the two must agree byte for byte.

        `api/nodes.py` keys its copy by type **name** and resolves through the
        registry, which is what its hand-rolled `node_info` codec needs;
        `endpoints.py` keys by **class**, which is what a writer choosing a tag
        needs. Neither can be derived from the other without one module importing
        the other, so the guard against silent drift is this assertion rather
        than a shared constant.
        """
        try:
            from astral.api.nodes import ENDPOINT_TAGS
        except ImportError:  # pragma: no cover -- `nodes` is a Tier 3 module
            self.skipTest("astral.api.nodes is not present")
        self.assertEqual(
            ENDPOINT_TAGS,
            {tag: cls.ASTRAL_TYPE for tag, cls in NODE_INFO_TAGS.items()},
        )

    def test_the_tags_and_the_registry_are_different_tables(self):
        """The registry is keyed by network name and holds four classes; the
        tags are keyed by a byte and hold three. `kcp` is in one and not the
        other."""
        from astral.api.exonet import endpoint_types

        self.assertEqual(len(endpoint_types().classes()), 4)
        self.assertEqual(len(NODE_INFO_TAGS), 3)
        self.assertIn(KcpEndpoint, endpoint_types().classes())
        self.assertNotIn(KcpEndpoint, NODE_INFO_TAG_OF)


class NetworkNameTest(unittest.TestCase):
    """The four network names, and the one alias."""

    def test_the_names_are_the_ones_astrald_registers(self):
        self.assertEqual(TCP_NETWORK, "tcp")
        self.assertEqual(TCP_ALIAS, "inet")
        self.assertEqual(KCP_NETWORK, "kcp")
        self.assertEqual(TOR_NETWORK, "tor")
        self.assertEqual(GATEWAY_NETWORK, "gw")

    def test_the_gateway_module_and_its_network_have_different_names(self):
        """`mod/gateway` registers the network `gw`. Conflating them makes
        `gateway:<id>:<id>` an unsupported network."""
        self.assertNotEqual(GATEWAY_NETWORK, "gateway")
        self.assertEqual(GatewayEndpoint().network(), "gw")

    def test_every_endpoint_is_an_exonet_endpoint(self):
        for endpoint in (TCP, KCP, TOR, GATEWAY):
            with self.subTest(endpoint=type(endpoint).__name__):
                self.assertIsInstance(endpoint, Endpoint)


class LiveEndpointsTest(live_support.LiveCase):
    """The node's own layout and zero value for each of the five types.

    Read-only. `objects.new` builds a zero value server-side and
    `objects.get_blueprint` describes a type; neither writes anything.
    """

    @bounded(30.0)
    async def test_the_node_builds_the_zero_value_this_module_builds(self):
        async with await self.client() as client:
            for name, payload in sorted(LIVE_ZERO_PAYLOADS.items()):
                with self.subTest(type=name):
                    body = await client.call_raw(
                        f"objects.new?type={name}", timeout=20.0
                    )
                    self.assertEqual(body, frame(name, payload))
                    built = default_blueprints().new(name)
                    self.assertEqual(payload_bytes(built), payload)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_derives_the_blueprint_this_module_derives(self):
        """Four types the node can describe, described identically."""
        async with await self.client() as client:
            for name, fields in sorted(LIVE_BLUEPRINTS.items()):
                with self.subTest(type=name):
                    got = await client.call_one(
                        f"objects.get_blueprint?type={name}", timeout=20.0
                    )
                    self.assertEqual(str(got.type), name)
                    self.assertEqual(
                        [(str(f.name), spec_of(f.spec)) for f in got.fields], fields
                    )
                    mine = blueprint_of(type(default_blueprints().new(name)))
                    self.assertEqual(
                        [(f.name, spec_of(f.spec)) for f in mine.fields], fields
                    )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_refuses_to_describe_a_digest(self):
        """`mod.tor.digest` has no derivable blueprint on either side. The SDK
        marks it non-derivable and the node answers an `error_message`."""
        from astral.errors import RemoteError

        async with await self.client() as client:
            with self.assertRaises(RemoteError) as caught:
                await client.call_one(
                    "objects.get_blueprint?type=mod.tor.digest", timeout=20.0
                )
        self.assertIn("tor.Digest", str(caught.exception))
        self.assertFalse(TorDigest.DERIVABLE)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_packed_endpoint_survives_the_node_s_own_codec(self):
        """`objects.echo?strict=true` drops the unparsed-object fallback, so the
        node decodes the frame through its own registry and re-encodes it from
        the decoded value. A byte-identical answer is the node agreeing with
        this module's encoder for a populated endpoint, not only a zero one."""
        async with await self.client() as client:
            for endpoint in (TCP, TCP6, KCP, GATEWAY):
                name = type(endpoint).ASTRAL_TYPE
                with self.subTest(type=name):
                    async with client.stream(
                        "objects.echo?strict=true", timeout=20.0
                    ) as stream:
                        await stream.send(endpoint)
                        await stream.send_eos()
                        got = [obj async for obj in stream]
                    self.assertEqual(got, [endpoint])
                    self.assertEqual(payload_bytes(got[0]), payload_bytes(endpoint))
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
