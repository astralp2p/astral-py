"""The `nodes` module client, its eleven wire types, and the Tier 3 gate.

Three tiers in one file, because the same claim is made at each and the three
must agree:

- **Tier A** pins the wire against **astral-go's own output**. Every vector in
  `GO_VECTORS` was produced by a Go program linked against
  `astral-go/api/nodes` at `5c18d9c`, printing
  `hex.EncodeToString` of what `WriteTo` wrote; the base62 strings are what
  `MarshalText` returned. So a round trip through them cannot agree with itself
  while disagreeing with the reference. The three `node_info` vectors and their
  base62 strings were regenerated the same way at astral-go `221ce52`, where
  `NodeInfo` encodes through `astral.Objectify`.
- **Tier B** pins the seven ops against `MockApphost`: the query string each one
  builds, the answer each one accepts, and the gate refusing every one of them
  before a byte reaches the node.
- **Tier C** runs the three read-only ops against a real node. Nothing here
  mutates: no `add_endpoint`, no `close_link`, no `new_link`, no
  `migrate_session`, per design section 7.3.

**A zero `mod.nodes.node_info` encodes.** `WriteTo` hands the nil
`*astral.Identity` the registry's zero value holds to `astral.Objectify`, which
writes it as an absent presence flag. The zero value is asserted from the vector,
and `ReferenceClaimTest` re-reads the source.
"""

from __future__ import annotations

import ipaddress
import unittest

import astral
from astral.api.endpoints import GatewayEndpoint, KcpEndpoint, TcpEndpoint, TorDigest, TorEndpoint
from astral.api.ip import IPAddress
from astral.api.nat import Endpoint as NatEndpoint
from astral.api.nodes import (
    BASE62_ALPHABET,
    NODES_TYPES,
    OP_ADD_ENDPOINT,
    OP_CLOSE_LINK,
    OP_LINKS,
    OP_MIGRATE_SESSION,
    OP_NEW_LINK,
    OP_RESOLVE_ENDPOINTS,
    OP_SESSIONS,
    EndpointWithTTL,
    LinkClosedEvent,
    LinkCreatedEvent,
    LinkInfo,
    LinkPressureEvent,
    MigrateSignal,
    NewObservedEndpointEvent,
    NodeInfo,
    Nodes,
    ObservedEndpointMessage,
    RelayForAction,
    SessionInfo,
    base62_decode,
    base62_encode,
)
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import (
    BadArgument,
    FeatureUnavailable,
    ParseError,
    ProtocolError,
    StreamCorrupted,
)
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive, Ptr, Slice
from astral.types import Duration, Identity, Nonce

import live_support
import reference
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    MockApphost,
    bounded,
    socket_fds,
)

OTHER = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

# The tor digest `furry-bolt` advertises for itself, captured this session from
# `nodes.resolve_endpoints`.
TOR_DIGEST = bytes.fromhex(
    "e931ffbc1e28eab1b17223cc87060b590d85b0206f03b4666ad4e293bb68abe27ca203"
)


def ip(text: str) -> IPAddress:
    return IPAddress(ipaddress.ip_address(text).packed)


TCP_EP = TcpEndpoint(ip=ip("10.21.0.5"), port=1791)
TOR_EP = TorEndpoint(digest=TorDigest(TOR_DIGEST), port=1791)
GW_EP = GatewayEndpoint(gateway_id=FURRY_BOLT, target_id=OTHER)
KCP_EP = KcpEndpoint(ip=ip("10.21.0.5"), port=1792)
NAT_EP = NatEndpoint(ip=ip("10.21.0.5"), port=1793)

# Every string below is astral-go's own output, printed by a Go program linked
# against `api/nodes` at astral-go `5c18d9c`; the three `node_info` vectors at
# astral-go `221ce52`.
GO_VECTORS = {
    "node_info_full": (
        "0a66757272792d626f6c74"
        "01" "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
        "00000005"
        "106d6f642e7463702e656e64706f696e74" "040a15000506ff"
        "106d6f642e746f722e656e64706f696e74"
        "e931ffbc1e28eab1b17223cc87060b590d85b0206f03b4666ad4e293bb68abe27ca20306ff"
        "146d6f642e676174657761792e656e64706f696e74"
        "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "106d6f642e6b63702e656e64706f696e74" "040a1500050700"
        "0c6e61742e656e64706f696e74" "040a1500050701"
    ),
    "node_info_zero": "00" "00" "00000000",
    "node_info_alias_only": (
        "0a66757272792d626f6c74"
        "01" "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
        "00000000"
    ),
    "link_info": (
        "0102030405060708"
        "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "106d6f642e7463702e656e64706f696e74" "040a15000506ff"
        "106d6f642e746f722e656e64706f696e74"
        "e931ffbc1e28eab1b17223cc87060b590d85b0206f03b4666ad4e293bb68abe27ca20306ff"
        "01" "03746370" "00" "00000000000004d2"
    ),
    "link_info_zero": "00" * 23,
    "session_info": (
        "1122334455667788"
        "0102030405060708"
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "01"
        "0011" "6f626a656374732e726561643f69643d78"
        "0000000000001000"
        "00000014f46b0400"
    ),
    "session_info_zero": "00" * 36,
    "ewt_with_ttl": "106d6f642e7463702e656e64706f696e74040a15000506ff0100093a80",
    "ewt_no_ttl": "106d6f642e7463702e656e64706f696e74040a15000506ff00",
    "migrate_signal": "05726561647900010000",
    "link_created_event": (
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "0000000000000007" "00000003"
    ),
    "link_closed_event": (
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "01" "02"
    ),
    "link_pressure_event": (
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "0000000000000009"
    ),
    "new_observed_endpoint_event": "",
    "observed_endpoint_message": "106d6f642e7463702e656e64706f696e74040a15000506ff",
}

# `base62.Encode` of each blob above, as astral-go's `MarshalText` returned it.
GO_BASE62 = {
    "node_info_full": (
        "BcQBAUhCEQnbp9Gck5WZuQXYuxAAHUAAVoAB05WavBHZuVmLwN2auQ2btBBmXgvFbFo8ZlNKO3y2"
        "8vpAHswhOXpYgWFr7yde9zMfmnABEue6twIwvxLHlq1WKfLLlq531HwXNvxy8AG5yuIlEcyOQA05"
        "WavBHZuVmL5F2dlRXYn5CZv1GFf3gBElPxXFtdnUcqVzMaH4NQgtwGyaBDOk5RkL2YVHFP49fxkO"
        "dul2bwRmbl5icvRnLk9WbQ8vBFAQFKQAdul2bwRmbl5CcjRnLk9WbQUAAAAQ461bhRgfGvcUqWbp"
        "8XWKVzvrPgvaeGLzDYkL7iUSwJ7ABQHbvJWL5Jnc1ZmC"
    ),
    "node_info_zero": "AAAAAAAA",
    "node_info_alias_only": (
        "AAAAAEue6twIwvxLHlq1WKfLLlq531HwXNvxy8AG5yuIlEcyOQA0x2bi1SekTu6MTB"
    ),
}

# `base62.Encode(hex)` for arbitrary blobs, from the same run. The algorithm is
# a bit stream, not a base conversion, so these settle the port and nothing else
# would: an implementation that treated the input as one big integer agrees with
# it on `00` and disagrees on almost everything longer.
GO_BASE62_SCALARS = {
    "": "",
    "00": "AA",
    "01": "BA",
    "ff": "fH",
    "0001": "BAA",
    "ffff": "fffB",
    "68656c6c6f": "vxGblhG",
    "000000": "AAAA",
    "0102030405060708090a0b0c0d0e0f": "P4QDMsgCJgwBGUABDIQA",
    "ffffffffffffffffffffffffffffffffff": "fffffffffffffffffffffffffffB",
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1": (
        "hrXvFGBeb8yRpatlyfySpae76D4rm3YZeAG5yuIlEcyOA"
    ),
    "7e7f8081fefdfc": "83vfDEwf5H",
    "1f3e": "e5D",
    "3f": "fB",
}


def vector(name: str) -> bytes:
    return bytes.fromhex(GO_VECTORS[name])


def frame(obj: object) -> tuple[str, bytes]:
    """One response frame: an object's type name and its payload."""
    return (obj.ASTRAL_TYPE, payload_bytes(obj))  # type: ignore[attr-defined]


def frame_error(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ACK_FRAME = ("ack", b"")


# --- Tier A: base62, which nothing else in the SDK uses -------------------


class Base62Test(unittest.TestCase):
    """The port of `jxskiss/base62`, against the reference's own output."""

    def test_the_alphabet_is_letters_before_digits(self):
        """`[A-Za-z0-9]`, not the `[0-9A-Za-z]` most base62 tables use. A table
        in the other order encodes every input to a different string."""
        self.assertEqual(len(BASE62_ALPHABET), 62)
        self.assertEqual(len(set(BASE62_ALPHABET)), 62)
        self.assertTrue(BASE62_ALPHABET.startswith("ABC"))
        self.assertTrue(BASE62_ALPHABET.endswith("789"))

    def test_every_reference_vector_encodes_to_the_reference_string(self):
        for hexed, want in GO_BASE62_SCALARS.items():
            with self.subTest(input=hexed):
                self.assertEqual(base62_encode(bytes.fromhex(hexed)), want)

    def test_every_reference_vector_decodes_back_to_its_bytes(self):
        for hexed, encoded in GO_BASE62_SCALARS.items():
            with self.subTest(input=hexed):
                self.assertEqual(base62_decode(encoded).hex(), hexed)

    def test_a_leading_zero_byte_survives_the_round_trip(self):
        """The property a big-integer base62 loses. `00` is two characters here,
        and `0x0001` is three, because the stream is bit-oriented."""
        for raw in (b"\x00", b"\x00\x00", b"\x00\x01", b"\x00" * 33):
            with self.subTest(raw=raw.hex()):
                self.assertEqual(base62_decode(base62_encode(raw)), raw)

    def test_every_byte_length_up_to_forty_round_trips(self):
        for length in range(41):
            raw = bytes((i * 37 + 11) & 0xFF for i in range(length))
            with self.subTest(length=length):
                self.assertEqual(base62_decode(base62_encode(raw)), raw)

    def test_a_character_outside_the_alphabet_is_a_parse_error(self):
        for bad in ("A-B", "hello!", " A", "A\n"):
            with self.subTest(text=bad):
                with self.assertRaises(ParseError):
                    base62_decode(bad)

    def test_it_is_an_astral_error_as_well_as_a_value_error(self):
        with self.assertRaises(astral.AstralError):
            base62_decode("!")
        with self.assertRaises(ValueError):
            base62_decode("!")


# --- Tier A: node_info --------------------------------------------------


class NodeInfoWireTest(unittest.TestCase):
    """`mod.nodes.node_info` against astral-go's bytes and its own rules."""

    def full(self) -> NodeInfo:
        return NodeInfo(
            alias=FURRY_BOLT_ALIAS,
            identity=FURRY_BOLT,
            endpoints=[TCP_EP, TOR_EP, GW_EP, KCP_EP, NAT_EP],
        )

    def test_the_full_value_encodes_to_the_reference_bytes(self):
        self.assertEqual(payload_bytes(self.full()), vector("node_info_full"))

    def test_the_reference_bytes_decode_to_the_full_value(self):
        got = NodeInfo.read_payload(object_reader(vector("node_info_full")))
        self.assertEqual(got, self.full())
        self.assertEqual(
            [type(e) for e in got.endpoints],
            [TcpEndpoint, TorEndpoint, GatewayEndpoint, KcpEndpoint, NatEndpoint],
        )

    def test_the_identity_sits_behind_a_presence_flag(self):
        """The Go field is `*astral.Identity` and `astral.Objectify` writes it
        as one. The zero value settles it: 6 bytes, the nil identity a single
        `00`."""
        raw = vector("node_info_zero")
        self.assertEqual(len(raw), 1 + 1 + 4)
        self.assertEqual(raw[0], 0x00)  # empty alias
        self.assertEqual(raw[1], 0x00)  # nil identity
        self.assertEqual(raw[2:6], b"\x00\x00\x00\x00")  # uint32 endpoint count
        self.assertEqual(payload_bytes(NodeInfo()), raw)
        got = NodeInfo.read_payload(object_reader(raw))
        self.assertEqual(got, NodeInfo())
        self.assertIsNone(got.identity)

    def test_the_alias_only_value_matches_the_reference(self):
        n = NodeInfo(alias=FURRY_BOLT_ALIAS, identity=FURRY_BOLT)
        raw = vector("node_info_alias_only")
        self.assertEqual(payload_bytes(n), raw)
        self.assertEqual(raw[11], 0x01)  # present identity, then its 33 bytes
        self.assertEqual(raw[12:45], FURRY_BOLT.key)

    def test_each_endpoint_carries_its_object_type(self):
        raw = vector("node_info_full")
        # 1 alias length byte + 10 alias bytes + 1 flag + 33 identity bytes.
        self.assertEqual(raw[45:49], b"\x00\x00\x00\x05")  # uint32 count
        self.assertEqual(raw[49:66], b"\x10mod.tcp.endpoint")
        self.assertIn(b"\x10mod.kcp.endpoint", raw)
        self.assertIn(b"\x0cnat.endpoint", raw)

    def test_the_text_form_is_the_reference_base62(self):
        for name, want in GO_BASE62.items():
            with self.subTest(vector=name):
                got = NodeInfo.read_payload(object_reader(vector(name)))
                self.assertEqual(got.text(), want)

    def test_the_invite_string_parses_back(self):
        for name, encoded in GO_BASE62.items():
            with self.subTest(vector=name):
                got = NodeInfo.parse(encoded)
                self.assertEqual(payload_bytes(got), vector(name))

    def test_the_json_form_is_the_same_string_and_not_a_field_walk(self):
        """astral-go gives `NodeInfo` a `MarshalText` and no `MarshalJSON`, and
        its JSON channel marshals the object itself
        (`astral/channel/json_sender.go`), so `encoding/json` uses the text
        marshaler. A field walk here would be this SDK talking to itself."""
        from astral.codec.jsoncodec import marshal, unmarshal

        n = self.full()
        self.assertEqual(marshal(n), GO_BASE62["node_info_full"])
        self.assertEqual(unmarshal("mod.nodes.node_info", marshal(n)), n)

    def test_a_json_value_that_is_not_a_string_is_refused(self):
        with self.assertRaises(ParseError):
            NodeInfo.from_json({"Alias": "x"})

    def test_every_type_in_the_module_describes_its_bytes(self):
        """No type in this module carries a hand-written codec: the declaration
        is the binary layout, so a blueprint derived from it encodes what the
        class reads."""
        from astral.blueprint import of as blueprint_of

        for cls in NODES_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertIs(cls.DERIVABLE, True)
                self.assertEqual(
                    len(blueprint_of(cls).blueprint_specs()), len(cls.FIELDS)
                )


# --- Tier A: the reflective types ----------------------------------------


class NodesWireTest(unittest.TestCase):
    """Every other `mod.nodes.*` type, against astral-go's bytes."""

    def link_info(self) -> LinkInfo:
        return LinkInfo(
            id=Nonce(0x0102030405060708),
            local_identity=FURRY_BOLT,
            remote_identity=OTHER,
            local_endpoint=TCP_EP,
            remote_endpoint=TOR_EP,
            outbound=True,
            network="tcp",
            high_pressure=False,
            bytes_throughput=1234,
        )

    def session_info(self) -> SessionInfo:
        return SessionInfo(
            id=Nonce(0x1122334455667788),
            link_id=Nonce(0x0102030405060708),
            remote_identity=OTHER,
            outbound=True,
            query="objects.read?id=x",
            bytes=4096,
            age=Duration(90 * 10**9),
        )

    def test_link_info_matches_the_reference_both_ways(self):
        raw = vector("link_info")
        self.assertEqual(payload_bytes(self.link_info()), raw)
        self.assertEqual(LinkInfo.read_payload(object_reader(raw)), self.link_info())

    def test_a_link_info_endpoint_is_type_tagged(self):
        """The two endpoint fields are interface-typed on the Go side, so each
        carries its own `string8` type name."""
        self.assertIn(b"\x10mod.tcp.endpoint", vector("link_info"))
        self.assertIn(b"\x10mod.tor.endpoint", vector("link_info"))

    def test_a_link_info_with_no_endpoints_is_a_zero_length_tag(self):
        raw = vector("link_info_zero")
        self.assertEqual(len(raw), 23)
        got = LinkInfo.read_payload(object_reader(raw))
        self.assertIsNone(got.local_endpoint)
        self.assertIsNone(got.remote_endpoint)
        self.assertIsNone(got.local_identity)
        self.assertEqual(payload_bytes(LinkInfo()), raw)

    def test_session_info_matches_the_reference_both_ways(self):
        raw = vector("session_info")
        self.assertEqual(payload_bytes(self.session_info()), raw)
        self.assertEqual(SessionInfo.read_payload(object_reader(raw)), self.session_info())
        self.assertEqual(payload_bytes(SessionInfo()), vector("session_info_zero"))

    def test_the_session_query_is_a_string16(self):
        """A `string8` would truncate a query longer than 255 bytes, and the
        node's own cap is 65 535."""
        raw = vector("session_info")
        # 8 id + 8 link id + 1 nil flag + 33 identity + 1 outbound.
        self.assertEqual(raw[51:53], b"\x00\x11")
        self.assertEqual(raw[53:70], b"objects.read?id=x")

    def test_endpoint_with_ttl_carries_the_ttl_behind_a_nil_flag(self):
        with_ttl = EndpointWithTTL(endpoint=TCP_EP, ttl=604800)
        without = EndpointWithTTL(endpoint=TCP_EP)
        self.assertEqual(payload_bytes(with_ttl), vector("ewt_with_ttl"))
        self.assertEqual(payload_bytes(without), vector("ewt_no_ttl"))
        self.assertIsNone(
            EndpointWithTTL.read_payload(object_reader(vector("ewt_no_ttl"))).ttl
        )
        self.assertEqual(
            EndpointWithTTL.read_payload(object_reader(vector("ewt_with_ttl"))).ttl,
            604800,
        )

    def test_a_zero_ttl_is_not_the_same_as_no_ttl(self):
        """`*astral.Uint32`: the nil flag is the whole distinction between "no
        expiry" and "expires now", and both are expressible."""
        zero = payload_bytes(EndpointWithTTL(endpoint=TCP_EP, ttl=0))
        self.assertNotEqual(zero, payload_bytes(EndpointWithTTL(endpoint=TCP_EP)))
        self.assertEqual(zero[-5:], b"\x01\x00\x00\x00\x00")

    def test_the_signals_and_events_match_the_reference(self):
        cases = [
            (MigrateSignal(signal="ready", buffer=65536), "migrate_signal"),
            (
                LinkCreatedEvent(remote_identity=OTHER, link_id=Nonce(7), link_count=3),
                "link_created_event",
            ),
            (
                LinkClosedEvent(remote_identity=OTHER, forced=True, link_count=2),
                "link_closed_event",
            ),
            (
                LinkPressureEvent(remote_identity=OTHER, link_id=Nonce(9)),
                "link_pressure_event",
            ),
            (NewObservedEndpointEvent(), "new_observed_endpoint_event"),
            (ObservedEndpointMessage(endpoint=TCP_EP), "observed_endpoint_message"),
        ]
        for obj, name in cases:
            with self.subTest(type=obj.ASTRAL_TYPE):
                self.assertEqual(payload_bytes(obj), vector(name))
                back = type(obj).read_payload(object_reader(vector(name)))
                self.assertEqual(back, obj)

    def test_the_two_link_count_widths_really_do_differ(self):
        """`link_created_event.LinkCount` is a `uint32` and
        `link_closed_event.LinkCount` is a `uint8`, in astral-go's source. A
        node holding more than 255 links reports a wrapped count on close."""
        def widths(cls: type) -> dict[str, str]:
            return {
                f.wire_name: f.spec.name
                for f in cls.FIELDS
                if hasattr(f.spec, "name")
            }

        created = widths(LinkCreatedEvent)
        closed = widths(LinkClosedEvent)
        self.assertEqual(created["LinkCount"], "uint32")
        self.assertEqual(closed["LinkCount"], "uint8")

    def test_relay_for_action_flattens_the_action_fields_first(self):
        """An `auth.Action` embed is a value embed: `Nonce` and `ActorID` come
        first and flatten under their own names, which is Go's promotion order."""
        self.assertEqual(
            [f.wire_name for f in RelayForAction.FIELDS], ["Nonce", "ActorID", "ForID"]
        )
        self.assertEqual(payload_bytes(RelayForAction()), bytes(10))


class NodesRegistryTest(unittest.TestCase):
    """What importing `astral.api` puts in the registry, and what it does not."""

    def test_every_declared_type_is_registered_under_its_wire_name(self):
        registry = default_blueprints()
        for cls in NODES_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(registry.has(cls.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(cls.ASTRAL_TYPE), cls)

    def test_the_declared_set_is_the_whole_module(self):
        """`NODES_TYPES` is what a private-registry sweep adds, so a type
        declared and left out of it would decode in the default registry and
        not in a private one."""
        import astral.api.nodes as module

        declared = {
            value
            for value in vars(module).values()
            if isinstance(value, type)
            and getattr(value, "ASTRAL_TYPE", "").startswith("mod.nodes.")
        }
        self.assertEqual(declared, set(NODES_TYPES))

    def test_the_endpoint_types_belong_to_another_module(self):
        """Design section 0.1 ships them in `astral.api.endpoints`. This module
        reaches them by name, so a private registry built from `NODES_TYPES`
        alone cannot decode a `link_info` carrying one -- and says so."""
        names = {cls.ASTRAL_TYPE for cls in NODES_TYPES}
        self.assertNotIn("mod.tcp.endpoint", names)
        self.assertNotIn("mod.kcp.endpoint", names)
        self.assertTrue(default_blueprints().has("mod.tcp.endpoint"))

    def test_an_unregistered_endpoint_type_fails_by_name(self):
        from astral.registry import Blueprints

        private = Blueprints()
        private.add(NodeInfo)
        with self.assertRaises(StreamCorrupted) as caught:
            NodeInfo.read_payload(
                object_reader(vector("node_info_full"), registry=private)
            )
        self.assertIn("mod.tcp.endpoint", str(caught.exception))


# --- Tier B: the seven ops against the mock ------------------------------


class NodesCase(unittest.IsolatedAsyncioTestCase):
    """A `Nodes` over a mock apphost, closed by the teardown whatever a test does."""

    async def asyncSetUp(self) -> None:
        self.clients: list[astral.Client] = []
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for client in self.clients:
            await client.aclose()
        await flush_cancels(5.0)

    def connector(self, mock: MockApphost):  # type: ignore[no-untyped-def]
        async def open_session() -> Session:
            return await Session.over(
                await mock.open(), endpoint="mem:mock", connector=open_session
            )

        return open_session

    async def nodes(self, mock: MockApphost, **kw: object) -> Nodes:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Nodes(client, experimental=True)

    async def gated(self, mock: MockApphost, **kw: object) -> Nodes:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Nodes(client)

    def sent(self, mock: MockApphost) -> str:
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query


class GateTest(NodesCase):
    """Design section 0.1: Tier 3 is opt-in, and the opt-in is per call site."""

    @bounded()
    async def test_every_op_refuses_without_the_flag_and_sends_nothing(self):
        async with MockApphost() as mock:
            n = await self.gated(mock)
            calls = (
                lambda: n.links(),
                lambda: n.sessions(),
                lambda: n.resolve_endpoints("furry-bolt"),
                lambda: n.add_endpoint(FURRY_BOLT, "tcp:10.0.0.1:1791"),
                lambda: n.close_link(1),
                lambda: n.new_link("furry-bolt"),
                lambda: n.migrate_session(1, 2),
            )
            for index, call in enumerate(calls):
                with self.subTest(op=index):
                    with self.assertRaises(FeatureUnavailable) as caught:
                        await call()
                    self.assertIn("experimental=True", str(caught.exception))
            self.assertEqual(mock.queries, [], "a gated op reached the node")

    @bounded()
    async def test_the_gate_is_an_astral_error(self):
        async with MockApphost() as mock:
            n = await self.gated(mock)
            with self.assertRaises(astral.AstralError):
                await n.links()

    @bounded()
    async def test_the_gate_names_this_modules_class_and_not_the_other_one(self):
        """The class the caller would construct is read off the op's module
        prefix, because one shared gate serving two modules would otherwise name
        the wrong one half the time."""
        async with MockApphost() as mock:
            n = await self.gated(mock)
            with self.assertRaises(FeatureUnavailable) as caught:
                await n.links()
        message = str(caught.exception)
        self.assertIn(OP_LINKS, message)
        self.assertIn("Nodes(client, experimental=True)", message)
        self.assertNotIn("Nat(client", message)

    @bounded()
    async def test_the_per_call_flag_opens_one_call(self):
        async with MockApphost(routes={OP_LINKS: Accept(eos=True)}) as mock:
            n = await self.gated(mock)
            self.assertEqual(await n.links(experimental=True), [])
            self.assertIs(n.opted_in, False)
            with self.assertRaises(FeatureUnavailable):
                await n.links()

    @bounded()
    async def test_an_opted_in_instance_needs_no_flag(self):
        async with MockApphost(routes={OP_LINKS: Accept(eos=True)}) as mock:
            n = await self.nodes(mock)
            self.assertIs(n.opted_in, True)
            self.assertEqual(await n.links(), [])

    @bounded()
    async def test_the_client_property_is_gated_and_cached(self):
        async with MockApphost() as mock:
            client = await connect(connector=self.connector(mock))
            self.clients.append(client)
            self.assertIs(client.nodes, client.nodes)
            self.assertIs(client.nodes.opted_in, False)
            with self.assertRaises(FeatureUnavailable):
                await client.nodes.links()

    @bounded()
    async def test_the_types_decode_whether_or_not_the_ops_are_opened(self):
        """The gate is on the ops and not on the types, deliberately: a
        `link_info` can arrive on any stream, and a registry that depended on an
        opt-in would answer `BlueprintNotFound` in production."""
        async with MockApphost(
            routes={"objects.echo": Accept(objects=[frame(MigrateSignal(signal="ready"))])}
        ) as mock:
            client = await connect(connector=self.connector(mock))
            self.clients.append(client)
            got = await client.call_one("objects.echo")
        self.assertIsInstance(got, MigrateSignal)


class LinksOpTest(NodesCase):
    """`nodes.links`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_typed_link_info(self):
        info = LinkInfo(
            id=Nonce(7),
            local_identity=FURRY_BOLT,
            remote_identity=OTHER,
            network="tcp",
        )
        async with MockApphost(
            routes={OP_LINKS: Accept(objects=[frame(info), frame(info)], eos=True)}
        ) as mock:
            n = await self.nodes(mock)
            got = await n.links()
        self.assertEqual(got, [info, info])
        self.assertEqual(self.sent(mock), OP_LINKS)

    @bounded()
    async def test_an_idle_node_answers_an_empty_list(self):
        async with MockApphost(routes={OP_LINKS: Accept(eos=True)}) as mock:
            n = await self.nodes(mock)
            self.assertEqual(await n.links(), [])

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        async with MockApphost(routes={OP_LINKS: Accept(objects=[ACK_FRAME], eos=True)}) as mock:
            n = await self.nodes(mock)
            with self.assertRaises(ProtocolError) as caught:
                await n.links()
        self.assertIn("mod.nodes.link_info", str(caught.exception))


class SessionsOpTest(NodesCase):
    """`nodes.sessions`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_typed_session_info(self):
        info = SessionInfo(id=Nonce(3), link_id=Nonce(7), query="objects.read?id=x")
        async with MockApphost(
            routes={OP_SESSIONS: Accept(objects=[frame(info)], eos=True)}
        ) as mock:
            n = await self.nodes(mock)
            got = await n.sessions()
        self.assertEqual(got, [info])
        self.assertEqual(self.sent(mock), OP_SESSIONS)


class ResolveEndpointsOpTest(NodesCase):
    """`nodes.resolve_endpoints`: ST, and the op that needs the endpoint types."""

    @bounded()
    async def test_it_sends_the_name_and_decodes_the_endpoints(self):
        answer = EndpointWithTTL(endpoint=TCP_EP, ttl=604800)
        async with MockApphost(
            routes={
                f"{OP_RESOLVE_ENDPOINTS}?identity={FURRY_BOLT_ALIAS}": Accept(
                    objects=[frame(answer)], eos=True
                )
            }
        ) as mock:
            n = await self.nodes(mock)
            got = await n.resolve_endpoints(FURRY_BOLT_ALIAS)
        self.assertEqual(got, [answer])
        self.assertIsInstance(got[0].endpoint, TcpEndpoint)

    @bounded()
    async def test_an_identity_travels_as_hex(self):
        async with MockApphost(
            routes={
                f"{OP_RESOLVE_ENDPOINTS}?identity={FURRY_BOLT.hex()}": Accept(eos=True)
            }
        ) as mock:
            n = await self.nodes(mock)
            await n.resolve_endpoints(FURRY_BOLT)
        self.assertEqual(
            self.sent(mock), f"{OP_RESOLVE_ENDPOINTS}?identity={FURRY_BOLT.hex()}"
        )

    @bounded()
    async def test_an_empty_name_never_reaches_the_node(self):
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            with self.assertRaises(BadArgument):
                await n.resolve_endpoints("")
            self.assertEqual(mock.queries, [])


class AddEndpointOpTest(NodesCase):
    """`nodes.add_endpoint`: RR, one `ack`, and it writes a 90-day record."""

    @bounded()
    async def test_it_sends_the_identity_and_the_qualified_endpoint(self):
        async with MockApphost(default_route=Accept(objects=[ACK_FRAME])) as mock:
            n = await self.nodes(mock)
            await n.add_endpoint(FURRY_BOLT, "tcp:10.21.0.5:1791")
        op, params = parse(self.sent(mock))
        self.assertEqual(op, OP_ADD_ENDPOINT)
        self.assertEqual(
            params, {"identity": FURRY_BOLT.hex(), "endpoint": "tcp:10.21.0.5:1791"}
        )

    @bounded()
    async def test_an_endpoint_with_no_network_is_refused_here(self):
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            with self.assertRaises(BadArgument):
                await n.add_endpoint(FURRY_BOLT, "10.21.0.5")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_directory_name_is_refused_before_it_is_sent(self):
        """This client parses the argument as an identity and names the fix.
        astrald resolves a name here, so refusing locally is this client's
        choice, not the node's limit."""
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            with self.assertRaises(ParseError):
                await n.add_endpoint("furry-bolt", "tcp:10.21.0.5:1791")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        async with MockApphost(
            default_route=Accept(objects=[frame_error("invalid endpoint")])
        ) as mock:
            n = await self.nodes(mock)
            with self.assertRaises(astral.RemoteError):
                await n.add_endpoint(FURRY_BOLT, "nope:x")


class CloseLinkOpTest(NodesCase):
    """`nodes.close_link`: RR, one `ack`."""

    @bounded()
    async def test_the_id_travels_as_padded_hex_under_link_id(self):
        async with MockApphost(default_route=Accept(objects=[ACK_FRAME])) as mock:
            n = await self.nodes(mock)
            await n.close_link(Nonce(0x0102030405060708))
        self.assertEqual(self.sent(mock), f"{OP_CLOSE_LINK}?link_id=0102030405060708")

    @bounded()
    async def test_an_int_and_a_hex_string_reach_the_same_query(self):
        for value in (1, "1", "0000000000000001", Nonce(1)):
            with self.subTest(value=value):
                async with MockApphost(default_route=Accept(objects=[ACK_FRAME])) as mock:
                    n = await self.nodes(mock)
                    await n.close_link(value)
                    self.assertEqual(
                        mock.queries[0].query,
                        f"{OP_CLOSE_LINK}?link_id=0000000000000001",
                    )

    @bounded()
    async def test_a_value_that_is_not_a_nonce_is_refused(self):
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            for bad in ("zz", None, 1.5):
                with self.subTest(value=bad):
                    with self.assertRaises(astral.AstralError):
                        await n.close_link(bad)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])


class NewLinkOpTest(NodesCase):
    """`nodes.new_link`: RR, long, and the op with a required parameter."""

    @bounded()
    async def test_the_bare_form_sends_the_identity_alone(self):
        info = LinkInfo(id=Nonce(7), network="tcp")
        async with MockApphost(default_route=Accept(objects=[frame(info)])) as mock:
            n = await self.nodes(mock)
            got = await n.new_link("furry-bolt")
        self.assertEqual(got, info)
        self.assertEqual(self.sent(mock), f"{OP_NEW_LINK}?identity=furry-bolt")

    @bounded()
    async def test_an_endpoint_and_strategies_travel_with_it(self):
        info = LinkInfo(id=Nonce(7))
        async with MockApphost(default_route=Accept(objects=[frame(info)])) as mock:
            n = await self.nodes(mock)
            await n.new_link(
                "furry-bolt", endpoint="tcp:10.21.0.5:1791", strategies=["basic", "nat"]
            )
        op, params = parse(self.sent(mock))
        self.assertEqual(op, OP_NEW_LINK)
        self.assertEqual(
            params,
            {
                "identity": "furry-bolt",
                "endpoint": "tcp:10.21.0.5:1791",
                "strategies": "basic,nat",
            },
        )

    @bounded()
    async def test_a_single_strategy_is_accepted_unwrapped(self):
        async with MockApphost(default_route=Accept(objects=[frame(LinkInfo())])) as mock:
            n = await self.nodes(mock)
            await n.new_link("furry-bolt", strategies="basic")
        self.assertIn("strategies=basic", self.sent(mock))

    @bounded()
    async def test_an_empty_strategy_list_is_refused(self):
        """The node reads an empty argument as every strategy it has, which is
        the opposite of what an empty list means to a caller."""
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            for bad in ([], ["basic", ""], ["a,b"]):
                with self.subTest(value=bad):
                    with self.assertRaises(BadArgument):
                        await n.new_link("furry-bolt", strategies=bad)
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_routing_target_stays_reachable(self):
        """`peer`, not `target`: the op's target is the node to link to and the
        routing target is the node that answers, and here they differ."""
        async with MockApphost(default_route=Accept(objects=[frame(LinkInfo())])) as mock:
            n = await self.nodes(mock)
            await n.new_link("furry-bolt", target=OTHER)
        self.assertEqual(mock.queries[0].target, OTHER)
        self.assertEqual(self.sent(mock), f"{OP_NEW_LINK}?identity=furry-bolt")


class MigrateSessionOpTest(NodesCase):
    """`nodes.migrate_session`: only the `start=true` form ships."""

    @bounded()
    async def test_it_sends_both_ids_and_start_true(self):
        async with MockApphost(default_route=Accept(objects=[ACK_FRAME])) as mock:
            n = await self.nodes(mock)
            await n.migrate_session(Nonce(1), Nonce(2))
        op, params = parse(self.sent(mock))
        self.assertEqual(op, OP_MIGRATE_SESSION)
        self.assertEqual(
            params,
            {
                "session_id": "0000000000000001",
                "link_id": "0000000000000002",
                "start": "true",
            },
        )

    @bounded()
    async def test_the_negotiated_mode_raises_and_opens_no_channel(self):
        """Design section 4.5 drops it: the node becomes the responder of a
        four-signal handshake this SDK does not drive, and an undriven channel
        holds one of the node's 32 workers."""
        async with MockApphost() as mock:
            n = await self.nodes(mock)
            with self.assertRaises(FeatureUnavailable) as caught:
                await n.migrate_session(1, 2, start=False)
            self.assertEqual(mock.queries, [])
        self.assertIn("4.5", str(caught.exception))


# --- Tier C: the live node -----------------------------------------------


class LiveNodesTest(live_support.LiveCase):
    """`nodes` against a real node. Read-only: three ops of the seven.

    `add_endpoint`, `close_link`, `new_link` and `migrate_session` all mutate,
    and design section 7.3 forbids every one of them here -- `close_link` would
    drop a live link belonging to somebody else's node.
    """

    @bounded(30.0)
    async def test_links_and_sessions_decode_and_end_at_an_eos(self):
        async with await self.client() as client:
            n = astral.api.nodes.Nodes(client, experimental=True)
            links = await n.links()
            sessions = await n.sessions()
        self.assertTrue(all(isinstance(x, LinkInfo) for x in links))
        self.assertTrue(all(isinstance(x, SessionInfo) for x in sessions))
        for link in links:
            self.assertIsInstance(link.id, Nonce)
        for session in sessions:
            self.assertIsInstance(session.query, str)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_resolve_endpoints_answers_the_nodes_own_endpoints(self):
        """The gate of this module: a live `endpoint_with_ttl` decodes, and its
        polymorphic endpoint field resolves through `astral.api.endpoints`.

        Node-agnostic: it asserts that every answer is typed and that every TTL
        is either absent or positive, not which endpoints this node has.
        """
        async with await self.client() as client:
            n = astral.api.nodes.Nodes(client, experimental=True)
            found = await n.resolve_endpoints(client.host_alias)
            same = await n.resolve_endpoints(client.host_id)
        self.assertTrue(found, "the node resolved no endpoint for itself")
        for entry in found:
            self.assertIsInstance(entry, EndpointWithTTL)
            self.assertIsNotNone(entry.endpoint, "an endpoint decoded as absent")
            self.assertTrue(hasattr(entry.endpoint, "network"))
            if entry.ttl is not None:
                self.assertGreater(entry.ttl, 0)
        self.assertEqual(
            {e.endpoint.qualified() for e in found},
            {e.endpoint.qualified() for e in same},
            "an alias and its identity resolved to different endpoints",
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_live_endpoint_re_encodes_to_the_bytes_it_arrived_as(self):
        async with await self.client() as client:
            n = astral.api.nodes.Nodes(client, experimental=True)
            found = await n.resolve_endpoints(client.host_alias)
        for entry in found:
            with self.subTest(endpoint=entry.endpoint.qualified()):
                raw = payload_bytes(entry)
                again = EndpointWithTTL.read_payload(object_reader(raw))
                self.assertEqual(again, entry)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unresolvable_name_is_a_rejection_and_not_an_error_message(self):
        """astrald rejects with code 2 before accepting the query
        (`mod/nodes/src/op_resolve_endpoints.go`), which is a different failure
        from an `error_message` inside an accepted stream."""
        async with await self.client() as client:
            n = astral.api.nodes.Nodes(client, experimental=True)
            with self.assertRaises(astral.QueryRejected) as caught:
                await n.resolve_endpoints("astral-py-no-such-node")
        self.assertEqual(caught.exception.code, 2)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_gate_still_refuses_against_a_real_node(self):
        async with await self.client() as client:
            with self.assertRaises(FeatureUnavailable):
                await client.nodes.links()
        await self.assert_no_open_sockets()


# --- what this module claims about the reference -------------------------


class ReferenceClaimTest(unittest.TestCase):
    """Every claim this module makes about astral-go and astrald, re-read.

    At the pins `tests/reference.py` holds, so upstream drift is a deliberate
    bump rather than a surprise failure. Absent reference: skip.
    """

    def source(self, repo: str, path: str, rev: str | None = None) -> str:
        try:
            return reference.read(repo, path, rev)
        except reference.Unavailable as exc:
            self.skipTest(str(exc))

    def test_the_pin_encodes_through_objectify(self):
        """Both halves of the binary codec are `astral.Objectify`, the field
        walk this module's declaration mirrors (`api/nodes/node_info.go:24-29`)."""
        src = self.source(reference.ASTRAL_GO, "api/nodes/node_info.go")
        lines = src.splitlines()
        self.assertEqual(
            lines[23], "func (info NodeInfo) WriteTo(w io.Writer) (n int64, err error) {"
        )
        self.assertEqual(lines[24], "\treturn astral.Objectify(&info).WriteTo(w)")
        self.assertEqual(
            lines[27], "func (info *NodeInfo) ReadFrom(r io.Reader) (n int64, err error) {"
        )
        self.assertEqual(lines[28], "\treturn astral.Objectify(info).ReadFrom(r)")

    def test_the_pin_declares_the_three_fields_in_this_order(self):
        src = self.source(reference.ASTRAL_GO, "api/nodes/node_info.go")
        struct = src.split("type NodeInfo struct {")[1].split("}")[0]
        self.assertEqual(
            [line.split() for line in struct.strip().splitlines()],
            [
                ["Alias", "astral.String8"],
                ["Identity", "*astral.Identity"],
                ["Endpoints", "[]exonet.Endpoint"],
            ],
        )
        self.assertEqual(
            [f.spec for f in NodeInfo.FIELDS],
            [Primitive("string8"), Ptr("identity"), Slice()],
        )

    def test_the_pin_round_trips_kcp_and_nat_endpoints(self):
        """The test this module's docstring cites
        (`api/nodes/node_info_test.go:88-103`)."""
        src = self.source(reference.ASTRAL_GO, "api/nodes/node_info_test.go")
        lines = src.splitlines()
        self.assertIn("Every endpoint type travels under its own object type", lines[87])
        self.assertIn('kcp.ParseEndpoint, "5.6.7.8:1792"', lines[102])
        self.assertIn('nat.ParseEndpoint, "9.10.11.12:1793"', lines[103])

    def test_the_pin_writes_a_nil_identity_as_an_absent_flag(self):
        """The zero-value test this module's docstring cites
        (`api/nodes/node_info_test.go:17-33`): 6 bytes."""
        src = self.source(reference.ASTRAL_GO, "api/nodes/node_info_test.go")
        lines = src.splitlines()
        self.assertEqual(lines[17], "func TestNodeInfoWriteTo_NilIdentity(t *testing.T) {")
        self.assertIn("identity presence flag (1) + uint32 endpoint count (4)", lines[25])
        self.assertIn("want := int64(6)", lines[26])
        self.assertEqual(len(vector("node_info_zero")), 6)

    def test_a_truncated_node_info_is_a_wire_error(self):
        truncated = bytes([0x0A]) + b"furry"
        with self.assertRaises(astral.WireError):
            NodeInfo.read_payload(object_reader(truncated))

    def test_the_text_form_is_base62(self):
        src = self.source(reference.ASTRAL_GO, "api/nodes/node_info.go")
        self.assertIn("base62.Encode(buf.Bytes())", src)
        self.assertIn("base62.Decode(text)", src)
        self.assertNotIn("MarshalJSON", src)

    def test_the_two_link_count_widths_differ_in_the_source(self):
        created = self.source(reference.ASTRAL_GO, "api/nodes/link_created_event.go")
        closed = self.source(reference.ASTRAL_GO, "api/nodes/link_closed_event.go")
        self.assertIn("LinkCount      astral.Uint32", created)
        self.assertIn("LinkCount      astral.Uint8", closed)

    def test_three_ops_have_an_astral_go_client(self):
        """The count `require_experimental` states: three at the pin."""
        src = self.source(reference.ASTRAL_GO, "api/nodes/module.go")
        self.assertIn('MethodLinks            = "nodes.links"', src)
        self.assertIn('MethodResolveEndpoints = "nodes.resolve_endpoints"', src)
        self.assertIn('MethodMigrateSession   = "nodes.migrate_session"', src)
        self.assertEqual(src.count('= "nodes.'), 3)

    def test_the_pin_requires_the_seven_parameters_the_module_names(self):
        required = {
            "op_new_link.go": ["Identity   string"],
            "op_migrate_session.go": ["SessionID astral.Nonce", "LinkID    astral.Nonce"],
            "op_resolve_endpoints.go": ["Identity string"],
            "op_add_endpoint.go": ["Identity string", "Endpoint string"],
            "op_close_link.go": ["LinkID astral.Nonce"],
        }
        for name, fields in required.items():
            src = self.source(reference.ASTRALD, f"mod/nodes/src/{name}")
            for field in fields:
                with self.subTest(file=name, field=field):
                    self.assertIn(f'{field} `query:"required"`', src)
            with self.subTest(file=name):
                self.assertEqual(src.count('`query:"required"`'), len(fields))
        try:
            names = reference.listdir(reference.ASTRALD, "mod/nodes/src")
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))
        total = sum(
            self.source(reference.ASTRALD, f"mod/nodes/src/{name}").count(
                '`query:"required"`'
            )
            for name in names
            if name.startswith("op_") and not name.endswith("_test.go")
        )
        self.assertEqual(total, 7)

    def test_resolve_endpoints_rejects_with_code_two(self):
        src = self.source(reference.ASTRALD, "mod/nodes/src/op_resolve_endpoints.go")
        self.assertIn("return q.RejectWithCode(2)", src)

    def test_add_endpoint_writes_a_ninety_day_ttl(self):
        src = self.source(reference.ASTRALD, "mod/nodes/src/op_add_endpoint.go")
        self.assertIn("3*30*24*time.Hour", src)
        self.assertIn('strings.SplitN(args.Endpoint, ":", 2)', src)

    def test_migrate_session_without_start_is_the_responder_handshake(self):
        src = self.source(reference.ASTRALD, "mod/nodes/src/op_migrate_session.go")
        self.assertIn("if args.Start {", src)
        self.assertIn("MigrateSignalReady", src)
        self.assertIn("MigrateSignalSwitched", src)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
