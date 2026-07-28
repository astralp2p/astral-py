"""The `nat` module client, its four wire types, and the two dropped ops.

Three tiers, as `test_api_nodes.py` has them and for the same reason:

- **Tier A** pins the wire against **astral-go's own output**, printed this
  session by a Go program linked against `api/nat` at the pinned revision. The
  vectors matter most for `nat.hole`, whose two endpoint fields are concrete
  values rather than the type-tagged interface fields `nodes` uses -- three
  bytes each for a zero endpoint, with nothing naming the type.
- **Tier B** pins the three shipped ops against `MockApphost`, the two dropped
  ones against their own refusals, and the Tier 3 gate against all five.
- **Tier C** runs `nat.list_holes` against a real node, which is the only
  read-only op in the module. `punch` and `set_enabled` both mutate and design
  section 7.3 names `nat.punch` as forbidden here by itself.

**D-17 is what this file exists to keep true.** astral-docs writes
`nat.list_holes -With`, `nat.punch -Target` and `nat.node_consume_hole -Pair
-Target`; parameter matching is case-sensitive and unknown keys are dropped in
silence, so every one of those examples asks a different question from the one
it looks like. The query-string assertions below are on the lowercase names the
live registry declares.
"""

from __future__ import annotations

import ipaddress
import unittest

import astral
from astral.api.ip import IPAddress
from astral.api.nat import (
    CONSUME_HOLE_SIGNALS,
    NAT_TYPES,
    NETWORK,
    OP_LIST_HOLES,
    OP_NODE_CONSUME_HOLE,
    OP_NODE_PUNCH,
    OP_PUNCH,
    OP_SET_ENABLED,
    PUNCH_SIGNALS,
    ConsumeHoleSignal,
    Endpoint,
    Hole,
    Nat,
    PunchSignal,
)
from astral.api.exonet import Endpoint as ExonetEndpoint
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import BadArgument, FeatureUnavailable, ParseError, ProtocolError
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.types import Identity, Nonce, Time

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


def ip(text: str) -> IPAddress:
    return IPAddress(ipaddress.ip_address(text).packed)


EP4 = Endpoint(ip=ip("10.21.0.5"), port=41234)
EP6 = Endpoint(ip=ip("fe80::8aa2:9eff:fea8:4ab0"), port=41234)

# astral-go's own bytes, printed this session from `api/nat` at the pin.
GO_VECTORS = {
    "endpoint_v4": "040a150005a112",
    "endpoint_v6": "10fe800000000000008aa29efffea84ab0a112",
    "hole": (
        "deadbeefcafe0001"
        "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
        "040a150005a112"
        "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "10fe800000000000008aa29efffea84ab0a112"
        "18c6725246d18000"
    ),
    # astral-go's zero `nat.hole`, whose `CreatedAt` is not a time at all.
    "hole_zero_go": "00000000000000000000000000000000a1b203eb3d1a0000",
    "punch_signal": "056f666665720401020304040a150005a1120102030405060708",
    "consume_hole_signal": "046c6f636b01020304050607080100",
}

GO_TEXT = {
    "endpoint_v4": "10.21.0.5:41234",
    "endpoint_v6": "[fe80::8aa2:9eff:fea8:4ab0]:41234",
}


def vector(name: str) -> bytes:
    return bytes.fromhex(GO_VECTORS[name])


def frame(obj: object) -> tuple[str, bytes]:
    return (obj.ASTRAL_TYPE, payload_bytes(obj))  # type: ignore[attr-defined]


def frame_error(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ACK_FRAME = ("ack", b"")


def hole() -> Hole:
    return Hole(
        nonce=Nonce(0xDEADBEEFCAFE0001),
        active_identity=FURRY_BOLT,
        active_endpoint=EP4,
        passive_identity=OTHER,
        passive_endpoint=EP6,
        created_at=Time.parse("2026-07-28T12:00:00Z"),
    )


# --- Tier A: the four wire types -----------------------------------------


class NatEndpointTest(unittest.TestCase):
    """`nat.endpoint`: an IP and a port, and an exonet endpoint no name reaches."""

    def test_both_families_match_the_reference_both_ways(self):
        for value, name in ((EP4, "endpoint_v4"), (EP6, "endpoint_v6")):
            with self.subTest(endpoint=name):
                raw = vector(name)
                self.assertEqual(payload_bytes(value), raw)
                self.assertEqual(Endpoint.read_payload(object_reader(raw)), value)

    def test_the_ip_is_length_prefixed_and_the_port_is_not(self):
        """`bytes8` then `uint16`: four or sixteen bytes behind one length byte,
        and the length is the only thing that says which family it is."""
        self.assertEqual(vector("endpoint_v4")[0], 4)
        self.assertEqual(vector("endpoint_v6")[0], 16)
        self.assertEqual(vector("endpoint_v4")[-2:], (41234).to_bytes(2, "big"))

    def test_the_text_form_brackets_an_ipv6_host(self):
        self.assertEqual(EP4.text(), GO_TEXT["endpoint_v4"])
        self.assertEqual(EP6.text(), GO_TEXT["endpoint_v6"])
        self.assertEqual(EP4.address(), GO_TEXT["endpoint_v4"])

    def test_the_text_form_parses_back(self):
        for value in (EP4, EP6):
            with self.subTest(endpoint=value.text()):
                self.assertEqual(Endpoint.parse(value.text()), value)

    def test_an_unbracketed_ipv6_host_is_refused(self):
        """Go splits with `net.SplitHostPort`, which requires the brackets;
        `fe80::1:41234` has no unambiguous split and neither implementation
        guesses."""
        bad_forms = (
            "fe80::1:41234", "10.21.0.5", "10.21.0.5:", "10.21.0.5:x", "[::1]:99999",
        )
        for bad in bad_forms:
            with self.subTest(text=bad):
                with self.assertRaises(ParseError):
                    Endpoint.parse(bad)

    def test_the_json_form_is_the_text_form(self):
        """astral-go gives this type a `MarshalText` and no `MarshalJSON`, so
        the JSON channel emits the string -- and a `nat.hole`'s two endpoint
        fields come out as strings inside it."""
        from astral.codec.jsoncodec import marshal, unmarshal

        self.assertEqual(marshal(EP4), GO_TEXT["endpoint_v4"])
        self.assertEqual(unmarshal("nat.endpoint", GO_TEXT["endpoint_v6"]), EP6)
        with self.assertRaises(ParseError):
            Endpoint.from_json({"IP": "10.21.0.5"})

    def test_it_is_an_exonet_endpoint_reporting_kcp(self):
        self.assertIsInstance(EP4, ExonetEndpoint)
        self.assertEqual(EP4.network(), NETWORK)
        self.assertEqual(EP4.network(), "kcp")
        self.assertEqual(EP4.qualified(), "kcp:10.21.0.5:41234")
        self.assertEqual(EP4.pack(), vector("endpoint_v4"))

    def test_no_exonet_network_name_resolves_to_it(self):
        """astrald's `mod/kcp` claims `kcp` in the exonet dispatch table and
        `mod/nat` claims nothing, so `parse_endpoint('kcp:...')` must yield a
        `mod.kcp.endpoint` and never this type. Registering it would either
        collide or make import order decide what `kcp:` means."""
        from astral.api.exonet import endpoint_types

        self.assertNotIn(Endpoint, endpoint_types().classes())
        self.assertEqual(endpoint_types().get("kcp").ASTRAL_TYPE, "mod.kcp.endpoint")

    def test_it_is_a_different_type_from_the_kcp_endpoint_it_mirrors(self):
        from astral.api.endpoints import KcpEndpoint

        twin = KcpEndpoint(ip=ip("10.21.0.5"), port=41234)
        self.assertEqual(payload_bytes(twin), payload_bytes(EP4))
        self.assertNotEqual(twin.ASTRAL_TYPE, EP4.ASTRAL_TYPE)
        self.assertNotEqual(twin, EP4)


class HoleTest(unittest.TestCase):
    """`nat.hole`, its two by-value endpoints, and its two zeros."""

    def test_it_matches_the_reference_both_ways(self):
        raw = vector("hole")
        self.assertEqual(payload_bytes(hole()), raw)
        self.assertEqual(Hole.read_payload(object_reader(raw)), hole())

    def test_an_endpoint_field_carries_no_type_tag(self):
        """A `Ref`, not an `Any`: the field is a concrete `nat.Endpoint` value on
        the Go side, so its payload is inlined bare. `mod.nodes.link_info` in the
        same session's vectors does carry a `string8` type name, and the
        difference is the field declaration, not the value."""
        raw = vector("hole")
        self.assertNotIn(b"nat.endpoint", raw)
        # 8 nonce + 1 nil flag + 33 identity.
        self.assertEqual(raw[42:49], vector("endpoint_v4"))

    def test_the_sdk_zero_and_the_reference_zero_differ_only_in_the_time(self):
        """astral-go's zero `time.Time` is year 1, and `UnixNano` is undefined
        there: it wraps to 1754-08-30. The SDK's zero is the epoch. Both decode
        here and both re-encode to the bytes they arrived as, so the divergence
        never travels."""
        go_zero = vector("hole_zero_go")
        sdk_zero = payload_bytes(Hole())
        self.assertEqual(len(sdk_zero), len(go_zero))
        self.assertEqual(sdk_zero[:16], go_zero[:16])
        self.assertEqual(sdk_zero[16:], bytes(8))
        decoded = Hole.read_payload(object_reader(go_zero))
        self.assertEqual(payload_bytes(decoded), go_zero)
        self.assertEqual(decoded.created_at.text()[:4], "1754")

    def test_a_zero_endpoint_is_three_bytes(self):
        """An empty `bytes8` and a zero port. There is no way to say "no
        endpoint" in this type: the field is a value, not a pointer."""
        self.assertEqual(payload_bytes(Endpoint()), b"\x00\x00\x00")
        self.assertEqual(payload_bytes(Hole())[9:12], b"\x00\x00\x00")

    def test_matches_answers_for_either_side(self):
        h = hole()
        self.assertTrue(h.matches(FURRY_BOLT))
        self.assertTrue(h.matches(OTHER))
        self.assertFalse(h.matches(Identity.ANYONE))

    def test_the_remote_identity_is_the_other_side(self):
        h = hole()
        self.assertEqual(h.remote_identity(FURRY_BOLT), OTHER)
        self.assertEqual(h.remote_identity(OTHER), FURRY_BOLT)
        self.assertIsNone(h.remote_identity(Identity.ANYONE))

    def test_the_local_and_remote_endpoints_follow_the_identity(self):
        h = hole()
        self.assertEqual(h.local_endpoint(FURRY_BOLT), EP4)
        self.assertEqual(h.remote_endpoint(FURRY_BOLT), EP6)
        self.assertEqual(h.local_endpoint(OTHER), EP6)
        self.assertEqual(h.remote_endpoint(OTHER), EP4)

    def test_a_stranger_gets_a_refusal_and_not_somebody_elses_address(self):
        """Go's `GetLocalAddr` falls through to the passive side for an identity
        on neither, which hands back an address belonging to a third party."""
        with self.assertRaises(BadArgument):
            hole().local_endpoint(Identity.ANYONE)


class SignalTest(unittest.TestCase):
    """The two signal types, declared for decode and never sent."""

    def test_the_punch_signal_matches_the_reference(self):
        raw = vector("punch_signal")
        signal = PunchSignal(
            signal="offer",
            session=b"\x01\x02\x03\x04",
            ip=ip("10.21.0.5"),
            port=41234,
            pair_nonce=Nonce(0x0102030405060708),
        )
        self.assertEqual(payload_bytes(signal), raw)
        self.assertEqual(PunchSignal.read_payload(object_reader(raw)), signal)
        self.assertEqual(PUNCH_SIGNALS[0], "offer")
        self.assertEqual(len(PUNCH_SIGNALS), 5)

    def test_the_consume_hole_signal_matches_the_reference(self):
        raw = vector("consume_hole_signal")
        signal = ConsumeHoleSignal(
            signal="lock", pair=Nonce(0x0102030405060708), ok=True, error=""
        )
        self.assertEqual(payload_bytes(signal), raw)
        self.assertEqual(ConsumeHoleSignal.read_payload(object_reader(raw)), signal)
        self.assertEqual(CONSUME_HOLE_SIGNALS, ("lock", "locked", "take", "taken"))

    def test_a_plain_go_bool_is_one_byte_like_any_other(self):
        """`ConsumeHoleSignal.Ok` is a Go `bool` and not an `astral.Bool`; the
        reflective codec maps both to the same byte, which is why this SDK can
        declare it as `Primitive('bool')` without a special case."""
        self.assertEqual(vector("consume_hole_signal")[-2], 0x01)
        off = ConsumeHoleSignal(signal="lock", pair=Nonce(1), ok=False, error="no")
        self.assertEqual(payload_bytes(off)[-4:], b"\x00\x02no")

    def test_the_punch_signal_json_uses_astral_gos_tag_names(self):
        """astral-go gives this one type explicit lowercase `json:` tags where
        every other type in `nodes` and `nat` marshals through its Go field
        names, and `MarshalJSON` goes through them.

        Case folding alone is not enough to bridge that: `signal`, `session`,
        `ip` and `port` fold onto the declared names and `pair_nonce` does not,
        so a decoder that only folded case would refuse the reference's own
        output as an unknown field. `JSON_TAGS` is the map that closes it, in
        both directions.
        """
        from astral.api.nat import JSON_TAGS
        from astral.codec.jsoncodec import marshal, unmarshal

        signal = PunchSignal(
            signal="offer",
            session=b"\x01\x02\x03\x04",
            ip=ip("10.21.0.5"),
            port=41234,
            pair_nonce=Nonce(0x0102030405060708),
        )
        self.assertEqual(
            marshal(signal),
            {
                "signal": "offer",
                "session": "AQIDBA==",
                "ip": "10.21.0.5",
                "port": 41234,
                "pair_nonce": "102030405060708",
            },
        )
        self.assertEqual(set(JSON_TAGS.values()), set(marshal(signal)))
        self.assertEqual(unmarshal("nat.punch_signal", marshal(signal)), signal)

    def test_the_punch_signal_also_reads_the_go_field_names(self):
        """A payload written with the field names still decodes: the rename
        touches the five tags and leaves every other key to the ordinary
        case-insensitive walk."""
        from astral.codec.jsoncodec import unmarshal

        signal = PunchSignal(signal="offer", ip=ip("10.21.0.5"), port=41234)
        by_field_name = {
            "Signal": "offer",
            "IP": "10.21.0.5",
            "Port": 41234,
        }
        self.assertEqual(unmarshal("nat.punch_signal", by_field_name), signal)

    def test_a_punch_signal_json_that_is_not_an_object_is_refused(self):
        with self.assertRaises(ParseError):
            PunchSignal.from_json("offer")


class NatRegistryTest(unittest.TestCase):
    """What importing `astral.api` puts in the registry, and what it does not."""

    def test_every_declared_type_is_registered_under_its_wire_name(self):
        registry = default_blueprints()
        for cls in NAT_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(registry.has(cls.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(cls.ASTRAL_TYPE), cls)

    def test_the_type_names_carry_no_mod_prefix(self):
        """Design section 5.1 rule 6 lists `nat.hole` and `nat.endpoint` among
        the names that are spelled without `mod.`, and the live registry agrees."""
        for cls in NAT_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(cls.ASTRAL_TYPE.startswith("nat."))

    def test_the_declared_set_is_the_whole_module(self):
        import astral.api.nat as module

        declared = {
            value
            for value in vars(module).values()
            if isinstance(value, type)
            and getattr(value, "ASTRAL_TYPE", "").startswith("nat.")
        }
        self.assertEqual(declared, set(NAT_TYPES))

    def test_the_ip_type_belongs_to_another_module(self):
        names = {cls.ASTRAL_TYPE for cls in NAT_TYPES}
        self.assertNotIn("mod.ip.ip_address", names)
        self.assertTrue(default_blueprints().has("mod.ip.ip_address"))

    def test_no_type_here_needs_the_escape_hatch(self):
        """All four are the reflective field walk, so all four describe their
        own bytes. `Endpoint` overrides the text and JSON forms and not the
        payload codec, which is what keeps it derivable -- design section 2.5
        permits four hand-written codecs in the whole SDK and none is here."""
        from astral.blueprint import of as blueprint_of

        for cls in NAT_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertIs(cls.DERIVABLE, True)
                self.assertEqual(
                    len(blueprint_of(cls).blueprint_specs()), len(cls.FIELDS)
                )


# --- Tier B: the five ops against the mock -------------------------------


class NatCase(unittest.IsolatedAsyncioTestCase):
    """A `Nat` over a mock apphost, closed by the teardown whatever a test does."""

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

    async def nat(self, mock: MockApphost, *, experimental: bool = True) -> Nat:
        client = await connect(connector=self.connector(mock))
        self.clients.append(client)
        return Nat(client, experimental=experimental)

    def sent(self, mock: MockApphost) -> str:
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query


class GateTest(NatCase):
    """Design section 0.1: Tier 3 is opt-in, and the opt-in is per call site."""

    @bounded()
    async def test_every_op_refuses_without_the_flag_and_sends_nothing(self):
        async with MockApphost() as mock:
            n = await self.nat(mock, experimental=False)
            calls = (
                lambda: n.list_holes(),
                lambda: n.punch("furry-bolt"),
                lambda: n.set_enabled(True),
            )
            for index, call in enumerate(calls):
                with self.subTest(op=index):
                    with self.assertRaises(FeatureUnavailable) as caught:
                        await call()
                    self.assertIn("experimental=True", str(caught.exception))
            self.assertEqual(mock.queries, [], "a gated op reached the node")

    @bounded()
    async def test_the_gate_names_this_modules_class_and_not_the_other_one(self):
        """One gate serves both Tier 3 modules, so the class it tells the caller
        to construct is read off the op's own module prefix."""
        async with MockApphost() as mock:
            n = await self.nat(mock, experimental=False)
            with self.assertRaises(FeatureUnavailable) as caught:
                await n.list_holes()
        message = str(caught.exception)
        self.assertIn(OP_LIST_HOLES, message)
        self.assertIn("Tier 3", message)
        self.assertIn("Nat(client, experimental=True)", message)
        self.assertNotIn("Nodes(client", message)

    @bounded()
    async def test_the_per_call_flag_opens_one_call(self):
        async with MockApphost(routes={OP_LIST_HOLES: Accept(eos=True)}) as mock:
            n = await self.nat(mock, experimental=False)
            self.assertEqual(await n.list_holes(experimental=True), [])
            with self.assertRaises(FeatureUnavailable):
                await n.list_holes()

    @bounded()
    async def test_the_client_property_is_gated_and_cached(self):
        async with MockApphost() as mock:
            client = await connect(connector=self.connector(mock))
            self.clients.append(client)
            self.assertIs(client.nat, client.nat)
            self.assertIs(client.nat.opted_in, False)
            with self.assertRaises(FeatureUnavailable):
                await client.nat.list_holes()


class ListHolesOpTest(NatCase):
    """`nat.list_holes`: ST, ends at `eos`, and the module's only read."""

    @bounded()
    async def test_the_bare_form_sends_no_parameters(self):
        async with MockApphost(
            routes={OP_LIST_HOLES: Accept(objects=[frame(hole())], eos=True)}
        ) as mock:
            n = await self.nat(mock)
            got = await n.list_holes()
        self.assertEqual(got, [hole()])
        self.assertEqual(self.sent(mock), OP_LIST_HOLES)

    @bounded()
    async def test_a_peer_travels_as_lowercase_with(self):
        """D-17: the docs write `-With`, which the node drops in silence."""
        async with MockApphost(
            routes={f"{OP_LIST_HOLES}?with={FURRY_BOLT_ALIAS}": Accept(eos=True)}
        ) as mock:
            n = await self.nat(mock)
            self.assertEqual(await n.list_holes(FURRY_BOLT_ALIAS), [])
        op, params = parse(self.sent(mock))
        self.assertEqual(op, OP_LIST_HOLES)
        self.assertEqual(params, {"with": FURRY_BOLT_ALIAS})
        self.assertNotIn("With=", self.sent(mock))

    @bounded()
    async def test_an_identity_travels_as_hex(self):
        async with MockApphost(default_route=Accept(eos=True)) as mock:
            n = await self.nat(mock)
            await n.list_holes(FURRY_BOLT)
        self.assertEqual(self.sent(mock), f"{OP_LIST_HOLES}?with={FURRY_BOLT.hex()}")

    @bounded()
    async def test_an_empty_peer_never_reaches_the_node(self):
        async with MockApphost() as mock:
            n = await self.nat(mock)
            with self.assertRaises(BadArgument):
                await n.list_holes("")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_unresolvable_peer_is_an_error_message_in_the_stream(self):
        """astrald sends it inside the accepted stream rather than rejecting,
        because it resolves the name per hole and after accepting."""
        async with MockApphost(
            default_route=Accept(objects=[frame_error("unknown identity")], eos=True)
        ) as mock:
            n = await self.nat(mock)
            with self.assertRaises(astral.RemoteError):
                await n.list_holes("nope")

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        route = Accept(objects=[ACK_FRAME], eos=True)
        async with MockApphost(default_route=route) as mock:
            n = await self.nat(mock)
            with self.assertRaises(ProtocolError) as caught:
                await n.list_holes()
        self.assertIn("nat.hole", str(caught.exception))


class PunchOpTest(NatCase):
    """`nat.punch`: RR, long, and the node does the punching."""

    @bounded()
    async def test_it_sends_the_target_and_returns_the_hole(self):
        async with MockApphost(default_route=Accept(objects=[frame(hole())])) as mock:
            n = await self.nat(mock)
            got = await n.punch("furry-bolt")
        self.assertEqual(got, hole())
        self.assertEqual(self.sent(mock), f"{OP_PUNCH}?target=furry-bolt")

    @bounded()
    async def test_the_routing_target_stays_reachable(self):
        """`peer`, not `target`: the query goes to one node and asks it to punch
        towards another."""
        async with MockApphost(default_route=Accept(objects=[frame(hole())])) as mock:
            n = await self.nat(mock)
            await n.punch("furry-bolt", target=OTHER)
        self.assertEqual(mock.queries[0].target, OTHER)
        self.assertEqual(self.sent(mock), f"{OP_PUNCH}?target=furry-bolt")

    @bounded()
    async def test_a_failure_surfaces_as_a_remote_error(self):
        async with MockApphost(
            default_route=Accept(objects=[frame_error("punch failed")])
        ) as mock:
            n = await self.nat(mock)
            with self.assertRaises(astral.RemoteError):
                await n.punch("furry-bolt")


class SetEnabledOpTest(NatCase):
    """`nat.set_enabled`: the positional key, which is `arg`."""

    @bounded()
    async def test_the_value_travels_under_arg(self):
        for value, text in ((True, "true"), (False, "false")):
            with self.subTest(value=value):
                route = Accept(objects=[ACK_FRAME])
                async with MockApphost(default_route=route) as mock:
                    n = await self.nat(mock)
                    await n.set_enabled(value)
                    self.assertEqual(
                        mock.queries[0].query, f"{OP_SET_ENABLED}?arg={text}"
                    )

    @bounded()
    async def test_a_non_bool_is_refused_before_it_is_sent(self):
        """The op parses this argument with `strconv.ParseBool`, which reads
        `1` and `t` as true and refuses everything else; sending an int would
        work by accident and stop working on the next value."""
        async with MockApphost() as mock:
            n = await self.nat(mock)
            for bad in (1, "true", None):
                with self.subTest(value=bad):
                    with self.assertRaises(BadArgument):
                        await n.set_enabled(bad)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])


class DroppedOpTest(NatCase):
    """The two ops design section 4.5 drops, and how they say so."""

    @bounded()
    async def test_both_raise_and_name_the_reason(self):
        async with MockApphost() as mock:
            n = await self.nat(mock)
            for call, op in (
                (n.node_punch, OP_NODE_PUNCH),
                (n.node_consume_hole, OP_NODE_CONSUME_HOLE),
            ):
                with self.subTest(op=op):
                    with self.assertRaises(FeatureUnavailable) as caught:
                        await call()
                    message = str(caught.exception)
                    self.assertIn(op, message)
                    self.assertIn("4.5", message)
                    self.assertIn("puncher", message)
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_they_are_present_rather_than_absent(self):
        """A missing method and a dropped op are different facts, and a caller
        cannot tell them apart by `hasattr`. These are methods that refuse."""
        self.assertTrue(callable(Nat.node_punch))
        self.assertTrue(callable(Nat.node_consume_hole))

    @bounded()
    async def test_the_signal_types_they_would_have_used_still_decode(self):
        """The node sends these to a peer that speaks the protocol; a decoder
        that did not know the types could not name what it received."""
        self.assertTrue(default_blueprints().has("nat.punch_signal"))
        self.assertTrue(default_blueprints().has("nat.consume_hole_signal"))


# --- Tier C: the live node -----------------------------------------------


class LiveNatTest(live_support.LiveCase):
    """`nat` against a real node. `list_holes` only: the other four mutate.

    Design section 7.3 names `nat.punch` as forbidden here in as many words, and
    `set_enabled` would change a setting on somebody's node.
    """

    @bounded(30.0)
    async def test_list_holes_answers_typed_holes_and_ends_at_an_eos(self):
        async with await self.client() as client:
            n = astral.api.nat.Nat(client, experimental=True)
            holes = await n.list_holes()
        self.assertIsInstance(holes, list)
        for h in holes:
            self.assertIsInstance(h, Hole)
            self.assertIsInstance(h.active_endpoint, Endpoint)
            raw = payload_bytes(h)
            self.assertEqual(payload_bytes(Hole.read_payload(object_reader(raw))), raw)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_filtering_by_the_nodes_own_identity_is_accepted(self):
        """The `with=` parameter reaches the op: a node with no holes answers a
        bare `eos` either way, so what this asserts is that the query is
        accepted and not rejected for an unknown parameter."""
        async with await self.client() as client:
            n = astral.api.nat.Nat(client, experimental=True)
            holes = await n.list_holes(client.host_id)
        self.assertEqual([h for h in holes if not h.matches(client.host_id)], [])
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_gate_still_refuses_against_a_real_node(self):
        async with await self.client() as client:
            with self.assertRaises(FeatureUnavailable):
                await client.nat.list_holes()
        await self.assert_no_open_sockets()


# --- what this module claims about the reference -------------------------


class ReferenceClaimTest(unittest.TestCase):
    """Every claim this module makes about astral-go and astrald, re-read."""

    def source(self, repo: str, path: str) -> str:
        try:
            return reference.read(repo, path)
        except reference.Unavailable as exc:
            self.skipTest(str(exc))

    def test_the_module_declares_five_ops(self):
        src = self.source(reference.ASTRAL_GO, "api/nat/module.go")
        ops = (
            OP_PUNCH,
            OP_LIST_HOLES,
            OP_SET_ENABLED,
            OP_NODE_PUNCH,
            OP_NODE_CONSUME_HOLE,
        )
        for op in ops:
            with self.subTest(op=op):
                self.assertIn(f'"{op}"', src)

    def test_set_enabled_takes_the_positional_key(self):
        astrald_src = self.source(reference.ASTRALD, "mod/nat/src/op_enable.go")
        go_src = self.source(reference.ASTRAL_GO, "api/nat/client/set_enabled.go")
        self.assertIn("Arg bool", astrald_src)
        self.assertIn('"arg": enabled', go_src)

    def test_list_holes_takes_with_and_resolves_it_per_hole(self):
        src = self.source(reference.ASTRALD, "mod/nat/src/op_list_holes.go")
        self.assertIn('With string `query:"optional"`', src)
        self.assertIn("mod.Dir.ResolveIdentity(string(args.With))", src)
        self.assertIn("ch.Send(astral.NewError(err.Error()))", src)

    def test_punch_asks_the_node_to_be_the_initiator(self):
        src = self.source(reference.ASTRALD, "mod/nat/src/op_punch.go")
        self.assertIn("Target string", src)
        self.assertIn("client.NodePunch(ctx, target, localIP, puncher)", src)

    def test_the_two_dropped_ops_need_a_puncher(self):
        """Both astral-go clients take a `nat.Puncher`, or drive a handshake
        that ends with the caller owning a punched socket."""
        punch = self.source(reference.ASTRAL_GO, "api/nat/client/node_punch.go")
        consume = self.source(
            reference.ASTRAL_GO, "api/nat/client/node_consume_hole.go"
        )
        iface = self.source(reference.ASTRAL_GO, "api/nat/puncher.go")
        self.assertIn("puncher nat.Puncher", punch)
        self.assertIn("HolePunch(ctx context.Context", iface)
        self.assertIn("ConsumeHoleSignalTypeLock", consume)

    def test_the_hole_endpoints_are_values_and_not_interfaces(self):
        src = self.source(reference.ASTRAL_GO, "api/nat/hole.go")
        self.assertIn("ActiveEndpoint  Endpoint", src)
        self.assertIn("PassiveEndpoint Endpoint", src)
        self.assertNotIn("exonet.Endpoint", src)

    def test_the_nat_endpoint_reports_the_kcp_network(self):
        src = self.source(reference.ASTRAL_GO, "api/nat/endpoint.go")
        self.assertIn('return "kcp"', src)

    def test_only_the_kcp_module_claims_the_kcp_network_name(self):
        deps = self.source(reference.ASTRALD, "mod/kcp/src/deps.go")
        self.assertIn('mod.Exonet.SetParser("kcp", mod)', deps)
        for name in reference.listdir(reference.ASTRALD, "mod/nat/src"):
            with self.subTest(file=name):
                body = reference.read(reference.ASTRALD, f"mod/nat/src/{name}")
                self.assertNotIn("Exonet.SetParser", body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
