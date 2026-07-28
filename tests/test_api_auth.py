"""The `auth` module client, its three wire types, and the action field base.

Three tiers in one file, and every Tier-A vector in it is bytes the node sent
rather than bytes this SDK produced, so a round trip cannot agree with itself
while disagreeing with `furry-bolt`:

- **Tier A** pins the schema and the two embed rules. The node's own
  `astral.blueprint` for each of the three types is compared field for field
  against `astral.blueprint.of()` on the declaration here -- a stronger check
  than a zero-payload vector, because it names every field and every spec rather
  than the bytes they happen to produce when empty. The zero payloads are pinned
  too, in both façades, and they are what proves the embed asymmetry:
  `mod.auth.signed_contract` nests its embedded pointer under `"Contract"` in
  JSON and flattens it in binary, while every action type flattens its embedded
  **value** in both.
- **Tier B** pins the two ops against `MockApphost`: the query string `index`
  builds, the required-argument discipline, and the fact that `sign_contract`
  puts the contract on the channel **body** with an `eos` after it.
- **Tier C** runs the read-only half against a real node: the op inventory from
  `shell.spec`, the three zero values from `objects.new`, the three blueprints
  from `objects.get_blueprint`, and the two ops' refusal shapes. Nothing in the
  live tier signs, stores or indexes anything: `auth.index` is sent **without**
  its required `id`, so the routing layer refuses it before the op body runs,
  and `auth.sign_contract` is opened and closed with no contract on the body, so
  there is nothing for the node to sign.

The two ops are the module's whole surface and neither is a read: `auth.index`
mutates the local contract index and `auth.sign_contract` needs the node to hold
two private keys. So the live tier exercises their **refusals** and their
types, which is the whole of what a read-only tier is entitled to.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import pathlib
import re
import unittest

import astral
from astral import blueprint
from astral.api.auth import (
    AUTH_TYPES,
    Action,
    Auth,
    Contract,
    OP_INDEX,
    OP_SIGN_CONTRACT,
    Permit,
    SignedContract,
)
from astral.client import Client, connect
from astral.codec import jsoncodec
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import (
    BadArgumentType,
    ParseError,
    ProtocolError,
    QueryRejected,
    RangeError,
    RemoteError,
    RouteNotFound,
)
from astral.errors import QueryTimeout
from astral.object import Bundle
from astral.objectid import object_id
from astral.primitives import String8
from astral.record import record, wire
from astral.registry import Blueprints, default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive, Ptr, Slice
from astral.types import Identity, Nonce, ObjectID, Time
from astral.wire import Writer

import live_support
import reference
from astral.api import auth as auth_module
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    MockConn,
    MockApphost,
    QUERY_ACCEPTED,
    Reject,
    RouteQuery,
    bounded,
    socket_fds,
)

OTHER = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

# --- vectors captured from `furry-bolt` this session ----------------------
#
# `objects.get_blueprint?type=<t>`: the node's own schema for each type, as the
# payload of the `astral.blueprint` object it answered with.

NODE_BLUEPRINTS = {
    "mod.auth.contract": (
        "00116d6f642e617574682e636f6e74726163740000000401000649737375657219"
        "61737472616c2e626c75657072696e742e7074725f7370656300086964656e7469"
        "74790100075375626a6563741961737472616c2e626c75657072696e742e707472"
        "5f7370656300086964656e746974790100075065726d6974731b61737472616c2e"
        "626c75657072696e742e736c6963655f73706563000f6d6f642e617574682e7065"
        "726d69740100094578706972657341741f61737472616c2e626c75657072696e74"
        "2e7072696d69746976655f73706563000474696d650000"
    ),
    "mod.auth.permit": (
        "000f6d6f642e617574682e7065726d697400000003010006416374696f6e1f6173"
        "7472616c2e626c75657072696e742e7072696d69746976655f7370656300077374"
        "72696e673801000b436f6e73747261696e74731961737472616c2e626c75657072"
        "696e742e7074725f73706563000662756e646c6501000a44656c65676174696f6e"
        "1f61737472616c2e626c75657072696e742e7072696d69746976655f7370656300"
        "0575696e74380000"
    ),
    "mod.auth.signed_contract": (
        "00186d6f642e617574682e7369676e65645f636f6e747261637400000003010008"
        "436f6e74726163741961737472616c2e626c75657072696e742e7074725f737065"
        "6300116d6f642e617574682e636f6e74726163740100094973737565725369671961"
        "737472616c2e626c75657072696e742e7074725f7370656300146d6f642e637279"
        "70746f2e7369676e617475726501000a5375626a6563745369671961737472616c"
        "2e626c75657072696e742e7074725f7370656300146d6f642e63727970746f2e73"
        "69676e61747572650000"
    ),
}

# `objects.new?type=<t>`: the zero value's payload, and the same value in JSON.
NODE_ZERO_BINARY = {
    "mod.auth.contract": "000000000000a1b203eb3d1a0000",
    "mod.auth.permit": "000000",
    "mod.auth.signed_contract": "000000",
}
NODE_ZERO_JSON = {
    "mod.auth.contract": (
        '{"ExpiresAt":"0001-01-01T00:00:00Z","Issuer":null,"Permits":[],'
        '"Subject":null}'
    ),
    "mod.auth.permit": '{"Action":"","Constraints":null,"Delegation":0}',
    "mod.auth.signed_contract": (
        '{"Contract":null,"IssuerSig":null,"SubjectSig":null}'
    ),
}

# Every action type on the node flattens its embedded `auth.Action`. Both
# façades, captured the same way.
NODE_ACTION_BINARY = {
    "mod.auth.sudo_action": "00000000000000000000",
    "mod.objects.read_object_action": "00000000000000000000",
    "mod.objects.create_object_action": "000000000000000000",
    "mod.user.adopt_action": "00000000000000000000",
}
NODE_ACTION_JSON = {
    "mod.auth.sudo_action": '{"Nonce":"0","ActorID":null,"AsID":null}',
    "mod.objects.read_object_action": (
        '{"Nonce":"0","ActorID":null,"ObjectID":null}'
    ),
    "mod.objects.create_object_action": '{"Nonce":"0","ActorID":null}',
    "mod.user.adopt_action": '{"Nonce":"0","ActorID":null,"Subject":null}',
}

# The blueprint every action type is refused, and the reason astral-go gives.
NODE_ACTION_BLUEPRINT_ERROR = (
    "BlueprintFromType mod.objects.read_object_action.Action: type auth.Action "
    "does not implement Object and is not a supported container"
)

def frame_error(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ACK_FRAME = ("ack", b"")
OID = ObjectID(size=5, hash=bytes(range(32)))


def a_contract() -> Contract:
    """A fully populated contract: two identities, one permit, an expiry."""
    return Contract(
        issuer=FURRY_BOLT,
        subject=OTHER,
        permits=[
            Permit(
                action="mod.objects.read_object_action",
                constraints=None,
                delegation=2,
            )
        ],
        expires_at=Time.parse("2030-01-01T00:00:00Z"),
    )


class SigningNode:
    """A mock route that reads its input **before** answering, like the op does.

    `Accept(read=True)` cannot serve a write-and-answer op: it writes the answer
    first, and a client that has its answer closes the stream, which discards
    whatever the mock had not yet read -- `MemTransport.abandon` models a socket
    RST and drops unread bytes. So the frames the client sent would be
    unobservable exactly when the exchange succeeded. This handler reads first,
    which is also the order `ch.Switch` reads in.
    """

    def __init__(self, answer: tuple[str, bytes] | None = None, expect: int = 2) -> None:
        self.answer = answer
        self.expect = expect
        self.received: list[tuple[str, bytes]] = []

    async def __call__(self, conn: MockConn, query: RouteQuery) -> None:
        conn.send_frame(QUERY_ACCEPTED)
        await conn.flush()
        for _ in range(self.expect):
            got = await conn.recv_frame_or_none()
            if got is None:
                break
            self.received.append(got)
        if self.answer is not None:
            conn.send_frame(*self.answer)
            await conn.flush()

    @property
    def types(self) -> list[str]:
        return [name for name, _ in self.received]


def a_signature(scheme: str, data: bytes) -> object:
    """One `mod.crypto.signature`, built through the registry by wire name.

    The class belongs to `astral.api.crypto`; this file reaches it by **name**
    rather than by import, because that is exactly the coupling the declaration
    states: `Ptr("mod.crypto.signature")` resolves through the registry and
    `astral.api.auth` never imports the class. The fields are addressed through
    the schema for the same reason -- `Scheme` and `Data` are Go's names and
    travel, the Python attributes are that module's to choose.
    """
    value = default_blueprints().new("mod.crypto.signature")
    attrs = {f.wire_name: f.attr for f in type(value).FIELDS}
    setattr(value, attrs["Scheme"], scheme)
    setattr(value, attrs["Data"], data)
    return value


def a_signed_contract() -> SignedContract:
    """The same contract with both signatures set."""
    return SignedContract(
        contract=a_contract(),
        issuer_sig=a_signature("asn1", b"\x01\x02\x03"),
        subject_sig=a_signature("bip137", b"\xaa"),
    )


# --- Tier A: the types, against the node's own schema ---------------------


class AuthTypesTest(unittest.TestCase):
    """What this module registers, and what it deliberately does not."""

    def test_the_three_types_are_registered_under_their_wire_names(self):
        registry = default_blueprints()
        for cls in (Contract, Permit, SignedContract):
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertIs(registry.find(cls.ASTRAL_TYPE), cls)
        self.assertEqual(
            {cls.ASTRAL_TYPE for cls in AUTH_TYPES},
            {"mod.auth.contract", "mod.auth.permit", "mod.auth.signed_contract"},
        )
        self.assertEqual(Auth.TYPES, AUTH_TYPES)

    def test_mod_auth_action_is_not_a_registered_type(self):
        """The node answers `nil` to `objects.new?type=mod.auth.action` and
        `blueprint not found` to `objects.get_blueprint`, both verified live.
        astral-go's `auth.Action` has no `ObjectType` method and is never added
        to the registry, so a record here would invent a name nothing knows."""
        self.assertFalse(default_blueprints().has("mod.auth.action"))
        self.assertFalse(hasattr(Action, "ASTRAL_TYPE"))
        self.assertNotIn(Action, AUTH_TYPES)

    def test_mod_auth_sudo_action_is_not_declared_here(self):
        """It exists -- astrald declares and registers it, and the live node
        answers a ten-byte zero instance -- but it belongs to astrald rather
        than to astral-go's `api/auth`, and no op sends one."""
        self.assertFalse(default_blueprints().has("mod.auth.sudo_action"))

    def test_the_signature_type_the_declaration_points_at_is_registered(self):
        """Both signature fields are `Ptr("mod.crypto.signature")`, resolved by
        name at decode time. `astral.api.crypto` owns the class; this module
        never imports it, and importing `astral.api` registers both."""
        self.assertTrue(default_blueprints().has("mod.crypto.signature"))
        specs = {f.wire_name: f.spec for f in SignedContract.FIELDS}
        self.assertEqual(specs["IssuerSig"], Ptr("mod.crypto.signature"))
        self.assertEqual(specs["SubjectSig"], Ptr("mod.crypto.signature"))


class BlueprintParityTest(unittest.TestCase):
    """The node's schema for each type, field for field, against this module's.

    Stronger than a zero-payload vector: a blueprint names every field and every
    spec, so a declaration that produced the right zero bytes with the wrong
    field order still fails here.
    """

    def test_every_declaration_equals_the_node_s_own_blueprint(self):
        for cls in (Contract, Permit, SignedContract):
            with self.subTest(type=cls.ASTRAL_TYPE):
                raw = bytes.fromhex(NODE_BLUEPRINTS[cls.ASTRAL_TYPE])
                theirs = blueprint.Blueprint.read_payload(object_reader(raw))
                self.assertEqual(theirs, blueprint.of(cls))

    def test_the_node_s_blueprint_re_encodes_byte_for_byte(self):
        """The vector is the node's bytes, so decode-then-encode is the identity
        on them or the vector is not what it claims to be."""
        for name, hexed in NODE_BLUEPRINTS.items():
            with self.subTest(type=name):
                raw = bytes.fromhex(hexed)
                theirs = blueprint.Blueprint.read_payload(object_reader(raw))
                self.assertEqual(payload_bytes(theirs), raw)

    def test_the_contract_field_order_is_the_node_s(self):
        self.assertEqual(
            [(f.wire_name, f.spec) for f in Contract.FIELDS],
            [
                ("Issuer", Ptr("identity")),
                ("Subject", Ptr("identity")),
                ("Permits", Slice("mod.auth.permit")),
                ("ExpiresAt", Primitive("time")),
            ],
        )

    def test_the_permit_field_order_is_the_node_s(self):
        self.assertEqual(
            [(f.wire_name, f.spec) for f in Permit.FIELDS],
            [
                ("Action", Primitive("string8")),
                ("Constraints", Ptr("bundle")),
                ("Delegation", Primitive("uint8")),
            ],
        )


class ZeroValueTest(unittest.TestCase):
    """The node's zero payloads, decoded and re-encoded."""

    def test_every_zero_payload_decodes_and_re_encodes(self):
        for cls in (Contract, Permit, SignedContract):
            with self.subTest(type=cls.ASTRAL_TYPE):
                raw = bytes.fromhex(NODE_ZERO_BINARY[cls.ASTRAL_TYPE])
                value = cls.read_payload(object_reader(raw))
                self.assertEqual(payload_bytes(value), raw)

    def test_the_permit_and_signed_contract_zeros_are_this_sdk_s_too(self):
        """Three bytes each, and the SDK constructs the same value the node
        does: a string8 length, a nil flag and a uint8 for the permit; three nil
        flags for the signed contract."""
        self.assertEqual(payload_bytes(Permit()).hex(), NODE_ZERO_BINARY["mod.auth.permit"])
        self.assertEqual(
            payload_bytes(SignedContract()).hex(),
            NODE_ZERO_BINARY["mod.auth.signed_contract"],
        )

    def test_the_contract_zero_differs_from_the_node_s_in_the_timestamp_alone(self):
        """astral-go's zero `Time` is Go's zero `time.Time`, year 1, whose
        `UnixNano()` overflows int64; the SDK's zero `time` is the Unix epoch.
        The first six bytes -- two nil flags and a zero permit count -- are
        identical, and the eight that follow are the only difference."""
        theirs = bytes.fromhex(NODE_ZERO_BINARY["mod.auth.contract"])
        mine = payload_bytes(Contract())
        self.assertEqual(len(theirs), len(mine))
        self.assertEqual(theirs[:6], mine[:6])
        self.assertNotEqual(theirs[6:], mine[6:])

    def test_the_node_s_zero_timestamp_reads_as_the_instant_its_bytes_encode(self):
        """`a1b203eb3d1a0000` is what Go writes for year 1 and reads back as
        1754-08-30. The SDK reproduces the bytes and the instant, because the
        wire is int64 nanoseconds and that is the value on it."""
        raw = bytes.fromhex(NODE_ZERO_BINARY["mod.auth.contract"])
        contract = Contract.read_payload(object_reader(raw))
        self.assertEqual(str(contract.expires_at), "1754-08-30T22:43:41.128654848Z")

    def test_the_node_s_zero_json_matches_this_module_s_field_names(self):
        """Keys and values both: the JSON the node sends is what this module's
        walker produces, save for the empty-slice and zero-time divergences the
        `DivergenceTest` below pins."""
        for name in ("mod.auth.permit", "mod.auth.signed_contract"):
            with self.subTest(type=name):
                theirs = json.loads(NODE_ZERO_JSON[name])
                cls = default_blueprints().find(name)
                self.assertEqual(jsoncodec.marshal(cls()), theirs)


class EmbedTest(unittest.TestCase):
    """The one asymmetry: a pointer embed nests in JSON, a value embed does not.

    Both halves are the node's own output. The distinction is invisible in
    binary -- everything flattens there -- so JSON is the only place it can be
    observed, and getting it wrong makes an object that encodes correctly and
    decodes into silence.
    """

    def test_the_embedded_contract_nests_under_its_type_name_in_json(self):
        theirs = json.loads(NODE_ZERO_JSON["mod.auth.signed_contract"])
        self.assertEqual(sorted(theirs), ["Contract", "IssuerSig", "SubjectSig"])
        for key in ("Issuer", "Subject", "Permits", "ExpiresAt"):
            self.assertNotIn(key, theirs)

    def test_a_populated_embed_carries_the_contract_s_own_keys_one_level_down(self):
        value = jsoncodec.marshal(a_signed_contract())
        self.assertEqual(sorted(value), ["Contract", "IssuerSig", "SubjectSig"])
        self.assertEqual(
            sorted(value["Contract"]),
            ["ExpiresAt", "Issuer", "Permits", "Subject"],
        )

    def test_the_embedded_contract_flattens_in_binary(self):
        """A pointer embed is a nil flag and the payload inline. The signed
        contract's zero payload is three bytes, one per pointer, so the embed
        costs exactly one byte when absent."""
        self.assertEqual(len(payload_bytes(SignedContract())), 3)
        signed = a_signed_contract()
        inner = payload_bytes(signed.contract)
        self.assertIn(inner, payload_bytes(signed))

    def test_an_action_s_value_embed_flattens_in_both_facades(self):
        """`mod.objects.read_object_action` on the node: ten binary bytes and
        three top-level JSON keys, with no `Action` key anywhere."""
        theirs = json.loads(NODE_ACTION_JSON["mod.objects.read_object_action"])
        self.assertEqual(sorted(theirs), ["ActorID", "Nonce", "ObjectID"])
        self.assertNotIn("Action", theirs)
        self.assertEqual(
            len(bytes.fromhex(NODE_ACTION_BINARY["mod.objects.read_object_action"])),
            10,
        )


class ActionBaseTest(unittest.TestCase):
    """`Action` as a field base: the two fields, promoted, in Go's order."""

    def setUp(self) -> None:
        # A private registry with no parent, so this fixture never claims a name
        # in the process-wide one -- `astral.api.objects` owns these two types
        # and a child registry would collide with it the moment it lands.
        self.registry = Blueprints()

        @record("mod.objects.read_object_action", registry=self.registry)
        class ReadObjectAction(Action):
            object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))

        self.cls = ReadObjectAction

    def test_the_base_fields_come_first_and_in_the_node_s_order(self):
        self.assertEqual(
            [f.wire_name for f in self.cls.FIELDS], ["Nonce", "ActorID", "ObjectID"]
        )

    def test_the_zero_payload_is_the_node_s(self):
        self.assertEqual(
            payload_bytes(self.cls()).hex(),
            NODE_ACTION_BINARY["mod.objects.read_object_action"],
        )

    def test_the_zero_json_is_the_node_s(self):
        self.assertEqual(
            jsoncodec.marshal(self.cls()),
            json.loads(NODE_ACTION_JSON["mod.objects.read_object_action"]),
        )

    def test_an_action_with_no_extra_field_is_nine_bytes(self):
        """`mod.objects.create_object_action` adds nothing to the base, so the
        base alone is a nonce and one nil flag."""

        @record("mod.objects.create_object_action", registry=self.registry)
        class CreateObjectAction(Action):
            pass

        self.assertEqual(
            payload_bytes(CreateObjectAction()).hex(),
            NODE_ACTION_BINARY["mod.objects.create_object_action"],
        )

    def test_a_populated_action_round_trips(self):
        value = self.cls(nonce=Nonce(0x1122334455667788), actor_id=FURRY_BOLT, object_id=OID)
        raw = payload_bytes(value)
        back = self.cls.read_payload(object_reader(raw, registry=self.registry))
        self.assertEqual(back, value)
        self.assertEqual(payload_bytes(back), raw)

    def test_the_base_is_a_dataclass_and_not_a_record(self):
        self.assertTrue(dataclasses.is_dataclass(Action))
        self.assertFalse(hasattr(Action, "ASTRAL_TYPE"))


class PermitTest(unittest.TestCase):
    """`allows`, the constraints bundle, and the delegation byte."""

    def test_a_permit_allows_its_own_action_type_and_no_other(self):
        permit = Permit(action="mod.objects.read_object_action")

        class Anything:
            ASTRAL_TYPE = "mod.objects.read_object_action"

        class Other:
            ASTRAL_TYPE = "mod.user.adopt_action"

        self.assertTrue(permit.allows(Anything()))
        self.assertFalse(permit.allows(Other()))

    def test_an_action_that_declares_constraints_decides_for_itself(self):
        bundle = Bundle([String8("x")])
        permit = Permit(action="a", constraints=bundle)
        seen: list[object] = []

        class Constrained:
            ASTRAL_TYPE = "a"

            def apply_constraints(self, constraints):  # type: ignore[no-untyped-def]
                seen.append(constraints)
                return False

        self.assertFalse(permit.allows(Constrained()))
        self.assertEqual(seen, [bundle])

    def test_an_action_with_no_constraint_method_is_allowed_regardless(self):
        """astral-go's rule, ported unchanged: a type that does not implement
        `Constrainable` is permitted whatever the constraints say. The trap is
        that a new action type which forgets the method is unconstrained rather
        than refused."""
        permit = Permit(action="a", constraints=Bundle([String8("no")]))

        class Unconstrained:
            ASTRAL_TYPE = "a"

        self.assertTrue(permit.allows(Unconstrained()))

    def test_a_permit_with_a_bundle_round_trips(self):
        permit = Permit(action="a", constraints=Bundle([String8("x")]), delegation=3)
        raw = payload_bytes(permit)
        back = Permit.read_payload(object_reader(raw))
        self.assertEqual(back, permit)
        self.assertEqual(payload_bytes(back), raw)

    def test_delegation_is_one_byte(self):
        self.assertEqual(payload_bytes(Permit(delegation=255)).hex(), "0000ff")
        with self.assertRaises((RangeError, ValueError)):
            payload_bytes(Permit(delegation=256))


class ContractTest(unittest.TestCase):
    """The contract's own reads: permits, expiry and the two signing preimages."""

    def test_a_populated_contract_round_trips(self):
        contract = a_contract()
        raw = payload_bytes(contract)
        back = Contract.read_payload(object_reader(raw))
        self.assertEqual(back, contract)
        self.assertEqual(payload_bytes(back), raw)

    def test_a_permit_slice_element_carries_its_own_presence_byte(self):
        """`Permits` is `[]*Permit` in Go, whose element type is a pointer, so
        `ptrValue` writes the flag and the container synthesizes none. The SDK's
        slice-of-named-type rule writes the same byte, which is why the two
        spellings are the same bytes."""
        contract = a_contract()
        raw = payload_bytes(contract)
        # 1 issuer flag + 33 identity, 1 subject flag + 33 identity = 68, then
        # the uint32 count, then the element's own flag.
        self.assertEqual(raw[68:72], b"\x00\x00\x00\x01")
        self.assertEqual(raw[72], 0x01)
        element = payload_bytes(contract.permits[0])
        self.assertEqual(raw[73 : 73 + len(element)], element)

    def test_an_absent_permit_decodes_to_none_and_re_encodes_to_the_same_byte(self):
        contract = Contract(permits=[None])
        raw = payload_bytes(contract)
        back = Contract.read_payload(object_reader(raw))
        self.assertEqual(back.permits, [None])
        self.assertEqual(payload_bytes(back), raw)

    def test_has_permit_selects_by_action_type(self):
        read = Permit(action="mod.objects.read_object_action")
        adopt = Permit(action="mod.user.adopt_action")
        contract = Contract(permits=[read, None, adopt, read])
        self.assertEqual(
            contract.has_permit("mod.objects.read_object_action"), [read, read]
        )
        self.assertEqual(contract.has_permit("mod.nodes.relay_for_action"), [])

    def test_has_permit_accepts_an_action_object(self):
        read = Permit(action="mod.objects.read_object_action")

        class ReadAction:
            ASTRAL_TYPE = "mod.objects.read_object_action"

        self.assertEqual(Contract(permits=[read]).has_permit(ReadAction()), [read])

    def test_expiry_is_the_whole_of_the_validity_window(self):
        past = Contract(expires_at=Time(Time.now() - 10**9))
        future = Contract(expires_at=Time(Time.now() + 3600 * 10**9))
        self.assertTrue(past.expired)
        self.assertFalse(future.expired)

    def test_signable_hash_is_the_object_id_hash_of_the_contract(self):
        contract = a_contract()
        self.assertEqual(contract.signable_hash(), object_id(contract).hash)
        self.assertEqual(len(contract.signable_hash()), 32)

    def test_signable_text_reproduces_the_go_format_verbatim(self):
        """One character of difference is a signature that never verifies, so
        the whole string is asserted rather than a substring of it."""
        self.assertEqual(
            a_contract().signable_text(),
            f"{FURRY_BOLT.text()} grants {OTHER.text()} permits (1) until "
            "2030-01-01 00:00:00",
        )

    def test_signable_text_renders_an_absent_identity_as_sixty_six_zeros(self):
        """Go's `(*Identity).String()` maps a nil receiver and the zero key to
        the same 66 zeros, so the signed text cannot distinguish them."""
        text = Contract().signable_text()
        self.assertEqual(text.count("0" * 66), 2)
        self.assertTrue(text.startswith(Identity.ANYONE.text()))

    def test_signable_text_truncates_the_timestamp_to_the_second(self):
        contract = Contract(expires_at=Time.parse("2030-01-01T00:00:00.999999999Z"))
        self.assertTrue(contract.signable_text().endswith("2030-01-01 00:00:00"))


class SignedContractTest(unittest.TestCase):
    """The signed wrapper: the pointer embed, the two signatures, the predicate."""

    def test_a_populated_signed_contract_round_trips_through_the_registry(self):
        """The signature type is resolved by name, so this is also the check
        that `Ptr("mod.crypto.signature")` reaches `astral.api.crypto`."""
        signed = a_signed_contract()
        raw = payload_bytes(signed)
        back = SignedContract.read_payload(object_reader(raw))
        self.assertEqual(back, signed)
        self.assertEqual(payload_bytes(back), raw)
        self.assertEqual(back.issuer_sig.ASTRAL_TYPE, "mod.crypto.signature")

    def test_fully_signed_is_both_signatures_present(self):
        signed = a_signed_contract()
        self.assertTrue(signed.fully_signed)
        signed.subject_sig = None
        self.assertFalse(signed.fully_signed)
        self.assertFalse(SignedContract().fully_signed)

    def test_the_contract_is_reached_through_the_field_and_not_forwarded(self):
        """The embedded pointer is nullable, so a forwarding hop through `None`
        would produce a worse message than the direct one."""
        signed = a_signed_contract()
        self.assertEqual(signed.contract.issuer, FURRY_BOLT)
        with self.assertRaises(AttributeError):
            signed.issuer  # noqa: B018 -- the assertion is the access

    def test_an_absent_contract_is_one_nil_byte(self):
        self.assertEqual(payload_bytes(SignedContract(contract=None))[0], 0x00)


class DivergenceTest(unittest.TestCase):
    """Two places where this SDK and the node do not agree, both recorded.

    Neither is in a path any shipped op takes today -- no channel format but
    binary is implemented -- and neither is fixable inside this module. They are
    pinned so that a change to either is deliberate.
    """

    def test_an_empty_permit_list_marshals_to_null_where_the_node_sends_an_array(self):
        """`astral-go/astral/slice_value.go:90` allocates a non-nil array so an
        empty slice marshals to `[]`, and the node's zero contract carries
        `"Permits":[]`. The SDK's JSON codec maps an empty container to `null`,
        which astral-go reads back as a nil slice, so the divergence is in the
        emission and not in the round trip."""
        self.assertIn('"Permits":[]', NODE_ZERO_JSON["mod.auth.contract"])
        self.assertIsNone(jsoncodec.marshal(Contract())["Permits"])
        self.assertEqual(
            jsoncodec.unmarshal("mod.auth.contract", {"Permits": []}).permits, []
        )

    def test_the_node_s_zero_contract_json_is_out_of_int64_nanosecond_range(self):
        """`"ExpiresAt":"0001-01-01T00:00:00Z"` is Go's zero `time.Time`, which
        is -6.2e19 nanoseconds and does not fit the int64 the binary wire
        carries. The SDK refuses it rather than truncating. The same value in
        binary arrives as `a1b203eb3d1a0000` and decodes, because that is the
        wrapped int64 Go actually wrote."""
        with self.assertRaises(RangeError):
            jsoncodec.unmarshal(
                "mod.auth.contract", json.loads(NODE_ZERO_JSON["mod.auth.contract"])
            )
        Contract.read_payload(
            object_reader(bytes.fromhex(NODE_ZERO_BINARY["mod.auth.contract"]))
        )


# --- Tier B: the two ops, against the mock -------------------------------


class AuthCase(unittest.IsolatedAsyncioTestCase):
    """An `Auth` over a mock apphost, closed by the teardown whatever a test does."""

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

    async def auth(self, mock: MockApphost, **kw: object) -> Auth:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Auth(client)

    def sent(self, mock: MockApphost) -> str:
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    def assert_no_faults(self, mock: MockApphost) -> None:
        self.assertEqual(mock.errors, [])


class IndexOpTest(AuthCase):
    """`auth.index`: RR, one required argument, `ack` or `error_message`."""

    @bounded()
    async def test_it_sends_the_object_id_and_reads_the_ack(self):
        mock = MockApphost(routes={f"{OP_INDEX}?id={OID}": Accept(objects=[ACK_FRAME])})
        async with mock:
            api = await self.auth(mock)
            self.assertIsNone(await api.index(OID))
        self.assertEqual(self.sent(mock), f"{OP_INDEX}?id={OID}")
        self.assert_no_faults(mock)

    @bounded()
    async def test_it_accepts_the_text_form_of_an_object_id(self):
        mock = MockApphost(routes={f"{OP_INDEX}?id={OID}": Accept(objects=[ACK_FRAME])})
        async with mock:
            api = await self.auth(mock)
            await api.index(str(OID))
        self.assertEqual(self.sent(mock), f"{OP_INDEX}?id={OID}")

    @bounded()
    async def test_a_value_that_is_not_an_object_id_never_reaches_the_node(self):
        mock = MockApphost(routes={OP_INDEX: Accept(objects=[ACK_FRAME])})
        async with mock:
            api = await self.auth(mock)
            with self.assertRaises(ParseError):
                await api.index("not-an-object-id")
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_id_is_always_sent_because_the_op_requires_it(self):
        """`id` carries `query:"required"` and the live spec flags it, so an
        absent one is refused by the routing layer before the op body runs. The
        argument is therefore positional here and has no default."""
        with self.assertRaises(TypeError):
            await Auth(object()).index()  # type: ignore[call-arg]

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        """Every failure past the required check arrives this way: object not
        found, invalid contract, a signature that does not verify."""
        mock = MockApphost(
            routes={f"{OP_INDEX}?id={OID}": Accept(objects=[frame_error("invalid contract")])}
        )
        async with mock:
            api = await self.auth(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.index(OID)
        self.assertIn("invalid contract", str(caught.exception))

    @bounded()
    async def test_an_answer_that_is_not_an_ack_is_a_protocol_error(self):
        mock = MockApphost(
            routes={f"{OP_INDEX}?id={OID}": Accept(objects=[("eos", b"")])}
        )
        async with mock:
            api = await self.auth(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.index(OID)
        self.assertIn(OP_INDEX, str(caught.exception))

    @bounded()
    async def test_a_rejected_query_surfaces_as_query_rejected(self):
        """The shape an absent `id` produces on a real node, reproduced here so
        the distinction from an `error_message` is pinned: a rejection carries a
        code and no message."""
        mock = MockApphost(routes={f"{OP_INDEX}?id={OID}": Reject(1)})
        async with mock:
            api = await self.auth(mock)
            with self.assertRaises(QueryRejected):
                await api.index(OID)


class SignContractOpTest(AuthCase):
    """`auth.sign_contract`: WA, the contract on the body, an `eos` after it."""

    def signed_frame(self) -> tuple[str, bytes]:
        return ("mod.auth.signed_contract", payload_bytes(a_signed_contract()))

    async def node(self, answer: tuple[str, bytes] | None, **kw: object) -> tuple[
        Auth, SigningNode, MockApphost
    ]:
        """A client, the route that serves it, and the mock, all torn down by
        the case's teardown."""
        route = SigningNode(answer, **kw)  # type: ignore[arg-type]
        mock = MockApphost(routes={OP_SIGN_CONTRACT: route})
        await self.enterAsyncContext(mock)
        return await self.auth(mock), route, mock

    @bounded()
    async def test_the_contract_travels_on_the_body_and_not_in_the_query_string(self):
        api, route, mock = await self.node(self.signed_frame())
        answer = await api.sign_contract(a_contract())
        self.assertEqual(self.sent(mock), OP_SIGN_CONTRACT)
        self.assertIsInstance(answer, SignedContract)
        self.assertEqual(answer.contract, a_contract())
        self.assertEqual(route.types, ["mod.auth.contract", "eos"])
        self.assertEqual(route.received[0][1], payload_bytes(a_contract()))

    @bounded()
    async def test_the_terminator_is_sent_because_this_op_breaks_on_it(self):
        """`auth.sign_contract`'s reader is `ch.Switch(handler, BreakOnEOS)`;
        `apphost.sign_app_contract`'s is not, and answers `error_message` for
        the same frame. One op name apart, opposite terminators."""
        api, route, _ = await self.node(self.signed_frame())
        await api.sign_contract(a_contract())
        self.assertEqual(route.types[-1], "eos")

    @bounded()
    async def test_the_answer_is_typed(self):
        api, _, _ = await self.node(self.signed_frame())
        answer = await api.sign_contract(a_contract())
        self.assertTrue(answer.fully_signed)
        self.assertEqual(answer.issuer_sig.ASTRAL_TYPE, "mod.crypto.signature")

    @bounded()
    async def test_an_answer_of_another_type_is_a_protocol_error(self):
        api, _, _ = await self.node(ACK_FRAME)
        with self.assertRaises(ProtocolError) as caught:
            await api.sign_contract(a_contract())
        self.assertIn("mod.auth.signed_contract", str(caught.exception))

    @bounded()
    async def test_a_stream_that_answers_nothing_is_reported(self):
        """The op read the contract, accepted it and closed. `expect=1` reads
        one answer and stops, so the report is the SDK's rather than a deadline
        the caller waited out."""
        api, _, _ = await self.node(None)
        with self.assertRaises(ProtocolError) as caught:
            await api.sign_contract(a_contract())
        self.assertIn("without answering", str(caught.exception))

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        api, _, _ = await self.node(frame_error("sign as issuer: key not found"))
        with self.assertRaises(RemoteError) as caught:
            await api.sign_contract(a_contract())
        self.assertIn("sign as issuer", str(caught.exception))

    @bounded()
    async def test_a_signed_contract_is_refused_before_it_is_sent(self):
        """The op reads the unsigned body and wraps it in a **new**
        `SignedContract`, discarding any signatures, so sending a signed one is
        a round trip that cannot mean what the caller meant."""
        api, _, mock = await self.node(None)
        with self.assertRaises(BadArgumentType) as caught:
            await api.sign_contract(a_signed_contract())  # type: ignore[arg-type]
        self.assertEqual(mock.queries, [])
        self.assertIn("unsigned body", str(caught.exception))


class AuthPlumbingTest(AuthCase):
    """What every op shares: the keyword set, routing, and closing the stream."""

    @bounded()
    async def test_query_keywords_reach_the_client(self):
        mock = MockApphost(routes={f"{OP_INDEX}?id={OID}": Accept(objects=[ACK_FRAME])})
        async with mock:
            api = await self.auth(mock)
            await api.index(OID, caller=FURRY_BOLT, target=OTHER)
        query = mock.queries[0]
        self.assertEqual(query.caller, FURRY_BOLT)
        self.assertEqual(query.target, OTHER)

    @bounded()
    async def test_an_unrouted_op_is_route_not_found(self):
        async with MockApphost() as mock:
            api = await self.auth(mock)
            with self.assertRaises(RouteNotFound):
                await api.index(OID)

    @bounded()
    async def test_every_op_closes_its_stream(self):
        """A stream left open burns one of the node's 32 workers until the node
        restarts, so both ops are run and the client is then asserted idle."""
        mock = MockApphost(
            routes={
                f"{OP_INDEX}?id={OID}": Accept(objects=[ACK_FRAME]),
                OP_SIGN_CONTRACT: SigningNode(
                    ("mod.auth.signed_contract", payload_bytes(a_signed_contract()))
                ),
            }
        )
        async with mock:
            api = await self.auth(mock)
            await api.index(OID)
            await api.sign_contract(a_contract())
            self.assertEqual(api.client.live_streams, 0)


# --- Tier C: the live node ----------------------------------------------


class LiveAuthTest(live_support.LiveCase):
    """The read-only half against a real node.

    Nothing here signs, stores or indexes. `auth.index` is sent without its
    required `id`, which the routing layer refuses before the op body runs, and
    `auth.sign_contract` is opened and closed with nothing on the body, so the
    node has nothing to sign. Both are the ops' refusal shapes and both are
    verified rather than assumed.
    """

    @bounded(30.0)
    async def test_the_module_s_op_surface_is_exactly_these_two(self):
        """`shell.spec` is the node's own op registry, so this is the inventory
        rather than a copy of it."""
        async with await self.client() as client:
            body = await client.call_raw("shell.spec?out=json", timeout=20.0)
        names = {
            json.loads(line)["Object"]["Name"]
            for line in body.decode().splitlines()
            if line and json.loads(line)["Type"] == "routing.op_spec"
        }
        self.assertEqual(
            {name for name in names if name.startswith("auth.")},
            {OP_INDEX, OP_SIGN_CONTRACT},
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_index_op_requires_its_object_id(self):
        """The node's own flag, and the pin on the batch-mode drift: astrald
        `fdbddccb` makes `id` optional and adds a batch form this module does
        not implement. A node upgraded past that commit fails here, which is
        where the decision to add `index_many()` belongs."""
        async with await self.client() as client:
            spec = json.loads(
                (await client.call_raw(f"shell.spec?op={OP_INDEX}&out=json", timeout=20.0))
                .decode()
                .splitlines()[0]
            )["Object"]
        required = {p["Name"]: p["Required"] for p in spec["Parameters"]}
        self.assertEqual(required["id"], True)
        self.assertEqual(spec["Parameters"][0]["Type"], "object_id.sha256")

    @bounded(30.0)
    async def test_the_three_zero_values_decode_and_re_encode(self):
        """`objects.new` is read-only and answers a zero-valued instance, so
        this is the whole schema exercised against the node with no state
        touched."""
        async with await self.client() as client:
            for cls in (Contract, Permit, SignedContract):
                with self.subTest(type=cls.ASTRAL_TYPE):
                    value = await client.call_one(
                        f"objects.new?type={cls.ASTRAL_TYPE}", timeout=20.0
                    )
                    self.assertIsInstance(value, cls)
                    self.assertEqual(
                        payload_bytes(value).hex(),
                        NODE_ZERO_BINARY[cls.ASTRAL_TYPE],
                    )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_every_declaration_matches_the_node_s_live_blueprint(self):
        async with await self.client() as client:
            for cls in (Contract, Permit, SignedContract):
                with self.subTest(type=cls.ASTRAL_TYPE):
                    theirs = await client.call_one(
                        f"objects.get_blueprint?type={cls.ASTRAL_TYPE}", timeout=20.0
                    )
                    self.assertEqual(theirs, blueprint.of(cls))

    @bounded(30.0)
    async def test_mod_auth_action_is_not_a_type_on_the_node(self):
        """The op survey's D-27 says `mod.auth.sudo_action` has no counterpart;
        the base struct is the one that genuinely has none. `objects.new`
        answers `nil` for an unregistered name."""
        async with await self.client() as client:
            value = await client.call_one("objects.new?type=mod.auth.action", timeout=20.0)
        self.assertEqual(getattr(value, "ASTRAL_TYPE", ""), "nil")

    @bounded(30.0)
    async def test_mod_auth_sudo_action_is_a_type_on_the_node(self):
        """astrald declares and registers it even though astral-go does not, so
        D-27's premise holds for astral-go and not for the node. Ten bytes: a
        nonce and two nil flags, the embedded `auth.Action` flattened."""
        async with await self.client() as client:
            async with client.stream(
                "objects.new?type=mod.auth.sudo_action", allow_unparsed=True, timeout=20.0
            ) as stream:
                objects = [obj async for obj in stream.raw_objects()]
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].ASTRAL_TYPE, "mod.auth.sudo_action")
        self.assertEqual(
            objects[0].payload.hex(), NODE_ACTION_BINARY["mod.auth.sudo_action"]
        )

    @bounded(30.0)
    async def test_no_action_type_has_a_blueprint_on_the_node(self):
        """astral-go's derivation stops at the embedded `auth.Action`, which has
        no `ObjectType` method, so no action type can be described to a peer and
        `astral.blueprint.of()` on an SDK action record produces a schema
        astral-go cannot produce for itself. The message is the node's."""
        async with await self.client() as client:
            with self.assertRaises(RemoteError) as caught:
                await client.call_one(
                    "objects.get_blueprint?type=mod.objects.read_object_action",
                    timeout=20.0,
                )
        self.assertTrue(
            str(caught.exception).endswith(NODE_ACTION_BLUEPRINT_ERROR),
            f"the node's message changed: {caught.exception}",
        )

    @bounded(30.0)
    async def test_index_without_its_required_id_is_rejected_before_the_op_runs(self):
        """A rejection, not an `error_message`: the routing layer refuses the
        query and the op body never executes, so nothing is loaded and nothing
        is indexed."""
        async with await self.client() as client:
            with self.assertRaises(QueryRejected):
                await client.call_one(OP_INDEX, timeout=20.0)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_sign_contract_accepts_and_says_nothing_until_it_is_given_one(self):
        """The WA shape, verified without signing anything: the op accepts and
        then blocks on its own reader, so a caller that waits for an answer it
        never asked for waits for the deadline. Closing with no contract on the
        body ends the op -- `Switch` returns on EOF and the deferred close runs
        -- and nothing has been signed."""
        async with await self.client() as client:
            async with client.stream(OP_SIGN_CONTRACT, timeout=20.0) as stream:
                with self.assertRaises(QueryTimeout):
                    await stream.first(timeout=2.0)
        await self.assert_no_open_sockets()


# --- the docstring, held to what the tree actually carries ---------------


class DocstringTest(unittest.TestCase):
    """Claims in the module docstring that the tree can check."""

    def test_the_docstring_matches_whether_client_carries_an_auth_property(self):
        """`client.auth` is the surface design section 5.1 specifies. It is not
        declared in `client.py`, and the docstring says so; when the property
        lands, this test fails and that sentence changes with it."""
        declared = isinstance(
            getattr(Client, "auth", None), functools.cached_property
        )
        doc = auth_module.__doc__ or ""
        claimed = "is not declared in `client.py`" not in doc
        self.assertEqual(
            declared,
            claimed,
            "the module docstring and `Client` disagree about `client.auth`",
        )

    def test_the_op_table_names_both_ops_and_no_others(self):
        doc = auth_module.__doc__ or ""
        found = set(re.findall(r"`(auth\.[a-z_]+)`", doc))
        self.assertEqual(found, {OP_INDEX, OP_SIGN_CONTRACT})


class CitationTest(unittest.TestCase):
    """Every `path:line` in this module lands on the claim it is cited for."""

    GO = reference.ASTRAL_GO

    CITATIONS = {
        "astral/channel/switch.go:101": "NewErrUnexpectedObject",
        "astral/struct_value.go:149": "s.Type().Field(i).Name",
        "astral/time.go:16": "func (t Time) WriteTo",
        "astral/identity.go:87": "func (id *Identity) String()",
        "astral/slice_value.go:90": "make([]json.RawMessage",
    }

    def test_every_cited_line_lands_on_its_claim(self):
        """Read at the pinned revision: a citation is a claim about a revision,
        and reading whatever the sibling checkout holds makes somebody else's
        `git pull` a failure of this suite."""
        for citation, expected in self.CITATIONS.items():
            path, _, number = citation.rpartition(":")
            with self.subTest(citation=citation):
                try:
                    line = reference.cited_line(self.GO, path, int(number))
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(expected, line)

    def test_only_the_lines_this_test_checks_are_cited(self):
        """A citation added without a line here would go unchecked, which is
        worse than an absent one: it makes a reader distrust the exact ones.
        Both the module and this file are scanned, because a vector's provenance
        is cited where the vector lives."""
        prose = pathlib.Path(auth_module.__file__).read_text(encoding="utf-8")
        prose += pathlib.Path(__file__).read_text(encoding="utf-8")
        cited = set(re.findall(r"astral-go/(astral/[\w/]+\.go:\d+)", prose))
        self.assertEqual(cited, set(self.CITATIONS))
