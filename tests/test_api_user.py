"""The `user` module client: fifteen ops, eleven types, one non-`eos` stream.

Three tiers in one file, because the same claim is made at each and the three
must agree:

- **Tier A** pins the wire on bytes `furry-bolt` sent this session, captured
  through `Client.call_raw`, which hands back the response body unframed and so
  records exactly what the node wrote. Four captures: a `mod.user.info` carrying
  a fully signed four-permit contract, a `mod.users.swarm_member` followed by an
  `eos`, `user.assets`'s bare `eos`, and `user.sync_assets`'s single `uint64`
  frame with **no** `eos` after it. The last is the whole reason design section
  3.10 names a third streaming shape.
- **Tier B** pins the fifteen ops against `MockApphost`: the query string each
  one builds, the answer each one accepts, the two body-input ops' frame order
  and their absent terminator, and the guards that keep an empty target from
  reaching a node that would read it as `anyone`.
- **Tier C** runs the read-only ops against a real node. Nothing here mutates:
  `adopt`, `expel`, `add_asset`, `remove_asset`, `sync_with`,
  `request_membership`, `accept_contract` and `accept_membership` are exercised
  against the mock alone.

`furry-bolt` is **claimed** -- it holds an active contract issued by
`03a40290…941d` -- so `user.info` and `user.swarm_status` answer here rather than
rejecting with code 2. Both states are legal and neither is this SDK's to
choose, so every live assertion accepts the rejection as well and asserts on the
decoded object only when one arrives.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import astral
from astral.api.auth import Contract, Permit, SignedContract
from astral.api.user import (
    AdoptAction,
    AssetSync,
    CreatedUserInfo,
    DEFAULT_CONTRACT_VALIDITY,
    EVENT_ASSETS,
    ExpelAction,
    Expulsion,
    Info,
    InfoAction,
    MINIMAL_CONTRACT_LENGTH,
    Notification,
    OP_ACCEPT_CONTRACT,
    OP_ACCEPT_MEMBERSHIP,
    OP_ADD_ASSET,
    OP_ADOPT,
    OP_ASSETS,
    OP_EXPEL,
    OP_INFO,
    OP_LIST_EXPELLED,
    OP_LIST_SIBLINGS,
    OP_NEW_NODE_CONTRACT,
    OP_REMOVE_ASSET,
    OP_REQUEST_MEMBERSHIP,
    OP_SWARM_STATUS,
    OP_SYNC_ASSETS,
    OP_SYNC_WITH,
    OpUpdate,
    SignedExpulsion,
    SwarmMember,
    SwarmMembershipAction,
    USER_TYPES,
    User,
    is_node_contract,
    new_node_contract_local,
)
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import (
    BadArgument,
    BadArgumentType,
    ParseError,
    ProtocolError,
    QueryRejected,
    QueryTimeout,
    RemoteError,
)
from astral.object import Bundle
from astral.objectid import object_id
from astral.primitives import Uint64
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.types import Duration, Identity, Nonce, ObjectID, Time, Zone
from astral.wire import Reader

import live_support
import reference
from astral.api import user as user_module
from mock_apphost import (
    ACK,
    Accept,
    EOS,
    ERROR_MSG,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    MockApphost,
    MockConn,
    QUERY_ACCEPTED,
    Reject,
    RouteQuery,
    bounded,
    error_msg_payload,
    frame,
    socket_fds,
)

# --- what the node sent, captured this session ---------------------------
#
# `Client.call_raw` declares RAW mode client-side and changes no byte of the
# query, so the body it returns is the frame stream exactly as `furry-bolt`
# wrote it: `string8(type) ++ bytes32(payload)` per frame.

LIVE_INFO_BODY = bytes.fromhex(
    "0d6d6f642e757365722e696e666f000001a5"          # frame: mod.user.info, 421 B
    "0a66757272792d626f6c74"                        # NodeAlias string8
    "1130336134303239303a383339663934316401"        # UserAlias, ContractID flag
    "000000000000017b"                              # ContractID size = 379
    "35f07d56df0b9da0dab570df28a74d453f3f360"       # ContractID hash
    "57072dba619797479f63dd0f7"
    "01"                                            # Contract present
    "01"                                            # SignedContract.Contract present
    "0103a40290fa01b9127b06f3dd990219939274e2e61afab7445f608ad652839f941d"
    "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
    "00000004"                                      # four permits
    "01206d6f642e757365722e737761726d5f6d656d626572736869705f616374696f6e0000"
    "01156d6f642e757365722e657870656c5f616374696f6e0001"
    "01156d6f642e757365722e61646f70745f616374696f6e0001"
    "01146d6f642e757365722e696e666f5f616374696f6e0001"
    "1935f826fb049d74"                              # ExpiresAt
    "010461736e31004830460221008ff2ac7dab887549f53049289582dbc9eeb0f35030"
    "bf3696e400588fc456e76d022100cacc8bfa2e5be25063543a69aebb12ad2e6b58eb"
    "f5f6e2121b0c7d437df28c00"                      # IssuerSig, asn1, 72 B
    "010461736e31004730450220057543b8ad4c959f8df427b4023ee63c207830c9de78"
    "665ffb56d2db76cf0a240221008f061c31de5c022eac244054b76ccfbebf70ccc6eb"
    "f28cb9fd940e622f7893a9"                        # SubjectSig, asn1, 71 B
)

LIVE_SWARM_STATUS_BODY = bytes.fromhex(
    "166d6f642e75736572732e737761726d5f6d656d6265720000002e"   # frame, 46 B
    "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
    "0a66757272792d626f6c74"                                    # Alias
    "00"                                                        # Linked = false
    "03656f7300000000"                                          # eos
)

LIVE_ASSETS_BODY = bytes.fromhex("03656f7300000000")
"""`user.assets` on a node with no assets: one `eos` frame and nothing else."""

LIVE_SYNC_ASSETS_BODY = bytes.fromhex("0675696e743634000000080000000000000000")
"""`user.sync_assets` with no rows: one `uint64` frame, **and no `eos`**."""

LIVE_SYNC_ASSETS_FROM_7 = bytes.fromhex("0675696e743634000000080000000000000007")
"""`user.sync_assets?start=7`: the height echoed back, so re-polling is safe."""

USER_ID = Identity.parse(
    "03a40290fa01b9127b06f3dd990219939274e2e61afab7445f608ad652839f941d"
)
"""The user `furry-bolt` belongs to, read out of the captured contract."""

OTHER = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

OID = ObjectID.parse(
    "data19kygic9q9ibq4ibaikrw9ci76kj6fs1jitxk6wjbwnkrezt8q5jk"
)
"""The reference ObjectID of `uint32(42)` (design section 2.7)."""

ACK_FRAME = (ACK, b"")
EOS_FRAME = (EOS, b"")


def frames_of(body: bytes) -> list[tuple[str, bytes]]:
    """Split a captured response body into its `(type, payload)` frames."""
    reader = Reader(body)
    out: list[tuple[str, bytes]] = []
    while reader.remaining:
        type_name = reader.string8()
        out.append((type_name, reader.raw(reader.uint32())))
    return out


def frame_error(message: str) -> tuple[str, bytes]:
    """An in-stream `error_message`, which is a different channel from
    `mod.apphost.error_msg` and never merged with it."""
    return ("error_message", len(message).to_bytes(2, "big") + message.encode())


def an_expulsion() -> Expulsion:
    return Expulsion(
        issuer=USER_ID, subject=OTHER, expelled_at=Time.parse("2026-01-01T00:00:00Z")
    )


def a_signature(scheme: str = "asn1", data: bytes = b"\x30\x06") -> object:
    """One `mod.crypto.signature`, built through the registry by wire name.

    `astral.api.user` reaches the class by import, this file by name: the
    declaration's coupling is `Ptr("mod.crypto.signature")` through the
    registry, and addressing the fields by their wire names is what the codec
    does.
    """
    value = default_blueprints().new("mod.crypto.signature")
    attrs = {f.wire_name: f.attr for f in type(value).FIELDS}
    setattr(value, attrs["Scheme"], scheme)
    setattr(value, attrs["Data"], data)
    return value


def a_contract() -> Contract:
    return Contract(
        issuer=USER_ID,
        subject=FURRY_BOLT,
        permits=[Permit(action=SwarmMembershipAction.ASTRAL_TYPE, delegation=0)],
        expires_at=Time.parse("2030-01-01T00:00:00Z"),
    )


def a_signed_contract() -> SignedContract:
    return SignedContract(
        contract=a_contract(), issuer_sig=a_signature(), subject_sig=a_signature()
    )


# --- Tier A: the wire, on the bytes the node sent ------------------------


class LiveCaptureTest(unittest.TestCase):
    """The four captures, decoded and re-encoded."""

    def test_the_info_frame_decodes_to_a_typed_info(self):
        (type_name, payload), = frames_of(LIVE_INFO_BODY)
        self.assertEqual(type_name, Info.ASTRAL_TYPE)
        info = Info.read_payload(object_reader(payload))
        self.assertEqual(info.node_alias, FURRY_BOLT_ALIAS)
        # astrald's DisplayName falls back to a short form for an identity the
        # directory has no alias for, so the user's "alias" is not a name.
        self.assertEqual(info.user_alias, "03a40290:839f941d")
        self.assertEqual(info.user_id, USER_ID)
        self.assertEqual(info.node_id, FURRY_BOLT)

    def test_the_info_payload_re_encodes_to_the_bytes_it_arrived_as(self):
        """Decode then encode is the identity over the whole nested graph: an
        `Info`, a `SignedContract`, a `Contract`, four `Permit` elements each
        with its own presence byte, and two `Signature` pointers."""
        (_, payload), = frames_of(LIVE_INFO_BODY)
        info = Info.read_payload(object_reader(payload))
        self.assertEqual(payload_bytes(info), payload)

    def test_the_node_s_contract_id_is_the_id_this_sdk_computes(self):
        """`ContractID` is `astral.ResolveObjectID(contract)` on the node. The
        SDK recomputing the same 40 bytes from the decoded object proves the
        re-encoding is byte-exact, because a content hash has no slack."""
        (_, payload), = frames_of(LIVE_INFO_BODY)
        info = Info.read_payload(object_reader(payload))
        self.assertEqual(object_id(info.contract), info.contract_id)

    def test_the_captured_contract_is_a_fully_signed_node_contract(self):
        (_, payload), = frames_of(LIVE_INFO_BODY)
        info = Info.read_payload(object_reader(payload))
        self.assertTrue(info.contract.fully_signed)
        self.assertTrue(is_node_contract(info.contract.contract))
        self.assertEqual(
            [p.action for p in info.contract.contract.permits],
            [
                SwarmMembershipAction.ASTRAL_TYPE,
                ExpelAction.ASTRAL_TYPE,
                AdoptAction.ASTRAL_TYPE,
                InfoAction.ASTRAL_TYPE,
            ],
        )
        self.assertEqual(
            [p.delegation for p in info.contract.contract.permits], [0, 1, 1, 1]
        )

    def test_the_swarm_status_capture_is_one_member_then_an_eos(self):
        got = frames_of(LIVE_SWARM_STATUS_BODY)
        self.assertEqual([name for name, _ in got], [SwarmMember.ASTRAL_TYPE, EOS])
        member = SwarmMember.read_payload(object_reader(got[0][1]))
        self.assertEqual(member.identity, FURRY_BOLT)
        self.assertEqual(member.alias, FURRY_BOLT_ALIAS)
        # A node is not linked to itself: `Nodes.IsLinked` is liveness of a
        # link, and there is no link to the local node.
        self.assertIs(member.linked, False)
        self.assertEqual(payload_bytes(member), got[0][1])

    def test_assets_ends_at_an_eos_with_no_object_before_it(self):
        self.assertEqual(frames_of(LIVE_ASSETS_BODY), [EOS_FRAME])

    def test_sync_assets_answers_a_bare_uint64_and_never_an_eos(self):
        """The pin of design section 3.10's third shape. Every generic reader
        in this SDK stops at `eos` or EOF; this op sends neither until the
        responder closes, so a reader that waits for one waits for the close it
        is itself supposed to perform."""
        for body, expected in (
            (LIVE_SYNC_ASSETS_BODY, 0),
            (LIVE_SYNC_ASSETS_FROM_7, 7),
        ):
            with self.subTest(height=expected):
                got = frames_of(body)
                self.assertEqual([name for name, _ in got], ["uint64"])
                self.assertEqual(
                    int.from_bytes(got[0][1], "big"),
                    expected,
                    "the height is the next cursor; an empty answer echoes start",
                )
                self.assertNotIn(EOS, [name for name, _ in got])


class RoundTripTest(unittest.TestCase):
    """The types no live op on this node populates, round-tripped synthetically.

    `furry-bolt` holds no assets and has expelled nobody, so `op_update` and
    `signed_expulsion` have no capture. Their field order is the node's own,
    read from `objects.get_blueprint` this session, and is asserted against the
    declaration in `BlueprintParityTest`.
    """

    def assert_round_trips(self, value: object) -> None:
        payload = payload_bytes(value)
        again = type(value).read_payload(object_reader(payload))
        self.assertEqual(again, value)
        self.assertEqual(payload_bytes(again), payload)

    def test_an_op_update_round_trips(self):
        self.assert_round_trips(
            OpUpdate(nonce=Nonce(0x1122334455667788), object_id=OID, removed=True)
        )

    def test_an_op_update_carries_its_nonce_and_removal_flag_in_order(self):
        update = OpUpdate(nonce=Nonce(1), object_id=OID, removed=False)
        payload = payload_bytes(update)
        self.assertEqual(payload[:8], (1).to_bytes(8, "big"))
        self.assertEqual(payload[8], 1, "the ObjectID pointer's presence byte")
        self.assertEqual(payload[-1], 0, "Removed is the last byte")

    def test_a_removed_update_differs_from_an_added_one_in_one_byte(self):
        added = payload_bytes(OpUpdate(nonce=Nonce(1), object_id=OID, removed=False))
        removed = payload_bytes(OpUpdate(nonce=Nonce(1), object_id=OID, removed=True))
        self.assertEqual(len(added), len(removed))
        self.assertEqual(added[:-1], removed[:-1])

    def test_an_expulsion_round_trips(self):
        self.assert_round_trips(an_expulsion())

    def test_a_signed_expulsion_round_trips(self):
        self.assert_round_trips(
            SignedExpulsion(expulsion=an_expulsion(), issuer_sig=a_signature())
        )

    def test_an_absent_expulsion_body_is_one_nil_byte(self):
        self.assertEqual(
            payload_bytes(SignedExpulsion(expulsion=None, issuer_sig=None)), b"\x00\x00"
        )

    def test_a_notification_round_trips(self):
        self.assert_round_trips(Notification(event=EVENT_ASSETS))

    def test_a_created_user_info_round_trips(self):
        self.assert_round_trips(
            CreatedUserInfo(
                id=USER_ID,
                alias="somebody",
                key_id=OID,
                contract_id=OID,
                contract=a_signed_contract(),
                access_token="t0ken",
            )
        )

    def test_every_zero_value_round_trips(self):
        for kind in USER_TYPES:
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assert_round_trips(kind())


class BlueprintParityTest(unittest.TestCase):
    """Every declaration equals the node's own blueprint for that type.

    The field orders below were read from `objects.get_blueprint?type=…` on
    `furry-bolt` this session, one query per type. The four action types are
    absent: that op refuses them -- `BlueprintFromType …Action: type auth.Action
    does not implement Object and is not a supported container` -- which is the
    same refusal `mod.objects.*_action` gets and says nothing about their wire
    form.
    """

    NODE = {
        "mod.user.info": [
            ("NodeAlias", "primitive:string8"),
            ("UserAlias", "primitive:string8"),
            ("ContractID", "ptr:object_id.sha256"),
            ("Contract", "ptr:mod.auth.signed_contract"),
        ],
        "mod.user.op_update": [
            ("Nonce", "primitive:nonce64"),
            ("ObjectID", "ptr:object_id.sha256"),
            ("Removed", "primitive:bool"),
        ],
        "mod.user.expulsion": [
            ("Issuer", "ptr:identity"),
            ("Subject", "ptr:identity"),
            ("ExpelledAt", "primitive:time"),
        ],
        "mod.user.signed_expulsion": [
            ("Expulsion", "ptr:mod.user.expulsion"),
            ("IssuerSig", "ptr:mod.crypto.signature"),
        ],
        "mod.user.notification": [("Event", "primitive:string8")],
        "mod.users.swarm_member": [
            ("Identity", "ptr:identity"),
            ("Alias", "primitive:string8"),
            ("Linked", "primitive:bool"),
        ],
        "mod.users.created_user_info": [
            ("ID", "ptr:identity"),
            ("Alias", "primitive:string8"),
            ("KeyID", "ptr:object_id.sha256"),
            ("ContractID", "ptr:object_id.sha256"),
            ("Contract", "ptr:mod.auth.signed_contract"),
            ("AccessToken", "primitive:string8"),
        ],
    }

    @staticmethod
    def rendered(spec: object) -> str:
        name = type(spec).__name__.replace("Spec", "").lower()
        return f"{name}:{getattr(spec, 'name', None) or getattr(spec, 'type', '')}"

    def test_every_declaration_equals_the_node_s_blueprint(self):
        by_name = {kind.ASTRAL_TYPE: kind for kind in USER_TYPES}
        for type_name, expected in self.NODE.items():
            with self.subTest(type=type_name):
                kind = by_name[type_name]
                self.assertEqual(
                    [(f.wire_name, self.rendered(f.spec)) for f in kind.FIELDS],
                    expected,
                )

    def test_the_action_types_carry_the_embedded_fields_first(self):
        """Go promotes an embedded struct's fields, so `auth.Action`'s two come
        before the concrete type's own and the payload flattens."""
        for kind in (AdoptAction, ExpelAction, InfoAction, SwarmMembershipAction):
            with self.subTest(type=kind.ASTRAL_TYPE):
                names = [f.wire_name for f in kind.FIELDS]
                self.assertEqual(names[:2], ["Nonce", "ActorID"])
        self.assertEqual([f.wire_name for f in AdoptAction.FIELDS][2:], ["Subject"])
        self.assertEqual([f.wire_name for f in InfoAction.FIELDS][2:], [])


class TypeRegistrationTest(unittest.TestCase):
    """Every type this module declares is registered under its wire name."""

    def test_every_declared_type_is_in_the_default_registry(self):
        registry = default_blueprints()
        for kind in USER_TYPES:
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertTrue(registry.has(kind.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(kind.ASTRAL_TYPE), kind)

    def test_user_types_names_every_record_the_module_declares(self):
        """The sweep list is walked from the module rather than trusted, because
        a type left out of it is a type a private registry cannot decode while
        the default one can -- a difference that only shows up in someone
        else's process."""
        declared = {
            value
            for value in vars(user_module).values()
            if isinstance(value, type)
            and getattr(value, "__module__", "") == user_module.__name__
            and getattr(value, "ASTRAL_TYPE", None)
        }
        self.assertEqual(declared, set(USER_TYPES))

    def test_the_plural_type_names_are_spelled_literally(self):
        """Two types carry `mod.users` and every other carries `mod.user`.
        Design section 5.1 rule 6: the name is the node's, not a pattern."""
        self.assertEqual(SwarmMember.ASTRAL_TYPE, "mod.users.swarm_member")
        self.assertEqual(CreatedUserInfo.ASTRAL_TYPE, "mod.users.created_user_info")
        self.assertEqual(Info.ASTRAL_TYPE, "mod.user.info")
        for kind in USER_TYPES:
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertTrue(kind.ASTRAL_TYPE.startswith(("mod.user.", "mod.users.")))

    def test_the_op_names_are_the_fifteen_the_registry_reports(self):
        """The live `shell.spec` registry answered exactly these fifteen
        `user.*` names this session; astral-go's `api/user/module.go` declares
        the same fifteen constants."""
        names = sorted(
            value
            for name, value in vars(user_module).items()
            if name.startswith("OP_") and isinstance(value, str)
        )
        self.assertEqual(len(names), 15)
        self.assertEqual(
            names,
            [
                "user.accept_contract",
                "user.accept_membership",
                "user.add_asset",
                "user.adopt",
                "user.assets",
                "user.expel",
                "user.info",
                "user.list_expelled",
                "user.list_siblings",
                "user.new_node_contract",
                "user.remove_asset",
                "user.request_membership",
                "user.swarm_status",
                "user.sync_assets",
                "user.sync_with",
            ],
        )

    def test_every_op_has_a_method_of_the_same_name(self):
        for name, value in sorted(vars(user_module).items()):
            if not name.startswith("OP_") or not isinstance(value, str):
                continue
            with self.subTest(op=value):
                method = value.split(".", 1)[1]
                self.assertTrue(
                    callable(getattr(User, method, None)),
                    f"{value} has no User.{method}",
                )


class ExpulsionSignableTest(unittest.TestCase):
    """The preimages a signature covers, reproduced from astral-go verbatim."""

    def test_signable_text_reproduces_the_go_format(self):
        self.assertEqual(
            an_expulsion().signable_text(),
            f"{USER_ID.text()} expels {OTHER.text()} from the swarm",
        )

    def test_signable_text_renders_an_absent_identity_as_sixty_six_zeros(self):
        text = Expulsion(issuer=None, subject=None).signable_text()
        self.assertEqual(text, f"{'0' * 66} expels {'0' * 66} from the swarm")

    def test_signable_hash_is_the_object_id_hash_of_the_body(self):
        expulsion = an_expulsion()
        self.assertEqual(expulsion.signable_hash(), object_id(expulsion).hash)

    def test_the_signature_covers_the_body_and_not_the_signed_wrapper(self):
        """`SignedExpulsion` has no signable form: a signature over an object
        that contains it cannot exist."""
        self.assertFalse(hasattr(SignedExpulsion, "signable_hash"))
        self.assertFalse(hasattr(SignedExpulsion, "signable_text"))

    def test_the_body_is_reached_through_the_field_and_not_forwarded(self):
        signed = SignedExpulsion(expulsion=an_expulsion(), issuer_sig=None)
        self.assertEqual(signed.expulsion.issuer, USER_ID)
        with self.assertRaises(AttributeError):
            signed.issuer  # noqa: B018 -- the assertion is that it raises


class NodeContractHelperTest(unittest.TestCase):
    """`new_node_contract_local` and `is_node_contract`, astral-go's two."""

    def test_an_ordinary_member_gets_one_permit(self):
        contract = new_node_contract_local(USER_ID, FURRY_BOLT)
        self.assertEqual(
            [p.action for p in contract.permits], [SwarmMembershipAction.ASTRAL_TYPE]
        )
        self.assertEqual(contract.permits[0].delegation, 0)

    def test_a_management_node_gets_four_permits_three_of_them_delegable(self):
        contract = new_node_contract_local(USER_ID, FURRY_BOLT, management_node=True)
        self.assertEqual(
            [(p.action, p.delegation) for p in contract.permits],
            [
                (SwarmMembershipAction.ASTRAL_TYPE, 0),
                (ExpelAction.ASTRAL_TYPE, 1),
                (AdoptAction.ASTRAL_TYPE, 1),
                (InfoAction.ASTRAL_TYPE, 1),
            ],
        )

    def test_the_management_shape_is_the_one_the_node_answered_with(self):
        """The op passes `managementNode=true` unconditionally, so its answer
        and this helper's four-permit form must be the same object but for the
        parties and the expiry. Compared against the captured contract."""
        (_, payload), = frames_of(LIVE_INFO_BODY)
        live = Info.read_payload(object_reader(payload)).contract.contract
        local = new_node_contract_local(
            live.issuer, live.subject, management_node=True
        )
        self.assertEqual(
            [(p.action, p.delegation, p.constraints) for p in local.permits],
            [(p.action, p.delegation, p.constraints) for p in live.permits],
        )

    def test_the_default_validity_is_the_node_s_year(self):
        before = Time.now()
        contract = new_node_contract_local(USER_ID, FURRY_BOLT)
        self.assertGreaterEqual(
            int(contract.expires_at), int(before) + int(DEFAULT_CONTRACT_VALIDITY)
        )
        self.assertEqual(DEFAULT_CONTRACT_VALIDITY.text(), "8760h0m0s")
        self.assertEqual(MINIMAL_CONTRACT_LENGTH.text(), "1h0m0s")

    def test_a_duration_is_taken_as_nanoseconds_from_now(self):
        contract = new_node_contract_local(
            USER_ID, FURRY_BOLT, duration=Duration.parse("48h")
        )
        self.assertLess(
            abs(int(contract.expires_at) - int(Time.now()) - 48 * 3600 * 10**9),
            10**9,
        )

    def test_is_node_contract_names_the_membership_permit_and_nothing_else(self):
        self.assertTrue(is_node_contract(new_node_contract_local(USER_ID, FURRY_BOLT)))
        self.assertFalse(
            is_node_contract(
                Contract(
                    issuer=USER_ID,
                    subject=FURRY_BOLT,
                    permits=[Permit(action=InfoAction.ASTRAL_TYPE)],
                )
            )
        )
        self.assertFalse(is_node_contract(Contract()))

    def test_an_expired_node_contract_is_still_a_node_contract(self):
        """Membership and validity are two questions; `Contract.expired` is the
        other one."""
        contract = new_node_contract_local(
            USER_ID, FURRY_BOLT, duration=Duration(-1)
        )
        self.assertTrue(contract.expired)
        self.assertTrue(is_node_contract(contract))


class ErrorTextTest(unittest.TestCase):
    """The four error texts, read back out of astral-go at the pin.

    They arrive as `error_message` objects, so `RemoteError.message` is the
    responder's text verbatim and matching on it is the only way to tell one
    refusal from another: the wire carries a string and no code.
    """

    def test_every_declared_text_is_one_astral_go_declares(self):
        try:
            source = reference.read(reference.ASTRAL_GO, "api/user/errors.go")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        for text in (
            user_module.ERR_INVITATION_DECLINED,
            user_module.ERR_REQUEST_DECLINED,
            user_module.ERR_NO_ACTIVE_CONTRACT,
            user_module.ERR_EXPELLED,
        ):
            with self.subTest(text=text):
                self.assertIn(f'astral.NewError("{text}")', source)

    def test_the_declared_set_is_the_whole_of_astral_go_s(self):
        try:
            source = reference.read(reference.ASTRAL_GO, "api/user/errors.go")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        upstream = set(re.findall(r'astral\.NewError\("([^"]+)"\)', source))
        declared = {
            value
            for name, value in vars(user_module).items()
            if name.startswith("ERR_") and isinstance(value, str)
        }
        self.assertEqual(upstream, declared)


class ActionConstraintTest(unittest.TestCase):
    """`ApplyConstraints`, ported: any constraint at all refuses."""

    def test_an_absent_or_empty_bundle_permits(self):
        for kind in (AdoptAction, ExpelAction, InfoAction):
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertTrue(kind().apply_constraints(None))
                self.assertTrue(kind().apply_constraints(Bundle()))

    def test_any_constraint_denies(self):
        bundle = Bundle([Uint64(1)])
        for kind in (AdoptAction, ExpelAction, InfoAction):
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertFalse(kind().apply_constraints(bundle))

    def test_a_permit_allows_only_its_own_action_type(self):
        permit = Permit(action=AdoptAction.ASTRAL_TYPE)
        self.assertTrue(permit.allows(AdoptAction()))
        self.assertFalse(permit.allows(ExpelAction()))

    def test_swarm_membership_declares_no_constraint_method_and_so_is_allowed(self):
        """astral-go declares none for this one type, and `Permit.allows`
        permits an action that declares none whatever the constraints say."""
        self.assertFalse(hasattr(SwarmMembershipAction, "apply_constraints"))
        permit = Permit(
            action=SwarmMembershipAction.ASTRAL_TYPE,
            constraints=Bundle([Uint64(1)]),
        )
        self.assertTrue(permit.allows(SwarmMembershipAction()))


# --- Tier B: the fifteen ops against the mock ----------------------------


class BodyReadingNode:
    """A mock route that reads its input **before** answering, as the op does.

    `Accept(read=True)` cannot serve a write-and-answer op: it writes the
    answer first, and a client that has its answer closes the stream, which
    discards whatever the mock had not yet read. So the frames the client sent
    would be unobservable exactly when the exchange succeeded.
    """

    def __init__(
        self, *answers: tuple[str, bytes], expect: int = 2, hold: bool = False
    ) -> None:
        self.answers = answers
        self.expect = expect
        self.hold = hold
        self.received: list[tuple[str, bytes]] = []

    async def __call__(self, conn: MockConn, query: RouteQuery) -> None:
        conn.send_frame(QUERY_ACCEPTED)
        await conn.flush()
        for _ in range(self.expect):
            got = await conn.recv_frame_or_none()
            if got is None:
                break
            self.received.append(got)
        for answer in self.answers:
            conn.send_frame(*answer)
        await conn.flush()

    @property
    def types(self) -> list[str]:
        return [name for name, _ in self.received]


class UserCase(unittest.IsolatedAsyncioTestCase):
    """A `User` over a mock apphost, closed by the teardown whatever a test does."""

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

    async def user(self, mock: MockApphost, **kw: object) -> User:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return User(client)

    async def serving(self, routes: dict[str, object], **kw: object) -> User:
        mock = MockApphost(routes=routes)  # type: ignore[arg-type]
        await self.enterAsyncContext(mock)
        self.mock = mock
        return await self.user(mock, **kw)

    def sent(self) -> str:
        self.assertEqual(len(self.mock.queries), 1, f"queries: {self.mock.queries}")
        return self.mock.queries[0].query

    def params(self) -> tuple[str, dict[str, str]]:
        return parse(self.sent())

    def assert_no_faults(self) -> None:
        self.assertEqual(self.mock.errors, [])


class InfoOpTest(UserCase):
    """`user.info`: RR, one object, no `eos`."""

    def info_frame(self) -> tuple[str, bytes]:
        return frames_of(LIVE_INFO_BODY)[0]

    @bounded()
    async def test_it_sends_no_parameters_and_returns_a_typed_info(self):
        api = await self.serving({OP_INFO: Accept(objects=[self.info_frame()])})
        info = await api.info()
        self.assertIsInstance(info, Info)
        self.assertEqual(info.node_alias, FURRY_BOLT_ALIAS)
        self.assertEqual(self.sent(), OP_INFO)
        self.assert_no_faults()

    @bounded()
    async def test_it_does_not_wait_for_an_eos(self):
        api = await self.serving({OP_INFO: Accept(objects=[self.info_frame()])})
        await api.info()
        self.assert_no_faults()

    @bounded()
    async def test_a_node_with_no_active_contract_rejects_with_code_two(self):
        api = await self.serving({OP_INFO: Reject(2)})
        with self.assertRaises(QueryRejected) as caught:
            await api.info()
        self.assertEqual(caught.exception.code, 2)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        api = await self.serving({OP_INFO: Accept(objects=[ACK_FRAME])})
        with self.assertRaises(ProtocolError) as caught:
            await api.info()
        self.assertIn(Info.ASTRAL_TYPE, str(caught.exception))


class AssetsOpTest(UserCase):
    """`user.assets`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_the_object_ids(self):
        api = await self.serving(
            {
                OP_ASSETS: Accept(
                    objects=[("object_id.sha256", payload_bytes(OID))], eos=True
                )
            }
        )
        self.assertEqual(await api.assets(), [OID])
        self.assertEqual(self.sent(), OP_ASSETS)

    @bounded()
    async def test_an_empty_asset_set_is_a_bare_eos(self):
        api = await self.serving({OP_ASSETS: Accept(eos=True)})
        self.assertEqual(await api.assets(), [])

    @bounded()
    async def test_a_wrong_element_type_is_a_protocol_error(self):
        api = await self.serving({OP_ASSETS: Accept(objects=[ACK_FRAME], eos=True)})
        with self.assertRaises(ProtocolError):
            await api.assets()


class SyncAssetsOpTest(UserCase):
    """`user.sync_assets`: updates, then a bare `uint64`, and no `eos`."""

    @staticmethod
    def height(value: int) -> tuple[str, bytes]:
        return ("uint64", value.to_bytes(8, "big"))

    @staticmethod
    def update(nonce: int, removed: bool = False) -> tuple[str, bytes]:
        return (
            OpUpdate.ASTRAL_TYPE,
            payload_bytes(
                OpUpdate(nonce=Nonce(nonce), object_id=OID, removed=removed)
            ),
        )

    @bounded()
    async def test_it_reads_to_the_height_and_stops_without_an_eos(self):
        api = await self.serving(
            {
                f"{OP_SYNC_ASSETS}?start=0": Accept(
                    objects=[self.update(1), self.update(2, removed=True)]
                    + [self.height(3)],
                    hold=True,
                )
            }
        )
        answer = await api.sync_assets()
        self.assertIsInstance(answer, AssetSync)
        self.assertEqual(answer.next_height, 3)
        self.assertEqual([u.nonce for u in answer.updates], [Nonce(1), Nonce(2)])
        self.assertEqual([u.removed for u in answer.updates], [False, True])
        self.assert_no_faults()

    @bounded()
    async def test_the_answer_unpacks_as_the_pair_the_design_names(self):
        api = await self.serving(
            {f"{OP_SYNC_ASSETS}?start=0": Accept(objects=[self.height(0)], hold=True)}
        )
        updates, next_height = await api.sync_assets()
        self.assertEqual(updates, [])
        self.assertEqual(next_height, 0)

    @bounded()
    async def test_a_held_open_stream_still_returns_because_nothing_waits_for_eos(self):
        """`hold=True` keeps the mock's connection open after the height, which
        is what the node does until the op returns. A reader that waited for a
        terminator would block here until the deadline."""
        api = await self.serving(
            {f"{OP_SYNC_ASSETS}?start=0": Accept(objects=[self.height(9)], hold=True)}
        )
        self.assertEqual((await api.sync_assets()).next_height, 9)

    @bounded()
    async def test_the_start_height_travels(self):
        api = await self.serving(
            {f"{OP_SYNC_ASSETS}?start=7": Accept(objects=[self.height(7)], hold=True)}
        )
        self.assertEqual((await api.sync_assets(start=7)).next_height, 7)
        self.assertEqual(self.sent(), f"{OP_SYNC_ASSETS}?start=7")

    @bounded()
    async def test_a_stream_that_ends_with_no_height_is_a_protocol_error(self):
        api = await self.serving({f"{OP_SYNC_ASSETS}?start=0": Accept()})
        with self.assertRaises(ProtocolError) as caught:
            await api.sync_assets()
        self.assertIn("no height", str(caught.exception))

    @bounded()
    async def test_an_eos_before_the_height_is_reported_and_not_awaited(self):
        """astrald sends no `eos` here. One arriving means the op changed shape,
        which is a report and not a hang."""
        api = await self.serving({f"{OP_SYNC_ASSETS}?start=0": Accept(eos=True)})
        with self.assertRaises(ProtocolError):
            await api.sync_assets()

    @bounded()
    async def test_an_object_that_is_neither_an_update_nor_a_height_is_reported(self):
        api = await self.serving(
            {f"{OP_SYNC_ASSETS}?start=0": Accept(objects=[ACK_FRAME], hold=True)}
        )
        with self.assertRaises(ProtocolError) as caught:
            await api.sync_assets()
        self.assertIn(OpUpdate.ASTRAL_TYPE, str(caught.exception))

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        api = await self.serving(
            {f"{OP_SYNC_ASSETS}?start=0": Accept(objects=[frame_error("db error")])}
        )
        with self.assertRaises(RemoteError):
            await api.sync_assets()

    @bounded()
    async def test_a_negative_height_never_reaches_the_node(self):
        api = await self.serving({OP_SYNC_ASSETS: Accept()})
        with self.assertRaises(BadArgument):
            await api.sync_assets(start=-1)
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_a_height_that_is_not_an_int_never_reaches_the_node(self):
        api = await self.serving({OP_SYNC_ASSETS: Accept()})
        with self.assertRaises(BadArgumentType):
            await api.sync_assets(start="7")  # type: ignore[arg-type]
        self.assertEqual(self.mock.queries, [])


class ListSiblingsOpTest(UserCase):
    """`user.list_siblings`: ST, `eos`, and the one zone argument."""

    @bounded()
    async def test_it_returns_the_identities(self):
        api = await self.serving(
            {
                OP_LIST_SIBLINGS: Accept(
                    objects=[("identity", FURRY_BOLT.key)], eos=True
                )
            }
        )
        self.assertEqual(await api.list_siblings(), [FURRY_BOLT])
        self.assertEqual(self.sent(), OP_LIST_SIBLINGS)

    @bounded()
    async def test_no_zone_argument_is_sent_when_none_is_asked_for(self):
        api = await self.serving({OP_LIST_SIBLINGS: Accept(eos=True)})
        await api.list_siblings()
        self.assertEqual(self.sent(), OP_LIST_SIBLINGS)

    @bounded()
    async def test_a_zone_goes_to_the_op_argument_and_to_the_routing_zone(self):
        """One scope, two levers, as `Objects` does it. The op's own argument is
        inert on astrald 074a852b -- the context it builds is never used -- and
        the routing zone is not, so sending only one of them is wrong whichever
        one it is."""
        api = await self.serving(
            {f"{OP_LIST_SIBLINGS}?zone=dv": Accept(eos=True)}
        )
        await api.list_siblings(zone=Zone.DEVICE | Zone.VIRTUAL)
        self.assertEqual(self.params()[1], {"zone": "dv"})
        self.assertEqual(self.mock.queries[0].zone, int(Zone.DEVICE | Zone.VIRTUAL))

    @bounded()
    async def test_a_zone_is_accepted_as_letters_or_as_bits(self):
        for value in ("dv", int(Zone.DEVICE | Zone.VIRTUAL)):
            with self.subTest(zone=value):
                api = await self.serving(
                    {f"{OP_LIST_SIBLINGS}?zone=dv": Accept(eos=True)}
                )
                await api.list_siblings(zone=value)
                self.assertEqual(self.params()[1], {"zone": "dv"})


class SwarmStatusOpTest(UserCase):
    """`user.swarm_status`: ST, `eos`, membership with liveness."""

    @bounded()
    async def test_it_returns_typed_members(self):
        member, _ = frames_of(LIVE_SWARM_STATUS_BODY)
        api = await self.serving({OP_SWARM_STATUS: Accept(objects=[member], eos=True)})
        members = await api.swarm_status()
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0].identity, FURRY_BOLT)
        self.assertIs(members[0].linked, False)
        self.assertEqual(self.sent(), OP_SWARM_STATUS)

    @bounded()
    async def test_no_active_contract_rejects_with_code_two(self):
        api = await self.serving({OP_SWARM_STATUS: Reject(2)})
        with self.assertRaises(QueryRejected) as caught:
            await api.swarm_status()
        self.assertEqual(caught.exception.code, 2)


class ListExpelledOpTest(UserCase):
    """`user.list_expelled`: ST, `eos`, the swarm's ban list."""

    @bounded()
    async def test_it_returns_typed_expulsions(self):
        signed = SignedExpulsion(expulsion=an_expulsion(), issuer_sig=a_signature())
        api = await self.serving(
            {
                OP_LIST_EXPELLED: Accept(
                    objects=[(SignedExpulsion.ASTRAL_TYPE, payload_bytes(signed))],
                    eos=True,
                )
            }
        )
        got = await api.list_expelled()
        self.assertEqual(got, [signed])
        self.assertEqual(got[0].expulsion.subject, OTHER)

    @bounded()
    async def test_an_empty_ban_list_is_a_bare_eos(self):
        api = await self.serving({OP_LIST_EXPELLED: Accept(eos=True)})
        self.assertEqual(await api.list_expelled(), [])


class NewNodeContractOpTest(UserCase):
    """`user.new_node_contract`: RR, pure construction, three arguments."""

    def contract_frame(self) -> tuple[str, bytes]:
        return (Contract.ASTRAL_TYPE, payload_bytes(a_contract()))

    @bounded()
    async def test_no_argument_sends_a_bare_op(self):
        api = await self.serving(
            {OP_NEW_NODE_CONTRACT: Accept(objects=[self.contract_frame()])}
        )
        contract = await api.new_node_contract()
        self.assertEqual(contract, a_contract())
        self.assertEqual(self.sent(), OP_NEW_NODE_CONTRACT)

    @bounded()
    async def test_the_three_arguments_travel_under_their_own_names(self):
        api = await self.serving(
            {OP_NEW_NODE_CONTRACT: Accept(objects=[self.contract_frame()])}
        )
        await api.new_node_contract(
            user="somebody", node=FURRY_BOLT, duration="48h"
        )
        self.assertEqual(
            self.params()[1],
            {"user": "somebody", "node": FURRY_BOLT.text(), "duration": "48h"},
        )

    @bounded()
    async def test_a_duration_object_travels_as_go_duration_syntax(self):
        api = await self.serving(
            {OP_NEW_NODE_CONTRACT: Accept(objects=[self.contract_frame()])}
        )
        await api.new_node_contract(duration=Duration.parse("90m"))
        self.assertEqual(self.params()[1], {"duration": "1h30m0s"})

    @bounded()
    async def test_a_year_unit_never_reaches_the_node(self):
        """Go's `ParseDuration` has no year unit and answers `time: unknown
        unit "y" in duration "1y"` -- verified live. `Duration.parse` carries
        Go's unit table, so the refusal happens here."""
        api = await self.serving({OP_NEW_NODE_CONTRACT: Accept()})
        with self.assertRaises(ParseError) as caught:
            await api.new_node_contract(duration="1y")
        self.assertIn("'y'", str(caught.exception))
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_an_empty_name_never_reaches_the_node(self):
        api = await self.serving({OP_NEW_NODE_CONTRACT: Accept()})
        with self.assertRaises(BadArgument):
            await api.new_node_contract(user="")
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_an_unknown_name_surfaces_as_a_remote_error(self):
        api = await self.serving(
            {OP_NEW_NODE_CONTRACT: Accept(objects=[frame_error("unknown identity: x")])}
        )
        with self.assertRaises(RemoteError):
            await api.new_node_contract(user="x")


class AssetOpTest(UserCase):
    """`user.add_asset` and `user.remove_asset`: RR, one `ack`, one argument."""

    @bounded()
    async def test_add_sends_the_object_id_and_reads_the_ack(self):
        api = await self.serving(
            {f"{OP_ADD_ASSET}?id={OID}": Accept(objects=[ACK_FRAME])}
        )
        self.assertIsNone(await api.add_asset(OID))
        self.assertEqual(self.sent(), f"{OP_ADD_ASSET}?id={OID}")

    @bounded()
    async def test_remove_sends_the_object_id_and_reads_the_ack(self):
        api = await self.serving(
            {f"{OP_REMOVE_ASSET}?id={OID}": Accept(objects=[ACK_FRAME])}
        )
        self.assertIsNone(await api.remove_asset(str(OID)))
        self.assertEqual(self.sent(), f"{OP_REMOVE_ASSET}?id={OID}")

    @bounded()
    async def test_the_id_is_always_sent_because_an_absent_one_writes_a_null_row(self):
        """astrald does not mark `ID` required, so an omitted argument reaches
        the database as a null object ID. The argument is mandatory here."""
        api = await self.serving({OP_ADD_ASSET: Accept(objects=[ACK_FRAME])})
        with self.assertRaises(TypeError):
            await api.add_asset()  # type: ignore[call-arg]
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_a_value_that_is_not_an_object_id_never_reaches_the_node(self):
        api = await self.serving({OP_ADD_ASSET: Accept(objects=[ACK_FRAME])})
        with self.assertRaises(ParseError) as caught:
            await api.add_asset("not-an-object-id")
        self.assertIn(OP_ADD_ASSET, str(caught.exception))
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_a_database_failure_arrives_as_a_rejection(self):
        """`op_add_asset.go` rejects with `internal_error` before it accepts,
        so the failure is a `QueryRejected` and never an object."""
        api = await self.serving({f"{OP_ADD_ASSET}?id={OID}": Reject(4)})
        with self.assertRaises(QueryRejected) as caught:
            await api.add_asset(OID)
        self.assertEqual(caught.exception.code, 4)


class SyncWithOpTest(UserCase):
    """`user.sync_with`: RR, one `ack`, an identity argument and a height."""

    @bounded()
    async def test_it_sends_the_identity_and_no_height_by_default(self):
        """`start` is inert on astrald 074a852b and the node reads the height
        out of its own tree. An implicit `start=0` is identical today and would
        mean "re-read the whole log" the moment the argument is wired up, which
        is not what a caller who named no height asked for."""
        query = f"{OP_SYNC_WITH}?node={FURRY_BOLT.text()}"
        api = await self.serving({query: Accept(objects=[ACK_FRAME])})
        self.assertIsNone(await api.sync_with(FURRY_BOLT))
        self.assertEqual(self.sent(), query)
        self.assertNotIn("start", self.params()[1])

    @bounded()
    async def test_a_named_start_height_travels(self):
        query = f"{OP_SYNC_WITH}?node={FURRY_BOLT.text()}&start=12"
        api = await self.serving({query: Accept(objects=[ACK_FRAME])})
        await api.sync_with(FURRY_BOLT, start=12)
        self.assertEqual(self.params()[1]["start"], "12")

    @bounded()
    async def test_a_start_of_zero_is_sent_when_it_is_asked_for(self):
        """Naming the height is a different statement from omitting it, so an
        explicit zero travels."""
        query = f"{OP_SYNC_WITH}?node={FURRY_BOLT.text()}&start=0"
        api = await self.serving({query: Accept(objects=[ACK_FRAME])})
        await api.sync_with(FURRY_BOLT, start=0)
        self.assertEqual(self.params()[1]["start"], "0")

    @bounded()
    async def test_a_directory_name_never_reaches_the_node(self):
        """The op parses this argument as an identity, so a name arrives as a
        rejected query rather than as an error message."""
        api = await self.serving({OP_SYNC_WITH: Accept(objects=[ACK_FRAME])})
        with self.assertRaises(ParseError) as caught:
            await api.sync_with(FURRY_BOLT_ALIAS)
        self.assertIn("resolve it first", str(caught.exception))
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        """`syncAssets` returns `ErrNoActiveContract` as an object on the
        stream, not as a rejection: the op accepts before it runs."""
        query = f"{OP_SYNC_WITH}?node={FURRY_BOLT.text()}"
        api = await self.serving(
            {query: Accept(objects=[frame_error("no active contract")])}
        )
        with self.assertRaises(RemoteError) as caught:
            await api.sync_with(FURRY_BOLT)
        self.assertEqual(caught.exception.message, "no active contract")


class AdoptAndExpelOpTest(UserCase):
    """`user.adopt` and `user.expel`: RR, one `target=` argument each."""

    def signed_frame(self) -> tuple[str, bytes]:
        return (SignedContract.ASTRAL_TYPE, payload_bytes(a_signed_contract()))

    def expulsion_frame(self) -> tuple[str, bytes]:
        signed = SignedExpulsion(expulsion=an_expulsion(), issuer_sig=a_signature())
        return (SignedExpulsion.ASTRAL_TYPE, payload_bytes(signed))

    @bounded()
    async def test_adopt_sends_the_target_and_returns_the_signed_contract(self):
        api = await self.serving(
            {f"{OP_ADOPT}?target=somebody": Accept(objects=[self.signed_frame()])}
        )
        signed = await api.adopt("somebody")
        self.assertIsInstance(signed, SignedContract)
        self.assertEqual(self.sent(), f"{OP_ADOPT}?target=somebody")

    @bounded()
    async def test_expel_sends_the_target_and_returns_the_signed_expulsion(self):
        api = await self.serving(
            {f"{OP_EXPEL}?target=somebody": Accept(objects=[self.expulsion_frame()])}
        )
        signed = await api.expel("somebody")
        self.assertIsInstance(signed, SignedExpulsion)
        self.assertEqual(signed.expulsion.subject, OTHER)
        self.assertEqual(self.sent(), f"{OP_EXPEL}?target=somebody")

    @bounded()
    async def test_an_identity_travels_as_sixty_six_hex_characters(self):
        api = await self.serving(
            {
                f"{OP_ADOPT}?target={OTHER.text()}": Accept(
                    objects=[self.signed_frame()]
                )
            }
        )
        await api.adopt(OTHER)
        self.assertEqual(self.params()[1], {"target": OTHER.text()})

    @bounded()
    async def test_the_routing_target_is_still_reachable_on_these_two_ops(self):
        """The op's own target is `node`, so `target=` in the keywords keeps
        meaning the node this query is routed to. On these two ops those are
        genuinely different nodes."""
        api = await self.serving(
            {f"{OP_ADOPT}?target=somebody": Accept(objects=[self.signed_frame()])}
        )
        await api.adopt("somebody", target=OTHER, caller=FURRY_BOLT)
        query = self.mock.queries[0]
        self.assertEqual(query.target, OTHER)
        self.assertEqual(query.caller, FURRY_BOLT)
        self.assertEqual(parse(query.query)[1], {"target": "somebody"})

    @bounded()
    async def test_an_empty_target_never_reaches_the_node(self):
        """astrald resolves the empty string to the zero identity rather than
        failing, so the op would sign a membership contract, or an irreversible
        ban, naming `anyone`."""
        for method in ("adopt", "expel"):
            with self.subTest(op=method):
                api = await self.serving({OP_ADOPT: Accept(), OP_EXPEL: Accept()})
                with self.assertRaises(BadArgument) as caught:
                    await getattr(api, method)("")
                self.assertIn("anyone", str(caught.exception))
                self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_an_unauthorized_caller_is_a_rejection_with_code_four(self):
        api = await self.serving({f"{OP_EXPEL}?target=somebody": Reject(4)})
        with self.assertRaises(QueryRejected) as caught:
            await api.expel("somebody")
        self.assertEqual(caught.exception.code, 4)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        api = await self.serving(
            {f"{OP_ADOPT}?target=somebody": Accept(objects=[self.expulsion_frame()])}
        )
        with self.assertRaises(ProtocolError) as caught:
            await api.adopt("somebody")
        self.assertIn(SignedContract.ASTRAL_TYPE, str(caught.exception))


class RequestMembershipOpTest(UserCase):
    """`user.request_membership`: RR, no argument, the caller is the subject."""

    @bounded()
    async def test_it_sends_no_parameters_and_returns_the_signed_contract(self):
        api = await self.serving(
            {
                OP_REQUEST_MEMBERSHIP: Accept(
                    objects=[
                        (SignedContract.ASTRAL_TYPE, payload_bytes(a_signed_contract()))
                    ]
                )
            }
        )
        self.assertIsInstance(await api.request_membership(), SignedContract)
        self.assertEqual(self.sent(), OP_REQUEST_MEMBERSHIP)

    @bounded()
    async def test_a_declined_request_surfaces_as_a_remote_error(self):
        api = await self.serving(
            {OP_REQUEST_MEMBERSHIP: Accept(objects=[frame_error("request declined")])}
        )
        with self.assertRaises(RemoteError) as caught:
            await api.request_membership()
        self.assertEqual(caught.exception.message, "request declined")


class AcceptMembershipOpTest(UserCase):
    """`user.accept_membership`: WA, two inputs on the body, no `eos`."""

    async def node(
        self, *answers: tuple[str, bytes]
    ) -> tuple[User, BodyReadingNode]:
        route = BodyReadingNode(*answers, expect=2)
        mock = MockApphost(routes={OP_ACCEPT_MEMBERSHIP: route})
        await self.enterAsyncContext(mock)
        self.mock = mock
        return await self.user(mock), route

    @bounded()
    async def test_both_inputs_travel_on_the_body_in_order(self):
        signature = a_signature()
        api, route = await self.node(
            ("mod.crypto.signature", payload_bytes(signature))
        )
        answer = await api.accept_membership(a_contract(), signature)  # type: ignore[arg-type]
        self.assertEqual(self.sent(), OP_ACCEPT_MEMBERSHIP)
        self.assertEqual(
            route.types, [Contract.ASTRAL_TYPE, "mod.crypto.signature"]
        )
        self.assertEqual(route.received[0][1], payload_bytes(a_contract()))
        self.assertEqual(answer, signature)

    @bounded()
    async def test_no_terminator_follows_the_inputs(self):
        """The op's reader breaks on the object it expects and answers
        `err_unexpected_object` for anything else, so an `eos` after the last
        input is an error rather than a no-op.

        The node reads a **third** frame that never comes and answers nothing,
        so the call expires on its own short budget and the recorded frames are
        everything the client wrote. Asserting the absence of a terminator
        against a node that reads only two frames would pass whether or not one
        was sent.
        """
        route = BodyReadingNode(expect=3)
        mock = MockApphost(routes={OP_ACCEPT_MEMBERSHIP: route})
        await self.enterAsyncContext(mock)
        self.mock = mock
        api = await self.user(mock)
        with self.assertRaises(QueryTimeout):
            await api.accept_membership(
                a_contract(), a_signature(), timeout=0.3  # type: ignore[arg-type]
            )
        self.assertEqual(route.types, [Contract.ASTRAL_TYPE, "mod.crypto.signature"])
        self.assertNotIn(EOS, route.types)

    @bounded()
    async def test_a_stream_that_answers_nothing_is_reported(self):
        api, _ = await self.node()
        with self.assertRaises(ProtocolError) as caught:
            await api.accept_membership(a_contract(), a_signature())  # type: ignore[arg-type]
        self.assertIn("without a signature", str(caught.exception))

    @bounded()
    async def test_a_declined_invitation_surfaces_as_a_remote_error(self):
        api, _ = await self.node(frame_error("invitation declined"))
        with self.assertRaises(RemoteError) as caught:
            await api.accept_membership(a_contract(), a_signature())  # type: ignore[arg-type]
        self.assertEqual(caught.exception.message, "invitation declined")

    @bounded()
    async def test_an_error_after_the_signature_fails_the_whole_ceremony(self):
        """The node countersigned and then failed to index, store or activate.
        The exchange did not complete, so the countersignature is discarded
        with the error rather than returned as a success."""
        api, _ = await self.node(
            ("mod.crypto.signature", payload_bytes(a_signature())),
            frame_error("failed to index contract"),
        )
        with self.assertRaises(RemoteError) as caught:
            await api.accept_membership(a_contract(), a_signature())  # type: ignore[arg-type]
        self.assertEqual(caught.exception.message, "failed to index contract")

    @bounded()
    async def test_a_signed_contract_is_refused_before_it_is_sent(self):
        api, _ = await self.node()
        with self.assertRaises(BadArgumentType) as caught:
            await api.accept_membership(a_signed_contract(), a_signature())  # type: ignore[arg-type]
        self.assertIn("unsigned body", str(caught.exception))
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_a_second_input_that_is_not_a_signature_is_refused(self):
        api, _ = await self.node()
        with self.assertRaises(BadArgumentType) as caught:
            await api.accept_membership(a_contract(), a_contract())  # type: ignore[arg-type]
        self.assertIn("issuer's signature", str(caught.exception))
        self.assertEqual(self.mock.queries, [])


class AcceptContractOpTest(UserCase):
    """`user.accept_contract`: WA, one input on the body, one `ack`."""

    async def node(
        self, *answers: tuple[str, bytes]
    ) -> tuple[User, BodyReadingNode]:
        route = BodyReadingNode(*answers, expect=1)
        mock = MockApphost(routes={OP_ACCEPT_CONTRACT: route})
        await self.enterAsyncContext(mock)
        self.mock = mock
        return await self.user(mock), route

    @bounded()
    async def test_the_signed_contract_travels_on_the_body(self):
        api, route = await self.node(ACK_FRAME)
        self.assertIsNone(await api.accept_contract(a_signed_contract()))
        self.assertEqual(self.sent(), OP_ACCEPT_CONTRACT)
        self.assertEqual(route.types, [SignedContract.ASTRAL_TYPE])
        self.assertEqual(route.received[0][1], payload_bytes(a_signed_contract()))

    @bounded()
    async def test_no_terminator_follows_the_input(self):
        """The node reads a **second** frame that never comes, so the recorded
        frames are everything the client wrote and the absence of a terminator
        is a fact rather than an artefact of how much the mock read."""
        route = BodyReadingNode(expect=2)
        mock = MockApphost(routes={OP_ACCEPT_CONTRACT: route})
        await self.enterAsyncContext(mock)
        self.mock = mock
        api = await self.user(mock)
        with self.assertRaises(QueryTimeout):
            await api.accept_contract(a_signed_contract(), timeout=0.3)
        self.assertEqual(route.types, [SignedContract.ASTRAL_TYPE])
        self.assertNotIn(EOS, route.types)

    @bounded()
    async def test_an_unsigned_contract_is_refused_before_it_is_sent(self):
        api, _ = await self.node(ACK_FRAME)
        with self.assertRaises(BadArgumentType) as caught:
            await api.accept_contract(a_contract())  # type: ignore[arg-type]
        self.assertIn("already signed", str(caught.exception))
        self.assertEqual(self.mock.queries, [])

    @bounded()
    async def test_an_invalid_contract_surfaces_as_a_remote_error(self):
        api, _ = await self.node(frame_error("invalid contract"))
        with self.assertRaises(RemoteError) as caught:
            await api.accept_contract(a_signed_contract())
        self.assertEqual(caught.exception.message, "invalid contract")

    @bounded()
    async def test_a_node_that_is_already_claimed_rejects_with_code_two(self):
        mock = MockApphost(routes={OP_ACCEPT_CONTRACT: Reject(2)})
        await self.enterAsyncContext(mock)
        self.mock = mock
        api = await self.user(mock)
        with self.assertRaises(QueryRejected) as caught:
            await api.accept_contract(a_signed_contract())
        self.assertEqual(caught.exception.code, 2)

    @bounded()
    async def test_a_stream_that_answers_nothing_is_reported(self):
        api, _ = await self.node()
        with self.assertRaises(ProtocolError) as caught:
            await api.accept_contract(a_signed_contract())
        self.assertIn("without an answer", str(caught.exception))


class UserPlumbingTest(UserCase):
    """What every op shares: the keyword set, routing, and closing the stream."""

    @bounded()
    async def test_query_keywords_reach_the_client(self):
        api = await self.serving({OP_ASSETS: Accept(eos=True)})
        await api.assets(caller=FURRY_BOLT, target=OTHER, filters=["localnode"])
        query = self.mock.queries[0]
        self.assertEqual(query.caller, FURRY_BOLT)
        self.assertEqual(query.target, OTHER)
        self.assertEqual(query.filters, ("localnode",))

    @bounded()
    async def test_the_module_client_is_reachable_from_the_client(self):
        mock = MockApphost()
        await self.enterAsyncContext(mock)
        client = await connect(connector=self.connector(mock))
        self.clients.append(client)
        self.assertIsInstance(client.user, User)
        self.assertIs(client.user, client.user)
        self.assertIs(client.user.client, client)

    @bounded()
    async def test_every_op_closes_its_stream(self):
        api = await self.serving({OP_ASSETS: Accept(eos=True)})
        await api.assets()
        self.assertEqual(api.client.live_streams, 0)

    @bounded()
    async def test_an_apphost_error_msg_is_not_an_in_stream_error(self):
        """`mod.apphost.error_msg` and an `error_message` object are different
        channels and are never merged."""
        mock = MockApphost(
            routes={
                OP_INFO: lambda conn, query: _send_error_msg(conn),
            }
        )
        await self.enterAsyncContext(mock)
        self.mock = mock
        api = await self.user(mock)
        with self.assertRaises(astral.errors.RouteNotFound):
            await api.info()


async def _send_error_msg(conn: MockConn) -> None:
    conn.send_frame(ERROR_MSG, error_msg_payload("route_not_found"))
    await conn.flush()


# --- Tier C: the live node ------------------------------------------------


class LiveUserTest(live_support.LiveCase):
    """`user` against a real node. Read-only: nothing here changes node state.

    Seven of the fifteen ops are safe to run: `assets`, `list_siblings`,
    `list_expelled`, `swarm_status`, `sync_assets`, `info` and
    `new_node_contract`, the last of which constructs and returns without
    signing or storing. The other eight change who a node belongs to or what it
    holds and are exercised against the mock alone.

    Every assertion accepts `QueryRejected(2)` where the op declares it, because
    whether the node under test is claimed is not this SDK's to decide.
    """

    @bounded(30.0)
    async def test_the_empty_shapes_all_end_at_an_eos(self):
        async with await self.client() as client:
            api = client.user
            self.assertIsInstance(await api.assets(), list)
            self.assertIsInstance(await api.list_siblings(), list)
            try:
                self.assertIsInstance(await api.list_expelled(), list)
            except QueryRejected as exc:
                self.assertEqual(exc.code, 2)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_sync_assets_returns_a_height_and_never_waits_for_an_eos(self):
        """The gate of design step 13. The op sends no `eos` at all, so a
        client that waits for one hangs; this returns."""
        async with await self.client() as client:
            answer = await client.user.sync_assets()
            self.assertIsInstance(answer, AssetSync)
            self.assertIsInstance(answer.next_height, int)
            self.assertGreaterEqual(answer.next_height, 0)
            # An empty answer echoes `start`, so re-polling is safe and empty.
            again = await client.user.sync_assets(start=answer.next_height)
            self.assertEqual(again.next_height, answer.next_height)
            self.assertEqual(again.updates, [])
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_info_decodes_or_reports_an_unclaimed_node(self):
        async with await self.client() as client:
            try:
                info = await client.user.info()
            except QueryRejected as exc:
                self.assertEqual(exc.code, 2, "code 2 is the setup-mode probe")
                return
            self.assertIsInstance(info, Info)
            self.assertIsInstance(info.contract, SignedContract)
            self.assertTrue(info.contract.fully_signed)
            self.assertEqual(info.node_id, client.host_id)
            # The node computes ContractID with ResolveObjectID; recomputing it
            # locally proves the whole nested graph re-encoded byte-exactly.
            self.assertEqual(object_id(info.contract), info.contract_id)
            self.assertTrue(is_node_contract(info.contract.contract))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_swarm_status_lists_the_node_itself_or_reports_no_contract(self):
        async with await self.client() as client:
            try:
                members = await client.user.swarm_status()
            except QueryRejected as exc:
                self.assertEqual(exc.code, 2)
                return
            self.assertTrue(all(isinstance(m, SwarmMember) for m in members))
            self.assertIn(client.host_id, [m.identity for m in members])
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_new_node_contract_builds_a_management_contract(self):
        """Construction only: the answer is unsigned, unstored and authorizes
        nothing. astrald passes `managementNode=true` unconditionally, so the
        four permits are the shape every answer has."""
        async with await self.client() as client:
            contract = await client.user.new_node_contract()
            self.assertIsInstance(contract, Contract)
            self.assertTrue(is_node_contract(contract))
            self.assertEqual(
                [p.action for p in contract.permits],
                [
                    SwarmMembershipAction.ASTRAL_TYPE,
                    ExpelAction.ASTRAL_TYPE,
                    AdoptAction.ASTRAL_TYPE,
                    InfoAction.ASTRAL_TYPE,
                ],
            )
            self.assertFalse(contract.expired)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_duration_shortens_the_contract_the_node_builds(self):
        async with await self.client() as client:
            api = client.user
            default = await api.new_node_contract()
            short = await api.new_node_contract(duration="48h")
            self.assertLess(int(short.expires_at), int(default.expires_at))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_year_unit_is_refused_here_and_by_the_node(self):
        """`Duration.parse` carries Go's unit table, so `1y` never travels.
        The node's own answer for it is
        `time: unknown unit "y" in duration "1y"`, verified this session."""
        async with await self.client() as client:
            with self.assertRaises(ParseError):
                await client.user.new_node_contract(duration="1y")
            with self.assertRaises(RemoteError) as caught:
                await client.call_one(f"{OP_NEW_NODE_CONTRACT}?duration=1y")
            self.assertIn("unknown unit", str(caught.exception))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unknown_name_answers_with_an_error_message(self):
        async with await self.client() as client:
            with self.assertRaises(RemoteError) as caught:
                await client.user.new_node_contract(user="astral-py-no-such-user")
            self.assertIn("unknown identity", str(caught.exception))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_s_own_types_are_the_ones_this_module_declares(self):
        """`objects.blueprints` names every type the node can decode. Every
        `mod.user*` name it reports must be one this module declares, or the
        SDK cannot decode an object the node can send."""
        async with await self.client() as client:
            names = {
                name
                for name in await client.objects.blueprints()
                if name.startswith(("mod.user.", "mod.users."))
            }
        declared = {kind.ASTRAL_TYPE for kind in USER_TYPES}
        self.assertEqual(names - declared, set())
        await self.assert_no_open_sockets()


# --- the module's own claims ----------------------------------------------


class CitationTest(unittest.TestCase):
    """Every source anchor this module cites, read back at the pin.

    astrald and astral-go are moving targets and a drifted line number costs a
    reader more than an absent one: it makes them distrust the exact citations
    too. The anchors are read out of the module's own prose rather than
    restated here, so a citation that stops landing names itself.
    """

    ASTRALD_LINES = {
        ("mod/user/src/op_sync_assets.go", 47): "return ch.Send(&height)",
        ("mod/user/src/op_sync_assets.go", 33): "height = args.Start",
        ("mod/user/src/op_sync_assets.go", 44): "height++",
        ("mod/user/src/op_list_siblings.go", 17): "IncludeZone(args.Zone)",
        ("mod/user/src/config.go", 11): "minimalContractLength   = time.Hour",
        ("mod/user/src/config.go", 12): "defaultContractValidity = 365 * 24 * time.Hour",
        ("mod/user/src/siblings.go", 25): "user.Notification{Event",
        ("mod/user/src/op_adopt.go", 34): "return q.RejectWithCode(4)",
        ("mod/user/src/db.go", 60): "db.Save(&dbAsset{",
        ("mod/user/src/op_sync_with.go", 20): "mod.syncAssets(ctx.IncludeZone",
        ("mod/user/src/sync.go", 29): "tree.Get[*astral.Uint64](ctx, heightNode)",
        ("mod/dir/src/module.go", 56): 'if s == "" || s == "anyone"',
        ("mod/dir/src/module.go", 105): "return identity.Fingerprint()",
        ("mod/user/src/contracts.go", 171): "defaultContractValidity",
    }

    ASTRAL_GO_LINES = {
        ("api/user/contract.go", 12): "SwarmMembershipAction{}.ObjectType()",
        ("api/user/contract.go", 20): "SwarmMembershipAction{}.ObjectType()",
        ("api/user/contract.go", 26): "InfoAction{}.ObjectType()",
        ("api/user/expulsion.go", 39): "expels %s from the swarm",
    }

    def assert_lands(self, repo: str, anchors: dict) -> None:
        for (path, number), expected in anchors.items():
            with self.subTest(file=path, line=number):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(expected, line)

    def test_every_astrald_anchor_lands_on_its_claim(self):
        self.assert_lands(reference.ASTRALD, self.ASTRALD_LINES)

    def test_every_astral_go_anchor_lands_on_its_claim(self):
        self.assert_lands(reference.ASTRAL_GO, self.ASTRAL_GO_LINES)

    def test_the_module_cites_no_line_this_test_does_not_check(self):
        """A citation the suite does not read is a citation nobody re-reads."""
        source = pathlib.Path(user_module.__file__).read_text(encoding="utf-8")
        cited = set(re.findall(r"(mod/\w+/src/\w+\.go|api/user/\w+\.go):(\d+)", source))
        checked = {
            (path, str(number))
            for path, number in list(self.ASTRALD_LINES) + list(self.ASTRAL_GO_LINES)
        }
        self.assertEqual(cited - checked, set())

    def test_astrald_carries_the_op_this_module_says_it_carries(self):
        """`user.accept_contract` is astrald #357 and is present at the pin;
        astral-go carries no client for it there."""
        try:
            names = reference.listdir(reference.ASTRALD, "mod/user/src")
            clients = reference.listdir(reference.ASTRAL_GO, "api/user/client")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        self.assertIn("op_accept_contract.go", names)
        self.assertNotIn("accept_contract.go", clients)

    def test_every_op_file_astrald_carries_has_an_op_constant_here(self):
        """A census rather than a list: an op astrald grows and this module
        does not is a hole a reader cannot see from inside the module."""
        try:
            names = reference.listdir(reference.ASTRALD, "mod/user/src")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        ops = {
            "user." + name[len("op_") : -len(".go")]
            for name in names
            if name.startswith("op_") and not name.endswith("_test.go")
        }
        declared = {
            value
            for name, value in vars(user_module).items()
            if name.startswith("OP_") and isinstance(value, str)
        }
        self.assertEqual(ops, declared)


class ShapeDeclarationTest(unittest.TestCase):
    """No generic reader is used on the op that has no terminator.

    Design section 3.10 names `user.sync_assets` as the shape `collect()`,
    `call()` and `async for` all hang on. The module must therefore not route
    it through `Client.call`, and the guard is the source rather than a
    docstring, because the failure mode is a hang and not a wrong answer.
    """

    def test_sync_assets_does_not_go_through_a_terminator_reader(self):
        import ast

        source = pathlib.Path(user_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if node.name != "sync_assets":
                continue
            body = ast.unparse(node)
            for banned in ("call(", "collect(", "call_with(", "async for"):
                self.assertNotIn(
                    banned,
                    body,
                    f"sync_assets reaches for {banned!r}, which waits for a "
                    "terminator this op never sends",
                )
            self.assertIn("first(", body)
            return
        self.fail("sync_assets was not found")

    def test_the_module_declares_a_shape_for_every_op_in_its_table(self):
        """The docstring table is the module's declaration of op shape, which
        design section 4.7 makes a per-op contract. Fifteen rows, fifteen
        ops."""
        table = [
            line
            for line in (user_module.__doc__ or "").splitlines()
            if line.startswith("| `user.")
        ]
        self.assertEqual(len(table), 15)
        named = {line.split("`")[1] for line in table}
        declared = {
            value
            for name, value in vars(user_module).items()
            if name.startswith("OP_") and isinstance(value, str)
        }
        self.assertEqual(named, declared)
