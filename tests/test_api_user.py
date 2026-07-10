"""Tests for the ``user`` protocol helper and its net-new record family.

Two layers, mirroring ``test_api_auth.py``:

* **Record round-trips** — each net-new ``user`` record (``mod.user.info``,
  ``mod.users.swarm_member`` — PLURAL ``users`` — ``mod.user.expulsion`` /
  ``mod.user.signed_expulsion``, ``mod.user.op_update``) is round-tripped over BOTH
  framings (binary ``write_to``/``read_from`` and JSON ``from_value``/``encode_json``),
  matching the transport-decision requirement that structured objects decode over
  binary IPC too. ``UserInfo`` nests a ``SignedContract`` under a nullable pointer;
  ``SignedExpulsion`` is the FLATTENED (``Issuer``/``Subject``/``ExpelledAt``/
  ``IssuerSig``) form astral-go marshals. The imported cross-protocol records
  (``Contract``/``SignedContract``/``Signature``) are exercised only as nested
  fields — they are NOT re-registered here (pinned below).
* **Ops over a binary MockNode** — all 14 ops. Pins the swarm_status PLURAL type,
  the ``sync_assets`` NON-EOS terminator (a bare ``uint64`` ends the stream with no
  ``eos``; the explicit ``recv`` loop must stop on it), the ``accept_membership``
  2-send input body (contract THEN issuer signature, reply is the subject sig, no
  ``eos``), and ``new_node_contract`` returning an UNSIGNED ``Contract``.

Plus registry resolution for the five net-new types, and that the imported
cross-protocol types keep their own record classes (no double-registration).

Grounding: ``protocols/user/`` op + type docs, astral-go ``api/user/*.go`` +
``api/user/client/*.go``, astrald ``mod/user/src/op_*.go`` + ``sync.go``.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.auth import Contract, Permit, SignedContract
from astral.api.crypto import Signature
from astral.api.user import (
    Expulsion,
    OpUpdate,
    SignedExpulsion,
    SwarmMember,
    User,
    UserInfo,
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
from astral.objects import AstralObject, ack, eos
from astral.registry import record_for
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
ID_A = "03" + "cd" * 32
ID_B = "02" + "ef" * 32
OID_1 = ObjectID(11, b"\x11" * 32)
OID_2 = ObjectID(22, b"\x22" * 32)
NONCE = "0011223344556677"


def _binary_roundtrip(record):
    """Encode ``record`` to binary and decode it back through the same class."""
    writer = BinaryWriter()
    record.write_to(writer)
    return type(record).read_from(BinaryReader(writer.getvalue()))


def _json_roundtrip(record):
    """Encode ``record`` to its JSON value form and decode it back."""
    return type(record).from_value(record.encode_json())


def _signed_contract():
    contract = Contract(
        issuer=HOST_ID,
        subject=ID_A,
        permits=[Permit(action="mod.user.swarm_membership_action", constraints=None, delegation=0)],
        expires_at=1927848000,
    )
    return SignedContract(
        contract=contract,
        issuer_sig=Signature(scheme="asn1", data=b"\x01\x02\x03\x04"),
        subject_sig=Signature(scheme="asn1", data=b"\x05\x06\x07\x08"),
    )


# ======================================================================
# Record round-trips (binary + JSON)
# ======================================================================
class UserInfoRecordTest(unittest.TestCase):
    def _info(self):
        return UserInfo(
            node_alias="phone",
            user_alias="alice",
            contract_id=OID_1,
            contract=_signed_contract(),
        )

    def test_binary_roundtrip(self):
        info = self._info()
        self.assertEqual(_binary_roundtrip(info), info)

    def test_nil_pointers_binary_roundtrip(self):
        info = UserInfo(node_alias="", user_alias="", contract_id=None, contract=None)
        self.assertEqual(_binary_roundtrip(info), info)

    def test_binary_field_order(self):
        # string8(NodeAlias) ++ string8(UserAlias) ++ ptr(object_id ContractID)
        # ++ ptr(record SignedContract Contract).
        info = self._info()
        writer = BinaryWriter()
        writer.string8("phone")
        writer.string8("alice")
        writer.u8(1)  # ContractID ptr present
        writer.raw(OID_1.to_bytes())
        writer.u8(1)  # Contract ptr present
        info.contract.write_to(writer)
        self.assertEqual(info.encode_binary(), writer.getvalue())

    def test_json_roundtrip_contract_is_record(self):
        info = self._info()
        back = UserInfo.from_value(info.encode_json())
        self.assertEqual(back, info)
        self.assertIsInstance(back.contract, SignedContract)

    def test_json_keys_are_pascalcase(self):
        info = self._info()
        value = info.encode_json()
        self.assertEqual(
            set(value), {"NodeAlias", "UserAlias", "ContractID", "Contract"}
        )


class SwarmMemberRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        m = SwarmMember(identity=ID_A, alias="laptop", linked=True)
        self.assertEqual(_binary_roundtrip(m), m)

    def test_binary_field_order(self):
        # identity(Identity) ++ string8(Alias) ++ bool(Linked).
        m = SwarmMember(identity=ID_A, alias="laptop", linked=True)
        writer = BinaryWriter()
        writer.identity(ID_A)
        writer.string8("laptop")
        writer.boolean(True)
        self.assertEqual(m.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        m = SwarmMember(identity=ID_A, alias="", linked=False)
        self.assertEqual(_json_roundtrip(m), m)

    def test_type_string_is_plural_users(self):
        # The one type whose namespace is the PLURAL ``users`` — pinned so a
        # refactor cannot quietly singularize it.
        self.assertEqual(SwarmMember.TYPE, "mod.users.swarm_member")
        self.assertIs(record_for("mod.users.swarm_member"), SwarmMember)


class ExpulsionRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        e = Expulsion(issuer=HOST_ID, subject=ID_A, expelled_at=1750320000)
        self.assertEqual(_binary_roundtrip(e), e)

    def test_binary_field_order(self):
        # identity(Issuer) ++ identity(Subject) ++ time(uint64 ExpelledAt).
        e = Expulsion(issuer=HOST_ID, subject=ID_A, expelled_at=1750320000)
        writer = BinaryWriter()
        writer.identity(HOST_ID)
        writer.identity(ID_A)
        writer.u64(1750320000)
        self.assertEqual(e.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        e = Expulsion(issuer=HOST_ID, subject=ID_A, expelled_at=1750320000)
        self.assertEqual(_json_roundtrip(e), e)


class SignedExpulsionRecordTest(unittest.TestCase):
    def _signed(self):
        return SignedExpulsion(
            issuer=HOST_ID,
            subject=ID_A,
            expelled_at=1750320000,
            issuer_sig=Signature(scheme="asn1", data=b"\x0a\x0b\x0c\x0d"),
        )

    def test_binary_roundtrip(self):
        se = self._signed()
        self.assertEqual(_binary_roundtrip(se), se)

    def test_nil_sig_binary_roundtrip(self):
        se = SignedExpulsion(issuer=HOST_ID, subject=ID_A, expelled_at=7, issuer_sig=None)
        self.assertEqual(_binary_roundtrip(se), se)

    def test_flattened_binary_field_order(self):
        # astral-go embeds *Expulsion so its fields are FLATTENED to the top level:
        # identity(Issuer) ++ identity(Subject) ++ time(ExpelledAt) ++ ptr(record IssuerSig).
        se = self._signed()
        writer = BinaryWriter()
        writer.identity(HOST_ID)
        writer.identity(ID_A)
        writer.u64(1750320000)
        writer.u8(1)  # IssuerSig ptr present
        se.issuer_sig.write_to(writer)
        self.assertEqual(se.encode_binary(), writer.getvalue())

    def test_flattened_json_shape(self):
        # The docs example is flattened: Issuer/Subject/ExpelledAt/IssuerSig at the
        # top level, with NO nested "Expulsion" key.
        se = self._signed()
        value = se.encode_json()
        self.assertEqual(set(value), {"Issuer", "Subject", "ExpelledAt", "IssuerSig"})
        self.assertNotIn("Expulsion", value)
        self.assertEqual(SignedExpulsion.from_value(value), se)


class OpUpdateRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        u = OpUpdate(nonce=NONCE, object_id=OID_1, removed=True)
        self.assertEqual(_binary_roundtrip(u), u)

    def test_binary_field_order(self):
        # nonce64(Nonce, 8 raw bytes) ++ object_id(ObjectID) ++ bool(Removed).
        u = OpUpdate(nonce=NONCE, object_id=OID_1, removed=False)
        writer = BinaryWriter()
        writer.nonce(NONCE)
        writer.raw(OID_1.to_bytes())
        writer.boolean(False)
        self.assertEqual(u.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        u = OpUpdate(nonce=NONCE, object_id=OID_2, removed=True)
        self.assertEqual(_json_roundtrip(u), u)


# ======================================================================
# Registry resolution + no double-registration / no re-registration
# ======================================================================
class RegistryTest(unittest.TestCase):
    def test_net_new_records_resolve_by_type(self):
        self.assertIs(record_for("mod.user.info"), UserInfo)
        self.assertIs(record_for("mod.users.swarm_member"), SwarmMember)
        self.assertIs(record_for("mod.user.expulsion"), Expulsion)
        self.assertIs(record_for("mod.user.signed_expulsion"), SignedExpulsion)
        self.assertIs(record_for("mod.user.op_update"), OpUpdate)

    def test_cross_protocol_types_not_re_registered(self):
        # Contract/SignedContract/Signature are IMPORTED, not re-registered here —
        # they keep the classes their own modules registered.
        self.assertIs(record_for("mod.auth.contract"), Contract)
        self.assertIs(record_for("mod.auth.signed_contract"), SignedContract)
        self.assertIs(record_for("mod.crypto.signature"), Signature)

    def test_no_double_registration(self):
        from astral.registry import register

        for obj_type, cls in (
            ("mod.user.info", UserInfo),
            ("mod.users.swarm_member", SwarmMember),
            ("mod.user.expulsion", Expulsion),
            ("mod.user.signed_expulsion", SignedExpulsion),
            ("mod.user.op_update", OpUpdate),
        ):
            self.assertIs(register(obj_type)(cls), cls)
            self.assertIs(record_for(obj_type), cls)


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
class UserMockNode:
    """A minimal binary apphost server tailored to the 14 user ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received
        self.accept_body = []  # objects streamed to accept_membership

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

        if op == "user.info":
            info = UserInfo(
                node_alias="phone",
                user_alias="alice",
                contract_id=OID_1,
                contract=_signed_contract(),
            )
            ch.send(AstralObject("mod.user.info", info.encode_binary()))
            # op_info sends a single object then closes (no explicit eos).

        elif op == "user.swarm_status":
            for m in (
                SwarmMember(identity=ID_A, alias="phone", linked=True),
                SwarmMember(identity=ID_B, alias="laptop", linked=False),
            ):
                ch.send(AstralObject("mod.users.swarm_member", m.encode_binary()))
            ch.send(eos())

        elif op == "user.list_siblings":
            ch.send(AstralObject("identity", ID_A))
            ch.send(AstralObject("identity", ID_B))
            ch.send(eos())

        elif op == "user.list_expelled":
            se = SignedExpulsion(
                issuer=HOST_ID,
                subject=ID_A,
                expelled_at=1750320000,
                issuer_sig=Signature(scheme="asn1", data=b"\x0a\x0b"),
            )
            ch.send(AstralObject("mod.user.signed_expulsion", se.encode_binary()))
            ch.send(eos())

        elif op == "user.assets":
            ch.send(AstralObject("object_id", OID_1))
            ch.send(AstralObject("object_id", OID_2))
            ch.send(eos())

        elif op == "user.add_asset" or op == "user.remove_asset":
            ch.send(ack())
            ch.send(eos())

        elif op == "user.sync_assets":
            # NON-EOS terminator: op_updates then a BARE uint64 (next height); NO eos.
            u1 = OpUpdate(nonce=NONCE, object_id=OID_1, removed=False)
            u2 = OpUpdate(nonce="8899aabbccddeeff", object_id=OID_2, removed=True)
            ch.send(AstralObject("mod.user.op_update", u1.encode_binary()))
            ch.send(AstralObject("mod.user.op_update", u2.encode_binary()))
            ch.send(AstralObject("uint64", 2))  # next height; deliberately NO eos

        elif op == "user.sync_with":
            ch.send(ack())
            ch.send(eos())

        elif op == "user.adopt":
            ch.send(
                AstralObject("mod.auth.signed_contract", _signed_contract().encode_binary())
            )
            ch.send(eos())

        elif op == "user.expel":
            se = SignedExpulsion(
                issuer=HOST_ID,
                subject=ID_A,
                expelled_at=1750320000,
                issuer_sig=Signature(scheme="asn1", data=b"\xaa\xbb"),
            )
            ch.send(AstralObject("mod.user.signed_expulsion", se.encode_binary()))
            ch.send(eos())

        elif op == "user.new_node_contract":
            # UNSIGNED mod.auth.contract (NOT signed_contract).
            contract = Contract(
                issuer=HOST_ID,
                subject=ID_A,
                permits=[
                    Permit(
                        action="mod.user.swarm_membership_action",
                        constraints=None,
                        delegation=0,
                    )
                ],
                expires_at=1927848000,
            )
            ch.send(AstralObject("mod.auth.contract", contract.encode_binary()))
            ch.send(eos())

        elif op == "user.request_membership":
            ch.send(
                AstralObject("mod.auth.signed_contract", _signed_contract().encode_binary())
            )
            ch.send(eos())

        elif op == "user.accept_membership":
            # INPUT-BODY: read the contract, then the issuer signature; reply with
            # the node's subject signature BEFORE any eos (mirrors astral-go).
            self.accept_body.append(ch.recv())
            self.accept_body.append(ch.recv())
            subject_sig = Signature(scheme="asn1", data=b"\x11\x22\x33\x44")
            ch.send(AstralObject("mod.crypto.signature", subject_sig.encode_binary()))
            # No eos — end-of-input is the reply-read and channel close.

        else:
            ch.send(eos())


class UserOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = UserMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []
        self.node.accept_body = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_user_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.user, User)
            self.assertIs(c.user, c.user)  # lazily cached

    def test_info_returns_single_userinfo(self):
        with self.connect() as c:
            info = c.user.info()
        self.assertIsInstance(info, UserInfo)
        self.assertEqual(info.node_alias, "phone")
        self.assertEqual(info.user_alias, "alice")
        self.assertEqual(info.contract_id, OID_1)
        self.assertIsInstance(info.contract, SignedContract)
        self.assertEqual(info.contract.contract.issuer, HOST_ID)
        self.assertIn("user.info", self.node.seen)

    def test_swarm_status_streams_plural_swarm_members(self):
        with self.connect() as c:
            members = c.user.swarm_status()
        self.assertEqual(len(members), 2)
        self.assertTrue(all(isinstance(m, SwarmMember) for m in members))
        self.assertEqual(members[0], SwarmMember(identity=ID_A, alias="phone", linked=True))
        self.assertEqual(members[1], SwarmMember(identity=ID_B, alias="laptop", linked=False))
        self.assertIn("user.swarm_status", self.node.seen)

    def test_list_siblings_streams_identities(self):
        with self.connect() as c:
            siblings = c.user.list_siblings()
        self.assertEqual(siblings, [ID_A, ID_B])

    def test_list_siblings_passes_zone(self):
        with self.connect() as c:
            c.user.list_siblings(zone="n")
        self.assertIn("user.list_siblings?zone=n", self.node.seen)

    def test_list_expelled_streams_signed_expulsions(self):
        with self.connect() as c:
            bans = c.user.list_expelled()
        self.assertEqual(len(bans), 1)
        self.assertIsInstance(bans[0], SignedExpulsion)
        self.assertEqual(bans[0].issuer, HOST_ID)
        self.assertEqual(bans[0].subject, ID_A)
        self.assertEqual(bans[0].issuer_sig, Signature(scheme="asn1", data=b"\x0a\x0b"))

    def test_assets_streams_object_ids(self):
        with self.connect() as c:
            assets = c.user.assets()
        self.assertEqual(assets, [OID_1, OID_2])
        self.assertTrue(all(isinstance(a, ObjectID) for a in assets))

    def test_add_asset_acks_and_pins_id(self):
        with self.connect() as c:
            self.assertIsNone(c.user.add_asset(OID_1))
        self.assertIn(f"user.add_asset?id={OID_1}", self.node.seen)

    def test_remove_asset_acks_and_pins_id(self):
        with self.connect() as c:
            self.assertIsNone(c.user.remove_asset(str(OID_2)))
        self.assertIn(f"user.remove_asset?id={OID_2}", self.node.seen)

    def test_sync_assets_non_eos_terminator_stops_on_uint64(self):
        # The stream ends with a BARE uint64 and NO eos; the explicit recv loop must
        # accumulate the op_updates and stop on that height, returning it.
        with self.connect() as c:
            updates, next_height = c.user.sync_assets(start=0)
        self.assertEqual(next_height, 2)
        self.assertEqual(len(updates), 2)
        self.assertTrue(all(isinstance(u, OpUpdate) for u in updates))
        self.assertEqual(updates[0], OpUpdate(nonce=NONCE, object_id=OID_1, removed=False))
        self.assertEqual(
            updates[1], OpUpdate(nonce="8899aabbccddeeff", object_id=OID_2, removed=True)
        )
        self.assertIn("user.sync_assets?start=0", self.node.seen)

    def test_sync_assets_default_omits_start(self):
        with self.connect() as c:
            c.user.sync_assets()
        self.assertIn("user.sync_assets", self.node.seen)
        self.assertNotIn("user.sync_assets?start=0", self.node.seen)

    def test_sync_with_acks_and_pins_args(self):
        with self.connect() as c:
            self.assertIsNone(c.user.sync_with(ID_B, start=5))
        self.assertIn(f"user.sync_with?node={ID_B}&start=5", self.node.seen)

    def test_adopt_returns_signed_contract(self):
        with self.connect() as c:
            signed = c.user.adopt("laptop")
        self.assertIsInstance(signed, SignedContract)
        self.assertEqual(signed.contract.issuer, HOST_ID)
        self.assertIn("user.adopt?target=laptop", self.node.seen)

    def test_expel_returns_signed_expulsion(self):
        with self.connect() as c:
            se = c.user.expel("phone")
        self.assertIsInstance(se, SignedExpulsion)
        self.assertEqual(se.subject, ID_A)
        self.assertIn("user.expel?target=phone", self.node.seen)

    def test_new_node_contract_returns_unsigned_contract(self):
        with self.connect() as c:
            contract = c.user.new_node_contract(user="alice", node="laptop", duration="720h")
        # UNSIGNED contract, NOT a SignedContract.
        self.assertIsInstance(contract, Contract)
        self.assertNotIsInstance(contract, SignedContract)
        self.assertEqual(contract.issuer, HOST_ID)
        self.assertEqual(
            contract.permits[0].action, "mod.user.swarm_membership_action"
        )
        q = self.node.seen[-1]
        self.assertTrue(q.startswith("user.new_node_contract?"))
        self.assertIn("user=alice", q)
        self.assertIn("node=laptop", q)
        self.assertIn("duration=720h", q)

    def test_new_node_contract_no_args(self):
        with self.connect() as c:
            contract = c.user.new_node_contract()
        self.assertIsInstance(contract, Contract)
        self.assertIn("user.new_node_contract", self.node.seen)

    def test_request_membership_returns_signed_contract(self):
        with self.connect() as c:
            signed = c.user.request_membership()
        self.assertIsInstance(signed, SignedContract)
        self.assertIn("user.request_membership", self.node.seen)

    def test_accept_membership_sends_two_body_objects_and_returns_subject_sig(self):
        contract = Contract(
            issuer=HOST_ID,
            subject=ID_A,
            permits=[
                Permit(action="mod.user.swarm_membership_action", constraints=None, delegation=0)
            ],
            expires_at=1927848000,
        )
        issuer_sig = Signature(scheme="asn1", data=b"\xde\xad\xbe\xef")
        with self.connect() as c:
            subject_sig = c.user.accept_membership(contract, issuer_sig)
        # The reply is the node's subject signature (no eos was needed to read it).
        self.assertIsInstance(subject_sig, Signature)
        self.assertEqual(subject_sig, Signature(scheme="asn1", data=b"\x11\x22\x33\x44"))
        # Exactly two objects crossed the body, in order: contract THEN issuer sig.
        self.assertEqual(len(self.node.accept_body), 2)
        first, second = self.node.accept_body
        self.assertEqual(first.type, "mod.auth.contract")
        self.assertEqual(Contract.from_value(first.value), contract)
        self.assertEqual(second.type, "mod.crypto.signature")
        self.assertEqual(Signature.from_value(second.value), issuer_sig)
        # The query itself carried no args.
        self.assertIn("user.accept_membership", self.node.seen)


# ======================================================================
# Record SEND path (the encode counterpart of the decode dispatch)
# ======================================================================
class RecordSendPathTest(unittest.TestCase):
    def test_encode_payload_encodes_op_update_over_binary(self):
        from astral.payload import encode_payload

        u = OpUpdate(nonce=NONCE, object_id=OID_1, removed=True)
        self.assertEqual(encode_payload("mod.user.op_update", u), u.encode_binary())

    def test_to_json_envelope_encodes_swarm_member(self):
        from astral.encoding import to_json_envelope

        m = SwarmMember(identity=ID_A, alias="phone", linked=True)
        env = to_json_envelope(AstralObject("mod.users.swarm_member", m))
        self.assertEqual(
            env, {"Type": "mod.users.swarm_member", "Object": m.encode_json()}
        )


if __name__ == "__main__":
    unittest.main()
