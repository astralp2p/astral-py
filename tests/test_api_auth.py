"""Tests for the ``auth`` protocol helper, its record family, and the Bundle codec.

Two layers:

* **Record round-trips** — each ``mod.auth.*`` / ``mod.crypto.signature`` record is
  round-tripped over BOTH framings (binary ``write_to``/``read_from`` and JSON
  ``from_value``/``encode_json``), matching the transport-decision requirement that
  structured objects decode over binary IPC too. Covers ``Signature`` (bytes16),
  ``Permit`` (nil AND non-nil OPAQUE ``Bundle`` of 1-2 blobs — the blobs must
  survive), ``Contract`` (a ``[]*Permit`` array), and ``SignedContract`` (present +
  all-nil signatures, and the FLATTENED-JSON ``from_value`` path astral-go marshals).
* **Ops over a binary MockNode** — ``sign_contract`` streams the contract on the
  body (no eos, mirroring ``apphost.sign_app_contract``) and decodes the reply to a
  ``SignedContract``; ``index`` acks and the id arg is pinned.

Plus registry resolution + no double-registration for the three ``mod.auth.*`` types.
Grounding: ``protocols/auth/`` op + type docs, astral-go ``api/auth/`` +
``api/crypto/signature.go``, ``astral/bundle.go`` (the opaque Bundle wire).
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.auth import Auth, Contract, Permit, SignedContract
from astral.api.crypto import Signature
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
ID_A = "03" + "cd" * 32
# A stored signed-contract object id (sha256 hex) for the index op.
CONTRACT_ID = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


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
class SignatureRecordTest(unittest.TestCase):
    def test_binary_roundtrip(self):
        sig = Signature(scheme="asn1", data=bytes(range(16)))
        self.assertEqual(_binary_roundtrip(sig), sig)

    def test_binary_layout_is_string8_then_u16_length_prefixed(self):
        # string8(Scheme) ++ uint16(len) ++ raw data (bytes16).
        sig = Signature(scheme="ed", data=b"\xaa\xbb\xcc")
        expected = bytes([2]) + b"ed" + (3).to_bytes(2, "big") + b"\xaa\xbb\xcc"
        self.assertEqual(sig.encode_binary(), expected)

    def test_json_is_base64_string(self):
        sig = Signature(scheme="asn1", data=b"\x00\x01\x02\x03")
        self.assertEqual(sig.encode_json(), {"Scheme": "asn1", "Data": "AAECAw=="})

    def test_json_roundtrip(self):
        sig = Signature(scheme="ed25519", data=bytes(range(20)))
        self.assertEqual(_json_roundtrip(sig), sig)

    def test_from_value_accepts_scheme_base64_text(self):
        # The compact TEXT form "<scheme>:<base64>" decodes to a Signature — the
        # JSON text-vs-object ambiguity this override flags.
        sig = Signature.from_value("asn1:AAECAw==")
        self.assertEqual(sig, Signature(scheme="asn1", data=b"\x00\x01\x02\x03"))

    def test_from_value_object_form_still_works(self):
        sig = Signature.from_value({"Scheme": "ed", "Data": "AAEC"})
        self.assertEqual(sig, Signature(scheme="ed", data=b"\x00\x01\x02"))

    def test_from_value_idempotent(self):
        sig = Signature(scheme="asn1", data=b"\x09")
        self.assertIs(Signature.from_value(sig), sig)


class PermitRecordTest(unittest.TestCase):
    def test_nil_constraints_binary_roundtrip(self):
        permit = Permit(action="mod.user.swarm_access_action", constraints=None, delegation=0)
        self.assertEqual(_binary_roundtrip(permit), permit)

    def test_nil_constraints_binary_layout(self):
        # string8(Action) ++ ptr-nil(0x00 for Constraints) ++ uint8(Delegation).
        permit = Permit(action="a", constraints=None, delegation=2)
        expected = bytes([1]) + b"a" + b"\x00" + bytes([2])
        self.assertEqual(permit.encode_binary(), expected)

    def test_nonnil_bundle_blobs_survive_binary_roundtrip(self):
        # A non-nil OPAQUE Bundle of two framed blobs: the raw blobs must survive
        # the round-trip byte-for-byte (opaque passthrough — inner objects not
        # decoded). astral.Bundle wire: uint32(count) ++ bytes32(blob) per object.
        blobs = [b"\x05blob-one", b"\x00\x01\x02\x03"]
        permit = Permit(action="mod.x", constraints=blobs, delegation=1)
        back = _binary_roundtrip(permit)
        self.assertEqual(back.constraints, blobs)
        self.assertEqual(back, permit)

    def test_single_blob_bundle_binary_layout(self):
        # ptr-present(0x01) ++ uint32(1) ++ bytes32(len) ++ blob, framed after the
        # string8(Action); then uint8(Delegation).
        blob = b"\xde\xad\xbe\xef"
        permit = Permit(action="", constraints=[blob], delegation=0)
        expected = (
            bytes([0])  # string8("") Action
            + b"\x01"  # Constraints ptr present
            + (1).to_bytes(4, "big")  # bundle count
            + (len(blob)).to_bytes(4, "big")  # bytes32 length prefix
            + blob
            + bytes([0])  # uint8 Delegation
        )
        self.assertEqual(permit.encode_binary(), expected)

    def test_bundle_json_passthrough(self):
        # JSON is an opaque passthrough of the blob list (inner objects untouched).
        blobs = [b"a", b"bc"]
        permit = Permit(action="x", constraints=blobs, delegation=3)
        value = permit.encode_json()
        self.assertEqual(value["Constraints"], blobs)
        self.assertEqual(_json_roundtrip(permit), permit)

    def test_nil_constraints_json_is_none(self):
        permit = Permit(action="x", constraints=None, delegation=0)
        self.assertEqual(
            permit.encode_json(), {"Action": "x", "Constraints": None, "Delegation": 0}
        )
        self.assertEqual(_json_roundtrip(permit), permit)


class ContractRecordTest(unittest.TestCase):
    def _contract(self):
        return Contract(
            issuer=HOST_ID,
            subject=ID_A,
            permits=[
                Permit(action="mod.storage.read", constraints=None, delegation=0),
                Permit(action="mod.storage.write", constraints=[b"\x01c"], delegation=2),
            ],
            expires_at=1927848000,
        )

    def test_binary_roundtrip(self):
        contract = self._contract()
        self.assertEqual(_binary_roundtrip(contract), contract)

    def test_empty_permits_binary_roundtrip(self):
        contract = Contract(issuer=HOST_ID, subject=ID_A, permits=[], expires_at=0)
        self.assertEqual(_binary_roundtrip(contract), contract)

    def test_binary_field_order(self):
        # identity(Issuer) ++ identity(Subject) ++ uint32(len) ++ (ptr-flag ++ Permit)
        # per element (Permits is []*Permit) ++ time(uint64 ExpiresAt).
        contract = self._contract()
        writer = BinaryWriter()
        writer.identity(HOST_ID)
        writer.identity(ID_A)
        writer.u32(2)
        for p in contract.permits:
            writer.u8(1)  # ptr present-flag for each []*Permit element
            p.write_to(writer)
        writer.u64(1927848000)
        self.assertEqual(contract.encode_binary(), writer.getvalue())

    def test_json_roundtrip_permits_are_records(self):
        contract = self._contract()
        back = Contract.from_value(contract.encode_json())
        self.assertEqual(back, contract)
        self.assertTrue(all(isinstance(p, Permit) for p in back.permits))


class SignedContractRecordTest(unittest.TestCase):
    def _contract(self):
        return Contract(
            issuer=HOST_ID,
            subject=ID_A,
            permits=[Permit(action="mod.storage.read", constraints=None, delegation=1)],
            expires_at=42,
        )

    def _signed(self):
        return SignedContract(
            contract=self._contract(),
            issuer_sig=Signature(scheme="asn1", data=b"\x01\x02\x03\x04"),
            subject_sig=Signature(scheme="asn1", data=b"\x05\x06\x07\x08"),
        )

    def test_present_binary_roundtrip(self):
        signed = self._signed()
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_all_nil_sigs_binary_roundtrip(self):
        # The unsigned-then-signing intermediate: contract present, both sigs nil.
        signed = SignedContract(contract=self._contract(), issuer_sig=None, subject_sig=None)
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_fully_nil_binary_layout(self):
        # All three nullable pointers nil: three 0x00 flag bytes.
        signed = SignedContract()
        self.assertEqual(signed.encode_binary(), b"\x00\x00\x00")
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_present_json_roundtrip(self):
        signed = self._signed()
        self.assertEqual(_json_roundtrip(signed), signed)

    def test_nested_json_form_decodes(self):
        # The nested {"Contract": {...}} shape decodes directly.
        signed = self._signed()
        nested = signed.encode_json()
        self.assertIn("Contract", nested)
        self.assertEqual(SignedContract.from_value(nested), signed)

    def test_flattened_json_form_decodes(self):
        # astral-go marshals SignedContract with the contract's fields FLATTENED
        # to the top level (no "Contract" key) alongside IssuerSig/SubjectSig.
        signed = self._signed()
        contract_json = signed.contract.encode_json()
        flattened = dict(contract_json)  # Issuer/Subject/Permits/ExpiresAt at top level
        flattened["IssuerSig"] = signed.issuer_sig.encode_json()
        flattened["SubjectSig"] = signed.subject_sig.encode_json()
        self.assertNotIn("Contract", flattened)
        self.assertEqual(SignedContract.from_value(flattened), signed)

    def test_flattened_json_all_nil_sigs(self):
        # Flattened form with the signatures absent (pre-signing).
        contract = self._contract()
        flattened = dict(contract.encode_json())
        self.assertEqual(
            SignedContract.from_value(flattened),
            SignedContract(contract=contract, issuer_sig=None, subject_sig=None),
        )


# ======================================================================
# Registry resolution + no double-registration
# ======================================================================
class RegistryTest(unittest.TestCase):
    def test_records_resolve_by_type(self):
        self.assertIs(record_for("mod.auth.permit"), Permit)
        self.assertIs(record_for("mod.auth.contract"), Contract)
        self.assertIs(record_for("mod.auth.signed_contract"), SignedContract)

    def test_no_double_registration(self):
        # Re-applying @register to the SAME class object is idempotent (returns the
        # class, leaves the registry pointing at it); a DIFFERENT class under a
        # taken type would raise. This pins that the three types each map to exactly
        # one record and re-registration does not clash.
        from astral.registry import register

        for obj_type, cls in (
            ("mod.auth.permit", Permit),
            ("mod.auth.contract", Contract),
            ("mod.auth.signed_contract", SignedContract),
        ):
            self.assertIs(register(obj_type)(cls), cls)
            self.assertIs(record_for(obj_type), cls)


# ======================================================================
# Ops over a binary MockNode
# ======================================================================
class AuthMockNode:
    """A minimal binary apphost server tailored to the two auth ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received
        self.contract_input = None  # the body object sent to sign_contract

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

    def _signed_reply(self):
        contract = Contract(
            issuer=HOST_ID,
            subject=ID_A,
            permits=[Permit(action="mod.storage.read", constraints=None, delegation=0)],
            expires_at=1927848000,
        )
        signed = SignedContract(
            contract=contract,
            issuer_sig=Signature(scheme="asn1", data=b"\x01\x02\x03\x04"),
            subject_sig=Signature(scheme="asn1", data=b"\x05\x06\x07\x08"),
        )
        return AstralObject("mod.auth.signed_contract", signed.encode_binary())

    def _query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        self.seen.append(rq.Query)
        ch.send(QueryAcceptedMsg())

        if op == "auth.sign_contract":
            # The client sends exactly one contract object on the body (no eos,
            # mirroring apphost.sign_app_contract); read it, then reply with the
            # signed contract.
            self.contract_input = ch.recv()
            ch.send(self._signed_reply())
            ch.send(eos())
        elif op == "auth.index":
            if "id=missing" in rq.Query:
                ch.send(AstralObject("error_message", "signed contract not found"))
            else:
                ch.send(ack())
            ch.send(eos())
        else:
            ch.send(eos())


class AuthOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = AuthMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []
        self.node.contract_input = None

    def connect(self):
        return astral.connect(self.node.endpoint)

    def test_client_exposes_auth_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.auth, Auth)
            self.assertIs(c.auth, c.auth)  # lazily cached

    def test_sign_contract_sends_body_and_decodes_signed(self):
        contract = Contract(
            issuer=HOST_ID,
            subject=ID_A,
            permits=[Permit(action="mod.storage.read", constraints=None, delegation=0)],
            expires_at=1927848000,
        )
        with self.connect() as c:
            signed = c.auth.sign_contract(contract)  # a typed Contract record on the body
        # The reply decoded to a typed SignedContract over binary (via the registry).
        self.assertIsInstance(signed, SignedContract)
        self.assertIsInstance(signed.contract, Contract)
        self.assertEqual(signed.contract.issuer, HOST_ID)
        self.assertEqual(signed.issuer_sig, Signature(scheme="asn1", data=b"\x01\x02\x03\x04"))
        self.assertEqual(signed.subject_sig, Signature(scheme="asn1", data=b"\x05\x06\x07\x08"))
        # The contract crossed the wire on the body as a mod.auth.contract object.
        self.assertIsInstance(self.node.contract_input, AstralObject)
        self.assertEqual(self.node.contract_input.type, "mod.auth.contract")
        # The body bytes decode back to the contract we sent.
        self.assertEqual(
            Contract.from_value(self.node.contract_input.value), contract
        )
        self.assertIn("auth.sign_contract", self.node.seen)

    def test_sign_contract_accepts_pre_encoded_bytes(self):
        # Backward-compatible: the untyped pass-through form (raw bytes as received
        # from an untyped op) is still accepted on the body.
        contract = Contract(issuer=HOST_ID, subject=ID_A, permits=[], expires_at=7)
        with self.connect() as c:
            signed = c.auth.sign_contract(contract.encode_binary())
        self.assertIsInstance(signed, SignedContract)
        self.assertEqual(self.node.contract_input.value, contract)

    def test_index_acks_and_pins_id(self):
        with self.connect() as c:
            self.assertIsNone(c.auth.index(CONTRACT_ID))
        self.assertIn(f"auth.index?id={CONTRACT_ID}", self.node.seen)

    def test_index_error_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.auth.index("missing")


# ======================================================================
# Record SEND path (the encode counterpart of the decode dispatch)
# ======================================================================
class RecordSendPathTest(unittest.TestCase):
    def _contract(self):
        return Contract(
            issuer=HOST_ID, subject=ID_A,
            permits=[Permit(action="mod.storage.read", constraints=None, delegation=1)],
            expires_at=42,
        )

    def test_encode_payload_encodes_a_record_over_binary(self):
        from astral.payload import encode_payload

        c = self._contract()
        self.assertEqual(encode_payload("mod.auth.contract", c), c.encode_binary())

    def test_to_json_envelope_encodes_a_record(self):
        from astral.encoding import to_json_envelope

        c = self._contract()
        env = to_json_envelope(AstralObject("mod.auth.contract", c))
        self.assertEqual(env, {"Type": "mod.auth.contract", "Object": c.encode_json()})


if __name__ == "__main__":
    unittest.main()
