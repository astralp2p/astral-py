"""Tests for the COMPOSITE field kinds of the :class:`~astral.record.Record` codec.

The scalar record codec (``record.py``) handles the flat ``mod.apphost.*`` and
``apphost.access_token`` shapes; the ``mod.auth.*`` / ``mod.crypto.*`` objects the
app-contract ops return are structured — slices of nested records, an embedded
record, byte fields, and nullable pointers — which the scalar codec cannot express.
This module exercises the four tuple-form (composite) kinds added to the codec:

* ``("array", elem_kind)`` — ``uint32`` count then each element (a ``0x01`` presence
  byte per value-kind element; ``("ptr", …)`` elements carry their own flag).
* ``("record", RecordClass)`` — a nested record inlined with no framing.
* ``("bytes", nbits)`` — a length-prefixed byte field (``bytes16`` here).
* ``("ptr", inner_kind)`` — a Go nullable pointer (present + nil).

The records below are TEST-ONLY stand-ins that mirror the real astral-go shapes
(``api/auth/contract.go``, ``api/auth/signed_contract.go``, ``api/crypto/signature.go``);
the production typed records land with ``api/auth.py``, out of scope here. Each
composite kind is round-tripped over BOTH framings: binary (``write_to`` ->
``read_from``) and JSON (``from_value(dict)`` -> ``encode_json``), matching the
transport-decision requirement that structured objects decode over binary IPC too.

Live-node / modelling uncertainties (flagged, not resolved here):

* ``astral.Bundle`` (the real ``Permit.Constraints *astral.Bundle``) is a
  heterogeneous, self-typing container (``u32`` count of ``bytes32``-framed typed
  objects — see astral-go ``astral/bundle.go``). It is modelled here as an OPAQUE
  passthrough and left off the ``Permit`` schema rather than typed; a faithful codec
  needs the whole Blueprint/registry decode path, which is out of scope.
* The ``("array", elem)`` binary layout matches astral-go's ``sliceValue`` /
  ``objectify.go`` ``elemNeedsPresenceFlag``: a ``0x01`` presence byte precedes each
  *value-kind* element, while ``("ptr", …)`` elements carry their own nil-flag instead
  (so ``[]*Permit`` = ``u32(len)`` then a ptr-flag + ``Permit`` per element). Worth a
  live-node pin on a real ``Contract`` all the same.
* The JSON form of a ``bytesN`` field is a base64 ``str`` here (Go's default
  ``[]byte`` JSON marshalling, and the ``Signature`` compact-text form). An
  int-array JSON form is the documented alternative; the choice is UNCONFIRMED
  against a live node.
* A ``mod.crypto.signature`` also has a compact TEXT form (``scheme:base64``); this
  codec only models the object (binary + object-JSON) form. Whether an op returns
  the text or the object form over JSON is UNCONFIRMED.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dataclasses import dataclass, field
from typing import Any, List, Optional

from astral.codec import BinaryReader, BinaryWriter
from astral.record import Record

# A valid 33-byte (66-hex) compressed public key, from the docs examples.
IDENTITY = "0282fee8775757cdd8fda8b220195f5b8611312cd145c5a1a3aa55df210e779b2c"
IDENTITY2 = "0344b8f8b9d5f3a2c1e0d7b6a5948372615043f2e1d0c9b8a79685f4e3d2c1b0a9"


# --- TEST-ONLY records mirroring the astral-go auth/crypto shapes -------------


@dataclass(frozen=True)
class Permit(Record):
    """Scalar stand-in for astral-go ``auth.Permit``.

    Real shape: ``Action String8``, ``Constraints *astral.Bundle``, ``Delegation
    Uint8``. ``Constraints`` is modelled as an opaque passthrough and left off the
    binary schema (see the module note); the remaining fields are plain scalars, so
    ``Permit`` exercises ``("record", Permit)`` nesting a SCALAR record.
    """

    TYPE = "mod.auth.permit"
    FIELDS = (
        ("action", "Action", "string8"),
        ("delegation", "Delegation", "uint8"),
    )

    action: str = ""
    delegation: int = 0


@dataclass(frozen=True)
class Contract(Record):
    """Stand-in for astral-go ``auth.Contract``.

    Real shape: ``Issuer *Identity``, ``Subject *Identity``, ``Permits []*Permit``,
    ``ExpiresAt Time``. Exercises ``("array", ("ptr", ("record", Permit)))`` (the real
    ``[]*Permit``) alongside identity/time scalars.
    """

    TYPE = "mod.auth.contract"
    FIELDS = (
        ("issuer", "Issuer", "identity"),
        ("subject", "Subject", "identity"),
        ("permits", "Permits", ("array", ("ptr", ("record", Permit)))),
        ("expires_at", "ExpiresAt", "time"),
    )

    issuer: str = ""
    subject: str = ""
    permits: List[Permit] = field(default_factory=list)
    expires_at: int = 0


@dataclass(frozen=True)
class Signature(Record):
    """Stand-in for astral-go ``crypto.Signature``.

    Real shape: ``Scheme String8``, ``Data Bytes16``. Exercises ``("bytes", 16)``.
    """

    TYPE = "mod.crypto.signature"
    FIELDS = (
        ("scheme", "Scheme", "string8"),
        ("data", "Data", ("bytes", 16)),
    )

    scheme: str = ""
    data: bytes = b""


@dataclass(frozen=True)
class SignedContract(Record):
    """Stand-in for astral-go ``auth.SignedContract``.

    Real shape: an embedded ``*Contract`` plus ``IssuerSig`` / ``SubjectSig``
    (``*crypto.Signature``) — all three are nullable pointers. Exercises
    ``("ptr", ("record", ...))`` for both present and nil values.
    """

    TYPE = "mod.auth.signed_contract"
    FIELDS = (
        ("contract", "Contract", ("ptr", ("record", Contract))),
        ("issuer_sig", "IssuerSig", ("ptr", ("record", Signature))),
        ("subject_sig", "SubjectSig", ("ptr", ("record", Signature))),
    )

    contract: Optional[Contract] = None
    issuer_sig: Optional[Signature] = None
    subject_sig: Optional[Signature] = None


# A record with a scalar array field, to exercise ``("array", scalar_kind)``.
@dataclass(frozen=True)
class ActionList(Record):
    TYPE = "test.action_list"
    FIELDS = (("actions", "Actions", ("array", "string8")),)
    actions: List[str] = field(default_factory=list)


def _binary_roundtrip(record: Record) -> Record:
    """Encode ``record`` to binary and decode it back through the same class."""
    writer = BinaryWriter()
    record.write_to(writer)
    return type(record).read_from(BinaryReader(writer.getvalue()))


def _json_roundtrip(record: Record) -> Record:
    """Encode ``record`` to its JSON value form and decode it back."""
    return type(record).from_value(record.encode_json())


# --- array of scalars --------------------------------------------------------


class TestArrayOfScalars(unittest.TestCase):
    def test_binary_roundtrip(self):
        rec = ActionList(actions=["read", "write", "delete"])
        self.assertEqual(_binary_roundtrip(rec), rec)

    def test_binary_layout_is_u32_count_then_presence_flagged_elements(self):
        # uint32(2) ++ (0x01 presence ++ string8) per value-kind element, matching
        # astral-go's sliceValue.
        rec = ActionList(actions=["hi", "yo"])
        expected = (
            (2).to_bytes(4, "big")
            + b"\x01" + bytes([2]) + b"hi"
            + b"\x01" + bytes([2]) + b"yo"
        )
        self.assertEqual(rec.encode_binary(), expected)

    def test_empty_array_binary(self):
        rec = ActionList(actions=[])
        self.assertEqual(rec.encode_binary(), (0).to_bytes(4, "big"))
        self.assertEqual(_binary_roundtrip(rec), rec)

    def test_json_roundtrip(self):
        rec = ActionList(actions=["read", "write"])
        self.assertEqual(rec.encode_json(), {"Actions": ["read", "write"]})
        self.assertEqual(_json_roundtrip(rec), rec)

    def test_json_missing_defaults_to_empty_list(self):
        self.assertEqual(ActionList.from_value({}), ActionList(actions=[]))


# --- array of nested records + nested-record ("record") ----------------------


class TestNestedRecord(unittest.TestCase):
    def test_binary_roundtrip(self):
        permit = Permit(action="mod.storage.read", delegation=3)
        self.assertEqual(_binary_roundtrip(permit), permit)

    def test_json_roundtrip(self):
        permit = Permit(action="mod.storage.read", delegation=3)
        self.assertEqual(
            permit.encode_json(),
            {"Action": "mod.storage.read", "Delegation": 3},
        )
        self.assertEqual(_json_roundtrip(permit), permit)


class TestArrayOfNestedRecords(unittest.TestCase):
    def _contract(self) -> Contract:
        return Contract(
            issuer=IDENTITY,
            subject=IDENTITY2,
            permits=[
                Permit(action="mod.storage.read", delegation=0),
                Permit(action="mod.storage.write", delegation=2),
            ],
            expires_at=1927848000,
        )

    def test_binary_roundtrip(self):
        contract = self._contract()
        self.assertEqual(_binary_roundtrip(contract), contract)

    def test_empty_permits_binary_roundtrip(self):
        contract = Contract(issuer=IDENTITY, subject=IDENTITY2, permits=[], expires_at=0)
        self.assertEqual(_binary_roundtrip(contract), contract)

    def test_binary_field_order(self):
        # identity(Issuer) ++ identity(Subject) ++ uint32(len) ++ (ptr-flag 0x01 ++
        # each Permit) ++ time(uint64 ExpiresAt). Permits is []*Permit, so each element
        # carries the ptr nil-flag (no synthesised presence byte for ptr elements).
        contract = self._contract()
        writer = BinaryWriter()
        writer.identity(IDENTITY)
        writer.identity(IDENTITY2)
        writer.u32(2)
        for p in contract.permits:
            writer.u8(1)  # ptr present-flag for each []*Permit element
            p.write_to(writer)
        writer.u64(1927848000)
        self.assertEqual(contract.encode_binary(), writer.getvalue())

    def test_json_roundtrip(self):
        contract = self._contract()
        value = contract.encode_json()
        self.assertEqual(
            value["Permits"],
            [
                {"Action": "mod.storage.read", "Delegation": 0},
                {"Action": "mod.storage.write", "Delegation": 2},
            ],
        )
        self.assertEqual(_json_roundtrip(contract), contract)

    def test_json_nested_records_decode_to_records(self):
        contract = Contract.from_value(self._contract().encode_json())
        self.assertTrue(all(isinstance(p, Permit) for p in contract.permits))


# --- bytesN ------------------------------------------------------------------


class TestBytesField(unittest.TestCase):
    def test_binary_roundtrip(self):
        sig = Signature(scheme="ed25519", data=bytes(range(48)))
        self.assertEqual(_binary_roundtrip(sig), sig)

    def test_binary_layout_is_u16_length_prefixed(self):
        # string8(Scheme) ++ uint16(len) ++ raw data (bytes16).
        sig = Signature(scheme="ed", data=b"\xaa\xbb\xcc")
        expected = bytes([2]) + b"ed" + (3).to_bytes(2, "big") + b"\xaa\xbb\xcc"
        self.assertEqual(sig.encode_binary(), expected)

    def test_empty_bytes_binary_roundtrip(self):
        sig = Signature(scheme="", data=b"")
        self.assertEqual(_binary_roundtrip(sig), sig)

    def test_json_is_base64_string(self):
        sig = Signature(scheme="ed25519", data=b"\x00\x01\x02\x03")
        value = sig.encode_json()
        # base64 of b"\x00\x01\x02\x03" is "AAECAw=="
        self.assertEqual(value, {"Scheme": "ed25519", "Data": "AAECAw=="})

    def test_json_roundtrip(self):
        sig = Signature(scheme="ed25519", data=bytes(range(40)))
        self.assertEqual(_json_roundtrip(sig), sig)

    def test_json_accepts_int_array_alternative(self):
        # The documented alternative JSON form (int array) is coerced on decode; we
        # emit base64, but decode tolerates either (flagged uncertainty).
        sig = Signature.from_value({"Scheme": "ed", "Data": [1, 2, 3]})
        self.assertEqual(sig.data, b"\x01\x02\x03")


# --- ptr / nullable pointer --------------------------------------------------


class TestPtrField(unittest.TestCase):
    def _full(self) -> SignedContract:
        contract = Contract(
            issuer=IDENTITY,
            subject=IDENTITY2,
            permits=[Permit(action="mod.storage.read", delegation=1)],
            expires_at=42,
        )
        return SignedContract(
            contract=contract,
            issuer_sig=Signature(scheme="ed25519", data=b"\x01\x02\x03\x04"),
            subject_sig=Signature(scheme="ed25519", data=b"\x05\x06\x07\x08"),
        )

    def test_present_binary_roundtrip(self):
        signed = self._full()
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_nil_binary_roundtrip(self):
        # All three nullable pointers nil: three 0x00 flag bytes, nothing else.
        signed = SignedContract()
        self.assertEqual(signed.encode_binary(), b"\x00\x00\x00")
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_partial_nil_binary_roundtrip(self):
        # Embedded Contract present, both signatures nil (the unsigned-then-signing
        # intermediate state astral-go's SignedContract models).
        signed = SignedContract(
            contract=Contract(issuer=IDENTITY, subject="", permits=[], expires_at=7),
            issuer_sig=None,
            subject_sig=None,
        )
        self.assertEqual(_binary_roundtrip(signed), signed)

    def test_present_ptr_binary_flag(self):
        # A present ptr writes 0x01 then the inner value; nil writes a single 0x00.
        signed = SignedContract(
            contract=None,
            issuer_sig=Signature(scheme="", data=b""),
            subject_sig=None,
        )
        # contract nil -> 0x00; issuer_sig present -> 0x01 ++ string8("") ++ u16(0);
        # subject_sig nil -> 0x00.
        expected = b"\x00" + b"\x01" + bytes([0]) + (0).to_bytes(2, "big") + b"\x00"
        self.assertEqual(signed.encode_binary(), expected)

    def test_present_json_roundtrip(self):
        signed = self._full()
        value = signed.encode_json()
        self.assertIsInstance(value["Contract"], dict)
        self.assertIsInstance(value["IssuerSig"], dict)
        self.assertEqual(_json_roundtrip(signed), signed)

    def test_nil_json_is_none(self):
        signed = SignedContract()
        self.assertEqual(
            signed.encode_json(),
            {"Contract": None, "IssuerSig": None, "SubjectSig": None},
        )
        self.assertEqual(_json_roundtrip(signed), signed)

    def test_json_missing_keys_decode_to_none(self):
        self.assertEqual(SignedContract.from_value({}), SignedContract())

    def test_ptr_of_scalar_binary_roundtrip(self):
        # ("ptr", scalar) composes too: present writes 0x01 ++ scalar, nil writes 0x00.
        @dataclass(frozen=True)
        class Optional8(Record):
            TYPE = "test.optional8"
            FIELDS = (("count", "Count", ("ptr", "uint8")),)
            count: Any = None

        present = Optional8(count=5)
        self.assertEqual(present.encode_binary(), b"\x01\x05")
        self.assertEqual(_binary_roundtrip(present), present)

        nil = Optional8(count=None)
        self.assertEqual(nil.encode_binary(), b"\x00")
        self.assertEqual(_binary_roundtrip(nil), nil)


# --- scalar path is undisturbed ----------------------------------------------


class TestScalarPathUnchanged(unittest.TestCase):
    def test_existing_scalar_record_tests_still_pass(self):
        # Import and run the byte-pinned scalar record checks in-process so a
        # regression in the composite dispatch surfaces here too.
        from astral.api.apphost import AccessToken

        token = AccessToken(identity="", token="hi", expires_at=1)
        expected = bytes.fromhex("00") + bytes([2]) + b"hi" + (1).to_bytes(8, "big")
        self.assertEqual(token.encode_binary(), expected)
        self.assertEqual(_binary_roundtrip(token), token)
        self.assertEqual(
            token.encode_json(),
            {"Identity": "", "Token": "hi", "ExpiresAt": 1},
        )


if __name__ == "__main__":
    unittest.main()
