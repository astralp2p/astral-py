"""Tests for the ``("object",)`` polymorphic kind and the ``"duration"`` scalar kind.

``("object",)`` mirrors astral-go's ``interfaceValue``: ``string8(type) ++
inner.WriteTo`` with NO length prefix (``nil == string8("") == 0x00``), so it is
SELF-NULLING and self-delimiting only via the inner type's own length. That last
point is why a MID-STRUCT ``("object",)`` field must have its inner type registered
to bound the read (there is no ``remaining()`` fallback the way the last-field
``payload.decode_payload`` path has). These tests pin the nil byte, prove a
mid-struct object leaves a FOLLOWING scalar field intact, exercise the allowed-set
rejection and the unregistered-type error, and round-trip the ``{Type, Object}``
JSON form for both a typed (registered) and an opaque (raw-bytes) inner.

``"duration"`` is astral-go's ``astral.Duration`` — a SIGNED int64 of nanoseconds
(distinct from the unsigned ``"time"`` u64) — round-tripped over binary (incl. a
negative value) and JSON.
"""

import os
import sys
import unittest
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from astral.codec import BinaryReader, BinaryWriter
from astral.errors import ProtocolError
from astral.objects import AstralObject
from astral.record import Record
from astral.registry import register


# --- THROWAWAY registered inner record ---------------------------------------


@register("test.object_kind.inner")
@dataclass(frozen=True)
class Inner(Record):
    """A tiny registered record used as an ``("object",)`` inner value."""

    TYPE = "test.object_kind.inner"
    FIELDS = (("n", "N", "uint16"),)
    n: int = 0


# --- host records carrying an ("object",) field ------------------------------


@dataclass(frozen=True)
class Wrapper(Record):
    """A record whose sole field is an ``("object",)`` (last-field case)."""

    TYPE = "test.object_kind.wrapper"
    FIELDS = (("item", "Item", ("object",)),)
    item: object = None


@dataclass(frozen=True)
class MidStruct(Record):
    """An ``("object",)`` field FOLLOWED by a scalar, to prove the bounded read.

    If the polymorphic read consumed too much/little, the trailing ``uint16`` would
    decode wrong — so this record is the guard that the inner record's own length
    bounds the object field exactly.
    """

    TYPE = "test.object_kind.mid"
    FIELDS = (
        ("item", "Item", ("object",)),
        ("tail", "Tail", "uint16"),
    )
    item: object = None
    tail: int = 0


@dataclass(frozen=True)
class Restricted(Record):
    """An ``("object", allowed_set)`` field rejecting out-of-set types."""

    TYPE = "test.object_kind.restricted"
    FIELDS = (("item", "Item", ("object", {"test.object_kind.inner"})),)
    item: object = None


def _binary_roundtrip(record):
    return type(record).read_from(BinaryReader(record.encode_binary()))


def _json_roundtrip(record):
    return type(record).from_value(record.encode_json())


class TestObjectKindNil(unittest.TestCase):
    def test_nil_writes_single_zero_byte(self):
        # nil object == string8("") == a single 0x00.
        self.assertEqual(Wrapper(item=None).encode_binary(), b"\x00")

    def test_nil_binary_roundtrip(self):
        w = Wrapper(item=None)
        self.assertEqual(_binary_roundtrip(w), w)
        self.assertIsNone(_binary_roundtrip(w).item)

    def test_nil_json_is_none(self):
        w = Wrapper(item=None)
        self.assertEqual(w.encode_json(), {"Item": None})
        self.assertEqual(_json_roundtrip(w), w)


class TestObjectKindTyped(unittest.TestCase):
    def test_binary_layout(self):
        # string8("test.object_kind.inner") ++ uint16(N) — NO length prefix.
        w = Wrapper(item=AstralObject("test.object_kind.inner", Inner(n=0x1234)))
        type_str = "test.object_kind.inner"
        expected = bytes([len(type_str)]) + type_str.encode() + (0x1234).to_bytes(2, "big")
        self.assertEqual(w.encode_binary(), expected)

    def test_binary_roundtrip(self):
        w = Wrapper(item=AstralObject("test.object_kind.inner", Inner(n=7)))
        got = _binary_roundtrip(w)
        self.assertEqual(got, w)
        self.assertIsInstance(got.item, AstralObject)
        self.assertIsInstance(got.item.value, Inner)
        self.assertEqual(got.item.value.n, 7)

    def test_json_roundtrip(self):
        w = Wrapper(item=AstralObject("test.object_kind.inner", Inner(n=9)))
        self.assertEqual(
            w.encode_json(),
            {"Item": {"Type": "test.object_kind.inner", "Object": {"N": 9}}},
        )
        got = _json_roundtrip(w)
        self.assertEqual(got, w)
        self.assertIsInstance(got.item.value, Inner)


class TestObjectKindMidStruct(unittest.TestCase):
    """The bounded-read guard: an object field followed by a scalar."""

    def test_binary_roundtrip_leaves_tail_intact(self):
        rec = MidStruct(
            item=AstralObject("test.object_kind.inner", Inner(n=0xABCD)),
            tail=0xBEEF,
        )
        got = _binary_roundtrip(rec)
        self.assertEqual(got, rec)
        self.assertEqual(got.item.value.n, 0xABCD)
        self.assertEqual(got.tail, 0xBEEF)  # the trailing field survived

    def test_binary_layout_is_object_then_tail(self):
        rec = MidStruct(
            item=AstralObject("test.object_kind.inner", Inner(n=1)),
            tail=2,
        )
        type_str = "test.object_kind.inner"
        expected = (
            bytes([len(type_str)]) + type_str.encode()
            + (1).to_bytes(2, "big")  # inner Inner.N
            + (2).to_bytes(2, "big")  # tail
        )
        self.assertEqual(rec.encode_binary(), expected)

    def test_nil_object_then_tail(self):
        rec = MidStruct(item=None, tail=0x0102)
        # 0x00 (nil object) ++ uint16(tail).
        self.assertEqual(rec.encode_binary(), b"\x00" + (0x0102).to_bytes(2, "big"))
        self.assertEqual(_binary_roundtrip(rec), rec)


class TestObjectKindOpaqueBytes(unittest.TestCase):
    """An inner value that is raw bytes (unregistered / opaque) round-trips over JSON."""

    def test_json_opaque_roundtrip(self):
        # An unregistered inner type keeps its opaque JSON value through the adapter.
        w = Wrapper(item=AstralObject("test.unregistered", {"anything": 1}))
        self.assertEqual(
            w.encode_json(),
            {"Item": {"Type": "test.unregistered", "Object": {"anything": 1}}},
        )
        got = _json_roundtrip(w)
        self.assertEqual(got.item.type, "test.unregistered")
        self.assertEqual(got.item.value, {"anything": 1})

    def test_binary_write_raw_bytes_inner(self):
        # A raw-bytes inner writes string8(type) ++ the raw bytes verbatim.
        w = Wrapper(item=AstralObject("test.raw", b"\xde\xad\xbe\xef"))
        expected = bytes([len("test.raw")]) + b"test.raw" + b"\xde\xad\xbe\xef"
        self.assertEqual(w.encode_binary(), expected)


class TestObjectKindAllowedSet(unittest.TestCase):
    def test_in_set_ok(self):
        rec = Restricted(item=AstralObject("test.object_kind.inner", Inner(n=1)))
        self.assertEqual(_binary_roundtrip(rec), rec)

    def test_out_of_set_write_rejected(self):
        rec = Restricted(item=AstralObject("test.other", b""))
        with self.assertRaises(ProtocolError):
            rec.encode_binary()


class TestObjectKindUnregistered(unittest.TestCase):
    def test_unregistered_type_read_raises(self):
        # Hand-craft: string8("test.never_registered") then some bytes. A mid-struct
        # object with an unregistered inner cannot be bounded -> ProtocolError.
        blob = BinaryWriter().string8("test.never_registered").raw(b"\x00\x01").getvalue()
        with self.assertRaises(ProtocolError):
            Wrapper.read_from(BinaryReader(blob))


class TestObjectKindNotAstralObject(unittest.TestCase):
    def test_non_astralobject_value_rejected(self):
        with self.assertRaises(ProtocolError):
            Wrapper(item="not-an-astral-object").encode_binary()


# --- duration scalar ---------------------------------------------------------


@dataclass(frozen=True)
class Timed(Record):
    TYPE = "test.duration_kind"
    FIELDS = (("d", "D", "duration"),)
    d: int = 0


class TestDurationKind(unittest.TestCase):
    def test_binary_layout_is_signed_i64(self):
        self.assertEqual(Timed(d=1).encode_binary(), (1).to_bytes(8, "big"))

    def test_positive_binary_roundtrip(self):
        rec = Timed(d=1_500_000_000)
        self.assertEqual(_binary_roundtrip(rec), rec)

    def test_negative_binary_roundtrip(self):
        # SIGNED: a negative duration must round-trip (unlike the unsigned "time").
        rec = Timed(d=-42)
        self.assertEqual(rec.encode_binary(), (-42).to_bytes(8, "big", signed=True))
        self.assertEqual(_binary_roundtrip(rec), rec)

    def test_json_roundtrip(self):
        rec = Timed(d=-123456789)
        self.assertEqual(rec.encode_json(), {"D": -123456789})
        self.assertEqual(_json_roundtrip(rec), rec)

    def test_json_missing_defaults_to_zero(self):
        self.assertEqual(Timed.from_value({}), Timed(d=0))


if __name__ == "__main__":
    unittest.main()
