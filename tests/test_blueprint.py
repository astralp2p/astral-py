"""Tier A: blueprints as self-hosted records, and records built from the wire.

Three jobs, in this order:

1. Register step 5's codecs with the vector harness, so every `astral.blueprint*`
   vector in the corpus starts executing.
2. Pin the two blueprint entries of the design's section 7.1 must-pass table, and
   every validation rule.
3. Prove the gate: a runtime record encodes and decodes byte-identically to an
   equivalent declared record, including nested references to declared types.
"""

from __future__ import annotations

import unittest
from typing import Any

from astral import blueprint as B, codec, object as objects, primitives as P
from astral.codec import canonical_bytes, jsoncodec
from astral.codec.binary import ObjectReader, payload_bytes
from astral.errors import CycleDetected, DepthExceeded, ParseError, SchemaError
from astral.objectid import object_id, object_id_of_bytes
from astral.record import alias, record, wire
from astral.registry import Blueprints, default_blueprints
from astral.spec import (
    MAX_ARRAY_LENGTH,
    MAX_DEPTH,
    MAX_NAME_LEN,
    Any as AnySpec,
    Array,
    Map,
    Primitive,
    Ptr,
    Ref,
    Slice,
    Spec,
)
from vectors import Codec, register_codec, register_vector_skip, vector_by_id

# Every test-only schema lives in a child of the process registry: a child cannot
# shadow a parent, and the process registry stays exactly as the SDK ships it.
_R = Blueprints(default_blueprints())


# --- the declared reference record -----------------------------------------


@record("t.every", registry=_R)
class Every:
    """One field per spec kind, so one comparison covers the whole walker."""

    u: int = wire("U", Primitive("uint32"))
    s: str = wire("S", Primitive("string16"))
    r: int = wire("R", Ref("uint8"))
    sl: list[int] = wire("Sl", Slice("uint32"))
    ar: list[int] = wire("Ar", Array("uint16", 2))
    mp: dict[str, int] = wire("Mp", Map("string16", "uint8"))
    pt: str | None = wire("Pt", Ptr("string8"))
    an: Any = wire("An", AnySpec())


@record("t.hetero", registry=_R)
class Hetero:
    """The three heterogeneous slots, where every element carries its own tag."""

    items: list[Any] = wire("Items", Slice(""))
    by_key: dict[int, Any] = wire("ByKey", Map("uint8", ""))
    one: Any = wire("One", AnySpec())


@record("t.holder", registry=_R)
class Holder:
    """Every way one record reaches another: inline, optional, counted."""

    one: Every = wire("One", Ref("t.every"))
    maybe: Every | None = wire("Maybe", Ptr("t.every"))
    many: list[Every] = wire("Many", Slice("t.every"))


Mode = alias("t.mode", "uint8", registry=_R)


@record("t.custom", registry=_R)
class Custom:
    """A hand-written payload codec: `FIELDS` no longer describes the bytes."""

    n: int = wire("N", Primitive("uint8"))

    def write_payload(self, w: Any) -> None:
        w.uint16(self.n)

    @classmethod
    def read_payload(cls, r: Any) -> "Custom":
        return cls(n=r.uint16())


_EVERY_FIELDS: tuple[tuple[str, Spec], ...] = (
    ("U", Primitive("uint32")),
    ("S", Primitive("string16")),
    ("R", Ref("uint8")),
    ("Sl", Slice("uint32")),
    ("Ar", Array("uint16", 2)),
    ("Mp", Map("string16", "uint8")),
    ("Pt", Ptr("string8")),
    ("An", AnySpec()),
)


def _every_value() -> Every:
    return Every(
        u=0xDEADBEEF,
        s="hi",
        r=7,
        sl=[1, 2],
        ar=[1, 2],
        mp={"ab": 2, "hi": 1},
        pt="x",
        an=P.Uint8(21),
    )


def _runtime_every(type_name: str = "t.every.runtime") -> B.Blueprint:
    return B.blueprint(
        type_name,
        *[B.field(name, spec) for name, spec in _EVERY_FIELDS],
        registry=_R,
    )


def _fill(rr: B.RuntimeRecord, value: Every) -> B.RuntimeRecord:
    for name, attr in zip(
        ("U", "S", "R", "Sl", "Ar", "Mp", "Pt", "An"),
        ("u", "s", "r", "sl", "ar", "mp", "pt", "an"),
    ):
        rr.set(name, getattr(value, attr))
    return rr


# --- harness registration --------------------------------------------------


def _blueprint_codec(cls: type, **kw: Any) -> Codec:
    def decode(payload: bytes) -> Any:
        reader = ObjectReader(payload)
        value = cls.read_payload(reader)  # type: ignore[attr-defined]
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    return Codec(decode=decode, encode=payload_bytes, **kw)


def _json_codec(cls: type) -> Codec:
    name = cls.ASTRAL_TYPE  # type: ignore[attr-defined]
    return _blueprint_codec(
        cls,
        to_json=jsoncodec.marshal,
        from_json=lambda data, _n=name: jsoncodec.unmarshal(_n, data),
    )


# The two corpus vectors whose JSON renders a polymorphic `Field.Spec` slot
# inline, which is what Go's `encoding/json` does to an interface field of a
# compiled struct. The SDK emits the `{Type, Object}` envelope, which is what
# astral-go's own codec does to the same slot -- and the only spelling either
# side can read back, because `ref_spec`, `slice_spec` and `ptr_spec` all render
# inline as `{"Type": …}` and astral-go's `Objectify(&bp).UnmarshalJSON` refuses
# its own `json.Marshal` output with `blueprint not found: `. Keyed by vector, so
# `blueprint.alias` -- which has no polymorphic slot at all -- is measured.
_SPEC_SLOT_GAP = (
    "gap.struct_json.polymorphic_field: the vector's JSON came out of Go's "
    "encoding/json, which renders the polymorphic Field.Spec slot inline. The "
    "SDK emits astral-go's own codec form, the {Type,Object} envelope, which is "
    "the only invertible one; see "
    "BlueprintJsonTests.test_the_inline_spec_form_is_not_invertible."
)


def _register_step5_codecs() -> None:
    for cls in (
        B.Blueprint,
        B.Field,
        B.PrimitiveSpec,
        B.RefSpec,
        B.SliceSpec,
        B.ArraySpec,
        B.MapSpec,
        B.PtrSpec,
        B.ObjectSpec,
    ):
        register_codec(cls.ASTRAL_TYPE, _json_codec(cls))
    for vector_id in ("blueprint.struct", "blueprint.field"):
        for aspect in ("json_emit", "json_parse"):
            register_vector_skip(vector_id, aspect, _SPEC_SLOT_GAP)


# --- the must-pass layouts -------------------------------------------------


class LayoutTests(unittest.TestCase):
    """The design's section 7.1 blueprint rows, byte for byte."""

    maxDiff = None

    def test_struct_kind_layout(self) -> None:
        bp = B.blueprint(
            "t.x",
            B.field("a", Primitive("uint32")),
            B.field("b", AnySpec()),
        )
        self.assertEqual(
            payload_bytes(bp),
            b"\x00\x03t.x"
            b"\x00\x00\x00\x02"
            b"\x01" b"\x00\x01a" b"\x1fastral.blueprint.primitive_spec" b"\x00\x06uint32"
            b"\x01" b"\x00\x01b" b"\x1castral.blueprint.object_spec"
            b"\x00\x00",
        )

    def test_alias_kind_layout(self) -> None:
        bp = B.blueprint_alias("t.mode", "uint8")
        self.assertEqual(
            payload_bytes(bp), b"\x00\x06t.mode" b"\x00\x00\x00\x00" b"\x00\x05uint8"
        )

    def test_field_order_changes_the_object_id(self) -> None:
        first = B.blueprint(
            "t.x", B.field("a", Primitive("uint8")), B.field("b", Primitive("uint16"))
        )
        second = B.blueprint(
            "t.x", B.field("b", Primitive("uint16")), B.field("a", Primitive("uint8"))
        )
        self.assertNotEqual(object_id(first), object_id(second))

    def test_every_spec_carrier_round_trips_through_a_field(self) -> None:
        for spec in (
            Primitive("uint32"),
            Ref("uint8"),
            Slice("uint32"),
            Slice(""),
            Array("uint16", 4),
            Array("", 0),
            Map("string16", "identity"),
            Map("uint64", ""),
            Ptr("identity"),
            AnySpec(),
        ):
            with self.subTest(spec=spec):
                entry = B.field("F", spec)
                payload = payload_bytes(entry)
                back = B.Field.read_payload(ObjectReader(payload))
                self.assertEqual(B.spec_of(back.spec), spec)
                self.assertEqual(payload_bytes(back).hex(), payload.hex())

    def test_the_spec_slot_is_polymorphic(self) -> None:
        entry = B.field("X", Primitive("uint32"))
        payload = payload_bytes(entry)
        self.assertEqual(payload[:3].hex(), "000158")
        self.assertEqual(payload[3], len("astral.blueprint.primitive_spec"))

    def test_object_spec_has_an_empty_payload(self) -> None:
        self.assertEqual(payload_bytes(B.ObjectSpec()), b"")


class SelfHostingTests(unittest.TestCase):
    """The schema system describes itself with no special case."""

    def test_blueprint_describes_itself(self) -> None:
        derived = B.of(B.Blueprint)
        self.assertEqual(derived.type, "astral.blueprint")
        self.assertEqual(
            [f.name for f in derived.fields], ["Type", "Fields", "Underlying"]
        )
        self.assertEqual(derived.blueprint_specs(), tuple(f.spec for f in B.Blueprint.FIELDS))

    def test_field_describes_itself(self) -> None:
        derived = B.of(B.Field)
        self.assertEqual(
            derived.blueprint_specs(), (Primitive("string16"), AnySpec())
        )

    def test_a_derived_blueprint_round_trips_on_the_wire(self) -> None:
        for cls in (B.Blueprint, B.Field, B.ArraySpec, B.MapSpec, B.ObjectSpec, Every, Holder):
            with self.subTest(cls.ASTRAL_TYPE):
                derived = B.of(cls)
                payload = payload_bytes(derived)
                back = B.Blueprint.read_payload(ObjectReader(payload))
                self.assertEqual(back, derived)
                self.assertEqual(payload_bytes(back).hex(), payload.hex())

    def test_every_declared_type_the_sdk_ships_is_describable(self) -> None:
        registry = default_blueprints()
        described = []
        for name in registry.ordered():
            entry = registry.find(name)
            if not isinstance(entry, type) or not getattr(entry, "DERIVABLE", False):
                continue
            with self.subTest(name):
                derived = B.of(entry)
                derived.validate()
                self.assertEqual(
                    B.Blueprint.read_payload(ObjectReader(payload_bytes(derived))), derived
                )
                described.append(name)
        # The nine self-hosting types plus the two records object.py declares.
        self.assertIn("astral.blueprint", described)
        self.assertIn("query", described)

    def test_an_alias_class_derives_an_alias_kind_blueprint(self) -> None:
        derived = B.of(Mode)
        self.assertTrue(derived.is_alias)
        self.assertEqual(derived.underlying, "uint8")
        self.assertEqual(derived.fields, [])

    def test_a_custom_codec_has_no_derivable_blueprint(self) -> None:
        with self.assertRaises(SchemaError):
            B.of(Custom)

    def test_a_primitive_has_no_blueprint(self) -> None:
        for cls in (P.Uint8, P.String16, P.Bytes32):
            with self.subTest(cls.ASTRAL_TYPE), self.assertRaises(SchemaError):
                B.of(cls)

    def test_an_untyped_object_has_no_blueprint(self) -> None:
        with self.assertRaises(SchemaError):
            B.of(objects.Blob)

    def test_a_hand_written_object_has_no_blueprint(self) -> None:
        # Bundle's payload is a count plus framed elements, which no Spec
        # describes; an empty struct blueprint would be a lie.
        with self.assertRaises(SchemaError):
            B.of(objects.Bundle)

    def test_conversion_is_total_in_both_directions(self) -> None:
        for spec in (
            Primitive("bool"),
            Ref("t.every"),
            Slice("uint8"),
            Array("uint8", MAX_ARRAY_LENGTH),
            Map("uint8", "uint8"),
            Ptr("uint8"),
            AnySpec(),
        ):
            with self.subTest(spec=spec):
                self.assertEqual(B.spec_of(B.carrier_of(spec)), spec)

    def test_an_unknown_carrier_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            B.spec_of(P.Uint8(1))
        with self.assertRaises(SchemaError):
            B.spec_of(None)
        with self.assertRaises(SchemaError):
            B.carrier_of("uint8")  # type: ignore[arg-type]


class ValidationTests(unittest.TestCase):
    """`validateBlueprint`, ported rule for rule."""

    def test_an_empty_type_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            B.blueprint("").validate()

    def test_a_non_ascii_type_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            B.blueprint("t.é").validate()

    def test_an_oversized_name_is_rejected(self) -> None:
        B.blueprint("t" * MAX_NAME_LEN).validate()
        with self.assertRaises(SchemaError):
            B.blueprint("t" * (MAX_NAME_LEN + 1)).validate()
        with self.assertRaises(SchemaError):
            B.blueprint(
                "t.x", B.field("f" * (MAX_NAME_LEN + 1), Primitive("uint8"))
            ).validate()

    def test_an_empty_struct_is_not_an_alias(self) -> None:
        bp = B.blueprint("t.empty")
        bp.validate()
        self.assertFalse(bp.is_alias)
        self.assertEqual(payload_bytes(bp), b"\x00\x07t.empty\x00\x00\x00\x00\x00\x00")

    def test_both_kinds_at_once_is_rejected(self) -> None:
        bp = B.blueprint("t.x", B.field("a", Primitive("uint8")))
        bp.underlying = "uint8"
        with self.assertRaises(SchemaError):
            bp.validate()

    def test_an_alias_underlying_must_be_allowlisted(self) -> None:
        B.blueprint_alias("t.mode", "uint8").validate()
        for bad in ("int64", "float32", "size", "error_message", "nope"):
            with self.subTest(bad), self.assertRaises(SchemaError):
                B.blueprint_alias("t.mode", bad).validate()

    def test_an_empty_field_name_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            B.blueprint("t.x", B.field("", Primitive("uint8"))).validate()

    def test_field_names_differing_only_in_case_are_rejected(self) -> None:
        bp = B.blueprint(
            "t.x", B.field("Foo", Primitive("uint8")), B.field("FOO", Primitive("uint8"))
        )
        with self.assertRaises(SchemaError):
            bp.validate()

    def test_a_self_referential_ref_or_ptr_is_rejected(self) -> None:
        for spec in (Ref("t.x"), Ptr("t.x")):
            with self.subTest(spec=spec), self.assertRaises(CycleDetected):
                B.blueprint("t.x", B.field("Self", spec)).validate()

    def test_a_self_referential_container_is_allowed(self) -> None:
        # Bounded by the wire count, so it terminates: astral-go allows it too.
        for spec in (Slice("t.x"), Array("t.x", 2), Map("uint8", "t.x")):
            with self.subTest(spec=spec):
                B.blueprint("t.x", B.field("Self", spec)).validate()

    def test_an_off_allowlist_primitive_is_rejected(self) -> None:
        # A carrier holds a `string16` and validates nothing on its own, exactly
        # as astral-go's PrimitiveSpec does; the allowlist is enforced where the
        # carrier becomes a Spec.
        for bad in ("int64", "float64", "size", "object_type"):
            with self.subTest(bad):
                carrier = B.PrimitiveSpec(primitive_type=bad)
                with self.assertRaises(SchemaError):
                    B.blueprint("t.x", B.Field(name="F", spec=carrier)).validate()
                with self.assertRaises(SchemaError):
                    B.spec_of(carrier)
                with self.assertRaises(SchemaError):
                    Primitive(bad)

    def test_an_off_allowlist_primitive_from_the_wire_is_rejected(self) -> None:
        payload = payload_bytes(
            B.blueprint("t.x", B.field("F", Primitive("uint8")))
        ).replace(b"\x00\x05uint8", b"\x00\x05int64")
        bp = B.Blueprint.read_payload(ObjectReader(payload))
        with self.assertRaises(SchemaError):
            bp.validate()

    def test_an_absent_spec_is_rejected(self) -> None:
        bp = B.blueprint("t.x", B.Field(name="F"))
        self.assertIsNone(bp.fields[0].spec)
        with self.assertRaises(SchemaError):
            bp.validate()

    def test_an_oversized_array_length_is_rejected(self) -> None:
        bp = B.blueprint("t.x", B.field("F", Array("uint8", MAX_ARRAY_LENGTH)))
        bp.validate()
        bp.fields[0].spec.length = MAX_ARRAY_LENGTH + 1
        with self.assertRaises(SchemaError):
            bp.validate()

    def test_an_off_allowlist_map_key_is_rejected(self) -> None:
        bp = B.blueprint("t.x", B.field("F", Map("uint16", "")))
        bp.validate()
        for bad in ("string8", "int64", "identity", ""):
            with self.subTest(bad):
                bp.fields[0].spec.key_type = bad
                with self.assertRaises(SchemaError):
                    bp.validate()

    def test_an_empty_ref_or_ptr_target_is_rejected(self) -> None:
        for carrier in (B.RefSpec(type=""), B.PtrSpec(type="")):
            with self.subTest(type(carrier).__name__), self.assertRaises(SchemaError):
                B.blueprint("t.x", B.Field(name="F", spec=carrier)).validate()

    def test_a_non_field_in_the_fields_list_is_rejected(self) -> None:
        bp = B.blueprint("t.x")
        bp.fields.append("Nope")  # type: ignore[arg-type]
        with self.assertRaises(SchemaError):
            bp.validate()


class RegistryTests(unittest.TestCase):
    """A blueprint as a registry entry, through the RuntimeBlueprint protocol."""

    def setUp(self) -> None:
        self.registry = Blueprints(_R)

    def test_registration_returns_the_object_id_of_the_canonical_form(self) -> None:
        bp = B.blueprint("t.reg.point", B.field("X", Primitive("uint32")))
        self.assertEqual(self.registry.register_blueprint(bp), object_id(bp))
        self.assertTrue(self.registry.has("t.reg.point"))
        self.assertIsNotNone(self.registry.blueprint("t.reg.point"))

    def test_the_stored_blueprint_is_a_clone(self) -> None:
        bp = B.blueprint("t.reg.clone", B.field("X", Primitive("uint32")))
        self.registry.register_blueprint(bp)
        bp.fields[0].name = "Y"
        stored = self.registry.blueprint("t.reg.clone")
        assert stored is not None
        self.assertEqual([f.name for f in stored.fields], ["X"])  # type: ignore[attr-defined]

    def test_a_reference_must_already_be_registered(self) -> None:
        with self.assertRaises(SchemaError):
            self.registry.register_blueprint(
                B.blueprint("t.reg.dangling", B.field("R", Ref("t.reg.absent")))
            )

    def test_registration_rejects_an_invalid_blueprint(self) -> None:
        with self.assertRaises(SchemaError):
            self.registry.register_blueprint(B.blueprint(""))

    def test_a_registered_name_constructs_a_runtime_record(self) -> None:
        self.registry.register_blueprint(_runtime_every("t.reg.every").bound_to(self.registry))
        value = self.registry.new("t.reg.every")
        self.assertIsInstance(value, B.RuntimeRecord)
        self.assertEqual(value.ASTRAL_TYPE, "t.reg.every")
        self.assertEqual(value.get("U"), 0)
        self.assertEqual(value.get("Sl"), [])
        self.assertEqual(value.get("Ar"), [0, 0])
        self.assertIsNone(value.get("Pt"))

    def test_ordering_places_a_reference_before_its_user(self) -> None:
        # Alphabetically t.ord.a precedes t.ord.b; the topological order does not,
        # because a blueprint must follow every name it references.
        self.registry.register_blueprint(B.blueprint("t.ord.b", B.field("N", Primitive("uint8"))))
        self.registry.register_blueprint(B.blueprint("t.ord.a", B.field("B", Ref("t.ord.b"))))
        self.registry.register_blueprint(B.blueprint_alias("t.ord.mode", "uint8"))
        order = [name for name in self.registry.ordered() if name.startswith("t.ord.")]
        self.assertEqual(order, ["t.ord.mode", "t.ord.b", "t.ord.a"])

    def test_a_two_step_cycle_is_rejected_at_registration(self) -> None:
        # Closure alone cannot catch this: the declared record referencing a name
        # that does not exist yet is legal, and the cycle closes only when the
        # blueprint completing it arrives.
        @record("t.cyc.declared", registry=self.registry)
        class Declared:
            other: Any = wire("Other", Ref("t.cyc.runtime"))

        with self.assertRaises(CycleDetected):
            self.registry.register_blueprint(
                B.blueprint("t.cyc.runtime", B.field("Back", Ref("t.cyc.declared")))
            )
        self.assertFalse(self.registry.has("t.cyc.runtime"))

    def test_a_name_cannot_shadow_a_parent(self) -> None:
        with self.assertRaises(SchemaError):
            self.registry.register_blueprint(
                B.blueprint("t.every", B.field("X", Primitive("uint8")))
            )


class DepthTests(unittest.TestCase):
    """astral-go bug G-22: the depth guard must wrap construction, not only I/O."""

    def setUp(self) -> None:
        self.registry = Blueprints(_R)

    def _install_mutual_pair(self, spec: Any) -> None:
        """Bypass `register_blueprint`, exactly as astral-go's test does.

        Registration rejects the pair outright, so reaching the construction
        guard means writing straight into the registry's own map.
        """
        first = B.blueprint("t.dep.x", B.field("Y", spec("t.dep.y")), registry=self.registry)
        second = B.blueprint("t.dep.y", B.field("X", spec("t.dep.x")), registry=self.registry)
        self.registry._entries["t.dep.x"] = first
        self.registry._entries["t.dep.y"] = second

    def test_a_mutual_ref_pair_exceeds_depth_at_construction(self) -> None:
        self._install_mutual_pair(Ref)
        with self.assertRaises(DepthExceeded):
            self.registry.new("t.dep.x")

    def test_a_mutual_ptr_pair_constructs_because_a_ptr_zero_is_absent(self) -> None:
        # A Ptr's zero is None, so construction terminates on the first frame;
        # only a decode with presence bytes set can recurse.
        self._install_mutual_pair(Ptr)
        value = self.registry.new("t.dep.x")
        self.assertIsNone(value.get("Y"))

    def test_a_mutual_ptr_pair_exceeds_depth_at_decode(self) -> None:
        self._install_mutual_pair(Ptr)
        reader = ObjectReader(b"\x01" * (MAX_DEPTH + 8), registry=self.registry)
        with self.assertRaises(DepthExceeded):
            self.registry.new("t.dep.x").read_payload(reader)

    def test_a_deep_chain_of_present_pointers_is_capped_on_encode(self) -> None:
        self._install_mutual_pair(Ptr)
        value = self.registry.new("t.dep.x")
        current = value
        for _ in range(MAX_DEPTH + 2):
            nxt = self.registry.new("t.dep.y" if current.ASTRAL_TYPE == "t.dep.x" else "t.dep.x")
            current.set("Y" if current.ASTRAL_TYPE == "t.dep.x" else "X", nxt)
            current = nxt
        with self.assertRaises(DepthExceeded):
            payload_bytes(value)


class RuntimeRecordTests(unittest.TestCase):
    """The gate: a runtime record and a declared record agree on every byte."""

    maxDiff = None

    def setUp(self) -> None:
        self.registry = Blueprints(_R)
        self.registry.register_blueprint(_runtime_every().bound_to(self.registry))
        self.declared = _every_value()
        self.payload = payload_bytes(self.declared)

    def _runtime(self) -> B.RuntimeRecord:
        value = self.registry.new("t.every.runtime")
        assert isinstance(value, B.RuntimeRecord)
        return value

    def test_a_runtime_record_encodes_the_declared_bytes(self) -> None:
        value = _fill(self._runtime(), self.declared)
        self.assertEqual(payload_bytes(value).hex(), self.payload.hex())

    def test_a_runtime_record_decodes_the_declared_bytes(self) -> None:
        value = self._runtime().read_payload(ObjectReader(self.payload, registry=self.registry))
        self.assertEqual(value.get("U"), 0xDEADBEEF)
        self.assertEqual(value.get("S"), "hi")
        self.assertEqual(value.get("R"), 7)
        self.assertEqual(value.get("Sl"), [1, 2])
        self.assertEqual(value.get("Ar"), [1, 2])
        self.assertEqual(value.get("Mp"), {"ab": 2, "hi": 1})
        self.assertEqual(value.get("Pt"), "x")
        self.assertEqual(value.get("An"), P.Uint8(21))
        self.assertEqual(payload_bytes(value).hex(), self.payload.hex())

    def test_the_field_walker_reaches_a_runtime_value_by_attribute(self) -> None:
        value = _fill(self._runtime(), self.declared)
        self.assertEqual(value.U, 0xDEADBEEF)
        self.assertEqual(value.Mp, {"ab": 2, "hi": 1})
        with self.assertRaises(AttributeError):
            value.Nope

    def test_a_runtime_record_decodes_through_a_polymorphic_field(self) -> None:
        framed = b"\x0ft.every.runtime" + self.payload
        holder = objects.ErrUnexpectedObject.read_payload(
            ObjectReader(framed, registry=self.registry)
        )
        self.assertEqual(holder.object.ASTRAL_TYPE, "t.every.runtime")
        self.assertEqual(payload_bytes(holder), framed)

    def test_a_runtime_record_reaches_a_declared_type_by_reference(self) -> None:
        self.registry.register_blueprint(
            B.blueprint(
                "t.holder.runtime",
                B.field("One", Ref("t.every")),
                B.field("Maybe", Ptr("t.every")),
                B.field("Many", Slice("t.every")),
                registry=self.registry,
            ).bound_to(self.registry)
        )
        declared = Holder(one=self.declared, maybe=self.declared, many=[self.declared])
        payload = payload_bytes(declared)

        value = self.registry.new("t.holder.runtime")
        value.set("One", self.declared)
        value.set("Maybe", self.declared)
        value.set("Many", [self.declared])
        self.assertEqual(payload_bytes(value).hex(), payload.hex())

        back = self.registry.new("t.holder.runtime").read_payload(
            ObjectReader(payload, registry=self.registry)
        )
        self.assertEqual(back.get("One"), self.declared)
        self.assertEqual(back.get("Maybe"), self.declared)
        self.assertEqual(back.get("Many"), [self.declared])

    def test_a_derived_blueprint_reproduces_the_declared_schema(self) -> None:
        # The whole point of `of`: what a peer receives describes exactly the
        # bytes the declaring class writes.
        derived = B.of(Every)
        derived.type = "t.every.derived"
        self.registry.register_blueprint(derived.bound_to(self.registry))
        value = _fill(self.registry.new("t.every.derived"), self.declared)
        self.assertEqual(payload_bytes(value).hex(), self.payload.hex())

    def test_a_runtime_record_carries_the_heterogeneous_slots(self) -> None:
        derived = B.of(Hetero)
        derived.type = "t.hetero.runtime"
        self.registry.register_blueprint(derived.bound_to(self.registry))
        declared = Hetero(
            items=[P.Uint8(7), P.String8("hi")],
            by_key={1: P.Uint8(2), 0: None},
            one=None,
        )
        payload = payload_bytes(declared)

        value = self.registry.new("t.hetero.runtime")
        value.set("Items", [P.Uint8(7), P.String8("hi")])
        value.set("ByKey", {1: P.Uint8(2), 0: None})
        self.assertEqual(payload_bytes(value).hex(), payload.hex())

        back = self.registry.new("t.hetero.runtime").read_payload(
            ObjectReader(payload, registry=self.registry)
        )
        self.assertEqual(back.get("Items"), [P.Uint8(7), P.String8("hi")])
        self.assertEqual(back.get("ByKey"), {0: None, 1: P.Uint8(2)})
        self.assertIsNone(back.get("One"))

    def test_a_runtime_record_nests_another_runtime_record(self) -> None:
        self.registry.register_blueprint(
            B.blueprint(
                "t.nest.runtime",
                B.field("Inner", Ref("t.every.runtime")),
                B.field("Slot", Ptr("t.every.runtime")),
                registry=self.registry,
            ).bound_to(self.registry)
        )
        outer = self.registry.new("t.nest.runtime")
        self.assertIsInstance(outer.get("Inner"), B.RuntimeRecord)
        outer.set("Inner", _fill(self._runtime(), self.declared))
        outer.set("Slot", _fill(self._runtime(), self.declared))
        payload = payload_bytes(outer)
        self.assertEqual(payload.hex(), (self.payload + b"\x01" + self.payload).hex())

        back = self.registry.new("t.nest.runtime").read_payload(
            ObjectReader(payload, registry=self.registry)
        )
        self.assertEqual(payload_bytes(back).hex(), payload.hex())

    def test_a_container_of_runtime_records_needs_no_slow_path(self) -> None:
        # astral-go needs a special decode path here: its reflective codec
        # allocates an *unbound* RuntimeObject that silently reads nothing. A
        # schema-driven decoder constructs each element from its Spec, so the
        # hazard has no counterpart.
        self.registry.register_blueprint(
            B.blueprint(
                "t.container.runtime",
                B.field("Many", Slice("t.every.runtime")),
                B.field("Two", Array("t.every.runtime", 2)),
                B.field("ByKey", Map("string16", "t.every.runtime")),
                registry=self.registry,
            ).bound_to(self.registry)
        )
        one = _fill(self._runtime(), self.declared)
        value = self.registry.new("t.container.runtime")
        value.set("Many", [one, one])
        value.set("Two", [one, one])
        value.set("ByKey", {"a": one})
        payload = payload_bytes(value)

        back = self.registry.new("t.container.runtime").read_payload(
            ObjectReader(payload, registry=self.registry)
        )
        self.assertEqual(len(back.get("Many")), 2)
        self.assertEqual(back.get("Many"), [one, one])
        self.assertEqual(back.get("Two"), [one, one])
        self.assertEqual(back.get("ByKey"), {"a": one})
        self.assertEqual(payload_bytes(back).hex(), payload.hex())

    def test_an_alias_kind_runtime_record_is_the_underlying_bytes(self) -> None:
        self.registry.register_blueprint(B.blueprint_alias("t.runtime.mode", "uint8"))
        value = self.registry.new("t.runtime.mode")
        assert isinstance(value, B.RuntimeRecord)
        self.assertEqual(value.ASTRAL_TYPE, "t.runtime.mode")
        self.assertEqual(value.value, 0)
        value.value = 21
        self.assertEqual(payload_bytes(value), b"\x15")
        back = self.registry.new("t.runtime.mode").read_payload(ObjectReader(b"\x07"))
        self.assertEqual(back.value, 7)
        self.assertEqual(back.FIELDS, ())

    def test_an_alias_kind_matches_the_declared_alias(self) -> None:
        self.registry.register_blueprint(B.blueprint_alias("t.runtime.mode", "uint8"))
        runtime = self.registry.new("t.runtime.mode")
        runtime.value = 21
        self.assertEqual(payload_bytes(runtime), payload_bytes(Mode(21)))

    def test_setting_an_unknown_field_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            self._runtime().set("Nope", 1)
        self.assertIsNone(self._runtime().get("Nope"))

    def test_a_field_name_that_shadows_the_carrier_is_rejected(self) -> None:
        for bad in ("values", "value", "blueprint", "FIELDS", "ASTRAL_TYPE", "get", "set"):
            with self.subTest(bad), self.assertRaises(SchemaError):
                B.blueprint("t.shadow", B.field(bad, Primitive("uint8"))).new()

    def test_the_runtime_record_iterates_in_declared_order(self) -> None:
        value = _fill(self._runtime(), self.declared)
        self.assertEqual([name for name, _ in value], [name for name, _ in _EVERY_FIELDS])

    def test_equality_covers_the_type_and_the_values(self) -> None:
        left = _fill(self._runtime(), self.declared)
        right = _fill(self._runtime(), self.declared)
        self.assertEqual(left, right)
        right.set("U", 0)
        self.assertNotEqual(left, right)
        self.assertNotEqual(left, self.declared)

    def test_a_runtime_record_round_trips_through_the_object_codec(self) -> None:
        value = _fill(self._runtime(), self.declared)
        wire = codec.encode(value)
        self.assertEqual(wire, b"\x0ft.every.runtime" + self.payload)
        back = codec.decode(wire, registry=self.registry)
        self.assertEqual(back, value)

    def test_a_runtime_record_has_an_object_id(self) -> None:
        value = _fill(self._runtime(), self.declared)
        self.assertEqual(
            canonical_bytes(value), b"\x41\x44\x43\x30\x0ft.every.runtime" + self.payload
        )
        self.assertEqual(object_id(value), object_id_of_bytes(canonical_bytes(value)))


class RuntimeRecordJsonTests(unittest.TestCase):
    """A runtime record's JSON, through the walker every declared record shares.

    The schema is per instance, so nothing here may resolve it off the class:
    `type(value).FIELDS` is the slot descriptor and walking it fails inside the
    codec instead of at the schema.
    """

    maxDiff = None

    def setUp(self) -> None:
        self.registry = Blueprints(_R)
        self.registry.register_blueprint(_runtime_every().bound_to(self.registry))
        self.declared = _every_value()

    def _runtime(self) -> B.RuntimeRecord:
        value = self.registry.new("t.every.runtime")
        assert isinstance(value, B.RuntimeRecord)
        return value

    def test_a_runtime_record_marshals_like_the_declared_record(self) -> None:
        runtime = _fill(self._runtime(), self.declared)
        self.assertEqual(jsoncodec.marshal(runtime), jsoncodec.marshal(self.declared))

    def test_a_runtime_record_parses_its_own_json_back_to_the_same_bytes(self) -> None:
        runtime = _fill(self._runtime(), self.declared)
        data = jsoncodec.marshal(runtime)
        back = jsoncodec.unmarshal("t.every.runtime", data, registry=self.registry)
        self.assertEqual(payload_bytes(back).hex(), payload_bytes(runtime).hex())
        self.assertEqual(back, runtime)

    def test_the_json_line_carries_the_runtime_type_name(self) -> None:
        runtime = _fill(self._runtime(), self.declared)
        line = jsoncodec.encode_line(runtime)
        self.assertTrue(line.startswith('{"Type":"t.every.runtime","Object":{'))
        self.assertEqual(
            jsoncodec.decode_line(line, registry=self.registry), runtime
        )

    def test_a_runtime_record_reaches_the_registry_through_a_polymorphic_field(
        self,
    ) -> None:
        runtime = _fill(self._runtime(), self.declared)
        holder = objects.ErrUnexpectedObject(object=runtime)
        data = jsoncodec.marshal(holder)
        self.assertEqual(data["Object"]["Type"], "t.every.runtime")
        back = jsoncodec.unmarshal(
            "err_unexpected_object", data, registry=self.registry
        )
        self.assertEqual(back.object, runtime)

    def test_an_alias_kind_runtime_record_is_the_underlying_scalar(self) -> None:
        self.registry.register_blueprint(B.blueprint_alias("t.runtime.mode", "uint8"))
        value = self.registry.new("t.runtime.mode")
        value.value = 21
        self.assertEqual(jsoncodec.marshal(value), 21)
        back = jsoncodec.unmarshal("t.runtime.mode", 7, registry=self.registry)
        self.assertEqual(back.value, 7)
        self.assertEqual(payload_bytes(back), b"\x07")
        # The declared alias agrees, which is what makes the two interchangeable.
        self.assertEqual(jsoncodec.marshal(Mode(21)), 21)

    def test_an_unknown_field_is_a_fault_and_a_missing_one_keeps_its_zero(self) -> None:
        with self.assertRaises(ParseError):
            jsoncodec.unmarshal(
                "t.every.runtime", {"Nope": 1}, registry=self.registry
            )
        partial = jsoncodec.unmarshal(
            "t.every.runtime", {"u": 7}, registry=self.registry
        )
        self.assertEqual(partial.get("U"), 7)
        self.assertEqual(partial.get("S"), "")

    def test_the_zero_value_json_records_the_two_divergences_from_astral_go(
        self,
    ) -> None:
        """astral-go's runtime zero differs in two places, both by design.

        `{"An":null,"Ar":[null,null],"Mp":null,"Pt":null,"Sl":[],"U":0}` is what
        astral-go emits for the same blueprint. Two fields differ and neither is
        a codec fault: an empty container is `null` here and Go's runtime slice
        renders `[]` (both parse back empty, design 2.3), and an array's
        spec-zero holds element zeros here where Go holds nil pointers -- Go
        reads our `01`-flagged elements without complaint.
        """
        zero = jsoncodec.marshal(self._runtime())
        self.assertEqual(zero["An"], None)
        self.assertEqual(zero["Pt"], None)
        self.assertEqual(zero["Mp"], None)
        self.assertEqual(zero["Sl"], None)
        self.assertEqual(zero["Ar"], [0, 0])
        self.assertEqual(zero["U"], 0)

    def test_an_absent_polymorphic_field_writes_the_documented_zero_byte(self) -> None:
        """Design 2.9: write `0x00`, accept `0x00` and `string8("nil")` on read.

        astral-go's runtime-blueprint reader refuses `0x00` for an `ObjectSpec`
        field -- it fails the whole frame with `blueprint not found: ` -- and
        writes `036e696c` itself, so this is the one place the SDK's bytes are
        not readable by the peer that supplied the blueprint. Pinned because it
        is a design decision, not an oversight: changing it needs 2.9 amended.
        """
        zero = self._runtime()
        payload = payload_bytes(zero)
        # `An` is the last field of the blueprint, so the absent polymorphic
        # slot is the final byte.
        self.assertEqual(payload[-1:], b"\x00")
        self.assertIsNone(
            zero.read_payload(ObjectReader(payload, registry=self.registry)).get("An")
        )
        # The runtime spelling reads back as absent too, and re-encodes as 0x00.
        again = self._runtime().read_payload(
            ObjectReader(payload[:-1] + b"\x03nil", registry=self.registry)
        )
        self.assertIsNone(again.get("An"))
        self.assertEqual(payload_bytes(again).hex(), payload.hex())


class BlueprintJsonTests(unittest.TestCase):
    """`astral.blueprint`'s JSON: the envelope, and why the inline form is refused."""

    maxDiff = None

    def test_a_blueprint_emits_the_envelope_for_its_spec_slot(self) -> None:
        bp = B.blueprint("demo.point", B.field("X", Primitive("uint32")))
        self.assertEqual(
            jsoncodec.marshal(bp),
            {
                "Type": "demo.point",
                "Fields": [
                    {
                        "Name": "X",
                        "Spec": {
                            "Type": "astral.blueprint.primitive_spec",
                            "Object": {"PrimitiveType": "uint32"},
                        },
                    }
                ],
                "Underlying": "",
            },
        )
        back = jsoncodec.unmarshal("astral.blueprint", jsoncodec.marshal(bp))
        self.assertEqual(payload_bytes(back).hex(), payload_bytes(bp).hex())

    def test_the_inline_spec_form_is_not_invertible(self) -> None:
        """The corpus's blueprint JSON is Go's `encoding/json` output, and lossy.

        `json.Marshal(*Blueprint)` renders the polymorphic `Field.Spec` slot
        inline because `*astral.Blueprint` has no `MarshalJSON`. Three carriers
        render identically that way -- `ref_spec`, `slice_spec` and `ptr_spec` are
        all `{"Type": …}` -- so no decoder can resolve the form, and astral-go
        proves it: `Objectify(&bp).UnmarshalJSON` fed astral-go's own
        `json.Marshal(bp)` output fails with `blueprint not found: `. The SDK
        refuses it rather than guessing, and says why.
        """
        for carrier in (B.RefSpec, B.SliceSpec, B.PtrSpec):
            with self.subTest(carrier.ASTRAL_TYPE):
                self.assertEqual(
                    jsoncodec.marshal(carrier(type="uint32")), {"Type": "uint32"}
                )
        node_form = jsoncodec.loads(vector_by_id("blueprint.struct").json_line)
        with self.assertRaises(ParseError) as caught:
            jsoncodec.unmarshal("astral.blueprint", node_form)
        self.assertIn("polymorphic field", str(caught.exception))

    def test_the_alias_kind_matches_the_corpus_json_exactly(self) -> None:
        # No polymorphic slot, so the gap does not reach this vector and the
        # corpus measures it in both directions.
        vector = vector_by_id("blueprint.alias")
        bp = B.Blueprint.read_payload(ObjectReader(vector.payload))
        self.assertEqual(jsoncodec.marshal(bp), vector.json_value)
        back = jsoncodec.unmarshal("astral.blueprint", vector.json_value)
        self.assertEqual(payload_bytes(back).hex(), vector.payload.hex())


_register_step5_codecs()
