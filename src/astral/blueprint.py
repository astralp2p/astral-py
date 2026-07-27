"""The schema system describing itself, and records built from a wire schema.

`Blueprint`, `Field` and the seven `*_spec` carriers are declared here with the
same `@record` syntax every other wire type uses. Nothing about them is special:
`objects.register_blueprint` carries a `Blueprint` because a `Blueprint` is an
ordinary object, a peer's `astral.blueprint` decodes through the ordinary codec,
and every validation rule is a plain function over a plain value.

Two spellings of one schema meet in this module:

- `spec.py`'s seven carriers are the in-memory form a declaration site writes.
- The seven `*_spec` records are the wire form. `carrier_of` and `spec_of`
  convert, and the conversion is total in both directions.

`RuntimeRecord` is a record whose `FIELDS` came off the wire instead of a class
body; its values live in a dict rather than in slots. It shares `write_fields` /
`read_fields` with every declared record, so there is no second walker, no
unbound-carrier hazard, and no runtime container slow path: a schema-driven
decoder constructs each element from its Spec.

Two guards, both needed, because a `Ref`/`Ptr` cycle recurses through *value
construction* and not only through I/O:

- Decoding counts frames in `codec.binary`, on the reader and on the writer.
- Constructing counts frames in `Blueprints.new`, which every nested spec-zero
  passes through.

astral-go guards only I/O, so a two-step mutually recursive `RefSpec` pair
installed straight into its registry map still overflows the stack at
construction (astral-go bug G-22). `Blueprints.register_blueprint` rejects such a
pair outright; the construction counter is what holds when a caller bypasses
registration.

**A node can be asked for a schema after all.** Design section 2.10 and
astral-go bug G-21 both say it cannot -- that `objects.blueprints` returns names
only and nothing serves a blueprint body -- and both are wrong.
`objects.get_blueprint?type=<name>` has been in astrald since `3de755d9`
(2026-06-11) and is in the live node's `shell.spec` registry, confirmed this
session against `furry-bolt`; astrald's handler sends one `astral.blueprint` for
the named type. Two limits are real and are the reason the SDK still carries its
own schema for everything it means to decode: referenced types are **not**
resolved or included, so learning a composite type means walking its references
one query at a time, and a primitive has no blueprint and answers with an error.
The op is confirmed present, not exercised -- the node crashed before this
session reached it (see `tests/test_risk_register.py`).
"""

from __future__ import annotations

import dataclasses
from typing import Any as AnyValue
from typing import ClassVar, Iterator, Self

from .codec.binary import read_fields, spec_zero, write_fields
from .codec.jsoncodec import (
    json_fields,
    json_scalar,
    read_json_fields,
    read_json_scalar,
)
from .errors import CycleDetected, SchemaError
from .primitives import SCALARS
from .record import F, fields_of, record, wire
from .registry import Blueprints, default_blueprints
from .spec import (
    PRIMITIVE_TYPES,
    Any as AnySpec,
    Array,
    Map,
    Primitive,
    Ptr,
    Ref,
    Slice,
    Spec,
    validate_name,
    validate_spec,
)
from .wire import Reader, Writer

__all__ = [
    "ArraySpec",
    "Blueprint",
    "Field",
    "MapSpec",
    "ObjectSpec",
    "PrimitiveSpec",
    "PtrSpec",
    "RefSpec",
    "RuntimeRecord",
    "SliceSpec",
    "blueprint",
    "blueprint_alias",
    "carrier_of",
    "field",
    "of",
    "spec_of",
]


# --- the seven Spec carriers, as records ---------------------------------


@record("astral.blueprint.primitive_spec")
class PrimitiveSpec:
    """A field holding one allowlisted primitive. Payload: `string16`."""

    primitive_type: str = wire("PrimitiveType", Primitive("string16"))


@record("astral.blueprint.ref_spec")
class RefSpec:
    """A field holding another registered type, inlined bare. Payload: `string16`."""

    type: str = wire("Type", Primitive("string16"))


@record("astral.blueprint.slice_spec")
class SliceSpec:
    """A `uint32`-counted sequence. An empty `Type` makes every element carry a tag."""

    type: str = wire("Type", Primitive("string16"))


@record("astral.blueprint.array_spec")
class ArraySpec:
    """A fixed-length sequence. The length is schema, so no count reaches the wire."""

    type: str = wire("Type", Primitive("string16"))
    length: int = wire("Length", Primitive("uint32"))


@record("astral.blueprint.map_spec")
class MapSpec:
    """A sorted map. An empty `ValueType` makes every value carry a tag."""

    key_type: str = wire("KeyType", Primitive("string16"))
    value_type: str = wire("ValueType", Primitive("string16"))


@record("astral.blueprint.ptr_spec")
class PtrSpec:
    """An optional field: a nil flag, then the payload when present."""

    type: str = wire("Type", Primitive("string16"))


@record("astral.blueprint.object_spec")
class ObjectSpec:
    """A polymorphic field. Zero-byte payload: the schema pins no type at all."""


# The closed set of Spec carriers, in Blueprint field order.
_CARRIERS = (PrimitiveSpec, RefSpec, SliceSpec, ArraySpec, MapSpec, PtrSpec, ObjectSpec)


# --- conversion between the two spellings --------------------------------


def carrier_of(spec: Spec) -> AnyValue:
    """The wire carrier for a `spec.py` Spec."""
    if isinstance(spec, Primitive):
        return PrimitiveSpec(primitive_type=spec.name)
    if isinstance(spec, Ref):
        return RefSpec(type=spec.type)
    if isinstance(spec, Slice):
        return SliceSpec(type=spec.type)
    if isinstance(spec, Array):
        return ArraySpec(type=spec.type, length=spec.length)
    if isinstance(spec, Map):
        return MapSpec(key_type=spec.key, value_type=spec.value)
    if isinstance(spec, Ptr):
        return PtrSpec(type=spec.type)
    if isinstance(spec, AnySpec):
        return ObjectSpec()
    raise SchemaError(f"unknown spec {type(spec).__name__}")


def spec_of(carrier: AnyValue) -> Spec:
    """The `spec.py` Spec a wire carrier describes.

    Each Spec validates itself on construction, so this is also where a
    blueprint's per-field rules are enforced: an off-allowlist primitive, an
    empty `Ref`/`Ptr` target, an oversized array length, an off-allowlist map
    key.
    """
    if isinstance(carrier, PrimitiveSpec):
        return Primitive(carrier.primitive_type)
    if isinstance(carrier, RefSpec):
        return Ref(carrier.type)
    if isinstance(carrier, SliceSpec):
        return Slice(carrier.type)
    if isinstance(carrier, ArraySpec):
        return Array(carrier.type, carrier.length)
    if isinstance(carrier, MapSpec):
        return Map(carrier.key_type, carrier.value_type)
    if isinstance(carrier, PtrSpec):
        return Ptr(carrier.type)
    if isinstance(carrier, ObjectSpec):
        return AnySpec()
    if carrier is None:
        raise SchemaError("field spec is absent")
    raise SchemaError(f"unknown spec carrier {type(carrier).__name__}")


def _clone_carrier(carrier: AnyValue) -> AnyValue:
    if not isinstance(carrier, _CARRIERS):
        raise SchemaError(f"unknown spec carrier {type(carrier).__name__}")
    return dataclasses.replace(carrier)


# --- Field and Blueprint -------------------------------------------------


@record("astral.blueprint.field")
class Field:
    """One named slot. Payload: `string16` Name, then the Spec, polymorphically."""

    name: str = wire("Name", Primitive("string16"))
    spec: AnyValue = wire("Spec", AnySpec())


@record("astral.blueprint")
class Blueprint:
    """A type described by name, either as ordered fields or as a primitive alias.

    Exactly one kind: a non-empty `underlying` is the alias kind and `fields`
    must be empty; anything else is the struct kind, and an empty `fields` is a
    legitimate empty struct rather than an alias.

    `registry` is not a wire field. It names the registry this blueprint
    resolves its field types through when constructing a value, and it is
    excluded from `FIELDS`, from equality and from `repr`, so no codec can reach
    it. A blueprint decoded off the wire carries `None` and falls back to the
    process registry; `bound_to` is how a peer's schema gets scoped to a child.
    """

    type: str = wire("Type", Primitive("string16"))
    fields: list[Field] = wire("Fields", Slice("astral.blueprint.field"))
    underlying: str = wire("Underlying", Primitive("string16"))
    registry: Blueprints | None = dataclasses.field(
        default=None, repr=False, compare=False
    )

    # --- kind ---

    @property
    def is_alias(self) -> bool:
        return bool(self.underlying)

    # --- the RuntimeBlueprint protocol the registry reads ---

    def blueprint_name(self) -> str:
        return self.type

    def blueprint_specs(self) -> tuple[Spec, ...]:
        if self.is_alias:
            return ()
        return tuple(spec_of(f.spec) for f in self.fields)

    def blueprint_underlying(self) -> str:
        return self.underlying

    def validate(self) -> None:
        """Raise unless the blueprint is well formed.

        Ported from astral-go's `validateBlueprint`, with one addition: a field
        name is checked against `MAX_NAME_LEN` and the printable-ASCII range by
        the same function that checks a type name, so an identifier can never
        make an ObjectID depend on Unicode normalisation.

        Only one-step self-reference is caught here, because a longer cycle is a
        property of the registry rather than of one blueprint.
        `Blueprints.register_blueprint` walks the whole graph.
        """
        validate_name(self.type, "type name")
        if self.underlying and self.fields:
            raise SchemaError(f"{self.type}: kind ambiguous -- both fields and underlying set")
        if self.is_alias:
            if self.underlying not in PRIMITIVE_TYPES:
                raise SchemaError(
                    f"{self.type}: underlying {self.underlying!r} is not a primitive type"
                )
            return

        seen: dict[str, str] = {}
        for entry in self.fields:
            if not isinstance(entry, Field):
                raise SchemaError(f"{self.type}: {type(entry).__name__} is not a field")
            validate_name(entry.name, "field name")
            folded = entry.name.lower()
            if folded in seen:
                # Folded, because the JSON decoder matches case-insensitively: a
                # schema the binary codec accepts must round-trip through JSON.
                raise SchemaError(
                    f"{self.type}: fields {seen[folded]!r} and {entry.name!r} differ only in case"
                )
            seen[folded] = entry.name
            spec = spec_of(entry.spec)
            validate_spec(spec)
            if isinstance(spec, (Ref, Ptr)) and spec.type == self.type:
                raise CycleDetected(f"{self.type}: field {entry.name!r} references itself")

    def clone(self) -> "Blueprint":
        """A copy the caller cannot mutate through, carriers included."""
        return Blueprint(
            type=self.type,
            fields=[Field(name=f.name, spec=_clone_carrier(f.spec)) for f in self.fields],
            underlying=self.underlying,
            registry=self.registry,
        )

    def bound_to(self, registry: Blueprints) -> "Blueprint":
        """A clone that resolves its field types through `registry`.

        `register_blueprint` stores a clone, so binding before registration is
        what scopes a peer's schema to a child registry.
        """
        bound = self.clone()
        bound.registry = registry
        return bound

    def new(self, registry: Blueprints | None = None) -> "RuntimeRecord":
        """A zero value bound to this blueprint."""
        return RuntimeRecord(self, registry if registry is not None else self.registry)

    # --- derived views ---

    def field_schema(self) -> tuple[F, ...]:
        """This blueprint as a record schema.

        The wire name is the only name a runtime field has, so it serves as the
        Python attribute too. `RuntimeRecord.__getattr__` resolves it against
        the value dict, which is what lets the declared-record walker drive a
        runtime record unchanged.
        """
        return tuple(F(f.name, f.name, spec_of(f.spec)) for f in self.fields)


# --- the runtime record --------------------------------------------------


class RuntimeRecord:
    """A record whose schema came off the wire.

    Values live in `values`, keyed by wire field name. `FIELDS` and
    `ASTRAL_TYPE` are per-instance because the schema is per-instance, which is
    the whole point: one class decodes every type the SDK was never built
    against.

    An alias-kind blueprint short-circuits both directions to the underlying
    primitive and keeps its single value in `value`. The alias name lives in the
    registry and never reaches the wire.
    """

    __slots__ = ("ASTRAL_TYPE", "FIELDS", "blueprint", "values", "value")

    DERIVABLE: ClassVar[bool] = True

    def __init__(self, bp: Blueprint, registry: Blueprints | None = None) -> None:
        bp.validate()
        target = registry if registry is not None else (bp.registry or default_blueprints())
        self.blueprint = bp
        self.ASTRAL_TYPE = bp.type
        self.values: dict[str, AnyValue] = {}
        self.value: AnyValue = None
        self.FIELDS: tuple[F, ...] = ()
        if bp.is_alias:
            found = SCALARS.get(bp.underlying)
            if found is None:
                raise SchemaError(f"{bp.type}: underlying {bp.underlying} is not registered")
            self.value = found.zero()
            return
        self.FIELDS = bp.field_schema()
        for entry in self.FIELDS:
            if entry.attr in _RESERVED:
                raise SchemaError(
                    f"{bp.type}: field {entry.attr!r} collides with RuntimeRecord's own attribute"
                )
            # Depth is counted inside `Blueprints.new`, which every nested
            # spec-zero of a Ref, a Ptr or an array element passes through.
            self.values[entry.attr] = spec_zero(entry.spec, target)

    # --- values ---

    def __getattr__(self, item: str) -> AnyValue:
        # The message names no attribute of self: a slot that is not set yet
        # would route the formatting straight back into this method.
        try:
            return object.__getattribute__(self, "values")[item]
        except KeyError:
            raise AttributeError(f"runtime record has no field {item!r}") from None

    def get(self, name: str) -> AnyValue:
        """The field's value, or `None` for a name the schema does not carry."""
        return self.values.get(name)

    def set(self, name: str, value: AnyValue) -> None:
        """Assign a field. The spec decides whether the value encodes, on encode."""
        if name not in self.values:
            raise SchemaError(f"{self.ASTRAL_TYPE}: unknown field {name!r}")
        self.values[name] = value

    def __iter__(self) -> Iterator[tuple[str, AnyValue]]:
        return iter([(entry.attr, self.values[entry.attr]) for entry in self.FIELDS])

    def __repr__(self) -> str:
        if self.blueprint.is_alias:
            return f"RuntimeRecord({self.ASTRAL_TYPE!r}, {self.value!r})"
        return f"RuntimeRecord({self.ASTRAL_TYPE!r}, {self.values!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RuntimeRecord):
            return NotImplemented
        return (
            other.ASTRAL_TYPE == self.ASTRAL_TYPE
            and other.values == self.values
            and other.value == self.value
        )

    # --- the codec, shared with every declared record ---

    def write_payload(self, w: Writer) -> None:
        if self.blueprint.is_alias:
            SCALARS[self.blueprint.underlying].write(w, self.value)
            return
        write_fields(w, self.FIELDS, self)

    def read_payload(self, r: Reader) -> Self:
        """Fill this record from the reader and return it.

        A declared record's `read_payload` is a classmethod that builds a fresh
        value; a runtime record is already bound to its schema, so the registry
        hands out a constructed carrier and this fills it. `read_object` calls
        it the same way in both cases.
        """
        if self.blueprint.is_alias:
            self.value = SCALARS[self.blueprint.underlying].read(r)
            return self
        self.values.update(read_fields(r, self.FIELDS))
        return self

    def json(self) -> AnyValue:
        """This record's JSON value, through the walker every record shares.

        The pair exists because the schema is per instance: the JSON codec
        resolves a declared record's fields off its class and constructs a fresh
        value from keywords, and neither is possible here. `jsoncodec` dispatches
        on these two the same way `read_object` dispatches on `read_payload`.
        """
        if self.blueprint.is_alias:
            return json_scalar(self.blueprint.underlying, self.value)
        return json_fields(self.FIELDS, self)

    def read_json(
        self, data: AnyValue, *, registry: Blueprints | None = None
    ) -> Self:
        """Fill this record from a JSON value and return it."""
        if self.blueprint.is_alias:
            self.value = read_json_scalar(self.blueprint.underlying, data)
            return self
        self.values.update(read_json_fields(self.FIELDS, data, registry=registry))
        return self


# A field name RuntimeRecord's own namespace would shadow. The walker reaches a
# field value through `getattr`, so a collision would silently encode the wrong
# value; wire field names are PascalCase and none of these are, so the check
# costs nothing in practice and turns an undebuggable mis-encoding into a
# rejected schema.
_RESERVED: frozenset[str] = frozenset(dir(RuntimeRecord))


# --- derivation from a declared record -----------------------------------


def of(cls: type) -> Blueprint:
    """The blueprint of a declared record or alias class.

    Only `@record` and `@alias` classes are describable. A class with a
    hand-written payload codec is refused: its `FIELDS` serves JSON only and
    does not describe its bytes, so a peer given such a blueprint would encode a
    shape the class cannot read. A primitive is refused too -- primitives are
    registered under their own names and have no blueprint.
    """
    name = str(getattr(cls, "ASTRAL_TYPE", ""))
    validate_name(name, "type name")
    underlying = str(getattr(cls, "UNDERLYING", ""))
    if underlying:
        return blueprint_alias(name, underlying)
    if not getattr(cls, "DERIVABLE", False):
        raise SchemaError(f"{name}: not a declared record, so it has no derivable blueprint")
    if name in SCALARS:
        raise SchemaError(f"{name}: a primitive has no blueprint")
    return Blueprint(
        type=name,
        fields=[field(entry.wire_name, entry.spec) for entry in fields_of(cls)],
    )


# --- construction helpers ------------------------------------------------


def field(name: str, spec: Spec | AnyValue) -> Field:
    """One field, from either spelling of its spec."""
    return Field(name=name, spec=spec if isinstance(spec, _CARRIERS) else carrier_of(spec))


def blueprint(type_name: str, *fields: Field, registry: Blueprints | None = None) -> Blueprint:
    """A struct-kind blueprint."""
    return Blueprint(type=type_name, fields=list(fields), registry=registry)


def blueprint_alias(
    type_name: str, underlying: str, *, registry: Blueprints | None = None
) -> Blueprint:
    """An alias-kind blueprint: the underlying primitive's bytes, a new name."""
    return Blueprint(type=type_name, underlying=underlying, registry=registry)
