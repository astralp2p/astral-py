"""The seven Spec carriers, the two allowlists, and spec validation.

A Spec names one field's wire shape. The seven carriers mirror astral-go's
`Spec` implementations one for one, so a Spec tree converts to an
`astral.blueprint` object and back without loss:

    Primitive(name)        the named primitive's payload
    Ref(type)              the referenced type's payload, inlined bare
    Slice(type="")         uint32 count ++ element x count
    Array(type, length)    element x length, no count on the wire
    Map(key, value="")     uint32 count ++ (key ++ value) x count, sorted
    Ptr(type)              0x00 absent / 0x01 ++ payload
    Any()                  string8(type) ++ payload

Schema derivation from Python type hints does not exist. Hints are width-free:
`str` cannot distinguish `string8` from `string32`, `int` cannot distinguish
`uint8` from `int64`, `bytes` cannot distinguish `bytes8` from `identity`. The
Spec tree is declared directly and is the single source of truth.

A container's element type, an array's element type and a map's value type are
type *names*, never nested Specs. That is astral-go's constraint: a `SliceSpec`
carries a `String16`, so a slice of slices requires a named intermediate type.

Two allowlists bound what a runtime blueprint can express. They are narrower
than the set of encodable scalars: `int8..int64`, `float32/64`, `size`,
`error_message` and `object_type` are registered and fully encodable, and a
blueprint reaches them only through `Ref(name)`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeAlias

from .errors import SchemaError

__all__ = [
    "Any",
    "AnySpec",
    "Array",
    "MAP_KEY_TYPES",
    "MAX_ARRAY_LENGTH",
    "MAX_DEPTH",
    "MAX_NAME_LEN",
    "Map",
    "PRIMITIVE_TYPES",
    "Primitive",
    "Ptr",
    "Ref",
    "Slice",
    "Spec",
    "needs_presence",
    "referenced_type",
    "validate_name",
    "validate_spec",
]

# The 19 names a `PrimitiveSpec` may carry, ported verbatim from astral-go's
# `primitiveAllowlist`.
PRIMITIVE_TYPES: Final = frozenset(
    {
        "string8",
        "string16",
        "string32",
        "string64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "bytes8",
        "bytes16",
        "bytes32",
        "bytes64",
        "bool",
        "time",
        "identity",
        "object_id.sha256",
        "nonce64",
        "duration",
        "zone",
    }
)

# The five names a `MapSpec.KeyType` may carry. Platform-width integers are
# absent by design: their width would make content hashes host-dependent.
MAP_KEY_TYPES: Final = frozenset({"string16", "uint8", "uint16", "uint32", "uint64"})

# An array's length is schema data, so a hostile peer schema could otherwise
# demand gigabytes per constructed value.
MAX_ARRAY_LENGTH: Final = 65536

# Both a type name and a field name are capped here, even though `string16`
# carries up to 65535 bytes.
MAX_NAME_LEN: Final = 255

# Nested record frames, on encode, on decode, and at construction.
MAX_DEPTH: Final = 64


@dataclass(frozen=True, slots=True)
class Primitive:
    """The named primitive's payload. The name must be on the allowlist."""

    name: str

    def __post_init__(self) -> None:
        if self.name not in PRIMITIVE_TYPES:
            raise SchemaError(f"Primitive({self.name!r}): not a primitive type")


@dataclass(frozen=True, slots=True)
class Ref:
    """The referenced type's payload, inlined bare: no tag, no length, no flag.

    Also how an embedded value struct encodes. Resolution is by name through the
    registry, never by class reference, so forward references and import cycles
    do not arise.
    """

    type: str

    def __post_init__(self) -> None:
        validate_name(self.type, "Ref.type")


@dataclass(frozen=True, slots=True)
class Slice:
    """`uint32` count then one element per count. An empty type is heterogeneous."""

    type: str = ""

    def __post_init__(self) -> None:
        if self.type:
            validate_name(self.type, "Slice.type")


@dataclass(frozen=True, slots=True)
class Array:
    """One element per `length`. No count on the wire: the length is the schema."""

    type: str
    length: int

    def __post_init__(self) -> None:
        if self.type:
            validate_name(self.type, "Array.type")
        if self.length < 0:
            raise SchemaError(f"Array.length {self.length} is negative")
        if self.length > MAX_ARRAY_LENGTH:
            raise SchemaError(f"Array.length {self.length} exceeds {MAX_ARRAY_LENGTH}")


@dataclass(frozen=True, slots=True)
class Map:
    """`uint32` count then pairs, sorted by encoded key bytes.

    An empty value type is heterogeneous: every value carries its own type tag.
    """

    key: str
    value: str = ""

    def __post_init__(self) -> None:
        if self.key not in MAP_KEY_TYPES:
            raise SchemaError(f"Map.key {self.key!r}: not a map key type")
        if self.value:
            validate_name(self.value, "Map.value")


@dataclass(frozen=True, slots=True)
class Ptr:
    """`0x00` absent, `0x01` then the payload. Anything else is corrupt."""

    type: str

    def __post_init__(self) -> None:
        validate_name(self.type, "Ptr.type")


@dataclass(frozen=True, slots=True)
class Any:
    """`string8(type)` then the payload. A zero-length tag means nil."""


# `Any` mirrors astral-go's `ObjectSpec` and the design's declaration syntax.
# `AnySpec` is the same carrier under a name that does not collide with
# `typing.Any` at an import site.
AnySpec: TypeAlias = Any

Spec: TypeAlias = Primitive | Ref | Slice | Array | Map | Ptr | Any

_KINDS: Final = (Primitive, Ref, Slice, Array, Map, Ptr, Any)


def needs_presence(spec: Spec) -> bool:
    """Whether a container synthesizes the presence byte for this spec.

    The presence byte is a property of the container slot, never of the value.
    `Ptr` emits its own nil flag and `Any` emits its own type tag; everything
    else sitting in a slice element, an array element or a map value slot is
    preceded by a synthesized byte -- `0x01` before a value, `0x00` for an
    element that has none. A map key never carries one.
    """
    return not isinstance(spec, (Ptr, Any))


def referenced_type(spec: Spec) -> str:
    """The type name this spec needs resolvable, or `""`.

    Drives closure validation on blueprint registration and the topological
    order of a blueprint sync.
    """
    if isinstance(spec, (Ref, Slice, Array, Ptr)):
        return spec.type
    if isinstance(spec, Map):
        return spec.value
    return ""


def validate_name(name: str, what: str = "name") -> None:
    """Non-empty, printable ASCII `0x20..0x7E`, at most 255 bytes.

    Identifiers stay ASCII so an ObjectID cannot depend on Unicode
    normalisation: two visually identical names must never hash differently.
    """
    if not name:
        raise SchemaError(f"{what}: empty")
    raw = name.encode("utf-8", "surrogateescape")
    if len(raw) > MAX_NAME_LEN:
        raise SchemaError(f"{what}: {len(raw)} bytes exceeds {MAX_NAME_LEN}")
    for byte in raw:
        if byte < 0x20 or byte > 0x7E:
            raise SchemaError(f"{what} {name!r}: must be printable ASCII")


def validate_spec(spec: Spec) -> None:
    """Re-check one spec. Each carrier validates itself on construction.

    A spec built from a peer's blueprint passes through here, so an unknown
    carrier is rejected rather than silently skipped.
    """
    if not isinstance(spec, _KINDS):
        raise SchemaError(f"unknown spec {type(spec).__name__}")
    if isinstance(spec, Primitive) and spec.name not in PRIMITIVE_TYPES:
        raise SchemaError(f"Primitive({spec.name!r}): not a primitive type")
    if isinstance(spec, Map) and spec.key not in MAP_KEY_TYPES:
        raise SchemaError(f"Map.key {spec.key!r}: not a map key type")
    if isinstance(spec, Array) and not 0 <= spec.length <= MAX_ARRAY_LENGTH:
        raise SchemaError(f"Array.length {spec.length} out of range")
