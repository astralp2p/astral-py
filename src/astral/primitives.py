"""The registered scalar object types, and the scalar codec table.

Two views of the same scalars, and both are load-bearing:

- `SCALARS` maps a type name to the plain-value codec the spec walker uses.
  `Primitive("uint8")` and `Ref("uint8")` therefore decode to `int`, and
  `Primitive("string16")` to `str`. Field values are plain Python values.
- The classes below are the registry entries. A polymorphic field carries an
  Object -- the type tag comes off `ASTRAL_TYPE` -- so `Uint8(7)` is what goes
  into an `Any()` slot, and what comes back out of one. Each wraps the plain
  value and subclasses its builtin, so arithmetic, comparison and formatting
  keep working.

`SCALARS` is deliberately wider than `spec.PRIMITIVE_TYPES`: `int8..int64`,
`float32/64`, `size`, `object_type` and `error_message` are fully encodable but
are not on the blueprint allowlist, so a runtime blueprint reaches them only
through `Ref(name)`.

The seven value types of `types.py` are registered as themselves rather than
through a wrapper, so an identity read out of a polymorphic field compares equal
to one constructed directly.
"""

from __future__ import annotations

from typing import Any, Callable, ClassVar, Final, NamedTuple, Self

from .errors import ParseError, RangeError, SchemaError
from .registry import default_blueprints
from .types import Duration, Identity, Nonce, ObjectID, Size, Time, Zone
from .wire import Reader, Writer

__all__ = [
    "Bool",
    "Bytes8",
    "Bytes16",
    "Bytes32",
    "Bytes64",
    "Float32",
    "Float64",
    "Int8",
    "Int16",
    "Int32",
    "Int64",
    "ObjectType",
    "SCALARS",
    "STAMP",
    "Scalar",
    "Stamp",
    "String8",
    "String16",
    "String32",
    "String64",
    "Uint8",
    "Uint16",
    "Uint32",
    "Uint64",
    "scalar",
]

# The big-endian uint32 0x41444330, ASCII "ADC0". Prefixes every canonical form.
STAMP: Final = b"\x41\x44\x43\x30"


class Scalar(NamedTuple):
    """One scalar type's plain-value codec."""

    read: Callable[[Reader], Any]
    write: Callable[[Writer, Any], None]
    zero: Callable[[], Any]


def _value_writer(cls: type) -> Callable[[Writer, Any], None]:
    """Write a `types.py` value type, coercing a plain Python value first.

    `zone=7` and `nonce=5` are the natural call sites, and coercion cannot
    change the bytes: each value type's constructor is the only thing that
    decides them.
    """

    def write(w: Writer, value: Any) -> None:
        if not isinstance(value, cls):
            try:
                value = cls(value)
            except TypeError as exc:
                raise SchemaError(
                    f"{cls.ASTRAL_TYPE}: cannot encode {type(value).__name__}"
                ) from exc
        value.write(w)

    return write


SCALARS: Final[dict[str, Scalar]] = {
    "bool": Scalar(Reader.boolean, Writer.boolean, bool),
    "uint8": Scalar(Reader.uint8, Writer.uint8, int),
    "uint16": Scalar(Reader.uint16, Writer.uint16, int),
    "uint32": Scalar(Reader.uint32, Writer.uint32, int),
    "uint64": Scalar(Reader.uint64, Writer.uint64, int),
    "int8": Scalar(Reader.int8, Writer.int8, int),
    "int16": Scalar(Reader.int16, Writer.int16, int),
    "int32": Scalar(Reader.int32, Writer.int32, int),
    "int64": Scalar(Reader.int64, Writer.int64, int),
    "float32": Scalar(Reader.float32, Writer.float32, float),
    "float64": Scalar(Reader.float64, Writer.float64, float),
    "string8": Scalar(Reader.string8, Writer.string8, str),
    "string16": Scalar(Reader.string16, Writer.string16, str),
    "string32": Scalar(Reader.string32, Writer.string32, str),
    "string64": Scalar(Reader.string64, Writer.string64, str),
    "bytes8": Scalar(Reader.bytes8, Writer.bytes8, bytes),
    "bytes16": Scalar(Reader.bytes16, Writer.bytes16, bytes),
    "bytes32": Scalar(Reader.bytes32, Writer.bytes32, bytes),
    "bytes64": Scalar(Reader.bytes64, Writer.bytes64, bytes),
    "identity": Scalar(Identity.read, _value_writer(Identity), Identity),
    "nonce64": Scalar(Nonce.read, _value_writer(Nonce), Nonce),
    "object_id.sha256": Scalar(ObjectID.read, _value_writer(ObjectID), ObjectID),
    "time": Scalar(Time.read, _value_writer(Time), Time),
    "duration": Scalar(Duration.read, _value_writer(Duration), Duration),
    "size": Scalar(Size.read, _value_writer(Size), Size),
    "zone": Scalar(Zone.read, _value_writer(Zone), lambda: Zone(0)),
    # object_type and error_message have no payload of their own: one is a
    # string8 and the other a string16, byte for byte.
    "object_type": Scalar(Reader.string8, Writer.string8, str),
    "error_message": Scalar(Reader.string16, Writer.string16, str),
}


def scalar(type_name: str) -> Scalar | None:
    """The plain-value codec for a scalar type name, or `None`."""
    return SCALARS.get(type_name)


# --- the registered object types -------------------------------------------


class _ScalarObject:
    """Read and write through the Reader/Writer method named by the type.

    Every scalar's Reader and Writer method is its astral type name, `bool`
    excepted: `boolean` is the lenient payload reader, distinct from the strict
    `flag` used for presence and nil bytes.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = ""
    WIRE_METHOD: ClassVar[str] = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.WIRE_METHOD:
            cls.WIRE_METHOD = cls.ASTRAL_TYPE

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls(getattr(r, cls.WIRE_METHOD)())  # type: ignore[call-arg]

    def write_payload(self, w: Writer) -> None:
        getattr(w, self.WIRE_METHOD)(self._wire_value())

    def _wire_value(self) -> Any:
        raise NotImplementedError


class _IntObject(_ScalarObject, int):
    """A fixed-width integer, range-checked at construction."""

    __slots__ = ()

    BITS: ClassVar[int] = 0
    SIGNED: ClassVar[bool] = False

    def __new__(cls, value: int = 0) -> Self:
        if cls.SIGNED:
            low, high = -(1 << (cls.BITS - 1)), (1 << (cls.BITS - 1)) - 1
        else:
            low, high = 0, (1 << cls.BITS) - 1
        if not low <= value <= high:
            raise RangeError(f"{cls.ASTRAL_TYPE}: {value} out of range")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)})"

    def _wire_value(self) -> int:
        return int(self)


class Uint8(_IntObject):
    ASTRAL_TYPE = "uint8"
    BITS = 8


class Uint16(_IntObject):
    ASTRAL_TYPE = "uint16"
    BITS = 16


class Uint32(_IntObject):
    ASTRAL_TYPE = "uint32"
    BITS = 32


class Uint64(_IntObject):
    ASTRAL_TYPE = "uint64"
    BITS = 64


class Int8(_IntObject):
    ASTRAL_TYPE = "int8"
    BITS = 8
    SIGNED = True


class Int16(_IntObject):
    ASTRAL_TYPE = "int16"
    BITS = 16
    SIGNED = True


class Int32(_IntObject):
    ASTRAL_TYPE = "int32"
    BITS = 32
    SIGNED = True


class Int64(_IntObject):
    ASTRAL_TYPE = "int64"
    BITS = 64
    SIGNED = True


class Bool(_ScalarObject, int):
    """A boolean payload.

    `bool` cannot be subclassed, so the carrier is an `int` restricted to 0 and
    1. `bool(Bool(1))` and `Bool(1) == True` both hold.
    """

    __slots__ = ()

    ASTRAL_TYPE = "bool"
    WIRE_METHOD = "boolean"

    def __new__(cls, value: object = False) -> Self:
        return super().__new__(cls, 1 if value else 0)

    def __repr__(self) -> str:
        return f"Bool({bool(self)})"

    def _wire_value(self) -> bool:
        return bool(self)


class _FloatObject(_ScalarObject, float):
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({float(self)!r})"

    def _wire_value(self) -> float:
        return float(self)


class Float32(_FloatObject):
    ASTRAL_TYPE = "float32"


class Float64(_FloatObject):
    ASTRAL_TYPE = "float64"


class _StrObject(_ScalarObject, str):
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r})"

    def _wire_value(self) -> str:
        return str(self)


class String8(_StrObject):
    ASTRAL_TYPE = "string8"


class String16(_StrObject):
    ASTRAL_TYPE = "string16"


class String32(_StrObject):
    ASTRAL_TYPE = "string32"


class String64(_StrObject):
    ASTRAL_TYPE = "string64"


class ObjectType(_StrObject):
    """A type name as an object in its own right. `string8` on the wire."""

    ASTRAL_TYPE = "object_type"
    WIRE_METHOD = "string8"


class _BytesObject(_ScalarObject, bytes):
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({bytes(self)!r})"

    def _wire_value(self) -> bytes:
        return bytes(self)


class Bytes8(_BytesObject):
    ASTRAL_TYPE = "bytes8"


class Bytes16(_BytesObject):
    ASTRAL_TYPE = "bytes16"


class Bytes32(_BytesObject):
    ASTRAL_TYPE = "bytes32"


class Bytes64(_BytesObject):
    ASTRAL_TYPE = "bytes64"


class Stamp:
    """The four magic bytes as an object.

    Every instance is equal to every other: the type carries no state. A payload
    whose four bytes are not `41 44 43 30` is a hard error, and the bytes are
    consumed before the check, so the stream cannot be resynchronised.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "stamp"

    def __repr__(self) -> str:
        return "Stamp()"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Stamp)

    def __hash__(self) -> int:
        return hash(Stamp)

    @classmethod
    def read_payload(cls, r: Reader) -> "Stamp":
        raw = r.raw(4)
        if raw != STAMP:
            raise ParseError(f"stamp: expected {STAMP.hex()}, got {raw.hex()}")
        return cls()

    def write_payload(self, w: Writer) -> None:
        w.raw(STAMP)


default_blueprints().add(
    Bool,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    String8,
    String16,
    String32,
    String64,
    Bytes8,
    Bytes16,
    Bytes32,
    Bytes64,
    ObjectType,
    Stamp,
    Identity,
    Nonce,
    ObjectID,
    Time,
    Duration,
    Size,
    Zone,
)
