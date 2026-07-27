"""Object encode and decode, the three type encoders, and the four framings.

A payload never contains its own type. Four containers carry it and the tag sits
in a different place in each -- the single most common reimplementation error:

| Container              | Layout                                            |
|------------------------|---------------------------------------------------|
| Binary channel frame   | `string8(type) ++ bytes32(payload)` -- type outside |
| Bundle element         | `bytes32( string8(type) ++ payload )` -- type inside |
| Canonical              | `Stamp ++ string8(type) ++ payload` -- no length   |
| Polymorphic field      | `string8(type) ++ payload` -- no length            |

Three type encoders: `Short` (the default), `Canonical` (ObjectID preimages and
the canonical channel) and `Indexed` (a `uint8` into a closed table both peers
hold). **All three reject an empty type.** The untyped-blob path on a binary
channel bypasses the encoder and writes `string8("")` directly, which is why
`channel_frame` takes the type name rather than an encoder.
"""

from __future__ import annotations

from typing import Any as AnyValue
from typing import Protocol, Sequence

from ..errors import ParseError, SchemaError, StreamCorrupted
from ..primitives import STAMP
from ..registry import Blueprints
from ..wire import Reader, Writer
from .binary import (
    ObjectReader,
    ObjectWriter,
    object_reader,
    payload_bytes,
    read_object,
    registry_of,
)

__all__ = [
    "Canonical",
    "Indexed",
    "ObjectReader",
    "ObjectWriter",
    "STAMP",
    "Short",
    "TypeEncoder",
    "bundle_element",
    "canonical",
    "canonical_bytes",
    "channel_frame",
    "decode",
    "encode",
    "encode_to",
    "object_reader",
    "payload_bytes",
    "polymorphic_field",
    "read_channel_frame",
    "registry_of",
]


class TypeEncoder(Protocol):
    """Writes and reads the type name that precedes a payload."""

    def write(self, w: Writer, type_name: str) -> None: ...

    def read(self, r: Reader) -> str: ...


def _require_type(type_name: str) -> str:
    if not type_name:
        raise SchemaError("type encoder: empty object type")
    return type_name


class Short:
    """`string8(type)`. The default, and the polymorphic-field form."""

    @classmethod
    def write(cls, w: Writer, type_name: str) -> None:
        w.string8(_require_type(type_name))

    @classmethod
    def read(cls, r: Reader) -> str:
        return r.string8()


class Canonical:
    """`Stamp ++ string8(type)`. The ObjectID preimage header."""

    @classmethod
    def write(cls, w: Writer, type_name: str) -> None:
        w.raw(STAMP)
        w.string8(_require_type(type_name))

    @classmethod
    def read(cls, r: Reader) -> str:
        stamp = r.raw(4)
        if stamp != STAMP:
            # The four bytes are consumed before the check, so the stream is
            # unrecoverable either way.
            raise ParseError(f"canonical: expected stamp {STAMP.hex()}, got {stamp.hex()}")
        return r.string8()


class Indexed:
    """A `uint8` index into a closed table both peers agreed on out of band."""

    __slots__ = ("_types", "_index")

    def __init__(self, types: Sequence[str]) -> None:
        if len(types) > 256:
            raise SchemaError(f"Indexed: {len(types)} types exceeds 256")
        for name in types:
            _require_type(name)
        self._types: tuple[str, ...] = tuple(types)
        self._index: dict[str, int] = {name: i for i, name in enumerate(self._types)}

    def write(self, w: Writer, type_name: str) -> None:
        code = self._index.get(_require_type(type_name))
        if code is None:
            raise SchemaError(f"Indexed: {type_name} is not in the table")
        w.uint8(code)

    def read(self, r: Reader) -> str:
        code = r.uint8()
        if code >= len(self._types):
            raise ParseError(f"Indexed: invalid type code {code}")
        return self._types[code]


# --- object encode and decode -------------------------------------------


def encode_to(w: Writer, obj: AnyValue, *, types: TypeEncoder = Short) -> None:
    """Write `type ++ payload` into an existing writer."""
    types.write(w, getattr(obj, "ASTRAL_TYPE", ""))
    obj.write_payload(w)


def encode(obj: AnyValue, *, types: TypeEncoder = Short) -> bytes:
    """`type ++ payload`, with the type in the named encoder's form."""
    w = ObjectWriter()
    encode_to(w, obj, types=types)
    return w.getvalue()


def decode(
    data: bytes | bytearray | memoryview | Reader,
    *,
    registry: Blueprints | None = None,
    types: TypeEncoder = Short,
) -> AnyValue:
    """Read `type ++ payload` and construct the object the type names.

    An unknown type name raises `StreamCorrupted` wrapping `BlueprintNotFound`:
    nothing at field granularity carries a length, so the stream cannot be
    resynchronised. Only the binary channel layer recovers, via its frame
    length.
    """
    r = object_reader(data, registry=registry)
    type_name = types.read(r)
    if not type_name:
        raise StreamCorrupted("empty object type: an untyped object decodes as a blob")
    return read_object(r, type_name)


def canonical_bytes(obj: AnyValue) -> bytes:
    """`Stamp ++ string8(type) ++ payload`. The ObjectID preimage of a typed object."""
    return encode(obj, types=Canonical)


# --- the four framings ---------------------------------------------------


def canonical(type_name: str, payload: bytes) -> bytes:
    """`Stamp ++ string8(type) ++ payload`. No length prefix anywhere."""
    w = Writer()
    Canonical.write(w, type_name)
    w.raw(payload)
    return w.getvalue()


def polymorphic_field(type_name: str, payload: bytes) -> bytes:
    """`string8(type) ++ payload`. The self-delimiting generic-object field form."""
    w = Writer()
    Short.write(w, type_name)
    w.raw(payload)
    return w.getvalue()


def channel_frame(type_name: str, payload: bytes) -> bytes:
    """`string8(type) ++ bytes32(payload)`. The type sits outside the length.

    An empty type name is legal here and only here: it marks an untyped blob,
    which the receiver maps to `Blob` by an explicit special case.
    """
    w = Writer()
    w.string8(type_name)
    w.bytes32(payload)
    return w.getvalue()


def read_channel_frame(r: Reader) -> tuple[str, bytes]:
    """One binary channel frame: the type name and the raw payload."""
    return r.string8(), r.bytes32()


def bundle_element(type_name: str, payload: bytes) -> bytes:
    """`bytes32( string8(type) ++ payload )`. The type sits inside the length."""
    w = Writer()
    w.bytes32(polymorphic_field(type_name, payload))
    return w.getvalue()
