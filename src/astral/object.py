"""The Object protocol and the objects the protocol itself is built from.

Three invariants, inherited from astral-go and non-negotiable:

1. `write_payload` and `read_payload` handle the payload only. They never write
   or read a type tag and never write a length prefix. Framing belongs to
   whoever owns the stream.
2. `read_payload` may read greedily to the end of its reader. A framed receiver
   must therefore hand it a reader over exactly one frame's payload.
3. The type string lives on the class, never in the payload.

`Blob` is the untyped object and is deliberately absent from the registry:
astral-go's `Add` rejects an empty type and discards the error, so `blob` is not
a registered type there either. The binary channel maps a zero-length type tag
to `Blob` by an explicit special case.

`Blob` and `UnparsedObject` read to the end of their reader. Both must receive a
reader bounded to one frame's payload and must never see a socket.
"""

from __future__ import annotations

import base64
from typing import Any as AnyValue
from typing import ClassVar, Iterator, Protocol, Self, Sequence, runtime_checkable

from . import codec
from .codec.binary import ObjectReader, ObjectWriter, nested_frame, registry_of
from .errors import ParseError, SchemaError
from .record import record, wire
from .spec import Any, Primitive, Ptr
from .types import Identity, Nonce, ObjectID
from .wire import Reader, Writer

__all__ = [
    "Ack",
    "Blob",
    "Bundle",
    "EOS",
    "EmptyObject",
    "ErrUnexpectedObject",
    "ErrorMessage",
    "Nil",
    "Object",
    "Query",
    "UnparsedObject",
]


@runtime_checkable
class Object(Protocol):
    """An astral object: a unique type name plus a payload codec."""

    ASTRAL_TYPE: ClassVar[str]

    def write_payload(self, w: Writer) -> None: ...

    @classmethod
    def read_payload(cls, r: Reader) -> Self: ...


# --- untyped and unparsed -------------------------------------------------


class Blob(bytes):
    """The untyped object: raw bytes, no type, no length prefix.

    Not in the registry. Its ObjectID takes the untyped path -- sha256 over the
    raw payload, with no stamp and no type header.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = ""

    def __repr__(self) -> str:
        return f"Blob({bytes(self)!r})"

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls(r.rest())

    def write_payload(self, w: Writer) -> None:
        w.raw(self)

    def json(self) -> str:
        return base64.b64encode(self).decode("ascii")

    @classmethod
    def from_json(cls, data: AnyValue) -> Self:
        if not isinstance(data, str):
            raise ParseError(f"blob: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return self.json()

    @classmethod
    def parse(cls, text: str) -> Self:
        try:
            return cls(base64.b64decode(text, validate=True))
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise ParseError(f"blob: {text!r} is not base64") from exc


class UnparsedObject:
    """A type name the registry does not know, with its payload preserved.

    Produced only when a channel opts in with `allow_unparsed=True`, because
    only a length-framed channel can skip a payload it cannot decode. It has no
    JSON and no text form.
    """

    __slots__ = ("ASTRAL_TYPE", "payload")

    def __init__(self, type_name: str, payload: bytes = b"") -> None:
        self.ASTRAL_TYPE = type_name
        self.payload = bytes(payload)

    def __repr__(self) -> str:
        return f"UnparsedObject({self.ASTRAL_TYPE!r}, {len(self.payload)} bytes)"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, UnparsedObject)
            and other.ASTRAL_TYPE == self.ASTRAL_TYPE
            and other.payload == self.payload
        )

    def __hash__(self) -> int:
        return hash((self.ASTRAL_TYPE, self.payload))

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls("", r.rest())

    def write_payload(self, w: Writer) -> None:
        w.raw(self.payload)

    def json(self) -> AnyValue:
        raise ParseError(f"cannot marshal an unparsed object: {self.ASTRAL_TYPE}")

    def text(self) -> str:
        raise ParseError(f"cannot marshal an unparsed object: {self.ASTRAL_TYPE}")


# --- zero-payload objects -------------------------------------------------


class EmptyObject:
    """A zero-byte payload. Every instance of one subclass equals every other."""

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = ""
    FIELDS: ClassVar[tuple[()]] = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self)

    def __hash__(self) -> int:
        return hash(type(self))

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls()

    def write_payload(self, w: Writer) -> None:
        return None

    def json(self) -> None:
        return None

    @classmethod
    def from_json(cls, data: AnyValue) -> Self:
        return cls()

    def text(self) -> str:
        # astral-go's text channel emits "#[ack] " with a trailing space; the
        # space belongs to the channel's separator, not to the object.
        return ""

    @classmethod
    def parse(cls, text: str) -> Self:
        return cls()


class Ack(EmptyObject):
    """Acknowledgement."""

    __slots__ = ()
    ASTRAL_TYPE: ClassVar[str] = "ack"


class EOS(EmptyObject):
    """End of object stream."""

    __slots__ = ()
    ASTRAL_TYPE: ClassVar[str] = "eos"


class Nil(EmptyObject):
    """The canonical absent carrier. A registered type the SDK will see."""

    __slots__ = ()
    ASTRAL_TYPE: ClassVar[str] = "nil"


# --- error_message --------------------------------------------------------


class ErrorMessage(str):
    """An error as an object. `string16` on the wire, identical to a string16.

    A value type, not an exception: `errors.RemoteError` is what a receiver
    raises when one of these arrives in a query's object stream.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "error_message"

    def __repr__(self) -> str:
        return f"ErrorMessage({str(self)!r})"

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls(r.string16())

    def write_payload(self, w: Writer) -> None:
        w.string16(str(self))

    def json(self) -> str:
        return str(self)

    @classmethod
    def from_json(cls, data: AnyValue) -> Self:
        if not isinstance(data, str):
            raise ParseError(
                f"error_message: expected a JSON string, got {type(data).__name__}"
            )
        return cls(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def parse(cls, text: str) -> Self:
        return cls(text)


# --- bundle ---------------------------------------------------------------


class Bundle:
    """An ordered collection of **unique** objects of various types.

    `uint32` count, then `bytes32( string8(type) ++ payload )` per element. The
    type tag sits **inside** the length prefix, the opposite of a binary channel
    frame.

    Uniqueness is by ObjectID and it is part of the format, not a convenience:
    astral-go funnels every element of `Bundle.ReadFrom` through `append`, which
    refuses a repeat, so a bundle carrying one object twice is bytes the
    reference decoder rejects mid-frame. Construction, `append` and decoding all
    enforce it here for that reason. Mutating `objects` in place bypasses the
    check, exactly as reaching into astral-go's unexported slice would.
    """

    __slots__ = ("objects", "_ids")

    ASTRAL_TYPE: ClassVar[str] = "bundle"

    def __init__(self, objects: Sequence[AnyValue] = ()) -> None:
        self.objects: list[AnyValue] = []
        self._ids: set[ObjectID] = set()
        self.append(*objects)

    def __repr__(self) -> str:
        return f"Bundle({len(self.objects)} objects)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Bundle) and other.objects == self.objects

    def __len__(self) -> int:
        return len(self.objects)

    def __iter__(self) -> Iterator[AnyValue]:
        return iter(self.objects)

    def append(self, *objects: AnyValue) -> None:
        """Add objects, refusing one the bundle already carries."""
        # The import is local: objectid.py sits above this module and reaches
        # back into it through the codec.
        from .objectid import object_id_of

        for obj in objects:
            key = object_id_of(obj)
            if key in self._ids:
                raise SchemaError(f"bundle: duplicate object {key}")
            self._ids.add(key)
            self.objects.append(obj)

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        count = r.uint32()
        registry = registry_of(r)
        out = cls()
        # A bundle element is a nested frame and may be another bundle, so the
        # window inherits this reader's depth. Decoding the raw element bytes
        # instead would build a reader at depth zero and no chain of bundles
        # would ever reach MAX_DEPTH.
        with nested_frame(r, "bundle"):
            for _ in range(count):
                element = ObjectReader(
                    r.bytes32(),
                    registry=registry,
                    max_alloc=r.max_alloc,
                    depth=getattr(r, "depth", 0),
                )
                out.append(codec.decode(element))
        return out

    def write_payload(self, w: Writer) -> None:
        w.uint32(len(self.objects))
        with nested_frame(w, "bundle"):
            for obj in self.objects:
                inner = ObjectWriter(depth=getattr(w, "depth", 0))
                codec.encode_to(inner, obj)
                w.bytes32(inner.getvalue())


# --- records --------------------------------------------------------------


@record("err_unexpected_object")
class ErrUnexpectedObject:
    """One polymorphic field: the object that was not expected."""

    object: AnyValue = wire("Object", Any())


@record("query")
class Query:
    """A routed query: nonce, caller, target and the query string.

    The query object carries no zone. Zone travels per hop, not in the query
    (astral-docs bug D-25).
    """

    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    # A bare Go string field, therefore string32. A nil *Identity is one 0x00
    # byte and Anyone is 0x01 plus 33 zero bytes: they are not the same bytes.
    query_string: str = wire("QueryString", Primitive("string32"))


def _register() -> None:
    from .registry import default_blueprints

    default_blueprints().add(Ack, EOS, Nil, ErrorMessage, Bundle)


_register()
