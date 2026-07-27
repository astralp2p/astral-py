"""The spec-driven binary payload codec.

This module is the single source of the presence-byte rules, the map sort and
the container rules. Nothing else in the package may re-derive them.

The presence byte is one rule with three faces, and it is a property of the
container slot, never of the value:

- `Ptr` emits its own nil flag, `0x00` or `0x01`.
- `Any` emits its own type tag; a zero-length tag is the nil signal.
- Everything else, in a slice element, an array element or a **map value** slot,
  is preceded by a synthesized `0x01`. A map key never carries one.

On write the synthesized byte is `0x01` for a present value. On read `0x00` is
additionally accepted as "absent, no payload follows": astral-go's reflection
codec rejects it, but its blueprint-built containers resolve their element type
to a pointer prototype (`resolveElemType` returns `*Uint8` for `"uint8"`, and
`elemNeedsPresenceFlag` is false for a pointer), so they legally emit it and a
strict reader desynchronises against a blueprint peer. An element that decoded
as absent writes `0x00` again -- the byte that peer wrote -- because a decode
this codec accepts must re-encode to the bytes it came from.

The map sort is part of the wire format. Each key and each value encodes into
its own buffer, the pairs sort by the encoded key bytes, and only then does
anything reach the writer. Python's dict insertion order must never reach the
wire: content hashes depend on the sort.

The registry travels on the reader. `ObjectReader` carries it, and every nested
frame inherits it, so a per-call registry scopes an entire object graph.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any as AnyValue
from typing import Callable, Iterator, Sequence

from ..errors import (
    BlueprintNotFound,
    DepthExceeded,
    SchemaError,
    StreamCorrupted,
    ValueTooLarge,
)
from ..primitives import SCALARS, Scalar
from ..registry import Blueprints, default_blueprints
from ..spec import (
    MAX_DEPTH,
    Any,
    Array,
    Map,
    Primitive,
    Ptr,
    Ref,
    Slice,
    Spec,
)
from ..wire import DEFAULT_MAX_ALLOC, Reader, Writer

__all__ = [
    "FieldTriple",
    "ObjectReader",
    "ObjectWriter",
    "nested_frame",
    "object_reader",
    "payload_bytes",
    "read_fields",
    "read_object",
    "read_spec",
    "registry_of",
    "spec_zero",
    "write_fields",
    "write_spec",
]

# A field as the walker needs it: the Python attribute, the wire name, the spec.
# `record.F` is exactly this tuple; the annotation avoids an import cycle,
# because record.py imports this module.
FieldTriple = tuple[str, str, Spec]

# The nil form astral-go's runtime-blueprint codec writes for an absent
# polymorphic field. It cannot read its own output, so the SDK writes the
# documented `0x00` and accepts both (astral-go bug G-1).
_RUNTIME_NIL_TAG = "nil"


class ObjectReader(Reader):
    """A reader that carries the registry and the frame depth.

    Mirrors astral-go's `objectReader`: the registry is set once and every
    nested frame inherits it, including a bounded window.
    """

    __slots__ = ("registry", "depth")

    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        *,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        start: int = 0,
        end: int | None = None,
        depth: int = 0,
    ) -> None:
        super().__init__(data, max_alloc=max_alloc, start=start, end=end)
        self.registry: Blueprints = default_blueprints() if registry is None else registry
        self.depth: int = depth

    def bounded(self, n: int) -> "ObjectReader":
        """One frame's payload, carrying this reader's registry and depth."""
        window = super().bounded(n)
        return ObjectReader(
            window.rest(),
            registry=self.registry,
            max_alloc=self.max_alloc,
            depth=self.depth,
        )


class ObjectWriter(Writer):
    """A writer that carries the frame depth."""

    __slots__ = ("depth",)

    def __init__(self, buf: bytearray | None = None, *, depth: int = 0) -> None:
        super().__init__(buf)
        self.depth: int = depth


def registry_of(r: Reader) -> Blueprints:
    """The registry this reader carries, or the process-wide default."""
    return getattr(r, "registry", None) or default_blueprints()


def object_reader(
    data: bytes | bytearray | memoryview | Reader,
    *,
    registry: Blueprints | None = None,
    max_alloc: int = DEFAULT_MAX_ALLOC,
) -> ObjectReader:
    """An `ObjectReader` over bytes, or over what is left of a reader.

    An `ObjectReader` is returned unchanged unless a different registry is
    named. A plain `Reader` carries no registry, so one is attached by copying
    what is left -- which **consumes** that reader. A caller decoding several
    objects from one buffer therefore holds an `ObjectReader` from the start;
    the canonical channel, whose framing has no length prefix at all, is the one
    that must.
    """
    if isinstance(data, Reader):
        if isinstance(data, ObjectReader) and registry is None:
            return data
        rest = data.rest()
        return ObjectReader(
            rest, registry=registry or registry_of(data), max_alloc=data.max_alloc
        )
    return ObjectReader(data, registry=registry, max_alloc=max_alloc)


# --- depth --------------------------------------------------------------


def _enter(rw: Reader | Writer, what: str) -> int | None:
    """Count one nested record frame.

    A plain `Reader`/`Writer` carries no counter; every public entry point
    installs one that does, and a `Ref` cycle is rejected at registration, so a
    declared record cannot recurse without bound in either case.
    """
    depth = getattr(rw, "depth", None)
    if depth is None:
        return None
    if depth >= MAX_DEPTH:
        raise DepthExceeded(f"{what}: nesting passed depth {MAX_DEPTH}")
    rw.depth = depth + 1  # type: ignore[union-attr]
    return depth


def _leave(rw: Reader | Writer, saved: int | None) -> None:
    if saved is not None:
        rw.depth = saved  # type: ignore[union-attr]


@contextmanager
def nested_frame(rw: Reader | Writer, what: str) -> Iterator[None]:
    """Count one nested frame for the duration of the block.

    The counter every object with a hand-written codec must use around its own
    nesting. `Bundle` is the case that needs it: its elements are whole objects
    and one of them may be another bundle.
    """
    saved = _enter(rw, what)
    try:
        yield
    finally:
        _leave(rw, saved)


# --- named types --------------------------------------------------------


def _scalar(type_name: str) -> Scalar | None:
    return SCALARS.get(type_name)


def _write_named(w: Writer, type_name: str, value: AnyValue) -> None:
    """Write one value of a named type, bare: no tag, no length, no flag."""
    if value is None:
        raise SchemaError(
            f"{type_name}: None has no bare encoding -- only Ptr and Any carry absence"
        )
    found = _scalar(type_name)
    if found is not None:
        found.write(w, value)
        return
    write = getattr(value, "write_payload", None)
    if write is None:
        raise SchemaError(f"{type_name}: {type(value).__name__} is not an astral object")
    write(w)


def _read_named(r: Reader, type_name: str) -> AnyValue:
    """Read one value of a named type, bare."""
    found = _scalar(type_name)
    if found is not None:
        return found.read(r)
    return read_object(r, type_name)


def read_object(r: Reader, type_name: str) -> AnyValue:
    """Construct the named type from the reader's registry and read its payload.

    An unknown type name is fatal for the stream: nothing at field granularity
    carries a length, so there is no way to resume. Only the binary channel
    layer can recover, because its frame length lets it skip.
    """
    proto = registry_of(r).new(type_name)
    if proto is None:
        raise StreamCorrupted(f"unknown type {type_name}") from BlueprintNotFound(type_name)
    return proto.read_payload(r)


# --- map keys -----------------------------------------------------------

_MAP_KEY_READ: dict[str, Callable[[Reader], AnyValue]] = {
    "string16": Reader.string16,
    "uint8": Reader.uint8,
    "uint16": Reader.uint16,
    "uint32": Reader.uint32,
    "uint64": Reader.uint64,
}

_MAP_KEY_WRITE: dict[str, Callable[[Writer, AnyValue], None]] = {
    "string16": Writer.string16,
    "uint8": Writer.uint8,
    "uint16": Writer.uint16,
    "uint32": Writer.uint32,
    "uint64": Writer.uint64,
}


def _write_map_key(w: Writer, key_type: str, key: AnyValue) -> None:
    if key_type == "string16":
        if not isinstance(key, str):
            raise SchemaError(f"map key: {type(key).__name__} is not a string16 key")
    else:
        if isinstance(key, bool) or not isinstance(key, int):
            raise SchemaError(f"map key: {type(key).__name__} is not a {key_type} key")
    _MAP_KEY_WRITE[key_type](w, key)


# --- the walker ---------------------------------------------------------


def write_spec(w: Writer, spec: Spec, value: AnyValue) -> None:
    """Write one field's payload from its spec."""
    if isinstance(spec, Primitive):
        if value is None:
            raise SchemaError(f"Primitive({spec.name}): value is required")
        SCALARS[spec.name].write(w, value)
        return

    if isinstance(spec, Ref):
        _write_named(w, spec.type, value)
        return

    if isinstance(spec, Ptr):
        if value is None:
            w.flag(False)
            return
        w.flag(True)
        _write_named(w, spec.type, value)
        return

    if isinstance(spec, Any):
        _write_any(w, value)
        return

    if isinstance(spec, Slice):
        items = () if value is None else value
        w.uint32(len(items))
        for item in items:
            _write_element(w, spec.type, item)
        return

    if isinstance(spec, Array):
        items = list(() if value is None else value)
        if len(items) != spec.length:
            raise ValueTooLarge(
                f"Array({spec.type}, {spec.length}): got {len(items)} elements"
            )
        for item in items:
            _write_element(w, spec.type, item)
        return

    if isinstance(spec, Map):
        _write_map(w, spec, {} if value is None else value)
        return

    raise SchemaError(f"unknown spec {type(spec).__name__}")


def read_spec(r: Reader, spec: Spec) -> AnyValue:
    """Read one field's payload from its spec."""
    if isinstance(spec, Primitive):
        return SCALARS[spec.name].read(r)

    if isinstance(spec, Ref):
        return _read_named(r, spec.type)

    if isinstance(spec, Ptr):
        if not r.flag():
            return None
        return _read_named(r, spec.type)

    if isinstance(spec, Any):
        return _read_any(r)

    if isinstance(spec, Slice):
        # No pre-allocation: a hostile count must cost bytes, not gigabytes.
        # Every element consumes at least one byte -- the synthesized presence
        # byte, or the type tag of a heterogeneous element -- so a count beyond
        # the frame aborts on ShortRead.
        count = r.uint32()
        out: list[AnyValue] = []
        for _ in range(count):
            out.append(_read_element(r, spec.type))
        return out

    if isinstance(spec, Array):
        return [_read_element(r, spec.type) for _ in range(spec.length)]

    if isinstance(spec, Map):
        return _read_map(r, spec)

    raise SchemaError(f"unknown spec {type(spec).__name__}")


def _write_any(w: Writer, value: AnyValue) -> None:
    if value is None:
        w.string8("")
        return
    type_name = getattr(value, "ASTRAL_TYPE", "")
    if not type_name:
        raise SchemaError(
            f"polymorphic field: {type(value).__name__} has no object type"
        )
    w.string8(type_name)
    value.write_payload(w)


def _read_any(r: Reader) -> AnyValue:
    type_name = r.string8()
    if type_name == "" or type_name == _RUNTIME_NIL_TAG:
        return None
    return read_object(r, type_name)


def _write_element(w: Writer, type_name: str, value: AnyValue) -> None:
    """One slice element, array element or map value.

    A named element type gets the synthesized `0x01`; an empty element type is
    heterogeneous and carries its own tag instead. `None` is the value
    `_read_element` produces from a `0x00` element, and writing `0x00` back is
    what keeps that decode exact -- it is also the byte astral-go's
    blueprint-built containers write for a nil `*T`.
    """
    if not type_name:
        _write_any(w, value)
        return
    if value is None:
        w.flag(False)
        return
    w.flag(True)
    _write_named(w, type_name, value)


def _read_element(r: Reader, type_name: str) -> AnyValue:
    if not type_name:
        return _read_any(r)
    if not r.flag():
        return None
    return _read_named(r, type_name)


def _write_map(w: Writer, spec: Map, value: AnyValue) -> None:
    items = value.items() if hasattr(value, "items") else value
    pairs: list[tuple[bytes, bytes]] = []
    for key, item in items:
        key_buf = Writer()
        _write_map_key(key_buf, spec.key, key)
        value_buf = ObjectWriter(depth=getattr(w, "depth", 0))
        _write_element(value_buf, spec.value, item)
        pairs.append((key_buf.getvalue(), value_buf.getvalue()))

    pairs.sort(key=lambda pair: pair[0])
    w.uint32(len(pairs))
    for key_bytes, value_bytes in pairs:
        w.raw(key_bytes)
        w.raw(value_bytes)


def _read_map(r: Reader, spec: Map) -> dict[AnyValue, AnyValue]:
    count = r.uint32()
    read_key = _MAP_KEY_READ[spec.key]
    out: dict[AnyValue, AnyValue] = {}
    for _ in range(count):
        key = read_key(r)
        out[key] = _read_element(r, spec.value)
    return out


# --- records ------------------------------------------------------------


def write_fields(w: Writer, fields: Sequence[FieldTriple], obj: AnyValue) -> None:
    """Write every field of a record in declaration order.

    Field names never reach the binary wire. Order is the schema.
    """
    saved = _enter(w, type(obj).__name__)
    try:
        for attr, _wire_name, spec in fields:
            write_spec(w, spec, getattr(obj, attr))
    finally:
        _leave(w, saved)


def read_fields(r: Reader, fields: Sequence[FieldTriple]) -> dict[str, AnyValue]:
    """Read every field of a record in declaration order, keyed by attribute."""
    saved = _enter(r, "record")
    try:
        return {attr: read_spec(r, spec) for attr, _wire_name, spec in fields}
    finally:
        _leave(r, saved)


def payload_bytes(obj: AnyValue) -> bytes:
    """One object's payload: no type tag, no length prefix."""
    w = ObjectWriter()
    obj.write_payload(w)
    return w.getvalue()


# --- spec zero ----------------------------------------------------------


def spec_zero(spec: Spec, registry: Blueprints | None = None) -> AnyValue:
    """The zero value of a spec.

    A record's field defaults to this, so declaration order is never
    constrained by dataclass default rules. `Ref` resolves through the registry
    and yields `None` for a type that is not registered yet, which is what
    astral-go's `New` does for an unknown name.
    """
    if isinstance(spec, Primitive):
        return SCALARS[spec.name].zero()
    if isinstance(spec, Ref):
        found = _scalar(spec.type)
        if found is not None:
            return found.zero()
        return (registry or default_blueprints()).new(spec.type)
    if isinstance(spec, Slice):
        return []
    if isinstance(spec, Array):
        return [_element_zero(spec.type, registry) for _ in range(spec.length)]
    if isinstance(spec, Map):
        return {}
    if isinstance(spec, (Ptr, Any)):
        return None
    raise SchemaError(f"unknown spec {type(spec).__name__}")


def _element_zero(type_name: str, registry: Blueprints | None) -> AnyValue:
    if not type_name:
        return None
    return spec_zero(Ref(type_name), registry)
