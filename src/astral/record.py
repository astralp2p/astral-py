"""Typed structured records over the binary and JSON framings.

Master decodes only the documented common types over the binary channel; any
structured object comes back as raw bytes (see
:func:`astral.payload.decode_payload`), so the one structured type today —
``apphost.access_token`` — could be decoded only over a JSON transport. This
module generalizes master's ``AccessToken.from_value(dict)`` into a shared
:class:`Record` base carrying an ordered field schema (``FIELDS``), giving every
registered record three façades over one schema:

* :meth:`Record.from_value` — the JSON/text path (PascalCase wire keys), plus an
  idempotent pass-through when handed an already-decoded record.
* :meth:`Record.read_from` / :meth:`Record.write_to` — the per-type binary
  schema, so structured objects decode over the native binary IPC path, not only
  over JSON. This is the addition the transport decision demands: registered
  records are dispatched from :func:`astral.payload.decode_payload`.
* :meth:`Record.encode_json` — the JSON-envelope value form.

``FIELDS`` entries are ``(python_attr, wire_name, kind)`` triples: the Python
attribute is snake_case (the friendly SDK API), the wire name is the PascalCase
JSON/object key, and ``kind`` is either a scalar common-type tag (``common-types/``,
the same vocabulary :mod:`astral.messages` uses for the apphost control messages) or
a COMPOSITE tuple that recurses into an element/inner kind or nested :class:`Record`
class — ``("array", elem_kind)``, ``("record", RecordClass)``, ``("bytes", nbits)``,
``("ptr", inner_kind)`` and the OPAQUE ``("bundle",)``. Composite kinds let structured
astral-go objects with slices, embedded structs, byte fields, nullable pointers and
opaque bundles (``mod.auth.contract``, ``mod.auth.signed_contract``,
``mod.crypto.signature``, ``mod.auth.permit``) decode over both framings; see the
``Kind`` note below for the exact wire layouts.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, ClassVar, Tuple, Union

from .codec import BinaryReader, BinaryWriter
from .errors import ProtocolError
from .objectid import ObjectID

__all__ = ["Record"]

# A field ``kind`` is either a scalar tag (a ``str``, e.g. ``"uint32"``) or a
# COMPOSITE tag: a tuple whose first element names the composite and whose tail
# carries the element/inner kind or nested :class:`Record` class. The four kinds:
#
# * ``("array", elem_kind)`` — ``uint32`` count then each element, matching astral-go
#   ``sliceValue``: a ``0x01`` presence byte precedes each *value-kind* element;
#   ``("ptr", …)`` elements are exempt (they carry their own nil-flag), so ``[]T`` and
#   ``[]*T`` share one wire form (see :func:`_elem_needs_presence`).
# * ``("record", RecordClass)`` — a nested :class:`Record` inlined via its own
#   ``read_from``/``write_to`` (no length prefix, self-delimiting; matches astral-go
#   ``structValue`` which writes a struct's fields in order with no framing).
# * ``("bytes", nbits)`` / ``("bytes",)`` — a length-prefixed byte field
#   (astral ``bytes8``/``bytes16``/…: an ``nbits``-bit length then the raw bytes;
#   ``nbits`` defaults to 8). JSON form is a base64 ``str`` (see the live-node note).
# * ``("ptr", inner_kind)`` — a Go nullable pointer field: a ``bool`` presence flag
#   (``0x01`` then the inner value, or a single ``0x00`` when nil), matching
#   astral-go ``ptrValue``. JSON ``None`` means nil.
# * ``("bundle",)`` — an OPAQUE ``astral.Bundle`` (astral-go ``astral/bundle.go``):
#   ``uint32`` count then each contained object as a ``bytes32``-framed blob. This
#   codec is a PASSTHROUGH: it preserves the framed blobs for a byte-exact
#   round-trip but does NOT decode the inner objects (a faithful decode needs the
#   whole Blueprint/registry path). The Python value is a ``list[bytes]`` of the raw
#   per-object blobs; JSON carries the same list through unchanged.
Kind = Union[str, tuple]

# kind -> (BinaryWriter method, BinaryReader method) for the fixed-width integer
# kinds. String kinds share their name with the writer/reader method.
_INT_RW = {
    "uint8": ("u8", "u8"),
    "uint16": ("u16", "u16"),
    "uint32": ("u32", "u32"),
    "uint64": ("u64", "u64"),
    "int8": ("i8", "i8"),
    "int16": ("i16", "i16"),
    "int32": ("i32", "i32"),
    "int64": ("i64", "i64"),
}
_STRING_KINDS = {"string8", "string16", "string32", "string64"}
_OBJECT_ID_KINDS = {"object_id.sha256", "object_id"}

# ``bytesN`` writer/reader method names on BinaryWriter/BinaryReader, keyed by the
# length-prefix width in bits.
_BYTES_RW = {8: "bytes8", 16: "bytes16", 32: "bytes32", 64: "bytes64"}


def _bytes_bits(kind: tuple) -> int:
    """Return the length-prefix width for a ``("bytes", nbits)`` / ``("bytes",)`` kind."""
    bits = kind[1] if len(kind) > 1 else 8
    if bits not in _BYTES_RW:
        raise ProtocolError(f"record field: bytes width {bits!r} must be one of {sorted(_BYTES_RW)}")
    return bits


def _to_bytes(value: Any) -> bytes:
    """Coerce a ``bytes`` field's Python value to raw bytes for the binary wire.

    Accepts raw ``bytes``/``bytearray`` (stored form and the recommended in-memory
    form), a base64 ``str`` (the JSON form — see the live-node note), or an iterable
    of ints (the JSON int-array alternative). ``None`` is the empty byte string.
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value)
    return bytes(value)


def _elem_needs_presence(elem_kind: "Kind") -> bool:
    """Whether an array synthesises a ``0x01`` presence byte before each element.

    Mirrors astral-go's ``elemNeedsPresenceFlag`` (``objectify.go`` / ``slice_value.go``):
    value-kind elements get the byte; ``("ptr", …)`` elements frame themselves with
    their own nil-flag and are exempt, so ``[]T`` and ``[]*T`` share one wire form.
    """
    return not (isinstance(elem_kind, tuple) and elem_kind[0] == "ptr")


def _write_field(writer: BinaryWriter, kind: Kind, value: Any) -> None:
    if isinstance(kind, tuple):
        tag = kind[0]
        if tag == "array":
            elem_kind = kind[1]
            items = value or []
            writer.u32(len(items))
            flagged = _elem_needs_presence(elem_kind)
            for item in items:
                if flagged:
                    writer.u8(1)  # per-element presence flag (astral-go sliceValue)
                _write_field(writer, elem_kind, item)
        elif tag == "record":
            record_cls = kind[1]
            (value if value is not None else record_cls()).write_to(writer)
        elif tag == "bytes":
            getattr(writer, _BYTES_RW[_bytes_bits(kind)])(_to_bytes(value))
        elif tag == "ptr":
            inner_kind = kind[1]
            if value is None:
                writer.u8(0)
            else:
                writer.u8(1)
                _write_field(writer, inner_kind, value)
        elif tag == "bundle":
            # OPAQUE astral.Bundle: uint32(count) then each object as a
            # bytes32-framed blob. Passthrough — each item is a raw blob.
            items = value or []
            writer.u32(len(items))
            for blob in items:
                writer.bytes32(blob)
        else:
            raise ProtocolError(f"record field: unknown composite kind {tag!r}")
        return
    if kind in _INT_RW:
        getattr(writer, _INT_RW[kind][0])(int(value or 0))
    elif kind in _STRING_KINDS:
        getattr(writer, kind)(str(value or ""))
    elif kind == "bool":
        writer.boolean(bool(value))
    elif kind == "identity":
        writer.identity(value or "")
    elif kind == "nonce64":
        writer.nonce(value)
    elif kind == "time":
        # The ``time`` common type is encoded as a uint64 (as assumed in
        # astral.payload); the units are not yet confirmed against a live node.
        writer.u64(int(value or 0))
    elif kind in _OBJECT_ID_KINDS:
        oid = value if isinstance(value, ObjectID) else ObjectID.parse(str(value))
        writer.raw(oid.to_bytes())
    else:
        raise ProtocolError(f"record field: cannot binary-encode kind {kind!r}")


def _read_field(reader: BinaryReader, kind: Kind) -> Any:
    if isinstance(kind, tuple):
        tag = kind[0]
        if tag == "array":
            elem_kind = kind[1]
            count = reader.u32()
            flagged = _elem_needs_presence(elem_kind)
            out = []
            for _ in range(count):
                if flagged:
                    flag = reader.u8()
                    if flag != 1:
                        raise ProtocolError(
                            f"record field: invalid array presence flag {flag}"
                        )
                out.append(_read_field(reader, elem_kind))
            return out
        if tag == "record":
            return kind[1].read_from(reader)
        if tag == "bytes":
            return getattr(reader, _BYTES_RW[_bytes_bits(kind)])()
        if tag == "ptr":
            if reader.u8() == 0:
                return None
            return _read_field(reader, kind[1])
        if tag == "bundle":
            # OPAQUE astral.Bundle: uint32(count) then each object as a
            # bytes32-framed blob. Passthrough — return the raw blobs.
            count = reader.u32()
            return [reader.bytes32() for _ in range(count)]
        raise ProtocolError(f"record field: unknown composite kind {tag!r}")
    if kind in _INT_RW:
        return getattr(reader, _INT_RW[kind][1])()
    if kind in _STRING_KINDS:
        return getattr(reader, kind)()
    if kind == "bool":
        return reader.boolean()
    if kind == "identity":
        return reader.identity()
    if kind == "nonce64":
        return reader.nonce()
    if kind == "time":
        return reader.u64()
    if kind in _OBJECT_ID_KINDS:
        return ObjectID(reader.u64(), reader.raw(32))
    raise ProtocolError(f"record field: cannot binary-decode kind {kind!r}")


def _field_from_json(kind: Kind, value: Any) -> Any:
    if isinstance(kind, tuple):
        tag = kind[0]
        if tag == "array":
            elem_kind = kind[1]
            return [_field_from_json(elem_kind, v) for v in (value or [])]
        if tag == "record":
            # value may already be a decoded record (idempotent) or a dict.
            return kind[1].from_value(value) if value is not None else None
        if tag == "bytes":
            # JSON carries a base64 ``str`` (Go's default ``[]byte`` marshalling and
            # ``Signature`` text form); store the raw bytes. See the live-node note on
            # the base64-str-vs-int-array ambiguity.
            return _to_bytes(value) if value is not None else b""
        if tag == "ptr":
            return _field_from_json(kind[1], value) if value is not None else None
        if tag == "bundle":
            # OPAQUE passthrough: the inner objects are not decoded, so pass the
            # list through as-is (missing -> empty list).
            return list(value) if value is not None else []
        raise ProtocolError(f"record field: unknown composite kind {tag!r}")
    if kind in _INT_RW:
        return int(value) if value is not None else 0
    if kind == "bool":
        return bool(value)
    if value is None and (kind in _STRING_KINDS or kind in ("identity", "nonce64", "time")):
        return ""
    return value


def _field_to_json(kind: Kind, value: Any) -> Any:
    if isinstance(kind, tuple):
        tag = kind[0]
        if tag == "array":
            elem_kind = kind[1]
            return [_field_to_json(elem_kind, v) for v in (value or [])]
        if tag == "record":
            return value.encode_json() if value is not None else None
        if tag == "bytes":
            # Symmetric with ``_field_from_json``: emit a base64 ``str``.
            return base64.b64encode(_to_bytes(value)).decode("ascii")
        if tag == "ptr":
            return _field_to_json(kind[1], value) if value is not None else None
        if tag == "bundle":
            # OPAQUE passthrough: emit the list of blobs unchanged (see above).
            return list(value) if value is not None else []
        raise ProtocolError(f"record field: unknown composite kind {tag!r}")
    return value


@dataclass(frozen=True)
class Record:
    """Base for structured wire records; see the module docstring."""

    TYPE: ClassVar[str] = ""
    #: ordered ``(python_attr, wire_name, kind)`` field schema; ``kind`` is a scalar
    #: tag (``str``) or a composite tuple (see the ``Kind`` note at module top).
    FIELDS: ClassVar[Tuple[Tuple[str, str, Kind], ...]] = ()

    # -- decode -------------------------------------------------------------
    @classmethod
    def from_value(cls, value: Any) -> "Record":
        """Decode a record from a JSON ``dict`` or binary (``bytes``/reader).

        Passing an already-decoded record of this type returns it unchanged, so
        a protocol helper can call ``Record.from_value(client.call_one(...))``
        uniformly whether the transport handed back a dict (JSON) or a typed
        record (binary, via :func:`astral.payload.decode_payload`).
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(
                **{
                    attr: _field_from_json(kind, value.get(wire))
                    for attr, wire, kind in cls.FIELDS
                }
            )
        if isinstance(value, BinaryReader):
            return cls.read_from(value)
        if isinstance(value, (bytes, bytearray)):
            return cls.read_from(BinaryReader(bytes(value)))
        raise ProtocolError(f"cannot decode {cls.__name__} from {type(value).__name__}")

    @classmethod
    def read_from(cls, reader: BinaryReader) -> "Record":
        """Read the record's binary payload from ``reader`` (fields in ``FIELDS`` order)."""
        return cls(**{attr: _read_field(reader, kind) for attr, _wire, kind in cls.FIELDS})

    # -- encode -------------------------------------------------------------
    def write_to(self, writer: BinaryWriter) -> BinaryWriter:
        """Write the record's binary payload into ``writer``; returns it for chaining."""
        for attr, _wire, kind in self.FIELDS:
            _write_field(writer, kind, getattr(self, attr))
        return writer

    def encode_binary(self) -> bytes:
        """Return the record's binary payload bytes."""
        return self.write_to(BinaryWriter()).getvalue()

    def encode_json(self) -> Any:
        """Return the record as a JSON-envelope value (PascalCase wire keys)."""
        return {
            wire: _field_to_json(kind, getattr(self, attr))
            for attr, wire, kind in self.FIELDS
        }
