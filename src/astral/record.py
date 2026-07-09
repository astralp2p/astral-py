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
JSON/object key, and ``kind`` is a common-type tag (``common-types/``) — the same
vocabulary :mod:`astral.messages` uses for the apphost control messages.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Tuple

from .codec import BinaryReader, BinaryWriter
from .errors import ProtocolError
from .objectid import ObjectID

__all__ = ["Record"]

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


def _write_field(writer: BinaryWriter, kind: str, value: Any) -> None:
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


def _read_field(reader: BinaryReader, kind: str) -> Any:
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


def _field_from_json(kind: str, value: Any) -> Any:
    if kind in _INT_RW:
        return int(value) if value is not None else 0
    if kind == "bool":
        return bool(value)
    if value is None and (kind in _STRING_KINDS or kind in ("identity", "nonce64", "time")):
        return ""
    return value


def _field_to_json(kind: str, value: Any) -> Any:
    return value


@dataclass(frozen=True)
class Record:
    """Base for structured wire records; see the module docstring."""

    TYPE: ClassVar[str] = ""
    #: ordered ``(python_attr, wire_name, kind)`` field schema.
    FIELDS: ClassVar[Tuple[Tuple[str, str, str], ...]] = ()

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
