"""Encode/decode the *Payload* of common typed objects for the binary channel.

A channel frame is ``string8(type) ++ bytes32(payload)`` where ``payload`` is
the object's type-specific *Payload* — exactly the encoding described in the
relevant ``common-types/`` doc. For example ``Payload(uint8 21) == b"\\x15"``
and ``Payload(string8 "hi") == b"\\x02hi"`` (the generic ``object`` example in
``common-types/object.md`` confirms the uint8 case).

Only the documented common types are decoded to Python values; anything else is
returned as raw :class:`bytes` so unknown/structured payloads still round-trip.
JSON transports (HTTP/WebSocket) do not use this module — their values are
self-describing.
"""

from __future__ import annotations

from typing import Any

from .codec import BinaryReader, BinaryWriter
from .errors import EncodingError
from .objectid import ObjectID
from .objects import AstralObject
from .registry import record_for

__all__ = ["encode_payload", "decode_payload"]

_INT_KINDS = {
    "uint8": ("u8", "u8"),
    "uint16": ("u16", "u16"),
    "uint32": ("u32", "u32"),
    "uint64": ("u64", "u64"),
    "int8": ("i8", "i8"),
    "int16": ("i16", "i16"),
    "int32": ("i32", "i32"),
    "int64": ("i64", "i64"),
}

_STRING_KINDS = {
    "string8": ("string8", "string8"),
    "string16": ("string16", "string16"),
    "string32": ("string32", "string32"),
    "string64": ("string64", "string64"),
}

_OBJECT_ID_TYPES = {"object_id.sha256", "object_id"}


def encode_payload(obj_type: str, value: Any) -> bytes:
    """Encode the payload of an object of ``obj_type`` carrying ``value``."""
    if obj_type in ("", "ack", "eos"):
        if obj_type == "":
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
            if value is None:
                return b""
            raise EncodingError("untyped object payload must be bytes")
        return b""

    writer = BinaryWriter()

    if obj_type in _INT_KINDS:
        getattr(writer, _INT_KINDS[obj_type][0])(int(value))
        return writer.getvalue()

    if obj_type in _STRING_KINDS:
        getattr(writer, _STRING_KINDS[obj_type][0])(str(value))
        return writer.getvalue()

    if obj_type == "bool":
        return writer.boolean(bool(value)).getvalue()

    if obj_type == "error_message":
        return writer.string16(str(value)).getvalue()

    if obj_type == "identity":
        return writer.identity(value or "").getvalue()

    if obj_type == "nonce64":
        return writer.nonce(value).getvalue()

    if obj_type == "time":
        return writer.u64(int(value)).getvalue()

    if obj_type in _OBJECT_ID_TYPES:
        oid = value if isinstance(value, ObjectID) else ObjectID.parse(str(value))
        return oid.to_bytes()

    if obj_type == "object":  # generic typed object, self-delimiting
        if not isinstance(value, AstralObject):
            raise EncodingError("'object' payload requires an AstralObject value")
        return (
            BinaryWriter().string8(value.type).getvalue()
            + encode_payload(value.type, value.value)
        )

    # Registered structured type: encode a typed Record via its own write_to —
    # the send counterpart of decode_payload's read_from dispatch.
    record_cls = record_for(obj_type)
    if record_cls is not None and isinstance(value, record_cls):
        return value.encode_binary()

    # Unknown/structured type: accept pre-encoded raw bytes.
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise EncodingError(
        f"don't know how to binary-encode payload for type {obj_type!r}; "
        "pass raw bytes or use a JSON transport"
    )


def decode_payload(obj_type: str, payload: bytes) -> Any:
    """Decode the payload of an object of ``obj_type`` to a Python value."""
    if obj_type == "":
        return payload
    if obj_type in ("ack", "eos"):
        return None

    reader = BinaryReader(payload)

    if obj_type in _INT_KINDS:
        return getattr(reader, _INT_KINDS[obj_type][1])()

    if obj_type in _STRING_KINDS:
        return getattr(reader, _STRING_KINDS[obj_type][1])()

    if obj_type == "bool":
        return reader.boolean()

    if obj_type == "error_message":
        return reader.string16()

    if obj_type == "identity":
        return reader.identity()

    if obj_type == "nonce64":
        return reader.nonce()

    if obj_type == "time":
        return reader.u64()

    if obj_type in _OBJECT_ID_TYPES:
        return ObjectID(reader.u64(), reader.raw(32))

    if obj_type == "object":
        inner_type = reader.string8()
        return AstralObject(inner_type, decode_payload(inner_type, reader.remaining()))

    # Registered structured type: decode it to a typed Record over the binary
    # channel (``reader`` is positioned at the start of the payload). This is
    # what lets structured objects decode over binary IPC, not only over JSON.
    record_cls = record_for(obj_type)
    if record_cls is not None:
        return record_cls.read_from(reader)

    # Unknown/structured type: hand back the raw payload bytes.
    return payload
