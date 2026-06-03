"""Object IDs and the zBase32 alphabet used to render them.

Reference: ``core-primitives/object-id.md`` and
``common-types/object_id.sha256.md``.

An *Object ID* is a 320-bit value: an ``Object Size`` (``uint64``) followed by
the ``Object Hash`` (SHA-256 of the object's *Binary Encoding*). It is rendered
as zBase32 with the leading ``y`` characters removed and a ``data1`` prefix.

The *Binary Encoding* that is hashed includes the *Object Header* —
``Stamp ++ string8(type)`` — only when the object is typed; an untyped object
hashes its payload directly (``topics/binary-encoding.md``).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .codec import BinaryWriter
from .errors import EncodingError

__all__ = [
    "STAMP",
    "ObjectID",
    "compute_object_id",
    "object_binary_encoding",
    "zbase32_encode",
    "zbase32_decode",
]

# "magic bytes" that prefix a typed object's binary encoding
# (``core-primitives/stamp.md``): 0x41444330 == b"ADC0".
STAMP = struct.pack(">I", 0x41444330)

_ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
_ZBASE32_REVERSE = {c: i for i, c in enumerate(_ZBASE32_ALPHABET)}

_ID_PREFIX = "data1"
_ID_BYTES = 40  # uint64 size (8) + sha256 hash (32)
_ID_CHARS = 64  # 320 bits / 5 bits per zbase32 char


def zbase32_encode(data: bytes) -> str:
    """Encode bytes as zBase32 (MSB-first), using the Astral alphabet."""
    bits = 0
    nbits = 0
    out = []
    for byte in data:
        bits = (bits << 8) | byte
        nbits += 8
        while nbits >= 5:
            nbits -= 5
            out.append(_ZBASE32_ALPHABET[(bits >> nbits) & 0x1F])
    if nbits:
        out.append(_ZBASE32_ALPHABET[(bits << (5 - nbits)) & 0x1F])
    return "".join(out)


def zbase32_decode(text: str) -> bytes:
    """Decode a zBase32 string (MSB-first) using the Astral alphabet."""
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in text:
        try:
            bits = (bits << 5) | _ZBASE32_REVERSE[ch]
        except KeyError:
            raise EncodingError(f"invalid zbase32 character: {ch!r}") from None
        nbits += 5
        if nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)


def object_binary_encoding(payload: bytes, obj_type: str = "") -> bytes:
    """Return the *Binary Encoding* of an object (header for typed objects)."""
    writer = BinaryWriter()
    if obj_type:
        writer.raw(STAMP).string8(obj_type)
    writer.raw(payload)
    return writer.getvalue()


@dataclass(frozen=True)
class ObjectID:
    """A content address: the size and SHA-256 hash of an object's encoding."""

    size: int
    hash: bytes  # 32-byte SHA-256 digest

    def __post_init__(self) -> None:
        if len(self.hash) != 32:
            raise EncodingError("object hash must be 32 bytes")

    def to_bytes(self) -> bytes:
        """The raw 40-byte representation: ``uint64(size) ++ hash``."""
        return struct.pack(">Q", self.size) + self.hash

    def __str__(self) -> str:
        return _ID_PREFIX + zbase32_encode(self.to_bytes()).lstrip("y")

    def __repr__(self) -> str:
        return f"ObjectID({str(self)!r})"

    @classmethod
    def parse(cls, text: str) -> "ObjectID":
        """Parse a ``data1...`` object-id string."""
        if not text.startswith(_ID_PREFIX):
            raise EncodingError(f"object id must start with {_ID_PREFIX!r}")
        body = text[len(_ID_PREFIX) :]
        if len(body) > _ID_CHARS:
            raise EncodingError("object id is too long")
        # Leading "y" (zero) characters were stripped on encoding; restore them.
        raw = zbase32_decode(body.rjust(_ID_CHARS, "y"))[:_ID_BYTES]
        if len(raw) != _ID_BYTES:
            raise EncodingError("object id has wrong length")
        size = struct.unpack(">Q", raw[:8])[0]
        return cls(size, raw[8:_ID_BYTES])


def compute_object_id(payload: bytes, obj_type: str = "") -> ObjectID:
    """Compute the :class:`ObjectID` of an object from its payload and type."""
    encoding = object_binary_encoding(payload, obj_type)
    return ObjectID(len(encoding), hashlib.sha256(encoding).digest())
