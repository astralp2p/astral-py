"""ObjectID derivation: the canonical form and the two hashing paths.

An ObjectID is `uint64 size ++ sha256(preimage)`, and **what the preimage is
depends on whether the object has a type**. The two paths are separate functions
here because conflating them is exactly the defect astral-go carries:
`ResolveObjectID` always writes the stamp and the type header, so on an untyped
`Blob(b"hello")` it hashes `ADC0 ++ 0x00 ++ hello` and reports size 10 where the
rest of the system -- the docs, `objects.create`, every content address a node
stores -- uses size 5 over the raw five bytes (design G-2, D-28). The docs win.

- Typed object: preimage = `Stamp ++ string8(type) ++ payload`, no length
  prefix. This is the canonical form, defined once in `codec.Canonical`.
- Untyped object: preimage = the raw payload. No stamp, no type, nothing else.

The text form (`data1` + zBase32, leading `y` stripped) lives on `ObjectID` in
`types.py`; nothing is re-derived here. The zero ID stringifies to a bare
`data1` because all 64 symbols are the zero symbol and every one of them is
stripped.
"""

from __future__ import annotations

import hashlib
from typing import Any as AnyValue
from typing import Protocol

from . import codec
from .codec.binary import payload_bytes
from .primitives import STAMP
from .types import ObjectID

__all__ = [
    "STAMP",
    "ByteStream",
    "canonical_form",
    "object_id",
    "object_id_of",
    "object_id_of_bytes",
    "object_id_of_stream",
    "preimage",
]

# The read size for the streaming path. It cannot affect the digest, so it is
# tuned for syscall count alone.
_CHUNK = 1 << 16


class ByteStream(Protocol):
    """A blocking synchronous byte source: `read(n)` short-reads, `b""` at EOF."""

    def read(self, size: int = ..., /) -> bytes: ...


def canonical_form(obj: AnyValue) -> bytes:
    """`Stamp ++ string8(type) ++ payload`. Raises `SchemaError` if untyped.

    The canonical form has no length delimiter anywhere, so it is a preimage and
    a stream terminator, never a frame.
    """
    return codec.canonical_bytes(obj)


def preimage(type_name: str, payload: bytes) -> bytes:
    """The bytes an ObjectID is taken over, chosen by typed-ness.

    The byte-level form of the same branch `object_id_of` takes over objects.
    """
    if not type_name:
        return bytes(payload)
    return codec.canonical(type_name, payload)


def object_id(obj: AnyValue) -> ObjectID:
    """The ID of a typed object: size and sha256 over its canonical form.

    Raises `SchemaError` on an empty `ASTRAL_TYPE`. An untyped object has no
    canonical form at all -- call `object_id_of_bytes` on its payload instead.
    """
    data = canonical_form(obj)
    return ObjectID(size=len(data), hash=hashlib.sha256(data).digest())


def object_id_of_bytes(data: bytes) -> ObjectID:
    """The ID of untyped bytes: size and sha256 over the bytes themselves."""
    return ObjectID(size=len(data), hash=hashlib.sha256(data).digest())


def object_id_of_stream(stream: ByteStream) -> ObjectID:
    """The ID of an untyped byte stream, read to EOF without buffering it.

    The path `objects.create` and `objects.read` take: an object large enough to
    need an ID is too large to hold in memory.
    """
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return ObjectID(size=size, hash=digest.digest())


def object_id_of(obj: AnyValue) -> ObjectID:
    """The ID of any object, typed or not.

    The branch point. A typed object hashes its canonical form; an untyped one
    hashes its raw payload.
    """
    if getattr(obj, "ASTRAL_TYPE", ""):
        return object_id(obj)
    return object_id_of_bytes(payload_bytes(obj))
