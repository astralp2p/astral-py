"""The :class:`AstralObject` value type and small constructors.

An *Object* on the Astral Network (``core-primitives/object.md``) is an
optional *Object Type* plus an optional *Payload*. This module models one as a
``(type, value)`` pair, matching the friendly shape used by the reference
``apphost-js`` client (``{ type, value }``).

The meaning of ``value`` depends on how the object was produced:

* JSON transports (HTTP / WebSocket) decode the ``"Object"`` field of the
  envelope, so ``value`` is a plain Python value (``str``, ``int``, ``float``,
  ``bool``, ``None``, ``dict`` or ``list``).
* The binary transport decodes known common types into Python values and
  leaves unknown/structured types as raw :class:`bytes` (the object's payload).
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import RemoteError

__all__ = [
    "AstralObject",
    "obj",
    "ack",
    "eos",
    "error",
    "blob",
    "EOS",
    "ACK",
    "EMPTY",
]


class AstralObject:
    """A typed (or untyped) Astral object: an object type and a value.

    An empty ``type`` denotes an *Untyped Object* — a raw binary blob whose
    ``value`` is :class:`bytes`.
    """

    __slots__ = ("type", "value")

    def __init__(self, type: str, value: Any = None) -> None:
        self.type = type
        self.value = value

    # -- predicates ---------------------------------------------------------
    @property
    def is_eos(self) -> bool:
        """True if this object marks the end of a stream (``eos``)."""
        return self.type in ("eos", "astral.eos")

    @property
    def is_ack(self) -> bool:
        """True if this is a generic acknowledgement (``ack``)."""
        return self.type in ("ack", "astral.ack")

    @property
    def is_error(self) -> bool:
        """True if this is an ``error_message`` object."""
        return self.type == "error_message"

    @property
    def is_empty(self) -> bool:
        """True if this is the *Empty Object* (no type and no payload)."""
        return self.type == "" and not self.value

    @property
    def is_untyped(self) -> bool:
        """True if this is an *Untyped Object* (no type)."""
        return self.type == ""

    # -- helpers ------------------------------------------------------------
    def raise_for_error(self) -> "AstralObject":
        """Raise :class:`RemoteError` if this is an ``error_message``.

        Returns ``self`` otherwise, so it can be chained.
        """
        if self.is_error:
            raise RemoteError(str(self.value))
        return self

    def unwrap(self) -> Any:
        """Return ``value`` after raising on ``error_message`` objects."""
        self.raise_for_error()
        return self.value

    # -- dunder -------------------------------------------------------------
    def __repr__(self) -> str:
        v = self.value
        if isinstance(v, (bytes, bytearray)):
            shown: Any = f"<{len(v)} bytes>"
        else:
            shown = v
        label = self.type or "<untyped>"
        return f"AstralObject({label!r}, {shown!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AstralObject):
            return NotImplemented
        return self.type == other.type and self.value == other.value

    def __hash__(self) -> int:
        v = self.value
        if isinstance(v, (bytes, bytearray)):
            v = bytes(v)
        try:
            return hash((self.type, v))
        except TypeError:  # unhashable value (dict/list)
            return hash(self.type)


# --- constructors -----------------------------------------------------------


def obj(type: str, value: Any = None) -> AstralObject:
    """Build a typed object, e.g. ``obj("string8", "hello")``."""
    return AstralObject(type, value)


def ack() -> AstralObject:
    """The generic acknowledgement object (``ack``)."""
    return AstralObject("ack", None)


def eos() -> AstralObject:
    """The end-of-stream marker object (``eos``)."""
    return AstralObject("eos", None)


def error(message: str) -> AstralObject:
    """An ``error_message`` object carrying ``message``."""
    return AstralObject("error_message", message)


def blob(data: bytes) -> AstralObject:
    """An untyped binary object (an *Untyped Object*) wrapping ``data``."""
    return AstralObject("", bytes(data))


# Convenient singletons for the payload-less control objects.
EOS = eos()
ACK = ack()
EMPTY = AstralObject("", b"")
