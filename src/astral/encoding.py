"""Text encoding, query-string assembly, JSON envelopes, and zones.

* Text encoding: ``topics/text-encoding.md`` and ``core-primitives/query-string.md``.
* JSON encoding: ``topics/json-encoding.md``.
* Zones: ``topics/astral-ipc.md`` (``dvn`` / device / network / virtual).
"""

from __future__ import annotations

import base64
from typing import Any, Mapping, Optional
from urllib.parse import quote

from .errors import EncodingError
from .objectid import ObjectID
from .objects import AstralObject

__all__ = [
    "Zone",
    "to_text",
    "build_query_string",
    "to_json_envelope",
    "from_json_envelope",
    "text_encode_object",
    "MAX_QUERY_STRING",
]

# A Query String can be up to 255 bytes long (``core-primitives/query-string.md``).
MAX_QUERY_STRING = 255


class Zone:
    """Network zones, encoded as a bitmask of device/virtual/network.

    JSON and text transports use the lowercase-letter string form (e.g.
    ``"dvn"``); the binary transport uses the single-byte mask. The default
    used by the reference client is all three zones (``"dvn"``).
    """

    DEVICE = 1
    VIRTUAL = 2
    NETWORK = 4
    ALL = DEVICE | VIRTUAL | NETWORK

    _LETTERS = (("d", DEVICE), ("v", VIRTUAL), ("n", NETWORK))

    DEFAULT = "dvn"

    @classmethod
    def to_mask(cls, zone: "ZoneLike") -> int:
        """Coerce a zone (string like ``"dvn"`` or int mask) to an int mask."""
        if isinstance(zone, int):
            return zone & cls.ALL
        mask = 0
        for ch in zone.lower():
            for letter, bit in cls._LETTERS:
                if ch == letter:
                    mask |= bit
                    break
            else:
                if ch not in " ,|":
                    raise EncodingError(f"unknown zone flag: {ch!r}")
        return mask

    @classmethod
    def to_string(cls, zone: "ZoneLike") -> str:
        """Coerce a zone to its canonical letter string (e.g. ``"dvn"``)."""
        if isinstance(zone, str):
            zone = cls.to_mask(zone)
        return "".join(letter for letter, bit in cls._LETTERS if zone & bit)


ZoneLike = Any  # str | int


def to_text(value: Any) -> str:
    """Render a Python value as the type-specific *Text Encoding* payload.

    Used for query-string parameter values (``core-primitives/query-string.md``),
    which carry only the payload, not the ``#[type]`` prefix.
    """
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return value
    if isinstance(value, ObjectID):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if value is None:
        return ""
    if isinstance(value, AstralObject):
        # Use the payload-only form for whatever the value holds.
        return to_text(value.value)
    raise EncodingError(f"cannot text-encode value of type {type(value).__name__}")


def build_query_string(op: str, args: Optional[Mapping[str, Any]] = None) -> str:
    """Assemble ``operation?k=v&...`` with URL-encoded, text-encoded values.

    ``None`` argument values are skipped. Raises if the result exceeds the
    255-byte query-string limit.
    """
    query = op
    if args:
        parts = []
        for key, value in args.items():
            if value is None:
                continue
            parts.append(f"{quote(str(key), safe='')}={quote(to_text(value), safe='')}")
        if parts:
            query = op + "?" + "&".join(parts)
    if len(query.encode("utf-8")) > MAX_QUERY_STRING:
        raise EncodingError(
            f"query string exceeds {MAX_QUERY_STRING} bytes: {query!r}"
        )
    return query


def text_encode_object(obj: AstralObject) -> str:
    """Full *Text Encoding* of an object: ``#[type]`` + sep + payload.

    Uses the Base64 form (``:`` separator) for untyped/byte payloads and the
    type-specific form (`` `` separator) for everything else.
    """
    value = obj.value
    if obj.type == "" or isinstance(value, (bytes, bytearray)):
        raw = value if isinstance(value, (bytes, bytearray)) else b""
        return f"#[{obj.type}]:" + base64.b64encode(bytes(raw)).decode("ascii")
    return f"#[{obj.type}] " + to_text(value)


def to_json_envelope(obj: AstralObject) -> dict:
    """Encode an object as a JSON envelope ``{"Type": ..., "Object": ...}``."""
    value = obj.value
    if obj.is_ack or obj.is_eos or value is None:
        return {"Type": obj.type, "Object": None}
    if hasattr(value, "encode_json") and hasattr(value, "FIELDS"):
        # A typed Record: serialize to its JSON value form — the send counterpart
        # of Record.from_value on decode.
        return {"Type": obj.type, "Object": value.encode_json()}
    if isinstance(value, (bytes, bytearray)):
        raise EncodingError(
            f"cannot JSON-encode raw bytes for type {obj.type!r}; "
            "use the binary transport for untyped blobs"
        )
    return {"Type": obj.type, "Object": value}


def from_json_envelope(envelope: Mapping[str, Any]) -> AstralObject:
    """Decode a JSON envelope into an :class:`AstralObject`."""
    if "Type" not in envelope:
        raise EncodingError(f"JSON envelope missing 'Type': {envelope!r}")
    return AstralObject(envelope["Type"], envelope.get("Object"))
