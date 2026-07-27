"""The text encoding: the `#[type] sep body` line, and the bare payload half.

Two related forms, and confusing them is the usual bug:

    #[uint8] 21                 a whole text-encoded object, header included
    21                          the bare payload half, which is what a
                                query-string parameter carries

A query-string parameter never carries the `#[type]` header: the parameter's
type comes from the operation's declaration, so it does not travel. `text_spec`
produces the bare half and `encode` produces the whole line.

The separator selects the body's encoding. astral-go's parser is wider than the
docs and the wider form is the one that must be honoured:

| Separator      | Body                                          |
|----------------|-----------------------------------------------|
| ` ` or `\\t`    | the type's own text form                      |
| `:` or `=`     | base64 of the binary payload                  |
| nothing        | no payload; the zero value                     |

Emission picks the text form whenever the type has one and base64 otherwise,
which is astral-go's `TextSender` and not what the docs describe:

- An untyped blob emits `#[] <base64>`, with a **space**, because `Blob`'s own
  text form is base64. The docs say `#[]:<base64>` with a colon. Both parse
  identically, so the docs are not wrong about the wire, only about the emitter.
- A zero-payload object emits `#[ack] ` -- header, space, empty body. The
  trailing space is the separator, not part of the object.
- A record has no text form at all, so `mod.dir.alias_map` emits
  `#[mod.dir.alias_map]:<base64>`. That is the live node's own output.
- `object_type` and `stamp` are registered scalars with **no** text form in
  astral-go, so they take the base64 branch on a channel. `object_type` still has
  a bare parameter form -- the raw string -- because a query parameter is matched
  by Go's field editor, not by the text channel.
"""

from __future__ import annotations

import math
import re
from typing import Any as AnyValue
from typing import Callable, Final, NamedTuple

from ..errors import BlueprintNotFound, ParseError, RangeError, SchemaError, StreamCorrupted
from ..registry import Blueprints, default_blueprints
from ..spec import Any, Array, Map, Primitive, Ptr, Ref, Slice, Spec
from ..types import Duration, Identity, Nonce, ObjectID, Size, Time, Zone
from .binary import object_reader, payload_bytes, read_object
from .jsoncodec import (
    FLOAT32_MAX,
    decode_base64,
    encode_base64,
    float_text,
    narrow_float32,
)

__all__ = [
    "BASE64_SEP",
    "BASE64_SEPS",
    "CHANNEL_TEXT_EXCLUDED",
    "ParsedText",
    "SCALAR_TEXT",
    "TEXT_SEP",
    "TEXT_SEPS",
    "TextScalar",
    "decode",
    "decode_line",
    "encode",
    "encode_line",
    "has_text_form",
    "parse_header",
    "read_text_scalar",
    "read_text_spec",
    "text_scalar",
    "text_spec",
    "to_text",
]

# The separators emission uses. Parsing accepts one more of each.
TEXT_SEP: Final = " "
BASE64_SEP: Final = ":"

TEXT_SEPS: Final = (" ", "\t")
BASE64_SEPS: Final = (":", "=")

_HEADER_OPEN: Final = "#["
_HEADER_CLOSE: Final = "]"

# Registered scalars astral-go gives no text marshaller, so a text channel must
# base64 them. Their bare parameter form still exists.
CHANNEL_TEXT_EXCLUDED: Final = frozenset({"object_type", "stamp"})

_UINT_TEXT: Final = re.compile(r"\A[0-9]+\Z")
_INT_TEXT: Final = re.compile(r"\A[+-]?[0-9]+\Z")

_TRUE: Final = frozenset({"true", "yes", "t", "y", "1"})
_FALSE: Final = frozenset({"false", "no", "f", "n", "0"})


class ParsedText(NamedTuple):
    """One text line split into its header, its separator's meaning and its body."""

    type: str
    encoding: str
    body: str


class TextScalar(NamedTuple):
    """One scalar type's text codec over plain Python values."""

    to: Callable[[AnyValue], str]
    of: Callable[[str], AnyValue]


# --- the scalar table ------------------------------------------------------


def _uint(name: str, bits: int) -> TextScalar:
    high = (1 << bits) - 1

    def to(value: AnyValue) -> str:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaError(f"{name}: {type(value).__name__} is not an integer")
        if not 0 <= value <= high:
            raise RangeError(f"{name}: {value} out of range")
        return str(int(value))

    def of(text: str) -> int:
        # Go's ParseUint rejects a sign outright, so `-1` is not a wrapped
        # maximum here; Python's int() would accept it, and underscores too.
        if not _UINT_TEXT.match(text):
            raise ParseError(f"{name}: {text!r} is not an unsigned decimal")
        value = int(text)
        if value > high:
            raise RangeError(f"{name}: {value} out of range")
        return value

    return TextScalar(to, of)


def _int(name: str, bits: int) -> TextScalar:
    low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1

    def to(value: AnyValue) -> str:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaError(f"{name}: {type(value).__name__} is not an integer")
        if not low <= value <= high:
            raise RangeError(f"{name}: {value} out of range")
        return str(int(value))

    def of(text: str) -> int:
        if not _INT_TEXT.match(text):
            raise ParseError(f"{name}: {text!r} is not a decimal")
        value = int(text)
        if not low <= value <= high:
            # astral-go parses every signed width through int8 and silently
            # overflows the wider ones; the design refuses to reproduce that.
            raise RangeError(f"{name}: {value} out of range")
        return value

    return TextScalar(to, of)


def _float(name: str, bits: int) -> TextScalar:
    def to(value: AnyValue) -> str:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SchemaError(f"{name}: {type(value).__name__} is not a number")
        number = float(value)
        if bits == 32 and not math.isinf(number) and abs(number) > FLOAT32_MAX:
            # The bound `Writer.float32` enforces. NaN and the infinities keep
            # Go's spellings and are excluded from it.
            raise RangeError(f"{name}: {number!r} out of range")
        return float_text(number, bits)

    def of(text: str) -> float:
        if "_" in text or text != text.strip():
            raise ParseError(f"{name}: {text!r} is not a number")
        try:
            number = float(text)
        except ValueError as exc:
            raise ParseError(f"{name}: {text!r} is not a number") from exc
        # Go parses at bit size 32, so `3.4028235e+38` is FLT_MAX and not a
        # double slightly above it, which nothing could then encode.
        return number if bits != 32 else narrow_float32(name, number)

    return TextScalar(to, of)


def _string(name: str) -> TextScalar:
    def to(value: AnyValue) -> str:
        if not isinstance(value, str):
            raise SchemaError(f"{name}: {type(value).__name__} is not a string")
        return str(value)

    return TextScalar(to, str)


def _bytes(name: str) -> TextScalar:
    def to(value: AnyValue) -> str:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise SchemaError(f"{name}: {type(value).__name__} is not bytes")
        return encode_base64(bytes(value))

    return TextScalar(to, decode_base64)


def _boolean() -> TextScalar:
    def to(value: AnyValue) -> str:
        return "true" if value else "false"

    def of(text: str) -> bool:
        folded = text.lower()
        if folded in _TRUE:
            return True
        if folded in _FALSE:
            return False
        raise ParseError(f"bool: {text!r} is not a boolean")

    return TextScalar(to, of)


def _value_type(cls: AnyValue) -> TextScalar:
    def to(value: AnyValue) -> str:
        return (value if isinstance(value, cls) else cls(value)).text()

    return TextScalar(to, cls.parse)


SCALAR_TEXT: Final[dict[str, TextScalar]] = {
    "bool": _boolean(),
    "uint8": _uint("uint8", 8),
    "uint16": _uint("uint16", 16),
    "uint32": _uint("uint32", 32),
    "uint64": _uint("uint64", 64),
    "int8": _int("int8", 8),
    "int16": _int("int16", 16),
    "int32": _int("int32", 32),
    "int64": _int("int64", 64),
    "float32": _float("float32", 32),
    "float64": _float("float64", 64),
    "string8": _string("string8"),
    "string16": _string("string16"),
    "string32": _string("string32"),
    "string64": _string("string64"),
    "bytes8": _bytes("bytes8"),
    "bytes16": _bytes("bytes16"),
    "bytes32": _bytes("bytes32"),
    "bytes64": _bytes("bytes64"),
    "identity": _value_type(Identity),
    "nonce64": _value_type(Nonce),
    "object_id.sha256": _value_type(ObjectID),
    "time": _value_type(Time),
    "duration": _value_type(Duration),
    "size": _value_type(Size),
    "zone": _value_type(Zone),
    "object_type": _string("object_type"),
    "error_message": _string("error_message"),
}


def text_scalar(type_name: str, value: AnyValue) -> str:
    """One scalar's text form. This is the bare parameter half, never a header."""
    codec = SCALAR_TEXT.get(type_name)
    if codec is None:
        raise SchemaError(f"{type_name}: no text form")
    return codec.to(value)


def read_text_scalar(type_name: str, text: str) -> AnyValue:
    """One scalar's plain value, from its text form."""
    codec = SCALAR_TEXT.get(type_name)
    if codec is None:
        raise SchemaError(f"{type_name}: no text form")
    return codec.of(text)


# --- whole objects ---------------------------------------------------------


def to_text(obj: AnyValue) -> str:
    """One object's bare text body.

    Raises `SchemaError` for a type with no text form, which is the signal
    `encode` uses to fall back to base64.
    """
    own = getattr(obj, "text", None)
    if callable(own):
        return own()

    type_name = getattr(obj, "ASTRAL_TYPE", "")
    if type_name and type_name not in CHANNEL_TEXT_EXCLUDED and type_name in SCALAR_TEXT:
        return text_scalar(type_name, obj)

    raise SchemaError(f"{type_name or type(obj).__name__}: no text form")


def has_text_form(obj: AnyValue) -> bool:
    """Whether `to_text` can render this object."""
    try:
        to_text(obj)
    except SchemaError:
        return False
    return True


def encode(obj: AnyValue, *, base64_only: bool = False) -> str:
    """One text-encoded object, header included and with no newline.

    `base64_only` is the `base64` channel format: the header is unchanged and
    the body is forced to base64 even for a type that has a text form.
    """
    header = _HEADER_OPEN + getattr(obj, "ASTRAL_TYPE", "") + _HEADER_CLOSE
    if not base64_only:
        try:
            body = to_text(obj)
        except SchemaError:
            pass
        else:
            return header + TEXT_SEP + body
    return header + BASE64_SEP + encode_base64(payload_bytes(obj))


def encode_line(obj: AnyValue, *, base64_only: bool = False) -> str:
    """One text-channel line: the encoded object, then a newline."""
    return encode(obj, base64_only=base64_only) + "\n"


def parse_header(line: str) -> ParsedText:
    """Split a text line into its type, its body's encoding and its body.

    The encoding is `text`, `base64` or `none`; anything else after the header is
    a fault. astral-go reports `unknown` and then errors, which is the same
    outcome one step later.
    """
    if not line.startswith(_HEADER_OPEN):
        raise ParseError(f"text: no {_HEADER_OPEN!r} type header in {line!r}")
    close = line.find(_HEADER_CLOSE)
    if close == -1:
        raise ParseError(f"text: unterminated type header in {line!r}")
    type_name = line[len(_HEADER_OPEN) : close]
    rest = line[close + 1 :]
    if not rest:
        return ParsedText(type_name, "none", "")
    separator, body = rest[0], rest[1:]
    if separator in TEXT_SEPS:
        return ParsedText(type_name, "text", body)
    if separator in BASE64_SEPS:
        return ParsedText(type_name, "base64", body)
    raise ParseError(f"text: {separator!r} is not a payload separator in {line!r}")


def decode(text: str, *, registry: Blueprints | None = None) -> AnyValue:
    """The object one text-encoded line carries.

    An empty type is the untyped blob, exactly as a zero-length type tag is on a
    binary channel.
    """
    parsed = parse_header(text)
    blueprints = default_blueprints() if registry is None else registry

    if not parsed.type:
        # object.py sits above this package, so the untyped carrier is fetched
        # on demand rather than imported at module level.
        from ..object import Blob

        proto: AnyValue = Blob()
    else:
        found = blueprints.new(parsed.type)
        if found is None:
            raise StreamCorrupted(f"unknown type {parsed.type}") from BlueprintNotFound(
                parsed.type
            )
        proto = found

    if parsed.encoding == "text":
        return _from_text(proto, parsed.body)
    if parsed.encoding == "base64":
        payload = decode_base64(parsed.body)
        reader = object_reader(payload, registry=blueprints)
        if not parsed.type:
            return type(proto).read_payload(reader)
        return read_object(reader, parsed.type)
    return proto


def decode_line(line: str, *, registry: Blueprints | None = None) -> AnyValue:
    """One text-channel line, with its terminating newline removed if present."""
    return decode(line[:-1] if line.endswith("\n") else line, registry=registry)


def _from_text(proto: AnyValue, body: str) -> AnyValue:
    cls = type(proto)
    own = getattr(cls, "parse", None)
    if own is not None:
        return own(body)
    type_name = getattr(proto, "ASTRAL_TYPE", "")
    if type_name in SCALAR_TEXT and type_name not in CHANNEL_TEXT_EXCLUDED:
        return cls(read_text_scalar(type_name, body))
    raise ParseError(f"{type_name or cls.__name__}: no text form")


# --- the spec walker -------------------------------------------------------


def text_spec(spec: Spec, value: AnyValue) -> str:
    """One field's bare text form -- the query-string parameter encoding.

    A polymorphic field is the exception: its text form is the whole
    `#[type] body` line, because nothing else in a text parameter names the type.
    """
    if isinstance(spec, Primitive):
        if value is None:
            raise SchemaError(f"Primitive({spec.name}): value is required")
        return text_scalar(spec.name, value)

    if isinstance(spec, Ref):
        return _named_text(spec.type, value)

    if isinstance(spec, Ptr):
        if value is None:
            # An empty string is a legitimate string8, so absence cannot be
            # spelled in a parameter value. The caller omits the key instead.
            raise SchemaError(f"Ptr({spec.type}): an absent value has no text form")
        return _named_text(spec.type, value)

    if isinstance(spec, Any):
        if value is None:
            raise SchemaError("Any(): an absent value has no text form")
        return encode(value)

    raise SchemaError(f"{type(spec).__name__}: no text form")


def read_text_spec(
    spec: Spec, text: str, *, registry: Blueprints | None = None
) -> AnyValue:
    """One field's value, from its bare text form."""
    if isinstance(spec, Primitive):
        return read_text_scalar(spec.name, text)

    if isinstance(spec, (Ref, Ptr)):
        return _named_of_text(spec.type, text, registry)

    if isinstance(spec, Any):
        return decode(text, registry=registry)

    if isinstance(spec, (Slice, Array, Map)):
        raise SchemaError(f"{type(spec).__name__}: no text form")

    raise SchemaError(f"unknown spec {type(spec).__name__}")


def _named_text(type_name: str, value: AnyValue) -> str:
    if value is None:
        raise SchemaError(
            f"{type_name}: None has no text form -- only Ptr and Any carry absence"
        )
    if type_name in SCALAR_TEXT:
        return text_scalar(type_name, value)
    return to_text(value)


def _named_of_text(
    type_name: str, text: str, registry: Blueprints | None
) -> AnyValue:
    if type_name in SCALAR_TEXT:
        return read_text_scalar(type_name, text)
    blueprints = default_blueprints() if registry is None else registry
    proto = blueprints.new(type_name)
    if proto is None:
        raise StreamCorrupted(f"unknown type {type_name}") from BlueprintNotFound(type_name)
    return _from_text(proto, text)
