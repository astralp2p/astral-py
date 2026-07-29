"""JSON marshalling for every spec kind, plus the `{"Type","Object"}` envelope.

Named `jsoncodec` rather than `json` so no module inside the package can shadow
the standard library one; `astral.codec.json` would break every sibling that
imports stdlib `json` under an implicit relative resolution.

The same `FIELDS` tuple that drives the binary codec drives this one, keyed by
`wire_name` instead of by position. Nothing here re-derives a schema.

Facts settled against astral-go, which outranks astral-docs:

- The envelope is exactly `{"Type": <object type>, "Object": <payload JSON>}`, in
  that key order, and it is the form a **polymorphic field** takes as well
  (`marshalFieldJSON`'s `ObjectSpec` branch, `interfaceValue.MarshalJSON`'s
  `JSONAdapter`, and the `err_unexpected_object` vector). The corpus's
  `struct.demo` vector shows the inline form instead because it was generated
  through Go's `encoding/json`, which resolves the interface before any astral
  code runs; that path is a recorded corpus gap
  (`gap.struct_json.polymorphic_field`) and is not what the SDK emits.
  The inline form is also **not invertible**, which settles the choice rather
  than merely justifying it: `ref_spec`, `slice_spec` and `ptr_spec` all render
  as `{"Type": …}`, so nothing can tell them apart, and astral-go itself refuses
  the form -- `Objectify(&bp).UnmarshalJSON` fed astral-go's own
  `json.Marshal(bp)` output fails with `blueprint not found: `. The envelope is
  the only round-trippable spelling, so it is the only one accepted here.
- Key order inside a record is **declaration order**, and astral-go has two
  orders. A type with no `MarshalJSON` marshals through Go's struct reflection
  and keeps declaration order; a type whose `MarshalJSON` delegates to
  `Objectify` reaches `structValue.MarshalJSON`, which builds a
  `map[string]json.RawMessage`, and `encoding/json` **sorts** map keys. `query`,
  `mod.dir.alias_map`, `err_unexpected_object` and most `api/…` types are in the
  second group, so the node emits `{"Caller",…,"Nonce",…}` where the declaration
  is `Nonce, Caller, Target, QueryString`. Nothing on either side reads records
  by key position -- parsing folds keys case-insensitively -- so this is a
  recorded divergence, not a defect. A byte-exact JSON-line vector for a record
  would have to decide which of Go's two orders it pins.
- `bytes*`, `blob` and a Go `[]byte` field are base64, **std alphabet with `=`
  padding**. Emission pads; parsing accepts any length.
- An empty container emits `null`. Go distinguishes a nil slice from an empty
  one and Python cannot: the design normalises a zero count to an empty
  container, and both corpus data points for an empty container
  (`route_query_msg.Filters`, `blueprint.alias.Fields`) are `null`. Parsing
  accepts `null` and `[]`/`{}` alike, so the choice cannot desynchronise a peer.
  An `Array` is exempt: its length is schema data and Go has no nil array.
- A map's JSON keys are the stringified keys, **sorted**, matching Go's
  `encoding/json` map ordering. That order is not the binary map order: binary
  sorts by encoded key bytes, so a `string16` key sorts by its length prefix
  first. The two must not be conflated.
- Field-name lookup on parse is case-insensitive, and two keys that differ only
  in case are ambiguous and rejected.
- `float` rejects NaN and infinity rather than emitting Python's non-standard
  `NaN` / `Infinity`, which no JSON parser is required to accept.

`dumps` exists because `json.dumps` cannot reproduce Go's byte-for-byte output:
Go escapes `<`, `>`, `&` and U+2028/U+2029, writes `\\u0008` where Python writes
`\\b`, and selects between `f` and `e` float styles at different thresholds. The
JSON-channel line has to match the node's byte for byte, so the writer is ours.
Key order is the caller's: a record is emitted in declaration order and a map is
sorted before it ever reaches here.
"""

from __future__ import annotations

import base64
import binascii
import json as _json
import math
import struct
from collections.abc import Sequence as _Sequence
from typing import Any as AnyValue
from typing import Callable, Final, Mapping, NamedTuple, Sequence

from ..errors import (
    BlueprintNotFound,
    ParseError,
    RangeError,
    SchemaError,
    StreamCorrupted,
)
from ..registry import Blueprints, default_blueprints
from ..spec import Any, Array, Map, Primitive, Ptr, Ref, Slice, Spec
from ..types import Duration, Identity, Nonce, ObjectID, Size, Time, Zone

__all__ = [
    "ENVELOPE_OBJECT",
    "ENVELOPE_TYPE",
    "FLOAT32_MAX",
    "Float32Number",
    "JsonScalar",
    "SCALAR_JSON",
    "decode_line",
    "dumps",
    "encode_line",
    "envelope",
    "float_json",
    "float_text",
    "json_fields",
    "json_scalar",
    "json_spec",
    "loads",
    "marshal",
    "narrow_float32",
    "read_envelope",
    "read_json_fields",
    "read_json_scalar",
    "read_json_spec",
    "unmarshal",
]

# The envelope's two keys, in emission order.
ENVELOPE_TYPE: Final = "Type"
ENVELOPE_OBJECT: Final = "Object"


class JsonScalar(NamedTuple):
    """One scalar type's JSON codec over plain Python values."""

    to: Callable[[AnyValue], AnyValue]
    of: Callable[[AnyValue], AnyValue]


# --- plain-value guards ---------------------------------------------------


def _int_value(name: str, value: AnyValue) -> int:
    # `bool` is an int subclass in Python and a distinct wire type here, so a
    # boolean reaching an integer field is a schema mistake, not a 0 or a 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"{name}: {type(value).__name__} is not an integer")
    return int(value)


def _int_json(name: str, data: AnyValue) -> int:
    if isinstance(data, bool) or not isinstance(data, int):
        raise ParseError(f"{name}: expected a JSON integer, got {type(data).__name__}")
    return int(data)


def _float_value(name: str, value: AnyValue) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaError(f"{name}: {type(value).__name__} is not a number")
    return float(value)


def _str_value(name: str, value: AnyValue) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{name}: {type(value).__name__} is not a string")
    return str(value)


def _str_json(name: str, data: AnyValue) -> str:
    if not isinstance(data, str):
        raise ParseError(f"{name}: expected a JSON string, got {type(data).__name__}")
    return data


def encode_base64(data: bytes) -> str:
    """Std-alphabet base64 with `=` padding, as every astral byte form uses."""
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_base64(text: str) -> bytes:
    """Decode std-alphabet base64, supplying missing padding.

    astral-go requires exact padding and always emits it. Accepting an unpadded
    form costs one line and makes a hand-written query parameter work.
    """
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"base64: {text!r} is not base64: {exc}") from exc


# --- float formatting ------------------------------------------------------

_FLOAT_DIGITS: Final = 18

# FLT_MAX is one float32 step below 2**128, and a double narrows to FLT_MAX up to
# and including the midpoint between the two -- Go's rule is that only *more* than
# half a step past FLT_MAX is an infinity, which is what `strconv.ParseFloat(s, 32)`
# does and therefore what the wire means. Both constants are exact in a double and
# are written as arithmetic because their decimal literals are not checkable by eye.
FLOAT32_MAX: Final = 2.0**128 - 2.0**104
_FLOAT32_HALF_STEP_PAST_MAX: Final = 2.0**128 - 2.0**103


def _narrow32(value: float) -> float:
    """`float32(value)`, rounding to nearest as Go does.

    `struct.pack(">f")` raises `OverflowError` for every double above FLT_MAX,
    including the band Go rounds back down to FLT_MAX. `3.4028235e+38` is in that
    band and is the shortest decimal for FLT_MAX, so the band has to be handled
    or the whole top of the float32 range becomes unencodable.
    """
    if -FLOAT32_MAX <= value <= FLOAT32_MAX:
        return float(struct.unpack(">f", struct.pack(">f", value))[0])
    if math.isnan(value):
        return value
    if abs(value) <= _FLOAT32_HALF_STEP_PAST_MAX:
        return math.copysign(FLOAT32_MAX, value)
    return math.copysign(math.inf, value)


def narrow_float32(name: str, value: float) -> float:
    """A parsed decimal as the float32 it denotes, or `RangeError`.

    Go parses every `float32` text and JSON form at bit size 32, so a peer's
    number is already narrowed by the time it reaches a field. Keeping the wider
    double would hand `Writer.float32` a value it refuses -- `3.4028235e+38` is
    the shortest form of FLT_MAX and does not fit a double comparison against it.
    """
    narrowed = _narrow32(value)
    if math.isinf(narrowed) and not math.isinf(value):
        raise RangeError(f"{name}: {value!r} out of range")
    return narrowed


def _shortest(value: float, bits: int) -> tuple[str, str, int]:
    """The shortest decimal that round-trips at `bits`, as (sign, digits, exp10).

    `exp10` is the power of ten the first digit carries, so `1.5` is
    `("", "15", 0)`. Python's `repr` produces the same digits but chooses its
    own style thresholds, and `struct` is the only way to ask whether a decimal
    round-trips through 32 bits.
    """
    for precision in range(_FLOAT_DIGITS):
        text = f"{value:.{precision}e}"
        if _round_trips(text, value, bits):
            break
    else:
        text = f"{value:.{_FLOAT_DIGITS - 1}e}"
    mantissa, _, exponent = text.partition("e")
    sign = "-" if mantissa.startswith("-") else ""
    digits = mantissa.lstrip("+-").replace(".", "").rstrip("0") or "0"
    return sign, digits, int(exponent)


def _round_trips(text: str, value: float, bits: int) -> bool:
    parsed = float(text)
    if bits == 32:
        parsed = _narrow32(parsed)
        value = _narrow32(value)
    return parsed == value or (parsed != parsed and value != value)


def _fixed(sign: str, digits: str, exp10: int) -> str:
    """Render digits in `f` style: a decimal point, never an exponent."""
    if exp10 >= 0:
        whole = digits[: exp10 + 1].ljust(exp10 + 1, "0")
        frac = digits[exp10 + 1 :]
    else:
        whole = "0"
        frac = "0" * (-exp10 - 1) + digits
    return sign + whole + ("." + frac if frac else "")


def float_text(value: float, bits: int = 64) -> str:
    """The text encoding: `strconv.FormatFloat(v, 'f', -1, bits)`.

    Always positional, never an exponent, and never more digits than the width
    needs to round-trip. NaN and infinity keep Go's spellings rather than
    raising: a text channel can carry them, and Python's `float()` reads all
    three back. Only JSON refuses them.
    """
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return _fixed(*_shortest(value, bits))


def float_json(value: float, bits: int = 64) -> str:
    """Go's `encoding/json` float form: `f` style inside [1e-6, 1e21), else `e`.

    NaN and infinity raise: Python would emit `NaN` / `Infinity`, which is not
    JSON, and Go refuses them outright.
    """
    if math.isnan(value) or math.isinf(value):
        raise RangeError(f"float{bits}: {value!r} cannot be marshalled to JSON")
    magnitude = abs(value)
    sign, digits, exp10 = _shortest(value, bits)
    if magnitude != 0 and (magnitude < 1e-6 or magnitude >= 1e21):
        head = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
        # Go trims `e-07` to `e-7`; a positive exponent here is always >= 21, so
        # it never carries a leading zero to trim.
        return f"{sign}{head}e{'+' if exp10 >= 0 else '-'}{abs(exp10):02d}".replace(
            "e-0", "e-"
        )
    return _fixed(sign, digits, exp10)


class Float32Number(float):
    """A float whose JSON form must be rendered at 32-bit precision.

    `dumps` sees a value, never the schema that declared it, and a `float32`
    widened to a Python float is not the same decimal: `float32(0.1)` is
    `0.10000000149011612`, where Go writes `0.1`. The width therefore travels on
    the value. It compares equal to the plain float it wraps, so nothing above
    the serialiser has to know.
    """

    __slots__ = ()


# --- the scalar table ------------------------------------------------------


def _uint(name: str, bits: int) -> JsonScalar:
    high = (1 << bits) - 1

    def to(value: AnyValue) -> int:
        result = _int_value(name, value)
        if not 0 <= result <= high:
            raise RangeError(f"{name}: {result} out of range")
        return result

    def of(data: AnyValue) -> int:
        result = _int_json(name, data)
        if not 0 <= result <= high:
            raise RangeError(f"{name}: {result} out of range")
        return result

    return JsonScalar(to, of)


def _int(name: str, bits: int) -> JsonScalar:
    low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1

    def to(value: AnyValue) -> int:
        result = _int_value(name, value)
        if not low <= result <= high:
            raise RangeError(f"{name}: {result} out of range")
        return result

    def of(data: AnyValue) -> int:
        result = _int_json(name, data)
        if not low <= result <= high:
            raise RangeError(f"{name}: {result} out of range")
        return result

    return JsonScalar(to, of)


def _float(name: str, bits: int) -> JsonScalar:
    def to(value: AnyValue) -> float:
        result = _float_value(name, value)
        # The emitted number is a Python float; `float_json` is what turns it
        # into Go's bytes. Rejecting NaN and infinity here keeps a value that
        # cannot be serialised out of the tree entirely.
        if math.isnan(result) or math.isinf(result):
            raise RangeError(f"{name}: {result!r} cannot be marshalled to JSON")
        if bits != 32:
            return result
        if abs(result) > FLOAT32_MAX:
            # The same bound `Writer.float32` enforces: a value with no float32
            # payload has no float32 JSON form either.
            raise RangeError(f"{name}: {result!r} out of range")
        return Float32Number(result)

    def of(data: AnyValue) -> float:
        result = _float_value(name, data)
        if bits != 32:
            return result
        return narrow_float32(name, result)

    return JsonScalar(to, of)


def _string(name: str) -> JsonScalar:
    return JsonScalar(lambda v: _str_value(name, v), lambda d: _str_json(name, d))


def _bytes(name: str) -> JsonScalar:
    def to(value: AnyValue) -> str:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise SchemaError(f"{name}: {type(value).__name__} is not bytes")
        return encode_base64(bytes(value))

    def of(data: AnyValue) -> bytes:
        if data is None:
            return b""
        return decode_base64(_str_json(name, data))

    return JsonScalar(to, of)


def _value_type(cls: AnyValue) -> JsonScalar:
    """A `types.py` value type, coercing a plain Python value before emitting."""

    def to(value: AnyValue) -> AnyValue:
        return (value if isinstance(value, cls) else cls(value)).json()

    return JsonScalar(to, cls.from_json)


def _boolean() -> JsonScalar:
    def to(value: AnyValue) -> bool:
        return bool(value)

    def of(data: AnyValue) -> bool:
        if not isinstance(data, bool):
            raise ParseError(f"bool: expected a JSON boolean, got {type(data).__name__}")
        return data

    return JsonScalar(to, of)


SCALAR_JSON: Final[dict[str, JsonScalar]] = {
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
    # Both share a string's JSON exactly, as they share its payload.
    "object_type": _string("object_type"),
    "error_message": _string("error_message"),
}


def json_scalar(type_name: str, value: AnyValue) -> AnyValue:
    """One scalar's JSON value."""
    codec = SCALAR_JSON.get(type_name)
    if codec is None:
        raise SchemaError(f"{type_name}: no JSON scalar codec")
    return codec.to(value)


def read_json_scalar(type_name: str, data: AnyValue) -> AnyValue:
    """One scalar's plain value, from its JSON form."""
    codec = SCALAR_JSON.get(type_name)
    if codec is None:
        raise SchemaError(f"{type_name}: no JSON scalar codec")
    return codec.of(data)


# --- whole objects ---------------------------------------------------------


def _registry(registry: Blueprints | None) -> Blueprints:
    return default_blueprints() if registry is None else registry


def _bundle_json(obj: AnyValue) -> AnyValue:
    objects = list(obj)
    # A Go nil slice of envelopes, which is what an empty bundle marshals
    # through, is `null` and not `[]`.
    return [envelope(each) for each in objects] if objects else None


def _bundle_of_json(cls: AnyValue, data: AnyValue, registry: Blueprints | None) -> AnyValue:
    bundle = cls()
    if data is None:
        return bundle
    if not isinstance(data, list):
        raise ParseError(f"bundle: expected a JSON array, got {type(data).__name__}")
    for element in data:
        bundle.append(read_envelope(element, registry=registry))
    return bundle


def _stamp_of_json(cls: AnyValue, data: AnyValue, registry: Blueprints | None) -> AnyValue:
    if data is not None and not isinstance(data, dict):
        raise ParseError(f"stamp: expected a JSON object, got {type(data).__name__}")
    return cls()


# The types whose JSON is neither a `json()` method, nor a `FIELDS` walk, nor a
# scalar: `stamp` is Go's `struct{}` and `bundle` is a list of envelopes.
_TYPE_JSON: Final[
    dict[
        str,
        tuple[
            Callable[[AnyValue], AnyValue],
            Callable[[AnyValue, AnyValue, Blueprints | None], AnyValue],
        ],
    ]
] = {
    "stamp": (lambda obj: {}, _stamp_of_json),
    "bundle": (_bundle_json, _bundle_of_json),
}


def _schema_of(obj: AnyValue) -> Sequence[FieldTriple] | None:
    """The record schema this object carries, read off the object itself.

    Off the object and not off its class: a `RuntimeRecord`'s schema arrived on
    the wire and lives per instance, so `type(obj).FIELDS` is the slot
    descriptor rather than a tuple. Anything that is not a sequence of triples
    is a broken declaration and says so, rather than failing inside the walk.
    """
    fields = getattr(obj, "FIELDS", None)
    if fields is None:
        return None
    if isinstance(fields, _Sequence) and not isinstance(fields, (str, bytes)):
        return fields
    raise SchemaError(f"{type(obj).__name__}: FIELDS is not a sequence of fields")


def marshal(obj: AnyValue) -> AnyValue:
    """One object's JSON value, without the envelope.

    Resolution order, and it matters: an object that carries its own `json()`
    wins, because `ack` is a zero-field record whose JSON is `null` rather than
    `{}`, and an alias resolves to its underlying scalar rather than to the empty
    field walk its `FIELDS` would produce.
    """
    if obj is None:
        return None

    own = getattr(obj, "json", None)
    if callable(own):
        return own()

    type_name = getattr(obj, "ASTRAL_TYPE", "")

    handler = _TYPE_JSON.get(type_name)
    if handler is not None:
        return handler[0](obj)

    underlying = getattr(obj, "UNDERLYING", "")
    if underlying:
        return json_scalar(underlying, obj.value)

    fields = _schema_of(obj)
    if fields is not None:
        return json_fields(fields, obj)

    if type_name in SCALAR_JSON:
        return json_scalar(type_name, obj)

    raise SchemaError(f"{type(obj).__name__}: no JSON form")


def unmarshal(
    type_name: str, data: AnyValue, *, registry: Blueprints | None = None
) -> AnyValue:
    """Construct the named type from its JSON value.

    An unknown type name is fatal: a JSON payload alone does not say what shape
    the missing schema had, so there is nothing to fall back to.
    """
    proto = _registry(registry).new(type_name)
    if proto is None:
        raise StreamCorrupted(f"unknown type {type_name}") from BlueprintNotFound(type_name)
    return _fill(proto, data, registry)


def _fill(proto: AnyValue, data: AnyValue, registry: Blueprints | None) -> AnyValue:
    """Populate a freshly constructed prototype from a JSON value."""
    cls = type(proto)

    # A prototype already bound to its own schema fills itself, exactly as
    # `read_payload` fills it on the binary path: a declared record's classmethod
    # builds a fresh value, a runtime record's instance method populates the one
    # the registry handed out. Checked before `from_json`, because the two hooks
    # differ in nothing but whether the registry travels with the call.
    into = getattr(proto, "read_json", None)
    if callable(into):
        return into(data, registry=registry)

    own = getattr(cls, "from_json", None)
    if own is not None:
        return own(data)

    type_name = getattr(proto, "ASTRAL_TYPE", "")

    handler = _TYPE_JSON.get(type_name)
    if handler is not None:
        return handler[1](cls, data, registry)

    underlying = getattr(proto, "UNDERLYING", "")
    if underlying:
        return cls(read_json_scalar(underlying, data))

    fields = _schema_of(proto)
    if fields is not None:
        return cls(**read_json_fields(fields, data, registry=registry))

    if type_name in SCALAR_JSON:
        return cls(read_json_scalar(type_name, data))

    raise ParseError(f"{type_name or cls.__name__}: no JSON form")


def envelope(obj: AnyValue) -> dict[str, AnyValue]:
    """`{"Type": …, "Object": …}`. Rejects an untyped object.

    JSON encoding can only carry a typed object: the envelope is the only thing
    naming the type, so an untyped blob has nowhere to put its identity.
    """
    type_name = getattr(obj, "ASTRAL_TYPE", "")
    if not type_name:
        raise SchemaError("JSON encoding requires a typed object")
    return {ENVELOPE_TYPE: type_name, ENVELOPE_OBJECT: marshal(obj)}


def read_envelope(data: AnyValue, *, registry: Blueprints | None = None) -> AnyValue:
    """The object an envelope names, or `None` for a JSON `null`.

    `null` is the absent form a polymorphic field takes, mirroring the
    zero-length type tag on the binary wire.

    A key other than `Type` and `Object` is an error, as at the record level:
    ignoring it left the payload unread and the named type at its zero value
    with no error, so `{"Type": "…slice_spec", "Obejct": {"Type": "uint32"}}`
    parsed to a heterogeneous `SliceSpec` and registered a corrupted schema.
    Sourced: astral-docs `topics/json-encoding.md`, and astral-go `JSONAdapter.
    UnmarshalJSON` (`astral/object.go`), which rejects the same shape.

    A missing `Object` key is not an error -- it carries an absent payload, the
    same as an explicit `null`, and every SDK emits both keys unconditionally so
    the form does not arise in practice.
    """
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ParseError(f"envelope: expected a JSON object, got {type(data).__name__}")
    folded = _fold(data, "envelope")
    type_name = folded.pop(ENVELOPE_TYPE.lower(), None)
    payload = folded.pop(ENVELOPE_OBJECT.lower(), None)
    if not isinstance(type_name, str) or not type_name:
        # The failure a peer's inline polymorphic field produces, so the message
        # names the shape rather than the missing key: Go's `encoding/json`
        # writes an interface field as the inner object's own JSON, which no
        # decoder can resolve back to a type.
        raise ParseError(
            "envelope: missing or empty Type -- a polymorphic field carries "
            f'{{"Type": …, "Object": …}}, got keys {sorted(data)}'
        )
    if folded:
        raise ParseError(f"envelope: unknown keys {sorted(folded)}")
    return unmarshal(type_name, payload, registry=registry)


# --- the field walker ------------------------------------------------------

FieldTriple = tuple[str, str, Spec]


def json_fields(
    fields: Sequence[FieldTriple], obj: AnyValue
) -> dict[str, AnyValue]:
    """Every field of a record, keyed by wire name, in declaration order.

    An embedded struct nests under its Go type name rather than flattening --
    that name is the field's wire name, so nesting falls out of the same walk.
    Binary flattens the same declaration; the two are not symmetric and
    astral-go is the authority that they are not.
    """
    return {
        wire_name: json_spec(spec, getattr(obj, attr)) for attr, wire_name, spec in fields
    }


def read_json_fields(
    fields: Sequence[FieldTriple],
    data: AnyValue,
    *,
    registry: Blueprints | None = None,
) -> dict[str, AnyValue]:
    """Read a record's fields into constructor keywords.

    Lookup is case-insensitive; two keys that fold together are ambiguous and
    rejected rather than resolved by chance. A field the payload omits is left
    to its declared default, and an unrecognised key is an error -- a schema the
    peer and the SDK disagree about is a fault to surface, not to ignore.
    """
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ParseError(f"record: expected a JSON object, got {type(data).__name__}")

    folded = _fold(data, "record")
    out: dict[str, AnyValue] = {}
    for attr, wire_name, spec in fields:
        key = wire_name.lower()
        if key not in folded:
            continue
        out[attr] = read_json_spec(spec, folded.pop(key), registry=registry)
    if folded:
        raise ParseError(f"record: unknown fields {sorted(folded)}")
    return out


def _fold(data: Mapping[str, AnyValue], what: str) -> dict[str, AnyValue]:
    folded: dict[str, AnyValue] = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise ParseError(f"{what}: non-string key {key!r}")
        lowered = key.lower()
        if lowered in folded:
            raise ParseError(f"{what}: keys differing only in case: {key!r}")
        folded[lowered] = value
    return folded


# --- the spec walker -------------------------------------------------------


def json_spec(spec: Spec, value: AnyValue) -> AnyValue:
    """One field's JSON value, from its spec."""
    if isinstance(spec, Primitive):
        if value is None:
            raise SchemaError(f"Primitive({spec.name}): value is required")
        return json_scalar(spec.name, value)

    if isinstance(spec, Ref):
        return _named_json(spec.type, value)

    if isinstance(spec, Ptr):
        return None if value is None else _named_json(spec.type, value)

    if isinstance(spec, Any):
        return None if value is None else envelope(value)

    if isinstance(spec, Slice):
        items = () if value is None else value
        # An empty container is `null`: Python cannot tell Go's nil slice from
        # its empty one, and every corpus data point is `null`.
        return [_element_json(spec.type, item) for item in items] or None

    if isinstance(spec, Array):
        items = list(() if value is None else value)
        if len(items) != spec.length:
            raise SchemaError(
                f"Array({spec.type}, {spec.length}): got {len(items)} elements"
            )
        return [_element_json(spec.type, item) for item in items]

    if isinstance(spec, Map):
        return _map_json(spec, {} if value is None else value)

    raise SchemaError(f"unknown spec {type(spec).__name__}")


def read_json_spec(
    spec: Spec, data: AnyValue, *, registry: Blueprints | None = None
) -> AnyValue:
    """One field's value, from its JSON form."""
    if isinstance(spec, Primitive):
        return read_json_scalar(spec.name, data)

    if isinstance(spec, Ref):
        return _named_of_json(spec.type, data, registry)

    if isinstance(spec, Ptr):
        return None if data is None else _named_of_json(spec.type, data, registry)

    if isinstance(spec, Any):
        return read_envelope(data, registry=registry)

    if isinstance(spec, Slice):
        if data is None:
            return []
        if not isinstance(data, list):
            raise ParseError(f"slice: expected a JSON array, got {type(data).__name__}")
        return [_element_of_json(spec.type, item, registry) for item in data]

    if isinstance(spec, Array):
        if data is None:
            raise ParseError(f"array({spec.type}, {spec.length}): expected a JSON array")
        if not isinstance(data, list):
            raise ParseError(f"array: expected a JSON array, got {type(data).__name__}")
        if len(data) != spec.length:
            raise ParseError(
                f"array({spec.type}, {spec.length}): got {len(data)} elements"
            )
        return [_element_of_json(spec.type, item, registry) for item in data]

    if isinstance(spec, Map):
        return _map_of_json(spec, data, registry)

    raise SchemaError(f"unknown spec {type(spec).__name__}")


def _named_json(type_name: str, value: AnyValue) -> AnyValue:
    if value is None:
        raise SchemaError(
            f"{type_name}: None has no JSON form -- only Ptr and Any carry absence"
        )
    if type_name in SCALAR_JSON:
        return json_scalar(type_name, value)
    return marshal(value)


def _named_of_json(
    type_name: str, data: AnyValue, registry: Blueprints | None
) -> AnyValue:
    if type_name in SCALAR_JSON:
        return read_json_scalar(type_name, data)
    return unmarshal(type_name, data, registry=registry)


def _element_json(type_name: str, value: AnyValue) -> AnyValue:
    """One slice element, array element or map value.

    An empty element type is heterogeneous, so the element carries its own
    envelope, exactly as it carries its own type tag on the binary wire.
    """
    if not type_name:
        return None if value is None else envelope(value)
    if value is None:
        return None
    return _named_json(type_name, value)


def _element_of_json(
    type_name: str, data: AnyValue, registry: Blueprints | None
) -> AnyValue:
    if not type_name:
        return read_envelope(data, registry=registry)
    if data is None:
        return None
    return _named_of_json(type_name, data, registry)


def _map_json(spec: Map, value: AnyValue) -> AnyValue:
    items = value.items() if hasattr(value, "items") else value
    pairs = [(_map_key_json(spec.key, key), item) for key, item in items]
    if not pairs:
        return None
    # Go's encoding/json sorts map keys by their string form. That is NOT the
    # binary order, which sorts by encoded key bytes and therefore puts a short
    # `string16` key first regardless of its content.
    pairs.sort(key=lambda pair: pair[0].encode("utf-8", "surrogateescape"))
    return {key: _element_json(spec.value, item) for key, item in pairs}


def _map_of_json(
    spec: Map, data: AnyValue, registry: Blueprints | None
) -> dict[AnyValue, AnyValue]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ParseError(f"map: expected a JSON object, got {type(data).__name__}")
    return {
        _map_key_of_json(spec.key, key): _element_of_json(spec.value, item, registry)
        for key, item in data.items()
    }


def _map_key_json(key_type: str, key: AnyValue) -> str:
    if key_type == "string16":
        return _str_value("map key", key)
    return str(_int_value("map key", key))


def _map_key_of_json(key_type: str, key: AnyValue) -> AnyValue:
    if not isinstance(key, str):
        raise ParseError(f"map key: expected a JSON string, got {type(key).__name__}")
    if key_type == "string16":
        return key
    try:
        parsed = int(key, 10)
    except ValueError as exc:
        raise ParseError(f"map key: {key!r} is not a {key_type}") from exc
    return read_json_scalar(key_type, parsed)


# --- serialisation ---------------------------------------------------------

_ESCAPES: Final = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    # Go's encoder escapes these so a JSON document is safe to embed in HTML.
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    # Valid JSON, invalid JavaScript source, so Go escapes them too.
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def _string_json(value: str) -> str:
    out = ['"']
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < " ":
            out.append(f"\\u{ord(char):04x}")
        elif "\ud800" <= char <= "\udfff":
            # A lone surrogate is what `surrogateescape` leaves behind for a
            # non-UTF-8 byte. Go replaces each such byte with U+FFFD.
            out.append("\ufffd")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def dumps(value: AnyValue) -> str:
    """Serialise a JSON value the way Go's `encoding/json` does.

    Compact, HTML-escaped, `f`-style floats inside [1e-6, 1e21). Mapping order
    is preserved as given: a record arrives in declaration order and a map
    arrives sorted, and re-sorting here would undo both.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string_json(value)
    if isinstance(value, int):
        return str(int(value))
    if isinstance(value, Float32Number):
        return float_json(value, 32)
    if isinstance(value, float):
        return float_json(value)
    if isinstance(value, Mapping):
        inner = ",".join(
            f"{_string_json(str(key))}:{dumps(item)}" for key, item in value.items()
        )
        return "{" + inner + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(dumps(item) for item in value) + "]"
    raise SchemaError(f"{type(value).__name__} is not a JSON value")


def loads(text: str | bytes) -> AnyValue:
    """Parse one JSON document. The standard library is authoritative on input."""
    try:
        return _json.loads(text)
    except ValueError as exc:
        raise ParseError(f"json: {exc}") from exc


def encode_line(obj: AnyValue) -> str:
    """One JSON-channel line: the envelope, then a newline.

    The channel framing is JSON Lines, and the terminating newline is part of
    the frame -- Go's `json.Encoder.Encode` appends it.
    """
    return dumps(envelope(obj)) + "\n"


def decode_line(line: str | bytes, *, registry: Blueprints | None = None) -> AnyValue:
    """The object one JSON-channel line carries."""
    return read_envelope(loads(line), registry=registry)
