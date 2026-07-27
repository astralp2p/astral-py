"""Tier A: drive the whole wire-vector corpus against the SDK.

One test method per (vector, aspect) pair, so a skip names exactly which
encoding of which value is not implemented yet and a failure names exactly which
one broke. Aspects with no codec or no provider registered skip; nothing in this
file computes an expected value.

What each step registers is listed at the bottom of the file. Step 1 owns
`wire.py` and `types.py`, so it registers payload codecs for the scalar widths
and all four encodings of the seven value types. Framing, ObjectID derivation
and channel lines wait for the steps that own them.
"""

from __future__ import annotations

import unittest
from typing import Any, Callable

from astral import types as T
from astral.errors import (
    AllocationLimit,
    InvalidFlag,
    ParseError,
    RangeError,
    ShortRead,
    ValueTooLarge,
)
from astral.wire import DEFAULT_MAX_ALLOC, Reader, Writer
from vectors import (
    FRAMING_PAYLOAD_SOURCE,
    Codec,
    Vector,
    codec_for,
    corpus,
    framing_kind,
    framing_payload,
    negative_handler,
    negative_vectors,
    provider,
    register_codec,
    register_negative,
    vector_skip,
    vectors,
)

# A corpus vector no implementation of this design can satisfy, and why. The
# corpus is authoritative about astral-go; the design deliberately diverges here.
# A test listed below is an expected failure once its handler exists, never a
# silent pass and never an edit to the corpus.
DESIGN_DIVERGENCES: dict[str, str] = {
    "neg.container_presence.0x00": (
        "design 2.3 / R-9: 0x01 for a present element, 0x00 accepted on read as "
        "absent and written back for an absent one. astral-go's *reflection* codec "
        "rejects 0x00 and the corpus records that; its blueprint-built containers "
        "resolve their element type to a pointer prototype and emit 0x00 for a nil "
        "element, so a strict decoder desynchronises against a blueprint peer and a "
        "strict encoder cannot echo what it just decoded. astral-go reads the SDK's "
        "bytes for both cases and re-emits them unchanged."
    ),
}


# --- aspect implementations -----------------------------------------------


def _codec(case: unittest.TestCase, vector: Vector) -> Codec:
    found = codec_for(vector.astral_type)
    if found is None:
        case.skipTest(f"no codec registered for astral type {vector.astral_type!r}")
    return found


def _require(case: unittest.TestCase, value: Any, what: str) -> Any:
    if value is None:
        case.skipTest(f"no {what} registered")
    return value


def _value(vector: Vector, codec: Codec) -> Any:
    """The value the vector describes.

    The text form is preferred as the source of truth because one vector's
    payload is deliberately lossy: `object_id.size99_zerohash` encodes to 40 zero
    bytes, so its Size survives only in its text form.
    """
    if vector.has("text") and not vector.text_is_line and codec.from_text is not None:
        return codec.from_text(vector.text)
    return codec.decode(vector.payload)


def _aspect_binary(case: unittest.TestCase, vector: Vector) -> None:
    codec = _codec(case, vector)
    payload = vector.payload
    case.assertEqual(codec.encode(codec.decode(payload)).hex(), payload.hex())


def _aspect_binary_framing(case: unittest.TestCase, vector: Vector) -> None:
    framing = _require(case, provider("framing"), "framing provider")
    got = getattr(framing, framing_kind(vector))(vector.astral_type, framing_payload(vector))
    case.assertEqual(got.hex(), vector.payload.hex())


def _aspect_json_emit(case: unittest.TestCase, vector: Vector) -> None:
    codec = _codec(case, vector)
    _require(case, codec.to_json, f"JSON encoder for {vector.astral_type!r}")
    assert codec.to_json is not None
    case.assertEqual(codec.to_json(_value(vector, codec)), vector.json_value)


def _aspect_json_parse(case: unittest.TestCase, vector: Vector) -> None:
    codec = _codec(case, vector)
    _require(case, codec.from_json, f"JSON parser for {vector.astral_type!r}")
    assert codec.from_json is not None
    value = codec.from_json(vector.json_value)
    case.assertEqual(codec.encode(value).hex(), vector.payload.hex())


def _aspect_text_emit(case: unittest.TestCase, vector: Vector) -> None:
    codec = _codec(case, vector)
    _require(case, codec.to_text, f"text encoder for {vector.astral_type!r}")
    assert codec.to_text is not None
    case.assertEqual(codec.to_text(_value(vector, codec)), vector.text)


def _aspect_text_parse(case: unittest.TestCase, vector: Vector) -> None:
    codec = _codec(case, vector)
    _require(case, codec.from_text, f"text parser for {vector.astral_type!r}")
    assert codec.from_text is not None
    value = codec.from_text(vector.text)
    case.assertEqual(codec.encode(value).hex(), vector.payload.hex())


def _framing_aspect(key: str) -> Callable[[unittest.TestCase, Vector], None]:
    def run(case: unittest.TestCase, vector: Vector) -> None:
        framing = _require(case, provider("framing"), "framing provider")
        got = getattr(framing, key)(vector.astral_type, vector.payload)
        case.assertEqual(got.hex(), vector.hex(key).hex())

    return run


def _line_aspect(key: str) -> Callable[[unittest.TestCase, Vector], None]:
    def run(case: unittest.TestCase, vector: Vector) -> None:
        line = _require(case, provider("line"), "channel-line provider")
        got = getattr(line, f"{key}_line")(vector.astral_type, vector.payload)
        case.assertEqual(got, vector.raw[key])

    return run


def _aspect_object_id(case: unittest.TestCase, vector: Vector) -> None:
    ids = _require(case, provider("object_id"), "object_id provider")
    if vector.object_id_is_derivation:
        preimage = vector.hex("object_id_preimage")
    else:
        # The provider picks the typed or the untyped preimage: `blob.hello` is
        # untyped and its preimage carries no stamp and no type header, so the
        # canonical framing is not the one form that answers for every vector.
        preimage = ids.preimage(vector.astral_type, vector.payload)
        case.assertEqual(preimage.hex(), vector.hex("object_id_preimage").hex())
    case.assertEqual(ids.id_of_bytes(preimage), vector.raw["object_id"])


_ASPECTS: dict[str, Callable[[unittest.TestCase, Vector], None]] = {
    "binary": _aspect_binary,
    "binary_framing": _aspect_binary_framing,
    "json_emit": _aspect_json_emit,
    "json_parse": _aspect_json_parse,
    "text_emit": _aspect_text_emit,
    "text_parse": _aspect_text_parse,
    "canonical": _framing_aspect("canonical"),
    "channel_frame": _framing_aspect("channel_frame"),
    "polymorphic_field": _framing_aspect("polymorphic_field"),
    "json_line": _line_aspect("json"),
    "text_line": _line_aspect("text"),
    "object_id": _aspect_object_id,
}


def _aspects_of(vector: Vector) -> list[str]:
    names = ["binary_framing" if vector.binary_is_framing else "binary"]
    if vector.has("json"):
        names += ["json_line"] if vector.json_is_line else ["json_emit", "json_parse"]
    if vector.has("text"):
        names += ["text_line"] if vector.text_is_line else ["text_emit", "text_parse"]
    for key in ("canonical", "channel_frame", "polymorphic_field"):
        if vector.has(key):
            names.append(key)
    if vector.has("object_id"):
        names.append("object_id")
    return names


# --- generated test cases -------------------------------------------------


class VectorTests(unittest.TestCase):
    """Populated at import time, one method per vector aspect."""

    maxDiff = None


class NegativeVectorTests(unittest.TestCase):
    """The corpus's `expect: reject` entries: bytes and inputs that must raise."""

    maxDiff = None


def _install() -> None:
    for vector in vectors():
        for aspect in _aspects_of(vector):
            run = _ASPECTS[aspect]

            def method(
                case: unittest.TestCase,
                _v: Vector = vector,
                _r: Any = run,
                _a: str = aspect,
            ) -> None:
                # A registered skip is one aspect of one vector the corpus
                # itself records as unresolved, and it carries the reason.
                declared = vector_skip(_v.id, _a)
                if declared is not None:
                    case.skipTest(declared)
                _r(case, _v)

            method.__doc__ = f"{vector.id} [{aspect}] {vector.description}"
            setattr(VectorTests, f"test_{vector.slug}__{aspect}", method)

    for vector in negative_vectors():

        def negative(case: unittest.TestCase, _v: Vector = vector) -> None:
            handler = negative_handler(_v.id)
            if handler is None:
                reason = DESIGN_DIVERGENCES.get(_v.id)
                case.skipTest(
                    f"no handler registered; design divergence: {reason}"
                    if reason
                    else "no handler registered"
                )
            handler(case, _v)

        negative.__doc__ = f"{vector.id} must be rejected: {vector.description}"
        if vector.id in DESIGN_DIVERGENCES:
            negative = unittest.expectedFailure(negative)
        setattr(NegativeVectorTests, f"test_{vector.slug}", negative)


class CorpusIntegrityTests(unittest.TestCase):
    """Guards against the corpus silently shrinking or a vector id being renamed."""

    def test_counts_match_the_recorded_tally(self) -> None:
        counted = corpus()["counts"]
        self.assertEqual(len(corpus()["vectors"]), counted["total"])
        self.assertEqual(len(corpus()["negative_vectors"]), counted["negative"])
        self.assertEqual(len(corpus()["gaps"]), counted["gaps"])

    def test_ids_are_unique(self) -> None:
        ids = [v.id for v in vectors()] + [v.id for v in negative_vectors()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_vector_drives_at_least_one_aspect(self) -> None:
        for vector in vectors():
            with self.subTest(vector.id):
                self.assertTrue(_aspects_of(vector))

    def test_every_generated_method_exists(self) -> None:
        for vector in vectors():
            for aspect in _aspects_of(vector):
                name = f"test_{vector.slug}__{aspect}"
                with self.subTest(name):
                    self.assertTrue(hasattr(VectorTests, name))

    def test_every_framing_vector_has_a_payload_source(self) -> None:
        for vector in vectors():
            if vector.binary_is_framing:
                with self.subTest(vector.id):
                    self.assertIn(vector.id, FRAMING_PAYLOAD_SOURCE)
                    self.assertEqual(framing_payload(vector), framing_payload(vector))
                    framing_kind(vector)


# --- step 1: wire.py and types.py -----------------------------------------


def _payload_codec(
    read: Callable[[Reader], Any], write: Callable[[Writer, Any], None], **kw: Any
) -> Codec:
    def decode(payload: bytes) -> Any:
        reader = Reader(payload)
        value = read(reader)
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    def encode(value: Any) -> bytes:
        writer = Writer()
        write(writer, value)
        return writer.getvalue()

    return Codec(decode=decode, encode=encode, **kw)


def _scalar(name: str) -> Codec:
    return _payload_codec(
        lambda r, _n=name: getattr(r, _n)(),
        lambda w, v, _n=name: getattr(w, _n)(v),
    )


def _register_step1_codecs() -> None:
    for name in (
        "bool",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "int8",
        "int16",
        "int32",
        "int64",
        "float32",
        "float64",
        "string8",
        "string16",
        "string32",
        "string64",
        "bytes8",
        "bytes16",
        "bytes32",
        "bytes64",
    ):
        # `bool` is `boolean` on the reader and writer, because `bool` is a builtin.
        register_codec(name, _scalar("boolean" if name == "bool" else name))

    for astral_type, cls in (
        ("identity", T.Identity),
        ("nonce64", T.Nonce),
        ("zone", T.Zone),
        ("time", T.Time),
        ("duration", T.Duration),
        ("size", T.Size),
        ("object_id.sha256", T.ObjectID),
    ):
        register_codec(
            astral_type,
            _payload_codec(
                cls.read,
                lambda w, v: v.write(w),
                to_json=lambda v: v.json(),
                from_json=cls.from_json,
                to_text=lambda v: v.text(),
                from_text=cls.parse,
            ),
        )


@register_negative("neg.string8.oversize")
def _neg_string8_oversize(case: unittest.TestCase, vector: Vector) -> None:
    """The width cap is checked before any byte is written."""
    writer = Writer()
    writer.uint8(0xAA)
    with case.assertRaises(ValueTooLarge):
        writer.string8("x" * 256)
    case.assertEqual(writer.getvalue(), b"\xaa", "a rejected write must leave the buffer alone")
    with case.assertRaises(ValueTooLarge):
        Writer().bytes8(b"x" * 256)


@register_negative("neg.presence.0x02")
def _neg_presence_flag(case: unittest.TestCase, vector: Vector) -> None:
    """0x02..0xff in a nil or presence slot is rejected before any value byte."""
    reader = Reader(vector.payload)
    with case.assertRaises(InvalidFlag):
        reader.flag()
    for byte in (0x02, 0x7F, 0xFF):
        with case.assertRaises(InvalidFlag):
            Reader(bytes([byte]) + b"\x00\x2a").flag()
    # A `bool` payload uses the other reader and stays lenient.
    case.assertTrue(Reader(b"\x02").boolean())


@register_negative("neg.object_id.empty_string")
def _neg_object_id_empty_string(case: unittest.TestCase, vector: Vector) -> None:
    """The text parser rejects `""`; the JSON parser accepts it as the zero ID.

    astral-go marshals the zero ID to `""` and cannot parse it back. We keep its
    emission and decline its asymmetry, so the rejection this vector records
    holds for `parse` -- the text form -- and not for `from_json`.
    """
    with case.assertRaises(ParseError):
        T.ObjectID.parse("")
    with case.assertRaises(ParseError):
        T.ObjectID.parse("notdata1")
    case.assertEqual(T.ObjectID.from_json(""), T.ObjectID.ZERO)
    case.assertEqual(T.ObjectID.ZERO.json(), "")


class WireStrictnessTests(unittest.TestCase):
    """The section 7.1 negative cases that `wire.py` alone answers for."""

    def test_a_truncated_string16_raises_and_yields_no_value(self) -> None:
        with self.assertRaises(ShortRead):
            Reader(b"\x00\x03AB").string16()

    def test_a_failed_read_does_not_advance_the_cursor(self) -> None:
        reader = Reader(b"ab")
        with self.assertRaises(ShortRead):
            reader.raw(3)
        self.assertEqual(reader.pos, 0)

    def test_short_read_on_a_truncated_scalar(self) -> None:
        with self.assertRaises(ShortRead):
            Reader(b"\x00\x01\x02").uint32()

    def test_allocation_cap_precedes_allocation(self) -> None:
        hostile = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
        with self.assertRaises(AllocationLimit):
            Reader(hostile + b"ab").string64()

    def test_allocation_cap_is_configurable(self) -> None:
        payload = (32).to_bytes(4, "big") + b"x" * 32
        self.assertEqual(len(Reader(payload).bytes32()), 32)
        with self.assertRaises(AllocationLimit):
            Reader(payload, max_alloc=16).bytes32()
        self.assertEqual(DEFAULT_MAX_ALLOC, 64 * 1024 * 1024)

    def test_integer_range_is_checked_per_width(self) -> None:
        for method, bad in (
            ("uint8", 256),
            ("uint8", -1),
            ("uint16", 1 << 16),
            ("uint32", 1 << 32),
            ("uint64", 1 << 64),
            ("int8", 128),
            ("int8", -129),
            ("int16", 1 << 15),
            ("int32", 1 << 31),
            ("int64", 1 << 63),
        ):
            with self.subTest(method=method, value=bad), self.assertRaises(RangeError):
                getattr(Writer(), method)(bad)

    def test_bounded_reader_windows_one_frame(self) -> None:
        reader = Reader(b"\x02ab" + b"tail")
        window = reader.bounded(3)
        self.assertEqual(window.bytes8(), b"ab")
        self.assertTrue(window.at_end)
        self.assertEqual(reader.rest(), b"tail")

    def test_strings_round_trip_arbitrary_bytes(self) -> None:
        # surrogateescape is the only handler that keeps a non-UTF-8 byte string
        # byte-exact through `str`, which content hashes depend on.
        writer = Writer()
        writer.string8(Reader(b"\x03\xff\xfe\xfd").string8())
        self.assertEqual(writer.getvalue(), b"\x03\xff\xfe\xfd")


_register_step1_codecs()
_install()
