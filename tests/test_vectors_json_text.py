"""Tier A: the JSON and text codecs, the channel lines, and query strings.

Three jobs, in this order:

1. Upgrade the vector harness's codecs with the JSON and text halves step 4
   owns, and register the channel-line provider, so every corpus vector carrying
   a `json` or `text` field starts executing.
2. Pin the parts of the two encodings the corpus does not carry as vectors: the
   container kinds, the text parser's wider separator set, and the negative
   cases of design section 7.1 that belong to JSON.
3. Pin the query-string form: sorted keys, Go's escaping, the reserved `arg`
   key, the length policy, and the per-type parameter text forms.

**Load order is load-bearing.** The harness keys codecs by astral type and a
later registration replaces an earlier one, so this module must import after
`test_vectors.py` -- which registers the payload-only codecs for the scalar
widths -- and its file name sorts that way. `test_every_encoded_vector_has_a_codec`
turns a reordering into a failure instead of a silent pile of skips.

The record schemas come from `test_codec_binary`: they are stand-ins that the
session and module-client steps move into `astral/api/`, and duplicating them
here would let the two copies drift.
"""

from __future__ import annotations

import dataclasses
import unittest
import warnings
from typing import Any, Callable

from astral import object as objects
from astral import querystring as qs
from astral.codec import jsoncodec, text
from astral.codec.binary import ObjectReader, payload_bytes, read_object
from astral.errors import ParseError, RangeError, SchemaError, StreamCorrupted, ValueTooLarge
from astral.primitives import SCALARS, Bytes8, String8, Uint8
from astral.spec import Any as AnySpec
from astral.spec import Array, Map, Primitive, Ptr, Ref, Slice
from astral.types import (
    Duration,
    Identity,
    Nonce,
    ObjectID,
    Size,
    Time,
    Zone,
    ascii_int,
)
from astral.wire import Reader, Writer
from test_codec_binary import _STANDIN
from vectors import (
    Codec,
    codec_for,
    register_codec,
    register_vector_skip,
    set_provider,
    vector_skip,
    vectors,
)

NODE = Identity.parse("03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1")

# The scalar widths whose JSON and text forms this step adds. The seven value
# types already carry all four of their encodings and are left alone.
_SCALAR_NAMES = (
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
)

# One vector's JSON provably cannot be inverted in Python: Go marshals negative
# zero as `-0`, a JSON *integer* literal, so every parser that yields native
# numbers hands back `0` and the sign is gone before any SDK code runs. It is one
# vector and not the whole float32 type, so it is keyed that way -- every other
# float32 vector's json_parse is measured.
# `test_float32_json_survives_everything_except_negative_zero` covers what the
# skip removes.
_NEGATIVE_ZERO = (
    "Go emits negative zero as the JSON integer literal `-0`; no Python JSON "
    "parser preserves its sign, so the payload cannot be recovered from the "
    "corpus JSON. See test_float32_json_survives_everything_except_negative_zero."
)

# A corpus vector whose JSON this design cannot emit, and why. Each is a gap the
# corpus itself records; none is a failure being silenced, and every one leaves
# its aspect reported as a skip rather than a pass.
NO_JSON_CODEC: dict[str, str] = {
    "struct(demo)": (
        "gap.struct_json.polymorphic_field and gap.struct_json.raw_bytes_field. "
        "The vector's JSON came out of Go's encoding/json, which resolves an "
        "interface field to the inner object's own JSON and a []byte field to "
        "base64 before any astral code runs. astral-go's own codec emits the "
        "{Type,Object} envelope for a polymorphic field and a number array for a "
        "uint8 slice. The corpus records both as unresolved; see "
        "test_struct_demo_json_differs_from_the_corpus_in_exactly_two_fields."
    ),
}

# One generated test the corpus and the harness disagree about. Reported in the
# step's return value; the vector is left exactly as the corpus records it.
_NEWLINE_DISAGREEMENT = "test_live_dir_alias_map__text_line"


# --- harness registration --------------------------------------------------


def _scalar_codec(name: str) -> Codec:
    """A payload codec for one scalar width, with both text façades attached."""
    scalar = SCALARS[name]

    def decode(payload: bytes) -> Any:
        reader = Reader(payload)
        value = scalar.read(reader)
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    def encode(value: Any) -> bytes:
        writer = Writer()
        scalar.write(writer, value)
        return writer.getvalue()

    return Codec(
        decode=decode,
        encode=encode,
        to_json=lambda v, _n=name: jsoncodec.json_scalar(_n, v),
        from_json=lambda d, _n=name: jsoncodec.read_json_scalar(_n, d),
        to_text=lambda v, _n=name: text.text_scalar(_n, v),
        from_text=lambda s, _n=name: text.read_text_scalar(_n, s),
    )


def _with_object_json(astral_type: str) -> None:
    """Attach whole-object JSON to a codec another step already registered.

    The existing codec keeps its payload half; only the JSON callables are
    added. `unmarshal` needs the type name and the stand-in registry, which is
    why the pair is built per type rather than once.
    """
    existing = codec_for(astral_type)
    assert existing is not None, f"no codec registered for {astral_type!r}"
    register_codec(
        astral_type,
        dataclasses.replace(
            existing,
            to_json=jsoncodec.marshal,
            from_json=lambda d, _t=astral_type: jsoncodec.unmarshal(
                _t, d, registry=_STANDIN
            ),
        ),
    )


def _with_spec_forms(astral_type: str, spec: Any) -> None:
    """Attach the JSON and text forms of one bare spec to its existing codec."""
    existing = codec_for(astral_type)
    assert existing is not None, f"no codec registered for {astral_type!r}"
    register_codec(
        astral_type,
        dataclasses.replace(
            existing,
            to_json=lambda v, _s=spec: jsoncodec.json_spec(_s, v),
            from_json=lambda d, _s=spec: jsoncodec.read_json_spec(
                _s, d, registry=_STANDIN
            ),
            to_text=lambda v, _s=spec: text.text_spec(_s, v),
            from_text=lambda s, _s=spec: text.read_text_spec(_s, s, registry=_STANDIN),
        ),
    )


def _object_of(astral_type: str, payload: bytes) -> Any:
    """The object a type name and a payload describe.

    An empty type is the untyped blob, which is not in the registry and is
    reached by an explicit special case, exactly as a binary channel reaches it.
    """
    reader = ObjectReader(payload, registry=_STANDIN)
    if not astral_type:
        return objects.Blob.read_payload(reader)
    return read_object(reader, astral_type)


class _Line:
    """The channel-line provider: one whole framed line, newline included."""

    @staticmethod
    def json_line(astral_type: str, payload: bytes) -> str:
        return jsoncodec.encode_line(_object_of(astral_type, payload))

    @staticmethod
    def text_line(astral_type: str, payload: bytes) -> str:
        return text.encode_line(_object_of(astral_type, payload))


def _register_step4_codecs() -> None:
    for name in _SCALAR_NAMES:
        register_codec(name, _scalar_codec(name))
    register_vector_skip("float32.neg0", "json_parse", _NEGATIVE_ZERO)

    for astral_type in (
        "stamp",
        "object_type",
        "bundle",
        "err_unexpected_object",
        "query",
        "mod.dir.alias_map",
        "mod.apphost.auth_token_msg",
        "mod.apphost.auth_success_msg",
        "mod.apphost.bind_msg",
        "mod.apphost.attach_query_msg",
        "mod.apphost.register_service_msg",
        "mod.apphost.incoming_query_msg",
        "mod.apphost.handle_query_msg",
        "mod.apphost.reject_incoming_msg",
        "mod.apphost.register_handler_msg",
        "mod.apphost.ping_msg",
        "mod.apphost.error_msg",
        "mod.apphost.query_rejected_msg",
        "mod.apphost.query_accepted_msg",
        "mod.apphost.host_info_msg",
        "mod.apphost.route_query_msg",
        "struct{string}",
        "struct{[]byte}",
        "struct{A *uint16; B *uint16}",
    ):
        _with_object_json(astral_type)

    _with_spec_forms("object", AnySpec())


# --- the JSON codec --------------------------------------------------------


class JsonScalarTests(unittest.TestCase):
    def test_json_refuses_nan_and_infinity(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            for name in ("float32", "float64"):
                with self.subTest(value=value, name=name):
                    with self.assertRaises(RangeError):
                        jsoncodec.json_scalar(name, value)
                    with self.assertRaises(RangeError):
                        jsoncodec.float_json(value)

    def test_text_keeps_gos_spellings_for_nan_and_infinity(self) -> None:
        # JSON has no literal for these; the text encoding does, and a text
        # channel carries them, so only JSON refuses.
        self.assertEqual(jsoncodec.float_text(float("nan")), "NaN")
        self.assertEqual(jsoncodec.float_text(float("inf")), "+Inf")
        self.assertEqual(jsoncodec.float_text(float("-inf")), "-Inf")
        for spelling in ("NaN", "+Inf", "-Inf"):
            with self.subTest(spelling=spelling):
                parsed = text.read_text_scalar("float64", spelling)
                self.assertEqual(jsoncodec.float_text(parsed), spelling)

    def test_a_float32_carries_its_width_to_the_serialiser(self) -> None:
        # dumps() sees a value, not a schema, and float32(0.1) widened to a
        # Python float is 0.10000000149011612.
        widened = SCALARS["float32"].read(Reader(bytes.fromhex("3dcccccd")))
        self.assertEqual(jsoncodec.dumps(jsoncodec.json_scalar("float32", widened)), "0.1")
        self.assertEqual(jsoncodec.dumps(widened), "0.10000000149011612")

    def test_a_boolean_is_not_an_integer(self) -> None:
        with self.assertRaises(SchemaError):
            jsoncodec.json_scalar("uint8", True)
        with self.assertRaises(ParseError):
            jsoncodec.read_json_scalar("uint8", True)

    def test_integer_width_is_enforced_in_both_directions(self) -> None:
        for name, bad in (("uint8", 256), ("uint8", -1), ("int8", 128), ("int16", -32769)):
            with self.subTest(name=name, value=bad):
                with self.assertRaises(RangeError):
                    jsoncodec.json_scalar(name, bad)
                with self.assertRaises(RangeError):
                    jsoncodec.read_json_scalar(name, bad)

    def test_base64_is_std_alphabet_with_padding(self) -> None:
        self.assertEqual(jsoncodec.json_scalar("bytes8", b"\xde\xad"), "3q0=")
        self.assertEqual(jsoncodec.read_json_scalar("bytes8", "3q0="), b"\xde\xad")
        # Emission always pads; parsing does not insist on it.
        self.assertEqual(jsoncodec.read_json_scalar("bytes8", "3q0"), b"\xde\xad")
        with self.assertRaises(ParseError):
            jsoncodec.read_json_scalar("bytes8", "not base64!")

    def test_a_float_json_number_may_be_an_integer_literal(self) -> None:
        self.assertEqual(jsoncodec.read_json_scalar("float64", 2), 2.0)

    def test_float32_json_survives_everything_except_negative_zero(self) -> None:
        # The corpus's float32 json_parse aspect is skipped as lossy, so the
        # invertible half is pinned here instead.
        for value, payload in ((1.5, "3fc00000"), (0.0, "00000000"), (-1.5, "bfc00000")):
            with self.subTest(value=value):
                parsed = jsoncodec.read_json_scalar("float32", value)
                writer = Writer()
                SCALARS["float32"].write(writer, parsed)
                self.assertEqual(writer.getvalue().hex(), payload)
        # And the sign that is lost is lost in the parser, not in the codec.
        self.assertEqual(jsoncodec.float_json(-0.0, 32), "-0")
        self.assertEqual(jsoncodec.loads("-0"), 0)

    def test_float32_at_the_top_of_its_range_encodes_and_parses(self) -> None:
        """The whole band above FLT_MAX that a shortest decimal can land in.

        `struct.pack(">f")` raises `OverflowError` for every double above
        FLT_MAX, including the band IEEE 754 rounds back down to it, and
        `3.4028235e+38` -- the shortest form of FLT_MAX -- is in that band. Both
        forms are astral-go's own output for the same payloads
        (`json.Marshal` / `MarshalText` on `astral.Float32(math.MaxFloat32)`).
        """
        cases = {
            "7f7fffff": ("3.4028235e+38", "340282350000000000000000000000000000000"),
            "ff7fffff": ("-3.4028235e+38", "-340282350000000000000000000000000000000"),
            "7f7ffffe": ("3.4028233e+38", "340282330000000000000000000000000000000"),
            "7f7ffff0": ("3.4028204e+38", "340282040000000000000000000000000000000"),
        }
        for payload, (as_json, as_text) in cases.items():
            with self.subTest(payload):
                value = SCALARS["float32"].read(Reader(bytes.fromhex(payload)))
                self.assertEqual(jsoncodec.json_scalar("float32", value), value)
                self.assertEqual(jsoncodec.dumps(jsoncodec.json_scalar("float32", value)), as_json)
                self.assertEqual(text.text_scalar("float32", value), as_text)
                for parsed in (
                    jsoncodec.read_json_scalar("float32", jsoncodec.loads(as_json)),
                    text.read_text_scalar("float32", as_text),
                ):
                    writer = Writer()
                    SCALARS["float32"].write(writer, parsed)
                    self.assertEqual(writer.getvalue().hex(), payload)

    def test_a_number_outside_the_float32_range_is_refused(self) -> None:
        # The bound `Writer.float32` enforces: a value with no float32 payload
        # has no float32 JSON or text form either.
        for value in (1e39, -1e39, 3.5e38):
            with self.subTest(value):
                with self.assertRaises(RangeError):
                    jsoncodec.json_scalar("float32", value)
                with self.assertRaises(RangeError):
                    text.text_scalar("float32", value)
                with self.assertRaises(RangeError):
                    jsoncodec.read_json_scalar("float32", value)
                with self.assertRaises(RangeError):
                    text.read_text_scalar("float32", repr(value))
                with self.assertRaises(RangeError):
                    SCALARS["float32"].write(Writer(), value)
        # float64 carries all of them.
        self.assertEqual(jsoncodec.read_json_scalar("float64", 1e39), 1e39)

    def test_the_float32_parse_boundary_is_gos_boundary(self) -> None:
        # `strconv.ParseFloat(s, 32)` returns an infinity only for a value MORE
        # than half a float32 step past FLT_MAX, so the midpoint itself parses as
        # FLT_MAX. Each line below is astral-go's own output for that string.
        largest = SCALARS["float32"].read(Reader(bytes.fromhex("7f7fffff")))
        for text_form in (
            "3.4028235e+38",
            "3.402823567797336e+38",
            "3.4028235677973366e+38",
        ):
            with self.subTest(text_form):
                self.assertEqual(text.read_text_scalar("float32", text_form), largest)
                self.assertEqual(
                    jsoncodec.read_json_scalar("float32", float(text_form)), largest
                )
        for text_form in ("3.4028236e+38", "-3.4028236e+38"):
            with self.subTest(text_form), self.assertRaises(RangeError):
                text.read_text_scalar("float32", text_form)

    def test_go_float_style_thresholds(self) -> None:
        # Go's encoding/json leaves `f` style at 1e-6 and 1e21, and trims a
        # two-digit negative exponent's leading zero.
        self.assertEqual(jsoncodec.float_json(1e-6), "0.000001")
        self.assertEqual(jsoncodec.float_json(1e-7), "1e-7")
        self.assertEqual(jsoncodec.float_json(1e20), "100000000000000000000")
        self.assertEqual(jsoncodec.float_json(1e21), "1e+21")
        self.assertEqual(jsoncodec.float_json(-0.0), "-0")
        # The text form never uses an exponent.
        self.assertEqual(jsoncodec.float_text(1e-7), "0.0000001")
        self.assertEqual(jsoncodec.float_text(1e21), "1000000000000000000000")


class JsonSpecTests(unittest.TestCase):
    def test_an_empty_container_is_null_and_null_parses_back_empty(self) -> None:
        self.assertIsNone(jsoncodec.json_spec(Slice("string8"), []))
        self.assertIsNone(jsoncodec.json_spec(Map("string16", "uint8"), {}))
        self.assertEqual(jsoncodec.read_json_spec(Slice("string8"), None), [])
        self.assertEqual(jsoncodec.read_json_spec(Map("string16", "uint8"), None), {})
        # A peer that emits the empty forms instead is read the same way.
        self.assertEqual(jsoncodec.read_json_spec(Slice("string8"), []), [])
        self.assertEqual(jsoncodec.read_json_spec(Map("string16", "uint8"), {}), {})

    def test_an_array_is_always_a_list(self) -> None:
        self.assertEqual(jsoncodec.json_spec(Array("uint16", 2), [1, 2]), [1, 2])
        self.assertEqual(jsoncodec.json_spec(Array("uint16", 0), []), [])
        with self.assertRaises(SchemaError):
            jsoncodec.json_spec(Array("uint16", 2), [1])
        with self.assertRaises(ParseError):
            jsoncodec.read_json_spec(Array("uint16", 2), [1])

    def test_map_json_keys_are_strings_sorted_lexicographically(self) -> None:
        # Binary sorts by encoded key bytes, so "hi" precedes "abc" there --
        # the length prefix comes first. JSON sorts the string forms.
        spec = Map("string16", "uint8")
        self.assertEqual(
            list(jsoncodec.json_spec(spec, {"hi": 1, "abc": 2})), ["abc", "hi"]
        )
        numeric = Map("uint16", "uint8")
        self.assertEqual(
            list(jsoncodec.json_spec(numeric, {256: 1, 7: 2, 1: 3})), ["1", "256", "7"]
        )
        self.assertEqual(
            jsoncodec.read_json_spec(numeric, {"1": 3, "256": 1}), {1: 3, 256: 1}
        )

    def test_a_polymorphic_field_is_an_envelope(self) -> None:
        self.assertEqual(
            jsoncodec.json_spec(AnySpec(), Uint8(21)),
            {"Type": "uint8", "Object": 21},
        )
        self.assertIsNone(jsoncodec.json_spec(AnySpec(), None))
        parsed = jsoncodec.read_json_spec(AnySpec(), {"Type": "uint8", "Object": 21})
        self.assertEqual(parsed, Uint8(21))
        self.assertIsNone(jsoncodec.read_json_spec(AnySpec(), None))

    def test_a_ptr_is_null_when_absent(self) -> None:
        self.assertIsNone(jsoncodec.json_spec(Ptr("identity"), None))
        self.assertEqual(jsoncodec.json_spec(Ptr("identity"), Identity.ANYONE), "anyone")
        self.assertIsNone(jsoncodec.read_json_spec(Ptr("identity"), None))

    def test_a_ref_refuses_absence(self) -> None:
        with self.assertRaises(SchemaError):
            jsoncodec.json_spec(Ref("identity"), None)
        with self.assertRaises(SchemaError):
            jsoncodec.json_spec(Primitive("uint8"), None)

    def test_an_unregistered_type_is_fatal(self) -> None:
        with self.assertRaises(StreamCorrupted):
            jsoncodec.read_envelope({"Type": "no.such.type", "Object": None})


class JsonEnvelopeTests(unittest.TestCase):
    def test_an_untyped_object_has_no_envelope(self) -> None:
        with self.assertRaises(SchemaError):
            jsoncodec.envelope(objects.Blob(b"hello"))

    def test_the_envelope_keys_are_type_then_object(self) -> None:
        self.assertEqual(list(jsoncodec.envelope(Uint8(7))), ["Type", "Object"])

    def test_the_type_key_is_matched_case_insensitively(self) -> None:
        self.assertEqual(
            jsoncodec.read_envelope({"type": "uint8", "object": 7}), Uint8(7)
        )
        with self.assertRaises(ParseError):
            jsoncodec.read_envelope({"Type": "uint8", "type": "uint8"})
        with self.assertRaises(ParseError):
            jsoncodec.read_envelope({"Object": 7})

    def test_an_absent_object_key_reads_as_the_zero_value(self) -> None:
        # `omitempty` on Go's raw-message field can drop the key entirely.
        self.assertEqual(jsoncodec.read_envelope({"Type": "ack"}), objects.Ack())


class JsonFieldTests(unittest.TestCase):
    """Field-name handling, which is where the JSON codec differs from binary."""

    def test_fields_are_matched_case_insensitively(self) -> None:
        parsed = jsoncodec.unmarshal(
            "mod.apphost.host_info_msg",
            {"identity": NODE.hex(), "ALIAS": "furry-bolt"},
            registry=_STANDIN,
        )
        self.assertEqual(parsed.alias, "furry-bolt")
        self.assertEqual(parsed.identity, NODE)

    def test_keys_differing_only_in_case_are_ambiguous(self) -> None:
        with self.assertRaises(ParseError):
            jsoncodec.unmarshal(
                "mod.apphost.host_info_msg",
                {"Alias": "a", "alias": "b"},
                registry=_STANDIN,
            )

    def test_an_omitted_field_keeps_its_declared_default(self) -> None:
        parsed = jsoncodec.unmarshal(
            "mod.apphost.route_query_msg", {"Query": "dir.alias_map"}, registry=_STANDIN
        )
        self.assertEqual(parsed.zone, Zone.ALL)
        self.assertEqual(parsed.filters, [])

    def test_an_unknown_field_is_a_fault(self) -> None:
        with self.assertRaises(ParseError):
            jsoncodec.unmarshal(
                "mod.apphost.host_info_msg", {"Nope": 1}, registry=_STANDIN
            )

    def test_the_schema_is_read_off_the_object_and_not_off_its_class(self) -> None:
        # A schema that arrived on the wire lives per instance -- `RuntimeRecord`
        # declares FIELDS in `__slots__` -- so a class-level lookup finds the
        # slot descriptor and the walk fails inside the codec.
        class PerInstance:
            __slots__ = ("ASTRAL_TYPE", "FIELDS", "N")

            def __init__(self) -> None:
                self.ASTRAL_TYPE = "t.per_instance"
                self.FIELDS = (("N", "N", Primitive("uint8")),)
                self.N = 7

        self.assertEqual(jsoncodec.marshal(PerInstance()), {"N": 7})

        broken = PerInstance()
        broken.FIELDS = object()  # type: ignore[assignment]
        with self.assertRaises(SchemaError):
            jsoncodec.marshal(broken)

    def test_a_record_with_no_fields_is_an_empty_object(self) -> None:
        ping = _STANDIN.new("mod.apphost.ping_msg")
        self.assertEqual(jsoncodec.marshal(ping), {})

    def test_a_zero_payload_object_is_null_and_not_an_empty_object(self) -> None:
        self.assertIsNone(jsoncodec.marshal(objects.Ack()))


class JsonWriterTests(unittest.TestCase):
    def test_output_is_compact_and_html_escaped(self) -> None:
        self.assertEqual(jsoncodec.dumps({"a": 1, "b": [1, 2]}), '{"a":1,"b":[1,2]}')
        self.assertEqual(jsoncodec.dumps("a<b>&c"), '"a\\u003cb\\u003e\\u0026c"')

    def test_control_characters_follow_go(self) -> None:
        # Go writes \n, \r and \t as escapes and everything else below 0x20 as
        # \u00xx -- including backspace and form feed, which Python shortens.
        self.assertEqual(jsoncodec.dumps("\n\r\t\b\f\x00"), '"\\n\\r\\t\\u0008\\u000c\\u0000"')

    def test_line_separators_are_escaped(self) -> None:
        self.assertEqual(jsoncodec.dumps("  "), '"\\u2028\\u2029"')

    def test_a_non_utf8_byte_becomes_the_replacement_character(self) -> None:
        # `surrogateescape` is how a non-UTF-8 byte survives as `str`; Go's
        # encoder substitutes U+FFFD for each such byte.
        self.assertEqual(jsoncodec.dumps("a\udcffb"), '"a�b"')

    def test_mapping_order_is_the_callers(self) -> None:
        self.assertEqual(jsoncodec.dumps({"b": 1, "a": 2}), '{"b":1,"a":2}')

    def test_a_non_json_value_is_refused(self) -> None:
        with self.assertRaises(SchemaError):
            jsoncodec.dumps(object())


# --- the text codec --------------------------------------------------------


class TextParserTests(unittest.TestCase):
    def test_separators_the_docs_omit(self) -> None:
        for line, encoding in (
            ("#[uint8] 21", "text"),
            ("#[uint8]\t21", "text"),
            ("#[uint8]:FQ==", "base64"),
            ("#[uint8]=FQ==", "base64"),
            ("#[ack]", "none"),
        ):
            with self.subTest(line=line):
                self.assertEqual(text.parse_header(line).encoding, encoding)

    def test_a_missing_or_unterminated_header_is_a_fault(self) -> None:
        for line in ("uint8 21", "#[uint8 21", ""):
            with self.subTest(line=line), self.assertRaises(ParseError):
                text.parse_header(line)

    def test_an_unrecognised_separator_is_a_fault(self) -> None:
        with self.assertRaises(ParseError):
            text.parse_header("#[uint8]/21")

    def test_an_empty_type_is_the_untyped_blob(self) -> None:
        self.assertEqual(text.parse_header("#[] aGVsbG8=").type, "")
        self.assertEqual(text.decode("#[] aGVsbG8="), objects.Blob(b"hello"))
        self.assertEqual(text.decode("#[]:aGVsbG8="), objects.Blob(b"hello"))

    def test_a_bare_header_yields_the_zero_value(self) -> None:
        self.assertEqual(text.decode("#[ack]"), objects.Ack())
        self.assertEqual(text.decode("#[uint8]"), Uint8(0))

    def test_an_unregistered_type_is_fatal(self) -> None:
        with self.assertRaises(StreamCorrupted):
            text.decode("#[no.such.type] x")


class TextEmissionTests(unittest.TestCase):
    def test_a_zero_payload_object_keeps_its_trailing_space(self) -> None:
        self.assertEqual(text.encode(objects.Ack()), "#[ack] ")
        self.assertEqual(text.encode_line(objects.EOS()), "#[eos] \n")

    def test_an_untyped_blob_uses_the_space_separator(self) -> None:
        # The docs say `#[]:<base64>`; astral-go emits `#[] <base64>` because
        # Blob's own text form is base64. Both parse identically.
        self.assertEqual(text.encode(objects.Blob(b"hello")), "#[] aGVsbG8=")

    def test_a_type_with_no_text_form_falls_back_to_base64(self) -> None:
        alias_map = _STANDIN.new("mod.dir.alias_map")
        alias_map.aliases = {"furry-bolt": NODE}
        self.assertEqual(
            text.encode(alias_map),
            "#[mod.dir.alias_map]:"
            + jsoncodec.encode_base64(payload_bytes(alias_map)),
        )
        self.assertFalse(text.has_text_form(alias_map))

    def test_object_type_and_stamp_have_no_channel_text_form(self) -> None:
        # Neither implements MarshalText in astral-go, so a text channel cannot
        # render either as text and must base64 the payload.
        self.assertTrue(text.encode(_STANDIN.new("object_type")).startswith("#[object_type]:"))
        self.assertTrue(text.encode(_STANDIN.new("stamp")).startswith("#[stamp]:"))

    def test_base64_only_forces_the_colon_form(self) -> None:
        self.assertEqual(text.encode(Uint8(21), base64_only=True), "#[uint8]:FQ==")

    def test_a_line_round_trips(self) -> None:
        for obj in (
            Uint8(21),
            String8("hi"),
            Bytes8(b"\xde\xad"),
            objects.Ack(),
            objects.Blob(b"hello"),
            Identity.ANYONE,
            Zone.ALL,
            Nonce(0x0102030405060708),
            Time(1),
            Duration(-1),
            Size(1536),
            ObjectID.ZERO,
        ):
            with self.subTest(obj=obj):
                line = text.encode_line(obj, base64_only=False)
                self.assertEqual(text.decode_line(line, registry=_STANDIN), obj)


class AsciiIntTests(unittest.TestCase):
    """`ascii_int` is the one guard for text a peer wrote that must be a number.

    `int()` is not that grammar -- it strips whitespace, takes a sign, takes PEP
    515 underscores and takes an `0x` prefix at base 16 -- and `str.isdigit()`
    is not a guard for it either, being true of U+00B2, which `int()` refuses.
    The pair `isdigit()` then `int()` therefore raised a bare `ValueError` from
    outside the SDK's hierarchy on peer bytes; it guarded an HTTP status line, a
    `Content-Length`, a `tcp:` port and a `ws://` port.
    """

    def test_only_ascii_digits_are_a_number(self) -> None:
        self.assertEqual(ascii_int("8625"), 8625)
        self.assertEqual(ascii_int("007"), 7)
        for bad in ("+5", "-5", "1_0", " 5", "5 ", "", "0x5", "²", "١٢", "5.0"):
            with self.subTest(bad=bad):
                self.assertIsNone(ascii_int(bad))

    def test_base_sixteen_is_hexdig_and_nothing_else(self) -> None:
        self.assertEqual(ascii_int("ff", 16), 255)
        self.assertEqual(ascii_int("FF", 16), 255)
        for bad in ("0xff", "+ff", "f_f", " ff", "", "g"):
            with self.subTest(bad=bad):
                self.assertIsNone(ascii_int(bad, 16))

    def test_a_nonce_reads_hex_and_only_hex(self) -> None:
        """A nonce is a correlator a peer supplies: `apphost.cancel?id=` carries
        one back, so its parser is on the peer-facing surface."""
        self.assertEqual(int(Nonce.parse("1122334455667788")), 0x1122334455667788)
        self.assertEqual(int(Nonce.parse("ff")), 255)
        for bad in ("0xff", "+ff", "f_f", " ff"):
            with self.subTest(bad=bad):
                with self.assertRaises(ParseError):
                    Nonce.parse(bad)


class TextScalarTests(unittest.TestCase):
    def test_unsigned_text_refuses_a_sign(self) -> None:
        # astral-go's ParseUint rejects a sign; Python's int() would not.
        for bad in ("-1", "+1", "1_0", " 1", "0x10", ""):
            with self.subTest(bad=bad), self.assertRaises((ParseError, RangeError)):
                text.read_text_scalar("uint8", bad)

    def test_signed_text_is_parsed_at_its_own_width(self) -> None:
        # astral-go parses every signed width through int8 and overflows the
        # wider ones; each width is checked here.
        self.assertEqual(text.read_text_scalar("int16", "-32768"), -32768)
        self.assertEqual(text.read_text_scalar("int64", "-9223372036854775808"), -(1 << 63))
        with self.assertRaises(RangeError):
            text.read_text_scalar("int8", "128")
        with self.assertRaises(RangeError):
            text.read_text_scalar("int16", "32768")

    def test_boolean_text_is_lenient_on_parse(self) -> None:
        for true in ("true", "TRUE", "yes", "t", "Y", "1"):
            with self.subTest(true=true):
                self.assertIs(text.read_text_scalar("bool", true), True)
        for false in ("false", "No", "f", "n", "0"):
            with self.subTest(false=false):
                self.assertIs(text.read_text_scalar("bool", false), False)
        with self.assertRaises(ParseError):
            text.read_text_scalar("bool", "maybe")

    def test_a_container_has_no_text_form(self) -> None:
        for spec in (Slice("uint8"), Array("uint8", 2), Map("string16", "uint8")):
            with self.subTest(spec=spec):
                with self.assertRaises(SchemaError):
                    text.text_spec(spec, [])
                with self.assertRaises(SchemaError):
                    text.read_text_spec(spec, "")

    def test_a_polymorphic_parameter_carries_its_own_header(self) -> None:
        # Nothing else in a bare parameter value names the type.
        self.assertEqual(text.text_spec(AnySpec(), Uint8(21)), "#[uint8] 21")
        self.assertEqual(
            text.read_text_spec(AnySpec(), "#[uint8] 21", registry=_STANDIN), Uint8(21)
        )

    def test_an_absent_pointer_has_no_text_form(self) -> None:
        # A caller omits the key; an empty string is a legitimate string8.
        with self.assertRaises(SchemaError):
            text.text_spec(Ptr("identity"), None)


# --- query strings ---------------------------------------------------------


class QueryStringTests(unittest.TestCase):
    def test_keys_are_sorted(self) -> None:
        self.assertEqual(
            qs.build("objects.read", {"zone": "dvn", "id": "x", "arg": "y"}),
            "objects.read?arg=y&id=x&zone=dvn",
        )

    def test_an_operation_with_no_parameters_carries_no_question_mark(self) -> None:
        self.assertEqual(qs.build("dir.alias_map"), "dir.alias_map")
        self.assertEqual(qs.build("dir.alias_map", {}), "dir.alias_map")

    def test_escaping_matches_gos_query_escape(self) -> None:
        self.assertEqual(qs.quote("a b"), "a+b")
        self.assertEqual(qs.quote("-_.~"), "-_.~")
        self.assertEqual(qs.quote("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e")
        self.assertEqual(qs.unquote("a+b%2Fc"), "a b/c")

    def test_a_none_parameter_is_omitted_rather_than_sent_empty(self) -> None:
        # `key=` and an absent key are different: the node's defaults hold only
        # while the key stays absent.
        self.assertEqual(qs.build("crypto.sign", scheme=None, data="x"), "crypto.sign?data=x")
        self.assertEqual(
            qs.build("crypto.sign", scheme="", data="x"), "crypto.sign?data=x&scheme="
        )

    def test_value_types_use_their_text_form_not_their_str(self) -> None:
        # str(Size(1536)) is the human form 1.5KiB; the text encoding is decimal.
        self.assertEqual(qs.build("objects.new_mem", size=Size(1536)), "objects.new_mem?size=1536")
        self.assertEqual(qs.build("q", zone=Zone.ALL), "q?zone=dvn")
        self.assertEqual(
            qs.build("q", nonce=Nonce(0xFF)), "q?nonce=00000000000000ff"
        )
        self.assertEqual(qs.build("q", d=Duration(90_000_000_000)), "q?d=1m30s")
        self.assertEqual(qs.build("q", id=NODE), "q?id=" + NODE.hex())

    def test_bytes_and_booleans_have_parameter_forms(self) -> None:
        self.assertEqual(qs.build("q", raw=b"\xde\xad"), "q?raw=3q0%3D")
        self.assertEqual(qs.build("q", flag=True, off=False), "q?flag=true&off=false")

    def test_parse_splits_the_operation_from_its_parameters(self) -> None:
        self.assertEqual(qs.parse("dir.alias_map"), ("dir.alias_map", {}))
        self.assertEqual(
            qs.parse("objects.read?id=abc+d&zone=dvn"),
            ("objects.read", {"id": "abc d", "zone": "dvn"}),
        )

    def test_the_first_value_of_a_repeated_key_wins(self) -> None:
        self.assertEqual(qs.parse("q?a=1&a=2")[1], {"a": "1"})

    def test_a_valueless_segment_yields_an_empty_value(self) -> None:
        # astral-go has a branch meant to route this to `arg`, but
        # url.ParseQuery always produces a value, so the branch is dead.
        self.assertEqual(qs.parse("q?flag")[1], {"flag": ""})

    def test_build_and_parse_round_trip(self) -> None:
        params = {"a": "x y", "b": "?&=", "c": "zażółć"}
        self.assertEqual(qs.parse(qs.build("op", params)), ("op", params))

    def test_the_positional_argument_lands_under_arg(self) -> None:
        self.assertEqual(qs.ARG_KEY, "arg")
        self.assertEqual(
            qs.args_to_params(["-zone", "dvn", "path", "--out", "json"]),
            {"zone": "dvn", "arg": "path", "out": "json"},
        )
        # A later positional replaces an earlier one, matching ArgsToMap.
        self.assertEqual(qs.args_to_params(["a", "b"]), {"arg": "b"})
        self.assertEqual(qs.args_to_params(["-flag"]), {"flag": ""})
        self.assertEqual(qs.args_to_params([]), {})

    def test_the_255_byte_limit_warns_and_the_wire_limit_refuses(self) -> None:
        self.assertEqual((qs.ADVISORY_LENGTH, qs.MAX_LENGTH), (255, 65535))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            long = qs.build("op", a="x" * 300)
        self.assertEqual(len(caught), 1)
        self.assertIs(caught[0].category, qs.QueryStringTooLong)
        self.assertTrue(long.startswith("op?a=xxx"))
        with self.assertRaises(ValueTooLarge):
            qs.build("op", a="x" * 70_000)

    def test_a_short_query_warns_about_nothing(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            qs.build("dir.resolve", name="furry-bolt")
        self.assertEqual(caught, [])

    def test_declared_specs_drive_the_parameter_form(self) -> None:
        specs = {"zone": Primitive("zone"), "id": Ptr("identity"), "n": Primitive("uint8")}
        self.assertEqual(
            qs.encode_params(specs, {"zone": Zone.DEVICE, "id": NODE, "n": 7, "x": None}),
            {"zone": "d", "id": NODE.hex(), "n": "7"},
        )
        self.assertEqual(qs.parse_param(Primitive("zone"), "dn"), Zone.DEVICE | Zone.NETWORK)
        self.assertEqual(qs.parse_param(Ptr("identity"), NODE.hex()), NODE)

    def test_a_type_tagged_cli_value_reduces_to_the_bare_form(self) -> None:
        # `-p name=#[type]value` is a CLI convenience; the query string carries
        # only the payload half.
        self.assertEqual(qs.bare_param("#[uint8] 21"), "21")
        self.assertEqual(qs.bare_param("#[zone] dvn"), "dvn")
        self.assertEqual(qs.bare_param("21"), "21")


# --- the recorded gap ------------------------------------------------------


class RecordedGapTests(unittest.TestCase):
    def test_struct_demo_json_differs_from_the_corpus_in_exactly_two_fields(self) -> None:
        """The corpus's `struct.demo` JSON is a recorded gap, in two fields.

        Its `Any` is the inner object's own JSON and its `Raw` is base64, both
        because the vector was produced through Go's `encoding/json`. astral-go's
        own codec -- `marshalFieldJSON` for a polymorphic field, `sliceValue` for
        a `uint8` slice -- produces the envelope and a number array, which is
        what this SDK emits. No other field disagrees, so the divergence is
        exactly the two the corpus already flags.
        """
        vector = next(v for v in vectors() if v.id == "struct.demo")
        codec = codec_for("struct(demo)")
        assert codec is not None
        ours = jsoncodec.marshal(codec.decode(vector.payload))
        theirs = vector.json_value

        self.assertEqual(
            {k: v for k, v in ours.items() if k not in ("Any", "Raw")},
            {k: v for k, v in theirs.items() if k not in ("Any", "Raw")},
        )
        self.assertEqual(ours["Any"], {"Type": "nonce64", "Object": "1122334455667788"})
        self.assertEqual(theirs["Any"], "1122334455667788")
        self.assertEqual(ours["Raw"], [222, 173])
        self.assertEqual(theirs["Raw"], "3q0=")

    def test_the_live_alias_map_text_matches_apart_from_the_channel_newline(self) -> None:
        """`live.dir.alias_map`'s text is an encoding, not a whole channel line.

        Every `line.*` vector records the line a text channel writes, newline
        included; this one records the same object's text *encoding* without it,
        and the harness routes both through `text_line`. The generated
        `text_line` aspect is therefore an expected failure, and the fidelity
        claim it was meant to make is asserted here instead: the emitted encoding
        is the live capture, byte for byte.
        """
        vector = next(v for v in vectors() if v.id == "live.dir.alias_map")
        line = _Line.text_line(vector.astral_type, vector.payload)
        self.assertEqual(line, vector.text + "\n")


# --- the load-order guard --------------------------------------------------


class CodecCoverageTests(unittest.TestCase):
    """Turn a silent skip back into a failure.

    Every codec here replaces one another step registered, so an import order
    that puts this module first would leave the JSON and text aspects skipping
    with no other symptom.
    """

    def _missing(self, aspect: str, attribute: str) -> list[str]:
        missing: list[str] = []
        for vector in vectors():
            if not vector.has(aspect):
                continue
            if getattr(vector, f"{aspect}_is_line"):
                continue
            astral_type = vector.astral_type
            if astral_type in NO_JSON_CODEC and aspect == "json":
                continue
            codec = codec_for(astral_type)
            if codec is None or getattr(codec, attribute) is None:
                missing.append(f"{vector.id} [{astral_type}]")
        return missing

    def test_every_encoded_vector_has_a_codec(self) -> None:
        self.assertEqual(self._missing("json", "to_json"), [])
        self.assertEqual(self._missing("json", "from_json"), [])
        self.assertEqual(self._missing("text", "to_text"), [])
        self.assertEqual(self._missing("text", "from_text"), [])

    def test_every_skipped_aspect_names_a_reason(self) -> None:
        """No JSON or text aspect may be skipped without a citation.

        A skip is either a whole type with no codec -- `NO_JSON_CODEC`, one entry,
        the `struct(demo)` gap -- or one vector's one aspect registered with the
        gap it cites. Anything else that skips is an unexplained hole.
        """
        expected = {
            ("blueprint.struct", "json_emit"),
            ("blueprint.struct", "json_parse"),
            ("blueprint.field", "json_emit"),
            ("blueprint.field", "json_parse"),
            ("float32.neg0", "json_parse"),
        }
        registered = {
            (vector.id, aspect)
            for vector in vectors()
            for aspect in ("json_emit", "json_parse", "text_emit", "text_parse")
            if vector_skip(vector.id, aspect) is not None
        }
        self.assertEqual(registered, expected)
        for vector_id, aspect in registered:
            with self.subTest(vector_id, aspect=aspect):
                reason = vector_skip(vector_id, aspect)
                assert reason is not None
                self.assertTrue(reason.startswith("gap.") or "Go " in reason, reason)

    def test_the_line_provider_is_registered_for_every_line_vector(self) -> None:
        for vector in vectors():
            if vector.json_is_line and vector.has("json"):
                with self.subTest(vector.id):
                    self.assertIsInstance(
                        _Line.json_line(vector.astral_type, vector.payload), str
                    )


def _mark_newline_disagreement() -> None:
    """Mark the one generated test the corpus and the harness disagree about.

    `line.*` records a whole text-channel line, newline included, and
    `live.dir.alias_map` records the same object's text *encoding* without one --
    yet the harness routes both through `text_line`. The provider emits what
    astral-go's `TextSender` emits, which is the form with the newline, so the
    live vector cannot match. The vector is left exactly as recorded.
    """
    # Imported here rather than at module scope: a name bound in this module
    # would make discovery collect the generated vector suite a second time.
    from test_vectors import VectorTests

    existing: Callable[..., None] | None = getattr(VectorTests, _NEWLINE_DISAGREEMENT, None)
    if existing is None:  # pragma: no cover - the corpus no longer carries it
        return
    setattr(VectorTests, _NEWLINE_DISAGREEMENT, unittest.expectedFailure(existing))


_register_step4_codecs()
set_provider("line", _Line)
_mark_newline_disagreement()
