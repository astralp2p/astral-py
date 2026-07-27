"""Tier A: the spec-driven binary codec, the registry and the framings.

Three jobs, in this order:

1. Register step 2's codecs and the framing provider with the vector harness, so
   every corpus vector whose payload this step can encode starts executing.
2. Pin the design's section 7.1 must-pass table for the cases the corpus does
   not carry as vectors, and every negative case.
3. Sweep every spec kind with a seeded generator, 10 000 round trips.

**Stand-in schemas.** `mod.apphost.*` and `mod.dir.alias_map` belong in
`astral/api/apphost.py` and `astral/api/dir.py`, which land with the session and
module-client steps. Their schemas are declared here, in a child registry, so
their vectors are proven now. Whoever writes those modules moves the
declarations across verbatim and deletes `_STANDIN` and everything under it.
"""

from __future__ import annotations

import random
import struct
import unittest
from typing import Any, Callable

from astral import codec, object as objects, primitives as P
from astral.codec.binary import (
    ObjectReader,
    ObjectWriter,
    object_reader,
    payload_bytes,
    read_spec,
    spec_zero,
    write_spec,
)
from astral.errors import (
    CycleDetected,
    DepthExceeded,
    InvalidFlag,
    ParseError,
    SchemaError,
    StreamCorrupted,
    ValueTooLarge,
    WireError,
)
from astral.record import F, alias, embed, record, wire
from astral.registry import Blueprints, default_blueprints
from astral.spec import (
    MAP_KEY_TYPES,
    MAX_ARRAY_LENGTH,
    MAX_DEPTH,
    PRIMITIVE_TYPES,
    Any as AnySpec,
    Array,
    Map,
    Primitive,
    Ptr,
    Ref,
    Slice,
    Spec,
    needs_presence,
)
from astral.types import Duration, Identity, Nonce, ObjectID, Size, Time, Zone
from astral.wire import Reader, Writer
from vectors import Codec, Vector, register_codec, register_negative, set_provider

NODE = Identity.parse("03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1")

# Every test-only schema lives in a child of the process registry: a child cannot
# shadow a parent, and a parent that later gains the same name never collides
# with a child that already holds it.
_STANDIN = Blueprints(default_blueprints())


# --- stand-in schemas: mod.apphost.* ---------------------------------------


@record("mod.apphost.auth_token_msg", registry=_STANDIN)
class AuthTokenMsg:
    token: str = wire("Token", Primitive("string8"))


@record("mod.apphost.auth_success_msg", registry=_STANDIN)
class AuthSuccessMsg:
    guest_id: Identity | None = wire("GuestID", Ptr("identity"))


@record("mod.apphost.bind_msg", registry=_STANDIN)
class BindMsg:
    # A nonce64, not the string8 that auth_token_msg carries.
    token: Nonce = wire("Token", Primitive("nonce64"))


@record("mod.apphost.attach_query_msg", registry=_STANDIN)
class AttachQueryMsg:
    query_id: Nonce = wire("QueryID", Primitive("nonce64"))


@record("mod.apphost.register_service_msg", registry=_STANDIN)
class RegisterServiceMsg:
    identity: Identity | None = wire("Identity", Ptr("identity"))


@record("mod.apphost.incoming_query_msg", registry=_STANDIN)
class IncomingQueryMsg:
    query_id: Nonce = wire("QueryID", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))


@record("mod.apphost.handle_query_msg", registry=_STANDIN)
class HandleQueryMsg:
    ipc_token: Nonce = wire("IPCToken", Primitive("nonce64"))
    id: Nonce = wire("ID", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))


@record("mod.apphost.reject_incoming_msg", registry=_STANDIN)
class RejectIncomingMsg:
    query_id: Nonce = wire("QueryID", Primitive("nonce64"))
    code: int = wire("Code", Primitive("uint8"))


@record("mod.apphost.register_handler_msg", registry=_STANDIN)
class RegisterHandlerMsg:
    identity: Identity | None = wire("Identity", Ptr("identity"))
    endpoint: str = wire("Endpoint", Primitive("string8"))
    auth_token: Nonce = wire("AuthToken", Primitive("nonce64"))


@record("mod.apphost.ping_msg", registry=_STANDIN)
class PingMsg:
    """No fields. A registered type with no handler: sending it yields protocol_error."""


@record("mod.apphost.error_msg", registry=_STANDIN)
class ErrorMsg:
    # error_msg codes are strings; query_rejected_msg codes are uint8. Two
    # separate namespaces.
    code: str = wire("Code", Primitive("string8"))


@record("mod.apphost.query_rejected_msg", registry=_STANDIN)
class QueryRejectedMsg:
    code: int = wire("Code", Primitive("uint8"))


@record("mod.apphost.query_accepted_msg", registry=_STANDIN)
class QueryAcceptedMsg:
    """No fields."""


@record("mod.apphost.host_info_msg", registry=_STANDIN)
class HostInfoMsg:
    identity: Identity | None = wire("Identity", Ptr("identity"))
    alias: str = wire("Alias", Primitive("string8"))


@record("mod.apphost.route_query_msg", registry=_STANDIN)
class RouteQueryMsg:
    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))
    zone: Zone = wire("Zone", Primitive("zone"), default=Zone.ALL)
    filters: list[str] = wire("Filters", Slice("string8"))


@record("mod.dir.alias_map", registry=_STANDIN)
class AliasMap:
    # The map kind, and the reason dir.alias_map was undecodable before it
    # existed. The field name reaches JSON only: the payload starts straight at
    # the map count.
    aliases: dict[str, Identity | None] = wire("Aliases", Map("string16", "identity"))


# --- stand-in schemas: the corpus's synthetic struct vectors ---------------


@record("struct{A *uint16; B *uint16}", registry=_STANDIN)
class TwoOptionals:
    a: int | None = wire("A", Ptr("uint16"))
    b: int | None = wire("B", Ptr("uint16"))


@record("struct{string}", registry=_STANDIN)
class PlainString:
    # A bare Go string field is string32, never string8 or string16.
    s: str = wire("S", Primitive("string32"))


@record("struct{[]byte}", registry=_STANDIN)
class PlainBytes:
    # A bare Go []byte field is a uint32-counted slice of uint8, never bytes32.
    raw: list[int] = wire("Raw", Slice("uint8"))


@record("struct(demo)", registry=_STANDIN)
class Demo:
    """Every reflection-codec field kind at once."""

    s: str = wire("S", Primitive("string32"))
    raw: list[int] = wire("Raw", Slice("uint8"))
    b16: bytes = wire("B16", Primitive("bytes16"))
    p: str | None = wire("P", Ptr("string8"))
    any: Any = wire("Any", AnySpec())
    m: dict[str, Identity | None] = wire("M", Map("string16", "identity"))
    flag: bool = wire("Flag", Primitive("bool"))


# --- harness registration --------------------------------------------------


def _spec_codec(spec: Spec, **kw: Any) -> Codec:
    """A harness codec over one bare spec, with no enclosing record."""

    def decode(payload: bytes) -> Any:
        reader = ObjectReader(payload, registry=_STANDIN)
        value = read_spec(reader, spec)
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    def encode(value: Any) -> bytes:
        writer = ObjectWriter()
        write_spec(writer, spec, value)
        return writer.getvalue()

    return Codec(decode=decode, encode=encode, **kw)


def _record_codec(cls: type, **kw: Any) -> Codec:
    """A harness codec over a record class."""

    def decode(payload: bytes) -> Any:
        reader = ObjectReader(payload, registry=_STANDIN)
        value = cls.read_payload(reader)  # type: ignore[attr-defined]
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    return Codec(decode=decode, encode=payload_bytes, **kw)


_SPEC_VECTOR_TYPES: dict[str, Spec] = {
    "ptr(uint16)": Ptr("uint16"),
    "slice(uint32)": Slice("uint32"),
    "slice(string8)": Slice("string8"),
    "array(uint16,2)": Array("uint16", 2),
    "map(string16,uint8)": Map("string16", "uint8"),
    "map(uint16,uint8)": Map("uint16", "uint8"),
    # A Go map value of *identity emits its own nil flag and a map value of
    # identity gets the synthesized 0x01. The bytes are identical, and a map
    # value type is a name, so one spec covers both.
    "map(string16,ptr(identity))": Map("string16", "identity"),
    "object": AnySpec(),
}

_RECORD_VECTOR_TYPES: tuple[type, ...] = (
    AuthTokenMsg,
    AuthSuccessMsg,
    BindMsg,
    AttachQueryMsg,
    RegisterServiceMsg,
    IncomingQueryMsg,
    HandleQueryMsg,
    RejectIncomingMsg,
    RegisterHandlerMsg,
    PingMsg,
    ErrorMsg,
    QueryRejectedMsg,
    QueryAcceptedMsg,
    HostInfoMsg,
    RouteQueryMsg,
    AliasMap,
    TwoOptionals,
    PlainString,
    PlainBytes,
    Demo,
    objects.ErrUnexpectedObject,
    objects.Query,
)


def _object_codec(cls: type, **kw: Any) -> Codec:
    """A harness codec over an object with a hand-written payload codec."""

    def decode(payload: bytes) -> Any:
        reader = ObjectReader(payload, registry=_STANDIN)
        value = cls.read_payload(reader)  # type: ignore[attr-defined]
        if not reader.at_end:
            raise AssertionError(f"{reader.remaining} trailing bytes left in payload")
        return value

    return Codec(decode=decode, encode=payload_bytes, **kw)


def _four_forms(cls: type) -> Codec:
    """An object that carries all four of its own encodings."""
    return _object_codec(
        cls,
        to_json=lambda v: v.json(),
        from_json=cls.from_json,  # type: ignore[attr-defined]
        to_text=lambda v: v.text(),
        from_text=cls.parse,  # type: ignore[attr-defined]
    )


def _register_step2_codecs() -> None:
    for astral_type, spec in _SPEC_VECTOR_TYPES.items():
        register_codec(astral_type, _spec_codec(spec))
    for cls in _RECORD_VECTOR_TYPES:
        register_codec(cls.ASTRAL_TYPE, _record_codec(cls))  # type: ignore[attr-defined]

    # object.py's objects carry their own JSON and text forms, as the value
    # types do. Every scalar and every composite waits for the JSON and text
    # codecs.
    register_codec("", _four_forms(objects.Blob))
    register_codec("ack", _four_forms(objects.Ack))
    register_codec("eos", _four_forms(objects.EOS))
    register_codec("nil", _four_forms(objects.Nil))
    register_codec("error_message", _four_forms(objects.ErrorMessage))
    register_codec("object_type", _object_codec(P.ObjectType))
    register_codec("stamp", _object_codec(P.Stamp))
    register_codec("bundle", _object_codec(objects.Bundle))


class _Framing:
    """The framing provider: the three type-tag placements of design 2.8."""

    canonical = staticmethod(codec.canonical)
    channel_frame = staticmethod(codec.channel_frame)
    polymorphic_field = staticmethod(codec.polymorphic_field)


# --- negative vectors ------------------------------------------------------


@register_negative("neg.canonical.bad_stamp")
def _neg_bad_stamp(case: unittest.TestCase, vector: Vector) -> None:
    """A canonical form whose leading four bytes are not the stamp."""
    with case.assertRaises(ParseError):
        codec.Canonical.read(Reader(vector.payload))
    with case.assertRaises(ParseError):
        P.Stamp.read_payload(Reader(b"\x41\x44\x43\x31"))
    case.assertEqual(codec.Canonical.read(Reader(codec.canonical("uint32", b"\x00" * 4))), "uint32")


@register_negative("neg.interface.empty_type")
def _neg_empty_type(case: unittest.TestCase, vector: Vector) -> None:
    """All three type encoders reject an empty type, and so does an Any field."""
    for encoder in (codec.Short, codec.Canonical):
        with case.assertRaises(SchemaError):
            encoder.write(Writer(), "")
    with case.assertRaises(SchemaError):
        codec.Indexed(["uint8"]).write(Writer(), "")
    with case.assertRaises(SchemaError):
        write_spec(Writer(), AnySpec(), objects.Blob(b"hello"))
    with case.assertRaises(SchemaError):
        codec.encode(objects.Blob(b"hello"))
    # The untyped-blob path bypasses the encoder entirely.
    case.assertEqual(codec.channel_frame("", b"hello"), bytes.fromhex("000000000568656c6c6f"))


@register_negative("neg.map.platform_width_key")
def _neg_map_key(case: unittest.TestCase, vector: Vector) -> None:
    """Map key types are a closed set, and a key value must match the width."""
    for bad in ("uint", "int", "int64", "string8", "identity", ""):
        with case.assertRaises(SchemaError):
            Map(bad, "uint8")
    with case.assertRaises(SchemaError):
        write_spec(Writer(), Map("string16", "uint8"), {7: 1})
    with case.assertRaises(SchemaError):
        write_spec(Writer(), Map("uint16", "uint8"), {"7": 1})
    case.assertEqual(MAP_KEY_TYPES, {"string16", "uint8", "uint16", "uint32", "uint64"})


@register_negative("neg.container_presence.0x00")
def _neg_container_presence(case: unittest.TestCase, vector: Vector) -> None:
    """The corpus records astral-go's rejection; the design accepts 0x00 as absent.

    This test is expected to fail, and the failure is the record of the
    divergence. `PresenceTests.test_a_zero_byte_in_a_value_slot_reads_as_absent`
    states what the SDK does instead.
    """
    with case.assertRaises(WireError):
        read_spec(Reader(vector.payload), Slice("uint32"))


# --- the section 7.1 must-pass table --------------------------------------


class MustPassTests(unittest.TestCase):
    """The cases of design 7.1 that the corpus does not carry as vectors."""

    maxDiff = None

    def _spec_hex(self, spec: Spec, value: Any) -> str:
        writer = ObjectWriter()
        write_spec(writer, spec, value)
        return writer.getvalue().hex()

    def test_heterogeneous_slice_of_objects(self) -> None:
        self.assertEqual(
            self._spec_hex(Slice(), [P.Uint32(1), P.String8("hi")]),
            "00000002" "0675696e743332" "00000001" "07737472696e6738" "026869",
        )

    def test_heterogeneous_map_of_objects(self) -> None:
        self.assertEqual(
            self._spec_hex(Map("string16"), {"k": P.Uint32(7)}),
            "00000001" "00016b" "0675696e743332" "00000007",
        )

    def test_homogeneous_map_of_uint32(self) -> None:
        self.assertEqual(
            self._spec_hex(Map("string16", "uint32"), {"a": 42, "bb": 99}),
            "00000002" "000161" "01" "0000002a" "00026262" "01" "00000063",
        )

    def test_nil_identity_and_anyone_are_different_bytes(self) -> None:
        self.assertEqual(self._spec_hex(Ptr("identity"), None), "00")
        self.assertEqual(self._spec_hex(Ptr("identity"), Identity.ANYONE), "01" + "00" * 33)

    def test_an_alias_value_is_the_underlying_bytes_under_a_new_name(self) -> None:
        mode = alias("t.zz.mode", "uint8", registry=_STANDIN)
        self.assertEqual(payload_bytes(mode(7)).hex(), "07")
        self.assertEqual(mode.ASTRAL_TYPE, "t.zz.mode")
        self.assertEqual(mode.UNDERLYING, "uint8")
        self.assertEqual(_STANDIN.new("t.zz.mode"), mode(0))
        self.assertEqual(mode.read_payload(Reader(b"\x07")), mode(7))
        # The alias name reaches a polymorphic slot but never the payload.
        self.assertEqual(self._spec_hex(AnySpec(), mode(7)), "09742e7a7a2e6d6f646507")

    def test_host_info_msg_channel_frame(self) -> None:
        payload = payload_bytes(HostInfoMsg(identity=NODE, alias="furry-bolt"))
        self.assertEqual(
            codec.channel_frame(HostInfoMsg.ASTRAL_TYPE, payload).hex(),
            "196d6f642e617070686f73742e686f73745f696e666f5f6d73670000002d01"
            + NODE.hex()
            + "0a66757272792d626f6c74",
        )

    def test_alias_map_payload(self) -> None:
        self.assertEqual(
            payload_bytes(AliasMap(aliases={"furry-bolt": NODE})).hex(),
            "00000001000a66757272792d626f6c7401" + NODE.hex(),
        )

    def test_canonical_form_of_uint32_42(self) -> None:
        self.assertEqual(
            codec.canonical_bytes(P.Uint32(42)).hex(), "414443300675696e7433320000002a"
        )
        self.assertEqual(codec.canonical("uint32", b"\x00\x00\x00\x2a").hex(), "414443300675696e7433320000002a")

    def test_the_four_framings_place_the_tag_differently(self) -> None:
        payload = b"\x02hi"
        self.assertEqual(codec.polymorphic_field("string8", payload).hex(), "07737472696e6738026869")
        self.assertEqual(
            codec.channel_frame("string8", payload).hex(), "07737472696e673800000003026869"
        )
        self.assertEqual(
            codec.bundle_element("string8", payload).hex(), "0000000b07737472696e6738026869"
        )
        self.assertEqual(
            codec.canonical("string8", payload).hex(), "4144433007737472696e6738026869"
        )

    def test_empty_containers_encode_as_a_zero_count(self) -> None:
        self.assertEqual(self._spec_hex(Slice("uint32"), []), "00000000")
        self.assertEqual(self._spec_hex(Map("string16", "uint8"), {}), "00000000")
        self.assertEqual(self._spec_hex(Slice("uint32"), None), "00000000")
        self.assertEqual(read_spec(Reader(bytes(4)), Slice("uint32")), [])
        self.assertEqual(read_spec(Reader(bytes(4)), Map("string16", "uint8")), {})

    def test_arrays_carry_no_count(self) -> None:
        self.assertEqual(self._spec_hex(Array("uint16", 2), [1, 2]), "010001010002")
        self.assertEqual(read_spec(Reader(bytes.fromhex("010001010002")), Array("uint16", 2)), [1, 2])


# --- presence, containers, maps -------------------------------------------


class PresenceTests(unittest.TestCase):
    """The presence byte is a container property, decided by the spec."""

    def test_needs_presence_is_the_whole_rule(self) -> None:
        for spec in (Primitive("uint8"), Ref("uint8"), Slice(), Array("uint8", 1), Map("uint8")):
            self.assertTrue(needs_presence(spec), spec)
        self.assertFalse(needs_presence(Ptr("uint8")))
        self.assertFalse(needs_presence(AnySpec()))

    def test_a_named_element_type_gets_the_synthesized_byte(self) -> None:
        writer = Writer()
        write_spec(writer, Slice("string8"), ["a", "bc"])
        self.assertEqual(writer.getvalue().hex(), "0000000201016101026263")

    def test_a_heterogeneous_element_carries_a_tag_instead(self) -> None:
        writer = Writer()
        write_spec(writer, Slice(), [P.Uint8(7)])
        self.assertEqual(writer.getvalue().hex(), "000000010575696e743807")

    def test_a_map_key_never_carries_a_presence_byte(self) -> None:
        writer = Writer()
        write_spec(writer, Map("string16", "uint8"), {"hi": 1, "ab": 2})
        self.assertEqual(writer.getvalue().hex(), "00000002000261620102000268690101")

    def test_a_zero_byte_in_a_value_slot_reads_as_absent(self) -> None:
        # astral-go's reflection codec rejects this; its blueprint-built
        # containers emit it for a nil *T element, so a strict reader
        # desynchronises against a blueprint peer.
        self.assertEqual(read_spec(Reader(bytes.fromhex("0000000100")), Slice("uint32")), [None])
        self.assertEqual(
            read_spec(Reader(bytes.fromhex("00000001000161" "00")), Map("string16", "uint8")),
            {"a": None},
        )

    def test_a_presence_byte_above_one_is_rejected(self) -> None:
        for payload in ("0000000102", "0000000102000000ff"):
            with self.subTest(payload), self.assertRaises(InvalidFlag):
                read_spec(Reader(bytes.fromhex(payload)), Slice("uint32"))
        with self.assertRaises(InvalidFlag):
            read_spec(Reader(b"\x02\x00\x2a"), Ptr("uint16"))

    def test_an_element_that_decoded_as_absent_re_encodes_to_the_same_byte(self) -> None:
        # `0x00` is what astral-go's blueprint-built containers write for a nil
        # `*T` element -- resolveElemType hands the container a pointer
        # prototype -- so a decode this codec accepts has to re-encode to the
        # bytes it came from.
        for spec, payload in (
            (Slice("uint16"), "0000000201000100"),
            (Map("string16", "uint16"), "0000000100016b00"),
            (Array("uint8", 2), "0000"),
        ):
            with self.subTest(spec=spec):
                value = read_spec(ObjectReader(bytes.fromhex(payload)), spec)
                writer = ObjectWriter()
                write_spec(writer, spec, value)
                self.assertEqual(writer.getvalue().hex(), payload)
        self.assertEqual(
            read_spec(ObjectReader(bytes.fromhex("0000000201000100")), Slice("uint16")),
            [1, None],
        )

    def test_a_bare_slot_still_has_no_absent_form(self) -> None:
        # Only a container element carries the synthesized byte that can say
        # "absent". A `Primitive` or a `Ref` has nowhere to put it.
        with self.assertRaises(SchemaError):
            write_spec(Writer(), Primitive("uint32"), None)
        with self.assertRaises(SchemaError):
            write_spec(Writer(), Ref("uint32"), None)

    def test_an_absent_pointer_consumes_one_byte_and_nothing_else(self) -> None:
        reader = Reader(b"\x00tail")
        self.assertIsNone(read_spec(reader, Ptr("identity")))
        self.assertEqual(reader.rest(), b"tail")


class MapTests(unittest.TestCase):
    """The sort is part of the wire format, not a nicety."""

    def test_entries_sort_by_encoded_key_bytes(self) -> None:
        first = Writer()
        write_spec(first, Map("string16", "uint8"), {"hi": 1, "ab": 2})
        second = Writer()
        write_spec(second, Map("string16", "uint8"), {"ab": 2, "hi": 1})
        self.assertEqual(first.getvalue(), second.getvalue())

    def test_string_keys_sort_by_length_prefix_first(self) -> None:
        writer = Writer()
        write_spec(writer, Map("string16", "uint8"), {"zz": 1, "a": 2})
        # 0001 "a" precedes 0002 "zz": the length prefix leads.
        self.assertEqual(writer.getvalue().hex(), "00000002000161010200027a7a0101")

    def test_integer_keys_ascend_by_encoded_bytes(self) -> None:
        writer = Writer()
        write_spec(writer, Map("uint16", "uint8"), {7: 0x0B, 256: 0x0C, 1: 0x0A})
        self.assertEqual(writer.getvalue().hex(), "000000030001010a0007010b0100010c")

    def test_insertion_order_never_reaches_the_wire(self) -> None:
        rnd = random.Random(1)
        entries = [(f"k{i:02d}", i) for i in range(24)]
        expected: bytes | None = None
        for _ in range(8):
            rnd.shuffle(entries)
            writer = Writer()
            write_spec(writer, Map("string16", "uint8"), dict(entries))
            got = writer.getvalue()
            # Each value follows its own key, so identical bytes across eight
            # shuffles can only come from sorting the pairs.
            if expected is None:
                expected = got
                self.assertEqual(got[:4].hex(), "00000018")
                self.assertEqual(got[4:10].hex(), "00036b3030" + "01")
            self.assertEqual(got, expected)

    def test_a_key_width_is_range_checked(self) -> None:
        with self.assertRaises(WireError):
            write_spec(Writer(), Map("uint8", "uint8"), {256: 1})

    def test_a_bool_is_not_an_integer_key(self) -> None:
        with self.assertRaises(SchemaError):
            write_spec(Writer(), Map("uint8", "uint8"), {True: 1})

    def test_a_zero_count_decodes_to_an_empty_map(self) -> None:
        self.assertEqual(read_spec(Reader(bytes(4)), Map("string16", "identity")), {})


class ContainerTests(unittest.TestCase):
    def test_an_array_must_match_its_declared_length(self) -> None:
        with self.assertRaises(ValueTooLarge):
            write_spec(Writer(), Array("uint16", 2), [1])
        with self.assertRaises(ValueTooLarge):
            write_spec(Writer(), Array("uint16", 2), [1, 2, 3])

    def test_a_truncated_container_aborts_rather_than_allocating(self) -> None:
        # A hostile count costs bytes, not gigabytes: every element consumes at
        # least its presence byte, so the read aborts inside the frame.
        with self.assertRaises(WireError):
            read_spec(Reader(bytes.fromhex("ffffffff") + b"\x01\x00"), Slice("uint16"))

    def test_a_slice_of_zero_payload_objects_still_costs_a_byte_each(self) -> None:
        self.assertEqual(
            read_spec(Reader(bytes.fromhex("00000003") + b"\x01\x01\x01"), Slice("ack")),
            [objects.Ack()] * 3,
        )
        with self.assertRaises(WireError):
            read_spec(Reader(bytes.fromhex("00ffffff") + b"\x01"), Slice("ack"))


class PolymorphicTests(unittest.TestCase):
    def test_an_empty_tag_is_nil(self) -> None:
        self.assertIsNone(read_spec(Reader(b"\x00"), AnySpec()))
        writer = Writer()
        write_spec(writer, AnySpec(), None)
        self.assertEqual(writer.getvalue(), b"\x00")

    def test_the_runtime_nil_tag_is_accepted_on_read(self) -> None:
        # astral-go's runtime-blueprint codec writes string8("nil") and cannot
        # read its own output. The SDK writes 0x00 and accepts both.
        self.assertIsNone(read_spec(Reader(b"\x03nil"), AnySpec()))

    def test_the_runtime_nil_tag_does_not_survive_a_round_trip(self) -> None:
        """Design 2.9 collapses `string8("nil")` to absence, and that loses bytes.

        `nil` is a registered object type, not a private marker: astral-go's
        reflection codec reads `036e696c` into `&Nil{}` and writes `036e696c`
        back, while `00` is a Go nil and stays `00`. Mapping both to `None` makes
        the two indistinguishable, so this re-encode is not byte-exact. The
        design decides it; the test pins it so the cost stays visible and any
        change to it is deliberate.
        """
        writer = Writer()
        write_spec(writer, AnySpec(), read_spec(Reader(b"\x03nil"), AnySpec()))
        self.assertEqual(writer.getvalue(), b"\x00")
        # The registered object is still reachable, and still round trips when a
        # caller names it rather than letting the decoder collapse it.
        explicit = Writer()
        write_spec(explicit, AnySpec(), objects.Nil())
        self.assertEqual(explicit.getvalue(), b"\x03nil")

    def test_an_unknown_type_corrupts_the_stream(self) -> None:
        with self.assertRaises(StreamCorrupted) as caught:
            read_spec(ObjectReader(b"\x04t.no"), AnySpec())
        self.assertIn("t.no", str(caught.exception))

    def test_a_polymorphic_slot_yields_the_registered_object(self) -> None:
        value = read_spec(ObjectReader(bytes.fromhex("0575696e743807")), AnySpec())
        self.assertEqual(value, P.Uint8(7))
        self.assertIsInstance(value, P.Uint8)

    def test_a_value_type_decodes_to_itself_in_a_polymorphic_slot(self) -> None:
        payload = codec.polymorphic_field("identity", NODE.key)
        self.assertEqual(read_spec(ObjectReader(payload), AnySpec()), NODE)


# --- schema and registry ---------------------------------------------------


class SpecTests(unittest.TestCase):
    def test_the_primitive_allowlist_is_nineteen_names(self) -> None:
        self.assertEqual(len(PRIMITIVE_TYPES), 19)
        for name in ("int8", "int64", "float32", "float64", "size", "object_type", "stamp"):
            self.assertNotIn(name, PRIMITIVE_TYPES)

    def test_a_non_allowlisted_primitive_is_rejected_at_declaration(self) -> None:
        for name in ("int64", "float32", "size", "error_message", "object_type", "nope"):
            with self.subTest(name), self.assertRaises(SchemaError):
                Primitive(name)

    def test_the_scalar_table_is_wider_than_the_allowlist(self) -> None:
        # Ref reaches every encodable scalar; Primitive reaches the allowlist.
        for name in ("int8", "int16", "int32", "int64", "float32", "float64", "size"):
            with self.subTest(name):
                self.assertIn(name, P.SCALARS)
                self.assertEqual(spec_zero(Ref(name)), 0 if name.startswith("int") else 0.0)
        self.assertEqual(
            read_spec(Reader(b"\xff\xff\xff\xff\xff\xff\xff\xff"), Ref("int64")), -1
        )

    def test_an_array_length_is_capped_at_registration(self) -> None:
        Array("uint8", MAX_ARRAY_LENGTH)
        with self.assertRaises(SchemaError):
            Array("uint8", MAX_ARRAY_LENGTH + 1)
        with self.assertRaises(SchemaError):
            Array("uint8", -1)

    def test_a_name_is_printable_ascii_and_at_most_255_bytes(self) -> None:
        Ref("a" * 255)
        for bad in ("", "a" * 256, "a\nb", "\x7f", "café"):
            with self.subTest(bad), self.assertRaises(SchemaError):
                Ref(bad)

    def test_spec_zero_per_kind(self) -> None:
        self.assertEqual(spec_zero(Primitive("string16")), "")
        self.assertEqual(spec_zero(Primitive("uint8")), 0)
        self.assertEqual(spec_zero(Primitive("identity")), Identity.ANYONE)
        self.assertEqual(spec_zero(Primitive("zone")), Zone(0))
        self.assertEqual(spec_zero(Slice("uint8")), [])
        self.assertEqual(spec_zero(Map("string16", "uint8")), {})
        self.assertEqual(spec_zero(Array("uint16", 3)), [0, 0, 0])
        self.assertIsNone(spec_zero(Ptr("identity")))
        self.assertIsNone(spec_zero(AnySpec()))
        self.assertIsNone(spec_zero(Ref("t.not.registered")))


class RecordTests(unittest.TestCase):
    def test_fields_carry_attribute_wire_name_and_spec(self) -> None:
        self.assertEqual(
            HostInfoMsg.FIELDS,
            (F("identity", "Identity", Ptr("identity")), F("alias", "Alias", Primitive("string8"))),
        )

    def test_construction_is_keyword_only_and_defaults_to_the_spec_zero(self) -> None:
        with self.assertRaises(TypeError):
            HostInfoMsg(NODE, "furry-bolt")  # type: ignore[misc]
        self.assertEqual(HostInfoMsg(), HostInfoMsg(identity=None, alias=""))
        self.assertEqual(RouteQueryMsg().zone, Zone.ALL)
        self.assertEqual(RouteQueryMsg().filters, [])
        self.assertIsNot(RouteQueryMsg().filters, RouteQueryMsg().filters)

    def test_a_record_is_registered_and_constructible_by_name(self) -> None:
        self.assertTrue(_STANDIN.has("mod.apphost.host_info_msg"))
        self.assertEqual(_STANDIN.new("mod.apphost.host_info_msg"), HostInfoMsg())
        self.assertIsNone(_STANDIN.new(""))
        self.assertIsNone(_STANDIN.new("mod.nope"))

    def test_field_names_differing_only_in_case_are_rejected(self) -> None:
        with self.assertRaises(SchemaError):

            @record("t.dup.case", registry=_STANDIN)
            class Dup:
                a: int = wire("Code", Primitive("uint8"))
                b: int = wire("code", Primitive("uint8"))

    def test_a_self_reference_is_rejected(self) -> None:
        for spec in (Ref("t.self"), Ptr("t.self")):
            with self.subTest(spec), self.assertRaises(CycleDetected):

                @record("t.self", registry=Blueprints(default_blueprints()))
                class SelfRef:
                    inner: Any = wire("Inner", spec)

    def test_a_two_step_cycle_is_rejected_at_registration(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.a", registry=scope)
        class A:
            b: Any = wire("B", Ref("t.b"))

        with self.assertRaises(CycleDetected):

            @record("t.b", registry=scope)
            class B:
                a: Any = wire("A", Ref("t.a"))

    def test_a_container_cycle_is_legal(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.node", registry=scope)
        class Node:
            children: list[Any] = wire("Children", Slice("t.node"))

        self.assertEqual(payload_bytes(Node()).hex(), "00000000")
        nested = Node(children=[Node(children=[Node()])])
        self.assertEqual(payload_bytes(nested).hex(), "0000000101000000010100000000")
        reader = ObjectReader(payload_bytes(nested), registry=scope)
        self.assertEqual(Node.read_payload(reader), nested)

    def test_the_depth_guard_bounds_nesting_on_encode_and_decode(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.deep", registry=scope)
        class Deep:
            children: list[Any] = wire("Children", Slice("t.deep"))

        chain = Deep()
        for _ in range(MAX_DEPTH):
            chain = Deep(children=[chain])
        with self.assertRaises(DepthExceeded):
            payload_bytes(chain)
        frame = b"\x00\x00\x00\x01\x01" * (MAX_DEPTH + 1) + bytes(4)
        with self.assertRaises(DepthExceeded):
            Deep.read_payload(ObjectReader(frame, registry=scope))

    def test_an_alias_underlying_must_be_a_primitive(self) -> None:
        with self.assertRaises(SchemaError):
            alias("t.bad.alias", "int64", registry=Blueprints(default_blueprints()))

    def test_a_custom_codec_marks_the_blueprint_non_derivable(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.custom", registry=scope)
        class Custom:
            digest: bytes = wire("Digest", Primitive("bytes8"))

            def write_payload(self, w: Writer) -> None:
                w.raw(self.digest)

            @classmethod
            def read_payload(cls, r: Reader) -> "Custom":
                return cls(digest=r.raw(3))

        self.assertFalse(Custom.DERIVABLE)
        self.assertTrue(HostInfoMsg.DERIVABLE)
        self.assertEqual(payload_bytes(Custom(digest=b"abc")), b"abc")
        self.assertEqual(Custom.read_payload(Reader(b"abc")).digest, b"abc")

    def test_half_a_custom_codec_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):

            @record("t.half", registry=Blueprints(default_blueprints()))
            class Half:
                digest: bytes = wire("Digest", Primitive("bytes8"))

                def write_payload(self, w: Writer) -> None:
                    w.raw(self.digest)

    def test_an_embedded_value_struct_flattens_and_forwards(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.inner", registry=scope)
        class Inner:
            issuer: Identity | None = wire("Issuer", Ptr("identity"))

        @record("t.outer", registry=scope)
        class Outer:
            inner: Any = embed("Inner", "t.inner")
            sig: bytes = wire("Sig", Primitive("bytes8"))

        outer = Outer(inner=Inner(issuer=NODE), sig=b"\x01")
        self.assertEqual(payload_bytes(outer).hex(), "01" + NODE.hex() + "0101")
        self.assertEqual(outer.issuer, NODE)
        self.assertEqual(Outer.FIELDS[0].wire_name, "Inner")
        with self.assertRaises(AttributeError):
            outer.nope

    def test_an_embedded_pointer_struct_carries_a_nil_flag(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.pinner", registry=scope)
        class Inner:
            issuer: Identity | None = wire("Issuer", Ptr("identity"))

        @record("t.pouter", registry=scope)
        class Outer:
            inner: Any = embed("Inner", "t.pinner", optional=True)

        self.assertEqual(payload_bytes(Outer()).hex(), "00")
        self.assertEqual(payload_bytes(Outer(inner=Inner())).hex(), "0100")
        reader = ObjectReader(bytes.fromhex("0100"), registry=scope)
        self.assertEqual(Outer.read_payload(reader), Outer(inner=Inner()))


class _FakeBlueprint:
    """The `RuntimeBlueprint` contract, standing in for `astral.blueprint`.

    The blueprint record itself lands with the self-hosting step; the
    registration policy it drives lives in the registry and is testable now.
    """

    def __init__(self, name: str, specs: tuple[Spec, ...] = (), underlying: str = "") -> None:
        self._name = name
        self._specs = specs
        self._underlying = underlying

    def blueprint_name(self) -> str:
        return self._name

    def blueprint_specs(self) -> tuple[Spec, ...]:
        return self._specs

    def blueprint_underlying(self) -> str:
        return self._underlying

    def validate(self) -> None:
        return None

    def clone(self) -> "_FakeBlueprint":
        return _FakeBlueprint(self._name, self._specs, self._underlying)

    def new(self) -> Any:
        return {"blueprint": self._name}


class RegistryTests(unittest.TestCase):
    def test_a_child_cannot_shadow_a_parent(self) -> None:
        parent = Blueprints()
        child = Blueprints(parent)

        @record("t.shadow", registry=parent)
        class Parent:
            a: int = wire("A", Primitive("uint8"))

        self.assertTrue(child.has("t.shadow"))
        with self.assertRaises(SchemaError):

            @record("t.shadow", registry=child)
            class Child:
                a: int = wire("A", Primitive("uint8"))

    def test_an_empty_type_name_is_rejected(self) -> None:
        scope = Blueprints()
        with self.assertRaises(SchemaError):
            scope.add(objects.Blob)
        self.assertFalse(default_blueprints().has(""))
        self.assertIsNone(default_blueprints().new(""))

    def test_a_duplicate_in_one_add_is_rejected(self) -> None:
        scope = Blueprints()
        with self.assertRaises(SchemaError):
            scope.add(P.Uint8, P.Uint8)
        self.assertFalse(scope.has("uint8"))

    def test_ordering_is_prototypes_then_aliases_then_runtime(self) -> None:
        scope = Blueprints()

        @record("t.order.b", registry=scope)
        class B:
            a: int = wire("A", Primitive("uint8"))

        @record("t.order.a", registry=scope)
        class A:
            a: int = wire("A", Primitive("uint8"))

        scope.add(P.Uint8)
        alias("t.order.mode", "uint8", registry=scope)
        self.assertEqual(scope.ordered(), ["t.order.a", "t.order.b", "uint8", "t.order.mode"])

    def test_ordering_puts_parent_levels_first(self) -> None:
        parent = Blueprints()
        child = Blueprints(parent)
        parent.add(P.Uint8)

        @record("t.child", registry=child)
        class Child:
            a: int = wire("A", Primitive("uint8"))

        self.assertEqual(child.ordered(), ["uint8", "t.child"])

    def test_the_default_registry_holds_the_wire_core(self) -> None:
        registry = default_blueprints()
        for name in ("uint8", "identity", "zone", "ack", "eos", "nil", "query", "bundle"):
            with self.subTest(name):
                self.assertTrue(registry.has(name))
        # blob is not registered: astral-go's Add rejects an empty type and
        # discards the error, so blob is absent there too.
        self.assertFalse(registry.has("blob"))
        self.assertEqual(objects.Blob.ASTRAL_TYPE, "")

    def test_a_bounded_window_keeps_the_registry(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.windowed", registry=scope)
        class Windowed:
            a: int = wire("A", Primitive("uint8"))

        frame = codec.channel_frame("t.windowed", b"\x07")
        reader = ObjectReader(frame, registry=scope)
        type_name = reader.string8()
        window = reader.bounded(reader.uint32())
        self.assertIs(window.registry, scope)
        self.assertEqual(codec.read_object(window, type_name), Windowed(a=7))
        self.assertTrue(reader.at_end)

    def test_the_registry_travels_on_the_reader(self) -> None:
        scope = Blueprints(default_blueprints())

        @record("t.scoped", registry=scope)
        class Scoped:
            a: int = wire("A", Primitive("uint8"))

        payload = codec.polymorphic_field("t.scoped", b"\x07")
        self.assertEqual(read_spec(ObjectReader(payload, registry=scope), AnySpec()), Scoped(a=7))
        with self.assertRaises(StreamCorrupted):
            read_spec(ObjectReader(payload), AnySpec())
        self.assertEqual(codec.decode(payload, registry=scope), Scoped(a=7))

    def test_registering_a_blueprint_validates_closure_and_collision(self) -> None:
        scope = Blueprints(default_blueprints())
        with self.assertRaises(SchemaError):
            scope.register_blueprint(_FakeBlueprint("t.bp", specs=(Ref("t.missing"),)))
        self.assertFalse(scope.has("t.bp"))
        with self.assertRaises(SchemaError):
            scope.register_blueprint(_FakeBlueprint("uint8", specs=()))
        with self.assertRaises(SchemaError):
            scope.register_blueprint(_FakeBlueprint("t.alias", underlying="t.nope"))
        with self.assertRaises(SchemaError):
            scope.register_blueprint(
                _FakeBlueprint("t.both", specs=(Primitive("uint8"),), underlying="uint8")
            )
        with self.assertRaises(SchemaError):
            scope.register_blueprint(_FakeBlueprint("", specs=()))

    def test_a_runtime_blueprint_entry_is_classified_as_runtime(self) -> None:
        scope = Blueprints(default_blueprints())
        scope._entries["t.runtime"] = _FakeBlueprint("t.runtime", specs=(Primitive("uint8"),))
        scope._entries["t.runtime.alias"] = _FakeBlueprint("t.runtime.alias", underlying="uint8")
        self.assertEqual(scope.ordered(), default_blueprints().ordered() + [
            "t.runtime.alias",
            "t.runtime",
        ])
        self.assertEqual(scope.new("t.runtime"), {"blueprint": "t.runtime"})
        self.assertIsNotNone(scope.blueprint("t.runtime"))
        self.assertIsNone(scope.blueprint("uint8"))

    def test_construction_depth_is_bounded(self) -> None:
        # A registry whose entries reference one another can only be built by
        # bypassing add(); the guard makes the construction terminate anyway.
        # astral-go stack-overflows on exactly this input (bug G-22).
        scope = Blueprints()

        @record("t.cx", registry=scope)
        class X:
            inner: Any = wire("Inner", Ref("t.cx.again"))

        scope.find("t.cx")
        scope._entries["t.cx.again"] = X
        with self.assertRaises(DepthExceeded):
            scope.new("t.cx")


class TypeEncoderTests(unittest.TestCase):
    def test_short_is_a_string8(self) -> None:
        writer = Writer()
        codec.Short.write(writer, "uint8")
        self.assertEqual(writer.getvalue(), b"\x05uint8")
        self.assertEqual(codec.Short.read(Reader(b"\x05uint8")), "uint8")

    def test_canonical_prefixes_the_stamp(self) -> None:
        writer = Writer()
        codec.Canonical.write(writer, "uint8")
        self.assertEqual(writer.getvalue(), b"ADC0\x05uint8")
        self.assertEqual(codec.STAMP, b"\x41\x44\x43\x30")

    def test_indexed_is_a_uint8_into_a_closed_table(self) -> None:
        table = codec.Indexed(["uint8", "string8"])
        writer = Writer()
        table.write(writer, "string8")
        self.assertEqual(writer.getvalue(), b"\x01")
        self.assertEqual(table.read(Reader(b"\x00")), "uint8")
        with self.assertRaises(ParseError):
            table.read(Reader(b"\x02"))
        with self.assertRaises(SchemaError):
            table.write(Writer(), "uint16")

    def test_decode_rejects_an_empty_tag(self) -> None:
        with self.assertRaises(StreamCorrupted):
            codec.decode(b"\x00")

    def test_encode_and_decode_round_trip_through_every_encoder(self) -> None:
        for encoder in (codec.Short, codec.Canonical, codec.Indexed(["uint32"])):
            with self.subTest(type(encoder).__name__):
                data = codec.encode(P.Uint32(42), types=encoder)
                self.assertEqual(codec.decode(data, types=encoder), P.Uint32(42))


class ObjectTests(unittest.TestCase):
    def test_a_blob_reads_to_the_end_of_its_reader(self) -> None:
        reader = Reader(b"\x02hi" + b"payload")
        window = reader.bounded(3)
        self.assertEqual(objects.Blob.read_payload(window), b"\x02hi")
        self.assertEqual(objects.Blob.read_payload(reader), b"payload")

    def test_an_unparsed_object_cannot_be_marshalled(self) -> None:
        unparsed = objects.UnparsedObject("mod.nope", b"\x01")
        self.assertEqual(unparsed.ASTRAL_TYPE, "mod.nope")
        self.assertEqual(payload_bytes(unparsed), b"\x01")
        with self.assertRaises(ParseError):
            unparsed.json()
        with self.assertRaises(ParseError):
            unparsed.text()

    def test_the_empty_objects_have_no_payload(self) -> None:
        for cls, name in ((objects.Ack, "ack"), (objects.EOS, "eos"), (objects.Nil, "nil")):
            with self.subTest(name):
                self.assertEqual(cls.ASTRAL_TYPE, name)
                self.assertEqual(payload_bytes(cls()), b"")
                reader = Reader(b"tail")
                self.assertEqual(cls.read_payload(reader), cls())
                self.assertEqual(reader.rest(), b"tail")
        self.assertNotEqual(objects.Ack(), objects.EOS())

    def test_a_bundle_decodes_its_elements_through_the_registry(self) -> None:
        bundle = objects.Bundle([P.Uint8(7), P.String8("hi")])
        payload = payload_bytes(bundle)
        self.assertEqual(
            payload.hex(), "00000002000000070575696e7438070000000b07737472696e6738026869"
        )
        decoded = objects.Bundle.read_payload(object_reader(payload))
        self.assertEqual(decoded, bundle)
        self.assertEqual(list(decoded), [P.Uint8(7), P.String8("hi")])

    def test_a_bundle_refuses_a_duplicate_object(self) -> None:
        # astral-go funnels every decoded element through `append`, which refuses
        # a repeat, so a bundle carrying one object twice encodes to bytes the
        # reference decoder rejects mid-frame.
        bundle = objects.Bundle([P.Uint8(7)])
        with self.assertRaises(SchemaError):
            bundle.append(P.Uint8(7))
        with self.assertRaises(SchemaError):
            objects.Bundle([P.Uint8(7), P.Uint8(7)])
        # Same payload under a different type is a different object.
        bundle.append(P.Int8(7))
        self.assertEqual(len(bundle), 2)
        repeated = bytes.fromhex(
            "00000002" "00000007" "0575696e743807" "00000007" "0575696e743807"
        )
        with self.assertRaises(SchemaError):
            objects.Bundle.read_payload(object_reader(repeated))

    def test_nested_bundles_are_bounded_by_the_depth_guard(self) -> None:
        # A bundle element is a nested frame and may be another bundle. Each
        # level costs 15 bytes, so an unguarded decoder exhausts the interpreter
        # stack on a payload of a few kilobytes.
        def nest(depth: int) -> bytes:
            payload = bytes(4)
            for _ in range(depth):
                inner = b"\x06bundle" + payload
                payload = (1).to_bytes(4, "big") + len(inner).to_bytes(4, "big") + inner
            return payload

        self.assertEqual(len(objects.Bundle.read_payload(object_reader(nest(3)))), 1)
        for depth in (MAX_DEPTH + 1, 400):
            with self.subTest(depth=depth), self.assertRaises(DepthExceeded):
                objects.Bundle.read_payload(object_reader(nest(depth)))
        # The chain is assembled by direct mutation: `append` resolves each
        # element's ObjectID, which encodes it, so the guard would fire during
        # construction and never reach the payload walk under test.
        chain = objects.Bundle()
        for _ in range(MAX_DEPTH + 1):
            deeper = objects.Bundle()
            deeper.objects.append(chain)
            chain = deeper
        with self.assertRaises(DepthExceeded):
            payload_bytes(chain)
        with self.assertRaises(DepthExceeded):
            objects.Bundle([chain])

    def test_a_bundle_element_inverts_the_channel_frame(self) -> None:
        # The bundle element holds the type inside its length; the channel frame
        # holds it outside.
        self.assertEqual(codec.bundle_element("uint8", b"\x07").hex(), "000000070575696e743807")
        self.assertEqual(codec.channel_frame("uint8", b"\x07").hex(), "0575696e74380000000107")

    def test_a_query_carries_no_zone(self) -> None:
        self.assertEqual(
            [f.wire_name for f in objects.Query.FIELDS],
            ["Nonce", "Caller", "Target", "QueryString"],
        )

    def test_error_message_is_a_string16(self) -> None:
        message = objects.ErrorMessage("nope")
        self.assertEqual(payload_bytes(message).hex(), "00046e6f7065")
        self.assertEqual(message, "nope")
        self.assertEqual(message.json(), "nope")


# --- the seeded sweep ------------------------------------------------------


def _random_bytes(rnd: random.Random, size: int) -> bytes:
    return bytes(rnd.randrange(256) for _ in range(size))


_SCALAR_VALUES: dict[str, Callable[[random.Random], Any]] = {
    "bool": lambda rnd: rnd.random() < 0.5,
    "uint8": lambda rnd: rnd.randrange(1 << 8),
    "uint16": lambda rnd: rnd.randrange(1 << 16),
    "uint32": lambda rnd: rnd.randrange(1 << 32),
    "uint64": lambda rnd: rnd.randrange(1 << 64),
    "int8": lambda rnd: rnd.randrange(-(1 << 7), 1 << 7),
    "int16": lambda rnd: rnd.randrange(-(1 << 15), 1 << 15),
    "int32": lambda rnd: rnd.randrange(-(1 << 31), 1 << 31),
    "int64": lambda rnd: rnd.randrange(-(1 << 63), 1 << 63),
    "float32": lambda rnd: struct.unpack(">f", _random_bytes(rnd, 4))[0],
    "float64": lambda rnd: struct.unpack(">d", _random_bytes(rnd, 8))[0],
    "string8": lambda rnd: _random_bytes(rnd, rnd.randrange(8)).decode(
        "utf-8", "surrogateescape"
    ),
    "string16": lambda rnd: _random_bytes(rnd, rnd.randrange(8)).decode(
        "utf-8", "surrogateescape"
    ),
    "string32": lambda rnd: _random_bytes(rnd, rnd.randrange(8)).decode(
        "utf-8", "surrogateescape"
    ),
    "string64": lambda rnd: _random_bytes(rnd, rnd.randrange(8)).decode(
        "utf-8", "surrogateescape"
    ),
    "bytes8": lambda rnd: _random_bytes(rnd, rnd.randrange(8)),
    "bytes16": lambda rnd: _random_bytes(rnd, rnd.randrange(8)),
    "bytes32": lambda rnd: _random_bytes(rnd, rnd.randrange(8)),
    "bytes64": lambda rnd: _random_bytes(rnd, rnd.randrange(8)),
    "identity": lambda rnd: Identity(_random_bytes(rnd, 33)),
    "nonce64": lambda rnd: Nonce(rnd.randrange(1 << 64)),
    "object_id.sha256": lambda rnd: ObjectID(
        size=rnd.randrange(1 << 32), hash=_random_bytes(rnd, 32)
    ),
    "time": lambda rnd: Time(rnd.randrange(-(1 << 63), 1 << 63)),
    "duration": lambda rnd: Duration(rnd.randrange(-(1 << 63), 1 << 63)),
    "size": lambda rnd: Size(rnd.randrange(1 << 64)),
    "zone": lambda rnd: Zone(rnd.randrange(8)),
    "object_type": lambda rnd: f"t.{rnd.randrange(1000)}",
    "error_message": lambda rnd: f"error {rnd.randrange(1000)}",
}

_OBJECT_VALUES: tuple[Callable[[random.Random], Any], ...] = (
    lambda rnd: None,
    lambda rnd: P.Uint8(rnd.randrange(1 << 8)),
    lambda rnd: P.String8(f"s{rnd.randrange(100)}"),
    lambda rnd: Identity(_random_bytes(rnd, 33)),
    lambda rnd: objects.Ack(),
    lambda rnd: objects.ErrorMessage("nope"),
    lambda rnd: P.Bytes16(_random_bytes(rnd, 4)),
)


def _sweep_specs() -> list[Spec]:
    specs: list[Spec] = [Primitive(name) for name in sorted(PRIMITIVE_TYPES)]
    specs += [Ref(name) for name in sorted(_SCALAR_VALUES)]
    specs += [Ptr(name) for name in sorted(_SCALAR_VALUES)]
    specs += [AnySpec()]
    for element in ("uint8", "uint32", "string8", "identity", "ack", ""):
        specs.append(Slice(element))
        specs.append(Array(element, 3))
    for key in sorted(MAP_KEY_TYPES):
        specs.append(Map(key, "uint16"))
        specs.append(Map(key, "identity"))
        specs.append(Map(key, ""))
    return specs


def _random_for(rnd: random.Random, spec: Spec) -> Any:
    if isinstance(spec, Primitive):
        return _SCALAR_VALUES[spec.name](rnd)
    if isinstance(spec, Ref):
        return _SCALAR_VALUES[spec.type](rnd)
    if isinstance(spec, Ptr):
        return None if rnd.random() < 0.25 else _SCALAR_VALUES[spec.type](rnd)
    if isinstance(spec, AnySpec):
        return rnd.choice(_OBJECT_VALUES)(rnd)
    if isinstance(spec, (Slice, Array)):
        length = spec.length if isinstance(spec, Array) else rnd.randrange(4)
        return [_element_for(rnd, spec.type) for _ in range(length)]
    if isinstance(spec, Map):
        out: dict[Any, Any] = {}
        for _ in range(rnd.randrange(5)):
            out[_map_key_for(rnd, spec.key)] = _element_for(rnd, spec.value)
        return out
    raise AssertionError(spec)


def _element_for(rnd: random.Random, type_name: str) -> Any:
    if not type_name:
        # A heterogeneous slot needs an object; nil is legal there and nowhere
        # else in a container.
        return rnd.choice(_OBJECT_VALUES)(rnd)
    if type_name == "ack":
        return objects.Ack()
    return _SCALAR_VALUES[type_name](rnd)


def _map_key_for(rnd: random.Random, key_type: str) -> Any:
    if key_type == "string16":
        return f"k{rnd.randrange(64)}"
    return _SCALAR_VALUES[key_type](rnd)


class SweepTests(unittest.TestCase):
    """A seeded round-trip sweep over every spec kind."""

    def test_ten_thousand_round_trips(self) -> None:
        rnd = random.Random(0)
        specs = _sweep_specs()
        self.assertGreater(len(specs), 60)
        for case in range(10_000):
            spec = specs[case % len(specs)]
            value = _random_for(rnd, spec)
            writer = ObjectWriter()
            write_spec(writer, spec, value)
            encoded = writer.getvalue()
            reader = ObjectReader(encoded, registry=default_blueprints())
            decoded = read_spec(reader, spec)
            if not reader.at_end:
                self.fail(f"{spec}: {reader.remaining} trailing bytes for {value!r}")
            again = ObjectWriter()
            write_spec(again, spec, decoded)
            if again.getvalue() != encoded:
                self.fail(f"{spec}: {value!r} re-encoded to different bytes")

    def test_every_spec_kind_is_swept(self) -> None:
        kinds = {type(spec).__name__ for spec in _sweep_specs()}
        self.assertEqual(kinds, {"Primitive", "Ref", "Slice", "Array", "Map", "Ptr", "Any"})


_register_step2_codecs()
set_provider("framing", _Framing)
