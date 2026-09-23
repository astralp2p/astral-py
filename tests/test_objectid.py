"""ObjectID derivation: the harness hook plus the cases the corpus cannot state.

The corpus measures every vector's `object_id_preimage` and `object_id` through
the provider registered at the bottom of this file. What is left for this module
is the reference table of design 2.7, the text form's shape, and the one place
where astral-go and the docs disagree -- an untyped object's ID -- which no
positive vector can express because the corpus records both answers.
"""

from __future__ import annotations

import io
import unittest

from astral import object as objects
from astral.codec.binary import payload_bytes
from astral.errors import ParseError, SchemaError
from astral.objectid import (
    canonical_form,
    object_id,
    object_id_of,
    object_id_of_bytes,
    object_id_of_stream,
    preimage,
)
from astral.primitives import String8, Uint32
from astral.types import ObjectID
from vectors import set_provider, vector_by_id

# Design 2.7, verified against astral-go and an independent reimplementation.
# Fixtures, not examples: `hello` appears twice on purpose, once as a `string8`
# payload inside a canonical form and once as five untyped bytes.
REFERENCE: dict[str, tuple[str, str]] = {
    "uint32(42)": (
        "414443300675696e7433320000002a",
        "data19kygic9q9ibq4ibaikrw9ci76kj6fs1jitxk6wjbwnkrezt8q5jk",
    ),
    'string8("hello")': (
        "4144433007737472696e67380568656c6c6f",
        "data1brwgb65sy54z9imojxaaof9btx3nujt1rxqyozt9ahxm189hi36e1",
    ),
    "ack": (
        "414443300361636b",
        "data1o3dutabz1sm1zyyueipc3q18dam6aszrte4hqtmfspxtkje17npe",
    ),
    "eos": (
        "4144433003656f73",
        "data1t45yb4f1o4atw33k85dbo78uudnw4eoju7z7jo5ba5p53rqyz5ft",
    ),
    "raw hello": (
        "68656c6c6f",
        "data1km81js7f9cfdbauqoq3kash6f8o5naxfa878ejx8gbbuckjazgbr",
    ),
    "empty": (
        "",
        "data1ba7oatbjt9yhn1pxz7geufz51jb8i3y6e3r51pgkjfc3dphffqni",
    ),
}


class ReferenceIDTests(unittest.TestCase):
    """The six reference ObjectIDs of design 2.7, each by the path it belongs to."""

    def test_the_four_typed_references(self) -> None:
        for label, obj in (
            ("uint32(42)", Uint32(42)),
            ('string8("hello")', String8("hello")),
            ("ack", objects.Ack()),
            ("eos", objects.EOS()),
        ):
            expected_preimage, expected_id = REFERENCE[label]
            with self.subTest(label):
                self.assertEqual(canonical_form(obj).hex(), expected_preimage)
                self.assertEqual(str(object_id(obj)), expected_id)
                self.assertEqual(str(object_id_of(obj)), expected_id)

    def test_the_two_untyped_references(self) -> None:
        for label, data in (("raw hello", b"hello"), ("empty", b"")):
            expected_preimage, expected_id = REFERENCE[label]
            with self.subTest(label):
                self.assertEqual(data.hex(), expected_preimage)
                self.assertEqual(str(object_id_of_bytes(data)), expected_id)
                self.assertEqual(str(object_id_of(objects.Blob(data))), expected_id)

    def test_size_counts_the_preimage_and_not_the_payload(self) -> None:
        # 4 stamp + 1 length + 6 name + 4 payload.
        self.assertEqual(object_id(Uint32(42)).size, 15)
        self.assertEqual(object_id_of_bytes(b"hello").size, 5)


class TwoPathsTests(unittest.TestCase):
    """The typed and untyped paths are separate, and only one of them is astral-go's."""

    def test_the_typed_path_refuses_an_untyped_object(self) -> None:
        for obj in (objects.Blob(b"hello"), objects.Blob(b"")):
            with self.subTest(obj), self.assertRaises(SchemaError):
                object_id(obj)

    def test_astral_go_would_report_a_different_id_for_a_blob(self) -> None:
        """astral-go's `ResolveObjectID` has no untyped branch (design G-2, D-28).

        The corpus records what it produces for `Blob(b"hello")` and this test
        pins the divergence: same object, two IDs, and the untyped one is the ID
        the node, the docs and `objects.create` agree on.
        """
        go = vector_by_id("objectid.blob_via_typed_path")
        # `Stamp ++ string8("") ++ hello`: 10 bytes where the correct preimage is 5.
        self.assertEqual(go.hex("object_id_preimage"), b"\x41\x44\x43\x30\x00hello")
        wrong = object_id_of_bytes(go.hex("object_id_preimage"))
        self.assertEqual(str(wrong), go.raw["object_id"])
        self.assertEqual(wrong.size, 10)

        right = object_id_of(objects.Blob(b"hello"))
        self.assertEqual(right.size, 5)
        self.assertNotEqual(str(right), str(wrong))
        self.assertEqual(str(right), REFERENCE["raw hello"][1])

    def test_the_preimage_branch_is_chosen_by_typedness_alone(self) -> None:
        self.assertEqual(preimage("", b"hello"), b"hello")
        self.assertEqual(preimage("uint32", b"\x00\x00\x00\x2a").hex(), REFERENCE["uint32(42)"][0])
        self.assertEqual(preimage("", b""), b"")


class StreamPathTests(unittest.TestCase):
    """The streaming ID equals the in-memory one, across any chunk boundary."""

    def test_stream_matches_bytes(self) -> None:
        for data in (b"", b"hello", bytes(range(256)) * 1024, b"\xff" * ((1 << 16) + 1)):
            with self.subTest(len(data)):
                self.assertEqual(
                    object_id_of_stream(io.BytesIO(data)), object_id_of_bytes(data)
                )

    def test_a_short_reading_stream_is_read_to_eof(self) -> None:
        class Dribble:
            """A stream that returns one byte per call, as a socket may."""

            def __init__(self, data: bytes) -> None:
                self._data = data
                self._pos = 0

            def read(self, size: int = -1, /) -> bytes:
                chunk = self._data[self._pos : self._pos + 1]
                self._pos += len(chunk)
                return chunk

        self.assertEqual(object_id_of_stream(Dribble(b"hello")), object_id_of_bytes(b"hello"))


class TextFormTests(unittest.TestCase):
    """40 bytes render as at most 64 symbols, never padded, `y`-stripped."""

    def test_every_reference_id_is_prefixed_and_unpadded(self) -> None:
        for label, (_, text) in REFERENCE.items():
            with self.subTest(label):
                self.assertTrue(text.startswith("data1"))
                self.assertLessEqual(len(text) - len("data1"), 64)
                self.assertNotIn("=", text)

    def test_the_zero_id_is_a_bare_prefix(self) -> None:
        # Every symbol of 40 zero bytes is the zero symbol `y`, and all 64 strip.
        self.assertEqual(str(ObjectID.ZERO), "data1")
        self.assertEqual(ObjectID.parse("data1"), ObjectID.ZERO)

    def test_derived_ids_round_trip_through_text(self) -> None:
        for data in (b"", b"hello", b"\x00" * 40):
            with self.subTest(data):
                got = object_id_of_bytes(data)
                self.assertEqual(ObjectID.parse(str(got)), got)

    def test_a_full_width_id_is_exactly_64_symbols(self) -> None:
        # A size whose top byte is set leaves no leading zero symbol to strip.
        full = ObjectID(size=1 << 63, hash=b"\xff" * 32)
        self.assertEqual(len(str(full)) - len("data1"), 64)
        self.assertEqual(ObjectID.parse(str(full)), full)


def _partial_body(oid: ObjectID) -> str:
    """The 52 symbols of `oid`'s hash, computed without the parser.

    The encoder under test emits `data1` only, so the expected `data0` body is
    derived here from the alphabet rather than taken from the SDK.
    """
    alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
    value = int.from_bytes(bytes(8) + oid.hash, "big")
    symbols = "".join(alphabet[(value >> (5 * i)) & 31] for i in range(63, -1, -1))
    return symbols[12:]


class PartialTextFormTests(unittest.TestCase):
    """`data0`: an ID that names an object by hash, with no size.

    The two vectors are astral-docs `0040e909`
    `primitive-types/object_id.sha256.md` -- the astral-docs authority of
    `docs/architecture.md`, and past the `1d6787c` the Tier A corpus freezes,
    because `data0` does not exist at `1d6787c`. Each is checked against the
    `data1` form of the same hash rather than against itself: a vector that only
    agrees with its own prefix would pass on a decoder that ignored the body.

    The `hello` vector does not rest on the docs. Its `data1` form is
    `REFERENCE["raw hello"]` above -- design 2.7's table, derived against
    astral-go and an independent reimplementation long before `data0` existed --
    so the hash the docs publish and the hash this module already computed for
    `hello` are the same 32 bytes, checked by
    `test_the_vectors_agree_with_the_reference_table`.

    The size-71 vector rests on astral-docs alone, which under `CLAUDE.md` does
    not establish a wire fact. It is kept for the one thing the `hello` vector
    cannot show -- a body opening on `b` -- and the parser behaviour it covers
    is established independently: astral-go `astral/object_id.go:36` at the pin
    accepts exactly these bodies, and `test_every_derived_id_has_a_partial_form_that_parses_back`
    covers both openers over hashes this module computes itself.
    """

    # payload `hello`, size 5. The first hash bit is 0, so the body opens on `y`.
    HELLO_FULL = "data1km81js7f9cfdbauqoq3kash6f8o5naxfa878ejx8gbbuckjazgbr"
    HELLO_PARTIAL = "data0ym81js7f9cfdbauqoq3kash6f8o5naxfa878ejx8gbbuckjazgbr"
    # size 71. The first hash bit is 1, so the body opens on `b`.
    SIZED_FULL = "data1rxqff36hhoddbhwbsd5c1smbpoh9oq5pgum6n6g4bg1esia4psp1r"
    SIZED_PARTIAL = "data0bqff36hhoddbhwbsd5c1smbpoh9oq5pgum6n6g4bg1esia4psp1r"

    VECTORS = ((HELLO_FULL, HELLO_PARTIAL, 5), (SIZED_FULL, SIZED_PARTIAL, 71))

    def test_the_vectors_agree_with_the_reference_table(self) -> None:
        """The `hello` vector's full form is design 2.7's own entry, so the
        `data0` body is checked against a hash this repository established
        independently of the document that publishes the vector."""
        self.assertEqual(self.HELLO_FULL, REFERENCE["raw hello"][1])
        self.assertEqual(
            ObjectID.parse(self.HELLO_PARTIAL).hash, object_id_of_bytes(b"hello").hash
        )

    def test_each_vector_parses_to_the_hash_of_its_full_form_and_no_size(self) -> None:
        for full_text, partial_text, size in self.VECTORS:
            with self.subTest(partial_text):
                full = ObjectID.parse(full_text)
                partial = ObjectID.parse(partial_text)
                self.assertEqual(full.size, size)
                self.assertEqual(partial.size, 0)
                self.assertEqual(partial.hash, full.hash)

    def test_both_permitted_opening_symbols_are_accepted(self) -> None:
        """The body's first symbol carries four zero size bits and the first
        hash bit, so a well-formed body opens on `y` or `b` and on nothing else.

        Both openers are exercised through the parser: the two vectors cover
        them, and a decoder that refused either would fail here.
        """
        openers = set()
        for _, partial_text, _ in self.VECTORS:
            opener = partial_text[len("data0")]
            openers.add(opener)
            parsed = ObjectID.parse(partial_text)
            self.assertEqual(parsed.size, 0)
            # The opener's four size bits are zero, so the hash's leading bit is
            # what distinguishes the two: `y` is 0, `b` is 1.
            leading_hash_bit = parsed.hash[0] >> 7
            self.assertEqual(leading_hash_bit, 0 if opener == "y" else 1)
        self.assertEqual(openers, {"y", "b"})

    def test_the_encoder_never_emits_the_partial_form(self) -> None:
        """Parsing is the only direction that is asymmetric: every encoding of a
        size-0 ID is `data1`, so a round trip through text widens the form."""
        partial = ObjectID.parse(self.HELLO_PARTIAL)
        self.assertTrue(str(partial).startswith("data1"))
        self.assertEqual(partial.json(), str(partial))
        self.assertEqual(ObjectID.parse(str(partial)), partial)

    def test_the_binary_form_is_forty_bytes_with_a_zero_size(self) -> None:
        """`Size` 0 means absent in every encoding, the 40-byte one included."""
        partial = ObjectID.parse(self.HELLO_PARTIAL)
        raw = payload_bytes(partial)
        self.assertEqual(len(raw), 40)
        self.assertEqual(raw[:8], bytes(8))
        self.assertEqual(raw[8:], partial.hash)

    def test_a_body_that_is_not_fifty_two_symbols_is_refused(self) -> None:
        """Exact, not maximal: a short `data0` body is a different hash, not a
        smaller number, so padding one would invent an ID."""
        body = self.HELLO_PARTIAL[len("data0") :]
        for bad in (body[:-1], body + "y", "", body[:26]):
            with self.subTest(len(bad)):
                with self.assertRaises(ParseError):
                    ObjectID.parse("data0" + bad)

    def test_a_body_opening_on_another_symbol_is_refused(self) -> None:
        body = self.HELLO_PARTIAL[len("data0") + 1 :]
        for opener in ("n", "d", "9", "1"):
            with self.subTest(opener):
                with self.assertRaises(ParseError):
                    ObjectID.parse("data0" + opener + body)

    def test_a_symbol_outside_the_alphabet_is_refused(self) -> None:
        """`l`, `v`, `2` and `0` are not zBase32, and neither is an uppercase
        symbol: the alphabet is lowercase."""
        body = self.HELLO_PARTIAL[len("data0") :]
        for bad in ("y" + body[1:].upper(), "y" + "l" * 51, "y" + "0" * 51):
            with self.subTest(bad[:8]):
                with self.assertRaises(ParseError):
                    ObjectID.parse("data0" + bad)

    def test_a_body_of_fifty_two_y_symbols_is_the_zero_id(self) -> None:
        """Decoding is the encoding's rule and reports what the text carries: 40
        zero bytes. No object hashes to them, so the value is the zero ID and the
        ops that refuse an unset id refuse it."""
        zero = ObjectID.parse("data0" + "y" * 52)
        self.assertEqual(zero, ObjectID.ZERO)
        self.assertTrue(zero.is_zero)

    def test_the_empty_object_carries_one_body_in_both_forms(self) -> None:
        """Its own `Size` is 0, so its full ID is already partial and the two
        text forms agree symbol for symbol."""
        empty = object_id_of_bytes(b"")
        self.assertEqual(empty.size, 0)
        body = str(empty)[len("data1") :]
        # 12 leading `y` strip from the `data1` form too, because the size is 0
        # and the first hash bit is 1 -- so symbol 12 is `b` and stops the strip.
        self.assertEqual(len(body), 52)
        self.assertTrue(body.startswith("b"))
        self.assertEqual(body, _partial_body(empty))
        self.assertEqual(ObjectID.parse("data0" + body), empty)

    def test_every_derived_id_has_a_partial_form_that_parses_back(self) -> None:
        """Over hashes this module computes rather than quotes, and covering
        both openers, so the parser is exercised on `y` and `b` bodies whose
        provenance owes nothing to astral-docs."""
        openers = set()
        for data in (b"", b"hello", b"\x00" * 40, bytes(range(256))):
            with self.subTest(data[:8]):
                got = object_id_of_bytes(data)
                body = _partial_body(got)
                openers.add(body[0])
                parsed = ObjectID.parse("data0" + body)
                self.assertEqual(parsed.size, 0)
                self.assertEqual(parsed.hash, got.hash)
        self.assertEqual(openers, {"y", "b"})

    def test_the_full_form_still_parses_as_it_did(self) -> None:
        """The `data0` branch is additive: `data1` keeps its stripped, variable
        body and its size."""
        self.assertEqual(ObjectID.parse("data1"), ObjectID.ZERO)
        full = ObjectID(size=1 << 63, hash=b"\xff" * 32)
        self.assertEqual(ObjectID.parse(str(full)), full)
        with self.assertRaises(ParseError):
            ObjectID.parse("data1" + "y" * 65)
        with self.assertRaises(ParseError):
            ObjectID.parse("data2" + "y" * 52)


class _ObjectIDs:
    """The corpus's `object_id` provider: the preimage branch and the ID text."""

    @staticmethod
    def preimage(astral_type: str, payload: bytes) -> bytes:
        return preimage(astral_type, payload)

    @staticmethod
    def id_of_bytes(data: bytes) -> str:
        return str(object_id_of_bytes(data))


set_provider("object_id", _ObjectIDs)
