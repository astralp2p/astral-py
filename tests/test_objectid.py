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
from astral.errors import SchemaError
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


class _ObjectIDs:
    """The corpus's `object_id` provider: the preimage branch and the ID text."""

    @staticmethod
    def preimage(astral_type: str, payload: bytes) -> bytes:
        return preimage(astral_type, payload)

    @staticmethod
    def id_of_bytes(data: bytes) -> str:
        return str(object_id_of_bytes(data))


set_provider("object_id", _ObjectIDs)
