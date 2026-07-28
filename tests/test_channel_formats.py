"""Tier B and C: `open_channel`'s format matrix and the split pair.

The six tokens are `bin|json|text|canonical|base64|render` (astral-docs bug
D-7). Four are input formats; `base64` and `render` are output alone.

Three jobs:

1. Pin which implementation each `(in, out)` pair builds. The pair is what
   astral-go builds independently -- `newReceiver` from `in=`, `newSender` from
   `out=` -- so a channel that reads one format and writes another is the
   ordinary case, not an exotic one.
2. Pin the client-side validation. A node **accepts an unknown `out=` and then
   produces zero bytes** (astral-docs bug D-24), verified this session:
   `apphost.whoami?out=xml` and `apphost.whoami?out=BIN` both answer 0 bytes on
   an accepted query, where `out=` answers the 46-byte binary frame. Tokens are
   case-sensitive, and nothing on the wire ever says so.
3. Pin the format matrix against the live node: `bin`, `json`, `text` and
   `canonical` decode one op's answer to the same objects.

Every async test is `bounded`.
"""

from __future__ import annotations

import unittest

from astral import primitives as P
from astral.channel import (
    INPUT_FORMATS,
    OUTPUT_FORMATS,
    Format,
    SplitChannel,
    open_channel,
    parse_format,
)
from astral.channel.binary import BinaryChannel
from astral.channel.canonical import CanonicalChannel
from astral.channel.jsonl import JSONLinesChannel
from astral.channel.textchan import TextChannel
from astral.errors import AstralError, ParseError, TransportUnsupported
from astral.api.objects import QueryTag
from astral.object import EOS
from astral.registry import default_blueprints
from astral.session import Session
from astral.transport import MemTransport
from astral.types import Identity

from live_support import LiveCase
from mock_apphost import bounded, frame

# The one channel each format pair builds. `text` in with any of its three outs
# is one implementation, so only a genuine second implementation splits.
MATRIX = {
    ("bin", "bin"): BinaryChannel,
    ("json", "json"): JSONLinesChannel,
    ("text", "text"): TextChannel,
    ("text", "base64"): TextChannel,
    ("text", "render"): TextChannel,
    ("canonical", "canonical"): CanonicalChannel,
}


class MatrixTest(unittest.TestCase):
    def test_every_input_and_output_token_is_accounted_for(self):
        self.assertEqual(
            sorted(f.value for f in OUTPUT_FORMATS),
            ["base64", "bin", "canonical", "json", "render", "text"],
        )
        self.assertEqual(
            sorted(f.value for f in INPUT_FORMATS), ["bin", "canonical", "json", "text"]
        )

    def test_each_pair_builds_the_implementation_it_names(self):
        for fmt_in in sorted(f.value for f in INPUT_FORMATS):
            for fmt_out in sorted(f.value for f in OUTPUT_FORMATS):
                with self.subTest(fmt_in=fmt_in, fmt_out=fmt_out):
                    channel = open_channel(MemTransport.solo(), fmt_in, fmt_out)
                    expected = MATRIX.get((fmt_in, fmt_out), SplitChannel)
                    self.assertIsInstance(channel, expected)

    def test_a_split_pair_names_both_halves(self):
        channel = open_channel(MemTransport.solo(), "json", "bin")
        self.assertIsInstance(channel.reader, JSONLinesChannel)
        self.assertIsInstance(channel.writer, BinaryChannel)

    def test_an_output_only_token_is_refused_as_an_input(self):
        """`render` has no parser anywhere: astral-go's `newReceiver` answers
        "unsupported input format" for it, and there is no render receiver in
        the package at all."""
        for fmt in ("base64", "render"):
            with self.subTest(fmt=fmt):
                with self.assertRaises(ParseError):
                    open_channel(MemTransport.solo(), fmt, "bin")

    def test_an_unknown_token_is_refused_before_anything_is_dialed(self):
        """The node accepts it and then produces zero bytes and reports nothing
        (astral-docs bug D-24), so the check has to be here."""
        with self.assertRaises(ParseError):
            open_channel(MemTransport.solo(), "bin", "xml")

    def test_tokens_are_case_sensitive(self):
        """Verified live: `apphost.whoami?out=BIN` is accepted and answers zero
        bytes, where `apphost.whoami?out=` answers the 46-byte frame."""
        with self.assertRaises(ParseError):
            parse_format("BIN", output=True)
        with self.assertRaises(ParseError):
            parse_format("JSON", output=True)
        self.assertIs(parse_format("", output=True), Format.BIN)

    def test_the_format_names_are_the_channels_own_directions(self):
        """`open_channel(t, fmt_in, fmt_out)` reads `fmt_in`. A query string's
        `in=`/`out=` are the **responder's**, so a caller passing them through
        swaps the two, which `Stream` does."""
        channel = open_channel(MemTransport.solo(), "json", "bin")
        self.assertIsInstance(channel.reader, JSONLinesChannel)


class SplitChannelTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_it_reads_one_format_and_writes_the_other(self):
        """The common case, not an exotic one: a query naming only `out=json`
        asks the node to write JSON and leaves the body binary."""
        t = MemTransport.solo()
        t.feed(b'{"Type":"uint32","Object":7}\n')
        t.feed_eof()
        channel = open_channel(t, "json", "bin")
        self.assertEqual(await channel.receive(), P.Uint32(7))
        await channel.send(P.Uint32(1))
        self.assertEqual(t.sent, frame("uint32", b"\x00\x00\x00\x01"))

    @bounded()
    async def test_the_read_half_owns_what_the_read_side_reports(self):
        t = MemTransport.solo()
        t.feed(b'{"Type":"eos","Object":null}\n')
        t.feed_eof()
        channel = open_channel(t, "json", "text")
        self.assertFalse(channel.saw_eos)
        self.assertIsInstance(await channel.receive(), EOS)
        self.assertTrue(channel.saw_eos)
        self.assertTrue(channel.at_frame_boundary)
        self.assertIs(channel.transport, t)

    @bounded()
    async def test_detach_is_refused_and_names_both_halves(self):
        channel = open_channel(MemTransport.solo(), "bin", "render")
        with self.assertRaises(TransportUnsupported) as caught:
            channel.detach()
        self.assertIn("BinaryChannel", str(caught.exception))
        self.assertIn("TextChannel", str(caught.exception))

    @bounded()
    async def test_aclose_closes_the_one_transport_both_halves_share(self):
        t = MemTransport.solo()
        channel = open_channel(t, "canonical", "json")
        await channel.aclose()
        await channel.aclose()
        self.assertTrue(t.closed)

    @bounded()
    async def test_a_binary_reader_paired_with_a_render_writer_works_both_ways(self):
        """`in=bin&out=render` is what a terminal client asks for: it sends
        objects and reads a rendering."""
        t = MemTransport.solo()
        t.feed(frame("uint32", b"\x00\x00\x00\x2a"))
        t.feed_eof()
        channel = open_channel(t, "bin", "render")
        self.assertEqual(await channel.receive(), P.Uint32(42))
        await channel.send(P.String8("localuser"))
        self.assertEqual(t.sent, b"localuser\n")


class EmitterReadsBackTest(unittest.IsolatedAsyncioTestCase):
    """Whatever this SDK writes on a channel, the same channel reads back.

    The property is one sentence and it was false in three ways, each silent:
    a value carrying a newline forged extra objects on a text channel, a type
    with a `text()` and no `parse()` wrote a line the reader refused, and three
    types whose `parse` refused their own encoder's output could not cross the
    text framing at all. All three failed with no exception anywhere -- the
    first by producing *more* objects than were sent.

    `channel_text_body` is the one place the emitter's rule lives, so the sweep
    below is the regression test for the class rather than for the three
    instances that were found.
    """

    FORMATS = ("bin", "json", "text", "canonical")

    DIVERGENCES = {
        "mod.gateway.endpoint": (
            "an absent Ptr(identity) is 66 zeros in the Address() text form and "
            "a nil flag in the binary one, so json and text read back "
            "Identity.ANYONE where bin and canonical read back None. astral-go's "
            "spelling has no third state and neither does this one, so the "
            "divergence is named here rather than repaired"
        ),
        "mod.tor.endpoint": (
            "the zero value's json form is the literal `unknown`, which "
            "astral-go's UnmarshalText reads back as the zero endpoint, while "
            "its binary form is two bytes where ReadFrom wants 37. Both halves "
            "are astral-go's (api/tor/endpoint.go, digest.go at 5c18d9c) and "
            "neither can be repaired without leaving the node behind"
        ),
    }

    async def roundtrip(self, fmt: str, obj: object) -> object | str:
        """What one framing makes of one object, or `refused` if it will not.

        Which `WireError` a codec raises is its own business -- a short binary
        payload is a `ShortRead` and the same shortfall in a text body is a
        `ParseError` -- so the comparison is refusal against value, not message
        against message.
        """
        out = MemTransport.solo()
        try:
            await open_channel(out, "bin", fmt).send(obj)
        except AstralError:
            return "refused"
        back = MemTransport.solo()
        back.feed(out.sent)
        back.feed_eof()
        try:
            return await open_channel(back, fmt, "bin").receive()
        except AstralError:
            return "refused"

    @bounded()
    async def test_every_registered_zero_value_reads_the_same_in_every_framing(self):
        """115 types, four framings, one assertion: they agree.

        Agreeing on a refusal counts. `bip137sig.entropy` and `mod.tor.digest`
        have zero values astral-go itself cannot re-read, and reproducing that
        faithfully is the contract; what the four framings must never do is
        disagree, because then a value crosses one channel and is lost on
        another with nothing raised on either.
        """
        for name in default_blueprints().ordered():
            obj = default_blueprints().new(name)
            answers = {fmt: await self.roundtrip(fmt, obj) for fmt in self.FORMATS}
            with self.subTest(type=name):
                if name in self.DIVERGENCES:
                    self.assertNotEqual(
                        answers["bin"], answers["json"], self.DIVERGENCES[name]
                    )
                    continue
                self.assertEqual(
                    {fmt: repr(answer) for fmt, answer in answers.items()},
                    {fmt: repr(answers["bin"]) for fmt in self.FORMATS},
                )

    @bounded()
    async def test_a_value_carrying_a_newline_cannot_inject_an_object(self):
        """The framing locates a line by its terminator alone, so an unescaped
        newline inside a value is a frame boundary and everything after it is a
        fresh object -- including a forged `eos`, which ends the stream early
        and leaves the consumer with a clean, complete, wrong answer.

        astral-go writes `" " + text + "\\n"` with no escaping
        (`astral/channel/text_sender.go` at `5c18d9c`), so escaping here would
        leave the node behind; base64 is a spelling its `TextReceiver` reads.
        """
        forged = P.String16("xxx\n#[eos] ")
        out = MemTransport.solo()
        await open_channel(out, "bin", "text").send(forged)
        self.assertEqual(out.sent.count(b"\n"), 1, out.sent)
        self.assertEqual(await self.roundtrip("text", forged), forged)

    @bounded()
    async def test_a_type_with_a_text_form_and_no_parser_takes_the_base64_branch(self):
        """`objects.query_tag` declares `text()` for the query-parameter half of
        the encoding and no `parse()`, because astral-go's `QueryTag` declares no
        `MarshalText` at all -- so base64 is what the node emits for it too."""
        tag = QueryTag(name="title", mod="", value="x")
        out = MemTransport.solo()
        await open_channel(out, "bin", "text").send(tag)
        self.assertEqual(out.sent, b"#[objects.query_tag]:BXRpdGxlAAF4\n")
        self.assertEqual(await self.roundtrip("text", tag), tag)

    @bounded()
    async def test_the_base64_output_format_still_forces_base64(self):
        """`out=base64` is not the fallback: it is the format that never takes
        the text branch, including for a type whose text form reads back."""
        out = MemTransport.solo()
        await open_channel(out, "bin", "base64").send(P.Uint8(21))
        self.assertEqual(out.sent, b"#[uint8]:FQ==\n")


# --- Tier C ---------------------------------------------------------------


class LiveFormatMatrixTest(LiveCase):
    """Design step 14's gate: `bin`, `json`, `text` and `canonical` decode one
    op's answer to the same objects.

    Read-only and anonymous. Each format is a separate query, so the assertion
    is made on ops whose answer does not drift between two requests --
    `objects.repositories` reports free bytes, which do.
    """

    FORMATS = ("bin", "json", "text", "canonical")

    async def raw(self, qs: str) -> bytes:
        async with await self.client() as client:
            async with client.stream(qs, raw=True) as stream:
                return await stream.read_bytes(timeout=15.0)

    async def objects(self, fmt: str, data: bytes) -> list:
        t = MemTransport.solo()
        t.feed(data)
        t.feed_eof()
        channel = open_channel(t, fmt, "bin")
        out = []
        while True:
            try:
                out.append(await channel.receive())
            except EOFError:
                return out

    async def framed(self, op: str, fmt: str) -> tuple[list, str | None]:
        """One op's answer read through the ordinary client path.

        The gate is met on the path callers use and not on a replay: the channel
        frames the live socket, so a format the client refused to open would fail
        here rather than pass on bytes read raw and fed to a `MemTransport`.
        """
        async with await self.client() as client:
            async with client.stream(f"{op}?out={fmt}") as stream:
                return await stream.collect(timeout=15.0), stream.terminated_by

    async def matrix(self, op: str) -> dict[str, list]:
        return {fmt: (await self.framed(op, fmt))[0] for fmt in self.FORMATS}

    @bounded(60.0)
    async def test_one_identity_decodes_the_same_in_every_format(self):
        answers = await self.matrix("apphost.whoami")
        for fmt, objects in answers.items():
            with self.subTest(fmt=fmt):
                self.assertEqual(len(objects), 1)
                self.assertIsInstance(objects[0], Identity)
                self.assertEqual(objects[0], answers["bin"][0])
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_one_record_decodes_the_same_in_every_format(self):
        """`dir.alias_map` is the map-kind proof, and it carries an identity
        inside a map value, so every rule the four codecs disagree about is in
        one object."""
        answers = await self.matrix("dir.alias_map")
        for fmt, objects in answers.items():
            with self.subTest(fmt=fmt):
                self.assertEqual(objects, answers["bin"])
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_a_terminated_stream_decodes_the_same_in_every_format(self):
        """The node answers `dir.filters` in a different order per request, so
        the comparison is by set. The terminator is per-format and must be an
        `eos` in all four -- `collect()` consumes it, so `terminated_by` is what
        records which end arrived."""
        for fmt in self.FORMATS:
            objects, ended = await self.framed("dir.filters", fmt)
            with self.subTest(fmt=fmt):
                self.assertEqual(ended, "eos")
                self.assertGreater(len(objects), 1)
                if fmt == "bin":
                    binary = {str(o) for o in objects}
                else:
                    self.assertEqual({str(o) for o in objects}, binary)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_the_framed_answer_is_the_bytes_the_node_wrote(self):
        """The other half of the gate: the framed path decodes the same bytes a
        raw read hands over, so agreement between the four formats is agreement
        about the node's output and not about this SDK's own encoder."""
        for fmt in self.FORMATS:
            with self.subTest(fmt=fmt):
                data = await self.raw(f"apphost.whoami?out={fmt}")
                self.assertEqual(
                    await self.objects(fmt, data),
                    (await self.framed("apphost.whoami", fmt))[0],
                )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unknown_output_format_answers_zero_bytes(self):
        """astral-docs bug D-24, re-verified rather than remembered: the query is
        **accepted**, nothing is written, and no error is reported.

        The probe goes through a bare `Session` because `Client` refuses the
        token before dialing, which is the whole point of validating it
        client-side. Uppercase is the same silence: format tokens are
        case-sensitive and nothing on the wire says so.
        """
        with self.assertRaises(ParseError):
            parse_format("xml", output=True)
        for qs in ("apphost.whoami?out=xml", "apphost.whoami?out=BIN"):
            with self.subTest(query=qs):
                self.assertEqual(await self.unvalidated(qs), b"")
        # And the same op with a token the node knows still answers.
        self.assertEqual(len(await self.unvalidated("apphost.whoami?out=")), 46)
        await self.assert_no_open_sockets()

    async def unvalidated(self, qs: str) -> bytes:
        """One query, with no client-side format check between here and the node."""
        session = await Session.connect(self.endpoint)
        try:
            stream = await session.route_query(qs, timeout=15.0)
        except BaseException:
            await session.aclose()
            raise
        try:
            return await stream.read(-1)
        finally:
            await stream.aclose()
            await session.aclose()


if __name__ == "__main__":
    unittest.main()
