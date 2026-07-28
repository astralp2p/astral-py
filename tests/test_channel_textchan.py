"""Tier B and C: the text channel and its base64 and render variants.

Four jobs:

1. Pin the line bytes in both directions against **captures taken from
   `furry-bolt` this session**, including the two branches a text emitter picks
   between: the type's own text form, and base64 for a type that has none.
2. Pin the parser's wider separator set. astral-go accepts ` `, `\\t`, `:` and
   `=` where the docs give two (astral-docs bug D-6), and a bare header with no
   separator at all is the zero value.
3. Pin `base64` and `render` as output-only. `render` has no parser anywhere,
   and the node's render output proves why: it is view-driven and colourised.
4. Pin the line framing's rules, which the JSON channel shares and
   `channel/lines.py` owns.

Every async test is `bounded`.
"""

from __future__ import annotations

import unittest

from astral import primitives as P
from astral.channel import Format, open_channel
from astral.channel.textchan import TextChannel, render, render_line
from astral.errors import ParseError, StreamCorrupted, TransportUnsupported
from astral.object import Ack, Blob, EOS, ErrorMessage, UnparsedObject
from astral.transport import MemTransport
from astral.types import Identity, Size

from live_support import LiveCase
from mock_apphost import FURRY_BOLT, bounded

# Captured from `furry-bolt` this session, byte for byte.
LIVE_WHOAMI_TEXT = (
    b"#[identity] 03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185"
    b"bd7ae1\n"
)
LIVE_WHOAMI_BASE64 = b"#[identity]:A7JwSUi7LkYDzLG81fAfXfmqUsv5S2tUo5eN+BGFvXrh\n"
LIVE_ALIAS_MAP_TEXT = (
    b"#[mod.dir.alias_map]:AAAAAQAKZnVycnktYm9sdAEDsnBJSLsuRgPMsbzV8B9d+apSy/l"
    b"La1Sjl434EYW9euE=\n"
)
LIVE_FILTERS_TEXT = (
    b"#[string8] all\n"
    b"#[string8] localnode\n"
    b"#[string8] linked\n"
    b"#[string8] localswarm\n"
    b"#[string8] localuser\n"
    b"#[eos] \n"
)
LIVE_FILTERS_BASE64 = (
    b"#[string8]:CWxvY2Fsbm9kZQ==\n"
    b"#[string8]:BmxpbmtlZA==\n"
    b"#[string8]:CmxvY2Fsc3dhcm0=\n"
    b"#[string8]:CWxvY2FsdXNlcg==\n"
    b"#[string8]:A2FsbA==\n"
    b"#[eos]:\n"
)
# `apphost.whoami?out=render` on the live node. An alias, in colour, where the
# object is an identity: astrald resolves it through a view registry this SDK
# does not have and cannot have.
LIVE_WHOAMI_RENDER = b"\x1b[38;2;255;162;68mfurry-bolt\x1b[0m\n"


def channel(transport: MemTransport, **kw) -> TextChannel:  # type: ignore[no-untyped-def]
    return TextChannel(transport, **kw)


def fed(data: bytes, *, eof: bool = True, **kw) -> TextChannel:  # type: ignore[no-untyped-def]
    t = MemTransport.solo()
    t.feed(data)
    if eof:
        t.feed_eof()
    return channel(t, **kw)


class SendTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_type_with_a_text_form_takes_the_text_branch(self):
        t = MemTransport.solo()
        await channel(t).send(FURRY_BOLT)
        self.assertEqual(t.sent, LIVE_WHOAMI_TEXT)

    @bounded()
    async def test_a_record_has_no_text_form_and_takes_the_base64_branch(self):
        import astral.api  # noqa: F401 -- registers mod.dir.alias_map

        alias_map = await fed(LIVE_ALIAS_MAP_TEXT).receive()
        t = MemTransport.solo()
        await channel(t).send(alias_map)
        self.assertEqual(t.sent, LIVE_ALIAS_MAP_TEXT)

    @bounded()
    async def test_a_zero_payload_object_is_a_header_a_space_and_nothing(self):
        """The trailing space is the separator, not part of the object. The node
        writes `#[eos] ` and so does this."""
        t = MemTransport.solo()
        await channel(t).send(EOS())
        self.assertEqual(t.sent, b"#[eos] \n")

    @bounded()
    async def test_an_untyped_blob_carries_an_empty_header(self):
        """The one format where an untyped object survives: the header names no
        type and the body is the blob's own text form, which is base64."""
        t = MemTransport.solo()
        await channel(t).send(Blob(b"raw"))
        self.assertEqual(t.sent, b"#[] cmF3\n")

    @bounded()
    async def test_every_object_is_exactly_one_write(self):
        t = MemTransport.solo()
        ch = channel(t)
        for obj in (P.Uint32(1), Ack(), EOS()):
            await ch.send(obj)
        self.assertEqual(t.writes, [b"#[uint32] 1\n", b"#[ack] \n", b"#[eos] \n"])

    @bounded()
    async def test_an_unparsed_object_is_refused(self):
        """astral-go's text sender would emit its base64 form.
        `UnparsedObject.text()` raises `ParseError`, which `codec.text.encode`
        does not catch, so no base64 fallback is reached. Layer 1 owns that
        decision."""
        t = MemTransport.solo()
        with self.assertRaises(ParseError):
            await channel(t).send(UnparsedObject("test.absent", b"\x01"))
        self.assertEqual(t.writes, [])


class Base64OutputTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_base64_forces_the_payload_branch_for_a_type_with_a_text_form(self):
        t = MemTransport.solo()
        await channel(t, fmt_out="base64").send(FURRY_BOLT)
        self.assertEqual(t.sent, LIVE_WHOAMI_BASE64)

    @bounded()
    async def test_the_live_base64_filter_lines_are_reproduced_exactly(self):
        t = MemTransport.solo()
        ch = channel(t, fmt_out=Format.BASE64)
        for name in ("localnode", "linked", "localswarm", "localuser", "all"):
            await ch.send(P.String8(name))
        await ch.send(EOS())
        self.assertEqual(t.sent, LIVE_FILTERS_BASE64)

    @bounded()
    async def test_the_header_is_unchanged_and_only_the_body_is_forced(self):
        t = MemTransport.solo()
        ch = channel(t, fmt_out="base64")
        await ch.send(Ack())
        await ch.send(Blob(b"raw"))
        self.assertEqual(t.sent, b"#[ack]:\n#[]:cmF3\n")

    @bounded()
    async def test_a_base64_channel_still_reads_text(self):
        """The two directions are independent. astral-go builds the receiver
        from `in=` and the sender from `out=`, and `base64` names an output."""
        t = MemTransport.solo()
        t.feed(LIVE_WHOAMI_TEXT)
        t.feed_eof()
        self.assertEqual(await channel(t, fmt_out="base64").receive(), FURRY_BOLT)


class RenderTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_render_writes_the_value_with_no_header(self):
        t = MemTransport.solo()
        ch = channel(t, fmt_out="render")
        for obj in (P.Uint32(42), P.String8("localuser"), Blob(b"raw"), EOS()):
            await ch.send(obj)
        self.assertEqual(t.sent, b"42\nlocaluser\ncmF3\n\n")

    def test_render_prefers_the_text_form_over_the_repr_fallback(self):
        """Python's `__str__` is a `repr` fallback rather than a declared
        marshaller, so astral-go's `String()`-first order cannot be ported:
        `str(Uint32(42))` is `Uint32(42)` and `str(Blob(b"raw"))` is `b'raw'`."""
        self.assertEqual(render(P.Uint32(42)), "42")
        self.assertEqual(render(Blob(b"raw")), "cmF3")
        self.assertEqual(render(Ack()), "")
        self.assertEqual(render(ErrorMessage("nope")), "nope")
        self.assertEqual(render(FURRY_BOLT), str(FURRY_BOLT))

    def test_a_type_with_no_text_form_falls_back_to_its_plain_spelling(self):
        """`object_type` has no text marshaller in astral-go, so the fallback is
        what renders it, and it renders the same string astral-go's `String()`
        does."""
        self.assertEqual(render(P.ObjectType("uint8")), "uint8")

    def test_size_is_the_one_type_the_two_orders_disagree_on(self):
        """astral-go renders `Size.String()`, the human form. The text form is
        the decimal, and the design says so explicitly (section 2.2)."""
        self.assertEqual(render(Size(1536)), "1536")
        self.assertEqual(str(Size(1536)), "1.5KiB")

    def test_a_record_renders_as_a_debugging_spelling_neither_side_parses(self):
        import astral.api  # noqa: F401

        from astral.api.dir import AliasMap

        rendered = render(AliasMap(aliases={"furry-bolt": FURRY_BOLT}))
        self.assertIn("furry-bolt", rendered)
        self.assertNotIn("#[", rendered)

    def test_render_line_terminates_the_line(self):
        self.assertEqual(render_line(P.Uint32(7)), "7\n")

    @bounded()
    async def test_render_is_output_only_everywhere(self):
        t = MemTransport.solo()
        with self.assertRaises(ValueError):
            open_channel(t, "render", "bin")
        with self.assertRaises(ValueError):
            TextChannel(t, fmt_out="bin")

    def test_the_nodes_render_output_is_not_a_text_line(self):
        """astrald resolves each object through a view registry and colours the
        result: `apphost.whoami?out=render` answers an alias in ANSI, where the
        object is an identity. Nothing can parse that back, and nothing should
        try."""
        self.assertNotIn(b"#[", LIVE_WHOAMI_RENDER)
        self.assertIn(b"\x1b[", LIVE_WHOAMI_RENDER)


class ReceiveTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_the_live_whoami_line_decodes_to_the_hosts_identity(self):
        received = await fed(LIVE_WHOAMI_TEXT).receive()
        self.assertIsInstance(received, Identity)
        self.assertEqual(received, FURRY_BOLT)

    @bounded()
    async def test_the_live_base64_body_decodes_to_the_same_identity(self):
        self.assertEqual(await fed(LIVE_WHOAMI_BASE64).receive(), FURRY_BOLT)

    @bounded()
    async def test_the_live_filter_stream_stops_at_the_eos_line(self):
        ch = fed(LIVE_FILTERS_TEXT)
        seen = [obj async for obj in ch]
        self.assertEqual(
            [str(o) for o in seen],
            ["all", "localnode", "linked", "localswarm", "localuser"],
        )
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_every_separator_astral_go_accepts_is_accepted(self):
        """Four, where the docs give two (astral-docs bug D-6). A bare header
        with no separator carries no payload and is the zero value."""
        ch = fed(b"#[uint8] 21\n#[uint8]\t21\n#[uint8]:FQ==\n#[uint8]=FQ==\n#[uint8]\n")
        self.assertEqual(
            [obj async for obj in ch],
            [P.Uint8(21), P.Uint8(21), P.Uint8(21), P.Uint8(21), P.Uint8(0)],
        )

    @bounded()
    async def test_an_empty_type_header_is_an_untyped_blob(self):
        received = await fed(b"#[] cmF3\n").receive()
        self.assertIsInstance(received, Blob)
        self.assertEqual(received, b"raw")

    @bounded()
    async def test_a_line_with_no_type_header_is_a_parse_error(self):
        ch = fed(b"localuser\n")
        with self.assertRaises(ParseError):
            await ch.receive()

    @bounded()
    async def test_a_separator_that_is_not_one_is_a_parse_error(self):
        ch = fed(b"#[uint8]!21\n")
        with self.assertRaises(ParseError):
            await ch.receive()

    @bounded()
    async def test_an_unknown_type_ends_the_stream(self):
        ch = fed(b"#[test.absent] 1\n" + LIVE_WHOAMI_TEXT)
        with self.assertRaises(StreamCorrupted):
            await ch.receive()
        with self.assertRaises(StreamCorrupted):
            await ch.receive()

    @bounded()
    async def test_a_line_with_no_terminator_is_a_truncation(self):
        """The reason this is stricter than astral-go, which drops it: a
        truncated `#[uint8] 21` reads as `#[uint8] 2`, which is a plausible wrong
        value rather than a fault."""
        ch = fed(b"#[uint8] 21")
        with self.assertRaises(StreamCorrupted):
            await ch.receive()
        self.assertFalse(ch.at_frame_boundary)

    @bounded()
    async def test_a_line_split_across_arrivals_reassembles(self):
        t = MemTransport.solo(max_chunk=1)
        t.feed(LIVE_FILTERS_TEXT)
        t.feed_eof()
        ch = channel(t)
        self.assertEqual(len([obj async for obj in ch]), 5)
        self.assertTrue(ch.saw_eos)

    @bounded()
    async def test_detach_is_refused(self):
        ch = fed(LIVE_FILTERS_TEXT, eof=False)
        with self.assertRaises(TransportUnsupported) as caught:
            ch.detach()
        self.assertIn("text", str(caught.exception))


class OpenChannelTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_one_text_channel_covers_text_in_with_each_of_its_outs(self):
        for fmt_out in ("text", "base64", "render"):
            with self.subTest(out=fmt_out):
                ch = open_channel(MemTransport.solo(), "text", fmt_out)
                self.assertIsInstance(ch, TextChannel)
                self.assertIs(ch.fmt_out, Format(fmt_out))


# --- Tier C ---------------------------------------------------------------


class LiveTextTest(LiveCase):
    """The node's own text lines, decoded and re-encoded byte for byte."""

    async def raw(self, qs: str) -> bytes:
        async with await self.client() as client:
            async with client.stream(qs, raw=True) as stream:
                return await stream.read_bytes(timeout=15.0)

    async def objects(self, data: bytes) -> list:
        t = MemTransport.solo()
        t.feed(data)
        t.feed_eof()
        ch = TextChannel(t)
        out = []
        while True:
            try:
                out.append(await ch.receive())
            except EOFError:
                return out

    @bounded(30.0)
    async def test_the_whoami_line_carries_the_hosts_identity(self):
        [identity] = await self.objects(await self.raw("apphost.whoami?out=text"))
        self.assertIsInstance(identity, Identity)
        self.assertEqual(len(identity.key), 33)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_re_encoding_the_nodes_stream_reproduces_its_bytes(self):
        for qs, fmt_out in (
            ("dir.alias_map?out=text", "text"),
            ("dir.filters?out=text", "text"),
            ("objects.repositories?out=text", "text"),
            ("dir.filters?out=base64", "base64"),
            ("apphost.whoami?out=base64", "base64"),
        ):
            with self.subTest(query=qs):
                data = await self.raw(qs)
                t = MemTransport.solo()
                ch = TextChannel(t, fmt_out=fmt_out)
                for obj in await self.objects(data):
                    await ch.send(obj)
                self.assertEqual(t.sent, data)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_nodes_render_output_carries_no_type_header(self):
        """Verified rather than argued: render is display, and no client parses
        it back."""
        data = await self.raw("dir.filters?out=render")
        self.assertTrue(data)
        self.assertNotIn(b"#[", data)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
