"""Tier B: `astral-query` -- its three output formats and its six exit codes.

The gate of implementation step 12, and both halves of it are here because both
are a **contract with other programs**. The CLI is the only human-facing surface
of this SDK and scripts parse it: a changed separator breaks an `awk`, a changed
exit code breaks an `if`, and neither failure is visible from inside the SDK.

- **Output formats are golden.** The whole of stdout is compared to a literal,
  byte for byte, rather than probed for a substring. A substring assertion
  passes on a line that gained a prefix, lost a tab, or arrived in the wrong
  order, and all three break a parser downstream.
- **Every exit code has a test.** 0, 1, 2, 3, 130 and 141, each from the fault
  that produces it rather than from a patched return value, with the two signal
  codes driven through `main` itself.

`main` runs on a worker thread while the mock node runs on the test's loop, so
what is under test is the real entry point -- `asyncio.run`, the `async with` on
the client, the `KeyboardInterrupt` and `BrokenPipeError` handlers -- and not a
coroutine lifted out of it. The two loops never meet: they talk over a loopback
socket, exactly as a shell and a node do.

Every test bounds itself and none contacts a node.
"""

from __future__ import annotations

import asyncio
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence
from unittest import mock as mocklib

import astral
from astral import cli
from astral.client import ENDPOINT_VARS, TOKEN_VARS
from astral.wire import Writer

import api_walk
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    Hang,
    MockApphost,
    Reject,
    bounded,
    until,
)

# --- object frames -------------------------------------------------------


def u8(value: int) -> tuple[str, bytes]:
    return ("uint8", bytes([value]))


def s8(text: str) -> tuple[str, bytes]:
    w = Writer()
    w.string8(text)
    return ("string8", w.getvalue())


def error(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


IDENTITY_FRAME = ("identity", FURRY_BOLT.key)
IDENTITY_HEX = FURRY_BOLT.hex()
BLOB_FRAME = ("", b"hello")

MIXED = [u8(21), s8("hello"), IDENTITY_FRAME, BLOB_FRAME]
"""One object of each display rule: a scalar, a string, a value type, untyped bytes."""


# --- capture -------------------------------------------------------------


class Capture:
    """A text stream with a byte side, so `sys.stdout.buffer` has a stand-in.

    `write_through=True` so a `write()` reaches the buffer immediately: the raw
    passthrough of design section 6.1 writes to `stream.buffer` directly, and a
    text layer holding a line back would reorder the two.
    """

    __slots__ = ("raw", "text")

    def __init__(self) -> None:
        self.raw = io.BytesIO()
        self.text = io.TextIOWrapper(
            self.raw, encoding="utf-8", newline="", write_through=True
        )

    @property
    def data(self) -> bytes:
        self.text.flush()
        return self.raw.getvalue()

    @property
    def value(self) -> str:
        return self.data.decode("utf-8", "replace")

    @property
    def lines(self) -> list[str]:
        return self.value.splitlines()


class CliCase(unittest.IsolatedAsyncioTestCase):
    """One mock node on this loop, one `main()` on a worker thread.

    The endpoint and token variables are blanked for every test: both resolvers
    skip an empty value, so a developer's own `ASTRALD_TOKEN` cannot make the
    command authenticate against a mock that has no token and fail the whole
    file with `AuthFailed`.
    """

    async def asyncSetUp(self) -> None:
        self.out = Capture()
        self.err = Capture()
        blanked = {name: "" for name in ENDPOINT_VARS + TOKEN_VARS}
        patch = mocklib.patch.dict(os.environ, blanked)
        patch.start()
        self.addCleanup(patch.stop)

    async def run_argv(self, argv: Sequence[str]) -> int:
        """Run `main` on a worker thread, with both streams captured."""
        return await asyncio.to_thread(
            cli.main, list(argv), stdout=self.out.text, stderr=self.err.text
        )

    async def run_cli(
        self, mock: MockApphost, *argv: str, timeout: str = "3"
    ) -> int:
        """Run `main` against a listening mock, with a deadline on the query.

        The deadline is not decoration: a worker thread cannot be cancelled, so a
        command that hung would outlive the test that started it and stall the
        interpreter's exit rather than failing anything.
        """
        return await self.run_argv(
            ["--endpoint", mock.endpoint, "--timeout", timeout, *argv]
        )

    async def node(self, **kw: Any) -> MockApphost:
        """A listening mock node, closed when the test ends."""
        mock = MockApphost(**kw)
        await mock.__aenter__()
        self.addAsyncCleanup(mock.aclose)
        await mock.listen("tcp")
        return mock


# --- output formats ------------------------------------------------------


class OutputFormatTest(CliCase):
    """The three renderings, each pinned whole.

    `bin` is the raw passthrough -- bytes, unaltered, on the byte side of
    stdout. `text` is the default `type<TAB>value` line of design section 6.1.
    `json` is its `{"Type": …, "Object": …}` envelope. All three are what a
    script downstream reads, so all three are literals here.
    """

    @bounded()
    async def test_default_format_is_one_tab_separated_line_per_object(self):
        mock = await self.node(routes={"x.mixed": Accept(objects=MIXED, eos=True)})
        code = await self.run_cli(mock, "x.mixed")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(
            self.out.value,
            "uint8\t21\n"
            "string8\thello\n"
            f"identity\t{IDENTITY_HEX}\n"
            "<untyped>\thello\n",
        )
        self.assertEqual(self.err.value, "")

    @bounded()
    async def test_json_format_is_one_envelope_per_line(self):
        mock = await self.node(routes={"x.mixed": Accept(objects=MIXED, eos=True)})
        code = await self.run_cli(mock, "--json", "x.mixed")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(
            self.out.value,
            '{"Type": "uint8", "Object": 21}\n'
            '{"Type": "string8", "Object": "hello"}\n'
            f'{{"Type": "identity", "Object": "{IDENTITY_HEX}"}}\n'
            '{"Type": "", "Object": "68656c6c6f"}\n',
        )

    @bounded()
    async def test_objects_read_writes_the_body_to_stdout_unaltered(self):
        """The RAW op: bytes, no framing, no trailing newline, exit 0.

        The body is deliberately not UTF-8. A stored file is not text, and a
        passthrough that decoded it would corrupt every byte above 0x7f.
        """
        body = bytes(range(256))
        mock = await self.node(routes={"objects.read": Accept(raw=body)})
        code = await self.run_cli(mock, "objects.read", "-id", "data1abc")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.out.data, body)

    @bounded()
    async def test_objects_read_returns_zero_on_an_empty_body(self):
        mock = await self.node(routes={"objects.read": Accept()})
        code = await self.run_cli(mock, "objects.read", "-id", "data1abc")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.out.data, b"")

    @bounded()
    async def test_every_out_format_help_advertises_actually_runs(self):
        """`--help` names six and five of them exited 1.

        Four are framings this side reads, so the objects come back decoded and
        the ordinary `type<TAB>value` rendering applies. `base64` and `render`
        are the two spellings **no** receiver anywhere parses -- astral-go's
        `newReceiver` has a case for neither -- so their body is written out
        unaltered, which is what a human asking for a rendering wanted.
        """
        # One `uint8` and an `eos`, spelled by hand in each framing, so a wrong
        # layout in the SDK cannot agree with a wrong layout in the harness.
        # `bin` carries no `out=` in the query string: the client writes only a
        # non-default format into it, so an ordinary query travels unchanged.
        bodies = {
            "bin": ("x.one", b"\x05uint8\x00\x00\x00\x01\x15\x03eos\x00\x00\x00\x00"),
            "json": (
                "x.one?out=json",
                b'{"Type":"uint8","Object":21}\n{"Type":"eos","Object":null}\n',
            ),
            "text": ("x.one?out=text", b"#[uint8] 21\n#[eos] \n"),
            "canonical": ("x.one?out=canonical", b"ADC0\x05uint8\x15ADC0\x03eos"),
        }
        for fmt, (route, body) in bodies.items():
            with self.subTest(fmt=fmt):
                mock = await self.node(routes={route: Accept(raw=body)})
                out, self.out = self.out, Capture()
                code = await self.run_cli(mock, "--out", fmt, "x.one")
                self.assertEqual(code, cli.EXIT_OK, self.err.value)
                self.assertEqual(self.out.lines, ["uint8\t21"])
                self.assertEqual([q.query for q in mock.queries], [route])
                self.out = out
        for fmt, body in (("base64", b"#[uint8]:FQ==\n"), ("render", b"21\n")):
            with self.subTest(fmt=fmt):
                mock = await self.node(
                    routes={f"x.one?out={fmt}": Accept(raw=body)}
                )
                out, self.out = self.out, Capture()
                code = await self.run_cli(mock, "--out", fmt, "x.one")
                self.assertEqual(code, cli.EXIT_OK, self.err.value)
                self.assertEqual(self.out.data, body)
                self.out = out

    @bounded()
    async def test_an_unknown_type_prints_rather_than_killing_the_stream(self):
        """`allow_unparsed=True`: a diagnostic command shows what it received.

        Without it a single unregistered type raises `BlueprintNotFound` and the
        whole answer is lost, including the objects that decoded.
        """
        mock = await self.node(
            routes={
                "x.new": Accept(
                    objects=[u8(7), ("x.unheard_of", b"\x01\x02")], eos=True
                )
            }
        )
        code = await self.run_cli(mock, "x.new")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.out.lines, ["uint8\t7", "x.unheard_of\t\x01\x02"])

    @bounded()
    async def test_an_error_message_goes_to_stderr_and_iteration_continues(self):
        """Design section 6.1: a partial stream still prints.

        The object after the error is the assertion that matters. `__aiter__`
        raises on the first `error_message` and loses it; the CLI uses
        `Stream.raw_objects()`, which does not.
        """
        route = Accept(objects=[u8(1), error("no such repository"), u8(2)], eos=True)
        mock = await self.node(routes={"x.partial": route})
        code = await self.run_cli(mock, "x.partial")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.out.lines, ["uint8\t1", "uint8\t2"])
        self.assertEqual(self.err.lines, ["error: no such repository"])


# --- exit codes ----------------------------------------------------------


class ExitCodeTest(CliCase):
    """All six, each from the fault that produces it."""

    @bounded()
    async def test_zero_when_the_query_answers(self):
        mock = await self.node(routes={"x.ok": Accept(objects=[u8(1)], eos=True)})
        self.assertEqual(await self.run_cli(mock, "x.ok"), 0)

    @bounded()
    async def test_one_when_an_error_message_arrives(self):
        mock = await self.node(routes={"x.err": Accept(objects=[error("nope")])})
        self.assertEqual(await self.run_cli(mock, "x.err"), 1)
        self.assertIn("error: nope", self.err.value)

    @bounded()
    async def test_one_when_the_connect_fails(self):
        code = await self.run_argv(
            ["--endpoint", "unix:/nonexistent/astral-cli-test.sock", "x.op"]
        )
        self.assertEqual(code, 1)
        self.assertTrue(self.err.value.startswith("connect failed: "), self.err.value)

    @bounded()
    async def test_one_when_the_route_is_not_found(self):
        """An `AstralError` with no `error_message` in it. Section 6.1's middle case."""
        mock = await self.node()
        self.assertEqual(await self.run_cli(mock, "x.absent"), 1)
        self.assertIn("RouteNotFound", self.err.value)

    @bounded()
    async def test_one_when_the_deadline_expires(self):
        """`--timeout` bounds the whole command, not merely the route.

        `Hang` accepts nothing and answers nothing, which is what a node with all
        32 apphost workers held looks like from outside.
        """
        mock = await self.node(routes={"x.wedged": Hang()})
        self.assertEqual(await self.run_cli(mock, "x.wedged", timeout="0.3"), 1)

    @bounded()
    async def test_two_when_no_operation_is_given(self):
        self.assertEqual(await self.run_argv([]), 2)
        self.assertIn("no operation given", self.err.value)

    @bounded()
    async def test_two_on_an_unknown_global_option(self):
        self.assertEqual(await self.run_argv(["--nonsense", "x.op"]), 2)

    @bounded()
    async def test_two_on_an_output_format_the_node_would_accept_in_silence(self):
        """astral-docs bug D-24: an unknown `out=` yields zero bytes and no error.

        Validation is therefore client-side and happens before anything is
        dialed, which is what makes this a usage fault rather than an empty
        answer.
        """
        self.assertEqual(await self.run_argv(["--out", "yaml", "x.op"]), 2)
        self.assertIn("unknown channel format", self.err.value)

    @bounded()
    async def test_two_on_an_output_only_format_in_an_input_position(self):
        self.assertEqual(await self.run_argv(["--in", "base64", "x.op"]), 2)
        self.assertIn("output-only", self.err.value)

    @bounded()
    async def test_two_on_a_zone_string_that_would_route_nowhere(self):
        """`Zone.parse` drops an unknown letter in silence; a typed flag may not."""
        self.assertEqual(await self.run_argv(["--zone", "xyz", "x.op"]), 2)
        self.assertIn("zone", self.err.value)

    @bounded()
    async def test_two_on_a_typed_parameter_with_no_value(self):
        self.assertEqual(await self.run_argv(["-p", "lonely", "x.op"]), 2)
        self.assertIn("name=value", self.err.value)

    @bounded()
    async def test_two_when_two_flags_name_two_shapes_for_one_stream(self):
        for argv in (
            ["--follow", "--input", "-", "x.op"],
            ["--follow", "objects.read"],
            ["--input", "-", "objects.read"],
        ):
            with self.subTest(argv=argv):
                self.out, self.err = Capture(), Capture()
                self.assertEqual(await self.run_argv(argv), 2)

    @bounded()
    async def test_three_when_the_responder_rejects(self):
        """Design section 6.2: `QueryRejected` is its own code, with the number.

        The legacy printed it through the generic handler and returned 1, so a
        script could not tell "the responder declined" from "the node is down".
        """
        mock = await self.node(routes={"x.no": Reject(code=7)})
        self.assertEqual(await self.run_cli(mock, "x.no"), 3)
        self.assertIn("code 7", self.err.value)

    def test_one_hundred_thirty_on_a_keyboard_interrupt(self):
        """`128 + SIGINT`. Driven through `main`, which owns `asyncio.run`."""

        async def interrupted(argv, *, out, err):  # type: ignore[no-untyped-def]
            raise KeyboardInterrupt

        with mocklib.patch.object(cli, "_amain", interrupted):
            code = cli.main(["x.op"], stdout=self.out.text, stderr=self.err.text)
        self.assertEqual(code, 130)

    def test_one_hundred_forty_one_on_a_closed_pipe(self):
        """`128 + SIGPIPE`: `astral-query dir.filters | head -1`.

        Without the handler CPython reports the closed pipe from its own
        shutdown flush, as `Exception ignored`, after the shell has already read
        the exit code.
        """

        async def piped(argv, *, out, err):  # type: ignore[no-untyped-def]
            raise BrokenPipeError(32, "Broken pipe")

        with mocklib.patch.object(cli, "_amain", piped):
            code = cli.main(["x.op"], stdout=self.out.text, stderr=self.err.text)
        self.assertEqual(code, 141)

    def test_zero_for_help_and_version(self):
        for argv in (["--help"], ["--version"]):
            with self.subTest(argv=argv):
                out = Capture()
                code = cli.main(argv, stdout=out.text, stderr=self.err.text)
                self.assertEqual(code, 0)
                self.assertNotEqual(out.value, "")

    def test_the_six_codes_are_distinct(self):
        codes = [
            cli.EXIT_OK,
            cli.EXIT_ERROR,
            cli.EXIT_USAGE,
            cli.EXIT_REJECTED,
            cli.EXIT_INTERRUPTED,
            cli.EXIT_BROKEN_PIPE,
        ]
        self.assertEqual(len(set(codes)), 6)
        self.assertEqual(codes, [0, 1, 2, 3, 130, 141])


# --- the command line ----------------------------------------------------


class ParseTest(unittest.TestCase):
    """The argument grammar of design section 6.3. No node, no loop."""

    def parse(self, *argv: str) -> Any:
        return cli._parse(list(argv), out=Capture().text, err=Capture().text)

    def refused(self, *argv: str) -> None:
        with self.assertRaises(cli._Exit) as caught:
            self.parse(*argv)
        self.assertEqual(caught.exception.status, cli.EXIT_USAGE)

    def test_free_form_pairs_become_parameters(self):
        command = self.parse("dir.resolve", "-name", "alice")
        self.assertEqual(command.operation, "dir.resolve")
        self.assertEqual(command.query_string, "dir.resolve?name=alice")

    def test_one_dash_and_two_dashes_name_the_same_parameter(self):
        self.assertEqual(
            self.parse("x.op", "-k", "v").query_string,
            self.parse("x.op", "--k", "v").query_string,
        )

    def test_the_target_prefix_is_split_off_the_operation(self):
        command = self.parse("alice:dir.filters")
        self.assertEqual(command.operation, "dir.filters")
        self.assertEqual(command.target, "alice")

    def test_an_explicit_target_beats_the_prefix(self):
        command = self.parse("--target", "bob", "alice:dir.filters")
        self.assertEqual(command.target, "bob")

    def test_the_operation_is_the_first_positional_slot_not_the_first_token(self):
        """`-name alice dir.resolve`: `alice` is a value, not the operation."""
        command = self.parse("-name", "alice", "dir.resolve")
        self.assertEqual(command.operation, "dir.resolve")
        self.assertEqual(command.params, {"name": "alice"})

    def test_a_second_positional_is_the_reserved_arg_parameter(self):
        command = self.parse("objects.search", "holiday")
        self.assertEqual(command.params, {"arg": "holiday"})

    def test_a_trailing_key_with_no_value_sets_it_empty(self):
        """`dir.set_alias -alias` removes an alias: `alias=` is not an absent key."""
        self.assertEqual(self.parse("dir.set_alias", "-alias").params, {"alias": ""})

    def test_a_global_option_after_the_operation_is_still_a_global_option(self):
        """The legacy parser swallowed it as a query parameter. Section 6.3."""
        command = self.parse("dir.filters", "--endpoint", "tcp:1.2.3.4:1")
        self.assertEqual(command.endpoint, "tcp:1.2.3.4:1")
        self.assertEqual(command.params, {})

    def test_the_double_dash_terminator_hands_the_rest_over_verbatim(self):
        command = self.parse("x.op", "--", "--endpoint", "not-a-flag")
        self.assertEqual(command.endpoint, None)
        self.assertEqual(command.params, {"endpoint": "not-a-flag"})

    def test_a_typed_parameter_is_reduced_to_the_bare_payload_form(self):
        """A query string never carries a `#[type]` header. `querystring.py`."""
        command = self.parse("x.op", "-p", "n=#[uint8] 21")
        self.assertEqual(command.params, {"n": "21"})

    def test_a_typed_parameter_settles_a_key_the_free_form_pass_also_set(self):
        command = self.parse("x.op", "-n", "1", "-p", "n=#[uint8] 21")
        self.assertEqual(command.params, {"n": "21"})

    def test_the_query_string_sorts_its_keys(self):
        """Byte-for-byte reproducibility against the reference client."""
        self.assertEqual(
            self.parse("x.op", "-z", "1", "-a", "2").query_string, "x.op?a=2&z=1"
        )

    def test_a_value_is_escaped_the_way_go_escapes_it(self):
        self.assertEqual(
            self.parse("dir.resolve", "-name", "a b&c").query_string,
            "dir.resolve?name=a+b%26c",
        )

    def test_zone_and_filters_parse_to_their_types(self):
        command = self.parse("--zone", "dv", "--filters", "one,two", "x.op")
        self.assertEqual(int(command.zone), 3)
        self.assertEqual(command.filters, ["one", "two"])

    def test_follow_adds_the_argument_that_makes_the_op_follow(self):
        """The reader and the argument are one request.

        With only the reader the node answers an ordinary snapshot, the boundary
        is printed at its terminating `eos`, and the command exits 0 having
        followed nothing -- observed against `objects.scan` on `furry-bolt`.
        """
        command = self.parse("--follow", "objects.scan", "-repo", "main")
        self.assertEqual(command.query_string, "objects.scan?follow=true&repo=main")

    def test_an_explicit_follow_value_wins_over_the_flag(self):
        command = self.parse("--follow", "x.op", "-follow", "false")
        self.assertEqual(command.query_string, "x.op?follow=false")

    def test_objects_read_is_the_only_operation_declared_raw(self):
        self.assertTrue(self.parse("objects.read", "-id", "x").raw)
        self.assertFalse(self.parse("objects.scan").raw)

    def test_a_query_string_the_wire_cannot_carry_is_refused_before_the_dial(self):
        """`route_query_msg.Query` is a `string16`, so 65 535 bytes is the limit."""
        self.refused("x.op", "-big", "x" * 70000)

    def test_the_advisory_length_warns_and_still_builds(self):
        """255 bytes is documented policy, not a wire limit. `querystring.py`."""
        with self.assertWarns(UserWarning):
            command = self.parse("x.op", "-big", "y" * 300)
        self.assertTrue(command.query_string.startswith("x.op?big=yyy"))

    def test_stdin_is_read_for_a_single_dash(self):
        with mocklib.patch.object(sys, "stdin", io.StringIO("#[uint8] 5\n")):
            objects = cli._read_objects("-")
        self.assertEqual([int(obj) for obj in objects], [5])

    def test_usage_faults(self):
        for argv in ([], ["--zone", "q", "x.op"], ["--out", "nope", "x.op"]):
            with self.subTest(argv=argv):
                self.refused(*argv)


# --- what reaches the node -----------------------------------------------


class QueryTest(CliCase):
    """The query the node receives, and the routing fields around it."""

    @bounded()
    async def test_the_query_string_is_what_the_parameters_build(self):
        mock = await self.node(
            routes={"dir.resolve?name=alice": Accept(objects=[IDENTITY_FRAME])}
        )
        code = await self.run_cli(mock, "dir.resolve", "-name", "alice")
        self.assertEqual(code, 0)
        self.assertEqual(mock.queries[-1].query, "dir.resolve?name=alice")

    @bounded()
    async def test_zone_and_filters_reach_the_route_query(self):
        mock = await self.node(routes={"x.op": Accept(objects=[u8(1)], eos=True)})
        code = await self.run_cli(
            mock, "--zone", "dv", "--filters", "one,two", "x.op"
        )
        self.assertEqual(code, 0)
        query = mock.queries[-1]
        self.assertEqual(query.zone, 3)
        self.assertEqual(query.filters, ("one", "two"))

    @bounded()
    async def test_a_named_target_is_resolved_before_the_query(self):
        """Design section 6.1: the apphost `Target` field is an identity.

        A name never travels, so `alice:x.op` costs one `dir.resolve` first and
        the second query carries the identity that answered.
        """
        mock = await self.node(
            routes={
                "dir.resolve?name=alice": Accept(objects=[IDENTITY_FRAME]),
                "x.op": Accept(objects=[u8(1)], eos=True),
            }
        )
        code = await self.run_cli(mock, "alice:x.op")
        self.assertEqual(code, 0)
        self.assertEqual([q.op for q in mock.queries], ["dir.resolve", "x.op"])
        self.assertEqual(mock.queries[-1].target, FURRY_BOLT)

    @bounded()
    async def test_a_hex_target_is_parsed_locally(self):
        mock = await self.node(routes={"x.op": Accept(objects=[u8(1)], eos=True)})
        code = await self.run_cli(mock, "--target", IDENTITY_HEX, "x.op")
        self.assertEqual(code, 0)
        self.assertEqual([q.op for q in mock.queries], ["x.op"])
        self.assertEqual(mock.queries[-1].target, FURRY_BOLT)

    @bounded()
    async def test_a_named_caller_is_resolved_too(self):
        mock = await self.node(
            routes={
                "dir.resolve?name=alice": Accept(objects=[IDENTITY_FRAME]),
                "x.op": Accept(objects=[u8(1)], eos=True),
            }
        )
        code = await self.run_cli(mock, "--caller", "alice", "x.op")
        self.assertEqual(code, 0)
        self.assertEqual(mock.queries[-1].caller, FURRY_BOLT)

    @bounded()
    async def test_the_channel_formats_are_written_into_the_query_string(self):
        """The node's encoder is chosen by the query string and by nothing else."""
        mock = await self.node(routes={"x.op": Accept(raw=b"")})
        # `objects.read` is the RAW op, and a raw stream frames nothing, so a
        # format this SDK cannot yet decode is still a format it can ask for.
        await self.run_cli(mock, "--out", "text", "objects.read", "-id", "x")
        self.assertIn("out=text", mock.queries[-1].query)

    @bounded()
    async def test_the_command_leaves_no_connection_open_at_the_node(self):
        """Measured at the node, which is where the 32 workers are.

        Two connections and no more: `connect()` reads the greeting and closes,
        then the query opens its own. A command that left either open would burn
        one worker until astrald restarted (bug G-13, design section 3.9).
        """
        mock = await self.node(routes={"x.op": Accept(objects=[u8(1)], eos=True)})
        self.assertEqual(await self.run_cli(mock, "x.op"), 0)
        self.assertTrue(await until(lambda: mock.live == 0), f"{mock.live} left open")
        self.assertEqual(mock.conn_count, 2)

    @bounded()
    async def test_every_module_namespace_reaches_the_node_untouched(self):
        """No op table, no whitelist, and no gate on the raw query surface.

        Every module in `astral.api` that declares ops is walked rather than
        listed, so a module added later is covered without editing this file.
        `nodes` and `nat` are Tier 3 and their **module clients** refuse without
        `experimental=True`; this command is the raw query surface, exactly as
        `Client.query` is, and it gates nothing.
        """
        modules = api_walk.op_modules()
        self.assertIn("nodes", modules)
        self.assertIn("user", modules)
        ops = [f"{name}.probe_op" for name in modules]
        mock = await self.node(
            default_route=Accept(objects=[u8(1)], eos=True)
        )
        for op in ops:
            with self.subTest(op=op):
                self.assertEqual(await self.run_cli(mock, op), 0)
        self.assertEqual([q.query for q in mock.queries], ops)


# --- follow, input, and the wire dump ------------------------------------


class FollowTest(CliCase):
    """`--follow`: the snapshot, the boundary, the live updates."""

    @bounded()
    async def test_the_boundary_is_on_stderr_and_the_objects_are_on_stdout(self):
        """Design section 6.2. stdout stays parsable data; the marker is not data.

        The first `eos` of a follow-mode op is the snapshot/live separator and
        not the terminator, so `async for` would stop at it and drop `uint8 2`
        in silence.
        """
        route = Accept(objects=[u8(1)], eos=True, live=[u8(2)])
        mock = await self.node(routes={"x.watch": route})
        code = await self.run_cli(mock, "--follow", "x.watch")
        self.assertEqual(code, 0)
        self.assertEqual(self.out.lines, ["uint8\t1", "uint8\t2"])
        self.assertEqual(self.err.lines, [cli.LIVE_SEPARATOR])
        self.assertEqual(mock.queries[-1].query, "x.watch?follow=true")

    @bounded()
    async def test_the_boundary_is_printed_even_with_an_empty_snapshot(self):
        route = Accept(objects=[], eos=True, live=[u8(9)])
        mock = await self.node(routes={"x.watch": route})
        self.assertEqual(await self.run_cli(mock, "--follow", "x.watch"), 0)
        self.assertEqual(self.out.lines, ["uint8\t9"])
        self.assertEqual(self.err.lines, [cli.LIVE_SEPARATOR])


class InputTest(CliCase):
    """`--input`: the channel-body ops the legacy CLI could not reach."""

    def write(self, text: str) -> str:
        directory = tempfile.mkdtemp()
        path = Path(directory) / "input.txt"
        path.write_text(text, encoding="utf-8")
        self.addCleanup(lambda: (path.unlink(missing_ok=True), os.rmdir(directory)))
        return str(path)

    @bounded()
    async def test_each_line_is_one_text_encoded_object_terminated_by_eos(self):
        """`Accept(echo=True)` runs astrald's own echo shape: one answer per input."""
        path = self.write("#[uint8] 21\n\n#[string8] hi\n")
        mock = await self.node(routes={"objects.echo": Accept(echo=True)})
        code = await self.run_cli(mock, "--input", path, "objects.echo")
        self.assertEqual(code, 0)
        self.assertEqual(self.out.lines, ["uint8\t21", "string8\thi"])

    @bounded()
    async def test_a_malformed_line_costs_no_connection(self):
        """Parsed before the dial: a typo must not spend one of 32 node workers."""
        path = self.write("not a text-encoded object\n")
        mock = await self.node(routes={"x.op": Accept(objects=[u8(1)], eos=True)})
        code = await self.run_cli(mock, "--input", path, "x.op")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(mock.conn_count, 0)

    @bounded()
    async def test_a_missing_file_costs_no_connection(self):
        mock = await self.node()
        code = await self.run_cli(mock, "--input", "/nonexistent/input.txt", "x.op")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(mock.conn_count, 0)


class DumpWireTest(CliCase):
    """`--dump-wire`: the replacement for a hand-rolled framing diagnostic."""

    @bounded()
    async def test_both_directions_are_hex_dumped_to_stderr(self):
        mock = await self.node(routes={"x.op": Accept(objects=[u8(1)], eos=True)})
        code = await self.run_cli(mock, "--dump-wire", "x.op")
        self.assertEqual(code, 0)
        dump = self.err.value
        self.assertIn(f"{cli._WireDump.SENT} ", dump)
        self.assertIn(f"{cli._WireDump.RECEIVED} ", dump)
        # The greeting's own bytes, read through the decorator rather than
        # reconstructed by it: the type tag of `mod.apphost.host_info_msg`.
        self.assertIn("mod.apphost.host_info_msg".encode().hex(" "), dump)
        # The dump is a decorator, not a replacement: the query still ran.
        self.assertEqual(self.out.lines, ["uint8\t1"])


# --- the entry points ----------------------------------------------------


class EntryPointTest(unittest.TestCase):
    """`python -m astral` and the console script name one callable.

    Run as a subprocess because that is the only way to exercise
    `astral/__main__.py`: importing it runs nothing, and `runpy` in-process
    would share this interpreter's `sys.stdout`.
    """

    def run_module(self, *argv: str) -> subprocess.CompletedProcess:
        source = str(Path(astral.__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=source)
        return subprocess.run(
            [sys.executable, "-m", "astral", *argv],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )

    def test_python_m_astral_reports_the_version(self):
        done = self.run_module("--version")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), f"astral-query {astral.__version__}")

    def test_a_closed_stdout_exits_141_and_prints_no_interpreter_noise(self):
        """The real `| head` path, end to end and in a real process.

        The read end is closed before the command runs, so the first flush to
        stdout raises `BrokenPipeError` in a process that owns its own
        `sys.stdout`. stderr must stay empty: without `_silence_broken_pipe`
        CPython reports the same pipe again from its shutdown flush, as
        `Exception ignored`, after the shell has read the exit code.
        """
        source = str(Path(astral.__file__).resolve().parent.parent)
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            done = subprocess.run(
                [sys.executable, "-m", "astral", "--version"],
                stdout=write_fd,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                env=dict(os.environ, PYTHONPATH=source),
            )
        finally:
            os.close(write_fd)
        self.assertEqual(done.returncode, cli.EXIT_BROKEN_PIPE)
        self.assertEqual(done.stderr, "")

    def test_python_m_astral_reports_usage_with_no_operation(self):
        done = self.run_module()
        self.assertEqual(done.returncode, cli.EXIT_USAGE)
        self.assertIn("usage: astral-query", done.stderr)

    def test_the_console_script_target_is_this_module(self):
        import tomllib

        pyproject = Path(astral.__file__).resolve().parents[2] / "pyproject.toml"
        scripts = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
            "scripts"
        ]
        self.assertEqual(scripts, {"astral-query": "astral.cli:main"})
        self.assertIs(cli.main, getattr(cli, "main"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
