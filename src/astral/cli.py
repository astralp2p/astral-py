"""`astral-query`: the query surface of the protocol, as a command.

    astral-query [global options] [target:]<operation> [-param value ...] [-- raw args]

Design section 6. The CLI is the only human-facing surface of this SDK and
scripts parse its output, so this module changes none of the behaviours section
6.1 fixes verbatim: the `target:operation` prefix and its `dir.resolve`
resolution, free-form `-param value` pairs, the `objects.read` raw passthrough,
the default `type<TAB>value` line, the `--json` envelope, `error_message`
objects on stderr with iteration continuing, and the endpoint and token
precedence of design section 3.3.

**Every op is reachable and none is enumerated.** The operand is a query string,
not a name from a table: `astral-query objects.scan -repo main` and
`astral-query some.module.op -k v` take the same path, so an op no module client
wraps and an op no version of this SDK has heard of both work. The module
clients are reached the same way -- `astral-query nodes.links` sends the query
`nodes.links`, exactly as `Client.query` does -- and that is deliberate. The
Tier 3 gate of design section 0.1 is a **module-client** gate:
`client.nodes.links()` refuses without `experimental=True` because an attribute
typo must not reach an op that drops a live link, and
`client.call_one("nodes.links")` is ungated because a caller who typed the op
name meant it. This command is the second of those, so it gates nothing.

Two consequences of driving arbitrary query strings, both settled here:

- **`allow_unparsed=True`.** A type this SDK does not know decodes to
  `UnparsedObject` and prints, rather than raising `BlueprintNotFound` and
  losing the whole stream. The legacy SDK had the same property by accident --
  an unregistered structured type came back as raw bytes -- and a diagnostic
  command that cannot show an unknown answer is not one.
- **`--in`/`--out` are validated client-side.** The node silently accepts an
  unknown `out=` and then produces zero bytes (astral-docs bug D-24), so an
  unusable format is refused as usage before anything is dialed.

**Exit codes**, six, each a distinct fact a script can branch on:

| Code | Meaning |
|---|---|
| 0 | The query ran and no `error_message` arrived |
| 1 | Connect failure, any `AstralError`, or any `error_message` seen |
| 2 | Usage: an unparsable command line, or no operation |
| 3 | `QueryRejected`, with the responder's numeric code on stderr |
| 130 | `KeyboardInterrupt`, the shell's `128 + SIGINT` |
| 141 | `BrokenPipeError`, the shell's `128 + SIGPIPE` |

0, 1, 2 are section 6.1's and 3 is section 6.2's. 130 is section 6.3's. 141 is
the same convention as 130 and covers the commonest pipeline of all,
`astral-query dir.filters | head -1`: without it CPython reports the closed
pipe as `Exception ignored` from the interpreter's own flush, after the shell
has already moved on.

**One `asyncio.run`, one `async with` on the client** (design section 6.3).
`max_concurrency=1` because the command issues one query plus at most the two
`dir.resolve` calls a named `--target` and a named `--caller` cost, and
`KeyboardInterrupt` unwinds through the `async with`, so Ctrl-C closes the
connection rather than leaving one of astrald's 32 apphost workers held.

**Argument parsing is fixed.** `argparse` with `allow_abbrev=False` for the
global options, `parse_known_args`, then one manual pass over the remainder for
the `-param value` pairs. The legacy hand-rolled parser mis-parsed `--endpoint`
appearing *after* the operation and swallowed it as a query parameter; here the
global options are position-independent because argparse reads them wherever
they are.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import json
import os
import sys
from typing import Any, Final, Iterable, NoReturn, Sequence, TextIO

from . import __version__, querystring
from .channel import parse_format
from .client import Client, connect, resolve_endpoint, resolve_token
from .codec import text as textcodec
from .codec.jsoncodec import envelope
from .errors import AstralError, ParseError, QueryRejected, QueryTimeout, ValueTooLarge
from .object import UnparsedObject
from .session import CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, Session
from .stream import Stream
from .transport import Transport, dial
from .types import Zone

__all__ = [
    "EXIT_BROKEN_PIPE",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_REJECTED",
    "EXIT_USAGE",
    "FOLLOW_PARAM",
    "LIVE_SEPARATOR",
    "OP_READ",
    "PROGRAM",
    "UNTYPED",
    "main",
]

PROGRAM: Final = "astral-query"

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1
EXIT_USAGE: Final = 2
EXIT_REJECTED: Final = 3
EXIT_INTERRUPTED: Final = 130
EXIT_BROKEN_PIPE: Final = 141

OP_READ: Final = "objects.read"
"""The one RAW op (design section 4.7). Its body is a stored file, not objects."""

UNREADABLE_FORMATS: Final = frozenset({"base64", "render"})
"""The two `--out` spellings no receiver parses, so the CLI writes them out raw.

astral-go's `newReceiver` has a case for neither, and a rendering is resolved
through astrald's own view registry -- `apphost.whoami?out=render` answers a
coloured alias where the object is an identity -- so there is nothing to decode
it into. `Client` refuses either on a framed stream and says so; here the body is
written unaltered, which is what `--help` has always advertised these for."""

FOLLOW_PARAM: Final = "follow"
"""The query argument that makes an ST op send a snapshot/live separator."""

UNTYPED: Final = "<untyped>"
"""What the default line prints for an object with no type. Section 6.1."""

LIVE_SEPARATOR: Final = "--- live ---"
"""The `--follow` snapshot/live boundary, written to stderr so stdout stays data."""

_ZONE_LETTERS: Final = frozenset("dvn")

_ERROR_TYPE: Final = "error_message"
"""Matched by type name and not by class, exactly as `Stream` matches it, so a
record decoded under that name from a runtime blueprint reads as an error too."""


# --- the command line ----------------------------------------------------


class _Exit(Exception):
    """A parse that is over: a usage fault, `--help`, or `--version`.

    `argparse` calls `sys.exit()` for all three. A command whose exit code is a
    return value cannot have its parser leave through the interpreter, so the
    parser below raises this instead and `_amain` turns it back into a code.
    """

    __slots__ = ("status",)

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    """An `ArgumentParser` that writes to this command's streams and never exits.

    Both overrides exist for the same reason: `main(argv, stdout=…, stderr=…)`
    promises that everything the command emits reaches the streams it was given,
    and stock `argparse` writes to `sys.stdout` / `sys.stderr` directly and then
    calls `sys.exit`. A golden test over `--help` or a usage fault would
    otherwise assert on nothing.
    """

    def __init__(self, *args: Any, out: TextIO, err: TextIO, **kw: Any) -> None:
        super().__init__(*args, **kw)
        self._out = out
        self._err = err

    def _print_message(self, message: str, file: Any = None) -> None:
        if not message:
            return
        # `argparse` names the destination by passing `sys.stderr` explicitly and
        # leaves `None` for everything it considers an error too, so anything not
        # positively stdout is stderr.
        stream = self._out if file is sys.stdout else self._err
        stream.write(message)
        stream.flush()

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self._print_message(message, sys.stderr)
        raise _Exit(status)

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _format_in(token: str) -> str:
    """Validate an `--in` token client-side. Output-only formats are refused."""
    try:
        parse_format(token, output=False)
    except ParseError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return token


def _format_out(token: str) -> str:
    """Validate an `--out` token client-side.

    The node accepts an unknown `out=` in silence and then writes zero bytes
    (astral-docs bug D-24), so a typo here is otherwise an empty answer with no
    error anywhere.
    """
    try:
        parse_format(token, output=True)
    except ParseError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return token


def _zone(token: str) -> Zone:
    """Validate a zone string, then parse it.

    `Zone.parse` drops an unrecognised letter in silence, matching
    `astral.Zones`, so `--zone dnv` and `--zone xyz` would both parse and the
    second would route nowhere with nothing said. A flag a human types is
    checked first.
    """
    unknown = sorted(set(token) - _ZONE_LETTERS)
    if unknown or not token:
        raise argparse.ArgumentTypeError(
            f"zone {token!r}: expected some of d (device), v (virtual), "
            f"n (network) -- e.g. dvn"
        )
    return Zone.parse(token)


def _filters(token: str) -> list[str]:
    """`a,b,c` to a filter list. A comma is the separator and never a name."""
    return [name for name in token.split(",") if name]


def _build_parser(*, out: TextIO, err: TextIO) -> _Parser:
    # `color=False` from 3.14, where `argparse` colourises help and usage by
    # default. It decides from the process's own `sys.stdout`, not from the
    # stream this parser was handed, so a caller capturing output would collect
    # ANSI escapes it never asked for -- and scripts parse this command's output.
    colour: dict[str, Any] = {"color": False} if sys.version_info >= (3, 14) else {}
    parser = _Parser(
        prog=PROGRAM,
        usage=(
            f"{PROGRAM} [global options] [target:]<operation> "
            "[-param value ...] [-- raw args]"
        ),
        description="Route one query to an astrald node and print its answer.",
        allow_abbrev=False,
        add_help=True,
        out=out,
        err=err,
        **colour,
    )
    parser.add_argument("--endpoint", metavar="URL", help="node endpoint to dial")
    parser.add_argument("--token", metavar="TOKEN", help="apphost auth token")
    parser.add_argument(
        "--target", metavar="ID", help="target identity, alias or 66-hex key"
    )
    parser.add_argument(
        "--caller", metavar="ID", help="identity to route as, alias or 66-hex key"
    )
    parser.add_argument(
        "--zone", type=_zone, metavar="dvn", help="routing zones to traverse"
    )
    parser.add_argument(
        "--filters", type=_filters, metavar="a,b", help="identity filters for the hop"
    )
    parser.add_argument(
        "--in",
        dest="fmt_in",
        default="",
        type=_format_in,
        metavar="FMT",
        help="channel format this side writes: bin|json|text|canonical",
    )
    parser.add_argument(
        "--out",
        dest="fmt_out",
        default="",
        type=_format_out,
        metavar="FMT",
        help="channel format the node writes: bin|json|text|canonical|base64|render",
    )
    parser.add_argument(
        "--timeout", type=float, metavar="SECS", help="deadline for the whole query"
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help=(
            f"add follow=true, print the snapshot, then {LIVE_SEPARATOR!r} on "
            "stderr, then live updates"
        ),
    )
    parser.add_argument(
        "--input",
        metavar="FILE",
        help="channel-body input: one text-encoded object per line, - for stdin",
    )
    parser.add_argument(
        "-p",
        "--param",
        action="append",
        default=[],
        metavar="name=#[type]value",
        help="a typed parameter, in the full text encoding",
    )
    parser.add_argument(
        "--json", action="store_true", help="one JSON envelope per line"
    )
    parser.add_argument(
        "--dump-wire",
        action="store_true",
        help="hex-dump every byte read and written, to stderr",
    )
    parser.add_argument(
        "--version", action="version", version=f"{PROGRAM} {__version__}"
    )
    return parser


def _split_terminator(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split at the first `--`. Everything after it is raw argument text.

    Done before `argparse` rather than by it, because what `parse_known_args`
    does with a `--` it did not need has changed between CPython releases and
    the terminator is part of this command's documented surface.
    """
    argv = list(argv)
    if "--" not in argv:
        return argv, []
    cut = argv.index("--")
    return argv[:cut], argv[cut + 1 :]


def _split_operation(tokens: Sequence[str]) -> tuple[str | None, list[str]]:
    """Pull the operation out of the free-form remainder.

    The operation is the first token in a **positional** slot: a `-key` consumes
    the token after it, so `-name alice dir.resolve` names the op `dir.resolve`
    and not `alice`. That pairing rule is `querystring.args_to_params`, which
    encodes what is left; this walk knows only enough of it to find the
    positional slots, and the two must not diverge.
    """
    rest: list[str] = []
    op: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            if op is None:
                op = token
            else:
                # A second positional is the reserved `arg` parameter, which is
                # what `args_to_params` makes of it.
                rest.append(token)
            index += 1
            continue
        rest.append(token)
        if index + 1 < len(tokens):
            rest.append(tokens[index + 1])
        index += 2
    return op, rest


def _typed_params(pairs: Iterable[str]) -> dict[str, str]:
    """`-p name=#[uint8]21` to `{"name": "21"}`.

    A query string carries the bare payload half of the text encoding and never
    a `#[type]` header, so a tagged value is decoded and re-rendered by
    `querystring.bare_param`. An untagged value passes through untouched.
    """
    params: dict[str, str] = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise ParseError(f"-p {pair!r}: expected name=value")
        params[name] = querystring.bare_param(value)
    return params


@dataclasses.dataclass(slots=True, kw_only=True)
class _Command:
    """One parsed command line: what to send, where, and how to print it.

    Keyword-only and complete: a field the parser forgot to fill is a
    `TypeError` here rather than a `None` that reaches the node as a dropped
    flag.
    """

    operation: str
    params: dict[str, str]
    query_string: str
    """Built once, in `_parse`, so an over-long one is a usage fault and the
    255-byte advisory warning is issued once rather than per access."""
    target: str | None
    caller: str | None
    zone: Zone | None
    filters: list[str] | None
    fmt_in: str
    fmt_out: str
    timeout: float | None
    follow: bool
    input_path: str | None
    as_json: bool
    endpoint: str | None
    token: str | None
    dump_wire: bool
    inputs: list[Any] | None = None
    """The `--input` objects, read by `_amain` once the line has parsed."""

    @property
    def raw(self) -> bool:
        """Whether the body is bytes to be written out rather than objects.

        Two cases, and they are the same case from the caller's side. `objects.
        read` is the one RAW op of design section 4.7: its body is a stored file.
        `--out base64` and `--out render` are the two output-only spellings --
        the node writes them and no receiver anywhere parses them back -- so the
        only honest thing to do with either is to hand the bytes over, which is
        what a human asking for a rendering wanted in the first place.
        """
        return self.operation == OP_READ or self.fmt_out in UNREADABLE_FORMATS


def _parse(argv: Sequence[str], *, out: TextIO, err: TextIO) -> _Command:
    """The whole command line. Raises `_Exit` for usage, `--help` and `--version`."""
    parser = _build_parser(out=out, err=err)
    head, tail = _split_terminator(argv)
    args, extra = parser.parse_known_args(head)

    operation, rest = _split_operation(list(extra) + tail)
    if operation is None:
        parser.error("no operation given")

    target = args.target
    if ":" in operation:
        # `alice:dir.filters`. An explicit --target wins (design section 6.1).
        prefix, _, operation = operation.partition(":")
        if target is None:
            target = prefix

    params = querystring.args_to_params(rest)
    try:
        # Applied last: `-p` is the form that states a type, so it settles a key
        # the free-form pass also set.
        params.update(_typed_params(args.param))
    except ParseError as exc:
        parser.error(str(exc))

    if args.follow:
        # `--follow` is two things at once and both are required: the reader that
        # crosses the snapshot/live separator, and the `follow=true` argument
        # that makes the op send one. Set only the reader and a node answers an
        # ordinary snapshot, `snapshot()` stops at its terminating `eos`, the
        # boundary is printed, `live()` meets EOF and the command exits 0 having
        # followed nothing -- verified against `objects.scan` on `furry-bolt`.
        # Injected only when the caller left the key unset, so `-follow false`
        # still wins.
        params.setdefault(FOLLOW_PARAM, "true")

    # Three combinations name two shapes for one stream, and each would drop a
    # flag the caller typed. A dropped flag is a wrong answer with nothing said.
    if args.follow and args.input is not None:
        parser.error("--follow and --input: a follow-mode op takes no body input")
    if operation == OP_READ and args.follow:
        parser.error(f"--follow and {OP_READ}: a raw body carries no objects")
    if operation == OP_READ and args.input is not None:
        parser.error(f"--input and {OP_READ}: a raw body carries no objects")
    if args.fmt_out in UNREADABLE_FORMATS and args.follow:
        # The same rule as `objects.read`'s, for the same reason: a body nothing
        # parses has no objects, so it has no snapshot/live separator either.
        parser.error(
            f"--follow and --out {args.fmt_out}: nothing parses that format back, "
            "so the body is bytes and carries no objects"
        )

    try:
        query_string = querystring.build(operation, params)
    except ValueTooLarge as exc:
        # `route_query_msg.Query` is a `string16`. Refused here, before a
        # connection is spent on a query the wire cannot carry.
        parser.error(str(exc))

    return _Command(
        operation=operation,
        params=params,
        query_string=query_string,
        target=target,
        caller=args.caller,
        zone=args.zone,
        filters=args.filters,
        fmt_in=args.fmt_in,
        fmt_out=args.fmt_out,
        timeout=args.timeout,
        follow=args.follow,
        input_path=args.input,
        as_json=args.json,
        endpoint=args.endpoint,
        token=args.token,
        dump_wire=args.dump_wire,
    )


def _read_objects(path: str) -> list[Any]:
    """Channel-body input: one text-encoded object per line, blank lines skipped.

    Read whole and parsed **before** anything is dialed, so a typo in the input
    file costs no connection and no node worker. `-` is stdin, which is why this
    is synchronous: the read happens with nothing else running on the loop.
    """
    if path == "-":
        source = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    return [
        textcodec.decode_line(line) for line in source.splitlines() if line.strip()
    ]


# --- output --------------------------------------------------------------


def _display(obj: Any) -> str:
    """One object's value half of the default `type<TAB>value` line.

    Three rules, in this order, and the order is the point:

    1. **An untyped object is bytes and prints as utf-8 with `errors="replace"`.**
       Section 6.1 preserves this verbatim, and it is what makes a stored text
       file or a hand-written blob readable. `Blob` also has a text form --
       base64 -- so the bytes rule has to come first or nothing would ever reach
       it.
    2. **A typed object prints its text form** when it has one, which is the
       protocol's own rendering and is the exact form `-p name=#[type]value`
       reads back.
    3. Anything else prints `str()`, which for a record is its dataclass repr.

    The decoding is for display only. Nothing here is re-encoded.
    """
    if isinstance(obj, UnparsedObject):
        # A type the registry does not know. Its payload is bytes and is shown
        # the way rule 1 shows bytes.
        return _text_bytes(obj.payload)
    type_name = getattr(obj, "ASTRAL_TYPE", "")
    if isinstance(obj, (bytes, bytearray)) and not type_name:
        return _text_bytes(bytes(obj))
    try:
        return textcodec.to_text(obj)
    except AstralError:
        pass
    if isinstance(obj, (bytes, bytearray)):
        return _text_bytes(bytes(obj))
    return str(obj)


def _text_bytes(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _line(obj: Any, *, as_json: bool) -> str:
    """One output line for one object."""
    if not as_json:
        return f"{getattr(obj, 'ASTRAL_TYPE', '') or UNTYPED}\t{_display(obj)}"
    try:
        return json.dumps(envelope(obj))
    except AstralError:
        # A type with no JSON form still has a type name and a payload, and a
        # `--json` reader that got no line at all for it would silently see a
        # shorter stream. The legacy CLI hex-encoded the same fallback.
        value = obj.payload.hex() if isinstance(obj, UnparsedObject) else None
        if value is None:
            value = obj.hex() if isinstance(obj, (bytes, bytearray)) else str(obj)
        return json.dumps({"Type": getattr(obj, "ASTRAL_TYPE", ""), "Object": value})


def _emit(obj: Any, *, stream: TextIO, as_json: bool) -> None:
    print(_line(obj, as_json=as_json), file=stream, flush=True)


def _write_bytes(stream: TextIO, data: bytes) -> None:
    """The RAW body, unaltered, onto the byte side of a text stream.

    `sys.stdout.buffer` is what section 6.1 names, and a stored file is not text:
    encoding it would corrupt every non-UTF-8 byte in it. A stream with no
    `buffer` -- a `StringIO` -- gets the display decoding instead, which is the
    only thing it can carry.
    """
    stream.flush()
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(_text_bytes(data))
        stream.flush()
        return
    buffer.write(data)
    buffer.flush()


# --- the wire dump -------------------------------------------------------


class _WireDump(Transport):
    """A `Transport` decorator that hex-dumps every byte in both directions.

    `--dump-wire`, and the replacement for the standalone
    `examples/dump_handshake.py` of the legacy SDK, which opened its own socket
    and re-implemented the frame layout by hand -- so it could agree with itself
    and disagree with the SDK. This one sits under the real session, so what it
    prints is what the protocol sent.

    Buffering rule 1 of `transport/base.py` holds: this decorator adds no buffer.
    Every read is forwarded and its result is reported, never withheld.
    """

    __slots__ = ("_inner", "_sink")

    SENT: Final = "->"
    RECEIVED: Final = "<-"

    def __init__(self, inner: Transport, sink: TextIO) -> None:
        self._inner = inner
        self._sink = sink

    def _dump(self, direction: str, data: bytes) -> None:
        if not data:
            return
        print(
            f"{direction} {len(data)} bytes: {data.hex(' ')}",
            file=self._sink,
            flush=True,
        )

    @property
    def endpoint(self) -> str:
        return self._inner.endpoint

    @property
    def closed(self) -> bool:
        return self._inner.closed

    async def readexactly(self, n: int) -> bytes:
        data = await self._inner.readexactly(n)
        self._dump(self.RECEIVED, data)
        return data

    async def read(self, n: int = -1) -> bytes:
        data = await self._inner.read(n)
        self._dump(self.RECEIVED, data)
        return data

    def write(self, data: bytes) -> None:
        self._dump(self.SENT, data)
        self._inner.write(data)

    async def drain(self) -> None:
        await self._inner.drain()

    def write_eof(self) -> None:
        self._inner.write_eof()

    async def aclose(self) -> None:
        await self._inner.aclose()


def _dumping_connector(endpoint: str, token: str | None, sink: TextIO) -> Any:
    """A connector whose transport is hex-dumped.

    `Session.connect` dials internally and has no seam for a decorator, so this
    calls the two halves it is made of: `dial`, which raises `NodeUnavailable`
    for every dial fault, and `Session.over`, which reads the greeting,
    authenticates and closes the transport on every failure path.

    The one divergence from `Session.connect`: `CONNECT_TIMEOUT` bounds the dial
    and the greeting separately here rather than jointly, so a node that both
    connects slowly and greets slowly may take twice as long to fail. That is a
    debug flag's cost and it is bounded either way.
    """

    async def open_session() -> Session:
        transport = await dial(endpoint, timeout=CONNECT_TIMEOUT)
        return await Session.over(
            _WireDump(transport, sink),
            token=token,
            timeout=CONNECT_TIMEOUT,
            handshake_timeout=HANDSHAKE_TIMEOUT,
            endpoint=endpoint,
            connector=open_session,
        )

    return open_session


# --- running the query ---------------------------------------------------


def _query_kw(command: _Command) -> dict[str, Any]:
    """The `Client.query` keywords this command names, and only those.

    `target` and `caller` are omitted rather than passed as `None`, because
    `None` is the nil identity on the wire and the default is the session's own:
    they are different bytes and a flag nobody typed must not choose either.
    """
    kw: dict[str, Any] = {
        "fmt_in": command.fmt_in,
        "fmt_out": command.fmt_out,
        "allow_unparsed": True,
    }
    if command.target is not None:
        kw["target"] = command.target
    if command.zone is not None:
        kw["zone"] = command.zone
    if command.filters is not None:
        kw["filters"] = command.filters
    if command.timeout is not None:
        kw["timeout"] = command.timeout
    return kw


async def _run(command: _Command, client: Client, out: TextIO, err: TextIO) -> int:
    """Route the query and print the answer, inside `--timeout`.

    `--timeout` bounds the **whole** command and not merely the route, which is
    the reason design section 6.2 adds it: a node that accepts a query and then
    says nothing is exactly the wedged state astrald reaches at 32 held workers,
    and `Client.query`'s own deadline ends the moment the stream is usable.
    """
    if command.timeout is None:
        return await _route(command, client, out, err)
    try:
        async with asyncio.timeout(command.timeout):
            return await _route(command, client, out, err)
    except TimeoutError as exc:
        raise QueryTimeout(
            f"{command.query_string}: not finished within {command.timeout}s"
        ) from exc


async def _route(command: _Command, client: Client, out: TextIO, err: TextIO) -> int:
    """Route the query and print the answer. Returns the exit code."""
    kw = _query_kw(command)
    if command.caller is not None:
        # Resolved here rather than passed through, because `Client.query`
        # resolves a named `target` and takes `caller` as an identity only.
        kw["caller"] = await client.resolve_identity(
            command.caller, timeout=command.timeout
        )

    qs = command.query_string

    if command.raw:
        # RAW: the body is a stored file, or a rendering, or base64. No framing,
        # no objects, no exit code but zero -- section 6.1.
        _write_bytes(out, await client.call_raw(qs, **kw))
        return EXIT_OK

    if command.follow:
        return await _run_follow(command, client, qs, kw, out, err)

    async with client.stream(qs, **kw) as stream:
        if command.inputs is not None:
            await _send_inputs(stream, command.inputs)
        return await _drain(stream, command, out, err)


async def _run_follow(
    command: _Command,
    client: Client,
    qs: str,
    kw: dict[str, Any],
    out: TextIO,
    err: TextIO,
) -> int:
    """`--follow`: the snapshot, the boundary on stderr, then the live updates.

    The `follow=true` argument is already in the query string; `_parse` puts it
    there, because the reader and the argument are one request and setting only
    the reader follows nothing.

    `Client.follow` sets the three things ST+follow needs at once -- the
    persistent lane, no deadline, and the separator declaration -- and
    `Stream.snapshot()` / `Stream.live()` are the two readers that see the
    boundary. `async for` would stop at it and drop every update in silence.

    The boundary goes to stderr so that stdout stays parsable data.

    An `error_message` raises here rather than being printed and skipped:
    the separator-aware readers are the only ones that cross the boundary and
    they have no error-tolerant variant. `_amain` reports it and returns 1,
    which is the same code section 6.1 gives an `error_message`.
    """
    async with client.follow(qs, **kw) as stream:
        async for obj in stream.snapshot():
            _emit(obj, stream=out, as_json=command.as_json)
        print(LIVE_SEPARATOR, file=err, flush=True)
        async for obj in stream.live():
            _emit(obj, stream=out, as_json=command.as_json)
    return EXIT_OK


async def _send_inputs(stream: Stream, inputs: Sequence[Any]) -> None:
    """The `--input` body: every object, then `eos`.

    Design section 6.2. This is what unlocks `tree.set`, `crypto.verify_*`,
    `crypto.public_key`, `objects.store/push/create`, `auth.sign_contract` and
    `user.accept_membership` -- the body-input ops of design section 4.7, which
    the legacy CLI could not reach at all. Passing their input as a query
    argument instead is the single most common way to get an op wrong, and on
    `crypto.verify_*` it silently never verifies.

    Batch first, then read: `eos` terminates the input, so the op it names has
    answered nothing until the input is complete and there is nothing to
    interleave with.
    """
    for obj in inputs:
        await stream.send(obj)
    await stream.send_eos()


async def _drain(stream: Stream, command: _Command, out: TextIO, err: TextIO) -> int:
    """Print every object to the terminator. `error_message` sets exit 1.

    `Stream.raw_objects()` and not `async for`: an `error_message` goes to
    stderr and iteration **continues**, so a partial stream still prints
    (section 6.1). `__aiter__` raises on the first one and loses the rest.
    """
    code = EXIT_OK
    async for obj in stream.raw_objects():
        if getattr(obj, "ASTRAL_TYPE", "") == _ERROR_TYPE:
            print(f"error: {obj}", file=err, flush=True)
            code = EXIT_ERROR
            continue
        _emit(obj, stream=out, as_json=command.as_json)
    return code


# --- entry points --------------------------------------------------------


async def _amain(argv: Sequence[str], *, out: TextIO, err: TextIO) -> int:
    """The async core. One client, opened and closed, whatever happens."""
    try:
        command = _parse(argv, out=out, err=err)
    except _Exit as exit_:
        return exit_.status

    if command.input_path is not None:
        # Before the dial: a typo in the input file must cost no connection and
        # no node worker.
        try:
            command.inputs = _read_objects(command.input_path)
        except (OSError, AstralError) as exc:
            print(f"--input {command.input_path}: {exc}", file=err, flush=True)
            return EXIT_ERROR

    endpoint = resolve_endpoint(command.endpoint)
    token = resolve_token(command.token)
    connector = (
        _dumping_connector(endpoint, token, err) if command.dump_wire else None
    )

    try:
        client = await connect(
            endpoint, token=token, connector=connector, max_concurrency=1
        )
    except AstralError as exc:
        print(f"connect failed: {exc}", file=err, flush=True)
        return EXIT_ERROR

    try:
        async with client:
            return await _run(command, client, out, err)
    except QueryRejected as exc:
        print(f"rejected: code {exc.code}: {exc}", file=err, flush=True)
        return EXIT_REJECTED
    except AstralError as exc:
        print(f"{type(exc).__name__}: {exc}", file=err, flush=True)
        return EXIT_ERROR


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run one query. The console script `astral-query` and `python -m astral`.

    One `asyncio.run` at the top and one `async with` on the client inside it
    (design section 6.3), so every exit path -- a clean return, an exception, a
    Ctrl-C -- closes the connection. astrald serves apphost from 32 workers
    shared by every app on the machine and never notices a peer that vanished,
    so a command that leaked its connection would burn one of them until the
    node restarted.

    `stdout` and `stderr` default to the process's own. They are parameters
    because every byte this command emits is part of its contract and a test
    that could not capture them would be asserting on nothing.
    """
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return asyncio.run(_amain(argv, out=out, err=err))
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        _silence_broken_pipe(out)
        return EXIT_BROKEN_PIPE


def _silence_broken_pipe(stream: TextIO) -> None:
    """Point the closed stream at the null device before the interpreter flushes.

    CPython flushes `sys.stdout` during shutdown, after `main` has returned. On a
    pipe the reader closed -- `astral-query dir.filters | head -1` -- that flush
    raises again, outside any handler, and prints `Exception ignored` after the
    shell has already reported the exit code. Redirecting the descriptor is the
    documented remedy. A stream with no descriptor needs none.
    """
    with contextlib.suppress(Exception):
        os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())


if __name__ == "__main__":  # pragma: no cover -- `python -m astral` is the entry
    sys.exit(main())
