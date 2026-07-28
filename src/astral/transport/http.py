"""One-shot HTTP/1.1: the request transport, and the parser the upgrade shares.

The apphost HTTP gateway serves one query per request. The query string is the
request path, the auth token is a bearer credential, the target is a header, and
the response body is the query's object stream in whatever format the query
asked for -- newline-delimited JSON when it asked for `out=json`, which is what
`query()` asks for by default. There is no input streaming and no serving:
`HTTPResponse.write()` raises rather than pretending (design section 3.1).

The module is stdlib-only by decision, not by omission (design section 8.1):
issuing one request and reading a `Content-Length`, `chunked` or read-to-EOF body
over `asyncio` streams is a bounded amount of code and adds nothing to the trust
surface that `http.client` would not also add a synchronous socket to.

`websocket.py` imports the request formatter, the response-head parser and the
URL parser from here, because an RFC 6455 upgrade **is** an HTTP/1.1 request:
one parser, one place, and the WebSocket handshake cannot drift from the query
path's idea of a header.

**Every read goes through the transport and stops at the blank line.** No buffer
sits above it (design section 3.2, rule 1), so the first body byte -- or, for the
upgrade, the first WebSocket frame -- is still in the one buffer underneath when
the head has been parsed. A transport carrying an `asyncio.StreamReader` reads a
line with `readuntil`, which is that same buffer; anything else is read one byte
at a time, which is the same guarantee at a slower constant.

What the node does with a request, verified against `furry-bolt` this session and
sourced from `astrald/mod/apphost/src/http_server.go` and `http_query_handler.go`:

| Request part | Effect |
|---|---|
| path `/<query string>` | the query, `@<alias>/<op>` resolving the target by alias |
| `Authorization: Bearer <token>` | the guest identity. **Mandatory**: an absent or unknown token is 401, and there is no anonymous HTTP guest, unlike IPC and WebSocket |
| `X-Astral-Target: <66 hex>` | the query target; the node itself by default |
| `Accept: application/json` | forces `out=json`, **overwriting** an `out=` the caller wrote |
| `Content-Type: application/json` | forces `in=json`, overwriting an `in=` the caller wrote |

The overwrite is why both headers are conditional here: `Accept` is sent only
when the query string names no `out=`, and `Content-Type` only when it names no
`in=`. Sending them unconditionally is what made `out=text` unreachable over
WebSocket in the legacy SDK (design section 4.5); the same fix applies here.

Status mapping is exhaustive and is the HTTP half of design section 3.4's table:

| Status | Exception |
|---|---|
| 200 | -- |
| 400 | `QueryRejected(2)` -- the node's "invalid query" code |
| 401 | `AuthFailed` |
| 403 | `Denied` -- the per-object read authorization on `/.objects/` |
| 404 | `RouteNotFound` |
| 405 | `QueryRejected(1)` -- astrald's mapping of `ErrRejected` |
| 408, 504 | `QueryTimeout` |
| 3xx | `ProtocolError` -- a redirect is never followed; one request is one request |
| other 4xx | `ProtocolError` |
| 5xx | `InternalError` |
| dial fault | `NodeUnavailable` -- the query was never sent, so a retry is safe |
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import ssl as _ssl
from dataclasses import dataclass
from typing import Final, Iterator, Mapping

from ..errors import (
    AuthFailed,
    BadArgument,
    ConcurrentRead,
    Denied,
    InternalError,
    NodeUnavailable,
    ParseError,
    ProtocolError,
    QueryRejected,
    QueryTimeout,
    RouteNotFound,
    TransportError,
    TransportUnsupported,
)
from ..querystring import parse as parse_query_string
from ..types import Identity, ascii_int
from .base import IncompleteRead, Transport
from .socket import StreamTransport

__all__ = [
    "AUTH_HEADER",
    "DEFAULT_HTTP_PORT",
    "DEFAULT_HTTPS_PORT",
    "GUEST_HEADER",
    "HOST_HEADER",
    "HTTPResponse",
    "Headers",
    "MAX_HEAD_BYTES",
    "ResponseHead",
    "TARGET_HEADER",
    "WebAddress",
    "format_request",
    "open_object",
    "open_web_connection",
    "open_response",
    "parse_web_endpoint",
    "query",
    "raise_for_status",
    "read_response_head",
]

DEFAULT_HTTP_PORT: Final = 8624
"""astrald's default `bind_http`, `tcp:0.0.0.0:8624` (sourced: `config.go:51`)."""

DEFAULT_HTTPS_PORT: Final = 443
"""The node serves no TLS. `https:` and `wss:` reach it through a proxy, where
443 is the port that needs no writing down."""

MAX_HEAD_BYTES: Final = 64 * 1024
"""Cap on a status line plus its headers. A head past this is not a head."""

MAX_HEAD_LINES: Final = 100
MAX_LINE_BYTES: Final = 8 * 1024

ERROR_BODY_PEEK: Final = 512
"""Bytes of a failing response kept for the exception message. A proxy's 502 page
is otherwise invisible, and "HTTP 502" alone does not say which hop refused."""

ERROR_PEEK_TIMEOUT: Final = 1.0
"""How long that peek waits. A courtesy is worth about a second.

`open_response` bounds the dial, the request and the head; the body is
deliberately outside it, because a body is a stream and a stream has no length a
connect timeout could cover. The peek is not a stream -- it is at most 512 bytes
read to improve an exception message -- so it carries its own small bound rather
than inheriting the body's absence of one. Without it a peer that declared an
error body and sent none held the caller for ever, and `http.query`'s own
`timeout` argument, documented as the bound, was not one."""

AUTH_HEADER: Final = "Authorization"
TARGET_HEADER: Final = "X-Astral-Target"
GUEST_HEADER: Final = "X-Astral-Guest-Identity"
HOST_HEADER: Final = "X-Astral-Host-Identity"

_JSON: Final = "application/json"
_WEB_PORTS: Final = {
    "http": DEFAULT_HTTP_PORT,
    "ws": DEFAULT_HTTP_PORT,
    "https": DEFAULT_HTTPS_PORT,
    "wss": DEFAULT_HTTPS_PORT,
}
_TLS_PROTOCOLS: Final = frozenset({"https", "wss"})
_STANDARD_PORTS: Final = {"http": 80, "ws": 80, "https": 443, "wss": 443}
"""The ports the *schemes* default to, which is not what this SDK dials.

`_WEB_PORTS` is where a port-less endpoint connects -- 8624, the node's own.
`_STANDARD_PORTS` is the only port a `Host` header may omit, so an endpoint that
names 8624, or one that defaults to it, still says so to a virtual-host router."""


# --- addresses ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WebAddress:
    """A `ws`, `wss`, `http` or `https` endpoint, resolved to what a dial needs."""

    proto: str
    host: str
    port: int
    path: str

    @property
    def tls(self) -> bool:
        return self.proto in _TLS_PROTOCOLS

    @property
    def authority(self) -> str:
        """The `Host` header: the port, unless it is the scheme's standard one."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == _STANDARD_PORTS[self.proto]:
            return host
        return f"{host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.proto}://{self.authority}{self.path}"


def parse_web_endpoint(endpoint: str, *, default_path: str = "/") -> WebAddress:
    """Split `ws://host:port/path`, or the `proto:addr` form of the same thing.

    The endpoint grammar splits on the first colon (design section 3.3), so
    `ws://127.0.0.1:8624/.ws` arrives as proto `ws` and addr `//127.0.0.1:8624/.ws`.
    The `//` is optional here, so `ws:127.0.0.1:8624/.ws` names the same endpoint.

    The path is taken literally. An endpoint with no path at all gets
    `default_path`; `ws://host/` asks for `/` and gets `/`, because a parser that
    silently rewrote a path the caller wrote would be unpredictable exactly where
    a wrong path is diagnosable -- the node answers 401 on every path but `/.ws`.
    """
    proto, sep, rest = endpoint.partition(":")
    if not sep:
        raise ParseError(f"invalid endpoint {endpoint!r}: expected proto:addr")
    if proto not in _WEB_PORTS:
        raise TransportUnsupported(f"{proto}: not a web protocol")
    if rest.startswith("//"):
        rest = rest[2:]
    authority, slash, tail = rest.partition("/")
    path = (slash + tail) if slash else default_path
    if not authority:
        raise ParseError(f"invalid endpoint {endpoint!r}: no host")
    if "@" in authority:
        raise ParseError(f"invalid endpoint {endpoint!r}: userinfo is not supported")
    host, port = _split_authority(authority, _WEB_PORTS[proto], endpoint)
    return WebAddress(proto, host, port, path)


def _split_authority(authority: str, default_port: int, endpoint: str) -> tuple[str, int]:
    """`host`, `host:port` or `[::1]:port`. The port is optional here."""
    if authority.startswith("["):
        host, sep, rest = authority[1:].partition("]")
        if not sep:
            raise ParseError(f"invalid endpoint {endpoint!r}: unclosed [")
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ParseError(f"invalid endpoint {endpoint!r}: junk after ]")
        port_text = rest[1:]
    else:
        host, sep, port_text = authority.rpartition(":")
        if not sep:
            return authority, default_port
    port = ascii_int(port_text)
    if port is None:
        raise ParseError(f"invalid endpoint {endpoint!r}: port is not a number")
    if not 0 <= port <= 65535:
        raise ParseError(f"invalid endpoint {endpoint!r}: port out of range")
    return host, port


# --- the message head -----------------------------------------------------


class Headers(Mapping[str, str]):
    """HTTP headers, looked up without regard to case.

    Go answers `Sec-Websocket-Accept` where RFC 6455 writes `Sec-WebSocket-Accept`
    -- verified against `furry-bolt` -- so a case-sensitive lookup would fail the
    handshake against the very node this SDK exists to talk to. Repeated fields
    join with `", "`, per RFC 9110 section 5.3; `raw` keeps the wire order and the
    wire spelling for anything that needs them.
    """

    __slots__ = ("_map", "raw")

    def __init__(self, raw: list[tuple[str, str]] | None = None) -> None:
        self.raw: list[tuple[str, str]] = list(raw or ())
        self._map: dict[str, str] = {}
        for name, value in self.raw:
            key = name.lower()
            self._map[key] = f"{self._map[key]}, {value}" if key in self._map else value

    def __getitem__(self, name: str) -> str:
        return self._map[name.lower()]

    def __iter__(self) -> Iterator[str]:
        return iter(self._map)

    def __len__(self) -> int:
        return len(self._map)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._map

    def __repr__(self) -> str:
        return f"Headers({self.raw!r})"

    def tokens(self, name: str) -> list[str]:
        """A comma-separated field as lowercase tokens, e.g. `Connection`."""
        return [t.strip().lower() for t in self._map.get(name.lower(), "").split(",") if t.strip()]


@dataclass(frozen=True, slots=True)
class ResponseHead:
    """A status line and its headers."""

    version: str
    status: int
    reason: str
    headers: Headers


def format_request(
    method: str, path: str, headers: Mapping[str, str], *, body: bytes | None = None
) -> bytes:
    """One request as one `bytes`, issued in one `write()` (rule 2).

    A header value carrying CR or LF is refused rather than escaped: a target
    identity or a token arrives from outside the SDK, and a value that could
    inject a second header is a request-splitting hole, not a formatting problem.
    """
    if not path.startswith("/"):
        raise ParseError(f"request target {path!r}: a path begins with /")
    if any(c <= " " or c == "\x7f" for c in path):
        raise ParseError(
            f"request target {path!r}: a space or control character ends the "
            "request line early -- percent-encode it, which astral.querystring."
            "build() already does"
        )
    lines = [f"{method} {path} HTTP/1.1"]
    for name, value in headers.items():
        if "\r" in value or "\n" in value or "\r" in name or "\n" in name:
            raise ParseError(f"header {name!r}: a header may not carry CR or LF")
        lines.append(f"{name}: {value}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "strict")
    return head + body if body else head


async def read_response_head(
    transport: Transport, *, max_bytes: int = MAX_HEAD_BYTES
) -> ResponseHead:
    """Read a status line and its headers, and not one byte more.

    Raises `EOFError` when the peer closes before the status line -- a clean
    "nothing came back" -- and `TransportError` for a truncated or malformed
    head. Obsolete line folding is refused, as RFC 9112 section 5.2 requires of a
    recipient that does not replace it.
    """
    budget = _Budget(max_bytes)
    line = await _read_line(transport, budget)
    parts = line.split(" ", 2)
    status = ascii_int(parts[1]) if len(parts) >= 2 else None
    if status is None or not parts[0].startswith("HTTP/"):
        raise TransportError(f"malformed HTTP status line {line!r}")
    if not 100 <= status <= 599:
        raise TransportError(f"HTTP status {status} is out of range")
    raw: list[tuple[str, str]] = []
    while True:
        field = await _read_line(transport, budget)
        if not field:
            return ResponseHead(parts[0], status, parts[2] if len(parts) > 2 else "", Headers(raw))
        if field[0] in " \t":
            raise TransportError("obsolete header line folding is not accepted")
        name, sep, value = field.partition(":")
        if not sep or not name or name != name.strip():
            raise TransportError(f"malformed HTTP header {field!r}")
        raw.append((name, value.strip()))
        if len(raw) > MAX_HEAD_LINES:
            raise TransportError(f"HTTP head carries more than {MAX_HEAD_LINES} headers")


class _Budget:
    """Bytes left for one message head. Shared by every line of it."""

    __slots__ = ("left", "total")

    def __init__(self, total: int) -> None:
        self.left = total
        self.total = total

    def spend(self, n: int) -> None:
        self.left -= n
        if self.left < 0:
            raise TransportError(f"HTTP head exceeds {self.total} bytes")


async def _read_line(transport: Transport, budget: _Budget) -> str:
    """One CRLF-terminated line, without its terminator.

    Nothing is consumed past the blank line that ends the head, by either route.
    A transport carrying an `asyncio.StreamReader` is read with `readuntil`,
    which stops at the delimiter and leaves the rest in **that same buffer** --
    the one the body and the first WebSocket frame are read from afterwards, so
    rule 1 holds and a 64 KiB head costs one call rather than 65,536.
    Everything else is read one byte at a time, which is the same guarantee at
    the same place and a slower constant.

    A bare LF terminates a line too: every server accepts one and a response that
    arrived is worth reading.
    """
    reader = getattr(transport, "reader", None)
    if isinstance(reader, asyncio.StreamReader):
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError as exc:
            raise TransportError(f"HTTP head line exceeds {MAX_LINE_BYTES} bytes") from exc
        except asyncio.IncompleteReadError as exc:
            raise EOFError("stream closed inside an HTTP head") from exc
        budget.spend(len(raw))
        if len(raw) > MAX_LINE_BYTES:
            raise TransportError(f"HTTP head line exceeds {MAX_LINE_BYTES} bytes")
        return raw[:-2].decode("latin-1") if raw.endswith(b"\r\n") else raw[:-1].decode("latin-1")
    out = bytearray()
    while True:
        byte = await transport.readexactly(1)
        budget.spend(1)
        if byte == b"\n":
            if out.endswith(b"\r"):
                del out[-1:]
            return out.decode("latin-1")
        out += byte
        if len(out) > MAX_LINE_BYTES:
            raise TransportError(f"HTTP head line exceeds {MAX_LINE_BYTES} bytes")


# --- the response ---------------------------------------------------------


class _Body(enum.Enum):
    """How the response body is delimited."""

    EMPTY = "empty"
    LENGTH = "length"
    CHUNKED = "chunked"
    UNTIL_EOF = "eof"


class HTTPResponse(Transport):
    """One HTTP response: the head as data, the body as a byte stream.

    A `Transport`, so a channel frames over it exactly as over a socket -- which
    is the whole point of the seam. Read-only: `write()` raises
    `TransportUnsupported`, because the request is over before the response
    begins and an op that streams input needs IPC or WebSocket.

    `detach()` on a channel above this is illegal for the same reason it is on
    every line-oriented channel: nothing here is byte-exact after a line reader
    has run. The apphost handshake never happens over HTTP, so nothing needs it.
    """

    __slots__ = (
        "_transport",
        "_endpoint",
        "_head",
        "_mode",
        "_left",
        "_chunk_left",
        "_chunk_crlf",
        "_eof",
        "_reading",
        "_stranded",
    )

    def __init__(
        self, transport: Transport, head: ResponseHead, *, endpoint: str, method: str = "GET"
    ) -> None:
        self._transport = transport
        self._endpoint = endpoint
        self._head = head
        self._eof = False
        self._left = 0
        self._chunk_left = 0
        # Whether the chunk that just ended still owes its CRLF. Owed rather
        # than taken, so no `await` sits between consuming a chunk's bytes and
        # returning them.
        self._chunk_crlf = False
        self._reading = False
        self._stranded = False
        self._mode = self._body_mode(head, method)
        if self._mode is _Body.LENGTH:
            self._left = self._content_length(head.headers)

    @staticmethod
    def _body_mode(head: ResponseHead, method: str) -> _Body:
        """RFC 9112 section 6.3, in the order that specification gives.

        `Transfer-Encoding` outranks `Content-Length`, and a message carrying
        both is refused: the two disagreeing is how a request is smuggled past a
        proxy, so it is a fault and never a preference.
        """
        if method == "HEAD" or head.status < 200 or head.status in (204, 304):
            return _Body.EMPTY
        encodings = head.headers.tokens("Transfer-Encoding")
        if encodings:
            if encodings[-1] != "chunked":
                raise TransportError(
                    f"unsupported Transfer-Encoding {head.headers['Transfer-Encoding']!r}"
                )
            if "Content-Length" in head.headers:
                raise TransportError(
                    "the response carries both Transfer-Encoding and Content-Length"
                )
            return _Body.CHUNKED
        return _Body.LENGTH if "Content-Length" in head.headers else _Body.UNTIL_EOF

    @staticmethod
    def _content_length(headers: Headers) -> int:
        """The declared body length. Repeated fields must agree, per RFC 9112."""
        text = headers["Content-Length"]
        values = {part.strip() for part in text.split(",") if part.strip()}
        if len(values) != 1:
            raise TransportError(f"conflicting Content-Length {text!r}")
        length = ascii_int(values.pop())
        if length is None:
            raise TransportError(f"malformed Content-Length {text!r}")
        return length

    # --- the head as data ---

    @property
    def head(self) -> ResponseHead:
        return self._head

    @property
    def status(self) -> int:
        return self._head.status

    @property
    def reason(self) -> str:
        return self._head.reason

    @property
    def headers(self) -> Headers:
        return self._head.headers

    @property
    def host_id(self) -> Identity | None:
        """`X-Astral-Host-Identity`: the node's own identity, or `None`."""
        return self._identity(HOST_HEADER)

    @property
    def guest_id(self) -> Identity | None:
        """`X-Astral-Guest-Identity`: the identity the token authenticated as."""
        return self._identity(GUEST_HEADER)

    def _identity(self, name: str) -> Identity | None:
        text = self._head.headers.get(name)
        return Identity.parse(text) if text else None

    # --- Transport ---

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def closed(self) -> bool:
        return self._transport.closed

    @property
    def at_eof(self) -> bool:
        """Whether the body has been read to its end."""
        return self._eof

    @property
    def at_frame_boundary(self) -> bool:
        """Whether an abandoned read left this body readable.

        Every other framing in this SDK answers this and `Session._recv` and
        `QueryStream.receive` act on it; a body that answered nothing left a
        caller unable to tell a recoverable expiry from an unrecoverable one.

        The dechunker never strands: a chunk's bytes are returned in the same
        turn they are taken and the terminator is owed rather than held.
        `readexactly` can, because it accumulates across reads, and it says so.
        The carrier's own answer is conjoined for the reason every channel
        conjoins this one.
        """
        return not self._stranded and self._transport.at_frame_boundary

    async def readexactly(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"negative read length {n}")
        if n == 0:
            return b""
        out = bytearray()
        while len(out) < n:
            try:
                chunk = await self.read(n - len(out))
            except BaseException:
                # The accumulator dies with the call. `IncompleteRead` below is
                # not this case: it hands the partial bytes to the caller.
                if out:
                    self._stranded = True
                raise
            if not chunk:
                if not out:
                    raise EOFError("the response body ended")
                raise IncompleteRead(bytes(out), n)
            out += chunk
        return bytes(out)

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        if self._reading:
            # `ConcurrentRead`, not a bare `RuntimeError`: this body is handed to
            # a caller by `http.query`, so a second reader on it is a caller's
            # fault on a public object and belongs inside the documented
            # `except AstralError`. `WebSocketClient.receive_frame` already
            # raises it for the identical condition on the other alternate
            # transport, and `ConcurrentRead` is a `RuntimeError` too, so
            # nothing that caught one stops working.
            raise ConcurrentRead(
                f"{self._endpoint}: read() called while another coroutine is "
                "already waiting for incoming data"
            )
        self._reading = True
        try:
            if n < 0:
                out = bytearray()
                while True:
                    try:
                        chunk = await self._body_read(64 * 1024)
                    except BaseException:
                        # Read-to-EOF accumulates across many reads, so an
                        # abandoned one discards every byte taken so far.
                        if out:
                            self._stranded = True
                        raise
                    if not chunk:
                        return bytes(out)
                    out += chunk
            return await self._body_read(n)
        finally:
            self._reading = False

    async def _body_read(self, n: int) -> bytes:
        """Up to `n` body bytes, `b""` at the end of the body."""
        if self._eof:
            return b""
        match self._mode:
            case _Body.EMPTY:
                self._eof = True
                return b""
            case _Body.UNTIL_EOF:
                data = await self._transport.read(n)
                if not data:
                    self._eof = True
                return data
            case _Body.LENGTH:
                if not self._left:
                    self._eof = True
                    return b""
                data = await self._transport.read(min(n, self._left))
                if not data:
                    raise TransportError(
                        f"the response body ended {self._left} bytes short of its "
                        "Content-Length"
                    )
                self._left -= len(data)
                if not self._left:
                    self._eof = True
                return data
            case _:
                return await self._chunked_read(n)

    async def _chunked_read(self, n: int) -> bytes:
        """Up to `n` bytes of the body, dechunked.

        **The chunk's bytes are returned with no `await` between taking them and
        handing them back**, which is the whole shape of this method. Awaiting
        the chunk's CRLF terminator before returning was one await too many: a
        deadline landing on it discarded bytes the reader had already consumed
        and never received, and left `_chunk_left == 0` with the terminator
        unread, so the next read parsed that CRLF as a chunk-size line and the
        body was over. Measured: a peer sends `5\\r\\nhello` and then `\\r\\n5\\r\\nworld
        \\r\\n0\\r\\n\\r\\n`; an expired `read(5)` consumed `hello`, returned nothing,
        and the next read answered `malformed chunk size ''` -- the caller
        received neither half of `helloworld`.

        So the terminator is owed rather than taken: `_chunk_crlf` records that
        one is outstanding and the next read consumes it before the next
        chunk-size line. It is still validated, and still refused when it is not
        CRLF; only the instant it is read has moved.
        """
        if self._chunk_left == 0:
            if self._chunk_crlf:
                await self._chunk_terminator()
            size = await self._chunk_size()
            if size == 0:
                await self._read_trailers()
                self._eof = True
                return b""
            self._chunk_left = size
        try:
            data = await self._transport.read(min(n, self._chunk_left))
        except EOFError as exc:  # pragma: no cover -- read() reports EOF as b""
            raise TransportError("the response body ended inside a chunk") from exc
        if not data:
            raise TransportError(
                f"the response body ended {self._chunk_left} bytes short of its chunk"
            )
        self._chunk_left -= len(data)
        self._chunk_crlf = self._chunk_left == 0
        return data

    async def _chunk_terminator(self) -> None:
        """The CRLF owed by the chunk that just ended.

        Cleared before it is checked, so a malformed terminator is reported once
        rather than re-read by every later call on a body that is already over.
        """
        terminator = await self._transport.readexactly(2)
        self._chunk_crlf = False
        if terminator != b"\r\n":
            raise TransportError(f"chunk is not CRLF-terminated: {terminator!r}")

    async def _chunk_size(self) -> int:
        """One chunk-size line. A chunk extension is read and discarded.

        A stream that ends where a chunk size belongs is a truncated body, so it
        is a `TransportError` and never the `b""` that `read()` returns at a
        clean end: the difference between "that is all of it" and "that is all
        that arrived" is the whole value of a chunked framing.
        """
        try:
            line = await _read_line(self._transport, _Budget(MAX_LINE_BYTES))
        except EOFError as exc:
            raise TransportError("the response body ended before its final chunk") from exc
        # RFC 9112 section 7.1 is `1*HEXDIG`. `int(text, 16)` also reads `0x5`,
        # `+5` and `1_0`, and a hop that frames those differently -- as
        # malformed, or as 1 byte rather than 16 -- reads a different body out
        # of the same bytes. That is the response-splitting shape this module
        # already refuses a doubly-framed message for.
        # Trailing whitespace only, which is Go's `trimTrailingWhitespace` in
        # `net/http/internal.readChunkLine`. A leading space is not `1*HEXDIG`
        # and no sender emits one, so accepting it would be leniency in the one
        # direction that changes how a body is framed.
        text = line.split(";", 1)[0].rstrip(" \t")
        size = ascii_int(text, 16)
        if size is None:
            raise TransportError(f"malformed chunk size {line!r}")
        return size

    async def _read_trailers(self) -> None:
        """The trailer block after the last chunk, read and discarded.

        A peer that closes inside it has still delivered every body byte -- the
        terminating chunk came first -- so the body is whole and the close is not
        a fault. That is the one place this parser is lenient, and it is lenient
        about nothing that changes the bytes a caller receives.
        """
        budget = _Budget(MAX_HEAD_BYTES)
        with contextlib.suppress(EOFError):
            while await _read_line(self._transport, budget):
                pass

    def write(self, data: bytes) -> None:
        raise TransportUnsupported(
            f"{self._endpoint}: the http transport is request/response only -- the "
            "request is complete before the response begins, so an op that streams "
            "input needs the ipc or websocket transport"
        )

    async def drain(self) -> None:
        """Nothing is ever buffered for sending here, so nothing is ever waited on."""

    def write_eof(self) -> None:
        """A no-op: the request ended before the response began.

        The half-close this method promises is already a fact on an HTTP
        response, so it is honoured rather than refused.
        """

    async def aclose(self) -> None:
        await self._transport.aclose()

    def __repr__(self) -> str:
        return f"HTTPResponse({self._endpoint!r}, {self.status}, {self._mode.value})"


# --- requests -------------------------------------------------------------


async def open_response(
    endpoint: str,
    path: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout: float | None = None,
    ssl_context: _ssl.SSLContext | None = None,
) -> HTTPResponse:
    """Issue one request and return its response, body unread.

    `timeout` bounds the dial, the request and the head. The body is read under
    the caller's own deadline, because a body is a stream and a stream has no
    length a connect timeout could cover.

    **A fault before the request is `NodeUnavailable`; a fault after it is not.**
    `NodeUnavailable` is the one error the retry decorator retries, and it is
    safe to retry only because nothing was sent. Once the request is on the wire
    the query may have run, so a head that never arrives is `QueryTimeout` and a
    connection that dies is `TransportError` -- neither of which a retry
    decorator may duplicate.

    The connection is closed on every failure path, cancellation included: a
    response that never came back hands nothing to close.
    """
    address = parse_web_endpoint(endpoint)
    request = format_request(
        method, path, _request_headers(address, headers, body), body=body
    )
    opened: Transport | None = None
    sent = False
    try:
        async with asyncio.timeout(timeout):
            try:
                opened = await open_web_connection(address, endpoint, ssl_context)
            except OSError as exc:
                raise NodeUnavailable(f"{endpoint}: {exc}") from exc
            opened.write(request)
            await opened.drain()
            sent = True
            head = await read_response_head(opened)
            response = HTTPResponse(opened, head, endpoint=endpoint, method=method)
            opened = None
            return response
    except TimeoutError as exc:
        # Ahead of the `OSError` arm deliberately: the builtin `TimeoutError`
        # **is** an `OSError`, so the wider arm first would swallow the deadline.
        if not sent:
            raise NodeUnavailable(f"{endpoint}: no connection within {timeout}s") from exc
        raise QueryTimeout(
            f"{endpoint}: no response head within {timeout}s -- the node's own "
            "deadline on an http query is 5 seconds"
        ) from exc
    except OSError as exc:
        raise TransportError(f"{endpoint}: {exc}") from exc
    except EOFError as exc:
        raise TransportError(f"{endpoint}: closed before answering") from exc
    finally:
        if opened is not None:
            await opened.aclose()


def _request_headers(
    address: WebAddress, extra: Mapping[str, str] | None, body: bytes | None
) -> dict[str, str]:
    """`Host` and `Connection: close` first, the caller's on top.

    `Connection: close` because this is a one-shot: the response body may be
    delimited by the close itself, and a pooled connection nobody reuses is one
    more descriptor to lose track of.
    """
    headers = {"Host": address.authority, "Connection": "close"}
    if body is not None:
        headers["Content-Length"] = str(len(body))
    headers.update(extra or {})
    return headers


async def open_web_connection(
    address: WebAddress, endpoint: str, ssl_context: _ssl.SSLContext | None = None
) -> StreamTransport:
    """The TCP or TLS connection under a web endpoint.

    Shared with the WebSocket upgrade, which dials the same two ways. `OSError`
    reaches the caller unchanged, so each entry point maps a dial fault itself.
    """
    context = ssl_context
    if address.tls and context is None:
        context = _ssl.create_default_context()
    reader, writer = await asyncio.open_connection(
        address.host,
        address.port,
        ssl=context,
        server_hostname=address.host if context else None,
    )
    return StreamTransport(reader, writer, endpoint)


async def query(
    endpoint: str,
    query_string: str,
    *,
    token: str | None = None,
    target: Identity | str | None = None,
    timeout: float | None = None,
    ssl_context: _ssl.SSLContext | None = None,
    check_status: bool = True,
    caller: object = None,
    zone: object = None,
    filters: object = None,
) -> HTTPResponse:
    """Route one query over HTTP and return the response, body unread.

    `caller`, `zone` and `filters` have no HTTP representation: the token
    determines the caller and the node applies its own zone. Passing one raises
    `TransportUnsupported` rather than dropping it, because a query that silently
    ran in the wrong zone is worse than one that did not run.

    `check_status` raises the mapped exception for a non-200 status and closes
    the connection first, so a refusal never leaves a descriptor behind.

    The node's own deadline on an HTTP query is **5 seconds** and covers the
    whole response, not the routing alone (`http_query_handler.go`: the routing
    context is `WithTimeout(5 * time.Second)` and the body is copied under it).
    An op that streams for longer is cut off mid-body over this transport, and
    `follow=true` is unusable over it.
    """
    for name, value in (("caller", caller), ("zone", zone), ("filters", filters)):
        if value is not None:
            raise TransportUnsupported(
                f"{name}: the http transport has no representation for it -- the "
                "auth token determines the caller and the node applies the zone"
            )
    headers: dict[str, str] = {}
    _, params = parse_query_string(query_string)
    # Both headers overwrite the query string's own `in=`/`out=` server-side, so
    # each is sent only where the caller named neither.
    if "out" not in params:
        headers["Accept"] = _JSON
    if "in" not in params:
        headers["Content-Type"] = _JSON
    if token:
        headers[AUTH_HEADER] = f"Bearer {token}"
    if target is not None:
        headers[TARGET_HEADER] = _target_header(target)
    response = await open_response(
        endpoint,
        "/" + query_string.lstrip("/"),
        headers=headers,
        timeout=timeout,
        ssl_context=ssl_context,
    )
    if check_status:
        await _check(response, query_string)
    return response


def _target_header(target: Identity | str) -> str:
    """`X-Astral-Target`, validated here rather than refused by the node.

    astrald parses this header with `astral.ParseIdentity`, which takes 66 hex
    characters or the literal `anyone` and nothing else, so an alias here is a
    400 from the node. An alias belongs in the path -- `@<alias>/<op>` -- which
    the node resolves through the directory (`http_query_handler.go`).
    """
    if isinstance(target, Identity):
        return target.hex()
    try:
        return Identity.parse(target).hex()
    except ParseError as exc:
        raise BadArgument(
            f"target {target!r}: the target header carries an identity, not an "
            "alias -- write '@<alias>/<op>' as the query string to resolve one"
        ) from exc


async def open_object(
    endpoint: str,
    object_id: object,
    *,
    token: str | None = None,
    timeout: float | None = None,
    ssl_context: _ssl.SSLContext | None = None,
    check_status: bool = True,
) -> HTTPResponse:
    """`GET /.objects/<id>`: an object's raw bytes as a byte stream.

    The one apphost surface that exists on HTTP and nowhere else. Authorized by
    the bearer token **and** by a per-object read check, so a token that reaches
    every op still gets 403 -- `Denied` -- on an object it may not read.
    """
    response = await open_response(
        endpoint,
        f"/.objects/{object_id}",
        headers={AUTH_HEADER: f"Bearer {token}"} if token else None,
        timeout=timeout,
        ssl_context=ssl_context,
    )
    if check_status:
        await _check(response, f".objects/{object_id}")
    return response


async def _check(response: HTTPResponse, query_string: str) -> None:
    """Raise for a non-200 status, with the connection closed first.

    Two bounds, and both were absent. `open_response` bounds the dial, the
    request and the head and deliberately leaves the body out, so this read sat
    outside every deadline the caller could set: a peer answering a non-200 that
    declares a body and then sends nothing -- a stalled proxy, a wedged gateway,
    an interrupted node -- parked `http.query(timeout=T)` for ever, measured
    still blocked at 6.03 s on a 1.0 s deadline. And the close ran after a
    `contextlib.suppress(Exception)`, which does not catch a `CancelledError`,
    so a caller's own deadline landing in the peek abandoned the connection to
    the collector -- `ResourceWarning: unclosed <StreamWriter …>`, the
    interpreter naming the one resource this module declares it never leaks.

    So the peek is bounded at `ERROR_PEEK_TIMEOUT` and the close is in a
    `finally`. The status is raised whether or not the peek arrived: the body is
    a courtesy for the message, and the refusal is the fact.
    """
    if response.status == 200:
        return
    peek = b""
    try:
        # `suppress` outside the timeout: an expiry is a `TimeoutError`, an
        # `Exception`, and is swallowed; a cancellation aimed at the caller
        # stays a `CancelledError` and leaves through the `finally`.
        with contextlib.suppress(Exception):
            async with asyncio.timeout(ERROR_PEEK_TIMEOUT):
                peek = await response.read(ERROR_BODY_PEEK)
    finally:
        await response.aclose()
    raise_for_status(response.status, response.headers, query=query_string, body=peek)


def raise_for_status(
    status: int, headers: Headers | None = None, *, query: str | None = None, body: bytes = b""
) -> None:
    """The status table of this module's docstring, as one function."""
    if status == 200:
        return
    detail = body.decode("utf-8", "replace").strip()
    text = f"HTTP {status}" + (f": {detail}" if detail else "")
    if 200 <= status < 300:
        raise ProtocolError(
            f"{text}: a routed query is answered with 200 and nothing else"
        )
    match status:
        case 400:
            raise QueryRejected(2, f"{text} -- the node refused the query as invalid", query=query)
        case 401:
            raise AuthFailed(f"{text} -- the http transport has no anonymous guest")
        case 403:
            raise Denied(text)
        case 404:
            raise RouteNotFound(text)
        case 405:
            raise QueryRejected(1, f"{text} -- the responder declined", query=query)
        case 408 | 504:
            raise QueryTimeout(text)
    if 300 <= status < 400:
        location = (headers or Headers()).get("Location", "")
        raise ProtocolError(
            f"{text}: a redirect to {location!r} is not followed -- one request is "
            "one query, and a redirected query is a different query"
        )
    if status >= 500:
        raise InternalError(text)
    raise ProtocolError(text)
