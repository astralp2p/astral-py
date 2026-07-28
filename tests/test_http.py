"""Tier B and C: the one-shot HTTP/1.1 transport and its response body.

Four jobs:

1. Pin the request: the path, the conditional `Accept`/`Content-Type`, the bearer
   token, the target header, and the refusal of anything HTTP cannot carry.
2. Pin the head parser: Go's header capitalisation, repeated fields, the caps,
   and every malformed head it must refuse rather than guess at.
3. Pin all four body framings -- `Content-Length`, `chunked`, read-to-EOF and
   empty -- including the truncations of each.
4. Pin the status table: one exception per status, the connection closed before
   it is raised.

Every async test is `bounded`. The Tier-B tests contact no node; the Tier-C class
skips unless one answers.
"""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock as mocklib

from astral.errors import (
    AstralError,
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
from astral.transport import MemTransport, dial
from astral.transport.base import IncompleteRead
from astral.transport import http as http_module
from astral.transport.http import (
    AUTH_HEADER,
    ERROR_PEEK_TIMEOUT,
    GUEST_HEADER,
    HOST_HEADER,
    TARGET_HEADER,
    Headers,
    HTTPResponse,
    ResponseHead,
    format_request,
    open_object,
    open_response,
    parse_web_endpoint,
    query,
    raise_for_status,
    read_response_head,
)
from astral.types import Identity

import live_support
from mock_apphost import bounded, leaked_sockets, socket_fds
from mock_web import HTTPMock, RequestHead, chunked_body, response

ALICE = Identity(bytes.fromhex("02") + bytes(32))
ENDPOINT = "http://mock:8624"


async def head_of(raw: bytes) -> ResponseHead:
    """Parse one response head out of a memory transport."""
    transport = MemTransport.solo("http")
    transport.feed(raw)
    return await read_response_head(transport)


async def body_of(raw: bytes, *, method: str = "GET") -> HTTPResponse:
    """A response over memory, its head already parsed, its body unread.

    The peer is gone by construction: a one-shot request sends `Connection:
    close`, so the response is whole and the connection ends with it. A test that
    needs the peer still there builds its own transport.
    """
    transport = MemTransport.solo("http")
    transport.feed(raw)
    transport.feed_eof()
    head = await read_response_head(transport)
    return HTTPResponse(transport, head, endpoint=ENDPOINT, method=method)


# --- endpoints ------------------------------------------------------------


class WebEndpointTest(unittest.TestCase):
    def test_the_url_form_and_the_proto_addr_form_name_the_same_endpoint(self):
        for text in ("http://127.0.0.1:8624/x", "http:127.0.0.1:8624/x"):
            with self.subTest(text=text):
                address = parse_web_endpoint(text)
                self.assertEqual(
                    (address.proto, address.host, address.port, address.path),
                    ("http", "127.0.0.1", 8624, "/x"),
                )

    def test_a_missing_port_defaults_to_the_nodes_own(self):
        """8624 is astrald's `bind_http` default, not HTTP's port 80: an endpoint
        with no port names the node, which is the only server this dials."""
        self.assertEqual(parse_web_endpoint("http://node").port, 8624)
        self.assertEqual(parse_web_endpoint("ws://node").port, 8624)
        self.assertEqual(parse_web_endpoint("https://node").port, 443)
        self.assertEqual(parse_web_endpoint("wss://node").port, 443)

    def test_the_host_header_keeps_a_port_that_is_not_the_schemes_standard_one(self):
        """A virtual-host router matches on the port, and 8624 is not HTTP's
        default, so it must be written even when the endpoint left it out."""
        self.assertEqual(parse_web_endpoint("http://node").authority, "node:8624")
        self.assertEqual(parse_web_endpoint("http://node:80").authority, "node")
        self.assertEqual(parse_web_endpoint("https://node").authority, "node")
        self.assertEqual(parse_web_endpoint("https://node:8443").authority, "node:8443")

    def test_an_absent_path_takes_the_default_and_a_written_one_is_kept(self):
        self.assertEqual(parse_web_endpoint("ws://node", default_path="/.ws").path, "/.ws")
        self.assertEqual(parse_web_endpoint("ws://node/", default_path="/.ws").path, "/")
        self.assertEqual(parse_web_endpoint("http://node/a/b?c=d").path, "/a/b?c=d")

    def test_an_ipv6_literal_keeps_its_brackets_in_the_host_header(self):
        address = parse_web_endpoint("http://[::1]:8624/x")
        self.assertEqual((address.host, address.port), ("::1", 8624))
        self.assertEqual(address.authority, "[::1]:8624")

    def test_a_malformed_endpoint_is_a_parse_error(self):
        for text in ("http://", "http://node:notaport", "http://[::1", "http://[::1]junk",
                     "http://user@node", "nothing",
                     # `str.isdigit()` is true of these and `int()` refuses the
                     # first and accepts the rest, so the guard has to be the
                     # conversion's own grammar and not a lookalike.
                     "http://node:\u00b2\u00b2", "http://node:+80", "http://node:8_0"):
            with self.subTest(text=text):
                with self.assertRaises(ParseError):
                    parse_web_endpoint(text)

    def test_a_protocol_that_is_not_web_is_unsupported(self):
        with self.assertRaises(TransportUnsupported):
            parse_web_endpoint("tcp:127.0.0.1:8625")


class DialTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_http_is_not_dialable_and_the_error_names_the_entry_point(self):
        """An HTTP request carries its query in the request line, so there is no
        connection to open before a query exists."""
        for endpoint in ("http://127.0.0.1:8624", "https://node"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(TransportUnsupported) as caught:
                    await dial(endpoint)
                self.assertIn("http.query", str(caught.exception))


# --- headers and the head parser ------------------------------------------


class HeadersTest(unittest.TestCase):
    def test_lookup_ignores_case_because_go_capitalises_its_own_way(self):
        headers = Headers([("Sec-Websocket-Accept", "abc"), ("Content-Length", "3")])
        self.assertEqual(headers["sec-websocket-accept"], "abc")
        self.assertEqual(headers.get("SEC-WEBSOCKET-ACCEPT"), "abc")
        self.assertIn("Content-Length", headers)
        self.assertNotIn("Content-Type", headers)

    def test_repeated_fields_join_with_a_comma(self):
        headers = Headers([("Via", "one"), ("Via", "two")])
        self.assertEqual(headers["via"], "one, two")
        self.assertEqual(headers.tokens("via"), ["one", "two"])

    def test_the_wire_order_and_spelling_survive_in_raw(self):
        raw = [("X-B", "2"), ("X-A", "1")]
        self.assertEqual(Headers(raw).raw, raw)


class ResponseHeadTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_status_line_and_its_headers_are_read_and_nothing_more(self):
        transport = MemTransport.solo("http")
        transport.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
        head = await read_response_head(transport)
        self.assertEqual((head.version, head.status, head.reason), ("HTTP/1.1", 200, "OK"))
        self.assertEqual(head.headers["content-length"], "4")
        # Not one byte past the blank line: the body is still in the transport.
        self.assertEqual(await transport.read(4), b"body")

    @bounded()
    async def test_a_reason_phrase_may_carry_spaces_or_be_absent(self):
        self.assertEqual((await head_of(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")).reason,
                         "Method Not Allowed")
        self.assertEqual((await head_of(b"HTTP/1.1 204\r\n\r\n")).status, 204)

    @bounded()
    async def test_a_bare_lf_terminates_a_line(self):
        """Every server accepts one, and a response that arrives is worth reading."""
        head = await head_of(b"HTTP/1.1 200 OK\nX-A: 1\n\n")
        self.assertEqual(head.headers["x-a"], "1")

    @bounded()
    async def test_a_malformed_head_is_refused_rather_than_guessed_at(self):
        for raw in (
            b"200 OK\r\n\r\n",
            b"HTTP/1.1 XX OK\r\n\r\n",
            b"HTTP/1.1 999 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nnocolon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n: empty\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Space : 1\r\n\r\n",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(TransportError):
                    await head_of(raw)

    @bounded()
    async def test_a_number_no_int_accepts_is_refused_inside_the_hierarchy(self):
        """`str.isdigit()` is true of U+00B2 and `int()` refuses it, so the two
        together passed the guard and raised a bare `ValueError` -- outside the
        documented `except AstralError` -- on bytes a peer chooses. The same
        pair admits `+5` and `1_0`, which are not `1*DIGIT` in RFC 9112.

        `\\xb2` survives the latin-1 decode this parser uses, so it reaches the
        conversion as a character `int()` will not take."""
        for raw in (
            b"HTTP/1.1 \xb2\xb2\xb2 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 +200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 2_0_0 OK\r\nContent-Length: 0\r\n\r\n",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(TransportError):
                    await head_of(raw)

    @bounded()
    async def test_obsolete_line_folding_is_refused(self):
        """RFC 9112 section 5.2: a recipient that does not replace a folded value
        rejects the message. Accepting one is how two parsers read one head
        differently."""
        with self.assertRaises(TransportError) as caught:
            await head_of(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n  folded\r\n\r\n")
        self.assertIn("folding", str(caught.exception))

    @bounded()
    async def test_an_unbounded_head_is_refused(self):
        """Three caps, because a head has three ways to be unbounded: one long
        line, many lines, and many bytes across lines."""
        long_line = b"HTTP/1.1 200 OK\r\nX-Pad: " + b"p" * 9000 + b"\r\n\r\n"
        with self.assertRaises(TransportError) as caught:
            await head_of(long_line)
        self.assertIn("line exceeds", str(caught.exception))

        many = b"HTTP/1.1 200 OK\r\n" + b"".join(
            f"X-{i}: v\r\n".encode() for i in range(150)
        ) + b"\r\n"
        with self.assertRaises(TransportError) as caught:
            await head_of(many)
        self.assertIn("headers", str(caught.exception))

        transport = MemTransport.solo("http")
        transport.feed(b"HTTP/1.1 200 OK\r\n" + b"".join(
            f"X-{i}: {'v' * 60}\r\n".encode() for i in range(20)
        ) + b"\r\n")
        with self.assertRaises(TransportError) as caught:
            await read_response_head(transport, max_bytes=512)
        self.assertIn("exceeds", str(caught.exception))

    @bounded()
    async def test_a_peer_that_closes_before_the_status_line_is_a_clean_eof(self):
        transport = MemTransport.solo("http")
        transport.feed_eof()
        with self.assertRaises(EOFError):
            await read_response_head(transport)


# --- the body -------------------------------------------------------------


class BodyFramingTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_content_length_delimits_the_body(self):
        body = await body_of(response(body=b"one\ntwo\n"))
        self.assertEqual(await body.read(-1), b"one\ntwo\n")
        self.assertEqual(await body.read(4), b"")
        self.assertTrue(body.at_eof)

    @bounded()
    async def test_a_body_short_of_its_content_length_is_a_fault(self):
        """A truncated body read as a complete one is a silently short answer."""
        transport = MemTransport.solo("http")
        transport.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
        transport.feed_eof()
        head = await read_response_head(transport)
        response_ = HTTPResponse(transport, head, endpoint=ENDPOINT)
        with self.assertRaises(TransportError) as caught:
            await response_.read(-1)
        self.assertIn("short of its Content-Length", str(caught.exception))

    @bounded()
    async def test_a_chunk_size_outside_1_hexdig_is_refused(self):
        """RFC 9112 section 7.1 is `1*HEXDIG`. `int(text, 16)` also reads `0x5`,
        `+5` and `1_0`, and a hop that reads `1_0` as 1 byte where this reads 16
        frames a different body out of the same bytes -- the response-splitting
        shape this module already refuses a doubly-framed message for."""
        for size in (b"0x5", b"+5", b"1_0", b" 5"):
            with self.subTest(size=size):
                raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       + size + b"\r\nhello\r\n0\r\n\r\n")
                body = await body_of(raw)
                with self.assertRaises(TransportError) as caught:
                    await body.read(-1)
                self.assertIn("chunk size", str(caught.exception))

    @bounded()
    async def test_a_content_length_no_int_accepts_is_refused(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: \xb2\xb2\xb2\r\n\r\nhi"
        with self.assertRaises(TransportError):
            await body_of(raw)

    @bounded()
    async def test_a_chunked_body_is_dechunked(self):
        body = await body_of(response(body=b"abcdefghij", framing="chunked"))
        self.assertEqual(await body.read(-1), b"abcdefghij")

    @bounded()
    async def test_chunk_extensions_and_trailers_are_read_and_discarded(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked_body(
            b"payload", size=3, extension=";x=1", trailers=[("X-Trailer", "1")]
        )
        body = await body_of(raw)
        self.assertEqual(await body.read(-1), b"payload")

    @bounded()
    async def test_a_malformed_chunk_is_refused(self):
        for tail in (
            b"zz\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabcXX0\r\n\r\n",
            b"5\r\nabc",
        ):
            with self.subTest(tail=tail):
                body = await body_of(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + tail
                )
                with self.assertRaises(TransportError):
                    await body.read(-1)

    @bounded()
    async def test_a_chunk_is_handed_back_before_its_terminator_is_read(self):
        """A deadline must not be able to eat bytes the reader already consumed.

        The dechunker used to take the chunk's bytes and then await its CRLF
        before returning them, so a deadline landing on the terminator discarded
        what it had taken and left `_chunk_left == 0` with the CRLF unread --
        the next read parsed that CRLF as a chunk-size line and the body was
        over. Measured: the peer's body was `helloworld` and the caller received
        neither half, only `malformed chunk size ''`. The terminator is now owed
        and consumed at the start of the next read, so no `await` sits between
        taking a chunk's bytes and handing them back.
        """
        transport = MemTransport.solo("chunk")
        transport.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello")
        head = await read_response_head(transport)
        body = HTTPResponse(transport, head, endpoint=ENDPOINT)
        # The terminator has not arrived; the five bytes have.
        async with asyncio.timeout(1):
            self.assertEqual(await body.read(5), b"hello")
        self.assertTrue(body.at_frame_boundary)
        transport.feed(b"\r\n5\r\nworld\r\n0\r\n\r\n")
        self.assertEqual(await body.read(-1), b"world")

    @bounded()
    async def test_a_terminator_that_is_not_crlf_is_still_refused(self):
        """Only the instant the terminator is read has moved, not the check."""
        body = await body_of(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n"
        )
        self.assertEqual(await body.read(3), b"abc")
        with self.assertRaises(TransportError) as caught:
            await body.read(3)
        self.assertIn("CRLF", str(caught.exception))

    @bounded()
    async def test_a_chunked_body_cut_before_its_final_chunk_is_a_fault(self):
        """`read()` answers `b""` at a clean end. A stream that stops where a
        chunk size belongs is not a clean end, and reporting one would make a
        truncated answer indistinguishable from a complete one."""
        body = await body_of(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"3\r\nabc\r\n"
        )
        with self.assertRaises(TransportError) as caught:
            await body.read(-1)
        self.assertIn("before its final chunk", str(caught.exception))

    @bounded()
    async def test_a_close_inside_the_trailer_block_is_not_a_fault(self):
        """The terminating chunk came first, so every body byte arrived."""
        body = await body_of(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
        )
        self.assertEqual(await body.read(-1), b"abc")

    @bounded()
    async def test_a_body_delimited_by_the_close_is_read_to_eof(self):
        transport = MemTransport.solo("http")
        transport.feed(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed")
        transport.feed_eof()
        head = await read_response_head(transport)
        body = HTTPResponse(transport, head, endpoint=ENDPOINT)
        self.assertEqual(await body.read(-1), b"streamed")

    @bounded()
    async def test_a_status_that_carries_no_body_reads_empty(self):
        for status in (204, 304, 101):
            with self.subTest(status=status):
                body = await body_of(f"HTTP/1.1 {status} X\r\n\r\n".encode())
                self.assertEqual(await body.read(-1), b"")
        head = await head_of(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n")
        transport = MemTransport.solo("http")
        empty = HTTPResponse(transport, head, endpoint=ENDPOINT, method="HEAD")
        self.assertEqual(await empty.read(-1), b"")

    @bounded()
    async def test_a_message_carrying_both_framings_is_refused(self):
        """Two delimiters that disagree is how a request is smuggled past a
        proxy: a fault, never a preference."""
        with self.assertRaises(TransportError):
            await body_of(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
            )

    @bounded()
    async def test_an_unsupported_transfer_encoding_is_refused(self):
        with self.assertRaises(TransportError):
            await body_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")

    @bounded()
    async def test_conflicting_content_lengths_are_refused(self):
        with self.assertRaises(TransportError):
            await body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc")
        with self.assertRaises(TransportError):
            await body_of(b"HTTP/1.1 200 OK\r\nContent-Length: three\r\n\r\n")


class BodyTransportTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_readexactly_has_the_two_eof_shapes(self):
        body = await body_of(response(body=b"abc"))
        self.assertEqual(await body.readexactly(3), b"abc")
        with self.assertRaises(EOFError) as caught:
            await body.readexactly(1)
        self.assertNotIsInstance(caught.exception, IncompleteRead)

        body = await body_of(response(body=b"abc"))
        with self.assertRaises(IncompleteRead) as short:
            await body.readexactly(6)
        self.assertEqual(short.exception.partial, b"abc")

    @bounded()
    async def test_a_zero_length_read_is_not_an_ending(self):
        body = await body_of(response(body=b"abc"))
        self.assertEqual(await body.read(0), b"")
        self.assertEqual(await body.readexactly(0), b"")
        self.assertFalse(body.at_eof)

    @bounded()
    async def test_a_second_concurrent_reader_is_refused(self):
        transport = MemTransport.solo("http")
        transport.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
        head = await read_response_head(transport)
        body = HTTPResponse(transport, head, endpoint=ENDPOINT)
        first = asyncio.create_task(body.read(8))
        for _ in range(3):
            await asyncio.sleep(0)
        # `ConcurrentRead`, which the hierarchy declares for exactly this and
        # which `WebSocketClient.receive_frame` already raised on the other
        # alternate transport. A bare `RuntimeError` here fell outside the
        # documented `except AstralError` on one transport and inside it on the
        # other, for one condition. It is a `RuntimeError` too.
        with self.assertRaises(ConcurrentRead):
            await body.read(8)
        with self.assertRaises(RuntimeError):
            await body.read(8)
        with self.assertRaises(AstralError):
            await body.read(8)
        transport.feed(b"finished")
        self.assertEqual(await first, b"finished")

    @bounded()
    async def test_writing_is_refused_and_says_what_to_use_instead(self):
        body = await body_of(response())
        with self.assertRaises(TransportUnsupported) as caught:
            body.write(b"input")
        self.assertIn("request/response", str(caught.exception))

    @bounded()
    async def test_write_eof_is_a_no_op_because_the_request_already_ended(self):
        body = await body_of(response())
        body.write_eof()
        await body.drain()

    @bounded()
    async def test_aclose_is_idempotent(self):
        body = await body_of(response())
        await body.aclose()
        await body.aclose()
        self.assertTrue(body.closed)

    @bounded()
    async def test_the_identity_headers_are_parsed(self):
        head = await head_of(
            f"HTTP/1.1 200 OK\r\n{HOST_HEADER}: {ALICE}\r\n{GUEST_HEADER}: anyone\r\n"
            "Content-Length: 0\r\n\r\n".encode()
        )
        body = HTTPResponse(MemTransport.solo("http"), head, endpoint=ENDPOINT)
        self.assertEqual(body.host_id, ALICE)
        self.assertTrue(body.guest_id.is_zero)
        empty = HTTPResponse(
            MemTransport.solo("http"),
            await head_of(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            endpoint=ENDPOINT,
        )
        self.assertIsNone(empty.host_id)


# --- the request ----------------------------------------------------------


class RequestFormatTest(unittest.TestCase):
    def test_a_request_is_one_bytes_with_crlf_line_endings(self):
        raw = format_request("GET", "/apphost.whoami", {"Host": "node:8624"})
        self.assertEqual(raw, b"GET /apphost.whoami HTTP/1.1\r\nHost: node:8624\r\n\r\n")

    def test_a_header_carrying_a_newline_is_refused(self):
        """A target identity and a token arrive from outside the SDK. A value that
        could inject a second header is a request-splitting hole."""
        for name, value in (("X-A", "one\r\nX-B: two"), ("X-A", "one\nX-B: two"),
                            ("X-A\r\n", "one")):
            with self.subTest(value=value):
                with self.assertRaises(ParseError):
                    format_request("GET", "/x", {name: value})

    def test_a_request_target_with_a_space_is_refused(self):
        """A space ends the request line early, so the rest of the query becomes
        the HTTP version and the node sees a different query than the caller
        wrote."""
        for path in ("/objects.search?q=two words", "/x\x7f", "apphost.whoami"):
            with self.subTest(path=path):
                with self.assertRaises(ParseError):
                    format_request("GET", path, {})

    def test_a_body_follows_the_head_in_the_same_bytes(self):
        raw = format_request("POST", "/x", {"Content-Length": "2"}, body=b"hi")
        self.assertTrue(raw.endswith(b"\r\n\r\nhi"))


class QueryRequestTest(unittest.IsolatedAsyncioTestCase):
    async def request_for(self, *args: object, **kw: object) -> RequestHead:
        async with HTTPMock() as mock:
            result = await query(mock.endpoint, *args, **kw)  # type: ignore[arg-type]
            await result.aclose()
            return mock.requests[0]

    @bounded()
    async def test_the_query_string_is_the_path(self):
        head = await self.request_for("objects.search?q=hello&zone=d")
        self.assertEqual(head.method, "GET")
        self.assertEqual(head.path, "/objects.search?q=hello&zone=d")
        self.assertEqual(head.get("Host"), "127.0.0.1:" + head.get("Host").split(":")[1])

    @bounded()
    async def test_one_shot_means_connection_close(self):
        head = await self.request_for("apphost.whoami")
        self.assertEqual(head.get("Connection").lower(), "close")

    @bounded()
    async def test_the_json_headers_are_sent_when_the_caller_named_no_format(self):
        head = await self.request_for("apphost.whoami")
        self.assertEqual(head.get("Accept"), "application/json")
        self.assertEqual(head.get("Content-Type"), "application/json")

    @bounded()
    async def test_the_json_headers_are_withheld_where_the_caller_named_a_format(self):
        """astrald overwrites `out=` from `Accept` and `in=` from `Content-Type`
        (`http_query_handler.go`), so sending them unconditionally would make
        `out=text` unreachable over HTTP -- the legacy SDK's WebSocket bug, one
        transport sideways."""
        head = await self.request_for("shell.spec?out=text")
        self.assertFalse(head.has("Accept"))
        self.assertEqual(head.get("Content-Type"), "application/json")
        head = await self.request_for("objects.store?in=bin&out=bin")
        self.assertFalse(head.has("Accept"))
        self.assertFalse(head.has("Content-Type"))

    @bounded()
    async def test_a_token_is_a_bearer_credential(self):
        head = await self.request_for("apphost.whoami", token="s3cret")
        self.assertEqual(head.get(AUTH_HEADER), "Bearer s3cret")

    @bounded()
    async def test_a_target_is_an_identity_and_an_alias_is_refused_here(self):
        """astrald parses this header with `ParseIdentity`: 66 hex characters or
        `anyone`. An alias belongs in the path as `@<alias>/<op>`, and sending one
        in the header is a 400 the SDK can refuse locally instead."""
        head = await self.request_for("apphost.whoami", target=ALICE)
        self.assertEqual(head.get(TARGET_HEADER), ALICE.hex())
        head = await self.request_for("apphost.whoami", target=ALICE.hex())
        self.assertEqual(head.get(TARGET_HEADER), ALICE.hex())
        async with HTTPMock() as mock:
            with self.assertRaises(BadArgument) as caught:
                await query(mock.endpoint, "apphost.whoami", target="furry-bolt")
            self.assertIn("@<alias>/<op>", str(caught.exception))

    @bounded()
    async def test_an_alias_target_travels_in_the_path(self):
        head = await self.request_for("@furry-bolt/apphost.whoami")
        self.assertEqual(head.path, "/@furry-bolt/apphost.whoami")

    @bounded()
    async def test_a_leading_slash_on_the_query_string_is_absorbed(self):
        head = await self.request_for("/apphost.whoami")
        self.assertEqual(head.path, "/apphost.whoami")

    @bounded()
    async def test_what_http_cannot_carry_is_refused_and_named(self):
        """Design section 3.1: `caller`, `zone` and `filters` have no HTTP
        representation. A query that silently ran in the wrong zone is worse than
        one that did not run."""
        async with HTTPMock() as mock:
            for name, value in (("caller", ALICE), ("zone", "d"), ("filters", ["a"])):
                with self.subTest(name=name):
                    with self.assertRaises(TransportUnsupported) as caught:
                        await query(mock.endpoint, "apphost.whoami", **{name: value})
                    self.assertIn(name, str(caught.exception))
            self.assertEqual(mock.conns, 0)

    @bounded()
    async def test_an_object_request_takes_the_dot_objects_path(self):
        async with HTTPMock() as mock:
            result = await open_object(mock.endpoint, "data1abc", token="t")
            await result.aclose()
            self.assertEqual(mock.requests[0].path, "/.objects/data1abc")
            self.assertEqual(mock.requests[0].get(AUTH_HEADER), "Bearer t")


class ResponseStatusTest(unittest.IsolatedAsyncioTestCase):
    async def status(self, status: int, body: bytes = b"", headers=()) -> BaseException:
        async with HTTPMock(response(status, body, headers=headers, reason="X")) as mock:
            before = socket_fds()
            with self.assertRaises(Exception) as caught:
                await query(mock.endpoint, "apphost.whoami")
            # The connection is closed before the exception leaves, or a refusal
            # costs a descriptor for as long as the caller holds the traceback.
            for _ in range(50):
                await asyncio.sleep(0)
                if not leaked_sockets(before):
                    break
            self.assertEqual(leaked_sockets(before), set())
            return caught.exception

    @bounded()
    async def test_every_status_maps_to_one_exception(self):
        for status, expected in (
            (400, QueryRejected),
            (401, AuthFailed),
            (403, Denied),
            (404, RouteNotFound),
            (405, QueryRejected),
            (408, QueryTimeout),
            (504, QueryTimeout),
            (201, ProtocolError),
            (418, ProtocolError),
            (500, InternalError),
            (502, InternalError),
        ):
            with self.subTest(status=status):
                self.assertIsInstance(await self.status(status), expected)

    @bounded()
    async def test_the_reject_codes_are_the_nodes_own(self):
        """astrald maps `ErrRejected` to 405 and a malformed query to 400; the
        SDK's reject codes for those are 1 (rejected) and 2 (invalid query)."""
        self.assertEqual((await self.status(405)).code, 1)
        self.assertEqual((await self.status(400)).code, 2)

    @bounded()
    async def test_a_redirect_is_never_followed(self):
        exc = await self.status(302, headers=[("Location", "http://elsewhere/")])
        self.assertIsInstance(exc, ProtocolError)
        self.assertIn("http://elsewhere/", str(exc))

    @bounded()
    async def test_the_error_body_reaches_the_message(self):
        """"HTTP 502" alone does not say which hop refused."""
        exc = await self.status(502, b"upstream is down")
        self.assertIn("upstream is down", str(exc))

    @bounded()
    async def test_a_status_may_be_inspected_instead_of_raised(self):
        async with HTTPMock(response(404, b"missing")) as mock:
            result = await query(mock.endpoint, "apphost.whoami", check_status=False)
            try:
                self.assertEqual(result.status, 404)
                self.assertEqual(await result.read(-1), b"missing")
            finally:
                await result.aclose()

    def test_the_table_is_a_function_a_caller_can_reach(self):
        raise_for_status(200)
        with self.assertRaises(AuthFailed):
            raise_for_status(401)


class ErrorPeekTest(unittest.IsolatedAsyncioTestCase):
    """The failing body is peeked for the message, and the peek is a courtesy.

    `open_response` bounds the dial, the request and the head and leaves the
    body out on purpose. The peek sat outside that scope with no bound of its
    own, so a peer answering a non-200 that declares a body and sends none
    parked `http.query(timeout=T)` for ever -- measured still blocked at 6.03 s
    on a 1.0 s deadline. And the close ran after a `contextlib.suppress(
    Exception)`, which does not catch a `CancelledError`, so a cancellation
    landing there abandoned the connection to the collector.
    """

    def _stalled(self) -> HTTPResponse:
        """A 401 declaring a 64-byte body, of which nothing ever arrives."""
        transport = MemTransport.solo("peek")
        return transport, HTTPResponse(
            transport,
            ResponseHead(
                "HTTP/1.1", 401, "Unauthorized", Headers([("Content-Length", "64")])
            ),
            endpoint=ENDPOINT,
        )

    @bounded()
    async def test_a_body_that_never_arrives_does_not_hold_the_refusal(self):
        transport, response = self._stalled()
        with mocklib.patch.object(http_module, "ERROR_PEEK_TIMEOUT", 0.05):
            with self.assertRaises(AuthFailed):
                await http_module._check(response, "apphost.whoami")  # noqa: SLF001
        self.assertTrue(transport.closed)

    @bounded()
    async def test_a_cancellation_in_the_peek_still_closes_the_connection(self):
        transport, response = self._stalled()
        task = asyncio.create_task(
            http_module._check(response, "apphost.whoami")  # noqa: SLF001
        )
        for _ in range(20):
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(transport.closed)

    def test_the_peek_bound_is_a_courtesys_worth(self):
        """A second at most: 512 bytes read to improve an exception message is
        not worth more than the refusal it decorates."""
        self.assertLessEqual(ERROR_PEEK_TIMEOUT, 1.0)


class TransportFaultTest(unittest.IsolatedAsyncioTestCase):
    @bounded()
    async def test_a_closed_port_is_node_unavailable(self):
        async with HTTPMock() as mock:
            endpoint = mock.endpoint
        with self.assertRaises(NodeUnavailable):
            await open_response(endpoint, "/", timeout=2)

    @bounded()
    async def test_a_peer_that_never_answers_is_a_query_timeout_not_a_retry(self):
        """The request is on the wire, so the query may have run. `NodeUnavailable`
        is the retry key and retrying here could duplicate an effect."""
        async with HTTPMock() as mock:
            mock.delay = 30
            with self.assertRaises(QueryTimeout):
                await open_response(mock.endpoint, "/", timeout=0.3)

    @bounded()
    async def test_a_peer_that_closes_without_answering_is_a_transport_error(self):
        async with HTTPMock(b"") as mock:
            with self.assertRaises(TransportError) as caught:
                await open_response(mock.endpoint, "/", timeout=2)
            self.assertIn("closed before answering", str(caught.exception))

    @bounded()
    async def test_a_dial_fault_leaves_no_descriptor_behind(self):
        before = socket_fds()
        async with HTTPMock(b"HTTP/1.1 nonsense\r\n\r\n") as mock:
            with self.assertRaises(TransportError):
                await open_response(mock.endpoint, "/", timeout=2)
        for _ in range(50):
            await asyncio.sleep(0)
            if not leaked_sockets(before):
                break
        self.assertEqual(leaked_sockets(before), set())


# --- the node -------------------------------------------------------------


HTTP_ENDPOINT_VAR = "ASTRAL_TEST_HTTP_ENDPOINT"
DEFAULT_HTTP_ENDPOINT = "http://127.0.0.1:8624"


class LiveHTTPTest(unittest.IsolatedAsyncioTestCase):
    """Tier C. Skips unless the live tier is on and the HTTP listener answers.

    Read-only, and unauthenticated on purpose: astrald has **no anonymous HTTP
    guest** -- `AuthenticateToken("")` fails, so every query without a token is
    401 (`access_tokens.go:48`). Minting a token is a write op and this tier does
    not perform one, so the authenticated path is exercised against `HTTPMock`
    and the refusal path against the node.
    """

    async def asyncSetUp(self) -> None:
        reason = await live_support.verdict()
        if reason:
            self.skipTest(reason)
        self.http_endpoint = os.environ.get(HTTP_ENDPOINT_VAR) or DEFAULT_HTTP_ENDPOINT
        try:
            probe = await open_response(self.http_endpoint, "/", method="OPTIONS", timeout=3)
        except Exception as exc:  # noqa: BLE001 -- any fault is a reason to skip
            self.skipTest(f"{self.http_endpoint}: {type(exc).__name__}: {exc}")
        await probe.aclose()
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for _ in range(200):
            await asyncio.sleep(0)
            if not leaked_sockets(self.sockets_before):
                return
        self.assertEqual(leaked_sockets(self.sockets_before), set())

    @bounded(20)
    async def test_the_preflight_is_answered_with_the_cors_headers(self):
        result = await open_response(self.http_endpoint, "/", method="OPTIONS")
        try:
            self.assertEqual(result.status, 200)
            self.assertEqual(result.headers["access-control-allow-origin"], "*")
            self.assertEqual(await result.read(-1), b"")
        finally:
            await result.aclose()

    @bounded(20)
    async def test_a_query_without_a_token_is_refused_as_auth_failed(self):
        with self.assertRaises(AuthFailed) as caught:
            await query(self.http_endpoint, "apphost.whoami")
        self.assertIn("401", str(caught.exception))

    @bounded(20)
    async def test_the_refusal_carries_no_identity_headers(self):
        """The node sets `X-Astral-Host-Identity` only after authenticating, so a
        401 says nothing about the node -- and the SDK must not invent it."""
        result = await query(self.http_endpoint, "apphost.whoami", check_status=False)
        try:
            self.assertEqual(result.status, 401)
            self.assertIsNone(result.host_id)
            self.assertIsNone(result.guest_id)
            self.assertEqual(await result.read(-1), b"")
        finally:
            await result.aclose()

    @bounded(20)
    async def test_an_object_request_without_a_token_is_refused(self):
        with self.assertRaises(AuthFailed):
            await open_object(self.http_endpoint, "data1abc")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
