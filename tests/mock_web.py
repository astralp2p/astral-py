"""Tier B: in-process HTTP/1.1 and RFC 6455 servers, correct and misbehaving.

The harness `test_http.py` and `test_websocket.py` drive. Both servers bind a
real loopback listener with `asyncio.start_server` and speak their protocol by
hand -- the status line, the header block, the chunked body, the frame header,
the mask -- so a wrong layout in the SDK cannot agree with a wrong layout in the
mock. That is the same discipline `mock_apphost.py` applies to apphost framing,
for the same reason: a mock built on the code under test proves the code agrees
with itself.

Misbehaviour is a first-class feature, because a proxy, a cache and a wrong port
all answer something:

| Knob | Fault |
|---|---|
| `WSMock(status=...)` | the upgrade is refused with an HTTP status |
| `WSMock(accept=...)` | a wrong `Sec-WebSocket-Accept` -- a peer that is not a WebSocket server |
| `WSMock(extensions=...)` | an extension nobody offered |
| `WSMock(subprotocol=...)` | a subprotocol nobody offered |
| `WSMock(upgrade=..., connection=...)` | a 101 that upgrades to nothing |
| `server_frame(masked=True)` | a masked server frame, which RFC 6455 forbids |
| `server_frame(rsv=...)` | a reserved bit with no extension negotiated |
| `HTTPMock(raw=...)` | any byte sequence at all in place of a response |
| `response(framing="chunked"/"eof"/"length")` | every body delimiter |

`WSServerTransport` is the server half of `astral.binary.v1`: the byte stream a
`MockApphost` connection is bridged to, so the whole session state machine runs
over WebSocket with no node and no change to `session.py`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Final, Sequence

from astral.transport.base import IncompleteRead, Transport

__all__ = [
    "HTTPMock",
    "RequestHead",
    "WSConn",
    "WSMock",
    "WSServerTransport",
    "bridge",
    "chunked_body",
    "long_frame",
    "response",
    "server_frame",
    "ws_accept",
]

GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# --- request parsing ------------------------------------------------------


@dataclass(slots=True)
class RequestHead:
    """One request line and its headers, as the mock read them."""

    method: str = ""
    path: str = ""
    version: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def get(self, name: str, default: str = "") -> str:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return default

    def has(self, name: str) -> bool:
        return any(key.lower() == name.lower() for key, _ in self.headers)


async def read_request_head(reader: asyncio.StreamReader) -> RequestHead:
    """Read one request head. Raises `EOFError` when the peer sends nothing."""
    line = await reader.readline()
    if not line:
        raise EOFError("no request line")
    parts = line.decode("latin-1").rstrip("\r\n").split(" ")
    head = RequestHead(*(parts + ["", "", ""])[:3])
    while True:
        field_line = await reader.readline()
        text = field_line.decode("latin-1").rstrip("\r\n")
        if not text:
            break
        name, _, value = text.partition(":")
        head.headers.append((name, value.strip()))
    length = head.get("Content-Length")
    if length.isdigit() and int(length):
        head.body = await reader.readexactly(int(length))
    return head


# --- websocket framing, written by hand -----------------------------------


def ws_accept(key: str) -> str:
    """RFC 6455 section 4.2.2, computed here rather than imported."""
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def server_frame(
    opcode: int, payload: bytes = b"", *, fin: bool = True, rsv: int = 0, masked: bool = False
) -> bytes:
    """One frame as a server sends it: unmasked unless a test asks otherwise."""
    out = bytearray([(0x80 if fin else 0) | (rsv << 4) | opcode])
    size = len(payload)
    flag = 0x80 if masked else 0
    if size < 126:
        out.append(flag | size)
    elif size < 65536:
        out.append(flag | 126)
        out += size.to_bytes(2, "big")
    else:
        out.append(flag | 127)
        out += size.to_bytes(8, "big")
    if masked:
        key = b"\x01\x02\x03\x04"
        out += key
        out += bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    else:
        out += payload
    return bytes(out)


def long_frame(opcode: int, size: int, *, declared: int | None = None) -> bytes:
    """A frame header declaring `declared` bytes, followed by `size` of them.

    Declaring more than it carries is how an oversize frame is tested without
    allocating it.
    """
    payload_size = declared if declared is not None else size
    out = bytearray([0x80 | opcode])
    if payload_size < 126:
        out.append(payload_size)
    elif payload_size < 65536:
        out.append(126)
        out += payload_size.to_bytes(2, "big")
    else:
        out.append(127)
        out += payload_size.to_bytes(8, "big")
    return bytes(out) + b"\x00" * size


@dataclass(slots=True)
class ClientFrame:
    """One frame the mock read from the client, unmasked by hand."""

    fin: bool
    opcode: int
    payload: bytes
    masked: bool
    key: bytes


class WSConn:
    """One upgraded connection, at frame granularity."""

    __slots__ = ("reader", "writer", "request", "received")

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, request: RequestHead
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.request = request
        self.received: list[ClientFrame] = []

    async def recv_frame(self) -> ClientFrame:
        """One client frame. Raises `EOFError` at a clean end of stream."""
        head = await self.reader.readexactly(2)
        fin = bool(head[0] & 0x80)
        opcode = head[0] & 0x0F
        masked = bool(head[1] & 0x80)
        size = head[1] & 0x7F
        if size == 126:
            size = int.from_bytes(await self.reader.readexactly(2), "big")
        elif size == 127:
            size = int.from_bytes(await self.reader.readexactly(8), "big")
        key = await self.reader.readexactly(4) if masked else b""
        raw = await self.reader.readexactly(size) if size else b""
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(raw)) if masked else raw
        frame = ClientFrame(fin, opcode, payload, masked, key)
        self.received.append(frame)
        return frame

    async def recv_data(self) -> bytes:
        """The next data frame's payload, control frames answered on the way."""
        while True:
            frame = await self.recv_frame()
            if frame.opcode == 0x9:
                await self.send(server_frame(0xA, frame.payload))
                continue
            if frame.opcode in (0xA,):
                continue
            return frame.payload

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def send_binary(self, payload: bytes, **kw: object) -> None:
        await self.send(server_frame(0x2, payload, **kw))  # type: ignore[arg-type]

    async def send_text(self, text: str, **kw: object) -> None:
        await self.send(server_frame(0x1, text.encode(), **kw))  # type: ignore[arg-type]

    async def send_close(self, code: int = 1000, reason: str = "") -> None:
        payload = code.to_bytes(2, "big") + reason.encode() if code else b""
        await self.send(server_frame(0x8, payload))

    async def aclose(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()


class WSServerTransport(Transport):
    """The server half of `astral.binary.v1`: frames in, one frame per write out.

    Reads concatenate across frames, exactly as the node's do. Written for the
    bridge that puts a whole `MockApphost` behind a WebSocket.
    """

    __slots__ = ("_conn", "_buf", "_eof", "_closed")

    def __init__(self, conn: WSConn) -> None:
        self._conn = conn
        self._buf = bytearray()
        self._eof = False
        self._closed = False

    @property
    def endpoint(self) -> str:
        return "ws:mock"

    @property
    def closed(self) -> bool:
        return self._closed

    async def _fill(self) -> bool:
        while not self._eof:
            try:
                frame = await self._conn.recv_frame()
            except (EOFError, ConnectionError, asyncio.IncompleteReadError):
                self._eof = True
                return False
            if frame.opcode == 0x8:
                self._eof = True
                return False
            if frame.opcode == 0x9:
                await self._conn.send(server_frame(0xA, frame.payload))
                continue
            if frame.payload:
                self._buf += frame.payload
                return True
        return False

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            if not await self._fill():
                if not self._buf:
                    raise EOFError("stream closed")
                partial = bytes(self._buf)
                self._buf.clear()
                raise IncompleteRead(partial, n)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read(self, n: int = -1) -> bytes:
        if n < 0:
            while await self._fill():
                pass
            out, self._buf = bytes(self._buf), bytearray()
            return out
        while not self._buf:
            if not await self._fill():
                return b""
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def write(self, data: bytes) -> None:
        if data:
            self._conn.writer.write(server_frame(0x2, data))

    async def drain(self) -> None:
        await self._conn.writer.drain()

    def write_eof(self) -> None:
        raise AssertionError("websocket has no half-close")

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._conn.send(server_frame(0x8, (1000).to_bytes(2, "big")))
        await self._conn.aclose()


async def bridge(left: Transport, right: Transport) -> None:
    """Copy bytes both ways until either side ends. Closes both on the way out.

    The first EOF tears down both directions, which is what a relay does and what
    keeps a bridged connection from outliving the connection it bridges.
    """

    async def pump(source: Transport, sink: Transport) -> None:
        try:
            while True:
                data = await source.read(65536)
                if not data:
                    return
                sink.write(data)
                await sink.drain()
        except Exception:  # noqa: BLE001 -- either end may vanish at any moment
            return

    tasks = [asyncio.create_task(pump(left, right)), asyncio.create_task(pump(right, left))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await left.aclose()
        await right.aclose()


# --- the servers ----------------------------------------------------------


class _Loopback:
    """A loopback listener whose lifetime is an async context manager."""

    def __init__(self) -> None:
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self.port = 0
        self.conns = 0

    async def start(self) -> str:
        self._server = await asyncio.start_server(self._on_connect, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.endpoint

    @property
    def endpoint(self) -> str:  # pragma: no cover -- overridden
        raise NotImplementedError

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.conns += 1
        self._writers.add(writer)
        try:
            await self.serve(reader, writer)
        except (EOFError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:  # pragma: no cover -- overridden
        raise NotImplementedError

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self.aclose()

    async def aclose(self) -> None:
        """Stop listening and drop every connection.

        The writers are aborted before `wait_closed()`, because since CPython
        3.12.1 that call waits for every handler still running -- and a handler
        parked on a read the test never satisfied never returns.
        """
        for writer in list(self._writers):
            with contextlib.suppress(Exception):
                writer.transport.abort()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 2)
            self._server = None


WSHandler = Callable[[WSConn], Awaitable[None]]


class WSMock(_Loopback):
    """A WebSocket server that upgrades, or refuses, on demand."""

    def __init__(
        self,
        handler: WSHandler | None = None,
        *,
        path: str = "/.ws",
        subprotocol: str | None = None,
        subprotocols: Sequence[str] = ("astral.binary.v1", "astral.json.v1"),
        status: int | None = None,
        accept: str | None = None,
        extensions: str | None = None,
        upgrade: str | None = "websocket",
        connection: str | None = "Upgrade",
        close_before_reply: bool = False,
        silent: bool = False,
        raw_reply: bytes | None = None,
    ) -> None:
        super().__init__()
        self.handler = handler
        self.path = path
        self.subprotocol = subprotocol
        self.subprotocols = list(subprotocols)
        self.status = status
        self.accept = accept
        self.extensions = extensions
        self.upgrade = upgrade
        self.connection = connection
        self.close_before_reply = close_before_reply
        self.silent = silent
        self.raw_reply = raw_reply
        self._stop = asyncio.Event()
        self.requests: list[RequestHead] = []
        self.errors: list[BaseException] = []

    @property
    def endpoint(self) -> str:
        return f"ws://127.0.0.1:{self.port}{self.path}"

    async def aclose(self) -> None:
        self._stop.set()
        await super().aclose()

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request = await read_request_head(reader)
        self.requests.append(request)
        if self.silent:
            # The wedged-peer case: the socket is open, the request is read, and
            # no reply ever comes. Held until shutdown.
            await self._stop.wait()
            return
        if self.close_before_reply:
            return
        if self.raw_reply is not None:
            writer.write(self.raw_reply)
            await writer.drain()
            return
        if self.status is not None:
            body = b"refused\n"
            writer.write(
                f"HTTP/1.1 {self.status} Refused\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
            return
        chosen = self.subprotocol
        if chosen is None:
            offered = [t.strip() for t in request.get("Sec-WebSocket-Protocol").split(",")]
            chosen = next((p for p in offered if p in self.subprotocols), "")
        lines = ["HTTP/1.1 101 Switching Protocols"]
        # Go's canonical header capitalisation, which is not RFC 6455's.
        if self.connection is not None:
            lines.append(f"Connection: {self.connection}")
        lines.append(
            "Sec-Websocket-Accept: "
            + (self.accept if self.accept is not None else ws_accept(request.get("Sec-WebSocket-Key")))
        )
        if chosen:
            lines.append(f"Sec-Websocket-Protocol: {chosen}")
        if self.extensions is not None:
            lines.append(f"Sec-Websocket-Extensions: {self.extensions}")
        if self.upgrade is not None:
            lines.append(f"Upgrade: {self.upgrade}")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        await writer.drain()
        conn = WSConn(reader, writer, request)
        if self.handler is not None:
            try:
                await self.handler(conn)
            except (EOFError, ConnectionError, asyncio.IncompleteReadError):
                pass
            except Exception as exc:  # noqa: BLE001 -- a mock never breaks the loop
                self.errors.append(exc)


Responder = Callable[[RequestHead], bytes]


class HTTPMock(_Loopback):
    """An HTTP/1.1 server that answers whatever bytes a test hands it."""

    def __init__(self, responder: Responder | bytes | None = None) -> None:
        super().__init__()
        self.responder: Responder = (
            responder
            if callable(responder)
            else (lambda _head, _raw=responder: _raw if _raw is not None else response())
        )
        self.requests: list[RequestHead] = []
        self.delay = 0.0

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request = await read_request_head(reader)
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        writer.write(self.responder(request))
        await writer.drain()


def response(
    status: int = 200,
    body: bytes = b"",
    *,
    headers: Sequence[tuple[str, str]] = (),
    framing: str = "length",
    reason: str = "OK",
    version: str = "HTTP/1.1",
) -> bytes:
    """One response, framed the way a test asks for.

    `length` sets `Content-Length`, `chunked` sets `Transfer-Encoding` and chunks
    the body, `eof` sends neither and delimits by closing, `none` sends the body
    with no framing header at all.
    """
    lines = [f"{version} {status} {reason}"]
    payload = body
    match framing:
        case "length":
            lines.append(f"Content-Length: {len(body)}")
        case "chunked":
            lines.append("Transfer-Encoding: chunked")
            payload = chunked_body(body)
        case "eof" | "none":
            lines.append("Connection: close")
    lines.extend(f"{name}: {value}" for name, value in headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + payload


def chunked_body(
    body: bytes, *, size: int = 8, extension: str = "", trailers: Sequence[tuple[str, str]] = ()
) -> bytes:
    """A body cut into chunks, with an optional extension and trailer block."""
    out = bytearray()
    for start in range(0, len(body), size):
        piece = body[start : start + size]
        out += f"{len(piece):x}{extension}\r\n".encode()
        out += piece + b"\r\n"
    out += b"0\r\n"
    for name, value in trailers:
        out += f"{name}: {value}\r\n".encode()
    out += b"\r\n"
    return bytes(out)
