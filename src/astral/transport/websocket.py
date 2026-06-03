"""WebSocket transport: the apphost protocol over JSON envelopes.

Reference: ``topics/ws-transport.md``. The host exposes a WebSocket upgrade at
``/.ws`` (default ``ws://127.0.0.1:8624/.ws``); the client negotiates the
``astral.json.v1`` subprotocol and every frame is one text message carrying a
``{ "Type": ..., "Object": ... }`` envelope.

A minimal RFC 6455 client is implemented here so the library has no third-party
dependencies. The apphost session logic is inherited from
:class:`ChannelTransport`; only :class:`JsonWebSocketChannel` differs from the
binary transport.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import threading
from typing import Any, List, Optional

from .base import UNSET

from ..encoding import from_json_envelope, to_json_envelope
from ..errors import ConnectError, NotSupported, ProtocolError
from ..messages import REGISTRY, Message
from ..objects import AstralObject
from .base import Channel, Endpoint
from .session import ChannelTransport

__all__ = ["WebSocketClient", "JsonWebSocketChannel", "WebSocketTransport"]

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_SUBPROTOCOL = "astral.json.v1"
_RECV_SIZE = 65536

# opcodes
_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


class WebSocketClient:
    """A tiny client-side WebSocket (RFC 6455) over a stream socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._rbuf = bytearray()
        self._send_lock = threading.Lock()
        self._closed = False

    # -- connection ---------------------------------------------------------
    @classmethod
    def connect(cls, host: str, port: int, path: str, *, secure: bool, timeout: float) -> "WebSocketClient":
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise ConnectError(f"cannot connect to {host}:{port}: {exc}") from exc
        if secure:
            import ssl

            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=host)
        raw.settimeout(None)
        client = cls(raw)
        client._handshake(host, port, path)
        return client

    def _handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {_SUBPROTOCOL}\r\n"
            "\r\n"
        )
        self._sock.sendall(request.encode("ascii"))

        header = self._read_until(b"\r\n\r\n")
        status_line = header.split(b"\r\n", 1)[0].decode("latin1")
        if "101" not in status_line:
            raise ConnectError(f"WebSocket upgrade failed: {status_line!r}")
        expected = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if expected.encode("ascii") not in header:
            raise ConnectError("WebSocket handshake: bad Sec-WebSocket-Accept")

    def _read_until(self, delimiter: bytes) -> bytes:
        while delimiter not in self._rbuf:
            chunk = self._sock.recv(_RECV_SIZE)
            if not chunk:
                raise ConnectError("connection closed during WebSocket handshake")
            self._rbuf += chunk
        index = self._rbuf.index(delimiter) + len(delimiter)
        head = bytes(self._rbuf[:index])
        del self._rbuf[:index]
        return head

    # -- framing ------------------------------------------------------------
    def _read_exact(self, n: int) -> bytes:
        while len(self._rbuf) < n:
            try:
                chunk = self._sock.recv(_RECV_SIZE)
            except OSError:
                chunk = b""
            if not chunk:
                raise EOFError
            self._rbuf += chunk
        out = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])  # FIN set
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)  # MASK bit set (client frames must mask)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        with self._send_lock:
            if self._closed:
                raise ConnectError("WebSocket is closed")
            self._sock.sendall(bytes(header) + masked)

    def _recv_frame(self):
        b0 = self._read_exact(1)[0]
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        b1 = self._read_exact(1)[0]
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        return fin, opcode, payload

    def send_text(self, text: str) -> None:
        self._send_frame(_OP_TEXT, text.encode("utf-8"))

    def recv_text(self) -> Optional[str]:
        """Return the next text message, or ``None`` once the socket closes."""
        fragments: List[bytes] = []
        message_op: Optional[int] = None
        while True:
            try:
                fin, opcode, payload = self._recv_frame()
            except (EOFError, OSError):
                return None
            if opcode == _OP_CLOSE:
                self._send_close()
                return None
            if opcode == _OP_PING:
                self._send_frame(_OP_PONG, payload)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CONT:
                fragments.append(payload)
            elif opcode in (_OP_TEXT, _OP_BINARY):
                message_op = opcode
                fragments.append(payload)
            if fin:
                data = b"".join(fragments)
                if message_op == _OP_BINARY:
                    # Binary frames are silently dropped (text/JSON only).
                    fragments, message_op = [], None
                    continue
                return data.decode("utf-8")

    def _send_close(self) -> None:
        try:
            self._send_frame(_OP_CLOSE, b"")
        except Exception:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._send_close()
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


class JsonWebSocketChannel(Channel):
    """An apphost :class:`Channel` carrying JSON envelopes over a WebSocket."""

    def __init__(self, ws: WebSocketClient) -> None:
        self._ws = ws

    def send(self, item) -> None:
        if isinstance(item, Message):
            envelope = {"Type": item.TYPE, "Object": item.encode_json()}
        elif isinstance(item, AstralObject):
            envelope = to_json_envelope(item)
        else:  # pragma: no cover - defensive
            raise TypeError(f"cannot send {type(item).__name__} on a channel")
        self._ws.send_text(json.dumps(envelope))

    def recv(self) -> Optional[object]:
        text = self._ws.recv_text()
        if text is None:
            return None
        try:
            envelope = json.loads(text)
        except ValueError as exc:
            raise ProtocolError(f"invalid JSON frame: {text!r}") from exc
        obj_type = envelope.get("Type", "")
        message_cls = REGISTRY.get(obj_type)
        if message_cls is not None:
            return message_cls.decode_json(envelope.get("Object"))
        return from_json_envelope(envelope)

    def recv_bytes(self, size: int = -1) -> bytes:
        raise NotSupported(
            "raw byte reads are not available over the JSON WebSocket transport; "
            "use the binary or HTTP transport for unframed-output ops"
        )

    def close(self) -> None:
        self._ws.close()


class WebSocketTransport(ChannelTransport):
    """Opens JSON WebSocket channels to the apphost ``/.ws`` endpoint."""

    def __init__(
        self,
        endpoint: Endpoint,
        token: Optional[str],
        *,
        connect_timeout: float = 10.0,
    ) -> None:
        super().__init__(endpoint, token)
        self.connect_timeout = connect_timeout
        from urllib.parse import urlsplit

        split = urlsplit(endpoint.url)
        self._host = split.hostname or "127.0.0.1"
        self._port = split.port or 8624
        self._path = split.path or "/.ws"
        self._secure = endpoint.scheme == "wss"

    def _open_channel(self) -> Channel:
        ws = WebSocketClient.connect(
            self._host,
            self._port,
            self._path,
            secure=self._secure,
            timeout=self.connect_timeout,
        )
        return JsonWebSocketChannel(ws)

    def query(
        self,
        query_string: str,
        *,
        target: Optional[str] = None,
        caller: Any = UNSET,
        zone: Any = "dvn",
        filters: Optional[List[str]] = None,
    ):
        # The channel is JSON-only, so the responder must encode in JSON; inject
        # in=json&out=json unless the caller already chose an encoding.
        query_string = _ensure_json_encoding(query_string)
        return super().query(
            query_string, target=target, caller=caller, zone=zone, filters=filters
        )


def _ensure_json_encoding(query_string: str) -> str:
    base, sep, params = query_string.partition("?")
    pairs = [p for p in params.split("&") if p] if sep else []
    keys = {pair.split("=", 1)[0] for pair in pairs}
    for key in ("in", "out"):
        if key not in keys:
            pairs.append(f"{key}=json")
    return base + "?" + "&".join(pairs)
