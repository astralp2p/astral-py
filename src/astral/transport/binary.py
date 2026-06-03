"""Native binary apphost transport over a Unix-domain or TCP socket.

This is the canonical local *Astral IPC* (``topics/astral-ipc.md``): a binary
:class:`~astral.transport.base.Channel` whose frames are
``string8(type) ++ bytes32(payload)`` (``core-primitives/channel.md``). The
session logic is inherited from :class:`ChannelTransport`.
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

from ..codec import channel_frame
from ..errors import ConnectError
from ..messages import REGISTRY, Message
from ..objects import AstralObject
from ..payload import decode_payload, encode_payload
from .base import Channel, Endpoint
from .session import ChannelTransport

__all__ = ["BinaryChannel", "BinaryTransport"]

_RECV_SIZE = 65536


class BinaryChannel(Channel):
    """A binary object channel over a connected stream socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._rbuf = bytearray()
        self._send_lock = threading.Lock()
        self._closed = False

    # -- low-level socket IO ------------------------------------------------
    def _safe_recv(self) -> bytes:
        try:
            return self._sock.recv(_RECV_SIZE)
        except OSError:
            return b""

    def _read_exact(self, n: int) -> bytes:
        while len(self._rbuf) < n:
            chunk = self._safe_recv()
            if not chunk:
                raise EOFError
            self._rbuf += chunk
        out = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return out

    def _sendall(self, data: bytes) -> None:
        with self._send_lock:
            if self._closed:
                raise ConnectError("channel is closed")
            self._sock.sendall(data)

    # -- framed objects -----------------------------------------------------
    def send(self, item) -> None:
        if isinstance(item, Message):
            frame = channel_frame(item.TYPE, item.encode_binary())
        elif isinstance(item, AstralObject):
            frame = channel_frame(item.type, encode_payload(item.type, item.value))
        else:  # pragma: no cover - defensive
            raise TypeError(f"cannot send {type(item).__name__} on a channel")
        self._sendall(frame)

    def recv(self) -> Optional[object]:
        # A clean EOF at a frame boundary ends the stream.
        while not self._rbuf:
            chunk = self._safe_recv()
            if not chunk:
                return None
            self._rbuf += chunk
        type_len = self._rbuf[0]
        del self._rbuf[:1]
        try:
            type_bytes = self._read_exact(type_len) if type_len else b""
            payload_len = int.from_bytes(self._read_exact(4), "big")
            payload = self._read_exact(payload_len) if payload_len else b""
        except EOFError:
            raise ConnectError("connection closed mid-frame")
        obj_type = type_bytes.decode("utf-8")
        message_cls = REGISTRY.get(obj_type)
        if message_cls is not None:
            return message_cls.decode_binary(payload)
        return AstralObject(obj_type, decode_payload(obj_type, payload))

    # -- raw bytes (post-acceptance bytestream) -----------------------------
    def send_bytes(self, data: bytes) -> None:
        self._sendall(bytes(data))

    def recv_bytes(self, size: int = -1) -> bytes:
        if size < 0:
            chunks = [bytes(self._rbuf)]
            self._rbuf.clear()
            while True:
                chunk = self._safe_recv()
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        while len(self._rbuf) < size:
            chunk = self._safe_recv()
            if not chunk:
                break
            self._rbuf += chunk
        out = bytes(self._rbuf[:size])
        del self._rbuf[:size]
        return out

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


class BinaryTransport(ChannelTransport):
    """Opens binary channels to a Unix-socket or TCP apphost endpoint."""

    def __init__(
        self,
        endpoint: Endpoint,
        token: Optional[str],
        *,
        connect_timeout: float = 10.0,
    ) -> None:
        super().__init__(endpoint, token)
        self.connect_timeout = connect_timeout

    def _open_channel(self) -> Channel:
        ep = self.endpoint
        if ep.scheme == "unix":
            family = getattr(socket, "AF_UNIX", None)
            if family is None:
                raise ConnectError("unix sockets are not supported on this platform")
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            try:
                sock.connect(ep.address)
            except OSError as exc:
                sock.close()
                raise ConnectError(f"cannot connect to {ep.address}: {exc}") from exc
        elif ep.scheme == "tcp":
            host, port = ep.host_port
            try:
                sock = socket.create_connection((host, port), timeout=self.connect_timeout)
            except OSError as exc:
                raise ConnectError(f"cannot connect to {host}:{port}: {exc}") from exc
        else:  # pragma: no cover - guarded by the dispatcher in client.py
            raise ConnectError(f"binary transport cannot use scheme {ep.scheme!r}")
        # Blocking IO for the lifetime of the channel (queries may stream).
        sock.settimeout(None)
        return BinaryChannel(sock)
