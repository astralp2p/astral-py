"""The apphost session protocol, shared by the channel-based transports.

The binary and WebSocket transports differ only in how a :class:`Channel`
frames objects; the session handshake and the query/register/attach flows are
identical and live here (``topics/astral-ipc.md``). A concrete transport only
has to implement :meth:`ChannelTransport._open_channel`.
"""

from __future__ import annotations

import logging
import secrets
import threading
from typing import Any, List, Optional

from ..errors import (
    AuthError,
    ConnectError,
    ProtocolError,
    query_error_for_code,
)
from ..messages import (
    AttachQueryMsg,
    AuthSuccessMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    QueryAcceptedMsg,
    QueryRejectedMsg,
    RegisterServiceMsg,
    RejectIncomingMsg,
)
from ..objects import AstralObject
from ..stream import Stream
from .base import UNSET, Channel, HandlerFn, HostInfo, Transport

logger = logging.getLogger("astral")

__all__ = ["ChannelTransport", "Registration", "IncomingQuery", "new_nonce"]

# Handler reject code used when a handler raises (mirrors apphost-js: 0xff).
_HANDLER_ERROR_CODE = 0xFF


def new_nonce() -> str:
    """Generate a fresh 16-hex-character nonce."""
    return secrets.token_hex(8)


class ChannelTransport(Transport):
    """Base for transports that speak the apphost protocol over a channel."""

    supports_serving = True

    def _open_channel(self) -> Channel:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- handshake ----------------------------------------------------------
    def _handshake(self, channel: Channel, *, authenticate: bool = True) -> HostInfo:
        info = channel.recv()
        if not isinstance(info, HostInfoMsg):
            raise ConnectError(f"expected host_info, got {info!r}")
        guest_id = ""
        if authenticate and self.token:
            channel.send(AuthTokenMsg(Token=self.token))
            reply = channel.recv()
            if isinstance(reply, AuthSuccessMsg):
                guest_id = reply.GuestID
            elif isinstance(reply, ErrorMsg):
                raise AuthError(f"auth failed: {reply.Code}")
            else:
                raise ProtocolError(f"unexpected reply to auth token: {reply!r}")
        return HostInfo(info.Identity, info.Alias, guest_id)

    def connect(self) -> HostInfo:
        channel = self._open_channel()
        try:
            self.host = self._handshake(channel)
        finally:
            channel.close()
        return self.host

    # -- outbound queries ---------------------------------------------------
    def query(
        self,
        query_string: str,
        *,
        target: Optional[str] = None,
        caller: Any = UNSET,
        zone: Any = "dvn",
        filters: Optional[List[str]] = None,
    ) -> Stream:
        channel = self._open_channel()
        try:
            info = self._handshake(channel)
            caller_id = info.guest_id if caller is UNSET else (caller or "")
            target_id = info.identity if target is None else target
            nonce = new_nonce()
            from ..messages import RouteQueryMsg

            channel.send(
                RouteQueryMsg(
                    Nonce=nonce,
                    Caller=caller_id,
                    Target=target_id,
                    Query=query_string,
                    Zone=zone,
                    Filters=list(filters or []),
                )
            )
            reply = channel.recv()
            if isinstance(reply, QueryAcceptedMsg):
                return Stream(channel, nonce=nonce, transport=self)
            if isinstance(reply, QueryRejectedMsg):
                from ..errors import QueryRejected

                raise QueryRejected(reply.Code)
            if isinstance(reply, ErrorMsg):
                raise query_error_for_code(reply.Code)
            raise ProtocolError(f"unexpected reply to route_query: {reply!r}")
        except BaseException:
            channel.close()
            raise

    # -- inbound queries ----------------------------------------------------
    def register(self, identity: str, handler: HandlerFn) -> "Registration":
        channel = self._open_channel()
        try:
            self._handshake(channel)
            channel.send(RegisterServiceMsg(Identity=identity))
            reply = channel.recv()
            if isinstance(reply, ErrorMsg):
                raise query_error_for_code(reply.Code)
            if not (isinstance(reply, AstralObject) and reply.is_ack):
                raise ProtocolError(f"unexpected reply to register_service: {reply!r}")
        except BaseException:
            channel.close()
            raise
        registration = Registration(self, channel, identity, handler)
        registration._start()
        return registration

    def attach(self, query_id: str) -> Stream:
        channel = self._open_channel()
        try:
            # Per the protocol the QueryID is the pairing token; no auth needed.
            self._handshake(channel, authenticate=False)
            channel.send(AttachQueryMsg(QueryID=query_id))
            reply = channel.recv()
            if isinstance(reply, AstralObject) and reply.is_ack:
                return Stream(channel, nonce=query_id, responder=True, transport=self)
            if isinstance(reply, ErrorMsg):
                raise query_error_for_code(reply.Code)
            raise ProtocolError(f"unexpected reply to attach_query: {reply!r}")
        except BaseException:
            channel.close()
            raise

    def bind(self, token: str) -> Stream:
        """Open an ``apphost.bind`` session bound to handler ``token``.

        Keeping the returned stream open ties the lifetime of handlers
        registered with ``token`` (via ``apphost.register_handler``) to it;
        closing the stream removes them (``topics/astral-ipc.md``).
        """
        stream = self.query("apphost.bind")
        ack = stream.recv()
        if ack is None or not ack.is_ack:
            stream.close()
            raise ProtocolError(f"unexpected reply to apphost.bind: {ack!r}")
        stream.send(BindMsg(Token=token))
        return stream

    def close(self) -> None:
        # Channel transports open a fresh connection per operation; nothing to
        # hold onto here. Active streams/registrations own their connections.
        pass


class IncomingQuery:
    """An inbound query delivered to a registered handler."""

    def __init__(self, registration: "Registration", msg: IncomingQueryMsg) -> None:
        self._registration = registration
        self.query_id: str = msg.QueryID
        self.caller: str = msg.Caller
        self.target: str = msg.Target
        self.query: str = msg.Query
        self._answered = False
        self._lock = threading.Lock()

    @property
    def op(self) -> str:
        """The operation name (the query string without its parameters)."""
        return self.query.split("?", 1)[0]

    def accept(self) -> Stream:
        """Accept the query; returns the responder-side :class:`Stream`.

        Must be called within the host's attach timeout (5 s).
        """
        with self._lock:
            if self._answered:
                raise RuntimeError("incoming query already answered")
            self._answered = True
        return self._registration._transport.attach(self.query_id)

    def reject(self, code: int = 1) -> None:
        """Reject the query with a non-zero uint8 ``code`` (1–255)."""
        if not 1 <= code <= 255:
            raise ValueError("reject code must be in range 1..255")
        with self._lock:
            if self._answered:
                raise RuntimeError("incoming query already answered")
            self._answered = True
        self._registration._send_reject(self.query_id, code)

    @property
    def answered(self) -> bool:
        return self._answered

    def __repr__(self) -> str:
        return (
            f"IncomingQuery(query={self.query!r}, caller={self.caller!r}, "
            f"id={self.query_id!r})"
        )


class Registration:
    """A live service registration; closing it unregisters the handler."""

    def __init__(
        self,
        transport: ChannelTransport,
        channel: Channel,
        identity: str,
        handler: HandlerFn,
    ) -> None:
        self._transport = transport
        self._channel = channel
        self.identity = identity
        self._handler = handler
        self._send_lock = threading.Lock()
        self._closed = False
        self._thread: Optional[threading.Thread] = None

    def _start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name=f"astral-registration-{self.identity[:8]}", daemon=True
        )
        self._thread.start()

    def _loop(self) -> None:
        while not self._closed:
            try:
                item = self._channel.recv()
            except Exception:
                break
            if item is None:
                break
            if isinstance(item, IncomingQueryMsg):
                query = IncomingQuery(self, item)
                worker = threading.Thread(
                    target=self._dispatch, args=(query,), daemon=True
                )
                worker.start()
            # Stray frames are ignored, per the protocol.
        self._closed = True

    def _dispatch(self, query: IncomingQuery) -> None:
        try:
            self._handler(query)
        except Exception:
            logger.exception("astral query handler raised for %r", query)
            if not query.answered:
                try:
                    query.reject(_HANDLER_ERROR_CODE)
                except Exception:
                    pass

    def _send_reject(self, query_id: str, code: int) -> None:
        with self._send_lock:
            self._channel.send(RejectIncomingMsg(QueryID=query_id, Code=code))

    def unregister(self) -> None:
        """Unregister the handler and close the registration connection."""
        if self._closed:
            self._channel.close()
            return
        self._closed = True
        self._channel.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> "Registration":
        return self

    def __exit__(self, *exc) -> None:
        self.unregister()

    def __repr__(self) -> str:
        return f"Registration(identity={self.identity!r}, closed={self._closed})"
