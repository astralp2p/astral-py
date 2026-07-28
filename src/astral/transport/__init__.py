"""Endpoint strings, `dial()`, `listen()` and `listen_any()`.

An endpoint is `"<proto>:<addr>"`, split on the **first** colon only, so
`tcp:127.0.0.1:8625` is proto `tcp` and addr `127.0.0.1:8625`. Six protos are
recognised: `tcp`, `unix`, `ws`, `wss`, `http`, `https`. `memu` and `memb` are
recognised and rejected -- they are astral-go's in-process `memconn` transport,
which `MemTransport` is deliberately not wire-compatible with.

`~/` in a unix path is expanded on dial **and** on listen. astral-go expands it
on listen only, so a Go client configured with the documented default
`unix:~/.apphost.sock` cannot dial it (astral-go bug G-15). The expansion here is
symmetric, and the divergence is deliberate.

The default endpoint prefers the unix socket when its path exists, because it is
cheaper and because the node's TCP listener is the one that wedges (design
section 3.9). Environment precedence over that default belongs to `client.py`;
this module reads no environment.

A dial fault is `NodeUnavailable`. It is the one error the retry decorator
retries, and it is safe to retry because no query has been sent yet. A `ws:`
upgrade the peer *answers* and refuses is a `TransportError` instead: the peer is
reachable, and a retry would collect the same refusal.

`tcp` and `unix` are sockets and are dialed and bound here. `ws` and `wss` are
sockets under an upgrade and are dialed through `websocket.py`, which hands back
a byte stream the session cannot tell from a socket. `http` and `https` carry one
query per request and cannot be dialed at all: `http.query()` is their entry
point, and `listen()` refuses every one of the four.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Final

from ..errors import NodeUnavailable, ParseError, TransportUnsupported
from .base import IncompleteRead, Server, Transport
from .mem import MemTransport
from .socket import (
    CLOSE_TIMEOUT,
    DEFAULT_MAX_PENDING,
    StreamServer,
    StreamTransport,
    _split_host_port,
    open_stream,
    serve_stream,
    serve_stream_any,
)

__all__ = [
    "CLOSE_TIMEOUT",
    "DEFAULT_TCP_ENDPOINT",
    "DEFAULT_UNIX_ENDPOINT",
    "Endpoint",
    "HTTP_PROTOCOLS",
    "IncompleteRead",
    "MemTransport",
    "STREAM_PROTOCOLS",
    "WS_PROTOCOLS",
    "Server",
    "StreamServer",
    "StreamTransport",
    "Transport",
    "default_endpoint",
    "dial",
    "expand_path",
    "listen",
    "listen_any",
    "parse_endpoint",
]

DEFAULT_TCP_ENDPOINT: Final = "tcp:127.0.0.1:8625"
DEFAULT_UNIX_ENDPOINT: Final = "unix:~/.apphost.sock"

# Protos this module binds, and dials as a socket.
STREAM_PROTOCOLS: Final = frozenset({"tcp", "unix"})
# Protos `dial()` reaches through the WebSocket upgrade. A byte stream, so the
# session state machine above it is the same one the socket gets.
WS_PROTOCOLS: Final = frozenset({"ws", "wss"})
# Protos that carry one query per request and have no session to dial.
HTTP_PROTOCOLS: Final = frozenset({"http", "https"})
# Protos the parser accepts and the WebSocket and HTTP transports serve.
_WEB_PROTOCOLS: Final = WS_PROTOCOLS | HTTP_PROTOCOLS
# astral-go's in-process transport. Recognised so the error names the reason.
_MEM_PROTOCOLS: Final = frozenset({"memu", "memb"})


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A parsed endpoint string."""

    proto: str
    addr: str

    def __str__(self) -> str:
        return f"{self.proto}:{self.addr}"

    @property
    def is_stream(self) -> bool:
        """Whether this proto is a socket `listen()` binds and `dial()` opens raw.

        False for the four web protocols. `ws:` and `wss:` are dialable all the
        same -- through the upgrade in `websocket.py` -- so this property says
        which mechanism reaches an endpoint, never whether one exists.
        """
        return self.proto in STREAM_PROTOCOLS


def parse_endpoint(endpoint: str) -> Endpoint:
    """Split `proto:addr` on the first colon.

    Raises `ParseError` for a malformed string and `TransportUnsupported` for a
    proto the SDK does not speak. A unix path keeps its `~/` here; expansion
    happens at dial and listen, so the parsed form round-trips.

    A `tcp` address is split here as well as at dial time, so `tcp:` and
    `tcp:notaport` -- the same typo in the same environment variable -- fail the
    same way, before any connection is attempted. A malformed endpoint is a
    `ParseError` and never a `NodeUnavailable`: the retry decorator retries
    `NodeUnavailable`, and no amount of retrying repairs a typo.
    """
    proto, sep, addr = endpoint.partition(":")
    if not sep:
        raise ParseError(f"invalid endpoint {endpoint!r}: expected proto:addr")
    if not proto:
        raise ParseError(f"invalid endpoint {endpoint!r}: empty protocol")
    if not addr:
        raise ParseError(f"invalid endpoint {endpoint!r}: empty address")
    if proto in _MEM_PROTOCOLS:
        raise TransportUnsupported(
            f"{proto}: astral-go's in-process transport has no wire format; "
            "use MemTransport in-process or tcp:/unix: across processes"
        )
    if proto not in STREAM_PROTOCOLS and proto not in _WEB_PROTOCOLS:
        raise TransportUnsupported(f"{proto}: unsupported protocol")
    if proto == "tcp":
        _split_host_port(addr)
    return Endpoint(proto, addr)


def expand_path(path: str) -> str:
    """Expand a leading `~/` in a unix socket path.

    Applied on dial as well as on listen, unlike astral-go (bug G-15).
    """
    if path.startswith("~/") or path == "~":
        return os.path.expanduser(path)
    return path


def default_endpoint() -> str:
    """The unix socket when its path exists, else the TCP endpoint."""
    if os.path.exists(expand_path(DEFAULT_UNIX_ENDPOINT[len("unix:") :])):
        return DEFAULT_UNIX_ENDPOINT
    return DEFAULT_TCP_ENDPOINT


async def dial(endpoint: str, *, timeout: float | None = None) -> Transport:
    """Connect to an endpoint.

    `timeout` bounds the connect only. The greeting that follows it is the
    session's deadline, and `CONNECT_TIMEOUT` covers both, because a saturated
    node accepts the socket and never greets.

    Every fault -- a refused connect, a missing socket file, a name that does not
    resolve, an expired `timeout` -- raises `NodeUnavailable` with the original
    exception attached.

    `ws:` and `wss:` dial through the WebSocket upgrade and hand back a byte
    stream on the `astral.binary.v1` subprotocol, so the session above them is
    the same state machine a socket gets. An upgrade the peer refuses is a
    `TransportError` and not a `NodeUnavailable`: the peer answered, and
    answering the same way again is all a retry would achieve.

    `http:` and `https:` are not dialable. An HTTP request carries its query in
    the request line, so there is no connection to open before a query exists;
    `astral.transport.http.query()` is the entry point.
    """
    parsed = parse_endpoint(endpoint)
    if parsed.proto in WS_PROTOCOLS:
        from .websocket import open_websocket

        return await open_websocket(endpoint, timeout=timeout)
    if parsed.proto in HTTP_PROTOCOLS:
        raise TransportUnsupported(
            f"{parsed.proto}: an http request carries its query in the request "
            "line, so there is no session to dial -- use "
            "astral.transport.http.query(endpoint, query_string)"
        )
    if not parsed.is_stream:  # pragma: no cover -- the parser accepts no other proto
        raise TransportUnsupported(f"{parsed.proto}: unsupported protocol")
    addr = expand_path(parsed.addr) if parsed.proto == "unix" else parsed.addr
    if timeout is None:
        try:
            return await open_stream(parsed.proto, addr, endpoint)
        except OSError as exc:
            raise NodeUnavailable(f"{endpoint}: {exc}") from exc

    # `opened` closes the one window where a connection could outlive a failed
    # dial: the deadline expiring between the connect completing and this scope
    # returning. A leaked connection burns one of the node's 32 apphost workers.
    opened: Transport | None = None
    try:
        async with asyncio.timeout(timeout):
            opened = await open_stream(parsed.proto, addr, endpoint)
        return opened
    except (OSError, TimeoutError) as exc:
        if opened is not None:
            await opened.aclose()
        raise NodeUnavailable(f"{endpoint}: {exc}") from exc


async def listen(
    endpoint: str,
    *,
    max_pending: int = DEFAULT_MAX_PENDING,
    unlink_stale: bool = False,
) -> Server:
    """Bind a local endpoint and return a server.

    The returned server's `endpoint` is the bound address, so an ephemeral port
    is resolved and can be handed to `apphost.register_handler`.
    """
    parsed = parse_endpoint(endpoint)
    if not parsed.is_stream:
        raise TransportUnsupported(f"{parsed.proto}: serving is tcp and unix only")
    addr = expand_path(parsed.addr) if parsed.proto == "unix" else parsed.addr
    return await serve_stream(
        parsed.proto, addr, max_pending=max_pending, unlink_stale=unlink_stale
    )


async def listen_any(
    proto: str = "tcp", *, max_pending: int = DEFAULT_MAX_PENDING
) -> Server:
    """Bind an ephemeral local address for the given proto."""
    if proto not in STREAM_PROTOCOLS:
        raise TransportUnsupported(f"{proto}: serving is tcp and unix only")
    return await serve_stream_any(proto, max_pending=max_pending)
