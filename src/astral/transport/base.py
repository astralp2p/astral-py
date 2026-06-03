"""Shared transport plumbing: the channel abstraction and endpoint parsing.

A :class:`Channel` is a bidirectional link that carries *objects* (and, after a
query is accepted, optionally raw bytes). The binary and WebSocket transports
provide full channels; the HTTP transport provides a read-only one.

Control messages (the ``mod.apphost.*`` :class:`~astral.messages.Message`
types) and data objects (:class:`~astral.objects.AstralObject`) travel over the
same channel; :meth:`Channel.recv` returns a ``Message`` for recognised control
types and an ``AstralObject`` otherwise.
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional, Tuple, Union
from urllib.parse import urlsplit

from ..encoding import Zone
from ..errors import NotSupported
from ..messages import Message
from ..objects import AstralObject

if TYPE_CHECKING:
    from ..stream import Stream

__all__ = [
    "Channel",
    "Transport",
    "HostInfo",
    "Endpoint",
    "parse_endpoint",
    "default_endpoint",
    "discover_token",
    "Item",
    "UNSET",
    "HandlerFn",
]

# Sentinel for "caller not specified" — distinct from an explicit anonymous
# caller (``None`` / zero identity).
UNSET: Any = object()

# A handler for inbound queries: ``handler(incoming_query) -> None``.
HandlerFn = Callable[[Any], None]

Item = Union[AstralObject, Message]

# Default listener addresses (``topics/astral-ipc.md``, ``topics/*-transport.md``).
DEFAULT_UNIX_SOCKET = "~/.apphost.sock"
DEFAULT_TCP = "127.0.0.1:8625"
DEFAULT_HTTP_PORT = 8624
DEFAULT_WS_PATH = "/.ws"


@dataclass(frozen=True)
class HostInfo:
    """Identity information captured during the session handshake."""

    identity: str = ""
    alias: str = ""
    guest_id: str = ""


@dataclass(frozen=True)
class Endpoint:
    """A parsed connection endpoint."""

    scheme: str  # "unix" | "tcp" | "http" | "https" | "ws" | "wss"
    address: str  # path for unix; host:port otherwise
    url: str  # full URL form for http/ws transports

    @property
    def host_port(self) -> Tuple[str, int]:
        host, _, port = self.address.rpartition(":")
        return host or "127.0.0.1", int(port)


def parse_endpoint(target: str) -> Endpoint:
    """Parse a connection string into an :class:`Endpoint`.

    Accepted forms::

        unix:~/.apphost.sock      unix:/run/apphost.sock
        tcp:127.0.0.1:8625        tcp://127.0.0.1:8625      127.0.0.1:8625
        http://localhost:8624     https://host:8624
        ws://127.0.0.1:8624/.ws   wss://host/.ws
    """
    target = target.strip()
    scheme, sep, rest = target.partition(":")
    scheme = scheme.lower()

    if scheme == "unix":
        return Endpoint("unix", os.path.expanduser(rest), target)

    if scheme in ("http", "https"):
        return Endpoint(scheme, urlsplit(target).netloc, target)

    if scheme in ("ws", "wss"):
        split = urlsplit(target)
        path = split.path or DEFAULT_WS_PATH
        url = f"{scheme}://{split.netloc}{path}"
        return Endpoint(scheme, split.netloc, url)

    if scheme == "tcp":
        addr = rest[2:] if rest.startswith("//") else rest
        return Endpoint("tcp", addr, target)

    # Bare "host:port" → TCP binary.
    if sep and rest.isdigit():
        return Endpoint("tcp", target, target)

    raise ValueError(f"cannot parse endpoint: {target!r}")


def default_endpoint() -> Endpoint:
    """Pick a default endpoint for the local node.

    Honours ``ASTRALD_ENDPOINT`` / ``ASTRAL_ENDPOINT``; otherwise prefers the
    unix socket (the canonical local IPC) when it exists, falling back to TCP.
    """
    env = os.environ.get("ASTRALD_ENDPOINT") or os.environ.get("ASTRAL_ENDPOINT")
    if env:
        return parse_endpoint(env)
    sock = os.path.expanduser(DEFAULT_UNIX_SOCKET)
    if os.path.exists(sock):
        return Endpoint("unix", sock, f"unix:{sock}")
    return parse_endpoint(f"tcp:{DEFAULT_TCP}")


def discover_token(explicit: Optional[str]) -> Optional[str]:
    """Resolve an auth token from the argument or the environment.

    Checks (in order): the explicit argument, then ``ASTRALD_TOKEN`` /
    ``ASTRAL_AUTH_TOKEN`` / ``ASTRAL_TOKEN``. Returns ``None`` if none is set
    (anonymous access, allowed by the host's ``AllowAnonymous`` default).
    """
    if explicit:
        return explicit
    for var in ("ASTRALD_TOKEN", "ASTRAL_AUTH_TOKEN", "ASTRAL_TOKEN"):
        value = os.environ.get(var)
        if value:
            return value
    return None


class Channel(abc.ABC):
    """A bidirectional object link to the host."""

    @abc.abstractmethod
    def send(self, item: Item) -> None:
        """Send a control message or data object."""

    @abc.abstractmethod
    def recv(self) -> Optional[Item]:
        """Receive the next message/object, or ``None`` at end of stream."""

    def send_bytes(self, data: bytes) -> None:
        """Write raw bytes to the underlying stream (post-acceptance)."""
        raise NotSupported("raw byte writes are not supported on this transport")

    def recv_bytes(self, size: int = -1) -> bytes:
        """Read raw bytes from the underlying stream (post-acceptance).

        ``size < 0`` reads until end of stream. Returns ``b""`` at EOF.
        """
        raise NotSupported("raw byte reads are not supported on this transport")

    @abc.abstractmethod
    def close(self) -> None:
        """Close the channel and its underlying connection."""

    def __enter__(self) -> "Channel":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class Transport(abc.ABC):
    """A connection strategy to the local node (binary / WebSocket / HTTP)."""

    #: Whether this transport can register handlers and serve inbound queries.
    supports_serving: bool = False

    def __init__(self, endpoint: Endpoint, token: Optional[str]) -> None:
        self.endpoint = endpoint
        self.token = token
        self.host = HostInfo()

    @abc.abstractmethod
    def connect(self) -> HostInfo:
        """Perform the initial handshake and capture host identity info."""

    @abc.abstractmethod
    def query(
        self,
        query_string: str,
        *,
        target: Optional[str] = None,
        caller: Any = UNSET,
        zone: "Zone" = Zone.DEFAULT,
        filters: Optional[list] = None,
    ) -> "Stream":
        """Route an outbound query and return its :class:`Stream` once accepted."""

    def register(self, identity: str, handler: HandlerFn) -> Any:
        """Register a handler for inbound queries to ``identity``."""
        raise NotSupported(
            f"{type(self).__name__} does not support serving inbound queries"
        )

    def attach(self, query_id: str) -> "Stream":
        """Attach to an inbound query as the responder (internal)."""
        raise NotSupported(
            f"{type(self).__name__} does not support serving inbound queries"
        )

    @abc.abstractmethod
    def close(self) -> None:
        """Release any persistent resources held by the transport."""
