"""The high-level :class:`Client` and the :func:`connect` entry point."""

from __future__ import annotations

from typing import Any, List, Mapping, Optional

from .encoding import Zone, build_query_string
from .stream import Stream
from .transport.base import (
    UNSET,
    HandlerFn,
    HostInfo,
    Transport,
    default_endpoint,
    discover_token,
    parse_endpoint,
)

__all__ = ["Client", "connect", "build_transport"]


def build_transport(endpoint, token: Optional[str], **kwargs: Any) -> Transport:
    """Construct the right :class:`Transport` for a parsed ``endpoint``."""
    scheme = endpoint.scheme
    if scheme in ("unix", "tcp"):
        from .transport.binary import BinaryTransport

        return BinaryTransport(endpoint, token, **kwargs)
    if scheme in ("ws", "wss"):
        from .transport.websocket import WebSocketTransport

        return WebSocketTransport(endpoint, token, **kwargs)
    if scheme in ("http", "https"):
        from .transport.http import HttpTransport

        return HttpTransport(endpoint, token, **kwargs)
    raise ValueError(f"unsupported endpoint scheme: {scheme!r}")


class Client:
    """A connection to the local astrald node's apphost surface.

    Construct one with :func:`connect`. The client routes outbound queries and,
    on the binary/WebSocket transports, serves inbound ones. Protocol helpers
    are available as attributes (``client.dir``, ``client.tree``,
    ``client.crypto``, ``client.objects``, ``client.apphost``).
    """

    def __init__(self, transport: Transport) -> None:
        self._transport = transport
        self._apphost = None
        self._dir = None
        self._tree = None
        self._crypto = None
        self._objects = None

    # -- identity -----------------------------------------------------------
    @property
    def host(self) -> HostInfo:
        """Identity info captured during the handshake."""
        return self._transport.host

    @property
    def identity(self) -> str:
        """The host node's identity (hex public key)."""
        return self._transport.host.identity

    @property
    def alias(self) -> str:
        """The host node's local alias."""
        return self._transport.host.alias

    @property
    def guest_id(self) -> str:
        """This client's authenticated guest identity (``""`` if anonymous)."""
        return self._transport.host.guest_id

    @property
    def supports_serving(self) -> bool:
        """Whether the active transport can serve inbound queries."""
        return self._transport.supports_serving

    @property
    def transport(self) -> Transport:
        return self._transport

    # -- queries ------------------------------------------------------------
    def query(
        self,
        op: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        target: Optional[str] = None,
        caller: Any = UNSET,
        zone: Any = Zone.DEFAULT,
        filters: Optional[List[str]] = None,
    ) -> Stream:
        """Route a query and return its :class:`Stream` once accepted.

        ``op`` is an operation name (``"dir.resolve"``) optionally followed by
        its own query string (``"dir.resolve?name=alice"``). Extra ``args`` are
        text-encoded and appended.
        """
        if args is None and "?" in op:
            query_string = op
        else:
            query_string = build_query_string(op, args)
        return self._transport.query(
            query_string, target=target, caller=caller, zone=zone, filters=filters
        )

    def call(
        self,
        op: str,
        args: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> List:
        """Run a query and collect all result objects (closing the stream).

        Raises :class:`~astral.errors.RemoteError` if the op emits an
        ``error_message``.
        """
        with self.query(op, args, **kwargs) as stream:
            return list(stream.results())

    def call_one(
        self,
        op: str,
        args: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Run a query and return the value of its first result object."""
        with self.query(op, args, **kwargs) as stream:
            return stream.value()

    # -- serving ------------------------------------------------------------
    def register(self, identity: str, handler: HandlerFn):
        """Register ``handler`` for inbound queries targeting ``identity``.

        Returns a :class:`~astral.transport.session.Registration`; call
        ``unregister()`` (or use it as a context manager) to stop serving.
        """
        return self._transport.register(identity, handler)

    def serve(self, handler: HandlerFn, identity: Optional[str] = None):
        """Register ``handler`` for this client's own identity (``guest_id``)."""
        target = identity or self.guest_id
        if not target:
            raise ValueError(
                "no identity to serve; authenticate with a token or pass identity="
            )
        return self.register(target, handler)

    # -- common ops ---------------------------------------------------------
    def whoami(self) -> str:
        """Return the caller's identity as authenticated by the host."""
        return self.call_one("apphost.whoami")

    def ping(self) -> bool:
        """Re-run the handshake to confirm the node is reachable."""
        self._transport.connect()
        return True

    # -- protocol helpers ---------------------------------------------------
    @property
    def apphost(self):
        if self._apphost is None:
            from .api.apphost import Apphost

            self._apphost = Apphost(self)
        return self._apphost

    @property
    def dir(self):
        if self._dir is None:
            from .api.dir import Dir

            self._dir = Dir(self)
        return self._dir

    @property
    def tree(self):
        if self._tree is None:
            from .api.tree import Tree

            self._tree = Tree(self)
        return self._tree

    @property
    def crypto(self):
        if self._crypto is None:
            from .api.crypto import Crypto

            self._crypto = Crypto(self)
        return self._crypto

    @property
    def objects(self):
        if self._objects is None:
            from .api.objects import Objects

            self._objects = Objects(self)
        return self._objects

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        """Release transport resources."""
        self._transport.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        ep = self._transport.endpoint
        return f"Client({ep.scheme}:{ep.address!r}, identity={self.identity[:12]!r}...)"


def connect(
    target: Optional[str] = None,
    *,
    token: Optional[str] = None,
    handshake: bool = True,
    **kwargs: Any,
) -> Client:
    """Connect to the local node and return a :class:`Client`.

    ``target`` is an endpoint string (see
    :func:`~astral.transport.base.parse_endpoint`); when omitted, a sensible
    local default is chosen (unix socket if present, else TCP). ``token`` (or
    the ``ASTRALD_TOKEN`` environment variable) authenticates the session;
    without one the client is anonymous.

    By default the handshake runs immediately so :attr:`Client.identity` is
    populated and connectivity is verified; pass ``handshake=False`` to defer.
    """
    endpoint = parse_endpoint(target) if target else default_endpoint()
    transport = build_transport(endpoint, discover_token(token), **kwargs)
    client = Client(transport)
    if handshake:
        transport.connect()
    return client
