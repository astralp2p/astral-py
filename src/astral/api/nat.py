"""The ``nat`` protocol: enumerate NAT-traversal holes punched between peers.

UNDOCUMENTED. There is no ``astral-docs`` spec for the ``nat`` protocol; this
module is grounded ONLY in the astral-go source
(``api/nat/{module.go,hole.go,endpoint.go}`` and
``api/nat/client/list_holes.go``) and has NOT been verified against a live node.
Treat the wire layout, the object-type strings, and the ``time`` units as
best-effort until a running node confirms them.

A *hole* is the pair of connected UDP endpoints that results from a successful
``nat.punch`` between an *active* (dialling) and a *passive* (listening) peer.
``nat.list_holes`` streams the holes the node currently knows about, optionally
filtered to those involving a given peer.

Scope. Only the READ op ``nat.list_holes`` is implemented here. The other four
``nat`` methods from ``api/nat/module.go`` are node / signalling-side and are
OUT OF SCOPE for an app-facing client:

* ``nat.punch`` — initiate a hole-punch to a peer (signalling ceremony).
* ``nat.node_punch`` — the node-to-node punch half of that ceremony.
* ``nat.node_consume_hole`` — hand a freshly punched hole to the node's link
  layer.
* ``nat.set_enabled`` — toggle the node's NAT-traversal feature.

Object types (VERIFIED against the Go source, and DIFFERENT from the ``mod.*``
form the task brief guessed): astral-go's ``Hole.ObjectType()`` returns the bare
``"nat.hole"`` and ``Endpoint.ObjectType()`` the bare ``"nat.endpoint"`` (see
``api/nat/hole.go`` line 23 and ``api/nat/endpoint.go`` line 21) — there is no
``mod.`` prefix, matching the other ``api/nat`` types (``nat.punch_signal`` /
``nat.consume_hole_signal``). Both are registered under those exact strings so a
``Hole`` decodes over the binary channel.

Endpoint modelling. astral-go's ``nat.Endpoint`` is a CONCRETE struct
(``IP ip.IP`` + ``Port astral.Uint16``), so as a field of ``Hole`` it is INLINED
by ``astral.Objectify`` as a ``structValue`` with NO type tag (``objectify.go``
routes a ``reflect.Struct`` field to ``structValue``; ``struct_value.go``
``WriteTo`` writes each field's payload bare). It is therefore a ``("record",
NatEndpoint)`` field, NOT the polymorphic ``("object",)`` kind the task brief
assumed — an ``("object",)`` field would be a Go ``interface`` field carrying a
``string8(type)`` tag, which ``Hole``'s concrete endpoints do not. The wire form
is structurally identical to :class:`~astral.api.exonet.TcpEndpoint` (``ip.IP``
packs as astral ``bytes8``; ``astral.Uint16`` as ``uint16``); :class:`NatEndpoint`
is a self-contained copy so ``import astral.api.nat`` is enough to decode a hole
(no dependency on the exonet module) and so its object type is the ``nat.*`` one.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import List, Optional

from ..errors import ProtocolError
from ..record import Record
from ..registry import register
from . import Protocol

__all__ = ["Nat", "Hole", "NatEndpoint"]


def _ip_str(raw: bytes) -> str:
    """Format a raw IP address (4 or 16 bytes, NO length prefix) as a string.

    The ``("bytes", 8)`` reader has already stripped the astral ``bytes8`` length
    prefix (astral-go ``ip.IP.WriteTo`` packs an IPv4 as 4 bytes, an IPv6 as 16
    via ``astral.Bytes8``), so ``raw`` is the bare address body.
    """
    raw = bytes(raw)
    if len(raw) == 0:
        return ""
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    if len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    raise ProtocolError(f"nat.endpoint: unexpected IP length {len(raw)}")


def _ip_bytes(host: str) -> bytes:
    """Parse an IP host string to its raw 4/16 address bytes (no length prefix)."""
    if host == "":
        return b""
    try:
        return socket.inet_pton(socket.AF_INET, host)
    except OSError:
        pass
    try:
        return socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        raise ProtocolError(f"nat.endpoint: invalid IP {host!r}") from None


def _split_host_port(s: str) -> tuple:
    """Split ``"host:port"`` into ``(host, port)``, honouring the ``[ipv6]:port`` form."""
    if s.startswith("["):
        close = s.rfind("]")
        if close == -1 or close + 1 >= len(s) or s[close + 1] != ":":
            raise ProtocolError(f"nat.endpoint: malformed address {s!r}")
        return s[1:close], int(s[close + 2:])
    host, sep, port = s.rpartition(":")
    if sep == "":
        raise ProtocolError(f"nat.endpoint: malformed address {s!r}")
    return host, int(port)


@register("nat.endpoint")
@dataclass(frozen=True)
class NatEndpoint(Record):
    """A single NAT UDP endpoint: an IP address and a port (``nat.endpoint``).

    Wire type ``nat.endpoint`` (astral-go ``api/nat/endpoint.go``). Binary
    ``structValue``: ``IP`` (astral ``bytes8`` = ``("bytes", 8)``: a ``uint8``
    length then the 4/16 raw address bytes) then ``Port`` (``uint16``). Over the
    JSON transports astral-go ``MarshalText``\\ s the endpoint to the bare address
    string ``net.JoinHostPort(ip, port)`` (an IPv6 host bracketed), NOT a
    ``{Field: value}`` object — so :meth:`from_value` also accepts a bare address
    ``str`` and :meth:`encode_json` emits one, mirroring
    :class:`~astral.api.exonet.TcpEndpoint`.
    """

    TYPE = "nat.endpoint"
    FIELDS = (
        ("ip", "IP", ("bytes", 8)),
        ("port", "Port", "uint16"),
    )

    ip: bytes = b""
    port: int = 0

    @property
    def address(self) -> str:
        """The ``"ip:port"`` address string (IPv6 host bracketed, like Go)."""
        host = _ip_str(self.ip)
        if ":" in host:  # IPv6 -> net.JoinHostPort brackets it
            host = f"[{host}]"
        return f"{host}:{self.port}"

    @classmethod
    def from_value(cls, value):
        if isinstance(value, str):
            host, port = _split_host_port(value)
            return cls(ip=_ip_bytes(host), port=port)
        return super().from_value(value)

    def encode_json(self):
        return self.address


@register("nat.hole")
@dataclass(frozen=True)
class Hole(Record):
    """A pair of connected endpoints from a successful ``nat.punch`` (``nat.hole``).

    Wire type ``nat.hole`` (astral-go ``api/nat/hole.go``). Binary ``structValue``,
    fields IN STRUCT ORDER:

    * ``Nonce`` (``astral.Nonce`` → ``nonce64``: 8 raw bytes / a 16-hex string) —
      the punch nonce that identifies the hole.
    * ``ActiveIdentity`` (``*astral.Identity`` → ``identity``: a presence flag then
      the 33-byte compressed key) — the dialling peer, ``""`` if absent.
    * ``ActiveEndpoint`` (``nat.Endpoint`` → ``("record", NatEndpoint)``: inlined,
      NO type tag) — the dialling peer's UDP endpoint.
    * ``PassiveIdentity`` (``*astral.Identity`` → ``identity``) — the listening peer.
    * ``PassiveEndpoint`` (``nat.Endpoint`` → ``("record", NatEndpoint)``) — the
      listening peer's UDP endpoint.
    * ``CreatedAt`` (``astral.Time`` → ``time``) — when the hole was punched. This
      is a UnixNano ``uint64`` over binary / an RFC3339 string over the JSON
      transports (astral-go ``astral.Time`` is ``UnixNano``); the units are NOT
      confirmed against a live node, so do not compare ``created_at`` across
      transports.

    The two endpoint fields default to an empty :class:`NatEndpoint` (astral-go's
    zero-value struct), NOT ``None`` — they are inlined value fields with no
    nil-flag, so a hole always carries two endpoints on the wire.
    """

    TYPE = "nat.hole"
    FIELDS = (
        ("nonce", "Nonce", "nonce64"),
        ("active_identity", "ActiveIdentity", "identity"),
        ("active_endpoint", "ActiveEndpoint", ("record", NatEndpoint)),
        ("passive_identity", "PassiveIdentity", "identity"),
        ("passive_endpoint", "PassiveEndpoint", ("record", NatEndpoint)),
        ("created_at", "CreatedAt", "time"),
    )

    nonce: str = ""
    active_identity: str = ""
    active_endpoint: NatEndpoint = NatEndpoint()
    passive_identity: str = ""
    passive_endpoint: NatEndpoint = NatEndpoint()
    created_at: object = 0


class Nat(Protocol):
    """Typed helper for the ``nat`` protocol's read op (``list_holes``).

    UNDOCUMENTED and grounded only in astral-go (see the module docstring); only
    ``list_holes`` is implemented — the punch / signalling / set-enabled methods
    are node-side and out of scope.
    """

    def list_holes(self, with_: Optional[str] = None) -> List[Hole]:
        """List the NAT holes the node knows about as :class:`Hole`\\ s.

        Streams one ``nat.hole`` object per hole, then an ``eos`` (astral-go
        ``api/nat/client/list_holes.go`` collects them via ``channel.Collect`` +
        ``channel.BreakOnEOS``). ``with_`` is an optional peer filter — a peer
        identity / alias string — sent as the ``with`` query arg; when omitted the
        node returns every hole (astral-go sends the arg only for a non-empty
        ``with``).
        """
        args = {"with": with_} if with_ is not None else {}
        return [
            Hole.from_value(obj.value)
            for obj in self.client.call("nat.list_holes", args)
        ]
