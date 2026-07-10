"""Exonet endpoint records: TCP, Tor and gateway network addresses.

Reference: astral-go ``api/tcp/endpoint.go``, ``api/tor/endpoint.go`` and
``api/gateway/endpoint.go``. An *exonet* endpoint identifies a routable network
address; each is an ``astral.Object`` registered under its ``mod.<net>.endpoint``
type so the binary channel decodes it to a typed :class:`~astral.record.Record`.

This is a PURE-RECORD module: it registers the wire types (so ``import astral.api``
fires the ``@register`` side effects and the nodes/nat protocols can decode
endpoints) but does not add a :class:`~astral.api.Protocol` helper or a
:class:`~astral.client.Client` property — there is no dedicated "exonet" op surface.

The one wrinkle: astral-go JSON-marshals every endpoint as a bare ADDRESS STRING
(via ``MarshalJSON``/``MarshalText``), not as a ``{Field: value}`` object — TCP as
``"ip:port"``, Tor as ``"<base32>.onion:port"``, gateway as
``"<gatewayID>:<targetID>"``. So each record overrides :meth:`from_value` to accept
EITHER the fields dict (the generic record form) OR a bare address ``str``, and
:meth:`encode_json` to emit the address string. The BINARY form is the plain
astral ``structValue`` of the fields, which the declarative ``FIELDS`` schema
already produces.
"""

from __future__ import annotations

import base64
import socket
from dataclasses import dataclass

from ..codec import BinaryReader, BinaryWriter
from ..errors import ProtocolError
from ..record import Record
from ..registry import register

__all__ = ["TcpEndpoint", "TorEndpoint", "GatewayEndpoint"]

# astral-go's zero identity stringifies to 66 hex zeros (astral.anyoneKey), while
# astral-py's "identity" kind represents the zero identity as the empty string.
_ZERO_IDENTITY_HEX = "00" * 33


def _ip_str(raw: bytes) -> str:
    """Format a raw IP address (4 or 16 bytes, NO length prefix) as a string.

    The ``("bytes", 8)`` reader has already stripped the astral ``bytes8`` length
    prefix, so ``raw`` is the bare address body — 4 bytes IPv4, 16 bytes IPv6.
    (Contrast ``api/ip.py``'s ``_ip_str``, which drops a leading length byte
    because it sees the un-stripped ``bytes8`` payload.)
    """
    raw = bytes(raw)
    if len(raw) == 0:
        return ""
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    if len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    raise ProtocolError(f"mod.tcp.endpoint: unexpected IP length {len(raw)}")


def _ip_bytes(host: str) -> bytes:
    """Parse an IP host string to its raw 4/16 address bytes (no length prefix).

    Mirrors astral-go ``ip.IP.WriteTo``: an IPv4 address packs to 4 bytes, an IPv6
    address to 16. The empty host is the empty (nil) IP.
    """
    if host == "":
        return b""
    try:
        return socket.inet_pton(socket.AF_INET, host)
    except OSError:
        pass
    try:
        return socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        raise ProtocolError(f"mod.tcp.endpoint: invalid IP {host!r}") from None


def _split_host_port(s: str) -> tuple:
    """Split ``"host:port"`` into ``(host, port)``, honouring the ``[ipv6]:port`` form."""
    if s.startswith("["):
        # Bracketed IPv6 literal: "[::1]:8080".
        close = s.rfind("]")
        if close == -1 or close + 1 >= len(s) or s[close + 1] != ":":
            raise ProtocolError(f"mod.tcp.endpoint: malformed address {s!r}")
        return s[1:close], int(s[close + 2:])
    host, sep, port = s.rpartition(":")
    if sep == "":
        raise ProtocolError(f"mod.tcp.endpoint: malformed address {s!r}")
    return host, int(port)


@register("mod.tcp.endpoint")
@dataclass(frozen=True)
class TcpEndpoint(Record):
    """A TCP endpoint: an IP address and a port (astral-go ``api/tcp/endpoint.go``).

    Binary ``structValue``: ``IP`` (astral ``bytes8`` = ``("bytes", 8)``) then
    ``Port`` (``uint16``). JSON: the bare address string ``"ip:port"``
    (``net.JoinHostPort``, so an IPv6 host is bracketed).
    """

    TYPE = "mod.tcp.endpoint"
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


@register("mod.tor.endpoint")
@dataclass(frozen=True)
class TorEndpoint(Record):
    """A Tor endpoint: a 35-byte digest and a port (astral-go ``api/tor/endpoint.go``).

    Binary ``structValue``: ``Digest`` (35 RAW bytes, no length prefix — astral-go's
    ``tor.Digest.WriteTo`` writes the slice verbatim and ``ReadFrom`` reads exactly
    ``DigestSize == 35``) then ``Port`` (``uint16``). Because the digest is a
    fixed-width raw field the declarative scalar/composite kinds can't express it, so
    the binary codec is overridden here. JSON: the bare address string
    ``"<base32-lower>.onion:port"`` (``tor.Endpoint.MarshalText``).
    """

    TYPE = "mod.tor.endpoint"
    DIGEST_SIZE = 35
    FIELDS = (
        ("digest", "Digest", ("bytes", 8)),  # nominal; binary is overridden (raw 35)
        ("port", "Port", "uint16"),
    )

    digest: bytes = b""
    port: int = 0

    # -- address / text form ------------------------------------------------
    @property
    def address(self) -> str:
        """The ``"<base32-lower>.onion:port"`` address (``tor.Endpoint.MarshalText``)."""
        onion = base64.b32encode(bytes(self.digest)).decode("ascii").lower() + ".onion"
        return f"{onion}:{self.port}"

    @staticmethod
    def _digest_from_onion(host: str) -> bytes:
        s = host.upper()
        if s.endswith(".ONION"):
            s = s[: -len(".ONION")]
        return base64.b32decode(s)

    @classmethod
    def from_value(cls, value):
        if isinstance(value, str):
            host, _sep, port = value.rpartition(":")
            if _sep == "":
                raise ProtocolError(f"mod.tor.endpoint: malformed address {value!r}")
            return cls(digest=cls._digest_from_onion(host), port=int(port))
        return super().from_value(value)

    def encode_json(self):
        return self.address

    # -- binary: Digest is 35 raw bytes with NO length prefix ---------------
    def write_to(self, writer: BinaryWriter) -> BinaryWriter:
        raw = bytes(self.digest)
        if raw and len(raw) != self.DIGEST_SIZE:
            raise ProtocolError(
                f"mod.tor.endpoint: digest must be {self.DIGEST_SIZE} bytes, got {len(raw)}"
            )
        writer.raw(raw.ljust(self.DIGEST_SIZE, b"\x00"))
        writer.u16(int(self.port))
        return writer

    @classmethod
    def read_from(cls, reader: BinaryReader) -> "TorEndpoint":
        digest = reader.raw(cls.DIGEST_SIZE)
        port = reader.u16()
        return cls(digest=digest, port=port)


@register("mod.gateway.endpoint")
@dataclass(frozen=True)
class GatewayEndpoint(Record):
    """A gateway endpoint: a gateway identity and a target identity.

    astral-go ``api/gateway/endpoint.go``: traffic to ``TargetID`` is forwarded via
    ``GatewayID`` over the ``gw`` exonet network. Binary ``structValue``: ``GatewayID``
    then ``TargetID`` (each a ``*astral.Identity`` — the ``"identity"`` kind, whose
    presence-flag + 33-byte-key form matches astral-go's ``ptrValue`` around
    ``Identity``). JSON: the bare address string ``"<gatewayID>:<targetID>"``
    (``gateway.Endpoint.MarshalText``, each identity as compressed-key hex).
    """

    TYPE = "mod.gateway.endpoint"
    FIELDS = (
        ("gateway_id", "GatewayID", "identity"),
        ("target_id", "TargetID", "identity"),
    )

    gateway_id: str = ""
    target_id: str = ""

    @property
    def address(self) -> str:
        """The ``"<gatewayID>:<targetID>"`` address (each identity as hex)."""
        return f"{self.gateway_id or _ZERO_IDENTITY_HEX}:{self.target_id or _ZERO_IDENTITY_HEX}"

    @classmethod
    def from_value(cls, value):
        if isinstance(value, str):
            gw, sep, target = value.partition(":")
            if sep == "":
                raise ProtocolError(f"mod.gateway.endpoint: malformed address {value!r}")
            return cls(
                gateway_id=_normalize_identity(gw),
                target_id=_normalize_identity(target),
            )
        return super().from_value(value)

    def encode_json(self):
        return self.address


def _normalize_identity(hex_str: str) -> str:
    """Map astral-go's zero-identity string (66 hex zeros) back to astral-py's ``""``."""
    return "" if hex_str == _ZERO_IDENTITY_HEX else hex_str
