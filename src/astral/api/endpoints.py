"""The four concrete endpoint types, codec-only: tcp, tor, gateway, kcp.

Design section 0.1 excludes `tcp`, `tor`, `gateway` and `kcp` as SDK modules and
keeps their **types**: `mod.nodes.node_info` carries a list of endpoints behind
numeric tags and `mod.nodes.link_info` carries two in polymorphic slots, so
neither decodes without them. Excluding a module means excluding its ops, not
its types. **No op ships here.** `tcp.new_ephemeral_listener`,
`kcp.set_endpoint_local_port`, `gateway.node_register` and the rest stay
unimplemented, and a caller that needs one has `Client.call` and the op name.

There is no `client.endpoints` property and no `ModuleClient` subclass, for that
reason: a module client is a bound set of ops and this file has none.

| Type | Layout | Network |
|---|---|---|
| `mod.tcp.endpoint` | `IP` ref ++ `Port` uint16 | `tcp`, alias `inet` |
| `mod.kcp.endpoint` | `IP` ref ++ `Port` uint16 | `kcp` |
| `mod.tor.endpoint` | `Digest` ref ++ `Port` uint16 | `tor` |
| `mod.gateway.endpoint` | `GatewayID` ptr ++ `TargetID` ptr | `gw` |
| `mod.tor.digest` | 35 raw bytes, no length prefix | -- |

**Every layout above is the node's own answer, not a reading of the Go source.**
`objects.get_blueprint?type=<name>` on `furry-bolt` this session::

    mod.tcp.endpoint      IP RefSpec(mod.ip.ip_address)   Port PrimitiveSpec(uint16)
    mod.kcp.endpoint      IP RefSpec(mod.ip.ip_address)   Port PrimitiveSpec(uint16)
    mod.tor.endpoint      Digest RefSpec(mod.tor.digest)  Port PrimitiveSpec(uint16)
    mod.gateway.endpoint  GatewayID PtrSpec(identity)     TargetID PtrSpec(identity)

and `objects.new?type=<name>` gives each zero value's bytes: `000000` for tcp
and kcp, `0000` for tor and for gateway, and an empty payload for
`mod.tor.digest`. Both sets are pinned as vectors in `tests/test_api_endpoints.py`.

**`mod.tor.digest` is the type that cannot be declared, not `mod.tor.endpoint`.**
Design section 2.5 lists `mod.tor.endpoint` among the four types that carry a
hand-written codec, with the reason "Digest is 35 raw bytes with no length
prefix". The reason is right and the type named is wrong: the digest is what has
no length prefix, and once it carries its own codec the endpoint is an ordinary
two-field record. The node settles it -- `objects.get_blueprint` **derives**
`mod.tor.endpoint` and **refuses** `mod.tor.digest` with `BlueprintFromType:
want struct or *struct, got tor.Digest`, verified live -- so a hand-rolled
`mod.tor.endpoint` would make `blueprint.of` disagree with the node about a type
the node can describe. The count of hand-written codecs is unchanged; the name
in the table is not. Filed as a design objection.

**A digest's length rule is one-directional, and astral-go's is too.**
`Digest.WriteTo` writes whatever bytes it holds and `Digest.ReadFrom` demands
exactly 35 (`api/tor/digest.go`, astral-go `5c18d9c`), so the zero value encodes
to nothing and cannot be read back. The node proves it:
`objects.new?type=mod.tor.digest` answers a **zero-byte** frame, and
`objects.new?type=mod.tor.endpoint` answers `0000`, which is a two-byte payload
where the reader wants 37. This SDK reproduces both halves rather than repairing
one: the encoder writes what the node wrote, the decoder fails where the node
fails, and `TorDigest.SIZE` names the number. Filed against astral-go.

**Two text forms per type, and they are not always the same string.**
`Address()` is the address alone; `MarshalText` is what the text channel emits.
They agree for tcp, kcp and gateway and differ for tor's zero value, which is
`unknown` as an address and `.onion:0` as text. `text()` here is `MarshalText`
so a text-channel decode reads what the node wrote; `address()` is `Address()`;
`json()` is `MarshalJSON`, which every one of the four defines as
`json.Marshal(e.Address())`.

**Three astral-go parser defects, none of them ported** (design section 5.1
rule 7):

1. `ip.ParseIP` never returns an error, so `tcp.ParseEndpoint("garbage:80")`
   succeeds with a nil IP and `<nil>:80` as its address. `IPAddress.parse`
   raises, so every `parse` here raises.
2. The port check in `tcp.ParseEndpoint` and `kcp.ParseEndpoint` is
   `(port >> 16) > 0`, which is false for every negative number in Go, so
   `1.2.3.4:-1` parses and becomes port 65535. `parse` here requires
   `0 <= port <= 65535`.
3. `tor.Endpoint.UnmarshalText` has no port check at all and truncates through
   `astral.Uint16`, so `…onion:99999` becomes port 33999. `parse` here raises.

**`mod.tcp.endpoint` and `mod.kcp.endpoint` are the same shape and share it.**
`IPEndpoint` carries the address, text, JSON and parse behaviour for an
endpoint that is an IP address and a port; each record declares its own two
fields, because a `@record` owns its schema. `nat.endpoint` is a third of the
same shape -- `IP` ref, `Port` uint16, `Network()` of `kcp` -- and Tier 3 can
reuse `IPEndpoint` rather than restate it.

Source citations are pinned to astral-go `5c18d9c` and astrald `074a852b`.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Final, Mapping, Sequence

from ..errors import BadArgumentType, ParseError, StreamCorrupted
from ..record import record, wire
from ..registry import default_blueprints
from ..spec import Primitive, Ptr, Ref
from ..types import Identity
from .exonet import Endpoint, endpoint_types
from .ip import IPAddress

__all__ = [
    "ENDPOINTS_TYPES",
    "GatewayEndpoint",
    "IPEndpoint",
    "KcpEndpoint",
    "NODE_INFO_TAGS",
    "NODE_INFO_TAG_OF",
    "TcpEndpoint",
    "TorDigest",
    "TorEndpoint",
    "endpoint_for_tag",
    "join_host_port",
    "split_host_port",
    "tag_for_endpoint",
]

MAX_PORT: Final = 0xFFFF

TCP_NETWORK: Final = "tcp"
TCP_ALIAS: Final = "inet"
"""astrald's TCP module parses and unpacks `inet` as well as `tcp`
(`mod/tcp/src/parse.go` `Module.Parse`, line 11 at astrald `074a852b`). The
endpoint's own `Network()` is `tcp` and never `inet`."""

KCP_NETWORK: Final = "kcp"
TOR_NETWORK: Final = "tor"
GATEWAY_NETWORK: Final = "gw"
"""`mod/gateway/src/module.go` `NetworkName`, line 27 at astrald `074a852b`.
The module is `gateway` and its network is `gw`."""

TOR_DEFAULT_PORT: Final = 1791
"""`mod/tor/src/module.go` `defaultListenPort`, line 17 at astrald `074a852b`.
astrald's tor parser supplies it for an address with no port; astral-go's
`UnmarshalText` requires one. `TorEndpoint.parse` accepts both."""

TOR_UNKNOWN: Final = "unknown"
"""What `tor.Endpoint.Address()` renders for a zero value, and what its
`UnmarshalText` reads back as one."""

ONION_SUFFIX: Final = ".onion"

_NIL_HOST: Final = "<nil>"
"""What `IPAddress.text()` renders for the unset address, and so the host half
of a zero `mod.tcp.endpoint`'s own text form."""


# --- host:port, exactly as Go splits and joins it ------------------------


def join_host_port(host: str, port: int) -> str:
    """Go's `net.JoinHostPort`: brackets a host that contains a colon.

    `10.21.0.5:8625` and `[fe80::1]:8625`. Verified against Go 1.25.1 for both
    families and for the `<nil>` host a zero endpoint renders.
    """
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def split_host_port(text: str) -> tuple[str, str]:
    """Go's `net.SplitHostPort`, in the cases an endpoint reaches.

    A bracketed host takes everything between the brackets and requires a colon
    straight after; an unbracketed one must hold exactly one colon, so a bare
    IPv6 address is a fault rather than a host with a port cut off its end.
    """
    if not isinstance(text, str):
        raise ParseError(f"address: expected the text form, got {type(text).__name__}")
    if text.startswith("["):
        close = text.find("]")
        if close == -1:
            raise ParseError(f"address {text!r}: missing ']' in address")
        rest = text[close + 1 :]
        if not rest.startswith(":"):
            raise ParseError(f"address {text!r}: missing port in address")
        return text[1:close], rest[1:]
    if text.count(":") != 1:
        # Go reports "too many colons in address" for two or more and "missing
        # port in address" for none. Both are this fault: an unbracketed host
        # with a port has exactly one.
        raise ParseError(
            f"address {text!r}: a host and port need exactly one ':' unless the "
            "host is bracketed"
        )
    host, _, port = text.partition(":")
    return host, port


_PORT_DIGITS: Final = re.compile(r"[+-]?[0-9]+")
"""Go's `strconv.Atoi` grammar: an optional sign and ASCII digits.

`int()` is wider than that in three ways Go is not -- it strips surrounding
whitespace, it accepts `_` as a group separator, and `str.isdigit` is true of
every Unicode decimal digit -- so `10.21.0.5: 8625` and `10.21.0.5:8_625` would
parse to a port the node's own parser rejects.
"""


def _port(text: str, what: str) -> int:
    """One port number, refused unless a `uint16` can carry it.

    astral-go checks `(port >> 16) > 0`, which every negative number passes, so
    `-1` reaches `astral.Uint16` and becomes 65535. This check is the one the
    wire width actually imposes.
    """
    if not _PORT_DIGITS.fullmatch(text):
        raise ParseError(f"{what}: {text!r} is not a port number")
    value = int(text, 10)
    if not 0 <= value <= MAX_PORT:
        raise ParseError(f"{what}: port {value} is outside 0..{MAX_PORT}")
    return value


# --- an IP address and a port: tcp, kcp, and Tier 3's nat.endpoint -------


class IPEndpoint(Endpoint):
    """The behaviour `mod.tcp.endpoint` and `mod.kcp.endpoint` share.

    Both are `{IP ip.IP, Port astral.Uint16}` in astral-go with identical text,
    JSON and parse rules; only `Network()` and the type name differ. A subclass
    declares the two fields and the network name, and inherits everything below.
    `nat.endpoint` is a third of the same shape.
    """

    __slots__ = ()

    ip: IPAddress
    port: int

    def address(self) -> str:
        """`host:port`, bracketed for IPv6. astral-go's `Address()`, which is
        `net.JoinHostPort(e.IP.String(), port)`."""
        return join_host_port(self.ip.text(), self.port)

    def is_zero(self) -> bool:
        """Whether the endpoint is unset. astral-go's `IsZero`, which tests the
        IP alone and says nothing about the port."""
        return self.ip.is_zero()

    def text(self) -> str:
        """astral-go's `MarshalText`, which is `Address()`."""
        return self.address()

    @classmethod
    def parse(cls, text: str) -> Any:
        """One endpoint from `host:port`. astral-go's `UnmarshalText`, repaired.

        The two repairs are the module docstring's defects 1 and 2: a host that
        is not an address raises rather than becoming the nil IP, and a port
        outside `uint16` raises rather than wrapping.
        """
        host, port = split_host_port(text)
        return cls(
            ip=_address(host, cls.ASTRAL_TYPE),  # type: ignore[attr-defined]
            port=_port(port, cls.ASTRAL_TYPE),  # type: ignore[attr-defined]
        )

    def json(self) -> str:
        """astral-go's `MarshalJSON`, which is `json.Marshal(e.Address())`."""
        return self.address()

    @classmethod
    def from_json(cls, data: Any) -> Any:
        return cls.parse(_json_string(data, cls.ASTRAL_TYPE))  # type: ignore[attr-defined]


def _address(host: str, what: str) -> IPAddress:
    """One host, as an address. `<nil>` is the unset address and nothing else.

    `text()` renders the unset address as `<nil>`, so `IPEndpoint().text()` is
    `<nil>:0` and this is what reads it back. astral-go reaches the same value
    by accident -- `net.ParseIP("<nil>")` is nil and `ip.ParseIP` drops the
    error -- and by the same accident reaches it for every other unparseable
    host too. Here it is the one spelling and everything else raises.
    """
    if host == _NIL_HOST:
        return IPAddress()
    try:
        return IPAddress.parse(host)
    except ParseError as exc:
        raise ParseError(f"{what}: {host!r} is not an IP address") from exc


def _json_string(data: Any, what: str) -> str:
    if not isinstance(data, str):
        raise ParseError(f"{what}: expected a JSON string, got {type(data).__name__}")
    return data


@record("mod.tcp.endpoint")
class TcpEndpoint(IPEndpoint):
    """A TCP endpoint: an IP address and a port.

    Numeric tag `0` inside `mod.nodes.node_info`. Registered under `tcp` and
    under astrald's alias `inet`; `network()` is `tcp` for both.
    """

    ip: IPAddress = wire("IP", Ref("mod.ip.ip_address"))
    port: int = wire("Port", Primitive("uint16"))

    def network(self) -> str:
        return TCP_NETWORK


@record("mod.kcp.endpoint")
class KcpEndpoint(IPEndpoint):
    """A KCP endpoint: an IP address and a UDP port.

    Identical on the wire to `mod.tcp.endpoint` and a different type: the
    network name is what says which transport dials it. No numeric tag --
    `mod.nodes.node_info` knows three types and this is not one of them, so a
    node advertising KCP endpoints in an invite string cannot be encoded by
    astral-go at all.
    """

    ip: IPAddress = wire("IP", Ref("mod.ip.ip_address"))
    port: int = wire("Port", Primitive("uint16"))

    def network(self) -> str:
        return KCP_NETWORK


# --- tor -----------------------------------------------------------------


class TorDigest:
    """A Tor v3 service digest: 35 raw bytes, with no length prefix.

    `type Digest []byte` in astral-go, with a `WriteTo` that writes the bytes
    bare and a `ReadFrom` that reads exactly `DigestSize`. No spec kind can
    express that -- a `bytes8` would prefix a length and a `Primitive` has no
    fixed-width raw form -- so this type carries its own codec and has **no
    derivable blueprint**. The node agrees: `objects.get_blueprint?type=
    mod.tor.digest` answers `BlueprintFromType: want struct or *struct, got
    tor.Digest`, verified live.

    The text form is base32 of the bytes, lowercased, with `.onion` appended.
    Parsing accepts either case and the suffix is optional, which is astral-go's
    `UnmarshalText` exactly.

    A digest of any other length is constructible and encodable -- astral-go's
    writer has no check and the node's zero value is empty -- and is not
    decodable, because the reader has to commit to a length before it reads.
    """

    __slots__ = ("value",)

    ASTRAL_TYPE: Final = "mod.tor.digest"
    FIELDS: Final[tuple[Any, ...]] = ()
    DERIVABLE: Final = False
    SIZE: Final = 35

    def __init__(self, value: Any = b"") -> None:
        if isinstance(value, str):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got str; `.parse()` reads "
                "the base32 form"
            )
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got {type(value).__name__}"
            )
        self.value = bytes(value)

    def __repr__(self) -> str:
        return f"TorDigest({self.text()!r})"

    def __str__(self) -> str:
        return self.text()

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TorDigest) and other.value == self.value

    def __hash__(self) -> int:
        return hash((self.ASTRAL_TYPE, self.value))

    def is_zero(self) -> bool:
        """Whether the digest is empty, which is astral-go's `len(Digest) == 0`."""
        return not self.value

    def text(self) -> str:
        """astral-go's `MarshalText`: lowercase base32 of the bytes, then
        `.onion`. An empty digest renders the bare suffix, which `parse`
        refuses -- see the module docstring."""
        return base64.b32encode(self.value).decode("ascii").lower() + ONION_SUFFIX

    @classmethod
    def parse(cls, text: str) -> "TorDigest":
        """astral-go's `UnmarshalText`: uppercase, drop `.ONION`, base32-decode,
        and require exactly `SIZE` bytes."""
        if not isinstance(text, str):
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected the text form, got "
                f"{type(text).__name__}"
            )
        body = text.upper()
        if body.endswith(ONION_SUFFIX.upper()):
            body = body[: -len(ONION_SUFFIX)]
        try:
            # `binascii.Error` is a `ValueError`, so both the alphabet fault and
            # the padding fault land here.
            data = base64.b32decode(body)
        except ValueError as exc:
            raise ParseError(f"{cls.ASTRAL_TYPE}: {text!r} is not base32") from exc
        if len(data) != cls.SIZE:
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: {len(data)} bytes is not a digest; a Tor v3 "
                f"digest is {cls.SIZE} bytes"
            )
        return cls(data)

    def json(self) -> str:
        """astral-go's `MarshalJSON`, which wraps `MarshalText`."""
        return self.text()

    @classmethod
    def from_json(cls, data: Any) -> "TorDigest":
        return cls.parse(_json_string(data, cls.ASTRAL_TYPE))

    @classmethod
    def read_payload(cls, r: Any) -> "TorDigest":
        """Exactly `SIZE` raw bytes. A shorter payload is a short read, which is
        what astral-go's `io.ReadFull` reports."""
        return cls(r.raw(cls.SIZE))

    def write_payload(self, w: Any) -> None:
        """The bytes, bare. No length check: astral-go has none either, and the
        node's own zero value is a digest of length zero."""
        w.raw(self.value)


# Registered before the record below is ever constructed: `TorEndpoint()` builds
# its `Digest` field through `Ref("mod.tor.digest")`, which resolves here.
default_blueprints().add(TorDigest)


@record("mod.tor.endpoint")
class TorEndpoint(Endpoint):
    """A Tor endpoint: a v3 service digest and a port.

    Numeric tag `1` inside `mod.nodes.node_info`. The payload is the digest's 35
    raw bytes and then a `uint16`, so a zero value encodes to two bytes and
    cannot be decoded -- see `TorDigest`.
    """

    digest: TorDigest = wire("Digest", Ref("mod.tor.digest"))
    port: int = wire("Port", Primitive("uint16"))

    def network(self) -> str:
        return TOR_NETWORK

    def is_zero(self) -> bool:
        """astral-go's `IsZero`: an empty digest, whatever the port."""
        return self.digest.is_zero()

    def address(self) -> str:
        """astral-go's `Address()`: `unknown` for a zero value, else
        `<digest>.onion:<port>`."""
        if self.is_zero():
            return TOR_UNKNOWN
        return f"{self.digest.text()}:{self.port}"

    def text(self) -> str:
        """astral-go's `MarshalText`, which is **not** `Address()`: it renders a
        zero value as `.onion:0` rather than `unknown`, and its own `parse`
        refuses that string. Reproduced rather than repaired -- the text channel
        emits it and a decoder that invented a third spelling would be reading
        something the node never wrote."""
        return f"{self.digest.text()}:{self.port}"

    @classmethod
    def parse(cls, text: str) -> "TorEndpoint":
        """One endpoint from its text form.

        `unknown` is the zero value, which is astral-go's `UnmarshalText`. A
        missing port defaults to 1791, which is astrald's parser
        (`mod/tor/src/parse.go` `Parse`, astrald `074a852b`) and is accepted
        here so a string the node reads is a string this SDK reads. A port
        outside `uint16` raises rather than truncating.
        """
        if not isinstance(text, str):
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected the text form, got "
                f"{type(text).__name__}"
            )
        if text == TOR_UNKNOWN:
            return cls()
        host, separator, port = text.partition(":")
        return cls(
            digest=TorDigest.parse(host),
            port=_port(port, cls.ASTRAL_TYPE) if separator else TOR_DEFAULT_PORT,
        )

    def json(self) -> str:
        """astral-go's `MarshalJSON`, which is `json.Marshal(e.Address())` and
        so renders a zero value as `unknown`. The one round-trippable spelling
        of the zero endpoint: `text()` is not."""
        return self.address()

    @classmethod
    def from_json(cls, data: Any) -> "TorEndpoint":
        return cls.parse(_json_string(data, cls.ASTRAL_TYPE))


# --- gateway -------------------------------------------------------------


@record("mod.gateway.endpoint")
class GatewayEndpoint(Endpoint):
    """A route to a target through one gateway node.

    Numeric tag `2` inside `mod.nodes.node_info`. Both fields are pointers, so
    each carries a presence byte and a zero value is the two bytes `0000` --
    which is what `objects.new?type=mod.gateway.endpoint` answers, verified live.

    `parse` produces identities and never `None`, so a parsed zero endpoint is
    `01` and 33 zero bytes twice where a constructed one is `0000`. Both decode
    to the same address text and neither re-encodes to the other's bytes;
    astral-go has the same two spellings for the same reason, a nil pointer
    against a pointer to the zero identity.

    **That makes this the one type whose framings disagree about a value rather
    than about an error.** `bin` and `canonical` carry the presence byte and
    read an absent half back as `None`; `json` and `text` carry `Address()`, and
    66 zeros read back as `Identity.ANYONE`. So `ep.gateway_id is None` flips
    with the framing an answer arrived on. The encoding cannot spell the
    difference -- neither here nor in astral-go, whose `Identity.String()`
    answers the same 66 zeros for a nil receiver -- and mapping the zeros back
    to `None` would only move the collision onto callers who mean
    `Identity.ANYONE`. It is therefore named and pinned rather than repaired:
    `tests/test_channel_formats.py::EmitterReadsBackTest.DIVERGENCES`.

    astrald's parser does two things this one cannot: it resolves each half
    through the directory, and it refuses an endpoint whose gateway is its
    target (`mod/gateway/src/parser.go` `Module.Parse`, astrald `074a852b`).
    Both need a node. A wire type has none, so `parse` is astral-go's
    `ParseEndpoint`: two identities, parsed locally, no resolution and no
    equality rule.
    """

    gateway_id: Identity | None = wire("GatewayID", Ptr("identity"))
    target_id: Identity | None = wire("TargetID", Ptr("identity"))

    def network(self) -> str:
        return GATEWAY_NETWORK

    def is_zero(self) -> bool:
        """astral-go's `IsZero`: both halves absent or zero."""
        return _zero_identity(self.gateway_id) and _zero_identity(self.target_id)

    def address(self) -> str:
        """astral-go's `Address()`: the two identities, colon-joined.

        An absent identity renders as 66 zeros, because astral-go's
        `Identity.String()` answers `anyoneKey` for a nil receiver
        (`astral/identity.go`, astral-go `5c18d9c`).
        """
        return f"{_identity_text(self.gateway_id)}:{_identity_text(self.target_id)}"

    def text(self) -> str:
        """astral-go's `MarshalText`, which is `Address()`."""
        return self.address()

    @classmethod
    def parse(cls, text: str) -> "GatewayEndpoint":
        """One endpoint from `<gatewayID>:<targetID>`. Both halves required."""
        if not isinstance(text, str):
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected the text form, got "
                f"{type(text).__name__}"
            )
        gateway, separator, target = text.partition(":")
        if not separator:
            raise ParseError(f"{cls.ASTRAL_TYPE}: malformed endpoint {text!r}")
        return cls(
            gateway_id=_identity(gateway, cls.ASTRAL_TYPE),
            target_id=_identity(target, cls.ASTRAL_TYPE),
        )

    def json(self) -> str:
        """astral-go's `MarshalJSON`, which is `json.Marshal(e.Address())`."""
        return self.address()

    @classmethod
    def from_json(cls, data: Any) -> "GatewayEndpoint":
        return cls.parse(_json_string(data, cls.ASTRAL_TYPE))


def _zero_identity(identity: Identity | None) -> bool:
    return identity is None or identity.is_zero


def _identity_text(identity: Identity | None) -> str:
    return Identity.ANYONE.text() if identity is None else identity.text()


def _identity(text: str, what: str) -> Identity:
    try:
        return Identity.parse(text)
    except ParseError as exc:
        raise ParseError(f"{what}: {text!r} is not an identity") from exc


# --- the numeric tags `mod.nodes.node_info` carries ----------------------

NODE_INFO_TAGS: Final[Mapping[int, type[Endpoint]]] = {
    0: TcpEndpoint,
    1: TorEndpoint,
    2: GatewayEndpoint,
}
"""`uint8` tag -> endpoint class, for `mod.nodes.node_info` alone.

`NodeInfo.WriteTo` writes `uint8 count` and then one `uint8` tag and one bare
payload per endpoint, with `0 = tcp`, `1 = tor`, `2 = gateway` and an error for
anything else (`api/nodes/node_info.go`, astral-go `5c18d9c`). No other type
uses these numbers: `mod.nodes.link_info` and `mod.nodes.endpoint_with_ttl` hold
their endpoints in polymorphic slots, which carry the type name.

The table lives here because it names concrete classes. It is the only reason a
`kcp` endpoint cannot appear in a node invite string.
"""

NODE_INFO_TAG_OF: Final[Mapping[type, int]] = {
    cls: tag for tag, cls in NODE_INFO_TAGS.items()
}


def endpoint_for_tag(tag: int) -> type[Endpoint]:
    """The class a `mod.nodes.node_info` tag names.

    An unknown tag is `StreamCorrupted` and not a soft failure: the payload that
    follows has no length, so a reader that skipped it would resynchronise on
    nothing. astral-go aborts the frame in the same place.
    """
    found = NODE_INFO_TAGS.get(tag)
    if found is None:
        raise StreamCorrupted(
            f"mod.nodes.node_info: endpoint type tag {tag} is not one of "
            f"{sorted(NODE_INFO_TAGS)}"
        )
    return found


def tag_for_endpoint(endpoint: Endpoint) -> int:
    """The `mod.nodes.node_info` tag of an endpoint.

    A `mod.kcp.endpoint` has none, and so has every endpoint type a future node
    adds. astral-go answers `unknown endpoint type` and aborts the frame; this
    raises before a byte is written.
    """
    found = NODE_INFO_TAG_OF.get(type(endpoint))
    if found is None:
        raise StreamCorrupted(
            f"mod.nodes.node_info: {getattr(endpoint, 'ASTRAL_TYPE', type(endpoint).__name__)} "
            f"has no endpoint type tag; the three that do are "
            f"{', '.join(sorted(c.ASTRAL_TYPE for c in NODE_INFO_TAGS.values()))}"  # type: ignore[attr-defined]
        )
    return found


# --- registration --------------------------------------------------------

endpoint_types().register(TcpEndpoint, TCP_ALIAS)
endpoint_types().register(KcpEndpoint)
endpoint_types().register(TorEndpoint)
endpoint_types().register(GatewayEndpoint)

ENDPOINTS_TYPES: Final[Sequence[type]] = (
    TcpEndpoint,
    KcpEndpoint,
    TorDigest,
    TorEndpoint,
    GatewayEndpoint,
)
"""Every wire type this module declares, for a private-registry sweep."""
