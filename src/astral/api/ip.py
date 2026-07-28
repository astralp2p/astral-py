"""`ip`: the node's own addresses, and the `mod.ip.ip_address` wire type.

Tier 2, three ops, and **zero astral-go client**: `api/ip` at `5c18d9c` is
`ip.go` and `event_network_address_changed.go` and nothing else -- no
`module.go` method constants, no `client/` package. The op names come from the
live `shell.spec` registry, which is the authority design section 0 puts first.

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `ip.default_gateway` | RR | `mod.ip.ip_address` \\| `error_message` | read-only |
| `ip.local_addrs` | ST | `mod.ip.ip_address` x n ++ `eos` | read-only |
| `ip.public_ip_candidates` | ST | `mod.ip.ip_address` x n ++ `eos` | read-only |

**No op here takes an argument.** The live registry declares `out` for all
three and `in` for `local_addrs`, which are the channel formats every op
carries, and nothing else. Verified this session against `furry-bolt`.

**The two terminations differ, per op, and neither is discoverable from the
wire.** `local_addrs` and `public_ip_candidates` end at an `eos`;
`default_gateway` ends at a bare EOF with no `eos`. Both raw bodies, live::

    ip.local_addrs
      11 6d6f642e69702e69705f61646472657373 00000005 04 0a150005
      11 6d6f642e69702e69705f61646472657373 00000011 10 fe80…4ab0
      03 656f73 00000000
    ip.default_gateway
      11 6d6f642e69702e69705f61646472657373 00000005 04 0a150001

**Design risk R-12 is settled, and the answer is 4 or 16.** `mod.ip.ip_address`
is a `bytes8` whose payload is the address bytes: **four for IPv4, sixteen for
IPv6, zero for the unset address**. astral-go writes `To4()` when the value is
IPv4 and the whole slice otherwise (`api/ip/ip.go` `IP.WriteTo`, astral-go
`5c18d9c`), and its reader takes whatever length arrives. The three payloads
above are the proof and are pinned as vectors in `tests/test_api_ip.py`:
`04 0a150005` is `10.21.0.5`, `10 fe800000000000008aa29efffea84ab0` is
`fe80::8aa2:9eff:fea8:4ab0`, and `objects.new?type=mod.ip.ip_address` answers
the single byte `00`.

**`local_addrs` excludes the loopback and `public_ip_candidates` can be empty.**
On `furry-bolt` the first answers two addresses with no `127.0.0.1` among them
and the second answers a bare `eos` with no objects at all. An empty answer is
the ordinary answer, not a fault.

**One `bytes8` record and one text function.** The legacy SDK carried two
contradictory `_ip_str` helpers, which is the defect R-12 names. `IPAddress` is
the record, `IPAddress.text()` is the function, and every rendering path -- the
text channel, JSON, `str()`, a query parameter -- goes through it.
`text()` reproduces Go's `net.IP.String()` exactly, verified by generating both
sides: twenty byte patterns rendered by Go 1.25.1 and by this module agree on
all twenty, tie-breaking of equal zero runs included. The three rules the
agreement rests on:

- an empty value renders `<nil>`, which is Go's word for the unset address;
- a length that is neither 4 nor 16 renders `?` and lowercase hex;
- an IPv4-mapped IPv6 address renders dotted, because `To4()` accepts it.

**One address has one representation.** An IPv4-mapped IPv6 address --
sixteen bytes, ten zeros, `ffff`, four address bytes -- is narrowed to its four
bytes at construction. astral-go keeps the sixteen in memory and narrows in
`WriteTo`, so the bytes that reach the wire are identical either way; narrowing
earlier is what makes `==` on this type agree with `text()`, which it cannot do
while one address has two byte forms. `Identity` is 33 opaque bytes and this is
not: the length is meaningful here and is the only thing that distinguishes an
IPv4 address from an IPv6 one.

**`parse()` is Go's `net.ParseIP` and is not `text()`'s exact inverse.** Go
refuses a scope id (`fe80::1%eth0`), a leading zero (`010.1.1.1`), surrounding
space, a CIDR suffix, and both spellings `String()` invents for a value that is
not an address (`<nil>`, `?0a15`). All seven verified against Go 1.25.1. Python's
`ipaddress` refuses the same seven, so it is the parser, and the divergence is
recorded rather than papered over: `IPAddress().text()` is `<nil>` and
`IPAddress.parse('<nil>')` raises. astral-go has the same hole -- its
`UnmarshalText` calls `net.ParseIP` and rejects its own `MarshalText` output for
the zero value -- and this SDK does not invent a spelling neither reference has.

**The derived blueprint carries the layout and not the length rule.**
`blueprint.of(IPAddress)` answers the `bytes8` alias, which is the payload
exactly; `astral.blueprint` has no way to express "4 or 16". The node derives
**no** blueprint for this type at all -- `objects.get_blueprint?type=
mod.ip.ip_address` answers `BlueprintFromType: want struct or *struct, got
ip.IP`, verified live, because `ip.IP` is a named slice and not a struct. The
divergence is deliberate and follows `bip137sig.entropy`, which is the same
shape of type for the same reason: a peer that learns this type from a blueprint
learns where the bytes end, which is more than astral-go can tell it.

**astral-go's `ip.ParseIP` never returns an error.** `func ParseIP(s string)
(IP, error) { return IP(net.ParseIP(s)), nil }` (`api/ip/ip.go`, astral-go
`5c18d9c`): `net.ParseIP` answers nil for anything it cannot read, and the nil
travels as a valid-looking zero address. Every caller of it inherits the defect
-- `tcp.ParseEndpoint("garbage:80")` succeeds -- and this SDK does not port it
(design section 5.1 rule 7). `IPAddress.parse` raises `ParseError`.

Reached as `client.ip`, a `functools.cached_property` on `Client` built on first
use. Importing `astral.api` registers `mod.ip.ip_address` and
`mod.ip.events.network_address_changed` whether or not that property is touched:
`mod.tcp.endpoint`, `mod.kcp.endpoint` and `nat.endpoint` all hold an
`mod.ip.ip_address` in a `Ref` slot, so a program that never asks this module
anything still needs the type to decode a link.

Source citations are pinned to astral-go `5c18d9c` and astrald `074a852b`.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Final, Sequence

from ..errors import BadArgumentType, ParseError
from ..record import AliasRecord, record, wire
from ..registry import default_blueprints
from ..spec import Slice
from .base import ModuleClient

__all__ = [
    "IPAddress",
    "IP_TYPES",
    "Ip",
    "NetworkAddressChanged",
    "OP_DEFAULT_GATEWAY",
    "OP_LOCAL_ADDRS",
    "OP_PUBLIC_IP_CANDIDATES",
]

OP_DEFAULT_GATEWAY: Final = "ip.default_gateway"
OP_LOCAL_ADDRS: Final = "ip.local_addrs"
OP_PUBLIC_IP_CANDIDATES: Final = "ip.public_ip_candidates"

IPV4_LENGTH: Final = 4
IPV6_LENGTH: Final = 16

# The prefix that makes a sixteen-byte value an IPv4 address: ten zero bytes and
# `ffff`. Go's `To4` accepts exactly this and nothing else -- an IPv4-compatible
# address (ten zeros and `0000`) is **not** narrowed and renders as IPv6.
_V4_MAPPED_PREFIX: Final = bytes(10) + b"\xff\xff"

# Go's `IPv6loopback` and `IPv4bcast`, in the narrowed forms this type holds.
_IPV6_LOOPBACK: Final = bytes(15) + b"\x01"
_IPV4_BROADCAST: Final = b"\xff\xff\xff\xff"

NIL_TEXT: Final = "<nil>"
"""What Go's `net.IP.String()` renders for an empty value, and what this type
renders for its zero. Not parseable, by Go and so by this module."""

UNKNOWN_PREFIX: Final = "?"
"""What Go's `net.IP.String()` prefixes to the hex of a value that is neither 4
nor 16 bytes long. Not parseable, by Go and so by this module."""


# --- the wire types ------------------------------------------------------


class IPAddress(AliasRecord):
    """An IP address: `bytes8`, four bytes for IPv4 and sixteen for IPv6.

    `type IP net.IP` in astral-go, whose `WriteTo` and `ReadFrom` are
    hand-rolled; design section 2.5 lists this among the four types that carry
    their own codec. The payload is a `uint8` length and then the address bytes;
    the length is the only thing that says which family the address belongs to.

    **The binary half needs no hand-rolled codec here.** astral-go's `WriteTo`
    differs from a plain `bytes8` in exactly one respect -- it narrows an
    IPv4-mapped value to four bytes -- and that narrowing happens at
    construction, so the alias codec is the whole binary form and what reaches
    the wire is identical. What is this type's own is the text form, the JSON
    form and the length rule.

    The zero value is the unset address: an empty payload, one `0x00` byte on
    the wire, `<nil>` in text. It is constructible, encodable, and not
    parseable back from its own text form -- see the module docstring.

    A length other than 0, 4 or 16 decodes rather than raising, because
    astral-go's reader takes any `bytes8` and a decoder that refused would be
    unable to read what the reference can write. Such a value renders `?` and
    its hex, and answers `False` to every family question.
    """

    __slots__ = ()

    ASTRAL_TYPE = "mod.ip.ip_address"
    UNDERLYING = "bytes8"

    def __init__(self, value: Any = b"") -> None:
        # `bytes(value)` is not the check: `bytes(4)` is four zero bytes, so an
        # integer would build `0.0.0.0` out of nothing, and a text address would
        # build a sixteen-byte value out of its characters.
        if isinstance(value, str):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got str; `.parse()` reads "
                "the text form"
            )
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got {type(value).__name__}"
            )
        super().__init__(_narrow(bytes(value)))

    def __repr__(self) -> str:
        return f"IPAddress({self.text()!r})"

    def __str__(self) -> str:
        return self.text()

    def __bytes__(self) -> bytes:
        return bytes(self.value)

    def __len__(self) -> int:
        return len(self.value)

    # --- families ---

    def is_zero(self) -> bool:
        """Whether this is the unset address, whose payload is empty.

        Not `0.0.0.0`, which is four zero bytes and a real IPv4 address.
        """
        return not self.value

    def is_ipv4(self) -> bool:
        """Whether this address is IPv4. Go's `IsIPv4`, which is `To4() != nil`."""
        return len(self.value) == IPV4_LENGTH

    def is_ipv6(self) -> bool:
        """Whether this address is IPv6.

        Go's `IsIPv6` is `To16() != nil`, which is **true for an IPv4 address
        too** -- `To16` widens four bytes to sixteen. This is the narrower
        question, and the one a caller asking "which family" means: an address
        is IPv4 or IPv6 here, never both.
        """
        return len(self.value) == IPV6_LENGTH

    def is_unspecified(self) -> bool:
        """Whether every byte is zero. Go's `IsUnspecified`: `0.0.0.0` or `::`.

        Not the same question as `is_zero`, which asks whether the payload is
        empty. `0.0.0.0` is an address and the unset value is not.
        """
        return self._family() and not any(self.value)

    def is_loopback(self) -> bool:
        """Whether the address is a loopback address. Go's `IsLoopback`.

        `127.0.0.0/8` for IPv4 and `::1` alone for IPv6. `ip.local_addrs`
        excludes these, verified live.
        """
        data = bytes(self.value)
        if self.is_ipv4():
            return data[0] == 127
        return self.is_ipv6() and data == _IPV6_LOOPBACK

    def is_multicast(self) -> bool:
        """Whether the address is multicast. Go's `IsMulticast`.

        `224.0.0.0/4` for IPv4, `ff00::/8` for IPv6.
        """
        data = bytes(self.value)
        if self.is_ipv4():
            return data[0] & 0xF0 == 0xE0
        return self.is_ipv6() and data[0] == 0xFF

    def is_link_local_unicast(self) -> bool:
        """Whether the address is link-local unicast. Go's
        `IsLinkLocalUnicast`.

        `169.254.0.0/16` for IPv4, `fe80::/10` for IPv6. Every `fe80::` address
        `ip.local_addrs` returns is one.
        """
        data = bytes(self.value)
        if self.is_ipv4():
            return data[0] == 169 and data[1] == 254
        return self.is_ipv6() and data[0] == 0xFE and data[1] & 0xC0 == 0x80

    def is_private(self) -> bool:
        """Whether the address is in a private range. Go's `IsPrivate`.

        RFC 1918 for IPv4 -- `10/8`, `172.16/12`, `192.168/16` -- and RFC 4193
        `fc00::/7` for IPv6. **Narrower than `ipaddress.is_private`**, which
        also counts the loopback, the link-local range, `100.64/10` and the
        documentation ranges: `100.64.0.1` is private to Python and public to
        Go, and this type answers what astral-go answers.
        """
        data = bytes(self.value)
        if self.is_ipv4():
            return (
                data[0] == 10
                or (data[0] == 172 and data[1] & 0xF0 == 16)
                or (data[0] == 192 and data[1] == 168)
            )
        return self.is_ipv6() and data[0] & 0xFE == 0xFC

    def is_global_unicast(self) -> bool:
        """Go's `IsGlobalUnicast`.

        Every address of either family except the IPv4 broadcast, the
        unspecified address, a loopback, a multicast address and a link-local
        unicast address. **Not** a test for a public address: a private address
        is global unicast too, which is why `is_public` exists and why
        astral-go's own comment says not to use this one for that.
        """
        return (
            self._family()
            and bytes(self.value) != _IPV4_BROADCAST
            and not self.is_unspecified()
            and not self.is_loopback()
            and not self.is_multicast()
            and not self.is_link_local_unicast()
        )

    def is_public(self) -> bool:
        """Whether the address is a public unicast address.

        Go's `IsPublic`, which is `IsGlobalUnicast() && !IsPrivate()`.
        """
        return self.is_global_unicast() and not self.is_private()

    # --- forms ---

    def to4(self) -> bytes | None:
        """The four-byte form, or `None` for an address that has none.

        Go's `To4`. Every IPv4 value here is already four bytes, because the
        mapped form is narrowed at construction, so this answers the bytes
        themselves or nothing.
        """
        return bytes(self.value) if self.is_ipv4() else None

    def address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """The standard-library address object, for arithmetic and containment.

        Raises `ParseError` for the unset address and for a length that is
        neither 4 nor 16: `ipaddress` has no value for either, and inventing one
        would answer a question about an address that is not there.
        """
        if not self.is_ipv4() and not self.is_ipv6():
            raise ParseError(
                f"{self.ASTRAL_TYPE}: {self.text()} is not an address of either "
                "family, so it has no ipaddress value"
            )
        return ipaddress.ip_address(bytes(self.value))

    def text(self) -> str:
        """The text form. Go's `net.IP.String()`, reproduced exactly.

        `<nil>` for the unset address, `?` and hex for a length neither 4 nor
        16, dotted for IPv4 and RFC 5952 for IPv6 -- lowercase, longest zero run
        compressed, first run on a tie.
        """
        data = bytes(self.value)
        if not data:
            return NIL_TEXT
        if len(data) not in (IPV4_LENGTH, IPV6_LENGTH):
            return UNKNOWN_PREFIX + data.hex()
        return str(ipaddress.ip_address(data))

    @classmethod
    def parse(cls, text: str) -> "IPAddress":
        """One address from its text form. Go's `net.ParseIP`, plus its inverse.

        Refuses everything Go refuses **except the two spellings `text()` itself
        produces** for a value that is not an address: `<nil>` for an empty value
        and `?<hex>` for a length that is neither 4 nor 16. Go refuses both --
        `net.ParseIP("<nil>")` is nil, so astral-go's `UnmarshalText` errors --
        and the consequence is not confined to this leaf type. The value is
        legally constructible, it is what `registry.new` and `objects.new` build,
        and `nat.endpoint`, `nat.hole` and `nat.punch_signal` all reach it
        through `Ref('mod.ip.ip_address')`; with the refusal in place the binary
        and canonical framings carried a half-filled `nat.hole` and the json and
        text framings could not read it back, which is the one thing the format
        matrix must not do. So the parser accepts its own encoder's output. No
        address spelling changes meaning: the two additions are strings Go's
        parser rejects outright, and the values they name are exactly the ones
        the binary framing already carries.

        A scope id is still refused rather than dropped: `fe80::1%eth0` and
        `fe80::1` are different destinations and Go reads neither as the other.
        """
        if not isinstance(text, str):
            # `ipaddress.ip_address(5)` is `0.0.0.5`, so an int reaching here
            # would parse into an address nobody named.
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected the text form, got "
                f"{type(text).__name__}"
            )
        if text == NIL_TEXT:
            return cls()
        if text.startswith(UNKNOWN_PREFIX):
            try:
                return cls(bytes.fromhex(text[len(UNKNOWN_PREFIX) :]))
            except ValueError as exc:
                raise ParseError(
                    f"{cls.ASTRAL_TYPE}: {text!r} is not the {UNKNOWN_PREFIX!r} "
                    "form, which is that prefix and hex"
                ) from exc
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError as exc:
            raise ParseError(f"{cls.ASTRAL_TYPE}: {text!r} is not an IP address") from exc
        if getattr(parsed, "scope_id", None) is not None:
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: {text!r} carries a scope id, which no "
                "astral endpoint encodes"
            )
        return cls(parsed.packed)

    def json(self) -> str:
        """Go's `MarshalJSON`, which is `json.Marshal(ip.String())`: the text
        form as a JSON string, `<nil>` included."""
        return self.text()

    @classmethod
    def from_json(cls, data: Any) -> "IPAddress":
        if not isinstance(data, str):
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected a JSON string, got "
                f"{type(data).__name__}"
            )
        return cls.parse(data)

    def _family(self) -> bool:
        """Whether the value is 4 or 16 bytes long, which every predicate needs.

        Go answers `false` for every predicate on a nil or malformed address
        rather than failing, so the questions are total here as well: each one
        starts from this and none of them indexes into a shorter value.
        """
        return len(self.value) in (IPV4_LENGTH, IPV6_LENGTH)


def _narrow(data: bytes) -> bytes:
    """An IPv4-mapped IPv6 address as its four bytes; anything else unchanged.

    Go's `To4` narrowing, applied at construction rather than in `WriteTo`. The
    wire bytes are the same either way -- astral-go narrows before it writes --
    and applying it once means one address never has two byte forms.
    """
    if len(data) == IPV6_LENGTH and data.startswith(_V4_MAPPED_PREFIX):
        return data[len(_V4_MAPPED_PREFIX) :]
    return data


# Registered here rather than at the end of the module: the record below holds
# three `Slice("mod.ip.ip_address")` fields, and a decode of one reaches the
# registry for the element type.
default_blueprints().add(IPAddress)


@record("mod.ip.events.network_address_changed")
class NetworkAddressChanged:
    """The node's addresses changed: what went, what came, and what is there now.

    `Removed`, `Added` and `All`, each a slice of `mod.ip.ip_address`. Declared
    reflectively in astral-go, so the layout is three `uint32` counts with their
    elements and nothing else; the node's own blueprint agrees field for field,
    read this session with `objects.get_blueprint?type=
    mod.ip.events.network_address_changed`.

    Registered for decode completeness. No `ip` op sends it: it is an event, and
    events reach a client through the node's event stream rather than through
    this module.
    """

    removed: list[IPAddress] = wire("Removed", Slice("mod.ip.ip_address"))
    added: list[IPAddress] = wire("Added", Slice("mod.ip.ip_address"))
    # `all` shadows the builtin inside this class body alone. The wire name is
    # `All` and a field is named after the wire name it carries.
    all: list[IPAddress] = wire("All", Slice("mod.ip.ip_address"))  # noqa: A003


# --- the client ----------------------------------------------------------


class Ip(ModuleClient):
    """The `ip` module's ops, over one `Client`.

    Reached as `client.ip`, a cached property built on first use; `Ip(client)`
    constructs the same object directly. The scaffolding and the `**kw` contract
    are `ModuleClient`'s.

    Every op here is read-only and takes no argument of its own.
    """

    __slots__ = ()

    async def default_gateway(self, **kw: Any) -> IPAddress:
        """The default gateway's address. RR, **no `eos`**.

        A node with no default route answers with an `error_message`, which
        surfaces as `RemoteError`. Live on `furry-bolt`: `10.21.0.1`.
        """
        return self._expect(
            await self._c.call_one(OP_DEFAULT_GATEWAY, **kw),
            IPAddress,
            OP_DEFAULT_GATEWAY,
        )

    async def local_addrs(self, **kw: Any) -> list[IPAddress]:
        """Every local address of the node's interfaces. ST, ends at `eos`.

        The loopback is excluded by the node. Live on `furry-bolt`:
        `10.21.0.5` and `fe80::8aa2:9eff:fea8:4ab0`.
        """
        return await self._addresses(OP_LOCAL_ADDRS, **kw)

    async def public_ip_candidates(self, **kw: Any) -> list[IPAddress]:
        """The addresses the node believes may be reachable publicly. ST, ends
        at `eos`.

        Candidates, not confirmations: the node offers them and nothing here has
        tested one. An empty list is the ordinary answer -- `furry-bolt` answers
        a bare `eos` with no objects, verified live.
        """
        return await self._addresses(OP_PUBLIC_IP_CANDIDATES, **kw)

    async def _addresses(self, op: str, **kw: Any) -> list[IPAddress]:
        """One streaming op's addresses, each checked against the shape it
        declared."""
        return [
            self._expect(obj, IPAddress, op) for obj in await self._c.call(op, **kw)
        ]


IP_TYPES: Final[Sequence[type]] = (IPAddress, NetworkAddressChanged)
"""Every wire type this module declares, for a private-registry sweep."""

Ip.TYPES = IP_TYPES
