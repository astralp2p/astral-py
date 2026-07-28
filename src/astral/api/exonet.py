"""`exonet`: the endpoint abstraction, and the registry of endpoint types.

Tier 2, and the one module in this package with **no ops at all**.
`api/exonet/module.go` at astral-go `5c18d9c` declares one interface and nothing
else -- no method constants, no client package, no docs directory:

    type Endpoint interface {
        astral.Object
        Network() string   // network name
        Address() string   // text representation of the address
        Pack() []byte      // binary representation of the address
    }

So this module is that interface plus the dispatch table astrald keeps beside
it. `mod/exonet/module.go` at astrald `074a852b` declares a per-network registry
of dialers, unpackers and parsers with three dispatch methods; `Unpack(network,
data)` and `Parse(network, address)` are the two a client needs, and `Dial` is
the one it does not -- dialing an endpoint is the node's business and no
endpoint type in this SDK carries a transport.

**An endpoint type is a wire type, an endpoint module is not.** Design section
0.1 excludes `tcp`, `tor`, `gateway` and `kcp` as SDK modules and keeps their
types, because `mod.nodes.node_info` and `mod.nodes.link_info` cannot decode
without them. The concrete four live in `endpoints.py` and register themselves
here at import; this file names no concrete type, so the abstraction does not
depend on which endpoints a build ships.

**Two names for one thing, kept apart.** `Endpoint.network()` is the network a
concrete type belongs to and is fixed per class; a *registration* maps one or
more names to that class, because astrald's TCP module answers to both `tcp` and
`inet` (`mod/tcp/src/parse.go` `Module.Parse`, line 11 at astrald `074a852b`).
`network()` is always the canonical name, never an alias.

**`Endpoint.pack()` is the object payload and nothing else.** Every concrete
`Pack()` in astral-go is `WriteTo` into a buffer, which is the payload with no
type tag and no length prefix, so `pack()` is `payload_bytes(self)` once here
rather than four times in `endpoints.py`, and `unpack_endpoint` is its inverse.

**Nothing here reads a concrete type's Go `String()`.** It is two different
things across the four: `tcp` and `kcp` return `Address()`, `tor` and `gateway`
return `Network() + ":" + Address()`. `Endpoint.qualified()` is the one form the
SDK uses for both directions -- it is what `nodes.add_endpoint` takes as its
`endpoint` argument and what `parse_endpoint` reads.

This module registers **no wire type**. `mod.exonet.endpoint` is not a type name
at all: `objects.new?type=mod.exonet.endpoint` on `furry-bolt` answers `nil`,
verified this session, because a Go interface has no `ObjectType()` of its own.
`EXONET_TYPES` is empty and is declared anyway, so the per-module sweep is
uniform across thirteen modules.

There is no `client.exonet` property and no `ModuleClient` subclass here, for
the same reason: a module client is a bound set of ops and this module has none.
"""

from __future__ import annotations

import abc
from typing import Final, Iterator, Sequence

from ..codec.binary import object_reader, payload_bytes
from ..errors import BadArgument

__all__ = [
    "EXONET_TYPES",
    "Endpoint",
    "EndpointTypes",
    "NETWORK_SEPARATOR",
    "endpoint_types",
    "parse_endpoint",
    "unpack_endpoint",
]

NETWORK_SEPARATOR: Final = ":"
"""What separates the network from the address in the qualified form.

The address half may contain more of them -- `tcp:[fe80::1]:8625` -- so the
split is on the **first** one only.
"""


# --- the abstraction -----------------------------------------------------


class Endpoint(abc.ABC):
    """A dialable address on one network. astral-go's `exonet.Endpoint`.

    A subclass is an ordinary astral object -- a `@record` with its own
    `ASTRAL_TYPE`, read and written by the codec like any other -- plus the two
    abstract methods below. `__slots__` is empty so a `@record` subclass keeps
    its own slots and grows no instance dictionary.

    **Codec-only in this SDK.** An endpoint carries an address and knows how to
    render, parse and pack it. It does not dial: `mod/exonet` registers a dialer
    per network inside the node, and the SDK reaches a peer through the node's
    router, never through an endpoint of its own.
    """

    __slots__ = ()

    @abc.abstractmethod
    def network(self) -> str:
        """The canonical network name. Fixed per class, never per value."""

    @abc.abstractmethod
    def address(self) -> str:
        """The address in its own text form, with no network prefix.

        astral-go's `Address()`. It is not always the type's `MarshalText`
        output: `mod.tor.endpoint` renders a zero value as `unknown` here and as
        `.onion:0` there.
        """

    def pack(self) -> bytes:
        """The binary address: the object payload, no tag and no length.

        astral-go's `Pack()`, which is `WriteTo` into a buffer.
        `unpack_endpoint(network, data)` is the inverse.
        """
        return payload_bytes(self)

    def qualified(self) -> str:
        """`<network>:<address>` -- the form the node reads and writes.

        `nodes.add_endpoint` takes exactly this as its `endpoint` argument
        (`endpoint:string8`, `<network>:<address>`), and `parse_endpoint` is the
        inverse. Preferred over a concrete type's Go `String()`, which is
        `Address()` for `tcp` and `kcp` and this form for `tor` and `gateway`.
        """
        return f"{self.network()}{NETWORK_SEPARATOR}{self.address()}"


# --- the registry --------------------------------------------------------


class EndpointTypes:
    """Network name -> endpoint class. astrald's `mod/exonet` dispatch table.

    One registration may claim several names, and the class keeps one canonical
    `network()`: astrald's TCP module parses and unpacks both `tcp` and `inet`
    into a `mod.tcp.endpoint`, whose `Network()` is `tcp`.

    Separate from `Blueprints`, and deliberately: a blueprint registry maps a
    **type name** to a decoder and every endpoint is in it already; this maps a
    **network name**, which is a different key with a different vocabulary and
    no entry for the great majority of registered types.
    """

    __slots__ = ("_by_network",)

    def __init__(self) -> None:
        self._by_network: dict[str, type[Endpoint]] = {}

    def __repr__(self) -> str:
        return f"EndpointTypes({sorted(self._by_network)})"

    def __len__(self) -> int:
        return len(self._by_network)

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._by_network))

    def __contains__(self, network: object) -> bool:
        return network in self._by_network

    def register(self, cls: type[Endpoint], *aliases: str) -> None:
        """Register a class under its own `network()` and under each alias.

        The canonical name comes off the class rather than the caller, so a
        registration cannot disagree with what the values it produces report.
        A name already taken is refused: a silent replacement makes which module
        imported last decide what `tcp:` means.
        """
        names = (_canonical(cls), *aliases)
        for name in names:
            if not name:
                raise BadArgument(f"{cls.__name__}: empty network name")
            if name in self._by_network:
                raise BadArgument(
                    f"network {name!r} is already registered to "
                    f"{self._by_network[name].__name__}"
                )
        for name in names:
            self._by_network[name] = cls

    def get(self, network: str) -> type[Endpoint] | None:
        """The class registered for a network name, or `None`."""
        return self._by_network.get(network)

    def networks(self) -> list[str]:
        """Every registered name, aliases included, sorted."""
        return sorted(self._by_network)

    def classes(self) -> list[type[Endpoint]]:
        """Every registered class, once each, in registration order."""
        seen: dict[type[Endpoint], None] = {}
        for cls in self._by_network.values():
            seen.setdefault(cls, None)
        return list(seen)

    def parse(self, network: str, address: str) -> Endpoint:
        """One endpoint from a network name and its address text.

        astrald's `Module.Parse(network, address)`. The address is read by the
        class's own `parse`, which is astral-go's `UnmarshalText` for that type.
        """
        return _require(self, network).parse(address)  # type: ignore[attr-defined,no-any-return]

    def unpack(self, network: str, data: bytes) -> Endpoint:
        """One endpoint from a network name and a packed address.

        astrald's `Module.Unpack(network, data)`. `data` is what `pack()`
        produced: the payload alone, so the type comes from the network name and
        never from the bytes.
        """
        cls = _require(self, network)
        return cls.read_payload(object_reader(data))  # type: ignore[attr-defined,no-any-return]

    def parse_qualified(self, text: str) -> Endpoint:
        """One endpoint from `<network>:<address>`.

        Split on the first separator only: an IPv6 address holds more of them,
        and `tcp:[fe80::1]:8625` has exactly one network name.
        """
        network, separator, address = text.partition(NETWORK_SEPARATOR)
        if not separator:
            raise BadArgument(
                f"endpoint {text!r} has no {NETWORK_SEPARATOR!r}; the form is "
                f"<network>{NETWORK_SEPARATOR}<address>"
            )
        return self.parse(network, address)


def _canonical(cls: type[Endpoint]) -> str:
    """The network name a class reports, read off a zero value.

    `network()` is an instance method in astral-go and stays one here, so the
    canonical name is read from an instance. Every endpoint class is a record
    with a zero value, which is what the registry constructs anyway.
    """
    return cls().network()


def _require(types: EndpointTypes, network: str) -> type[Endpoint]:
    """The class for a network name, or the fault of there being none.

    astrald answers `ErrUnsupportedNetwork` here
    (`mod/exonet/errors.go`, astrald `074a852b`). This SDK adds no exception
    class for it: an unregistered network is an argument this SDK refuses before
    it sends anything, which is `BadArgument`.
    """
    found = types.get(network)
    if found is None:
        raise BadArgument(
            f"unsupported network {network!r}; registered: "
            f"{', '.join(types.networks()) or '(none)'}"
        )
    return found


_DEFAULT: Final = EndpointTypes()


def endpoint_types() -> EndpointTypes:
    """The process-wide registry `astral.api.endpoints` populates on import.

    The counterpart of `registry.default_blueprints()`, and populated the same
    way: importing `astral.api` is what fills it, so no caller has to know which
    module registered what.
    """
    return _DEFAULT


def parse_endpoint(text: str) -> Endpoint:
    """One endpoint from its `<network>:<address>` form, in the default registry."""
    return _DEFAULT.parse_qualified(text)


def unpack_endpoint(network: str, data: bytes) -> Endpoint:
    """One endpoint from a network name and a packed address, in the default registry."""
    return _DEFAULT.unpack(network, data)


EXONET_TYPES: Final[Sequence[type]] = ()
"""Every wire type this module declares: none.

`exonet.Endpoint` is a Go interface. It has no `ObjectType()`, so it has no
registry entry and no payload of its own -- verified live:
`objects.new?type=mod.exonet.endpoint` answers `nil`. Declared empty rather than
omitted so `registry.add(*MODULE.TYPES)` reads the same for every module.
"""
