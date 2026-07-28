"""`nat`: UDP hole punching, and the three of its five ops that ship.

**Tier 3, experimental, and every op is gated** exactly as `nodes` is: the gate
is `require_experimental`, imported from `astral.api.nodes` so that both Tier 3
modules refuse in the same words, and the wire types register unconditionally so
that a `nat.hole` arriving on any stream still decodes.

    from astral.api.nat import Nat
    await Nat(client, experimental=True).list_holes()
    await client.nat.list_holes(experimental=True)

**Op surface, and what happened to the two that are missing** (design section
4.5, which drops them in v1 rather than half-building them):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `nat.list_holes` | ST | `nat.hole` x n ++ `eos` | read-only |
| `nat.punch` | RR (long) | `nat.hole` \\| `error_message` | **mutates**, initiator |
| `nat.set_enabled` | RR | `ack` | **mutates** node settings |
| `nat.node_punch` | -- | **DROPPED**: needs a local UDP puncher | -- |
| `nat.node_consume_hole` | -- | **DROPPED**: needs a local UDP puncher | -- |

`node_punch` and `node_consume_hole` are present as methods that raise. Both
require an implementation of astral-go's `nat.Puncher` -- open a UDP socket,
punch towards a peer, report the port that answered -- which is a transport
concern outside this SDK's stated scope, and both drive a multi-step signal
handshake that is meaningless without one. A caller reaching for either gets a
sentence saying so; the alternative, leaving them out, makes the same two ops
indistinguishable from ops that do not exist.

`nat.punch` needs no puncher of ours: it asks **the node** to be the initiator,
and the node runs the protocol against the target with its own puncher. It still
mutates -- it creates a hole in the node's pool -- so no live test calls it.

**D-17: the documented parameter names are capitalised and therefore dead.**
astral-docs writes `nat.list_holes -With`, `nat.punch -Target` and
`nat.node_consume_hole -Pair -Target`. Parameter matching is case-sensitive and
unknown keys are silently dropped (`lib/query`'s `Editor.SetMany`), so every one
of those shellsession examples is a no-op that lists every hole instead of the
filtered set. This module sends `with`, `target` and `pair`, which is what the
live registry declares -- read off `shell.spec` this session, not off the docs.

**`nat.endpoint` is an exonet endpoint that no exonet name reaches.** It is a
`{IP, Port}` pair whose `Network()` is `kcp`, structurally identical to
`mod.kcp.endpoint` and a distinct wire type from it. astrald's `mod/kcp` claims
the `kcp` name in the exonet dispatch table (`mod/kcp/src/deps.go`) and
`mod/nat` claims nothing, so `nat.endpoint` is never what `exonet.parse('kcp',
...)` yields. This module therefore does **not** register it in
`astral.api.exonet.endpoint_types()`: doing so would either collide with
`mod.kcp.endpoint` or silently change what `kcp:` means depending on import
order.

Reached as `client.nat`, a `functools.cached_property` built on first use.
"""

from __future__ import annotations

from typing import Any, Final, NoReturn, Sequence

from .. import querystring
from ..client import Client
from ..codec.jsoncodec import json_fields, read_json_fields
from ..errors import BadArgument, FeatureUnavailable, ParseError
from ..object import Ack
from ..record import record, wire
from ..spec import Primitive, Ptr, Ref, Spec
from ..types import Identity, Nonce, Time
from .base import ModuleClient
from .endpoints import IPEndpoint
from .ip import IPAddress
from .nodes import require_experimental

__all__ = [
    "CONSUME_HOLE_SIGNALS",
    "ConsumeHoleSignal",
    "Endpoint",
    "Hole",
    "JSON_TAGS",
    "NAT_TYPES",
    "Nat",
    "OP_LIST_HOLES",
    "OP_NODE_CONSUME_HOLE",
    "OP_NODE_PUNCH",
    "OP_PUNCH",
    "OP_SET_ENABLED",
    "PUNCH_SIGNALS",
    "PunchSignal",
]

OP_LIST_HOLES: Final = "nat.list_holes"
OP_NODE_CONSUME_HOLE: Final = "nat.node_consume_hole"
OP_NODE_PUNCH: Final = "nat.node_punch"
OP_PUNCH: Final = "nat.punch"
OP_SET_ENABLED: Final = "nat.set_enabled"

# `nat.set_enabled` takes the *positional* key, which is `arg`
# (`lib/query`'s `DefaultArgKey`), not `enabled`. Verified against the live
# registry: `nat.set_enabled` declares `arg:bool`, `in`, `out`.
POSITIONAL_KEY: Final = "arg"

_BOOL: Final[Spec] = Primitive("bool")
_STRING8: Final[Spec] = Primitive("string8")

NETWORK: Final = "kcp"
"""The network `nat.endpoint` reports. astral-go's `Endpoint.Network()`."""


# --- wire types ----------------------------------------------------------


@record("nat.endpoint")
class Endpoint(IPEndpoint):
    """One UDP endpoint of a NAT hole: an IP address and a port.

    An `exonet.Endpoint` by interface, reporting the `kcp` network, and the same
    two fields as `mod.kcp.endpoint` under a different type name. The two are
    not interchangeable on the wire: a `nat.hole` carries `nat.endpoint` by
    value and nothing converts between them.

    `IPEndpoint` is where that shape lives -- `api/endpoints.py` says so in as
    many words -- and this class inherits it rather than restating it. The
    hand-written copy that used to sit here had drifted in two ways by the time
    it was compared: its port parser was a bare `int(port, 10)`, which reads
    `8_625` and `+8625` where Go's `strconv.Atoi` reads neither, and its host
    parser called `ipaddress` directly, so it took a scope id `IPAddress.parse`
    refuses and could not read back the `<nil>:0` its own `address()` writes.

    The text form is `host:port` with an IPv6 host in brackets, which is Go's
    `net.JoinHostPort`, and the JSON form is that same string -- astral-go gives
    this type a `MarshalText` and no `MarshalJSON`, so the JSON channel emits the
    text.
    """

    # No `__slots__` here: `@record` applies `dataclass(slots=True)`, which
    # builds them and refuses a class that declared its own. The ABC's empty
    # `__slots__` is what keeps this class dictionary-free.
    ip: IPAddress = wire("IP", Ref("mod.ip.ip_address"))
    port: int = wire("Port", Primitive("uint16"))

    def network(self) -> str:
        return NETWORK


@record("nat.hole")
class Hole:
    """A punched pair of UDP endpoints, held in the node's hole pool.

    `active` is the side that initiated the punch and `passive` the side that
    answered; which one is *this* node is what `remote_identity()` answers.

    **The zero value's `created_at` differs from astral-go's, and neither is a
    time.** Go's `time.Time{}` is year 1, and `astral.Time` marshals through
    `UnixNano`, which is undefined outside 1678-2262: the reference emits
    `a1b203eb3d1a0000`, which reads back as 1754-08-30T22:43:41.128654848Z. This
    SDK's zero is the epoch, `0000000000000000`. Both decode here and both
    re-encode to the bytes they arrived as, so the divergence is confined to
    which zero a locally constructed value carries -- the same class of choice
    design section 11.3 settled for arrays.
    """

    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    active_identity: Identity | None = wire("ActiveIdentity", Ptr("identity"))
    active_endpoint: Endpoint = wire("ActiveEndpoint", Ref("nat.endpoint"))
    passive_identity: Identity | None = wire("PassiveIdentity", Ptr("identity"))
    passive_endpoint: Endpoint = wire("PassiveEndpoint", Ref("nat.endpoint"))
    created_at: Time = wire("CreatedAt", Primitive("time"))

    def matches(self, peer: Identity) -> bool:
        """Whether this hole has `peer` on either side. Go's `MatchesPeer`."""
        return peer in (self.active_identity, self.passive_identity)

    def remote_identity(self, local: Identity) -> Identity | None:
        """The other side's identity. `None` covers both ways there is not one.

        Go's `RemoteIdentity` answers `(nil, false)` when `local` is on neither
        side and `(nil, true)` when it is on one side and the other side's
        identity is nil. Both are `None` here: neither gives a caller an
        identity to act on, and the second is a hole the node could not have
        punched.
        """
        if self.active_identity is not None and self.active_identity == local:
            return self.passive_identity
        if self.passive_identity is not None and self.passive_identity == local:
            return self.active_identity
        return None

    def local_endpoint(self, local: Identity) -> Endpoint:
        """This node's own side of the hole. Go's `GetLocalAddr`."""
        return self._side(local, mine=True)

    def remote_endpoint(self, local: Identity) -> Endpoint:
        """The peer's side of the hole. Go's `GetRemoteAddr`."""
        return self._side(local, mine=False)

    def _side(self, local: Identity, *, mine: bool) -> Endpoint:
        if self.active_identity is not None and self.active_identity == local:
            return self.active_endpoint if mine else self.passive_endpoint
        if self.passive_identity is not None and self.passive_identity == local:
            return self.passive_endpoint if mine else self.active_endpoint
        raise BadArgument(
            f"nat.hole {self.nonce}: {local} is on neither side of it; "
            "Go's GetLocalAddr answers the passive side for a stranger, which "
            "is an address belonging to somebody else"
        )


PUNCH_SIGNALS: Final = ("offer", "answer", "ready", "go", "result")
"""The five steps of the punch handshake, in order.

Initiator sends `offer`, the passive side answers `answer` then `ready`, the
initiator says `go` and both punch, then the initiator reports `result`. Every
signal after `offer` must carry the session the offer established.
"""


JSON_TAGS: Final[dict[str, str]] = {
    "Signal": "signal",
    "Session": "session",
    "IP": "ip",
    "Port": "port",
    "PairNonce": "pair_nonce",
}
"""`nat.punch_signal`'s JSON names: the field name -> astral-go's `json:` tag.

This one type carries explicit tags where every other type in `nodes` and `nat`
marshals through its Go field names, and `MarshalJSON` goes through them. Four of
the five fold to the same key case-insensitively and `PairNonce` does not, so a
decoder that only folded case would refuse `pair_nonce` as an unknown field. The
map is what makes the JSON form the reference's rather than nearly it.
"""

_FIELD_OF_TAG: Final[dict[str, str]] = {tag: name for name, tag in JSON_TAGS.items()}


@record("nat.punch_signal")
class PunchSignal:
    """One control message of the punch handshake. `PUNCH_SIGNALS` names them.

    Declared for decode completeness: `nat.node_punch`, the only op that
    exchanges these, is dropped in v1. The binary form is the reflective field
    walk and needs no help; the JSON form goes through `JSON_TAGS`.
    """

    signal: str = wire("Signal", Primitive("string8"))
    session: bytes = wire("Session", Primitive("bytes8"))
    ip: IPAddress = wire("IP", Ref("mod.ip.ip_address"))
    port: int = wire("Port", Primitive("uint16"))
    pair_nonce: Nonce = wire("PairNonce", Primitive("nonce64"))

    def json(self) -> dict[str, Any]:
        """The field walk under astral-go's tag names."""
        walked = json_fields(type(self).FIELDS, self)
        return {JSON_TAGS[name]: value for name, value in walked.items()}

    @classmethod
    def from_json(cls, data: Any) -> "PunchSignal":
        """Either spelling: the tags, or the field names.

        A key that is one of the tags is renamed to its field name and anything
        else is left alone, so the ordinary case-insensitive walk still reads a
        payload written with the Go field names. A payload carrying **both**
        spellings of one field is ambiguous and the walk refuses it.
        """
        if not isinstance(data, dict):
            raise ParseError(
                f"nat.punch_signal: expected a JSON object, got "
                f"{type(data).__name__}"
            )
        renamed = {
            _FIELD_OF_TAG.get(str(key).lower(), key): value
            for key, value in data.items()
        }
        return cls(**read_json_fields(cls.FIELDS, renamed))


CONSUME_HOLE_SIGNALS: Final = ("lock", "locked", "take", "taken")
"""The two-phase handshake that hands a hole over: lock, then take."""


@record("nat.consume_hole_signal")
class ConsumeHoleSignal:
    """One control message of the consume-hole handshake.

    `ok` is a plain Go `bool` rather than an `astral.Bool`; the reflective codec
    maps it to the same single byte, verified against astral-go's own output.
    `error` carries the failure text when `ok` is false.
    """

    signal: str = wire("Signal", Primitive("string8"))
    pair: Nonce = wire("Pair", Primitive("nonce64"))
    ok: bool = wire("Ok", Primitive("bool"))
    error: str = wire("Error", Primitive("string8"))


# --- the client ----------------------------------------------------------


class Nat(ModuleClient):
    """The `nat` module's ops, over one `Client`. **Tier 3, gated.**

    Every op takes `experimental: bool = False` on top of the query keywords
    `ModuleClient` documents, and reads it rather than forwarding it. The gate,
    and why it is per call as well as per instance, is `astral.api.nodes`.
    """

    __slots__ = ("_experimental",)

    def __init__(self, client: Client, *, experimental: bool = False) -> None:
        super().__init__(client)
        self._experimental = bool(experimental)

    @property
    def opted_in(self) -> bool:
        """Whether this instance was constructed opted into the Tier 3 gate."""
        return self._experimental

    def _gate(self, op: str, experimental: bool) -> None:
        require_experimental(op, self._experimental or experimental)

    # --- the one read ---

    async def list_holes(
        self,
        peer: Identity | str | None = None,
        *,
        experimental: bool = False,
        **kw: Any,
    ) -> list[Hole]:
        """Every hole in the node's pool. ST, ends at `eos`.

        `peer` filters to the holes that peer is on either side of, and the node
        resolves it -- an alias, `localnode`, or a hex key. A name the node
        cannot resolve is an `error_message` **inside** the stream, so it
        surfaces as `RemoteError` and not as a rejection.

        **`peer`, not `with`.** The wire key is `with=`, which is a Python
        keyword and cannot be a parameter name. astral-docs writes it `-With`,
        which the node drops silently (D-17); this sends the lowercase name the
        registry declares.
        """
        self._gate(OP_LIST_HOLES, experimental)
        params: dict[str, Any] = {}
        if peer is not None:
            params["with"] = _param(_STRING8, _name(peer, OP_LIST_HOLES))
        qs = querystring.build(OP_LIST_HOLES, params)
        return [
            self._expect(obj, Hole, OP_LIST_HOLES)
            for obj in await self._c.call(qs, **kw)
        ]

    # --- the two writes ---

    async def punch(
        self, peer: Identity | str, *, experimental: bool = False, **kw: Any
    ) -> Hole:
        """Ask the node to punch a hole to a peer. RR, slow. **Mutates.**

        The node is the initiator: it runs the five-step handshake against the
        peer with its own puncher and registers the resulting hole in its pool.
        Nothing here punches, so this op needs no `nat.Puncher` of ours --
        unlike `node_punch`, which is the passive side and does.

        It takes as long as a UDP handshake across two NATs takes, so a caller's
        own `timeout=` is what bounds it. A failure is an `error_message`, which
        surfaces as `RemoteError`.

        **`peer`, not `target`.** The wire argument is `target=`, and `target`
        is also the routing keyword `Client.query` takes: here they are two
        different nodes, since the query goes to one node and asks it to punch
        towards another. astral-docs writes this argument `-Target`, which the
        node drops in silence (D-17).
        """
        self._gate(OP_PUNCH, experimental)
        qs = querystring.build(
            OP_PUNCH, {"target": _param(_STRING8, _name(peer, OP_PUNCH))}
        )
        return self._expect(await self._c.call_one(qs, **kw), Hole, OP_PUNCH)

    async def set_enabled(
        self, enabled: bool, *, experimental: bool = False, **kw: Any
    ) -> None:
        """Turn NAT traversal on or off. RR. **Mutates node settings.**

        The argument travels under the positional key `arg`, which is what the
        op declares; `enabled=` would be dropped in silence. The node answers
        `ack` whatever the value was, so the answer is not a report of what the
        setting became.
        """
        self._gate(OP_SET_ENABLED, experimental)
        if not isinstance(enabled, bool):
            raise BadArgument(
                f"{OP_SET_ENABLED}: {enabled!r} is not a bool; the op parses "
                "this argument with strconv.ParseBool"
            )
        qs = querystring.build(
            OP_SET_ENABLED, {POSITIONAL_KEY: _param(_BOOL, enabled)}
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_SET_ENABLED)

    # --- the two the design drops ---

    async def node_punch(self, *_args: Any, **_kw: Any) -> NoReturn:
        """**Dropped in v1** (design section 4.5). Needs a local UDP puncher.

        This is the *passive* side of the punch protocol: the node signals
        `answer`/`go` and the caller must open a UDP socket, punch towards the
        peer, and report which port answered -- astral-go's `nat.Puncher`
        interface. That is a transport implementation, not a client call, and
        this SDK's scope stops at the apphost session. `punch()` is the op that
        asks the node to do the punching instead.
        """
        raise FeatureUnavailable(
            f"{OP_NODE_PUNCH}: dropped in v1 (design section 4.5). It is the "
            "passive side of the punch protocol and requires a local UDP "
            "puncher (astral-go's nat.Puncher: open a socket, punch towards the "
            "peer, report the port that answered), which is a transport "
            "concern outside this SDK's scope. Use punch(), which asks the node "
            "to be the initiator"
        )

    async def node_consume_hole(self, *_args: Any, **_kw: Any) -> NoReturn:
        """**Dropped in v1** (design section 4.5). Needs a local UDP puncher.

        The initiator form answers a bare `ack`, but it hands a hole to a
        responder that must then own the punched socket, and the responder form
        drives a `lock`/`locked`/`take`/`taken` handshake and ends holding that
        socket. Neither half is usable without a puncher, so neither ships.
        """
        raise FeatureUnavailable(
            f"{OP_NODE_CONSUME_HOLE}: dropped in v1 (design section 4.5). Both "
            "its forms end with the caller owning a punched UDP socket, which "
            "requires a local puncher (astral-go's nat.Puncher) this SDK does "
            "not implement"
        )


# --- argument discipline -------------------------------------------------


_param = ModuleClient._param
"""One parameter value, in its text form. `ModuleClient`'s, not a copy."""


def _name(value: Identity | str, op: str) -> str:
    """A name argument the node resolves: an alias, `localnode`, or a hex key.

    An empty string is refused: astrald's resolver maps it to the zero identity,
    so an accidental empty name asks about `anyone`, which no hole is ever on.
    """
    if isinstance(value, Identity):
        return value.text()
    if not value:
        raise BadArgument(
            f"{op}: the empty name resolves to the zero identity on the node; "
            "pass Identity.ANYONE to mean that identity"
        )
    return value


NAT_TYPES: Final[Sequence[type]] = (
    ConsumeHoleSignal,
    Endpoint,
    Hole,
    PunchSignal,
)
"""Every wire type this module declares, for a private-registry sweep.

`mod.ip.ip_address` is not here: `astral.api.ip` declares it and this module
reaches it by name through the registry.
"""

Nat.TYPES = NAT_TYPES
