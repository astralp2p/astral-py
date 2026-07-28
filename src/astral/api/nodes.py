"""`nodes`: links, sessions, endpoints and the node invite string.

**Tier 3, experimental, and every op is gated.** Design section 0.1 puts `nodes`
and `nat` behind an explicit opt-in and section 10 step 15 calls that gate
"import-gated". Import gating is not what ships, and the reason is a rule this
package enforces with a test: `astral/api/__init__.py` imports every module
eagerly so that **importing `astral` registers every wire type this SDK can
decode**. A `mod.nodes.link_info` can arrive on any stream a caller opens -- it
is what `nodes.links` answers, and `objects.search` can name one -- so making
its decodability depend on an opt-in would trade a legible refusal for a
`BlueprintNotFound` in production. The gate is therefore on the **ops**, not on
the types: the seven ops refuse to run without `experimental=True`, and all
eleven types decode always. This is the single divergence from section 10 that
this module takes, and it is deliberate.

    from astral.api.nodes import Nodes
    nodes = Nodes(client, experimental=True)   # opted in once
    await nodes.links()

    await client.nodes.links(experimental=True)   # opted in per call

`FeatureUnavailable` is what a gated op raises, which is what
`serve.require_service_transport` already raises for the gated register-service
path (design section 4.4) -- one exception for "this SDK will not do that in
this configuration, and here is the flag that changes it".

**Op surface, and the shape each one declares** (design section 4.7; a shape is
a per-op contract and is not discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `nodes.links` | ST | `mod.nodes.link_info` x n ++ `eos` | read-only |
| `nodes.sessions` | ST | `mod.nodes.session_info` x n ++ `eos` | read-only |
| `nodes.resolve_endpoints` | ST | `endpoint_with_ttl` x n ++ `eos` | read-only |
| `nodes.add_endpoint` | RR | `ack` \\| `error_message` | **mutates** (90-day TTL) |
| `nodes.close_link` | RR | `ack` \\| `error_message` | **mutates** |
| `nodes.new_link` | RR (long) | `link_info` \\| `error_message` \\| reject 2-5 | **mutates** |
| `nodes.migrate_session` | RR | `ack` \\| `error_message` | **mutates** |

Parameter names and which of them the node enforces are read off the live
`shell.spec` registry rather than off the docs: `nodes.migrate_session` marks
`session_id` and `link_id` required and `nodes.new_link` marks `target`
required; every other parameter of every other op is optional, `out` included.

**`nodes.migrate_session` ships only in its `start=true` form.** Design section
4.5 drops the negotiated mode -- the `ready`/`switched`/`resume`/`done` signal
handshake -- in v1: it needs two live nodes and an astrald-only state machine
that no client reference implements and that cannot be verified here.
`migrate_session(..., start=False)` therefore raises rather than opening a
channel this SDK would not drive. `MigrateSignal` is declared anyway, because
the node sends one to a peer that speaks that mode and a decoder that did not
know the type could not even name what it received.

**`mod.nodes.node_info` is hand-rolled on the Go side and is hand-rolled here.**
It is the one type in this module whose binary form is not the reflective field
walk:

    string8(Alias) ++ 33 flat identity bytes ++ uint8(count)
                   ++ (uint8(tag) ++ endpoint payload) x count

with `tag` numeric -- `0` tcp, `1` tor, `2` gateway -- and **anything else a
hard decode error**, matching `astral-go/api/nodes/node_info.go`. Two traps live
in those bytes and both are pinned by vectors generated from astral-go itself:

- **The identity is flat.** The Go field is `*astral.Identity`, so the
  reflective codec would write a presence byte in front of it; `WriteTo` calls
  `Identity.WriteTo` directly and writes 33 bytes with no flag. A zero
  `node_info` is `00` ++ 33 zero bytes ++ `00`, 35 bytes, and astral-go emits
  exactly that.
- **There is no tag for kcp**, even though kcp is now the NAT transport and
  `furry-bolt` advertises two `mod.kcp.endpoint`s of its own -- verified live
  through `nodes.resolve_endpoints`. astral-go's `WriteTo` answers
  `unknown endpoint type` for a `node_info` carrying one, so **a node whose
  endpoints include kcp cannot express its own invite string**. That is an
  astral-go limitation, recorded here and not worked around: inventing a tag
  would produce a blob no other implementation could read.

**Never ask a node to construct a zero one.** `objects.new` on this type
**panics astrald**, deterministically, on every build carrying astral-go
`5c18d9c`: `WriteTo` hands `info.Identity`, a `*astral.Identity`, to
`streams.WriteAllTo`, and `Identity.WriteTo` has a value receiver, so the nil
pointer in the zero value the registry builds is dereferenced rather than
erroring, on a goroutine with no recover. A guard exists on an unmerged
astral-go branch. Decoding a `node_info` is entirely safe -- it is what this
module does -- and asking the node to build one is not. `NodeInfo()` here is
that zero value, needs no node, and is byte-identical to what astral-go writes
once the identity is non-nil.

The text form is base62 of that blob (`jxskiss/base62`, alphabet `[A-Za-z0-9]`),
and so is the JSON form: `NodeInfo` has a `MarshalText` and no `MarshalJSON`, so
astral-go's JSON channel sender -- `json.Marshal(object)` in
`astral/channel/json_sender.go` -- emits the base62 **string**, not a field
walk. `json()` and `from_json()` below match that, so a `node_info` crossing
`out=json` round-trips against the reference rather than against this SDK's own
field walk.

**The endpoint types are not declared here.** `mod.tcp.endpoint`,
`mod.tor.endpoint`, `mod.gateway.endpoint` and `mod.kcp.endpoint` ship in
`astral.api.endpoints` (design section 0.1), and this module reaches them by
**name** through the registry -- `Any()` for the interface-typed fields of
`link_info`, `endpoint_with_ttl` and `observed_endpoint_message`, and the
numeric tag table for `node_info`. So there is no import edge, and a stream
carrying an endpoint type the registry does not know fails as
`unknown type mod.tcp.endpoint` rather than silently.

Reached as `client.nodes`, a `functools.cached_property` built on first use.
"""

from __future__ import annotations

from typing import Any, Final, Sequence

from .. import querystring
from ..client import Client
from ..codec.binary import (
    nested_frame,
    object_reader,
    payload_bytes,
    read_object,
    read_spec,
    write_spec,
)
from ..errors import (
    BadArgument,
    FeatureUnavailable,
    ParseError,
    SchemaError,
    StreamCorrupted,
    ValueTooLarge,
)
from ..object import Ack
from ..record import record, wire
from ..spec import AnySpec, Primitive, Ptr, Slice, Spec
from ..types import Duration, Identity, Nonce
from ..wire import Reader, Writer
from .auth import Action
from .base import ModuleClient

__all__ = [
    "ENDPOINT_TAGS",
    "EndpointWithTTL",
    "LinkClosedEvent",
    "LinkCreatedEvent",
    "LinkInfo",
    "LinkPressureEvent",
    "MIGRATE_SIGNALS",
    "MigrateSignal",
    "NODES_TYPES",
    "NewObservedEndpointEvent",
    "NodeInfo",
    "Nodes",
    "OP_ADD_ENDPOINT",
    "OP_CLOSE_LINK",
    "OP_LINKS",
    "OP_MIGRATE_SESSION",
    "OP_NEW_LINK",
    "OP_RESOLVE_ENDPOINTS",
    "OP_SESSIONS",
    "ObservedEndpointMessage",
    "RelayForAction",
    "SessionInfo",
    "base62_decode",
    "base62_encode",
    "require_experimental",
]

OP_ADD_ENDPOINT: Final = "nodes.add_endpoint"
OP_CLOSE_LINK: Final = "nodes.close_link"
OP_LINKS: Final = "nodes.links"
OP_MIGRATE_SESSION: Final = "nodes.migrate_session"
OP_NEW_LINK: Final = "nodes.new_link"
OP_RESOLVE_ENDPOINTS: Final = "nodes.resolve_endpoints"
OP_SESSIONS: Final = "nodes.sessions"

# astrald splits the strategy list on this byte and trims each name
# (`mod/nodes/src/op_new_link.go` `OpNewLink`), so a name containing one is two
# strategies on the server.
STRATEGY_SEPARATOR: Final = ","

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
_BOOL: Final[Spec] = Primitive("bool")
_IDENTITY: Final[Spec] = Primitive("identity")
_NONCE: Final[Spec] = Primitive("nonce64")
_STRING8: Final[Spec] = Primitive("string8")


# --- the gate ------------------------------------------------------------


def require_experimental(op: str, opted_in: bool) -> None:
    """Refuse a Tier 3 op that the caller has not opted into.

    One gate and one message for both Tier 3 modules. It lives here rather than
    in `base.py`, which belongs to every module, and rather than in a private
    third file, which design section 1's layout does not have: `nat` imports it
    from `nodes`, which is a leaf-to-leaf edge with no cycle in it.

    What the gate is not is a claim that these ops are unsafe to call:
    `nodes.links` is read-only and answers on any node. What it is, is design
    section 0.1's Tier 3 in force. This surface is the least covered by the
    reference client -- 2 of 7 `nodes` ops have an astral-go client at all --
    two of `nat`'s five ops are dropped outright (section 4.5), and four of
    these seven **mutate node state**: `close_link` drops a live link,
    `add_endpoint` writes a record that stands for 90 days. An SDK that let all
    of that be reached by a typo in an attribute name would be overstating what
    it has verified.

    The message names the class the caller would construct, which is read off
    the op's own module prefix so it cannot name the wrong one.
    """
    if opted_in:
        return
    module = op.partition(".")[0]
    raise FeatureUnavailable(
        f"{op}: the nodes and nat modules are Tier 3 experimental (design "
        "section 0.1) and every op is gated. Pass experimental=True to this "
        f"call, or construct the module client with it -- "
        f"{module.capitalize()}(client, experimental=True)"
    )


# --- base62, the node invite string's alphabet ---------------------------
#
# A port of `github.com/jxskiss/base62` v1.1.0, which is what astral-go's
# `NodeInfo.MarshalText` calls. It is **not** a base conversion of the blob as
# one big integer: it is a little-endian bit stream read six bits at a time from
# the last byte back, where a group whose bits 1-4 are all set consumes five bits
# instead of six. Two implementations that both call themselves base62 therefore
# disagree on nearly every input, so the algorithm is ported rather than
# approximated, and the vectors in `tests/test_api_nodes.py` are the reference
# implementation's own output.

BASE62_ALPHABET: Final = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)
"""jxskiss/base62's `StdEncoding`: `[A-Za-z0-9]`, letters before digits.

Not the `[0-9A-Za-z]` order most base62 tables use. A table in the other order
encodes every byte string to a different text.
"""

_BASE62_VALUES: Final = {char: index for index, char in enumerate(BASE62_ALPHABET)}

_COMPACT_MASK: Final = 0x1E
_MASK_5: Final = 0x1F
_MASK_6: Final = 0x3F


def _six_bits(src: bytes, pos: int) -> int:
    """The six bits ending at bit `pos`, counting from the end of `src`."""
    remainder = pos & 7
    index = pos >> 3
    if remainder == 0:
        index, remainder = index - 1, 8
    value = src[index] >> (8 - remainder)
    if remainder < 6 and index > 0:
        value |= src[index - 1] << remainder
    return value & _MASK_6


def base62_encode(data: bytes) -> str:
    """jxskiss/base62 `Encode`. The empty input encodes to the empty string."""
    if not data:
        return ""
    out: list[str] = []
    pos = len(data) * 8
    while pos > 0:
        size = 6
        value = _six_bits(data, pos)
        if value & _COMPACT_MASK == _COMPACT_MASK:
            if pos > 6 or value > _MASK_5:
                size = 5
            value &= _MASK_5
        out.append(BASE62_ALPHABET[value])
        pos -= size
    return "".join(out)


def base62_decode(text: str) -> bytes:
    """jxskiss/base62 `Decode`. A character outside the alphabet is a fault.

    Go's decoder writes into a buffer sized `len(src)*6/8+1` from the back and
    panics if that estimate is short; a hostile string cannot make it short, but
    the guard is explicit here rather than an index that would silently wrap
    around a Python list.
    """
    if not text:
        return b""
    out = bytearray(len(text) * 6 // 8 + 1)
    index = len(out)
    pos = 0
    acc = 0
    last = len(text) - 1
    for offset, char in enumerate(text):
        value = _BASE62_VALUES.get(char)
        if value is None:
            raise ParseError(f"base62: {char!r} at offset {offset} is not base62")
        acc |= value << pos
        if offset == last:
            pos += value.bit_length()
        elif value & _COMPACT_MASK == _COMPACT_MASK:
            pos += 5
        else:
            pos += 6
        if pos >= 8:
            if index == 0:  # pragma: no cover -- unreachable by construction
                raise ParseError(f"base62: {text!r} decodes past its own length")
            index -= 1
            out[index] = acc & 0xFF
            pos %= 8
            acc >>= 8
    if pos > 0:
        if index == 0:  # pragma: no cover -- unreachable by construction
            raise ParseError(f"base62: {text!r} decodes past its own length")
        index -= 1
        out[index] = acc & 0xFF
    return bytes(out[index:])


# --- wire types ----------------------------------------------------------


ENDPOINT_TAGS: Final[dict[int, str]] = {
    0: "mod.tcp.endpoint",
    1: "mod.tor.endpoint",
    2: "mod.gateway.endpoint",
}
"""`mod.nodes.node_info`'s numeric endpoint tags, and the whole of them.

`mod.kcp.endpoint` has no tag. astral-go's switch has three cases and a default
that errors, on both the read and the write side, so a `node_info` carrying a
kcp endpoint is unrepresentable in the reference implementation -- and the live
node advertises kcp endpoints. Adding a fourth entry here would encode blobs
nothing else can read.
"""

_TAG_OF_ENDPOINT: Final[dict[str, int]] = {
    name: tag for tag, name in ENDPOINT_TAGS.items()
}


@record("mod.nodes.link_info")
class LinkInfo:
    """One live link between two nodes.

    The two endpoint fields are interface-typed on the Go side, so each carries
    its own `string8` type tag on the wire and decoding one needs the endpoint
    type registered (`astral.api.endpoints`). An absent endpoint is a zero-length
    tag, which decodes to `None` rather than failing.

    `bytes_throughput` is bytes per second at the moment the node built the
    record, not a total. `network` is the exonet network name (`tcp`, `tor`,
    `gw`, `kcp`), which is also derivable from the endpoint type and is sent
    anyway.
    """

    id: Nonce = wire("ID", Primitive("nonce64"))  # noqa: A003
    local_identity: Identity | None = wire("LocalIdentity", Ptr("identity"))
    remote_identity: Identity | None = wire("RemoteIdentity", Ptr("identity"))
    local_endpoint: Any = wire("LocalEndpoint", AnySpec())
    remote_endpoint: Any = wire("RemoteEndpoint", AnySpec())
    outbound: bool = wire("Outbound", Primitive("bool"))
    network: str = wire("Network", Primitive("string8"))
    high_pressure: bool = wire("HighPressure", Primitive("bool"))
    bytes_throughput: int = wire("BytesThroughput", Primitive("uint64"))


@record("mod.nodes.session_info")
class SessionInfo:
    """One open session multiplexed over a link.

    `query` is the query string the session carries, so a session list is also
    the answer to "what is this node doing right now". `age` is a `duration`,
    nanoseconds on the wire.
    """

    id: Nonce = wire("ID", Primitive("nonce64"))  # noqa: A003
    link_id: Nonce = wire("LinkID", Primitive("nonce64"))
    remote_identity: Identity | None = wire("RemoteIdentity", Ptr("identity"))
    outbound: bool = wire("Outbound", Primitive("bool"))
    query: str = wire("Query", Primitive("string16"))
    bytes: int = wire("Bytes", Primitive("uint64"))  # noqa: A003
    age: Duration = wire("Age", Primitive("duration"))


@record("mod.nodes.endpoint_with_ttl")
class EndpointWithTTL:
    """An endpoint and how long the node will keep believing in it.

    `ttl` is seconds and `None` means no expiry -- a `*astral.Uint32` on the Go
    side, so the pointer's nil flag is the whole distinction between "no expiry"
    and "expires in zero seconds". `nodes.add_endpoint` writes 90 days
    (7 776 000); the endpoints `furry-bolt` resolves for itself carry 7 days
    (604 800) for tcp and kcp and 90 days for tor.
    """

    endpoint: Any = wire("Endpoint", AnySpec())
    ttl: int | None = wire("TTL", Ptr("uint32"))


@record("mod.nodes.node_info")
class NodeInfo:
    """A node's alias, identity and endpoints: the invite string.

    Hand-rolled on both sides. See this module's docstring for the layout, the
    flat identity and the missing kcp tag.

    `endpoints` holds decoded endpoint objects, whose types come from
    `astral.api.endpoints` through the registry. Constructing one for a type
    with no numeric tag is refused on **write**, where astral-go refuses it too,
    rather than at construction: a `NodeInfo` decoded from a peer and handed
    straight back must not fail differently from one this SDK built.
    """

    alias: str = wire("Alias", Primitive("string8"))
    identity: Identity = wire("Identity", Primitive("identity"))
    endpoints: list[Any] = wire("Endpoints", Slice())

    # The escape hatch of design section 2.5, which sets `DERIVABLE` to False.
    # The declaration above is still what gives each field its zero value and
    # its name, and it is **not** a description of these bytes: `blueprint.of()`
    # refuses this class for exactly that reason, since a peer handed such a
    # blueprint would encode a shape the class cannot read. The JSON form is
    # overridden below too, so the schema serves construction and reading, not
    # the wire.
    def write_payload(self, w: Writer) -> None:
        with nested_frame(w, "mod.nodes.node_info"):
            write_spec(w, _NODE_INFO_ALIAS, self.alias)
            write_spec(w, _NODE_INFO_IDENTITY, self.identity)
            count = len(self.endpoints)
            if count > 255:
                # astral-go returns `too many endpoints` here. The count is a
                # uint8 and nothing above it is expressible.
                raise ValueTooLarge(
                    f"mod.nodes.node_info: {count} endpoints exceeds the 255 a "
                    "uint8 count can carry"
                )
            w.uint8(count)
            for endpoint in self.endpoints:
                w.uint8(_endpoint_tag(endpoint))
                endpoint.write_payload(w)

    @classmethod
    def read_payload(cls, r: Reader) -> "NodeInfo":
        with nested_frame(r, "mod.nodes.node_info"):
            alias = read_spec(r, _NODE_INFO_ALIAS)
            identity = read_spec(r, _NODE_INFO_IDENTITY)
            endpoints = []
            for _ in range(r.uint8()):
                tag = r.uint8()
                type_name = ENDPOINT_TAGS.get(tag)
                if type_name is None:
                    raise StreamCorrupted(
                        f"mod.nodes.node_info: endpoint type tag {tag} is not "
                        f"one of {sorted(ENDPOINT_TAGS)}; the payload cannot be "
                        "located past it"
                    )
                endpoints.append(read_object(r, type_name))
        return cls(alias=alias, identity=identity, endpoints=endpoints)

    # --- the text and JSON forms, which are the same string ---

    def text(self) -> str:
        """The invite string: base62 of the binary payload."""
        return base62_encode(payload_bytes(self))

    @classmethod
    def parse(cls, text: str) -> "NodeInfo":
        """A node invite string back into a `NodeInfo`."""
        return cls.read_payload(object_reader(base62_decode(text)))

    def json(self) -> str:
        """The same base62 string.

        `NodeInfo` has a `MarshalText` and no `MarshalJSON`, and astral-go's
        JSON channel sender marshals the object itself, so `encoding/json` uses
        the text marshaler and the JSON body is the invite string. A field walk
        here would be this SDK talking to itself.
        """
        return self.text()

    @classmethod
    def from_json(cls, data: Any) -> "NodeInfo":
        if not isinstance(data, str):
            raise ParseError(
                f"mod.nodes.node_info: JSON is the base62 invite string, got "
                f"{type(data).__name__}"
            )
        return cls.parse(data)


_NODE_INFO_ALIAS: Final[Spec] = Primitive("string8")
_NODE_INFO_IDENTITY: Final[Spec] = Primitive("identity")


def _endpoint_tag(endpoint: Any) -> int:
    """The numeric tag of an endpoint, or the fault of it having none."""
    type_name = getattr(endpoint, "ASTRAL_TYPE", "")
    tag = _TAG_OF_ENDPOINT.get(type_name)
    if tag is None:
        raise SchemaError(
            f"mod.nodes.node_info: {type_name or type(endpoint).__name__} has no "
            f"numeric endpoint tag; the type carries one of "
            f"{sorted(ENDPOINT_TAGS.values())}. mod.kcp.endpoint has none in "
            "astral-go either, so a node with kcp endpoints cannot express its "
            "own node_info"
        )
    return tag


MIGRATE_SIGNALS: Final = ("ready", "switched", "resume", "done")
"""The four signals of the negotiated `nodes.migrate_session` handshake.

Declared, not driven: design section 4.5 drops the negotiated mode in v1.
"""


@record("mod.nodes.migrate_signal")
class MigrateSignal:
    """One step of the session-migration handshake.

    `buffer` is the sender's receive-buffer size, so the peer can size its write
    window. The signal names are `MIGRATE_SIGNALS`.
    """

    signal: str = wire("Signal", Primitive("string8"))
    buffer: int = wire("Buffer", Primitive("uint32"))


@record("mod.nodes.observed_endpoint_message")
class ObservedEndpointMessage:
    """An endpoint a peer observed this node arriving from.

    One polymorphic field and nothing else: astral-go encodes it through the
    generic `astral.Encode`/`Decode`, which is the type tag plus the payload,
    unlike `node_info`'s numeric tags. The two are not interchangeable.
    """

    endpoint: Any = wire("Endpoint", AnySpec())


@record("mod.nodes.relay_for_action")
class RelayForAction(Action):
    """Permission for the actor to relay traffic for another identity.

    An `auth` action: `Nonce` and `ActorID` come first and flatten under their
    own names, which is what `auth.Action` exists for. astral-go's
    `ApplyConstraints` accepts only an empty constraint bundle, so a permit
    granting this action grants it for every identity or for none.
    """

    for_id: Identity | None = wire("ForID", Ptr("identity"))


@record("mod.nodes.link_created_event")
class LinkCreatedEvent:
    """A link came up. `link_count` is how many the node holds afterwards."""

    remote_identity: Identity | None = wire("RemoteIdentity", Ptr("identity"))
    link_id: Nonce = wire("LinkID", Primitive("nonce64"))
    link_count: int = wire("LinkCount", Primitive("uint32"))


@record("mod.nodes.link_closed_event")
class LinkClosedEvent:
    """A link went down.

    `link_count` is a `uint8` here and a `uint32` on `link_created_event`. That
    asymmetry is in astral-go's source, not a transcription slip, and it means a
    node holding more than 255 links reports a wrapped count on close.
    """

    remote_identity: Identity | None = wire("RemoteIdentity", Ptr("identity"))
    forced: bool = wire("Forced", Primitive("bool"))
    link_count: int = wire("LinkCount", Primitive("uint8"))


@record("mod.nodes.link_pressure_event")
class LinkPressureEvent:
    """A link crossed its pressure threshold in either direction."""

    remote_identity: Identity | None = wire("RemoteIdentity", Ptr("identity"))
    link_id: Nonce = wire("LinkID", Primitive("nonce64"))


@record("mod.nodes.new_observed_endpoint_event")
class NewObservedEndpointEvent:
    """A peer reported a new endpoint for this node. No fields, no payload."""


# --- the client ----------------------------------------------------------


class Nodes(ModuleClient):
    """The `nodes` module's ops, over one `Client`. **Tier 3, gated.**

    Every op takes `experimental: bool = False` on top of the query keywords
    `ModuleClient` documents. That keyword is **read** rather than forwarded,
    which is the one place this module departs from the base class's contract,
    and it departs deliberately: a gate the caller states at the call site is
    one a reviewer can see, and `client.serve(..., experimental=True)` already
    spells the register-service gate that way (design section 4.4).

    `Nodes(client, experimental=True)` opts the whole instance in, for a program
    that has decided once.
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

    # --- reads ---

    async def links(
        self, *, experimental: bool = False, **kw: Any
    ) -> list[LinkInfo]:
        """Every link the node holds. ST, ends at `eos`.

        Ordered oldest first: astrald sorts by the link's creation time
        (`mod/nodes/src/op_links.go` `OpLinks`). An idle node answers a bare
        `eos` and this is an empty list.
        """
        self._gate(OP_LINKS, experimental)
        return [
            self._expect(obj, LinkInfo, OP_LINKS)
            for obj in await self._c.call(OP_LINKS, **kw)
        ]

    async def sessions(
        self, *, experimental: bool = False, **kw: Any
    ) -> list[SessionInfo]:
        """Every open session on every link. ST, ends at `eos`.

        Ordered oldest first. astrald skips a session that is not open and one
        whose link it can no longer find (`mod/nodes/src/op_sessions.go`
        `OpSessions`), so the answer is what is live at that instant rather than
        every session the muxes hold.
        """
        self._gate(OP_SESSIONS, experimental)
        return [
            self._expect(obj, SessionInfo, OP_SESSIONS)
            for obj in await self._c.call(OP_SESSIONS, **kw)
        ]

    async def resolve_endpoints(
        self, name: Identity | str, *, experimental: bool = False, **kw: Any
    ) -> list[EndpointWithTTL]:
        """Every endpoint the node can find for an identity. ST, ends at `eos`.

        `name` is resolved by the node -- an alias, `localnode`, or a hex key --
        because the op declares `ID string` and hands it to the directory. An
        identity the node cannot resolve is **rejected with code 2**, which
        surfaces as `QueryRejected`, not as an `error_message`.

        The answers are `mod.nodes.endpoint_with_ttl`, whose endpoint field is
        polymorphic, so this is the op that needs `astral.api.endpoints`
        registered. Verified live against `furry-bolt`: five endpoints, two tcp,
        one tor and two kcp.
        """
        self._gate(OP_RESOLVE_ENDPOINTS, experimental)
        qs = querystring.build(
            OP_RESOLVE_ENDPOINTS,
            {"id": _param(_STRING8, _name(name, OP_RESOLVE_ENDPOINTS))},
        )
        return [
            self._expect(obj, EndpointWithTTL, OP_RESOLVE_ENDPOINTS)
            for obj in await self._c.call(qs, **kw)
        ]

    # --- writes ---

    async def add_endpoint(
        self,
        identity: Identity | str,
        endpoint: str,
        *,
        experimental: bool = False,
        **kw: Any,
    ) -> None:
        """Record an endpoint for an identity. RR. **Mutates**, for 90 days.

        `endpoint` is `<network>:<address>` -- `tcp:10.21.0.5:1791`,
        `kcp:10.21.0.5:1792` -- and the node splits it on the **first** colon
        only, so an IPv6 address needs its brackets. The TTL is astrald's, fixed
        at three 30-day months, and is not a parameter.

        `identity` is parsed as an identity by the op, so a directory name never
        reaches it; resolve one first.
        """
        self._gate(OP_ADD_ENDPOINT, experimental)
        if ":" not in endpoint:
            raise BadArgument(
                f"{OP_ADD_ENDPOINT}: {endpoint!r} is not <network>:<address>; "
                "the node splits this argument on the first colon and answers "
                "`invalid endpoint` without one"
            )
        qs = querystring.build(
            OP_ADD_ENDPOINT,
            {
                "id": _param(_IDENTITY, _identity(identity, OP_ADD_ENDPOINT)),
                "endpoint": _param(_STRING8, endpoint),
            },
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_ADD_ENDPOINT)

    async def close_link(
        self, link_id: Nonce | int | str, *, experimental: bool = False, **kw: Any
    ) -> None:
        """Drop a link by id. RR. **Mutates.**

        Every session multiplexed over that link dies with it. The id is a
        `nonce64`, which `links()` reports as `LinkInfo.id`; an id the node does
        not hold answers with an `error_message`.
        """
        self._gate(OP_CLOSE_LINK, experimental)
        qs = querystring.build(
            OP_CLOSE_LINK, {"id": _param(_NONCE, _nonce(link_id, OP_CLOSE_LINK))}
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_CLOSE_LINK)

    async def new_link(
        self,
        peer: Identity | str,
        *,
        endpoint: str | None = None,
        strategies: str | Sequence[str] | None = None,
        experimental: bool = False,
        **kw: Any,
    ) -> LinkInfo:
        """Build a link to a peer. RR, and it can be slow. **Mutates.**

        With `endpoint` set the node dials exactly that `<network>:<address>`;
        without it, it runs the named strategies, or every strategy it has when
        `strategies` is omitted too. The node **accepts the query before the
        link exists**, deliberately, so that link creation may outlast the query
        timeout -- so a caller's own `timeout=` is what bounds this, and the
        default one is likely to be too short.

        The failure modes are reject codes, not error messages: 2 for an
        unresolvable peer or a malformed endpoint, 3 for an endpoint the exonet
        parser refuses, 4 for a cancelled context or a resolver failure and 5
        for a scheduler refusal. They surface numerically in `QueryRejected`;
        design risk R-17 declines to map them to meanings, because the table is
        source-only.

        **`peer`, not `target`.** The wire argument is `target=` and travels as
        one, but `target` is also the routing keyword every module-client method
        forwards to `Client.query` -- which node answers the query -- and here
        the two are different nodes: the query goes to one node and asks it to
        link to another. `Tree.mount_remote` renamed the same collision for the
        same reason.

        `target=` is the one required parameter in this module besides
        `migrate_session`'s two, per the live registry.
        """
        self._gate(OP_NEW_LINK, experimental)
        params: dict[str, Any] = {"target": _param(_STRING8, _name(peer, OP_NEW_LINK))}
        if endpoint is not None:
            if ":" not in endpoint:
                raise BadArgument(
                    f"{OP_NEW_LINK}: {endpoint!r} is not <network>:<address>; "
                    "the node rejects this query with code 3 without a colon"
                )
            params["endpoint"] = _param(_STRING8, endpoint)
        if strategies is not None:
            params["strategies"] = _param(
                _STRING8, _strategy_list(strategies, OP_NEW_LINK)
            )
        obj = await self._c.call_one(querystring.build(OP_NEW_LINK, params), **kw)
        return self._expect(obj, LinkInfo, OP_NEW_LINK)

    async def migrate_session(
        self,
        session_id: Nonce | int | str,
        link_id: Nonce | int | str,
        *,
        start: bool = True,
        experimental: bool = False,
        **kw: Any,
    ) -> None:
        """Move an open session onto another link. RR. **Mutates.**

        Only the `start=true` form ships. With `start` set the node drives the
        migration itself and answers a single `ack`; with it clear the node
        becomes the **responder** of a `ready`/`switched`/`resume`/`done`
        handshake that the caller must drive, and design section 4.5 drops that
        mode in v1 -- it needs two live nodes and an astrald-only state machine
        that no client reference implements. `start=False` therefore raises here
        instead of opening a channel this SDK would leave hanging, which would
        cost one of the node's 32 workers.

        Both ids are required by the op itself, so neither is defaulted.
        """
        self._gate(OP_MIGRATE_SESSION, experimental)
        if not start:
            raise FeatureUnavailable(
                f"{OP_MIGRATE_SESSION}: the negotiated mode (start=false) is "
                "dropped in v1 (design section 4.5). It makes the node the "
                "responder of a ready/switched/resume/done handshake this SDK "
                "does not drive, and an undriven channel holds one of the "
                "node's 32 workers. Pass start=True, which the node drives "
                "itself and answers with one ack"
            )
        qs = querystring.build(
            OP_MIGRATE_SESSION,
            {
                "session_id": _param(_NONCE, _nonce(session_id, OP_MIGRATE_SESSION)),
                "link_id": _param(_NONCE, _nonce(link_id, OP_MIGRATE_SESSION)),
                "start": _param(_BOOL, True),
            },
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_MIGRATE_SESSION)


# --- argument discipline -------------------------------------------------


_param = ModuleClient._param
"""One parameter value, in its text form. `ModuleClient`'s, not a copy."""


def _identity(value: Identity | str, op: str) -> Identity:
    """An identity argument: 66 hex characters or `anyone`, never a name."""
    if isinstance(value, Identity):
        return value
    try:
        return Identity.parse(value)
    except ParseError as exc:
        raise ParseError(
            f"{op}: {value!r} is not an identity; this argument is parsed as one "
            f"and a directory name never reaches it -- resolve it first"
        ) from exc


def _name(value: Identity | str, op: str) -> str:
    """A name argument the node resolves: an alias, `localnode`, or a hex key.

    An empty string is refused: astrald's resolver maps `""` and `"anyone"` to
    the zero identity, so an accidental empty name asks about `anyone` and
    `resolve_endpoints` then answers a bare `eos` for it.
    """
    if isinstance(value, Identity):
        return value.text()
    if not value:
        raise BadArgument(
            f"{op}: the empty name resolves to the zero identity on the node; "
            "pass Identity.ANYONE to mean that identity"
        )
    return value


def _nonce(value: Nonce | int | str, op: str) -> Nonce:
    """A `nonce64` argument, from a `Nonce`, an int, or 16 hex digits."""
    if isinstance(value, Nonce):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return Nonce(value)
    if isinstance(value, str):
        try:
            return Nonce.parse(value)
        except ParseError as exc:
            raise ParseError(f"{op}: {value!r} is not a nonce64") from exc
    raise BadArgument(f"{op}: {value!r} is not a nonce64")


def _strategy_list(strategies: str | Sequence[str], op: str) -> str:
    """Strategy names, joined for the wire.

    A single name is accepted unwrapped. A name carrying the separator is two
    strategies on the server, and an empty list is an empty argument, which
    astrald reads as "every strategy" -- the opposite of what an empty list
    means to a caller -- so both are refused here.
    """
    names = [strategies] if isinstance(strategies, str) else list(strategies)
    if not names:
        raise BadArgument(
            f"{op}: no strategy names; the node reads an empty argument as "
            "every strategy it has, so omit the argument to mean that"
        )
    for name in names:
        if not name.strip():
            raise BadArgument(f"{op}: empty strategy name")
        if STRATEGY_SEPARATOR in name:
            raise BadArgument(
                f"{op}: strategy name {name!r} contains "
                f"{STRATEGY_SEPARATOR!r}, which the node reads as two names"
            )
    return STRATEGY_SEPARATOR.join(names)


NODES_TYPES: Final[Sequence[type]] = (
    EndpointWithTTL,
    LinkClosedEvent,
    LinkCreatedEvent,
    LinkInfo,
    LinkPressureEvent,
    MigrateSignal,
    NewObservedEndpointEvent,
    NodeInfo,
    ObservedEndpointMessage,
    RelayForAction,
    SessionInfo,
)
"""Every wire type this module declares, for a private-registry sweep.

The four endpoint types the polymorphic fields resolve to are **not** here:
they belong to `astral.api.endpoints` (design section 0.1) and are reached by
name through the registry.
"""

Nodes.TYPES = NODES_TYPES
