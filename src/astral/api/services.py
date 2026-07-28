"""`services`: what a node offers, and the cache of what its peers offer.

Tier 1, two ops, and the module that proves the `bundle` kind inside a record.

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `services.discover` | ST, ST+follow | `services.update` × n ++ `eos` | read-only |
| `services.sync` | RR, BD with `follow` | `ack` \\| `error_message` | **mutates** |

Both are the complete surface: the live `shell.spec` registry holds
`services.discover` and `services.sync` and nothing else under this module.
Verified against `furry-bolt` this session.

**`services.update` is one record with two pointer slots.** Field order,
widths and both nil flags read off the node itself -- `objects.new?type=
services.update` builds the zero value server-side and sends it as
`0f 73657276696365732e757064617465 00000004 00000000`, four zero bytes for four
fields::

    01                          Available   bool, one byte
    07 67617465776179          Name        string8
    01 03b270…ae1               ProviderID  ptr, flag then 33 flat identity bytes
    01 <bundle payload>         Info        ptr, flag then the bundle

`Available` is a plain Go `bool` in astral-go's struct, not an `astral.Bool`;
the reflection codec encodes both as one byte, so the distinction never reaches
the wire. `Name` is an explicit `astral.String8`. Both pointers are genuinely
nil on this node, so both nil flags are exercised by the zero value above.

**R-13 is settled, and the answer is that `Info` is a full `bundle`.** The
legacy SDK treated a bundle as opaque bytes, which made every object a provider
advertises unreachable from Python. `Info` decodes through the registry like any
other bundle, inner objects included. Settled by round trip rather than by
reading: `objects.echo?strict=true` drops the unparsed-object fallback, so the
node must decode a frame through its own registry and re-encode it from the
decoded value. A `services.update` carrying `Bundle([String8('hello'),
Uint64(7)])` came back byte for byte::

    01 07 67617465776179
    01 03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1
    01                                          Info present
      00000002                                  uint32 count
      0000000e 07 737472696e6738 05 68656c6c6f  bytes32( string8("string8") ++ "hello" )
      0000000f 06 75696e743634 0000000000000007 bytes32( string8("uint64")  ++ 7 )

The type name is `services.update` with **no `mod.` prefix** -- astral-go's
`Update.ObjectType()` returns exactly that (`api/services/update.go:19`), and
the registry name is what travels, so a `mod.` here would make every update
frame undecodable. Design section 5.1 rule 6 lists it among the literal
exceptions.

**`services.discover` answers an empty snapshot on a node with neither NAT nor
gateway enabled.** astrald fans the op out to every loaded module that
implements `services.Discoverer`, and exactly two do:
`mod/nat/src/service_discoverer.go` and `mod/gateway/src/service_discoverer.go`.
Each emits one update only while its own feature is on. Verified live:
`services.discover?follow=false` returns zero objects and the raw body is
`03656f7300000000`, one `eos` frame and EOF. **An empty answer is the normal
answer, not a fault.**

**The `follow` flag changes the meaning of the first `eos`, so it gets its own
method.** `discover()` is ST and stops at the terminator. `discover_follow()` is
ST+follow: the first `eos` is a snapshot/live separator and the channel stays
open until the caller closes it. Conflating them **truncates silently**: an
`async for` and `Stream.collect()` both stop at the first `eos`, so on the
follow form they answer the snapshot alone and drop every live update with no
error. That is why design section 4.2 requires two methods rather than one
boolean that changes the return type.

**`follow` is not parsed as an astral `bool`.** The op's argument struct field
is a plain Go `bool`, and `query.FieldEditor.UnmarshalText` sends that through
`strconv.ParseBool` (`astral-go/lib/query/field_editor.go:143`), never through
`astral.Bool.UnmarshalText`. The two vocabularies differ:
`strconv.ParseBool` takes `1`/`0`/`t`/`f`/`true`/`false`/`TRUE`/`True` and
refuses `yes`; `astral.Bool` takes `yes`/`no`/`y`/`n` and refuses `1`/`0`. A
value neither accepts fails `SetMany` **before** the op body runs, so the query
is **rejected** rather than answered -- verified live:
`services.discover?follow=yes` and `?follow=maybe` both raise `QueryRejected`
with code 1, while `?follow=1` and `?follow=TRUE` are accepted. This module
sends `true`/`false` through the parameter's declared spec, which both parsers
read, so the divergence is unreachable from here.

**`services.sync` mutates and has no astral-go client.** It fetches another
node's service list over `ZoneNetwork` and writes it into the local cache. The
write is destructive first: `syncServices` calls `deleteAllProviderServices`
before the first update arrives and never opens a transaction
(`astrald/mod/services/src/module.go` `syncServices`, lines 41-60 at astrald
`3392926b`), so a sync that dies mid-stream leaves the local registry **empty**
for that provider rather than unchanged. astrald ships `DB.InTx` and documents
it as "the only transaction API"; this path does not use it. The defect is
reported against astrald and carries no number in the design's register.

**`services.sync?follow=true` never answers on its own.** The op sends its `ack`
only after `syncServices` returns, and with `follow` that call runs until its
context is cancelled. astrald cancels it on **any inbound channel object**:
`OpSync` parks a goroutine on `ch.Receive()` and cancels on the first thing it
reads (`op_sync.go:31-34`). So the shape is BD, not RR -- the caller must send
something to end it -- and `sync_follow()` is that method. `sync()` is the RR
form and never sets `follow`.

**`id` is required by this module and optional on the node.** astrald declares
`opSyncArgs.ID string` with no `query` tag, so `Op.invoke`'s required check does
not fire and an absent `id` reaches the op as the empty string, which
`dir.ResolveIdentity` maps to the **zero identity**
(`astrald/mod/dir/src/module.go:56`). A sync of `anyone` wipes the cache for the
zero identity and then routes a query to it. `sync()` therefore refuses an empty
id rather than sending one, the same rule `dir.resolve` applies for the same
reason.

`id` is resolved by the node, not parsed as an identity: the field is a plain Go
`string`, so an alias, `localnode`, a hex key or a directory name all reach it.
This module never spends a query resolving one.

`Services(client)` constructs the module client, and `client.services` is the
property design section 5.1 gives every module: a `functools.cached_property`
in `client.py`, named after the node module and built on first use.
Registration does not wait on it either way: `astral/__init__.py` imports the
whole `api` package eagerly, so whether `services.update` decodes never depends
on which property a caller happened to touch.

Line numbers cite astrald `3392926b` and astral-go `0a15afb`, the reference
heads this module was read against.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Final, Sequence

from .. import querystring
# `StreamContext` is imported at module scope and not under `TYPE_CHECKING`, for
# the reason `base.py` states: this package ships `py.typed`, so every annotation
# in it must resolve at runtime. The arrow runs module clients -> client, which
# is the direction `client.py` already keeps by importing `astral.api.*` inside
# its property bodies.
from ..client import StreamContext
from ..errors import BadArgument
from ..object import Ack, Bundle
from ..record import record, wire
from ..spec import Primitive, Ptr, Spec
from ..stream import Stream
from ..types import Identity
from .base import ModuleClient

__all__ = [
    "OP_DISCOVER",
    "OP_SYNC",
    "SERVICES_TYPES",
    "Services",
    "Update",
]

OP_DISCOVER: Final = "services.discover"
OP_SYNC: Final = "services.sync"

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
#
# `follow` is declared `bool` because that is the type `shell.spec` reports for
# it, and the declaration is what refuses a wrong-typed value here rather than
# letting it reach a node that rejects the whole query. `id` is `string8` and
# not `identity`: the op resolves this argument server-side and a directory name
# is a legitimate value for it.
_DISCOVER: Final[dict[str, Spec]] = {
    "follow": Primitive("bool"),
}
_SYNC: Final[dict[str, Spec]] = {
    "id": Primitive("string8"),
    "follow": Primitive("bool"),
}


# --- the wire type -------------------------------------------------------


@record("services.update")
class Update:
    """One service of one provider, appearing or disappearing.

    An update is a **delta**, not a listing: `available` false names a service
    that is gone and carries no `info`. astrald's own consumer reads it that way
    -- `syncServices` creates a cache row when `Available` is set and deletes one
    otherwise (`astrald/mod/services/src/module.go` `syncServices`, lines 48-55).

    `provider_id` is `None` when the node wrote `0x00`, and `info` likewise. Both
    are nil on every update the two shipped discoverers produce, because neither
    sets them: `mod/nat/src/service_discoverer.go` `newServiceUpdate` and
    `mod/gateway/src/service_discoverer.go` `DiscoverServices` fill `Available`,
    `Name` and `ProviderID` only. The absence is surfaced rather than dropped,
    because a decode this SDK accepts must re-encode to the bytes it came from.

    `info` is a full `bundle`, decoded through the registry: a provider may
    advertise any registered object with the service, and the legacy SDK's
    opaque-bytes model made every one of them unreachable (R-13).

    The name is a **module name**, not an op name: astrald fills it from the
    advertising module's `ModuleName` -- `nat` and `gateway` are the two values
    this node can produce.
    """

    available: bool = wire("Available", Primitive("bool"))
    name: str = wire("Name", Primitive("string8"))
    provider_id: Identity | None = wire("ProviderID", Ptr("identity"))
    info: Bundle | None = wire("Info", Ptr("bundle"))

    @property
    def objects(self) -> Sequence[Any]:
        """Every object in `info`, or an empty sequence when there is none.

        The reason to reach for `info` at all, without the `None` check at each
        call site. An absent bundle and an empty bundle are different bytes and
        `info` keeps them apart; this view does not, because a consumer reading
        the advertisement has the same nothing to read either way.
        """
        return () if self.info is None else tuple(self.info)


# --- the client ----------------------------------------------------------


class Services(ModuleClient):
    """The `services` module's ops, over one `Client`.

    `Services(client)` constructs one. The scaffolding and the `**kw` contract
    are `ModuleClient`'s.
    """

    __slots__ = ()

    # --- discovery: read-only ---

    async def discover(self, **kw: Any) -> list[Update]:
        """Every service the target advertises now. ST, ends at `eos`.

        The snapshot alone: `follow=false` travels explicitly, so the answer
        terminates rather than staying open. An empty list is the ordinary
        answer for a node with neither NAT nor gateway enabled.

        `follow` is never sent true from here. `Stream.collect()` stops at the
        first `eos`, and on a follow stream that `eos` is a boundary, so this
        method against the follow form would answer the snapshot alone and drop
        every live update without saying so. `discover_follow()` is the method
        that crosses the boundary.
        """
        return [
            self._expect(obj, Update, OP_DISCOVER)
            for obj in await self._c.call(_discover_query(follow=False), **kw)
        ]

    def discover_follow(self, **kw: Any) -> StreamContext:
        """`async with s.discover_follow() as stream:` -- ST+follow.

        The snapshot, then a separator `eos`, then live updates until the caller
        closes the stream. `Stream.follow()` yields `(update, live)` pairs across
        the boundary, `snapshot()` stops at it and `live()` starts after it;
        which one is wanted is a per-call question, so the stream is handed over
        rather than a list.

        `Client.follow` supplies the pairing this mode needs -- `persistent=True`
        so the permit comes from the long-lived lane, and `timeout=None` because
        a follow stream is idle for as long as nothing changes. A caller may
        override either.

        **The stream must be closed.** A follow stream holds one of the node's 32
        workers for as long as it is open and astrald never notices a peer that
        vanished; `async with` is the contract.
        """
        return self._c.follow(_discover_query(follow=True), **kw)

    async def updates(self, **kw: Any) -> AsyncIterator[tuple[Update, bool]]:
        """`(update, live)` pairs from a follow stream, closed on exit.

        The iterator form of `discover_follow()`, for a consumer that wants the
        pairs and not the stream. The body is `ModuleClient._follow_pairs`, so
        every module's follow op can grow the same convenience from one
        implementation rather than from a habit copied per module.
        """
        async for pair in self._follow_pairs(
            self.discover_follow(**kw), Update, OP_DISCOVER
        ):
            yield pair

    # --- the write ---

    async def sync(self, id: str | Identity, **kw: Any) -> None:  # noqa: A002
        """Refresh the local cache of one identity's services. RR. **Mutates.**

        One `ack`, or an `error_message` that surfaces as `RemoteError`. The
        query runs over `ZoneNetwork` on the node's side and takes as long as
        reaching that node takes, so `timeout` is worth setting.

        `id` is resolved by the node: an alias, `localnode`, a hex key or a
        directory name all reach it. An empty value is refused here rather than
        sent, because the node's resolver maps it to the zero identity and the
        sync would wipe the cache for `anyone`.

        **The cache is cleared before the new list arrives** and astrald opens no
        transaction around the two, so a sync interrupted mid-stream leaves the
        local registry empty for that provider.
        """
        obj = await self._c.call_one(_sync_query(id, follow=None), **kw)
        self._expect(obj, Ack, OP_SYNC)

    def sync_follow(self, id: str | Identity, **kw: Any) -> StreamContext:  # noqa: A002
        """`async with s.sync_follow(id) as stream:` -- BD. **Mutates.**

        The node keeps syncing that identity's services into the local cache
        until the exchange ends, and answers `ack` only then. The op parks a
        goroutine on the channel and cancels on the **first object it reads**, so
        `Stream.send()` of anything at all ends the sync; `stop()` below is that
        call under a name. Closing the stream ends it too, and then no `ack`
        arrives, because there is nothing left to write it to.

        Opened on the persistent lane with no deadline, for the same reasons
        `discover_follow` is: this exchange does not end on its own.
        """
        kw.setdefault("persistent", True)
        kw.setdefault("timeout", None)
        return self._c.stream(_sync_query(id, follow=True), **kw)

    async def stop_sync(self, stream: Stream, *, timeout: float | None = None) -> bool:
        """End a `sync_follow` exchange and read its `ack`. True when it came.

        Any object cancels the sync; `ack` is the one sent here because it is the
        smallest frame and carries no payload to misread. `False` comes back when
        the op had already ended -- a sync that failed sent its `error_message`
        and closed -- so the distinction survives and the failure is not silent.

        **`bool`, not the `Ack` object.** `Ack` carries no fields and encodes to
        zero bytes, so the value conveys exactly one bit and returning the record
        leaked a wire type into a public signature that neither `astral` nor this
        module exports -- a caller who wanted to annotate the result had to go
        and find `astral.object.Ack` on their own. Every other ack-answering op
        in the SDK returns `None`: `Tree.set`, `Dir.set_alias`, `Objects.delete`,
        `Auth.index`, and `Services.sync` two methods above.

        This method takes `stream` rather than a query, so it routes nothing and
        has no `**kw` to forward; `timeout` bounds the send and the answer.
        """
        await stream.send(Ack(), timeout=timeout)
        obj = await stream.first(timeout=timeout)
        if obj is None:
            return False
        self._expect(obj, Ack, OP_SYNC)
        return True


# --- query construction and argument discipline --------------------------


def _discover_query(*, follow: bool) -> str:
    """`services.discover?follow=…`, with `follow` always explicit.

    Sent even when false, though the op's zero value is false and the two are
    the same query to astrald -- verified live, a bare `services.discover`
    answers the same bare `eos`. The value states the op shape this call
    declares, and design section 4.7 makes that shape a contract the caller
    carries rather than one the wire reveals.
    """
    return querystring.build(OP_DISCOVER, _encode(_DISCOVER, {"follow": follow}))


def _sync_query(id: str | Identity, *, follow: bool | None) -> str:  # noqa: A002
    """`services.sync?id=…`, with `follow` only when it is true.

    Omitted rather than sent false, because `false` is the op's zero value and
    design section 5.1 rule 5 keeps a server default standing by leaving its key
    absent.
    """
    return querystring.build(
        OP_SYNC, _encode(_SYNC, {"id": _name(id), "follow": follow or None})
    )


_encode = ModuleClient._encode
"""Every parameter through its declared spec. `ModuleClient`'s, not a copy."""


def _name(value: str | Identity) -> str:
    """A name argument the node resolves: an alias, `localnode`, or a hex key.

    An empty string is refused: the node's resolver maps it to the zero identity
    (`astrald/mod/dir/src/module.go:56`), so an accidental empty id syncs
    `anyone` -- and `services.sync` mutates, so the accident costs the cached
    services of the zero identity rather than one wasted query.
    """
    if isinstance(value, Identity):
        return value.text()
    if not isinstance(value, str):
        raise BadArgument(
            f"{OP_SYNC}: id must be a directory name or an Identity, got "
            f"{type(value).__name__}"
        )
    if not value:
        raise BadArgument(
            f"{OP_SYNC}: the empty id resolves to the zero identity on the node; "
            "pass Identity.ANYONE to mean that identity"
        )
    return value


SERVICES_TYPES: Final[Sequence[type]] = (Update,)
"""Every wire type this module declares, for a private-registry sweep."""

Services.TYPES = SERVICES_TYPES
