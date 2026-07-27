"""`Context`: the routing half of astral-go's `astral.Context`, frozen.

astral-go's `Context` is two things wearing one name: a routing value object
(`identity`, `zone`, `filters`) and a cancellation carrier (an embedded
`context.Context`, plus `WithCancel`, `WithCancelCause` and `WithTimeout`).
asyncio owns cancellation natively -- every `await` is a cancellation point and
`asyncio.timeout()` sets deadlines -- so the two halves separate here and only
the value object survives. **A `Context` cannot cancel anything**, no method on
it returns a cancel function, and nothing in this SDK inspects one to decide
whether to stop. That is the whole reason `sig.Send/Recv/Context/On/OnCtx`
disappear rather than being ported (design section 3.5).

Frozen, slotted and hashable, so one instance is shared by concurrent tasks
without a lock, and `filters` is coerced to a tuple at construction because a
list would make the value unhashable and mutable behind a caller's back.

The zone verbs mirror astral-go's bitmask helpers one for one:

| astral-go | here | operation |
|---|---|---|
| `WithZone` | `with_zone` | assignment |
| `IncludeZone` | `include_zone` | `\\|` |
| `ExcludeZone` | `exclude_zone` | Go's `&^` |
| `LimitZone` | `limit_zone` | `&` |

`DEFAULT` carries every zone, matching astral-go's `NewContext`, which sets
`ZoneDefault`. An **anonymous** apphost session cannot reach the network however
it asks: astrald runs `ctx.ExcludeZone(ZoneNetwork)` for a token-less guest
regardless of the `Zone` byte the guest sent, so a client that wants to know the
zone the node will actually route in calls `anonymous()` and gets the narrowed
copy. `Session.route_query` sends what the caller asked for, byte for byte with
astral-go; the narrowing is the node's and is reproduced here for reporting, not
imposed on the wire.

Zone travels per hop in `route_query_msg`. The `query` wire type has no `Zone`
field at all (astral-docs bug D-25), so a `Context` is never encoded: it is a
client-side carrier of per-hop routing parameters and nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, Iterable

from .types import Identity, Zone

__all__ = ["Context"]


@dataclass(frozen=True, slots=True)
class Context:
    """The identity, zone and filters one hop of routing is performed under."""

    identity: Identity | None = None
    zone: Zone = Zone.ALL
    filters: tuple[str, ...] = ()

    DEFAULT: ClassVar["Context"]

    def __post_init__(self) -> None:
        # A caller passing a list gets a hashable value back rather than a
        # dataclass that raises on hash three frames later.
        if not isinstance(self.filters, tuple):
            object.__setattr__(self, "filters", tuple(self.filters))
        if not isinstance(self.zone, Zone):
            object.__setattr__(self, "zone", Zone(int(self.zone)))

    def __repr__(self) -> str:
        who = "anonymous" if self.identity is None else self.identity.fingerprint()
        return f"Context({who}, zone={str(self.zone)!r}, filters={list(self.filters)})"

    # --- copies ---

    def with_identity(self, identity: Identity | None) -> "Context":
        """A copy acting as `identity`. `None` is anonymous."""
        return replace(self, identity=identity)

    def with_zone(self, zone: Zone | int) -> "Context":
        """A copy whose zone is exactly `zone`."""
        return replace(self, zone=Zone(int(zone)))

    def include_zone(self, zone: Zone | int) -> "Context":
        """A copy with `zone` added."""
        return replace(self, zone=Zone(int(self.zone) | int(zone)))

    def exclude_zone(self, zone: Zone | int) -> "Context":
        """A copy with `zone` removed. Go's `&^`."""
        return replace(self, zone=Zone(int(self.zone) & ~int(zone)))

    def limit_zone(self, zone: Zone | int) -> "Context":
        """A copy narrowed to `zone`. Go's `&`."""
        return replace(self, zone=Zone(int(self.zone) & int(zone)))

    def with_filters(self, *filters: str) -> "Context":
        """A copy whose filters are exactly `filters`.

        Replacement, not accumulation, matching astral-go's `WithFilters`, and a
        bare call clears them.
        """
        return replace(self, filters=tuple(filters))

    def add_filters(self, filters: Iterable[str]) -> "Context":
        """A copy with `filters` appended, skipping ones already present."""
        merged = list(self.filters)
        merged += [name for name in filters if name not in merged]
        return replace(self, filters=tuple(merged))

    def anonymous(self) -> "Context":
        """The copy an anonymous session actually routes under.

        The identity is dropped and the network zone with it: astrald strips
        `ZoneNetwork` for every token-less guest, whatever the guest sent.
        """
        return replace(self, identity=None, zone=Zone(int(self.zone) & ~int(Zone.NETWORK)))


Context.DEFAULT = Context()
