"""`dir`: the node's directory of aliases, identities and identity filters.

Tier 1, six ops, and the module that proves the map kind end to end.
`mod.dir.alias_map` is `map[string]*astral.Identity` on the Go side, so its
payload is the map layout of design section 2.3 and nothing else: a `uint32`
count, then `string16` key and value pairs sorted by encoded key bytes, each
value a `0x01` presence byte and a flat 33-byte identity. The legacy SDK had no
map kind, so this one type came back as untyped bytes and every alias in it was
unreachable. Verified live this session, one alias in the table::

    00000001                                    uint32 count = 1
    000a 66757272792d626f6c74                   string16 key "furry-bolt"
    01                                          presence byte on the map VALUE
    03b2704948bb…ae1                            33 flat identity bytes

Those bytes are pinned as a regression vector in `tests/test_api_dir.py`. Two
rules in them are easy to get wrong and are checked by that vector: the presence
byte sits on the value and never on the key, and the identity is 33 flat bytes
with no flag of its own -- the `0x01` in front of it belongs to the map slot.

**Op surface, and the shape each one declares** (design section 4.7; a shape is
a per-op contract and is not discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `dir.alias_map` | RR | `mod.dir.alias_map` | read-only |
| `dir.apply_filters` | RR | `bool` \\| `error_message` | read-only |
| `dir.filters` | ST | `string8` × n ++ `eos` | read-only |
| `dir.get_alias` | RR | `string8` \\| `error_message` | read-only |
| `dir.resolve` | RR | `identity` \\| `error_message` | read-only |
| `dir.set_alias` | RR | `ack` \\| `error_message` | **mutates** |

`dir.alias_map`, `dir.apply_filters`, `dir.get_alias` and `dir.resolve` end at a
bare EOF with no `eos`; `dir.filters` ends at an `eos`. Both shapes verified
live against `furry-bolt` this session. `set_alias` is the one op here that
writes, and it is the only one no live test calls.

**`apply_filters` is read-only here.** astral-go's client sends it to
`dir.set_alias` (`api/dir/client/apply_filters.go:20`), so a read helper names
the write op: with `id` and `filters` present and `alias` absent the required
check fails (`astral-go/lib/routing/op.go:137`) and the query is rejected, and a
caller that also carried an `alias` renames an identity while asking a question.
Design bug G-8, not inherited. `OP_APPLY_FILTERS` is the only op name
`apply_filters` sends, and a test asserts on the op the node received.

**`apply_filters` is OR, not AND.** astrald returns true when the identity
passes **any** named filter (`mod/dir/src/module.go:131`), and skips a filter
name it does not know. astral-go's client documents "returns true if the
identity matches all of them" (`api/dir/client/apply_filters.go:15`), which is
the opposite. astrald is the authority and OR is what this module documents. An
unknown filter name contributes nothing, so a misspelled name is a silent
`False` -- verified live: `dir.apply_filters?filters=nope` answers `bool(false)`
and `dir.apply_filters?filters=` answers `bool(false)`.

**`set_alias` needs both arguments, `alias` included when it is empty.**
astrald declares `Alias *string` with `query:"required"` and the comment
"required but can be empty" (`mod/dir/src/op_set_alias.go` `opSetAliasArgs.Alias`,
line 11 at astrald `154ba3ae`); the required
check tests key **presence** in the parsed parameters
(`astral-go/lib/routing/op.go:137`). Removal is therefore `alias=` with an empty
value, which is a different query string from an absent `alias`. Design bug
D-18. `remove_alias()` is the named form of it.

**Three arguments named `id`, two different types.** `dir.get_alias` and
`dir.set_alias` declare `ID *astral.Identity`, parsed by
`astral.ParseIdentity`, so only 66 hex characters or `anyone` reach the op and a
directory name never does. `dir.apply_filters` declares `ID string` and resolves
it through the node's own resolver, so an alias, `localnode`, a hex key or the
empty string all reach it. This module keeps the distinction rather than
flattening it: `get_alias` and `set_alias` take an identity, `apply_filters`
takes a name **or** an identity and never spends a query resolving one. Verified
live: `dir.apply_filters?filters=all&id=furry-bolt` answers `bool(true)`, and
`dir.get_alias?id=` with 66 hex characters that are not a curve point is
**rejected** rather than answered, because astral-go validates the point.

**An empty name is refused client-side.** `dir.resolve?name=` answers with the
**zero identity** rather than an error -- verified live -- because astrald maps
`""` and `"anyone"` to `astral.Identity{}` (`mod/dir/src/module.go:56`). A
caller that meant a name and sent an empty one gets `anyone`, which routes
somewhere else entirely, so `resolve("")` raises instead. `Identity.ANYONE` is
the way to name that identity on purpose.

**No cache.** astral-go's client memoizes `resolve` and `get_alias` behind
`EnableCache`. An alias is mutable node state -- `set_alias` from any app
changes it -- so a cached answer is a stale answer with no invalidation path,
and the SDK never offers one.

Reached as `client.dir`, a `functools.cached_property` on `Client` built on first
use (design section 5.1). This module holds no reference to `Client` at import
time -- the annotation is a string -- so `client.py` imports it inside the
property body without a cycle, and `astral/__init__.py` imports the whole `api`
package eagerly so registration never depends on the property being touched.

**Source citations name the symbol as well as the line.** astrald is a moving
target and three anchors in this file had already drifted by a line or two, which
costs a reader more than an absent citation: it makes them distrust the exact
ones. Line numbers below are pinned to astrald `154ba3ae`.
"""

from __future__ import annotations

from typing import (
    Any,
    Final,
    ItemsView,
    Iterator,
    KeysView,
    Sequence,
    ValuesView,
)

from .. import querystring
from ..errors import BadArgument, ParseError
from ..object import Ack
from ..primitives import Bool, String8
# Imported under a private name: `alias` is also this module's argument name for
# the string an identity is known by, and one term must mean one thing.
from ..record import alias as _alias_type
from ..record import record, wire
from ..spec import Map, Primitive, Spec
from ..types import Identity
from .base import ModuleClient

__all__ = [
    "Alias",
    "AliasMap",
    "DIR_TYPES",
    "Dir",
    "OP_ALIAS_MAP",
    "OP_APPLY_FILTERS",
    "OP_FILTERS",
    "OP_GET_ALIAS",
    "OP_RESOLVE",
    "OP_SET_ALIAS",
]

OP_ALIAS_MAP: Final = "dir.alias_map"
OP_APPLY_FILTERS: Final = "dir.apply_filters"
OP_FILTERS: Final = "dir.filters"
OP_GET_ALIAS: Final = "dir.get_alias"
OP_RESOLVE: Final = "dir.resolve"
OP_SET_ALIAS: Final = "dir.set_alias"

# astrald joins and splits filter names on this byte, so a name containing one
# is two names on the server (`mod/dir/src/op_apply_filters.go` `OpApplyFilters`,
# line 25 at astrald `154ba3ae`).
FILTER_SEPARATOR: Final = ","

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
_IDENTITY: Final[Spec] = Primitive("identity")
_STRING8: Final[Spec] = Primitive("string8")


# --- wire types ----------------------------------------------------------


Alias = _alias_type("mod.dir.alias", "string8")
"""A human-readable node name. `string8` on the wire, under its own type name.

Registered for decode completeness: no `dir` op sends it. `dir.get_alias` and
`dir.filters` both send a plain `string8`, verified live.
"""

# `alias()` derives a class name from the type name, so the default repr reads
# `ModDirAlias('furry-bolt')`. The public name is what a caller sees.
Alias.__name__ = "Alias"
Alias.__qualname__ = "Alias"


@record("mod.dir.alias_map")
class AliasMap:
    """Every alias the directory holds, mapped to its identity.

    A read-only view of node state at one instant; the node builds it in one
    shot per query. Both columns are unique in astrald's schema -- `Identity` is
    the primary key and `Alias` carries a unique index
    (`mod/dir/src/db.go` `dbAlias`, lines 9-10) -- so the mapping is a bijection and `alias_of` has
    at most one answer.

    A value is `None` when the node wrote `0x00` in the value slot. The Go type
    is `map[string]*astral.Identity`, so a nil pointer is expressible; the one
    entry `furry-bolt` holds carries `0x01`, verified this session. The absence
    is surfaced rather than dropped, because a decode this SDK accepts must
    re-encode to the bytes it came from.
    """

    aliases: dict[str, Identity | None] = wire(
        "Aliases", Map("string16", "identity")
    )

    # The mapping surface, so the record reads as the map it is. Keys are
    # aliases and values are identities, never the reverse: the reverse lookup
    # is `alias_of`.

    def __len__(self) -> int:
        return len(self.aliases)

    def __iter__(self) -> Iterator[str]:
        return iter(self.aliases)

    def __contains__(self, name: object) -> bool:
        return name in self.aliases

    def __getitem__(self, name: str) -> Identity | None:
        return self.aliases[name]

    def get(self, name: str, default: Any = None) -> Any:
        return self.aliases.get(name, default)

    def keys(self) -> KeysView[str]:
        return self.aliases.keys()

    def values(self) -> ValuesView[Identity | None]:
        return self.aliases.values()

    def items(self) -> ItemsView[str, Identity | None]:
        return self.aliases.items()

    def alias_of(self, identity: Identity) -> str | None:
        """The alias of an identity, or `None`.

        The reverse of the map, and the reason to fetch the whole of it: one
        query answers the name of every identity in the directory, where
        `get_alias` answers for one.
        """
        for name, value in self.aliases.items():
            if value == identity:
                return name
        return None


# --- the client ----------------------------------------------------------


class Dir(ModuleClient):
    """The `dir` module's ops, over one `Client`.

    Reached as `client.dir`, a cached property built on first use; `Dir(client)`
    constructs the same object directly. The scaffolding and the `**kw` contract
    are `ModuleClient`'s.
    """

    __slots__ = ()

    # --- reads ---

    async def alias_map(self, **kw: Any) -> AliasMap:
        """Every alias in the directory, with its identity. RR, no `eos`.

        One query for the whole table. `AliasMap.alias_of` then answers the
        reverse question without a second one.
        """
        return self._expect(
            await self._c.call_one(OP_ALIAS_MAP, **kw), AliasMap, OP_ALIAS_MAP
        )

    async def resolve(self, name: str, **kw: Any) -> Identity:
        """The identity a directory name stands for. RR, no `eos`.

        The node's resolver, not a local parse: an alias, `localnode`, or a hex
        key all resolve. A name the node does not know answers with an
        `error_message`, which surfaces as `RemoteError`.

        An empty name is refused here rather than sent, because the node answers
        it with the zero identity.
        """
        if not name:
            raise BadArgument(
                f"{OP_RESOLVE}: the empty name resolves to the zero identity on "
                "the node; pass Identity.ANYONE to mean that identity"
            )
        obj = await self._c.call_one(
            querystring.build(OP_RESOLVE, {"name": _param(_STRING8, name)}), **kw
        )
        return self._expect(obj, Identity, OP_RESOLVE)

    async def resolve_identity(self, name: Identity | str, **kw: Any) -> Identity:
        """An identity from 66 hex characters, `anyone`, or a directory name.

        Hex parses locally and costs no query; anything else goes to
        `dir.resolve`. This is astral-go's `ResolveIdentity` and the rule the
        `target:operation` CLI prefix follows.

        Takes the same keywords `resolve()` one method above takes, and honours
        them: `Client.resolve_identity` accepts the whole query keyword set, so
        `d.resolve_identity(name, zone=Zone.DEVICE)` works rather than raising a
        `TypeError` naming a method the caller never called.
        """
        return await self._c.resolve_identity(name, **kw)

    async def get_alias(self, identity: Identity | str, **kw: Any) -> str:
        """The alias of one identity. RR, no `eos`.

        An identity with no alias answers with an `error_message` carrying
        astrald's `record not found`, which surfaces as `RemoteError`; there is
        no empty-string answer to distinguish. Verified live.

        `identity` is an `Identity`, 66 hex characters, or `anyone`. A directory
        name is refused: the op parses this argument as an identity and never
        resolves it.
        """
        obj = await self._c.call_one(
            querystring.build(
                OP_GET_ALIAS, {"id": _param(_IDENTITY, _identity(identity, OP_GET_ALIAS))}
            ),
            **kw,
        )
        return str(self._expect(obj, String8, OP_GET_ALIAS))

    async def filters(self, **kw: Any) -> list[str]:
        """Every identity filter the node has registered. ST, ends at `eos`.

        The names `apply_filters` accepts. Live on `furry-bolt`: `localnode`,
        `linked`, `localswarm`, `localuser`, `all`.
        """
        return [
            str(self._expect(obj, String8, OP_FILTERS))
            for obj in await self._c.call(OP_FILTERS, **kw)
        ]

    async def apply_filters(
        self,
        names: str | Sequence[str],
        *,
        identity: Identity | str | None = None,
        **kw: Any,
    ) -> bool:
        """Whether an identity passes **any** of the named filters. RR, no `eos`.

        OR, not AND, and an unknown filter name contributes nothing, so a
        misspelled name is a silent `False`. Names are refused here when they
        cannot survive the round trip: the node splits the argument on `,`, so a
        name containing one is two names, and an empty sequence is an empty
        argument, which the node reads as one unknown filter and answers
        `False`.

        **`names`, not `filters`.** The op's wire argument is `filters=` and it
        travels as one, but `filters` is also a routing keyword every method
        forwards to `Client.query`, where it is `route_query_msg.Filters` -- the
        identity filters applied to the *hop*, not the names this op evaluates.
        Taking the op's argument under that name made the routing lever
        unreachable on this op and did it silently.

        `identity` defaults to the query's caller, which is the node itself for
        an anonymous client. Unlike `get_alias`, it accepts a directory name,
        `localnode`, or a hex key: the op resolves this argument server-side.
        A name the node does not know answers with an `error_message`.

        Read-only. astral-go's client sends this op's arguments to
        `dir.set_alias` (bug G-8); this one never names another op.
        """
        params: dict[str, Any] = {
            "filters": _param(_STRING8, _filter_list(names)),
        }
        if identity is not None:
            params["id"] = _param(_STRING8, _name(identity, OP_APPLY_FILTERS))
        obj = await self._c.call_one(
            querystring.build(OP_APPLY_FILTERS, params), **kw
        )
        return bool(self._expect(obj, Bool, OP_APPLY_FILTERS))

    # --- the one write ---

    async def set_alias(self, identity: Identity | str, alias: str, **kw: Any) -> None:
        """Name an identity in the directory. RR, no `eos`. **Mutates.**

        An empty `alias` removes the entry, and `remove_alias` is the named form
        of that. The `alias` parameter is always sent, empty or not: the op
        requires the key to be present and reads removal from an empty value.

        `identity` is an `Identity`, 66 hex characters, or `anyone`. A directory
        name is refused; resolve it first.
        """
        obj = await self._c.call_one(
            querystring.build(
                OP_SET_ALIAS,
                {
                    "id": _param(_IDENTITY, _identity(identity, OP_SET_ALIAS)),
                    # Never omitted. An absent key is a rejected query, an empty
                    # value is a removal, and the two are different bytes.
                    "alias": _param(_STRING8, alias),
                },
            ),
            **kw,
        )
        self._expect(obj, Ack, OP_SET_ALIAS)

    async def remove_alias(self, identity: Identity | str, **kw: Any) -> None:
        """Drop an identity's entry from the directory. **Mutates.**

        `set_alias` with an explicitly empty alias, which is the only removal
        the op offers.
        """
        await self.set_alias(identity, "", **kw)


# --- argument and answer discipline --------------------------------------


_param = ModuleClient._param
"""One parameter value, in its text form. `ModuleClient`'s, not a copy."""


def _identity(value: Identity | str, op: str) -> Identity:
    """An identity argument. 66 hex characters or `anyone`, never a name.

    The op parses this argument with `astral.ParseIdentity`, so a name reaches
    it as a rejected query rather than as an error message. Refusing it here
    names the fix instead.
    """
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

    An empty string is refused: the node's resolver maps it to the zero
    identity, so an accidental empty name asks about `anyone`.
    """
    if isinstance(value, Identity):
        return value.text()
    if not value:
        raise BadArgument(
            f"{op}: the empty name resolves to the zero identity on the node; "
            "pass Identity.ANYONE to mean that identity"
        )
    return value


def _filter_list(filters: str | Sequence[str]) -> str:
    """Filter names, joined for the wire.

    A single name is accepted unwrapped, because one filter is the common call.
    """
    names = [filters] if isinstance(filters, str) else list(filters)
    if not names:
        raise BadArgument(
            f"{OP_APPLY_FILTERS}: no filter names; the node reads an empty "
            "argument as one unknown filter and answers false"
        )
    for name in names:
        if not name:
            raise BadArgument(f"{OP_APPLY_FILTERS}: empty filter name")
        if FILTER_SEPARATOR in name:
            raise BadArgument(
                f"{OP_APPLY_FILTERS}: filter name {name!r} contains "
                f"{FILTER_SEPARATOR!r}, which the node reads as two names"
            )
    return FILTER_SEPARATOR.join(names)


DIR_TYPES: Final[Sequence[type]] = (Alias, AliasMap)
"""Every wire type this module declares, for a private-registry sweep."""

Dir.TYPES = DIR_TYPES
