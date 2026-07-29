"""`tree`: the node's configuration tree, addressed by path and holding objects.

Tier 1, six ops, and the one module whose values have no declared type. A tree
node holds any registered object and may hold named subnodes at the same time;
astrald's modules keep their settings here, so `/mod/tcp/settings/listen` is a
`bool` and `/mod/user/config/active_contract` is a `mod.auth.signed_contract`.
A path begins with a slash and its segments carry any non-slash printable
characters (`astral-go/api/tree/module.go:7`).

**Op surface, and the shape each one declares** (design section 4.7; a shape is
a per-op contract and is not discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `tree.get` | ST | the stored object ++ `eos` | read-only |
| `tree.get` with `follow` | ST, unbounded | one object per change | read-only |
| `tree.list` | ST | `string8` x n ++ `eos`, sorted | read-only |
| `tree.set` with `value` | RR | `ack` \\| `error_message` | **mutates** |
| `tree.set` without `value` | WA | one `ack` per object on the body | **mutates** |
| `tree.delete` | RR | `ack` \\| `error_message` | **mutates** |
| `tree.mount_remote` | RR | `ack` \\| `error_message` | **mutates** |
| `tree.unmount` | RR | `ack` \\| `error_message` | **mutates** |

Five of the six ops mutate. `tree.get` and `tree.list` are verified live against
`furry-bolt`; every mutating op is exercised against the mock alone.

**`tree.get` with `follow` has no snapshot/live separator, and design section
4.7 says it has one.** The op sends the current value, then one object per
change, and one `eos` at the very end when the value channel closes: the `eos`
follows the loop over the values rather than its first element
(`astral-go/api/tree/client/server.go:57` and
`astral-go/api/tree/client/server.go:61`). The single `eos` is therefore the
**terminator**, not a boundary. Verified live: `tree.get?follow=true` on
`/mod/tcp/settings/listen` answers `bool(true)` and then nothing at all -- a
second read expired on its own deadline rather than returning `None` at a
separator. `Stream.follow()`, `snapshot()` and `live()` are consequently the
wrong readers for this op and would block until the deadline; `async for` is the
right one, and `get_follow()` below hands out a stream that refuses the
other three rather than blocking on them. Design
objection D-T1, filed: section 4.7's ST+follow row and the
`tree.get?follow=true` example in `stream.py`'s module docstring both name a
separator this op never sends.

The row is right about its other two members and wrong only about this one:
`services.discover` sends a separator `eos` on a nil sentinel and a second one
at the end (`astrald/mod/services/src/op_discover.go:33`, documented as such at
`astrald/mod/services/src/op_discover.go:17`). ST+follow is therefore a real
mode with a real member, and `tree.get` is not in it.

**A node with no value answers `nil`, not `mod.tree.err_no_value`.** astrald
substitutes `&astral.Nil{}` when the row carries no type
(`astrald/mod/tree/src/node.go:37`), and `mod.tree.err_no_value` is declared and
registered by astral-go (`astral-go/api/tree/err_no_value.go:15`) yet
constructed nowhere in either tree. Verified live: 20 of the 27 paths on
`furry-bolt` answer `Nil()`. `get()` returns that object rather than `None`,
because `nil` is a registered type and collapsing its tag loses the distinction
the wire keeps (design section 11.4); `Nil()` is truthy, so `if await t.get(p)`
is a wrong question and `isinstance(value, Nil)` is the right one. The type is
registered here anyway, for decode completeness. Docs bug D-T2: the
`mod.tree.err_no_value` page states "A read such as `tree.get` surfaces this
object in place of a stored value", which no code path does.

**A value may be of a type this SDK has never heard of**, because any module can
store any object. `get()` and `get_follow()` therefore default
`allow_unparsed=True`, so an unknown type arrives as an `UnparsedObject`
carrying its name and payload rather than raising `BlueprintNotFound`. Verified
live: `/mod/nearby/mode` holds a `mod.nearby.mode`, which no SDK type declares,
and the default query keyword fails that read outright. A caller that wants the
failure passes `allow_unparsed=False`.

**`tree.set` switches mode on `value` being empty, so an empty value cannot be
stored through the text form.** astrald routes to the single-value branch only
when the value is non-empty (`astral-go/api/tree/client/server.go:78`), so
`tree.set?path=/x&type=string8&value=` enters batch mode and waits for an object
on the channel body. `set_text()` refuses an empty `value` and names `set()`,
which is the form that stores one. The rest of the trap is inherited from the
same branch: with `type` given the node is created if missing
(`astral-go/api/tree/client/server.go:87`), and with `type` inferred it is not,
because inference reads the node's current value and fails when there is none
(`astral-go/api/tree/client/server.go:101`).

**D-17: the documented parameter names for two ops do not exist.** astral-docs
writes `tree.delete -Recursive` and `tree.set -Type -Value`; parameter matching
is case-sensitive and an unknown key is silently dropped, so every one of those
shellsession examples is a no-op that reports success. The real names are
`recursive`, `type` and `value`, which is what this module sends. Verified live:
`tree.get?path=/mod/tcp/settings/listen&recursive=true` is accepted and answers
exactly what the same query without the key answers.

**G-11: astral-go's `tree.Node.Create` issues `tree.set` and never reads the
response** (`astral-go/api/tree/client/node.go:151` opens the query,
`astral-go/api/tree/client/node.go:160` returns without a read). The consequence
is worse than the unread `ack` the survey records: batch mode answers one object
per object received, so a `Create` that sent none leaves **nothing** on the wire
when it succeeds and an `error_message` when the path walk failed -- the one
case a caller needs. `create()` sends the `eos` and reads to the end of the
stream, so a failed creation raises `RemoteError` instead of returning a handle
for a node that does not exist.

**`client.tree` is the surface design section 5.1 specifies**, a cached property
in `client.py`; `Tree(client)` constructs the same object and is what the tests
use. A test pins this sentence to what `Client` actually carries, so the two
cannot drift apart again.

Source citations name a single line each, and every one of them is read back by
`tests/test_api_tree.py`. astrald and astral-go are moving targets, and a
citation that has drifted by two lines costs a reader more than an absent one:
it makes them distrust the exact ones. Line numbers are pinned to astral-go
`5c18d9c` and astrald `074a852b`.
"""

from __future__ import annotations

from typing import Any, ClassVar, Final, Sequence

from .. import querystring
from ..client import StreamContext
from ..errors import BadArgument, BadArgumentType, ProtocolError
from ..object import Ack, EmptyObject
from ..primitives import String8
from ..registry import default_blueprints
from ..spec import Primitive, Spec
from ..types import Identity
from .base import ModuleClient

__all__ = [
    "ErrNoValue",
    "OP_DELETE",
    "OP_GET",
    "OP_LIST",
    "OP_MOUNT_REMOTE",
    "OP_SET",
    "OP_UNMOUNT",
    "ROOT",
    "TREE_TYPES",
    "Tree",
]

OP_DELETE: Final = "tree.delete"
OP_GET: Final = "tree.get"
OP_LIST: Final = "tree.list"
OP_MOUNT_REMOTE: Final = "tree.mount_remote"
OP_SET: Final = "tree.set"
OP_UNMOUNT: Final = "tree.unmount"

ROOT: Final = "/"
"""The root path, and `tree.list`'s default.

The node reads an absent `path` as the root
(`astral-go/api/tree/client/server.go:202`), and the path walk strips one
leading slash and skips empty segments
(`astral-go/api/tree/node.go:33`, `astral-go/api/tree/node.go:41`). An empty
path and `/` therefore address the root alike. Verified live: a missing leading
slash (`mod/tcp/settings/listen`), a trailing slash and a doubled inner slash
(`/mod//tcp`) all address what the plain path addresses. This module sends `/`
rather than omitting the key, so the query string states what it read.
"""

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
_BOOL: Final[Spec] = Primitive("bool")
_STRING8: Final[Spec] = Primitive("string8")


# --- wire types ----------------------------------------------------------


class ErrNoValue(EmptyObject):
    """The error a node with no value is documented to answer, and never does.

    Declared and registered by astral-go
    (`astral-go/api/tree/err_no_value.go:15`), constructed nowhere in astral-go
    or astrald, and never observed live. astrald answers `nil` for a value-less
    node instead (`astrald/mod/tree/src/node.go:37`).

    Registered here for decode completeness: a node that does send it must
    decode, and an empty payload under a name the registry lacks would otherwise
    raise. `EmptyObject` rather than a zero-field record, because astral-go
    embeds `astral.EmptyObject` and that is what renders `{"Type":
    "mod.tree.err_no_value", "Object": null}`; a zero-field record renders
    `"Object": {}` and has no text form at all.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "mod.tree.err_no_value"


default_blueprints().add(ErrNoValue)


# --- the client ----------------------------------------------------------


class Tree(ModuleClient):
    """The `tree` module's ops, over one `Client`.

    `Tree(client)` constructs one; `client.tree` is the property design section
    5.1 specifies and `client.py` declares. The scaffolding and the `**kw`
    contract are `ModuleClient`'s.

    `get` and `list` are the only ops here that do not mutate, and the only ones
    any live test calls.
    """

    __slots__ = ()

    # --- reads ---

    async def get(self, path: str, **kw: Any) -> Any:
        """The object stored at a path. ST, one object then `eos`.

        A node with no value answers `nil`, which decodes to `Nil()` and is
        truthy. A missing path, a missing parent and the root all answer an
        `error_message`, which surfaces as `RemoteError`; the root holds no
        value by construction (`astrald/mod/tree/src/node.go:29`).

        `allow_unparsed` defaults to `True` here, because the value's type is
        the storing module's and not this op's: an unknown one arrives as an
        `UnparsedObject` rather than failing the read. Pass
        `allow_unparsed=False` to have the unknown type raise.
        """
        kw.setdefault("allow_unparsed", True)
        return await self._c.call_one(
            querystring.build(OP_GET, {"path": _param(_STRING8, _path(path, OP_GET))}),
            **kw,
        )

    def get_follow(self, path: str, **kw: Any) -> StreamContext:
        """`async with t.get_follow(p) as s:` -- every value the path takes.

        The current value arrives first, then one object per change, until the
        caller closes the stream or the node ends it. Read it with `async for`::

            async with tree.get_follow("/mod/tcp/settings/listen") as s:
                async for value in s:
                    ...

        **Never `s.follow()`, `s.snapshot()` or `s.live()`,** and the stream
        refuses all three rather than demonstrating why. They read the first
        `eos` as a snapshot/live separator; this op sends no separator, so its
        single `eos` is the terminator and arrives only when the stream ends, and
        all three would block until the deadline while holding one of the node's
        32 workers. Verified live: `tree.get?path=/mod/indexing&follow=true`
        answered one `nil` frame and no `eos`, with the stream still open four
        seconds later. `async for` stops at exactly that `eos`, which is the op's
        own contract, and `separator=False` is how this method says so in a form
        the stream can enforce.

        **Named `get_follow`, not `follow`.** The method named after
        `Stream.follow()` was the one method you must not call `Stream.follow()`
        on, which is the worst available name. Every follow form in the SDK is
        `<op>_follow` now: `scan_follow`, `discover_follow`, `sync_follow`,
        `get_follow`.

        `persistent=True` and `timeout=None` are defaults rather than constants:
        a stream that never ends must not be billed against the query permits
        and must not carry a deadline, and a caller that wants either may still
        set it. `Client.follow()` is deliberately not used, because its contract
        is the separator this op does not have.
        """
        kw.setdefault("persistent", True)
        kw.setdefault("timeout", None)
        kw.setdefault("allow_unparsed", True)
        kw.setdefault("separator", False)
        return self._c.stream(
            querystring.build(
                OP_GET,
                {
                    "follow": _param(_BOOL, True),
                    "path": _param(_STRING8, _path(path, OP_GET)),
                },
            ),
            **kw,
        )

    async def list(self, path: str = ROOT, **kw: Any) -> list[str]:
        """The names of a path's immediate subnodes. ST, ends at `eos`.

        Sorted by the node, so a caller redrawing a list does not reshuffle it
        (`astral-go/api/tree/client/server.go:222`). A node with no subnodes
        answers a bare `eos`; a missing path answers an `error_message`. Names
        are path segments, not paths: join one onto `path` to address a child.
        """
        return [
            str(self._expect(obj, String8, OP_LIST))
            for obj in await self._c.call(
                querystring.build(
                    OP_LIST, {"path": _param(_STRING8, _path(path, OP_LIST))}
                ),
                **kw,
            )
        ]

    # --- writes ---

    async def set(self, path: str, value: Any, **kw: Any) -> None:
        """Store one object at a path. WA, one `ack`. **Mutates.**

        The object travels on the channel body, which is what `tree.set` with no
        `value` argument reads, and the node creates the path if it is missing
        (`astral-go/api/tree/client/server.go:127`). This is the form that
        stores an object of any type, including one with no text encoding and
        including an empty `string8`; `set_text` is the query-string form and
        can do neither.
        """
        await self.set_many(path, [value], **kw)

    async def set_many(self, path: str, values: Sequence[Any], **kw: Any) -> None:
        """Store objects at a path in order, one `ack` each. WA. **Mutates.**

        Every object lands at the same path, so the last one is what the node
        holds afterwards; the batch exists because the op reads a stream, not
        because the writes address different nodes.

        The node answers one object per object received and keeps reading, so a
        failed write is an `error_message` among the answers and surfaces as
        `RemoteError` from that point; the answers before it are not returned,
        and nothing is returned on success either. An answer count that does not
        match the input count is the op having stopped early, and raises
        `ProtocolError`. The final `eos` a mirroring node answers to the sent
        terminator is deliberately left unread; the stream closes over it.
        """
        objects = list(values)
        if not objects:
            raise BadArgument(
                f"{OP_SET}: no objects; `create` is the form that makes a node "
                "with no value"
            )
        qs = querystring.build(OP_SET, {"path": _param(_STRING8, _path(path, OP_SET))})
        answers = await self._c.call_with(
            qs, *objects, eos=True, expect=len(objects), **kw
        )
        if len(answers) != len(objects):
            raise ProtocolError(
                f"{OP_SET}: sent {len(objects)} object(s) and got "
                f"{len(answers)} answer(s)"
            )
        for obj in answers:
            self._expect(obj, Ack, OP_SET)

    async def set_text(
        self,
        path: str,
        value: str,
        *,
        type: str | None = None,  # noqa: A002 -- the node's own argument name
        **kw: Any,
    ) -> None:
        """Store a text-encoded value at a path. RR, one `ack`. **Mutates.**

        `value` is the bare payload half of the type's text encoding, the same
        form every query argument takes. `type` is the wire type name to parse
        it as; a type with no text decoder answers an `error_message` naming
        itself.

        **`type` given creates the path; `type` omitted does not.** Omitting it
        makes the node infer the type from the node's *current* value
        (`astral-go/api/tree/client/server.go:87`), so a path that does not
        exist, or exists with no value, answers `cannot infer type`
        (`astral-go/api/tree/client/server.go:101`).

        An empty `value` is refused rather than sent: the node reads it as the
        batch-mode switch and waits for an object on the channel body instead of
        storing anything. `set()` is the form that stores an empty value.
        """
        if not value:
            raise BadArgument(
                f"{OP_SET}: an empty value switches the op to batch mode and "
                "stores nothing; `set` sends the object on the body"
            )
        if type is not None and not type:
            raise BadArgument(
                f"{OP_SET}: an empty type is not a type; omit the argument to "
                "have the node infer one from the current value"
            )
        params = {
            "path": _param(_STRING8, _path(path, OP_SET)),
            "value": _param(_STRING8, value),
        }
        if type is not None:
            params["type"] = _param(_STRING8, type)
        obj = await self._c.call_one(querystring.build(OP_SET, params), **kw)
        self._expect(obj, Ack, OP_SET)

    async def create(self, path: str, **kw: Any) -> None:
        """Make a path exist, with no value. WA, no answer. **Mutates.**

        `tree.set` in batch mode with an empty body: the node walks the path
        creating every missing segment
        (`astral-go/api/tree/client/server.go:127`), then reads objects until
        the `eos` and answers one per object -- none, here.

        The `eos` is sent and the stream is read to its end, which is what
        astral-go's `Node.Create` omits (bug G-11): on success the node answers
        nothing, and on a failed walk it answers an `error_message` that the Go
        client discards, so a creation that failed is reported as one that
        worked. Here it raises `RemoteError`.

        An `ack` is tolerated and not required, because zero objects earn zero
        answers on this node and a node that acknowledged the empty batch would
        not be breaking the op's contract.
        """
        qs = querystring.build(OP_SET, {"path": _param(_STRING8, _path(path, OP_SET))})
        for obj in await self._c.call_with(qs, eos=True, **kw):
            self._expect(obj, Ack, OP_SET)

    async def delete(self, path: str, *, recursive: bool = False, **kw: Any) -> None:
        """Delete the node at a path. RR, one `ack`. **Mutates.**

        A node with subnodes cannot be deleted on its own: astrald answers `node
        has subnodes` (`astrald/mod/tree/src/module.go:215`). `recursive=True`
        descends the subtree depth-first and deletes from the leaves up
        (`astral-go/api/tree/client/server.go:178`), and it descends **through
        remote mounts**, where every step is a query to the mounted node.

        The argument is `recursive` and is sent only when true. astral-docs
        writes `-Recursive`, which the node drops silently, so the documented
        recursive delete has never once been recursive (bug D-17).
        """
        params = {"path": _param(_STRING8, _path(path, OP_DELETE))}
        if recursive:
            params["recursive"] = _param(_BOOL, True)
        obj = await self._c.call_one(querystring.build(OP_DELETE, params), **kw)
        self._expect(obj, Ack, OP_DELETE)

    async def mount_remote(
        self,
        path: str,
        node: Identity | str,
        *,
        root: str | None = None,
        **kw: Any,
    ) -> None:
        """Mount a remote node's subtree at a local path. RR, one `ack`.
        **Mutates.**

        `path` must be absolute and must not already be a mount point; astrald
        answers `path must be absolute` (`astrald/mod/tree/src/module.go:92`) or
        `mount point already exists` (`astrald/mod/tree/src/module.go:99`).
        `node` is resolved by the node's own directory, so an alias,
        `localnode`, or 66 hex characters all reach it; an empty one is refused
        here, because the node's resolver reads it as the zero identity and
        would mount a subtree of `anyone`.

        **`node`, not `target`, and the name is the whole point.** The op's wire
        argument is `target=` and it travels as one, but `target` is also the
        routing keyword every method of every module client forwards to
        `Client.query` -- "route this query to node X" -- and this op is the one
        place in the SDK where those are two different nodes. Taking the op's
        argument under that name ate the routing keyword: `mount_remote(p, X)`
        put X in the query string and routed to the local node, with no way to
        reach the routing target on this op at all and nothing said about it.
        `Objects` met the same collision on `zone`, where the two levers really
        are one scope, and forwards the value to both (`_scope`); here they are
        not one thing, so the parameter is renamed instead and `target=` in `**kw`
        keeps meaning what it means everywhere else.

        `root` is the path on the remote node, and is sent only when given. An
        absent `root` mounts the remote root, which is what `/` addresses too
        (`astrald/mod/tree/src/module.go:126`).

        Every read under the mount point becomes a query to the remote node, so
        a `list` or a recursive `delete` below it leaves the local process.
        """
        params = {
            "path": _param(_STRING8, _path(path, OP_MOUNT_REMOTE)),
            "target": _param(_STRING8, _target(node, OP_MOUNT_REMOTE)),
        }
        if root is not None:
            params["root"] = _param(_STRING8, _path(root, OP_MOUNT_REMOTE))
        obj = await self._c.call_one(querystring.build(OP_MOUNT_REMOTE, params), **kw)
        self._expect(obj, Ack, OP_MOUNT_REMOTE)

    async def unmount(self, path: str, **kw: Any) -> None:
        """Remove a mount point. RR, one `ack`. **Mutates.**

        The mount point only, never the nodes under it: unmounting drops the
        entry that overlaid the path and leaves whatever the local subtree held
        before. A path that is not a mount point answers `mount point does not
        exist` (`astrald/mod/tree/src/module.go:116`), and a relative one
        answers `path must be absolute`.

        `/` is a mount point on every node -- astrald mounts the database store
        there at load (`astrald/mod/tree/src/loader.go:30`) -- so unmounting it
        detaches the whole tree and every later op answers an error. Nothing
        here refuses it; the caller names the path.
        """
        obj = await self._c.call_one(
            querystring.build(
                OP_UNMOUNT, {"path": _param(_STRING8, _path(path, OP_UNMOUNT))}
            ),
            **kw,
        )
        self._expect(obj, Ack, OP_UNMOUNT)


# --- argument discipline --------------------------------------------------


_param = ModuleClient._param
"""One parameter value, in its text form. `ModuleClient`'s, not a copy."""


def _path(value: str, op: str) -> str:
    """A path argument. Never empty, because the empty path is the root.

    The walk strips one leading slash and skips empty segments
    (`astral-go/api/tree/node.go:33`, `astral-go/api/tree/node.go:41`), so an
    empty path addresses the root exactly as `/` does. A caller that passed an
    unset variable would therefore read, write or delete the root instead of
    failing, which is the one path no caller means by accident.
    """
    if not isinstance(value, str):
        raise BadArgumentType(
            f"{op}: expected a path string, got {type(value).__name__}"
        )
    if not value:
        raise BadArgument(
            f"{op}: the empty path addresses the root; pass ROOT to mean the root"
        )
    return value


def _target(value: Identity | str, op: str) -> str:
    """A target the node resolves: an alias, `localnode`, or a hex key.

    An empty string is refused: astrald's resolver maps `""` and `"anyone"` to
    the zero identity (`astrald/mod/dir/src/module.go:56`), so an accidental
    empty target mounts a subtree of `anyone`.
    """
    if isinstance(value, Identity):
        return value.text()
    if not isinstance(value, str):
        raise BadArgumentType(
            f"{op}: expected an identity or a name, got {type(value).__name__}"
        )
    if not value:
        raise BadArgument(
            f"{op}: the empty target resolves to the zero identity on the node; "
            "pass Identity.ANYONE to mean that identity"
        )
    return value


TREE_TYPES: Final[Sequence[type]] = (ErrNoValue,)
"""Every wire type this module declares, for a private-registry sweep.

One, and it is the only type `astral-go/api/tree` registers. A tree *value* is
any object at all, so this module's vocabulary is not the vocabulary of what it
carries: `registry.add(*Tree.TYPES)` makes `tree`'s own error decodable and
nothing else, and a value whose type the registry lacks is what
`allow_unparsed=True` on `get` and `follow` exists for.
"""

Tree.TYPES = TREE_TYPES
