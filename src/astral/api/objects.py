"""`objects.*` -- repositories, object bytes, descriptors, search and schema.

The largest module in the SDK: 25 ops, nine wire types, the `Writer` lifecycle
and the search grammar. Every op below is present on the live node's `shell.spec`
registry, verified this session against `furry-bolt`.

**Op surface, and the shape each one declares** (design section 4.7; a shape is a
per-op contract and is **not** discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `objects.blueprints` | ST | `string8` x n ++ `eos` | read-only |
| `objects.contains` | RR / BD | `bool` per id | read-only |
| `objects.create` | BD | `ack`, then `object_id.sha256` on commit | **mutates** |
| `objects.delete` | RR / BD | `ack` per id | **mutates** |
| `objects.describe` | ST | `mod.objects.describe_result` x n ++ `eos` | read-only |
| `objects.echo` | BD | the objects sent, filtered | read-only |
| `objects.find` | ST | `identity` x n ++ `eos` | read-only |
| `objects.get_blueprint` | RR | `astral.blueprint` | read-only |
| `objects.get_type` | RR | `string8` | read-only |
| `objects.load` | RR / BD | the decoded object per id | read-only |
| `objects.new` | RR | a zero value of the named type, or `nil` | read-only |
| `objects.new_mem` | RR | `ack` | **mutates** |
| `objects.probe` | RR / BD | `mod.objects.probe` per id | read-only |
| `objects.purge` | ST | `object_id.sha256` x n ++ `eos` | **deletes data** |
| `objects.push` | BD | `bool` per object | **mutates** |
| `objects.read` | RAW | unframed bytes | read-only |
| `objects.register_blueprint` | BD | `object_id.sha256` per input ++ `eos` | **mutates** |
| `objects.register_describer` | RR | `ack` | **mutates** |
| `objects.register_finder` | RR | `ack` | **mutates** |
| `objects.register_searcher` | RR | `ack` | **mutates** |
| `objects.remove_repository` | RR | `ack` | **mutates** |
| `objects.repositories` | ST | `mod.objects.repository_info` x n ++ `eos` | read-only |
| `objects.scan` | ST(+follow) | `object_id.sha256` x n ++ `eos` | read-only |
| `objects.search` | ST | `mod.objects.search_result` x n ++ `eos` | read-only |
| `objects.store` | BD | `object_id.sha256` per object | **mutates** |

**`objects.read` is the SDK's only RAW op.** Its response is not a framed object
channel at all, so an accepted query does not always carry objects. Verified
live: 48 bytes of `data1rq4d…` came back as `41444330` -- the `ADC0` canonical
stamp -- then `string8("mod.crypto.private_key")` and the payload. A stored
astral object reads back in its canonical form; a stored blob reads back as
itself.

**Four ops have no default repository and answer `error_message("repository not
found")` without one**: `contains`, `delete`, `purge` and `scan`. astrald looks
the name up with no fallback, and for `delete` says so -- "no default to avoid
accidental deletion" (`mod/objects/src/op_delete.go`). Verified live for `scan`
and `contains`. So `repo` is a **positional, required** argument on all four
here, and a caller cannot reach the failure by forgetting a keyword. `probe`,
`load`, `store` and `create` do have defaults (`ReadDefault`/`WriteDefault`) and
take `repo` as an option.

**The streamed-id forms terminate four different ways.** Every one of
`contains`, `delete`, `load`, `probe`, `push`, `store` and `register_blueprint`
reads its input off the channel body, and no two agree on what ends it:

| Op | On the client's `eos` | What ends the op |
|---|---|---|
| `contains` | ignored | EOF -- the client closing |
| `delete` | ignored | EOF |
| `load` | ignored | EOF |
| `probe` | the op closes the channel | the `eos` |
| `push` | the op returns | the `eos` |
| `store` | the op returns | the `eos` |
| `register_blueprint` | the op returns, after a final `eos` | the `eos` |

Verified live: after `send_eos()` on `objects.contains?repo=main` the node
answered nothing further and the stream stayed open until the client closed it.
So the terminator is declared per op below and never inferred, and the three ops
that ignore it are not sent one.

**Every input is interleaved with its answer**, one send then one read, rather
than sending the whole batch first. Each of these ops answers one object per
input as it goes, so batching the sends would fill the node's socket buffer
while nobody read the answers -- a deadlock whose size is the batch's.

**`objects.load`'s `unparsed` argument does not do what its name says.** astrald
passes it to `channel.AllowUnparsed`, which configures the channel's *receiver*
(`astral-go/astral/channel/channel.go:69` -> `binary_receiver.go`), so it governs
the op's reads of the caller's input on the streamed-id form and nothing else.
The object the op sends back is decoded by `Module.Load` through
`astral.Decode(…, astral.Canonical())` with no such tolerance, so an object whose
blueprint the node does not know fails with an `error_message` whether or not
`unparsed` is set. It is sent faithfully and documented for what it is; the
client-side tolerance is `allow_unparsed=True`, which is a different keyword on a
different side of the wire.

**`objects.new` on `mod.nodes.node_info` panics the node.** A nil `*Identity`
reaches a value-receiver `WriteTo` and astrald dies; the fix is not merged. That
one type name is refused here rather than sent (`CRASHES_ON_NEW`), because a
refusal is strictly better than a node crash and this module is the only thing
between the two. `client.call_one("objects.new?type=…")` is the deliberate
bypass, and the refusal is one line to delete when the fix lands.

**`objects.get_blueprint` exists and answers.** Design bug G-21 -- "there is no
way to fetch a blueprint's schema from a node" -- is **withdrawn**: the op is on
the live registry, it is absent only from astral-go's method constants, and it
returns an `astral.blueprint` for any registered non-primitive type. Verified
live for seven types. `learn()` is the wiring: it fetches a type's blueprint,
fetches every type that blueprint references first, and registers the closure, so
a `RuntimeRecord` can decode a type this SDK was never built against.

**Importing this module registers `astral.blueprint`.** The nine blueprint
carriers live in `astral.blueprint`, which nothing else imports, so before this
module existed `objects.get_blueprint` answered with a type the process could not
decode -- observed: `BlueprintNotFound: astral.blueprint` against a healthy node.
The import here is the registration.

**`mod.objects.repository_info.Free` is a `uint64`** (R-8, docs bug D-22, which
examples a signed `-1`). `0xFFFF_FFFF_FFFF_FFFF` means unknown or unbounded and
`RepositoryInfo.free_unknown` is the test for it. Verified live across the ten
repositories `furry-bolt` holds: every `Free` decoded as an unsigned byte count,
the three network- and virtual-backed ones reported 0, and none reported the
sentinel.

**`objects.describe` answers a bare `eos` for every object in the default
repo.** astrald fans the query out to registered describers and this node has
none, so the shape is real and the emptiness is the node's state, not a fault.
The 1-minute server timeout applies to `describe`, `find` and `search` alike.

**astral-go client bugs not ported** (design section 5.1 rule 7):
`objects.new_mem` sends `size` as an int64 where the op parses a size string;
`objects.read` hardcodes `zone=dvn`; `objects.register_blueprint` and
`objects.store` never send the terminating `eos` (G-10). This module sends a size
string, sends no zone the caller did not ask for, and sends the `eos`.

**The `zone` argument is not the routing zone, and on four ops it destroys it.**
Eight ops declare a `zone` query-string argument. astrald sets the op's context
zone from `route_query_msg.Zone` (`mod/apphost/src/guest.go:220`), and then
`describe`, `find`, `search` and `read` *widen* it with `IncludeZone(args.Zone)`
while `scan`, `delete`, `purge` and `load` *replace* it with `WithZone` --
defaulting to `ZoneAll` when the argument is absent. So on those four a routing
zone the caller set is silently discarded. This module therefore takes one
`zone=` keyword on those eight ops and sends it **both** as the op argument and
as the routing zone, so one argument means one scope. Everywhere else `zone`
stays in `**kw` and means the routing zone alone, as on every other module.

**`in` and `out` are not arguments here.** Every op declares them; they are the
channel formats and belong to `Client.query`'s `fmt_in`/`fmt_out`, which writes
them into the query string itself (design section 4.7). An op-level `in=`
parameter would be a second answer to the question the query string already
answers.

**`client.objects` is the surface design section 5.1 specifies**, a cached
property in `client.py`; `Objects(client)` constructs the same object and is
what the tests here use. This module holds no reference to `Client` at import
time -- the annotations are strings -- so `client.py` imports it inside the
property body without a cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import TracebackType
from typing import Any, Final, Iterable, Iterator, Sequence

from .. import querystring
from ..blueprint import (
    ArraySpec,
    Blueprint,
    MapSpec,
    ObjectSpec,
    PrimitiveSpec,
    PtrSpec,
    RefSpec,
    SliceSpec,
)
from ..blueprint import Field as BlueprintField
from ..blueprint import of as blueprint_of
from ..blueprint import spec_of
from ..client import Client, StreamContext
from ..codec.binary import payload_bytes
from ..errors import (
    BadArgument,
    BadArgumentType,
    CycleDetected,
    ParseError,
    ProtocolError,
    QueryTimeout,
    RemoteError,
    StreamClosed,
)
from ..object import Ack, Blob, ErrorMessage
from ..primitives import Bool, String8
from ..record import record, wire
from ..registry import Blueprints, default_blueprints
from ..registrar import (
    OP_REGISTER_DESCRIBER,
    OP_REGISTER_FINDER,
    OP_REGISTER_SEARCHER,
)
from ..spec import PRIMITIVE_TYPES, AnySpec, Primitive, Ptr, Slice, Spec, referenced_type
from ..stream import Stream
# `Nonce` is imported for its annotation, not for a reference in this file:
# `ReadObjectAction` and `CreateObjectAction` inherit `auth.Action`'s
# `nonce: Nonce`, and the `__init__` a dataclass generates for them resolves its
# annotations against **this** module's globals. Without the name here,
# `inspect.signature(ReadObjectAction, eval_str=True)` and
# `typing.get_type_hints(ReadObjectAction.__init__)` both raise `NameError` --
# the exact py.typed failure `api/base.py` exists to prevent, and one that
# `get_type_hints(cls)` does not show, because that walks `__mro__` and uses each
# base's own globals.
from ..types import Duration, Identity, Nonce, ObjectID, Size, Zone
from .auth import Action
from .base import ModuleClient

__all__ = [
    "CHUNK_SIZE",
    "CRASHES_ON_NEW",
    "CommitMsg",
    "CreateObjectAction",
    "Descriptor",
    "FREE_UNKNOWN",
    "LIST_SEPARATOR",
    "MAX_PUSH_SIZE",
    "OBJECTS_TYPES",
    "OP_BLUEPRINTS",
    "OP_CONTAINS",
    "OP_CREATE",
    "OP_DELETE",
    "OP_DESCRIBE",
    "OP_ECHO",
    "OP_FIND",
    "OP_GET_BLUEPRINT",
    "OP_GET_TYPE",
    "OP_LOAD",
    "OP_NEW",
    "OP_NEW_MEM",
    "OP_PROBE",
    "OP_PURGE",
    "OP_PUSH",
    "OP_READ",
    "OP_REGISTER_BLUEPRINT",
    "OP_REGISTER_DESCRIBER",
    "OP_REGISTER_FINDER",
    "OP_REGISTER_SEARCHER",
    "OP_REMOVE_REPOSITORY",
    "OP_REPOSITORIES",
    "OP_SCAN",
    "OP_SEARCH",
    "OP_STORE",
    "Objects",
    "Probe",
    "QueryTag",
    "REPO_DEVICE",
    "REPO_GROUPS",
    "REPO_LOCAL",
    "REPO_MAIN",
    "REPO_MEMORY",
    "REPO_NETWORK",
    "REPO_REMOVABLE",
    "REPO_SYSTEM",
    "REPO_VIRTUAL",
    "ReadObjectAction",
    "RepositoryInfo",
    "SearchQuery",
    "SearchResult",
    "TAG_EXCLUDE",
    "TAG_OPTIONAL",
    "TAG_OPTIONAL_EXCLUDE",
    "TAG_REQUIRE",
    "Writer",
    "WriterContext",
]

# --- op names ------------------------------------------------------------
#
# The three `register_*` names are imported from `astral.registrar` rather than
# respelled: the registrar re-runs those ops as a post-connect hook after every
# reconnect (design section 4.6), and two spellings of one op name is one typo
# away from a registration that silently never happens.

OP_BLUEPRINTS: Final = "objects.blueprints"
OP_CONTAINS: Final = "objects.contains"
OP_CREATE: Final = "objects.create"
OP_DELETE: Final = "objects.delete"
OP_DESCRIBE: Final = "objects.describe"
OP_ECHO: Final = "objects.echo"
OP_FIND: Final = "objects.find"
OP_GET_BLUEPRINT: Final = "objects.get_blueprint"
OP_GET_TYPE: Final = "objects.get_type"
OP_LOAD: Final = "objects.load"
OP_NEW: Final = "objects.new"
OP_NEW_MEM: Final = "objects.new_mem"
OP_PROBE: Final = "objects.probe"
OP_PURGE: Final = "objects.purge"
OP_PUSH: Final = "objects.push"
OP_READ: Final = "objects.read"
OP_REGISTER_BLUEPRINT: Final = "objects.register_blueprint"
OP_REMOVE_REPOSITORY: Final = "objects.remove_repository"
OP_REPOSITORIES: Final = "objects.repositories"
OP_SCAN: Final = "objects.scan"
OP_SEARCH: Final = "objects.search"
OP_STORE: Final = "objects.store"


# --- repository group names ----------------------------------------------
#
# astral-go's `api/objects/module.go` constants. A group is a repository name
# like any other, so any of these is a legitimate `repo` argument.

REPO_MAIN: Final = "main"
REPO_DEVICE: Final = "device"
REPO_MEMORY: Final = "memory"
REPO_LOCAL: Final = "local"
REPO_REMOVABLE: Final = "removable"
REPO_VIRTUAL: Final = "virtual"
REPO_NETWORK: Final = "network"
REPO_SYSTEM: Final = "system"

REPO_GROUPS: Final[tuple[str, ...]] = (
    REPO_MAIN,
    REPO_DEVICE,
    REPO_MEMORY,
    REPO_LOCAL,
    REPO_REMOVABLE,
    REPO_VIRTUAL,
    REPO_NETWORK,
    REPO_SYSTEM,
)
"""The eight group names astrald ships. A node may hold repositories besides
these -- `furry-bolt` also answers `data`, `mem0` and `system` -- so this is the
vocabulary, not the inventory. `repositories()` is the inventory."""


# --- constants the node fixes --------------------------------------------

FREE_UNKNOWN: Final = 0xFFFF_FFFF_FFFF_FFFF
"""`repository_info.Free` for a repository whose free space is unknown.

R-8: the field is `astral.Uint64` in astral-go and the docs example it as a
signed `-1`, which is these bytes. `RepositoryInfo.free_unknown` is the test.
"""

MAX_PUSH_SIZE: Final = 32 * 1024
"""The documented per-object cap on `objects.push`.

**astrald does not enforce it.** `maxPushSize` is declared in
`mod/objects/src/op_push.go` and referenced nowhere -- verified by grep over the
module. It is checked here anyway: a client that relies on an unenforced remote
limit is a client that breaks when the limit is implemented.
"""

CHUNK_SIZE: Final = 1 << 16
"""How much of a `Writer.write()` goes into one `blob` frame.

The frame carries a `bytes32` length, so a single frame could hold four
gigabytes; splitting keeps one `write()` of an arbitrarily large buffer from
becoming one arbitrarily large allocation on both sides. The repository writer
concatenates the blobs in order, so chunking is invisible to the stored object.
"""

CRASHES_ON_NEW: Final[frozenset[str]] = frozenset({"mod.nodes.node_info"})
"""Type names `objects.new` must never be sent.

`mod.nodes.node_info` holds a `*astral.Identity` and astral-go's zero value
leaves it nil; the type's `WriteTo` has a value receiver, so serialising the zero
value dereferences nil and **the node dies**. Deterministic, observed, and the
fix is on an unmerged astral-go branch, so the running node still crashes.
"""


# --- parameter specs -----------------------------------------------------
#
# One dict for the whole module, unlike `apphost.py`'s three: every parameter
# name that appears in more than one `objects` op has the same type in all of
# them -- `id` is an `object_id.sha256` in all eight ops that declare it, `repo`
# is a `string8` in all nine. Verified against the live `shell.spec` registry.
#
# Design section 5.1 rule 2 makes `querystring.encode_param(spec, value)` the
# single implementation of parameter encoding, and the declaration is what
# refuses a wrong-typed value instead of encoding it into a query the node reads
# as something else.

_SPECS: Final[dict[str, Spec]] = {
    "alloc": Primitive("uint64"),
    "except": Primitive("string8"),
    "follow": Primitive("bool"),
    "id": Primitive("object_id.sha256"),
    "limit": Primitive("uint64"),
    "name": Primitive("string8"),
    "offset": Primitive("uint64"),
    "only": Primitive("string8"),
    "q": Primitive("string8"),
    "repo": Primitive("string8"),
    "size": Primitive("string8"),
    "stop": Primitive("string8"),
    "strict": Primitive("bool"),
    "type": Primitive("string8"),
    "unparsed": Primitive("bool"),
    "zone": Primitive("zone"),
}

# astrald splits `only`, `except` and the repo-group membership lists on this
# byte, so a name containing one is two names on the server.
LIST_SEPARATOR: Final = ","


# --- wire types ----------------------------------------------------------


@record("mod.objects.probe")
class Probe:
    """What a repository knows about an object without decoding it.

    `time` is how long the probe took, not a timestamp: the Go field is
    `astral.Duration`. Verified live -- `mod.crypto.private_key`, repo `system`,
    mime `application/octet-stream`, 8500 ns.

    `type` is empty for an object with no astral type header, which is what
    distinguishes a stored blob from a stored object. astral-go names this type
    `Probe` and the wire name is `mod.objects.probe`; both agree here.
    """

    type: str = wire("Type", Primitive("string8"))
    repo: str = wire("Repo", Primitive("string8"))
    mime: str = wire("Mime", Primitive("string8"))
    time: Duration = wire("Time", Primitive("duration"))


@record("mod.objects.repository_info")
class RepositoryInfo:
    """One repository: its name, its human label, and its free space in bytes.

    `free` is a **`uint64`**, and `FREE_UNKNOWN` is the value that means unknown
    or unbounded (R-8). The docs example it as a signed `-1`, which is the same
    64 bits read the other way; decoding it as signed would report an exabyte of
    free space as a byte short of nothing.

    `name` is what a `repo=` argument takes. `label` is prose and is not an
    identifier: `furry-bolt` labels its `main` repository `World`.
    """

    name: str = wire("Name", Primitive("string8"))
    label: str = wire("Label", Primitive("string8"))
    free: int = wire("Free", Primitive("uint64"))

    @property
    def free_unknown(self) -> bool:
        """Whether `free` is the unknown-or-unbounded sentinel."""
        return int(self.free) == FREE_UNKNOWN

    @property
    def free_bytes(self) -> int | None:
        """`free` as a byte count, or `None` when it is the sentinel."""
        return None if self.free_unknown else int(self.free)


@record("mod.objects.describe_result")
class Descriptor:
    """One describer's answer about one object: who said it, about what, and what.

    astral-go names the Go type `Descriptor` and the wire type
    `mod.objects.describe_result`; the two names are both real and this class
    carries both.

    `data` is a polymorphic slot -- `astral.Object` in Go, an `Any` spec here --
    so a descriptor carries whatever type the describer chose and the field
    decodes through the registry. A type the registry does not know raises
    `BlueprintNotFound`; `learn()` is how a caller teaches it one.

    Verified live: the node's own blueprint for this type is `SourceID` as a
    `ptr` to `identity`, `ObjectID` as a `ptr` to `object_id.sha256`, and `Data`
    as an object spec. Both pointers, so R-2's off-by-one -- the legacy SDK
    modelled `*ObjectID` as a bare `object_id.sha256` -- cannot recur here.
    """

    source_id: Identity | None = wire("SourceID", Ptr("identity"))
    object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))
    data: Any = wire("Data", AnySpec())


@record("mod.objects.search_result")
class SearchResult:
    """One search match: the object, and the identity that can provide it.

    astrald deduplicates by `ObjectID` before sending, so one object appears once
    per `objects.search` even when several searchers found it -- and the surviving
    `source_id` is whichever searcher answered first.
    """

    source_id: Identity | None = wire("SourceID", Ptr("identity"))
    object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))


TAG_REQUIRE: Final = ""
"""`tag:value` -- the match must include it. The default modifier."""

TAG_EXCLUDE: Final = "EXCLUDE"
"""`-tag:value` -- the match must exclude it."""

TAG_OPTIONAL: Final = "OPTIONAL"
"""`?tag:value` -- the searcher may ignore it."""

TAG_OPTIONAL_EXCLUDE: Final = "OPTIONAL_EXCLUDE"
"""`~tag:value` -- an exclusion the searcher may ignore."""

_TAG_MODS: Final[dict[str, str]] = {
    "-": TAG_EXCLUDE,
    "?": TAG_OPTIONAL,
    "~": TAG_OPTIONAL_EXCLUDE,
}
_TAG_PREFIXES: Final[dict[str, str]] = {mod: prefix for prefix, mod in _TAG_MODS.items()}


@record("objects.query_tag")
class QueryTag:
    """One `name:value` constraint in a search query, with its modifier.

    **The type name has no `mod.` prefix** -- astral-go's `QueryTag.ObjectType()`
    returns `objects.query_tag`, and the registry name is what travels, so a
    `mod.` here would make every search query undecodable. Verified against the
    node's own blueprint for the type.

    `mod` is one of the four `TAG_*` constants and nothing else. astrald does not
    validate it; a searcher matches on the exact string, so an unrecognised
    modifier is a tag no searcher honours.
    """

    name: str = wire("Name", Primitive("string8"))
    mod: str = wire("Mod", Primitive("string8"))
    value: str = wire("Value", Primitive("string8"))

    def text(self) -> str:
        """This tag in the search grammar: `[prefix]name:value`."""
        value = str(self.value)
        if " " in value:
            value = f'"{value}"'
        return f"{_TAG_PREFIXES.get(str(self.mod), '')}{self.name}:{value}"


@record("objects.search_query")
class SearchQuery:
    """A parsed search: free words, plus zero or more tags.

    Also `objects.search`'s `q=` argument, in its text form. The grammar is
    ported from astral-go's `SearchQuery.UnmarshalText` verbatim, because a
    searcher registered through `objects.register_searcher` is handed the string
    and parses it with that function -- a second dialect here would make the SDK
    and the node disagree about what the user asked for.

    Grammar:

    - Tokens split on spaces; a double quote toggles quoting and is **removed**,
      so `title:"around the world"` is one token and one tag.
    - A leading `-`, `?` or `~` sets the modifier; anything else is `TAG_REQUIRE`.
    - The first `:` splits a token into name and value; a token with no `:` is a
      bare word.
    - Names, values and bare words are **lowercased**. Bare words join with a
      single space into `query`.

    The prefix is read after the quotes are stripped, so `"-tag:v"` is an
    exclusion, not a bare word. That is astral-go's behaviour and it is
    reproduced rather than corrected.
    """

    query: str = wire("Query", Primitive("string16"))
    tags: list[QueryTag] = wire("Tags", Slice("objects.query_tag"))

    @classmethod
    def parse(cls, text: str) -> "SearchQuery":
        """A search string in the grammar above."""
        words: list[str] = []
        tags: list[QueryTag] = []
        for token in _tokenize(text):
            mod = _TAG_MODS.get(token[:1], TAG_REQUIRE)
            if mod:
                token = token[1:]
            name, separator, value = token.partition(":")
            if separator:
                tags.append(QueryTag(name=name.lower(), mod=mod, value=value.lower()))
            else:
                words.append(token.lower())
        return cls(query=" ".join(words), tags=tags)

    def text(self) -> str:
        """This query back in the grammar, tags first, then the words.

        Not the inverse of `parse` on every input -- astral-go's `MarshalText`
        emits the tags before the words whatever order they arrived in, and a
        value with a space is re-quoted. Parsing the result yields an equal
        query, which is the property that matters.
        """
        tokens = [tag.text() for tag in self.tags]
        words = str(self.query).strip()
        if words:
            tokens.append(f'"{words}"' if " " in words else words)
        return " ".join(tokens)

    def required_tags_in(self, *known: str) -> str | None:
        """The first required or excluded tag name not in `known`, or `None`.

        astral-go's `RequiredTagsIn`, which a searcher calls to reject a query it
        cannot answer honestly. Optional tags are ignored: a searcher is allowed
        to disregard those.
        """
        names = frozenset(known)
        for tag in self.tags:
            if str(tag.mod) in (TAG_REQUIRE, TAG_EXCLUDE) and str(tag.name) not in names:
                return str(tag.name)
        return None


@record("mod.objects.commit_msg")
class CommitMsg:
    """The zero-byte object that commits an `objects.create` writer.

    Sent by `Writer.commit()` and by nothing else. The node's own blueprint for
    the type declares no fields, verified live.
    """


@record("mod.objects.read_object_action")
class ReadObjectAction(Action):
    """The authorization action `objects.read` submits before serving bytes.

    A denial is a **query rejection**, not an `error_message`: `op_read.go` calls
    `q.Reject()`, so the caller sees `QueryRejected` and never an object stream.

    `Action`'s two fields come first, matching Go's promotion order for the
    embedded `auth.Action`, so the zero value is ten bytes -- an eight-byte
    nonce and two absent pointers. Verified live: `objects.new?type=…` answers
    `00000000000000000000`.
    """

    object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))


@record("mod.objects.create_object_action")
class CreateObjectAction(Action):
    """The authorization action guarding object creation.

    Carries the `auth.Action` fields and nothing else. astral-go's
    `ApplyConstraints` returns true unconditionally, so a permit for this action
    is unconstrained however it was written.
    """


def _tokenize(text: str) -> Iterator[str]:
    """Split on spaces, respecting double quotes, dropping the quotes.

    astral-go's `tokenizeQuery`, character for character. An unbalanced quote
    leaves the rest of the string in one token rather than raising, which is what
    the reference does and therefore what a searcher will be handed.
    """
    current: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
        elif char == " " and not quoted:
            if current:
                yield "".join(current)
                current.clear()
        else:
            current.append(char)
    if current:
        yield "".join(current)


# --- the writer ----------------------------------------------------------


_WRITER_SCOPE: Final = object()
"""The token `WriterContext.__aenter__` holds and no caller can spell.

`Writer`'s docstring used to claim its reachability was structural while
`Writer(stream, qs)` was an ordinary public constructor and both classes were in
`__all__`. A writer obtained that way is bound to no scope: every byte written to
it is lost, the stream stays open, one of the node's 32 workers stays held, and
there is no exception, no warning and no `ResourceWarning`, because this SDK has
no `__del__` fallback anywhere by design. A sentinel makes the claim true for
construction, which is the half that can be made true.
"""


class Writer:
    """An open `objects.create` handle: `write()`, then `commit()` or `discard()`.

    astral-go states the rule in the interface it defines -- "Either Commit() or
    Discard() must be called at the end" -- and enforces nothing. Here it is
    enforced, because the failure it prevents is silent: a writer that is neither
    committed nor discarded loses every byte written to it, the node reports
    nothing, and the caller's next read of the object it thinks it created is a
    "not found" that names no cause.

    Enforcement has two halves, and they are not equally strong. The second is
    structural and the first is only as strong as `async with`:

    1. A `Writer` cannot be constructed. `__init__` refuses every caller but
       `WriterContext.__aenter__`, so the only way to hold one is to have
       entered the scope that ends it. This used to be asserted as structural
       while `Writer(stream, qs)` was an ordinary public constructor.
    2. Leaving that scope without committing or discarding discards the data --
       which is what the node does anyway -- and **raises** `StreamClosed`. An
       exception on the way out is left alone: the data is discarded and the
       original exception propagates, because a failure inside the body is a
       reason not to commit and not a second fault to report.

    **What is still reachable, and is a documented way to lose data:** driving
    `WriterContext.__aenter__()` by hand and never calling `__aexit__`. That
    writer is bound to no scope, so nothing ends it; the bytes written to it are
    lost, the stream stays open, and one of the node's 32 workers stays held,
    with no exception and no `ResourceWarning` -- the SDK has no `__del__`
    fallback anywhere, by design (`stream.py`). Every context manager in Python
    can be driven that way and none of them can defend against it. `async with`
    is the contract.

    `commit()` and `discard()` are both terminal. `discard()` after `commit()` is
    a no-op, so `try: … finally: await w.discard()` is a correct idiom rather
    than a way to lose a committed object.
    """

    __slots__ = ("_stream", "_qs", "_state", "_object_id")

    def __init__(self, stream: Stream, qs: str, _scope: object = None) -> None:
        if _scope is not _WRITER_SCOPE:
            raise BadArgument(
                "Writer is not constructible: `async with objects.create(...)` "
                "is the only way to one, because the scope is what guarantees "
                "the writer is committed or discarded"
            )
        self._stream = stream
        self._qs = qs
        self._state = "open"
        self._object_id: ObjectID | None = None

    def __repr__(self) -> str:
        return f"Writer({self._qs!r}, {self._state})"

    @property
    def resolved(self) -> bool:
        """Whether `commit()` or `discard()` has run."""
        return self._state != "open"

    @property
    def committed(self) -> bool:
        """Whether the data reached storage. `object_id` is set exactly then."""
        return self._state == "committed"

    @property
    def object_id(self) -> ObjectID | None:
        """The committed object's ID, or `None` before a successful commit."""
        return self._object_id

    async def write(self, data: bytes, *, timeout: float | None = None) -> int:
        """Append bytes to the object. Returns how many were written.

        One `blob` frame per `CHUNK_SIZE` bytes. Empty `data` sends no frame at
        all and returns 0: an empty blob appends nothing and costs the node one
        more frame to read.

        `timeout` bounds each frame's drain, which is where a node that stopped
        reading pins the send. It has no default, because how long a write may
        take is the object's size divided by a link speed neither side knows.
        """
        if self._state != "open":
            raise StreamClosed(f"{self._qs}: the writer is already {self._state}")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise BadArgumentType(
                f"{self._qs}: write expects bytes, got {type(data).__name__}"
            )
        raw = bytes(data)
        for start in range(0, len(raw), CHUNK_SIZE):
            await self._stream.send(
                Blob(raw[start : start + CHUNK_SIZE]), timeout=timeout
            )
        return len(raw)

    async def commit(self, *, timeout: float | None = None) -> ObjectID:
        """Commit what was written and return the new object's ID.

        Sends `mod.objects.commit_msg` and reads the one answer. astrald ends the
        op on that answer either way -- the repository writer accepts no further
        blob and no second commit -- so the stream is closed here rather than
        left open to be closed by the scope.

        An `error_message` surfaces as `RemoteError` and the writer is left
        `discarded`: the data did not reach storage and there is nothing to
        commit a second time.

        `timeout` has no default and none is defensible: astrald hashes the whole
        object inside this call, so a bound that suited a kilobyte would abandon
        a gigabyte mid-commit and a bound that suited a gigabyte would not be a
        bound. The caller knows the size; `async with asyncio.timeout(…)` around
        the commit is the general form.
        """
        if self._state != "open":
            raise StreamClosed(f"{self._qs}: the writer is already {self._state}")
        try:
            await self._stream.send(CommitMsg(), timeout=timeout)
            answer = await self._stream.first(timeout=timeout)
        except BaseException:
            self._state = "discarded"
            await self._close()
            raise
        if answer is None:
            self._state = "discarded"
            await self._close()
            raise ProtocolError(f"{self._qs}: the stream ended before the commit answer")
        if not isinstance(answer, ObjectID):
            self._state = "discarded"
            await self._close()
            raise ProtocolError(
                f"{self._qs}: expected 'object_id.sha256', got "
                f"{getattr(answer, 'ASTRAL_TYPE', type(answer).__name__)!r}"
            )
        self._state = "committed"
        self._object_id = answer
        await self._close()
        return answer

    async def discard(self) -> None:
        """Throw the written data away. Closing without committing is the discard.

        A no-op once the writer is resolved, so a `finally` that discards after a
        successful commit is correct rather than destructive.
        """
        if self._state == "open":
            self._state = "discarded"
        await self._close()

    async def _close(self) -> None:
        await self._stream.aclose()


class WriterContext:
    """What `Objects.create()` returns: the scope a `Writer` may exist in.

    The query is routed on `__aenter__` and not on construction, so building one
    and discarding it opens nothing -- the same rule `StreamContext` follows.
    Public and exported, because it is the return type of a public method.
    """

    __slots__ = ("_client", "_qs", "_kw", "_ack_timeout", "_writer")

    def __init__(
        self,
        client: Client,
        qs: str,
        kw: dict[str, Any],
        ack_timeout: float | None,
    ) -> None:
        self._client = client
        self._qs = qs
        self._kw = kw
        self._ack_timeout = ack_timeout
        self._writer: Writer | None = None

    async def __aenter__(self) -> Writer:
        stream = await self._client.query(self._qs, **self._kw)
        try:
            first = await stream.first(timeout=self._ack_timeout)
            if first is None:
                raise ProtocolError(f"{self._qs}: the stream closed before the ack")
            if not isinstance(first, Ack):
                raise ProtocolError(
                    f"{self._qs}: expected 'ack', got "
                    f"{getattr(first, 'ASTRAL_TYPE', type(first).__name__)!r}"
                )
        except BaseException:
            # Including cancellation: a create stream abandoned here holds one of
            # the node's 32 workers with a repository writer open behind it.
            await stream.aclose()
            raise
        self._writer = Writer(stream, self._qs, _WRITER_SCOPE)
        return self._writer

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        writer, self._writer = self._writer, None
        if writer is None:
            return
        unresolved = not writer.resolved
        await writer.discard()
        if unresolved and exc_type is None:
            raise StreamClosed(
                f"{self._qs}: the writer was neither committed nor discarded, so "
                "everything written to it is gone -- call commit() to keep it or "
                "discard() to say the loss was intended"
            )


# --- argument discipline -------------------------------------------------


def _encode(values: dict[str, Any]) -> dict[str, str]:
    """Every parameter through its declared spec, from this module's one table.

    A partial application of `ModuleClient._encode` and not a second
    implementation: every op here draws from one module-wide `_SPECS`, so the
    table is bound once rather than named at 25 call sites.
    """
    return ModuleClient._encode(_SPECS, values)


_object_id = ModuleClient._object_id
"""An `object_id.sha256` argument, naming the op. `ModuleClient`'s, not a copy.

This module's form is the one the base class adopted: naming the op in the
failure is what lets `objects.probe('nope')` say which op refused it, and the
two copies elsewhere that did not were the caller-visible half of the divergence.
"""


def _repo(name: str, op: str) -> str:
    """A repository name the node has no default for.

    Refused when empty: astrald looks the name up with no fallback and answers
    `error_message("repository not found")`, which reads as a missing repository
    rather than as a missing argument.
    """
    if not isinstance(name, str):
        raise BadArgumentType(
            f"{op}: repo expects a repository name, got {type(name).__name__}"
        )
    if not name:
        raise BadArgument(
            f"{op}: this op has no default repository; an empty name answers "
            f"'repository not found'. Name one -- {REPO_MAIN!r} is everything"
        )
    return name


def _type_name(name: str, op: str) -> str:
    """A registry type name argument."""
    if not isinstance(name, str):
        raise BadArgumentType(
            f"{op}: type expects a type name, got {type(name).__name__}"
        )
    if not name:
        raise BadArgument(f"{op}: empty type name")
    return name


def _name_list(values: str | Sequence[str] | None, key: str, op: str) -> str | None:
    """Type names joined for a `only=` or `except=` argument.

    A single name is accepted unwrapped. A name containing the separator is
    refused: astrald splits the argument on it, so such a name is two names on
    the server and matches neither.
    """
    if values is None:
        return None
    names = [values] if isinstance(values, str) else list(values)
    for name in names:
        if not name:
            raise BadArgument(f"{op}: empty name in {key}")
        if LIST_SEPARATOR in name:
            raise BadArgument(
                f"{op}: {key} name {name!r} contains {LIST_SEPARATOR!r}, which "
                "the node reads as two names"
            )
    return LIST_SEPARATOR.join(names) if names else None


def _zone(value: Zone | int | str) -> Zone:
    """A zone argument, from a `Zone`, its bits, or its `dvn` letters."""
    if isinstance(value, Zone):
        return value
    if isinstance(value, str):
        return Zone.parse(value)
    return Zone(int(value))


def _scope(
    zone: Zone | int | str | None, params: dict[str, Any], kw: dict[str, Any]
) -> None:
    """Send one zone as the op argument **and** as the routing zone.

    The two are one scope for a caller and two levers on the wire: astrald seeds
    the op's context from `route_query_msg.Zone` and then `scan`, `delete`,
    `purge` and `load` overwrite it with the argument, defaulting to `ZoneAll`
    when there is none. Setting only the routing zone on those four therefore
    does nothing at all, and setting only the argument leaves the hop wider than
    the caller asked for.
    """
    if zone is None:
        return
    value = _zone(zone)
    params["zone"] = value
    kw["zone"] = value


def _size(value: Size | int | str, op: str) -> str:
    """A `size` argument, as the **size string** the op parses.

    astral-go's client sends an int64 here (bug G-11 item 3) while
    `op_new_mem.go` parses the value with `astral.ParseSize`, which reads
    `64M`, `1.5GiB` or plain digits. A string is passed through after being
    parsed locally, so a typo is refused here rather than becoming a repository
    of the wrong size; an int or a `Size` travels as decimal bytes.
    """
    if isinstance(value, str):
        Size.parse(value)  # raises ParseError on anything the node would reject
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadArgumentType(
            f"{op}: size expects a size string, an int of bytes or a Size, got "
            f"{type(value).__name__}"
        )
    return Size(int(value)).text()


def _typed(
    obj: Any, kind: type | None, op: str, index: int, endpoint: str | None = None
) -> Any:
    """One answer of a per-input batch, or the fault that names which input.

    **The remote's own text stays unprefixed in `RemoteError.message`.** That is
    the attribute a caller matches on -- astrald's `record not found` is the
    common one -- and `errors.py` promises it is the responder's text and not
    the SDK's rendering of it. The input's position goes in the query slot beside
    the op name, where `attributed()` renders it into `str(exc)`. `load_many`
    used to fold that attribution into `message` instead, which reads identically
    through `str(exc)` -- `attributed()` de-duplicates the prefix -- and silently
    broke `e.message == "record not found"` for that one op.

    `kind=None` accepts any object and checks only for the fault, which is what a
    batch whose answers are ordinary objects of many types needs.

    `endpoint` names where the fault came from, as every stream-raised
    `RemoteError` does. It is not optional in spirit: an error that cannot say
    which node produced it is one a caller with two clients cannot act on.
    """
    if isinstance(obj, ErrorMessage):
        raise RemoteError(str(obj), query=f"{op}: input {index}", endpoint=endpoint)
    if kind is None:
        return obj
    if not isinstance(obj, kind):
        raise ProtocolError(
            f"{op}: input {index}: expected "
            f"{getattr(kind, 'ASTRAL_TYPE', kind.__name__)!r}, got "
            f"{getattr(obj, 'ASTRAL_TYPE', type(obj).__name__)!r}"
        )
    return obj


# --- the client ----------------------------------------------------------


class Objects(ModuleClient):
    """The `objects.*` ops, over one `Client`.

    Constructed as `Objects(client)`. The scaffolding and the `**kw` contract are
    `ModuleClient`'s: every method takes the query keywords `Client.query` takes
    and passes them through unread, except that the eight ops with a `zone`
    argument spend `zone=` on both the op and the hop (see the module docstring).
    """

    __slots__ = ()

    # --- repositories ---

    async def repositories(self, **kw: Any) -> list[RepositoryInfo]:
        """Every repository the node holds. ST, ends at `eos`.

        Answers ten entries on `furry-bolt`, including the eight group names and
        the two concrete repositories behind them. `free` is a `uint64` and
        `FREE_UNKNOWN` is the unknown sentinel.

        The op excludes the network zone server-side, so this is always the local
        inventory whatever zone the query carries.
        """
        return [
            self._expect(obj, RepositoryInfo, OP_REPOSITORIES)
            for obj in await self._c.call(OP_REPOSITORIES, **kw)
        ]

    async def new_mem(
        self, name: str, *, size: Size | int | str | None = None, **kw: Any
    ) -> None:
        """Create an in-memory repository under `name`. RR. **Mutates.**

        `size` is a size string -- `64M`, `1.5GiB` -- or a byte count. Omitted, it
        leaves astrald's default. The repository joins the `memory` group.

        An existing name answers with an `error_message`, which surfaces as
        `RemoteError`; the op does not replace a repository.
        """
        params: dict[str, Any] = {"name": _type_name(name, OP_NEW_MEM)}
        if size is not None:
            params["size"] = _size(size, OP_NEW_MEM)
        qs = querystring.build(OP_NEW_MEM, _encode(params))
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_NEW_MEM)

    async def remove_repository(self, name: str, **kw: Any) -> None:
        """Drop a repository and its group memberships. RR. **Mutates.**

        The repository's objects go with it if nothing else holds them. An empty
        name answers `error_message("name is empty")` and an unknown one
        `repository <name> not found`; both surface as `RemoteError`.

        Absent from astral-go entirely.
        """
        qs = querystring.build(
            OP_REMOVE_REPOSITORY, _encode({"name": _type_name(name, OP_REMOVE_REPOSITORY)})
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_REMOVE_REPOSITORY)

    # --- listing and membership ---

    async def scan(
        self, repo: str, *, zone: Zone | int | str | None = None, **kw: Any
    ) -> list[ObjectID]:
        """Every object id in a repository. ST, ends at `eos`.

        `repo` is required and positional: this op has no default repository and
        answers `error_message("repository not found")` without one -- verified
        live.

        `scan_follow` is the live form. This one asks for the snapshot and the
        node closes the stream after it.
        """
        params: dict[str, Any] = {"repo": _repo(repo, OP_SCAN), "follow": False}
        _scope(zone, params, kw)
        qs = querystring.build(OP_SCAN, _encode(params))
        return [
            self._expect(obj, ObjectID, OP_SCAN) for obj in await self._c.call(qs, **kw)
        ]

    def scan_follow(
        self, repo: str, *, zone: Zone | int | str | None = None, **kw: Any
    ) -> StreamContext:
        """`async with objects.scan_follow(repo) as s:` -- ST + follow.

        The snapshot, then the `eos` separator, then every id the repository
        gains while the stream is open. `Stream.snapshot()`, `live()` and
        `follow()` are the three readers; `async for` is **not** one of them --
        it stops at the separator and drops every live object in silence, so the
        stream refuses it rather than doing that. `Client.follow()` declares
        `separator=True`, which is what makes the refusal possible.

        **Named `scan_follow`, not `follow_scan`.** One convention for the follow
        form of an op, `<op>_follow`, shared with `discover_follow`,
        `sync_follow` and `get_follow`. The prefix form put the word that names
        the *shape* where a reader looks for the word that names the *op*.

        Opened on the persistent lane with no deadline, which is what
        `Client.follow` does for every follow-mode op: a stream that never ends
        must not hold a query permit and must not die of idleness.

        **Drain it and close it.** A follow stream left open holds one of the
        node's 32 workers until the node restarts.
        """
        params: dict[str, Any] = {"repo": _repo(repo, OP_SCAN), "follow": True}
        _scope(zone, params, kw)
        return self._c.follow(querystring.build(OP_SCAN, _encode(params)), **kw)

    async def contains(self, repo: str, id: ObjectID | str, **kw: Any) -> bool:  # noqa: A002
        """Whether a repository holds an object. RR.

        `repo` is required and positional: no default, verified live -- omitting
        it answers `error_message("repository not found")`.

        astrald's own doc line calls the answer probabilistic; the implementation
        is a repository lookup and the answer is exact for a local repository.
        Absent from astral-go entirely.
        """
        params = {
            "repo": _repo(repo, OP_CONTAINS),
            "id": _object_id(id, OP_CONTAINS),
        }
        qs = querystring.build(OP_CONTAINS, _encode(params))
        return bool(self._expect(await self._c.call_one(qs, **kw), Bool, OP_CONTAINS))

    async def contains_many(
        self, repo: str, ids: Iterable[ObjectID | str], **kw: Any
    ) -> list[bool]:
        """Whether a repository holds each of many objects. BD, one query.

        The ids travel on the **channel body**, one `object_id.sha256` per
        object, and the node answers one `bool` each. Passing them as a query
        argument instead is the single most common way to get an op wrong
        (design section 4.7).

        No `eos` is sent: astrald's handler ignores it and keeps reading, so what
        ends this op is the stream closing. Verified live -- after `send_eos()`
        the node answered nothing further and the stream stayed open.
        """
        objects = [_object_id(i, OP_CONTAINS) for i in ids]
        qs = querystring.build(OP_CONTAINS, _encode({"repo": _repo(repo, OP_CONTAINS)}))
        answers = await self._exchange(qs, objects, kw, eos=False)
        return [
            bool(_typed(obj, Bool, OP_CONTAINS, index, self._c.endpoint))
            for index, obj in enumerate(answers)
        ]

    # --- reading ---

    async def probe(
        self, id: ObjectID | str, *, repo: str | None = None, **kw: Any  # noqa: A002
    ) -> Probe:
        """An object's type, repository, mime type and probe cost. RR.

        The replacement for `get_type`, which is deprecated. `repo` defaults to
        the node's read-default repository.
        """
        params: dict[str, Any] = {"id": _object_id(id, OP_PROBE)}
        if repo is not None:
            params["repo"] = _repo(repo, OP_PROBE)
        qs = querystring.build(OP_PROBE, _encode(params))
        return self._expect(await self._c.call_one(qs, **kw), Probe, OP_PROBE)

    async def probe_many(
        self, ids: Iterable[ObjectID | str], *, repo: str | None = None, **kw: Any
    ) -> list[Probe]:
        """Probe many objects over one query. BD.

        The ids travel on the channel body. astrald closes the channel on the
        `eos`, so the terminator is sent here and the op ends on it rather than
        on the close.
        """
        objects = [_object_id(i, OP_PROBE) for i in ids]
        params: dict[str, Any] = {}
        if repo is not None:
            params["repo"] = _repo(repo, OP_PROBE)
        qs = querystring.build(OP_PROBE, _encode(params))
        answers = await self._exchange(qs, objects, kw, eos=True)
        return [
            _typed(obj, Probe, OP_PROBE, index, self._c.endpoint)
            for index, obj in enumerate(answers)
        ]

    async def get_type(self, id: ObjectID | str, **kw: Any) -> str:  # noqa: A002
        """An object's astral type name. RR. **Deprecated -- use `probe`.**

        An object the node cannot type answers `error_message("unknown type")`,
        which surfaces as `RemoteError` and says nothing about why. `probe`
        answers the same question with the repository and the mime type beside
        it, which is why astrald marks this one deprecated.
        """
        qs = querystring.build(
            OP_GET_TYPE, _encode({"id": _object_id(id, OP_GET_TYPE)})
        )
        return str(self._expect(await self._c.call_one(qs, **kw), String8, OP_GET_TYPE))

    async def load(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        repo: str | None = None,
        zone: Zone | int | str | None = None,
        unparsed: bool = False,
        **kw: Any,
    ) -> Any:
        """Decode an object into memory and return it. RR.

        The node reads the whole object, verifies its hash, decodes it through
        its own registry and sends the typed object; an object with no astral
        stamp comes back as a `Blob`. A type this SDK does not know raises
        `BlueprintNotFound` on decode -- `learn()` is how to teach it one.

        `unparsed` is sent faithfully and **changes nothing on this form**: it
        configures the op's channel receiver, which only the streamed-id form
        reads. See the module docstring.

        Absent from astral-go entirely.
        """
        params: dict[str, Any] = {"id": _object_id(id, OP_LOAD)}
        if repo is not None:
            params["repo"] = _repo(repo, OP_LOAD)
        if unparsed:
            params["unparsed"] = True
        _scope(zone, params, kw)
        qs = querystring.build(OP_LOAD, _encode(params))
        return await self._c.call_one(qs, **kw)

    async def load_many(
        self,
        ids: Iterable[ObjectID | str],
        *,
        repo: str | None = None,
        zone: Zone | int | str | None = None,
        unparsed: bool = False,
        **kw: Any,
    ) -> list[Any]:
        """Load many objects over one query. BD.

        The ids travel on the channel body. astrald ignores the `eos` here, so
        none is sent and the stream closing is what ends the op.
        """
        objects = [_object_id(i, OP_LOAD) for i in ids]
        params: dict[str, Any] = {}
        if repo is not None:
            params["repo"] = _repo(repo, OP_LOAD)
        if unparsed:
            params["unparsed"] = True
        _scope(zone, params, kw)
        qs = querystring.build(OP_LOAD, _encode(params))
        answers = await self._exchange(qs, objects, kw, eos=False)
        return [
            _typed(obj, None, OP_LOAD, index, self._c.endpoint)
            for index, obj in enumerate(answers)
        ]

    async def read(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        offset: int = 0,
        limit: int | None = None,
        repo: str | None = None,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> bytes:
        """An object's bytes. **RAW** -- the response carries no object framing.

        The only RAW op in the SDK. What comes back is what is stored: an astral
        object reads back in its canonical form, stamp and type header included,
        and a blob reads back as itself. Verified live.

        `limit` omitted reads to the end of the object. **`limit=0` also reads to
        the end** -- that is astrald's spelling of "no limit" -- so it is refused
        here rather than sent as a request for nothing.

        The whole body is buffered. `open_read` is the streaming form and is what
        an object larger than memory needs.

        Denial is a **query rejection**, not an `error_message`: the op submits a
        `mod.objects.read_object_action` and calls `q.Reject()` when it is
        refused, so a denied read raises `QueryRejected`. astral-go's client
        hardcodes `zone=dvn`; this one sends what the caller asked for and
        nothing else.
        """
        qs = self._read_query(id, offset, limit, repo, zone, kw)
        return await self._c.call_raw(qs, **kw)

    def open_read(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        offset: int = 0,
        limit: int | None = None,
        repo: str | None = None,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> StreamContext:
        """`async with objects.open_read(id) as s:` -- the streaming RAW read.

        `Stream.read_bytes(n)` walks the body in bounded pieces, so an object
        larger than memory is a loop rather than an allocation. `read()` is the
        whole-body form.
        """
        kw.setdefault("raw", True)
        return self._c.stream(
            self._read_query(id, offset, limit, repo, zone, kw), **kw
        )

    def _read_query(
        self,
        id: ObjectID | str,  # noqa: A002
        offset: int,
        limit: int | None,
        repo: str | None,
        zone: Zone | int | str | None,
        kw: dict[str, Any],
    ) -> str:
        """The `objects.read` query string, built once for both read forms."""
        params: dict[str, Any] = {"id": _object_id(id, OP_READ)}
        if offset:
            params["offset"] = int(offset)
        if limit is not None:
            if limit <= 0:
                raise BadArgument(
                    f"{OP_READ}: limit={limit} is the node's spelling of no limit; "
                    "omit it to read to the end"
                )
            params["limit"] = int(limit)
        if repo is not None:
            params["repo"] = _repo(repo, OP_READ)
        _scope(zone, params, kw)
        return querystring.build(OP_READ, _encode(params))

    # --- description, discovery, search ---

    async def describe(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        only: str | Sequence[str] | None = None,
        except_: str | Sequence[str] | None = None,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> list[Descriptor]:
        """Every descriptor the node's describers have for an object. ST.

        `only` and `except_` filter by descriptor type name, server-side. The
        wire keys are `only` and `except`; `except` is a Python keyword, so the
        parameter carries the trailing underscore PEP 8 reserves for exactly
        this, and the key on the wire is unchanged.

        Ends at an `eos`, and a **bare `eos` is the ordinary answer** on a node
        with no describers registered -- verified live for each of the three
        objects `furry-bolt` holds in its default repository. The op is bounded
        to one minute server-side.
        """
        params: dict[str, Any] = {"id": _object_id(id, OP_DESCRIBE)}
        names = _name_list(only, "only", OP_DESCRIBE)
        if names is not None:
            params["only"] = names
        names = _name_list(except_, "except", OP_DESCRIBE)
        if names is not None:
            params["except"] = names
        _scope(zone, params, kw)
        qs = querystring.build(OP_DESCRIBE, _encode(params))
        return [
            self._expect(obj, Descriptor, OP_DESCRIBE)
            for obj in await self._c.call(qs, **kw)
        ]

    async def find(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> list[Identity]:
        """The identities that can provide an object. ST, deduplicated.

        Ends at an `eos`; a bare `eos` means nobody offered, which is the
        ordinary answer on a node with no finders -- verified live. Bounded to
        one minute server-side.

        `id` is positional and required. astrald answers a zero or absent one
        with `error_message("id is required")` rather than rejecting the query,
        so the fault would otherwise arrive as a `RemoteError` naming an argument
        the caller thought they had passed.
        """
        params: dict[str, Any] = {"id": _object_id(id, OP_FIND)}
        _scope(zone, params, kw)
        qs = querystring.build(OP_FIND, _encode(params))
        return [
            self._expect(obj, Identity, OP_FIND) for obj in await self._c.call(qs, **kw)
        ]

    async def search(
        self,
        query: str | SearchQuery,
        *,
        repo: str | None = None,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> list[SearchResult]:
        """Search every registered searcher. ST, deduplicated by object id.

        `query` is a search string in the grammar `SearchQuery` documents, or a
        `SearchQuery`, which is rendered to that grammar: the node parses the
        string itself and the parsed form never travels.

        `repo` filters the results to objects that repository contains; it does
        not scope the search. Bounded to one minute server-side. A node with no
        searchers answers a bare `eos` -- verified live.
        """
        text = query.text() if isinstance(query, SearchQuery) else query
        if not isinstance(text, str):
            raise BadArgumentType(
                f"{OP_SEARCH}: expected a search string or a SearchQuery, got "
                f"{type(query).__name__}"
            )
        params: dict[str, Any] = {"q": text}
        if repo is not None:
            params["repo"] = _repo(repo, OP_SEARCH)
        _scope(zone, params, kw)
        qs = querystring.build(OP_SEARCH, _encode(params))
        return [
            self._expect(obj, SearchResult, OP_SEARCH)
            for obj in await self._c.call(qs, **kw)
        ]

    # --- the type registry ---

    async def blueprints(self, **kw: Any) -> list[str]:
        """Every type name the node can decode, in dependency order. ST.

        153 names on `furry-bolt` this session, more than this SDK declares.
        Names only: `get_blueprint` fetches one type's schema and `learn`
        fetches a schema's closure.

        **`get_blueprint` cannot describe every name here.** astral-go's
        reflector answered 97 of the 134 non-primitive names and refused 37 --
        see `get_blueprint`. So this list is what the node can *decode*, not what
        it can *describe*, and the two are different sets.
        """
        return [
            str(self._expect(obj, String8, OP_BLUEPRINTS))
            for obj in await self._c.call(OP_BLUEPRINTS, **kw)
        ]

    async def get_blueprint(self, type_name: str, **kw: Any) -> Blueprint:
        """One type's schema, as an `astral.blueprint`. RR, no `eos`.

        **Referenced types are not included.** astrald sends the one blueprint
        and leaves its references to the caller, so registering the answer
        directly fails closure whenever it names a type the registry lacks.
        `learn` is the form that walks the references first.

        A primitive answers `error_message("primitive type has no blueprint: …")`
        and an unknown name `blueprint not found: …`; both surface as
        `RemoteError`. Both verified live.

        **A registered type is not necessarily a describable one.** astral-go's
        `BlueprintFromType` refuses any struct holding a plain Go scalar, a
        value-embedded non-`Object` struct, or a primitive newtype that does not
        implement `PrimitiveAlias`. Swept live over `furry-bolt`: 97 of the 134
        non-primitive registered names answered and 37 refused, including this
        module's own `mod.objects.read_object_action` and
        `mod.objects.create_object_action`, both of which embed `auth.Action`.
        The refusal is an `error_message`, so it arrives as `RemoteError` and
        never as a wrong schema.

        Design bug G-21 said this op does not exist. It does, on the live
        registry; it is missing only from astral-go's method constants.
        """
        qs = querystring.build(
            OP_GET_BLUEPRINT, _encode({"type": _type_name(type_name, OP_GET_BLUEPRINT)})
        )
        blueprint = self._expect(
            await self._c.call_one(qs, **kw), Blueprint, OP_GET_BLUEPRINT
        )
        if blueprint.type != type_name:
            raise ProtocolError(
                f"{OP_GET_BLUEPRINT}: asked for {type_name!r}, got "
                f"{blueprint.type!r}"
            )
        return blueprint

    async def learn(
        self,
        type_name: str,
        *,
        registry: Blueprints | None = None,
        **kw: Any,
    ) -> Blueprint:
        """Fetch a type's schema and its whole closure, and register it.

        This is what makes a `RuntimeRecord` of a type the SDK was never built
        against: every field of the fetched blueprint whose spec names another
        type is learned first, so `Blueprints.register_blueprint`'s closure rule
        is satisfied by construction rather than by luck.

        Already-registered names cost no query and are returned from the
        registry, so calling this in a loop over `blueprints()` fetches each type
        once. A primitive is refused locally with the same reason the node gives.

        A reference cycle raises `CycleDetected` rather than recursing: astral-go
        stack-overflows on a mutually recursive pair (bug G-22) and this is the
        path that would reach it.

        A type the node cannot describe raises `RemoteError` from
        `get_blueprint`, and so does one of its references -- a partial closure
        is left registered, because registration is per type and the node offers
        no transaction.

        `registry` defaults to the process registry, so what is learned is what
        every later decode can read. Pass a child `Blueprints` to keep a peer's
        schema out of the process-wide one.
        """
        target = default_blueprints() if registry is None else registry
        return await self._learn(type_name, target, set(), kw)

    async def _learn(
        self,
        type_name: str,
        registry: Blueprints,
        pending: set[str],
        kw: dict[str, Any],
    ) -> Blueprint:
        if type_name in PRIMITIVE_TYPES:
            raise BadArgument(
                f"{OP_GET_BLUEPRINT}: {type_name!r} is a primitive type and has "
                "no blueprint"
            )
        existing = registry.find(type_name)
        if existing is not None:
            return (
                existing.clone()
                if isinstance(existing, Blueprint)
                else blueprint_of(existing)
            )
        if type_name in pending:
            raise CycleDetected(
                f"{OP_GET_BLUEPRINT}: {type_name!r} references itself through "
                f"{sorted(pending)}"
            )
        pending.add(type_name)
        try:
            blueprint = await self.get_blueprint(type_name, **kw)
            for field in blueprint.fields:
                reference = referenced_type(spec_of(field.spec))
                if reference and not registry.has(reference):
                    await self._learn(reference, registry, pending, kw)
            registry.register_blueprint(blueprint.bound_to(registry))
        finally:
            pending.discard(type_name)
        return blueprint

    async def new(self, type_name: str, **kw: Any) -> Any:
        """A zero value of a registered type, built by the node. RR.

        A name the node does not know answers `nil` rather than an error --
        verified live for `no.such.type` -- so `Nil()` is a legitimate answer and
        is returned as one. A primitive name answers that primitive's zero value.

        **`mod.nodes.node_info` is refused rather than sent**: the query panics
        astrald deterministically (see `CRASHES_ON_NEW`). Sweeping this op over
        `blueprints()` is therefore not safe on any node running an astral-go
        without the unmerged fix.

        Absent from astral-go entirely.
        """
        name = _type_name(type_name, OP_NEW)
        if name in CRASHES_ON_NEW:
            raise BadArgument(
                f"{OP_NEW}: {name!r} crashes the node -- its zero value has a nil "
                "*Identity and a value-receiver WriteTo, so serialising it "
                "dereferences nil. The fix is not merged"
            )
        qs = querystring.build(OP_NEW, _encode({"type": name}))
        return await self._c.call_one(qs, **kw)

    async def register_blueprint(
        self, *blueprints: Blueprint, **kw: Any
    ) -> list[ObjectID]:
        """Register runtime schemas on the node. BD. **Mutates the registry.**

        The blueprints travel on the **channel body**, one per input, and the
        node answers one `object_id.sha256` each -- the ObjectID of the
        blueprint's own canonical form -- then a final `eos`.

        **The terminating `eos` is sent** (design bug G-10: astral-go's client
        never sends it, so the op's read loop waits for input that never ends and
        the exchange finishes only when the connection dies).

        An input the node refuses -- a name already registered, a reference it
        cannot resolve -- raises `RemoteError` naming which input failed. The
        registration is not transactional: inputs before the failure are already
        registered on the node.

        astrald gates this on nothing at all. Its own source carries the note:
        any peer can squat a type name and define its wire schema.
        """
        for index, blueprint in enumerate(blueprints):
            if not isinstance(blueprint, Blueprint):
                raise BadArgumentType(
                    f"{OP_REGISTER_BLUEPRINT}: input {index}: expected an "
                    f"astral.blueprint, got {type(blueprint).__name__}"
                )
        answers = await self._exchange(
            OP_REGISTER_BLUEPRINT, list(blueprints), kw, eos=True
        )
        return [
            _typed(obj, ObjectID, OP_REGISTER_BLUEPRINT, index, self._c.endpoint)
            for index, obj in enumerate(answers)
        ]

    # --- writing ---

    def create(
        self,
        *,
        repo: str | None = None,
        alloc: int | None = None,
        ack_timeout: float | None = 30.0,
        **kw: Any,
    ) -> WriterContext:
        """`async with objects.create() as w:` -- a new object. **Mutates.**

        The node answers `ack`, then reads `blob` frames until
        `mod.objects.commit_msg` arrives. `Writer.commit()` sends that and
        returns the new object's ID; `Writer.discard()`, or the scope ending
        without either, throws the data away.

        **The scope is the enforcement.** A `Writer` exists only inside this
        context manager, and leaving it uncommitted and undiscarded raises rather
        than losing the data quietly -- see `Writer`.

        `alloc` is a size hint for the repository, in bytes; omitted, the
        repository decides. `repo` defaults to the node's write-default.

        `ack_timeout` bounds the `ack` alone, which is a different thing from
        `timeout`: `timeout` covers the route, and this covers an op that was
        **accepted and then said nothing** -- the state the wire reaches whenever
        the op goroutine stalls between `q.AcceptRaw()` and its first send.
        """
        params: dict[str, Any] = {}
        if repo is not None:
            params["repo"] = _repo(repo, OP_CREATE)
        if alloc is not None:
            if alloc < 0:
                raise BadArgument(f"{OP_CREATE}: alloc={alloc} is negative")
            params["alloc"] = int(alloc)
        return WriterContext(
            self._c, querystring.build(OP_CREATE, _encode(params)), kw, ack_timeout
        )

    async def store(
        self, *objects: Any, repo: str | None = None, **kw: Any
    ) -> list[ObjectID]:
        """Store whole objects, one query for all of them. BD. **Mutates.**

        The objects travel on the **channel body** and the node answers one
        `object_id.sha256` each. The node encodes each one in its canonical form
        before storing, so the ID is the canonical ID and `create` + `write` of
        the same bytes yields a different one.

        **The terminating `eos` is sent** (G-10). astral-go's client sends one
        object, never terminates, and relies on the connection closing.

        `repo` defaults to the node's write-default.
        """
        params: dict[str, Any] = {}
        if repo is not None:
            params["repo"] = _repo(repo, OP_STORE)
        qs = querystring.build(OP_STORE, _encode(params))
        answers = await self._exchange(qs, list(objects), kw, eos=True)
        return [
            _typed(obj, ObjectID, OP_STORE, index, self._c.endpoint)
            for index, obj in enumerate(answers)
        ]

    async def push(self, *objects: Any, **kw: Any) -> list[bool]:
        """Offer objects to the node's registered receivers. BD. **Mutates.**

        The objects travel on the channel body and the node answers one `bool`
        each: whether **any** receiver accepted it. A node with no receiver
        registered for a type answers `False` for every object, which is the
        ordinary outcome and not an error.

        Each object's **payload** is checked against `MAX_PUSH_SIZE` before it is
        sent. astrald declares that cap and does not enforce it -- `maxPushSize`
        is referenced nowhere in the module -- so the number is documentation
        until it is not, and relying on an unenforced remote limit is how a
        client breaks the day it is enforced.
        """
        for index, obj in enumerate(objects):
            size = len(payload_bytes(obj))
            if size > MAX_PUSH_SIZE:
                raise BadArgument(
                    f"{OP_PUSH}: input {index}: {size} bytes passes the "
                    f"documented {MAX_PUSH_SIZE}-byte limit"
                )
        answers = await self._exchange(OP_PUSH, list(objects), kw, eos=True)
        return [
            bool(_typed(obj, Bool, OP_PUSH, index, self._c.endpoint))
            for index, obj in enumerate(answers)
        ]

    async def delete(
        self,
        repo: str,
        id: ObjectID | str,  # noqa: A002
        *,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> None:
        """Delete one object from a repository. RR. **Mutates.**

        `repo` is required and positional, and astrald says why in its own
        source: there is no default "to avoid accidental deletion".
        """
        params: dict[str, Any] = {
            "repo": _repo(repo, OP_DELETE),
            "id": _object_id(id, OP_DELETE),
        }
        _scope(zone, params, kw)
        qs = querystring.build(OP_DELETE, _encode(params))
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_DELETE)

    async def delete_many(
        self,
        repo: str,
        ids: Iterable[ObjectID | str],
        *,
        zone: Zone | int | str | None = None,
        **kw: Any,
    ) -> None:
        """Delete many objects over one query. BD. **Mutates.**

        The ids travel on the channel body and the node answers one `ack` each.
        astrald ignores the `eos` here, so none is sent and the stream closing is
        what ends the op.
        """
        objects = [_object_id(i, OP_DELETE) for i in ids]
        params: dict[str, Any] = {"repo": _repo(repo, OP_DELETE)}
        _scope(zone, params, kw)
        qs = querystring.build(OP_DELETE, _encode(params))
        answers = await self._exchange(qs, objects, kw, eos=False)
        for index, obj in enumerate(answers):
            _typed(obj, Ack, OP_DELETE, index, self._c.endpoint)

    async def purge(
        self, repo: str, *, zone: Zone | int | str | None = None, **kw: Any
    ) -> list[ObjectID]:
        """Delete every unheld object in a repository. ST. **Deletes data.**

        Returns the ids that were purged, in the order the node freed them:
        oldest-read-first, skipping anything a holder keeps alive. `repo` is
        required and positional -- there is no default.
        """
        params: dict[str, Any] = {"repo": _repo(repo, OP_PURGE)}
        _scope(zone, params, kw)
        qs = querystring.build(OP_PURGE, _encode(params))
        return [
            self._expect(obj, ObjectID, OP_PURGE) for obj in await self._c.call(qs, **kw)
        ]

    # --- external providers ---

    async def register_searcher(self, **kw: Any) -> None:
        """Register this identity as an external searcher. RR. **Mutates.**

        Design section 4.6: the registration is **not** channel-scoped. The op
        answers one `ack` and this closes the channel; the node keeps the
        registration and sends an ordinary `objects.search` query to this
        identity whenever it searches. The app serves that query on its own
        inbound handler, which is `astral.serve`'s business, and re-registers
        after every reconnect, which is `astral.registrar`'s.

        Local-only: a network-origin query is rejected outright. The caller must
        have a **non-zero identity that is not the node's own**, so an anonymous
        guest -- for whom the router substitutes the node's identity -- answers
        `error_message` rather than registering.
        """
        self._expect(
            await self._c.call_one(OP_REGISTER_SEARCHER, **kw),
            Ack,
            OP_REGISTER_SEARCHER,
        )

    async def register_describer(self, **kw: Any) -> None:
        """Register this identity as an external describer. RR. **Mutates.**

        The mirror of `register_searcher`; the node sends `objects.describe`
        queries with an `id` argument, and the app answers with
        `mod.objects.describe_result` objects and an `eos`.
        """
        self._expect(
            await self._c.call_one(OP_REGISTER_DESCRIBER, **kw),
            Ack,
            OP_REGISTER_DESCRIBER,
        )

    async def register_finder(self, **kw: Any) -> None:
        """Register this identity as an external finder. RR. **Mutates.**

        The node sends `objects.find` queries with an `id` argument, and the app
        answers with `identity` objects and an `eos`.
        """
        self._expect(
            await self._c.call_one(OP_REGISTER_FINDER, **kw), Ack, OP_REGISTER_FINDER
        )

    # --- debugging ---

    def echo(
        self,
        *,
        only: str | Sequence[str] | None = None,
        except_: str | Sequence[str] | None = None,
        stop: str | None = None,
        strict: bool = False,
        **kw: Any,
    ) -> StreamContext:
        """`async with objects.echo() as s:` -- objects back as they were sent. BD.

        The node's wire-schema conformance tool: send an object, read the same
        object back. A round trip through it proves the SDK and the node agree on
        a type's bytes, which is why it is the only debug op in this module.

        `strict` drops the node's unparsed fallback, so an object whose blueprint
        the node does not know comes back as an `error_message` instead of being
        relayed untouched. `stop` names a type that ends the exchange, and the
        `eos` is echoed rather than treated as a terminator unless `stop` names
        it -- verified live.

        Read-only: nothing is stored and nothing is registered.
        """
        params: dict[str, Any] = {}
        names = _name_list(only, "only", OP_ECHO)
        if names is not None:
            params["only"] = names
        names = _name_list(except_, "except", OP_ECHO)
        if names is not None:
            params["except"] = names
        if stop is not None:
            params["stop"] = _type_name(stop, OP_ECHO)
        if strict:
            params["strict"] = True
        return self._c.stream(querystring.build(OP_ECHO, _encode(params)), **kw)

    # --- the shared body-input path ---

    async def _exchange(
        self,
        qs: str,
        inputs: Sequence[Any],
        kw: dict[str, Any],
        *,
        eos: bool,
    ) -> list[Any]:
        """Send objects on the body and read one answer each. The BD batch path.

        One send then one read, never the whole batch then the answers: each of
        these ops answers per input as it goes, so filling the socket with
        requests nobody is reading is a deadlock whose size is the batch's.

        `eos` is declared per call and never inferred, because the seven ops that
        read their input this way terminate four different ways (see the module
        docstring). `Client.call_with` covers the shapes whose answers are read
        to the stream's end; this one reads a fixed count and names the input an
        `error_message` belongs to, which is what makes a failed store or a
        refused blueprint say which one.

        The budget is `Client`'s own one-shot budget, so an op that accepts and
        then says nothing costs `timeout` and not the rest of the process's life.
        A deadline reached here is reported as `QueryTimeout` and not as the bare
        `TimeoutError` `asyncio.timeout` raises, which sits outside `AstralError`
        and would escape the catch-all every docstring in this SDK promises.
        """
        if not inputs:
            return []
        async with self._one_shot(qs, kw) as (stream, budget):
            answers: list[Any] = []
            objects = stream.raw_objects()
            try:
                for obj in inputs:
                    await stream.send(obj, timeout=budget.remaining)
                    # Read before the wait, so the message states the deadline
                    # that expired rather than the nothing left of it.
                    remaining = budget.remaining
                    try:
                        async with asyncio.timeout(remaining):
                            answer = await anext(objects, None)
                    except TimeoutError as exc:
                        raise QueryTimeout(
                            f"{qs}: input {len(answers)} was not answered within "
                            f"{remaining}s"
                        ) from exc
                    if answer is None:
                        raise ProtocolError(
                            f"{qs}: the stream ended after {len(answers)} of "
                            f"{len(inputs)} answers"
                        )
                    answers.append(answer)
                if eos:
                    await stream.send_eos(timeout=budget.remaining)
            finally:
                with contextlib.suppress(Exception):
                    await objects.aclose()
        return answers


OBJECTS_TYPES: Final[Sequence[type]] = (
    # The eight spec carriers first, then the blueprint that references them, so
    # the sweep reads in dependency order even though `Blueprints.add` does not
    # require one.
    PrimitiveSpec,
    RefSpec,
    SliceSpec,
    ArraySpec,
    MapSpec,
    PtrSpec,
    ObjectSpec,
    BlueprintField,
    Blueprint,
    CommitMsg,
    CreateObjectAction,
    Descriptor,
    Probe,
    QueryTag,
    ReadObjectAction,
    RepositoryInfo,
    SearchQuery,
    SearchResult,
)
"""Every wire type this module declares or re-exports, for a registry sweep.

The nine `astral.blueprint` types are re-exported rather than declared: they are
`astral.blueprint`'s own records, this module is the only one that exchanges them
-- `get_blueprint` answers with one and `register_blueprint` sends them -- and
naming the whole set here is what makes `registry.add(*Objects.TYPES)` produce a
registry that can decode this module's answers. Naming `astral.blueprint` alone
would not: its `Fields` slot references `astral.blueprint.field`, which
references the seven carriers through a polymorphic slot.

`mod.objects.commit_msg`, `mod.objects.read_object_action` and
`mod.objects.create_object_action` are declared here even though no op answers
with one: the first is sent, and the two actions name themselves inside a
`mod.auth.permit` and inside an authorization bundle.
"""

Objects.TYPES = OBJECTS_TYPES
