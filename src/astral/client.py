"""`Client`: the facade every caller and every module client goes through.

One `Client` is a *budget*, not a connection. There is no multiplexing on the
apphost IPC leg by design (design section 3.7): the moment a query is accepted
the socket stops being a message channel and becomes that query's raw
bytestream, so one connection carries at most one accepted query and concurrency
means more connections. `Client` therefore holds no idle connection of its own,
opens a fresh one per query, and bounds how many it may hold at once.

**The bound is a correctness requirement, not a performance knob.** astrald's
apphost module runs a fixed pool of 32 workers pulling from an unbuffered
channel, with `NewGuest(conn).Serve(ctx)` run synchronously per connection and no
read deadline anywhere in it. So the node serves at most 32 apphost connections
across *every* local app; a saturated pool accepts new sockets at the OS layer
and never greets them, which a client sees as a connect that succeeds followed
by silence; and a connection left open -- leaked or merely idle -- holds one
worker exactly as a busy one does, until the node restarts. Thirty-two of those
and every app on the machine is dead. It has been observed, it is astrald bug
G-13, and it is why `max_concurrency` defaults to **8**: a shared-resource budget
with room for three other apps to be equally wrong.

Everything else here follows from that:

- `CONNECT_TIMEOUT` covers the greeting and not merely the TCP connect, so a
  saturated node surfaces as `NodeUnavailable` in five seconds rather than as an
  infinite hang.
- Every stream is an async context manager, `aclose()` is idempotent and never
  raises, and there is no `__del__` fallback.
- The permit is released after the descriptor is gone, never before, so a client
  bounded at N never holds N+1 connections.
- Long-lived streams -- `apphost.bind`, any `follow=true` op, the registrar's
  bind channel -- are opened on a **second lane** (`persistent=True`) that spends
  none of the query budget, because a budget of 8 held forever by 8 follow
  streams is a client that has deadlocked itself. That lane is bounded too, at
  `max_persistent`: an unbounded escape hatch on the most-used method of the
  facade is not a budget, and a client must be able to state its worst case,
  which is `max_concurrency + max_persistent` and stays well under 32.
- The bound queues rather than fails, in FIFO order, and the wait is inside the
  caller's own `timeout` so it cannot become an unbounded stall. A caller that
  runs out of budget is told which half of the deadline consumed it.
- **`aclose()` returning means closed**, which costs more than it looks: the walk
  cannot be abandoned half-done and then latch `closed`, the streams close
  concurrently so a bounded shutdown is one `CLOSE_TIMEOUT` rather than N of
  them, and a query already queued on the semaphore is failed rather than fed --
  a client that reported itself shut down and then dialed the node once per
  queued query is the worker pool's worst caller.

**Nothing here infers an op's shape.** The op-mode taxonomy of design section 4.7
is four-way plus RAW and is *not* discoverable from the wire: request/response
ending at a bare EOF, server-streaming terminated by `eos`, bidirectional, and
unframed bytes. `apphost.whoami` sends one `identity` and closes with no `eos`,
`dir.alias_map` sends one map and closes, `.spec` sends 118 objects and then an
`eos`, and `objects.read` sends no objects at all (astral-docs bug D-23). So
`call`, `call_one`, `call_raw`, `follow` and `call_with` are five different
declarations of shape and never five guesses at one, and every one of them
terminates on `eos` **or** EOF. Nothing in this module ever waits for an `eos`.

**A helper that owns the stream owns its deadline.** `timeout` on `query()`
covers the route and nothing after it, which is right for a method that hands the
stream back: how long a stream stays open is the op's business and the caller's.
It is wrong for `call`, `call_one`, `call_raw` and `call_with`, which close the
stream themselves and so leave the caller nothing to wrap in `asyncio.timeout`.
Those spend **one** budget across the route and the answer, so `call(qs,
timeout=T)` cannot exceed T end to end and a node that accepts and then says
nothing costs T rather than the rest of the process's life.

**Endpoint and token resolution** is design section 3.3, in one place so the CLI
and the library agree byte for byte::

    endpoint:  the argument, else ASTRAL_ENDPOINT, else ASTRALD_ENDPOINT,
               else unix:~/.apphost.sock when that socket exists,
               else tcp:127.0.0.1:8625
    token:     the argument, else the first non-empty of
               ASTRALD_APPHOST_TOKEN, ASTRALD_TOKEN, ASTRAL_AUTH_TOKEN,
               ASTRAL_TOKEN

The unix socket is preferred because it is cheaper and because the node's TCP
listener is the one that wedges.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
from types import TracebackType
from typing import TYPE_CHECKING, Any, AsyncIterator, Final, Sequence

from . import querystring
from .channel import Format, parse_format
from .context import Context
from .errors import (
    BadArgument,
    ClientClosed,
    Denied,
    ProtocolError,
    QueryTimeout,
    TransportUnsupported,
)
from .registry import Blueprints
from .session import (
    _DEFAULT,
    CANCEL_TIMEOUT,
    CONNECT_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    QUERY_TIMEOUT,
    Connector,
    Session,
    _Default,
    flush_cancels,
)
from .stream import Stream
from .types import Identity, Nonce, Zone
from .wire import DEFAULT_MAX_ALLOC

if TYPE_CHECKING:  # pragma: no cover -- typing only
    from .api.apphost import Apphost
    from .api.auth import Auth
    from .api.crypto import Crypto
    from .api.dir import Dir
    from .api.objects import Objects
    from .api.services import Services
    from .api.tree import Tree
    from .serve import Handler, Service

__all__ = [
    "CANCEL_FLUSH_TIMEOUT",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_MAX_PERSISTENT",
    "ENDPOINT_VARS",
    "OP_RESOLVE",
    "TOKEN_VARS",
    "Client",
    "StreamContext",
    "connect",
    "resolve_endpoint",
    "resolve_token",
]

DEFAULT_MAX_CONCURRENCY: Final = 8
"""Concurrent connections one client may hold. Well under astrald's 32 workers,
because that pool is shared with every other app on the machine (bug G-13)."""

DEFAULT_MAX_PERSISTENT: Final = 4
"""Long-lived connections one client may hold outside the query budget.

The persistent lane exists because a follow stream or a bind channel held for the
process's lifetime would otherwise never give its permit back. That is a reason
to bill it separately, not a reason to leave it unbounded: a client configured
`max_concurrency=1` could open forty connections through `persistent=True` and
outnumber the node's whole worker pool. Four plus the default eight is twelve,
which leaves room for two more equally wrong apps.
"""

ENDPOINT_VARS: Final = ("ASTRAL_ENDPOINT", "ASTRALD_ENDPOINT")
TOKEN_VARS: Final = (
    "ASTRALD_APPHOST_TOKEN",
    "ASTRALD_TOKEN",
    "ASTRAL_AUTH_TOKEN",
    "ASTRAL_TOKEN",
)

CANCEL_FLUSH_TIMEOUT: Final = CANCEL_TIMEOUT + 1.0
"""How long `aclose()` waits for best-effort cancels dialed during teardown.

Each is already bounded by `CANCEL_TIMEOUT` inside `cancel_query`, so this is a
backstop against a cancel task that cannot be scheduled at all, not a second
deadline on the dial. Abandoning one would leave a half-open connection to the
node -- one burned worker -- which is the whole reason the flush exists.
"""

OP_RESOLVE: Final = "dir.resolve"

_HEX: Final = frozenset("0123456789abcdefABCDEF")

# `_DEFAULT` is the session's sentinel, imported rather than redefined. It marks
# "not given", so `None` can keep its own meanings -- no deadline, the nil
# identity -- and those arguments are passed straight through to
# `Session.route_query`, which tests them with `isinstance`. A second class of
# the same name and meaning would fail that test and be parsed as an identity.


# --- environment ---------------------------------------------------------


def resolve_endpoint(endpoint: str | None = None) -> str:
    """The endpoint to dial: the argument, then the environment, then the default.

    Shared with the CLI so a script and a library call reach the same node.
    An empty environment variable is not a setting and is skipped.
    """
    if endpoint:
        return endpoint
    for name in ENDPOINT_VARS:
        value = os.environ.get(name)
        if value:
            return value
    from .transport import default_endpoint

    return default_endpoint()


def resolve_token(token: str | None = None) -> str | None:
    """The auth token: the argument, then the first non-empty variable.

    `None` means anonymous, which the node allows by default for routing and
    refuses for every registration -- even on the zero identity.
    """
    if token:
        return token
    for name in TOKEN_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _looks_like_identity(name: str) -> bool:
    """Whether a target string is an identity rather than a directory name.

    66 hex characters, or the literal `anyone`. Anything else is a name and goes
    to `dir.resolve`, because the apphost `Target` field is an identity and a
    name never travels (design section 4.1).
    """
    return name == "anyone" or (len(name) == 66 and all(c in _HEX for c in name))


class _Budget:
    """One deadline, spent across the permit wait, the dial and the route.

    A caller's `timeout` means "a usable stream within T seconds", so it has to
    cover the wait for a connection permit as much as the node's answer.
    Splitting it into per-phase deadlines would make the total unbounded, and
    excluding the permit wait would make a client at its bound ignore deadlines
    entirely. What each phase must still do is name itself when it expires: "the
    budget is fully committed" and "the node did not answer" are different
    faults with different fixes.
    """

    __slots__ = ("_deadline", "timeout")

    def __init__(self, timeout: float | None) -> None:
        self.timeout = timeout
        self._deadline = (
            None
            if timeout is None
            else asyncio.get_running_loop().time() + max(0.0, timeout)
        )

    @property
    def remaining(self) -> float | None:
        """Seconds left, or `None` when there is no deadline."""
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - asyncio.get_running_loop().time())


class Client:
    """A connection budget onto one node, and the query facade over it."""

    # No `__slots__`: the module clients below attach as
    # `functools.cached_property`, which writes its cache through `__dict__`.

    def __init__(
        self,
        connector: Connector,
        *,
        endpoint: str,
        host_id: Identity | None = None,
        host_alias: str = "",
        guest_id: Identity | None = None,
        max_concurrency: int | None = DEFAULT_MAX_CONCURRENCY,
        max_persistent: int | None = DEFAULT_MAX_PERSISTENT,
        query_timeout: float | None = QUERY_TIMEOUT,
        cancel_timeout: float | None = CANCEL_TIMEOUT,
    ) -> None:
        """Build a client over a connector. `connect()` is the public way in.

        `connector` opens one greeted, authenticated session per call. Every
        query gets a fresh one, and the same callable is what `apphost.cancel`
        and a `Stream.cancel()` dial, so a cancel reaches the node a query was
        sent to and not some other one. It carries its own dial deadline, which
        is why this constructor takes no `connect_timeout`: a parameter the class
        stores and never reads reads as configuration and is not.

        `max_concurrency` bounds ordinary queries and `max_persistent` bounds the
        long-lived lane, so the client's worst case is their sum and is a number
        it can state. `None` is unbounded on either, and is a deliberate choice a
        caller has to make rather than a default.
        """
        if max_concurrency is not None and max_concurrency < 1:
            raise BadArgument(
                f"max_concurrency={max_concurrency}: a client that may hold no "
                "connection can issue no query; pass None for unbounded"
            )
        if max_persistent is not None and max_persistent < 1:
            raise BadArgument(
                f"max_persistent={max_persistent}: a client that may hold no "
                "long-lived connection can open no follow stream and no bind "
                "channel; pass None for unbounded"
            )
        self._connector = connector
        self._endpoint = endpoint
        self._host_id = host_id
        self._host_alias = host_alias
        self._guest_id = guest_id
        self._max_concurrency = max_concurrency
        self._max_persistent = max_persistent
        self.query_timeout = query_timeout
        self.cancel_timeout = cancel_timeout
        self._permits = (
            None if max_concurrency is None else asyncio.Semaphore(max_concurrency)
        )
        self._persistent_permits = (
            None if max_persistent is None else asyncio.Semaphore(max_persistent)
        )
        # Counted here rather than read off the semaphores: `Semaphore._value` is
        # a private asyncio attribute, and a documented public property must not
        # break on a CPython rename.
        self._held = 0
        self._held_persistent = 0
        # stream -> which lane it spends from, or `None` for neither. Persistent
        # streams are tracked for shutdown exactly as budgeted ones are.
        self._live: dict[Stream, str | None] = {}
        # Inbound services, closed ahead of the streams by `aclose()` (design
        # section 3.8 step 2). A service holds a listener, serving tasks and its
        # registrar's bind stream, and the bind stream is one of `_live`, so
        # closing services first is what makes the bind stream close last.
        self._services: list[Any] = []
        self._closing = False
        self._closed = False
        # One walk at a time, and the second caller inherits an abandoned
        # walk's remainder rather than waiting for a completion signal that
        # a cancelled walk would never send.
        self._sweep = asyncio.Lock()

    def __repr__(self) -> str:
        if not self._closing:
            state = "open"
        else:
            state = "closed" if self._closed else "closing"
        return (
            f"Client({self._endpoint!r}, {state}, {len(self._live)} live, "
            f"max_concurrency={self._max_concurrency})"
        )

    # --- module clients (design sections 4.1 and 5.1) ---
    #
    # Lazily constructed and cached, so a client that never touches `dir` builds
    # no `Dir`. Registration of the wire types is **not** lazy: `astral/__init__`
    # imports `astral.api` eagerly, so whether `mod.dir.alias_map` decodes never
    # depends on which property someone touched. That was a real latent bug in
    # the legacy SDK, and a property-local import alone would reintroduce it --
    # `client.call_one("dir.alias_map")` never touches `client.dir`.
    #
    # Every module that lands from here on gets a property here too. The import
    # is local to the body because `astral.api.*` annotate `Client`, so the
    # module-level direction has to stay api -> client.

    @functools.cached_property
    def apphost(self) -> "Apphost":
        """The `apphost.*` ops: whoami, tokens, holds, handlers, bind, cancel."""
        from .api.apphost import Apphost

        return Apphost(self)

    @functools.cached_property
    def dir(self) -> "Dir":  # noqa: A003 -- the module's name is the node's
        """The `dir` ops: the alias map, resolution, filters."""
        from .api.dir import Dir

        return Dir(self)

    @functools.cached_property
    def auth(self) -> "Auth":
        """The `auth` ops: contracts, signing, indexing."""
        from .api.auth import Auth

        return Auth(self)

    @functools.cached_property
    def crypto(self) -> "Crypto":
        """The `crypto` ops: public keys, signing, verification."""
        from .api.crypto import Crypto

        return Crypto(self)

    @functools.cached_property
    def objects(self) -> "Objects":
        """The `objects` ops: repositories, reads, writes, search, blueprints."""
        from .api.objects import Objects

        return Objects(self)

    @functools.cached_property
    def services(self) -> "Services":
        """The `services` ops: discovery and sync."""
        from .api.services import Services

        return Services(self)

    @functools.cached_property
    def tree(self) -> "Tree":
        """The `tree` ops: get, list, set, mounts."""
        from .api.tree import Tree

        return Tree(self)

    # --- what the greeting said ---

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def host_id(self) -> Identity | None:
        """The node's identity, from the greeting.

        `None` only if the node greeted with a nil `*Identity`, which is legal on
        the wire and which no astrald build sends. It is also the default
        `Target` of every query, where nil means "this node" anyway.
        """
        return self._host_id

    @property
    def host_alias(self) -> str:
        """The node's directory display name. Not a stable identifier."""
        return self._host_alias

    @property
    def guest_id(self) -> Identity | None:
        """The authenticated identity, or `None` on an anonymous client.

        An anonymous client may route queries when the node allows it (default
        on), has the network zone stripped server-side whatever it sends, and
        cannot register a service or a handler.
        """
        return self._guest_id

    @property
    def authenticated(self) -> bool:
        return self._guest_id is not None and not self._guest_id.is_zero

    # --- the budget ---

    @property
    def max_concurrency(self) -> int | None:
        """Ordinary queries this client may have in flight at once.

        Read-only: it sizes the semaphore at construction and `asyncio` offers no
        way to resize one, so a settable attribute would change `repr()` and the
        starvation message and change no behaviour at all.
        """
        return self._max_concurrency

    @property
    def max_persistent(self) -> int | None:
        """Long-lived connections this client may hold outside the query budget."""
        return self._max_persistent

    @property
    def live_streams(self) -> int:
        """Streams this client has open, budgeted and persistent together."""
        return len(self._live)

    @property
    def available(self) -> int | None:
        """Query permits not currently held, or `None` when unbounded.

        Counted by this class rather than read off `Semaphore._value`, which is
        private to asyncio: a documented public property must not break on a
        CPython rename.
        """
        if self._max_concurrency is None:
            return None
        return self._max_concurrency - self._held

    @property
    def available_persistent(self) -> int | None:
        """Persistent permits not currently held, or `None` when unbounded."""
        if self._max_persistent is None:
            return None
        return self._max_persistent - self._held_persistent

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def closing(self) -> bool:
        return self._closing

    # --- the query path ---

    async def query(
        self,
        qs: str,
        *,
        target: Identity | str | None | _Default = _DEFAULT,
        caller: Identity | None | _Default = _DEFAULT,
        zone: Zone | int | None = None,
        filters: Sequence[str] | None = None,
        context: Context | None = None,
        fmt_in: str = "",
        fmt_out: str = "",
        timeout: float | None | _Default = _DEFAULT,
        persistent: bool = False,
        raw: bool = False,
        separator: bool | None = None,
        allow_unparsed: bool = False,
        nonce: Nonce | int | None = None,
    ) -> Stream:
        """Route one query on a fresh connection and hand back its stream.

        `qs` is the query string: `operation?param=value&…`, built by
        `querystring.build` so the keys are sorted and every value carries the
        bare payload half of its type's text encoding.

        The returned `Stream` owns the connection and **must be closed**; every
        caller that can use `async with` should, and `stream()`, `call()`,
        `call_one()`, `call_raw()`, `call_with()` and `follow()` all do.

        `target` accepts an `Identity`, 66 hex characters, `anyone`, or a
        directory name -- which is resolved through `dir.resolve` **before** this
        query is sent, because the apphost `Target` field is an identity and a
        name never travels. The resolution runs before any permit is taken, so a
        client at its bound resolves and queues rather than deadlocking on a
        permit it is itself holding, and it runs **inside** `timeout`, so a
        stalled directory cannot outlast the deadline the caller set.

        `caller` is the identity to route as, defaulting to the session's guest
        identity (`None` on an anonymous client, which is the nil form on the
        wire). `zone` is the routing scope, `Zone.ALL` by default and with the
        network bit stripped server-side for an anonymous guest. `filters` names
        identity filters for the hop. `context` supplies all three at once for
        the ones left out.

        `timeout` is the whole operation up to a usable stream: the resolution of
        a named target, the wait for a permit, the dial, the greeting and the
        node's accept-or-reject. Omit it for the client's default (60 s); pass
        `None` for no deadline at all, which is what a follow-mode stream wants.
        It does **not** bound the body -- how long a stream stays open is the op's
        business and the caller's, and this method hands the stream over. The
        helpers that keep it (`call`, `call_one`, `call_raw`, `call_with`) spend
        one budget across both halves instead.

        `persistent=True` opens on the long-lived lane. Use it for anything that
        does not end on its own -- `apphost.bind`, `follow=true`,
        `objects.register_*`, `log.listen` -- and for nothing else: a query budget
        spent on streams that never end is a client that stops working. The lane
        is bounded at `max_persistent` for the mirror-image reason.

        `raw=True` declares the RAW mode of design section 4.7. It is checked
        against the session before the query is routed, so `objects.read` over a
        session that cannot carry unframed bytes fails without spending one of
        the node's workers on a response nobody can read, and it is carried into
        the `Stream`, which then refuses to frame a file as protocol.

        `separator` declares whether this op's first `eos` is design section
        4.7's snapshot/live boundary, and it is carried into the `Stream`, which
        then refuses the readers that would misread it. `None`, the default,
        declares nothing and permits every reader, which is right for every ST
        and RR op. `True` -- what `follow()` sets -- refuses `async for`, which
        would stop at the separator and drop every live object in silence.
        `False` refuses `follow()`, `snapshot()` and `live()`, for a follow-shaped
        op that sends no separator at all: `tree.get?follow=true` is one, and
        those three would block until the deadline holding a node worker.

        `fmt_in` and `fmt_out` are the channel formats, and they are reconciled
        with any `in=`/`out=` the query string already carries -- the query string
        is what the node reads, so a disagreement is refused rather than resolved
        silently in favour of the argument the node never sees.

        `nonce` fixes the query's correlator instead of drawing a random one;
        `apphost.cancel?id=` names it. `allow_unparsed=True` decodes an
        unregistered type as `UnparsedObject` rather than raising, which only the
        binary framing can offer, because only its length prefix locates the next
        frame.
        """
        self._require_open()
        qs, wire_in, wire_out = self._framing(qs, fmt_in, fmt_out, raw)

        budget = _Budget(self.query_timeout if isinstance(timeout, _Default) else timeout)
        resolved = await self._target(target, budget)

        lane = "persistent" if persistent else "query"
        await self._acquire(lane, budget)
        holds_permit = True

        registered = False
        try:
            # Re-checked here and not only at entry: a query that waited on the
            # semaphore was queued behind streams `aclose()` has since closed,
            # and each close hands its permit to the next waiter. Without this,
            # a shutdown feeds its own queue -- every waiter dials the node,
            # routes, is accepted, and only then finds the client closed, so a
            # client that has reported itself shut down opens one connection per
            # queued query against a pool of 32.
            self._require_open()
            session = await self._open(budget)
            try:
                if raw and not session.supports_raw_stream:
                    raise TransportUnsupported(
                        f"{qs}: this op answers with unframed bytes and this "
                        "session cannot carry them"
                    )
                conn = await session.route_query(
                    qs,
                    context=context,
                    caller=caller,
                    target=resolved,
                    zone=zone,
                    filters=filters,
                    nonce=nonce,
                    timeout=budget.remaining,
                    allow_unparsed=allow_unparsed,
                )
            finally:
                # A no-op once the query was accepted -- the stream owns the
                # transport by then -- and the close that matters when it was
                # not. `route_query` closes on its own failure paths too; this
                # covers the ones between them.
                await session.aclose()

            try:
                stream = Stream(
                    conn,
                    fmt_in=wire_in,
                    fmt_out=wire_out,
                    connector=self._connector,
                    cancel_timeout=self.cancel_timeout,
                    on_close=self._forget,
                    raw=raw,
                    separator=separator,
                )
            except BaseException:
                await conn.aclose()
                raise
            if self._closing:
                # A shutdown that began while this query was in flight. Closing
                # here is the only thing that can: `aclose()` has already walked
                # the live set, so a stream registered after it would outlive the
                # client with nothing left to close it.
                await stream.aclose()
                raise ClientClosed(
                    f"{self!r}: the client closed while {qs} was in flight"
                )
            self._live[stream] = lane
            registered = True
            return stream
        finally:
            # The permit is given back by `Stream.aclose()` once the stream
            # exists. Until it does, this is the only thing that can, and a
            # cancellation landing anywhere above reaches here.
            if holds_permit and not registered:
                self._release_permit(lane)

    def stream(self, qs: str, **kw: Any) -> "StreamContext":
        """`async with client.stream(...) as s:` -- a query that always closes.

        The reason to prefer it over `query()`: an exception thrown through the
        body still closes the connection, and a connection that does not close
        burns one of the node's 32 workers permanently.
        """
        return StreamContext(self, qs, kw)

    def follow(self, qs: str, **kw: Any) -> "StreamContext":
        """`async with client.follow(...) as s:` -- the ST+follow helper.

        Design section 4.7's follow mode, whose three requirements have nothing
        to do with each other and so were three things to remember at once:
        `persistent=True`, because a follow stream never ends and a query permit
        spent on it is never returned; `timeout=None`, because a follow stream is
        idle for as long as nothing happens and any deadline would kill it; and
        `Stream.follow()` / `snapshot()` / `live()` rather than `async for`, whose
        `eos` rule would truncate the stream at the snapshot separator. This
        makes the pairing once. The caller may still override either keyword,
        which is why they are defaults and not constants.

        The reader is still the caller's to choose, because the separator is
        visible only through those three iterators and which one is wanted is a
        per-call question: `snapshot()` for the stored state, `live()` for the
        updates, `follow()` for both with the boundary marked.
        """
        kw.setdefault("persistent", True)
        kw.setdefault("timeout", None)
        kw.setdefault("separator", True)
        return StreamContext(self, qs, kw)

    async def call(self, qs: str, **kw: Any) -> list[Any]:
        """Every object of a streaming op. The ST helper of design section 4.7.

        Terminates on `eos` **or** EOF and raises `RemoteError` on an
        `error_message`. Never call it on a follow-mode op, whose first `eos` is
        a separator -- `follow()` is that one -- nor on `user.sync_assets`, which
        ends with a bare `uint64`: both would block until the responder closed.

        `timeout` bounds the **whole** call, route and answer together, so an op
        that is accepted and then says nothing costs the deadline and not the
        rest of the process's life.
        """
        async with self._one_shot(qs, kw) as (s, budget):
            return await s.collect(timeout=budget.remaining)

    async def call_one(self, qs: str, **kw: Any) -> Any:
        """Exactly one object. The RR helper of design section 4.7.

        A second object raises rather than being dropped: an RR op that answered
        twice has made this call's single return value a lie about the rest.
        `timeout` bounds the route and the answer together.
        """
        async with self._one_shot(qs, kw) as (s, budget):
            return await s.value(timeout=budget.remaining)

    async def call_raw(self, qs: str, **kw: Any) -> bytes:
        """The unframed response body. The RAW helper, and `objects.read` alone.

        Not an object stream: an accepted query does not always carry objects,
        and framing this one would decode the file as protocol. `timeout` bounds
        the route and the body together.
        """
        kw.setdefault("raw", True)
        async with self._one_shot(qs, kw) as (s, budget):
            return await s.read_bytes(timeout=budget.remaining)

    async def call_with(
        self,
        qs: str,
        *objects: Any,
        eos: bool = False,
        expect: int | None = None,
        **kw: Any,
    ) -> list[Any]:
        """Send objects on the body, then read the answers. The WA helper.

        Design section 4.7's write-and-answer mode, and design section 5.1 names
        fifteen ops that take their input this way -- `crypto.sign_text`,
        `objects.store`, `auth.sign_contract` and the rest. **Passing that input
        as a query argument instead is the single most common way to get an op
        wrong**, and on `crypto.verify_*` it silently never verifies, so the
        helper exists to make the right thing the short thing.

        Both terminators are declared rather than inferred, because both are
        per-op contracts that the wire does not carry:

        `eos=True` sends the terminator after the inputs, for an op that reads to
        one. The default is off because astrald's `apphost.sign_app_contract`
        loop dispatches on the object's type and has no branch for `eos`, so the
        terminator would end that exchange as an error; closing the stream is
        what tells it the input is complete.

        `expect=None` reads to the stream's own end, `eos` or EOF, which is the
        WA termination design section 4.7 states and needs the op to end its
        stream. `expect=n` reads exactly n answers and stops, for an op that
        answers one per input and then waits for the caller to close --
        `sign_app_contract` again. Reading to the end of a stream that never ends
        blocks until the responder closes, which for that op is never.

        **`expect=n` interleaves: one send, then one read.** That declaration is
        exactly the statement that the op answers as it goes, and an op that
        answers as it goes cannot be fed a whole batch first. The answers pile up
        unread in this process's receive buffer while it is still writing; when
        that buffer fills, the responder's own `ch.Send` blocks, it stops reading,
        this side's `send()` blocks on its drain, and neither moves until the
        one-shot budget expires as `QueryTimeout`. Measured against a mock that
        runs astrald's own `ch.Switch` loop over loopback: 20,000 inputs of 1 kB
        with 1 kB answers wedged after 4,767 exchanges, and the interleaved form
        completes every size tried. `Objects._exchange` was written with the
        interleave for this reason and said so in its docstring while the shared
        helper -- which drives `tree.set`, `crypto.public_key`, `crypto.sign_hash`,
        `crypto.sign_text` and `auth.sign_contract` -- did not.

        `expect=None` keeps the batch-first order: it reads to the stream's end,
        so the op it names has answered nothing until the input is complete and
        there is nothing to interleave with.

        `timeout` bounds the send, the answers and the route together.
        """
        async with self._one_shot(qs, kw) as (s, budget):
            if expect is None:
                for obj in objects:
                    await s.send(obj, timeout=budget.remaining)
                if eos:
                    await s.send_eos(timeout=budget.remaining)
                return await s.collect(timeout=budget.remaining)
            answers: list[Any] = []
            sent = 0
            total = len(objects)
            # The terminator goes after the last input on both paths, so the
            # frames this side writes are in the same order either way and only
            # the points it reads at move.
            if total == 0 and eos:
                await s.send_eos(timeout=budget.remaining)
            while sent < total or len(answers) < expect:
                if sent < total:
                    await s.send(objects[sent], timeout=budget.remaining)
                    sent += 1
                    if sent == total and eos:
                        await s.send_eos(timeout=budget.remaining)
                if len(answers) < expect:
                    answer = await s.first(timeout=budget.remaining)
                    if answer is None:
                        break
                    answers.append(answer)
            return answers

    async def resolve_identity(self, name: Identity | str, **kw: Any) -> Identity:
        """An identity from 66 hex characters, `anyone`, or a directory name.

        Hex is parsed locally and costs nothing; a name is one `dir.resolve`
        query, which is what astral-go's `ResolveIdentity` does and what the
        `target:operation` CLI prefix needs. The op answers with an `identity`
        object or an `error_message`, which `call_one` raises as `RemoteError`.

        Takes the full query keyword set rather than `timeout` alone, because
        every one of them is meaningful on the `dir.resolve` it issues and
        because `Dir.resolve_identity` forwards `**kw` to it -- a narrower
        signature here made `d.resolve(name, zone=...)` work and
        `d.resolve_identity(name, zone=...)` a `TypeError` naming a method the
        caller never called.
        """
        if isinstance(name, Identity):
            return name
        if _looks_like_identity(name):
            return Identity.parse(name)
        obj = await self.call_one(querystring.build(OP_RESOLVE, {"name": name}), **kw)
        if not isinstance(obj, Identity):
            raise ProtocolError(
                f"{OP_RESOLVE}: expected an identity, got "
                f"{getattr(obj, 'ASTRAL_TYPE', type(obj).__name__)!r}"
            )
        return obj

    async def serve(
        self,
        identity: Identity | None = None,
        handler: "Handler | None" = None,
        *,
        mode: str = "handler",
        proto: str | None = None,
        endpoint: str | None = None,
        token: Nonce | int | None = None,
        experimental: bool = False,
        ready_timeout: float | None = None,
        **kw: Any,
    ) -> "Service":
        """Serve inbound queries. Design sections 4.3 and 4.4.

        `mode="handler"` is the primary path: a local listener is bound, the
        accept loop starts **before** anything is registered, and
        `apphost.bind` + `apphost.register_handler` tell the node where to dial.
        The returned `Service` owns the listener, the op table and the registrar,
        and `Service.aclose()` closes all three in design section 3.8's order.

        `mode="service"` is design section 4.4's register-service path, which is
        the WebSocket design. astral-go implements neither side of it and astrald
        closes the IPC guest connection unconditionally after `Guest.Serve`
        returns while guarding the same close on `donated` only on the WebSocket
        path, so a donated responder stream over IPC can be closed under it
        (design risk R-16, unsettled). Over IPC it therefore needs
        `experimental=True`; over WebSocket it needs nothing.

        `identity` names the identity to serve. It reaches the wire only in
        service mode, where `register_service_msg` carries it. Register-handler
        has no identity argument at all: astrald registers the handler under
        `q.Caller()`, so a `handler`-mode `identity` that is not this client's
        guest identity is refused here rather than silently registered under
        another one.

        **The two modes are authenticated differently, and it is astrald's
        asymmetry rather than this SDK's.** `register_service_msg` is refused
        outright for a token-less guest, the zero identity included, because
        `onRegisterServiceMsg` tests `isAuthenticated()` first. The
        `apphost.register_handler` **op** tests nothing but the query's origin
        and then registers under `q.Caller()` -- which the core router rewrites
        to the node's own identity for an anonymous guest -- so an anonymous
        local process can register a handler, and it registers as the node.

        **Returning means registered.** The first registration cycle runs
        before this returns, bounded by `ready_timeout`, and its failure is this
        call's failure with the service already closed: a service the node has
        never heard of answers nothing and reports nothing, which is worse than
        an exception. Only a connection that worked and then dropped is retried,
        and that retrying is the registrar's.
        """
        from .registrar import READY_TIMEOUT, Registrar
        from .serve import DEFAULT_PROTO, Service, require_service_transport

        if mode not in ("handler", "service"):
            raise BadArgument(f"serve mode {mode!r}: expected 'handler' or 'service'")
        self._require_open()
        if mode == "service":
            # Both refusals are certainties, and both happen before anything is
            # dialed: astrald tests `isAuthenticated()` ahead of everything else
            # in `onRegisterServiceMsg` and answers `denied` even for the zero
            # identity, so an anonymous registration is a round trip whose answer
            # is already known -- and one of 32 node workers spent to hear it.
            # The unsettled risk outranks the fixable refusal: a caller told to
            # get a token first would obtain one and only then learn that the
            # path is gated.
            require_service_transport(self._endpoint, experimental=experimental)
            if not self.authenticated:
                raise Denied(
                    "an anonymous client cannot register a service: astrald "
                    "refuses every registration from a token-less guest, the "
                    "zero identity included. mode='handler' is not refused -- "
                    "apphost.register_handler checks only the query's origin -- "
                    "but it then registers under the caller the core router "
                    "substitutes, which is the node's own identity"
                )
        if mode == "handler" and identity is not None and identity != self._guest_id:
            # An anonymous client fails this too, and correctly: its `guest_id`
            # is `None`, the node substitutes its own identity for the nil
            # caller, and a client that cannot name the identity it will be
            # registered under cannot be asked to confirm it.
            whose = (
                "which this anonymous client does not know -- the core router "
                "substitutes the node's own identity for a nil caller"
                if self._guest_id is None
                else f"which is {self._guest_id.fingerprint()}"
            )
            raise BadArgument(
                f"serve(identity={identity.fingerprint()}): apphost.register_handler "
                "takes no identity -- astrald registers the handler under the "
                f"query's caller, {whose}. The message that could name another "
                "one, mod.apphost.register_handler_msg, is registered in "
                "astral-go and unreachable in astrald: Guest.Serve's dispatch "
                "switch never routes to it (astral-go bug G-16)"
            )

        service = Service(
            handler=handler,
            identity=identity,
            token=token,
            connector=self._connector,
            **kw,
        )
        self._services.append(service)
        try:
            if mode == "service":
                session = await self._connector()
                try:
                    await service.attach_registration(
                        session, identity, experimental=experimental
                    )
                except BaseException:
                    await session.aclose()
                    raise
                return service

            registrar = Registrar(self)
            service.attach_registrar(registrar)
            # The accept loop is up before anything is registered, which is
            # design section 4.3 step 2: a post-connect hook's own query can be
            # routed straight back to this identity, and astrald waits for the
            # `ack` with no deadline of its own.
            await service.listen(DEFAULT_PROTO if proto is None else proto, endpoint=endpoint)
            await registrar.register(service.endpoint, service.token)
            await registrar.start(
                timeout=READY_TIMEOUT if ready_timeout is None else ready_timeout
            )
            return service
        except BaseException:
            self._forget_service(service)
            await service.aclose()
            raise

    # --- internals ---

    def _require_open(self) -> None:
        if self._closing:
            raise ClientClosed(f"{self!r}: the client is closed")

    @contextlib.asynccontextmanager
    async def _one_shot(
        self, qs: str, kw: dict[str, Any]
    ) -> AsyncIterator[tuple[Stream, _Budget]]:
        """One stream and one budget spanning the route **and** the answer.

        The helpers that own their stream have to bound the body, because the
        caller has nothing to wrap in `asyncio.timeout`: `timeout` is the only
        knob offered and it reached only `query()`. So a node that accepted and
        then said nothing pinned the caller forever with the connection open and
        one of the node's 32 workers held -- measured: `call(timeout=0.3)` still
        running after 1.5 s, four such calls holding four connections.

        One budget rather than two deadlines, so `call(qs, timeout=T)` cannot
        exceed T end to end: two would make the total 2T and the promise the
        docstrings make would still be false, only by less.
        """
        timeout = kw.get("timeout", _DEFAULT)
        budget = _Budget(self.query_timeout if isinstance(timeout, _Default) else timeout)
        stream = await self.query(qs, **{**kw, "timeout": budget.remaining})
        try:
            yield stream, budget
        finally:
            await stream.aclose()

    def _framing(
        self, qs: str, fmt_in: str, fmt_out: str, raw: bool = False
    ) -> tuple[str, str, str]:
        """Reconcile the query string's `in=`/`out=` with the format keywords.

        **The node's encoder is chosen by the query string and by nothing else.**
        astrald builds the responder's channel from the parsed `In`/`Out`
        arguments (`mod/apphost/src/op_whoami.go`), and astral-go's `newSender`
        switches on the same values. The `fmt_in`/`fmt_out` keywords select only
        *this* side's channel, so a query string that says `out=json` and a
        keyword that says `bin` are two different answers to one question, and
        the one the node hears is the query string's. Validating the keyword and
        ignoring the parameter -- which is what this method used to do -- checks
        the half that has no effect: `call_one('apphost.whoami?out=json')` passed
        every guard and handed a JSON body to a binary channel.

        So the query string wins where it speaks, the keyword fills in where it
        does not, and a genuine disagreement is refused rather than resolved
        silently. A non-default keyword is written **into** the query string, so
        what this side is configured for and what the node is asked for are the
        same string.

        The keywords default to `""`, which astral-go already reads as `bin`, so
        "not given" and "explicitly bin" stay distinguishable. With
        `fmt_out=Format.BIN` as the default they were not, and every non-`bin`
        `out=` in a query string would have read as a contradiction with a
        keyword the caller never touched.

        `in=` and `out=` are the responder's directions, not ours: `in=` is what
        the responder **reads**, so it is what this side writes, and `out=` is
        what the responder writes, so it is what this side reads. They are kept
        in that form all the way down to `Stream`, which does the one swap
        `open_channel` needs. Validating `in=` as an input format is what rejects
        `base64` and `render`, which exist only as output.

        A node silently accepts an unknown `out=` and then produces zero bytes
        (astral-docs bug D-24), so the validation is client-side and happens
        before anything is dialed. `raw` relaxes only the "which channels have
        landed" half of it: a RAW stream opens no channel, so a format this SDK
        cannot frame is still a format it can hand to the caller as bytes -- and
        that is how the risk register reads `apphost.whoami?out=json` off a live
        node without a JSON channel existing. Note also that `in=` reaches only
        seven of the nineteen ops these modules cover -- the other twelve build their channel
        with `channel.WithOutputFormat(args.Out)` alone and drop `in=` in silence
        -- so an `in=` that is not `bin` is a promise this SDK cannot keep for
        every op, and step 14 has to gate it per op.
        """
        op, params = querystring.parse(qs)
        wanted = {"in": fmt_in, "out": fmt_out}
        for key, keyword in wanted.items():
            in_qs = params.get(key)
            if in_qs is None:
                continue
            output = key == "out"
            if keyword and parse_format(in_qs, output=output) is not parse_format(
                keyword, output=output
            ):
                raise BadArgument(
                    f"{qs}: the query string says {key}={in_qs} and the "
                    f"fmt_{key} keyword says {keyword}; the node reads the query "
                    "string, so these cannot differ"
                )
            wanted[key] = in_qs

        parsed_in = parse_format(wanted["in"], output=False)
        parsed_out = parse_format(wanted["out"], output=True)
        # `raw=True` opens no channel at all: the caller reads the body as bytes
        # and decides what it is. So the format is the *node's* business there
        # and refusing it would refuse the one thing the raw view exists for --
        # reading what a format this SDK cannot yet frame actually looks like on
        # the wire. The token is still validated above, because an unknown `out=`
        # makes the node produce zero bytes and report nothing (astral-docs bug
        # D-24), and that is worth catching whoever decodes the answer.
        if not raw and (parsed_in is not Format.BIN or parsed_out is not Format.BIN):
            raise TransportUnsupported(
                f"channel format in={parsed_in.value} out={parsed_out.value}: the "
                "json, text, canonical, base64 and render channels land with "
                "channel/jsonl.py, channel/textchan.py and channel/canonical.py "
                "(implementation step 14), together with the per-op gating that "
                "`in=` needs"
            )
        # Rebuilt only when a keyword adds something, so an ordinary query string
        # travels byte for byte as the caller wrote it.
        for key, value in wanted.items():
            if parse_format(value, output=key == "out") is not Format.BIN:
                params[key] = value
                qs = querystring.build(op, params)
        return qs, str(parsed_in), str(parsed_out)

    async def _target(
        self, target: Identity | str | None | _Default, budget: _Budget
    ) -> Identity | None | _Default:
        """Resolve a target name inside the caller's budget.

        `_DEFAULT` means "the session's host", `None` means the nil identity, and
        the two are different bytes on the wire, so neither is resolved.

        The budget is threaded in rather than left out because the resolution is
        a *query*: it dials the node, routes `dir.resolve` and reads an answer,
        and on the client's own 60 s default it can outlast a caller's 0.2 s
        deadline by three hundred times. A `timeout` documented as the whole
        operation has to cover the leg the caller cannot see.
        """
        if isinstance(target, _Default) or target is None:
            return target
        return await self.resolve_identity(target, timeout=budget.remaining)

    async def _acquire(self, lane: str, budget: _Budget) -> None:
        """Take one permit on a lane, or say why the budget could not be met."""
        permits = self._permits if lane == "query" else self._persistent_permits
        if permits is None:
            self._count(lane, 1)
            return
        try:
            async with asyncio.timeout(budget.remaining):
                await permits.acquire()
        except TimeoutError as exc:
            raise QueryTimeout(
                f"{self._endpoint}: waited {budget.timeout}s for one of "
                f"{self._max_concurrency if lane == 'query' else self._max_persistent}"
                f" {lane} connection permits, all of which are held by streams "
                "still open; long-lived streams belong on the persistent lane "
                "(persistent=True), which spends none of the query budget"
            ) from exc
        self._count(lane, 1)

    def _release_permit(self, lane: str) -> None:
        permits = self._permits if lane == "query" else self._persistent_permits
        self._count(lane, -1)
        if permits is not None:
            permits.release()

    def _count(self, lane: str, delta: int) -> None:
        if lane == "query":
            self._held += delta
        else:
            self._held_persistent += delta

    async def _open(self, budget: _Budget) -> Session:
        """One greeted session, inside what is left of the caller's deadline."""
        try:
            async with asyncio.timeout(budget.remaining):
                return await self._connector()
        except TimeoutError as exc:
            raise QueryTimeout(
                f"{self._endpoint}: no connection within {budget.timeout}s"
            ) from exc

    def _forget_service(self, service: Any) -> None:
        """Drop a service from the shutdown walk. Called by `serve()` on failure."""
        with contextlib.suppress(ValueError):
            self._services.remove(service)

    def _forget(self, stream: Stream) -> None:
        """A stream has closed: drop it and give its permit back.

        Called from `Stream.aclose()` **after** the descriptor is gone, so the
        query that takes the permit next cannot overlap the connection that gave
        it up.
        """
        lane = self._live.pop(stream, None)
        if lane is not None:
            self._release_permit(lane)

    # --- shutdown ---

    async def aclose(self) -> None:
        """Close every connection this client holds. Idempotent.

        **Never raises a fault of its own.** A `CancelledError` aimed at the
        caller still propagates, because swallowing one would break structured
        cancellation -- but every stream is closed by then anyway, which is what
        the promise is actually about. The older, flatter claim ("never raises")
        was false in exactly the case that mattered.

        Design section 3.8's order, with the reason for it:

        1. refuse new work, so nothing is opened behind the teardown, **and wake
           the queue** so a query already waiting on a permit fails instead of
           being handed one by a stream this method just closed;
        2. close every inbound service: its listener, then its serving tasks,
           then its registrar's bind stream, which is what makes the node run its
           deferred handler sweep with the handlers already torn down (design
           section 3.8 step 4, and the bind stream is one of the streams step 3
           would otherwise close first);
        3. close every live stream, budgeted and persistent alike;
        4. drain best-effort `apphost.cancel` dials, so one issued during
           teardown is not abandoned half-open on the node.

        Swallowing teardown faults supersedes design section 3.8's
        `ExceptionGroup` clause and follows section 3.5: this runs from
        `__aexit__`, and a teardown that raised a bookkeeping fault would replace
        the caller's own exception with it.

        **Step 3 closes concurrently, and each close is shielded.** Both follow
        from one fact: `StreamTransport.aclose()` is bounded at `CLOSE_TIMEOUT`
        *per connection*, deliberately, because a peer that stopped reading would
        otherwise pin `wait_closed()` forever. Closed in sequence, the bounds add
        -- measured at 2.00 s, 4.00 s and 8.01 s for one, two and four stuck
        streams, so 16 s at the default bound of 8 -- which makes any sanely
        bounded shutdown expire *inside* the walk by construction. And a
        `CancelledError` arriving inside the walk used to abort it with streams
        still live while the `finally` marked the client closed and woke every
        future caller, so a retry took the idempotent fast path and returned in
        0.0000 s having closed nothing. Each of those abandoned connections is
        one of astrald's 32 workers held until the node restarts, which is the
        exact failure this module exists to prevent. Shielding each close means a
        cancelled teardown still closes every stream; gathering them means the
        bound is one `CLOSE_TIMEOUT` rather than N.

        `closed` is set only when the live set is empty. A teardown that could
        not finish leaves the client *closing* -- new work still refused -- and a
        later `aclose()` resumes the walk rather than short-circuiting on a claim
        that is not true.
        """
        if self._closed:
            return
        # Refused and the queue woken before anything is awaited, so a caller
        # whose own `aclose()` is cancelled a moment later still stopped the
        # client taking new work.
        self._closing = True
        self._wake_waiters()
        # The lock is what makes "returning means closed" true for the second
        # caller as well: it waits for the walk rather than for an event a
        # cancelled walk would never set, and if that walk was abandoned it
        # inherits the remainder instead of reporting a close that did not
        # happen. Cancellation while waiting for it releases it.
        async with self._sweep:
            if self._closed:
                return
            try:
                # Services first, and one at a time: each one closes its listener,
                # its serving tasks and then its bind stream, and the ordering
                # inside a service is what the node's deferred handler sweep
                # depends on. Shielded for the same reason the streams are -- a
                # cancelled teardown that abandoned a listener would leave it
                # accepting connections nothing serves.
                while self._services:
                    service = self._services.pop()
                    with contextlib.suppress(Exception):
                        await asyncio.shield(service.aclose())
                # `shield` per stream, gathered: a cancellation delivered here
                # cancels this `gather` and not the closes underneath it, so
                # every descriptor is still released, and the bound is one
                # `CLOSE_TIMEOUT` rather than one per stream.
                # `return_exceptions` keeps one stream's fault from cancelling
                # its siblings mid-close.
                #
                # The loop runs at most twice. `_live` cannot grow behind it --
                # `query()` re-checks `_closing` and closes the stream itself
                # with no `await` between that check and the registration -- and
                # every completed `Stream.aclose()` removes its own entry from
                # `_forget` before it returns.
                while self._live:
                    await asyncio.gather(
                        *(asyncio.shield(s.aclose()) for s in list(self._live)),
                        return_exceptions=True,
                    )
                with contextlib.suppress(Exception):
                    await flush_cancels(CANCEL_FLUSH_TIMEOUT)
            finally:
                if not self._live and not self._services:
                    self._closed = True

    def _wake_waiters(self) -> None:
        """Fail the permit queue rather than feeding it.

        A query blocked in `_acquire` is not told the client is closing, and each
        stream this teardown closes hands its permit to the next waiter, so the
        whole queue drains as post-close dials -- measured at 60 connections
        opened *after* `aclose()` returned. Releasing the whole bound wakes every
        waiter at once; each then finds `_closing` set on the re-check that
        follows `_acquire` and raises `ClientClosed` without dialing.
        """
        for permits, bound in (
            (self._permits, self._max_concurrency),
            (self._persistent_permits, self._max_persistent),
        ):
            if permits is None or bound is None:
                continue
            for _ in range(bound):
                permits.release()

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class StreamContext:
    """What `Client.stream()` and `Client.follow()` return: one query's scope.

    The query is routed on `__aenter__` and not on construction, so building one
    and discarding it opens nothing. That is why `Client.stream()` can be a plain
    `def` -- there is no coroutine to await and nothing to leak if the `async
    with` is never reached.

    Public and exported, because it is the return type of two public methods and
    a caller writing a wrapper has to be able to spell it.
    """

    __slots__ = ("_client", "_qs", "_kw", "_stream")

    def __init__(self, client: Client, qs: str, kw: dict[str, Any]) -> None:
        self._client = client
        self._qs = qs
        self._kw = kw
        self._stream: Stream | None = None

    async def __aenter__(self) -> Stream:
        self._stream = await self._client.query(self._qs, **self._kw)
        return self._stream

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            await stream.aclose()


async def connect(
    endpoint: str | None = None,
    *,
    token: str | None = None,
    connector: Connector | None = None,
    max_concurrency: int | None = DEFAULT_MAX_CONCURRENCY,
    max_persistent: int | None = DEFAULT_MAX_PERSISTENT,
    registry: Blueprints | None = None,
    connect_timeout: float | None = CONNECT_TIMEOUT,
    handshake_timeout: float | None = HANDSHAKE_TIMEOUT,
    query_timeout: float | None = QUERY_TIMEOUT,
    cancel_timeout: float | None = CANCEL_TIMEOUT,
    max_alloc: int = DEFAULT_MAX_ALLOC,
) -> Client:
    """Open a client onto a node.

    One connection is made here and **closed again before this returns**. It
    exists to learn the host identity and alias from the greeting and, when a
    token is given, to have it accepted or refused now rather than on some later
    query. Holding it open would spend one of the node's 32 apphost workers for
    as long as the client lived, doing nothing (design section 3.9).

    `endpoint` and `token` fall back to the environment and then to the defaults
    of design section 3.3. `connector` replaces both, for a caller that already
    knows how to open a session -- a test harness over memory, or a transport
    someone else dialed. **`connect_timeout`, `handshake_timeout`, `registry`,
    `max_alloc` and `token` configure the connector this function builds**, so
    passing `connector` supersedes all five: a connector the caller supplied
    already carries its own, and this function cannot reach inside one.

    The timeouts are named parameters rather than `**timeouts`: a misspelled
    keyword must fail here, not be silently dropped, which is the exact defect
    astral-go ships twice in its own clients (bug G-9).
    """
    target = resolve_endpoint(endpoint)
    if connector is None:
        connector = functools.partial(
            Session.connect,
            target,
            token=resolve_token(token),
            timeout=connect_timeout,
            handshake_timeout=handshake_timeout,
            registry=registry,
            max_alloc=max_alloc,
            cancel_timeout=cancel_timeout,
        )

    session = await connector()
    try:
        host_id = session.host_id
        host_alias = session.host_alias
        guest_id = session.guest_id
        endpoint_used = session.endpoint
    finally:
        await session.aclose()

    return Client(
        connector,
        endpoint=endpoint_used,
        host_id=host_id,
        host_alias=host_alias,
        guest_id=guest_id,
        max_concurrency=max_concurrency,
        max_persistent=max_persistent,
        query_timeout=query_timeout,
        cancel_timeout=cancel_timeout,
    )
