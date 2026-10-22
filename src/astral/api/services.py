"""`services`: providers answer for their services, consumers discover them.

The Services v1 wire. Two ops; `services.sync` is gone from the node.

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `services.advertise` | BD, held open | `ack` \\| `error_message`, then `services.ask` × n | binds while open |
| `services.discover` | ST+follow | `services.update` \\| `services.removed` × n, `services.incomplete`?, `eos` | read-only |

The two are the complete surface: the live `shell.spec` registry holds
`services.advertise` and `services.discover` and nothing else under this module,
verified on an isolated astrald built from `1286a469`.

**A provider binds a fixed set of services for as long as its channel is open.**
`services.advertise?services=a,b` names the set. The op refuses a network-origin
query (`astrald/mod/services/src/op_advertise.go:25`), asks
`mod.auth.serve_apps_action` for the caller
(`astrald/mod/services/src/op_advertise.go:31`), and refuses a zero caller and the
node's own identity (`astrald/mod/services/src/op_advertise.go:39`), each with a
query rejection. An anonymous IPC caller is the node, so it is rejected: verified
on that node, `QueryRejected` with code 1. A malformed service list and a name
this provider already advertises are answered after accept with an
`error_message` (`astrald/mod/services/src/op_advertise.go:49`,
`astrald/mod/services/src/op_advertise.go:55`); the second carries the text
`ERR_ADVERTISED`. Then the node sends `ack`, and after it one `services.ask` per
caller and service it needs evaluated. The provider sends one `services.answer`
per ask and a `services.change` whenever offerings may have changed; any other
object, and closing the channel, ends the binding
(`astrald/mod/services/src/op_advertise.go:65`). `advertise()` returns a
`Binding`, the counterpart of astral-go's (`api/services/client/advertise.go` at
astral-go `8972f283`), and `async with` is its contract, because the open channel
**is** the advertisement.

**An answer is the complete offering of one service for one caller.** The
handler a `Binding` holds evaluates it. `None` or an exception is answered as
unavailable, so an ask is never left unanswered, which is astral-go's rule
(`astral-go/api/services/client/advertise.go:81`). The answer always carries the asked
name and no provider: the node refuses an answer whose name differs from the
ask's and one naming another provider, and it sets the provider from the binding
(`astrald/mod/services/src/coordinator/source_messages.go:45`,
`astrald/mod/services/src/coordinator/source_messages.go:47`,
`astrald/mod/services/src/coordinator/source_messages.go:30`). One ask waits 10 s
for its answer (`astrald/mod/services/src/coordinator/coordinator.go:36`).

**A change that selects no caller fails the binding**
(`astrald/mod/services/src/coordinator/source_messages.go:85`), so
`Binding.change()` with no callers sends nothing.

**A consumer discovers named services for itself.** `services.discover?
services=a,b` admits the request before any work: the list must parse, `reach`
must be `local` or `swarm`, and the caller must hold
`mod.services.service_discovery_action` for every named service on every
contributing node, else the op answers `not permitted to discover "<name>"`
(`astrald/mod/services/src/op_discover.go:159`). `reach=swarm` carries the
discovery to every member of the node's local swarm in the caller's name, and is
accepted only from a local app (`astrald/mod/services/src/op_discover.go:29`).
Verified on the isolated node: an anonymous caller, which is the node, is refused
`not permitted to discover "chat"`, because the node identity holds no discovery
permit.

**The stream has one `eos`, and it ends the initial attempt.** Before it come the
offering views -- `services.update`, one complete offering, `available` false
when the provider offers nothing -- and `services.removed`, the offerings of a
lost provider. `services.incomplete` precedes the `eos` when some initial work
did not resolve; a bare `eos` means the initial attempt completed. Without
`follow` the channel closes after the `eos`; with `follow` it carries later views
and removals (`astrald/mod/services/src/op_discover.go:34`,
`astrald/mod/services/src/op_discover.go:36`). The node gives the initial attempt
5 s (`astrald/mod/services/src/coordinator/coordinator.go:36`). This module turns
the `eos` into an `InitialOutcome` event, so a reader never sees the separator:
`complete` true for a bare `eos`, false with the incomplete service names
otherwise. A one-shot stream that ends before its `eos` and a follow stream that
ends at all are `ProtocolError`, as `ErrStreamEnded` is in astral-go
(`astral-go/api/services/client/services.go:16`).

**`follow` is not parsed as an astral `bool`.** The op's argument struct field
is a plain Go `bool`, and `query.FieldEditor.UnmarshalText` sends that through
`strconv.ParseBool` (`astral-go/lib/query/field_editor.go:143`), never through
`astral.Bool.UnmarshalText`. This module sends `true`/`false` through the
parameter's declared spec, which both parsers read.

**`services.update` is one record with two pointer slots.** Field order, widths
and both nil flags read off the node itself -- `objects.new?type=
services.update` builds the zero value server-side and sends it as
`0f 73657276696365732e757064617465 00000004 00000000`, four zero bytes for four
fields. `Info` is a full `bundle` decoded through the registry (R-13), settled by
`objects.echo?strict=true` round-tripping a populated update byte for byte. The
type name carries **no `mod.` prefix** -- astral-go's `Update.ObjectType()`
returns `services.update` (`astral-go/api/services/update.go:19`) -- and so do
`ask`, `answer`, `change`, `incomplete`, `removed`, `offering_key` and
`operations_list`. The three authorization types carry it:
`mod.services.service_discovery_action`, `mod.services.discovery_scope`,
`mod.services.discovery_rule`. Design section 5.1 rule 6 lists the exceptions.

Every type here round-trips the bytes astral-go `221ce52` writes for it,
`tests/test_api_services.py` `GoWireTest` holds those bytes.

`Services(client)` constructs the module client, and `client.services` is the
property design section 5.1 gives every module. Registration does not wait on
it: `astral/__init__.py` imports the whole `api` package eagerly, so whether
`services.update` decodes never depends on which property a caller touched.

Line numbers cite astrald `48ae88b2` and astral-go `8972f283`, the revisions
`tests/reference.py` pins, and `tests/test_api_services.py` reads each one back.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
from types import TracebackType
from typing import Any, AsyncIterator, Awaitable, Callable, Final, Sequence, Union

from .. import querystring
# `StreamContext` is imported at module scope and not under `TYPE_CHECKING`, for
# the reason `base.py` states: this package ships `py.typed`, so every annotation
# in it must resolve at runtime.
from ..client import StreamContext
from ..errors import BadArgument, BadArgumentType, ProtocolError, QueryTimeout
from ..object import Ack, Bundle
from ..record import record, wire
from ..spec import Primitive, Ptr, Slice, Spec
from ..stream import Stream
from ..types import Identity, Nonce
from .auth import Action
from .base import ModuleClient

__all__ = [
    "Answer",
    "Ask",
    "Binding",
    "Change",
    "DiscoveryEvent",
    "DiscoveryRule",
    "DiscoveryScope",
    "DiscoveryStream",
    "ERR_ADVERTISED",
    "Incomplete",
    "InitialOutcome",
    "MAX_NAMES",
    "MAX_NAME_LEN",
    "OP_ADVERTISE",
    "OP_DISCOVER",
    "OfferingHandler",
    "OfferingKey",
    "OperationsList",
    "REACH_LOCAL",
    "REACH_SWARM",
    "Removed",
    "SERVICES_TYPES",
    "ServiceDiscoveryAction",
    "Services",
    "Update",
    "Watcher",
    "join_names",
    "validate_name",
]

OP_ADVERTISE: Final = "services.advertise"
OP_DISCOVER: Final = "services.discover"

MAX_NAMES: Final = 64
"""The most services one advertise or discover call names
(`astral-go/api/services/names.go:10`)."""

MAX_NAME_LEN: Final = 255
"""The longest service name in bytes: a name travels as a `string8`
(`astral-go/api/services/names.go:13`)."""

ERR_ADVERTISED: Final = "service already advertised by this provider"
"""The node's `error_message` text for an advertisement naming a service this
provider already advertises on a live binding
(`astral-go/api/services/errors.go:8`). `error_message` carries text only, so a
caller compares `RemoteError.message` with it."""

REACH_LOCAL: Final = "local"
"""Discover the providers the queried node hosts. The node's default
(`astral-go/api/services/reach.go:11`)."""

REACH_SWARM: Final = "swarm"
"""Also carry the discovery to every member of the node's local swarm, in the
caller's name (`astral-go/api/services/reach.go:14`)."""

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding (design section 5.1, rule 2). The types are the ones the
# live `shell.spec` reports for each parameter: `string8` for the plain Go
# strings `services` and `reach`, `bool` for `follow`.
_ADVERTISE: Final[dict[str, Spec]] = {
    "services": Primitive("string8"),
}
_DISCOVER: Final[dict[str, Spec]] = {
    "services": Primitive("string8"),
    "follow": Primitive("bool"),
    "reach": Primitive("string8"),
}


# --- service names -------------------------------------------------------


def validate_name(name: str) -> None:
    """Refuse a name that is not a valid service name.

    A name is non-empty, at most `MAX_NAME_LEN` bytes of UTF-8, holds no comma,
    and has no leading or trailing whitespace: astral-go's `ValidateName`
    (`astral-go/api/services/names.go`), which the node applies to every list.
    """
    if not isinstance(name, str):
        raise BadArgumentType(f"service name must be str, got {type(name).__name__}")
    if not name:
        raise BadArgument("empty service name")
    if len(name.encode("utf-8")) > MAX_NAME_LEN:
        raise BadArgument(f"service name longer than {MAX_NAME_LEN} bytes")
    if "," in name:
        raise BadArgument(f"service name {name!r} contains a comma")
    if name.strip() != name:
        raise BadArgument(f"service name {name!r} has surrounding whitespace")


def join_names(names: Sequence[str]) -> str:
    """The `services` argument: valid names, joined with commas.

    A list holds at least one name, at most `MAX_NAMES`, and no name twice:
    astral-go's `ParseNames`, applied here so a bad list is refused before it
    spends one of the node's workers. A bare `str` is refused rather than read
    as a sequence of one-character names.
    """
    if isinstance(names, str) or not isinstance(names, Sequence):
        raise BadArgumentType(
            f"service names must be a sequence of str, got {type(names).__name__}"
        )
    if not names:
        raise BadArgument("no service names")
    if len(names) > MAX_NAMES:
        raise BadArgument(f"more than {MAX_NAMES} service names")
    seen: set[str] = set()
    for name in names:
        validate_name(name)
        if name in seen:
            raise BadArgument(f"service {name!r} named twice")
        seen.add(name)
    return ",".join(names)


# --- the wire types ------------------------------------------------------


@record("services.update")
class Update:
    """One complete offering: one service of one provider for one caller.

    `available` false means the provider offers the caller nothing for the
    service. `provider_id` is set by the node from the advertising binding;
    `info` is a full `bundle`, decoded through the registry (R-13), and a
    provider's `services.operations_list` travels in it.

    `provider_id` is `None` when the node wrote `0x00`, and `info` likewise. The
    absence is surfaced rather than dropped, because a decode this SDK accepts
    must re-encode to the bytes it came from.
    """

    available: bool = wire("Available", Primitive("bool"))
    name: str = wire("Name", Primitive("string8"))
    provider_id: Identity | None = wire("ProviderID", Ptr("identity"))
    info: Bundle | None = wire("Info", Ptr("bundle"))

    @property
    def objects(self) -> Sequence[Any]:
        """Every object in `info`, or an empty sequence when there is none.

        An absent bundle and an empty bundle are different bytes and `info`
        keeps them apart; this view does not.
        """
        return () if self.info is None else tuple(self.info)


@record("services.ask")
class Ask:
    """The node asks a provider, on its binding, to evaluate one service for
    one caller. The provider replies with an `Answer` echoing `request_id`."""

    request_id: Nonce = wire("RequestID", Primitive("nonce64"))
    caller_id: Identity | None = wire("CallerID", Ptr("identity"))
    service: str = wire("Service", Primitive("string8"))


@record("services.answer")
class Answer:
    """A provider's reply to one `Ask`: the complete offering of the asked
    service for the asked caller. The provider leaves `update.provider_id`
    unset; the node sets it from the binding."""

    request_id: Nonce = wire("RequestID", Primitive("nonce64"))
    update: Update | None = wire("Update", Ptr("services.update"))


@record("services.change")
class Change:
    """The provider tells the node that some callers' offerings may have
    changed. With `all` false, `callers` names them and must be non-empty; with
    `all` true it covers every caller following a service of the binding."""

    all: bool = wire("All", Primitive("bool"))  # noqa: A003 -- the Go field
    callers: list[Identity | None] = wire("Callers", Slice("identity"))


@record("services.incomplete")
class Incomplete:
    """Precedes the `eos` ending a discovery's initial attempt when some initial
    work did not resolve. `services` names requested services, never providers
    or nodes."""

    services: list[str] = wire("Services", Slice("string8"))


@record("services.offering_key")
class OfferingKey:
    """One offering's identity: a provider and a service name."""

    provider_id: Identity | None = wire("ProviderID", Ptr("identity"))
    name: str = wire("Name", Primitive("string8"))


@record("services.removed")
class Removed:
    """Offerings a discovery stream had shown are no longer valid because their
    provider was lost. Distinct from an `Update` with `available` false, which is
    the provider's own answer."""

    offerings: list[OfferingKey | None] = wire(
        "Offerings", Slice("services.offering_key")
    )


@record("services.operations_list")
class OperationsList:
    """The operations a provider exposes to one caller, carried in
    `Update.info`. Listing an operation grants nothing."""

    operations: list[str] = wire("Operations", Slice("string8"))


@record("mod.services.discovery_rule")
class DiscoveryRule:
    """Allows its `services` on its `nodes`. An empty `services` list allows
    nothing; an empty `nodes` list allows any node within reach."""

    services: list[str] = wire("Services", Slice("string8"))
    nodes: list[Identity | None] = wire("Nodes", Slice("identity"))

    def allows(self, service: str, node: Identity | None) -> bool:
        """astral-go's `DiscoveryRule.Allows`."""
        if service not in self.services:
            return False
        if not self.nodes:
            return True
        return node is not None and any(n == node for n in self.nodes if n is not None)


@record("mod.services.discovery_scope")
class DiscoveryScope:
    """Narrows a discovery permit to pairs of service and contributing node.
    It allows a pair when one of its rules does."""

    rules: list[DiscoveryRule | None] = wire(
        "Rules", Slice("mod.services.discovery_rule")
    )

    def allows(self, service: str, node: Identity | None) -> bool:
        """astral-go's `DiscoveryScope.Allows`."""
        return any(r.allows(service, node) for r in self.rules if r is not None)


@record("mod.services.service_discovery_action")
class ServiceDiscoveryAction(Action):
    """Permission for the actor to discover `service` on the contributing node
    `node_id`. Discovery submits one action per requested service and node
    before it evaluates any provider."""

    service: str = wire("Service", Primitive("string8"))
    node_id: Identity | None = wire("NodeID", Ptr("identity"))

    def apply_constraints(self, constraints: Any) -> bool:
        """astral-go's `ApplyConstraints`: covered only when the constraints
        hold exactly one `DiscoveryScope` that allows the service on the node.

        An unconstrained permit covers nothing, because discovery is granted per
        service (`astral-go/api/services/service_discovery_action.go`).
        """
        if constraints is None:
            return False
        objects = list(constraints)
        if len(objects) != 1 or not isinstance(objects[0], DiscoveryScope):
            return False
        return objects[0].allows(self.service, self.node_id)


# --- discovery events ----------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class InitialOutcome:
    """Whether a discovery's initial attempt completed.

    Not a wire type: the event this module makes of the `eos` that ends the
    initial attempt, and of the `services.incomplete` before it. `incomplete`
    names the requested services whose initial work did not resolve.
    """

    complete: bool
    incomplete: tuple[str, ...] = ()


DiscoveryEvent = Union[Update, Removed, InitialOutcome]
"""One item of a discovery: an offering view, a removal, or the initial
outcome."""


async def _events(stream: Stream, *, follow: bool) -> AsyncIterator[Any]:
    """The events of one discovery stream, read off its separator readers.

    The `eos` never reaches the caller: it becomes the `InitialOutcome`. An
    `error_message` raises `RemoteError` from the readers themselves.
    """
    incomplete: Incomplete | None = None
    async for obj in stream.snapshot():
        if isinstance(obj, Incomplete):
            incomplete = obj
            continue
        yield _view(obj)
    if not stream.is_live:
        raise ProtocolError(
            f"{stream.query_string}: the discovery stream ended before its "
            "initial attempt did"
        )
    if incomplete is None:
        yield InitialOutcome(complete=True)
    else:
        yield InitialOutcome(complete=False, incomplete=tuple(incomplete.services))
    if not follow:
        return
    async for obj in stream.live():
        # A `services.incomplete` past the boundary describes nothing the
        # caller can act on; astral-go's reader stores it and emits nothing.
        if not isinstance(obj, Incomplete):
            yield _view(obj)
    raise ProtocolError(f"{stream.query_string}: the discovery stream ended")


def _view(obj: Any) -> Update | Removed:
    if isinstance(obj, (Update, Removed)):
        return obj
    raise ProtocolError(
        f"{OP_DISCOVER}: expected 'services.update' or 'services.removed', got "
        f"{getattr(obj, 'ASTRAL_TYPE', type(obj).__name__)!r}"
    )


class DiscoveryStream:
    """`async with services.discover_follow(names) as events:` -- ST+follow.

    `async for event in events` yields `Update`, `Removed` and one
    `InitialOutcome`, and continues until the caller leaves the block. A stream
    the node ends is a `ProtocolError`, because a followed discovery never ends
    on its own. Nothing is routed on construction.

    **The stream must be closed.** It holds one of the node's 32 apphost workers
    for as long as it is open; `async with` is the contract.
    """

    __slots__ = ("_context", "_stream")

    def __init__(self, context: StreamContext) -> None:
        self._context = context
        self._stream: Stream | None = None

    async def __aenter__(self) -> DiscoveryStream:
        self._stream = await self._context.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stream = None
        await self._context.__aexit__(exc_type, exc, tb)

    @property
    def stream(self) -> Stream:
        """The open stream. Raises `ProtocolError` outside the `async with`."""
        if self._stream is None:
            raise ProtocolError(f"{OP_DISCOVER}: the discovery is not open")
        return self._stream

    def __aiter__(self) -> AsyncIterator[Any]:
        return _events(self.stream, follow=True)


# --- the watcher ---------------------------------------------------------


class Watcher:
    """`async with services.watch(names) as watcher:` -- the current offerings.

    Follows a discovery and keeps the available offerings, keyed by provider and
    name: an `Update` with `available` true sets one, with `available` false
    deletes it, and a `Removed` deletes the offerings it names. astral-go's
    `Watcher` (`api/services/client/watch.go` at astral-go `8972f283`). It has no
    reconnect policy: once `done` is set, the app starts a new one.

    **The stream must be closed.** Leaving the `async with` closes it.
    """

    __slots__ = (
        "_discovery",
        "_offerings",
        "_initial",
        "_changed",
        "_done",
        "_error",
        "_task",
    )

    def __init__(self, discovery: DiscoveryStream) -> None:
        self._discovery = discovery
        self._offerings: dict[tuple[str, str], Update] = {}
        self._initial: asyncio.Future[InitialOutcome] | None = None
        self._changed = asyncio.Event()
        self._done = asyncio.Event()
        self._error: BaseException | None = None
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> Watcher:
        await self._discovery.__aenter__()
        self._initial = asyncio.get_running_loop().create_future()
        self._task = asyncio.create_task(self._run())
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await self._discovery.__aexit__(exc_type, exc, tb)

    async def _run(self) -> None:
        try:
            async for event in self._discovery:
                self._apply(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- kept as the terminal error
            self._error = exc
        finally:
            if self._initial is not None and not self._initial.done():
                self._initial.set_exception(
                    self._error
                    or ProtocolError(f"{OP_DISCOVER}: the watcher closed")
                )
                # Read here so a caller that never awaits `initial()` leaves no
                # "exception was never retrieved" behind.
                self._initial.exception()
            self._done.set()
            self._changed.set()

    def _apply(self, event: Any) -> None:
        if isinstance(event, InitialOutcome):
            if self._initial is not None and not self._initial.done():
                self._initial.set_result(event)
            return
        if isinstance(event, Update):
            key = (_key_text(event.provider_id), event.name)
            if event.available:
                self._offerings[key] = event
            else:
                self._offerings.pop(key, None)
        else:
            for k in event.offerings:
                if k is not None:
                    self._offerings.pop((_key_text(k.provider_id), k.name), None)
        self._changed.set()

    def offerings(self) -> list[Update]:
        """The available offerings, ordered by provider and name."""
        return [self._offerings[k] for k in sorted(self._offerings)]

    async def initial(self) -> InitialOutcome:
        """The outcome of the initial attempt, once it arrived. Raises the
        terminal error when the stream ended first."""
        if self._initial is None:
            raise ProtocolError(f"{OP_DISCOVER}: the watcher is not open")
        return await asyncio.shield(self._initial)

    async def changed(self) -> None:
        """Wait for the next change to the offerings or to the watcher's state.

        Changes that arrive together are coalesced into one wake-up. The end of
        the stream is a change too, so a loop over this checks `done`.
        """
        await self._changed.wait()
        self._changed.clear()

    @property
    def done(self) -> bool:
        """True once the stream ended."""
        return self._done.is_set()

    @property
    def error(self) -> BaseException | None:
        """The terminal error, or `None` while the stream is open."""
        return self._error


def _key_text(provider: Identity | None) -> str:
    return "" if provider is None else provider.text()


# --- a standing advertisement --------------------------------------------


OfferingHandler = Callable[
    [Union[Identity, None], str], Union[Awaitable[Union[Update, None]], Update, None]
]
"""Evaluates one service for one caller: `handler(caller, service)`. Returns
the offering, or `None` for none; may be a coroutine function."""


class Binding:
    """`async with services.advertise(names, handler) as binding:` -- an open
    advertisement.

    The services are bound from `__aenter__` until the channel closes, and
    closing the channel is what releases them. Nothing is routed on
    construction. `__aenter__` routes the query on the persistent lane and reads
    the node's `ack`. A refusal raises and leaves nothing open: `QueryRejected`
    for a network origin, a caller without `mod.auth.serve_apps_action` and the
    node itself, and `RemoteError` for the node's `error_message`, such as
    `ERR_ADVERTISED`. `timeout` bounds the route and the `ack` together and
    defaults to the client's query timeout; the held channel has no deadline.

    Each `services.ask` is answered on its own task, so a slow evaluation never
    delays another caller's. The node already sends at most one ask per caller
    at a time. The binding ends when the node closes the channel or sends
    anything but an ask; `done` reports it.

    **The channel must be closed.** It holds one of the node's 32 apphost
    workers for as long as it is open.
    """

    __slots__ = (
        "_services",
        "_names",
        "_handler",
        "_kw",
        "_stream",
        "_reader",
        "_answers",
        "_done",
    )

    def __init__(
        self,
        services: Services,
        names: tuple[str, ...],
        handler: OfferingHandler,
        kw: dict[str, Any],
    ) -> None:
        self._services = services
        self._names = names
        self._handler = handler
        self._kw = kw
        self._stream: Stream | None = None
        self._reader: asyncio.Task[None] | None = None
        self._answers: set[asyncio.Task[None]] = set()
        self._done = asyncio.Event()

    @property
    def names(self) -> tuple[str, ...]:
        """The service names this binding advertises."""
        return self._names

    @property
    def done(self) -> bool:
        """True once the binding ended, by `aclose()` or by the node."""
        return self._done.is_set()

    async def wait_closed(self) -> None:
        """Wait until the binding ends."""
        await self._done.wait()

    async def __aenter__(self) -> Binding:
        kw = dict(self._kw)
        client = self._services.client
        timeout = kw.pop("timeout", client.query_timeout)
        kw.setdefault("persistent", True)
        qs = querystring.build(
            OP_ADVERTISE, _encode(_ADVERTISE, {"services": ",".join(self._names)})
        )
        stream = await client.query(qs, timeout=timeout, **kw)
        try:
            answer = await stream.first(timeout=timeout)
            if answer is None:
                raise ProtocolError(
                    f"{OP_ADVERTISE}: the stream ended before the node "
                    "acknowledged the advertisement"
                )
            ModuleClient._expect(answer, Ack, OP_ADVERTISE)
        except BaseException:
            await stream.aclose()
            raise
        self._stream = stream
        self._done.clear()
        self._reader = asyncio.create_task(self._serve(stream))
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _serve(self, stream: Stream) -> None:
        try:
            while True:
                try:
                    obj = await stream.first()
                except Exception:  # noqa: BLE001 -- any fault ends the binding
                    break
                if not isinstance(obj, Ask):
                    break
                task = asyncio.create_task(self._answer(stream, obj))
                self._answers.add(task)
                task.add_done_callback(self._answers.discard)
        finally:
            for task in list(self._answers):
                task.cancel()
            self._done.set()
        await stream.aclose()

    async def _answer(self, stream: Stream, ask: Ask) -> None:
        try:
            offered: Any = self._handler(ask.caller_id, ask.service)
            if inspect.isawaitable(offered):
                offered = await offered
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- answered as unavailable, as astral-go does
            offered = None
        if isinstance(offered, Update):
            update = dataclasses.replace(offered, name=ask.service, provider_id=None)
        else:
            update = Update(
                available=False, name=ask.service, provider_id=None, info=None
            )
        try:
            await stream.send(Answer(request_id=ask.request_id, update=update))
        except Exception:  # noqa: BLE001 -- the binding closed meanwhile
            pass

    def _open(self) -> Stream:
        if self._stream is None or self._done.is_set():
            raise ProtocolError(f"{OP_ADVERTISE}: the binding of {self._names} is not open")
        return self._stream

    async def change(self, *callers: Identity, timeout: float | None = None) -> None:
        """Tell the node that these callers' offerings may have changed.

        No callers sends nothing: the node fails a binding on a change that
        selects no caller. `timeout` bounds the send.
        """
        if not callers:
            return
        for caller in callers:
            if not isinstance(caller, Identity):
                raise BadArgumentType(
                    f"{OP_ADVERTISE}: a caller must be an Identity, got "
                    f"{type(caller).__name__}"
                )
        await self._open().send(
            Change(all=False, callers=list(callers)), timeout=timeout
        )

    async def change_all(self, *, timeout: float | None = None) -> None:
        """Tell the node that every following caller's offerings may have
        changed. `timeout` bounds the send."""
        await self._open().send(Change(all=True, callers=[]), timeout=timeout)

    async def aclose(self) -> None:
        """End the binding; the node releases its services. Idempotent."""
        reader, self._reader = self._reader, None
        stream, self._stream = self._stream, None
        if reader is not None:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        for task in list(self._answers):
            task.cancel()
        if self._answers:
            await asyncio.gather(*self._answers, return_exceptions=True)
        if stream is not None:
            await stream.aclose()
        self._done.set()


# --- the client ----------------------------------------------------------


class Services(ModuleClient):
    """The `services` module's ops, over one `Client`.

    `Services(client)` constructs one. The scaffolding and the `**kw` contract
    are `ModuleClient`'s.
    """

    __slots__ = ()

    def advertise(
        self, names: Sequence[str], handler: OfferingHandler, **kw: Any
    ) -> Binding:
        """`async with s.advertise(names, handler) as binding:` -- BD, held open.

        Binds `names` with this client's caller as the provider, for as long as
        the `async with` block runs, and answers every ask with
        `handler(caller, service)`. The list is validated here, so a bad name is
        refused before it spends one of the node's workers.
        """
        joined = join_names(names)
        if not callable(handler):
            raise BadArgumentType(
                f"{OP_ADVERTISE}: handler must be callable, got "
                f"{type(handler).__name__}"
            )
        return Binding(self, tuple(joined.split(",")), handler, kw)

    async def discover(
        self, names: Sequence[str], *, reach: str | None = None, **kw: Any
    ) -> list[Any]:
        """The initial attempt of one discovery. ST, ends at its `eos`.

        Every event in arrival order -- `Update` and `Removed` -- and an
        `InitialOutcome` last. `timeout` bounds the route and the whole read;
        the node spends at most 5 s on the attempt. `reach` is `REACH_LOCAL`, the
        node's default when absent, or `REACH_SWARM`.
        """
        qs = _discover_query(names, follow=False, reach=reach)
        kw.setdefault("separator", True)
        async with self._one_shot(qs, kw) as (stream, budget):
            try:
                async with asyncio.timeout(budget.remaining):
                    return [event async for event in _events(stream, follow=False)]
            except TimeoutError:
                raise QueryTimeout(
                    f"{qs}: the initial attempt did not end within the deadline"
                ) from None

    def discover_follow(
        self, names: Sequence[str], *, reach: str | None = None, **kw: Any
    ) -> DiscoveryStream:
        """`async with s.discover_follow(names) as events:` -- ST+follow.

        The initial attempt's events, its `InitialOutcome`, then later views and
        removals until the caller leaves the block. `Client.follow` supplies the
        pairing this mode needs -- `persistent=True` and `timeout=None` -- and a
        caller may override either.
        """
        return DiscoveryStream(
            self._c.follow(_discover_query(names, follow=True, reach=reach), **kw)
        )

    def watch(
        self, names: Sequence[str], *, reach: str | None = None, **kw: Any
    ) -> Watcher:
        """`async with s.watch(names) as watcher:` -- the current offerings of a
        followed discovery."""
        return Watcher(self.discover_follow(names, reach=reach, **kw))


# --- query construction --------------------------------------------------


def _discover_query(names: Sequence[str], *, follow: bool, reach: str | None) -> str:
    """`services.discover?follow=…&services=…`, with `reach` only when named.

    `follow` is sent even when false, so the query string states the op shape
    this call declares. `reach` is omitted when absent, which keeps the node's
    default standing (design section 5.1 rule 5).
    """
    params: dict[str, Any] = {"services": join_names(names), "follow": follow}
    if reach is not None:
        if reach not in (REACH_LOCAL, REACH_SWARM):
            raise BadArgument(
                f"{OP_DISCOVER}: reach must be {REACH_LOCAL!r} or {REACH_SWARM!r}, "
                f"got {reach!r}"
            )
        params["reach"] = reach
    return querystring.build(OP_DISCOVER, _encode(_DISCOVER, params))


_encode = ModuleClient._encode
"""Every parameter through its declared spec. `ModuleClient`'s, not a copy."""


SERVICES_TYPES: Final[Sequence[type]] = (
    Answer,
    Ask,
    Change,
    DiscoveryRule,
    DiscoveryScope,
    Incomplete,
    OfferingKey,
    OperationsList,
    Removed,
    ServiceDiscoveryAction,
    Update,
)
"""Every wire type this module declares, for a private-registry sweep."""

Services.TYPES = SERVICES_TYPES
