"""`Registrar`: the bind session, the handler registrations, and the reconnect.

`astral.serve` owns the listener and the queries that arrive on it. This module
owns everything that has to be re-done when the connection to the node drops:

    apphost.bind                                   -> ack, held open
    apphost.register_handler?endpoint=&token=      -> ack, once per registration
    mod.apphost.bind_msg{Token} on the bind stream -> once per registration
    post-connect hooks                             -> objects.register_* and the rest
    the bind stream ends                           -> reconnect with backoff, re-run

**The bind stream is the only deterministic deregistration.** astrald's
`apphost.register_handler` adds the handler to a module-wide set and nothing
removes it when the registering connection closes: `query_router.go` drops a
handler only when a later routing attempt reports `errEndpointUnavailable`, so
removal is **lazy** and a dead registration lingers and consumes one routing
attempt per query (astral-docs bug D-13, which claims the opposite). The one
eager removal is `op_bind.go`, which collects every `bind_msg` of a session and
runs `removeHandlersByToken` in a deferred sweep when the session ends. So the
bind stream is held for exactly as long as the registrations should live, and it
is closed **last** on shutdown, with the listener already torn down.

**Registration is forgotten on disconnect, and the hooks with it.** A reconnect
therefore re-runs `register_handler`, re-sends every `bind_msg`, and re-runs
every hook, in that order. astral-go's `AppRegistrar` does the same, and this is
where `objects.register_searcher` belongs: design section 4.6 settles it as an RR
call, not a channel to hold, and the node forgets the searcher when the guest
disconnects.

**The gate is a readiness signal, not an admission gate.** astral-go wraps its
inbound router in a `gateRouter` that blocks every inbound query until the
registrar reports ready, and readiness is reached only **after** the hooks have
run -- so a hook whose own query the node routes back to this identity blocks on
a gate that the hook itself has to open. astral-go's `serve.go` documents that
exact deadlock as the reason its route loop starts before registration, and then
reintroduces it one layer up: astrald's `IPCHandler.RouteQuery` waits for the
`ack` through `ch.Switch(channel.ExpectAck, ...)` with neither `WithTimeout` nor
`WithContext`, so on the IPC path the reintroduced deadlock is unbounded and ends
only when the app's own context is cancelled. Nothing on the serving path here
consults the gate: the listener answers from the moment it binds, which is the
ordering design section 4.3 step 2 states, and a query that arrives before the
hooks have finished is one the mounted op can already serve. The gate is what a
**caller** waits on to learn that the node has heard about it.

**Generations, not a flag.** `Gate` replaces its `asyncio.Event` on disconnect
and never clears it, mirroring astral-go's `sig.Value[chan struct{}]`. The
difference is not cosmetic: a waiter admitted by generation *n* stays admitted,
because the decision was made when it sampled the gate and a later disconnect
cannot reach back and unmake it, while a waiter that arrives after the disconnect
samples a fresh generation and waits for the next connect. A cleared flag gives
neither property -- it re-blocks nobody and it lets a task that sampled `is_set()`
act on a readiness that has since gone.

**Reconnect is bounded, backed off and jittered.** `BACKOFF_MIN` 1 s,
`BACKOFF_MAX` 30 s, factor 2, matching astral-go's `sig.NewRetry` defaults, plus
a jitter astral-go does not have. The jitter is not decoration: astrald serves
apphost from 32 workers shared by every local app (astrald bug G-13, design
section 3.9), so a node restart releases every app's registrar at the same
instant and an unjittered backoff makes all of them dial in lockstep against the
pool whose exhaustion is the failure they are recovering from.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections import deque
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Awaitable, Callable, Final, Mapping

from . import querystring
from .client import Client
from .errors import BadArgument, ProtocolError, QueryTimeout, StreamClosed
from .object import Ack
from .session import (
    BACKOFF_FACTOR,
    BACKOFF_MAX,
    BACKOFF_MIN,
    BACKOFF_STEP,
    ERROR_HISTORY,
    HANDSHAKE_TIMEOUT,
    BindMsg,
)
from .spec import Spec
from .stream import Stream
from .types import Nonce

__all__ = [
    "CLOSE_TIMEOUT",
    "DEFAULT_JITTER",
    "Gate",
    "OP_REGISTER_DESCRIBER",
    "OP_REGISTER_FINDER",
    "OP_REGISTER_SEARCHER",
    "READY_TIMEOUT",
    "Registrar",
    "Registration",
    "RegistrationHook",
    "op_hook",
]


DEFAULT_JITTER: Final = 0.1
"""Fraction of each backoff delay drawn at random, either way.

Zero reproduces astral-go's `sig.Retry` exactly. The default is non-zero because
every local app's registrar wakes at the same instant after a node restart and
astrald's apphost pool is 32 workers wide for all of them together.
"""

READY_TIMEOUT: Final = 30.0
"""How long a caller waits for the first successful registration by default.

Long enough to cover a node that is still starting, short enough that a service
nobody can reach is reported rather than awaited forever. The registrar keeps
retrying past it; only the caller's wait ends.
"""

CLOSE_TIMEOUT: Final = 5.0
"""How long `aclose()` waits for the cancelled loop task to end.

`Service._stop_tasks` bounds the same wait and this did not, which was safe only
because every carrier's close happened to be bounded. It is the class of defect
this file was already fixed for once: a teardown that awaits something with no
bound is a teardown a peer can suspend. A loop that outlives the budget leaves
the registrar *closing* rather than closed, and a later `aclose()` waits again --
`_stop_tasks`' answer, for `_stop_tasks`' reason.

`serve.CLOSE_TIMEOUT` in value; held here so `registrar` keeps importing nothing
from `serve` (the arrow points the other way).
"""

OP_REGISTER_SEARCHER: Final = "objects.register_searcher"
OP_REGISTER_DESCRIBER: Final = "objects.register_describer"
OP_REGISTER_FINDER: Final = "objects.register_finder"


RegistrationHook = Callable[[Client], Awaitable[None]]
"""What runs after every successful (re)registration.

One coroutine, one client, no return value. A hook that raises aborts the
registration cycle and forces a reconnect, which is astral-go's semantics and is
the only safe one: a half-registered app answers queries it cannot serve.
"""


@dataclass(frozen=True, slots=True)
class Registration:
    """One handler registration: where the node dials, and what it must quote."""

    endpoint: str
    token: Nonce


def op_hook(
    op: str,
    params: Mapping[str, Any] | None = None,
    *,
    specs: Mapping[str, Spec] | None = None,
    expect_ack: bool = True,
    timeout: float | None = HANDSHAKE_TIMEOUT,
) -> RegistrationHook:
    """A hook that routes one RR op and requires its `ack`.

    The shape every `objects.register_*` op has, and design section 4.6's
    correction in executable form: open the channel, read the `ack`, close it.
    astrald's `OpRegisterSearcher` calls `mod.AddSearcher(...)`, sends `ack` and
    returns into a deferred `ch.Close()`, so the registration is **not**
    channel-scoped and holding the stream open buys nothing.

    An `error_message` arrives as `RemoteError` and aborts the cycle, which is
    what a node refusing the registration should do: astrald refuses a zero
    caller identity and refuses the node registering as itself, and an app that
    ignored either would serve searches nothing routes to it.

    `expect_ack=False` accepts any single object, for a registration op whose
    answer is not an `ack`.
    """
    encoded = querystring.encode_params(dict(specs or {}), dict(params or {}))
    query = querystring.build(op, encoded)

    async def hook(client: Client) -> None:
        answer = await client.call_one(query, timeout=timeout)
        if expect_ack and not isinstance(answer, Ack):
            raise ProtocolError(
                f"{op}: expected an ack, got "
                f"{getattr(answer, 'ASTRAL_TYPE', type(answer).__name__)!r}"
            )

    return hook


class Gate:
    """A readiness signal whose generation is replaced, never cleared.

    `snapshot()` hands back the current generation. A caller that samples it
    while the gate is open is admitted for good; a caller that samples it while
    the gate is shut waits for the **next** opening and is not woken by a stale
    one. That is astral-go's `sig.Value[chan struct{}]` in asyncio's vocabulary,
    and it is the property `Event.clear()` cannot give: clearing mutates the
    object a sampler already holds, so an admission decision made a moment ago
    is unmade behind the task that made it.
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def __repr__(self) -> str:
        return f"Gate({'open' if self._event.is_set() else 'shut'})"

    @property
    def is_open(self) -> bool:
        """Whether the current generation is open."""
        return self._event.is_set()

    def snapshot(self) -> asyncio.Event:
        """The current generation. Holding one pins that generation's answer."""
        return self._event

    def open(self) -> None:
        """Open the current generation. Every waiter on it proceeds."""
        self._event.set()

    def close(self) -> None:
        """Replace the generation with a fresh, shut one.

        A waiter on the previous generation keeps whatever answer that generation
        gave it. Nothing is cleared, so nothing is retracted.
        """
        self._event = asyncio.Event()

    async def wait(self, timeout: float | None = None) -> None:
        """Wait for the current generation to open.

        The generation is sampled once, before the wait, so a disconnect landing
        mid-wait does not move the goalpost: this call is waiting for *that*
        opening, and the next connect opens it.
        """
        generation = self._event
        try:
            async with asyncio.timeout(timeout):
                await generation.wait()
        except TimeoutError as exc:
            raise QueryTimeout(f"not registered with the node within {timeout}s") from exc


class Registrar:
    """The bind session, the handler registrations, the hooks and the reconnect.

    One registrar keeps one client's inbound registrations alive. It holds a bind
    stream on the client's persistent lane -- a long-lived stream on the query
    lane is a permit the client never gets back -- re-registers everything after
    every disconnect, and closes the bind stream last so the node's deferred
    handler sweep runs with the listener already gone.
    """

    __slots__ = (
        "_backoff_factor",
        "_backoff_max",
        "_backoff_min",
        "_bind",
        "_closed",
        "_closing",
        "_client",
        "_gate",
        "_hooks",
        "_jitter",
        "_on_connect",
        "_on_disconnect",
        "_random",
        "_registrations",
        "_starting",
        "_sweep",
        "_task",
        "connects",
        "errors",
        "faults",
    )

    def __init__(
        self,
        client: Client,
        *,
        backoff_min: float = BACKOFF_MIN,
        backoff_max: float = BACKOFF_MAX,
        backoff_factor: float = BACKOFF_FACTOR,
        jitter: float = DEFAULT_JITTER,
        on_connect: Callable[[], None] | None = None,
        on_disconnect: Callable[[BaseException | None], None] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if backoff_min < 0 or backoff_max < backoff_min:
            raise BadArgument(
                f"backoff {backoff_min}..{backoff_max}: the minimum must be "
                "non-negative and no larger than the maximum"
            )
        if backoff_factor < 1.0:
            raise BadArgument(
                f"backoff_factor={backoff_factor}: a factor below 1 shortens the "
                "delay on every failure, which is not a backoff"
            )
        if not 0.0 <= jitter < 1.0:
            raise BadArgument(f"jitter={jitter}: expected 0 <= jitter < 1")
        self._client = client
        self._backoff_min = backoff_min
        self._backoff_max = backoff_max
        self._backoff_factor = backoff_factor
        self._jitter = jitter
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._random = rng if rng is not None else random.Random()

        self._registrations: list[Registration] = []
        self._hooks: list[RegistrationHook] = []
        self._gate = Gate()
        self._bind: Stream | None = None
        self._task: asyncio.Task[None] | None = None
        # One `start()` at a time: the idempotence check cannot be the task
        # handle alone, which is set only after the first cycle has completed,
        # so two concurrent callers would each open a bind session and one of
        # them would be dropped with the node still holding it.
        self._starting = asyncio.Lock()
        self._closing = False
        self._closed = False
        # A lock rather than an event: an event a cancelled teardown sets anyway
        # tells the second caller the bind stream is gone while it is still open.
        self._sweep = asyncio.Lock()

        self.connects = 0
        """Successful registration cycles. Every reconnect adds one."""

        self.errors: deque[BaseException] = deque(maxlen=ERROR_HISTORY)
        """The last faults this registrar met, newest last. Bounded, and counted.

        A `deque`, not a list, and the same bound `Service.errors` uses -- the
        two import one constant so they cannot drift. A registrar is a
        process-lifetime object and all three sites that append here are driven
        by something outside this process: `_watch` appends one `ProtocolError`
        for **every** frame the node writes on the bind stream after the ack, so
        the growth rate is the peer's write rate; `_reconnect` appends one per
        failed cycle, which is a retained traceback every 30 s for as long as a
        node is unreachable; `_fire` appends one per faulty observer callback.
        Measured: 5,000 frames on the bind stream gave 5,000 retained exceptions
        with the registrar still reporting `ready`.

        `faults` counts what this drops, so a bounded log does not turn "the node
        wrote 5,000 frames at us" into "the node wrote 32".
        """

        self.faults = 0
        """Faults met, including the ones `errors` has already dropped."""

    def __repr__(self) -> str:
        if self._closing:
            state = "closed" if self._closed else "closing"
        else:
            state = "registered" if self._gate.is_open else "connecting"
        return (
            f"Registrar({state}, {len(self._registrations)} handlers, "
            f"{len(self._hooks)} hooks)"
        )

    # --- state ---

    @property
    def client(self) -> Client:
        return self._client

    @property
    def ready(self) -> bool:
        """Whether the node currently holds this registrar's registrations."""
        return self._gate.is_open

    @property
    def gate(self) -> Gate:
        """The readiness gate, for a caller that wants a generation of its own."""
        return self._gate

    @property
    def registrations(self) -> tuple[Registration, ...]:
        return tuple(self._registrations)

    @property
    def hooks(self) -> tuple[RegistrationHook, ...]:
        return tuple(self._hooks)

    @property
    def bind_stream(self) -> Stream | None:
        """The live bind stream, or `None` between connections."""
        return self._bind

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def closing(self) -> bool:
        return self._closing

    # --- declarations ---

    def add_hook(self, *hooks: RegistrationHook) -> None:
        """Add post-connect hooks. They run in the order they were added.

        A hook added while a cycle is live does not run until the next one.
        `register()` is what runs the hooks now, because a hook that registers a
        capability of a handler is meaningless before that handler exists.
        """
        for hook in hooks:
            if hook is None:  # pragma: no cover -- a typed caller cannot
                raise BadArgument("a registration hook cannot be None")
            self._hooks.append(hook)

    async def register(
        self, endpoint: str, token: Nonce | int, *, timeout: float | None = HANDSHAKE_TIMEOUT
    ) -> None:
        """Register one handler endpoint, now if connected and on connect if not.

        `endpoint` is the `<proto>:<addr>` string the **node** dials, so it is the
        listener's bound address and never the one it was asked for: an ephemeral
        port and a generated socket path are only known after the bind.

        With a live bind stream this registers immediately and re-runs the hooks,
        so a handler added to a running service is reachable when this returns.

        **The rollback undoes what this call did to the node, and nothing else.**
        A failure in `_attach` -- `apphost.register_handler` refused, or the
        `bind_msg` never reached the bind stream -- means the node never heard of
        the endpoint, so the record goes with it: a record the node does not
        share would be re-registered on every reconnect after being refused once.

        A failure in the **hooks** is the other case and it used to be treated as
        the same one. By then `register_handler` has executed and the token is on
        the bind stream: the node holds the registration. Dropping the SDK's
        record there left a handler live on a node the SDK had forgotten -- it
        survives until the bind session ends, costing one routing attempt per
        query (astral-docs D-13's lazy removal), and no reconnect would ever
        re-register or replace it. So the registration is **kept** and the
        exception still propagates: the caller learns the hook failed, and the
        endpoint the node is already dialing is one this registrar knows about.
        """
        registration = Registration(endpoint, Nonce(int(token)))
        if self._closing:
            raise StreamClosed(f"{self!r}: the registrar is closed")
        self._registrations.append(registration)
        stream = self._bind
        if stream is None:
            return
        try:
            await self._attach(stream, registration, timeout=timeout)
        except BaseException:
            self._registrations.remove(registration)
            raise
        await self._run_hooks()

    async def wait_ready(self, timeout: float | None = READY_TIMEOUT) -> None:
        """Wait for the current generation of registrations to be in place.

        `start()` already waited for the first one, so this is the **reconnect**
        question: a caller that must not issue a query while its own handler is
        unregistered waits here after a disconnect. Raises `QueryTimeout` on
        expiry and leaves the registrar running; only the caller's patience ends.
        """
        await self._gate.wait(timeout)

    # --- the run loop ---

    async def start(self, *, timeout: float | None = READY_TIMEOUT) -> None:
        """Register everything now, then keep it registered. Idempotent.

        **The first cycle runs in the caller's frame**, so a node that refuses
        `apphost.bind`, a token that buys no registration and a hook whose op
        does not exist are all exceptions from this call. Retrying belongs to a
        connection that worked and then dropped; retrying one that never worked
        turns a permanent misconfiguration into a service that silently answers
        nothing. astral-go draws the same line: `AppRegistrar.run` returns on a
        failed dial, and the retry wrapper is opt-in.

        Every cycle after the first -- the watch, the disconnect, the backoff,
        the re-registration, the hooks again -- belongs to the loop this starts.
        """
        async with self._starting:
            if self._closing:
                raise StreamClosed(f"{self!r}: the registrar is closed")
            if self._task is not None:
                return
            try:
                async with asyncio.timeout(timeout):
                    stream = await self._connect()
            except TimeoutError as exc:
                raise QueryTimeout(
                    f"not registered with the node within {timeout}s"
                ) from exc
            self._promote(stream)
            self._task = asyncio.get_running_loop().create_task(
                self._run(stream), name="astral-registrar"
            )

    async def _connect(self) -> Stream:
        """One full cycle: bind, register every handler, run every hook.

        The bind stream is closed on every failure path. A bind stream nobody
        owns is one of astrald's 32 apphost workers held until the node restarts,
        and a bind session with no tokens on it registers nothing anyway.
        """
        stream = await self._client.apphost.bind()
        try:
            for registration in list(self._registrations):
                await self._attach(stream, registration)
            await self._run_hooks()
        except BaseException:
            await stream.aclose()
            raise
        return stream

    def _promote(self, stream: Stream) -> None:
        """Adopt a completed cycle: hold the stream, open the gate, announce it."""
        self._bind = stream
        self.connects += 1
        self._gate.open()
        self._fire(self._on_connect)

    async def _run(self, stream: Stream) -> None:
        """Watch the bind stream, and rebuild the cycle every time it ends."""
        current = stream
        while True:
            fault = await self._watch(current)
            self._gate.close()
            self._bind = None
            await current.aclose()
            self._fire(self._on_disconnect, fault)
            if self._closing or self._client.closing:
                return
            reconnected = await self._reconnect()
            if reconnected is None:
                return
            current = reconnected
            self._promote(current)

    async def _reconnect(self) -> Stream | None:
        """Retry one full cycle until it succeeds, or until the client is gone.

        The delay grows from `backoff_min` to `backoff_max` by `backoff_factor`
        and is reset by the caller's next disconnect rather than by a bind that
        succeeded on its own: a bind that comes up and a registration that then
        fails is not progress, and resetting there would repeat the same failure
        once a second for as long as the process lives.
        """
        delay = self._backoff_min
        while True:
            await asyncio.sleep(self._delay(delay))
            if self._closing or self._client.closing:
                return None
            try:
                return await self._connect()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- a dead node is a delay
                self._record(exc)
                delay = self._grow(delay)

    async def _attach(
        self,
        stream: Stream,
        registration: Registration,
        *,
        timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> None:
        """`apphost.register_handler`, then `bind_msg` on the bind stream.

        Both, and in that order. The op is what makes the node dial this
        endpoint; the `bind_msg` is what makes the node forget it again when the
        bind session ends, which is the only eager deregistration astrald has.
        Sending the token without registering would scope nothing; registering
        without sending it leaves a handler the node drops only on the next
        failed dial (astral-docs bug D-13).
        """
        await self._client.apphost.register_handler(
            registration.endpoint, registration.token, timeout=timeout
        )
        await stream.send(BindMsg(token=registration.token), timeout=timeout)

    async def _run_hooks(self) -> None:
        """Every hook, in order. The first failure aborts the cycle."""
        for hook in list(self._hooks):
            await hook(self._client)

    async def _watch(self, stream: Stream) -> BaseException | None:
        """Read the bind stream until it ends. That end is the disconnect.

        astrald's `OpBind` sends the `ack` and then reads, writing back only an
        `error_message` when its own switch fails, so this loop is idle for as
        long as the registration is healthy. `raw_objects()` rather than the
        raising iterator: an `error_message` here is the node reporting the bind
        session's own fault, and it is worth recording rather than raising into a
        loop whose next act is to reconnect anyway.
        """
        try:
            # `aclosing` rather than a bare `async for`: `aclose()` cancels this
            # task mid-iteration, and an async generator abandoned at a
            # suspension point is finalised by the loop's own shutdown rather
            # than by the code that left it -- which is a stream still framed
            # for as long as that takes.
            async with contextlib.aclosing(stream.raw_objects()) as objects:
                async for obj in objects:
                    # `apphost.bind` sends one `ack`, which `Client.apphost.bind()`
                    # has already read. Anything after it is astrald reporting
                    # the bind session's own fault, or a frame nothing in the
                    # protocol accounts for; both are worth keeping and neither
                    # is fatal.
                    self._record(
                        ProtocolError(f"apphost.bind: unexpected object {obj!r}")
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- the reason for the reconnect
            return exc
        return None

    def _fire(self, callback: Any, *args: Any) -> None:
        """Run one lifecycle callback. A fault in it is recorded, never raised."""
        if callback is None:
            return
        try:
            callback(*args)
        except Exception as exc:  # noqa: BLE001 -- an observer never breaks the loop
            self._record(exc)

    def _record(self, exc: BaseException) -> None:
        """Keep one fault, bounded, and count it whether it was kept or not."""
        self.faults += 1
        self.errors.append(exc)

    def _grow(self, delay: float) -> float:
        """The next delay in the series, and never another zero.

        `backoff_min=0` asks for the *first* retry to be immediate, which is a
        reasonable thing to want and which eight tests in this tree ask for. It
        must not mean "retry at the speed of the event loop for the life of the
        process", and it did: `min(max, 0 * factor)` is zero however many times
        it is applied, so a zero minimum against a node that refuses dialed
        158,000 times a second and appended 108,738 exceptions -- each holding a
        traceback -- to `errors` in one second. The series therefore grows from
        `BACKOFF_STEP` when it would otherwise stay at zero. The caller's zero is
        still honoured where it was asked for: the first attempt.
        """
        return min(self._backoff_max, max(delay, BACKOFF_STEP) * self._backoff_factor)

    def _delay(self, delay: float) -> float:
        """One backoff delay, jittered either way and never negative."""
        if not self._jitter or delay <= 0:
            return delay
        spread = delay * self._jitter
        return max(0.0, delay + self._random.uniform(-spread, spread))

    # --- lifetime ---

    async def aclose(self) -> None:
        """Stop the loop, then close the bind stream **last**. Idempotent.

        The order is design section 3.8's step 4 and it is the node's, not this
        object's: closing the bind stream is what makes astrald run
        `removeHandlersByToken` for every token this session registered, and it
        must run with the listener already gone or the node dials an endpoint
        that is closing. `Service.aclose()` closes its listener and then calls
        this, which is the whole of that ordering.

        Returning means the walk was made, for a second concurrent caller as
        much as for the first. `closed` is what that walk reached -- the bind
        stream gone and the loop task ended -- so a teardown that could not
        finish leaves the registrar *closing* and a later `aclose()` resumes it.

        **The bind stream is closed on the cancelled path too**, which is why the
        run task is cancelled but not awaited before it. The wait used to come
        first, and a `CancelledError` landing on it -- a bounded shutdown, a
        parent `TaskGroup` aborting on a sibling -- left the stream open forever
        while the `finally` latched `closed=True`, so those lines never ran
        again: measured as the bind session still live on the node and one
        persistent permit never returned. Cancelling is synchronous and the run
        loop's only remaining job is to stop, so nothing is gained by waiting for
        it first, and the stream close is what the node's deregistration hangs
        on. Each step is shielded and `_closed` is latched only once both are
        done, so a teardown that could not finish leaves the registrar *closing*
        and a later `aclose()` resumes it.
        """
        if self._closed:
            return
        # Latched before anything is awaited, so a teardown cancelled a moment
        # later still stopped `register()` and `start()` taking new work.
        self._closing = True
        self._gate.close()
        async with self._sweep:
            if self._closed:
                return
            try:
                task = self._task
                if task is not None:
                    task.cancel()
                await self._close_bind()
                if task is not None:
                    # `asyncio.wait` rather than `await task`: the loop's own
                    # `CancelledError` belongs to this registrar and not to the
                    # caller's teardown, and `await` would deliver it there --
                    # while a cancellation aimed at **this** task still
                    # propagates, which is what design section 3.5 requires.
                    #
                    # Bounded, as `Service._stop_tasks` bounds the same wait: a
                    # cancelled task parked in a carrier's close is a teardown
                    # the peer decides the length of. The handle is cleared only
                    # once the task has actually ended, so a loop that outlived
                    # the budget leaves `closed` false and a later `aclose()`
                    # waits for it again rather than reporting it gone.
                    done, _ = await asyncio.shield(
                        asyncio.wait({task}, timeout=CLOSE_TIMEOUT)
                    )
                    if done:
                        self._task = None
                # The loop may have promoted a fresh bind stream between the
                # cancel and its own last breath.
                await self._close_bind()
            finally:
                self._closed = self._bind is None and self._task is None

    async def _close_bind(self) -> None:
        """Close the bind stream, shielded, and forget it only once it is gone.

        Clearing the attribute first would let a cancellation mid-close leave
        `closed` claiming a stream is released while its descriptor is open, so
        the order is close-then-forget and `Stream.aclose()` is idempotent for
        the retry that follows.

        **Forgotten on the stream's own answer, not on the call returning.** The
        two used to be the same because `Stream.aclose()` latched `closed`
        whatever happened; it no longer does, so a close that released nothing
        leaves the stream here and `closed` false, and the next `aclose()` tries
        again. Reading the call's return as the fact is the defect this file was
        fixed for once already.
        """
        stream = self._bind
        if stream is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.shield(stream.aclose())
        if stream.closed:
            self._bind = None

    async def __aenter__(self) -> "Registrar":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
