"""THE apphost session state machine, written once for every transport.

Binary IPC, WebSocket-binary, WebSocket-JSON and HTTP differ in **one method**:
`Session._open_channel()`. Everything else -- the greeting, the optional auth
exchange, the three session kinds, the failure mapping, the connection hygiene --
is written here exactly once. That was the single best structural decision in the
legacy SDK and it carries over unchanged (design section 3.4).

The state machine, from astrald's `mod/apphost/src/guest.go` rather than from the
prose::

    connect
      |- the host speaks first, unconditionally:
      |     mod.apphost.host_info_msg{Identity, Alias}
      |  (on a register-handler dial-back there is NO greeting: the first frame is
      |   mod.apphost.handle_query_msg. `Session.dialed_in` is that path.)
      |- optional: guest -> auth_token_msg{Token}
      |            host  -> auth_success_msg{GuestID} | error_msg{auth_failed}
      +- one of:
           route_query_msg      -> query_accepted_msg   POINT OF NO RETURN
                                 | query_rejected_msg{Code}
                                 | error_msg{Code}
           register_service_msg -> ack | error_msg{denied}   (stays a channel)
           attach_query_msg     -> ack | error_msg{route_not_found}

Five facts here contradict the documentation, and every one comes from reading
the server:

1. **"Exactly one of" is false on the failure paths.** After
   `error_msg{route_not_found}` or `query_rejected_msg` the connection is still a
   message channel and a second `route_query_msg` is served normally, verified
   live (astral-docs bug D-14). Only `query_accepted_msg` is a one-way door.
   **Every failure closes the connection anyway**, matching astral-go's client:
   reuse is unexercised by any reference implementation and buys nothing, while an
   extra live connection costs one of the node's 32 apphost workers.
2. **Zone travels per hop**, in `route_query_msg`. The `query` wire type has no
   `Zone` field (astral-docs bug D-25).
3. **An anonymous session is narrowed server-side**: `ZoneNetwork` is stripped
   whatever the guest sent, and no registration of any kind is permitted -- even
   on the zero identity -- because astrald checks `isAuthenticated()` first.
4. **`eos` is per-op, not universal.** `apphost.whoami` and `dir.alias_map` end
   at bare EOF (astral-docs bug D-23). Nothing in this module ever waits for an
   `eos`; termination is `eos` **or** EOF and the caller is told which.
5. **An accepted query does not always carry objects.** `objects.read` answers
   with unframed bytes, so the handover hands back a `QueryStream` over the
   transport and never assumes a framing.

Two wire types are registered and never sent. `mod.apphost.register_handler_msg`
is dead on the wire -- astrald has an `onRegisterHandlerMsg` method that
`Guest.Serve`'s dispatch switch never reaches (astral-go bug G-16) -- so it is not
declared here at all; register-handler is the `apphost.register_handler` **op**.
`mod.apphost.ping_msg` has no server handler and yields `error_msg{protocol_error}`
(astrald bug G-17); it is declared for decode completeness and never sent.

**Connection hygiene is a correctness requirement.** astrald serves apphost
connections from a fixed pool of 32 workers, runs `NewGuest(conn).Serve(ctx)`
synchronously per connection, and does not notice a peer that vanished: an
abandoned connection sits in CLOSE-WAIT and its worker never returns to the pool.
After 32 of them the node's entire app surface is dead and new clients hang
instead of failing (astrald bug G-13, design section 3.9). So every constructor
here closes the transport on every failure path including cancellation, every
failure reply closes the connection before raising, and the one path that does
**not** close -- the handover -- transfers ownership to a `QueryStream` that is
itself an async context manager.

The pool is worse than "leaks wedge it": `Guest.Serve` blocks in `Receive()` with
no read deadline and astrald's apphost config carries no idle timeout, so an open
but idle connection holds its worker exactly as a leaked one does. A connection
this SDK keeps open on purpose -- a bind session, a follow-mode stream, a
registration -- spends from the same budget of 32 as a query does.

**One reader per connection.** There is no multiplexing on the IPC leg, by
design (design section 3.7), so a session refuses a second concurrent control
read instead of letting it take frames belonging to the first. The refusal
happens before any close-on-failure path, so the caller that broke the rule is
the one that fails and the query it interrupted survives.

**Cancellation.** On an **external** `CancelledError` between sending
`route_query_msg` and receiving its reply, the session makes a shielded
best-effort attempt to route `apphost.cancel?id=<nonce>` on a **fresh**
connection with its own 2 s timeout, then re-raises. astral-go's equivalent dials
with the *already-cancelled* context, so `net.Dialer.DialContext` returns
`ctx.Err()` immediately and its cancel query is never sent (astral-go bug G-7).
That defect is not inherited: the fresh connection is opened by a task nothing
cancels, held by a strong reference so it cannot be garbage-collected mid-flight,
and drained by `flush_cancels()` -- which propagates its own cancellation rather
than swallowing it, and holds its registry per event loop, because a task belongs
to the loop that created it.

The session's **own** deadline is excluded, and the distinction is not
cosmetic: `asyncio.timeout` expires by cancelling, so both arrive at the same
`except` clause, and answering the deadline the same way opens a second
connection to the node that just failed to answer -- per timed-out query, held
for `CANCEL_TIMEOUT` -- while stretching a caller's `timeout=T` to T + 2 s. That
is demand amplification on the exhausted 32-worker pool that produces these
deadlines in the first place. Only the `asyncio.Timeout` object can tell the two
apart, so `route_query` hands it to `_exchange`.

**A lost frame boundary closes the connection**, wherever it happens and
however it was lost. A `WireError` out of a control read is one way -- a length
past `max_alloc` is refused with its payload undrained -- so the rest of the
peer's bytes are read as control messages and the peer can forge the acceptance
of a query the node never routed. **An abandoned read is the other, and it is
the quiet one**: a deadline expiring and a caller cancelling raise no
`WireError` at all, yet a read cut off between a frame's tag and its payload has
consumed half a frame and left the rest, and the peer's next whole frame is then
returned as a message the node never sent. So `_recv` asks the channel where the
reader is instead of assuming, and closes for either. `auth()`'s documented
exemption, that a refused token leaves the connection usable, is exactly one
outcome wide: `error_msg{auth_failed}` and nothing else.

**A dead peer is a domain error, whichever way it dies.** Waiting for a reply,
the peer vanishing arrives two ways -- a clean close as `EOFError` and a reset as
`ConnectionResetError`, which is an `OSError` and no `AstralError` at all -- and
both are mapped: to `NodeUnavailable` where nothing was sent and a retry is
therefore safe, and to `ProtocolError` where a query was already on the wire. A
reset is what a restarting or OOM-killed astrald produces on the TCP endpoint
that is its own default, so this is the common case, not the exotic one. The
send half of a control exchange is mapped the same way, because it is the same
dead peer arriving a few microseconds earlier -- and through the same helper,
`_mapped`, because writing the fault set twice is how the send half came to map
its deadline and not its resets. Where a clean close is a legitimate ending
rather than a missing answer -- `next_incoming`, `receive`, `read_query` -- the
`EOFError` stands and only the reset is mapped. Outside an exchange the
transport's own language stands: `Transport.write` on a raw stream reports a
dead connection as `ConnectionResetError`, on every transport.

**`aclose()` returning means closed**, at every layer of this stack and for
every caller. A second concurrent close waits for the first rather than
reporting a connection released while its descriptor is still open; a shutdown
that counted the difference would count a node worker free that is still held.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import weakref
from types import TracebackType
from typing import Any, AsyncIterator, Awaitable, Callable, Final, Sequence

from . import querystring
from .channel import Channel, open_channel
from .channel.binary import BinaryChannel
from .conn import QueryStream
from .context import Context
from .errors import (
    AstralError,
    AuthFailed,
    Denied,
    InternalError,
    NodeUnavailable,
    ProtocolError,
    QueryCanceled,
    QueryRejected,
    QueryTimeout,
    RouteNotFound,
    SessionError,
    TargetNotAllowed,
    WireError,
)
from .object import Ack, Query
from .record import record, wire
from .registry import Blueprints
from .spec import Primitive, Ptr, Slice
from .transport import Transport, default_endpoint, dial
from .types import Identity, Nonce, Zone
from .wire import DEFAULT_MAX_ALLOC

__all__ = [
    "ACCEPT_TIMEOUT",
    "ATTACH_TIMEOUT",
    "AttachQueryMsg",
    "AuthSuccessMsg",
    "AuthTokenMsg",
    "BACKOFF_FACTOR",
    "BACKOFF_MAX",
    "BACKOFF_MIN",
    "BindMsg",
    "CANCEL_TIMEOUT",
    "CONNECT_TIMEOUT",
    "Connector",
    "DEFAULT_REJECT_CODE",
    "ERROR_CODES",
    "ErrorMsg",
    "FIRST_FRAME_TIMEOUT",
    "HANDSHAKE_TIMEOUT",
    "HandleQueryMsg",
    "HostInfoMsg",
    "IncomingQueryMsg",
    "OP_BIND",
    "OP_CANCEL",
    "OP_REGISTER_HANDLER",
    "OP_WHOAMI",
    "PingMsg",
    "QUERY_TIMEOUT",
    "QueryAcceptedMsg",
    "QueryRejectedMsg",
    "REJECT_CANCELED",
    "REJECT_INTERNAL_ERROR",
    "REJECT_INVALID_QUERY",
    "REJECT_REJECTED",
    "RegisterServiceMsg",
    "RejectIncomingMsg",
    "RouteQueryMsg",
    "STREAM_IDLE_TIMEOUT",
    "Session",
    "cancel_query",
    "error_for",
    "flush_cancels",
    "pending_cancels",
]


# --- timeouts (design section 3.6) ---------------------------------------
#
# Every one of astrald's own deadlines is undocumented, and `lib/apphost.Router`
# has no query timeout at all -- an outbound Go apphost query can hang forever.
# All of them are named constants here so a caller can see and override them.

CONNECT_TIMEOUT: Final = 5.0
"""Dial **and** `host_info_msg`. A saturated node accepts the socket and never
greets, so a deadline on the connect alone would hang forever (bug G-13)."""

HANDSHAKE_TIMEOUT: Final = 5.0
"""The auth exchange, and every other single control reply."""

QUERY_TIMEOUT: Final = 60.0
"""`route_query_msg` to its reply. Mirrors astrald's undocumented
`maxQueryTimeout`, which the apphost client path does not actually apply."""

STREAM_IDLE_TIMEOUT: Final[float | None] = None
"""Between objects on an accepted stream. `None`, because follow-mode ops are
idle for as long as nothing happens."""

CANCEL_TIMEOUT: Final = 2.0
"""The shielded `apphost.cancel` dial, connect and reply together."""

ATTACH_TIMEOUT: Final = 5.0
"""`attach_query_msg` to its `ack`. astrald's `QueryAttachTimeout`, the one
deadline the docs mention, is the server side of the same 5 s."""

ACCEPT_TIMEOUT: Final = 5.0
"""Server-side deadline for an op to accept or reject, from astral-go's
`routing/incoming_query.go`. Undocumented."""

FIRST_FRAME_TIMEOUT: Final = 5.0
"""A local listener waiting for `handle_query_msg` on a connection the node dialed."""

BACKOFF_MIN: Final = 1.0
BACKOFF_MAX: Final = 30.0
BACKOFF_FACTOR: Final = 2.0

# --- op names ------------------------------------------------------------

OP_CANCEL: Final = "apphost.cancel"
OP_BIND: Final = "apphost.bind"
OP_REGISTER_HANDLER: Final = "apphost.register_handler"
OP_WHOAMI: Final = "apphost.whoami"

# --- reject codes --------------------------------------------------------
#
# From astral-go's `astral/codes.go`. 0 is success and is never a valid rejection.
# astral-go coerces rather than refusing: `IncomingQuery.RejectWithCode` rewrites
# 0 to 1 and `NewErrRejected` substitutes `DefaultRejectCode`, while
# `apps.PendingQuery.RejectWithCode` does not check at all and puts 0 on the wire.
# This SDK raises instead, because a silent rewrite hides a caller's bug and the
# third path proves the rewrite is not even applied consistently. 5 and above are
# op-specific and no meaning is claimed for them here.

REJECT_REJECTED: Final = 1
REJECT_INVALID_QUERY: Final = 2
REJECT_CANCELED: Final = 3
REJECT_INTERNAL_ERROR: Final = 4
DEFAULT_REJECT_CODE: Final = REJECT_REJECTED


# --- the control messages ------------------------------------------------
#
# Design section 1 files these under `api/apphost.py`, which is layer 3, while
# `session.py` is layer 2 and the dependency arrow points module clients ->
# session -> channel -> transport. Layer 2 cannot import layer 3, so the
# declarations live here, where the state machine that needs them is, and
# `api/apphost.py` re-exports them alongside the `apphost.*` ops.
#
# Message payloads are struct walks in declaration order: no field names, no tags,
# no padding. `auth_token_msg` and `error_msg` hand-roll a bare `String8` in
# astral-go rather than going through `Objectify`; a one-field record emits exactly
# those bytes, so the declared form and the hand-rolled form coincide.


@record("mod.apphost.host_info_msg")
class HostInfoMsg:
    """The greeting. The host sends it first on every connection, unprompted.

    `Alias` is the node's directory display name, not a stable identifier.
    """

    identity: Identity | None = wire("Identity", Ptr("identity"))
    alias: str = wire("Alias", Primitive("string8"))


@record("mod.apphost.auth_token_msg")
class AuthTokenMsg:
    """A bare `string8` token."""

    token: str = wire("Token", Primitive("string8"))


@record("mod.apphost.auth_success_msg")
class AuthSuccessMsg:
    """The authenticated guest identity."""

    guest_id: Identity | None = wire("GuestID", Ptr("identity"))


@record("mod.apphost.error_msg")
class ErrorMsg:
    """A bare `string8` code. One of `ERROR_CODES`, and unrelated to the
    `error_message` **object** that travels inside a query stream."""

    code: str = wire("Code", Primitive("string8"))


@record("mod.apphost.route_query_msg")
class RouteQueryMsg:
    """The guest's outbound query.

    A nil `Caller` is one `0x00` byte and the `anyone` identity is `0x01` plus 33
    zero bytes: both mean anonymous and they are not the same bytes. The nil form
    is what an anonymous caller sends, matching astral-go, whose `GuestID()`
    returns nil.
    """

    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))
    zone: Zone = wire("Zone", Primitive("zone"), default=Zone.ALL)
    filters: list[str] = wire("Filters", Slice("string8"))


@record("mod.apphost.query_accepted_msg")
class QueryAcceptedMsg:
    """An empty payload, and the point of no return: the connection is now the
    query's raw bidirectional bytestream."""


@record("mod.apphost.query_rejected_msg")
class QueryRejectedMsg:
    """The responder declined, with a code."""

    code: int = wire("Code", Primitive("uint8"))


@record("mod.apphost.register_service_msg")
class RegisterServiceMsg:
    """Register this connection as the handler for inbound queries to `Identity`."""

    identity: Identity | None = wire("Identity", Ptr("identity"))


@record("mod.apphost.incoming_query_msg")
class IncomingQueryMsg:
    """One inbound query pushed onto a register-service connection."""

    query_id: Nonce = wire("QueryID", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))


@record("mod.apphost.attach_query_msg")
class AttachQueryMsg:
    """Pair a freshly opened connection with a pending inbound query.

    The unguessable `QueryID` is the pairing token, so this connection completes
    the greeting and **skips auth**.
    """

    query_id: Nonce = wire("QueryID", Primitive("nonce64"))


@record("mod.apphost.reject_incoming_msg")
class RejectIncomingMsg:
    """Refuse a pending inbound query. Sent on the **registration** connection."""

    query_id: Nonce = wire("QueryID", Primitive("nonce64"))
    code: int = wire("Code", Primitive("uint8"))


@record("mod.apphost.handle_query_msg")
class HandleQueryMsg:
    """The first frame on a connection the host dialed to a registered handler.

    There is no greeting on that connection: this frame arrives first, and its
    `IPCToken` must equal the token the handler registered.
    """

    ipc_token: Nonce = wire("IPCToken", Primitive("nonce64"))
    id: Nonce = wire("ID", Primitive("nonce64"))
    caller: Identity | None = wire("Caller", Ptr("identity"))
    target: Identity | None = wire("Target", Ptr("identity"))
    query: str = wire("Query", Primitive("string16"))


@record("mod.apphost.bind_msg")
class BindMsg:
    """One handler token to unregister when the bind session ends.

    Repeatable: astrald's `OpBind` collects every `bind_msg` of the session and
    runs the removals in a `defer`. The docs read as if one message is expected.
    """

    token: Nonce = wire("Token", Primitive("nonce64"))


@record("mod.apphost.ping_msg")
class PingMsg:
    """Registered for decode completeness and never sent.

    The live node answers `error_msg{protocol_error}` and closes (astrald bug
    G-17), so this is not a keepalive and there is no keepalive.
    """


# --- the failure mapping -------------------------------------------------

ERROR_CODES: Final[dict[str, type[SessionError]]] = {
    "auth_failed": AuthFailed,
    "denied": Denied,
    "route_not_found": RouteNotFound,
    "internal_error": InternalError,
    "protocol_error": ProtocolError,
    "timeout": QueryTimeout,
    "canceled": QueryCanceled,
    "target_not_allowed": TargetNotAllowed,
}
"""Every `error_msg` code astral-go defines, and the one exception each maps to.

Exhaustive by construction: `api/apphost/error_msg.go` declares these eight and
no more. An unknown code raises the base `SessionError` carrying the code, rather
than being silently folded into a neighbouring meaning.
"""


def error_for(code: str) -> SessionError:
    """The exception for one `error_msg` code."""
    kind = ERROR_CODES.get(code)
    if kind is None:
        return SessionError(f"apphost error: {code}")
    return kind(f"apphost error: {code}")


def _type_of(obj: Any) -> str:
    return getattr(obj, "ASTRAL_TYPE", type(obj).__name__)


class _Default:
    """The sentinel for "not given", so `None` can mean the nil identity."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "DEFAULT"


_DEFAULT: Final = _Default()

# The three ways a control exchange fails -- its deadline, a clean close, a
# reset -- said once for the half that waits for a reply and once for the half
# that only sends. The wording is all that differs between them; the fault set
# and the order it is caught in are `Session._mapped`'s and are not restatable
# per call site, which is the point.
_AWAITING: Final = (
    "no reply to {what} within {timeout}s",
    "closed without answering {what}",
    "connection lost without answering {what}: {exc}",
)

_SENDING: Final = (
    "{what} was not sent within {timeout}s -- the peer stopped reading",
    "closed before {what} was sent",
    "connection lost before {what} was sent: {exc}",
)

Connector = Callable[[], Awaitable["Session"]]
"""How a session opens another one: for `apphost.cancel`, for `attach_query`, and
for a reconnect. `Session.connect` builds one from its own arguments; a session
over a transport the caller supplied is given one, or has none and then cannot
cancel."""


class Session:
    """One apphost connection, in whichever state the protocol has left it."""

    __slots__ = (
        "_transport",
        "_channel",
        "_endpoint",
        "_registry",
        "_max_alloc",
        "_connector",
        "cancel_timeout",
        "_host_id",
        "_host_alias",
        "_guest_id",
        "_greeted",
        "_spent",
        "_closing",
        "_closed",
        "_released",
        "_reading",
        "_inbound",
    )

    def __init__(
        self,
        transport: Transport,
        *,
        endpoint: str | None = None,
        registry: Blueprints | None = None,
        connector: Connector | None = None,
        greeted: bool = False,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        cancel_timeout: float | None = CANCEL_TIMEOUT,
    ) -> None:
        self._transport = transport
        self._endpoint = endpoint if endpoint is not None else transport.endpoint
        self._registry = registry
        self._max_alloc = max_alloc
        self._connector = connector
        # How long a cancelled query waits for its shielded `apphost.cancel`
        # before re-raising. The wait is deliberate -- a fire-and-forget cancel
        # can be lost when the loop stops immediately after -- and this bounds it.
        self.cancel_timeout = cancel_timeout
        self._channel = self._open_channel(transport)
        self._host_id: Identity | None = None
        self._host_alias = ""
        self._guest_id: Identity | None = None
        self._greeted = greeted
        self._spent = False
        self._closing = False
        self._closed = False
        self._released = asyncio.Event()
        self._reading = False
        self._inbound: HandleQueryMsg | None = None

    def __repr__(self) -> str:
        if self._closing:
            # The two are not one state and a `repr` that said so would be the
            # same lie `closed` was written to avoid: a close in flight is a
            # connection still open.
            state = "closed" if self._closed else "closing"
        elif self._spent:
            state = "handed over"
        elif not self._greeted:
            state = "ungreeted"
        elif self._guest_id is not None:
            state = f"authenticated as {self._guest_id.fingerprint()}"
        else:
            state = "anonymous"
        return f"Session({self._endpoint!r}, {state})"

    # --- the one seam ---

    def _open_channel(self, transport: Transport) -> Channel:
        """THE transport seam. Binary IPC, WS-binary, WS-JSON and HTTP differ here
        and nowhere else.

        `allow_unparsed` is on: a control type this SDK does not know must be
        *named* in a `ProtocolError`, not raise `BlueprintNotFound` at the framing
        layer, and in binary framing the length prefix always locates the next
        frame. The framing an accepted query's body uses is a separate decision,
        made by `QueryStream`.
        """
        return open_channel(
            transport,
            allow_unparsed=True,
            registry=self._registry,
            max_alloc=self._max_alloc,
        )

    # --- state ---

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def host_id(self) -> Identity | None:
        """The node's identity, from the greeting."""
        return self._host_id

    @property
    def host_alias(self) -> str:
        """The node's directory display name. Not a stable identifier."""
        return self._host_alias

    @property
    def guest_id(self) -> Identity | None:
        """The authenticated identity, or `None` on an anonymous session."""
        return self._guest_id

    @property
    def authenticated(self) -> bool:
        """Whether a token was accepted.

        An anonymous session may route queries when the node allows it (default
        on), has `ZoneNetwork` stripped server-side, and may not register
        anything.
        """
        return self._guest_id is not None and not self._guest_id.is_zero

    @property
    def closed(self) -> bool:
        """Whether the connection is closed, descriptor included.

        Set when `aclose()` has finished rather than when it was called: closing
        a socket with bytes still queued takes a bounded flush, and a flag that
        latched on entry would report a live connection as closed for the whole
        of it. `transport.closed` is the same fact one layer down. True whenever
        an `aclose()` has returned, whichever caller's it was.
        """
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    @property
    def spent(self) -> bool:
        """Whether the transport has been handed to a `QueryStream`."""
        return self._spent

    @property
    def supports_raw_stream(self) -> bool:
        """Whether an accepted query can become a raw bytestream.

        True for the binary framings, false for the line-oriented ones, where a
        receiver may hold a partial line. A RAW-mode op -- `objects.read` is the
        only one -- must check this rather than silently getting something else.
        """
        return isinstance(self._channel, BinaryChannel)

    # --- construction ---

    @classmethod
    async def connect(
        cls,
        endpoint: str | None = None,
        *,
        token: str | None = None,
        timeout: float | None = CONNECT_TIMEOUT,
        handshake_timeout: float | None = HANDSHAKE_TIMEOUT,
        registry: Blueprints | None = None,
        connector: Connector | None | _Default = _DEFAULT,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        cancel_timeout: float | None = CANCEL_TIMEOUT,
    ) -> "Session":
        """Dial, read the greeting, and authenticate when a token is given.

        `timeout` covers the dial **and** the greeting, because a node whose 32
        apphost workers are all busy accepts the socket and never greets: without
        this the client would hang forever instead of failing in 5 s. The auth
        exchange gets `handshake_timeout`, its own budget, exactly as design
        section 3.6 divides them -- sharing one deadline would leave auth
        whatever the dial did not spend, and would report an auth stall as a
        missing greeting, which is the single most confusable failure here.

        Every failure closes the socket before raising, including a cancellation
        landing between the connect completing and this method returning.
        """
        target = default_endpoint() if endpoint is None else endpoint
        if isinstance(connector, _Default):
            connector = functools.partial(
                cls.connect,
                target,
                token=token,
                timeout=timeout,
                handshake_timeout=handshake_timeout,
                registry=registry,
                max_alloc=max_alloc,
                cancel_timeout=cancel_timeout,
            )
        opened: Transport | None = None
        try:
            async with asyncio.timeout(timeout):
                opened = await dial(target)
                # The dial and the greeting only. Authenticating inside this
                # deadline is what made `HANDSHAKE_TIMEOUT` inert and mislabelled
                # its failure.
                session = await cls.over(
                    opened,
                    timeout=None,
                    endpoint=target,
                    registry=registry,
                    connector=connector,
                    max_alloc=max_alloc,
                    cancel_timeout=cancel_timeout,
                )
                # `over` owns the transport from here: it closed it itself on
                # every failure path, and on success the session holds it.
                opened = None
        except TimeoutError as exc:
            raise NodeUnavailable(
                f"{target}: no greeting within {timeout}s -- the node accepted the "
                "connection and never spoke, which is what a saturated 32-worker "
                "apphost pool looks like"
            ) from exc
        finally:
            if opened is not None:
                await opened.aclose()

        if token is None:
            return session
        try:
            await session.auth(token, timeout=handshake_timeout)
        except BaseException:
            # `auth()` leaves the connection usable on a refusal, deliberately.
            # A session built by `connect` hands nothing back on failure, so
            # nothing else could close it.
            await session.aclose()
            raise
        return session

    @classmethod
    async def over(
        cls,
        transport: Transport,
        *,
        token: str | None = None,
        timeout: float | None = CONNECT_TIMEOUT,
        handshake_timeout: float | None = HANDSHAKE_TIMEOUT,
        endpoint: str | None = None,
        registry: Blueprints | None = None,
        connector: Connector | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        cancel_timeout: float | None = CANCEL_TIMEOUT,
    ) -> "Session":
        """Handshake over a transport the caller already holds.

        Two budgets, as in `connect`: `timeout` for the greeting and
        `handshake_timeout` for the auth exchange.

        The transport is closed on every failure path, cancellation included: a
        session that never came up hands nothing back, so nothing else can close
        it. That includes a constructor fault -- `_open_channel()` is the one
        method every transport variant overrides, and it raises for every framing
        not yet implemented -- which is why the construction is guarded too.
        """
        try:
            session = cls(
                transport,
                endpoint=endpoint,
                registry=registry,
                connector=connector,
                max_alloc=max_alloc,
                cancel_timeout=cancel_timeout,
            )
        except BaseException:
            await transport.aclose()
            raise
        try:
            await session._greeting(timeout)
            if token is not None:
                await session.auth(token, timeout=handshake_timeout)
        except BaseException:
            await session.aclose()
            raise
        return session

    @classmethod
    def dialed_in(
        cls,
        transport: Transport,
        *,
        endpoint: str | None = None,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
    ) -> "Session":
        """A connection the **host** dialed to us. There is no greeting.

        The register-handler path: the node opens a connection to the endpoint a
        handler registered and sends `handle_query_msg` as the first frame with no
        handshake at all. Synchronous, because nothing is exchanged yet.
        """
        return cls(
            transport,
            endpoint=endpoint,
            registry=registry,
            greeted=True,
            max_alloc=max_alloc,
        )

    async def _greeting(self, timeout: float | None) -> None:
        """Read `host_info_msg`. Every fault is `NodeUnavailable` bar a wrong type."""
        try:
            async with asyncio.timeout(timeout):
                greeting = await self._recv()
        except TimeoutError as exc:
            raise NodeUnavailable(
                f"{self._endpoint}: no greeting within {timeout}s"
            ) from exc
        except EOFError as exc:
            raise NodeUnavailable(
                f"{self._endpoint}: closed before the greeting"
            ) from exc
        except OSError as exc:
            # A reset rather than a clean close: `ConnectionResetError` is what a
            # restarting, OOM-killed or crashed astrald produces on the TCP
            # endpoint that is its own default. It is not an `AstralError` at
            # all, so letting it out would put the commonest node fault outside
            # the hierarchy and outside the one class the retry decorator
            # retries. Nothing was sent, so retrying is safe.
            raise NodeUnavailable(
                f"{self._endpoint}: connection lost before the greeting: {exc}"
            ) from exc
        except WireError as exc:
            # A truncated, oversized or non-frame greeting. The node did not
            # greet, so this is the retryable class: no query has been sent.
            raise NodeUnavailable(f"{self._endpoint}: unreadable greeting: {exc}") from exc
        if not isinstance(greeting, HostInfoMsg):
            raise ProtocolError(
                f"{self._endpoint}: expected {HostInfoMsg.ASTRAL_TYPE}, "
                f"got {_type_of(greeting)}"
            )
        self._host_id = greeting.identity
        self._host_alias = greeting.alias
        self._greeted = True

    # --- auth ---

    async def auth(
        self, token: str, *, timeout: float | None = HANDSHAKE_TIMEOUT
    ) -> Identity | None:
        """Authenticate with an access token. Returns the guest identity.

        Raises `AuthFailed` on a refused token and **leaves the connection
        usable**: verified live, the node answers `error_msg{auth_failed}` and
        keeps its read loop running, so an anonymous query on the same connection
        still works. `Session.connect(token=...)` closes on this failure anyway,
        because a session that never came up hands nothing back; a direct `auth()`
        call does not, because the caller still holds the session and its context
        manager will close it.

        That exemption covers exactly one outcome, and every other failure
        closes. The live node's behaviour justifies keeping a connection whose
        *token* was refused; it says nothing about one whose reply was a framing
        fault, an unexpected type or a different error code, and on the first of
        those the byte stream is desynchronised -- the peer's next bytes are
        read as control messages and it can forge the acceptance of a query the
        node never routed. A connection that cannot be trusted is worth less
        than the node worker it holds.
        """
        self._require_live()
        keep = False
        try:
            # Both faults are `NodeUnavailable` here and only here: no query has
            # been sent on this connection, so the class's promise -- a retry
            # cannot duplicate an effect -- still holds.
            reply = await self._expect(
                timeout,
                what="auth_token_msg",
                send=AuthTokenMsg(token=token),
                expired=NodeUnavailable,
                broken=NodeUnavailable,
            )
            if isinstance(reply, AuthSuccessMsg):
                self._guest_id = reply.guest_id
                keep = True
                return self._guest_id
            if isinstance(reply, ErrorMsg):
                keep = reply.code == "auth_failed"
                raise error_for(reply.code)
            raise ProtocolError(
                f"unexpected reply to auth_token_msg: {_type_of(reply)}"
            )
        finally:
            if not keep:
                await self.aclose()

    # --- session kind 1: route a query ---

    async def route_query(
        self,
        query: str,
        *,
        context: Context | None = None,
        caller: Identity | None | _Default = _DEFAULT,
        target: Identity | str | None | _Default = _DEFAULT,
        zone: Zone | int | None = None,
        filters: Sequence[str] | None = None,
        nonce: Nonce | int | None = None,
        timeout: float | None = QUERY_TIMEOUT,
        allow_unparsed: bool = False,
        cancel_on_abort: bool = True,
    ) -> QueryStream:
        """Route one query and hand back its accepted stream.

        `caller` defaults to the session's guest identity, which is `None` on an
        anonymous session and encodes as the single `0x00` nil flag; `target`
        defaults to the host identity. Passing `None` explicitly sends the nil
        form for either. A `str` target is parsed as 66 hex characters: resolving
        a **name** needs `dir.resolve` and therefore belongs one layer up.

        `context` supplies `caller`, `zone` and `filters` for the arguments left
        out. Zone travels per hop, in this message; the `query` object has no zone
        field.

        On any reply but `query_accepted_msg` the connection is closed and the
        mapped exception raised -- the connection would in fact still be a message
        channel (bug D-14), and closing anyway matches astral-go's client. On
        acceptance the transport is handed to the returned `QueryStream` and this
        session is spent.

        Cancellation between the send and the reply routes `apphost.cancel` on a
        fresh connection, best effort and shielded, then re-raises.
        """
        self._require_live()
        # Before the try below, whose `finally` closes: a second concurrent
        # caller must fail on its own account, not tear down the first one's
        # query.
        self._require_reader()
        if context is not None:
            if isinstance(caller, _Default) and context.identity is not None:
                caller = context.identity
            if zone is None:
                zone = context.zone
            if filters is None:
                filters = context.filters

        request = RouteQueryMsg(
            nonce=Nonce.random() if nonce is None else Nonce(int(nonce)),
            caller=self._guest_id if isinstance(caller, _Default) else caller,
            target=self._host_id if isinstance(target, _Default) else _identity(target),
            query=query,
            zone=Zone.ALL if zone is None else Zone(int(zone)),
            filters=list(filters or ()),
        )
        routed = Query(
            nonce=request.nonce,
            caller=request.caller,
            target=request.target,
            query_string=query,
        )

        accepted: QueryStream | None = None
        try:
            async with asyncio.timeout(timeout) as deadline:
                reply = await self._exchange(
                    request, cancel_on_abort=cancel_on_abort, deadline=deadline
                )
            if isinstance(reply, QueryAcceptedMsg):
                accepted = self._handover(
                    routed, outbound=True, allow_unparsed=allow_unparsed
                )
                return accepted
            if isinstance(reply, QueryRejectedMsg):
                # Code 0 is success and never a valid rejection, and the
                # substitution is this SDK's own: astral-go's apphost client
                # builds `ErrRejected{Code: uint8(msg.Code)}` verbatim
                # (`lib/apphost/host.go`), so a 0 on the wire reaches a Go caller
                # as a rejection whose code means success. Only the responder-side
                # constructors coerce.
                raise QueryRejected(int(reply.code) or DEFAULT_REJECT_CODE)
            if isinstance(reply, ErrorMsg):
                raise error_for(reply.code)
            raise ProtocolError(
                f"unexpected reply to route_query_msg: {_type_of(reply)}"
            )
        except TimeoutError as exc:
            raise QueryTimeout(
                f"{query}: no reply within {timeout}s (this deadline is the "
                "client's; the node has none on this path)"
            ) from exc
        finally:
            if accepted is None:
                await self.aclose()

    async def _exchange(
        self,
        request: RouteQueryMsg,
        *,
        cancel_on_abort: bool,
        deadline: asyncio.Timeout | None = None,
    ) -> Any:
        """Send `route_query_msg` and read its one reply, cancel-aware throughout.

        The cancel window covers the send as well as the wait. A frame is written
        whole and synchronously, so cancellation can only land in the `drain()`
        that follows it -- by which point the query is in the socket buffer and
        the node will very probably route it. A cancel naming a nonce the node
        never saw is answered `query not found` and costs nothing, so covering
        the send is free and the alternative loses queries.

        **Our own deadline is not a caller's cancellation, and only the timeout
        object can tell them apart** -- `asyncio.timeout` expires by cancelling
        the task, so both arrive here as `CancelledError`. Answering the
        deadline with `apphost.cancel` would dial a second connection into the
        node whose non-answer produced the deadline in the first place, holding
        it for `CANCEL_TIMEOUT`: the SDK would amplify demand on the very
        32-worker pool whose exhaustion is the likeliest cause (design section
        3.9), and `route_query(timeout=T)` would return after T + 2 s rather
        than after T. The node either never saw the query or is not answering
        anything, and closing this connection -- which the caller's `finally`
        does -- already tears the query down at the node.
        """
        try:
            await self._channel.send(request)
            return await self._recv()
        except asyncio.CancelledError:
            if cancel_on_abort and not (deadline is not None and deadline.expired()):
                await _best_effort_cancel(
                    self._connector, request.nonce, timeout=self.cancel_timeout
                )
            raise
        except EOFError as exc:
            raise ProtocolError(
                "the node closed the connection without answering the query"
            ) from exc
        except OSError as exc:
            # A reset, not a clean close. The query *was* sent, so this is not
            # the retryable class however much it looks like a dial failure.
            raise ProtocolError(
                f"the connection was lost without answering the query: {exc}"
            ) from exc

    def _handover(
        self, query: Query, *, outbound: bool, allow_unparsed: bool
    ) -> QueryStream:
        """The point of no return: stop framing, hand the transport onward.

        A no-op handover of the identical `Transport` object, so the first bytes
        of the raw stream -- which may have arrived in the same write as the
        acceptance frame -- are still in the one buffer that was there before.
        The session keeps no claim on it: `aclose()` will not close a transport
        that now belongs to a `QueryStream`.
        """
        transport = self._channel.detach()
        self._spent = True
        return QueryStream(
            transport,
            query,
            outbound=outbound,
            endpoint=self._endpoint,
            registry=self._registry,
            allow_unparsed=allow_unparsed,
            max_alloc=self._max_alloc,
        )

    async def cancel(
        self,
        nonce: Nonce | int,
        *,
        cause: str | None = None,
        timeout: float | None | _Default = _DEFAULT,
    ) -> bool:
        """Cancel an en-route query by nonce, on a fresh connection.

        The protocol has no in-band cancel: a query is cancelled by routing
        `apphost.cancel?id=<nonce>` from a **separate** session, after which the
        original session reports `error_msg{canceled}`. Returns whether the cancel
        query was accepted, and never raises.
        """
        if self._connector is None:
            return False
        return await cancel_query(
            self._connector,
            Nonce(int(nonce)),
            cause=cause,
            timeout=self.cancel_timeout if isinstance(timeout, _Default) else timeout,
        )

    # --- session kind 2: the host dials us (register-handler) ---

    async def read_query(
        self,
        *,
        token: Nonce | int | None = None,
        timeout: float | None = FIRST_FRAME_TIMEOUT,
    ) -> HandleQueryMsg:
        """Read the `handle_query_msg` that opens a dialed-in connection.

        Validation follows astral-go's `apps/handler.go`: a wrong first type is
        answered `error_msg{protocol_error}` and a token mismatch
        `error_msg{denied}`, both followed by a close. Neither is fatal to the
        listener that accepted the connection -- it drops this connection and
        keeps accepting -- which is why the exception is raised after the
        connection is already closed.
        """
        self._require_live()
        self._require_reader()
        try:
            async with asyncio.timeout(timeout):
                first = await self._recv()
        except TimeoutError as exc:
            await self.aclose()
            raise ProtocolError(
                f"no {HandleQueryMsg.ASTRAL_TYPE} within {timeout}s"
            ) from exc
        except OSError as exc:
            await self.aclose()
            raise ProtocolError(
                f"connection lost before {HandleQueryMsg.ASTRAL_TYPE}: {exc}"
            ) from exc
        except BaseException:
            await self.aclose()
            raise

        if not isinstance(first, HandleQueryMsg):
            await self._refuse(ErrorMsg(code="protocol_error"))
            raise ProtocolError(
                f"expected {HandleQueryMsg.ASTRAL_TYPE}, got {_type_of(first)}"
            )
        if token is not None and int(first.ipc_token) != int(token):
            await self._refuse(ErrorMsg(code="denied"))
            raise Denied("handle_query_msg: ipc token mismatch")
        self._inbound = first
        return first

    async def accept_query(
        self,
        *,
        allow_unparsed: bool = False,
        timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> QueryStream:
        """Answer `ack` and **then** hand back the stream.

        astral-go holds a write lock until the `ack` has been written so an op
        handler cannot emit response bytes first. The same invariant falls out of
        not giving the handler the stream until the `ack` is on the wire, which
        needs no lock at all.

        `timeout` bounds the `ack`. It is a send and therefore blocks on the
        peer's receive window, so an acceptance nobody reads must fail rather
        than hold this connection -- and its node worker -- open indefinitely.
        """
        self._require_live()
        if self._inbound is None:
            raise RuntimeError("accept_query: no handle_query_msg has been read")
        msg = self._inbound
        try:
            await self._send(Ack(), timeout, what="ack")
        except BaseException:
            await self.aclose()
            raise
        return self._handover(
            Query(
                nonce=msg.id,
                caller=msg.caller,
                target=msg.target,
                query_string=msg.query,
            ),
            outbound=False,
            allow_unparsed=allow_unparsed,
        )

    async def reject_query(
        self, code: int = DEFAULT_REJECT_CODE, *, timeout: float | None = HANDSHAKE_TIMEOUT
    ) -> None:
        """Decline the inbound query with a code, then close.

        Code 0 is success and is not a rejection. astral-go coerces it to the
        default reject code on two of its three paths and sends it unchanged on
        the third; this raises, because a silent rewrite hides a caller's bug.
        """
        if code == 0:
            raise ValueError("reject code 0 is success, not a rejection")
        await self._fail(QueryRejectedMsg(code=code), timeout=timeout)

    async def skip_query(self, *, timeout: float | None = HANDSHAKE_TIMEOUT) -> None:
        """Decline by claiming no route, then close.

        The caller sees `route_not_found`, as if this handler had never been
        registered, which is what astral-go's `Skip()` sends.
        """
        await self._fail(ErrorMsg(code="route_not_found"), timeout=timeout)

    async def _fail(
        self, message: Any, *, timeout: float | None = HANDSHAKE_TIMEOUT
    ) -> None:
        """Send one refusal inside a deadline and close, whatever the send does.

        The deadline is the point: a refusal sent to a peer that has stopped
        reading would otherwise never return, and the close that follows it --
        the whole reason a refusal is worth sending -- would never run.
        """
        try:
            await self._send(message, timeout, what=_type_of(message))
        finally:
            await self.aclose()

    async def _refuse(
        self, message: Any, *, timeout: float | None = HANDSHAKE_TIMEOUT
    ) -> None:
        """`_fail`, where the refusal not arriving is not the news.

        `read_query` already knows why it is failing and says so on the next
        line; a dead peer swallowing the courtesy reply must not replace that
        diagnosis with a worse one -- "the refusal was not sent" tells a caller
        nothing about the token that did not match. `reject_query` and
        `skip_query` raise instead, because there the refusal *is* the whole
        call. The close happens either way: `_fail` does it in a `finally`.
        """
        with contextlib.suppress(AstralError):
            await self._fail(message, timeout=timeout)

    # --- session kind 3: register-service (experimental on IPC) ---

    async def register_service(
        self,
        identity: Identity | None = None,
        *,
        timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> Identity | None:
        """Register this connection as the handler for queries to `identity`.

        The connection **stays a message channel**: the node then pushes one
        `incoming_query_msg` per inbound query, which `next_incoming()` reads.

        Experimental over IPC, and register-handler is the supported inbound path
        there. astrald's IPC worker closes the guest connection unconditionally
        after `Guest.Serve` returns -- `mod/apphost/src/worker.go` calls
        `conn.Close()` with no guard -- while the WebSocket path guards on the
        `donated` flag `onAttachQueryMsg` sets, so a donated responder stream over
        IPC looks closed at once (design risk R-16); and the IPC guest channel is
        built **without** locked writes while the WebSocket one is not, so
        concurrent `incoming_query_msg` pushes from arbitrary routing goroutines
        can interleave one frame's three writes (astrald bug G-12).

        An anonymous session is refused locally. astrald checks
        `isAuthenticated()` before anything else and answers `denied` even for the
        zero identity, so the round trip is a certainty, and a certain refusal is
        not worth one of 32 node workers.
        """
        self._require_live()
        self._require_reader()
        if not self.authenticated:
            raise Denied(
                "an anonymous session cannot register a service: astrald refuses "
                "every registration from a token-less guest, the zero identity "
                "included"
            )
        target = self._guest_id if identity is None else identity
        registered = False
        try:
            reply = await self._expect(
                timeout,
                what="register_service_msg",
                send=RegisterServiceMsg(identity=target),
            )
            if isinstance(reply, Ack):
                registered = True
                return target
            if isinstance(reply, ErrorMsg):
                raise error_for(reply.code)
            raise ProtocolError(
                f"unexpected reply to register_service_msg: {_type_of(reply)}"
            )
        finally:
            # Every failure closes, the deadline and a dead connection included:
            # a registration that never came up is a connection nobody owns, and
            # an unowned connection holds one of the node's 32 workers until the
            # node restarts.
            if not registered:
                await self.aclose()

    async def next_incoming(
        self, *, timeout: float | None = None
    ) -> IncomingQueryMsg:
        """The next inbound query pushed on a register-service connection.

        Raises `EOFError` when the node closes the registration, and
        `ProtocolError` when it is lost rather than closed -- a reset is a fault
        and is not passed off as the orderly end an `EOFError` means. The default
        deadline is `None`: a registration is idle for as long as nothing arrives,
        and a deadline here would tear down a working registration.

        A frame that fails to decode is fatal, is not resynchronised past, and
        **closes the connection**. astrald's IPC guest channel writes a frame in
        three unlocked calls, so concurrent pushes can interleave them (bug
        G-12); a reader that resynchronised would turn corrupt framing into
        plausible garbage. Closing is the other half of that: astrald's
        `Guest.Serve` then blocks in `Receive()` forever -- there is no read
        deadline and its apphost config has no idle timeout -- so a caller that
        logged the fault and moved on would burn one of the node's 32 workers
        permanently.

        A deadline that finds the reader **at a frame boundary** does not close:
        a registration parked between pushes is healthy, and the deadline is the
        caller's own patience. One that lands **inside** a frame does close, and
        the difference is established rather than assumed -- `_recv` asks the
        channel where the reader is. Half a frame plus whatever the peer sends
        next is a message the node never wrote, and this method's whole output is
        an identity the app will authorise against.
        """
        self._require_live()
        try:
            async with asyncio.timeout(timeout):
                message = await self._recv()
        except TimeoutError as exc:
            raise QueryTimeout(
                f"{self._endpoint}: no inbound query on the registration within "
                f"{timeout}s"
            ) from exc
        except WireError:
            await self.aclose()
            raise
        except OSError as exc:
            await self.aclose()
            raise ProtocolError(
                f"{self._endpoint}: the registration connection was lost: {exc}"
            ) from exc
        if isinstance(message, IncomingQueryMsg):
            return message
        if isinstance(message, ErrorMsg):
            raise error_for(message.code)
        raise ProtocolError(f"unexpected message on a registration: {_type_of(message)}")

    async def incoming(self) -> AsyncIterator[IncomingQueryMsg]:
        """Every inbound query until the registration ends."""
        while True:
            try:
                yield await self.next_incoming()
            except EOFError:
                return

    async def reject_incoming(
        self,
        query_id: Nonce | IncomingQueryMsg,
        code: int = DEFAULT_REJECT_CODE,
        *,
        timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> None:
        """Refuse a pending inbound query, on the registration connection.

        The caller sees `query_rejected_msg{code}`. Ignoring the push instead
        yields `route_not_found` for the caller after the node's 5 s attach
        deadline.

        `timeout` bounds the send, which is the only thing this method does and
        the thing that blocks: a node that has stopped reading the registration
        would otherwise pin the refusal forever. The registration itself is left
        open, because it belongs to the caller and one unsent refusal is not
        evidence that every later push is unanswerable.
        """
        self._require_live()
        if code == 0:
            raise ValueError("reject code 0 is success, not a rejection")
        ident = query_id.query_id if isinstance(query_id, IncomingQueryMsg) else query_id
        await self._send(
            RejectIncomingMsg(query_id=Nonce(int(ident)), code=code),
            timeout,
            what="reject_incoming_msg",
        )

    async def attach_query(
        self,
        query_id: Nonce | int | IncomingQueryMsg,
        *,
        timeout: float | None = ATTACH_TIMEOUT,
        caller: Identity | None = None,
        target: Identity | None = None,
        query: str = "",
        allow_unparsed: bool = False,
    ) -> QueryStream:
        """Attach this connection to a pending inbound query as its responder.

        Called on a **fresh** session that completed the greeting and **skipped
        auth**: the unguessable `QueryID` is the pairing token. On `ack` the
        connection becomes the responder bytestream; an unknown or expired ID
        answers `error_msg{route_not_found}` and the connection is closed.

        Passing the `incoming_query_msg` rather than a bare id carries the caller,
        the target and the query string onto the stream, so the responder stream
        names the query it answers.
        """
        self._require_live()
        self._require_reader()
        if isinstance(query_id, IncomingQueryMsg):
            caller = query_id.caller if caller is None else caller
            target = query_id.target if target is None else target
            query = query_id.query if not query else query
            ident = Nonce(int(query_id.query_id))
        else:
            ident = Nonce(int(query_id))

        accepted: QueryStream | None = None
        try:
            reply = await self._expect(
                timeout,
                what="attach_query_msg",
                send=AttachQueryMsg(query_id=ident),
            )
            if isinstance(reply, Ack):
                accepted = self._handover(
                    Query(
                        nonce=ident, caller=caller, target=target, query_string=query
                    ),
                    outbound=False,
                    allow_unparsed=allow_unparsed,
                )
                return accepted
            if isinstance(reply, ErrorMsg):
                raise error_for(reply.code)
            raise ProtocolError(
                f"unexpected reply to attach_query_msg: {_type_of(reply)}"
            )
        finally:
            if accepted is None:
                await self.aclose()

    # --- apphost.bind ---

    async def bind(
        self,
        *tokens: Nonce | int,
        timeout: float | None = QUERY_TIMEOUT,
        ack_timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> QueryStream:
        """Open a bind session and register handler tokens against its lifetime.

        `apphost.bind` is an ordinary op: route it, read the `ack` off the
        accepted stream, then send one `bind_msg` per handler token. The node
        removes every handler registered under those tokens when this stream
        closes, which is what makes handler registration crash-safe. Repeatable:
        the returned stream stays open and accepts further `bind_msg` objects.

        The exchange runs over an accepted stream and is a session exchange even
        so: the `ack` and the `bind_msg` tokens are messages this method demands
        and waits for, not bytes a caller chose to write, so every way they can
        fail lands inside the hierarchy. `QueryStream`'s own raw API is where the
        transport's language stands instead.
        """
        stream = await self.route_query(querystring.build(OP_BIND), timeout=timeout)
        try:
            try:
                try:
                    async with asyncio.timeout(ack_timeout):
                        first = await stream.receive()
                except TimeoutError as exc:
                    # The query was accepted; this is the op failing to answer,
                    # and it is reported in the same vocabulary as every other
                    # reply that never came rather than as the caller's own
                    # deadline.
                    raise QueryTimeout(
                        f"{OP_BIND}: no ack within {ack_timeout}s"
                    ) from exc
                if not isinstance(first, Ack):
                    raise ProtocolError(
                        f"apphost.bind: expected ack, got {_type_of(first)}"
                    )
                try:
                    # Inside a deadline like every other send: `apphost.bind` is
                    # a long-lived stream, and a node that stopped reading it
                    # would otherwise pin this call with the handler tokens
                    # unregistered.
                    async with asyncio.timeout(ack_timeout):
                        for token in tokens:
                            await stream.send(BindMsg(token=Nonce(int(token))))
                except TimeoutError as exc:
                    raise QueryTimeout(
                        f"{OP_BIND}: the bind stream stopped reading within "
                        f"{ack_timeout}s"
                    ) from exc
                return stream
            except EOFError as exc:
                raise ProtocolError(
                    f"{OP_BIND}: the bind stream closed before the tokens were "
                    "registered"
                ) from exc
            except OSError as exc:
                # Under both deadline arms, which have already turned every
                # expiry into a `QueryTimeout`: the builtin `TimeoutError` is an
                # `OSError` and this arm would otherwise swallow one.
                raise ProtocolError(
                    f"{OP_BIND}: the bind stream was lost before the tokens were "
                    f"registered: {exc}"
                ) from exc
        except BaseException:
            await stream.aclose()
            raise

    # --- the message channel ---

    async def receive(self) -> Any:
        """One control message. `EOFError` at a clean end of stream.

        Exposed because the failure paths leave the connection a message channel
        and because the serving layer drives the same connection. After the
        handover it raises: the connection is a bytestream by then.

        A clean close is an `EOFError` and a reset is a `ProtocolError`, the
        same split `next_incoming` makes on the same bytes: the peer hanging up
        between messages is an ending, the peer dying mid-connection is a fault,
        and a fault belongs in the hierarchy. The connection is closed on the
        reset because there is nothing left to talk to and the descriptor is
        worth more free.
        """
        self._require_live()
        try:
            return await self._recv()
        except OSError as exc:
            # No `TimeoutError` arm above this one because nothing below raises
            # one: a caller's `asyncio.timeout` expiring arrives here as
            # `CancelledError` and becomes a `TimeoutError` in the caller's own
            # frame, well outside this `except`.
            await self.aclose()
            raise ProtocolError(
                f"{self._endpoint}: the connection was lost: {exc}"
            ) from exc

    async def send(self, obj: Any, *, timeout: float | None = None) -> None:
        """One control message, in exactly one `write()`.

        `timeout` bounds the send, and defaults to `None` because this is the
        escape hatch the serving layer drives: the methods above name what their
        deadline covers, and a caller reaching for this one owns the question
        itself. A peer that stops reading pins an unbounded send indefinitely,
        so a long-lived caller should pass one.
        """
        self._require_live()
        await self._send(obj, timeout, what=_type_of(obj))

    @contextlib.asynccontextmanager
    async def _mapped(
        self,
        timeout: float | None,
        *,
        what: str,
        phrases: tuple[str, str, str] = _AWAITING,
        expired: type[AstralError] = QueryTimeout,
        broken: type[AstralError] = ProtocolError,
    ) -> AsyncIterator[None]:
        """THE deadline and THE dead-peer mapping of every control exchange.

        One place, not one per half, because one per half is how the halves came
        apart: the reply half mapped the reset and the send half mapped only the
        deadline, so a peer that vanished escaped as a bare
        `ConnectionResetError` -- an `OSError`, no `AstralError` at all -- from
        five public methods, and a caller catching `AstralError`, the documented
        catch-all, missed the commonest way a node dies. A fault set written
        once cannot drift.

        The three faults, in the order they are caught:

        - the deadline, which bounds the send as much as the wait, because
          `Channel.send` ends in `Transport.drain()` whose entire job is to wait
          for the peer's receive window and a peer that stops reading pins it
          for as long as it likes;
        - a clean close, `EOFError`;
        - a reset, `ConnectionResetError` and its siblings.

        **`TimeoutError` is caught first and that is load-bearing**: the builtin
        `TimeoutError` *is* an `OSError`, so an `except OSError` placed ahead of
        it swallows the expiry and reports a deadline as a dead peer.

        `expired` and `broken` are `NodeUnavailable` only where the message
        belongs to the handshake: that class promises the query was never sent
        and so is safe to retry, and a control message that *was* sent does not
        qualify.
        """
        try:
            async with asyncio.timeout(timeout):
                yield
        except TimeoutError as exc:
            raise expired(
                f"{self._endpoint}: " + phrases[0].format(what=what, timeout=timeout)
            ) from exc
        except EOFError as exc:
            raise broken(f"{self._endpoint}: " + phrases[1].format(what=what)) from exc
        except OSError as exc:
            raise broken(
                f"{self._endpoint}: " + phrases[2].format(what=what, exc=exc)
            ) from exc

    async def _expect(
        self,
        timeout: float | None,
        *,
        what: str,
        send: Any | None = None,
        expired: type[AstralError] = QueryTimeout,
        broken: type[AstralError] = ProtocolError,
    ) -> Any:
        """One exchange -- the send **and** its one reply -- inside one deadline."""
        async with self._mapped(
            timeout, what=what, expired=expired, broken=broken
        ):
            if send is not None:
                await self._channel.send(send)
            return await self._recv()

    async def _send(self, message: Any, timeout: float | None, *, what: str) -> None:
        """One control message with no reply, inside its own deadline.

        Every fault `_expect` maps is mapped here too, through the same helper.
        A refusal or a rejection that never left the socket is not a refusal,
        and the peer that never received it is dead however it died.
        """
        async with self._mapped(timeout, what=what, phrases=_SENDING):
            await self._channel.send(message)

    async def _recv(self) -> Any:
        """One control frame, from the one reader a session is allowed.

        There is no multiplexing on the IPC leg, by design (design section 3.7):
        a second concurrent reader takes frames belonging to the first. Refusing
        is not tidiness. Without the guard the second caller fails deep inside
        the framing layer -- `RuntimeError` out of `StreamReader` -- and its own
        failure handling then closes the connection under the first, so one
        misuse destroys one valid in-flight query.

        **A lost frame boundary closes the connection**, and it is lost two
        ways.

        A `WireError` out of the channel is the loud one: a reply declaring four
        gigabytes is refused after the tag and the length have been consumed and
        its payload is never drained, so every byte after it is read as a
        control message. A session left open there is not merely useless, it is
        forgeable -- the peer's next bytes become a `query_accepted_msg` for a
        query the node never routed, and the caller writes its request body into
        the apphost control channel. Closing is also the only answer that frees
        the node's worker; astrald's `Guest.Serve` would otherwise sit in
        `Receive()` with no read deadline forever (bug G-13).

        **An abandoned read is the quiet one, and it forges the same frame.** A
        deadline expiring and a caller cancelling both arrive as
        `CancelledError`, no `WireError` is raised, and a read cut off between a
        frame's tag and its payload has consumed part of the frame and left the
        rest. Measured: a peer sends one push's tag and length and stops,
        `next_incoming(timeout=0.5)` reports the deadline, and the peer's next
        whole frame is then returned as an `incoming_query_msg` the node never
        routed -- attacker-chosen caller, target and query string, handed
        straight to the app's dispatch. So the boundary is asked about rather
        than assumed: the channel knows whether it stranded anything, and a read
        abandoned anywhere but at a boundary closes exactly as a `WireError`
        does. A read abandoned *at* a boundary costs nothing and the connection
        survives it, which is what makes an idle registration's deadline safe.
        """
        self._require_reader()
        self._reading = True
        try:
            return await self._channel.receive()
        except WireError:
            await self.aclose()
            raise
        except BaseException:
            if not self._channel.at_frame_boundary:
                await self.aclose()
            raise
        finally:
            self._reading = False

    def _require_reader(self) -> None:
        """Refuse a second concurrent read, **before** any close-on-failure path.

        Checked at the entry of every method that closes on failure, so the
        caller that broke the rule is the one that fails and the connection the
        rule protects stays open.
        """
        if self._reading:
            raise RuntimeError(
                f"{self!r}: a control read is already in flight; one connection "
                "carries one exchange at a time, and concurrency is more "
                "connections"
            )

    def _require_live(self) -> None:
        if self._closing:
            raise RuntimeError(f"{self!r}: the session is closed")
        if self._spent:
            raise RuntimeError(
                f"{self!r}: the connection became a query stream and is no longer "
                "a message channel"
            )
        if not self._greeted:
            raise RuntimeError(f"{self!r}: the greeting has not been read")

    # --- lifetime ---

    async def aclose(self) -> None:
        """Close the connection. Idempotent, and never raises on a fault.

        **Returning means closed**, for every caller and not only for the first
        one. A concurrent second call does not close the connection twice and
        does not walk away either: it waits for the first close to finish, so
        `closed` is true whenever this returns. The alternative was measured --
        a second caller returned in 0.00 s reporting `closed=False` with the
        descriptor still open, while the first was two seconds into a bounded
        flush -- and a shutdown that believed it would have reported a node
        worker released that was still held.

        `_closing` latches first and `_closed` only once the transport is
        actually gone, so `closed` stays a fact rather than an intention.

        A no-op after the handover: the transport then belongs to the
        `QueryStream`, which closes it.
        """
        if self._closing:
            await self._released.wait()
            return
        self._closing = True
        try:
            with contextlib.suppress(Exception):
                # Detached after a handover, where this is already a no-op.
                await self._channel.aclose()
        finally:
            self._closed = True
            self._released.set()

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def _identity(value: Identity | str | None) -> Identity | None:
    """Coerce a target. A 66-hex string is parsed; a name is not resolvable here."""
    if value is None or isinstance(value, Identity):
        return value
    return Identity.parse(value)


# --- the cancel path -----------------------------------------------------
#
# astral-go reacts to a cancelled context by dialing with that same cancelled
# context, so `net.Dialer.DialContext` returns immediately and the cancel query is
# never sent (bug G-7). The fix is a connection nothing cancels: a task with its
# own deadline, held by a strong reference so the garbage collector cannot destroy
# it mid-flight, awaited through a shield so a second cancellation cannot abandon
# it either.

_CANCELS: Final[
    "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, set[asyncio.Task[bool]]]"
] = weakref.WeakKeyDictionary()
"""In-flight cancel tasks, **per event loop**.

A task belongs to the loop that created it: awaiting one from another loop
raises `RuntimeError` instead of draining it, and cancelling one from another
thread bypasses `call_soon_threadsafe`. A registry shared across loops therefore
reports work as finished that no loop ever finished, and reaches into a foreign
loop's tasks. Keyed weakly so a finished loop's entry disappears with it.
"""


def _cancels() -> set[asyncio.Task[bool]]:
    """The running loop's cancel tasks, created on first use."""
    loop = asyncio.get_running_loop()
    pending = _CANCELS.get(loop)
    if pending is None:
        pending = set()
        _CANCELS[loop] = pending
    return pending


def _track_cancel(task: asyncio.Task[bool]) -> None:
    """Hold the one strong reference to a cancel task until it finishes.

    A task nobody references can be garbage-collected before it runs, which would
    leak the connection it was about to close.
    """
    pending = _cancels()
    pending.add(task)
    task.add_done_callback(pending.discard)


async def cancel_query(
    connector: Connector,
    nonce: Nonce | int,
    *,
    cause: str | None = None,
    timeout: float | None = CANCEL_TIMEOUT,
) -> bool:
    """Route `apphost.cancel?id=<nonce>` on a fresh session. Never raises.

    Returns whether the node accepted the cancel query. `zone=device`, matching
    astral-go: cancelling a query is a local operation and must never leave the
    machine. The accepted stream is closed without reading its `ack`, because the
    op has already cancelled the query by the time it answers.
    """
    params: dict[str, Any] = {"id": Nonce(int(nonce))}
    if cause:
        params["cause"] = cause
    query = querystring.build(OP_CANCEL, params)
    try:
        async with asyncio.timeout(timeout):
            session = await connector()
            try:
                stream = await session.route_query(
                    query,
                    zone=Zone.DEVICE,
                    timeout=None,
                    cancel_on_abort=False,
                )
            finally:
                # A no-op when the query was accepted -- the stream owns the
                # transport now -- and the close that matters when it was not.
                await session.aclose()
            await stream.aclose()
            return True
    except Exception:
        return False


async def _best_effort_cancel(
    connector: Connector | None,
    nonce: Nonce,
    *,
    timeout: float | None = CANCEL_TIMEOUT,
    cause: str | None = None,
) -> bool:
    """Attempt a cancel from inside a cancellation. Shielded, tracked, bounded.

    A session with no connector -- one built over a transport the caller supplied
    and gave no way to reopen -- cannot cancel, and says so by returning False
    rather than by pretending.
    """
    if connector is None:
        return False
    task = asyncio.get_running_loop().create_task(
        cancel_query(connector, nonce, cause=cause, timeout=timeout),
        name=f"astral-cancel-{nonce}",
    )
    _track_cancel(task)
    with contextlib.suppress(Exception):
        return await asyncio.shield(task)
    return False


def pending_cancels() -> int:
    """How many best-effort cancels are still in flight on the running loop.

    Per loop, because that is the only scope in which the answer is actionable:
    a task on another loop is one this loop can neither await nor cancel. Raises
    outside a loop rather than reporting a reassuring zero for a loop it never
    looked at.
    """
    return len(_cancels())


async def flush_cancels(timeout: float | None = None) -> None:
    """Await every outstanding best-effort cancel on this loop.

    Shutdown calls this so a cancel dialed during teardown is not abandoned
    half-open, and tests call it to make the path deterministic. A cancel that
    failed is not an error here: it was best effort by construction. A
    cancellation of **this** call is, and propagates: the deadline argument, an
    enclosing `asyncio.timeout` and a `TaskGroup` abort all arrive that way, and
    swallowing one would silently void a caller's deadline.

    The deadline expiring is a `QueryTimeout`, in the vocabulary every other
    deadline in this module speaks. A bare `TimeoutError` is outside the
    hierarchy, so a caller catching `AstralError` around its shutdown would miss
    the one thing this call reports.
    """
    try:
        await _flush_cancels(timeout)
    except TimeoutError as exc:
        raise QueryTimeout(
            f"{len(_cancels())} best-effort cancels still in flight after {timeout}s"
        ) from exc


async def _flush_cancels(timeout: float | None) -> None:
    async with asyncio.timeout(timeout):
        pending = _cancels()
        while pending:
            task = next(iter(pending))
            try:
                # Shielded, and this is load-bearing rather than defensive:
                # `await task` delegates *this* task's cancellation into the
                # awaited one, so the CancelledError would always arrive with
                # `task.cancelled()` true and every deadline around this call
                # would be swallowed. The registry holds the strong reference,
                # so shielding orphans nothing.
                await asyncio.shield(task)
            except asyncio.CancelledError:
                # The cancel task itself being cancelled is expected during
                # teardown; being cancelled ourselves is not the same thing.
                if _cancel_requested() or not task.cancelled():
                    raise
            except Exception:
                pass
            finally:
                # Only a task that actually finished is forgotten. Discarding a
                # live one would drop the single strong reference keeping it --
                # and the connection it holds -- alive.
                if task.done():
                    pending.discard(task)


def _cancel_requested() -> bool:
    """Whether cancellation has been requested of the calling task.

    The one sound discriminator: an awaited task's own state cannot tell "the
    cancel task was cancelled" from "we were cancelled and asyncio passed it on".
    """
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0
