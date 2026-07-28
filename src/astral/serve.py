"""Inbound serving: the register-handler listener, the op table, `PendingQuery`.

The node dials **us**. That is design section 4.3's primary inbound path, it is
what astral-go's `lib/apps` implements, it survives reconnects, it needs no
per-query attach round trip, it carries many handlers under one bind, and
`asyncio.start_server` fits it exactly. The sequence, from astrald's
`mod/apphost/src/{op_register_handler,ipc_handler}.go` rather than from prose::

    1. bind a local listener and pick a random Nonce token
    2. START THE ACCEPT LOOP FIRST
    3. apphost.bind        -> ack; the stream scopes handler lifetime  (registrar.py)
    4. apphost.register_handler?endpoint=&token=  -> ack; local-only   (registrar.py)
    5. mod.apphost.bind_msg{Token} on the bind stream, one per token   (registrar.py)
    6. post-connect hooks: objects.register_searcher / _describer / _finder
    7. per inbound query the node DIALS the endpoint and sends, as the FIRST
       FRAME and with NO handshake, mod.apphost.handle_query_msg
    8. validate IPCToken; a mismatch is error_msg{denied}, a wrong first type is
       error_msg{protocol_error}; neither kills the listener
    9. answer exactly once: ack | query_rejected_msg{Code} |
       error_msg{route_not_found} | close
    10. on disconnect, reconnect with backoff and re-run 3-6               (registrar.py)

Steps 3 to 6 and step 10 are `astral.registrar`. This module owns steps 1, 2 and
7 to 9, and the op table that sits on top of them.

**Concurrency correction.** astral-go's accept loop is serial: `Handler.Route`
accepts one connection, blocks on its first frame, then blocks on routing until
the query is resolved, and only then accepts the next, so one slow dialer stalls
every other inbound query (astral-go bug G-14). Every connection here is handled
in its own task under a `TaskGroup`, with a `FIRST_FRAME_TIMEOUT` on the frame
the node owes us.

**Write-ordering correction.** astral-go wraps the connection in a
`lockableWriteCloser` and holds the lock until the `ack` is written, so an op
handler cannot emit response bytes ahead of the acceptance. The same invariant
falls out of not handing the handler the writer at all: `PendingQuery.accept()`
writes `ack` and **then** returns the `Stream`. No lock exists.

**An unanswered query pins a node goroutine.** astrald's `IPCHandler.RouteQuery`
sends `handle_query_msg` and then calls `ch.Switch(channel.ExpectAck, ...)` with
no deadline and no context, so a handler that never accepts and never rejects
blocks that goroutine for as long as the connection lives. astral-go's own
responder has the same hole. Every inbound query here therefore carries an
**answer deadline** (`ACCEPT_TIMEOUT`, astral-go's own 5 s from
`routing/incoming_query.go`) which is disarmed the moment the query is answered
and which skips the query when it expires. The deadline bounds the decision, not
the response body: a follow-mode responder streams for hours after its `ack`.

**Every accepted stream closes when its handler returns.** One inbound query is
one connection, so a handler that hands its stream to another task and returns
has leaked it, and a leaked connection burns one of astrald's 32 apphost workers
until the node restarts (astrald bug G-13, design section 3.9). `Service` closes
it, `aclose()` is idempotent, and `async with` in the handler is still the
contract.

**Handler deregistration is lazy.** astrald removes a handler on the **next**
failed push -- `query_router.go` drops it only when `RouteQuery` reports
`errEndpointUnavailable` -- so closing the listener does not unregister anything
(astral-docs bug D-13). A dead registration lingers and consumes one routing
attempt per query. `apphost.bind` is the only deterministic removal, which is
why the registrar holds a bind stream and why `Service.aclose()` closes it last.

Design section 4.4's register-service path ships here too, **gated**. It is the
WebSocket design, astral-go implements neither side of it, and two facts in
astrald's source make it experimental over IPC: the IPC worker closes the guest
connection unconditionally after `Guest.Serve` returns (`worker.go` calls
`conn.Close()` while the WebSocket server guards on `guest.donated`), so a
donated responder stream over IPC can be closed under the responder (design risk
R-16, unsettled); and the IPC guest channel is built without locked writes while
the WebSocket one is not, so concurrent `incoming_query_msg` pushes from
arbitrary routing goroutines can interleave one frame's three writes (astrald bug
G-12). Over WebSocket the path is sound and is the only inbound option a browser
has, so the gate is proto-shaped: `mode="service"` needs `experimental=True`
unless the session is a WebSocket one.

Two message types are **not** built on, and neither absence is an omission here:
`mod.apphost.register_handler_msg` is registered in astral-go and has an
`onRegisterHandlerMsg` method in astrald that `Guest.Serve`'s dispatch switch
never routes to (astral-go bug G-16), so registering a handler is the
`apphost.register_handler` **op**; and `mod.apphost.ping_msg` has no handler at
all and yields `error_msg{protocol_error}` (astrald bug G-17), so there is no
keepalive and none is simulated.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from dataclasses import dataclass, field
from types import MappingProxyType, TracebackType
from typing import Any, Callable, Final, Iterable, Mapping, Protocol, Sequence

from . import querystring
from .channel import Format, parse_format
from .errors import (
    AstralError,
    BadArgument,
    FeatureUnavailable,
    StreamClosed,
    TransportError,
    TransportUnsupported,
)
from .object import Query
from .registrar import (
    OP_REGISTER_DESCRIBER,
    OP_REGISTER_FINDER,
    OP_REGISTER_SEARCHER,
    RegistrationHook,
    Registrar,
    op_hook,
)
from .registry import Blueprints
from .session import (
    ACCEPT_TIMEOUT,
    ERROR_HISTORY as _ERROR_HISTORY,
    ATTACH_TIMEOUT,
    DEFAULT_REJECT_CODE,
    FIRST_FRAME_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    REJECT_INVALID_QUERY,
    Connector,
    HandleQueryMsg,
    IncomingQueryMsg,
    Session,
)
from .spec import Primitive, Spec
from .stream import Stream
from .transport import DEFAULT_MAX_PENDING, Server, Transport, listen_any
from .transport import listen as listen_at
from .transport.socket import HAS_UNIX_SOCKETS
from .types import Identity, Nonce
from .wire import DEFAULT_MAX_ALLOC

__all__ = [
    "CLOSE_TIMEOUT",
    "DEFAULT_PROTO",
    "ERROR_HISTORY",
    "Handler",
    "InboundQuery",
    "IncomingQuery",
    "OP_DESCRIBE",
    "OP_FIND",
    "OP_SEARCH",
    "Op",
    "OpHandler",
    "PendingQuery",
    "RESPOND_TIMEOUT",
    "SERVE_MODES",
    "Service",
    "WS_PROTOCOLS",
    "echo_handler",
    "object_handler",
    "require_service_transport",
]


# --- constants -----------------------------------------------------------

DEFAULT_PROTO: Final = "unix" if HAS_UNIX_SOCKETS else "tcp"
"""What a listener binds when the caller names no protocol.

The unix socket is preferred for the same reason `transport.default_endpoint`
prefers it: it is cheaper, it is filesystem-scoped rather than reachable from
every interface, and the node's TCP listener is the one that wedges.
"""

RESPOND_TIMEOUT: Final = HANDSHAKE_TIMEOUT
"""How long one `ack`, `query_rejected_msg` or `error_msg` has to reach the node.

A send blocks on the peer's receive window, so a refusal nobody reads would
otherwise hold this connection -- and the node goroutine behind it -- open with
no deadline anywhere in the exchange.
"""

CLOSE_TIMEOUT: Final = 5.0
"""How long `aclose()` waits for the serving tasks after the listener is shut.

Every task is awaiting I/O on a connection this method has already closed, so
the ordinary case returns at once. The bound exists for a handler that awaits
something this service does not own; on expiry the task group cancels what is
left, so shutdown is bounded whatever a handler does.
"""

ERROR_HISTORY: Final = _ERROR_HISTORY
"""Faults `Service.errors` keeps. Bounded, because a service runs for months and
an unbounded fault log is a leak with a diagnostic excuse.

Re-exported from `astral.session` rather than declared here, so `Service.errors`
and `Registrar.errors` cannot drift: `serve` imports `registrar`, so the shared
constant cannot live in either and lives with the rest of the timing contract.
"""

WS_PROTOCOLS: Final = frozenset({"ws", "wss"})
"""Endpoint protocols on which register-service is not experimental.

astrald's WebSocket server guards the guest close on `guest.donated`, so a
donated responder stream survives there. The IPC worker does not guard, which is
design risk R-16 and the whole of the gate below.
"""

SERVE_MODES: Final = ("handler", "service")

OP_SEARCH: Final = "objects.search"
OP_DESCRIBE: Final = "objects.describe"
OP_FIND: Final = "objects.find"

_NO_PARAMS: Final[Mapping[str, Spec]] = MappingProxyType({})
_SEARCH_PARAMS: Final[Mapping[str, Spec]] = MappingProxyType({"q": Primitive("string8")})
_ID_PARAMS: Final[Mapping[str, Spec]] = MappingProxyType(
    {"id": Primitive("object_id.sha256")}
)


def require_service_transport(endpoint: str, *, experimental: bool = False) -> None:
    """Refuse register-service where design risk R-16 is unsettled.

    The gate of design section 4.4, in one place, so that `Client.serve` can
    apply it **before** it dials: a certain refusal is not worth one of astrald's
    32 apphost workers, which is the same rule `Session.register_service` applies
    to an anonymous guest.

    astrald's IPC worker closes the guest connection unconditionally after
    `Guest.Serve` returns (`worker.go`), whereas its WebSocket server guards the
    same close on `guest.donated` (`ws_server.go`), so a donated responder stream
    over IPC can be closed under its responder; and the IPC guest channel is
    built without locked writes while the WebSocket one is not, so concurrent
    `incoming_query_msg` pushes from arbitrary routing goroutines can interleave
    one frame's three writes (astrald bug G-12). Over WebSocket the path is sound
    and is the only inbound option a browser has.
    """
    proto = endpoint.partition(":")[0]
    if proto in WS_PROTOCOLS or experimental:
        return
    raise FeatureUnavailable(
        f"register-service over {proto or 'ipc'}: astrald closes the guest "
        "connection unconditionally after Guest.Serve returns and guards that "
        "close on `donated` only on the websocket path, so a donated responder "
        "stream can be closed under it (design risk R-16, unsettled); and the "
        "ipc guest channel is built without locked writes, so concurrent "
        "incoming_query_msg pushes can interleave a frame (astrald bug G-12). "
        "Pass experimental=True to serve it anyway, or use mode='handler', "
        "which is the supported inbound path here"
    )


class Handler(Protocol):
    """What serves one inbound query. Design section 4.3.

    Exactly one of `accept()`, `reject()`, `skip()` and `aclose()` resolves the
    query; a handler that returns without resolving one has the query skipped and
    the connection closed on its behalf, because the node is blocked on the
    answer.
    """

    async def __call__(self, q: "InboundQuery") -> None: ...


OpHandler = Handler
"""A mounted op's handler. The same protocol: an op is a handler under a name."""


# --- the op table --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Op:
    """One mounted operation: a name, a handler, and its declared parameters.

    Parameters are declared rather than inferred, exactly as design section 5.1
    rule 2 declares them on the outbound side: a query string carries the bare
    payload half of each value's text encoding and **not** its type, so the type
    comes from this declaration or from nowhere. A parameter with no declaration
    still reaches the handler through `InboundQuery.params` as the text the
    caller wrote.

    `required` is enforced here and is enforced by name. astrald enforces
    required arguments on twelve ops and treats the marker as aspirational on the
    rest (astral-docs bug D-19); a mounted op states its own.
    """

    name: str
    handler: OpHandler
    params: Mapping[str, Spec] = field(default_factory=lambda: _NO_PARAMS)
    required: frozenset[str] = frozenset()

    def coerce(self, params: Mapping[str, str]) -> dict[str, Any]:
        """The declared parameters, decoded from their bare text forms.

        Raises `BadArgument` for a missing required parameter and whatever
        `querystring.parse_param` raises for an unparsable one. Both are the
        caller's fault and both are answered `query_rejected_msg{2}`, which is
        `CodeInvalidQuery` in astral-go's own table.
        """
        args: dict[str, Any] = {}
        for name, spec in self.params.items():
            text = params.get(name)
            if text is None:
                if name in self.required:
                    raise BadArgument(f"{self.name}: {name} is required")
                continue
            args[name] = querystring.parse_param(spec, text)
        return args


# --- one inbound query ---------------------------------------------------


class _Inbound:
    """What `PendingQuery` and `IncomingQuery` share: one query, answered once.

    The two differ only in the mechanics of the three answers. Design section 4.3
    answers on the connection the node dialed; design section 4.4 answers on a
    connection this side opens, or by writing a refusal back on the registration.
    Everything above them -- the op table, the answer deadline, the argument
    coercion, the accepted stream's lifetime -- is written once, here.
    """

    __slots__ = (
        "_answer",
        "_args",
        "_deadline",
        "_op",
        "_params",
        "_query",
        "_service",
        "_stream",
    )

    def __init__(self, query: Query, service: "Service | None" = None) -> None:
        self._query = query
        self._service = service
        self._op, self._params = querystring.parse(query.query_string)
        self._args: dict[str, Any] = {}
        self._answer: str | None = None
        self._deadline: asyncio.Timeout | None = None
        self._stream: Stream | None = None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.query_string!r}, "
            f"{self._answer or 'pending'})"
        )

    # --- the query ---

    @property
    def query(self) -> Query:
        """The query as it arrived: nonce, caller, target, query string."""
        return self._query

    @property
    def query_string(self) -> str:
        return self._query.query_string

    @property
    def op(self) -> str:
        """The query string with its parameters stripped. What the table keys on."""
        return self._op

    @property
    def params(self) -> Mapping[str, str]:
        """Every parameter, as the text the caller wrote. Nothing is dropped.

        astrald drops a parameter whose key it does not declare, case-sensitively
        (astral-docs bug D-17), so five documented shellsession examples are
        no-ops there. Nothing is dropped here: an undeclared parameter is text a
        handler can read.
        """
        return self._params

    @property
    def args(self) -> Mapping[str, Any]:
        """The declared parameters, decoded through their specs.

        Empty on a query served by the fallback handler: nothing declared a
        spec, so nothing can be decoded, and `params` is the text.
        """
        return self._args

    @property
    def nonce(self) -> Nonce:
        return self._query.nonce

    @property
    def caller(self) -> Identity | None:
        """Who asked. Nil for an anonymous caller, which astrald's core router
        rewrites to the node's own identity before the query leaves it."""
        return self._query.caller

    @property
    def target(self) -> Identity | None:
        """The identity the query was routed to. This service's, by construction."""
        return self._query.target

    @property
    def answered(self) -> bool:
        """Whether one of the four answers has been given."""
        return self._answer is not None

    @property
    def answer(self) -> str | None:
        """Which answer was given: `accepted`, `rejected`, `skipped` or `closed`."""
        return self._answer

    @property
    def stream(self) -> Stream | None:
        """The accepted stream, or `None` while the query is unanswered or refused."""
        return self._stream

    # --- resolution ---

    def _arm(self, deadline: "asyncio.Timeout | None") -> None:
        """Attach, or detach, the answer deadline this query is dispatched under."""
        self._deadline = deadline

    def _claim(self, what: str) -> None:
        """Take the one answer this query has, and disarm the answer deadline.

        Latched **before** the I/O, so a refusal that fails to reach the node
        does not leave the query answerable a second time: the node has already
        been told, or the connection is already gone, and a second answer on
        either would be a frame the node reads as belonging to something else.
        """
        if self._answer is not None:
            raise StreamClosed(
                f"{self!r}: already {self._answer}; one query has one answer"
            )
        self._answer = what
        deadline, self._deadline = self._deadline, None
        if deadline is not None:
            # The decision is made; what follows it is the response body, which
            # is the op's business and is not bounded here.
            with contextlib.suppress(RuntimeError):
                deadline.reschedule(None)

    def _reconcile(self, key: str, keyword: str, *, output: bool) -> str:
        """One format token, from the query string or from the keyword.

        The keyword names what this responder is prepared to write or read; the
        parameter names what the caller asked for and what its own channel was
        built from. They cannot differ, because the bytes are one exchange.
        """
        in_qs = self._params.get(key)
        if in_qs is None:
            return keyword
        if keyword and parse_format(in_qs, output=output) is not parse_format(
            keyword, output=output
        ):
            raise BadArgument(
                f"{self.query_string}: the query string says {key}={in_qs} and "
                f"the handler asked for fmt_{key}={keyword}; the caller's channel "
                "is built from the query string, so these cannot differ"
            )
        return in_qs

    def _framing(self, fmt_in: str, fmt_out: str) -> tuple[str, str]:
        """The two channel formats this side reads and writes, from the query.

        `in=` is what the responder **reads** and `out=` is what the responder
        **writes**, and this side is the responder, so the roles are the mirror
        image of `Client.query`'s. The query string fills in where the keyword is
        silent, and a genuine disagreement is refused rather than resolved: the
        caller built its own channel from those parameters, so a responder that
        quietly preferred either one would frame one exchange two ways. That is
        `Client._framing`'s rule from the other side of the wire.
        """
        wanted_in = self._reconcile("in", fmt_in, output=False)
        wanted_out = self._reconcile("out", fmt_out, output=True)
        parsed_in = parse_format(wanted_in, output=False)
        parsed_out = parse_format(wanted_out, output=True)
        if parsed_in is not Format.BIN or parsed_out is not Format.BIN:
            raise TransportUnsupported(
                f"{self.query_string}: this query asks to be served "
                f"in={parsed_in.value} out={parsed_out.value}; the json, text, "
                "canonical, base64 and render channels land with "
                "channel/jsonl.py, channel/textchan.py and channel/canonical.py"
            )
        return str(parsed_in), str(parsed_out)

    def _wrap(self, conn: Any, read_fmt: str, write_fmt: str, raw: bool) -> Stream:
        """The accepted `QueryStream`, as the `Stream` a handler writes to.

        `Stream` names its formats from the **caller's** side -- `fmt_in` is what
        that side writes -- so a responder passes them swapped. The swap happens
        here, once, rather than at every call site that would otherwise get it
        backwards.
        """
        stream = Stream(
            conn,
            fmt_in=write_fmt,
            fmt_out=read_fmt,
            connector=None,
            on_close=None if self._service is None else self._service._forget_stream,
            raw=raw,
        )
        self._stream = stream
        if self._service is not None:
            self._service._remember_stream(stream)
        return stream

    async def accept(
        self,
        *,
        fmt_in: str = "",
        fmt_out: str = "",
        raw: bool = False,
        allow_unparsed: bool = False,
        timeout: float | None = RESPOND_TIMEOUT,
    ) -> Stream:
        """Accept the query and take the stream. Subclass mechanics."""
        raise NotImplementedError

    async def reject(
        self, code: int = DEFAULT_REJECT_CODE, *, timeout: float | None = RESPOND_TIMEOUT
    ) -> None:
        """Decline with a code. Subclass mechanics."""
        raise NotImplementedError

    async def skip(self, *, timeout: float | None = RESPOND_TIMEOUT) -> None:
        """Decline by claiming no route. Subclass mechanics."""
        raise NotImplementedError

    async def aclose(self) -> None:
        """Answer nothing and release the connection. Subclass mechanics."""
        raise NotImplementedError


InboundQuery = _Inbound
"""One inbound query, whichever inbound path carried it.

The name a handler annotates against: `PendingQuery` is design section 4.3's and
`IncomingQuery` is design section 4.4's, and a handler written against either
works against both.
"""


class PendingQuery(_Inbound):
    """One inbound query on a connection the **node** dialed. Design section 4.3.

    The connection carried `mod.apphost.handle_query_msg` as its first frame with
    no greeting and no auth; its `IPCToken` has already been checked against the
    listener's. Exactly one of `accept`, `reject`, `skip` and `aclose` resolves
    it, and every one of them ends this connection's life as a message channel.
    """

    __slots__ = ("_session",)

    def __init__(
        self, session: Session, message: HandleQueryMsg, service: "Service | None" = None
    ) -> None:
        super().__init__(
            Query(
                nonce=message.id,
                caller=message.caller,
                target=message.target,
                query_string=message.query,
            ),
            service,
        )
        self._session = session

    @property
    def session(self) -> Session:
        """The dialed-in session. Spent once the query is accepted."""
        return self._session

    @property
    def endpoint(self) -> str:
        return self._session.endpoint

    async def accept(
        self,
        *,
        fmt_in: str = "",
        fmt_out: str = "",
        raw: bool = False,
        allow_unparsed: bool = False,
        timeout: float | None = RESPOND_TIMEOUT,
    ) -> Stream:
        """Write `ack`, **then** hand back the stream.

        The order is the whole of astral-go's write lock: a handler that never
        holds the writer before the acceptance is on the wire cannot emit
        response bytes ahead of it. `timeout` bounds the `ack`, which is a send
        and therefore blocks on the node's receive window.

        The channel formats are validated **before** the acceptance is claimed,
        so a query asking for a framing this SDK cannot write leaves the query
        unanswered and answerable -- `skip()` is what a handler that cannot serve
        it should say, and the caller then sees `route_not_found` rather than an
        accepted stream that produces nothing.
        """
        read_fmt, write_fmt = self._framing(fmt_in, fmt_out)
        self._claim("accepted")
        conn = await self._session.accept_query(
            allow_unparsed=allow_unparsed, timeout=timeout
        )
        return self._wrap(conn, read_fmt, write_fmt, raw)

    async def reject(
        self, code: int = DEFAULT_REJECT_CODE, *, timeout: float | None = RESPOND_TIMEOUT
    ) -> None:
        """Decline with `query_rejected_msg{code}`, then close.

        Code 0 is success and is not a rejection: astral-go coerces it on two of
        its three paths and puts it on the wire unchanged on the third, so the
        coercion is not even consistent there. This refuses instead, before the
        answer is claimed, so a caller's bug is a caller's error and not a
        rejection the node reads as success.
        """
        if code == 0:
            raise BadArgument("reject code 0 is success, not a rejection")
        self._claim("rejected")
        await self._session.reject_query(code, timeout=timeout)

    async def skip(self, *, timeout: float | None = RESPOND_TIMEOUT) -> None:
        """Decline with `error_msg{route_not_found}`, then close.

        The caller sees exactly what it would have seen had this handler never
        been registered, which is astral-go's `Skip()` and is the right answer
        for an op name this service does not mount.
        """
        self._claim("skipped")
        await self._session.skip_query(timeout=timeout)

    async def aclose(self) -> None:
        """Close with no answer at all.

        The node's `ch.Switch(ExpectAck, ...)` reads the close as
        `route_not_found` through its catch-all error branch, so the caller is
        told the same thing `skip()` tells it, one frame later and without a
        frame on the wire.
        """
        self._claim("closed")
        await self._session.aclose()


class IncomingQuery(_Inbound):
    """One inbound query pushed on a register-service registration. Section 4.4.

    The registration connection stays a message channel and the node pushes one
    `mod.apphost.incoming_query_msg` per inbound query. Answering it means
    opening a **fresh** connection, completing the greeting, sending
    `mod.apphost.attach_query_msg{QueryID}` and reading its `ack`; or writing
    `mod.apphost.reject_incoming_msg{QueryID, Code}` back on the registration.
    Ignoring it yields `route_not_found` for the caller after astrald's
    `QueryAttachTimeout` of 5 s.

    **Experimental over IPC** (design risk R-16): astrald's IPC worker closes the
    guest connection unconditionally after `Guest.Serve` returns, whereas the
    WebSocket server guards on `guest.donated`, so the connection this class
    donates can be closed under it. The gate is `Service.attach_registration`'s.
    """

    __slots__ = ("_connector", "_message", "_registration")

    def __init__(
        self,
        registration: Session,
        message: IncomingQueryMsg,
        connector: Connector,
        service: "Service | None" = None,
    ) -> None:
        super().__init__(
            Query(
                nonce=message.query_id,
                caller=message.caller,
                target=message.target,
                query_string=message.query,
            ),
            service,
        )
        self._registration = registration
        self._message = message
        self._connector = connector

    @property
    def endpoint(self) -> str:
        return self._registration.endpoint

    async def accept(
        self,
        *,
        fmt_in: str = "",
        fmt_out: str = "",
        raw: bool = False,
        allow_unparsed: bool = False,
        timeout: float | None = ATTACH_TIMEOUT,
    ) -> Stream:
        """Open a fresh connection, attach it to this query, take the stream.

        `timeout` is `ATTACH_TIMEOUT`, which is astrald's own
        `QueryAttachTimeout`: the node holds the caller for 5 s and then answers
        `route_not_found`, so an attach that has not been acked by then is
        already too late.

        The attach connection completes the greeting. Whether it also
        authenticates is the connector's business and not this call's: astrald's
        `onAttachQueryMsg` checks no identity at all -- the unguessable `QueryID`
        is the whole of the pairing -- so an authenticated attach is a superset
        of what the protocol needs and costs one round trip.
        """
        read_fmt, write_fmt = self._framing(fmt_in, fmt_out)
        self._claim("accepted")
        session = await self._connector()
        conn = await session.attach_query(
            self._message, timeout=timeout, allow_unparsed=allow_unparsed
        )
        return self._wrap(conn, read_fmt, write_fmt, raw)

    async def reject(
        self, code: int = DEFAULT_REJECT_CODE, *, timeout: float | None = RESPOND_TIMEOUT
    ) -> None:
        """Refuse on the **registration** connection, which stays open.

        The caller sees `query_rejected_msg{code}`. The registration is not this
        query's to close: one unanswerable push is not evidence that the next one
        is unanswerable too.
        """
        if code == 0:
            raise BadArgument("reject code 0 is success, not a rejection")
        self._claim("rejected")
        await self._registration.reject_incoming(
            self._message, code, timeout=timeout
        )

    async def skip(self, *, timeout: float | None = RESPOND_TIMEOUT) -> None:
        """Answer nothing. The caller sees `route_not_found` after 5 s.

        There is no route-not-found message on this path: astrald's
        `WSHandler.RouteQuery` waits on the attach, on a rejection, or on its own
        timer, so silence is the third answer and it is the slow one. A handler
        that knows it cannot serve the query should `reject()` instead and free
        the caller now.
        """
        self._claim("skipped")

    async def aclose(self) -> None:
        """Answer nothing, exactly as `skip()`. The registration is untouched."""
        self._claim("closed")


# --- the service ---------------------------------------------------------


class Service:
    """A local listener, an op table, and every inbound query served over them.

    One `Service` is one identity's inbound surface. It binds a listener, accepts
    every connection the node dials, validates the first frame, dispatches by op
    name, and closes deterministically. Registration with the node is
    `astral.registrar`'s; a `Service` built by `Client.serve` **owns** the
    registrar and closes it last, so the node's deferred handler sweep runs with
    the listener already torn down (design section 3.8).
    """

    __slots__ = (
        "_answer_timeout",
        "_closed",
        "_closing",
        "_connector",
        "_first_frame_timeout",
        "_handler",
        "_hooks",
        "_identity",
        "_max_alloc",
        "_on_error",
        "_ops",
        "_ready",
        "_registrar",
        "_registration",
        "_registry",
        "_respond_timeout",
        "_server",
        "_sessions",
        "_stop",
        "_streams",
        "_supervisor",
        "_sweep",
        "_tg",
        "_token",
        "close_timeout",
        "errors",
        "served",
    )

    def __init__(
        self,
        *,
        handler: Handler | None = None,
        identity: Identity | None = None,
        token: Nonce | int | None = None,
        registry: Blueprints | None = None,
        connector: Connector | None = None,
        registrar: Registrar | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        first_frame_timeout: float | None = FIRST_FRAME_TIMEOUT,
        answer_timeout: float | None = ACCEPT_TIMEOUT,
        respond_timeout: float | None = RESPOND_TIMEOUT,
        close_timeout: float | None = CLOSE_TIMEOUT,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        """Build a service. `Client.serve` is the public way in.

        `handler` serves every query no mounted op claims. With no handler and no
        matching op the query is skipped, which tells the caller exactly what a
        handler that was never registered would.

        `token` is the IPC token the node must quote back in
        `mod.apphost.handle_query_msg`. It defaults to a fresh random `Nonce` and
        is the only thing standing between this listener and any local process
        that finds the socket, so it is never derived from anything guessable.

        `answer_timeout` bounds the decision on each inbound query, not the
        response body: astrald waits for the `ack` with no deadline of its own,
        so an unanswered query pins one of its goroutines.
        """
        self._handler = handler
        self._identity = identity
        self._token = Nonce.random() if token is None else Nonce(int(token))
        self._registry = registry
        self._connector = connector
        self._registrar = registrar
        self._max_alloc = max_alloc
        self._first_frame_timeout = first_frame_timeout
        self._answer_timeout = answer_timeout
        self._respond_timeout = respond_timeout
        self.close_timeout = close_timeout
        self._on_error = on_error

        self._ops: dict[str, Op] = {}
        self._hooks: list[RegistrationHook] = []
        self._server: Server | None = None
        self._registration: Session | None = None
        self._sessions: set[Session] = set()
        self._streams: set[Stream] = set()
        self._tg: asyncio.TaskGroup | None = None
        self._supervisor: asyncio.Task[None] | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._closing = False
        self._closed = False
        # A lock rather than an event, for the reason `Client.aclose()` states:
        # an event a cancelled walk sets anyway tells the second caller the
        # service is closed while its descriptors are still open. The lock makes
        # the second caller wait for the walk and inherit whatever it left.
        self._sweep = asyncio.Lock()

        self.errors: deque[BaseException] = deque(maxlen=ERROR_HISTORY)
        """The last faults this service met, newest last. Bounded at `ERROR_HISTORY`.

        A fault in one connection never reaches another and never stops the
        listener: a token mismatch, a wrong first frame and a handler that raised
        are all one connection's business.
        """

        self.served = 0
        """Inbound queries dispatched, refused ones included."""

    def __repr__(self) -> str:
        if not self._closing:
            state = "listening" if self._server is not None else "idle"
        else:
            state = "closed" if self._closed else "closing"
        where = "" if self._server is None else f"{self._server.endpoint!r}, "
        return f"Service({where}{state}, {len(self._ops)} ops, {self.served} served)"

    # --- state ---

    @property
    def endpoint(self) -> str:
        """The endpoint the node dials, resolved from the bound address.

        This is the string `apphost.register_handler` receives, so an ephemeral
        port or a generated socket path is already resolved in it.
        """
        if self._server is None:
            raise StreamClosed(f"{self!r}: not listening")
        return self._server.endpoint

    @property
    def token(self) -> Nonce:
        """The IPC token every inbound `handle_query_msg` must carry."""
        return self._token

    @property
    def identity(self) -> Identity | None:
        """The identity this service serves, when the caller named one."""
        return self._identity

    @property
    def registrar(self) -> Registrar | None:
        """The registrar that keeps this service registered, when there is one."""
        return self._registrar

    @property
    def mounted(self) -> tuple[str, ...]:
        """Every op name this service answers, sorted."""
        return tuple(sorted(self._ops))

    @property
    def hooks(self) -> tuple[RegistrationHook, ...]:
        """Post-connect hooks this service's mounts require."""
        return tuple(self._hooks)

    @property
    def live_queries(self) -> int:
        """Inbound connections this service holds: one per query in flight.

        A session becomes a stream at the acceptance -- the transport is handed
        over and the session is spent -- so the two sets never count the same
        connection twice.
        """
        return sum(1 for s in self._sessions if not s.spent) + len(self._streams)

    @property
    def listening(self) -> bool:
        return self._server is not None and not self._closing

    @property
    def closed(self) -> bool:
        """Whether the close has completed: no listener, no connection, no task."""
        return self._closed

    @property
    def closing(self) -> bool:
        """Whether a close has begun. True from the first `aclose()` call on."""
        return self._closing

    # --- the op table ---

    def mount(
        self,
        name: str,
        handler: OpHandler,
        *,
        params: Mapping[str, Spec] | None = None,
        required: Iterable[str] = (),
    ) -> None:
        """Mount one op under the name callers query it by.

        The name is the whole op name as it travels -- `objects.search`, not
        `search`. astral-go splits the module prefix off in a `ScopeRouter` and
        dispatches the remainder; a flat table keyed on what the wire carries
        reaches the same op with one lookup and no prefix rule to get wrong.

        Mounting the same name twice is refused: an op silently replaced is an op
        whose behaviour depends on import order.
        """
        if name in self._ops:
            raise BadArgument(f"{name}: already mounted")
        required = frozenset(required)
        declared = dict(params or {})
        unknown = required - set(declared)
        if unknown:
            raise BadArgument(
                f"{name}: required parameters {sorted(unknown)} have no declared "
                "spec, so nothing would decode them"
            )
        self._ops[name] = Op(name, handler, declared, required)

    def unmount(self, name: str) -> None:
        """Remove one op. A name that is not mounted is refused, not ignored."""
        if self._ops.pop(name, None) is None:
            raise BadArgument(f"{name}: not mounted")

    def add_provider(
        self,
        op: str,
        register_op: str,
        handler: OpHandler,
        *,
        params: Mapping[str, Spec] | None = None,
        required: Iterable[str] = (),
    ) -> None:
        """Mount an op **and** re-register it with the node after every reconnect.

        Design section 4.6's corrected model, in one call. The legacy SDK
        documented `objects.register_searcher` as a channel the node proxies
        calls back over, to be held open or the registration drops. astral-go's
        own client contradicts that -- it opens the channel, reads the `ack` and
        closes it -- and astrald settles it: `OpRegisterSearcher` calls
        `mod.AddSearcher(...)`, sends `ack`, and returns into a deferred
        `ch.Close()`. Registration is **not** channel-scoped and there is no
        serving loop to build.

        What there is: the app serves inbound queries on its own identity, mounts
        the scoped op on itself, and re-runs the registration after every
        reconnect, because the node forgets it when the guest disconnects.
        """
        self.mount(op, handler, params=params, required=required)
        self._add_hook(op_hook(register_op))

    def add_searcher(self, handler: OpHandler, **kw: Any) -> None:
        """Serve `objects.search` and register as a searcher. Design section 4.6.

        The op reads `q`, the search string, and streams `mod.objects.search_result`
        objects followed by `eos`. The caller identity and the zone are **not**
        propagated to it: astrald routes the search to this identity and
        astral-go's own searcher op records both omissions.
        """
        self.add_provider(
            OP_SEARCH, OP_REGISTER_SEARCHER, handler, params=_SEARCH_PARAMS, **kw
        )

    def add_describer(self, handler: OpHandler, **kw: Any) -> None:
        """Serve `objects.describe` and register as a describer. Section 4.6.

        The op reads `id` and streams `mod.objects.describe_result` objects
        followed by `eos`. `id` is not declared required: astral-go's own
        describer answers `error_message("id is required")` and an `eos` rather
        than refusing the query, so the handler owns that choice.
        """
        self.add_provider(
            OP_DESCRIBE, OP_REGISTER_DESCRIBER, handler, params=_ID_PARAMS, **kw
        )

    def add_finder(self, handler: OpHandler, **kw: Any) -> None:
        """Serve `objects.find` and register as a finder. Design section 4.6.

        The op reads `id` and streams `identity` objects followed by `eos`.
        """
        self.add_provider(OP_FIND, OP_REGISTER_FINDER, handler, params=_ID_PARAMS, **kw)

    def _add_hook(self, hook: RegistrationHook) -> None:
        """Record a post-connect hook, and hand it to the registrar when there is one."""
        self._hooks.append(hook)
        if self._registrar is not None:
            self._registrar.add_hook(hook)

    def attach_registrar(self, registrar: Registrar) -> None:
        """Bind this service to the registrar that keeps it registered.

        Every hook declared by a mount made before this call is handed over now,
        and every one made after it is handed over as it is made, so mount order
        and attach order do not interact.
        """
        self._registrar = registrar
        registrar.add_hook(*self._hooks)

    # --- listening (design section 4.3, steps 1 and 2) ---

    async def listen(
        self,
        proto: str = DEFAULT_PROTO,
        *,
        endpoint: str | None = None,
        max_pending: int = DEFAULT_MAX_PENDING,
        unlink_stale: bool = False,
    ) -> str:
        """Bind a listener and **start accepting before anything is registered**.

        The order is design section 4.3's step 2 and it is not a preference: a
        post-connect hook's own query can be routed straight back to this
        identity, so the node dials this listener while the registration is still
        in flight. A listener that was not yet accepting would leave that dial
        unanswered, and astrald's `IPCHandler.RouteQuery` waits for the `ack`
        with no deadline.

        `endpoint` binds a named address; without one an ephemeral address is
        bound -- `$TMPDIR/apphostclient.<16 chars>` for unix, `127.0.0.1:0` for
        tcp -- matching astral-go's `ipc.ListenAny`. Loopback rather than every
        interface, because an inbound apphost handler is local-only and the node
        rejects a registration whose query origin is the network.

        **`max_pending` is not a bound on what this service holds.** It caps
        `Server._pending`, the connections the OS has delivered and the accept
        loop has not yet claimed, which a tight accept loop keeps at zero. Once
        accepted, every connection gets a task and a `Session` of its own with no
        ceiling, and the IPC token is validated only after a first frame arrives
        -- so a peer that connects and sends nothing is held for
        `first_frame_timeout`, 5 s by default. Measured: 400 token-less dials
        held 400 sessions and 402 tasks with nothing dispatched, all of them
        released when the deadline expired. The exposure is a rate bounded by
        that deadline, not a leak, and `first_frame_timeout` is the lever that
        governs it. `max_pending` is not.

        **A failed bind owns no task.** `_start()` runs first, deliberately --
        the accept loop must exist before the listener does -- and a bind that
        then raised used to leave the `astral-service` supervisor parked inside
        an open `TaskGroup` with nothing to set `_stop`: the natural reaction to
        an "address already in use" is to drop the object, and the object could
        not report that it still owned a task (`listening` False, `closed`
        False). Under `-X dev` that surfaces as "Task was destroyed but it is
        pending". So a failure undoes exactly what this call started, and nothing
        it did not: a service the caller had already entered keeps its
        supervisor.

        Returns the bound endpoint, which is what `apphost.register_handler`
        receives.
        """
        if self._closing:
            raise StreamClosed(f"{self!r}: the service is closed")
        if self._server is not None:
            raise StreamClosed(f"{self!r}: already listening at {self.endpoint}")
        started_here = self._supervisor is None
        await self._start()
        try:
            server = (
                await listen_any(proto, max_pending=max_pending)
                if endpoint is None
                else await listen_at(
                    endpoint, max_pending=max_pending, unlink_stale=unlink_stale
                )
            )
        except BaseException:
            await self._unstart(started_here)
            raise
        self._server = server
        try:
            self._spawn(self._accept_loop(server))
        except BaseException:
            self._server = None
            await server.aclose()
            await self._unstart(started_here)
            raise
        return server.endpoint

    # --- register-service (design section 4.4, gated) ---

    async def attach_registration(
        self,
        session: Session,
        identity: Identity | None = None,
        *,
        connector: Connector | None = None,
        experimental: bool = False,
        timeout: float | None = HANDSHAKE_TIMEOUT,
    ) -> Identity | None:
        """Register `session` as this identity's inbound channel. Section 4.4.

        The connection stays a message channel and the node pushes one
        `mod.apphost.incoming_query_msg` per inbound query, each of which this
        service dispatches through the same op table the listener uses.

        **Gated.** astral-go implements neither side of this path, the only
        reference is `apphost-js`, and two facts in astrald's source make it
        experimental over IPC: `worker.go` closes the guest connection
        unconditionally after `Guest.Serve` returns while `ws_server.go` guards
        the same close on `guest.donated`, so a donated responder stream over IPC
        can be closed under its responder (design risk R-16, unsettled and
        untested -- settling it needs an auth token); and the IPC guest channel
        is built without locked writes while the WebSocket one is not, so
        concurrent pushes from arbitrary routing goroutines can interleave one
        frame's three writes (astrald bug G-12). Over WebSocket the path is sound
        and is the only inbound option a browser has, so a WebSocket session
        needs no flag and an IPC session needs `experimental=True`.
        """
        if self._closing:
            raise StreamClosed(f"{self!r}: the service is closed")
        if self._registration is not None:
            raise StreamClosed(f"{self!r}: already registered as a service")
        require_service_transport(session.endpoint, experimental=experimental)
        attach = connector if connector is not None else self._connector
        if attach is None:
            raise BadArgument(
                "register-service needs a connector: answering an "
                "incoming_query_msg means opening a **fresh** connection and "
                "sending attach_query_msg on it"
            )
        # `listen()`'s guard, for the same reason: a registration the node
        # refuses must not leave the supervisor parked with nothing to stop it.
        started_here = self._supervisor is None
        await self._start()
        try:
            registered = await session.register_service(identity, timeout=timeout)
        except BaseException:
            await self._unstart(started_here)
            raise
        self._registration = session
        self._identity = registered if identity is None else identity
        try:
            self._spawn(self._registration_loop(session, attach))
        except BaseException:
            self._registration = None
            await session.aclose()
            await self._unstart(started_here)
            raise
        return registered

    # --- the accept loop ---

    async def _accept_loop(self, server: Server) -> None:
        """One task per connection. astral-go serves them in sequence (bug G-14)."""
        while True:
            try:
                transport = await server.accept()
            except TransportError:
                return
            if self._closing:
                await transport.aclose()
                return
            try:
                self._spawn(self._serve_connection(transport))
            except RuntimeError:
                # The task group is closing under this loop. The connection is
                # ours until somebody owns it, and nobody now will.
                await transport.aclose()
                return

    async def _serve_connection(self, transport: Transport) -> None:
        """Read the first frame, dispatch it, and close whatever is left.

        Every fault here is one connection's. A token mismatch, a wrong first
        type and a first frame that never arrives are all answered and closed by
        `Session.read_query`, and the listener keeps accepting -- which is what
        makes an unguessable token a gate rather than a fuse.
        """
        session = Session.dialed_in(
            transport,
            endpoint=transport.endpoint,
            registry=self._registry,
            max_alloc=self._max_alloc,
        )
        self._sessions.add(session)
        try:
            try:
                message = await session.read_query(
                    token=self._token, timeout=self._first_frame_timeout
                )
            except AstralError as exc:
                # `read_query` has already refused and closed the connection.
                self._record(exc)
                return
            pending = PendingQuery(session, message, self)
            await self._run(pending)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- one connection never kills the loop
            self._record(exc)
        finally:
            self._sessions.discard(session)
            await session.aclose()

    async def _registration_loop(self, session: Session, connector: Connector) -> None:
        """Every `incoming_query_msg` on a register-service registration.

        One task per push, for the reason the accept loop has one task per
        connection: answering a push means opening a connection and completing a
        handshake on it, and a serial reader would hold every later push behind
        that round trip while astrald's 5 s attach timer ran on all of them.
        """
        try:
            while True:
                try:
                    message = await session.next_incoming()
                except EOFError:
                    return
                except AstralError as exc:
                    self._record(exc)
                    return
                incoming = IncomingQuery(session, message, connector, self)
                try:
                    self._spawn(self._run(incoming))
                except RuntimeError:
                    return
        finally:
            self._registration = None
            await session.aclose()

    async def _run(self, query: _Inbound) -> None:
        """Dispatch one inbound query under its answer deadline, then clean up.

        Three things happen here that nothing else can do: the deadline that
        keeps an unanswered query from pinning a node goroutine, the guarantee
        that an unresolved query is refused rather than abandoned, and the close
        of the accepted stream. The last is not tidiness -- one inbound query is
        one connection, so a handler that returns holding its stream has leaked
        one of astrald's 32 apphost workers.
        """
        self.served += 1
        try:
            async with asyncio.timeout(self._answer_timeout) as deadline:
                query._arm(deadline)
                await self._dispatch(query)
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            self._record(exc)
        except Exception as exc:  # noqa: BLE001 -- one query never kills the service
            self._record(exc)
        finally:
            query._arm(None)
            await self._resolve(query)

    async def _dispatch(self, query: _Inbound) -> None:
        """The op table, and the fallback under it.

        An op name nothing mounts is skipped, which is astral-go's
        `OpRouter.RouteQuery` answering `RouteNotFound` and is the only honest
        answer: the caller is told what it would have been told had this handler
        never been registered.
        """
        op = self._ops.get(query.op)
        if op is None:
            if self._handler is None:
                await query.skip(timeout=self._respond_timeout)
                return
            await self._handler(query)
            return
        try:
            query._args = op.coerce(query.params)
        except AstralError as exc:
            self._record(exc)
            await query.reject(REJECT_INVALID_QUERY, timeout=self._respond_timeout)
            return
        await op.handler(query)

    async def _resolve(self, query: _Inbound) -> None:
        """Close the accepted stream, or refuse a query the handler left pending.

        Both are the node's business rather than tidiness: an unanswered query
        blocks the goroutine that is waiting for the `ack`, and an unclosed
        stream holds one of the 32 apphost workers until the node restarts.
        """
        stream = query.stream
        if stream is not None:
            with contextlib.suppress(Exception):
                await stream.aclose()
        if query.answered:
            return
        with contextlib.suppress(Exception):
            await query.skip(timeout=self._respond_timeout)
        if not query.answered:  # pragma: no cover -- `_claim` latches first
            with contextlib.suppress(Exception):
                await query.aclose()

    # --- bookkeeping ---

    def _remember_stream(self, stream: Stream) -> None:
        self._streams.add(stream)

    def _forget_stream(self, stream: Stream) -> None:
        self._streams.discard(stream)

    def _record(self, exc: BaseException) -> None:
        """Keep one fault and hand it to the caller's observer, if any."""
        self.errors.append(exc)
        if self._on_error is not None:
            with contextlib.suppress(Exception):
                self._on_error(exc)

    def _spawn(self, coro: Any) -> None:
        if self._tg is None:
            coro.close()
            raise StreamClosed(f"{self!r}: the service has not been started")
        self._tg.create_task(coro)

    async def _start(self) -> None:
        """Start the supervisor that owns the serving task group. Idempotent.

        The group is entered and exited **inside one task of this service's
        own**, not in whichever task happened to call `listen()` and whichever
        one later calls `aclose()`. `TaskGroup` records the entering task and
        drives cancellation through it, so entering in one task and exiting in
        another delivers the group's cancellation to a task that is not in the
        group's `__aexit__` at all. `Client.aclose()` is exactly that caller: the
        client is shut down from wherever the application's teardown runs, which
        is rarely the task that opened the service.
        """
        if self._supervisor is not None:
            return
        self._supervisor = asyncio.get_running_loop().create_task(
            self._supervise(), name="astral-service"
        )
        await self._ready.wait()

    async def _unstart(self, started_here: bool) -> None:
        """Undo a `_start()` this call made, after the work that needed it failed.

        `started_here` is what keeps this from tearing down a supervisor the
        caller owns: `_start()` returns early when one already exists, so a
        service entered with `async with` and then given a listener that would
        not bind keeps the task group it entered with.

        The events are replaced rather than cleared, so a later `listen()` gets a
        supervisor that waits for a stop that has not happened yet -- and they
        are replaced only if the old supervisor is genuinely gone, because a task
        that outlived both budgets still owns the ones it is waiting on.
        """
        if not started_here or self._supervisor is None:
            return
        await self._stop_tasks()
        if self._supervisor is None:
            self._stop = asyncio.Event()
            self._ready = asyncio.Event()

    async def _supervise(self) -> None:
        """Hold the task group open until `aclose()` asks for it back."""
        try:
            async with asyncio.TaskGroup() as tg:
                self._tg = tg
                self._ready.set()
                await self._stop.wait()
        finally:
            self._tg = None
            # A group that failed to open must not leave `_start` waiting for a
            # readiness that will never arrive.
            self._ready.set()

    # --- lifetime ---

    async def aclose(self) -> None:
        """Close the service. Idempotent, and never raises a fault of its own.

        Design section 3.8's order, and each step is what makes the next one
        finish:

        1. refuse new work, so nothing is accepted behind the teardown;
        2. close the listener, so the accept loop ends and every connection the
           OS queued and nobody claimed is closed rather than left unanswered --
           an accepted-but-unserved connection is exactly what wedges astrald's
           own pool (bug G-13);
        3. close every live session and every accepted stream, so the serving
           tasks stop awaiting I/O and return;
        4. await the task group, bounded, and cancel what is left;
        5. close the registrar **last**, so the node's crash-safe deregistration
           fires with the handlers already torn down.

        **Returning means closed**, for every caller: a concurrent second call
        waits for the first rather than reporting a service shut down while its
        descriptors are still open.

        **A cancelled teardown still releases everything, and does not claim to
        have finished.** Both halves are needed and neither is theoretical: the
        canonical bounded shutdown is `asyncio.wait_for(service.aclose(), t)`,
        and a `CancelledError` delivered into this walk used to stop it wherever
        it landed while the `finally` marked the service closed anyway --
        measured at five inbound queries still live, six tasks still running and
        the bind stream still open, with `closed=True` and a second `aclose()`
        returning instantly on the idempotent fast path. So every step is
        `asyncio.shield`ed, which detaches the close from this frame and lets it
        finish whatever happens here, and `_closed` is latched only once nothing
        is left. A teardown that could not finish leaves the service *closing*
        and a later `aclose()` resumes the walk. This is `Client.aclose()`'s
        shape, for the same reasons, against the same failure.
        """
        if self._closed:
            return
        # Latched before anything is awaited, so a teardown cancelled a moment
        # later still stopped the service accepting work.
        self._closing = True
        async with self._sweep:
            if self._closed:
                return
            try:
                server = self._server
                if server is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.shield(server.aclose())
                    self._server = None
                await self._close_all(self._sessions)
                registration = self._registration
                if registration is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.shield(registration.aclose())
                    self._registration = None
                await self._close_all(self._streams)
                await self._stop_tasks()
                # The reference is kept rather than dropped: `registrar` stays a
                # readable fact about a closed service, and `Registrar.aclose()` is
                # idempotent, so nothing depends on forgetting it.
                if self._registrar is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.shield(self._registrar.aclose())
            finally:
                self._closed = self._quiet()

    def _quiet(self) -> bool:
        """Whether the teardown has nothing left to do. The `closed` predicate.

        Every one of these is a resource the close is responsible for, so the
        conjunction is the honest reading of "closed" and anything short of it
        leaves the service *closing*.
        """
        return (
            self._server is None
            and not self._sessions
            and not self._streams
            and self._registration is None
            and self._supervisor is None
            and (self._registrar is None or self._registrar.closed)
        )

    async def _close_all(self, held: set[Any]) -> None:
        """Close every member of one resource set, concurrently and shielded.

        Gathered rather than walked in sequence for the reason `Client.aclose()`
        gives: each close is bounded at `CLOSE_TIMEOUT` per connection, so N
        sequential closes bound at N times it and any sane teardown budget
        expires *inside* the walk by construction.

        A member is dropped only once its own close returned in this frame, so a
        cancellation mid-`gather` leaves it in the set and `closed` stays false.
        The loop runs until the set is empty: a serving task spawned before the
        close began can still add one, and the accept loop cannot, because it
        re-checks `_closing` and closes the transport itself.
        """
        while held:
            batch = list(held)
            await asyncio.gather(
                *(asyncio.shield(item.aclose()) for item in batch),
                return_exceptions=True,
            )
            held.difference_update(batch)

    async def _stop_tasks(self) -> None:
        """Let the supervisor close its group, bounded, then cancel what is left.

        `asyncio.wait` rather than `await task`: the supervisor's own fault, and
        the `CancelledError` it raises after forcing the group down, belong to
        this service and not to the caller's teardown, and `await` would deliver
        both into it. A cancellation aimed at **this** task still propagates,
        which is what `wait` does and what design section 3.5 requires.

        The handle is cleared only once the supervisor has actually ended, so a
        service whose tasks outlived both budgets reports `closing` rather than
        `closed` and a later `aclose()` waits for them again.
        """
        self._stop.set()
        task = self._supervisor
        if task is None:
            return
        done, _ = await asyncio.shield(
            asyncio.wait({task}, timeout=self.close_timeout)
        )
        if not done:
            # A handler is awaiting something this service does not own. The
            # group cancels every child on the way out, so the descriptors are
            # released either way.
            task.cancel()
            done, _ = await asyncio.shield(
                asyncio.wait({task}, timeout=self.close_timeout)
            )
        if not done:  # pragma: no cover -- a task that outlives its own cancel
            return
        self._supervisor = None
        if not task.cancelled():
            fault = task.exception()
            if fault is not None:
                self._record(fault)

    async def __aenter__(self) -> "Service":
        await self._start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def echo_handler(fmt_in: str = "", fmt_out: str = "") -> Handler:
    """A handler that accepts and echoes every object back until `eos` or EOF.

    `objects.echo`'s shape, and the smallest complete responder: it exercises the
    acceptance, the framed read, the framed write and the terminator in four
    lines. Useful as a mount in a test and as the worked example a caller copies.
    """

    async def handle(q: InboundQuery) -> None:
        async with await q.accept(fmt_in=fmt_in, fmt_out=fmt_out) as stream:
            async for obj in stream.raw_objects():
                await stream.send(obj)
            await stream.send_eos()

    return handle


def object_handler(objects: Sequence[Any], *, eos: bool = True) -> Handler:
    """A handler that answers a fixed object sequence. The ST shape.

    `eos=False` ends the stream at bare EOF instead, which is what
    `apphost.whoami` and `dir.alias_map` do (astral-docs bug D-23) and which a
    consumer must therefore handle.
    """

    async def handle(q: InboundQuery) -> None:
        async with await q.accept() as stream:
            for obj in objects:
                await stream.send(obj)
            if eos:
                await stream.send_eos()

    return handle
