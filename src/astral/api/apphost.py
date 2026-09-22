"""`apphost.*` -- the module that hosts the SDK's own connection.

apphost is the node module the IPC protocol is named after: it owns the guest
sessions, the access tokens that authenticate them, the inbound-handler
registrations, and the object holds a local app uses to keep an object from
being collected. Ten ops have a client below, all of them confirmed present on
the live node's `shell.spec` registry. astrald's apphost registry holds more
than this SDK drives; *Authorization* counts it at a named revision.

| Op | Mode | Answer | Notes |
|---|---|---|---|
| `apphost.whoami` | RR | `identity` | anonymous-safe, read-only |
| `apphost.list_tokens` | ST | `apphost.access_token`* + `eos` | local-only, admin action, see below |
| `apphost.list_held_objects` | ST | `object_id.sha256`* + `eos` | local-only, per caller |
| `apphost.create_token` | RR | `apphost.access_token` | local-only, admin action, see below |
| `apphost.register` | RR | `apphost.access_token` | policy-gated |
| `apphost.hold_object` | RR | `ack` | local-only, needs a caller |
| `apphost.unhold_object` | RR | `ack` | local-only, needs a caller |
| `apphost.register_handler` | RR | `ack` | local-only, `serve_apps` |
| `apphost.bind` | BD | `ack`, then held open | local-only |
| `apphost.cancel` | RR | `ack` \\| `error_message` | local-only, owner or admin |

Op mode is a per-op contract and is **not discoverable from the wire** (design
section 4.7), so every method below declares its own and none of them infers
one. The two shapes sit side by side here and were both observed on the same
node in the same run: `whoami` answers with one object and a bare EOF, while
`list_tokens` and `list_held_objects` answer with zero or more and an `eos`.

**"Local-only" is the node's word, not a hint.** Those ops answer
`query_rejected_msg` when `q.Origin()` is the network, so they work from an IPC
guest and never from a peer.

**The `mod.apphost.*_msg` control types are declared in `astral.session`** and
re-exported here. Design section 1 files them under this module, but they are
the layer-2 state machine's own vocabulary and the dependency arrow runs module
clients -> session, never back. They are re-exported rather than redeclared so
there is exactly one `mod.apphost.route_query_msg` class in the process.

**Two wire types exist on the node and are unavailable as surface**, and that is
a property of astrald rather than an omission here:

- `mod.apphost.register_handler_msg` is registered in astral-go and astrald has
  an `onRegisterHandlerMsg` method for it, but `Guest.Serve`'s dispatch switch
  never routes to it (astrald bug G-16). Nothing can reach that method, so the
  type is not declared anywhere in this SDK; registering a handler is the
  `apphost.register_handler` **op**, which is `register_handler()` below.
- `mod.apphost.ping_msg` is a registered type with no handler at all: sending
  one gets `error_msg{protocol_error}` and the connection closed (astrald bug
  G-17). It is declared in `astral.session` for decode completeness and is never
  sent. **There is no keepalive on this protocol.**

## Authorization

**Every `path:line` in this module is read at the revisions `tests/reference.py`
pins, astrald `993ffac0` and astral-go `bf8542a`.** An identity argument travels
under the key `identity` and `apphost.cancel`'s nonce under `query_id`.

**`apphost.list_tokens` and `apphost.create_token` are administration, not
introspection.** Each refuses a query whose origin is the network and then asks
`mod.auth.admin_manage_apps_action`, in that order, before it accepts the
connection or reads a token -- `op_list_tokens.go:21,27` and
`op_create_token.go:21,25`. Each op asks the action itself, through
`mod.Auth.Authorize` on an `AdminManageAppsAction` built from `q.Caller()`;
there is no shared helper between the op and the authority. The action's name is
astral-go's `AdminManageAppsAction.ObjectType()`,
`api/auth/admin_manage_apps_action.go:19`.

`apphost.delete_token` carries the same pair (`op_delete_token.go:20,24`) and so
does the grant surface beside it -- `apphost.grant`, `apphost.list_grants`,
`apphost.revoke`. None of the four has a client here. `apphost.cancel` refuses
the network origin too (`op_cancel.go:23`) and authorizes on ownership instead:
a session cancels what it launched, and the action is the way past that
(`op_cancel.go:58-68`).

**The two questions are not the same question.** `apphost.bind` and
`apphost.cancel` reach the action through `mayManageApps`
(`authorize_admin_manage_apps.go:19-27`), which refuses a zero principal before
it asks the authority (`authorize_admin_manage_apps.go:20-22`) and takes the
session's authenticated identity rather than `q.Caller()`. The token and grant
ops do not use it. The distinction decides who the plaintext-token paragraph
below applies to: the router's substitution of the node identity for a missing
caller reaches the token ops and is refused by `mayManageApps`.

**The census, re-derived at `993ffac0`.** Fourteen `op_*.go` files. Twelve
refuse a network origin; the two that do not are `whoami` and `register`. Six
ask `mod.auth.admin_manage_apps_action` -- `create_token`, `delete_token`,
`list_tokens`, `grant`, `list_grants`, `revoke`. One asks
`mod.auth.serve_apps_action`: `register_handler` (`op_register_handler.go:29`).
The other seven ask no action.

**A local caller holding no token passes the action check, because it arrives
wearing the node's identity.** `mod/user/src/authorize_user_or_node.go:16-21`
allows the user identity and the node's own identity and nobody else; any other
identity reaches the action through a node-local grant or a signed contract
permit (`authorize_user_or_node.go:11-12`). A token-less guest session sends a
nil `Caller` and `core/router.go:45-47` rewrites it to the node's identity.
astrald marks such a session anonymous (`mod/apphost/src/guest.go:200-206`) and
the mark cannot reach an op: `routing.Op` builds its `IncomingQuery` from the
query and its origin alone and drops `Extra`
(`mod/crypto/src/sign_guard.go:33-37`). Inferred from those four, with no live
run behind it: **an unauthenticated local process still reads every access token
on the node in plaintext, and still mints one for any identity it names.** The
two guards stop the caller off a link, and the authenticated app that holds
neither a grant nor a contract permit for the action.

An access token is a bearer credential: whoever reads one authenticates as the
identity it was issued for. That is what makes reading the list administration,
and it is why an SDK caller is told here that the value coming back is a secret.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
from typing import Any, Final, Sequence

from .. import querystring
from ..errors import BadArgumentType, ProtocolError
from ..object import Ack
from ..record import record, wire
from ..session import (
    HANDSHAKE_TIMEOUT,
    OP_BIND,
    OP_CANCEL,
    OP_REGISTER_HANDLER,
    OP_WHOAMI,
    AttachQueryMsg,
    AuthSuccessMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    HandleQueryMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    PingMsg,
    QueryAcceptedMsg,
    QueryRejectedMsg,
    RegisterServiceMsg,
    RejectIncomingMsg,
    RouteQueryMsg,
)
from ..spec import Primitive, Ptr, Spec
from ..stream import Stream
from ..types import Duration, Identity, Nonce, ObjectID, Time, Zone
from .base import ModuleClient

__all__ = [
    "AccessToken",
    "APPHOST_TYPES",
    "Apphost",
    "apphost_types",
    "AttachQueryMsg",
    "AuthSuccessMsg",
    "AuthTokenMsg",
    "BindMsg",
    "ErrorMsg",
    "HandleQueryMsg",
    "HostInfoMsg",
    "IncomingQueryMsg",
    "OP_BIND",
    "OP_CANCEL",
    "OP_CREATE_TOKEN",
    "OP_HOLD_OBJECT",
    "OP_LIST_HELD_OBJECTS",
    "OP_LIST_TOKENS",
    "OP_NEW_APP_CONTRACT",
    "OP_REGISTER",
    "OP_REGISTER_HANDLER",
    "OP_SIGN_APP_CONTRACT",
    "OP_UNHOLD_OBJECT",
    "OP_WHOAMI",
    "PingMsg",
    "QueryAcceptedMsg",
    "QueryRejectedMsg",
    "RegisterServiceMsg",
    "RejectIncomingMsg",
    "RouteQueryMsg",
]

# --- op names ------------------------------------------------------------
#
# The four the session state machine already routes are imported rather than
# respelled: two spellings of "apphost.cancel" is one typo away from a cancel
# that silently never cancels.

OP_CREATE_TOKEN: Final = "apphost.create_token"
OP_HOLD_OBJECT: Final = "apphost.hold_object"
OP_LIST_HELD_OBJECTS: Final = "apphost.list_held_objects"
OP_LIST_TOKENS: Final = "apphost.list_tokens"
OP_REGISTER: Final = "apphost.register"
OP_UNHOLD_OBJECT: Final = "apphost.unhold_object"


# --- parameter specs -----------------------------------------------------
#
# Design section 5.1 rule 2 makes `querystring.encode_param(spec, value)` the
# single implementation of parameter encoding, and a spec is what makes it one:
# without a declared spec the encoder dispatches on the *value*, so a
# wrong-typed argument is encoded rather than refused. `encode_param(
# Primitive("string8"), b"ab")` raises `SchemaError`; `param_text(b"ab")`
# silently sends `YWI=`. The two agree on every value these ops actually send
# today, which is what makes the gap latent rather than loud, and latent is how
# it survives into eleven more modules.
#
# Three specs name three different things on the node:
# `apphost.hold_object`/`unhold_object` take an `object_id.sha256` under `id`,
# the identity ops take a `string8` under `identity`, and `apphost.cancel` takes
# a `nonce64` under `query_id` (`opCreateTokenArgs.Identity` and
# `opCancelArgs.QueryID`). The node resolves `identity` through its
# directory; `list_tokens` and `create_token` send the hex of an identity this
# client has already resolved.

_IDENTITY: Final[dict[str, Spec]] = {
    "identity": Primitive("string8"),
    "duration": Primitive("duration"),
}
_OBJECT_ID: Final[dict[str, Spec]] = {
    "id": Primitive("object_id.sha256"),
    "duration": Primitive("duration"),
}
_HANDLER: Final[dict[str, Spec]] = {
    "endpoint": Primitive("string8"),
    "token": Primitive("nonce64"),
}
_CANCEL: Final[dict[str, Spec]] = {
    "query_id": Primitive("nonce64"),
    "cause": Primitive("string8"),
}


# --- the two data types --------------------------------------------------


@record("apphost.access_token")
class AccessToken:
    """One bearer credential: an identity, the secret that authenticates as it,
    and when it stops doing so.

    The type name has **no `mod.` prefix**. That is not a slip in this
    declaration: astral-go's `AccessToken.ObjectType()` returns
    `apphost.access_token`, and the registry name is what travels on the wire, so
    a `mod.` here would make every token frame undecodable.

    `Token` is a secret in the same sense a password is. astrald mints it as
    `randomString(32)` over `math/rand` rather than `crypto/rand`, and hands the
    whole table to a caller holding `mod.auth.admin_manage_apps_action`, which an
    unauthenticated local process does hold (see the module docstring), so treat
    one that arrives here as compromised the moment it is logged.

    `ExpiresAt` is advisory as far as the node is concerned:
    `Module.AuthenticateToken` looks the token up and returns its identity
    without ever comparing the expiry, so an expired token still authenticates.
    """

    identity: Identity | None = wire("Identity", Ptr("identity"))
    token: str = wire("Token", Primitive("string8"))
    expires_at: Time = wire("ExpiresAt", Primitive("time"))

    @property
    def expired(self) -> bool:
        """Whether `ExpiresAt` has passed. **The node does not check this.**"""
        return int(self.expires_at) <= Time.now()


# --- argument coercion ---------------------------------------------------
#
# Every parameter goes onto the query string in the bare payload half of its
# type's text encoding, which `querystring.build` produces from the value's own
# `text()`. So the coercions below are about accepting what a caller naturally
# holds, and about refusing what would be misread rather than rejected.


def _duration(value: Duration | int | _dt.timedelta | None) -> Duration | None:
    """A `duration` parameter, in nanoseconds.

    A plain `int` is **nanoseconds**, because that is what `Duration` is and
    reinterpreting it as seconds here would make `Duration(5)` and `5` mean
    different things at the same call site. A `float` is refused outright rather
    than read as nanoseconds: every caller who writes `duration=1.5` means
    seconds, and silently sending 1.5 nanoseconds is a token that expires
    before the reply arrives.
    """
    if value is None:
        return None
    if isinstance(value, _dt.timedelta):
        return Duration(int(value // _dt.timedelta(microseconds=1)) * 1_000)
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadArgumentType(
            f"duration: expected a Duration, an int of nanoseconds or a "
            f"timedelta, got {type(value).__name__}"
            + (
                "; seconds are Duration(int(seconds * 1e9))"
                if isinstance(value, float)
                else ""
            )
        )
    return Duration(int(value))


# One implementation, on `ModuleClient`. These names stay because the call sites
# and the tests spell them, but the bodies are the base class's: four spellings
# of one encoder across six modules is how thirteen dialects start.
_encode = ModuleClient._encode


def _object_id(value: ObjectID | str, op: str) -> ObjectID:
    """An `object_id.sha256` parameter, naming the op that refused it."""
    return ModuleClient._object_id(value, op)


class Apphost(ModuleClient):
    """The `apphost.*` ops, bound to one client.

    Reached as `client.apphost`, a cached property built on first use;
    `Apphost(client)` constructs the same object directly. The scaffolding and
    the `**kw` contract are `ModuleClient`'s.

    Two methods take an identity that may be a **directory name**, which costs
    one `dir.resolve` before the op's own query. That resolution runs inside the
    caller's `timeout` -- `kw` is forwarded into it -- so a name target cannot
    make a bounded call unbounded.
    """

    __slots__ = ()

    # --- read-only, anonymous-safe ---

    async def whoami(self, **kw: Any) -> Identity:
        """The identity the node sees this connection as. RR.

        Answers one `identity` and then **closes with no `eos`** -- astral-docs
        bug D-23, verified live. An anonymous guest sends a nil `Caller` and
        astrald's core router substitutes the node's own identity for it, so an
        anonymous caller is told the *node's* identity here and an authenticated
        one is told its guest identity. That substitution is the router's, not
        this op's, and it applies to every op that reads `q.Caller()`.
        """
        return self._expect(await self._c.call_one(OP_WHOAMI, **kw), Identity, OP_WHOAMI)

    async def list_tokens(
        self, id: Identity | str | None = None, **kw: Any  # noqa: A002
    ) -> list[AccessToken]:
        """Access tokens on the node, optionally for one identity. ST.

        **This is a privileged read and the result is secret.** Local-only, and
        gated on `mod.auth.admin_manage_apps_action`; a caller off a link and a
        caller without the action both get `QueryRejected`. With no `id` the node
        returns every token it holds, with the token strings in plaintext, and an
        unauthenticated local process passes the gate as the node (see the module
        docstring). Passing `id` filters server-side, under the wire key
        `identity`; it does not authorize anything.

        `id` accepts an `Identity`, 66 hex characters, `anyone`, or a directory
        name, which costs one `dir.resolve` before this query is sent; the query
        carries the resolved identity's hex. `anyone` names the zero identity,
        which the node refuses with `missing identity`.
        """
        params: dict[str, Any] = {}
        if id is not None:
            params["identity"] = (await self._c.resolve_identity(id, **kw)).text()
        qs = querystring.build(OP_LIST_TOKENS, _encode(_IDENTITY, params))
        return [
            self._expect(obj, AccessToken, OP_LIST_TOKENS)
            for obj in await self._c.call(qs, **kw)
        ]

    async def list_held_objects(self, **kw: Any) -> list[ObjectID]:
        """The objects this caller is holding. ST, local-only.

        Scoped to `q.Caller()` and to unexpired holds, so it is the read side of
        `hold_object` and never a view of anyone else's holds. An anonymous guest
        is given the node's own identity by the router, so it reads the node's
        holds rather than being refused.
        """
        return [
            self._expect(obj, ObjectID, OP_LIST_HELD_OBJECTS)
            for obj in await self._c.call(OP_LIST_HELD_OBJECTS, **kw)
        ]

    # --- tokens ---

    async def create_token(
        self,
        id: Identity | str,  # noqa: A002
        *,
        duration: Duration | int | _dt.timedelta | None = None,
        **kw: Any,
    ) -> AccessToken:
        """Mint an access token for an identity. RR.

        Local-only, and gated on `mod.auth.admin_manage_apps_action`; a caller off
        a link and a caller without the action both get `QueryRejected`. The token
        authenticates as `id` whoever asked for it, so this is the node handing
        out a credential for an identity the caller need not control.

        `id` travels under the wire key `identity`, as the hex of the identity
        this client resolves; a directory name costs one `dir.resolve` first. The
        node refuses the zero identity, `anyone`, with `missing identity`.

        `duration` omitted leaves the node's default of one year. astral-go's
        client sends the identity alone and has no way to ask for anything else.
        """
        resolved = await self._c.resolve_identity(id, **kw)
        params: dict[str, Any] = {"identity": resolved.text()}
        span = _duration(duration)
        if span is not None:
            params["duration"] = span
        qs = querystring.build(OP_CREATE_TOKEN, _encode(_IDENTITY, params))
        return self._expect(await self._c.call_one(qs, **kw), AccessToken, OP_CREATE_TOKEN)

    async def register(self, **kw: Any) -> AccessToken:
        """Provision a fresh guest identity and a token for it. RR.

        The node generates a key pair, signs an app contract for it and answers
        with the token, so this is the bootstrap an app with no credentials
        starts from. Gated by the node's register policy and by the trusted-web-
        origin table: a node that declines answers `query_rejected_msg{1}`, which
        arrives as `QueryRejected`.

        Absent from astral-go entirely; the docs are ahead of it here.
        """
        return self._expect(await self._c.call_one(OP_REGISTER, **kw), AccessToken, OP_REGISTER)

    # --- object holds ---

    async def hold_object(
        self,
        id: ObjectID | str,  # noqa: A002
        *,
        duration: Duration | int | _dt.timedelta | None = None,
        **kw: Any,
    ) -> None:
        """Keep an object from being collected. RR, local-only.

        `duration` omitted is a **permanent** hold, not a defaulted one: astrald
        stores a null expiry for it. The hold is recorded against `q.Caller()`,
        so an anonymous guest holds objects as the node, and an object may be
        held before this node has ever fetched it.

        astral-go's client cannot pass `duration` at all.
        """
        params: dict[str, Any] = {"id": _object_id(id, OP_HOLD_OBJECT)}
        span = _duration(duration)
        if span is not None:
            params["duration"] = span
        qs = querystring.build(OP_HOLD_OBJECT, _encode(_OBJECT_ID, params))
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_HOLD_OBJECT)

    async def unhold_object(self, id: ObjectID | str, **kw: Any) -> None:  # noqa: A002
        """Release this caller's hold on an object. RR, local-only.

        Releases only the calling identity's own hold; another app's hold on the
        same object survives, and the node answers `ack` either way -- a delete
        of no rows is not an error there, so this is not a report that a hold
        existed.
        """
        qs = querystring.build(
            OP_UNHOLD_OBJECT, _encode(_OBJECT_ID, {"id": _object_id(id, OP_UNHOLD_OBJECT)})
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_UNHOLD_OBJECT)

    # --- inbound handlers ---

    async def register_handler(
        self, endpoint: str, token: Nonce | int, **kw: Any
    ) -> None:
        """Tell the node where to dial this app, and with which token. RR.

        `endpoint` is a `<proto>:<addr>` string the **node** must be able to
        reach -- it dials one connection per inbound query and sends
        `mod.apphost.handle_query_msg` as the first frame, with no greeting --
        and `token` is the unguessable value that frame must carry back for the
        listener to trust it.

        Registration is scoped to the calling identity and is **not** scoped to
        this connection. It survives this stream closing; what removes it is
        `bind()` ending with the same token, or the node failing to dial the
        endpoint. So this call alone leaves a registration behind that outlives
        the process (astral-docs bug D-13 is the claim that closing unregisters).

        Local-only, then `mod.auth.serve_apps_action` for the identity the
        handler answers for (`op_register_handler.go:26`).
        That second check does not make the op an authenticated one. It registers
        under `q.Caller()`, which for an anonymous guest is the node's own
        identity because the core router substitutes it for a nil caller, and
        `mod/user/src/authorize_serve_apps.go:8,15` allows the node's identity.
        Registering as the node is therefore still something an unauthenticated
        local process can attempt; whether it then receives the node's queries is
        astrald's business and is not asserted here. `register_service_msg` is
        the authenticated counterpart -- astrald refuses it outright from a
        token-less guest (`mod/apphost/src/guest.go:268-270`).
        """
        qs = querystring.build(
            OP_REGISTER_HANDLER,
            _encode(_HANDLER, {"endpoint": endpoint, "token": Nonce(int(token))}),
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_REGISTER_HANDLER)

    async def bind(
        self,
        *tokens: Nonce | int,
        ack_timeout: float | None = HANDSHAKE_TIMEOUT,
        **kw: Any,
    ) -> Stream:
        """Open the session that scopes handler registrations. BD, local-only.

        The returned stream is **held open for as long as the registrations
        should live**. When it closes -- deliberately, or because the process
        died -- the node removes every handler registered under every token sent
        on it. That is the whole point of the op: crash-safe deregistration that
        does not depend on the app getting to run any cleanup.

        Each `bind_msg` is additive and the stream stays writable, so further
        tokens are `await stream.send(BindMsg(token=Nonce(t)))` at any time.
        astrald collects them all and runs the removals in one deferred sweep;
        the docs read as though one message were expected.

        `ack_timeout` bounds the `ack` and the token sends, and it is a separate
        knob from `timeout` because they bound different things: `timeout` covers
        the route, and this covers an op that was **accepted and then said
        nothing**. That is a state the wire reaches whenever the op goroutine
        stalls between two statements -- `op_bind.go` does `ch := q.Accept(...)`
        and only then `ch.Send(&astral.Ack{})` -- and this stream is opened on
        the persistent lane, so an unbounded wait here would be invisible to the
        client's own budget and would hold one of the node's 32 workers for as
        long as the process lived. `Session.bind()` bounds the same wait with the
        same default and the same message; the two must not drift.

        Opened on the client's **persistent lane**, which spends none of the
        query budget: a permit held for the process's lifetime is a permit the
        client can never reuse, and eight of them is a client that has deadlocked
        itself (design section 3.7). It is still registered with the client, so
        `Client.aclose()` closes it -- which is why this is not
        `Session.bind()`, whose stream no client knows about and which therefore
        outlives its client, holding one of the node's 32 workers.
        """
        kw.setdefault("persistent", True)
        stream = await self._c.query(querystring.build(OP_BIND), **kw)
        try:
            first = await stream.first(timeout=ack_timeout)
            if first is None:
                raise ProtocolError(f"{OP_BIND}: the stream closed before the ack")
            self._expect(first, Ack, OP_BIND)
            for token in tokens:
                await stream.send(BindMsg(token=Nonce(int(token))), timeout=ack_timeout)
        except BaseException:
            # Including cancellation: a bind stream abandoned here would hold a
            # node worker with no tokens registered on it, which is the worst of
            # both.
            await stream.aclose()
            raise
        return stream

    # --- cancellation ---

    async def cancel(
        self, id: Nonce | int, *, cause: str | None = None, **kw: Any  # noqa: A002
    ) -> bool:
        """Cancel a query that is still en route, by its nonce. RR.

        The protocol has no in-band cancel: a query is cancelled from a
        **different** connection, naming the nonce the original `route_query_msg`
        carried, after which that query's caller sees `error_msg{canceled}` or
        EOF. `Stream.cancel()` is the same op reached from the stream that owns
        the nonce, and the SDK issues it itself when an in-flight query is
        cancelled. The nonce travels under the wire key `query_id`.

        Returns whether the node had that query en route. `False` is the ordinary
        outcome for a query that has already been answered, and it is the only
        `error_message` this op sends, so the message is not inspected. It is
        also what a caller that may not cancel the query is told, deliberately:
        a session cancels what it launched, `mod.auth.admin_manage_apps_action`
        is the way past that, and a refusal reads as "not found" so a caller
        learns nothing about the nonces other apps hold (`op_cancel.go:36-40`).

        Local-only. A query off a link is rejected before any of that
        (`op_cancel.go:23`).

        `zone=device` by default, matching astral-go: cancelling is a local act
        and a cancel that left the machine would be routed as a query of its own.
        """
        kw.setdefault("zone", Zone.DEVICE)
        params: dict[str, Any] = {"query_id": Nonce(int(id))}
        if cause:
            params["cause"] = cause
        qs = querystring.build(OP_CANCEL, _encode(_CANCEL, params))
        async with self._one_shot(qs, kw) as (s, budget):
            # `raw_objects()` rather than `first()`: the `error_message` is the
            # answer here, not a failure, and the iterator that raises on one
            # would turn "already finished" into an exception. The budget is the
            # client's one-shot budget, so an accepted-and-silent cancel costs
            # `timeout` and not the connection.
            answers = s.raw_objects()
            try:
                async with asyncio.timeout(budget.remaining):
                    answer = await anext(answers, None)
            finally:
                await answers.aclose()
        return isinstance(answer, Ack)


APPHOST_TYPES: Final[Sequence[type]] = (
    AccessToken,
    AttachQueryMsg,
    AuthSuccessMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    HandleQueryMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    PingMsg,
    QueryAcceptedMsg,
    QueryRejectedMsg,
    RegisterServiceMsg,
    RejectIncomingMsg,
    RouteQueryMsg,
)
"""Every wire type this module declares or re-exports, for a registry sweep.

Useful to a caller building a private `Blueprints` rather than the default one:
`registry.add(*Apphost.TYPES)` puts the whole apphost vocabulary in it.
`mod.apphost.register_handler_msg` is absent because it is unreachable on the
node (bug G-16), and `ping_msg` is present because it decodes even though nothing
ever sends it (bug G-17).
"""

Apphost.TYPES = APPHOST_TYPES


def apphost_types() -> Sequence[type]:
    """`APPHOST_TYPES`, as a call. Kept for the callers that already spell it."""
    return APPHOST_TYPES
