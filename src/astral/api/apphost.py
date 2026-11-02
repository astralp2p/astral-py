"""`apphost.*` -- the module that hosts the SDK's own connection.

apphost is the node module the IPC protocol is named after: it owns the guest
sessions, the access tokens that authenticate them, the inbound-handler
registrations, and the object holds a local app uses to keep an object from
being collected. Fifteen ops have a client below. Eleven were confirmed present
on the live node's `shell.spec` registry; the four grant ops -- `grant`,
`request_grant`, `list_grants` and `revoke` -- are read at the pins and at
astral-go's clients, not confirmed live. astrald's apphost registry holds more
than this SDK drives; *Authorization* counts it at a named revision.

| Op | Mode | Answer | Notes |
|---|---|---|---|
| `apphost.whoami` | RR | `identity` | read-only |
| `apphost.list_tokens` | ST | `apphost.access_token`* + `eos` | local-only, admin action, see below |
| `apphost.list_held_objects` | ST | `object_id.sha256`* + `eos` | local-only, per caller |
| `apphost.create_token` | RR | `apphost.access_token` | local-only, admin action, see below |
| `apphost.register` | WA | `apphost.access_token` \\| `error_message` | local-only, policy-gated, no token needed, **mutates** |
| `apphost.grant` | WA | `ack` \\| `error_message` | local-only, admin action, **mutates** |
| `apphost.request_grant` | WA | `ack` \\| `error_message` | local-only, session identity, policy-gated, **mutates** |
| `apphost.list_grants` | ST | `mod.apphost.grant`* + `eos` | local-only, admin action |
| `apphost.revoke` | RR | `ack` \\| `error_message` | local-only, admin action, **mutates** |
| `apphost.set_app_register_policy` | RR | `ack` \\| `error_message` | admin action, **mutates** |
| `apphost.hold_object` | RR | `ack` | local-only, needs a caller, `store_objects` |
| `apphost.unhold_object` | RR | `ack` | local-only, needs a caller |
| `apphost.register_handler` | RR | `ack` | local-only, `serve_apps` |
| `apphost.bind` | BD | `ack`, then held open | local-only |
| `apphost.cancel` | RR | `ack` \\| `error_message` | local-only, owner or admin |

Op mode is a per-op contract and is **not discoverable from the wire** (design
section 4.7), so every method below declares its own and none of them infers
one. The two shapes sit side by side here and were both observed on the same
node in the same run: `whoami` answers with one object and a bare EOF, while
`list_tokens` and `list_held_objects` answer with zero or more and an `eos`.

**"Local-only" is the node's word, not a hint.** Those ops accept the query
and answer `origin not allowed: network` when `q.Origin()` is the network, so
they work from an IPC guest and never from a peer.

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
pins, astrald `5f17900d` and astral-go `dbc27574`.** An identity argument travels
under the key `identity` and `apphost.cancel`'s nonce under `query_id`.

**Every op accepts the query before it refuses one.** A refused caller reads an
`error_message` inside the accepted stream, which surfaces as `RemoteError`, and
never a `query_rejected_msg`: `origin not allowed: network` for a network
origin, `not permitted` for a caller the action check refuses
(`astral-go/api/auth/errors.go`, `astral-go/astral/errors.go`
`NewErrOriginNotAllowed`).

**A session without a token reaches six ops and no others.** apphost confines
it, IPC and WebSocket alike, to `anonymous_allowlist`
(`mod/apphost/src/setup_guard.go` `admitsAnonymous`, called at
`mod/apphost/src/guest.go:150`), and denies every other query with
`error_msg{denied}` before routing. The default lists are `user.info`,
`user.derive_identity`, `user.bootstrap`, `user.join`, `apphost.register` and
`.spec` while the node is unclaimed, and `user.info`, `apphost.register` and
`.spec` once a user claims it (`mod/apphost/src/config.go:55-69`). Every op
below except `register` therefore needs a token.

**`apphost.list_tokens` and `apphost.create_token` are administration, not
introspection.** Each accepts, then answers a network origin and then asks
`mod.auth.admin_manage_apps_action`, in that order, before it reads a token --
`op_list_tokens.go:24,30` and `op_create_token.go:21,25`. Each op asks the
action itself, through `mod.Auth.Authorize` on an `AdminManageAppsAction`
built from `q.Caller()`; there is no shared helper between the op and the
authority. The action's name is astral-go's
`AdminManageAppsAction.ObjectType()`,
`api/auth/admin_manage_apps_action.go:19`.

`apphost.delete_token` carries the same pair (`op_delete_token.go:23,27`) and so
does the grant surface beside it -- `apphost.grant`, `apphost.list_grants`,
`apphost.revoke`; `grant()`, `list_grants()` and `revoke()` below are their
clients. `apphost.cancel` refuses the network origin too
(`op_cancel.go:30`) and authorizes on ownership instead:
a session cancels what it launched, and the action is the way past that
(`op_cancel.go:57-63`).

**The two questions are not the same question.** `apphost.bind` and
`apphost.cancel` reach the action through `mayManageApps`
(`authorize_admin_manage_apps.go:19-27`), which refuses a zero principal before
it asks the authority (`authorize_admin_manage_apps.go:20-22`) and takes the
session's authenticated identity rather than `q.Caller()`. The token and grant
ops do not use it.

**The census, re-derived at `5f17900d`.** Seventeen `op_*.go` files. Fifteen
refuse a network origin; the two that do not are `whoami` and
`set_app_register_policy`, whose file also serves
`apphost.set_grant_request_policy`. Seven ask
`mod.auth.admin_manage_apps_action` -- `create_token`, `delete_token`,
`list_tokens`, `grant`, `list_grants`, `revoke` and `set_app_register_policy`.
One asks `mod.auth.serve_apps_action`: `register_handler`
(`op_register_handler.go:33`). One asks `mod.user.see_swarm_action`: `hosts`
(`op_hosts.go:35`), which names the nodes that host an app, finds them through
their `mod.nodes.relay_for_action` contracts and has no client here. One asks
`mod.auth.store_objects_action`: `hold_object` (`op_hold_object.go:36`).
`request_grant` asks no action: it refuses a session with no authenticated
identity and asks the grant request policy (`op_request_grant.go:40-62`);
`request_grant()` below is its client. The other five ask no action.

**`apphost.set_app_register_policy` delegates the decision on every
`apphost.register` to an op of another identity**, or with no delegate named
restores the bundled accept-all policy (`op_set_app_register_policy.go:60-66`);
`set_app_register_policy()` below is its client. It accepts, then asks the
action and answers `not permitted` when it is refused, and it refuses no
origin, so a network caller holding the permit reaches it
(`op_set_app_register_policy.go:53-58`). The node stores the delegate as a
`policy.delegate` (`astral.api.policy`), asks it with a
`mod.apphost.app_register_request` and reads a
`mod.apphost.app_register_decision` back; both are declared below.

**`apphost.register`, `apphost.grant` and `apphost.request_grant` each read
one object off the channel after they accept.** The query carries no argument,
and the object carries everything the op needs:
`mod.apphost.register_request` (`api/apphost/register_request.go:10-22`),
`mod.apphost.grant_request` (`api/apphost/grant_request.go:10-19`) and
`mod.apphost.request_grant_request`
(`api/apphost/request_grant_request.go:10-19`), each permit a whole
`mod.auth.permit` with its constraints. astral-go's client sends the object
even when it is empty (`api/apphost/client/register.go:49-50`). Grants add up:
a grant never replaces another, granting a permit identical to a held one sets
that grant's expiry to the new value, and narrowing is granting the narrow
permit and then revoking the wide one (`api/apphost/client/grant.go:15-17`).
An unknown action, missing required constraints, or constraints the action's
validator refuses are refused with `invalid permit: <action>: <detail>` before
anything is written (`api/auth/errors.go:16-19`).

**The astrald pin precedes the object inputs.** At `5f17900d` the three ops
read query arguments -- `grant_permits`, `contract_permits` and `name` on
register (`op_register.go:23-39`), `identity`, `action`, `duration` and
`constrained` on grant (`op_grant.go:12-19`), `permits` on request_grant
(`op_request_grant.go:12-18`) -- and `list_grants` answers bare
`mod.auth.permit` objects (`op_list_grants.go:43-55`), not `mod.apphost.grant`.
The clients below send the form astral-go `dbc27574` defines, which astrald
`5f17900d` does not read. At the pin the register grant request opens with
`mod.auth.serve_apps_action` and `mod.auth.use_blueprints_action`
(`register_grant_request.go:17-20`), the op answers a network origin with
`origin not allowed: network` (`op_register.go:55-62`), and the bundled policy
answers with both lists as asked (`mod/apphost/register_policy.go:29-34`).

**A session holding a token that names the node passes every action check.**
`mod/user/src/authorize_user_or_node.go:17-22` allows the user identity and the
node's own identity and nobody else; any other identity reaches the action
through a node-local grant or a signed contract permit
(`authorize_user_or_node.go:12-13`). An authenticated session's empty caller
is its own identity (`mod/apphost/src/guest.go:154-158`), and a token-less
session's nil caller is rewritten to the node's identity by
`core/router.go:45-47` -- but such a session reaches no op outside
`anonymous_allowlist`, and none of the token or grant ops is on it. **Whoever
holds the node's token reads every access token on the node in plaintext,
mints one for any identity it names, and grants any identity any action.** The
two guards stop the caller off a link, and the authenticated app that holds
neither a grant nor a contract permit for the action.

An access token is a bearer credential: whoever reads one authenticates as the
identity it was issued for. That is what makes reading the list administration,
and it is why an SDK caller is told here that the value coming back is a secret.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
from typing import Any, Final, Iterable, Sequence

from .. import querystring
from ..errors import BadArgument, BadArgumentType, ProtocolError
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
from ..spec import Primitive, Ptr, Slice, Spec
from ..stream import Stream
from ..types import Duration, Identity, Nonce, ObjectID, Time, Zone
from .auth import AuthorizerAssignment, Permit
from .base import ModuleClient
from .policy import setter_query

__all__ = [
    "AccessToken",
    "APPHOST_TYPES",
    "Apphost",
    "AppRegisterDecision",
    "AppRegisterRequest",
    "apphost_types",
    "AttachQueryMsg",
    "AuthSuccessMsg",
    "AuthTokenMsg",
    "BindMsg",
    "ERR_GRANT_DECLINED",
    "ERR_GRANT_NOT_FOUND",
    "ERR_REGISTRATION_DECLINED",
    "ErrorMsg",
    "Grant",
    "GrantRequest",
    "HandleQueryMsg",
    "HostInfoMsg",
    "IncomingQueryMsg",
    "OP_BIND",
    "OP_CANCEL",
    "OP_CREATE_TOKEN",
    "OP_GRANT",
    "OP_HOLD_OBJECT",
    "OP_LIST_GRANTS",
    "OP_LIST_HELD_OBJECTS",
    "OP_LIST_TOKENS",
    "OP_REGISTER",
    "OP_REGISTER_HANDLER",
    "OP_REQUEST_GRANT",
    "OP_REVOKE",
    "OP_SET_APP_REGISTER_POLICY",
    "OP_UNHOLD_OBJECT",
    "OP_WHOAMI",
    "PingMsg",
    "QueryAcceptedMsg",
    "QueryRejectedMsg",
    "RegisterRequest",
    "RegisterServiceMsg",
    "RejectIncomingMsg",
    "RequestGrantRequest",
    "RouteQueryMsg",
]

# --- op names ------------------------------------------------------------
#
# The four the session state machine already routes are imported rather than
# respelled: two spellings of "apphost.cancel" is one typo away from a cancel
# that silently never cancels.

OP_CREATE_TOKEN: Final = "apphost.create_token"
OP_GRANT: Final = "apphost.grant"
OP_HOLD_OBJECT: Final = "apphost.hold_object"
OP_LIST_GRANTS: Final = "apphost.list_grants"
OP_LIST_HELD_OBJECTS: Final = "apphost.list_held_objects"
OP_LIST_TOKENS: Final = "apphost.list_tokens"
OP_REGISTER: Final = "apphost.register"
OP_REQUEST_GRANT: Final = "apphost.request_grant"
OP_REVOKE: Final = "apphost.revoke"
OP_SET_APP_REGISTER_POLICY: Final = "apphost.set_app_register_policy"
OP_UNHOLD_OBJECT: Final = "apphost.unhold_object"

ERR_REGISTRATION_DECLINED: Final = "registration declined"
"""`register`: the register policy refused, or could not decide.

The node accepts the query before its policy decides and then sends this as
an `error_message`, which surfaces as `RemoteError` with this `message`
(`api/apphost/errors.go:5-7` at astral-go `dbc27574`, sent at
`mod/apphost/src/op_register.go:75-86`).
"""

ERR_GRANT_DECLINED: Final = "grant declined"
"""`request_grant`: the grant request policy refused, or could not decide.

The node accepts the query before its policy decides and then sends this as
an `error_message`, which surfaces as `RemoteError` with this `message`
(`api/apphost/errors.go:9-11` at astral-go `dbc27574`, sent at
`mod/apphost/src/op_request_grant.go:56-63`).
"""

ERR_GRANT_NOT_FOUND: Final = "grant not found"
"""`revoke`: the identity holds no grant the arguments name.

Sent as an `error_message` (`mod/apphost/src/op_revoke.go:50-51`), which
surfaces as `RemoteError` with this `message`.
"""


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
# `apphost.revoke` names one grant by `id` or every grant for an action by
# `action`. astral-go's clients send `id` as an `astral.Uint64` and `action` as
# a string (`api/apphost/client/revoke.go:14,27`), and the node's `Action` is an
# `astral.String8` (`opRevokeArgs`, `mod/apphost/src/op_revoke.go:13-17`).
_REVOKE: Final[dict[str, Spec]] = {
    "identity": Primitive("string8"),
    "id": Primitive("uint64"),
    "action": Primitive("string8"),
}

_STRING8_MAX: Final = 255
"""The longest `string8` astral-go writes (`astral/string_types.go:25-27`)."""


# --- the data types -------------------------------------------------------


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
    whole table to a caller holding `mod.auth.admin_manage_apps_action`, which a
    session holding the node's token does hold (see the module docstring), so treat
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


# --- the app registration policy types --------------------------------------
#
# What the app registration policy is asked and what it answers. The node sends
# a request to a delegate and reads a decision back; no op of this module
# answers with one. Each field order is the node's `objects.get_blueprint`
# answer on astrald `1286a469`, and each is astral-go's
# `api/apphost/app_register_policy.go`.


@record("mod.apphost.app_register_request")
class AppRegisterRequest:
    """One `apphost.register`, as the policy sees it.

    `origin` is the caller's web origin, empty for a local IPC caller. `name`
    is the app's own claim and the node does not verify it. `grant_permits`
    are the permits the app asked to hold as node-local grants, and
    `contract_permits` the permits it asked to hold in a signed node-to-app
    contract. astral-go's comment says the origin's trusted-source entitlement
    is joined into `contract_permits` (`api/apphost/app_register_policy.go:12-26`);
    astrald joins nothing and sends the asked list
    (`mod/apphost/src/op_register.go:51`). The grant request always opens with
    `mod.auth.serve_apps_action` and `mod.auth.use_blueprints_action`
    (`mod/apphost/src/register_grant_request.go:17-20`).
    """

    origin: str = wire("Origin", Primitive("string8"))
    name: str = wire("Name", Primitive("string8"))
    grant_permits: list[Permit | None] = wire("GrantPermits", Slice("mod.auth.permit"))
    contract_permits: list[Permit | None] = wire("ContractPermits", Slice("mod.auth.permit"))


@record("mod.apphost.app_register_decision")
class AppRegisterDecision:
    """The app registration policy's answer.

    `allow` false refuses the registration and the node ignores the other
    fields. Otherwise the node writes exactly the permits listed, on the rail
    each list names, and records `authorizers` for the new identity
    (`api/apphost/app_register_policy.go:46-58`). An assignment that is nil,
    invalid, or names an `actor` fails astral-go's
    `AppRegisterDecision.Validate`, and the node refuses the registration on it
    (`mod/apphost/src/op_register.go:83-86`): the delegate names the authorizer
    and the node names the actor.
    """

    allow: bool = wire("Allow", Primitive("bool"))
    grant_permits: list[Permit | None] = wire("GrantPermits", Slice("mod.auth.permit"))
    contract_permits: list[Permit | None] = wire("ContractPermits", Slice("mod.auth.permit"))
    authorizers: list[AuthorizerAssignment | None] = wire(
        "Authorizers", Slice("mod.auth.authorizer_assignment")
    )


# --- the grant types --------------------------------------------------------
#
# One grant as `apphost.list_grants` reports it, and the three objects
# `apphost.register`, `apphost.grant` and `apphost.request_grant` read off the
# channel. Each is astral-go's `api/apphost` type at `dbc27574`, whose field
# order is the wire order, and each field list is `astral.BlueprintOf`'s answer
# there, which is what the node's `objects.get_blueprint` sends
# (`mod/objects/src/module.go:237-255` at astrald `5f17900d`).


@record("mod.apphost.grant")
class Grant:
    """One node-local grant (`api/apphost/grant.go:10-21`).

    `id` names the grant to `apphost.revoke`, and the node never assigns the ID
    of a deleted grant to another grant. `permit` is the recorded permit, with
    its constraints as written. `expires_at` is the instant the grant lapses;
    `None` means the grant lasts until revoked.
    """

    id: int = wire("ID", Primitive("uint64"))
    permit: Permit | None = wire("Permit", Ptr("mod.auth.permit"))
    expires_at: Time | None = wire("ExpiresAt", Ptr("time"))


@record("mod.apphost.register_request")
class RegisterRequest:
    """What an app sends `apphost.register`
    (`api/apphost/register_request.go:10-22`).

    The node hands it to the app register policy as an `AppRegisterRequest`,
    which adds the caller's web origin. `name` is the app's own claim and the
    node does not verify it. `grant_permits` are the permits the app asks to
    hold as node-local grants and `contract_permits` the permits it asks to hold
    in a signed node-to-app contract, each with its constraints.
    """

    name: str = wire("Name", Primitive("string8"))
    grant_permits: list[Permit | None] = wire("GrantPermits", Slice("mod.auth.permit"))
    contract_permits: list[Permit | None] = wire("ContractPermits", Slice("mod.auth.permit"))


@record("mod.apphost.grant_request")
class GrantRequest:
    """The grants a caller asks `apphost.grant` to write for one identity
    (`api/apphost/grant_request.go:10-19`).

    Each permit becomes one node-local grant for `identity`. `duration` is the
    lifetime of each grant; zero writes grants that last until revoked.
    """

    identity: Identity | None = wire("Identity", Ptr("identity"))
    duration: Duration = wire("Duration", Primitive("duration"))
    permits: list[Permit | None] = wire("Permits", Slice("mod.auth.permit"))


@record("mod.apphost.request_grant_request")
class RequestGrantRequest:
    """The grants a session asks `apphost.request_grant` for
    (`api/apphost/request_grant_request.go:10-19`).

    The grantee is the identity of the session's access token, and the request
    names no identity. `duration` is the lifetime asked for each grant; zero
    asks for grants that last until revoked.
    """

    permits: list[Permit | None] = wire("Permits", Slice("mod.auth.permit"))
    duration: Duration = wire("Duration", Primitive("duration"))


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


def _permit_list(
    values: Iterable[Permit | str] | None, key: str, op: str
) -> list[Permit | None]:
    """A permit list of a request object: whole `mod.auth.permit`s.

    `None` is the empty list. A `Permit` is sent as given, constraints and all;
    a `str` names an action and becomes `Permit(action=...)` with no
    constraints. A bare `str`, `bytes` or `Permit` is refused rather than read
    as a list, and so is an entry of any other type. An action is a `string8`
    in `mod.auth.permit`, so an empty one or one over 255 UTF-8 bytes raises
    `BadArgument` before a query leaves.
    """
    if values is None:
        return []
    if isinstance(values, (str, bytes, Permit)):
        raise BadArgumentType(
            f"{op}: {key} expects a list of permits, got {type(values).__name__}"
        )
    permits: list[Permit | None] = []
    for value in values:
        if isinstance(value, str):
            value = Permit(action=value)
        elif not isinstance(value, Permit):
            raise BadArgumentType(
                f"{op}: {key} expects Permit or action-name entries, got "
                f"{type(value).__name__}"
            )
        size = len(value.action.encode("utf-8"))
        if not size or size > _STRING8_MAX:
            raise BadArgument(
                f"{op}: {key} entry names an action of {size} bytes; an action "
                f"is a string8 of 1 to {_STRING8_MAX}"
            )
        permits.append(value)
    return permits


def _app_name(value: str | None) -> str | None:
    """`RegisterRequest.name`: a `string8`, so a name over 255 UTF-8 bytes
    cannot be encoded and is refused here with the op named."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadArgumentType(
            f"{OP_REGISTER}: name expects a str, got {type(value).__name__}"
        )
    if len(value.encode("utf-8")) > _STRING8_MAX:
        raise BadArgument(
            f"{OP_REGISTER}: name is {len(value.encode('utf-8'))} bytes; it is a "
            f"string8 of at most {_STRING8_MAX}"
        )
    return value


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

    Five methods -- `list_tokens`, `create_token`, `grant`, `list_grants` and
    `revoke` -- take an identity that may be a **directory name**, which costs
    one `dir.resolve` before the op's own query. That resolution runs inside the
    caller's `timeout` -- `kw` is forwarded into it -- so a name target cannot
    make a bounded call unbounded.
    """

    __slots__ = ()

    # --- read-only ---

    async def whoami(self, **kw: Any) -> Identity:
        """The identity the node sees this connection as. RR.

        Answers one `identity` and then **closes with no `eos`** -- astral-docs
        bug D-23, verified live. An authenticated session that sends a nil
        `Caller` is told its guest identity, because apphost names an empty
        caller after the session's token (`mod/apphost/src/guest.go:154-158`).
        A session without a token is denied this op: it is not on astrald's
        `anonymous_allowlist`.
        """
        return self._expect(await self._c.call_one(OP_WHOAMI, **kw), Identity, OP_WHOAMI)

    async def list_tokens(
        self, id: Identity | str | None = None, **kw: Any  # noqa: A002
    ) -> list[AccessToken]:
        """Access tokens on the node, optionally for one identity. ST.

        **This is a privileged read and the result is secret.** Local-only, and
        gated on `mod.auth.admin_manage_apps_action`; the node accepts, then
        answers a caller off a link with `origin not allowed: network` and a
        caller without the action with `not permitted`, each a `RemoteError`.
        With no `id` the node returns every token it holds, with the token
        strings in plaintext, and a session holding the node's token passes the
        gate as the node (see the module docstring). Passing `id` filters
        server-side, under the wire key `identity`; it does not authorize
        anything.

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
        `hold_object` and never a view of anyone else's holds. A session holding
        the node's token reads the node's holds; a session without a token is
        denied the op.
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

        Local-only, and gated on `mod.auth.admin_manage_apps_action`; the node
        accepts, then answers a caller off a link with
        `origin not allowed: network` and a caller without the action with
        `not permitted`, each a `RemoteError`. The token
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

    # --- grants ---

    async def grant(
        self,
        identity: Identity | str,
        permits: Iterable[Permit | str],
        *,
        duration: Duration | int | _dt.timedelta | None = None,
        **kw: Any,
    ) -> None:
        """Grant `identity` the permits named, on this node. WA: one
        `mod.apphost.grant_request` in, one `ack` out, then EOF. **Mutates.**

        Each permit, with its constraints, becomes one node-local grant for
        `identity`. Grants add up: a grant never replaces another, and granting
        a permit identical to one `identity` holds sets that grant's expiry to
        the new value (`api/apphost/client/grant.go:10-17`). The answer carries
        no ID; `list_grants()` names each grant. Constraints on an action that
        evaluates none are written as sent and change nothing it allows, as
        `Permit` states.

        Local-only, and gated on `mod.auth.admin_manage_apps_action`; the node
        accepts, then answers a caller off a link with
        `origin not allowed: network` and a caller without the action with
        `not permitted`, each a `RemoteError` (`op_grant.go:29-40`). An invalid
        permit is a `RemoteError` reading `invalid permit: <action>: <detail>`
        (`api/auth/errors.go:16-19`).

        `identity` is resolved by this client, so a directory name costs one
        `dir.resolve` first, and travels in the request's `Identity`. The node
        refuses the zero identity, `anyone`, with `missing identity`
        (`op_grant.go:47-49`). Each entry of `permits` is a `Permit` or an
        action name, which becomes a `Permit` with no constraints. An empty
        list raises `BadArgument` before a query leaves, because a request
        with no permits writes nothing. `duration` omitted or zero writes
        grants that last until revoked (`api/apphost/grant_request.go:13-14`).
        """
        permit_list = _permit_list(permits, "permits", OP_GRANT)
        if not permit_list:
            raise BadArgument(f"{OP_GRANT}: permits is empty")
        span = _duration(duration)
        req = GrantRequest(
            identity=await self._c.resolve_identity(identity, **kw),
            duration=Duration(0) if span is None else span,
            permits=permit_list,
        )
        answers = await self._c.call_with(OP_GRANT, req, expect=1, **kw)
        if not answers:
            raise ProtocolError(f"{OP_GRANT}: the stream ended without answering the request")
        self._expect(answers[0], Ack, OP_GRANT)

    async def request_grant(
        self,
        permits: Iterable[Permit | str],
        *,
        duration: Duration | int | _dt.timedelta | None = None,
        **kw: Any,
    ) -> None:
        """Ask the node to grant this session's identity the permits named.
        WA: one `mod.apphost.request_grant_request` in, one `ack` out, then
        EOF. **Mutates** when the policy approves.

        The grantee is the identity of this session's access token; the request
        names no identity (`api/apphost/request_grant_request.go:10-12`). The
        node answers a network origin with `origin not allowed: network` and a
        session with no authenticated identity with `not permitted`
        (`op_request_grant.go:33-42`). It accepts the query before its grant
        request policy decides and asks the policy on every call, even for
        permits the session already holds; approved grants add to those the
        session holds (`api/apphost/client/request_grant.go:10-18`). A refusal
        is a `RemoteError` reading `ERR_GRANT_DECLINED`, and an invalid permit
        one reading `invalid permit: <action>: <detail>`
        (`request_grant.go:20-21`). `apphost.set_grant_request_policy` sets
        the policy and has no client here.

        Each entry of `permits` is a `Permit` or an action name, as for
        `grant()`, and an empty list raises `BadArgument` before a query
        leaves. `duration` omitted or zero asks for grants that last until
        revoked (`api/apphost/request_grant_request.go:14-15`).

        A delegated policy may wait on a person, and the node bounds one
        question at ten minutes (`api/policy/delegate.go:14-16`), so `timeout`
        defaults to 600 s here rather than the client's 60 s. The call holds
        one of the node's 32 apphost workers while it waits.

        A discovery permit scoped to one service, the shape smithd asks for::

            await client.apphost.request_grant([
                Permit(
                    action=ServiceDiscoveryAction.ASTRAL_TYPE,
                    constraints=Bundle([
                        DiscoveryScope(rules=[DiscoveryRule(services=["inference"])])
                    ]),
                )
            ])
        """
        permit_list = _permit_list(permits, "permits", OP_REQUEST_GRANT)
        if not permit_list:
            raise BadArgument(f"{OP_REQUEST_GRANT}: permits is empty")
        span = _duration(duration)
        req = RequestGrantRequest(
            permits=permit_list, duration=Duration(0) if span is None else span
        )
        kw.setdefault("timeout", 600.0)
        answers = await self._c.call_with(OP_REQUEST_GRANT, req, expect=1, **kw)
        if not answers:
            raise ProtocolError(
                f"{OP_REQUEST_GRANT}: the stream ended without answering the request"
            )
        self._expect(answers[0], Ack, OP_REQUEST_GRANT)

    async def list_grants(self, identity: Identity | str, **kw: Any) -> list[Grant]:
        """The unexpired node-local grants `identity` holds. ST: zero or more
        `mod.apphost.grant`, then `eos`.

        Each grant's `id` names it to `revoke()`
        (`api/apphost/client/list_grants.go:10-13`), and the node leaves an
        expired grant out (`op_list_grants.go:17-19`). Local-only and gated on
        `mod.auth.admin_manage_apps_action`, as `grant()` is; a refusal is a
        `RemoteError`.

        `identity` travels under the wire key `identity`, as the hex of the
        identity this client resolves; a directory name costs one `dir.resolve`
        first.
        """
        resolved = await self._c.resolve_identity(identity, **kw)
        qs = querystring.build(
            OP_LIST_GRANTS, _encode(_IDENTITY, {"identity": resolved.text()})
        )
        return [
            self._expect(obj, Grant, OP_LIST_GRANTS)
            for obj in await self._c.call(qs, **kw)
        ]

    async def revoke(
        self,
        identity: Identity | str,
        *,
        id: int | None = None,  # noqa: A002
        action: str | None = None,
        **kw: Any,
    ) -> None:
        """Delete node-local grants of `identity`. RR, one `ack`. **Mutates.**

        Exactly one of `id` or `action`. `id` deletes the one grant
        `list_grants()` reported under it, which must be a grant `identity`
        holds; `action` deletes every grant `identity` holds for that action
        (`api/apphost/client/revoke.go:9-12,23-25`). Both or neither raises
        `BadArgument` before a query leaves. `id` is an `int` that fits a
        `uint64`, and `action` an action name of 1 to 255 UTF-8 bytes.

        A grant the node does not find is a `RemoteError` reading
        `ERR_GRANT_NOT_FOUND`. Local-only and gated on
        `mod.auth.admin_manage_apps_action`, as `grant()` is. `identity`
        travels as the hex of the identity this client resolves.
        """
        if (id is None) == (action is None):
            raise BadArgument(f"{OP_REVOKE}: give exactly one of id and action")
        params: dict[str, Any] = {}
        if id is not None:
            if isinstance(id, bool) or not isinstance(id, int):
                raise BadArgumentType(
                    f"{OP_REVOKE}: id expects an int, got {type(id).__name__}"
                )
            if not 0 <= id < 1 << 64:
                raise BadArgument(f"{OP_REVOKE}: id {id} does not fit a uint64")
            params["id"] = id
        else:
            if not isinstance(action, str):
                raise BadArgumentType(
                    f"{OP_REVOKE}: action expects a str, got {type(action).__name__}"
                )
            size = len(action.encode("utf-8"))
            if not size or size > _STRING8_MAX:
                raise BadArgument(
                    f"{OP_REVOKE}: action is {size} bytes; it is a string8 of 1 "
                    f"to {_STRING8_MAX}"
                )
            params["action"] = action
        params["identity"] = (await self._c.resolve_identity(identity, **kw)).text()
        qs = querystring.build(OP_REVOKE, _encode(_REVOKE, params))
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_REVOKE)

    async def register(
        self,
        *,
        name: str | None = None,
        grant_permits: Iterable[Permit | str] | None = None,
        contract_permits: Iterable[Permit | str] | None = None,
        **kw: Any,
    ) -> AccessToken:
        """Provision a fresh guest identity and a token for it. WA: one
        `mod.apphost.register_request` in, one `apphost.access_token` out, then
        EOF. **Mutates.**

        The node generates a key pair, signs an app contract for it and answers
        with the token, so this is the bootstrap an app with no credentials
        starts from (`api/apphost/client/register.go:22-26`). The token and
        every permit written expire after ten years
        (`op_register.go:17,128,178`).

        `grant_permits` are the permits to hold as node-local grants and
        `contract_permits` those to hold in a signed node-to-app contract; each
        entry is a `Permit`, constraints and all, or an action name. `name` is
        shown to a delegated policy and the node does not verify it. Asking is
        not receiving: the node's register policy decides what is written, on
        which rail, and the answer carries the token alone
        (`register.go:28-32`). Grants add up. All three are keyword-only, and
        the request travels as one object even when every field is empty
        (`register.go:49-50`). An action name that is empty or over 255 UTF-8
        bytes, or a `name` over 255 bytes, raises `BadArgument` before a query
        leaves.

        The node accepts the query before its register policy decides, so a
        refusal is an `error_message` reading `ERR_REGISTRATION_DECLINED` and
        arrives as `RemoteError` (`register.go:37-39`).
        """
        req = RegisterRequest(
            name=_app_name(name) or "",
            grant_permits=_permit_list(grant_permits, "grant_permits", OP_REGISTER),
            contract_permits=_permit_list(
                contract_permits, "contract_permits", OP_REGISTER
            ),
        )
        answers = await self._c.call_with(OP_REGISTER, req, expect=1, **kw)
        if not answers:
            raise ProtocolError(
                f"{OP_REGISTER}: the stream ended without answering the request"
            )
        return self._expect(answers[0], AccessToken, OP_REGISTER)

    async def set_app_register_policy(
        self,
        identity: Identity | str | None = None,
        operation: str | None = None,
        *,
        timeout: Duration | str | None = None,
        **kw: Any,
    ) -> None:
        """Delegate the app register policy, or restore the bundled one. RR, one
        `ack`. **Mutates.**

        `identity` and `operation` name the delegate's op; the node resolves
        `identity` through its directory. Both omitted restore the bundled
        accept-all policy, and one without the other is refused here, as the
        node refuses it. `timeout` bounds one question in Go's duration syntax;
        omitted, the node waits ten minutes (`op_set_app_register_policy.go:14-24`).

        Accepts, then answers `not permitted` when the caller lacks
        `mod.auth.admin_manage_apps_action`, and refuses no origin
        (`op_set_app_register_policy.go:53-58`). A delegate the node cannot
        resolve, the node itself, or a `timeout` above ten minutes is an
        `error_message` too; every one arrives as `RemoteError`
        (`op_set_app_register_policy.go:68-71,83-93`).

        astral-go `dbc27574` has no client for this op.
        """
        qs = setter_query(OP_SET_APP_REGISTER_POLICY, identity, operation, timeout)
        self._expect(
            await self._c.call_one(qs, **kw), Ack, OP_SET_APP_REGISTER_POLICY
        )

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
        stores a null expiry for it. The node accepts, then asks
        `mod.auth.store_objects_action` for `q.Caller()` and answers
        `not permitted` when it is refused (`op_hold_object.go:36-38`). The hold
        is recorded against `q.Caller()`, so a session holding the node's token
        holds objects as the node, and an object may be held before this node
        has ever fetched it.

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
        handler answers for (`op_register_handler.go:33`); the node accepts
        first and answers either refusal with an `error_message`, which arrives
        as `RemoteError`. It registers under `q.Caller()`, and
        `mod/user/src/authorize_serve_apps.go:8,15` allows the node's identity,
        so a session holding the node's token registers as the node. A session
        without a token never reaches the op: it is not on astrald's
        `anonymous_allowlist`. `register_service_msg` is the message-level
        counterpart, and astrald refuses it outright from a token-less guest
        (`mod/apphost/src/guest.go:271-273`).
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
        outcome for a query that has already been answered, and for a local
        caller it is the only `error_message` this op sends, so the message is
        not inspected. It is
        also what a caller that may not cancel the query is told, deliberately:
        a session cancels what it launched, `mod.auth.admin_manage_apps_action`
        is the way past that, and a refusal reads as "not found" so a caller
        learns nothing about the nonces other apps hold (`op_cancel.go:36-40`).

        Local-only. A query off a link is answered `origin not allowed: network`
        before any of that (`op_cancel.go:30-32`).

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
    AppRegisterDecision,
    AppRegisterRequest,
    AttachQueryMsg,
    AuthSuccessMsg,
    AuthTokenMsg,
    BindMsg,
    ErrorMsg,
    Grant,
    GrantRequest,
    HandleQueryMsg,
    HostInfoMsg,
    IncomingQueryMsg,
    PingMsg,
    QueryAcceptedMsg,
    QueryRejectedMsg,
    RegisterRequest,
    RegisterServiceMsg,
    RejectIncomingMsg,
    RequestGrantRequest,
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
