"""`sys.*` -- the node's lifecycle: its manager and the manager's appointment.

sys is the node module that holds the node state and the manager. One op has a
client below.

| Op | Mode | Answer | Notes |
|---|---|---|---|
| `sys.register_manager` | WA | `apphost.access_token` \\| `error_message` | local-only, fresh node only, no token needed, **mutates** |

## Where the citations point

**Every `path:line` in this module is read at the revisions `tests/reference.py`
pins, astrald `a7c773d6` and astral-go `4a3e111c`**, the merges that brought
`mod/sys` and `api/sys` (`tests/test_api_sys.py`, `CitationTest`). The protocol
text is astral-docs `protocols/sys/`.

## The appointment

**`sys.register_manager` appoints the node's manager, once.** The op replaces
`apphost.register_manager` with the same arguments, input, answer and errors;
its types replace `mod.apphost.register_manager_request` and
`mod.apphost.policy_binding` with the same fields
(`api/sys/register_manager_request.go:36-41,64-68`, `api/sys/module.go:10`).
It provisions a new App identity as `apphost.register` does, holding the
permits the request asks for, without asking the app register policy; it
stores a delegate whose identity is the new manager for each policy the
request binds, clears the stored delegate of every policy the request does not
bind, writes the manager record last and answers the access token
(`mod/sys/src/op_register_manager.go:38-63`, `OpRegisterManager`;
`appointManager`, `:67-88`; `bindManagerPolicies`, `:123-136`). The policies a
binding names are `app_register`, `grant_request`, `swarm_join`,
`swarm_invite` and `contract_accept`
(`api/sys/register_manager_request.go:23-29`, `PolicyNames`). The op refuses a
network origin (`mod/sys/src/op_register_manager.go:43-45`), then answers an
invalid permit, an unknown or repeated policy name, a binding with no
operation, a timeout outside zero to ten minutes and a `user` policy on a node
without the `user` module with an `error_message` (`validateManagerRequest`,
`mod/sys/src/op_register_manager.go:93-118`), and a node that is not fresh
with `node is not fresh` (`api/sys/errors.go:7`, `ErrNotFresh`).

The node stores the manager at `/mod/sys/manager`, and a node with no record
there reads the one at `/mod/apphost/manager`, where an apphost-appointed
manager was stored (`mod/sys/src/state.go:27-32`, `Manager`). The node state
moved with it: claimed while a user contract is active; else unclaimed when a
manager is appointed or a user owned the node before; else fresh
(`mod/sys/src/state.go:42-60`, `NodeState`).

**The gate.** The default gate lists `sys.register_manager` on
`gate.tokenless` and on `gate.states.fresh`
(`mod/apphost/src/config.go:77,83`). So a fresh node admits the op to a
session with a token or without, an unclaimed node's list does not name it and
denies it, and a claimed node's `*` admits it and the op answers
`node is not fresh`.

**The manager holds `mod.auth.configure_node_state_action` in every node state,
claimed included** (`mod/sys/src/authorizers.go:15-18`,
`AuthorizeConfigureNodeState`). That action is what every policy setter
requires -- `apphost.set_app_register_policy`,
`apphost.set_grant_request_policy`, `user.set_swarm_join_policy`,
`user.set_swarm_invite_policy` and `user.set_contract_accept_policy`
(`maySetPolicies`, `mod/apphost/src/op_set_app_register_policy.go:153-155`
and `mod/user/src/op_set_swarm_policy.go:106-108`) -- so the manager sets
every policy's delegate through it. The manager may claim the node with
`user.bootstrap` or `user.join` (`mayClaim`,
`mod/user/src/op_bootstrap.go:198-204`).

**What was verified, and against which node.** The answers
`tests/test_api_sys.py` pins were captured from `apphost.register_manager` on
an isolated astrald built from `5b4dde12`, before the rename: a token-less
session on the fresh node received the manager's token, and the claimed node
answered `node is not fresh`. Neither frame names the op, and the handler
moved to `mod/sys` with its answers unchanged, so the captures stand for
`sys.register_manager` by inference from the astrald diff; no node running the
sys module was queried. The `mod.sys.*` vectors were produced by a Go program
linked against astral-go branch `intern0/dev/sys-api`, which merged as
`4a3e111c`; the test reads the two types' names and fields at that pin.
"""

from __future__ import annotations

from typing import Any, Final, Iterable, Sequence

from ..errors import BadArgument, BadArgumentType, ProtocolError
from ..record import record, wire
from ..spec import Primitive, Slice
from ..types import Duration
from .apphost import _STRING8_MAX, AccessToken, _app_name, _permit_list
from .auth import Permit
from .base import ModuleClient

__all__ = [
    "ERR_NOT_FRESH",
    "OP_REGISTER_MANAGER",
    "POLICY_APP_REGISTER",
    "POLICY_CONTRACT_ACCEPT",
    "POLICY_GRANT_REQUEST",
    "POLICY_NAMES",
    "POLICY_SWARM_INVITE",
    "POLICY_SWARM_JOIN",
    "PolicyBinding",
    "RegisterManagerRequest",
    "SYS_TYPES",
    "Sys",
]

OP_REGISTER_MANAGER: Final = "sys.register_manager"
"""astral-go's `MethodRegisterManager` (`api/sys/module.go:10`)."""

ERR_NOT_FRESH: Final = "node is not fresh"
"""`register_manager`: a manager is appointed, or a user owns or owned the node.

Sent as an `error_message` after the op accepts, which surfaces as
`RemoteError` with this `message` (`api/sys/errors.go:7`, `ErrNotFresh`, sent by
`appointManager`, `mod/sys/src/op_register_manager.go:72`). An unclaimed node
under the default gate denies the query instead, which surfaces as `Denied`.
"""

# --- the policy names a binding takes --------------------------------------
#
# `api/sys/register_manager_request.go:14-29`, the constants and `PolicyNames`.
# Each names the admission policy of one op; the node refuses any other name
# (`validateManagerRequest`, `mod/sys/src/op_register_manager.go:93-118`).

POLICY_APP_REGISTER: Final = "app_register"
"""Decides `apphost.register`."""

POLICY_GRANT_REQUEST: Final = "grant_request"
"""Decides `apphost.request_grant`."""

POLICY_SWARM_JOIN: Final = "swarm_join"
"""Decides `user.request_membership`."""

POLICY_SWARM_INVITE: Final = "swarm_invite"
"""Decides `user.accept_membership`."""

POLICY_CONTRACT_ACCEPT: Final = "contract_accept"
"""Decides `user.accept_contract`."""

POLICY_NAMES: Final = (
    POLICY_APP_REGISTER,
    POLICY_GRANT_REQUEST,
    POLICY_SWARM_JOIN,
    POLICY_SWARM_INVITE,
    POLICY_CONTRACT_ACCEPT,
)
"""Every policy name a `PolicyBinding` takes, in astral-go's `PolicyNames` order."""


@record("mod.sys.policy_binding")
class PolicyBinding:
    """The manager's op that answers one policy
    (`api/sys/register_manager_request.go:64-68`, `PolicyBinding`).

    `policy` is one of `POLICY_NAMES`. `operation` is the op of the manager the
    node asks. `timeout` bounds one question as `policy.delegate`'s does: zero
    waits ten minutes (`api/policy/delegate.go:18-20` at astral-go
    `4a3e111c`), and the node refuses a negative one or one above ten minutes
    (`validateManagerRequest`). The node stores the binding as a
    `policy.delegate` whose identity is the new manager
    (`bindManagerPolicies`, `mod/sys/src/op_register_manager.go:123-136`).
    """

    policy: str = wire("Policy", Primitive("string8"))
    operation: str = wire("Operation", Primitive("string8"))
    timeout: Duration = wire("Timeout", Primitive("duration"))


@record("mod.sys.register_manager_request")
class RegisterManagerRequest:
    """What an app sends `sys.register_manager` to become the node's manager
    (`api/sys/register_manager_request.go:36-41`, `RegisterManagerRequest`).

    `name`, `grant_permits` and `contract_permits` mean what they mean in
    `astral.api.apphost.RegisterRequest`. `policies` names the policies the
    manager answers, at most one binding per policy name; a policy the request
    does not bind loses its stored delegate (`bindManagerPolicies`).
    """

    name: str = wire("Name", Primitive("string8"))
    grant_permits: list[Permit | None] = wire("GrantPermits", Slice("mod.auth.permit"))
    contract_permits: list[Permit | None] = wire("ContractPermits", Slice("mod.auth.permit"))
    policies: list[PolicyBinding | None] = wire(
        "Policies", Slice("mod.sys.policy_binding")
    )


def _policy_bindings(values: Iterable[PolicyBinding] | None) -> list[PolicyBinding | None]:
    """`RegisterManagerRequest.policies`: whole `PolicyBinding`s.

    `None` is the empty list. A bare `PolicyBinding`, `str` or `bytes` is
    refused rather than read as a list, and so is an entry of any other type.
    `policy` and `operation` are `string8`, so one over 255 UTF-8 bytes raises
    `BadArgument` before a query leaves. Which names and timeouts the node
    accepts is the node's to answer.
    """
    if values is None:
        return []
    if isinstance(values, (str, bytes, PolicyBinding)):
        raise BadArgumentType(
            f"{OP_REGISTER_MANAGER}: policies expects a list of PolicyBinding, got "
            f"{type(values).__name__}"
        )
    bindings: list[PolicyBinding | None] = []
    for value in values:
        if not isinstance(value, PolicyBinding):
            raise BadArgumentType(
                f"{OP_REGISTER_MANAGER}: policies expects PolicyBinding entries, got "
                f"{type(value).__name__}"
            )
        for key in ("policy", "operation"):
            text = getattr(value, key)
            if not isinstance(text, str):
                raise BadArgumentType(
                    f"{OP_REGISTER_MANAGER}: a binding's {key} expects a str, got "
                    f"{type(text).__name__}"
                )
            if len(text.encode("utf-8")) > _STRING8_MAX:
                raise BadArgument(
                    f"{OP_REGISTER_MANAGER}: a binding's {key} is "
                    f"{len(text.encode('utf-8'))} bytes; it is a string8 of at most "
                    f"{_STRING8_MAX}"
                )
        bindings.append(value)
    return bindings


class Sys(ModuleClient):
    """The `sys.*` ops, bound to one client.

    Reached as `client.sys`, a cached property built on first use; `Sys(client)`
    constructs the same object directly. The scaffolding and the `**kw`
    contract are `ModuleClient`'s.
    """

    __slots__ = ()

    async def register_manager(
        self,
        *,
        name: str | None = None,
        grant_permits: Iterable[Permit | str] | None = None,
        contract_permits: Iterable[Permit | str] | None = None,
        policies: Iterable[PolicyBinding] | None = None,
        **kw: Any,
    ) -> AccessToken:
        """Provision a fresh App identity and appoint it the node's manager. WA:
        one `mod.sys.register_manager_request` in, one `apphost.access_token`
        out, then EOF. **Mutates**, once per node.

        The node provisions the identity as `apphost.register` does, without
        asking the app register policy, and for each binding in `policies`
        stores a delegate whose identity is the new manager; every policy the
        request does not bind loses its stored delegate. It records the
        appointment last and answers the manager's token
        (`api/sys/client/register_manager.go:26-42`,
        `mod/sys/src/op_register_manager.go:67-88`). The node is then unclaimed,
        `user.info` names the manager, and the manager may claim the node with
        `user.bootstrap` or `user.join` and, holding
        `mod.auth.configure_node_state_action`, set every policy setter's
        delegate.

        `name`, `grant_permits` and `contract_permits` are
        `Apphost.register`'s, with its coercions and refusals. Each entry of
        `policies` is a `PolicyBinding`; a bare binding, a `str`, or an entry of
        another type raises `BadArgumentType`, and a `policy` or `operation`
        over 255 UTF-8 bytes raises `BadArgument`, before a query leaves. All
        four are keyword-only. The query carries no argument and the request
        travels on the channel as one object, as astral-go's client sends it,
        here even when every field is empty.

        The default gate admits the op on a fresh node, to a session with a
        token or without, and denies it on an unclaimed node, which surfaces
        as `Denied` (`mod/apphost/src/config.go:81-96`). Past
        the gate the node accepts, then answers a network origin, an invalid
        permit, an unknown or repeated policy name, a binding with no
        operation, a timeout outside zero to ten minutes, a `user` policy on a
        node without the `user` module, and a node that is not fresh
        (`ERR_NOT_FRESH`) with an `error_message`, each a `RemoteError`
        (`mod/sys/src/op_register_manager.go:43-58`).
        """
        req = RegisterManagerRequest(
            name=_app_name(name, OP_REGISTER_MANAGER) or "",
            grant_permits=_permit_list(
                grant_permits, "grant_permits", OP_REGISTER_MANAGER
            ),
            contract_permits=_permit_list(
                contract_permits, "contract_permits", OP_REGISTER_MANAGER
            ),
            policies=_policy_bindings(policies),
        )
        answers = await self._c.call_with(OP_REGISTER_MANAGER, req, expect=1, **kw)
        if not answers:
            raise ProtocolError(
                f"{OP_REGISTER_MANAGER}: the stream ended without answering the request"
            )
        return self._expect(answers[0], AccessToken, OP_REGISTER_MANAGER)


SYS_TYPES: Final[Sequence[type]] = (
    PolicyBinding,
    RegisterManagerRequest,
)
"""Every wire type this module declares, for a registry sweep.

`apphost.access_token`, the op's answer, is `astral.api.apphost`'s.
"""

Sys.TYPES = SYS_TYPES
