"""`policy.delegate` -- the op a node asks instead of deciding an admission itself.

astral-go's `api/policy` package holds what a node and the app it delegates an
admission decision to share (`api/policy/delegate.go` at astral-go
`1ec701ca`). Two node modules store a delegate:
`apphost` for `apphost.register` and `apphost.request_grant`, and `user` for
`user.request_membership`, `user.accept_membership` and `user.accept_contract`,
each persisted as a `policy.delegate` in the node's tree under
`/mod/apphost/policy` and `/mod/user/policy`
(`mod/apphost/src/register_policy.go:12,23-26` and
`mod/user/src/swarm_policy.go:15,19-23` at astrald `6974d9e7`). The question and
the answer are the owning module's types -- `mod.apphost.app_register_request`
and `mod.apphost.app_register_decision` in `astral.api.apphost`, the four
`mod.user.swarm_*` types and the two `mod.user.contract_accept_*` types in
`astral.api.user`. The grant request policy's
`mod.apphost.grant_policy_request` and `mod.apphost.grant_decision` are
astral-go's (`api/apphost/grant_request_policy.go`) and are not declared in
this SDK.

**The node puts the request to the delegate as itself and reads one object
back** (`api/policy/ask.go`). An app serving as a delegate therefore answers
one query carrying one request object, from the node's identity, with one
decision object. An answer of another type, or no answer, declines
(`mod/apphost/src/register_policy.go:65-73`).

The type name has **no `mod.` prefix**: `Delegate.ObjectType()` returns
`policy.delegate` (`api/policy/delegate.go:27`), and design section 5.1 rule 6
spells it literally.

**No op ships here.** No astrald module is named `policy`; the setters that
store a delegate are `apphost.set_app_register_policy`,
`apphost.set_grant_request_policy`, `user.set_swarm_join_policy`,
`user.set_swarm_invite_policy` and `user.set_contract_accept_policy`, each in
its own module. There is no `client.policy` property and no `ModuleClient` subclass, for
that reason: a module client is a bound set of ops and this module has none.

**The five setters take one argument set, and `setter_query` builds it.** Each
op declares `Identity string`, `Operation string` and `Timeout
astral.Duration`, and reads both names empty as a clear of the stored delegate
(`mod/apphost/src/op_set_app_register_policy.go:14-24` and
`mod/user/src/op_set_swarm_policy.go:14-25` at astrald `6974d9e7`). The two
apphost setters share `opSetPolicyArgs` and one write path, which answers a
query naming `mode` with `unknown argument: mode` before it writes anything
(`mod/apphost/src/op_set_app_register_policy.go:30,45,61-64`,
`mod/apphost/src/validate_permits.go:31-35`; astral-go
`lib/query/editor.go:26`). Every setter admits
a caller holding `mod.auth.configure_node_state_action` and answers any other
caller `not permitted` (`maySetPolicies`,
`mod/apphost/src/op_set_app_register_policy.go:112-114` and
`mod/user/src/op_set_swarm_policy.go:106-108`). The manager
`sys.register_manager` appointed holds that action in every node state
(`mod/sys/src/authorizers.go:16-18,39-42`), and `sys.register_manager` itself
stores a delegate for each policy its request binds (`bindManagerPolicies`,
`mod/sys/src/op_register_manager.go:123-136`; `astral.api.sys`).

**Each of the five policies decides in one order: a stored delegate, then its
config value, then the code default `reject_all`.** The app register and grant
request policies read `policies.app_register` and `policies.grant_request` of
`apphost.yaml`; the swarm join, swarm invite and contract accept policies read
`policies.swarm_join`, `policies.swarm_invite` and `policies.contract_accept` of
`user.yaml` (`mod/apphost/src/config.go:43-48`, `mod/user/src/config.go:25-31`).
A stored delegate outranks the value, and an unset one selects it
(`mod/apphost/src/register_policy.go:14-15`, `mod/user/src/swarm_policy.go:17-18`).
Each value is `accept_all`, `reject_all` or a delegate mapping, and the zero
value selects `reject_all` (`lib/policyconf/setting.go:20-25`); each defaults to
`reject_all` (`mod/apphost/src/config.go:113-116`,
`mod/user/src/config.go:33-39`). The five getters apply that order alike: a
configured delegate whose identity does not resolve declines, `accept_all`
accepts, and anything else refuses (`GetRegisterAppPolicy`,
`mod/apphost/src/register_policy.go:36-55`; `GetGrantRequestPolicy`,
`mod/apphost/src/register_policy.go:86-105`; `GetSwarmJoinPolicy`,
`GetSwarmInvitePolicy` and `GetContractAcceptPolicy`,
`mod/user/src/swarm_policy.go:33-49,55-71,97-115`).
"""

from __future__ import annotations

from typing import Any, Final, Sequence

from .. import querystring
from ..errors import BadArgument
from ..record import record, wire
from ..spec import Primitive, Ptr, Spec
from ..types import Duration, Identity

__all__ = [
    "Delegate",
    "POLICY_TYPES",
]


@record("policy.delegate")
class Delegate:
    """The op that answers an admission question instead of the node.

    `identity` and `operation` name the op; `timeout` bounds one question. A
    zero `timeout` waits ten minutes, the bound, and a `timeout` above it fails
    astral-go's `Delegate.Validate` (`api/policy/delegate.go:14-25`). An
    absent or zero `identity` is no delegate (`api/policy/delegate.go:37-40`),
    and the module then applies its config value, as the module docstring
    states. Field order is the
    node's `objects.get_blueprint` answer on astrald `1286a469`.
    """

    identity: Identity | None = wire("Identity", Ptr("identity"))
    operation: str = wire("Operation", Primitive("string8"))
    timeout: Duration = wire("Timeout", Primitive("duration"))


POLICY_TYPES: Final[Sequence[type]] = (Delegate,)
"""Every wire type this module declares, for a private-registry sweep."""


_SETTER: Final[dict[str, Spec]] = {
    "identity": Primitive("string8"),
    "operation": Primitive("string8"),
    "timeout": Primitive("duration"),
}


def setter_query(
    op: str,
    identity: Identity | str | None,
    operation: str | None,
    timeout: Duration | str | None,
) -> str:
    """The query string a delegate setter sends: `op` and its three arguments.

    Both names or neither: the node answers an `error_message` for one alone,
    so that is refused before a query leaves. An empty `identity` is refused
    too: beside an operation the node resolves it to the zero identity, which
    fails `Delegate.Validate`, and the restore is both names omitted. A string
    `timeout` is parsed here, so a unit Go's `time.ParseDuration` lacks is
    refused before the node sees it.
    """
    if (identity is None) != (operation is None):
        raise BadArgument(
            f"{op}: identity and operation name one delegate together; pass "
            "both, or neither to clear the stored delegate"
        )
    params: dict[str, Any] = {}
    if identity is not None:
        if isinstance(identity, Identity):
            identity = identity.text()
        elif not identity:
            raise BadArgument(
                f"{op}: the empty name resolves to the zero identity on the "
                "node, so identity= would name `anyone`; pass Identity.ANYONE "
                "to mean that identity"
            )
        params["identity"] = identity
        params["operation"] = operation
    if timeout is not None:
        params["timeout"] = Duration.parse(timeout) if isinstance(timeout, str) else timeout
    return querystring.build(op, querystring.encode_params(_SETTER, params))
