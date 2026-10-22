"""`policy.delegate` -- the op a node asks instead of deciding an admission itself.

astral-go's `api/policy` package holds what a node and the app it delegates an
admission decision to share (`api/policy/delegate.go` at astral-go `8972f283`,
the revision astrald `48ae88b2` requires). Two node modules store a delegate:
`apphost` for `apphost.register` and `user` for `user.request_membership` and
`user.accept_membership`, each persisted as a `policy.delegate` in the node's
tree under `/mod/apphost/policy` and `/mod/user/policy`
(`mod/apphost/src/register_policy.go:12,21` and
`mod/user/src/swarm_policy.go:12,17-18` at astrald `48ae88b2`). The question and
the answer are the owning module's types -- `mod.apphost.app_register_request`
and `mod.apphost.app_register_decision` in `astral.api.apphost`, the four
`mod.user.swarm_*` types in `astral.api.user`.

**The node puts the request to the delegate as itself and reads one object
back** (`api/policy/ask.go`). An app serving as a delegate therefore answers
one query carrying one request object, from the node's identity, with one
decision object. An answer of another type, or no answer, declines
(`mod/apphost/src/register_policy.go:45-53`).

The type name has **no `mod.` prefix**: `Delegate.ObjectType()` returns
`policy.delegate` (`api/policy/delegate.go:27`), and design section 5.1 rule 6
spells it literally.

**No op ships here.** No astrald module is named `policy`; the setters that
store a delegate are `apphost.set_app_register_policy`,
`user.set_swarm_join_policy` and `user.set_swarm_invite_policy`, each in its own
module. There is no `client.policy` property and no `ModuleClient` subclass, for
that reason: a module client is a bound set of ops and this module has none.

**The three setters take one argument set, and `setter_query` builds it.** Each
op declares `Identity string`, `Operation string` and `Timeout
astral.Duration`, and reads both names empty as a restore of the bundled
accept-all policy (`mod/apphost/src/op_set_app_register_policy.go:13-23` and
`mod/user/src/op_set_swarm_policy.go:14-24` at astrald `48ae88b2`).
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
    astral-go's `Delegate.Validate`; an absent or zero `identity` selects the
    module's bundled policy (`api/policy/delegate.go:14-25`). Field order is the
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
            "both, or neither to restore the bundled policy"
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
