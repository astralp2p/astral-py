"""`user.*` -- the swarm a node belongs to: membership, siblings, assets, bans.

Tier 2 and the largest module of it: fifteen ops, eleven wire types, and the one
op in the SDK whose stream ends with a **value** instead of a terminator. Every
op below is on the live node's `shell.spec` registry, verified this session
against `furry-bolt` -- fifteen entries, the argument names and types read out of
`routing.op_spec`.

A node belongs to at most one user. The membership is a `mod.auth.contract`
signed by the user as issuer and by the node as subject; the node's copy of it is
the **active contract**, and six ops here reject with code 2 when there is
none. The user's other nodes are **siblings**; the set of them is the **swarm**.
An **asset** is an object ID the user's swarm keeps; an **expulsion** is an
identity-level, irreversible ban.

**Op surface, and the shape each one declares** (design section 4.7; a shape is a
per-op contract and is **not** discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `user.accept_contract` | WA | `ack` \\| `error_message` | **mutates** |
| `user.accept_membership` | WA | `mod.crypto.signature` \\| `error_message` | **mutates** |
| `user.add_asset` | RR | `ack` | **mutates** |
| `user.adopt` | RR | `mod.auth.signed_contract` \\| `error_message` | **mutates** |
| `user.assets` | ST | `object_id.sha256` x n ++ `eos` | read-only |
| `user.expel` | RR | `mod.user.signed_expulsion` \\| `error_message` | **irreversible** |
| `user.info` | RR | `mod.user.info` | read-only |
| `user.list_expelled` | ST | `mod.user.signed_expulsion` x n ++ `eos` | read-only |
| `user.list_siblings` | ST | `identity` x n ++ `eos` | read-only |
| `user.new_node_contract` | RR | `mod.auth.contract` \\| `error_message` | read-only |
| `user.remove_asset` | RR | `ack` | **mutates** |
| `user.request_membership` | RR | `mod.auth.signed_contract` \\| `error_message` | **mutates** |
| `user.swarm_status` | ST | `mod.users.swarm_member` x n ++ `eos` | read-only |
| `user.sync_assets` | ST+value | `mod.user.op_update` x n ++ `uint64`, **no `eos`** | read-only |
| `user.sync_with` | RR | `ack` \\| `error_message` | **mutates** |

**`user.sync_assets` is the third streaming shape and the reason design section
3.10 has one.** Zero or more `mod.user.op_update` objects, then a bare `uint64`
that is the next unread height, then the close -- and **no `eos` at any point**
(`astrald/mod/user/src/op_sync_assets.go:47`, the op's last statement). Every
generic reader in this SDK terminates on `eos` or EOF, so `call()`, `collect()`
and `async for` all block on this op until the responder closes. `sync_assets()`
below is hand-written for it and returns an `AssetSync`, which is
`(updates, next_height)`. Verified live twice: `user.sync_assets` answered
`uint64(0)` and `user.sync_assets?start=7` answered `uint64(7)`, both terminated
by EOF with `Stream.terminated_by == "eof"`.

The height is the poll cursor. An empty answer echoes `start` back, so the same
value re-polls safely (`op_sync_assets.go:33`); a non-empty answer is the highest
row's height plus one (`op_sync_assets.go:44`).

**Four ops end at `eos`, ten end at a bare EOF, and one ends at a value.**
`assets`, `list_expelled`, `list_siblings` and `swarm_status` each close with
`ch.Send(&astral.EOS{})`; the eight RR ops and the two write-and-answer ops each
send their objects and return; `sync_assets` is the value. Confirmed live for
`assets`, `list_siblings` and `list_expelled` (`terminated_by == "eos"`, all
three empty on this node) and for `new_node_contract` and `sync_assets`
(`"eof"`). Nothing here waits for `eos` unconditionally.

**Type names are singular for `mod.user.*` and plural for two of them.**
`mod.users.swarm_member` and `mod.users.created_user_info` carry the plural
segment and `mod.user.info`, `mod.user.op_update`, `mod.user.expulsion`,
`mod.user.signed_expulsion`, `mod.user.notification` and the four action types do
not. The names are spelled literally, as design section 5.1 rule 6 requires; both
spellings are on the live registry, verified this session through
`objects.blueprints`.

**`mod.user.op_update` is declared here.** astral-go's `api/user` does not carry
it -- astrald defines it beside the op that sends it
(`astrald/mod/user/src/op_sync_assets.go`, `type OpUpdate`) and registers it from
that package's `init`. The field order below is the node's own, read from
`objects.get_blueprint?type=mod.user.op_update` on `furry-bolt`: `Nonce nonce64`,
`ObjectID *object_id.sha256`, `Removed bool`. The same query answered for
`mod.user.info`, `mod.user.expulsion`, `mod.user.signed_expulsion`,
`mod.user.notification`, `mod.users.swarm_member` and
`mod.users.created_user_info`, and every field order below is that answer. The
four action types are **refused** by that op -- `BlueprintFromType …Action: type
auth.Action does not implement Object and is not a supported container` -- which
is the same refusal `mod.objects.*_action` gets and says nothing about their wire
form.

**The op's own target argument is `node`, never `target`.** `user.adopt` and
`user.expel` declare `Target string`, resolved by the node's directory; `target`
is also the routing keyword every module-client method forwards to
`Client.query`, and on these two ops the routing target (the node running the op)
and the op's target (the node being adopted or expelled) are different nodes.
`Tree.mount_remote` met this collision first and renamed for it.

**An empty target adopts or expels `anyone`.** astrald declares `Target string`
with no `query:"required"` tag, so an absent argument reaches
`Dir.ResolveIdentity("")`, which maps the empty string to the zero identity
(`astrald/mod/dir/src/module.go:56`) rather than failing. The op then signs a
membership contract, or an irreversible ban, for `anyone`. The same hole is on
`user.add_asset` and `user.remove_asset` -- `ID *astral.ObjectID`, untagged, and
no nil guard between the op and the row it writes
(`astrald/mod/user/src/db.go:60`) -- and on `user.sync_with`, whose `Node` is an
identity the op never checks. Every one of those arguments is mandatory here and
an empty name is refused client-side. Defect filed against astrald.

**Two declared arguments are inert on astrald `074a852b`.**
`user.list_siblings`'s `zone` builds a context the op then never uses --
`mod.getSiblings()` takes none (`astrald/mod/user/src/op_list_siblings.go:17`) --
and `user.sync_with`'s `start` is never read at all
(`astrald/mod/user/src/op_sync_with.go:20`). Both are still sent, because a
declared argument is the op's own statement of its interface, but they are sent
differently: `zone` always, because the value is forwarded to the routing zone
too and that lever is not inert; `start` only when the caller names one, because
the node has its own default for it and an implicit zero would mean "re-read the
whole log" the moment the argument is wired up. Defect filed against astrald.

**Reject codes are numeric and carry no message.** Code 2 is "no active
contract" on `adopt`, `expel`, `info`, `list_expelled`, `request_membership` and
`swarm_status`, and "an active contract already exists" on `accept_contract` and
`accept_membership` -- the same number for opposite states, because the state a
node has is not the state either op wants. On `adopt` and `expel` code 3 is an
unresolvable target and code 4 is an unauthorized caller
(`astrald/mod/user/src/op_adopt.go:34`). `sync_assets` rejects with 2 on a
database fault. `add_asset` and `remove_asset` reject with
`astral.CodeInternalError`, which is 4 (`astral-go/astral/codes.go`).
No code is mapped to a semantic exception here: `QueryRejected.code` carries the
number, and design risk R-17 declines to claim more.

**Two ops read their input off the channel body and neither takes an `eos`.**
`accept_contract` reads one `mod.auth.signed_contract`; `accept_membership` reads
a `mod.auth.contract` and then the issuer's `mod.crypto.signature`. Both use
`ch.Switch(channel.Expect(&x))` with no `channel.BreakOnEOS`
(`astral-go/astral/channel/switch.go`, `Switch` returns
`ErrUnexpectedObject` for an object no handler takes), so a terminator sent after
the last input is answered with an `error_message` rather than ignored. Passing
that input as a query argument instead is the single most common way to get an op
wrong (design section 4.7), and neither op declares a parameter to put it in.

**`accept_membership` cannot interleave.** The node answers once, after both
inputs, so a send-one-read-one exchange deadlocks on the first read. Both objects
go out before the first answer is read, which is safe for two frames of this size
and is what astral-go's client does (`api/user/client/accept_membership.go`).

**`user.new_node_contract` builds and returns; it signs nothing and stores
nothing.** Its `duration` is Go's duration syntax and the node parses it with
`time.ParseDuration`, which has no year unit: `duration=1y` answers
`time: unknown unit "y" in duration "1y"`, verified live. The default is one
year expressed as 365 x 24h (`astrald/mod/user/src/config.go:12`), applied
server-side when the argument is absent. `Duration.parse` accepts exactly Go's
unit table, so a bad spelling is refused here rather than travelling. Verified
live: no argument expires 365 days out, `duration=48h` two days out, and both
carry the four permits of a management node.

**A contract shorter than one hour is refused by `accept_membership`**
(`astrald/mod/user/src/config.go:11`, `minimalContractLength`). The check is the
node's; nothing here pre-empts it, because the contract is signed elsewhere and
its expiry is not this module's to choose.

**`mod.user.notification` is sent and nothing receives it.** `AddAsset` and
`RemoveAsset` push `Notification{Event: "assets"}` to every linked sibling
(`astrald/mod/user/src/siblings.go:25`), and astrald's own object receiver has no
case for the type (`mod/user/src/object_receiver.go` switches on
`*auth.SignedContract`, `*user.SignedExpulsion` and `*events.Event` only), so the
push is neither accepted nor rejected and the event triggers nothing. The type is
declared here for decode completeness: an app that receives pushed objects meets
it. Defect filed against astrald.

**`mod.users.created_user_info` is answered by no op on this node.** The live
registry has no `users.*` module at all, verified this session -- 118 ops, none of
them `users.`-prefixed. astral-go declares the type in `api/user`
(`created_user_info.go`) and astrald never constructs it. It is declared here so
the type is decodable when a peer sends one, and for nothing else.

Reached as `client.user`, a `functools.cached_property` on `Client` built on
first use (design section 5.1). Source citations are pinned to astrald
`074a852b` and astral-go `5c18d9c`, the revisions `tests/reference.py` names;
`tests/test_api_user.py` reads every one of them back and fails when it stops
landing.
"""

from __future__ import annotations

from typing import Any, Final, NamedTuple, Sequence

from .. import querystring
from ..errors import BadArgument, BadArgumentType, ParseError, ProtocolError
from ..object import Ack
from ..objectid import object_id
from ..primitives import Uint64
from ..record import record, wire
from ..spec import Primitive, Ptr, Spec
from ..types import Duration, Identity, Nonce, ObjectID, Time, Zone
from .auth import Action, Contract, Permit, SignedContract
from .base import ModuleClient
from .crypto import Signature

__all__ = [
    "AdoptAction",
    "AssetSync",
    "CreatedUserInfo",
    "DEFAULT_CONTRACT_VALIDITY",
    "ERR_EXPELLED",
    "ERR_INVITATION_DECLINED",
    "ERR_NO_ACTIVE_CONTRACT",
    "ERR_REQUEST_DECLINED",
    "EVENT_ASSETS",
    "ExpelAction",
    "Expulsion",
    "Info",
    "InfoAction",
    "MINIMAL_CONTRACT_LENGTH",
    "Notification",
    "OP_ACCEPT_CONTRACT",
    "OP_ACCEPT_MEMBERSHIP",
    "OP_ADD_ASSET",
    "OP_ADOPT",
    "OP_ASSETS",
    "OP_EXPEL",
    "OP_INFO",
    "OP_LIST_EXPELLED",
    "OP_LIST_SIBLINGS",
    "OP_NEW_NODE_CONTRACT",
    "OP_REMOVE_ASSET",
    "OP_REQUEST_MEMBERSHIP",
    "OP_SWARM_STATUS",
    "OP_SYNC_ASSETS",
    "OP_SYNC_WITH",
    "OpUpdate",
    "SignedExpulsion",
    "SwarmMember",
    "SwarmMembershipAction",
    "USER_TYPES",
    "User",
    "is_node_contract",
    "new_node_contract_local",
]

# --- op names ------------------------------------------------------------

OP_ACCEPT_CONTRACT: Final = "user.accept_contract"
OP_ACCEPT_MEMBERSHIP: Final = "user.accept_membership"
OP_ADD_ASSET: Final = "user.add_asset"
OP_ADOPT: Final = "user.adopt"
OP_ASSETS: Final = "user.assets"
OP_EXPEL: Final = "user.expel"
OP_INFO: Final = "user.info"
OP_LIST_EXPELLED: Final = "user.list_expelled"
OP_LIST_SIBLINGS: Final = "user.list_siblings"
OP_NEW_NODE_CONTRACT: Final = "user.new_node_contract"
OP_REMOVE_ASSET: Final = "user.remove_asset"
OP_REQUEST_MEMBERSHIP: Final = "user.request_membership"
OP_SWARM_STATUS: Final = "user.swarm_status"
OP_SYNC_ASSETS: Final = "user.sync_assets"
OP_SYNC_WITH: Final = "user.sync_with"

# --- the constants astrald fixes -----------------------------------------

DEFAULT_CONTRACT_VALIDITY: Final = Duration(365 * 24 * 3600 * 1_000_000_000)
"""One year, the validity `user.new_node_contract` applies with no `duration`.

`astrald/mod/user/src/config.go:12`, `365 * 24 * time.Hour`. Its text form is
`8760h0m0s`, which is what Go's `ParseDuration` reads back; there is no year
unit in that syntax.
"""

MINIMAL_CONTRACT_LENGTH: Final = Duration(3600 * 1_000_000_000)
"""One hour, the shortest contract `user.accept_membership` accepts.

`astrald/mod/user/src/config.go:11`. The check is the node's and runs on the
remaining validity, not on the contract's total span.
"""

EVENT_ASSETS: Final = "assets"
"""The only `mod.user.notification` event astrald sends.

`AddAsset` and `RemoveAsset` push it (`astrald/mod/user/src/siblings.go:25`),
and no other call site exists.
"""

# --- the error texts this module's ops answer with ------------------------
#
# Every one arrives as an `error_message` object and surfaces as `RemoteError`,
# whose `message` is the responder's text verbatim. They are named here because
# a caller that must tell "declined" from "expelled" has nothing else to match
# on: the wire carries a string and no code. `astral-go/api/user/errors.go`.

ERR_INVITATION_DECLINED: Final = "invitation declined"
"""`accept_membership`: the node's swarm invite policy refused the caller."""

ERR_REQUEST_DECLINED: Final = "request declined"
"""`request_membership`: the remote's join-request policy refused the caller."""

ERR_NO_ACTIVE_CONTRACT: Final = "no active contract"
"""`sync_with`: the node belongs to no user, so there is nothing to sync."""

ERR_EXPELLED: Final = "identity expelled from swarm"
"""`accept_membership`: the node holds the issuer's ban on itself.

Self-refusal, so a hostile or buggy issuer cannot re-seat an expelled node. It
is effective only once the ban has propagated to the node being invited.
"""

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
_IDENTITY: Final[Spec] = Primitive("identity")
_OBJECT_ID: Final[Spec] = Primitive("object_id.sha256")
_STRING8: Final[Spec] = Primitive("string8")
_UINT64: Final[Spec] = Primitive("uint64")
_ZONE: Final[Spec] = Primitive("zone")


# --- wire types ----------------------------------------------------------


@record("mod.user.info")
class Info:
    """The node's own membership: whose node it is, and under which contract.

    `user.info`'s whole answer. `node_alias` and `user_alias` are the
    directory's **display names** for the contract's subject and issuer at the
    moment of the query, so neither is a stable identifier and neither is part
    of the contract. `Dir.DisplayName` is an alias when there is one, else a
    resolver's name, else the identity's fingerprint -- eight hex characters, a
    colon, eight hex characters (`astrald/mod/dir/src/module.go:105`); the zero
    identity renders as `<anyone>`. Verified live: `furry-bolt` for the node,
    `03a40290:839f941d` for the user, which is a fingerprint and not a name.

    `contract_id` is the ObjectID of `contract`, which the node computes with
    `astral.ResolveObjectID` before sending. `astral.objectid.object_id
    (info.contract)` recomputes it locally and the two agree on any contract
    this SDK decoded correctly, because a content hash has no slack -- verified
    live and pinned as a byte vector.
    """

    node_alias: str = wire("NodeAlias", Primitive("string8"))
    user_alias: str = wire("UserAlias", Primitive("string8"))
    contract_id: ObjectID | None = wire("ContractID", Ptr("object_id.sha256"))
    contract: SignedContract | None = wire(
        "Contract", Ptr("mod.auth.signed_contract")
    )

    @property
    def user_id(self) -> Identity | None:
        """The user this node belongs to: the active contract's issuer."""
        if self.contract is None or self.contract.contract is None:
            return None
        return self.contract.contract.issuer

    @property
    def node_id(self) -> Identity | None:
        """The node the contract names: the active contract's subject."""
        if self.contract is None or self.contract.contract is None:
            return None
        return self.contract.contract.subject


@record("mod.users.swarm_member")
class SwarmMember:
    """One node of the swarm, with its alias and whether it is linked now.

    `linked` is liveness at the instant of the query -- `Nodes.IsLinked` --
    and not membership: an unlinked member is still a member. Membership comes
    from the active contracts the issuer signed.

    The type name carries the **plural** `mod.users` segment while the op that
    sends it and every other type here is singular. Spelled literally, verified
    on the live registry.
    """

    identity: Identity | None = wire("Identity", Ptr("identity"))
    alias: str = wire("Alias", Primitive("string8"))
    linked: bool = wire("Linked", Primitive("bool"))


@record("mod.users.created_user_info")
class CreatedUserInfo:
    """A newly provisioned user, its key, its first contract and its token.

    Declared for decode completeness. No op on the live registry answers with
    one -- there is no `users.*` module on the node, verified this session --
    and astrald never constructs the type; astral-go declares it in `api/user`.

    `access_token` is a bearer credential. It is a plain field on a plain
    record: nothing here redacts it and `repr` prints it.
    """

    id: Identity | None = wire("ID", Ptr("identity"))  # noqa: A003
    alias: str = wire("Alias", Primitive("string8"))
    key_id: ObjectID | None = wire("KeyID", Ptr("object_id.sha256"))
    contract_id: ObjectID | None = wire("ContractID", Ptr("object_id.sha256"))
    contract: SignedContract | None = wire(
        "Contract", Ptr("mod.auth.signed_contract")
    )
    access_token: str = wire("AccessToken", Primitive("string8"))


@record("mod.user.notification")
class Notification:
    """A sibling's announcement that something changed. One field: the event.

    Pushed, never answered: `AddAsset` and `RemoveAsset` push one with
    `event == "assets"` to every linked sibling
    (`astrald/mod/user/src/siblings.go:25`). astrald's own receiver has no case
    for the type, so nothing acts on it there; an app that serves
    `objects.push` receives it and decides for itself.
    """

    event: str = wire("Event", Primitive("string8"))


@record("mod.user.expulsion")
class Expulsion:
    """The unsigned body of a ban: `issuer` bans `subject`, permanently.

    Identity-level and irreversible: astrald has no op that lifts one, and the
    ban is re-checked on every membership path -- `IssueMembership` refuses an
    expelled subject and `accept_membership` self-refuses when the node already
    holds the issuer's ban on itself.

    `expelled_at` is the moment the ban was signed, not an expiry. A ban does
    not expire.

    `SignedExpulsion` is the wire, stored and propagated form. This body alone
    authorizes nothing.
    """

    issuer: Identity | None = wire("Issuer", Ptr("identity"))
    subject: Identity | None = wire("Subject", Ptr("identity"))
    expelled_at: Time = wire("ExpelledAt", Primitive("time"))

    def signable_hash(self) -> bytes:
        """The 32 bytes a hash signature covers. astral-go's `SignableHash`.

        `ResolveObjectID(expulsion).Hash`, the content hash of this object's
        canonical form, and the same construction `mod.auth.contract` uses.
        """
        return object_id(self).hash

    def signable_text(self) -> str:
        """The one line a text signature covers. astral-go's `SignableText`.

        Reproduced verbatim from `api/user/expulsion.go:39`, because a
        signature is over the bytes of this string and one character is a
        signature that never verifies::

            <issuer> expels <subject> from the swarm

        An absent identity renders as 66 zeros, which is what Go's
        `(*Identity).String()` returns for a nil receiver.
        """
        return (
            f"{_identity_text(self.issuer)} expels "
            f"{_identity_text(self.subject)} from the swarm"
        )


@record("mod.user.signed_expulsion")
class SignedExpulsion:
    """A ban with the issuer's signature beside it. One signature, not two.

    `expulsion` is Go's embedded `*Expulsion`, declared as an ordinary pointer
    field for the reason `mod.auth.signed_contract` is: the two spellings
    produce identical bytes and identical JSON, and the node's own blueprint
    carries `ptr_spec -> mod.user.expulsion` under the name `Expulsion`,
    verified live.

    Attribute lookups do **not** forward into the body: `signed.issuer` is an
    `AttributeError` and `signed.expulsion.issuer` is the issuer.

    The subject never signs. A ban is issued against an identity, not agreed
    with it, so `fully_signed` has no counterpart here.
    """

    expulsion: Expulsion | None = wire("Expulsion", Ptr("mod.user.expulsion"))
    issuer_sig: Signature | None = wire("IssuerSig", Ptr("mod.crypto.signature"))


@record("mod.user.op_update")
class OpUpdate:
    """One row of the asset log: an object ID added, or removed.

    The unit `user.sync_assets` streams. `removed` is the whole of the
    semantics: `False` adds `object_id` to the user's assets, `True` removes
    it. `nonce` is the row's identity in the log, which is what makes the
    removal of a re-added object unambiguous -- astrald's reader calls
    `RemoveAssetByNonce(nonce, object_id)`.

    Declared here rather than imported: astral-go's `api/user` does not carry
    the type. astrald defines it beside the op
    (`astrald/mod/user/src/op_sync_assets.go`) and the live node knows it,
    verified through `objects.get_blueprint`.
    """

    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))
    removed: bool = wire("Removed", Primitive("bool"))


# --- the action types -----------------------------------------------------
#
# Each embeds `auth.Action` by value, so `Nonce` and `ActorID` come first and
# the payload flattens. They are the strings a `mod.auth.permit` names, not
# objects any op here exchanges: `Permit.action` matches on the type name.


@record("mod.user.adopt_action")
class AdoptAction(Action):
    """Permission for the actor to adopt `subject` into the user's swarm.

    Granted with `Delegation: 1` on a management node's contract, so the node
    can contract it out one hop to an app it hosts.
    """

    subject: Identity | None = wire("Subject", Ptr("identity"))

    def apply_constraints(self, constraints: Any) -> bool:
        """astral-go's `ApplyConstraints`: any constraint at all refuses.

        `cs == nil || len(cs.Objects()) == 0` -- an empty bundle permits and a
        non-empty one denies, whatever it holds. The action reads no constraint
        it is given, so a permit that carries one grants nothing.
        """
        return _unconstrained(constraints)


@record("mod.user.expel_action")
class ExpelAction(Action):
    """Permission for the actor to expel `subject` from the user's swarm.

    Delegable one hop on a management node's contract, exactly as
    `AdoptAction` is, and constrained the same way: any constraint refuses.
    """

    subject: Identity | None = wire("Subject", Ptr("identity"))

    def apply_constraints(self, constraints: Any) -> bool:
        return _unconstrained(constraints)


@record("mod.user.info_action")
class InfoAction(Action):
    """Permission for the actor to read `user.info`.

    Carries `auth.Action`'s two fields and nothing else. The user and every
    swarm sibling hold it implicitly; another identity needs the permit.
    """

    def apply_constraints(self, constraints: Any) -> bool:
        return _unconstrained(constraints)


@record("mod.user.swarm_membership_action")
class SwarmMembershipAction(Action):
    """The permit that makes a contract a node contract.

    Named by `is_node_contract`, which is the whole of astral-go's
    `IsNodeContract` (`api/user/contract.go:12`). It carries no constraint
    method: astral-go declares none, so any constraint on a permit for it is
    inert rather than restrictive (`mod.auth.permit.allows`).
    """


class AssetSync(NamedTuple):
    """`user.sync_assets`'s answer: the rows, and the cursor to poll from next.

    A tuple, so `updates, next_height = await client.user.sync_assets()`
    unpacks as design section 3.10 states, and named, so a caller that keeps
    the whole thing can say which half it means.

    `next_height` is the value to pass as the next `start`. It is `start`
    itself when no row was found, so re-polling with it is safe and empty.
    """

    updates: list[OpUpdate]
    next_height: int


# --- the client -----------------------------------------------------------


class User(ModuleClient):
    """The `user` module's fifteen ops, over one `Client`.

    Reached as `client.user`, a cached property built on first use;
    `User(client)` constructs the same object directly. The scaffolding and the
    `**kw` contract are `ModuleClient`'s.

    Seven of the fifteen are read-only: `info`, `assets`, `sync_assets`,
    `list_siblings`, `list_expelled`, `swarm_status` and `new_node_contract`.
    Of the other eight, `adopt`, `expel`, `accept_contract`,
    `accept_membership` and `request_membership` change who a node belongs to,
    `add_asset`, `remove_asset` and `sync_with` change what it holds, and
    `expel` is irreversible.
    """

    __slots__ = ()

    # --- reads ---

    async def info(self, **kw: Any) -> Info:
        """The node's own membership. RR, one object, no `eos`.

        Rejects with code 2 when the node has no active contract, which is the
        setup-mode probe, and with code 4 when the caller holds no
        `mod.user.info_action` permit. The user and every swarm sibling are
        authorized implicitly.

        Verified live against `furry-bolt`, which is claimed: the answer
        decodes to an `Info` whose contract's subject is the node's own
        identity.
        """
        return self._expect(await self._c.call_one(OP_INFO, **kw), Info, OP_INFO)

    async def assets(self, **kw: Any) -> list[ObjectID]:
        """Every object ID in the user's asset set. ST, ends at `eos`.

        Removed assets are excluded by the node. The set is the user's, not
        this node's repository: an asset is a claim about what the swarm keeps,
        and `objects.contains` is what answers whether the bytes are here.

        No active contract is needed. Verified live: an `eos` and nothing else
        on a node with no assets.
        """
        return [
            self._expect(obj, ObjectID, OP_ASSETS)
            for obj in await self._c.call(OP_ASSETS, **kw)
        ]

    async def sync_assets(self, *, start: int = 0, **kw: Any) -> AssetSync:
        """The asset log from `start`, and the next height. **No `eos`.**

        The one op in the SDK whose stream ends with a value: zero or more
        `mod.user.op_update` objects, then a bare `uint64`, then the close. The
        generic readers all wait for a terminator that never comes, so this
        method reads object by object and stops at the height
        (design section 3.10).

        `start` is a database height, not a time and not a count. Poll with the
        `next_height` of the previous answer; an empty answer echoes `start`
        back, so the same value re-polls safely.

        The whole exchange is bounded by the one-shot budget `timeout` sets, so
        a node that streams without ever sending the height costs the deadline
        and not the rest of the process's life.

        Rejects with code 2 on a database fault. No active contract is needed.
        """
        qs = querystring.build(
            OP_SYNC_ASSETS,
            self._encode(
                {"start": _UINT64}, {"start": _height(start, OP_SYNC_ASSETS)}
            ),
        )
        updates: list[OpUpdate] = []
        async with self._one_shot(qs, kw) as (stream, budget):
            while True:
                obj = await stream.first(timeout=budget.remaining)
                if obj is None:
                    raise ProtocolError(
                        f"{OP_SYNC_ASSETS}: the stream ended after "
                        f"{len(updates)} update(s) with no height "
                        f"({stream.terminated_by}); the op's last object is a "
                        "bare uint64 and there is no eos"
                    )
                if isinstance(obj, Uint64):
                    return AssetSync(updates, int(obj))
                updates.append(self._expect(obj, OpUpdate, OP_SYNC_ASSETS))

    async def list_siblings(
        self, *, zone: Zone | int | str | None = None, **kw: Any
    ) -> list[Identity]:
        """The identities of the currently linked sibling nodes. ST, `eos`.

        Two filters, both of them: linked **now**, and not the local node. An
        unlinked member of the swarm is a member and is not in this list, and
        the node answering is never in it. `swarm_status` is the list that
        carries every member with its liveness beside it.

        `zone` is sent as the op's argument **and** as the routing zone, the
        way `Objects` sends its one scope to both levers. The op's own
        argument is inert on astrald `074a852b` -- the context built from it is
        never used (`mod/user/src/op_list_siblings.go:17`) -- and the routing
        zone is not.

        The op has no active-contract guard, so it answers on any node.
        Verified live on a claimed node with no linked sibling: a bare `eos`.
        """
        params: dict[str, Any] = {}
        if zone is not None:
            scope = _zone(zone)
            params["zone"] = scope
            kw["zone"] = scope
        qs = querystring.build(
            OP_LIST_SIBLINGS, self._encode({"zone": _ZONE}, params)
        )
        return [
            self._expect(obj, Identity, OP_LIST_SIBLINGS)
            for obj in await self._c.call(qs, **kw)
        ]

    async def swarm_status(self, **kw: Any) -> list[SwarmMember]:
        """Every active node of the swarm, with its alias and liveness. ST, `eos`.

        The membership list, where `list_siblings` is the linked subset of it:
        `SwarmMember.linked` carries the fact `list_siblings` filters on, so one
        query answers both questions. **The local node is in this list** and is
        never in `list_siblings` -- verified live, where `swarm_status` answered
        one member, the node itself, with `linked=False`.

        Rejects with code 2 when the node has no active contract. Readable by
        any caller.
        """
        return [
            self._expect(obj, SwarmMember, OP_SWARM_STATUS)
            for obj in await self._c.call(OP_SWARM_STATUS, **kw)
        ]

    async def list_expelled(self, **kw: Any) -> list[SignedExpulsion]:
        """Every ban the active user has issued. ST, ends at `eos`.

        Scoped to the active contract's issuer, so it is the swarm's ban list
        and not this node's. Rejects with code 2 without an active contract.
        Readable by any caller.
        """
        return [
            self._expect(obj, SignedExpulsion, OP_LIST_EXPELLED)
            for obj in await self._c.call(OP_LIST_EXPELLED, **kw)
        ]

    async def new_node_contract(
        self,
        *,
        user: Identity | str | None = None,
        node: Identity | str | None = None,
        duration: Duration | str | None = None,
        **kw: Any,
    ) -> Contract:
        """Build an unsigned node contract. RR, one object, no `eos`.

        Construction only: nothing is signed, stored or activated, and the
        answer authorizes nothing until it is signed by both parties and
        indexed. `new_node_contract_local` builds the same object with no query
        at all.

        `user` defaults to the node's user identity and `node` to the node
        itself. Both are resolved by the node's directory, so an alias,
        `localnode` or 66 hex characters all reach it; an unknown name answers
        `unknown identity: <name>`, verified live.

        `duration` is Go's duration syntax -- `48h`, `30m`, `8760h0m0s` -- and
        **has no year unit**: `1y` answers `time: unknown unit "y" in duration
        "1y"`, verified live. A string is validated locally with
        `Duration.parse`, whose unit table is Go's, so a typo is refused here.
        The node's default is one year (`DEFAULT_CONTRACT_VALIDITY`).

        The contract carries the four permits of a management node --
        membership, and expel, adopt and info each delegable one hop -- because
        astrald passes `managementNode=true` unconditionally
        (`mod/user/src/op_new_node_contract.go`). Verified live.
        """
        params: dict[str, Any] = {}
        if user is not None:
            params["user"] = _name(user, OP_NEW_NODE_CONTRACT, "user")
        if node is not None:
            params["node"] = _name(node, OP_NEW_NODE_CONTRACT, "node")
        if duration is not None:
            params["duration"] = _duration(duration, OP_NEW_NODE_CONTRACT)
        qs = querystring.build(
            OP_NEW_NODE_CONTRACT,
            self._encode(
                {"user": _STRING8, "node": _STRING8, "duration": _STRING8}, params
            ),
        )
        return self._expect(
            await self._c.call_one(qs, **kw), Contract, OP_NEW_NODE_CONTRACT
        )

    # --- assets ---

    async def add_asset(self, id: ObjectID | str, **kw: Any) -> None:  # noqa: A002
        """Add one object ID to the user's assets. RR, one `ack`. **Mutates.**

        The node writes a log row and pushes a `mod.user.notification` to every
        linked sibling. A database failure is a **rejection** with
        `internal_error` (4), not an `error_message`: the op rejects before it
        accepts, so the failure arrives as `QueryRejected` and never as an
        object.

        `id` is mandatory here. astrald does not mark it required, so an absent
        one reaches the database as a null object ID.
        """
        qs = querystring.build(
            OP_ADD_ASSET,
            self._encode({"id": _OBJECT_ID}, {"id": _object_id(id, OP_ADD_ASSET)}),
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_ADD_ASSET)

    async def remove_asset(self, id: ObjectID | str, **kw: Any) -> None:  # noqa: A002
        """Remove one object ID from the user's assets. RR, one `ack`.
        **Mutates.**

        Removal is a log row like the addition, so a later `sync_assets` sees a
        `mod.user.op_update` with `removed=True` rather than a gap. The stored
        bytes are untouched: this is the user's asset set, not a repository.

        A database failure rejects with `internal_error` (4), as `add_asset`
        does.
        """
        qs = querystring.build(
            OP_REMOVE_ASSET,
            self._encode(
                {"id": _OBJECT_ID}, {"id": _object_id(id, OP_REMOVE_ASSET)}
            ),
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_REMOVE_ASSET)

    async def sync_with(
        self, node: Identity | str, *, start: int | None = None, **kw: Any
    ) -> None:
        """Pull the asset log from one sibling. RR, one `ack`. **Mutates.**

        The node runs `sync_assets` against `node` over the network zone and
        applies every row to its own database, then stores the next height in
        its tree at `/mod/user/assets/<node>/next_height`. Long-running: the
        `ack` arrives only after the whole exchange, and any failure in it --
        `ERR_NO_ACTIVE_CONTRACT` included -- is an `error_message` rather than
        a rejection.

        `node` is parsed as an **identity** by the op, so 66 hex characters or
        `anyone` reach it and a directory name never does -- unlike `adopt`,
        `expel` and `new_node_contract`, whose targets the node resolves.
        Refused here rather than sent, because the op's argument is not marked
        required and an absent one syncs with the zero identity.

        **`start` is inert on astrald `074a852b`.** The op declares it and
        `OpSyncWith` never reads it: `syncAssets` takes the node and reads the
        height out of the tree itself (`mod/user/src/op_sync_with.go:20`,
        `mod/user/src/sync.go:29`). It is therefore sent only when the caller
        names it, never by default -- an implicit `start=0` is identical to an
        absent one today and would mean "re-read the whole log from zero" the
        moment astrald wires the argument up, which is not what a caller who
        named no height asked for.
        """
        params: dict[str, Any] = {"node": _identity(node, OP_SYNC_WITH)}
        if start is not None:
            params["start"] = _height(start, OP_SYNC_WITH)
        qs = querystring.build(
            OP_SYNC_WITH,
            self._encode({"node": _IDENTITY, "start": _UINT64}, params),
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_SYNC_WITH)

    # --- the swarm ---

    async def adopt(self, node: Identity | str, **kw: Any) -> SignedContract:
        """Adopt a node into the user's swarm. RR, one object. **Mutates.**

        The node issues a membership contract for `node`, indexes it, stores
        it, and pushes it to the local swarm. The answer is the signed
        contract.

        Rejects with 2 without an active contract, 3 when `node` does not
        resolve, and 4 when the caller holds no `mod.user.adopt_action` permit
        (`astrald/mod/user/src/op_adopt.go:34`). The user always holds it.

        `node` is resolved by the node's directory: an alias, `localnode` or 66
        hex characters all reach it. An empty name is refused here -- the
        node's resolver reads it as the zero identity and the op would sign a
        membership contract for `anyone`.

        **`node`, not `target`.** The op's wire argument is `target=` and
        travels as one; `target` in `**kw` keeps meaning the node this query is
        routed to, which on this op is a different node.
        """
        return self._expect(
            await self._c.call_one(_targeted(OP_ADOPT, node), **kw),
            SignedContract,
            OP_ADOPT,
        )

    async def expel(self, node: Identity | str, **kw: Any) -> SignedExpulsion:
        """Ban a node from the swarm, permanently. RR, one object.
        **Irreversible.**

        The ban is identity-level and astrald has no op that lifts one. The
        answer is the signed expulsion, which the node propagates; a sibling
        that receives it stops treating the subject as a member.

        Reject codes are `adopt`'s: 2 without an active contract, 3 for an
        unresolvable target, 4 for a caller with no `mod.user.expel_action`
        permit.

        `node` is a directory name or an identity, and an empty one is refused:
        the zero identity resolves and the ban would name `anyone`.
        """
        return self._expect(
            await self._c.call_one(_targeted(OP_EXPEL, node), **kw),
            SignedExpulsion,
            OP_EXPEL,
        )

    async def request_membership(self, **kw: Any) -> SignedContract:
        """Ask a node's user to admit **this caller**. RR, one object.
        **Mutates.**

        The subject is the query's caller and there is no argument to name
        another one, so this is the op a joining node sends outward. The remote
        applies its join-request policy, issues the membership contract,
        indexes it, stores it and pushes it to its swarm; a refusal is
        `ERR_REQUEST_DECLINED` on the stream.

        Rejects with code 2 when the remote has no active contract of its own:
        a node that belongs to no user cannot admit one.

        Answers on the **remote's** state. Route it with `target=` to the node
        being asked.
        """
        return self._expect(
            await self._c.call_one(OP_REQUEST_MEMBERSHIP, **kw),
            SignedContract,
            OP_REQUEST_MEMBERSHIP,
        )

    async def accept_membership(
        self, contract: Contract, issuer_sig: Signature, **kw: Any
    ) -> Signature:
        """Run the signing ceremony against a node. WA. **Mutates.**

        **Both inputs travel on the channel body**, in order: the unsigned
        `mod.auth.contract`, then the issuer's `mod.crypto.signature` over it.
        The op has no parameters at all. The answer is the subject's
        countersignature.

        No `eos` is sent. The op's reader breaks on the object it expects and
        answers `err_unexpected_object` for anything else, so a terminator
        after the last input is an error rather than a no-op.

        Both objects go out before the answer is read. The op answers once,
        after both, so a send-one-read-one exchange would deadlock on the first
        read.

        The node checks the contract before it signs: the subject must be the
        node itself, the remaining validity must exceed one hour
        (`MINIMAL_CONTRACT_LENGTH`), the node must not already hold the
        issuer's ban on itself (`ERR_EXPELLED`), and the swarm invite policy
        must approve (`ERR_INVITATION_DECLINED`). Every failure is an
        `error_message` and arrives as `RemoteError`.
        Rejects with code 2 when the node already has an active contract.

        An `error_message` **after** the signature means the node signed and
        then failed to index, store or activate: the ceremony did not complete,
        the exception is raised, and the countersignature is discarded with it.
        """
        if not isinstance(contract, Contract):
            raise BadArgumentType(
                f"{OP_ACCEPT_MEMBERSHIP}: expected a Contract, got "
                f"{type(contract).__name__}; the unsigned body is the first "
                "input and the issuer's signature the second"
            )
        if not isinstance(issuer_sig, Signature):
            raise BadArgumentType(
                f"{OP_ACCEPT_MEMBERSHIP}: expected a Signature, got "
                f"{type(issuer_sig).__name__}; the second input is the "
                "issuer's signature over the contract"
            )
        answers = await self._c.call_with(
            OP_ACCEPT_MEMBERSHIP, contract, issuer_sig, eos=False, **kw
        )
        if not answers:
            raise ProtocolError(
                f"{OP_ACCEPT_MEMBERSHIP}: the stream ended without a signature"
            )
        return self._expect(answers[0], Signature, OP_ACCEPT_MEMBERSHIP)

    async def accept_contract(self, signed: SignedContract, **kw: Any) -> None:
        """Activate a contract that is already fully signed. WA, one `ack`.
        **Mutates.**

        The cold-card counterpart of `accept_membership`: no ceremony, one
        input. The node validates the signatures, the subject, the expiry and
        the membership permit **before** it stores anything, then stores the
        contract and activates it.

        **The contract travels on the channel body**, and no `eos` follows it,
        for the reason `accept_membership` sends none.

        Rejects with code 2 when the node already has an active contract:
        claiming a node is a one-time transition. Every validation failure is
        an `error_message` and arrives as `RemoteError`.

        astrald `074a852b` carries the op (`op_accept_contract.go`, astrald
        #357) and astral-go `5c18d9c` carries no client for it; the client that
        exists upstream is newer than the pin.
        """
        if not isinstance(signed, SignedContract):
            raise BadArgumentType(
                f"{OP_ACCEPT_CONTRACT}: expected a SignedContract, got "
                f"{type(signed).__name__}; this op takes a contract both "
                "parties have already signed"
            )
        answers = await self._c.call_with(
            OP_ACCEPT_CONTRACT, signed, eos=False, **kw
        )
        if not answers:
            raise ProtocolError(
                f"{OP_ACCEPT_CONTRACT}: the stream ended without an answer"
            )
        self._expect(answers[0], Ack, OP_ACCEPT_CONTRACT)


# --- the pure helpers -----------------------------------------------------


def new_node_contract_local(
    issuer: Identity,
    subject: Identity,
    *,
    management_node: bool = False,
    duration: Duration | int = DEFAULT_CONTRACT_VALIDITY,
) -> Contract:
    """Build a node contract with no query. astral-go's `NewNodeContract`.

    The same object `user.new_node_contract` answers with, constructed here:
    one `mod.user.swarm_membership_action` permit, plus expel, adopt and info
    permits with `Delegation: 1` for a management node
    (`astral-go/api/user/contract.go:20-26`).

    The op passes `managementNode=true` unconditionally, so its answer always
    carries four permits; this helper defaults to `False`, which is the shape
    astrald uses for an ordinary member (`mod/user/src/contracts.go:171`).

    `expires_at` is now plus `duration`, resolved at call time.
    """
    permits = [Permit(action=SwarmMembershipAction.ASTRAL_TYPE, delegation=0)]
    if management_node:
        permits += [
            Permit(action=ExpelAction.ASTRAL_TYPE, delegation=1),
            Permit(action=AdoptAction.ASTRAL_TYPE, delegation=1),
            Permit(action=InfoAction.ASTRAL_TYPE, delegation=1),
        ]
    return Contract(
        issuer=issuer,
        subject=subject,
        permits=permits,
        expires_at=Time(Time.now() + int(duration)),
    )


def is_node_contract(contract: Contract) -> bool:
    """Whether a contract grants swarm membership. astral-go's `IsNodeContract`.

    One test and no other: the contract holds at least one permit for
    `mod.user.swarm_membership_action` (`astral-go/api/user/contract.go:12`).
    Neither expiry nor signature is examined -- an expired node contract is
    still a node contract, and `Contract.expired` is the separate question.
    """
    return bool(contract.has_permit(SwarmMembershipAction.ASTRAL_TYPE))


# --- argument and answer discipline --------------------------------------


_param = ModuleClient._param
"""One parameter value, in its text form. `ModuleClient`'s, not a copy."""


def _object_id(value: ObjectID | str, op: str) -> ObjectID:
    """An `object_id.sha256` argument, naming the op that refused it."""
    return ModuleClient._object_id(value, op)


def _identity(value: Identity | str, op: str) -> Identity:
    """An identity argument. 66 hex characters or `anyone`, never a name.

    The op parses this argument with `astral.ParseIdentity`, so a name reaches
    it as a rejected query rather than as an error message. Refusing it here
    names the fix instead.
    """
    if isinstance(value, Identity):
        return value
    try:
        return Identity.parse(value)
    except ParseError as exc:
        raise ParseError(
            f"{op}: {value!r} is not an identity; this argument is parsed as "
            "one and a directory name never reaches it -- resolve it first"
        ) from exc


def _name(value: Identity | str, op: str, key: str) -> str:
    """A name argument the node resolves: an alias, `localnode`, or a hex key.

    An empty string is refused: the node's resolver maps it to the zero
    identity, so an accidental empty name adopts, expels or contracts
    `anyone`.
    """
    if isinstance(value, Identity):
        return value.text()
    if not value:
        raise BadArgument(
            f"{op}: the empty name resolves to the zero identity on the node, "
            f"so {key}= would name `anyone`; pass Identity.ANYONE to mean that "
            "identity"
        )
    return value


def _targeted(op: str, node: Identity | str) -> str:
    """`<op>?target=<name>`, the query string `adopt` and `expel` share."""
    return querystring.build(
        op, {"target": _param(_STRING8, _name(node, op, "target"))}
    )


def _height(value: int, op: str) -> int:
    """A `start` argument: a database height, non-negative and never a time.

    The op is named in the failure, as every other refusal in this package
    names it: two ops take a height and a message that says only `start` does
    not say which one refused the value.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadArgumentType(
            f"{op}: start expects an int height, got {type(value).__name__}"
        )
    if value < 0:
        raise BadArgument(f"{op}: start={value} is negative; a height is a uint64")
    return value


def _zone(value: Zone | int | str) -> Zone:
    """A zone argument, from a `Zone`, its bits, or its `dvn` letters."""
    if isinstance(value, Zone):
        return value
    if isinstance(value, str):
        return Zone.parse(value)
    return Zone(int(value))


def _duration(value: Duration | str, op: str) -> str:
    """A `duration` argument, as the Go duration string the op parses.

    A string is parsed locally first, so `1y` is refused here with the unit
    named rather than arriving as `time: unknown unit "y"` from the node.
    `Duration.parse` accepts exactly Go's unit table.
    """
    if isinstance(value, Duration):
        return value.text()
    if not isinstance(value, str):
        raise BadArgumentType(
            f"{op}: duration expects a Go duration string or a Duration, got "
            f"{type(value).__name__}"
        )
    Duration.parse(value)  # raises ParseError on anything the node would reject
    return value


def _identity_text(value: Identity | None) -> str:
    """An identity as `SignableText` renders it: 66 zeros for an absent one.

    Go's `(*Identity).String()` maps a nil receiver and the zero key to the
    same 66 zeros, so the signed text cannot distinguish them either.
    """
    return Identity.ANYONE.text() if value is None else value.text()


def _unconstrained(constraints: Any) -> bool:
    """astral-go's `ApplyConstraints` for the three constrained action types.

    `cs == nil || len(cs.Objects()) == 0`: an absent or empty bundle permits,
    and any constraint at all denies.
    """
    return constraints is None or len(constraints) == 0


USER_TYPES: Final[Sequence[type]] = (
    AdoptAction,
    CreatedUserInfo,
    ExpelAction,
    Expulsion,
    Info,
    InfoAction,
    Notification,
    OpUpdate,
    SignedExpulsion,
    SwarmMember,
    SwarmMembershipAction,
)
"""Every wire type this module declares, for a private-registry sweep.

`mod.auth.contract`, `mod.auth.signed_contract` and `mod.crypto.signature` are
answered by ops here and declared by `astral.api.auth` and `astral.api.crypto`;
a private registry that wants to decode this module needs
`registry.add(*User.TYPES, *Auth.TYPES, *Crypto.TYPES)`. Registration into the
default registry has already happened at import
(`astral/api/__init__.py`); this is the list, not the act.
"""

User.TYPES = USER_TYPES
