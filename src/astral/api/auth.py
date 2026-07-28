"""`auth`: contracts, permits and actions -- the node's authorization vocabulary.

Tier 1, two ops, three wire types and one field base. The ops are the smallest
surface of any module in this SDK; the types are the largest part of it, because
`mod.auth.contract` and `mod.auth.signed_contract` are what two other modules
exchange -- `apphost.new_app_contract`, `apphost.sign_app_contract`,
`apphost.install_app`, `user.accept_contract`, `user.accept_membership`,
`user.adopt`, `user.request_membership` and `user.new_node_contract` all answer
with one or read one.

**Op surface, and the shape each one declares** (design section 4.7; a shape is
a per-op contract and is not discoverable from the wire):

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `auth.index` | RR | `ack` \\| `error_message` | **mutates** the local contract index |
| `auth.sign_contract` | WA | `mod.auth.signed_contract` \\| `error_message` | privileged, no state written |

Both are the whole of the module. `shell.spec` on `furry-bolt` lists exactly
`auth.index` and `auth.sign_contract`, verified this session, and astral-go's
`api/auth/module.go` declares the same two constants.

**`auth.index` requires its object ID on the running node.** The live spec flags
`id` `"Required":true` and the routing layer refuses the query before the op
runs: `auth.index` with no `id` answers `query_rejected_msg{1}`, both verified
against `furry-bolt` this session. So an absent id is a `QueryRejected` and
never an `error_message`.

**astrald has since grown a batch mode for it, and the running node does not
carry one.** At astrald `fdbddccb`, `opIndexArgs.ID` becomes
`query:"optional"` and an omitted `id` makes the op read `object_id.sha256`
objects off the channel until `eos`, answering one `ack` or `error_message` per
input -- the RR/BD hybrid `objects.contains`, `objects.delete`, `objects.load`
and `objects.probe` already have. The single form is unchanged in both. This
module implements the single form only, because it is what the op inventory
lists and what any reachable node answers; `LiveAuthTest` asserts the node's own
`"Required"` flag, so a node upgraded past that commit fails there rather than
somewhere subtler.

**A contract is signed and indexed in two separate steps, and the op that signs
does not store.** `auth.sign_contract` builds a fresh `SignedContract` around
the contract it reads, signs it as issuer and as subject, sends it back, and
writes nothing (`astrald/mod/auth/src/op_sign_contract.go`). `auth.index` takes
an **object ID**, loads that object from the default read repository, and
refuses anything that is not a `mod.auth.signed_contract`. The sequence is
therefore: sign, `objects.store` the answer, index the ID that store returns.
`astral.objectid.object_id(signed)` computes the same ID locally without a
query.

`apphost.sign_app_contract` is the one-call form of all three and is a different
op: it signs, indexes, stores and pushes to the local swarm
(`astrald/mod/apphost/src/op_sign_app_contract.go`).

**`auth.sign_contract` signs both halves or fails.** The node signs as the
issuer *and* as the subject, so it must hold both private keys; `signAs` resolves
each identity to a key it owns (`astrald/mod/auth/src/signing.go`). It cannot
countersign: the op discards any signatures on its input by wrapping the contract
in a **new** `SignedContract`, and `SignIssuer`/`SignSubject` refuse a signature
that is already set (`auth.ErrAlreadySigned`), which this op can never reach.
A contract between two identities whose keys live on different nodes is signed
one half at a time through `user.accept_membership`, not here.

**The two sibling body-input ops disagree about `eos`, and both disagreements are
load-bearing.** `auth.sign_contract`'s reader is
`ch.Switch(handler, channel.BreakOnEOS)`, so a terminator ends the exchange
cleanly and this module sends one. `apphost.sign_app_contract`'s reader is
`ch.Switch(handler)` with no `BreakOnEOS`, so a terminator there reaches
`astral.NewErrUnexpectedObject` and comes back as an `error_message`
(`astral-go/astral/channel/switch.go:101`). One op name apart, opposite
terminators; neither is inferable from the wire.

**An embedded struct nests in JSON when it is a pointer and flattens when it is a
value.** Both halves are verified live against `furry-bolt`:

    mod.auth.signed_contract  {"Contract":null,"IssuerSig":null,"SubjectSig":null}
    mod.auth.sudo_action      {"Nonce":"0","ActorID":null,"AsID":null}

`SignedContract` embeds `*Contract`, a pointer, and the contract's own four keys
are absent from the outer object -- the key is `Contract`, the embedded type's
name. Every action type embeds `auth.Action` by value, and the base's two fields
are promoted into the concrete type's key set. Binary flattens both: the signed
contract's zero payload is `000000`, three nil flags, and the read-object
action's is `00000000000000000000`, a nonce and two nil flags. So `Action` below
is a **field base and not a wire type**, and `SignedContract.contract` is a
declared pointer field.

The mechanism differs from the shape and is worth naming, because it is the
reason an SDK cannot derive one rule from the other. astral-go marshals a type
that declares `MarshalJSON` through its own reflection walker, which keys every
immediate field by the Go field name -- an embedded field's name is its type's
name (`astral-go/astral/struct_value.go:149`). No action type declares
`MarshalJSON`, so every one of them is marshalled by `encoding/json`, which
promotes anonymous fields. The nesting is astral-go's rule; the flattening is
Go's default showing through a gap.

**No action type has a blueprint.** `objects.get_blueprint` answers
`error_message` for every one of them -- verified live for
`mod.auth.sudo_action`, `mod.objects.read_object_action`,
`mod.objects.create_object_action` and `mod.user.adopt_action`, each with
`BlueprintFromType <type>.Action: type auth.Action does not implement Object and
is not a supported container`. `auth.Action` has no `ObjectType` method, so
astral-go's blueprint derivation stops at the embedded field. A peer therefore
cannot learn an action type over the wire, and `astral.blueprint.of()` on the
SDK's own action records produces a schema astral-go cannot produce for itself.

**`mod.auth.action` is not a type.** It is documented in astral-docs, absent
from astral-go's registry, and the node answers `nil` to
`objects.new?type=mod.auth.action` and `blueprint not found: mod.auth.action` to
`objects.get_blueprint` -- both verified live. `Action` below is a plain
dataclass carrying the two field declarations, inherited by a concrete action
record so the fields flatten under their own names. Declaring it as a record
would put a name in the registry that no node knows and would nest the two
fields in JSON under a key no node sends.

**`mod.auth.sudo_action` exists.** astral-docs documents
`protocols/auth/types/mod.auth.sudo_action.md`, the op survey records it as
having no counterpart in astral-go (D-27), and the survey is right about
astral-go and wrong about the node: astrald declares the type in
`mod/auth/sudo_action.go`, registers it with `astral.Add`, and the live node
answers `objects.new?type=mod.auth.sudo_action` with a ten-byte zero instance,
verified this session. The type is `{Action, AsID *identity}` and its authorizer
is `Actor().IsEqual(AsID)` (`astrald/mod/auth/src/authorizers.go`), i.e. it
grants nothing that is not already the caller. It is **not declared here**: no
op in the node's 118-op registry sends one, and it belongs to astrald rather
than to astral-go's `api/auth`.

**`mod.crypto.signature` is declared by `astral.api.crypto`, not here.** Both
signature fields are `Ptr("mod.crypto.signature")`, resolved by name through the
registry at decode time, so this module states the dependency and does not own
it. A `SignedContract` whose signatures are absent decodes with `crypto` absent
too; one carrying a signature raises `StreamCorrupted` naming the unregistered
type until that module is imported. Importing `astral.api` imports both.

**A contract's validity window is one field wide.** astrald's active-contract
query is `starts_at <= now AND expires_at > now`
(`astrald/mod/auth/src/db.go`), and `storeSignedContract` never assigns
`starts_at`, so the lower bound is the Go zero time and always passes.
`ExpiresAt` is the whole of the window, and `Contract.expired` reads it.

**The zero contract carries a timestamp astral-go cannot round-trip.**
`astral.Time.WriteTo` writes `UnixNano()` and `ReadFrom` reads
`time.Unix(0, nsec)` (`astral-go/astral/time.go:16`), and Go's zero
`time.Time` -- year 1 -- overflows int64 nanoseconds. The node's own
`objects.new?type=mod.auth.contract` answers `ExpiresAt` as
`a1b203eb3d1a0000`, which is `1754-08-30T22:43:41.128654848Z`, while the same
object in JSON says `0001-01-01T00:00:00Z`: the two façades disagree about the
same value. The SDK reproduces the bytes exactly and reads the instant they
encode. Verified live, both façades, this session.

Reached as `client.auth`, the property design section 5.1 specifies, or as
`Auth(client)`, which constructs the same object; a test pins this docstring to
what `Client` actually carries, so the two cannot drift apart.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final, Sequence

from .. import querystring
from ..errors import BadArgumentType, ProtocolError
from ..object import Ack, Bundle
from ..objectid import object_id
from ..record import record, wire
from ..spec import Primitive, Ptr, Slice, Spec
from ..types import Identity, Nonce, ObjectID, Time
from .base import ModuleClient

__all__ = [
    "AUTH_TYPES",
    "Action",
    "Auth",
    "Contract",
    "OP_INDEX",
    "OP_SIGN_CONTRACT",
    "Permit",
    "SignedContract",
]

OP_INDEX: Final = "auth.index"
OP_SIGN_CONTRACT: Final = "auth.sign_contract"

# The parameter specs, so every value travels as the bare payload half of its
# type's text encoding and nothing re-derives one (design section 5.1, rule 2).
# `auth.index` declares the module's only parameter.
_INDEX: Final[dict[str, Spec]] = {"id": Primitive("object_id.sha256")}


# --- the action field base ------------------------------------------------


@dataclasses.dataclass(slots=True, kw_only=True)
class Action:
    """The two fields every concrete action type carries, and no wire type.

    astral-go's `auth.Action` is embedded by value into `mod.objects.*_action`,
    `mod.user.*_action`, `mod.nodes.relay_for_action` and astrald's
    `mod.auth.sudo_action`. A value embed flattens in binary **and** in JSON, so
    a concrete action inherits this class rather than referencing it:

        @record("mod.objects.read_object_action")
        class ReadObjectAction(Action):
            object_id: ObjectID | None = wire("ObjectID", Ptr("object_id.sha256"))

    `dataclasses.fields()` returns base fields first, which is Go's promotion
    order, so `FIELDS` is `Nonce, ActorID, ObjectID` and the payload is
    `00000000000000000000` for the zero value -- the bytes the live node answers
    for that type, verified this session.

    Not decorated with `@record`: `mod.auth.action` is not registered on any
    node, and a record would both invent a registry name and nest these two
    fields in JSON under a key nothing sends.

    `Nonce` is a fresh 64-bit value per action, not a query correlator.
    `Nonce.random()` is what astral-go's `NewAction` calls; the zero value is a
    zero nonce, and a caller that reuses one hands the node two actions it
    cannot tell apart.

    astral-go's `ActionObject` interface -- `Id()`, `Actor()`, `SetActor()` --
    has no counterpart here: the two fields are public and mutable, so an
    accessor would be a second name for one of them.
    """

    nonce: Nonce = wire("Nonce", Primitive("nonce64"))
    actor_id: Identity | None = wire("ActorID", Ptr("identity"))


# --- wire types -----------------------------------------------------------


@record("mod.auth.permit")
class Permit:
    """One grant: an action type, its constraints, and how far it delegates.

    `action` is the **object type name** of an action, not a verb:
    `mod.objects.read_object_action`, `mod.user.adopt_action`. A permit whose
    action names a type the node does not know grants nothing, because
    authorization matches on the string the concrete action reports.

    `constraints` is a `bundle` of arbitrary objects, interpreted by the action
    type and by nothing else. astral-go's rule is that an action which does not
    implement `Constrainable` is permitted **regardless** of the constraints
    (`api/auth/action.go`), so constraints on a permit for such an action are
    inert rather than restrictive.

    `delegation` is the number of hops allowed *below* a link carrying this
    permit; 0 is non-delegable. astrald checks `int(p.Delegation) < hopsBelow`
    at every link of the chain and constraints apply at every link too, so
    authority attenuates and never widens (`astrald/mod/auth/src/authorize.go`).
    """

    action: str = wire("Action", Primitive("string8"))
    constraints: Bundle | None = wire("Constraints", Ptr("bundle"))
    delegation: int = wire("Delegation", Primitive("uint8"))

    def allows(self, action: Any) -> bool:
        """Whether this permit covers one concrete action object.

        astral-go's `Permit.Allows`, ported unchanged: the action's object type
        must equal `action`, and an action that declares `apply_constraints` --
        Go's `Constrainable` -- decides the rest for itself. An action type
        that declares no such method is **allowed** whatever the constraints
        say, which is Go's behaviour and is the trap it implies: a new action
        type that forgets the method is unconstrained rather than refused.
        """
        if self.action != getattr(action, "ASTRAL_TYPE", ""):
            return False
        apply = getattr(action, "apply_constraints", None)
        if callable(apply):
            return bool(apply(self.constraints))
        return True


@record("mod.auth.contract")
class Contract:
    """An unsigned authorization grant from one identity to another.

    Field order is the node's own: `Issuer`, `Subject`, `Permits`, `ExpiresAt`,
    read from `objects.get_blueprint?type=mod.auth.contract` on `furry-bolt`
    this session. The zero value's payload is fourteen bytes -- two nil flags, a
    zero count, and eight bytes of timestamp.

    A permit is `None` where the wire carried a nil element: `Permits` is
    `[]*Permit` in Go, whose elements each carry their own nil flag, so absence
    is expressible and is surfaced rather than dropped. A decode this SDK
    accepts must re-encode to the bytes it came from.

    The contract itself is the signing preimage in both schemes: `signable_hash`
    is the ObjectID hash of **this** object and `signable_text` its one-line
    form, so a signature covers the unsigned body and never the signatures
    around it.
    """

    issuer: Identity | None = wire("Issuer", Ptr("identity"))
    subject: Identity | None = wire("Subject", Ptr("identity"))
    permits: list[Permit | None] = wire("Permits", Slice("mod.auth.permit"))
    expires_at: Time = wire("ExpiresAt", Primitive("time"))

    @property
    def expired(self) -> bool:
        """Whether `expires_at` has passed.

        astrald's active-contract query is `expires_at > now`, so an expired
        contract is inert rather than invalid: it stays in the index, verifies
        as before, and authorizes nothing.
        """
        return int(self.expires_at) <= Time.now()

    def has_permit(self, action: Any) -> list[Permit]:
        """Every permit for one action type. astral-go's `Contract.HasPermit`.

        `action` is a type name or an object that carries one. An empty result
        means the contract grants no such permission; it does **not** mean the
        action is refused, because another contract in the chain may grant it.
        """
        name = action if isinstance(action, str) else getattr(action, "ASTRAL_TYPE", "")
        return [p for p in self.permits if p is not None and p.action == name]

    def signable_hash(self) -> bytes:
        """The 32 bytes a hash signature covers. astral-go's `SignableHash`.

        `ResolveObjectID(contract).Hash`, i.e. the content hash of this object's
        canonical form. `crypto.sign_hash` and `crypto.verify_hash_signature`
        take it in hex.
        """
        return object_id(self).hash

    def signable_text(self) -> str:
        """The one line a text signature covers. astral-go's `SignableText`.

        Reproduced verbatim from `api/auth/contract.go`, including the
        parenthesised permit count and the space-separated timestamp, because a
        signature is over the bytes of this string and a difference of one
        character is a signature that never verifies:

            <issuer> grants <subject> permits (<n>) until <YYYY-MM-DD HH:MM:SS>

        An absent identity renders as 66 zeros, which is what Go's
        `(*Identity).String()` returns for a nil receiver. The timestamp is UTC
        and truncated to the second. A contract decoded from binary renders the
        instant its eight bytes encode, which for a Go zero time is
        `1754-08-30 22:43:41` rather than year 1 -- see the module docstring.
        """
        moment = self.expires_at.datetime
        return (
            f"{_identity_text(self.issuer)} grants {_identity_text(self.subject)} "
            f"permits ({len(self.permits)}) until "
            f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d} "
            f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        )


@record("mod.auth.signed_contract")
class SignedContract:
    """A contract with the issuer's and the subject's signatures beside it.

    `contract` is Go's embedded `*Contract`. It is declared as an ordinary
    pointer field rather than through `record.embed`, because the two spellings
    would produce identical bytes and identical JSON here -- the node's own
    blueprint for this type carries `ptr_spec -> mod.auth.contract` under the
    name `Contract`, verified live -- and one field is one thing.

    Attribute lookups do **not** forward into the contract: `signed.issuer` is
    an `AttributeError`, `signed.contract.issuer` is the issuer. The embedded
    pointer is nullable and a forwarding hop through `None` is a worse error
    message than the direct one.

    Either signature may be absent, and both are absent on a contract that has
    only been constructed. `auth.sign_contract` answers with both set or with an
    `error_message`; astrald's index refuses a contract missing either
    (`VerifyIssuer`/`VerifySubject` in `astrald/mod/auth/src/signing.go`).
    """

    contract: Contract | None = wire("Contract", Ptr("mod.auth.contract"))
    issuer_sig: Any = wire("IssuerSig", Ptr("mod.crypto.signature"))
    subject_sig: Any = wire("SubjectSig", Ptr("mod.crypto.signature"))

    @property
    def fully_signed(self) -> bool:
        """Whether both signatures are present.

        The condition astrald's index requires: `contractExists` treats a row
        with either signature empty as not indexed, and `VerifyContract` checks
        both. Presence is not validity -- verification needs the public keys and
        happens on the node.
        """
        return self.issuer_sig is not None and self.subject_sig is not None


# --- the client -----------------------------------------------------------


class Auth(ModuleClient):
    """The `auth` module's two ops, over one `Client`.

    Constructed as `Auth(client)`. The scaffolding and the `**kw` contract are
    `ModuleClient`'s.
    """

    __slots__ = ()

    async def index(self, id: ObjectID | str, **kw: Any) -> None:  # noqa: A002
        """Index a stored signed contract by its object ID. RR. **Mutates.**

        The node loads `id` from its default read repository, refuses anything
        that is not a `mod.auth.signed_contract` with
        `error_message("invalid contract")`, verifies both signatures, and
        stores the row. Idempotent: a contract already in the index returns
        without re-verifying (`astrald/mod/auth/src/contracts.go`).

        `id` is the ID of the **signed** contract, so the object must exist on
        the node first -- `objects.store` puts it there and answers with this
        ID, and `astral.objectid.object_id(signed)` computes the same value
        locally.

        Every failure past the required-argument check arrives as an
        `error_message`, which surfaces as `RemoteError`: object not found,
        invalid contract, a signature that does not verify, a database fault.
        An absent `id` is refused before the op runs and arrives as
        `QueryRejected` instead.

        One ID per call. The batch form the module docstring records is not
        implemented, because no reachable node answers it.
        """
        qs = querystring.build(
            OP_INDEX, querystring.encode_params(_INDEX, {"id": _object_id(id)})
        )
        self._expect(await self._c.call_one(qs, **kw), Ack, OP_INDEX)

    async def sign_contract(self, contract: Contract, **kw: Any) -> SignedContract:
        """Sign a contract as both issuer and subject. WA. **Privileged.**

        **The contract travels on the channel body, not in the query string.**
        That is the single most common way to get an op wrong (design section
        4.7) and this op has no parameters at all, so a caller who reaches for
        one has nowhere to put it.

        The node must hold the private keys of both identities named in the
        contract; it signs as the issuer, then as the subject, and either
        failure is an `error_message` and a `RemoteError` here. It writes
        nothing: the answer is durable only after `objects.store`, and it
        authorizes nothing until `index()`.

        An `eos` terminates the input, because this op's reader breaks on one
        (`channel.BreakOnEOS`). `apphost.sign_app_contract`'s reader does not,
        and sends an `error_message` for the same terminator -- the two ops are
        one name apart and take opposite terminators.

        `expect=1` rather than reading to the stream's end: the answer is one
        object and the op then loops on its own reader until the stream closes,
        so a reader waiting for a terminator would wait for the close it is
        itself supposed to perform.
        """
        if not isinstance(contract, Contract):
            raise BadArgumentType(
                f"{OP_SIGN_CONTRACT}: expected a Contract, got "
                f"{type(contract).__name__}; this op reads the unsigned body and "
                "answers the signed one"
            )
        answers = await self._c.call_with(
            OP_SIGN_CONTRACT, contract, eos=True, expect=1, **kw
        )
        if not answers:
            raise ProtocolError(
                f"{OP_SIGN_CONTRACT}: the stream ended without answering the contract"
            )
        return self._expect(answers[0], SignedContract, OP_SIGN_CONTRACT)


# --- argument discipline --------------------------------------------------


def _object_id(value: ObjectID | str, op: str = OP_INDEX) -> ObjectID:
    """An `object_id.sha256` parameter, naming the op that refused it."""
    return ModuleClient._object_id(value, op)


def _identity_text(value: Identity | None) -> str:
    """An identity as `SignableText` renders it: 66 zeros for an absent one.

    Go's `(*Identity).String()` maps a nil receiver and the zero key to the same
    66 zeros (`astral-go/astral/identity.go:87`), so the signed text cannot
    distinguish them either.
    """
    return Identity.ANYONE.text() if value is None else value.text()


AUTH_TYPES: Final[Sequence[type]] = (Contract, Permit, SignedContract)
"""Every wire type this module declares, for a private-registry sweep.

`Action` is absent because it is a field base rather than a type, and
`mod.auth.sudo_action` because it belongs to astrald.
"""

Auth.TYPES = AUTH_TYPES
