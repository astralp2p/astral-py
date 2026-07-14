"""The ``user`` protocol: the user identity, its node swarm, and its asset list.

Reference: ``protocols/user/`` (README, ``ops/``, ``types/``), astral-go
``api/user/*.go`` + ``api/user/client/*.go``, and the astrald module
``mod/user/src/op_*.go`` (the authoritative wire behaviour). A node belongs to a
user's swarm by holding an active ``mod.user.swarm_membership_action`` contract
issued by that user; once it does it can describe the user (``user.info``),
enumerate the swarm (``user.swarm_status`` / ``user.list_siblings``), keep a
synchronised asset list (``user.assets`` / ``add_asset`` / ``remove_asset`` /
``sync_assets`` / ``sync_with``), and take part in the membership ceremony
(``adopt`` / ``request_membership`` / ``accept_membership`` /
``accept_contract`` / ``expel`` / ``list_expelled`` / ``new_node_contract``).

This module lands the net-new ``user`` records — ``mod.user.info``,
``mod.users.swarm_member`` (note the PLURAL ``users``), ``mod.user.expulsion`` /
``mod.user.signed_expulsion``, and ``mod.user.op_update`` — plus the 15 ops. It
IMPORTS the cross-protocol records it references (``Contract`` /
``SignedContract`` from :mod:`astral.api.auth`, ``Signature`` from
:mod:`astral.api.crypto`) rather than re-registering them. Via the
:class:`~astral.record.Record` base and the registry, every record here decodes
over the binary channel (``read_from`` / ``write_to``, dispatched from
:func:`astral.payload.decode_payload`) AND the JSON transports (``from_value``),
and — being registered — can also be SENT (``encode_payload`` /
``to_json_envelope`` dispatch a :class:`~astral.record.Record`).

Modelling notes / caveats:

* **PLURAL ``users`` in ``mod.users.swarm_member``.** The swarm-member type is
  registered under ``mod.users.swarm_member`` (astral-go
  ``api/user/swarm_member.go`` ``ObjectType()``, and ``user.swarm_status``'s
  streamed type), even though every other ``user`` type is singular
  ``mod.user.*``. This is deliberate, matches the docs, and is pinned by a test.
* **Flattened SignedExpulsion.** astral-go's ``SignedExpulsion`` embeds a
  ``*Expulsion`` and adds ``IssuerSig``; ``astral.Objectify`` flattens the
  embedded struct's fields to the top level over BOTH framings, so the wire /
  JSON layout is ``Issuer`` / ``Subject`` / ``ExpelledAt`` / ``IssuerSig`` (not a
  nested ``Expulsion`` object). :class:`SignedExpulsion` is modelled flattened to
  match; see the docs example.
* **``new_node_contract`` returns an UNSIGNED contract.** The op and the
  astral-go client both return a ``mod.auth.contract`` (``*auth.Contract``) ready
  to be signed — NOT a ``mod.auth.signed_contract``. :meth:`User.new_node_contract`
  therefore returns a :class:`~astral.api.auth.Contract`. (The task brief guessed
  ``SignedContract`` "confirm return type"; the docs + go + astrald op all say
  unsigned, so ``Contract`` is used.)
* **``sync_assets`` non-EOS terminator.** The stream is a sequence of
  ``mod.user.op_update`` objects followed by a BARE ``uint64`` (the next height)
  and NO ``eos`` — astral-go's ``syncAssets`` loops ``Receive()`` and stops when a
  ``*astral.Uint64`` arrives (``mod/user/src/sync.go``). :meth:`sync_assets`
  mirrors that with an explicit ``recv()`` loop; it does NOT use
  ``results()``/``collect()`` (which stop at ``eos``, which never comes).
* **UnixNano time.** ``ExpelledAt`` is an RFC3339 string over the JSON transports
  and a raw ``time`` ``uint64`` over binary (astral-go ``astral.Time`` is
  UnixNano); no canonical normalization yet — do not compare across transports.
* **Reject codes (not hardcoded here).** Several ops reject with a numeric code
  the node maps to an ``error_message`` the SDK surfaces as
  :class:`~astral.errors.RemoteError`; the ops do not hardcode the codes. Per the
  ``ops/`` docs: code ``2`` = no active contract (``info`` / ``swarm_status`` /
  ``list_expelled`` / ``adopt`` / ``expel`` / ``request_membership`` /
  ``sync_assets`` db read; ``accept_membership`` code ``2`` = already has an
  active contract); code ``3`` = caller is not the active contract's issuer
  (``adopt`` / ``expel``); the internal-error code for a failed asset db write
  (``add_asset`` / ``remove_asset``).

Live-node uncertainties (flagged, none exercised against a running node):

* The exact JSON shape of ``mod.user.info`` over a live node — in particular
  whether ``Contract`` is nested (as modelled) or flattened like
  ``mod.auth.signed_contract`` — is unconfirmed.
* Whether ``accept_membership`` emits the subject signature as a
  ``mod.crypto.signature`` OBJECT or the compact ``"scheme:base64"`` TEXT over the
  JSON transports is unconfirmed; :meth:`~astral.api.crypto.Signature.from_value`
  accepts both.
* The ``time`` units / normalization for ``ExpelledAt`` (see above).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Union

from ..objectid import ObjectID
from ..objects import AstralObject
from ..record import Record
from ..registry import register
from .auth import Contract, SignedContract
from .crypto import Signature
from . import Protocol

__all__ = [
    "User",
    "UserInfo",
    "SwarmMember",
    "Expulsion",
    "SignedExpulsion",
    "OpUpdate",
]


@register("mod.user.info")
@dataclass(frozen=True)
class UserInfo(Record):
    """The user configuration this node operates under (``mod.user.info``).

    Wire type ``mod.user.info`` (astral-go ``api/user/info.go``): ``NodeAlias``
    (string8), ``UserAlias`` (string8), ``ContractID`` (``*astral.ObjectID`` — a
    nullable object-id pointer), ``Contract`` (``*auth.SignedContract`` — a
    nullable signed-contract pointer). The active contract the node holds, plus
    the display aliases the node resolves for itself and its user.
    """

    TYPE = "mod.user.info"
    FIELDS = (
        ("node_alias", "NodeAlias", "string8"),
        ("user_alias", "UserAlias", "string8"),
        ("contract_id", "ContractID", ("ptr", "object_id.sha256")),
        ("contract", "Contract", ("ptr", ("record", SignedContract))),
    )

    node_alias: str = ""
    user_alias: str = ""
    contract_id: Optional[ObjectID] = None
    contract: Optional[SignedContract] = None


@register("mod.users.swarm_member")
@dataclass(frozen=True)
class SwarmMember(Record):
    """One node in the user's swarm (``mod.users.swarm_member`` — PLURAL ``users``).

    Wire type ``mod.users.swarm_member`` (astral-go ``api/user/swarm_member.go``
    ``ObjectType()`` returns the PLURAL ``mod.users.swarm_member``; it is the type
    ``user.swarm_status`` streams): ``Identity`` (identity), ``Alias`` (string8,
    empty if unknown), ``Linked`` (bool — a live link exists to this member).
    """

    TYPE = "mod.users.swarm_member"
    FIELDS = (
        ("identity", "Identity", "identity"),
        ("alias", "Alias", "string8"),
        ("linked", "Linked", "bool"),
    )

    identity: str = ""
    alias: str = ""
    linked: bool = False


@register("mod.user.expulsion")
@dataclass(frozen=True)
class Expulsion(Record):
    """The unsigned body of a swarm ban (``mod.user.expulsion``).

    Wire type ``mod.user.expulsion`` (astral-go ``api/user/expulsion.go``):
    ``Issuer`` (identity), ``Subject`` (identity), ``ExpelledAt`` (time). ``Issuer``
    permanently bans ``Subject`` from the swarm; wrap in :class:`SignedExpulsion`
    before storing / propagating. ``ExpelledAt`` is a UnixNano ``uint64`` over
    binary / RFC3339 string over JSON (see the module note).
    """

    TYPE = "mod.user.expulsion"
    FIELDS = (
        ("issuer", "Issuer", "identity"),
        ("subject", "Subject", "identity"),
        ("expelled_at", "ExpelledAt", "time"),
    )

    issuer: str = ""
    subject: str = ""
    expelled_at: Any = 0


@register("mod.user.signed_expulsion")
@dataclass(frozen=True)
class SignedExpulsion(Record):
    """An :class:`Expulsion` paired with the issuer's signature (``mod.user.signed_expulsion``).

    Wire type ``mod.user.signed_expulsion`` (astral-go ``api/user/expulsion.go``):
    a struct that EMBEDS ``*Expulsion`` and adds ``IssuerSig`` (``*crypto.Signature``).
    ``astral.Objectify`` FLATTENS the embedded expulsion's fields to the top level
    over both framings, so the layout is ``Issuer`` / ``Subject`` / ``ExpelledAt`` /
    ``IssuerSig`` — not a nested ``Expulsion`` object (see the docs example and the
    module note). Modelled flattened to match; ``IssuerSig`` is a nullable pointer.
    """

    TYPE = "mod.user.signed_expulsion"
    FIELDS = (
        ("issuer", "Issuer", "identity"),
        ("subject", "Subject", "identity"),
        ("expelled_at", "ExpelledAt", "time"),
        ("issuer_sig", "IssuerSig", ("ptr", ("record", Signature))),
    )

    issuer: str = ""
    subject: str = ""
    expelled_at: Any = 0
    issuer_sig: Optional[Signature] = None


@register("mod.user.op_update")
@dataclass(frozen=True)
class OpUpdate(Record):
    """One entry in the asset operation log streamed by ``user.sync_assets`` (``mod.user.op_update``).

    Wire type ``mod.user.op_update`` (astrald ``mod/user/src/op_sync_assets.go``
    ``OpUpdate``): ``Nonce`` (nonce), ``ObjectID`` (``*astral.ObjectID``),
    ``Removed`` (bool — ``true`` is a tombstone / removal, ``false`` an addition).
    ``ObjectID`` is a plain object id here (not a nullable pointer field over the
    wire the module always sets it), so it is modelled as ``object_id.sha256``.
    """

    TYPE = "mod.user.op_update"
    FIELDS = (
        ("nonce", "Nonce", "nonce64"),
        ("object_id", "ObjectID", "object_id.sha256"),
        ("removed", "Removed", "bool"),
    )

    nonce: str = ""
    object_id: Any = None
    removed: bool = False


class User(Protocol):
    """Typed helpers for the ``user`` protocol (all 15 documented ops).

    Grounded in ``protocols/user/ops/``, astral-go ``api/user/`` +
    ``api/user/client/``, and astrald ``mod/user/src/op_*.go``. Most ops are
    query-arg driven; three depart from that: ``accept_membership`` and
    ``accept_contract`` stream their inputs on the channel body, and
    ``sync_assets`` reads a non-EOS-terminated stream (see the class methods and
    the module note).
    """

    # -- user & swarm info --------------------------------------------------
    def info(self) -> UserInfo:
        """Return this node's :class:`UserInfo` (aliases + active contract).

        Single ``mod.user.info`` object. The caller must be the user (the active
        contract's issuer) or a fellow swarm node; rejected (surfaced as
        :class:`~astral.errors.RemoteError`) with code ``2`` if the node has no
        active contract.
        """
        return UserInfo.from_value(self.client.call_one("user.info"))

    def swarm_status(self) -> List[SwarmMember]:
        """List the swarm's nodes as :class:`SwarmMember`\\ s (alias + link status).

        Streams one ``mod.users.swarm_member`` (PLURAL ``users``) per node, then
        an ``eos``. Rejected with code ``2`` if the node has no active contract.
        """
        return [
            SwarmMember.from_value(obj.value)
            for obj in self.client.call("user.swarm_status")
        ]

    def list_siblings(self, *, zone: Optional[str] = None) -> List[str]:
        """List identities of currently-linked sibling nodes.

        Streams one ``identity`` (a hex public key) per linked sibling, then an
        ``eos``. ``zone`` is an optional zone mask (e.g. ``"n"`` for network)
        included in the enumeration context.
        """
        args = {}
        if zone is not None:
            args["zone"] = zone
        return [obj.value for obj in self.client.call("user.list_siblings", args)]

    def list_expelled(self) -> List[SignedExpulsion]:
        """List the swarm's bans as :class:`SignedExpulsion`\\ s.

        Streams one ``mod.user.signed_expulsion`` per ban issued by the active
        contract's issuer, then an ``eos``. Rejected with code ``2`` if the node
        has no active contract; readable by any caller.
        """
        return [
            SignedExpulsion.from_value(obj.value)
            for obj in self.client.call("user.list_expelled")
        ]

    # -- asset list ---------------------------------------------------------
    def assets(self) -> List[ObjectID]:
        """List the object IDs currently held in the user's asset list.

        Streams one ``object_id`` per asset, then an ``eos``.
        """
        return [obj.value for obj in self.client.call("user.assets")]

    def add_asset(self, id: Union[str, ObjectID]) -> None:
        """Add object ``id`` to the user's asset list (acks).

        The change is logged and a ``mod.user.notification`` (event ``assets``) is
        pushed to linked siblings so they pull it. Rejected with the internal-error
        code if the db write fails.
        """
        self.client.call_one("user.add_asset", {"id": str(id)})

    def remove_asset(self, id: Union[str, ObjectID]) -> None:
        """Remove object ``id`` from the user's asset list (acks).

        Logged as a removal (tombstone) so siblings pick it up via
        ``sync_assets``, and a ``mod.user.notification`` is pushed. Rejected with
        the internal-error code if the db write fails.
        """
        self.client.call_one("user.remove_asset", {"id": str(id)})

    def sync_assets(
        self, *, start: Optional[int] = None
    ) -> Tuple[List[OpUpdate], int]:
        """Pull the asset log from ``start`` (inclusive); return ``(updates, next_height)``.

        NON-EOS STREAM. The node streams zero or more ``mod.user.op_update``
        objects in ascending height order, then a BARE ``uint64`` (the next height
        to pass as ``start``) with NO ``eos`` — astral-go's ``syncAssets`` loops
        ``Receive()`` and stops on the ``*astral.Uint64`` (``mod/user/src/sync.go``).

        So this drives an EXPLICIT ``recv()`` loop rather than ``results()`` /
        ``collect()`` (which would block waiting for an ``eos`` that never comes):
        accumulate every ``mod.user.op_update`` object, and when the bare ``uint64``
        arrives treat its value as ``next_height`` and STOP. If the stream ends
        without a terminator (``recv`` returns ``None`` / an ``eos`` slips in),
        ``next_height`` falls back to ``start or 0`` (matching the node's "no rows
        → echo start" contract). Rejected with code ``2`` if the db read failed.
        """
        args = {}
        if start is not None:
            args["start"] = start
        updates: List[OpUpdate] = []
        next_height = start or 0
        with self.client.query("user.sync_assets", args) as stream:
            while True:
                obj = stream.recv()
                if obj is None or obj.is_eos:
                    # No explicit terminator seen — fall back to start (or 0).
                    break
                obj.raise_for_error()
                if obj.type == "mod.user.op_update":
                    updates.append(OpUpdate.from_value(obj.value))
                    continue
                # A bare uint64 (the next height) terminates the stream.
                next_height = int(obj.value)
                break
        return updates, next_height

    def sync_with(self, node: str, *, start: Optional[int] = None) -> None:
        """Force a one-shot asset sync with sibling ``node`` (acks).

        Triggers this node to pull the asset list from ``node`` by calling
        ``user.sync_assets`` against it. ``node`` is the sibling's identity;
        ``start`` is the optional height to start from (defaults to ``0``).
        """
        args = {"node": str(node)}
        if start is not None:
            args["start"] = start
        self.client.call_one("user.sync_with", args)

    # -- membership ceremony ------------------------------------------------
    def adopt(self, target: str) -> SignedContract:
        """Adopt ``target`` into the swarm; return the issued :class:`SignedContract`.

        ``target`` is an alias or public key. Single ``mod.auth.signed_contract``.
        Rejected with code ``2`` if the node has no active contract, code ``3`` if
        the caller is not the active contract's issuer.
        """
        return SignedContract.from_value(
            self.client.call_one("user.adopt", {"target": target})
        )

    def expel(self, target: str) -> SignedExpulsion:
        """Permanently ban ``target`` from the swarm; return the :class:`SignedExpulsion`.

        ``target`` is an alias or public key; the ban is identity-level and
        irreversible. Single ``mod.user.signed_expulsion``. Rejected with code
        ``2`` if the node has no active contract, code ``3`` if the caller is not
        the active contract's issuer.
        """
        return SignedExpulsion.from_value(
            self.client.call_one("user.expel", {"target": target})
        )

    def new_node_contract(
        self,
        *,
        user: Optional[str] = None,
        node: Optional[str] = None,
        duration: Optional[Union[str, int]] = None,
    ) -> Contract:
        """Build an UNSIGNED node :class:`Contract` granting swarm membership.

        Returns a ``mod.auth.contract`` ready to be signed — NOT a signed contract
        (astral-go ``api/user/client/new_node_contract.go`` returns ``*auth.Contract``;
        astrald ``op_new_node_contract.go`` sends the unsigned contract). ``user``
        (issuer, defaults to this node's user), ``node`` (subject, defaults to the
        local node) and ``duration`` (Go-style, e.g. ``"8760h"``; defaults to one
        year) are all optional. Errors (unresolvable identity, bad duration) surface
        as :class:`~astral.errors.RemoteError`.
        """
        args = {}
        if user is not None:
            args["user"] = user
        if node is not None:
            args["node"] = node
        if duration is not None:
            args["duration"] = duration
        return Contract.from_value(self.client.call_one("user.new_node_contract", args))

    def request_membership(self) -> SignedContract:
        """Request swarm membership for the calling node; return the :class:`SignedContract`.

        Single ``mod.auth.signed_contract`` on approval. Rejected with code ``2``
        if the node has no active contract; the join-request policy may decline the
        caller (surfaced as :class:`~astral.errors.RemoteError`).
        """
        return SignedContract.from_value(
            self.client.call_one("user.request_membership")
        )

    def accept_membership(self, contract: Any, issuer_sig: Any) -> Signature:
        """Accept an inbound membership ``contract``; return the node's subject :class:`Signature`.

        INPUT-BODY op. The query takes NO args; the caller streams the contract and
        the issuer's signature on the channel body, then reads back the node's
        subject signature — astral-go ``api/user/client/accept_membership.go`` sends
        the contract, sends ``issuerSig``, then ``Expect(&subjectSig)``. The node
        emits the subject signature BEFORE it indexes/stores the contract, so it is
        the first (and reply) object; there is NO ``eos``.

        ``contract`` may be a :class:`~astral.api.auth.Contract`, a dict (JSON) or
        raw bytes (binary); ``issuer_sig`` may be a
        :class:`~astral.api.crypto.Signature`, its ``"scheme:base64"`` text, a dict
        or raw bytes. Rejected with code ``2`` if the node already has an active
        contract, or with an ``error_message`` on validation / policy / signing
        failure (surfaced as :class:`~astral.errors.RemoteError`).
        """
        with self.client.query("user.accept_membership") as stream:
            stream.send(AstralObject("mod.auth.contract", contract))
            stream.send(AstralObject("mod.crypto.signature", issuer_sig))
            return Signature.from_value(stream.value())

    def accept_contract(self, contract: Any) -> None:
        """Activate a fully-signed ``contract`` as this node's active contract (acks).

        INPUT-BODY op and the local-setup / cold-card counterpart of
        :meth:`accept_membership`: instead of running the signing handshake, the
        caller streams a contract already signed by BOTH the issuer and the
        subject, and the node validates, stores, and activates it. The query
        takes NO args; the signed contract streams on the channel body (then
        ``eos``) and the node replies with a single ``ack`` — astrald
        ``mod/user/src/op_accept_contract.go`` (``Expect(&signed)`` then
        ``Send(Ack)``), spec ``protocols/user/ops/user.accept_contract.md``. It
        is the setup-time replacement for a raw ``tree.set`` of the
        active-contract path now that that path is a protected op, and rides the
        node's pre-user setup allowlist.

        ``contract`` may be a :class:`~astral.api.auth.SignedContract`, a dict
        (JSON) or raw bytes (binary). Rejected with code ``2`` if the node
        ALREADY has an active contract (claiming a node is a one-time
        transition), or with an ``error_message`` on validation failure — both
        signatures, subject == node, remaining validity, swarm-membership permit
        — surfaced as :class:`~astral.errors.RemoteError`.
        """
        with self.client.query("user.accept_contract") as stream:
            stream.send(AstralObject("mod.auth.signed_contract", contract))
            stream.send_eos()
            stream.value()  # ack, or raises on error_message
