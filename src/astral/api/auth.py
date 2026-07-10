"""The ``auth`` protocol: authorization contracts (sign, index).

Reference: ``protocols/auth/`` and astral-go ``api/auth/`` (``contract.go``,
``signed_contract.go``, ``permit.go``) + ``api/crypto/signature.go``. An
authorization *contract* grants one identity (the issuer) a set of actions on
another's (the subject's) behalf until an expiry; once co-signed by both it
becomes a *signed contract* the node can index and consult when authorizing.

This module lands the typed records the app-contract ops
(``apphost.new_app_contract`` / ``sign_app_contract`` / ``install_app``) return —
a ``mod.auth.contract`` and ``mod.auth.signed_contract`` — plus the two ``auth.*``
ops that operate on them. Via the :class:`~astral.record.Record` base and the
registry, ``Contract`` and ``SignedContract`` now decode over the BINARY channel
(``read_from`` / ``write_to``, dispatched from :func:`astral.payload.decode_payload`)
AND the JSON transports (``from_value``), not only over JSON.

Modelling notes / caveats:

* **Opaque Bundle.** ``Permit.Constraints`` is an ``*astral.Bundle`` — a
  heterogeneous, self-typing container of framed typed objects. It is modelled as
  the OPAQUE ``("bundle",)`` kind (see :mod:`astral.record`): a byte-exact
  passthrough (``uint32`` count then ``bytes32``-framed blobs) that preserves the
  inner objects for round-trip WITHOUT decoding them. A faithful typed decode needs
  the whole Blueprint/registry path and is out of scope here.
* **UnixNano time.** ``ExpiresAt`` is an RFC3339 string over the JSON transports and
  the raw ``time`` integer over binary — nanoseconds since the Unix epoch
  (astral-go's ``astral.Time`` is ``UnixNano``, encoded as a ``uint64``). No
  canonical normalization yet; do not compare ``expires_at`` across transports.
* **Flattened SignedContract JSON.** astral-go marshals ``SignedContract`` with the
  embedded contract's fields FLATTENED to the top level (``Issuer`` / ``Subject`` /
  ``Permits`` / ``ExpiresAt`` alongside ``IssuerSig`` / ``SubjectSig``), not nested
  under a ``"Contract"`` key. :meth:`SignedContract.from_value` accepts both shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Union

from ..objectid import ObjectID
from ..objects import AstralObject
from ..record import Record
from ..registry import register
from .crypto import Signature
from . import Protocol

__all__ = ["Auth", "Permit", "Contract", "SignedContract"]


@register("mod.auth.permit")
@dataclass(frozen=True)
class Permit(Record):
    """A single capability granted by a :class:`Contract` (``mod.auth.permit``).

    Wire type ``mod.auth.permit`` (astral-go ``api/auth/permit.go``): ``Action``
    (string8), ``Constraints`` (``*astral.Bundle``), ``Delegation`` (uint8).
    ``Constraints`` is a nullable pointer to the OPAQUE ``("bundle",)`` — its inner
    objects survive round-trip as raw blobs but are not decoded (see the module
    note); ``None`` means no constraints.
    """

    TYPE = "mod.auth.permit"
    FIELDS = (
        ("action", "Action", "string8"),
        ("constraints", "Constraints", ("ptr", ("bundle",))),
        ("delegation", "Delegation", "uint8"),
    )

    action: str = ""
    constraints: Any = None
    delegation: int = 0


@register("mod.auth.contract")
@dataclass(frozen=True)
class Contract(Record):
    """An unsigned authorization grant (``mod.auth.contract``).

    Wire type ``mod.auth.contract`` (astral-go ``api/auth/contract.go``): ``Issuer``
    (identity), ``Subject`` (identity), ``Permits`` (``[]*Permit``), ``ExpiresAt``
    (time). ``Permits`` is an array of nullable ``Permit`` pointers; ``ExpiresAt`` is
    a UnixNano ``uint64`` over binary / RFC3339 string over JSON (see the module note).
    """

    TYPE = "mod.auth.contract"
    FIELDS = (
        ("issuer", "Issuer", "identity"),
        ("subject", "Subject", "identity"),
        ("permits", "Permits", ("array", ("ptr", ("record", Permit)))),
        ("expires_at", "ExpiresAt", "time"),
    )

    issuer: str = ""
    subject: str = ""
    permits: List[Permit] = field(default_factory=list)
    expires_at: Any = 0


@register("mod.auth.signed_contract")
@dataclass(frozen=True)
class SignedContract(Record):
    """A :class:`Contract` co-signed by its issuer and subject (``mod.auth.signed_contract``).

    Wire type ``mod.auth.signed_contract`` (astral-go ``api/auth/signed_contract.go``):
    an embedded ``*Contract`` plus ``IssuerSig`` / ``SubjectSig`` (``*crypto.Signature``)
    — all three nullable pointers (both signatures absent before signing completes).

    astral-go marshals this with the contract's fields FLATTENED to the top level;
    :meth:`from_value` accepts both that shape and the nested ``{"Contract": {...}}``
    form (and reconstructs the embedded contract when it is flattened).
    """

    TYPE = "mod.auth.signed_contract"
    FIELDS = (
        ("contract", "Contract", ("ptr", ("record", Contract))),
        ("issuer_sig", "IssuerSig", ("ptr", ("record", Signature))),
        ("subject_sig", "SubjectSig", ("ptr", ("record", Signature))),
    )

    contract: Optional[Contract] = None
    issuer_sig: Optional[Signature] = None
    subject_sig: Optional[Signature] = None

    @classmethod
    def from_value(cls, value: Any) -> "SignedContract":
        """Decode from the nested OR the FLATTENED JSON shape (plus binary/passthrough).

        When ``value`` is a ``dict`` without a ``"Contract"`` key, the embedded
        contract's fields are flattened to the top level (astral-go's marshalling),
        so rebuild the ``Contract`` via :meth:`Contract.from_value` on the same dict
        and fold it in under ``"Contract"`` before deferring to the base decoder.
        The nested form and the binary path pass straight through unchanged.
        """
        if isinstance(value, dict) and "Contract" not in value:
            value = {**value, "Contract": Contract.from_value(value).encode_json()}
        return super().from_value(value)


class Auth(Protocol):
    """Typed helpers for the ``auth`` protocol (``sign_contract``, ``index``).

    Grounded in ``protocols/auth/ops/`` and astral-go ``api/auth/`` +
    ``mod/auth/src/``. The two ops differ in how the contract reaches the node:
    ``sign_contract`` streams it on the channel body (its full nested shape must
    round-trip intact), while ``index`` passes an object id as a query arg.
    """

    def sign_contract(self, contract: Any) -> SignedContract:
        """Co-sign an unsigned ``contract`` and return the :class:`SignedContract`.

        The contract is sent on the channel body (not as a query arg) — mirroring
        ``apphost.sign_app_contract`` (astral-go ``Client.SignContract`` +
        ``mod/auth`` ``OpSignContract``): the single ``mod.auth.contract`` object is
        sent and the reply is read, with NO ``eos`` (end-of-input is the reply-read
        and channel close). ``contract`` may be a :class:`Contract` (encoded per the
        transport), a dict (JSON) or raw bytes (binary) — pass it as received.

        The node signs as both the issuer and the subject, so it must hold both
        private keys and neither signature may already be set; otherwise it returns
        an ``error_message``, surfaced here as :class:`~astral.errors.RemoteError`.
        """
        with self.client.query("auth.sign_contract") as stream:
            stream.send(AstralObject("mod.auth.contract", contract))
            return SignedContract.from_value(stream.value())

    def index(self, id: Union[str, ObjectID]) -> None:
        """Index the signed contract stored at object ``id`` into the auth store.

        The node loads the ``mod.auth.signed_contract`` at ``id``, verifies both
        signatures, and indexes it (idempotent), then acks. Raises
        :class:`~astral.errors.RemoteError` on failure (id unknown, wrong type, or a
        signature that does not verify).
        """
        self.client.call_one("auth.index", {"id": str(id)})
