"""The ``crypto`` protocol: signing, verification and public-key derivation.

Reference: ``protocols/crypto/``. Signatures, public keys and hashes are opaque
text tokens of the form ``<scheme>:<base64-or-hex>`` (astral-go's
``mod.crypto.signature`` / ``mod.crypto.public_key`` text encodings); this module
passes them straight through as strings — no records, no ``@register``.

Two caveats apply to every op here:

* **Untested against a live node.** These helpers are written from the op docs
  (``protocols/crypto/ops/``) and the astral-go/astrald sources; none has been
  exercised against a running node, so the exact ack/error shapes are unconfirmed.
* **Query-arg mode only.** Each helper drives the op through query arguments,
  which selects a signer/verifier *key the node already holds* (defaulting to the
  caller's identity). It cannot derive a key from an external private key: that
  requires astral-go's streamed-input mode (send a ``mod.crypto.public_key`` on the
  channel body, then the hash/text/signature), a separate future path not yet
  wired here.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Optional

from ..record import Record
from ..registry import register
from . import Protocol

__all__ = ["Crypto", "Signature"]


@register("mod.crypto.signature")
@dataclass(frozen=True)
class Signature(Record):
    """A ``mod.crypto.signature`` object: a scheme tag plus opaque signature bytes.

    Wire type ``mod.crypto.signature`` (astral-go ``api/crypto/signature.go``):
    ``Scheme`` (string8), ``Data`` (bytes16). Via the :class:`~astral.record.Record`
    base and the registry it decodes over the binary channel (``read_from`` /
    ``write_to``) and the JSON transports (``from_value``) alike.

    JSON ambiguity (flagged): a signature also has a compact TEXT form
    ``"<scheme>:<base64>"`` — the same token the ``crypto`` string helpers pass
    through. :meth:`from_value` therefore accepts BOTH the object form
    (``{"Scheme": ..., "Data": ...}``) AND that plain ``str`` (split on the first
    ``":"``, base64-decode the tail). Which form an op emits over JSON is
    UNCONFIRMED against a live node.
    """

    TYPE = "mod.crypto.signature"
    FIELDS = (
        ("scheme", "Scheme", "string8"),
        ("data", "Data", ("bytes", 16)),
    )

    scheme: str = ""
    data: bytes = b""

    @classmethod
    def from_value(cls, value: Any) -> "Signature":
        """Decode a signature from the object form OR the ``"scheme:base64"`` text.

        Adds the compact-text case to the base :meth:`Record.from_value` (dict /
        binary / passthrough): a plain ``str`` is split on the first ``":"`` and its
        tail base64-decoded into :attr:`data` (an empty/``":"``-less string yields an
        empty signature). Everything else defers to the base decoder.
        """
        if isinstance(value, str):
            scheme, sep, b64 = value.partition(":")
            return cls(scheme=scheme if sep else "", data=base64.b64decode(b64) if b64 else b"")
        return super().from_value(value)


class Crypto(Protocol):
    def sign_text(
        self,
        text: str,
        *,
        key: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> str:
        """Sign ``text`` with a node-held key; returns ``<scheme>:<sig>``."""
        args = {"text": text}
        if key is not None:
            args["key"] = key
        if scheme is not None:
            args["scheme"] = scheme
        return self.client.call_one("crypto.sign_text", args)

    def sign_hash(
        self,
        hash: str,
        *,
        key: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> str:
        """Sign hex ``hash`` with a node-held key; returns ``<scheme>:<sig>``.

        Unlike :meth:`sign_text` (whose scheme defaults to ``bip137``), the node
        defaults this op's scheme to ``asn1``; we send ``scheme`` only when the
        caller passes it, letting that server-side default stand. Unconfirmed:
        untested against a live node (see the module note).
        """
        args = {"hash": hash}
        if key is not None:
            args["key"] = key
        if scheme is not None:
            args["scheme"] = scheme
        return self.client.call_one("crypto.sign_hash", args)

    def verify_text_signature(self, text: str, signature: str, key: str) -> bool:
        """Verify ``signature`` over ``text`` for public key ``key``."""
        obj = self.client.call_one(
            "crypto.verify_text_signature",
            {"text": text, "sig": signature, "key": key},
        )
        # The op acks on success; treat any non-error result as valid.
        return obj is None or obj is True or obj == "ack"

    def verify_hash_signature(self, hash: str, sig: str, key: str) -> bool:
        """Verify ``sig`` over hex ``hash`` for public key ``key``."""
        obj = self.client.call_one(
            "crypto.verify_hash_signature",
            {"hash": hash, "sig": sig, "key": key},
        )
        # The op acks on success; treat any non-error result as valid.
        return obj is None or obj is True or obj == "ack"

    def public_key(self, *, scheme: Optional[str] = None) -> str:
        """Derive the caller's public key (``<scheme>:<hex>``)."""
        args = {}
        if scheme is not None:
            args["scheme"] = scheme
        return self.client.call_one("crypto.public_key", args)
