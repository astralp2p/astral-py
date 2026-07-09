"""The ``crypto`` protocol: signing, verification and public-key derivation.

Reference: ``protocols/crypto/``. Signatures and public keys use the compact
text form ``<scheme>:<base64-or-hex>`` over the JSON transports.
"""

from __future__ import annotations

from typing import Optional

from . import Protocol

__all__ = ["Crypto"]


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

    def verify_text_signature(self, text: str, signature: str, key: str) -> bool:
        """Verify ``signature`` over ``text`` for public key ``key``."""
        obj = self.client.call_one(
            "crypto.verify_text_signature",
            {"text": text, "sig": signature, "key": key},
        )
        # The op acks on success; treat any non-error result as valid.
        return obj is None or obj is True or obj == "ack"

    def public_key(self, *, scheme: Optional[str] = None) -> str:
        """Derive the caller's public key (``<scheme>:<hex>``)."""
        args = {}
        if scheme is not None:
            args["scheme"] = scheme
        return self.client.call_one("crypto.public_key", args)
