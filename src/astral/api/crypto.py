"""The ``crypto`` protocol: signing, verification and public-key derivation.

Reference: ``protocols/crypto/`` + astral-go ``api/crypto`` + astrald
``mod/crypto/src/op_*.go``. Signatures, public keys and private keys are the
records ``mod.crypto.signature`` / ``mod.crypto.public_key`` /
``mod.crypto.private_key`` (each ``{Type, Key}``), each with a compact
``"<scheme>:<hex-or-base64>"`` text form.

Two input styles, matching the astrald ops:

* ``sign_text`` / ``sign_hash`` are QUERY-ARG driven: ``text`` / ``hash`` (and
  optional ``key`` / ``scheme``) ride as query args; the node signs with a key it
  holds and replies with a ``mod.crypto.signature``.
* ``verify_*`` and ``public_key`` STREAM their key material on the channel body.
  The astrald op reads a streamed ``mod.crypto.signature`` (verify) or
  ``mod.crypto.private_key`` (public_key) via ``ch.Switch`` — there is NO ``sig``
  query arg and ``public_key`` takes no key/scheme arg — so the value must be sent
  on the stream (astral-go ``api/crypto/client``). Sending the signature as a query
  arg (the old form here, and in astral-js) silently never verifies.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Optional

from ..objects import AstralObject
from ..record import Record
from ..registry import register
from . import Protocol

__all__ = ["Crypto", "Signature", "PublicKey", "PrivateKey"]


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

    @property
    def text(self) -> str:
        """The ``"<scheme>:<base64>"`` text form (astral-go ``Signature.MarshalText``)."""
        return f"{self.scheme}:{base64.b64encode(bytes(self.data)).decode('ascii')}"

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


@register("mod.crypto.public_key")
@dataclass(frozen=True)
class PublicKey(Record):
    """A ``mod.crypto.public_key``: a key-scheme tag plus the key bytes.

    Wire type ``mod.crypto.public_key`` (astral-go ``api/crypto/public_key.go``):
    ``Type`` (string8, the scheme e.g. ``secp256k1``), ``Key`` (bytes16). The
    compact TEXT form is ``"<type>:<hex>"`` — note ``MarshalText`` uses HEX, unlike
    the private key's base64. :meth:`from_value` accepts the object form
    (``{"Type", "Key"}``) AND that text; :attr:`text` renders it.
    """

    TYPE = "mod.crypto.public_key"
    FIELDS = (
        ("type", "Type", "string8"),
        ("key", "Key", ("bytes", 16)),
    )

    type: str = ""
    key: bytes = b""

    @property
    def text(self) -> str:
        """The ``"<type>:<hex>"`` text form (astral-go ``PublicKey.MarshalText``)."""
        return f"{self.type}:{bytes(self.key).hex()}"

    @classmethod
    def from_value(cls, value: Any) -> "PublicKey":
        """Decode from the object form OR the ``"<type>:<hex>"`` text."""
        if isinstance(value, str):
            scheme, sep, hexed = value.partition(":")
            return cls(type=scheme if sep else "", key=bytes.fromhex(hexed) if hexed else b"")
        return super().from_value(value)


@register("mod.crypto.private_key")
@dataclass(frozen=True)
class PrivateKey(Record):
    """A ``mod.crypto.private_key``: a key-scheme tag plus the key bytes.

    Wire type ``mod.crypto.private_key`` (astral-go ``api/crypto/private_key.go``):
    ``Type`` (string8), ``Key`` (bytes16). The compact TEXT form is
    ``"<type>:<base64>"`` — ``MarshalText`` uses BASE64, unlike the public key's hex.
    :meth:`from_value` accepts the object form AND that text; :attr:`text` renders
    it. Streamed to ``crypto.public_key`` to derive the matching public key.
    """

    TYPE = "mod.crypto.private_key"
    FIELDS = (
        ("type", "Type", "string8"),
        ("key", "Key", ("bytes", 16)),
    )

    type: str = ""
    key: bytes = b""

    @property
    def text(self) -> str:
        """The ``"<type>:<base64>"`` text form (astral-go ``PrivateKey.MarshalText``)."""
        return f"{self.type}:{base64.b64encode(bytes(self.key)).decode('ascii')}"

    @classmethod
    def from_value(cls, value: Any) -> "PrivateKey":
        """Decode from the object form OR the ``"<type>:<base64>"`` text."""
        if isinstance(value, str):
            scheme, sep, b64 = value.partition(":")
            return cls(type=scheme if sep else "", key=base64.b64decode(b64) if b64 else b"")
        return super().from_value(value)


class Crypto(Protocol):
    def sign_text(
        self,
        text: str,
        *,
        key: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> str:
        """Sign ``text`` with a node-held key; returns ``<scheme>:<sig>``.

        Query-arg driven (astrald ``op_sign_text.go``): ``text`` (and optional
        ``key`` / ``scheme``, scheme defaulting server-side to ``bip137``) ride as
        args. The node replies with a ``mod.crypto.signature`` OBJECT (astrald
        ``ch.Send(sig)``), rendered here as its ``"<scheme>:<base64>"`` text.
        """
        args = {"text": text}
        if key is not None:
            args["key"] = key
        if scheme is not None:
            args["scheme"] = scheme
        return Signature.from_value(self.client.call_one("crypto.sign_text", args)).text

    def sign_hash(
        self,
        hash: str,
        *,
        key: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> str:
        """Sign hex ``hash`` with a node-held key; returns ``<scheme>:<sig>``.

        As :meth:`sign_text` but the node defaults this op's scheme to ``asn1``
        (astrald ``op_sign_hash.go``); we send ``scheme`` only when the caller
        passes it, letting that server-side default stand. The reply is a
        ``mod.crypto.signature`` object, rendered as its ``"<scheme>:<base64>"`` text.
        """
        args = {"hash": hash}
        if key is not None:
            args["key"] = key
        if scheme is not None:
            args["scheme"] = scheme
        return Signature.from_value(self.client.call_one("crypto.sign_hash", args)).text

    def verify_text_signature(
        self, text: str, signature: str, key: Optional[str] = None
    ) -> bool:
        """Verify ``signature`` over ``text``; ``True`` iff the node acks it valid.

        The op reads the signature on the CHANNEL BODY (astrald
        ``op_verify_text_signature.go`` ``ch.Switch`` on ``crypto.Signature``), NOT
        as a query arg, then replies ``ack`` (valid) or an ``error_message`` (an
        invalid signature, or missing text/key). ``text`` and ``key`` ride as query
        args; ``key`` defaults server-side to the caller's identity when omitted.

        Returns ``False`` on any non-ack reply — a mismatched signature is a normal
        ``False``, not an exception (mirrors astral-js ``verifyTextSignature``).
        """
        args = {"text": text}
        if key is not None:
            args["key"] = key
        with self.client.query("crypto.verify_text_signature", args) as stream:
            stream.send(AstralObject("mod.crypto.signature", Signature.from_value(signature)))
            reply = stream.recv()
            return reply is not None and reply.is_ack

    def verify_hash_signature(
        self, hash: str, sig: str, key: Optional[str] = None
    ) -> bool:
        """Verify ``sig`` over hex ``hash``; ``True`` iff the node acks it valid.

        As :meth:`verify_text_signature` but for a hash (astrald
        ``op_verify_hash_signature.go``): the signature streams on the channel body;
        ``hash`` / ``key`` ride as query args. Returns ``False`` on any non-ack reply.
        """
        args = {"hash": hash}
        if key is not None:
            args["key"] = key
        with self.client.query("crypto.verify_hash_signature", args) as stream:
            stream.send(AstralObject("mod.crypto.signature", Signature.from_value(sig)))
            reply = stream.recv()
            return reply is not None and reply.is_ack

    def public_key(self, private_key: Any) -> str:
        """Derive the public key for ``private_key`` (returns ``"<type>:<hex>"``).

        The op takes NO key/scheme query arg: the caller streams a
        ``mod.crypto.private_key`` on the channel body and the node replies with the
        matching ``mod.crypto.public_key`` (astrald ``op_public_key.go``; astral-go
        ``api/crypto/client/public_key.go`` sends the private key then
        ``Expect(&publicKey)``). ``private_key`` may be a :class:`PrivateKey`, its
        ``"<type>:<base64>"`` text, or the object form. Node-side errors surface as
        :class:`~astral.errors.RemoteError`.
        """
        with self.client.query("crypto.public_key") as stream:
            stream.send(
                AstralObject("mod.crypto.private_key", PrivateKey.from_value(private_key))
            )
            return PublicKey.from_value(stream.value()).text
