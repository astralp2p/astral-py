"""The ``apphost`` protocol: on-device app/agent APIs.

Reference: ``protocols/apphost/``. The complete documented op surface: identity
(``whoami``), access tokens (``create_token``, ``register``, ``list_tokens``),
query cancellation (``cancel``), object holds (``hold_object``,
``unhold_object``, ``list_held_objects``), app contracts (``new_app_contract``,
``sign_app_contract``, ``install_app``), and handler registration
(``register_handler``, ``bind``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Union

from ..errors import NotSupported
from ..objectid import ObjectID
from ..objects import AstralObject
from ..record import Record
from ..registry import register
from ..stream import Stream
from . import Protocol

__all__ = ["Apphost", "AccessToken"]


@register("apphost.access_token")
@dataclass(frozen=True)
class AccessToken(Record):
    """An access token issued by the host for a guest identity.

    Wire type ``apphost.access_token`` (astral-go ``api/apphost/access_token.go``):
    ``Identity`` (identity), ``Token`` (string8), ``ExpiresAt`` (time). Via the
    :class:`~astral.record.Record` base and the registry it now decodes over the
    binary channel too, not only over the JSON transports.

    Note: ``expires_at`` is an RFC3339 string over the JSON transports and the raw
    ``time`` integer over the binary transport — nanoseconds since the Unix epoch
    (astral-go's ``astral.Time`` is ``UnixNano``; the ``time`` common type encodes
    as a ``uint64``). A canonical normalization is deferred to when the record layer
    grows a typed time; until then a caller must not compare ``expires_at`` across
    transports.
    """

    TYPE = "apphost.access_token"
    FIELDS = (
        ("identity", "Identity", "identity"),
        ("token", "Token", "string8"),
        ("expires_at", "ExpiresAt", "time"),
    )

    identity: str = ""
    token: str = ""
    expires_at: Any = ""


class Apphost(Protocol):
    """Typed helpers for the ``apphost`` protocol (all 13 documented ops)."""

    # -- identity & access tokens -------------------------------------------
    def whoami(self) -> str:
        """Return the caller's identity as authenticated by the host."""
        return self.client.call_one("apphost.whoami")

    def create_token(
        self, identity: str, *, duration: Optional[Union[str, int]] = None
    ) -> AccessToken:
        """Create an access token authenticating ``identity``."""
        args = {"id": identity}
        if duration is not None:
            args["duration"] = duration
        return AccessToken.from_value(self.client.call_one("apphost.create_token", args))

    def register(self) -> AccessToken:
        """Provision a fresh guest identity and return its access token.

        Bootstraps an app/agent on first run (new keypair + app contract +
        token).
        """
        return AccessToken.from_value(self.client.call_one("apphost.register"))

    def list_tokens(self, identity: Optional[str] = None) -> List[AccessToken]:
        """List access tokens, optionally filtered to ``identity``.

        Streams ``apphost.access_token`` objects; each decodes to an
        :class:`AccessToken` over binary (via the registry) and JSON alike.
        """
        args = {}
        if identity is not None:
            args["id"] = identity
        return [
            AccessToken.from_value(obj.value)
            for obj in self.client.call("apphost.list_tokens", args)
        ]

    def cancel(self, id: str, *, cause: Optional[str] = None) -> None:
        """Cancel the in-flight query with nonce ``id``; ``cause`` is optional.

        Routed over a fresh session (not the cancelled query's channel).
        """
        args = {"id": id}
        if cause is not None:
            args["cause"] = cause
        self.client.call_one("apphost.cancel", args)

    # -- object holds -------------------------------------------------------
    def hold_object(
        self, id: Union[str, ObjectID], *, duration: Optional[Union[str, int]] = None
    ) -> None:
        """Pin an object so the node keeps it (local-only op).

        ``duration`` is documented but not sent by the astral-go client; it is
        forwarded here and untested against a live node.
        """
        args = {"id": str(id)}
        if duration is not None:
            args["duration"] = duration
        self.client.call_one("apphost.hold_object", args)

    def unhold_object(self, id: Union[str, ObjectID]) -> None:
        """Release a hold placed by :meth:`hold_object` (local-only op)."""
        self.client.call_one("apphost.unhold_object", {"id": str(id)})

    def list_held_objects(self) -> List[ObjectID]:
        """List the object IDs currently held (local-only op)."""
        return [obj.value for obj in self.client.call("apphost.list_held_objects")]

    # -- app contracts ------------------------------------------------------
    # These return mod.auth.* objects with nested/array fields the scalar record
    # codec cannot yet express, so they are returned untyped for now: a dict over
    # the JSON transports, raw bytes over binary. The untyped value is opaque and
    # transport-bound — pass it back (e.g. into sign_app_contract) on the same
    # transport it came from. new_app_contract yields an UNSIGNED mod.auth.contract;
    # sign_app_contract and install_app yield a SIGNED mod.auth.signed_contract.
    # TODO(auth): return typed Contract / SignedContract records once api/auth.py
    # and the nested/array FIELDS codec land.
    def new_app_contract(
        self, identity: str, *, duration: Optional[Union[str, int]] = None
    ) -> Any:
        """Create an unsigned app contract for ``identity``.

        Returns the ``mod.auth.contract`` as received (dict over JSON, bytes over
        binary) — see the module note on the deferred typed record.
        """
        args = {"id": identity}
        if duration is not None:
            args["duration"] = duration
        return self.client.call_one("apphost.new_app_contract", args)

    def sign_app_contract(self, contract: Any) -> Any:
        """Sign an app ``contract`` and return the signed contract.

        ``contract`` is sent on the channel body (not as a query arg); pass it
        back as received from :meth:`new_app_contract` **on the same transport**
        (the untyped value is transport-bound). Returns the
        ``mod.auth.signed_contract`` untyped (dict over JSON, bytes over binary).

        Like the astral-go client (``api/apphost/client/sign_app_contract.go``),
        the single contract object is sent and then the reply is read — no ``eos``
        is sent; end-of-input is the reply-read and channel close.
        """
        with self.client.query("apphost.sign_app_contract") as stream:
            stream.send(AstralObject("mod.auth.contract", contract))
            return stream.value()

    def install_app(
        self, identity: str, *, duration: Optional[Union[str, int]] = None
    ) -> Any:
        """Install an app for ``identity`` (local-only op), returning its signed
        contract untyped (dict over JSON, bytes over binary)."""
        args = {"id": identity}
        if duration is not None:
            args["duration"] = duration
        return self.client.call_one("apphost.install_app", args)

    # -- handler registration ----------------------------------------------
    def register_handler(self, endpoint: str, token: str) -> None:
        """Register a host-side callback that dials ``endpoint`` for inbound
        queries, presenting ``token`` as the callback auth token.

        This registers the host side only: the guest must already be serving an
        IPC listener at ``endpoint`` (e.g. ``tcp:127.0.0.1:9001``) that speaks
        ``mod.apphost.handle_query_msg``. This SDK does not yet provide that
        listener — for serving today, use
        :meth:`~astral.client.Client.register` / ``serve`` (the register-service
        model). Pair with :meth:`bind` to scope the handler's lifetime.
        """
        self.client.call_one(
            "apphost.register_handler", {"endpoint": endpoint, "token": token}
        )

    def bind(self, token: str) -> Stream:
        """Open an ``apphost.bind`` session scoping the lifetime of handlers
        registered (via :meth:`register_handler`) with ``token``.

        Returns a live :class:`~astral.stream.Stream`; **keep it open** — closing
        it removes those handlers. Requires a serving transport (binary or ws).
        """
        if not self.client.supports_serving:
            raise NotSupported("apphost.bind requires a serving transport (binary or ws)")
        return self.client.transport.bind(token)
