"""The ``apphost`` protocol: on-device app/agent APIs.

Reference: ``protocols/apphost/``. Covers identity (``whoami``), access-token
issuance (``create_token``) and first-run bootstrap (``register``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Union

from ..record import Record
from ..registry import register
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
    ``time`` integer over the binary transport (the ``time`` common type encodes as
    a ``uint64``, as assumed in :mod:`astral.payload`); a canonical normalization
    is deferred until the ``time`` units are confirmed against a live node.
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
