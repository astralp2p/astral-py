"""The ``apphost`` protocol: on-device app/agent APIs.

Reference: ``protocols/apphost/``. Covers identity (``whoami``), access-token
issuance (``create_token``) and first-run bootstrap (``register``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Union

from ..errors import ProtocolError
from . import Protocol

__all__ = ["Apphost", "AccessToken"]


@dataclass(frozen=True)
class AccessToken:
    """An access token issued by the host for a guest identity."""

    identity: str
    token: str
    expires_at: str = ""

    @classmethod
    def from_value(cls, value: Any) -> "AccessToken":
        if not isinstance(value, dict):
            raise ProtocolError(
                "access token was not decoded as a structured object; "
                "use a JSON transport (ws:// or http://) for apphost token ops"
            )
        return cls(
            identity=value.get("Identity", ""),
            token=value.get("Token", ""),
            expires_at=value.get("ExpiresAt", ""),
        )


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
