"""The ``dir`` protocol: resolve identities by name/alias and manage aliases.

Reference: ``protocols/dir/``.
"""

from __future__ import annotations

from typing import Optional

from . import Protocol

__all__ = ["Dir"]


class Dir(Protocol):
    def resolve(self, name: str) -> str:
        """Resolve ``name`` (hex pubkey or alias) to an identity hex string."""
        return self.client.call_one("dir.resolve", {"name": name})

    def get_alias(self, identity: str) -> Optional[str]:
        """Return the alias of ``identity``, or ``None`` if it has none."""
        return self.client.call_one("dir.get_alias", {"id": identity})

    def set_alias(self, identity: str, alias: Optional[str] = None) -> None:
        """Set ``alias`` for ``identity`` (omit ``alias`` to remove it)."""
        args = {"id": identity}
        if alias is not None:
            args["alias"] = alias
        self.client.call_one("dir.set_alias", args)
