"""The ``dir`` protocol: resolve identities by name/alias and manage aliases.

Reference: ``protocols/dir/``.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Union

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
        """Set ``alias`` for ``identity`` (omit ``alias`` to remove it).

        Passing ``alias=""`` (the empty string) also removes the alias: the empty
        string is forwarded as the ``alias`` arg, whereas ``None`` omits the arg
        entirely. The ``if alias is not None`` guard below draws that line.
        """
        args = {"id": identity}
        if alias is not None:
            args["alias"] = alias
        self.client.call_one("dir.set_alias", args)

    def alias_map(self) -> Any:
        """Return the complete alias-to-identity mapping.

        Returns UNTYPED: the ``mod.dir.alias_map`` object's ``Aliases`` map field
        is not expressible by the scalar record codec yet. Over the JSON transports
        the value is a dict ``{"Aliases": {alias: identity_hex}}`` — this returns
        the inner ``Aliases`` dict (``{}`` if absent). Over binary the value is the
        raw ``mod.dir.alias_map`` payload bytes, returned as received.

        TODO(dir): typed AliasMap once a map-kind record codec lands.
        """
        val = self.client.call_one("dir.alias_map")
        if isinstance(val, dict):
            return val.get("Aliases", {})
        return val

    def apply_filters(
        self,
        filters: Union[str, Sequence[str]],
        identity: Optional[str] = None,
    ) -> bool:
        """Test ``identity`` against the named server-side filters.

        ``filters`` is a single comma-separated string or a sequence of filter
        names (joined with commas). ``identity`` defaults to the caller when
        ``None``. Returns ``True`` if any named filter matches, ``False`` otherwise.

        The op string is ``dir.apply_filters`` — note the astral-go client
        (``api/dir/client/apply_filters.go``) queries ``dir.set_alias`` here, a
        confirmed bug; the args are grounded in
        ``protocols/dir/ops/dir.apply_filters.md``.
        """
        if not isinstance(filters, str):
            filters = ",".join(filters)
        args = {"filters": filters}
        if identity is not None:
            args["id"] = identity
        return self.client.call_one("dir.apply_filters", args)

    def filters(self) -> List[str]:
        """Return the names of all registered identity filters.

        The op streams one ``string8`` filter name per object, terminating in
        ``eos``.
        """
        return [o.value for o in self.client.call("dir.filters")]
