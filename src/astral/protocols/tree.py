"""The ``tree`` protocol: a hierarchical key-value configuration store.

Reference: ``protocols/tree/``. ``set`` streams an input object, so it needs a
bidirectional transport (binary or WebSocket).
"""

from __future__ import annotations

from typing import Any, Iterator, List

from ..objects import AstralObject
from . import Protocol

__all__ = ["Tree"]


class Tree(Protocol):
    def get(self, path: str) -> Any:
        """Get the value stored at ``path`` (raises if it does not exist)."""
        return self.client.call_one("tree.get", {"path": path})

    def get_object(self, path: str) -> AstralObject:
        """Like :meth:`get` but return the full typed :class:`AstralObject`."""
        with self.client.query("tree.get", {"path": path}) as stream:
            obj = stream.first()
            if obj is None:
                raise KeyError(path)
            return obj

    def follow(self, path: str) -> Iterator[AstralObject]:
        """Stream the value at ``path`` and subsequent updates (stays open)."""
        with self.client.query("tree.get", {"path": path, "follow": True}) as stream:
            yield from stream.results()

    def list(self, path: str = "/") -> List[str]:
        """List the child key names at ``path``."""
        return [obj.value for obj in self.client.call("tree.list", {"path": path})]

    def set(self, path: str, value: AstralObject) -> None:
        """Store typed ``value`` at ``path`` (requires a streaming transport)."""
        with self.client.query("tree.set", {"path": path}) as stream:
            stream.send(value)
            stream.send_eos()
            stream.value()  # ack, or raises on error_message

    def delete(self, path: str) -> None:
        """Delete the value at ``path``."""
        self.client.call_one("tree.delete", {"path": path})
