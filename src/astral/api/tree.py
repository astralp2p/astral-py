"""The ``tree`` protocol: a hierarchical key-value configuration store.

Reference: ``protocols/tree/`` and astral-go ``mod/tree/`` (``client/node.go``,
``server.go``, ``module.go``). Values are arbitrary typed objects stored at
slash-separated paths (e.g. ``/mod/tcp/settings/listen``); modules use the tree
to expose and persist their settings. The complete documented op surface:
``get`` (one-shot and ``follow``), ``set``, ``list``, ``delete``,
``mount_remote``, and ``unmount``.

The tree defines no custom wire types: ``list`` streams bare ``string8`` child
names, and ``get``/``set`` carry arbitrary registered typed objects as generic
:class:`~astral.objects.AstralObject`, so this module registers no records.

``set`` streams an input object on the channel body, so it needs a
bidirectional transport (binary or WebSocket); the same is true of ``follow``,
which stays open to stream updates. The args-only ops (``list``, ``delete``,
``mount_remote``, ``unmount``) and one-shot ``get`` work on every transport.
"""

from __future__ import annotations

from typing import Any, Iterator, List, Optional

from ..objects import AstralObject
from . import Protocol

__all__ = ["Tree"]


class Tree(Protocol):
    """Typed helpers for the ``tree`` protocol (all 6 documented ops)."""

    # -- reads --------------------------------------------------------------
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
        """Stream the value at ``path`` and subsequent updates (stays open).

        A FOLLOW-MODE op: the node sends an initial snapshot, then a single
        ``eos`` acting as a snapshot/live *separator* (not a terminator), then
        keeps streaming updates as the value changes until the channel closes
        (astral-go ``Node.Get`` with ``follow`` — its ``Switch``/``BreakOnEOS``
        loop emitting successive updates). Drains via :meth:`Stream.follow`,
        which reads across that separator. Needs a transport that stays open
        (binary or WebSocket; effectively unusable over http).
        """
        with self.client.query("tree.get", {"path": path, "follow": True}) as stream:
            yield from stream.follow()

    def list(self, path: str = "/") -> List[str]:
        """List the child key names at ``path`` (defaults to the root)."""
        return [obj.value for obj in self.client.call("tree.list", {"path": path})]

    # -- writes -------------------------------------------------------------
    def set(self, path: str, value: AstralObject) -> None:
        """Store typed ``value`` at ``path`` (requires a streaming transport).

        The value travels on the channel INPUT stream, not as a query arg: the
        op opens ``tree.set?path=<path>``, streams ``value`` then ``eos``, and
        awaits the ``ack`` (astral-go ``NodeOps.setBatch``). Requires a
        bidirectional/serving transport (binary or WebSocket); http cannot
        stream input.
        """
        with self.client.query("tree.set", {"path": path}) as stream:
            stream.send(value)
            stream.send_eos()
            stream.value()  # ack, or raises on error_message

    def delete(self, path: str, *, recursive: bool = False) -> None:
        """Delete the value at ``path``.

        When ``recursive`` is true the node and all of its subnodes are deleted
        depth-first, leaves up (astral-go ``DeleteArgs.Recursive`` /
        ``deleteRecursive``). The wire arg is lowercase ``recursive`` and is
        sent only when true.
        """
        args = {"path": path}
        if recursive:
            args["recursive"] = True
        self.client.call_one("tree.delete", args)

    # -- remote mounts ------------------------------------------------------
    def mount_remote(
        self, path: str, target: str, *, root: Optional[str] = None
    ) -> None:
        """Mount a remote node's tree subtree at a local ``path``.

        ``target`` is the identity (or alias) of the remote node to mount from;
        ``root`` is the path on the remote node to use as the mount root and
        defaults to ``/`` when omitted. Acks on success, otherwise raises
        :class:`~astral.errors.RemoteError`.
        """
        args = {"path": path, "target": target}
        if root is not None:
            args["root"] = root
        self.client.call_one("tree.mount_remote", args)

    def unmount(self, path: str) -> None:
        """Unmount a previously mounted remote subtree from a local ``path``.

        Acks on success; raises :class:`~astral.errors.RemoteError` if the path
        is not mounted or on error.
        """
        self.client.call_one("tree.unmount", {"path": path})
