"""The :class:`Stream` returned by accepted queries.

A stream wraps a :class:`~astral.transport.base.Channel`. The caller side comes
from :meth:`Client.query`; the responder side from
:meth:`IncomingQuery.accept`. Both directions exchange objects until an ``eos``
arrives or the channel closes. Some ops (e.g. ``objects.read``) write raw bytes
instead of framed objects — use :meth:`read` for those.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterator, List, Optional

from .messages import Message
from .objects import AstralObject, eos
from .transport.base import Channel

if TYPE_CHECKING:  # avoid an import cycle with the transports
    from .transport.base import Item

__all__ = ["Stream"]


class Stream:
    """A bidirectional object stream over an accepted query."""

    def __init__(
        self,
        channel: Channel,
        *,
        nonce: str = "",
        responder: bool = False,
        transport: Any = None,
    ) -> None:
        self._channel = channel
        self._nonce = nonce
        self._responder = responder
        self._transport = transport
        self._closed = False
        self._ended = False

    @property
    def nonce(self) -> str:
        """The query nonce / id this stream belongs to."""
        return self._nonce

    @property
    def is_responder(self) -> bool:
        """True if this is the responder (server) side of the query."""
        return self._responder

    # -- sending ------------------------------------------------------------
    def send(self, obj: "Item") -> "Stream":
        """Send one object (or control message) on the stream."""
        self._channel.send(obj)
        return self

    def send_object(self, obj_type: str, value: Any = None) -> "Stream":
        """Convenience: send ``AstralObject(obj_type, value)``."""
        return self.send(AstralObject(obj_type, value))

    def send_eos(self) -> "Stream":
        """Send the end-of-stream marker (``eos``)."""
        return self.send(eos())

    def write(self, data: bytes) -> "Stream":
        """Write raw bytes (for ops whose input is an unframed bytestream)."""
        self._channel.send_bytes(data)
        return self

    # -- receiving ----------------------------------------------------------
    def recv(self) -> Optional[AstralObject]:
        """Receive the next object, or ``None`` at end of stream."""
        if self._ended:
            return None
        item = self._channel.recv()
        if item is None:
            self._ended = True
            return None
        if isinstance(item, Message):
            return item.to_object()
        return item

    def read(self, size: int = -1) -> bytes:
        """Read raw bytes from the stream (for unframed-output ops)."""
        return self._channel.recv_bytes(size)

    def __iter__(self) -> Iterator[AstralObject]:
        """Iterate received objects, stopping at ``eos`` or channel close."""
        while True:
            obj = self.recv()
            if obj is None:
                return
            if obj.is_eos:
                self._ended = True
                return
            yield obj

    def objects(self) -> Iterator[AstralObject]:
        """Alias for iterating the stream's objects."""
        return iter(self)

    def results(self) -> Iterator[AstralObject]:
        """Iterate objects, raising :class:`RemoteError` on ``error_message``."""
        for obj in self:
            obj.raise_for_error()
            yield obj

    def collect(self) -> List[AstralObject]:
        """Read every object up to ``eos`` into a list."""
        return list(self)

    def follow(self) -> Iterator[AstralObject]:
        """Iterate a *follow-mode* op's objects across the snapshot separator.

        Follow-mode ops (``tree.get`` with ``follow``, ``services.discover``
        with ``follow``) send an initial snapshot, then a single ``eos`` that
        acts as a snapshot/live *separator* — not a terminator — and then keep
        streaming live updates on the same channel until it closes.

        Unlike :meth:`__iter__` (which stops at the first ``eos`` and marks the
        stream ended), this generator treats that first ``eos`` as a separator:
        it does **not** stop and does **not** end the stream. It keeps yielding
        objects until the channel closes (``recv`` returns ``None``) or the
        caller breaks out. Like :meth:`results`, an ``error_message`` object
        raises :class:`~astral.errors.RemoteError`.

        The snapshot/live boundary is not surfaced here; a caller that needs it
        can drain the snapshot with the default iterator first and then call
        :meth:`follow` for the live tail (``recv`` past the first ``eos`` works
        because this method reads the channel directly rather than through the
        ``_ended`` gate).
        """
        while True:
            item = self._channel.recv()
            if item is None:  # channel closed: end of the follow stream
                self._ended = True
                return
            obj = item.to_object() if isinstance(item, Message) else item
            if obj.is_eos:  # separator, not a terminator — keep reading live updates
                continue
            obj.raise_for_error()
            yield obj

    def value(self) -> Any:
        """Return the value of the first object (raising on ``error_message``).

        Returns ``None`` if the stream is empty.
        """
        for obj in self.results():
            return obj.value
        return None

    def first(self) -> Optional[AstralObject]:
        """Return the first object (raising on ``error_message``), or ``None``."""
        for obj in self.results():
            return obj
        return None

    # -- lifecycle ----------------------------------------------------------
    def cancel(self) -> None:
        """Cancel the in-flight query host-side, then close.

        Routes ``apphost.cancel?id=<nonce>`` over a separate session when a
        transport is available (``topics/astral-ipc.md``); always closes.
        """
        if self._transport is not None and self._nonce:
            try:
                self._transport.query(
                    f"apphost.cancel?id={self._nonce}"
                ).close()
            except Exception:
                pass
        self.close()

    def close(self) -> None:
        """Close the underlying channel. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._channel.close()

    def __enter__(self) -> "Stream":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        side = "responder" if self._responder else "caller"
        return f"Stream({side}, nonce={self._nonce!r})"
