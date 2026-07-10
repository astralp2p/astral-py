"""The ``services`` protocol: service-availability discovery and sync.

Reference: ``protocols/services/`` and astral-go ``api/services/`` (``update.go``,
``module.go``, ``client/services.go``). A *service update* announces that a named
service, offered by some provider, has become available or been withdrawn on the
node's view of the swarm. The two documented ops both revolve around that single
wire record:

* ``services.discover`` streams the current ``services.update`` snapshot, and —
  in follow mode — keeps the channel open and delivers live updates as they occur.
* ``services.sync`` fetches and stores a remote identity's advertisements into the
  local registry, acking on success.

Via the :class:`~astral.record.Record` base and the registry, :class:`ServiceUpdate`
decodes over the BINARY channel (``read_from`` / ``write_to``, dispatched from
:func:`astral.payload.decode_payload`) AND the JSON transports (``from_value``);
importing this module fires the ``@register`` decorator that makes it so.

Modelling notes / caveats:

* **Follow has two eos semantics across the ONE discover op.** In snapshot mode
  (``follow=False``) the ``eos`` after the snapshot is a TERMINATOR — the channel
  closes and :meth:`Services.discover` returns the collected list. In follow mode
  (``follow=True``) that first ``eos`` is a snapshot/live SEPARATOR: the channel
  stays open and live updates keep flowing (astral-go ``client/services.go`` marks
  the boundary with a nil sentinel). To keep the two apart, this SDK exposes them
  as two methods — :meth:`Services.discover` (snapshot list) and
  :meth:`Services.discover_follow` (live iterator over :meth:`Stream.follow`).
* **Opaque Info bundle.** ``Update.Info`` is a ``*astral.Bundle`` — exactly the
  precedent of ``mod.auth.permit``'s ``Constraints`` field — modelled as the
  nullable ``("ptr", ("bundle",))`` kind (see :mod:`astral.record`): the ptr's
  null-flag maps JSON ``null`` → ``None`` and an empty bundle ``[]`` → ``[]``, while
  the OPAQUE ``("bundle",)`` passes the framed inner blobs through WITHOUT decoding
  them (a faithful typed decode needs the whole Blueprint/registry path).
* **ProviderID is an identity, not a time.** ``Update.ProviderID`` is a nullable
  ``*astral.Identity``: a hex string over the JSON transports, a present/absent
  33-byte key over binary. Unlike a ``time`` field it needs no cross-transport
  normalization caveat.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Union

from ..objectid import ObjectID
from ..record import Record
from ..registry import register
from . import Protocol

__all__ = ["Services", "ServiceUpdate"]


@register("services.update")
@dataclass(frozen=True)
class ServiceUpdate(Record):
    """A single service-availability announcement (``services.update``).

    Wire type ``services.update`` (astral-go ``api/services/update.go`` struct
    ``Update``), fields in declaration order (astral-go ``Objectify`` encodes struct
    fields in that order): ``Available`` (bool), ``Name`` (string8), ``ProviderID``
    (``*astral.Identity``), ``Info`` (``*astral.Bundle``).

    ``provider_id`` is a nullable identity — a hex string over JSON, a present/absent
    key over binary (``("ptr", "identity")``). ``info`` is a nullable OPAQUE bundle
    (``("ptr", ("bundle",))``): ``None`` for ``null``, a ``list[bytes]`` of raw framed
    blobs otherwise (the inner objects are NOT decoded; see the module note). Via the
    registry it decodes over binary (``read_from``) and JSON (``from_value``) alike,
    and can also be sent (``encode_binary`` / ``encode_json``).
    """

    TYPE = "services.update"
    FIELDS = (
        ("available", "Available", "bool"),
        ("name", "Name", "string8"),
        ("provider_id", "ProviderID", ("ptr", "identity")),
        ("info", "Info", ("ptr", ("bundle",))),
    )

    available: bool = False
    name: str = ""
    provider_id: Optional[str] = None
    info: Any = None


class Services(Protocol):
    """Typed helpers for the ``services`` protocol (``discover``, ``sync``).

    Grounded in ``protocols/services/ops/`` and astral-go ``api/services/``. The one
    documented ``services.discover`` op carries two eos semantics keyed by ``follow``,
    split here into :meth:`discover` (snapshot) and :meth:`discover_follow` (live).
    """

    def discover(self) -> List[ServiceUpdate]:
        """Return the current snapshot of visible ``services.update`` records.

        Snapshot mode (``follow=False``): the node streams the current
        ``services.update`` objects then an ``eos`` TERMINATOR; iterate up to it and
        decode each object via :meth:`ServiceUpdate.from_value` (which handles a dict
        over JSON, a typed record over binary via the registry, and an already-decoded
        record idempotently). Raises :class:`~astral.errors.RemoteError` if discovery
        cannot start.

        For the live-tail variant use :meth:`discover_follow`; ``follow`` is fixed
        here so the snapshot's ``eos`` stays a terminator (exposing it would conflate
        the two eos semantics).
        """
        with self.client.query("services.discover", {"follow": False}) as stream:
            return [ServiceUpdate.from_value(obj.value) for obj in stream.results()]

    def discover_follow(self) -> Iterator[ServiceUpdate]:
        """Stream the snapshot then live ``services.update`` records (stays open).

        Follow mode (``follow=True``): the channel STAYS OPEN — the first ``eos`` is a
        snapshot/live SEPARATOR, not a terminator — so this uses :meth:`Stream.follow`
        (not :meth:`Stream.results`), which skips that separator and keeps yielding
        live updates until the channel closes, raising
        :class:`~astral.errors.RemoteError` on an ``error_message``. This is why
        ``Stream`` grew ``follow()``: unlike ``tree.follow`` (whose tail never crosses
        an eos separator and so can use ``results()``), ``services.discover`` DOES
        cross one (astral-go ``client/services.go`` uses a nil sentinel to mark the
        boundary).

        Requires a streaming transport (binary or WebSocket); HTTP (request/response
        only) cannot keep the channel open. Breaking out of the loop closes the stream
        via the ``with`` block.
        """
        with self.client.query("services.discover", {"follow": True}) as stream:
            for obj in stream.follow():
                yield ServiceUpdate.from_value(obj.value)

    def sync(self, id: Union[str, ObjectID], *, follow: Optional[bool] = None) -> None:
        """Fetch and store ``id``'s service advertisements into the local registry.

        ``id`` is the target identity to sync from — a hex public key or an alias
        resolved node-side via the directory — sent as a query arg via ``str(id)``
        (mirroring :meth:`~astral.api.auth.Auth.index`). The node acks on success and
        returns an ``error_message`` (surfaced as
        :class:`~astral.errors.RemoteError`) if the target cannot be resolved or the
        sync fails.

        ``follow`` (forwarded only when not ``None``, per the skip-None convention) has
        DIFFERENT semantics from :meth:`discover_follow`: it asks the node to keep
        syncing until ANY input arrives on the channel, at which point the node cancels
        it. CAVEAT: this one-shot helper (``call_one``) closes the channel right after
        reading the ack, so ``follow=True`` effectively cancels at once here; a
        genuinely long-running follow-sync would need a held-open :meth:`query`, out of
        scope for the single-ack helper.
        """
        args = {"id": str(id)}
        if follow is not None:
            args["follow"] = follow
        self.client.call_one("services.sync", args)
