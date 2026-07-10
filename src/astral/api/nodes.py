"""The ``nodes`` protocol: links, sessions, endpoints and session migration.

Reference: ``protocols/nodes/`` (README, ``ops/``, ``types/``), astral-go
``api/nodes/*.go`` + ``api/nodes/client/*.go``, and the astrald module
``mod/nodes/src/op_*.go`` (the authoritative wire behaviour). The ``nodes``
protocol exposes a node's live transport state — its active *links* (an
authenticated connection to a peer), the multiplexed *sessions* riding those
links, the network *endpoints* it knows for an identity — and the two mutating
ops that dial a fresh link (``new_link``) or move a session between links
(``migrate_session``), plus endpoint registration (``add_endpoint``) and link
teardown (``close_link``).

This module lands the three net-new ``nodes`` records — ``mod.nodes.link_info``,
``mod.nodes.session_info`` and ``mod.nodes.endpoint_with_ttl`` — plus the 7 ops.
The two ``LinkInfo`` endpoint fields and ``EndpointWithTTL.Endpoint`` are
POLYMORPHIC ``exonet.Endpoint`` interface fields, modelled as the ``("object",
ENDPOINTS)`` kind (:mod:`astral.record`): a self-describing ``string8(type) ++
inner`` field whose concrete inner type must be REGISTERED for the binary read to
bound itself. The three exonet endpoint records
(:mod:`astral.api.exonet` — ``mod.tcp.endpoint`` / ``mod.tor.endpoint`` /
``mod.gateway.endpoint``) are exactly those registered inners, so this module
IMPORTS ``astral.api.exonet`` to fire their ``@register`` side effects and pins
the accepted-type set to :data:`ENDPOINTS`. Via the
:class:`~astral.record.Record` base and the registry, every record here decodes
over the binary channel (``read_from`` / ``write_to``, dispatched from
:func:`astral.payload.decode_payload`) AND the JSON transports (``from_value``),
and — being registered — can also be SENT.

Modelling notes / caveats:

* **Polymorphic endpoint fields.** ``LinkInfo.LocalEndpoint`` /
  ``LinkInfo.RemoteEndpoint`` and ``EndpointWithTTL.Endpoint`` are
  ``exonet.Endpoint`` interface values (astral-go ``interfaceValue``), so they
  carry their own type tag on the wire and are modelled as ``("object",
  ENDPOINTS)`` — the ``("object",)`` kind restricted to the exonet endpoint
  types. The Python value is an :class:`~astral.objects.AstralObject`
  ``(type, TcpEndpoint | TorEndpoint | GatewayEndpoint)``. Over JSON they follow
  astral-go's ``JSONAdapter`` shape ``{"Type": <type>, "Object": <address>}``
  where each endpoint marshals to its bare ADDRESS STRING (see
  :mod:`astral.api.exonet`); a nil endpoint is ``None``.
* **``EndpointWithTTL.TTL`` is a nullable ``*uint32``.** Seconds-to-expiry, or
  ``None`` for an endpoint that does not expire — modelled ``("ptr", "uint32")``.
* **``SessionInfo.Age`` is a duration.** astral-go ``astral.Duration`` — a SIGNED
  int64 of NANOSECONDS over binary, the raw integer over JSON (see the docs
  example ``"Age": 12000000000`` == 12s). Modelled as the ``"duration"`` kind.
* **``add_endpoint`` takes the endpoint as a query-arg STRING.** astrald
  ``op_add_endpoint.go`` reads ``endpoint`` off the query args and splits it on
  the first ``:`` into ``<network>:<address>`` (e.g. ``tcp:1.2.3.4:1791``), then
  parses it via the exonet module — it is NOT streamed on the channel body. So
  :meth:`Nodes.add_endpoint` forwards a plain wire string; a caller holding a
  typed endpoint record formats it as ``f"{network}:{record.address}"`` (the
  records expose ``.address`` but not the network prefix — ``tcp`` / ``tor`` /
  ``gw``).
* **``migrate_session`` — start=true-only.** astrald ``op_migrate_session.go``
  has two modes keyed on the ``start`` arg: with ``start=true`` the node drives
  the migration locally and replies with a single ``ack`` (the MANUAL mode this
  SDK implements); with ``start`` unset/false it runs a NEGOTIATED handshake,
  exchanging ``mod.nodes.migrate_signal`` objects (``ready`` / ``switched`` /
  ``resume`` / ``done``) over the channel. The negotiated mode needs a bespoke
  signalling loop and is DEFERRED; :meth:`Nodes.migrate_session` defaults
  ``start=True`` and documents the deferral.

Live-node uncertainties (flagged, none exercised against a running node):

* The exact JSON ``"Type"`` string of an endpoint over a live node is unconfirmed
  against the registry key. The docs examples abbreviate it to ``"tcp.endpoint"``
  / ``"tor.endpoint"``, but astral-go's ``exonet.Endpoint.ObjectType()`` returns
  the FULL ``mod.tcp.endpoint`` / ``mod.tor.endpoint`` / ``mod.gateway.endpoint``
  (confirmed in ``api/tcp|tor|gateway/endpoint.go``), which is what the registry
  is keyed by and what :data:`ENDPOINTS` pins. If a live node emits the
  abbreviated form over JSON the ``{"Type", "Object"}`` decode would miss the
  registry; this is not exercised here.
* The reject codes for ``resolve_endpoints`` / ``new_link`` (``code 2``…``5``,
  per the ``ops/`` docs) are surfaced verbatim as the node maps them; the ops do
  not hardcode them and no live node was consulted.
* The ``duration`` units / normalization for ``SessionInfo.Age`` (nanoseconds
  assumed, matching the docs example) is unconfirmed against a live node, as with
  the ``time`` common type elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Union

from ..objects import AstralObject
from ..record import Record
from ..registry import register
from . import Protocol
from . import exonet as _exonet  # noqa: F401  (fire the endpoint @register side effects)

__all__ = ["Nodes", "LinkInfo", "SessionInfo", "EndpointWithTTL", "ENDPOINTS"]

#: The exonet endpoint types accepted in the polymorphic ``("object", …)`` endpoint
#: fields — astral-go's ``exonet.Endpoint`` implementations
#: (:mod:`astral.api.exonet`). An endpoint object with any other type is rejected
#: by the record codec (see :mod:`astral.record`'s ``("object", allowed_set)``).
ENDPOINTS = {"mod.tcp.endpoint", "mod.tor.endpoint", "mod.gateway.endpoint"}


@register("mod.nodes.link_info")
@dataclass(frozen=True)
class LinkInfo(Record):
    """A live authenticated link to a peer node (``mod.nodes.link_info``).

    Wire type ``mod.nodes.link_info`` (astral-go ``api/nodes/link_info.go``):
    ``ID`` (nonce64), ``LocalIdentity`` (``*astral.Identity``), ``RemoteIdentity``
    (``*astral.Identity``), ``LocalEndpoint`` (``exonet.Endpoint``),
    ``RemoteEndpoint`` (``exonet.Endpoint``), ``Outbound`` (bool), ``Network``
    (string8), ``HighPressure`` (bool), ``BytesThroughput`` (uint64). The two
    endpoint fields are POLYMORPHIC exonet interface values, modelled
    ``("object", ENDPOINTS)`` (see the module note): each is an
    :class:`~astral.objects.AstralObject` wrapping a :class:`~astral.api.exonet`
    endpoint record, or ``None`` for a nil endpoint.
    """

    TYPE = "mod.nodes.link_info"
    FIELDS = (
        ("id", "ID", "nonce64"),
        ("local_identity", "LocalIdentity", "identity"),
        ("remote_identity", "RemoteIdentity", "identity"),
        ("local_endpoint", "LocalEndpoint", ("object", ENDPOINTS)),
        ("remote_endpoint", "RemoteEndpoint", ("object", ENDPOINTS)),
        ("outbound", "Outbound", "bool"),
        ("network", "Network", "string8"),
        ("high_pressure", "HighPressure", "bool"),
        ("bytes_throughput", "BytesThroughput", "uint64"),
    )

    id: str = ""
    local_identity: str = ""
    remote_identity: str = ""
    local_endpoint: Optional[AstralObject] = None
    remote_endpoint: Optional[AstralObject] = None
    outbound: bool = False
    network: str = ""
    high_pressure: bool = False
    bytes_throughput: int = 0


@register("mod.nodes.session_info")
@dataclass(frozen=True)
class SessionInfo(Record):
    """A multiplexed session riding a link (``mod.nodes.session_info``).

    Wire type ``mod.nodes.session_info`` (astral-go ``api/nodes/session_info.go``):
    ``ID`` (nonce64), ``LinkID`` (nonce64), ``RemoteIdentity``
    (``*astral.Identity``), ``Outbound`` (bool), ``Query`` (string16), ``Bytes``
    (uint64), ``Age`` (``astral.Duration``). ``Age`` is the session's lifetime as a
    SIGNED int64 of NANOSECONDS over binary / the raw integer over JSON (the
    ``"duration"`` kind; see the module note — the docs example ``"Age":
    12000000000`` is 12 seconds).
    """

    TYPE = "mod.nodes.session_info"
    FIELDS = (
        ("id", "ID", "nonce64"),
        ("link_id", "LinkID", "nonce64"),
        ("remote_identity", "RemoteIdentity", "identity"),
        ("outbound", "Outbound", "bool"),
        ("query", "Query", "string16"),
        ("bytes", "Bytes", "uint64"),
        ("age", "Age", "duration"),
    )

    id: str = ""
    link_id: str = ""
    remote_identity: str = ""
    outbound: bool = False
    query: str = ""
    bytes: int = 0
    age: int = 0


@register("mod.nodes.endpoint_with_ttl")
@dataclass(frozen=True)
class EndpointWithTTL(Record):
    """An exonet endpoint paired with an optional expiry (``mod.nodes.endpoint_with_ttl``).

    Wire type ``mod.nodes.endpoint_with_ttl`` (astral-go
    ``api/nodes/endpoint_with_ttl.go``): ``Endpoint`` (``exonet.Endpoint``),
    ``TTL`` (``*astral.Uint32`` — seconds to expiry, nil = no expiry). ``Endpoint``
    is the POLYMORPHIC exonet interface value modelled ``("object", ENDPOINTS)``
    (an :class:`~astral.objects.AstralObject` wrapping a
    :class:`~astral.api.exonet` endpoint record, or ``None``); ``TTL`` is the
    nullable ``("ptr", "uint32")`` — ``None`` means the endpoint does not expire.
    """

    TYPE = "mod.nodes.endpoint_with_ttl"
    FIELDS = (
        ("endpoint", "Endpoint", ("object", ENDPOINTS)),
        ("ttl", "TTL", ("ptr", "uint32")),
    )

    endpoint: Optional[AstralObject] = None
    ttl: Optional[int] = None


class Nodes(Protocol):
    """Typed helpers for the ``nodes`` protocol (all 7 documented ops).

    Grounded in ``protocols/nodes/ops/``, astral-go ``api/nodes/`` +
    ``api/nodes/client/``, and astrald ``mod/nodes/src/op_*.go``. Every op is
    query-arg driven (no channel-body inputs). Three stream a list terminated by
    ``eos`` (``links`` / ``sessions`` / ``resolve_endpoints``); two ack
    (``add_endpoint`` / ``close_link``); ``new_link`` returns a single
    ``mod.nodes.link_info``; ``migrate_session`` acks in the start=true manual
    mode (see the module note on the deferred negotiated mode).
    """

    # -- read: links, sessions, endpoints -----------------------------------
    def links(self) -> List[LinkInfo]:
        """List the node's active links as :class:`LinkInfo`\\ s (creation order).

        Streams one ``mod.nodes.link_info`` per active link, then an ``eos``. On a
        per-item send failure the node emits an ``error_message`` (surfaced as
        :class:`~astral.errors.RemoteError`) and ends the stream.
        """
        return [
            LinkInfo.from_value(obj.value)
            for obj in self.client.call("nodes.links")
        ]

    def sessions(self) -> List[SessionInfo]:
        """List the node's open sessions as :class:`SessionInfo`\\ s (creation order).

        Streams one ``mod.nodes.session_info`` per open session across every active
        link, then an ``eos``. A per-item send failure emits an ``error_message``
        (surfaced as :class:`~astral.errors.RemoteError`) and ends the stream.
        """
        return [
            SessionInfo.from_value(obj.value)
            for obj in self.client.call("nodes.sessions")
        ]

    def resolve_endpoints(self, id: str) -> List[EndpointWithTTL]:
        """Resolve every known endpoint for identity ``id`` as :class:`EndpointWithTTL`\\ s.

        Queries every registered endpoint resolver and streams one
        ``mod.nodes.endpoint_with_ttl`` per result, then an ``eos``. ``id`` is a hex
        public key or an alias resolved via the directory. Rejected with code ``2``
        if the identity cannot be resolved, or an internal-error code if a resolver
        lookup fails (surfaced as :class:`~astral.errors.RemoteError`).
        """
        return [
            EndpointWithTTL.from_value(obj.value)
            for obj in self.client.call("nodes.resolve_endpoints", {"id": str(id)})
        ]

    # -- mutate: endpoints & links ------------------------------------------
    def add_endpoint(self, id: str, endpoint: str) -> None:
        """Register ``endpoint`` for identity ``id`` (acks); stored with a ~90-day TTL.

        ``endpoint`` is the wire string ``"<network>:<address>"`` — e.g.
        ``"tcp:1.2.3.4:1791"``, ``"tor:<base32>.onion:1791"`` or
        ``"gw:<gatewayID>:<targetID>"``. astrald ``op_add_endpoint.go`` reads it off
        the query args (NOT the channel body), splits on the first ``:`` into
        ``<network>`` + ``<address>`` and parses it via the exonet module. A caller
        holding a typed :class:`~astral.api.exonet` endpoint record formats it as
        ``f"{network}:{record.address}"`` (the records expose ``.address`` but not
        the ``tcp`` / ``tor`` / ``gw`` network prefix). Rejected (surfaced as
        :class:`~astral.errors.RemoteError`) if the endpoint cannot be parsed or
        stored.
        """
        self.client.call_one(
            "nodes.add_endpoint", {"id": str(id), "endpoint": endpoint}
        )

    def close_link(self, id: str) -> None:
        """Close the active link with local id ``id`` (acks).

        ``id`` is the link's local nonce64 (from :meth:`links` /
        :meth:`new_link`). Rejected (surfaced as
        :class:`~astral.errors.RemoteError`) if no link with that id exists.
        """
        self.client.call_one("nodes.close_link", {"id": str(id)})

    def new_link(
        self,
        target: str,
        *,
        endpoint: Optional[str] = None,
        strategies: Optional[Union[str, List[str]]] = None,
    ) -> LinkInfo:
        """Dial a new link to ``target``; return the resulting :class:`LinkInfo`.

        Single ``mod.nodes.link_info`` on success. ``target`` is a hex public key or
        an alias resolved via the directory. With ``endpoint`` set (the wire string
        ``"<network>:<address>"``, e.g. ``"tcp:1.2.3.4:1791"``) the node dials that
        specific endpoint; otherwise it runs its link *strategies*. ``strategies`` is
        a comma-separated list (or a Python ``list`` joined here) of strategy names
        to try (e.g. ``"basic,tor,nat"``); empty means all registered strategies, and
        it is IGNORED when ``endpoint`` is set.

        Rejected (surfaced as :class:`~astral.errors.RemoteError`) with code ``2``
        (target unresolvable / invalid endpoint format), ``3`` (endpoint parse
        failure), ``4`` (context cancelled / endpoint resolution failed) or ``5``
        (link task could not be scheduled) — the node maps these; they are not
        hardcoded here.
        """
        args = {"target": str(target)}
        if endpoint is not None:
            args["endpoint"] = endpoint
        if strategies is not None:
            args["strategies"] = (
                ",".join(strategies) if isinstance(strategies, list) else strategies
            )
        return LinkInfo.from_value(self.client.call_one("nodes.new_link", args))

    def migrate_session(
        self, session_id: str, link_id: str, *, start: bool = True
    ) -> None:
        """Migrate session ``session_id`` onto link ``link_id`` (acks in manual mode).

        MANUAL (``start=True``, the default and only mode implemented here): the node
        drives the migration locally and replies with a single ``ack`` once the
        session's traffic has moved onto ``link_id``. Both ids are nonce64 (from
        :meth:`sessions` / :meth:`links`).

        The NEGOTIATED mode (``start=False``) is DEFERRED: astrald
        ``op_migrate_session.go`` then runs a signalling handshake, exchanging
        ``mod.nodes.migrate_signal`` objects (``ready`` / ``switched`` / ``resume`` /
        ``done``) over the channel — a bespoke back-and-forth this SDK does not yet
        implement. Passing ``start=False`` still sends the arg, but this method reads
        only the first reply object (the ``ack`` path); driving the signal exchange
        is out of scope. Rejected (surfaced as
        :class:`~astral.errors.RemoteError`) if the session or link is unknown, the
        session is in an invalid state, or it is already on the target link.
        """
        args = {
            "session_id": str(session_id),
            "link_id": str(link_id),
            "start": start,
        }
        self.client.call_one("nodes.migrate_session", args)
