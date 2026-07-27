"""astral -- an asyncio client for the astrald apphost IPC protocol.

    async with await astral.connect() as client:
        who = await client.call_one("apphost.whoami")

The facade is deliberately narrow (design section 1): `connect`, `Client`, the
three value types a caller names in its own signatures -- `Identity`, `ObjectID`,
`Zone` -- and the whole exception hierarchy, so that `except astral.AstralError`
catches everything this SDK raises on its own behalf without a second import.
That promise is kept literally: the argument and state faults a caller meets --
a refused value, a closed stream, a second reader -- are `AstralError`
subclasses that *also* inherit `ValueError`, `TypeError` or `RuntimeError`, so
the stdlib reflex keeps working and the catch-all is not a lie. Everything else
is one module deeper and is named where it lives: `astral.stream` for `Stream`,
`astral.types` for `Nonce`, `Time`, `Duration` and `Size`, `astral.object` for
the object model, `astral.api` for the module clients. Re-exporting more would
make every internal rename a breaking change.

`Stream` is absent on purpose: a caller receives one from `Client.query()` and
never constructs one, so importing the name buys only an annotation, and
`astral.stream.Stream` is where an annotation should point.

Importing this package registers every wire type -- the core's and every
module's, because the last line here imports `astral.api` eagerly. So whether an
object decodes never depends on which submodule a caller happened to import
first, or on which `client.<module>` property they happened to touch. That was a
real latent bug in the legacy SDK, and a `Client` whose module clients were
lazily imported *and* lazily registered would have reintroduced it:
`client.call_one("dir.alias_map")` never touches `client.dir`, and would have
raised `BlueprintNotFound`. Construction is lazy; registration is not.

**Close what you open.** astrald serves apphost from a fixed pool of 32 workers
shared by every app on the machine, and never notices a peer that vanished, so a
`Client` or a `Stream` that is not closed burns one worker until the node
restarts (astrald bug G-13, design section 3.9). `async with` on both is the
contract; there is no `__del__` fallback.
"""

from __future__ import annotations

from .client import Client, connect
from .errors import (
    AllocationLimit,
    AstralError,
    AuthFailed,
    BadArgument,
    BadArgumentType,
    BlueprintNotFound,
    ClientClosed,
    ConcurrentRead,
    CycleDetected,
    Denied,
    DepthExceeded,
    FeatureUnavailable,
    InternalError,
    InvalidFlag,
    NodeUnavailable,
    ParseError,
    ProtocolError,
    QueryCanceled,
    QueryRejected,
    QueryTimeout,
    RangeError,
    RemoteError,
    RouteNotFound,
    SchemaError,
    SessionError,
    ShortRead,
    StreamClosed,
    StreamCorrupted,
    TargetNotAllowed,
    TransportError,
    TransportUnsupported,
    ValueTooLarge,
    WireError,
)
from .types import Identity, ObjectID, Zone

__version__ = "0.1.0"

__all__ = [
    # the facade
    "Client",
    "connect",
    # value types a caller names
    "Identity",
    "ObjectID",
    "Zone",
    # the exception hierarchy, root first
    "AstralError",
    "WireError",
    "ShortRead",
    "AllocationLimit",
    "InvalidFlag",
    "RangeError",
    "ValueTooLarge",
    "ParseError",
    "SchemaError",
    "DepthExceeded",
    "CycleDetected",
    "BlueprintNotFound",
    "StreamCorrupted",
    "TransportError",
    "NodeUnavailable",
    "TransportUnsupported",
    "SessionError",
    "ProtocolError",
    "AuthFailed",
    "Denied",
    "TargetNotAllowed",
    "RouteNotFound",
    "QueryTimeout",
    "QueryCanceled",
    "QueryRejected",
    "InternalError",
    "RemoteError",
    "BadArgument",
    "BadArgumentType",
    "StreamClosed",
    "ConcurrentRead",
    "ClientClosed",
    "FeatureUnavailable",
]

# Last, and eagerly: importing `astral` must register every module's wire types,
# not only the core's. It is the last line because `astral.api.*` import from
# `astral.*`, so this module has to be built before they run.
from . import api  # noqa: E402,F401 -- imported for its registrations
