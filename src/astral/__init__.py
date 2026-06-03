"""astral — a Python client for the astrald apphost IPC protocol.

Quick start::

    import astral

    with astral.connect(token="...") as node:
        print(node.identity, node.alias)
        identity = node.dir.resolve("alice")
        for key in node.tree.list("/mod"):
            print(key)

The default :func:`connect` target is the local node's unix socket (binary
*Astral IPC*), falling back to TCP. Pass ``ws://127.0.0.1:8624/.ws`` for the
JSON WebSocket transport or ``http://localhost:8624`` for simple HTTP queries.
See the module docs and ``README.md`` for the full surface.
"""

from __future__ import annotations

from .client import Client, build_transport, connect
from .encoding import (
    Zone,
    build_query_string,
    text_encode_object,
    to_text,
)
from .errors import (
    AstralError,
    AuthError,
    Canceled,
    ConnectError,
    Denied,
    EncodingError,
    InternalError,
    NotSupported,
    ProtocolError,
    QueryRejected,
    RemoteError,
    RouteNotFound,
    TargetNotAllowed,
    Timeout,
)
from .objectid import (
    STAMP,
    ObjectID,
    compute_object_id,
    object_binary_encoding,
    zbase32_decode,
    zbase32_encode,
)
from .objects import (
    ACK,
    EMPTY,
    EOS,
    AstralObject,
    ack,
    blob,
    eos,
    error,
    obj,
)
from .stream import Stream
from .transport.base import (
    Endpoint,
    HostInfo,
    default_endpoint,
    parse_endpoint,
)
from .transport.session import IncomingQuery, Registration

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # entry points
    "connect",
    "Client",
    "build_transport",
    # objects
    "AstralObject",
    "obj",
    "ack",
    "eos",
    "error",
    "blob",
    "ACK",
    "EOS",
    "EMPTY",
    # object ids
    "ObjectID",
    "compute_object_id",
    "object_binary_encoding",
    "zbase32_encode",
    "zbase32_decode",
    "STAMP",
    # encoding
    "Zone",
    "build_query_string",
    "to_text",
    "text_encode_object",
    # streams & serving
    "Stream",
    "IncomingQuery",
    "Registration",
    # connection
    "HostInfo",
    "Endpoint",
    "parse_endpoint",
    "default_endpoint",
    # errors
    "AstralError",
    "ConnectError",
    "AuthError",
    "ProtocolError",
    "EncodingError",
    "NotSupported",
    "QueryRejected",
    "RouteNotFound",
    "TargetNotAllowed",
    "Denied",
    "Canceled",
    "Timeout",
    "InternalError",
    "RemoteError",
]
