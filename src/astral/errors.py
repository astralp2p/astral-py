"""Exception hierarchy for the astral client library.

The classes mirror the failure modes described in the apphost IPC protocol
(see ``topics/astral-ipc.md`` and ``topics/ws-transport.md`` in astral-docs).
"""

from __future__ import annotations

from typing import Optional

__all__ = [
    "AstralError",
    "ConnectError",
    "AuthError",
    "ProtocolError",
    "QueryRejected",
    "RouteNotFound",
    "TargetNotAllowed",
    "Denied",
    "Canceled",
    "Timeout",
    "InternalError",
    "RemoteError",
    "NotSupported",
    "EncodingError",
    "query_error_for_code",
]


class AstralError(Exception):
    """Base class for every error raised by this library."""


class ConnectError(AstralError):
    """A transport failed to open, or closed before the expected reply."""


class AuthError(AstralError):
    """The host rejected the supplied auth token (``error_msg{auth_failed}``)."""


class ProtocolError(AstralError):
    """An unexpected/invalid message was received, or an unknown error code."""


class EncodingError(AstralError):
    """An object could not be encoded to or decoded from the wire format."""


class NotSupported(AstralError):
    """The requested feature is not available on the active transport."""


class QueryRejected(AstralError):
    """The target rejected the query with a non-zero uint8 reject code.

    The generic reject code is ``1``; other values are operation specific
    (see ``core-primitives/query.md``).
    """

    def __init__(self, code: int, message: Optional[str] = None) -> None:
        self.code = code
        super().__init__(message or f"query rejected with code {code}")


# --- error_msg.Code values returned by the host for route_query -------------
# (topics/astral-ipc.md, "Error codes")


class RouteNotFound(AstralError):
    """No handler accepted the query (``route_not_found``)."""


class TargetNotAllowed(AstralError):
    """The caller may not query this target (``target_not_allowed``)."""


class Denied(AstralError):
    """The guest lacks the required authorization (``denied``)."""


class Canceled(AstralError):
    """The query was cancelled (``canceled``)."""


class Timeout(AstralError):
    """The query timed out (``timeout``)."""


class InternalError(AstralError):
    """Catch-all host failure (``internal_error``)."""


# Mapping of the string codes carried in ``mod.apphost.error_msg`` to classes.
_CODE_MAP = {
    "auth_failed": AuthError,
    "denied": Denied,
    "route_not_found": RouteNotFound,
    "target_not_allowed": TargetNotAllowed,
    "canceled": Canceled,
    "timeout": Timeout,
    "protocol_error": ProtocolError,
    "internal_error": InternalError,
}


def query_error_for_code(code: str) -> AstralError:
    """Return the appropriate exception instance for an ``error_msg`` code."""
    cls = _CODE_MAP.get(code)
    if cls is None:
        return ProtocolError(f"unknown error code: {code!r}")
    return cls(code)


class RemoteError(AstralError):
    """An ``error_message`` object was received in an operation's result stream.

    Many ops signal failure by emitting an ``error_message`` object rather than
    rejecting the query outright (see e.g. ``dir.resolve``). Helpers that decode
    result streams raise this when they encounter one.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)
