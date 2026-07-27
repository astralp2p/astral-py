"""The complete astral exception hierarchy.

This module imports nothing from the package. Every other module may depend on
it; it depends on none of them.

The tree, in one place::

    AstralError
    |-- WireError                  a byte-level, text-level or schema-level fault
    |   |-- ShortRead              a read past the end of the reader
    |   |-- AllocationLimit        a declared length above the reader's max_alloc
    |   |-- InvalidFlag            a presence or nil flag outside {0x00, 0x01}
    |   |-- RangeError             a value outside its wire width  (also ValueError)
    |   |-- ValueTooLarge          a payload a length prefix cannot carry (also ValueError)
    |   |-- ParseError             an unparsable text or JSON form   (also ValueError)
    |   |-- SchemaError            a declaration the codec cannot honour
    |   |   |-- DepthExceeded
    |   |   +-- CycleDetected
    |   |-- BlueprintNotFound      a type name the registry does not know
    |   +-- StreamCorrupted        an unrecoverable framing fault
    |-- TransportError
    |   |-- NodeUnavailable        dial failed, or the greeting never arrived
    |   +-- TransportUnsupported   the session cannot carry what was asked of it
    |-- SessionError               one apphost failure reply, one class each
    |   |-- ProtocolError
    |   |-- AuthFailed
    |   |-- Denied
    |   |-- TargetNotAllowed
    |   |-- RouteNotFound
    |   |-- QueryTimeout
    |   |-- QueryCanceled
    |   |-- QueryRejected
    |   +-- InternalError
    |-- RemoteError                an error_message object inside a stream
    |-- ClientClosed
    +-- FeatureUnavailable

`RemoteError` is deliberately not a `SessionError`. An `error_message` object
travels in the query's own object stream; an `error_msg` travels in the apphost
control channel. Merging them loses the distinction between "the node refused to
route this" and "the op ran and reported a failure".
"""

from __future__ import annotations

__all__ = [
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
    "ClientClosed",
    "FeatureUnavailable",
]


class AstralError(Exception):
    """Base class for every error this SDK raises on its own behalf."""


# --- wire core ------------------------------------------------------------


class WireError(AstralError):
    """An encoding or decoding fault. Raised only by the synchronous core."""


class ShortRead(WireError):
    """A read ran past the end of the reader.

    The reader assigns nothing when this is raised. astral-go's
    `String16.ReadFrom` hands back partial data alongside the error; a caller
    that ignores the error then holds a silently truncated value.
    """


class AllocationLimit(WireError):
    """A length prefix or container count declared more than `max_alloc` bytes.

    Checked before allocating, because a `string64` length and a `uint32`
    container count are both attacker-controlled.
    """


class InvalidFlag(WireError):
    """A pointer nil flag or synthesized presence byte was neither 0x00 nor 0x01."""


class RangeError(WireError, ValueError):
    """A value does not fit the wire width it was written to."""


class ValueTooLarge(WireError, ValueError):
    """A length-prefixed payload exceeds what its prefix width can carry.

    Raised before any byte is written, so a rejected write never leaves a
    truncated length prefix behind.
    """


class ParseError(WireError, ValueError):
    """A text or JSON form could not be parsed into its value type."""


class SchemaError(WireError):
    """A schema declaration the codec cannot honour."""


class DepthExceeded(SchemaError):
    """Nesting passed MAX_DEPTH on encode, on decode or at construction."""


class CycleDetected(SchemaError):
    """A `Ref` or `Ptr` chain closes on itself.

    Both one-step self-reference and multi-step cycles are rejected at
    registration; astral-go catches only the one-step case and stack-overflows
    on a mutual pair.
    """


class BlueprintNotFound(WireError):
    """The registry, and its whole parent chain, does not know this type name."""


class StreamCorrupted(WireError):
    """The stream can no longer be decoded and cannot be resynchronised.

    Nothing at field granularity carries a length, so an unknown type name
    mid-payload ends the stream. Only the binary channel layer can recover,
    because its frame length lets it skip.
    """


# --- transport ------------------------------------------------------------


class TransportError(AstralError):
    """A fault below the apphost session."""


class NodeUnavailable(TransportError):
    """The node could not be reached, or accepted the socket and never greeted.

    The only error the retry decorator retries: the query was never sent, so a
    retry cannot duplicate an effect. A saturated apphost worker pool surfaces
    here rather than as an infinite hang.
    """


class TransportUnsupported(TransportError):
    """The session cannot carry what the caller asked of it.

    Raised for a RAW-mode op on a JSON or HTTP session, and for `caller`,
    `zone` or `filters` passed to an HTTP session.
    """


# --- session --------------------------------------------------------------


class SessionError(AstralError):
    """An apphost control-channel failure reply."""


class ProtocolError(SessionError):
    """`error_msg{protocol_error}`: the peer rejected the message sequence."""


class AuthFailed(SessionError):
    """`error_msg{auth_failed}`: the auth token was refused."""


class Denied(SessionError):
    """`error_msg{denied}`: the node refused the operation for this guest.

    An anonymous guest gets this for every registration attempt, including one
    on the zero identity.
    """


class TargetNotAllowed(SessionError):
    """`error_msg{target_not_allowed}`: the guest may not act as that target."""


class RouteNotFound(SessionError):
    """`error_msg{route_not_found}`: nothing on the network served the query."""


class QueryTimeout(SessionError):
    """`error_msg{timeout}`: the node timed the query out."""


class QueryCanceled(SessionError):
    """`error_msg{canceled}`: the query was cancelled at the node."""


class QueryRejected(SessionError):
    """`query_rejected_msg{Code}`: the responder declined.

    Codes are surfaced numerically and no semantic mapping above 4 is claimed:
    0 success, 1 rejected, 2 invalid query, 3 canceled, 4 internal error, and
    5 upwards are op-specific. Rejection codes and `error_msg` codes are
    different namespaces.
    """

    def __init__(self, code: int, message: str | None = None) -> None:
        super().__init__(message if message is not None else f"query rejected with code {code}")
        self.code = code


class InternalError(SessionError):
    """`error_msg{internal_error}`: the node failed while serving the query."""


# --- above the session ----------------------------------------------------


class RemoteError(AstralError):
    """An `error_message` object arrived in the query's object stream."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ClientClosed(AstralError):
    """The client is shutting down and accepts no new work."""


class FeatureUnavailable(AstralError):
    """An optional dependency is missing.

    Raised by the curve-dependent crypto helpers when the `secp256k1` extra is
    not installed. Nothing else degrades without it.
    """
