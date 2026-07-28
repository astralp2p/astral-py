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
    |-- BadArgument               an argument value refused here (also ValueError)
    |-- BadArgumentType           an argument type refused here  (also TypeError)
    |-- StreamClosed              use of a closed stream or client (also RuntimeError)
    |-- ConcurrentRead            a second reader on a one-reader stream (also RuntimeError)
    |-- ClientClosed                                              (also RuntimeError)
    +-- FeatureUnavailable

`RemoteError` is deliberately not a `SessionError`. An `error_message` object
travels in the query's own object stream; an `error_msg` travels in the apphost
control channel. Merging them loses the distinction between "the node refused to
route this" and "the op ran and reported a failure".

**Every fault this SDK raises on its own behalf is an `AstralError`**, which is
what `astral/__init__.py` promises, and the five classes above with a second
stdlib base are how the promise is kept without breaking the reflex a Python
caller already has. An argument fault is a `ValueError` or a `TypeError` *and* an
`AstralError`; use after close is a `RuntimeError` *and* an `AstralError`. The
alternative -- narrowing the promise to protocol and transport faults -- was
rejected because use-after-close is the commonest runtime fault in an async SDK
and a caller who wrote the documented catch-all would crash on it.

Nine guards stay bare, and every one of them answers a caller who used an
internal API wrongly rather than a caller who used the SDK: a negative length
handed to `Reader` (twice), `MemTransport`, `StreamTransport`, `HTTPResponse` or
`WebSocketByteTransport`; a base other than 10 or 16 handed to `ascii_int`;
reframing a `QueryStream` that is already framed; a second reader on a
`MemTransport`, which is test-only and mirrors `asyncio.StreamReader`
deliberately; and the abstract `read_payload` of the primitive base. None is
reachable through `Client`, `Stream` or a module client, so none can surprise the
documented catch-all.

The rule that decides it: a fault a caller can reach through a **public** object
is an `AstralError`. `HTTPResponse.read` raised a bare `RuntimeError` for a
second concurrent reader where `WebSocketClient.receive_frame` raises
`ConcurrentRead` for the identical condition, and `TextChannel` raised a bare
`ValueError` for an output format `parse_format` reports as a `ParseError` one
line above; both are now the documented class, and both keep their stdlib base,
so nothing that caught the old one stops working.
"""

from __future__ import annotations

__all__ = [
    "AstralError",
    "attributed",
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


class AstralError(Exception):
    """Base class for every error this SDK raises on its own behalf."""


def attributed(message: str, query: str | None) -> str:
    """`"<query>: <message>"`, or the message alone when no query is known.

    The SDK attributes its own faults well -- `dir.filters: expected 'string8'`
    names the op -- and the faults a caller meets in production are the remote's.
    This is the one place that prefix is formed, so a remote fault reads like a
    local one. An already-prefixed message is left alone rather than prefixed
    twice, which happens when a layer that knew the op wrapped one that did not.
    """
    if not query or message.startswith(f"{query}:"):
        return message
    return f"{query}: {message}"


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
    """The message sequence was wrong, whichever side noticed.

    `error_msg{protocol_error}` is the peer saying so. The same class is raised
    locally when a reply is the wrong type, when an exchange ends without one, or
    when an op breaks the shape its own documentation declares -- an RR op
    answering with two objects, say. The op-mode taxonomy is not discoverable
    from the wire (design section 4.7), so the caller declares the shape and a
    violation of it is the responder failing to keep the contract, not a
    transport fault.
    """


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

    `query` names the query string that was rejected when the raising layer knew
    it. A program that issues ten queries and is told only "rejected with code 1"
    has been told nothing it can act on.
    """

    def __init__(
        self, code: int, message: str | None = None, *, query: str | None = None
    ) -> None:
        text = message if message is not None else f"query rejected with code {code}"
        super().__init__(attributed(text, query))
        self.code = code
        self.query = query


class InternalError(SessionError):
    """`error_msg{internal_error}`: the node failed while serving the query."""


# --- above the session ----------------------------------------------------


class RemoteError(AstralError):
    """An `error_message` object arrived in the query's object stream.

    `message` is the responder's own text, unprefixed, because a caller that
    matches on it -- astrald's `record not found` is the common one -- must not
    have to strip attribution first. `str(exc)` carries the query string in front
    of it when the raising layer knew one: `record not found` alone does not say
    which of a program's ten queries failed, and no frame in the traceback does
    either.
    """

    def __init__(
        self, message: str, *, query: str | None = None, endpoint: str | None = None
    ) -> None:
        super().__init__(attributed(message, query))
        self.message = message
        self.query = query
        self.endpoint = endpoint


class BadArgument(AstralError, ValueError):
    """An argument value this SDK refuses before it sends anything.

    A `ValueError` too, so the stdlib reflex keeps working, and an `AstralError`
    so the documented catch-all does. Raised where sending the value would be
    worse than refusing it: an empty `dir.resolve` name resolves to the zero
    identity on the node rather than failing, a filter name containing a comma
    arrives as two names.
    """


class BadArgumentType(AstralError, TypeError):
    """An argument of a type this SDK cannot use. A `TypeError` too."""


class StreamClosed(AstralError, RuntimeError):
    """A closed `Stream`, `Client` or session was used again.

    A `RuntimeError` too: use after close is a caller fault of exactly that kind,
    and it is the commonest runtime fault in an async SDK, so it must satisfy
    both `except RuntimeError` and `except AstralError`.
    """


class ConcurrentRead(AstralError, RuntimeError):
    """A second read was started on a stream that allows one reader.

    There is no multiplexing on the IPC leg, so two readers split one stream's
    frames between them. The *second* read is what fails, leaving the first
    untouched, so the caller that broke the rule is the one that hears about it.
    """


class ClientClosed(StreamClosed):
    """The client is shutting down and accepts no new work."""


class FeatureUnavailable(AstralError):
    """This SDK will not do that in this configuration, and names what changes it.

    Three raisers, one shape: the message says what is unavailable and what the
    caller would pass or install to have it.

    - The curve-dependent crypto helpers, when the `secp256k1` extra is not
      installed. Nothing else degrades without that extra.
    - `serve.require_service_transport`, for register-service over IPC, where
      design risk R-16 is unsettled; `experimental=True` overrides it.
    - The Tier 3 `nodes` and `nat` ops, and the two of them design section 4.5
      drops in v1. `experimental=True` opens the gated ones; the dropped ones
      name why no flag opens them.

    It is deliberately not a `TransportError` or a `SessionError`: nothing was
    sent, and nothing about the node or the connection is being reported.
    """
