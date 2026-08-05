"""Tier B: `MockApphost`, an in-process apphost server, correct and misbehaving.

The harness the framing, session, client and serving suites drive. It reaches a
client two ways, and every test that matters runs over both: `open()` hands back a
`MemTransport` whose peer this mock serves with no kernel involved, and `listen()`
binds a real loopback listener whose endpoint a client dials, so the socket path is
exercised by the same assertions.

**Framing is written by hand here, on purpose.** `frame()` builds
`string8(type) ++ bytes32(payload)` from `int.to_bytes` rather than calling
`astral.codec.channel_frame`, so a wrong layout in the SDK cannot agree with a
wrong layout in the mock. Payload scalars do come from `astral.wire`, which the
layer-1 vector corpus pins byte for byte.

The mock plays a correct host and a misbehaving one. Misbehaviour is a first-class
feature, because a real node misbehaves:

| Knob | Fault |
|---|---|
| `Handshake.SILENT` | connect succeeds, no greeting, connection never closed -- astrald's wedged 32-worker pool, bug G-13 |
| `Handshake.CLOSE` | EOF before the greeting |
| `Handshake.TRUNCATED` | half a `host_info_msg` frame, then close |
| `Handshake.WRONG_TYPE` | a well-formed frame of the wrong type |
| `Handshake.GARBAGE` | bytes that are not a frame |
| `Handshake.OVERSIZE` | a frame declaring a 4 GiB payload |
| `Hang` | a route that is never answered |
| `Drop` | a route answered by closing |
| `ErrorMsg` / `Reject` | every `error_msg` code, every reject code |
| `Accept(truncate=n)` | a response body cut mid-frame, then close |
| `Accept(coalesce=True)` | `query_accepted_msg` and the first raw bytes in one write |
| `Garbage` | non-frame bytes in place of a reply |

A handler never propagates an exception into the enclosing `TaskGroup`: faults land
in `errors` for the test to assert on. `bounded` wraps every test in
`asyncio.timeout`, because a hanging test in an async suite wedges the whole run.

**Importing this module blanks the ambient node.** `blank_ambient_environment()`
runs at import and empties the endpoint and token variables of design section
3.3, so a developer's own `ASTRALD_APPHOST_TOKEN` cannot make a client
authenticate against a mock that has no token. That is the one import side effect
here and it is deliberate: a stdlib `unittest` run has no fixture that covers
`discover`, a single module and a single test alike, and every test module that
reaches `connect()` imports this one.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import functools
import os
from dataclasses import dataclass
from typing import Awaitable, Callable, Coroutine, Final, Sequence

from astral.client import ENDPOINT_VARS, TOKEN_VARS
from astral.errors import TransportError
from astral.transport import MemTransport, Server, Transport, listen_any
from astral.transport.mem import _Pipe
from astral.types import Identity, Nonce
from astral.wire import Reader, Writer

__all__ = [
    "ACK",
    "AMBIENT_VARS",
    "RefusesToClose",
    "refusing",
    "ATTACH_QUERY",
    "AUTH_SUCCESS",
    "AUTH_TOKEN",
    "Accept",
    "BIND",
    "Drop",
    "EOS",
    "ERROR_CODES",
    "ERROR_MSG",
    "ErrorMsg",
    "FURRY_BOLT",
    "FURRY_BOLT_ALIAS",
    "Garbage",
    "HANDLE_QUERY",
    "HOST_INFO",
    "Handshake",
    "Hang",
    "INCOMING_QUERY",
    "MockApphost",
    "MockConn",
    "PING",
    "QUERY_ACCEPTED",
    "QUERY_REJECTED",
    "REGISTER_SERVICE",
    "REJECT_INCOMING",
    "ROUTE_QUERY",
    "Reject",
    "RouteQuery",
    "attach_query_payload",
    "auth_success_payload",
    "auth_token_payload",
    "bind_payload",
    "blank_ambient_environment",
    "bounded",
    "error_msg_payload",
    "frame",
    "handle_query_payload",
    "host_info_payload",
    "incoming_query_payload",
    "leaked_sockets",
    "oversize_frame",
    "parse_attach_query",
    "parse_auth_success",
    "parse_auth_token",
    "parse_bind",
    "parse_error_msg",
    "parse_handle_query",
    "parse_host_info",
    "parse_incoming_query",
    "parse_query_rejected",
    "parse_register_service",
    "parse_reject_incoming",
    "parse_route_query",
    "partial_frame",
    "query_rejected_payload",
    "register_service_payload",
    "reject_incoming_payload",
    "route_query_payload",
    "socket_fds",
    "until",
]

# --- the ambient node, neutralised ---------------------------------------

AMBIENT_VARS: Final = ENDPOINT_VARS + TOKEN_VARS
"""The production variables `connect()` falls back to when given neither.

Design section 3.3 makes that fallback the library's behaviour, and it is right
for an application and wrong for a test. The mock host in this module has no
token, so a developer's own `ASTRALD_APPHOST_TOKEN` reaches it as an
`auth_token_msg` it can only refuse, and the test dies on `AuthFailed` against an
in-process server that was never meant to authenticate anybody. Verified: with
that one variable exported, `test_api_crypto.ResetTest`,
`test_client.OpModeHelperTest` and `test_websocket.SessionOverWebSocketTest` each
lost the one test in it that calls `connect()` with an endpoint rather than a
connector -- three of 3,254, and the same `AuthFailed` in all three.

Neutralising these costs the live tier nothing, because the suite's own opt-ins
are deliberately not these names: design section 7.3 gates Tier C on
`ASTRAL_TEST_ENDPOINT` and its serving half on `ASTRAL_TEST_TOKEN`, which
`test_serve.py` reads and passes explicitly. The read-only half is the
anonymous-safe op set by design, and it answers the same way anonymous. Verified
against `furry-bolt`: the tier's results are identical with the ambient token
present and absent.
"""


def blank_ambient_environment() -> None:
    """Blank the production endpoint and token variables for this process.

    Blanked, not deleted, for two reasons: both resolvers skip an empty value, so
    blank is as good as absent, and an empty variable is inherited by the
    subprocesses `test_cli` spawns, which take a copy of `os.environ` and would
    otherwise resolve the developer's node all over again.

    Called at import rather than from a fixture, because import is the only hook
    a stdlib `unittest` run offers that covers every entry point -- `discover`, a
    single module, a single test -- and there is no package `__init__` to hang
    one on. Both halves of that reach are pinned by
    `test_mock_apphost.AmbientEnvironmentTest`: that the variables are blank once
    this module is imported, and that every test module which calls `connect`
    imports it.
    """
    os.environ.update({name: "" for name in AMBIENT_VARS})


blank_ambient_environment()

# The live node this design was surveyed against: alias `furry-bolt`, identity
# 03b2704948bb...ae1. Its host_info_msg frame is pinned as a byte vector.
FURRY_BOLT: Final = Identity.parse(
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)
FURRY_BOLT_ALIAS: Final = "furry-bolt"

HOST_INFO: Final = "mod.apphost.host_info_msg"
AUTH_TOKEN: Final = "mod.apphost.auth_token_msg"
AUTH_SUCCESS: Final = "mod.apphost.auth_success_msg"
ERROR_MSG: Final = "mod.apphost.error_msg"
ROUTE_QUERY: Final = "mod.apphost.route_query_msg"
QUERY_ACCEPTED: Final = "mod.apphost.query_accepted_msg"
QUERY_REJECTED: Final = "mod.apphost.query_rejected_msg"
REGISTER_SERVICE: Final = "mod.apphost.register_service_msg"
INCOMING_QUERY: Final = "mod.apphost.incoming_query_msg"
ATTACH_QUERY: Final = "mod.apphost.attach_query_msg"
REJECT_INCOMING: Final = "mod.apphost.reject_incoming_msg"
HANDLE_QUERY: Final = "mod.apphost.handle_query_msg"
BIND: Final = "mod.apphost.bind_msg"
PING: Final = "mod.apphost.ping_msg"
ACK: Final = "ack"
EOS: Final = "eos"

# Every apphost error_msg code, from astral-go's api/apphost/error_msg.go.
ERROR_CODES: Final = (
    "auth_failed",
    "denied",
    "route_not_found",
    "internal_error",
    "protocol_error",
    "timeout",
    "canceled",
    "target_not_allowed",
)


# --- framing, written independently of the SDK ---------------------------


def frame(type_name: str, payload: bytes = b"") -> bytes:
    """`string8(type) ++ bytes32(payload)`, built from scratch."""
    tag = type_name.encode("utf-8")
    return len(tag).to_bytes(1, "big") + tag + len(payload).to_bytes(4, "big") + payload


def partial_frame(type_name: str, payload: bytes, keep: int) -> bytes:
    """The first `keep` bytes of a frame. What a host that dies mid-write emits."""
    return frame(type_name, payload)[:keep]


def oversize_frame(type_name: str, declared: int = 0xFFFFFFFF) -> bytes:
    """A frame header declaring `declared` payload bytes, with none following."""
    tag = type_name.encode("utf-8")
    return len(tag).to_bytes(1, "big") + tag + declared.to_bytes(4, "big")


# --- payload builders ----------------------------------------------------


def _ptr_identity(w: Writer, identity: Identity | None) -> None:
    """A `*astral.Identity` field: a nil flag, then 33 flat bytes when present.

    A nil pointer is one `0x00` byte; the `anyone` identity is `0x01` and 33 zero
    bytes. Both mean anonymous and they are not the same bytes.
    """
    if identity is None:
        w.flag(False)
        return
    w.flag(True)
    identity.write(w)


def host_info_payload(identity: Identity, alias: str) -> bytes:
    w = Writer()
    _ptr_identity(w, identity)
    w.string8(alias)
    return w.getvalue()


def auth_success_payload(guest_id: Identity | None) -> bytes:
    w = Writer()
    _ptr_identity(w, guest_id)
    return w.getvalue()


def error_msg_payload(code: str) -> bytes:
    """A bare `string8`. `error_msg` hand-rolls its payload with no struct wrapper."""
    w = Writer()
    w.string8(code)
    return w.getvalue()


def query_rejected_payload(code: int) -> bytes:
    w = Writer()
    w.uint8(code)
    return w.getvalue()


def incoming_query_payload(
    query_id: Nonce, caller: Identity | None, target: Identity | None, query: str
) -> bytes:
    w = Writer()
    w.uint64(int(query_id))
    _ptr_identity(w, caller)
    _ptr_identity(w, target)
    w.string16(query)
    return w.getvalue()


def handle_query_payload(
    token: Nonce,
    query_id: Nonce,
    caller: Identity | None,
    target: Identity | None,
    query: str,
) -> bytes:
    """The first frame on a connection the host dials to a registered handler.

    There is no greeting on that connection: this frame arrives first.
    """
    w = Writer()
    w.uint64(int(token))
    w.uint64(int(query_id))
    _ptr_identity(w, caller)
    _ptr_identity(w, target)
    w.string16(query)
    return w.getvalue()


def route_query_payload(
    nonce: Nonce,
    caller: Identity | None,
    target: Identity | None,
    query: str,
    zone: int = 7,
    filters: Sequence[str] = (),
) -> bytes:
    """The guest's outbound query. `Filters` elements carry a presence byte."""
    w = Writer()
    w.uint64(int(nonce))
    _ptr_identity(w, caller)
    _ptr_identity(w, target)
    w.string16(query)
    w.uint8(zone)
    w.uint32(len(filters))
    for name in filters:
        w.flag(True)
        w.string8(name)
    return w.getvalue()


def auth_token_payload(token: str) -> bytes:
    """A bare `string8`, hand-rolled like `error_msg`."""
    w = Writer()
    w.string8(token)
    return w.getvalue()


def register_service_payload(identity: Identity | None) -> bytes:
    w = Writer()
    _ptr_identity(w, identity)
    return w.getvalue()


def attach_query_payload(query_id: Nonce) -> bytes:
    w = Writer()
    w.uint64(int(query_id))
    return w.getvalue()


def reject_incoming_payload(query_id: Nonce, code: int) -> bytes:
    w = Writer()
    w.uint64(int(query_id))
    w.uint8(code)
    return w.getvalue()


def bind_payload(token: Nonce) -> bytes:
    w = Writer()
    w.uint64(int(token))
    return w.getvalue()


# --- payload parsers -----------------------------------------------------


def _read_ptr_identity(r: Reader) -> Identity | None:
    return Identity.read(r) if r.flag() else None


@dataclass(frozen=True, slots=True)
class RouteQuery:
    """One `mod.apphost.route_query_msg`, as the mock read it."""

    nonce: Nonce
    caller: Identity | None
    target: Identity | None
    query: str
    zone: int
    filters: tuple[str, ...]

    @property
    def op(self) -> str:
        """The query string with its parameters stripped."""
        return self.query.partition("?")[0]


def parse_route_query(payload: bytes) -> RouteQuery:
    r = Reader(payload)
    nonce = Nonce(r.uint64())
    caller = _read_ptr_identity(r)
    target = _read_ptr_identity(r)
    query = r.string16()
    zone = r.uint8()
    count = r.uint32()
    filters: list[str] = []
    for _ in range(count):
        # A `string8` element is neither Ptr nor Any, so it carries a synthesized
        # presence byte. Absence is legal on read and contributes no filter.
        if r.flag():
            filters.append(r.string8())
    if not r.at_end:
        raise AssertionError(f"route_query_msg: {r.remaining} trailing bytes")
    return RouteQuery(nonce, caller, target, query, zone, tuple(filters))


def parse_auth_token(payload: bytes) -> str:
    return Reader(payload).string8()


def parse_host_info(payload: bytes) -> tuple[Identity | None, str]:
    r = Reader(payload)
    return _read_ptr_identity(r), r.string8()


def parse_auth_success(payload: bytes) -> Identity | None:
    return _read_ptr_identity(Reader(payload))


def parse_error_msg(payload: bytes) -> str:
    return Reader(payload).string8()


def parse_query_rejected(payload: bytes) -> int:
    return Reader(payload).uint8()


def parse_incoming_query(payload: bytes) -> tuple[Nonce, Identity | None, Identity | None, str]:
    r = Reader(payload)
    return Nonce(r.uint64()), _read_ptr_identity(r), _read_ptr_identity(r), r.string16()


def parse_handle_query(
    payload: bytes,
) -> tuple[Nonce, Nonce, Identity | None, Identity | None, str]:
    r = Reader(payload)
    return (
        Nonce(r.uint64()),
        Nonce(r.uint64()),
        _read_ptr_identity(r),
        _read_ptr_identity(r),
        r.string16(),
    )


def parse_attach_query(payload: bytes) -> Nonce:
    return Nonce(Reader(payload).uint64())


def parse_bind(payload: bytes) -> Nonce:
    return Nonce(Reader(payload).uint64())


def parse_register_service(payload: bytes) -> Identity | None:
    return _read_ptr_identity(Reader(payload))


def parse_reject_incoming(payload: bytes) -> tuple[Nonce, int]:
    r = Reader(payload)
    return Nonce(r.uint64()), r.uint8()


# --- a carrier that does not honour the Transport contract ----------------


class RefusesToClose(MemTransport):
    """A transport whose `aclose()` returns having released nothing.

    Every carrier the SDK ships closes: `StreamTransport` bounds its flush and
    then aborts, `MemTransport` clears its pipes, and `WebSocketClient` reaches
    that bounded close through a `finally`. This one does not, and it exists
    because the layers above must not *assume* they do. Latching `closed` in a
    `finally` made that assumption at three sites, and over a carrier whose
    close had not completed it reported a released connection on a socket still
    ESTABLISHED -- the sixth occurrence of a defect class already fixed five
    times elsewhere.

    It relents after `relents_after` calls, so a test can also assert that a
    later `aclose()` resumes the walk rather than short-circuiting on a claim
    that was never true.
    """

    relents_after = 3

    def __init__(self, *args, **kw) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kw)
        self.aclose_calls = 0

    async def aclose(self) -> None:
        self.aclose_calls += 1
        if self.aclose_calls >= self.relents_after:
            await super().aclose()


def refusing(name: str = "refuses") -> "RefusesToClose":
    """One `RefusesToClose` with no peer, for a test that only closes it."""
    left, right = _Pipe(), _Pipe()
    return RefusesToClose(left, right, f"mem:{name}")


# --- test bounding -------------------------------------------------------

DEFAULT_TEST_TIMEOUT: Final = 5.0

# Nothing the apphost protocol sends comes close. A larger declared length is a
# desynchronised client, not a large object.
MAX_FRAME: Final = 16 * 1024 * 1024


def bounded(seconds: float = DEFAULT_TEST_TIMEOUT):  # type: ignore[no-untyped-def]
    """Bound one async test. A hanging test wedges the whole suite."""

    def decorate(fn):  # type: ignore[no-untyped-def]
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            async with asyncio.timeout(seconds):
                return await fn(*args, **kwargs)

        return wrapper

    return decorate


async def until(condition: Callable[[], bool], turns: int = 200) -> bool:
    """Yield to the loop until `condition` holds. Bounded, and never a sleep.

    A wall-clock sleep in a test is either flaky or slow; a bounded count of loop
    turns is neither.
    """
    for _ in range(turns):
        if condition():
            return True
        await asyncio.sleep(0)
    return condition()


# --- counting real descriptors -------------------------------------------
#
# A transport's `closed` flag is a promise; a descriptor is a fact. The two came
# apart once already, and expensively: `aclose()` set the flag and then blocked
# forever inside `wait_closed()` on a socket that stayed ESTABLISHED, so every
# assertion written against the flag passed over a leaked connection. The leak
# assertions therefore count what the kernel says this process holds.

_FD_DIR: Final = "/proc/self/fd"


def socket_fds() -> dict[str, str] | None:
    """Every socket descriptor this process holds, as `fd -> socket:[inode]`.

    `None` where the kernel does not publish the table, which is every platform
    but Linux; a caller then has nothing to count and says so rather than
    reporting a reassuring zero.
    """
    try:
        names = os.listdir(_FD_DIR)
    except OSError:
        return None
    found: dict[str, str] = {}
    for name in names:
        try:
            target = os.readlink(os.path.join(_FD_DIR, name))
        except OSError:
            # The descriptor closed between the listing and the readlink, or it
            # is the listing's own. Either way it is not a leak.
            continue
        if target.startswith("socket:"):
            found[name] = target
    return found


def leaked_sockets(before: dict[str, str] | None) -> set[str]:
    """Sockets open now that were not open at `before`.

    Compared by `socket:[inode]` rather than by descriptor number, because a
    freed number is reused immediately and a reused number would hide a leak
    behind a coincidence.
    """
    if before is None:
        return set()
    now = socket_fds()
    if now is None:  # pragma: no cover -- the table does not come and go
        return set()
    return set(now.values()) - set(before.values())


# --- the reply vocabulary ------------------------------------------------


class Handshake(enum.StrEnum):
    """What the mock does with the greeting every connection opens with."""

    CORRECT = "correct"
    WRONG_TYPE = "wrong_type"
    TRUNCATED = "truncated"
    SILENT = "silent"
    GARBAGE = "garbage"
    CLOSE = "close"
    OVERSIZE = "oversize"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class Accept:
    """`query_accepted_msg`, then the accepted query's raw stream."""

    objects: Sequence[tuple[str, bytes]] = ()
    """Response frames, in order."""
    eos: bool = False
    """Append an `eos` frame after `objects`."""
    live: Sequence[tuple[str, bytes]] = ()
    """Frames after the `eos`, which is then a snapshot/live separator."""
    raw: bytes | None = None
    """Unframed bytes appended to the body. The `objects.read` shape."""
    coalesce: bool = False
    """Write the acceptance and the whole body in one call, in one segment."""
    truncate: int | None = None
    """Send only the first `truncate` bytes of the body, then close."""
    echo: bool = False
    """Read frames after answering and echo each one back, until `eos` or EOF."""
    read: bool = False
    """Read frames after answering and record them, until EOF or shutdown."""
    half_close: bool = False
    """`write_eof` after the body, keeping the read direction open."""
    hold: bool = False
    """Stay open until the mock shuts down, instead of closing after the body."""
    delay: float = 0.0
    """Wait this long before answering."""


@dataclass(frozen=True, slots=True)
class Reject:
    """`query_rejected_msg{Code}`. The connection stays a message channel."""

    code: int = 1


@dataclass(frozen=True, slots=True)
class ErrorMsg:
    """`error_msg{Code}`. The connection stays a message channel."""

    code: str = "route_not_found"


@dataclass(frozen=True, slots=True)
class Hang:
    """No answer, ever. The connection stays open until shutdown."""


@dataclass(frozen=True, slots=True)
class Drop:
    """No answer. The connection closes."""


@dataclass(frozen=True, slots=True)
class Garbage:
    """Bytes that are not a frame, then close."""

    data: bytes = b"HTTP/1.1 400 Bad Request\r\n\r\n"


Handler = Callable[["MockConn", RouteQuery], Awaitable[None]]
Route = Accept | Reject | ErrorMsg | Hang | Drop | Garbage | Handler


# --- one connection ------------------------------------------------------


class MockConn:
    """One accepted connection, at frame granularity."""

    __slots__ = ("transport", "received", "raw_read")

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.received: list[tuple[str, bytes]] = []
        self.raw_read = bytearray()

    def __repr__(self) -> str:
        return f"MockConn({self.transport!r}, {len(self.received)} frames)"

    # --- receive ---

    async def recv_frame(self) -> tuple[str, bytes]:
        """One frame. Raises `EOFError` at a clean end of stream."""
        head = await self.transport.readexactly(1)
        type_name = ""
        if head[0]:
            type_name = (await self.transport.readexactly(head[0])).decode(
                "utf-8", "surrogateescape"
            )
        length = int.from_bytes(await self.transport.readexactly(4), "big")
        # A declared length beyond anything the protocol sends means the client
        # desynchronised. Reported as a fault rather than waited on, so the test
        # names the cause instead of expiring on its deadline.
        if length > MAX_FRAME:
            raise AssertionError(f"{type_name or 'blob'}: frame declares {length} bytes")
        payload = await self.transport.readexactly(length) if length else b""
        self.received.append((type_name, payload))
        return type_name, payload

    async def recv_frame_or_none(self) -> tuple[str, bytes] | None:
        try:
            return await self.recv_frame()
        except EOFError:
            return None

    async def read_raw(self, n: int = -1) -> bytes:
        """Unframed bytes off the stream, recorded in `raw_read`."""
        data = await self.transport.read(n)
        self.raw_read += data
        return data

    # --- send ---

    def send_frame(self, type_name: str, payload: bytes = b"") -> None:
        """One frame in exactly one `write()`."""
        self.transport.write(frame(type_name, payload))

    def send_batch(self, *frames: tuple[str, bytes]) -> None:
        """Several frames in one `write()`, hence one segment."""
        self.transport.write(b"".join(frame(t, p) for t, p in frames))

    def send_raw(self, data: bytes) -> None:
        self.transport.write(data)

    async def flush(self) -> None:
        await self.transport.drain()

    def half_close(self) -> None:
        self.transport.write_eof()

    async def aclose(self) -> None:
        await self.transport.aclose()


# --- the server ----------------------------------------------------------


class MockApphost:
    """An in-process apphost host, over memory or over loopback.

    Lifetime is an async context manager. Every connection handler runs in one
    `TaskGroup`; shutdown sets the stop event, closes the listener, closes every
    connection and awaits the group, so no task and no transport outlives the
    block.
    """

    def __init__(
        self,
        *,
        host_id: Identity | None = None,
        alias: str = FURRY_BOLT_ALIAS,
        token: str | None = None,
        guest_id: Identity | None = None,
        handshake: Handshake = Handshake.CORRECT,
        routes: dict[str, Route] | None = None,
        default_route: Route | None = None,
        register_service: Route | str = "denied",
        attach_query: Route | str = "route_not_found",
        session: Callable[["MockConn"], Awaitable[None]] | None = None,
    ) -> None:
        self.host_id = FURRY_BOLT if host_id is None else host_id
        self.alias = alias
        self.token = token
        # The identity an accepted auth_token_msg reports. Defaults to the host's
        # own, which is what a token minted for a local app resolves to.
        self.guest_id = self.host_id if guest_id is None else guest_id
        self.handshake = handshake
        self.routes: dict[str, Route] = dict(routes or {})
        # An unrouted query string gets what the node gives it.
        self.default_route: Route = (
            ErrorMsg("route_not_found") if default_route is None else default_route
        )
        self.register_service = register_service
        self.attach_query = attach_query
        self._session = session

        self.connections: list[MockConn] = []
        self.queries: list[RouteQuery] = []
        self.tokens: list[str] = []
        self.bind_tokens: list[Nonce] = []
        self.errors: list[BaseException] = []
        self.conn_count = 0
        self.live = 0
        self.peak_live = 0

        self._stop = asyncio.Event()
        self._stack: contextlib.AsyncExitStack | None = None
        self._tg: asyncio.TaskGroup | None = None
        self._server: Server | None = None
        self._closed = False

    # --- lifetime ---

    async def __aenter__(self) -> "MockApphost":
        self._stack = contextlib.AsyncExitStack()
        await self._stack.__aenter__()
        self._tg = await self._stack.enter_async_context(asyncio.TaskGroup())
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._server is not None:
            await self._server.aclose()
        for conn in list(self.connections):
            await conn.aclose()
        stack, self._stack = self._stack, None
        if stack is not None:
            await stack.aclose()

    @property
    def endpoint(self) -> str:
        """The endpoint a client dials. Set by `listen()`."""
        if self._server is None:
            raise AssertionError("mock apphost is not listening")
        return self._server.endpoint

    # --- connection sources ---

    async def open(
        self, *, max_chunk: int | None = None, peer_max_chunk: int | None = None
    ) -> MemTransport:
        """A client transport whose peer this mock serves, with no kernel involved.

        `max_chunk` bounds every read the client makes, so a caller can force
        one-byte-at-a-time delivery.
        """
        client, server = MemTransport.pair(
            f"mock-{self.conn_count}", max_chunk=max_chunk, peer_max_chunk=peer_max_chunk
        )
        self._serve(server)
        return client

    async def listen(self, proto: str = "tcp") -> str:
        """Bind a real loopback listener. Returns the endpoint to dial."""
        self._server = await listen_any(proto)
        self._task(self._accept_loop(self._server))
        return self._server.endpoint

    async def _accept_loop(self, server: Server) -> None:
        while True:
            try:
                conn = await server.accept()
            except TransportError:
                return
            self._serve(conn)

    def _serve(self, transport: Transport) -> None:
        conn = MockConn(transport)
        self.connections.append(conn)
        self.conn_count += 1
        self._task(self._run(conn))

    def _task(self, coro: Coroutine[None, None, None]) -> None:
        if self._tg is None:
            coro.close()
            raise AssertionError("mock apphost used outside `async with`")
        self._tg.create_task(coro)

    async def _run(self, conn: MockConn) -> None:
        self.live += 1
        self.peak_live = max(self.peak_live, self.live)
        try:
            handler = self._session or self._default_session
            await handler(conn)
        except Exception as exc:  # noqa: BLE001 -- a mock never breaks the TaskGroup
            # Teardown noise is not a fault: a read pending when the transport
            # closes reports a reset, and shutdown closes every transport.
            if not self._stop.is_set():
                self.errors.append(exc)
        finally:
            self.live -= 1
            await conn.aclose()

    # --- the session ---

    async def _default_session(self, conn: MockConn) -> None:
        if not await self._greet(conn):
            return
        while True:
            try:
                type_name, payload = await conn.recv_frame()
            except EOFError:
                return
            if not await self._dispatch(conn, type_name, payload):
                return

    async def _greet(self, conn: MockConn) -> bool:
        """The greeting. Returns whether the message loop runs afterwards."""
        payload = host_info_payload(self.host_id, self.alias)
        match self.handshake:
            case Handshake.CORRECT:
                conn.send_frame(HOST_INFO, payload)
            case Handshake.WRONG_TYPE:
                conn.send_frame(ACK)
            case Handshake.TRUNCATED:
                conn.send_raw(partial_frame(HOST_INFO, payload, 20))
                await conn.flush()
                await conn.aclose()
                return False
            case Handshake.OVERSIZE:
                conn.send_raw(oversize_frame(HOST_INFO))
                await conn.flush()
                await conn.aclose()
                return False
            case Handshake.GARBAGE:
                conn.send_raw(Garbage().data)
                await conn.flush()
                await conn.aclose()
                return False
            case Handshake.CLOSE:
                await conn.aclose()
                return False
            case Handshake.SILENT:
                # The wedged-worker case: the socket is open, nothing arrives, and
                # the host never closes. Held until shutdown.
                await self._stop.wait()
                return False
            case Handshake.NONE:
                # No greeting, straight to the message loop. The dial-back shape:
                # the host's first frame is handle_query_msg.
                pass
        await conn.flush()
        return True

    async def _dispatch(self, conn: MockConn, type_name: str, payload: bytes) -> bool:
        """Answer one guest message. Returns whether the message loop continues."""
        if type_name == AUTH_TOKEN:
            token = parse_auth_token(payload)
            self.tokens.append(token)
            if self.token is not None and token == self.token:
                conn.send_frame(AUTH_SUCCESS, auth_success_payload(self.guest_id))
            else:
                # A bogus token leaves the connection usable as a message channel,
                # verified live against the node.
                conn.send_frame(ERROR_MSG, error_msg_payload("auth_failed"))
            await conn.flush()
            return True

        if type_name == ROUTE_QUERY:
            query = parse_route_query(payload)
            self.queries.append(query)
            return await self._route(conn, query)

        if type_name == REGISTER_SERVICE:
            return await self._reply(conn, self.register_service)

        if type_name == ATTACH_QUERY:
            return await self._reply(conn, self.attach_query)

        if type_name == REJECT_INCOMING:
            return True

        if type_name == BIND:
            self.bind_tokens.append(parse_bind(payload))
            return True

        # Anything else, including ping_msg: the node answers protocol_error and
        # closes.
        conn.send_frame(ERROR_MSG, error_msg_payload("protocol_error"))
        await conn.flush()
        await conn.aclose()
        return False

    async def _reply(self, conn: MockConn, reply: Route | str) -> bool:
        """A configured reply to a non-routing message. A bare string is an error code."""
        if isinstance(reply, str):
            if reply == ACK:
                conn.send_frame(ACK)
                await conn.flush()
                return True
            conn.send_frame(ERROR_MSG, error_msg_payload(reply))
            await conn.flush()
            return True
        return await self._execute(conn, reply, None)

    async def _route(self, conn: MockConn, query: RouteQuery) -> bool:
        route = self.routes.get(query.query)
        if route is None:
            route = self.routes.get(query.op, self.default_route)
        return await self._execute(conn, route, query)

    async def _execute(
        self, conn: MockConn, route: Route, query: RouteQuery | None
    ) -> bool:
        match route:
            case Accept():
                return await self._accept(conn, route)
            case Reject(code=code):
                conn.send_frame(QUERY_REJECTED, query_rejected_payload(code))
                await conn.flush()
                return True
            case ErrorMsg(code=code):
                conn.send_frame(ERROR_MSG, error_msg_payload(code))
                await conn.flush()
                return True
            case Garbage(data=data):
                conn.send_raw(data)
                await conn.flush()
                await conn.aclose()
                return False
            case Hang():
                await self._stop.wait()
                return False
            case Drop():
                await conn.aclose()
                return False
            case _:
                if query is None:
                    raise AssertionError("a handler route needs a query")
                await route(conn, query)  # type: ignore[operator]
                return False

    async def _accept(self, conn: MockConn, route: Accept) -> bool:
        if route.delay:
            await asyncio.sleep(route.delay)

        body = b"".join(frame(t, p) for t, p in route.objects)
        if route.eos:
            body += frame(EOS)
        body += b"".join(frame(t, p) for t, p in route.live)
        if route.raw is not None:
            body += route.raw
        if route.truncate is not None:
            body = body[: route.truncate]

        if route.coalesce:
            # The acceptance and the first raw-stream bytes in one write, hence
            # one segment. A client that read ahead into a buffer of its own
            # strands the body here.
            conn.send_raw(frame(QUERY_ACCEPTED) + body)
        else:
            conn.send_frame(QUERY_ACCEPTED)
            if body:
                conn.send_raw(body)
        await conn.flush()

        if route.truncate is not None:
            await conn.aclose()
            return False

        if route.echo:
            await self._echo(conn)
        elif route.read:
            await self._drain_frames(conn)

        if route.half_close:
            conn.half_close()
        if route.hold:
            await self._stop.wait()
        # The handler's exit closes the connection unconditionally. A mock that
        # left one open would be the leak this SDK exists to avoid.
        return False

    async def _echo(self, conn: MockConn) -> None:
        """Echo every frame back, relaying the terminating `eos`. `objects.echo`."""
        while True:
            received = await conn.recv_frame_or_none()
            if received is None:
                return
            type_name, payload = received
            conn.send_frame(type_name, payload)
            await conn.flush()
            if type_name == EOS:
                return

    async def _drain_frames(self, conn: MockConn) -> None:
        """Record frames until EOF or shutdown. The `apphost.bind` shape."""
        while True:
            received = await conn.recv_frame_or_none()
            if received is None:
                return
            type_name, payload = received
            if type_name == BIND:
                self.bind_tokens.append(parse_bind(payload))
