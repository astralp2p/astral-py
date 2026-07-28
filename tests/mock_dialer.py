"""Tier B: `MockDialer`, the node's half of the register-handler dial-back.

`MockApphost` plays the host a client dials. `MockDialer` plays the host that
**dials us**: it opens a connection to the SDK's own listener, sends
`mod.apphost.handle_query_msg` as the first frame **with no handshake**, and
asserts the SDK answers exactly one of `ack`, `query_rejected_msg`, `error_msg`
or a close (design section 7.2).

Framing is written by hand here for the same reason it is in `mock_apphost`: a
wrong layout in the SDK must not be able to agree with a wrong layout in the
harness. The helpers are imported from `mock_apphost` rather than copied, so
there is still exactly one hand-rolled framing in the tree.

What this harness exists to catch:

| Case | What it proves |
|---|---|
| a correct dial | the first frame is read, the token checked, one answer written |
| a wrong token | `error_msg{denied}` and a close, with the listener still serving |
| a wrong first type | `error_msg{protocol_error}` and a close, listener still serving |
| no first frame | the first-frame deadline closes one connection and no more |
| concurrent dials | one slow handler does not stall the others (astral-go bug G-14) |
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Final

from astral.transport import Transport, dial
from astral.types import Identity, Nonce

from mock_apphost import (
    ACK,
    ERROR_MSG,
    HANDLE_QUERY,
    QUERY_REJECTED,
    MockConn,
    handle_query_payload,
    parse_error_msg,
    parse_query_rejected,
)

__all__ = ["ANSWER_TYPES", "Answered", "MockDialer"]

ANSWER_TYPES: Final = (ACK, QUERY_REJECTED, ERROR_MSG)
"""The three frames a registered handler may answer with. A close is the fourth
answer and carries no frame."""


@dataclass(frozen=True, slots=True)
class Answered:
    """One inbound query's answer, as the dialing node read it."""

    kind: str
    """`ack`, `query_rejected_msg`, `error_msg`, or `closed` for a bare close."""

    code: int | str | None = None
    """The reject code for `query_rejected_msg`, the error code for `error_msg`."""

    conn: MockConn | None = None
    """The connection, still open. The response body follows on it after an `ack`."""

    @property
    def accepted(self) -> bool:
        return self.kind == ACK

    @property
    def denied(self) -> bool:
        return self.kind == ERROR_MSG and self.code == "denied"

    @property
    def protocol_error(self) -> bool:
        return self.kind == ERROR_MSG and self.code == "protocol_error"

    @property
    def route_not_found(self) -> bool:
        return self.kind == ERROR_MSG and self.code == "route_not_found"


class MockDialer:
    """The node dialing a registered handler, one connection per query.

    `astrald`'s `IPCHandler.RouteQuery` dials the endpoint for **every** inbound
    query and never reuses a connection, so every method here does the same.
    """

    __slots__ = ("caller", "endpoint", "target", "token", "conns", "dials")

    def __init__(
        self,
        endpoint: str,
        token: Nonce | int,
        *,
        caller: Identity | None = None,
        target: Identity | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.token = Nonce(int(token))
        self.caller = caller
        self.target = target
        self.conns: list[MockConn] = []
        self.dials = 0

    def __repr__(self) -> str:
        return f"MockDialer({self.endpoint!r}, {self.dials} dials)"

    # --- one connection ---

    async def open(self) -> MockConn:
        """Dial the handler's endpoint. No greeting is sent: there is none."""
        transport: Transport = await dial(self.endpoint)
        conn = MockConn(transport)
        self.conns.append(conn)
        self.dials += 1
        return conn

    def send_query(
        self,
        conn: MockConn,
        query: str,
        *,
        token: Nonce | int | None = None,
        nonce: Nonce | int | None = None,
        caller: Identity | None = None,
        target: Identity | None = None,
    ) -> Nonce:
        """Write `handle_query_msg` as the first frame. Returns the query nonce."""
        ident = Nonce.random() if nonce is None else Nonce(int(nonce))
        conn.send_frame(
            HANDLE_QUERY,
            handle_query_payload(
                self.token if token is None else Nonce(int(token)),
                ident,
                self.caller if caller is None else caller,
                self.target if target is None else target,
                query,
            ),
        )
        return ident

    async def read_answer(
        self, conn: MockConn, *, timeout: float | None = 5.0
    ) -> Answered:
        """Read the one answer, or report the close that stood in for it.

        A frame that is none of the three is an assertion failure here rather
        than a value the test has to re-check: design section 4.3 step 9 permits
        exactly `ack`, `query_rejected_msg`, `error_msg` and a close.
        """
        try:
            async with asyncio.timeout(timeout):
                received = await conn.recv_frame_or_none()
        except TimeoutError:
            raise AssertionError(
                f"{self.endpoint}: no answer to the inbound query within {timeout}s"
            ) from None
        if received is None:
            return Answered("closed", conn=conn)
        type_name, payload = received
        if type_name == ACK:
            return Answered(ACK, conn=conn)
        if type_name == QUERY_REJECTED:
            return Answered(QUERY_REJECTED, parse_query_rejected(payload), conn)
        if type_name == ERROR_MSG:
            return Answered(ERROR_MSG, parse_error_msg(payload), conn)
        raise AssertionError(
            f"{self.endpoint}: answered {type_name!r}; a handler answers one of "
            f"{list(ANSWER_TYPES)} or closes"
        )

    async def query(
        self,
        query: str,
        *,
        token: Nonce | int | None = None,
        nonce: Nonce | int | None = None,
        caller: Identity | None = None,
        target: Identity | None = None,
        timeout: float | None = 5.0,
    ) -> Answered:
        """Dial, send the first frame, read the one answer. The whole exchange."""
        conn = await self.open()
        self.send_query(
            conn, query, token=token, nonce=nonce, caller=caller, target=target
        )
        await conn.flush()
        return await self.read_answer(conn, timeout=timeout)

    async def send_first(self, type_name: str, payload: bytes = b"") -> MockConn:
        """Dial and send an arbitrary first frame. For the wrong-type case."""
        conn = await self.open()
        conn.send_frame(type_name, payload)
        await conn.flush()
        return conn

    async def silent(self) -> MockConn:
        """Dial and send nothing. For the first-frame deadline."""
        return await self.open()

    # --- reading a response body ---

    async def objects(
        self, conn: MockConn, *, limit: int = 64, timeout: float | None = 5.0
    ) -> list[tuple[str, bytes]]:
        """Every response frame up to `eos` or EOF, as `(type, payload)` pairs."""
        out: list[tuple[str, bytes]] = []
        async with asyncio.timeout(timeout):
            for _ in range(limit):
                received = await conn.recv_frame_or_none()
                if received is None:
                    return out
                out.append(received)
                if received[0] == "eos":
                    return out
        raise AssertionError(f"{self.endpoint}: more than {limit} response frames")

    # --- lifetime ---

    async def aclose(self) -> None:
        """Close every connection this dialer opened."""
        for conn in self.conns:
            await conn.aclose()
        self.conns.clear()

    async def __aenter__(self) -> "MockDialer":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self.aclose()
