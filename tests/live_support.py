"""Tier-C scaffolding: one health precheck per process, one live base case.

Design section 7.3 gates the live tier on `ASTRAL_TEST_ENDPOINT` and requires a
precheck before any test runs, because the failure this tier meets most often is
not a wrong answer but **no answer**: astrald serves apphost from a fixed pool of
32 workers and a saturated pool accepts the socket without ever greeting, so
every test in the tier would otherwise fail on its own deadline and none of them
would say why.

The precheck is shared rather than copied per module for one reason that is not
tidiness: it dials the node. A copy per file is a dial per file, and every dial
occupies one of those 32 workers for as long as it takes. One probe per process,
cached, is the whole budget this tier is entitled to spend on finding out whether
it may run.

The cache is a plain string across event loops, not an object bound to one.
`IsolatedAsyncioTestCase` builds a fresh loop per test, so anything holding a
future or a transport would be reused across loops and fail on the second test.
"""

from __future__ import annotations

import asyncio
import os
from typing import Final

import unittest

import astral
from astral.client import connect
from astral.session import CONNECT_TIMEOUT

from mock_apphost import leaked_sockets, socket_fds

ENDPOINT_VAR: Final = "ASTRAL_TEST_ENDPOINT"

_VERDICT: str | None = None
"""None until the precheck has run, then a skip reason or "" for healthy."""


def endpoint() -> str | None:
    """The node to test against, or `None` when the tier is not opted into."""
    return os.environ.get(ENDPOINT_VAR) or None


async def _probe(target: str) -> str:
    """Dial once and close. Returns a skip reason, or "" when the node answers."""
    try:
        async with await connect(target, max_concurrency=1) as client:
            if client.host_id is None:
                return f"{target}: the node greeted with no identity"
    except Exception as exc:  # noqa: BLE001 -- any fault is a reason to skip
        return f"{target}: {type(exc).__name__}: {exc}"
    return ""


async def verdict() -> str:
    """"" when the live tier may run, else the reason it may not.

    Computed once per process and reused. The bound is three times
    `CONNECT_TIMEOUT` rather than one: `connect()` already spends that on the
    greeting, and a precheck that expired first would report a healthy node as
    unreachable.
    """
    global _VERDICT
    if _VERDICT is not None:
        return _VERDICT
    target = endpoint()
    if target is None:
        _VERDICT = (
            f"{ENDPOINT_VAR} is not set: the live tier is opt-in "
            "(design section 7.3)"
        )
        return _VERDICT
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT * 3):
            _VERDICT = await _probe(target)
    except TimeoutError:
        _VERDICT = f"{target}: no greeting within {CONNECT_TIMEOUT * 3}s"
    return _VERDICT


class LiveCase(unittest.IsolatedAsyncioTestCase):
    """One client per test, closed by the test, with the descriptors counted.

    `max_concurrency=4` rather than the default 8: this is somebody's real node
    and its worker pool is shared with every app on the machine.
    """

    async def asyncSetUp(self) -> None:
        reason = await verdict()
        if reason:
            self.skipTest(reason)
        self.endpoint = endpoint()
        # Taken inside the loop, so the loop's own self-pipe is in the baseline.
        self.sockets_before = socket_fds()

    async def client(self, **kw: object) -> astral.Client:
        kw.setdefault("max_concurrency", 4)
        return await connect(self.endpoint, **kw)  # type: ignore[arg-type]

    async def assert_no_open_sockets(self) -> None:
        if self.sockets_before is None:  # pragma: no cover -- Linux in this tree
            self.skipTest("no /proc/self/fd: descriptors cannot be counted here")
        leaked = leaked_sockets(self.sockets_before)
        if leaked:
            # asyncio releases a descriptor from a `call_soon` callback, so the
            # table settles a turn after the close rather than inside it.
            for _ in range(200):
                await asyncio.sleep(0)
                leaked = leaked_sockets(self.sockets_before)
                if not leaked:
                    break
        self.assertEqual(
            leaked,
            set(),
            f"{len(leaked)} socket descriptor(s) left open against the node: "
            f"{sorted(leaked)} -- each one is a node worker of 32",
        )
