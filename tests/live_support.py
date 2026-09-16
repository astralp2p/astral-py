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

**Opting in buys a verdict, not a chance of one.** With `ASTRAL_TEST_ENDPOINT`
unset the tier skips, which is what keeps the suite green on a machine with no
node. With it set, a node that does not greet **fails** every live test with the
precheck's reason rather than skipping them. A skip there is indistinguishable
from a pass in the one line a run ends on. Before this rule, a run whose
endpoint named a socket nothing listened on ended
`OK (skipped=157, expected failures=2)`, verified at `263c792`, so a run that
was asked to exercise the live tier reported success without touching it. `gate()`
is where that rule lives, and every live base class goes through it.
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


async def gate(case: unittest.TestCase) -> None:
    """Return when the live tier may run; otherwise skip or fail `case`.

    Skip when the tier is not opted into, and fail when it is and the node did
    not greet. The verdict is still computed once per process, so a dead node
    costs one probe and each test fails at once on the cached reason rather than
    on its own deadline.
    """
    reason = await verdict()
    if not reason:
        return
    if endpoint() is None:
        case.skipTest(reason)
    case.fail(f"{ENDPOINT_VAR} is set, so the live tier must run: {reason}")


class LiveCase(unittest.IsolatedAsyncioTestCase):
    """One client per test, closed by the test, with the descriptors counted.

    `max_concurrency=4` rather than the default 8: this is somebody's real node
    and its worker pool is shared with every app on the machine.
    """

    async def asyncSetUp(self) -> None:
        await gate(self)
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
