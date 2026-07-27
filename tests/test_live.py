"""Tier C: the first tests that talk to a real astrald.

    ASTRAL_TEST_ENDPOINT=unix:~/.apphost.sock \\
        PYTHONPATH=src python3 -m unittest discover -s tests

**Skipped entirely unless `ASTRAL_TEST_ENDPOINT` is set** (design section 7.3),
so the suite is green on a machine with no node, and skipped again -- once, with
the reason -- if the node named there does not greet. The precheck lives in
`live_support.py` and is shared with every other Tier-C file; it is not
ceremony, because a saturated apphost worker pool accepts the socket and never
speaks, so without it every test here would fail on a different-looking deadline
and none of them would say why.

What is asserted here cannot be asserted anywhere else, because it is the *node*
being right rather than the SDK being self-consistent:

- **`apphost.whoami` answers with one `identity` and then a bare EOF.** No `eos`
  anywhere in it. That is astral-docs bug D-23 as a live fact, and it is the
  reason nothing in this SDK waits for an `eos`. The identity it returns is
  cross-checked against the one the node greeted with, which are two independent
  decodes of the same 33 bytes down two different paths -- the greeting's
  `Ptr("identity")` inside `host_info_msg`, and a bare `identity` object in a
  channel frame. The legacy SDK got the second wrong for its whole life.
- **`objects.blueprints` answers with many objects and *does* end with `eos`.**
  The other shape, from the same node, in the same run. Two shapes, one op-mode
  taxonomy that is not discoverable from the wire (design section 4.7).
- **A directory name resolves to an identity before a query carries it.**
- **Nothing leaks.** The kernel is asked, not the SDK: a leaked connection burns
  one of the node's 32 apphost workers permanently and thirty-two of them wedge
  every app on the machine (astrald bug G-13).

Read-only, anonymous-safe ops only. Nothing here mutates node state: no
`dir.set_alias`, no `tree.set`, no `objects.*` writes, no registration, no
`apphost.cancel`. `log.listen` in particular is never opened -- it registers a
callback into the node's global logger, and a subscriber that stops reading is a
subscriber the node is entitled to wait for.
"""

from __future__ import annotations

import asyncio
import unittest

import astral
from astral.object import ErrorMessage
from astral.types import Identity

from live_support import LiveCase
from mock_apphost import bounded


class SmokeTest(LiveCase):
    """The first live test of the client layer, and the gate of step 8."""

    @bounded(30.0)
    async def test_whoami_answers_the_identity_the_node_greeted_with(self):
        """Connect, ask, check, close, and count the descriptors.

        The identity assertion is node-agnostic and grounded in astrald rather
        than in this machine's node: `OpWhoami` sends `query.Caller()`, and
        `core/router.go` substitutes the node's own identity for a nil caller. An
        anonymous client sends the nil form, so `whoami` gives back the identity
        from the greeting. An authenticated one gets its own guest identity, and
        the assertion follows whichever this client is -- the environment may
        carry a token.
        """
        async with await self.client() as client:
            self.assertIsInstance(client.host_id, Identity)
            self.assertTrue(client.host_alias)

            who = await client.call_one("apphost.whoami")
            self.assertIsInstance(who, Identity)
            expected = client.guest_id if client.authenticated else client.host_id
            self.assertEqual(who, expected)

        self.assertTrue(client.closed)
        self.assertEqual(client.live_streams, 0)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_whoami_ends_at_a_bare_eof_with_no_eos(self):
        """astral-docs bug D-23, live. An SDK that waited for an `eos` here would
        block until the node closed, holding one of its 32 workers."""
        async with await self.client() as client:
            async with client.stream("apphost.whoami") as s:
                objects = [obj async for obj in s]
                self.assertEqual(len(objects), 1)
                self.assertEqual(s.terminated_by, "eof")
                self.assertFalse(s.saw_eos)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_objects_blueprints_ends_at_an_eos(self):
        """The other shape, from the same node in the same run: many objects and
        a terminator. Which one an op uses is not on the wire."""
        async with await self.client() as client:
            async with client.stream("objects.blueprints") as s:
                names = [str(obj) async for obj in s]
                self.assertGreater(len(names), 50)
                self.assertIn("ack", names)
                self.assertEqual(s.terminated_by, "eos")
                self.assertTrue(s.saw_eos)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_directory_name_resolves_before_a_query_carries_it(self):
        """The apphost `Target` field is an identity; a name never travels."""
        async with await self.client() as client:
            resolved = await client.resolve_identity(client.host_alias)
            self.assertEqual(resolved, client.host_id)
            # And the same name given as a target reaches the same node.
            who = await client.call_one("apphost.whoami", target=client.host_alias)
            self.assertIsInstance(who, Identity)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_client_holds_no_idle_connection(self):
        """`connect()` learns the greeting and closes. One connection held for
        the client's lifetime would spend a node worker doing nothing."""
        client = await self.client()
        try:
            await self.assert_no_open_sockets()
        finally:
            await client.aclose()

    @bounded(60.0)
    async def test_concurrent_queries_run_through_the_budget_and_all_close(self):
        """Sixteen queries through four permits. The node is real, so this is
        also the assertion that the budget does not deadlock against one."""
        async with await self.client(max_concurrency=4) as client:

            async def one() -> object:
                return await client.call_one("apphost.whoami")

            got = await asyncio.gather(*[one() for _ in range(16)])
            self.assertEqual(len(got), 16)
            self.assertEqual(len({str(g) for g in got}), 1)
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available, 4)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unrouted_query_is_route_not_found_and_closes(self):
        """The failure path a client meets most often, and the one that must not
        leave a connection behind."""
        async with await self.client() as client:
            with self.assertRaises(astral.RouteNotFound):
                await client.call("astral.py.no.such.op")
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available, 4)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_call_one_refuses_a_streaming_op(self):
        """The RR helper is a declaration, not a guess: pointed at an ST op it
        says so rather than returning the first of 150 objects."""
        async with await self.client() as client:
            with self.assertRaises(astral.ProtocolError):
                await client.call_one("objects.blueprints")
            self.assertEqual(client.live_streams, 0)
        await self.assert_no_open_sockets()


class LiveErrorObjectTest(LiveCase):
    """An `error_message` object is not an `error_msg` control reply."""

    @bounded(30.0)
    async def test_an_op_that_fails_reports_through_the_object_stream(self):
        """`dir.resolve` on a name no node knows answers with an `error_message`
        **inside the accepted stream**, not with an apphost `error_msg`. The two
        are different channels and the SDK never merges them: this is the op
        running and failing, not the node failing to route."""
        async with await self.client() as client:
            with self.assertRaises(astral.RemoteError):
                await client.call_one("dir.resolve?name=astral-py-no-such-alias")
            # And as data, for the CLI's view of the same answer.
            async with client.stream(
                "dir.resolve?name=astral-py-no-such-alias"
            ) as s:
                objects = [obj async for obj in s.raw_objects()]
            self.assertTrue(objects)
            self.assertIsInstance(objects[0], ErrorMessage)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
