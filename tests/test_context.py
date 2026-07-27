"""Tier A: `Context`, the routing half of astral-go's `astral.Context`.

Two things to prove. The value semantics: frozen, hashable, copy-on-write, with
the four zone verbs matching astral-go's bitmask helpers exactly. And the
absence: nothing here cancels anything, because asyncio owns cancellation and
the SDK deletes every `sig.*` helper that paired an operation with `ctx.Done()`.

No async, no transport, no node.
"""

from __future__ import annotations

import dataclasses
import unittest

from astral.context import Context
from astral.types import Identity, Zone

NODE = Identity.parse("03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1")


class ValueTest(unittest.TestCase):
    def test_the_default_is_anonymous_in_every_zone(self):
        """astral-go's `NewContext` sets `ZoneDefault`, which is all three bits."""
        ctx = Context()
        self.assertIsNone(ctx.identity)
        self.assertEqual(ctx.zone, Zone.ALL)
        self.assertEqual(ctx.filters, ())
        self.assertIs(Context.DEFAULT.zone, Zone.ALL)

    def test_a_context_is_frozen_and_hashable(self):
        ctx = Context(identity=NODE, filters=("a", "b"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ctx.zone = Zone.DEVICE  # type: ignore[misc]
        self.assertEqual(hash(ctx), hash(Context(identity=NODE, filters=("a", "b"))))
        self.assertEqual({ctx, Context(identity=NODE, filters=("a", "b"))}, {ctx})

    def test_a_filter_list_is_coerced_to_a_tuple(self):
        """A list would make the value unhashable and mutable behind a caller."""
        ctx = Context(filters=["a", "b"])
        self.assertEqual(ctx.filters, ("a", "b"))
        self.assertIsInstance(ctx.filters, tuple)
        hash(ctx)

    def test_an_integer_zone_is_coerced(self):
        self.assertEqual(Context(zone=1).zone, Zone.DEVICE)
        self.assertIsInstance(Context(zone=1).zone, Zone)

    def test_repr_names_the_identity_and_the_zone(self):
        self.assertIn("anonymous", repr(Context()))
        self.assertIn("dvn", repr(Context()))
        self.assertIn(NODE.fingerprint(), repr(Context(identity=NODE)))

    def test_it_carries_no_cancellation(self):
        """The whole point of the split: `sig.Send/Recv/Context/On/OnCtx` and
        `WithCancel`/`WithTimeout` disappear, because `await` is cancellable."""
        for absent in ("cancel", "done", "deadline", "with_cancel", "with_timeout"):
            self.assertFalse(hasattr(Context(), absent), absent)


class CopyTest(unittest.TestCase):
    def test_with_identity_replaces_and_none_is_anonymous(self):
        ctx = Context()
        named = ctx.with_identity(NODE)
        self.assertEqual(named.identity, NODE)
        self.assertIsNone(ctx.identity)
        self.assertIsNone(named.with_identity(None).identity)

    def test_the_four_zone_verbs_match_astral_gos_bitmask_helpers(self):
        ctx = Context()
        self.assertEqual(ctx.with_zone(Zone.DEVICE).zone, Zone.DEVICE)
        self.assertEqual(
            Context(zone=Zone.DEVICE).include_zone(Zone.NETWORK).zone,
            Zone.DEVICE | Zone.NETWORK,
        )
        # Go's &^ : clear the named bits, keep the rest.
        self.assertEqual(ctx.exclude_zone(Zone.NETWORK).zone, Zone.DEVICE | Zone.VIRTUAL)
        # Go's & : narrow to the named bits.
        self.assertEqual(
            ctx.limit_zone(Zone.DEVICE | Zone.NETWORK).zone, Zone.DEVICE | Zone.NETWORK
        )
        self.assertEqual(ctx.zone, Zone.ALL)

    def test_the_zone_verbs_take_a_plain_integer(self):
        self.assertEqual(Context().with_zone(1).zone, Zone.DEVICE)
        self.assertEqual(Context().exclude_zone(4).zone, Zone.DEVICE | Zone.VIRTUAL)

    def test_with_filters_replaces_rather_than_accumulates(self):
        """astral-go's `WithFilters` assigns; a bare call clears."""
        ctx = Context().with_filters("a", "b")
        self.assertEqual(ctx.filters, ("a", "b"))
        self.assertEqual(ctx.with_filters("c").filters, ("c",))
        self.assertEqual(ctx.with_filters().filters, ())

    def test_add_filters_appends_without_duplicating(self):
        ctx = Context().with_filters("a").add_filters(["b", "a"])
        self.assertEqual(ctx.filters, ("a", "b"))

    def test_anonymous_drops_the_identity_and_the_network_zone(self):
        """astrald runs `ctx.ExcludeZone(ZoneNetwork)` for every token-less guest
        whatever the guest sent, so this is the zone that actually applies."""
        ctx = Context(identity=NODE, zone=Zone.ALL, filters=("f",)).anonymous()
        self.assertIsNone(ctx.identity)
        self.assertEqual(ctx.zone, Zone.DEVICE | Zone.VIRTUAL)
        self.assertEqual(ctx.filters, ("f",))


if __name__ == "__main__":
    unittest.main()
