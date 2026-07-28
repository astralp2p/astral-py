"""The `services` module client, and the bundle kind it proves.

Three tiers in one file, because the same claim is made at each and the three
must agree:

- **Tier A** pins the wire. `services.update` is the SDK's first record with a
  `bundle` in a pointer slot, and R-13 is exactly the question of whether that
  bundle decodes through the registry or stays opaque. Both vectors here are
  bytes the node produced, not bytes this SDK produced: the zero value comes
  from `objects.new?type=services.update` and the populated one came back from
  `objects.echo?strict=true`, which drops the unparsed-object fallback and so
  forces the node to decode through its own registry and re-encode from the
  decoded value.
- **Tier B** pins the two ops against `MockApphost`: the query string each one
  builds, the answer each one accepts, the shape each one declares, and the
  three faults that are the point of separating `discover` from
  `discover_follow` -- collecting past a separator, leaving a follow stream
  open, and sending `follow` on a `sync` that must answer.
- **Tier C** runs the read-only half against a real node, plus the two probes
  that settle R-13 live. `services.sync` is never called: it mutates the local
  registry (design section 7.3).

The op inventory is the live `shell.spec` registry and nothing else:
`services.discover` and `services.sync`, verified this session against
`furry-bolt`.
"""

from __future__ import annotations

import asyncio
import json
import unittest

import astral
from astral.api.services import (
    OP_DISCOVER,
    OP_SYNC,
    SERVICES_TYPES,
    Services,
    Update,
)
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import BadArgument, ProtocolError, RemoteError
from astral.object import Ack, Bundle, UnparsedObject
from astral.primitives import String8, Uint64
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive, Ptr
from astral.types import Identity

import live_support
from astral.api import services as services_module
from mock_apphost import (
    ACK,
    Accept,
    ErrorMsg,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    MockApphost,
    QUERY_ACCEPTED,
    ROUTE_QUERY,
    bounded,
    frame,
    socket_fds,
)

# --- vectors, all of them bytes the node sent ----------------------------

# `objects.new?type=services.update` on `furry-bolt`, whole frame. The node
# builds the zero value server-side and sends it, so the four zero bytes are
# four fields and not a coincidence of length.
LIVE_NEW_FRAME = bytes.fromhex(
    "0f" "73657276696365732e757064617465"  # string8 "services.update"
    "00000004"                             # bytes32 length
    "00"                                   # Available  bool false
    "00"                                   # Name       string8 ""
    "00"                                   # ProviderID ptr nil
    "00"                                   # Info       ptr nil
)

ZERO_UPDATE = bytes.fromhex("00000000")

# The payload `objects.echo?strict=true` returned for an update carrying a
# bundle. Byte for byte what this SDK sent, after the node decoded it through
# its own registry and re-encoded it from the decoded value.
LIVE_BUNDLE_UPDATE = bytes.fromhex(
    "01"                                    # Available true
    "07" "67617465776179"                   # Name string8 "gateway"
    "01" "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
    "01"                                    # Info present
    "00000002"                              # bundle: uint32 count
    "0000000e" "07" "737472696e6738" "05" "68656c6c6f"
    "0000000f" "06" "75696e743634" "0000000000000007"
)

# The whole body of `services.discover?follow=false` on a node with neither NAT
# nor gateway enabled: one `eos` frame and EOF. An empty answer is the ordinary
# answer, not a fault.
LIVE_EMPTY_DISCOVER_BODY = bytes.fromhex("03656f7300000000")


def update_frame(update: Update) -> tuple[str, bytes]:
    return ("services.update", payload_bytes(update))


NAT_UPDATE = Update(
    available=True, name="nat", provider_id=FURRY_BOLT, info=None
)
GATEWAY_UPDATE = Update(
    available=True, name="gateway", provider_id=FURRY_BOLT, info=None
)
GONE_UPDATE = Update(available=False, name="nat", provider_id=FURRY_BOLT, info=None)

ACK_FRAME = ("ack", b"")


def frame_error(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


# --- Tier A: the record, on the bytes the node sent ----------------------


class UpdateWireTest(unittest.TestCase):
    """`services.update` against the node's own frames."""

    def test_the_zero_value_the_node_built_decodes_to_four_absent_fields(self):
        """`objects.new` builds the zero value server-side, so this fixes the
        field count and the two nil flags without a live discoverer."""
        self.assertEqual(LIVE_NEW_FRAME[1:16], b"services.update")
        self.assertEqual(LIVE_NEW_FRAME[16:20], b"\x00\x00\x00\x04")
        self.assertEqual(LIVE_NEW_FRAME[20:], ZERO_UPDATE)

        u = Update.read_payload(object_reader(ZERO_UPDATE))
        self.assertEqual(u.available, False)
        self.assertEqual(u.name, "")
        self.assertIsNone(u.provider_id)
        self.assertIsNone(u.info)
        self.assertEqual(payload_bytes(u), ZERO_UPDATE)

    def test_the_bundle_carrying_update_decodes_through_the_registry(self):
        """R-13. The legacy SDK read a bundle as opaque bytes, which made every
        object a provider advertises unreachable from Python."""
        u = Update.read_payload(object_reader(LIVE_BUNDLE_UPDATE))
        self.assertEqual(u.available, True)
        self.assertEqual(u.name, "gateway")
        self.assertEqual(u.provider_id, FURRY_BOLT)
        self.assertIsInstance(u.info, Bundle)
        self.assertEqual(len(u.info), 2)
        self.assertEqual(list(u.info), [String8("hello"), Uint64(7)])
        self.assertIsInstance(list(u.info)[0], String8)
        self.assertIsInstance(list(u.info)[1], Uint64)

    def test_the_bundle_carrying_update_re_encodes_byte_for_byte(self):
        """Decode then encode is the identity on the bytes the node returned."""
        u = Update.read_payload(object_reader(LIVE_BUNDLE_UPDATE))
        self.assertEqual(payload_bytes(u), LIVE_BUNDLE_UPDATE)

    def test_the_identity_is_thirty_three_flat_bytes_behind_one_flag(self):
        """The `01` in front of the key belongs to the pointer slot. Modelling
        `identity` as a flag plus 33 bytes is the same 34 bytes here and a
        different 34 bytes wherever the slot is not a pointer."""
        self.assertEqual(LIVE_BUNDLE_UPDATE[9], 0x01)
        self.assertEqual(LIVE_BUNDLE_UPDATE[10:43], FURRY_BOLT.key)
        self.assertEqual(len(FURRY_BOLT.key), 33)

    def test_an_absent_bundle_and_an_empty_bundle_are_different_bytes(self):
        """One byte against five, so the two must not be conflated on decode.
        `Update.objects` conflates them on purpose and is documented as doing
        so; the field does not."""
        absent = Update(available=True, name="x", provider_id=None, info=None)
        empty = Update(available=True, name="x", provider_id=None, info=Bundle())
        self.assertEqual(payload_bytes(absent)[-1:], b"\x00")
        self.assertEqual(payload_bytes(empty)[-5:], b"\x01\x00\x00\x00\x00")
        self.assertNotEqual(payload_bytes(absent), payload_bytes(empty))
        self.assertEqual(absent.objects, ())
        self.assertEqual(empty.objects, ())
        self.assertIsNone(absent.info)
        self.assertIsNotNone(empty.info)

    def test_the_field_declaration_matches_the_go_struct(self):
        """Order, wire names and specs. `Info` is `Ptr("bundle")` and not a bare
        `Ref`: astral-go declares `Info *astral.Bundle`, so the nil flag is on
        the wire and a bare reference would be off by one byte for every
        update."""
        self.assertEqual(
            [(f.attr, f.wire_name, f.spec) for f in Update.FIELDS],
            [
                ("available", "Available", Primitive("bool")),
                ("name", "Name", Primitive("string8")),
                ("provider_id", "ProviderID", Ptr("identity")),
                ("info", "Info", Ptr("bundle")),
            ],
        )

    def test_the_type_name_carries_no_mod_prefix(self):
        """astral-go's `Update.ObjectType()` returns `services.update`. The
        registry name is what travels, so a `mod.` here would make every update
        frame undecodable. Design section 5.1 rule 6 lists the exception."""
        self.assertEqual(Update.ASTRAL_TYPE, "services.update")
        self.assertTrue(default_blueprints().has("services.update"))
        self.assertIs(default_blueprints().find("services.update"), Update)
        self.assertFalse(default_blueprints().has("mod.services.update"))

    def test_the_objects_view_reads_the_bundle_without_a_none_check(self):
        u = Update.read_payload(object_reader(LIVE_BUNDLE_UPDATE))
        self.assertEqual(list(u.objects), [String8("hello"), Uint64(7)])
        self.assertEqual(
            Update(
                available=False, name="", provider_id=None, info=None
            ).objects,
            (),
        )

    def test_an_unavailable_update_is_a_delta_and_carries_no_info(self):
        """astrald's own consumer reads it that way: `syncServices` creates a
        cache row when `Available` is set and deletes one otherwise."""
        u = Update.read_payload(object_reader(payload_bytes(GONE_UPDATE)))
        self.assertFalse(u.available)
        self.assertEqual(u.name, "nat")
        self.assertIsNone(u.info)

    def test_the_empty_discover_body_is_one_eos_frame(self):
        """The whole body of a live `services.discover?follow=false` on a node
        with neither discoverer enabled."""
        self.assertEqual(LIVE_EMPTY_DISCOVER_BODY, frame("eos"))


class ServicesTypesTest(unittest.TestCase):
    """The module's type sweep and its op constants."""

    def test_the_type_sweep_names_every_declared_type(self):
        self.assertEqual(tuple(SERVICES_TYPES), (Update,))
        self.assertEqual(tuple(Services.TYPES), (Update,))

    def test_the_op_names_carry_no_mod_prefix(self):
        """`mod.` is never part of an op name (design section 5.1 rule 6)."""
        self.assertEqual(OP_DISCOVER, "services.discover")
        self.assertEqual(OP_SYNC, "services.sync")

    def test_the_module_declares_the_whole_live_op_surface(self):
        """Two ops, which is the whole of `services` in the node's registry.
        Pinned here so a module that grows a third op without a client fails
        rather than silently offering half a surface; `LiveServicesTest` asserts
        the same set against the node itself."""
        ops = {
            value
            for name, value in vars(services_module).items()
            if name.startswith("OP_") and isinstance(value, str)
        }
        self.assertEqual(ops, {OP_DISCOVER, OP_SYNC})

    def test_every_op_has_a_method(self):
        """A module that implements half its ops is worse than an absent one,
        because a caller cannot tell which half works."""
        for name in ("discover", "discover_follow", "updates", "sync", "sync_follow"):
            with self.subTest(method=name):
                self.assertTrue(callable(getattr(Services, name)))


class QueryStringTest(unittest.TestCase):
    """What each op puts on the wire, before any transport is involved."""

    def test_discover_always_states_its_follow_flag(self):
        self.assertEqual(
            services_module._discover_query(follow=False),
            "services.discover?follow=false",
        )
        self.assertEqual(
            services_module._discover_query(follow=True),
            "services.discover?follow=true",
        )

    def test_follow_travels_as_true_and_false_and_never_as_yes(self):
        """The op's field is a plain Go `bool` and `query.FieldEditor` parses it
        with `strconv.ParseBool`, which refuses `yes` -- and a parse failure
        rejects the whole query before the op body runs. Verified live:
        `services.discover?follow=yes` raises `QueryRejected` with code 1.

        `true` and `false` are the two words both that parser and
        `astral.Bool.UnmarshalText` read, so the divergence is unreachable from
        here. Nothing outside this module chooses the value: `follow` is not a
        parameter of any public method, so a caller cannot supply a third word.
        """
        import inspect

        self.assertEqual(
            services_module._encode(services_module._DISCOVER, {"follow": True}),
            {"follow": "true"},
        )
        self.assertEqual(
            services_module._encode(services_module._DISCOVER, {"follow": False}),
            {"follow": "false"},
        )
        for name in ("discover", "discover_follow", "sync", "sync_follow"):
            with self.subTest(method=name):
                params = inspect.signature(getattr(Services, name)).parameters
                self.assertNotIn("follow", params)

    def test_sync_omits_follow_rather_than_sending_it_false(self):
        """Design section 5.1 rule 5: a server default stands while its key is
        absent."""
        self.assertEqual(
            services_module._sync_query("furry-bolt", follow=None),
            "services.sync?id=furry-bolt",
        )
        self.assertEqual(
            services_module._sync_query("furry-bolt", follow=False),
            "services.sync?id=furry-bolt",
        )
        self.assertEqual(
            services_module._sync_query("furry-bolt", follow=True),
            "services.sync?follow=true&id=furry-bolt",
        )

    def test_sync_takes_a_name_or_an_identity(self):
        """The op's field is a plain Go `string` resolved server-side, so an
        alias, `localnode`, a hex key or a directory name all reach it. An
        `Identity` travels as its text form and costs no resolving query."""
        self.assertEqual(
            services_module._sync_query("localnode", follow=None),
            "services.sync?id=localnode",
        )
        self.assertEqual(
            services_module._sync_query(FURRY_BOLT, follow=None),
            f"services.sync?id={FURRY_BOLT.text()}",
        )

    def test_the_parameters_go_through_their_declared_specs(self):
        """Design section 5.1 rule 2. Without the declaration the encoder
        dispatches on the value, and `id` is `string8` rather than `identity`
        because the op resolves this argument and a name is legitimate."""
        self.assertEqual(services_module._DISCOVER["follow"], Primitive("bool"))
        self.assertEqual(services_module._SYNC["id"], Primitive("string8"))
        self.assertEqual(services_module._SYNC["follow"], Primitive("bool"))

    def test_a_name_is_url_escaped(self):
        op, params = parse(services_module._sync_query("a b&c", follow=None))
        self.assertEqual(op, OP_SYNC)
        self.assertEqual(params, {"id": "a b&c"})


class ArgumentRefusalTest(unittest.TestCase):
    """What must never reach the node, refused where it is named."""

    def test_the_empty_id_is_refused_rather_than_sent(self):
        """astrald's resolver maps `""` to the zero identity, and
        `services.sync` mutates, so the accident costs the cached services of
        `anyone` rather than one wasted query."""
        with self.assertRaises(BadArgument) as caught:
            services_module._sync_query("", follow=None)
        self.assertIn(OP_SYNC, str(caught.exception))
        self.assertIn("Identity.ANYONE", str(caught.exception))

    def test_every_refusal_is_inside_the_hierarchy(self):
        for value in ("", None, 7):
            with self.subTest(value=value):
                with self.assertRaises(astral.AstralError):
                    services_module._sync_query(value, follow=None)
                with self.assertRaises(ValueError):
                    services_module._sync_query(value, follow=None)

    def test_the_zero_identity_is_reachable_on_purpose(self):
        """Refusing the empty name must not make `anyone` unnameable."""
        self.assertEqual(
            services_module._sync_query(Identity.ANYONE, follow=None),
            f"services.sync?id={Identity.ANYONE.text()}",
        )


# --- Tier B: the ops, against a mock apphost -----------------------------


class ServicesCase(unittest.IsolatedAsyncioTestCase):
    """A `Services` over a mock apphost, closed by the teardown whatever a test
    does."""

    async def asyncSetUp(self) -> None:
        self.clients: list[astral.Client] = []
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for client in self.clients:
            await client.aclose()
        await flush_cancels(5.0)

    def connector(self, mock: MockApphost):  # type: ignore[no-untyped-def]
        async def open_session() -> Session:
            return await Session.over(
                await mock.open(), endpoint="mem:mock", connector=open_session
            )

        return open_session

    async def services(self, mock: MockApphost, **kw: object) -> Services:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Services(client)

    def sent(self, mock: MockApphost) -> str:
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    def assert_no_faults(self, mock: MockApphost) -> None:
        self.assertEqual(mock.errors, [])


class DiscoverOpTest(ServicesCase):
    """`services.discover`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_typed_updates_and_states_follow_false(self):
        mock = MockApphost(
            routes={
                OP_DISCOVER: Accept(
                    objects=[update_frame(NAT_UPDATE), update_frame(GATEWAY_UPDATE)],
                    eos=True,
                )
            }
        )
        async with mock:
            s = await self.services(mock)
            got = await s.discover()
        self.assertEqual(got, [NAT_UPDATE, GATEWAY_UPDATE])
        self.assertTrue(all(isinstance(u, Update) for u in got))
        self.assertEqual(self.sent(mock), "services.discover?follow=false")
        self.assert_no_faults(mock)

    @bounded()
    async def test_an_empty_snapshot_is_an_empty_list_and_not_a_fault(self):
        """The ordinary answer on a node with neither NAT nor gateway enabled,
        verified live."""
        mock = MockApphost(routes={OP_DISCOVER: Accept(eos=True)})
        async with mock:
            s = await self.services(mock)
            self.assertEqual(await s.discover(), [])
        self.assert_no_faults(mock)

    @bounded()
    async def test_it_ends_at_a_bare_eof_as_well_as_at_an_eos(self):
        """`ch.Close()` after the final `eos` is astrald's shape, but a node that
        closed without one must not hang the caller."""
        mock = MockApphost(
            routes={OP_DISCOVER: Accept(objects=[update_frame(NAT_UPDATE)])}
        )
        async with mock:
            s = await self.services(mock)
            self.assertEqual(await s.discover(), [NAT_UPDATE])

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_DISCOVER: Accept(objects=[ACK_FRAME], eos=True)})
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(ProtocolError) as caught:
                await s.discover()
        self.assertIn(OP_DISCOVER, str(caught.exception))
        self.assertIn("services.update", str(caught.exception))

    @bounded()
    async def test_an_error_message_raises_rather_than_being_yielded(self):
        """astrald sends `ch.Send(astral.NewError(...))` when the discoverer
        fan-out fails, in place of the snapshot."""
        mock = MockApphost(
            routes={OP_DISCOVER: Accept(objects=[frame_error("no discoverers")])}
        )
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(RemoteError) as caught:
                await s.discover()
        self.assertIn("no discoverers", str(caught.exception))

    @bounded()
    async def test_a_rejected_query_surfaces_as_a_rejection(self):
        """A `follow` value neither parser accepts fails before the op body runs
        and the whole query is rejected -- verified live with `follow=yes`."""
        mock = MockApphost(routes={OP_DISCOVER: ErrorMsg("route_not_found")})
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(astral.RouteNotFound):
                await s.discover()

    @bounded()
    async def test_it_leaves_no_stream_open(self):
        mock = MockApphost(routes={OP_DISCOVER: Accept(eos=True)})
        async with mock:
            s = await self.services(mock)
            await s.discover()
            self.assertEqual(s.client.live_streams, 0)

    @bounded()
    async def test_the_query_keywords_reach_the_node(self):
        mock = MockApphost(routes={OP_DISCOVER: Accept(eos=True)})
        async with mock:
            s = await self.services(mock)
            await s.discover(zone=astral.Zone.DEVICE, timeout=5.0)
        self.assertEqual(mock.queries[-1].zone, int(astral.Zone.DEVICE))


class DiscoverFollowOpTest(ServicesCase):
    """`services.discover?follow=true`: ST+follow, the first `eos` is a
    separator."""

    def route(self) -> Accept:
        return Accept(
            objects=[update_frame(NAT_UPDATE)],
            eos=True,
            live=[update_frame(GATEWAY_UPDATE), update_frame(GONE_UPDATE)],
            hold=True,
        )

    @bounded()
    async def test_it_crosses_the_separator_and_marks_the_boundary(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            pairs = []
            async with s.discover_follow() as stream:
                async for obj, live in stream.follow():
                    pairs.append((obj, live))
                    if len(pairs) == 3:
                        break
        self.assertEqual(
            pairs,
            [(NAT_UPDATE, False), (GATEWAY_UPDATE, True), (GONE_UPDATE, True)],
        )
        self.assertEqual(self.sent(mock), "services.discover?follow=true")

    @bounded()
    async def test_snapshot_stops_at_the_separator_and_live_resumes_after_it(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            async with s.discover_follow() as stream:
                snapshot = [obj async for obj in stream.snapshot()]
                live = []
                async for obj in stream.live():
                    live.append(obj)
                    if len(live) == 2:
                        break
        self.assertEqual(snapshot, [NAT_UPDATE])
        self.assertEqual(live, [GATEWAY_UPDATE, GONE_UPDATE])

    @bounded()
    async def test_it_takes_the_persistent_lane_with_no_deadline(self):
        """The three requirements of follow mode have nothing to do with each
        other, so `Client.follow` pairs them once: `persistent=True`, because a
        follow stream never ends and a query permit spent on it is never
        returned, and `timeout=None`, because such a stream is idle for as long
        as nothing changes."""
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            ctx = s.discover_follow()
            self.assertEqual(ctx._kw["persistent"], True)
            self.assertIsNone(ctx._kw["timeout"])
            async with ctx as stream:
                self.assertEqual(s.client.live_streams, 1)
                self.assertEqual(s.client.available, s.client.max_concurrency)

    @bounded()
    async def test_a_caller_may_override_the_pairing(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            ctx = s.discover_follow(persistent=False, timeout=9.0)
            self.assertEqual(ctx._kw["persistent"], False)
            self.assertEqual(ctx._kw["timeout"], 9.0)
            async with ctx:
                pass

    @bounded()
    async def test_the_context_manager_closes_the_stream(self):
        """A follow stream holds one of the node's 32 workers for as long as it
        is open, and astrald never notices a peer that vanished."""
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            async with s.discover_follow() as stream:
                self.assertFalse(stream.closed)
            self.assertTrue(stream.closed)
            self.assertEqual(s.client.live_streams, 0)

    @bounded()
    async def test_an_exception_through_the_body_still_closes_the_stream(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(ZeroDivisionError):
                async with s.discover_follow() as stream:
                    raise ZeroDivisionError
            self.assertTrue(stream.closed)
            self.assertEqual(s.client.live_streams, 0)

    @bounded()
    async def test_collecting_a_follow_stream_is_refused_rather_than_truncated(self):
        """The reason `discover` and `discover_follow` are two methods rather
        than one boolean that silently changes the return type.

        `collect()` and `async for` stop at the first `eos`, and on a follow
        stream that `eos` is a boundary. Both therefore answered with the
        snapshot alone and dropped every live update **without saying so** -- a
        silent loss, which is what makes it worse than a hang. The stream now
        declares which shape it has, so both refuse and name `follow()`,
        `snapshot()` and `live()` instead.
        """
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            async with s.discover_follow() as stream:
                for what in ("collect", "aiter"):
                    with self.subTest(reader=what):
                        with self.assertRaises(ProtocolError) as caught:
                            if what == "collect":
                                await stream.collect(timeout=5.0)
                            else:
                                async for _ in stream:
                                    pass
                        self.assertIn("dropped in silence", str(caught.exception))
                # The declared reader still crosses the boundary.
                pairs = stream.follow()
                try:
                    self.assertEqual(await anext(pairs), (NAT_UPDATE, False))
                    self.assertEqual(await anext(pairs), (GATEWAY_UPDATE, True))
                finally:
                    await pairs.aclose()


class UpdatesIteratorTest(ServicesCase):
    """`Services.updates`: the pairs, with the closing built in."""

    def route(self) -> Accept:
        return Accept(
            objects=[update_frame(NAT_UPDATE)],
            eos=True,
            live=[update_frame(GATEWAY_UPDATE)],
            hold=True,
        )

    @bounded()
    async def test_it_yields_typed_pairs_across_the_boundary(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            pairs = []
            async for update, live in s.updates():
                pairs.append((update, live))
                if len(pairs) == 2:
                    break
        self.assertEqual(pairs, [(NAT_UPDATE, False), (GATEWAY_UPDATE, True)])
        self.assertEqual(self.sent(mock), "services.discover?follow=true")

    @bounded()
    async def test_breaking_out_of_the_loop_closes_the_stream(self):
        """An undrained follow stream is a node worker held for the life of the
        process, so the iterator owns the closing rather than the caller."""
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            async for _ in s.updates():
                break
            for _ in range(100):
                if s.client.live_streams == 0:
                    break
                await asyncio.sleep(0)
            self.assertEqual(s.client.live_streams, 0)

    @bounded()
    async def test_an_exception_through_the_loop_closes_the_stream(self):
        mock = MockApphost(routes={OP_DISCOVER: self.route()})
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(ZeroDivisionError):
                async for _ in s.updates():
                    raise ZeroDivisionError
            for _ in range(100):
                if s.client.live_streams == 0:
                    break
                await asyncio.sleep(0)
            self.assertEqual(s.client.live_streams, 0)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(
            routes={OP_DISCOVER: Accept(objects=[ACK_FRAME], eos=True, hold=True)}
        )
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(ProtocolError):
                async for _ in s.updates():
                    pass


class SyncOpTest(ServicesCase):
    """`services.sync`: RR, one `ack`. **Mutates**, so only the mock sees it."""

    @bounded()
    async def test_it_sends_the_id_and_reads_the_ack(self):
        mock = MockApphost(routes={OP_SYNC: Accept(objects=[ACK_FRAME])})
        async with mock:
            s = await self.services(mock)
            self.assertIsNone(await s.sync(FURRY_BOLT_ALIAS))
        self.assertEqual(self.sent(mock), f"services.sync?id={FURRY_BOLT_ALIAS}")
        self.assert_no_faults(mock)

    @bounded()
    async def test_it_never_sends_follow(self):
        """`follow=true` makes the op answer only after the caller cancels it,
        so an RR helper that sent it would wait forever."""
        mock = MockApphost(routes={OP_SYNC: Accept(objects=[ACK_FRAME])})
        async with mock:
            s = await self.services(mock)
            await s.sync("localnode")
        _, params = parse(self.sent(mock))
        self.assertNotIn("follow", params)

    @bounded()
    async def test_an_identity_travels_as_its_text_form(self):
        mock = MockApphost(routes={OP_SYNC: Accept(objects=[ACK_FRAME])})
        async with mock:
            s = await self.services(mock)
            await s.sync(FURRY_BOLT)
        self.assertEqual(self.sent(mock), f"services.sync?id={FURRY_BOLT.text()}")

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        """astrald answers this way when the identity does not resolve and when
        the sync itself fails."""
        mock = MockApphost(
            routes={OP_SYNC: Accept(objects=[frame_error("unknown identity: nope")])}
        )
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(RemoteError) as caught:
                await s.sync("nope")
        self.assertIn("unknown identity", str(caught.exception))

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(
            routes={OP_SYNC: Accept(objects=[update_frame(NAT_UPDATE)])}
        )
        async with mock:
            s = await self.services(mock)
            with self.assertRaises(ProtocolError) as caught:
                await s.sync("localnode")
        self.assertIn(OP_SYNC, str(caught.exception))

    @bounded()
    async def test_a_refused_id_never_reaches_the_node(self):
        async with MockApphost() as mock:
            s = await self.services(mock)
            for value in ("", None, 7):
                with self.subTest(value=value):
                    with self.assertRaises(astral.AstralError):
                        await s.sync(value)
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_it_leaves_no_stream_open(self):
        mock = MockApphost(routes={OP_SYNC: Accept(objects=[ACK_FRAME])})
        async with mock:
            s = await self.services(mock)
            await s.sync("localnode")
            self.assertEqual(s.client.live_streams, 0)


class SyncFollowOpTest(ServicesCase):
    """`services.sync?follow=true`: BD. The node answers only once cancelled."""

    @staticmethod
    def handler():  # type: ignore[no-untyped-def]
        """Accept, say nothing, then `ack` after the first inbound object.

        astrald's shape: `OpSync` parks a goroutine on `ch.Receive()` and
        cancels the sync on the first thing it reads, and the `ack` follows the
        cancellation.
        """

        async def route(conn, query):  # type: ignore[no-untyped-def]
            conn.send_frame(QUERY_ACCEPTED)
            await conn.flush()
            await conn.recv_frame()
            conn.send_frame(ACK)
            await conn.flush()
            await conn.aclose()

        return route

    @staticmethod
    def ended():  # type: ignore[no-untyped-def]
        """Accept, then close on the first inbound object without answering.

        The failed sync: astrald sent its `error_message` and closed, so there
        is no `ack` left for `stop_sync` to read.
        """

        async def route(conn, query):  # type: ignore[no-untyped-def]
            conn.send_frame(QUERY_ACCEPTED)
            await conn.flush()
            await conn.recv_frame()
            await conn.aclose()

        return route

    @bounded()
    async def test_it_states_follow_true_and_takes_the_persistent_lane(self):
        async with MockApphost(routes={OP_SYNC: self.handler()}) as mock:
            s = await self.services(mock)
            ctx = s.sync_follow(FURRY_BOLT_ALIAS)
            self.assertEqual(ctx._kw["persistent"], True)
            self.assertIsNone(ctx._kw["timeout"])
            async with ctx as stream:
                self.assertEqual(s.client.live_streams, 1)
                answer = await s.stop_sync(stream, timeout=5.0)
        # `bool`, not the payload-less `Ack` record: the value is one bit and
        # `Ack` is exported from neither `astral` nor this module.
        self.assertIs(answer, True)
        self.assertEqual(
            self.sent(mock), f"services.sync?follow=true&id={FURRY_BOLT_ALIAS}"
        )

    @bounded()
    async def test_stop_sync_sends_one_object_and_reads_the_ack(self):
        """Any object cancels the sync; `ack` is the one sent because it is the
        smallest frame and carries no payload to misread."""
        async with MockApphost(routes={OP_SYNC: self.handler()}) as mock:
            s = await self.services(mock)
            async with s.sync_follow("localnode") as stream:
                await s.stop_sync(stream, timeout=5.0)
            self.assertEqual(
                [t for t, _ in mock.connections[-1].received[-2:]],
                [ROUTE_QUERY, ACK],
            )

    @bounded()
    async def test_stop_sync_answers_false_when_the_op_already_ended(self):
        """A sync that failed sent its `error_message` and closed, so there is
        no `ack` left to read and the absence is not silent."""
        async with MockApphost(routes={OP_SYNC: self.ended()}) as mock:
            s = await self.services(mock)
            async with s.sync_follow("localnode") as stream:
                self.assertIs(await s.stop_sync(stream, timeout=5.0), False)

    @bounded()
    async def test_a_refused_id_never_reaches_the_node(self):
        async with MockApphost() as mock:
            s = await self.services(mock)
            with self.assertRaises(BadArgument):
                s.sync_follow("")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_context_manager_closes_the_stream(self):
        """Closing ends the sync too -- astrald's `ch.Receive()` errors and
        cancels -- and then no `ack` arrives, because there is nothing left to
        write it to."""
        async with MockApphost(routes={OP_SYNC: Accept(read=True)}) as mock:
            s = await self.services(mock)
            async with s.sync_follow("localnode") as stream:
                pass
            self.assertTrue(stream.closed)
            self.assertEqual(s.client.live_streams, 0)


class ModulePlumbingTest(ServicesCase):
    """The scaffolding `ModuleClient` carries, checked on this module."""

    @bounded()
    async def test_it_is_a_module_client_over_one_client(self):
        from astral.api.base import ModuleClient

        self.assertTrue(issubclass(Services, ModuleClient))
        self.assertIs(Services._expect, ModuleClient._expect)
        async with MockApphost() as mock:
            s = await self.services(mock)
            self.assertIs(s.client, s._c)
            self.assertIn("Services", repr(s))
            with self.assertRaises(ProtocolError) as caught:
                s._expect(Ack(), Update, "op")
            self.assertEqual(
                str(caught.exception), "op: expected 'services.update', got 'ack'"
            )

    @bounded()
    async def test_the_module_is_imported_by_the_api_package(self):
        """Importing `astral.api` must register every wire type, so a module
        without a line in `__init__.py` makes `services.update` decode in one
        program and raise `BlueprintNotFound` in another."""
        import sys

        import astral.api

        self.assertIn("astral.api.services", sys.modules)
        self.assertIs(astral.api.services, services_module)
        self.assertIs(astral.api.Services, Services)


# --- Tier C: the read-only half against a real node ----------------------


class LiveServicesTest(live_support.LiveCase):
    """`services` against a real node. Read-only.

    `services.sync` is never called from here: it clears the local cache for an
    identity and refills it over the network, which design section 7.3 puts
    outside the live tier entirely.

    Two probes here are not `services` ops. Both are on the anonymous read-only
    list and both exist because this node's `services.discover` answers an empty
    snapshot -- neither the NAT nor the gateway discoverer is enabled -- so the
    design's own settling probe for R-13 cannot see a populated frame.
    `objects.new` builds the zero value server-side and `objects.echo` makes the
    node decode and re-encode a populated one.
    """

    @bounded(30.0)
    async def test_the_module_s_op_surface_is_exactly_these_two(self):
        """`shell.spec` is the node's own op registry, so this is the inventory
        rather than a copy of it."""
        async with await self.client() as client:
            body = await client.call_raw("shell.spec?out=json", timeout=20.0)
        names = {
            json.loads(line)["Object"]["Name"]
            for line in body.decode().splitlines()
            if line and json.loads(line)["Type"] == "routing.op_spec"
        }
        self.assertEqual(
            {name for name in names if name.startswith("services.")},
            {OP_DISCOVER, OP_SYNC},
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_neither_op_enforces_a_required_argument(self):
        """`Required` is set only by a `query:"required"` struct tag, and
        `opSyncArgs.ID` carries none -- so an absent `id` reaches the op as the
        empty string and resolves to the zero identity. That is why `sync()`
        refuses an empty id client-side rather than relying on the node."""
        async with await self.client() as client:
            params = {}
            for op in (OP_DISCOVER, OP_SYNC):
                body = await client.call_raw(
                    f"shell.spec?op={op}&out=json", timeout=20.0
                )
                spec = json.loads(body.decode().splitlines()[0])["Object"]
                params[op] = [
                    (p["Name"], p["Type"], p["Required"]) for p in spec["Parameters"]
                ]
        self.assertEqual(
            params[OP_DISCOVER],
            [
                ("follow", "bool", False),
                ("in", "string8", False),
                ("out", "string8", False),
            ],
        )
        self.assertEqual(
            params[OP_SYNC],
            [
                ("id", "string8", False),
                ("follow", "bool", False),
                ("in", "string8", False),
                ("out", "string8", False),
            ],
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_discover_answers_a_list_of_updates_and_ends_at_an_eos(self):
        """An empty list is the ordinary answer here: astrald fans the op out to
        every module implementing `services.Discoverer`, and the two that do
        emit an update only while their own feature is enabled."""
        async with await self.client() as client:
            got = await Services(client).discover(timeout=20.0)
        self.assertIsInstance(got, list)
        for update in got:
            self.assertIsInstance(update, Update)
            self.assertIsInstance(update.name, str)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_discover_body_is_framed_objects_ending_in_one_eos(self):
        """The shape, off the raw body rather than off the decoded objects."""
        async with await self.client() as client:
            body = await client.call_raw(
                "services.discover?follow=false", timeout=20.0
            )
        self.assertTrue(body.endswith(frame("eos")), body.hex())
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_follow_stream_reaches_its_separator_and_closes_clean(self):
        """The separator is what `follow=true` changes, so the assertion is that
        the stream crosses it and stays open. The live half is bounded and the
        stream is closed on the way out: an undrained follow stream holds one of
        the node's 32 workers until the node restarts."""
        async with await self.client() as client:
            s = Services(client)
            async with s.discover_follow() as stream:
                snapshot = [obj async for obj in stream.snapshot()]
                self.assertTrue(stream.saw_eos)
                self.assertTrue(stream.is_live)
                live = []
                try:
                    async with asyncio.timeout(2.0):
                        async for obj in stream.live():
                            live.append(obj)
                except TimeoutError:
                    pass
            self.assertTrue(stream.closed)
            self.assertEqual(client.live_streams, 0)
        for update in snapshot + live:
            self.assertIsInstance(update, Update)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_nodes_zero_value_decodes_to_four_absent_fields(self):
        """R-13, first half: the field order and both nil flags, built by the
        node rather than by this SDK.

        One deliberate type, not a sweep. `services.Update.WriteTo` is
        `astral.Objectify(&s).WriteTo(w)`, pure reflection, and `ptrValue.WriteTo`
        writes `0x00` for a nil pointer without calling through it -- so the nil
        `*astral.Identity` that panics `mod.nodes.node_info`'s hand-written
        encoder cannot arise here.
        """
        async with await self.client() as client:
            body = await client.call_raw(
                "objects.new?type=services.update", timeout=20.0
            )
        self.assertEqual(body, LIVE_NEW_FRAME)
        u = Update.read_payload(object_reader(body[20:]))
        self.assertEqual(
            u, Update(available=False, name="", provider_id=None, info=None)
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_populated_update_round_trips_through_the_nodes_registry(self):
        """R-13, second half, and the whole of it: `Info` is a real `bundle`
        whose inner objects decode through the registry.

        `strict=true` drops the unparsed-object fallback, so the node must decode
        the frame through its own blueprints and re-encode it from the decoded
        value. Bytes back that equal bytes out are the reference implementation
        agreeing with this SDK's model. `objects.echo` stores nothing.
        """
        sent = Update(
            available=True,
            name="gateway",
            provider_id=FURRY_BOLT,
            info=Bundle([String8("hello"), Uint64(7)]),
        )
        self.assertEqual(payload_bytes(sent), LIVE_BUNDLE_UPDATE)
        async with await self.client() as client:
            async with client.stream(
                "objects.echo?strict=true&stop=eos", timeout=20.0
            ) as stream:
                await stream.send(sent, timeout=10.0)
                await stream.send_eos(timeout=10.0)
                got = [obj async for obj in stream]
        self.assertEqual(len(got), 1, got)
        self.assertNotIsInstance(got[0], UnparsedObject)
        self.assertEqual(got[0], sent)
        self.assertEqual(payload_bytes(got[0]), LIVE_BUNDLE_UPDATE)
        self.assertEqual(list(got[0].info), [String8("hello"), Uint64(7)])
        await self.assert_no_open_sockets()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
