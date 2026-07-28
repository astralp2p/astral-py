"""The `tree` module client: six ops, three tiers, and one design objection.

- **Tier A** pins what needs no node: the one wire type this module registers,
  the argument refusals, and the op-name constants.
- **Tier B** pins the six ops against `MockApphost` -- the query string each one
  builds, where each one puts its input, the answer each one accepts, and the
  two reference bugs neither may reproduce: astral-docs' capitalised `-Recursive`
  and `-Type`/`-Value`, which the node drops silently (D-17), and astral-go's
  `Node.Create`, which never reads its response (G-11).
- **Tier C** runs the two read-only ops against a real node. Five of the six ops
  mutate and no live test calls one; the config tree is somebody's running
  configuration.

The objection this file exists to pin is `tree.get` with `follow`. Design
section 4.7 lists it as ST+follow, whose first `eos` is a snapshot/live
separator. The op sends no separator: its single `eos` is the terminator, so
`Stream.follow()` reads past it and waits forever while `async for` stops
exactly there. `FollowShapeTest` asserts both halves against the mock, and
`LiveTreeTest` asserts the live half -- one value, then silence, no `eos`.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import unittest

import astral
from astral.api import tree as tree_module
from astral.api.tree import (
    ErrNoValue,
    OP_DELETE,
    OP_GET,
    OP_LIST,
    OP_MOUNT_REMOTE,
    OP_SET,
    OP_UNMOUNT,
    ROOT,
    TREE_TYPES,
    Tree,
)
from astral.client import Client, connect
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.jsoncodec import envelope
from astral.errors import (
    BadArgument,
    BadArgumentType,
    BlueprintNotFound,
    ProtocolError,
    RemoteError,
)
from astral.object import Ack, Nil, UnparsedObject
from astral.primitives import Bool, String8
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.types import Identity
from astral.wire import Writer

import live_support
import reference
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    MockApphost,
    MockConn,
    RouteQuery,
    bounded,
    frame,
    socket_fds,
)


# --- frames --------------------------------------------------------------


def frame_string8(value: str) -> tuple[str, bytes]:
    w = Writer()
    w.string8(value)
    return ("string8", w.getvalue())


def frame_error(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


OTHER = Identity.parse("02" + "aa" * 32)
"""A second node, so the routing target is distinguishable from the mount's."""

ACK_FRAME = ("ack", b"")
EOS_FRAME = ("eos", b"")
NIL_FRAME = ("nil", b"")
TRUE_FRAME = ("bool", b"\x01")
UNKNOWN_FRAME = ("mod.nearby.mode", b"\x00")


def switch(*replies: tuple[str, bytes]):  # type: ignore[no-untyped-def]
    """astrald's batch `ch.Switch`: read one object, answer one, `BreakOnEOS`.

    `tree.set` without a `value` argument has exactly this shape
    (`astral-go/api/tree/client/server.go:132`), and a canned `Accept` cannot
    model it: `MockApphost` writes an `Accept` body and closes at once, while
    the op writes its input **after** the query has been accepted, so the two
    race and the client's frames are dropped.

    Replies are consumed in order, one per input object. An input past the last
    reply is read and left unanswered, which is how a short-answering op is
    tested.
    """

    async def handler(conn: MockConn, query: RouteQuery) -> None:
        conn.send_raw(frame("mod.apphost.query_accepted_msg"))
        await conn.flush()
        pending = list(replies)
        while True:
            received = await conn.recv_frame_or_none()
            if received is None or received[0] == "eos":
                break
            if pending:
                conn.send_frame(*pending.pop(0))
                await conn.flush()
        await conn.aclose()

    return handler


def refuse(message: str):  # type: ignore[no-untyped-def]
    """The batch shape that fails before it reads: the path walk did not resolve.

    astrald answers `astral.Err` and returns without reading anything
    (`astral-go/api/tree/client/server.go:129`). The body is drained here anyway
    so the client's `eos` does not meet a closed socket -- a reset would destroy
    the very message this route exists to deliver.
    """

    async def handler(conn: MockConn, query: RouteQuery) -> None:
        conn.send_raw(frame("mod.apphost.query_accepted_msg"))
        conn.send_frame(*frame_error(message))
        await conn.flush()
        while await conn.recv_frame_or_none() is not None:
            pass
        await conn.aclose()

    return handler


# --- Tier A: what needs no node ------------------------------------------


class ErrNoValueTest(unittest.TestCase):
    """The one wire type this module registers, and the one it never receives."""

    def test_it_is_registered_under_its_wire_name(self):
        registry = default_blueprints()
        self.assertTrue(registry.has("mod.tree.err_no_value"))
        self.assertIsInstance(registry.new("mod.tree.err_no_value"), ErrNoValue)

    def test_its_payload_is_empty_in_both_directions(self):
        self.assertEqual(payload_bytes(ErrNoValue()), b"")
        self.assertEqual(ErrNoValue.read_payload(object_reader(b"")), ErrNoValue())

    def test_its_json_object_is_null_and_not_an_empty_mapping(self):
        """astral-go embeds `astral.EmptyObject`, which marshals to `null`; the
        docs page prints `{"Type": "mod.tree.err_no_value", "Object": null}`. A
        zero-field record would print `{}` here and have no text form at all."""
        self.assertEqual(
            envelope(ErrNoValue()),
            {"Type": "mod.tree.err_no_value", "Object": None},
        )
        self.assertEqual(ErrNoValue().text(), "")

    def test_the_module_declares_exactly_this_one_type(self):
        self.assertEqual(tuple(TREE_TYPES), (ErrNoValue,))
        self.assertEqual(tuple(Tree.TYPES), (ErrNoValue,))


class ConstantTest(unittest.TestCase):
    """The op names, spelled as the live registry spells them."""

    def test_the_six_op_names_carry_no_mod_prefix(self):
        self.assertEqual(
            [OP_DELETE, OP_GET, OP_LIST, OP_MOUNT_REMOTE, OP_SET, OP_UNMOUNT],
            [
                "tree.delete",
                "tree.get",
                "tree.list",
                "tree.mount_remote",
                "tree.set",
                "tree.unmount",
            ],
        )

    def test_root_is_the_slash_the_node_defaults_to(self):
        self.assertEqual(ROOT, "/")


class ArgumentRefusalTest(unittest.TestCase):
    """What never reaches the wire, and why each one would be worse if it did."""

    def test_an_empty_path_is_refused_for_every_op_that_takes_one(self):
        """The walk strips one leading slash and skips empty segments, so the
        empty path addresses the root. A caller that passed an unset variable
        would read, write or delete the root rather than fail."""
        with self.assertRaises(BadArgument) as caught:
            tree_module._path("", OP_GET)
        self.assertIn("addresses the root", str(caught.exception))
        self.assertIsInstance(caught.exception, ValueError)

    def test_a_non_string_path_is_a_type_error_inside_the_hierarchy(self):
        with self.assertRaises(BadArgumentType):
            tree_module._path(7, OP_GET)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            tree_module._path(None, OP_GET)  # type: ignore[arg-type]

    def test_a_path_that_is_only_a_slash_is_allowed(self):
        """The root is a legitimate argument to `list` and a clear error from
        `get`; refusing it here would hide the node's own message."""
        self.assertEqual(tree_module._path(ROOT, OP_LIST), "/")

    def test_an_empty_mount_target_is_refused(self):
        with self.assertRaises(BadArgument) as caught:
            tree_module._target("", OP_MOUNT_REMOTE)
        self.assertIn("zero identity", str(caught.exception))

    def test_an_identity_target_travels_as_its_hex_text(self):
        self.assertEqual(
            tree_module._target(FURRY_BOLT, OP_MOUNT_REMOTE), FURRY_BOLT.text()
        )
        self.assertEqual(
            tree_module._target(FURRY_BOLT_ALIAS, OP_MOUNT_REMOTE), FURRY_BOLT_ALIAS
        )

    def test_a_non_identity_target_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            tree_module._target(7, OP_MOUNT_REMOTE)  # type: ignore[arg-type]


# --- Tier B: the six ops against the mock --------------------------------


class TreeCase(unittest.IsolatedAsyncioTestCase):
    """A `Tree` over a mock apphost, closed by the teardown whatever a test does."""

    async def asyncSetUp(self) -> None:
        self.clients: list[Client] = []
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

    async def client(self, mock: MockApphost, **kw: object) -> Client:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return client

    async def tree(self, mock: MockApphost, **kw: object) -> Tree:
        return Tree(await self.client(mock, **kw))

    def sent(self, mock: MockApphost) -> str:
        """The one query string the mock received."""
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    @staticmethod
    def body(mock: MockApphost) -> list[tuple[str, bytes]]:
        """The frames the mock received on the accepted query's body.

        Everything up to and including the `route_query_msg` is the session
        handshake; what follows is what the op would have read.
        """
        received = mock.connections[-1].received
        for index, (type_name, _) in enumerate(received):
            if type_name == "mod.apphost.route_query_msg":
                return received[index + 1 :]
        return []


class GetTest(TreeCase):
    """`tree.get`: one object, then `eos`."""

    @bounded()
    async def test_it_sends_the_path_and_returns_the_stored_object(self):
        mock = MockApphost(routes={OP_GET: Accept(objects=[TRUE_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            value = await t.get("/mod/tcp/settings/listen")
        self.assertEqual(value, Bool(True))
        self.assertEqual(
            self.sent(mock), f"{OP_GET}?path=%2Fmod%2Ftcp%2Fsettings%2Flisten"
        )
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_a_value_less_node_answers_nil_and_nil_is_returned(self):
        """astrald substitutes `&astral.Nil{}` for a row with no type. `Nil()` is
        truthy, so it is returned rather than collapsed to `None`: `nil` is a
        registered type and its tag is part of the wire contract."""
        mock = MockApphost(routes={OP_GET: Accept(objects=[NIL_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            value = await t.get("/mod")
        self.assertIsInstance(value, Nil)
        self.assertTrue(value)

    @bounded()
    async def test_an_unknown_value_type_arrives_unparsed_by_default(self):
        """Any module may store any object, so the value's type is not this op's
        to declare. Verified live: `/mod/nearby/mode` holds a `mod.nearby.mode`
        and the client default fails that read."""
        mock = MockApphost(routes={OP_GET: Accept(objects=[UNKNOWN_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            value = await t.get("/mod/nearby/mode")
        self.assertIsInstance(value, UnparsedObject)
        self.assertEqual(value.ASTRAL_TYPE, "mod.nearby.mode")
        self.assertEqual(value.payload, b"\x00")

    @bounded()
    async def test_allow_unparsed_false_restores_the_failure(self):
        mock = MockApphost(routes={OP_GET: Accept(objects=[UNKNOWN_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BlueprintNotFound):
                await t.get("/mod/nearby/mode", allow_unparsed=False)

    @bounded()
    async def test_a_missing_path_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[frame_error("node nope not found in /")])}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError) as caught:
                await t.get("/nope")
        self.assertIn("not found", str(caught.exception))

    @bounded()
    async def test_a_second_object_is_a_protocol_error(self):
        """The op stores one value per node, so two objects before the `eos`
        would make this call's single return value a lie about the second."""
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[TRUE_FRAME, NIL_FRAME], eos=True)}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError):
                await t.get("/x")

    @bounded()
    async def test_an_empty_path_never_reaches_the_node(self):
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument):
                await t.get("")
            self.assertEqual(mock.queries, [])


class FollowShapeTest(TreeCase):
    """The design objection, as two assertions on the same bytes.

    `tree.get` with `follow` sends the current value, then one object per
    change, then a single `eos` when the stream ends. Design section 4.7 calls
    that first `eos` a snapshot/live separator. It is not one.
    """

    @bounded()
    async def test_the_query_carries_follow_true_and_the_keys_are_sorted(self):
        mock = MockApphost(
            routes={
                f"{OP_GET}?follow=true&path=%2Fx": Accept(
                    objects=[TRUE_FRAME], eos=True
                )
            }
        )
        async with mock:
            t = await self.tree(mock)
            async with t.get_follow("/x") as stream:
                self.assertEqual([o async for o in stream], [Bool(True)])
        self.assertEqual(self.sent(mock), f"{OP_GET}?follow=true&path=%2Fx")

    @bounded()
    async def test_async_for_yields_every_value_and_stops_at_the_eos(self):
        """The reader this op declares. The `eos` terminates it, so the loop
        ends by itself and the stream closes on the way out of the block."""
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[TRUE_FRAME, NIL_FRAME], eos=True, hold=True)}
        )
        async with mock:
            t = await self.tree(mock)
            async with t.get_follow("/x") as stream:
                got = [o async for o in stream]
        self.assertEqual(got, [Bool(True), Nil()])

    @bounded()
    async def test_the_three_separator_readers_are_refused_rather_than_hanging(self):
        """The rule the module docstring states, enforced by the stream itself.

        Read through the ST+follow iterators these bytes classify every object as
        snapshot, cross the **terminating** `eos`, and then wait for a live
        object no `tree.get` ever sends: a deadline was the only thing that ended
        it, and until it expired the caller held one of the node's 32 workers.
        `get_follow` declares `separator=False`, so all three refuse at once and
        name the reader that works.
        """
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[TRUE_FRAME], eos=True, hold=True)}
        )
        async with mock:
            t = await self.tree(mock)
            async with t.get_follow("/x") as stream:
                for what, reader in (
                    ("follow()", stream.follow),
                    ("snapshot()", stream.snapshot),
                    ("live()", stream.live),
                ):
                    with self.subTest(reader=what):
                        with self.assertRaises(ProtocolError) as caught:
                            iterator = reader()
                            await anext(iterator)  # noqa: F821 -- 3.10+ builtin
                        message = str(caught.exception)
                        self.assertIn("sends none", message)
                        self.assertIn("async for", message)
                # And the reader the op does declare still works.
                self.assertEqual([o async for o in stream], [Bool(True)])

    @bounded()
    async def test_a_follow_stream_is_billed_to_the_persistent_lane(self):
        """A stream that never ends must not hold a query permit: the permit is
        returned on close and a follow stream is not closed until the caller says
        so."""
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[TRUE_FRAME], eos=True, hold=True)}
        )
        async with mock:
            t = await self.tree(mock)
            client = self.clients[-1]
            async with t.get_follow("/x"):
                self.assertEqual(client.available, 8)
                self.assertEqual(client.available_persistent, 3)
                self.assertEqual(client.live_streams, 1)
            self.assertEqual(client.available_persistent, 4)
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_the_caller_may_override_both_defaults(self):
        mock = MockApphost(
            routes={OP_GET: Accept(objects=[TRUE_FRAME], eos=True)}
        )
        async with mock:
            t = await self.tree(mock)
            client = self.clients[-1]
            async with t.get_follow("/x", persistent=False, timeout=5.0) as stream:
                self.assertEqual(client.available, 7)
                self.assertEqual(client.available_persistent, 4)
                self.assertEqual([o async for o in stream], [Bool(True)])

    @bounded()
    async def test_an_empty_path_is_refused_before_the_query_is_built(self):
        """`follow` is a plain `def` returning a context manager, so the refusal
        has to happen when it is called and not when it is entered."""
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument):
                t.get_follow("")
            self.assertEqual(mock.queries, [])


class ListTest(TreeCase):
    """`tree.list`: sorted names, terminated by `eos`."""

    @bounded()
    async def test_it_defaults_to_the_root_and_sends_it(self):
        mock = MockApphost(
            routes={OP_LIST: Accept(objects=[frame_string8("mod")], eos=True)}
        )
        async with mock:
            t = await self.tree(mock)
            names = await t.list()
        self.assertEqual(names, ["mod"])
        self.assertEqual(self.sent(mock), f"{OP_LIST}?path=%2F")

    @bounded()
    async def test_it_returns_plain_strings_in_the_order_the_node_sent(self):
        """The node sorts; nothing here re-sorts, so a node that stopped sorting
        is visible rather than hidden."""
        names = ["indexing", "kcp", "log", "nat", "nearby", "tcp", "tor", "user"]
        mock = MockApphost(
            routes={
                OP_LIST: Accept(objects=[frame_string8(n) for n in names], eos=True)
            }
        )
        async with mock:
            t = await self.tree(mock)
            got = await t.list("/mod")
        self.assertEqual(got, names)
        self.assertTrue(all(type(n) is str for n in got))
        self.assertEqual(self.sent(mock), f"{OP_LIST}?path=%2Fmod")

    @bounded()
    async def test_a_node_with_no_subnodes_is_an_empty_list(self):
        mock = MockApphost(routes={OP_LIST: Accept(eos=True)})
        async with mock:
            t = await self.tree(mock)
            self.assertEqual(await t.list("/mod/nearby/mode"), [])

    @bounded()
    async def test_an_answer_that_is_not_a_string8_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_LIST: Accept(objects=[TRUE_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError) as caught:
                await t.list("/mod")
        self.assertIn(OP_LIST, str(caught.exception))

    @bounded()
    async def test_a_missing_path_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_LIST: Accept(objects=[frame_error("node nope not found in /")])}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.list("/nope")


class SetTest(TreeCase):
    """`tree.set` in batch mode: the object goes on the body, not in the query."""

    @bounded()
    async def test_the_object_goes_on_the_body_and_the_query_carries_only_the_path(self):
        """The single most common way to get an op wrong is passing channel-body
        input as a query argument (design section 4.7). A `value` in the query
        string would switch the node to the text branch and parse the object's
        repr."""
        mock = MockApphost(routes={OP_SET: switch(ACK_FRAME)})
        async with mock:
            t = await self.tree(mock)
            await t.set("/tmp/mykey", String8("hello"))
        self.assertEqual(self.sent(mock), f"{OP_SET}?path=%2Ftmp%2Fmykey")
        self.assertEqual(parse(self.sent(mock))[1], {"path": "/tmp/mykey"})
        self.assertEqual(
            self.body(mock),
            [("string8", payload_bytes(String8("hello"))), EOS_FRAME],
        )

    @bounded()
    async def test_an_empty_string8_is_storable_this_way_and_only_this_way(self):
        """The text form cannot store one: an empty `value` is the node's own
        batch-mode switch."""
        mock = MockApphost(routes={OP_SET: switch(ACK_FRAME)})
        async with mock:
            t = await self.tree(mock)
            await t.set("/tmp/mykey", String8(""))
        self.assertEqual(self.body(mock), [("string8", b"\x00"), EOS_FRAME])

    @bounded()
    async def test_a_batch_is_one_query_one_eos_and_one_ack_per_object(self):
        mock = MockApphost(routes={OP_SET: switch(ACK_FRAME, ACK_FRAME, ACK_FRAME)})
        async with mock:
            t = await self.tree(mock)
            await t.set_many("/tmp/k", [Bool(True), Bool(False), Nil()])
        self.assertEqual(len(mock.queries), 1)
        self.assertEqual(
            self.body(mock),
            [("bool", b"\x01"), ("bool", b"\x00"), ("nil", b""), EOS_FRAME],
        )

    @bounded()
    async def test_a_short_answer_list_is_a_protocol_error(self):
        """The op answers once per object and keeps reading, so a missing answer
        is the op having stopped; pairing the answers against the inputs after
        that would pair the wrong ones."""
        mock = MockApphost(routes={OP_SET: switch(ACK_FRAME)})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError) as caught:
                await t.set_many("/tmp/k", [Bool(True), Bool(False)])
        self.assertIn("2 object(s)", str(caught.exception))

    @bounded()
    async def test_a_failed_write_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_SET: switch(frame_error("root node cannot hold a value"))}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.set("/", Bool(True))

    @bounded()
    async def test_an_answer_that_is_not_an_ack_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_SET: switch(TRUE_FRAME)})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError):
                await t.set("/tmp/k", Bool(True))

    @bounded()
    async def test_an_empty_batch_names_create_and_sends_nothing(self):
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument) as caught:
                await t.set_many("/tmp/k", [])
            self.assertEqual(mock.queries, [])
        self.assertIn("create", str(caught.exception))


class SetTextTest(TreeCase):
    """`tree.set` in text mode, and the two names astral-docs gets wrong."""

    @bounded()
    async def test_the_arguments_are_lowercase_type_and_value(self):
        """Bug D-17. astral-docs writes `-Type` and `-Value`; parameter matching
        is case-sensitive and an unknown key is dropped without a word, so the
        documented invocation stores nothing and prints an `ack`."""
        mock = MockApphost(routes={OP_SET: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.set_text("/tmp/mykey", "hello", type="string8")
        sent = self.sent(mock)
        self.assertEqual(sent, f"{OP_SET}?path=%2Ftmp%2Fmykey&type=string8&value=hello")
        _, params = parse(sent)
        self.assertEqual(params, {"path": "/tmp/mykey", "type": "string8", "value": "hello"})
        self.assertNotIn("Type", params)
        self.assertNotIn("Value", params)
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_an_omitted_type_omits_the_key_rather_than_sending_it_empty(self):
        """An absent `type` is the node's inference branch, which reads the
        node's current value; `type=` would be the same branch by accident and a
        different query string."""
        mock = MockApphost(routes={OP_SET: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.set_text("/tmp/mykey", "true")
        self.assertEqual(self.sent(mock), f"{OP_SET}?path=%2Ftmp%2Fmykey&value=true")

    @bounded()
    async def test_an_empty_value_is_refused_and_names_the_form_that_works(self):
        """The node routes to the text branch only when the value is non-empty,
        so `value=` enters batch mode and waits for an object that never comes."""
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument) as caught:
                await t.set_text("/tmp/k", "", type="string8")
            self.assertEqual(mock.queries, [])
        self.assertIn("batch mode", str(caught.exception))

    @bounded()
    async def test_an_empty_type_is_refused(self):
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument):
                await t.set_text("/tmp/k", "x", type="")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_value_the_node_cannot_parse_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_SET: Accept(objects=[frame_error("unknown object type: nope")])}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.set_text("/tmp/k", "x", type="nope")


class CreateTest(TreeCase):
    """`tree.set` with an empty body, and the astral-go bug it must not repeat."""

    @bounded()
    async def test_it_sends_the_eos_and_reads_the_stream_to_its_end(self):
        """Bug G-11. astral-go's `Node.Create` opens the query and returns
        without reading, so a creation that failed reports success. The `eos` is
        what lets the node finish, and the read is what surfaces the failure."""
        mock = MockApphost(routes={OP_SET: switch()})
        async with mock:
            t = await self.tree(mock)
            await t.create("/tmp/newdir")
        self.assertEqual(self.sent(mock), f"{OP_SET}?path=%2Ftmp%2Fnewdir")
        self.assertEqual(self.body(mock), [EOS_FRAME])

    @bounded()
    async def test_a_failed_walk_raises_instead_of_reporting_success(self):
        mock = MockApphost(routes={OP_SET: refuse("node has subnodes")})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError) as caught:
                await t.create("/tmp/newdir")
        self.assertIn("node has subnodes", str(caught.exception))

    @bounded()
    async def test_an_ack_is_tolerated_and_a_wrong_type_is_not(self):
        """Zero objects earn zero answers on this node; a node that
        acknowledged the empty batch would not be breaking the op's contract, and
        one that answered a `bool` would be."""
        mock = MockApphost(routes={OP_SET: Accept(objects=[ACK_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            await t.create("/tmp/newdir")
        mock = MockApphost(routes={OP_SET: Accept(objects=[TRUE_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError):
                await t.create("/tmp/newdir")


class DeleteTest(TreeCase):
    """`tree.delete`, and the flag astral-docs spells so that it never arrives."""

    @bounded()
    async def test_a_plain_delete_sends_the_path_alone(self):
        mock = MockApphost(routes={OP_DELETE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            self.assertIsNone(await t.delete("/tmp/mykey"))
        self.assertEqual(self.sent(mock), f"{OP_DELETE}?path=%2Ftmp%2Fmykey")

    @bounded()
    async def test_the_recursive_flag_is_lowercase_and_only_sent_when_true(self):
        """Bug D-17. `tree.delete -Recursive` is dropped by the node's
        case-sensitive matching, so the documented recursive delete has never
        once descended -- and it prints an `ack` either way, so nothing says so.
        """
        mock = MockApphost(routes={OP_DELETE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.delete("/tmp/mydir", recursive=True)
        sent = self.sent(mock)
        self.assertEqual(sent, f"{OP_DELETE}?path=%2Ftmp%2Fmydir&recursive=true")
        _, params = parse(sent)
        self.assertEqual(params["recursive"], "true")
        self.assertNotIn("Recursive", params)

    @bounded()
    async def test_a_node_with_subnodes_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_DELETE: Accept(objects=[frame_error("node has subnodes")])}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.delete("/mod")

    @bounded()
    async def test_an_answer_that_is_not_an_ack_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_DELETE: Accept(objects=[TRUE_FRAME])})
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(ProtocolError):
                await t.delete("/tmp/k")


class MountRemoteTest(TreeCase):
    """`tree.mount_remote`: two required arguments and one optional root."""

    @bounded()
    async def test_it_sends_path_and_target_with_the_keys_sorted(self):
        mock = MockApphost(routes={OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.mount_remote("/remote/peer", FURRY_BOLT_ALIAS)
        self.assertEqual(
            self.sent(mock),
            f"{OP_MOUNT_REMOTE}?path=%2Fremote%2Fpeer&target={FURRY_BOLT_ALIAS}",
        )

    @bounded()
    async def test_the_routing_target_is_reachable_and_is_not_the_mount_target(self):
        """The op's own remote node is `node`; `target` still routes.

        This op is the one place in the SDK where the two are different nodes,
        and the parameter used to be called `target`, so it ate the routing
        keyword: `mount_remote(p, X)` put X in the query string and routed to the
        local node, with no way to reach the routing target on this op at all.
        """
        mock = MockApphost(routes={OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.mount_remote("/remote/peer", "somenode", target=OTHER)
        self.assertEqual(
            self.sent(mock),
            f"{OP_MOUNT_REMOTE}?path=%2Fremote%2Fpeer&target=somenode",
        )
        self.assertEqual(
            mock.queries[-1].target,
            OTHER,
            "the routing target did not reach route_query_msg",
        )

    @bounded()
    async def test_an_identity_target_travels_as_hex(self):
        mock = MockApphost(routes={OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.mount_remote("/remote/peer", FURRY_BOLT)
        self.assertIn(f"target={FURRY_BOLT.hex()}", self.sent(mock))

    @bounded()
    async def test_the_root_is_sent_only_when_given(self):
        mock = MockApphost(routes={OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            await t.mount_remote("/remote/peer", "somenode", root="/mod")
        sent = self.sent(mock)
        _, params = parse(sent)
        self.assertEqual(
            params, {"path": "/remote/peer", "root": "/mod", "target": "somenode"}
        )
        self.assertEqual(
            sent,
            f"{OP_MOUNT_REMOTE}?path=%2Fremote%2Fpeer&root=%2Fmod&target=somenode",
        )

    @bounded()
    async def test_an_empty_target_never_reaches_the_node(self):
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(BadArgument):
                await t.mount_remote("/remote/peer", "")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_unresolvable_target_raises_the_error_message(self):
        mock = MockApphost(
            routes={
                OP_MOUNT_REMOTE: Accept(objects=[frame_error("unknown identity: nope")])
            }
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.mount_remote("/remote/peer", "nope")


class UnmountTest(TreeCase):
    """`tree.unmount`: one argument, one `ack`."""

    @bounded()
    async def test_it_sends_the_path_and_reads_the_ack(self):
        mock = MockApphost(routes={OP_UNMOUNT: Accept(objects=[ACK_FRAME])})
        async with mock:
            t = await self.tree(mock)
            self.assertIsNone(await t.unmount("/remote/peer"))
        self.assertEqual(self.sent(mock), f"{OP_UNMOUNT}?path=%2Fremote%2Fpeer")

    @bounded()
    async def test_a_path_that_is_not_a_mount_point_raises(self):
        mock = MockApphost(
            routes={OP_UNMOUNT: Accept(objects=[frame_error("mount point does not exist")])}
        )
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(RemoteError):
                await t.unmount("/nowhere")


class TreePlumbingTest(TreeCase):
    """What every op shares."""

    @bounded()
    async def test_query_keywords_reach_the_client(self):
        mock = MockApphost(routes={OP_GET: Accept(objects=[TRUE_FRAME], eos=True)})
        async with mock:
            t = await self.tree(mock)
            await t.get("/x", target=FURRY_BOLT, timeout=5.0)
        self.assertEqual(mock.queries[0].target, FURRY_BOLT)

    @bounded()
    async def test_an_unrouted_op_is_route_not_found(self):
        mock = MockApphost()
        async with mock:
            t = await self.tree(mock)
            with self.assertRaises(astral.RouteNotFound):
                await t.list()

    @bounded()
    async def test_every_op_closes_its_stream(self):
        """A stream left open burns one of the node's 32 workers permanently
        (astrald bug G-13)."""
        mock = MockApphost(
            routes={
                OP_GET: Accept(objects=[TRUE_FRAME], eos=True),
                OP_LIST: Accept(objects=[frame_string8("mod")], eos=True),
                OP_SET: switch(ACK_FRAME),
                OP_DELETE: Accept(objects=[ACK_FRAME]),
                OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME]),
                OP_UNMOUNT: Accept(objects=[ACK_FRAME]),
            }
        )
        async with mock:
            t = await self.tree(mock)
            client = self.clients[-1]
            await t.get("/x")
            await t.list("/x")
            await t.set("/x", Bool(True))
            await t.delete("/x")
            await t.mount_remote("/x", "peer")
            await t.unmount("/x")
            async with t.get_follow("/x"):
                pass
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available, 8)
            self.assertEqual(client.available_persistent, 4)
        self.assertEqual(len(mock.queries), 7)

    @bounded()
    async def test_no_op_ever_sends_a_capitalised_parameter_key(self):
        """Bug D-17 as a sweep rather than a case: the node's matching is
        case-sensitive and an unknown key is dropped in silence, so a capitalised
        key is an argument that has never once arrived."""
        mock = MockApphost(
            routes={
                OP_GET: Accept(objects=[TRUE_FRAME], eos=True),
                OP_LIST: Accept(objects=[frame_string8("mod")], eos=True),
                OP_SET: Accept(objects=[ACK_FRAME]),
                OP_DELETE: Accept(objects=[ACK_FRAME]),
                OP_MOUNT_REMOTE: Accept(objects=[ACK_FRAME]),
                OP_UNMOUNT: Accept(objects=[ACK_FRAME]),
            }
        )
        async with mock:
            t = await self.tree(mock)
            await t.get("/x")
            await t.list("/x")
            await t.set_text("/x", "true", type="bool")
            await t.delete("/x", recursive=True)
            await t.mount_remote("/x", "peer", root="/y")
            await t.unmount("/x")
        keys = {key for q in mock.queries for key in parse(q.query)[1]}
        self.assertEqual(keys, {"path", "type", "value", "recursive", "root", "target"})
        self.assertTrue(all(key == key.lower() for key in keys), keys)


# --- Tier C: the live node ------------------------------------------------


class LiveTreeTest(live_support.LiveCase):
    """`tree` against a real node. Read-only: `get` and `list` and nothing else.

    The config tree is the node's running configuration, so no live test calls
    `set`, `create`, `delete`, `mount_remote` or `unmount`. Every assertion is
    node-agnostic: the paths are discovered by walking from the root rather than
    named, because another node's tree holds other modules.
    """

    MAX_DEPTH = 4

    async def walk(self, tree: Tree, path: str = ROOT, depth: int = 0) -> list[str]:
        """Every path under `path`, depth-first, bounded. One query per node."""
        if depth >= self.MAX_DEPTH:
            return []
        found: list[str] = []
        for name in await tree.list(path, timeout=15.0):
            child = f"{path.rstrip('/')}/{name}"
            found.append(child)
            found.extend(await self.walk(tree, child, depth + 1))
        return found

    @bounded(60.0)
    async def test_list_walks_the_tree_and_ends_every_stream_at_an_eos(self):
        """`tree.list` on the root, on a branch and on a leaf. A leaf answers a
        bare `eos`, which is an empty list and not an error."""
        async with await self.client() as client:
            t = Tree(client)
            roots = await t.list(timeout=15.0)
            self.assertEqual(roots, sorted(roots), "the node stopped sorting")
            paths = await self.walk(t)
            self.assertTrue(paths, "the tree is empty")
            leaves = [
                p for p in paths if not await t.list(p, timeout=15.0)
            ]
            self.assertTrue(leaves, "no leaf in the tree")
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_get_answers_one_object_then_an_eos(self):
        """Every path the walk found reads, and every read ends at an `eos`. A
        node with no value answers `nil`, which is an object and not an error --
        `mod.tree.err_no_value` is what the docs claim and is never sent."""
        async with await self.client() as client:
            t = Tree(client)
            paths = await self.walk(t)
            values = {p: await t.get(p, timeout=15.0) for p in paths}
        self.assertTrue(values)
        for path, value in values.items():
            with self.subTest(path=path):
                self.assertIsNotNone(value)
                self.assertNotIsInstance(value, ErrNoValue)
        self.assertTrue(
            any(isinstance(v, Nil) for v in values.values()),
            "no value-less node on this tree; the nil claim is unexercised",
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_root_and_a_missing_path_answer_error_messages(self):
        """Two failures the op distinguishes, both `error_message` and both
        `RemoteError`: the root holds no value, and a missing segment names
        itself."""
        async with await self.client() as client:
            t = Tree(client)
            with self.assertRaises(RemoteError) as root:
                await t.get(ROOT, timeout=15.0)
            self.assertIn("root node cannot hold a value", str(root.exception))
            with self.assertRaises(RemoteError) as missing:
                await t.get("/astral-py-no-such-path", timeout=15.0)
            self.assertIn("not found", str(missing.exception))
            with self.assertRaises(RemoteError):
                await t.list("/astral-py-no-such-path", timeout=15.0)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_a_value_of_an_unregistered_type_arrives_unparsed(self):
        """The reason `get` defaults `allow_unparsed=True`. Skipped when every
        type this node stores happens to be one the SDK declares."""
        async with await self.client() as client:
            t = Tree(client)
            unknown = None
            for path in await self.walk(t):
                value = await t.get(path, timeout=15.0)
                if isinstance(value, UnparsedObject):
                    unknown = (path, value)
                    break
            if unknown is None:
                self.skipTest("every stored type on this node is registered")
            path, value = unknown
            self.assertTrue(value.ASTRAL_TYPE)
            with self.assertRaises(BlueprintNotFound):
                await t.get(path, allow_unparsed=False, timeout=15.0)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_follow_sends_the_current_value_and_then_no_separator(self):
        """The design objection, live. `tree.get?follow=true` answers the stored
        value and then nothing: no `eos` arrives until the stream ends, so the
        first `eos` cannot be a snapshot/live separator.

        The second read expires at a frame boundary, which is the one place an
        abandoned read costs nothing, and the stream is closed immediately after.
        """
        async with await self.client() as client:
            t = Tree(client)
            valued = [
                p
                for p in await self.walk(t)
                if not isinstance(await t.get(p, timeout=15.0), Nil)
            ]
            if not valued:
                self.skipTest("no node on this tree holds a value")
            async with t.get_follow(valued[0]) as stream:
                objects = stream.__aiter__()
                first = await asyncio.wait_for(objects.__anext__(), 15.0)
                self.assertIsNotNone(first)
                self.assertIsNone(stream.terminated_by)
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(objects.__anext__(), 3.0)
                self.assertIsNone(stream.terminated_by)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unknown_argument_key_is_dropped_without_a_word(self):
        """The mechanism behind D-17, on the node itself: `recursive` is not an
        argument of `tree.get`, and sending it changes nothing and reports
        nothing. The documented `-Recursive` on `tree.delete` fails the same
        silent way."""
        async with await self.client() as client:
            t = Tree(client)
            names = await t.list("/mod", timeout=15.0)
            same = await client.call(
                f"{OP_LIST}?path=%2Fmod&Path=%2Fnope&nosuchkey=1", timeout=15.0
            )
            self.assertEqual([str(o) for o in same], names)
        await self.assert_no_open_sockets()


# --- the prose, held to what the tree actually carries -------------------


class DocstringTest(unittest.TestCase):
    """Claims in the module docstring that the repository can check."""

    def test_the_op_table_names_the_six_ops_and_no_others(self):
        doc = tree_module.__doc__ or ""
        found = set(re.findall(r"`(tree\.[a-z_]+)", doc))
        self.assertEqual(
            found,
            {OP_DELETE, OP_GET, OP_LIST, OP_MOUNT_REMOTE, OP_SET, OP_UNMOUNT},
        )

    def test_the_docstring_matches_whether_client_carries_a_tree_property(self):
        """`client.tree` is the surface design section 5.1 specifies. It is not
        declared in `client.py`, which this module does not own, and the
        docstring says so; when the property lands, this test fails and that
        sentence changes with it."""
        import functools

        declared = isinstance(getattr(Client, "tree", None), functools.cached_property)
        # Whitespace-normalised, so rewrapping the paragraph cannot silently
        # turn the claim into its opposite.
        doc = " ".join((tree_module.__doc__ or "").split())
        claimed = "It is not declared in `client.py`" not in doc
        self.assertEqual(
            declared, claimed, "the module docstring and `Client` disagree about `client.tree`"
        )

    def test_importing_astral_api_imports_this_module(self):
        """The rule `astral/api/__init__.py` states: registration is a side
        effect of import, so a module missing from that file makes decodability
        depend on which property a caller happened to touch."""
        import sys

        import astral.api

        self.assertIn("astral.api.tree", sys.modules)
        self.assertIs(astral.api.Tree, Tree)


class CitationTest(unittest.TestCase):
    """Every `path:line` in this module lands on the claim it is cited for.

    astrald and astral-go are moving targets. A citation that has drifted by two
    lines costs a reader more than an absent one: it makes them distrust the
    exact ones, including the byte-level claims.
    """

    GO = reference.ASTRAL_GO
    ASTRALD = reference.ASTRALD

    GO_CITATIONS = {
        "api/tree/module.go:7": "Paths begin with a slash",
        "api/tree/client/server.go:57": "for object := range val {",
        "api/tree/client/server.go:61": "return ch.Send(&astral.EOS{})",
        "api/tree/client/server.go:78": 'if args.Value != "" {',
        "api/tree/client/server.go:87": 'createIfMissing := args.Type != ""',
        "api/tree/client/server.go:101": "cannot infer type: node has no current value",
        "api/tree/client/server.go:127": "tree.Query(ctx, ops.Node, args.Path, true)",
        "api/tree/client/server.go:129": "return ch.Send(astral.Err(err))",
        "api/tree/client/server.go:132": "return ch.Switch(",
        "api/tree/client/server.go:178": "func deleteRecursive(",
        "api/tree/client/server.go:202": "if len(args.Path) > 0 {",
        "api/tree/client/server.go:222": "sort.Strings(names)",
        "api/tree/client/node.go:151": "calling set without sending any value",
        "api/tree/client/node.go:160": "return &Node{client: node.client",
        "api/tree/node.go:33": 'strings.TrimPrefix(path, "/")',
        "api/tree/node.go:41": "if len(s) == 0 {",
        "api/tree/err_no_value.go:15": 'return "mod.tree.err_no_value"',
    }

    ASTRALD_CITATIONS = {
        "mod/tree/src/node.go:29": "root node cannot hold a value",
        "mod/tree/src/node.go:37": "object = &astral.Nil{}",
        "mod/tree/src/module.go:92": "path must be absolute",
        "mod/tree/src/module.go:99": "mount point already exists",
        "mod/tree/src/module.go:116": "mount point does not exist",
        "mod/tree/src/module.go:126": "if len(remotePath) > 0 {",
        "mod/tree/src/module.go:215": "return tree.ErrNodeHasSubnodes",
        "mod/tree/src/loader.go:30": 'mod.mounts.Set("/", &Node{mod: mod})',
        "mod/dir/src/module.go:56": 'if s == "" || s == "anyone"',
        # The op that does have a separator, cited so the objection is scoped:
        # ST+follow is a real mode and `tree.get` is not in it.
        "mod/services/src/op_discover.go:17": "snapshot/stream separator",
        "mod/services/src/op_discover.go:33": "if update == nil {",
    }

    def check(self, repo: str, citations: dict[str, str]) -> None:
        """Every citation, read at the revision the docstrings name.

        The reference working tree is not consulted: a citation is a claim about
        a revision, and reading whatever a sibling checkout happens to hold
        turns somebody else's `git pull` into a failure of this SDK's suite.
        """
        for citation, expected in citations.items():
            path, _, number = citation.rpartition(":")
            with self.subTest(citation=citation):
                try:
                    line = reference.cited_line(repo, path, int(number))
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(expected, line)

    def test_every_astral_go_citation_lands_on_its_claim(self):
        self.check(self.GO, self.GO_CITATIONS)

    def test_every_astrald_citation_lands_on_its_claim(self):
        self.check(self.ASTRALD, self.ASTRALD_CITATIONS)

    def test_only_the_lines_this_test_checks_are_cited(self):
        """A citation added without a line here would go unchecked, which is
        worse than an absent one. Both the module and this file are scanned."""
        prose = pathlib.Path(tree_module.__file__).read_text(encoding="utf-8")
        prose += pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(
            set(re.findall(r"astral-go/(api/[\w/]+\.go:\d+)", prose)),
            set(self.GO_CITATIONS),
        )
        self.assertEqual(
            set(re.findall(r"astrald/(mod/[\w/]+\.go:\d+)", prose)),
            set(self.ASTRALD_CITATIONS),
        )


if __name__ == "__main__":
    unittest.main()
