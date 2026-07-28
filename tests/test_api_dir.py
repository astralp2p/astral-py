"""The `dir` module client, and the map kind it proves.

Three tiers in one file, because the same claim is made at each and the three
must agree:

- **Tier A** pins the wire. `mod.dir.alias_map` is the SDK's only live use of
  the map kind, and its payload is the whole of design section 2.3's map rule:
  a `uint32` count, pairs sorted by encoded key bytes, a presence byte on the
  **value** and never on the key, and a flat 33-byte identity behind that byte.
  The vector is bytes captured from `furry-bolt` this session, not bytes this
  SDK produced, so a round trip through it cannot agree with itself while
  disagreeing with the node.
- **Tier B** pins the six ops against `MockApphost`: the query string each one
  builds, the answer each one accepts, and the two reference bugs neither may
  reproduce -- astral-go's `apply_filters` querying `dir.set_alias` (G-8) and
  the omitted `alias=` on removal (D-18).
- **Tier C** runs the same six ops against a real node, minus `set_alias`. It
  is the gate of implementation step 9: a live `dir.alias_map` decodes to a
  typed `AliasMap` whose keys are aliases and whose values are `Identity`.

Nothing here mutates node state. `set_alias` is exercised only against the
mock; the live tier is read-only, and `dir.filters` is the only live assertion
that touches an ordered collection -- astrald's filter registry is a
`sig.Map`, whose `Keys()` order varies between queries (observed this session),
so no live assertion depends on it.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import unittest

import astral
from astral.api.dir import (
    Alias,
    AliasMap,
    Dir,
    OP_ALIAS_MAP,
    OP_APPLY_FILTERS,
    OP_FILTERS,
    OP_GET_ALIAS,
    OP_RESOLVE,
    OP_SET_ALIAS,
)
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import ParseError, ProtocolError, RemoteError
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Map
from astral.types import Identity
from astral.wire import Writer

import live_support
import reference
from astral.api import dir as dir_module
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    FURRY_BOLT_ALIAS,
    MockApphost,
    bounded,
    socket_fds,
)

# The `dir.alias_map` payload as `furry-bolt` sent it, captured this session
# over `unix:~/.apphost.sock`. One entry, and every map rule in 51 bytes.
LIVE_ALIAS_MAP = bytes.fromhex(
    "00000001"                      # uint32 count
    "000a" "66757272792d626f6c74"   # string16 key "furry-bolt"
    "01"                            # presence byte, on the VALUE
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)

OTHER = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


def frame_bool(value: bool) -> tuple[str, bytes]:
    return ("bool", b"\x01" if value else b"\x00")


def frame_string8(value: str) -> tuple[str, bytes]:
    w = Writer()
    w.string8(value)
    return ("string8", w.getvalue())


def frame_error(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ALIAS_MAP_FRAME = ("mod.dir.alias_map", LIVE_ALIAS_MAP)
IDENTITY_FRAME = ("identity", FURRY_BOLT.key)
ACK_FRAME = ("ack", b"")


# --- Tier A: the map kind, on the bytes the node sent --------------------


class AliasMapWireTest(unittest.TestCase):
    """`mod.dir.alias_map` against the live payload and the map rules."""

    def test_the_live_payload_decodes_to_a_typed_alias_map(self):
        """The gate of implementation step 9, as a fixed vector.

        The legacy SDK had no map kind, so these bytes decoded to an opaque
        blob and every alias in the directory was unreachable from Python.
        """
        m = AliasMap.read_payload(object_reader(LIVE_ALIAS_MAP))
        self.assertIsInstance(m, AliasMap)
        self.assertEqual(list(m.keys()), [FURRY_BOLT_ALIAS])
        self.assertEqual(m[FURRY_BOLT_ALIAS], FURRY_BOLT)
        self.assertIsInstance(m[FURRY_BOLT_ALIAS], Identity)

    def test_the_live_payload_re_encodes_byte_for_byte(self):
        """Decode then encode is the identity on the node's own bytes."""
        m = AliasMap.read_payload(object_reader(LIVE_ALIAS_MAP))
        self.assertEqual(payload_bytes(m), LIVE_ALIAS_MAP)

    def test_the_presence_byte_sits_on_the_value_and_not_on_the_key(self):
        """The one byte the whole map rule turns on.

        `01` precedes the 33 identity bytes and nothing precedes the key. An
        implementation that put the byte on the key would still produce 51
        bytes, so the assertion names offsets rather than a length.
        """
        self.assertEqual(LIVE_ALIAS_MAP[4:6], b"\x00\x0a")
        self.assertEqual(LIVE_ALIAS_MAP[6:16], FURRY_BOLT_ALIAS.encode())
        self.assertEqual(LIVE_ALIAS_MAP[16], 0x01)
        self.assertEqual(LIVE_ALIAS_MAP[17:], FURRY_BOLT.key)
        self.assertEqual(len(FURRY_BOLT.key), 33)

    def test_the_identity_carries_no_flag_of_its_own(self):
        """33 flat bytes. The `01` in front belongs to the map slot.

        The legacy SDK modelled `identity` as a presence byte plus 33 bytes,
        which is the same 34 bytes here and a different 34 bytes everywhere
        else. A payload of 33 bytes past the flag is what settles it.
        """
        self.assertEqual(len(LIVE_ALIAS_MAP) - 17, 33)

    def test_the_field_is_declared_as_a_map_of_string16_to_identity(self):
        (field,) = AliasMap.FIELDS
        self.assertEqual(field.wire_name, "Aliases")
        self.assertEqual(field.spec, Map("string16", "identity"))

    def test_pairs_encode_sorted_by_encoded_key_bytes_not_alphabetically(self):
        """`string16` keys sort by their length prefix first.

        `"b"` precedes `"aa"` on the wire and follows it alphabetically, so a
        codec that sorted the strings would produce different bytes and a
        different ObjectID for the same value. Python's dict insertion order
        never reaches the wire.
        """
        m = AliasMap(aliases={"aa": FURRY_BOLT, "b": OTHER})
        raw = payload_bytes(m)
        self.assertEqual(raw[:4], b"\x00\x00\x00\x02")
        self.assertEqual(raw[4:6], b"\x00\x01")  # len("b")
        self.assertEqual(raw[6:7], b"b")
        self.assertEqual(raw[7], 0x01)
        self.assertEqual(raw[8:41], OTHER.key)
        self.assertEqual(raw[41:43], b"\x00\x02")  # len("aa")
        # And insertion order is irrelevant: the reverse dict is the same bytes.
        self.assertEqual(payload_bytes(AliasMap(aliases={"b": OTHER, "aa": FURRY_BOLT})), raw)

    def test_an_empty_map_is_a_zero_count_and_not_an_absent_field(self):
        m = AliasMap()
        self.assertEqual(m.aliases, {})
        self.assertEqual(payload_bytes(m), b"\x00\x00\x00\x00")
        self.assertEqual(len(AliasMap.read_payload(object_reader(b"\x00\x00\x00\x00"))), 0)

    def test_an_absent_value_decodes_to_none_and_re_encodes_to_the_same_byte(self):
        """`map[string]*astral.Identity` can hold a nil pointer.

        The node has never sent one; the round trip must survive it anyway,
        because a decode this SDK accepts must re-encode to the bytes it came
        from (design section 11.1).
        """
        raw = bytes.fromhex("00000001" "0001" "78" "00")
        m = AliasMap.read_payload(object_reader(raw))
        self.assertEqual(m.aliases, {"x": None})
        self.assertEqual(payload_bytes(m), raw)

    def test_a_key_never_carries_a_presence_byte_on_decode(self):
        """A decoder that expected one would read the key's length prefix as it
        and desynchronise on the first entry."""
        with self.assertRaises(astral.WireError):
            AliasMap.read_payload(object_reader(b"\x00\x00\x00\x01\x01" + LIVE_ALIAS_MAP[4:]))


class DirTypesTest(unittest.TestCase):
    """The two types this module registers."""

    def test_both_types_are_in_the_registry_under_their_wire_names(self):
        registry = default_blueprints()
        self.assertTrue(registry.has("mod.dir.alias_map"))
        self.assertTrue(registry.has("mod.dir.alias"))
        self.assertIsInstance(registry.new("mod.dir.alias_map"), AliasMap)

    def test_the_alias_type_is_a_string8_under_its_own_name(self):
        """Registered for decode completeness. No `dir` op sends it: verified
        live, `dir.get_alias` and `dir.filters` both answer with `string8`."""
        a = Alias(FURRY_BOLT_ALIAS)
        self.assertEqual(a.ASTRAL_TYPE, "mod.dir.alias")
        self.assertEqual(payload_bytes(a), b"\x0a" + FURRY_BOLT_ALIAS.encode())
        self.assertEqual(
            Alias.read_payload(object_reader(payload_bytes(a))).value, FURRY_BOLT_ALIAS
        )


class AliasMapMappingTest(unittest.TestCase):
    """The mapping surface, which is the reason to fetch the whole table."""

    def setUp(self) -> None:
        self.m = AliasMap(aliases={FURRY_BOLT_ALIAS: FURRY_BOLT, "other": OTHER})

    def test_it_reads_as_the_map_it_is(self):
        self.assertEqual(len(self.m), 2)
        self.assertIn(FURRY_BOLT_ALIAS, self.m)
        self.assertNotIn("absent", self.m)
        self.assertEqual(self.m[FURRY_BOLT_ALIAS], FURRY_BOLT)
        self.assertIsNone(self.m.get("absent"))
        self.assertEqual(sorted(self.m), ["furry-bolt", "other"])
        self.assertEqual(sorted(self.m.keys()), ["furry-bolt", "other"])
        self.assertEqual(len(list(self.m.items())), 2)
        self.assertIn(OTHER, list(self.m.values()))

    def test_alias_of_is_the_reverse_lookup(self):
        """astrald's schema makes both columns unique, so there is at most one
        answer (`mod/dir/src/db.go:9`)."""
        self.assertEqual(self.m.alias_of(FURRY_BOLT), FURRY_BOLT_ALIAS)
        self.assertEqual(self.m.alias_of(OTHER), "other")
        self.assertIsNone(self.m.alias_of(Identity.ANYONE))


# --- Tier B: the six ops against the mock --------------------------------


class DirCase(unittest.IsolatedAsyncioTestCase):
    """A `Dir` over a mock apphost, closed by the teardown whatever a test does."""

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

    async def dir(self, mock: MockApphost, **kw: object) -> Dir:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Dir(client)

    def sent(self, mock: MockApphost) -> str:
        """The one query string the mock received."""
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    def params(self, mock: MockApphost) -> tuple[str, dict[str, str]]:
        return parse(self.sent(mock))

    def assert_no_faults(self, mock: MockApphost) -> None:
        self.assertEqual(mock.errors, [])


class AliasMapOpTest(DirCase):
    """`dir.alias_map`: RR, one object, no `eos`."""

    @bounded()
    async def test_it_returns_a_typed_alias_map(self):
        mock = MockApphost(routes={OP_ALIAS_MAP: Accept(objects=[ALIAS_MAP_FRAME])})
        async with mock:
            d = await self.dir(mock)
            m = await d.alias_map()
        self.assertIsInstance(m, AliasMap)
        self.assertEqual(m[FURRY_BOLT_ALIAS], FURRY_BOLT)
        self.assertEqual(self.sent(mock), OP_ALIAS_MAP)
        self.assert_no_faults(mock)

    @bounded()
    async def test_it_does_not_wait_for_an_eos(self):
        """The node sends one map and closes -- verified live, `terminated_by`
        is `eof`. A helper that waited for a terminator would hold one of the
        node's 32 workers until the connection died."""
        mock = MockApphost(routes={OP_ALIAS_MAP: Accept(objects=[ALIAS_MAP_FRAME])})
        async with mock:
            d = await self.dir(mock)
            await d.alias_map()
        self.assert_no_faults(mock)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_ALIAS_MAP: Accept(objects=[ACK_FRAME])})
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ProtocolError) as caught:
                await d.alias_map()
        self.assertIn("mod.dir.alias_map", str(caught.exception))


class ResolveOpTest(DirCase):
    """`dir.resolve`: a name to an identity."""

    @bounded()
    async def test_it_sends_the_name_and_returns_the_identity(self):
        mock = MockApphost(routes={OP_RESOLVE: Accept(objects=[IDENTITY_FRAME])})
        async with mock:
            d = await self.dir(mock)
            got = await d.resolve(FURRY_BOLT_ALIAS)
        self.assertEqual(got, FURRY_BOLT)
        self.assertEqual(self.sent(mock), f"{OP_RESOLVE}?name={FURRY_BOLT_ALIAS}")

    @bounded()
    async def test_a_name_is_url_escaped(self):
        mock = MockApphost(routes={OP_RESOLVE: Accept(objects=[IDENTITY_FRAME])})
        async with mock:
            d = await self.dir(mock)
            await d.resolve("a b&c")
        op, params = self.params(mock)
        self.assertEqual(op, OP_RESOLVE)
        self.assertEqual(params, {"name": "a b&c"})
        self.assertIn("name=a+b%26c", self.sent(mock))

    @bounded()
    async def test_an_empty_name_never_reaches_the_node(self):
        """`dir.resolve?name=` answers with the **zero identity** rather than an
        error -- verified live -- because astrald maps `""` to
        `astral.Identity{}`. A caller that meant a name would then hold
        `anyone` and route somewhere else entirely."""
        mock = MockApphost(routes={OP_RESOLVE: Accept(objects=[IDENTITY_FRAME])})
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ValueError):
                await d.resolve("")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_unknown_name_raises_the_error_message(self):
        """The op runs and fails: an `error_message` inside the accepted stream,
        not an apphost `error_msg`. The two are different channels."""
        mock = MockApphost(
            routes={OP_RESOLVE: Accept(objects=[frame_error("unknown identity: nope")])}
        )
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(RemoteError) as caught:
                await d.resolve("nope")
        self.assertIn("unknown identity", str(caught.exception))

    @bounded()
    async def test_resolve_identity_parses_hex_without_a_query(self):
        """astral-go's `ResolveIdentity`: a public key costs no round trip."""
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            got = await d.resolve_identity(str(FURRY_BOLT))
        self.assertEqual(got, FURRY_BOLT)
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_resolve_identity_sends_a_name_to_the_node(self):
        mock = MockApphost(routes={OP_RESOLVE: Accept(objects=[IDENTITY_FRAME])})
        async with mock:
            d = await self.dir(mock)
            got = await d.resolve_identity(FURRY_BOLT_ALIAS)
        self.assertEqual(got, FURRY_BOLT)
        self.assertEqual(self.sent(mock), f"{OP_RESOLVE}?name={FURRY_BOLT_ALIAS}")


class GetAliasOpTest(DirCase):
    """`dir.get_alias`: an identity to a name."""

    @bounded()
    async def test_it_sends_the_identity_as_hex(self):
        mock = MockApphost(
            routes={OP_GET_ALIAS: Accept(objects=[frame_string8(FURRY_BOLT_ALIAS)])}
        )
        async with mock:
            d = await self.dir(mock)
            got = await d.get_alias(FURRY_BOLT)
        self.assertEqual(got, FURRY_BOLT_ALIAS)
        self.assertEqual(self.sent(mock), f"{OP_GET_ALIAS}?id={FURRY_BOLT.hex()}")

    @bounded()
    async def test_it_accepts_the_hex_text_of_an_identity(self):
        mock = MockApphost(
            routes={OP_GET_ALIAS: Accept(objects=[frame_string8(FURRY_BOLT_ALIAS)])}
        )
        async with mock:
            d = await self.dir(mock)
            await d.get_alias(FURRY_BOLT.hex())
        self.assertEqual(self.sent(mock), f"{OP_GET_ALIAS}?id={FURRY_BOLT.hex()}")

    @bounded()
    async def test_a_directory_name_is_refused_before_it_is_sent(self):
        """The op parses this argument with `astral.ParseIdentity`, so a name
        reaches it as a **rejected query** and not as an error message.
        Verified live: 66 hex characters that are not a curve point are
        rejected with code 1."""
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ParseError) as caught:
                await d.get_alias(FURRY_BOLT_ALIAS)
            self.assertEqual(mock.queries, [])
        self.assertIn("resolve it first", str(caught.exception))

    @bounded()
    async def test_an_identity_with_no_alias_raises_the_error_message(self):
        """astrald answers `record not found` -- verified live -- so there is no
        empty-string answer to distinguish and no swallow here that would have
        to match on the text of a gorm error."""
        mock = MockApphost(
            routes={OP_GET_ALIAS: Accept(objects=[frame_error("record not found")])}
        )
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(RemoteError):
                await d.get_alias(OTHER)


class FiltersOpTest(DirCase):
    """`dir.filters`: the one streaming op in the module."""

    @bounded()
    async def test_it_collects_every_name_up_to_the_eos(self):
        names = ["localnode", "linked", "localswarm", "localuser", "all"]
        mock = MockApphost(
            routes={
                OP_FILTERS: Accept(
                    objects=[frame_string8(n) for n in names], eos=True
                )
            }
        )
        async with mock:
            d = await self.dir(mock)
            got = await d.filters()
        self.assertEqual(got, names)
        self.assertEqual(self.sent(mock), OP_FILTERS)
        self.assertTrue(all(type(n) is str for n in got))

    @bounded()
    async def test_it_ends_at_a_bare_eof_too(self):
        """`eos` **or** EOF, never `eos` alone (design section 3.10)."""
        mock = MockApphost(routes={OP_FILTERS: Accept(objects=[frame_string8("all")])})
        async with mock:
            d = await self.dir(mock)
            self.assertEqual(await d.filters(), ["all"])

    @bounded()
    async def test_an_empty_registry_is_an_empty_list(self):
        mock = MockApphost(routes={OP_FILTERS: Accept(eos=True)})
        async with mock:
            d = await self.dir(mock)
            self.assertEqual(await d.filters(), [])


class ApplyFiltersOpTest(DirCase):
    """`dir.apply_filters`, and the astral-go bug it must not reproduce."""

    @bounded()
    async def test_it_queries_apply_filters_and_never_set_alias(self):
        """Design bug G-8. astral-go's `ApplyFilters` sends its arguments to
        `dir.set_alias` (`api/dir/client/apply_filters.go:20`), so a read
        helper mutates the directory. The assertion is on the op name the node
        received, because that is the only place the bug is visible."""
        mock = MockApphost(routes={OP_APPLY_FILTERS: Accept(objects=[frame_bool(True)])})
        async with mock:
            d = await self.dir(mock)
            got = await d.apply_filters("all")
        self.assertIs(got, True)
        self.assertEqual(mock.queries[0].op, OP_APPLY_FILTERS)
        self.assertNotIn(OP_SET_ALIAS, self.sent(mock))
        self.assertEqual(self.sent(mock), f"{OP_APPLY_FILTERS}?filters=all")

    @bounded()
    async def test_several_names_are_comma_joined_and_the_keys_are_sorted(self):
        mock = MockApphost(routes={OP_APPLY_FILTERS: Accept(objects=[frame_bool(False)])})
        async with mock:
            d = await self.dir(mock)
            got = await d.apply_filters(["linked", "all"], identity=FURRY_BOLT)
        self.assertIs(got, False)
        # Sorted keys, matching Go's `url.Values.Encode()`; the filter order is
        # the caller's and is preserved.
        self.assertEqual(
            self.sent(mock),
            f"{OP_APPLY_FILTERS}?filters=linked%2Call&id={FURRY_BOLT.hex()}",
        )
        _, params = self.params(mock)
        self.assertEqual(params["filters"], "linked,all")

    @bounded()
    async def test_the_identity_argument_accepts_a_directory_name(self):
        """Unlike `get_alias`, this op declares `ID string` and resolves it
        server-side (`mod/dir/src/op_apply_filters.go:14`). Verified live:
        `dir.apply_filters?filters=all&id=furry-bolt` answers `bool(true)`. No
        query is spent resolving the name here."""
        mock = MockApphost(routes={OP_APPLY_FILTERS: Accept(objects=[frame_bool(True)])})
        async with mock:
            d = await self.dir(mock)
            await d.apply_filters("all", identity=FURRY_BOLT_ALIAS)
        self.assertEqual(len(mock.queries), 1)
        self.assertEqual(
            self.sent(mock), f"{OP_APPLY_FILTERS}?filters=all&id={FURRY_BOLT_ALIAS}"
        )

    @bounded()
    async def test_no_filter_names_is_refused_before_it_is_sent(self):
        """An empty argument is one unknown filter on the node, which answers
        `False` -- verified live. A silent `False` is worse than an error."""
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ValueError):
                await d.apply_filters([])
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_name_containing_the_separator_is_refused(self):
        """astrald splits the argument on `,`, so such a name is two names."""
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ValueError) as caught:
                await d.apply_filters(["a,b"])
            self.assertEqual(mock.queries, [])
        self.assertIn("two names", str(caught.exception))

    @bounded()
    async def test_an_empty_identity_name_is_refused(self):
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ValueError):
                await d.apply_filters("all", identity="")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_unknown_identity_raises_the_error_message(self):
        mock = MockApphost(
            routes={
                OP_APPLY_FILTERS: Accept(
                    objects=[frame_error("unknown identity: not-a-real-alias")]
                )
            }
        )
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(RemoteError):
                await d.apply_filters("all", identity="not-a-real-alias")


class SetAliasOpTest(DirCase):
    """`dir.set_alias`: the one op here that writes."""

    @bounded()
    async def test_it_sends_both_arguments_and_reads_the_ack(self):
        mock = MockApphost(routes={OP_SET_ALIAS: Accept(objects=[ACK_FRAME])})
        async with mock:
            d = await self.dir(mock)
            self.assertIsNone(await d.set_alias(FURRY_BOLT, "new-name"))
        self.assertEqual(
            self.sent(mock), f"{OP_SET_ALIAS}?alias=new-name&id={FURRY_BOLT.hex()}"
        )

    @bounded()
    async def test_removal_sends_an_explicitly_empty_alias(self):
        """Design bug D-18. astrald declares `Alias *string` as required and
        reads removal from an empty value, and the required check tests key
        **presence** (`astral-go/lib/routing/op.go:137`). An omitted `alias` is
        a rejected query, so `alias=` and no `alias` are different queries."""
        mock = MockApphost(routes={OP_SET_ALIAS: Accept(objects=[ACK_FRAME])})
        async with mock:
            d = await self.dir(mock)
            await d.remove_alias(FURRY_BOLT)
        sent = self.sent(mock)
        self.assertEqual(sent, f"{OP_SET_ALIAS}?alias=&id={FURRY_BOLT.hex()}")
        op, params = parse(sent)
        self.assertEqual(op, OP_SET_ALIAS)
        self.assertIn("alias", params)
        self.assertEqual(params["alias"], "")

    @bounded()
    async def test_set_alias_with_an_empty_name_is_the_same_query_as_removal(self):
        mock = MockApphost(routes={OP_SET_ALIAS: Accept(objects=[ACK_FRAME])})
        async with mock:
            d = await self.dir(mock)
            await d.set_alias(FURRY_BOLT, "")
        self.assertEqual(self.sent(mock), f"{OP_SET_ALIAS}?alias=&id={FURRY_BOLT.hex()}")

    @bounded()
    async def test_a_directory_name_is_refused_before_it_is_sent(self):
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ParseError):
                await d.set_alias(FURRY_BOLT_ALIAS, "x")
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_answer_that_is_not_an_ack_is_a_protocol_error(self):
        mock = MockApphost(
            routes={OP_SET_ALIAS: Accept(objects=[frame_string8("ok")])}
        )
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(ProtocolError):
                await d.set_alias(FURRY_BOLT, "x")

    @bounded()
    async def test_a_failed_write_raises_the_error_message(self):
        mock = MockApphost(
            routes={OP_SET_ALIAS: Accept(objects=[frame_error("UNIQUE constraint failed")])}
        )
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(RemoteError):
                await d.set_alias(FURRY_BOLT, "furry-bolt")


class DirPlumbingTest(DirCase):
    """What every op shares."""

    @bounded()
    async def test_query_keywords_reach_the_client(self):
        """`target`, `timeout` and the rest are the client's, not the op's."""
        mock = MockApphost(routes={OP_ALIAS_MAP: Accept(objects=[ALIAS_MAP_FRAME])})
        async with mock:
            d = await self.dir(mock)
            await d.alias_map(target=FURRY_BOLT, timeout=5.0)
        self.assertEqual(mock.queries[0].target, FURRY_BOLT)

    @bounded()
    async def test_an_unrouted_op_is_route_not_found(self):
        mock = MockApphost()
        async with mock:
            d = await self.dir(mock)
            with self.assertRaises(astral.RouteNotFound):
                await d.filters()

    @bounded()
    async def test_every_op_closes_its_stream(self):
        """A stream left open burns one of the node's 32 workers permanently
        (astrald bug G-13)."""
        mock = MockApphost(
            routes={
                OP_ALIAS_MAP: Accept(objects=[ALIAS_MAP_FRAME]),
                OP_FILTERS: Accept(objects=[frame_string8("all")], eos=True),
                OP_RESOLVE: Accept(objects=[IDENTITY_FRAME]),
                OP_GET_ALIAS: Accept(objects=[frame_string8("furry-bolt")]),
                OP_APPLY_FILTERS: Accept(objects=[frame_bool(True)]),
                OP_SET_ALIAS: Accept(objects=[ACK_FRAME]),
            }
        )
        async with mock:
            d = await self.dir(mock)
            client = self.clients[-1]
            await d.alias_map()
            await d.filters()
            await d.resolve(FURRY_BOLT_ALIAS)
            await d.get_alias(FURRY_BOLT)
            await d.apply_filters("all")
            await d.set_alias(FURRY_BOLT, "x")
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available, 8)
        self.assertEqual(len(mock.queries), 6)


# --- Tier C: the live node ------------------------------------------------

class LiveDirTest(live_support.LiveCase):
    """`dir` against a real node. Read-only: no `set_alias`, no `remove_alias`.

    The precheck, the client factory and the descriptor assertion all come from
    `live_support.LiveCase`, and that is not tidiness: the precheck **dials the
    node**, so a copy per file is a dial per file and every dial occupies one of
    the 32 workers for as long as it takes. The copies had also drifted --
    `live_support.verdict()` turns a `TimeoutError` around the probe into a skip
    reason, and a bare `asyncio.run(asyncio.wait_for(...))` in `setUpModule`
    errored the whole module instead, which is precisely the failure a precheck
    exists to avoid. `max_concurrency=4` there rather than 2 here; this is
    somebody's real node either way.
    """

    @bounded(30.0)
    async def test_a_live_alias_map_decodes_to_a_typed_alias_map(self):
        """The gate of implementation step 9.

        Keys are aliases, values are `Identity`, and the node's own alias maps
        to the identity it greeted with. Node-agnostic: the alias asserted is
        whatever the greeting reported, and astrald guarantees the node has one
        -- `setDefaultAlias` runs at load and generates one when the table is
        empty (`mod/dir/src/module.go:150`).
        """
        async with await self.client() as client:
            m = await Dir(client).alias_map()
        self.assertIsInstance(m, AliasMap)
        self.assertTrue(all(isinstance(k, str) for k in m.keys()))
        self.assertTrue(all(isinstance(v, Identity) for v in m.values()))
        self.assertIn(client.host_alias, m)
        self.assertEqual(m[client.host_alias], client.host_id)
        self.assertEqual(m.alias_of(client.host_id), client.host_alias)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_live_map_re_encodes_to_the_bytes_it_arrived_as(self):
        """Decode then encode is the identity on whatever the node holds, not
        only on the pinned one-entry vector: sort order and presence bytes are
        re-derived from the value and must land where they were."""
        async with await self.client() as client:
            d = Dir(client)
            m = await d.alias_map()
            again = AliasMap.read_payload(object_reader(payload_bytes(m)))
        self.assertEqual(again, m)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_filters_ends_at_an_eos_and_names_the_default_filter(self):
        """The other shape in the same module: `dir.filters` terminates with
        `eos` where the other five ops end at a bare EOF. astrald's registry is
        a `sig.Map`, whose key order varies between queries, so nothing here
        asserts order."""
        async with await self.client() as client:
            names = await Dir(client).filters()
        self.assertIn("all", names)
        self.assertIn("localnode", names)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_resolve_and_get_alias_are_inverses_on_the_node_itself(self):
        async with await self.client() as client:
            d = Dir(client)
            self.assertEqual(await d.resolve(client.host_alias), client.host_id)
            self.assertEqual(await d.get_alias(client.host_id), client.host_alias)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_an_unknown_alias_answers_with_an_error_message(self):
        async with await self.client() as client:
            with self.assertRaises(RemoteError):
                await Dir(client).resolve("astral-py-no-such-alias")
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_apply_filters_is_read_only_and_or_semantics(self):
        """`all` passes, an unknown name is a silent `False`, and the identity
        argument takes the node's own alias without a resolving query. The
        directory is unchanged afterwards: the alias map is read before and
        after and compared."""
        async with await self.client() as client:
            d = Dir(client)
            before = await d.alias_map()
            self.assertIs(await d.apply_filters("all"), True)
            self.assertIs(await d.apply_filters(["astral-py-no-such-filter"]), False)
            self.assertIs(
                await d.apply_filters("all", identity=client.host_alias), True
            )
            self.assertEqual(await d.alias_map(), before)
        await self.assert_no_open_sockets()


# --- the review's findings ------------------------------------------------


class KeywordParityTest(DirCase):
    """Two adjacent methods documenting the same `**kw` must accept the same."""

    @bounded()
    async def test_resolve_identity_accepts_what_resolve_accepts(self):
        """`d.resolve(name, zone=...)` worked and
        `d.resolve_identity(name, zone=...)` raised `TypeError: Client.
        resolve_identity() got an unexpected keyword argument 'zone'` -- naming a
        method the caller never called."""
        for method in ("resolve", "resolve_identity"):
            with self.subTest(method=method):
                async with MockApphost(
                    routes={f"{OP_RESOLVE}?name=furry-bolt": Accept(objects=[IDENTITY_FRAME])}
                ) as mock:
                    d = await self.dir(mock)
                    got = await getattr(d, method)(
                        "furry-bolt", zone=astral.Zone.DEVICE, timeout=5.0
                    )
                self.assertEqual(got, FURRY_BOLT)
                self.assertEqual(mock.queries[-1].zone, int(astral.Zone.DEVICE))

    @bounded()
    async def test_every_argument_refusal_is_inside_the_hierarchy(self):
        """`d.get_alias('not-an-identity')` raised `ParseError`, an `AstralError`,
        while `d.resolve('')` raised a bare `ValueError` for the same class of
        fault. Both are now both."""
        async with MockApphost() as mock:
            d = await self.dir(mock)
            cases = (
                lambda: d.resolve(""),
                lambda: d.apply_filters("a", identity=""),
                lambda: d.apply_filters([]),
                lambda: d.apply_filters(["a", ""]),
                lambda: d.apply_filters("a,b"),
                lambda: d.get_alias("not-an-identity"),
            )
            for i, run in enumerate(cases):
                with self.subTest(case=i):
                    with self.assertRaises(astral.AstralError):
                        await run()
                    with self.assertRaises(ValueError):
                        await run()
        self.assertEqual(mock.queries, [], "a refused argument still reached the node")


class CitationTest(unittest.TestCase):
    """Every astrald anchor this module cites, read out of the module itself.

    Three of them had drifted by a line or two. Every claim was correct, which is
    what makes the drift expensive: a reader who checks one anchor and finds it
    off distrusts the whole set, including the byte captures that are exact.
    astrald is a moving target, so the citations name the symbol as well and this
    test reads the line numbers out of the prose rather than restating them.
    """

    ASTRALD = reference.ASTRALD

    # What must appear on the line each anchor names, keyed by the file.
    EXPECTED = {
        "op_set_alias.go": "Alias *string",
        "op_apply_filters.go": 'strings.Split(args.Filters, ",")',
    }

    def test_every_line_number_this_module_cites_lands_on_its_claim(self):
        # The whole source, not only the docstring: two of the three anchors
        # live in comments beside the code they explain, which is where a
        # citation belongs and where drift is least visible.
        source = pathlib.Path(dir_module.__file__).read_text(encoding="utf-8")
        cited = re.findall(
            r"`mod/dir/src/(\w+\.go)`[^\n]*\n?[^\n]*?line (\d+) at astrald", source
        )
        self.assertEqual(
            {name for name, _ in cited},
            set(self.EXPECTED),
            "a cited file gained or lost its symbol-plus-line form",
        )
        for name, number in cited:
            with self.subTest(file=name, line=number):
                try:
                    line = reference.cited_line(
                        self.ASTRALD, f"mod/dir/src/{name}", int(number)
                    )
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(self.EXPECTED[name], line)

    def test_the_bare_line_citations_still_land(self):
        """The anchors that were already exact, kept exact."""
        for relative, number, expected in (
            ("mod/dir/src/module.go", 131, "func (mod *Module) ApplyFilters"),
            ("mod/dir/src/module.go", 56, 'if s == "" || s == "anyone"'),
        ):
            with self.subTest(file=relative, line=number):
                try:
                    line = reference.cited_line(self.ASTRALD, relative, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(expected, line)


class QueryKeywordShadowTest(unittest.TestCase):
    """No module-client method eats a routing keyword by accident.

    `api/base.py` states the contract for every method of every subclass: "Every
    method of every subclass takes the query keywords `Client.query` takes --
    `target`, `caller`, `zone`, `filters`, ... -- and passes them through
    unread." A method whose own parameter is named after one of them takes that
    name for itself, and the routing lever becomes unreachable on that op with
    nothing said about it.

    Two ops did it and neither said so. `Tree.mount_remote(path, target)` spent
    `target` on the mount's remote node, so `target=X` put X in the query string
    and routed to the *local* node -- and this is the one op in the SDK where the
    routing target and the op's own target are genuinely different nodes.
    `Dir.apply_filters(filters)` spent `filters` on the op's filter names, which
    are not `route_query_msg.Filters` at all. Both parameters are renamed.

    `Objects` collides on `zone` for thirteen methods and is correct: there the
    two levers really are one scope, so `_scope` forwards the value to both, and
    the class docstring says so. That is what the allow-list records.
    """

    # name -> the reason the collision is deliberate.
    ALLOWED = {
        "zone": "Objects: one scope, two levers; `_scope` sends the value to both",
        "timeout": "the query deadline itself, under its own name",
    }

    def test_no_method_shadows_a_query_keyword_without_declaring_it(self):
        import importlib
        import inspect

        import astral.api
        from astral.client import Client

        keywords = {
            p.name
            for p in inspect.signature(Client.query).parameters.values()
            if p.kind is inspect.Parameter.KEYWORD_ONLY
        }
        self.assertIn("target", keywords)
        directory = pathlib.Path(astral.api.__file__).parent
        checked = 0
        for path in sorted(directory.glob("*.py")):
            if path.stem.startswith("_") or path.stem == "base":
                continue
            module = importlib.import_module(f"astral.api.{path.stem}")
            for cname in sorted(vars(module)):
                cls = getattr(module, cname)
                if not inspect.isclass(cls):
                    continue
                if getattr(cls, "__module__", None) != module.__name__:
                    continue
                for mname, method in sorted(vars(cls).items()):
                    if mname.startswith("_") or not callable(method):
                        continue
                    try:
                        sig = inspect.signature(method)
                    except (TypeError, ValueError):  # pragma: no cover
                        continue
                    checked += 1
                    for shadowed in sorted(set(sig.parameters) & keywords):
                        with self.subTest(method=f"{cname}.{mname}", name=shadowed):
                            self.assertIn(
                                shadowed,
                                self.ALLOWED,
                                f"{cname}.{mname} takes `{shadowed}` for its own "
                                f"and so eats the routing keyword of the same "
                                f"name; rename the parameter, or forward the "
                                f"value to both levers and add it here with the "
                                f"reason",
                            )
        self.assertGreater(checked, 40, "the sweep found nothing to check")


class ModulePatternPolicyTest(unittest.TestCase):
    """One dialect, not thirteen. The rules `api/base.py` states, enforced.

    `base.py` exists because two modules already had two message formats for the
    same violation, and it says so: "which is how thirteen modules end up with
    thirteen dialects of the same fault. One base class, one message." It caught
    `_expect` and caught nothing else, and the six modules that landed after it
    grew four spellings of the parameter encoder, three copies of `_object_id` in
    two behaviours, two conventions for the batch form of an op and three for the
    follow form. None of that was enforced anywhere, which is why it happened.
    """

    SHARED = ("_param", "_encode", "_object_id", "_expect")
    """Helpers that live on `ModuleClient` and must not be reimplemented."""

    def modules(self):  # type: ignore[no-untyped-def]
        import astral.api

        directory = pathlib.Path(astral.api.__file__).parent
        return [
            path
            for path in sorted(directory.glob("*.py"))
            if not path.stem.startswith("_") and path.stem != "base"
        ]

    def test_no_module_reimplements_a_helper_the_base_class_owns(self):
        """A module may bind one of these to its own spec table -- that is a
        partial application and its body is one call -- but may not grow a second
        body for it. The divergence this catches was caller-visible:
        `objects.probe('nope')` named the op that refused the id and
        `auth.index('nope')` did not."""
        import ast

        from astral.api.base import ModuleClient

        for name in self.SHARED:
            self.assertTrue(hasattr(ModuleClient, name), f"{name} is not on the base")
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name not in self.SHARED:
                    continue
                with self.subTest(module=path.name, helper=node.name):
                    body = [n for n in node.body if not isinstance(n, ast.Expr)]
                    self.assertEqual(
                        len(body),
                        1,
                        f"{path.name} reimplements {node.name}; it lives on "
                        "ModuleClient, and a second body is a second dialect",
                    )
                    source = ast.unparse(body[0])
                    self.assertIn(
                        "ModuleClient." + node.name,
                        source,
                        f"{path.name}:{node.name} does not delegate to the base",
                    )

    def test_the_batch_and_follow_forms_use_one_naming_convention_each(self):
        """`<op>_many` for the batch form, `<op>_follow` for the follow form.

        A suffix applies mechanically to every op name where pluralising does
        not, and `<op>_follow` avoids a method named `follow` on which
        `Stream.follow()` is the one reader that must not be used -- which is
        exactly what `Tree.follow` was. Before this rule: `Objects` used `_many`,
        `Crypto` pluralised, `Objects` prefixed `follow_`, `Services` suffixed
        `_follow`, and `Tree` used the bare name.
        """
        import importlib
        import inspect

        from astral.api.base import ModuleClient

        checked = 0
        for path in self.modules():
            module = importlib.import_module(f"astral.api.{path.stem}")
            for cname in sorted(vars(module)):
                cls = getattr(module, cname)
                if not inspect.isclass(cls) or not issubclass(cls, ModuleClient):
                    continue
                if getattr(cls, "__module__", None) != module.__name__:
                    continue
                for mname in sorted(vars(cls)):
                    if mname.startswith("_"):
                        continue
                    checked += 1
                    with self.subTest(method=f"{cname}.{mname}"):
                        self.assertFalse(
                            mname.startswith("follow_"),
                            f"{cname}.{mname}: the follow form is `<op>_follow`",
                        )
                        self.assertNotEqual(
                            mname,
                            "follow",
                            f"{cname}.follow: name it `<op>_follow`; a method "
                            "called `follow` is the one you must not call "
                            "`Stream.follow()` on",
                        )
        self.assertGreater(checked, 40, "the sweep found nothing to check")


class ReferencePolicyTest(unittest.TestCase):
    """No test reads a reference checkout by path. One pin, one reader.

    Five files used to hardcode an absolute path into `astrald` or `astral-go`
    and assert equality against whatever the working tree held. astrald moved two
    commits, gained `op_delete_token.go`, and the apphost origin-guard census
    went red -- over an op the running node does not serve and no SDK method
    drives. That is the SDK's suite reporting a sibling repository's `git pull`,
    and at thirteen modules it is thirteen files doing it.

    So the paths live in `tests/reference.py` with the revision beside them, and
    every read is `git show <rev>:<path>`. Bumping a reference is then a
    deliberate edit in one place, and the citations that name it get re-read
    because the suite says which ones stopped landing.
    """

    def test_no_test_file_hardcodes_a_reference_checkout_path(self):
        # Assembled rather than written out, so this file does not match itself
        # and the check is not silently vacuous.
        needle = "astralp2p" + "/astral"
        tests = pathlib.Path(__file__).resolve().parent
        checked = 0
        for path in sorted(tests.glob("*.py")):
            if path.name == "reference.py":
                continue
            checked += 1
            with self.subTest(module=path.name):
                self.assertNotIn(
                    needle,
                    path.read_text(encoding="utf-8"),
                    f"{path.name} reads a reference checkout by path; go through "
                    "tests/reference.py, which pins the revision",
                )
        self.assertGreater(checked, 10, "the walk found nothing to check")
        # And the one file that may name them does.
        self.assertIn(
            needle,
            (tests / "reference.py").read_text(encoding="utf-8"),
            "the guard's needle no longer matches the reader it exempts",
        )

    def test_the_pins_resolve_and_name_the_revisions_the_modules_cite(self):
        """The pins are the revisions the module docstrings say they were read
        against. If a pin is bumped without the prose, the citations move and
        this suite says which ones."""
        for repo, (_, rev) in reference.PINS.items():
            with self.subTest(repo=repo):
                try:
                    resolved = reference.pin(repo)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertTrue(resolved.startswith(rev))


class SharedPrecheckTest(unittest.TestCase):
    """One dial per process, for the whole live tier."""

    def test_no_module_reimplements_the_tier_c_health_precheck(self):
        """`live_support` exists because the precheck **dials the node**, and a
        copy per file is a dial per file on a pool of 32 shared with every app on
        the machine. The copies had also drifted: `live_support.verdict()` turns
        a `TimeoutError` around the probe into a skip reason, while a bare
        `asyncio.run(asyncio.wait_for(...))` in a copied `setUpModule` errored the
        whole module -- the precise failure a precheck exists to avoid.
        """
        import live_support

        tests = pathlib.Path(__file__).resolve().parent
        for path in sorted(tests.glob("test_*.py")):
            source = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                self.assertIsNone(
                    re.search(r"^def setUpModule", source, re.M),
                    f"{path.name} reimplements the precheck; inherit "
                    "live_support.LiveCase instead",
                )

        import test_api_apphost

        self.assertTrue(issubclass(LiveDirTest, live_support.LiveCase))
        self.assertTrue(
            issubclass(test_api_apphost.LiveApphostTest, live_support.LiveCase)
        )


if __name__ == "__main__":
    unittest.main()
