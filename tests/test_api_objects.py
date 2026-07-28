"""The `objects` module client: 25 ops, the `Writer` lifecycle, the grammar.

Three tiers in one file, on the pattern `test_api_dir.py` set, because the same
claim is made at each and the three must agree:

- **Tier A** pins the wire. Every payload here is bytes `furry-bolt` sent this
  session -- ten `mod.objects.repository_info` frames, a `mod.objects.probe`, and
  the zero value of six types as `objects.new` produced them -- so a round trip
  through them cannot agree with itself while disagreeing with the node. The
  search grammar is pinned against astral-go's `SearchQuery.UnmarshalText` case
  by case, because a searcher registered through `objects.register_searcher` is
  handed the raw string and parses it with that function.
- **Tier B** pins the 25 ops against `MockApphost`: the query string each one
  builds, the answer each one accepts, the terminator each one sends, and the
  `Writer` lifecycle. It also pins the four astral-go client bugs this module
  does not reproduce (G-10 twice, the int64 size, the hardcoded `zone=dvn`).
- **Tier C** runs the read-only ops against a real node and skips without one.

**Nothing here mutates a live node.** `create`, `store`, `push`, `delete`,
`purge`, `new_mem`, `remove_repository` and the three `register_*` ops are
exercised against the mock only; Tier C is the read-only subset of design
section 13's anonymous safe list. `objects.new` is never swept over type names:
`mod.nodes.node_info` panics astrald deterministically, and the one test that
names that type asserts the client refuses it without sending anything.
"""

from __future__ import annotations

import asyncio
import unittest

import astral
from astral.api import objects as objects_module
from astral.api.objects import (
    CHUNK_SIZE,
    CRASHES_ON_NEW,
    FREE_UNKNOWN,
    MAX_PUSH_SIZE,
    OBJECTS_TYPES,
    OP_BLUEPRINTS,
    OP_CONTAINS,
    OP_CREATE,
    OP_DELETE,
    OP_DESCRIBE,
    OP_ECHO,
    OP_FIND,
    OP_GET_BLUEPRINT,
    OP_GET_TYPE,
    OP_LOAD,
    OP_NEW,
    OP_NEW_MEM,
    OP_PROBE,
    OP_PURGE,
    OP_PUSH,
    OP_READ,
    OP_REGISTER_BLUEPRINT,
    OP_REGISTER_DESCRIBER,
    OP_REGISTER_FINDER,
    OP_REGISTER_SEARCHER,
    OP_REMOVE_REPOSITORY,
    OP_REPOSITORIES,
    OP_SCAN,
    OP_SEARCH,
    OP_STORE,
    REPO_GROUPS,
    REPO_MAIN,
    TAG_EXCLUDE,
    TAG_OPTIONAL,
    TAG_OPTIONAL_EXCLUDE,
    TAG_REQUIRE,
    CommitMsg,
    CreateObjectAction,
    Descriptor,
    Objects,
    Probe,
    QueryTag,
    ReadObjectAction,
    RepositoryInfo,
    SearchQuery,
    SearchResult,
)
from astral.blueprint import Blueprint, Field, PrimitiveSpec, SliceSpec
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes
from astral.errors import (
    BadArgument,
    BadArgumentType,
    CycleDetected,
    ParseError,
    ProtocolError,
    RemoteError,
    StreamClosed,
)
from astral.object import Ack, Blob, EOS, ErrorMessage, Nil
from astral.primitives import Bool, String8
from astral.querystring import parse
from astral.registry import Blueprints, default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import PRIMITIVE_TYPES, AnySpec, Primitive, Ptr
from astral.types import Duration, Identity, ObjectID, Size, Zone

import live_support
from mock_apphost import (
    Accept,
    FURRY_BOLT,
    MockApphost,
    MockConn,
    QUERY_ACCEPTED,
    RouteQuery,
    bounded,
    socket_fds,
    until,
)

# --- bytes the node sent, captured this session over unix:~/.apphost.sock ---

LIVE_REPOSITORY_INFO = {
    # name, label, free -- three of the ten `objects.repositories` answered.
    "local": bytes.fromhex(
        "05" "6c6f63616c"
        "0d" "4c6f63616c2073746f72616765"
        "0000000227759000"
    ),
    "memory": bytes.fromhex(
        "06" "6d656d6f7279"
        "0f" "496e2d6d656d6f7279207265706f73"
        "0000000007ffffb9"
    ),
    "virtual": bytes.fromhex(
        "07" "7669727475616c"
        "14" "5669727475616c207265706f7369746f72696573"
        "0000000000000000"
    ),
}

LIVE_PROBE = bytes.fromhex(
    "16" "6d6f642e63727970746f2e707269766174655f6b6579"   # string8 "mod.crypto.private_key"
    "06" "73797374656d"                                   # string8 "system"
    "18" "6170706c69636174696f6e2f6f637465742d73747265616d"  # string8 mime
    "0000000000002134"                                    # duration 8500 ns
)

# `objects.new?type=<name>` on the live node, one zero value per type.
LIVE_ZEROS = {
    "mod.objects.probe": bytes.fromhex("0000000000000000000000"),
    "mod.objects.search_result": bytes.fromhex("0000"),
    "objects.search_query": bytes.fromhex("000000000000"),
    "mod.objects.commit_msg": b"",
    "mod.objects.read_object_action": bytes.fromhex("00000000000000000000"),
}

# Three object ids `objects.scan?repo=main` answered on `furry-bolt`.
ID_A = ObjectID.parse("data1rq4d1hh59rce647e31c8yabupjmiwzrctjwbffm5tjp6gebqedu7j")
ID_B = ObjectID.parse("data1rx47ghdxpmnz3dzab1watz5658m5yt7iaxcqne89b7esq9ijb4gig")
ID_C = ObjectID.parse("data1zspxoximp6nh7wdpmkhg9fnuw4tj98h5ykhd15qub16mwx85d5w8z")

# The first bytes `objects.read?id=<ID_A>` answered: the ADC0 canonical stamp,
# then the type header. Proof that a RAW read is not an object stream.
LIVE_READ_HEAD = bytes.fromhex("41444330166d6f642e63727970746f2e")


def framed(obj: object) -> tuple[str, bytes]:
    """One response frame for an object this SDK can build."""
    return (getattr(obj, "ASTRAL_TYPE", ""), payload_bytes(obj))


def error_frame(message: str) -> tuple[str, bytes]:
    return framed(ErrorMessage(message))


ACK_FRAME = framed(Ack())
EOS_FRAME = framed(EOS())


# --- Tier A: the wire, on the bytes the node sent ------------------------


class RepositoryInfoWireTest(unittest.TestCase):
    """`mod.objects.repository_info`, and R-8's unsigned `Free`."""

    def test_the_live_payloads_decode_and_re_encode_byte_for_byte(self):
        expected = {
            "local": ("Local storage", 9251950592),
            "memory": ("In-memory repos", 134217657),
            "virtual": ("Virtual repositories", 0),
        }
        for name, raw in LIVE_REPOSITORY_INFO.items():
            with self.subTest(repo=name):
                info = RepositoryInfo.read_payload(object_reader(raw))
                label, free = expected[name]
                self.assertEqual(info.name, name)
                self.assertEqual(info.label, label)
                self.assertEqual(int(info.free), free)
                self.assertEqual(payload_bytes(info), raw)

    def test_free_is_unsigned_and_the_sentinel_is_max_uint64(self):
        """R-8 and astral-docs bug D-22. The docs example `Free: -1`; the field
        is `astral.Uint64`, so those bits are 18446744073709551615 and reading
        them signed reports an exabyte of free space as one byte short of
        nothing."""
        self.assertEqual(FREE_UNKNOWN, (1 << 64) - 1)
        raw = payload_bytes(RepositoryInfo(name="x", label="y", free=FREE_UNKNOWN))
        self.assertEqual(raw[-8:], b"\xff" * 8)
        info = RepositoryInfo.read_payload(object_reader(raw))
        self.assertEqual(int(info.free), FREE_UNKNOWN)
        self.assertTrue(info.free_unknown)
        self.assertIsNone(info.free_bytes)

    def test_a_known_free_space_is_reported_as_a_byte_count(self):
        info = RepositoryInfo(name="x", label="y", free=1024)
        self.assertFalse(info.free_unknown)
        self.assertEqual(info.free_bytes, 1024)

    def test_the_field_specs_are_two_string8s_and_a_uint64(self):
        self.assertEqual(
            [(f.wire_name, f.spec) for f in RepositoryInfo.FIELDS],
            [
                ("Name", Primitive("string8")),
                ("Label", Primitive("string8")),
                ("Free", Primitive("uint64")),
            ],
        )


class ProbeWireTest(unittest.TestCase):
    """`mod.objects.probe`, against the node's own bytes and its own blueprint."""

    def test_the_live_payload_decodes_and_re_encodes(self):
        probe = Probe.read_payload(object_reader(LIVE_PROBE))
        self.assertEqual(probe.type, "mod.crypto.private_key")
        self.assertEqual(probe.repo, "system")
        self.assertEqual(probe.mime, "application/octet-stream")
        self.assertEqual(int(probe.time), 8500)
        self.assertEqual(payload_bytes(probe), LIVE_PROBE)

    def test_time_is_a_duration_and_not_a_timestamp(self):
        """The Go field is `astral.Duration`: how long the probe took. Reading it
        as a `time` would report 1970 for every object on the node."""
        self.assertEqual(Probe.FIELDS[-1].spec, Primitive("duration"))
        self.assertIsInstance(Probe().time, Duration)

    def test_the_zero_value_is_the_bytes_the_node_answers(self):
        self.assertEqual(payload_bytes(Probe()), LIVE_ZEROS["mod.objects.probe"])


class DescriptorWireTest(unittest.TestCase):
    """`mod.objects.describe_result`: two pointers and a polymorphic slot."""

    def test_both_ids_are_pointers_and_data_is_an_any_slot(self):
        """R-2: the legacy SDK modelled `*ObjectID` as a bare `object_id.sha256`
        and was one byte off on four records. The node's own blueprint for this
        type declares `ptr`, `ptr`, `object_spec` -- verified live."""
        self.assertEqual(
            [(f.wire_name, f.spec) for f in Descriptor.FIELDS],
            [
                ("SourceID", Ptr("identity")),
                ("ObjectID", Ptr("object_id.sha256")),
                ("Data", AnySpec()),
            ],
        )

    def test_a_populated_descriptor_round_trips(self):
        value = Descriptor(source_id=FURRY_BOLT, object_id=ID_A, data=String8("hi"))
        raw = payload_bytes(value)
        self.assertEqual(raw[0], 0x01)
        self.assertEqual(raw[1:34], FURRY_BOLT.key)
        self.assertEqual(raw[34], 0x01)
        self.assertEqual(raw[35:75], payload_bytes(ID_A))
        back = Descriptor.read_payload(object_reader(raw))
        self.assertEqual(back, value)
        self.assertEqual(payload_bytes(back), raw)

    def test_an_absent_source_is_a_single_zero_byte(self):
        value = Descriptor()
        self.assertEqual(payload_bytes(value)[:2], b"\x00\x00")

    def test_the_wire_name_is_describe_result_and_the_go_name_is_descriptor(self):
        self.assertEqual(Descriptor.ASTRAL_TYPE, "mod.objects.describe_result")
        self.assertEqual(Descriptor.__name__, "Descriptor")


class SearchResultWireTest(unittest.TestCase):
    def test_the_zero_value_is_the_bytes_the_node_answers(self):
        self.assertEqual(
            payload_bytes(SearchResult()), LIVE_ZEROS["mod.objects.search_result"]
        )

    def test_both_fields_are_pointers(self):
        self.assertEqual(
            [f.spec for f in SearchResult.FIELDS],
            [Ptr("identity"), Ptr("object_id.sha256")],
        )


class ActionWireTest(unittest.TestCase):
    """The two authorization actions, and the embedded `auth.Action`."""

    def test_the_field_order_is_gos_promotion_order(self):
        """A value embed flattens in binary, and `dataclasses.fields()` returns
        base fields first, which is what Go promotion does."""
        self.assertEqual(
            [f.wire_name for f in ReadObjectAction.FIELDS],
            ["Nonce", "ActorID", "ObjectID"],
        )
        self.assertEqual(
            [f.wire_name for f in CreateObjectAction.FIELDS], ["Nonce", "ActorID"]
        )

    def test_the_read_action_zero_value_is_the_bytes_the_node_answers(self):
        """Ten bytes: an eight-byte nonce and two absent pointers."""
        self.assertEqual(
            payload_bytes(ReadObjectAction()),
            LIVE_ZEROS["mod.objects.read_object_action"],
        )

    def test_a_populated_read_action_round_trips(self):
        value = ReadObjectAction(actor_id=FURRY_BOLT, object_id=ID_A)
        raw = payload_bytes(value)
        self.assertEqual(ReadObjectAction.read_payload(object_reader(raw)), value)


class CommitMsgWireTest(unittest.TestCase):
    def test_the_payload_is_empty_and_the_node_agrees(self):
        self.assertEqual(payload_bytes(CommitMsg()), b"")
        self.assertEqual(payload_bytes(CommitMsg()), LIVE_ZEROS["mod.objects.commit_msg"])
        self.assertEqual(CommitMsg.FIELDS, ())


class ObjectsTypesTest(unittest.TestCase):
    """What importing this module puts in the registry."""

    def test_every_declared_type_is_registered_under_its_wire_name(self):
        registry = default_blueprints()
        for name in (
            "mod.objects.probe",
            "mod.objects.repository_info",
            "mod.objects.describe_result",
            "mod.objects.search_result",
            "objects.search_query",
            "objects.query_tag",
            "mod.objects.commit_msg",
            "mod.objects.read_object_action",
            "mod.objects.create_object_action",
        ):
            with self.subTest(type=name):
                self.assertTrue(registry.has(name), name)

    def test_the_search_types_carry_no_mod_prefix(self):
        """astral-go's `QueryTag.ObjectType()` is `objects.query_tag`. A `mod.`
        here would make every search query undecodable, and the node's own
        blueprint for the type names it without one -- verified live."""
        self.assertEqual(QueryTag.ASTRAL_TYPE, "objects.query_tag")
        self.assertEqual(SearchQuery.ASTRAL_TYPE, "objects.search_query")

    def test_importing_this_module_registers_astral_blueprint(self):
        """`objects.get_blueprint` answers with an `astral.blueprint`, and
        nothing else in the SDK imports the module that declares it. Before this
        module existed the op answered a type the process could not decode --
        observed against a healthy node as `BlueprintNotFound: astral.blueprint`.
        """
        registry = default_blueprints()
        self.assertTrue(registry.has("astral.blueprint"))
        for carrier in (
            "astral.blueprint.field",
            "astral.blueprint.primitive_spec",
            "astral.blueprint.ref_spec",
            "astral.blueprint.slice_spec",
            "astral.blueprint.array_spec",
            "astral.blueprint.map_spec",
            "astral.blueprint.ptr_spec",
            "astral.blueprint.object_spec",
        ):
            with self.subTest(type=carrier):
                self.assertTrue(registry.has(carrier), carrier)
        self.assertIn(Blueprint, OBJECTS_TYPES)

    def test_the_type_sweep_names_every_declared_type(self):
        self.assertEqual(tuple(Objects.TYPES), tuple(OBJECTS_TYPES))
        for kind in OBJECTS_TYPES:
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertTrue(default_blueprints().has(kind.ASTRAL_TYPE))

    def test_the_sweep_builds_a_registry_that_decodes_a_blueprint(self):
        """The reason to name all nine `astral.blueprint` types rather than the
        one this module exchanges: `astral.blueprint`'s `Fields` slot references
        `astral.blueprint.field`, which reaches the seven carriers through a
        polymorphic slot, so a sweep naming the outer type alone produces a
        registry that raises `BlueprintNotFound` on the first answer."""
        registry = Blueprints()
        registry.add(*Objects.TYPES)
        for name in ("astral.blueprint", "astral.blueprint.field", "objects.query_tag"):
            with self.subTest(type=name):
                self.assertTrue(registry.has(name))

    def test_the_module_declares_one_constant_per_op(self):
        """25 ops, and the inventory is the live `shell.spec` registry: verified
        this session against `furry-bolt`, whose 118 op specs contain exactly
        these 25 under the `objects.` prefix."""
        expected = {
            "objects.blueprints": "blueprints",
            "objects.contains": "contains",
            "objects.create": "create",
            "objects.delete": "delete",
            "objects.describe": "describe",
            "objects.echo": "echo",
            "objects.find": "find",
            "objects.get_blueprint": "get_blueprint",
            "objects.get_type": "get_type",
            "objects.load": "load",
            "objects.new": "new",
            "objects.new_mem": "new_mem",
            "objects.probe": "probe",
            "objects.purge": "purge",
            "objects.push": "push",
            "objects.read": "read",
            "objects.register_blueprint": "register_blueprint",
            "objects.register_describer": "register_describer",
            "objects.register_finder": "register_finder",
            "objects.register_searcher": "register_searcher",
            "objects.remove_repository": "remove_repository",
            "objects.repositories": "repositories",
            "objects.scan": "scan",
            "objects.search": "search",
            "objects.store": "store",
        }
        self.assertEqual(len(expected), 25)
        constants = {
            value
            for name, value in vars(objects_module).items()
            if name.startswith("OP_") and isinstance(value, str)
        }
        self.assertEqual(constants, set(expected))
        for op, method in expected.items():
            with self.subTest(op=op):
                self.assertTrue(callable(getattr(Objects, method)), op)

    def test_the_batch_and_follow_forms_are_named_after_their_op(self):
        """A second entry point for one op, never a second op: `contains_many`
        is `objects.contains` with its ids on the body, `scan_follow` is
        `objects.scan` with `follow=true`, `open_read` is `objects.read`
        streamed."""
        for method, op in (
            ("contains_many", OP_CONTAINS),
            ("delete_many", OP_DELETE),
            ("load_many", OP_LOAD),
            ("probe_many", OP_PROBE),
            ("scan_follow", OP_SCAN),
            ("open_read", OP_READ),
            ("learn", OP_GET_BLUEPRINT),
        ):
            with self.subTest(method=method):
                self.assertTrue(callable(getattr(Objects, method)))
                self.assertTrue(op.startswith("objects."))

    def test_the_repository_group_names_are_astral_gos_eight(self):
        self.assertEqual(
            REPO_GROUPS,
            ("main", "device", "memory", "local", "removable", "virtual", "network", "system"),
        )
        self.assertEqual(REPO_MAIN, "main")


class SearchGrammarTest(unittest.TestCase):
    """`objects.search_query`'s text form, against astral-go's parser.

    A searcher registered through `objects.register_searcher` is handed the raw
    string and parses it with `SearchQuery.UnmarshalText`, so a second dialect
    here would make the SDK and the node disagree about what the user asked for.
    """

    def test_bare_words_accumulate_into_the_query_and_lowercase(self):
        q = SearchQuery.parse("Hello World")
        self.assertEqual(q.query, "hello world")
        self.assertEqual(q.tags, [])

    def test_a_tag_splits_at_the_first_colon_and_lowercases_both_halves(self):
        q = SearchQuery.parse("Foo:BAR")
        self.assertEqual(q.query, "")
        self.assertEqual([(t.name, t.mod, t.value) for t in q.tags], [("foo", "", "bar")])

    def test_a_value_may_contain_further_colons(self):
        (tag,) = SearchQuery.parse("a:b:c").tags
        self.assertEqual((tag.name, tag.value), ("a", "b:c"))

    def test_the_four_modifiers(self):
        q = SearchQuery.parse("a:1 -b:2 ?c:3 ~d:4")
        self.assertEqual(
            [(t.name, t.mod) for t in q.tags],
            [
                ("a", TAG_REQUIRE),
                ("b", TAG_EXCLUDE),
                ("c", TAG_OPTIONAL),
                ("d", TAG_OPTIONAL_EXCLUDE),
            ],
        )
        self.assertEqual(TAG_REQUIRE, "")
        self.assertEqual(TAG_EXCLUDE, "EXCLUDE")
        self.assertEqual(TAG_OPTIONAL, "OPTIONAL")
        self.assertEqual(TAG_OPTIONAL_EXCLUDE, "OPTIONAL_EXCLUDE")

    def test_double_quotes_group_spaces_and_are_removed(self):
        (tag,) = SearchQuery.parse('title:"around the world"').tags
        self.assertEqual((tag.name, tag.value), ("title", "around the world"))

    def test_a_quoted_bare_phrase_is_one_word_run(self):
        self.assertEqual(SearchQuery.parse('"quoted phrase"').query, "quoted phrase")

    def test_the_modifier_is_read_after_the_quotes_are_stripped(self):
        """astral-go tokenizes first and tests the prefix second, so `"-tag:v"`
        is an exclusion rather than a bare word. Reproduced, not corrected."""
        (tag,) = SearchQuery.parse('-"tag:v"').tags
        self.assertEqual((tag.name, tag.mod), ("tag", TAG_EXCLUDE))

    def test_an_unbalanced_quote_does_not_raise(self):
        """The reference keeps the rest of the string in one token. A parser that
        raised here would refuse a query the node accepts."""
        self.assertEqual(SearchQuery.parse('unbalanced"quote here').query, "unbalancedquote here")

    def test_runs_of_spaces_collapse(self):
        self.assertEqual(SearchQuery.parse("x  y").query, "x y")

    def test_an_empty_query_is_empty_and_not_an_error(self):
        for text in ("", "   "):
            with self.subTest(text=text):
                q = SearchQuery.parse(text)
                self.assertEqual((q.query, q.tags), ("", []))

    def test_the_text_form_puts_tags_first_and_quotes_what_has_spaces(self):
        q = SearchQuery.parse('title:"around the world" -tag:x word one')
        self.assertEqual(q.text(), 'title:"around the world" -tag:x "word one"')

    def test_parsing_the_text_form_yields_an_equal_query(self):
        for text in (
            'title:"around the world" -tag:x ?a:b ~c:d word',
            "plain words only",
            "k:v",
            "",
        ):
            with self.subTest(text=text):
                q = SearchQuery.parse(text)
                self.assertEqual(SearchQuery.parse(q.text()), q)

    def test_required_tags_in_ignores_optional_tags(self):
        q = SearchQuery.parse("a:1 -b:2 ?c:3 ~d:4")
        self.assertEqual(q.required_tags_in("a"), "b")
        self.assertIsNone(q.required_tags_in("a", "b"))

    def test_a_query_round_trips_through_the_binary_codec(self):
        q = SearchQuery.parse('title:"a b" -x:y words')
        raw = payload_bytes(q)
        self.assertEqual(SearchQuery.read_payload(object_reader(raw)), q)
        self.assertEqual(payload_bytes(SearchQuery.read_payload(object_reader(raw))), raw)

    def test_the_zero_query_is_the_bytes_the_node_answers(self):
        self.assertEqual(payload_bytes(SearchQuery()), LIVE_ZEROS["objects.search_query"])

    def test_a_tag_renders_its_own_prefix(self):
        self.assertEqual(QueryTag(name="a", mod=TAG_EXCLUDE, value="b").text(), "-a:b")
        self.assertEqual(QueryTag(name="a", mod=TAG_REQUIRE, value="b c").text(), 'a:"b c"')


class ArgumentDisciplineTest(unittest.TestCase):
    """What this module refuses before it sends anything."""

    def test_every_parameter_has_a_declared_spec(self):
        """Design section 5.1 rule 2. Without one the encoder dispatches on the
        *value*, so a wrong-typed argument is encoded rather than refused."""
        self.assertEqual(objects_module._SPECS["id"], Primitive("object_id.sha256"))
        self.assertEqual(objects_module._SPECS["repo"], Primitive("string8"))
        self.assertEqual(objects_module._SPECS["zone"], Primitive("zone"))
        self.assertEqual(objects_module._SPECS["alloc"], Primitive("uint64"))
        with self.assertRaises(astral.SchemaError):
            objects_module._encode({"repo": b"main"})
        with self.assertRaises(astral.SchemaError):
            objects_module._encode({"alloc": b"4096"})

    def test_one_spec_dict_is_enough_because_id_means_one_thing(self):
        """`apphost` needed three dicts: its `id` is an identity, an object id or
        a nonce depending on the op. Every `objects` op that declares `id`
        declares an `object_id.sha256` -- verified against the live registry."""
        self.assertEqual(len(objects_module._SPECS), 16)

    def test_an_empty_repository_name_is_refused_with_the_reason(self):
        for op in (OP_SCAN, OP_CONTAINS, OP_DELETE, OP_PURGE):
            with self.subTest(op=op), self.assertRaises(BadArgument) as caught:
                objects_module._repo("", op)
            self.assertIn("no default repository", str(caught.exception))

    def test_a_type_name_containing_the_separator_is_refused(self):
        """astrald splits `only=` and `except=` on the comma, so such a name is
        two names on the server and matches neither."""
        with self.assertRaises(BadArgument) as caught:
            objects_module._name_list(["a,b"], "only", OP_DESCRIBE)
        self.assertIn("two names", str(caught.exception))
        self.assertEqual(objects_module._name_list(["a", "b"], "only", OP_DESCRIBE), "a,b")
        self.assertEqual(objects_module._name_list("a", "only", OP_DESCRIBE), "a")
        self.assertIsNone(objects_module._name_list(None, "only", OP_DESCRIBE))

    def test_a_size_travels_as_a_size_string_and_not_as_an_int64(self):
        """astral-go's `new_mem` client sends an int64 where the op parses the
        value with `astral.ParseSize` (bug G-11 item 3)."""
        self.assertEqual(objects_module._size("64M", OP_NEW_MEM), "64M")
        self.assertEqual(objects_module._size(1024, OP_NEW_MEM), "1024")
        self.assertEqual(objects_module._size(Size(1536), OP_NEW_MEM), "1536")
        with self.assertRaises(ParseError):
            objects_module._size("64 gigabytes", OP_NEW_MEM)
        with self.assertRaises(BadArgumentType):
            objects_module._size(1.5, OP_NEW_MEM)

    def test_an_object_id_argument_accepts_the_text_form(self):
        self.assertEqual(objects_module._object_id(str(ID_A), OP_LOAD), ID_A)
        with self.assertRaises(ParseError):
            objects_module._object_id("not-an-id", OP_LOAD)

    def test_a_zone_argument_accepts_letters_bits_or_a_zone(self):
        self.assertEqual(objects_module._zone("dv"), Zone.DEVICE | Zone.VIRTUAL)
        self.assertEqual(objects_module._zone(1), Zone.DEVICE)
        self.assertEqual(objects_module._zone(Zone.ALL), Zone.ALL)

    def test_the_zone_argument_is_sent_as_the_op_argument_and_as_the_hop(self):
        """astrald seeds the op's context from `route_query_msg.Zone` and then
        `scan`, `delete`, `purge` and `load` overwrite it with the argument,
        defaulting to `ZoneAll`. Setting only one of the two therefore either
        does nothing or leaves the hop wider than the caller asked."""
        params: dict[str, object] = {}
        kw: dict[str, object] = {}
        objects_module._scope(Zone.DEVICE, params, kw)
        self.assertEqual(params["zone"], Zone.DEVICE)
        self.assertEqual(kw["zone"], Zone.DEVICE)
        params, kw = {}, {}
        objects_module._scope(None, params, kw)
        self.assertEqual((params, kw), ({}, {}))

    def test_the_node_killing_type_is_named_and_refused(self):
        self.assertEqual(CRASHES_ON_NEW, frozenset({"mod.nodes.node_info"}))


# --- Tier B: the ops against the mock ------------------------------------


class ObjectsCase(unittest.IsolatedAsyncioTestCase):
    """An `Objects` over a mock apphost, closed by the teardown whatever a test
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

    async def objects(self, mock: MockApphost, **kw: object) -> Objects:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Objects(client)

    def sent(self, mock: MockApphost) -> str:
        """The one query string the mock received."""
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    def params(self, mock: MockApphost) -> tuple[str, dict[str, str]]:
        return parse(self.sent(mock))

    async def finished(self, route: "Batch | CreateRoute") -> None:
        """Yield to the loop until the mock's handler has read to the end.

        The mock's handler is a task. When an op returns, its last frame is on
        the wire but the handler has not necessarily been scheduled to read it,
        and `MockApphost.aclose()` closes every connection before awaiting the
        task group -- which discards unread bytes exactly as a closed socket
        does. So a test that asserts on what the client sent waits for the reader
        rather than for the writer.
        """
        self.assertTrue(await until(lambda: route.done), f"{route!r} never finished")

    def assert_no_faults(self, mock: MockApphost) -> None:
        self.assertEqual(mock.errors, [])


class Batch:
    """A route that answers one frame per input frame, as the BD ops do.

    Reads and answers strictly in step, so a client that sent its whole batch
    before reading any answer would deadlock here rather than passing: the mock
    never runs ahead of the exchange it is standing in for.

    `frames` is every body frame the client sent, in order, and `done` says the
    reader reached the end -- either the client's terminator or EOF.
    """

    def __init__(
        self,
        *answers: tuple[str, bytes],
        trailing_eos: bool = False,
        short: bool = False,
    ) -> None:
        self.answers = list(answers)
        self.trailing_eos = trailing_eos
        # `short` closes as soon as the answers run out, which is the op dying
        # mid-batch rather than the op ending.
        self.short = short
        self.frames: list[tuple[str, bytes]] = []
        self.done = False

    def __repr__(self) -> str:
        return f"Batch({len(self.answers)} answers, {len(self.frames)} read)"

    @property
    def types(self) -> list[str]:
        return [name for name, _ in self.frames]

    async def __call__(self, conn: MockConn, query: RouteQuery) -> None:
        conn.send_frame(QUERY_ACCEPTED)
        await conn.flush()
        for answer in self.answers:
            received = await conn.recv_frame_or_none()
            if received is None:
                break
            self.frames.append(received)
            if received[0] == "eos":
                break
            conn.send_frame(*answer)
            await conn.flush()
        if self.short:
            self.done = True
            await conn.aclose()
            return
        while not self.frames or self.frames[-1][0] != "eos":
            received = await conn.recv_frame_or_none()
            if received is None:
                break
            self.frames.append(received)
        if self.trailing_eos:
            conn.send_frame(*EOS_FRAME)
            await conn.flush()
        self.done = True
        await conn.aclose()


class CreateRoute:
    """`objects.create`: ack, absorb blobs, answer the commit."""

    def __init__(self, *, object_id: ObjectID | None = ID_A, error: str | None = None) -> None:
        self.object_id = object_id
        self.error = error
        self.frames: list[tuple[str, bytes]] = []
        self.done = False

    def __repr__(self) -> str:
        return f"CreateRoute({len(self.frames)} read)"

    @property
    def types(self) -> list[str]:
        return [name for name, _ in self.frames]

    @property
    def blobs(self) -> list[bytes]:
        return [payload for name, payload in self.frames if name == ""]

    async def __call__(self, conn: MockConn, query: RouteQuery) -> None:
        conn.send_frame(QUERY_ACCEPTED)
        conn.send_frame(*ACK_FRAME)
        await conn.flush()
        while True:
            received = await conn.recv_frame_or_none()
            if received is None:
                break
            self.frames.append(received)
            if received[0] == "mod.objects.commit_msg":
                conn.send_frame(
                    *(error_frame(self.error) if self.error else framed(self.object_id))
                )
                await conn.flush()
                break
        self.done = True
        await conn.aclose()


class RepositoriesOpTest(ObjectsCase):
    """`objects.repositories`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_typed_repository_info(self):
        frames = [
            ("mod.objects.repository_info", raw)
            for raw in LIVE_REPOSITORY_INFO.values()
        ]
        mock = MockApphost(routes={OP_REPOSITORIES: Accept(objects=frames, eos=True)})
        async with mock:
            o = await self.objects(mock)
            repos = await o.repositories()
        self.assertEqual([r.name for r in repos], ["local", "memory", "virtual"])
        self.assertEqual(int(repos[0].free), 9251950592)
        self.assertEqual(self.sent(mock), OP_REPOSITORIES)
        self.assert_no_faults(mock)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_REPOSITORIES: Accept(objects=[ACK_FRAME], eos=True)})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ProtocolError) as caught:
                await o.repositories()
        self.assertIn("mod.objects.repository_info", str(caught.exception))


class NewMemOpTest(ObjectsCase):
    """`objects.new_mem`: RR, mutates."""

    @bounded()
    async def test_it_sends_a_size_string(self):
        mock = MockApphost(routes={OP_NEW_MEM: Accept(objects=[ACK_FRAME])})
        async with mock:
            o = await self.objects(mock)
            await o.new_mem("cache", size="64M")
        self.assertEqual(self.params(mock), (OP_NEW_MEM, {"name": "cache", "size": "64M"}))

    @bounded()
    async def test_an_int_size_travels_as_decimal_bytes(self):
        mock = MockApphost(routes={OP_NEW_MEM: Accept(objects=[ACK_FRAME])})
        async with mock:
            o = await self.objects(mock)
            await o.new_mem("cache", size=1024)
        self.assertEqual(self.params(mock)[1]["size"], "1024")

    @bounded()
    async def test_size_is_omitted_when_the_caller_omits_it(self):
        mock = MockApphost(routes={OP_NEW_MEM: Accept(objects=[ACK_FRAME])})
        async with mock:
            o = await self.objects(mock)
            await o.new_mem("cache")
        self.assertEqual(self.params(mock), (OP_NEW_MEM, {"name": "cache"}))

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        mock = MockApphost(
            routes={OP_NEW_MEM: Accept(objects=[error_frame("repository exists")])}
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.new_mem("cache")
        self.assertEqual(caught.exception.message, "repository exists")


class RemoveRepositoryOpTest(ObjectsCase):
    """`objects.remove_repository`: RR, mutates."""

    @bounded()
    async def test_it_sends_the_name_and_expects_an_ack(self):
        mock = MockApphost(routes={OP_REMOVE_REPOSITORY: Accept(objects=[ACK_FRAME])})
        async with mock:
            o = await self.objects(mock)
            await o.remove_repository("cache")
        self.assertEqual(
            self.params(mock), (OP_REMOVE_REPOSITORY, {"name": "cache"})
        )

    @bounded()
    async def test_an_empty_name_is_refused_without_a_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                await o.remove_repository("")
        self.assertEqual(mock.queries, [])


class ScanOpTest(ObjectsCase):
    """`objects.scan`: ST, and the op with no default repository."""

    @bounded()
    async def test_it_returns_object_ids(self):
        frames = [framed(i) for i in (ID_A, ID_B, ID_C)]
        mock = MockApphost(routes={OP_SCAN: Accept(objects=frames, eos=True)})
        async with mock:
            o = await self.objects(mock)
            ids = await o.scan(REPO_MAIN)
        self.assertEqual(ids, [ID_A, ID_B, ID_C])
        self.assertEqual(
            self.params(mock), (OP_SCAN, {"repo": "main", "follow": "false"})
        )

    @bounded()
    async def test_an_omitted_repository_is_refused_without_a_query(self):
        """Verified live: `objects.scan` with no `repo` answers
        `error_message("repository not found")`, which reads as a missing
        repository rather than as a missing argument."""
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                await o.scan("")
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_zone_reaches_the_query_string_and_the_hop(self):
        mock = MockApphost(routes={OP_SCAN: Accept(objects=[], eos=True)})
        async with mock:
            o = await self.objects(mock)
            await o.scan(REPO_MAIN, zone=Zone.DEVICE)
        self.assertEqual(self.params(mock)[1]["zone"], "d")
        self.assertEqual(mock.queries[0].zone, int(Zone.DEVICE))

    @bounded()
    async def test_scan_follow_crosses_the_snapshot_separator(self):
        mock = MockApphost(
            routes={
                OP_SCAN: Accept(
                    objects=[framed(ID_A)], eos=True, live=[framed(ID_B)], hold=True
                )
            }
        )
        async with mock:
            o = await self.objects(mock)
            async with o.scan_follow(REPO_MAIN) as stream:
                snapshot = [obj async for obj in stream.snapshot()]
                self.assertEqual(snapshot, [ID_A])
                self.assertTrue(stream.is_live)
                updates = stream.live()
                try:
                    self.assertEqual(await anext(updates), ID_B)
                finally:
                    await updates.aclose()
        self.assertEqual(self.params(mock)[1]["follow"], "true")

    @bounded()
    async def test_async_for_on_a_follow_stream_is_refused_rather_than_truncating(self):
        """The other half of the pairing, and the quieter failure of the two.

        `async for` stops at the first `eos`, which on a follow op is the
        snapshot/live separator: it returns the snapshot, drops every live object
        and reports nothing at all. Verified against the real op -- three ids
        then silence -- so the refusal names the readers that work.
        """
        mock = MockApphost(
            routes={
                OP_SCAN: Accept(
                    objects=[framed(ID_A)], eos=True, live=[framed(ID_B)], hold=True
                )
            }
        )
        async with mock:
            o = await self.objects(mock)
            async with o.scan_follow(REPO_MAIN) as stream:
                with self.assertRaises(ProtocolError) as caught:
                    async for _ in stream:
                        pass
                message = str(caught.exception)
                self.assertIn("dropped in silence", message)
                self.assertIn("snapshot()", message)
                # The declared readers are untouched by the refusal.
                self.assertEqual([obj async for obj in stream.snapshot()], [ID_A])

    @bounded()
    async def test_scan_follow_opens_on_the_persistent_lane_with_no_deadline(self):
        """Three requirements that have nothing to do with each other. A query
        permit spent on a stream that never ends is a permit never returned."""
        mock = MockApphost(routes={OP_SCAN: Accept(objects=[framed(ID_A)], hold=True)})
        async with mock:
            o = await self.objects(mock, max_concurrency=1, max_persistent=1)
            async with o.scan_follow(REPO_MAIN) as stream:
                self.assertFalse(stream.closed)
                # The persistent lane carries it; the query lane is untouched, so
                # an ordinary call still fits beside a stream that never ends.
                self.assertEqual(o.client.available_persistent, 0)
                self.assertEqual(o.client.available, 1)


class ContainsOpTest(ObjectsCase):
    """`objects.contains`: RR with an id, BD without one."""

    @bounded()
    async def test_the_single_form_returns_a_bool(self):
        mock = MockApphost(routes={OP_CONTAINS: Accept(objects=[framed(Bool(True))])})
        async with mock:
            o = await self.objects(mock)
            self.assertIs(await o.contains(REPO_MAIN, ID_A), True)
        self.assertEqual(
            self.params(mock), (OP_CONTAINS, {"repo": "main", "id": str(ID_A)})
        )

    @bounded()
    async def test_the_batch_form_sends_ids_on_the_body(self):
        route = Batch(framed(Bool(True)), framed(Bool(False)))
        mock = MockApphost(routes={OP_CONTAINS: route})
        async with mock:
            o = await self.objects(mock)
            got = await o.contains_many(REPO_MAIN, [ID_A, ID_B])
            await self.finished(route)
        self.assertEqual(got, [True, False])
        self.assertEqual(self.params(mock), (OP_CONTAINS, {"repo": "main"}))
        self.assertEqual(route.frames, [framed(ID_A), framed(ID_B)])

    @bounded()
    async def test_the_batch_form_sends_no_eos(self):
        """astrald's handler ignores it and keeps reading, so what ends this op
        is the stream closing -- verified live: after `send_eos()` the node
        answered nothing further and the stream stayed open."""
        route = Batch(framed(Bool(True)))
        mock = MockApphost(routes={OP_CONTAINS: route})
        async with mock:
            o = await self.objects(mock)
            await o.contains_many(REPO_MAIN, [ID_A])
            await self.finished(route)
        self.assertNotIn("eos", route.types)

    @bounded()
    async def test_an_empty_batch_costs_no_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.contains_many(REPO_MAIN, []), [])
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_per_input_error_names_which_input(self):
        mock = MockApphost(
            routes={OP_CONTAINS: Batch(framed(Bool(True)), error_frame("repository not found"))}
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.contains_many(REPO_MAIN, [ID_A, ID_B])
        self.assertEqual(caught.exception.message, "repository not found")
        self.assertIn("input 1", str(caught.exception))


class ProbeOpTest(ObjectsCase):
    """`objects.probe`: RR with an id, BD without one."""

    @bounded()
    async def test_the_single_form_returns_a_probe(self):
        mock = MockApphost(
            routes={OP_PROBE: Accept(objects=[("mod.objects.probe", LIVE_PROBE)])}
        )
        async with mock:
            o = await self.objects(mock)
            probe = await o.probe(ID_A)
        self.assertEqual(probe.type, "mod.crypto.private_key")
        self.assertEqual(self.params(mock), (OP_PROBE, {"id": str(ID_A)}))

    @bounded()
    async def test_a_repository_may_be_named(self):
        mock = MockApphost(
            routes={OP_PROBE: Accept(objects=[("mod.objects.probe", LIVE_PROBE)])}
        )
        async with mock:
            o = await self.objects(mock)
            await o.probe(ID_A, repo="system")
        self.assertEqual(self.params(mock)[1]["repo"], "system")

    @bounded()
    async def test_the_batch_form_sends_the_eos_because_the_op_closes_on_it(self):
        route = Batch(("mod.objects.probe", LIVE_PROBE), ("mod.objects.probe", LIVE_PROBE))
        mock = MockApphost(routes={OP_PROBE: route})
        async with mock:
            o = await self.objects(mock)
            probes = await o.probe_many([ID_A, ID_B])
            await self.finished(route)
        self.assertEqual(len(probes), 2)
        self.assertEqual(route.types, ["object_id.sha256", "object_id.sha256", "eos"])


class GetTypeOpTest(ObjectsCase):
    """`objects.get_type`: RR, deprecated in favour of `probe`."""

    @bounded()
    async def test_it_returns_the_type_name(self):
        mock = MockApphost(
            routes={OP_GET_TYPE: Accept(objects=[framed(String8("mod.crypto.private_key"))])}
        )
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.get_type(ID_A), "mod.crypto.private_key")
        self.assertEqual(self.params(mock), (OP_GET_TYPE, {"id": str(ID_A)}))

    @bounded()
    async def test_an_untypeable_object_is_a_remote_error(self):
        mock = MockApphost(routes={OP_GET_TYPE: Accept(objects=[error_frame("unknown type")])})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.get_type(ID_A)
        self.assertEqual(caught.exception.message, "unknown type")


class LoadOpTest(ObjectsCase):
    """`objects.load`: RR with an id, BD without one."""

    @bounded()
    async def test_it_returns_the_decoded_object(self):
        mock = MockApphost(routes={OP_LOAD: Accept(objects=[framed(String8("hi"))])})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.load(ID_A), String8("hi"))
        self.assertEqual(self.params(mock), (OP_LOAD, {"id": str(ID_A)}))

    @bounded()
    async def test_unparsed_is_sent_when_asked_for(self):
        """Sent faithfully, and documented for what it is: astrald hands it to
        `channel.AllowUnparsed`, which configures the op's *receiver*, so on this
        form it changes nothing."""
        mock = MockApphost(routes={OP_LOAD: Accept(objects=[framed(String8("hi"))])})
        async with mock:
            o = await self.objects(mock)
            await o.load(ID_A, unparsed=True)
        self.assertEqual(self.params(mock)[1]["unparsed"], "true")

    @bounded()
    async def test_the_batch_form_sends_no_eos(self):
        route = Batch(framed(String8("a")), framed(String8("b")))
        mock = MockApphost(routes={OP_LOAD: route})
        async with mock:
            o = await self.objects(mock)
            got = await o.load_many([ID_A, ID_B])
            await self.finished(route)
        self.assertEqual(got, [String8("a"), String8("b")])
        self.assertNotIn("eos", route.types)

    @bounded()
    async def test_a_per_input_error_names_which_input(self):
        mock = MockApphost(
            routes={OP_LOAD: Batch(framed(String8("a")), error_frame("not found"))}
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.load_many([ID_A, ID_B])
        self.assertIn("input 1", str(caught.exception))


class ReadOpTest(ObjectsCase):
    """`objects.read`: the SDK's only RAW op."""

    @bounded()
    async def test_it_returns_unframed_bytes(self):
        mock = MockApphost(routes={OP_READ: Accept(raw=LIVE_READ_HEAD)})
        async with mock:
            o = await self.objects(mock)
            data = await o.read(ID_A)
        self.assertEqual(data, LIVE_READ_HEAD)
        self.assertEqual(self.params(mock), (OP_READ, {"id": str(ID_A)}))

    @bounded()
    async def test_the_body_is_not_an_object_stream(self):
        """`41444330` is the ADC0 canonical stamp of the stored object. Framing
        this as protocol would decode a file as a type name."""
        self.assertEqual(LIVE_READ_HEAD[:4], b"ADC0")

    @bounded()
    async def test_offset_and_limit_are_sent_when_given(self):
        mock = MockApphost(routes={OP_READ: Accept(raw=b"x" * 8)})
        async with mock:
            o = await self.objects(mock)
            await o.read(ID_A, offset=4, limit=8)
        self.assertEqual(
            self.params(mock)[1], {"id": str(ID_A), "offset": "4", "limit": "8"}
        )

    @bounded()
    async def test_no_zone_is_sent_unless_the_caller_asks(self):
        """astral-go's client hardcodes `zone=dvn` and ignores the caller's own
        context (bug G-11 item 4)."""
        mock = MockApphost(routes={OP_READ: Accept(raw=b"x")})
        async with mock:
            o = await self.objects(mock)
            await o.read(ID_A)
        self.assertNotIn("zone", self.params(mock)[1])

    @bounded()
    async def test_limit_zero_is_refused_because_it_means_no_limit(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument) as caught:
                await o.read(ID_A, limit=0)
        self.assertIn("no limit", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_open_read_walks_the_body_in_pieces(self):
        mock = MockApphost(routes={OP_READ: Accept(raw=b"abcdefgh")})
        async with mock:
            o = await self.objects(mock)
            async with o.open_read(ID_A) as stream:
                self.assertEqual(await stream.read_bytes(4), b"abcd")
                self.assertEqual(await stream.read_bytes(4), b"efgh")


class DescribeOpTest(ObjectsCase):
    """`objects.describe`: ST, and a bare `eos` is the ordinary answer."""

    @bounded()
    async def test_it_returns_typed_descriptors(self):
        value = Descriptor(source_id=FURRY_BOLT, object_id=ID_A, data=String8("hi"))
        mock = MockApphost(routes={OP_DESCRIBE: Accept(objects=[framed(value)], eos=True)})
        async with mock:
            o = await self.objects(mock)
            got = await o.describe(ID_A)
        self.assertEqual(got, [value])

    @bounded()
    async def test_a_bare_eos_is_an_empty_list_and_not_a_fault(self):
        """Verified live for every object in the default repository: the node has
        no describers registered, so the shape is real and the emptiness is node
        state."""
        mock = MockApphost(routes={OP_DESCRIBE: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.describe(ID_A), [])

    @bounded()
    async def test_only_and_except_are_comma_joined_under_the_wire_keys(self):
        mock = MockApphost(routes={OP_DESCRIBE: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            await o.describe(ID_A, only=["a", "b"], except_="c")
        self.assertEqual(
            self.params(mock)[1],
            {"id": str(ID_A), "only": "a,b", "except": "c"},
        )


class FindOpTest(ObjectsCase):
    """`objects.find`: ST, deduplicated identities."""

    @bounded()
    async def test_it_returns_identities(self):
        mock = MockApphost(routes={OP_FIND: Accept(objects=[framed(FURRY_BOLT)], eos=True)})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.find(ID_A), [FURRY_BOLT])
        self.assertEqual(self.params(mock), (OP_FIND, {"id": str(ID_A)}))

    @bounded()
    async def test_a_bare_eos_means_nobody_offered(self):
        mock = MockApphost(routes={OP_FIND: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.find(ID_A), [])


class SearchOpTest(ObjectsCase):
    """`objects.search`: ST, deduplicated by object id."""

    @bounded()
    async def test_it_returns_typed_search_results(self):
        value = SearchResult(source_id=FURRY_BOLT, object_id=ID_A)
        mock = MockApphost(routes={OP_SEARCH: Accept(objects=[framed(value)], eos=True)})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.search("word"), [value])
        self.assertEqual(self.params(mock), (OP_SEARCH, {"q": "word"}))

    @bounded()
    async def test_a_search_query_object_travels_as_its_text_form(self):
        """The node parses the string itself; the parsed form never travels."""
        mock = MockApphost(routes={OP_SEARCH: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            await o.search(SearchQuery.parse('title:"a b" word'))
        self.assertEqual(self.params(mock)[1]["q"], 'title:"a b" word')

    @bounded()
    async def test_a_repository_filters_the_results(self):
        mock = MockApphost(routes={OP_SEARCH: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            await o.search("word", repo=REPO_MAIN)
        self.assertEqual(self.params(mock)[1]["repo"], "main")

    @bounded()
    async def test_a_wrong_argument_type_is_refused_without_a_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgumentType):
                await o.search(object())  # type: ignore[arg-type]
        self.assertEqual(mock.queries, [])


class BlueprintsOpTest(ObjectsCase):
    """`objects.blueprints`: ST, names in dependency order."""

    @bounded()
    async def test_it_returns_type_names(self):
        frames = [framed(String8(n)) for n in ("ack", "eos", "mod.objects.probe")]
        mock = MockApphost(routes={OP_BLUEPRINTS: Accept(objects=frames, eos=True)})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(
                await o.blueprints(), ["ack", "eos", "mod.objects.probe"]
            )
        self.assertEqual(self.sent(mock), OP_BLUEPRINTS)


def blueprint_frame(bp: Blueprint) -> tuple[str, bytes]:
    return ("astral.blueprint", payload_bytes(bp))


PROBE_BLUEPRINT = Blueprint(
    type="mod.objects.probe",
    fields=[
        Field(name="Type", spec=PrimitiveSpec(primitive_type="string8")),
        Field(name="Repo", spec=PrimitiveSpec(primitive_type="string8")),
        Field(name="Mime", spec=PrimitiveSpec(primitive_type="string8")),
        Field(name="Time", spec=PrimitiveSpec(primitive_type="duration")),
    ],
)

PEER_TAG = Blueprint(
    type="peer.tag",
    fields=[Field(name="Name", spec=PrimitiveSpec(primitive_type="string8"))],
)

PEER_QUERY = Blueprint(
    type="peer.query",
    fields=[
        Field(name="Text", spec=PrimitiveSpec(primitive_type="string16")),
        Field(name="Tags", spec=SliceSpec(type="peer.tag")),
    ],
)


class GetBlueprintOpTest(ObjectsCase):
    """`objects.get_blueprint`: RR, and design bug G-21 withdrawn."""

    @bounded()
    async def test_it_returns_a_typed_blueprint(self):
        mock = MockApphost(
            routes={OP_GET_BLUEPRINT: Accept(objects=[blueprint_frame(PROBE_BLUEPRINT)])}
        )
        async with mock:
            o = await self.objects(mock)
            bp = await o.get_blueprint("mod.objects.probe")
        self.assertIsInstance(bp, Blueprint)
        self.assertEqual([f.name for f in bp.fields], ["Type", "Repo", "Mime", "Time"])
        self.assertEqual(
            self.params(mock), (OP_GET_BLUEPRINT, {"type": "mod.objects.probe"})
        )

    @bounded()
    async def test_a_blueprint_for_the_wrong_type_is_a_protocol_error(self):
        mock = MockApphost(
            routes={OP_GET_BLUEPRINT: Accept(objects=[blueprint_frame(PEER_TAG)])}
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ProtocolError) as caught:
                await o.get_blueprint("mod.objects.probe")
        self.assertIn("peer.tag", str(caught.exception))

    @bounded()
    async def test_a_primitive_answers_a_remote_error(self):
        mock = MockApphost(
            routes={
                OP_GET_BLUEPRINT: Accept(
                    objects=[error_frame("primitive type has no blueprint: uint8")]
                )
            }
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError):
                await o.get_blueprint("uint8")


class LearnTest(ObjectsCase):
    """`learn`: a node's type, its closure, and a `RuntimeRecord` over both."""

    def route(self, *blueprints: Blueprint) -> dict[str, object]:
        return {
            f"{OP_GET_BLUEPRINT}?type={bp.type}": Accept(objects=[blueprint_frame(bp)])
            for bp in blueprints
        }

    @bounded()
    async def test_it_learns_a_types_references_before_the_type_itself(self):
        """`Blueprints.register_blueprint` forbids a dangling reference, and
        astrald sends one blueprint and leaves its references to the caller. So
        the recursion is what makes registration possible at all."""
        mock = MockApphost(routes=self.route(PEER_QUERY, PEER_TAG))
        registry = Blueprints(default_blueprints())
        async with mock:
            o = await self.objects(mock)
            bp = await o.learn("peer.query", registry=registry)
        self.assertEqual(bp.type, "peer.query")
        self.assertTrue(registry.has("peer.tag"))
        self.assertTrue(registry.has("peer.query"))
        self.assertEqual([q.op for q in mock.queries], [OP_GET_BLUEPRINT] * 2)

    @bounded()
    async def test_a_learned_type_constructs_a_runtime_record(self):
        mock = MockApphost(routes=self.route(PEER_QUERY, PEER_TAG))
        registry = Blueprints(default_blueprints())
        async with mock:
            o = await self.objects(mock)
            await o.learn("peer.query", registry=registry)
        value = registry.new("peer.query")
        self.assertEqual(value.ASTRAL_TYPE, "peer.query")
        self.assertEqual(payload_bytes(value), bytes.fromhex("000000000000"))

    @bounded()
    async def test_an_already_registered_type_costs_no_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            bp = await o.learn("mod.objects.probe")
        self.assertEqual(bp.type, "mod.objects.probe")
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_primitive_is_refused_locally_with_the_nodes_own_reason(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument) as caught:
                await o.learn("uint8")
        self.assertIn("primitive", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_reference_cycle_raises_rather_than_recursing(self):
        """astral-go stack-overflows on a mutually recursive pair (bug G-22) and
        this is the path that would reach it."""
        left = Blueprint(
            type="cyc.left", fields=[Field(name="R", spec=SliceSpec(type="cyc.right"))]
        )
        right = Blueprint(
            type="cyc.right", fields=[Field(name="L", spec=SliceSpec(type="cyc.left"))]
        )
        mock = MockApphost(routes=self.route(left, right))
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(CycleDetected):
                await o.learn("cyc.left", registry=Blueprints(default_blueprints()))

    @bounded()
    async def test_learning_into_a_child_keeps_the_process_registry_clean(self):
        mock = MockApphost(routes=self.route(PEER_TAG))
        registry = Blueprints(default_blueprints())
        async with mock:
            o = await self.objects(mock)
            await o.learn("peer.tag", registry=registry)
        self.assertTrue(registry.has("peer.tag"))
        self.assertFalse(default_blueprints().has("peer.tag"))


class NewOpTest(ObjectsCase):
    """`objects.new`: RR, and the one type that must never be sent."""

    @bounded()
    async def test_it_returns_the_zero_value(self):
        mock = MockApphost(
            routes={OP_NEW: Accept(objects=[("mod.objects.probe", LIVE_ZEROS["mod.objects.probe"])])}
        )
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.new("mod.objects.probe"), Probe())
        self.assertEqual(self.params(mock), (OP_NEW, {"type": "mod.objects.probe"}))

    @bounded()
    async def test_an_unknown_type_answers_nil_and_nil_is_returned(self):
        """Verified live for `no.such.type`. `Nil()` is a registered type and a
        legitimate answer, not an error to translate."""
        mock = MockApphost(routes={OP_NEW: Accept(objects=[framed(Nil())])})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.new("no.such.type"), Nil())

    @bounded()
    async def test_the_node_killing_type_is_refused_without_a_query(self):
        """`mod.nodes.node_info`'s zero value holds a nil `*Identity` and its
        `WriteTo` has a value receiver, so serialising it kills astrald. The fix
        is not merged, so the running node still crashes."""
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument) as caught:
                await o.new("mod.nodes.node_info")
        self.assertIn("crashes the node", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_empty_type_name_is_refused(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                await o.new("")
        self.assertEqual(mock.queries, [])


class RegisterBlueprintOpTest(ObjectsCase):
    """`objects.register_blueprint`: BD, and G-10's missing terminator."""

    @bounded()
    async def test_it_sends_the_blueprints_on_the_body_and_returns_their_ids(self):
        route = Batch(framed(ID_A), framed(ID_B), trailing_eos=True)
        mock = MockApphost(routes={OP_REGISTER_BLUEPRINT: route})
        async with mock:
            o = await self.objects(mock)
            ids = await o.register_blueprint(PEER_TAG, PEER_QUERY)
            await self.finished(route)
        self.assertEqual(ids, [ID_A, ID_B])
        self.assertEqual(route.frames[0], blueprint_frame(PEER_TAG))
        self.assertEqual(route.frames[1], blueprint_frame(PEER_QUERY))

    @bounded()
    async def test_the_terminating_eos_is_sent(self):
        """Design bug G-10: astral-go's client never sends it, so the op's read
        loop waits for input that never ends and the exchange finishes only when
        the connection dies."""
        route = Batch(framed(ID_A), trailing_eos=True)
        mock = MockApphost(routes={OP_REGISTER_BLUEPRINT: route})
        async with mock:
            o = await self.objects(mock)
            await o.register_blueprint(PEER_TAG)
            await self.finished(route)
        self.assertEqual(route.types, ["astral.blueprint", "eos"])

    @bounded()
    async def test_a_refused_blueprint_names_which_input(self):
        mock = MockApphost(
            routes={
                OP_REGISTER_BLUEPRINT: Batch(
                    framed(ID_A), error_frame("blueprint for peer.query already added")
                )
            }
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.register_blueprint(PEER_TAG, PEER_QUERY)
        self.assertIn("input 1", str(caught.exception))
        self.assertEqual(
            caught.exception.message, "blueprint for peer.query already added"
        )

    @bounded()
    async def test_a_non_blueprint_input_is_refused_without_a_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgumentType):
                await o.register_blueprint(Ack())  # type: ignore[arg-type]
        self.assertEqual(mock.queries, [])


class StoreOpTest(ObjectsCase):
    """`objects.store`: BD, and G-10's other missing terminator."""

    @bounded()
    async def test_it_sends_objects_on_the_body_and_returns_their_ids(self):
        route = Batch(framed(ID_A), framed(ID_B))
        mock = MockApphost(routes={OP_STORE: route})
        async with mock:
            o = await self.objects(mock)
            ids = await o.store(String8("a"), String8("b"), repo=REPO_MAIN)
            await self.finished(route)
        self.assertEqual(ids, [ID_A, ID_B])
        self.assertEqual(self.params(mock), (OP_STORE, {"repo": "main"}))
        self.assertEqual(route.frames[:2], [framed(String8("a")), framed(String8("b"))])

    @bounded()
    async def test_the_terminating_eos_is_sent(self):
        route = Batch(framed(ID_A))
        mock = MockApphost(routes={OP_STORE: route})
        async with mock:
            o = await self.objects(mock)
            await o.store(String8("a"))
            await self.finished(route)
        self.assertEqual(route.types, ["string8", "eos"])

    @bounded()
    async def test_a_rejected_object_names_which_input(self):
        mock = MockApphost(routes={OP_STORE: Batch(error_frame("read-only"))})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.store(String8("a"))
        self.assertIn("input 0", str(caught.exception))


class PushOpTest(ObjectsCase):
    """`objects.push`: BD, one `bool` per object."""

    @bounded()
    async def test_it_returns_one_bool_per_object(self):
        mock = MockApphost(
            routes={OP_PUSH: Batch(framed(Bool(True)), framed(Bool(False)))}
        )
        async with mock:
            o = await self.objects(mock)
            got = await o.push(String8("a"), String8("b"))
        self.assertEqual(got, [True, False])
        self.assertEqual(self.sent(mock), OP_PUSH)

    @bounded()
    async def test_false_is_the_ordinary_answer_and_not_an_error(self):
        """A node with no receiver registered for a type answers `False` for
        every object."""
        mock = MockApphost(routes={OP_PUSH: Batch(framed(Bool(False)))})
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.push(String8("a")), [False])

    @bounded()
    async def test_an_oversized_object_is_refused_without_a_query(self):
        """astrald declares the cap and does not enforce it; relying on an
        unenforced remote limit is how a client breaks the day it is."""
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument) as caught:
                await o.push(Blob(b"x" * (MAX_PUSH_SIZE + 1)))
        self.assertIn(str(MAX_PUSH_SIZE), str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_terminating_eos_is_sent(self):
        route = Batch(framed(Bool(True)))
        mock = MockApphost(routes={OP_PUSH: route})
        async with mock:
            o = await self.objects(mock)
            await o.push(String8("a"))
            await self.finished(route)
        self.assertEqual(route.types, ["string8", "eos"])


class DeleteOpTest(ObjectsCase):
    """`objects.delete`: RR with an id, BD without one. Mutates."""

    @bounded()
    async def test_the_single_form_expects_an_ack(self):
        mock = MockApphost(routes={OP_DELETE: Accept(objects=[ACK_FRAME])})
        async with mock:
            o = await self.objects(mock)
            await o.delete(REPO_MAIN, ID_A)
        self.assertEqual(
            self.params(mock), (OP_DELETE, {"repo": "main", "id": str(ID_A)})
        )

    @bounded()
    async def test_a_repository_is_required_and_positional(self):
        """astrald says why in its own source: no default, "to avoid accidental
        deletion"."""
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                await o.delete("", ID_A)
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_batch_form_reads_one_ack_per_id(self):
        route = Batch(ACK_FRAME, ACK_FRAME)
        mock = MockApphost(routes={OP_DELETE: route})
        async with mock:
            o = await self.objects(mock)
            await o.delete_many(REPO_MAIN, [ID_A, ID_B])
            await self.finished(route)
        self.assertEqual(route.frames, [framed(ID_A), framed(ID_B)])


class PurgeOpTest(ObjectsCase):
    """`objects.purge`: ST, and it deletes data."""

    @bounded()
    async def test_it_returns_the_purged_ids(self):
        mock = MockApphost(
            routes={OP_PURGE: Accept(objects=[framed(ID_A), framed(ID_B)], eos=True)}
        )
        async with mock:
            o = await self.objects(mock)
            self.assertEqual(await o.purge(REPO_MAIN), [ID_A, ID_B])
        self.assertEqual(self.params(mock), (OP_PURGE, {"repo": "main"}))

    @bounded()
    async def test_a_repository_is_required(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                await o.purge("")
        self.assertEqual(mock.queries, [])


class RegisterProviderOpTest(ObjectsCase):
    """The three `objects.register_*` ops: RR, one `ack`, then close."""

    @bounded()
    async def test_each_one_reads_an_ack_and_closes(self):
        """Design section 4.6: the registration is **not** channel-scoped.
        astral-go's own client opens the channel, expects an `ack` and closes
        it, contradicting the legacy SDK's "keep the stream open"."""
        for op, call in (
            (OP_REGISTER_SEARCHER, "register_searcher"),
            (OP_REGISTER_DESCRIBER, "register_describer"),
            (OP_REGISTER_FINDER, "register_finder"),
        ):
            with self.subTest(op=op):
                mock = MockApphost(routes={op: Accept(objects=[ACK_FRAME])})
                async with mock:
                    o = await self.objects(mock)
                    await getattr(o, call)()
                self.assertEqual(self.sent(mock), op)

    @bounded()
    async def test_an_anonymous_caller_is_refused_by_the_node(self):
        """The op needs a non-zero identity that is not the node's own, and the
        router substitutes the node's identity for an anonymous guest."""
        mock = MockApphost(
            routes={OP_REGISTER_SEARCHER: Accept(objects=[error_frame("invalid source identity")])}
        )
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(RemoteError) as caught:
                await o.register_searcher()
        self.assertEqual(caught.exception.message, "invalid source identity")

    def test_the_op_names_come_from_the_registrar(self):
        """The registrar re-runs these after every reconnect; two spellings of
        one op name is one typo away from a registration that never happens."""
        from astral import registrar

        self.assertIs(OP_REGISTER_SEARCHER, registrar.OP_REGISTER_SEARCHER)
        self.assertIs(OP_REGISTER_DESCRIBER, registrar.OP_REGISTER_DESCRIBER)
        self.assertIs(OP_REGISTER_FINDER, registrar.OP_REGISTER_FINDER)


class EchoOpTest(ObjectsCase):
    """`objects.echo`: BD, the wire-schema conformance tool."""

    @bounded()
    async def test_an_object_comes_back_identical(self):
        mock = MockApphost(routes={OP_ECHO: Accept(echo=True)})
        async with mock:
            o = await self.objects(mock)
            async with o.echo() as stream:
                value = Probe(type="t", repo="r", mime="m")
                await stream.send(value)
                back = await stream.first()
                self.assertEqual(back, value)
                self.assertEqual(payload_bytes(back), payload_bytes(value))
                await stream.send_eos()

    @bounded()
    async def test_every_argument_reaches_the_query_string(self):
        mock = MockApphost(routes={OP_ECHO: Accept(echo=True)})
        async with mock:
            o = await self.objects(mock)
            async with o.echo(only=["a"], except_=["b"], stop="eos", strict=True):
                pass
        self.assertEqual(
            self.params(mock)[1],
            {"only": "a", "except": "b", "stop": "eos", "strict": "true"},
        )

    @bounded()
    async def test_nothing_is_sent_when_nothing_is_asked_for(self):
        mock = MockApphost(routes={OP_ECHO: Accept(echo=True)})
        async with mock:
            o = await self.objects(mock)
            async with o.echo():
                pass
        self.assertEqual(self.sent(mock), OP_ECHO)


class CreateOpTest(ObjectsCase):
    """`objects.create` and the `Writer` lifecycle."""

    @bounded()
    async def test_a_committed_writer_returns_the_new_object_id(self):
        route = CreateRoute()
        mock = MockApphost(routes={OP_CREATE: route})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                self.assertEqual(await writer.write(b"hello"), 5)
                self.assertEqual(await writer.commit(), ID_A)
                self.assertTrue(writer.committed)
                self.assertEqual(writer.object_id, ID_A)
            await self.finished(route)
        self.assertEqual(route.frames[0], ("", b"hello"))
        self.assertEqual(route.types, ["", "mod.objects.commit_msg"])

    @bounded()
    async def test_the_data_travels_as_untyped_blob_frames(self):
        """A `blob` frame carries a zero-length type tag: `blob` is not a
        registered type name, it is the absence of one."""
        route = CreateRoute()
        mock = MockApphost(routes={OP_CREATE: route})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.write(b"abc")
                await writer.commit()
            await self.finished(route)
        self.assertEqual(route.frames[0], ("", b"abc"))

    @bounded()
    async def test_a_large_write_is_split_into_chunks(self):
        route = CreateRoute()
        mock = MockApphost(routes={OP_CREATE: route})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.write(b"x" * (CHUNK_SIZE + 1))
                await writer.commit()
            await self.finished(route)
        self.assertEqual([len(b) for b in route.blobs], [CHUNK_SIZE, 1])

    @bounded()
    async def test_an_empty_write_sends_no_frame(self):
        route = CreateRoute()
        mock = MockApphost(routes={OP_CREATE: route})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                self.assertEqual(await writer.write(b""), 0)
                await writer.commit()
            await self.finished(route)
        self.assertEqual(route.types, ["mod.objects.commit_msg"])

    @bounded()
    async def test_a_discarded_writer_sends_no_commit(self):
        route = CreateRoute()
        mock = MockApphost(routes={OP_CREATE: route})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.write(b"lost")
                await writer.discard()
                self.assertTrue(writer.resolved)
                self.assertFalse(writer.committed)
            await self.finished(route)
        self.assertEqual(route.types, [""])

    @bounded()
    async def test_leaving_the_scope_unresolved_discards_and_raises(self):
        """The rule astral-go states and does not enforce. A writer that is
        neither committed nor discarded loses every byte written to it and the
        node reports nothing, so the loss is made loud here."""
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(StreamClosed) as caught:
                async with o.create() as writer:
                    await writer.write(b"lost")
        self.assertIn("neither committed nor discarded", str(caught.exception))

    @bounded()
    async def test_an_exception_in_the_body_discards_and_propagates(self):
        """A failure inside the body is a reason not to commit, not a second
        fault to report."""
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ZeroDivisionError):
                async with o.create() as writer:
                    await writer.write(b"lost")
                    raise ZeroDivisionError("in the body")

    @bounded()
    async def test_discard_after_commit_is_a_no_op(self):
        """`try: … finally: await w.discard()` is a correct idiom rather than a
        way to lose a committed object."""
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.commit()
                await writer.discard()
                self.assertTrue(writer.committed)

    @bounded()
    async def test_write_after_commit_is_refused(self):
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.commit()
                with self.assertRaises(StreamClosed):
                    await writer.write(b"late")
                with self.assertRaises(StreamClosed):
                    await writer.commit()

    @bounded()
    async def test_a_non_bytes_write_is_refused(self):
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                with self.assertRaises(BadArgumentType):
                    await writer.write("text")  # type: ignore[arg-type]
                await writer.discard()

    @bounded()
    async def test_a_failed_commit_leaves_the_writer_discarded(self):
        mock = MockApphost(routes={OP_CREATE: CreateRoute(error="disk full")})
        async with mock:
            o = await self.objects(mock)
            async with o.create() as writer:
                await writer.write(b"data")
                with self.assertRaises(RemoteError) as caught:
                    await writer.commit()
                self.assertEqual(caught.exception.message, "disk full")
                self.assertTrue(writer.resolved)
                self.assertFalse(writer.committed)

    @bounded()
    async def test_the_arguments_reach_the_query_string(self):
        mock = MockApphost(routes={OP_CREATE: CreateRoute()})
        async with mock:
            o = await self.objects(mock)
            async with o.create(repo=REPO_MAIN, alloc=4096) as writer:
                await writer.discard()
        self.assertEqual(self.params(mock)[1], {"repo": "main", "alloc": "4096"})

    @bounded()
    async def test_a_negative_alloc_is_refused_without_a_query(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(BadArgument):
                async with o.create(alloc=-1):
                    pass
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_op_that_never_acks_costs_the_ack_timeout_and_closes(self):
        """The state the wire reaches whenever the op goroutine stalls between
        `q.AcceptRaw()` and its first send."""
        mock = MockApphost(routes={OP_CREATE: Accept(hold=True)})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(astral.QueryTimeout):
                async with o.create(ack_timeout=0.2):
                    pass
        await self.assert_client_has_no_live_streams()

    @bounded()
    async def test_a_wrong_first_object_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_CREATE: Accept(objects=[framed(String8("no"))])})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ProtocolError) as caught:
                async with o.create():
                    pass
        self.assertIn("ack", str(caught.exception))

    async def assert_client_has_no_live_streams(self) -> None:
        for client in self.clients:
            self.assertEqual(client.live_streams, 0)


class ExchangeTest(ObjectsCase):
    """The shared body-input path the seven BD ops go through."""

    @bounded()
    async def test_a_short_answer_stream_is_a_protocol_error_naming_the_count(self):
        mock = MockApphost(routes={OP_STORE: Batch(framed(ID_A), short=True)})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ProtocolError) as caught:
                await o.store(String8("a"), String8("b"))
        self.assertIn("1 of 2", str(caught.exception))

    @bounded()
    async def test_the_whole_exchange_is_bounded_by_one_budget(self):
        """An op that accepts and then says nothing costs `timeout`, not the rest
        of the process's life."""
        mock = MockApphost(routes={OP_STORE: Accept(hold=True)})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(astral.QueryTimeout):
                await o.store(String8("a"), timeout=0.2)
        for client in self.clients:
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_wrong_answer_type_names_the_input_and_both_types(self):
        mock = MockApphost(routes={OP_STORE: Batch(ACK_FRAME)})
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(ProtocolError) as caught:
                await o.store(String8("a"))
        message = str(caught.exception)
        self.assertIn("input 0", message)
        self.assertIn("object_id.sha256", message)
        self.assertIn("ack", message)


class ModuleClientContractTest(ObjectsCase):
    """What `ModuleClient` promises, kept by this module too."""

    @bounded()
    async def test_the_client_is_reachable_and_the_repr_names_it(self):
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            self.assertIs(o.client, self.clients[0])
            self.assertTrue(repr(o).startswith("Objects("))

    @bounded()
    async def test_query_keywords_pass_through_unread(self):
        mock = MockApphost(routes={OP_REPOSITORIES: Accept(eos=True)})
        async with mock:
            o = await self.objects(mock)
            await o.repositories(target=FURRY_BOLT, filters=["all"])
        self.assertEqual(mock.queries[0].target, FURRY_BOLT)
        self.assertEqual(mock.queries[0].filters, ("all",))

    @bounded()
    async def test_a_misspelled_keyword_fails_rather_than_being_dropped(self):
        """The defect astral-go ships in its own clients: its
        `apphost.new_app_contract` sends `ID` and `Duration` capitalised, the
        node's parameter matching is case-sensitive, and unknown keys are
        silently discarded."""
        mock = MockApphost()
        async with mock:
            o = await self.objects(mock)
            with self.assertRaises(TypeError):
                await o.repositories(Target=FURRY_BOLT)  # type: ignore[call-arg]

    @bounded()
    async def test_every_remote_error_carries_the_responders_own_text(self):
        """`errors.py` documents the attribute a caller matches on: "`message`
        is the responder's own text, unprefixed, because a caller that matches on
        it -- astrald's `record not found` is the common one -- must not have to
        strip attribution first."

        `objects.load_many` folded the op name and the input index into
        `message`. It was invisible in every test that asserts on the string,
        because `attributed()` de-duplicates the prefix and `str(exc)` reads the
        same either way -- the divergence is only in the attribute. So the check
        drives one op per raising path and reads `.message` and `.endpoint`.
        """
        fault = "record not found"
        answer = Accept(objects=[error_frame(fault)])
        batch = Batch(error_frame(fault))
        cases = {
            # (route, call) -- one per RemoteError-raising path in this module.
            "stream": (
                {OP_REPOSITORIES: answer},
                lambda o: o.repositories(),
            ),
            "_typed batch": (
                {OP_STORE: batch},
                lambda o: o.store(String8("a")),
            ),
            "load_many": (
                {OP_LOAD: batch},
                lambda o: o.load_many([ID_A]),
            ),
        }
        for name, (routes, call) in cases.items():
            with self.subTest(path=name):
                mock = MockApphost(routes=routes)
                async with mock:
                    o = await self.objects(mock)
                    with self.assertRaises(RemoteError) as caught:
                        await call(o)
                self.assertEqual(
                    caught.exception.message,
                    fault,
                    "the SDK's attribution leaked into the responder's text",
                )
                self.assertEqual(caught.exception.endpoint, "mem:mock")


# --- Tier C: the live node ------------------------------------------------


class LiveObjectsTest(live_support.LiveCase):
    """The read-only ops against a real node. Skips when none answers.

    Nothing here mutates. `create`, `store`, `push`, `delete`, `purge`,
    `new_mem`, `remove_repository` and the three `register_*` ops never reach a
    live node from this suite, and `objects.new` is called on two named types
    rather than swept over the registry.
    """

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.client = await self.client()
        self.objects = Objects(self.client)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        await flush_cancels(5.0)
        await self.assert_no_open_sockets()

    async def any_id(self) -> ObjectID:
        ids = await self.objects.scan(REPO_MAIN, timeout=20)
        if not ids:
            self.skipTest("the node's main repository is empty")
        return ids[0]

    async def test_repositories_decode_to_typed_records(self):
        repos = await self.objects.repositories(timeout=20)
        self.assertTrue(repos)
        names = {r.name for r in repos}
        self.assertIn(REPO_MAIN, names)
        for repo in repos:
            with self.subTest(repo=repo.name):
                self.assertIsInstance(repo, RepositoryInfo)
                self.assertIsInstance(repo.free, int)
                self.assertGreaterEqual(int(repo.free), 0)

    async def test_scan_needs_an_explicit_repository(self):
        """The refusal is local; the node's own answer is
        `error_message("repository not found")`."""
        with self.assertRaises(BadArgument):
            await self.objects.scan("", timeout=20)

    async def test_scan_and_contains_agree(self):
        ids = await self.objects.scan(REPO_MAIN, timeout=20)
        for object_id in ids[:3]:
            with self.subTest(id=str(object_id)):
                self.assertIsInstance(object_id, ObjectID)
                self.assertTrue(await self.objects.contains(REPO_MAIN, object_id, timeout=20))

    async def test_contains_many_answers_one_bool_per_id(self):
        ids = await self.objects.scan(REPO_MAIN, timeout=20)
        if not ids:
            self.skipTest("the node's main repository is empty")
        answers = await self.objects.contains_many(REPO_MAIN, ids, timeout=25)
        self.assertEqual(len(answers), len(ids))
        self.assertTrue(all(answers))

    async def test_probe_and_get_type_agree(self):
        object_id = await self.any_id()
        probe = await self.objects.probe(object_id, timeout=20)
        self.assertIsInstance(probe, Probe)
        self.assertEqual(await self.objects.get_type(object_id, timeout=20), probe.type)

    async def test_probe_many_answers_one_probe_per_id(self):
        ids = await self.objects.scan(REPO_MAIN, timeout=20)
        probes = await self.objects.probe_many(ids[:2], timeout=25)
        self.assertEqual(len(probes), len(ids[:2]))
        for probe in probes:
            self.assertIsInstance(probe, Probe)

    async def test_load_returns_a_typed_object(self):
        object_id = await self.any_id()
        probe = await self.objects.probe(object_id, timeout=20)
        loaded = await self.objects.load(object_id, timeout=20)
        self.assertEqual(getattr(loaded, "ASTRAL_TYPE", ""), probe.type)

    async def test_load_many_answers_one_object_per_id(self):
        ids = await self.objects.scan(REPO_MAIN, timeout=20)
        loaded = await self.objects.load_many(ids[:2], timeout=25)
        self.assertEqual(len(loaded), len(ids[:2]))

    async def test_read_answers_unframed_bytes(self):
        """The one RAW op. An accepted query does not always carry objects."""
        object_id = await self.any_id()
        data = await self.objects.read(object_id, limit=16, timeout=20)
        self.assertEqual(len(data), 16)
        self.assertEqual(data[:4], b"ADC0")

    async def test_read_honours_offset(self):
        object_id = await self.any_id()
        whole = await self.objects.read(object_id, limit=16, timeout=20)
        tail = await self.objects.read(object_id, offset=4, limit=12, timeout=20)
        self.assertEqual(tail, whole[4:])

    async def test_open_read_walks_the_body(self):
        object_id = await self.any_id()
        async with self.objects.open_read(object_id, timeout=20) as stream:
            self.assertEqual(await stream.read_bytes(4, timeout=20), b"ADC0")

    async def test_describe_answers_a_bare_eos(self):
        """The node has no describers registered, so the empty list is node state
        rather than a fault. The claim is the shape, not the emptiness."""
        object_id = await self.any_id()
        self.assertEqual(await self.objects.describe(object_id, timeout=20), [])

    async def test_find_answers_a_terminated_stream(self):
        object_id = await self.any_id()
        found = await self.objects.find(object_id, timeout=30)
        for identity in found:
            self.assertIsInstance(identity, Identity)

    async def test_search_accepts_both_argument_forms(self):
        for query in ("test", SearchQuery.parse("key:value word")):
            with self.subTest(query=str(query)):
                results = await self.objects.search(query, timeout=30)
                for result in results:
                    self.assertIsInstance(result, SearchResult)

    async def test_blueprints_lists_more_types_than_this_sdk_declares(self):
        names = await self.objects.blueprints(timeout=20)
        self.assertGreater(len(names), len(default_blueprints().ordered()))
        self.assertIn("mod.objects.probe", names)

    async def test_get_blueprint_answers_the_probe_schema(self):
        """Design bug G-21 withdrawn: the op exists and answers."""
        bp = await self.objects.get_blueprint("mod.objects.probe", timeout=20)
        self.assertEqual(bp.type, "mod.objects.probe")
        self.assertEqual([f.name for f in bp.fields], ["Type", "Repo", "Mime", "Time"])

    async def test_get_blueprint_refuses_a_primitive(self):
        with self.assertRaises(RemoteError):
            await self.objects.get_blueprint("uint8", timeout=20)

    @bounded(600.0)
    async def test_the_census_in_the_docstrings_matches_the_node(self):
        """The two docstrings state one live census and both had it off by one:
        "96 of the 133 non-primitive names" where the node answers 97 of 134.
        The pair was internally consistent -- 96 + 37 = 133 -- so the error was
        one classification and nothing failed. A stale sentence in a module that
        cites live measurement everywhere costs a reader the rest of the file's
        credibility, so the numbers are read off the node instead.

        Serial, one query at a time, and the whole sweep is one session: this is
        somebody's node and its worker pool is 32 wide for every app on the
        machine.
        """
        names = [str(n) for n in await self.objects.blueprints(timeout=30)]
        non_primitive = [n for n in names if n not in PRIMITIVE_TYPES]
        answered = refused = 0
        for name in non_primitive:
            try:
                blueprint = await self.objects.get_blueprint(name, timeout=20)
            except RemoteError:
                refused += 1
                continue
            answered += 1
            # The SDK's own assertion, over every name the node will describe.
            self.assertEqual(blueprint.type, name)

        doc = objects_module.Objects.get_blueprint.__doc__ or ""
        doc += objects_module.Objects.blueprints.__doc__ or ""
        self.assertIn(
            f"{answered} of the {len(non_primitive)}",
            doc,
            f"the docstrings state a census the node does not: it answered "
            f"{answered} of {len(non_primitive)} non-primitive names and "
            f"refused {refused}",
        )
        self.assertIn(f"refused {refused}", doc)
        self.assertIn(f"{len(names)} names on `furry-bolt`", doc + (
            objects_module.Objects.blueprints.__doc__ or ""
        ))

    async def test_learn_registers_a_types_closure(self):
        """The wiring `RuntimeRecord` needed: a node's type, learned into a child
        registry, constructs a runtime value."""
        registry = Blueprints(default_blueprints())
        name = "mod.nodes.link_info"
        try:
            await self.objects.learn(name, registry=registry, timeout=30)
        except RemoteError as exc:
            # astral-go's reflector cannot describe every registered type; that
            # is the node's limit and it is reported rather than hidden.
            self.skipTest(f"the node cannot describe {name}: {exc.message}")
        self.assertTrue(registry.has(name))
        value = registry.new(name)
        self.assertEqual(value.ASTRAL_TYPE, name)
        self.assertEqual(payload_bytes(value), payload_bytes(value))

    async def test_new_answers_a_zero_value_and_nil_for_an_unknown_type(self):
        self.assertEqual(await self.objects.new("mod.objects.probe", timeout=20), Probe())
        self.assertEqual(await self.objects.new("no.such.type", timeout=20), Nil())

    async def test_new_refuses_the_node_killing_type_without_a_query(self):
        with self.assertRaises(BadArgument):
            await self.objects.new("mod.nodes.node_info", timeout=20)

    async def test_echo_round_trips_this_modules_own_types(self):
        """The strongest agreement test the protocol offers: the node decodes
        what this SDK encoded and re-encodes it to the same bytes."""
        values = [
            Probe(type="t", repo="r", mime="m", time=Duration(5)),
            SearchQuery(query="q", tags=[QueryTag(name="a", mod="EXCLUDE", value="b")]),
            Descriptor(source_id=FURRY_BOLT, object_id=await self.any_id()),
            SearchResult(object_id=await self.any_id()),
        ]
        async with self.objects.echo(timeout=25) as stream:
            for value in values:
                with self.subTest(type=value.ASTRAL_TYPE):
                    await stream.send(value, timeout=20)
                    back = await stream.first(timeout=20)
                    self.assertEqual(back, value)
                    self.assertEqual(payload_bytes(back), payload_bytes(value))
            await stream.send_eos(timeout=20)

    async def test_scan_follow_separates_the_snapshot_from_the_live_stream(self):
        """Drained and closed inside the block: a follow stream left open holds
        one of the node's 32 workers until the node restarts."""
        async with self.objects.scan_follow(REPO_MAIN) as stream:
            snapshot = []
            iterator = stream.snapshot()
            try:
                async with asyncio.timeout(20):
                    async for object_id in iterator:
                        snapshot.append(object_id)
            finally:
                await iterator.aclose()
            self.assertTrue(stream.is_live)
        stored = await self.objects.scan(REPO_MAIN, timeout=20)
        self.assertEqual(snapshot, stored)

    async def test_a_zone_argument_reaches_the_op(self):
        ids = await self.objects.scan(REPO_MAIN, zone=Zone.DEVICE, timeout=20)
        for object_id in ids:
            self.assertIsInstance(object_id, ObjectID)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
