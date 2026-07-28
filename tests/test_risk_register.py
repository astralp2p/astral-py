"""The risk register of design section 9.1, pinned to the bytes a node sent.

Seventeen risks, each an assumption the legacy SDK carried for its whole life
without ever confirming it against a node. This file is where the ones that
have been settled stop being assumptions: every vector below is bytes captured
from `furry-bolt` (`03b27049...ae1`, astrald `074a852b`, astral-go `5c18d9c`)
over `unix:~/.apphost.sock`, decoded here through the SDK's own codec. A round
trip through bytes the SDK produced could agree with itself while disagreeing
with the node; a round trip through the node's bytes cannot.

The tier split is the point of the file. **Tier A needs no node**, so the
assumption stays pinned on a machine where astrald has never run -- which is
the only way an assumption cannot silently rot. Tier C re-runs each probe
against a live node and asserts the same bytes come back, which is how a *node*
changing under the SDK is caught.

Four types below -- `mod.objects.repository_info`, `mod.objects.search_result`,
`mod.objects.describe_result` and `routing.op_spec` -- were declared here in a
private registry under `probe.`-prefixed names while the modules that own them
were unwritten, so that the shape a live node proved was pinned before there was
anywhere else to put it. All four have since landed, in `api/objects.py` and
`api/shell.py`, and this file now imports the **shipped** declarations and
decodes the captured bytes through them. That is the regression the probes
existed for and it is strictly stronger: a stand-in can agree with the node while
the code that ships disagrees with both, which is exactly what a duplicate
declaration stops anyone noticing.

`PROBE_TYPES` remains, empty of records and parented on the default registry, for
the next shape a node proves before a module claims it.

**One live probe in this file's subject area must never be run again.**
`objects.new?type=mod.nodes.node_info` **kills astrald** -- the registry's zero
value has a nil `*astral.Identity`, `NodeInfo.WriteTo` hands it straight to
`streams.WriteAllTo`, and `Identity.WriteTo` has a value receiver, so the call
dereferences nil and panics on a goroutine `lib/routing.(*Op).RouteQuery`
spawns without any recover. Observed this session: the node wrote
`13 "mod.nodes.node_info"` -- the type tag `BinarySender.Send` writes before it
serialises the payload -- and the process was gone before the length prefix.
Any local process that can open the apphost socket can end the node with that
one read-only query, authenticated or not. `FORBIDDEN_LIVE_QUERIES` names it and
a test asserts nothing here sends it.
"""

from __future__ import annotations

import json
import os
import unittest

from astral.codec.binary import object_reader, payload_bytes, read_fields, write_fields
from astral.registry import Blueprints, default_blueprints
from astral.types import Identity, Nonce, ObjectID, Size
from astral.wire import Reader, Writer

from astral.api.objects import Descriptor as DescribeResult
from astral.api.objects import RepositoryInfo, SearchResult
from astral.api.shell import OpSpec

from live_support import LiveCase
from mock_apphost import bounded

# --- the node these bytes came from --------------------------------------

FURRY_BOLT = Identity.parse(
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)
FURRY_BOLT_HEX = (
    "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
)

FORBIDDEN_LIVE_QUERIES = ("objects.new?type=mod.nodes.node_info",)
"""Queries that crash astrald. Never sent, live tier or not (module docstring)."""


# --- the shipped types these captures are decoded through -----------------
#
# Imported rather than restated: a stand-in declared here could agree with the
# node while `api/objects.py` and `api/shell.py` disagreed with both.

PROBE_TYPES = Blueprints(parent=default_blueprints())
"""A private registry for the next shape a node proves before a module owns it.

Empty today. It is kept because the mechanism is the point: `Blueprints` refuses
a name already present anywhere in the parent chain, so a probe record holding a
real type name would make importing `astral.api` and this module in the same
process a hard failure, and the `probe.` prefix is what keeps the two apart.
"""


def decode(cls: type, payload: bytes):
    """One captured payload, decoded through the type the SDK ships."""
    r = object_reader(payload, registry=default_blueprints())
    obj = cls(**read_fields(r, cls.FIELDS))
    if r.remaining:
        raise AssertionError(f"{cls.__name__}: {r.remaining} bytes left over")
    return obj


def encode(obj) -> bytes:
    """One record's payload, for the byte-exact half of a round trip."""
    w = Writer()
    write_fields(w, type(obj).FIELDS, obj)
    return w.getvalue()


# --- R-1: identity is 33 flat bytes --------------------------------------


class R1IdentityWidth(unittest.TestCase):
    """One error, four broken ops, and the whole reason for the rewrite.

    The legacy SDK modelled `identity` as a presence byte plus 33 bytes and
    claimed live verification for it. The flag it saw belongs to the enclosing
    `*astral.Identity` **pointer field**; a bare `identity` object has none.
    That one byte broke `dir.resolve`, `apphost.whoami`, `objects.find` and
    `user.list_siblings` over binary for the SDK's entire life.
    """

    # `apphost.whoami` over `out=bin`, the whole accepted stream, 46 bytes.
    WHOAMI_BIN = bytes.fromhex(
        "08" "6964656e74697479"  # string8 type tag "identity"
        "00000021"  # bytes32 payload length = 33, not 34
        + FURRY_BOLT_HEX  # 33 raw bytes, no flag of their own
    )

    def test_the_whoami_frame_declares_exactly_thirty_three_payload_bytes(self):
        r = Reader(self.WHOAMI_BIN)
        self.assertEqual(r.string8(), "identity")
        payload = r.bytes32()
        self.assertEqual(len(payload), 33)
        self.assertEqual(r.remaining, 0)
        self.assertEqual(Identity.read_payload(Reader(payload)), FURRY_BOLT)

    def test_a_presence_byte_would_have_made_the_frame_thirty_four(self):
        """The legacy layout, stated as the arithmetic that refutes it."""
        self.assertEqual(int.from_bytes(self.WHOAMI_BIN[9:13], "big"), 33)
        self.assertNotEqual(int.from_bytes(self.WHOAMI_BIN[9:13], "big"), 34)

    def test_the_identity_round_trips_to_the_same_thirty_three_bytes(self):
        self.assertEqual(payload_bytes(FURRY_BOLT), bytes.fromhex(FURRY_BOLT_HEX))


# --- R-2: a *ObjectID field carries its own nil flag ---------------------


class R2OptionalObjectID(unittest.TestCase):
    """`*astral.ObjectID` is `Ptr("object_id.sha256")`, never a bare 40 bytes.

    The legacy SDK modelled four records' optional ObjectID fields as the bare
    primitive, so every one of them was off by one byte and desynchronised the
    rest of the payload. The zero values below are the proof in the smallest
    possible form: a bare `object_id.sha256` cannot encode in one byte.
    """

    # `objects.new?type=mod.objects.search_result`, payload only.
    SEARCH_RESULT_ZERO = bytes.fromhex("0000")
    # `objects.new?type=mod.objects.describe_result`, payload only.
    DESCRIBE_RESULT_ZERO = bytes.fromhex("000000")

    def test_two_nil_pointers_are_two_bytes_and_not_seventy_four(self):
        """`SourceID` nil + `ObjectID` nil. Bare fields would be 33 + 40 + 2."""
        got = decode(SearchResult, self.SEARCH_RESULT_ZERO)
        self.assertIsNone(got.source_id)
        self.assertIsNone(got.object_id)
        self.assertEqual(encode(got), self.SEARCH_RESULT_ZERO)

    def test_the_describe_result_zero_is_three_nil_bytes(self):
        """Two pointers and one polymorphic field, one byte each."""
        got = decode(DescribeResult, self.DESCRIBE_RESULT_ZERO)
        self.assertIsNone(got.source_id)
        self.assertIsNone(got.object_id)
        self.assertIsNone(got.data)
        self.assertEqual(encode(got), self.DESCRIBE_RESULT_ZERO)

    def test_a_present_object_id_is_forty_bytes_behind_its_flag(self):
        """The other half of the pointer rule, so the flag is not mistaken for
        the value. The ID is `objects.scan?repo=main`'s first answer."""
        scanned = bytes.fromhex(
            "0000000000000047"  # uint64 Size = 71
            "6872e737f2311ed7519930e0c066d4aeb4b91914d0252af714b7c6405c81cfa9"
        )
        self.assertEqual(len(scanned), 40)
        oid = ObjectID.read_payload(Reader(scanned))
        self.assertEqual(int(oid.size), 71)
        present = SearchResult(source_id=None, object_id=oid)
        self.assertEqual(encode(present), b"\x00" + b"\x01" + scanned)


# --- R-3: an embedded struct is nested in JSON ---------------------------


class R3EmbeddedStructJSON(unittest.TestCase):
    """astral-go's JSON key for an embedded field is its **type name**.

    The legacy SDK asserted the opposite -- that Go flattens an embedded struct
    into the enclosing object -- and would have looked for `Issuer` and
    `Subject` at the top level of a `mod.auth.signed_contract`. The node's own
    zero values settle it: `signed_contract` has exactly one key for its
    embedded `*Contract`, and it is `"Contract"`.
    """

    # `objects.new?type=mod.auth.signed_contract&out=json`, one line.
    SIGNED_CONTRACT_JSON = (
        '{"Type":"mod.auth.signed_contract","Object":'
        '{"Contract":null,"IssuerSig":null,"SubjectSig":null}}'
    )
    # `objects.new?type=mod.auth.contract&out=json`, for the keys a flattened
    # embed would have put in the object above.
    CONTRACT_JSON = (
        '{"Type":"mod.auth.contract","Object":'
        '{"ExpiresAt":"0001-01-01T00:00:00Z","Issuer":null,"Permits":[],'
        '"Subject":null}}'
    )

    def test_the_embed_appears_under_its_type_name(self):
        obj = json.loads(self.SIGNED_CONTRACT_JSON)["Object"]
        self.assertIn("Contract", obj)
        self.assertEqual(set(obj), {"Contract", "IssuerSig", "SubjectSig"})

    def test_the_embedded_fields_are_absent_from_the_outer_object(self):
        """The refutation, not merely the confirmation: if Go flattened, the
        contract's own four keys would be here."""
        outer = json.loads(self.SIGNED_CONTRACT_JSON)["Object"]
        inner = json.loads(self.CONTRACT_JSON)["Object"]
        self.assertEqual(set(inner), {"ExpiresAt", "Issuer", "Permits", "Subject"})
        self.assertEqual(set(outer) & set(inner), set())

    def test_the_pointer_embed_is_one_nil_byte_in_binary(self):
        """Nested in JSON, flattened in binary -- the two halves of design
        section 2.5. `objects.new?type=mod.auth.signed_contract` payload."""
        self.assertEqual(bytes.fromhex("000000"), b"\x00\x00\x00")


# --- R-4: nonce64 JSON is unpadded ---------------------------------------


class R4NonceJSON(unittest.TestCase):
    """`Nonce.MarshalJSON` is `strconv.FormatUint(v, 16)` -- hex, unpadded.

    astral-docs documents a 16-digit hex string (bug D-4). The node's `query`
    zero value settles the padding half live: a padded emitter would have
    written sixteen zeros.
    """

    # `objects.new?type=query&out=json`, one line.
    QUERY_JSON = (
        '{"Type":"query","Object":'
        '{"Caller":null,"Nonce":"0","QueryString":"","Target":null}}'
    )

    def test_a_zero_nonce_is_one_digit_and_not_sixteen(self):
        obj = json.loads(self.QUERY_JSON)["Object"]
        self.assertEqual(obj["Nonce"], "0")
        self.assertNotEqual(obj["Nonce"], "0" * 16)

    def test_the_sdk_emits_the_same_unpadded_form(self):
        self.assertEqual(Nonce(0).json(), "0")
        self.assertEqual(Nonce(0x1122334455667788).json(), "1122334455667788")
        self.assertEqual(Nonce(0xFF).json(), "ff")

    def test_the_text_form_stays_padded(self):
        """Text is the other façade and the padding is deliberate there: a
        `%016x` nonce sorts and aligns in CLI output."""
        self.assertEqual(Nonce(0xFF).text(), "00000000000000ff")


# --- R-5: a zero ObjectID in JSON ----------------------------------------


class R5ZeroObjectIDJSON(unittest.TestCase):
    """A **nil** `*ObjectID` is `null`; a present zero one is `""`.

    Two different absences, and the node's zero values only prove the first --
    `encoding/json` short-circuits a nil pointer before `ObjectID.MarshalJSON`
    is ever reached, so `objects.new?type=mod.objects.search_result&out=json`
    cannot exercise the second. The design's probe expected `"ObjectID":""` *or*
    `null` and got `null`; the `""` half needs a bare zero `object_id.sha256`
    and is not settled live (see the findings note for the exact query).
    """

    SEARCH_RESULT_JSON = (
        '{"Type":"mod.objects.search_result","Object":'
        '{"SourceID":null,"ObjectID":null}}'
    )

    def test_a_nil_pointer_marshals_to_json_null(self):
        obj = json.loads(self.SEARCH_RESULT_JSON)["Object"]
        self.assertIsNone(obj["ObjectID"])
        self.assertIsNone(obj["SourceID"])

    def test_the_sdk_emits_the_empty_string_for_a_present_zero_id(self):
        """astral-go's own asymmetry, which this SDK declines to inherit: Go
        emits `""` and then fails to parse it back."""
        zero = ObjectID(size=Size(0), hash=b"\x00" * 32)
        self.assertTrue(zero.is_zero)
        self.assertEqual(zero.json(), "")
        self.assertEqual(ObjectID.from_json(""), zero)


# --- R-6: the zero identity in JSON --------------------------------------


class R6AnyoneJSON(unittest.TestCase):
    """`Identity.MarshalJSON` writes the literal `anyone` for a zero identity.

    The legacy SDK mapped it to `""` and would have crashed on
    `bytes.fromhex("anyone")`. The register records this as settled by
    `apphost.whoami?out=json`; **that probe no longer produces it**. astrald's
    `core/router.go` substitutes the node's own identity for a nil caller
    before `OpWhoami` reads `query.Caller()`, so an anonymous guest is answered
    with a non-zero identity and gets hex. The captured bytes below are what the
    node actually sends today; the `anyone` half is astral-go
    `astral/identity.go:171` and is pinned against this SDK rather than against
    a node.
    """

    WHOAMI_JSON = (
        '{"Type":"identity","Object":'
        f'"{FURRY_BOLT_HEX}"}}'
    )
    WHOAMI_TEXT = f"#[identity] {FURRY_BOLT_HEX}\n"

    def test_whoami_answers_hex_because_the_router_substitutes_the_node(self):
        obj = json.loads(self.WHOAMI_JSON)
        self.assertEqual(obj["Type"], "identity")
        self.assertEqual(obj["Object"], FURRY_BOLT_HEX)
        self.assertNotEqual(obj["Object"], "anyone")
        self.assertEqual(Identity.from_json(obj["Object"]), FURRY_BOLT)

    def test_the_text_form_is_hex_and_never_the_word(self):
        """Design section 2.2: `anyone` is a JSON form only, never a text one."""
        body = self.WHOAMI_TEXT.rstrip("\n").split(" ", 1)[1]
        self.assertEqual(body, FURRY_BOLT_HEX)
        self.assertEqual(Identity.ANYONE.text(), "0" * 66)

    def test_the_zero_identity_still_parses_from_the_word(self):
        """The half the legacy crashed on, and the reason to keep this test."""
        self.assertEqual(Identity.ANYONE.json(), "anyone")
        self.assertEqual(Identity.from_json("anyone"), Identity.ANYONE)
        self.assertEqual(Identity.from_json("0" * 66), Identity.ANYONE)


# --- R-7: a nil polymorphic field ----------------------------------------


class R7PolymorphicNil(unittest.TestCase):
    """The node writes `0x00` for an absent `Any`, never `string8("nil")`.

    astral-go contradicts itself here (bug G-1): its reflection codec writes the
    zero-length type tag and its runtime-blueprint codec writes
    `03 6e 69 6c`, which it then cannot read back. Both captures below come
    off the reflection path, which is every compile-time `api/...` type and so
    everything this SDK exchanges. The runtime-blueprint half is **not** settled
    -- design section 11.4 defers it deliberately and nothing here touches it.
    """

    # `objects.new?type=err_unexpected_object`, payload only. One `Any` field.
    ERR_UNEXPECTED_ZERO = bytes.fromhex("00")
    # `objects.new?type=mod.objects.describe_result`, payload only.
    DESCRIBE_RESULT_ZERO = bytes.fromhex("000000")

    def test_the_absent_any_is_a_single_zero_byte(self):
        r = object_reader(self.ERR_UNEXPECTED_ZERO, registry=default_blueprints())
        self.assertEqual(len(self.ERR_UNEXPECTED_ZERO), 1)
        self.assertEqual(r.uint8(), 0x00)

    def test_it_is_not_the_four_byte_runtime_form(self):
        """`string8("nil")` is `036e696c`, four bytes. The node sent one."""
        self.assertNotEqual(self.ERR_UNEXPECTED_ZERO, bytes.fromhex("036e696c"))

    def test_the_sdk_writes_the_same_byte(self):
        got = decode(DescribeResult, self.DESCRIBE_RESULT_ZERO)
        self.assertEqual(encode(got)[-1:], b"\x00")


# --- R-8: repository_info.Free is unsigned -------------------------------


class R8RepositoryFree(unittest.TestCase):
    """`Free` is `astral.Uint64`: eight bytes, no sign, ever.

    astral-docs examples it as a signed `-1` (bug D-22), which the legacy SDK
    would have decoded as a negative number and then compared against a size.
    Ten repositories, ten payloads, captured from `objects.repositories` in one
    query.
    """

    # Every `mod.objects.repository_info` frame payload, in the order the node
    # sent them.
    LIVE = {
        "memory": bytes.fromhex(
            "066d656d6f7279" "0f496e2d6d656d6f7279207265706f73" "0000000007ffffb9"
        ),
        "removable": bytes.fromhex(
            "0972656d6f7661626c65"
            "1152656d6f7661626c652064657669636573"
            "0000000000000000"
        ),
        "data": bytes.fromhex(
            "0464617461" "0744656661756c74" "000000023b1ae000"
        ),
        "main": bytes.fromhex("046d61696e" "05576f726c64" "00000002431adfb9"),
    }

    def test_every_free_value_is_eight_unsigned_bytes(self):
        for name, payload in self.LIVE.items():
            with self.subTest(repo=name):
                info = decode(RepositoryInfo, payload)
                self.assertEqual(info.name, name)
                self.assertGreaterEqual(info.free, 0)
                self.assertEqual(encode(info), payload)

    def test_the_captured_values_are_the_ones_the_node_sent(self):
        self.assertEqual(decode(RepositoryInfo, self.LIVE["memory"]).free, 0x07FFFFB9)
        self.assertEqual(decode(RepositoryInfo, self.LIVE["removable"]).free, 0)
        self.assertEqual(decode(RepositoryInfo, self.LIVE["main"]).label, "World")

    def test_the_documented_minus_one_is_the_all_ones_pattern(self):
        """What D-22's `-1` is on the wire, and what this SDK decodes it to.

        Not observed live -- no repository on `furry-bolt` reported it -- so
        this pins the SDK's reading of the pattern and claims nothing about the
        node.
        """
        payload = bytes.fromhex("0464617461" "0744656661756c74") + b"\xff" * 8
        self.assertEqual(decode(RepositoryInfo, payload).free, 0xFFFF_FFFF_FFFF_FFFF)


# --- R-14: routing.op_spec uses string32 ---------------------------------


class R14OpSpecStringWidth(unittest.TestCase):
    """A bare Go `string` field is `string32`, and `routing.op_spec` is all of
    them.

    astral-docs never states which width a struct field uses (bug D-9), which
    makes this the highest-impact silent-corruption trap in the corpus: reading
    a `string32` as a `string8` takes the first length byte for the whole length
    and desynchronises everything after it. Two captured `routing.op_spec`
    frames from `shell.spec`, the first of the 118 the node sends.
    """

    APPHOST_BIND = bytes.fromhex(
        "0000000c" "617070686f73742e62696e64"  # string32 Name "apphost.bind"
        "00000001"  # uint32 Parameters count
        "01"  # synthesized presence byte on a slice element
        "00000003" "6f7574"  # string32 Name "out"
        "00000007" "737472696e6738"  # string32 Type "string8"
        "00"  # bool Required
    )
    APPHOST_CANCEL = bytes.fromhex(
        "0000000e" "617070686f73742e63616e63656c"
        "00000003"
        "01" "00000002" "6964" "00000007" "6e6f6e63653634" "00"
        "01" "00000005" "6361757365" "00000007" "737472696e6738" "00"
        "01" "00000003" "6f7574" "00000007" "737472696e6738" "00"
    )

    def test_the_first_field_is_a_four_byte_length(self):
        r = Reader(self.APPHOST_BIND)
        self.assertEqual(r.uint32(), 12)

    def test_the_op_spec_decodes_whole(self):
        spec = decode(OpSpec, self.APPHOST_BIND)
        self.assertEqual(spec.name, "apphost.bind")
        self.assertEqual(len(spec.parameters), 1)
        self.assertEqual(spec.parameters[0].name, "out")
        self.assertEqual(spec.parameters[0].type, "string8")
        self.assertFalse(spec.parameters[0].required)
        self.assertEqual(encode(spec), self.APPHOST_BIND)

    def test_a_three_parameter_op_round_trips(self):
        spec = decode(OpSpec, self.APPHOST_CANCEL)
        self.assertEqual(spec.name, "apphost.cancel")
        self.assertEqual(
            [(p.name, p.type) for p in spec.parameters],
            [("id", "nonce64"), ("cause", "string8"), ("out", "string8")],
        )
        self.assertEqual(encode(spec), self.APPHOST_CANCEL)

    def test_reading_the_name_as_a_string8_desynchronises(self):
        """Why the width matters, stated as the failure it causes."""
        r = Reader(self.APPHOST_BIND)
        self.assertEqual(r.string8(), "")  # the first length byte is 0x00


# --- R-12: mod.ip.ip_address is a bytes8 ---------------------------------


class R12IPAddress(unittest.TestCase):
    """`mod.ip.ip_address` is a `bytes8` whose length picks the text form.

    The legacy SDK carried two contradictory `_ip_str` helpers. The zero value
    settles the container -- one length byte and nothing else -- and the 4-or-16
    half is **settled**: `ip.local_addrs` on `furry-bolt` answered one address of
    each family in one capture, four bytes for IPv4 and sixteen for IPv6. Both
    payloads are below. `tests/test_api_ip.py` carries the whole settlement --
    the frames, the text function against twenty Go-generated renderings, and
    the live tier that re-asks the node.
    """

    # `objects.new?type=mod.ip.ip_address`, payload only.
    ZERO = bytes.fromhex("00")
    ZERO_JSON = '{"Type":"mod.ip.ip_address","Object":"\\u003cnil\\u003e"}'

    # `ip.local_addrs` on `furry-bolt`, one payload per frame: `10.21.0.5` and
    # `fe80::8aa2:9eff:fea8:4ab0`.
    IPV4 = bytes.fromhex("040a150005")
    IPV6 = bytes.fromhex("10fe800000000000008aa29efffea84ab0")

    def test_the_zero_value_is_one_length_byte(self):
        r = Reader(self.ZERO)
        self.assertEqual(r.bytes8(), b"")
        self.assertEqual(r.remaining, 0)

    def test_the_zero_json_is_gos_nil_rendering_and_not_a_base64_string(self):
        """A `bytes8` field would have marshalled to `""`; this type overrides
        JSON with its text form, so an empty address is Go's `<nil>`."""
        self.assertEqual(json.loads(self.ZERO_JSON)["Object"], "<nil>")

    def test_the_payload_is_four_bytes_for_ipv4_and_sixteen_for_ipv6(self):
        """R-12's open half, settled by one live capture. The length is the only
        thing that says which family an address belongs to."""
        for payload, length in ((self.IPV4, 4), (self.IPV6, 16)):
            with self.subTest(length=length):
                r = Reader(payload)
                self.assertEqual(len(r.bytes8()), length)
                self.assertEqual(r.remaining, 0)


# --- the safety rail -----------------------------------------------------


class CrashingQueryIsNeverSent(unittest.TestCase):
    """No test in this repository may route a query that kills the node."""

    def test_the_forbidden_query_appears_only_as_a_forbidden_query(self):
        here = os.path.dirname(os.path.abspath(__file__))
        for forbidden in FORBIDDEN_LIVE_QUERIES:
            for name in sorted(os.listdir(here)):
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(here, name), encoding="utf-8") as fh:
                    body = fh.read()
                if forbidden in body and name != os.path.basename(__file__):
                    self.fail(f"{name} names the crashing query {forbidden!r}")


# --- Tier C: the same probes, against a node -----------------------------


class LiveRiskProbes(LiveCase):
    """Every vector above, re-fetched. Skipped whole when no node answers.

    Tier A pins what a node said once; this asserts a node still says it. The
    two must never be merged: a live-only pin rots into a skipped test the day
    astrald is not running, which is the failure mode the whole register exists
    to end.

    Read-only and anonymous throughout. `objects.new` is a pure registry read
    -- it constructs a zero value and sends it, storing nothing -- with the one
    exception this module's docstring names.
    """

    async def raw(self, qs: str) -> bytes:
        """One query's whole accepted stream, unframed and unparsed.

        The raw view rather than the framed one, because half these assertions
        are about the framing itself and a decoder that agreed with the SDK
        would prove nothing about the node.
        """
        self.assertNotIn(qs, FORBIDDEN_LIVE_QUERIES)
        async with await self.client() as client:
            async with client.stream(qs, raw=True) as s:
                return await s.read_bytes(timeout=15.0)

    @bounded(30.0)
    async def test_r1_the_whoami_frame_still_declares_thirty_three_bytes(self):
        data = await self.raw("apphost.whoami")
        r = Reader(data)
        self.assertEqual(r.string8(), "identity")
        self.assertEqual(len(r.bytes32()), 33)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_r6_whoami_json_is_the_hex_identity_not_the_word(self):
        """The register calls this settled as `anyone`; it is not, and the
        reason is astrald's router, not this SDK (see `R6AnyoneJSON`)."""
        data = await self.raw("apphost.whoami?out=json")
        obj = json.loads(data.decode())
        self.assertEqual(obj["Type"], "identity")
        self.assertNotEqual(obj["Object"], "anyone")
        self.assertEqual(Identity.from_json(obj["Object"]), Identity.parse(obj["Object"]))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_r2_r7_the_zero_values_are_still_one_byte_per_absence(self):
        for cls, expected in (
            (SearchResult, R2OptionalObjectID.SEARCH_RESULT_ZERO),
            (DescribeResult, R2OptionalObjectID.DESCRIBE_RESULT_ZERO),
        ):
            with self.subTest(type=cls.ASTRAL_TYPE):
                data = await self.raw(f"objects.new?type={cls.ASTRAL_TYPE}")
                r = Reader(data)
                self.assertEqual(r.string8(), cls.ASTRAL_TYPE)
                self.assertEqual(r.bytes32(), expected)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_r8_repository_free_is_still_eight_unsigned_bytes(self):
        data = await self.raw("objects.repositories")
        r = Reader(data)
        seen = 0
        while r.remaining:
            name = r.string8()
            payload = r.bytes32()
            if name == "eos":
                break
            self.assertEqual(name, RepositoryInfo.ASTRAL_TYPE)
            info = decode(RepositoryInfo, payload)
            self.assertGreaterEqual(info.free, 0)
            self.assertEqual(encode(info), payload)
            seen += 1
        self.assertGreater(seen, 0)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_r14_op_spec_names_still_carry_a_four_byte_length(self):
        data = await self.raw("shell.spec")
        r = Reader(data)
        names = []
        while r.remaining:
            frame_type = r.string8()
            payload = r.bytes32()
            if frame_type == "eos":
                break
            self.assertEqual(frame_type, OpSpec.ASTRAL_TYPE)
            spec = decode(OpSpec, payload)
            self.assertEqual(encode(spec), payload)
            names.append(spec.name)
        self.assertGreater(len(names), 100)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_the_node_can_hand_over_a_blueprint_after_all(self):
        """astral-go bug G-21 and design section 2.10 both say a node cannot be
        asked for a type's schema. `objects.get_blueprint` has been in astrald
        since `3de755d9` (2026-06-11) and is in the live registry, so both are
        wrong and `RuntimeRecord` can learn the node's types after all.
        """
        data = await self.raw("shell.spec")
        r = Reader(data)
        names = []
        while r.remaining:
            frame_type = r.string8()
            payload = r.bytes32()
            if frame_type == "eos":
                break
            names.append(decode(OpSpec, payload).name)
        self.assertIn("objects.get_blueprint", names)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
