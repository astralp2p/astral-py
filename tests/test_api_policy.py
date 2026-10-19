"""`policy.delegate`, against astral-go's own output and the node's own answers.

No op ships in `policy.py`, so there is no Tier B here. What there is:

- **Tier A** pins the one type against **astral-go's own output**. Every vector
  in `GO_VECTORS` was produced by a Go program linked against astral-go
  `221ce52`, the revision astrald `1286a469` requires: `hex.EncodeToString` of
  what `WriteTo` wrote, `json.Marshal` of the value (what astral-go's
  `JSONSender` emits), the line `channel.TextSender` wrote, and
  `astral.ResolveObjectID`. The field declaration is checked against the
  blueprint `objects.get_blueprint` derived on an isolated astrald built from
  `1286a469`.
- **Tier C** asks the node for the blueprint and the zero value again, and has
  it decode and re-encode a populated delegate through `objects.echo`.
"""

from __future__ import annotations

import inspect
import json
import unittest

from astral.api import policy as policy_module
from astral.api.policy import POLICY_TYPES, Delegate
from astral.blueprint import of as blueprint_of
from astral.blueprint import spec_of
from astral.codec import jsoncodec
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.text import decode as text_decode
from astral.codec.text import encode as text_encode
from astral.objectid import object_id
from astral.registry import default_blueprints
from astral.spec import Primitive, Ptr
from astral.types import Duration, Identity

import live_support
import reference
from mock_apphost import bounded, frame

# The secp256k1 generator, compressed: a real point, which the node's
# `Identity.ReadFrom` requires for the echo test to answer at all.
G = Identity.parse("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

DELEGATE = Delegate(
    identity=G,
    operation="control.decide_app_register",
    timeout=Duration(5 * 60 * 10**9),
)

# Name -> (value, payload hex, JSON, text line, ObjectID), each string astral-go
# `221ce52`'s output for the Go struct literal the value mirrors.
GO_VECTORS: dict[str, tuple[Delegate, str, str, str, str]] = {
    "delegate_full": (
        DELEGATE,
        "01" "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "1b" "636f6e74726f6c2e6465636964655f6170705f7265676973746572"
        "00000045d964b800",
        '{"Identity":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",'
        '"Operation":"control.decide_app_register","Timeout":300000000000}',
        "#[policy.delegate]:AQJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmBtjb250cm9sLmRl"
        "Y2lkZV9hcHBfcmVnaXN0ZXIAAABF2WS4AA==",
        "data1fi4e69ow4xmm6oo9k7n6tzfw6o1s8qjak1p1bqrdsuzw15gyme47a",
    ),
    "delegate_zero": (
        Delegate(),
        "00" "00" "0000000000000000",
        '{"Identity":null,"Operation":"","Timeout":0}',
        "#[policy.delegate]:AAAAAAAAAAAAAA==",
        "data1bhsr3yi8zufmjb7fuz7m6q5zx638ejj5wyarfbmnx6e7nsgb3p99h",
    ),
}

# `objects.get_blueprint?type=policy.delegate` on an isolated astrald built from
# `1286a469`, decoded.
LIVE_BLUEPRINT = [
    ("Identity", Ptr("identity")),
    ("Operation", Primitive("string8")),
    ("Timeout", Primitive("duration")),
]


class GoWireTest(unittest.TestCase):
    """The delegate against astral-go's own encoders, all four forms."""

    def test_the_value_encodes_to_the_go_bytes(self):
        for name, (value, payload, _, _, _) in GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(payload_bytes(value).hex(), payload)

    def test_the_go_bytes_decode_to_the_value(self):
        for name, (value, payload, _, _, _) in GO_VECTORS.items():
            with self.subTest(vector=name):
                got = Delegate.read_payload(object_reader(bytes.fromhex(payload)))
                self.assertEqual(got, value)

    def test_the_json_form_is_the_go_json_both_ways(self):
        for name, (value, _, go_json, _, _) in GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(jsoncodec.marshal(value), json.loads(go_json))
                self.assertEqual(
                    jsoncodec.unmarshal("policy.delegate", json.loads(go_json)), value
                )

    def test_the_text_line_is_the_go_line_both_ways(self):
        for name, (value, _, _, line, _) in GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(text_encode(value), line)
                self.assertEqual(text_decode(line), value)

    def test_the_object_id_is_the_go_object_id(self):
        for name, (value, _, _, _, oid) in GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(str(object_id(value)), oid)


class LayoutTest(unittest.TestCase):
    """The declaration, the registry and the module's shape."""

    def test_the_field_declaration_matches_the_node_s_blueprint(self):
        self.assertEqual([(f.wire_name, f.spec) for f in Delegate.FIELDS], LIVE_BLUEPRINT)
        got = blueprint_of(Delegate)
        self.assertEqual(got.type, "policy.delegate")
        self.assertEqual([(f.name, spec_of(f.spec)) for f in got.fields], LIVE_BLUEPRINT)

    def test_the_type_name_carries_no_mod_prefix(self):
        """Design section 5.1 rule 6: the name is astral-go's
        `Delegate.ObjectType()`, spelled literally."""
        self.assertEqual(Delegate.ASTRAL_TYPE, "policy.delegate")
        self.assertIs(default_blueprints().find("policy.delegate"), Delegate)
        self.assertFalse(default_blueprints().has("mod.policy.delegate"))

    def test_the_type_sweep_names_every_declared_type(self):
        declared = {
            value
            for value in vars(policy_module).values()
            if isinstance(value, type)
            and value.__module__ == policy_module.__name__
            and getattr(value, "ASTRAL_TYPE", None)
        }
        self.assertEqual(declared, set(POLICY_TYPES))
        self.assertEqual(tuple(POLICY_TYPES), (Delegate,))

    def test_this_module_declares_no_module_client(self):
        from astral.api.base import ModuleClient
        from astral.client import Client

        clients = [
            value
            for value in vars(policy_module).values()
            if inspect.isclass(value)
            and issubclass(value, ModuleClient)
            and value.__module__ == policy_module.__name__
        ]
        self.assertEqual(clients, [])
        self.assertFalse(hasattr(Client, "policy"))


class CitationTest(unittest.TestCase):
    """Every `path:line` the module docstring cites, read at the pins."""

    ASTRAL_GO_LINES = {
        ("api/policy/delegate.go", 14): "MaxTimeout bounds one admission question",
        ("api/policy/delegate.go", 16): "MaxTimeout = 10 * time.Minute",
        ("api/policy/delegate.go", 21): "type Delegate struct",
        ("api/policy/delegate.go", 25): "}",
        ("api/policy/delegate.go", 27): 'return "policy.delegate"',
    }
    ASTRALD_LINES = {
        ("mod/apphost/src/register_policy.go", 12): '"/mod/apphost/policy"',
        ("mod/apphost/src/register_policy.go", 21): "tree.Value[*policy.Delegate]",
        ("mod/apphost/src/register_policy.go", 45): "policy.Ask(",
        ("mod/apphost/src/register_policy.go", 51): "obj.(*apphost.AppRegisterDecision)",
        ("mod/apphost/src/register_policy.go", 53): "NewErrUnexpectedObject",
        ("mod/user/src/swarm_policy.go", 12): '"/mod/user/policy"',
        ("mod/user/src/swarm_policy.go", 17): "SwarmJoin   tree.Value[*policy.Delegate]",
        ("mod/user/src/swarm_policy.go", 18): "SwarmInvite tree.Value[*policy.Delegate]",
    }

    def assert_lands(self, repo: str, anchors: dict) -> None:
        for (path, number), expected in anchors.items():
            with self.subTest(file=path, line=number):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(expected, line)

    def test_every_astral_go_anchor_lands_on_its_claim(self):
        self.assert_lands(reference.ASTRAL_GO, self.ASTRAL_GO_LINES)

    def test_every_astrald_anchor_lands_on_its_claim(self):
        self.assert_lands(reference.ASTRALD, self.ASTRALD_LINES)

    def test_the_node_asks_the_delegate_as_itself(self):
        try:
            ask = reference.read(reference.ASTRAL_GO, "api/policy/ask.go")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        self.assertIn("query.New(node.Identity(), d.Identity, string(d.Operation), nil)", ask)
        self.assertIn("ch.Send(req)", ask)
        self.assertIn("ch.Receive()", ask)


class LivePolicyTest(live_support.LiveCase):
    """The node's own layout, zero value and codec for `policy.delegate`.

    Read-only. `objects.get_blueprint` describes a type, `objects.new` builds a
    zero value server-side and `objects.echo` sends back what it decoded;
    none writes anything.
    """

    @bounded(30.0)
    async def test_the_node_derives_the_blueprint_this_module_derives(self):
        async with await self.client() as client:
            got = await client.call_one(
                "objects.get_blueprint?type=policy.delegate", timeout=20.0
            )
        self.assertEqual(str(got.type), "policy.delegate")
        self.assertEqual([(str(f.name), spec_of(f.spec)) for f in got.fields], LIVE_BLUEPRINT)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_builds_the_zero_value_this_module_builds(self):
        async with await self.client() as client:
            body = await client.call_raw("objects.new?type=policy.delegate", timeout=20.0)
        self.assertEqual(body, frame("policy.delegate", payload_bytes(Delegate())))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_populated_delegate_survives_the_node_s_own_codec(self):
        """`objects.echo?strict=true` decodes the frame through the node's
        registry and re-encodes it from the decoded value."""
        async with await self.client() as client:
            async with client.stream("objects.echo?strict=true", timeout=20.0) as stream:
                await stream.send(DELEGATE)
                await stream.send_eos()
                got = [obj async for obj in stream]
        self.assertEqual(got, [DELEGATE])
        self.assertEqual(payload_bytes(got[0]), payload_bytes(DELEGATE))
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
