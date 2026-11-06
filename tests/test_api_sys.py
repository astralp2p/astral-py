"""The `sys` module client and its two wire types.

- **Tier A** pins `mod.sys.register_manager_request` and
  `mod.sys.policy_binding` against astral-go's own output: every vector in
  `MANAGER_GO_VECTORS` was produced by a Go program linked against the head of
  astral-go branch `intern0/dev/sys-api`, printing `hex.EncodeToString` of what
  `WriteTo` wrote, `json.Marshal` of the value, the line `channel.TextSender`
  wrote, and `astral.ResolveObjectID`. That branch is not pushed, so no pin in
  `tests/reference.py` reaches it. The node's answers are captures from
  `apphost.register_manager` on an isolated astrald built from `5b4dde12`, the
  op `sys.register_manager` replaces; neither frame names the op.
- **Tier B** pins the query and the request object against `MockApphost`.

No live test: the op mutates the node once and for all (design section 7.3).
"""

from __future__ import annotations

import json
import re
import unittest

from astral.api import apphost as apphost_module
from astral.api import sys as sys_module
from astral.api.apphost import AccessToken
from astral.api.sys import (
    ERR_NOT_FRESH,
    OP_REGISTER_MANAGER,
    POLICY_APP_REGISTER,
    POLICY_NAMES,
    POLICY_SWARM_JOIN,
    SYS_TYPES,
    PolicyBinding,
    RegisterManagerRequest,
    Sys,
)
from astral.blueprint import of as blueprint_of
from astral.blueprint import spec_of
from astral.codec import decode, jsoncodec
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.text import decode as text_decode
from astral.codec.text import encode as text_encode
from astral.errors import BadArgument, BadArgumentType, ProtocolError, RemoteError
from astral.objectid import object_id
from astral.registry import default_blueprints
from astral.spec import Primitive, Slice
from astral.types import Duration, Identity

import reference
from mock_apphost import MockApphost, bounded
from test_api_apphost import (
    ACK_FRAME,
    CONTRACT_PERMIT,
    DISCOVERY_PERMIT,
    ApphostCase,
    body,
    frames_of,
    read_one_then,
)


APP_REGISTER_BINDING = PolicyBinding(
    policy=POLICY_APP_REGISTER,
    operation="manager.decide_app_register",
    timeout=Duration(30 * 10**9),
)
SWARM_JOIN_BINDING = PolicyBinding(
    policy=POLICY_SWARM_JOIN, operation="manager.decide_swarm_join"
)
MANAGER_REQUEST = RegisterManagerRequest(
    name="manager",
    grant_permits=[DISCOVERY_PERMIT],
    contract_permits=[CONTRACT_PERMIT],
    policies=[APP_REGISTER_BINDING, SWARM_JOIN_BINDING],
)

# Name -> (value, payload hex, JSON, text line, ObjectID), each string the
# output of a Go program linked against the head of astral-go branch
# `intern0/dev/sys-api` for the Go struct literal the value mirrors. The payload
# and JSON strings equal the `mod.apphost.*` ones astral-go `2481dd7a` wrote:
# the rename changes the type name, which only the text line and the ObjectID
# carry.
MANAGER_GO_VECTORS: dict[str, tuple[object, str, str, str, str]] = {
    "policy_binding_full": (
        APP_REGISTER_BINDING,
        "0c6170705f72656769737465721b6d616e616765722e6465636964655f6170705f726567"
        "697374657200000006fc23ac00",
        '{"Operation":"manager.decide_app_register","Policy":"app_register","Time'
        'out":30000000000}',
        "#[mod.sys.policy_binding]:DGFwcF9yZWdpc3RlchttYW5hZ2VyLmRlY2lkZV9hcHBfcm"
        "VnaXN0ZXIAAAAG/COsAA==",
        "data1raraefcethyjmehjueyzs85kq5wshgceb1kx8yzbaos34utfbo9y4",
    ),
    "policy_binding_zero": (
        PolicyBinding(),
        "00000000000000000000",
        '{"Operation":"","Policy":"","Timeout":0}',
        "#[mod.sys.policy_binding]:AAAAAAAAAAAAAA==",
        "data1nmbd4frqe5ia3bg8j8sc83166dzzoizadpcxh4u6w79abcgyqxy7k",
    ),
    "register_manager_request_full": (
        MANAGER_REQUEST,
        "076d616e616765720000000101256d6f642e73657276696365732e736572766963655f64"
        "6973636f766572795f616374696f6e0100000001000000351c6d6f642e73657276696365"
        "732e646973636f766572795f73636f70650000000101000000010109696e666572656e63"
        "65000000000000000001011b6d6f642e617574682e7365655f6f626a656374735f616374"
        "696f6e000100000002010c6170705f72656769737465721b6d616e616765722e64656369"
        "64655f6170705f726567697374657200000006fc23ac00010a737761726d5f6a6f696e19"
        "6d616e616765722e6465636964655f737761726d5f6a6f696e0000000000000000",
        '{"ContractPermits":[{"Action":"mod.auth.see_objects_action","Constraints'
        '":null,"Delegation":1}],"GrantPermits":[{"Action":"mod.services.service_'
        'discovery_action","Constraints":[{"Type":"mod.services.discovery_scope",'
        '"Object":{"Rules":[{"Nodes":[],"Services":["inference"]}]}}],"Delegation'
        '":0}],"Name":"manager","Policies":[{"Operation":"manager.decide_app_regi'
        'ster","Policy":"app_register","Timeout":30000000000},{"Operation":"manag'
        'er.decide_swarm_join","Policy":"swarm_join","Timeout":0}]}',
        "#[mod.sys.register_manager_request]:B21hbmFnZXIAAAABASVtb2Quc2VydmljZXMu"
        "c2VydmljZV9kaXNjb3ZlcnlfYWN0aW9uAQAAAAEAAAA1HG1vZC5zZXJ2aWNlcy5kaXNjb3Zl"
        "cnlfc2NvcGUAAAABAQAAAAEBCWluZmVyZW5jZQAAAAAAAAAAAQEbbW9kLmF1dGguc2VlX29i"
        "amVjdHNfYWN0aW9uAAEAAAACAQxhcHBfcmVnaXN0ZXIbbWFuYWdlci5kZWNpZGVfYXBwX3Jl"
        "Z2lzdGVyAAAABvwjrAABCnN3YXJtX2pvaW4ZbWFuYWdlci5kZWNpZGVfc3dhcm1fam9pbgAA"
        "AAAAAAAA",
        "data1thixx4awihm4gt7776dziy756uccnr9bj633t71bu4r9apxdsnh4n",
    ),
    "register_manager_request_zero": (
        RegisterManagerRequest(),
        "00000000000000000000000000",
        '{"ContractPermits":[],"GrantPermits":[],"Name":"","Policies":[]}',
        "#[mod.sys.register_manager_request]:AAAAAAAAAAAAAAAAAA==",
        "data1df911wrew65wpbppxewkxe7k5ymx4dnsbxnrjync71hd8yx7qq4fe",
    ),
}

# `astral.BlueprintOf` from the same Go program, `astral.blueprint` payloads in
# hex. No node running the sys module answered `objects.get_blueprint` for them.
MANAGER_BLUEPRINT_PAYLOADS = {
    "mod.sys.register_manager_request": (
        "00206d6f642e7379732e72656769737465725f6d616e616765725f726571756573740000"
        "00040100044e616d651f61737472616c2e626c75657072696e742e7072696d6974697665"
        "5f737065630007737472696e673801000c4772616e745065726d6974731b61737472616c"
        "2e626c75657072696e742e736c6963655f73706563000f6d6f642e617574682e7065726d"
        "697401000f436f6e74726163745065726d6974731b61737472616c2e626c75657072696e"
        "742e736c6963655f73706563000f6d6f642e617574682e7065726d6974010008506f6c69"
        "636965731b61737472616c2e626c75657072696e742e736c6963655f7370656300166d6f"
        "642e7379732e706f6c6963795f62696e64696e670000"
    ),
    "mod.sys.policy_binding": (
        "00166d6f642e7379732e706f6c6963795f62696e64696e6700000003010006506f6c6963"
        "791f61737472616c2e626c75657072696e742e7072696d69746976655f73706563000773"
        "7472696e67380100094f7065726174696f6e1f61737472616c2e626c75657072696e742e"
        "7072696d69746976655f737065630007737472696e673801000754696d656f75741f6173"
        "7472616c2e626c75657072696e742e7072696d69746976655f7370656300086475726174"
        "696f6e0000"
    ),
}

MANAGER_BLUEPRINTS = {
    "mod.sys.register_manager_request": [
        ("Name", Primitive("string8")),
        ("GrantPermits", Slice("mod.auth.permit")),
        ("ContractPermits", Slice("mod.auth.permit")),
        ("Policies", Slice("mod.sys.policy_binding")),
    ],
    "mod.sys.policy_binding": [
        ("Policy", Primitive("string8")),
        ("Operation", Primitive("string8")),
        ("Timeout", Primitive("duration")),
    ],
}

LIVE_MANAGER_TOKEN_BODY = bytes.fromhex(
    "14617070686f73742e6163636573735f746f6b656e0000004b"  # frame, 75 B
    "01" "03831c1b8085669f85e01bc90bc278d718c9b279ec75d0a5aa44c4b06953e19d2f"
    "20" "3153385332784a596548466243677972574d32515f705f4645774872794748"
    "61"
    "1d44eb824dd84b2c"                                    # ExpiresAt
)
"""`apphost.register_manager` from a token-less session on a fresh isolated
astrald built from `5b4dde12`, default gate, sent `register_manager_request_full`
as astral-go wrote it. One frame, then EOF. The node, and the token with it, is
gone. Captured before the rename to `sys.register_manager`; the frame names no
op, so it stands for the sys op by inference (`astral.api.sys`)."""

LIVE_NOT_FRESH_BODY = bytes.fromhex(
    "0d6572726f725f6d6573736167650000001300116e6f6465206973206e6f74206672657368"
)
"""`apphost.register_manager` from a token-less session on the same node once
claimed: `error_message{"node is not fresh"}`, then EOF. Captured before the
rename, as `LIVE_MANAGER_TOKEN_BODY` was."""


class SysCase(ApphostCase):
    """`ApphostCase`'s client, as the `sys` module client."""

    async def sys(self, mock: MockApphost, **kw: object) -> Sys:
        return Sys(await self.client(mock, **kw))


class ManagerTypesTest(unittest.TestCase):
    """The manager request and its policy binding, against astral-go branch
    `intern0/dev/sys-api`."""

    def test_every_value_encodes_to_the_go_bytes(self):
        for name, (value, payload, _, _, _) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(payload_bytes(value).hex(), payload)

    def test_the_go_bytes_decode_to_every_value(self):
        for name, (value, payload, _, _, _) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = type(value).read_payload(object_reader(bytes.fromhex(payload)))
                self.assertEqual(got, value)

    def test_the_go_json_decodes_to_every_value(self):
        for name, (value, _, go_json, _, _) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = jsoncodec.unmarshal(value.ASTRAL_TYPE, json.loads(go_json))
                self.assertEqual(got, value)

    def test_a_populated_value_marshals_to_the_go_json(self):
        for name in ("policy_binding_full", "policy_binding_zero"):
            value, _, go_json, _, _ = MANAGER_GO_VECTORS[name]
            with self.subTest(vector=name):
                self.assertEqual(jsoncodec.marshal(value), json.loads(go_json))

    def test_every_value_survives_its_own_json(self):
        """The full request holds a discovery rule's empty `Nodes`, which the
        SDK marshals as `null` and Go as `[]`, the divergence
        `AppRegisterPolicyTypesTest` pins."""
        for name, (value, _, _, _, _) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                mine = jsoncodec.marshal(value)
                self.assertEqual(jsoncodec.unmarshal(value.ASTRAL_TYPE, mine), value)

    def test_an_empty_list_marshals_to_null_where_go_sends_an_array(self):
        value, _, go_json, _, _ = MANAGER_GO_VECTORS["register_manager_request_zero"]
        theirs = json.loads(go_json)
        mine = jsoncodec.marshal(value)
        lists = {key for key, item in theirs.items() if item == []}
        self.assertEqual(lists, {"GrantPermits", "ContractPermits", "Policies"})
        self.assertEqual({key: mine[key] for key in lists}, dict.fromkeys(lists))
        self.assertEqual(mine["Name"], theirs["Name"])
        self.assertEqual(jsoncodec.unmarshal(value.ASTRAL_TYPE, mine), value)

    def test_the_text_line_is_the_go_line_both_ways(self):
        for name, (value, _, _, line, _) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(text_encode(value), line)
                self.assertEqual(text_decode(line), value)

    def test_every_object_id_is_the_go_object_id(self):
        for name, (value, _, _, _, oid) in MANAGER_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(str(object_id(value)), oid)

    def test_every_field_declaration_matches_the_go_blueprint(self):
        for cls in (RegisterManagerRequest, PolicyBinding):
            with self.subTest(type=cls.ASTRAL_TYPE):
                expected = MANAGER_BLUEPRINTS[cls.ASTRAL_TYPE]
                self.assertEqual([(f.wire_name, f.spec) for f in cls.FIELDS], expected)
                got = blueprint_of(cls)
                self.assertEqual([(f.name, spec_of(f.spec)) for f in got.fields], expected)
                name = b"astral.blueprint"
                go = decode(
                    bytes([len(name)]) + name
                    + bytes.fromhex(MANAGER_BLUEPRINT_PAYLOADS[cls.ASTRAL_TYPE])
                )
                self.assertEqual(str(go.type), cls.ASTRAL_TYPE)
                self.assertEqual(
                    [(str(f.name), spec_of(f.spec)) for f in go.fields], expected
                )

    def test_the_captured_token_decodes_and_re_encodes(self):
        (type_name, payload), = frames_of(LIVE_MANAGER_TOKEN_BODY)
        self.assertEqual(type_name, AccessToken.ASTRAL_TYPE)
        token = AccessToken.read_payload(object_reader(payload))
        self.assertEqual(
            token.identity,
            Identity.parse(
                "03831c1b8085669f85e01bc90bc278d718c9b279ec75d0a5aa44c4b06953e19d2f"
            ),
        )
        self.assertEqual(len(token.token), 32)
        self.assertEqual(payload_bytes(token), payload)

    def test_the_captured_refusal_is_the_not_fresh_text(self):
        (type_name, payload), = frames_of(LIVE_NOT_FRESH_BODY)
        self.assertEqual(type_name, "error_message")
        self.assertEqual(payload[2:].decode(), ERR_NOT_FRESH)
        self.assertEqual(ERR_NOT_FRESH, "node is not fresh")

    def test_the_policy_names_are_the_five_the_protocol_names(self):
        """`api/sys/register_manager_request.go`'s `PolicyNames`, in its order.

        Read off that file on astral-go branch `intern0/dev/sys-api` when this
        was written, and not re-read here: no pin reaches it.
        """
        self.assertEqual(
            POLICY_NAMES,
            ("app_register", "grant_request", "swarm_join", "swarm_invite", "contract_accept"),
        )


class RegisterManagerTest(SysCase):
    """`sys.register_manager`: WA, one `mod.sys.register_manager_request` in,
    one `apphost.access_token` out, and `apphost.register`'s argument
    handling."""

    async def register_manager(self, **kw: object) -> tuple[AccessToken, MockApphost]:
        (reply,) = frames_of(LIVE_MANAGER_TOKEN_BODY)
        async with MockApphost(
            routes={OP_REGISTER_MANAGER: read_one_then(reply)}
        ) as mock:
            api = await self.sys(mock)
            token = await api.register_manager(**kw)
        return token, mock

    @bounded()
    async def test_no_arguments_send_one_zero_request_and_answer_a_token(self):
        token, mock = await self.register_manager()
        self.assertEqual(mock.queries[-1].query, OP_REGISTER_MANAGER)
        self.assertEqual(
            body(mock),
            [
                (
                    RegisterManagerRequest.ASTRAL_TYPE,
                    bytes.fromhex(MANAGER_GO_VECTORS["register_manager_request_zero"][1]),
                )
            ],
        )
        self.assertEqual(token.token, "1S8S2xJYeHFbCgyrWM2Q_p_FEwHryGHa")

    @bounded()
    async def test_every_field_travels_in_the_object_byte_for_byte(self):
        """astral-go's request, byte for byte."""
        _, mock = await self.register_manager(
            name="manager",
            grant_permits=[DISCOVERY_PERMIT],
            contract_permits=(p for p in [CONTRACT_PERMIT]),
            policies=(b for b in [APP_REGISTER_BINDING, SWARM_JOIN_BINDING]),
        )
        self.assertEqual(
            body(mock),
            [
                (
                    RegisterManagerRequest.ASTRAL_TYPE,
                    bytes.fromhex(MANAGER_GO_VECTORS["register_manager_request_full"][1]),
                )
            ],
        )

    @bounded()
    async def test_a_malformed_argument_never_reaches_the_node(self):
        async with MockApphost(routes={OP_REGISTER_MANAGER: read_one_then()}) as mock:
            api = await self.sys(mock)
            for value, error in (
                (APP_REGISTER_BINDING, BadArgumentType),
                (POLICY_APP_REGISTER, BadArgumentType),
                ([POLICY_APP_REGISTER], BadArgumentType),
                ([None], BadArgumentType),
                ([PolicyBinding(policy="p" * 256, operation="x")], BadArgument),
                ([PolicyBinding(policy=POLICY_APP_REGISTER, operation="o" * 256)], BadArgument),
                ([PolicyBinding(policy=POLICY_APP_REGISTER, operation=b"x")], BadArgumentType),
            ):
                with self.subTest(value=value):
                    with self.assertRaises(error) as caught:
                        await api.register_manager(policies=value)
                    self.assertIn(OP_REGISTER_MANAGER, str(caught.exception))
            with self.assertRaises(BadArgument):
                await api.register_manager(name="n" * 256)
            with self.assertRaises(BadArgumentType):
                await api.register_manager(grant_permits="mod.user.see_swarm_action")
            with self.assertRaises(TypeError):
                await api.register_manager([APP_REGISTER_BINDING])  # type: ignore[misc]
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_node_that_is_not_fresh_is_a_remote_error(self):
        """The captured refusal: the op accepts, then answers the text."""
        (reply,) = frames_of(LIVE_NOT_FRESH_BODY)
        async with MockApphost(
            routes={OP_REGISTER_MANAGER: read_one_then(reply)}
        ) as mock:
            api = await self.sys(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.register_manager()
        self.assertEqual(caught.exception.message, ERR_NOT_FRESH)

    @bounded()
    async def test_an_answer_of_the_wrong_type_or_none_is_a_protocol_error(self):
        for route in (read_one_then(ACK_FRAME), read_one_then()):
            with self.subTest(route=route):
                async with MockApphost(routes={OP_REGISTER_MANAGER: route}) as mock:
                    api = await self.sys(mock)
                    with self.assertRaises(ProtocolError):
                        await api.register_manager()


class SurfaceTest(unittest.TestCase):
    """The rename is hard: one op name, two type names, no alias."""

    def test_the_op_constant_is_astral_go_s_method_name(self):
        self.assertEqual(OP_REGISTER_MANAGER, "sys.register_manager")
        self.assertEqual(ERR_NOT_FRESH, "node is not fresh")

    def test_both_types_are_registered_under_the_sys_names_alone(self):
        blueprints = default_blueprints()
        self.assertEqual(
            {cls.ASTRAL_TYPE for cls in SYS_TYPES},
            {"mod.sys.register_manager_request", "mod.sys.policy_binding"},
        )
        self.assertEqual(Sys.TYPES, SYS_TYPES)
        for cls in SYS_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertIs(blueprints.find(cls.ASTRAL_TYPE), cls)
        for name in ("mod.apphost.register_manager_request", "mod.apphost.policy_binding"):
            with self.subTest(type=name):
                self.assertFalse(blueprints.has(name))

    def test_apphost_carries_no_manager_surface(self):
        for name in (
            "OP_REGISTER_MANAGER",
            "ERR_NOT_FRESH",
            "PolicyBinding",
            "RegisterManagerRequest",
            "POLICY_NAMES",
            "POLICY_APP_REGISTER",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(apphost_module, name))
                self.assertNotIn(name, apphost_module.__all__)
        self.assertFalse(hasattr(apphost_module.Apphost, "register_manager"))


class CitationTest(unittest.TestCase):
    """What the module's citations claim about themselves."""

    def test_no_sys_source_is_cited_by_line(self):
        """`api/sys/*` and `mod/sys/*` sit on branches no pin reaches, so a
        `path:line` to either is a claim `tests/reference.py` cannot read."""
        text = " ".join(
            filter(
                None,
                [sys_module.__doc__]
                + [
                    getattr(obj, "__doc__", None)
                    for obj in vars(sys_module).values()
                    if getattr(obj, "__module__", None) == sys_module.__name__
                ],
            )
        )
        self.assertIsNone(re.search(r"(api|mod)/sys/[\w/.]+:\d", text))

    def test_every_pinned_anchor_lands_on_its_claim(self):
        cites = (
            (reference.ASTRAL_GO, "api/policy/delegate.go", 18, "Delegate names the op"),
            (reference.ASTRAL_GO, "api/policy/delegate.go", 20, "MaxTimeout; a Timeout above it fails"),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)


if __name__ == "__main__":
    unittest.main()
