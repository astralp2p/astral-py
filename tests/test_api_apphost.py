"""The `apphost` module client, its data types, and the eager-import rule.

Three tiers in one file, because they assert three different things about the
same eleven ops:

- **Tier A** pins the wire: `apphost.access_token` byte for byte, the missing
  `mod.` prefix that would make every token frame undecodable, and the registry
  contents -- including the one type that must *not* be there. The two app
  registration policy types are pinned against **astral-go's own output**:
  every vector in `POLICY_GO_VECTORS` was produced by a Go program linked
  against astral-go `221ce52`, printing `hex.EncodeToString` of what `WriteTo`
  wrote, `json.Marshal` of the value, the line `channel.TextSender` wrote, and
  `astral.ResolveObjectID`.
- **Tier B** pins the query strings and the shapes against `MockApphost`. A
  module client is argument marshalling plus one call, so the marshalling is
  what can be wrong: a capitalised key is silently dropped by the node, an
  omitted parameter and an empty one are different things, and an op's mode is a
  declaration that a test has to make as well.
- **Tier C** asks the node, and only through the three read-only anonymous-safe
  ops and the read-only `objects.get_blueprint`, `objects.new` and
  `objects.echo` for the two policy types. `apphost.register` and
  `apphost.set_app_register_policy` mutate the node and are exercised against
  the mock alone (design section 7.3). Skipped with a reason when
  `ASTRAL_TEST_ENDPOINT` is unset.

The assertion that is not about apphost at all: **importing `astral.api` imports
every module in the package.** Wire-type registration is a side effect of import,
so a module that this package's `__init__` forgets is a type that decodes in one
program and raises `BlueprintNotFound` in another. The test walks the directory
rather than a list, so it fails for a module that has not been added yet.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import pathlib
import sys
import unittest

import astral
from astral.api import apphost as apphost_module
from astral.api.apphost import (
    OP_BIND,
    OP_CANCEL,
    OP_CREATE_TOKEN,
    OP_GRANT,
    OP_HOLD_OBJECT,
    OP_LIST_HELD_OBJECTS,
    OP_LIST_TOKENS,
    OP_REGISTER,
    OP_REGISTER_HANDLER,
    OP_SET_APP_REGISTER_POLICY,
    OP_UNHOLD_OBJECT,
    OP_WHOAMI,
    ERR_REGISTRATION_DECLINED,
    AccessToken,
    APPHOST_TYPES,
    Apphost,
    AppRegisterDecision,
    AppRegisterRequest,
    _duration,
    _object_id,
    apphost_types,
)
from astral.api.auth import AuthorizerAssignment, Permit
from astral.blueprint import of as blueprint_of
from astral.blueprint import spec_of
from astral.client import Client, connect
from astral.codec import decode, encode, jsoncodec
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.text import decode as text_decode
from astral.codec.text import encode as text_encode
from astral.errors import (
    BadArgument,
    BadArgumentType,
    ParseError,
    ProtocolError,
    QueryRejected,
    QueryTimeout,
    RemoteError,
)
from astral.object import Ack, Bundle
from astral.objectid import object_id
from astral.querystring import QueryStringTooLong
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive, Slice
from astral.transport import Transport
from astral.types import Duration, Identity, Nonce, ObjectID, Time, Zone
from astral.wire import Writer

import api_walk
import live_support
import reference
from mock_apphost import (
    ACK,
    Accept,
    FURRY_BOLT,
    MockApphost,
    Reject,
    bounded,
    frame,
    socket_fds,
    until,
)

# The identity every fixture below uses. The live node's own, so a captured
# frame and a constructed one are comparable.
ID_HEX = "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
TOKEN = "R6mLmR21IajGVMhcXvbPtjfNiXKuJpsO"
# 2027-07-27T11:02:23.112712094Z, as read off the live node.
EXPIRES = Time(1816630943112712094)
# The secp256k1 base point: a valid identity by construction, and one no node has
# ever issued a token to. The node refuses an identity parameter that is not a
# point on the curve, so an arbitrary 33 bytes will not serve.
GENERATOR = Identity.parse(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

ACK_FRAME = (ACK, b"")
IDENTITY_FRAME = ("identity", FURRY_BOLT.key)


def access_token_payload(
    identity: Identity | None = FURRY_BOLT, token: str = TOKEN, expires: int = EXPIRES
) -> bytes:
    """`apphost.access_token`, framed by hand rather than by the codec.

    The point of the duplication: a wrong layout in the SDK cannot agree with a
    wrong layout here.
    """
    w = Writer()
    if identity is None:
        w.uint8(0)
    else:
        w.uint8(1)
        w.raw(identity.key)
    w.string8(token)
    w.uint64(expires)
    return w.getvalue()


TOKEN_FRAME = ("apphost.access_token", access_token_payload())

GRANT = Permit(action="mod.objects.read_object_action")
CONTRACT_PERMIT = Permit(action="mod.auth.see_objects_action", delegation=1)
REGISTER_REQUEST = AppRegisterRequest(
    origin="https://app.example",
    name="chat",
    grant_permits=[GRANT],
    contract_permits=[CONTRACT_PERMIT],
)
REGISTER_DECISION = AppRegisterDecision(
    allow=True,
    grant_permits=[GRANT],
    contract_permits=[CONTRACT_PERMIT],
    authorizers=[
        AuthorizerAssignment(
            action="mod.auth.see_objects_action",
            endpoint="astral://control-plane:control.authorize",
            timeout=Duration(30 * 10**9),
        )
    ],
)

# Name -> (value, payload hex, JSON, text line, ObjectID), each string astral-go
# `221ce52`'s output for the Go struct literal the value mirrors.
POLICY_GO_VECTORS: dict[str, tuple[object, str, str, str, str]] = {
    "app_register_request_full": (
        REGISTER_REQUEST,
        "13" "68747470733a2f2f6170702e6578616d706c65"
        "04" "63686174"
        "00000001" "01" "1e" "6d6f642e6f626a656374732e726561645f6f626a6563745f616374696f6e"
        "00" "00"
        "00000001" "01" "1b" "6d6f642e617574682e7365655f6f626a656374735f616374696f6e"
        "00" "01",
        '{"ContractPermits":[{"Action":"mod.auth.see_objects_action","Constraints":null,'
        '"Delegation":1}],"GrantPermits":[{"Action":"mod.objects.read_object_action",'
        '"Constraints":null,"Delegation":0}],"Name":"chat","Origin":"https://app.example"}',
        "#[mod.apphost.app_register_request]:E2h0dHBzOi8vYXBwLmV4YW1wbGUEY2hhdAAAAAEBHm1v"
        "ZC5vYmplY3RzLnJlYWRfb2JqZWN0X2FjdGlvbgAAAAAAAQEbbW9kLmF1dGguc2VlX29iamVjdHNf"
        "YWN0aW9uAAE=",
        "data1ex864ipz7mw8uimywtgieujgriwmugom1o4x5kfeuf8msubtjjfxb",
    ),
    "app_register_request_zero": (
        AppRegisterRequest(),
        "00" "00" "00000000" "00000000",
        '{"ContractPermits":[],"GrantPermits":[],"Name":"","Origin":""}',
        "#[mod.apphost.app_register_request]:AAAAAAAAAAAAAA==",
        "data1n99e6c1kabwtx5dbifp44mqw5c9qictecizqpe9ok8kxytxmqk4wo",
    ),
    "app_register_decision_full": (
        REGISTER_DECISION,
        "01"
        "00000001" "01" "1e" "6d6f642e6f626a656374732e726561645f6f626a6563745f616374696f6e"
        "00" "00"
        "00000001" "01" "1b" "6d6f642e617574682e7365655f6f626a656374735f616374696f6e"
        "00" "01"
        "00000001" "01" "1b" "6d6f642e617574682e7365655f6f626a656374735f616374696f6e"
        "00"
        "28" "61737472616c3a2f2f636f6e74726f6c2d706c616e653a636f6e74726f6c2e617574686f72697a65"
        "00000006fc23ac00" "00" "00" "00",
        '{"Allow":true,"Authorizers":[{"Action":"mod.auth.see_objects_action","Actor":null,'
        '"Endpoint":"astral://control-plane:control.authorize","Timeout":30000000000,'
        '"TokenEnv":"","TokenFile":"","TokenValue":""}],"ContractPermits":[{"Action":'
        '"mod.auth.see_objects_action","Constraints":null,"Delegation":1}],"GrantPermits":'
        '[{"Action":"mod.objects.read_object_action","Constraints":null,"Delegation":0}]}',
        "#[mod.apphost.app_register_decision]:AQAAAAEBHm1vZC5vYmplY3RzLnJlYWRfb2JqZWN0X2Fj"
        "dGlvbgAAAAAAAQEbbW9kLmF1dGguc2VlX29iamVjdHNfYWN0aW9uAAEAAAABARttb2QuYXV0aC5z"
        "ZWVfb2JqZWN0c19hY3Rpb24AKGFzdHJhbDovL2NvbnRyb2wtcGxhbmU6Y29udHJvbC5hdXRob3Jp"
        "emUAAAAG/COsAAAAAA==",
        "data1ccwokrd8kr4k4i317uqioct7wnrkjzhkcxp49jx6aq8kktby7nk48",
    ),
    "app_register_decision_zero": (
        AppRegisterDecision(),
        "00" "00000000" "00000000" "00000000",
        '{"Allow":false,"Authorizers":[],"ContractPermits":[],"GrantPermits":[]}',
        "#[mod.apphost.app_register_decision]:AAAAAAAAAAAAAAAAAA==",
        "data1d8d7596ja3jxebk333ugycds9s514bno1idw7gfaxfjnq3si38d1b",
    ),
}

# `objects.get_blueprint?type=<name>` on an isolated astrald built from
# `1286a469`, decoded.
POLICY_BLUEPRINTS = {
    "mod.apphost.app_register_request": [
        ("Origin", Primitive("string8")),
        ("Name", Primitive("string8")),
        ("GrantPermits", Slice("mod.auth.permit")),
        ("ContractPermits", Slice("mod.auth.permit")),
    ],
    "mod.apphost.app_register_decision": [
        ("Allow", Primitive("bool")),
        ("GrantPermits", Slice("mod.auth.permit")),
        ("ContractPermits", Slice("mod.auth.permit")),
        ("Authorizers", Slice("mod.auth.authorizer_assignment")),
    ],
}


def error_frame(message: str) -> tuple[str, bytes]:
    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


def object_id_frame(oid: ObjectID) -> tuple[str, bytes]:
    w = Writer()
    oid.write(w)
    return ("object_id.sha256", w.getvalue())


# --- Tier A: the wire ----------------------------------------------------


class AccessTokenTest(unittest.TestCase):
    """The one type this module contributes to the wire, pinned."""

    def test_the_type_name_carries_no_mod_prefix(self):
        """Every other apphost type is `mod.apphost.*`; this one is not.

        astral-go's `AccessToken.ObjectType()` returns `apphost.access_token`,
        and the registry name is what the frame carries, so a `mod.` here would
        make every token the node sends undecodable.
        """
        self.assertEqual(AccessToken.ASTRAL_TYPE, "apphost.access_token")
        self.assertTrue(default_blueprints().has("apphost.access_token"))
        self.assertFalse(default_blueprints().has("mod.apphost.access_token"))

    def test_the_payload_is_a_nil_flag_an_identity_a_string8_and_a_time(self):
        token = AccessToken(identity=FURRY_BOLT, token=TOKEN, expires_at=EXPIRES)
        payload = encode(token)[len("apphost.access_token") + 1 :]
        self.assertEqual(payload, access_token_payload())
        # 1 flag + 33 identity + 1 length + 32 token + 8 time
        self.assertEqual(len(payload), 75)

    def test_a_captured_payload_round_trips_byte_for_byte(self):
        payload = access_token_payload()
        frame = bytes([len("apphost.access_token")]) + b"apphost.access_token" + payload
        token = decode(frame)
        self.assertIsInstance(token, AccessToken)
        self.assertEqual(token.identity, FURRY_BOLT)
        self.assertEqual(token.token, TOKEN)
        self.assertEqual(token.expires_at, EXPIRES)
        self.assertEqual(encode(token), frame)

    def test_a_nil_identity_is_one_byte(self):
        """`Identity` is a `*astral.Identity` field: absent is `0x00` alone, not
        33 zero bytes."""
        token = AccessToken(identity=None, token="", expires_at=Time(0))
        payload = encode(token)[len("apphost.access_token") + 1 :]
        self.assertEqual(payload, b"\x00" + b"\x00" + bytes(8))

    def test_expired_reads_the_expiry_the_node_never_reads(self):
        """The property exists because astrald's `AuthenticateToken` looks a
        token up and returns its identity without comparing `ExpiresAt`, so an
        expired token still authenticates. Checking it is the caller's job."""
        past = AccessToken(identity=FURRY_BOLT, token="x", expires_at=Time(1))
        future = AccessToken(
            identity=FURRY_BOLT, token="x", expires_at=Time(Time.now() + 10**12)
        )
        self.assertTrue(past.expired)
        self.assertFalse(future.expired)


class AppRegisterPolicyTypesTest(unittest.TestCase):
    """The app registration policy's question and answer, against astral-go."""

    def test_every_value_encodes_to_the_go_bytes(self):
        for name, (value, payload, _, _, _) in POLICY_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(payload_bytes(value).hex(), payload)

    def test_the_go_bytes_decode_to_every_value(self):
        for name, (value, payload, _, _, _) in POLICY_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = type(value).read_payload(object_reader(bytes.fromhex(payload)))
                self.assertEqual(got, value)

    def test_the_go_json_decodes_to_every_value(self):
        for name, (value, _, go_json, _, _) in POLICY_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = jsoncodec.unmarshal(value.ASTRAL_TYPE, json.loads(go_json))
                self.assertEqual(got, value)

    def test_a_populated_value_marshals_to_the_go_json(self):
        for name in ("app_register_request_full", "app_register_decision_full"):
            value, _, go_json, _, _ = POLICY_GO_VECTORS[name]
            with self.subTest(vector=name):
                self.assertEqual(jsoncodec.marshal(value), json.loads(go_json))

    def test_an_empty_list_marshals_to_null_where_go_sends_an_array(self):
        """The divergence `test_api_auth.DivergenceTest` pins for
        `mod.auth.contract`'s `Permits`: the SDK's JSON codec maps an empty
        container to `null`, astral-go `Objectify` emits `[]`, and each side
        reads the other's form back to the same value."""
        for name in ("app_register_request_zero", "app_register_decision_zero"):
            value, _, go_json, _, _ = POLICY_GO_VECTORS[name]
            with self.subTest(vector=name):
                theirs = json.loads(go_json)
                mine = jsoncodec.marshal(value)
                lists = {key for key, item in theirs.items() if item == []}
                self.assertTrue(lists)
                self.assertEqual({key: mine[key] for key in lists}, dict.fromkeys(lists))
                self.assertEqual(
                    {k: v for k, v in mine.items() if k not in lists},
                    {k: v for k, v in theirs.items() if k not in lists},
                )

    def test_the_text_line_is_the_go_line_both_ways(self):
        for name, (value, _, _, line, _) in POLICY_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(text_encode(value), line)
                self.assertEqual(text_decode(line), value)

    def test_every_object_id_is_the_go_object_id(self):
        for name, (value, _, _, _, oid) in POLICY_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(str(object_id(value)), oid)

    def test_every_field_declaration_matches_the_node_s_blueprint(self):
        for cls in (AppRegisterRequest, AppRegisterDecision):
            with self.subTest(type=cls.ASTRAL_TYPE):
                expected = POLICY_BLUEPRINTS[cls.ASTRAL_TYPE]
                self.assertEqual([(f.wire_name, f.spec) for f in cls.FIELDS], expected)
                got = blueprint_of(cls)
                self.assertEqual([(f.name, spec_of(f.spec)) for f in got.fields], expected)

    def test_every_anchor_lands_on_its_claim(self):
        """The `path:line` citations in the two docstrings, read at the pins."""
        cites = (
            (reference.ASTRAL_GO, "api/apphost/app_register_policy.go", 12,
             "AppRegisterRequest is what the app registration policy decides on"),
            (reference.ASTRAL_GO, "api/apphost/app_register_policy.go", 26, "}"),
            (reference.ASTRAL_GO, "api/apphost/app_register_policy.go", 46,
             "AppRegisterDecision is the app registration policy's answer"),
            (reference.ASTRAL_GO, "api/apphost/app_register_policy.go", 57,
             "Authorizers []*auth.AuthorizerAssignment"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 50,
             "carries ServeApps whatever the app asked for"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 51,
             "serveAppsGrantRequest"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 83, "dec.Validate()"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 85,
             "ErrRegistrationDeclined"),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)


class RegistryTest(unittest.TestCase):
    """What is registered, and the one thing that must not be."""

    def test_every_apphost_type_is_registered_under_its_own_name(self):
        registry = default_blueprints()
        for kind in apphost_types():
            with self.subTest(type=kind.ASTRAL_TYPE):
                self.assertTrue(registry.has(kind.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(kind.ASTRAL_TYPE), kind)

    def test_register_handler_msg_is_not_declared_anywhere(self):
        """astrald registers the type and has an `onRegisterHandlerMsg` method,
        but `Guest.Serve`'s dispatch switch never routes to it, so nothing can
        reach that method (bug G-16). Declaring the type would advertise a
        message that is dead on the wire; registering a handler is the
        `apphost.register_handler` op."""
        self.assertFalse(default_blueprints().has("mod.apphost.register_handler_msg"))
        self.assertNotIn(
            "mod.apphost.register_handler_msg",
            {kind.ASTRAL_TYPE for kind in apphost_types()},
        )

    def test_ping_msg_is_registered_and_is_not_a_keepalive(self):
        """The other half of the same rule: `ping_msg` decodes, because the type
        exists, and is never sent, because the node has no handler for it and
        answers `error_msg{protocol_error}` (bug G-17). There is no keepalive."""
        self.assertTrue(default_blueprints().has("mod.apphost.ping_msg"))
        self.assertNotIn("ping", dir(Apphost))

    def test_the_control_messages_are_the_session_s_own_classes(self):
        """Re-exported, not redeclared: two `route_query_msg` classes in one
        process would put two entries in the registry and the second `@record`
        would fail on the duplicate name."""
        from astral import session

        self.assertIs(apphost_module.RouteQueryMsg, session.RouteQueryMsg)
        self.assertIs(apphost_module.BindMsg, session.BindMsg)


class EagerImportTest(unittest.TestCase):
    """The guarantee `astral.api` exists to make."""

    def test_importing_astral_api_imports_every_module_in_the_package(self):
        """Walked from the directory, not from a list, so a module added without
        a line in `__init__.py` fails here rather than failing a decode in
        production. Registration is a side effect of import; leaving it to first
        attribute access makes decodability depend on which property a caller
        happened to touch."""
        import astral.api

        directory = pathlib.Path(astral.api.__file__).parent
        modules = {
            path.stem
            for path in directory.glob("*.py")
            if path.stem != "__init__" and not path.stem.startswith("_")
        }
        self.assertTrue(modules, "astral.api has no modules to import")
        missing = {
            name for name in modules if f"astral.api.{name}" not in sys.modules
        }
        self.assertEqual(
            missing,
            set(),
            f"astral.api.__init__ does not import {sorted(missing)}: importing "
            "astral.api must register every wire type",
        )


class CoercionTest(unittest.TestCase):
    """What a caller naturally holds, and what must be refused rather than read."""

    def test_an_int_duration_is_nanoseconds(self):
        self.assertEqual(_duration(5), Duration(5))
        self.assertEqual(_duration(Duration(5)), Duration(5))

    def test_a_timedelta_is_exact_to_the_microsecond(self):
        self.assertEqual(_duration(dt.timedelta(seconds=1)), Duration(1_000_000_000))
        self.assertEqual(_duration(dt.timedelta(microseconds=1)), Duration(1_000))

    def test_a_float_duration_is_refused_with_the_conversion_named(self):
        """`duration=1.5` always means seconds and would be sent as 1.5
        nanoseconds -- a token that expires before the reply arrives."""
        with self.assertRaises(TypeError) as caught:
            _duration(1.5)
        self.assertIn("1e9", str(caught.exception))

    def test_an_absent_duration_is_absent_rather_than_zero(self):
        """Zero is a value the node reads as "use the default" for tokens and as
        a permanent hold for objects; absence is not the same key."""
        self.assertIsNone(_duration(None))

    def test_an_object_id_parses_from_its_text_form(self):
        oid = ObjectID(size=5, hash=bytes(range(32)))
        self.assertEqual(_object_id(str(oid), OP_HOLD_OBJECT), oid)
        self.assertEqual(_object_id(oid, OP_HOLD_OBJECT), oid)

    def test_a_duration_renders_as_a_go_duration_string(self):
        """The node parses this parameter with Go's `time.ParseDuration`."""
        self.assertEqual(Duration(365 * 24 * 3600 * 10**9).text(), "8760h0m0s")


# --- Tier B: the mock ----------------------------------------------------


class ApphostCase(unittest.IsolatedAsyncioTestCase):
    """One client per test over a `MemTransport`, closed by the teardown."""

    async def asyncSetUp(self) -> None:
        self.clients: list[Client] = []
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for client in self.clients:
            await client.aclose()
        await flush_cancels(5.0)

    def connector(self, mock: MockApphost):  # type: ignore[no-untyped-def]
        async def open_session() -> Session:
            raw: Transport = await mock.open()
            return await Session.over(raw, endpoint="mem:mock", connector=open_session)

        return open_session

    async def client(self, mock: MockApphost, **kw: object) -> Client:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return client

    async def apphost(self, mock: MockApphost, **kw: object) -> Apphost:
        return Apphost(await self.client(mock, **kw))


class WhoamiTest(ApphostCase):
    @bounded()
    async def test_whoami_reads_one_identity_off_a_stream_that_never_sends_eos(self):
        """astral-docs bug D-23 as a client assertion: an SDK that waited for an
        `eos` here would hold one of the node's 32 workers until it closed."""
        async with MockApphost(
            routes={OP_WHOAMI: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            who = await api.whoami()
        self.assertEqual(who, FURRY_BOLT)
        self.assertEqual(mock.queries[-1].query, OP_WHOAMI)

    @bounded()
    async def test_whoami_reports_an_answer_of_the_wrong_type_as_a_protocol_error(self):
        """The op declared `identity`. Returning whatever arrived would push the
        fault into the caller's next line, where it reads as their bug."""
        async with MockApphost(
            routes={OP_WHOAMI: Accept(objects=(("uint8", b"\x07"),))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.whoami()
        self.assertIn("identity", str(caught.exception))

    @bounded()
    async def test_an_error_message_in_the_stream_is_a_remote_error(self):
        """An `error_message` object is the op failing, and is a different
        channel from an apphost `error_msg`. The two are never merged."""
        async with MockApphost(
            routes={OP_WHOAMI: Accept(objects=(error_frame("nope"),))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError):
                await api.whoami()


class ListTokensTest(ApphostCase):
    @bounded()
    async def test_no_identity_sends_no_parameter_at_all(self):
        """An empty `identity=` and an absent `identity` are different query
        strings, though the node filters nothing for either, and a parameter the
        caller did not set must never be invented."""
        async with MockApphost(routes={OP_LIST_TOKENS: Accept(eos=True)}) as mock:
            api = await self.apphost(mock)
            self.assertEqual(await api.list_tokens(), [])
        self.assertEqual(mock.queries[-1].query, OP_LIST_TOKENS)

    @bounded()
    async def test_an_identity_travels_as_66_lowercase_hex_under_a_lowercase_key(self):
        """Parameter matching on the node is case-sensitive and an unknown key is
        silently dropped, so a capitalised key does nothing at all -- which is
        the bug astral-go ships in this very module (G-9)."""
        async with MockApphost(routes={OP_LIST_TOKENS: Accept(eos=True)}) as mock:
            api = await self.apphost(mock)
            await api.list_tokens(ID_HEX)
        self.assertEqual(mock.queries[-1].query, f"{OP_LIST_TOKENS}?identity={ID_HEX}")

    @bounded()
    async def test_the_tokens_decode_and_the_stream_ends_at_an_eos(self):
        """The other termination shape, next to `whoami`'s: same module, same
        run, and nothing infers which is which."""
        frames = (
            ("apphost.access_token", access_token_payload()),
            ("apphost.access_token", access_token_payload(token="second")),
        )
        async with MockApphost(
            routes={OP_LIST_TOKENS: Accept(objects=frames, eos=True)}
        ) as mock:
            api = await self.apphost(mock)
            tokens = await api.list_tokens()
        self.assertEqual([t.token for t in tokens], [TOKEN, "second"])
        self.assertEqual(tokens[0].identity, FURRY_BOLT)
        self.assertEqual(tokens[0].expires_at, EXPIRES)

    @bounded()
    async def test_a_wrong_object_in_the_stream_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_LIST_TOKENS: Accept(objects=(("uint8", b"\x01"),), eos=True)}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.list_tokens()


class ListHeldObjectsTest(ApphostCase):
    @bounded()
    async def test_the_ids_decode_and_the_op_takes_no_arguments(self):
        oid = ObjectID(size=5, hash=bytes(range(32)))
        async with MockApphost(
            routes={OP_LIST_HELD_OBJECTS: Accept(objects=(object_id_frame(oid),), eos=True)}
        ) as mock:
            api = await self.apphost(mock)
            held = await api.list_held_objects()
        self.assertEqual(held, [oid])
        self.assertEqual(mock.queries[-1].query, OP_LIST_HELD_OBJECTS)


class GrantTest(ApphostCase):
    """`apphost.grant`: RR, one `ack`; constraints travel on the body."""

    DISCOVERY = "mod.services.service_discovery_action"

    @staticmethod
    def body(mock: MockApphost) -> list[tuple[str, bytes]]:
        """The frames the mock received after the session handshake."""
        received = mock.connections[-1].received
        for index, (type_name, _) in enumerate(received):
            if type_name == "mod.apphost.route_query_msg":
                return received[index + 1 :]
        return []

    @bounded()
    async def test_grant_sends_the_identity_under_identity(self):
        """The identity argument travels under `identity`, the name astrald
        `bd98bbe8` gives it; `id` would be skipped by the node's binding."""
        async with MockApphost(routes={OP_GRANT: Accept(objects=(ACK_FRAME,))}) as mock:
            api = await self.apphost(mock)
            await api.grant(ID_HEX, self.DISCOVERY, duration=dt.timedelta(hours=1))
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_GRANT}?action={self.DISCOVERY}&duration=1h0m0s&identity={ID_HEX}",
        )
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_grant_with_constraints_sends_the_bundle_on_the_body(self):
        """A bundle is not a query argument: `constrained=true` on the query,
        the bundle as the one object on the body."""
        constraints = Bundle([Ack()])

        async def read_then_ack(conn, query) -> None:  # type: ignore[no-untyped-def]
            # astrald reads the bundle after accepting, then answers; a canned
            # `Accept` answers and closes first, and the input is dropped.
            conn.send_raw(frame("mod.apphost.query_accepted_msg"))
            await conn.flush()
            await conn.recv_frame_or_none()
            conn.send_frame(*ACK_FRAME)
            await conn.flush()
            await conn.aclose()

        async with MockApphost(routes={OP_GRANT: read_then_ack}) as mock:
            api = await self.apphost(mock)
            await api.grant(ID_HEX, self.DISCOVERY, constraints=constraints)
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_GRANT}?action={self.DISCOVERY}&constrained=true&identity={ID_HEX}",
        )
        self.assertEqual([t for t, _ in self.body(mock)], ["bundle"])


class TokenAndContractTest(ApphostCase):
    @bounded()
    async def test_create_token_sends_sorted_keys_and_a_go_duration(self):
        """Sorted keys match Go's `url.Values.Encode()`, so a query string is
        reproducible byte for byte against the reference client."""
        token_frame = ("apphost.access_token", access_token_payload())
        async with MockApphost(
            routes={OP_CREATE_TOKEN: Accept(objects=(token_frame,))}
        ) as mock:
            api = await self.apphost(mock)
            token = await api.create_token(ID_HEX, duration=dt.timedelta(days=365))
        self.assertEqual(token.token, TOKEN)
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_CREATE_TOKEN}?duration=8760h0m0s&identity={ID_HEX}",
        )

    @bounded()
    async def test_create_token_omits_the_duration_it_was_not_given(self):
        """Omitted leaves the node's one-year default standing; sending zero
        would be a different statement."""
        token_frame = ("apphost.access_token", access_token_payload())
        async with MockApphost(
            routes={OP_CREATE_TOKEN: Accept(objects=(token_frame,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.create_token(ID_HEX)
        self.assertEqual(mock.queries[-1].query, f"{OP_CREATE_TOKEN}?identity={ID_HEX}")

    @bounded()
    async def test_a_rejected_query_reaches_the_caller_as_a_rejection(self):
        """An unparseable parameter is rejected before the op runs -- astrald's
        arg binding fails and the deferred reject fires -- so this arrives as
        `query_rejected_msg`, not as an `error_message` in a stream."""
        async with MockApphost(routes={OP_CREATE_TOKEN: Reject(code=1)}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(QueryRejected):
                await api.create_token(ID_HEX)


class RegisterTest(ApphostCase):
    """`apphost.register`: RR, one `apphost.access_token`, three optional
    arguments, and a decline that is an `error_message` rather than a reject."""

    async def register(self, *args: object, **kw: object) -> tuple[AccessToken, str]:
        async with MockApphost(
            routes={OP_REGISTER: Accept(objects=(TOKEN_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            token = await api.register(*args, **kw)
        return token, mock.queries[-1].query

    @bounded()
    async def test_no_arguments_send_none_and_answer_a_token(self):
        """The bootstrap an app with no credentials starts from: the node makes
        the key, the contract and the token."""
        token, query = await self.register()
        self.assertEqual(token.token, TOKEN)
        self.assertEqual(query, OP_REGISTER)

    @bounded()
    async def test_every_argument_travels_lowercase_with_sorted_keys(self):
        """Each list is one comma-joined value, escaped as Go's
        `url.QueryEscape` escapes it; `url.ParseQuery` hands the node the
        commas back."""
        _, query = await self.register(
            ["mod.user.see_swarm_action", "mod.objects.read_object_action"],
            ("mod.auth.see_objects_action",),
            name="my chat",
        )
        self.assertEqual(
            query,
            f"{OP_REGISTER}?contract_permits=mod.auth.see_objects_action"
            "&grant_permits=mod.user.see_swarm_action%2Cmod.objects.read_object_action"
            "&name=my+chat",
        )

    @bounded()
    async def test_the_lists_are_keywords_too_and_any_iterable_serves(self):
        _, query = await self.register(
            contract_permits=(a for a in ["a.one", "a.two"])
        )
        self.assertEqual(query, f"{OP_REGISTER}?contract_permits=a.one%2Ca.two")

    @bounded()
    async def test_an_empty_list_sends_no_argument(self):
        """astral-go's client sends nothing for no permits; the node reads an
        absent list and an empty one alike."""
        _, query = await self.register([], [])
        self.assertEqual(query, OP_REGISTER)

    @bounded()
    async def test_an_empty_name_is_sent_as_given(self):
        _, query = await self.register(name="")
        self.assertEqual(query, f"{OP_REGISTER}?name=")

    @bounded()
    async def test_a_permit_the_node_would_misread_never_reaches_it(self):
        """The node splits on every comma, trims each piece and drops a blank
        one, so each of these is an action the caller did not name."""
        async with MockApphost(routes={OP_REGISTER: Accept()}) as mock:
            api = await self.apphost(mock)
            for key in ("grant_permits", "contract_permits"):
                for bad in ("a,b", "", " ", " a", "a\n", "x" * 256):
                    with self.subTest(key=key, permit=bad):
                        with self.assertRaises(BadArgument) as caught:
                            await api.register(**{key: ["ok.action", bad]})
                        self.assertIn(key, str(caught.exception))
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_255_byte_action_name_is_the_longest_sent(self):
        name = "\u00e9" * 127 + "x"  # 255 UTF-8 bytes
        with self.assertWarns(QueryStringTooLong):
            _, query = await self.register([name])
        self.assertTrue(query.startswith(f"{OP_REGISTER}?grant_permits="))
        with self.assertRaises(BadArgument):
            await self.register(["\u00e9" * 128])

    @bounded()
    async def test_a_bare_string_or_a_non_string_entry_is_a_type_error(self):
        """A bare `str` would iterate its characters into single-letter
        actions."""
        async with MockApphost(routes={OP_REGISTER: Accept()}) as mock:
            api = await self.apphost(mock)
            for value in ("mod.user.see_swarm_action", b"x", [1], [None]):
                with self.subTest(value=value):
                    with self.assertRaises(BadArgumentType):
                        await api.register(value)  # type: ignore[arg-type]
            with self.assertRaises(BadArgumentType):
                await api.register(name=b"chat")  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_name_over_255_bytes_never_reaches_the_node(self):
        """`Name` is a `string8` in the request a delegate reads."""
        with self.assertWarns(QueryStringTooLong):
            _, query = await self.register(name="n" * 255)
        self.assertEqual(query, f"{OP_REGISTER}?name={'n' * 255}")
        with self.assertRaises(BadArgument):
            await self.register(name="n" * 256)

    @bounded()
    async def test_a_declined_registration_is_a_remote_error(self):
        """The node accepts before its policy decides, so a refusal is an
        `error_message` in the stream, not `query_rejected_msg`."""
        async with MockApphost(
            routes={
                OP_REGISTER: Accept(objects=(error_frame(ERR_REGISTRATION_DECLINED),))
            }
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.register(["mod.user.see_swarm_action"])
        self.assertEqual(caught.exception.message, "registration declined")

    @bounded()
    async def test_an_answer_of_the_wrong_type_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_REGISTER: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.register()


class SetAppRegisterPolicyTest(ApphostCase):
    """`apphost.set_app_register_policy`: RR, one `ack`, the argument set the
    two swarm setters share."""

    async def set_policy(self, route: object, *args: object, **kw: object) -> MockApphost:
        async with MockApphost(routes={OP_SET_APP_REGISTER_POLICY: route}) as mock:
            api = await self.apphost(mock)
            self.assertIsNone(await api.set_app_register_policy(*args, **kw))
        return mock

    @bounded()
    async def test_a_delegate_travels_as_identity_operation_and_timeout(self):
        mock = await self.set_policy(
            Accept(objects=(ACK_FRAME,)),
            GENERATOR,
            "control.decide_app_register",
            timeout="90s",
        )
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_SET_APP_REGISTER_POLICY}?identity={GENERATOR.text()}"
            "&operation=control.decide_app_register&timeout=1m30s",
        )

    @bounded()
    async def test_a_directory_name_and_a_duration_pass_through(self):
        """The node resolves `identity` itself, so a name is sent as given."""
        mock = await self.set_policy(
            Accept(objects=(ACK_FRAME,)),
            "control-plane",
            "control.decide",
            timeout=Duration(5 * 60 * 10**9),
        )
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_SET_APP_REGISTER_POLICY}?identity=control-plane"
            "&operation=control.decide&timeout=5m0s",
        )

    @bounded()
    async def test_no_delegate_restores_the_bundled_policy(self):
        """Both names empty is the op's restore: the node clears the stored
        delegate and answers `ack`."""
        mock = await self.set_policy(Accept(objects=(ACK_FRAME,)))
        self.assertEqual(mock.queries[-1].query, OP_SET_APP_REGISTER_POLICY)

    @bounded()
    async def test_a_malformed_delegate_never_reaches_the_node(self):
        async with MockApphost(routes={OP_SET_APP_REGISTER_POLICY: Accept()}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(BadArgument):
                await api.set_app_register_policy(GENERATOR)
            with self.assertRaises(BadArgument):
                await api.set_app_register_policy(operation="control.decide")
            with self.assertRaises(BadArgument):
                await api.set_app_register_policy("", "control.decide")
            with self.assertRaises(ParseError):
                await api.set_app_register_policy(
                    GENERATOR, "control.decide", timeout="1y"
                )
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_refused_delegate_surfaces_as_a_remote_error(self):
        async with MockApphost(
            routes={
                OP_SET_APP_REGISTER_POLICY: Accept(
                    objects=(error_frame("the node cannot be its own delegate"),)
                )
            }
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.set_app_register_policy(FURRY_BOLT, "control.decide")
        self.assertEqual(caught.exception.message, "the node cannot be its own delegate")

    @bounded()
    async def test_an_unauthorized_caller_is_a_rejection(self):
        async with MockApphost(
            routes={OP_SET_APP_REGISTER_POLICY: Reject(code=1)}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(QueryRejected):
                await api.set_app_register_policy()

    @bounded()
    async def test_an_answer_other_than_ack_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_SET_APP_REGISTER_POLICY: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.set_app_register_policy()

class HoldTest(ApphostCase):
    @bounded()
    async def test_hold_object_with_no_duration_is_a_permanent_hold(self):
        """astrald stores a null expiry for an absent duration, so the absence is
        the request rather than an omission to be filled in."""
        oid = ObjectID(size=5, hash=bytes(range(32)))
        async with MockApphost(
            routes={OP_HOLD_OBJECT: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            self.assertIsNone(await api.hold_object(oid))
        self.assertEqual(mock.queries[-1].query, f"{OP_HOLD_OBJECT}?id={oid}")

    @bounded()
    async def test_hold_object_sends_a_duration_when_given_one(self):
        oid = ObjectID(size=5, hash=bytes(range(32)))
        async with MockApphost(
            routes={OP_HOLD_OBJECT: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.hold_object(oid, duration=Duration(60 * 10**9))
        self.assertEqual(
            mock.queries[-1].query, f"{OP_HOLD_OBJECT}?duration=1m0s&id={oid}"
        )

    @bounded()
    async def test_unhold_object_takes_the_id_alone(self):
        oid = ObjectID(size=5, hash=bytes(range(32)))
        async with MockApphost(
            routes={OP_UNHOLD_OBJECT: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.unhold_object(str(oid))
        self.assertEqual(mock.queries[-1].query, f"{OP_UNHOLD_OBJECT}?id={oid}")

    @bounded()
    async def test_an_ack_op_that_answers_otherwise_is_a_protocol_error(self):
        oid = ObjectID(size=5, hash=bytes(range(32)))
        async with MockApphost(
            routes={OP_UNHOLD_OBJECT: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.unhold_object(oid)


class RegisterHandlerTest(ApphostCase):
    @bounded()
    async def test_the_token_travels_as_sixteen_hex_digits(self):
        """A `nonce64` parameter is `%016x`, zero-padded. The node parses it back
        into the value the dial-back's `IPCToken` must equal, so a short form
        that round-trips through Go's parser is still a different token from the
        one the listener will check."""
        async with MockApphost(
            routes={OP_REGISTER_HANDLER: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.register_handler("unix:/tmp/app.sock", Nonce(0x0011223344556677))
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_REGISTER_HANDLER}?endpoint=unix%3A%2Ftmp%2Fapp.sock"
            "&token=0011223344556677",
        )


class BindTest(ApphostCase):
    @bounded()
    async def test_bind_reads_the_ack_and_then_sends_one_message_per_token(self):
        """The tokens are what the node forgets when this stream closes. Sending
        them before the `ack` would race the op's own setup."""
        async with MockApphost(
            routes={OP_BIND: Accept(objects=(ACK_FRAME,), read=True)}
        ) as mock:
            api = await self.apphost(mock)
            stream = await api.bind(Nonce(1), 2)
            self.assertTrue(await until(lambda: len(mock.bind_tokens) == 2))
            self.assertEqual(mock.bind_tokens, [Nonce(1), Nonce(2)])
            await stream.aclose()

    @bounded()
    async def test_bind_spends_no_connection_permit(self):
        """A permit held for the process's lifetime is a permit the client can
        never reuse; eight of them is a client that has deadlocked itself."""
        async with MockApphost(
            routes={OP_BIND: Accept(objects=(ACK_FRAME,), read=True)}
        ) as mock:
            client = await self.client(mock, max_concurrency=2)
            api = Apphost(client)
            stream = await api.bind()
            self.assertEqual(client.available, 2)
            self.assertEqual(client.live_streams, 1)
            await stream.aclose()
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_the_client_closes_a_bind_stream_it_was_never_given_back(self):
        """Why this is not `Session.bind()`: a bind stream is held for as long as
        the registrations should live, and one no client knows about outlives its
        client holding a node worker."""
        async with MockApphost(
            routes={OP_BIND: Accept(objects=(ACK_FRAME,), read=True)}
        ) as mock:
            client = await self.client(mock)
            stream = await Apphost(client).bind()
            await client.aclose()
            self.assertTrue(stream.closed)

    @bounded()
    async def test_a_bind_that_is_not_acked_closes_rather_than_leaking(self):
        async with MockApphost(
            routes={OP_BIND: Accept(objects=(IDENTITY_FRAME,), read=True)}
        ) as mock:
            client = await self.client(mock)
            with self.assertRaises(ProtocolError):
                await Apphost(client).bind()
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_bind_stream_that_closes_before_the_ack_is_a_protocol_error(self):
        async with MockApphost(routes={OP_BIND: Accept()}) as mock:
            client = await self.client(mock)
            with self.assertRaises(ProtocolError):
                await Apphost(client).bind()
            self.assertEqual(client.live_streams, 0)

    @bounded()
    async def test_a_bind_accepted_and_then_silent_is_bounded(self):
        """astrald accepts before it acks -- `op_bind.go` does `ch :=
        q.Accept(...)` and only then `ch.Send(&astral.Ack{})` -- so
        accepted-and-silent is a state the wire reaches whenever the op goroutine
        stalls between those two statements. `Session.bind()` bounded that wait
        and this, the entry point the docs point at, did not: measured at no
        exception within 12 s, on the persistent lane where the client's own
        budget cannot rescue it."""
        async with MockApphost(routes={OP_BIND: Accept(hold=True)}) as mock:
            client = await self.client(mock)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout) as caught:
                await Apphost(client).bind(ack_timeout=0.2)
            self.assertLess(loop.time() - started, 1.5)
            self.assertIn(OP_BIND, str(caught.exception))
            self.assertEqual(client.live_streams, 0)
            self.assertEqual(client.available_persistent, client.max_persistent)

    @bounded()
    async def test_a_bind_whose_token_send_stalls_is_bounded_too(self):
        """The ack arrives and the node then stops reading. The tokens are
        unregistered either way; the difference is whether the caller is told."""
        async with MockApphost(
            routes={OP_BIND: Accept(objects=(ACK_FRAME,), hold=True)}
        ) as mock:
            client = await self.client(mock)
            stream = await Apphost(client).bind(Nonce(1), ack_timeout=0.5)
            await stream.aclose()


class CancelTest(ApphostCase):
    @bounded()
    async def test_a_cancel_is_acked_and_never_leaves_the_machine(self):
        """`zone=device`, matching astral-go: cancelling is a local act, and a
        cancel that left the machine would be routed as a query of its own."""
        async with MockApphost(
            routes={OP_CANCEL: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            self.assertTrue(await api.cancel(Nonce(0x1122334455667788)))
        self.assertEqual(
            mock.queries[-1].query, f"{OP_CANCEL}?query_id=1122334455667788"
        )
        self.assertEqual(mock.queries[-1].zone, int(Zone.DEVICE))

    @bounded()
    async def test_a_query_the_node_never_had_is_false_rather_than_an_error(self):
        """"query not found" is the ordinary outcome for a query that has already
        been answered, and it is the only `error_message` this op sends."""
        async with MockApphost(
            routes={OP_CANCEL: Accept(objects=(error_frame("query not found"),))}
        ) as mock:
            api = await self.apphost(mock)
            self.assertFalse(await api.cancel(1))

    @bounded()
    async def test_a_cause_is_sent_only_when_given(self):
        async with MockApphost(
            routes={OP_CANCEL: Accept(objects=(ACK_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.cancel(1, cause="user quit")
        self.assertEqual(
            mock.queries[-1].query,
            f"{OP_CANCEL}?cause=user+quit&query_id=0000000000000001",
        )


class PassthroughTest(ApphostCase):
    @bounded()
    async def test_query_keywords_reach_the_query_rather_than_being_dropped(self):
        """A misspelled keyword must fail in `query()` rather than be discarded:
        silently dropping arguments is exactly the defect astral-go ships in this
        module."""
        async with MockApphost(
            routes={OP_WHOAMI: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.whoami(zone=Zone.DEVICE, filters=("a",))
            self.assertEqual(mock.queries[-1].zone, int(Zone.DEVICE))
            self.assertEqual(mock.queries[-1].filters, ("a",))
            with self.assertRaises(TypeError):
                await api.whoami(timeoutt=1.0)


# --- Tier C: the node ----------------------------------------------------

class LiveApphostTest(live_support.LiveCase):
    """The three read-only, anonymous-safe ops, against a real node.

    Nothing here mutates: no `create_token`, no `hold_object`, no
    `register_handler`, no `bind`, no `cancel`.

    The precheck, the client factory and the descriptor assertion come from
    `live_support.LiveCase`, which dials the node **once per process**. The copy
    that used to live here dialed it a second time, on a pool of 32 shared with
    every app on the machine, and it had drifted: a node that accepts and never
    greets raised `TimeoutError` out of the copied `setUpModule` and errored the
    whole module where the shared one skips it with a reason.
    """

    @bounded(30.0)
    async def test_whoami_answers_the_identity_the_router_substituted(self):
        """An anonymous guest sends a nil `Caller`; astrald's core router
        replaces it with the node's own identity before the op ever sees it. So
        the answer is the greeting's identity for an anonymous client and the
        guest identity for an authenticated one, and the assertion follows
        whichever this client is."""
        async with await self.client() as client:
            who = await Apphost(client).whoami()
            self.assertIsInstance(who, Identity)
            expected = client.guest_id if client.authenticated else client.host_id
            self.assertEqual(who, expected)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_list_tokens_decodes_every_token_the_node_holds(self):
        """The record against the node's own bytes. Also the live confirmation
        that this read needs no privilege: an anonymous guest gets the whole
        table, token strings included, which is why an `AccessToken` that arrives
        here is a secret."""
        async with await self.client() as client:
            tokens = await Apphost(client).list_tokens()
        for token in tokens:
            with self.subTest(identity=str(token.identity)):
                self.assertIsInstance(token, AccessToken)
                self.assertIsInstance(token.identity, Identity)
                self.assertTrue(token.token)
                self.assertGreater(int(token.expires_at), 0)
                # The record's own bytes are the node's bytes: encode what was
                # decoded and the frame comes back identical.
                self.assertEqual(decode(encode(token)), token)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_list_tokens_filtered_by_an_identity_is_a_subset(self):
        """The `identity` parameter reaches the node and filters server-side.

        `GENERATOR` is the secp256k1 base point: a valid identity by
        construction, and one no node has ever issued a token to.
        """
        async with await self.client() as client:
            api = Apphost(client)
            everything = await api.list_tokens()
            self.assertEqual(await api.list_tokens(GENERATOR), [])
            if everything:
                mine = await api.list_tokens(everything[0].identity)
                self.assertTrue(mine)
                self.assertTrue(
                    all(t.identity == everything[0].identity for t in mine)
                )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_validates_that_an_identity_is_a_point_on_the_curve(self):
        """The consequence of design section 5.2, live.

        This SDK treats an identity as 33 opaque bytes and does **not** check
        that they are a point on the curve: doing so would make the single most
        common decode in the protocol depend on a curve library. astral-go's
        `Identity.UnmarshalText` does check. So off-curve bytes are accepted
        locally and travel. astrald declares the argument `string8` and resolves
        it (`opListTokensArgs.Identity`): an off-curve key fails
        `astral.ParseIdentity`, names no alias, and answers `unknown identity`
        as an `error_message` in the accepted stream -- `RemoteError`, not an
        empty result.
        """
        off_curve = Identity.parse("02" + "11" * 32)  # accepted here, refused there
        async with await self.client() as client:
            with self.assertRaises(RemoteError):
                await Apphost(client).list_tokens(off_curve)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_list_held_objects_is_a_list_of_object_ids_ended_by_an_eos(self):
        async with await self.client() as client:
            held = await Apphost(client).list_held_objects()
        self.assertIsInstance(held, list)
        for oid in held:
            self.assertIsInstance(oid, ObjectID)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_whoami_ends_at_a_bare_eof_and_list_tokens_at_an_eos(self):
        """Both shapes, from one node in one run. Which one an op uses is a
        per-op contract and is not on the wire (design section 4.7)."""
        async with await self.client() as client:
            async with client.stream(OP_WHOAMI) as s:
                self.assertEqual(len([obj async for obj in s]), 1)
                self.assertEqual(s.terminated_by, "eof")
                self.assertFalse(s.saw_eos)
            async with client.stream(OP_LIST_TOKENS) as s:
                async for _ in s:
                    pass
                self.assertEqual(s.terminated_by, "eos")
                self.assertTrue(s.saw_eos)
        await self.assert_no_open_sockets()


class LiveAppRegisterPolicyTypesTest(live_support.LiveCase):
    """The node's own layout, zero value and codec for the two policy types.

    Read-only. `objects.get_blueprint` describes a type, `objects.new` builds a
    zero value server-side and `objects.echo` sends back what it decoded;
    none writes anything.
    """

    @bounded(30.0)
    async def test_the_node_derives_the_blueprint_this_module_derives(self):
        async with await self.client() as client:
            for name, fields in POLICY_BLUEPRINTS.items():
                with self.subTest(type=name):
                    got = await client.call_one(
                        f"objects.get_blueprint?type={name}", timeout=20.0
                    )
                    self.assertEqual(str(got.type), name)
                    self.assertEqual(
                        [(str(f.name), spec_of(f.spec)) for f in got.fields], fields
                    )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_builds_the_zero_value_this_module_builds(self):
        async with await self.client() as client:
            for cls in (AppRegisterRequest, AppRegisterDecision):
                with self.subTest(type=cls.ASTRAL_TYPE):
                    body = await client.call_raw(
                        f"objects.new?type={cls.ASTRAL_TYPE}", timeout=20.0
                    )
                    self.assertEqual(body, frame(cls.ASTRAL_TYPE, payload_bytes(cls())))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_a_populated_value_survives_the_node_s_own_codec(self):
        """`objects.echo?strict=true` decodes the frame through the node's
        registry and re-encodes it from the decoded value."""
        async with await self.client() as client:
            for value in (REGISTER_REQUEST, REGISTER_DECISION):
                with self.subTest(type=value.ASTRAL_TYPE):
                    async with client.stream(
                        "objects.echo?strict=true", timeout=20.0
                    ) as stream:
                        await stream.send(value)
                        await stream.send_eos()
                        got = [obj async for obj in stream]
                    self.assertEqual(got, [value])
                    self.assertEqual(payload_bytes(got[0]), payload_bytes(value))
        await self.assert_no_open_sockets()


# --- the review's findings ------------------------------------------------


class NameResolutionTest(ApphostCase):
    """The documented directory-name argument, on the four ops that take one.

    Every existing test passed hex or an `Identity`, so the two-query sequence
    those four docstrings promise -- `dir.resolve`, then the op with the resolved
    hex -- was asserted nowhere through a module client.
    """

    @bounded()
    async def test_a_directory_name_costs_one_resolve_then_the_op(self):
        cases = {
            OP_LIST_TOKENS: lambda a: a.list_tokens("furry-bolt"),
            OP_CREATE_TOKEN: lambda a: a.create_token("furry-bolt"),
        }
        answer = {
            OP_LIST_TOKENS: Accept(objects=(TOKEN_FRAME,), eos=True),
            OP_CREATE_TOKEN: Accept(objects=(TOKEN_FRAME,)),
        }
        for op, run in cases.items():
            with self.subTest(op=op):
                async with MockApphost(
                    routes={
                        "dir.resolve?identity=furry-bolt": Accept(
                            objects=(IDENTITY_FRAME,)
                        ),
                        op: answer[op],
                    }
                ) as mock:
                    api = await self.apphost(mock)
                    await run(api)
                self.assertEqual(
                    [q.query for q in mock.queries],
                    ["dir.resolve?identity=furry-bolt", f"{op}?identity={ID_HEX}"],
                )

    @bounded()
    async def test_the_resolve_leg_runs_inside_the_callers_timeout(self):
        """`timeout` sat unused in `**kw` and was applied only to the second
        query, so the leg the caller cannot see was bounded by the client's own
        60 s default."""
        async with MockApphost(
            routes={"dir.resolve?identity=furry-bolt": Accept(hold=True)}
        ) as mock:
            api = await self.apphost(mock, query_timeout=30.0)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout):
                await api.list_tokens("furry-bolt", timeout=0.2)
            self.assertLess(loop.time() - started, 1.0)


class SecurityNoteTest(unittest.TestCase):
    """The census this module's docstring states, counted at the pin.

    The note began by saying `list_tokens` was "alone among its neighbours" in
    carrying no network-origin guard, which understated the exposure. It was
    then corrected to a census of thirteen ops, and **that** went stale the
    other way: astrald guarded the token ops and the docstring kept telling a
    caller they were open. A census is a claim with a shelf life, so it names
    its revision and is read there: the pin, so moving the pin re-counts it.
    """

    SRC = "mod/apphost/src"

    # At the pin. The ops that ask an action before they touch what they guard.
    TOKEN_AND_GRANT = {
        "create_token",
        "delete_token",
        "list_tokens",
        "grant",
        "list_grants",
        "revoke",
    }
    ADMIN_MANAGE_APPS = TOKEN_AND_GRANT | {"set_app_register_policy"}
    SERVE_APPS = {"register_handler"}
    CURRENT_UNGUARDED = {"whoami", "register", "set_app_register_policy"}

    def ops(self) -> dict[str, str]:
        """Every `op_*.go` at the pin, name to source.

        `_test.go` is excluded, and that is not cosmetic: `op_grants_test.go`
        and three other `op_*_test.go` files sit beside the ops at the pin, and
        counting them makes the census nineteen.
        """
        try:
            names = reference.listdir(reference.ASTRALD, self.SRC)
            return {
                name[len("op_") : -len(".go")]: reference.read(
                    reference.ASTRALD, f"{self.SRC}/{name}"
                )
                for name in names
                if name.startswith("op_")
                and name.endswith(".go")
                and not name.endswith("_test.go")
            }
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

    def test_the_current_census_matches_the_pin(self):
        """The census the docstring states at the pin, recounted from the source.

        Recounted rather than compared against a number in the prose: the prose
        is what goes stale, and a test that read its numbers out of the prose
        would agree with it whatever it said.
        """
        ops = self.ops()
        guarded = {name for name, src in ops.items() if "OriginNetwork" in src}

        self.assertEqual(len(ops), 16)
        self.assertEqual(set(ops) - guarded, self.CURRENT_UNGUARDED)
        self.assertEqual(len(guarded), 13)

        # Unwrapped, because a line break inside a sentence is a formatting
        # choice and the claim is the sentence.
        doc = " ".join((apphost_module.__doc__ or "").split())
        self.assertNotIn("alone among its neighbours", doc)
        self.assertIn(f"re-derived at `{reference.PINS[reference.ASTRALD][1]}`", doc)
        self.assertIn("Sixteen `op_*.go` files.", doc)
        self.assertIn("Thirteen refuse a network origin", doc)
        self.assertIn(
            "the three that do not are `whoami`, `register` and "
            "`set_app_register_policy`",
            doc,
        )

    def test_the_token_ops_ask_admin_manage_apps_before_they_answer(self):
        """The action guard, per op.

        The order matters as much as the presence: the refusal has to come out
        before `AcceptRaw`, or a caller holding nothing has already been handed
        a channel by the time it is told no.
        """
        ops = self.ops()
        asked = {
            name
            for name, src in ops.items()
            if "AdminManageAppsAction" in src
        }
        self.assertEqual(asked, self.ADMIN_MANAGE_APPS)
        self.assertEqual(
            {n for n, s in ops.items() if "ServeAppsAction" in s}, self.SERVE_APPS
        )

        for name in sorted(self.ADMIN_MANAGE_APPS):
            with self.subTest(op=name):
                src = ops[name]
                self.assertLess(
                    src.index("AdminManageAppsAction"), src.index("q.Accept")
                )
                if name in self.TOKEN_AND_GRANT:
                    self.assertLess(src.index("OriginNetwork"), src.index("q.Accept"))

        doc = apphost_module.__doc__ or ""
        self.assertIn("mod.auth.admin_manage_apps_action", doc)
        self.assertIn("mod.auth.serve_apps_action", doc)
        for name in ("list_tokens", "create_token", "delete_token"):
            with self.subTest(op=name):
                self.assertIn(name, doc)

    def test_the_action_is_held_by_the_node_a_tokenless_caller_wears(self):
        """Why the guard does not close the plaintext read for a local process.

        Three files, and the docstring's inference is exactly their
        composition: the user module allows the node's own identity, the core
        router hands that identity to a caller who sent none, and the flag
        astrald sets for such a session cannot reach an op.
        """
        try:
            user_auth = reference.read(
                reference.ASTRALD, "mod/user/src/authorize_user_or_node.go"
            )
            router = reference.read(reference.ASTRALD, "core/router.go")
            guard = reference.read(reference.ASTRALD, "mod/crypto/src/sign_guard.go")
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

        self.assertIn("mod.node.Identity()", user_auth)
        self.assertIn("q.Caller = r.node.identity", router)
        self.assertIn("the flag cannot reach an op", guard)

        doc = " ".join((apphost_module.__doc__ or "").split())
        self.assertIn("wearing the node's identity", doc)
        self.assertIn("with no live run behind it", doc)

    def test_every_astrald_line_the_authorization_section_cites_lands(self):
        """`path:line` at the pin, each one read and matched against its claim.

        A citation that names the wrong line is a reader sent to the wrong
        place, which is the failure this whole file exists to make loud.
        """
        admin = "AdminManageAppsAction"
        cites = (
            (f"{self.SRC}/op_list_tokens.go", 21, "OriginNetwork"),
            (f"{self.SRC}/op_list_tokens.go", 27, admin),
            (f"{self.SRC}/op_create_token.go", 21, "OriginNetwork"),
            (f"{self.SRC}/op_create_token.go", 25, admin),
            (f"{self.SRC}/op_delete_token.go", 20, "OriginNetwork"),
            (f"{self.SRC}/op_delete_token.go", 24, admin),
            (f"{self.SRC}/op_cancel.go", 23, "OriginNetwork"),
            (f"{self.SRC}/op_cancel.go", 36, "answers as a missing one"),
            (f"{self.SRC}/op_cancel.go", 58, "func (mod *Module) mayCancel"),
            (f"{self.SRC}/op_register_handler.go", 29, "ServeAppsAction"),
            (f"{self.SRC}/authorize_admin_manage_apps.go", 19, "func (mod *Module) mayManageApps"),
            (f"{self.SRC}/authorize_admin_manage_apps.go", 24, "AdminManageAppsAction"),
            (f"{self.SRC}/guest.go", 204, "ExtraAnonymous"),
            (f"{self.SRC}/guest.go", 270, "isAuthenticated()"),
            ("mod/user/src/authorize_user_or_node.go", 16, "authorizeUserOrNode"),
            ("mod/user/src/authorize_user_or_node.go", 20, "mod.node.Identity()"),
            ("mod/user/src/authorize_serve_apps.go", 15, "AuthorizeServeApps"),
            ("core/router.go", 45, "q.Caller == nil"),
            ("core/router.go", 46, "q.Caller = r.node.identity"),
            ("mod/crypto/src/sign_guard.go", 36, "cannot reach an op"),
            (f"{self.SRC}/op_hosts.go", 26, "OriginNetwork"),
            (f"{self.SRC}/op_hosts.go", 32, "SeeSwarmAction"),
        )
        for path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(reference.ASTRALD, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)


class RegisterCitationTest(unittest.TestCase):
    """Every `path:line` the register and register-policy prose cites, read at
    the pins, and the separator claim read off the source rather than trusted."""

    SRC = "mod/apphost/src"

    def test_every_anchor_lands_on_its_claim(self):
        cites = (
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 17, "RegisterDuration = 10 * 365"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 23, "type opRegisterArgs struct"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 39, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 56,
             "append(mod.GetWebOriginPermits(origin), parsePermits(args.ContractPermits)...)"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 58, "why accept before deciding"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 60, "query.AcceptRaw()"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 69, "GetRegisterAppPolicy()"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 75, "switch {"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 78, "ErrRegistrationDeclined"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 86, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 132, "Add(RegisterDuration)"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 137, "range grantPermits"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 182, "CreateAccessToken(guestID"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 13,
             "type opSetAppRegisterPolicyArgs struct"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 23, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 31,
             "AdminManageAppsAction"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 35, "q.AcceptRaw()"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 38,
             'args.Identity == "" && args.Operation == ""'),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 46, "mod.newDelegate("),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 61,
             "func (mod *Module) newDelegate"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 71, "d.Validate()"),
            (reference.ASTRALD, f"{self.SRC}/parse_permits.go", 12, "func parsePermits"),
            (reference.ASTRALD, f"{self.SRC}/register_serve_apps.go", 15,
             "func serveAppsGrantRequest"),
            (reference.ASTRALD, f"{self.SRC}/register_serve_apps.go", 17,
             "append([]*auth.Permit{serveApps}, parsePermits(asked)...)"),
            (reference.ASTRALD, "mod/apphost/register_policy.go", 33, "func AcceptAll"),
            (reference.ASTRAL_GO, "api/apphost/errors.go", 7,
             'NewError("registration declined")'),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 38,
             "func (client *Client) Register(ctx *astral.Context, permits ...string)"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 70, "func registerArgs"),
            (reference.ASTRAL_GO, "lib/query/field_editor.go", 41, "case reflect.String:"),
            (reference.ASTRAL_GO, "lib/query/field_editor.go", 42, 'String8("").ObjectType()'),
            (reference.ASTRAL_GO, "astral/string_types.go", 25, "if len(s) > 1<<8-1"),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)

    def test_the_node_splits_on_commas_and_trims_each_piece(self):
        """What `_permits` refuses is what `parsePermits` would misread."""
        try:
            src = reference.read(reference.ASTRALD, f"{self.SRC}/parse_permits.go")
            args = reference.read(reference.ASTRALD, f"{self.SRC}/op_register.go")
        except reference.Unavailable as exc:  # pragma: no cover
            self.skipTest(str(exc))
        self.assertIn('strings.Split(joined, ",")', src)
        self.assertIn("strings.TrimSpace(action)", src)
        self.assertIn('action != ""', src)
        for field in ("GrantPermits string", "ContractPermits string", "Name string"):
            with self.subTest(field=field):
                self.assertIn(field, args)
        self.assertEqual(ERR_REGISTRATION_DECLINED, "registration declined")


class ModulePatternTest(ApphostCase):
    """One base class, one shape-violation message, one type sweep."""

    @bounded()
    async def test_the_two_module_clients_share_one_expect(self):
        from astral.api.base import ModuleClient
        from astral.api.dir import Dir

        self.assertIs(Apphost._expect, Dir._expect)
        self.assertIs(Apphost._expect, ModuleClient._expect)
        self.assertTrue(issubclass(Apphost, ModuleClient))
        self.assertTrue(issubclass(Dir, ModuleClient))

        async with MockApphost() as mock:
            client = await self.client(mock)
            for api in (Apphost(client), Dir(client)):
                with self.subTest(module=type(api).__name__):
                    self.assertIs(api.client, client)
                    self.assertIn(type(api).__name__, repr(api))
                    with self.assertRaises(ProtocolError) as caught:
                        api._expect(Ack(), Identity, "op")
                    self.assertEqual(
                        str(caught.exception), "op: expected 'identity', got 'ack'"
                    )

    @bounded()
    async def test_every_module_has_a_type_sweep_and_a_client_property(self):
        """Walked from the directory, not enumerated by hand. Enumerating it by
        hand is what let five modules land with no `Client` property while this
        test and `ModuleClientAttachmentTest` both passed: each named `apphost`
        and `dir` and neither looked at what else was in the package.

        The walk is over the modules that declare **ops**. Design section 0.1
        puts type-only modules in this package on purpose -- excluding a module
        excludes its ops and not its types -- so `exonet` and `endpoints` have
        no client and no property, and `api_walk` decides which is which by what
        a module declares rather than by name.
        """
        import astral.api
        from astral.api.base import ModuleClient

        self.assertEqual(tuple(Apphost.TYPES), tuple(APPHOST_TYPES))
        modules = api_walk.op_modules()
        self.assertGreaterEqual(len(modules), 7, "the walk found nothing to check")
        async with MockApphost() as mock:
            client = await self.client(mock)
            for name in modules:
                with self.subTest(module=name):
                    got = getattr(client, name)
                    self.assertIsInstance(got, ModuleClient)
                    self.assertIs(got, getattr(client, name))
                    # The sweep is the module's own tuple of declared types, and
                    # every name in it is registered by the eager import above.
                    self.assertEqual(
                        tuple(type(got).TYPES),
                        tuple(getattr(astral.api, name).__dict__[
                            f"{name.upper()}_TYPES"
                        ]),
                    )

    @bounded()
    async def test_every_parameter_goes_through_its_declared_spec(self):
        """Design section 5.1 rule 2 names `encode_param(spec, value)` the single
        implementation, and a spec is what makes it one: without one the encoder
        dispatches on the *value*, so `param_text(b'ab')` silently sends `YWI=`
        where `encode_param(Primitive('string8'), b'ab')` raises. `dir.py` used
        it and `apphost.py` never called it once."""
        from astral.api import apphost as mod
        from astral.querystring import param_text

        self.assertEqual(mod._IDENTITY["identity"], Primitive("string8"))
        self.assertEqual(mod._OBJECT_ID["id"], Primitive("object_id.sha256"))
        self.assertEqual(mod._CANCEL["query_id"], Primitive("nonce64"))
        self.assertEqual(
            mod._REGISTER,
            {key: Primitive("string8") for key in ("grant_permits", "contract_permits", "name")},
        )

        # The declaration is what refuses a wrong-typed value. Without it the
        # encoder dispatches on the value and sends base64 for bytes.
        with self.assertRaises(astral.AstralError):
            mod._encode(mod._IDENTITY, {"identity": b"not an identity"})
        self.assertEqual(param_text(b"not an identity"), "bm90IGFuIGlkZW50aXR5")

        # And what the ops actually send is an identity's hex, byte for byte.
        self.assertEqual(
            mod._encode(
                mod._IDENTITY,
                {"identity": FURRY_BOLT.text(), "duration": Duration(5)},
            ),
            {"identity": ID_HEX, "duration": param_text(Duration(5))},
        )

    @bounded()
    async def test_a_float_duration_is_refused_inside_the_hierarchy(self):
        """Every caller who writes `duration=1.5` means seconds, and 1.5
        nanoseconds is a token that expires before the reply arrives."""
        with self.assertRaises(BadArgumentType):
            _duration(1.5)
        with self.assertRaises(TypeError):
            _duration(1.5)
        with self.assertRaises(astral.AstralError):
            _duration(1.5)


if __name__ == "__main__":
    unittest.main()
