"""The `apphost` module client, its data types, and the eager-import rule.

Three tiers in one file, because they assert three different things about the
same fifteen ops:

- **Tier A** pins the wire: `apphost.access_token` byte for byte, the missing
  `mod.` prefix that would make every token frame undecodable, and the registry
  contents -- including the one type that must *not* be there. The two app
  registration policy types are pinned against **astral-go's own output**:
  every vector in `POLICY_GO_VECTORS` was produced by a Go program linked
  against astral-go `221ce52`, printing `hex.EncodeToString` of what `WriteTo`
  wrote, `json.Marshal` of the value, the line `channel.TextSender` wrote, and
  `astral.ResolveObjectID`. The four grant types are pinned the same way in
  `GRANT_GO_VECTORS`, from a program linked against astral-go `dbc27574`, the
  head of astral-go #167, whose tree its merge `08ead7ce` carries unchanged.
- **Tier B** pins the query strings and the shapes against `MockApphost`. A
  module client is argument marshalling plus one call, so the marshalling is
  what can be wrong: a capitalised key is silently dropped by the node, an
  omitted parameter and an empty one are different things, and an op's mode is a
  declaration that a test has to make as well.
- **Tier C** asks the node, as the node through `ASTRAL_TEST_NODE_TOKEN`, and
  only through the three read-only ops and the read-only `objects.get_blueprint`, `objects.new` and
  `objects.echo` for the two policy types. `apphost.register`,
  `apphost.set_app_register_policy`, `apphost.grant`, `apphost.request_grant`
  and `apphost.revoke` mutate the node and are exercised against the mock alone
  (design section 7.3). Skipped with a reason when
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
    OP_LIST_GRANTS,
    OP_LIST_HELD_OBJECTS,
    OP_LIST_TOKENS,
    OP_REGISTER,
    OP_REGISTER_HANDLER,
    OP_REQUEST_GRANT,
    OP_REVOKE,
    OP_SET_APP_REGISTER_POLICY,
    OP_UNHOLD_OBJECT,
    OP_WHOAMI,
    ERR_GRANT_DECLINED,
    ERR_GRANT_NOT_FOUND,
    ERR_REGISTRATION_DECLINED,
    AccessToken,
    APPHOST_TYPES,
    Apphost,
    AppRegisterDecision,
    AppRegisterRequest,
    Grant,
    GrantRequest,
    RegisterRequest,
    RequestGrantRequest,
    _duration,
    _object_id,
    apphost_types,
)
from astral.api.auth import AuthorizerAssignment, Permit
from astral.api.services import DiscoveryRule, DiscoveryScope, ServiceDiscoveryAction
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
    QueryTimeout,
    RemoteError,
)
from astral.object import Ack, Bundle
from astral.objectid import object_id
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive, Ptr, Slice
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
    bounded,
    frame,
    socket_fds,
    until,
)

# The identity every fixture below uses. The live node's own, so a captured
# frame and a constructed one are comparable.
ID_HEX = "03b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae1"
TOKEN = "R6mLmR21IajGVMhcXvbPtjfNiXKuJpsO"
# 2027-07-26T19:42:23.112712094Z, as read off the live node.
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

DISCOVERY_PERMIT = Permit(
    action=ServiceDiscoveryAction.ASTRAL_TYPE,
    constraints=Bundle([DiscoveryScope(rules=[DiscoveryRule(services=["inference"])])]),
)

# Name -> (value, payload hex, JSON, text line, ObjectID), each string astral-go
# `08ead7ce`'s output for the Go struct literal the value mirrors.
GRANT_GO_VECTORS: dict[str, tuple[object, str, str, str, str]] = {
    "grant_full": (
        Grant(id=7, permit=DISCOVERY_PERMIT, expires_at=EXPIRES),
        "000000000000000701256d6f642e73657276696365732e736572766963655f646973636f"
        "766572795f616374696f6e0100000001000000351c6d6f642e73657276696365732e6469"
        "73636f766572795f73636f70650000000101000000010109696e666572656e6365000000"
        "0000011935f837c4374f9e",
        '{"ExpiresAt":"2027-07-26T19:42:23.112712094Z","ID":7,"Permit":{"Action":"mod'
        '.services.service_discovery_action","Constraints":[{"Type":"mod.services.dis'
        'covery_scope","Object":{"Rules":[{"Nodes":[],"Services":["inference"]}]}}],"'
        'Delegation":0}}',
        "#[mod.apphost.grant]:AAAAAAAAAAcBJW1vZC5zZXJ2aWNlcy5zZXJ2aWNlX2Rpc2NvdmVyeV9"
        "hY3Rpb24BAAAAAQAAADUcbW9kLnNlcnZpY2VzLmRpc2NvdmVyeV9zY29wZQAAAAEBAAAAAQEJaW5"
        "mZXJlbmNlAAAAAAABGTX4N8Q3T54=",
        "data1e43t9nqpoaoet5w895mpwzbojhfg4fkt1ncksq8rjse1t6mpuweu3",
    ),
    "grant_until_revoked": (
        Grant(id=8, permit=GRANT),
        "0000000000000008011e6d6f642e6f626a656374732e726561645f6f626a6563745f6163"
        "74696f6e000000",
        '{"ExpiresAt":null,"ID":8,"Permit":{"Action":"mod.objects.read_object_action"'
        ',"Constraints":null,"Delegation":0}}',
        "#[mod.apphost.grant]:AAAAAAAAAAgBHm1vZC5vYmplY3RzLnJlYWRfb2JqZWN0X2FjdGlvbgA"
        "AAA==",
        "data1rdb5jry7rgo4wch5h1dp6ehdsxzsfuk5dtpkjmtohhe78b69dt791",
    ),
    "grant_zero": (
        Grant(),
        "00000000000000000000",
        '{"ExpiresAt":null,"ID":0,"Permit":null}',
        "#[mod.apphost.grant]:AAAAAAAAAAAAAA==",
        "data1nyhex4tb8nwew7thbmo7sx63nyidn15r359xwh1kzr9snwwmxcjae",
    ),
    "register_request_full": (
        RegisterRequest(
            name="smithd",
            grant_permits=[DISCOVERY_PERMIT],
            contract_permits=[CONTRACT_PERMIT],
        ),
        "06736d697468640000000101256d6f642e73657276696365732e736572766963655f6469"
        "73636f766572795f616374696f6e0100000001000000351c6d6f642e7365727669636573"
        "2e646973636f766572795f73636f70650000000101000000010109696e666572656e6365"
        "000000000000000001011b6d6f642e617574682e7365655f6f626a656374735f61637469"
        "6f6e0001",
        '{"ContractPermits":[{"Action":"mod.auth.see_objects_action","Constraints":nu'
        'll,"Delegation":1}],"GrantPermits":[{"Action":"mod.services.service_discover'
        'y_action","Constraints":[{"Type":"mod.services.discovery_scope","Object":{"R'
        'ules":[{"Nodes":[],"Services":["inference"]}]}}],"Delegation":0}],"Name":"sm'
        'ithd"}',
        "#[mod.apphost.register_request]:BnNtaXRoZAAAAAEBJW1vZC5zZXJ2aWNlcy5zZXJ2aWNl"
        "X2Rpc2NvdmVyeV9hY3Rpb24BAAAAAQAAADUcbW9kLnNlcnZpY2VzLmRpc2NvdmVyeV9zY29wZQAA"
        "AAEBAAAAAQEJaW5mZXJlbmNlAAAAAAAAAAABARttb2QuYXV0aC5zZWVfb2JqZWN0c19hY3Rpb24A"
        "AQ==",
        "data1mmcbbp8f9c6exhdcpxahbaanmhxi69fxgicuz5jen4f4w7hj3yt1h",
    ),
    "register_request_zero": (
        RegisterRequest(),
        "000000000000000000",
        '{"ContractPermits":[],"GrantPermits":[],"Name":""}',
        "#[mod.apphost.register_request]:AAAAAAAAAAAA",
        "data1nimzs4rzda6o37sqoogcdj834dgkz6dtbqezeoy4kfqigukt83mgt",
    ),
    "grant_request_full": (
        GrantRequest(
            identity=Identity.parse(ID_HEX),
            duration=Duration(3600 * 10**9),
            permits=[DISCOVERY_PERMIT, GRANT],
        ),
        "0103b2704948bb2e4603ccb1bcd5f01f5df9aa52cbf94b6b54a3978df81185bd7ae10000"
        "034630b8a0000000000201256d6f642e73657276696365732e736572766963655f646973"
        "636f766572795f616374696f6e0100000001000000351c6d6f642e73657276696365732e"
        "646973636f766572795f73636f70650000000101000000010109696e666572656e636500"
        "00000000011e6d6f642e6f626a656374732e726561645f6f626a6563745f616374696f6e"
        "0000",
        '{"Duration":3600000000000,"Identity":"03b2704948bb2e4603ccb1bcd5f01f5df9aa52'
        'cbf94b6b54a3978df81185bd7ae1","Permits":[{"Action":"mod.services.service_dis'
        'covery_action","Constraints":[{"Type":"mod.services.discovery_scope","Object'
        '":{"Rules":[{"Nodes":[],"Services":["inference"]}]}}],"Delegation":0},{"Acti'
        'on":"mod.objects.read_object_action","Constraints":null,"Delegation":0}]}',
        "#[mod.apphost.grant_request]:AQOycElIuy5GA8yxvNXwH135qlLL+UtrVKOXjfgRhb164QA"
        "AA0YwuKAAAAAAAgElbW9kLnNlcnZpY2VzLnNlcnZpY2VfZGlzY292ZXJ5X2FjdGlvbgEAAAABAAA"
        "ANRxtb2Quc2VydmljZXMuZGlzY292ZXJ5X3Njb3BlAAAAAQEAAAABAQlpbmZlcmVuY2UAAAAAAAE"
        "ebW9kLm9iamVjdHMucmVhZF9vYmplY3RfYWN0aW9uAAA=",
        "data1pe3hzt7338d9e1fzcbkqqfsdpbyky6d98j36pc4nf9q4fyk4cbutm",
    ),
    "grant_request_zero": (
        GrantRequest(),
        "00000000000000000000000000",
        '{"Duration":0,"Identity":null,"Permits":[]}',
        "#[mod.apphost.grant_request]:AAAAAAAAAAAAAAAAAA==",
        "data1nswk8o4rtnedxazs3xogyxi8q1fw99z1cwhjxuz1gs7gzogfw4yic",
    ),
    "request_grant_request_full": (
        RequestGrantRequest(
            permits=[DISCOVERY_PERMIT], duration=Duration(3600 * 10**9)
        ),
        "0000000101256d6f642e73657276696365732e736572766963655f646973636f76657279"
        "5f616374696f6e0100000001000000351c6d6f642e73657276696365732e646973636f76"
        "6572795f73636f70650000000101000000010109696e666572656e636500000000000000"
        "034630b8a000",
        '{"Duration":3600000000000,"Permits":[{"Action":"mod.services.service_discove'
        'ry_action","Constraints":[{"Type":"mod.services.discovery_scope","Object":{"'
        'Rules":[{"Nodes":[],"Services":["inference"]}]}}],"Delegation":0}]}',
        "#[mod.apphost.request_grant_request]:AAAAAQElbW9kLnNlcnZpY2VzLnNlcnZpY2VfZGl"
        "zY292ZXJ5X2FjdGlvbgEAAAABAAAANRxtb2Quc2VydmljZXMuZGlzY292ZXJ5X3Njb3BlAAAAAQE"
        "AAAABAQlpbmZlcmVuY2UAAAAAAAAAA0YwuKAA",
        "data1jt4pomr5n7ho5ukyaowh7dbb8ums8bnaperdwk35yitg5jcbf31gz",
    ),
    "request_grant_request_zero": (
        RequestGrantRequest(),
        "000000000000000000000000",
        '{"Duration":0,"Permits":[]}',
        "#[mod.apphost.request_grant_request]:AAAAAAAAAAAAAAAA",
        "data1dfuiero3q69zui5q9zq8pa53en7g3yzxxharzry4pwwiz7mxpez3o",
    ),
}

# `astral.BlueprintOf` at astral-go `08ead7ce`, the function the node's
# `objects.get_blueprint` answers with (`mod/objects/src/module.go:237-255` at
# astrald `a499928a`), decoded.
GRANT_BLUEPRINTS = {
    "mod.apphost.grant": [
        ("ID", Primitive("uint64")),
        ("Permit", Ptr("mod.auth.permit")),
        ("ExpiresAt", Ptr("time")),
    ],
    "mod.apphost.register_request": [
        ("Name", Primitive("string8")),
        ("GrantPermits", Slice("mod.auth.permit")),
        ("ContractPermits", Slice("mod.auth.permit")),
    ],
    "mod.apphost.grant_request": [
        ("Identity", Ptr("identity")),
        ("Duration", Primitive("duration")),
        ("Permits", Slice("mod.auth.permit")),
    ],
    "mod.apphost.request_grant_request": [
        ("Permits", Slice("mod.auth.permit")),
        ("Duration", Primitive("duration")),
    ],
}

# The four blueprints as astral-go `08ead7ce` writes them, `astral.blueprint`
# payloads in hex, for decoding rather than for trusting the table above.
GRANT_BLUEPRINT_PAYLOADS = {
    "mod.apphost.grant": (
        "00116d6f642e617070686f73742e6772616e740000000301000249441f61737472616c2e"
        "626c75657072696e742e7072696d69746976655f73706563000675696e74363401000650"
        "65726d69741961737472616c2e626c75657072696e742e7074725f73706563000f6d6f64"
        "2e617574682e7065726d69740100094578706972657341741961737472616c2e626c7565"
        "7072696e742e7074725f73706563000474696d650000"
    ),
    "mod.apphost.register_request": (
        "001c6d6f642e617070686f73742e72656769737465725f72657175657374000000030100"
        "044e616d651f61737472616c2e626c75657072696e742e7072696d69746976655f737065"
        "630007737472696e673801000c4772616e745065726d6974731b61737472616c2e626c75"
        "657072696e742e736c6963655f73706563000f6d6f642e617574682e7065726d69740100"
        "0f436f6e74726163745065726d6974731b61737472616c2e626c75657072696e742e736c"
        "6963655f73706563000f6d6f642e617574682e7065726d69740000"
    ),
    "mod.apphost.grant_request": (
        "00196d6f642e617070686f73742e6772616e745f72657175657374000000030100084964"
        "656e746974791961737472616c2e626c75657072696e742e7074725f7370656300086964"
        "656e746974790100084475726174696f6e1f61737472616c2e626c75657072696e742e70"
        "72696d69746976655f7370656300086475726174696f6e0100075065726d6974731b6173"
        "7472616c2e626c75657072696e742e736c6963655f73706563000f6d6f642e617574682e"
        "7065726d69740000"
    ),
    "mod.apphost.request_grant_request": (
        "00216d6f642e617070686f73742e726571756573745f6772616e745f7265717565737400"
        "0000020100075065726d6974731b61737472616c2e626c75657072696e742e736c696365"
        "5f73706563000f6d6f642e617574682e7065726d69740100084475726174696f6e1f6173"
        "7472616c2e626c75657072696e742e7072696d69746976655f7370656300086475726174"
        "696f6e0000"
    ),
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
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 211,
             "ContractPermits: req.ContractPermits"),
            (reference.ASTRALD, "mod/apphost/src/register_grant_request.go", 17,
             "func registerGrantRequest"),
            (reference.ASTRALD, "mod/apphost/src/register_grant_request.go", 20,
             "append([]*auth.Permit{serveApps, useBlueprints}, asked...)"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 71, "dec.Validate()"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 73,
             "ErrRegistrationDeclined"),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)


class GrantTypesTest(unittest.TestCase):
    """The grant and the three request objects, against astral-go `08ead7ce`."""

    def test_every_value_encodes_to_the_go_bytes(self):
        for name, (value, payload, _, _, _) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(payload_bytes(value).hex(), payload)

    def test_the_go_bytes_decode_to_every_value(self):
        for name, (value, payload, _, _, _) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = type(value).read_payload(object_reader(bytes.fromhex(payload)))
                self.assertEqual(got, value)

    def test_the_go_json_decodes_to_every_value(self):
        for name, (value, _, go_json, _, _) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                got = jsoncodec.unmarshal(value.ASTRAL_TYPE, json.loads(go_json))
                self.assertEqual(got, value)

    def test_every_value_survives_its_own_json(self):
        """The SDK's JSON differs from Go's only where `AppRegisterPolicyTypesTest`
        pins it, an empty list as `null`, so the round trip is the check for the
        vectors that hold one."""
        for name, (value, _, _, _, _) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                mine = jsoncodec.marshal(value)
                self.assertEqual(jsoncodec.unmarshal(value.ASTRAL_TYPE, mine), value)

    def test_an_until_revoked_grant_marshals_to_the_go_json(self):
        """`ExpiresAt` absent is `null` on both sides, not a zero time: Go's zero
        `time.Time` encodes in binary as a negative `UnixNano` and in JSON as
        year 1, which `Time` refuses."""
        value, payload, go_json, _, _ = GRANT_GO_VECTORS["grant_until_revoked"]
        self.assertIsNone(value.expires_at)
        self.assertEqual(jsoncodec.marshal(value), json.loads(go_json))
        self.assertTrue(payload.endswith("00"))

    def test_an_empty_list_marshals_to_null_where_go_sends_an_array(self):
        for name in (
            "register_request_zero",
            "grant_request_zero",
            "request_grant_request_zero",
        ):
            value, _, go_json, _, _ = GRANT_GO_VECTORS[name]
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
        for name, (value, _, _, line, _) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(text_encode(value), line)
                self.assertEqual(text_decode(line), value)

    def test_every_object_id_is_the_go_object_id(self):
        for name, (value, _, _, _, oid) in GRANT_GO_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(str(object_id(value)), oid)

    def test_every_field_declaration_matches_the_go_blueprint(self):
        for cls in (Grant, RegisterRequest, GrantRequest, RequestGrantRequest):
            with self.subTest(type=cls.ASTRAL_TYPE):
                expected = GRANT_BLUEPRINTS[cls.ASTRAL_TYPE]
                self.assertEqual([(f.wire_name, f.spec) for f in cls.FIELDS], expected)
                got = blueprint_of(cls)
                self.assertEqual([(f.name, spec_of(f.spec)) for f in got.fields], expected)
                name = b"astral.blueprint"
                go = decode(
                    bytes([len(name)]) + name
                    + bytes.fromhex(GRANT_BLUEPRINT_PAYLOADS[cls.ASTRAL_TYPE])
                )
                self.assertEqual(str(go.type), cls.ASTRAL_TYPE)
                self.assertEqual(
                    [(str(f.name), spec_of(f.spec)) for f in go.fields], expected
                )

    def test_every_anchor_lands_on_its_claim(self):
        """The `path:line` citations of the grant types and the grant prose."""
        cites = (
            (reference.ASTRAL_GO, "api/apphost/grant.go", 10,
             "Grant is one node-local grant"),
            (reference.ASTRAL_GO, "api/apphost/grant.go", 20, "ExpiresAt *astral.Time"),
            (reference.ASTRAL_GO, "api/apphost/grant.go", 21, "}"),
            (reference.ASTRAL_GO, "api/apphost/register_request.go", 10,
             "RegisterRequest is the registration an app sends"),
            (reference.ASTRAL_GO, "api/apphost/register_request.go", 22, "}"),
            (reference.ASTRAL_GO, "api/apphost/grant_request.go", 10,
             "GrantRequest is the grants a caller asks apphost.grant"),
            (reference.ASTRAL_GO, "api/apphost/grant_request.go", 13,
             "zero"),
            (reference.ASTRAL_GO, "api/apphost/grant_request.go", 14,
             "writes grants that last until revoked"),
            (reference.ASTRAL_GO, "api/apphost/grant_request.go", 19, "}"),
            (reference.ASTRAL_GO, "api/apphost/request_grant_request.go", 10,
             "RequestGrantRequest is the grants a session asks"),
            (reference.ASTRAL_GO, "api/apphost/request_grant_request.go", 12,
             "no identity"),
            (reference.ASTRAL_GO, "api/apphost/request_grant_request.go", 15,
             "zero asks for grants that last until revoked"),
            (reference.ASTRAL_GO, "api/apphost/request_grant_request.go", 19, "}"),
            (reference.ASTRAL_GO, "api/apphost/errors.go", 9, "ErrGrantDeclined is the answer"),
            (reference.ASTRAL_GO, "api/apphost/errors.go", 11, 'NewError("grant declined")'),
            (reference.ASTRAL_GO, "api/auth/errors.go", 16, "ErrInvalidPermit refuses a permit"),
            (reference.ASTRAL_GO, "api/auth/errors.go", 18,
             'A refusal reads "invalid permit: <action>: <detail>"'),
            (reference.ASTRAL_GO, "api/auth/errors.go", 19, 'NewError("invalid permit")'),
            (reference.ASTRAL_GO, "api/apphost/client/grant.go", 10,
             "Grant asks the target node to write the node-local grants"),
            (reference.ASTRAL_GO, "api/apphost/client/grant.go", 15,
             "Grants add up: a grant never replaces another"),
            (reference.ASTRAL_GO, "api/apphost/client/grant.go", 17,
             "is granting the narrow permit, then revoking the wide one"),
            (reference.ASTRAL_GO, "api/apphost/client/request_grant.go", 10,
             "RequestGrant asks the target node to grant the calling session"),
            (reference.ASTRAL_GO, "api/apphost/client/request_grant.go", 16,
             "asks the policy on every call"),
            (reference.ASTRAL_GO, "api/apphost/client/request_grant.go", 18,
             "closes the query and returns ctx's error"),
            (reference.ASTRAL_GO, "api/apphost/client/request_grant.go", 20,
             "A refusal arrives as apphost.ErrGrantDeclined, an invalid permit as"),
            (reference.ASTRAL_GO, "api/apphost/client/request_grant.go", 21,
             "auth.ErrInvalidPermit"),
            (reference.ASTRAL_GO, "api/apphost/client/list_grants.go", 10,
             "ListGrants returns the node-local grants identity holds"),
            (reference.ASTRAL_GO, "api/apphost/client/list_grants.go", 11,
             "Each grant's ID names it to RevokeGrant"),
            (reference.ASTRAL_GO, "api/apphost/client/revoke.go", 9,
             "RevokeGrant deletes the one node-local grant named id"),
            (reference.ASTRAL_GO, "api/apphost/client/revoke.go", 10,
             "must name a grant identity holds"),
            (reference.ASTRAL_GO, "api/apphost/client/revoke.go", 14,
             '"id": id'),
            (reference.ASTRAL_GO, "api/apphost/client/revoke.go", 23,
             "RevokeAction deletes every node-local grant identity holds for action"),
            (reference.ASTRAL_GO, "api/apphost/client/revoke.go", 27,
             '"action": action'),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 22,
             "Register provisions a fresh guest identity end to end"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 26,
             "being asked for is the one the caller does not have yet"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 30,
             "Asking is not receiving"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 32,
             "caller learns what it holds by using it"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 38,
             "apphost.ErrRegistrationDeclined"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 49,
             "The query carries no arguments; req travels"),
            (reference.ASTRAL_GO, "api/apphost/client/register.go", 50,
             "on the channel as one object, even when it is empty"),
            (reference.ASTRAL_GO, "api/policy/delegate.go", 14,
             "MaxTimeout bounds one admission question"),
            (reference.ASTRAL_GO, "api/policy/delegate.go", 16,
             "MaxTimeout = 10 * time.Minute"),
            (reference.ASTRALD, "mod/objects/src/module.go", 237,
             "func (mod *Module) GetBlueprint(typeName string)"),
            (reference.ASTRALD, "mod/objects/src/module.go", 254, "astral.BlueprintOf(proto)"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 192,
             'refuseRemovedArgs(queryString, "name", "grant_permits", "contract_permits")'),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 196,
             "var req *apphostapi.RegisterRequest"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 199, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 47,
             "identities minted over a link"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 49, "NewErrOriginNotAllowed"),
            (reference.ASTRALD, "mod/apphost/src/op_register.go", 50, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 41,
             '"identity", "action", "duration", "constrained"'),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 45,
             "var req *apphostapi.GrantRequest"),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 48, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 50, "switch {"),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 54, 'NewError("missing permits")'),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 56, 'NewError("negative duration")'),
            (reference.ASTRALD, "mod/apphost/src/op_grant.go", 57, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 79,
             'refuseRemovedArgs(queryString, "permits")'),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 83,
             "var req *apphostapi.RequestGrantRequest"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 86, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 87, "switch {"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 89, '"missing permits"'),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 91, '"negative duration"'),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 92, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 35,
             "why: a grant authorizes on this node alone"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 37, "OriginNetwork"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 43,
             "auth.ErrNotPermitted"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 44, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 56, "switch {"),
            (reference.ASTRALD, "mod/apphost/src/op_request_grant.go", 63, "}"),
            (reference.ASTRALD, "mod/apphost/src/validate_permits.go", 10,
             "validatePermits runs auth.ValidatePermit on every permit"),
            (reference.ASTRALD, "mod/apphost/src/validate_permits.go", 16,
             "func validatePermits"),
            (reference.ASTRALD, "mod/apphost/src/validate_permits.go", 25,
             "refuseRemovedArgs returns an error"),
            (reference.ASTRALD, "mod/apphost/src/validate_permits.go", 31,
             "func refuseRemovedArgs"),
            (reference.ASTRALD, "mod/apphost/src/register_policy.go", 64,
             "GetGrantRequestPolicy returns the policy apphost.request_grant applies"),
            (reference.ASTRALD, "mod/apphost/src/register_policy.go", 74,
             "apphostmod.GrantRequestAcceptAll"),
            (reference.ASTRALD, "mod/apphost/src/register_policy.go", 77,
             "return apphostmod.RefuseAllGrants"),
            (reference.ASTRALD, "mod/apphost/src/register_policy.go", 78, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 15,
             "OpListGrants lists the node-local grants"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 16,
             "mod.apphost.grant per grant"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 17,
             "carries no expiry"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 19,
             "the listing drops an expired grant"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 20,
             "answers what authorizes now"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 50,
             "for _, grant := range grants"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 51, "ch.Send(grant)"),
            (reference.ASTRALD, "mod/apphost/src/op_list_grants.go", 56, "astral.EOS{}"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 13, "type opRevokeArgs struct"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 16, "ID astral.Uint64"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 18, "Action astral.String8"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 20, "}"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 49, "switch {"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 56,
             "grant IDs start at 1, so a zero ID is an absent argument"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 57, "if args.ID != 0"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 63, "gorm.ErrRecordNotFound"),
            (reference.ASTRALD, "mod/apphost/src/op_revoke.go", 64, 'NewError("grant not found")'),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)

    def test_the_error_texts_are_the_node_s(self):
        self.assertEqual(ERR_GRANT_DECLINED, "grant declined")
        self.assertEqual(ERR_GRANT_NOT_FOUND, "grant not found")


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


def read_one_then(*replies: tuple[str, bytes]):  # type: ignore[no-untyped-def]
    """astrald's WA apphost ops: accept, read the one request object, answer,
    then read to EOF so every frame the client sent is recorded.

    A canned `Accept` answers and closes before the client writes its object,
    and the input is dropped.
    """

    async def handler(conn, query) -> None:  # type: ignore[no-untyped-def]
        conn.send_raw(frame("mod.apphost.query_accepted_msg"))
        await conn.flush()
        await conn.recv_frame_or_none()
        for reply in replies:
            conn.send_frame(*reply)
        await conn.flush()
        if replies:
            while await conn.recv_frame_or_none() is not None:
                pass
        await conn.aclose()

    return handler


def go_payload(name: str) -> bytes:
    """A `GRANT_GO_VECTORS` payload: astral-go's bytes, not the SDK's."""
    return bytes.fromhex(GRANT_GO_VECTORS[name][1])


def body(mock: MockApphost) -> list[tuple[str, bytes]]:
    """The frames the mock received after the session handshake."""
    received = mock.connections[-1].received
    for index, (type_name, _) in enumerate(received):
        if type_name == "mod.apphost.route_query_msg":
            return received[index + 1 :]
    return []


class GrantTest(ApphostCase):
    """`apphost.grant`: WA, one `mod.apphost.grant_request` in, one `ack` out."""

    async def grant(self, *args: object, **kw: object) -> MockApphost:
        async with MockApphost(routes={OP_GRANT: read_one_then(ACK_FRAME)}) as mock:
            api = await self.apphost(mock)
            self.assertIsNone(await api.grant(*args, **kw))
        return mock

    @bounded()
    async def test_the_request_is_the_one_object_on_the_body(self):
        """The query is the bare op name; identity, duration and permits all
        travel in the object, byte for byte what astral-go writes. The handler
        reads to EOF, so a second frame or an `eos` would show here."""
        mock = await self.grant(
            ID_HEX, [DISCOVERY_PERMIT, GRANT.action], duration=dt.timedelta(hours=1)
        )
        self.assertEqual(mock.queries[-1].query, OP_GRANT)
        self.assertEqual(body(mock), [("mod.apphost.grant_request", go_payload("grant_request_full"))])

    @bounded()
    async def test_no_duration_is_zero_which_is_until_revoked(self):
        mock = await self.grant(FURRY_BOLT, [GRANT])
        (type_name, payload), = body(mock)
        request = GrantRequest.read_payload(object_reader(payload))
        self.assertEqual(request.duration, Duration(0))
        self.assertEqual(request.identity, FURRY_BOLT)
        self.assertEqual(request.permits, [GRANT])

    @bounded()
    async def test_a_directory_name_costs_one_resolve_then_the_op(self):
        async with MockApphost(
            routes={
                "dir.resolve?identity=furry-bolt": Accept(objects=(IDENTITY_FRAME,)),
                OP_GRANT: read_one_then(ACK_FRAME),
            }
        ) as mock:
            api = await self.apphost(mock)
            await api.grant("furry-bolt", [GRANT])
        self.assertEqual(
            [q.query for q in mock.queries], ["dir.resolve?identity=furry-bolt", OP_GRANT]
        )
        request = GrantRequest.read_payload(object_reader(body(mock)[0][1]))
        self.assertEqual(request.identity, FURRY_BOLT)

    @bounded()
    async def test_a_malformed_permit_list_never_reaches_the_node(self):
        async with MockApphost(routes={OP_GRANT: read_one_then(ACK_FRAME)}) as mock:
            api = await self.apphost(mock)
            for permits, error in (
                ([], BadArgument),
                ([""], BadArgument),
                (["x" * 256], BadArgument),
                (GRANT.action, BadArgumentType),
                (GRANT, BadArgumentType),
                ([1], BadArgumentType),
                ([None], BadArgumentType),
            ):
                with self.subTest(permits=permits):
                    with self.assertRaises(error):
                        await api.grant(ID_HEX, permits)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_answer_that_ends_before_the_ack_is_a_protocol_error(self):
        """A stream that ends before the `ack` recorded nothing the caller can
        rely on; it is not a success."""
        async with MockApphost(routes={OP_GRANT: read_one_then()}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.grant(ID_HEX, [GRANT])

    @bounded()
    async def test_a_refusal_is_a_remote_error(self):
        """The op accepts, then answers a caller without the action with
        `not permitted` (`op_grant.go:38-40`), and an invalid permit with
        `invalid permit: <action>: <detail>`."""
        for answer in (
            "not permitted",
            "invalid permit: mod.services.service_discovery_action: "
            "constraints must hold exactly one discovery scope",
        ):
            with self.subTest(answer=answer):
                async with MockApphost(
                    routes={OP_GRANT: read_one_then(error_frame(answer))}
                ) as mock:
                    api = await self.apphost(mock)
                    with self.assertRaises(RemoteError) as caught:
                        await api.grant(ID_HEX, [GRANT])
                self.assertEqual(caught.exception.message, answer)

    @bounded()
    async def test_the_old_arguments_are_gone(self):
        """No `action` positional, no `constraints` keyword: a single action
        name in the permits slot is a bare `str`, refused as a list."""
        async with MockApphost(routes={}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(TypeError):
                await api.grant(ID_HEX, [GRANT], constraints=Bundle([]))  # type: ignore[call-arg]
            with self.assertRaises(BadArgumentType):
                await api.grant(ID_HEX, GRANT.action)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])


class RequestGrantTest(ApphostCase):
    """`apphost.request_grant`: WA, one `mod.apphost.request_grant_request` in,
    one `ack` out, and a decline that is an `error_message`."""

    @bounded()
    async def test_the_request_is_the_one_object_on_the_body(self):
        async with MockApphost(
            routes={OP_REQUEST_GRANT: read_one_then(ACK_FRAME)}
        ) as mock:
            api = await self.apphost(mock)
            self.assertIsNone(
                await api.request_grant([DISCOVERY_PERMIT], duration=Duration(3600 * 10**9))
            )
        self.assertEqual(mock.queries[-1].query, OP_REQUEST_GRANT)
        self.assertEqual(
            body(mock),
            [("mod.apphost.request_grant_request", go_payload("request_grant_request_full"))],
        )

    @bounded()
    async def test_a_decline_and_an_origin_refusal_are_remote_errors(self):
        for answer in (ERR_GRANT_DECLINED, "origin not allowed: network", "not permitted"):
            with self.subTest(answer=answer):
                async with MockApphost(
                    routes={OP_REQUEST_GRANT: read_one_then(error_frame(answer))}
                ) as mock:
                    api = await self.apphost(mock)
                    with self.assertRaises(RemoteError) as caught:
                        await api.request_grant([GRANT])
                self.assertEqual(caught.exception.message, answer)

    @bounded()
    async def test_an_empty_permit_list_is_refused_locally(self):
        async with MockApphost(routes={}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(BadArgument):
                await api.request_grant([])
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_the_default_timeout_waits_for_a_person(self):
        """A delegate may wait on a person for up to ten minutes; the client's
        60 s default would give up first, and 610 s outlasts the node's bound
        so the node's decline arrives before the client gives up."""
        async with MockApphost(
            routes={OP_REQUEST_GRANT: read_one_then(ACK_FRAME)}
        ) as mock:
            api = await self.apphost(mock)
            seen: list[object] = []
            real = api._c.call_with

            async def spy(*args: object, **kw: object) -> object:
                seen.append(kw.get("timeout"))
                return await real(*args, **kw)

            api._c.call_with = spy  # type: ignore[method-assign]
            await api.request_grant([GRANT])
            await api.request_grant([GRANT], timeout=5.0)
        self.assertEqual(seen, [610.0, 5.0])

    @bounded()
    async def test_an_explicit_timeout_bounds_a_silent_policy(self):
        async with MockApphost(routes={OP_REQUEST_GRANT: Accept(hold=True)}) as mock:
            api = await self.apphost(mock)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout):
                await api.request_grant([GRANT], timeout=0.2)
            self.assertLess(loop.time() - started, 1.5)


class ListGrantsTest(ApphostCase):
    """`apphost.list_grants`: ST, `mod.apphost.grant` objects, then `eos`."""

    @bounded()
    async def test_the_grants_decode_with_their_ids(self):
        frames = (
            ("mod.apphost.grant", go_payload("grant_full")),
            ("mod.apphost.grant", go_payload("grant_until_revoked")),
        )
        async with MockApphost(
            routes={OP_LIST_GRANTS: Accept(objects=frames, eos=True)}
        ) as mock:
            api = await self.apphost(mock)
            grants = await api.list_grants(ID_HEX)
        self.assertEqual(mock.queries[-1].query, f"{OP_LIST_GRANTS}?identity={ID_HEX}")
        self.assertEqual([g.id for g in grants], [7, 8])
        self.assertEqual(grants[0].permit, DISCOVERY_PERMIT)
        self.assertEqual(grants[0].expires_at, EXPIRES)
        self.assertIsNone(grants[1].expires_at)

    @bounded()
    async def test_a_directory_name_costs_one_resolve_then_the_op(self):
        async with MockApphost(
            routes={
                "dir.resolve?identity=furry-bolt": Accept(objects=(IDENTITY_FRAME,)),
                OP_LIST_GRANTS: Accept(eos=True),
            }
        ) as mock:
            api = await self.apphost(mock)
            self.assertEqual(await api.list_grants("furry-bolt"), [])
        self.assertEqual(
            [q.query for q in mock.queries],
            ["dir.resolve?identity=furry-bolt", f"{OP_LIST_GRANTS}?identity={ID_HEX}"],
        )

    @bounded()
    async def test_a_bare_permit_is_a_protocol_error(self):
        """A node that answers bare `mod.auth.permit` objects here, as astrald
        did before the grant object, is the remote breaking the op's
        contract; the client declares `mod.apphost.grant`."""
        permit = (
            "mod.auth.permit",
            bytes([len(GRANT.action)]) + GRANT.action.encode() + b"\x00\x00",
        )
        async with MockApphost(
            routes={OP_LIST_GRANTS: Accept(objects=(permit,), eos=True)}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.list_grants(ID_HEX)

    @bounded()
    async def test_a_refusal_is_a_remote_error(self):
        async with MockApphost(
            routes={OP_LIST_GRANTS: Accept(objects=(error_frame("not permitted"),))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError):
                await api.list_grants(ID_HEX)


class RevokeTest(ApphostCase):
    """`apphost.revoke`: RR, one `ack`; `id` or `action`, never both."""

    async def revoke(self, **kw: object) -> str:
        async with MockApphost(routes={OP_REVOKE: Accept(objects=(ACK_FRAME,))}) as mock:
            api = await self.apphost(mock)
            self.assertIsNone(await api.revoke(ID_HEX, **kw))
        return mock.queries[-1].query

    @bounded()
    async def test_an_id_names_one_grant(self):
        self.assertEqual(await self.revoke(id=3), f"{OP_REVOKE}?id=3&identity={ID_HEX}")

    @bounded()
    async def test_an_action_names_every_grant_for_it(self):
        self.assertEqual(
            await self.revoke(action=GRANT.action),
            f"{OP_REVOKE}?action={GRANT.action}&identity={ID_HEX}",
        )

    @bounded()
    async def test_both_or_neither_never_reaches_the_node(self):
        async with MockApphost(routes={OP_REVOKE: Accept()}) as mock:
            api = await self.apphost(mock)
            for kw, error in (
                ({}, BadArgument),
                ({"id": 1, "action": GRANT.action}, BadArgument),
                ({"id": -1}, BadArgument),
                ({"id": 0}, BadArgument),
                ({"id": 1 << 64}, BadArgument),
                ({"id": True}, BadArgumentType),
                ({"id": "3"}, BadArgumentType),
                ({"action": ""}, BadArgument),
                ({"action": "x" * 256}, BadArgument),
                ({"action": b"x"}, BadArgumentType),
            ):
                with self.subTest(kw=kw):
                    with self.assertRaises(error):
                        await api.revoke(ID_HEX, **kw)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_grant_the_node_does_not_find_is_a_remote_error(self):
        async with MockApphost(
            routes={OP_REVOKE: Accept(objects=(error_frame(ERR_GRANT_NOT_FOUND),))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.revoke(ID_HEX, id=9)
        self.assertEqual(caught.exception.message, "grant not found")


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
    async def test_an_argument_error_reaches_the_caller_as_a_remote_error(self):
        """An unparseable parameter fails astral-go's argument binding before
        the op runs, and an op that takes `out` accepts and answers the error
        as an `error_message` (`lib/routing/op.go` `Op.invoke`), so this
        arrives as `RemoteError`, not as `query_rejected_msg`."""
        async with MockApphost(
            routes={
                OP_CREATE_TOKEN: Accept(
                    objects=(error_frame("invalid argument: duration: bad"),)
                )
            }
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError):
                await api.create_token(ID_HEX)

    @bounded()
    async def test_a_refused_token_op_is_a_remote_error(self):
        """Both token ops accept, then answer a caller off a link and a caller
        without the action inside the stream (`op_list_tokens.go:24-32`,
        `op_create_token.go:21-27`)."""
        for op, answer in (
            (OP_LIST_TOKENS, "not permitted"),
            (OP_CREATE_TOKEN, "not permitted"),
            (OP_LIST_TOKENS, "origin not allowed: network"),
            (OP_CREATE_TOKEN, "origin not allowed: network"),
        ):
            with self.subTest(op=op, answer=answer):
                async with MockApphost(
                    routes={op: Accept(objects=(error_frame(answer),))}
                ) as mock:
                    api = await self.apphost(mock)
                    with self.assertRaises(RemoteError) as caught:
                        if op == OP_LIST_TOKENS:
                            await api.list_tokens()
                        else:
                            await api.create_token(ID_HEX)
                self.assertEqual(caught.exception.message, answer)


class RegisterTest(ApphostCase):
    """`apphost.register`: WA, one `mod.apphost.register_request` in, one
    `apphost.access_token` out, and a decline that is an `error_message`
    rather than a reject."""

    async def register(self, **kw: object) -> tuple[AccessToken, MockApphost]:
        async with MockApphost(
            routes={OP_REGISTER: read_one_then(TOKEN_FRAME)}
        ) as mock:
            api = await self.apphost(mock)
            token = await api.register(**kw)
        return token, mock

    @bounded()
    async def test_no_arguments_send_one_zero_request_and_answer_a_token(self):
        """The bootstrap an app with no credentials starts from. The object
        travels even when empty, as astral-go's client sends it."""
        token, mock = await self.register()
        self.assertEqual(token.token, TOKEN)
        self.assertEqual(mock.queries[-1].query, OP_REGISTER)
        self.assertEqual(
            body(mock), [("mod.apphost.register_request", go_payload("register_request_zero"))]
        )

    @bounded()
    async def test_the_name_and_both_lists_travel_in_the_object(self):
        """Byte for byte astral-go's request: the discovery permit keeps its
        scope and the contract permit its delegation."""
        _, mock = await self.register(
            name="smithd",
            grant_permits=[DISCOVERY_PERMIT],
            contract_permits=(p for p in [CONTRACT_PERMIT]),
        )
        self.assertEqual(mock.queries[-1].query, OP_REGISTER)
        self.assertEqual(
            body(mock), [("mod.apphost.register_request", go_payload("register_request_full"))]
        )

    @bounded()
    async def test_an_action_name_becomes_an_unconstrained_permit(self):
        _, mock = await self.register(grant_permits=["mod.user.see_swarm_action"])
        request = RegisterRequest.read_payload(object_reader(body(mock)[0][1]))
        self.assertEqual(request.grant_permits, [Permit(action="mod.user.see_swarm_action")])
        self.assertEqual(request.contract_permits, [])
        self.assertEqual(request.name, "")

    @bounded()
    async def test_the_longest_names_are_sent_and_one_byte_more_is_not(self):
        action = "é" * 127 + "x"  # 255 UTF-8 bytes
        _, mock = await self.register(name="n" * 255, grant_permits=[action])
        request = RegisterRequest.read_payload(object_reader(body(mock)[0][1]))
        self.assertEqual(request.name, "n" * 255)
        self.assertEqual(request.grant_permits, [Permit(action=action)])
        with self.assertRaises(BadArgument):
            await self.register(name="n" * 256)
        with self.assertRaises(BadArgument):
            await self.register(contract_permits=["é" * 128])

    @bounded()
    async def test_a_malformed_argument_never_reaches_the_node(self):
        """A bare `str` would iterate its characters into single-letter
        actions; the lists are keyword-only, so positional ones are refused."""
        async with MockApphost(routes={OP_REGISTER: read_one_then()}) as mock:
            api = await self.apphost(mock)
            for key in ("grant_permits", "contract_permits"):
                for value, error in (
                    ("mod.user.see_swarm_action", BadArgumentType),
                    (b"x", BadArgumentType),
                    (GRANT, BadArgumentType),
                    ([1], BadArgumentType),
                    ([None], BadArgumentType),
                    ([""], BadArgument),
                ):
                    with self.subTest(key=key, value=value):
                        with self.assertRaises(error) as caught:
                            await api.register(**{key: value})
                        self.assertIn(key, str(caught.exception))
            with self.assertRaises(BadArgumentType):
                await api.register(name=b"chat")  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                await api.register(["mod.user.see_swarm_action"])  # type: ignore[misc]
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_declined_registration_is_a_remote_error(self):
        """The node accepts before its policy decides, so a refusal is an
        `error_message` in the stream, not `query_rejected_msg`."""
        async with MockApphost(
            routes={OP_REGISTER: read_one_then(error_frame(ERR_REGISTRATION_DECLINED))}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.register(grant_permits=["mod.user.see_swarm_action"])
        self.assertEqual(caught.exception.message, "registration declined")
        self.assertEqual(ERR_REGISTRATION_DECLINED, "registration declined")

    @bounded()
    async def test_an_answer_of_the_wrong_type_or_none_is_a_protocol_error(self):
        for route in (read_one_then(ACK_FRAME), read_one_then()):
            with self.subTest(route=route):
                async with MockApphost(routes={OP_REGISTER: route}) as mock:
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
    async def test_an_unauthorized_caller_is_a_remote_error(self):
        """The op accepts, then answers a caller without the action with
        `not permitted` (`op_set_app_register_policy.go:53-58`)."""
        async with MockApphost(
            routes={
                OP_SET_APP_REGISTER_POLICY: Accept(objects=(error_frame("not permitted"),))
            }
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.set_app_register_policy()
        self.assertEqual(caught.exception.message, "not permitted")

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
    """The three read-only ops, against a real node, as the node's own token.

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
        """An authenticated session's nil `Caller` is its guest identity
        (`mod/apphost/src/guest.go:154-158`), and a token-less client's nil
        caller is the node's identity (`core/router.go:45-46`), on the ops
        `anonymous_allowlist` admits. So the answer is the guest identity for an
        authenticated client and the greeting's identity otherwise, and the
        assertion follows whichever this client is."""
        async with await self.client() as client:
            who = await Apphost(client).whoami()
            self.assertIsInstance(who, Identity)
            expected = client.guest_id if client.authenticated else client.host_id
            self.assertEqual(who, expected)
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_list_tokens_decodes_every_token_the_node_holds(self):
        """The record against the node's own bytes. Also the live confirmation
        that the node's own token reads the whole table, token strings
        included, which is why an `AccessToken` that arrives here is a
        secret."""
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
    CURRENT_UNGUARDED = {"whoami", "set_app_register_policy"}

    def ops(self) -> dict[str, str]:
        """Every `op_*.go` at the pin, name to source.

        `_test.go` is excluded, and that is not cosmetic: `op_grants_test.go`
        and three other `op_*_test.go` files sit beside the ops at the pin, and
        counting them makes the census larger than the op set.
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

        self.assertEqual(len(ops), 17)
        self.assertEqual(set(ops) - guarded, self.CURRENT_UNGUARDED)
        self.assertEqual(len(guarded), 15)

        # Unwrapped, because a line break inside a sentence is a formatting
        # choice and the claim is the sentence.
        doc = " ".join((apphost_module.__doc__ or "").split())
        self.assertNotIn("alone among its neighbours", doc)
        self.assertIn(f"re-derived at `{reference.PINS[reference.ASTRALD][1]}`", doc)
        self.assertIn("Seventeen `op_*.go` files.", doc)
        self.assertIn("Fifteen refuse a network origin", doc)
        self.assertIn(
            "the two that do not are `whoami` and `set_app_register_policy`", doc
        )
        self.assertIn("OpSetGrantRequestPolicy", ops["set_app_register_policy"])

    def test_the_token_ops_ask_admin_manage_apps_before_they_answer(self):
        """The action guard, per op.

        Every op accepts first and answers a refusal inside the channel, so the
        order that matters is the guards' among themselves and against the
        work: the origin before the action, and the action before the op
        resolves an identity, reads its request object or touches a store.
        Both setters in `op_set_app_register_policy.go` ask before
        `writePolicyDelegate` clears or writes a delegate.
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
                self.assertLess(src.index("q.Accept"), src.index("AdminManageAppsAction"))
                self.assertIn("return ch.Send(auth.ErrNotPermitted)", src)
                if name in self.TOKEN_AND_GRANT:
                    action = src.index("AdminManageAppsAction")
                    self.assertLess(src.index("OriginNetwork"), action)
                    work = [
                        src.index(marker, action)
                        for marker in (
                            "mod.Dir.ResolveIdentity",
                            "AccessToken",
                            "ch.Switch(",
                            "mod.grantAll(",
                        )
                        if marker in src[action:]
                    ]
                    self.assertTrue(work, "the op does no work the guard precedes")
                    self.assertLess(action, min(i for i in work if i > action))
                else:
                    register, grant = src.split(
                        "func (mod *Module) OpSetGrantRequestPolicy("
                    )
                    grant = grant.split("func (mod *Module) writePolicyDelegate(")[0]
                    for body in (register, grant):
                        self.assertLess(
                            body.index("AdminManageAppsAction"),
                            body.index("mod.writePolicyDelegate("),
                        )

        doc = apphost_module.__doc__ or ""
        self.assertIn("mod.auth.admin_manage_apps_action", doc)
        self.assertIn("mod.auth.serve_apps_action", doc)
        for name in ("list_tokens", "create_token", "delete_token"):
            with self.subTest(op=name):
                self.assertIn(name, doc)

    def test_a_tokenless_session_reaches_no_token_or_grant_op(self):
        """Why the action guard is the whole story for the token ops.

        The user module allows the node's own identity, the core router hands
        that identity to a caller who sent none, and apphost denies a
        token-less session every op outside `anonymous_allowlist` before it is
        routed. None of the admin-action ops is on either list, so the
        identity that passes is the one a token names.
        """
        try:
            user_auth = reference.read(
                reference.ASTRALD, "mod/user/src/authorize_user_or_node.go"
            )
            router = reference.read(reference.ASTRALD, "core/router.go")
            guard = reference.read(reference.ASTRALD, f"{self.SRC}/setup_guard.go")
            config = reference.read(reference.ASTRALD, f"{self.SRC}/config.go")
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

        self.assertIn("mod.node.Identity()", user_auth)
        self.assertIn("q.Caller = r.node.identity", router)
        self.assertIn("return slices.Contains(allowlist, opPath)", guard)
        allowlist = config.split("AnonymousAllowlist: AnonymousAllowlist{")[1]
        for name in sorted(self.ADMIN_MANAGE_APPS | self.SERVE_APPS):
            with self.subTest(op=name):
                self.assertNotIn(f'"apphost.{name}"', allowlist)

        doc = " ".join((apphost_module.__doc__ or "").split())
        self.assertIn("A session without a token reaches six ops and no others.", doc)
        self.assertIn("Whoever holds the node's token reads every access token", doc)

    def test_every_astrald_line_the_authorization_section_cites_lands(self):
        """`path:line` at the pin, each one read and matched against its claim.

        A citation that names the wrong line is a reader sent to the wrong
        place, which is the failure this whole file exists to make loud.
        """
        admin = "AdminManageAppsAction"
        cites = (
            (f"{self.SRC}/op_list_tokens.go", 24, "OriginNetwork"),
            (f"{self.SRC}/op_list_tokens.go", 30, admin),
            (f"{self.SRC}/op_create_token.go", 21, "OriginNetwork"),
            (f"{self.SRC}/op_create_token.go", 25, admin),
            (f"{self.SRC}/op_delete_token.go", 23, "OriginNetwork"),
            (f"{self.SRC}/op_delete_token.go", 27, admin),
            (f"{self.SRC}/op_cancel.go", 30, "OriginNetwork"),
            (f"{self.SRC}/op_cancel.go", 32, "}"),
            (f"{self.SRC}/op_cancel.go", 36, "answers as a missing one"),
            (f"{self.SRC}/op_cancel.go", 40, "}"),
            (f"{self.SRC}/op_cancel.go", 57, "func (mod *Module) mayCancel"),
            (f"{self.SRC}/op_register_handler.go", 33, "ServeAppsAction"),
            (f"{self.SRC}/authorize_admin_manage_apps.go", 19, "func (mod *Module) mayManageApps"),
            (f"{self.SRC}/authorize_admin_manage_apps.go", 24, "AdminManageAppsAction"),
            (f"{self.SRC}/guest.go", 150, "admitsAnonymous"),
            (f"{self.SRC}/guest.go", 156, "q.Caller.IsZero() && guest.isAuthenticated()"),
            (f"{self.SRC}/guest.go", 157, "q.Caller = guest.guestID"),
            (f"{self.SRC}/guest.go", 271, "isAuthenticated()"),
            (f"{self.SRC}/config.go", 55, "AnonymousAllowlist: AnonymousAllowlist{"),
            (f"{self.SRC}/config.go", 69, "},"),
            ("mod/user/src/authorize_user_or_node.go", 12, "anonymous_allowlist"),
            ("mod/user/src/authorize_user_or_node.go", 13, "node-local grant or a signed contract"),
            ("mod/user/src/authorize_user_or_node.go", 17, "authorizeUserOrNode"),
            ("mod/user/src/authorize_user_or_node.go", 21, "mod.node.Identity()"),
            ("mod/user/src/authorize_serve_apps.go", 15, "AuthorizeServeApps"),
            ("core/router.go", 45, "q.Caller == nil"),
            ("core/router.go", 46, "q.Caller = r.node.identity"),
            (f"{self.SRC}/op_hosts.go", 29, "OriginNetwork"),
            (f"{self.SRC}/op_hosts.go", 35, "SeeSwarmAction"),
            (f"{self.SRC}/op_hosts.go", 48, "RelayForAction"),
            (f"{self.SRC}/op_hold_object.go", 36, "StoreObjectsAction"),
            (f"{self.SRC}/op_hold_object.go", 37, "auth.ErrNotPermitted"),
            (f"{self.SRC}/op_request_grant.go", 42, "requester.IsZero()"),
            (f"{self.SRC}/op_request_grant.go", 62, "ErrGrantDeclined"),
            (f"{self.SRC}/op_grant.go", 28, "q.AcceptRaw()"),
            (f"{self.SRC}/op_grant.go", 33, "OriginNetwork"),
            (f"{self.SRC}/op_grant.go", 37, admin),
            (f"{self.SRC}/op_grant.go", 39, "}"),
            (f"{self.SRC}/op_grant.go", 51, "req.Identity.IsZero()"),
            (f"{self.SRC}/op_grant.go", 52, 'NewError("missing identity")'),
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
    the pins."""

    SRC = "mod/apphost/src"

    def test_every_anchor_lands_on_its_claim(self):
        cites = (
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 17, "RegisterDuration = 10 * 365"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 63, "switch {"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 66, "ErrRegistrationDeclined"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 74, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 116, "Add(RegisterDuration)"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 166, "CreateAccessToken(guestID"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 15,
             "type opSetPolicyArgs struct"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 25, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 46, "q.AcceptRaw()"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 49,
             "AdminManageAppsAction"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 50,
             "auth.ErrNotPermitted"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 51, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 122,
             'identity == "" && op == ""'),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 124, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 126, "mod.newDelegate("),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 129, "}"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 136,
             "func (mod *Module) newDelegate"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 146, "d.Validate()"),
            (reference.ASTRALD, f"{self.SRC}/op_set_app_register_policy.go", 147, "}"),
            (reference.ASTRALD, f"{self.SRC}/register_grant_request.go", 17,
             "func registerGrantRequest"),
            (reference.ASTRALD, f"{self.SRC}/register_grant_request.go", 20,
             "append([]*auth.Permit{serveApps, useBlueprints}, asked...)"),
            (reference.ASTRALD, f"{self.SRC}/op_register.go", 211,
             "ContractPermits: req.ContractPermits"),
            (reference.ASTRALD, "mod/apphost/register_policy.go", 29, "func AcceptAll"),
            (reference.ASTRAL_GO, "api/apphost/errors.go", 7,
             'NewError("registration declined")'),
            (reference.ASTRAL_GO, "astral/string_types.go", 25, "if len(s) > 1<<8-1"),
        )
        for repo, path, number, fragment in cites:
            with self.subTest(citation=f"{path}:{number}"):
                try:
                    line = reference.cited_line(repo, path, number)
                except reference.Unavailable as exc:  # pragma: no cover
                    self.skipTest(str(exc))
                self.assertIn(fragment, line)


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
            mod._REVOKE,
            {
                "identity": Primitive("string8"),
                "id": Primitive("uint64"),
                "action": Primitive("string8"),
            },
        )
        # The comma-list encoding and the query-argument grant are gone.
        for name in ("_REGISTER", "_GRANT", "_permits"):
            self.assertFalse(hasattr(mod, name), name)

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
