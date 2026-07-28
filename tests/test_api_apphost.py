"""The `apphost` module client, its two data types, and the eager-import rule.

Three tiers in one file, because they assert three different things about the
same thirteen ops:

- **Tier A** pins the wire: `apphost.access_token` byte for byte, the missing
  `mod.` prefix that would make every token frame undecodable, and the registry
  contents -- including the one type that must *not* be there.
- **Tier B** pins the query strings and the shapes against `MockApphost`. A
  module client is argument marshalling plus one call, so the marshalling is
  what can be wrong: a capitalised key is silently dropped by the node, an
  omitted parameter and an empty one are different things, and an op's mode is a
  declaration that a test has to make as well.
- **Tier C** asks the node, and only through the three read-only anonymous-safe
  ops. Skipped with a reason when `ASTRAL_TEST_ENDPOINT` is unset.

The assertion that is not about apphost at all: **importing `astral.api` imports
every module in the package.** Wire-type registration is a side effect of import,
so a module that this package's `__init__` forgets is a type that decodes in one
program and raises `BlueprintNotFound` in another. The test walks the directory
rather than a list, so it fails for a module that has not been added yet.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import pathlib
import sys
import unittest

import astral
from astral.api import apphost as apphost_module
from astral.api.apphost import (
    OP_BIND,
    OP_CANCEL,
    OP_CREATE_TOKEN,
    OP_HOLD_OBJECT,
    OP_INSTALL_APP,
    OP_LIST_HELD_OBJECTS,
    OP_LIST_TOKENS,
    OP_NEW_APP_CONTRACT,
    OP_REGISTER,
    OP_REGISTER_HANDLER,
    OP_SIGN_APP_CONTRACT,
    OP_UNHOLD_OBJECT,
    OP_WHOAMI,
    AccessToken,
    App,
    APPHOST_TYPES,
    Apphost,
    _duration,
    _object_id,
    apphost_types,
)
from astral.client import Client, connect
from astral.codec import decode, encode
from astral.errors import (
    BadArgumentType,
    ProtocolError,
    QueryRejected,
    QueryTimeout,
    RemoteError,
)
from astral.object import Ack
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Primitive
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


class AppTest(unittest.TestCase):
    def test_the_app_record_round_trips(self):
        app = App(app_id=FURRY_BOLT, host_id=None, installed_at=Time(7))
        self.assertEqual(decode(encode(app)), app)
        payload = encode(app)[len("mod.apphost.app") + 1 :]
        self.assertEqual(payload, b"\x01" + FURRY_BOLT.key + b"\x00" + (7).to_bytes(8, "big"))


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
        """An empty `id=` and an absent `id` are different things: the node reads
        the first as the zero identity and filters nothing either way, but a
        parameter the caller did not set must never be invented."""
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
        self.assertEqual(mock.queries[-1].query, f"{OP_LIST_TOKENS}?id={ID_HEX}")

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
            f"{OP_CREATE_TOKEN}?duration=8760h0m0s&id={ID_HEX}",
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
        self.assertEqual(mock.queries[-1].query, f"{OP_CREATE_TOKEN}?id={ID_HEX}")

    @bounded()
    async def test_a_rejected_query_reaches_the_caller_as_a_rejection(self):
        """An unparseable parameter is rejected before the op runs -- astrald's
        arg binding fails and the deferred reject fires -- so this arrives as
        `query_rejected_msg`, not as an `error_message` in a stream."""
        async with MockApphost(routes={OP_CREATE_TOKEN: Reject(code=1)}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(QueryRejected):
                await api.create_token(ID_HEX)

    @bounded()
    async def test_register_takes_no_arguments_and_answers_a_token(self):
        """The bootstrap an app with no credentials starts from: the node makes
        the key, the contract and the token."""
        token_frame = ("apphost.access_token", access_token_payload())
        async with MockApphost(
            routes={OP_REGISTER: Accept(objects=(token_frame,))}
        ) as mock:
            api = await self.apphost(mock)
            token = await api.register()
        self.assertEqual(token.token, TOKEN)
        self.assertEqual(mock.queries[-1].query, OP_REGISTER)

    @bounded()
    async def test_register_declines_are_rejections_not_error_messages(self):
        """A node whose register policy says no rejects the query; nothing is
        accepted and there is no stream to read."""
        async with MockApphost(routes={OP_REGISTER: Reject(code=1)}) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(QueryRejected):
                await api.register()

    @bounded()
    async def test_new_app_contract_sends_id_and_duration_and_returns_the_object(self):
        """The answer is a `mod.auth.contract`, which `astral.api.auth` declares;
        this module neither decodes nor inspects it, so the assertion is that
        whatever the stream carried is what comes back."""
        async with MockApphost(
            routes={OP_NEW_APP_CONTRACT: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            answer = await api.new_app_contract(ID_HEX, duration=Duration(10**9))
        self.assertEqual(answer, FURRY_BOLT)
        self.assertEqual(
            mock.queries[-1].query, f"{OP_NEW_APP_CONTRACT}?duration=1s&id={ID_HEX}"
        )

    @bounded()
    async def test_install_app_sends_the_same_arguments(self):
        async with MockApphost(
            routes={OP_INSTALL_APP: Accept(objects=(IDENTITY_FRAME,))}
        ) as mock:
            api = await self.apphost(mock)
            await api.install_app(ID_HEX)
        self.assertEqual(mock.queries[-1].query, f"{OP_INSTALL_APP}?id={ID_HEX}")

    @bounded()
    async def test_sign_app_contract_puts_the_contract_on_the_channel_body(self):
        """The confirmed way to get a body-input op wrong is passing the input as
        a query argument. Here the query string carries no parameter at all and
        the object is written onto the accepted stream."""
        async with MockApphost(
            routes={OP_SIGN_APP_CONTRACT: Accept(echo=True)}
        ) as mock:
            api = await self.apphost(mock)
            answer = await api.sign_app_contract(Ack())
        self.assertIsInstance(answer, Ack)
        self.assertEqual(mock.queries[-1].query, OP_SIGN_APP_CONTRACT)

    @bounded()
    async def test_sign_app_contract_reports_a_stream_that_answered_nothing(self):
        async with MockApphost(
            routes={OP_SIGN_APP_CONTRACT: Accept()}
        ) as mock:
            api = await self.apphost(mock)
            with self.assertRaises(ProtocolError):
                await api.sign_app_contract(Ack())


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
            mock.queries[-1].query, f"{OP_CANCEL}?id=1122334455667788"
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
            mock.queries[-1].query, f"{OP_CANCEL}?cause=user+quit&id=0000000000000001"
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
        """The `id` parameter reaches the node and filters server-side.

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
        locally, travel, and are refused by the node's argument binding *before*
        the op runs -- which surfaces as `query_rejected_msg{1}`, not as an
        empty result and not as an `error_message`.
        """
        off_curve = Identity.parse("02" + "11" * 32)  # accepted here, refused there
        async with await self.client() as client:
            with self.assertRaises(QueryRejected):
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
            OP_NEW_APP_CONTRACT: lambda a: a.new_app_contract("furry-bolt"),
            OP_INSTALL_APP: lambda a: a.install_app("furry-bolt"),
        }
        answer = {
            OP_LIST_TOKENS: Accept(objects=(TOKEN_FRAME,), eos=True),
            OP_CREATE_TOKEN: Accept(objects=(TOKEN_FRAME,)),
            OP_NEW_APP_CONTRACT: Accept(objects=(ACK_FRAME,)),
            OP_INSTALL_APP: Accept(objects=(ACK_FRAME,)),
        }
        for op, run in cases.items():
            with self.subTest(op=op):
                async with MockApphost(
                    routes={
                        "dir.resolve?name=furry-bolt": Accept(objects=(IDENTITY_FRAME,)),
                        op: answer[op],
                    }
                ) as mock:
                    api = await self.apphost(mock)
                    await run(api)
                self.assertEqual(
                    [q.query for q in mock.queries],
                    ["dir.resolve?name=furry-bolt", f"{op}?id={ID_HEX}"],
                )

    @bounded()
    async def test_the_resolve_leg_runs_inside_the_callers_timeout(self):
        """`timeout` sat unused in `**kw` and was applied only to the second
        query, so the leg the caller cannot see was bounded by the client's own
        60 s default."""
        async with MockApphost(
            routes={"dir.resolve?name=furry-bolt": Accept(hold=True)}
        ) as mock:
            api = await self.apphost(mock, query_timeout=30.0)
            loop = asyncio.get_running_loop()
            started = loop.time()
            with self.assertRaises(QueryTimeout):
                await api.list_tokens("furry-bolt", timeout=0.2)
            self.assertLess(loop.time() - started, 1.0)


class SecurityNoteTest(unittest.TestCase):
    """The origin-guard census this module's docstring states, counted.

    The note used to say `list_tokens` was "alone among its neighbours" in
    carrying no network-origin guard. Seven of the thirteen ops carry none, and
    the note was therefore false in the direction of **understating** the
    exposure: a reader takes "alone" to mean the other twelve are guarded. A
    security note that is wrong that way is worse than no note.
    """

    SRC = "mod/apphost/src"

    GUARDED = {
        "bind",
        "hold_object",
        "unhold_object",
        "list_held_objects",
        "register_handler",
        "install_app",
    }
    UNGUARDED = {
        "whoami",
        "list_tokens",
        "create_token",
        "register",
        "new_app_contract",
        "sign_app_contract",
        "cancel",
    }

    def ops(self) -> dict[str, str]:
        """Every `op_*.go` at the pin, name to source."""
        try:
            names = reference.listdir(reference.ASTRALD, self.SRC)
            return {
                name[len("op_") : -len(".go")]: reference.read(
                    reference.ASTRALD, f"{self.SRC}/{name}"
                )
                for name in names
                if name.startswith("op_") and name.endswith(".go")
            }
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

    def test_the_census_in_the_docstring_matches_the_node(self):
        """Read at the pinned revision, not out of the working tree.

        Globbing the checkout is what made this test fail on a sibling
        repository's pull: astrald moved to `3392926b`, gained a guarded
        `op_delete_token.go`, and the census went to seven -- for an op the
        running node does not serve and no SDK method drives. The census is a
        statement about the revision this module was read against, so it is read
        at that revision. Bumping the pin in `tests/reference.py` is what makes
        it a statement about a newer one, deliberately.
        """
        ops = self.ops()
        guarded = {name for name, src in ops.items() if "OriginNetwork" in src}
        self.assertEqual(guarded, self.GUARDED)
        self.assertEqual(set(ops) - guarded, self.UNGUARDED)

        doc = apphost_module.__doc__ or ""
        self.assertIn("six of the", doc)
        self.assertNotIn("alone among its neighbours", doc)
        for name in self.UNGUARDED:
            with self.subTest(op=name):
                self.assertIn(name, doc)

    def test_create_token_has_no_guard_and_no_authorization_check(self):
        """The sharper end of the same astrald defect: it *mints* a bearer token
        for any identity named in `id`, which is strictly worse than reading the
        ones that already exist."""
        source = self.ops()["create_token"]
        self.assertNotIn("OriginNetwork", source)
        self.assertIn("CreateAccessToken", source)
        self.assertIn("create_token", apphost_module.__doc__ or "")


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

        self.assertEqual(mod._IDENTITY_ID["id"], Primitive("identity"))
        self.assertEqual(mod._OBJECT_ID["id"], Primitive("object_id.sha256"))
        self.assertEqual(mod._CANCEL["id"], Primitive("nonce64"))

        # The declaration is what refuses a wrong-typed value. Without it the
        # encoder dispatches on the value and sends base64 for an identity.
        with self.assertRaises(astral.AstralError):
            mod._encode(mod._IDENTITY_ID, {"id": b"not an identity"})
        self.assertEqual(param_text(b"not an identity"), "bm90IGFuIGlkZW50aXR5")

        # And what the ops actually send is unchanged, byte for byte.
        self.assertEqual(
            mod._encode(mod._IDENTITY_ID, {"id": FURRY_BOLT, "duration": Duration(5)}),
            {"id": ID_HEX, "duration": param_text(Duration(5))},
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
