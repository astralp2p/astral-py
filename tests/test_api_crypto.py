"""The `crypto` module client, the folded `secp256k1`, and the shapes it pins.

Three tiers, and each one exists because the tier above it cannot make the same
claim:

- **Tier A** pins the four wire types against bytes, including one payload
  `furry-bolt` actually sent: a `mod.crypto.public_key` frame captured this
  session. It also pins the text asymmetry astral-go ships and this SDK
  preserves -- a private key renders base64, a public key renders hex, out of
  the same two-field struct.
- **Tier B** pins every op against `MockApphost`: which values reach the query
  string, which reach the channel body, and how many answers each exchange
  reads. **This is the tier that catches the historical bug.** astral-js and
  astral-py once drove `crypto.public_key` and both `crypto.verify_*` ops with
  query arguments alone, which on the verify ops means the node never sees a
  signature and never verifies anything; the tests below assert on the frames
  the mock received, so an implementation that stopped streaming would fail
  here rather than silently pass everything.
- **Tier C** runs the read-only half against a real node, including the four
  paths that had never been driven live at all: `sign_hash` in its RR
  query-argument form, `sign_text` with its payload on the body, and both
  verdicts. Every other live sign call names the public key of a private key
  `secp256k1.new` generated and the node stored nowhere, so the op gets as far
  as looking the private key up and then declines -- which is the failure half,
  and covering only that half was the gap.

**Two live calls are deliberately absent and must stay absent.**

`crypto.public_key` with a key type other than `secp256k1` **kills the node**:
astrald answers with a nil `*crypto.PublicKey` whose `ObjectType()` dereferences
nil, in a goroutine nothing recovers. The guard that refuses it is tested
against the mock, where the assertion is that *nothing was sent at all*.

`crypto.sign_hash` and `crypto.sign_text` with no `key` make the node sign as
itself, because the core router substitutes its own identity for an anonymous
caller. That is a signing *oracle* when the content is somebody else's choice,
so Tier C signs exactly two fixed constants declared in this file -- `DIGEST` and
`SIGNED_TEXT` -- and verifies them in the same process. Reaching the RR form,
the body form and the verdict path needs a real signature and there is no other
way to one; taking the payload from anywhere but this file would be the hazard.
"""

from __future__ import annotations

import pathlib
import unittest

from astral.api.crypto import (
    CRYPTO_TYPES,
    Crypto,
    Hash,
    KEY_TYPE,
    OP_NEW_KEY,
    OP_PUBLIC_KEY,
    OP_SIGN_HASH,
    OP_SIGN_TEXT,
    OP_VERIFY_HASH_SIGNATURE,
    OP_VERIFY_TEXT_SIGNATURE,
    PrivateKey,
    PublicKey,
    SCHEME_ASN1,
    SCHEME_BIP137,
    SECP256K1_EXTRA,
    Signature,
    Verdict,
    generate_key_local,
    identity_to_public_key,
    public_key_of,
    public_key_to_identity,
)
from astral.client import Client, connect
from astral.codec import text as text_codec
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.jsoncodec import marshal, unmarshal
from astral.errors import (
    BadArgument,
    BadArgumentType,
    FeatureUnavailable,
    ParseError,
    ProtocolError,
    RemoteError,
)
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.transport.base import Transport
from astral.types import Identity, Zone

import live_support
import reference
from astral.api import crypto as crypto_module
from mock_apphost import (
    Accept,
    MockApphost,
    MockConn,
    RouteQuery,
    bounded,
    frame,
    socket_fds,
)

# --- fixtures -------------------------------------------------------------

# A `mod.crypto.public_key` payload exactly as `furry-bolt` sent it this
# session, in answer to `crypto.public_key` over a private key `secp256k1.new`
# had just generated. Public in every sense: it is a point, the node stored
# neither half, and the private key it came from was never written down.
LIVE_PUBLIC_KEY = bytes.fromhex(
    "09" "736563703235366b31"  # string8 "secp256k1"
    "0021"                     # bytes16 length = 33
    "03f5a406bf01f4d81a912509cd3b5a2c95e3cefb57e785771719bf3d73a1c89094"
)

# The header of a `mod.crypto.private_key` the same node sent, and only the
# header: the 32 scalar bytes that followed are a private key and are not
# committed to a repository, freshly generated or not. What the header proves is
# the framing -- `string8` type, `bytes16` key -- which is the whole of what a
# vector here is for.
LIVE_PRIVATE_KEY_HEADER = bytes.fromhex("09" "736563703235366b31" "0020")

POINT = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
OTHER = Identity.parse(POINT.hex())
PUB = PublicKey(type=KEY_TYPE, key=POINT)
DIGEST = bytes(range(32))
SIG = Signature(scheme=SCHEME_ASN1, data=b"\xde\xad\xbe\xef")

SIGNED_TEXT = "astral-py live tier: signature round trip"
"""The one string the live tier ever asks a real node to sign.

Fixed here rather than taken from anywhere, which is the whole of the safety
argument: a signing oracle is a node that signs what somebody else chose. It
names itself so a signature found in a log is traceable to this suite.
"""


def frame_of(obj: object) -> tuple[str, bytes]:
    """One response frame for an object this SDK can encode."""
    return (obj.ASTRAL_TYPE, payload_bytes(obj))  # type: ignore[attr-defined]


def error_frame(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


ACK_FRAME = ("ack", b"")
PUBLIC_KEY_FRAME = ("mod.crypto.public_key", LIVE_PUBLIC_KEY)
SIGNATURE_FRAME = frame_of(SIG)


def rr(*frames: tuple[str, bytes]) -> Accept:
    """An accepted query that answers `frames` and closes. The RR shape.

    Only for the two ops here that write no body -- `secp256k1.new` and the
    query-argument form of `crypto.sign_hash` -- because a route that keeps
    reading never ends the stream, and an RR reader waits for the end.
    """
    return Accept(objects=frames)


def op(*replies: tuple[str, bytes], eos: bool = False):  # type: ignore[no-untyped-def]
    """A route shaped like astrald's `ch.Switch`: read one object, answer one.

    Every crypto op that takes a body has exactly this shape -- the switch reads
    a frame, the matching branch answers, the loop goes round, `BreakOnEOS` ends
    it -- so modelling it is both more faithful than a canned `Accept` and the
    only way to test these ops at all: `MockApphost` writes an `Accept` body and
    closes at once, while every op here writes its input **after** the query has
    been accepted, so the two race and the client's frames are dropped.

    Replies are consumed in order, one per input object. An input past the last
    reply is read and recorded and left unanswered, which is how a
    short-answering op is tested; a reply past the last input is never sent.
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
        if eos:
            conn.send_frame("eos")
            await conn.flush()
        await conn.aclose()

    return handler


# --- Tier A: the four wire types -----------------------------------------


class WireTypeTest(unittest.TestCase):
    """Payload, text and JSON for each type, against astral-go's own forms."""

    def test_the_live_public_key_payload_decodes_and_re_encodes(self):
        """Bytes the node sent, not bytes this SDK made, so a round trip through
        them cannot agree with itself while disagreeing with the node."""
        key = PublicKey.read_payload(object_reader(LIVE_PUBLIC_KEY))
        self.assertEqual(key.type, KEY_TYPE)
        self.assertEqual(len(key.key), 33)
        self.assertEqual(payload_bytes(key), LIVE_PUBLIC_KEY)

    def test_the_public_key_payload_is_a_string8_then_a_bytes16(self):
        """`PublicKey{Type astral.String8, Key astral.Bytes16}`. The length
        prefix on `Key` is two bytes and not one, which is the difference
        between decoding a key and desynchronising the stream."""
        self.assertEqual(LIVE_PUBLIC_KEY[0], 9)
        self.assertEqual(LIVE_PUBLIC_KEY[1:10], b"secp256k1")
        self.assertEqual(LIVE_PUBLIC_KEY[10:12], b"\x00\x21")
        self.assertEqual(len(LIVE_PUBLIC_KEY[12:]), 33)

    def test_the_live_private_key_header_is_the_same_two_fields(self):
        """One byte narrower in the payload and identical in shape: 32 scalar
        bytes where the public key carries a 33-byte point."""
        key = PrivateKey(type=KEY_TYPE, key=bytes(32))
        self.assertEqual(payload_bytes(key)[:12], LIVE_PRIVATE_KEY_HEADER)

    def test_a_hash_is_a_bytes8(self):
        """`type Hash []byte` whose `WriteTo` is `astral.Bytes8(hash).WriteTo`,
        so the length prefix is one byte and a digest above 255 bytes cannot be
        expressed at all."""
        self.assertEqual(payload_bytes(Hash(b"\x01\x02\x03")), b"\x03\x01\x02\x03")
        self.assertEqual(payload_bytes(Hash(b"")), b"\x00")

    def test_a_hash_round_trips_through_its_payload(self):
        digest = Hash(DIGEST)
        self.assertEqual(Hash.read_payload(object_reader(payload_bytes(digest))), digest)

    def test_a_hash_renders_as_hex_and_not_as_base64(self):
        """astral-go's `Hash.MarshalText` is `hex.EncodeToString`. An alias with
        no text form of its own would fall back to base64, which is legal on the
        wire and is not what the reference emits."""
        self.assertEqual(Hash(b"\xde\xad").text(), "dead")
        self.assertEqual(text_codec.encode(Hash(b"\xde\xad")), "#[mod.crypto.hash] dead")
        self.assertEqual(text_codec.decode("#[mod.crypto.hash] dead"), Hash(b"\xde\xad"))
        self.assertEqual(marshal(Hash(b"\xde\xad")), "dead")
        self.assertEqual(unmarshal("mod.crypto.hash", "dead"), Hash(b"\xde\xad"))

    def test_a_hash_refuses_a_text_form_that_is_not_hex(self):
        with self.assertRaises(ParseError):
            Hash.parse("not hex")

    def test_the_private_key_text_form_is_base64_and_the_public_key_s_is_hex(self):
        """The asymmetry is astral-go's, in two files that are otherwise the same
        struct: `api/crypto/private_key.go` renders base64 and `public_key.go`
        renders hex. It is preserved rather than tidied, because both are what
        the node parses."""
        private = PrivateKey(type=KEY_TYPE, key=b"\x00\x01\x02")
        public = PublicKey(type=KEY_TYPE, key=b"\x00\x01\x02")
        self.assertEqual(private.text(), "secp256k1:AAEC")
        self.assertEqual(public.text(), "secp256k1:000102")

    def test_every_type_round_trips_through_its_text_form(self):
        for value in (
            PrivateKey(type=KEY_TYPE, key=bytes(range(32))),
            PublicKey(type=KEY_TYPE, key=POINT),
            Signature(scheme=SCHEME_BIP137, data=bytes(range(65))),
        ):
            with self.subTest(type=value.ASTRAL_TYPE):
                self.assertEqual(type(value).parse(value.text()), value)

    def test_a_text_form_with_no_colon_is_refused(self):
        """astral-go's `UnmarshalText` splits on `:` and answers `invalid
        format`; an unsplittable value is a `ParseError` here."""
        for cls in (PrivateKey, PublicKey, Signature):
            with self.subTest(type=cls.__name__):
                with self.assertRaises(ParseError):
                    cls.parse("secp256k1")
                with self.assertRaises(ParseError):
                    cls.parse(":abcd")

    def test_a_signature_carries_its_scheme_and_the_scheme_is_load_bearing(self):
        """astrald dispatches on it and every engine refuses every scheme but its
        own, so a signature tagged wrongly is answered `unsupported` rather than
        `invalid signature`."""
        self.assertEqual(payload_bytes(SIG), b"\x04asn1\x00\x04\xde\xad\xbe\xef")
        self.assertEqual(SIG.text(), "asn1:3q2+7w==")

    def test_the_json_form_is_the_field_walk_astral_go_produces(self):
        """`Objectify(&key).MarshalJSON()` on the Go side: the PascalCase field
        names, bytes as base64. Declaring a `json()` on these records would have
        replaced that with something else."""
        self.assertEqual(
            marshal(PrivateKey(type=KEY_TYPE, key=b"\x00\x01")),
            {"Type": "secp256k1", "Key": "AAE="},
        )
        self.assertEqual(
            marshal(Signature(scheme=SCHEME_ASN1, data=b"\x00\x01")),
            {"Scheme": "asn1", "Data": "AAE="},
        )

    def test_every_declared_type_is_in_the_default_registry(self):
        """Registration is a side effect of importing `astral.api`, and a type
        that is declared but unregistered decodes as `BlueprintNotFound` in
        exactly the programs that never touched this module."""
        registry = default_blueprints()
        for cls in CRYPTO_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(registry.has(cls.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(cls.ASTRAL_TYPE), cls)
        self.assertEqual(
            {cls.ASTRAL_TYPE for cls in CRYPTO_TYPES},
            {
                "mod.crypto.hash",
                "mod.crypto.private_key",
                "mod.crypto.public_key",
                "mod.crypto.signature",
            },
        )


# --- Tier A: the pure helpers --------------------------------------------


class IdentityEquivalenceTest(unittest.TestCase):
    """An identity *is* a compressed secp256k1 public key. No curve math."""

    def test_an_identity_becomes_a_public_key_byte_for_byte(self):
        key = identity_to_public_key(OTHER)
        self.assertEqual(key.type, KEY_TYPE)
        self.assertEqual(key.key, OTHER.key)

    def test_a_public_key_becomes_an_identity_byte_for_byte(self):
        self.assertEqual(public_key_to_identity(PUB), OTHER)

    def test_the_two_are_inverses(self):
        self.assertEqual(public_key_to_identity(identity_to_public_key(OTHER)), OTHER)
        self.assertEqual(identity_to_public_key(public_key_to_identity(PUB)), PUB)

    def test_the_zero_identity_is_refused(self):
        """33 zero bytes are not a point on the curve, so a key made from them
        can neither sign nor verify and would reach the node only to be answered
        `unsupported`."""
        with self.assertRaises(BadArgument) as caught:
            identity_to_public_key(Identity.ANYONE)
        self.assertIn("zero identity", str(caught.exception))

    def test_a_foreign_key_type_is_not_re_tagged_as_an_identity(self):
        """The bytes of an ed25519 key are not an astral identity, and silently
        producing one would route nowhere."""
        with self.assertRaises(BadArgument) as caught:
            public_key_to_identity(PublicKey(type="ed25519", key=POINT))
        self.assertIn("ed25519", str(caught.exception))

    def test_a_key_of_the_wrong_length_is_refused(self):
        with self.assertRaises(BadArgument):
            public_key_to_identity(PublicKey(type=KEY_TYPE, key=b"\x02\x03"))

    def test_the_wrong_python_type_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            identity_to_public_key("not an identity")  # type: ignore[arg-type]
        with self.assertRaises(BadArgumentType):
            public_key_to_identity(OTHER)  # type: ignore[arg-type]

    def test_no_identity_is_checked_against_the_curve(self):
        """Design section 5.2's deliberate divergence from astral-go, whose
        `secp256k1.Identity` parses the point and answers nil when it is not on
        the curve. Validating here would put a curve library under the most
        common decode in the protocol."""
        bogus = PublicKey(type=KEY_TYPE, key=b"\x04" + bytes(32))
        self.assertEqual(public_key_to_identity(bogus).key, bogus.key)


class OptionalExtraTest(unittest.TestCase):
    """The two helpers that need arithmetic, and the promise that nothing else
    degrades without it."""

    @staticmethod
    def _have_curve() -> bool:
        try:
            import coincurve  # noqa: F401
        except ImportError:
            return False
        return True

    def test_the_module_imports_without_the_extra(self):
        """The import is inside the two helpers, so a missing optional
        dependency cannot make `import astral` fail."""
        self.assertIsNotNone(crypto_module.Crypto)
        self.assertIsNotNone(crypto_module.identity_to_public_key)

    def test_generate_key_local_names_the_extra_when_it_is_absent(self):
        if self._have_curve():  # pragma: no cover -- depends on the environment
            key = generate_key_local()
            self.assertEqual(key.type, KEY_TYPE)
            self.assertEqual(len(key.key), 32)
            return
        with self.assertRaises(FeatureUnavailable) as caught:
            generate_key_local()
        self.assertIn(SECP256K1_EXTRA, str(caught.exception))

    def test_public_key_of_names_the_extra_when_it_is_absent(self):
        private = PrivateKey(type=KEY_TYPE, key=bytes(range(1, 33)))
        if self._have_curve():  # pragma: no cover -- depends on the environment
            self.assertEqual(len(public_key_of(private).key), 33)
            return
        with self.assertRaises(FeatureUnavailable) as caught:
            public_key_of(private)
        self.assertIn(SECP256K1_EXTRA, str(caught.exception))

    def test_public_key_of_refuses_a_foreign_key_type_before_the_import(self):
        """Refused for the same reason `crypto.public_key` refuses it, and
        before the optional import, so the message says which fault it is."""
        with self.assertRaises(BadArgument) as caught:
            public_key_of(PrivateKey(type="ed25519", key=bytes(32)))
        self.assertIn("ed25519", str(caught.exception))

    def test_public_key_of_refuses_the_wrong_python_type(self):
        with self.assertRaises(BadArgumentType):
            public_key_of(PUB)  # type: ignore[arg-type]


class VerdictTest(unittest.TestCase):
    """A bool that carries the reason, because `False` alone answers nothing."""

    def test_a_verdict_is_a_bool(self):
        self.assertTrue(Verdict(True))
        self.assertFalse(Verdict(False))
        self.assertEqual(Verdict(True), True)
        self.assertEqual(Verdict(False), False)
        self.assertEqual(bool(Verdict(1)), True)

    def test_a_verdict_carries_the_responder_s_own_words(self):
        """`invalid signature` is a verdict about the signature; `unsupported` is
        the node saying no engine of its own can judge. A bare False conflates
        them, and the difference is the whole question."""
        self.assertEqual(Verdict(False, "invalid signature").message, "invalid signature")
        self.assertEqual(Verdict(False, "unsupported").message, "unsupported")
        self.assertEqual(Verdict(True).message, "")

    def test_a_verdict_reprs_its_state_and_its_reason(self):
        self.assertEqual(repr(Verdict(True)), "Verdict(True)")
        self.assertEqual(repr(Verdict(False, "nope")), "Verdict(False, 'nope')")


class CoercionTest(unittest.TestCase):
    """What a caller naturally holds, and what must be refused rather than sent."""

    def test_a_key_argument_accepts_a_public_key_an_identity_or_either_text(self):
        expected = PUB.text()
        self.assertEqual(crypto_module._key_param(PUB, "op"), expected)
        self.assertEqual(crypto_module._key_param(OTHER, "op"), expected)
        self.assertEqual(crypto_module._key_param(PUB.text(), "op"), expected)
        self.assertEqual(crypto_module._key_param(OTHER.hex(), "op"), expected)

    def test_a_malformed_key_argument_is_refused_here_and_not_by_the_node(self):
        with self.assertRaises(ParseError):
            crypto_module._key_param("secp256k1:not-hex", "op")
        with self.assertRaises(ParseError):
            crypto_module._key_param("too short", "op")
        with self.assertRaises(BadArgumentType):
            crypto_module._key_param(7, "op")  # type: ignore[arg-type]

    def test_the_anyone_key_argument_is_refused(self):
        with self.assertRaises(BadArgument):
            crypto_module._key_param("anyone", "op")

    def test_a_digest_is_accepted_as_a_hash_as_bytes_or_as_hex(self):
        self.assertEqual(crypto_module._hash_bytes(Hash(DIGEST), "op"), DIGEST)
        self.assertEqual(crypto_module._hash_bytes(DIGEST, "op"), DIGEST)
        self.assertEqual(crypto_module._hash_bytes(DIGEST.hex(), "op"), DIGEST)
        self.assertEqual(crypto_module._hash_bytes(bytearray(DIGEST), "op"), DIGEST)

    def test_an_empty_digest_is_refused(self):
        """The node answers `hash is empty` for it, one round trip later."""
        with self.assertRaises(BadArgument) as caught:
            crypto_module._hash_bytes(b"", "op")
        self.assertIn("empty", str(caught.exception))

    def test_a_digest_wider_than_the_bytes8_prefix_is_refused(self):
        """`mod.crypto.hash` is a `Bytes8`, so a 256-byte digest cannot be
        streamed at all; refusing beats a length prefix that truncates."""
        with self.assertRaises(BadArgument) as caught:
            crypto_module._hash_bytes(bytes(256), "op")
        self.assertIn("bytes8", str(caught.exception))

    def test_a_digest_of_the_wrong_python_type_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            crypto_module._hash_bytes(7, "op")  # type: ignore[arg-type]

    def test_a_non_string_text_is_refused_before_it_is_framed(self):
        with self.assertRaises(BadArgumentType):
            crypto_module._texts([b"bytes"], "op")  # type: ignore[list-item]
        with self.assertRaises(BadArgument):
            crypto_module._texts([], "op")


# --- Tier B: the mock ----------------------------------------------------


class CryptoCase(unittest.IsolatedAsyncioTestCase):
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

    async def crypto(self, mock: MockApphost, **kw: object) -> Crypto:
        return Crypto(await self.client(mock, **kw))

    @staticmethod
    def body(mock: MockApphost) -> list[tuple[str, bytes]]:
        """The frames the mock received on the accepted query's body.

        Everything before and including the `route_query_msg` is the session
        handshake; what follows is what the op would have read.
        """
        received = mock.connections[-1].received
        for index, (type_name, _) in enumerate(received):
            if type_name == "mod.apphost.route_query_msg":
                return received[index + 1 :]
        return []


class NewKeyTest(CryptoCase):
    """`secp256k1.new`, folded in as design section 5.2 requires."""

    @bounded()
    async def test_new_key_takes_no_arguments_and_answers_a_private_key(self):
        answer = frame_of(PrivateKey(type=KEY_TYPE, key=bytes(range(32))))
        async with MockApphost(routes={OP_NEW_KEY: rr(answer)}) as mock:
            api = await self.crypto(mock)
            key = await api.new_key()
        self.assertIsInstance(key, PrivateKey)
        self.assertEqual(key.type, KEY_TYPE)
        self.assertEqual(mock.queries[-1].query, OP_NEW_KEY)
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_the_op_name_has_no_crypto_prefix(self):
        """It is registered by the node's `secp256k1` module; folding the client
        into `crypto` does not rename the op."""
        self.assertEqual(OP_NEW_KEY, "secp256k1.new")

    @bounded()
    async def test_an_answer_of_the_wrong_type_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_NEW_KEY: rr(PUBLIC_KEY_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.new_key()
        self.assertIn("mod.crypto.private_key", str(caught.exception))


class PublicKeyTest(CryptoCase):
    """The op whose whole input is a channel body -- and the guard that keeps it
    from killing the node."""

    @bounded()
    async def test_the_private_key_goes_on_the_body_and_not_in_the_query_string(self):
        """The historical bug, as an assertion on the frames the mock received:
        `crypto.public_key` declares no argument but `in` and `out`, so a query
        string with parameters in it is a client that never sent the key."""
        private = PrivateKey(type=KEY_TYPE, key=bytes(range(32)))
        async with MockApphost(
            routes={OP_PUBLIC_KEY: op(PUBLIC_KEY_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            key = await api.public_key(private)
        self.assertEqual(mock.queries[-1].query, OP_PUBLIC_KEY)
        self.assertEqual(parse(mock.queries[-1].query)[1], {})
        self.assertEqual(
            self.body(mock),
            [("mod.crypto.private_key", payload_bytes(private)), ("eos", b"")],
        )
        self.assertEqual(key.key, LIVE_PUBLIC_KEY[12:])

    @bounded()
    async def test_a_batch_is_one_query_and_one_answer_per_key_in_order(self):
        first = PublicKey(type=KEY_TYPE, key=b"\x02" + bytes(32))
        second = PublicKey(type=KEY_TYPE, key=b"\x03" + bytes(32))
        async with MockApphost(
            routes={
                OP_PUBLIC_KEY: op(frame_of(first), frame_of(second))
            }
        ) as mock:
            api = await self.crypto(mock)
            keys = await api.public_key_many(
                [
                    PrivateKey(type=KEY_TYPE, key=bytes(32)),
                    PrivateKey(type=KEY_TYPE, key=bytes(range(32))),
                ]
            )
        self.assertEqual(keys, [first, second])
        self.assertEqual(len(mock.queries), 1)

    @bounded()
    async def test_a_foreign_key_type_is_refused_and_nothing_is_sent(self):
        """The guard that matters most in this module. astrald answers a nil
        `*crypto.PublicKey` for any type but `secp256k1`, the sender calls
        `ObjectType()` through it, and the process dies with no recovery
        anywhere above. The assertion is that the node was never asked."""
        async with MockApphost(
            routes={OP_PUBLIC_KEY: op(PUBLIC_KEY_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgument) as caught:
                await api.public_key(PrivateKey(type="ed25519", key=bytes(32)))
            self.assertEqual(mock.queries, [])
        message = str(caught.exception)
        self.assertIn("crashes", message)
        self.assertIn("ed25519", message)

    @bounded()
    async def test_one_foreign_key_anywhere_in_a_batch_sends_nothing(self):
        """Every key is checked before the first is written, because a batch
        that failed halfway would have already killed the node."""
        async with MockApphost(
            routes={OP_PUBLIC_KEY: op(PUBLIC_KEY_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgument):
                await api.public_key_many(
                    [
                        PrivateKey(type=KEY_TYPE, key=bytes(32)),
                        PrivateKey(type="ed25519", key=bytes(32)),
                    ]
                )
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_empty_batch_is_refused(self):
        async with MockApphost() as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgument):
                await api.public_key_many([])
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_short_answer_list_is_a_protocol_error(self):
        """A caller zipping answers against inputs would pair the wrong ones, so
        the count is checked before anything is returned."""
        async with MockApphost(
            routes={OP_PUBLIC_KEY: op(PUBLIC_KEY_FRAME, eos=True)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.public_key_many(
                    [
                        PrivateKey(type=KEY_TYPE, key=bytes(32)),
                        PrivateKey(type=KEY_TYPE, key=bytes(range(32))),
                    ]
                )
        self.assertIn("2 object(s)", str(caught.exception))

    @bounded()
    async def test_an_error_message_is_a_remote_error_here(self):
        """Unlike the verify ops, a failed `public_key` is a failure and not an
        answer, so it raises."""
        async with MockApphost(
            routes={OP_PUBLIC_KEY: op(error_frame("unsupported"))}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(RemoteError):
                await api.public_key(PrivateKey(type=KEY_TYPE, key=bytes(32)))


class SignHashTest(CryptoCase):
    """The digest goes in the query string; a batch of digests goes on the body."""

    @bounded()
    async def test_sign_hash_sends_the_digest_as_hex_and_writes_no_body(self):
        async with MockApphost(
            routes={OP_SIGN_HASH: rr(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            sig = await api.sign_hash(DIGEST)
        self.assertEqual(sig, SIG)
        name, params = parse(mock.queries[-1].query)
        self.assertEqual(name, OP_SIGN_HASH)
        self.assertEqual(params, {"hash": DIGEST.hex()})
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_sign_hash_sends_the_key_in_its_public_key_text_form(self):
        """The node parses this argument with `PublicKey.UnmarshalText`, which is
        `"<type>:<hex>"` -- not an identity's 66 characters on their own."""
        async with MockApphost(
            routes={OP_SIGN_HASH: rr(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            await api.sign_hash(DIGEST, key=OTHER, scheme=SCHEME_ASN1)
        params = parse(mock.queries[-1].query)[1]
        self.assertEqual(params["key"], f"{KEY_TYPE}:{OTHER.hex()}")
        self.assertEqual(params["scheme"], SCHEME_ASN1)

    @bounded()
    async def test_an_omitted_scheme_is_absent_rather_than_defaulted_here(self):
        """Design section 5.1, rule 5: send `scheme` only when the caller asks,
        so the node's own default stands and the SDK cannot drift from it."""
        async with MockApphost(
            routes={OP_SIGN_HASH: rr(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            await api.sign_hash(DIGEST)
        self.assertNotIn("scheme", parse(mock.queries[-1].query)[1])

    @bounded()
    async def test_sign_hash_many_streams_the_digests_and_sends_no_hash_argument(self):
        """`hash` present is what makes the op answer once and stop reading, so
        sending both would sign the argument and ignore the body."""
        async with MockApphost(
            routes={OP_SIGN_HASH: op(SIGNATURE_FRAME, SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            sigs = await api.sign_hash_many([DIGEST, bytes(32)])
        self.assertEqual(sigs, [SIG, SIG])
        self.assertNotIn("hash", parse(mock.queries[-1].query)[1])
        self.assertEqual(
            self.body(mock),
            [
                ("mod.crypto.hash", payload_bytes(Hash(DIGEST))),
                ("mod.crypto.hash", payload_bytes(Hash(bytes(32)))),
                ("eos", b""),
            ],
        )

    @bounded()
    async def test_an_empty_batch_of_digests_is_refused(self):
        async with MockApphost() as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgument):
                await api.sign_hash_many([])
            self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_answer_of_the_wrong_type_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_SIGN_HASH: rr(ACK_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.sign_hash(DIGEST)
        self.assertIn("mod.crypto.signature", str(caught.exception))


class SignTextTest(CryptoCase):
    """The text goes on the body, and never into the node's query log."""

    @bounded()
    async def test_sign_text_streams_the_text_as_a_string16(self):
        async with MockApphost(
            routes={OP_SIGN_TEXT: op(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            sig = await api.sign_text("hello")
        self.assertEqual(sig, SIG)
        name, params = parse(mock.queries[-1].query)
        self.assertEqual(name, OP_SIGN_TEXT)
        self.assertEqual(params, {})
        self.assertEqual(
            self.body(mock), [("string16", b"\x00\x05hello"), ("eos", b"")]
        )

    @bounded()
    async def test_the_text_never_reaches_the_query_string(self):
        """astrald's core router logs the query string of every routed query at
        the default verbosity, so a text signed through the argument is a text
        in the node's log."""
        secret = "the quick brown fox"
        async with MockApphost(
            routes={OP_SIGN_TEXT: op(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            await api.sign_text(secret)
        self.assertNotIn(secret, mock.queries[-1].query)
        self.assertNotIn("text", parse(mock.queries[-1].query)[1])

    @bounded()
    async def test_a_batch_of_texts_is_one_query_and_one_signature_each(self):
        async with MockApphost(
            routes={OP_SIGN_TEXT: op(SIGNATURE_FRAME, SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            sigs = await api.sign_text_many(["a", "b"], key=PUB)
        self.assertEqual(len(sigs), 2)
        self.assertEqual(len(mock.queries), 1)
        self.assertEqual(
            self.body(mock),
            [("string16", b"\x00\x01a"), ("string16", b"\x00\x01b"), ("eos", b"")],
        )

    @bounded()
    async def test_the_key_travels_as_an_argument_because_the_streamed_one_is_ignored(
        self,
    ):
        """astrald's `OpSignText` builds its signer before entering `ch.Switch`,
        so a `mod.crypto.public_key` on the body is acked and then not used. The
        query argument is parsed before the switch and does work."""
        async with MockApphost(
            routes={OP_SIGN_TEXT: op(SIGNATURE_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            await api.sign_text("hello", key=PUB)
        self.assertEqual(parse(mock.queries[-1].query)[1]["key"], PUB.text())
        self.assertNotIn(
            "mod.crypto.public_key", [name for name, _ in self.body(mock)]
        )

    @bounded()
    async def test_an_empty_batch_of_texts_is_refused(self):
        async with MockApphost() as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgument):
                await api.sign_text_many([])
            self.assertEqual(mock.queries, [])


class ResetTest(CryptoCase):
    """The reset astrald produces by closing an op without draining its body."""

    def test_the_translation_names_the_cause_and_keeps_the_original(self):
        """A `ConnectionResetError` is not an `AstralError`, and every fault out
        of this SDK is one. The original is chained so a node that genuinely
        died is still visible."""
        original = ConnectionResetError("Connection lost")
        translated = crypto_module._reset(OP_SIGN_TEXT, original)
        self.assertIsInstance(translated, ProtocolError)
        message = str(translated)
        self.assertIn(OP_SIGN_TEXT, message)
        self.assertIn("without reading the body", message)
        self.assertIn("ConnectionResetError", message)
        self.assertIn("may also simply have gone", message)

    @bounded()
    async def test_a_node_that_closes_before_reading_is_reported_as_that(self):
        """Reproduced over a real loopback socket: the mock accepts and closes
        at once, so the client's body lands in a receive buffer nobody reads and
        the close becomes a reset. Over a memory transport this is a broken pipe
        instead; both translate."""

        async def accept_then_close(conn: MockConn, query: RouteQuery) -> None:
            conn.send_raw(frame("mod.apphost.query_accepted_msg"))
            await conn.flush()
            await conn.aclose()

        big = "x" * 40000
        async with MockApphost(routes={OP_SIGN_TEXT: accept_then_close}) as mock:
            await mock.listen("tcp")
            client = await connect(mock.endpoint, max_concurrency=2)
            self.clients.append(client)
            api = Crypto(client)
            with self.assertRaises(ProtocolError) as caught:
                await api.sign_text_many([big, big, big], timeout=5)
        self.assertIn(OP_SIGN_TEXT, str(caught.exception))


class VerifyTest(CryptoCase):
    """The op the historical bug broke silently, and the answer that is not a
    failure."""

    @bounded()
    async def test_the_signature_is_streamed_and_the_hash_is_an_argument(self):
        """There is no `signature` query argument and there never was: astrald
        verifies inside its `*crypto.Signature` branch and nowhere else. A client
        that sent arguments alone would get an accepted query, no answer and EOF
        -- which reported as success is the bug two SDKs shipped."""
        async with MockApphost(
            routes={OP_VERIFY_HASH_SIGNATURE: op(ACK_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            verdict = await api.verify_hash_signature(DIGEST, SIG, key=PUB)
        self.assertTrue(verdict)
        name, params = parse(mock.queries[-1].query)
        self.assertEqual(name, OP_VERIFY_HASH_SIGNATURE)
        self.assertEqual(params, {"hash": DIGEST.hex(), "key": PUB.text()})
        self.assertEqual(
            self.body(mock),
            [("mod.crypto.signature", payload_bytes(SIG)), ("eos", b"")],
        )

    @bounded()
    async def test_an_error_message_is_a_false_verdict_and_not_an_exception(self):
        """astrald answers every unsuccessful verification with one
        `error_message`, so raising would turn the ordinary answer into a
        failure."""
        async with MockApphost(
            routes={
                OP_VERIFY_HASH_SIGNATURE: op(
                    error_frame("invalid signature")
                )
            }
        ) as mock:
            api = await self.crypto(mock)
            verdict = await api.verify_hash_signature(DIGEST, SIG)
        self.assertFalse(verdict)
        self.assertEqual(verdict.message, "invalid signature")

    @bounded()
    async def test_unsupported_is_distinguishable_from_invalid(self):
        """`unsupported` is astrald saying no engine of its own can judge, which
        is not the same claim as `invalid signature`."""
        async with MockApphost(
            routes={
                OP_VERIFY_HASH_SIGNATURE: op(error_frame("unsupported"))
            }
        ) as mock:
            api = await self.crypto(mock)
            verdict = await api.verify_hash_signature(DIGEST, SIG)
        self.assertFalse(verdict)
        self.assertEqual(verdict.message, "unsupported")

    @bounded()
    async def test_verify_text_streams_the_text_then_the_signature(self):
        """Two objects on the body, so two answers: astrald acks the text and
        then answers the signature. The verdict is the **last** object."""
        async with MockApphost(
            routes={
                OP_VERIFY_TEXT_SIGNATURE: op(
                    ACK_FRAME, error_frame("invalid signature")
                )
            }
        ) as mock:
            api = await self.crypto(mock)
            verdict = await api.verify_text_signature("hello", SIG)
        self.assertFalse(verdict)
        self.assertEqual(verdict.message, "invalid signature")
        self.assertEqual(
            self.body(mock),
            [
                ("string16", b"\x00\x05hello"),
                ("mod.crypto.signature", payload_bytes(SIG)),
                ("eos", b""),
            ],
        )

    @bounded()
    async def test_verify_text_reads_the_ack_for_the_text_as_a_true_verdict(self):
        async with MockApphost(
            routes={OP_VERIFY_TEXT_SIGNATURE: op(ACK_FRAME, ACK_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            verdict = await api.verify_text_signature("hello", SIG, key=OTHER)
        self.assertTrue(verdict)
        self.assertEqual(parse(mock.queries[-1].query)[1], {"key": PUB.text()})

    @bounded()
    async def test_verify_text_never_puts_the_text_in_the_query_string(self):
        async with MockApphost(
            routes={OP_VERIFY_TEXT_SIGNATURE: op(ACK_FRAME, ACK_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            await api.verify_text_signature("a signed statement", SIG)
        self.assertNotIn("text", parse(mock.queries[-1].query)[1])

    @bounded()
    async def test_a_stream_that_answers_nothing_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_VERIFY_HASH_SIGNATURE: op(eos=True)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.verify_hash_signature(DIGEST, SIG)
        self.assertIn("ended before answering", str(caught.exception))

    @bounded()
    async def test_an_answer_that_is_neither_ack_nor_error_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_VERIFY_HASH_SIGNATURE: op(PUBLIC_KEY_FRAME)}
        ) as mock:
            api = await self.crypto(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.verify_hash_signature(DIGEST, SIG)
        self.assertIn("mod.crypto.public_key", str(caught.exception))

    @bounded()
    async def test_a_signature_of_the_wrong_python_type_is_refused_before_sending(self):
        """Naming the body path in the message, because passing the signature as
        a query argument is the mistake this refusal exists to catch."""
        async with MockApphost() as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgumentType) as caught:
                await api.verify_hash_signature(DIGEST, SIG.text())  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])
        self.assertIn("channel body", str(caught.exception))

    @bounded()
    async def test_a_non_string_text_is_refused_before_sending(self):
        async with MockApphost() as mock:
            api = await self.crypto(mock)
            with self.assertRaises(BadArgumentType):
                await api.verify_text_signature(b"bytes", SIG)  # type: ignore[arg-type]
            self.assertEqual(mock.queries, [])


class ModulePatternTest(CryptoCase):
    """The scaffolding design section 5.1 gives every module client."""

    @bounded()
    async def test_the_module_client_shares_the_one_expect(self):
        from astral.api.base import ModuleClient
        from astral.api.dir import Dir

        self.assertIs(Crypto._expect, ModuleClient._expect)
        self.assertIs(Crypto._expect, Dir._expect)

    @bounded()
    async def test_every_op_forwards_the_query_keywords(self):
        """`ModuleClient`'s contract: a misspelled keyword fails in `query()`
        rather than being dropped, which is the defect astral-go ships in its own
        clients."""
        async with MockApphost(
            routes={OP_NEW_KEY: rr(frame_of(PrivateKey(type=KEY_TYPE)))}
        ) as mock:
            api = await self.crypto(mock)
            await api.new_key(zone=Zone.DEVICE)
        self.assertEqual(mock.queries[-1].zone, Zone.DEVICE)

    def test_the_types_tuple_is_the_module_s_own(self):
        self.assertEqual(tuple(Crypto.TYPES), tuple(CRYPTO_TYPES))

    def test_the_client_reference_is_the_one_it_was_given(self):
        self.assertIn("Crypto(", repr(Crypto(None)))  # type: ignore[arg-type]


class AstraldParityTest(unittest.TestCase):
    """The op inventory, against astrald's own source rather than a list."""

    ASTRALD = "mod/crypto/src"
    SECP = "mod/secp256k1/src"

    def source(self, path: str) -> str:
        """One reference file at the pinned revision, or a skip."""
        try:
            return reference.read(reference.ASTRALD, path)
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

    def op_names(self, directory: str) -> set[str]:
        try:
            names = reference.listdir(reference.ASTRALD, directory)
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))
        return {
            name[len("op_") : -len(".go")]
            for name in names
            if name.startswith("op_") and name.endswith(".go")
        }

    IMPLEMENTED = {
        "public_key",
        "sign_hash",
        "sign_text",
        "verify_hash_signature",
        "verify_text_signature",
    }

    def test_every_crypto_op_astrald_serves_is_implemented_here(self):
        """Walked from `op_*.go` at the pinned revision, so an op astrald grows
        is a deliberate pin bump rather than a suite that goes red on somebody
        else's pull. A partially implemented module is worse than an absent one:
        callers cannot tell which half works."""
        ops = self.op_names(self.ASTRALD)
        self.assertEqual(ops, self.IMPLEMENTED)
        for name in ops:
            with self.subTest(op=name):
                self.assertTrue(hasattr(Crypto, name) or hasattr(Crypto, name + "s"))

    def test_the_folded_module_still_has_exactly_one_op(self):
        """Design section 0.1 folds `secp256k1` in on the ground that it is one
        op and four pure helpers. A second op there would make that false."""
        self.assertEqual(self.op_names(self.SECP), {"new"})

    def test_the_verify_ops_verify_only_inside_their_signature_branch(self):
        """The claim the whole module rests on, checked against the source: if
        astrald ever grew a `hash`-argument-only verification path, driving these
        with arguments would stop being silently wrong and this test would say
        so."""
        for name in ("verify_hash_signature", "verify_text_signature"):
            source = self.source(f"{self.ASTRALD}/op_{name}.go")
            with self.subTest(op=name):
                self.assertIn("crypto.Signature", source)
                self.assertIn("ch.Switch", source)

    def test_op_public_key_still_sends_an_underived_public_key(self):
        """The crash the guard exists for. `secp256k1.PublicKey` answers nil for
        a foreign key type and `OpPublicKey` sends the result unchecked; if
        astrald ever adds the nil test, this fails and the guard can be
        reconsidered."""
        source = self.source(f"{self.ASTRALD}/op_public_key.go")
        self.assertIn("ch.Send(secp256k1.PublicKey(key))", source)
        self.assertNotIn("== nil", source)

    def test_public_key_is_reachable_with_no_credential_at_all(self):
        """Both halves of the module docstring's security claim. An IPC guest is
        never gated -- `blocksAnonymousWeb` returns false for an empty web origin
        -- and an unauthenticated browser guest reaches the same op while the
        node is unclaimed."""
        self.assertIn(
            'if webOrigin == "" || authenticated {',
            self.source("mod/apphost/src/setup_guard.go"),
        )
        source = self.source("mod/apphost/src/config.go")
        unclaimed = source.split("Unclaimed:")[1].split("Claimed:")[0]
        self.assertIn('"crypto.public_key"', unclaimed)

    def test_the_node_logs_the_query_string_of_every_routed_query(self):
        """Why `sign_text` keeps its text off the query string. The hook in
        `lib/routing/op.go` is a red herring -- nothing in astrald sets
        `Op.LogFunc` -- and the real logging is the core router's, at verbosity
        zero, which is on by default."""
        source = self.source("core/router.go")
        self.assertIn('Infov(0, "%v routed in %v", q.Query, d)', source)

    def test_op_sign_text_still_builds_its_signer_before_the_switch(self):
        """The reason this SDK sends `key` as an argument on every sign op. When
        astrald moves the construction inside `signAndSend`, as `op_sign_hash.go`
        already does, this fails and the note can go."""
        text_source = self.source(f"{self.ASTRALD}/op_sign_text.go")
        hash_source = self.source(f"{self.ASTRALD}/op_sign_hash.go")
        # In sign_text the signer is built once, above `signAndSend`.
        self.assertLess(
            text_source.index("mod.NewTextSigner"),
            text_source.index("var signAndSend"),
        )
        # In sign_hash it is built inside, which is why that op honours a
        # streamed key and its sibling does not.
        self.assertGreater(
            hash_source.index("mod.NewHashSigner"),
            hash_source.index("var signAndSend"),
        )


# --- Tier C: the live node ------------------------------------------------


class LiveCryptoTest(live_support.LiveCase):
    """The read-only half, against a real node. Skips when none answers.

    Nothing here sends a private key whose type is not `secp256k1`, because that
    kills the node.

    **Signing, narrowly.** This tier used to obtain no signature at all, which
    left the module's most opinionated decision -- `sign_text` sends its payload
    on the channel **body** where the op inventory declares RR, on the grounds
    recorded in `crypto.py` -- live-tested only in the mode where the node
    refuses before it reads. Every live sign call named a key the node could not
    hold, so `sign_hash` in its RR query-argument form was never driven at all,
    no signature this SDK produced was ever verified, and the whole verdict path
    rested on the mock. Four paths, all of them working, none of them covered.

    So two cases sign with the node's own key, over `SIGNED_TEXT` below: a fixed,
    self-describing string chosen here and not by any caller. That is the line
    the docstring's old "nothing here asks a real node to sign anything" was
    drawing, and it is the part worth keeping -- a signing *oracle* is a node
    that will sign what somebody else picked. Signing one constant and verifying
    it in the same process is not one, and it is the only way to reach the RR
    form, the body form and the verdict together.
    """

    @bounded(30)
    async def test_a_generated_key_derives_a_public_key_that_is_an_identity(self):
        """The whole of the module's happy path in one exchange: the node
        generates, the node derives, and the derived key re-tags as an identity
        with no curve math anywhere in this process."""
        client = await self.client()
        try:
            api = Crypto(client)
            private = await api.new_key(timeout=10)
            self.assertEqual(private.type, KEY_TYPE)
            self.assertEqual(len(private.key), 32)

            public = await api.public_key(private, timeout=10)
            self.assertEqual(public.type, KEY_TYPE)
            self.assertEqual(len(public.key), 33)

            identity = public_key_to_identity(public)
            self.assertEqual(identity.key, public.key)
            self.assertFalse(identity.is_zero)
            self.assertEqual(identity_to_public_key(identity), public)
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()

    @bounded(30)
    async def test_two_keys_in_one_query_answer_in_order(self):
        client = await self.client()
        try:
            api = Crypto(client)
            first = await api.new_key(timeout=10)
            second = await api.new_key(timeout=10)
            self.assertNotEqual(first.key, second.key)

            both = await api.public_key_many([first, second], timeout=10)
            self.assertEqual(len(both), 2)
            self.assertEqual(both[0], await api.public_key(first, timeout=10))
            self.assertEqual(both[1], await api.public_key(second, timeout=10))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_a_bogus_hash_signature_is_a_false_verdict_with_a_reason(self):
        """Read-only, and the shape that the historical bug got wrong: the
        signature is streamed, so the node really does verify. A client that
        never streamed one would see no answer at all."""
        client = await self.client()
        try:
            api = Crypto(client)
            public = await api.public_key(await api.new_key(timeout=10), timeout=10)
            verdict = await api.verify_hash_signature(
                DIGEST,
                Signature(scheme=SCHEME_ASN1, data=bytes(70)),
                key=public,
                timeout=10,
            )
            self.assertFalse(verdict)
            self.assertIn("invalid signature", verdict.message)
        finally:
            await client.aclose()

    @bounded(30)
    async def test_a_scheme_no_engine_serves_is_unsupported_and_not_invalid(self):
        """The distinction `Verdict` exists to carry, from the node itself."""
        client = await self.client()
        try:
            api = Crypto(client)
            public = await api.public_key(await api.new_key(timeout=10), timeout=10)
            verdict = await api.verify_hash_signature(
                DIGEST,
                Signature(scheme="ed25519", data=bytes(64)),
                key=public,
                timeout=10,
            )
            self.assertFalse(verdict)
            self.assertEqual(verdict.message, "unsupported")
        finally:
            await client.aclose()

    @bounded(30)
    async def test_a_bogus_text_signature_reads_the_ack_and_then_the_verdict(self):
        """Two answers on the wire: the ack for the streamed `string16` and then
        the verdict for the signature. Reading only the first would report every
        verification as true."""
        client = await self.client()
        try:
            api = Crypto(client)
            verdict = await api.verify_text_signature(
                "astral-py live tier",
                Signature(scheme=SCHEME_BIP137, data=b"\x1f" + bytes(64)),
                timeout=10,
            )
            self.assertFalse(verdict)
            self.assertIn("invalid signature", verdict.message)
        finally:
            await client.aclose()

    @bounded(30)
    async def test_a_streamed_digest_reaches_the_op_as_a_typed_object(self):
        """`sign_hash_many` against a key the node cannot hold -- the public key of
        a private key it generated and stored nowhere. astrald reads the digest
        *before* it looks for a signer, so `unsupported` here proves the
        `mod.crypto.hash` frame decoded on the node. No signature is produced."""
        client = await self.client()
        try:
            api = Crypto(client)
            unheld = await api.public_key(await api.new_key(timeout=10), timeout=10)
            with self.assertRaises(RemoteError) as caught:
                await api.sign_hash_many([DIGEST], key=unheld, timeout=10)
            self.assertIn("unsupported", str(caught.exception))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_sign_text_with_an_unusable_key_is_the_translated_reset(self):
        """astrald builds the text signer before reading anything, so it answers
        and closes with the body unread and the connection resets. Pinned live
        because it is the one failure mode a caller of this module will meet
        that no mock would have predicted."""
        client = await self.client()
        try:
            api = Crypto(client)
            unheld = await api.public_key(await api.new_key(timeout=10), timeout=10)
            with self.assertRaises(ProtocolError) as caught:
                await api.sign_text("astral-py live tier", key=unheld, timeout=10)
            self.assertIn("without reading the body", str(caught.exception))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_the_same_query_with_the_text_as_an_argument_answers_cleanly(self):
        """The control for the test above, and the evidence that the reset is
        astrald closing on an unread body rather than anything this SDK does:
        the identical failure, with no body written, arrives as an
        `error_message`."""
        from astral import querystring

        client = await self.client()
        try:
            api = Crypto(client)
            unheld = await api.public_key(await api.new_key(timeout=10), timeout=10)
            qs = querystring.build(
                OP_SIGN_TEXT, {"text": "astral-py live tier", "key": unheld.text()}
            )
            with self.assertRaises(RemoteError) as caught:
                await client.call_one(qs, timeout=10)
            self.assertIn("unsupported", str(caught.exception))
        finally:
            await client.aclose()


    @bounded(30)
    async def test_sign_hash_in_its_rr_form_answers_an_asn1_signature(self):
        """The one op this module drives as RR, and it was never called live.

        `sign_hash` takes its digest as a **query argument** and answers one
        `mod.crypto.signature` at a bare EOF with no `eos`, which is what
        `call_one` reads. The default key is the caller's, which for an anonymous
        IPC guest is the node's own, and the hash engine's default scheme is
        `asn1`.
        """
        client = await self.client()
        try:
            api = Crypto(client)
            signature = await api.sign_hash(DIGEST, timeout=10)
            self.assertIsInstance(signature, Signature)
            self.assertEqual(signature.scheme, SCHEME_ASN1)
            self.assertTrue(signature.data)
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()

    @bounded(30)
    async def test_a_text_signature_this_sdk_made_verifies_and_a_tampered_one_does_not(
        self,
    ):
        """The body form and the verdict path, end to end.

        `sign_text` puts its payload on the channel body where the survey
        declares RR; `verify_text_signature` puts the text and the signature
        there because the op verifies inside its `*crypto.Signature` branch and
        nowhere else. Both of those are this module's own readings, and until now
        neither had ever produced or consumed a real signature. The negative case
        is what makes the positive one mean anything: a verifier that answers
        `True` for everything would pass the first assertion alone.
        """
        client = await self.client()
        try:
            api = Crypto(client)
            signature = await api.sign_text(SIGNED_TEXT, timeout=10)
            self.assertIsInstance(signature, Signature)
            self.assertEqual(signature.scheme, SCHEME_BIP137)

            good = await api.verify_text_signature(SIGNED_TEXT, signature, timeout=10)
            self.assertTrue(good, f"the node refused its own signature: {good.message}")

            bad = await api.verify_text_signature(
                SIGNED_TEXT + " tampered", signature, timeout=10
            )
            self.assertFalse(bad, "a signature over other text verified")
            self.assertEqual(bad.message, "invalid signature")
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()

    @bounded(30)
    async def test_a_hash_signature_this_sdk_made_verifies(self):
        """The same round trip on the hash side, where the scheme is `asn1` and
        the digest travels as an argument rather than on the body."""
        client = await self.client()
        try:
            api = Crypto(client)
            signature = await api.sign_hash(DIGEST, timeout=10)
            verdict = await api.verify_hash_signature(DIGEST, signature, timeout=10)
            self.assertTrue(
                verdict, f"the node refused its own signature: {verdict.message}"
            )
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
