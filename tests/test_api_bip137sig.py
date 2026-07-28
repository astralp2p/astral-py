"""The `bip137sig` module client: four ops, two wire types, one key chain.

Three tiers, each making a claim the tier above it cannot:

- **Tier A** pins the two wire types against bytes the node actually sent this
  session -- `10` and 16 entropy bytes, `40` and 64 seed bytes -- and pins the
  length validators that make a wrong length unsendable. It also pins the
  derivation-path grammar against the node's own answers, element for element.
- **Tier B** pins every op against `MockApphost`: which value reaches the query
  string, which reaches the channel body, and that **no `eos` is ever sent**.
  That last one is the trap here. Every `crypto` op ends its `ch.Switch` with
  `BreakOnEOS` and needs a terminator; not one op in this module reads a second
  object, so a terminator would sit unread in the node's receive buffer and the
  close would reset the connection, discarding the answer the node had already
  written. A test asserts on the frames the mock received, so an implementation
  that started sending one fails here.
- **Tier C** runs all four ops against a real node and checks the node's answers
  against this SDK's own `astral.bip39`. Two implementations of one standard is
  the only check worth making on a value nobody can read by eye.

**Nothing secret is asked of the node.** Every live call uses the all-zero
entropy, its published mnemonic, its published seed and the passphrase `TREZOR`
from the BIP-39 vector file. The passphrase argument of `bip137sig.seed` lands
in astrald's log at the default verbosity, which is why the module prefers
`seed_local` and why this suite sends only a passphrase that is already public.
"""

from __future__ import annotations

import unittest

from astral.api.bip137sig import (
    BIP137SIG_TYPES,
    Bip137Sig,
    Entropy,
    HARDENED_OFFSET,
    MAX_INDEX,
    OP_DERIVE_KEY,
    OP_MNEMONIC,
    OP_NEW_ENTROPY,
    OP_SEED,
    Seed,
    mnemonic_local,
    new_entropy_local,
    parse_derivation_path,
    seed_local,
)
from astral.api.crypto import KEY_TYPE, PrivateKey
from astral.client import Client, connect
from astral.codec import text as text_codec
from astral.codec.binary import object_reader, payload_bytes
from astral.codec.jsoncodec import marshal, unmarshal
from astral.errors import (
    AstralError,
    BadArgument,
    BadArgumentType,
    ParseError,
    ProtocolError,
    RemoteError,
)
from astral.primitives import String16
from astral.querystring import parse
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.transport.base import Transport
from astral.types import Zone

import live_support
import reference
from astral import bip39
from mock_apphost import Accept, MockApphost, MockConn, RouteQuery, bounded, frame, socket_fds

# --- fixtures -------------------------------------------------------------

ZERO_ENTROPY = bytes(16)
"""The BIP-39 vector file's first entropy, and the only entropy this suite
sends to a node."""

ZERO_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])
ZERO_SEED = bytes.fromhex(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5"
    "ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
"""`furry-bolt`'s answer for `ZERO_MNEMONIC` with no passphrase, which is the
published BIP-39 seed for it."""

TREZOR_SEED = bytes.fromhex(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f0"
    "9a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
"""The same mnemonic under the vector file's passphrase. Also live-verified."""

MASTER_KEY = bytes.fromhex(
    "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
)
"""What `bip137sig.derive_key` with no path answered for `ZERO_SEED`: the BIP-32
master key of the published test seed, and public test data."""

BIP44_KEY = bytes.fromhex(
    "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372"
)
"""The same seed along `m/44'/0'/0'/0/0`, live-verified. The first key of the
BIP-44 account of the world's most published test mnemonic."""

LIVE_ENTROPY_PAYLOAD = bytes.fromhex("10" + "00" * 16)
"""A `bip137sig.entropy` payload in the shape `furry-bolt` sends: `uint8` length
and then the bytes. `bits=256` answered `20` and 32 bytes (design risk R-11)."""

LIVE_SEED_PAYLOAD = bytes([64]) + ZERO_SEED
"""A `bip137sig.seed` payload, `40` and then 64 bytes."""

NFC_PASSPHRASE = "\u00e9"
"""`é` as one code point. What a caller most often types."""

NFKD_PASSPHRASE = "e\u0301"
"""The same `é` as `e` and a combining acute: the NFKD form BIP-39 requires,
and the only form that makes the node's answer a BIP-39 seed."""


def frame_of(obj: object) -> tuple[str, bytes]:
    """One response frame for an object this SDK can encode."""
    return (obj.ASTRAL_TYPE, payload_bytes(obj))  # type: ignore[attr-defined]


def raw_frame(type_name: str, payload: bytes) -> tuple[str, bytes]:
    """One response frame this SDK would refuse to build, for a misbehaving node."""
    return (type_name, payload)


def error_frame(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


def rr(*frames: tuple[str, bytes]) -> Accept:
    """An accepted query that answers and closes. `new_entropy` alone."""
    return Accept(objects=frames)


def exchange(*replies: tuple[str, bytes]):  # type: ignore[no-untyped-def]
    """A route shaped like astrald's op bodies: read one object, answer one, close.

    Every body op here is exactly `ch.Receive()`, `ch.Send(…)` and a deferred
    `ch.Close()`, with no `ch.Switch` and no second read. A canned `Accept` will
    not do: `MockApphost` writes an `Accept` body and closes at once, while the
    client writes its input after the query has been accepted, so the two race.
    """

    async def handler(conn: MockConn, query: RouteQuery) -> None:
        conn.send_raw(frame("mod.apphost.query_accepted_msg"))
        await conn.flush()
        for reply in replies:
            if await conn.recv_frame_or_none() is None:
                break
            conn.send_frame(*reply)
            await conn.flush()
        await conn.aclose()

    return handler


def silent():  # type: ignore[no-untyped-def]
    """The route an input the node cannot decode produces: read, answer nothing.

    `Entropy.ReadFrom` and `Seed.ReadFrom` abort the frame on a length they
    refuse and the op returns that error without sending. Verified live with an
    8-byte entropy and a 32-byte seed.
    """

    async def handler(conn: MockConn, query: RouteQuery) -> None:
        conn.send_raw(frame("mod.apphost.query_accepted_msg"))
        await conn.flush()
        await conn.recv_frame_or_none()
        await conn.aclose()

    return handler


# --- Tier A: the two wire types ------------------------------------------


class WireTypeTest(unittest.TestCase):
    """`uint8 len` and then the bytes, with the length rule on both sides."""

    def test_an_entropy_payload_is_a_length_and_then_the_bytes(self):
        """Design risk R-11, settled live: `bip137sig.new_entropy?bits=128`
        answered `10` and 16 bytes."""
        self.assertEqual(payload_bytes(Entropy(ZERO_ENTROPY)), LIVE_ENTROPY_PAYLOAD)
        self.assertEqual(payload_bytes(Entropy(bytes(32)))[0], 0x20)

    def test_an_entropy_payload_round_trips(self):
        value = Entropy(bytes(range(20)))
        self.assertEqual(Entropy.read_payload(object_reader(payload_bytes(value))), value)

    def test_a_seed_payload_is_sixty_four_bytes_under_a_length(self):
        self.assertEqual(payload_bytes(Seed(ZERO_SEED)), LIVE_SEED_PAYLOAD)
        self.assertEqual(len(LIVE_SEED_PAYLOAD), 65)

    def test_a_seed_payload_round_trips(self):
        value = Seed(ZERO_SEED)
        self.assertEqual(Seed.read_payload(object_reader(payload_bytes(value))), value)

    def test_an_entropy_of_a_length_bip39_does_not_define_cannot_be_encoded(self):
        """astral-go's `Entropy.WriteTo` returns `ErrInvalidEntropyLength` and
        writes nothing, so the rule is the wire contract and not an opinion."""
        for size in (0, 15, 17, 33):
            with self.subTest(size=size):
                with self.assertRaises(ParseError):
                    payload_bytes(Entropy(bytes(size)))

    def test_an_entropy_of_a_wrong_length_cannot_be_decoded(self):
        """The same rule on `ReadFrom`. A node that sent one would be sending a
        value BIP-39 has no mnemonic for."""
        with self.assertRaises(ParseError):
            Entropy.read_payload(object_reader(bytes([8]) + bytes(8)))

    def test_a_seed_of_any_other_length_cannot_be_encoded_or_decoded(self):
        for size in (0, 32, 63, 65):
            with self.subTest(size=size):
                with self.assertRaises(ParseError):
                    payload_bytes(Seed(bytes(size)))
                with self.assertRaises(ParseError):
                    Seed.read_payload(object_reader(bytes([size]) + bytes(size)))

    def test_the_zero_value_is_constructible_and_unencodable(self):
        """`Blueprints.new` needs a prototype and astral-go registers `T{}`, so
        the length is checked where astral-go checks it: on the wire, not in the
        constructor."""
        for cls in (Entropy, Seed):
            with self.subTest(type=cls.ASTRAL_TYPE):
                zero = default_blueprints().new(cls.ASTRAL_TYPE)
                self.assertIsInstance(zero, cls)
                self.assertEqual(len(zero), 0)
                with self.assertRaises(ParseError):
                    payload_bytes(zero)

    def test_the_text_form_is_hex(self):
        """astral-go's `MarshalText` is `hex.EncodeToString` for both types."""
        value = Entropy(ZERO_ENTROPY)
        self.assertEqual(value.text(), "00" * 16)
        self.assertEqual(value.hex(), "00" * 16)
        self.assertEqual(
            text_codec.encode(value), "#[bip137sig.entropy] " + "00" * 16
        )
        self.assertEqual(text_codec.decode(text_codec.encode(value)), value)
        self.assertEqual(text_codec.decode(text_codec.encode(Seed(ZERO_SEED))),
                         Seed(ZERO_SEED))

    def test_the_json_form_is_hex_too(self):
        self.assertEqual(marshal(Entropy(ZERO_ENTROPY)), "00" * 16)
        self.assertEqual(
            unmarshal("bip137sig.entropy", "00" * 16), Entropy(ZERO_ENTROPY)
        )
        self.assertEqual(marshal(Seed(ZERO_SEED)), ZERO_SEED.hex())

    def test_a_text_form_that_is_not_hex_is_refused(self):
        for cls in (Entropy, Seed):
            with self.subTest(type=cls.ASTRAL_TYPE):
                with self.assertRaises(ParseError):
                    cls.parse("not hex")

    def test_a_json_value_that_is_not_a_string_is_refused(self):
        with self.assertRaises(ParseError):
            unmarshal("bip137sig.entropy", 7)

    def test_the_repr_shows_the_length_and_never_the_bytes(self):
        """An entropy is a mnemonic is a seed is every key under it, and a repr
        reaches a log or a traceback without anybody choosing to put it there."""
        secret = bytes(range(1, 17))
        self.assertEqual(repr(Entropy(secret)), "Entropy(16 bytes)")
        self.assertEqual(repr(Seed(ZERO_SEED)), "Seed(64 bytes)")
        self.assertNotIn(secret.hex(), repr(Entropy(secret)))

    def test_a_string_is_not_a_value(self):
        """`Entropy("00" * 16)` would be 32 bytes of ASCII, which is a different
        mnemonic and a legal length."""
        with self.assertRaises(BadArgumentType):
            Entropy("00" * 16)
        with self.assertRaises(BadArgumentType):
            Seed(ZERO_SEED.hex())

    def test_an_integer_is_not_a_value(self):
        """`bytes(64)` is 64 zero bytes, so `Seed(64)` would build a seed of the
        right length out of nothing and every length check would pass it."""
        for value in (16, 64, None, [0] * 16):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(BadArgumentType):
                    Seed(value)
                with self.assertRaises(BadArgumentType):
                    Entropy(value)

    def test_a_bytearray_and_a_memoryview_are_values(self):
        self.assertEqual(Entropy(bytearray(ZERO_ENTROPY)), Entropy(ZERO_ENTROPY))
        self.assertEqual(Seed(memoryview(ZERO_SEED)), Seed(ZERO_SEED))

    def test_bytes_and_len_read_the_value(self):
        self.assertEqual(bytes(Entropy(ZERO_ENTROPY)), ZERO_ENTROPY)
        self.assertEqual(len(Seed(ZERO_SEED)), 64)
        self.assertEqual(Entropy(ZERO_ENTROPY).bits, 128)
        self.assertEqual(Entropy(bytes(32)).bits, 256)

    def test_both_types_are_in_the_default_registry(self):
        registry = default_blueprints()
        for cls in BIP137SIG_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertTrue(registry.has(cls.ASTRAL_TYPE))
                self.assertIsInstance(registry.new(cls.ASTRAL_TYPE), cls)
        self.assertEqual(
            {cls.ASTRAL_TYPE for cls in BIP137SIG_TYPES},
            {"bip137sig.entropy", "bip137sig.seed"},
        )

    def test_the_type_names_carry_no_mod_prefix(self):
        """Design section 5.1 rule 6 lists both as exceptions to the prefix
        rule; astral-go's `ObjectType()` is the authority."""
        for cls in BIP137SIG_TYPES:
            with self.subTest(type=cls.ASTRAL_TYPE):
                self.assertFalse(cls.ASTRAL_TYPE.startswith("mod."))


# --- Tier A: the local forms and the path grammar -------------------------


class LocalFormTest(unittest.TestCase):
    """The three ops that need no node, over `astral.bip39`."""

    def test_local_entropy_is_the_op_s_shape_without_the_op(self):
        value = new_entropy_local()
        self.assertIsInstance(value, Entropy)
        self.assertEqual(len(value), 16)
        self.assertEqual(len(new_entropy_local(256)), 32)

    def test_local_mnemonic_matches_the_published_vector(self):
        self.assertEqual(" ".join(mnemonic_local(ZERO_ENTROPY)), ZERO_MNEMONIC)
        self.assertEqual(mnemonic_local(Entropy(ZERO_ENTROPY)), ZERO_MNEMONIC.split())

    def test_local_seed_matches_the_node_s_answer(self):
        self.assertEqual(bytes(seed_local(ZERO_MNEMONIC)), ZERO_SEED)
        self.assertEqual(bytes(seed_local(ZERO_MNEMONIC, "TREZOR")), TREZOR_SEED)
        self.assertIsInstance(seed_local(ZERO_MNEMONIC), Seed)

    def test_local_entropy_of_an_undefined_size_is_refused(self):
        with self.assertRaises(AstralError):
            new_entropy_local(100)

    def test_local_mnemonic_refuses_a_length_no_mnemonic_exists_for(self):
        with self.assertRaises(ParseError):
            mnemonic_local(bytes(8))

    def test_the_chain_composes(self):
        """The whole of a wallet's derivation, minus BIP-32, with no node."""
        entropy = new_entropy_local(192)
        words = mnemonic_local(entropy)
        self.assertEqual(len(words), 18)
        self.assertEqual(bip39.mnemonic_to_entropy(words), bytes(entropy))
        self.assertEqual(len(seed_local(words)), 64)


class DerivationPathTest(unittest.TestCase):
    """astral-go's `ParseDerivationPath`, rule for rule and live-verified."""

    def test_the_master_key_is_the_empty_path(self):
        self.assertEqual(parse_derivation_path(""), ())
        self.assertEqual(parse_derivation_path("m"), ())

    def test_a_leading_m_slash_is_stripped_and_nothing_else_is(self):
        """Verified live: `44'/0'` derives and `/0` answers `invalid path
        element ""`."""
        self.assertEqual(parse_derivation_path("m/0"), (0,))
        self.assertEqual(
            parse_derivation_path("44'/0'"),
            (44 + HARDENED_OFFSET, HARDENED_OFFSET),
        )
        with self.assertRaises(ParseError):
            parse_derivation_path("/0")

    def test_both_hardened_marks_set_bit_thirty_one(self):
        self.assertEqual(parse_derivation_path("m/0'"), (HARDENED_OFFSET,))
        self.assertEqual(parse_derivation_path("m/0h"), (HARDENED_OFFSET,))

    def test_the_bip44_path_is_five_elements(self):
        self.assertEqual(
            parse_derivation_path("m/44'/0'/0'/0/0"),
            (44 + HARDENED_OFFSET, HARDENED_OFFSET, HARDENED_OFFSET, 0, 0),
        )

    def test_the_largest_index_is_thirty_one_bits(self):
        """`strconv.ParseUint(p, 10, 31)`. Verified live: `m/2147483647h`
        derives and `m/2147483648` answers `invalid path element`."""
        self.assertEqual(
            parse_derivation_path(f"m/{MAX_INDEX}h"), (MAX_INDEX + HARDENED_OFFSET,)
        )
        with self.assertRaises(ParseError):
            parse_derivation_path(f"m/{MAX_INDEX + 1}")

    def test_every_element_the_node_refuses_is_refused_here(self):
        """The message is the node's own, word for word, so a caller reading the
        SDK's error and a caller reading the node's log see one sentence."""
        for path in ("m/", "/0", "m/-1", "m/0x10", "m/ 0", "m/1_0", "M/0", "m/١"):
            with self.subTest(path=path):
                with self.assertRaises(ParseError) as caught:
                    parse_derivation_path(path)
                self.assertIn("invalid path element", str(caught.exception))

    def test_a_non_string_path_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            parse_derivation_path(44)  # type: ignore[arg-type]


# --- Tier B: the mock -----------------------------------------------------


class Bip137SigCase(unittest.IsolatedAsyncioTestCase):
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

    async def api(self, mock: MockApphost, **kw: object) -> Bip137Sig:
        return Bip137Sig(await self.client(mock, **kw))

    @staticmethod
    def body(mock: MockApphost) -> list[tuple[str, bytes]]:
        """The frames the mock received on the accepted query's body."""
        received = mock.connections[-1].received
        for index, (type_name, _) in enumerate(received):
            if type_name == "mod.apphost.route_query_msg":
                return received[index + 1 :]
        return []


class NewEntropyTest(Bip137SigCase):
    """RR, one argument, no body."""

    @bounded()
    async def test_an_omitted_size_sends_no_argument_at_all(self):
        """Design section 5.1 rule 5: the server's default stands unless the
        caller asks. astrald reads an absent `bits` as 128."""
        async with MockApphost(
            routes={OP_NEW_ENTROPY: rr(frame_of(Entropy(ZERO_ENTROPY)))}
        ) as mock:
            api = await self.api(mock)
            value = await api.new_entropy()
        self.assertEqual(value, Entropy(ZERO_ENTROPY))
        self.assertEqual(mock.queries[-1].query, OP_NEW_ENTROPY)
        self.assertEqual(self.body(mock), [])

    @bounded()
    async def test_a_size_travels_as_a_decimal_argument(self):
        async with MockApphost(
            routes={OP_NEW_ENTROPY: rr(frame_of(Entropy(bytes(32))))}
        ) as mock:
            api = await self.api(mock)
            value = await api.new_entropy(256)
        self.assertEqual(len(value), 32)
        self.assertEqual(parse(mock.queries[-1].query)[1], {"bits": "256"})

    @bounded()
    async def test_a_size_bip39_does_not_define_never_reaches_the_node(self):
        """The node's answer to one is `invalid entropy size: 100` and a round
        trip; refusing here names the sizes instead.

        `BadArgument`, which is the class `bip39.new_entropy` raises for the same
        fault: one fault, one class, whichever door it comes through."""
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(BadArgument) as caught:
                await api.new_entropy(100)
        self.assertIn("128", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_non_integer_size_is_a_type_error(self):
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(BadArgumentType):
                await api.new_entropy("128")  # type: ignore[arg-type]
            with self.assertRaises(BadArgumentType):
                await api.new_entropy(True)  # type: ignore[arg-type]
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_an_error_message_raises(self):
        async with MockApphost(
            routes={OP_NEW_ENTROPY: rr(error_frame("invalid entropy size: 100"))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.new_entropy()
        self.assertIn("invalid entropy size", str(caught.exception))

    @bounded()
    async def test_another_type_is_a_protocol_error(self):
        async with MockApphost(routes={OP_NEW_ENTROPY: rr(("ack", b""))}) as mock:
            api = await self.api(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.new_entropy()
        self.assertIn("bip137sig.entropy", str(caught.exception))


class MnemonicTest(Bip137SigCase):
    """WA: the entropy on the body, one `string16` back, no `eos`."""

    @bounded()
    async def test_the_entropy_travels_on_the_body_and_no_eos_follows_it(self):
        """The op reads one object and closes, so an `eos` after the input is
        unread data at close, which is a reset, which discards the answer."""
        async with MockApphost(
            routes={OP_MNEMONIC: exchange(frame_of(String16(ZERO_MNEMONIC)))}
        ) as mock:
            api = await self.api(mock)
            words = await api.mnemonic(ZERO_ENTROPY)
        self.assertEqual(words, ZERO_MNEMONIC.split())
        self.assertEqual(mock.queries[-1].query, OP_MNEMONIC)
        self.assertEqual(
            self.body(mock), [("bip137sig.entropy", LIVE_ENTROPY_PAYLOAD)]
        )

    @bounded()
    async def test_an_entropy_object_and_raw_bytes_send_the_same_frame(self):
        async with MockApphost(
            routes={OP_MNEMONIC: exchange(frame_of(String16(ZERO_MNEMONIC)))}
        ) as mock:
            api = await self.api(mock)
            await api.mnemonic(Entropy(ZERO_ENTROPY))
        self.assertEqual(
            self.body(mock), [("bip137sig.entropy", LIVE_ENTROPY_PAYLOAD)]
        )

    @bounded()
    async def test_a_length_the_node_cannot_read_never_reaches_it(self):
        """The node answers an undecodable input with silence and a closed
        stream, so the fault must be named here or it is named nowhere."""
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(ParseError) as caught:
                await api.mnemonic(bytes(8))
        self.assertIn(OP_MNEMONIC, str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_mnemonic_for_other_entropy_is_a_protocol_error(self):
        """The answer is checked against the entropy that was sent. A wrong
        mnemonic is a wrong seed and every key under it, and the check is local
        and free."""
        other = " ".join(mnemonic_local(bytes([1]) + bytes(15)))
        async with MockApphost(
            routes={OP_MNEMONIC: exchange(frame_of(String16(other)))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.mnemonic(ZERO_ENTROPY)
        self.assertIn("different entropy", str(caught.exception))

    @bounded()
    async def test_a_mnemonic_this_sdk_cannot_decode_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_MNEMONIC: exchange(frame_of(String16("nonsense words here")))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.mnemonic(ZERO_ENTROPY)
        self.assertIn("cannot decode", str(caught.exception))

    @bounded()
    async def test_a_stream_that_answers_nothing_is_a_protocol_error(self):
        async with MockApphost(routes={OP_MNEMONIC: silent()}) as mock:
            api = await self.api(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.mnemonic(ZERO_ENTROPY)
        self.assertIn("ended before answering", str(caught.exception))

    @bounded()
    async def test_an_error_message_raises(self):
        async with MockApphost(
            routes={OP_MNEMONIC: exchange(error_frame("invalid entropy length"))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(RemoteError):
                await api.mnemonic(ZERO_ENTROPY)


class SeedTest(Bip137SigCase):
    """WA: the mnemonic on the body, the passphrase in the query string."""

    @bounded()
    async def test_the_mnemonic_travels_as_one_string16_and_no_eos_follows(self):
        async with MockApphost(
            routes={OP_SEED: exchange(frame_of(Seed(ZERO_SEED)))}
        ) as mock:
            api = await self.api(mock)
            seed = await api.seed(ZERO_MNEMONIC)
        self.assertEqual(bytes(seed), ZERO_SEED)
        self.assertEqual(mock.queries[-1].query, OP_SEED)
        self.assertEqual(
            self.body(mock), [frame_of(String16(ZERO_MNEMONIC))]
        )

    @bounded()
    async def test_a_word_sequence_and_a_string_send_the_same_frame(self):
        """The node splits with `strings.Fields`, so both spellings are one
        mnemonic there; they are one frame here."""
        async with MockApphost(
            routes={OP_SEED: exchange(frame_of(Seed(ZERO_SEED)))}
        ) as mock:
            api = await self.api(mock)
            await api.seed(ZERO_MNEMONIC.split())
        self.assertEqual(self.body(mock), [frame_of(String16(ZERO_MNEMONIC))])

    @bounded()
    async def test_an_empty_passphrase_sends_no_argument(self):
        async with MockApphost(
            routes={OP_SEED: exchange(frame_of(Seed(ZERO_SEED)))}
        ) as mock:
            api = await self.api(mock)
            await api.seed(ZERO_MNEMONIC, passphrase="")
        self.assertEqual(mock.queries[-1].query, OP_SEED)

    @bounded()
    async def test_a_passphrase_travels_normalised(self):
        """BIP-39 requires NFKD and astral-go omits it, so the node derives a
        different seed for each spelling of one passphrase -- verified live,
        `8382db94...` against `f37f8652...`. Normalising here feeds it the form
        that makes its own answer standard.

        Both spellings are written as escapes. They render identically, so a
        tool that normalises this file on save would make the pair one value and
        leave every assertion below passing while testing nothing."""
        self.assertNotEqual(NFC_PASSPHRASE, NFKD_PASSPHRASE)
        async with MockApphost(
            routes={OP_SEED: exchange(frame_of(Seed(ZERO_SEED)))}
        ) as mock:
            api = await self.api(mock)
            await api.seed(ZERO_MNEMONIC, passphrase=NFC_PASSPHRASE)
        sent = parse(mock.queries[-1].query)[1]["passphrase"]
        self.assertEqual(sent, NFKD_PASSPHRASE)
        self.assertNotEqual(sent, NFC_PASSPHRASE)

    @bounded()
    async def test_an_invalid_mnemonic_never_leaves_this_process(self):
        """Nor does the passphrase, which is the argument astrald logs."""
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(ParseError) as caught:
                await api.seed(" ".join(["abandon"] * 12), passphrase="secret")
        self.assertIn("checksum", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_non_string_passphrase_is_a_type_error(self):
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(BadArgumentType):
                await api.seed(ZERO_MNEMONIC, passphrase=b"bytes")  # type: ignore[arg-type]
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_seed_of_the_wrong_length_does_not_decode(self):
        """A node cannot answer one -- `Seed.WriteTo` refuses it -- so a stream
        carrying one is corrupt rather than surprising."""
        async with MockApphost(
            routes={OP_SEED: exchange(raw_frame("bip137sig.seed", bytes([32]) + bytes(32)))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(AstralError):
                await api.seed(ZERO_MNEMONIC)

    @bounded()
    async def test_another_type_is_a_protocol_error(self):
        async with MockApphost(
            routes={OP_SEED: exchange(frame_of(String16("nope")))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(ProtocolError) as caught:
                await api.seed(ZERO_MNEMONIC)
        self.assertIn("bip137sig.seed", str(caught.exception))


class DeriveKeyTest(Bip137SigCase):
    """WA: the seed on the body, the path in the query string."""

    @bounded()
    async def test_the_seed_travels_on_the_body_with_the_path_as_an_argument(self):
        answer = frame_of(PrivateKey(type=KEY_TYPE, key=BIP44_KEY))
        async with MockApphost(routes={OP_DERIVE_KEY: exchange(answer)}) as mock:
            api = await self.api(mock)
            key = await api.derive_key(ZERO_SEED, "m/44'/0'/0'/0/0")
        self.assertIsInstance(key, PrivateKey)
        self.assertEqual(key.key, BIP44_KEY)
        self.assertEqual(parse(mock.queries[-1].query)[1], {"path": "m/44'/0'/0'/0/0"})
        self.assertEqual(self.body(mock), [("bip137sig.seed", LIVE_SEED_PAYLOAD)])

    @bounded()
    async def test_an_omitted_path_sends_no_argument(self):
        """astrald's `opDeriveKeyArgs.Path` carries no `query:"required"` tag,
        so an absent path is the master key. Verified live."""
        answer = frame_of(PrivateKey(type=KEY_TYPE, key=MASTER_KEY))
        async with MockApphost(routes={OP_DERIVE_KEY: exchange(answer)}) as mock:
            api = await self.api(mock)
            key = await api.derive_key(Seed(ZERO_SEED))
        self.assertEqual(key.key, MASTER_KEY)
        self.assertEqual(mock.queries[-1].query, OP_DERIVE_KEY)

    @bounded()
    async def test_a_malformed_path_never_sends_the_seed(self):
        """A rejected query is a master secret that crossed the socket for
        nothing."""
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(ParseError) as caught:
                await api.derive_key(ZERO_SEED, "m/nope")
        self.assertIn("invalid path element", str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_seed_of_the_wrong_length_never_reaches_the_node(self):
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(ParseError) as caught:
                await api.derive_key(bytes(32))
        self.assertIn(OP_DERIVE_KEY, str(caught.exception))
        self.assertEqual(mock.queries, [])

    @bounded()
    async def test_a_seed_of_the_wrong_python_type_is_a_type_error(self):
        async with MockApphost() as mock:
            api = await self.api(mock)
            with self.assertRaises(BadArgumentType):
                await api.derive_key(ZERO_SEED.hex())  # type: ignore[arg-type]

    @bounded()
    async def test_the_answer_type_carries_the_mod_prefix(self):
        """Design objection D-21: astral-docs calls it `crypto.private_key`. The
        node sends `mod.crypto.private_key`, verified live, and a client that
        expected the documented name would decode nothing."""
        async with MockApphost(
            routes={
                OP_DERIVE_KEY: exchange(
                    raw_frame("crypto.private_key", payload_bytes(String16("x")))
                )
            }
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(AstralError):
                await api.derive_key(ZERO_SEED)
        self.assertEqual(PrivateKey.ASTRAL_TYPE, "mod.crypto.private_key")

    @bounded()
    async def test_an_error_message_raises(self):
        async with MockApphost(
            routes={OP_DERIVE_KEY: exchange(error_frame('invalid path element "nope"'))}
        ) as mock:
            api = await self.api(mock)
            with self.assertRaises(RemoteError) as caught:
                await api.derive_key(ZERO_SEED)
        self.assertIn("invalid path element", str(caught.exception))


class ModulePatternTest(Bip137SigCase):
    """The scaffolding design section 5.1 gives every module client."""

    @bounded()
    async def test_the_module_client_shares_the_one_expect(self):
        from astral.api.base import ModuleClient

        self.assertIs(Bip137Sig._expect, ModuleClient._expect)

    @bounded()
    async def test_every_op_forwards_the_query_keywords(self):
        async with MockApphost(
            routes={OP_NEW_ENTROPY: rr(frame_of(Entropy(ZERO_ENTROPY)))}
        ) as mock:
            api = await self.api(mock)
            await api.new_entropy(zone=Zone.DEVICE)
        self.assertEqual(mock.queries[-1].zone, Zone.DEVICE)

    @bounded()
    async def test_the_client_property_is_this_module_s(self):
        async with MockApphost() as mock:
            client = await self.client(mock)
            self.assertIsInstance(client.bip137sig, Bip137Sig)
            self.assertIs(client.bip137sig, client.bip137sig)
            self.assertIs(client.bip137sig.client, client)

    def test_the_types_tuple_is_the_module_s_own(self):
        self.assertEqual(tuple(Bip137Sig.TYPES), tuple(BIP137SIG_TYPES))

    def test_the_client_reference_is_the_one_it_was_given(self):
        self.assertIn("Bip137Sig(", repr(Bip137Sig(None)))  # type: ignore[arg-type]


class AstraldParityTest(unittest.TestCase):
    """The op inventory and the two claims that shape this client, from source."""

    ASTRALD = "mod/bip137sig/src"
    IMPLEMENTED = {"derive_key", "mnemonic", "new_entropy", "seed"}

    def source(self, repo: str, path: str) -> str:
        try:
            return reference.read(repo, path)
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))

    def test_every_op_astrald_serves_is_implemented_here(self):
        """Walked from `op_*.go` at the pinned revision. A partial module is
        worse than an absent one: callers cannot tell which half works."""
        try:
            names = reference.listdir(reference.ASTRALD, self.ASTRALD)
        except reference.Unavailable as exc:  # pragma: no cover -- may be absent
            self.skipTest(str(exc))
        ops = {
            name[len("op_") : -len(".go")]
            for name in names
            if name.startswith("op_") and name.endswith(".go")
        }
        self.assertEqual(ops, self.IMPLEMENTED)
        for name in ops:
            with self.subTest(op=name):
                self.assertTrue(hasattr(Bip137Sig, name))

    def test_no_op_reads_a_second_object_so_no_eos_is_ever_sent(self):
        """The claim the whole exchange shape rests on. Each op is one
        `ch.Receive()`, one `ch.Send()` and a deferred `ch.Close()`; none runs a
        `ch.Switch`, so nothing on the node ever reads a terminator."""
        for name in ("mnemonic", "seed", "derive_key"):
            source = self.source(reference.ASTRALD, f"{self.ASTRALD}/op_{name}.go")
            with self.subTest(op=name):
                self.assertEqual(source.count("ch.Receive()"), 1)
                self.assertNotIn("ch.Switch", source)
                self.assertIn("defer ch.Close()", source)

    def test_the_path_argument_is_not_required(self):
        """`Path` carries no `query:"required"` tag, which is what makes an
        absent path the master key rather than a rejected query."""
        source = self.source(reference.ASTRALD, f"{self.ASTRALD}/op_derive_key.go")
        declaration = source.split("type opDeriveKeyArgs struct {")[1].split("}")[0]
        self.assertIn("Path string", declaration)
        self.assertNotIn('Path string `query:"required"`', declaration)

    def test_the_four_ops_are_anonymous_callable_on_an_unclaimed_node(self):
        source = self.source(reference.ASTRALD, "mod/apphost/src/config.go")
        unclaimed = source.split("Unclaimed:")[1].split("Claimed:")[0]
        for op in (OP_NEW_ENTROPY, OP_MNEMONIC, OP_SEED, OP_DERIVE_KEY):
            with self.subTest(op=op):
                self.assertIn(f'"{op}"', unclaimed)

    def test_astral_go_derives_a_seed_without_normalising_it(self):
        """astral-go defect G-BIP39-NFKD, from the source that causes it. When
        `MnemonicToSeed` grows a normalisation, this fails and this SDK's
        pre-normalisation becomes redundant rather than load-bearing."""
        source = self.source(reference.ASTRAL_GO, "api/bip137sig/bip39.go")
        self.assertIn('salt := "mnemonic" + passphrase', source)
        self.assertNotIn("norm", source)

    def test_the_wordlist_is_astral_go_s_wordlist(self):
        """Two copies of 2048 words, and the pair must agree exactly: a mnemonic
        this SDK builds is one the node's `MnemonicToEntropy` decodes."""
        import re

        source = self.source(reference.ASTRAL_GO, "api/bip137sig/bip39_wordlist.go")
        words = re.findall(r'^\t"([a-z]+)",$', source, re.M)
        self.assertEqual(tuple(words), bip39.WORDLIST)

    def test_the_entropy_and_seed_lengths_are_astral_go_s(self):
        source = self.source(reference.ASTRAL_GO, "api/bip137sig/bip39.go")
        self.assertIn("MinEntropyBits   = 128", source)
        self.assertIn("MaxEntropyBits   = 256", source)
        self.assertIn("EntropyStepBits  = 32", source)
        self.assertIn("SeedLengthBytes  = 64", source)
        self.assertIn("DefaultEntropyBits = MinEntropyBits", source)

    def test_the_node_logs_the_query_string_of_every_routed_query(self):
        """Why `seed_local` is the preferred form: the passphrase is a query
        argument and every routed query string is logged at verbosity zero.

        The line number is asserted as well as the text, because both modules
        cite `core/router.go:81` and a citation nothing reads is a citation
        nobody re-reads. The pin is `reference.PINS`, so upstream drift is a
        deliberate bump here rather than a red suite on somebody else's pull."""
        lines = self.source(reference.ASTRALD, "core/router.go").splitlines()
        self.assertIn('Infov(0, "%v routed in %v", q.Query, d)', lines[80])


# --- Tier C: the live node ------------------------------------------------


class LiveBip137SigTest(live_support.LiveCase):
    """All four ops against a real node. Skips when none answers.

    Read-only in the sense that matters: every op generates or derives and
    stores nothing. The only values sent are the published BIP-39 test vectors,
    so nothing here is a secret and nothing here asks the node to derive one.
    """

    @bounded(30)
    async def test_new_entropy_answers_the_size_it_is_asked_for(self):
        """Design risk R-11 settled: `uint8` length and then the bytes."""
        client = await self.client()
        try:
            api = Bip137Sig(client)
            default = await api.new_entropy(timeout=10)
            self.assertIsInstance(default, Entropy)
            self.assertEqual(len(default), 16)
            self.assertEqual(default.bits, 128)

            wide = await api.new_entropy(256, timeout=10)
            self.assertEqual(len(wide), 32)

            again = await api.new_entropy(timeout=10)
            self.assertNotEqual(bytes(default), bytes(again))
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()

    @bounded(30)
    async def test_the_node_and_this_sdk_build_the_same_mnemonic(self):
        """Two implementations of BIP-39, one wordlist, one checksum rule."""
        client = await self.client()
        try:
            api = Bip137Sig(client)
            words = await api.mnemonic(ZERO_ENTROPY, timeout=10)
            self.assertEqual(words, ZERO_MNEMONIC.split())
            self.assertEqual(words, mnemonic_local(ZERO_ENTROPY))

            generated = await api.new_entropy(192, timeout=10)
            answered = await api.mnemonic(generated, timeout=10)
            self.assertEqual(len(answered), 18)
            self.assertEqual(answered, mnemonic_local(generated))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_the_node_and_this_sdk_derive_the_same_seed(self):
        """The one value a caller cannot check by eye, checked by a second
        implementation. The passphrase is the vector file's own."""
        client = await self.client()
        try:
            api = Bip137Sig(client)
            plain = await api.seed(ZERO_MNEMONIC, timeout=10)
            self.assertEqual(bytes(plain), ZERO_SEED)
            self.assertEqual(plain, seed_local(ZERO_MNEMONIC))

            salted = await api.seed(ZERO_MNEMONIC, passphrase="TREZOR", timeout=10)
            self.assertEqual(bytes(salted), TREZOR_SEED)
            self.assertEqual(salted, seed_local(ZERO_MNEMONIC, "TREZOR"))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_an_invalid_mnemonic_is_the_node_s_answer_too(self):
        """The SDK refuses it locally; this asserts the node agrees, so the
        local check is a shortcut and not a divergence."""
        client = await self.client()
        try:
            with self.assertRaises(RemoteError) as caught:
                await client.call_with(
                    OP_SEED,
                    String16(" ".join(["abandon"] * 12)),
                    eos=False,
                    expect=1,
                    timeout=10,
                )
            self.assertIn("invalid mnemonic", str(caught.exception))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_derive_key_answers_a_secp256k1_private_key(self):
        """D-21: the type name carries the `mod.` prefix that astral-docs drops.
        The seed is the published test seed and the keys under it are public."""
        client = await self.client()
        try:
            api = Bip137Sig(client)
            master = await api.derive_key(ZERO_SEED, timeout=10)
            self.assertIsInstance(master, PrivateKey)
            self.assertEqual(master.ASTRAL_TYPE, "mod.crypto.private_key")
            self.assertEqual(master.type, KEY_TYPE)
            self.assertEqual(master.key, MASTER_KEY)

            explicit = await api.derive_key(Seed(ZERO_SEED), "m", timeout=10)
            self.assertEqual(explicit.key, MASTER_KEY)

            account = await api.derive_key(ZERO_SEED, "m/44'/0'/0'/0/0", timeout=10)
            self.assertEqual(account.key, BIP44_KEY)
            self.assertEqual(len(account.key), 32)
        finally:
            await client.aclose()

    @bounded(30)
    async def test_the_node_refuses_the_paths_this_sdk_refuses(self):
        """The local grammar against the node's, in the node's own words. Driven
        through `call_with` because `derive_key` refuses this path before it
        sends -- which is the behaviour being justified."""
        client = await self.client()
        try:
            with self.assertRaises(ParseError):
                parse_derivation_path("nope")
            with self.assertRaises(RemoteError) as caught:
                await client.call_with(
                    "bip137sig.derive_key?path=nope",
                    Seed(ZERO_SEED),
                    eos=False,
                    expect=1,
                    timeout=10,
                )
            self.assertIn('invalid path element "nope"', str(caught.exception))
        finally:
            await client.aclose()

    @bounded(30)
    async def test_the_whole_chain_runs_through_the_node(self):
        """`new_entropy` to `derive_key`, four ops on one session, and every
        intermediate value checked against the local implementation."""
        client = await self.client()
        try:
            api = Bip137Sig(client)
            entropy = await api.new_entropy(timeout=10)
            words = await api.mnemonic(entropy, timeout=10)
            seed = await api.seed(words, timeout=10)
            self.assertEqual(seed, seed_local(words))
            key = await api.derive_key(seed, "m/0h", timeout=10)
            self.assertEqual(key.type, KEY_TYPE)
            self.assertEqual(len(key.key), 32)
        finally:
            await client.aclose()
        await self.assert_no_open_sockets()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
