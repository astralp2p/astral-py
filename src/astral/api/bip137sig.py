"""`bip137sig`: BIP-39 entropy, mnemonics and seeds, and BIP-32 key derivation.

Tier 2, four ops, and the whole of a wallet's key chain::

    new_entropy  ->  entropy  ->  mnemonic  ->  seed  ->  derive_key
                       16-32 B    12-24 words  64 B     a secp256k1 private key

| Op | Mode | Input | Answer | Effect |
|---|---|---|---|---|
| `bip137sig.new_entropy` | RR | `bits=` in the query string | `bip137sig.entropy` | generates, stores nothing |
| `bip137sig.mnemonic` | WA | `bip137sig.entropy` on the body | `string16` | pure computation |
| `bip137sig.seed` | WA | `string16` on the body, `passphrase=` | `bip137sig.seed` | pure computation |
| `bip137sig.derive_key` | WA | `bip137sig.seed` on the body, `path=` | `mod.crypto.private_key` | pure computation |

All four generate or derive and store nothing, on the node's side and on this
one; all four are on astrald's anonymous-web allowlist for an unclaimed node.

**The first three have a local form that needs no node**, because the values
they carry are the master secret of a wallet: `new_entropy_local`,
`mnemonic_local` and `seed_local` over `astral.bip39`, byte for byte the same
answers (verified against `furry-bolt`, and against the published BIP-39
vectors). The local form is the one to prefer, and the passphrase is why:
`bip137sig.seed` takes it as a **query argument**, and astrald writes the query
string of every routed query to its log at the default verbosity
(`astrald/core/router.go:81`, `Infov(0, "%v routed in %v", q.Query, d)`, over an
`astral.Query` that has no `String()`). One call to the node op therefore leaves
the passphrase in the node's log; `seed_local` leaves the process untouched.

**BIP-32 derivation has no local form.** Non-hardened child derivation needs a
point multiplication, so it needs the curve, and design section 5.2 rules that
`derive_key` routes to the node. `parse_derivation_path` is the half that is
pure: it refuses a malformed path here, before a seed crosses the socket.

**Not one of these ops reads to an `eos`, and this client never sends one.**
Each op body is a single `ch.Receive()`, a single `ch.Send()` and a deferred
`ch.Close()` (`astrald/mod/bip137sig/src/op_*.go`), so an `eos` written after
the input is never read: the node closes with unread data in its receive buffer,
which is a reset, and a reset discards the answer the node had already written.
This is the opposite of `crypto`, whose ops end their `ch.Switch` with
`BreakOnEOS` and need the terminator. Every exchange here is therefore one send
and one read, and `Client.call_with(expect=1)` is that shape.

Every op ends at a **bare EOF**, never at an `eos`. Verified live for all four,
including their error paths.

**An input the node cannot decode is answered with silence.** `Entropy.ReadFrom`
and `Seed.ReadFrom` validate the length and abort the frame, and the op returns
that read error without sending anything: verified live, an 8-byte entropy and a
32-byte seed both answer nothing at all and close. The wire types below validate
on encode for exactly this reason -- a length this SDK refuses to send is a
length that would have cost a round trip and a `ProtocolError` naming nothing.

**`derive_key` answers `mod.crypto.private_key`.** astral-docs says
`crypto.private_key` (design objection D-21); the name on the wire carries the
`mod.` prefix, verified live. The type is `api/crypto.py`'s and is not
redeclared here.

**Argument shapes, all live-verified against `furry-bolt`:**

- `bits` is optional and defaults to 128; `bits=0` also means 128 there, because
  astrald reads zero as absent. `bits=100` answers `invalid entropy size: 100`.
  This client sends no `bits` at all rather than a zero, and refuses zero rather
  than treating it as a second spelling of the default: `new_entropy()` is how
  the default is asked for.
- `path` is optional -- astrald's `opDeriveKeyArgs.Path` carries no
  `query:"required"` tag -- and an absent path, `""` and `m` all derive the
  master key. `m/` is not a path: it answers `invalid path element ""`.
- `passphrase` is optional. An empty passphrase is not an absent salt: the salt
  is `"mnemonic"` and then the passphrase.
- A mnemonic travels as one `string16` and the node splits it with
  `strings.Fields`, so any whitespace separates and leading whitespace is
  dropped.

Reached as `client.bip137sig`, a `functools.cached_property` built on first use.
"""

from __future__ import annotations

from typing import Any, Final, Sequence

from .. import bip39, querystring
from ..errors import BadArgument, BadArgumentType, ParseError, ProtocolError
from ..primitives import SCALARS, String16
from ..record import AliasRecord
from ..registry import default_blueprints
from ..spec import Primitive, Spec
from ..wire import Reader, Writer
from .base import ModuleClient
from .crypto import PrivateKey

__all__ = [
    "BIP137SIG_TYPES",
    "Bip137Sig",
    "Entropy",
    "OP_DERIVE_KEY",
    "OP_MNEMONIC",
    "OP_NEW_ENTROPY",
    "OP_SEED",
    "Seed",
    "mnemonic_local",
    "new_entropy_local",
    "parse_derivation_path",
    "seed_local",
]

OP_DERIVE_KEY: Final = "bip137sig.derive_key"
OP_MNEMONIC: Final = "bip137sig.mnemonic"
OP_NEW_ENTROPY: Final = "bip137sig.new_entropy"
OP_SEED: Final = "bip137sig.seed"

# The node declares `bits` as `int64` and `passphrase` and `path` as `string8`
# -- read from the live `shell.spec` registry. `int64` is not in the SDK's
# parameter vocabulary (`spec.PRIMITIVE_TYPES`), and `uint64` renders an integer
# identically; the value is checked against `bip39.ENTROPY_BITS` before it is
# encoded, so the narrower encoder can never meet a legal value it cannot carry.
_BITS: Final[Spec] = Primitive("uint64")
_STRING8: Final[Spec] = Primitive("string8")

# BIP-32's hardened offset: index `i'` is `i + 2**31`. astral-go's
# `ParseDerivationPath` sets the same bit and accepts `'` or `h` for it.
HARDENED_OFFSET: Final = 0x80000000

# `strconv.ParseUint(p, 10, 31)` in astral-go, so the largest unhardened index a
# path element can name is 2**31 - 1. Verified live: `m/2147483647h` derives and
# `m/2147483648` answers `invalid path element "2147483648"`.
MAX_INDEX: Final = HARDENED_OFFSET - 1

_HARDENED_MARKS: Final = ("'", "h")
_PATH_PREFIX: Final = "m/"
_MASTER: Final = ("", "m")


# --- the two wire types --------------------------------------------------


class _Bytes8Alias(AliasRecord):
    """A `bytes8` payload under its own type name, with a length rule.

    `bip137sig.entropy` and `bip137sig.seed` are both `type T []byte` in
    astral-go with a hand-rolled `WriteTo` that validates the length before it
    writes and after it reads (`api/bip137sig/entropy.go`, `seed.go`), so the
    rule is part of the wire contract and not an API nicety: astral-go aborts
    the frame either way. Design section 2.5 lists `bip137sig.entropy` as one of
    the four types that cannot be declared and must carry their own codec.

    **The zero value is constructible and is not encodable.** `Blueprints.new`
    needs a prototype and `T{}` is astral-go's, so the length is checked by every
    encoding rather than by `__init__`: `read_payload`, `write_payload`, `text`,
    `parse`, `json` and `from_json` all go through `_check`, and a value that
    fails it can be held and cannot cross any of the four framings.

    **The derived blueprint carries the layout and not the rule.**
    `blueprint.of` answers the `bytes8` alias, which is the payload exactly;
    `astral.blueprint` has no way to express a length constraint, so a peer that
    learns this type from a blueprint learns where the bytes end and not how
    many of them are legal.

    **The repr shows the length and never the bytes.** An entropy is a mnemonic
    is a seed is every key derived from it, and a repr reaches a log or a
    traceback without anybody choosing to put it there. `text()`, `hex()` and
    `bytes()` are the ways to see the value, and each is an explicit call.
    """

    __slots__ = ()

    UNDERLYING = "bytes8"

    def __init__(self, value: Any = b"") -> None:
        # `bytes(value)` is not the check: `bytes(64)` is 64 zero bytes, so an
        # integer would build a seed of the right length out of nothing at all,
        # and a hex string would build one twice the length it names.
        if isinstance(value, str):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got str; `.parse()` reads "
                "the hex form"
            )
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise BadArgumentType(
                f"{self.ASTRAL_TYPE}: expected bytes, got {type(value).__name__}"
            )
        super().__init__(bytes(value))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self.value)} bytes)"

    def __bytes__(self) -> bytes:
        return bytes(self.value)

    def __len__(self) -> int:
        return len(self.value)

    def hex(self) -> str:
        """The value in hex, under the name `bytes.hex` uses. `text()`'s twin."""
        return bytes(self.value).hex()

    def text(self) -> str:
        """astral-go's `MarshalText`, which is `hex.EncodeToString`.

        **The length rule holds here too, and in astral-go it does not.** Go
        checks it in `WriteTo`/`ReadFrom` and not in `MarshalText`/`UnmarshalText`
        (`api/bip137sig/entropy.go` at `5c18d9c`), so over there a JSON or text
        channel carries an entropy the binary channel refuses -- and once such a
        value exists nothing can re-emit it, because the only encoding it came
        through is the one that let it in. The rule belongs to the type rather
        than to one of its four encodings, so all four enforce it. Nothing legal
        is refused: a BIP-39 entropy is 16 to 32 bytes in steps of 4 and a seed
        is 64, in every framing.
        """
        return self._checked_hex()

    @classmethod
    def parse(cls, text: str) -> Any:
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise ParseError(f"{cls.ASTRAL_TYPE}: {text!r} is not hex") from exc
        return cls(cls._check(data))

    def json(self) -> str:
        """Hex, as `mod.crypto.hash` renders: the Go type's `MarshalText` wins
        over the base64 an undeclared alias would fall back to. Length-checked
        for the reason `text()` gives."""
        return self._checked_hex()

    def _checked_hex(self) -> str:
        """The hex form of a value this type is allowed to hold."""
        return bytes(self._check(bytes(self.value))).hex()

    @classmethod
    def from_json(cls, data: Any) -> Any:
        if not isinstance(data, str):
            raise ParseError(
                f"{cls.ASTRAL_TYPE}: expected a JSON string, got "
                f"{type(data).__name__}"
            )
        return cls.parse(data)

    @classmethod
    def read_payload(cls, r: Reader) -> Any:
        return cls(cls._check(SCALARS[cls.UNDERLYING].read(r)))

    def write_payload(self, w: Writer) -> None:
        SCALARS[self.UNDERLYING].write(w, self._check(bytes(self.value)))

    @staticmethod
    def _check(data: bytes) -> bytes:
        raise NotImplementedError  # pragma: no cover -- each subclass declares one


class Entropy(_Bytes8Alias):
    """BIP-39 entropy: 16 to 32 bytes in steps of 4, under a length prefix.

    `uint8 len` and then the bytes, and the length rule holds on encode and on
    decode. Verified live: `bip137sig.new_entropy?bits=128` answers `10` and 16
    bytes, `bits=256` answers `20` and 32 bytes (design risk R-11, settled).

    Secret. The mnemonic of an entropy is the entropy, and whoever holds either
    holds every key derived from them.
    """

    __slots__ = ()

    ASTRAL_TYPE = "bip137sig.entropy"

    @property
    def bits(self) -> int:
        """The entropy's size in bits, which is what `new_entropy` asks for."""
        return len(self.value) * 8

    @staticmethod
    def _check(data: bytes) -> bytes:
        return bip39.validate_entropy(data)


class Seed(_Bytes8Alias):
    """A BIP-39 seed: exactly 64 bytes, under a length prefix.

    The output of PBKDF2 over a mnemonic, and the input BIP-32 derives every key
    from. astral-go's `Seed.WriteTo` refuses any other length and its `ReadFrom`
    refuses it too, so a 32-byte seed cannot be sent at all.

    Secret, and the most concentrated of the three: a seed is a whole wallet.
    """

    __slots__ = ()

    ASTRAL_TYPE = "bip137sig.seed"

    @staticmethod
    def _check(data: bytes) -> bytes:
        if len(data) != bip39.SEED_LENGTH:
            raise ParseError(
                f"bip137sig.seed: {len(data)} bytes is not a seed; BIP-39 seeds "
                f"are {bip39.SEED_LENGTH} bytes"
            )
        return data


default_blueprints().add(Entropy, Seed)


# --- the local forms, which need no node ---------------------------------


def new_entropy_local(bits: int = bip39.DEFAULT_ENTROPY_BITS) -> Entropy:
    """Fresh entropy from this machine's CSPRNG. `bip137sig.new_entropy` local.

    The node's op generates from `crypto/rand` and sends the bytes over the IPC
    socket; this one keeps them here.
    """
    return Entropy(bip39.new_entropy(bits))


def mnemonic_local(entropy: Entropy | bytes | bytearray | memoryview) -> list[str]:
    """The mnemonic of an entropy. `bip137sig.mnemonic` without the node."""
    return bip39.entropy_to_mnemonic(_entropy_bytes(entropy, "mnemonic_local"))


def seed_local(mnemonic: str | Sequence[str], passphrase: str = "") -> Seed:
    """The seed of a mnemonic under a passphrase. `bip137sig.seed` without the node.

    The passphrase never leaves this process, where the op puts it in the node's
    log. Both are NFKD-normalised, which BIP-39 requires and astral-go omits.
    """
    return Seed(bip39.mnemonic_to_seed(mnemonic, passphrase))


def parse_derivation_path(path: str) -> tuple[int, ...]:
    """A BIP-32 path as child indices, or the fault in it.

    astral-go's `ParseDerivationPath` (`api/bip137sig/bip32.go`), rule for rule,
    so a path this function accepts is a path the node accepts:

    - `""` and `"m"` are the master key, and derive nothing.
    - One leading `m/` is stripped; nothing else is. `44'/0'` is therefore a
      valid path and `/0` is not, verified live.
    - A trailing `'` or `h` is hardened and sets bit 31.
    - An element is a decimal integer of at most 31 bits. `2147483648`, `-1`,
      `0x10` and the empty element are each `invalid path element` on the node
      and a `ParseError` here.

    The check is local so that a malformed path costs no query, which matters
    here more than elsewhere: the seed is the input, and a rejected query is a
    seed that crossed the socket for nothing.
    """
    if not isinstance(path, str):
        raise BadArgumentType(
            f"{OP_DERIVE_KEY}: path must be str, got {type(path).__name__}"
        )
    if path in _MASTER:
        return ()
    body = path[len(_PATH_PREFIX) :] if path.startswith(_PATH_PREFIX) else path

    indices: list[int] = []
    for element in body.split("/"):
        text = element
        hardened = text.endswith(_HARDENED_MARKS)
        if hardened:
            text = text[:-1]
        # `str.isdigit()` before `int()`: `int()` accepts a sign, an underscore
        # and Unicode digits, none of which `strconv.ParseUint` reads.
        if not text.isascii() or not text.isdigit():
            raise ParseError(f'{OP_DERIVE_KEY}: invalid path element "{element}"')
        index = int(text)
        if index > MAX_INDEX:
            raise ParseError(f'{OP_DERIVE_KEY}: invalid path element "{element}"')
        indices.append(index + HARDENED_OFFSET if hardened else index)
    return tuple(indices)


# --- the client ----------------------------------------------------------


class Bip137Sig(ModuleClient):
    """The `bip137sig` ops, over one `Client`.

    Reached as `client.bip137sig`; `Bip137Sig(client)` constructs the same
    object. The scaffolding and the `**kw` contract are `ModuleClient`'s.

    Three of the four ops have a local counterpart that needs no node
    (`new_entropy_local`, `mnemonic_local`, `seed_local`). The ops exist for the
    caller who wants the node's answer -- a node with an HSM behind it, or a
    check against a second implementation -- and every one of them puts secret
    material on the IPC socket.
    """

    __slots__ = ()

    async def new_entropy(self, bits: int | None = None, **kw: Any) -> Entropy:
        """Fresh entropy from the node. RR, no `eos`.

        `bits` omitted leaves astrald's default of 128, in the rule design
        section 5.1 states for every optional argument: the server's default
        stands unless the caller asks for something else. A size BIP-39 does not
        define is refused here rather than sent, because the node's answer to
        one is an `error_message` and a round trip.

        `new_entropy_local` is the same value without the node.
        """
        params: dict[str, Any] = {}
        if bits is not None:
            if isinstance(bits, bool) or not isinstance(bits, int):
                raise BadArgumentType(
                    f"{OP_NEW_ENTROPY}: bits must be an int, got "
                    f"{type(bits).__name__}"
                )
            if bits not in bip39.ENTROPY_BITS:
                # `BadArgument`, as `bip39.new_entropy` raises for the same
                # fault: a size the caller named is an argument value, where a
                # length the type refuses is a `ParseError` on both sides of the
                # wire. One fault, one class, whichever door it comes through.
                raise BadArgument(
                    f"{OP_NEW_ENTROPY}: {bits} is not an entropy size; BIP-39 "
                    f"defines {', '.join(str(b) for b in bip39.ENTROPY_BITS)} bits"
                )
            params["bits"] = self._param(_BITS, bits)
        obj = await self._c.call_one(
            querystring.build(OP_NEW_ENTROPY, params), **kw
        )
        return self._expect(obj, Entropy, OP_NEW_ENTROPY)

    async def mnemonic(
        self, entropy: Entropy | bytes | bytearray | memoryview, **kw: Any
    ) -> list[str]:
        """The mnemonic of an entropy, computed by the node. WA, one exchange.

        The entropy travels on the channel body, which is the whole of this op's
        input: it declares no argument but `in` and `out`.

        The answer is one `string16` of space-joined words, and it is checked
        against the entropy that was sent before it is returned. The check is
        local, costs no query, and is worth making: a mnemonic that does not
        decode to the entropy behind it is a wrong seed and every key under it,
        and this SDK's own `bip39` is the second implementation that makes the
        check possible.
        """
        data = _entropy_bytes(entropy, OP_MNEMONIC)
        answer = await self._exchange(
            OP_MNEMONIC, Entropy(data), String16, OP_MNEMONIC, kw
        )
        words = bip39.words_of(str(answer))
        try:
            decoded = bip39.mnemonic_to_entropy(words)
        except ParseError as exc:
            raise ProtocolError(
                f"{OP_MNEMONIC}: the node answered a mnemonic this SDK cannot "
                f"decode ({exc})"
            ) from exc
        if decoded != data:
            raise ProtocolError(
                f"{OP_MNEMONIC}: the node answered the mnemonic of a different "
                "entropy"
            )
        return words

    async def seed(
        self,
        mnemonic: str | Sequence[str],
        *,
        passphrase: str = "",
        **kw: Any,
    ) -> Seed:
        """The BIP-39 seed of a mnemonic, computed by the node. WA, one exchange.

        **The passphrase reaches the node's log.** It is a query argument and
        astrald logs every routed query string; `seed_local` is the same
        computation with nothing on the socket and nothing in the log.

        The mnemonic is validated here before it is sent, by the same rules the
        node applies, so a typo names the word that is wrong rather than
        answering `invalid mnemonic`.

        Both the mnemonic and the passphrase are NFKD-normalised before they are
        sent, which is what BIP-39 requires of them. astral-go omits the step,
        so the node derives one seed for `é` as U+00E9 and another for U+0065
        U+0301 -- verified live -- and only the normalised form is the seed
        BIP-39 defines. Normalising here feeds the node the input that makes its
        own answer standard.
        """
        if not isinstance(passphrase, str):
            raise BadArgumentType(
                f"{OP_SEED}: passphrase must be str, got {type(passphrase).__name__}"
            )
        words = bip39.words_of(mnemonic)
        bip39.mnemonic_to_entropy(words)
        params: dict[str, Any] = {}
        if passphrase:
            params["passphrase"] = self._param(_STRING8, bip39.normalize(passphrase))
        return await self._exchange(
            querystring.build(OP_SEED, params),
            String16(" ".join(words)),
            Seed,
            OP_SEED,
            kw,
        )

    async def derive_key(
        self, seed: Seed | bytes | bytearray | memoryview, path: str = "", **kw: Any
    ) -> PrivateKey:
        """The `secp256k1` key a BIP-32 path derives from a seed. WA, one exchange.

        The answer is a `mod.crypto.private_key`, whatever astral-docs calls it
        (D-21). Its `Type` is `secp256k1` and its `Key` is the 32-byte scalar.

        `path` empty derives the master key, which is astrald's own behaviour
        for an absent argument. A malformed path is refused here, so the seed is
        not sent to be rejected.

        **The seed crosses the IPC socket.** There is no local form: BIP-32
        needs a point multiplication for every non-hardened element, so it needs
        the curve, and design section 5.2 rules that this op routes to the node.
        """
        parse_derivation_path(path)
        params = {"path": self._param(_STRING8, path)} if path else {}
        return await self._exchange(
            querystring.build(OP_DERIVE_KEY, params),
            Seed(_seed_bytes(seed, OP_DERIVE_KEY)),
            PrivateKey,
            OP_DERIVE_KEY,
            kw,
        )

    async def _exchange(
        self, qs: str, value: Any, kind: type, op: str, kw: dict[str, Any]
    ) -> Any:
        """Send one object, read one answer, send no `eos`.

        The shape all three body ops share. `expect=1` rather than reading to
        the stream's end for the reason the terminator is absent: the op reads
        exactly one object, answers it and closes, so there is nothing after the
        answer to wait for.

        A stream that ends without answering is the op having failed inside its
        own read -- an input length its `ReadFrom` refuses -- and the wire types
        make that unreachable from here, so it is reported as the protocol fault
        it would be rather than as an empty list.
        """
        answers = await self._c.call_with(qs, value, eos=False, expect=1, **kw)
        if not answers:
            raise ProtocolError(f"{op}: the stream ended before answering")
        return self._expect(answers[0], kind, op)


# --- argument discipline -------------------------------------------------


def _entropy_bytes(value: Entropy | bytes | bytearray | memoryview, op: str) -> bytes:
    """An entropy argument, validated before it can reach the wire."""
    return _checked(Entropy, value, op)


def _seed_bytes(value: Seed | bytes | bytearray | memoryview, op: str) -> bytes:
    """A seed argument, validated before it can reach the wire."""
    return _checked(Seed, value, op)


def _checked(kind: type, value: Any, op: str) -> bytes:
    """The bytes of a wire-type argument, by that type's own length rule.

    The type's validator rather than a second copy of the rule, so the op and
    the encoder can never disagree about what a legal value is. The op is named
    in the message because the node answers an input it cannot decode with
    silence and a closed stream: a `ProtocolError` about an empty stream names
    nothing at all, and this is the fault it would have been.
    """
    if not isinstance(value, (kind, bytes, bytearray, memoryview)):
        raise BadArgumentType(
            f"{op}: expected bytes or {kind.__name__}, got {type(value).__name__}"
        )
    try:
        return kind._check(bytes(value))  # noqa: SLF001 -- the type's own rule
    except ParseError as exc:
        raise ParseError(f"{op}: {exc}") from exc


BIP137SIG_TYPES: Final[Sequence[type]] = (Entropy, Seed)
"""Every wire type this module declares, for a private-registry sweep.

`mod.crypto.private_key` is `api/crypto.py`'s and is registered there;
`registry.add(*Bip137Sig.TYPES, *Crypto.TYPES)` is what a private registry needs
to decode every answer these four ops give.
"""

Bip137Sig.TYPES = BIP137SIG_TYPES
