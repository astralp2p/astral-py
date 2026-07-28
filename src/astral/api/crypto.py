"""`crypto`: keys, hashes, signatures, and the folded `secp256k1`.

Tier 1. Six ops -- the five `crypto.*` ops plus `secp256k1.new`, which design
sections 0.1 and 5.2 fold in here rather than giving it a module of its own --
and four pure local helpers that need no node at all.

| Op | Mode | Input | Answer | Effect |
|---|---|---|---|---|
| `crypto.public_key` | WA | `mod.crypto.private_key` on the body | `mod.crypto.public_key` per input | pure computation |
| `crypto.sign_hash` | RR | `hash=` in the query string | `mod.crypto.signature` | **uses a node-held private key** |
| `crypto.sign_hash` | WA | `mod.crypto.hash` on the body | one signature per hash | **uses a node-held private key** |
| `crypto.sign_text` | WA | `string16` on the body | one signature per text | **uses a node-held private key** |
| `crypto.verify_hash_signature` | WA | `mod.crypto.signature` on the body | `ack` \\| `error_message` | read-only |
| `crypto.verify_text_signature` | WA | `string16` then `mod.crypto.signature` | `ack` \\| `error_message` | read-only |
| `secp256k1.new` | RR | -- | `mod.crypto.private_key` | generates, stores nothing |

**Not one of these ops sends `eos`.** astral-go's `Channel.Close` closes the
transport and writes no terminator (`astral/channel/channel.go` `Close`), and
every crypto op ends in `defer ch.Close()`, so each one terminates at EOF. The
SDK sends `eos` on the ops that read a body, because every one of them ends its
`ch.Switch` with `channel.BreakOnEOS` and so leaves its read loop on the
terminator rather than on a read error.

**The input shape is the trap this module is famous for.** astral-js and
astral-py once shared a bug in which `crypto.public_key`,
`crypto.verify_text_signature` and `crypto.verify_hash_signature` were driven
with query arguments alone. There is no `signature` query argument and there
never was: verification is triggered only by a `mod.crypto.signature` arriving
on the channel body (`mod/crypto/src/op_verify_hash_signature.go`,
`op_verify_text_signature.go`), so an implementation that never streams one
gets an accepted query, no answer, EOF -- and, if it reports that as success,
**silently never verifies**. Every shape below was read out of astrald's
`mod/crypto/src` at `074a852b`, never out of a sibling SDK.

**One rule decides where each value travels**, and it is stated once here so no
method has to argue it again:

> A value the op accepts as a query argument travels as a query argument when it
> is bounded and public -- `hash`, `key`, `scheme`. A value that is unbounded or
> is itself content travels on the body -- `text`. A value with no query
> argument at all travels on the body -- `private_key`, `signature`. A batch
> always travels on the body, because a query argument names exactly one value.

So `sign_hash` puts its digest in the query string and `sign_text` does not put
its text there: a hash is a fixed-width public digest, a text is the content
being signed, it has no length bound, and **astrald writes the query string of
every routed query to its log at the default verbosity** --
`astrald/core/router.go` answers each one with
`Infov(0, "%v routed in %v", q.Query, d)`, and `astral.Query` has no `String()`,
so `%v` renders the struct with `QueryString` in it.

**`crypto.public_key` crashes the node when the key type is not `secp256k1`.**
`OpPublicKey` sends `secp256k1.PublicKey(key)` straight onto the channel, and
that function returns a **nil** `*crypto.PublicKey` for any other key type
(`astral-go/api/secp256k1/module.go` `PublicKey`, line 31). Every sender starts
with `object.ObjectType()`, `ObjectType` is declared on the value receiver, and
calling it through a nil pointer dereferences nil. Nothing recovers: the op runs
in a bare `go func()` (`astral-go/lib/routing/op.go` `RouteQuery`, line 90) and
there is exactly one `recover()` in either repository, in `astrald/debug`, which
re-panics anyway.

**No authentication stands between a caller and it.** An IPC guest is never
gated -- `blocksAnonymousWeb` returns false for an empty web origin, so a local
process needs no token at all -- and an unauthenticated *browser* guest reaches
it too while the node is unclaimed, because `crypto.public_key` is on the
`anonymous_web_allowlist.Unclaimed` list (`mod/apphost/src/config.go`, line 70).
**`public_key()` refuses a foreign key type before it sends anything**; that
guard is the most load-bearing line in this file.

It is the same defect class as `objects.new?type=mod.nodes.node_info`, and that
one has been fixed -- astral-go `0a15afb`, "stop NodeInfo.WriteTo panicking on a
nil Identity", substitutes the zero identity for a nil pointer. This one has
not, and is the sharper of the two: `NodeInfo` needed a nil field *inside* a
value, where `OpPublicKey` hands the channel a nil *object* and the panic lands
in `ObjectType()` before any field is read.

**`crypto.sign_text` ignores a public key streamed on its body.**
`OpSignText` builds its signer from `signerKey` *before* entering `ch.Switch`
(`mod/crypto/src/op_sign_text.go`, line 38); the `*crypto.PublicKey` branch then
assigns to `signerKey` and answers `ack`, but `signer` has already captured the
old key, so the text is signed as the caller and the `ack` says otherwise. Its
sibling `OpSignHash` builds the signer *inside* `signAndSend` and does honour a
streamed key, which is what makes this an oversight rather than a design. This
SDK sends `key` as a query argument on every sign and verify op, which is
parsed before the switch and therefore works on both -- so nothing here depends
on the broken path, and nothing here can be repaired into depending on it.

**A failed verification is an `error_message`, not a failure.** Both verify ops
answer `ack` on success and `astral.Err(err)` on anything else, so an exception
would turn "this signature is invalid" -- the ordinary answer -- into a raised
error. `verify_hash_signature` and `verify_text_signature` return a `Verdict`,
which is a `bool` carrying the responder's own words, because "false" alone
cannot distinguish an invalid signature from a scheme no engine on that node
implements. `apphost.cancel` reads its stream the same way and for the same
reason.

**Schemes.** `asn1` for hashes, `bip137` for text; both are astrald's defaults
and neither is sent unless the caller asks (design section 5.1, rule 5). Only
one engine serves each: `mod/secp256k1/src/engine.go` refuses anything but
`secp256k1` keys and `asn1` hash signatures, `mod/bip137sig/src/engine.go`
anything but `bip137` text signatures. When no engine matches, astrald's
`dispatchVerify` answers `unsupported`; `invalid signature` is the verdict.

**secp256k1 is folded in, and is not a separate module** (design section 5.2).
An `astral.Identity` *is* a compressed secp256k1 public key, so
`identity_to_public_key` and `public_key_to_identity` are re-tagging with no
curve math and are always available. `new_key()` is the `secp256k1.new` op, so
it needs no curve library either -- the node does the arithmetic.
`generate_key_local()` and `public_key_of()` are the only two that need one, and
without the optional extra `astral-ipc[secp256k1]` they raise
`FeatureUnavailable` naming it. Nothing else in this module, or anywhere else in
the SDK, degrades without the extra: **the SDK never validates that a 33-byte
identity is a point on the curve**, deliberately, because that check would put a
curve library under the most common decode in the protocol.

Reached as `client.crypto`, the `functools.cached_property` design section 5.1
asks for, or as `Crypto(client)`, which constructs the same object and is what
the tests here use.

Source citations are pinned to astrald `074a852b` and astral-go `5c18d9c`. Both
references have moved since -- astrald to `3392926b`, astral-go to `0a15afb` --
and `mod/crypto`, `mod/secp256k1`, `mod/bip137sig`, `api/crypto` and
`api/secp256k1` are byte for byte unchanged across both moves, so every line
number above still resolves at either end. `tests/test_api_crypto.py` reads
those directories rather than trusting this paragraph.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final, Iterable, Sequence

from .. import querystring
from ..codec.jsoncodec import decode_base64, encode_base64
from ..errors import (
    BadArgument,
    BadArgumentType,
    FeatureUnavailable,
    ParseError,
    ProtocolError,
)
from ..primitives import String16
from ..record import AliasRecord, record, wire
from ..registry import default_blueprints
from ..spec import Primitive, Spec
from ..types import Identity
from .base import ModuleClient

__all__ = [
    "CRYPTO_TYPES",
    "Crypto",
    "Hash",
    "KEY_TYPE",
    "OP_NEW_KEY",
    "OP_PUBLIC_KEY",
    "OP_SIGN_HASH",
    "OP_SIGN_TEXT",
    "OP_VERIFY_HASH_SIGNATURE",
    "OP_VERIFY_TEXT_SIGNATURE",
    "PrivateKey",
    "PublicKey",
    "SCHEME_ASN1",
    "SCHEME_BIP137",
    "SECP256K1_EXTRA",
    "Signature",
    "Verdict",
    "generate_key_local",
    "identity_to_public_key",
    "public_key_of",
    "public_key_to_identity",
]


# --- op names ------------------------------------------------------------

OP_PUBLIC_KEY: Final = "crypto.public_key"
OP_SIGN_HASH: Final = "crypto.sign_hash"
OP_SIGN_TEXT: Final = "crypto.sign_text"
OP_VERIFY_HASH_SIGNATURE: Final = "crypto.verify_hash_signature"
OP_VERIFY_TEXT_SIGNATURE: Final = "crypto.verify_text_signature"

# The one folded op. Its name has no `crypto.` prefix: it is registered by the
# `secp256k1` module on the node and the op name is what travels.
OP_NEW_KEY: Final = "secp256k1.new"

# The only key type any engine on a stock node implements, and the type
# `Identity` is: `astral-go/api/secp256k1/module.go` `KeyType`.
KEY_TYPE: Final = "secp256k1"

# astrald's defaults, one per signable form. `mod/secp256k1/src/engine.go`
# serves `asn1` hash signatures and `mod/bip137sig/src/engine.go` serves
# `bip137` text signatures; there is no third.
SCHEME_ASN1: Final = "asn1"
SCHEME_BIP137: Final = "bip137"

# Named in every `FeatureUnavailable` this module raises, so the message says
# what to install rather than that something is missing.
SECP256K1_EXTRA: Final = "astral-ipc[secp256k1]"

# The two answers a verify op can end on, matched by **type name** and not by
# class -- exactly as `stream._is_error` and `channel.is_eos` match, so a type
# decoded through a runtime blueprint under the same name reads the same way.
_ACK_TYPE: Final = "ack"
_ERROR_TYPE: Final = "error_message"

# What a `bytes8` length prefix can carry, and therefore the widest digest that
# fits in a `mod.crypto.hash`. A SHA-256 uses 32 of them.
_MAX_HASH: Final = 255

# Every parameter of every op here is declared `string8` on the node -- verified
# against the live `shell.spec` registry, which reports `hash`, `key`, `scheme`,
# `in` and `out` as `string8` for all five `crypto.*` ops. The *content* of
# `hash` is hex and of `key` is a public key's own text form; neither is a
# distinct wire type in the parameter, so neither gets one here (design section
# 5.1, rule 2).
_PARAMS: Final[dict[str, Spec]] = {
    "hash": Primitive("string8"),
    "key": Primitive("string8"),
    "scheme": Primitive("string8"),
}


# --- the four wire types -------------------------------------------------


class Hash(AliasRecord):
    """A digest to be signed or verified. `bytes8` on the wire, hex as text.

    astral-go declares `type Hash []byte` whose `WriteTo` is
    `astral.Bytes8(hash).WriteTo` (`api/crypto/hash.go`), so the payload is a
    `uint8` length and then the bytes: **a hash on this wire cannot exceed 255
    bytes**, which no digest astrald signs comes near. `SignableHash()` on
    `mod.auth.contract` and `mod.user.expulsion` is the object's content hash,
    32 bytes.

    An alias kind rather than a record: one primitive payload under a distinct
    type name. The text and JSON forms are hex and are declared here rather than
    inherited, because `AliasRecord` has neither and the base64 fallback
    `codec.text.encode` would otherwise choose is legal on the wire but is not
    what astral-go emits -- `Hash.MarshalText` is `hex.EncodeToString`.
    """

    __slots__ = ()

    ASTRAL_TYPE = "mod.crypto.hash"
    UNDERLYING = "bytes8"

    def __init__(self, value: Any = b"") -> None:
        super().__init__(bytes(value))

    def __repr__(self) -> str:
        return f"Hash({bytes(self.value).hex()})"

    def text(self) -> str:
        return bytes(self.value).hex()

    @classmethod
    def parse(cls, text: str) -> "Hash":
        try:
            return cls(bytes.fromhex(text))
        except ValueError as exc:
            raise ParseError(f"mod.crypto.hash: {text!r} is not hex") from exc

    def json(self) -> str:
        return self.text()

    @classmethod
    def from_json(cls, data: Any) -> "Hash":
        if not isinstance(data, str):
            raise ParseError(
                f"mod.crypto.hash: expected a JSON string, got {type(data).__name__}"
            )
        return cls.parse(data)


default_blueprints().add(Hash)


@record("mod.crypto.private_key")
class PrivateKey:
    """A private key: the algorithm that owns it, and the secret itself.

    **`key` is a secret.** For `secp256k1` it is the 32-byte scalar,
    `dcrd`'s `PrivateKey.Serialize()`, and whoever holds it is the identity it
    derives. This SDK produces one in `new_key()` and `generate_key_local()`;
    it also *decodes* one wherever a stream carries it, because a private key is
    an ordinary stored object -- astrald's crypto module scans its repositories
    for exactly this type (`mod/crypto/src/module.go` `indexRepo`).

    The text form is `"<type>:<base64>"` -- base64, where a *public* key's text
    form is hex. The asymmetry is astral-go's (`api/crypto/private_key.go`
    against `public_key.go`) and is preserved rather than tidied, because both
    forms are parsed by the node.
    """

    type: str = wire("Type", Primitive("string8"))  # noqa: A003
    key: bytes = wire("Key", Primitive("bytes16"))

    @property
    def is_secp256k1(self) -> bool:
        """Whether any engine on a stock node can do anything with this key."""
        return self.type == KEY_TYPE

    def text(self) -> str:
        return f"{self.type}:{encode_base64(bytes(self.key))}"

    @classmethod
    def parse(cls, text: str) -> "PrivateKey":
        type_name, secret = _split_key_text(text, "mod.crypto.private_key")
        return cls(type=type_name, key=decode_base64(secret))


@record("mod.crypto.public_key")
class PublicKey:
    """A public key: the algorithm that owns it, and the point.

    For `secp256k1` the key is 33 bytes, the compressed point, and is byte for
    byte an `astral.Identity` -- `public_key_to_identity` and
    `identity_to_public_key` are that equivalence, with no curve math on either
    side.

    The text form is `"<type>:<hex>"`, which is what the `key` query argument of
    every sign and verify op carries.
    """

    type: str = wire("Type", Primitive("string8"))  # noqa: A003
    key: bytes = wire("Key", Primitive("bytes16"))

    @property
    def is_secp256k1(self) -> bool:
        return self.type == KEY_TYPE

    def text(self) -> str:
        return f"{self.type}:{bytes(self.key).hex()}"

    @classmethod
    def parse(cls, text: str) -> "PublicKey":
        type_name, point = _split_key_text(text, "mod.crypto.public_key")
        try:
            return cls(type=type_name, key=bytes.fromhex(point))
        except ValueError as exc:
            raise ParseError(f"mod.crypto.public_key: {point!r} is not hex") from exc


@record("mod.crypto.signature")
class Signature:
    """A signature and the scheme that produced it.

    The scheme is not decoration: astrald dispatches on it
    (`mod/crypto/src/module.go` `Verify`) and each engine refuses every scheme
    but its own, so a signature whose scheme is wrong is answered `unsupported`
    rather than `invalid signature`. The text form is `"<scheme>:<base64>"`.
    """

    scheme: str = wire("Scheme", Primitive("string8"))
    data: bytes = wire("Data", Primitive("bytes16"))

    def text(self) -> str:
        return f"{self.scheme}:{encode_base64(bytes(self.data))}"

    @classmethod
    def parse(cls, text: str) -> "Signature":
        scheme, data = _split_key_text(text, "mod.crypto.signature")
        return cls(scheme=scheme, data=decode_base64(data))


def _split_key_text(text: str, type_name: str) -> tuple[str, str]:
    """`"<prefix>:<body>"`, split once. astral-go's `strings.SplitN(s, ":", 2)`.

    A missing colon is `invalid format` there and a `ParseError` here; the two
    halves are never both optional, so an empty prefix is refused as well.
    """
    prefix, separator, body = text.partition(":")
    if not separator:
        raise ParseError(f"{type_name}: {text!r} has no ':' separator")
    if not prefix:
        raise ParseError(f"{type_name}: {text!r} has an empty type")
    return prefix, body


# --- the verification answer ---------------------------------------------


class Verdict(int):
    """The answer to a verification: a `bool` that carries the reason.

    `bool(verdict)`, `if verdict:` and `verdict == True` all behave as the plain
    boolean this replaces; `verdict is True` does not, and nothing in this SDK
    asks for identity against a literal.

    It exists because astrald reports every unsuccessful verification the same
    way -- one `error_message` on the stream -- and the messages are not
    interchangeable. `invalid signature` is a verdict about the signature;
    `unsupported` is astrald saying no engine on that node implements the
    scheme or the key type at all (`mod/crypto/errors.go`, and `dispatchVerify`
    in `mod/crypto/src/dispatch.go`); `missing hash` and `missing text` are the
    op saying the exchange was incomplete. A bare `False` conflates all four,
    and the difference between "this is forged" and "this node cannot tell" is
    the whole question a caller is asking.
    """

    # No `__slots__`: `int` is a variable-length type and CPython refuses a
    # non-empty slots list on a subclass of one. The instance dict is the cost
    # of carrying the reason, and one Verdict is built per verification.
    message: str

    def __new__(cls, ok: object, message: str = "") -> "Verdict":
        verdict = super().__new__(cls, 1 if ok else 0)
        verdict.message = message
        return verdict

    def __repr__(self) -> str:
        state = "True" if self else "False"
        if not self.message:
            return f"Verdict({state})"
        return f"Verdict({state}, {self.message!r})"


# --- the pure helpers (design section 5.2) -------------------------------


def identity_to_public_key(identity: Identity) -> PublicKey:
    """An identity as a `secp256k1` public key. No curve math, no node.

    An `astral.Identity` is exactly a compressed secp256k1 public key, so this
    is a re-tagging: the 33 bytes are copied unchanged under the `secp256k1`
    type name. astral-go's `secp256k1.FromIdentity` does the same thing by way
    of `PublicKey().SerializeCompressed()`.

    The zero identity is refused. It is 33 zero bytes, which is not a point on
    the curve, so a key made from it can neither verify nor sign anything: the
    node's engine reaches `secp256k1.ParsePubKey`, fails, and answers
    `invalid signature: ...` -- a verdict about the *signature*, for a fault
    that was in the key.
    """
    if not isinstance(identity, Identity):
        raise BadArgumentType(
            f"identity_to_public_key: expected an Identity, got "
            f"{type(identity).__name__}"
        )
    if identity.is_zero:
        raise BadArgument(
            "identity_to_public_key: the zero identity is not a point on the "
            "curve; it names nobody and can verify nothing"
        )
    return PublicKey(type=KEY_TYPE, key=identity.key)


def public_key_to_identity(key: PublicKey) -> Identity:
    """A `secp256k1` public key as an identity. No curve math, no node.

    The inverse of `identity_to_public_key`, and astral-go's
    `secp256k1.Identity` minus its curve check: that function parses the point
    and answers nil when it is not on the curve, where this one hands back 33
    opaque bytes. The divergence is design section 5.2's and is deliberate --
    the SDK never puts a curve library under an identity decode.

    A key of another type is refused, because the bytes of an ed25519 key are
    not an astral identity and silently re-tagging them would produce one that
    routes nowhere.
    """
    if not isinstance(key, PublicKey):
        raise BadArgumentType(
            f"public_key_to_identity: expected a PublicKey, got {type(key).__name__}"
        )
    if not key.is_secp256k1:
        raise BadArgument(
            f"public_key_to_identity: key type {key.type!r} is not {KEY_TYPE!r}; "
            "an astral identity is a compressed secp256k1 public key and nothing else"
        )
    if len(key.key) != Identity.SIZE:
        raise BadArgument(
            f"public_key_to_identity: expected {Identity.SIZE} bytes, got "
            f"{len(key.key)}"
        )
    return Identity(bytes(key.key))


def generate_key_local() -> PrivateKey:
    """A fresh `secp256k1` private key, generated here. **Needs the extra.**

    The offline counterpart of `Crypto.new_key()`, which asks the node. Prefer
    this one when the key must not cross a socket, and that one when the extra
    is not installed -- the node's generator is the same arithmetic and the SDK
    ships no third option.

    Raises `FeatureUnavailable` without `astral-ipc[secp256k1]`. secp256k1
    arithmetic cannot be implemented responsibly in pure Python: constant-time
    behaviour and point validation are the whole of the security argument and
    neither survives a hand-rolled `pow()` (design section 8.1).
    """
    curve = _curve("generate_key_local")
    return PrivateKey(type=KEY_TYPE, key=bytes(curve.PrivateKey().secret))


def public_key_of(private_key: PrivateKey) -> PublicKey:
    """The public key of a private key, computed here. **Needs the extra.**

    The offline counterpart of `Crypto.public_key()`. Point multiplication, so
    it needs the curve library that `generate_key_local` needs, and it refuses
    the same foreign key types the node would crash on.
    """
    _require_private_key(private_key, "public_key_of")
    if not private_key.is_secp256k1:
        raise BadArgument(
            f"public_key_of: key type {private_key.type!r} is not {KEY_TYPE!r}; "
            "no curve here derives a public key for it"
        )
    curve = _curve("public_key_of")
    try:
        derived = curve.PrivateKey(bytes(private_key.key))
    except Exception as exc:  # noqa: BLE001 -- the library's own validation
        raise BadArgument(f"public_key_of: not a valid secp256k1 scalar: {exc}") from exc
    return PublicKey(type=KEY_TYPE, key=bytes(derived.public_key.format(compressed=True)))


def _curve(what: str) -> Any:
    """The curve library, or the message that names what to install.

    Imported here and not at module scope: the extra is optional, so the module
    has to import without it and only the two helpers that need arithmetic may
    fail.
    """
    try:
        import coincurve
    except ImportError as exc:
        raise FeatureUnavailable(
            f"{what}: secp256k1 arithmetic needs the optional extra "
            f"`pip install {SECP256K1_EXTRA}`; every other helper here, and "
            "every op, works without it"
        ) from exc
    return coincurve


# --- argument discipline -------------------------------------------------


def _require_private_key(value: Any, op: str) -> PrivateKey:
    if not isinstance(value, PrivateKey):
        raise BadArgumentType(
            f"{op}: expected a PrivateKey, got {type(value).__name__}"
        )
    return value


def _require_signature(value: Any, op: str) -> Signature:
    if not isinstance(value, Signature):
        raise BadArgumentType(
            f"{op}: expected a Signature, got {type(value).__name__}; there is no "
            "signature query argument -- it travels on the channel body"
        )
    return value


def _hash_bytes(value: Hash | bytes | bytearray | memoryview | str, op: str) -> bytes:
    """A digest, from a `Hash`, raw bytes, or its hex form.

    Hex is accepted because that is what the `hash` query argument carries and
    what every tool that prints a digest produces.

    An empty digest is refused, and on `sign_hash` that refusal is the whole
    point rather than a courtesy: an empty `hash=` argument does not select the
    op's request/response path at all -- `OpSignHash` tests `len(args.Hash) > 0`
    -- so the query would quietly become a streamed exchange with nothing
    streamed, be accepted, and answer nothing. On `verify_hash_signature` it is
    one round trip and an `error_message` reading `hash is empty`.
    """
    if isinstance(value, Hash):
        raw = bytes(value.value)
    elif isinstance(value, str):
        raw = bytes(Hash.parse(value).value)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise BadArgumentType(
            f"{op}: expected a Hash, bytes or a hex string, got {type(value).__name__}"
        )
    if not raw:
        raise BadArgument(f"{op}: the digest is empty; the node answers 'hash is empty'")
    if len(raw) > _MAX_HASH:
        # `mod.crypto.hash` is a Bytes8. The writer would refuse it anyway --
        # `ValueTooLarge`, before a byte is written -- but that fault names a
        # length prefix, and this one names the digest and the op.
        raise BadArgument(
            f"{op}: {len(raw)}-byte digest exceeds the {_MAX_HASH} bytes "
            "`mod.crypto.hash` can carry (it is a bytes8)"
        )
    return raw


def _key_param(value: PublicKey | Identity | str, op: str) -> str:
    """The `key` query argument: a public key in its `"<type>:<hex>"` text form.

    An `Identity` is converted here rather than at the call site, because the
    two are the same 33 bytes and a caller holding an identity should not have
    to know that. A string is accepted in either form the caller is likely to
    hold -- a key's own text form, or 66 hex characters -- and is round-tripped
    through the parser so a malformed one is refused here rather than answered
    by the node one query later.
    """
    if isinstance(value, PublicKey):
        return value.text()
    if isinstance(value, Identity):
        return identity_to_public_key(value).text()
    if not isinstance(value, str):
        raise BadArgumentType(
            f"{op}: expected a PublicKey, an Identity or its text form, got "
            f"{type(value).__name__}"
        )
    if ":" in value:
        return PublicKey.parse(value).text()
    return identity_to_public_key(Identity.parse(value)).text()


def _refuse_node_crash(key: PrivateKey, op: str) -> None:
    """The guard that keeps `crypto.public_key` from killing the node.

    `OpPublicKey` answers with whatever `secp256k1.PublicKey(key)` returns and
    that is a nil pointer for every key type but `secp256k1`; the sender then
    calls `ObjectType()` through it and the process dies with no recovery
    anywhere above (see the module docstring). The message names the crash
    because a caller who reads "unsupported key type" will retry.
    """
    if key.is_secp256k1:
        return
    raise BadArgument(
        f"{op}: key type {key.type!r} is not {KEY_TYPE!r}, and this op **crashes "
        f"the node** for any other type -- astrald sends a nil public key whose "
        f"ObjectType() dereferences nil, in a goroutine nothing recovers. Not sent."
    )


def _texts(values: Iterable[str], op: str) -> list[String16]:
    """Texts to be signed or verified, as the `string16` the op switches on.

    `string8` is accepted by both ops too and caps at 255 bytes; `string16` is
    sent always so one length rule covers every call, and it is the wider of the
    two the op declares a branch for.
    """
    out: list[String16] = []
    for value in values:
        if not isinstance(value, str):
            raise BadArgumentType(
                f"{op}: expected a string to sign, got {type(value).__name__}"
            )
        out.append(String16(value))
    if not out:
        raise BadArgument(f"{op}: nothing to sign")
    return out


def _params(op: str, **values: Any) -> str:
    """One query string, every value through its declared spec, `None` dropped.

    A partial application of `ModuleClient._encode` over this module's one
    `_PARAMS` table, and not a second implementation of the encoder.
    """
    return querystring.build(op, ModuleClient._encode(_PARAMS, values))


# --- the client ----------------------------------------------------------


class Crypto(ModuleClient):
    """The `crypto.*` ops plus `secp256k1.new`, over one `Client`.

    `Crypto(client)` constructs one. The scaffolding and the `**kw` contract are
    `ModuleClient`'s: every method takes the query keywords `Client.query`
    takes and passes them through unread.

    The four pure helpers are module-level functions, not methods, because none
    of them touches the client and a method would suggest otherwise.
    """

    __slots__ = ()

    # --- keys ---

    async def new_key(self, **kw: Any) -> PrivateKey:
        """A fresh `secp256k1` private key from the node. RR, `secp256k1.new`.

        The node generates and answers; **it stores nothing** -- `OpNew` is one
        `ch.Send(secp256k1.New())` and no repository write
        (`mod/secp256k1/src/op_new.go`) -- so this neither mutates node state
        nor leaves a key behind on it. That is what makes a read-only live test
        of it legitimate, and there is one.

        Callable with no credential from an IPC guest, which is not gated at
        all; it is **not** on the anonymous-web allowlist, so a browser guest
        needs a token for it.

        The key crosses the IPC socket in the clear, which is what
        `generate_key_local()` avoids at the cost of the optional extra.
        """
        return self._expect(
            await self._c.call_one(OP_NEW_KEY, **kw), PrivateKey, OP_NEW_KEY
        )

    async def public_key(self, private_key: PrivateKey, **kw: Any) -> PublicKey:
        """The public key of one private key, computed by the node. WA.

        **The private key travels on the channel body**, which is the whole of
        this op's input: `crypto.public_key` declares no argument but `in` and
        `out`. Driving it with query arguments is the historical bug this
        module's docstring names.

        A key type other than `secp256k1` is refused here and never sent,
        because the op crashes the node on one. `public_key_of()` is the local
        form and needs no node.
        """
        return (await self.public_key_many([private_key], **kw))[0]

    async def public_key_many(
        self, private_keys: Sequence[PrivateKey], **kw: Any
    ) -> list[PublicKey]:
        """One public key per private key, in order. WA, one query for the batch.

        The op's `ch.Switch` loops, so a batch is one accepted query rather than
        n of them -- which matters, because the node serves apphost from 32
        workers and each query holds one for its lifetime (design section 3.9).
        """
        keys = [_require_private_key(k, OP_PUBLIC_KEY) for k in private_keys]
        if not keys:
            raise BadArgument(f"{OP_PUBLIC_KEY}: no private keys")
        for key in keys:
            _refuse_node_crash(key, OP_PUBLIC_KEY)
        return await self._batch(OP_PUBLIC_KEY, keys, PublicKey, OP_PUBLIC_KEY, kw)

    # --- signing. Every one of these uses a node-held private key. ---

    async def sign_hash(
        self,
        hash: Hash | bytes | str,  # noqa: A002 -- the node's own argument name
        *,
        key: PublicKey | Identity | str | None = None,
        scheme: str | None = None,
        **kw: Any,
    ) -> Signature:
        """Sign one digest with a node-held key. RR, digest in the query string.

        **Privileged.** The node signs with the private key it holds for `key`,
        so this is a signing oracle and not a computation: what it can sign is
        what that node's crypto module has indexed. `key` defaults to the
        query's caller, which for an anonymous IPC guest is **the node's own
        identity** -- astrald's core router substitutes it for a nil caller --
        so an omitted `key` here asks the node to sign as itself.

        The digest goes in the query string because that is the op's own
        request/response path: with `hash` present `OpSignHash` answers one
        signature and never reads the channel. `sign_hash_many` is the streamed
        form and the only one that can carry more than one digest.

        `scheme` omitted leaves astrald's `asn1`, which is the only hash scheme
        any stock engine implements.
        """
        qs = _params(
            OP_SIGN_HASH,
            hash=_hash_bytes(hash, OP_SIGN_HASH).hex(),
            key=None if key is None else _key_param(key, OP_SIGN_HASH),
            scheme=scheme,
        )
        return self._expect(await self._c.call_one(qs, **kw), Signature, OP_SIGN_HASH)

    async def sign_hash_many(
        self,
        hashes: Sequence[Hash | bytes | str],
        *,
        key: PublicKey | Identity | str | None = None,
        scheme: str | None = None,
        **kw: Any,
    ) -> list[Signature]:
        """Sign several digests with a node-held key. WA, digests on the body.

        **Privileged**, as `sign_hash` is. One signature per digest, in order.
        No `hash` argument is sent: its presence is what makes the op answer
        once and stop reading, so sending both would sign the argument and
        ignore the body.

        The key travels as a query argument even though this op does honour one
        streamed on the body -- unlike `crypto.sign_text`, which acks a streamed
        key and then signs with the caller's anyway. One path that works on both
        ops is worth more than the one this op alone would allow.
        """
        digests = [Hash(_hash_bytes(h, OP_SIGN_HASH)) for h in hashes]
        if not digests:
            raise BadArgument(f"{OP_SIGN_HASH}: no digests")
        qs = _params(
            OP_SIGN_HASH,
            key=None if key is None else _key_param(key, OP_SIGN_HASH),
            scheme=scheme,
        )
        return await self._batch(qs, digests, Signature, OP_SIGN_HASH, kw)

    async def sign_text(
        self,
        text: str,
        *,
        key: PublicKey | Identity | str | None = None,
        scheme: str | None = None,
        **kw: Any,
    ) -> Signature:
        """Sign one text with a node-held key. WA, text on the body.

        **Privileged**, and with the same caller default `sign_hash` has: no
        `key` means the node signs as itself for an anonymous guest.

        The text goes on the body and not in the query string, although the op
        accepts either. Two reasons, and both are about the text rather than
        about the protocol: it has no length bound where a query string has two
        (255 advisory, 65 535 on the wire, before URL escaping multiplies a
        non-ASCII text), and astrald's core router writes the query string of
        every routed query to its log at the default verbosity, so a text signed
        through the argument is a text in the node's log.

        `scheme` omitted leaves astrald's `bip137`, the only text scheme any
        stock engine implements.

        **A key or scheme the node cannot serve resets the connection here.**
        `OpSignText` builds its signer *before* entering `ch.Switch`, so it
        answers `unsupported` and closes with the body still unread, and a close
        with unread data is a TCP reset that destroys the message the node just
        wrote. Verified live against `furry-bolt`: the same call with the text in
        the query string answers a clean `error_message`, the body form does not.
        The reset is reported as a `ProtocolError` naming this, rather than as
        the bare `ConnectionResetError` the socket raises. `sign_hash` builds its
        signer inside the switch and does not share the defect.
        """
        return (await self.sign_text_many([text], key=key, scheme=scheme, **kw))[0]

    async def sign_text_many(
        self,
        texts: Sequence[str],
        *,
        key: PublicKey | Identity | str | None = None,
        scheme: str | None = None,
        **kw: Any,
    ) -> list[Signature]:
        """Sign several texts with a node-held key. WA, one query for the batch.

        **Privileged.** One signature per text, in order. Each text is a
        `string16`; the op has a `string8` branch too and this SDK never uses
        it, so one length rule covers every call. `sign_text` documents the
        reset a key the node cannot serve produces; it applies to a batch too,
        and to the whole batch, because the op fails before reading any of it.
        """
        values = _texts(texts, OP_SIGN_TEXT)
        qs = _params(
            OP_SIGN_TEXT,
            key=None if key is None else _key_param(key, OP_SIGN_TEXT),
            scheme=scheme,
        )
        return await self._batch(qs, values, Signature, OP_SIGN_TEXT, kw)

    # --- verifying. Read-only, and a `False` is an answer rather than a fault. ---

    async def verify_hash_signature(
        self,
        hash: Hash | bytes | str,  # noqa: A002 -- the node's own argument name
        signature: Signature,
        *,
        key: PublicKey | Identity | str | None = None,
        **kw: Any,
    ) -> Verdict:
        """Whether a signature covers a digest. WA, signature on the body.

        **The signature is what triggers verification and it has no query
        argument.** `OpVerifyHashSignature` verifies inside its
        `*crypto.Signature` branch and nowhere else, so a caller that sends only
        arguments gets an accepted query, no answer and EOF -- which is the
        shape of the bug that made two earlier SDKs report success without ever
        verifying anything.

        Read-only. `key` defaults to the caller, which for an anonymous IPC
        guest is the node's own identity, so an omitted key asks "did this node
        sign this?".

        Returns a `Verdict`: false with `invalid signature` is a forged or
        mismatched signature, false with `unsupported` is a node whose engines
        cannot judge -- the hash engine takes `secp256k1` keys and `asn1`
        signatures and nothing else.
        """
        qs = _params(
            OP_VERIFY_HASH_SIGNATURE,
            hash=_hash_bytes(hash, OP_VERIFY_HASH_SIGNATURE).hex(),
            key=None if key is None else _key_param(key, OP_VERIFY_HASH_SIGNATURE),
        )
        sig = _require_signature(signature, OP_VERIFY_HASH_SIGNATURE)
        return await self._verdict(qs, kw, [sig], 1, OP_VERIFY_HASH_SIGNATURE)

    async def verify_text_signature(
        self,
        text: str,
        signature: Signature,
        *,
        key: PublicKey | Identity | str | None = None,
        **kw: Any,
    ) -> Verdict:
        """Whether a signature covers a text. WA, text then signature on the body.

        Two objects on the body and therefore two answers: astrald acks the
        text, then answers the signature with the verdict, so the verdict is the
        **last** object and not the first. The text goes on the body for the
        reasons `sign_text` states, and the signature because there is no
        argument for one.

        Read-only, with `sign_text`'s caller default. A `bip137` signature is
        the only kind any stock engine verifies.
        """
        if not isinstance(text, str):
            raise BadArgumentType(
                f"{OP_VERIFY_TEXT_SIGNATURE}: expected a string, got "
                f"{type(text).__name__}"
            )
        qs = _params(
            OP_VERIFY_TEXT_SIGNATURE,
            key=None if key is None else _key_param(key, OP_VERIFY_TEXT_SIGNATURE),
        )
        sig = _require_signature(signature, OP_VERIFY_TEXT_SIGNATURE)
        return await self._verdict(
            qs, kw, [String16(text), sig], 2, OP_VERIFY_TEXT_SIGNATURE
        )

    # --- the two body-writing readers ---

    async def _batch(
        self,
        qs: str,
        inputs: Sequence[Any],
        kind: type,
        op: str,
        kw: dict[str, Any],
    ) -> list[Any]:
        """Send the body, terminate it with `eos`, read one answer per input.

        `expect=len(inputs)` rather than reading to the end: every op here
        answers exactly once per object, so the count is known, and an op that
        answers and then waits for the caller to close would otherwise be read
        until the deadline. A short list is `_answers`' to report.
        """
        try:
            answers = await self._c.call_with(
                qs, *inputs, eos=True, expect=len(inputs), **kw
            )
        except (ConnectionResetError, BrokenPipeError) as exc:
            raise _reset(op, exc) from exc
        return _answers(answers, inputs, kind, op)

    async def _verdict(
        self,
        qs: str,
        kw: dict[str, Any],
        inputs: Sequence[Any],
        expect: int,
        op: str,
    ) -> Verdict:
        """Send the body, read `expect` answers, and read the last as a verdict.

        `raw_objects()` rather than `call_with`, for the reason `apphost.cancel`
        uses it: an `error_message` here is the answer and not a failure, and the
        iterator that raises on one would turn "not verified" into an exception.
        The budget is the client's own one-shot budget, so an op that accepts and
        then says nothing costs `timeout` and not the connection.

        Neither verify op can fail before it reads -- there is no signer to
        build -- so the reset `sign_text` documents does not arise *from the op*
        here. The translation is applied anyway: a responder that goes away
        mid-exchange raises the same exception, and the promise that every fault
        out of this SDK is an `AstralError` has to hold for that one too.
        """
        try:
            return await self._verdict_exchange(qs, kw, inputs, expect, op)
        except (ConnectionResetError, BrokenPipeError) as exc:
            raise _reset(op, exc) from exc

    async def _verdict_exchange(
        self,
        qs: str,
        kw: dict[str, Any],
        inputs: Sequence[Any],
        expect: int,
        op: str,
    ) -> Verdict:
        """The one WA path here that writes its whole body before reading.

        `Client.call_with(expect=n)` and `Objects._exchange` both interleave one
        send with one read, because an op that answers per input deadlocks
        against a caller that batches: the answers fill the caller's receive
        buffer, the responder's `ch.Send` blocks, it stops reading, and the
        caller's own `send()` blocks on its drain. **This exchange cannot reach
        that state and the reason is structural, not a measurement.** Both
        callers pass a literal list -- one `Signature`, or a `string16` and a
        `Signature` -- so the batch is one or two objects and the answers are one
        or two acks. Neither side can fill a socket buffer with that.

        It is written this way rather than interleaved because the eos before the
        first read is what makes the exchange work against an op that answers
        only once its switch has seen everything, and that tolerance costs
        nothing at two objects. **Do not copy this shape to an op whose input
        count comes from the caller**; use `call_with(expect=...)`, which
        interleaves.
        """
        async with self._one_shot(qs, kw) as (stream, budget):
            for obj in inputs:
                await stream.send(obj, timeout=budget.remaining)
            # Every crypto op ends its switch with `BreakOnEOS`, so the
            # terminator is what lets the op leave its read loop cleanly rather
            # than on the read error a bare close produces.
            await stream.send_eos(timeout=budget.remaining)
            answers = stream.raw_objects()
            seen: list[Any] = []
            try:
                async with asyncio.timeout(budget.remaining):
                    for _ in range(expect):
                        answer = await anext(answers, None)
                        if answer is None:
                            break
                        seen.append(answer)
            finally:
                await answers.aclose()
        if not seen:
            raise ProtocolError(f"{op}: the stream ended before answering")
        final = seen[-1]
        name = getattr(final, "ASTRAL_TYPE", type(final).__name__)
        if name == _ACK_TYPE:
            return Verdict(True)
        if name == _ERROR_TYPE:
            return Verdict(False, str(final))
        raise ProtocolError(
            f"{op}: expected {_ACK_TYPE!r} or {_ERROR_TYPE!r}, got {name!r}"
        )


def _reset(op: str, exc: BaseException) -> ProtocolError:
    """The connection reset an op produces by closing without draining its body.

    astrald's `OpSignText` answers and closes before it reads anything when it
    cannot build a signer, so the caller's body sits unread in the node's
    receive buffer; a close with unread data is a reset, and a reset discards
    whatever the node had already written -- including the `error_message` that
    would have said *why*. Verified live: the same call with the text as a query
    argument, which writes no body, answers `unsupported` cleanly.

    Translated to a `ProtocolError` because the op has broken the shape it
    declares -- it accepts a query whose whole input is a channel body and then
    does not read one -- and because the raw `ConnectionResetError` the socket
    raises is not an `AstralError`, which every fault out of this SDK is. The
    original is chained, so a node that genuinely died is still visible in the
    traceback rather than being renamed.
    """
    return ProtocolError(
        f"{op}: the node closed the stream without reading the body it asked "
        f"for, which reset the connection and destroyed its own error message "
        f"({type(exc).__name__}: {exc}). The usual cause is a key or scheme no "
        f"engine on that node serves; astrald builds the signer before reading "
        f"and cannot report it. The node may also simply have gone."
    )


def _answers(
    answers: Sequence[Any], inputs: Sequence[Any], kind: type, op: str
) -> list[Any]:
    """One answer of the declared type per input, or the shape violation.

    A short answer list is the op having stopped early -- astrald sends
    `astral.Err` and returns from `ch.Switch` on the first failure -- and a
    caller zipping answers against inputs would silently pair the wrong ones,
    so the count is checked before anything is returned.
    """
    if len(answers) != len(inputs):
        raise ProtocolError(
            f"{op}: sent {len(inputs)} object(s) and got {len(answers)} answer(s)"
        )
    return [ModuleClient._expect(obj, kind, op) for obj in answers]


CRYPTO_TYPES: Final[Sequence[type]] = (Hash, PrivateKey, PublicKey, Signature)
"""Every wire type this module declares, for a private-registry sweep.

`registry.add(*Crypto.TYPES)` puts the whole crypto vocabulary in a `Blueprints`
that is not the default one. These four are the only `mod.crypto.*` types
astral-go registers (`api/crypto/*.go`, four `astral.Add` calls); `secp256k1`
declares none of its own -- its op answers a `mod.crypto.private_key`.
"""

Crypto.TYPES = CRYPTO_TYPES
